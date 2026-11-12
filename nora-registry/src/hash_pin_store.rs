// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Hash Pin Store — the local filesystem backend's record of the SHA-256 pin of
//! every artifact it stores.
//!
//! `LocalStorage` records a pin on every write and hands it back on every read;
//! the `Storage` wrapper is what compares it against the bytes. Together they
//! detect tampering at the storage layer (e.g. direct filesystem modification
//! bypassing NORA).
//!
//! Persistence: append-only NDJSON file (`.nora-pins.ndjson`) compacted on
//! startup and when it outgrows its live entries. Each line: `{"k":"storage/key","h":"sha256hex"}`. An empty `h`
//! marks a deletion (tombstone).
//!
//! Durability: every pin write **propagates** its I/O result to the caller,
//! which fails closed (`StorageError::Io`) rather than report a `put()` success
//! the disk never accepted. A swallowed pin-write error would silently
//! downgrade a pinned key to open-world after a restart — the very integrity
//! bypass #582/#604 closed — because the in-memory pin is now updated only
//! *after* the durable append succeeds. (Crash-durability of the pin via
//! `fsync` is tracked separately: it must land together with the matching body
//! `fsync` on `put_from_path`, so the pin is never made *more* durable than the
//! bytes it pins.)

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use tracing::{error, warn};

#[derive(Serialize, Deserialize)]
struct PinEntry {
    k: String,
    h: String,
}

/// The log file as its writers see it. One writer at a time holds it, for the whole of
/// check, append and map update.
struct Log {
    /// Lines in the file, live or not.
    lines: usize,
    /// Whether the file may be rewritten from the map. False after a load that did not read
    /// every entry: a rewrite would then drop the pins that were not read.
    complete: bool,
}

/// A log shorter than this is never compacted while running.
const COMPACT_MIN_LINES: usize = 4096;

pub struct HashPinStore {
    pins: RwLock<HashMap<String, String>>,
    log: Mutex<Log>,
    path: PathBuf,
    /// Whether the start read every entry of the log. Until a start that does, a key without
    /// a pin may be one whose pin was not read, and its reads fail closed ([`Self::loaded`]).
    loaded: bool,
}

impl HashPinStore {
    /// Load (or create) a pin store backed by the given NDJSON file.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let mut pins = HashMap::new();
        let mut log = Log {
            lines: 0,
            complete: true,
        };

        // Replay NDJSON log — last entry per key wins. A line that cannot be read is skipped
        // and the ones after it still load: stopping there would drop every later pin.
        match std::fs::File::open(&path) {
            Ok(file) => {
                let mut reader = std::io::BufReader::new(file);
                let mut line = Vec::new();
                let mut bad = 0usize;
                let mut torn = false;
                let mut last_bad = false;
                loop {
                    line.clear();
                    match reader.read_until(b'\n', &mut line) {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(e) => {
                            error!(
                                error = %e,
                                path = %path.display(),
                                loaded = pins.len(),
                                "hash-pin log read failed part way; the pins after this point \
                                 are NOT loaded (their keys verify open-world until this is fixed)"
                            );
                            log.complete = false;
                            break;
                        }
                    }
                    log.lines += 1;
                    torn = line.last() != Some(&b'\n');
                    last_bad = false;
                    if line.iter().all(u8::is_ascii_whitespace) {
                        continue;
                    }
                    last_bad = true;
                    match serde_json::from_slice::<PinEntry>(&line) {
                        Ok(entry) if entry.h.is_empty() => {
                            last_bad = false;
                            pins.remove(&entry.k);
                        }
                        Ok(entry) => {
                            last_bad = false;
                            pins.insert(entry.k, entry.h);
                        }
                        Err(_) => bad += 1,
                    }
                }
                // A last line cut by a crash mid-append is the one write that never finished,
                // not a pin lost from the middle: the load is complete without it.
                if torn && last_bad {
                    warn!(path = %path.display(), "hash-pin log: its last line was cut short (a crash mid-append); it is dropped");
                    bad -= 1;
                }
                if bad > 0 {
                    error!(
                        path = %path.display(),
                        unreadable_lines = bad,
                        loaded = pins.len(),
                        "hash-pin log has lines that do not parse; their pins are NOT loaded \
                         and the log is left as it is (no compaction) until it is repaired"
                    );
                    log.complete = false;
                }
                // A last line without its newline (a crash mid-append) would swallow the
                // next entry appended after it.
                if torn {
                    if let Err(e) = std::fs::OpenOptions::new()
                        .append(true)
                        .open(&path)
                        .and_then(|mut f| f.write_all(b"\n"))
                    {
                        warn!(error = %e, path = %path.display(), "hash-pin log: could not end its last line");
                    }
                }
            }
            // First run / empty store — nothing to replay.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            // The pin file exists but cannot be read (permissions, EIO).
            // Loading an empty set would silently make every key open-world;
            // surface it loudly so the operator notices the integrity index did
            // not load rather than discovering it only on a missed tamper.
            Err(e) => {
                error!(
                    error = %e,
                    path = %path.display(),
                    "hash-pin log present but unreadable; integrity index NOT loaded \
                     (keys verify open-world until this is fixed)"
                );
                log.complete = false;
            }
        }

        crate::metrics::HASH_PIN_LOG_INCOMPLETE.set(i64::from(!log.complete));
        if !log.complete {
            error!(
                path = %path.display(),
                "hash-pin log NOT fully loaded: reads of keys without a loaded pin are refused \
                 (integrity violation) until a start loads the whole log; \
                 nora_hash_pin_log_incomplete is 1"
            );
        }
        let store = Self {
            pins: RwLock::new(pins),
            loaded: log.complete,
            log: Mutex::new(log),
            path,
        };

        // Compact on startup to remove tombstones and duplicates. Compaction is
        // an optimization, not an integrity-critical write: a failure leaves the
        // (correct, already-persisted) uncompacted log in place, so it is logged
        // and tolerated rather than fatal. A log that was not read in full is never
        // rewritten or removed: it still holds the pins this process could not load.
        store.compact(&mut store.log.lock());
        store
    }

    /// Record a pre-computed SHA-256 hash for a storage key.
    ///
    /// `hash` must be a lowercase hex-encoded SHA-256 (64 chars).
    ///
    /// Returns the I/O error if the pin append fails, so the caller can fail
    /// closed rather than serve an artifact it could not pin. The in-memory
    /// index is updated only *after* the append succeeds — memory must never
    /// claim a pin the disk does not hold, or a `get()` after a failed `put()`
    /// would verify against a RAM-only pin that vanishes on restart, and a
    /// retried `put()` would skip the (still-missing) append.
    pub fn record_hash(&self, key: &str, hash: &str) -> io::Result<()> {
        debug_assert!(
            hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()),
            "record_hash: expected 64-char hex SHA-256, got: {hash}"
        );

        // One writer at a time, across check → append → insert: the disk append happens
        // before the in-memory update (durability), and two writers of one key cannot
        // interleave their appends and inserts, so disk and memory cannot diverge. (An
        // earlier version without it had a TOCTOU where the two orders disagreed.) Readers
        // wait only for the map update, never for the file I/O: the map's own lock is taken
        // after the append.
        let mut log = self.log.lock();
        if self.get(key).as_deref() != Some(hash) {
            Self::append_to_file(&self.path, key, hash)?;
            log.lines += 1;
            self.pins.write().insert(key.to_string(), hash.to_string());
            self.compact_if_grown(&mut log);
        }
        Ok(())
    }

    /// Remove a pin entry. Called on `delete()`.
    ///
    /// Appends a tombstone before dropping the in-memory entry, returning any
    /// I/O error. A tombstone-write failure leaves the (now stale) pin in place;
    /// that is benign — `get()` on a deleted key fails at the inner backend
    /// before verification, and a later `put()` of the key overwrites the pin —
    /// so callers may treat a remove failure as non-fatal.
    pub fn remove(&self, key: &str) -> io::Result<()> {
        // Tombstone, then the map, as one writer (see record_hash()).
        let mut log = self.log.lock();
        if self.get(key).is_some() {
            Self::append_to_file(&self.path, key, "")?;
            log.lines += 1;
            self.pins.write().remove(key);
            self.compact_if_grown(&mut log);
        }
        Ok(())
    }

    /// Whether the start read the whole log: when false, a key without a pin is not known to
    /// be unpinned, and a read of it must fail closed.
    pub fn loaded(&self) -> bool {
        self.loaded
    }

    /// Look up the stored SHA-256 hash for a key, if pinned.
    pub fn get(&self, key: &str) -> Option<String> {
        self.pins.read().get(key).cloned()
    }

    /// Compact once the log holds more than twice the live pins: every overwrite of a
    /// mutable key appends a line, and the file would otherwise grow until a restart. The
    /// rewrite is amortized over the appends that caused it and runs on the writer's
    /// thread (the blocking pool); readers are not held.
    fn compact_if_grown(&self, log: &mut Log) {
        let live = self.pins.read().len();
        if log.lines > COMPACT_MIN_LINES && log.lines / 2 > live {
            self.compact(log);
        }
    }

    /// Compact the NDJSON file: rewrite with only live entries via a temp file
    /// and an atomic rename. Does nothing to a log whose load was incomplete. A failure is
    /// logged and tolerated: the uncompacted log stays, correct as it is.
    fn compact(&self, log: &mut Log) {
        if !log.complete {
            return;
        }
        match self.rewrite() {
            Ok(lines) => log.lines = lines,
            Err(e) => {
                warn!(
                    error = %e,
                    path = %self.path.display(),
                    "hash-pin compaction failed; continuing with uncompacted log"
                );
                // Ask again only after the log has grown as much once more.
                log.lines = self.pins.read().len();
            }
        }
    }

    /// The file rewritten from the map; returns its line count.
    fn rewrite(&self) -> io::Result<usize> {
        let pins = self.pins.read();
        if pins.is_empty() {
            // No live pins: remove the file if present; an absent file is fine.
            return match std::fs::remove_file(&self.path) {
                Ok(()) => Ok(0),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(0),
                Err(e) => Err(e),
            };
        }

        let temp_path = self.path.with_extension("ndjson.tmp");
        let mut file = io::BufWriter::new(std::fs::File::create(&temp_path)?);
        for (key, hash) in pins.iter() {
            let entry = PinEntry {
                k: key.clone(),
                h: hash.clone(),
            };
            let line = serde_json::to_string(&entry).map_err(io::Error::other)?;
            writeln!(file, "{line}")?;
        }
        // On disk before it replaces the log: a crash must not leave an empty index.
        file.into_inner()
            .map_err(io::IntoInnerError::into_error)?
            .sync_all()?;
        std::fs::rename(&temp_path, &self.path)?;
        Ok(pins.len())
    }

    /// Append a single entry to the NDJSON file (static, safe to call from any
    /// thread). Propagates any open/serialize/write error to the caller instead
    /// of swallowing it.
    fn append_to_file(path: &std::path::Path, key: &str, hash: &str) -> io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        let entry = PinEntry {
            k: key.to_string(),
            h: hash.to_string(),
        };
        let line = serde_json::to_string(&entry).map_err(io::Error::other)?;
        writeln!(file, "{line}")?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    fn pin_path(dir: &TempDir) -> PathBuf {
        dir.path().join(".nora-pins.ndjson")
    }

    fn sha(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    #[test]
    fn test_record_and_get() {
        let dir = TempDir::new().unwrap();
        let store = HashPinStore::new(pin_path(&dir));
        let key = "maven/com/example/1.0/app.jar";

        store.record_hash(key, &sha(b"jar-content")).unwrap();
        assert_eq!(
            store.get(key).as_deref(),
            Some(sha(b"jar-content").as_str())
        );
        assert_eq!(store.get("unknown/key"), None);
    }

    #[test]
    fn test_record_update_overwrites_pin() {
        let dir = TempDir::new().unwrap();
        let store = HashPinStore::new(pin_path(&dir));
        let key = "npm/meta/express";

        store.record_hash(key, &sha(b"v1")).unwrap();
        // Metadata update — pin is updated
        store.record_hash(key, &sha(b"v2")).unwrap();
        assert_eq!(store.get(key).as_deref(), Some(sha(b"v2").as_str()));
    }

    #[test]
    fn test_remove_pin() {
        let dir = TempDir::new().unwrap();
        let store = HashPinStore::new(pin_path(&dir));

        store.record_hash("key", &sha(b"data")).unwrap();
        store.remove("key").unwrap();
        assert_eq!(store.get("key"), None);
    }

    #[test]
    fn test_persistence_and_reload() {
        let dir = TempDir::new().unwrap();
        let path = pin_path(&dir);

        {
            let store = HashPinStore::new(&path);
            store.record_hash("a", &sha(b"data-a")).unwrap();
            store.record_hash("b", &sha(b"data-b")).unwrap();
            store.remove("b").unwrap();
        }

        // Reload from disk
        let store = HashPinStore::new(&path);
        assert_eq!(store.get("a").as_deref(), Some(sha(b"data-a").as_str()));
        assert_eq!(store.get("b"), None);
    }

    #[test]
    fn test_compact_removes_tombstones() {
        let dir = TempDir::new().unwrap();
        let path = pin_path(&dir);

        {
            let store = HashPinStore::new(&path);
            store.record_hash("keep", &sha(b"data")).unwrap();
            store.record_hash("remove", &sha(b"data")).unwrap();
            store.remove("remove").unwrap();
        }

        // After reload + compact, file should only have 1 entry
        let store = HashPinStore::new(&path);
        assert!(store.get("keep").is_some());

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("keep"));
    }

    #[test]
    fn test_idempotent_record() {
        let dir = TempDir::new().unwrap();
        let path = pin_path(&dir);
        let store = HashPinStore::new(&path);

        // Same hash twice — should not append duplicate
        store.record_hash("key", &sha(b"data")).unwrap();
        store.record_hash("key", &sha(b"data")).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1, "duplicate record_hash should be idempotent");
    }

    #[test]
    fn test_empty_store_no_file() {
        let dir = TempDir::new().unwrap();
        let path = pin_path(&dir);
        let store = HashPinStore::new(&path);

        assert_eq!(store.get("anything"), None);
        assert!(!path.exists(), "empty store should not create file");
    }

    /// A pin write to an unwritable path must surface the I/O error, not swallow
    /// it — otherwise `put()` reports success while the pin never lands,
    /// silently downgrading the key to open-world on the next restart.
    ///
    /// The path is placed *under a regular file* so `open()` fails with
    /// `ENOTDIR` — a structural error the kernel returns even to root, unlike a
    /// `chmod`-based read-only directory which root (a common deployment for
    /// this code) bypasses via `DAC_OVERRIDE`.
    #[test]
    fn test_record_propagates_io_error() {
        let dir = TempDir::new().unwrap();
        let not_a_dir = dir.path().join("iamafile");
        std::fs::write(&not_a_dir, b"x").unwrap();
        let unwritable = not_a_dir.join(".nora-pins.ndjson");

        let store = HashPinStore::new(&unwritable);
        assert!(
            store.record_hash("k", &sha(b"data")).is_err(),
            "pin write to an unwritable path must return an error, not swallow it"
        );
        // The in-memory index must not claim a pin the disk never accepted.
        assert_eq!(
            store.get("k"),
            None,
            "failed pin write must not update memory"
        );
    }

    /// Regression for the disk-first TOCTOU: concurrent record_hash() calls for
    /// the SAME key with DIFFERENT hashes must leave the in-memory pin equal to
    /// what a fresh reload from disk sees — disk and memory cannot diverge.
    /// Holding the write lock across check → append → insert makes each call
    /// atomic per key; the earlier two-lock version could append in one order
    /// but insert in the other.
    #[test]
    fn test_concurrent_same_key_disk_memory_consistent() {
        use std::sync::Arc;
        let dir = TempDir::new().unwrap();
        let path = pin_path(&dir);
        let store = Arc::new(HashPinStore::new(&path));
        let key = "concurrent/key";

        let handles: Vec<_> = (0..20)
            .map(|i| {
                let s = Arc::clone(&store);
                std::thread::spawn(move || {
                    let _ = s.record_hash(key, &sha(format!("data-{i}").as_bytes()));
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        let in_memory = store.get(key);
        drop(store);
        // What survives a restart must equal what the live process holds.
        let reloaded = HashPinStore::new(&path);
        assert_eq!(
            in_memory,
            reloaded.get(key),
            "in-memory pin must match the durably-recorded pin (no TOCTOU divergence)"
        );
        assert!(in_memory.is_some(), "some writer must have recorded a pin");
    }

    fn line(key: &str, data: &[u8]) -> String {
        format!("{{\"k\":\"{key}\",\"h\":\"{}\"}}\n", sha(data))
    }

    /// R4-C04: a line that does not read (here: not UTF-8) in the middle of the log costs
    /// that line only. The pins after it load, and the log is not rewritten from the partial
    /// map: the damaged line stays for a repair.
    #[test]
    fn a_corrupt_line_in_the_middle_loses_no_other_pin_and_blocks_compaction() {
        let dir = TempDir::new().unwrap();
        let path = pin_path(&dir);
        let mut bytes = line("a", b"a").into_bytes();
        bytes.extend_from_slice(b"{\"k\":\"b\",\"h\":\"\xff\xfe\"}\n");
        bytes.extend_from_slice(line("c", b"c").as_bytes());
        bytes.extend_from_slice(line("a", b"a2").as_bytes());
        std::fs::write(&path, &bytes).unwrap();

        let store = HashPinStore::new(&path);
        assert!(
            !store.loaded(),
            "a pin may be missing: unpinned reads fail closed"
        );
        assert_eq!(store.get("a"), Some(sha(b"a2")));
        assert_eq!(store.get("c"), Some(sha(b"c")), "a pin after the bad line");
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "the log is untouched");

        // Writes still append, and a store of nothing but tombstones removes nothing.
        store.record_hash("d", &sha(b"d")).unwrap();
        for key in ["a", "c", "d"] {
            store.remove(key).unwrap();
        }
        let after = std::fs::read(&path).unwrap();
        assert!(after.starts_with(&bytes), "the log only grew");
        drop(store);
        assert_eq!(HashPinStore::new(&path).get("d"), None);
        assert!(path.exists());
    }

    /// R4-C04: a log that exists and cannot be read is neither removed nor rewritten by the
    /// start that could not load it. (A directory under the name: `open` succeeds and the
    /// read fails, for root as well.)
    #[test]
    fn an_unreadable_log_is_left_in_place() {
        let dir = TempDir::new().unwrap();
        let path = pin_path(&dir);
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("evidence"), b"x").unwrap();

        let store = HashPinStore::new(&path);
        assert_eq!(store.get("a"), None);
        assert!(!store.log.lock().complete);
        assert!(path.join("evidence").exists(), "nothing was removed");
    }

    /// R4-C04, the open-fails arm: the log is a file this process may not open.
    #[cfg(unix)]
    #[test]
    fn a_log_that_cannot_be_opened_is_left_in_place() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = pin_path(&dir);
        let content = line("a", b"a");
        std::fs::write(&path, &content).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::File::open(&path).is_ok() {
            return; // root reads anything: the arm cannot be reached here
        }

        let store = HashPinStore::new(&path);
        assert_eq!(store.get("a"), None);
        drop(store);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), content);
        assert_eq!(HashPinStore::new(&path).get("a"), Some(sha(b"a")));
    }

    /// A last line cut by a crash mid-append does not swallow the entry appended next.
    #[test]
    fn an_append_after_a_torn_last_line_is_read_back() {
        let dir = TempDir::new().unwrap();
        let path = pin_path(&dir);
        std::fs::write(&path, format!("{}{{\"k\":\"torn", line("a", b"a"))).unwrap();

        let store = HashPinStore::new(&path);
        assert!(
            store.loaded(),
            "the cut line is the unfinished write, no pin is missing"
        );
        store.record_hash("b", &sha(b"b")).unwrap();
        drop(store);
        let store = HashPinStore::new(&path);
        assert_eq!(store.get("a"), Some(sha(b"a")));
        assert_eq!(store.get("b"), Some(sha(b"b")));
    }

    /// R4-P17: the log of a running store is compacted once it holds more than twice the
    /// live pins, not only at the next start.
    #[test]
    fn a_log_of_overwrites_is_compacted_while_running() {
        let dir = TempDir::new().unwrap();
        let path = pin_path(&dir);
        let store = HashPinStore::new(&path);
        for i in 0..=COMPACT_MIN_LINES {
            store
                .record_hash("npm/a/metadata.json", &sha(&i.to_le_bytes()))
                .unwrap();
        }
        let lines = std::fs::read_to_string(&path).unwrap().lines().count();
        assert_eq!(lines, 1, "one live pin, one line");
        assert_eq!(
            store.get("npm/a/metadata.json"),
            Some(sha(&COMPACT_MIN_LINES.to_le_bytes()))
        );
    }

    /// R4-P17: a pin append that is stuck on the disk holds no reader. The log is a FIFO
    /// nobody reads, so the append blocks in `open` for as long as the test wants; a reader
    /// that waited for it would not answer.
    #[cfg(unix)]
    #[test]
    fn a_read_does_not_wait_for_an_append() {
        let dir = TempDir::new().unwrap();
        let path = pin_path(&dir);
        let store = HashPinStore::new(&path);
        store.record_hash("k", &sha(b"v")).unwrap();
        std::fs::remove_file(&path).unwrap();
        let made = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap();
        assert!(made.success());

        std::thread::scope(|threads| {
            let appending = threads.spawn(|| store.record_hash("k2", &sha(b"w")));
            while !store.log.is_locked() {
                std::thread::yield_now();
            }
            let (read, answer) = std::sync::mpsc::channel();
            let store = &store;
            threads.spawn(move || read.send(store.get("k")));
            let read = answer.recv_timeout(std::time::Duration::from_secs(10));
            // Read the FIFO to its end: the append goes through, and both threads end.
            let appended = std::fs::read_to_string(&path).unwrap();
            appending.join().unwrap().unwrap();
            assert_eq!(read, Ok(Some(sha(b"v"))), "the read waited for the append");
            assert!(appended.contains("\"k2\""), "{appended}");
        });
        assert_eq!(store.get("k2"), Some(sha(b"w")));
    }
}
