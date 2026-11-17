// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Structured audit log — append-only JSONL output.
//!
//! Records who/when/what for every registry write operation.
//! Output modes (NORA_AUDIT_LOG):
//!   - `file`   — write to {storage_path}/audit.jsonl
//!   - `stdout`  — write JSONL to stderr (12-factor compatible)
//!   - `both`   — write to file AND stderr (default)
//!   - `off`    — disable audit logging
//!
//! Reads (`pull`, `cache_hit`, `proxy_fetch`, `curation_block`) go to
//! `audit-reads.jsonl`, everything else to `audit.jsonl`, so download traffic cannot
//! rotate write records out. Both files are size-rotated (`audit.max_size_mb`, half of
//! it for reads; `audit.max_files`): `audit.jsonl` → `audit.jsonl.1` → … →
//! `audit.jsonl.N`, the oldest dropped. Files are created 0600.
//!
//! Uses a bounded mpsc channel with a single writer task (#543) to avoid
//! per-entry `spawn_blocking` + Mutex contention under load.

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Channel bound for audit entries. Under normal load, entries are drained
/// faster than they arrive. The bound provides backpressure under extreme
/// load — entries exceeding this are dropped with a warning (#543).
const AUDIT_CHANNEL_BOUND: usize = 10_000;

/// Where read events go, next to `audit.jsonl`.
const READS_FILE: &str = "audit-reads.jsonl";

/// A download served or refused. Reads get their own file and budget so they cannot
/// rotate write records out of `audit.jsonl`; an unknown action counts as a write.
fn is_read_event(action: &str) -> bool {
    matches!(
        action,
        "pull" | "cache_hit" | "proxy_fetch" | "curation_block"
    )
}

/// Audit output mode.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditMode {
    File,
    Stdout,
    #[default]
    Both,
    Off,
}

impl std::fmt::Display for AuditMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File => write!(f, "file"),
            Self::Stdout => write!(f, "stdout"),
            Self::Both => write!(f, "both"),
            Self::Off => write!(f, "off"),
        }
    }
}

impl std::str::FromStr for AuditMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "file" => Ok(Self::File),
            "stdout" | "stderr" => Ok(Self::Stdout),
            "both" => Ok(Self::Both),
            "off" | "none" | "false" | "0" => Ok(Self::Off),
            other => Err(format!(
                "unknown audit mode {:?} — valid values: file, stdout, both, off",
                other
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub ts: DateTime<Utc>,
    pub action: String,
    pub actor: String,
    pub artifact: String,
    pub registry: String,
    pub detail: String,
}

impl AuditEntry {
    /// The entry of a token mint, the same on every route that mints: `actor`
    /// minted for `owner` (artifact) through `route` (registry: `api`, `ui`,
    /// `admin`) a token of `role` living `ttl_secs`, as granted. Never the
    /// token itself.
    pub fn token_mint(
        actor: &str,
        route: &str,
        owner: &str,
        role: &dyn std::fmt::Display,
        ttl_secs: u64,
    ) -> Self {
        Self::new(
            "token_mint",
            actor,
            owner,
            route,
            &format!("role={role} ttl_secs={ttl_secs}"),
        )
    }

    pub fn new(action: &str, actor: &str, artifact: &str, registry: &str, detail: &str) -> Self {
        Self {
            ts: Utc::now(),
            action: action.to_string(),
            actor: actor.to_string(),
            artifact: artifact.to_string(),
            registry: registry.to_string(),
            detail: detail.to_string(),
        }
    }
}

/// Size-based rotation of the audit file. `max_bytes == 0` never rotates.
#[derive(Debug, Clone, Copy, Default)]
pub struct Rotation {
    pub max_bytes: u64,
    pub keep: u32,
}

impl From<&crate::config::AuditConfig> for Rotation {
    fn from(cfg: &crate::config::AuditConfig) -> Self {
        Self {
            max_bytes: cfg.max_size_mb.saturating_mul(1024 * 1024),
            keep: cfg.max_files,
        }
    }
}

/// The open audit file plus what rotation needs to know about it.
struct FileSink {
    file: fs::File,
    path: PathBuf,
    size: u64,
    rotation: Rotation,
}

impl FileSink {
    fn write_line(&mut self, json: &str) {
        let len = json.len() as u64 + 1;
        if self.rotation.max_bytes > 0 && self.size > 0 && self.size + len > self.rotation.max_bytes
        {
            self.rotate();
        }
        // One write per line: a kill between the JSON and the newline would glue
        // the next entry onto it.
        if let Err(e) = self.file.write_all(format!("{json}\n").as_bytes()) {
            tracing::error!(error = %e, "Audit log write failed");
        }
        if let Err(e) = self.file.flush() {
            tracing::error!(error = %e, "Audit log flush failed");
        }
        self.size += len;
    }

    /// Shift `audit.jsonl.{n}` → `.{n+1}` (the rename over `.{keep}` drops the
    /// oldest), move the live file to `.1` and reopen. On failure the entry goes
    /// to the current file and the next attempt waits another `max_bytes`.
    fn rotate(&mut self) {
        let numbered = |n: u32| {
            let mut p = self.path.clone().into_os_string();
            p.push(format!(".{n}"));
            PathBuf::from(p)
        };
        for n in (1..self.rotation.keep).rev() {
            let _ = fs::rename(numbered(n), numbered(n + 1));
        }
        let moved = if self.rotation.keep == 0 {
            fs::remove_file(&self.path)
        } else {
            fs::rename(&self.path, numbered(1))
        };
        let reopened = moved.and_then(|()| open_append(&self.path));
        match reopened {
            Ok(f) => self.file = f,
            Err(e) => {
                tracing::error!(path = %self.path.display(), error = %e, "Audit log rotation failed")
            }
        }
        self.size = 0;
    }
}

/// Owner-only on create; an existing file keeps its mode.
fn open_append(path: &Path) -> std::io::Result<fs::File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
}

/// Open `path` for appending, terminating a tail torn by a kill so the next entry
/// starts a line.
fn open_sink(path: PathBuf, rotation: Rotation) -> Option<FileSink> {
    match open_append(&path) {
        Ok(mut file) => {
            let mut size = file.metadata().map(|m| m.len()).unwrap_or(0);
            if !tail_is_terminated(&path).unwrap_or(true) && file.write_all(b"\n").is_ok() {
                size += 1;
            }
            Some(FileSink {
                file,
                path,
                size,
                rotation,
            })
        }
        Err(e) => {
            warn!(path = %path.display(), error = %e, "Failed to open audit log file");
            None
        }
    }
}

/// True when `path` is missing, empty, or ends with a newline.
fn tail_is_terminated(path: &Path) -> std::io::Result<bool> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(e) => return Err(e),
    };
    if file.metadata()?.len() == 0 {
        return Ok(true);
    }
    file.seek(SeekFrom::End(-1))?;
    let mut last = [0u8; 1];
    file.read_exact(&mut last)?;
    Ok(last[0] == b'\n')
}

pub struct AuditLog {
    path: PathBuf,
    mode: AuditMode,
    /// Channel sender, wrapped in Mutex<Option<>> so `shutdown()` can take it
    /// through `&self` (needed because AuditLog is behind Arc in AppState).
    sender: Mutex<Option<mpsc::Sender<AuditEntry>>>,
    /// Handle to the background writer task, used for graceful shutdown.
    writer_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl AuditLog {
    /// Audit log without file rotation.
    pub fn new(storage_path: &str, mode: AuditMode) -> Self {
        Self::with_rotation(storage_path, mode, Rotation::default())
    }

    pub fn with_rotation(storage_path: &str, mode: AuditMode, rotation: Rotation) -> Self {
        let path = PathBuf::from(storage_path).join("audit.jsonl");

        if mode == AuditMode::Off {
            info!("Audit log disabled (mode=off)");
            return Self {
                path,
                mode,
                sender: Mutex::new(None),
                writer_handle: Mutex::new(None),
            };
        }

        // Open file handles if needed. Reads get half the size budget, so the two chains
        // together stay within 1.5x what one chain used to take.
        let (writes, reads) = if mode == AuditMode::File || mode == AuditMode::Both {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let reads_rotation = Rotation {
                max_bytes: rotation.max_bytes.div_ceil(2),
                keep: rotation.keep,
            };
            info!(path = %path.display(), mode = ?mode, "Audit log initialized");
            (
                open_sink(path.clone(), rotation),
                open_sink(path.with_file_name(READS_FILE), reads_rotation),
            )
        } else {
            info!(mode = ?mode, "Audit log initialized (stderr only)");
            (None, None)
        };

        let (tx, rx) = mpsc::channel(AUDIT_CHANNEL_BOUND);

        debug_assert!(
            mode != AuditMode::Off,
            "channel should not be created when mode is Off"
        );

        let writer_mode = mode.clone();
        // Without its writer the audit log would take entries and record none, so a panic
        // there ends the process with `EXIT_TASK_PANICKED` (`supervise::blocking`).
        let handle = tokio::task::spawn_blocking(move || {
            let exit = crate::supervise::process_exit();
            crate::supervise::blocking("audit", &exit, move || {
                Self::writer_loop(rx, writes, reads, writer_mode)
            });
        });

        Self {
            path,
            mode,
            sender: Mutex::new(Some(tx)),
            writer_handle: Mutex::new(Some(handle)),
        }
    }

    /// Background writer loop — receives entries from the channel and writes
    /// them to file/stderr. Runs until the channel is closed (all senders dropped).
    fn writer_loop(
        mut rx: mpsc::Receiver<AuditEntry>,
        mut writes: Option<FileSink>,
        mut reads: Option<FileSink>,
        mode: AuditMode,
    ) {
        // blocking_recv() blocks the current thread until an entry arrives
        // or the channel is closed. This is correct because we're inside
        // spawn_blocking.
        while let Some(entry) = rx.blocking_recv() {
            #[cfg(test)]
            if entry.action == tests::WRITER_PANIC {
                panic!("a bug in the audit writer");
            }
            #[cfg(feature = "fault-injection")]
            if crate::fault_injection::task_fault("audit") {
                panic!("fault injection: audit task panic");
            }
            Self::write_entry(&entry, &mut writes, &mut reads, &mode);
        }

        // Channel closed — drain any remaining buffered entries
        while let Ok(entry) = rx.try_recv() {
            Self::write_entry(&entry, &mut writes, &mut reads, &mode);
        }

        // Final flush on shutdown
        for f in [&mut writes, &mut reads].into_iter().flatten() {
            if let Err(e) = f.file.flush() {
                tracing::error!(error = %e, "Audit log final flush failed");
            }
        }
    }

    /// Write a single audit entry to file and/or stderr.
    fn write_entry(
        entry: &AuditEntry,
        writes: &mut Option<FileSink>,
        reads: &mut Option<FileSink>,
        mode: &AuditMode,
    ) {
        let json = match serde_json::to_string(entry) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!(error = %e, "Audit log serialization failed");
                return;
            }
        };

        if *mode == AuditMode::File || *mode == AuditMode::Both {
            let file = if is_read_event(&entry.action) {
                reads
            } else {
                writes
            };
            if let Some(f) = file {
                f.write_line(&json);
            }
        }

        if *mode == AuditMode::Stdout || *mode == AuditMode::Both {
            eprintln!("{}", json);
        }
    }

    /// Send an audit entry to the background writer (#543).
    ///
    /// Infallible and non-blocking: if the channel is full (extreme backpressure),
    /// see [`Self::overflow`]. If the channel is closed (shutdown), the entry is
    /// silently discarded.
    pub fn log(&self, entry: AuditEntry) {
        if self.mode == AuditMode::Off {
            return;
        }

        if let Some(ref sender) = *self.sender.lock() {
            if let Err(mpsc::error::TrySendError::Full(entry)) = sender.try_send(entry) {
                Self::overflow(&entry);
            }
            // TrySendError::Closed is silently ignored — happens during shutdown
        }
    }

    /// An entry the full channel refused: a read is dropped, a write goes to stderr at
    /// once, so a flood of reads cannot lose a write record. True when it was kept.
    fn overflow(entry: &AuditEntry) -> bool {
        if is_read_event(&entry.action) {
            warn!("Audit log channel full — read entry dropped (backpressure)");
            return false;
        }
        warn!("Audit log channel full — write entry sent to stderr (backpressure)");
        if let Ok(json) = serde_json::to_string(entry) {
            eprintln!("{json}");
        }
        true
    }

    /// Graceful shutdown: close the channel and wait for the writer to drain.
    ///
    /// Must be called AFTER all background schedulers have finished (#543),
    /// so their final audit entries are captured.
    pub async fn shutdown(&self) {
        // Drop the sender to close the channel
        self.sender.lock().take();

        // Take the handle out of the mutex BEFORE awaiting (avoid holding
        // MutexGuard across .await)
        let handle = self.writer_handle.lock().take();

        // Wait for the writer task to finish draining
        if let Some(handle) = handle {
            if let Err(e) = handle.await {
                tracing::error!(error = %e, "Audit log writer task panicked");
            }
        }
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub fn mode(&self) -> &AuditMode {
        &self.mode
    }
}

/// Records each download curation refused: a refusal leaves its handler as a
/// `CurationRefusal` response extension, and this layer — inside auth, so it knows the
/// caller — writes one `curation_block` entry for it. One layer covers every refusal site
/// (`check_download`, `check_namespace_isolation`, `verify_integrity`) instead of each
/// taking the audit log and the caller.
pub async fn curation_refusal_middleware(
    axum::extract::State(state): axum::extract::State<crate::AppState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let actor = request
        .extensions()
        .get::<crate::auth::AuthenticatedUser>()
        .map_or_else(|| "anonymous".to_string(), |user| user.0.clone());
    let response = next.run(request).await;
    if let Some(refusal) = response
        .extensions()
        .get::<crate::curation::CurationRefusal>()
    {
        state.audit.log(AuditEntry::new(
            "curation_block",
            &actor,
            &format!(
                "{}@{}",
                refusal.package,
                refusal.version.as_deref().unwrap_or("*")
            ),
            &refusal.registry,
            &format!("{}: {}", refusal.rule, refusal.reason),
        ));
    }
    response
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// An entry whose action this is makes the writer panic.
    pub(super) const WRITER_PANIC: &str = "test-writer-panic";

    /// A panic in the writer of the server's audit log ends the process with the code its
    /// units restart on: the log would otherwise take entries and record none.
    #[tokio::test]
    async fn a_writer_panic_ends_the_process() {
        let exits = || {
            crate::supervise::exits_requested()
                .into_iter()
                .filter(|code| *code == crate::supervise::EXIT_TASK_PANICKED)
                .count()
        };
        let before = exits();
        let tmp = TempDir::new().unwrap();
        let log = AuditLog::new(tmp.path().to_str().unwrap(), AuditMode::File);
        log.log(AuditEntry::new("pull", "user1", "lodash", "npm", ""));
        log.log(AuditEntry::new(WRITER_PANIC, "user1", "lodash", "npm", ""));
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while exits() == before {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the writer's panic did not end the process"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(exits(), before + 1);
    }

    #[test]
    fn test_audit_entry_new() {
        let entry = AuditEntry::new(
            "push",
            "admin",
            "nginx:latest",
            "docker",
            "uploaded manifest",
        );
        assert_eq!(entry.action, "push");
        assert_eq!(entry.actor, "admin");
        assert_eq!(entry.artifact, "nginx:latest");
        assert_eq!(entry.registry, "docker");
        assert_eq!(entry.detail, "uploaded manifest");
    }

    #[test]
    fn test_audit_log_new_and_path() {
        // AuditLog::new() spawns a tokio task, so we need a runtime
        let rt = tokio::runtime::Runtime::new().unwrap();
        let tmp = TempDir::new().unwrap();
        let log =
            rt.block_on(async { AuditLog::new(tmp.path().to_str().unwrap(), AuditMode::File) });
        assert!(log.path().ends_with("audit.jsonl"));
    }

    #[tokio::test]
    async fn test_audit_log_write_entry() {
        let tmp = TempDir::new().unwrap();
        let log = AuditLog::new(tmp.path().to_str().unwrap(), AuditMode::File);

        let entry = AuditEntry::new("pull", "user1", "lodash", "npm", "downloaded");
        log.log(entry);

        // Wait for writer to process by shutting down (drains channel)
        let path = log.path().with_file_name(READS_FILE);
        log.shutdown().await;

        let content = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(content.contains(r#""action":"pull""#));
        assert!(content.contains(r#""actor":"user1""#));
        assert!(content.contains(r#""artifact":"lodash""#));
    }

    #[tokio::test]
    async fn test_audit_log_multiple_entries() {
        let tmp = TempDir::new().unwrap();
        let log = AuditLog::new(tmp.path().to_str().unwrap(), AuditMode::File);

        log.log(AuditEntry::new("push", "admin", "a", "docker", ""));
        log.log(AuditEntry::new("pull", "user", "b", "npm", ""));
        log.log(AuditEntry::new("delete", "admin", "c", "maven", ""));

        let path = log.path().clone();
        log.shutdown().await;

        let content = std::fs::read_to_string(&path).unwrap_or_default();
        let reads = read(&path.with_file_name(READS_FILE));
        assert_eq!(content.lines().count(), 2, "push and delete: {content}");
        assert_eq!(reads.lines().count(), 1, "the pull: {reads}");
        assert!(reads.contains(r#""action":"pull""#));
    }

    #[test]
    fn test_audit_entry_serialization() {
        let entry = AuditEntry::new("push", "ci", "app:v1", "docker", "ci build");
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains(r#""action":"push""#));
        assert!(json.contains(r#""ts":""#));
    }

    #[test]
    fn test_audit_mode_from_str() {
        assert_eq!("stdout".parse::<AuditMode>().unwrap(), AuditMode::Stdout);
        assert_eq!("stderr".parse::<AuditMode>().unwrap(), AuditMode::Stdout);
        assert_eq!("both".parse::<AuditMode>().unwrap(), AuditMode::Both);
        assert_eq!("off".parse::<AuditMode>().unwrap(), AuditMode::Off);
        assert_eq!("none".parse::<AuditMode>().unwrap(), AuditMode::Off);
        assert_eq!("false".parse::<AuditMode>().unwrap(), AuditMode::Off);
        assert_eq!("0".parse::<AuditMode>().unwrap(), AuditMode::Off);
        assert_eq!("file".parse::<AuditMode>().unwrap(), AuditMode::File);
    }

    #[test]
    fn test_audit_mode_rejects_invalid() {
        assert!("anything".parse::<AuditMode>().is_err());
        assert!("flie".parse::<AuditMode>().is_err());
        assert!("".parse::<AuditMode>().is_err());
        let err = "typo".parse::<AuditMode>().unwrap_err();
        assert!(
            err.contains("file"),
            "error should list valid values: {err}"
        );
    }

    #[test]
    fn test_audit_mode_display_roundtrip() {
        for mode in [
            AuditMode::File,
            AuditMode::Stdout,
            AuditMode::Both,
            AuditMode::Off,
        ] {
            let s = mode.to_string();
            let parsed: AuditMode = s.parse().unwrap();
            assert_eq!(mode, parsed);
        }
    }

    fn read(path: &std::path::Path) -> String {
        std::fs::read_to_string(path).unwrap_or_default()
    }

    /// Past `max_bytes` the live file moves to `.1`, older files shift up and
    /// the one past `keep` is dropped: disk use stays bounded.
    #[tokio::test]
    async fn test_audit_log_rotates_by_size_and_keeps_n() {
        let tmp = TempDir::new().unwrap();
        // One timestamp for every entry: chrono writes 0, 3, 6 or 9 fractional digits, so
        // entries stamped `now` differ in length and "two per file" would hold only by luck.
        let ts = Utc::now();
        let entry = |artifact: &str| AuditEntry {
            ts,
            ..AuditEntry::new("push", "u", artifact, "raw", "")
        };
        let line_len = serde_json::to_string(&entry("a0")).unwrap().len() as u64 + 1;
        // Two entries per file.
        let rotation = Rotation {
            max_bytes: line_len * 2,
            keep: 2,
        };
        let log = AuditLog::with_rotation(tmp.path().to_str().unwrap(), AuditMode::File, rotation);
        for i in 0..7 {
            log.log(entry(&format!("a{i}")));
        }
        let path = log.path().clone();
        log.shutdown().await;

        let live = read(&path);
        let one = read(&tmp.path().join("audit.jsonl.1"));
        let two = read(&tmp.path().join("audit.jsonl.2"));
        assert_eq!(live.lines().count(), 1, "live: {live}");
        assert!(live.contains(r#""artifact":"a6""#));
        assert!(one.contains(r#""artifact":"a4""#) && one.contains(r#""artifact":"a5""#));
        assert!(two.contains(r#""artifact":"a2""#) && two.contains(r#""artifact":"a3""#));
        assert!(
            !tmp.path().join("audit.jsonl.3").exists(),
            "files past max_files must be deleted"
        );
        for f in [&live, &one, &two] {
            assert!(f.len() as u64 <= rotation.max_bytes);
        }
    }

    /// The size check counts what is already on disk: a restart does not reset
    /// the budget of an existing file.
    #[tokio::test]
    async fn test_audit_log_rotation_counts_existing_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("audit.jsonl");
        std::fs::write(&path, "x".repeat(100) + "\n").unwrap();
        let rotation = Rotation {
            max_bytes: 120,
            keep: 1,
        };
        let log = AuditLog::with_rotation(tmp.path().to_str().unwrap(), AuditMode::Both, rotation);
        log.log(AuditEntry::new("push", "u", "after-restart", "raw", ""));
        log.shutdown().await;

        assert!(read(&tmp.path().join("audit.jsonl.1")).starts_with("xxx"));
        assert!(read(&path).contains("after-restart"));
    }

    /// `max_bytes == 0` (and `AuditLog::new`) never rotates.
    #[tokio::test]
    async fn test_audit_log_rotation_disabled() {
        let tmp = TempDir::new().unwrap();
        let log = AuditLog::with_rotation(
            tmp.path().to_str().unwrap(),
            AuditMode::File,
            Rotation {
                max_bytes: 0,
                keep: 3,
            },
        );
        for i in 0..20 {
            log.log(AuditEntry::new("push", "u", &format!("a{i}"), "raw", ""));
        }
        let path = log.path().clone();
        log.shutdown().await;
        assert_eq!(read(&path).lines().count(), 20);
        assert!(!tmp.path().join("audit.jsonl.1").exists());
    }

    #[test]
    fn test_rotation_from_config() {
        let cfg = crate::config::AuditConfig::default();
        let r = Rotation::from(&cfg);
        assert_eq!(r.max_bytes, 100 * 1024 * 1024);
        assert_eq!(r.keep, 5);
    }

    /// A018: however many reads are logged, a write record stays in `audit.jsonl`;
    /// the reads rotate in their own bounded chain at half the size.
    #[tokio::test]
    async fn reads_cannot_rotate_a_write_record_out() {
        let tmp = TempDir::new().unwrap();
        let rotation = Rotation {
            max_bytes: 4096,
            keep: 2,
        };
        let log = AuditLog::with_rotation(tmp.path().to_str().unwrap(), AuditMode::File, rotation);
        log.log(AuditEntry::new("push", "alice", "v398/a.txt", "raw", ""));
        for _ in 0..1000 {
            // The entry a served raw download writes.
            log.log(AuditEntry::new("pull", "proxy", "", "raw", ""));
        }
        let path = log.path().clone();
        log.shutdown().await;

        assert!(
            read(&path).contains(r#""action":"push""#),
            "write record lost"
        );
        let reads = path.with_file_name(READS_FILE);
        let numbered = |n: u32| PathBuf::from(format!("{}.{n}", reads.display()));
        assert!(numbered(2).exists(), "1000 reads must have rotated");
        assert!(!numbered(3).exists(), "reads chain must stay bounded");
        for f in [reads.clone(), numbered(1), numbered(2)] {
            let text = read(&f);
            assert!(!text.contains(r#""action":"push""#), "{}", f.display());
            assert!(
                text.len() as u64 <= rotation.max_bytes / 2,
                "{}",
                f.display()
            );
        }
    }

    /// Unknown actions count as writes, so a new state-changing action keeps the
    /// protected budget.
    #[test]
    fn only_known_downloads_are_reads() {
        for read in ["pull", "cache_hit", "proxy_fetch", "curation_block"] {
            assert!(is_read_event(read), "{read}");
        }
        for write in [
            "push",
            "delete",
            "token_mint",
            "overwrite",
            "some_new_action",
        ] {
            assert!(!is_read_event(write), "{write}");
        }
    }

    /// A018: when the channel is full a read is dropped but a write is kept (on
    /// stderr), so a flood of reads cannot lose a write record.
    #[tokio::test]
    async fn a_full_channel_keeps_write_records() {
        let (tx, mut rx) = mpsc::channel(1);
        let log = AuditLog {
            path: PathBuf::from("unused"),
            mode: AuditMode::File,
            sender: Mutex::new(Some(tx)),
            writer_handle: Mutex::new(None),
        };
        let pull = || AuditEntry::new("pull", "proxy", "", "raw", "");
        let push = || AuditEntry::new("push", "alice", "a.txt", "raw", "");
        log.log(pull());
        // Channel full from here on.
        log.log(push());
        log.log(pull());
        assert_eq!(rx.recv().await.unwrap().action, "pull");
        assert!(rx.try_recv().is_err(), "the channel held only one entry");
        assert!(AuditLog::overflow(&push()), "a write must be kept");
        assert!(!AuditLog::overflow(&pull()), "a read is dropped");
    }

    /// B27: audit files are created owner-only whatever the umask, the rotated
    /// ones too.
    #[tokio::test]
    async fn audit_files_are_created_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let log = AuditLog::with_rotation(
            tmp.path().to_str().unwrap(),
            AuditMode::File,
            Rotation {
                max_bytes: 1,
                keep: 1,
            },
        );
        for action in ["push", "push", "pull", "pull"] {
            log.log(AuditEntry::new(action, "u", "a", "raw", ""));
        }
        log.shutdown().await;
        for name in [
            "audit.jsonl",
            "audit.jsonl.1",
            "audit-reads.jsonl",
            "audit-reads.jsonl.1",
        ] {
            let mode = fs::metadata(tmp.path().join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{name} mode {mode:o}");
        }
    }

    /// B28: the binary default also writes to stderr, so a non-chart install ships audit
    /// records off the host through its log pipeline; the two defaults cannot drift.
    #[test]
    fn default_audit_mode_is_both() {
        assert_eq!(AuditMode::default(), AuditMode::Both);
        assert_eq!(crate::config::AuditConfig::default().mode, AuditMode::Both);
    }

    #[tokio::test]
    async fn test_audit_log_off_mode() {
        let tmp = TempDir::new().unwrap();
        let log = AuditLog::new(tmp.path().to_str().unwrap(), AuditMode::Off);
        assert_eq!(log.mode(), &AuditMode::Off);
        // Should not panic even when logging to Off mode
        log.log(AuditEntry::new("test", "test", "test", "test", "test"));
    }
}

/// A download refused by curation leaves one entry in `audit-reads.jsonl` (who / what /
/// registry / rule), as push, delete, proxy_fetch, cache_hit and pull do. The test context opts into the file audit log the way an
/// operator does (`NORA_AUDIT_LOG=file`) and requests go through the whole router,
/// so the test holds wherever the entry is written — handler or middleware.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod curation_refusal_audit_tests {
    use super::*;
    use crate::test_helpers::{create_test_context_with_config, send, TestContext};
    use axum::http::{Method, StatusCode};
    use tempfile::TempDir;

    const CPAN_AUTHOR: &str = "/cpan/authors/id/A/AU/AUTHOR";

    /// Curation in enforce mode with both refusal kinds: a blocklist rule for raw
    /// (hosted) and an allowlist for CPAN (proxy). The four files are seeded straight
    /// into storage, so the audit log starts empty. The policy directory is returned
    /// to keep it alive.
    async fn audited_context() -> (TestContext, TempDir) {
        let policy = TempDir::new().unwrap();
        let blocklist = policy.path().join("blocklist.json");
        std::fs::write(
            &blocklist,
            r#"{"version": 1, "rules": [{"registry": "raw", "name": "secret*", "version": "*", "reason": "blocked"}]}"#,
        )
        .unwrap();
        let allowlist = policy.path().join("allowlist.json");
        std::fs::write(
            &allowlist,
            r#"{"version": 1, "entries": [{"registry": "cpan", "name": "Foo-Bar", "version": "1.0"}]}"#,
        )
        .unwrap();
        let blocklist = blocklist.to_string_lossy().into_owned();
        let allowlist = allowlist.to_string_lossy().into_owned();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.audit.mode = AuditMode::File;
            cfg.cpan.enabled = true;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist);
            cfg.curation.allowlist_path = Some(allowlist);
        });
        for key in [
            "raw/secret.txt",
            "raw/public.txt",
            "cpan/authors/id/A/AU/AUTHOR/Foo-Bar-1.0.tar.gz",
            "cpan/authors/id/A/AU/AUTHOR/Other-Dist-2.0.tar.gz",
        ] {
            ctx.state.storage.put(key, b"data").await.unwrap();
        }
        (ctx, policy)
    }

    /// Drain the writer and parse every line of `audit.jsonl`, then of `audit-reads.jsonl`.
    async fn written_entries(audit: &AuditLog) -> Vec<serde_json::Value> {
        let path = audit.path().clone();
        audit.shutdown().await;
        [path.clone(), path.with_file_name(READS_FILE)]
            .iter()
            .flat_map(|p| {
                std::fs::read_to_string(p)
                    .unwrap_or_default()
                    .lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    fn blocked_downloads() -> u64 {
        crate::metrics::CURATION_DECISIONS_TOTAL
            .with_label_values(&["block"])
            .get()
    }

    #[tokio::test]
    async fn a_refused_download_leaves_one_audit_entry() {
        let (ctx, _policy) = audited_context().await;
        let blocks_before = blocked_downloads();

        // A blocklisted raw file, and a CPAN distribution the allowlist misses.
        let refusals = [
            (
                "raw",
                "/raw/secret.txt".to_string(),
                "secret.txt",
                "blocklist",
            ),
            (
                "cpan",
                format!("{CPAN_AUTHOR}/Other-Dist-2.0.tar.gz"),
                "Other-Dist",
                "allowlist",
            ),
        ];
        for (_, uri, _, rule) in &refusals {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{uri}");
            assert_eq!(resp.headers()["x-nora-decision"], "blocked", "{uri}");
            assert_eq!(resp.headers()["x-nora-rule"], *rule, "{uri}");
        }
        // The block counter moved (other tests only ever add to it) ...
        assert!(
            blocked_downloads() >= blocks_before + 2,
            "nora_curation_decisions_total{{decision=\"block\"}} must count both refusals"
        );

        // ... and each refusal must be in the audit trail, once.
        let entries = written_entries(&ctx.state.audit).await;
        let per_registry: Vec<(&str, usize)> = refusals
            .iter()
            .map(|(registry, ..)| {
                let hits = entries.iter().filter(|e| e["registry"] == *registry);
                (*registry, hits.count())
            })
            .collect();
        assert_eq!(
            per_registry,
            [("raw", 1), ("cpan", 1)],
            "each download refused by curation must leave one audit entry; \
             audit.jsonl = {entries:?}"
        );
        for (registry, _, artifact, rule) in &refusals {
            let entry = entries.iter().find(|e| e["registry"] == *registry).unwrap();
            assert!(
                !entry["actor"].as_str().unwrap_or("").is_empty(),
                "who: {entry}"
            );
            assert!(
                entry["artifact"].as_str().unwrap_or("").contains(artifact),
                "what: {entry}"
            );
            assert!(entry.to_string().contains(rule), "rule: {entry}");
        }
    }

    /// Each entry names the refusal exactly as the client was told it: action
    /// `curation_block`, the caller (`anonymous`, or the user who signed in), the
    /// artifact as `package@version` and the detail as `rule: reason` from the 403 body —
    /// for a blocklist hit and for a namespace-isolation refusal alike.
    #[tokio::test]
    async fn a_refusal_entry_names_the_caller_artifact_and_rule() {
        let policy = TempDir::new().unwrap();
        let blocklist = policy.path().join("blocklist.json");
        std::fs::write(
            &blocklist,
            r#"{"version": 1, "rules": [{"registry": "raw", "name": "secret*", "version": "*", "reason": "blocked"}]}"#,
        )
        .unwrap();
        let blocklist = blocklist.to_string_lossy().into_owned();
        // Every request signs in: with `anonymous_read` a read is served as `anonymous`
        // whatever credentials it carries, so the caller could not be told apart.
        let ctx = crate::test_helpers::create_test_context_with_auth_and_config(
            &[("alice", "pw"), ("bob", "pw")],
            move |cfg| {
                cfg.audit.mode = AuditMode::File;
                cfg.curation.mode = crate::config::CurationMode::Enforce;
                cfg.curation.blocklist_path = Some(blocklist);
                cfg.curation.internal_namespaces = vec!["internal-*".to_string()];
            },
        );
        ctx.state
            .storage
            .put("raw/secret.txt", b"data")
            .await
            .unwrap();

        // base64("alice:pw"), base64("bob:pw")
        let alice = || vec![("authorization", "Basic YWxpY2U6cHc=")];
        let bob = || vec![("authorization", "Basic Ym9iOnB3")];
        let mut expected = Vec::new();
        for (uri, headers, actor) in [
            ("/raw/secret.txt", alice(), "alice"),
            ("/raw/secret.txt", bob(), "bob"),
            ("/simple/internal-secret/", alice(), "alice"),
        ] {
            let resp =
                crate::test_helpers::send_with_headers(&ctx.app, Method::GET, uri, headers, "")
                    .await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{uri}");
            let body: serde_json::Value =
                serde_json::from_slice(&crate::test_helpers::body_bytes(resp).await).unwrap();
            let c = &body["context"];
            expected.push(serde_json::json!({
                "action": "curation_block",
                "actor": actor,
                "artifact": format!("{}@{}", c["package"].as_str().unwrap(), c["version"].as_str().unwrap()),
                "registry": c["registry"],
                "detail": format!("{}: {}", c["rule"].as_str().unwrap(), c["reason"].as_str().unwrap()),
            }));
        }
        let entries: Vec<serde_json::Value> = written_entries(&ctx.state.audit)
            .await
            .into_iter()
            .filter(|e| e["action"] == "curation_block")
            .map(|mut e| {
                e.as_object_mut().unwrap().remove("ts");
                e
            })
            .collect();
        assert_eq!(entries, expected);
    }

    /// Control for the test above: the same context and policy, with downloads that
    /// curation allows — each leaves its one existing audit entry, so the harness
    /// captures what these routes write. The reads land in `audit-reads.jsonl`, a hosted
    /// upload in `audit.jsonl` (A018).
    #[tokio::test]
    async fn allowed_downloads_keep_their_audit_entries() {
        let (ctx, _policy) = audited_context().await;

        let resp = send(&ctx.app, Method::GET, "/raw/public.txt", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let uri = format!("{CPAN_AUTHOR}/Foo-Bar-1.0.tar.gz");
        let resp = send(&ctx.app, Method::GET, &uri, "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = send(&ctx.app, Method::PUT, "/raw/new.txt", "data").await;
        assert!(resp.status().is_success(), "{}", resp.status());

        let path = ctx.state.audit.path().clone();
        let entries = written_entries(&ctx.state.audit).await;
        let actions: Vec<(&str, &str)> = entries
            .iter()
            .map(|e| {
                (
                    e["registry"].as_str().unwrap(),
                    e["action"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            actions,
            [("raw", "push"), ("raw", "pull"), ("cpan", "cache_hit")]
        );
        let writes = std::fs::read_to_string(&path).unwrap();
        assert_eq!(writes.lines().count(), 1, "only the push: {writes}");
        assert!(writes.contains(r#""action":"push""#));
    }
}

/// Every refusal kind — an allowlist miss with a known version, an integrity mismatch, a
/// blocklist hit on a nested raw path with a reason in Cyrillic and with a line break (which
/// no header can carry) — leaves exactly the entry the 403 body describes.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod curation_refusal_audit_kinds {
    use super::*;
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use tempfile::TempDir;

    #[tokio::test]
    async fn each_refusal_kind_is_recorded_as_its_body_says() {
        let policy = TempDir::new().unwrap();
        let blocklist = policy.path().join("blocklist.json");
        std::fs::write(
            &blocklist,
            r#"{"version": 1, "rules": [{"registry": "raw", "name": "dir/secret.txt", "version": "*", "reason": "заблокировано\nполитикой"}]}"#,
        )
        .unwrap();
        let allowlist = policy.path().join("allowlist.json");
        std::fs::write(
            &allowlist,
            r#"{"version": 1, "entries": [{"registry": "cpan", "name": "Foo-Bar", "version": "1.0", "integrity": "sha256:0000000000000000000000000000000000000000000000000000000000000000", "integrity_source": "manual"}]}"#,
        )
        .unwrap();
        let blocklist = blocklist.to_string_lossy().into_owned();
        let allowlist = allowlist.to_string_lossy().into_owned();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.audit.mode = AuditMode::File;
            cfg.cpan.enabled = true;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist);
            cfg.curation.allowlist_path = Some(allowlist);
        });
        for key in [
            "raw/dir/secret.txt",
            "cpan/authors/id/A/AU/AUTHOR/Foo-Bar-1.0.tar.gz",
            "cpan/authors/id/A/AU/AUTHOR/Other-Dist-2.0.tar.gz",
        ] {
            ctx.state.storage.put(key, b"data").await.unwrap();
        }
        let mut expected = Vec::new();
        for uri in [
            "/raw/dir/secret.txt",
            "/cpan/authors/id/A/AU/AUTHOR/Foo-Bar-1.0.tar.gz",
            "/cpan/authors/id/A/AU/AUTHOR/Other-Dist-2.0.tar.gz",
        ] {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{uri}");
            let body: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
            let c = &body["context"];
            expected.push(serde_json::json!({
                "action": "curation_block",
                "actor": "anonymous",
                "artifact": format!("{}@{}", c["package"].as_str().unwrap(), c["version"].as_str().unwrap()),
                "registry": c["registry"],
                "detail": format!("{}: {}", c["rule"].as_str().unwrap(), c["reason"].as_str().unwrap()),
            }));
        }
        let path = ctx.state.audit.path().with_file_name(READS_FILE);
        ctx.state.audit.shutdown().await;
        let entries: Vec<serde_json::Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .filter(|e| e["action"] == "curation_block")
            .map(|mut e| {
                e.as_object_mut().unwrap().remove("ts");
                e
            })
            .collect();
        assert_eq!(entries, expected);
        // The cases must keep covering a known version, a nested path, integrity and non-ASCII.
        let text = serde_json::to_string(&expected).unwrap();
        for needle in [
            "Other-Dist@2.0",
            "dir/secret.txt@*",
            "integrity",
            "заблокировано",
        ] {
            assert!(text.contains(needle), "lost {needle}: {text}");
        }
    }
}

/// the docker blob path refuses through two sites the other tests do not
/// reach — `check_download` in the blob handler and `verify_integrity_by_hash` for a stored
/// blob. Each refusal must leave exactly the entry its 403 body describes.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod curation_refusal_audit_docker {
    use super::*;
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use tempfile::TempDir;

    #[tokio::test]
    async fn docker_blob_refusals_are_recorded() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let policy = TempDir::new().unwrap();
        let blocklist = policy.path().join("blocklist.json");
        std::fs::write(
            &blocklist,
            r#"{"version": 1, "rules": [{"registry": "docker", "name": "blocked*", "version": "*", "reason": "blocked"}]}"#,
        )
        .unwrap();
        let allowlist = policy.path().join("allowlist.json");
        std::fs::write(
            &allowlist,
            format!(
                r#"{{"version": 1, "entries": [{{"registry": "docker", "name": "alpine", "version": "{digest}", "integrity": "sha256:{}", "integrity_source": "manual"}}]}}"#,
                "0".repeat(64)
            ),
        )
        .unwrap();
        let blocklist = blocklist.to_string_lossy().into_owned();
        let allowlist = allowlist.to_string_lossy().into_owned();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.audit.mode = AuditMode::File;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist);
            cfg.curation.allowlist_path = Some(allowlist);
        });
        ctx.state
            .storage
            .put(&format!("docker/alpine/blobs/{digest}"), b"data")
            .await
            .unwrap();
        let mut expected = Vec::new();
        for uri in [
            format!("/v2/blocked/blobs/{digest}"),
            format!("/v2/alpine/blobs/{digest}"),
        ] {
            let resp = send(&ctx.app, Method::GET, &uri, "").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{uri}");
            let body: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
            let c = &body["context"];
            expected.push(serde_json::json!({
                "action": "curation_block",
                "actor": "anonymous",
                "artifact": format!("{}@{}", c["package"].as_str().unwrap(), c["version"].as_str().unwrap()),
                "registry": c["registry"],
                "detail": format!("{}: {}", c["rule"].as_str().unwrap(), c["reason"].as_str().unwrap()),
            }));
        }
        let text = serde_json::to_string(&expected).unwrap();
        assert!(
            text.contains("allowlist:integrity"),
            "integrity case lost: {text}"
        );
        let path = ctx.state.audit.path().with_file_name(READS_FILE);
        ctx.state.audit.shutdown().await;
        let entries: Vec<serde_json::Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .filter(|e| e["action"] == "curation_block")
            .map(|mut e| {
                e.as_object_mut().unwrap().remove("ts");
                e
            })
            .collect();
        assert_eq!(entries, expected);
    }
}
