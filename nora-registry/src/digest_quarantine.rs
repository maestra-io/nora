// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Digest quarantine — first-seen tracking for proxy-fetched artifacts.
//!
//! Tracks when a content digest was first seen by NORA's proxy layer.
//! New digests can be held in quarantine for a configurable duration,
//! providing a time-based supply chain defense for registries that lack
//! upstream publish dates (e.g. Docker/OCI).
//!
//! Persistence: one object per entry under [`ENTRY_PREFIX`] in the storage
//! backend, written with `put_if_absent` (first writer wins, also across
//! replicas), plus a boot-time snapshot of the whole map so a start reads one
//! object and a listing instead of one GET per entry. A legacy
//! `{storage.path}/quarantine.jsonl` is imported at every boot.
//! Fail-open: unreadable entries or a failed listing → those digests unknown.

use axum::body::Bytes;
use chrono::Utc;
use futures::StreamExt;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use tracing::{error, info, warn};

use axum::http::{header, HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::storage::{Storage, StorageError};

/// Legacy ledger file name under `storage.path`, imported at boot (Maestra).
pub const LEDGER_FILE: &str = "quarantine.jsonl";

/// Per-entry objects: `.nora-quarantine/<registry>/<digest>` = the [`DigestEntry`] JSON.
pub(crate) const ENTRY_PREFIX: &str = ".nora-quarantine/";

/// The compacted map plus `as_of`, rewritten at each boot. Outside [`ENTRY_PREFIX`],
/// so backup and migrate never carry it: a store without it reads every entry once.
pub(crate) const SNAPSHOT_KEY: &str = ".nora-quarantine-snapshot.json";

/// Concurrent storage requests while loading or importing the ledger.
const LOAD_CONCURRENCY: usize = 32;
/// Upper bound on the background ledger load (listing + reads + snapshot).
const LOAD_DEADLINE: std::time::Duration = std::time::Duration::from_secs(600);

/// Stale entry TTL: entries older than 90 days are pruned on startup.
const PRUNE_TTL_SECS: i64 = 90 * 24 * 3600;

// ============================================================================
// Quarantine Mode
// ============================================================================

/// Quarantine operating mode.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QuarantineMode {
    /// Quarantine disabled (default).
    #[default]
    Off,
    /// Record + log, but don't block downloads.
    Observe,
    /// Block downloads for unknown/pending digests.
    Enforce,
}

impl std::fmt::Display for QuarantineMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Off => write!(f, "off"),
            Self::Observe => write!(f, "observe"),
            Self::Enforce => write!(f, "enforce"),
        }
    }
}

impl std::str::FromStr for QuarantineMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "observe" => Ok(Self::Observe),
            "enforce" => Ok(Self::Enforce),
            other => Err(format!(
                "unknown quarantine mode {:?} — valid values: off, observe, enforce",
                other
            )),
        }
    }
}

// ============================================================================
// Digest Entry
// ============================================================================

/// A single quarantine record persisted in JSONL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigestEntry {
    /// Registry type (e.g. "docker").
    pub registry: String,
    /// Content digest (e.g. "sha256:abc123...").
    pub digest: String,
    /// Unix timestamp (seconds) when first seen by NORA.
    pub first_seen: i64,
    /// Upstream that provided the content (e.g. "registry-1.docker.io").
    pub upstream: String,
}

// ============================================================================
// Quarantine Status
// ============================================================================

/// Result of checking a digest against the quarantine store.
#[derive(Debug, Clone, PartialEq)]
pub enum QuarantineStatus {
    /// Digest not seen before — just recorded.
    New,
    /// Digest known but still within quarantine window.
    Pending { remaining_secs: i64 },
    /// Digest has aged past the quarantine threshold.
    Mature,
}

impl QuarantineStatus {
    /// Value for the `X-Nora-Quarantine` response header.
    pub fn header_value(&self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Pending { .. } => "pending",
            Self::Mature => "mature",
        }
    }
}

// ============================================================================
// Digest Store
// ============================================================================

/// In-memory digest store backed by per-entry objects in the storage backend.
///
/// Thread-safe via `parking_lot::RwLock`. Reads (check) take a shared lock,
/// writes (record) take an exclusive lock with double-check pattern.
pub struct DigestStore {
    entries: Arc<RwLock<HashMap<String, DigestEntry>>>,
    storage: Storage,
}

/// The [`SNAPSHOT_KEY`] document.
#[derive(Serialize, Deserialize)]
struct Snapshot {
    /// Unix time the snapshot was written.
    as_of: i64,
    entries: Vec<DigestEntry>,
}

fn map_key(registry: &str, digest: &str) -> String {
    format!("{}:{}", registry, digest)
}

fn entry_key(entry: &DigestEntry) -> String {
    format!("{ENTRY_PREFIX}{}/{}", entry.registry, entry.digest)
}

impl DigestStore {
    /// Load the ledger from `storage`: import a legacy `{storage_path}/quarantine.jsonl`,
    /// read the snapshot plus every entry recorded since it, prune stale (>90d)
    /// entries and their objects, and write a fresh snapshot.
    ///
    /// Fail-open: unreadable entries are skipped, a failed listing → empty store.
    pub async fn load(storage: Storage, storage_path: &str) -> Self {
        let legacy = Path::new(storage_path).join(LEDGER_FILE);
        let entries = load_entries(&storage, &legacy).await;
        Self {
            entries: Arc::new(RwLock::new(entries)),
            storage,
        }
    }

    /// [`Self::load`] off the startup path: the store starts empty and serves at
    /// once, the ledger is merged in when the walk over `storage` finishes
    /// (bounded by `LOAD_DEADLINE`; past it the walk is dropped and logged).
    /// Until then a known digest reads as new, so an enforcing quarantine may
    /// hold a cached version for one more TTL; the listener never waits on R2.
    /// Maestra: on 20.10.2026 the blocking load kept packages.maestra.io from
    /// binding its port for minutes on a slow R2 listing, and the startup probe
    /// killed the pod in a loop.
    pub fn load_in_background(storage: Storage, storage_path: &str) -> Self {
        let store = Self::empty(storage.clone());
        let legacy = Path::new(storage_path).join(LEDGER_FILE);
        let entries = Arc::clone(&store.entries);
        tokio::spawn(async move {
            let started = std::time::Instant::now();
            match tokio::time::timeout(LOAD_DEADLINE, load_entries(&storage, &legacy)).await {
                Ok(loaded) => {
                    let cutoff = Utc::now().timestamp() - PRUNE_TTL_SECS;
                    let mut map = entries.write();
                    for (key, entry) in loaded {
                        // An entry recorded meanwhile keeps the older first_seen.
                        match map.get(&key) {
                            Some(live) if live.first_seen <= entry.first_seen => {}
                            _ => {
                                map.insert(key, entry);
                            }
                        }
                    }
                    // A record() that adopted a stale object the walk then pruned
                    // would read as Mature until restart: apply the same cutoff here.
                    map.retain(|_, entry| entry.first_seen >= cutoff);
                    info!(
                        elapsed_ms = started.elapsed().as_millis() as u64,
                        entries = map.len(),
                        "Quarantine store merged into the live map"
                    );
                }
                Err(_) => error!(
                    deadline_secs = LOAD_DEADLINE.as_secs(),
                    "Quarantine store load did not finish, serving without the ledger (fail-open)"
                ),
            }
        });
        store
    }

    /// Create an empty store (for tests or when quarantine is off).
    pub fn empty(storage: Storage) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            storage,
        }
    }

    /// Record a proxy-fetched digest. Returns the entry (existing or new).
    ///
    /// Idempotent: if the digest already exists, the original entry is returned.
    /// New entries are written to storage asynchronously.
    /// `first_seen` overrides the recorded first-seen timestamp with a trusted
    /// upstream release date (only when `server.trust_upstream_dates` is set and
    /// the registry caches one, #750); `None` uses NORA's own clock — the
    /// unspoofable default. SECURITY: a trusted date is upstream-supplied and
    /// spoofable, so it is opt-in via `trust_upstream_dates`.
    pub fn record(
        &self,
        registry: &str,
        digest: &str,
        upstream: &str,
        first_seen: Option<i64>,
    ) -> DigestEntry {
        let key = map_key(registry, digest);

        // Fast path: read lock
        {
            let entries = self.entries.read();
            if let Some(entry) = entries.get(&key) {
                return entry.clone();
            }
        }

        // Slow path: write lock
        let mut entries = self.entries.write();
        // Double-check after acquiring write lock
        if let Some(entry) = entries.get(&key) {
            return entry.clone();
        }

        let entry = DigestEntry {
            registry: registry.to_string(),
            digest: digest.to_string(),
            first_seen: first_seen.unwrap_or_else(|| Utc::now().timestamp()),
            upstream: upstream.to_string(),
        };

        entries.insert(key, entry.clone());
        drop(entries);
        // A trusted upstream date past the prune TTL is Mature from the start:
        // the object would only be read and deleted again by the next boot walk
        // (563 of them on 20.10.2026 made that walk outlive the startup probe).
        if entry.first_seen >= Utc::now().timestamp() - PRUNE_TTL_SECS {
            self.persist(entry.clone());
        }
        entry
    }

    /// Write a new entry off the request path. The object is created once: when it
    /// exists already (another replica, or a pod that started before it), the stored
    /// entry is the ledger's and replaces the one just recorded in memory.
    fn persist(&self, entry: DigestEntry) {
        let storage = self.storage.clone();
        let entries = Arc::clone(&self.entries);
        tokio::spawn(async move {
            let key = entry_key(&entry);
            let Some(body) = entry_body(&entry) else {
                return;
            };
            match storage.put_if_absent(&key, body).await {
                Ok(true) => {}
                Ok(false) => {
                    if let Some(stored) = read_entry(&storage, &key).await {
                        entries
                            .write()
                            .insert(map_key(&stored.registry, &stored.digest), stored);
                    }
                }
                Err(e) => error!(
                    key = %key,
                    error = %e,
                    "Failed to persist quarantine entry (fail-open)"
                ),
            }
        });
    }

    // NOTE: the ledger records PROXY-fetched content only. Locally-pushed artifacts
    // are intentionally NOT recorded — the cooldown is a control on content arriving
    // from upstream, and the serve gate treats an unrecorded digest (`New`) as "serve".
    // A prior `record_trusted` matured local pushes here; it was removed because it
    // wrote the same key the proxy `check` reads, letting a local push set the
    // first-seen clock for a digest later fetched from upstream.

    /// Check quarantine status for a digest.
    #[must_use = "ignoring quarantine status may serve blocked artifacts"]
    pub fn check(&self, registry: &str, digest: &str, quarantine_secs: i64) -> QuarantineStatus {
        let key = map_key(registry, digest);
        let entries = self.entries.read();

        match entries.get(&key) {
            None => QuarantineStatus::New,
            Some(entry) => {
                let age = Utc::now().timestamp() - entry.first_seen;
                if age >= quarantine_secs {
                    QuarantineStatus::Mature
                } else {
                    QuarantineStatus::Pending {
                        remaining_secs: quarantine_secs - age,
                    }
                }
            }
        }
    }

    /// Number of tracked digests.
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }
}

// ============================================================================
// Generic proxy quarantine gate
// ============================================================================
//
// Registry-agnostic generalization of the digest-quarantine wiring that
// previously lived only in the Docker handler. min-release-age cannot give a
// trustworthy release age on the proxy path (upstream dates are unsigned and
// spoofable, and several registries expose no date at all), so first-seen
// quarantine — keyed on the artifact's content digest and NORA's own clock — is
// the unspoofable supply-chain control that works for every proxy registry.

/// Resolve the effective quarantine `(mode, ttl_secs)` from the global curation
/// config. Returns `(Off, 0)` when disabled. Per-registry overrides can be
/// layered on top later; the proxy gate uses the global setting for now.
pub fn resolve_global(mode: Option<&QuarantineMode>, ttl: Option<&str>) -> (QuarantineMode, i64) {
    let mode = mode.cloned().unwrap_or(QuarantineMode::Off);
    if matches!(mode, QuarantineMode::Off) {
        return (QuarantineMode::Off, 0);
    }
    // Config validation refuses a TTL that does not parse (#1099); the default only
    // covers a config built without it.
    let secs = crate::curation::parse_duration(ttl.unwrap_or("14d")).unwrap_or(14 * 86400);
    (mode, secs)
}

/// Post-fetch / pre-serve quarantine gate for a proxy-fetched artifact.
///
/// Records the artifact's content digest as first-seen, then checks maturity.
/// Returns `Some(403)` to BLOCK (enforce mode, not yet mature), `None` to serve.
/// In observe mode it logs but never blocks. Idempotent: `record` preserves the
/// earliest `first_seen`, so calling this on every request (proxy fetch or cache
/// hit) is safe and the quarantine clock does not reset.
#[must_use = "the returned response blocks a quarantined artifact; dropping it serves the artifact"]
pub fn proxy_gate(
    store: &DigestStore,
    registry: &str,
    bytes: &[u8],
    mode: &QuarantineMode,
    quarantine_secs: i64,
    upstream: &str,
) -> Option<Response> {
    proxy_gate_dated(
        store,
        registry,
        bytes,
        mode,
        quarantine_secs,
        upstream,
        None,
    )
}

/// Like [`proxy_gate`], but seeds the first-seen clock from a trusted upstream
/// release date (#750). When `trusted_first_seen` is `Some` — only when
/// `server.trust_upstream_dates` is set and the registry caches a date — an
/// artifact whose release date is already older than the TTL matures
/// immediately, so a provably-old package is not held as "new to this mirror".
/// `None` falls back to NORA's own clock (the unspoofable default).
#[must_use = "the returned response blocks a quarantined artifact; dropping it serves the artifact"]
pub fn proxy_gate_dated(
    store: &DigestStore,
    registry: &str,
    bytes: &[u8],
    mode: &QuarantineMode,
    quarantine_secs: i64,
    upstream: &str,
    trusted_first_seen: Option<i64>,
) -> Option<Response> {
    if matches!(mode, QuarantineMode::Off) {
        return None;
    }
    use sha2::Digest;
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)));
    proxy_gate_digest(
        store,
        registry,
        &digest,
        mode,
        quarantine_secs,
        upstream,
        trusted_first_seen,
    )
}

/// [`proxy_gate_dated`] for an artifact whose `sha256:<hex>` digest is already
/// known — a body streamed from a spool file or from storage, never held whole.
#[must_use = "the returned response blocks a quarantined artifact; dropping it serves the artifact"]
pub fn proxy_gate_digest(
    store: &DigestStore,
    registry: &str,
    digest: &str,
    mode: &QuarantineMode,
    quarantine_secs: i64,
    upstream: &str,
    trusted_first_seen: Option<i64>,
) -> Option<Response> {
    if matches!(mode, QuarantineMode::Off) {
        return None;
    }
    store.record(registry, digest, upstream, trusted_first_seen);
    let status = store.check(registry, digest, quarantine_secs);
    if matches!(status, QuarantineStatus::Mature) {
        return None;
    }
    // Operator-facing signal: previously a held artifact was visible only in this
    // WARN line. The metric lets the operator alert/graph on it, and the log + the
    // 403 now name the responsible policy (registry + quarantine_ttl + remaining).
    let outcome = if matches!(mode, QuarantineMode::Enforce) {
        "blocked"
    } else {
        "observed"
    };
    crate::metrics::QUARANTINE_HOLDS_TOTAL
        .with_label_values(&[registry, outcome])
        .inc();
    warn!(
        registry = %registry,
        digest = %digest,
        status = %status.header_value(),
        mode = %mode,
        quarantine_ttl_secs = quarantine_secs,
        "quarantine: proxy artifact held by registry policy"
    );
    if matches!(mode, QuarantineMode::Enforce) {
        Some(quarantine_forbidden(
            registry,
            digest,
            &status,
            quarantine_secs,
        ))
    } else {
        None
    }
}

/// Build a generic 403 for a quarantined proxy artifact (non-Docker shape).
///
/// Names the responsible policy (`registry` + `quarantine_ttl_secs` + how much
/// longer the hold lasts) so the client — and an operator reading the body — can
/// tell WHY it was held, not just that it was.
fn quarantine_forbidden(
    registry: &str,
    digest: &str,
    status: &QuarantineStatus,
    quarantine_secs: i64,
) -> Response {
    let remaining = match status {
        QuarantineStatus::New => quarantine_secs,
        QuarantineStatus::Pending { remaining_secs } => *remaining_secs,
        QuarantineStatus::Mature => 0,
    };
    let quarantine_until = Utc::now().timestamp() + remaining;
    let body = serde_json::json!({
        "error": "quarantine",
        "message": format!(
            "held by quarantine policy on registry '{}': artifact must age past the quarantine window before it is served",
            registry
        ),
        "detail": {
            "registry": registry,
            "digest": digest,
            "policy": {
                "control": "quarantine",
                "quarantine_ttl_secs": quarantine_secs,
            },
            "quarantine_until": quarantine_until,
            "remaining_secs": remaining,
        }
    });
    (
        StatusCode::FORBIDDEN,
        [
            (
                HeaderName::from_static("x-nora-quarantine"),
                status.header_value(),
            ),
            (header::CONTENT_TYPE, "application/json"),
        ],
        body.to_string(),
    )
        .into_response()
}

// ============================================================================
// Storage I/O helpers
// ============================================================================

/// The stored body of an entry.
fn entry_body(entry: &DigestEntry) -> Option<Bytes> {
    serde_json::to_vec(entry).ok().map(Bytes::from)
}

/// One per-entry object; `None` when missing or unreadable.
async fn read_entry(storage: &Storage, key: &str) -> Option<DigestEntry> {
    match storage.get(key).await {
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(entry) => Some(entry),
            Err(e) => {
                warn!(key = %key, error = %e, "Skipping unparsable quarantine entry");
                None
            }
        },
        Err(StorageError::NotFound) => None,
        Err(e) => {
            warn!(key = %key, error = %e, "Skipping unreadable quarantine entry");
            None
        }
    }
}

/// Every per-entry object key; `None` (logged) when the listing fails.
async fn list_entries(storage: &Storage) -> Option<HashSet<String>> {
    match storage.list_internal(ENTRY_PREFIX).await {
        Ok(keys) => Some(keys.into_iter().collect()),
        Err(e) => {
            error!(error = %e, "Failed to list quarantine entries, starting empty (fail-open)");
            None
        }
    }
}

/// The snapshot's entries by object key; empty when missing or unreadable.
async fn read_snapshot(storage: &Storage) -> HashMap<String, DigestEntry> {
    let snapshot = match storage.get(SNAPSHOT_KEY).await {
        Ok(bytes) => match serde_json::from_slice::<Snapshot>(&bytes) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "Unparsable quarantine snapshot, reading every entry");
                return HashMap::new();
            }
        },
        Err(StorageError::NotFound) => return HashMap::new(),
        Err(e) => {
            warn!(error = %e, "Unreadable quarantine snapshot, reading every entry");
            return HashMap::new();
        }
    };
    snapshot
        .entries
        .into_iter()
        .map(|e| (entry_key(&e), e))
        .collect()
}

/// Write every ledger line of `jsonl` (the legacy file format) to its per-entry
/// object, keeping its `first_seen`. The first line of a digest wins, as it did in
/// the file; stale (>90d) lines are dropped. `overwrite` replaces an existing object
/// (a restore: the backup's time wins), otherwise the stored object wins. Keys in
/// `present` cost no request. Returns (entries written, already present, failed).
pub(crate) async fn import_jsonl(
    storage: &Storage,
    jsonl: &[u8],
    present: &HashSet<String>,
    overwrite: bool,
) -> (Vec<DigestEntry>, usize, usize) {
    let cutoff = Utc::now().timestamp() - PRUNE_TTL_SECS;
    let mut seen = HashSet::new();
    let mut todo = Vec::new();
    let mut already = 0;
    for line in jsonl.split(|b| *b == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let entry: DigestEntry = match serde_json::from_slice(line) {
            Ok(entry) => entry,
            Err(e) => {
                warn!(error = %e, "Skipping unparsable quarantine line");
                continue;
            }
        };
        let key = entry_key(&entry);
        if entry.first_seen < cutoff || !seen.insert(key.clone()) {
            continue;
        }
        if present.contains(&key) {
            already += 1;
            continue;
        }
        todo.push((key, entry));
    }
    let results: Vec<_> = futures::stream::iter(todo)
        .map(|(key, entry)| async move {
            let result = match entry_body(&entry) {
                Some(body) if overwrite => storage.put_bytes(&key, body).await.map(|()| true),
                Some(body) => storage.put_if_absent(&key, body).await,
                None => Ok(false),
            };
            (key, entry, result)
        })
        .buffer_unordered(LOAD_CONCURRENCY)
        .collect()
        .await;
    let mut written = Vec::new();
    let mut failed = 0;
    for (key, entry, result) in results {
        match result {
            Ok(true) => written.push(entry),
            Ok(false) => already += 1,
            Err(e) => {
                error!(key = %key, error = %e, "Failed to import quarantine entry");
                failed += 1;
            }
        }
    }
    (written, already, failed)
}

/// [`DigestStore::load`]: the map keyed `registry:digest`.
async fn load_entries(storage: &Storage, legacy: &Path) -> HashMap<String, DigestEntry> {
    let Some(mut listed) = list_entries(storage).await else {
        return HashMap::new();
    };
    // Snapshot entries by object key, plus what the import below writes.
    let mut known = read_snapshot(storage).await;

    // Maestra: the ledger was a file on the volume. Imported at every boot while it is
    // there; only lines with no object yet cost a request.
    match tokio::fs::read(legacy).await {
        Ok(data) => {
            let (written, present, failed) = import_jsonl(storage, &data, &listed, false).await;
            info!(
                failed = failed,
                "imported {} quarantine entries from {}, {} already present",
                written.len(),
                legacy.display(),
                present
            );
            for entry in written {
                let key = entry_key(&entry);
                listed.insert(key.clone());
                known.insert(key, entry);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            warn!(path = %legacy.display(), error = %e, "Cannot read legacy quarantine ledger")
        }
    }

    // The listing decides membership: a snapshot entry without its object was
    // pruned by another start. Entries recorded since the snapshot are read here.
    let missing: Vec<String> = listed
        .iter()
        .filter(|k| !known.contains_key(*k))
        .cloned()
        .collect();
    let fetched = missing.len();
    let read: Vec<(String, Option<DigestEntry>)> = futures::stream::iter(missing)
        .map(|key| async move {
            let entry = read_entry(storage, &key).await;
            (key, entry)
        })
        .buffer_unordered(LOAD_CONCURRENCY)
        .collect()
        .await;
    for (key, entry) in read {
        if let Some(entry) = entry {
            known.insert(key, entry);
        }
    }

    let cutoff = Utc::now().timestamp() - PRUNE_TTL_SECS;
    let mut entries = HashMap::new();
    let mut stale = Vec::new();
    for key in listed {
        match known.remove(&key) {
            Some(entry) if entry.first_seen < cutoff => stale.push(key),
            Some(entry) => {
                entries.insert(map_key(&entry.registry, &entry.digest), entry);
            }
            None => {}
        }
    }
    let pruned = stale.len();
    futures::stream::iter(stale)
        .map(|key| async move {
            if let Err(e) = storage.delete(&key).await {
                warn!(key = %key, error = %e, "Failed to delete stale quarantine entry");
            }
        })
        .buffer_unordered(LOAD_CONCURRENCY)
        .collect::<Vec<()>>()
        .await;

    let snapshot = Snapshot {
        as_of: Utc::now().timestamp(),
        entries: entries.values().cloned().collect(),
    };
    match serde_json::to_vec(&snapshot) {
        Ok(body) => {
            if let Err(e) = storage.put(SNAPSHOT_KEY, &body).await {
                warn!(error = %e, "Failed to write quarantine snapshot");
            }
        }
        Err(e) => warn!(error = %e, "Failed to encode quarantine snapshot"),
    }

    info!(
        entries = entries.len(),
        fetched = fetched,
        pruned = pruned,
        "Quarantine store loaded"
    );
    entries
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn storage(tmp: &TempDir) -> Storage {
        Storage::new_local(tmp.path().to_str().unwrap())
    }

    /// Wait for the object `record` writes from a spawned task.
    async fn wait_for(storage: &Storage, key: &str) {
        for _ in 0..500 {
            if storage.stat(key).await.is_some() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("{key} was never written");
    }

    fn entry(digest: &str, first_seen: i64) -> DigestEntry {
        DigestEntry {
            registry: "docker".into(),
            digest: digest.into(),
            first_seen,
            upstream: "up".into(),
        }
    }

    #[test]
    fn test_quarantine_mode_from_str() {
        assert_eq!(
            "off".parse::<QuarantineMode>().unwrap(),
            QuarantineMode::Off
        );
        assert_eq!(
            "observe".parse::<QuarantineMode>().unwrap(),
            QuarantineMode::Observe
        );
        assert_eq!(
            "enforce".parse::<QuarantineMode>().unwrap(),
            QuarantineMode::Enforce
        );
        // Case insensitive
        assert_eq!(
            "OBSERVE".parse::<QuarantineMode>().unwrap(),
            QuarantineMode::Observe
        );
        assert_eq!(
            "ENFORCE".parse::<QuarantineMode>().unwrap(),
            QuarantineMode::Enforce
        );
        assert_eq!(
            "Off".parse::<QuarantineMode>().unwrap(),
            QuarantineMode::Off
        );
    }

    #[test]
    fn test_quarantine_mode_rejects_invalid() {
        assert!("anything".parse::<QuarantineMode>().is_err());
        assert!("eforce".parse::<QuarantineMode>().is_err());
        assert!("enabled".parse::<QuarantineMode>().is_err());
        assert!("on".parse::<QuarantineMode>().is_err());
        assert!("".parse::<QuarantineMode>().is_err());
        // Error message includes valid values
        let err = "typo".parse::<QuarantineMode>().unwrap_err();
        assert!(err.contains("off"), "error should list valid values: {err}");
        assert!(
            err.contains("observe"),
            "error should list valid values: {err}"
        );
        assert!(
            err.contains("enforce"),
            "error should list valid values: {err}"
        );
    }

    #[test]
    fn test_quarantine_mode_display_roundtrip() {
        for mode in [
            QuarantineMode::Off,
            QuarantineMode::Observe,
            QuarantineMode::Enforce,
        ] {
            let s = mode.to_string();
            let parsed: QuarantineMode = s.parse().unwrap();
            assert_eq!(mode, parsed);
        }
    }

    #[test]
    fn test_quarantine_mode_default_is_off() {
        assert_eq!(QuarantineMode::default(), QuarantineMode::Off);
    }

    #[tokio::test]
    async fn test_check_unknown_digest_is_new() {
        let tmp = TempDir::new().unwrap();
        let store = DigestStore::empty(storage(&tmp));

        let status = store.check("docker", "sha256:abc123", 86400);
        assert_eq!(status, QuarantineStatus::New);
    }

    #[tokio::test]
    async fn test_record_then_check_pending() {
        let tmp = TempDir::new().unwrap();
        let store = DigestStore::empty(storage(&tmp));

        store.record("docker", "sha256:abc123", "registry-1.docker.io", None);

        let status = store.check("docker", "sha256:abc123", 86400);
        match status {
            QuarantineStatus::Pending { remaining_secs } => {
                assert!(remaining_secs > 0);
                assert!(remaining_secs <= 86400);
            }
            other => panic!("Expected Pending, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_record_then_check_mature_zero_ttl() {
        let tmp = TempDir::new().unwrap();
        let store = DigestStore::empty(storage(&tmp));

        store.record("docker", "sha256:abc123", "registry-1.docker.io", None);

        // TTL=0 → immediately mature
        let status = store.check("docker", "sha256:abc123", 0);
        assert_eq!(status, QuarantineStatus::Mature);
    }

    #[tokio::test]
    async fn test_unrecorded_digest_is_new() {
        // The ledger tracks proxy-fetched content only. A digest that was never
        // proxy-recorded (e.g. a locally-pushed artifact, which is deliberately not
        // recorded) reads as `New`. The cache-serve gate treats `New` as "serve" and
        // blocks only `Pending`, so a local push is served and can never set the
        // first-seen clock for — or mature — a digest on the proxy path.
        let tmp = TempDir::new().unwrap();
        let store = DigestStore::empty(storage(&tmp));

        let status = store.check("docker", "sha256:never_seen", 86400);
        assert_eq!(status, QuarantineStatus::New);
    }

    #[tokio::test]
    async fn test_record_idempotent() {
        let tmp = TempDir::new().unwrap();
        let store = DigestStore::empty(storage(&tmp));

        let entry1 = store.record("docker", "sha256:abc", "upstream1", None);
        let entry2 = store.record("docker", "sha256:abc", "upstream2", None);

        assert_eq!(entry1.first_seen, entry2.first_seen);
        assert_eq!(entry1.upstream, entry2.upstream);
        assert_eq!(store.len(), 1);
    }

    #[tokio::test]
    async fn test_registry_isolation() {
        let tmp = TempDir::new().unwrap();
        let store = DigestStore::empty(storage(&tmp));

        store.record("docker", "sha256:abc", "docker-upstream", None);
        store.record("npm", "sha256:abc", "npmjs.org", None);

        assert_eq!(store.len(), 2);
    }

    #[tokio::test]
    async fn test_trusted_first_seen_matures_old_release() {
        // #750: when a trusted upstream release date is supplied, the artifact's
        // first_seen is that date — so a package released long ago is immediately
        // Mature (served), not held as "new to this mirror".
        let tmp = TempDir::new().unwrap();
        let store = DigestStore::empty(storage(&tmp));
        let two_years_ago = Utc::now().timestamp() - 2 * 365 * 86400;

        store.record(
            "pypi",
            "sha256:old",
            "files.pythonhosted.org",
            Some(two_years_ago),
        );
        // 14-day TTL: a 2-year-old release is well past it.
        assert_eq!(
            store.check("pypi", "sha256:old", 14 * 86400),
            QuarantineStatus::Mature
        );

        // A freshly-released artifact (date = now) is still held.
        store.record(
            "pypi",
            "sha256:fresh",
            "files.pythonhosted.org",
            Some(Utc::now().timestamp()),
        );
        assert!(matches!(
            store.check("pypi", "sha256:fresh", 14 * 86400),
            QuarantineStatus::Pending { .. }
        ));

        assert_eq!(store.len(), 2);
    }

    /// A legacy `quarantine.jsonl` is imported into storage at boot.
    #[tokio::test]
    async fn test_persistence_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().to_str().unwrap();
        let jsonl_path = tmp.path().join("quarantine.jsonl");

        let now = Utc::now().timestamp();
        let entries = [
            DigestEntry {
                registry: "docker".into(),
                digest: "sha256:aaa".into(),
                first_seen: now,
                upstream: "upstream1".into(),
            },
            DigestEntry {
                registry: "docker".into(),
                digest: "sha256:bbb".into(),
                first_seen: now,
                upstream: "upstream2".into(),
            },
        ];
        {
            let mut file = std::fs::File::create(&jsonl_path).unwrap();
            for e in &entries {
                writeln!(file, "{}", serde_json::to_string(e).unwrap()).unwrap();
            }
            file.flush().unwrap();
        }

        let store = DigestStore::load(storage(&tmp), path).await;
        assert_eq!(store.len(), 2);
        assert_eq!(
            storage(&tmp)
                .list_internal(ENTRY_PREFIX)
                .await
                .unwrap()
                .len(),
            2
        );

        let status = store.check("docker", "sha256:aaa", 86400);
        assert!(matches!(status, QuarantineStatus::Pending { .. }));
    }

    #[tokio::test]
    async fn test_load_empty_dir() {
        let tmp = TempDir::new().unwrap();
        let store = DigestStore::load(storage(&tmp), tmp.path().to_str().unwrap()).await;
        assert_eq!(store.len(), 0);
    }

    #[tokio::test]
    async fn test_load_corrupt_file_fail_open() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("quarantine.jsonl");

        let now = Utc::now().timestamp();
        let valid = serde_json::json!({
            "registry": "docker",
            "digest": "sha256:good",
            "first_seen": now,
            "upstream": "up"
        });
        std::fs::write(&path, format!("not json\n{}\ngarbage\n", valid)).unwrap();

        let store = DigestStore::load(storage(&tmp), tmp.path().to_str().unwrap()).await;
        assert_eq!(store.len(), 1);
    }

    #[tokio::test]
    async fn test_prune_stale_entries() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("quarantine.jsonl");

        let now = Utc::now().timestamp();
        let old_ts = now - (91 * 24 * 3600); // 91 days — stale
        let fresh_ts = now - (10 * 24 * 3600); // 10 days — kept

        let old = serde_json::json!({
            "registry": "docker", "digest": "sha256:old",
            "first_seen": old_ts, "upstream": "up"
        });
        let fresh = serde_json::json!({
            "registry": "docker", "digest": "sha256:fresh",
            "first_seen": fresh_ts, "upstream": "up"
        });
        std::fs::write(&path, format!("{}\n{}\n", old, fresh)).unwrap();

        let store = DigestStore::load(storage(&tmp), tmp.path().to_str().unwrap()).await;
        assert_eq!(store.len(), 1);

        assert!(matches!(
            store.check("docker", "sha256:fresh", 86400),
            QuarantineStatus::Mature
        ));
        assert_eq!(
            store.check("docker", "sha256:old", 86400),
            QuarantineStatus::New
        );
    }

    #[test]
    fn test_quarantine_status_header_values() {
        assert_eq!(QuarantineStatus::New.header_value(), "new");
        assert_eq!(
            QuarantineStatus::Pending {
                remaining_secs: 100
            }
            .header_value(),
            "pending"
        );
        assert_eq!(QuarantineStatus::Mature.header_value(), "mature");
    }

    #[tokio::test]
    async fn test_import_keeps_one_object_per_digest() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("quarantine.jsonl");

        let now = Utc::now().timestamp();
        let first = serde_json::json!({
            "registry": "docker", "digest": "sha256:dup",
            "first_seen": now - 100, "upstream": "up"
        });
        let later = serde_json::json!({
            "registry": "docker", "digest": "sha256:dup",
            "first_seen": now, "upstream": "up"
        });
        std::fs::write(&path, format!("{}\n{}\n{}\n", first, later, later)).unwrap();

        let store = DigestStore::load(storage(&tmp), tmp.path().to_str().unwrap()).await;
        assert_eq!(store.len(), 1);
        assert_eq!(
            store.record("docker", "sha256:dup", "x", None).first_seen,
            now - 100,
            "the first line of a digest wins"
        );
        assert_eq!(
            storage(&tmp)
                .list_internal(ENTRY_PREFIX)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    /// (a) A recorded entry outlives the process: a store loaded later over the same
    /// storage holds it with the same first-seen.
    #[tokio::test]
    async fn test_record_survives_a_new_store() {
        let tmp = TempDir::new().unwrap();
        let first_seen = Utc::now().timestamp() - 3600;
        let store = DigestStore::empty(storage(&tmp));
        store.record("npm", "sha256:aa", "registry.npmjs.org", Some(first_seen));
        wait_for(&storage(&tmp), ".nora-quarantine/npm/sha256:aa").await;
        drop(store);

        let reloaded = DigestStore::load(storage(&tmp), "/nonexistent").await;
        assert_eq!(reloaded.len(), 1);
        assert_eq!(
            reloaded
                .record("npm", "sha256:aa", "other", None)
                .first_seen,
            first_seen
        );
        // A third start reads it from the snapshot the second one wrote.
        assert!(storage(&tmp).stat(SNAPSHOT_KEY).await.is_some());
        let third = DigestStore::load(storage(&tmp), "/nonexistent").await;
        assert_eq!(
            third.record("npm", "sha256:aa", "other", None).first_seen,
            first_seen
        );
    }

    /// Two replicas record the same digest: the first object wins, and the
    /// second replica adopts its first-seen.
    #[tokio::test]
    async fn test_second_writer_adopts_the_stored_first_seen() {
        let tmp = TempDir::new().unwrap();
        let early = Utc::now().timestamp() - 5 * 86400;
        let a = DigestStore::empty(storage(&tmp));
        a.record("docker", "sha256:bb", "up", Some(early));
        wait_for(&storage(&tmp), ".nora-quarantine/docker/sha256:bb").await;

        let b = DigestStore::empty(storage(&tmp));
        b.record("docker", "sha256:bb", "up", None);
        for _ in 0..500 {
            if b.check("docker", "sha256:bb", 86400) == QuarantineStatus::Mature {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("the second store never adopted the stored first-seen");
    }

    /// (b) The boot import runs at every start: a second run writes nothing and
    /// the original first-seen stays, also after a later re-recording.
    #[tokio::test]
    async fn test_boot_import_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap();
        let original = Utc::now().timestamp() - 2 * 86400;
        std::fs::write(
            tmp.path().join(LEDGER_FILE),
            format!(
                "{}\n",
                serde_json::to_string(&entry("sha256:cc", original)).unwrap()
            ),
        )
        .unwrap();

        let first = DigestStore::load(storage(&tmp), dir).await;
        assert_eq!(first.len(), 1);
        drop(first);
        let second = DigestStore::load(storage(&tmp), dir).await;
        assert_eq!(second.len(), 1);
        assert_eq!(
            second.record("docker", "sha256:cc", "x", None).first_seen,
            original
        );
        assert_eq!(
            storage(&tmp).list_internal(ENTRY_PREFIX).await.unwrap(),
            vec![".nora-quarantine/docker/sha256:cc".to_string()]
        );

        // Not even a conditional write: the key is listed already.
        let listed = list_entries(&storage(&tmp)).await.unwrap();
        let data = std::fs::read(tmp.path().join(LEDGER_FILE)).unwrap();
        let (written, present, failed) = import_jsonl(&storage(&tmp), &data, &listed, false).await;
        assert_eq!((written.len(), present, failed), (0, 1, 0));
        // Without the listing, put_if_absent keeps the stored object.
        let newer = entry("sha256:cc", Utc::now().timestamp());
        let line = serde_json::to_vec(&newer).unwrap();
        let (written, present, _) =
            import_jsonl(&storage(&tmp), &line, &HashSet::new(), false).await;
        assert_eq!((written.len(), present), (0, 1));
        let stored = read_entry(&storage(&tmp), ".nora-quarantine/docker/sha256:cc").await;
        assert_eq!(stored.unwrap().first_seen, original);
    }

    /// (c) A start prunes entries past 90 days: the object goes, and so does the
    /// snapshot line.
    #[tokio::test]
    async fn test_prune_deletes_object_and_snapshot_omits_it() {
        let tmp = TempDir::new().unwrap();
        let st = storage(&tmp);
        let now = Utc::now().timestamp();
        for e in [
            entry("sha256:old", now - 91 * 86400),
            entry("sha256:new", now),
        ] {
            st.put(&entry_key(&e), &serde_json::to_vec(&e).unwrap())
                .await
                .unwrap();
        }

        let store = DigestStore::load(st.clone(), "/nonexistent").await;
        assert_eq!(store.len(), 1);
        assert!(st
            .stat(".nora-quarantine/docker/sha256:old")
            .await
            .is_none());
        assert!(st
            .stat(".nora-quarantine/docker/sha256:new")
            .await
            .is_some());
        let snapshot: Snapshot =
            serde_json::from_slice(&st.get(SNAPSHOT_KEY).await.unwrap()).unwrap();
        let digests: Vec<_> = snapshot.entries.iter().map(|e| e.digest.as_str()).collect();
        assert_eq!(digests, vec!["sha256:new"]);
    }

    #[tokio::test]
    async fn test_empty_store_is_empty() {
        let tmp = TempDir::new().unwrap();
        let store = DigestStore::empty(storage(&tmp));
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_digest_entry_serialization() {
        let entry = DigestEntry {
            registry: "docker".to_string(),
            digest: "sha256:abc".to_string(),
            first_seen: 1700000000,
            upstream: "registry-1.docker.io".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"registry\":\"docker\""));
        assert!(json.contains("\"first_seen\":1700000000"));

        let parsed: DigestEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.digest, "sha256:abc");
    }
}
