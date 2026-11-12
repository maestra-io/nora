// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::auth::{enforce_namespace_scope, NamespaceAuthority};
use crate::circuit_breaker::{upstream_key, CircuitBreakerRegistry, ProbeToken};
use crate::config::basic_auth_header;
use crate::proxy_coalesce::Flight;
use crate::registry::docker_auth::{DockerAuth, TokenError};
use crate::registry::{
    content_length, sha256_of_file, stream_body_to_file, StreamOutcome, TempFileGuard,
};
use crate::registry::{method_not_allowed, ProxyError, UpstreamMiss};
use crate::secrets::expose_opt;
use crate::storage::Storage;
use crate::validation::{
    ends_with_ci, validate_digest, validate_docker_name, validate_docker_reference,
};
use crate::AppState;
use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::{header, HeaderName, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::get,
    Extension, Json, Router,
};
use futures::StreamExt;
use nora_registry::docker_manifest::detect_manifest_media_type;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ============================================================================
// Namespaced key builders (issue #323)
// ============================================================================

/// Build a namespaced storage key for Docker blobs.
///
/// With namespace: `docker/{ns}/{name}/blobs/{digest}`
/// Without (local push): `docker/{name}/blobs/{digest}`
fn blob_key(namespace: Option<&str>, name: &str, digest: &str) -> String {
    match namespace {
        Some(ns) => format!("docker/{}/{}/blobs/{}", ns, name, digest),
        None => format!("docker/{}/blobs/{}", name, digest),
    }
}

/// Build a namespaced storage key for Docker manifests.
fn manifest_key(namespace: Option<&str>, name: &str, reference: &str) -> String {
    match namespace {
        Some(ns) => format!("docker/{}/{}/manifests/{}.json", ns, name, reference),
        None => format!("docker/{}/manifests/{}.json", name, reference),
    }
}

/// Build a namespaced storage key for Docker manifest metadata.
fn manifest_meta_key(namespace: Option<&str>, name: &str, reference: &str) -> String {
    match namespace {
        Some(ns) => format!("docker/{}/{}/manifests/{}.meta.json", ns, name, reference),
        None => format!("docker/{}/manifests/{}.meta.json", name, reference),
    }
}

/// Stems of the sidecars stored beside a manifest `<reference>.json`: `<reference>.meta.json`
/// (push metadata) and `<reference>.stats.json` (pull counts, #1114).
const MANIFEST_SIDECAR_STEMS: [&str; 2] = [".meta", ".stats"];

/// The tag a file under `…/manifests/` stores, or `None` if it stores no tag: a digest copy
/// (`sha256:….json`), a sidecar (`<tag>.meta.json`, `<tag>.stats.json`) or any name that is not
/// a valid tag. Every listing of tags (tags/list, delete by digest, retention, the UI, the
/// repository index) asks this one function.
pub(crate) fn tag_from_manifest_file(file_name: &str) -> Option<&str> {
    let tag = file_name.strip_suffix(".json")?;
    let is_tag = validate_docker_reference(tag).is_ok() && !tag.contains(':');
    let is_sidecar = MANIFEST_SIDECAR_STEMS.iter().any(|s| ends_with_ci(tag, s));
    (is_tag && !is_sidecar).then_some(tag)
}

/// Build a namespaced storage key prefix for listing manifests.
fn manifest_prefix(namespace: Option<&str>, name: &str) -> String {
    match namespace {
        Some(ns) => format!("docker/{}/{}/manifests/", ns, name),
        None => format!("docker/{}/manifests/", name),
    }
}

/// Result of Docker image name canonicalization.
///
/// Unifies both config-aware prefix routing and hostname-based namespace
/// detection into a single entry point, eliminating the asymmetry between
/// write-path (former `resolve_upstream`) and read-path (`strip_docker_namespace`).
pub(crate) struct Canonical {
    /// Cleaned image name (prefix/hostname stripped).
    pub name: String,
    /// Namespace for storage key construction (e.g. `"docker.io"`).
    pub namespace: Option<String>,
    /// Which upstreams are asked for the name.
    route: Route,
    /// When true, the request should be rejected (no prefix match in deny mode).
    pub denied: bool,
}

/// Which upstreams a canonical name is asked of.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Route {
    /// The upstream at this index in the config, matched by prefix, namespaces or host.
    Upstream(usize),
    /// The fallback chain: every upstream that owns no namespaces, in config order.
    Chain,
    /// None: the name is behind this registry host, which no upstream serves (#1195).
    UnknownHost(String),
}

impl Canonical {
    /// Get the list of upstreams to try for fetching this image.
    ///
    /// If a specific upstream was matched (prefix, namespaces or hostname), returns only
    /// that one. A name behind a registry host that no upstream serves gets none: it is
    /// answered from local storage only, never by another registry (#1195). Otherwise returns
    /// the fallback chain: every upstream that does not own namespaces, in config order — a
    /// private registry is never asked for a public name.
    pub fn upstreams_to_try<'a>(
        &self,
        upstreams: &'a [crate::config::DockerUpstream],
    ) -> Vec<&'a crate::config::DockerUpstream> {
        match &self.route {
            Route::Upstream(idx) => vec![&upstreams[*idx]],
            Route::Chain => upstreams.iter().filter(|u| !u.is_bound()).collect(),
            Route::UnknownHost(host) => {
                tracing::info!(
                    host = %host,
                    name = %self.name,
                    "no Docker upstream serves this registry host: answering from local storage only"
                );
                Vec::new()
            }
        }
    }

    /// Return a 403 response if this request was denied by `default_action = "deny"`.
    pub fn denied_response(&self) -> Option<axum::response::Response> {
        if self.denied {
            tracing::warn!(
                name = %self.name,
                "Docker request denied: no prefix, namespaces or registry host routes this name"
            );
            Some(
                (
                    axum::http::StatusCode::FORBIDDEN,
                    axum::Json(serde_json::json!({
                        "errors": [{
                            "code": "DENIED",
                            "message": "no upstream prefix, namespaces or registry host routes this image name",
                            "detail": "default_action is set to deny"
                        }]
                    })),
                )
                    .into_response(),
            )
        } else {
            None
        }
    }
}

/// Canonicalize a Docker image name: resolve upstream, strip prefix/hostname,
/// and determine the storage namespace.
///
/// This is the single entry point for Docker name resolution. Use instead of
/// the heuristic `strip_docker_namespace()` whenever upstream config is available.
///
/// Resolution order (early-return):
/// 1. Prefix match — first path segment matches a configured upstream prefix
/// 2. Namespace binding — first segment of a multi-segment name is owned by an upstream's
///    `namespaces` (#1188): the name is kept whole, and that upstream is the only one asked,
///    under either `default_action`
/// 3. Hostname detection — first segment contains a dot (FQDN like `docker.io`): the
///    upstream that serves the host ([`crate::config::DockerUpstream::serves_host`]); Docker Hub without an
///    upstream of its own is the fallback chain, as a bare name is; any other host has no
///    upstream, and the name is answered from local storage only (#1195)
/// 4. Fallback — if `default_action = deny`, mark as denied; otherwise use
///    the first upstream that owns no namespaces
pub(crate) fn canonicalize(
    raw_name: &str,
    docker_config: &crate::config::DockerConfig,
) -> Canonical {
    let upstreams = &docker_config.upstreams;
    let deny_mode = docker_config.default_action == crate::config::DefaultAction::Deny;
    // Copies served by the fallback chain are stored under its first upstream's namespace.
    let fallback_ns = || {
        upstreams
            .iter()
            .find(|u| !u.is_bound())
            .map(|u| u.resolved_namespace())
    };

    // Step 1: Check for prefix-based routing
    if let Some((first_segment, rest)) = raw_name.split_once('/') {
        for (idx, upstream) in upstreams.iter().enumerate() {
            if let Some(ref prefix) = upstream.prefix {
                if first_segment == prefix {
                    tracing::debug!(
                        prefix = %prefix,
                        upstream = %upstream.url,
                        stripped_name = %rest,
                        routing = "prefix",
                        "Docker path-based upstream routing"
                    );
                    return Canonical {
                        name: rest.to_string(),
                        namespace: Some(upstream.resolved_namespace()),
                        route: Route::Upstream(idx),
                        denied: false,
                    };
                }
            }
        }

        // Step 2: Namespace binding — the owner gets the whole name; its answer is final
        if let Some(idx) = upstreams.iter().position(|u| u.binds(first_segment)) {
            tracing::debug!(
                upstream = %upstreams[idx].url,
                name = %raw_name,
                routing = "namespaces",
                "Docker namespace-bound upstream routing"
            );
            return Canonical {
                name: raw_name.to_string(),
                namespace: Some(upstreams[idx].resolved_namespace()),
                route: Route::Upstream(idx),
                denied: false,
            };
        }

        // Step 3: Hostname detection (dot in first segment = FQDN)
        if first_segment.contains('.') && !rest.is_empty() {
            if let Some(idx) = upstreams.iter().position(|u| u.serves_host(first_segment)) {
                return Canonical {
                    name: rest.to_string(),
                    namespace: Some(upstreams[idx].resolved_namespace()),
                    route: Route::Upstream(idx),
                    denied: false,
                };
            }
            // Docker Hub is where a bare name lives: without an upstream of its own, the chain.
            if crate::config::is_docker_hub_host(first_segment) {
                return Canonical {
                    name: rest.to_string(),
                    namespace: fallback_ns(),
                    route: Route::Chain,
                    denied: deny_mode,
                };
            }
            // Any other host: another registry's name, which no upstream here may answer.
            // `None` keeps the cached copies of the upstreams out; local pushes stay readable.
            return Canonical {
                name: rest.to_string(),
                namespace: None,
                route: Route::UnknownHost(first_segment.to_string()),
                denied: deny_mode,
            };
        }
    }

    // Step 4: Fallback — first unbound upstream, name unchanged
    let ns = fallback_ns();
    Canonical {
        name: raw_name.to_string(),
        namespace: ns,
        route: Route::Chain,
        denied: deny_mode,
    }
}

/// Open a streaming reader for a blob, trying namespaced then legacy key (#580).
///
/// This provides backward compatibility during migration from flat to namespaced storage.
/// The fallback fires ONLY on `NotFound`: the two keys can hold different bytes (a
/// proxied-current copy vs a pre-migration one), so falling back on a transient backend
/// error would make which copy is served depend on backend weather — a per-request
/// divergent answer for the same reference. Transient errors propagate instead.
async fn storage_get_reader_with_fallback(
    storage: &Storage,
    ns_key: &str,
    legacy_key: &str,
) -> Result<
    (
        u64,
        std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
    ),
    crate::storage::StorageError,
> {
    match storage.get_reader(ns_key).await {
        Err(crate::storage::StorageError::NotFound) if ns_key != legacy_key => {
            storage.get_reader(legacy_key).await
        }
        other => other,
    }
    // Docker blobs are content-addressed: the URL digest is the integrity
    // check, so the stored pin is not needed here.
    .map(|(size, _pin, reader)| (size, reader))
}

/// A blob served from storage or from a fill in flight, checked against its digest as it
/// streams. The stream holds its last frame back until the digest is verified, so a blob
/// whose bytes do not match never arrives complete: hyper stops reading a body once the
/// declared `Content-Length` is out, and a check that waited for one more read after the last
/// byte never ran (R19). The docker client's own digest check is the complementary layer.
fn blob_verifying_stream(
    reader: std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
    digest: &str,
    log_key: String,
) -> nora_registry::verified::VerifyingStream {
    let expected = digest
        .strip_prefix("sha256:")
        .unwrap_or(digest)
        .to_ascii_lowercase();
    nora_registry::verified::verify_while_streaming(reader, Some(expected), log_key, None)
}

/// Check if a key exists in namespaced or legacy location.
async fn storage_stat_with_fallback(
    storage: &Storage,
    ns_key: &str,
    legacy_key: &str,
) -> Option<crate::storage::FileMeta> {
    if let Some(meta) = storage.stat(ns_key).await {
        return Some(meta);
    }
    if ns_key != legacy_key {
        return storage.stat(legacy_key).await;
    }
    None
}

/// Metadata for a Docker image stored alongside manifests
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ImageMetadata {
    pub push_timestamp: u64,
    pub last_pulled: u64,
    pub downloads: u64,
    pub size_bytes: u64,
    pub os: String,
    pub arch: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    pub layers: Vec<LayerInfo>,
    /// Set on a push: the digest of the manifest pushed to this tag. A push answers its tag
    /// whatever an upstream holds for it; a manifest without this record (pushed before 1.4.0,
    /// or a flat proxy cache from before #349) keeps its old place in the lookup order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pushed_digest: Option<String>,
}

/// Information about a single layer in a Docker image
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerInfo {
    pub digest: String,
    pub size: u64,
}

/// One manifest's un-flushed pull statistics (#1114).
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(crate) struct PullDelta {
    /// Pulls counted since the last flush.
    pub downloads: u64,
    /// Most recent pull time (unix secs) seen since the last flush.
    pub last_pulled: u64,
}

/// In-memory, off-request-path accumulator for docker pull statistics (#1114).
///
/// A manifest GET bumps the per-key counter here (a microsecond lock, no I/O)
/// instead of rewriting the manifest's `.meta.json` — which every pull used to
/// do and which raced the request-path publish-date read, logging INTEGRITY
/// VIOLATION on healthy data. A background task drains this in batches into a
/// separate `.stats.json` sidecar, so `.meta.json` is immutable after publish.
///
/// Soft state: the map is rebuildable-empty after a restart, so at most one
/// flush interval of counts is lost on a crash (accepted — pull stats are
/// best-effort, like the in-memory indexes). Mirrors the `publish_locks`
/// pattern (`parking_lot::Mutex<HashMap>`) to add no new dependency.
#[derive(Default)]
pub(crate) struct PullStatsAccumulator {
    inner: parking_lot::Mutex<std::collections::HashMap<String, PullDelta>>,
}

impl PullStatsAccumulator {
    /// Record one pull of `meta_key` at `now` (unix secs). Cheap: a brief lock,
    /// no storage I/O, no spawn, no publish lock.
    pub(crate) fn record(&self, meta_key: &str, now: u64) {
        let mut g = self.inner.lock();
        let e = g.entry(meta_key.to_string()).or_default();
        e.downloads += 1;
        if now > e.last_pulled {
            e.last_pulled = now;
        }
    }

    /// Take and clear every accumulated delta — for the flush task.
    pub(crate) fn drain(&self) -> Vec<(String, PullDelta)> {
        std::mem::take(&mut *self.inner.lock())
            .into_iter()
            .collect()
    }

    /// The current un-flushed delta for one key (for the UI read path to add on
    /// top of the flushed sidecar value). Default (zeros) when nothing pending.
    pub(crate) fn peek(&self, meta_key: &str) -> PullDelta {
        self.inner.lock().get(meta_key).copied().unwrap_or_default()
    }
}

/// In-progress upload session with metadata.
///
/// Blob data is streamed frame-by-frame to a temporary file, bounded per request
/// by [`effective_upload_cap`] and globally by [`IN_FLIGHT_UPLOADS`]; the request
/// body is never fully buffered in RAM (#817). Finalization hashes the temp file
/// and moves it into storage via `put_from_path` without an in-RAM copy.
pub struct UploadSession {
    /// Path to the temporary file holding blob data.
    temp_path: std::path::PathBuf,
    /// Current size of data written to temp file.
    size: u64,
    name: String,
    created_at: std::time::Instant,
}

/// Max concurrent upload sessions (prevent memory exhaustion)
const DEFAULT_MAX_UPLOAD_SESSIONS: usize = 100;
/// Max data per session (default 2 GB, configurable via NORA_MAX_UPLOAD_SESSION_SIZE_MB)
const DEFAULT_MAX_SESSION_SIZE_MB: usize = 2048;
/// Session TTL (30 minutes)
const SESSION_TTL: Duration = Duration::from_secs(30 * 60);

/// Read max upload sessions from env or use default
fn max_upload_sessions() -> usize {
    std::env::var("NORA_MAX_UPLOAD_SESSIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_UPLOAD_SESSIONS)
}

/// OCI-conformant 429 for the concurrent-upload ceiling. containers/common
/// retry logic only backs off on errcode TOOMANYREQUESTS in a JSON body; a
/// plain-text 429 aborts the client push outright.
fn too_many_uploads() -> Response {
    let body = json!({
        "errors": [{
            "code": "TOOMANYREQUESTS",
            "message": "too many concurrent uploads",
            "detail": { "limit": max_upload_sessions() }
        }]
    });
    // Jittered, not fixed: a constant retry window re-synchronizes every refused
    // client onto the same cadence, so the herd returns together and the same
    // subset wins each round.
    let retry_after = rand::Rng::gen_range(&mut rand::thread_rng(), 3..=10).to_string();
    (
        StatusCode::TOO_MANY_REQUESTS,
        [
            (header::RETRY_AFTER, retry_after.as_str()),
            (header::CONTENT_TYPE, "application/json"),
        ],
        body.to_string(),
    )
        .into_response()
}

/// Read max session size from env (in MB) or use default
fn max_session_size() -> usize {
    let mb = std::env::var("NORA_MAX_UPLOAD_SESSION_SIZE_MB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_MAX_SESSION_SIZE_MB);
    mb.saturating_mul(1024 * 1024)
}

/// Max bytes buffered for a manifest PUT. Manifests/indexes are small JSON
/// (layer lists + a config reference); a streaming `Body` extractor is not
/// bounded by `DefaultBodyLimit`, so the dispatcher caps the manifest collect
/// explicitly — otherwise the OOM this fix removes from blobs would just move to
/// the manifest path (#817). 4 MiB matches common registry limits.
const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;

/// Per-request byte ceiling for a blob upload: the smaller of the upload-session
/// cap and the operator's global `body_limit_mb`. A streaming `Body` extractor
/// is NOT subject to `DefaultBodyLimit` (that only bounds `Bytes`-based
/// extractors), so the streaming paths must re-apply the tuned-down limit
/// themselves, or lowering `body_limit_mb` would silently stop bounding uploads.
fn effective_upload_cap(body_limit_mb: usize) -> u64 {
    let body_limit = (body_limit_mb as u64).saturating_mul(1024 * 1024);
    std::cmp::min(max_session_size() as u64, body_limit)
}

/// Global count of in-flight streaming blob uploads. Bounds concurrent uploads —
/// including monolithic POSTs, which never open a session and so bypass
/// `max_upload_sessions` — so streaming to disk cannot fan out unboundedly and
/// exhaust the disk (#817). Ceiling mirrors `max_upload_sessions`.
static IN_FLIGHT_UPLOADS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// RAII guard: reserves an in-flight-upload slot, releasing it on drop (all exit
/// paths incl. cancellation/panic). `try_acquire` returns `None` if the ceiling
/// is already reached (caller returns 429).
struct InFlightGuard;

impl InFlightGuard {
    fn try_acquire() -> Option<Self> {
        use std::sync::atomic::Ordering;
        let prev = IN_FLIGHT_UPLOADS.fetch_add(1, Ordering::AcqRel);
        if prev >= max_upload_sessions() {
            IN_FLIGHT_UPLOADS.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(InFlightGuard)
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        IN_FLIGHT_UPLOADS.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// Current in-flight streaming upload count, sampled by the `/metrics` scrape.
pub fn in_flight_uploads() -> usize {
    IN_FLIGHT_UPLOADS.load(std::sync::atomic::Ordering::Acquire)
}

/// RAII guard for `PROXY_ACTIVE_DOWNLOADS` gauge — decrements on drop (#580).
///
/// Guarantees the gauge stays accurate on all exit paths including panics,
/// early `?` returns, and tokio task cancellation.
struct ProxyDownloadGuard;

impl Drop for ProxyDownloadGuard {
    fn drop(&mut self) {
        crate::metrics::PROXY_ACTIVE_DOWNLOADS.dec();
    }
}

/// Validate that an upload UUID from URL path is safe (no path traversal).
///
/// Accepts only lowercase hex + hyphens (UUID-4 format) up to 36 chars.
/// Rejects `/`, `..`, null bytes, and anything that could escape the temp directory.
fn validate_upload_uuid(uuid: &str) -> Result<(), &'static str> {
    if uuid.is_empty() || uuid.len() > 36 {
        return Err("invalid upload UUID length");
    }
    if uuid
        .bytes()
        .any(|b| !matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'-'))
    {
        return Err("invalid upload UUID characters");
    }
    Ok(())
}

/// Remove stale temp files from the Docker upload directory.
///
/// Files older than `SESSION_TTL` are removed regardless of name format.
/// Called at startup and periodically from the background task (mirrors
/// [`cleanup_proxy_temp_dir`]), so an upload temp orphaned by a storage-write
/// failure — whose session entry is already gone, so `cleanup_expired_sessions`
/// will never free it — is reclaimed without waiting for a restart. The
/// Get the temp directory for Docker uploads, creating it if needed.
fn upload_temp_dir(data_dir: &str) -> std::path::PathBuf {
    let dir = std::path::PathBuf::from(data_dir).join("tmp/docker-uploads");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        tracing::error!(path = %dir.display(), error = %e, "failed to create upload temp directory");
    }
    dir
}

fn proxy_temp_dir(data_dir: &str) -> std::path::PathBuf {
    let dir = std::path::PathBuf::from(data_dir).join("tmp/docker-proxy");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        tracing::error!(path = %dir.display(), error = %e, "failed to create proxy temp directory");
    }
    dir
}

/// Remove expired upload sessions and their temp files (called by background task)
pub fn cleanup_expired_sessions(sessions: &RwLock<HashMap<String, UploadSession>>) {
    let mut guard = sessions.write();
    let before = guard.len();
    guard.retain(|_, s| {
        // Reap only sessions that are BOTH past their creation TTL AND whose temp
        // file has not been written recently. `created_at` never advances, so a
        // slow multi-GB upload that streams for many minutes (#817) would be
        // unlinked mid-flight if we keyed off creation alone — losing the open
        // fd's data and 404-ing an otherwise-successful push. The temp's mtime
        // advances with every frame, so an in-flight stream stays safe (same
        // active-write-safe check `cleanup_upload_temp_dir` already uses).
        if s.created_at.elapsed() < SESSION_TTL {
            return true;
        }
        let temp_active = std::fs::metadata(&s.temp_path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age < SESSION_TTL);
        if temp_active {
            return true;
        }
        let _ = std::fs::remove_file(&s.temp_path);
        false
    });
    let removed = before - guard.len();
    if removed > 0 {
        tracing::info!(
            removed = removed,
            remaining = guard.len(),
            "Cleaned up expired upload sessions"
        );
    }
}

/// `SESSION_TTL` age guard keeps in-progress uploads safe under the periodic call.
pub fn cleanup_upload_temp_dir(data_dir: &str) {
    let dir = std::path::PathBuf::from(data_dir).join("tmp/docker-uploads");
    let removed = super::remove_stale_temp_files(&dir, SESSION_TTL);
    if removed > 0 {
        tracing::info!(removed, dir = %dir.display(), "Cleaned up stale Docker upload temp files");
    }
}

/// Max age for proxy temp files before cleanup removes them (#580).
///
/// 4 hours — long enough for slow multi-GB downloads over constrained links,
/// short enough to reclaim disk from orphaned files (crash, cancel, OOM).
const PROXY_TEMP_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(4 * 60 * 60);

/// Remove stale temp files from the Docker proxy download directory (#580).
///
/// Files older than `PROXY_TEMP_MAX_AGE` are removed. Called at startup
/// (catches orphans from crashes) and periodically from the background task.
/// Logs warnings on errors but never panics — cleanup is best-effort.
pub fn cleanup_proxy_temp_dir(data_dir: &str) {
    let dir = std::path::PathBuf::from(data_dir).join("tmp/docker-proxy");
    let removed = super::remove_stale_temp_files(&dir, PROXY_TEMP_MAX_AGE);
    if removed > 0 {
        tracing::info!(removed, dir = %dir.display(), "Cleaned up stale proxy temp files");
    }
}

/// Resolve effective quarantine mode and TTL (seconds) for Docker.
///
/// Returns `(QuarantineMode, quarantine_secs)`. Per-registry override takes
/// precedence over global curation config. Returns `(Off, 0)` when disabled.
fn resolve_quarantine(state: &AppState) -> (crate::digest_quarantine::QuarantineMode, i64) {
    use crate::digest_quarantine::QuarantineMode;

    let mode = state
        .config
        .curation
        .docker
        .quarantine
        .as_ref()
        .or(state.config.curation.quarantine.as_ref())
        .cloned()
        .unwrap_or(QuarantineMode::Off);
    if matches!(mode, QuarantineMode::Off) {
        return (QuarantineMode::Off, 0);
    }

    let ttl_str = state
        .config
        .curation
        .docker
        .quarantine_ttl
        .as_deref()
        .or(state.config.curation.quarantine_ttl.as_deref())
        .unwrap_or("14d");

    // Config validation refuses a TTL that does not parse (#1099); the default only
    // covers a config built without it.
    let secs = crate::curation::parse_duration(ttl_str).unwrap_or(14 * 86400);
    (mode, secs)
}

/// Build an HTTP 403 response for a quarantined digest.
fn quarantine_forbidden(
    digest: &str,
    status: &crate::digest_quarantine::QuarantineStatus,
    quarantine_secs: i64,
) -> Response {
    let remaining = match status {
        crate::digest_quarantine::QuarantineStatus::New => quarantine_secs,
        crate::digest_quarantine::QuarantineStatus::Pending { remaining_secs } => *remaining_secs,
        crate::digest_quarantine::QuarantineStatus::Mature => 0,
    };
    let quarantine_until = chrono::Utc::now().timestamp() + remaining;

    let body = json!({
        "errors": [{
            "code": "DENIED",
            "message": "held by quarantine policy on registry 'docker': digest must age past the quarantine window",
            "detail": {
                "registry": "docker",
                "digest": digest,
                "policy": {
                    "control": "quarantine",
                    "quarantine_ttl_secs": quarantine_secs,
                },
                "quarantine_until": quarantine_until,
            }
        }]
    });

    (
        StatusCode::FORBIDDEN,
        [
            (
                HeaderName::from_static("x-nora-quarantine"),
                status.header_value().to_string(),
            ),
            (
                HeaderName::from_static("x-nora-quarantine-until"),
                quarantine_until.to_string(),
            ),
            (header::CONTENT_TYPE, "application/json".to_string()),
        ],
        body.to_string(),
    )
        .into_response()
}

/// The quarantine verdict on a served (200) manifest, in the headers the 403 carries, so a
/// client can read it under `observe` too (fluxcd `scripts/nora-image-check.py`):
/// `x-nora-quarantine: pending` plus `x-nora-quarantine-until` (unix seconds) while the
/// digest is still within the TTL, `mature` once admitted: past the TTL, dated past it by
/// the registry (`trust_upstream_dates`), quarantine off, or served without a proxy record
/// (a local push), `exception` while held but admitted by a break-glass exception
/// ([`quarantine_excepted`]). A 403 keeps the headers [`quarantine_forbidden`] set.
fn with_quarantine_verdict(state: &AppState, mut resp: Response) -> Response {
    if resp.status() != StatusCode::OK {
        return resp;
    }
    let Some(digest) = resp
        .headers()
        .get("docker-content-digest")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
    else {
        return resp;
    };
    let (q_mode, q_secs) = resolve_quarantine(state);
    let held = match q_mode {
        crate::digest_quarantine::QuarantineMode::Off => None,
        _ => match state.digest_store.check("docker", &digest, q_secs) {
            crate::digest_quarantine::QuarantineStatus::Pending { remaining_secs } => {
                Some(remaining_secs)
            }
            _ => None,
        },
    };
    // Held, but admitted by a break-glass exception: served, and said so.
    let excepted = held.is_some() && state.quarantine_exceptions.covering(&digest).is_some();
    let held = held.filter(|_| !excepted);
    let headers = resp.headers_mut();
    let verdict = match (excepted, held) {
        (true, _) => "exception",
        (false, Some(_)) => "pending",
        (false, None) => "mature",
    };
    headers.insert(
        HeaderName::from_static("x-nora-quarantine"),
        axum::http::HeaderValue::from_static(verdict),
    );
    if let Some(remaining) = held {
        let until = chrono::Utc::now().timestamp() + remaining;
        headers.insert(
            HeaderName::from_static("x-nora-quarantine-until"),
            axum::http::HeaderValue::from(until),
        );
    }
    resp
}

/// Build a 404 `MANIFEST_UNKNOWN` response per the OCI Distribution Spec.
///
/// Used for a genuine not-found on a manifest we do not hold — including the local
/// miss on a hosted internal-namespace repo (#821): namespace isolation refuses to
/// proxy an internal name upstream, but a hosted image's absent tag is a not-found,
/// not an authorization denial. Docker/BuildKit treats `403` on a manifest
/// `HEAD`/`GET` as fatal, whereas `404 MANIFEST_UNKNOWN` lets push pre-flight probes
/// and OCI referrers lookups proceed.
fn manifest_unknown_response(name: &str, reference: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "errors": [{
                "code": "MANIFEST_UNKNOWN",
                "message": "manifest unknown",
                "detail": { "name": name, "reference": reference }
            }]
        })),
    )
        .into_response()
}

/// What a Docker miss was asked for, to name it in the OCI error.
enum Missed<'a> {
    Manifest { name: &'a str, reference: &'a str },
    Blob { name: &'a str, digest: &'a str },
}

/// The answer to a Docker miss once every upstream was asked ([`UpstreamMiss::response`] decides
/// the status and logs it), with the OCI error body a client prints (#1189): a manifest or blob no
/// upstream has is `MANIFEST_UNKNOWN` / `BLOB_UNKNOWN`, as a hosted miss answers; an upstream that
/// failed or was skipped for its open breaker is `UNAVAILABLE`; a refusal of NORA's credentials
/// is `DENIED` (#1196). Headers the status carries (`Retry-After` of a 503) are kept.
fn docker_miss_response(miss: &UpstreamMiss, missed: Missed<'_>) -> Response {
    let path = match missed {
        Missed::Manifest { name, reference } => format!("{name}:{reference}"),
        Missed::Blob { name, digest } => format!("{name}@{digest}"),
    };
    let response = miss.response("docker", &path);
    let status = response.status();
    let (code, message, detail) = if miss.credentials_refused() {
        (
            "DENIED",
            "an upstream registry refused NORA's credentials".to_string(),
            json!("the credentials NORA has for this upstream are wrong, lack pull access, or are not configured"),
        )
    } else if status == StatusCode::NOT_FOUND {
        return match missed {
            Missed::Manifest { name, reference } => manifest_unknown_response(name, reference),
            Missed::Blob { digest, .. } => blob_unknown_response(digest),
        };
    } else if miss.open_key().is_some() {
        // miss.response logged the breaker key; the body never names the upstream's URL.
        (
            "UNAVAILABLE",
            "upstream docker temporarily unavailable".to_string(),
            json!("its circuit breaker is open; retry after the Retry-After interval"),
        )
    } else {
        (
            "UNAVAILABLE",
            "every upstream registry failed to answer".to_string(),
            json!("the upstream answered 5xx, timed out or could not be reached; see NORA's log"),
        )
    };
    let (mut parts, _) = response.into_parts();
    parts.headers.remove(header::CONTENT_LENGTH);
    parts.headers.remove(header::CONTENT_TYPE);
    let body = Json(json!({
        "errors": [{ "code": code, "message": message, "detail": detail }]
    }));
    (parts, body).into_response()
}

/// Build a 404 `BLOB_UNKNOWN` response per the OCI Distribution Spec.
///
/// Companion to [`manifest_unknown_response`] for blobs; used for the internal-
/// namespace local miss (#821) so `GET` agrees with the `HEAD` probe (`check_blob`
/// already 404s) and never conflates not-found with `403 Forbidden`.
fn blob_unknown_response(digest: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "errors": [{
                "code": "BLOB_UNKNOWN",
                "message": "blob unknown to registry",
                "detail": { "digest": digest }
            }]
        })),
    )
        .into_response()
}

/// Cache-serve quarantine gate for an already-cached artifact with a known digest.
///
/// Blocks (403 in enforce) ONLY when a proxy record for this digest is still
/// `Pending`. A digest with no proxy record (`New` — a locally-pushed or internal
/// artifact, or a record pruned past 90d) is served, and `Mature` is served. Local
/// pushes are not recorded, so they always read as `New` and serve; a trusted push
/// can therefore neither hold nor mature a digest on the proxy path. Returns
/// `Some(403)` to block, `None` to proceed.
#[must_use = "the returned response blocks a quarantined artifact; dropping it serves it"]
fn quarantine_cache_serve_gate(
    state: &AppState,
    digest: &str,
    manifest: Option<&[u8]>,
) -> Option<Response> {
    let (q_mode, q_secs) = resolve_quarantine(state);
    if matches!(q_mode, crate::digest_quarantine::QuarantineMode::Off) {
        return None;
    }
    let status = state.digest_store.check("docker", digest, q_secs);
    if let crate::digest_quarantine::QuarantineStatus::Pending { .. } = status {
        if quarantine_excepted(state, digest, manifest) {
            return None;
        }
        let outcome = if matches!(q_mode, crate::digest_quarantine::QuarantineMode::Enforce) {
            "blocked"
        } else {
            "observed"
        };
        crate::metrics::QUARANTINE_HOLDS_TOTAL
            .with_label_values(&["docker", outcome])
            .inc();
        tracing::warn!(
            digest = %digest,
            status = %status.header_value(),
            mode = ?q_mode,
            quarantine_ttl_secs = q_secs,
            "Quarantine: held cached artifact (proxy cooldown)"
        );
        if matches!(q_mode, crate::digest_quarantine::QuarantineMode::Enforce) {
            return Some(quarantine_forbidden(digest, &status, q_secs));
        }
    }
    None
}

/// Whether a break-glass exception (`[docker] quarantine_exceptions`, quarantine_exceptions.rs)
/// admits `digest`, which the quarantine holds. `manifest` is its bytes when it is a manifest:
/// what it names is admitted with it, so a pull of the listed image gets its platform
/// manifests and blobs. Each use is logged and counted.
fn quarantine_excepted(state: &AppState, digest: &str, manifest: Option<&[u8]>) -> bool {
    let Some((listed, entry)) = state.quarantine_exceptions.covering(digest) else {
        return false;
    };
    if let Some(m) = manifest {
        state.quarantine_exceptions.admit_named(&listed, m);
    }
    crate::metrics::DOCKER_QUARANTINE_EXCEPTION_USED_TOTAL
        .with_label_values(&[listed.as_str(), entry.reason.as_str()])
        .inc();
    tracing::warn!(
        digest = %digest,
        listed = %listed,
        reason = %entry.reason,
        expires = entry.expires,
        "Quarantine: held digest admitted by a break-glass exception"
    );
    true
}

/// Post-proxy-fetch quarantine gate for a blob with a known content digest.
///
/// Records the digest as first-seen on the proxy path, then blocks (403 in enforce)
/// until it matures. Mirrors the manifest proxy-fetch path. `record` is idempotent,
/// so the cooldown clock starts at the first proxy fetch and never resets. The caller
/// caches the blob before calling this, so a held blob is still cached (the client is
/// blocked, not the cache) — identical to the manifest behaviour.
#[must_use = "the returned response blocks a quarantined artifact; dropping it serves it"]
/// Decide, without recording, whether a proxy-fetched blob is served or held: a digest
/// this mirror has never seen is treated as freshly quarantined for the decision, and is
/// recorded by [`quarantine_record_verified`] only once its fetch has verified — a fetch
/// that fails must not leave a first-seen timestamp behind for the real blob to inherit.
fn quarantine_proxy_fetch_gate(state: &AppState, digest: &str, upstream: &str) -> Option<Response> {
    let (q_mode, q_secs) = resolve_quarantine(state);
    if matches!(q_mode, crate::digest_quarantine::QuarantineMode::Off) {
        return None;
    }
    let status = match state.digest_store.check("docker", digest, q_secs) {
        crate::digest_quarantine::QuarantineStatus::New => {
            crate::digest_quarantine::QuarantineStatus::Pending {
                remaining_secs: q_secs,
            }
        }
        status => status,
    };
    if !matches!(status, crate::digest_quarantine::QuarantineStatus::Mature)
        && !quarantine_excepted(state, digest, None)
    {
        let outcome = if matches!(q_mode, crate::digest_quarantine::QuarantineMode::Enforce) {
            "blocked"
        } else {
            "observed"
        };
        crate::metrics::QUARANTINE_HOLDS_TOTAL
            .with_label_values(&["docker", outcome])
            .inc();
        tracing::warn!(
            digest = %digest,
            upstream = %upstream,
            status = %status.header_value(),
            mode = ?q_mode,
            quarantine_ttl_secs = q_secs,
            "Quarantine: proxy-fetched blob held (new to this mirror)"
        );
        if matches!(q_mode, crate::digest_quarantine::QuarantineMode::Enforce) {
            return Some(quarantine_forbidden(digest, &status, q_secs));
        }
    }
    None
}

/// Record a verified proxy-fetched blob as first seen now. A blob never carries an
/// upstream date of its own (only a manifest naming it dates it, #112) — NORA's own
/// clock, preserving the GHSA-4j4m fix. Idempotent: an existing record keeps its timestamp.
fn quarantine_record_verified(state: &AppState, digest: &str, upstream: &str) {
    let (q_mode, _) = resolve_quarantine(state);
    if matches!(q_mode, crate::digest_quarantine::QuarantineMode::Off) {
        return;
    }
    state.digest_store.record("docker", digest, upstream, None);
}

/// Start the quarantine clock of every digest a proxied manifest names (an index's
/// manifests, an image's config and layers) at the manifest's own first-seen. Without
/// it enforce held one level at a time, because a client asks for a child only once its
/// parent is served: the index for a TTL, then the platform manifest, then the blobs —
/// three TTLs for a multi-arch image. The names come from bytes hashed to the manifest
/// digest, and the date is the manifest's own first-seen: NORA's first sight of it, or
/// the registry's publish date under `trust_upstream_dates`, so no child is older than
/// what names it. Idempotent: a digest recorded later moves back to this date, never forward.
/// `persist` keeps a move across a restart ([`DigestStore::backdate`]).
///
/// [`DigestStore::backdate`]: crate::digest_quarantine::DigestStore::backdate
fn quarantine_record_referenced(
    state: &AppState,
    manifest: &[u8],
    upstream: &str,
    first_seen: i64,
    persist: bool,
) {
    for d in named_digests(manifest) {
        state
            .digest_store
            .record("docker", &d, upstream, Some(first_seen));
        // A digest with its own later record (a platform manifest pulled first, a layer
        // shared with a newer image) has existed since the manifest naming it.
        state
            .digest_store
            .backdate("docker", &d, first_seen, persist);
    }
}

/// Date `digest`, a manifest `upstream` served, at `at`, its registry's publish date, and
/// what it names with it (an index's platform manifests, which public.ecr.aws lists under no
/// tag), when that is earlier than the ledger has: on its first sight, a later fetch, a
/// cached serve or a walk that answered after the request stopped waiting. Persisted, so a
/// restart keeps it. Returns the entry.
pub(super) fn quarantine_dated(
    state: &AppState,
    upstream: &str,
    name: &str,
    digest: &str,
    manifest: &[u8],
    at: i64,
    source: &str,
) -> crate::digest_quarantine::DigestEntry {
    let mut entry = state
        .digest_store
        .record("docker", digest, upstream, Some(at));
    if at < entry.first_seen {
        if let Some(moved) = state.digest_store.backdate("docker", digest, at, true) {
            tracing::info!(digest = %digest, name = %name, source, was = entry.first_seen, first_seen = at, "Quarantine: held manifest dated by its registry");
            entry = moved;
        }
    }
    quarantine_record_referenced(state, manifest, upstream, entry.first_seen, true);
    entry
}

/// A cached manifest NORA's own clock still holds is asked about again before it is served:
/// a digest pull never reaches the upstream, so a digest whose first lookup missed (a walk
/// slower than the request's wait, a ledger entry from before its registry had a date
/// source) would stay held to the TTL. Only a registry dated by a walk of the repository,
/// which every request of the repository shares: a held digest costs no request of its own.
async fn quarantine_redate_cached(
    state: &AppState,
    upstreams: &[&crate::config::DockerUpstream],
    name: &str,
    reference: &str,
    manifest: &[u8],
) {
    let (q_mode, q_secs) = resolve_quarantine(state);
    if matches!(q_mode, crate::digest_quarantine::QuarantineMode::Off) {
        return;
    }
    use sha2::Digest;
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(manifest)));
    if !matches!(
        state.digest_store.check("docker", &digest, q_secs),
        crate::digest_quarantine::QuarantineStatus::Pending { .. }
    ) {
        return;
    }
    for upstream in upstreams {
        let Some(source) = upstream
            .date_source()
            .filter(|source| upstream.trust_upstream_dates && source.walks_repository())
        else {
            continue;
        };
        if let Some(at) = super::docker_dates::published_at(
            state, upstream, source, name, reference, &digest, manifest,
        )
        .await
        {
            quarantine_dated(
                state,
                &upstream.url,
                name,
                &digest,
                manifest,
                at,
                source.label(),
            );
            return;
        }
    }
}

/// The digests a manifest names: an index's manifests, an image's config and layers.
pub(crate) fn named_digests(manifest: &[u8]) -> Vec<String> {
    let Ok(doc) = serde_json::from_slice::<serde_json::Value>(manifest) else {
        return Vec::new();
    };
    let listed = ["manifests", "layers"]
        .iter()
        .filter_map(|k| doc[*k].as_array())
        .flatten();
    listed
        .chain(std::iter::once(&doc["config"]))
        .filter_map(|named| named["digest"].as_str())
        .filter(|d| validate_digest(d).is_ok())
        .map(str::to_owned)
        .collect()
}

/// Admit what a cached proxied manifest names when the manifest itself is admitted. A
/// ledger entry past 90 days is pruned at boot, or never written for a registry date that
/// old, so after a restart the manifest serves with no record while an uncached blob of it
/// would read as new and start a fresh TTL. The date is past the prune line, so nothing is
/// persisted, and `record` leaves a digest with its own record alone. Not for a local push
/// (`ns` is `None`: a push never matures a proxy digest), a manifest still held, or a
/// ledger not read whole (loading, or failed in part), where a held manifest has no record
/// either.
fn quarantine_readmit_referenced(
    state: &AppState,
    manifest: &[u8],
    digest: &str,
    ns: Option<&str>,
) {
    let (q_mode, q_secs) = resolve_quarantine(state);
    let Some(ns) = ns.filter(|_| state.digest_store.loaded()) else {
        return;
    };
    if matches!(q_mode, crate::digest_quarantine::QuarantineMode::Off)
        || matches!(
            state.digest_store.check("docker", digest, q_secs),
            crate::digest_quarantine::QuarantineStatus::Pending { .. }
        )
    {
        return;
    }
    let long_ago = chrono::Utc::now().timestamp() - crate::digest_quarantine::PRUNE_TTL_SECS - 1;
    quarantine_record_referenced(state, manifest, ns, long_ago, false);
}

/// Whether `copy`, the cached answer for tag `reference`, may stand in for `held`, the
/// digest the tag moved to: a different manifest that is not itself held. A digest with no
/// ledger record reads as admitted, as on the cache-serve gate: its record was pruned past
/// 90 days, or it was cached before the quarantine was on. A digest reference never falls
/// back: it asks for those bytes and no others.
fn admitted_copy(
    state: &AppState,
    reference: &str,
    copy: &[u8],
    held: &str,
    quarantine_secs: i64,
) -> bool {
    use sha2::Digest;
    if reference.starts_with("sha256:") {
        return false;
    }
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(copy)));
    digest != held
        && !matches!(
            state.digest_store.check("docker", &digest, quarantine_secs),
            crate::digest_quarantine::QuarantineStatus::Pending { .. }
        )
}

/// Docker v2 routes.
/// Uses a `{*rest}` wildcard to support image names with arbitrary path depth
/// (e.g., `library/astra/ubi18-cpp122`), per OCI Distribution spec.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/v2/",
            get(check).fallback(|| async { method_not_allowed("GET") }),
        )
        .route("/v2/_catalog", get(catalog))
        .route("/v2/{*rest}", axum::routing::any(docker_v2_dispatch))
}

/// Unified dispatcher for all Docker v2 image endpoints.
/// Parses the image name (arbitrary depth) and operation from the wildcard path,
/// then delegates to the appropriate handler with correct method routing.
async fn docker_v2_dispatch(
    state: State<AppState>,
    method: Method,
    Path(wildcard): Path<String>,
    Extension(authority): Extension<NamespaceAuthority>,
    uri: Uri,
    headers: axum::http::HeaderMap,
    body: Body,
) -> Response {
    let rest = wildcard.trim_start_matches('/');
    if rest.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Writes (push/delete) are gated by OIDC namespace_scope on the image name,
    // which is the docker namespace coordinate (#583). Reads are never gated here.
    let is_write = matches!(
        method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    );

    // Parse endpoint pattern from right — handles names containing "blobs", "manifests", etc.
    // Order matters: check blob uploads before blobs (substring overlap).

    // 1. Blob uploads: {name}/blobs/uploads/ or {name}/blobs/uploads/{uuid}
    if let Some((name, after)) = rest.rsplit_once("/blobs/uploads/") {
        if name.is_empty() {
            return StatusCode::NOT_FOUND.into_response();
        }
        if validate_docker_name(name).is_err() {
            return (StatusCode::BAD_REQUEST, "Invalid image name").into_response();
        }
        if is_write {
            if let Some(refusal) = write_gate(&state.0, &authority, name) {
                return refusal;
            }
        }
        // Fast-reject oversized uploads before reading a byte: docker clients send
        // Content-Length on monolithic PUT/POST. The streaming paths also enforce
        // this incrementally, but this rejects the common case up front (#817).
        if is_write {
            if let Some(len) = content_length(&headers) {
                if len > effective_upload_cap(state.0.config.server.body_limit_mb) {
                    return (StatusCode::PAYLOAD_TOO_LARGE, "Upload exceeds size limit")
                        .into_response();
                }
            }
        }
        return if after.is_empty() {
            match method {
                Method::POST => {
                    let params = parse_query_string(uri.query());
                    if params.contains_key("digest") {
                        // OCI single-POST monolithic upload (#688): the blob is in
                        // the body and ?digest= is set, so complete it in one
                        // request instead of opening a session. Reuse the upload
                        // finalizer with a fresh upload id — no session exists, so
                        // it takes the monolithic branch.
                        let upload_id = uuid::Uuid::new_v4().to_string();
                        upload_blob(
                            state,
                            Path((name.to_string(), upload_id)),
                            axum::extract::Query(params),
                            &headers,
                            true,
                            body,
                        )
                        .await
                    } else if let (Some(digest), Some(from)) =
                        (params.get("mount"), params.get("from"))
                    {
                        mount_blob(state, name, from, digest).await
                    } else {
                        start_upload(state, Path(name.to_string())).await
                    }
                }
                _ => method_not_allowed("POST"),
            }
        } else {
            match method {
                Method::GET => upload_status(state, name, after),
                Method::PATCH => {
                    patch_blob(
                        state,
                        Path((name.to_string(), after.to_string())),
                        &headers,
                        body,
                    )
                    .await
                }
                Method::PUT => {
                    let params = parse_query_string(uri.query());
                    upload_blob(
                        state,
                        Path((name.to_string(), after.to_string())),
                        axum::extract::Query(params),
                        &headers,
                        false,
                        body,
                    )
                    .await
                }
                Method::DELETE => {
                    cancel_upload(state, Path((name.to_string(), after.to_string()))).await
                }
                _ => method_not_allowed("GET, PATCH, PUT, DELETE"),
            }
        };
    }

    // 2. Blobs: {name}/blobs/{digest}
    if let Some((name, digest)) = rest.rsplit_once("/blobs/") {
        if name.is_empty() || digest.is_empty() {
            return StatusCode::NOT_FOUND.into_response();
        }
        if validate_docker_name(name).is_err() {
            return (StatusCode::BAD_REQUEST, "Invalid image name").into_response();
        }
        if is_write {
            if let Some(refusal) = write_gate(&state.0, &authority, name) {
                return refusal;
            }
        }
        return match method {
            Method::HEAD => {
                check_blob(
                    state,
                    &headers,
                    Path((name.to_string(), digest.to_string())),
                )
                .await
            }
            Method::GET => {
                download_blob(state, headers, Path((name.to_string(), digest.to_string()))).await
            }
            Method::DELETE => {
                delete_blob(state, Path((name.to_string(), digest.to_string()))).await
            }
            _ => method_not_allowed("GET, HEAD, DELETE"),
        };
    }

    // 3. Manifests: {name}/manifests/{reference}
    if let Some((name, reference)) = rest.rsplit_once("/manifests/") {
        if name.is_empty() || reference.is_empty() {
            return StatusCode::NOT_FOUND.into_response();
        }
        if validate_docker_name(name).is_err() {
            return (StatusCode::BAD_REQUEST, "Invalid image name").into_response();
        }
        if is_write {
            if let Some(refusal) = write_gate(&state.0, &authority, name) {
                return refusal;
            }
        }
        return match method {
            Method::GET | Method::HEAD => {
                let resp = get_manifest(
                    state.clone(),
                    headers,
                    Path((name.to_string(), reference.to_string())),
                )
                .await;
                let resp = with_quarantine_verdict(&state, resp);
                if method == Method::HEAD {
                    let (parts, _) = resp.into_parts();
                    Response::from_parts(parts, axum::body::Body::empty())
                } else {
                    resp
                }
            }
            Method::PUT => match axum::body::to_bytes(body, MAX_MANIFEST_BYTES).await {
                Ok(b) => match manifest_media_type_mismatch(&headers, &b) {
                    Some(reason) => manifest_invalid_response(reason),
                    None => {
                        put_manifest(state, Path((name.to_string(), reference.to_string())), b)
                            .await
                    }
                },
                Err(_) => (StatusCode::PAYLOAD_TOO_LARGE, "Manifest too large").into_response(),
            },
            Method::DELETE => {
                delete_manifest(state, Path((name.to_string(), reference.to_string()))).await
            }
            _ => method_not_allowed("GET, HEAD, PUT, DELETE"),
        };
    }

    // 4. Tags list: {name}/tags/list
    if let Some(name) = rest.strip_suffix("/tags/list") {
        if name.is_empty() {
            return StatusCode::NOT_FOUND.into_response();
        }
        if validate_docker_name(name).is_err() {
            return (StatusCode::BAD_REQUEST, "Invalid image name").into_response();
        }
        return match method {
            Method::GET => {
                list_tags(
                    state,
                    Path(name.to_string()),
                    parse_query_string(uri.query()),
                )
                .await
            }
            _ => method_not_allowed("GET"),
        };
    }

    StatusCode::NOT_FOUND.into_response()
}

/// The gate of a write (push, delete) on the repository it lands in — the canonical name the
/// handlers store under, not the name in the URL, which routing may rewrite (R4-R11):
/// - the OIDC `namespace_scope` is checked on the canonical name, so a scope that matches a
///   prefix or registry host routing strips does not reach the repository behind it
///   (`harbor.corp/payments/api` is stored as `payments/api`);
/// - a name under an upstream's storage namespace is refused: its keys are that upstream's
///   proxy cache (`docker/<namespace>/…`), which a push would overwrite.
///
/// `None` lets the write through.
fn write_gate(
    state: &AppState,
    authority: &NamespaceAuthority,
    raw_name: &str,
) -> Option<Response> {
    let c = canonicalize(raw_name, &state.config.docker);
    if enforce_namespace_scope(authority, &c.name).is_err() {
        return Some(StatusCode::FORBIDDEN.into_response());
    }
    let refused = |message: &str| {
        tracing::warn!(name = %raw_name, canonical = %c.name, reason = message, "Docker write refused");
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "errors": [{
                    "code": "NAME_INVALID",
                    "message": message,
                    "detail": { "name": raw_name }
                }]
            })),
        )
            .into_response()
    };
    let reserved = state.config.docker.upstreams.iter().any(|u| {
        c.name
            .strip_prefix(u.resolved_namespace().as_str())
            .is_some_and(|rest| rest.starts_with('/'))
    });
    reserved.then(|| refused("the name is under an upstream's cache namespace"))
}

fn parse_query_string(query: Option<&str>) -> HashMap<String, String> {
    use percent_encoding::percent_decode_str;
    query
        .unwrap_or_default()
        .split('&')
        .filter(|s| !s.is_empty())
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            Some((
                percent_decode_str(k).decode_utf8_lossy().into_owned(),
                percent_decode_str(v).decode_utf8_lossy().into_owned(),
            ))
        })
        .collect()
}

async fn check() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(
            HeaderName::from_static("docker-distribution-api-version"),
            "registry/2.0",
        )],
        Json(json!({})),
    )
}

/// Strip hostname prefix from a Docker repository name (config-free heuristic).
///
/// Detects hostnames by checking for a dot in the first path segment
/// (e.g. `docker.io/library/nginx` → `library/nginx`).
///
/// **When to use:** Only in config-free contexts like storage key classification
/// (e.g., `docker_key_migration`). For request-time routing, use [`canonicalize()`]
/// which is config-aware and handles prefix-based upstream matching.
pub(crate) fn strip_docker_namespace(name: &str) -> &str {
    if let Some((first, rest)) = name.split_once('/') {
        if first.contains('.') && !rest.is_empty() {
            return rest;
        }
    }
    name
}

/// List all repositories in the registry
async fn catalog(State(state): State<AppState>) -> Response {
    let keys = match state.storage.list("docker/").await {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(error = ?e, "docker: failed to list storage for catalog");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };

    // Extract unique repository names from paths like "docker/{name}/manifests/..."
    let mut repos: Vec<String> = keys
        .iter()
        .filter_map(|k| {
            let rest = k.strip_prefix("docker/")?;
            // Find the first known directory separator (manifests/ or blobs/)
            let name = if let Some(idx) = rest.find("/manifests/") {
                &rest[..idx]
            } else if let Some(idx) = rest.find("/blobs/") {
                &rest[..idx]
            } else {
                return None;
            };
            if name.is_empty() {
                return None;
            }
            // Canonicalize to strip upstream namespace prefix (e.g. "docker.io/")
            // so that images proxied through different upstreams are deduplicated.
            Some(canonicalize(name, &state.config.docker).name)
        })
        .collect();

    repos.sort();
    repos.dedup();

    Json(json!({ "repositories": repos })).into_response()
}

async fn check_blob(
    State(state): State<AppState>,
    headers: &axum::http::HeaderMap,
    Path((name, digest)): Path<(String, String)>,
) -> Response {
    let c = canonicalize(&name, &state.config.docker);
    if let Some(r) = c.denied_response() {
        return r;
    }
    let name = c.name;
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_digest(&digest) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    // The gates of the GET, so that HEAD never reports a blob the GET refuses.
    if let (_, Some(response)) = blob_curation_gate(&state, headers, &name, &digest) {
        return response;
    }

    let key = blob_key(c.namespace.as_deref(), &name, &digest);
    let legacy_key = blob_key(None, &name, &digest);
    // Use stat() instead of get() to avoid loading multi-GB blobs into memory
    // just to return Content-Length on a HEAD request (#526).
    // Through `confirm_blob`: GC must not sweep a layer this answer lets the client skip.
    let found = crate::gc::confirm_blob(
        state.config.gc.enabled,
        &state.publish_locks,
        &[&key, &legacy_key],
        storage_stat_with_fallback(&state.storage, &key, &legacy_key),
    )
    .await;
    match found {
        Some(meta) => {
            // Mirror download_blob / HEAD-manifest: a proxy-cached blob still within its
            // cooldown is reported as held (403), not available — so HEAD and GET agree.
            // A local/internal blob has no proxy record (`New`) and acks normally.
            if let Some(resp) = quarantine_cache_serve_gate(&state, &digest, None) {
                return resp;
            }
            if let Some(response) = crate::curation::verify_integrity_by_hash(
                &state.curation().curation_engine,
                crate::curation::RegistryType::Docker,
                &name,
                Some(&digest),
                &digest,
            ) {
                return response;
            }
            // The headers of the GET (OCI: HEAD SHOULD carry Docker-Content-Digest).
            (
                StatusCode::OK,
                [
                    (header::CONTENT_LENGTH, meta.size.to_string()),
                    (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                    (header::ACCEPT_RANGES, "bytes".to_string()),
                    (HeaderName::from_static("docker-content-digest"), digest),
                ],
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// The curation gate of a blob read (GET and HEAD): whether the name is in an internal
/// namespace — operator-owned, never checked and never proxied (#733) — and the refusal, if
/// curation refuses the download.
fn blob_curation_gate(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    name: &str,
    digest: &str,
) -> (bool, Option<Response>) {
    let internal = crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Docker,
        name,
    );
    if internal {
        return (true, None);
    }
    let refusal = crate::curation::check_download(
        &state.curation().curation_engine,
        state.bypass_token().as_deref(),
        headers,
        crate::curation::RegistryType::Docker,
        name,
        crate::curation::RequestVersion::Known(digest.to_string()),
        None,
    );
    (false, refusal)
}

/// Serve a blob already in storage (`key`, or the pre-namespace `legacy_key`): curation
/// integrity, the quarantine cooldown, `Range` (206/416), else the whole blob through the
/// streaming digest check. `None` when storage has neither key.
async fn serve_local_blob(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    name: &str,
    digest: &str,
    key: &str,
    legacy_key: &str,
) -> Option<Response> {
    // A Range request is answered by a ranged read: the object is described by a stat, not by
    // opening a read of the whole blob that is then dropped unread (a second GET and a
    // connection lost to the pool on S3). The full read is opened only for the 200.
    let ranged = headers.contains_key(header::RANGE);
    let (size, reader) = if ranged {
        let meta = storage_stat_with_fallback(&state.storage, key, legacy_key).await?;
        (meta.size, None)
    } else {
        let (size, reader) = storage_get_reader_with_fallback(&state.storage, key, legacy_key)
            .await
            .ok()?;
        (size, Some(reader))
    };
    // Curation integrity check using digest from URL (no full-data rehash).
    // Docker blobs are content-addressed: the URL digest IS the integrity.
    if let Some(response) = crate::curation::verify_integrity_by_hash(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Docker,
        name,
        Some(digest),
        digest,
    ) {
        return Some(response);
    }

    // Quarantine: a proxy-cached blob still within its cooldown window is held.
    // A blob with no proxy record (a local push, or an entry pruned past 90d)
    // reads as `New` and is served; only `Pending` blocks (enforce). Covers both
    // the 206 range serve and the 200 full serve below.
    if let Some(resp) = quarantine_cache_serve_gate(state, digest, None) {
        return Some(resp);
    }

    // Range request: 206 Partial Content, or 416 when the client asks past the end
    // (#657). A ranged response is partial, so the streaming SHA-256 verify (full-GET
    // only) does not apply — a ranged serve relies on the content-addressed storage
    // key plus the client's own content-digest check, as Docker/Harbor do. An
    // absent/malformed range falls through to the full 200 below.
    if let Some(response) = crate::registry::range::range_response(
        &state.storage,
        &[key, legacy_key],
        headers,
        size,
        "application/octet-stream",
        &[
            (
                header::CACHE_CONTROL,
                "public, max-age=31536000, immutable".to_string(),
            ),
            (
                HeaderName::from_static("docker-content-digest"),
                digest.to_string(),
            ),
        ],
    )
    .await
    {
        if response.status() == StatusCode::PARTIAL_CONTENT {
            state.metrics.record_download("docker");
            state.metrics.record_cache_hit("docker");
        }
        return Some(response);
    }

    // No usable range after all (malformed, or the ranged read failed): the whole blob.
    let (size, reader) = match reader {
        Some(reader) => (size, reader),
        None => storage_get_reader_with_fallback(&state.storage, key, legacy_key)
            .await
            .ok()?,
    };
    state.metrics.record_download("docker");
    state.metrics.record_cache_hit("docker");
    state.activity.push(ActivityEntry::new(
        ActionType::Pull,
        format!("{}@{}", name, &digest[..19.min(digest.len())]),
        crate::registry_type::RegistryType::Docker,
        "LOCAL",
    ));
    let stream = blob_verifying_stream(reader, digest, format!("docker/{name}/blobs/{digest}"));
    Some(
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::CONTENT_LENGTH, size)
            .header(header::ACCEPT_RANGES, "bytes")
            .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
            .header("docker-content-digest", digest)
            .body(nora_registry::verified::stream_body(stream))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
    )
}

async fn download_blob(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((name, digest)): Path<(String, String)>,
) -> Response {
    let c = canonicalize(&name, &state.config.docker);
    if let Some(r) = c.denied_response() {
        return r;
    }
    let upstreams_to_try = c.upstreams_to_try(&state.config.docker.upstreams);
    let ns = c.namespace;
    let name = c.name;
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_digest(&digest) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    // Curation check — defense in depth: check blobs too. #733 serve-local: an internal-namespace
    // image is operator-owned — skip curation and serve any local blob below; block the upstream
    // branch separately (never proxy an internal name).
    let (internal, refusal) = blob_curation_gate(&state, &headers, &name, &digest);
    if let Some(response) = refusal {
        return response;
    }

    let key = blob_key(ns.as_deref(), &name, &digest);
    let legacy_key = blob_key(None, &name, &digest);

    // Try local storage first — streaming read, never loads full blob into RAM (#580)
    if let Some(response) =
        serve_local_blob(&state, &headers, &name, &digest, &key, &legacy_key).await
    {
        return response;
    }

    // #733/#821: an internal-namespace image's blob with no local copy is never proxied
    // upstream (dependency-confusion defense — this early return precedes the proxy loop).
    // A hosted image's absent blob is a not-found, not an authz denial: return 404
    // BLOB_UNKNOWN so GET agrees with the HEAD probe (check_blob, which already 404s)
    // instead of the fatal-to-clients 403.
    if internal {
        crate::metrics::record_namespace_isolation_refused("docker");
        return blob_unknown_response(&digest);
    }

    let temp_dir = proxy_temp_dir(&state.config.storage.path);

    // Try upstream proxies (prefix-matched → single upstream, otherwise → fallback chain)
    // Includes library/ fallback for single-segment names (Docker Hub official images).
    let names_to_try: Vec<String> = if name.contains('/') {
        vec![name.clone()]
    } else {
        vec![name.clone(), format!("library/{}", name)]
    };

    // One record per upstream, across both names it may be asked under.
    let mut misses: Vec<UpstreamMiss> = upstreams_to_try
        .iter()
        .map(|_| UpstreamMiss::default())
        .collect();
    for try_name in &names_to_try {
        for (upstream, miss) in upstreams_to_try.iter().zip(misses.iter_mut()) {
            // Content-addressed: the URL digest is the hash the spool verifies before
            // storing, so the curation integrity check runs on it before upstream is
            // opened — a rejection must not strand a circuit-breaker probe.
            if let Some(response) = crate::curation::verify_integrity_by_hash(
                &state.curation().curation_engine,
                crate::curation::RegistryType::Docker,
                try_name,
                Some(&digest),
                &digest,
            ) {
                return response;
            }
            // One upstream fetch per blob, shared by every request that asks while it fills
            // (#1003). The key is the storage key plus the name and upstream this request
            // resolved to, so a request only ever joins a fill it could have started itself;
            // it joins here, after every check above ran on its own request.
            let flight_key = format!("{key}\n{try_name}\n{}", upstream.url);
            for _attempt in 0..2 {
                let mut failure = None;
                let flight = state
                    .blob_flights
                    .leased(
                        &flight_key,
                        "docker",
                        crate::proxy_coalesce::follower_budget(state.config.docker.proxy_timeout),
                        || {
                            start_fill(
                                &state,
                                &upstream.url,
                                expose_opt(&upstream.auth),
                                try_name,
                                &digest,
                                &temp_dir,
                                &mut failure,
                            )
                        },
                    )
                    .await;
                let target = BlobTarget {
                    name: &name,
                    upstream_name: try_name,
                    digest: &digest,
                    key: &key,
                    legacy_key: &legacy_key,
                    upstream_url: &upstream.url,
                };
                match flight {
                    Some(Flight::Leader { value, own, lease }) => {
                        return lead_fill(&state, value, own, Some(lease), &target, &headers).await;
                    }
                    Some(Flight::Alone { value, own }) => {
                        return lead_fill(&state, value, own, None, &target, &headers).await;
                    }
                    Some(Flight::Follower(share)) => {
                        if let Some(response) = follow_fill(&state, share, &target, &headers).await
                        {
                            return response;
                        }
                        // The fill failed and its slot is released: take another turn.
                        miss.record(&ProxyError::Network("shared fill failed".into()));
                    }
                    None => match failure {
                        Some(FillStartError::Spool) => {
                            return StatusCode::INTERNAL_SERVER_ERROR.into_response()
                        }
                        // An open breaker skips this upstream for the next, as a failure
                        // does (#1198).
                        Some(FillStartError::Upstream(e)) => {
                            tracing::debug!(error = ?e, upstream = %upstream.url, name = %try_name, "Docker blob proxy fetch failed, trying next");
                            miss.record(&e);
                            break;
                        }
                        None => break,
                    },
                }
            }
        }
    }

    let mut miss = UpstreamMiss::default();
    for asked in &misses {
        miss.record_upstream(asked);
    }
    docker_miss_response(
        &miss,
        Missed::Blob {
            name: &name,
            digest: &digest,
        },
    )
}

/// 201 for a blob that is now present in `name`, in the shape `upload_blob`
/// returns.
fn blob_created(name: &str, digest: &str) -> Response {
    (
        StatusCode::CREATED,
        [
            (header::LOCATION, format!("/v2/{}/blobs/{}", name, digest)),
            (
                HeaderName::from_static("docker-content-digest"),
                digest.to_string(),
            ),
        ],
    )
        .into_response()
}

/// Cross-repo blob mount: `POST /v2/{name}/blobs/uploads/?mount=<digest>&from=<repo>`
/// links a blob that `from` already holds into `name` with no re-upload.
///
/// Every reason a mount cannot happen — unknown digest, unusable source repo,
/// storage failure, a digest still held by quarantine — degrades to a normal
/// upload session (202) instead of an error, as the OCI distribution spec
/// requires: the client then pushes the blob itself.
async fn mount_blob(state: State<AppState>, raw_name: &str, from: &str, digest: &str) -> Response {
    let c = canonicalize(raw_name, &state.config.docker);
    if let Some(r) = c.denied_response() {
        return r;
    }
    let name = c.name;
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let Some(hex) = digest.strip_prefix("sha256:") else {
        return start_upload(state, Path(raw_name.to_string())).await;
    };
    if validate_digest(digest).is_err() {
        return start_upload(state, Path(raw_name.to_string())).await;
    }

    // Reads are never namespace-gated (see docker_v2_dispatch); the write scope
    // on `name` was already enforced there.
    let c_from = canonicalize(from, &state.config.docker);
    if c_from.denied || validate_docker_name(&c_from.name).is_err() {
        return start_upload(state, Path(raw_name.to_string())).await;
    }

    // Must match the key upload finalization writes.
    let dst_key = format!("docker/{}/blobs/{}", name, digest);
    let held = crate::gc::confirm_blob(
        state.config.gc.enabled,
        &state.publish_locks,
        &[&dst_key],
        state.storage.stat(&dst_key),
    )
    .await;
    if held.is_some() {
        return blob_created(&name, digest);
    }

    // A digest still inside its proxy cooldown must not be laundered into a
    // local repository by a mount.
    if quarantine_cache_serve_gate(&state, digest, None).is_some() {
        return start_upload(state, Path(raw_name.to_string())).await;
    }

    let ns_key = blob_key(c_from.namespace.as_deref(), &c_from.name, digest);
    let legacy_key = blob_key(None, &c_from.name, digest);
    let src_key = if state.storage.stat(&ns_key).await.is_some() {
        ns_key
    } else if ns_key != legacy_key && state.storage.stat(&legacy_key).await.is_some() {
        legacy_key
    } else {
        return start_upload(state, Path(raw_name.to_string())).await;
    };

    if let Err(e) = state.storage.copy(&src_key, &dst_key, Some(hex)).await {
        tracing::warn!(error = %e, src = %src_key, dst = %dst_key, "Blob mount failed, falling back to upload");
        return start_upload(state, Path(raw_name.to_string())).await;
    }

    state.audit.log(AuditEntry::new(
        "mount",
        "api",
        &format!("{}@{}", name, digest),
        "docker",
        "blob",
    ));
    state.activity.push(ActivityEntry::new(
        ActionType::Push,
        format!("{}@{}", name, &digest[..19.min(digest.len())]),
        crate::registry_type::RegistryType::Docker,
        "LOCAL",
    ));
    state.repo_index.invalidate("docker");
    blob_created(&name, digest)
}

async fn start_upload(State(state): State<AppState>, Path(name): Path<String>) -> Response {
    let c = canonicalize(&name, &state.config.docker);
    if let Some(r) = c.denied_response() {
        return r;
    }
    let name = c.name;
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let uuid = uuid::Uuid::new_v4().to_string();

    // Create temp file for blob data on disk BEFORE inserting into session map.
    // This ensures patch_blob can use .append(true) without .create(true),
    // preventing orphan re-creation if cleanup_expired_sessions deletes the file (#530).
    let temp_dir = upload_temp_dir(&state.config.storage.path);
    let temp_path = temp_dir.join(&uuid);
    if let Err(e) = tokio::fs::File::create(&temp_path).await {
        tracing::error!(path = %temp_path.display(), error = %e, "Failed to create upload temp file");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // Single write lock: check limit + insert atomically (no TOCTOU). The guard's
    // scope must end before the reject path awaits, so the temp to reclaim is
    // handed back out of the block rather than removed inside it.
    let rejected_temp = {
        let mut sessions = state.upload_sessions.write();
        let max_sessions = max_upload_sessions();
        if sessions.len() >= max_sessions {
            tracing::warn!(
                max = max_sessions,
                current = sessions.len(),
                "Upload session limit reached — rejecting new upload"
            );
            Some(temp_path)
        } else {
            sessions.insert(
                uuid.clone(),
                UploadSession {
                    temp_path,
                    size: 0,
                    name: name.clone(),
                    created_at: std::time::Instant::now(),
                },
            );
            None
        }
    };
    if let Some(p) = rejected_temp {
        let _ = tokio::fs::remove_file(&p).await;
        return too_many_uploads();
    }

    let location = format!("/v2/{}/blobs/uploads/{}", name, uuid);
    (
        StatusCode::ACCEPTED,
        [
            (header::LOCATION, location),
            (HeaderName::from_static("docker-upload-uuid"), uuid),
        ],
    )
        .into_response()
}

/// The first byte a chunk's `Content-Range: <start>-<end>` names (OCI: `^[0-9]+-[0-9]+$`).
/// `None` without the header or with one in another form: such a chunk is appended where the
/// upload stands, as a chunk without the header is (the docker client sends none).
fn chunk_start(headers: &axum::http::HeaderMap) -> Option<u64> {
    let value = headers.get(header::CONTENT_RANGE)?.to_str().ok()?;
    let (start, end) = value.trim().split_once('-')?;
    end.parse::<u64>().ok()?;
    start.parse().ok()
}

/// `Range` of an upload holding `size` bytes: `0-<last byte>`, and `0-0` for an empty one.
fn upload_range(size: u64) -> String {
    format!("0-{}", size.saturating_sub(1))
}

/// 416 for a chunk that does not start where the upload stands (OCI: out of order), with the
/// `Range` the upload holds so the client resumes from it — a retried chunk is not appended a
/// second time.
fn chunk_out_of_order(name: &str, uuid: &str, size: u64) -> Response {
    (
        StatusCode::RANGE_NOT_SATISFIABLE,
        upload_headers(name, uuid, size),
    )
        .into_response()
}

fn upload_headers(name: &str, uuid: &str, size: u64) -> [(HeaderName, String); 3] {
    [
        (
            header::LOCATION,
            format!("/v2/{}/blobs/uploads/{}", name, uuid),
        ),
        (header::RANGE, upload_range(size)),
        (
            HeaderName::from_static("docker-upload-uuid"),
            uuid.to_string(),
        ),
    ]
}

/// 404 `BLOB_UPLOAD_UNKNOWN` per the OCI Distribution Spec: no such upload, or it expired.
fn blob_upload_unknown_response() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "errors": [{
                "code": "BLOB_UPLOAD_UNKNOWN",
                "message": "blob upload unknown to registry",
            }]
        })),
    )
        .into_response()
}

/// `GET /v2/<name>/blobs/uploads/<uuid>`: where an upload stands — 204 with `Location` and
/// `Range: 0-<last byte>` — for a client that lost a chunk's answer or got a 416.
fn upload_status(State(state): State<AppState>, name: &str, uuid: &str) -> Response {
    let c = canonicalize(name, &state.config.docker);
    if let Some(r) = c.denied_response() {
        return r;
    }
    if validate_upload_uuid(uuid).is_err() {
        return blob_upload_unknown_response();
    }
    let sessions = state.upload_sessions.read();
    match sessions.get(uuid) {
        Some(s) if s.name == c.name && s.created_at.elapsed() < SESSION_TTL => (
            StatusCode::NO_CONTENT,
            upload_headers(&c.name, uuid, s.size),
        )
            .into_response(),
        _ => blob_upload_unknown_response(),
    }
}

/// PATCH handler for chunked blob uploads
/// Docker client sends data chunks via PATCH, then finalizes with PUT
async fn patch_blob(
    State(state): State<AppState>,
    Path((name, uuid)): Path<(String, String)>,
    headers: &axum::http::HeaderMap,
    body: Body,
) -> Response {
    let c = canonicalize(&name, &state.config.docker);
    if let Some(r) = c.denied_response() {
        return r;
    }
    let name = c.name;
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_upload_uuid(&uuid) {
        return (StatusCode::BAD_REQUEST, e).into_response();
    }

    // Bound concurrent streaming uploads (covers monolithic POSTs, which bypass
    // the session map) so streaming to disk cannot fan out unboundedly (#817).
    let _inflight = match InFlightGuard::try_acquire() {
        Some(g) => g,
        None => return too_many_uploads(),
    };

    // Phase 1: Validate session under lock, extract temp_path + current size (no I/O)
    let (temp_path, current_size) = {
        let mut sessions = state.upload_sessions.write();
        let session = match sessions.get_mut(&uuid) {
            Some(s) => s,
            None => {
                return (StatusCode::NOT_FOUND, "Upload session not found or expired")
                    .into_response();
            }
        };

        // Verify session belongs to this repository
        if session.name != name {
            tracing::warn!(
                session_name = %session.name,
                request_name = %name,
                "SECURITY: upload session name mismatch — possible session fixation"
            );
            return (
                StatusCode::BAD_REQUEST,
                "Session does not belong to this repository",
            )
                .into_response();
        }

        // Check session TTL
        if session.created_at.elapsed() >= SESSION_TTL {
            let _ = std::fs::remove_file(&session.temp_path);
            sessions.remove(&uuid);
            return (StatusCode::NOT_FOUND, "Upload session expired").into_response();
        }

        // A chunk that names its range starts where the upload stands, or is refused.
        if chunk_start(headers).is_some_and(|start| start != session.size) {
            return chunk_out_of_order(&name, &uuid, session.size);
        }

        (session.temp_path.clone(), session.size)
    }; // lock released before file I/O

    // Remaining byte budget for this session. The body length is unknown until
    // streamed, so the cap is enforced incrementally inside the stream loop —
    // DefaultBodyLimit does NOT bound a streaming Body extractor (#817).
    //
    // ACCEPTED LIMITATION: the per-session cap is best-effort under CONCURRENT
    // PATCHes to the SAME upload uuid — each reads `session.size` before the
    // other's Phase-3 update, so a single temp can exceed one session cap. No new
    // exhaustion vector: total upload disk stays <= IN_FLIGHT_UPLOADS * cap
    // regardless, and blob integrity is still enforced by the finalize digest
    // check. OCI clients PATCH sequentially (await each 202 Range), so this only
    // bites a misbehaving client. Upgrade path: per-uuid serialization.
    let budget =
        effective_upload_cap(state.config.server.body_limit_mb).saturating_sub(current_size);

    // Phase 2: stream the chunk to the temp file outside the lock, bounded by
    // `budget`. No .create(true) — the temp file was created by start_upload; if
    // cleanup deleted it, open() returns NotFound and we 404 rather than
    // re-creating an orphan (#530).
    let mut file = match tokio::fs::OpenOptions::new()
        .append(true)
        .open(&temp_path)
        .await
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(uuid = %uuid, "Upload temp file deleted by cleanup during PATCH — session race");
            state.upload_sessions.write().remove(&uuid);
            return (StatusCode::NOT_FOUND, "Upload session expired").into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to open upload temp file");
            state.upload_sessions.write().remove(&uuid);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    // CANCEL-SAFETY: if this future is dropped mid-stream, `guard` drops and
    // removes the partially appended temp; on success we disarm to keep it for
    // the next PATCH/PUT.
    let mut guard = TempFileGuard::new(temp_path.clone());
    let written = match stream_body_to_file(body, &mut file, budget).await {
        StreamOutcome::Ok(n) => {
            guard.disarm();
            n
        }
        StreamOutcome::TooLarge => {
            state.upload_sessions.write().remove(&uuid);
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "Upload session exceeds size limit",
            )
                .into_response();
        }
        StreamOutcome::ClientGone => {
            state.upload_sessions.write().remove(&uuid);
            return StatusCode::BAD_REQUEST.into_response();
        }
        StreamOutcome::Io(e) => {
            tracing::error!(error = %e, "Failed to write to upload temp file");
            state.upload_sessions.write().remove(&uuid);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let new_size = current_size + written;

    // Phase 3: Update session size (brief lock, no I/O).
    // If session is gone (cleanup raced, or upload_blob consumed it), log and return 404.
    // Do NOT delete the temp file here — upload_blob may be using it (#530).
    {
        let mut sessions = state.upload_sessions.write();
        match sessions.get_mut(&uuid) {
            Some(session) => session.size = new_size,
            None => {
                tracing::warn!(uuid = %uuid, "Upload session disappeared between Phase 1 and Phase 3");
                return (StatusCode::NOT_FOUND, "Upload session not found or expired")
                    .into_response();
            }
        }
    }

    let total_size = new_size;

    let location = format!("/v2/{}/blobs/uploads/{}", name, uuid);
    // Range header indicates bytes 0 to (total_size - 1) have been received
    let range = if total_size > 0 {
        format!("0-{}", total_size - 1)
    } else {
        "0-0".to_string()
    };

    (
        StatusCode::ACCEPTED,
        [
            (header::LOCATION, location),
            (header::RANGE, range),
            (HeaderName::from_static("docker-upload-uuid"), uuid),
        ],
    )
        .into_response()
}

/// DELETE handler: cancel an in-progress upload (OCI end-blob-upload cancel).
///
/// Without it the session is only reclaimed by `SESSION_TTL`, so a client that
/// correctly cancels still holds a `max_upload_sessions` slot for 30 minutes.
/// Concurrent CI pushes then saturate the ceiling and 429 each other while the
/// map is mostly dead entries.
async fn cancel_upload(
    State(state): State<AppState>,
    Path((name, uuid)): Path<(String, String)>,
) -> Response {
    let c = canonicalize(&name, &state.config.docker);
    if let Some(r) = c.denied_response() {
        return r;
    }
    let name = c.name;
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_upload_uuid(&uuid) {
        return (StatusCode::BAD_REQUEST, e).into_response();
    }

    // `map` yields an owned bool so no borrow of `sessions` outlives the match.
    let temp_path = {
        let mut sessions = state.upload_sessions.write();
        match sessions.get(&uuid).map(|s| s.name == name) {
            None => None,
            Some(false) => {
                tracing::warn!(
                    request_name = %name,
                    uuid = %uuid,
                    "SECURITY: upload cancel name mismatch — possible session fixation"
                );
                return (
                    StatusCode::BAD_REQUEST,
                    "Session does not belong to this repository",
                )
                    .into_response();
            }
            Some(true) => sessions.remove(&uuid).map(|s| s.temp_path),
        }
    }; // lock released before file I/O

    match temp_path {
        Some(p) => {
            let _ = tokio::fs::remove_file(&p).await;
            StatusCode::NO_CONTENT.into_response()
        }
        None => (StatusCode::NOT_FOUND, "Upload session not found or expired").into_response(),
    }
}

/// PUT handler for completing blob uploads
/// Handles both monolithic uploads (body contains all data) and
/// chunked upload finalization (body may be empty, data in session)
async fn upload_blob(
    State(state): State<AppState>,
    Path((name, uuid)): Path<(String, String)>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    headers: &axum::http::HeaderMap,
    // The single-POST form (`POST …/uploads/?digest=`): the whole blob is the body and no
    // session was opened. A PUT always closes a session.
    monolithic: bool,
    body: Body,
) -> Response {
    let c = canonicalize(&name, &state.config.docker);
    if let Some(r) = c.denied_response() {
        return r;
    }
    let name = c.name;
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_upload_uuid(&uuid) {
        return (StatusCode::BAD_REQUEST, e).into_response();
    }

    // Bound concurrent streaming uploads. Monolithic POSTs bypass the session
    // map, so `max_upload_sessions` alone does not cap their concurrency (#817).
    let _inflight = match InFlightGuard::try_acquire() {
        Some(g) => g,
        None => return too_many_uploads(),
    };

    let digest = match params.get("digest") {
        Some(d) => d,
        None => return (StatusCode::BAD_REQUEST, "Missing digest parameter").into_response(),
    };

    if let Err(e) = validate_digest(digest) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    // Only sha256 digests are supported for verification. Checked before the session is
    // taken: a refused request leaves the upload as it was.
    if !digest.starts_with("sha256:") {
        return (
            StatusCode::BAD_REQUEST,
            "Only sha256 digests are supported for blob uploads",
        )
            .into_response();
    }

    // Remove session from map under brief lock, then do file I/O outside
    let session_opt = {
        let mut sessions = state.upload_sessions.write();
        // A final chunk that names its range starts where the upload stands, or is refused
        // with the upload kept (OCI: 416).
        if let Some(session) = sessions.get(&uuid) {
            if session.name == name
                && chunk_start(headers).is_some_and(|start| start != session.size)
            {
                return chunk_out_of_order(&name, &uuid, session.size);
            }
        }
        sessions.remove(&uuid)
    }; // lock released before file I/O

    // A PUT closes an upload: without one (never opened, expired, or lost in a restart) the
    // body is not the blob, and hashing it alone would report corruption (DIGEST_INVALID)
    // where the client has to start the upload again.
    if session_opt.is_none() && !monolithic {
        return blob_upload_unknown_response();
    }

    let cap = effective_upload_cap(state.config.server.body_limit_mb);

    // Resolve the temp file and stream the request body into it, bounded by the
    // per-request cap (DefaultBodyLimit does not bound a streaming Body — #817).
    // `guard` reclaims a partial temp on ANY early return below (cap exceeded,
    // client disconnect, digest mismatch, storage failure, cancellation) — #580.
    let (temp_path, mut guard) = if let Some(session) = session_opt {
        // Verify session belongs to this repository
        if session.name != name {
            tracing::warn!(
                session_name = %session.name,
                request_name = %name,
                "SECURITY: upload finalization name mismatch"
            );
            let _ = tokio::fs::remove_file(&session.temp_path).await;
            return (
                StatusCode::BAD_REQUEST,
                "Session does not belong to this repository",
            )
                .into_response();
        }
        // create(true) covers the "no PATCH was sent, data all in the PUT body"
        // case; the session was already removed from the map, so we own this
        // temp exclusively.
        let mut file = match tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&session.temp_path)
            .await
        {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(error = %e, "Failed to open temp file for PUT body");
                let _ = tokio::fs::remove_file(&session.temp_path).await;
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        let guard = TempFileGuard::new(session.temp_path.clone());
        let budget = cap.saturating_sub(session.size);
        // CANCEL-SAFETY: partial temp reclaimed by `guard` if this future drops.
        match stream_body_to_file(body, &mut file, budget).await {
            StreamOutcome::Ok(_) => {}
            StreamOutcome::TooLarge => {
                return (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Upload session exceeds size limit",
                )
                    .into_response()
            }
            StreamOutcome::ClientGone => return StatusCode::BAD_REQUEST.into_response(),
            StreamOutcome::Io(e) => {
                tracing::error!(error = %e, "Failed to append PUT body to temp file");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
        (session.temp_path, guard)
    } else {
        // Monolithic upload (no session): create a fresh temp and stream into it.
        let temp_dir = upload_temp_dir(&state.config.storage.path);
        let temp_path = temp_dir.join(format!("mono-{}", uuid));
        let mut file = match tokio::fs::File::create(&temp_path).await {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(error = %e, "Failed to create monolithic upload temp file");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        let guard = TempFileGuard::new(temp_path.clone());
        // CANCEL-SAFETY: partial temp reclaimed by `guard` if this future drops.
        match stream_body_to_file(body, &mut file, cap).await {
            StreamOutcome::Ok(_) => {}
            StreamOutcome::TooLarge => {
                return (StatusCode::PAYLOAD_TOO_LARGE, "Upload exceeds size limit").into_response()
            }
            StreamOutcome::ClientGone => return StatusCode::BAD_REQUEST.into_response(),
            StreamOutcome::Io(e) => {
                tracing::error!(error = %e, "Failed to write monolithic upload temp file");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
        (temp_path, guard)
    };

    // Verify digest by streaming SHA-256 — O(chunk_size) memory, not O(blob_size)
    {
        let computed = match sha256_of_file(&temp_path).await {
            Ok(h) => format!("sha256:{h}"),
            Err(e) => {
                tracing::error!(error = %e, "Failed to hash temp file for digest verification");
                let _ = tokio::fs::remove_file(&temp_path).await;
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        if computed != *digest {
            tracing::warn!(
                expected = %digest,
                computed = %computed,
                name = %name,
                "SECURITY: blob digest mismatch — rejecting upload"
            );
            let _ = tokio::fs::remove_file(&temp_path).await;
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "errors": [{
                        "code": "DIGEST_INVALID",
                        "message": "provided digest did not match uploaded content",
                        "detail": { "expected": digest, "computed": computed }
                    }]
                })),
            )
                .into_response();
        }
    }

    // Move temp file into storage — no RAM copy of the blob. The digest was just checked
    // against the bytes (`sha256:` and their hex), so it pins them (#1154).
    let key = format!("docker/{}/blobs/{}", name, digest);
    match state
        .storage
        .put_from_path(&key, &temp_path, digest.strip_prefix("sha256:"))
        .await
    {
        Ok(()) => {
            guard.disarm(); // temp moved into storage — nothing left to clean up
            state.metrics.record_upload("docker");
            state.audit.log(AuditEntry::new(
                "push",
                "api",
                &format!("{}@{}", name, digest),
                "docker",
                "blob",
            ));
            state.activity.push(ActivityEntry::new(
                ActionType::Push,
                format!("{}@{}", name, &digest[..19.min(digest.len())]),
                crate::registry_type::RegistryType::Docker,
                "LOCAL",
            ));
            state.repo_index.invalidate("docker");
            blob_created(&name, digest)
        }
        Err(e) => {
            tracing::error!(error = %e, key = %key, name = %name, "Failed to store blob");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Try to fetch a manifest from upstream(s) and cache it locally.
///
/// Iterates over `upstreams`, fetching `upstream_name` (which may differ from
/// the user-facing `name` — e.g. `library/nginx` vs `nginx`). On success:
/// records metrics/activity, runs quarantine, spawns a cache task that writes
/// the manifest by tag, by digest, plus metadata sidecars.
///
/// Returns `Some(Response)` on first successful upstream (or quarantine block),
/// `None` if all upstreams failed.
/// `rate_limited` is set to the upstream `Retry-After` (if any) when an upstream
/// answered 429, so the caller can report throttling rather than a missing manifest.
/// `cached` is the copy held for the reference and the namespace it is served from: a tag
/// that moved to a held digest falls back to it ([`admitted_copy`]).
#[allow(clippy::too_many_arguments)]
async fn try_fetch_and_cache(
    state: &AppState,
    upstreams: &[&crate::config::DockerUpstream],
    misses: &mut [UpstreamMiss],
    upstream_name: &str,
    name: &str,
    reference: &str,
    cache_ns: Option<&str>,
    cached: Option<(&Bytes, Option<&str>)>,
    rate_limited: &mut Option<Option<String>>,
) -> Option<Response> {
    // Every copy this fetch writes — the tag, the digest copy and both metadata files — goes
    // under the namespace the request resolved to, where the reads look for them. On the
    // fallback chain that is its first upstream's, whichever upstream answered.
    let cache_key = manifest_key(cache_ns, name, reference);
    for (upstream, miss) in upstreams.iter().zip(misses.iter_mut()) {
        tracing::debug!(upstream_url = %upstream.url, upstream_name = %upstream_name, "Trying upstream");
        match fetch_manifest_from_upstream(
            &state.http_client,
            &upstream.url,
            upstream_name,
            reference,
            &state.docker_auth,
            state.config.docker.proxy_timeout,
            expose_opt(&upstream.auth),
            &state.circuit_breaker,
        )
        .await
        {
            Ok((data, content_type)) => {
                // A digest reference is content-addressed: an answer that hashes to another digest
                // is not this manifest. It counts as a failed upstream, and is neither served nor
                // cached under the requested digest.
                if !content_has_digest(reference, &data) {
                    tracing::warn!(upstream = %upstream.url, name = %upstream_name, reference = %reference, "Docker manifest from the upstream does not have the requested digest; trying next");
                    miss.record(&ProxyError::Upstream(502));
                    continue;
                }
                // The allowlist's pinned integrity holds on the first download too, before anything
                // is cached: serve_cached_manifest checks the same rule.
                if let Some(response) = crate::curation::verify_integrity(
                    &state.curation().curation_engine,
                    crate::curation::RegistryType::Docker,
                    name,
                    Some(reference),
                    &data,
                ) {
                    return Some(response);
                }
                // A 200 that is not a manifest (a captive portal, an error page) is a failed
                // upstream too: neither served nor cached under the tag.
                if let Some(reason) = upstream_manifest_invalid(&data) {
                    tracing::warn!(upstream = %upstream.url, name = %upstream_name, reference = %reference, reason, "Docker upstream answered 200 with a body that is not a manifest; trying next");
                    miss.record(&ProxyError::Upstream(502));
                    continue;
                }
                state.metrics.record_download("docker");
                state.metrics.record_cache_miss("docker");
                state.activity.push(ActivityEntry::new(
                    ActionType::ProxyFetch,
                    format!("{}:{}", name, reference),
                    crate::registry_type::RegistryType::Docker,
                    "PROXY",
                ));

                // Calculate digest for Docker-Content-Digest header
                use sha2::Digest;
                let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&data)));

                // Quarantine: record digest, check status
                let (q_mode, q_secs) = resolve_quarantine(state);
                let mut keep_tag_copy = false;
                if !matches!(q_mode, crate::digest_quarantine::QuarantineMode::Off) {
                    let seen = state.digest_store.check("docker", &digest, q_secs);
                    let first_sight =
                        matches!(seen, crate::digest_quarantine::QuarantineStatus::New);
                    let still_held = matches!(
                        seen,
                        crate::digest_quarantine::QuarantineStatus::Pending { .. }
                    );
                    // First sight under `trust_upstream_dates`: the registry's own publish
                    // date starts the clock, so an image older than the TTL is not new here.
                    // A digest held by NORA's clock is asked about again: it may have been
                    // recorded before its registry had a date source, or in a failed lookup.
                    let mut dated = None;
                    if let Some(source) = upstream.date_source().filter(|source| {
                        upstream.trust_upstream_dates
                            && (first_sight || (still_held && source.dates_digests()))
                    }) {
                        dated = super::docker_dates::published_at(
                            state,
                            upstream,
                            source,
                            upstream_name,
                            reference,
                            &digest,
                            &data,
                        )
                        .await
                        .map(|at| (at, source.label()));
                    }
                    let entry = match dated {
                        Some((at, source)) => quarantine_dated(
                            state,
                            &upstream.url,
                            upstream_name,
                            &digest,
                            &data,
                            at,
                            source,
                        ),
                        None => {
                            let entry =
                                state
                                    .digest_store
                                    .record("docker", &digest, &upstream.url, None);
                            quarantine_record_referenced(
                                state,
                                &data,
                                &upstream.url,
                                entry.first_seen,
                                true,
                            );
                            entry
                        }
                    };
                    let q_status = state.digest_store.check("docker", &digest, q_secs);
                    if first_sight {
                        let source = dated.map_or("first_seen", |(_, source)| source);
                        let status = if matches!(
                            q_status,
                            crate::digest_quarantine::QuarantineStatus::Mature
                        ) {
                            "mature"
                        } else {
                            "held"
                        };
                        let ns = upstream.resolved_namespace();
                        crate::metrics::DOCKER_QUARANTINE_FIRST_SIGHT_TOTAL
                            .with_label_values(&[ns.as_str(), source, status])
                            .inc();
                        tracing::info!(
                            digest = %digest,
                            name = %upstream_name,
                            reference = %reference,
                            upstream = %upstream.url,
                            source,
                            first_seen = entry.first_seen,
                            status,
                            "Quarantine: first sight of a proxied manifest"
                        );
                    }
                    // A break-glass exception admits the digest, and what it names.
                    let q_status =
                        if !matches!(q_status, crate::digest_quarantine::QuarantineStatus::Mature)
                            && quarantine_excepted(state, &digest, Some(&data[..]))
                        {
                            crate::digest_quarantine::QuarantineStatus::Mature
                        } else {
                            q_status
                        };
                    match &q_status {
                        crate::digest_quarantine::QuarantineStatus::Mature => {}
                        _ => {
                            let outcome = if matches!(
                                q_mode,
                                crate::digest_quarantine::QuarantineMode::Enforce
                            ) {
                                "blocked"
                            } else {
                                "observed"
                            };
                            crate::metrics::QUARANTINE_HOLDS_TOTAL
                                .with_label_values(&["docker", outcome])
                                .inc();
                            tracing::warn!(
                                digest = %digest,
                                upstream = %upstream.url,
                                status = %q_status.header_value(),
                                mode = ?q_mode,
                                quarantine_ttl_secs = q_secs,
                                "Quarantine: proxy-fetched manifest"
                            );
                        }
                    }
                    let enforce =
                        matches!(q_mode, crate::digest_quarantine::QuarantineMode::Enforce);
                    let held =
                        !matches!(q_status, crate::digest_quarantine::QuarantineStatus::Mature);
                    let admitted = cached
                        .filter(|_| held)
                        .filter(|(copy, _)| admitted_copy(state, reference, copy, &digest, q_secs));
                    keep_tag_copy = admitted.is_some();
                    if held && !reference.starts_with("sha256:") {
                        let outcome = match (enforce, admitted.is_some()) {
                            (true, true) => "fallback",
                            (true, false) => "blocked",
                            (false, true) => "would_fallback",
                            (false, false) => "would_block",
                        };
                        crate::metrics::DOCKER_QUARANTINE_TAG_HELD_TOTAL
                            .with_label_values(&[upstream.resolved_namespace().as_str(), outcome])
                            .inc();
                        tracing::warn!(
                            name = %upstream_name,
                            tag = %reference,
                            held = %digest,
                            outcome,
                            "Quarantine: tag resolves to a held digest"
                        );
                    }
                    // In enforce mode, still cache by digest, but the client gets the tag's
                    // admitted copy or a refusal. The tag copy stays: it is the fallback.
                    if enforce && held {
                        let storage = state.storage.clone();
                        let key_clone = manifest_key(cache_ns, name, &digest);
                        let repo_index = Arc::clone(&state.repo_index);
                        let held_data = data.clone();
                        tokio::spawn(async move {
                            if let Err(e) = storage.put(&key_clone, &held_data).await {
                                tracing::warn!(key = %key_clone, error = %e, "cache write failed (quarantine pre-cache)");
                                crate::metrics::CACHE_WRITE_ERRORS
                                    .with_label_values(&["docker", "manifest"])
                                    .inc();
                            }
                            repo_index.invalidate("docker");
                        });
                        let Some((copy, ns)) = admitted else {
                            return Some(quarantine_forbidden(&digest, &q_status, q_secs));
                        };
                        let mut response = serve_cached_manifest(state, copy, name, reference, ns);
                        let until = entry.first_seen + q_secs;
                        if let Ok(value) = axum::http::HeaderValue::from_str(&digest) {
                            response
                                .headers_mut()
                                .insert(HeaderName::from_static("x-nora-quarantine-held"), value);
                        }
                        response.headers_mut().insert(
                            HeaderName::from_static("x-nora-quarantine-held-until"),
                            axum::http::HeaderValue::from(until),
                        );
                        return Some(response);
                    }
                }

                // Cache manifest and create metadata (fire and forget)
                let upstream_ns = cache_ns.map(String::from);
                let storage = state.storage.clone();
                let key_clone = cache_key.clone();
                let data_clone = data.clone();
                let name_clone = name.to_string();
                let reference_clone = reference.to_string();
                let digest_clone = digest.clone();
                let repo_index = Arc::clone(&state.repo_index);
                let state_clone = state.clone();
                tokio::spawn(async move {
                    // Store manifest by tag and digest (namespaced). A held digest does not
                    // replace the admitted tag copy under observe either, so a tag that
                    // moved just before enforce still has one behind it.
                    if keep_tag_copy {
                        tracing::debug!(key = %key_clone, "tag copy kept: the new digest is held");
                    } else if let Err(e) = storage.put(&key_clone, &data_clone).await {
                        tracing::warn!(key = %key_clone, error = %e, "cache write failed (manifest by tag)");
                        crate::metrics::CACHE_WRITE_ERRORS
                            .with_label_values(&["docker", "manifest"])
                            .inc();
                    }
                    let digest_key =
                        manifest_key(upstream_ns.as_deref(), &name_clone, &digest_clone);
                    if let Err(e) = storage.put(&digest_key, &data_clone).await {
                        tracing::warn!(key = %digest_key, error = %e, "cache write failed (manifest by digest)");
                        crate::metrics::CACHE_WRITE_ERRORS
                            .with_label_values(&["docker", "manifest"])
                            .inc();
                    }

                    // Extract and save metadata
                    let metadata = extract_metadata(&data_clone, &storage, &name_clone).await;
                    // The manifest is stored first; its metadata goes under the metadata lock, so
                    // a pull's statistics on this copy cannot write over it.
                    if let Ok(meta_json) = serde_json::to_vec(&metadata) {
                        if let Err(e) = write_manifest_meta(
                            &state_clone,
                            upstream_ns.as_deref(),
                            &name_clone,
                            &reference_clone,
                            &meta_json,
                        )
                        .await
                        {
                            tracing::warn!(name = %name_clone, reference = %reference_clone, error = %e, "cache write failed (metadata by tag)");
                            crate::metrics::CACHE_WRITE_ERRORS
                                .with_label_values(&["docker", "metadata"])
                                .inc();
                        }

                        if let Err(e) = write_manifest_meta(
                            &state_clone,
                            upstream_ns.as_deref(),
                            &name_clone,
                            &digest_clone,
                            &meta_json,
                        )
                        .await
                        {
                            tracing::warn!(name = %name_clone, digest = %digest_clone, error = %e, "cache write failed (metadata by digest)");
                            crate::metrics::CACHE_WRITE_ERRORS
                                .with_label_values(&["docker", "metadata"])
                                .inc();
                        }
                    }
                    repo_index.invalidate("docker");
                });

                return Some(manifest_response(data, content_type, digest));
            }
            // An open breaker skips this upstream for the next, as a failure does (#1198).
            Err(e) => {
                if let ProxyError::RateLimited(retry_after) = &e {
                    *rate_limited = Some(retry_after.clone());
                }
                tracing::debug!(error = ?e, upstream = %upstream.url, name = %upstream_name, reference = %reference, "Docker manifest proxy fetch failed, trying next");
                miss.record(&e);
            }
        }
    }
    None
}

/// Whether `data` is the content a digest reference names (`sha256:` or `sha512:`, lowercase
/// hex as the OCI spec writes it). A tag names no content, so any bytes may answer it.
fn content_has_digest(reference: &str, data: &[u8]) -> bool {
    use sha2::Digest;
    if let Some(hex) = reference.strip_prefix("sha256:") {
        return hex::encode(sha2::Sha256::digest(data)) == hex;
    }
    if let Some(hex) = reference.strip_prefix("sha512:") {
        return hex::encode(sha2::Sha512::digest(data)) == hex;
    }
    true
}

/// Whether a reference is a digest (content-addressed) rather than a tag.
fn is_digest_reference(reference: &str) -> bool {
    reference.starts_with("sha256:") || reference.starts_with("sha512:")
}

/// Whether resolving a reference consults its push record: a tag whose namespaced (proxied) key
/// is not its bare (pushed) one. Only then is the tag's bare metadata needed to answer it.
fn consults_push_record(ns: Option<&str>, name: &str, reference: &str) -> bool {
    !is_digest_reference(reference)
        && manifest_key(ns, name, reference) != manifest_key(None, name, reference)
}

/// The stored copy that answers a manifest reference, and whether it is hosted (pushed or bare)
/// rather than proxied — one resolution for every reader: GET and HEAD, and the deletes that
/// follow a tag. A tag whose push record names the digest of the bare manifest answers with it
/// (a push answers its tag); otherwise the namespaced (proxied) copy, then the bare one.
/// Digest references are content-addressed and skip the record. A storage error other than
/// NotFound is the answer: a failed read never hands the reference to another copy.
async fn resolve_manifest(
    state: &AppState,
    ns: Option<&str>,
    name: &str,
    reference: &str,
    pushed: Option<crate::storage::Result<PushedTag>>,
) -> crate::storage::Result<Option<(Bytes, bool)>> {
    use crate::storage::StorageError;
    let key = manifest_key(ns, name, reference);
    let legacy_key = manifest_key(None, name, reference);
    if consults_push_record(ns, name, reference) {
        let pushed = match pushed {
            Some(pushed) => pushed,
            None => pushed_tag(&state.storage, name, reference).await,
        };
        if let PushedTag::Push { manifest, .. } = pushed? {
            return Ok(Some((manifest, true)));
        }
    }
    match state.storage.get(&key).await {
        Ok(data) => Ok(Some((data, key == legacy_key))),
        Err(StorageError::NotFound) if key != legacy_key => {
            match state.storage.get(&legacy_key).await {
                Ok(data) => Ok(Some((data, true))),
                Err(StorageError::NotFound) => Ok(None),
                Err(e) => Err(e),
            }
        }
        Err(StorageError::NotFound) => Ok(None),
        Err(e) => Err(e),
    }
}

/// What a pull reads of a tag a push may answer: the one decision that the tag is the push's.
enum PushedTag {
    /// The bare metadata holds a push record and the bare manifest is stored: the tag is the push's.
    /// Its manifest answers it — whatever bytes it holds, since the bare key is written only by a
    /// push, so other bytes are a re-push in progress — and curation dates it by the record.
    Push {
        manifest: Bytes,
        record: ImageMetadata,
    },
    /// No push answers the tag: no record, or a record without its manifest (an interrupted
    /// delete left it). The bare metadata as read, for the publish date.
    NotPushed { bare_meta: Option<Bytes> },
}

/// Reads whether a push answers a tag: its bare metadata and, with a push record
/// ([`push_record`]) there, its bare manifest. Err on a storage error other than NotFound, so that a
/// failed read never hands the tag to another copy.
async fn pushed_tag(
    storage: &Storage,
    name: &str,
    reference: &str,
) -> crate::storage::Result<PushedTag> {
    use crate::storage::StorageError;
    let bare_meta = read_bare_meta(storage, name, reference).await?;
    let Some(record) = bare_meta.as_deref().and_then(push_record) else {
        return Ok(PushedTag::NotPushed { bare_meta });
    };
    match storage.get(&manifest_key(None, name, reference)).await {
        Ok(manifest) => Ok(PushedTag::Push { manifest, record }),
        Err(StorageError::NotFound) => Ok(PushedTag::NotPushed { bare_meta }),
        Err(e) => Err(e),
    }
}

/// The push record in a tag's bare metadata: the metadata, when it names a pushed digest
/// (`sha256:` or `sha512:`). A tag with one is the push's: the bare
/// manifest answers it and curation dates it by the push. Pure: the whole test is this function.
pub(crate) fn push_record(meta: &[u8]) -> Option<ImageMetadata> {
    serde_json::from_slice::<ImageMetadata>(meta)
        .ok()
        .filter(|m| {
            m.pushed_digest
                .as_deref()
                .is_some_and(|d| d.starts_with("sha256:") || d.starts_with("sha512:"))
        })
}

/// Whether a cached manifest may be served WITHOUT revalidating against upstream.
///
/// A **digest** reference is immutable (content-addressed) → always fresh. A **tag** on a
/// **hosted** name (no upstream to revalidate against) is locally authoritative → fresh. A
/// **tag** on a **proxied** name is mutable: it must be revalidated against upstream unless it
/// is still within a POSITIVE `metadata_ttl` staleness window. The default (and any non-positive
/// ttl) revalidates every pull, so a re-pushed upstream tag is reflected (#638).
fn manifest_cache_fresh(
    is_digest: bool,
    has_upstream: bool,
    metadata_ttl: i64,
    modified: Option<u64>,
) -> bool {
    if is_digest || !has_upstream {
        return true;
    }
    metadata_ttl > 0
        && modified
            .map(|m| crate::cache_ttl::is_within_ttl(m, metadata_ttl))
            .unwrap_or(false)
}

async fn get_manifest(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((name, reference)): Path<(String, String)>,
) -> Response {
    let c = canonicalize(&name, &state.config.docker);
    if let Some(r) = c.denied_response() {
        return r;
    }
    let upstreams_to_try = c.upstreams_to_try(&state.config.docker.upstreams);
    let ns = c.namespace;
    let name = c.name;
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_docker_reference(&reference) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    // Whether a push answers the tag, read once: a tag that is the push's is dated by its record and
    // answered by its manifest; otherwise the date comes from the .meta.json sidecars (namespaced,
    // then the bare one already read) and the resolver goes on to the other copies.
    let pushed = if consults_push_record(ns.as_deref(), &name, &reference) {
        Some(pushed_tag(&state.storage, &name, &reference).await)
    } else {
        None
    };
    let publish_date = match &pushed {
        Some(Ok(PushedTag::Push { record, .. })) => {
            (record.push_timestamp > 0).then_some(record.push_timestamp as i64)
        }
        Some(Ok(PushedTag::NotPushed { bare_meta })) => {
            extract_docker_publish_date(
                &state.storage,
                &name,
                &reference,
                state.config.docker.upstreams.is_empty(),
                ns.as_deref(),
                &mut BareMeta::Read(Ok(bare_meta.clone())),
            )
            .await
        }
        _ => {
            extract_docker_publish_date(
                &state.storage,
                &name,
                &reference,
                state.config.docker.upstreams.is_empty(),
                ns.as_deref(),
                &mut BareMeta::Unread,
            )
            .await
        }
    };

    // Curation check — manifests carry the image identity. #733 serve-local: an internal-namespace
    // image is operator-owned — skip curation and serve any local manifest below; block the
    // upstream branch separately (never proxy an internal name).
    let internal = crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Docker,
        &name,
    );
    if !internal {
        if let Some(response) = crate::curation::check_download(
            &state.curation().curation_engine,
            state.bypass_token().as_deref(),
            &headers,
            crate::curation::RegistryType::Docker,
            &name,
            crate::curation::RequestVersion::Known(reference.to_string()),
            publish_date,
        ) {
            return response;
        }
    }

    let key = manifest_key(ns.as_deref(), &name, &reference);
    let legacy_key = manifest_key(None, &name, &reference);

    // Try local storage first (namespaced key, then bare-key fallback). Provenance lives in
    // the key layout: the namespaced key only ever holds an upstream-proxied copy, while the
    // bare key is what `put_manifest` writes — a bare-key hit is a locally pushed (hosted)
    // manifest. (Pre-#349 flat-keyed proxy caches are consequently read as hosted; the cost
    // is skipped tag revalidation on those legacy entries.)
    // Provenance decides freshness below, so a transient storage error must fail closed
    // (500) rather than fall through to the legacy key or the proxy: an error-driven
    // fallback silently flips WHICH copy answers (proxied-current vs legacy/hosted), and
    // an error-driven proxy would resolve a hosted name against an upstream that may be
    // squatted. Only `NotFound` may advance to the next source.
    let (cached, hosted) = match resolve_manifest(&state, ns.as_deref(), &name, &reference, pushed)
        .await
    {
        Ok(Some((data, hosted))) => (Some(data), hosted),
        Ok(None) => (None, true),
        Err(e) => {
            tracing::error!(error = %e, name = %name, reference = %reference, "manifest read failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    // A copy under a digest reference that hashes to another digest (cached before fetches were
    // checked) is not that manifest: it is neither served nor treated as cached.
    let cached = cached.filter(|data| content_has_digest(&reference, data));
    // A served copy's pull statistics live beside it: a bare-key (hosted) hit counts against
    // the pushed image's own metadata, a namespaced hit against the proxied copy's.
    let served_ns = if hosted { None } else { ns.as_deref() };
    // `Cache-Control: only-if-cached` (RFC 9111 5.2.1.7): answer from what NORA holds, never
    // from an upstream. A quarantine probe (github-actions base-image check) reads the verdict
    // of a digest without fetching it, so the probe never starts a digest's clock itself
    // (issues-maestra#1649). Not cached: 504, as the RFC says. A cached tag answers its copy,
    // fresh or not.
    if only_if_cached(&headers) {
        return match cached {
            Some(ref data) => serve_cached_manifest(&state, data, &name, &reference, served_ns),
            None => (
                StatusCode::GATEWAY_TIMEOUT,
                Json(json!({"errors": [{
                    "code": "MANIFEST_UNKNOWN",
                    "message": "not in NORA's cache (only-if-cached)",
                    "detail": {"name": name, "reference": reference},
                }]})),
            )
                .into_response(),
        };
    }
    // Digest references are immutable (content-addressed) → the cache is authoritative forever.
    // Tag references on PROXIED copies are MUTABLE: a tag can be re-pushed to point at a
    // different manifest, so a proxied tag must be revalidated against upstream before it is
    // served — otherwise a re-pushed upstream tag is never reflected (#638). `metadata_ttl` is
    // an optional staleness window for tags: only a POSITIVE value serves a tag from cache
    // without revalidating (within the window); otherwise the latest is fetched. A HOSTED
    // manifest (bare-key hit, or no upstreams configured) is authoritative and served without
    // any upstream round trip — before this distinction a hosted tag was revalidated against
    // an upstream that never had it, 404ing local images when upstream was down and
    // serve_stale off, and stale-marking every pull otherwise.
    let is_digest = reference.starts_with("sha256:");
    let revalidate = !hosted && !upstreams_to_try.is_empty();
    let cache_fresh = if cached.is_some() {
        let modified = if revalidate && !is_digest {
            storage_stat_with_fallback(&state.storage, &key, &legacy_key)
                .await
                .map(|m| m.modified)
        } else {
            None
        };
        manifest_cache_fresh(
            is_digest,
            revalidate,
            state.config.docker.metadata_ttl,
            modified,
        )
    } else {
        false
    };

    // Serve fresh cache immediately
    if let Some(ref data) = cached {
        if cache_fresh {
            // An internal-namespace name is never sent upstream, not even to a date API.
            if !hosted && !internal {
                quarantine_redate_cached(&state, &upstreams_to_try, &name, &reference, data).await;
            }
            return serve_cached_manifest(&state, data, &name, &reference, served_ns);
        }
    }

    // #733/#821: an internal-namespace image's manifest — serve any (stale) local copy, else
    // return a genuine not-found; never proxy upstream (the fresh path already returned above,
    // and this branch precedes the proxy loop — dependency-confusion defense intact). A hosted
    // image's absent tag is 404 MANIFEST_UNKNOWN, NOT 403: Docker/BuildKit treats 403 on a
    // manifest HEAD/GET as fatal, breaking push HEAD-probes and OCI referrers (sha256-<digest>)
    // lookups on locally-hosted images.
    if internal {
        if let Some(ref data) = cached {
            return serve_cached_manifest(&state, data, &name, &reference, served_ns);
        }
        crate::metrics::record_namespace_isolation_refused("docker");
        return manifest_unknown_response(&name, &reference);
    }

    // Try upstream proxies (always if no cache, or if cache is stale)
    tracing::debug!(
        upstreams_count = upstreams_to_try.len(),
        "Trying upstream proxies"
    );
    let mut rate_limited = None;
    // One record per upstream, across both names it may be asked under (library/ below).
    let mut misses: Vec<UpstreamMiss> = upstreams_to_try
        .iter()
        .map(|_| UpstreamMiss::default())
        .collect();
    let copy = cached.as_ref().map(|data| (data, served_ns));
    if let Some(response) = try_fetch_and_cache(
        &state,
        &upstreams_to_try,
        &mut misses,
        &name,
        &name,
        &reference,
        ns.as_deref(),
        copy,
        &mut rate_limited,
    )
    .await
    {
        return response;
    }

    // Auto-prepend library/ for single-segment names (Docker Hub official images)
    // e.g., "nginx" -> "library/nginx", "alpine" -> "library/alpine"
    if !name.contains('/') {
        let library_name = format!("library/{}", name);
        if let Some(response) = try_fetch_and_cache(
            &state,
            &upstreams_to_try,
            &mut misses,
            &library_name,
            &name,
            &reference,
            ns.as_deref(),
            copy,
            &mut rate_limited,
        )
        .await
        {
            return response;
        }
    }

    // Stale-while-error: serve stale cached manifest when upstream is unreachable
    if let Some(ref data) = cached {
        if state.config.docker.serve_stale {
            tracing::warn!(
                registry = "docker",
                name = %name,
                reference = %reference,
                "Upstream failed, serving stale cached manifest"
            );
            let mut response = serve_cached_manifest(&state, data, &name, &reference, served_ns);
            response.headers_mut().insert(
                axum::http::header::HeaderName::from_static("x-nora-stale"),
                axum::http::header::HeaderValue::from_static("true"),
            );
            response.headers_mut().insert(
                axum::http::header::CACHE_CONTROL,
                axum::http::header::HeaderValue::from_static("public, max-age=0, must-revalidate"),
            );
            return response;
        }
    }

    // Throttled upstream (Docker Hub pull-rate limit): 429 TOOMANYREQUESTS with its
    // Retry-After, which docker/containerd report as such — not MANIFEST_UNKNOWN.
    if let Some(retry_after) = rate_limited {
        tracing::warn!(registry = "docker", name = %name, reference = %reference, ?retry_after, "upstream rate-limited the manifest pull, returning 429");
        let retry_after = retry_after
            .as_deref()
            .and_then(|v| axum::http::HeaderValue::from_str(v).ok())
            .unwrap_or_else(|| axum::http::HeaderValue::from_static("60"));
        let body = serde_json::json!({"errors": [{
            "code": "TOOMANYREQUESTS",
            "message": "upstream registry rate limit exceeded",
            "detail": {"name": name, "reference": reference},
        }]});
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, retry_after)],
            axum::Json(body),
        )
            .into_response();
    }

    let mut miss = UpstreamMiss::default();
    for asked in &misses {
        miss.record_upstream(asked);
    }
    docker_miss_response(
        &miss,
        Missed::Manifest {
            name: &name,
            reference: &reference,
        },
    )
}

/// The request's `Cache-Control` holds `only-if-cached` (any case, among other directives).
fn only_if_cached(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get_all(header::CACHE_CONTROL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|d| d.trim().eq_ignore_ascii_case("only-if-cached"))
}

/// Serve a manifest from local cache with all required headers and side-effects.
fn serve_cached_manifest(
    state: &AppState,
    data: &[u8],
    name: &str,
    reference: &str,
    ns: Option<&str>,
) -> Response {
    // Curation integrity verification (issue #189)
    if let Some(response) = crate::curation::verify_integrity(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Docker,
        name,
        Some(reference),
        data,
    ) {
        return response;
    }

    state.metrics.record_download("docker");
    state.metrics.record_cache_hit("docker");
    state.activity.push(ActivityEntry::new(
        ActionType::Pull,
        format!("{}:{}", name, reference),
        crate::registry_type::RegistryType::Docker,
        "LOCAL",
    ));

    // Calculate digest for Docker-Content-Digest header
    use sha2::Digest;
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(data)));

    // Quarantine: a cached manifest still within its proxy cooldown is held. A manifest
    // with no proxy record (a local push, or a pruned entry) reads as `New` and serves —
    // only `Pending` blocks, so a local push is never held and never matures a proxy
    // digest. (A just-proxied manifest is recorded + checked on the fetch path above.)
    if let Some(resp) = quarantine_cache_serve_gate(state, &digest, Some(data)) {
        return resp;
    }
    quarantine_readmit_referenced(state, data, &digest, ns);

    // Detect manifest media type from content
    let content_type = detect_manifest_media_type(data);

    // Count the pull OFF the request path (#1114): bump the in-memory
    // accumulator instead of rewriting `.meta.json`. A background task flushes
    // it to a `.stats.json` sidecar. No spawn, no publish lock, no storage write
    // here — so the request-path publish-date read never races a pull.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    state
        .pull_stats
        .record(&manifest_meta_key(ns, name, reference), now);

    manifest_response(Bytes::copy_from_slice(data), content_type, digest)
}

/// Return the first blob / sub-manifest digest a pushed manifest references that NORA does not
/// hold for the repository, or `None` when every referenced item exists. Per the OCI
/// Distribution Spec a manifest pointing at content we do not have must be rejected
/// (`MANIFEST_BLOB_UNKNOWN`) rather than stored as a broken image. Bodies we cannot parse return
/// `None` — malformed manifests are out of scope here.
///
/// "Holds" is what the blob HEAD reports, so a client that skipped an upload on its 200 can
/// push the manifest: the pushed (bare) copy, or the proxied copy under `ns`. A proxied copy
/// is copied into the pushed layout — the pushed image must not depend on a cache that
/// eviction empties — unless the quarantine still holds its digest, as a mount refuses it.
/// A child manifest taken over this way has its own references checked the same way.
async fn missing_manifest_ref(
    state: &AppState,
    ns: Option<&str>,
    name: &str,
    body: &[u8],
) -> Option<String> {
    let storage = &state.storage;
    let mut pending = vec![Bytes::copy_from_slice(body)];
    while let Some(body) = pending.pop() {
        let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body) else {
            continue;
        };

        // Image index / manifest list: referenced sub-manifests live under manifests/.
        if let Some(manifests) = json.get("manifests").and_then(|v| v.as_array()) {
            for m in manifests {
                let Some(d) = m.get("digest").and_then(|v| v.as_str()) else {
                    continue;
                };
                let pushed = manifest_key(None, name, d);
                if storage.stat(&pushed).await.is_some() {
                    continue;
                }
                let proxied = manifest_key(ns, name, d);
                let Ok(child) = storage.get(&proxied).await else {
                    return Some(d.to_string());
                };
                if proxied == pushed
                    || !content_has_digest(d, &child)
                    || quarantine_cache_serve_gate(state, d, Some(&child)).is_some()
                    || storage.put(&pushed, &child).await.is_err()
                {
                    return Some(d.to_string());
                }
                pending.push(child);
            }
            continue;
        }

        // Image manifest: the config descriptor and every layer are blobs.
        let mut refs: Vec<&str> = Vec::new();
        if let Some(d) = json
            .get("config")
            .and_then(|c| c.get("digest"))
            .and_then(|v| v.as_str())
        {
            refs.push(d);
        }
        if let Some(layers) = json.get("layers").and_then(|v| v.as_array()) {
            for l in layers {
                if let Some(d) = l.get("digest").and_then(|v| v.as_str()) {
                    refs.push(d);
                }
            }
        }
        for d in refs {
            let pushed = blob_key(None, name, d);
            if storage.stat(&pushed).await.is_some() {
                continue;
            }
            let proxied = blob_key(ns, name, d);
            if proxied == pushed
                || storage.stat(&proxied).await.is_none()
                || quarantine_cache_serve_gate(state, d, None).is_some()
                || storage
                    .copy(&proxied, &pushed, d.strip_prefix("sha256:"))
                    .await
                    .is_err()
            {
                return Some(d.to_string());
            }
        }
    }
    None
}

/// Why `body` is not a manifest NORA stores or caches, or `None` when it is one: a JSON object
/// with `schemaVersion` 2, as every OCI and Docker v2 manifest and index is.
fn manifest_invalid(body: &[u8]) -> Option<&'static str> {
    match serde_json::from_slice::<Value>(body) {
        Ok(Value::Object(m)) if m.get("schemaVersion").and_then(Value::as_u64) == Some(2) => None,
        Ok(Value::Object(_)) => Some("schemaVersion must be 2"),
        _ => Some("manifest is not a JSON object"),
    }
}

/// Why a pushed manifest's `mediaType` field disagrees with the request's `Content-Type`, or
/// `None` when either is absent or they agree (media type parameters are not compared).
fn manifest_media_type_mismatch(
    headers: &axum::http::HeaderMap,
    body: &[u8],
) -> Option<&'static str> {
    let content_type = headers.get(header::CONTENT_TYPE)?.to_str().ok()?;
    let content_type = content_type.split(';').next().unwrap_or_default().trim();
    let json = serde_json::from_slice::<Value>(body).ok()?;
    let media_type = json.get("mediaType")?.as_str()?;
    (!content_type.eq_ignore_ascii_case(media_type))
        .then_some("mediaType does not match the Content-Type header")
}

/// 400 `MANIFEST_INVALID` per the OCI Distribution Spec.
fn manifest_invalid_response(reason: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "errors": [{ "code": "MANIFEST_INVALID", "message": "manifest invalid", "detail": reason }]
        })),
    )
        .into_response()
}

/// The lock that orders a push of `digest` against a tag delete deciding whether the digest
/// copy still has a tag: taken after the tag's own lock, never before it. Not the lock of the
/// digest's manifest key, which a delete by digest holds while it takes tag locks.
fn digest_refs_lock_key(name: &str, digest: &str) -> String {
    format!("{}#refs", manifest_key(None, name, digest))
}

async fn put_manifest(
    State(state): State<AppState>,
    Path((name, reference)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let c = canonicalize(&name, &state.config.docker);
    if let Some(r) = c.denied_response() {
        return r;
    }
    let name = c.name;
    let ns = c.namespace;
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_docker_reference(&reference) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    // A manifest pushed by digest is that digest's content (OCI DIGEST_INVALID otherwise).
    if !content_has_digest(&reference, &body) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "errors": [{
                    "code": "DIGEST_INVALID",
                    "message": "provided digest did not match uploaded content",
                    "detail": { "digest": reference }
                }]
            })),
        )
            .into_response();
    }

    // A body that is not a manifest is never stored: a pull would answer with it, and one
    // unreadable manifest stops the GC sweep of every repository.
    if let Some(reason) = manifest_invalid(&body) {
        return manifest_invalid_response(reason);
    }

    // Calculate digest
    use sha2::Digest;
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&body)));

    // Reject a manifest that references content (config / layers / sub-manifests) we do
    // not have — a broken image must not be pushable (OCI MANIFEST_BLOB_UNKNOWN).
    if let Some(missing) = missing_manifest_ref(&state, ns.as_deref(), &name, &body).await {
        tracing::warn!(
            name = %name,
            reference = %reference,
            missing = %missing,
            "rejecting manifest push: references an absent blob/sub-manifest"
        );
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "errors": [{
                    "code": "MANIFEST_BLOB_UNKNOWN",
                    "message": "manifest references an unknown blob",
                    "detail": { "digest": missing }
                }]
            })),
        )
            .into_response();
    }

    // Local push: NOT recorded in the quarantine ledger. The cooldown is a control on
    // content arriving from upstream; a local push has no proxy record, so the
    // cache-serve gate reads it as `New` and serves it. Not recording here also keeps a
    // local push from setting the first-seen clock for a digest later fetched upstream.

    // Store by tag/reference. Hold the SAME publish_lock key as delete_manifest so a
    // concurrent push/push or push/delete of one tag cannot interleave (the tag + digest
    // + metadata writes below stay consistent). Held until the end of the handler.
    let key = format!("docker/{}/manifests/{}.json", name, reference);
    let manifest_lock = state.publish_lock(&manifest_key(ns.as_deref(), &name, &reference));
    let _manifest_guard = manifest_lock.lock().await;
    // The digest copy and the tag are written under the digest's reference lock, which a
    // tag delete holds while it decides whether the digest copy has another tag left.
    let refs_lock = state.publish_lock(&digest_refs_lock_key(&name, &digest));
    let _refs_guard = refs_lock.lock().await;

    // The digest copy first, the tag last: a push that fails half-way has not moved the tag
    // to a manifest that a pull by digest cannot find.
    let digest_key = format!("docker/{}/manifests/{}.json", name, digest);
    if state.storage.put(&digest_key, &body).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if key != digest_key && state.storage.put(&key, &body).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // Extract and save metadata, with the record that this tag was pushed here.
    let mut metadata = extract_metadata(&body, &state.storage, &name).await;
    metadata.pushed_digest = Some(digest.clone());
    if let Ok(meta_json) = serde_json::to_vec(&metadata) {
        if let Err(e) = write_manifest_meta(&state, None, &name, &reference, &meta_json).await {
            tracing::warn!(name = %name, reference = %reference, error = %e, "cache write failed (push metadata by tag)");
            crate::metrics::CACHE_WRITE_ERRORS
                .with_label_values(&["docker", "metadata"])
                .inc();
        }

        // Also save metadata by digest
        if let Err(e) = write_manifest_meta(&state, None, &name, &digest, &meta_json).await {
            tracing::warn!(name = %name, digest = %digest, error = %e, "cache write failed (push metadata by digest)");
            crate::metrics::CACHE_WRITE_ERRORS
                .with_label_values(&["docker", "metadata"])
                .inc();
        }
    }

    // A push takes its tag back from the upstream: the proxied copy of this tag goes, with its
    // metadata (this handler holds the manifest lock; the metadata lock is taken after it).
    if let Some(ns) = ns.as_deref() {
        if manifest_key(Some(ns), &name, &reference) != key {
            delete_proxied_tag(&state, ns, &name, &reference).await;
        }
    }

    state.metrics.record_upload("docker");
    state.activity.push(ActivityEntry::new(
        ActionType::Push,
        format!("{}:{}", name, reference),
        crate::registry_type::RegistryType::Docker,
        "LOCAL",
    ));
    state.audit.log(AuditEntry::new(
        "push",
        "api",
        &format!("{}:{}", name, reference),
        "docker",
        "manifest",
    ));
    state.repo_index.invalidate("docker");

    let location = format!("/v2/{}/manifests/{}", name, reference);
    (
        StatusCode::CREATED,
        [
            (header::LOCATION, location),
            (HeaderName::from_static("docker-content-digest"), digest),
        ],
    )
        .into_response()
}

/// `GET /v2/<name>/tags/list[?n=<int>][&last=<tag>]`: the tags NORA holds for the repository
/// (pushed, or cached by a pull), in ASCII order. `last` starts after that tag, `n` caps the
/// page and a `Link: …; rel="next"` header names the next one. A repository NORA holds
/// nothing of is 404 `NAME_UNKNOWN`.
async fn list_tags(
    State(state): State<AppState>,
    Path(raw_name): Path<String>,
    params: HashMap<String, String>,
) -> Response {
    let c = canonicalize(&raw_name, &state.config.docker);
    if let Some(r) = c.denied_response() {
        return r;
    }
    let ns = c.namespace;
    let name = c.name;
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    let n = match params.get("n").map(|n| n.parse::<usize>()) {
        Some(Ok(n)) => Some(n),
        Some(Err(_)) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"errors": [{
                    "code": "PAGINATION_NUMBER_INVALID",
                    "message": "invalid number of results requested",
                    "detail": { "n": params.get("n") }
                }]})),
            )
                .into_response();
        }
        None => None,
    };
    let (mut tags, mut known) = match repository_tags(&state, ns.as_deref(), &name).await {
        Ok(found) => found,
        Err(e) => {
            tracing::error!(error = ?e, "docker: failed to list manifests for tags");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    // No manifest yet: the repository still exists while it holds a blob (a push in flight).
    if !known {
        let blobs = blob_key(ns.as_deref(), &name, "");
        let legacy_blobs = blob_key(None, &name, "");
        for prefix in [&blobs, &legacy_blobs] {
            match state.storage.list(prefix).await {
                Ok(keys) => known |= !keys.is_empty(),
                Err(e) => {
                    tracing::error!(error = ?e, "docker: failed to list blobs for tags");
                    return StatusCode::SERVICE_UNAVAILABLE.into_response();
                }
            }
            if known || blobs == legacy_blobs {
                break;
            }
        }
    }
    if !known {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"errors": [{
                "code": "NAME_UNKNOWN",
                "message": "repository name not known to registry",
                "detail": { "name": name }
            }]})),
        )
            .into_response();
    }
    if let Some(last) = params.get("last") {
        tags.retain(|t| t.as_str() > last.as_str());
    }
    let mut link = None;
    if let Some(n) = n {
        // `n=0` is an empty list with no Link (OCI); otherwise a full page names the next.
        if n > 0 && tags.len() > n {
            let last = percent_encoding::utf8_percent_encode(
                &tags[n - 1],
                percent_encoding::NON_ALPHANUMERIC,
            );
            link = Some(format!(
                "</v2/{raw_name}/tags/list?n={n}&last={last}>; rel=\"next\""
            ));
        }
        tags.truncate(n);
    }
    let mut response = (StatusCode::OK, Json(json!({"name": name, "tags": tags}))).into_response();
    if let Some(link) = link.and_then(|l| axum::http::HeaderValue::from_str(&l).ok()) {
        response.headers_mut().insert(header::LINK, link);
    }
    response
}

// ============================================================================
// Delete handlers (Docker Registry V2 spec)
// ============================================================================

// ── Manifest metadata (`*.meta.json`) ──────────────────────────────────────────────
//
// Only the functions in this section build a metadata key — `manifest_meta_key`'s callers are
// `write_manifest_meta`, `delete_manifest_and_meta`, `delete_proxied_tag`, `update_metadata_on_pull`
// and the readers `extract_docker_publish_date` and `read_bare_meta` (checked by
// `only_the_metadata_section_builds_metadata_keys`).
// They keep one order:
// - a manifest is written and deleted under its own lock (push, delete); its metadata under the
//   metadata lock, taken after the manifest's and never the other way round;
// - a manifest is deleted before its metadata, and its metadata only once it is gone;
// - a pull's statistics take only the metadata lock and write only while the manifest is stored.

/// Write a manifest's metadata (push, proxy fill) under the metadata lock: a pull's statistics
/// that read the file before this write cannot write the old contents back over it. A push
/// calls it while holding the manifest's lock.
async fn write_manifest_meta(
    state: &AppState,
    ns: Option<&str>,
    name: &str,
    reference: &str,
    json: &[u8],
) -> crate::storage::Result<()> {
    let key = manifest_meta_key(ns, name, reference);
    let lock = state.publish_lock(&key);
    let _guard = lock.lock().await;
    state.storage.put(&key, json).await
}

/// Delete the namespaced copy of an object and its bare one. Ok when either was deleted,
/// NotFound when neither was there, and any other failure is the answer, so the client
/// retries instead of believing the object gone.
async fn delete_copies(
    storage: &Storage,
    key: &str,
    legacy_key: &str,
) -> crate::storage::Result<()> {
    use crate::storage::StorageError;
    let mut results = vec![storage.delete(key).await];
    if legacy_key != key {
        results.push(storage.delete(legacy_key).await);
    }
    let (mut failure, mut deleted) = (None, false);
    for r in results {
        match r {
            Ok(()) => deleted = true,
            Err(StorageError::NotFound) => {}
            Err(e) => {
                failure.get_or_insert(e);
            }
        }
    }
    match (failure, deleted) {
        (Some(e), _) => Err(e),
        (None, true) => Ok(()),
        (None, false) => Err(StorageError::NotFound),
    }
}

/// Delete a manifest — the namespaced copy and the bare one (`both`), or the namespaced copy
/// and, when it is missing, the bare one — and then, once the manifest is gone, its metadata
/// (namespaced and bare), each under the metadata lock. The caller holds the manifest's lock.
/// Returns the manifest delete's result.
async fn delete_manifest_and_meta(
    state: &AppState,
    ns: Option<&str>,
    name: &str,
    reference: &str,
) -> crate::storage::Result<()> {
    let key = manifest_key(ns, name, reference);
    let legacy_key = manifest_key(None, name, reference);
    // Every copy goes, the namespaced one and a pre-migration bare one: a read falls back to the
    // bare copy, so a delete that stopped at the first copy left the manifest served. A failure
    // other than "not there" is the answer, so the client retries instead of believing it gone.
    let result = delete_copies(&state.storage, &key, &legacy_key).await;
    // Metadata goes only once the manifest is gone (deleted now, or not there at all).
    if matches!(result, Ok(()) | Err(crate::storage::StorageError::NotFound)) {
        let mut meta_keys = vec![manifest_meta_key(ns, name, reference)];
        if ns.is_some() {
            meta_keys.push(manifest_meta_key(None, name, reference));
        }
        for meta_key in meta_keys {
            let lock = state.publish_lock(&meta_key);
            let _guard = lock.lock().await;
            let _ = state.storage.delete(&meta_key).await;
            // #1114: drop the pull-stats sidecar under the same lock, so a
            // concurrent flush cannot leave a stale .stats.json for a gone manifest.
            let _ = state.storage.delete(&manifest_stats_key(&meta_key)).await;
        }
    }
    result
}

/// A tag's bare metadata as one request reads it. A push records itself there: a tag with a push
/// record is answered by the bare manifest and dated by the push, and a tag without one takes its
/// publish date from it when no proxied metadata exists. `get_manifest` lets the publish date read
/// it and hands what was read to the resolver; the deletes, which need only the push record, leave
/// it unread.
enum BareMeta {
    /// Not read: the reader that needs it reads it.
    Unread,
    /// Read once: Ok(None) when the tag has none; Err on a storage error other than NotFound.
    Read(crate::storage::Result<Option<Bytes>>),
}

/// A tag's bare metadata (see [`BareMeta`]). Err on a storage error other than NotFound.
async fn read_bare_meta(
    storage: &Storage,
    name: &str,
    reference: &str,
) -> crate::storage::Result<Option<Bytes>> {
    match storage.get(&manifest_meta_key(None, name, reference)).await {
        Ok(meta) => Ok(Some(meta)),
        Err(crate::storage::StorageError::NotFound) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Remove the proxied copy of a tag that has just been pushed, then its metadata under the
/// metadata lock. The caller holds the manifest's lock; the bare (pushed) copy is untouched.
async fn delete_proxied_tag(state: &AppState, ns: &str, name: &str, reference: &str) {
    let proxied = manifest_key(Some(ns), name, reference);
    if let Err(e) = state.storage.delete(&proxied).await {
        if !matches!(e, crate::storage::StorageError::NotFound) {
            tracing::warn!(key = %proxied, error = %e, "push: proxied copy of the tag not removed");
            return;
        }
    }
    let meta_key = manifest_meta_key(Some(ns), name, reference);
    let lock = state.publish_lock(&meta_key);
    let _guard = lock.lock().await;
    let _ = state.storage.delete(&meta_key).await;
}

/// The tags of a repository, sorted and distinct: the tag files under its namespaced and bare
/// manifest prefixes (digest copies and sidecars are not tags), and whether the repository
/// holds any manifest file at all. Err when either listing fails: a partial list is not the
/// list.
async fn repository_tags(
    state: &AppState,
    ns: Option<&str>,
    name: &str,
) -> crate::storage::Result<(Vec<String>, bool)> {
    let prefix = manifest_prefix(ns, name);
    let legacy_prefix = manifest_prefix(None, name);
    let mut keys = state.storage.list(&prefix).await?;
    if prefix != legacy_prefix {
        keys.extend(state.storage.list(&legacy_prefix).await?);
    }
    let mut tags: Vec<String> = keys
        .iter()
        .filter_map(|k| {
            k.strip_prefix(&prefix)
                .or_else(|| k.strip_prefix(&legacy_prefix))
                .and_then(tag_from_manifest_file)
                .map(String::from)
        })
        .collect();
    tags.sort();
    tags.dedup();
    Ok((tags, !keys.is_empty()))
}

/// The tags of a repository that answer with the manifest `digest`, each resolved as a read
/// resolves it. Err when the listing or any tag cannot be read.
async fn tags_resolving_to(
    state: &AppState,
    ns: Option<&str>,
    name: &str,
    digest: &str,
) -> crate::storage::Result<Vec<String>> {
    use sha2::Digest as _;
    let mut resolving = Vec::new();
    for tag in repository_tags(state, ns, name).await?.0 {
        if let Some((data, _)) = resolve_manifest(state, ns, name, &tag, None).await? {
            if format!("sha256:{}", hex::encode(sha2::Sha256::digest(&data))) == digest {
                resolving.push(tag);
            }
        }
    }
    Ok(resolving)
}

/// Delete every tag manifest that resolves to `digest` (#658).
///
/// NORA stores a tag and its digest as independent files, so deleting a manifest
/// by digest would otherwise leave the tag still serving it. Every tag is resolved
/// first, deleting nothing: a listing or a tag that cannot be read is the answer (Err),
/// so a delete never leaves a tag serving a manifest it removed. Each candidate tag
/// is then locked and re-read under the lock, and only deleted if it *still* hashes
/// to `digest`, so a concurrent re-tag is never clobbered.
async fn delete_tags_for_digest(
    state: &AppState,
    ns: Option<&str>,
    name: &str,
    digest: &str,
) -> crate::storage::Result<()> {
    use sha2::Digest as _;

    let resolves_to_digest =
        |data: &Bytes| format!("sha256:{}", hex::encode(sha2::Sha256::digest(data))) == digest;
    // Every tag resolved before anything is deleted: an unreadable one stops the delete here.
    for tag in tags_resolving_to(state, ns, name, digest).await? {
        let key = manifest_key(ns, name, &tag);
        // Serialize with put_manifest on this tag.
        let lock = state.publish_lock(&key);
        let _guard = lock.lock().await;
        // Re-read under the lock, as a read resolves the tag (a recorded push first); only delete if
        // it STILL resolves to `digest`.
        match resolve_manifest(state, ns, name, &tag, None).await? {
            Some((data, _)) if resolves_to_digest(&data) => {}
            _ => continue,
        }
        let _ = delete_manifest_and_meta(state, ns, name, &tag).await;
        tracing::info!(
            name = %name, tag = %tag, digest = %digest,
            "Docker tag removed because its manifest was deleted by digest (#658)"
        );
    }
    Ok(())
}

async fn delete_manifest(
    State(state): State<AppState>,
    Path((name, reference)): Path<(String, String)>,
) -> Response {
    let c = canonicalize(&name, &state.config.docker);
    if let Some(r) = c.denied_response() {
        return r;
    }
    let ns = c.namespace;
    let name = c.name;
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_docker_reference(&reference) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let key = manifest_key(ns.as_deref(), &name, &reference);

    // Serialize tag delete with put_manifest via publish_lock to prevent
    // concurrent put from updating the tag between our read and delete
    let lock = state.publish_lock(&key);
    let _guard = lock.lock().await;

    // If reference is a tag, also delete the digest-keyed copy — unless another tag of the
    // repository still answers with that digest: the copy is theirs too, and a client that
    // resolved the other tag pulls it by digest. `_refs_guard` is held to the end of the
    // handler, so a push of the same digest cannot land between the check and the delete.
    let is_tag = !reference.starts_with("sha256:");
    let _refs_guard = if is_tag {
        // The manifest the tag answers with, as a read resolves it (a recorded push first). A read
        // that fails is the answer: a delete that cannot tell what the tag answers with removes
        // nothing, as a pull of the tag answers 500 — never the tag without its manifest.
        match resolve_manifest(&state, ns.as_deref(), &name, &reference, None).await {
            Ok(Some((data, _))) => {
                use sha2::Digest;
                let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&data)));
                let refs_lock = state.publish_lock(&digest_refs_lock_key(&name, &digest));
                let guard = refs_lock.lock_owned().await;
                match tags_resolving_to(&state, ns.as_deref(), &name, &digest).await {
                    Ok(tags) if tags.iter().any(|t| *t != reference) => {
                        tracing::debug!(name = %name, reference = %reference, digest = %digest, "delete: the digest copy stays, another tag answers with it");
                    }
                    // Delete from both namespaced and legacy locations, then the metadata.
                    Ok(_) => {
                        let _ =
                            delete_manifest_and_meta(&state, ns.as_deref(), &name, &digest).await;
                    }
                    Err(e) => {
                        tracing::error!(error = %e, name = %name, reference = %reference, "delete: reading the other tags of the digest failed; nothing deleted");
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                }
                Some(guard)
            }
            Ok(None) => None,
            Err(e) => {
                tracing::error!(error = %e, name = %name, reference = %reference, "delete: reading what the tag answers with failed; nothing deleted");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    } else {
        // #658: deleting by digest must also drop the tags that resolve to it,
        // so the registry stops serving a tag whose manifest is now gone. A tag
        // that cannot be read stops the delete before anything is removed.
        if let Err(e) = delete_tags_for_digest(&state, ns.as_deref(), &name, &reference).await {
            tracing::error!(error = %e, name = %name, reference = %reference, "delete by digest: reading the tags failed; nothing deleted");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        None
    };

    // Delete manifest — try namespaced key first, then legacy fallback — then its metadata.
    match delete_manifest_and_meta(&state, ns.as_deref(), &name, &reference).await {
        Ok(()) => {
            state.audit.log(AuditEntry::new(
                "delete",
                "api",
                &format!("{}:{}", name, reference),
                "docker",
                "manifest",
            ));
            state.repo_index.invalidate("docker");
            tracing::info!(name = %name, reference = %reference, "Docker manifest deleted");
            StatusCode::ACCEPTED.into_response()
        }
        Err(crate::storage::StorageError::NotFound) => manifest_unknown_response(&name, &reference),
        Err(e) => {
            tracing::error!(error = %e, key = %key, name = %name, reference = %reference, "Failed to delete manifest");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn delete_blob(
    State(state): State<AppState>,
    Path((name, digest)): Path<(String, String)>,
) -> Response {
    let c = canonicalize(&name, &state.config.docker);
    if let Some(r) = c.denied_response() {
        return r;
    }
    let ns = c.namespace;
    let name = c.name;
    if let Err(e) = validate_docker_name(&name) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if let Err(e) = validate_digest(&digest) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let key = blob_key(ns.as_deref(), &name, &digest);
    let legacy_key = blob_key(None, &name, &digest);
    // Both copies go — the namespaced (proxied) one and the bare one a push writes — and the
    // answer is theirs together: deleted if either was there, unknown only if neither was.
    match delete_copies(&state.storage, &key, &legacy_key).await {
        Ok(()) => {
            state.audit.log(AuditEntry::new(
                "delete",
                "api",
                &format!("{}@{}", name, &digest[..19.min(digest.len())]),
                "docker",
                "blob",
            ));
            state.repo_index.invalidate("docker");
            tracing::info!(name = %name, digest = %digest, "Docker blob deleted");
            StatusCode::ACCEPTED.into_response()
        }
        Err(crate::storage::StorageError::NotFound) => blob_unknown_response(&digest),
        Err(e) => {
            tracing::error!(error = %e, key = %key, name = %name, digest = %digest, "Failed to delete blob");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// ============================================================================

/// Result of a successful streaming blob fetch from upstream (#580).
pub struct FetchedBlob {
    /// Path to temp file containing the complete blob data.
    pub path: std::path::PathBuf,
    /// SHA-256 hex digest computed incrementally during download (64 chars, lowercase).
    pub sha256: String,
    /// RAII guard — deletes temp file on drop unless disarmed.
    pub _guard: TempFileGuard,
}

/// An upstream blob whose response headers have arrived but whose body has not been
/// read: the point at which `download_blob` can answer the client, before the bytes
/// are on disk.
pub struct UpstreamBlob {
    response: reqwest::Response,
    /// Content-Length from upstream, None for a chunked response.
    pub content_length: Option<u64>,
    /// Where to ask for the rest if the body breaks off.
    source: BlobSource,
    cb_key: String,
    probe: ProbeToken,
    _download_gauge_guard: ProxyDownloadGuard,
}

/// Progress of an in-flight spool, published to the response followers reading it.
#[derive(Clone, Debug, Default)]
pub(crate) struct SpoolStatus {
    /// Bytes flushed to the spool file so far.
    pub written: u64,
    /// `Some` once the spool has finished: the upstream body is complete and verified
    /// (`Ok`) or the fetch failed and the file is being discarded (`Err`).
    pub done: Option<Result<(), String>>,
}

/// Temp file a spool writes into. Created by the caller so a follower can open its own
/// handle before the first byte lands and keep reading it after storage moves or the
/// guard deletes the path.
pub(crate) struct SpoolFile {
    path: std::path::PathBuf,
    file: tokio::fs::File,
    guard: TempFileGuard,
}

impl SpoolFile {
    pub(crate) async fn create(temp_dir: &std::path::Path) -> Result<Self, ProxyError> {
        let path = temp_dir.join(format!("proxy-{}", uuid::Uuid::new_v4()));
        let guard = TempFileGuard::new(path.clone());
        let file = tokio::fs::File::create(&path)
            .await
            .map_err(|e| ProxyError::Network(format!("temp file create: {}", e)))?;
        Ok(Self { path, file, guard })
    }

    /// A second, read-only handle on the spool file for a response to follow.
    pub(crate) async fn follower(&self) -> std::io::Result<tokio::fs::File> {
        tokio::fs::File::open(&self.path).await
    }
}

/// Read a spool file as it is being written, ending when the spool reports completion.
///
/// Bytes are released only up to what the spool has flushed, less a one-byte holdback
/// until it reports `done`: with a `Content-Length` body hyper stops reading once the
/// declared bytes are out, so the digest verdict has to gate the final byte, not EOF. A
/// failed spool surfaces as a read error, so the response aborts short instead of ending
/// cleanly. Progress is re-read after every short read, so bytes flushed between a read
/// and the next status check are never waited on.
///
/// `file` is positioned at byte `start` of the blob: a ranged response follows the
/// spool from there. A spool that reports nothing for `stall` fails the read.
fn spool_follower(
    file: tokio::fs::File,
    status: tokio::sync::watch::Receiver<SpoolStatus>,
    start: u64,
    stall: Duration,
) -> impl futures::Stream<Item = std::io::Result<Bytes>> + Send {
    const READ_BUF: usize = 256 * 1024;
    const HOLDBACK_BYTES: u64 = 1;
    // Flushed bytes are visible to a second handle at once; a run of empty reads below
    // the published count means the file is gone or truncated, not still in flight.
    const MAX_EMPTY_READS: u32 = 1_000;
    futures::stream::unfold(
        (file, status, start, 0u32),
        move |(mut file, mut status, mut offset, mut empty_reads)| async move {
            use tokio::io::AsyncReadExt;
            loop {
                let current = status.borrow_and_update().clone();
                let released = match &current.done {
                    Some(Ok(())) => current.written,
                    Some(Err(reason)) => {
                        let err =
                            std::io::Error::other(format!("upstream blob fetch failed: {reason}"));
                        return Some((Err(err), (file, status, offset, empty_reads)));
                    }
                    None => current.written.saturating_sub(HOLDBACK_BYTES),
                };
                if offset < released {
                    let want = usize::try_from(released - offset)
                        .unwrap_or(READ_BUF)
                        .min(READ_BUF);
                    let mut buf = vec![0u8; want];
                    match file.read(&mut buf).await {
                        Ok(0) => {
                            empty_reads += 1;
                            if empty_reads > MAX_EMPTY_READS {
                                let err = std::io::Error::other(format!(
                                    "spool published {} bytes but only {} were readable",
                                    current.written, offset
                                ));
                                return Some((Err(err), (file, status, offset, empty_reads)));
                            }
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                        Ok(n) => {
                            empty_reads = 0;
                            offset += n as u64;
                            buf.truncate(n);
                            return Some((
                                Ok(Bytes::from(buf)),
                                (file, status, offset, empty_reads),
                            ));
                        }
                        Err(e) => return Some((Err(e), (file, status, offset, empty_reads))),
                    }
                    continue;
                }
                if current.done.is_some() {
                    return None;
                }
                // CANCEL-SAFETY: `changed()` only borrows the receiver; a timeout drops the
                // wait and the stream ends with an error, the file handle goes with it.
                match tokio::time::timeout(stall, status.changed()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => {
                        let err = std::io::Error::other("upstream blob fetch abandoned");
                        return Some((Err(err), (file, status, offset, empty_reads)));
                    }
                    Err(_) => {
                        let err = std::io::Error::other(format!(
                            "upstream blob fill reported nothing for {stall:?}"
                        ));
                        return Some((Err(err), (file, status, offset, empty_reads)));
                    }
                }
            }
        },
    )
}

/// Answer a blob cache miss from the spool as it fills.
///
/// The last byte is withheld until the spool has verified the digest, so a poisoned
/// upstream can never complete a `Content-Length` body. A `Range` against a blob whose
/// length upstream declared is served 206 from that offset, or 416 past the end, the
/// way the cache-hit path does: a client resuming a broken pull (containerd sends
/// `bytes=N-`) gets the tail, not the blob again from byte zero, which it would have to
/// read and discard up to N. A ranged body is partial, so it has no whole-blob digest to
/// verify (as on the cache-hit path). Without a declared length, or for a range that
/// does not parse, the whole blob goes out as 200.
async fn spool_response(
    mut follower: tokio::fs::File,
    status: tokio::sync::watch::Receiver<SpoolStatus>,
    content_length: Option<u64>,
    digest: &str,
    headers: &axum::http::HeaderMap,
    stall: Duration,
) -> Response {
    use crate::registry::range::{parse_byte_range, ParsedRange};
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    // A declared zero length would let hyper complete the response from the headers
    // alone, before the digest verdict; an empty body goes chunked.
    let len = content_length.filter(|&len| len > 0);
    let range = match (
        len,
        headers.get(header::RANGE).and_then(|v| v.to_str().ok()),
    ) {
        (Some(len), Some(value)) => parse_byte_range(value, len),
        _ => ParsedRange::None,
    };
    let builder = Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
        .header("docker-content-digest", digest);
    let response = match (range, len) {
        (ParsedRange::Unsatisfiable, Some(len)) => builder
            .status(StatusCode::RANGE_NOT_SATISFIABLE)
            .header(header::CONTENT_RANGE, format!("bytes */{len}"))
            .body(Body::empty()),
        (ParsedRange::Satisfiable(start, end), Some(len)) => {
            debug_assert!(
                start <= end && end < len,
                "parse_byte_range clamps to the blob"
            );
            if let Err(e) = follower.seek(std::io::SeekFrom::Start(start)).await {
                tracing::error!(error = %e, "Failed to position proxy spool follower");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            let wanted = end - start + 1;
            let reader = tokio_util::io::StreamReader::new(Box::pin(spool_follower(
                follower, status, start, stall,
            )))
            .take(wanted);
            builder
                .status(StatusCode::PARTIAL_CONTENT)
                .header(header::ACCEPT_RANGES, "bytes")
                .header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{len}"))
                .header(header::CONTENT_LENGTH, wanted)
                .body(nora_registry::verified::open_world_stream_body(
                    tokio_util::io::ReaderStream::new(reader),
                ))
        }
        _ => {
            let reader = tokio_util::io::StreamReader::new(Box::pin(spool_follower(
                follower, status, 0, stall,
            )));
            let stream = blob_verifying_stream(
                Box::pin(reader),
                digest,
                format!("docker blob {digest} (fill)"),
            );
            let mut builder = builder.status(StatusCode::OK);
            if let Some(len) = len {
                builder = builder
                    .header(header::CONTENT_LENGTH, len)
                    .header(header::ACCEPT_RANGES, "bytes");
            }
            builder.body(nora_registry::verified::stream_body(stream))
        }
    };
    response.unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// What a request joining a running blob fill needs — the value a fill's leader publishes
/// through `blob_flights` (#1003): the spool file to open its own read handle on, the fill's
/// progress, and upstream's declared length for `Range`.
#[derive(Clone)]
pub(crate) struct SpoolShare {
    path: std::path::PathBuf,
    status: tokio::sync::watch::Receiver<SpoolStatus>,
    content_length: Option<u64>,
}

/// The leader's own part of a fill, never shared: what the spool task consumes and the
/// read handle the leader's response follows.
struct LeaderFill {
    blob: UpstreamBlob,
    spool: SpoolFile,
    follower: tokio::fs::File,
    progress: tokio::sync::watch::Sender<SpoolStatus>,
}

/// Why [`start_fill`] could not open a fill.
enum FillStartError {
    /// The local spool file could not be created or reopened.
    Spool,
    /// Upstream refused or failed before answering headers.
    Upstream(ProxyError),
}

/// Open a fill: the spool file and its first read handle, then the upstream request. The
/// spool exists before upstream answers, so once a circuit-breaker probe is taken the
/// only exits left are the ones the spool task records.
async fn start_fill(
    state: &AppState,
    upstream_url: &str,
    upstream_auth: Option<&str>,
    name: &str,
    digest: &str,
    temp_dir: &std::path::Path,
    failure: &mut Option<FillStartError>,
) -> Option<(SpoolShare, LeaderFill)> {
    let spool = match SpoolFile::create(temp_dir).await {
        Ok(spool) => spool,
        Err(e) => {
            tracing::error!(error = ?e, "Failed to create proxy spool file");
            *failure = Some(FillStartError::Spool);
            return None;
        }
    };
    let follower = match spool.follower().await {
        Ok(follower) => follower,
        Err(e) => {
            tracing::error!(error = %e, "Failed to open proxy spool file for streaming");
            *failure = Some(FillStartError::Spool);
            return None;
        }
    };
    match open_blob_from_upstream(
        &state.http_client,
        upstream_url,
        name,
        digest,
        &state.docker_auth,
        state.config.docker.proxy_timeout,
        upstream_auth,
        &state.circuit_breaker,
    )
    .await
    {
        Ok(blob) => {
            let (progress, status) = tokio::sync::watch::channel(SpoolStatus::default());
            let share = SpoolShare {
                path: spool.path.clone(),
                status,
                content_length: blob.content_length,
            };
            Some((
                share,
                LeaderFill {
                    blob,
                    spool,
                    follower,
                    progress,
                },
            ))
        }
        Err(e) => {
            *failure = Some(FillStartError::Upstream(e));
            None
        }
    }
}

/// Run a fill this request leads: start the detached spool task (it holds `lease`, so
/// requests arriving until the blob is stored join this fill) and answer from the spool.
async fn lead_fill(
    state: &AppState,
    share: SpoolShare,
    own: LeaderFill,
    lease: Option<crate::proxy_coalesce::Lease<SpoolShare>>,
    blob: &BlobTarget<'_>,
    headers: &axum::http::HeaderMap,
) -> Response {
    let (name, digest, upstream_url) = (blob.upstream_name, blob.digest, blob.upstream_url);
    state.metrics.record_download("docker");
    state.metrics.record_cache_miss("docker");
    state.activity.push(ActivityEntry::new(
        ActionType::ProxyFetch,
        format!("{}@{}", name, &digest[..19.min(digest.len())]),
        crate::registry_type::RegistryType::Docker,
        "PROXY",
    ));
    spawn_blob_spool(
        state.clone(),
        own.blob,
        own.spool,
        blob,
        own.progress,
        lease,
    );
    // Quarantine: the fill continues in the background and lands in the cache;
    // a held digest is answered 403 now (mirrors the manifest proxy path).
    if let Some(resp) = quarantine_proxy_fetch_gate(state, digest, upstream_url) {
        return resp;
    }
    // Answer as soon as upstream has answered: the body follows the spool file
    // as it grows, so a client that caps time-to-first-header (containerd ≥ 2.3
    // gives up after 30 s) is never left waiting for a multi-GB fill.
    spool_response(
        own.follower,
        share.status,
        share.content_length,
        digest,
        headers,
        fill_stall_ceiling(state.config.docker.read_timeout),
    )
    .await
}

/// Follow a fill another request leads, from the joiner's own read handle on the spool.
/// `None` when the fill can no longer be joined — it failed, or it finished and its spool
/// has already moved into storage — so the caller looks in storage or leads a new fill.
async fn join_fill(
    state: &AppState,
    share: SpoolShare,
    digest: &str,
    upstream_url: &str,
    headers: &axum::http::HeaderMap,
) -> Option<Response> {
    if matches!(share.status.borrow().done, Some(Err(_))) {
        return None;
    }
    // An open handle survives the spool's later rename into storage or its removal.
    let follower = tokio::fs::File::open(&share.path).await.ok()?;
    state.metrics.record_download("docker");
    if let Some(resp) = quarantine_proxy_fetch_gate(state, digest, upstream_url) {
        return Some(resp);
    }
    Some(
        spool_response(
            follower,
            share.status,
            share.content_length,
            digest,
            headers,
            fill_stall_ceiling(state.config.docker.read_timeout),
        )
        .await,
    )
}

/// The blob a request asked for, as its own request resolved it: the canonical name and
/// storage keys, and the upstream (with the name it goes by there) it is fetched from.
struct BlobTarget<'a> {
    name: &'a str,
    upstream_name: &'a str,
    digest: &'a str,
    key: &'a str,
    legacy_key: &'a str,
    upstream_url: &'a str,
}

/// Serve a follower of a running fill: join it, or — when the fill is gone because its
/// spool already moved into storage — serve the stored blob. `None` only when the fill
/// failed and nothing is stored, so the caller leads a new fill.
async fn follow_fill(
    state: &AppState,
    share: SpoolShare,
    blob: &BlobTarget<'_>,
    headers: &axum::http::HeaderMap,
) -> Option<Response> {
    if let Some(response) = join_fill(state, share, blob.digest, blob.upstream_url, headers).await {
        return Some(response);
    }
    serve_local_blob(
        state,
        headers,
        blob.name,
        blob.digest,
        blob.key,
        blob.legacy_key,
    )
    .await
}

/// Longest a response may wait on a fill that reports nothing: past the fill's own worst
/// case — a stalled chunk (`read_timeout`) on every resume attempt, plus their back-off —
/// with a margin. The fill always ends in bytes or a verdict before that; the ceiling only
/// guards against a fill that never reports at all.
fn fill_stall_ceiling(read_timeout: u64) -> Duration {
    let backoff: Duration = (1..=UPSTREAM_RESUME_ATTEMPTS)
        .map(|attempt| UPSTREAM_RESUME_BACKOFF * attempt)
        .sum();
    Duration::from_secs(read_timeout * (u64::from(UPSTREAM_RESUME_ATTEMPTS) + 1))
        + backoff
        + Duration::from_secs(30)
}

/// Spool an upstream blob to disk and store it, detached from the request that started
/// it: a client that gives up mid-fill (containerd retries a slow pull from scratch) no
/// longer discards the bytes already fetched, and the next request is a cache hit.
///
/// A panic inside the fill is caught like the other detached tasks (`spawn_cache`, the
/// PyPI backfill): it is logged, counted, and published to the follower as a failed
/// spool, so the response aborts instead of hanging on a dropped sender.
fn spawn_blob_spool(
    state: AppState,
    blob: UpstreamBlob,
    spool: SpoolFile,
    target: &BlobTarget<'_>,
    progress: tokio::sync::watch::Sender<SpoolStatus>,
    lease: Option<crate::proxy_coalesce::Lease<SpoolShare>>,
) {
    use futures::FutureExt as _;
    use std::panic::AssertUnwindSafe;

    let (key, digest, upstream) = (
        target.key.to_string(),
        target.digest.to_string(),
        target.upstream_url.to_string(),
    );

    let read_timeout = state.config.docker.read_timeout;
    let progress = Arc::new(progress);
    let on_panic = Arc::clone(&progress);
    let panic_key = key.clone();
    let task = async move {
        let outcome = spool_upstream_blob(
            blob,
            spool,
            read_timeout,
            &state.circuit_breaker,
            Some(progress.as_ref()),
        )
        .await;
        let mut fetched = match outcome {
            Ok(fetched) => fetched,
            Err(e) => {
                tracing::warn!(error = ?e, key = %key, "Docker blob proxy fetch failed mid-stream");
                // Release the flight before announcing the failure, so a request that sees
                // it can only start a fresh fill, never join this dead one.
                drop(lease);
                progress.send_modify(|s| s.done = Some(Err(format!("{e:?}"))));
                return;
            }
        };
        let expected_hash = digest.strip_prefix("sha256:").unwrap_or(&digest);
        if fetched.sha256 != expected_hash {
            tracing::warn!(
                digest = %digest,
                expected = %expected_hash,
                actual = %fetched.sha256,
                "Docker blob SHA-256 mismatch from upstream — not cached"
            );
            // TempFileGuard drops and cleans up; the follower's own handle still reads
            // to the end, and the verifying stream fails the response before its last frame.
            drop(lease);
            progress.send_modify(|s| s.done = Some(Err("SHA-256 mismatch".to_string())));
            return;
        }
        // The digest is the verdict the response is waiting on; release the last byte
        // now rather than after the storage upload, which can take as long again.
        progress.send_modify(|s| s.done = Some(Ok(())));
        quarantine_record_verified(&state, &digest, &upstream);
        let sha_for_pin = fetched.sha256.clone();
        match state
            .storage
            .put_from_path(&key, &fetched.path, Some(&sha_for_pin))
            .await
        {
            Ok(()) => {
                fetched._guard.disarm();
                state.repo_index.invalidate("docker");
            }
            Err(e) => {
                crate::metrics::CACHE_WRITE_ERRORS
                    .with_label_values(&["docker", "proxy_blob_store"])
                    .inc();
                tracing::error!(
                    error = %e,
                    key = %key,
                    "Failed to store proxied blob — the response still completes from the spool"
                );
            }
        }
        // Held until the blob is in storage (an S3 upload can take as long as the fill),
        // so a request arriving in between still joins instead of refetching.
        drop(lease);
    };
    tokio::spawn(AssertUnwindSafe(task).catch_unwind().map(move |done| {
        if let Err(panic) = done {
            crate::metrics::CACHE_WRITE_ERRORS
                .with_label_values(&["docker", "proxy_blob_spool_panic"])
                .inc();
            tracing::error!(panic = ?panic, key = %panic_key, "Docker blob spool task panicked");
            on_panic.send_modify(|s| {
                if s.done.is_none() {
                    s.done = Some(Err("spool task panicked".to_string()));
                }
            });
        }
    }));
}

/// How to ask upstream for a blob again: kept with an opened blob so a spool that loses
/// the connection mid-body can request the missing tail instead of failing the fill.
struct BlobSource {
    client: reqwest::Client,
    upstream_url: String,
    name: String,
    url: String,
    docker_auth: DockerAuth,
    basic_auth: Option<String>,
    /// Seconds to wait for the response headers of each request.
    timeout: u64,
}

/// Why a blob request produced no response.
enum BlobRequestError {
    /// Connection, TLS or header timeout: counts against the upstream's breaker.
    Network(String),
    /// Upstream answered 401 and no token came of it: refused, or the token server failed.
    Token(TokenError),
}

impl BlobSource {
    /// The error for a blob request: a token failure is logged and told apart (#1196).
    fn proxy_error(&self, e: BlobRequestError) -> ProxyError {
        match e {
            BlobRequestError::Network(reason) => ProxyError::Network(reason),
            BlobRequestError::Token(e) => token_error(
                e,
                &self.upstream_url,
                &self.name,
                self.basic_auth.as_deref(),
            ),
        }
    }
}

/// Why a blob fill stopped, split the way the circuit breaker needs it.
enum FillFailure {
    /// The upstream failed us: connection, stalled or short body, 5xx, bad range.
    Unavailable(ProxyError),
    /// The upstream answered but refused (4xx, no token): alive, not down.
    Refused(ProxyError),
}

impl FillFailure {
    fn as_proxy_error(&self) -> &ProxyError {
        match self {
            FillFailure::Unavailable(e) | FillFailure::Refused(e) => e,
        }
    }

    fn into_proxy_error(self) -> ProxyError {
        match self {
            FillFailure::Unavailable(e) | FillFailure::Refused(e) => e,
        }
    }
}

impl BlobSource {
    /// One blob GET, answering a 401 challenge with a bearer token. `range_from` asks for
    /// the tail from that byte and reuses the cached bearer token that opened the blob.
    async fn send(&self, range_from: Option<u64>) -> Result<reqwest::Response, BlobRequestError> {
        let cached_bearer = match range_from {
            Some(_) => self
                .docker_auth
                .get_token(
                    &self.upstream_url,
                    &self.name,
                    None,
                    self.basic_auth.as_deref(),
                )
                .await
                .ok()
                .map(|token| format!("Bearer {token}")),
            None => None,
        };
        let first_auth =
            cached_bearer.or_else(|| self.basic_auth.as_deref().map(basic_auth_header));
        let response = self.send_once(first_auth, range_from).await?;
        if response.status() != reqwest::StatusCode::UNAUTHORIZED {
            return Ok(response);
        }
        let www_auth = response
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let token = self
            .docker_auth
            .get_token(
                &self.upstream_url,
                &self.name,
                www_auth.as_deref(),
                self.basic_auth.as_deref(),
            )
            .await
            .map_err(BlobRequestError::Token)?;
        self.send_once(Some(format!("Bearer {token}")), range_from)
            .await
    }

    /// `timeout` bounds the wait for the response headers only. The body of a multi-GB
    /// layer is paced by the spool's per-chunk `read_timeout`: reqwest's
    /// `RequestBuilder::timeout` is a total deadline that would cut the body instead.
    async fn send_once(
        &self,
        authorization: Option<String>,
        range_from: Option<u64>,
    ) -> Result<reqwest::Response, BlobRequestError> {
        let mut request = self.client.get(&self.url);
        if let Some(value) = authorization {
            request = request.header(reqwest::header::AUTHORIZATION, value);
        }
        if let Some(from) = range_from {
            request = request.header(reqwest::header::RANGE, format!("bytes={from}-"));
        }
        // CANCEL-SAFETY: `send` resolves once the response headers are in; dropping it on
        // timeout drops the connection attempt before any body byte reaches the spool.
        match tokio::time::timeout(Duration::from_secs(self.timeout), request.send()).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(e)) => Err(BlobRequestError::Network(e.to_string())),
            Err(_) => Err(BlobRequestError::Network(format!(
                "no response headers within {}s",
                self.timeout
            ))),
        }
    }

    /// Ask for the rest of a blob from byte `offset`. Returns the response and how many
    /// leading body bytes to drop: none for a 206 that starts at `offset`, `offset` for an
    /// upstream that ignores `Range` and sends the whole blob again with 200.
    async fn resume(
        &self,
        offset: u64,
        total: Option<u64>,
    ) -> Result<(reqwest::Response, u64), FillFailure> {
        let response = match self.send(Some(offset)).await {
            Ok(response) => response,
            Err(BlobRequestError::Network(reason)) => {
                return Err(FillFailure::Unavailable(ProxyError::Network(reason)))
            }
            Err(e @ BlobRequestError::Token(_)) => {
                return Err(FillFailure::Refused(self.proxy_error(e)))
            }
        };
        match response.status() {
            reqwest::StatusCode::PARTIAL_CONTENT => {
                let range = response
                    .headers()
                    .get(reqwest::header::CONTENT_RANGE)
                    .and_then(|v| v.to_str().ok())
                    .and_then(parse_content_range);
                match range {
                    Some((start, size))
                        if start == offset && (total.is_none() || size == total) =>
                    {
                        Ok((response, 0))
                    }
                    other => Err(FillFailure::Unavailable(ProxyError::Network(format!(
                        "resume from byte {offset}: upstream answered range {other:?}"
                    )))),
                }
            }
            reqwest::StatusCode::OK => match (total, response.content_length()) {
                (Some(want), Some(got)) if want != got => {
                    Err(FillFailure::Unavailable(ProxyError::Network(format!(
                        "resume from byte {offset}: upstream now sends {got} bytes, not {want}"
                    ))))
                }
                _ => Ok((response, offset)),
            },
            // 4xx: upstream is alive and answered (a rejected token, say), as on open (#606)
            status if status.is_client_error() => {
                Err(FillFailure::Refused(ProxyError::Upstream(status.as_u16())))
            }
            status => Err(FillFailure::Unavailable(ProxyError::Upstream(
                status.as_u16(),
            ))),
        }
    }
}

/// `Content-Range: bytes <start>-<end>/<size>` → `(start, size)`; `size` is `None` for `*`.
fn parse_content_range(value: &str) -> Option<(u64, Option<u64>)> {
    let (span, size) = value.strip_prefix("bytes ")?.split_once('/')?;
    let (start, end) = span.split_once('-')?;
    let start: u64 = start.trim().parse().ok()?;
    let end: u64 = end.trim().parse().ok()?;
    if end < start {
        return None;
    }
    let size = match size.trim() {
        "*" => None,
        n => {
            let size: u64 = n.parse().ok()?;
            if end >= size {
                return None;
            }
            Some(size)
        }
    };
    Some((start, size))
}

/// Open a blob on an upstream Docker registry: request, token auth and status check,
/// stopping once the response headers are in. The body is read by
/// [`spool_upstream_blob`].
///
/// `timeout` bounds the wait for the response headers; the body itself is paced by the
/// per-chunk `read_timeout` of the spool, which also resumes a cut body.
#[allow(clippy::too_many_arguments)]
pub async fn open_blob_from_upstream(
    client: &reqwest::Client,
    upstream_url: &str,
    name: &str,
    digest: &str,
    docker_auth: &DockerAuth,
    timeout: u64,
    basic_auth: Option<&str>,
    cb: &CircuitBreakerRegistry,
) -> Result<UpstreamBlob, ProxyError> {
    use crate::metrics::PROXY_ACTIVE_DOWNLOADS;

    // Track active concurrent proxy downloads. ProxyDownloadGuard decrements
    // on drop (success, error, or cancellation — all paths).
    PROXY_ACTIVE_DOWNLOADS.inc();
    let _download_gauge_guard = ProxyDownloadGuard;

    tracing::info!(
        blob.name = %name,
        blob.digest = %digest,
        upstream = %upstream_url,
        "Proxy blob download started"
    );

    let cb_key = upstream_key(
        crate::registry_type::RegistryType::Docker.as_str(),
        upstream_url,
    );
    let probe = cb.check(&cb_key)?;

    let source = BlobSource {
        client: client.clone(),
        upstream_url: upstream_url.to_string(),
        name: name.to_string(),
        url: format!(
            "{}/v2/{}/blobs/{}",
            upstream_url.trim_end_matches('/'),
            name,
            digest
        ),
        docker_auth: docker_auth.clone(),
        basic_auth: basic_auth.map(String::from),
        timeout,
    };
    let response = match source.send(None).await {
        Ok(response) => response,
        Err(BlobRequestError::Network(reason)) => {
            cb.record_failure(&cb_key, probe);
            return Err(ProxyError::Network(reason));
        }
        // The registry answered (401) and the token server gave no token: an auth
        // issue, not the registry down — alive, as on resume (`FillFailure::Refused`).
        Err(e @ BlobRequestError::Token(_)) => {
            cb.record_alive(&cb_key, probe);
            return Err(source.proxy_error(e));
        }
    };

    if !response.status().is_success() {
        let status = response.status().as_u16();
        if (400..500).contains(&status) {
            // 4xx — upstream is alive and answered (e.g. blob not found); not an
            // availability failure, so recover the breaker instead of counting
            // it against the upstream (#606).
            cb.record_alive(&cb_key, probe);
        } else {
            cb.record_failure(&cb_key, probe);
        }
        return Err(ProxyError::Upstream(status));
    }

    Ok(UpstreamBlob {
        content_length: response.content_length(),
        response,
        source,
        cb_key,
        probe,
        _download_gauge_guard,
    })
}

/// Resume attempts a spool makes in a row, without receiving a byte, before it fails.
const UPSTREAM_RESUME_ATTEMPTS: u32 = 5;
/// Pause before resume attempt `n` is `n` times this.
const UPSTREAM_RESUME_BACKOFF: Duration = Duration::from_millis(500);

/// A spool write failed on the local disk. The upstream answered and was sending the
/// body, so the probe goes back as alive: counting our disk against the upstream would
/// open its breaker, and dropping the probe would hold the half-open slot (#585).
fn spool_write_failed(
    cb: &CircuitBreakerRegistry,
    cb_key: &str,
    probe: ProbeToken,
    op: &str,
    e: std::io::Error,
) -> ProxyError {
    cb.record_alive(cb_key, probe);
    ProxyError::Network(format!("temp file {op}: {e}"))
}

/// Stream an opened upstream blob to its spool file with a per-chunk `read_timeout` and
/// incremental SHA-256. Never accumulates the blob in RAM. Each chunk is flushed before
/// `progress` advances, so a follower never reads past what is on disk.
///
/// A body that breaks off (connection reset, stalled chunk, short body) is resumed with
/// `Range: bytes=<written>-`, up to [`UPSTREAM_RESUME_ATTEMPTS`] times in a row without
/// progress; the digest is still computed over every byte in order.
pub(crate) async fn spool_upstream_blob(
    blob: UpstreamBlob,
    spool: SpoolFile,
    read_timeout: u64,
    cb: &CircuitBreakerRegistry,
    progress: Option<&tokio::sync::watch::Sender<SpoolStatus>>,
) -> Result<FetchedBlob, ProxyError> {
    use crate::metrics::PROXY_DOWNLOAD_BYTES;
    use sha2::Digest;
    use tokio::io::AsyncWriteExt;

    let UpstreamBlob {
        mut response,
        content_length,
        source,
        cb_key,
        probe,
        _download_gauge_guard,
    } = blob;
    let SpoolFile {
        path: temp_path,
        mut file,
        guard,
    } = spool;
    let mut hasher = sha2::Sha256::new();
    let chunk_timeout = Duration::from_secs(read_timeout);
    let mut bytes_written: u64 = 0;
    // Leading bytes of the current response that are already on disk (a resume that
    // upstream answered with the whole blob).
    let mut skip: u64 = 0;
    let mut stalls: u32 = 0;
    'fill: loop {
        let mut stream = response.bytes_stream();
        let failure = loop {
            // CANCEL-SAFETY: timeout wraps a single stream.next() call. On timeout the
            // spool resumes or fails, and TempFileGuard deletes the partial file.
            match tokio::time::timeout(chunk_timeout, stream.next()).await {
                Ok(Some(Ok(mut chunk))) => {
                    if skip > 0 {
                        let dropped = usize::try_from(skip).unwrap_or(usize::MAX).min(chunk.len());
                        chunk = chunk.slice(dropped..);
                        skip -= dropped as u64;
                        if chunk.is_empty() {
                            continue;
                        }
                    }
                    stalls = 0;
                    hasher.update(&chunk);
                    if let Err(e) = file.write_all(&chunk).await {
                        return Err(spool_write_failed(cb, &cb_key, probe, "write", e));
                    }
                    bytes_written += chunk.len() as u64;
                    if let Some(progress) = progress {
                        if let Err(e) = file.flush().await {
                            return Err(spool_write_failed(cb, &cb_key, probe, "flush", e));
                        }
                        progress.send_modify(|s| s.written = bytes_written);
                    }
                }
                Ok(Some(Err(e))) => {
                    break ProxyError::Network(format!("chunk read error: {}", e));
                }
                Ok(None) => {
                    let short = skip > 0 || content_length.is_some_and(|len| bytes_written < len);
                    if !short {
                        break 'fill;
                    }
                    break ProxyError::Network(format!(
                        "upstream body ended at byte {} of {:?}",
                        bytes_written, content_length
                    ));
                }
                Err(_) => {
                    break ProxyError::Network(format!(
                        "read timeout ({}s per chunk)",
                        read_timeout
                    ));
                }
            }
        };
        let mut last = FillFailure::Unavailable(failure);
        (response, skip) = loop {
            stalls += 1;
            if stalls > UPSTREAM_RESUME_ATTEMPTS {
                match last {
                    FillFailure::Unavailable(_) => cb.record_failure(&cb_key, probe),
                    FillFailure::Refused(_) => cb.record_alive(&cb_key, probe),
                }
                return Err(last.into_proxy_error());
            }
            tracing::warn!(
                error = ?last.as_proxy_error(),
                offset = bytes_written,
                attempt = stalls,
                upstream = %source.upstream_url,
                "Proxy blob body interrupted, resuming from upstream"
            );
            tokio::time::sleep(UPSTREAM_RESUME_BACKOFF * stalls).await;
            match source.resume(bytes_written, content_length).await {
                Ok(next) => break next,
                Err(e) => last = e,
            }
        };
    }
    debug_assert_eq!(skip, 0, "a finished fill has no bytes left to skip");
    if let Err(e) = file.flush().await {
        return Err(spool_write_failed(cb, &cb_key, probe, "flush", e));
    }
    drop(file);
    let sha256 = hex::encode(sha2::Digest::finalize(hasher));
    cb.record_success(&cb_key, probe);
    PROXY_DOWNLOAD_BYTES.inc_by(bytes_written);
    tracing::info!(
        bytes = bytes_written,
        content_length = ?content_length,
        "Proxy blob download complete"
    );
    Ok(FetchedBlob {
        path: temp_path,
        sha256,
        _guard: guard,
    })
}

/// Fetch a blob from an upstream Docker registry into a temp file (#580): open it,
/// spool it, return once the complete, hashed blob is on disk. Callers that want to
/// serve while the spool is still running use [`open_blob_from_upstream`] and
/// [`spool_upstream_blob`] separately.
#[allow(clippy::too_many_arguments)]
pub async fn fetch_blob_from_upstream(
    client: &reqwest::Client,
    upstream_url: &str,
    name: &str,
    digest: &str,
    docker_auth: &DockerAuth,
    timeout: u64,
    read_timeout: u64,
    basic_auth: Option<&str>,
    cb: &CircuitBreakerRegistry,
    temp_dir: &std::path::Path,
) -> Result<FetchedBlob, ProxyError> {
    // The spool first, as in `start_fill`: once `open_blob_from_upstream` takes a
    // circuit-breaker probe, the only exits left are the ones the spool records.
    let spool = SpoolFile::create(temp_dir).await?;
    let blob = open_blob_from_upstream(
        client,
        upstream_url,
        name,
        digest,
        docker_auth,
        timeout,
        basic_auth,
        cb,
    )
    .await?;
    spool_upstream_blob(blob, spool, read_timeout, cb, None).await
}

/// The error for a 401 that got no token. A refusal is logged with the upstream: its cause is
/// the credential configured for that upstream, not an outage (#1196).
fn token_error(
    e: TokenError,
    upstream_url: &str,
    name: &str,
    basic_auth: Option<&str>,
) -> ProxyError {
    match e {
        TokenError::Refused if basic_auth.is_some() => {
            tracing::warn!(upstream = %upstream_url, name, "upstream refused NORA's credentials");
            ProxyError::CredentialsRefused
        }
        TokenError::Refused => {
            tracing::warn!(
                upstream = %upstream_url,
                name,
                "upstream requires credentials and none are configured for it"
            );
            ProxyError::CredentialsRefused
        }
        TokenError::Unavailable => {
            tracing::error!(upstream = %upstream_url, name, "Failed to acquire token");
            ProxyError::Network("token fetch failed".into())
        }
    }
}

/// Fetch a manifest from an upstream Docker registry
/// Returns (manifest_bytes, content_type)
#[allow(clippy::too_many_arguments)]
pub async fn fetch_manifest_from_upstream(
    client: &reqwest::Client,
    upstream_url: &str,
    name: &str,
    reference: &str,
    docker_auth: &DockerAuth,
    timeout: u64,
    basic_auth: Option<&str>,
    cb: &CircuitBreakerRegistry,
) -> Result<(Vec<u8>, String), ProxyError> {
    let cb_key = upstream_key(
        crate::registry_type::RegistryType::Docker.as_str(),
        upstream_url,
    );
    let probe = cb.check(&cb_key)?;

    let url = format!(
        "{}/v2/{}/manifests/{}",
        upstream_url.trim_end_matches('/'),
        name,
        reference
    );

    tracing::debug!(url = %url, "Fetching manifest from upstream");

    // Request with Accept header for manifest types
    let accept_header = "application/vnd.docker.distribution.manifest.v2+json, \
                         application/vnd.docker.distribution.manifest.list.v2+json, \
                         application/vnd.oci.image.manifest.v1+json, \
                         application/vnd.oci.image.index.v1+json";

    // First try — with basic auth if configured
    let mut request = client
        .get(&url)
        .timeout(Duration::from_secs(timeout))
        .header("Accept", accept_header);
    if let Some(credentials) = basic_auth {
        request = request.header("Authorization", basic_auth_header(credentials));
    }
    let response = request.send().await.map_err(|e| {
        tracing::error!(error = %e, url = %url, "Failed to send request to upstream");
        cb.record_failure(&cb_key, probe);
        ProxyError::Network(e.to_string())
    })?;

    tracing::debug!(status = %response.status(), "Initial upstream response");

    let response = if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        // Get Www-Authenticate header and fetch token
        let www_auth = response
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        tracing::debug!(www_auth = ?www_auth, "Got 401, fetching token");

        match docker_auth
            .get_token(upstream_url, name, www_auth.as_deref(), basic_auth)
            .await
        {
            Ok(token) => {
                tracing::debug!("Token acquired, retrying with auth");
                client
                    .get(&url)
                    .timeout(Duration::from_secs(timeout))
                    .header("Accept", accept_header)
                    .header("Authorization", format!("Bearer {}", token))
                    .send()
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "Failed to send authenticated request");
                        cb.record_failure(&cb_key, probe);
                        ProxyError::Network(e.to_string())
                    })?
            }
            // The registry answered (401) and gave no token: an auth issue, not the
            // registry down — alive, so the probe is returned.
            Err(e) => {
                cb.record_alive(&cb_key, probe);
                return Err(token_error(e, upstream_url, name, basic_auth));
            }
        }
    } else {
        response
    };

    tracing::debug!(status = %response.status(), "Final upstream response");

    if !response.status().is_success() {
        let status = response.status().as_u16();
        tracing::warn!(status = %response.status(), "Upstream returned non-success status");
        if status == 429 {
            // Docker Hub pull-rate limit: back off, and tell the client so (C55)
            // instead of letting it read as a missing manifest.
            cb.record_failure(&cb_key, probe);
            return Err(crate::registry::upstream_4xx(status, response.headers()));
        }
        if (400..500).contains(&status) {
            // 4xx — upstream is alive and answered (e.g. manifest not found);
            // recover the breaker rather than counting it as a failure (#606).
            cb.record_alive(&cb_key, probe);
        } else {
            cb.record_failure(&cb_key, probe);
        }
        return Err(ProxyError::Upstream(status));
    }

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/vnd.docker.distribution.manifest.v2+json")
        .to_string();

    // Read under the cap a pushed manifest has: an upstream cannot make NORA buffer more.
    let mut response = response;
    let mut bytes = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) if bytes.len() + chunk.len() > MAX_MANIFEST_BYTES => {
                tracing::warn!(url = %url, cap = MAX_MANIFEST_BYTES, "Upstream manifest exceeds the size cap; not served");
                // The registry answered: alive, though this answer is unusable.
                cb.record_alive(&cb_key, probe);
                return Err(ProxyError::Upstream(502));
            }
            Ok(Some(chunk)) => bytes.extend_from_slice(&chunk),
            Ok(None) => break,
            Err(e) => {
                cb.record_failure(&cb_key, probe);
                return Err(ProxyError::Network(e.to_string()));
            }
        }
    }
    // Only a manifest media type is passed on; anything else is read off the manifest.
    let essence = content_type.split(';').next().unwrap_or_default().trim();
    let content_type = if MANIFEST_MEDIA_TYPES
        .iter()
        .any(|t| essence.eq_ignore_ascii_case(t))
    {
        content_type
    } else {
        detect_manifest_media_type(&bytes)
    };

    cb.record_success(&cb_key, probe);
    Ok((bytes, content_type))
}

/// The media types a manifest is served with.
const MANIFEST_MEDIA_TYPES: [&str; 6] = [
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v1+prettyjws",
];

/// Why an upstream's 200 body is not a manifest, or `None` when it is one: a JSON object with
/// a numeric `schemaVersion` (1 for the schema an old registry may still hold, 2 otherwise).
fn upstream_manifest_invalid(body: &[u8]) -> Option<&'static str> {
    match serde_json::from_slice::<Value>(body) {
        Ok(Value::Object(m)) if m.get("schemaVersion").is_some_and(Value::is_u64) => None,
        Ok(Value::Object(_)) => Some("no schemaVersion"),
        _ => Some("not a JSON object"),
    }
}

/// Detect manifest media type from its JSON content
/// Build a standard Docker manifest response with Content-Type and Docker-Content-Digest headers.
fn manifest_response(data: impl Into<Bytes>, content_type: String, digest: String) -> Response {
    let body: Bytes = data.into();
    let content_length = body.len().to_string();
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (HeaderName::from_static("docker-content-digest"), digest),
            (header::CONTENT_LENGTH, content_length),
        ],
        body,
    )
        .into_response()
}

/// Extract publish date from Docker manifest `.meta.json` sidecar.
///
/// Docker metadata sidecar stores `push_timestamp` (Unix seconds) when the
/// manifest was first pushed or cached. This is a NORA-side timestamp (not an
/// upstream-supplied date), so it is unaffected by `server.trust_upstream_dates`
/// (#513) — there is no spoofable upstream date on this path.
async fn extract_docker_publish_date(
    storage: &Storage,
    name: &str,
    reference: &str,
    upstreams_empty: bool,
    ns: Option<&str>,
    bare: &mut BareMeta,
) -> Option<i64> {
    // The .meta.json sidecar (has push_timestamp) — namespaced, then legacy. The legacy (bare) one is
    // read only when no namespaced one exists, and not again when the request already holds it. (A
    // tag a push answers is dated by its record before this is asked: see `get_manifest`.)
    let meta = manifest_meta_key(ns, name, reference);
    let legacy_meta = manifest_meta_key(None, name, reference);
    let namespaced = if meta != legacy_meta {
        Some(storage.get(&meta).await)
    } else {
        None
    };
    let read = match namespaced {
        Some(Ok(data)) => Some(data),
        Some(Err(crate::storage::StorageError::NotFound)) | None => {
            if let BareMeta::Unread = bare {
                *bare = BareMeta::Read(read_bare_meta(storage, name, reference).await);
            }
            match bare {
                BareMeta::Read(Ok(Some(data))) => Some(data.clone()),
                _ => None,
            }
        }
        Some(Err(_)) => None,
    };
    if let Some(data) = read {
        if let Ok(meta) = serde_json::from_slice::<ImageMetadata>(&data) {
            if meta.push_timestamp > 0 {
                return Some(meta.push_timestamp as i64);
            }
        }
    }

    // mtime fallback — only for hosted mode (no upstreams configured)
    if upstreams_empty {
        let key = manifest_key(ns, name, reference);
        let legacy = manifest_key(None, name, reference);
        // Try namespaced first, then legacy
        if let Some(date) = crate::curation::extract_mtime_as_publish_date(storage, &key).await {
            return Some(date);
        }
        if key != legacy {
            return crate::curation::extract_mtime_as_publish_date(storage, &legacy).await;
        }
    }

    None
}

/// Extract metadata from a Docker manifest
/// Handles both single-arch manifests and multi-arch indexes
async fn extract_metadata(manifest: &[u8], storage: &Storage, name: &str) -> ImageMetadata {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut metadata = ImageMetadata {
        push_timestamp: now,
        last_pulled: 0,
        downloads: 0,
        ..Default::default()
    };

    let Ok(json) = serde_json::from_slice::<Value>(manifest) else {
        return metadata;
    };

    // Check if this is a manifest list/index (multi-arch)
    if json.get("manifests").is_some() {
        // For multi-arch, extract info from the first platform manifest
        if let Some(manifests) = json.get("manifests").and_then(|m| m.as_array()) {
            // Sum sizes from all platform manifests
            let total_size: u64 = manifests
                .iter()
                .filter_map(|m| m.get("size").and_then(|s| s.as_u64()))
                .sum();
            metadata.size_bytes = total_size;

            // Get OS/arch from first platform (usually linux/amd64)
            if let Some(first) = manifests.first() {
                if let Some(platform) = first.get("platform") {
                    metadata.os = platform
                        .get("os")
                        .and_then(|v| v.as_str())
                        .unwrap_or("multi-arch")
                        .to_string();
                    metadata.arch = platform
                        .get("architecture")
                        .and_then(|v| v.as_str())
                        .unwrap_or("multi")
                        .to_string();
                    metadata.variant = platform
                        .get("variant")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                }
            }
        }
        return metadata;
    }

    // Single-arch manifest - extract layers
    if let Some(layers) = json.get("layers").and_then(|l| l.as_array()) {
        let mut total_size: u64 = 0;
        for layer in layers {
            let digest = layer
                .get("digest")
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .to_string();
            let size = layer.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
            total_size += size;
            metadata.layers.push(LayerInfo { digest, size });
        }
        metadata.size_bytes = total_size;
    }

    // Try to get OS/arch from config blob
    if let Some(config) = json.get("config") {
        if let Some(config_digest) = config.get("digest").and_then(|d| d.as_str()) {
            let (os, arch, variant) = get_config_info(storage, name, config_digest).await;
            metadata.os = os;
            metadata.arch = arch;
            metadata.variant = variant;
        }
    }

    // If we couldn't get OS/arch, set defaults
    if metadata.os.is_empty() {
        metadata.os = "unknown".to_string();
    }
    if metadata.arch.is_empty() {
        metadata.arch = "unknown".to_string();
    }

    metadata
}

/// Get OS/arch information from a config blob
async fn get_config_info(
    storage: &Storage,
    name: &str,
    config_digest: &str,
) -> (String, String, Option<String>) {
    let key = format!("docker/{}/blobs/{}", name, config_digest);

    let Ok(data) = storage.get(&key).await else {
        return ("unknown".to_string(), "unknown".to_string(), None);
    };

    let Ok(config) = serde_json::from_slice::<Value>(&data) else {
        return ("unknown".to_string(), "unknown".to_string(), None);
    };

    let os = config
        .get("os")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let arch = config
        .get("architecture")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let variant = config
        .get("variant")
        .and_then(|v| v.as_str())
        .map(String::from);

    (os, arch, variant)
}

/// How often the background task folds accumulated pull counts into the
/// sidecars (#1114). Soft state: a crash loses at most this much (accepted).
pub(crate) const PULL_STATS_FLUSH_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(45);

/// Fold accumulated pull counts into their `.stats.json` sidecars every
/// `interval`, and once more on shutdown, so a hard crash loses at most one
/// interval of counts. Extracted from `main` (with the interval injected) so a
/// test can drive the tick path (not only the shutdown path): the loss bound
/// depends on the tick flush running, not just the final flush on cancel (#1114).
pub(crate) async fn pull_stats_flush_loop(state: AppState, interval: std::time::Duration) {
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        // CANCEL-SAFETY: both arms are cancel-safe (an interval tick and a
        // cancellation token). On shutdown we run one final flush, then stop.
        tokio::select! {
            _ = tick.tick() => {
                flush_pull_stats(&state).await;
            }
            _ = state.cancel_token.cancelled() => {
                flush_pull_stats(&state).await;
                break;
            }
        }
    }
}

/// Cumulative pull statistics for one manifest, stored in a `.stats.json`
/// sidecar beside its `.meta.json` (#1114). Kept out of `.meta.json` so a pull
/// never rewrites the integrity metadata a concurrent request reads.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub(crate) struct StatsSidecar {
    pub downloads: u64,
    pub last_pulled: u64,
}

/// The `.stats.json` sidecar key for a manifest's `.meta.json` key.
fn manifest_stats_key(meta_key: &str) -> String {
    let base = meta_key.strip_suffix(".meta.json").unwrap_or(meta_key);
    format!("{base}.stats.json")
}

/// Cumulative stats for a manifest: the `.stats.json` sidecar if present, else
/// the legacy counts still in a pre-V3 `.meta.json` (migrated on the next flush),
/// else zero.
async fn read_cumulative_stats(storage: &Storage, meta_key: &str) -> StatsSidecar {
    let stats_key = manifest_stats_key(meta_key);
    if let Ok(data) = storage.get(&stats_key).await {
        if let Ok(s) = serde_json::from_slice::<StatsSidecar>(&data) {
            return s;
        }
    }
    // Migration: a manifest pushed before V3 still carries counts in .meta.json.
    if let Ok(data) = storage.get(meta_key).await {
        if let Ok(m) = serde_json::from_slice::<ImageMetadata>(&data) {
            return StatsSidecar {
                downloads: m.downloads,
                last_pulled: m.last_pulled,
            };
        }
    }
    StatsSidecar::default()
}

/// Current pull stats for the UI and reports: the flushed cumulative value plus
/// the un-flushed in-memory delta.
pub(crate) async fn current_pull_stats(state: &AppState, meta_key: &str) -> StatsSidecar {
    let base = read_cumulative_stats(&state.storage, meta_key).await;
    let delta = state.pull_stats.peek(meta_key);
    StatsSidecar {
        downloads: base.downloads + delta.downloads,
        last_pulled: base.last_pulled.max(delta.last_pulled),
    }
}

/// Drain the pull-stats accumulator and fold each delta into its `.stats.json`
/// sidecar (#1114). Keeps the deleted-manifest guard of the old per-pull
/// writer: a delta for a manifest no longer stored is dropped, never
/// resurrecting its stats. Replaces the per-pull `.meta.json` rewrite.
pub(crate) async fn flush_pull_stats(state: &AppState) {
    for (meta_key, delta) in state.pull_stats.drain() {
        if delta.downloads == 0 && delta.last_pulled == 0 {
            continue;
        }
        // Serialize with push/delete on this manifest, as the old per-pull writer
        // did: take the publish lock, THEN re-check the manifest is stored, so a
        // delete that landed since the pull cannot be undone by writing a stale
        // sidecar after it (the sidecar is removed under the same lock on delete).
        let lock = state.publish_lock(&meta_key);
        let _guard = lock.lock().await;
        // The manifest blob key is the meta key with `.meta.json` → `.json`
        // (what `manifest_key` builds); stripping only `.meta.json` would check
        // `…/<ref>` and always miss, so the guard would skip every flush and the
        // sidecar would never be written (the stats would be silently lost).
        let manifest_key = format!(
            "{}.json",
            meta_key.strip_suffix(".meta.json").unwrap_or(&meta_key)
        );
        // Deleted-manifest guard: never resurrect a gone manifest's stats.
        if state.storage.stat(&manifest_key).await.is_none() {
            continue;
        }
        let mut stats = read_cumulative_stats(&state.storage, &meta_key).await;
        stats.downloads += delta.downloads;
        stats.last_pulled = stats.last_pulled.max(delta.last_pulled);
        let stats_key = manifest_stats_key(&meta_key);
        if let Ok(json) = serde_json::to_vec(&stats) {
            if let Err(e) = state.storage.put(&stats_key, &json).await {
                tracing::warn!(key = %stats_key, error = %e, "pull-stats sidecar write failed");
                crate::metrics::CACHE_WRITE_ERRORS
                    .with_label_values(&["docker", "stats"])
                    .inc();
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod index_cost_tests;

/// Review round 4: chunked uploads honour Content-Range and report their status (R4-R08), a
/// refused or session-less finalize (R4-R19), blob DELETE/HEAD answers (R4-R05, R4-R21), a
/// pushed manifest over proxied content (R4-R06) and Range without a full read (R4-P15).
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod r4_upload_and_blob_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod stream_spool_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod upstream_resume_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod blob_single_flight_tests;

/// Review round 4, R4-R11: a write is gated on the repository it lands in — the canonical
/// name, after routing — not on the name in the URL.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod r4_write_gate_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod breaker_probe_tests;

#[cfg(test)]
mod upstream_failure_cases;

#[cfg(test)]
mod upstream_failure_edge_cases;

/// A hosted pull's statistics and a re-push write the same metadata file: the pull's write
/// is held after its read, a re-push lands, then the held write is released — the push date
/// curation reads must be the re-push's, not the first push's.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod hosted_pull_stats_and_re_push;

/// Every writer and deleter of a manifest's metadata takes the lock a hosted pull's statistics
/// take: a delete by tag or by digest, a re-push, the legacy key, a mixed-case tag. Each test holds
/// one side between its read and its write while the other runs.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod hosted_pull_stats_every_writer_takes_the_lock;

/// A pull's statistics are recorded only while the manifest it was served from is stored: the
/// statistics task runs at any later point, and after a delete it must not bring the deleted
/// manifest's metadata back.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod hosted_pull_stats_after_a_delete;

/// A manifest and its metadata keep one order: a manifest is written and deleted under its lock
/// and its metadata under the metadata lock taken after it; a manifest goes before its metadata; a
/// pull's statistics take only the metadata lock and write only while the manifest is stored.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod manifest_before_metadata_one_lock_order;

/// Only the metadata section builds a manifest metadata key: `manifest_meta_key` is called, and
/// `.meta.json` written, in no other production function — so every write and delete of a
/// manifest's metadata goes through the helpers that keep the order "manifest, then metadata,
/// manifest lock before metadata lock". A white list, not a list of forbidden forms, which
/// would miss the next form.
#[cfg(test)]
mod only_the_metadata_section_builds_metadata_keys;

/// Review round 4: a tag delete keeps a shared digest copy (R4-R01), tags/list pages and knows
/// an unknown repository (R4-R09), a push stores only a manifest and moves the tag last
/// (R4-R14), an upstream answer is capped and must be a manifest (R4-R15), and one fetch
/// caches under one namespace (R4-R16).
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod r4_manifest_and_tag_tests;
