// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! PyPI registry — PEP 503 (Simple HTML) + PEP 691 (JSON) + twine upload.
//!
//! Implements:
//!   GET  /simple/                     — package index (HTML or JSON)
//!   GET  /simple/{name}/              — package versions (HTML or JSON)
//!   GET  /simple/{name}/{filename}    — download file
//!   POST /simple/                     — twine upload (multipart/form-data)

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::auth::{enforce_namespace_scope, NamespaceAuthority};
use crate::circuit_breaker::BreakerScope;
use crate::config::UpstreamAuth;
use crate::registry::{
    cache_read, circuit_open_response, method_not_allowed, nora_base_url, proxy_error_response,
    proxy_fetch_artifact, proxy_fetch_bytes, proxy_fetch_text, read_cached_artifact, ProxyBody,
    SpoolError, TempFileGuard,
};
use crate::registry_type::RegistryType;
use crate::ui::components::html_escape;
use crate::validation::ends_with_ci;
use crate::AppState;
use axum::{
    extract::{Multipart, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Extension, Router,
};
use sha2::Digest;
use std::fmt::Write;
use std::sync::Arc;
use std::time::Duration;

/// PEP 691 JSON content type
const PEP691_JSON: &str = "application/vnd.pypi.simple.v1+json";

/// `pypi/<project>/` object caching the project's upstream file list (every upstream's
/// index merged, an all-404 answer as an empty list), reused for `pypi.metadata_ttl`.
const UPSTREAM_INDEX_FILE: &str = "upstream-index.json";

/// `pypi/<project>/` object mapping each uploaded filename to twine's `requires_python`.
const REQUIRES_PYTHON_FILE: &str = "requires-python.json";

/// Largest `.dist-info/METADATA` stored for PEP 658; a larger one is not served.
const MAX_CORE_METADATA_BYTES: u64 = 16 << 20;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/simple/",
            get(list_packages)
                .post(upload)
                .fallback(|| async { method_not_allowed("GET, POST") }),
        )
        .route("/simple/{name}/", get(package_versions_filtered))
        .route("/simple/{name}/{filename}", get(download_file))
}

// ============================================================================
// Package index
// ============================================================================

/// GET /simple/ — list all packages (PEP 503 HTML or PEP 691 JSON).
///
/// Served from the in-memory repo index (rebuilt only after an upload or a proxy cache
/// write), not a listing of the whole `pypi/` prefix per request. Only projects holding
/// at least one distribution file are listed.
async fn list_packages(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let index = state.repo_index.get("pypi", &state).await;
    if !state.repo_index.is_ready("pypi") {
        // First build still running after a start: a 503 is retried, an empty
        // (cacheable) project list would read as "nothing here".
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::RETRY_AFTER, "5")],
            "package index is being built, retry shortly",
        )
            .into_response();
    }
    let pkg_list: Vec<&str> = index
        .iter()
        .filter(|repo| repo.versions > 0)
        .map(|repo| repo.name.as_str())
        .collect();
    let base_url = nora_base_url(&state);
    let base = base_url.trim_end_matches('/');

    if wants_json(&headers) {
        // PEP 691 JSON response
        let projects: Vec<serde_json::Value> = pkg_list
            .iter()
            .map(|name| serde_json::json!({"name": name}))
            .collect();
        let body = serde_json::json!({
            "meta": {"api-version": "1.0"},
            "projects": projects,
        });
        (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, PEP691_JSON),
                (header::CACHE_CONTROL, "public, max-age=60, must-revalidate"),
            ],
            serde_json::to_string(&body).unwrap_or_default(),
        )
            .into_response()
    } else {
        // PEP 503 HTML
        let mut html = String::from(
            "<!DOCTYPE html>\n<html><head><title>Simple Index</title></head><body><h1>Simple Index</h1>\n",
        );
        for pkg in pkg_list {
            let pkg = html_escape(pkg);
            let _ = writeln!(html, "<a href=\"{base}/simple/{pkg}/\">{pkg}</a><br>");
        }
        html.push_str("</body></html>");
        (
            StatusCode::OK,
            [(header::CACHE_CONTROL, "public, max-age=60, must-revalidate")],
            Html(html),
        )
            .into_response()
    }
}

// ============================================================================
// Package versions
// ============================================================================

/// GET /simple/{name}/ — list files for a package (PEP 503 HTML or PEP 691 JSON).
///
/// Q04: the simple index of a proxied package is served without files younger than
/// `min_release_age` (see `crate::metadata_filter`), dated by `dates.json`.
async fn package_versions_filtered(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    let normalized = normalize_name(&name);
    let resp = package_versions(State(state.clone()), Path(name), headers).await;
    let curation = state.curation();
    let engine = &curation.curation_engine;
    if resp.status() != StatusCode::OK
        || !engine.metadata_filter_active()
        || crate::curation::is_internal_namespace(engine, RegistryType::PyPI, &normalized)
    {
        return resp;
    }
    let dates = ensure_pypi_dates_cached(&state, &normalized, None).await;
    crate::metadata_filter::rewrite_body(resp, |body| {
        crate::metadata_filter::pypi_index(engine, &normalized, body, &dates)
    })
    .await
}

/// When proxy is configured, merges the upstream index with locally cached/uploaded
/// files, so pip sees all available wheels (e.g. both cp310 and cp314) regardless of
/// which were cached first. The upstream half is cached per project for
/// `pypi.metadata_ttl` (see [`upstream_index`]); local files are always read fresh.
async fn package_versions(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    let normalized = normalize_name(&name);
    let prefix = format!("pypi/{}/", normalized);
    let base_url = nora_base_url(&state);

    // Collect local files with their hashes and sizes. `list_with_meta` carries the
    // size from the listing itself; a per-key `stat()` is a HEAD per file on S3 and
    // must never appear on this path (#738, regressed on the JSON index by #969).
    let keys = match state.storage.list_with_meta(&prefix).await {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(error = ?e, "pypi: failed to list storage for package versions");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    // Digests come from the hash markers: one listing covers every file, where a sidecar
    // read per file is a request per file on an object store. A file without exactly one
    // marker (stored before markers existed, or left with a stale one) is served from its
    // sidecar and queued for backfill. If the listing fails, the sidecars still serve every
    // digest, and nothing is queued against a storage that is failing.
    let marker_prefix = format!("{HASH_MARKER_PREFIX}{normalized}/");
    let (marker_keys, markers_listed) = match state.storage.list(&marker_prefix).await {
        Ok(marker_keys) => (marker_keys, true),
        Err(e) => {
            tracing::warn!(error = ?e, "pypi: failed to list hash markers, reading sidecars");
            (Vec::new(), false)
        }
    };
    let mut markers: std::collections::HashMap<&str, Vec<&str>> = std::collections::HashMap::new();
    for (filename, sha256) in marker_keys
        .iter()
        .filter_map(|key| parse_hash_marker(&marker_prefix, key))
    {
        markers.entry(filename).or_default().push(sha256);
    }
    let listed: std::collections::HashSet<&str> = keys.iter().map(|(k, _)| k.as_str()).collect();
    // twine's `requires_python` of uploaded files: one object per project, read only when
    // the listing shows it exists.
    let requires_python_key = format!("{prefix}{REQUIRES_PYTHON_FILE}");
    let requires_python: std::collections::HashMap<String, String> = if listed
        .contains(requires_python_key.as_str())
    {
        match state.storage.get(&requires_python_key).await {
            Ok(data) => serde_json::from_slice(&data).unwrap_or_default(),
            Err(e) => {
                tracing::warn!(key = %requires_python_key, error = %e, "pypi: failed to read requires-python");
                Default::default()
            }
        }
    } else {
        Default::default()
    };
    let mut backfill: Vec<String> = Vec::new();
    let mut local_files: Vec<FileEntry> = Vec::new();
    let mut local_sizes: std::collections::HashMap<String, u64> =
        std::collections::HashMap::with_capacity(keys.len());
    for (key, meta) in &keys {
        if let Some(filename) = key.strip_prefix(&prefix) {
            if !filename.is_empty()
                && !ends_with_ci(filename, ".sha256")
                && is_valid_pypi_filename(filename)
            {
                let sha256 = match markers.get(filename).map(Vec::as_slice) {
                    Some([sha256]) => Some((*sha256).to_string()),
                    _ => {
                        if markers_listed {
                            backfill.push(filename.to_string());
                        }
                        state
                            .storage
                            .get(&format!("{}.sha256", key))
                            .await
                            .ok()
                            .and_then(|d| String::from_utf8(d.to_vec()).ok())
                    }
                };
                // PEP 658: advertised only when `<file>.metadata` is stored next to it.
                let core_metadata =
                    listed
                        .contains(format!("{key}.metadata").as_str())
                        .then(|| {
                            match markers
                                .get(format!("{filename}.metadata").as_str())
                                .map(Vec::as_slice)
                            {
                                Some([sha256]) => format!("sha256={sha256}"),
                                _ => "true".to_string(),
                            }
                        });
                local_sizes.insert(filename.to_string(), meta.size);
                local_files.push(FileEntry {
                    filename: filename.to_string(),
                    sha256,
                    requires_python: requires_python.get(filename).cloned(),
                    core_metadata,
                    ..Default::default()
                });
            }
        }
    }

    if !backfill.is_empty() {
        use futures::FutureExt as _;
        use std::panic::AssertUnwindSafe;
        let storage = state.storage.clone();
        let publish_locks = state.publish_locks.clone();
        let project = normalized.clone();
        let task = async move {
            for filename in backfill {
                backfill_hash_marker(&storage, &publish_locks, &project, &filename).await;
            }
        };
        tokio::spawn(AssertUnwindSafe(task).catch_unwind().map(|done| {
            if let Err(panic) = done {
                tracing::error!(panic = ?panic, "pypi: hash marker backfill panicked");
            }
        }));
    }

    // When proxy is configured, merge the upstream index with the local files.
    // This fixes the case where a cp314 wheel is cached but pip 3.10 needs to
    // see the full upstream file list to find a compatible cp310 wheel.
    // #68 namespace isolation: an internal-namespace package must never be fetched
    // upstream (dependency confusion). Skip the upstream merge entirely; a locally
    // published copy is still served from the local files, and an
    // internal name with no local copy is blocked (never proxied). Computed without
    // the `blocked` metric — the metric fires only on the actual block path below.
    let is_internal = crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::PyPI,
        &normalized,
    );

    let mut files = local_files;
    let mut stale = false;
    if !is_internal && !state.config.pypi.upstreams().is_empty() {
        let cache_key = format!("{prefix}{UPSTREAM_INDEX_FILE}");
        let cached_at = keys
            .iter()
            .find(|(key, _)| *key == cache_key)
            .map(|(_, meta)| meta.modified);
        let ttl = state.config.pypi.metadata_ttl;
        let upstream = match upstream_index(&state, &normalized, cached_at, ttl).await {
            UpstreamIndex::Files(upstream) => upstream,
            UpstreamIndex::Stale(upstream) => {
                stale = true;
                upstream
            }
            UpstreamIndex::Failed(response) => return response,
        };
        files = merge_file_lists(upstream, &files);
    }

    if !files.is_empty() {
        let mut response = if wants_json(&headers) {
            // #896: for JSON (Renovate) clients, ensure upstream PEP 700 upload-times are
            // cached so the index can surface them. No-op if already cached / internal /
            // no upstream. Read after the index refresh, which refreshes them too (R2-24),
            // and ONCE: re-reading `dates.json` per file was a round-trip each (#969).
            let dates = ensure_pypi_dates_cached(&state, &normalized, None).await;
            let pep700 = pep700_meta(&files, &local_sizes, &dates);
            versions_json_response(&normalized, &files, &base_url, &pep700)
        } else {
            versions_html_response(&normalized, &files, &base_url)
        };
        if stale {
            response.headers_mut().insert(
                header::WARNING,
                header::HeaderValue::from_static("110 - \"Response is Stale\""),
            );
        }
        return response;
    }

    // #68: an internal-namespace package with no local copy is blocked, never
    // proxied — return the namespace 403 (the only pypi metadata path that
    // increments the blocked metric).
    if is_internal {
        if let Some(response) = crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::PyPI,
            &normalized,
        ) {
            return response;
        }
    }

    StatusCode::NOT_FOUND.into_response()
}

/// The upstream half of a project's index ([`upstream_index`]).
enum UpstreamIndex {
    /// Within `metadata_ttl`, just fetched, or the merge of the upstreams that answered.
    Files(Vec<FileEntry>),
    /// The refetch failed: the last good copy, served with a `Warning`.
    Stale(Vec<FileEntry>),
    /// The refetch failed and there is no copy: the 5xx to send. Serving only the local
    /// files instead would let pip resolve an older cached version without a signal.
    Failed(Response),
}

/// What asking every upstream for a project's index returned.
#[derive(Default)]
struct UpstreamFetch {
    files: Vec<FileEntry>,
    /// At least one upstream listed the project or answered 404.
    answered: bool,
    circuit_open: bool,
    error: Option<(String, crate::registry::ProxyError)>,
}

/// Fetch each configured upstream's index and merge them (#663). Precedence is the
/// upstream order: the first upstream that lists a file wins.
async fn fetch_upstream_index(state: &AppState, normalized: &str) -> UpstreamFetch {
    let mut out = UpstreamFetch::default();
    for up in &state.config.pypi.upstreams() {
        let url = format!("{}/{}/", up.url().trim_end_matches('/'), normalized);
        match proxy_fetch_text(
            &state.http_client,
            &url,
            Duration::from_secs(state.config.pypi.proxy_timeout),
            up.auth().map(UpstreamAuth::Basic),
            Some(("Accept", "text/html")),
            &state.circuit_breaker,
            BreakerScope::upstream(RegistryType::PyPI, up.url()),
        )
        .await
        {
            Ok(html) => {
                out.answered = true;
                out.files
                    .extend(parse_upstream_files(&html, &url).into_iter().map(|mut f| {
                        f.upstream = Some(up.url().to_string());
                        f
                    }));
            }
            Err(crate::registry::ProxyError::NotFound) => out.answered = true,
            Err(crate::registry::ProxyError::CircuitOpen(_)) => out.circuit_open = true,
            Err(e) => {
                tracing::debug!(error = ?e, package = %normalized, upstream = %up.url(), "PyPI upstream index fetch failed, skipping");
                out.error = Some((url, e));
            }
        }
    }
    out
}

/// The upstream file list of `normalized`, cached in `pypi/<project>/upstream-index.json`
/// (`cached_at` is its mtime, `None` when absent) and served while within `ttl`
/// (`pypi.metadata_ttl`, or the miss TTL of a lookup the copy cannot answer).
///
/// Within the TTL the stored copy is served without asking the upstreams,
/// so a project every upstream 404s (a private one outside
/// `curation.internal_namespaces`) is not looked up on every request, and a CI fan-out
/// costs one upstream fetch per project per TTL. A refetch runs single-flight per
/// project and is stored only when every upstream answered. When it fails, the last
/// good copy is served stale; with no copy, the merge of the upstreams that did answer
/// (one dead mirror must not sink the others, #663), or the upstream error when none did.
///
/// With `server.trust_upstream_dates` the refetch also refreshes `dates.json`, after the
/// file list (a file published in between is dated, never listed undated) and stored
/// before it: the index and its dates are one snapshot (R2-24).
async fn upstream_index(
    state: &AppState,
    normalized: &str,
    cached_at: Option<u64>,
    ttl: i64,
) -> UpstreamIndex {
    let cache_key = format!("pypi/{normalized}/{UPSTREAM_INDEX_FILE}");
    let cache_key = cache_key.as_str();
    // A copy written before entries carried their URL cannot resolve a download.
    let read_cached = || async {
        let data = state.storage.get(cache_key).await.ok()?;
        serde_json::from_slice::<Vec<FileEntry>>(&data)
            .ok()
            .filter(|files| files.iter().all(|f| f.url.is_some()))
    };
    if cached_at.is_some_and(|m| crate::cache_ttl::is_within_ttl(m, ttl)) {
        if let Some(files) = read_cached().await {
            return UpstreamIndex::Files(files);
        }
    }

    // The fetch runs once per caller at most (as the leader, or as a follower whose
    // leader failed); its result lands in `fetch`.
    let mut fetch = UpstreamFetch::default();
    let fetch_slot = &mut fetch;
    let refresh = move || async move {
        *fetch_slot = fetch_upstream_index(state, normalized).await;
        if fetch_slot.circuit_open || fetch_slot.error.is_some() {
            return None;
        }
        if state.config.server.trust_upstream_dates {
            // A project no upstream lists has nothing to date: no second lookup.
            let dates = if fetch_slot.files.is_empty() {
                serde_json::Map::new()
            } else {
                fetch_upstream_dates(state, normalized).await?
            };
            let key = format!("pypi/{normalized}/dates.json");
            if let Err(e) = state
                .storage
                .put(&key, &serde_json::to_vec(&dates).ok()?)
                .await
            {
                tracing::warn!(key = %key, error = %e, "pypi: failed to cache dates");
                return None;
            }
        }
        let bytes = serde_json::to_vec(&fetch_slot.files).ok()?;
        if let Err(e) = state.storage.put(cache_key, &bytes).await {
            tracing::warn!(key = %cache_key, error = %e, "pypi: failed to cache the upstream index");
        }
        Some(axum::body::Bytes::from(bytes))
    };
    let shared = if state.config.server.proxy_coalesce {
        let budget = crate::proxy_coalesce::follower_budget(state.config.pypi.proxy_timeout)
            * state.config.pypi.upstreams().len().max(1) as u32;
        state
            .proxy_coalesce
            .coalesced(&format!("index:{cache_key}"), "pypi", budget, refresh)
            .await
    } else {
        refresh().await
    };
    if let Some(files) = shared.and_then(|b| serde_json::from_slice(&b).ok()) {
        return UpstreamIndex::Files(files);
    }

    if cached_at.is_some() {
        if let Some(files) = read_cached().await {
            tracing::warn!(package = %normalized, "PyPI upstream index refetch failed, serving the last good copy");
            return UpstreamIndex::Stale(files);
        }
    }
    if fetch.answered {
        return UpstreamIndex::Files(fetch.files);
    }
    // A tripped breaker means the upstream is temporarily down — 503 (retryable)
    // rather than 404, which would poison pip's negative cache.
    if fetch.circuit_open {
        return UpstreamIndex::Failed(circuit_open_response(RegistryType::PyPI.as_str()));
    }
    // An upstream failed (not "not found"): a 5xx pip retries, not a 404 it trusts.
    match fetch.error {
        Some((url, e)) => UpstreamIndex::Failed(proxy_error_response("pypi", &url, &e)),
        None => UpstreamIndex::Failed(StatusCode::BAD_GATEWAY.into_response()),
    }
}

/// The upstream index entries of `filename` with the configured upstream of each, in
/// precedence order, resolved from the cached index (R2-27): a download or `.metadata`
/// request costs no project page fetch while the index is within `pypi.metadata_ttl`.
/// A copy that does not list the file is refetched once it is older than the miss TTL
/// (a release published since); an upstream outage with no copy is its 5xx.
async fn upstream_entries(
    state: &AppState,
    normalized: &str,
    filename: &str,
) -> Result<Vec<(crate::config::PypiProxyEntry, FileEntry)>, Response> {
    let cache_key = format!("pypi/{normalized}/{UPSTREAM_INDEX_FILE}");
    let upstreams = state.config.pypi.upstreams();
    let listing = |files: Vec<FileEntry>| -> Vec<_> {
        files
            .into_iter()
            .filter(|f| f.filename == filename)
            .filter_map(|f| {
                let up = upstreams
                    .iter()
                    .find(|up| f.upstream.as_deref() == Some(up.url()))?;
                Some((up.clone(), f))
            })
            .collect()
    };
    let ttl = state.config.pypi.metadata_ttl;
    let cached_at = state.storage.stat(&cache_key).await.map(|m| m.modified);
    let (found, stale) = match upstream_index(state, normalized, cached_at, ttl).await {
        UpstreamIndex::Files(files) => (listing(files), false),
        UpstreamIndex::Stale(files) => (listing(files), true),
        UpstreamIndex::Failed(response) => return Err(response),
    };
    // Not listed by a copy served from cache past the miss TTL: refetch it once.
    let refetch = cached_at.is_some_and(|m| {
        crate::cache_ttl::is_within_ttl(m, ttl)
            && !crate::cache_ttl::is_within_ttl(m, miss_ttl(state))
    });
    if !found.is_empty() || stale || !refetch {
        return Ok(found);
    }
    match upstream_index(state, normalized, cached_at, miss_ttl(state)).await {
        UpstreamIndex::Files(files) | UpstreamIndex::Stale(files) => Ok(listing(files)),
        UpstreamIndex::Failed(response) => Err(response),
    }
}

// ============================================================================
// Download
// ============================================================================

/// GET /simple/{name}/{filename} — download a specific file.
// LOCK-SAFE: cache-through proxy — get miss → fetch upstream → put; no RMW race
async fn download_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((name, filename)): Path<(String, String)>,
) -> Response {
    let normalized = normalize_name(&name);

    // PEP 658: `<wheel>.metadata`.
    if let Some(wheel) = filename.strip_suffix(".metadata") {
        if ends_with_ci(wheel, ".whl") && is_valid_pypi_filename(wheel) {
            return core_metadata(&state, &normalized, wheel).await;
        }
        return StatusCode::NOT_FOUND.into_response();
    }

    // Block download of internal bookkeeping files (dates.json, etc.) that
    // live alongside packages in storage but are not real artifacts (#891).
    if !is_valid_pypi_filename(&filename) {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Curation check — before storage access
    let version = crate::curation::parse_pypi_version(&normalized, &filename);
    let key = format!("pypi/{}/{}", normalized, filename);

    // #733 serve-local: an internal-namespace package is operator-owned — skip curation
    // and serve any local copy below; the upstream branch is blocked separately (never proxy).
    let internal = crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::PyPI,
        &normalized,
    );

    // Digest-quarantine: first-seen hold for proxy artifacts (generalizes the
    // Docker-only wiring). Resolved once; applied at each serve point below.
    let (mut q_mode, q_secs) = crate::digest_quarantine::resolve_global(
        state.config.curation.pypi.quarantine.as_ref().or(state
            .config
            .curation
            .quarantine
            .as_ref()),
        state
            .config
            .curation
            .pypi
            .quarantine_ttl
            .as_deref()
            .or(state.config.curation.quarantine_ttl.as_deref()),
    );
    let quarantine_on = !matches!(q_mode, crate::digest_quarantine::QuarantineMode::Off);

    // A hosted file (internal namespace, or uploaded / imported here: stored without the
    // proxy's provenance marker) is our own publish, not an upstream artifact: never held
    // by the quarantine (R2-23, as npm's C30), never dated upstream (R2-45).
    let hosted = internal
        || ((quarantine_on || state.config.server.trust_upstream_dates)
            && state.storage.stat(&key).await.is_some()
            && state
                .storage
                .stat(&proxied_marker_key(&key))
                .await
                .is_none());
    if hosted {
        q_mode = crate::digest_quarantine::QuarantineMode::Off;
    }
    let quarantine_on = !matches!(q_mode, crate::digest_quarantine::QuarantineMode::Off);

    // Extract the upstream release date for this file (PEP 700 `upload-time` from
    // the PEP 691 simple JSON, cached as dates.json). Seeds the digest-quarantine
    // first-seen clock so a provably-old release is not held as "new to this
    // mirror" (#748/#750). Only consulted when upstream dates are trusted. A file the
    // cached map does not date (published after it was fetched) refreshes the index and
    // the map together, so a new release is never dated by an older snapshot (R2-24).
    let publish_date = if hosted {
        None
    } else if state.config.server.trust_upstream_dates {
        ensure_pypi_dates_cached(&state, &normalized, Some(&filename))
            .await
            .get(&filename)
            .and_then(|v| v.as_str())
            .and_then(crate::curation::parse_iso8601_to_unix)
    } else {
        extract_pypi_publish_date(&state.storage, &normalized, &filename).await
    };

    if !internal {
        if let Some(response) = crate::curation::check_download(
            &state.curation().curation_engine,
            state.bypass_token().as_deref(),
            &headers,
            crate::curation::RegistryType::PyPI,
            &normalized,
            crate::curation::RequestVersion::of_artifact(version.as_deref()),
            publish_date,
        ) {
            return response;
        }
    }

    // Resumable download (#657): serve the requested bytes from the backend and skip
    // the full read below. Package files only — the simple index is generated, never
    // ranged. A partial read cannot be hashed, so neither the quarantine gate nor the
    // curation integrity check can run on it: the range serve stands down while
    // quarantine holds artifacts, and integrity is the client's own hash (the PEP 691
    // `hashes` field), as docker does.
    if headers.contains_key(header::RANGE)
        && matches!(q_mode, crate::digest_quarantine::QuarantineMode::Off)
    {
        if let Some(meta) = state.storage.stat(&key).await {
            if let Some(response) = crate::registry::range::range_response(
                &state.storage,
                &[&key],
                &headers,
                meta.size,
                pypi_content_type(&filename),
                &[(
                    header::CACHE_CONTROL,
                    "public, max-age=31536000, immutable".to_string(),
                )],
            )
            .await
            {
                if response.status() == StatusCode::PARTIAL_CONTENT {
                    state.metrics.record_download("pypi");
                    state.metrics.record_cache_hit("pypi");
                }
                return response;
            }
        }
    }

    let engine = &state.curation().curation_engine;

    // Try local storage first, integrity-gated: read whole and verified, or above
    // `server.stream_threshold_mb` streamed with its pin checked as it streams.
    let cached = match read_cached_artifact(&state, "pypi", &key, internal).await {
        Ok(cached) => cached,
        Err(resp) => return resp,
    };
    if let Some(cached) = cached {
        // Curation integrity verification (issue #189)
        if engine.is_active() {
            if let Some(response) = crate::curation::verify_integrity_by_hash(
                engine,
                crate::curation::RegistryType::PyPI,
                &normalized,
                version.as_deref(),
                &cached.digest(),
            ) {
                return response;
            }
        }

        state.metrics.record_download("pypi");
        state.metrics.record_cache_hit("pypi");
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            format!("{}/{}", name, filename),
            crate::registry_type::RegistryType::PyPI,
            "CACHE",
        ));
        state
            .audit
            .log(AuditEntry::new("cache_hit", "proxy", "", "pypi", ""));

        if quarantine_on {
            if let Some(resp) = crate::digest_quarantine::proxy_gate_digest(
                &state.digest_store,
                "pypi",
                &cached.digest(),
                &q_mode,
                q_secs,
                "cache",
                publish_date,
            ) {
                return resp;
            }
        }

        let content_type = pypi_content_type(&filename);
        let len = cached.len().to_string();
        return (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, content_type),
                (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
                (header::ACCEPT_RANGES, "bytes"),
                (header::CONTENT_LENGTH, &len),
            ],
            cached.into_body(&state, "pypi", &key, internal),
        )
            .into_response();
    }

    // #733: an internal-namespace package with no local copy is never proxied upstream.
    if internal {
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::PyPI,
            &normalized,
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
    }

    // The upstreams whose index lists the file, in precedence order, from the cached
    // index (R2-27); each is fetched with that upstream's auth. One upstream's failure
    // or open breaker skips to the next rather than failing (#663).
    let entries = match upstream_entries(&state, &normalized, &filename).await {
        Ok(entries) => entries,
        Err(response) => return response,
    };
    let mut circuit_open = false;
    let mut upstream_err: Option<(String, crate::registry::ProxyError)> = None;
    for (up, entry) in &entries {
        let Some(file_url) = entry.url.clone() else {
            continue;
        };
        let expected_sha256 = entry.sha256.as_deref();

        // A file above `server.stream_threshold_mb` is spooled to disk (C17).
        match proxy_fetch_artifact(
            &state,
            &key,
            "pypi",
            &file_url,
            state.config.pypi.proxy_timeout,
            up.auth().map(UpstreamAuth::Basic),
            BreakerScope::upstream(RegistryType::PyPI, up.url()),
        )
        .await
        {
            Ok((data, fetched)) => {
                // Hashed once (a spooled body already carries it).
                let sha256 = data.sha256();
                // The index published this file's digest: a body that does not match
                // (truncated, corrupted, tampered) is neither served nor cached.
                if let Some(expected) = expected_sha256 {
                    let actual = &sha256;
                    if !actual.eq_ignore_ascii_case(expected) {
                        tracing::warn!(package = %normalized, filename = %filename, upstream = %up.url(), %expected, %actual, "PyPI upstream file does not match the index sha256, refusing it");
                        return StatusCode::BAD_GATEWAY.into_response();
                    }
                }
                // Curation integrity runs on the first serve too, not only on cache hits.
                if engine.is_active() {
                    if let Some(response) = crate::curation::verify_integrity_by_hash(
                        engine,
                        crate::curation::RegistryType::PyPI,
                        &normalized,
                        version.as_deref(),
                        &format!("sha256:{sha256}"),
                    ) {
                        return response;
                    }
                }
                state.metrics.record_download("pypi");
                state.metrics.record_cache_miss("pypi");
                state.activity.push(ActivityEntry::new(
                    ActionType::ProxyFetch,
                    format!("{}/{}", name, filename),
                    crate::registry_type::RegistryType::PyPI,
                    "PROXY",
                ));
                state
                    .audit
                    .log(AuditEntry::new("proxy_fetch", "proxy", "", "pypi", ""));

                // Cache in background + compute hash, invalidate AFTER write.
                // Only the caller that fetched caches; coalesced followers share its body.
                if fetched {
                    let cache_state = state.clone();
                    let storage = state.storage.clone();
                    let key_clone = key.clone();
                    let data_clone = data.clone();
                    let project = normalized.clone();
                    let file_name = filename.clone();
                    let repo_index = Arc::clone(&state.repo_index);
                    let hash = sha256.clone();
                    tokio::spawn(async move {
                        let core_meta = if ends_with_ci(&file_name, ".whl") {
                            match &data_clone {
                                ProxyBody::Mem(b) => {
                                    wheel_core_metadata(std::io::Cursor::new(&b[..]))
                                }
                                ProxyBody::File(spool) => {
                                    let spool = Arc::clone(spool);
                                    tokio::task::spawn_blocking(move || {
                                        std::fs::File::open(&spool.path)
                                            .ok()
                                            .and_then(wheel_core_metadata)
                                    })
                                    .await
                                    .ok()
                                    .flatten()
                                }
                            }
                        } else {
                            None
                        };
                        // Create-only under the file's publish lock: an upload that
                        // got there first wins (C53).
                        if let Ok(true) = data_clone.cache(&cache_state, &key_clone, true).await {
                            let _ = storage
                                .put(&format!("{}.sha256", key_clone), hash.as_bytes())
                                .await;
                            // Provenance: cached from upstream, so GC may evict it (C22).
                            let _ = storage
                                .put(&proxied_marker_key(&key_clone), hash.as_bytes())
                                .await;
                            put_hash_marker(&storage, &project, &file_name, &hash).await;
                            if let Some(meta) = core_meta {
                                put_core_metadata(&storage, &project, &file_name, &meta).await;
                            }
                            repo_index.invalidate("pypi");
                        }
                    });
                }

                if quarantine_on {
                    if let Some(resp) = crate::digest_quarantine::proxy_gate_digest(
                        &state.digest_store,
                        "pypi",
                        &format!("sha256:{sha256}"),
                        &q_mode,
                        q_secs,
                        &file_url,
                        publish_date,
                    ) {
                        return resp;
                    }
                }

                let content_type = pypi_content_type(&filename);
                let len = data.len().to_string();
                return match data.into_body(&key).await {
                    Ok(body) => (
                        StatusCode::OK,
                        [
                            (header::CONTENT_TYPE, content_type),
                            (header::CONTENT_LENGTH, &len),
                        ],
                        body,
                    )
                        .into_response(),
                    Err(e) => {
                        tracing::warn!(key = %key, error = %e, "pypi: spooled file unreadable");
                        StatusCode::INTERNAL_SERVER_ERROR.into_response()
                    }
                };
            }
            Err(crate::registry::ProxyError::CircuitOpen(_)) => {
                circuit_open = true;
                continue;
            }
            Err(crate::registry::ProxyError::NotFound) => continue,
            // nora's own disk: another upstream would not help.
            Err(crate::registry::ProxyError::Spool(e)) => return e.response("pypi"),
            Err(e) => {
                tracing::debug!(error = ?e, package = %normalized, filename = %filename, upstream = %up.url(), "PyPI file proxy fetch failed, trying next upstream");
                upstream_err = Some((file_url, e));
                continue;
            }
        }
    }

    // A tripped breaker means an upstream is temporarily down — 503 (retryable)
    // rather than 404, which would poison pip's negative cache; a failed upstream is
    // 502 for the same reason.
    if circuit_open {
        return circuit_open_response(RegistryType::PyPI.as_str());
    }
    // An upstream failed (not "not found"): a 5xx pip retries, not a 404 it trusts.
    if let Some((url, e)) = upstream_err {
        return proxy_error_response("pypi", &url, &e);
    }

    StatusCode::NOT_FOUND.into_response()
}

/// GET /simple/{name}/{wheel}.metadata — PEP 658 core metadata: the copy stored next to
/// a local wheel, else the upstream's own `.metadata` where its index advertises one.
async fn core_metadata(state: &AppState, normalized: &str, wheel: &str) -> Response {
    let respond = |data: axum::body::Bytes| {
        (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/octet-stream"),
                (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
            ],
            data,
        )
            .into_response()
    };
    let internal = crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::PyPI,
        normalized,
    );
    let key = format!("pypi/{normalized}/{wheel}.metadata");
    match cache_read(state.storage.get(&key).await, "pypi", &key, internal) {
        Ok(Some(data)) => return respond(data),
        Ok(None) => {}
        Err(response) => return response,
    }
    if internal {
        return StatusCode::NOT_FOUND.into_response();
    }

    let entries = match upstream_entries(state, normalized, wheel).await {
        Ok(entries) => entries,
        Err(response) => return response,
    };
    let mut circuit_open = false;
    let mut upstream_err: Option<(String, crate::registry::ProxyError)> = None;
    for (up, entry) in &entries {
        let timeout = Duration::from_secs(state.config.pypi.proxy_timeout);
        // Only where this upstream's index advertises it, as PEP 658 requires.
        let (Some(file_url), Some(advertised)) = (&entry.url, &entry.core_metadata) else {
            continue;
        };
        let url = format!("{file_url}.metadata");
        match proxy_fetch_bytes(
            &state.http_client,
            &url,
            timeout,
            up.auth().map(UpstreamAuth::Basic),
            &state.circuit_breaker,
            BreakerScope::upstream(RegistryType::PyPI, up.url()),
        )
        .await
        {
            Ok(data) => {
                if let Some(expected) = advertised.strip_prefix("sha256=") {
                    let actual = hex::encode(sha2::Sha256::digest(&data));
                    if !actual.eq_ignore_ascii_case(expected) {
                        tracing::warn!(package = %normalized, wheel = %wheel, upstream = %up.url(), %expected, %actual, "PyPI upstream core metadata does not match the index digest, refusing it");
                        return StatusCode::BAD_GATEWAY.into_response();
                    }
                }
                return respond(data);
            }
            Err(crate::registry::ProxyError::CircuitOpen(_)) => circuit_open = true,
            Err(crate::registry::ProxyError::NotFound) => {}
            Err(e) => upstream_err = Some((url, e)),
        }
    }
    if circuit_open {
        return circuit_open_response(RegistryType::PyPI.as_str());
    }
    if let Some((url, e)) = upstream_err {
        return proxy_error_response("pypi", &url, &e);
    }
    StatusCode::NOT_FOUND.into_response()
}

// ============================================================================
// Twine upload (PEP 503 — POST /simple/)
// ============================================================================

/// POST /simple/ — upload a package via twine.
///
/// twine sends multipart/form-data with fields:
///   :action = "file_upload"
///   name = package name
///   version = package version
///   filetype = "sdist" | "bdist_wheel"
///   content = the file bytes
///   sha256_digest = hex SHA-256 of file (optional)
///   requires_python = the `Requires-Python` specifier (optional, persisted)
///   metadata_version, summary, etc. (optional metadata)
///
/// `content` is streamed to a temp file with a running SHA-256, never held in memory.
async fn upload(
    State(state): State<AppState>,
    Extension(authority): Extension<NamespaceAuthority>,
    user: Option<Extension<crate::auth::AuthenticatedUser>>,
    mut multipart: Multipart,
) -> Response {
    use tokio::io::AsyncWriteExt as _;

    let mut action = String::new();
    let mut name = String::new();
    let mut version = String::new();
    let mut filename = String::new();
    let mut sha256_digest = String::new();
    let mut requires_python = String::new();
    // (temp file, its guard, size, sha256) of the `content` field.
    let mut content: Option<(std::path::PathBuf, TempFileGuard, u64, String)> = None;
    // Spool budget held by `content` until it is stored (R2-05).
    let mut reservation = None;
    // The body is capped by `server.body_limit_mb` (DefaultBodyLimit, which the multipart
    // stream enforces): crossing it is a 413, any other malformed body a 400 (R2-25).
    let limit_mb = state.config.server.body_limit_mb;
    let reject = |e: axum::extract::multipart::MultipartError| {
        let status = e.status();
        if status == StatusCode::PAYLOAD_TOO_LARGE {
            (status, format!("upload exceeds {limit_mb} MiB")).into_response()
        } else {
            (status, format!("Failed to read upload: {}", e.body_text())).into_response()
        }
    };

    // Parse multipart fields
    loop {
        let mut field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(e) => return reject(e),
        };
        let field_name = field.name().unwrap_or("").to_string();

        match field_name.as_str() {
            ":action" | "name" | "version" | "sha256_digest" | "requires_python" => {
                let value = match field.text().await {
                    Ok(value) => value,
                    Err(e) => return reject(e),
                };
                match field_name.as_str() {
                    ":action" => action = value,
                    "name" => name = value,
                    "version" => version = value,
                    "sha256_digest" => sha256_digest = value,
                    _ => requires_python = value,
                }
            }
            "content" if content.is_none() => {
                filename = field.file_name().unwrap_or("unknown").to_string();
                let dir = state.spool.dir(crate::registry::PYPI_UPLOAD_SUBDIR);
                let path = dir.join(uuid::Uuid::new_v4().to_string());
                let local = |e| SpoolError::io(&path)(e).response("pypi");
                let spool = reservation.insert(match state.spool.reserve(0) {
                    Ok(r) => r,
                    Err(e) => return e.response("pypi"),
                });
                if let Err(e) = tokio::fs::create_dir_all(&dir).await {
                    return local(e);
                }
                let guard = TempFileGuard::new(path.clone());
                let mut file = match tokio::fs::File::create(&path).await {
                    Ok(f) => f,
                    Err(e) => return local(e),
                };
                let mut hasher = sha2::Sha256::new();
                let mut size = 0u64;
                loop {
                    match field.chunk().await {
                        Ok(Some(chunk)) => {
                            size += chunk.len() as u64;
                            if let Err(e) = spool.grow(size) {
                                return e.response("pypi");
                            }
                            hasher.update(&chunk);
                            if let Err(e) = file.write_all(&chunk).await {
                                return local(e);
                            }
                        }
                        Ok(None) => break,
                        Err(e) => return reject(e),
                    }
                }
                // Durable before put_from_path's rename publishes it.
                if let Err(e) = file.sync_all().await {
                    return local(e);
                }
                content = Some((path, guard, size, hex::encode(hasher.finalize())));
            }
            _ => {
                // Skip other metadata fields (summary, author, etc.) without buffering.
                loop {
                    match field.chunk().await {
                        Ok(Some(_)) => {}
                        Ok(None) => break,
                        Err(e) => return reject(e),
                    }
                }
            }
        }
    }

    // Validate required fields
    if action != "file_upload" {
        return (StatusCode::BAD_REQUEST, "Unsupported action").into_response();
    }

    if name.is_empty() || version.is_empty() {
        return (StatusCode::BAD_REQUEST, "Missing name or version").into_response();
    }

    let (temp_path, _temp_guard, computed_hash) = match content {
        Some((path, guard, size, hash)) if size > 0 => (path, guard, hash),
        _ => return (StatusCode::BAD_REQUEST, "Missing file content").into_response(),
    };

    // Validate filename
    if filename.is_empty() || !is_valid_pypi_filename(&filename) {
        return (StatusCode::BAD_REQUEST, "Invalid filename").into_response();
    }

    // Verify SHA-256 if provided
    if !sha256_digest.is_empty() && !sha256_digest.eq_ignore_ascii_case(&computed_hash) {
        tracing::warn!(
            package = %name,
            expected = %sha256_digest,
            computed = %computed_hash,
            "SECURITY: PyPI upload SHA-256 mismatch"
        );
        return (StatusCode::BAD_REQUEST, "SHA-256 digest mismatch").into_response();
    }

    // Normalize name and store
    let normalized = normalize_name(&name);

    // The file must be a release of the project and version it is uploaded as, so the
    // storage key, the index and the audit trail agree on what it is.
    if let Some(reason) = upload_filename_mismatch(&filename, &normalized, &version) {
        return (StatusCode::BAD_REQUEST, reason).into_response();
    }

    // Enforce OIDC namespace_scope on the project coordinate (#583).
    if enforce_namespace_scope(&authority, &normalized).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }

    // PEP 658 core metadata, read before put_from_path moves the temp file.
    let core_meta = if ends_with_ci(&filename, ".whl") {
        let path = temp_path.clone();
        tokio::task::spawn_blocking(move || {
            std::fs::File::open(&path)
                .ok()
                .and_then(|f| wheel_core_metadata(std::io::BufReader::new(f)))
        })
        .await
        .ok()
        .flatten()
    } else {
        None
    };

    if let Err(e) = store_file(
        &state.storage,
        &state.publish_locks,
        &normalized,
        &filename,
        &temp_path,
        &computed_hash,
        core_meta,
        requires_python.trim(),
    )
    .await
    {
        return e.into_response();
    }

    state.metrics.record_upload("pypi");
    let artifact = format!("{}-{}", name, version);
    state.audit.log(AuditEntry::new(
        "push",
        crate::auth::audit_actor(&user),
        &artifact,
        "pypi",
        "",
    ));
    state.activity.push(ActivityEntry::new(
        ActionType::Push,
        artifact,
        crate::registry_type::RegistryType::PyPI,
        "LOCAL",
    ));
    state.repo_index.invalidate("pypi");

    StatusCode::OK.into_response()
}

/// Store a validated distribution file of `project` as an upload does, under the file's
/// publish lock: the file itself (immutable: an existing name is a 409), its `.sha256`
/// sidecar and hash marker, a wheel's core metadata as `<file>.metadata`, and its
/// `Requires-Python` (empty = none). Shared with `nora import`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn store_file(
    storage: &crate::storage::Storage,
    locks: &crate::PublishLocks,
    project: &str,
    filename: &str,
    src: &std::path::Path,
    sha256: &str,
    core_meta: Option<Vec<u8>>,
    requires_python: &str,
) -> Result<(), (StatusCode, String)> {
    // TOCTOU protection: lock per file to prevent concurrent uploads
    let file_key = format!("pypi/{project}/{filename}");
    let lock = crate::acquire_publish_lock(locks, &file_key);
    let _guard = lock.lock().await;

    // Check immutability (same filename = already exists)
    if storage.stat(&file_key).await.is_some() {
        return Err((
            StatusCode::CONFLICT,
            format!("File {filename} already exists"),
        ));
    }

    // An upload is never a proxy cache: drop any stale provenance marker, or GC
    // could evict the only copy (C22).
    let _ = storage.delete(&proxied_marker_key(&file_key)).await;

    // Store file
    if let Err(e) = storage.put_from_path(&file_key, src, Some(sha256)).await {
        tracing::error!(key = %file_key, error = %e, "pypi: failed to store upload");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to store {filename}"),
        ));
    }

    // Store SHA-256 hash
    let hash_key = format!("{file_key}.sha256");
    if let Err(e) = storage.put(&hash_key, sha256.as_bytes()).await {
        tracing::warn!(key = %hash_key, error = %e, "pypi: failed to store hash sidecar");
    }

    // Hash marker: the simple index reads every digest from one listing.
    put_hash_marker(storage, project, filename, sha256).await;
    if let Some(meta) = core_meta {
        put_core_metadata(storage, project, filename, &meta).await;
    }
    record_requires_python(storage, locks, project, filename, requires_python).await;
    Ok(())
}

/// Record twine's `requires_python` for an uploaded file in the project's
/// [`REQUIRES_PYTHON_FILE`] (an empty one drops a stale entry of an earlier file of the
/// same name). Best-effort: a failure is logged and the file is listed without it.
async fn record_requires_python(
    storage: &crate::storage::Storage,
    locks: &crate::PublishLocks,
    project: &str,
    filename: &str,
    requires_python: &str,
) {
    use crate::storage::StorageError;
    let key = format!("pypi/{project}/{REQUIRES_PYTHON_FILE}");
    let lock = crate::acquire_publish_lock(locks, &key);
    let _guard = lock.lock().await;
    let mut map: serde_json::Map<String, serde_json::Value> = match storage.get(&key).await {
        Ok(data) => serde_json::from_slice(&data).unwrap_or_default(),
        Err(StorageError::NotFound) if requires_python.is_empty() => return,
        Err(StorageError::NotFound) => serde_json::Map::new(),
        Err(e) => {
            tracing::warn!(key = %key, error = %e, "pypi: failed to read requires-python");
            return;
        }
    };
    let changed = if requires_python.is_empty() {
        map.remove(filename).is_some()
    } else {
        map.insert(filename.to_string(), requires_python.into()) != Some(requires_python.into())
    };
    if changed {
        if let Err(e) = storage
            .put(&key, &serde_json::to_vec(&map).unwrap_or_default())
            .await
        {
            tracing::warn!(key = %key, error = %e, "pypi: failed to store requires-python");
        }
    }
}

/// The `Requires-Python` header of core metadata (`METADATA` / `PKG-INFO`), if any.
pub(crate) fn metadata_requires_python(metadata: &[u8]) -> Option<String> {
    String::from_utf8_lossy(metadata)
        .lines()
        .take_while(|line| !line.is_empty())
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("Requires-Python")
                .then(|| value.trim().to_string())
        })
        .filter(|v| !v.is_empty())
}

// ============================================================================
// PEP 691 JSON responses — typed structs per spec
// ============================================================================

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
struct FileEntry {
    filename: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
    /// PEP 503 `data-requires-python`, unescaped (e.g. `>=3.8`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requires_python: Option<String>,
    /// PEP 592 `data-yanked`: `Some("")` is yanked without a reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    yanked: Option<String>,
    /// PEP 658/714 `data-core-metadata` value: `true` or `sha256=<hex>`. Set only where
    /// nora can serve `<file>.metadata`: a stored copy, or the upstream's own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    core_metadata: Option<String>,
    /// Upstream entries only: the file's absolute URL (no fragment) and the configured
    /// upstream that lists it, so a download or `.metadata` request is resolved from the
    /// cached index instead of refetching the project page (R2-27).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    upstream: Option<String>,
}

/// PEP 691 top-level response — typed to prevent field-name drift.
#[derive(serde::Serialize)]
struct Pep691Response<'a> {
    meta: Pep691Meta,
    name: &'a str,
    /// PEP 700: sorted, de-duplicated release versions present in `files`.
    versions: Vec<String>,
    files: Vec<Pep691File>,
}

#[derive(serde::Serialize)]
struct Pep691Meta {
    #[serde(rename = "api-version")]
    api_version: &'static str,
}

/// PEP 691 file entry — field `hashes` (NOT `digests`) per spec.
/// `upload-time` and `size` are PEP 700 (api-version 1.1) additions.
#[derive(serde::Serialize)]
struct Pep691File {
    filename: String,
    url: String,
    /// Always present, `{}` when no digest is known: PEP 691 says it MUST be (R2-29).
    hashes: Pep691Hashes,
    /// PEP 700 upload-time (RFC3339), when known (from the cached dates.json).
    #[serde(rename = "upload-time", skip_serializing_if = "Option::is_none")]
    upload_time: Option<String>,
    /// PEP 700 file size in bytes, when the artifact is stored locally.
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    #[serde(rename = "requires-python", skip_serializing_if = "Option::is_none")]
    requires_python: Option<String>,
    /// PEP 691: `true`, or the yank reason as a string.
    #[serde(skip_serializing_if = "Option::is_none")]
    yanked: Option<serde_json::Value>,
    /// PEP 658/714: `true` or `{"sha256": ...}`.
    #[serde(rename = "core-metadata", skip_serializing_if = "Option::is_none")]
    core_metadata: Option<serde_json::Value>,
    /// The pre-PEP 714 name of `core-metadata`, still read by older pip.
    #[serde(rename = "dist-info-metadata", skip_serializing_if = "Option::is_none")]
    dist_info_metadata: Option<serde_json::Value>,
}

#[derive(serde::Serialize)]
struct Pep691Hashes {
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
}

/// Render the PEP 691 + PEP 700 simple JSON. `pep700` maps filename → (size,
/// upload-time), gathered by [`collect_pep700_meta`] from storage + the cached
/// dates.json; a missing entry omits those (optional) per-file fields. Pure/sync so
/// it stays unit-testable without a storage backend.
fn versions_json_response(
    normalized: &str,
    files: &[FileEntry],
    base_url: &str,
    pep700: &std::collections::HashMap<String, (Option<u64>, Option<String>)>,
) -> Response {
    let base = base_url.trim_end_matches('/');
    let pep691_files: Vec<Pep691File> = files
        .iter()
        .map(|f| {
            let (size, upload_time) = pep700.get(&f.filename).cloned().unwrap_or((None, None));
            // `sha256=<hex>` becomes `{"sha256": "<hex>"}`, anything else `true`.
            let core_metadata = f.core_metadata.as_ref().map(|v| match v.split_once('=') {
                Some((alg, hash)) => serde_json::Value::Object(
                    [(alg.to_string(), serde_json::Value::from(hash))]
                        .into_iter()
                        .collect(),
                ),
                None => serde_json::Value::Bool(true),
            });
            Pep691File {
                filename: f.filename.clone(),
                url: format!("{}/simple/{}/{}", base, normalized, f.filename),
                hashes: Pep691Hashes {
                    sha256: f.sha256.clone(),
                },
                upload_time,
                size,
                requires_python: f.requires_python.clone(),
                yanked: f.yanked.as_ref().map(|r| {
                    if r.is_empty() {
                        serde_json::Value::Bool(true)
                    } else {
                        serde_json::Value::String(r.clone())
                    }
                }),
                dist_info_metadata: core_metadata.clone(),
                core_metadata,
            }
        })
        .collect();

    let body = Pep691Response {
        // PEP 700 support is signalled by api-version 1.1.
        meta: Pep691Meta { api_version: "1.1" },
        name: normalized,
        versions: versions_from_filenames(files),
        files: pep691_files,
    };

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, PEP691_JSON)],
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response()
}

/// PEP 700 project `versions`: sorted, de-duplicated release versions parsed from
/// the wheel/sdist filenames in the file list (best-effort).
fn versions_from_filenames(files: &[FileEntry]) -> Vec<String> {
    let mut vs: Vec<String> = files
        .iter()
        .filter_map(|f| version_from_filename(&f.filename))
        .collect();
    vs.sort();
    vs.dedup();
    vs
}

/// Extract the release version from a wheel, egg or sdist filename (best-effort).
pub(crate) fn version_from_filename(filename: &str) -> Option<String> {
    split_dist_filename(filename).map(|(_, version)| version.to_string())
}

/// `(distribution, version)` of a distribution filename (best-effort):
/// wheel/egg: `{distribution}-{version}(-{build})?-{py}-...`
/// sdist: `{name}-{version}.tar.gz|.tar.bz2|.tar.xz|.tgz|.zip`
pub(crate) fn split_dist_filename(filename: &str) -> Option<(&str, &str)> {
    if let Some(stem) = filename
        .strip_suffix(".whl")
        .or_else(|| filename.strip_suffix(".egg"))
    {
        let mut parts = stem.splitn(3, '-');
        let (name, version) = (parts.next()?, parts.next()?);
        return (!name.is_empty() && !version.is_empty()).then_some((name, version));
    }
    for ext in [".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip"] {
        if let Some(stem) = filename.strip_suffix(ext) {
            return stem
                .rsplit_once('-')
                .filter(|(name, version)| !name.is_empty() && !version.is_empty());
        }
    }
    None
}

/// Loose PEP 440 comparison key: case, a leading `v`, separators, leading zeros, trailing
/// `.0` release components and the alternate pre/post-release spellings do not matter
/// (`v1.0-RC.01` and `1.0.0rc1` are one version), as `packaging.Version` equality has it.
fn version_key(version: &str) -> Vec<String> {
    let version = version.trim().to_ascii_lowercase();
    let version = version.strip_prefix('v').unwrap_or(&version);
    let (public, local) = version.split_once('+').unwrap_or((version, ""));
    let tokens = |s: &str| -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut rest = s;
        while let Some(c) = rest.chars().next() {
            let len = if c.is_ascii_digit() {
                rest.find(|c: char| !c.is_ascii_digit())
            } else if c.is_ascii_alphabetic() {
                rest.find(|c: char| !c.is_ascii_alphabetic())
            } else {
                Some(c.len_utf8()) // a separator
            }
            .unwrap_or(rest.len());
            let (token, tail) = rest.split_at(len);
            rest = tail;
            if c.is_ascii_digit() {
                let trimmed = token.trim_start_matches('0');
                out.push(if trimmed.is_empty() { "0" } else { trimmed }.to_string());
            } else if c.is_ascii_alphabetic() {
                out.push(
                    match token {
                        "alpha" => "a",
                        "beta" => "b",
                        "c" | "pre" | "preview" => "rc",
                        "rev" | "r" => "post",
                        other => other,
                    }
                    .to_string(),
                );
            }
        }
        out
    };
    let mut key = tokens(public);
    let release = key
        .iter()
        .position(|t| !t.starts_with(|c: char| c.is_ascii_digit()))
        .unwrap_or(key.len());
    let trailing_zeros = key[..release]
        .iter()
        .skip(1)
        .rev()
        .take_while(|t| *t == "0")
        .count();
    key.drain(release - trailing_zeros..release);
    if !local.is_empty() {
        key.push("+".to_string());
        key.extend(tokens(local));
    }
    key
}

/// Why an uploaded `filename` cannot belong to release `version` of project `normalized`.
fn upload_filename_mismatch(filename: &str, normalized: &str, version: &str) -> Option<String> {
    let Some((dist, file_version)) = split_dist_filename(filename) else {
        return Some(format!("cannot read the project and version of {filename}"));
    };
    if normalize_name(dist) != normalized {
        return Some(format!("{filename} is not a file of project {normalized}"));
    }
    if version_key(file_version) != version_key(version) {
        return Some(format!("{filename} is not a file of version {version}"));
    }
    None
}

/// The PEP 658 core metadata of a wheel: its root-level `*.dist-info/METADATA`. `None`
/// when the archive is not a zip, has no single such entry, or it is too large.
pub(crate) fn wheel_core_metadata(data: impl std::io::Read + std::io::Seek) -> Option<Vec<u8>> {
    use std::io::Read as _;
    let mut zip = zip::ZipArchive::new(data).ok()?;
    let names: Vec<String> = zip
        .file_names()
        .filter(|n| {
            n.split_once('/')
                .is_some_and(|(dir, rest)| rest == "METADATA" && dir.ends_with(".dist-info"))
        })
        .map(str::to_string)
        .collect();
    let [name] = names.as_slice() else {
        return None;
    };
    let mut out = Vec::new();
    zip.by_name(name)
        .ok()?
        .take(MAX_CORE_METADATA_BYTES + 1)
        .read_to_end(&mut out)
        .ok()?;
    (out.len() as u64 <= MAX_CORE_METADATA_BYTES).then_some(out)
}

/// Store a wheel's core metadata as `<file>.metadata` with a hash marker, so the index
/// advertises `data-core-metadata="sha256=..."` from its one marker listing.
async fn put_core_metadata(
    storage: &crate::storage::Storage,
    project: &str,
    filename: &str,
    metadata: &[u8],
) {
    let key = format!("pypi/{project}/{filename}.metadata");
    if let Err(e) = storage.put(&key, metadata).await {
        tracing::warn!(key = %key, error = %e, "pypi: failed to store core metadata");
        return;
    }
    let sha256 = hex::encode(sha2::Sha256::digest(metadata));
    put_hash_marker(storage, project, &format!("{filename}.metadata"), &sha256).await;
}

/// Gather PEP 700 per-file metadata keyed by filename: `size` from the local
/// listing (`local_sizes`, built from `list_with_meta`) and `upload-time` from the
/// already-loaded `dates.json` map.
///
/// #969: this used to `stat()` every merged file — one HEAD per file on S3, issued
/// serially, so `/simple/{name}/` cost N round-trips against a proxied index of N
/// upstream files and uv timed out. Both inputs are now gathered by the single
/// listing and the single dates read the handler already performs, making this pure
/// and O(N) in memory only. Upstream-only files have no local size (a `stat()` would
/// have 404'd on them anyway), so both fields stay `None` and are omitted.
fn pep700_meta(
    files: &[FileEntry],
    local_sizes: &std::collections::HashMap<String, u64>,
    dates: &serde_json::Map<String, serde_json::Value>,
) -> std::collections::HashMap<String, (Option<u64>, Option<String>)> {
    let mut out = std::collections::HashMap::with_capacity(files.len());
    for f in files {
        let size = local_sizes.get(&f.filename).copied();
        let upload_time = dates
            .get(&f.filename)
            .and_then(|v| v.as_str())
            .map(str::to_string);
        out.insert(f.filename.clone(), (size, upload_time));
    }
    out
}

fn versions_html_response(normalized: &str, files: &[FileEntry], base_url: &str) -> Response {
    let base = base_url.trim_end_matches('/');
    let escaped = html_escape(normalized);
    let mut html = format!(
        "<!DOCTYPE html>\n<html><head><title>Links for {}</title></head><body><h1>Links for {}</h1>\n",
        escaped, escaped
    );

    for f in files {
        let hash_fragment = f
            .sha256
            .as_ref()
            .map(|h| format!("#sha256={}", h))
            .unwrap_or_default();
        let mut attrs = String::new();
        if let Some(rp) = &f.requires_python {
            let _ = write!(attrs, " data-requires-python=\"{}\"", html_escape(rp));
        }
        if let Some(reason) = &f.yanked {
            let _ = write!(attrs, " data-yanked=\"{}\"", html_escape(reason));
        }
        if let Some(meta) = &f.core_metadata {
            let meta = html_escape(meta);
            let _ = write!(
                attrs,
                " data-core-metadata=\"{meta}\" data-dist-info-metadata=\"{meta}\""
            );
        }
        let _ = writeln!(
            html,
            "<a href=\"{}/simple/{}/{}{}\"{}>{}</a><br>",
            base,
            normalized,
            html_escape(&f.filename),
            hash_fragment,
            attrs,
            html_escape(&f.filename)
        );
    }
    html.push_str("</body></html>");

    (StatusCode::OK, Html(html)).into_response()
}

// ============================================================================
// Helpers
// ============================================================================

/// Seconds a cached upstream index (and with trusted dates its `dates.json`) that
/// lacks a requested file is kept before that miss refetches it (bounds the upstream
/// lookups for a file no upstream lists or dates). Never above `pypi.metadata_ttl`.
const MISS_REFETCH_SECS: i64 = 60;

fn miss_ttl(state: &AppState) -> i64 {
    match state.config.pypi.metadata_ttl {
        ttl if ttl < 0 => MISS_REFETCH_SECS,
        ttl => ttl.min(MISS_REFETCH_SECS),
    }
}

/// Untrusted upstream dates (#513): NORA's own first-seen clock, the mtime of the
/// `dates.json` that listed the file (never rewritten in this mode). A file it does not
/// list appeared later: its date is unknown (`None`, curation policy decides), never
/// the older snapshot's.
async fn extract_pypi_publish_date(
    storage: &crate::storage::Storage,
    normalized: &str,
    filename: &str,
) -> Option<i64> {
    let dates_key = format!("pypi/{normalized}/dates.json");
    let data = storage.get(&dates_key).await.ok()?;
    let map: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(&data).ok()?;
    if !map.contains_key(filename) {
        return None;
    }
    crate::curation::extract_mtime_as_publish_date(storage, &dates_key).await
}

/// Cache a `filename → upload-time` map (`pypi/{name}/dates.json`) from the
/// upstream PEP 691 simple JSON (PEP 700 `upload-time`) and return it. Best-effort:
/// any failure returns the cached map (or none) and the quarantine clock falls back
/// to NORA's own time. The PEP 503 HTML index NORA fetches for the file *listing*
/// carries no dates, hence this JSON fetch.
///
/// With trusted upstream dates the map is written with the upstream index, as one
/// snapshot ([`upstream_index`], R2-24): a cached map is returned as is for the index
/// (`want` = `None`); one that does not list `want`, or no map at all, refreshes the
/// index (and with it the map) unless it is younger than the miss TTL, so a release
/// published after the snapshot is never dated by it. With untrusted dates a cached map
/// is never rewritten, its mtime is the first-seen clock ([`extract_pypi_publish_date`]).
///
/// #969: an upstream that answers but emits no `upload-time` (any pre-PEP-700 index —
/// devpi, Artifactory, an older NORA) used to leave nothing cached, so every single
/// `/simple/{name}/` JSON request re-downloaded the whole upstream JSON index. An
/// answered-but-dateless upstream is now recorded as an empty map, which reads back
/// identically for the quarantine clock (no entry for the file either way) and stops
/// the refetch. So is an upstream 404. A failed/open-breaker fetch still caches
/// nothing, so a transient outage stays retryable.
async fn ensure_pypi_dates_cached(
    state: &AppState,
    normalized: &str,
    want: Option<&str>,
) -> serde_json::Map<String, serde_json::Value> {
    let key = format!("pypi/{}/dates.json", normalized);
    let read = || async {
        state
            .storage
            .get(&key)
            .await
            .ok()
            .map(|data| serde_json::from_slice(&data).unwrap_or_default())
    };
    let trusted = state.config.server.trust_upstream_dates;
    let cached: Option<serde_json::Map<String, serde_json::Value>> = read().await;
    if let Some(map) = &cached {
        match want {
            _ if !trusted => return cached.unwrap_or_default(),
            Some(file) if map.contains_key(file) => return cached.unwrap_or_default(),
            None => return cached.unwrap_or_default(),
            Some(_) => {
                let fresh = state.storage.stat(&key).await.is_some_and(|meta| {
                    crate::cache_ttl::is_within_ttl(meta.modified, miss_ttl(state))
                });
                if fresh {
                    return cached.unwrap_or_default();
                }
            }
        }
    }
    // #68: never fetch an internal-namespace package's metadata upstream.
    if state.config.pypi.upstreams().is_empty()
        || crate::curation::is_internal_namespace(
            &state.curation().curation_engine,
            crate::curation::RegistryType::PyPI,
            normalized,
        )
    {
        return cached.unwrap_or_default();
    }
    if trusted {
        // R2-24: refetch the index, which refreshes the dates with it.
        let _ = upstream_index(state, normalized, None, 0).await;
        return read().await.or(cached).unwrap_or_default();
    }
    let refresh = || async {
        let map = fetch_upstream_dates(state, normalized).await?;
        // An empty map is still worth persisting once an upstream has actually answered:
        // it marks "this index carries no upload-time" and spares every later request
        // the full upstream JSON download (#969).
        let bytes = serde_json::to_vec(&map).ok()?;
        if let Err(e) = state.storage.put(&key, &bytes).await {
            tracing::warn!(key = %key, error = %e, "pypi: failed to cache dates");
        }
        Some(axum::body::Bytes::from(bytes))
    };
    let fetched = if state.config.server.proxy_coalesce {
        let budget = crate::proxy_coalesce::follower_budget(state.config.pypi.proxy_timeout)
            * state.config.pypi.upstreams().len().max(1) as u32;
        state
            .proxy_coalesce
            .coalesced(&format!("dates:{key}"), "pypi", budget, refresh)
            .await
    } else {
        refresh().await
    };
    fetched
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .or(cached)
        .unwrap_or_default()
}

/// The upload-time map of the first upstream whose PEP 691 JSON dates any file, an
/// empty map when the upstreams answered without dates (or 404), `None` when none
/// answered.
async fn fetch_upstream_dates(
    state: &AppState,
    normalized: &str,
) -> Option<serde_json::Map<String, serde_json::Value>> {
    let mut map = serde_json::Map::new();
    let mut upstream_answered = false;
    for up in &state.config.pypi.upstreams() {
        let url = format!("{}/{}/", up.url().trim_end_matches('/'), normalized);
        let text = match proxy_fetch_text(
            &state.http_client,
            &url,
            Duration::from_secs(state.config.pypi.proxy_timeout),
            up.auth().map(UpstreamAuth::Basic),
            Some(("Accept", PEP691_JSON)),
            &state.circuit_breaker,
            BreakerScope::upstream(RegistryType::PyPI, up.url()),
        )
        .await
        {
            Ok(text) => text,
            // A 404 is an answer: a project the upstream does not have (a private one)
            // has no dates there, and must not be asked again on every request.
            Err(crate::registry::ProxyError::NotFound) => {
                upstream_answered = true;
                continue;
            }
            Err(_) => continue,
        };
        upstream_answered = true;
        let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        if let Some(files) = json.get("files").and_then(|f| f.as_array()) {
            for fe in files {
                if let (Some(fname), Some(ut)) = (
                    fe.get("filename").and_then(|v| v.as_str()),
                    fe.get("upload-time").and_then(|v| v.as_str()),
                ) {
                    map.entry(fname.to_string())
                        .or_insert_with(|| serde_json::Value::String(ut.to_string()));
                }
            }
        }
        if !map.is_empty() {
            break; // first upstream that listed dated files wins
        }
    }
    upstream_answered.then_some(map)
}

/// Normalize package name according to PEP 503: lowercase, and every run of
/// `-`, `_`, `.` becomes a single `-` (`re.sub(r"[-_.]+", "-", name).lower()`).
pub(crate) fn normalize_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !out.ends_with('-') {
                out.push('-');
            }
        } else {
            out.extend(c.to_lowercase());
        }
    }
    out
}

/// Check Accept header for PEP 691 JSON.
fn wants_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains(PEP691_JSON))
        .unwrap_or(false)
}

/// Content-type for PyPI files.
fn pypi_content_type(filename: &str) -> &'static str {
    if ends_with_ci(filename, ".whl") {
        "application/zip"
    } else if ends_with_ci(filename, ".tar.gz") || ends_with_ci(filename, ".tgz") {
        "application/gzip"
    } else {
        "application/octet-stream"
    }
}

/// Storage prefix of the per-file SHA-256 markers: `pypi-sha256/<project>/<filename>/<sha256>`.
///
/// A marker is an empty object whose key carries the digest of one stored distribution
/// file, so one listing of `pypi-sha256/<project>/` yields every digest the simple index
/// needs instead of one sidecar read per file (a request per file on an object store).
/// Markers live outside `pypi/`, so listings of `pypi/` never take one for a distribution
/// file. The `.sha256` sidecar stays authoritative: a file without exactly one marker is
/// served from its sidecar.
pub(crate) const HASH_MARKER_PREFIX: &str = "pypi-sha256/";

/// Key of the marker recording `sha256` for `filename` of `project`.
/// Provenance marker of a file cached from an upstream (C22): proxied and uploaded
/// files share `pypi/<project>/<file>` keys, and only a proxied one may be evicted.
/// It lives under npm's `.nora-origins/` prefix, outside every listing.
pub(crate) fn proxied_marker_key(key: &str) -> String {
    crate::registry::npm::origin_key(key)
}

fn hash_marker_key(project: &str, filename: &str, sha256: &str) -> String {
    format!("{HASH_MARKER_PREFIX}{project}/{filename}/{sha256}")
}

/// `(filename, sha256)` of a marker key under `project_prefix` (`pypi-sha256/<project>/`),
/// or `None` for a key that is not a well-formed marker.
fn parse_hash_marker<'a>(project_prefix: &str, key: &'a str) -> Option<(&'a str, &'a str)> {
    let (filename, sha256) = key.strip_prefix(project_prefix)?.split_once('/')?;
    (!filename.is_empty() && is_sha256_hex(sha256)).then_some((filename, sha256))
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Record `sha256` as the one hash marker of `filename`: delete markers left for it with
/// another digest (the file was deleted and stored again with other bytes), then write its
/// own. A failed step is logged; the index serves a file with no marker, or with more than
/// one, from its sidecar.
async fn put_hash_marker(
    storage: &crate::storage::Storage,
    project: &str,
    filename: &str,
    sha256: &str,
) {
    let marker = hash_marker_key(project, filename, sha256);
    let file_prefix = format!("{HASH_MARKER_PREFIX}{project}/{filename}/");
    match storage.list(&file_prefix).await {
        Ok(existing) => {
            for stale in existing.iter().filter(|key| **key != marker) {
                if let Err(e) = storage.delete(stale).await {
                    tracing::warn!(key = %stale, error = %e, "pypi: failed to delete stale hash marker");
                }
            }
        }
        Err(e) => {
            tracing::warn!(prefix = %file_prefix, error = %e, "pypi: failed to list hash markers");
        }
    }
    if let Err(e) = storage.put(&marker, b"").await {
        tracing::warn!(key = %marker, error = %e, "pypi: failed to store hash marker");
    }
}

/// Write the hash marker of a stored file from its `.sha256` sidecar.
///
/// The sidecar is read under the file's publish lock, which upload and retention take to
/// store or delete the file, so the digest cannot belong to an earlier file of the same
/// name that was deleted and uploaded again after the index request that queued it.
async fn backfill_hash_marker(
    storage: &crate::storage::Storage,
    publish_locks: &crate::PublishLocks,
    project: &str,
    filename: &str,
) {
    let file_key = format!("pypi/{project}/{filename}");
    let lock = crate::acquire_publish_lock(publish_locks, &file_key);
    let _guard = lock.lock().await;
    if storage.stat(&file_key).await.is_none() {
        return;
    }
    let Ok(data) = storage.get(&format!("{file_key}.sha256")).await else {
        return;
    };
    let text = String::from_utf8_lossy(&data);
    let sha256 = text.trim();
    if is_sha256_hex(sha256) {
        put_hash_marker(storage, project, filename, sha256).await;
    }
}

/// Validate PyPI filename.
pub(crate) fn is_valid_pypi_filename(name: &str) -> bool {
    !name.is_empty()
        && !name.contains("..")
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
        && (ends_with_ci(name, ".tar.gz")
            || ends_with_ci(name, ".tgz")
            || ends_with_ci(name, ".whl")
            || ends_with_ci(name, ".zip")
            || ends_with_ci(name, ".egg"))
}

/// Extract filename from PyPI download URL.
fn extract_filename(url: &str) -> Option<&str> {
    let url = url.split('#').next()?;
    let filename = url.rsplit('/').next()?;

    if ends_with_ci(filename, ".tar.gz")
        || ends_with_ci(filename, ".tgz")
        || ends_with_ci(filename, ".whl")
        || ends_with_ci(filename, ".zip")
        || ends_with_ci(filename, ".egg")
    {
        Some(filename)
    } else {
        None
    }
}

/// Parse upstream PyPI simple index HTML into file entries.
///
/// Extracts filenames, optional `#sha256=` fragments and the PEP 503/592
/// `data-requires-python` / `data-yanked` attributes from `<a href="...">` links.
/// Filenames are percent-decoded (`%2B` -> `+`), the form the download route sees; each
/// `url` is the href without its fragment, still encoded, resolved against `page_url`
/// (relative hrefs of some mirrors: Tsinghua, USTC, Aliyun, #877).
fn parse_upstream_files(html: &str, page_url: &str) -> Vec<FileEntry> {
    let base = reqwest::Url::parse(page_url).ok();
    let mut files = Vec::new();
    let mut offset = 0;

    while let Some(href_start) = html[offset..].find("href=\"") {
        let value_start = offset + href_start + 6;
        let Some(href_len) = html[value_start..].find('"') else {
            break;
        };
        let url = &html[value_start..value_start + href_len];
        offset = value_start + href_len;
        if let Some(filename) = extract_filename(url) {
            // The anchor's attributes: from its `<a` to the first `>` outside quotes
            // (some mirrors leave `data-requires-python=">=3.8"` unescaped).
            let tag_start = html[..value_start].rfind("<a").unwrap_or(0);
            let mut quoted = false;
            let tag_end = html[offset + 1..]
                .char_indices()
                .find(|&(_, c)| {
                    quoted ^= c == '"';
                    c == '>' && !quoted
                })
                .map_or(html.len(), |(e, _)| offset + 1 + e);
            let tag = &html[tag_start..tag_end];
            let raw = url.split('#').next().unwrap_or(url);
            let resolved = if raw.starts_with("http://") || raw.starts_with("https://") {
                raw.to_string()
            } else {
                base.as_ref()
                    .and_then(|base| base.join(raw).ok())
                    .map_or_else(|| raw.to_string(), |u| u.to_string())
            };
            files.push(FileEntry {
                filename: percent_encoding::percent_decode_str(filename)
                    .decode_utf8_lossy()
                    .into_owned(),
                sha256: url.find("#sha256=").map(|pos| url[pos + 8..].to_string()),
                requires_python: html_attr(tag, "data-requires-python").map(html_unescape),
                yanked: html_attr(tag, "data-yanked").map(html_unescape),
                core_metadata: html_attr(tag, "data-core-metadata")
                    .or_else(|| html_attr(tag, "data-dist-info-metadata"))
                    .map(html_unescape),
                url: Some(resolved),
                upstream: None,
            });
        }
    }
    files
}

/// Value of a double-quoted attribute `name="..."` inside an HTML tag, raw (still escaped).
fn html_attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("{name}=\"");
    let mut from = 0;
    while let Some(pos) = tag[from..].find(&needle) {
        let start = from + pos;
        from = start + needle.len();
        // Whole attribute name only: `data-yanked` must not match `xdata-yanked`.
        if tag[..start].ends_with(|c: char| c.is_ascii_whitespace()) {
            let end = tag[from..].find('"')?;
            return Some(&tag[from..from + end]);
        }
    }
    None
}

/// Reverse the entity escaping index pages apply to attribute values.
fn html_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
        .replace("&amp;", "&")
}

/// Merge upstream and local file lists.
///
/// Local entries take precedence (they have verified hashes from storage).
/// Upstream entries are added only if no local file with the same name exists.
fn merge_file_lists(upstream: Vec<FileEntry>, local: &[FileEntry]) -> Vec<FileEntry> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut result = Vec::with_capacity(upstream.len() + local.len());

    // Local first (highest precedence). Dedup local against itself too: storage
    // listings are unique by construction, but keep the merge total so the output
    // never carries a duplicate filename regardless of caller input.
    for f in local {
        if seen.insert(f.filename.clone()) {
            result.push(f.clone());
        }
    }

    // `upstream` is concatenated across upstreams in precedence order; keep the
    // first entry seen for each filename so the highest-precedence upstream wins
    // and a file present on several upstreams (or already local) is not listed
    // twice (#663).
    for f in upstream {
        if seen.insert(f.filename.clone()) {
            result.push(f);
        } else if let Some(cached) = result.iter_mut().find(|r| r.filename == f.filename) {
            // A proxied file cached locally keeps the upstream's PEP 503/592
            // metadata: local storage does not record it. Not its core metadata: a
            // local file of the same name may hold other bytes than the upstream's,
            // so only a `.metadata` stored next to it is advertised.
            cached.requires_python = cached.requires_python.take().or(f.requires_python);
            cached.yanked = cached.yanked.take().or(f.yanked);
        }
    }

    result
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The resolved URL and lower-cased `#sha256=` of `target` in an upstream index page.
    fn find_file_url(html: &str, target: &str, page_url: &str) -> Option<(String, Option<String>)> {
        parse_upstream_files(html, page_url)
            .into_iter()
            .find(|f| f.filename == target)
            .map(|f| (f.url.unwrap(), f.sha256.map(|h| h.to_ascii_lowercase())))
    }

    fn find_url(html: &str, target: &str, page_url: &str) -> Option<String> {
        find_file_url(html, target, page_url).map(|(url, _)| url)
    }

    proptest! {
        #[test]
        fn extract_filename_never_panics(s in "\\PC{0,500}") {
            let _ = extract_filename(&s);
        }

        #[test]
        fn extract_filename_valid_tarball(
            name in "[a-z][a-z0-9_-]{0,20}",
            version in "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"
        ) {
            let url = format!("https://files.example.com/packages/{}-{}.tar.gz", name, version);
            let result = extract_filename(&url);
            prop_assert!(result.is_some());
            prop_assert!(result.unwrap().ends_with(".tar.gz"));
        }

        #[test]
        fn extract_filename_valid_wheel(
            name in "[a-z][a-z0-9_]{0,20}",
            version in "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"
        ) {
            let url = format!("https://files.example.com/{}-{}-py3-none-any.whl", name, version);
            let result = extract_filename(&url);
            prop_assert!(result.is_some());
            prop_assert!(result.unwrap().ends_with(".whl"));
        }

        #[test]
        fn extract_filename_strips_hash(
            name in "[a-z]{1,10}",
            hash in "[a-f0-9]{64}"
        ) {
            let url = format!("https://example.com/{}.tar.gz#sha256={}", name, hash);
            let result = extract_filename(&url);
            prop_assert!(result.is_some());
            let fname = result.unwrap();
            prop_assert!(!fname.contains('#'));
        }

        #[test]
        fn extract_filename_rejects_unknown_ext(
            name in "[a-z]{1,10}",
            ext in "(exe|dll|so|bin|dat)"
        ) {
            let url = format!("https://example.com/{}.{}", name, ext);
            prop_assert!(extract_filename(&url).is_none());
        }
    }

    #[test]
    fn test_normalize_name_lowercase() {
        assert_eq!(normalize_name("Flask"), "flask");
        assert_eq!(normalize_name("REQUESTS"), "requests");
    }

    #[test]
    fn find_file_url_matches_percent_encoded_plus() {
        // #664: PyTorch indexes encode '+' as %2B in hrefs, but the requested
        // filename arrives decoded — matching must decode, and the returned URL
        // must stay encoded so the upstream fetch resolves.
        let html = concat!(
            r#"<a href="https://download.pytorch.org/whl/cu124/"#,
            r#"torch-2.4.0%2Bcu124-cp310-cp310-linux_x86_64.whl#sha256=abc">"#,
            r#"torch-2.4.0+cu124-cp310-cp310-linux_x86_64.whl</a>"#,
        );
        assert_eq!(
            find_url(html, "torch-2.4.0+cu124-cp310-cp310-linux_x86_64.whl", "https://pypi.org/simple/torch/").as_deref(),
            Some(
                "https://download.pytorch.org/whl/cu124/torch-2.4.0%2Bcu124-cp310-cp310-linux_x86_64.whl"
            )
        );
        // A plain filename (no encoding) still matches.
        let plain = r#"<a href="https://x/torch-0.1.10-cp36-cp36m-macosx.whl">x</a>"#;
        assert_eq!(
            find_url(
                plain,
                "torch-0.1.10-cp36-cp36m-macosx.whl",
                "https://pypi.org/simple/torch/"
            )
            .as_deref(),
            Some("https://x/torch-0.1.10-cp36-cp36m-macosx.whl")
        );
    }

    #[test]
    fn test_normalize_name_separators() {
        assert_eq!(normalize_name("my-package"), "my-package");
        assert_eq!(normalize_name("my_package"), "my-package");
        assert_eq!(normalize_name("my.package"), "my-package");
    }

    #[test]
    fn test_normalize_name_mixed() {
        assert_eq!(
            normalize_name("My_Complex.Package-Name"),
            "my-complex-package-name"
        );
    }

    #[test]
    fn test_normalize_name_empty() {
        assert_eq!(normalize_name(""), "");
    }

    #[test]
    fn test_normalize_name_already_normal() {
        assert_eq!(normalize_name("simple"), "simple");
    }

    #[test]
    fn test_extract_filename_tarball() {
        assert_eq!(
            extract_filename(
                "https://files.pythonhosted.org/packages/aa/bb/flask-2.0.0.tar.gz#sha256=abc123"
            ),
            Some("flask-2.0.0.tar.gz")
        );
    }

    #[test]
    fn test_extract_filename_wheel() {
        assert_eq!(
            extract_filename(
                "https://files.pythonhosted.org/packages/aa/bb/flask-2.0.0-py3-none-any.whl"
            ),
            Some("flask-2.0.0-py3-none-any.whl")
        );
    }

    #[test]
    fn test_extract_filename_tgz() {
        assert_eq!(
            extract_filename("https://example.com/package-1.0.tgz"),
            Some("package-1.0.tgz")
        );
    }

    #[test]
    fn test_extract_filename_zip() {
        assert_eq!(
            extract_filename("https://example.com/package-1.0.zip"),
            Some("package-1.0.zip")
        );
    }

    #[test]
    fn test_extract_filename_egg() {
        assert_eq!(
            extract_filename("https://example.com/package-1.0.egg"),
            Some("package-1.0.egg")
        );
    }

    #[test]
    fn test_extract_filename_unknown_ext() {
        assert_eq!(extract_filename("https://example.com/readme.txt"), None);
    }

    #[test]
    fn test_extract_filename_no_path() {
        assert_eq!(extract_filename(""), None);
    }

    #[test]
    fn test_extract_filename_bare() {
        assert_eq!(
            extract_filename("package-1.0.tar.gz"),
            Some("package-1.0.tar.gz")
        );
    }

    #[test]
    fn test_find_file_url_found() {
        let html = r#"<a href="https://files.pythonhosted.org/packages/aa/bb/flask-2.0.tar.gz#sha256=abc">flask-2.0.tar.gz</a>"#;
        let result = find_url(html, "flask-2.0.tar.gz", "https://pypi.org/simple/flask/");
        assert_eq!(
            result,
            Some("https://files.pythonhosted.org/packages/aa/bb/flask-2.0.tar.gz".to_string())
        );
    }

    #[test]
    fn test_find_file_url_not_found() {
        let html = r#"<a href="https://example.com/other-1.0.tar.gz">other</a>"#;
        let result = find_url(html, "flask-2.0.tar.gz", "https://pypi.org/simple/flask/");
        assert_eq!(result, None);
    }

    #[test]
    fn test_find_file_url_strips_hash() {
        let html = r#"<a href="https://example.com/pkg-1.0.whl#sha256=DEADBEEF">pkg</a>"#;
        let result = find_url(html, "pkg-1.0.whl", "https://pypi.org/simple/pkg/");
        assert_eq!(result, Some("https://example.com/pkg-1.0.whl".to_string()));
        let (_, sha256) =
            find_file_url(html, "pkg-1.0.whl", "https://pypi.org/simple/pkg/").unwrap();
        assert_eq!(sha256.as_deref(), Some("deadbeef"));
    }

    // -- #877: relative URL resolution --

    #[test]
    fn test_find_file_url_relative() {
        let html = r#"<a href="../../packages/torch-2.4.0.whl#sha256=abc">torch-2.4.0.whl</a>"#;
        let result = find_url(
            html,
            "torch-2.4.0.whl",
            "https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple/torch/",
        );
        assert_eq!(
            result,
            Some(
                "https://mirrors.tuna.tsinghua.edu.cn/pypi/web/packages/torch-2.4.0.whl"
                    .to_string()
            )
        );
    }

    #[test]
    fn test_find_file_url_absolute_unchanged() {
        let html = r#"<a href="https://files.pythonhosted.org/packages/ab/cd/pkg-1.0.whl">pkg-1.0.whl</a>"#;
        let result = find_url(
            html,
            "pkg-1.0.whl",
            "https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple/pkg/",
        );
        assert_eq!(
            result,
            Some("https://files.pythonhosted.org/packages/ab/cd/pkg-1.0.whl".to_string())
        );
    }

    #[test]
    fn test_find_file_url_path_only() {
        let html = r#"<a href="/packages/pkg-1.0.whl#sha256=ff">pkg-1.0.whl</a>"#;
        let result = find_url(html, "pkg-1.0.whl", "https://pypi.example.com/simple/pkg/");
        assert_eq!(
            result,
            Some("https://pypi.example.com/packages/pkg-1.0.whl".to_string())
        );
    }

    #[test]
    fn test_is_valid_pypi_filename() {
        assert!(is_valid_pypi_filename("flask-2.0.tar.gz"));
        assert!(is_valid_pypi_filename("flask-2.0-py3-none-any.whl"));
        assert!(is_valid_pypi_filename("flask-2.0.tgz"));
        assert!(is_valid_pypi_filename("flask-2.0.zip"));
        assert!(is_valid_pypi_filename("flask-2.0.egg"));
        assert!(!is_valid_pypi_filename(""));
        assert!(!is_valid_pypi_filename("../evil.tar.gz"));
        assert!(!is_valid_pypi_filename("evil/path.tar.gz"));
        assert!(!is_valid_pypi_filename("noext"));
        assert!(!is_valid_pypi_filename("bad.exe"));
    }

    #[test]
    fn test_wants_json_pep691() {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, PEP691_JSON.parse().unwrap());
        assert!(wants_json(&headers));
    }

    #[test]
    fn test_wants_json_html() {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, "text/html".parse().unwrap());
        assert!(!wants_json(&headers));
    }

    #[test]
    fn test_wants_json_no_header() {
        let headers = HeaderMap::new();
        assert!(!wants_json(&headers));
    }

    // --- parse_upstream_files ---

    #[test]
    fn test_parse_upstream_files_basic() {
        let html = r#"<a href="https://files.example.com/pkg-1.0-cp310-cp310-linux_x86_64.whl#sha256=aaa">pkg</a>
<a href="https://files.example.com/pkg-1.0-cp314-cp314-linux_x86_64.whl#sha256=bbb">pkg</a>"#;
        let files = parse_upstream_files(html, "https://pypi.org/simple/x/");
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].filename, "pkg-1.0-cp310-cp310-linux_x86_64.whl");
        assert_eq!(files[0].sha256.as_deref(), Some("aaa"));
        assert_eq!(files[1].filename, "pkg-1.0-cp314-cp314-linux_x86_64.whl");
        assert_eq!(files[1].sha256.as_deref(), Some("bbb"));
    }

    #[test]
    fn test_parse_upstream_files_no_hash() {
        let html = r#"<a href="https://example.com/pkg-1.0.tar.gz">pkg</a>"#;
        let files = parse_upstream_files(html, "https://pypi.org/simple/x/");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].filename, "pkg-1.0.tar.gz");
        assert!(files[0].sha256.is_none());
    }

    #[test]
    fn test_parse_upstream_files_empty() {
        assert!(parse_upstream_files("", "https://pypi.org/simple/x/").is_empty());
        assert!(
            parse_upstream_files("<html><body></body></html>", "https://pypi.org/simple/x/")
                .is_empty()
        );
    }

    #[test]
    fn test_parse_upstream_files_skips_non_package_links() {
        let html = r#"<a href="https://example.com/readme.txt">readme</a>
<a href="https://example.com/pkg-1.0.whl#sha256=abc">pkg</a>"#;
        let files = parse_upstream_files(html, "https://pypi.org/simple/x/");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].filename, "pkg-1.0.whl");
    }

    // --- merge_file_lists ---

    #[test]
    fn test_merge_disjoint() {
        let upstream = vec![FileEntry {
            filename: "pkg-1.0-cp314-cp314-linux_x86_64.whl".to_string(),
            sha256: Some("uuu".to_string()),
            ..Default::default()
        }];
        let local = vec![FileEntry {
            filename: "pkg-1.0-cp310-cp310-linux_x86_64.whl".to_string(),
            sha256: Some("lll".to_string()),
            ..Default::default()
        }];
        let merged = merge_file_lists(upstream, &local);
        assert_eq!(merged.len(), 2);
        // Local first
        assert_eq!(merged[0].filename, "pkg-1.0-cp310-cp310-linux_x86_64.whl");
        assert_eq!(merged[1].filename, "pkg-1.0-cp314-cp314-linux_x86_64.whl");
    }

    #[test]
    fn test_merge_local_wins_on_duplicate() {
        let upstream = vec![FileEntry {
            filename: "pkg-1.0.tar.gz".to_string(),
            sha256: Some("upstream-hash".to_string()),
            ..Default::default()
        }];
        let local = vec![FileEntry {
            filename: "pkg-1.0.tar.gz".to_string(),
            sha256: Some("local-verified-hash".to_string()),
            ..Default::default()
        }];
        let merged = merge_file_lists(upstream, &local);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].sha256.as_deref(), Some("local-verified-hash"));
    }

    #[test]
    fn test_merge_empty_upstream() {
        let local = vec![FileEntry {
            filename: "pkg-1.0.tar.gz".to_string(),
            sha256: None,
            ..Default::default()
        }];
        let merged = merge_file_lists(vec![], &local);
        assert_eq!(merged.len(), 1);
    }

    #[test]
    fn test_merge_empty_local() {
        let upstream = vec![FileEntry {
            filename: "pkg-1.0.tar.gz".to_string(),
            sha256: Some("hash".to_string()),
            ..Default::default()
        }];
        let merged = merge_file_lists(upstream, &[]);
        assert_eq!(merged.len(), 1);
    }

    #[test]
    fn test_merge_both_empty() {
        let merged = merge_file_lists(vec![], &[]);
        assert!(merged.is_empty());
    }

    #[test]
    fn test_merge_first_upstream_wins_and_dedups() {
        // Multi-upstream (#663): `upstream` is the upstreams concatenated in
        // precedence order. The same filename from upstream A (first) and B must
        // be deduped to a single entry, and A wins.
        let upstream = vec![
            FileEntry {
                filename: "torch-1.0.whl".to_string(),
                sha256: Some("from-A".to_string()),
                ..Default::default()
            },
            FileEntry {
                filename: "torch-1.0.whl".to_string(),
                sha256: Some("from-B".to_string()),
                ..Default::default()
            },
            FileEntry {
                filename: "torchvision-1.0.whl".to_string(),
                sha256: Some("from-B".to_string()),
                ..Default::default()
            },
        ];
        let merged = merge_file_lists(upstream, &[]);
        assert_eq!(
            merged.len(),
            2,
            "duplicate filename across upstreams deduped"
        );
        let torch = merged
            .iter()
            .find(|f| f.filename == "torch-1.0.whl")
            .unwrap();
        assert_eq!(
            torch.sha256.as_deref(),
            Some("from-A"),
            "first upstream (A) wins precedence"
        );
        assert!(merged.iter().any(|f| f.filename == "torchvision-1.0.whl"));
    }

    proptest! {
        #[test]
        fn prop_merge_no_duplicate_filenames_and_local_wins(
            upstream_names in prop::collection::vec("[a-z]{1,6}", 0..20),
            local_names in prop::collection::vec("[a-z]{1,6}", 0..6),
        ) {
            let upstream: Vec<FileEntry> = upstream_names
                .iter()
                .map(|n| FileEntry { filename: n.clone(), sha256: None, ..Default::default() })
                .collect();
            let local: Vec<FileEntry> = local_names
                .iter()
                .map(|n| FileEntry { filename: n.clone(), sha256: Some("L".to_string()), ..Default::default() })
                .collect();
            let merged = merge_file_lists(upstream, &local);
            // No filename appears twice.
            let mut seen = std::collections::HashSet::new();
            for f in &merged {
                prop_assert!(seen.insert(f.filename.clone()), "duplicate filename in merge");
            }
            // Every local file survives, and local wins on collision.
            for ln in &local_names {
                let e = merged.iter().find(|f| &f.filename == ln);
                prop_assert!(e.is_some());
                prop_assert_eq!(e.unwrap().sha256.as_deref(), Some("L"));
            }
        }
    }

    // --- PEP 503 / 592 attributes on the proxied index ---

    #[test]
    fn test_normalize_name_collapses_separator_runs() {
        assert_eq!(normalize_name("foo__bar"), "foo-bar");
        assert_eq!(normalize_name("Foo.-Bar"), "foo-bar");
        assert_eq!(normalize_name("a._-b"), "a-b");
        assert_eq!(normalize_name("zope.interface"), "zope-interface");
    }

    #[test]
    fn test_parse_upstream_files_keeps_requires_python_and_yanked() {
        let html = concat!(
            r#"<a href="https://f/pkg-1.0.tar.gz#sha256=aa" data-requires-python="&gt;=3.8,&lt;4">pkg-1.0.tar.gz</a>"#,
            "\n",
            r#"<a data-yanked="" href="https://f/pkg-1.1.tar.gz#sha256=bb">pkg-1.1.tar.gz</a>"#,
            "\n",
            r#"<a href="https://f/pkg-1.2.tar.gz" data-yanked="broken &amp; bad">pkg-1.2.tar.gz</a>"#,
            "\n",
            r#"<a href="https://f/torch-2.4.0%2Bcu124-cp310-none-any.whl">x</a>"#,
            "\n",
            r#"<a data-requires-python="<4" href="https://f/pkg-2.0.tar.gz" data-yanked=">old">x</a>"#,
        );
        let files = parse_upstream_files(html, "https://pypi.org/simple/x/");
        assert_eq!(files.len(), 5);
        // Unescaped `<` / `>` inside attribute values (lenient mirrors).
        assert_eq!(files[4].requires_python.as_deref(), Some("<4"));
        assert_eq!(files[4].yanked.as_deref(), Some(">old"));
        assert_eq!(files[0].requires_python.as_deref(), Some(">=3.8,<4"));
        assert_eq!(files[0].yanked, None);
        // An attribute before href belongs to the same anchor.
        assert_eq!(files[1].yanked.as_deref(), Some(""));
        assert_eq!(files[1].sha256.as_deref(), Some("bb"));
        assert_eq!(files[2].yanked.as_deref(), Some("broken & bad"));
        assert_eq!(files[2].requires_python, None);
        // #664: the index lists the decoded name, the one the download route matches.
        assert_eq!(files[3].filename, "torch-2.4.0+cu124-cp310-none-any.whl");
    }

    #[test]
    fn test_index_attributes_round_trip_html_and_json() {
        let files = vec![
            FileEntry {
                filename: "pkg-1.0.tar.gz".into(),
                sha256: Some("aa".into()),
                requires_python: Some(">=3.8".into()),
                yanked: None,
                core_metadata: Some("sha256=cc".into()),
                ..Default::default()
            },
            FileEntry {
                filename: "pkg-1.1.tar.gz".into(),
                yanked: Some(String::new()),
                core_metadata: Some("true".into()),
                ..Default::default()
            },
            FileEntry {
                filename: "pkg-1.2.tar.gz".into(),
                yanked: Some("bad \"build\"".into()),
                ..Default::default()
            },
        ];
        let body = |r: Response| {
            futures::executor::block_on(axum::body::to_bytes(r.into_body(), 1 << 20)).unwrap()
        };

        let html = body(versions_html_response("pkg", &files, "http://nora"));
        let html = std::str::from_utf8(&html).unwrap();
        assert!(
            html.contains(r#"data-requires-python="&gt;=3.8""#),
            "{html}"
        );
        let parsed = parse_upstream_files(html, "https://pypi.org/simple/x/");
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].requires_python.as_deref(), Some(">=3.8"));
        assert_eq!(parsed[0].sha256.as_deref(), Some("aa"));
        assert_eq!(parsed[1].yanked.as_deref(), Some(""));
        assert_eq!(parsed[2].yanked.as_deref(), Some("bad \"build\""));
        // PEP 658/714: both attribute names, read back from either.
        assert!(
            html.contains(r#"data-core-metadata="sha256=cc" data-dist-info-metadata="sha256=cc""#),
            "{html}"
        );
        assert_eq!(parsed[0].core_metadata.as_deref(), Some("sha256=cc"));
        assert_eq!(parsed[1].core_metadata.as_deref(), Some("true"));
        assert_eq!(parsed[2].core_metadata, None);
        let legacy = parse_upstream_files(
            r#"<a href="https://up/pkg-1.0-py3-none-any.whl" data-dist-info-metadata="sha256=dd">x</a>"#,
            "https://pypi.org/simple/pkg/",
        );
        assert_eq!(legacy[0].core_metadata.as_deref(), Some("sha256=dd"));

        let json = body(versions_json_response(
            "pkg",
            &files,
            "http://nora",
            &Default::default(),
        ));
        let json: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(json["files"][0]["requires-python"], ">=3.8");
        assert!(json["files"][0].get("yanked").is_none());
        assert_eq!(json["files"][1]["yanked"], true);
        assert_eq!(json["files"][2]["yanked"], "bad \"build\"");
        assert!(json["files"][1].get("requires-python").is_none());
        assert_eq!(json["files"][0]["core-metadata"]["sha256"], "cc");
        assert_eq!(json["files"][0]["dist-info-metadata"]["sha256"], "cc");
        assert_eq!(json["files"][1]["core-metadata"], true);
        assert!(json["files"][2].get("core-metadata").is_none());
    }

    #[test]
    fn test_upload_filename_must_match_project_and_version() {
        // PEP 440 spellings of one version compare equal.
        for (a, b) in [
            ("1.0.0rc1", "V1.0.0-RC.01"),
            ("1.0", "1.0.0"),
            ("2.0b1", "2.0-beta.1"),
            ("1.0.post2", "1.0-r2"),
            ("1.0+local.1", "1.0.0+LOCAL-1"),
        ] {
            assert_eq!(version_key(a), version_key(b), "{a} == {b}");
        }
        for (a, b) in [("1.0", "1.1"), ("1.0rc1", "1.0"), ("1.0+a", "1.0")] {
            assert_ne!(version_key(a), version_key(b), "{a} != {b}");
        }
        assert!(
            upload_filename_mismatch("foo_bar-1.0-py3-none-any.whl", "foo-bar", "1.0").is_none()
        );
        assert!(upload_filename_mismatch("Foo.Bar-1.0.tar.gz", "foo-bar", "1.0").is_none());
        assert!(upload_filename_mismatch("requests-1.0.tar.gz", "foo", "1.0").is_some());
        assert!(upload_filename_mismatch("foo-1.1.tar.gz", "foo", "1.0").is_some());
        assert!(upload_filename_mismatch("foo.tar.gz", "foo", "1.0").is_some());
    }

    #[test]
    fn test_wheel_core_metadata_reads_the_root_dist_info() {
        use std::io::Write;
        let build = |entries: &[&str]| {
            let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            for name in entries {
                w.start_file(*name, zip::write::SimpleFileOptions::default())
                    .unwrap();
                w.write_all(format!("from {name}").as_bytes()).unwrap();
            }
            w.finish().unwrap().into_inner()
        };
        let one = build(&["pkg/__init__.py", "pkg-1.0.dist-info/METADATA"]);
        assert_eq!(
            wheel_core_metadata(std::io::Cursor::new(&one[..])).as_deref(),
            Some(&b"from pkg-1.0.dist-info/METADATA"[..])
        );
        // Vendored metadata deeper in the tree does not count; two at the root are ambiguous.
        let nested = build(&["pkg/_vendor/x-1.0.dist-info/METADATA"]);
        assert_eq!(wheel_core_metadata(std::io::Cursor::new(&nested[..])), None);
        let two = build(&["a-1.0.dist-info/METADATA", "b-1.0.dist-info/METADATA"]);
        assert_eq!(wheel_core_metadata(std::io::Cursor::new(&two[..])), None);
        assert_eq!(
            wheel_core_metadata(std::io::Cursor::new(&b"not a zip"[..])),
            None
        );
    }

    #[test]
    fn test_merge_cached_file_keeps_upstream_attributes() {
        let upstream = vec![FileEntry {
            filename: "pkg-1.0.whl".into(),
            sha256: Some("up".into()),
            requires_python: Some(">=3.9".into()),
            yanked: Some("cve".into()),
            core_metadata: Some("sha256=up".into()),
            ..Default::default()
        }];
        let local = vec![FileEntry {
            filename: "pkg-1.0.whl".into(),
            sha256: Some("local".into()),
            ..Default::default()
        }];
        let merged = merge_file_lists(upstream, &local);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].sha256.as_deref(), Some("local"));
        assert_eq!(merged[0].requires_python.as_deref(), Some(">=3.9"));
        assert_eq!(merged[0].yanked.as_deref(), Some("cve"));
        assert_eq!(
            merged[0].core_metadata, None,
            "the upstream's core metadata may describe other bytes than the local file"
        );
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use crate::test_helpers::{body_bytes, create_test_context, send, send_with_headers};
    use axum::http::{header, Method, StatusCode};

    /// A cold miss is "not found" only when an upstream said so. The simple index and a file
    /// whose upstreams all failed (5xx after the retry, unreachable) answer 502, and so does a
    /// file the index lists on a host that is down. An index that answers without the file,
    /// or a 404, is still 404 — also while another upstream is down.
    #[tokio::test]
    async fn a_cold_miss_is_404_only_when_an_upstream_said_not_found() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let down = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&down)
            .await;
        let missing = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&missing)
            .await;
        // The index answers and lists the file on the host that is down.
        let lists_down = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/flask/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"<html><body><a href="{}/files/flask-2.0.tar.gz">flask-2.0.tar.gz</a></body></html>"#,
                down.uri()
            )))
            .mount(&lists_down)
            .await;
        // The index answers without the file.
        let lists_other = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/flask/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<html><body><a href="/files/flask-1.0.tar.gz">flask-1.0.tar.gz</a></body></html>"#,
            ))
            .mount(&lists_other)
            .await;
        // The index answers with no files at all.
        let lists_nothing = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/flask/"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html><body></body></html>"))
            .mount(&lists_nothing)
            .await;
        let refused = "http://127.0.0.1:9".to_string();
        let index = "/simple/flask/";
        let file = "/simple/flask/flask-2.0.tar.gz";
        for (upstreams, uri, want) in [
            (vec![down.uri()], index, StatusCode::BAD_GATEWAY),
            (vec![refused.clone()], index, StatusCode::BAD_GATEWAY),
            (vec![missing.uri()], index, StatusCode::NOT_FOUND),
            (
                vec![down.uri(), lists_nothing.uri()],
                index,
                StatusCode::NOT_FOUND,
            ),
            (vec![down.uri()], file, StatusCode::BAD_GATEWAY),
            (vec![refused.clone()], file, StatusCode::BAD_GATEWAY),
            (vec![missing.uri()], file, StatusCode::NOT_FOUND),
            (vec![lists_down.uri()], file, StatusCode::BAD_GATEWAY),
            (vec![lists_other.uri()], file, StatusCode::NOT_FOUND),
            (
                vec![down.uri(), lists_other.uri()],
                file,
                StatusCode::NOT_FOUND,
            ),
        ] {
            let urls = upstreams.clone();
            let ctx = crate::test_helpers::create_test_context_with_config(move |cfg| {
                // Plain URL entries, as `proxies = ["https://..."]` reads from the config file.
                cfg.pypi.proxies = serde_json::from_value(serde_json::json!(urls)).unwrap();
            });
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), want, "{uri} {upstreams:?}");
        }
        assert!(!down.received_requests().await.unwrap().is_empty());
        assert!(!missing.received_requests().await.unwrap().is_empty());
        assert!(!lists_down.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_pypi_list_empty() {
        let ctx = create_test_context();
        let response = send(&ctx.app, Method::GET, "/simple/", "").await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("Simple Index"));
    }

    #[tokio::test]
    async fn test_pypi_list_with_packages() {
        let ctx = create_test_context();

        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", b"fake-tarball-data")
            .await
            .unwrap();

        let response = send(&ctx.app, Method::GET, "/simple/", "").await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("flask"));
    }

    #[tokio::test]
    async fn test_pypi_list_json_pep691() {
        let ctx = create_test_context();

        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", b"data")
            .await
            .unwrap();

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/",
            vec![("Accept", "application/vnd.pypi.simple.v1+json")],
            "",
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["meta"]["api-version"].as_str() == Some("1.0"));
        assert!(json["projects"].as_array().unwrap().len() == 1);
    }

    #[tokio::test]
    async fn test_pypi_versions_local() {
        let ctx = create_test_context();

        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", b"fake-data")
            .await
            .unwrap();

        let response = send(&ctx.app, Method::GET, "/simple/flask/", "").await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("flask-2.0.tar.gz"));
        // URL should contain base_url + /simple/flask/flask-2.0.tar.gz
        assert!(html.contains("/simple/flask/flask-2.0.tar.gz"));
    }

    #[tokio::test]
    async fn test_pypi_versions_with_hash() {
        let ctx = create_test_context();

        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", b"fake-data")
            .await
            .unwrap();
        ctx.state
            .storage
            .put(
                "pypi/flask/flask-2.0.tar.gz.sha256",
                b"abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
            )
            .await
            .unwrap();

        let response = send(&ctx.app, Method::GET, "/simple/flask/", "").await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("#sha256=abc123"));
    }

    #[tokio::test]
    async fn test_pypi_versions_json_pep691() {
        let ctx = create_test_context();

        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", b"data")
            .await
            .unwrap();
        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz.sha256", b"deadbeef")
            .await
            .unwrap();

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/flask/",
            vec![("Accept", "application/vnd.pypi.simple.v1+json")],
            "",
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["name"], "flask");
        assert_eq!(json["files"].as_array().unwrap().len(), 1);
        assert_eq!(json["files"][0]["filename"], "flask-2.0.tar.gz");
        assert_eq!(json["files"][0]["hashes"]["sha256"], "deadbeef");
    }

    /// #896: NORA's simple JSON must also carry PEP 700 fields so clients (e.g. Renovate)
    /// can compute a minimum release age: `meta.api-version` 1.1, a project-level
    /// `versions` list, and per-file `upload-time` + `size`. Upload-time is sourced from
    /// the cached `dates.json` (filename → RFC3339), size from storage.
    #[tokio::test]
    async fn test_pypi_versions_json_pep700() {
        let ctx = create_test_context();
        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", b"data")
            .await
            .unwrap();
        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz.sha256", b"deadbeef")
            .await
            .unwrap();
        // PEP 700 upload-time is read from the cached dates.json (filename → RFC3339).
        ctx.state
            .storage
            .put(
                "pypi/flask/dates.json",
                br#"{"flask-2.0.tar.gz":"2021-05-11T13:00:00Z"}"#,
            )
            .await
            .unwrap();

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/flask/",
            vec![("Accept", "application/vnd.pypi.simple.v1+json")],
            "",
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // PEP 700 signals support via api-version 1.1
        assert_eq!(
            json["meta"]["api-version"], "1.1",
            "PEP 700 requires meta.api-version 1.1"
        );
        // project-level versions list (PEP 700)
        let versions = json["versions"]
            .as_array()
            .expect("PEP 700 project versions[] must be present");
        assert!(
            versions.iter().any(|v| v == "2.0"),
            "versions must include 2.0, got {versions:?}"
        );
        // per-file upload-time + size (PEP 700)
        let f = &json["files"][0];
        assert_eq!(
            f["upload-time"], "2021-05-11T13:00:00Z",
            "PEP 700 per-file upload-time from dates.json"
        );
        assert_eq!(f["size"], 4, "PEP 700 per-file size = bytes of 'data'");
    }

    #[tokio::test]
    async fn test_pypi_download_local() {
        let ctx = create_test_context();

        let tarball_data = b"fake-tarball-content";
        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", tarball_data)
            .await
            .unwrap();

        let response = send(&ctx.app, Method::GET, "/simple/flask/flask-2.0.tar.gz", "").await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        assert_eq!(&body[..], tarball_data);
    }

    #[tokio::test]
    async fn test_pypi_download_range_request() {
        let ctx = create_test_context();
        let sdist = b"0123456789abcdef";
        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", sdist)
            .await
            .unwrap();
        let url = "/simple/flask/flask-2.0.tar.gz";

        let resp =
            send_with_headers(&ctx.app, Method::GET, url, vec![("range", "bytes=2-5")], "").await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_RANGE)
                .unwrap()
                .to_str()
                .unwrap(),
            format!("bytes 2-5/{}", sdist.len())
        );
        assert_eq!(
            resp.headers()
                .get(header::ACCEPT_RANGES)
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes"
        );
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap(),
            "application/gzip"
        );
        assert_eq!(body_bytes(resp).await.as_ref(), &sdist[2..=5]);

        // A client that already holds the whole file resumes with `bytes=<size>-`.
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            url,
            vec![("range", &format!("bytes={}-", sdist.len())[..])],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_RANGE)
                .unwrap()
                .to_str()
                .unwrap(),
            format!("bytes */{}", sdist.len())
        );

        let resp = send(&ctx.app, Method::GET, url, "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::ACCEPT_RANGES)
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes"
        );
        assert_eq!(body_bytes(resp).await.as_ref(), &sdist[..]);
    }

    #[tokio::test]
    async fn test_pypi_not_found_no_proxy() {
        let ctx = create_test_context();

        let response = send(&ctx.app, Method::GET, "/simple/nonexistent/", "").await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// Regression test for #891 path 1: internal `dates.json` must not leak
    /// into the PEP 691 simple index. `uv` and other strict clients require
    /// `hashes` on every file entry; `dates.json` has no sidecar → parse failure.
    #[tokio::test]
    async fn test_pypi_dates_json_excluded_from_index() {
        let ctx = create_test_context();

        ctx.state
            .storage
            .put("pypi/loguru/loguru-0.7.0.tar.gz", b"fake-sdist")
            .await
            .unwrap();
        ctx.state
            .storage
            .put("pypi/loguru/loguru-0.7.0.tar.gz.sha256", b"aabbccdd")
            .await
            .unwrap();
        ctx.state
            .storage
            .put(
                "pypi/loguru/dates.json",
                br#"{"loguru-0.7.0.tar.gz":"2023-08-20T12:00:00Z"}"#,
            )
            .await
            .unwrap();

        // HTML index must not contain dates.json
        let response = send(&ctx.app, Method::GET, "/simple/loguru/", "").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let html = String::from_utf8_lossy(&body);
        assert!(
            html.contains("loguru-0.7.0.tar.gz"),
            "real package must appear"
        );
        assert!(
            !html.contains("dates.json"),
            "dates.json must NOT appear in index (#891)"
        );

        // PEP 691 JSON index must also exclude dates.json
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/loguru/",
            vec![("Accept", "application/vnd.pypi.simple.v1+json")],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let files = json["files"].as_array().unwrap();
        assert_eq!(files.len(), 1, "only the real package file, not dates.json");
        assert_eq!(files[0]["filename"], "loguru-0.7.0.tar.gz");
    }

    /// Regression test for #891 path 2: `GET /simple/{name}/dates.json` must
    /// return 404, not serve the internal bookkeeping file.
    #[tokio::test]
    async fn test_pypi_dates_json_not_downloadable() {
        let ctx = create_test_context();

        ctx.state
            .storage
            .put(
                "pypi/loguru/dates.json",
                br#"{"loguru-0.7.0.tar.gz":"2023-08-20T12:00:00Z"}"#,
            )
            .await
            .unwrap();

        let response = send(&ctx.app, Method::GET, "/simple/loguru/dates.json", "").await;
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "internal dates.json must not be downloadable (#891)"
        );
    }

    /// Regression test for #905: `ensure_pypi_dates_cached` must never fetch
    /// an internal-namespace package's metadata upstream (#68 dependency
    /// A file whose version cannot be read from its name is refused by the
    /// allowlist, not passed on as a metadata request.
    #[tokio::test]
    async fn allowlist_refuses_a_file_whose_version_it_cannot_read() {
        use crate::test_helpers::create_test_context_with_config;
        let dir = tempfile::tempdir().unwrap();
        let allowlist = dir.path().join("allowlist.json");
        std::fs::write(&allowlist, r#"{"version": 1, "entries": [{"registry": "pypi", "name": "pkg", "version": "1.0.0"}]}"#).unwrap();
        let allowlist = allowlist.to_string_lossy().into_owned();
        let ctx = create_test_context_with_config(|cfg| {
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.allowlist_path = Some(allowlist);
        });
        ctx.state
            .storage
            .put("pypi/pkg/weird.tar.gz", b"sdist")
            .await
            .unwrap();
        let resp = send(&ctx.app, Method::GET, "/simple/pkg/weird.tar.gz", "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let resp = send(&ctx.app, Method::GET, "/simple/pkg/", "").await;
        assert_ne!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "control: the index passes"
        );
    }

    /// confusion). Verify that a tarball download for an internal-namespace
    /// package does not trigger any upstream requests for the dates endpoint.
    #[tokio::test]
    async fn test_pypi_self_prime_skips_internal_namespace() {
        use crate::test_helpers::create_test_context_with_config;
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;

        // Any request to the upstream = test failure (the guard must prevent it).
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_string("LEAKED"))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.pypi.proxy = Some(upstream.uri());
            cfg.server.trust_upstream_dates = true;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.internal_namespaces = vec!["internal-*".to_string()];
        });

        // Pre-populate a tarball so the download path is exercised.
        ctx.state
            .storage
            .put(
                "pypi/internal-secret/internal_secret-1.0.0.tar.gz",
                b"fake-sdist",
            )
            .await
            .unwrap();
        ctx.state
            .storage
            .put(
                "pypi/internal-secret/internal_secret-1.0.0.tar.gz.sha256",
                b"aabbccdd",
            )
            .await
            .unwrap();

        // Download the tarball — this triggers ensure_pypi_dates_cached.
        let _resp = send(
            &ctx.app,
            Method::GET,
            "/simple/internal-secret/internal_secret-1.0.0.tar.gz",
            "",
        )
        .await;

        // The internal-namespace guard must have prevented any upstream fetch.
        let upstream_hits = upstream.received_requests().await.unwrap().len();
        assert_eq!(
            upstream_hits, 0,
            "internal-namespace package dates must never be fetched upstream (#68, #905)"
        );

        // dates.json must NOT have been written for an internal package.
        assert!(
            ctx.state
                .storage
                .get("pypi/internal-secret/dates.json")
                .await
                .is_err(),
            "dates.json must not be created for internal-namespace packages"
        );
    }

    /// #969 A/B: the simple JSON must take each file's PEP 700 `size` from the listing
    /// (`list_with_meta`) and NEVER `stat()` per file. On S3 a `stat()` is a HEAD
    /// round-trip, and they were issued serially over the whole merged file list, so
    /// `/simple/{name}/` cost one HEAD per file — hundreds to tens of thousands for a
    /// proxied index — and uv timed out. A backend that counts `stat()` proves the JSON
    /// index now issues ZERO of them while still emitting the correct size.
    /// Same class as #738 on the Docker index rebuild.
    #[tokio::test]
    async fn pypi_simple_json_uses_list_with_meta_not_per_key_stat() {
        use crate::storage::{FileMeta, ObjectStorage, Storage, StorageBackend};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        /// Delegates every operation to a real in-memory object store, counting
        /// `stat()` calls. `list_with_meta` is inherited from the inner store, so the
        /// listing still carries real sizes.
        struct StatCounting {
            inner: ObjectStorage,
            stat_calls: Arc<AtomicUsize>,
        }

        #[async_trait::async_trait]
        impl StorageBackend for StatCounting {
            async fn stat(&self, key: &str) -> Option<FileMeta> {
                self.stat_calls.fetch_add(1, Ordering::SeqCst);
                self.inner.stat(key).await
            }
            async fn put(&self, k: &str, d: &[u8], sha256: &str) -> crate::storage::Result<()> {
                self.inner.put(k, d, sha256).await
            }
            async fn get(
                &self,
                k: &str,
            ) -> crate::storage::Result<(axum::body::Bytes, Option<String>)> {
                self.inner.get(k).await
            }
            async fn pin(&self, k: &str) -> Option<String> {
                self.inner.pin(k).await
            }
            async fn delete(&self, k: &str) -> crate::storage::Result<()> {
                self.inner.delete(k).await
            }
            async fn list(&self, prefix: &str) -> crate::storage::Result<Vec<String>> {
                self.inner.list(prefix).await
            }
            async fn list_with_meta(
                &self,
                prefix: &str,
            ) -> crate::storage::Result<Vec<(String, FileMeta)>> {
                self.inner.list_with_meta(prefix).await
            }
            async fn health_check(&self) -> bool {
                self.inner.health_check().await
            }
            async fn total_size(&self) -> u64 {
                self.inner.total_size().await
            }
            fn backend_name(&self) -> &'static str {
                "stat-counting-test"
            }
            async fn put_from_path(
                &self,
                k: &str,
                src: &std::path::Path,
                sha256: Option<&str>,
            ) -> crate::storage::Result<()> {
                self.inner.put_from_path(k, src, sha256).await
            }
            async fn copy(
                &self,
                src: &str,
                dst: &str,
                sha256: Option<&str>,
            ) -> crate::storage::Result<()> {
                self.inner.copy(src, dst, sha256).await
            }
            async fn get_reader(
                &self,
                k: &str,
            ) -> crate::storage::Result<(
                u64,
                Option<String>,
                std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
            )> {
                self.inner.get_reader(k).await
            }
        }

        let stat_calls = Arc::new(AtomicUsize::new(0));
        let ctx = crate::test_helpers::create_test_context_with_storage(Storage::from_backend(
            Arc::new(StatCounting {
                inner: ObjectStorage::in_memory(),
                stat_calls: Arc::clone(&stat_calls),
            }),
        ));
        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", b"data")
            .await
            .unwrap();
        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz.sha256", b"deadbeef")
            .await
            .unwrap();
        stat_calls.store(0, Ordering::SeqCst);

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/flask/",
            vec![("Accept", "application/vnd.pypi.simple.v1+json")],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        assert_eq!(
            stat_calls.load(Ordering::SeqCst),
            0,
            "#969: the simple JSON must not stat() per file — size comes from list_with_meta"
        );
        // Correctness preserved: the size still reaches the response.
        let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(
            json["files"][0]["size"], 4,
            "PEP 700 size must survive the stat-free path"
        );
    }

    /// #969: an upstream that answers the PEP 691 JSON but carries no `upload-time`
    /// (any pre-PEP-700 index) left nothing cached, so EVERY `/simple/{name}/` JSON
    /// request re-downloaded the whole upstream JSON index. The answered-but-dateless
    /// result is now cached once; the second request must not fetch it again.
    #[tokio::test]
    async fn test_pypi_dateless_upstream_json_is_fetched_once() {
        use super::PEP691_JSON;
        use crate::test_helpers::create_test_context_with_config;
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        // PEP 691 JSON without any `upload-time` — a pre-PEP-700 upstream.
        Mock::given(method("GET"))
            .and(path("/flask/"))
            .and(header("accept", PEP691_JSON))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"meta":{"api-version":"1.0"},"name":"flask","files":[{"filename":"flask-2.0.tar.gz","url":"https://up/flask-2.0.tar.gz"}]}"#,
            ))
            .mount(&upstream)
            .await;
        // The PEP 503 HTML listing the index itself merges.
        Mock::given(method("GET"))
            .and(path("/flask/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<html><body><a href="https://up/flask-2.0.tar.gz">flask-2.0.tar.gz</a></body></html>"#,
            ))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.pypi.proxy = Some(upstream.uri());
        });

        for _ in 0..2 {
            let response = send_with_headers(
                &ctx.app,
                Method::GET,
                "/simple/flask/",
                vec![("Accept", "application/vnd.pypi.simple.v1+json")],
                "",
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
        }

        let json_fetches = upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| {
                r.headers
                    .get("accept")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v == PEP691_JSON)
            })
            .count();
        assert_eq!(
            json_fetches, 1,
            "#969: a dateless upstream JSON index must be fetched once, not per request"
        );
        // The empty map is what got cached — it reads back like "no date for this file",
        // exactly as an absent dates.json did for the quarantine clock.
        assert_eq!(
            &ctx.state
                .storage
                .get("pypi/flask/dates.json")
                .await
                .unwrap()[..],
            b"{}",
            "an answered-but-dateless upstream is recorded as an empty map"
        );
    }

    /// #969: a failed upstream fetch must cache nothing, so a transient outage stays
    /// retryable. Only an upstream that actually answered may record the empty map.
    #[tokio::test]
    async fn test_pypi_dates_not_cached_when_upstream_fetch_fails() {
        use super::PEP691_JSON;
        use crate::test_helpers::create_test_context_with_config;
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        // The JSON index is down; the HTML listing still answers.
        Mock::given(method("GET"))
            .and(path("/flask/"))
            .and(header("accept", PEP691_JSON))
            .respond_with(ResponseTemplate::new(500))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/flask/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<html><body><a href="https://up/flask-2.0.tar.gz">flask-2.0.tar.gz</a></body></html>"#,
            ))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.pypi.proxy = Some(upstream.uri());
        });

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/flask/",
            vec![("Accept", PEP691_JSON)],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "the index still serves");
        assert!(
            ctx.state
                .storage
                .get("pypi/flask/dates.json")
                .await
                .is_err(),
            "#969: a failed upstream fetch must cache nothing — the outage must stay retryable"
        );
    }

    /// A corrupt `dates.json` (hand-edited, truncated write) must not fail the index:
    /// the PEP 700 `upload-time` is optional, so it is simply omitted while `size`
    /// still comes from the listing.
    #[tokio::test]
    async fn test_pypi_simple_json_survives_corrupt_dates_json() {
        let ctx = create_test_context();
        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", b"data")
            .await
            .unwrap();
        ctx.state
            .storage
            .put("pypi/flask/dates.json", b"{ this is not json")
            .await
            .unwrap();

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/flask/",
            vec![("Accept", "application/vnd.pypi.simple.v1+json")],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(
            json["files"][0]["size"], 4,
            "size survives a corrupt dates.json"
        );
        assert!(
            json["files"][0].get("upload-time").is_none(),
            "an unparsable dates.json omits upload-time instead of failing the index"
        );
    }

    /// PEP 700 `size` is only knowable for files NORA actually stores. In a merged
    /// index the local file carries a size and the upstream-only file does not —
    /// the same outcome the old per-file `stat()` produced (it 404'd on those),
    /// reached without the round-trip.
    #[tokio::test]
    async fn test_pypi_simple_json_size_only_for_local_files() {
        use super::PEP691_JSON;
        use crate::test_helpers::create_test_context_with_config;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/flask/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<html><body>
                   <a href="https://up/flask-2.0.tar.gz">flask-2.0.tar.gz</a>
                   <a href="https://up/flask-3.0.tar.gz">flask-3.0.tar.gz</a>
                   </body></html>"#,
            ))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.pypi.proxy = Some(upstream.uri());
        });
        // Only 2.0 is cached locally.
        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", b"seven!!")
            .await
            .unwrap();

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/flask/",
            vec![("Accept", PEP691_JSON)],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        let files = json["files"].as_array().expect("files array");
        assert_eq!(files.len(), 2, "both files are listed: {files:?}");
        let by_name = |n: &str| {
            files
                .iter()
                .find(|f| f["filename"] == n)
                .unwrap_or_else(|| panic!("{n} missing from {files:?}"))
        };
        assert_eq!(
            by_name("flask-2.0.tar.gz")["size"],
            7,
            "the locally stored file carries its real size"
        );
        assert!(
            by_name("flask-3.0.tar.gz").get("size").is_none(),
            "an upstream-only file has no local size and must omit the field"
        );
    }

    /// #969 class invariant (the one #738 should have carried): the simple JSON must
    /// cost the SAME number of storage round-trips whatever the size of the index it
    /// renders. Rendering a 1-file index and a 100-file index must issue an identical
    /// op count — anything proportional to the file list is an N+1 by construction,
    /// and on S3 every op is a network round-trip.
    #[tokio::test]
    async fn pypi_simple_json_cost_is_independent_of_index_size() {
        use super::PEP691_JSON;
        use crate::test_helpers::{
            create_test_context_with_storage_and_config, op_counting_storage,
        };
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        /// Serve an upstream index of `n` files and return the storage ops one JSON
        /// index request costs.
        async fn ops_for_index(n: usize) -> usize {
            let links: String = (1..=n)
                .map(|i| format!("<a href=\"https://up/pkg-{i}.0.tar.gz\">pkg-{i}.0.tar.gz</a>\n"))
                .collect();
            let upstream = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/pkg/"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_string(format!("<html><body>{links}</body></html>")),
                )
                .mount(&upstream)
                .await;

            let (storage, ops) = op_counting_storage();
            let ctx = create_test_context_with_storage_and_config(storage, |cfg| {
                cfg.pypi.proxy = Some(upstream.uri());
            });
            ops.reset();
            let response = send_with_headers(
                &ctx.app,
                Method::GET,
                "/simple/pkg/",
                vec![("Accept", PEP691_JSON)],
                "",
            )
            .await;
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "index of {n} files served"
            );
            ops.total()
        }

        let small = ops_for_index(1).await;
        let large = ops_for_index(100).await;
        assert_eq!(
            small, large,
            "#969: rendering the simple JSON must cost the same storage round-trips for a \
             1-file and a 100-file index — {small} vs {large} means the cost scales with N"
        );
    }

    /// A proxied file whose bytes do not match the index `#sha256` is refused with
    /// 502 and never cached; a matching one is served.
    #[tokio::test]
    async fn test_pypi_proxy_rejects_sha256_mismatch() {
        use crate::test_helpers::create_test_context_with_config;
        use sha2::Digest;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        let good = hex::encode(sha2::Sha256::digest(b"good-bytes"));
        let index = format!(
            r#"<a href="{0}/files/pkg-1.0.tar.gz#sha256={1}">a</a><a href="{0}/files/pkg-1.1.tar.gz#sha256={1}">b</a>"#,
            upstream.uri(),
            good
        );
        Mock::given(method("GET"))
            .and(path("/pkg/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(index))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/files/pkg-1.0.tar.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(&b"tampered"[..]))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/files/pkg-1.1.tar.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(&b"good-bytes"[..]))
            .mount(&upstream)
            .await;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.pypi.proxy = Some(upstream.uri());
        });

        let bad = send(&ctx.app, Method::GET, "/simple/pkg/pkg-1.0.tar.gz", "").await;
        assert_eq!(bad.status(), StatusCode::BAD_GATEWAY);
        let ok = send(&ctx.app, Method::GET, "/simple/pkg/pkg-1.1.tar.gz", "").await;
        assert_eq!(ok.status(), StatusCode::OK);
        assert_eq!(body_bytes(ok).await.as_ref(), b"good-bytes");

        // Let the background cache write of the good file land, then check neither
        // the bad file nor its sidecar was stored.
        for _ in 0..50 {
            if ctx
                .state
                .storage
                .stat("pypi/pkg/pkg-1.1.tar.gz")
                .await
                .is_some()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(ctx
            .state
            .storage
            .stat("pypi/pkg/pkg-1.1.tar.gz")
            .await
            .is_some());
        assert!(ctx
            .state
            .storage
            .stat("pypi/pkg/pkg-1.0.tar.gz")
            .await
            .is_none());
        assert!(ctx
            .state
            .storage
            .stat("pypi/pkg/pkg-1.0.tar.gz.sha256")
            .await
            .is_none());
    }

    /// C17: a file above `server.stream_threshold_mb` is spooled on the cold miss,
    /// checked against the index `#sha256` by the digest taken while spooling (a
    /// mismatch is a 502), cached pinned, then streamed from storage on the next hit.
    #[tokio::test]
    async fn test_large_file_spooled_then_streamed_from_cache() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config};
        use sha2::Digest;
        use wiremock::matchers::path;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let file: Vec<u8> = (0..(2 * 1024 * 1024 + 9))
            .map(|i| (i % 241) as u8)
            .collect();
        let sha = hex::encode(sha2::Sha256::digest(&file));
        let upstream = MockServer::start().await;
        let page = format!(
            r#"<a href="{0}/files/bigpy-1.0.tar.gz#sha256={sha}">bigpy-1.0.tar.gz</a>
<a href="{0}/files/bigpy-2.0.tar.gz#sha256={1}">bigpy-2.0.tar.gz</a>"#,
            upstream.uri(),
            "0".repeat(64),
        );
        Mock::given(path("/bigpy/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(page))
            .mount(&upstream)
            .await;
        for f in ["bigpy-1.0.tar.gz", "bigpy-2.0.tar.gz"] {
            Mock::given(path(format!("/files/{f}")))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(file.clone()))
                .mount(&upstream)
                .await;
        }
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.pypi.proxy = Some(uri);
            cfg.server.stream_threshold_mb = 1;
        });

        let resp = send(&ctx.app, Method::GET, "/simple/bigpy/bigpy-2.0.tar.gz", "").await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_GATEWAY,
            "index sha256 mismatch"
        );

        let resp = send(&ctx.app, Method::GET, "/simple/bigpy/bigpy-1.0.tar.gz", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_bytes(resp).await[..] == file[..]);
        let key = "pypi/bigpy/bigpy-1.0.tar.gz";
        let mut cached = false;
        for _ in 0..100 {
            if ctx.state.storage.pin(key).await.as_deref() == Some(sha.as_str()) {
                cached = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(cached, "the spooled file is cached pinned");
        for _ in 0..100 {
            if ctx
                .state
                .storage
                .get(&super::proxied_marker_key(key))
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            ctx.state
                .storage
                .get(&super::proxied_marker_key(key))
                .await
                .is_ok(),
            "a file cached from upstream carries the provenance marker (C22)"
        );

        let resp = send(&ctx.app, Method::GET, "/simple/bigpy/bigpy-1.0.tar.gz", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_bytes(resp).await[..] == file[..]);
        let fetches = upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path() == "/files/bigpy-1.0.tar.gz")
            .count();
        assert_eq!(fetches, 1, "the hit is served from storage");
    }

    /// An upstream outage with nothing local is a 502 (pip retries it), and a real
    /// upstream 404 stays a 404 — before, both were a 404 pip cached as "no such project".
    #[tokio::test]
    async fn test_pypi_upstream_outage_is_502_not_404() {
        use crate::test_helpers::create_test_context_with_config;
        use wiremock::matchers::path;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(path("/down/"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&upstream)
            .await;
        Mock::given(path("/gone/"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.pypi.proxy = Some(uri);
        });

        for (uri, want) in [
            ("/simple/down/", StatusCode::BAD_GATEWAY),
            ("/simple/gone/", StatusCode::NOT_FOUND),
            ("/simple/down/down-1.0.tar.gz", StatusCode::BAD_GATEWAY),
            ("/simple/gone/gone-1.0.tar.gz", StatusCode::NOT_FOUND),
        ] {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), want, "{uri}");
        }
    }

    /// A twine multipart body: `fields`, then `content` as `filename`.
    fn twine_body(fields: &[(&str, &str)], filename: &str, content: &[u8]) -> (String, Vec<u8>) {
        const B: &str = "nora-r2-boundary";
        let mut body = Vec::new();
        for (field, value) in [(":action", "file_upload")].iter().chain(fields) {
            body.extend_from_slice(
                format!(
                    "--{B}\r\nContent-Disposition: form-data; name=\"{field}\"\r\n\r\n{value}\r\n"
                )
                .as_bytes(),
            );
        }
        body.extend_from_slice(
            format!(
                "--{B}\r\nContent-Disposition: form-data; name=\"content\"; filename=\"{filename}\"\r\n\
                 Content-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(content);
        body.extend_from_slice(format!("\r\n--{B}--\r\n").as_bytes());
        (format!("multipart/form-data; boundary={B}"), body)
    }

    async fn twine_upload(
        app: &axum::Router,
        fields: &[(&str, &str)],
        filename: &str,
        content: &[u8],
    ) -> axum::http::Response<axum::body::Body> {
        let (content_type, body) = twine_body(fields, filename, content);
        send_with_headers(
            app,
            Method::POST,
            "/simple/",
            vec![("content-type", content_type.as_str())],
            body,
        )
        .await
    }

    /// R2-05: an upload spools under `server.spool_max_mb`: while other spools hold
    /// the budget it is a 503 + Retry-After, a file bigger than the whole budget a
    /// 507, and neither leaves a file behind.
    #[tokio::test]
    async fn upload_over_the_spool_budget_is_refused_and_leaves_no_spool() {
        let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
            cfg.server.spool_max_mb = 4;
        });
        let upload = |mib: usize| {
            let app = ctx.app.clone();
            async move {
                twine_upload(
                    &app,
                    &[("name", "big"), ("version", "1.0")],
                    "big-1.0.tar.gz",
                    &vec![0u8; mib * 1024 * 1024],
                )
                .await
            }
        };
        let held = ctx.state.spool.reserve(3 * 1024 * 1024).unwrap();
        let resp = upload(2).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(resp.headers().contains_key(header::RETRY_AFTER));
        drop(held);
        assert_eq!(upload(5).await.status(), StatusCode::INSUFFICIENT_STORAGE);
        let dir = ctx.state.spool.dir(crate::registry::PYPI_UPLOAD_SUBDIR);
        assert_eq!(std::fs::read_dir(dir).unwrap().count(), 0);
    }

    /// A wheel holding `{dist_info}/METADATA` and one module.
    fn wheel(dist_info: &str, metadata: &str) -> Vec<u8> {
        use std::io::Write;
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        w.start_file(format!("{dist_info}/METADATA"), opts).unwrap();
        w.write_all(metadata.as_bytes()).unwrap();
        w.start_file("pkg/__init__.py", opts).unwrap();
        w.write_all(b"x = 1\n").unwrap();
        w.finish().unwrap().into_inner()
    }

    fn sha256_hex(data: &[u8]) -> String {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(data))
    }

    async fn text(resp: axum::http::Response<axum::body::Body>) -> String {
        String::from_utf8(body_bytes(resp).await.to_vec()).unwrap()
    }

    /// C36: an uploaded wheel's `.dist-info/METADATA` is served as `<wheel>.metadata`
    /// (PEP 658) and advertised with its digest; twine's `requires_python` is kept and
    /// listed in both index forms.
    #[tokio::test]
    async fn hosted_wheel_serves_core_metadata_and_requires_python() {
        let ctx = create_test_context();
        let metadata =
            "Metadata-Version: 2.1\nName: hostpkg\nVersion: 1.0\nRequires-Python: >=3.9\n";
        let whl = wheel("hostpkg-1.0.dist-info", metadata);
        let resp = twine_upload(
            &ctx.app,
            &[
                ("name", "hostpkg"),
                ("version", "1.0"),
                ("requires_python", ">=3.9"),
            ],
            "hostpkg-1.0-py3-none-any.whl",
            &whl,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = twine_upload(
            &ctx.app,
            &[("name", "hostpkg"), ("version", "1.0")],
            "hostpkg-1.0.tar.gz",
            b"sdist",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let digest = sha256_hex(metadata.as_bytes());
        let html = text(send(&ctx.app, Method::GET, "/simple/hostpkg/", "").await).await;
        let wheel_line = html
            .lines()
            .find(|l| l.contains("hostpkg-1.0-py3-none-any.whl"))
            .unwrap();
        assert!(
            wheel_line.contains(&format!("data-core-metadata=\"sha256={digest}\"")),
            "{wheel_line}"
        );
        assert!(
            wheel_line.contains("data-requires-python=\"&gt;=3.9\""),
            "{wheel_line}"
        );
        let sdist_line = html
            .lines()
            .find(|l| l.contains("hostpkg-1.0.tar.gz"))
            .unwrap();
        assert!(!sdist_line.contains("data-core-metadata"), "{sdist_line}");
        assert!(!sdist_line.contains("data-requires-python"), "{sdist_line}");

        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/hostpkg/",
            vec![("Accept", "application/vnd.pypi.simple.v1+json")],
            "",
        )
        .await;
        let json: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        let file = json["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["filename"] == "hostpkg-1.0-py3-none-any.whl")
            .unwrap();
        assert_eq!(file["core-metadata"]["sha256"], digest.as_str());
        assert_eq!(file["requires-python"], ">=3.9");

        let resp = send(
            &ctx.app,
            Method::GET,
            "/simple/hostpkg/hostpkg-1.0-py3-none-any.whl.metadata",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(text(resp).await, metadata);
        // No metadata for an sdist, and none for a wheel nora does not have.
        for uri in [
            "/simple/hostpkg/hostpkg-1.0.tar.gz.metadata",
            "/simple/hostpkg/hostpkg-2.0-py3-none-any.whl.metadata",
        ] {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{uri}");
        }
    }

    /// C36: an upstream-only wheel's `.metadata` is proxied only where the upstream's
    /// index advertises one, checked against the advertised digest; a wheel cached from
    /// upstream gets its own `.metadata` extracted and advertised.
    #[tokio::test]
    async fn proxied_core_metadata_follows_the_upstream_advertisement() {
        use crate::test_helpers::create_test_context_with_config;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        let meta = "Metadata-Version: 2.1\nName: uppkg\nVersion: 1.0\n";
        let whl = wheel("uppkg-1.0.dist-info", meta);
        let index = format!(
            r#"<a href="{u}/f/uppkg-1.0-py3-none-any.whl#sha256={w}" data-core-metadata="sha256={m}">a</a>
<a href="{u}/f/uppkg-1.1-py3-none-any.whl" data-dist-info-metadata="sha256={m}">b</a>
<a href="{u}/f/uppkg-1.2-py3-none-any.whl">c</a>"#,
            u = upstream.uri(),
            w = sha256_hex(&whl),
            m = sha256_hex(meta.as_bytes()),
        );
        Mock::given(method("GET"))
            .and(path("/uppkg/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(index))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/f/uppkg-1.0-py3-none-any.whl.metadata"))
            .respond_with(ResponseTemplate::new(200).set_body_string(meta))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/f/uppkg-1.1-py3-none-any.whl.metadata"))
            .respond_with(ResponseTemplate::new(200).set_body_string("tampered"))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/f/uppkg-1.0-py3-none-any.whl"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(whl.clone()))
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| cfg.pypi.proxy = Some(uri));

        let html = text(send(&ctx.app, Method::GET, "/simple/uppkg/", "").await).await;
        assert_eq!(html.matches("data-core-metadata=").count(), 2, "{html}");

        let ok = send(
            &ctx.app,
            Method::GET,
            "/simple/uppkg/uppkg-1.0-py3-none-any.whl.metadata",
            "",
        )
        .await;
        assert_eq!(ok.status(), StatusCode::OK);
        assert_eq!(text(ok).await, meta);
        let bad = send(
            &ctx.app,
            Method::GET,
            "/simple/uppkg/uppkg-1.1-py3-none-any.whl.metadata",
            "",
        )
        .await;
        assert_eq!(bad.status(), StatusCode::BAD_GATEWAY, "digest mismatch");
        let none = send(
            &ctx.app,
            Method::GET,
            "/simple/uppkg/uppkg-1.2-py3-none-any.whl.metadata",
            "",
        )
        .await;
        assert_eq!(
            none.status(),
            StatusCode::NOT_FOUND,
            "not advertised upstream"
        );

        // Cache the wheel: its metadata is extracted and stored next to it.
        let resp = send(
            &ctx.app,
            Method::GET,
            "/simple/uppkg/uppkg-1.0-py3-none-any.whl",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let sidecar = "pypi/uppkg/uppkg-1.0-py3-none-any.whl.metadata";
        for _ in 0..100 {
            if ctx.state.storage.stat(sidecar).await.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(
            &ctx.state.storage.get(sidecar).await.unwrap()[..],
            meta.as_bytes()
        );
    }

    /// C37: the upload body is spooled to disk, stored byte for byte, and the spool file
    /// is gone afterwards, also when the upload is refused.
    #[tokio::test]
    async fn upload_spools_content_and_cleans_up() {
        let ctx = create_test_context();
        let spool =
            std::path::PathBuf::from(&ctx.state.config.storage.path).join("tmp/pypi-uploads");
        let content: Vec<u8> = (0..3 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
        let resp = twine_upload(
            &ctx.app,
            &[
                ("name", "big"),
                ("version", "1.0"),
                ("sha256_digest", &sha256_hex(&content)),
            ],
            "big-1.0.tar.gz",
            &content,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            &ctx.state
                .storage
                .get("pypi/big/big-1.0.tar.gz")
                .await
                .unwrap()[..],
            &content[..]
        );

        let resp = twine_upload(
            &ctx.app,
            &[
                ("name", "big"),
                ("version", "1.1"),
                ("sha256_digest", &"0".repeat(64)),
            ],
            "big-1.1.tar.gz",
            &content,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "digest mismatch");
        assert!(ctx
            .state
            .storage
            .stat("pypi/big/big-1.1.tar.gz")
            .await
            .is_none());
        let left = std::fs::read_dir(&spool).map(|d| d.count()).unwrap_or(0);
        assert_eq!(left, 0, "no spool file is left behind");
    }

    /// Invariant: an internal-namespace project uploaded here never depends on the
    /// upstream. With a dead upstream, its simple index (HTML and JSON) and its file
    /// are 200 and the upstream sees no request at all.
    #[tokio::test]
    async fn internal_project_never_touches_a_dead_upstream() {
        use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(503))
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let ctx = crate::test_helpers::create_test_context_with_config(move |cfg| {
            cfg.pypi.proxy = Some(uri);
            cfg.pypi.metadata_ttl = 0;
            cfg.curation.internal_namespaces = vec!["corp-*".to_string()];
        });
        let content = b"sdist-bytes".to_vec();
        let resp = twine_upload(
            &ctx.app,
            &[("name", "corp-lib"), ("version", "1.0")],
            "corp-lib-1.0.tar.gz",
            &content,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        assert!(
            ctx.state
                .storage
                .get(&super::proxied_marker_key(
                    "pypi/corp-lib/corp-lib-1.0.tar.gz"
                ))
                .await
                .is_err(),
            "an uploaded file never carries the provenance marker (C22)"
        );
        let resp = send(&ctx.app, Method::GET, "/simple/corp-lib/", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(String::from_utf8_lossy(&body_bytes(resp).await).contains("corp-lib-1.0.tar.gz"));
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/corp-lib/",
            vec![("accept", "application/vnd.pypi.simple.v1+json")],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = send(
            &ctx.app,
            Method::GET,
            "/simple/corp-lib/corp-lib-1.0.tar.gz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], &content[..]);
        let seen = upstream.received_requests().await.unwrap();
        assert!(
            seen.is_empty(),
            "upstream contacted: {:?}",
            seen.iter()
                .map(|r| r.url.path().to_string())
                .collect::<Vec<_>>()
        );
    }

    /// C44: the uploaded filename must name the form's project and version.
    #[tokio::test]
    async fn upload_rejects_a_filename_of_another_project_or_version() {
        let ctx = create_test_context();
        for (name, version, filename, want) in [
            (
                "foo",
                "1.0",
                "requests-99.0-py3-none-any.whl",
                StatusCode::BAD_REQUEST,
            ),
            ("foo", "1.0", "foo-2.0.tar.gz", StatusCode::BAD_REQUEST),
            ("foo", "1.0", "foo-1.0.0-py3-none-any.whl", StatusCode::OK),
            (
                "Foo.Bar",
                "V1.0-RC.1",
                "foo_bar-1.0rc1.tar.gz",
                StatusCode::OK,
            ),
        ] {
            let resp = twine_upload(
                &ctx.app,
                &[("name", name), ("version", version)],
                filename,
                b"data",
            )
            .await;
            assert_eq!(resp.status(), want, "{name} {version} {filename}");
        }
        assert!(ctx
            .state
            .storage
            .stat("pypi/foo/requests-99.0-py3-none-any.whl")
            .await
            .is_none());
    }

    /// Q02: a release published upstream after `dates.json` was cached is not in it; a
    /// download of it refreshes the dates, so a `min_release_age` cooldown holds it
    /// instead of letting an undated file through.
    #[tokio::test]
    async fn new_release_missing_from_cached_dates_is_held_by_min_release_age() {
        use crate::test_helpers::create_test_context_with_config;
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        let u = upstream.uri();
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        Mock::given(method("GET"))
            .and(path("/fresh/"))
            .and(header("accept", super::PEP691_JSON))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"{{"meta":{{"api-version":"1.1"}},"name":"fresh","files":[
                {{"filename":"fresh-1.0.tar.gz","url":"{u}/f/fresh-1.0.tar.gz","upload-time":"2020-01-01T00:00:00Z"}},
                {{"filename":"fresh-2.0.tar.gz","url":"{u}/f/fresh-2.0.tar.gz","upload-time":"{now}"}}]}}"#
            )))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/fresh/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"<a href="{u}/f/fresh-1.0.tar.gz">a</a><a href="{u}/f/fresh-2.0.tar.gz">b</a>"#
            )))
            .mount(&upstream)
            .await;
        for v in ["1.0", "2.0"] {
            Mock::given(method("GET"))
                .and(path(format!("/f/fresh-{v}.tar.gz")))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(b"sdist".to_vec()))
                .mount(&upstream)
                .await;
        }
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.pypi.proxy = Some(u);
            cfg.server.trust_upstream_dates = true;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.min_release_age = Some("7d".to_string());
        });
        // The snapshot cached before 2.0 was published, an hour ago.
        let dates = "pypi/fresh/dates.json";
        ctx.state
            .storage
            .put(dates, br#"{"fresh-1.0.tar.gz":"2020-01-01T00:00:00Z"}"#)
            .await
            .unwrap();
        let file = std::path::Path::new(&ctx.state.config.storage.path).join(dates);
        std::fs::File::options()
            .write(true)
            .open(&file)
            .unwrap()
            .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(3600))
            .unwrap();

        let resp = send(&ctx.app, Method::GET, "/simple/fresh/fresh-2.0.tar.gz", "").await;
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "a release published today is held"
        );
        let resp = send(&ctx.app, Method::GET, "/simple/fresh/fresh-1.0.tar.gz", "").await;
        assert_eq!(resp.status(), StatusCode::OK, "an old release passes");
        let cached: serde_json::Value =
            serde_json::from_slice(&ctx.state.storage.get(dates).await.unwrap()).unwrap();
        assert!(
            cached.get("fresh-2.0.tar.gz").is_some(),
            "the dates were refreshed"
        );
    }

    /// R2-23, R2-45: a file uploaded here (internal namespace or not) is never held by
    /// the digest quarantine and never dated upstream: its downloads cost no upstream
    /// request, even with a dead upstream. A proxied copy (provenance marker) still is held.
    #[tokio::test]
    async fn uploaded_files_are_neither_quarantined_nor_dated_upstream() {
        use crate::test_helpers::create_test_context_with_config;
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(500))
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.pypi.proxy = Some(uri);
            cfg.server.trust_upstream_dates = true;
            cfg.curation.quarantine = Some(crate::digest_quarantine::QuarantineMode::Enforce);
            cfg.curation.quarantine_ttl = Some("1h".to_string());
            cfg.curation.internal_namespaces = vec!["intpkg".to_string()];
        });
        for project in ["intpkg", "ownpkg"] {
            let file = format!("{project}-1.0.tar.gz");
            let resp = twine_upload(
                &ctx.app,
                &[("name", project), ("version", "1.0")],
                &file,
                b"sdist",
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK);
            for _ in 0..2 {
                let uri = format!("/simple/{project}/{file}");
                let resp = send(&ctx.app, Method::GET, &uri, "").await;
                assert_eq!(resp.status(), StatusCode::OK, "{uri}");
                assert_eq!(text(resp).await, "sdist");
            }
        }
        assert!(
            upstream.received_requests().await.unwrap().is_empty(),
            "an uploaded file is never looked up upstream"
        );

        let key = "pypi/cached/cached-1.0.tar.gz";
        ctx.state.storage.put(key, b"proxied").await.unwrap();
        ctx.state
            .storage
            .put(&super::proxied_marker_key(key), b"")
            .await
            .unwrap();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/simple/cached/cached-1.0.tar.gz",
            "",
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "a proxied copy is held"
        );
    }

    /// R2-24: the index and its dates are one snapshot. A dates map cached before a
    /// release (fresh by its own clock) no longer lets an index refresh list the release
    /// undated, nor its download through the `min_release_age` cooldown.
    #[tokio::test]
    async fn index_refresh_dates_the_files_it_lists() {
        use crate::test_helpers::create_test_context_with_config;
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        let u = upstream.uri();
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        Mock::given(method("GET"))
            .and(path("/fresh/"))
            .and(header("accept", super::PEP691_JSON))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"{{"files":[
                {{"filename":"fresh-1.0.tar.gz","upload-time":"2020-01-01T00:00:00Z"}},
                {{"filename":"fresh-2.0.tar.gz","upload-time":"{now}"}}]}}"#
            )))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/fresh/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"<a href="{u}/f/fresh-1.0.tar.gz">a</a><a href="{u}/f/fresh-2.0.tar.gz">b</a>"#
            )))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/f/fresh-2.0.tar.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"sdist".to_vec()))
            .mount(&upstream)
            .await;
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.pypi.proxy = Some(u);
            cfg.server.trust_upstream_dates = true;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.min_release_age = Some("7d".to_string());
        });
        // Just cached (by a download miss of another file), before 2.0 was published.
        ctx.state
            .storage
            .put(
                "pypi/fresh/dates.json",
                br#"{"fresh-1.0.tar.gz":"2020-01-01T00:00:00Z"}"#,
            )
            .await
            .unwrap();

        let html = text(send(&ctx.app, Method::GET, "/simple/fresh/", "").await).await;
        assert!(html.contains("fresh-1.0.tar.gz"), "{html}");
        assert!(!html.contains("fresh-2.0.tar.gz"), "listed undated: {html}");
        let resp = send(&ctx.app, Method::GET, "/simple/fresh/fresh-2.0.tar.gz", "").await;
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "the cooldown holds it"
        );
    }

    /// R2-27: a cold-miss download and a PEP 658 `.metadata` request are resolved from
    /// the cached upstream index: after the index request, no project page is fetched
    /// again.
    #[tokio::test]
    async fn downloads_resolve_from_the_cached_upstream_index() {
        use crate::test_helpers::create_test_context_with_config;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        let meta = "Metadata-Version: 2.1\nName: cold\nVersion: 1.0\n";
        let whl = wheel("cold-1.0.dist-info", meta);
        let index = format!(
            r#"<a href="{u}/f/cold-1.0-py3-none-any.whl#sha256={w}" data-core-metadata="sha256={m}">a</a>
<a href="{u}/f/cold-1.0.tar.gz">b</a>"#,
            u = upstream.uri(),
            w = sha256_hex(&whl),
            m = sha256_hex(meta.as_bytes()),
        );
        Mock::given(method("GET"))
            .and(path("/cold/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(index))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/f/cold-1.0-py3-none-any.whl.metadata"))
            .respond_with(ResponseTemplate::new(200).set_body_string(meta))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/f/cold-1.0-py3-none-any.whl"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(whl.clone()))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/f/cold-1.0.tar.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"sdist".to_vec()))
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| cfg.pypi.proxy = Some(uri));
        let page_fetches = || async {
            upstream
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.url.path() == "/cold/")
                .count()
        };

        assert_eq!(
            send(&ctx.app, Method::GET, "/simple/cold/", "")
                .await
                .status(),
            StatusCode::OK
        );
        let after_index = page_fetches().await;
        for file in [
            "cold-1.0-py3-none-any.whl.metadata",
            "cold-1.0-py3-none-any.whl.metadata",
            "cold-1.0-py3-none-any.whl",
            "cold-1.0.tar.gz",
        ] {
            let uri = format!("/simple/cold/{file}");
            assert_eq!(
                send(&ctx.app, Method::GET, &uri, "").await.status(),
                StatusCode::OK,
                "{uri}"
            );
        }
        assert_eq!(page_fetches().await, after_index, "no project page refetch");
    }

    /// R2-25: an upload over `server.body_limit_mb` is a 413, not a 400.
    #[tokio::test]
    async fn oversize_upload_is_413() {
        let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
            cfg.server.body_limit_mb = 1;
        });
        let resp = twine_upload(
            &ctx.app,
            &[("name", "big"), ("version", "1.0")],
            "big-1.0.tar.gz",
            &vec![0u8; 2 * 1024 * 1024],
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let dir = ctx.state.spool.dir(crate::registry::PYPI_UPLOAD_SUBDIR);
        let left = std::fs::read_dir(dir).map_or(0, |d| d.count());
        assert_eq!(left, 0, "no spool left");
    }

    /// C40: a project only nora has (every upstream answers 404) is looked up upstream
    /// once per `metadata_ttl`, not on every index request, for HTML and JSON clients.
    #[tokio::test]
    async fn hosted_project_upstream_404_is_cached() {
        use crate::test_helpers::create_test_context_with_config;
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(404))
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| cfg.pypi.proxy = Some(uri));
        let resp = twine_upload(
            &ctx.app,
            &[("name", "priv"), ("version", "1.0")],
            "priv-1.0.tar.gz",
            b"x",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        for _ in 0..3 {
            for accept in ["text/html", "application/vnd.pypi.simple.v1+json"] {
                let resp = send_with_headers(
                    &ctx.app,
                    Method::GET,
                    "/simple/priv/",
                    vec![("Accept", accept)],
                    "",
                )
                .await;
                assert_eq!(resp.status(), StatusCode::OK);
                assert!(text(resp).await.contains("priv-1.0.tar.gz"));
            }
        }
        let hits = upstream.received_requests().await.unwrap().len();
        assert_eq!(
            hits, 1,
            "one index lookup in total, not one per request; no upstream lists it, so \
             there is nothing to date"
        );
    }

    /// C41: concurrent index requests for one project cost one upstream fetch, and the
    /// result is reused within `metadata_ttl`.
    #[tokio::test]
    async fn upstream_index_is_single_flight_and_cached() {
        use crate::test_helpers::create_test_context_with_config;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/hot/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"<a href="https://up/hot-1.0.tar.gz">hot</a>"#)
                    .set_delay(std::time::Duration::from_millis(300)),
            )
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| cfg.pypi.proxy = Some(uri));

        let requests = (0..8).map(|_| send(&ctx.app, Method::GET, "/simple/hot/", ""));
        for resp in futures::future::join_all(requests).await {
            assert_eq!(resp.status(), StatusCode::OK);
            assert!(text(resp).await.contains("hot-1.0.tar.gz"));
        }
        let resp = send(&ctx.app, Method::GET, "/simple/hot/", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        // One fetch of the index and one of its dates (trusted upstream dates, R2-24).
        let accepts: Vec<String> = upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| r.headers["accept"].to_str().unwrap().to_string())
            .collect();
        assert_eq!(accepts, ["text/html", super::PEP691_JSON]);
    }

    /// C41: when the refetch fails, the last good merged index is served (with a
    /// `Warning`), never just the local files; with no good copy it is a 5xx.
    #[tokio::test]
    async fn upstream_failure_serves_last_good_index_or_5xx() {
        use crate::test_helpers::create_test_context_with_config;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/flaky/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<a href="https://up/flaky-2.0.tar.gz">new</a><a href="https://up/flaky-1.0.tar.gz">old</a>"#,
            ))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/down/"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.pypi.proxy = Some(uri);
            cfg.pypi.metadata_ttl = 0; // refetch on every request
        });
        for key in ["pypi/flaky/flaky-1.0.tar.gz", "pypi/down/down-1.0.tar.gz"] {
            ctx.state.storage.put(key, b"cached").await.unwrap();
        }

        let resp = send(&ctx.app, Method::GET, "/simple/flaky/", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get(header::WARNING).is_none());

        upstream.reset().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&upstream)
            .await;
        let resp = send(&ctx.app, Method::GET, "/simple/flaky/", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers().get(header::WARNING).is_some(),
            "stale is flagged"
        );
        assert!(
            text(resp).await.contains("flaky-2.0.tar.gz"),
            "the newer upstream release survives"
        );

        let resp = send(&ctx.app, Method::GET, "/simple/down/", "").await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_GATEWAY,
            "no good copy: not a partial local index"
        );
    }

    /// `/simple/` never runs the index build itself: before the startup build finishes
    /// it answers 503 + Retry-After at once (not an empty, cacheable project list).
    #[tokio::test]
    async fn root_index_answers_503_while_the_first_build_runs() {
        use crate::test_helpers::{create_test_context_with_storage, op_counting_storage};
        let (storage, ops) = op_counting_storage();
        let ctx = create_test_context_with_storage(storage);
        ctx.state
            .storage
            .put("pypi/real/real-1.0.tar.gz", b"x")
            .await
            .unwrap();
        ops.stall_lists(Some("pypi/"));
        let state = ctx.state.clone();
        let startup = tokio::spawn(async move { state.repo_index.refresh(&state).await });

        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            send(&ctx.app, Method::GET, "/simple/", ""),
        )
        .await
        .expect("/simple/ waited on the index build");
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(resp.headers()[header::RETRY_AFTER], "5");

        ops.stall_lists(None);
        startup.await.unwrap();
        let resp = send(&ctx.app, Method::GET, "/simple/", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(text(resp).await.contains("/simple/real/"));
    }

    /// C45: `/simple/` lists only projects holding a distribution file, with absolute
    /// hrefs, from the repo index — not a storage listing per request.
    #[tokio::test]
    async fn root_index_comes_from_the_repo_index() {
        use crate::test_helpers::{create_test_context_with_storage, op_counting_storage};
        let (storage, ops) = op_counting_storage();
        let ctx = create_test_context_with_storage(storage);
        ctx.state
            .storage
            .put("pypi/real/real-1.0.tar.gz", b"x")
            .await
            .unwrap();
        ctx.state
            .storage
            .put("pypi/ghost/dates.json", b"{}")
            .await
            .unwrap();

        let html = text(send(&ctx.app, Method::GET, "/simple/", "").await).await;
        let base = crate::registry::nora_base_url(&ctx.state);
        let base = base.trim_end_matches('/');
        assert!(
            html.contains(&format!("<a href=\"{base}/simple/real/\">real</a>")),
            "{html}"
        );
        assert!(!html.contains("ghost"), "{html}");

        ops.reset();
        let resp = send(&ctx.app, Method::GET, "/simple/", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            ops.total(),
            0,
            "a warm /simple/ costs no storage round-trip"
        );
    }
}

// ============================================================================
// PEP 691 spec conformance tests
// ============================================================================

#[cfg(test)]
mod spec_conformance_tests {
    use super::*;

    /// PEP 691 requires the field name `hashes`, NOT `digests`.
    /// Regression test for bug where `digests` was used instead.
    #[test]
    fn test_pep691_uses_hashes_not_digests() {
        let files = vec![FileEntry {
            filename: "pkg-1.0.tar.gz".into(),
            sha256: Some("abcdef1234567890".into()),
            ..Default::default()
        }];
        let response =
            versions_json_response("pkg", &files, "http://nora:4000", &Default::default());
        let body = response.into_body();
        let bytes = futures::executor::block_on(axum::body::to_bytes(body, 1024 * 1024)).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert!(
            json["files"][0].get("hashes").is_some(),
            "PEP 691 requires 'hashes' field, not 'digests'"
        );
        assert!(
            json["files"][0].get("digests").is_none(),
            "PEP 691 forbids 'digests' — must be 'hashes'"
        );
        assert_eq!(json["files"][0]["hashes"]["sha256"], "abcdef1234567890");
    }

    /// The simple JSON carries `meta.api-version`. NORA advertises 1.1 (PEP 700,
    /// still within the `v1` media type) now that it emits upload-time/size/versions.
    #[test]
    fn test_pep691_meta_api_version() {
        let files = vec![FileEntry {
            filename: "pkg-1.0.tar.gz".into(),
            sha256: None,
            ..Default::default()
        }];
        let response =
            versions_json_response("pkg", &files, "http://nora:4000", &Default::default());
        let bytes =
            futures::executor::block_on(axum::body::to_bytes(response.into_body(), 1024 * 1024))
                .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(
            json["meta"]["api-version"], "1.1",
            "PEP 700 support is signalled by meta.api-version = '1.1'"
        );
    }

    /// PEP 691 JSON Content-Type must be `application/vnd.pypi.simple.v1+json`.
    #[test]
    fn test_pep691_content_type() {
        let files = vec![];
        let response =
            versions_json_response("pkg", &files, "http://nora:4000", &Default::default());
        let ct = response
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            ct, PEP691_JSON,
            "PEP 691 requires Content-Type: {PEP691_JSON}"
        );
    }

    /// PEP 691: the `hashes` dictionary MUST be present even when no hash is available
    /// (uv rejects the whole project page without it), as `{}`, not null.
    #[test]
    fn test_pep691_hashes_empty_when_none() {
        let files = vec![FileEntry {
            filename: "pkg-1.0.tar.gz".into(),
            sha256: None,
            ..Default::default()
        }];
        let response =
            versions_json_response("pkg", &files, "http://nora:4000", &Default::default());
        let bytes =
            futures::executor::block_on(axum::body::to_bytes(response.into_body(), 1024 * 1024))
                .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(
            json["files"][0]["hashes"],
            serde_json::json!({}),
            "R2-29: PEP 691 hashes MUST be present, empty when no hash is known"
        );
    }

    /// PEP 691: `name` field must match the normalized package name.
    #[test]
    fn test_pep691_name_is_normalized() {
        let files = vec![];
        let normalized = normalize_name("Flask-RESTful");
        let response =
            versions_json_response(&normalized, &files, "http://nora:4000", &Default::default());
        let bytes =
            futures::executor::block_on(axum::body::to_bytes(response.into_body(), 1024 * 1024))
                .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(json["name"], "flask-restful");
    }

    /// PEP 691: file URLs must point to NORA, not upstream.
    #[test]
    fn test_pep691_urls_point_to_nora() {
        let files = vec![
            FileEntry {
                filename: "pkg-1.0.tar.gz".into(),
                sha256: Some("aaa".into()),
                ..Default::default()
            },
            FileEntry {
                filename: "pkg-2.0.whl".into(),
                sha256: Some("bbb".into()),
                ..Default::default()
            },
        ];
        let response =
            versions_json_response("pkg", &files, "http://nora:4000", &Default::default());
        let bytes =
            futures::executor::block_on(axum::body::to_bytes(response.into_body(), 1024 * 1024))
                .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        for file in json["files"].as_array().unwrap() {
            let url = file["url"].as_str().unwrap();
            assert!(
                url.starts_with("http://nora:4000/simple/"),
                "file URL must point to NORA base: {url}"
            );
        }
    }

    // ========================================================================
    // URL-rewrite systematic tests (#387)
    // ========================================================================

    /// URLs in HTML response must point to NORA, not upstream (#387).
    #[test]
    fn test_html_urls_point_to_nora_no_upstream_leak() {
        let files = vec![
            FileEntry {
                filename: "requests-2.31.0.tar.gz".into(),
                sha256: Some("aaa111".into()),
                ..Default::default()
            },
            FileEntry {
                filename: "requests-2.31.0-py3-none-any.whl".into(),
                sha256: Some("bbb222".into()),
                ..Default::default()
            },
        ];
        let response = versions_html_response("requests", &files, "http://nora:4000");
        let bytes =
            futures::executor::block_on(axum::body::to_bytes(response.into_body(), 1024 * 1024))
                .unwrap();
        let html = String::from_utf8(bytes.to_vec()).unwrap();

        assert!(
            html.contains("http://nora:4000/simple/requests/requests-2.31.0.tar.gz"),
            "HTML must contain NORA URL for tarball"
        );
        assert!(
            html.contains("http://nora:4000/simple/requests/requests-2.31.0-py3-none-any.whl"),
            "HTML must contain NORA URL for wheel"
        );
        // No upstream host leak
        assert!(
            !html.contains("pypi.org") && !html.contains("pythonhosted"),
            "HTML must not contain upstream URLs"
        );
    }

    /// Trailing slash on base_url must not produce double-slash in URLs (#387).
    #[test]
    fn test_pep691_trailing_slash_handling() {
        let files = vec![FileEntry {
            filename: "pkg-1.0.tar.gz".into(),
            sha256: Some("abc".into()),
            ..Default::default()
        }];
        let response =
            versions_json_response("pkg", &files, "http://nora:4000/", &Default::default());
        let bytes =
            futures::executor::block_on(axum::body::to_bytes(response.into_body(), 1024 * 1024))
                .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let url = json["files"][0]["url"].as_str().unwrap();
        assert!(
            !url.contains("//simple"),
            "trailing slash on base_url must not produce double-slash: {url}"
        );
        assert!(
            url.starts_with("http://nora:4000/"),
            "URL must start with base: {url}"
        );
    }

    /// Empty file list produces valid response with no file URLs (#387).
    #[test]
    fn test_pep691_no_files_clean_response() {
        let files: Vec<FileEntry> = vec![];
        let response =
            versions_json_response("empty-pkg", &files, "http://nora:4000", &Default::default());
        let bytes =
            futures::executor::block_on(axum::body::to_bytes(response.into_body(), 1024 * 1024))
                .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["files"].as_array().unwrap().len(), 0);
        assert_eq!(json["name"], "empty-pkg");
    }

    /// Upstream HTML with no matching package links → empty file list (#387).
    #[test]
    fn test_parse_upstream_no_package_links_yields_empty() {
        let html = r#"<html><body>
            <a href="https://example.com/page">Not a package</a>
            <a href="/about">About</a>
        </body></html>"#;
        let files = parse_upstream_files(html, "https://pypi.org/simple/x/");
        assert!(
            files.is_empty(),
            "HTML without package links should yield empty list"
        );
    }

    /// PEP 691 response must be valid JSON and deserializable back to typed struct.
    #[test]
    fn test_pep691_response_round_trip() {
        let files = vec![FileEntry {
            filename: "pkg-1.0.tar.gz".into(),
            sha256: Some("abc123".into()),
            ..Default::default()
        }];
        let response =
            versions_json_response("pkg", &files, "http://nora:4000", &Default::default());
        let bytes =
            futures::executor::block_on(axum::body::to_bytes(response.into_body(), 1024 * 1024))
                .unwrap();

        // Must parse as valid JSON with expected top-level keys
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(json.get("meta").is_some(), "missing 'meta' key");
        assert!(json.get("name").is_some(), "missing 'name' key");
        assert!(json.get("files").is_some(), "missing 'files' key");

        // Snapshot the structure
        insta::assert_json_snapshot!("pypi_pep691_response_structure", json);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod local_index_cost_tests {
    //! The simple index over locally stored files must cost the same storage round-trips
    //! for 1 and 100 files, in both the HTML and the JSON form.
    use crate::test_helpers::{
        body_bytes, create_test_context_with_storage, op_counting_storage, send_with_headers,
        TestContext,
    };
    use axum::http::{Method, StatusCode};

    pub(super) const BOUNDARY: &str = "nora-test-boundary";
    const JSON: &str = "application/vnd.pypi.simple.v1+json";
    const HTML: &str = "text/html";

    pub(super) fn upload_body(
        name: &str,
        version: &str,
        filename: &str,
        content: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        for (field, value) in [
            (":action", "file_upload"),
            ("name", name),
            ("version", version),
        ] {
            body.extend_from_slice(
                format!(
                    "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{field}\"\r\n\r\n{value}\r\n"
                )
                .as_bytes(),
            );
        }
        body.extend_from_slice(
            format!(
                "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"content\"; filename=\"{filename}\"\r\n\
                 Content-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(content);
        body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
        body
    }

    async fn upload(ctx: &TestContext, version: &str) {
        let filename = format!("costpkg-{version}-py3-none-any.whl");
        let content_type = format!("multipart/form-data; boundary={BOUNDARY}");
        let body = upload_body(
            "costpkg",
            version,
            &filename,
            format!("wheel {version}").as_bytes(),
        );
        let resp = send_with_headers(
            &ctx.app,
            Method::POST,
            "/simple/",
            vec![("content-type", content_type.as_str())],
            body,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "upload {filename}");
    }

    async fn index_ops(n: usize, accept: &str) -> (usize, String) {
        let (storage, ops) = op_counting_storage();
        let ctx = create_test_context_with_storage(storage);
        for i in 0..n {
            upload(&ctx, &format!("1.0.{i}")).await;
        }
        ops.reset();
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/costpkg/",
            vec![("Accept", accept)],
            "",
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "index of {n} local files ({accept})"
        );
        let counted = (ops.total(), format!("{:?}", ops.snapshot()));
        let body = String::from_utf8(body_bytes(resp).await.to_vec()).unwrap();
        assert!(
            body.matches("sha256").count() >= n,
            "every one of the {n} local files must carry its sha256 ({accept})"
        );
        counted
    }

    #[tokio::test]
    async fn pypi_simple_json_cost_is_independent_of_local_file_count() {
        let (small, small_ops) = index_ops(1, JSON).await;
        let (large, large_ops) = index_ops(100, JSON).await;
        assert_eq!(
            small, large,
            "the JSON simple index must cost the same storage round-trips for 1 and 100 local files: {small_ops} vs {large_ops}"
        );
    }

    #[tokio::test]
    async fn pypi_simple_html_cost_is_independent_of_local_file_count() {
        let (small, small_ops) = index_ops(1, HTML).await;
        let (large, large_ops) = index_ops(100, HTML).await;
        assert_eq!(
            small, large,
            "the HTML simple index must cost the same storage round-trips for 1 and 100 local files: {small_ops} vs {large_ops}"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod hash_marker_tests {
    //! The index trusts a file's hash marker only when it has exactly one; every other case
    //! is served from the `.sha256` sidecar and repaired in the background.
    use super::local_index_cost_tests::{upload_body, BOUNDARY};
    use super::{hash_marker_key, parse_hash_marker, HASH_MARKER_PREFIX};
    use crate::test_helpers::{
        body_bytes, create_test_context, create_test_context_with_storage,
        create_test_context_with_storage_and_config, op_counting_storage, send, send_with_headers,
        TestContext,
    };
    use axum::http::{Method, StatusCode};
    use sha2::Digest as _;

    fn digest(content: &[u8]) -> String {
        hex::encode(sha2::Sha256::digest(content))
    }

    async fn html_index(ctx: &TestContext, project: &str) -> String {
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            &format!("/simple/{project}/"),
            vec![("Accept", "text/html")],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "index of {project}");
        String::from_utf8(body_bytes(resp).await.to_vec()).unwrap()
    }

    /// Wait for the markers under `pypi-sha256/<project>/` to become exactly `expected`.
    ///
    /// Markers written by a background task appear some time after the response; the
    /// deadline only bounds a task that never finishes.
    async fn wait_for_markers(ctx: &TestContext, project: &str, expected: &[String]) {
        use std::time::{Duration, Instant};

        let prefix = format!("{HASH_MARKER_PREFIX}{project}/");
        let mut expected = expected.to_vec();
        expected.sort();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let mut markers = ctx.state.storage.list(&prefix).await.unwrap();
            markers.sort();
            if markers == expected {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "markers under {prefix}: expected {expected:?}, found {markers:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[test]
    fn parse_hash_marker_reads_filename_and_digest() {
        let sha = "ab".repeat(32);
        let prefix = format!("{HASH_MARKER_PREFIX}pkg/");
        let filename = "pkg-1.0+local@x-py3-none-any.whl";
        let key = hash_marker_key("pkg", filename, &sha);
        assert_eq!(
            parse_hash_marker(&prefix, &key),
            Some((filename, sha.as_str()))
        );
        for (malformed, why) in [
            (format!("{prefix}pkg-1.0.tar.gz/abc"), "short digest"),
            (format!("{prefix}pkg-1.0.tar.gz"), "no digest"),
            (format!("{prefix}/{sha}"), "no filename"),
            (format!("{prefix}a/b/{sha}"), "nested path"),
        ] {
            assert_eq!(parse_hash_marker(&prefix, &malformed), None, "{why}");
        }
        assert_eq!(
            parse_hash_marker(&format!("{HASH_MARKER_PREFIX}other/"), &key),
            None,
            "marker of another project"
        );
    }

    /// Files stored before markers existed are served from their sidecars, backfilled, and
    /// then cost no sidecar read.
    #[tokio::test]
    async fn legacy_sidecar_digests_are_served_then_backfilled() {
        let (storage, ops) = op_counting_storage();
        let ctx = create_test_context_with_storage(storage);
        let mut digests = Vec::new();
        let mut expected = Vec::new();
        for i in 0..3 {
            let filename = format!("legacypkg-1.0.{i}-py3-none-any.whl");
            let content = format!("legacy wheel {i}");
            let sha = digest(content.as_bytes());
            let key = format!("pypi/legacypkg/{filename}");
            ctx.state
                .storage
                .put(&key, content.as_bytes())
                .await
                .unwrap();
            ctx.state
                .storage
                .put(&format!("{key}.sha256"), sha.as_bytes())
                .await
                .unwrap();
            expected.push(hash_marker_key("legacypkg", &filename, &sha));
            digests.push(sha);
        }

        let body = html_index(&ctx, "legacypkg").await;
        for sha in &digests {
            assert!(
                body.contains(sha.as_str()),
                "sidecar digest {sha} served: {body}"
            );
        }
        wait_for_markers(&ctx, "legacypkg", &expected).await;

        ops.reset();
        let body = html_index(&ctx, "legacypkg").await;
        for sha in &digests {
            assert!(
                body.contains(sha.as_str()),
                "marker digest {sha} served: {body}"
            );
        }
        assert!(
            !ops.snapshot().contains_key("get"),
            "no sidecar is read once markers exist: {:?}",
            ops.snapshot()
        );
    }

    /// A file left with a stale marker next to its own is served from its sidecar, and the
    /// stale marker is removed.
    #[tokio::test]
    async fn conflicting_markers_fall_back_to_the_sidecar_and_are_repaired() {
        // In-memory object store: the repair runs in the background, and a local disk
        // would add fsync latency to what the test waits for.
        let (backend, _ops) = op_counting_storage();
        let ctx = create_test_context_with_storage(backend);
        let filename = "dup-1.0-py3-none-any.whl";
        let key = format!("pypi/dup/{filename}");
        let current = digest(b"current bytes");
        let stale = digest(b"earlier bytes");
        let storage = &ctx.state.storage;
        storage.put(&key, b"current bytes").await.unwrap();
        storage
            .put(&format!("{key}.sha256"), current.as_bytes())
            .await
            .unwrap();
        for sha in [&current, &stale] {
            storage
                .put(&hash_marker_key("dup", filename, sha), b"")
                .await
                .unwrap();
        }

        let body = html_index(&ctx, "dup").await;
        assert!(
            body.contains(current.as_str()),
            "current digest served: {body}"
        );
        assert!(
            !body.contains(stale.as_str()),
            "stale digest not served: {body}"
        );
        wait_for_markers(&ctx, "dup", &[hash_marker_key("dup", filename, &current)]).await;
    }

    /// C54: an uploaded file that fails its pin is the only copy: it is kept and
    /// answered 500, and the file is never fetched from the upstream.
    #[tokio::test]
    async fn tampered_uploaded_file_is_kept_not_refetched() {
        use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"upstream".to_vec()))
            .mount(&upstream)
            .await;
        let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
            cfg.pypi.proxy = Some(upstream.uri());
        });
        let filename = "ours-1.0-py3-none-any.whl";
        let content_type = format!("multipart/form-data; boundary={BOUNDARY}");
        let resp = send_with_headers(
            &ctx.app,
            Method::POST,
            "/simple/",
            vec![("content-type", content_type.as_str())],
            upload_body("ours", "1.0", filename, b"our wheel"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let key = format!("pypi/ours/{filename}");
        std::fs::write(
            std::path::Path::new(&ctx.state.config.storage.path).join(&key),
            b"rotten",
        )
        .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            &format!("/simple/ours/{filename}"),
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            ctx.state.storage.stat(&key).await.is_some(),
            "the only copy is kept"
        );
        // The index may be read for release dates; the file is never fetched.
        let requests = upstream.received_requests().await.unwrap();
        assert!(!requests.iter().any(|r| r.url.path().ends_with(".whl")));
    }

    /// Uploading a filename that was deleted and is stored again with other bytes replaces
    /// the marker left by the earlier file.
    #[tokio::test]
    async fn upload_replaces_a_stale_marker_of_the_same_filename() {
        let ctx = create_test_context();
        let filename = "reup-1.0-py3-none-any.whl";
        let stale = digest(b"earlier bytes");
        ctx.state
            .storage
            .put(&hash_marker_key("reup", filename, &stale), b"")
            .await
            .unwrap();

        let content_type = format!("multipart/form-data; boundary={BOUNDARY}");
        let resp = send_with_headers(
            &ctx.app,
            Method::POST,
            "/simple/",
            vec![("content-type", content_type.as_str())],
            upload_body("reup", "1.0", filename, b"current bytes"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let current = digest(b"current bytes");
        let markers = ctx
            .state
            .storage
            .list(&format!("{HASH_MARKER_PREFIX}reup/"))
            .await
            .unwrap();
        assert_eq!(markers, vec![hash_marker_key("reup", filename, &current)]);
        let body = html_index(&ctx, "reup").await;
        assert!(
            body.contains(current.as_str()) && !body.contains(stale.as_str()),
            "{body}"
        );
    }

    /// A file cached from the upstream is stored with its hash marker.
    #[tokio::test]
    async fn proxied_file_is_cached_with_its_hash_marker() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        let filename = "proxied-1.0.tar.gz";
        let content = b"proxied sdist";
        Mock::given(method("GET"))
            .and(path("/proxied/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                "<html><body><a href=\"{}/files/{filename}\">{filename}</a></body></html>",
                upstream.uri()
            )))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/files/{filename}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(content.to_vec()))
            .mount(&upstream)
            .await;
        // In-memory object store: the cache write runs in the background, and a local disk
        // would add fsync latency to what the test waits for.
        let (backend, _ops) = op_counting_storage();
        let ctx = create_test_context_with_storage_and_config(backend, |cfg| {
            cfg.pypi.proxy = Some(upstream.uri());
        });

        let resp = send(
            &ctx.app,
            Method::GET,
            &format!("/simple/proxied/{filename}"),
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "proxied download served");
        wait_for_markers(
            &ctx,
            "proxied",
            &[hash_marker_key("proxied", filename, &digest(content))],
        )
        .await;
    }
}

#[cfg(test)]
mod upstream_failure_cases {
    use crate::circuit_breaker::ProbeToken;
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// the index lists the file on a host that answers 404 — the upstream said
    /// "not found", so 404, not 502.
    #[tokio::test]
    async fn file_host_answering_404_is_404() {
        let missing = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&missing)
            .await;
        let lists_missing = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/flask/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"<html><body><a href="{}/files/flask-2.0.tar.gz">flask-2.0.tar.gz</a></body></html>"#,
                missing.uri()
            )))
            .mount(&lists_missing)
            .await;
        let urls = vec![lists_missing.uri()];
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.pypi.proxies = serde_json::from_value(serde_json::json!(urls)).unwrap();
        });
        let resp = send(&ctx.app, Method::GET, "/simple/flask/flask-2.0.tar.gz", "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(!missing.received_requests().await.unwrap().is_empty());
    }

    /// one upstream's breaker is open, the other failed — the open breaker still
    /// answers 503 (retryable), as before the change.
    #[tokio::test]
    async fn open_breaker_with_failed_peer_is_503() {
        let down = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&down)
            .await;
        let open = "http://127.0.0.1:1".to_string();
        let urls = vec![open.clone(), down.uri()];
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.circuit_breaker.enabled = true;
            cfg.circuit_breaker.failure_threshold = 2;
            cfg.circuit_breaker.reset_timeout = 3600;
            cfg.pypi.proxies = serde_json::from_value(serde_json::json!(urls)).unwrap();
        });
        let key = crate::circuit_breaker::upstream_key("pypi", &open);
        ctx.state
            .circuit_breaker
            .record_failure(&key, ProbeToken::BACKGROUND);
        ctx.state
            .circuit_breaker
            .record_failure(&key, ProbeToken::BACKGROUND);
        for uri in ["/simple/flask/flask-2.0.tar.gz", "/simple/flask/"] {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "{uri}");
        }
    }
}

#[cfg(test)]
mod upstream_failure_edge_cases {
    use crate::circuit_breaker::ProbeToken;
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// The index alone, one upstream's breaker open and the other failed with
    /// its own breaker still closed — the open breaker answers 503, as before the change.
    #[tokio::test]
    async fn index_open_breaker_with_failed_peer_is_503() {
        let down = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&down)
            .await;
        let open = "http://127.0.0.1:1".to_string();
        let urls = vec![open.clone(), down.uri()];
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.circuit_breaker.enabled = true;
            cfg.circuit_breaker.failure_threshold = 2;
            cfg.circuit_breaker.reset_timeout = 3600;
            cfg.pypi.proxies = serde_json::from_value(serde_json::json!(urls)).unwrap();
        });
        let key = crate::circuit_breaker::upstream_key("pypi", &open);
        for _ in 0..2 {
            ctx.state
                .circuit_breaker
                .record_failure(&key, ProbeToken::BACKGROUND);
        }
        let resp = send(&ctx.app, Method::GET, "/simple/flask/", "").await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!down.received_requests().await.unwrap().is_empty());
    }
}
