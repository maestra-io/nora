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
#[cfg(test)]
use nora_registry::pypi_files::extract_filename;
use nora_registry::pypi_files::{parse_upstream_files, FileEntry};
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
    // A hosted (imported) project lists only its own publishes: no upstream date holds them.
    // `package_versions` read the project's records already and says so on its response.
    if resp.extensions().get::<HostedProject>().is_some() {
        return resp;
    }
    let dates = ensure_pypi_dates_cached(&state, &normalized, None).await;
    crate::metadata_filter::rewrite_body(resp, |body| {
        crate::metadata_filter::pypi_index(engine, &normalized, body, &dates)
    })
    .await
}

/// Set on the index response of a hosted project, for [`package_versions_filtered`].
#[derive(Clone)]
struct HostedProject;

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
    if !crate::validation::is_one_segment(&normalized) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let prefix = format!("pypi/{}/", normalized);
    let base_url = nora_base_url(&state);

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
    // A project imported from the operator's own registry is NORA's: neither its index nor its
    // dates are asked of an upstream, and it lists only its own files.
    // The three listings of a project (records, files, hash markers) run together: each is a
    // LIST on an object store, and in a row they were three round-trips per index request.
    let marker_prefix = format!("{HASH_MARKER_PREFIX}{normalized}/");
    let (records, keys, marker_listing) = tokio::join!(
        own_records(&state.storage, &normalized),
        state.storage.list_with_meta(&prefix),
        state.storage.list(&marker_prefix),
    );
    let Some(records) = records else {
        return crate::registry::storage_unavailable("pypi", &own_prefix(&normalized));
    };
    let hosted = records.hosted();

    // Collect local files with their hashes and sizes. `list_with_meta` carries the
    // size from the listing itself; a per-key `stat()` is a HEAD per file on S3 and
    // must never appear on this path (#738, regressed on the JSON index by #969).
    let keys = match keys {
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
    let (marker_keys, markers_listed) = match marker_listing {
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
                && match records.file(filename) {
                    own::File::Proxied | own::File::Own => true,
                    own::File::Foreign => false,
                }
            {
                let sha256 = match markers.get(filename).map(Vec::as_slice) {
                    Some([sha256]) => Some((*sha256).to_string()),
                    _ => {
                        if markers_listed {
                            backfill.push(filename.to_string());
                        }
                        // A file without a sidecar is listed without a digest; one whose
                        // sidecar the store cannot read is not listed as if it had none.
                        let sidecar = format!("{}.sha256", key);
                        match state.storage.get(&sidecar).await {
                            Ok(d) => String::from_utf8(d.to_vec()).ok(),
                            Err(crate::storage::StorageError::NotFound) => None,
                            Err(e) => {
                                return crate::registry::local_copy_unreadable(
                                    "pypi", &sidecar, &e,
                                );
                            }
                        }
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
    let mut files = local_files;
    let mut stale = false;
    if !is_internal && !hosted && !state.config.pypi.upstreams().is_empty() {
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
            let dates = if hosted {
                serde_json::Map::new()
            } else {
                ensure_pypi_dates_cached(&state, &normalized, None).await
            };
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
        if hosted {
            response.extensions_mut().insert(HostedProject);
        }
        return response;
    }

    // A hosted project with no file left lists nothing; the upstream was not asked.
    if hosted {
        return StatusCode::NOT_FOUND.into_response();
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
    // An empty merge beside an open breaker is no answer: the upstream that is down may list
    // the project.
    if fetch.answered && !(fetch.files.is_empty() && fetch.circuit_open) {
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
    if !crate::validation::is_one_segment(&normalized) {
        return StatusCode::BAD_REQUEST.into_response();
    }

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
    let key = storage_key(&normalized, &filename);

    // A hosted project serves its own files only: a file NORA holds under its name without a
    // record — one an upstream served before the import — is no file of it, and neither is one
    // NORA does not hold; the upstream is not asked.
    let Some(records) = own_records(&state.storage, &normalized).await else {
        return crate::registry::storage_unavailable("pypi", &own_prefix(&normalized));
    };
    let own_file = match records.file(&filename) {
        own::File::Own => true,
        own::File::Foreign => return StatusCode::NOT_FOUND.into_response(),
        own::File::Proxied => false,
    };

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

    // A hosted file (internal namespace, an own file of an imported project, or uploaded /
    // imported here: stored without the proxy's provenance marker) is our own publish, not an
    // upstream artifact: never held by the quarantine (R2-23, as npm's C30), never dated
    // upstream (R2-45).
    let hosted = internal
        || own_file
        || ((quarantine_on || state.config.server.trust_upstream_dates)
            // The marker first: it alone tells a proxied copy, the common hit, so that one
            // costs a single HEAD before its GET.
            && state
                .storage
                .stat(&proxied_marker_key(&key))
                .await
                .is_none()
            && state.storage.stat(&key).await.is_some());
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
        extract_pypi_publish_date(&state, &normalized, &filename, &key).await
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
    // quarantine holds artifacts or an integrity rule applies to the file.
    if headers.contains_key(header::RANGE)
        && matches!(q_mode, crate::digest_quarantine::QuarantineMode::Off)
        && !crate::curation::integrity_applies(
            &state.curation().curation_engine,
            crate::curation::RegistryType::PyPI,
            &normalized,
            version.as_deref(),
        )
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
    let cached = match read_cached_artifact(&state, "pypi", &key, internal || own_file).await {
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
            // A digest with no record counts from when its copy was cached (R4-C05).
            if let Some(resp) = crate::digest_quarantine::cache_gate_digest(
                &state.digest_store,
                &state.storage,
                &key,
                "pypi",
                &cached.digest(),
                &q_mode,
                q_secs,
                crate::digest_quarantine::first_seen_seed(
                    state.config.server.trust_upstream_dates,
                    publish_date,
                ),
            )
            .await
            {
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
            cached.into_body(&state, "pypi", &key, internal || own_file),
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

    // An own file of a hosted project that NORA no longer holds is not asked of the upstream
    // either (one it cannot read was answered 503/500 above).
    if own_file {
        return StatusCode::NOT_FOUND.into_response();
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

        // The upstream's credential goes to the upstream's own origin only: an index may name its
        // files on another host, which must not receive it (pip scopes a credential the same way).
        let file_auth = if same_origin(&file_url, up.url()) {
            up.auth().map(UpstreamAuth::Basic)
        } else {
            None
        };
        // A file above `server.stream_threshold_mb` is spooled to disk (C17).
        match proxy_fetch_artifact(
            &state,
            &key,
            "pypi",
            &file_url,
            state.config.pypi.proxy_timeout,
            file_auth,
            BreakerScope::upstream(RegistryType::PyPI, up.url()),
        )
        .await
        {
            Ok((data, fetched)) => {
                let fetched = fetched.settle();
                // Hashed once (a spooled body already carries it).
                let sha256 = data.sha256();
                // The index published this file's digest: a body that does not match
                // (truncated, corrupted, tampered) is neither served nor cached.
                if let Some(expected) = expected_sha256 {
                    let actual = &sha256;
                    if !actual.eq_ignore_ascii_case(expected) {
                        tracing::warn!(package = %normalized, filename = %filename, upstream = %up.url(), %expected, %actual, "PyPI upstream file does not match the index sha256, refusing it");
                        return (
                            StatusCode::BAD_GATEWAY,
                            "upstream file does not match the sha256 its index gives",
                        )
                            .into_response();
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
                        crate::digest_quarantine::first_seen_seed(
                            state.config.server.trust_upstream_dates,
                            publish_date,
                        ),
                    )
                    .await
                    {
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
    // A hosted project's own wheel is served from local copies only; a wheel that is not one
    // of its files has no metadata here, and neither is asked of an upstream.
    let Some(records) = own_records(&state.storage, normalized).await else {
        return crate::registry::storage_unavailable("pypi", &own_prefix(normalized));
    };
    let internal = match records.file(wheel) {
        own::File::Foreign => return StatusCode::NOT_FOUND.into_response(),
        own::File::Own => true,
        own::File::Proxied => crate::curation::is_internal_namespace(
            &state.curation().curation_engine,
            crate::curation::RegistryType::PyPI,
            normalized,
        ),
    };
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
        // Like the file itself: the credential goes to the upstream's own origin only.
        let auth = if same_origin(&url, up.url()) {
            up.auth().map(UpstreamAuth::Basic)
        } else {
            None
        };
        match proxy_fetch_bytes(
            &state.http_client,
            &url,
            timeout,
            auth,
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

/// The text form fields of an upload that NORA reads are held in memory, each up to this many
/// bytes.
const MAX_UPLOAD_TEXT_FIELD: usize = 8 * 1024;

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
                // Read in chunks under a small cap: `field.text()` would hold a field as
                // large as `server.body_limit_mb` allows in memory before any validation.
                let mut raw = Vec::new();
                loop {
                    match field.chunk().await {
                        Ok(Some(chunk)) if raw.len() + chunk.len() > MAX_UPLOAD_TEXT_FIELD => {
                            return (
                                StatusCode::BAD_REQUEST,
                                format!("Field {field_name} exceeds {MAX_UPLOAD_TEXT_FIELD} bytes"),
                            )
                                .into_response();
                        }
                        Ok(Some(chunk)) => raw.extend_from_slice(&chunk),
                        Ok(None) => break,
                        Err(e) => return reject(e),
                    }
                }
                let value = String::from_utf8_lossy(&raw).into_owned();
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

    if let Err(response) = claim_uploaded_project(&state, &normalized).await {
        return response;
    }

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

/// R4-R04: a project with a file uploaded here is NORA's own, as a published npm name or a pushed
/// NuGet ID is. Its first upload makes it hosted before the file is stored, as `nora import`
/// does: from then on its index, JSON API and files are served from its own files only and its
/// name is never asked of an upstream (a version registered upstream under the name later is not
/// served: dependency confusion). What NORA held under the name before stays what it was: a file
/// stored without the proxy's provenance marker (an earlier upload) is recorded as one of the
/// project's own first, and a proxy cache copy is no file of it any more: neither listed nor
/// served. An internal-namespace project is owned by configuration already and is not claimed.
///
/// When an upstream is configured, the claim logs a `[SECURITY]` WARN and counts in
/// `nora_pypi_mixed_project_uploads_total`, with whether the cached upstream index lists the name:
/// a name the upstream lists stops being proxied here.
async fn claim_uploaded_project(state: &AppState, normalized: &str) -> Result<(), Response> {
    let unavailable = || crate::registry::storage_unavailable("pypi", &own_prefix(normalized));
    if crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::PyPI,
        normalized,
    ) {
        return Ok(());
    }
    let Some(records) = own_records(&state.storage, normalized).await else {
        return Err(unavailable());
    };
    if records.hosted() {
        return Ok(());
    }
    let prefix = format!("pypi/{normalized}/");
    let origins = proxied_marker_key(&prefix);
    // The files first, then their markers: a proxy cache write stores the file before its
    // marker, so the second listing sees the marker of a file the first caught mid-write.
    // ponytail: a marker written after both listings makes that copy count as an upload; a
    // lock over the cache write and the claim would close it, not worth it for a one-time claim.
    let Ok(keys) = state.storage.list(&prefix).await else {
        return Err(unavailable());
    };
    let Ok(proxied) = state.storage.list_internal(&origins).await else {
        return Err(unavailable());
    };
    let proxied: std::collections::HashSet<&str> = proxied
        .iter()
        .filter_map(|key| key.strip_prefix(&origins))
        .collect();
    for filename in keys
        .iter()
        .filter_map(|key| key.strip_prefix(&prefix))
        .filter(|f| is_valid_pypi_filename(f) && !proxied.contains(f))
    {
        if let Err(e) = record_own_file(&state.storage, normalized, filename).await {
            tracing::warn!(registry = "pypi", project = %normalized, file = %filename, error = %e, "pypi: failed to record an earlier upload");
            return Err(unavailable());
        }
    }
    if let Err(e) = claim_imported_project(&state.storage, normalized).await {
        tracing::warn!(registry = "pypi", project = %normalized, error = %e, "pypi: failed to make an uploaded project hosted");
        return Err(unavailable());
    }
    if state.config.pypi.upstreams().is_empty() {
        return Ok(());
    }
    // Only the cached index is read: an upload never sends the name to an upstream.
    let upstream_lists = match state
        .storage
        .get(&format!("{prefix}{UPSTREAM_INDEX_FILE}"))
        .await
    {
        Ok(data) => match serde_json::from_slice::<Vec<FileEntry>>(&data) {
            Ok(files) if files.is_empty() => "no",
            Ok(_) => "yes",
            Err(_) => "unknown",
        },
        Err(_) => "unknown",
    };
    crate::metrics::PYPI_MIXED_PROJECT_UPLOADS_TOTAL
        .with_label_values(&[upstream_lists])
        .inc();
    tracing::warn!(
        registry = "pypi",
        project = %normalized,
        upstream_lists,
        "[SECURITY] upload to a project outside curation.internal_namespaces while an upstream is configured: the project is now hosted, its name is no longer proxied (dependency confusion) and files cached from an upstream under it are no longer served"
    );
    Ok(())
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
    let file_key = storage_key(project, filename);
    let lock = crate::acquire_publish_lock(locks, &file_key);
    let _guard = lock.lock().await;

    // Check immutability (same filename = already exists). In a hosted project a file NORA holds
    // without a record is not one of its files — an upstream served it before the import — and
    // the upload replaces it.
    if storage.stat(&file_key).await.is_some() {
        let Some(records) = own_records(storage, project).await else {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "storage temporarily unavailable".to_string(),
            ));
        };
        if records.file(filename) != own::File::Foreign {
            return Err((
                StatusCode::CONFLICT,
                format!("File {filename} already exists"),
            ));
        }
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

    // The record last: in a hosted project a file is listed once it is recorded, so a record
    // always names the bytes this upload stored, never a file an upstream left under the name.
    if let Err(e) = record_own_file(storage, project, filename).await {
        tracing::warn!(key = %file_key, error = %e, "pypi: failed to record an uploaded file");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to record {filename}"),
        ));
    }
    Ok(())
}

/// `nora import`: the PEP 658 core metadata and `requires_python` of an imported file, as an
/// upload stores them. Written before the file's own-file record, so a file is listed with
/// them from the moment it is served.
pub(crate) async fn store_import_metadata(
    storage: &crate::storage::Storage,
    locks: &crate::PublishLocks,
    project: &str,
    filename: &str,
    core_meta: Option<Vec<u8>>,
    requires_python: &str,
) {
    if let Some(meta) = core_meta {
        put_core_metadata(storage, project, filename, &meta).await;
    }
    record_requires_python(storage, locks, project, filename, requires_python).await;
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
    /// Required by PEP 691 even when no digest is known — then it is `{}` (#1100).
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
        .flatten()
        .filter(|n| {
            n.split_once('/')
                .is_some_and(|(dir, rest)| rest == "METADATA" && dir.ends_with(".dist-info"))
        })
        .map(std::borrow::Cow::into_owned)
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
///
/// A missing listing is fetched only when a release-age rule reads the date and the file
/// is not stored yet (a cold miss goes upstream anyway): a client that reads only the
/// PEP 503 HTML index then gets the date a JSON client gets, while a cache hit (a hosted
/// package above all) never starts asking an upstream on every download.
async fn extract_pypi_publish_date(
    state: &AppState,
    normalized: &str,
    filename: &str,
    artifact_key: &str,
) -> Option<i64> {
    let dates_key = format!("pypi/{normalized}/dates.json");
    let map: serde_json::Map<String, serde_json::Value> = match state.storage.get(&dates_key).await
    {
        Ok(data) => serde_json::from_slice(&data).ok()?,
        Err(_)
            if crate::registry::release_date_read(state, RegistryType::PyPI)
                && state.storage.stat(artifact_key).await.is_none() =>
        {
            ensure_pypi_dates_cached(state, normalized, Some(filename)).await
        }
        Err(_) => return None,
    };
    if !map.contains_key(filename) {
        return None;
    }
    crate::curation::extract_mtime_as_publish_date(&state.storage, &dates_key).await
}

/// True when both URLs have the same scheme, host and port.
fn same_origin(a: &str, b: &str) -> bool {
    match (reqwest::Url::parse(a), reqwest::Url::parse(b)) {
        (Ok(a), Ok(b)) => {
            a.scheme() == b.scheme()
                && a.host_str() == b.host_str()
                && a.port_or_known_default() == b.port_or_known_default()
        }
        _ => false,
    }
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
    // Nor a hosted project's, nor one whose hosted state the store cannot tell: what an upstream
    // dated before the import does not date the project's own files.
    if own_records(&state.storage, normalized)
        .await
        .is_none_or(|records| records.hosted())
    {
        return serde_json::Map::new();
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
        // Every listed file gets an entry — null when the upstream gives no `upload-time` —
        // because the entry is what dates the file when upstream dates are untrusted. An
        // upstream without PEP 691 answers with its HTML index, which still lists the files.
        let listed: Vec<(String, Option<String>)> =
            match serde_json::from_str::<serde_json::Value>(&text) {
                Ok(json) => json
                    .get("files")
                    .and_then(|f| f.as_array())
                    .into_iter()
                    .flatten()
                    .filter_map(|fe| {
                        let fname = fe.get("filename")?.as_str()?;
                        let ut = fe.get("upload-time").and_then(|v| v.as_str());
                        Some((fname.to_string(), ut.map(str::to_string)))
                    })
                    .collect(),
                Err(_) => parse_upstream_files(&text, &url)
                    .into_iter()
                    .map(|f| (f.filename, None))
                    .collect(),
            };
        for (fname, ut) in listed {
            let entry = map.entry(fname).or_insert(serde_json::Value::Null);
            if let (true, Some(ut)) = (entry.is_null(), ut) {
                *entry = serde_json::Value::String(ut);
            }
        }
        if map.values().any(serde_json::Value::is_string) {
            break; // first upstream that listed dated files wins
        }
    }
    upstream_answered.then_some(map)
}

/// Normalize package name according to PEP 503 — the one normalization curation also uses
/// (`curation::pep503_normalize`): lowercase, every run of `-`, `_` and `.` one `-`.
pub(crate) fn normalize_name(name: &str) -> String {
    crate::curation::pep503_normalize(name)
}

/// The key of distribution file `filename` of project `normalized` (PEP 503): the one an upload
/// writes and a download reads. `nora import` writes the same key (contract
/// `import-key-format-equals-handler-key-format`).
pub(crate) fn storage_key(normalized: &str, filename: &str) -> String {
    format!("pypi/{normalized}/{filename}")
}

/// Storage prefix of what NORA records of the projects it owns: `pypi-own/<project>/`.
///
/// - `pypi-own/<project>/files/<filename>` — a file of the project that is NORA's own: an upload
///   or an import writes it with the file.
/// - `pypi-own/<project>/imported` — the project is hosted: `nora import` writes it when it
///   brings in a file of the project from the operator's own registry. From then on neither the
///   project's index, its dates nor a file of it is asked of an upstream, and only its own files
///   are listed and served: a file an upstream served under the name before the import is not.
///
/// One listing of the prefix answers both. The records live outside `pypi/`, so the listings of
/// `pypi/` that retention, the web UI and the simple index read never take one for a
/// distribution file.
pub(crate) const OWN_PREFIX: &str = "pypi-own/";

/// The prefix of project `normalized`'s records.
fn own_prefix(normalized: &str) -> String {
    format!("{OWN_PREFIX}{normalized}/")
}

/// The record that file `filename` of project `normalized` is NORA's own.
pub(crate) fn own_file_key(normalized: &str, filename: &str) -> String {
    format!("{OWN_PREFIX}{normalized}/files/{filename}")
}

/// What a project's records say of it and of each of its files, read from one listing of them.
/// What a file is, is asked of [`own::Records::file`] alone: the records themselves are private
/// to the module, so no handler decides by them otherwise.
mod own {
    use std::collections::HashSet;

    /// What one file of a project is.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum File {
        /// The project is not hosted: the file is what storage and the upstreams hold.
        Proxied,
        /// The project is hosted and the file is one of its own: listed and served, never asked
        /// of an upstream.
        Own,
        /// The project is hosted and the file is not one of its own: what an upstream served
        /// under the name before the import, or a file NORA does not hold. Neither listed nor
        /// served, nor asked of an upstream; an upload replaces it.
        Foreign,
    }

    /// The records of one project.
    pub(super) struct Records {
        hosted: bool,
        files: HashSet<String>,
    }

    impl Records {
        /// A project nothing is recorded of.
        pub(super) fn none() -> Self {
            Self {
                hosted: false,
                files: HashSet::new(),
            }
        }

        /// The records `names` name: the keys under the project's prefix, without it. The marker
        /// `imported` makes the project hosted, and `files/<filename>` records a file of it.
        pub(super) fn from_listing<'a>(names: impl IntoIterator<Item = &'a str>) -> Self {
            let mut records = Self::none();
            for name in names {
                if name == "imported" {
                    records.hosted = true;
                } else if let Some(file) = name.strip_prefix("files/") {
                    records.files.insert(file.to_owned());
                }
            }
            records
        }

        /// Whether the project is hosted: neither its index nor its dates are asked of an
        /// upstream.
        pub(super) fn hosted(&self) -> bool {
            self.hosted
        }

        /// What file `filename` of the project is. A hosted project without a record of the file
        /// — the marker is written first, so a record write that failed or a process that stopped
        /// leaves none — does not own it.
        pub(super) fn file(&self, filename: &str) -> File {
            match (self.hosted, self.files.contains(filename)) {
                (false, _) => File::Proxied,
                (true, true) => File::Own,
                (true, false) => File::Foreign,
            }
        }
    }
}

/// The records of project `normalized`, or `None` when the listing failed: nothing is decided on
/// a guess.
async fn own_records(storage: &crate::storage::Storage, normalized: &str) -> Option<own::Records> {
    let prefix = own_prefix(normalized);
    if crate::validation::validate_storage_key(crate::validation::listing_key(&prefix)).is_err() {
        return Some(own::Records::none());
    }
    // Asked on every request of every project, and empty for all but NORA's own: an
    // empty answer is remembered for `EMPTY_PREFIX_TTL` (R4-P01). A record written
    // through this process (an upload) is seen at once, one written by another (a
    // `nora import` run, a second replica) within the TTL.
    match storage.list_often_empty(&prefix).await {
        Ok(keys) => Some(own::Records::from_listing(
            keys.iter().filter_map(|k| k.strip_prefix(&prefix)),
        )),
        Err(e) => {
            tracing::warn!(registry = "pypi", project = %normalized, error = %e, "pypi: own records not listed");
            None
        }
    }
}

/// Make project `normalized` hosted. Written before the first file of it is stored, so from the
/// moment an import stores anything of the project its name is no longer asked of an upstream.
pub(crate) async fn claim_imported_project(
    storage: &crate::storage::Storage,
    normalized: &str,
) -> crate::storage::Result<()> {
    storage
        .put(&format!("{}imported", own_prefix(normalized)), b"")
        .await
}

/// Record file `filename` of project `normalized` as NORA's own. Written after the file and its
/// digest are stored: a hosted project lists a file only once it is recorded, so a record always
/// names bytes NORA stored, never what an upstream left under the same name.
pub(crate) async fn record_own_file(
    storage: &crate::storage::Storage,
    normalized: &str,
    filename: &str,
) -> crate::storage::Result<()> {
    storage.put(&own_file_key(normalized, filename), b"").await
}

/// Record the SHA-256 of a distribution file stored at `storage_key(project, filename)`, as an
/// upload records it: the `.sha256` sidecar the index serves the digest from, then the hash
/// marker. A failed sidecar write is returned; a failed marker write is logged, and the index
/// serves the digest from the sidecar.
pub(crate) async fn record_stored_file(
    storage: &crate::storage::Storage,
    normalized: &str,
    filename: &str,
    sha256: &str,
) -> crate::storage::Result<()> {
    let file_key = storage_key(normalized, filename);
    storage
        .put(&format!("{file_key}.sha256"), sha256.as_bytes())
        .await?;
    put_hash_marker(storage, normalized, filename, sha256).await;
    Ok(())
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
        && nora_registry::pypi_files::served_extension(name).is_some()
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
mod tests;

// ============================================================================
// Integration Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests;

// ============================================================================
// PEP 691 spec conformance tests
// ============================================================================

#[cfg(test)]
mod spec_conformance_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod local_index_cost_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod hash_marker_tests;

#[cfg(test)]
mod upstream_failure_cases;

#[cfg(test)]
mod upstream_failure_edge_cases;

/// A name or path with an empty segment (or, where the name is one segment, any `/`) never
/// reaches curation, storage or an upstream: it would name another artifact's files, and an
/// upstream that normalises paths would answer for that other artifact.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod empty_segment_requests;

/// Property tests against PEP 503: the normalized name is the registry's key for a project, so
/// every spelling a client or an uploader may use lands on the one key pip asks for.
#[cfg(test)]
mod name_normalization_properties;

/// A version-specific blocklist rule holds for every spelling of an sdist's file name.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod blocked_version_in_any_sdist_spelling;

/// A PyPI version is the version PEP 440 reads, not its spelling: pip compares parsed versions
/// (`packaging.version.Version`), so a rule or an allowlist entry holds for every spelling of
/// its version — `1.0-1` is `1.0.post1`, `2.0.0.RC1` is `2.0rc1`, `1.0.0` is `1.0`.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod pep440_version_curation;

/// Release age reaches a PEP 503 (HTML) client: pip before 22.2 never asks for the PEP 691
/// JSON index, which used to be the only request that cached `dates.json`, so its downloads
/// carried no date and min-release-age let every one of them through. A file is dated by the
/// listing NORA cached, and only if that listing names it.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod release_age_without_the_json_index;

/// A file the upstream index names with `#sha256=` is served only when its bytes have that
/// digest: pip checks it against the index NORA serves, and once NORA cached the file its own
/// digest would stand in for the upstream's, so wrong bytes would pass on the next install.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod upstream_index_digest;

#[cfg(test)]
mod own_memo_tests;
