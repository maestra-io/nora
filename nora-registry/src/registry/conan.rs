// Copyright (c) 2026 The Nora Authors
// SPDX-License-Identifier: MIT

//! Conan V2 proxy registry (C/C++ packages).
//!
//! Implements a caching proxy for ConanCenter (center2.conan.io):
//!
//! ## Endpoints
//!   GET /conan/v1/ping                             — health + capabilities (v2 client compat)
//!   GET /conan/v2/ping                             — health + capabilities
//!   GET /conan/v2/conans/search                    — search recipes
//!   GET /conan/v2/conans/{name}/{ver}/{user}/{chan}/latest — latest recipe revision
//!   GET /conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions — list recipe revisions
//!   GET /conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions/{rrev}/files — list recipe files
//!   GET /conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions/{rrev}/files/{filename} — download recipe file (immutable)
//!   GET /conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions/{rrev}/packages/{pkg_id}/latest — latest package revision
//!   GET /conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions/{rrev}/packages/{pkg_id}/revisions — list package revisions
//!   GET /conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions/{rrev}/packages/{pkg_id}/revisions/{prev}/files — list package files
//!   GET /conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions/{rrev}/packages/{pkg_id}/revisions/{prev}/files/{filename} — download package file (immutable)
//!
//! ## Client config
//!   conan remote add nora http://nora:4000/conan
//!
//! ## Design
//! - All revision-scoped files are immutably cached (revisions never change)
//! - Metadata endpoints (latest, revisions, search) use TTL-based caching
//! - Uses a single wildcard route + dispatcher pattern (deep URL hierarchy)

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::config::UpstreamAuth;
use crate::registry::{
    circuit_open_response, proxy_fetch, proxy_fetch_conditional, proxy_fetch_text, read_validators,
    write_validators, ProxyError, Revalidation, Validators,
};
use crate::registry_type::RegistryType;
use crate::secrets::expose_opt;
use crate::AppState;
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use std::collections::HashMap;
use std::time::Duration;

pub fn routes() -> Router<AppState> {
    Router::new()
        // Ping — must come before the wildcard.
        // v1/ping is required: Conan 2.x client calls GET /v1/ping first
        // (ClientV2Router.ping()) before any v2 API calls (#901).
        .route("/conan/v1/ping", get(ping))
        .route("/conan/v2/ping", get(ping))
        // Search
        .route("/conan/v2/conans/search", get(search))
        // Recipe file download (deepest, most specific — must be before shorter patterns)
        .route(
            "/conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions/{rrev}/packages/{pkg_id}/revisions/{prev}/files/{filename}",
            get(package_file_download),
        )
        // Package file listing
        .route(
            "/conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions/{rrev}/packages/{pkg_id}/revisions/{prev}/files",
            get(package_file_list),
        )
        // Package revision list
        .route(
            "/conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions/{rrev}/packages/{pkg_id}/revisions",
            get(package_revisions),
        )
        // Package latest revision
        .route(
            "/conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions/{rrev}/packages/{pkg_id}/latest",
            get(package_latest),
        )
        // Recipe file download
        .route(
            "/conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions/{rrev}/files/{filename}",
            get(recipe_file_download),
        )
        // Recipe file listing
        .route(
            "/conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions/{rrev}/files",
            get(recipe_file_list),
        )
        // Recipe revision list
        .route(
            "/conan/v2/conans/{name}/{ver}/{user}/{chan}/revisions",
            get(recipe_revisions),
        )
        // Recipe latest revision
        .route(
            "/conan/v2/conans/{name}/{ver}/{user}/{chan}/latest",
            get(recipe_latest),
        )
}

// ── Ping ──────────────────────────────────────────────────────────────

async fn ping() -> Response {
    (
        StatusCode::OK,
        [
            ("X-Conan-Server-Capabilities", "revisions"),
            ("Content-Type", "text/plain"),
        ],
        "",
    )
        .into_response()
}

// ── Search ────────────────────────────────────────────────────────────

async fn search(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let query = params.get("q").cloned().unwrap_or_default();
    if query.len() > 256 {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // #68 namespace isolation: never forward a search term matching an internal
    // namespace upstream (dependency confusion) — return an empty result set.
    if crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Conan,
        &query,
    ) {
        return with_json(br#"{"results":[]}"#.to_vec());
    }

    // No upstream when the operator switched it off: nothing beyond what is stored is searched.
    let Some(proxy_url) = upstream_url(&state) else {
        return with_json(br#"{"results":[]}"#.to_vec());
    };
    // Percent-encode query for upstream
    let encoded_query: String = query
        .bytes()
        .flat_map(|b| {
            if b.is_ascii_alphanumeric()
                || b == b'-'
                || b == b'_'
                || b == b'.'
                || b == b'*'
                || b == b'/'
            {
                vec![b as char]
            } else if b == b' ' {
                vec!['+']
            } else {
                format!("%{:02X}", b).chars().collect()
            }
        })
        .collect();
    let url = format!(
        "{}/v2/conans/search?q={}",
        proxy_url.trim_end_matches('/'),
        encoded_query
    );

    match proxy_fetch_text(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.conan.proxy_timeout),
        expose_opt(&state.config.conan.proxy_auth).map(UpstreamAuth::Basic),
        None,
        &state.circuit_breaker,
        RegistryType::Conan,
    )
    .await
    {
        Ok(text) => {
            state.metrics.record_download("conan");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                format!("search:{}", query),
                crate::registry_type::RegistryType::Conan,
                "PROXY",
            ));
            with_json(text.into_bytes())
        }
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::debug!(error = ?e, "Conan search error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Recipe latest revision (TTL cached) ───────────────────────────────

async fn recipe_latest(
    State(state): State<AppState>,
    Path((name, ver, user, chan)): Path<(String, String, String, String)>,
) -> Response {
    if !is_valid_ref(&name) || !is_valid_ref(&ver) || !is_valid_ref(&user) || !is_valid_ref(&chan) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let ref_str = format!("{}/{}/{}/{}", name, ver, user, chan);
    serve_mutable_json(&state, &name, &ref_str, "latest").await
}

// ── Recipe revisions (TTL cached) ─────────────────────────────────────

async fn recipe_revisions(
    State(state): State<AppState>,
    Path((name, ver, user, chan)): Path<(String, String, String, String)>,
) -> Response {
    if !is_valid_ref(&name) || !is_valid_ref(&ver) || !is_valid_ref(&user) || !is_valid_ref(&chan) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let ref_str = format!("{}/{}/{}/{}", name, ver, user, chan);
    serve_mutable_json(&state, &name, &ref_str, "revisions").await
}

/// A mutable, TTL-cached JSON document of reference `ref_str` (`rel` under
/// `/v2/conans/{ref}/`: a recipe or package `latest` or `revisions` listing). Every one of them
/// is answered here: a fresh copy (written, or confirmed by a 304, within `metadata_ttl`), else
/// for an internal-namespace recipe its local copy or the isolation refusal, never the upstream
/// (#68 dependency confusion), else the upstream, with the stale copy kept for its failure.
async fn serve_mutable_json(state: &AppState, name: &str, ref_str: &str, rel: &str) -> Response {
    let storage_key = format!("conan/{}/{}.json", ref_str, rel);

    // Eager cache read — preserve data for serve-stale fallback
    let (cached_data, read_failure) =
        crate::registry::cached_read(state.storage.get(&storage_key).await);
    if let Some(ref data) = cached_data {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            let ttl = state.config.conan.metadata_ttl;
            if crate::registry::fresh_within_ttl(&state.storage, &storage_key, meta.modified, ttl)
                .await
            {
                state.metrics.record_download("conan");
                state.metrics.record_cache_hit("conan");
                return with_json(data.to_vec());
            }
        }
    }

    if crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Conan,
        name,
    ) {
        return internal_answer(
            state,
            name,
            cached_data.as_deref(),
            read_failure.as_ref(),
            &storage_key,
        );
    }

    // The fetch helpers answer from storage alone when the upstream is switched off.
    let proxy_url = upstream_url(state).unwrap_or_default();
    let url = format!(
        "{}/v2/conans/{}/{}",
        proxy_url.trim_end_matches('/'),
        ref_str,
        rel
    );

    fetch_and_cache_json(state, &url, &storage_key, ref_str, cached_data).await
}

// ── Recipe file listing (immutable — scoped to revision) ──────────────

async fn recipe_file_list(
    State(state): State<AppState>,
    Path((name, ver, user, chan, rrev)): Path<(String, String, String, String, String)>,
) -> Response {
    if !is_valid_ref(&name)
        || !is_valid_ref(&ver)
        || !is_valid_ref(&user)
        || !is_valid_ref(&chan)
        || !is_valid_revision(&rrev)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let ref_str = format!("{}/{}/{}/{}", name, ver, user, chan);
    let storage_key = format!("conan/{}/revisions/{}/files.json", ref_str, rrev);

    // Immutable: if cached, serve directly
    let (cached, read_failure) =
        crate::registry::cached_read(state.storage.get(&storage_key).await);
    if let Some(data) = cached {
        state.metrics.record_download("conan");
        state.metrics.record_cache_hit("conan");
        return with_json(data.to_vec());
    }

    // #68 namespace isolation: a cached internal recipe's file list was served above;
    // an internal name with no local copy must not be fetched upstream, and one whose copy the
    // store could not read is unavailable, not absent.
    if let Some(e) = read_failure.as_ref().filter(|_| {
        crate::curation::is_internal_namespace(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Conan,
            &name,
        )
    }) {
        return crate::registry::local_copy_unreadable("conan", &storage_key, e);
    }
    if let Some(response) = crate::curation::check_namespace_isolation(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Conan,
        &name,
    ) {
        return response;
    }

    // The fetch helpers answer from storage alone when the upstream is switched off.
    let proxy_url = upstream_url(&state).unwrap_or_default();
    let url = format!(
        "{}/v2/conans/{}/revisions/{}/files",
        proxy_url.trim_end_matches('/'),
        ref_str,
        rrev
    );

    fetch_and_cache_immutable_json(&state, &url, &storage_key, &ref_str).await
}

// ── Recipe file download (immutable) ──────────────────────────────────

async fn recipe_file_download(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((name, ver, user, chan, rrev, filename)): Path<(
        String,
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Response {
    if !is_valid_ref(&name)
        || !is_valid_ref(&ver)
        || !is_valid_ref(&user)
        || !is_valid_ref(&chan)
        || !is_valid_revision(&rrev)
        || !is_valid_filename(&filename)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let artifact = format!("{name}/{ver}/{user}/{chan} rrev={rrev} {filename}");
    let file = FileRef {
        name: &name,
        ver: &ver,
        user: &user,
        chan: &chan,
        what: "recipe",
        rel: format!("revisions/{rrev}/files/{filename}"),
        artifact,
        proxy_timeout: state.config.conan.proxy_timeout,
    };
    file_download(&state, &headers, file).await
}

// ── Package latest revision (TTL cached) ──────────────────────────────

async fn package_latest(
    State(state): State<AppState>,
    Path((name, ver, user, chan, rrev, pkg_id)): Path<(
        String,
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Response {
    if !is_valid_ref(&name)
        || !is_valid_ref(&ver)
        || !is_valid_ref(&user)
        || !is_valid_ref(&chan)
        || !is_valid_revision(&rrev)
        || !is_valid_revision(&pkg_id)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let ref_str = format!("{}/{}/{}/{}", name, ver, user, chan);
    serve_mutable_json(
        &state,
        &name,
        &ref_str,
        &format!("revisions/{rrev}/packages/{pkg_id}/latest"),
    )
    .await
}

// ── Package revisions (TTL cached) ────────────────────────────────────

async fn package_revisions(
    State(state): State<AppState>,
    Path((name, ver, user, chan, rrev, pkg_id)): Path<(
        String,
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Response {
    if !is_valid_ref(&name)
        || !is_valid_ref(&ver)
        || !is_valid_ref(&user)
        || !is_valid_ref(&chan)
        || !is_valid_revision(&rrev)
        || !is_valid_revision(&pkg_id)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let ref_str = format!("{}/{}/{}/{}", name, ver, user, chan);
    serve_mutable_json(
        &state,
        &name,
        &ref_str,
        &format!("revisions/{rrev}/packages/{pkg_id}/revisions"),
    )
    .await
}

// ── Package file listing (immutable — scoped to PREV) ─────────────────

async fn package_file_list(
    State(state): State<AppState>,
    Path((name, ver, user, chan, rrev, pkg_id, prev)): Path<(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Response {
    if !is_valid_ref(&name)
        || !is_valid_ref(&ver)
        || !is_valid_ref(&user)
        || !is_valid_ref(&chan)
        || !is_valid_revision(&rrev)
        || !is_valid_revision(&pkg_id)
        || !is_valid_revision(&prev)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let ref_str = format!("{}/{}/{}/{}", name, ver, user, chan);
    let storage_key = format!(
        "conan/{}/revisions/{}/packages/{}/revisions/{}/files.json",
        ref_str, rrev, pkg_id, prev
    );

    // Immutable
    let (cached, read_failure) =
        crate::registry::cached_read(state.storage.get(&storage_key).await);
    if let Some(data) = cached {
        state.metrics.record_download("conan");
        state.metrics.record_cache_hit("conan");
        return with_json(data.to_vec());
    }

    // #68 namespace isolation: a cached internal package's file list was served above;
    // an internal name with no local copy must not be fetched upstream, and one whose copy the
    // store could not read is unavailable, not absent.
    if let Some(e) = read_failure.as_ref().filter(|_| {
        crate::curation::is_internal_namespace(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Conan,
            &name,
        )
    }) {
        return crate::registry::local_copy_unreadable("conan", &storage_key, e);
    }
    if let Some(response) = crate::curation::check_namespace_isolation(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Conan,
        &name,
    ) {
        return response;
    }

    // The fetch helpers answer from storage alone when the upstream is switched off.
    let proxy_url = upstream_url(&state).unwrap_or_default();
    let url = format!(
        "{}/v2/conans/{}/revisions/{}/packages/{}/revisions/{}/files",
        proxy_url.trim_end_matches('/'),
        ref_str,
        rrev,
        pkg_id,
        prev
    );

    fetch_and_cache_immutable_json(&state, &url, &storage_key, &ref_str).await
}

// ── Package file download (immutable) ─────────────────────────────────

async fn package_file_download(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((name, ver, user, chan, rrev, pkg_id, prev, filename)): Path<(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Response {
    if !is_valid_ref(&name)
        || !is_valid_ref(&ver)
        || !is_valid_ref(&user)
        || !is_valid_ref(&chan)
        || !is_valid_revision(&rrev)
        || !is_valid_revision(&pkg_id)
        || !is_valid_revision(&prev)
        || !is_valid_filename(&filename)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let artifact = format!("{name}/{ver}/{user}/{chan}#{rrev}:{pkg_id}#{prev} {filename}");
    let file = FileRef {
        name: &name,
        ver: &ver,
        user: &user,
        chan: &chan,
        what: "package",
        rel: format!("revisions/{rrev}/packages/{pkg_id}/revisions/{prev}/files/{filename}"),
        artifact,
        proxy_timeout: state.config.conan.proxy_timeout_dl,
    };
    file_download(&state, &headers, file).await
}

/// A recipe or a package file: the two downloads differ only in the path.
struct FileRef<'a> {
    name: &'a str,
    ver: &'a str,
    user: &'a str,
    chan: &'a str,
    /// "recipe" or "package", for the log.
    what: &'static str,
    /// The path under the reference, the same in storage and upstream.
    rel: String,
    /// The activity-log name.
    artifact: String,
    proxy_timeout: u64,
}

/// Curation, the immutable cache with its integrity and quarantine gates, Range,
/// then the upstream fetch (R4-T11: was two copies).
async fn file_download(state: &AppState, headers: &HeaderMap, file: FileRef<'_>) -> Response {
    let FileRef {
        name,
        ver,
        user,
        chan,
        what,
        rel,
        artifact,
        proxy_timeout,
    } = file;
    let ref_str = format!("{}/{}/{}/{}", name, ver, user, chan);

    // Extract publish date from cached revision metadata
    let publish_date = extract_conan_publish_date(
        &state.storage,
        name,
        ver,
        user,
        chan,
        state.config.server.trust_upstream_dates,
    )
    .await;

    // Curation check. #733 serve-local: an internal-namespace recipe or package is operator-owned — skip
    // curation and serve any local copy below; block the upstream branch separately.
    let internal = crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Conan,
        name,
    );
    if !internal {
        if let Some(response) = crate::curation::check_download(
            &state.curation().curation_engine,
            state.bypass_token().as_deref(),
            headers,
            crate::curation::RegistryType::Conan,
            name,
            crate::curation::RequestVersion::Known(ver.to_string()),
            publish_date,
        ) {
            return response;
        }
    }

    let storage_key = format!("conan/{ref_str}/{rel}");

    // Immutable cache. get_verified discharges the integrity witness at serve
    // (compile-time guarantee — see crate::verified).
    let (cached, read_failure) =
        crate::registry::cached_read(state.storage.get_verified(&storage_key).await);
    if let Some(outcome) = cached {
        use nora_registry::verified::{verified_body, GateOutcome};
        let data = match outcome {
            GateOutcome::Verified(blob) => verified_body(blob),
            GateOutcome::Unpinned(blob) => blob.into_inner(),
        };
        // Curation integrity
        if let Some(response) = crate::curation::verify_integrity(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Conan,
            name,
            Some(ver),
            &data,
        ) {
            return response;
        }

        let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
            state.config.curation.conan.quarantine.as_ref().or(state
                .config
                .curation
                .quarantine
                .as_ref()),
            state
                .config
                .curation
                .conan
                .quarantine_ttl
                .as_deref()
                .or(state.config.curation.quarantine_ttl.as_deref()),
        );
        // A digest with no record counts from when its copy was cached (R4-C05).
        if let Some(resp) = crate::digest_quarantine::cache_gate_dated(
            &state.digest_store,
            &state.storage,
            &storage_key,
            "conan",
            &data,
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

        // Range request: 206 Partial Content, or 416 when the client asks past the
        // end. The gates above ran on the whole object; the partial body itself
        // cannot be rehashed, so the client's own checksum covers it (#657).
        if let Some(response) = crate::registry::range::range_response_from_bytes(
            &data,
            headers,
            "application/octet-stream",
            &[],
        ) {
            if response.status() == StatusCode::PARTIAL_CONTENT {
                state.metrics.record_download("conan");
                state.metrics.record_cache_hit("conan");
            }
            return response;
        }

        state.metrics.record_download("conan");
        state.metrics.record_cache_hit("conan");
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            artifact,
            crate::registry_type::RegistryType::Conan,
            "CACHE",
        ));
        return with_binary(data.to_vec());
    }

    // #733: an internal-namespace recipe or package with no local copy is never proxied upstream.
    if internal {
        if let Some(e) = &read_failure {
            return crate::registry::local_copy_unreadable("conan", &storage_key, e);
        }
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Conan,
            name,
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
    }

    // Fetch from upstream — none when the operator switched it off.
    let Some(proxy_url) = upstream_url(state) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let url = format!(
        "{}/v2/conans/{ref_str}/{rel}",
        proxy_url.trim_end_matches('/')
    );

    match proxy_fetch(
        &state.http_client,
        &url,
        Duration::from_secs(proxy_timeout),
        expose_opt(&state.config.conan.proxy_auth).map(UpstreamAuth::Basic),
        &state.circuit_breaker,
        RegistryType::Conan,
    )
    .await
    {
        Ok(bytes) => {
            // The allowlist's pinned integrity holds on the first download too, before anything is cached:
            // the cache-hit branch checks the same rule.
            if let Some(response) = crate::curation::verify_integrity(
                &state.curation().curation_engine,
                crate::curation::RegistryType::Conan,
                name,
                Some(ver),
                &bytes,
            ) {
                return response;
            }
            state.metrics.record_download("conan");
            state.metrics.record_cache_miss("conan");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                artifact,
                crate::registry_type::RegistryType::Conan,
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "proxy", "", "conan", ""));

            // Immutable cache: put_if_absent
            state.spawn_cache_immutable("conan", storage_key, Bytes::from(bytes.clone()));
            let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
                state.config.curation.conan.quarantine.as_ref().or(state
                    .config
                    .curation
                    .quarantine
                    .as_ref()),
                state
                    .config
                    .curation
                    .conan
                    .quarantine_ttl
                    .as_deref()
                    .or(state.config.curation.quarantine_ttl.as_deref()),
            );
            if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
                &state.digest_store,
                "conan",
                &bytes,
                &q_mode,
                q_secs,
                &url,
                crate::digest_quarantine::first_seen_seed(
                    state.config.server.trust_upstream_dates,
                    publish_date,
                ),
            )
            .await
            {
                return resp;
            }
            with_binary(bytes)
        }
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::debug!(error = ?e, "Conan {what} file download error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Shared fetch helpers ──────────────────────────────────────────────

/// Fetch JSON from upstream, cache with TTL (mutable content).
async fn fetch_and_cache_json(
    state: &AppState,
    url: &str,
    storage_key: &str,
    artifact: &str,
    cached: Option<Bytes>,
) -> Response {
    // No upstream when the operator switched it off: what is stored is all there is.
    if upstream_url(state).is_none() {
        return match cached {
            Some(data) => with_json(data.to_vec()),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    // Revalidate stale metadata with a conditional request when enabled and fall
    // back to a full fetch otherwise. Empty validators ⇒ no conditional headers ⇒
    // always a 200, which is also how the first fetch captures validators.
    let validators = if state.config.conan.revalidate {
        read_validators(&state.storage, storage_key)
            .await
            .unwrap_or_default()
    } else {
        Validators::default()
    };
    let had_validators = validators.is_some();

    match proxy_fetch_conditional(
        &state.http_client,
        url,
        Duration::from_secs(state.config.conan.proxy_timeout),
        expose_opt(&state.config.conan.proxy_auth).map(UpstreamAuth::Basic),
        &validators,
        &state.circuit_breaker,
        RegistryType::Conan,
    )
    .await
    {
        // Upstream unchanged — serve the cached body and bump its freshness so we
        // do not revalidate again until the next TTL window. No body downloaded.
        Ok(Revalidation::NotModified) => {
            let body = match state.storage.get(storage_key).await {
                Ok(b) => b,
                // Body vanished under us — use the eagerly-read copy, or 502.
                Err(_) => match cached {
                    Some(b) => b,
                    None => return StatusCode::BAD_GATEWAY.into_response(),
                },
            };
            crate::metrics::PROXY_UPSTREAM_304_TOTAL
                .with_label_values(&["conan"])
                .inc();
            crate::metrics::PROXY_REVALIDATION_BYTES_SAVED_TOTAL
                .with_label_values(&["conan"])
                .inc_by(body.len() as u64);
            state.metrics.record_download("conan");
            state.metrics.record_cache_hit("conan");
            // Record the revalidation in the `.meta` sidecar; no body re-upload (C56).
            let storage = state.storage.clone();
            let key_clone = storage_key.to_string();
            tokio::spawn(async move {
                crate::registry::mark_revalidated(&storage, "conan", &key_clone).await;
            });
            with_json(body.to_vec())
        }
        // New body — cache the raw bytes first, then persist the fresh validators.
        Ok(Revalidation::Modified { body, validators }) => {
            state.metrics.record_download("conan");
            state.metrics.record_cache_miss("conan");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                artifact.to_string(),
                crate::registry_type::RegistryType::Conan,
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "proxy", "", "conan", ""));

            let raw = Bytes::from(body);
            let storage = state.storage.clone();
            let key_clone = storage_key.to_string();
            let raw_for_cache = raw.clone();
            tokio::spawn(async move {
                if let Err(e) = storage.put(&key_clone, &raw_for_cache).await {
                    tracing::warn!(key = %key_clone, error = ?e, "conan proxy: failed to cache metadata");
                    return;
                }
                write_validators(&storage, &key_clone, &validators).await;
            });
            with_json(raw.to_vec())
        }
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            if had_validators {
                crate::metrics::PROXY_REVALIDATION_ERRORS_TOTAL
                    .with_label_values(&["conan"])
                    .inc();
            }
            if let Some(ref data) = cached {
                if state.config.conan.serve_stale {
                    tracing::warn!(
                        registry = "conan",
                        artifact,
                        error = ?e,
                        "Conan upstream error, serving stale metadata"
                    );
                    return (
                        StatusCode::OK,
                        [
                            (
                                header::CONTENT_TYPE,
                                HeaderValue::from_static("application/json"),
                            ),
                            (
                                header::CACHE_CONTROL,
                                HeaderValue::from_static("public, max-age=0, must-revalidate"),
                            ),
                            (
                                axum::http::header::HeaderName::from_static("x-nora-stale"),
                                HeaderValue::from_static("true"),
                            ),
                        ],
                        data.to_vec(),
                    )
                        .into_response();
                }
            }
            tracing::debug!(url, error = ?e, "Conan upstream error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// Fetch JSON from upstream, cache immutably (content scoped to revision, never changes).
async fn fetch_and_cache_immutable_json(
    state: &AppState,
    url: &str,
    storage_key: &str,
    artifact: &str,
) -> Response {
    // No upstream when the operator switched it off.
    if upstream_url(state).is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    match proxy_fetch_text(
        &state.http_client,
        url,
        Duration::from_secs(state.config.conan.proxy_timeout),
        expose_opt(&state.config.conan.proxy_auth).map(UpstreamAuth::Basic),
        None,
        &state.circuit_breaker,
        RegistryType::Conan,
    )
    .await
    {
        Ok(text) => {
            state.metrics.record_download("conan");
            state.metrics.record_cache_miss("conan");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                artifact.to_string(),
                crate::registry_type::RegistryType::Conan,
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "proxy", "", "conan", ""));

            state.spawn_cache_immutable(
                "conan",
                storage_key.to_string(),
                Bytes::from(text.clone()),
            );
            with_json(text.into_bytes())
        }
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::debug!(url, error = ?e, "Conan upstream error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Extract publish date from cached Conan recipe revision metadata.
///
/// Conan v2 `latest.json` contains:
/// ```json
/// { "revision": "abc123", "time": "2024-01-15T10:30:00.000+0000" }
/// ```
async fn extract_conan_publish_date(
    storage: &crate::storage::Storage,
    name: &str,
    ver: &str,
    user: &str,
    chan: &str,
    trust_upstream: bool,
) -> Option<i64> {
    let ref_str = format!("{}/{}/{}/{}", name, ver, user, chan);
    let meta_key = format!("conan/{}/latest.json", ref_str);
    // #513: untrusted upstream dates → no date: never upstream time, nor the cache mtime.
    if !trust_upstream {
        return None;
    }
    let data = storage.get(&meta_key).await.ok()?;
    let json: serde_json::Value = serde_json::from_slice(&data).ok()?;
    let date_str = json.get("time")?.as_str()?;
    crate::curation::parse_iso8601_to_unix(date_str)
}

/// What an internal-namespace reference gets once no fresh copy answered it (#68):
/// never the upstream. The stored JSON, else the isolation refusal (404 without one); a
/// copy the store could not read is unavailable, not absent.
fn internal_answer(
    state: &AppState,
    name: &str,
    cached: Option<&[u8]>,
    read_failure: Option<&crate::storage::StorageError>,
    key: &str,
) -> Response {
    if let Some(data) = cached {
        state.metrics.record_download("conan");
        state.metrics.record_cache_hit("conan");
        return with_json(data.to_vec());
    }
    if let Some(e) = read_failure {
        return crate::registry::local_copy_unreadable("conan", key, e);
    }
    crate::curation::check_namespace_isolation(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Conan,
        name,
    )
    .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response())
}

/// The configured upstream, or None when the operator switched it off with an empty
/// NORA_CONAN_PROXY: then nothing is asked of any upstream.
fn upstream_url(state: &AppState) -> Option<String> {
    crate::config::configured_upstream(&state.config.conan.proxy).map(str::to_string)
}

fn with_json(data: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=60, must-revalidate"),
            ),
        ],
        data,
    )
        .into_response()
}

fn with_binary(data: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=31536000, immutable"),
            ),
            (header::ACCEPT_RANGES, HeaderValue::from_static("bytes")),
        ],
        data,
    )
        .into_response()
}

/// Validate a Conan reference component (name, version, user, channel).
/// Allows alphanumeric, hyphens, underscores, dots, and `_` (for `_/_` pattern).
fn is_valid_ref(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && !s.contains('/')
        && !s.contains('\0')
        && !s.contains("..")
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '+')
}

/// Validate a revision hash (SHA-256 hex or short hash).
fn is_valid_revision(rev: &str) -> bool {
    !rev.is_empty()
        && rev.len() <= 128
        && rev
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c.is_ascii_alphanumeric())
}

/// Validate a filename in the Conan file listing.
fn is_valid_filename(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && !name.contains('/')
        && !name.contains('\0')
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '+')
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache_ttl::is_within_ttl;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_valid_refs() {
        assert!(is_valid_ref("zlib"));
        assert!(is_valid_ref("1.2.13"));
        assert!(is_valid_ref("_")); // user/channel can be _
        assert!(is_valid_ref("my-org"));
        assert!(is_valid_ref("boost"));
        assert!(is_valid_ref("1.0.0+build1"));
    }

    #[test]
    fn test_invalid_refs() {
        assert!(!is_valid_ref(""));
        assert!(!is_valid_ref("../evil"));
        assert!(!is_valid_ref("foo/bar"));
        assert!(!is_valid_ref("foo\0bar"));
        assert!(!is_valid_ref("foo bar"));
    }

    #[test]
    fn test_valid_revisions() {
        assert!(is_valid_revision("abc123"));
        assert!(is_valid_revision(
            "e4f7c8d90ab1234567890abcdef1234567890abc"
        ));
        assert!(is_valid_revision("0"));
    }

    #[test]
    fn test_invalid_revisions() {
        assert!(!is_valid_revision(""));
        assert!(!is_valid_revision("abc/def"));
        assert!(!is_valid_revision("abc def"));
    }

    #[test]
    fn test_valid_filenames() {
        assert!(is_valid_filename("conanfile.py"));
        assert!(is_valid_filename("conanmanifest.txt"));
        assert!(is_valid_filename("conan_package.tgz"));
        assert!(is_valid_filename("conan_sources.tgz"));
        assert!(is_valid_filename("conaninfo.txt"));
        assert!(is_valid_filename("conan_export.tgz"));
    }

    #[test]
    fn test_invalid_filenames() {
        assert!(!is_valid_filename(""));
        assert!(!is_valid_filename("../evil.txt"));
        assert!(!is_valid_filename("path/to/file"));
        assert!(!is_valid_filename("file\0name"));
    }

    #[test]
    fn test_ttl_fresh() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(is_within_ttl(now - 10, 3600));
    }

    #[test]
    fn test_ttl_expired() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(!is_within_ttl(now - 7200, 3600));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use crate::test_helpers::{
        body_bytes, create_test_context_with_config, send, send_with_headers,
    };
    use axum::http::{Method, StatusCode};

    #[tokio::test]
    async fn test_conan_disabled_returns_404() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.conan.enabled = false;
        });
        let resp = send(&ctx.app, Method::GET, "/conan/v2/ping", "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_conan_ping() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.conan.enabled = true;
        });
        let resp = send(&ctx.app, Method::GET, "/conan/v2/ping", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("X-Conan-Server-Capabilities")
                .unwrap()
                .to_str()
                .unwrap(),
            "revisions"
        );
    }

    #[tokio::test]
    async fn test_conan_cached_recipe_file() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.conan.enabled = true;
        });

        // Pre-populate cache with immutable recipe file
        ctx.state
            .storage
            .put(
                "conan/zlib/1.2.13/_/_/revisions/abc123/files/conanfile.py",
                b"class ZlibConan(ConanFile):\n    pass",
            )
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/conan/v2/conans/zlib/1.2.13/_/_/revisions/abc123/files/conanfile.py",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert!(body.starts_with(b"class Zlib"));
    }

    #[tokio::test]
    async fn test_conan_cached_package_file() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.conan.enabled = true;
        });

        ctx.state
            .storage
            .put(
                "conan/zlib/1.2.13/_/_/revisions/abc123/packages/deadbeef/revisions/cafe42/files/conan_package.tgz",
                b"fake-tgz-data",
            )
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/conan/v2/conans/zlib/1.2.13/_/_/revisions/abc123/packages/deadbeef/revisions/cafe42/files/conan_package.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(&body[..], b"fake-tgz-data");
    }

    /// Resume support on a cached package binary: 206 for a byte range, 416 past
    /// the end, `Accept-Ranges` on the full 200.
    #[tokio::test]
    async fn test_conan_package_file_range_request() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.conan.enabled = true;
        });
        let url = "/conan/v2/conans/zlib/1.2.13/_/_/revisions/abc123/packages/deadbeef/revisions/cafe42/files/conan_package.tgz";
        ctx.state
            .storage
            .put(
                "conan/zlib/1.2.13/_/_/revisions/abc123/packages/deadbeef/revisions/cafe42/files/conan_package.tgz",
                b"0123456789",
            )
            .await
            .unwrap();

        let resp =
            send_with_headers(&ctx.app, Method::GET, url, vec![("range", "bytes=2-5")], "").await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers()
                .get("content-range")
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes 2-5/10"
        );
        assert_eq!(
            resp.headers()
                .get("accept-ranges")
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes"
        );
        assert_eq!(&body_bytes(resp).await[..], b"2345");

        let resp =
            send_with_headers(&ctx.app, Method::GET, url, vec![("range", "bytes=10-")], "").await;
        assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            resp.headers()
                .get("content-range")
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes */10"
        );

        let resp = send(&ctx.app, Method::GET, url, "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("accept-ranges")
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes"
        );
    }

    #[tokio::test]
    async fn test_conan_unreachable_proxy() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.conan.enabled = true;
            cfg.conan.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.conan.proxy_timeout = 1;
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/conan/v2/conans/zlib/1.2.13/_/_/latest",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn test_conan_invalid_ref_rejected() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.conan.enabled = true;
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/conan/v2/conans/../evil/_/_/latest",
            "",
        )
        .await;
        assert!(resp.status() == StatusCode::NOT_FOUND || resp.status() == StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_conan_curation_enforce_blocks() {
        use crate::test_helpers::send_with_headers;

        let blocklist_dir = tempfile::TempDir::new().unwrap();
        let blocklist_path = blocklist_dir.path().join("blocklist.json");
        let blocklist = serde_json::json!({
            "version": 1,
            "rules": [{"registry": "conan", "name": "evil-lib", "version": "*", "reason": "supply chain attack"}]
        });
        std::fs::write(&blocklist_path, serde_json::to_string(&blocklist).unwrap()).unwrap();

        let bl_path = blocklist_path.to_str().unwrap().to_string();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.conan.enabled = true;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(bl_path);
        });

        ctx.state
            .storage
            .put(
                "conan/evil-lib/1.0/_/_/revisions/abc123/files/conanfile.py",
                b"evil recipe",
            )
            .await
            .unwrap();

        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/conan/v2/conans/evil-lib/1.0/_/_/revisions/abc123/files/conanfile.py",
            vec![],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            resp.headers()
                .get("x-nora-decision")
                .and_then(|v| v.to_str().ok()),
            Some("blocked")
        );
    }

    #[tokio::test]
    async fn test_conan_curation_audit_passes() {
        let blocklist_dir = tempfile::TempDir::new().unwrap();
        let blocklist_path = blocklist_dir.path().join("blocklist.json");
        let blocklist = serde_json::json!({
            "version": 1,
            "rules": [{"registry": "conan", "name": "evil-lib", "version": "*", "reason": "supply chain attack"}]
        });
        std::fs::write(&blocklist_path, serde_json::to_string(&blocklist).unwrap()).unwrap();

        let bl_path = blocklist_path.to_str().unwrap().to_string();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.conan.enabled = true;
            cfg.curation.mode = crate::config::CurationMode::Audit;
            cfg.curation.blocklist_path = Some(bl_path);
        });

        ctx.state
            .storage
            .put(
                "conan/evil-lib/1.0/_/_/revisions/abc123/files/conanfile.py",
                b"evil recipe",
            )
            .await
            .unwrap();

        // Audit mode: logs but passes through
        let resp = send(
            &ctx.app,
            Method::GET,
            "/conan/v2/conans/evil-lib/1.0/_/_/revisions/abc123/files/conanfile.py",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(&body[..], b"evil recipe");
    }

    #[tokio::test]
    async fn test_conan_curation_enforce_allows_safe() {
        let blocklist_dir = tempfile::TempDir::new().unwrap();
        let blocklist_path = blocklist_dir.path().join("blocklist.json");
        let blocklist = serde_json::json!({
            "version": 1,
            "rules": [{"registry": "conan", "name": "evil-lib", "version": "*", "reason": "supply chain attack"}]
        });
        std::fs::write(&blocklist_path, serde_json::to_string(&blocklist).unwrap()).unwrap();

        let bl_path = blocklist_path.to_str().unwrap().to_string();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.conan.enabled = true;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(bl_path);
        });

        ctx.state
            .storage
            .put(
                "conan/zlib/1.2.13/_/_/revisions/abc123/files/conanfile.py",
                b"safe recipe",
            )
            .await
            .unwrap();

        // zlib is NOT blocked — should pass
        let resp = send(
            &ctx.app,
            Method::GET,
            "/conan/v2/conans/zlib/1.2.13/_/_/revisions/abc123/files/conanfile.py",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(&body[..], b"safe recipe");
    }

    #[tokio::test]
    async fn test_extract_conan_publish_date_found() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::new_local(dir.path().join("data").to_str().unwrap());
        let meta = serde_json::json!({
            "revision": "abc123",
            "time": "2024-03-15T14:30:00.000+0000"
        });
        storage
            .put(
                "conan/zlib/1.3/_/_/latest.json",
                serde_json::to_vec(&meta).unwrap().as_slice(),
            )
            .await
            .unwrap();

        let result =
            super::extract_conan_publish_date(&storage, "zlib", "1.3", "_", "_", true).await;
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_conan_untrusted_dates_ignore_upstream_and_mtime() {
        // #513: with trust=false, a spoofed-OLD upstream `time` must be ignored so an
        // attacker cannot backdate a fresh package; the cache mtime is no publish date
        // either (C49), so there is no date and the quarantine's own clock decides.
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::new_local(dir.path().join("data").to_str().unwrap());
        let meta = serde_json::json!({ "revision": "r1", "time": "2000-01-01T00:00:00.000+0000" });
        storage
            .put(
                "conan/zlib/1.3/_/_/latest.json",
                serde_json::to_vec(&meta).unwrap().as_slice(),
            )
            .await
            .unwrap();

        let trusted =
            super::extract_conan_publish_date(&storage, "zlib", "1.3", "_", "_", true).await;
        let untrusted =
            super::extract_conan_publish_date(&storage, "zlib", "1.3", "_", "_", false).await;

        // trust=true honors the (spoofed, old) upstream date
        assert_eq!(trusted, Some(946_684_800)); // 2000-01-01T00:00:00Z
                                                // trust=false ignores it, and the cache mtime is no release date either (C49)
        assert_eq!(untrusted, None);
    }

    #[tokio::test]
    async fn test_conan_untrusted_dates_fail_closed_when_uncached() {
        // #513 fail-closed: trust=false with no cached metadata yields None, which
        // curation's min-release-age treats as Block — never a bypass.
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::new_local(dir.path().join("data").to_str().unwrap());
        let result =
            super::extract_conan_publish_date(&storage, "uncached", "1.0", "_", "_", false).await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_extract_conan_publish_date_no_time_field() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::new_local(dir.path().join("data").to_str().unwrap());
        let meta = serde_json::json!({"revision": "abc123"});
        storage
            .put(
                "conan/zlib/1.3/_/_/latest.json",
                serde_json::to_vec(&meta).unwrap().as_slice(),
            )
            .await
            .unwrap();

        let result =
            super::extract_conan_publish_date(&storage, "zlib", "1.3", "_", "_", true).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_extract_conan_publish_date_no_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::new_local(dir.path().join("data").to_str().unwrap());

        let result =
            super::extract_conan_publish_date(&storage, "nonexistent", "1.0", "_", "_", true).await;
        assert!(result.is_none());
    }

    /// #52 acceptance: a stale recipe-revision read revalidates with
    /// `If-None-Match`; on upstream 304 the cached body is served with no
    /// 200-body download. (ConanCenter sends no validators in production, but this
    /// proves NORA uses them when a fronting CDN / Artifactory does.)
    #[tokio::test]
    async fn test_conan_revalidation_304_serves_cache_no_body_download() {
        use crate::registry::{write_validators, Validators};
        use wiremock::matchers::{header_exists, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        // Conditional request (has If-None-Match) → 304. A request WITHOUT it
        // would 404 (no other mount), so any full fetch would visibly fail.
        Mock::given(method("GET"))
            .and(header_exists("if-none-match"))
            .respond_with(ResponseTemplate::new(304))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.conan.enabled = true;
            cfg.conan.proxy = Some(upstream.uri());
            cfg.conan.metadata_ttl = 0; // always stale → always revalidate
            cfg.conan.revalidate = true;
            cfg.conan.serve_stale = false;
        });

        let key = "conan/zlib/1.3/_/_/latest.json";
        ctx.state
            .storage
            .put(key, br#"{"revision":"abc123"}"#)
            .await
            .unwrap();
        write_validators(
            &ctx.state.storage,
            key,
            &Validators {
                etag: Some("\"v1\"".to_string()),
                last_modified: None,
            },
        )
        .await;

        let before = crate::metrics::PROXY_UPSTREAM_304_TOTAL
            .with_label_values(&["conan"])
            .get();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/conan/v2/conans/zlib/1.3/_/_/latest",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert!(
            String::from_utf8_lossy(&body).contains("abc123"),
            "must serve the cached recipe revision"
        );

        let after = crate::metrics::PROXY_UPSTREAM_304_TOTAL
            .with_label_values(&["conan"])
            .get();
        assert!(after > before, "a 304 revalidation must be recorded");
    }

    /// Regression test for #901: Conan 2.x client calls `GET /v1/ping` before
    /// any v2 API interaction (`ClientV2Router.ping()`). Missing route caused
    /// 404 → client refused to proceed.
    #[tokio::test]
    async fn test_conan_v1_ping() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.conan.enabled = true;
        });
        let resp = send(&ctx.app, Method::GET, "/conan/v1/ping", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("X-Conan-Server-Capabilities")
                .unwrap()
                .to_str()
                .unwrap(),
            "revisions"
        );
    }

    /// Verify v1/ping is also gated behind `conan.enabled`.
    #[tokio::test]
    async fn test_conan_v1_ping_disabled() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.conan.enabled = false;
        });
        let resp = send(&ctx.app, Method::GET, "/conan/v1/ping", "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}

/// Conan references and REST paths as the Conan 2 client writes them (testdata/conan,
/// regenerated by the script there).
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod per_conan_client {
    use crate::storage::{ObjectStorage, Storage};
    use crate::test_helpers::{create_test_context_with_storage_and_config, send, upstream_paths};
    use axum::http::{Method, StatusCode};
    use std::time::Duration;
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Reference, path of every GET the client sent while reading (not uploading).
    fn reads() -> Vec<(String, String)> {
        let path = format!(
            "{}/testdata/conan/client-requests.tsv",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .filter(|row| !row.starts_with('#'))
            .map(|row| row.split('\t').map(String::from).collect::<Vec<_>>())
            .filter(|row| row[0] != "upload" && row[2] == "GET")
            .map(|row| (row[1].clone(), row[3].clone()))
            .collect()
    }

    /// The REST shapes NORA serves under `/conan/v2/conans/{name}/{version}/{user}/{channel}`.
    fn is_reference_route(path: &str) -> bool {
        let Some(rest) = path.strip_prefix("/conan/v2/conans/") else {
            return false;
        };
        let segments: Vec<&str> = rest.split('/').collect();
        let tail = &segments[segments.len().min(4)..];
        matches!(
            tail,
            ["latest"]
                | ["revisions"]
                | ["revisions", _, "files"]
                | ["revisions", _, "files", _]
                | ["revisions", _, "packages", _, "latest"]
                | ["revisions", _, "packages", _, "revisions"]
                | ["revisions", _, "packages", _, "revisions", _, "files"]
                | ["revisions", _, "packages", _, "revisions", _, "files", _]
        )
    }

    fn is_file(path: &str) -> bool {
        path.rsplit('/').nth(1) == Some("files")
    }

    /// Name and version of a reference, split as `RecipeReference.loads` splits it.
    fn name_version(reference: &str) -> (&str, &str) {
        let name_version = reference.split('@').next().unwrap();
        name_version.split_once('/').unwrap()
    }

    // Every reference `validate_ref` accepts (lowercase, or uppercase under
    // `core:allow_uppercase_pkg_names`) is one whose path segments NORA reads: name, version, and
    // user and channel as the client writes them (`_` for none, `client_routes.py:7-10`).
    #[test]
    fn every_reference_conan_accepts_has_path_segments_nora_reads() {
        let path = format!(
            "{}/testdata/conan/references.tsv",
            env!("CARGO_MANIFEST_DIR")
        );
        let rows: Vec<Vec<String>> = std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .filter(|row| !row.starts_with('#'))
            .map(|row| row.split('\t').map(String::from).collect())
            .filter(|row: &Vec<String>| row[5] == "OK" || row[5] == "UPPERCASE")
            .collect();
        assert_eq!(rows.len(), 62);
        // `..` in a segment is left to the storage-key rules: one row (`zlib/1..0`).
        let rows: Vec<Vec<String>> = rows
            .into_iter()
            .filter(|row| !row[0].contains(".."))
            .collect();
        assert_eq!(rows.len(), 61);
        for row in rows {
            let or_placeholder = |s: &str| {
                if s.is_empty() {
                    "_".to_string()
                } else {
                    s.to_string()
                }
            };
            for segment in [
                row[1].clone(),
                row[2].clone(),
                or_placeholder(&row[3]),
                or_placeholder(&row[4]),
            ] {
                assert!(super::is_valid_ref(&segment), "{}: {segment:?}", row[0]);
            }
        }
    }

    async fn upstream() -> MockServer {
        let up = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "revision": "66290236faab0c6a82918fe0fe028c85",
                "time": "2026-10-12T00:00:00.000+0000",
                "files": {}
            })))
            .mount(&up)
            .await;
        up
    }

    // Where the shared file download parts the two on purpose: a package file is fetched
    // under `proxy_timeout_dl`, a recipe file under `proxy_timeout`. An upstream that answers
    // after 2 s fails the recipe file under a 1 s metadata timeout and serves the package
    // file under its own 30 s. (A zero timeout raced: a fast local answer could still win.)
    #[tokio::test]
    async fn package_files_are_fetched_under_the_download_timeout() {
        let up = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes("file")
                    .set_delay(Duration::from_secs(2)),
            )
            .mount(&up)
            .await;
        let proxy = up.uri();
        let storage = Storage::from_backend(std::sync::Arc::new(ObjectStorage::in_memory()));
        let ctx = create_test_context_with_storage_and_config(storage, |cfg| {
            cfg.conan.enabled = true;
            cfg.conan.proxy = Some(proxy);
            cfg.conan.proxy_timeout = 1;
            cfg.conan.proxy_timeout_dl = 30;
        });
        let reference = "/conan/v2/conans/zlib/1.3/_/_/revisions/abc123";
        let package =
            format!("{reference}/packages/deadbeef/revisions/cafe42/files/conan_package.tgz");
        let resp = send(&ctx.app, Method::GET, &package, "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let recipe = format!("{reference}/files/conanfile.py");
        let resp = send(&ctx.app, Method::GET, &recipe, "").await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    // Every request the client sends for a reference reaches upstream at the same path, user and
    // channel (`_` for none) included.
    #[tokio::test]
    async fn every_reference_request_conan_sends_is_asked_upstream_as_sent() {
        let rows: Vec<(String, String)> = reads()
            .into_iter()
            .filter(|(_, path)| is_reference_route(path))
            .collect();
        assert_eq!(rows.len(), 390);
        let up = upstream().await;
        let proxy = up.uri();
        let storage = Storage::from_backend(std::sync::Arc::new(ObjectStorage::in_memory()));
        let ctx = create_test_context_with_storage_and_config(storage, |cfg| {
            cfg.conan.enabled = true;
            cfg.conan.proxy = Some(proxy);
        });
        for (reference, path) in rows {
            let resp = send(&ctx.app, Method::GET, &path, "").await;
            assert_eq!(resp.status(), StatusCode::OK, "{reference}: {path}");
            let asked = path.strip_prefix("/conan").unwrap().to_string();
            assert!(
                upstream_paths(&up).await.contains(&asked),
                "{reference}: {path}"
            );
        }
    }

    // Every file the client downloads, recipe or package, is curated as the name and version of
    // the reference it asked for: a rule naming them refuses it before upstream is asked.
    #[tokio::test]
    async fn every_file_conan_downloads_is_curated_as_its_reference() {
        let rows: Vec<(String, String)> = reads()
            .into_iter()
            .filter(|(_, path)| is_reference_route(path) && is_file(path))
            .collect();
        assert_eq!(rows.len(), 195);
        let rules: Vec<serde_json::Value> = rows
            .iter()
            .map(|(reference, _)| {
                let (name, version) = name_version(reference);
                serde_json::json!({"registry": "conan", "name": name, "version": version, "reason": "test"})
            })
            .collect();
        let dir = tempfile::TempDir::new().unwrap();
        let blocklist = dir.path().join("blocklist.json");
        std::fs::write(
            &blocklist,
            serde_json::json!({"version": 1, "rules": rules}).to_string(),
        )
        .unwrap();
        let up = upstream().await;
        let proxy = up.uri();
        let storage = Storage::from_backend(std::sync::Arc::new(ObjectStorage::in_memory()));
        let ctx = create_test_context_with_storage_and_config(storage, |cfg| {
            cfg.conan.enabled = true;
            cfg.conan.proxy = Some(proxy);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist.to_string_lossy().into_owned());
        });
        for (reference, path) in rows {
            let resp = send(&ctx.app, Method::GET, &path, "").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{reference}: {path}");
        }
        let sent = upstream_paths(&up).await;
        assert!(sent.iter().all(|path| !is_file(path)), "{sent:?}");
    }
}

/// Without trusted upstream dates the quarantine counts from NORA's own first fetch of an
/// artifact's bytes: metadata cached a month ago says when NORA last wrote it, not when it first
/// fetched this file, and its age would let a file first fetched now pass as mature. With trusted
/// dates the release date seeds it (#750), so an old release is not held as new to this mirror.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod quarantine_first_seen {
    use crate::test_helpers::{
        create_test_context_with_config, put_written_days_ago, quarantine_7d, send, TestContext,
    };
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn serve(up: &MockServer, at: &str, body: Vec<u8>) {
        Mock::given(method("GET"))
            .and(path(at))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(up)
            .await;
    }

    async fn status(ctx: &TestContext, uri: &str) -> StatusCode {
        send(&ctx.app, Method::GET, uri, "").await.status()
    }

    const REV: &str = "0123456789abcdef0123456789abcdef";
    const LATEST: &[u8] =
        br#"{"revision":"0123456789abcdef0123456789abcdef","time":"2019-01-01T00:00:00.000+0000"}"#;

    fn recipe_file() -> String {
        format!("/conan/v2/conans/oldlib/1.0/_/_/revisions/{REV}/files/conan_export.tgz")
    }

    fn package_file() -> String {
        format!(
            "/conan/v2/conans/oldlib/1.0/_/_/revisions/{REV}/packages/{REV}/revisions/{REV}/files/conan_package.tgz"
        )
    }

    async fn context(trust: bool) -> (MockServer, TestContext) {
        let up = MockServer::start().await;
        serve(
            &up,
            &format!("/v2/conans/oldlib/1.0/_/_/revisions/{REV}/files/conan_export.tgz"),
            b"RECIPE".to_vec(),
        )
        .await;
        serve(
            &up,
            &format!("/v2/conans/oldlib/1.0/_/_/revisions/{REV}/packages/{REV}/revisions/{REV}/files/conan_package.tgz"),
            b"PACKAGE".to_vec(),
        )
        .await;
        let uri = up.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.conan.enabled = true;
            cfg.conan.proxy = Some(uri);
            cfg.server.trust_upstream_dates = trust;
            quarantine_7d(cfg);
        });
        put_written_days_ago(&ctx, "conan/oldlib/1.0/_/_/latest.json", LATEST, 30).await;
        (up, ctx)
    }

    #[tokio::test]
    async fn without_trusted_dates_a_cached_latest_does_not_date_the_quarantine() {
        let (_up, ctx) = context(false).await;
        assert_eq!(
            status(&ctx, &recipe_file()).await,
            StatusCode::FORBIDDEN,
            "recipe"
        );
        assert_eq!(
            status(&ctx, &package_file()).await,
            StatusCode::FORBIDDEN,
            "package"
        );
    }

    /// Files cached before the quarantine recorded them are counted from now on the cache path.
    #[tokio::test]
    async fn a_file_cached_before_the_quarantine_saw_it_counts_from_now() {
        let (up, ctx) = context(false).await;
        let base = format!("conan/oldlib/1.0/_/_/revisions/{REV}");
        put_written_days_ago(
            &ctx,
            &format!("{base}/files/conan_export.tgz"),
            b"RECIPE",
            30,
        )
        .await;
        let package = format!("{base}/packages/{REV}/revisions/{REV}/files/conan_package.tgz");
        put_written_days_ago(&ctx, &package, b"PACKAGE", 30).await;
        assert_eq!(
            status(&ctx, &recipe_file()).await,
            StatusCode::FORBIDDEN,
            "recipe"
        );
        assert_eq!(
            status(&ctx, &package_file()).await,
            StatusCode::FORBIDDEN,
            "package"
        );
        assert!(crate::test_helpers::upstream_paths(&up).await.is_empty());
    }

    #[tokio::test]
    async fn with_trusted_dates_an_old_release_matures_in_the_quarantine() {
        let (_up, ctx) = context(true).await;
        assert_eq!(status(&ctx, &recipe_file()).await, StatusCode::OK, "recipe");
        assert_eq!(
            status(&ctx, &package_file()).await,
            StatusCode::OK,
            "package"
        );
    }
}

/// R5 pairs: the recipe and package `latest` and `revisions` listings are answered by one
/// function, so they cache, isolate and fetch alike: each is asked upstream under its own path
/// and cached under its own key, a fresh copy is served without asking, and an internal recipe
/// is never asked about.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod mutable_listings_alike {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const RREV: &str = "0123456789abcdef0123456789abcdef";
    const PKG: &str = "fedcba9876543210fedcba9876543210";

    /// (request path, upstream path, cache key) of each listing of `name`.
    fn listings(name: &str) -> Vec<(String, String, String)> {
        let reference = format!("{name}/1.0/_/_");
        [
            "latest".to_string(),
            "revisions".to_string(),
            format!("revisions/{RREV}/packages/{PKG}/latest"),
            format!("revisions/{RREV}/packages/{PKG}/revisions"),
        ]
        .into_iter()
        .map(|rel| {
            (
                format!("/conan/v2/conans/{reference}/{rel}"),
                format!("/v2/conans/{reference}/{rel}"),
                format!("conan/{reference}/{rel}.json"),
            )
        })
        .collect()
    }

    async fn upstream() -> MockServer {
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "revisions": []
            })))
            .mount(&upstream)
            .await;
        upstream
    }

    async fn asked(upstream: &MockServer) -> Vec<String> {
        upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect()
    }

    #[tokio::test]
    async fn each_listing_is_asked_upstream_under_its_own_path() {
        let upstream = upstream().await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.conan.enabled = true;
            cfg.conan.proxy = Some(uri);
            cfg.conan.metadata_ttl = 3600;
        });
        let listings = listings("zlib");
        for (path, _, _) in &listings {
            let resp = send(&ctx.app, Method::GET, path, "").await;
            assert_eq!(resp.status(), StatusCode::OK, "{path}");
        }
        let expected: Vec<String> = listings.iter().map(|(_, up, _)| up.clone()).collect();
        assert_eq!(asked(&upstream).await, expected);
    }

    #[tokio::test]
    async fn each_fresh_listing_is_served_from_its_own_key() {
        let upstream = upstream().await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.conan.enabled = true;
            cfg.conan.proxy = Some(uri);
            cfg.conan.metadata_ttl = 3600;
        });
        for (path, _, key) in listings("zlib") {
            let body = format!("{{\"key\":\"{key}\"}}");
            ctx.state.storage.put(&key, body.as_bytes()).await.unwrap();
            let resp = send(&ctx.app, Method::GET, &path, "").await;
            assert_eq!(resp.status(), StatusCode::OK, "{path}");
            assert_eq!(&body_bytes(resp).await[..], body.as_bytes(), "{path}");
        }
        let asked = asked(&upstream).await;
        assert!(asked.is_empty(), "asked upstream: {asked:?}");
    }

    #[tokio::test]
    async fn an_internal_recipe_is_never_asked_about_on_any_listing() {
        let upstream = upstream().await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.conan.enabled = true;
            cfg.conan.proxy = Some(uri);
            cfg.conan.metadata_ttl = 0; // every copy stale
            cfg.curation.internal_namespaces = vec!["corp-*".to_string()];
        });
        let listings = listings("corp-lib");
        // No local copy: refused.
        for (path, _, _) in &listings {
            let resp = send(&ctx.app, Method::GET, path, "").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{path}");
        }
        // A stale local copy: served as it is.
        for (path, _, key) in &listings {
            ctx.state
                .storage
                .put(key, b"{\"local\":true}")
                .await
                .unwrap();
            let resp = send(&ctx.app, Method::GET, path, "").await;
            assert_eq!(resp.status(), StatusCode::OK, "{path}");
            assert_eq!(&body_bytes(resp).await[..], b"{\"local\":true}");
        }
        let asked = asked(&upstream).await;
        assert!(asked.is_empty(), "asked upstream: {asked:?}");
    }
}
