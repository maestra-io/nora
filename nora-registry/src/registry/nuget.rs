// Copyright (c) 2026 The Nora Authors
// SPDX-License-Identifier: MIT

//! NuGet v3 registry proxy.
//!
//! Implements a caching proxy for api.nuget.org:
//!   GET /nuget/v3/index.json — service index (JSON, rewrite @id URLs)
//!   GET /nuget/v3/registration/{id}/index.json — package registration
//!   GET /nuget/v3/flatcontainer/{id}/index.json — version list
//!   GET /nuget/v3/flatcontainer/{id}/{ver}/{filename}.nupkg — package download (immutable)
//!   GET /nuget/v3/flatcontainer/{id}/{ver}/{filename}.nuspec — package spec (immutable)
//!
//! Client config:
//!   dotnet nuget add source http://nora:4000/nuget/v3/index.json -n nora

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::config::UpstreamAuth;
use crate::registry::{
    fresh_within_ttl, mark_revalidated, nora_base_url, proxy_error_response, proxy_fetch_artifact,
    proxy_fetch_conditional, proxy_fetch_shared, proxy_fetch_text, read_cached_artifact,
    read_validators, spawn_cache_body, write_validators, CachedArtifact, ProxyError, Revalidation,
    Validators,
};
use crate::registry_type::RegistryType;
use crate::secrets::expose_opt;
use crate::validation::ends_with_ci;
use crate::AppState;
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

pub(crate) mod hosted;
pub(crate) use hosted::HostedIndex;

const UPSTREAM_DEFAULT: &str = "https://api.nuget.org";
const SEARCH_TIMEOUT_SECS: u64 = 5;
const DEFAULT_SEARCH: &str = "https://azuresearch-usnc.nuget.org/query";
const DEFAULT_AUTOCOMPLETE: &str = "https://azuresearch-usnc.nuget.org/autocomplete";

#[derive(Deserialize)]
struct SearchParams {
    q: Option<String>,
    skip: Option<usize>,
    take: Option<usize>,
    prerelease: Option<bool>,
    #[serde(rename = "semVerLevel")]
    sem_ver_level: Option<String>,
}

/// Storage prefix and file suffix for repo index scanning.
/// Count .nupkg files (not index.json) so size reflects actual packages.
pub const INDEX_PATTERN: (&str, &str) = ("nuget/flatcontainer/", ".nupkg");

/// Upstream URL paths a rewritten NuGet response keeps on purpose: `catalogEntry.@id`
/// (`/v3/catalog0/…`) has no NORA handler and restore never fetches it. One list for
/// [`rewrite_registration_urls`], the leak detector (`metrics::LeakFinders`) and the
/// air-gap invariant test.
pub(crate) const UPSTREAM_PASSTHROUGH_PATHS: &[&str] = &["/v3/catalog0/"];

/// Discover search and autocomplete endpoints from the upstream NuGet V3 service index.
///
/// When the proxy URL differs from the default (api.nuget.org), the hardcoded
/// Azure Search URLs won't work for private feeds. This function fetches the
/// feed's service index and extracts the correct SearchQueryService and
/// SearchAutocompleteService URLs.
///
/// Only runs if search_service/autocomplete are still at their default values
/// (user overrides via env vars take precedence). Falls back silently on error.
pub async fn discover_search_endpoints(
    client: &reqwest::Client,
    config: &mut crate::config::NugetConfig,
) {
    let proxy_url = match &config.proxy {
        Some(url) => url.clone(),
        None => return, // no proxy configured
    };

    // Only discover if proxy is non-default AND search/autocomplete are at defaults
    let proxy_base = strip_url_path(&proxy_url);
    if proxy_base == UPSTREAM_DEFAULT {
        return; // using default upstream, Azure Search URLs are correct
    }
    let search_is_default = config.search_service == DEFAULT_SEARCH;
    let autocomplete_is_default = config.autocomplete == DEFAULT_AUTOCOMPLETE;
    if !search_is_default && !autocomplete_is_default {
        return; // user has overridden both, respect their config
    }

    // Fetch the upstream service index
    let index_url = format!("{}/v3/index.json", proxy_base);
    tracing::info!(
        url = %index_url,
        "NuGet: discovering search endpoints from upstream service index"
    );

    let resp = match client
        .get(&index_url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            tracing::warn!(
                status = %r.status(),
                url = %index_url,
                "NuGet: service index discovery failed, keeping defaults"
            );
            return;
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                url = %index_url,
                "NuGet: service index discovery failed, keeping defaults"
            );
            return;
        }
    };

    let body = match resp.text().await {
        Ok(t) if t.len() > 1_048_576 => {
            tracing::warn!(
                size = t.len(),
                "NuGet: service index too large, skipping discovery"
            );
            return;
        }
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "NuGet: failed to read service index body");
            return;
        }
    };

    let index: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "NuGet: failed to parse service index JSON");
            return;
        }
    };

    let resources = match index.get("resources").and_then(|r| r.as_array()) {
        Some(arr) => arr,
        None => {
            tracing::warn!("NuGet: service index has no 'resources' array");
            return;
        }
    };

    // Find SearchQueryService and SearchAutocompleteService
    for resource in resources {
        let rtype = resource.get("@type").and_then(|t| t.as_str()).unwrap_or("");
        let rid = resource.get("@id").and_then(|id| id.as_str()).unwrap_or("");
        if rid.is_empty() || !(rid.starts_with("https://") || rid.starts_with("http://")) {
            continue;
        }

        if search_is_default && rtype.starts_with("SearchQueryService") {
            tracing::info!(url = %rid, "NuGet: discovered search endpoint");
            config.search_service = rid.to_string();
        }
        if autocomplete_is_default && rtype.starts_with("SearchAutocompleteService") {
            tracing::info!(url = %rid, "NuGet: discovered autocomplete endpoint");
            config.autocomplete = rid.to_string();
        }
    }
}

pub fn routes() -> Router<AppState> {
    routes_with_prefix("nuget").merge(hosted::routes())
}

/// Alias routes for Chocolatey and PowerShell Gallery clients.
/// These serve the same NuGet V3 handlers under alternate path prefixes.
/// The service index points back to /nuget/ paths, so clients follow those
/// URLs after initial discovery — storage and caching stay unified.
pub fn alias_routes() -> Router<AppState> {
    routes_with_prefix("chocolatey").merge(routes_with_prefix("pwsh"))
}

fn routes_with_prefix(prefix: &str) -> Router<AppState> {
    Router::new()
        .route(&format!("/{prefix}/v3/index.json"), get(service_index))
        .route(&format!("/{prefix}/v3/query"), get(hosted::search_query))
        .route(
            &format!("/{prefix}/v3/autocomplete"),
            get(hosted::autocomplete_query),
        )
        .route(
            &format!("/{prefix}/v3/registration/{{id}}/index.json"),
            get(registration_index_filtered),
        )
        .route(
            &format!("/{prefix}/v3/registration/{{id}}/page/{{lower}}/{{*upper}}"),
            get(registration_page_filtered),
        )
        .route(
            &format!("/{prefix}/v3/flatcontainer/{{*path}}"),
            get(flatcontainer_handler),
        )
        .route(&format!("/{prefix}/v3/{{*path}}"), get(nuget_catchall))
}

// ── Service index ──────────────────────────────────────────────────────

async fn service_index(State(state): State<AppState>) -> Response {
    let base_url = nora_base_url(&state);
    let index = generate_service_index(&base_url);

    state.metrics.record_download("nuget");
    state.activity.push(ActivityEntry::new(
        ActionType::CacheHit,
        "service-index".to_string(),
        crate::registry_type::RegistryType::Nuget,
        "LOCAL",
    ));

    with_json(index.into_bytes())
}

// ── Search query (proxy to upstream SearchQueryService, local fallback) ──

async fn search_query(
    State(state): State<AppState>,
    _headers: HeaderMap,
    Query(params): Query<SearchParams>,
    raw_query: axum::extract::RawQuery,
) -> Response {
    let query = params.q.unwrap_or_default();
    let skip = params.skip.unwrap_or(0);
    let take = params.take.unwrap_or(20);
    let prerelease = params.prerelease.unwrap_or(false);
    let sem_ver_level = params.sem_ver_level;

    // No upstream proxy configured → local search directly
    if upstream_url(&state).is_none() {
        let data = local_search_results(
            &state,
            &query,
            skip,
            take,
            prerelease,
            sem_ver_level.as_deref(),
        )
        .await;
        return with_json(data);
    }

    // #68 namespace isolation: never forward a search term that matches an internal
    // namespace upstream (dependency confusion) — serve local results only.
    if crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Nuget,
        &query,
    ) {
        let data = local_search_results(
            &state,
            &query,
            skip,
            take,
            prerelease,
            sem_ver_level.as_deref(),
        )
        .await;
        return with_json(data);
    }

    // Try upstream with short timeout (UX-critical path)
    let qs = raw_query.0.unwrap_or_default();
    let url = format!("{}?{}", state.config.nuget.search_service, qs);

    match proxy_fetch_text(
        &state.http_client,
        &url,
        Duration::from_secs(SEARCH_TIMEOUT_SECS),
        None, // search endpoint is public
        None,
        &state.circuit_breaker,
        RegistryType::Nuget,
    )
    .await
    {
        Ok(text) => {
            let base_url = nora_base_url(&state);
            let upstream = rewrite_host(&state);
            let rewritten = rewrite_registration_urls(&text, &upstream, &base_url);
            state.metrics.record_download("nuget");
            state.metrics.record_cache_miss("nuget");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                format!("search?{}", qs.chars().take(50).collect::<String>()),
                crate::registry_type::RegistryType::Nuget,
                "PROXY",
            ));
            with_json(filter_search_results(&state, rewritten).await)
        }
        Err(ProxyError::NotFound) => with_json(br#"{"totalHits":0,"data":[]}"#.to_vec()),
        Err(_) => {
            if !state.config.nuget.serve_stale {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            tracing::info!("NuGet search: upstream unavailable, using local index");
            let data = local_search_results(
                &state,
                &query,
                skip,
                take,
                prerelease,
                sem_ver_level.as_deref(),
            )
            .await;
            with_json_stale(data)
        }
    }
}

// ── Autocomplete (proxy to upstream SearchAutocompleteService) ─────────

async fn autocomplete_query(
    State(state): State<AppState>,
    Query(params): Query<SearchParams>,
    raw_query: axum::extract::RawQuery,
) -> Response {
    let query = params.q.unwrap_or_default();
    let skip = params.skip.unwrap_or(0);
    let take = params.take.unwrap_or(20);
    let prerelease = params.prerelease.unwrap_or(false);
    let sem_ver_level = params.sem_ver_level;

    // No upstream proxy configured → local autocomplete from cache
    if upstream_url(&state).is_none() {
        let data = local_autocomplete_results(
            &state,
            &query,
            skip,
            take,
            prerelease,
            sem_ver_level.as_deref(),
        )
        .await;
        return with_json(data);
    }

    // #68 namespace isolation: don't forward an internal-namespace autocomplete term.
    if crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Nuget,
        &query,
    ) {
        let data = local_autocomplete_results(
            &state,
            &query,
            skip,
            take,
            prerelease,
            sem_ver_level.as_deref(),
        )
        .await;
        return with_json(data);
    }

    let qs = raw_query.0.unwrap_or_default();
    let url = format!("{}?{}", state.config.nuget.autocomplete, qs);

    match proxy_fetch_text(
        &state.http_client,
        &url,
        Duration::from_secs(SEARCH_TIMEOUT_SECS),
        None, // autocomplete endpoint is public
        None,
        &state.circuit_breaker,
        RegistryType::Nuget,
    )
    .await
    {
        Ok(text) => {
            let base_url = nora_base_url(&state);
            let upstream = rewrite_host(&state);
            let rewritten = rewrite_registration_urls(&text, &upstream, &base_url);
            state.metrics.record_download("nuget");
            state.metrics.record_cache_miss("nuget");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                format!("autocomplete?{}", qs.chars().take(50).collect::<String>()),
                crate::registry_type::RegistryType::Nuget,
                "PROXY",
            ));
            // `?id=` asks for one package's versions (hosted IDs never get here).
            match qs.split('&').find_map(|kv| kv.strip_prefix("id=")) {
                Some(id) => with_json(filter_autocomplete_versions(&state, id, rewritten).await),
                None => with_json(rewritten.into_bytes()),
            }
        }
        Err(ProxyError::NotFound) => with_json(br#"{"totalHits":0,"data":[]}"#.to_vec()),
        Err(_) => {
            if !state.config.nuget.serve_stale {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            tracing::info!("NuGet autocomplete: upstream unavailable, using local index");
            let data = local_autocomplete_results(
                &state,
                &query,
                skip,
                take,
                prerelease,
                sem_ver_level.as_deref(),
            )
            .await;
            with_json_stale(data)
        }
    }
}

// ── Registration index ─────────────────────────────────────────────────

async fn registration_index(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let id_lower = id.to_lowercase();
    if !is_valid_package_id(&id_lower) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if let Some(resp) = hosted::registration_index(&state, &id_lower).await {
        return resp;
    }

    // Curation check. #733 serve-local: an internal-namespace package is operator-owned — skip
    // curation and serve any local copy below; block the upstream branch separately.
    let internal = crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Nuget,
        &id_lower,
    );
    if !internal {
        if let Some(response) = crate::curation::check_download(
            &state.curation().curation_engine,
            state.bypass_token().as_deref(),
            &headers,
            crate::curation::RegistryType::Nuget,
            &id_lower,
            crate::curation::RequestVersion::Unspecified,
            None,
        ) {
            return response;
        }
    }

    let storage_key = format!("nuget/registration/{}/index.json", id_lower);

    let base_url = nora_base_url(&state);
    let upstream = rewrite_host(&state);

    // Read cache eagerly so stale data is available on upstream failure.
    let cached_data = state.storage.get(&storage_key).await.ok();

    // TTL cache — rewrite URLs on read (cache may contain pre-fix entries)
    if let Some(ref data) = cached_data {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            let ttl = state.config.nuget.metadata_ttl;
            if fresh_within_ttl(&state.storage, &storage_key, meta.modified, ttl).await {
                state.metrics.record_download("nuget");
                state.metrics.record_cache_hit("nuget");
                let text = String::from_utf8_lossy(data);
                let rewritten = rewrite_registration_urls(&text, &upstream, &base_url);
                return with_json_gzip(rewritten.into_bytes());
            }
        }
    }

    // #733: an internal-namespace package — serve any (stale) local registration, else block; never proxy.
    if internal {
        if let Some(ref data) = cached_data {
            state.metrics.record_download("nuget");
            state.metrics.record_cache_hit("nuget");
            let text = String::from_utf8_lossy(data);
            let rewritten = rewrite_registration_urls(&text, &upstream, &base_url);
            return with_json_gzip(rewritten.into_bytes());
        }
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Nuget,
            &id_lower,
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
    }

    // No upstream when the operator switched it off: what is stored is all there is.
    if upstream_url(&state).is_none() {
        return match cached_data {
            Some(data) => {
                let text = String::from_utf8_lossy(&data);
                with_json_gzip(rewrite_registration_urls(&text, &upstream, &base_url).into_bytes())
            }
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    let url = format!(
        "{}/v3/registration5-gz-semver2/{}/index.json",
        upstream.trim_end_matches('/'),
        id_lower
    );

    let rewrite = Some((upstream.as_str(), base_url.as_str()));
    match refresh_metadata(&state, &storage_key, &url, Some(id_lower.clone())).await {
        Ok(raw) => {
            let text = String::from_utf8_lossy(&raw);
            let rewritten = rewrite_registration_urls(&text, &upstream, &base_url);
            with_json_gzip(rewritten.into_bytes())
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::debug!(error = ?e, "NuGet registration error");
            serve_stale_or_error(&state, cached_data, "registration_index", rewrite, &e)
        }
    }
}

// ── Registration page (paginated version ranges) ────────────────────────

async fn registration_page(
    State(state): State<AppState>,
    Path((id, lower, upper_raw)): Path<(String, String, String)>,
) -> Response {
    let id_lower = id.to_lowercase();
    if !is_valid_package_id(&id_lower) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let upper = upper_raw
        .strip_suffix(".json")
        .unwrap_or(&upper_raw)
        .to_string();
    if !is_valid_version(&lower) || !is_valid_version(&upper) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if let Some(resp) = hosted::registration_page(&state, &id_lower, &lower, &upper).await {
        return resp;
    }

    let base_url = nora_base_url(&state);
    let upstream = rewrite_host(&state);
    let storage_key = format!(
        "nuget/registration/{}/page/{}/{}.json",
        id_lower, lower, upper
    );

    // Read cache eagerly so stale data is available on upstream failure.
    let cached_data = state.storage.get(&storage_key).await.ok();

    // TTL cache (a 304 revalidation keeps a page fresh without re-uploading it, C56)
    if let Some(ref data) = cached_data {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            let ttl = state.config.nuget.metadata_ttl;
            if fresh_within_ttl(&state.storage, &storage_key, meta.modified, ttl).await {
                state.metrics.record_download("nuget");
                state.metrics.record_cache_hit("nuget");
                let text = String::from_utf8_lossy(data);
                let rewritten = rewrite_registration_urls(&text, &upstream, &base_url);
                return with_json_gzip(rewritten.into_bytes());
            }
        }
    }

    // #68 namespace isolation: an internal-namespace package's registration must
    // never be fetched upstream (dependency confusion). Serve any local copy
    // (hosted/cached; the fresh path returned above), else block — never proxy.
    if crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Nuget,
        &id_lower,
    ) {
        if let Some(ref data) = cached_data {
            state.metrics.record_download("nuget");
            state.metrics.record_cache_hit("nuget");
            let text = String::from_utf8_lossy(data);
            let rewritten = rewrite_registration_urls(&text, &upstream, &base_url);
            return with_json_gzip(rewritten.into_bytes());
        }
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Nuget,
            &id_lower,
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
    }

    // No upstream when the operator switched it off: what is stored is all there is.
    if upstream_url(&state).is_none() {
        return match cached_data {
            Some(data) => {
                let text = String::from_utf8_lossy(&data);
                with_json_gzip(rewrite_registration_urls(&text, &upstream, &base_url).into_bytes())
            }
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    let url = format!(
        "{}/v3/registration5-gz-semver2/{}/page/{}/{}.json",
        upstream.trim_end_matches('/'),
        id_lower,
        lower,
        upper
    );

    // Single-flight (C48) and conditional revalidation (C56), as the index.
    let activity = Some(format!("{}/page/{}/{}", id_lower, lower, upper));
    match refresh_metadata(&state, &storage_key, &url, activity).await {
        Ok(raw) => {
            let text = String::from_utf8_lossy(&raw);
            let rewritten = rewrite_registration_urls(&text, &upstream, &base_url);
            with_json_gzip(rewritten.into_bytes())
        }
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::debug!(error = ?e, "NuGet registration page error");
            let rewrite = Some((upstream.as_str(), base_url.as_str()));
            serve_stale_or_error(&state, cached_data, "registration_page", rewrite, &e)
        }
    }
}

// ── Flat container dispatcher ───────────────────────────────────────────

async fn flatcontainer_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(path): Path<String>,
) -> Response {
    // Path patterns:
    //   {id}/index.json              → version list
    //   {id}/{ver}/{filename}.nupkg  → package download
    //   {id}/{ver}/{filename}.nuspec → package spec
    let parts: Vec<&str> = path.splitn(3, '/').collect();
    match parts.len() {
        2 if parts[1] == "index.json" => version_list_filtered(state, parts[0]).await,
        3 => flatcontainer_download(state, headers, &path, parts[0], parts[1], parts[2]).await,
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

// ── Version list ───────────────────────────────────────────────────────

async fn version_list(state: AppState, id: &str) -> Response {
    let id = id.to_string();
    let id_lower = id.to_lowercase();
    if !is_valid_package_id(&id_lower) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if let Some(resp) = hosted::version_list(&state, &id_lower).await {
        return resp;
    }

    let storage_key = format!("nuget/flatcontainer/{}/index.json", id_lower);

    // Read cache eagerly so stale data is available on upstream failure.
    let cached_data = state.storage.get(&storage_key).await.ok();

    // TTL cache
    if let Some(ref data) = cached_data {
        if let Some(meta) = state.storage.stat(&storage_key).await {
            let ttl = state.config.nuget.metadata_ttl;
            if fresh_within_ttl(&state.storage, &storage_key, meta.modified, ttl).await {
                state.metrics.record_download("nuget");
                state.metrics.record_cache_hit("nuget");
                return with_json(data.to_vec());
            }
        }
    }

    // #68 namespace isolation: serve any local version list for an internal package,
    // else block — never fetch upstream (dependency confusion).
    if crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Nuget,
        &id_lower,
    ) {
        if let Some(ref data) = cached_data {
            state.metrics.record_download("nuget");
            state.metrics.record_cache_hit("nuget");
            return with_json(data.to_vec());
        }
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Nuget,
            &id_lower,
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
    }

    // No upstream when the operator switched it off: what is stored is all there is.
    let Some(proxy_url) = upstream_url(&state) else {
        return match cached_data {
            Some(data) => with_json(data.to_vec()),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    };
    let url = format!(
        "{}/v3-flatcontainer/{}/index.json",
        proxy_url.trim_end_matches('/'),
        id_lower
    );

    let activity = Some(format!("{}/versions", id_lower));
    match refresh_metadata(&state, &storage_key, &url, activity).await {
        Ok(raw) => with_json(raw.to_vec()),
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::debug!(error = ?e, "NuGet version list error");
            serve_stale_or_error(&state, cached_data, "version_list", None, &e)
        }
    }
}

/// Refresh the cached metadata document at `storage_key` (registration index or
/// page, version list) from `url`, returning its raw (not yet rewritten) body.
///
/// Stale metadata is revalidated with a conditional request when enabled (a cheap
/// 304 — nuget.org returns validators); without stored validators the request is a
/// plain fetch, which is also how the first fetch captures them. Runs under
/// single-flight (C48): concurrent cold misses and revalidations of one document make
/// one upstream request, and only that request writes the cache, before the flight
/// ends, so the next reader finds the new copy (or the 304 stamp) in storage.
///
/// `activity` names a client request for the download metrics and the activity log;
/// `None` is nora's own read (the Q01/Q04 registration lookups), which counts as
/// neither.
async fn refresh_metadata(
    state: &AppState,
    storage_key: &str,
    url: &str,
    activity: Option<String>,
) -> Result<Bytes, ProxyError> {
    let client = activity.is_some();
    let fetch = async {
        let validators = if state.config.nuget.revalidate {
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
            Duration::from_secs(state.config.nuget.metadata_proxy_timeout),
            expose_opt(&state.config.nuget.proxy_auth).map(UpstreamAuth::Basic),
            &validators,
            &state.circuit_breaker,
            RegistryType::Nuget,
        )
        .await
        {
            // Upstream unchanged — serve the cached body and record the revalidation
            // so we do not revalidate again until the next TTL window. No body is
            // downloaded, and none is re-uploaded (C56).
            Ok(Revalidation::NotModified) => {
                let body = state
                    .storage
                    .get(storage_key)
                    .await
                    .map_err(|e| ProxyError::Network(format!("cached body unreadable: {e}")))?;
                crate::metrics::PROXY_UPSTREAM_304_TOTAL
                    .with_label_values(&["nuget"])
                    .inc();
                crate::metrics::PROXY_REVALIDATION_BYTES_SAVED_TOTAL
                    .with_label_values(&["nuget"])
                    .inc_by(body.len() as u64);
                if client {
                    state.metrics.record_download("nuget");
                    state.metrics.record_cache_hit("nuget");
                }
                mark_revalidated(&state.storage, "nuget", storage_key).await;
                Ok(body)
            }
            // New body — cache the raw bytes first, then persist the fresh validators.
            Ok(Revalidation::Modified { body, validators }) => {
                if let Some(activity) = activity {
                    state.metrics.record_download("nuget");
                    state.metrics.record_cache_miss("nuget");
                    state.activity.push(ActivityEntry::new(
                        ActionType::ProxyFetch,
                        activity,
                        crate::registry_type::RegistryType::Nuget,
                        "PROXY",
                    ));
                    state
                        .audit
                        .log(AuditEntry::new("proxy_fetch", "proxy", "", "nuget", ""));
                }
                let raw = Bytes::from(body);
                match state.storage.put_bytes(storage_key, raw.clone()).await {
                    Ok(()) => write_validators(&state.storage, storage_key, &validators).await,
                    Err(e) => crate::record_cache_write_error("nuget", storage_key, &e),
                }
                Ok(raw)
            }
            Err(e) => {
                if had_validators && !matches!(e, ProxyError::NotFound) {
                    crate::metrics::PROXY_REVALIDATION_ERRORS_TOTAL
                        .with_label_values(&["nuget"])
                        .inc();
                }
                Err(e)
            }
        }
    };
    let (body, fetched) = proxy_fetch_shared(
        state,
        storage_key,
        "nuget",
        state.config.nuget.metadata_proxy_timeout,
        fetch,
    )
    .await?;
    if !fetched && client {
        // A coalesced follower: served the leader's in-memory result.
        state.metrics.record_download("nuget");
        state.metrics.record_cache_hit("nuget");
    }
    Ok(body)
}

// ── Flatcontainer download (nupkg/nuspec, immutable) ───────────────────
// LOCK-SAFE: cache-through proxy — get miss → fetch upstream → put; no RMW race
async fn flatcontainer_download(
    state: AppState,
    headers: axum::http::HeaderMap,
    path: &str,
    id: &str,
    ver: &str,
    filename: &str,
) -> Response {
    if !is_safe_path(path) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Only serve .nupkg and .nuspec files
    if !ends_with_ci(filename, ".nupkg") && !ends_with_ci(filename, ".nuspec") {
        return StatusCode::NOT_FOUND.into_response();
    }

    let id_lower = id.to_lowercase();
    if let Some(resp) = hosted::download(&state, &headers, path, &id_lower).await {
        return resp;
    }
    let nupkg = ends_with_ci(filename, ".nupkg");

    // #733 serve-local: an internal-namespace package is operator-owned — skip curation and serve
    // any local copy below; block the upstream branch separately, for the .nuspec as for the
    // .nupkg (R2-42: either request would name the ID upstream).
    let internal = crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Nuget,
        &id_lower,
    );

    // Hoisted to function scope for the digest-quarantine serve gate (#750).
    let mut publish_date: Option<i64> = None;
    // Curation check for .nupkg downloads (.nuspec is uncurated)
    if nupkg && !internal {
        // Q01: a flat-container restore never requests the registration, so the date
        // comes from the registration this primes.
        publish_date = nuget_publish_date(&state, &id_lower, ver).await;

        if let Some(response) = crate::curation::check_download(
            &state.curation().curation_engine,
            state.bypass_token().as_deref(),
            &headers,
            crate::curation::RegistryType::Nuget,
            &id_lower,
            crate::curation::RequestVersion::Known(ver.to_string()),
            judged_date(&state, publish_date),
        ) {
            return response;
        }
    }

    let storage_key = format!("nuget/flatcontainer/{}", path.to_lowercase());
    let content_type = if nupkg {
        "application/octet-stream"
    } else {
        "application/xml"
    };

    let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
        state.config.curation.nuget.quarantine.as_ref().or(state
            .config
            .curation
            .quarantine
            .as_ref()),
        state
            .config
            .curation
            .nuget
            .quarantine_ttl
            .as_deref()
            .or(state.config.curation.quarantine_ttl.as_deref()),
    );
    let quarantine_on = !matches!(q_mode, crate::digest_quarantine::QuarantineMode::Off);

    // A Range request on a large cached package: one ranged read, never a streaming read
    // of the whole object opened first (R2-13). The quarantine needs the whole object.
    if nupkg && !quarantine_on {
        let integrity = Some((id_lower.as_str(), ver));
        if let Some(resp) = ranged_large_nupkg(&state, &headers, &storage_key, integrity).await {
            return resp;
        }
    }

    // Immutable cache, integrity-gated: read whole and verified, or above
    // `server.stream_threshold_mb` streamed with its pin checked as it streams.
    let cached = match read_cached_artifact(&state, "nuget", &storage_key, internal).await {
        Ok(cached) => cached,
        Err(resp) => return resp,
    };
    if let Some(cached) = cached {
        let engine = &state.curation().curation_engine;
        if nupkg && engine.is_active() {
            if let Some(response) = crate::curation::verify_integrity_by_hash(
                engine,
                crate::curation::RegistryType::Nuget,
                &id_lower,
                Some(ver),
                &cached.digest(),
            ) {
                return response;
            }
        }

        state.metrics.record_download("nuget");
        state.metrics.record_cache_hit("nuget");
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            format!("{}/{}", id_lower, filename),
            crate::registry_type::RegistryType::Nuget,
            "CACHE",
        ));

        if quarantine_on {
            if let Some(resp) = crate::digest_quarantine::proxy_gate_digest(
                &state.digest_store,
                "nuget",
                &cached.digest(),
                &q_mode,
                q_secs,
                "cache",
                publish_date,
            ) {
                return resp;
            }
        }

        return serve_artifact(&state, &headers, &storage_key, cached, nupkg, internal).await;
    }

    // #733: an internal-namespace .nupkg or .nuspec with no local copy is never proxied upstream.
    if internal {
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Nuget,
            &id_lower,
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
    }

    // Fetch from upstream — none when the operator switched it off.
    let Some(proxy_url) = upstream_url(&state) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let url = format!(
        "{}/v3-flatcontainer/{}/{}/{}",
        proxy_url.trim_end_matches('/'),
        id_lower,
        ver.to_lowercase(),
        filename.to_lowercase()
    );

    match proxy_fetch_artifact(
        &state,
        &storage_key,
        "nuget",
        &url,
        state.config.nuget.proxy_timeout,
        expose_opt(&state.config.nuget.proxy_auth).map(UpstreamAuth::Basic),
        RegistryType::Nuget,
    )
    .await
    {
        Ok((body, fetched)) => {
            // The allowlist's pinned integrity holds on the first download too, before anything is cached:
            // the cache-hit branch checks the same rule.
            if nupkg {
                if let Some(response) = crate::curation::verify_integrity_by_hash(
                    &state.curation().curation_engine,
                    crate::curation::RegistryType::Nuget,
                    &id_lower,
                    Some(ver),
                    &body.digest(),
                ) {
                    return response;
                }
            }
            state.metrics.record_download("nuget");
            state.metrics.record_cache_miss("nuget");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                format!("{}/{}", id_lower, filename),
                crate::registry_type::RegistryType::Nuget,
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "proxy", "", "nuget", ""));

            if fetched {
                spawn_cache_body(&state, "nuget", storage_key.clone(), body.clone());
            }

            // Best-effort: fetch flatcontainer index.json if missing (for local search)
            if nupkg {
                let index_key = format!("nuget/flatcontainer/{}/index.json", id_lower);
                let state2 = state.clone();
                let proxy_url2 = proxy_url.clone();
                let id2 = id_lower.clone();
                tokio::spawn(async move {
                    if state2.storage.stat(&index_key).await.is_none() {
                        let url = format!(
                            "{}/v3-flatcontainer/{}/index.json",
                            proxy_url2.trim_end_matches('/'),
                            id2
                        );
                        if let Ok(text) = proxy_fetch_text(
                            &state2.http_client,
                            &url,
                            Duration::from_secs(state2.config.nuget.proxy_timeout),
                            expose_opt(&state2.config.nuget.proxy_auth).map(UpstreamAuth::Basic),
                            None,
                            &state2.circuit_breaker,
                            RegistryType::Nuget,
                        )
                        .await
                        {
                            match state2.storage.put(&index_key, text.as_bytes()).await {
                                Ok(()) => state2.repo_index.invalidate("nuget"),
                                Err(e) => crate::record_cache_write_error("nuget", &index_key, &e),
                            }
                        }
                    }
                });
            }
            if quarantine_on {
                if let Some(resp) = crate::digest_quarantine::proxy_gate_digest(
                    &state.digest_store,
                    "nuget",
                    &body.digest(),
                    &q_mode,
                    q_secs,
                    &url,
                    publish_date,
                ) {
                    return resp;
                }
            }
            let len = body.len();
            let body = match body.into_body(&storage_key).await {
                Ok(body) => body,
                Err(e) => {
                    tracing::warn!(key = %storage_key, error = %e, "nuget: spooled package unreadable");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            };
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, content_type),
                    (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
                    (header::CONTENT_LENGTH, &len.to_string()),
                ],
                body,
            )
                .into_response()
        }
        // Not cached and upstream failed: only an upstream not-found is a 404 (NU1101,
        // never retried); an outage is a 5xx that NuGet's HttpRetryHandler retries.
        Err(e) => proxy_error_response("nuget", &url, &e),
    }
}

const IMMUTABLE: &str = "public, max-age=31536000, immutable";

/// The 200 for a stored `.nupkg` / `.nuspec` read by [`read_cached_artifact`] (cached
/// or hosted), or for a `.nupkg` Range request its 206/416. The range sits after the
/// caller's gates because the quarantine digest check needs the whole object; a
/// partial body cannot be rehashed, so it relies on the package hash the client
/// verifies itself (docker did the same in #657). An absent/malformed range falls
/// through to the full 200. The .nuspec manifest is a metadata read, never ranged.
async fn serve_artifact(
    state: &AppState,
    headers: &HeaderMap,
    key: &str,
    cached: CachedArtifact,
    nupkg: bool,
    internal: bool,
) -> Response {
    let content_type = if nupkg {
        "application/octet-stream"
    } else {
        "application/xml"
    };
    if nupkg {
        let extra = [(header::CACHE_CONTROL, IMMUTABLE.to_string())];
        let ranged = match &cached {
            // C23: a 206 cut from the body already read, not a second read.
            CachedArtifact::Buffered(data) => crate::registry::range::range_response_from_bytes(
                data,
                headers,
                content_type,
                &extra,
            ),
            CachedArtifact::Streamed { len, .. } => {
                crate::registry::range::range_response(
                    &state.storage,
                    &[key],
                    headers,
                    *len,
                    content_type,
                    &extra,
                )
                .await
            }
        };
        if let Some(response) = ranged {
            return response;
        }
    }
    let len = cached.len();
    let mut response = (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, IMMUTABLE),
        ],
        cached.into_body(state, "nuget", key, internal),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    if nupkg {
        response
            .headers_mut()
            .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    }
    response
}

/// R2-13: a `.nupkg` Range request for a stored object above `server.stream_threshold_mb`
/// served by `stat` plus one ranged read, as npm and PyPI do; [`read_cached_artifact`]
/// would open a streaming read of the whole object first and drop it unread. `None`
/// (no Range header, no such object, a small one, or no range served): the caller
/// reads the object as usual, a small one whole and sliced in memory (C23).
/// `integrity` (`id`, `version`) is set for a proxied package: its curation integrity
/// check runs against the stored pin, as on the streamed path; no pin, no shortcut.
async fn ranged_large_nupkg(
    state: &AppState,
    headers: &HeaderMap,
    key: &str,
    integrity: Option<(&str, &str)>,
) -> Option<Response> {
    if !headers.contains_key(header::RANGE) {
        return None;
    }
    let threshold = state.config.server.stream_threshold();
    let size = state.storage.stat(key).await?.size;
    if threshold == 0 || size <= threshold {
        return None;
    }
    if let Some((id, ver)) = integrity {
        let engine = &state.curation().curation_engine;
        if engine.is_active() {
            let pin = state.storage.pin(key).await?;
            if let Some(response) = crate::curation::verify_integrity_by_hash(
                engine,
                crate::curation::RegistryType::Nuget,
                id,
                Some(ver),
                &format!("sha256:{pin}"),
            ) {
                return Some(response);
            }
        }
    }
    let extra = [(header::CACHE_CONTROL, IMMUTABLE.to_string())];
    let response = crate::registry::range::range_response(
        &state.storage,
        &[key],
        headers,
        size,
        "application/octet-stream",
        &extra,
    )
    .await?;
    if response.status() == StatusCode::PARTIAL_CONTENT {
        state.metrics.record_download("nuget");
        state.metrics.record_cache_hit("nuget");
    }
    Some(response)
}

// ── Stale-while-error helper ──────────────────────────────────────────

/// Serve stale cached metadata when upstream failed, else answer for the upstream
/// error (`proxy_error_response`: 5xx for an outage, never a 404).
///
/// If `rewrite_ctx` is `Some((upstream, base_url))`, registration URL rewriting
/// is applied to the stale response (for registration endpoints).
fn serve_stale_or_error(
    state: &AppState,
    cached: Option<Bytes>,
    label: &str,
    rewrite_ctx: Option<(&str, &str)>,
    err: &ProxyError,
) -> Response {
    if let Some(data) = cached {
        if state.config.nuget.serve_stale {
            tracing::warn!(
                registry = "nuget",
                endpoint = label,
                "Upstream unreachable, serving stale cached metadata"
            );
            let body = if let Some((upstream, base_url)) = rewrite_ctx {
                let text = String::from_utf8_lossy(&data);
                rewrite_registration_urls(&text, upstream, base_url).into_bytes()
            } else {
                data.to_vec()
            };
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
                        axum::http::header::HeaderValue::from_static("true"),
                    ),
                ],
                body,
            )
                .into_response();
        }
    }
    // No cached data or serve_stale disabled.
    proxy_error_response("nuget", label, err)
}

// ── Helpers ────────────────────────────────────────────────────────────

/// Where a registration index puts a version: its inlined leaf, or the bounds of the
/// non-inlined page covering it (nuget.org inlines no pages for an ID with more than
/// 128 versions, e.g. AWSSDK.Core).
enum RegistrationHit {
    Leaf(serde_json::Value),
    Page(String, String),
}

/// The registration leaf of `version` among `leaves`.
fn find_leaf(leaves: &[serde_json::Value], version: &str) -> Option<serde_json::Value> {
    leaves
        .iter()
        .find(|l| {
            l.get("catalogEntry")
                .and_then(|e| e.get("version"))
                .and_then(|v| v.as_str())
                // A leaf may carry SemVer 2 build metadata the flat-container path drops.
                .is_some_and(|v| {
                    v.split('+')
                        .next()
                        .unwrap_or(v)
                        .eq_ignore_ascii_case(version)
                })
        })
        .cloned()
}

/// A NuGet date field as a Unix timestamp. nuget.org dates an unlisted version
/// `1900-01-01`: any year before 1950 is no release date and reads as unknown, never
/// as a decades-old release.
fn nuget_date(field: Option<&serde_json::Value>) -> Option<i64> {
    const Y1950: i64 = -631_152_000;
    crate::curation::parse_iso8601_to_unix(field?.as_str()?).filter(|&ts| ts >= Y1950)
}

/// Release date of a registration leaf: `catalogEntry.published`. An undated one (an
/// unlisted version) is dated from its catalog leaf ([`catalog_created`]), unless the
/// registration leaf's own `commitTimeStamp` (never before the release) is already past
/// the NuGet `min_release_age`: then by that, with no fetch.
async fn leaf_date(state: &AppState, id: &str, leaf: &serde_json::Value) -> Option<i64> {
    let entry = leaf.get("catalogEntry")?;
    if let Some(date) = nuget_date(entry.get("published")) {
        return Some(date);
    }
    let committed = nuget_date(leaf.get("commitTimeStamp"));
    let min_age = state
        .curation()
        .curation_engine
        .min_release_age_secs(RegistryType::Nuget);
    if let (Some(at), Some(min_age)) = (committed, min_age) {
        if crate::cache_ttl::now_unix() as i64 - at >= min_age {
            return Some(at);
        }
    }
    let version = entry_version(entry).filter(|v| is_valid_version(v))?;
    catalog_created(state, id, &version, entry.get("@id")?.as_str()?).await
}

/// `created` (else `catalog:commitTimeStamp`) of the catalog leaf at `url`
/// (`catalogEntry.@id`). Fetched through [`refresh_metadata`] (one flight per version)
/// and kept for good under `nuget/catalog/{id}/{version}.json`: a creation date never
/// changes. Only from the configured upstream's origin: the request carries `proxy_auth`.
async fn catalog_created(state: &AppState, id: &str, version: &str, url: &str) -> Option<i64> {
    let key = format!("nuget/catalog/{id}/{version}.json");
    let leaf = match read_json(&state.storage, &key).await {
        Some(leaf) => leaf,
        None => {
            // No upstream configured: no leaf is fetched.
            let origin = format!("{}/", upstream_url(state)?.trim_end_matches('/'));
            if !url.starts_with(&origin) {
                return None;
            }
            serde_json::from_slice(&refresh_metadata(state, &key, url, None).await.ok()?).ok()?
        }
    };
    nuget_date(leaf.get("created")).or_else(|| nuget_date(leaf.get("catalog:commitTimeStamp")))
}

/// The date curation judges a proxied version by: its release date, or for one still
/// unknown with `trust_upstream_dates` (every date source tried), what
/// `curation.on_failure` makes of it ([`crate::curation::CurationEngine::unknown_release_date`]).
fn judged_date(state: &AppState, date: Option<i64>) -> Option<i64> {
    if date.is_some() || !state.config.server.trust_upstream_dates {
        return date;
    }
    state.curation().curation_engine.unknown_release_date()
}

/// Find `version` in a registration index: an inlined leaf, or the page that covers it.
fn registration_hit(index: &serde_json::Value, version: &str) -> Option<RegistrationHit> {
    for page in index.get("items")?.as_array()? {
        // Pages may be non-inline (no items array) per NuGet V3 spec (#535).
        if let Some(leaves) = page.get("items").and_then(|i| i.as_array()) {
            if let Some(leaf) = find_leaf(leaves, version) {
                return Some(RegistrationHit::Leaf(leaf));
            }
            continue;
        }
        let bound = |k: &str| {
            page.get(k)
                .and_then(|v| v.as_str())
                .map(str::to_lowercase)
                .filter(|v| is_valid_version(v))
        };
        let (Some(lower), Some(upper)) = (bound("lower"), bound("upper")) else {
            continue;
        };
        if hosted::compare_versions(version, &lower).is_ge()
            && hosted::compare_versions(version, &upper).is_le()
        {
            return Some(RegistrationHit::Page(lower, upper));
        }
    }
    None
}

async fn read_json(storage: &crate::storage::Storage, key: &str) -> Option<serde_json::Value> {
    serde_json::from_slice(&storage.get(key).await.ok()?).ok()
}

fn registration_key(id: &str) -> String {
    format!("nuget/registration/{id}/index.json")
}

fn registration_page_key(id: &str, lower: &str, upper: &str) -> String {
    format!("nuget/registration/{id}/page/{lower}/{upper}.json")
}

/// Refresh a registration document (index or page) from upstream into the key its
/// proxy handler serves it from, through [`refresh_metadata`]: one flight with the
/// handler and every other caller (C48), a conditional request against the stored
/// validators (C56), persisted before it returns. Best-effort: `None` on any failure.
async fn fetch_registration_doc(
    state: &AppState,
    key: &str,
    upstream_path: &str,
) -> Option<serde_json::Value> {
    let url = format!(
        "{}/v3/registration5-gz-semver2/{upstream_path}",
        upstream_url(state)?.trim_end_matches('/')
    );
    let raw = refresh_metadata(state, key, &url, None).await.ok()?;
    serde_json::from_slice(&raw).ok()
}

/// Publish date of `id`/`version` from its registration, primed here (Q01).
///
/// `dotnet restore` reads only the flat container (`{id}/index.json`, then the
/// `.nupkg`), so the registration index — the carrier of `catalogEntry.published` —
/// is never requested on that path. The cached index is used when it places the
/// version (a publish date does not change); otherwise it is refreshed (missing, or
/// older than the version). A version on a non-inlined page is dated from the cached
/// page, else the refreshed one. Each document is read once (R2-43).
///
/// NuGet registration index JSON has nested items:
/// ```json
/// { "items": [{ "items": [{ "catalogEntry": { "version": "1.0.0", "published": "2024-01-15T10:30:00Z" } }] }] }
/// ```
/// An unlisted version is dated from its catalog leaf ([`leaf_date`]).
/// `None` when upstream dates are untrusted (#513): the upstream date is spoofable,
/// and nora's cache mtime is no publish date either (C49: every metadata refresh
/// re-dated every version to now, and an old index matured a new version in the
/// quarantine at once). Min-release-age then defers to the quarantine's own clock.
/// An internal or hosted ID never reaches it (both return before curation).
async fn nuget_publish_date(state: &AppState, id: &str, version: &str) -> Option<i64> {
    if !state.config.server.trust_upstream_dates {
        return None;
    }
    let index_key = registration_key(id);
    let cached = read_json(&state.storage, &index_key).await;
    let hit = match cached.and_then(|doc| registration_hit(&doc, version)) {
        Some(hit) => hit,
        None => {
            let doc = fetch_registration_doc(state, &index_key, &format!("{id}/index.json")).await;
            registration_hit(&doc?, version)?
        }
    };
    let (lower, upper) = match hit {
        RegistrationHit::Leaf(leaf) => return leaf_date(state, id, &leaf).await,
        RegistrationHit::Page(lower, upper) => (lower, upper),
    };
    let page_key = registration_page_key(id, &lower, &upper);
    let leaf = |page: serde_json::Value| find_leaf(page.get("items")?.as_array()?, version);
    let leaf = match read_json(&state.storage, &page_key).await.and_then(leaf) {
        Some(leaf) => leaf,
        None => {
            let upstream_path = format!("{id}/page/{lower}/{upper}.json");
            leaf(fetch_registration_doc(state, &page_key, &upstream_path).await?)?
        }
    };
    leaf_date(state, id, &leaf).await
}

// ── Q04: hide young versions from proxied metadata ─────────────────────

/// A catalog entry's version as the flat container spells it: lowercase, no
/// SemVer 2 build metadata.
fn entry_version(entry: &serde_json::Value) -> Option<String> {
    let v = entry.get("version")?.as_str()?;
    Some(v.split('+').next().unwrap_or(v).to_lowercase())
}

/// The version of `leaf` (a registration leaf) if metadata must hide it.
async fn leaf_hidden(state: &AppState, id: &str, leaf: &serde_json::Value) -> Option<String> {
    let version = entry_version(leaf.get("catalogEntry")?)?;
    let date = judged_date(state, leaf_date(state, id, leaf).await);
    let curation = state.curation();
    let engine = &curation.curation_engine;
    engine
        .hides_from_metadata(RegistryType::Nuget, id, &version, date)
        .then_some(version)
}

/// Drop `hidden` leaves from a registration index (its inlined pages) or page, fixing
/// each `count`. `None` when nothing is hidden.
fn filter_registration(hidden: &HashSet<String>, body: &[u8]) -> Option<Vec<u8>> {
    fn retain(hidden: &HashSet<String>, holder: &mut serde_json::Value) -> bool {
        let Some(leaves) = holder.get_mut("items").and_then(|i| i.as_array_mut()) else {
            return false;
        };
        let before = leaves.len();
        leaves.retain(|leaf| {
            leaf.get("catalogEntry")
                .and_then(entry_version)
                .is_none_or(|v| !hidden.contains(&v))
        });
        let after = leaves.len();
        if after != before {
            holder["count"] = serde_json::json!(after);
        }
        after != before
    }
    let mut doc: serde_json::Value = serde_json::from_slice(body).ok()?;
    let is_page = doc
        .get("items")?
        .as_array()?
        .iter()
        .any(|i| i.get("catalogEntry").is_some());
    let changed = if is_page {
        retain(hidden, &mut doc)
    } else {
        let mut changed = false;
        for page in doc.get_mut("items")?.as_array_mut()? {
            changed |= retain(hidden, page);
        }
        changed
    };
    changed.then(|| serde_json::to_vec(&doc).ok()).flatten()
}

/// Q04 hidden-version sets of proxied IDs by (ID, `last_page_only`), each kept for
/// `nuget.metadata_ttl` (R2-30): a restore asks for the flat `index.json` of every
/// package and searches repeat, and a set costs the registration index and pages.
/// An entry is tied to the curation config it was computed under, so a SIGHUP reload
/// (allow list, min age) applies at once; a version maturing meanwhile shows up when
/// its entry expires.
#[derive(Default)]
pub(crate) struct HiddenMemo(parking_lot::Mutex<HashMap<(String, bool), HiddenEntry>>);

struct HiddenEntry {
    at: std::time::Instant,
    curation: usize,
    hidden: Arc<HashSet<String>>,
}

/// Memo entries kept before expired ones are dropped.
// ponytail: whole-map prune at the cap, an LRU if the restored-ID set gets that big.
const HIDDEN_MEMO_MAX: usize = 4096;

/// [`compute_hidden_versions`], memoized in [`HiddenMemo`].
async fn hidden_versions(state: &AppState, id: &str, last_page_only: bool) -> Arc<HashSet<String>> {
    let ttl = std::time::Duration::from_secs(state.config.nuget.metadata_ttl.max(0) as u64);
    let curation = Arc::as_ptr(&*state.curation()) as usize;
    let memo = &state.nuget_hosted.hidden.0;
    let key = (id.to_string(), last_page_only);
    if let Some(e) = memo.lock().get(&key) {
        if e.curation == curation && e.at.elapsed() < ttl {
            return e.hidden.clone();
        }
    }
    let hidden = Arc::new(compute_hidden_versions(state, id, last_page_only).await);
    if !ttl.is_zero() {
        let mut memo = memo.lock();
        if memo.len() >= HIDDEN_MEMO_MAX {
            memo.retain(|_, e| e.at.elapsed() < ttl);
            if memo.len() >= HIDDEN_MEMO_MAX {
                memo.clear();
            }
        }
        let entry = HiddenEntry {
            at: std::time::Instant::now(),
            curation,
            hidden: hidden.clone(),
        };
        memo.insert(key, entry);
    }
    hidden
}

/// The versions of a proxied `id` metadata must hide, from its registration: the
/// index (fresh within `metadata_ttl` or revalidated within it, else refreshed through
/// [`refresh_metadata`]) and, for an ID whose pages are not inlined, the page
/// documents (cached by their bounds, fetched once, concurrently). `last_page_only`
/// reads only the newest page: search results show many IDs at once, and a fresh
/// version almost always lands there.
async fn compute_hidden_versions(
    state: &AppState,
    id: &str,
    last_page_only: bool,
) -> HashSet<String> {
    let index_key = registration_key(id);
    let ttl = state.config.nuget.metadata_ttl;
    let fresh = match state.storage.stat(&index_key).await {
        Some(m) if fresh_within_ttl(&state.storage, &index_key, m.modified, ttl).await => {
            read_json(&state.storage, &index_key).await
        }
        _ => None,
    };
    let index = match fresh {
        Some(doc) => Some(doc),
        None => {
            match fetch_registration_doc(state, &index_key, &format!("{id}/index.json")).await {
                Some(doc) => Some(doc),
                None => read_json(&state.storage, &index_key).await,
            }
        }
    };
    let Some(pages) = index
        .as_ref()
        .and_then(|d| d.get("items")?.as_array().cloned())
    else {
        return HashSet::new();
    };
    let skip = if last_page_only {
        pages.len().saturating_sub(1)
    } else {
        0
    };
    let docs = futures::future::join_all(pages.into_iter().skip(skip).map(|page| async move {
        if page.get("items").is_some() {
            return Some(page);
        }
        let bound = |k: &str| {
            page.get(k)
                .and_then(|v| v.as_str())
                .map(str::to_lowercase)
                .filter(|v| is_valid_version(v))
        };
        let (lower, upper) = (bound("lower")?, bound("upper")?);
        let key = registration_page_key(id, &lower, &upper);
        match read_json(&state.storage, &key).await {
            Some(doc) => Some(doc),
            None => {
                fetch_registration_doc(state, &key, &format!("{id}/page/{lower}/{upper}.json"))
                    .await
            }
        }
    }))
    .await;
    let leaves = docs
        .iter()
        .flatten()
        .filter_map(|d| d.get("items")?.as_array())
        .flatten();
    // ponytail: unbounded join; only undated leaves committed within min_release_age
    // fetch (once each), a semaphore if an upstream without commitTimeStamp shows up.
    futures::future::join_all(leaves.map(|leaf| leaf_hidden(state, id, leaf)))
        .await
        .into_iter()
        .flatten()
        .collect()
}

/// Whether a proxied ID's metadata goes through the Q04 filter at all.
async fn filters_metadata(state: &AppState, id_lower: &str) -> bool {
    let curation = state.curation();
    let engine = &curation.curation_engine;
    engine.metadata_filter_active()
        && is_valid_package_id(id_lower)
        && !crate::curation::is_internal_namespace(engine, RegistryType::Nuget, id_lower)
        && hosted::is_proxied(state, id_lower).await
}

/// Remove `hidden` (lowercase) from a JSON string array at `field`.
fn drop_versions(body: &[u8], field: &str, hidden: &HashSet<String>) -> Option<Vec<u8>> {
    if hidden.is_empty() {
        return None;
    }
    let mut doc: serde_json::Value = serde_json::from_slice(body).ok()?;
    let list = doc.get_mut(field)?.as_array_mut()?;
    let before = list.len();
    list.retain(|v| {
        v.as_str()
            .is_none_or(|v| !hidden.contains(&v.to_lowercase()))
    });
    (list.len() != before)
        .then(|| serde_json::to_vec(&doc).ok())
        .flatten()
}

async fn registration_index_filtered(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let id_lower = id.to_lowercase();
    let resp = registration_index(State(state.clone()), headers, Path(id)).await;
    if resp.status() != StatusCode::OK || !filters_metadata(&state, &id_lower).await {
        return resp;
    }
    let hidden = hidden_versions(&state, &id_lower, false).await;
    crate::metadata_filter::rewrite_body(resp, |b| filter_registration(&hidden, b)).await
}

async fn registration_page_filtered(
    State(state): State<AppState>,
    Path((id, lower, upper)): Path<(String, String, String)>,
) -> Response {
    let id_lower = id.to_lowercase();
    let resp = registration_page(State(state.clone()), Path((id, lower, upper))).await;
    if resp.status() != StatusCode::OK || !filters_metadata(&state, &id_lower).await {
        return resp;
    }
    let hidden = hidden_versions(&state, &id_lower, false).await;
    crate::metadata_filter::rewrite_body(resp, |b| filter_registration(&hidden, b)).await
}

/// Flat-container `index.json` — what `dotnet restore` resolves ranges against.
async fn version_list_filtered(state: AppState, id: &str) -> Response {
    let id_lower = id.to_lowercase();
    let resp = version_list(state.clone(), id).await;
    if resp.status() != StatusCode::OK || !filters_metadata(&state, &id_lower).await {
        return resp;
    }
    let hidden = hidden_versions(&state, &id_lower, false).await;
    crate::metadata_filter::rewrite_body(resp, |b| drop_versions(b, "versions", &hidden)).await
}

/// Autocomplete `?id=` lists one package's versions in `data`.
async fn filter_autocomplete_versions(state: &AppState, id: &str, body: String) -> Vec<u8> {
    let id_lower = id.to_lowercase();
    if !filters_metadata(state, &id_lower).await {
        return body.into_bytes();
    }
    let hidden = hidden_versions(state, &id_lower, false).await;
    drop_versions(body.as_bytes(), "data", &hidden).unwrap_or_else(|| body.into_bytes())
}

/// Search results: per hit, drop hidden entries from `versions` and move `version`
/// to the newest one left (a hit with none left is dropped).
async fn filter_search_results(state: &AppState, body: String) -> Vec<u8> {
    if !state.curation().curation_engine.metadata_filter_active() {
        return body.into_bytes();
    }
    let Ok(mut doc) = serde_json::from_str::<serde_json::Value>(&body) else {
        return body.into_bytes();
    };
    let Some(hits) = doc.get_mut("data").and_then(|d| d.as_array_mut()) else {
        return body.into_bytes();
    };
    let ids: Vec<String> = hits
        .iter()
        .map(|h| {
            h.get("id")
                .and_then(|i| i.as_str())
                .unwrap_or("")
                .to_lowercase()
        })
        .collect();
    let hidden = futures::future::join_all(ids.iter().map(|id| async move {
        if filters_metadata(state, id).await {
            hidden_versions(state, id, true).await
        } else {
            Arc::default()
        }
    }))
    .await;
    let mut changed = false;
    let mut keep = Vec::with_capacity(hits.len());
    for (hit, hidden) in hits.iter_mut().zip(&hidden) {
        if hidden.is_empty() {
            keep.push(true);
            continue;
        }
        changed = true;
        let Some(versions) = hit.get_mut("versions").and_then(|v| v.as_array_mut()) else {
            keep.push(true);
            continue;
        };
        versions.retain(|v| {
            v.get("version")
                .and_then(|v| v.as_str())
                .is_none_or(|v| !hidden.contains(&v.to_lowercase()))
        });
        let newest = versions
            .iter()
            .filter_map(|v| v.get("version")?.as_str())
            .max_by(|a, b| hosted::compare_versions(&a.to_lowercase(), &b.to_lowercase()))
            .map(str::to_string);
        keep.push(newest.is_some());
        if let Some(newest) = newest {
            hit["version"] = serde_json::Value::String(newest);
        }
    }
    if !changed {
        return body.into_bytes();
    }
    let mut flags = keep.into_iter();
    hits.retain(|_| flags.next().unwrap_or(true));
    serde_json::to_vec(&doc).unwrap_or_else(|_| body.into_bytes())
}

/// The configured upstream (`scheme://authority`), or None when the operator switched it off with
/// an empty NORA_NUGET_PROXY: then nothing is asked of any upstream.
fn upstream_url(state: &AppState) -> Option<String> {
    crate::config::configured_upstream(&state.config.nuget.proxy).map(strip_url_path)
}

/// The host stored registration bodies are rewritten from: the configured upstream, else the
/// default one a cached body may still name.
fn rewrite_host(state: &AppState) -> String {
    upstream_url(state).unwrap_or_else(|| UPSTREAM_DEFAULT.to_string())
}

/// Keep only `scheme://authority` from a URL, stripping path/query/fragment.
///
/// Callers append their own paths (e.g. `/v3-flatcontainer/`, `/v3/registration5-gz-semver2/`),
/// so the path component (e.g. `/v3/index.json`) must be stripped.
fn strip_url_path(url: &str) -> String {
    if let Some(idx) = url.find("://") {
        let after_scheme = &url[idx + 3..];
        let authority_end = after_scheme.find('/').unwrap_or(after_scheme.len());
        url[..idx + 3 + authority_end].to_string()
    } else {
        url.to_string()
    }
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

/// Build a gzip-compressed JSON response for registration endpoints.
///
/// The service index advertises `RegistrationsBaseUrl/3.6.0`, which per NuGet spec
/// means responses are gzip-encoded.  Falls back to plain JSON if compression fails.
fn with_json_gzip(data: Vec<u8>) -> Response {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    match std::io::Write::write_all(&mut encoder, &data).and_then(|_| encoder.finish()) {
        Ok(compressed) => (
            StatusCode::OK,
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                ),
                (header::CONTENT_ENCODING, HeaderValue::from_static("gzip")),
                (
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("public, max-age=60, must-revalidate"),
                ),
            ],
            compressed,
        )
            .into_response(),
        Err(_) => with_json(data), // fallback: plain JSON if gzip fails
    }
}

/// JSON response with `X-Nora-Stale: true` header indicating degraded/fallback data.
fn with_json_stale(data: Vec<u8>) -> Response {
    (
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
        data,
    )
        .into_response()
}
// ── Local search helpers ───────────────────────────────────────────────

/// Read cached version list from flatcontainer index.json.
async fn get_cached_versions(storage: &crate::storage::Storage, id: &str) -> Vec<String> {
    let key = format!("nuget/flatcontainer/{}/index.json", id.to_lowercase());
    let data = match storage.get(&key).await {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let json: serde_json::Value = match serde_json::from_slice(&data) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    json.get("versions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// Build one NuGet V3 search result entry.
fn build_search_entry(
    base_url: &str,
    pkg: &crate::repo_index::RepoInfo,
    versions: &[String],
) -> serde_json::Value {
    let nora_nuget = format!("{}/nuget", base_url.trim_end_matches('/'));
    let id = &pkg.name;
    let latest = versions.last().map(|s| s.as_str()).unwrap_or("0.0.0");

    let version_entries: Vec<serde_json::Value> = versions
        .iter()
        .map(|v| {
            serde_json::json!({
                "version": v,
                "downloads": 0,
                "@id": format!("{}/v3/registration/{}/{}.json", nora_nuget, id.to_lowercase(), v)
            })
        })
        .collect();

    serde_json::json!({
        "id": id,
        "version": latest,
        "versions": version_entries,
        "description": "",
        "totalDownloads": 0,
        "packageTypes": [{"name": "Dependency"}],
        "registration": format!("{}/v3/registration/{}/index.json", nora_nuget, id.to_lowercase())
    })
}

/// Build local search results from the in-memory repo index.
///
/// When `prerelease` is false, versions containing a hyphen (SemVer pre-release)
/// are excluded. When `sem_ver_level` is not `"2.0.0"`, SemVer 2.0 versions
/// (dot-separated pre-release or build metadata) are hidden.
/// Packages with zero remaining versions are omitted entirely.
async fn local_search_results(
    state: &AppState,
    query: &str,
    skip: usize,
    take: usize,
    prerelease: bool,
    sem_ver_level: Option<&str>,
) -> Vec<u8> {
    let packages = state.repo_index.get("nuget", state).await;
    let base_url = nora_base_url(state);

    let query_lower = query.to_lowercase();
    let filtered: Vec<&crate::repo_index::RepoInfo> = packages
        .iter()
        .filter(|pkg| query_lower.is_empty() || pkg.name.to_lowercase().contains(&query_lower))
        .collect();

    let mut data = Vec::new();
    for pkg in &filtered {
        let all_versions = get_cached_versions(&state.storage, &pkg.name).await;
        let versions: Vec<String> = if prerelease {
            all_versions
        } else {
            all_versions
                .into_iter()
                .filter(|v| !v.contains('-'))
                .collect()
        };
        // Hide SemVer 2.0 versions unless semVerLevel=2.0.0
        let versions: Vec<String> = if sem_ver_level == Some("2.0.0") {
            versions
        } else {
            versions
                .into_iter()
                .filter(|v| !is_semver2_version(v))
                .collect()
        };
        if versions.is_empty() {
            continue;
        }
        data.push(build_search_entry(&base_url, pkg, &versions));
    }

    let total_hits = data.len();
    let page: Vec<serde_json::Value> = data.into_iter().skip(skip).take(take).collect();

    let result = serde_json::json!({
        "totalHits": total_hits,
        "data": page,
    });
    serde_json::to_vec(&result).unwrap_or_else(|_| br#"{"totalHits":0,"data":[]}"#.to_vec())
}

/// Build local autocomplete results from the in-memory repo index.
/// Returns package name strings (not full search objects) per NuGet autocomplete spec.
///
/// When `prerelease` is false, packages that have only pre-release versions are omitted.
/// When `sem_ver_level` is not `"2.0.0"`, packages with only SemVer 2.0 versions are hidden.
async fn local_autocomplete_results(
    state: &AppState,
    query: &str,
    skip: usize,
    take: usize,
    prerelease: bool,
    sem_ver_level: Option<&str>,
) -> Vec<u8> {
    let packages = state.repo_index.get("nuget", state).await;

    let query_lower = query.to_lowercase();
    let mut matched: Vec<&str> = Vec::new();
    for pkg in packages.iter() {
        if !query_lower.is_empty() && !pkg.name.to_lowercase().contains(&query_lower) {
            continue;
        }
        let versions = get_cached_versions(&state.storage, &pkg.name).await;
        // Apply prerelease filter
        let versions: Vec<&String> = if prerelease {
            versions.iter().collect()
        } else {
            versions.iter().filter(|v| !v.contains('-')).collect()
        };
        // Apply SemVer 2.0 filter
        let versions: Vec<&&String> = if sem_ver_level == Some("2.0.0") {
            versions.iter().collect()
        } else {
            versions.iter().filter(|v| !is_semver2_version(v)).collect()
        };
        if versions.is_empty() {
            continue;
        }
        matched.push(pkg.name.as_str());
    }

    let total_hits = matched.len();
    let names: Vec<&str> = matched.into_iter().skip(skip).take(take).collect();

    let result = serde_json::json!({
        "totalHits": total_hits,
        "data": names,
    });
    serde_json::to_vec(&result).unwrap_or_else(|_| br#"{"totalHits":0,"data":[]}"#.to_vec())
}

/// Generate NuGet v3 service index from scratch, advertising only resources
/// that NORA actually implements. This is the fail-closed approach: clients
/// only see resources with real handlers behind them. (#404)
///
/// `base_url` is the full NORA base URL including scheme (e.g. `https://artifact.company.local`).
fn generate_service_index(base_url: &str) -> String {
    let nora_nuget = format!("{}/nuget", base_url.trim_end_matches('/'));
    let query = format!("{}/v3/query", nora_nuget);
    let autocomplete = format!("{}/v3/autocomplete", nora_nuget);

    let mut resources = vec![
        serde_json::json!({
            "@id": format!("{}/v3/flatcontainer/", nora_nuget),
            "@type": "PackageBaseAddress/3.0.0",
            "comment": "Base URL of NuGet package storage"
        }),
        serde_json::json!({
            "@id": format!("{}/v3/registration/", nora_nuget),
            "@type": "RegistrationsBaseUrl/3.6.0",
            "comment": "Base URL of NuGet package registration info"
        }),
        serde_json::json!({
            "@id": format!("{}/v3/package", nora_nuget),
            "@type": "PackagePublish/2.0.0",
            "comment": "Push, unlist (DELETE) and relist (POST) hosted packages"
        }),
    ];
    // Same @type set as api.nuget.org. The NuGet client resolves search only via
    // `/Versioned`, `/3.4.0` or `/3.0.0-beta` (autocomplete: `/Versioned`, `/3.0.0-beta`):
    // the bare and `/3.5.0` types alone make `dotnet package search` report
    // "The source does not have a Search service!".
    for version in ["", "/3.0.0-beta", "/3.0.0-rc", "/3.5.0"] {
        resources.push(serde_json::json!({
            "@id": query,
            "@type": format!("SearchQueryService{version}"),
            "comment": "NuGet search endpoint (hosted packages first)"
        }));
        resources.push(serde_json::json!({
            "@id": autocomplete,
            "@type": format!("SearchAutocompleteService{version}"),
            "comment": "NuGet autocomplete endpoint"
        }));
    }

    let index = serde_json::json!({ "version": "3.0.0", "resources": resources });
    serde_json::to_string_pretty(&index).expect("static JSON serialization cannot fail")
}

/// Catch-all handler for unhandled NuGet v3 resource paths.
/// Returns 404 with diagnostic logging so operators can see which resources
/// clients are requesting that NORA doesn't implement yet. (#404)
async fn nuget_catchall(Path(path): Path<String>) -> Response {
    tracing::debug!(path = %path, "NuGet: unhandled resource requested");
    StatusCode::NOT_FOUND.into_response()
}

/// Rewrite upstream registration URLs in NuGet registration index/page responses.
/// Replaces all registration5-* variants with NORA registration path,
/// and v3-flatcontainer packageContent URLs with NORA flatcontainer path.
fn rewrite_registration_urls(json_text: &str, upstream_url: &str, base_url: &str) -> String {
    let upstream = upstream_url.trim_end_matches('/');
    let nora_nuget = format!("{}/nuget", base_url.trim_end_matches('/'));
    let nora_reg = format!("{}/v3/registration/", nora_nuget);

    // Rewrite registration and flatcontainer URLs to point to Nora.
    // UPSTREAM_PASSTHROUGH_PATHS (catalog0, catalogEntry.@id) are intentionally left
    // as-is: Nora has no catalog handler, and NuGet clients do not fetch these during
    // restore. Rewriting them would produce Nora URLs that 404.
    // Each mapping is escape-aware (plain + `\/`-escaped) so a slash-escaped upstream
    // registration/flatcontainer URL cannot survive and leak the host — sending the
    // client back to the origin, past Nora — after the client unescapes `\/` (#385).
    use super::replace_url_escape_aware as rw;
    let s = rw(
        json_text,
        &format!("{}/v3/registration5-semver1/", upstream),
        &nora_reg,
    );
    let s = rw(
        &s,
        &format!("{}/v3/registration5-gz-semver1/", upstream),
        &nora_reg,
    );
    let s = rw(
        &s,
        &format!("{}/v3/registration5-gz-semver2/", upstream),
        &nora_reg,
    );
    rw(
        &s,
        &format!("{}/v3-flatcontainer/", upstream),
        &format!("{}/v3/flatcontainer/", nora_nuget),
    )
}

/// Validate NuGet version string for use in URL path construction.
/// Allows: digits, dots, hyphens, plus, alphanumeric (SemVer 2.0 compatible).
fn is_valid_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 256
        && !version.contains('/')
        && !version.contains('\\')
        && !version.contains('\0')
        && !version.contains("..")
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '+')
}

fn is_valid_package_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 256
        && !id.contains('/')
        && !id.contains('\0')
        && !id.contains("..")
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

/// Check if a version string uses SemVer 2.0.0 features.
///
/// SemVer 2.0 = dot-separated pre-release identifiers (`1.0.0-rc.1`)
/// OR build metadata (`1.0.0+build`).  NuGet V3 search/autocomplete hides
/// such versions unless `semVerLevel=2.0.0` is passed.
fn is_semver2_version(version: &str) -> bool {
    if version.contains('+') {
        return true;
    }
    if let Some(idx) = version.find('-') {
        return version[idx + 1..].contains('.');
    }
    false
}

fn is_safe_path(path: &str) -> bool {
    !path.contains("..")
        && !path.starts_with('/')
        && !path.contains("//")
        && !path.contains('\0')
        && !path.is_empty()
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// #385: a slash-escaped upstream registration URL must not survive the
    /// raw-text rewrite — otherwise the client, after unescaping `\/`, is sent
    /// back to the origin past Nora (host leak + air-gap bypass).
    #[test]
    fn rewrite_nuget_registration_drops_upstream_host_plain_and_escaped() {
        const HOST: &str = "api.nuget.org";
        let upstream = "https://api.nuget.org";
        let base = "http://nora.test";

        let plain = rewrite_registration_urls(
            r#"{"@id":"https://api.nuget.org/v3/registration5-semver1/pkg/index.json"}"#,
            upstream,
            base,
        );
        assert!(
            !plain.contains(HOST),
            "plain registration host leaked: {plain}"
        );

        let escaped = rewrite_registration_urls(
            r#"{"@id":"https:\/\/api.nuget.org\/v3\/registration5-semver1\/pkg\/index.json"}"#,
            upstream,
            base,
        );
        assert!(
            !escaped.contains(HOST),
            "slash-escaped registration host leaked (#385): {escaped}"
        );
    }

    #[test]
    fn test_valid_package_ids() {
        assert!(is_valid_package_id("newtonsoft.json"));
        assert!(is_valid_package_id("system.text.json"));
        assert!(is_valid_package_id("microsoft.extensions.logging"));
        assert!(is_valid_package_id("xunit"));
    }

    #[test]
    fn test_invalid_package_ids() {
        assert!(!is_valid_package_id(""));
        assert!(!is_valid_package_id("../evil"));
        assert!(!is_valid_package_id("foo/bar"));
    }

    #[test]
    fn test_strip_url_path_with_index_json() {
        assert_eq!(
            strip_url_path("https://api.nuget.org/v3/index.json"),
            "https://api.nuget.org"
        );
    }

    #[test]
    fn test_strip_url_path_no_path() {
        assert_eq!(
            strip_url_path("https://api.nuget.org"),
            "https://api.nuget.org"
        );
    }

    #[test]
    fn test_strip_url_path_trailing_slash() {
        assert_eq!(
            strip_url_path("https://api.nuget.org/"),
            "https://api.nuget.org"
        );
    }

    #[test]
    fn test_strip_url_path_custom_port() {
        assert_eq!(
            strip_url_path("https://artifact.company.local:8443/nuget/v3/index.json"),
            "https://artifact.company.local:8443"
        );
    }

    #[test]
    fn test_strip_url_path_http() {
        assert_eq!(
            strip_url_path("http://localhost:4000/nuget/v3/index.json"),
            "http://localhost:4000"
        );
    }

    #[test]
    fn test_generate_service_index_http() {
        let result = generate_service_index("http://nora:4000");
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["version"], "3.0.0");
        let resources = json["resources"].as_array().unwrap();
        assert_eq!(resources.len(), 11);
        assert!(result.contains("http://nora:4000/nuget/v3/flatcontainer/"));
        assert!(result.contains("http://nora:4000/nuget/v3/registration/"));
        assert!(result.contains("http://nora:4000/nuget/v3/query"));
        assert!(result.contains("http://nora:4000/nuget/v3/autocomplete"));
    }

    #[test]
    fn test_generate_service_index_https() {
        let result = generate_service_index("https://artifact.company.local");
        assert!(result.contains("https://artifact.company.local/nuget/v3/flatcontainer/"));
        assert!(result.contains("https://artifact.company.local/nuget/v3/registration/"));
        assert!(!result.contains("http://artifact.company.local"));
    }

    #[test]
    fn test_generate_service_index_no_upstream_urls() {
        let result = generate_service_index("http://nora:4000");
        assert!(!result.contains("api.nuget.org"));
        assert!(!result.contains("azuresearch-usnc.nuget.org"));
        assert!(!result.contains("azuresearch-ussc.nuget.org"));
        assert!(!result.contains("www.nuget.org"));
        assert!(!result.contains("nuget.org"));
    }

    #[test]
    fn test_generate_service_index_only_implemented_resources() {
        let result = generate_service_index("http://nora:4000");
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        let types: Vec<&str> = json["resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["@type"].as_str().unwrap())
            .collect();
        assert!(types.contains(&"PackageBaseAddress/3.0.0"));
        assert!(types.contains(&"RegistrationsBaseUrl/3.6.0"));
        assert!(types.contains(&"SearchQueryService"));
        assert!(types.contains(&"SearchAutocompleteService"));
        assert!(types.contains(&"SearchQueryService/3.5.0"));
        assert!(types.contains(&"PackagePublish/2.0.0"));
        // Must NOT include unimplemented resources
        assert!(!types.iter().any(|t| t.contains("Catalog")));
        assert!(!types.iter().any(|t| t.contains("RepositorySignatures")));
        assert!(!types.iter().any(|t| t.contains("Vulnerability")));
    }

    #[test]
    fn test_generate_service_index_trailing_slash() {
        let result = generate_service_index("http://nora:4000/");
        // Should not produce double slashes
        assert!(!result.contains("http://nora:4000//"));
        assert!(result.contains("http://nora:4000/nuget/v3/flatcontainer/"));
    }

    #[test]
    fn test_rewrite_registration_urls_all_variants() {
        let input = r#"{"items":[{"@id":"https://api.nuget.org/v3/registration5-gz-semver2/foo/page/1.0.0/2.0.0.json"},{"@id":"https://api.nuget.org/v3/registration5-semver1/foo/index.json"},{"@id":"https://api.nuget.org/v3/registration5-gz-semver1/foo/page/1.0.0/2.0.0.json"}]}"#;
        let result = rewrite_registration_urls(input, "https://api.nuget.org", "http://nora:4000");
        assert!(!result.contains("api.nuget.org"));
        assert!(result.contains("http://nora:4000/nuget/v3/registration/foo/page/1.0.0/2.0.0.json"));
        assert!(result.contains("http://nora:4000/nuget/v3/registration/foo/index.json"));
    }

    #[test]
    fn test_rewrite_registration_urls_rewrites_flatcontainer() {
        let input = r#"{"packageContent":"https://api.nuget.org/v3-flatcontainer/foo/1.0.0/foo.1.0.0.nupkg"}"#;
        let result = rewrite_registration_urls(input, "https://api.nuget.org", "http://nora:4000");
        assert!(!result.contains("api.nuget.org/v3-flatcontainer"));
        assert!(
            result.contains("http://nora:4000/nuget/v3/flatcontainer/foo/1.0.0/foo.1.0.0.nupkg")
        );
    }

    #[test]
    fn test_rewrite_registration_urls_custom_upstream() {
        let input =
            r#"{"@id":"https://private.registry.corp/v3/registration5-gz-semver2/bar/index.json"}"#;
        let result =
            rewrite_registration_urls(input, "https://private.registry.corp", "http://nora:4000");
        assert!(!result.contains("private.registry.corp"));
        assert!(result.contains("http://nora:4000/nuget/v3/registration/bar/index.json"));
    }

    /// Deprecation fields survive URL rewriting — catalog0 @ids left as-is (#424)
    #[test]
    fn test_rewrite_preserves_deprecation_field() {
        let input = r#"{"items":[{"catalogEntry":{"@id":"https://api.nuget.org/v3/catalog0/data/2024.09.20/ef.4.1.json","version":"4.1.10311","deprecation":{"@id":"https://api.nuget.org/v3/catalog0/data/2024.09.20/ef.4.1.json#deprecation","@type":"deprecation","alternatePackage":{"@id":"https://api.nuget.org/v3/catalog0/data/2024.09.20/ef.4.1.json#deprecation/alternatePackage","@type":"alternatePackage","id":"EntityFramework","range":"[6.5.1, )"},"reasons":["Legacy"]},"packageContent":"https://api.nuget.org/v3-flatcontainer/entityframework/4.1.10311/entityframework.4.1.10311.nupkg"}}]}"#;
        let result = rewrite_registration_urls(input, "https://api.nuget.org", "http://nora:4000");
        // deprecation block preserved intact (catalog0 URLs stay as-is)
        assert!(result.contains(r#""deprecation":{""#));
        assert!(result.contains(r#""reasons":["Legacy"]"#));
        assert!(result.contains(r#""id":"EntityFramework""#));
        assert!(result.contains("https://api.nuget.org/v3/catalog0/data/2024.09.20"));
        assert!(!result.contains("nora:4000/nuget/v3/catalog0"));
        // packageContent rewritten to Nora
        assert!(result.contains("http://nora:4000/nuget/v3/flatcontainer/"));
    }

    /// Vulnerabilities array survives URL rewriting (#424)
    #[test]
    fn test_rewrite_preserves_vulnerabilities_field() {
        let input = r#"{"items":[{"catalogEntry":{"@id":"https://api.nuget.org/v3/catalog0/data/2024.01.01/log4net.1.2.10.json","version":"1.2.10","vulnerabilities":[{"advisoryUrl":"https://github.com/advisories/GHSA-2cwj-8chv-9pp9","severity":"3"},{"advisoryUrl":"https://github.com/advisories/GHSA-4f7c-pmjv-c25w","severity":"1"}],"packageContent":"https://api.nuget.org/v3-flatcontainer/log4net/1.2.10/log4net.1.2.10.nupkg"}}]}"#;
        let result = rewrite_registration_urls(input, "https://api.nuget.org", "http://nora:4000");
        // vulnerabilities array preserved intact (external advisory URLs, not upstream registry)
        assert!(result.contains(r#""vulnerabilities":[{"#));
        assert!(result.contains("GHSA-2cwj-8chv-9pp9"));
        assert!(result.contains("GHSA-4f7c-pmjv-c25w"));
        assert!(result.contains(r#""severity":"3""#));
        assert!(result.contains(r#""advisoryUrl":"https://github.com/advisories/"#));
        // packageContent rewritten to Nora
        assert!(result.contains("http://nora:4000/nuget/v3/flatcontainer/"));
    }

    #[test]
    fn test_valid_versions() {
        assert!(is_valid_version("1.0.0"));
        assert!(is_valid_version("1.0.0-alpha"));
        assert!(is_valid_version("1.0.0-beta.1"));
        assert!(is_valid_version("1.0.0+build.123"));
        assert!(is_valid_version("0.0.1-alpha"));
        assert!(is_valid_version("3.1.27"));
    }

    #[test]
    fn test_invalid_versions() {
        assert!(!is_valid_version(""));
        assert!(!is_valid_version("../evil"));
        assert!(!is_valid_version("1.0.0/../../etc/passwd"));
        assert!(!is_valid_version("foo\0bar"));
        assert!(!is_valid_version("1..0"));
        assert!(!is_valid_version("1.0.0\\evil"));
    }

    #[test]
    fn test_is_semver2_version() {
        // SemVer 2.0: dot-separated pre-release identifiers
        assert!(is_semver2_version("1.0.0-rc.1"));
        assert!(is_semver2_version("9.0.0-rc.1.24431.7"));
        assert!(is_semver2_version("1.0.0-beta.2.3"));

        // SemVer 2.0: build metadata
        assert!(is_semver2_version("1.0.0+build"));
        assert!(is_semver2_version("1.0.0-alpha+001"));

        // SemVer 1.0: simple pre-release (no dots after hyphen)
        assert!(!is_semver2_version("1.0.0-alpha"));
        assert!(!is_semver2_version("1.0.0-beta1"));
        assert!(!is_semver2_version("2.0.0-preview"));

        // Stable versions: not SemVer 2.0
        assert!(!is_semver2_version("1.0.0"));
        assert!(!is_semver2_version("13.0.3"));
    }

    #[test]
    fn test_registration_returns_gzip_content_encoding() {
        let resp = with_json_gzip(br#"{"count":1}"#.to_vec());
        let (parts, body) = resp.into_parts();
        assert_eq!(parts.status, StatusCode::OK);
        assert_eq!(
            parts.headers.get("content-encoding").map(|v| v.as_bytes()),
            Some(b"gzip".as_slice()),
        );
        assert_eq!(
            parts.headers.get("content-type").map(|v| v.as_bytes()),
            Some(b"application/json".as_slice()),
        );

        // Decompress body and verify round-trip
        use axum::body::Body;
        use flate2::read::GzDecoder;
        use std::io::Read;

        let body_bytes =
            futures::executor::block_on(axum::body::to_bytes(Body::new(body), 1 << 20)).unwrap();
        let mut decoder = GzDecoder::new(&body_bytes[..]);
        let mut decompressed = String::new();
        decoder.read_to_string(&mut decompressed).unwrap();
        assert_eq!(decompressed, r#"{"count":1}"#);
    }

    #[test]
    fn test_service_index_no_gzip() {
        let resp = with_json(br#"{"version":"3.0.0"}"#.to_vec());
        let (parts, _body) = resp.into_parts();
        assert!(
            parts.headers.get("content-encoding").is_none(),
            "service index (with_json) must NOT have Content-Encoding header"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};

    /// A body of `len` bytes that is not one repeated byte (so a splice shows).
    fn big_body(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    /// C17: a .nupkg above `server.stream_threshold_mb` is spooled on a cold miss:
    /// six concurrent restores make one upstream fetch, all get the full package from
    /// the leader's spool file, and it lands in storage pinned to its digest.
    #[tokio::test]
    async fn test_large_cold_nupkg_is_spooled_and_shared() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let nupkg = big_body(3 * 1024 * 1024 + 17);
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(nupkg.clone())
                    .set_delay(std::time::Duration::from_millis(300)),
            )
            .mount(&upstream)
            .await;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some(upstream.uri());
            cfg.server.stream_threshold_mb = 1;
        });
        let uri = "/nuget/v3/flatcontainer/bigpkg/1.0.0/bigpkg.1.0.0.nupkg";
        let resps =
            futures::future::join_all((0..6).map(|_| send(&ctx.app, Method::GET, uri, ""))).await;
        for resp in resps {
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(
                resp.headers()["content-length"],
                nupkg.len().to_string().as_str()
            );
            assert!(body_bytes(resp).await[..] == nupkg[..]);
        }
        let fetches = upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path().ends_with(".nupkg"))
            .count();
        assert_eq!(fetches, 1);

        let key = "nuget/flatcontainer/bigpkg/1.0.0/bigpkg.1.0.0.nupkg";
        let want = {
            use sha2::Digest;
            hex::encode(sha2::Sha256::digest(&nupkg))
        };
        for _ in 0..100 {
            if ctx.state.storage.pin(key).await.as_deref() == Some(want.as_str()) {
                // Every holder dropped: the spool files are gone.
                let spool =
                    std::path::Path::new(&ctx.state.config.storage.path).join("tmp/proxy-spool");
                for _ in 0..100 {
                    if std::fs::read_dir(&spool).map_or(0, |d| d.count()) == 0 {
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                panic!("spool files left behind");
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("large nupkg was not cached with its pin");
    }

    /// C17: a cached .nupkg above the threshold streams from storage (no upstream),
    /// whole and with its length; a Range request on it is served from storage too.
    #[tokio::test]
    async fn test_large_cached_nupkg_streams() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some("http://127.0.0.1:1".into());
            cfg.server.stream_threshold_mb = 1;
        });
        let nupkg = big_body(2 * 1024 * 1024);
        let key = "nuget/flatcontainer/bighit/1.0.0/bighit.1.0.0.nupkg";
        ctx.state.storage.put(key, &nupkg).await.unwrap();
        let uri = "/nuget/v3/flatcontainer/bighit/1.0.0/bighit.1.0.0.nupkg";
        let resp = send(&ctx.app, Method::GET, uri, "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()["content-length"],
            nupkg.len().to_string().as_str()
        );
        assert!(body_bytes(resp).await[..] == nupkg[..]);

        let resp = crate::test_helpers::send_with_headers(
            &ctx.app,
            Method::GET,
            uri,
            vec![("range", "bytes=10-19")],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(&body_bytes(resp).await[..], &nupkg[10..20]);
    }

    /// C17 + C54: a streamed cache hit whose bytes no longer match the pin is cut off
    /// before the last frame (the client never gets a complete download), the bad
    /// copy is dropped, and the next request refetches and re-caches the package.
    #[tokio::test]
    async fn test_large_tampered_nupkg_aborts_then_self_heals() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let nupkg = big_body(2 * 1024 * 1024);
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(nupkg.clone()))
            .mount(&upstream)
            .await;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some(upstream.uri());
            cfg.server.stream_threshold_mb = 1;
        });
        let key = "nuget/flatcontainer/tamper/1.0.0/tamper.1.0.0.nupkg";
        ctx.state.storage.put(key, &nupkg).await.unwrap();
        // Corrupt the bytes at rest; the recorded pin stays.
        let mut bad = nupkg.clone();
        bad[1_500_000] ^= 0xff;
        std::fs::write(
            std::path::Path::new(&ctx.state.config.storage.path).join(key),
            &bad,
        )
        .unwrap();

        let uri = "/nuget/v3/flatcontainer/tamper/1.0.0/tamper.1.0.0.nupkg";
        let resp = send(&ctx.app, Method::GET, uri, "").await;
        assert_eq!(resp.status(), StatusCode::OK, "headers go out before EOF");
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await;
        assert!(body.is_err(), "a pin mismatch must abort the body");

        let mut healed = false;
        for _ in 0..100 {
            if ctx.state.storage.stat(key).await.is_none() {
                healed = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(healed, "the bad copy is dropped");
        let resp = send(&ctx.app, Method::GET, uri, "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_bytes(resp).await[..] == nupkg[..]);
        for _ in 0..100 {
            if let Ok(data) = ctx.state.storage.get(key).await {
                assert!(data[..] == nupkg[..]);
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("the refetched package was not re-cached");
    }

    /// C54: a small cached .nupkg failing its pin is refetched and the cache repaired
    /// (the immutable write used to skip the existing bad key forever).
    #[tokio::test]
    async fn test_tampered_cached_nupkg_is_repaired() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"good-nupkg".to_vec()))
            .mount(&upstream)
            .await;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some(upstream.uri());
        });
        let key = "nuget/flatcontainer/fixme/1.0.0/fixme.1.0.0.nupkg";
        ctx.state.storage.put(key, b"good-nupkg").await.unwrap();
        std::fs::write(
            std::path::Path::new(&ctx.state.config.storage.path).join(key),
            b"evil-nupkg",
        )
        .unwrap();

        let uri = "/nuget/v3/flatcontainer/fixme/1.0.0/fixme.1.0.0.nupkg";
        let resp = send(&ctx.app, Method::GET, uri, "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], b"good-nupkg");
        for _ in 0..100 {
            if let Ok(data) = ctx.state.storage.get(key).await {
                assert_eq!(&data[..], b"good-nupkg");
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("the cache was not repaired");
    }

    /// N concurrent restores of an uncached .nupkg: one upstream download, every
    /// client gets the package, and it is cached.
    #[tokio::test]
    async fn test_concurrent_cold_nupkg_misses_fetch_once() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(b"nupkg-bytes".to_vec())
                    .set_delay(std::time::Duration::from_millis(300)),
            )
            .mount(&upstream)
            .await;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some(upstream.uri());
        });
        let uri = "/nuget/v3/flatcontainer/coldpkg/1.0.0/coldpkg.1.0.0.nupkg";

        let resps =
            futures::future::join_all((0..6).map(|_| send(&ctx.app, Method::GET, uri, ""))).await;
        for resp in resps {
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(&body_bytes(resp).await[..], b"nupkg-bytes");
        }
        let nupkg_fetches = upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path().ends_with(".nupkg"))
            .count();
        assert_eq!(nupkg_fetches, 1);

        let key = "nuget/flatcontainer/coldpkg/1.0.0/coldpkg.1.0.0.nupkg";
        for _ in 0..50 {
            if ctx.state.storage.stat(key).await.is_some() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("nupkg was not cached");
    }

    /// C48: concurrent cold misses on the registration index, a registration page and
    /// the version list each make one upstream request; every client gets the body.
    #[tokio::test]
    async fn test_concurrent_cold_metadata_misses_fetch_once() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"versions":["1.0.0"],"items":[]}"#)
                    .set_delay(std::time::Duration::from_millis(300)),
            )
            .mount(&upstream)
            .await;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some(upstream.uri());
        });
        for (uri, upstream_suffix) in [
            (
                "/nuget/v3/registration/meta.pkg/index.json",
                "/registration5-gz-semver2/meta.pkg/index.json",
            ),
            (
                "/nuget/v3/registration/meta.pkg/page/1.0.0/2.0.0.json",
                "/registration5-gz-semver2/meta.pkg/page/1.0.0/2.0.0.json",
            ),
            (
                "/nuget/v3/flatcontainer/meta.pkg/index.json",
                "/v3-flatcontainer/meta.pkg/index.json",
            ),
        ] {
            let resps =
                futures::future::join_all((0..6).map(|_| send(&ctx.app, Method::GET, uri, "")))
                    .await;
            for resp in resps {
                assert_eq!(resp.status(), StatusCode::OK, "{uri}");
            }
            let fetches = upstream
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.url.path().ends_with(upstream_suffix))
                .count();
            assert_eq!(fetches, 1, "{uri}");
        }
    }

    /// `dotnet package search` resolves search only via `SearchQueryService/3.0.0-beta`
    /// (or `/3.4.0`, `/Versioned`); without it: "The source does not have a Search service!".
    #[tokio::test]
    async fn test_service_index_advertises_search_types_from_public_url() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.server.public_url = Some("https://packages.example.com/".to_string());
        });
        let resp = send(&ctx.app, Method::GET, "/nuget/v3/index.json", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        let ids: std::collections::HashMap<&str, &str> = json["resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (r["@type"].as_str().unwrap(), r["@id"].as_str().unwrap()))
            .collect();
        for v in ["", "/3.0.0-beta", "/3.0.0-rc", "/3.5.0"] {
            assert_eq!(
                ids.get(format!("SearchQueryService{v}").as_str()),
                Some(&"https://packages.example.com/nuget/v3/query"),
                "SearchQueryService{v}"
            );
            assert_eq!(
                ids.get(format!("SearchAutocompleteService{v}").as_str()),
                Some(&"https://packages.example.com/nuget/v3/autocomplete"),
                "SearchAutocompleteService{v}"
            );
        }
    }

    #[tokio::test]
    async fn test_nuget_disabled_returns_404() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = false;
        });
        let resp = send(&ctx.app, Method::GET, "/nuget/v3/index.json", "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_nuget_cached_nupkg() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
        });

        ctx.state
            .storage
            .put(
                "nuget/flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg",
                b"nupkg-data",
            )
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(&body[..], b"nupkg-data");
    }

    /// No cache + unreachable upstream → 502: an outage, not a missing package
    /// (a 404 is NU1101, which NuGet never retries).
    #[tokio::test]
    async fn test_nuget_unreachable_proxy() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.nuget.proxy_timeout = 1;
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/flatcontainer/test-package/index.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    /// Stale cache + unreachable upstream + serve_stale=true → 200 with X-Nora-Stale header (#409)
    #[tokio::test]
    async fn test_serve_stale_version_list() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.nuget.proxy_timeout = 1;
            cfg.nuget.metadata_ttl = 0; // force TTL expiry
            cfg.nuget.serve_stale = true;
        });
        // Seed cache
        let versions = br#"{"versions":["1.0.0","2.0.0"]}"#;
        ctx.state
            .storage
            .put("nuget/flatcontainer/test-package/index.json", versions)
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/flatcontainer/test-package/index.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("x-nora-stale").map(|v| v.as_bytes()),
            Some(b"true".as_slice())
        );
        let body = body_bytes(resp).await;
        assert!(body.starts_with(b"{\"versions\""));
    }

    /// Stale cache + unreachable upstream + serve_stale=false → 502, no stale body (#409)
    #[tokio::test]
    async fn test_serve_stale_disabled_returns_502() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.nuget.proxy_timeout = 1;
            cfg.nuget.metadata_ttl = 0;
            cfg.nuget.serve_stale = false;
        });
        // Seed cache
        ctx.state
            .storage
            .put(
                "nuget/flatcontainer/test-package/index.json",
                br#"{"versions":["1.0.0"]}"#,
            )
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/flatcontainer/test-package/index.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        assert!(resp.headers().get("x-nora-stale").is_none());
    }

    /// Uncached .nupkg + unreachable upstream → 502, which NuGet retries; a 404
    /// would be NU1101 "package not found", failing the restore outright.
    #[tokio::test]
    async fn test_uncached_nupkg_unreachable_upstream_returns_502() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.nuget.proxy_timeout = 1;
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/flatcontainer/nosuch-pkg/1.0.0/nosuch-pkg.1.0.0.nupkg",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    /// Stale registration index is served with URL rewriting (#409)
    #[tokio::test]
    async fn test_serve_stale_registration_index() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.nuget.proxy_timeout = 1;
            cfg.nuget.metadata_ttl = 0;
            cfg.nuget.serve_stale = true;
        });
        // Seed registration cache
        let reg_json =
            br#"{"items":[{"@id":"http://127.0.0.1:1/v3/registration/test-pkg/index.json"}]}"#;
        ctx.state
            .storage
            .put("nuget/registration/test-pkg/index.json", reg_json)
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/registration/test-pkg/index.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("x-nora-stale").map(|v| v.as_bytes()),
            Some(b"true".as_slice())
        );
    }

    /// A NuGet proxy whose upstream refuses connections: dates come from the cache only.
    fn date_ctx(trust: bool) -> crate::test_helpers::TestContext {
        create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.nuget.metadata_proxy_timeout = 1;
            cfg.server.trust_upstream_dates = trust;
        })
    }

    #[tokio::test]
    async fn test_nuget_publish_date_found() {
        let ctx = date_ctx(true);
        let storage = &ctx.state.storage;
        let meta = serde_json::json!({
            "items": [{
                "items": [{
                    "catalogEntry": {
                        "version": "6.0.0",
                        "published": "2023-11-14T10:30:00Z"
                    }
                }]
            }]
        });
        storage
            .put(
                "nuget/registration/newtonsoft.json/index.json",
                serde_json::to_vec(&meta).unwrap().as_slice(),
            )
            .await
            .unwrap();

        let result = super::nuget_publish_date(&ctx.state, "newtonsoft.json", "6.0.0").await;
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_nuget_publish_date_version_not_found() {
        let ctx = date_ctx(true);
        let storage = &ctx.state.storage;
        let meta = serde_json::json!({
            "items": [{"items": [{"catalogEntry": {"version": "1.0.0", "published": "2023-01-01T00:00:00Z"}}]}]
        });
        storage
            .put(
                "nuget/registration/test/index.json",
                serde_json::to_vec(&meta).unwrap().as_slice(),
            )
            .await
            .unwrap();

        let result = super::nuget_publish_date(&ctx.state, "test", "9.9.9").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_nuget_publish_date_no_metadata() {
        let ctx = date_ctx(true);

        let result = super::nuget_publish_date(&ctx.state, "nonexistent", "1.0.0").await;
        assert!(result.is_none());
    }

    /// Regression test for #535: pages without inline items must not abort
    /// date extraction for subsequent pages.
    #[tokio::test]
    async fn test_nuget_publish_date_sparse_pages() {
        let ctx = date_ctx(true);
        let storage = &ctx.state.storage;
        // Page 0: non-inline (only @id, no items array).
        // Page 1: inline with the target version.
        let meta = serde_json::json!({
            "items": [
                { "@id": "https://upstream/page/0" },
                {
                    "items": [{
                        "catalogEntry": {
                            "version": "2.0.0",
                            "published": "2024-06-15T12:00:00Z"
                        }
                    }]
                }
            ]
        });
        storage
            .put(
                "nuget/registration/sparse-pkg/index.json",
                serde_json::to_vec(&meta).unwrap().as_slice(),
            )
            .await
            .unwrap();

        // Before #535 fix: this returned None because page 0 had no "items".
        let result = super::nuget_publish_date(&ctx.state, "sparse-pkg", "2.0.0").await;
        assert!(result.is_some(), "date must be found despite sparse page 0");
    }

    /// ISO 8601 for `secs_ago` seconds before now.
    fn iso_ago(secs_ago: i64) -> String {
        (chrono::Utc::now() - chrono::Duration::seconds(secs_ago))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    }

    fn leaf(version: &str, published: &str) -> serde_json::Value {
        serde_json::json!({ "catalogEntry": { "version": version, "published": published } })
    }

    /// A proxy with a 7d cooldown in enforce mode, trusting upstream dates.
    async fn cooldown_upstream(
        trust: bool,
        allow: &[&str],
        quarantine: bool,
    ) -> (wiremock::MockServer, crate::test_helpers::TestContext) {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"\.nupkg$"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"nupkg".to_vec()))
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let allow: Vec<String> = allow.iter().map(|s| s.to_string()).collect();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some(uri);
            cfg.server.trust_upstream_dates = trust;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.min_release_age = Some("7d".to_string());
            cfg.curation.nuget.allow = allow;
            if quarantine {
                cfg.curation.quarantine = Some(crate::digest_quarantine::QuarantineMode::Enforce);
                cfg.curation.quarantine_ttl = Some("1d".to_string());
            }
        });
        (upstream, ctx)
    }

    async fn mount_json(upstream: &wiremock::MockServer, p: &str, body: serde_json::Value) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("GET"))
            .and(path(p))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(upstream)
            .await;
    }

    fn nupkg_uri(id: &str, ver: &str) -> String {
        format!("/nuget/v3/flatcontainer/{id}/{ver}/{id}.{ver}.nupkg")
    }

    /// Q01: a `dotnet restore`-shaped request order (flat-container `index.json`, then
    /// the `.nupkg`, no registration request) still dates the version from the inlined
    /// registration index: the young version is held, the old one is served.
    #[tokio::test]
    async fn test_flatcontainer_restore_enforces_cooldown_inlined_registration() {
        let (upstream, ctx) = cooldown_upstream(true, &[], false).await;
        mount_json(
            &upstream,
            "/v3-flatcontainer/fresh.pkg/index.json",
            serde_json::json!({ "versions": ["1.0.0", "2.0.0"] }),
        )
        .await;
        mount_json(
            &upstream,
            "/v3/registration5-gz-semver2/fresh.pkg/index.json",
            serde_json::json!({ "items": [{
                "lower": "1.0.0", "upper": "2.0.0",
                "items": [leaf("1.0.0", &iso_ago(30 * 86400)), leaf("2.0.0", &iso_ago(1800))]
            }] }),
        )
        .await;

        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/flatcontainer/fresh.pkg/index.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = send(&ctx.app, Method::GET, &nupkg_uri("fresh.pkg", "2.0.0"), "").await;
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "30-minute-old version must be held"
        );
        let resp = send(&ctx.app, Method::GET, &nupkg_uri("fresh.pkg", "1.0.0"), "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            ctx.state
                .storage
                .stat("nuget/registration/fresh.pkg/index.json")
                .await
                .is_some(),
            "the registration index must be cached for the next request"
        );
    }

    /// Q01: an ID with more than 128 versions has no inlined pages; the page covering
    /// the version is fetched (and cached) and dates it.
    #[tokio::test]
    async fn test_flatcontainer_restore_enforces_cooldown_paged_registration() {
        let (upstream, ctx) = cooldown_upstream(true, &[], false).await;
        let base = upstream.uri();
        mount_json(
            &upstream,
            "/v3/registration5-gz-semver2/big.pkg/index.json",
            serde_json::json!({ "count": 2, "items": [
                { "@id": format!("{base}/v3/registration5-gz-semver2/big.pkg/page/1.0.0/1.9.0.json"),
                  "count": 128, "lower": "1.0.0", "upper": "1.9.0" },
                { "@id": format!("{base}/v3/registration5-gz-semver2/big.pkg/page/2.0.0/3.0.0-beta.json"),
                  "count": 2, "lower": "2.0.0", "upper": "3.0.0-beta" }
            ] }),
        )
        .await;
        mount_json(
            &upstream,
            "/v3/registration5-gz-semver2/big.pkg/page/2.0.0/3.0.0-beta.json",
            serde_json::json!({ "lower": "2.0.0", "upper": "3.0.0-beta",
                "items": [leaf("2.0.0", &iso_ago(30 * 86400)), leaf("3.0.0-beta", &iso_ago(600))] }),
        )
        .await;

        let resp = send(
            &ctx.app,
            Method::GET,
            &nupkg_uri("big.pkg", "3.0.0-beta"),
            "",
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "10-minute-old version must be held"
        );
        let resp = send(&ctx.app, Method::GET, &nupkg_uri("big.pkg", "2.0.0"), "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let pages = upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path().contains("/page/"))
            .count();
        assert_eq!(
            pages, 1,
            "the page is fetched once, then read from the cache"
        );
        assert!(ctx
            .state
            .storage
            .stat("nuget/registration/big.pkg/page/2.0.0/3.0.0-beta.json")
            .await
            .is_some());
    }

    /// Q01: a cached index that predates the version is refetched, so a version
    /// published after the last metadata refresh is still dated (and held).
    #[tokio::test]
    async fn test_flatcontainer_refetches_registration_missing_the_version() {
        let (upstream, ctx) = cooldown_upstream(true, &[], false).await;
        let stale =
            serde_json::json!({ "items": [{ "items": [leaf("1.0.0", &iso_ago(30 * 86400))] }] });
        ctx.state
            .storage
            .put(
                "nuget/registration/late.pkg/index.json",
                stale.to_string().as_bytes(),
            )
            .await
            .unwrap();
        mount_json(
            &upstream,
            "/v3/registration5-gz-semver2/late.pkg/index.json",
            serde_json::json!({ "items": [{ "items": [
                leaf("1.0.0", &iso_ago(30 * 86400)), leaf("1.1.0", &iso_ago(60))
            ] }] }),
        )
        .await;
        let resp = send(&ctx.app, Method::GET, &nupkg_uri("late.pkg", "1.1.0"), "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// Q03: an allowlisted young version passes the cooldown; its neighbour does not.
    #[tokio::test]
    async fn test_flatcontainer_allowlisted_young_version_served() {
        let (upstream, ctx) = cooldown_upstream(true, &["Fresh.Pkg@2.0.0"], false).await;
        mount_json(
            &upstream,
            "/v3/registration5-gz-semver2/fresh.pkg/index.json",
            serde_json::json!({ "items": [{ "items": [
                leaf("2.0.0", &iso_ago(1800)), leaf("2.0.1", &iso_ago(1800))
            ] }] }),
        )
        .await;
        let resp = send(&ctx.app, Method::GET, &nupkg_uri("fresh.pkg", "2.0.0"), "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = send(&ctx.app, Method::GET, &nupkg_uri("fresh.pkg", "2.0.1"), "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// A prefix `allow` entry (`Microsoft.NETCore.*`, the .NET servicing case): every
    /// young version of every ID under it is listed in the flat `index.json` and
    /// served; a young version of an ID outside it stays hidden and held.
    #[tokio::test]
    async fn test_flatcontainer_allow_prefix_lists_and_serves_young_versions() {
        let (upstream, ctx) = cooldown_upstream(
            true,
            &["Microsoft.NETCore.*", "Microsoft.AspNetCore.*@*"],
            false,
        )
        .await;
        let ids = [
            "microsoft.netcore.app.runtime.linux-x64",
            "microsoft.aspnetcore.app.runtime.linux-x64",
            "microsoft.netcoreapp.other",
            "microsoft.extensions.logging",
        ];
        for id in ids {
            mount_json(
                &upstream,
                &format!("/v3-flatcontainer/{id}/index.json"),
                serde_json::json!({ "versions": ["10.0.12", "10.0.13"] }),
            )
            .await;
            mount_json(
                &upstream,
                &format!("/v3/registration5-gz-semver2/{id}/index.json"),
                serde_json::json!({ "items": [{ "lower": "10.0.12", "upper": "10.0.13", "items": [
                    leaf("10.0.12", &iso_ago(30 * 86400)), leaf("10.0.13", &iso_ago(19 * 3600))
                ] }] }),
            )
            .await;
        }
        let [netcore, aspnetcore, lookalike, other] = ids;
        for id in [netcore, aspnetcore] {
            assert_eq!(
                flat_versions(&ctx, id).await,
                serde_json::json!(["10.0.12", "10.0.13"]),
                "{id}: the young version stays listed"
            );
            let resp = send(&ctx.app, Method::GET, &nupkg_uri(id, "10.0.13"), "").await;
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "{id}: the young version is served"
            );
        }
        for id in [lookalike, other] {
            assert_eq!(
                flat_versions(&ctx, id).await,
                serde_json::json!(["10.0.12"]),
                "{id}: the young version stays hidden"
            );
            let resp = send(&ctx.app, Method::GET, &nupkg_uri(id, "10.0.13"), "").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{id}: held");
            let resp = send(&ctx.app, Method::GET, &nupkg_uri(id, "10.0.12"), "").await;
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "{id}: the old version is served"
            );
        }
    }

    /// A prefix `allow` entry never reaches an internal-namespace ID: it is not
    /// proxied at all, whatever its age.
    #[tokio::test]
    async fn test_allow_prefix_does_not_proxy_an_internal_namespace() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r".*"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"nupkg".to_vec()))
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some(uri);
            cfg.server.trust_upstream_dates = true;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.min_release_age = Some("7d".to_string());
            cfg.curation.internal_namespaces = vec!["corp.*".to_string()];
            cfg.curation.nuget.allow = vec!["Corp.*".to_string(), "corp.lib".to_string()];
        });
        let resp = send(&ctx.app, Method::GET, &nupkg_uri("corp.lib", "1.0.0"), "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/flatcontainer/corp.lib/index.json",
            "",
        )
        .await;
        assert_ne!(resp.status(), StatusCode::OK);
        assert!(
            upstream.received_requests().await.unwrap().is_empty(),
            "an internal ID is never asked upstream"
        );
    }

    /// An unlisted version is dated 1900-01-01 by NuGet: unknown, not ancient.
    #[test]
    fn test_unlisted_sentinel_date_is_unknown() {
        let date = |s: &str| super::nuget_date(Some(&serde_json::json!(s)));
        assert_eq!(date("1900-01-01T00:00:00+00:00"), None);
        assert_eq!(date("1949-12-31T23:59:59Z"), None);
        assert_eq!(date("not a date"), None);
        assert_eq!(super::nuget_date(None), None);
        assert_eq!(date("2026-10-12T03:21:10.437Z"), Some(1_791_775_270));
        let leaves = [leaf("1.0.0", "1900-01-01T00:00:00+00:00")];
        assert!(super::find_leaf(&leaves, "1.0.0").is_some());
        assert!(super::find_leaf(&leaves, "2.0.0").is_none());
    }

    /// A registration leaf of an unlisted version as nuget.org serves it
    /// (squil.sqlserver 1.0.0-beta.206, 12.10.2026): `published` 1900-01-01, the real
    /// date only in the catalog leaf at `catalogEntry.@id`.
    fn unlisted_leaf(base: &str, id: &str, version: &str, committed: &str) -> serde_json::Value {
        serde_json::json!({
            "@id": format!("{base}/v3/registration5-gz-semver2/{id}/{version}.json"),
            "@type": "Package",
            "commitId": "891f12ff-077f-4182-8232-37dfde0f100c",
            "commitTimeStamp": committed,
            "catalogEntry": {
                "@id": format!("{base}/v3/catalog0/data/2026.10.12.03.30.25/{id}.{version}.json"),
                "@type": "PackageDetails",
                "id": id,
                "listed": false,
                "published": "1900-01-01T00:00:00+00:00",
                "version": version
            },
            "packageContent": format!("{base}/v3-flatcontainer/{id}/{version}/{id}.{version}.nupkg")
        })
    }

    /// The catalog leaf of an unlisted version (the real document's date fields).
    fn catalog_leaf(id: &str, version: &str, created: &str) -> serde_json::Value {
        serde_json::json!({
            "@type": ["PackageDetails", "catalog:Permalink"],
            "catalog:commitId": "06705cfd-dce0-4e52-8dd0-0daf0abbc88b",
            "catalog:commitTimeStamp": iso_ago(3000),
            "created": created,
            "id": id,
            "lastEdited": iso_ago(3000),
            "listed": false,
            "published": "1900-01-01T00:00:00Z",
            "version": version
        })
    }

    /// `unl.pkg` on `upstream`, every version unlisted: 0.9.0 committed 30 days ago,
    /// 1.0.0 created 30 days ago and 2.0.0 an hour ago, both re-committed an hour ago.
    /// The catalog leaves are mounted when `leaves`.
    async fn mount_unlisted(upstream: &wiremock::MockServer, leaves: bool) {
        let base = upstream.uri();
        let reg = |v: &str, c: &str| unlisted_leaf(&base, "unl.pkg", v, c);
        mount_json(
            upstream,
            "/v3/registration5-gz-semver2/unl.pkg/index.json",
            serde_json::json!({ "items": [{ "items": [
                reg("0.9.0", &iso_ago(30 * 86400)),
                reg("1.0.0", &iso_ago(3600)),
                reg("2.0.0", &iso_ago(3600)),
            ] }] }),
        )
        .await;
        mount_json(
            upstream,
            "/v3-flatcontainer/unl.pkg/index.json",
            serde_json::json!({ "versions": ["0.9.0", "1.0.0", "2.0.0"] }),
        )
        .await;
        if leaves {
            for (v, created) in [("1.0.0", 30 * 86400), ("2.0.0", 3600)] {
                let path = format!("/v3/catalog0/data/2026.10.12.03.30.25/unl.pkg.{v}.json");
                mount_json(
                    upstream,
                    &path,
                    catalog_leaf("unl.pkg", v, &iso_ago(created)),
                )
                .await;
            }
        }
    }

    /// Upstream requests for `unl.pkg`'s catalog leaves, by version.
    async fn catalog_fetches(upstream: &wiremock::MockServer) -> super::HashMap<String, usize> {
        let mut by_version = super::HashMap::new();
        for r in upstream.received_requests().await.unwrap() {
            if let Some(leaf) = r.url.path().strip_prefix("/v3/catalog0/") {
                let v = leaf.trim_end_matches(".json").rsplit("unl.pkg.").next();
                *by_version.entry(v.unwrap().to_string()).or_default() += 1;
            }
        }
        by_version
    }

    /// Live on iota 12.10.2026: an unlisted version (dated 1900-01-01) passed the
    /// cooldown on both paths. It is dated from its catalog leaf: a young one is hidden
    /// and refused, an old one served; each leaf is fetched once, and none for a
    /// version whose registration commit is already past the cooldown.
    #[tokio::test]
    async fn test_unlisted_version_dated_from_catalog_leaf() {
        let (upstream, ctx) = cooldown_upstream(true, &[], false).await;
        mount_unlisted(&upstream, true).await;
        assert_eq!(
            flat_versions(&ctx, "unl.pkg").await,
            serde_json::json!(["0.9.0", "1.0.0"])
        );
        let doc = json_body(
            send(
                &ctx.app,
                Method::GET,
                "/nuget/v3/registration/unl.pkg/index.json",
                "",
            )
            .await,
        )
        .await;
        assert_eq!(leaf_versions(&doc["items"][0]["items"]), ["0.9.0", "1.0.0"]);
        for _ in 0..2 {
            for (v, status) in [
                ("0.9.0", StatusCode::OK),
                ("1.0.0", StatusCode::OK),
                ("2.0.0", StatusCode::FORBIDDEN),
            ] {
                let resp = send(&ctx.app, Method::GET, &nupkg_uri("unl.pkg", v), "").await;
                assert_eq!(resp.status(), status, "{v}");
            }
        }
        let fetches = catalog_fetches(&upstream).await;
        assert_eq!(fetches.get("1.0.0"), Some(&1), "{fetches:?}");
        assert_eq!(fetches.get("2.0.0"), Some(&1), "{fetches:?}");
        assert_eq!(fetches.get("0.9.0"), None, "{fetches:?}");
    }

    /// An unlisted version whose catalog leaf cannot be read: `curation.on_failure`
    /// decides, `closed` hides and refuses it, `open` serves it. The one dated by its
    /// old registration commit is served either way.
    #[tokio::test]
    async fn test_unlisted_version_without_catalog_leaf_follows_on_failure() {
        use crate::config::CurationOnFailure;
        for on_failure in [CurationOnFailure::Closed, CurationOnFailure::Open] {
            let (upstream, _) = cooldown_upstream(true, &[], false).await;
            mount_unlisted(&upstream, false).await;
            let (uri, mode) = (upstream.uri(), on_failure.clone());
            let ctx = create_test_context_with_config(move |cfg| {
                cfg.nuget.enabled = true;
                cfg.nuget.proxy = Some(uri);
                cfg.server.trust_upstream_dates = true;
                cfg.curation.mode = crate::config::CurationMode::Enforce;
                cfg.curation.min_release_age = Some("7d".to_string());
                cfg.curation.on_failure = mode;
            });
            let closed = on_failure == CurationOnFailure::Closed;
            let listed = if closed {
                serde_json::json!(["0.9.0"])
            } else {
                serde_json::json!(["0.9.0", "1.0.0", "2.0.0"])
            };
            assert_eq!(
                flat_versions(&ctx, "unl.pkg").await,
                listed,
                "{on_failure:?}"
            );
            for (v, status) in [
                ("0.9.0", StatusCode::OK),
                (
                    "1.0.0",
                    if closed {
                        StatusCode::FORBIDDEN
                    } else {
                        StatusCode::OK
                    },
                ),
            ] {
                let resp = send(&ctx.app, Method::GET, &nupkg_uri("unl.pkg", v), "").await;
                assert_eq!(resp.status(), status, "{on_failure:?} {v}");
            }
        }
    }

    /// C49: with `trust_upstream_dates = false` the cache mtime is no publish date:
    /// a freshly cached registration index yields no date at all.
    #[tokio::test]
    async fn test_nuget_publish_date_untrusted_ignores_mtime() {
        let untrusted = date_ctx(false);
        let storage = &untrusted.state.storage;
        let meta =
            serde_json::json!({ "items": [{ "items": [leaf("1.0.0", "2020-01-01T00:00:00Z")] }] });
        storage
            .put(
                "nuget/registration/pkg/index.json",
                meta.to_string().as_bytes(),
            )
            .await
            .unwrap();
        assert_eq!(
            super::nuget_publish_date(&untrusted.state, "pkg", "1.0.0").await,
            None
        );
        let trusted = crate::test_helpers::create_test_context_with_storage_and_config(
            storage.clone(),
            |cfg| {
                cfg.server.trust_upstream_dates = true;
            },
        );
        assert!(super::nuget_publish_date(&trusted.state, "pkg", "1.0.0")
            .await
            .is_some());
    }

    /// C49: untrusted dates + quarantine — an old cached registration index no longer
    /// seeds a new version's first-seen, so the quarantine holds it on nora's clock;
    /// and a just-refreshed index no longer makes min-release-age hold every version.
    #[tokio::test]
    async fn test_untrusted_dates_quarantine_uses_own_clock() {
        let (_upstream, ctx) = cooldown_upstream(false, &[], true).await;
        let index =
            serde_json::json!({ "items": [{ "items": [leaf("1.0.0", "2020-01-01T00:00:00Z")] }] });
        ctx.state
            .storage
            .put(
                "nuget/registration/q.pkg/index.json",
                index.to_string().as_bytes(),
            )
            .await
            .unwrap();
        let resp = send(&ctx.app, Method::GET, &nupkg_uri("q.pkg", "1.0.0"), "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(
            resp.headers().contains_key("x-nora-quarantine"),
            "held by the quarantine on nora's clock, not by min-release-age on a cache mtime"
        );
    }

    /// Body of a (possibly gzip-encoded) JSON response.
    async fn json_body(resp: axum::http::Response<axum::body::Body>) -> serde_json::Value {
        assert_eq!(resp.status(), StatusCode::OK);
        let gz = resp.headers().contains_key("content-encoding");
        let raw = body_bytes(resp).await;
        let mut out = Vec::new();
        if gz {
            std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&raw[..]), &mut out)
                .unwrap();
        } else {
            out = raw.to_vec();
        }
        serde_json::from_slice(&out).unwrap()
    }

    fn leaf_versions(leaves: &serde_json::Value) -> Vec<String> {
        leaves
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l["catalogEntry"]["version"].as_str().unwrap().to_string())
            .collect()
    }

    /// A paged registration (two non-inlined pages) for `big.pkg`, plus its flat index:
    /// 1.0.0 / 2.0.0 are old, 2.1.0 and 3.0.0-beta are young.
    async fn mount_paged(upstream: &wiremock::MockServer) {
        let base = upstream.uri();
        let reg = "/v3/registration5-gz-semver2/big.pkg";
        mount_json(
            upstream,
            &format!("{reg}/index.json"),
            serde_json::json!({ "count": 2, "items": [
                { "@id": format!("{base}{reg}/page/1.0.0/2.0.0.json"), "count": 2, "lower": "1.0.0", "upper": "2.0.0" },
                { "@id": format!("{base}{reg}/page/2.1.0/3.0.0-beta.json"), "count": 2, "lower": "2.1.0", "upper": "3.0.0-beta" }
            ] }),
        )
        .await;
        mount_json(
            upstream,
            &format!("{reg}/page/1.0.0/2.0.0.json"),
            serde_json::json!({ "count": 2, "lower": "1.0.0", "upper": "2.0.0",
                "items": [leaf("1.0.0", &iso_ago(90 * 86400)), leaf("2.0.0", &iso_ago(30 * 86400))] }),
        )
        .await;
        mount_json(
            upstream,
            &format!("{reg}/page/2.1.0/3.0.0-beta.json"),
            serde_json::json!({ "count": 2, "lower": "2.1.0", "upper": "3.0.0-beta",
                "items": [leaf("2.1.0", &iso_ago(3600)), leaf("3.0.0-beta", &iso_ago(600))] }),
        )
        .await;
        mount_json(
            upstream,
            "/v3-flatcontainer/big.pkg/index.json",
            serde_json::json!({ "versions": ["1.0.0", "2.0.0", "2.1.0", "3.0.0-beta"] }),
        )
        .await;
    }

    async fn flat_versions(ctx: &crate::test_helpers::TestContext, id: &str) -> serde_json::Value {
        let uri = format!("/nuget/v3/flatcontainer/{id}/index.json");
        json_body(send(&ctx.app, Method::GET, &uri, "").await).await["versions"].clone()
    }

    /// Storage `get`s of one warm `.nupkg` download (its second request).
    async fn nupkg_gets(
        ctx: &crate::test_helpers::TestContext,
        ops: &crate::test_helpers::OpCounts,
        uri: &str,
    ) -> usize {
        let _ = send(&ctx.app, Method::GET, uri, "").await;
        ops.reset();
        assert_eq!(
            send(&ctx.app, Method::GET, uri, "").await.status(),
            StatusCode::OK
        );
        ops.snapshot().get("get").copied().unwrap_or(0)
    }

    /// R2-43: dating a `.nupkg` (trusted upstream dates) reads each registration
    /// document once: the index, plus the page for a paged ID.
    #[tokio::test]
    async fn test_nupkg_download_reads_each_registration_doc_once() {
        use crate::test_helpers::{
            create_test_context_with_storage_and_config, op_counting_storage,
        };
        let (storage, ops) = op_counting_storage();
        let old = iso_ago(30 * 86400);
        let docs = [
            (
                "nuget/registration/dated.pkg/index.json",
                serde_json::json!({ "items": [{ "items": [leaf("1.0.0", &old)] }] }),
            ),
            (
                "nuget/registration/paged.pkg/index.json",
                serde_json::json!({ "items": [{ "lower": "1.0.0", "upper": "2.0.0" }] }),
            ),
            (
                "nuget/registration/paged.pkg/page/1.0.0/2.0.0.json",
                serde_json::json!({ "items": [leaf("1.0.0", &old)] }),
            ),
        ];
        for (key, doc) in docs {
            storage.put(key, doc.to_string().as_bytes()).await.unwrap();
        }
        for id in ["dated.pkg", "paged.pkg"] {
            let key = format!("nuget/flatcontainer/{id}/1.0.0/{id}.1.0.0.nupkg");
            storage.put(&key, b"nupkg").await.unwrap();
        }
        let ctx = |trust: bool| {
            create_test_context_with_storage_and_config(storage.clone(), move |cfg| {
                cfg.nuget.enabled = true;
                cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
                cfg.server.trust_upstream_dates = trust;
            })
        };
        let (plain, trusted) = (ctx(false), ctx(true));
        for (id, docs) in [("dated.pkg", 1), ("paged.pkg", 2)] {
            let uri = nupkg_uri(id, "1.0.0");
            let base = nupkg_gets(&plain, &ops, &uri).await;
            let dated = nupkg_gets(&trusted, &ops, &uri).await;
            assert_eq!(dated - base, docs, "{id}");
        }
    }

    /// R2-12: concurrent cold `.nupkg` downloads of one ID prime its registration with
    /// one upstream request (the proxy handlers' single-flight), and the prime stores
    /// the upstream validators with the body before the download answers.
    #[tokio::test]
    async fn test_registration_prime_is_single_flight_with_validators() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        let (upstream, ctx) = cooldown_upstream(true, &[], false).await;
        let index =
            serde_json::json!({ "items": [{ "items": [leaf("1.0.0", &iso_ago(30 * 86400))] }] });
        Mock::given(method("GET"))
            .and(path("/v3/registration5-gz-semver2/prime.pkg/index.json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"r1\"")
                    .set_body_json(index)
                    .set_delay(std::time::Duration::from_millis(300)),
            )
            .mount(&upstream)
            .await;
        let uri = nupkg_uri("prime.pkg", "1.0.0");
        let all =
            futures::future::join_all((0..4).map(|_| send(&ctx.app, Method::GET, &uri, ""))).await;
        assert!(all.iter().all(|r| r.status() == StatusCode::OK));
        let fetches = upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path().contains("/registration"))
            .count();
        assert_eq!(fetches, 1);
        let key = "nuget/registration/prime.pkg/index.json";
        let v = crate::registry::read_validators(&ctx.state.storage, key).await;
        assert_eq!(v.and_then(|v| v.etag).as_deref(), Some("\"r1\""));
    }

    /// R2-30/R2-37: the Q04 filter refreshes a stale registration index with a
    /// conditional request (304: only the sidecar is stamped, the body is not
    /// re-uploaded), under the handlers' single-flight.
    #[tokio::test]
    async fn test_q04_stale_registration_revalidates_once_conditionally() {
        use crate::registry::{validators_key, write_validators, Validators};
        use crate::test_helpers::{
            create_test_context_with_storage_and_config, op_counting_storage,
        };
        use wiremock::matchers::{header_exists, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let upstream = MockServer::start().await;
        let reg = "/v3/registration5-gz-semver2/small.pkg/index.json";
        Mock::given(method("GET"))
            .and(path(reg))
            .and(header_exists("if-none-match"))
            .respond_with(
                ResponseTemplate::new(304).set_delay(std::time::Duration::from_millis(300)),
            )
            .mount(&upstream)
            .await;
        mount_json(
            &upstream,
            "/v3-flatcontainer/small.pkg/index.json",
            serde_json::json!({ "versions": ["1.0.0", "1.1.0"] }),
        )
        .await;
        let (storage, ops) = op_counting_storage();
        let uri = upstream.uri();
        let ctx = create_test_context_with_storage_and_config(storage, move |cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some(uri);
            cfg.nuget.metadata_ttl = 0; // always stale, no memo
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.min_release_age = Some("7d".to_string());
        });
        let key = "nuget/registration/small.pkg/index.json";
        let index = serde_json::json!({ "items": [{ "items": [
            leaf("1.0.0", &iso_ago(30 * 86400)), leaf("1.1.0", &iso_ago(600))
        ] }] });
        let st = &ctx.state.storage;
        st.put(key, index.to_string().as_bytes()).await.unwrap();
        let v = Validators {
            etag: Some("\"r1\"".to_string()),
            last_modified: None,
        };
        write_validators(st, key, &v).await;
        ops.reset();

        let (a, b) = tokio::join!(
            flat_versions(&ctx, "small.pkg"),
            flat_versions(&ctx, "small.pkg")
        );
        assert_eq!(a, serde_json::json!(["1.0.0"]));
        assert_eq!(b, a);
        let reg_requests: Vec<_> = upstream
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.url.path() == reg)
            .collect();
        assert_eq!(reg_requests.len(), 1, "one flight for both requests");
        assert!(reg_requests[0].headers.contains_key("if-none-match"));
        let sidecar = st.get(&validators_key(key)).await.unwrap();
        assert!(String::from_utf8_lossy(&sidecar).contains("validated_at"));
        // Puts: the flat index (fetched once, coalesced) and the 304 stamp. Never the
        // registration body.
        assert_eq!(ops.snapshot().get("put"), Some(&2), "{:?}", ops.snapshot());
    }

    /// R2-30: within `metadata_ttl` a proxied ID's hidden versions are not recomputed
    /// per request: the second flat `index.json` reads no registration document.
    #[tokio::test]
    async fn test_q04_hidden_versions_memoized_within_ttl() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.nuget.metadata_proxy_timeout = 1;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.min_release_age = Some("7d".to_string());
        });
        let st = &ctx.state.storage;
        let reg = "nuget/registration/memo.pkg/index.json";
        let index = serde_json::json!({ "items": [{ "items": [
            leaf("1.0.0", &iso_ago(30 * 86400)), leaf("1.1.0", &iso_ago(600))
        ] }] });
        st.put(reg, index.to_string().as_bytes()).await.unwrap();
        st.put(
            "nuget/flatcontainer/memo.pkg/index.json",
            br#"{"versions":["1.0.0","1.1.0"]}"#,
        )
        .await
        .unwrap();
        assert_eq!(
            flat_versions(&ctx, "memo.pkg").await,
            serde_json::json!(["1.0.0"])
        );
        st.delete(reg).await.unwrap();
        assert_eq!(
            flat_versions(&ctx, "memo.pkg").await,
            serde_json::json!(["1.0.0"]),
            "served from the memo, not recomputed from the (now missing) registration"
        );
    }

    /// R2-46: a stale registration page is revalidated like the index: a conditional
    /// request, and on 304 only the sidecar is written.
    #[tokio::test]
    async fn test_registration_page_revalidates_with_304() {
        use crate::registry::{validators_key, write_validators, Validators};
        use crate::test_helpers::{
            create_test_context_with_storage_and_config, op_counting_storage,
        };
        use wiremock::matchers::{header_exists, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(header_exists("if-none-match"))
            .respond_with(ResponseTemplate::new(304))
            .mount(&upstream)
            .await;
        let (storage, ops) = op_counting_storage();
        let uri = upstream.uri();
        let ctx = create_test_context_with_storage_and_config(storage, move |cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some(uri);
            cfg.nuget.metadata_ttl = 0;
        });
        let key = "nuget/registration/pg.pkg/page/1.0.0/2.0.0.json";
        let page =
            serde_json::json!({ "count": 1, "items": [leaf("1.0.0", "2020-01-01T00:00:00Z")] });
        let st = &ctx.state.storage;
        st.put(key, page.to_string().as_bytes()).await.unwrap();
        let v = Validators {
            etag: Some("\"p1\"".to_string()),
            last_modified: None,
        };
        write_validators(st, key, &v).await;
        ops.reset();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/registration/pg.pkg/page/1.0.0/2.0.0.json",
            "",
        )
        .await;
        assert_eq!(json_body(resp).await["count"], 1);
        assert_eq!(upstream.received_requests().await.unwrap().len(), 1);
        let sidecar = st.get(&validators_key(key)).await.unwrap();
        assert!(String::from_utf8_lossy(&sidecar).contains("validated_at"));
        assert_eq!(ops.snapshot().get("put"), Some(&1), "{:?}", ops.snapshot());
    }

    /// Q04: `dotnet restore` resolves ranges against the flat-container version list:
    /// young versions are gone from it (dated through the paged registration), the
    /// registration page drops them too, and an allowlisted one stays.
    #[tokio::test]
    async fn test_q04_flat_index_and_pages_hide_young_versions() {
        let (upstream, ctx) = cooldown_upstream(true, &[], false).await;
        mount_paged(&upstream).await;
        assert_eq!(
            flat_versions(&ctx, "big.pkg").await,
            serde_json::json!(["1.0.0", "2.0.0"])
        );
        let page = json_body(
            send(
                &ctx.app,
                Method::GET,
                "/nuget/v3/registration/big.pkg/page/2.1.0/3.0.0-beta.json",
                "",
            )
            .await,
        )
        .await;
        assert_eq!(page["count"], 0);
        assert!(page["items"].as_array().unwrap().is_empty());

        let (upstream, ctx) = cooldown_upstream(true, &["Big.Pkg@2.1.0"], false).await;
        mount_paged(&upstream).await;
        assert_eq!(
            flat_versions(&ctx, "big.pkg").await,
            serde_json::json!(["1.0.0", "2.0.0", "2.1.0"])
        );
    }

    /// Q04: an inlined registration index loses its young leaves (count fixed); the
    /// cache keeps the upstream original. Audit mode filters nothing.
    #[tokio::test]
    async fn test_q04_registration_index_hides_young_leaves_enforce_only() {
        let index = serde_json::json!({ "count": 1, "items": [{ "count": 2, "lower": "1.0.0", "upper": "1.1.0",
            "items": [leaf("1.0.0", &iso_ago(30 * 86400)), leaf("1.1.0", &iso_ago(600))] }] });
        let (upstream, ctx) = cooldown_upstream(true, &[], false).await;
        mount_json(
            &upstream,
            "/v3/registration5-gz-semver2/fresh.pkg/index.json",
            index.clone(),
        )
        .await;
        let uri = "/nuget/v3/registration/fresh.pkg/index.json";
        let doc = json_body(send(&ctx.app, Method::GET, uri, "").await).await;
        assert_eq!(leaf_versions(&doc["items"][0]["items"]), ["1.0.0"]);
        assert_eq!(doc["items"][0]["count"], 1);
        for _ in 0..50 {
            if let Ok(raw) = ctx
                .state
                .storage
                .get("nuget/registration/fresh.pkg/index.json")
                .await
            {
                let cached: serde_json::Value = serde_json::from_slice(&raw).unwrap();
                assert_eq!(
                    leaf_versions(&cached["items"][0]["items"]),
                    ["1.0.0", "1.1.0"]
                );
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        let upstream = wiremock::MockServer::start().await;
        mount_json(
            &upstream,
            "/v3/registration5-gz-semver2/fresh.pkg/index.json",
            index,
        )
        .await;
        let up = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some(up);
            cfg.curation.mode = crate::config::CurationMode::Audit;
            cfg.curation.min_release_age = Some("7d".to_string());
        });
        let doc = json_body(send(&ctx.app, Method::GET, uri, "").await).await;
        assert_eq!(leaf_versions(&doc["items"][0]["items"]), ["1.0.0", "1.1.0"]);
    }

    /// Q04: search moves a hit's `version` to the newest allowed one; autocomplete
    /// `?id=` lists only allowed versions.
    #[tokio::test]
    async fn test_q04_search_and_autocomplete_hide_young_versions() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        let upstream = wiremock::MockServer::start().await;
        let (up, search, auto) = (
            upstream.uri(),
            format!("{}/query", upstream.uri()),
            format!("{}/autocomplete", upstream.uri()),
        );
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some(up);
            cfg.nuget.search_service = search;
            cfg.nuget.autocomplete = auto;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.min_release_age = Some("7d".to_string());
        });
        mount_paged(&upstream).await;
        let hit = serde_json::json!({ "totalHits": 1, "data": [{ "id": "Big.Pkg", "version": "3.0.0-beta",
            "versions": [{ "version": "1.0.0" }, { "version": "2.0.0" }, { "version": "2.1.0" }, { "version": "3.0.0-beta" }] }] });
        Mock::given(method("GET"))
            .and(path("/query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(hit))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/autocomplete"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({ "totalHits": 4, "data": ["1.0.0", "2.0.0", "2.1.0", "3.0.0-beta"] }),
            ))
            .mount(&upstream)
            .await;
        let doc = json_body(
            send(
                &ctx.app,
                Method::GET,
                "/nuget/v3/query?q=big&prerelease=true",
                "",
            )
            .await,
        )
        .await;
        assert_eq!(doc["data"][0]["version"], "2.0.0");
        assert_eq!(doc["data"][0]["versions"].as_array().unwrap().len(), 2);
        let doc = json_body(
            send(
                &ctx.app,
                Method::GET,
                "/nuget/v3/autocomplete?id=big.pkg&prerelease=true",
                "",
            )
            .await,
        )
        .await;
        assert_eq!(doc["data"], serde_json::json!(["1.0.0", "2.0.0"]));
    }

    /// Q04: a hosted package and an internal-namespace one are served as stored, even
    /// with versions published a minute ago.
    #[tokio::test]
    async fn test_q04_hosted_and_internal_packages_not_filtered() {
        use super::hosted::test_support::{multipart, nupkg};
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.nuget.metadata_proxy_timeout = 1;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.min_release_age = Some("7d".to_string());
            cfg.curation.internal_namespaces = vec!["corp.*".to_string()];
            // No upstream date can be read: a proxied version would be held (on_failure).
            cfg.server.trust_upstream_dates = true;
        });
        let (ct, body) = multipart(&nupkg("Own.Lib", "1.0.0", ""));
        let resp = crate::test_helpers::send_with_headers(
            &ctx.app,
            Method::PUT,
            "/nuget/v3/package/",
            vec![("content-type", ct.as_str())],
            body,
        )
        .await;
        assert!(resp.status().is_success(), "push: {}", resp.status());
        assert_eq!(
            flat_versions(&ctx, "own.lib").await,
            serde_json::json!(["1.0.0"])
        );
        let resp = send(&ctx.app, Method::GET, &nupkg_uri("own.lib", "1.0.0"), "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let doc = json_body(
            send(
                &ctx.app,
                Method::GET,
                "/nuget/v3/registration/own.lib/index.json",
                "",
            )
            .await,
        )
        .await;
        assert_eq!(leaf_versions(&doc["items"][0]["items"]), ["1.0.0"]);

        let index = serde_json::json!({ "items": [{ "items": [leaf("2.0.0", &iso_ago(60))] }] });
        ctx.state
            .storage
            .put(
                "nuget/registration/corp.lib/index.json",
                index.to_string().as_bytes(),
            )
            .await
            .unwrap();
        let doc = json_body(
            send(
                &ctx.app,
                Method::GET,
                "/nuget/v3/registration/corp.lib/index.json",
                "",
            )
            .await,
        )
        .await;
        assert_eq!(leaf_versions(&doc["items"][0]["items"]), ["2.0.0"]);
    }

    #[tokio::test]
    async fn test_local_search_empty_query() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = None;
        });

        // Populate index for two packages (index.json + .nupkg)
        for id in &["packagea", "packageb"] {
            let index = serde_json::json!({"versions": ["1.0.0"]});
            ctx.state
                .storage
                .put(
                    &format!("nuget/flatcontainer/{}/index.json", id),
                    serde_json::to_vec(&index).unwrap().as_slice(),
                )
                .await
                .unwrap();
            ctx.state
                .storage
                .put(
                    &format!("nuget/flatcontainer/{}/1.0.0/{}.1.0.0.nupkg", id, id),
                    b"fake-nupkg",
                )
                .await
                .unwrap();
        }
        ctx.state.repo_index.invalidate("nuget");

        let resp = send(&ctx.app, Method::GET, "/nuget/v3/query", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["totalHits"].as_u64().unwrap() >= 2);
        assert!(json["data"].as_array().unwrap().len() >= 2);
    }

    #[tokio::test]
    async fn test_local_search_substring_match() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = None;
        });

        let index = serde_json::json!({"versions": ["13.0.1"]});
        ctx.state
            .storage
            .put(
                "nuget/flatcontainer/newtonsoft.json/index.json",
                serde_json::to_vec(&index).unwrap().as_slice(),
            )
            .await
            .unwrap();
        ctx.state
            .storage
            .put(
                "nuget/flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg",
                b"fake-nupkg",
            )
            .await
            .unwrap();
        ctx.state.repo_index.invalidate("nuget");

        let resp = send(&ctx.app, Method::GET, "/nuget/v3/query?q=Newton", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["totalHits"].as_u64().unwrap(), 1);
        assert_eq!(json["data"][0]["id"].as_str().unwrap(), "newtonsoft.json");
    }

    #[tokio::test]
    async fn test_local_search_case_insensitive() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = None;
        });

        let index = serde_json::json!({"versions": ["13.0.1"]});
        ctx.state
            .storage
            .put(
                "nuget/flatcontainer/newtonsoft.json/index.json",
                serde_json::to_vec(&index).unwrap().as_slice(),
            )
            .await
            .unwrap();
        ctx.state
            .storage
            .put(
                "nuget/flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg",
                b"fake-nupkg",
            )
            .await
            .unwrap();
        ctx.state.repo_index.invalidate("nuget");

        let resp = send(&ctx.app, Method::GET, "/nuget/v3/query?q=newton", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["totalHits"].as_u64().unwrap(), 1);
    }

    #[tokio::test]
    async fn test_local_search_pagination() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = None;
        });

        for id in &["alpha", "beta", "gamma"] {
            let index = serde_json::json!({"versions": ["1.0.0"]});
            ctx.state
                .storage
                .put(
                    &format!("nuget/flatcontainer/{}/index.json", id),
                    serde_json::to_vec(&index).unwrap().as_slice(),
                )
                .await
                .unwrap();
            ctx.state
                .storage
                .put(
                    &format!("nuget/flatcontainer/{}/1.0.0/{}.1.0.0.nupkg", id, id),
                    b"fake-nupkg",
                )
                .await
                .unwrap();
        }
        ctx.state.repo_index.invalidate("nuget");

        let resp = send(&ctx.app, Method::GET, "/nuget/v3/query?skip=1&take=1", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["totalHits"].as_u64().unwrap(), 3);
        assert_eq!(json["data"].as_array().unwrap().len(), 1);
        // Sorted alphabetically: alpha, beta, gamma — skip 1 = beta
        assert_eq!(json["data"][0]["id"].as_str().unwrap(), "beta");
    }

    #[tokio::test]
    async fn test_search_response_format() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = None;
        });

        let index = serde_json::json!({"versions": ["1.0.0", "2.0.0"]});
        ctx.state
            .storage
            .put(
                "nuget/flatcontainer/testpkg/index.json",
                serde_json::to_vec(&index).unwrap().as_slice(),
            )
            .await
            .unwrap();
        for ver in &["1.0.0", "2.0.0"] {
            ctx.state
                .storage
                .put(
                    &format!("nuget/flatcontainer/testpkg/{}/testpkg.{}.nupkg", ver, ver),
                    b"fake-nupkg",
                )
                .await
                .unwrap();
        }
        ctx.state.repo_index.invalidate("nuget");

        let resp = send(&ctx.app, Method::GET, "/nuget/v3/query?q=testpkg", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Validate top-level structure
        assert!(json["totalHits"].is_number());
        assert!(json["data"].is_array());

        // Validate entry structure
        let entry = &json["data"][0];
        assert!(entry["id"].is_string());
        assert!(entry["version"].is_string());
        assert!(entry["versions"].is_array());
        assert_eq!(entry["version"].as_str().unwrap(), "2.0.0");
        assert_eq!(entry["versions"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_local_search_sem_ver_level_filters_v2() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = None;
        });

        // Package with SemVer 2.0 version (dot-separated pre-release)
        let index = serde_json::json!({"versions": ["1.0.0", "2.0.0-rc.1"]});
        ctx.state
            .storage
            .put(
                "nuget/flatcontainer/semver2pkg/index.json",
                serde_json::to_vec(&index).unwrap().as_slice(),
            )
            .await
            .unwrap();
        ctx.state
            .storage
            .put(
                "nuget/flatcontainer/semver2pkg/1.0.0/semver2pkg.1.0.0.nupkg",
                b"fake-nupkg",
            )
            .await
            .unwrap();
        ctx.state.repo_index.invalidate("nuget");

        // Without semVerLevel → SemVer2 version hidden, only 1.0.0 visible
        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/query?q=semver2pkg&prerelease=true",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let entry = &json["data"][0];
        let versions = entry["versions"].as_array().unwrap();
        assert_eq!(
            versions.len(),
            1,
            "without semVerLevel, SemVer2 must be hidden"
        );
        assert_eq!(versions[0]["version"].as_str().unwrap(), "1.0.0");

        // With semVerLevel=2.0.0 → both versions visible
        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/query?q=semver2pkg&prerelease=true&semVerLevel=2.0.0",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let entry = &json["data"][0];
        let versions = entry["versions"].as_array().unwrap();
        assert_eq!(
            versions.len(),
            2,
            "with semVerLevel=2.0.0, SemVer2 must be visible"
        );
    }

    #[tokio::test]
    async fn test_autocomplete_no_upstream_returns_empty() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = None;
        });

        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/autocomplete?q=Newtonsoft&take=5",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["totalHits"].as_u64().unwrap(), 0);
        assert!(json["data"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_autocomplete_unreachable_upstream_returns_empty() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.nuget.proxy_timeout = 1;
            cfg.nuget.autocomplete = "http://127.0.0.1:1/autocomplete".to_string();
        });

        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/autocomplete?q=Newtonsoft&take=5",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["totalHits"].as_u64().unwrap(), 0);
        assert!(json["data"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_registration_page_rejects_path_traversal() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
        });

        // Path traversal in version
        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/registration/foo/page/1.0.0/../../etc/passwd.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Path traversal in package id — axum normalizes ../ so route doesn't match (404)
        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/registration/../evil/page/1.0.0/2.0.0.json",
            "",
        )
        .await;
        assert_ne!(resp.status(), StatusCode::OK);
    }

    /// No cache + unreachable upstream → 502 (an outage, not a missing package)
    #[tokio::test]
    async fn test_registration_page_unreachable_upstream() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.nuget.proxy_timeout = 1;
        });

        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/registration/dotnet-ef/page/0.0.1-alpha/3.1.27.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    /// Search fallback adds X-Nora-Stale header when upstream is unreachable (#422)
    #[tokio::test]
    async fn test_search_fallback_has_stale_header() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.nuget.search_service = "http://127.0.0.1:1/query".to_string();
            cfg.nuget.serve_stale = true;
        });
        let resp = send(&ctx.app, Method::GET, "/nuget/v3/query?q=test", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("x-nora-stale").map(|v| v.as_bytes()),
            Some(b"true".as_slice())
        );
    }

    /// Search returns 503 when serve_stale=false and upstream is down (#422)
    #[tokio::test]
    async fn test_search_serve_stale_disabled_returns_503() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.nuget.search_service = "http://127.0.0.1:1/query".to_string();
            cfg.nuget.serve_stale = false;
        });
        let resp = send(&ctx.app, Method::GET, "/nuget/v3/query?q=test", "").await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(resp.headers().get("x-nora-stale").is_none());
    }

    /// Autocomplete fallback adds X-Nora-Stale header when upstream is unreachable (#422)
    #[tokio::test]
    async fn test_autocomplete_fallback_has_stale_header() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.nuget.autocomplete = "http://127.0.0.1:1/autocomplete".to_string();
            cfg.nuget.serve_stale = true;
        });
        let resp = send(&ctx.app, Method::GET, "/nuget/v3/autocomplete?q=test", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("x-nora-stale").map(|v| v.as_bytes()),
            Some(b"true".as_slice())
        );
    }

    /// Autocomplete returns 503 when serve_stale=false and upstream is down (#422)
    #[tokio::test]
    async fn test_autocomplete_serve_stale_disabled_returns_503() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.nuget.autocomplete = "http://127.0.0.1:1/autocomplete".to_string();
            cfg.nuget.serve_stale = false;
        });
        let resp = send(&ctx.app, Method::GET, "/nuget/v3/autocomplete?q=test", "").await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(resp.headers().get("x-nora-stale").is_none());
    }

    /// A cached .nupkg resumes: 206 for a satisfiable range, 416 once the client
    /// already holds the whole package, `Accept-Ranges` on the full 200.
    #[tokio::test]
    async fn test_nuget_nupkg_range_request() {
        use crate::test_helpers::send_with_headers;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
        });
        let nupkg = b"0123456789";
        ctx.state
            .storage
            .put("nuget/flatcontainer/rngpkg/1.0.0/rngpkg.1.0.0.nupkg", nupkg)
            .await
            .unwrap();
        let url = "/nuget/v3/flatcontainer/rngpkg/1.0.0/rngpkg.1.0.0.nupkg";

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
        assert_eq!(&body_bytes(resp).await[..], nupkg);
    }

    /// A Range request on a cached .nupkg reads the object once: the 206 is cut from
    /// the body the integrity and quarantine gates already loaded, not a second, ranged
    /// GET of the same object. The one extra round-trip is the `stat` (a HEAD, no body)
    /// that tells a small object from a large one (R2-13).
    #[tokio::test]
    async fn test_nuget_range_on_cache_hit_reads_storage_once() {
        use crate::test_helpers::{
            create_test_context_with_storage_and_config, op_counting_storage, send_with_headers,
        };

        let (storage, ops) = op_counting_storage();
        let ctx = create_test_context_with_storage_and_config(storage, |cfg| {
            cfg.nuget.enabled = true;
        });
        ctx.state
            .storage
            .put(
                "nuget/flatcontainer/rngpkg/1.0.0/rngpkg.1.0.0.nupkg",
                b"0123456789",
            )
            .await
            .unwrap();
        let url = "/nuget/v3/flatcontainer/rngpkg/1.0.0/rngpkg.1.0.0.nupkg";
        // Warm up once (hosted index load), then compare a full and a ranged hit.
        let _ = send(&ctx.app, Method::GET, url, "").await;
        ops.reset();
        let resp = send(&ctx.app, Method::GET, url, "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let full = ops.snapshot();
        ops.reset();
        let resp =
            send_with_headers(&ctx.app, Method::GET, url, vec![("range", "bytes=2-5")], "").await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(&body_bytes(resp).await[..], b"2345");
        let mut ranged = ops.snapshot();
        assert_eq!(ranged.remove("stat"), Some(1), "{ranged:?}");
        assert_eq!(ranged, full, "a ranged hit must read what a full hit reads");
        assert_eq!(ranged.get("get_range"), None, "{ranged:?}");
    }

    /// R2-13: a Range request on a cached .nupkg above `stream_threshold_mb` is one
    /// `stat` and one ranged read: the whole object is never opened for streaming first.
    #[tokio::test]
    async fn test_nuget_range_on_large_cache_hit_opens_one_ranged_read() {
        use crate::test_helpers::{
            create_test_context_with_storage_and_config, op_counting_storage, send_with_headers,
        };

        let (storage, ops) = op_counting_storage();
        let ctx = create_test_context_with_storage_and_config(storage, |cfg| {
            cfg.nuget.enabled = true;
            cfg.server.stream_threshold_mb = 1;
        });
        let nupkg: Vec<u8> = (0..(2 * 1024 * 1024 + 7))
            .map(|i| (i % 251) as u8)
            .collect();
        let key = "nuget/flatcontainer/bigpkg/1.0.0/bigpkg.1.0.0.nupkg";
        ctx.state.storage.put(key, &nupkg).await.unwrap();
        let url = "/nuget/v3/flatcontainer/bigpkg/1.0.0/bigpkg.1.0.0.nupkg";
        let _ = send(&ctx.app, Method::GET, url, "").await; // hosted index load
        ops.reset();
        let range = vec![("range", "bytes=1048576-1048585")];
        let resp = send_with_headers(&ctx.app, Method::GET, url, range, "").await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(&body_bytes(resp).await[..], &nupkg[1048576..=1048585]);
        let ranged = ops.snapshot();
        assert_eq!(ranged.get("get_reader"), None, "{ranged:?}");
        assert_eq!(ranged.get("get_range"), Some(&1), "{ranged:?}");
        assert_eq!(ranged.get("stat"), Some(&1), "{ranged:?}");

        // The full download still streams it, with its length.
        let resp = send(&ctx.app, Method::GET, url, "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()["content-length"],
            nupkg.len().to_string().as_str()
        );
        assert_eq!(body_bytes(resp).await.len(), nupkg.len());
    }

    /// Upstream failures on a cold .nupkg miss: only a 404 stays a 404; an outage is
    /// 502, a timeout 504, throttling 503 with the upstream Retry-After, and an auth
    /// refusal 502 — none of them may reach `dotnet restore` as NU1101.
    #[tokio::test]
    async fn test_cold_miss_upstream_errors_map_to_5xx() {
        use wiremock::matchers::path;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        for (name, resp) in [
            ("gone", ResponseTemplate::new(404)),
            ("down", ResponseTemplate::new(503)),
            (
                "throttled",
                ResponseTemplate::new(429).insert_header("retry-after", "7"),
            ),
            ("denied", ResponseTemplate::new(403)),
            (
                "slow",
                ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(3)),
            ),
        ] {
            Mock::given(path(format!(
                "/v3-flatcontainer/{name}/1.0.0/{name}.1.0.0.nupkg"
            )))
            .respond_with(resp)
            .mount(&upstream)
            .await;
        }
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some(uri);
            cfg.nuget.proxy_timeout = 1;
        });

        for (name, want) in [
            ("gone", StatusCode::NOT_FOUND),
            ("down", StatusCode::BAD_GATEWAY),
            ("throttled", StatusCode::SERVICE_UNAVAILABLE),
            ("denied", StatusCode::BAD_GATEWAY),
            ("slow", StatusCode::GATEWAY_TIMEOUT),
        ] {
            let url = format!("/nuget/v3/flatcontainer/{name}/1.0.0/{name}.1.0.0.nupkg");
            let resp = send(&ctx.app, Method::GET, &url, "").await;
            assert_eq!(resp.status(), want, "{name}");
            if name == "throttled" {
                assert_eq!(resp.headers()["retry-after"], "7");
            }
        }
    }

    /// A stale cached registration survives an upstream 429: it used to be collapsed
    /// into a 404 that discarded the cache.
    #[tokio::test]
    async fn test_registration_upstream_429_serves_stale_cache() {
        use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(429))
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some(uri);
            cfg.nuget.metadata_ttl = 0;
            cfg.nuget.serve_stale = true;
        });
        ctx.state
            .storage
            .put(
                "nuget/registration/test-package/index.json",
                br#"{"count":0,"items":[]}"#,
            )
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/registration/test-package/index.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()["x-nora-stale"], "true");
    }
}

// ── Spec conformance tests (#390) ─────────────────────────────────────
//
// Invariant: after URL rewriting, no upstream domains remain in the response.
// Uses golden fixtures from testdata/nuget/ to validate against realistic
// upstream payloads, not just synthetic test data.

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod spec_conformance_tests {
    use super::*;

    /// Known upstream domains that MUST NOT appear in rewritten responses.
    const NUGET_UPSTREAM_DOMAINS: &[&str] = &[
        "api.nuget.org",
        "azuresearch-usnc.nuget.org",
        "azuresearch-ussc.nuget.org",
    ];

    /// Known URL patterns in NuGet responses that are NOT client-fetchable
    /// and intentionally left unrewritten (the leak detector skips them too).
    const NUGET_EXCLUDED_PATTERNS: &[&str] = UPSTREAM_PASSTHROUGH_PATHS;

    /// Assert that no upstream URLs remain in a rewritten response body,
    /// excluding known non-client-fetchable URL patterns.
    /// This is the core air-gap invariant: any leaked URL means the client
    /// tries to reach the internet and fails in air-gapped environments.
    fn assert_no_upstream_urls(body: &str, context: &str) {
        for line in body.lines() {
            if NUGET_EXCLUDED_PATTERNS.iter().any(|p| line.contains(p)) {
                continue;
            }
            for domain in NUGET_UPSTREAM_DOMAINS {
                assert!(
                    !line.contains(domain),
                    "upstream domain '{}' leaked in {} (line: {})",
                    domain,
                    context,
                    line.trim()
                );
            }
        }
    }

    /// Load a golden fixture from testdata/nuget/.
    fn load_fixture(name: &str) -> String {
        let path = format!("{}/testdata/nuget/{}", env!("CARGO_MANIFEST_DIR"), name);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to load fixture {}: {}", path, e))
    }

    // ── Generated service index: air-gap invariants ──

    #[test]
    fn test_generated_service_index_no_upstream_leak() {
        let generated = generate_service_index("https://registry.airgap.local");
        assert_no_upstream_urls(&generated, "generated service-index");

        let json: serde_json::Value = serde_json::from_str(&generated).unwrap();
        assert!(json["resources"].is_array());
        assert!(!json["resources"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_generated_service_index_all_ids_point_to_nora() {
        let generated = generate_service_index("http://nora:4000");
        let json: serde_json::Value = serde_json::from_str(&generated).unwrap();
        let resources = json["resources"].as_array().unwrap();

        // Every @id must start with nora base — no exceptions (air-gap invariant)
        for res in resources {
            let id = res["@id"].as_str().unwrap();
            let res_type = res["@type"].as_str().unwrap_or("");
            assert!(
                id.starts_with("http://nora:4000/nuget/"),
                "resource @id not pointing to NORA: {} (type: {})",
                id,
                res_type
            );
        }
    }

    #[test]
    fn test_generated_service_index_snapshot() {
        let generated = generate_service_index("http://nora:4000");
        let json: serde_json::Value = serde_json::from_str(&generated).unwrap();

        let ids: Vec<&str> = json["resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["@id"].as_str().unwrap())
            .collect();
        insta::assert_json_snapshot!("nuget_service_index_ids", ids);
    }

    #[test]
    fn test_search_response_registration_urls_rewritten() {
        let upstream_search = r#"{"totalHits":1,"data":[{"id":"Newtonsoft.Json","version":"13.0.3","registration":"https://api.nuget.org/v3/registration5-gz-semver2/newtonsoft.json/index.json"}]}"#;
        let rewritten =
            rewrite_registration_urls(upstream_search, "https://api.nuget.org", "http://nora:4000");
        assert_no_upstream_urls(&rewritten, "search response rewrite");
        assert!(
            rewritten.contains("http://nora:4000/nuget/v3/registration/newtonsoft.json/index.json")
        );
    }

    #[test]
    fn test_autocomplete_response_no_leak() {
        // Autocomplete responses contain only package names, no URLs to rewrite
        let upstream =
            r#"{"totalHits":5,"data":["Newtonsoft.Json","NUnit","NLog","Nancy","Noda"]}"#;
        let rewritten =
            rewrite_registration_urls(upstream, "https://api.nuget.org", "http://nora:4000");
        assert_no_upstream_urls(&rewritten, "autocomplete response");
    }

    // ── Registration index rewrite: paginated fixture ──

    #[test]
    fn test_registration_paginated_golden_no_upstream_leak() {
        let fixture = load_fixture("registration-index-paginated.json");
        let rewritten = rewrite_registration_urls(
            &fixture,
            "https://api.nuget.org",
            "https://registry.airgap.local",
        );
        assert_no_upstream_urls(&rewritten, "registration-index-paginated rewrite");

        let json: serde_json::Value = serde_json::from_str(&rewritten).unwrap();
        assert_eq!(json["count"].as_u64().unwrap(), 2);

        // All page @id must point to NORA
        for item in json["items"].as_array().unwrap() {
            let id = item["@id"].as_str().unwrap();
            assert!(
                id.starts_with("https://registry.airgap.local/nuget/v3/registration/"),
                "page @id not rewritten: {}",
                id
            );
        }
    }

    #[test]
    fn test_registration_paginated_golden_snapshot() {
        let fixture = load_fixture("registration-index-paginated.json");
        let rewritten =
            rewrite_registration_urls(&fixture, "https://api.nuget.org", "http://nora:4000");
        let json: serde_json::Value = serde_json::from_str(&rewritten).unwrap();

        let page_ids: Vec<&str> = json["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["@id"].as_str().unwrap())
            .collect();
        insta::assert_json_snapshot!("nuget_registration_paginated_page_ids", page_ids);
    }

    // ── Registration index rewrite: inline fixture ──

    #[test]
    fn test_registration_inline_golden_no_upstream_leak() {
        let fixture = load_fixture("registration-index-inline.json");
        let rewritten =
            rewrite_registration_urls(&fixture, "https://api.nuget.org", "http://nora:4000");

        // registration5-gz-semver2 URLs must be rewritten
        assert!(!rewritten.contains("registration5-gz-semver2"));
        assert!(!rewritten.contains("registration5-semver1"));
        assert!(!rewritten.contains("registration5-gz-semver1"));

        let json: serde_json::Value = serde_json::from_str(&rewritten).unwrap();
        let page = &json["items"][0];
        let entry = &page["items"][0];

        // entry @id must be rewritten to NORA
        let entry_id = entry["@id"].as_str().unwrap();
        assert!(
            entry_id.starts_with("http://nora:4000/nuget/v3/registration/"),
            "inline entry @id not rewritten: {}",
            entry_id
        );
    }

    // ── Content-Type assertions ──

    #[tokio::test]
    async fn test_service_index_content_type_no_gzip() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::Method;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = None;
        });

        // Generated service index — no upstream or fixture needed
        let resp = send(&ctx.app, Method::GET, "/nuget/v3/index.json", "").await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let content_type = resp
            .headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap_or(""))
            .unwrap_or("");
        assert!(
            content_type.contains("application/json"),
            "NuGet service index must return application/json, got: {}",
            content_type
        );

        // Service index must NOT be gzip-encoded (only registration endpoints are)
        assert!(
            resp.headers().get("content-encoding").is_none(),
            "service index must not have Content-Encoding header"
        );
    }

    #[tokio::test]
    async fn test_cached_registration_content_type_and_gzip() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::Method;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = None;
        });

        let fixture = load_fixture("registration-index-inline.json");
        ctx.state
            .storage
            .put("nuget/registration/xunit/index.json", fixture.as_bytes())
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/registration/xunit/index.json",
            "",
        )
        .await;

        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let content_type = resp
            .headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap_or(""))
            .unwrap_or("");
        assert!(
            content_type.contains("application/json"),
            "NuGet registration index must return application/json, got: {}",
            content_type
        );

        // Registration must be gzip-encoded (RegistrationsBaseUrl/3.6.0 spec)
        let content_encoding = resp
            .headers()
            .get("content-encoding")
            .map(|v| v.to_str().unwrap_or(""))
            .unwrap_or("");
        assert_eq!(
            content_encoding, "gzip",
            "registration response must have Content-Encoding: gzip"
        );

        // Decompress and verify the rewritten body has no upstream URLs
        let body = body_bytes(resp).await;
        let mut decoder = flate2::read::GzDecoder::new(&body[..]);
        let mut decompressed = String::new();
        std::io::Read::read_to_string(&mut decoder, &mut decompressed).unwrap();
        assert_no_upstream_urls(&decompressed, "cached registration index response");
    }

    // ── Cache-Control assertions ──

    #[tokio::test]
    async fn test_nupkg_cache_control_immutable() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::Method;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
        });

        ctx.state
            .storage
            .put(
                "nuget/flatcontainer/testpkg/1.0.0/testpkg.1.0.0.nupkg",
                b"fake-nupkg",
            )
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/flatcontainer/testpkg/1.0.0/testpkg.1.0.0.nupkg",
            "",
        )
        .await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let cache_control = resp
            .headers()
            .get("cache-control")
            .map(|v| v.to_str().unwrap_or(""))
            .unwrap_or("");
        assert!(
            cache_control.contains("immutable"),
            "nupkg must have immutable cache-control, got: {}",
            cache_control
        );
    }

    /// C56: an upstream 304 writes only the small `.meta` sidecar (one PUT carrying
    /// `validated_at`), never the cached body again.
    #[tokio::test]
    async fn test_nuget_304_writes_only_the_sidecar() {
        use crate::registry::{validators_key, write_validators, Validators};
        use crate::test_helpers::{
            create_test_context_with_storage_and_config, op_counting_storage, send,
        };
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::{header_exists, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(header_exists("if-none-match"))
            .respond_with(ResponseTemplate::new(304))
            .mount(&upstream)
            .await;
        let (storage, ops) = op_counting_storage();
        let ctx = create_test_context_with_storage_and_config(storage, |cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some(upstream.uri());
            cfg.nuget.metadata_ttl = 0; // always stale → always revalidate
        });
        let key = "nuget/flatcontainer/sidecar-pkg/index.json";
        ctx.state
            .storage
            .put(key, br#"{"versions":["1.0.0"]}"#)
            .await
            .unwrap();
        let v = Validators {
            etag: Some("\"v1\"".to_string()),
            last_modified: None,
        };
        write_validators(&ctx.state.storage, key, &v).await;
        ops.reset();

        let uri = "/nuget/v3/flatcontainer/sidecar-pkg/index.json";
        let resp = send(&ctx.app, Method::GET, uri, "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let mut stamped = false;
        for _ in 0..100 {
            let sidecar = ctx.state.storage.get(&validators_key(key)).await.unwrap();
            if String::from_utf8_lossy(&sidecar).contains("validated_at") {
                stamped = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(stamped, "the 304 is recorded in the sidecar");
        assert_eq!(
            ops.snapshot().get("put"),
            Some(&1),
            "only the sidecar is written: {:?}",
            ops.snapshot()
        );
    }

    /// #52 acceptance: with a cached flat-container version list + stored
    /// validators, a stale request revalidates with `If-None-Match`; on upstream
    /// 304 the cached body is served with no 200-body download. nuget.org returns
    /// validators on this endpoint, so this is a real revalidation.
    #[tokio::test]
    async fn test_nuget_revalidation_304_serves_cache_no_body_download() {
        use crate::registry::{write_validators, Validators};
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
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
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some(upstream.uri());
            cfg.nuget.metadata_ttl = 0; // always stale → always revalidate
            cfg.nuget.revalidate = true;
            cfg.nuget.serve_stale = false;
        });

        let key = "nuget/flatcontainer/test-package/index.json";
        ctx.state
            .storage
            .put(key, br#"{"versions":["1.0.0","2.0.0"]}"#)
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
            .with_label_values(&["nuget"])
            .get();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/flatcontainer/test-package/index.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert!(
            String::from_utf8_lossy(&body).contains("2.0.0"),
            "must serve the cached version list"
        );

        let after = crate::metrics::PROXY_UPSTREAM_304_TOTAL
            .with_label_values(&["nuget"])
            .get();
        assert!(after > before, "a 304 revalidation must be recorded");
    }
}

/// A NuGet version is the version NuGet reads, not its spelling: clients put the normal form
/// in lowercase into flat-container URLs (`NuGetVersion.ToNormalizedString()`), so a rule or an
/// allowlist entry holds however it spells its version — `13.0` is `13.0.0`, `1.0.0.0` is
/// `1.0.0`, `2.0.0-Beta1` is `2.0.0-beta1`, build metadata does not count.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod nuget_version_curation {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn upstream() -> MockServer {
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"NUPKG".to_vec()))
            .mount(&upstream)
            .await;
        upstream
    }

    fn write(dir: &tempfile::TempDir, file: &str, body: &str) -> String {
        let path = dir.path().join(file);
        std::fs::write(&path, body).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn nupkg(id: &str, version: &str) -> String {
        format!("/nuget/v3/flatcontainer/{id}/{version}/{id}.{version}.nupkg")
    }

    #[tokio::test]
    async fn a_rule_holds_however_it_spells_its_version() {
        let upstream = upstream().await;
        let dir = tempfile::tempdir().unwrap();
        let blocklist = write(
            &dir,
            "blocklist.json",
            r#"{"version": 1, "rules": [
                {"registry": "nuget", "name": "Evil.Lib", "version": "13.0", "reason": "malware"},
                {"registry": "nuget", "name": "Evil.Lib", "version": "2.0.0-Beta1+build.7", "reason": "malware"},
                {"registry": "nuget", "name": "Evil.Lib", "version": "3.0.0.0", "reason": "malware"}
            ]}"#,
        );
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some(uri);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist);
        });
        for version in ["13.0.0", "2.0.0-beta1", "3.0.0"] {
            let resp = send(&ctx.app, Method::GET, &nupkg("evil.lib", version), "").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{version}");
        }
        for version in ["13.0.1", "2.0.0", "3.0.0.1"] {
            let resp = send(&ctx.app, Method::GET, &nupkg("evil.lib", version), "").await;
            assert_ne!(resp.status(), StatusCode::FORBIDDEN, "{version}");
        }
    }

    #[tokio::test]
    async fn an_allowlist_entry_admits_its_version_however_spelled() {
        let upstream = upstream().await;
        let dir = tempfile::tempdir().unwrap();
        let allowlist = write(
            &dir,
            "allowlist.json",
            r#"{"version": 1, "entries": [
                {"registry": "nuget", "name": "Newtonsoft.Json", "version": "13.0.1.0"},
                {"registry": "nuget", "name": "Newtonsoft.Json", "version": "14.0.0-Preview.2"}
            ]}"#,
        );
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some(uri);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.allowlist_path = Some(allowlist);
        });
        for version in ["13.0.1", "14.0.0-preview.2"] {
            let resp = send(
                &ctx.app,
                Method::GET,
                &nupkg("newtonsoft.json", version),
                "",
            )
            .await;
            assert_ne!(resp.status(), StatusCode::FORBIDDEN, "{version}");
        }
        let resp = send(
            &ctx.app,
            Method::GET,
            &nupkg("newtonsoft.json", "13.0.2"),
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
