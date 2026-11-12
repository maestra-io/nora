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
    mark_revalidated, nora_base_url, proxy_error_response, proxy_fetch_artifact,
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
            &format!("/{prefix}/v3/{HIVE_SEMVER1}/{{id}}/index.json"),
            get(registration_index_semver1),
        )
        .route(
            &format!("/{prefix}/v3/{HIVE_SEMVER1}/{{id}}/page/{{lower}}/{{*upper}}"),
            get(registration_page_semver1),
        )
        .route(
            &format!("/{prefix}/v3/{HIVE_GZ_SEMVER1}/{{id}}/index.json"),
            get(registration_index_gz_semver1),
        )
        .route(
            &format!("/{prefix}/v3/{HIVE_GZ_SEMVER1}/{{id}}/page/{{lower}}/{{*upper}}"),
            get(registration_page_gz_semver1),
        )
        .route(
            &format!("/{prefix}/v3/{HIVE_SEMVER1}/{{id}}/{{leaf}}"),
            get(|s, h, p| registration_leaf(s, h, p, HIVE_SEMVER1)),
        )
        .route(
            &format!("/{prefix}/v3/{HIVE_GZ_SEMVER1}/{{id}}/{{leaf}}"),
            get(|s, h, p| registration_leaf(s, h, p, HIVE_GZ_SEMVER1)),
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
    proxied_search(&state, params, raw_query, Search::Query).await
}

// ── Autocomplete (proxy to upstream SearchAutocompleteService) ─────────

async fn autocomplete_query(
    State(state): State<AppState>,
    Query(params): Query<SearchParams>,
    raw_query: axum::extract::RawQuery,
) -> Response {
    proxied_search(&state, params, raw_query, Search::Autocomplete).await
}

/// The two search services NuGet clients call: same flow, own upstream, local index
/// and response filter.
#[derive(Clone, Copy)]
enum Search {
    Query,
    Autocomplete,
}

impl Search {
    /// The activity-log and log name.
    fn name(self) -> &'static str {
        match self {
            Search::Query => "search",
            Search::Autocomplete => "autocomplete",
        }
    }

    async fn local(
        self,
        state: &AppState,
        query: &str,
        skip: usize,
        take: usize,
        prerelease: bool,
        sem_ver_level: Option<&str>,
    ) -> Vec<u8> {
        match self {
            Search::Query => {
                local_search_results(state, query, skip, take, prerelease, sem_ver_level).await
            }
            Search::Autocomplete => {
                local_autocomplete_results(state, query, skip, take, prerelease, sem_ver_level)
                    .await
            }
        }
    }
}

/// Proxy a search to the upstream service with a short timeout (UX-critical path),
/// local results when there is no upstream, for an internal-namespace term, and as
/// the stale fallback (R4-T11: was two copies).
async fn proxied_search(
    state: &AppState,
    params: SearchParams,
    raw_query: axum::extract::RawQuery,
    kind: Search,
) -> Response {
    let query = params.q.unwrap_or_default();
    let skip = params.skip.unwrap_or(0);
    let take = params.take.unwrap_or(20);
    let prerelease = params.prerelease.unwrap_or(false);
    let sem_ver_level = params.sem_ver_level;
    let local = || {
        kind.local(
            state,
            &query,
            skip,
            take,
            prerelease,
            sem_ver_level.as_deref(),
        )
    };

    // No upstream proxy configured → local results directly
    if upstream_url(state).is_none() {
        return with_json(local().await);
    }

    // #68 namespace isolation: never forward a term that matches an internal
    // namespace upstream (dependency confusion) — serve local results only.
    if crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Nuget,
        &query,
    ) {
        return with_json(local().await);
    }

    let qs = raw_query.0.unwrap_or_default();
    let service = match kind {
        Search::Query => &state.config.nuget.search_service,
        Search::Autocomplete => &state.config.nuget.autocomplete,
    };
    let url = format!("{service}?{qs}");

    match proxy_fetch_text(
        &state.http_client,
        &url,
        Duration::from_secs(SEARCH_TIMEOUT_SECS),
        None, // the search services are public
        None,
        &state.circuit_breaker,
        RegistryType::Nuget,
    )
    .await
    {
        Ok(text) => {
            let base_url = nora_base_url(state);
            let upstream = rewrite_host(state);
            let rewritten = rewrite_registration_urls(&text, &upstream, &base_url);
            state.metrics.record_download("nuget");
            state.metrics.record_cache_miss("nuget");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                format!(
                    "{}?{}",
                    kind.name(),
                    qs.chars().take(50).collect::<String>()
                ),
                crate::registry_type::RegistryType::Nuget,
                "PROXY",
            ));
            match kind {
                Search::Query => with_json(filter_search_results(state, rewritten).await),
                // `?id=` asks for one package's versions (hosted IDs never get here).
                Search::Autocomplete => match qs.split('&').find_map(|kv| kv.strip_prefix("id=")) {
                    Some(id) => with_json(filter_autocomplete_versions(state, id, rewritten).await),
                    None => with_json(rewritten.into_bytes()),
                },
            }
        }
        Err(ProxyError::NotFound) => with_json(br#"{"totalHits":0,"data":[]}"#.to_vec()),
        Err(_) => {
            if !state.config.nuget.serve_stale {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            match kind {
                Search::Query => {
                    tracing::info!("NuGet search: upstream unavailable, using local index")
                }
                Search::Autocomplete => {
                    tracing::info!("NuGet autocomplete: upstream unavailable, using local index")
                }
            }
            with_json_stale(local().await)
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

    // A hosted package's registration is built from its records; the upstream is not asked.
    match hosted_versions(&state.storage, &id_lower).await {
        Some(versions) if versions.hosted() => {
            return hosted_registration(&state, &id_lower, versions.listed()).await
        }
        Some(_) => {}
        None => return crate::registry::storage_unavailable("nuget", &hosted_prefix(&id_lower)),
    }

    let base_url = nora_base_url(&state);
    let upstream = rewrite_host(&state);

    // Read cache eagerly so stale data is available on upstream failure; the
    // freshness check rides the same store round trip.
    let ttl = state.config.nuget.metadata_ttl;
    let (read, validated_at) = tokio::join!(
        state.storage.get(&storage_key),
        crate::registry::stored_validated_at(&state.storage, &storage_key)
    );
    let fresh = validated_at.is_some_and(|t| crate::cache_ttl::is_within_ttl(t, ttl));
    let (cached_data, read_failure) = crate::registry::cached_read(read);

    // TTL cache — rewrite URLs on read (cache may contain pre-fix entries)
    if let Some(ref data) = cached_data {
        if fresh {
            state.metrics.record_download("nuget");
            state.metrics.record_cache_hit("nuget");
            return registration_response(data.clone(), &upstream, &base_url).await;
        }
    }

    // #733: an internal-namespace package — serve any (stale) local registration, else block; never proxy.
    if internal {
        if let Some(ref data) = cached_data {
            state.metrics.record_download("nuget");
            state.metrics.record_cache_hit("nuget");
            return registration_response(data.clone(), &upstream, &base_url).await;
        }
        if let Some(e) = &read_failure {
            return crate::registry::local_copy_unreadable("nuget", &storage_key, e);
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
            Some(data) => registration_response(data, &upstream, &base_url).await,
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    let url = format!(
        "{}/v3/registration5-gz-semver2/{}/index.json",
        upstream.trim_end_matches('/'),
        id_lower
    );

    if stale_while_revalidate(&state, validated_at) {
        if let Some(ref data) = cached_data {
            refresh_in_background(&state, &storage_key, &url);
            state.metrics.record_download("nuget");
            state.metrics.record_cache_hit("nuget");
            return mark_stale(registration_response(data.clone(), &upstream, &base_url).await);
        }
    }
    let rewrite = Some((upstream.as_str(), base_url.as_str()));
    match refresh_metadata(&state, &storage_key, &url, Some(id_lower.clone())).await {
        Ok(raw) => registration_response(raw, &upstream, &base_url).await,
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

    // A hosted package's registration lists every version inline: it has no pages, and the
    // upstream is not asked for one.
    match hosted_versions(&state.storage, &id_lower).await {
        Some(versions) if versions.hosted() => return StatusCode::NOT_FOUND.into_response(),
        Some(_) => {}
        None => return crate::registry::storage_unavailable("nuget", &hosted_prefix(&id_lower)),
    }

    let base_url = nora_base_url(&state);
    let upstream = rewrite_host(&state);
    let storage_key = format!(
        "nuget/registration/{}/page/{}/{}.json",
        id_lower, lower, upper
    );

    // Read cache eagerly so stale data is available on upstream failure; the
    // freshness check rides the same store round trip.
    let ttl = state.config.nuget.metadata_ttl;
    let (read, validated_at) = tokio::join!(
        state.storage.get(&storage_key),
        crate::registry::stored_validated_at(&state.storage, &storage_key)
    );
    let fresh = validated_at.is_some_and(|t| crate::cache_ttl::is_within_ttl(t, ttl));
    let (cached_data, read_failure) = crate::registry::cached_read(read);

    // TTL cache (a 304 revalidation keeps a page fresh without re-uploading it, C56)
    if let Some(ref data) = cached_data {
        if fresh {
            state.metrics.record_download("nuget");
            state.metrics.record_cache_hit("nuget");
            return registration_response(data.clone(), &upstream, &base_url).await;
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
            return registration_response(data.clone(), &upstream, &base_url).await;
        }
        if let Some(e) = &read_failure {
            return crate::registry::local_copy_unreadable("nuget", &storage_key, e);
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
            Some(data) => registration_response(data, &upstream, &base_url).await,
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
    if stale_while_revalidate(&state, validated_at) {
        if let Some(ref data) = cached_data {
            refresh_in_background(&state, &storage_key, &url);
            state.metrics.record_download("nuget");
            state.metrics.record_cache_hit("nuget");
            return mark_stale(registration_response(data.clone(), &upstream, &base_url).await);
        }
    }
    match refresh_metadata(&state, &storage_key, &url, activity).await {
        Ok(raw) => registration_response(raw, &upstream, &base_url).await,
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

    // A hosted package's versions are its records — before any list an upstream gave for the id.
    match hosted_versions(&state.storage, &id_lower).await {
        Some(versions) if versions.hosted() => {
            state.metrics.record_download("nuget");
            return with_json(
                serde_json::json!({ "versions": versions.listed() })
                    .to_string()
                    .into_bytes(),
            );
        }
        Some(_) => {}
        None => return crate::registry::storage_unavailable("nuget", &hosted_prefix(&id_lower)),
    }

    // Read cache eagerly so stale data is available on upstream failure; the
    // freshness check rides the same store round trip.
    let ttl = state.config.nuget.metadata_ttl;
    let (read, validated_at) = tokio::join!(
        state.storage.get(&storage_key),
        crate::registry::stored_validated_at(&state.storage, &storage_key)
    );
    let fresh = validated_at.is_some_and(|t| crate::cache_ttl::is_within_ttl(t, ttl));
    let (cached_data, read_failure) = crate::registry::cached_read(read);

    // TTL cache
    if let Some(ref data) = cached_data {
        if fresh {
            state.metrics.record_download("nuget");
            state.metrics.record_cache_hit("nuget");
            return with_json(data.to_vec());
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
        if let Some(e) = &read_failure {
            return crate::registry::local_copy_unreadable("nuget", &storage_key, e);
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
    if stale_while_revalidate(&state, validated_at) {
        if let Some(ref data) = cached_data {
            refresh_in_background(&state, &storage_key, &url);
            state.metrics.record_download("nuget");
            state.metrics.record_cache_hit("nuget");
            return with_json_stale(data.to_vec());
        }
    }
    match refresh_metadata(&state, &storage_key, &url, activity).await {
        Ok(raw) => with_json(raw.to_vec()),
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::debug!(error = ?e, "NuGet version list error");
            serve_stale_or_error(&state, cached_data, "version_list", None, &e)
        }
    }
}

/// Serve the stale cached document now and refresh it behind the response
/// (stale-while-revalidate). One revalidation is up to seven serial storage
/// round-trips plus the upstream request, all on the client's critical path; on a
/// slow store that chain put 3–8 s on every `flatcontainer/*/index.json` of a CI
/// wave (NoraHighLatency 03.11.2026). Concurrent refreshes of one key coalesce in
/// `refresh_metadata`, so a wave starts one flight. The callers gate it on
/// `serve_stale`: an operator who turned that off wants nothing past its TTL served.
///
/// The caller counts the response it served; the refresh is nora's own read (no
/// `activity`). An upstream 404 drops the cached document and its validators: the
/// synchronous path answered 404 for it, and a stale copy would otherwise be served,
/// and refreshed in vain, forever. Any other failure keeps the stale copy.
fn refresh_in_background(state: &AppState, storage_key: &str, url: &str) {
    let state = state.clone();
    let storage_key = storage_key.to_string();
    let url = url.to_string();
    tokio::spawn(async move {
        match refresh_metadata(&state, &storage_key, &url, None).await {
            Ok(_) => {}
            Err(ProxyError::NotFound) => {
                let _ = state.storage.delete(&storage_key).await;
                let _ = state
                    .storage
                    .delete(&crate::registry::validators_key(&storage_key))
                    .await;
            }
            Err(e) => {
                tracing::debug!(key = %storage_key, error = ?e, "background NuGet metadata refresh failed");
            }
        }
    });
}

/// Whether a copy past its TTL, last written or revalidated at `validated_at`, is answered
/// at once and refreshed behind the response: `serve_stale`, and only within
/// `nuget.max_stale`. An older copy is revalidated before the answer (R4-R02): without the
/// bound a version list last asked for a week ago was served as it was, and the first
/// restore of a version published since failed with NU1102.
fn stale_while_revalidate(state: &AppState, validated_at: Option<u64>) -> bool {
    state.config.nuget.serve_stale
        && validated_at
            .is_some_and(|t| crate::cache_ttl::is_within_ttl(t, state.config.nuget.max_stale))
}

/// A response served past its TTL: clients must not cache it, and `x-nora-stale` says so.
fn mark_stale(mut resp: Response) -> Response {
    let headers = resp.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=0, must-revalidate"),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("x-nora-stale"),
        HeaderValue::from_static("true"),
    );
    resp
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
        let mut validators = if state.config.nuget.revalidate {
            read_validators(&state.storage, storage_key)
                .await
                .unwrap_or_default()
        } else {
            Validators::default()
        };
        let had_validators = validators.is_some();
        let (fetched, cached_body) = loop {
            let fetched = proxy_fetch_conditional(
                &state.http_client,
                url,
                Duration::from_secs(state.config.nuget.metadata_proxy_timeout),
                expose_opt(&state.config.nuget.proxy_auth).map(UpstreamAuth::Basic),
                &validators,
                &state.circuit_breaker,
                RegistryType::Nuget,
            )
            .await;
            // A 304 for a body that is gone (deleted by hand, or a half-finished drop that
            // left the validators): the validators describe nothing. Drop them and fetch
            // whole, once — else every request is a 304 and a 502 (R4-R10).
            if !matches!(fetched, Ok(Revalidation::NotModified)) {
                break (fetched, None);
            }
            match state.storage.get(storage_key).await {
                Ok(body) => break (fetched, Some(body)),
                Err(crate::storage::StorageError::NotFound) if validators.is_some() => {
                    let _ = state
                        .storage
                        .delete(&crate::registry::validators_key(storage_key))
                        .await;
                    validators = Validators::default();
                }
                Err(e) => return Err(ProxyError::Network(format!("cached body unreadable: {e}"))),
            }
        };
        match fetched {
            // Upstream unchanged — serve the cached body and record the revalidation
            // so we do not revalidate again until the next TTL window. No body is
            // downloaded, and none is re-uploaded (C56).
            Ok(Revalidation::NotModified) => {
                let Some(body) = cached_body else {
                    return Err(ProxyError::Network("cached body unreadable".into()));
                };
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

    let storage_key = format!("nuget/flatcontainer/{}", path.to_lowercase());

    // An imported package serves the versions it has records of and nothing else: a version
    // without one is no version of it, whatever an upstream served under the id before it was
    // imported.
    let Some(versions) = hosted_versions(&state.storage, &id_lower).await else {
        return crate::registry::storage_unavailable("nuget", &hosted_prefix(&id_lower));
    };
    let imported = match versions.version(&ver.to_lowercase()) {
        imported::Version::Own => true,
        imported::Version::Foreign => return StatusCode::NOT_FOUND.into_response(),
        imported::Version::Proxied => false,
    };

    // Hoisted to function scope for the digest-quarantine serve gate (#750).
    let mut publish_date: Option<i64> = None;
    // Curation check for .nupkg downloads (.nuspec is uncurated)
    if nupkg && !internal {
        // Q01: a flat-container restore never requests the registration, so the date
        // comes from the registration this primes. An imported version has no upstream
        // date, and no registration of an upstream dates it.
        // #754: the upstream is asked only on a cache miss. Maestra: an undated version is
        // judged by `on_failure` only once the upstream was asked; a stored package's digest is
        // recorded and its date left to the quarantine.
        let mut asked_upstream = false;
        if !imported {
            let ask_upstream = state.config.server.trust_upstream_dates
                && crate::registry::release_date_read(&state, RegistryType::Nuget)
                && state.storage.stat(&storage_key).await.is_none();
            asked_upstream = ask_upstream;
            publish_date = nuget_publish_date(&state, &id_lower, ver, ask_upstream).await;
        }

        if let Some(response) = crate::curation::check_download(
            &state.curation().curation_engine,
            state.bypass_token().as_deref(),
            &headers,
            crate::curation::RegistryType::Nuget,
            &id_lower,
            crate::curation::RequestVersion::Known(ver.to_string()),
            if asked_upstream {
                judged_date(&state, publish_date)
            } else {
                publish_date
            },
        ) {
            return response;
        }
    }

    // The quarantine takes a release date only when upstream dates are trusted (#750).
    let first_seen = crate::digest_quarantine::first_seen_seed(
        state.config.server.trust_upstream_dates,
        publish_date,
    );
    let content_type = if nupkg {
        "application/octet-stream"
    } else {
        "application/xml"
    };

    let (mut q_mode, q_secs) = crate::digest_quarantine::resolve_global(
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
    // An imported version is the operator's own publish, not an upstream artifact: never held
    // by the quarantine (as a hosted PyPI file, R2-23).
    if imported {
        q_mode = crate::digest_quarantine::QuarantineMode::Off;
    }
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
    let cached =
        match read_cached_artifact(&state, "nuget", &storage_key, internal || imported).await {
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
            // A digest with no record counts from when its copy was cached (R4-C05).
            if let Some(resp) = crate::digest_quarantine::cache_gate_digest(
                &state.digest_store,
                &state.storage,
                &storage_key,
                "nuget",
                &cached.digest(),
                &q_mode,
                q_secs,
                first_seen,
            )
            .await
            {
                return resp;
            }
        }

        return serve_artifact(
            &state,
            &headers,
            &storage_key,
            cached,
            nupkg,
            internal || imported,
        )
        .await;
    }

    // An imported version NORA no longer holds is not asked of an upstream (one it cannot read
    // was answered 503/500 above).
    if imported {
        return StatusCode::NOT_FOUND.into_response();
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
                    first_seen,
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
            CachedArtifact::Buffered { data, .. } => {
                crate::registry::range::range_response_from_bytes(
                    data,
                    headers,
                    content_type,
                    &extra,
                )
            }
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
/// { "items": [{ "lower": "1.0.0", "upper": "2.0.0", "items": [{ "catalogEntry": { "version": "1.0.0", "published": "2024-01-15T10:30:00Z" } }] }] }
/// ```
/// An unlisted version is dated from its catalog leaf ([`leaf_date`]).
/// `None` when upstream dates are untrusted (#513): the upstream date is spoofable,
/// and nora's cache mtime is no publish date either (C49: every metadata refresh
/// re-dated every version to now, and an old index matured a new version in the
/// quarantine at once). Min-release-age then defers to the quarantine's own clock.
/// An internal or hosted ID never reaches it (both return before curation).
///
/// The upstream is asked only when `ask_upstream` (#754): on a cache miss, while something
/// reads the date ([`crate::registry::release_date_read`]); otherwise the cached documents are
/// all there is.
async fn nuget_publish_date(
    state: &AppState,
    id: &str,
    version: &str,
    ask_upstream: bool,
) -> Option<i64> {
    if !state.config.server.trust_upstream_dates {
        return None;
    }
    let index_key = registration_key(id);
    let cached = read_json(&state.storage, &index_key).await;
    let hit = match cached.and_then(|doc| registration_hit(&doc, version)) {
        Some(hit) => hit,
        None if !ask_upstream => return None,
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
        None if !ask_upstream => return None,
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

/// On tokio's clock, so a test on a paused clock can expire an entry (outside tests it
/// is `std::time::Instant`).
struct HiddenEntry {
    at: tokio::time::Instant,
    curation: usize,
    hidden: Arc<HashSet<String>>,
    /// Every version the set was judged over: an expired entry still answers for a
    /// version list inside it.
    known: Arc<HashSet<String>>,
    /// When a background recompute of this expired entry started.
    refreshing: Option<tokio::time::Instant>,
}

/// A background recompute older than this is taken as lost and started again.
const HIDDEN_REFRESH_STALL: std::time::Duration = std::time::Duration::from_secs(60);

/// Memo entries kept before expired ones are dropped.
// ponytail: whole-map prune at the cap, an LRU if the restored-ID set gets that big.
const HIDDEN_MEMO_MAX: usize = 4096;

/// [`compute_hidden_versions`], memoized in [`HiddenMemo`].
///
/// An expired entry under the same curation config still answers a caller whose
/// `listed` versions it judged all of: it is served and recomputed behind the
/// response (one recompute per entry), like the stale index in
/// [`compute_hidden_versions`]. A low-traffic ID otherwise paid the index and page
/// reads on every restore more than `metadata_ttl` apart (NoraHighLatency
/// 03.11.2026). A listed version the entry does not know may be new and young, so
/// it waits for the recompute.
async fn hidden_versions(
    state: &AppState,
    id: &str,
    last_page_only: bool,
    listed: Option<&HashSet<String>>,
) -> Arc<HashSet<String>> {
    let ttl = std::time::Duration::from_secs(state.config.nuget.metadata_ttl.max(0) as u64);
    let curation = Arc::as_ptr(&*state.curation()) as usize;
    let memo = &state.nuget_hosted.hidden.0;
    let key = (id.to_string(), last_page_only);
    let mut refresh_behind = false;
    if let Some(e) = memo.lock().get_mut(&key) {
        if e.curation == curation {
            if e.at.elapsed() < ttl {
                return e.hidden.clone();
            }
            let covered = state.config.nuget.serve_stale
                && listed.is_some_and(|listed| listed.is_subset(&e.known));
            if covered {
                if e.refreshing
                    .is_none_or(|t| t.elapsed() > HIDDEN_REFRESH_STALL)
                {
                    e.refreshing = Some(tokio::time::Instant::now());
                    refresh_behind = true;
                }
                let hidden = e.hidden.clone();
                if refresh_behind {
                    let (state, id) = (state.clone(), id.to_string());
                    tokio::spawn(async move {
                        let (hidden, known) =
                            compute_hidden_versions(&state, &id, last_page_only, None).await;
                        remember_hidden(&state, (id, last_page_only), curation, hidden, known);
                    });
                }
                return hidden;
            }
        }
    }
    let (hidden, known) = compute_hidden_versions(state, id, last_page_only, listed).await;
    remember_hidden(state, key, curation, hidden, known)
}

/// Store a computed hidden set in [`HiddenMemo`] (not at all with a zero
/// `metadata_ttl`) and return it.
fn remember_hidden(
    state: &AppState,
    key: (String, bool),
    curation: usize,
    hidden: HashSet<String>,
    known: HashSet<String>,
) -> Arc<HashSet<String>> {
    let hidden = Arc::new(hidden);
    let ttl = std::time::Duration::from_secs(state.config.nuget.metadata_ttl.max(0) as u64);
    if ttl.is_zero() {
        return hidden;
    }
    let mut memo = state.nuget_hosted.hidden.0.lock();
    if memo.len() >= HIDDEN_MEMO_MAX {
        memo.retain(|_, e| e.at.elapsed() < ttl);
        if memo.len() >= HIDDEN_MEMO_MAX {
            memo.clear();
        }
    }
    let entry = HiddenEntry {
        at: tokio::time::Instant::now(),
        curation,
        hidden: hidden.clone(),
        known: Arc::new(known),
        refreshing: None,
    };
    memo.insert(key, entry);
    hidden
}

/// The versions of a proxied `id` metadata must hide, from its registration: the
/// index (fresh within `metadata_ttl` or revalidated within it, else refreshed through
/// [`refresh_metadata`]) and, for an ID whose pages are not inlined, the page
/// documents (cached by their bounds, fetched once, concurrently). `last_page_only`
/// reads only the newest page: search results show many IDs at once, and a fresh
/// version almost always lands there.
///
/// `listed` is the version list the caller is about to serve. A stale index that
/// dates every one of them is used as is and refreshed behind the response (publish
/// dates do not change), so the client does not wait on the store and upstream chain
/// (NoraHighLatency 03.11.2026). A listed version the stale index does not know may
/// be new, and young: then the index is refreshed first, as without `listed`.
async fn compute_hidden_versions(
    state: &AppState,
    id: &str,
    last_page_only: bool,
    listed: Option<&HashSet<String>>,
) -> (HashSet<String>, HashSet<String>) {
    let index_key = registration_key(id);
    let index_path = format!("{id}/index.json");
    let ttl = state.config.nuget.metadata_ttl;
    let (stored, is_fresh) = tokio::join!(
        read_json(&state.storage, &index_key),
        crate::registry::stored_fresh(&state.storage, &index_key, ttl)
    );
    let (fresh, stale) = if is_fresh {
        (stored, None)
    } else {
        (None, stored)
    };
    if fresh.is_none() && state.config.nuget.serve_stale {
        if let (Some(listed), Some(stored)) = (listed, stale) {
            let leaves = registration_leaves(state, id, &stored, last_page_only).await;
            let known = leaf_versions(&leaves);
            if listed.is_subset(&known) {
                let (bg, key, path) = (state.clone(), index_key.clone(), index_path.clone());
                tokio::spawn(async move { fetch_registration_doc(&bg, &key, &path).await });
                return (hidden_leaves(state, id, &leaves).await, known);
            }
        }
    }
    let index = match fresh {
        Some(doc) => Some(doc),
        None => match fetch_registration_doc(state, &index_key, &index_path).await {
            Some(doc) => Some(doc),
            None => read_json(&state.storage, &index_key).await,
        },
    };
    let Some(index) = index else {
        return (HashSet::new(), HashSet::new());
    };
    let leaves = registration_leaves(state, id, &index, last_page_only).await;
    (
        hidden_leaves(state, id, &leaves).await,
        leaf_versions(&leaves),
    )
}

/// The (lowercase) versions of registration `leaves`.
fn leaf_versions(leaves: &[serde_json::Value]) -> HashSet<String> {
    leaves
        .iter()
        .filter_map(|l| entry_version(l.get("catalogEntry")?))
        .collect()
}

/// The leaves of a registration `index`: its inlined pages, else the page documents
/// (cached by their bounds, fetched once, concurrently); only the newest page with
/// `last_page_only`.
async fn registration_leaves(
    state: &AppState,
    id: &str,
    index: &serde_json::Value,
    last_page_only: bool,
) -> Vec<serde_json::Value> {
    let Some(pages) = index.get("items").and_then(|i| i.as_array()).cloned() else {
        return Vec::new();
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
    docs.into_iter()
        .flatten()
        .filter_map(|d| d.get("items")?.as_array().cloned())
        .flatten()
        .collect()
}

/// The versions among `leaves` that metadata must hide.
async fn hidden_leaves(
    state: &AppState,
    id: &str,
    leaves: &[serde_json::Value],
) -> HashSet<String> {
    // ponytail: unbounded join; only undated leaves committed within min_release_age
    // fetch (once each), a semaphore if an upstream without commitTimeStamp shows up.
    futures::future::join_all(leaves.iter().map(|leaf| leaf_hidden(state, id, leaf)))
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
        // An imported package is never asked of an upstream, for its dates neither.
        && hosted_versions(&state.storage, id_lower)
            .await
            .is_some_and(|versions| !versions.hosted())
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
    let hidden = hidden_versions(&state, &id_lower, false, None).await;
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
    let hidden = hidden_versions(&state, &id_lower, false, None).await;
    crate::metadata_filter::rewrite_body(resp, |b| filter_registration(&hidden, b)).await
}

/// The SemVer 1.0.0 registration hives the older `RegistrationsBaseUrl` types promise
/// (as api.nuget.org's `registration5-semver1` / `registration5-gz-semver1`): the bare,
/// `/3.0.0-beta` and `/3.0.0-rc` types read [`HIVE_SEMVER1`] (no Content-Encoding),
/// `/3.4.0` reads [`HIVE_GZ_SEMVER1`] (gzip); both leave out SemVer 2.0.0 packages.
/// `/3.6.0` and `/Versioned` stay on [`HIVE_SEMVER2`] (gzip, SemVer 2.0.0 included).
const HIVE_SEMVER1: &str = "registration-semver1";
const HIVE_GZ_SEMVER1: &str = "registration-gz-semver1";
const HIVE_SEMVER2: &str = "registration";

async fn registration_index_semver1(
    state: State<AppState>,
    headers: axum::http::HeaderMap,
    id: Path<String>,
) -> Response {
    semver1_index(state, headers, id, HIVE_SEMVER1).await
}

async fn registration_page_semver1(
    state: State<AppState>,
    path: Path<(String, String, String)>,
) -> Response {
    semver1_page(state, path, HIVE_SEMVER1).await
}

async fn registration_index_gz_semver1(
    state: State<AppState>,
    headers: axum::http::HeaderMap,
    id: Path<String>,
) -> Response {
    semver1_index(state, headers, id, HIVE_GZ_SEMVER1).await
}

async fn registration_page_gz_semver1(
    state: State<AppState>,
    path: Path<(String, String, String)>,
) -> Response {
    semver1_page(state, path, HIVE_GZ_SEMVER1).await
}

/// `f` on the blocking pool when `big` (a registration document past
/// [`REGISTRATION_INLINE_MAX`], as in [`registration_response`]), else on this task.
async fn on_pool_if<T: Send + 'static>(
    big: bool,
    f: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    if !big {
        return Some(f());
    }
    tokio::task::spawn_blocking(f).await.ok()
}

/// The JSON of a 200 registration answer (gzip or not), its header parts and whether it
/// is big ([`on_pool_if`]). Any other answer comes back as `Err`, unchanged.
async fn registration_json(
    resp: Response,
) -> Result<(axum::http::response::Parts, serde_json::Value, bool), Response> {
    if resp.status() != StatusCode::OK {
        return Err(resp);
    }
    let (parts, body) = resp.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, usize::MAX).await else {
        return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
    };
    let gzipped = parts
        .headers
        .get(header::CONTENT_ENCODING)
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"gzip"));
    // Registration JSON gzips about 8:1: judge the size it inflates to.
    let big = bytes.len() > REGISTRATION_INLINE_MAX / if gzipped { 8 } else { 1 };
    let parse = move || {
        if !gzipped {
            return serde_json::from_slice::<serde_json::Value>(&bytes).ok();
        }
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&bytes[..]), &mut out).ok()?;
        serde_json::from_slice(&out).ok()
    };
    match on_pool_if(big, parse).await.flatten() {
        Some(doc) => Ok((parts, doc, big)),
        None => Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
    }
}

/// `doc` as `hive` serves it: every `/v3/registration/` URL moved to `/v3/<hive>/`, gzip
/// unless [`HIVE_SEMVER1`].
async fn hive_response(
    mut parts: axum::http::response::Parts,
    doc: serde_json::Value,
    hive: &'static str,
    big: bool,
) -> Response {
    parts.headers.remove(header::CONTENT_LENGTH);
    parts.headers.remove(header::CONTENT_ENCODING);
    let gzip = hive != HIVE_SEMVER1;
    let render = move || -> Option<Vec<u8>> {
        let text = serde_json::to_string(&doc).ok()?;
        let text = text.replace("/v3/registration/", &format!("/v3/{hive}/"));
        if !gzip {
            return Some(text.into_bytes());
        }
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut enc, text.as_bytes()).ok()?;
        enc.finish().ok()
    };
    let Some(body) = on_pool_if(big, render).await.flatten() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if gzip {
        parts
            .headers
            .insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    }
    Response::from_parts(parts, axum::body::Body::from(body))
}

async fn semver1_page(
    State(state): State<AppState>,
    path: Path<(String, String, String)>,
    hive: &'static str,
) -> Response {
    let resp = registration_page_filtered(State(state), path).await;
    let (parts, mut doc, big) = match registration_json(resp).await {
        Ok(ok) => ok,
        Err(resp) => return resp,
    };
    semver1_registration(&mut doc);
    hive_response(parts, doc, hive, big).await
}

/// A SemVer 1 index. A page served by reference takes its `count` and bounds from the
/// SemVer 1 page itself, and one with no SemVer 1 package left is dropped.
// ponytail: every referenced page is read for this (one storage read each once cached);
// only pre-4.3 clients ask these hives.
async fn semver1_index(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    hive: &'static str,
) -> Response {
    let resp = registration_index_filtered(State(state.clone()), headers, Path(id.clone())).await;
    let (parts, mut doc, big) = match registration_json(resp).await {
        Ok(ok) => ok,
        Err(resp) => return resp,
    };
    semver1_registration(&mut doc);
    if let Some(items) = doc.get_mut("items").and_then(|i| i.as_array_mut()) {
        let summaries = futures::future::join_all(
            items
                .iter()
                .map(|page| semver1_page_summary(&state, &id, page)),
        )
        .await;
        let mut keep = Vec::with_capacity(items.len());
        for (mut page, summary) in std::mem::take(items).into_iter().zip(summaries) {
            match summary {
                Some((0, _)) => continue,
                Some((count, bounds)) => {
                    page["count"] = serde_json::json!(count);
                    if let Some((lower, upper)) = bounds {
                        page["lower"] = serde_json::json!(lower);
                        page["upper"] = serde_json::json!(upper);
                    }
                }
                None => {}
            }
            keep.push(page);
        }
        *items = keep;
        let pages = items.len();
        doc["count"] = serde_json::json!(pages);
    }
    hive_response(parts, doc, hive, big).await
}

/// The `/page/<lower>/<upper>.json` route parameters of a page's `@id`.
fn page_ref(page: &serde_json::Value) -> Option<(String, String)> {
    let url = page.get("@id")?.as_str()?;
    let (lower, upper) = url.rsplit_once("/page/")?.1.split_once('/')?;
    Some((lower.to_string(), upper.to_string()))
}

/// For a page served by reference: the count and bounds of its SemVer 1 packages.
/// `None` for an inlined page, or when the page cannot be read (the entry stays as is).
async fn semver1_page_summary(
    state: &AppState,
    id: &str,
    page: &serde_json::Value,
) -> Option<(usize, Option<(String, String)>)> {
    if page.get("items").is_some() {
        return None;
    }
    let (lower, upper) = page_ref(page)?;
    let resp =
        registration_page_filtered(State(state.clone()), Path((id.to_string(), lower, upper)))
            .await;
    let (_, mut doc, _) = registration_json(resp).await.ok()?;
    semver1_registration(&mut doc);
    let leaves = doc.get("items")?.as_array()?;
    Some((leaves.len(), semver1_bounds(leaves)))
}

/// Whether a registration leaf belongs to SemVer 2.0.0 only, as NuGet classifies it: its
/// version, or a bound of one of its dependency ranges, is SemVer 2.0.0.
fn semver2_leaf(leaf: &serde_json::Value) -> bool {
    let Some(entry) = leaf.get("catalogEntry") else {
        return false;
    };
    if entry
        .get("version")
        .and_then(|v| v.as_str())
        .is_some_and(is_semver2_version)
    {
        return true;
    }
    let groups = entry.get("dependencyGroups").and_then(|g| g.as_array());
    groups
        .into_iter()
        .flatten()
        .filter_map(|g| g.get("dependencies")?.as_array())
        .flatten()
        .filter_map(|d| d.get("range")?.as_str())
        .flat_map(|range| range.trim_matches(['[', ']', '(', ')', ' ']).split(','))
        .any(|bound| is_semver2_version(bound.trim()))
}

/// Lowest and highest version among `leaves`, as their `catalogEntry` spells them.
fn semver1_bounds(leaves: &[serde_json::Value]) -> Option<(String, String)> {
    let mut versions = leaves
        .iter()
        .filter_map(|l| l.get("catalogEntry")?.get("version")?.as_str());
    let first = versions.next()?;
    let order = |a: &str, b: &str| hosted::compare_versions(&a.to_lowercase(), &b.to_lowercase());
    let (lower, upper) = versions.fold((first, first), |(lo, hi), v| {
        (
            if order(v, lo).is_lt() { v } else { lo },
            if order(v, hi).is_gt() { v } else { hi },
        )
    });
    Some((lower.to_string(), upper.to_string()))
}

/// A registration index or page without its SemVer 2.0.0 leaves ([`semver2_leaf`]):
/// `count`, `lower` and `upper` follow the leaves kept, an inlined page left empty is
/// dropped. A page served by reference is left to [`semver1_index`].
fn semver1_registration(doc: &mut serde_json::Value) {
    fn retain_semver1(page: &mut serde_json::Value) {
        let Some(leaves) = page.get_mut("items").and_then(|i| i.as_array_mut()) else {
            return;
        };
        leaves.retain(|l| !semver2_leaf(l));
        let count = leaves.len();
        let bounds = semver1_bounds(leaves);
        page["count"] = serde_json::json!(count);
        if let Some((lower, upper)) = bounds {
            page["lower"] = serde_json::json!(lower);
            page["upper"] = serde_json::json!(upper);
        }
    }
    let Some(items) = doc.get_mut("items").and_then(|i| i.as_array_mut()) else {
        return;
    };
    if items.iter().any(|i| i.get("catalogEntry").is_some()) {
        retain_semver1(doc);
        return;
    }
    for page in items.iter_mut() {
        retain_semver1(page);
    }
    items.retain(|p| p.get("items").is_none() || p["count"] != 0);
    let pages = items.len();
    doc["count"] = serde_json::json!(pages);
}

/// A registration leaf (`/v3/<hive>/{id}/{version}.json`, the `@id` of every leaf an
/// index or page lists), built from the leaf in that hive's index or page: hidden and,
/// in the SemVer 1 hives, SemVer 2.0.0 versions are 404 as they are absent there.
async fn registration_leaf(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((id, leaf)): Path<(String, String)>,
    hive: &'static str,
) -> Response {
    let Some(version) = leaf.strip_suffix(".json").map(str::to_lowercase) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !is_valid_version(&version) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let index = match hive {
        HIVE_SEMVER2 => {
            registration_index_filtered(State(state.clone()), headers, Path(id.clone())).await
        }
        _ => semver1_index(State(state.clone()), headers, Path(id.clone()), hive).await,
    };
    let (_, doc, _) = match registration_json(index).await {
        Ok(ok) => ok,
        Err(resp) => return resp,
    };
    let mut found = None;
    for page in doc
        .get("items")
        .and_then(|i| i.as_array())
        .into_iter()
        .flatten()
    {
        if let Some(leaves) = page.get("items").and_then(|i| i.as_array()) {
            found = find_leaf(leaves, &version);
        } else if let Some(RegistrationHit::Page(..)) =
            registration_hit(&serde_json::json!({ "items": [page] }), &version)
        {
            let Some((lower, upper)) = page_ref(page) else {
                continue;
            };
            let path = Path((id.clone(), lower, upper));
            let resp = match hive {
                HIVE_SEMVER2 => registration_page_filtered(State(state.clone()), path).await,
                _ => semver1_page(State(state.clone()), path, hive).await,
            };
            if let Ok((_, page, _)) = registration_json(resp).await {
                found = find_leaf(
                    page.get("items")
                        .and_then(|i| i.as_array())
                        .map_or(&[], |v| v),
                    &version,
                );
            }
        }
        if found.is_some() {
            break;
        }
    }
    let Some(item) = found else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let entry = &item["catalogEntry"];
    let mut out = serde_json::Map::new();
    for (key, value) in [
        ("@id", item.get("@id")),
        ("catalogEntry", entry.get("@id")),
        ("listed", entry.get("listed")),
        ("packageContent", item.get("packageContent")),
        ("published", entry.get("published")),
        ("registration", item.get("registration")),
    ] {
        if let Some(value) = value {
            out.insert(key.to_string(), value.clone());
        }
    }
    out.entry("listed").or_insert(serde_json::json!(true));
    let Ok(body) = serde_json::to_vec(&out) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if hive == HIVE_SEMVER1 {
        with_json(body)
    } else {
        with_json_gzip(body)
    }
}

/// Flat-container `index.json` — what `dotnet restore` resolves ranges against.
async fn version_list_filtered(state: AppState, id: &str) -> Response {
    let id_lower = id.to_lowercase();
    let resp = version_list(state.clone(), id).await;
    if resp.status() != StatusCode::OK || !filters_metadata(&state, &id_lower).await {
        return resp;
    }
    // The versions about to be served: a stale registration index that dates all of
    // them is good enough (compute_hidden_versions). Unparsed → None, the full path.
    let (parts, body) = resp.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, usize::MAX).await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let listed: Option<HashSet<String>> = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|d| {
            d.get("versions")?.as_array().map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .map(str::to_lowercase)
                    .collect()
            })
        });
    let hidden = hidden_versions(&state, &id_lower, false, listed.as_ref()).await;
    let resp = Response::from_parts(parts, axum::body::Body::from(bytes));
    crate::metadata_filter::rewrite_body(resp, |b| drop_versions(b, "versions", &hidden)).await
}

/// Autocomplete `?id=` lists one package's versions in `data`.
async fn filter_autocomplete_versions(state: &AppState, id: &str, body: String) -> Vec<u8> {
    let id_lower = id.to_lowercase();
    if !filters_metadata(state, &id_lower).await {
        return body.into_bytes();
    }
    let hidden = hidden_versions(state, &id_lower, false, None).await;
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
            hidden_versions(state, id, true, None).await
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

/// How NuGet orders two versions (`VersionComparer.Default`): by their numbers, then a
/// pre-release before its release, pre-release labels one by one — numbers by value and before
/// words, words without case — and a shorter run of equal labels first. Build metadata does not
/// count. `None` when either is not a NuGet version.
fn nuget_version_order(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    use std::cmp::Ordering;
    fn parts(version: &str) -> Option<(Vec<u64>, Option<String>)> {
        let key = crate::curation::nuget_version_key(version)?;
        let (release, pre) = match key.split_once('-') {
            Some((release, pre)) => (release.to_string(), Some(pre.to_string())),
            None => (key, None),
        };
        let mut numbers = release
            .split('.')
            .map(|n| n.parse().ok())
            .collect::<Option<Vec<u64>>>()?;
        numbers.resize(4, 0);
        Some((numbers, pre))
    }
    fn label(a: &str, b: &str) -> Ordering {
        let number = |s: &str| s.bytes().all(|c| c.is_ascii_digit());
        match (number(a), number(b)) {
            (true, true) => a.len().cmp(&b.len()).then_with(|| a.cmp(b)),
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => a.cmp(b),
        }
    }
    let ((a_numbers, a_pre), (b_numbers, b_pre)) = (parts(a)?, parts(b)?);
    Some(
        a_numbers
            .cmp(&b_numbers)
            .then_with(|| match (a_pre, b_pre) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(a), Some(b)) => {
                    let (mut a, mut b) = (a.split('.'), b.split('.'));
                    loop {
                        match (a.next(), b.next()) {
                            (None, None) => break Ordering::Equal,
                            (None, Some(_)) => break Ordering::Less,
                            (Some(_), None) => break Ordering::Greater,
                            (Some(x), Some(y)) => match label(x, y) {
                                Ordering::Equal => continue,
                                other => break other,
                            },
                        }
                    }
                }
            }),
    )
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
        Ok(compressed) => {
            let mut resp = (
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
                .into_response();
            // For the metadata filter and the leak scan behind this handler (R4-P06):
            // the document itself, so neither inflates the body just built.
            resp.extensions_mut()
                .insert(crate::metrics::PlainBody(data.into()));
            resp
        }
        Err(_) => with_json(data), // fallback: plain JSON if gzip fails
    }
}

/// A stored registration document up to this size is rewritten and compressed on the
/// request's own task: cheaper than a hop to the blocking pool.
const REGISTRATION_INLINE_MAX: usize = 64 * 1024;

/// The response for the stored registration document `raw`: upstream URLs rewritten to
/// NORA's, gzip. A popular ID's index with inlined pages is megabytes, and its copy,
/// rewrite and gzip are tens of milliseconds of CPU per request: above
/// [`REGISTRATION_INLINE_MAX`] that runs on the blocking pool, not on an async worker
/// every other request shares (R4-P13).
async fn registration_response(raw: Bytes, upstream: &str, base_url: &str) -> Response {
    let big = raw.len() > REGISTRATION_INLINE_MAX;
    let (upstream, base_url) = (upstream.to_string(), base_url.to_string());
    let render = move || {
        let text = String::from_utf8_lossy(&raw);
        with_json_gzip(rewrite_registration_urls(&text, &upstream, &base_url).into_bytes())
    };
    if !big {
        return render();
    }
    tokio::task::spawn_blocking(render)
        .await
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
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
            "@id": format!("{}/v3/package", nora_nuget),
            "@type": "PackagePublish/2.0.0",
            "comment": "Push, unlist (DELETE) and relist (POST) hosted packages"
        }),
    ];
    // Every registration @type api.nuget.org publishes, each on the hive its spec promises.
    // A client takes the first type of its own list that the index has: NuGet.Protocol up
    // to 6.x asks only for `/Versioned`, `/3.4.0` and `/3.0.0-beta`, newer ones also
    // `/3.6.0`, `/3.0.0-rc` and the bare type; with `/3.6.0` alone an old client gets no
    // registration base URL at all.
    for (version, hive, comment) in [
        ("", HIVE_SEMVER1, "SemVer 1.0.0, not compressed"),
        ("/3.0.0-beta", HIVE_SEMVER1, "SemVer 1.0.0, not compressed"),
        ("/3.0.0-rc", HIVE_SEMVER1, "SemVer 1.0.0, not compressed"),
        ("/3.4.0", HIVE_GZ_SEMVER1, "SemVer 1.0.0, gzip"),
        ("/3.6.0", "registration", "SemVer 2.0.0, gzip"),
        ("/Versioned", "registration", "SemVer 2.0.0, gzip"),
    ] {
        let mut resource = serde_json::json!({
            "@id": format!("{nora_nuget}/v3/{hive}/"),
            "@type": format!("RegistrationsBaseUrl{version}"),
            "comment": format!("Base URL of NuGet package registration info ({comment})")
        });
        if version == "/Versioned" {
            // As on api.nuget.org: the oldest client that reads gzip + SemVer 2.0.0 hives.
            resource["clientVersion"] = "4.3.0-alpha".into();
        }
        resources.push(resource);
    }
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

/// Rewrite upstream registration URLs in NuGet registration index/page responses: registration5-*
/// and v3-flatcontainer URLs point through NORA, catalog0 `@id`s are left as they are. The rewrite
/// is [`nora_registry::upstream_rewrite::rewrite_registration_urls`], the one the fuzz target
/// drives; this name is where the server calls it.
fn rewrite_registration_urls(json_text: &str, upstream_url: &str, base_url: &str) -> String {
    nora_registry::upstream_rewrite::rewrite_registration_urls(json_text, upstream_url, base_url)
}

// ── Hosted packages ─────────────────────────────────────────────────────
//
// Besides the pushed feed ([`hosted`]), `nora import` brings packages in from the operator's own
// registry. An imported version is stored under the flat-container keys a client reads — the .nupkg and its
// .nuspec — and a record of it under `nuget/hosted/<id>/<version>.json`. Before it stores anything
// of a package the import writes the marker `nuget/hosted/<id>/imported`. A package with the
// marker or a record is NORA's own: its version list and registration are built from the
// records, a version without one is not served, and no upstream is asked for the id.

/// The flat-container key of the .nupkg of `id` at `version`, as a client asks for it: the id and
/// the normalized version, both in lowercase. `None` when either is not NuGet's. `nora import`
/// stores a package under this key (contract `import-key-format-equals-handler-key-format`).
pub(crate) fn package_key(id: &str, version: &str) -> Option<String> {
    let id = id.to_lowercase();
    let version = crate::curation::nuget_version_key(version)?;
    (is_valid_package_id(&id) && is_valid_version(&version))
        .then(|| format!("nuget/flatcontainer/{id}/{version}/{id}.{version}.nupkg"))
}

/// The id and version (lowercase, normalized) a [`package_key`] names.
fn package_key_parts(key: &str) -> Option<(&str, &str)> {
    let (id, rest) = key.strip_prefix("nuget/flatcontainer/")?.split_once('/')?;
    let (version, file) = rest.split_once('/')?;
    (file == format!("{id}.{version}.nupkg")).then_some((id, version))
}

fn nuspec_key(id_lower: &str, version: &str) -> String {
    format!("nuget/flatcontainer/{id_lower}/{version}/{id_lower}.nuspec")
}

fn hosted_prefix(id_lower: &str) -> String {
    format!("nuget/hosted/{id_lower}/")
}

fn hosted_record_key(id_lower: &str, version: &str) -> String {
    format!("{}{version}.json", hosted_prefix(id_lower))
}

/// The marker that makes package `id_lower` hosted: `nora import` writes it before it stores
/// anything of the package, so an import that stops after it leaves the package hosted and
/// empty, and its id is not asked of an upstream.
fn hosted_marker_key(id_lower: &str) -> String {
    format!("{}imported", hosted_prefix(id_lower))
}

/// What a package's records say of it and of each of its versions, read from one listing of
/// them. What a version is, is asked of [`imported::Versions::version`] alone, and the list a
/// hosted package serves of [`imported::Versions::listed`]: the records are private to the module,
/// so no handler decides by them otherwise.
mod imported {
    /// What one version of a package is.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum Version {
        /// The package is not hosted: the version is what storage and the upstream hold.
        Proxied,
        /// The package is hosted and has a record of the version: it is served, and never asked
        /// of an upstream.
        Own,
        /// The package is hosted and has no record of the version: whatever an upstream served
        /// under the id before it was imported, it is no version of the package.
        Foreign,
    }

    /// Whether a package is hosted, and the versions it has records of (lowercase, normalized),
    /// in NuGet's order.
    pub(super) struct Versions {
        marker: bool,
        listed: Vec<String>,
    }

    impl Versions {
        /// A package nothing is recorded of.
        pub(super) fn none() -> Self {
            Self {
                marker: false,
                listed: Vec::new(),
            }
        }

        /// The records `names` name: the keys under the package's prefix, without it. The marker
        /// `imported` makes the package hosted, and so does a record of a version,
        /// `<version>.json`.
        pub(super) fn from_listing<'a>(names: impl IntoIterator<Item = &'a str>) -> Self {
            let names: Vec<&str> = names.into_iter().collect();
            let marker = names.contains(&"imported");
            let mut listed: Vec<String> = names
                .into_iter()
                .filter_map(|name| name.strip_suffix(".json"))
                // Only versions: a stray `latest.json` is no record, and NuGet order against
                // byte order for a non-version is no total order, which `sort_by` may panic on.
                .filter(|v| !v.contains('/') && crate::curation::nuget_version_key(v).is_some())
                .map(str::to_string)
                .collect();
            listed.sort_by(|a, b| super::nuget_version_order(a, b).unwrap_or_else(|| a.cmp(b)));
            Self { marker, listed }
        }

        /// Whether the package is hosted: its versions and registration are built from its
        /// records, and its id is not asked of an upstream.
        pub(super) fn hosted(&self) -> bool {
            self.marker || !self.listed.is_empty()
        }

        /// The versions a hosted package serves: those it has records of, and no other.
        pub(super) fn listed(&self) -> &[String] {
            &self.listed
        }

        /// What version `version` (lowercase, normalized) of the package is.
        pub(super) fn version(&self, version: &str) -> Version {
            match (self.hosted(), self.listed.iter().any(|v| v == version)) {
                (false, _) => Version::Proxied,
                (true, true) => Version::Own,
                (true, false) => Version::Foreign,
            }
        }
    }
}

/// The records of package `id_lower`, or `None` when the listing failed: nothing is decided on a
/// guess.
async fn hosted_versions(
    storage: &crate::storage::Storage,
    id_lower: &str,
) -> Option<imported::Versions> {
    let prefix = hosted_prefix(id_lower);
    if crate::validation::validate_storage_key(crate::validation::listing_key(&prefix)).is_err() {
        return Some(imported::Versions::none());
    }
    // Asked on every request of every ID, and empty for all but the imported ones: an
    // empty answer is remembered for `EMPTY_PREFIX_TTL` (R4-P01). A record written
    // through this process is seen at once, one written by another (a `nora import`
    // run, a second replica) within the TTL.
    match storage.list_often_empty(&prefix).await {
        Ok(keys) => Some(imported::Versions::from_listing(
            keys.iter().filter_map(|k| k.strip_prefix(&prefix)),
        )),
        Err(e) => {
            tracing::warn!(registry = "nuget", package = %id_lower, error = %e, "nuget: hosted records not listed");
            None
        }
    }
}

/// What NORA records of a hosted version: the .nuspec's id and version (normalized, in the case
/// the package gives it) and what a registration leaf shows of it.
#[derive(serde::Serialize, serde::Deserialize, Default, Debug, PartialEq)]
struct HostedRecord {
    id: String,
    version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    description: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    authors: String,
    #[serde(rename = "dependencyGroups", default)]
    dependency_groups: Vec<DependencyGroup>,
}

#[derive(serde::Serialize, serde::Deserialize, Default, Debug, PartialEq)]
struct DependencyGroup {
    #[serde(
        rename = "targetFramework",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    target_framework: String,
    #[serde(default)]
    dependencies: Vec<Dependency>,
}

#[derive(serde::Serialize, serde::Deserialize, Default, Debug, PartialEq)]
struct Dependency {
    id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    range: String,
}

/// What `nora import` stores beside an imported .nupkg: its .nuspec and its record, each with
/// its key. The record is written last — it is what makes the version served.
pub(crate) struct ImportedPackage {
    /// The marker that makes the package hosted, written before anything of it is stored.
    pub marker_key: String,
    pub nuspec_key: String,
    pub nuspec: Vec<u8>,
    pub record_key: String,
    pub record: Vec<u8>,
}

/// Why a .nupkg is not imported.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ImportedPackageError {
    #[error("not a NuGet package key: {0}")]
    NotAPackageKey(String),
    #[error("not a zip archive: {0}")]
    NotAZip(&'static str),
    #[error("the package has no .nuspec at its root")]
    NoNuspec,
    #[error("the package has more than one .nuspec at its root")]
    SeveralNuspecs,
    #[error("the .nuspec cannot be read: {0}")]
    Nuspec(&'static str),
    #[error("the .nuspec is not well-formed XML: {0}")]
    Xml(#[from] quick_xml::Error),
    #[error("the .nuspec is not well-formed XML: {0}")]
    Encoding(#[from] quick_xml::encoding::EncodingError),
    #[error("the .nuspec is not well-formed XML: {0}")]
    Escape(#[from] quick_xml::escape::EscapeError),
    #[error("the package is {found}, its key names {expected}")]
    Mismatch { found: String, expected: String },
    #[error("reading the package: {0}")]
    Io(#[from] std::io::Error),
    #[error("writing the record: {0}")]
    Record(#[from] serde_json::Error),
}

/// The .nuspec and the record of the .nupkg read from `nupkg`, to be stored under `package_key`.
/// The .nuspec must name the id and version the key does: a package of another id or version
/// is not imported under this one.
pub(crate) fn imported_package(
    package_key: &str,
    nupkg: impl std::io::Read + std::io::Seek,
) -> Result<ImportedPackage, ImportedPackageError> {
    let (id_lower, version) = package_key_parts(package_key)
        .ok_or_else(|| ImportedPackageError::NotAPackageKey(package_key.to_string()))?;
    let nuspec = root_nuspec(nupkg)?;
    let record = parse_nuspec(&nuspec)?;
    let found = format!(
        "{}@{}",
        record.id.to_lowercase(),
        crate::curation::nuget_version_key(&record.version).unwrap_or_default()
    );
    let expected = format!("{id_lower}@{version}");
    if found != expected {
        return Err(ImportedPackageError::Mismatch { found, expected });
    }
    Ok(ImportedPackage {
        marker_key: hosted_marker_key(id_lower),
        nuspec_key: nuspec_key(id_lower, version),
        nuspec,
        record_key: hosted_record_key(id_lower, version),
        record: serde_json::to_vec(&record)?,
    })
}

/// The largest .nuspec read from a package. NuGet itself refuses a manifest a fraction this size.
const NUSPEC_MAX: u64 = 1 << 20;
/// The largest central directory read from a package: a few hundred thousand entries.
const CENTRAL_DIRECTORY_MAX: u64 = 64 << 20;

fn le16(b: &[u8], at: usize) -> Option<u64> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?).into())
}

fn le32(b: &[u8], at: usize) -> Option<u64> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?).into())
}

/// The bytes of the one .nuspec at the root of the zip archive `zip`, checked against the size and
/// CRC-32 the archive records for it. Stored and deflated entries are read; a zip64 archive is not.
fn root_nuspec(
    mut zip: impl std::io::Read + std::io::Seek,
) -> Result<Vec<u8>, ImportedPackageError> {
    use std::io::{Read, SeekFrom};
    use ImportedPackageError::{NotAZip, Nuspec};
    const END_OF_DIRECTORY: u64 = 0x0605_4b50;
    const DIRECTORY_ENTRY: u64 = 0x0201_4b50;
    const LOCAL_HEADER: u64 = 0x0403_4b50;

    let len = zip.seek(SeekFrom::End(0))?;
    if len < 22 {
        return Err(NotAZip("shorter than an empty archive"));
    }
    // The end-of-directory record is the last 22 bytes before a comment of up to 64 KiB.
    let tail_len = len.min(22 + 0xFFFF);
    zip.seek(SeekFrom::Start(len - tail_len))?;
    let mut tail = vec![0; tail_len as usize];
    zip.read_exact(&mut tail)?;
    let end = (0..=tail.len() - 22)
        .rev()
        .find(|&at| le32(&tail, at) == Some(END_OF_DIRECTORY))
        .ok_or(NotAZip("no end of central directory"))?;
    let entries = le16(&tail, end + 10).ok_or(NotAZip("truncated end record"))?;
    let directory_len = le32(&tail, end + 12).ok_or(NotAZip("truncated end record"))?;
    let directory_at = le32(&tail, end + 16).ok_or(NotAZip("truncated end record"))?;
    if entries == 0xFFFF || directory_at == 0xFFFF_FFFF || directory_len == 0xFFFF_FFFF {
        return Err(NotAZip("zip64 archives are not read"));
    }
    if directory_len > CENTRAL_DIRECTORY_MAX || directory_at + directory_len > len {
        return Err(NotAZip("central directory out of bounds"));
    }
    zip.seek(SeekFrom::Start(directory_at))?;
    let mut directory = vec![0; directory_len as usize];
    zip.read_exact(&mut directory)?;

    let mut at = 0usize;
    let mut found = None;
    for _ in 0..entries {
        let entry = directory
            .get(at..)
            .ok_or(NotAZip("truncated central directory"))?;
        let read = |offset: usize, width: usize| {
            match width {
                2 => le16(entry, offset),
                _ => le32(entry, offset),
            }
            .ok_or(NotAZip("truncated central directory"))
        };
        if read(0, 4)? != DIRECTORY_ENTRY {
            return Err(NotAZip("bad central directory entry"));
        }
        let (method, crc, packed, size) = (read(10, 2)?, read(16, 4)?, read(20, 4)?, read(24, 4)?);
        let name_len = read(28, 2)? as usize;
        let skip = (read(30, 2)? + read(32, 2)?) as usize;
        let local = read(42, 4)?;
        let name = entry
            .get(46..46 + name_len)
            .ok_or(NotAZip("truncated central directory"))?;
        if !name.contains(&b'/') && name.to_ascii_lowercase().ends_with(b".nuspec") {
            if found.is_some() {
                return Err(ImportedPackageError::SeveralNuspecs);
            }
            found = Some((method, crc, packed, size, local));
        }
        at += 46 + name_len + skip;
    }
    let (method, crc, packed, size, local) = found.ok_or(ImportedPackageError::NoNuspec)?;
    if size > NUSPEC_MAX {
        return Err(Nuspec("larger than 1 MiB"));
    }
    zip.seek(SeekFrom::Start(local))?;
    let mut header = [0u8; 30];
    zip.read_exact(&mut header)?;
    if le32(&header, 0) != Some(LOCAL_HEADER) {
        return Err(NotAZip("bad local header"));
    }
    let skip = le16(&header, 26).unwrap_or(0) + le16(&header, 28).unwrap_or(0);
    zip.seek(SeekFrom::Current(skip as i64))?;
    let packed_body = zip.take(packed);
    let mut nuspec = Vec::new();
    match method {
        0 => packed_body.take(NUSPEC_MAX + 1).read_to_end(&mut nuspec)?,
        8 => flate2::read::DeflateDecoder::new(packed_body)
            .take(NUSPEC_MAX + 1)
            .read_to_end(&mut nuspec)?,
        _ => return Err(Nuspec("compressed with a method other than deflate")),
    };
    let mut check = flate2::Crc::new();
    check.update(&nuspec);
    if nuspec.len() as u64 != size || u64::from(check.sum()) != crc {
        return Err(Nuspec(
            "its bytes do not match the size and CRC-32 the archive records",
        ));
    }
    Ok(nuspec)
}

/// The record of a .nuspec: `package/metadata`'s id, version (normalized), description, authors
/// and dependency groups — a `<dependencies>` without groups is one group for every framework.
fn parse_nuspec(nuspec: &[u8]) -> Result<HostedRecord, ImportedPackageError> {
    use quick_xml::events::{BytesStart, Event};
    use ImportedPackageError::Nuspec;
    fn attribute(element: &BytesStart, name: &[u8]) -> String {
        element
            .attributes()
            .flatten()
            .find(|a| a.key.local_name().as_ref() == name)
            .and_then(|a| {
                let raw = String::from_utf8(a.value.to_vec()).ok()?;
                Some(quick_xml::escape::unescape(&raw).ok()?.into_owned())
            })
            .unwrap_or_default()
    }

    let mut reader = quick_xml::Reader::from_reader(nuspec);
    reader.config_mut().trim_text(true);
    let mut record = HostedRecord::default();
    let mut path: Vec<Vec<u8>> = Vec::new();
    // The group the dependencies being read belong to, and the one of dependencies listed
    // without a group.
    let (mut group, mut flat): (Option<usize>, Option<usize>) = (None, None);
    loop {
        let event = reader.read_event()?;
        let (element, empty) = match &event {
            Event::Start(e) => (e, false),
            Event::Empty(e) => (e, true),
            Event::End(_) => {
                path.pop();
                continue;
            }
            // A document that ends inside an element is cut short.
            Event::Eof if path.is_empty() => break,
            Event::Eof => return Err(Nuspec("not well-formed XML")),
            _ => continue,
        };
        let name = element.local_name().as_ref().to_vec();
        let parents: Vec<&[u8]> = path.iter().map(Vec::as_slice).collect();
        match (parents.as_slice(), name.as_slice()) {
            (
                [b"package", b"metadata"],
                field @ (b"id" | b"version" | b"description" | b"authors"),
            ) if !empty => {
                let text = reader.read_text(element.name())?.decode()?.into_owned();
                let text = quick_xml::escape::unescape(&text)?.trim().to_string();
                match field {
                    b"id" => record.id = text,
                    b"version" => record.version = text,
                    b"description" => record.description = text,
                    _ => record.authors = text,
                }
                // `read_text` consumed the end tag.
                continue;
            }
            ([b"package", b"metadata", b"dependencies"], b"group") => {
                record.dependency_groups.push(DependencyGroup {
                    target_framework: attribute(element, b"targetFramework"),
                    dependencies: Vec::new(),
                });
                group = Some(record.dependency_groups.len() - 1);
            }
            ([b"package", b"metadata", b"dependencies", b"group"], b"dependency") => {
                if let Some(group) = group.and_then(|at| record.dependency_groups.get_mut(at)) {
                    group.dependencies.push(Dependency {
                        id: attribute(element, b"id"),
                        range: attribute(element, b"version"),
                    });
                }
            }
            ([b"package", b"metadata", b"dependencies"], b"dependency") => {
                let at = *flat.get_or_insert_with(|| {
                    record.dependency_groups.push(DependencyGroup::default());
                    record.dependency_groups.len() - 1
                });
                record.dependency_groups[at].dependencies.push(Dependency {
                    id: attribute(element, b"id"),
                    range: attribute(element, b"version"),
                });
            }
            _ => {}
        }
        if !empty {
            path.push(name);
        }
    }
    let normalized = crate::curation::nuget_version_key(&record.version)
        .ok_or(Nuspec("names no NuGet version"))?;
    if record.id.is_empty() || !is_valid_package_id(&record.id.to_lowercase()) {
        return Err(Nuspec("names no valid package id"));
    }
    // The normalized numbers, and the pre-release labels in the case the package gives them.
    let numbers = normalized
        .split_once('-')
        .map_or(normalized.as_str(), |(n, _)| n);
    let labels = record
        .version
        .split('+')
        .next()
        .and_then(|release| release.split_once('-'))
        .map(|(_, labels)| labels.trim());
    record.version = match labels {
        Some(labels) => format!("{numbers}-{labels}"),
        None => numbers.to_string(),
    };
    Ok(record)
}

/// The registration of a hosted package, built from its records: one inline page that lists every
/// version with its .nupkg in NORA's flat container and its dependency groups.
async fn hosted_registration(state: &AppState, id_lower: &str, versions: &[String]) -> Response {
    let nuget = format!("{}/nuget/v3", nora_base_url(state).trim_end_matches('/'));
    let registration = format!("{nuget}/registration/{id_lower}/index.json");
    let mut leaves = Vec::with_capacity(versions.len());
    let mut range: Option<(String, String)> = None;
    for version in versions {
        let key = hosted_record_key(id_lower, version);
        let record: HostedRecord = match state.storage.get(&key).await {
            Ok(data) => match serde_json::from_slice(&data) {
                Ok(record) => record,
                Err(e) => {
                    tracing::warn!(key = %key, error = %e, "nuget: hosted record not readable");
                    return crate::registry::storage_unavailable("nuget", &key);
                }
            },
            // Deleted since the listing: the version is no longer hosted.
            Err(crate::storage::StorageError::NotFound) => continue,
            Err(_) => return crate::registry::storage_unavailable("nuget", &key),
        };
        let content =
            format!("{nuget}/flatcontainer/{id_lower}/{version}/{id_lower}.{version}.nupkg");
        let leaf = format!("{nuget}/registration/{id_lower}/{version}.json");
        let groups: Vec<serde_json::Value> = record
            .dependency_groups
            .iter()
            .map(|group| {
                let mut value = serde_json::json!({
                    "@type": "PackageDependencyGroup",
                    "dependencies": group.dependencies.iter().map(|d| serde_json::json!({
                        "@type": "PackageDependency",
                        "id": d.id,
                        "range": d.range,
                    })).collect::<Vec<_>>(),
                });
                if !group.target_framework.is_empty() {
                    value["targetFramework"] = group.target_framework.clone().into();
                }
                value
            })
            .collect();
        range = Some(match range {
            None => (record.version.clone(), record.version.clone()),
            Some((lower, _)) => (lower, record.version.clone()),
        });
        leaves.push(serde_json::json!({
            "@id": leaf,
            "@type": "Package",
            "catalogEntry": {
                "@id": leaf,
                "@type": "PackageDetails",
                "id": record.id,
                "version": record.version,
                "description": record.description,
                "authors": record.authors,
                "listed": true,
                "packageContent": content,
                "dependencyGroups": groups,
            },
            "packageContent": content,
            "registration": registration,
        }));
    }
    let Some((lower, upper)) = range else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let doc = serde_json::json!({
        "@id": registration,
        "@type": ["catalog:CatalogRoot", "PackageRegistration", "catalog:Permalink"],
        "count": 1,
        "items": [{
            "@id": format!("{registration}#page/{lower}/{upper}"),
            "@type": "catalog:CatalogPage",
            "count": leaves.len(),
            "lower": lower,
            "upper": upper,
            "parent": registration,
            "items": leaves,
        }],
    });
    state.metrics.record_download("nuget");
    with_json_gzip(doc.to_string().into_bytes())
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
mod tests;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests;

// ── Spec conformance tests (#390) ─────────────────────────────────────
//
// Invariant: after URL rewriting, no upstream domains remain in the response.
// Uses golden fixtures from testdata/nuget/ to validate against realistic
// upstream payloads, not just synthetic test data.

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod spec_conformance_tests;

/// A NuGet version is the version NuGet reads, not its spelling: clients put the normal form
/// in lowercase into flat-container URLs (`NuGetVersion.ToNormalizedString()`), so a rule or an
/// allowlist entry holds however it spells its version — `13.0` is `13.0.0`, `1.0.0.0` is
/// `1.0.0`, `2.0.0-Beta1` is `2.0.0-beta1`, build metadata does not count.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod nuget_version_curation;

/// How a NuGet download is dated for release age and the quarantine clock. The flat-container
/// download a `dotnet restore` makes never reads the registration, so the date comes from what
/// NORA holds of it, and from the upstream registration when that does not date the version.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod nuget_release_dates;

#[cfg(test)]
mod imported_memo_tests;
