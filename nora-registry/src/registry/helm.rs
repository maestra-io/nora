// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Helm chart repository proxy (maestra): classic `index.yaml` + `.tgz` repositories,
//! one per `[helm.proxies]` entry, pull-through only.
//!
//!   GET /helm/{repo}/index.yaml                   — the upstream index, filtered
//!   GET /helm/{repo}/charts/{name}/{name}-{version}.tgz — a chart archive
//!
//! The index is fetched under `metadata_ttl` and kept as JSON (`helm/index/{repo}.json`,
//! upstream URLs untouched). On serve, internal-namespace charts and versions whose
//! digest the quarantine holds (enforce, already seen and not yet mature) are left out,
//! and so are versions younger than `min_release_age` by the index's `created`, for the
//! repos in `[helm] trust_created` only (others re-stamp `created` on every rebuild).
//! Every chart URL becomes the relative `charts/{name}/{name}-{version}.tgz`, so clients
//! download through NORA whatever host the upstream names. The answer is JSON, which is
//! YAML: Helm, Flux and Renovate read it as `index.yaml`.
//!
//! A chart is fetched from the URL the cached index names for that name and version
//! (never from client input), checked against the index `digest`, cached under
//! `helm/charts/{name}/{repo}/` and held by the digest quarantine like any proxy
//! artifact: first seen by NORA, seeded from `created` only with
//! `server.trust_upstream_dates` and the repo in `trust_created`.
//!
//! Client:
//!   helm repo add jetstack https://nora.example.com/helm/jetstack

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::cache_ttl::is_within_ttl;
use crate::circuit_breaker::BreakerScope;
use crate::config::{RepoProxyEntry, UpstreamAuth};
use crate::registry::{circuit_open_response, proxy_error_response, ProxyError};
use crate::registry_type::RegistryType;
use crate::AppState;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::time::Duration;

/// Chart archives, one directory per chart name: the repo index counts charts by name.
pub const INDEX_PATTERN: (&str, &str) = ("helm/charts/", ".tgz");

/// Largest upstream `index.yaml` parsed (prometheus-community's is ~7 MiB).
const MAX_INDEX_BYTES: usize = 128 * 1024 * 1024;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/helm/{repo}/index.yaml", get(index))
        .route("/helm/{repo}/charts/{name}/{file}", get(chart))
}

/// A chart repository index. Helm's own fields are typed as strings, so a scalar such
/// as `version: 1.10` keeps its spelling; everything else passes through as is. A null
/// entry or field is skipped as Helm skips it, not a reason to refuse the whole index.
#[derive(Debug, Serialize, Deserialize)]
struct IndexFile {
    #[serde(rename = "apiVersion", default)]
    api_version: String,
    #[serde(default, deserialize_with = "entries_without_nulls")]
    entries: BTreeMap<String, Vec<ChartVersion>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    generated: Option<String>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChartVersion {
    #[serde(default, deserialize_with = "null_as_default")]
    name: String,
    #[serde(default, deserialize_with = "null_as_default")]
    version: String,
    #[serde(
        rename = "appVersion",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    app_version: Option<String>,
    #[serde(
        rename = "kubeVersion",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    kube_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    created: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    digest: Option<String>,
    #[serde(default, deserialize_with = "null_as_default")]
    urls: Vec<String>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

fn null_as_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

fn entries_without_nulls<'de, D>(d: D) -> Result<BTreeMap<String, Vec<ChartVersion>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = BTreeMap::<String, Option<Vec<Option<ChartVersion>>>>::deserialize(d)?;
    Ok(raw
        .into_iter()
        .map(|(name, versions)| (name, versions.into_iter().flatten().flatten().collect()))
        .collect())
}

impl ChartVersion {
    /// The index digest as hex sha256 (`helm repo index` writes it bare; `sha256:`
    /// accepted), if the entry has one.
    fn sha256(&self) -> Option<&str> {
        let d = self.digest.as_deref()?;
        let d = d.strip_prefix("sha256:").unwrap_or(d);
        (!d.is_empty()).then_some(d)
    }

    fn created_unix(&self) -> Option<i64> {
        self.created
            .as_deref()
            .and_then(crate::curation::parse_iso8601_to_unix)
    }
}

/// Parse an upstream `index.yaml` under a budget sized for large repositories; aliases
/// and anchors keep the parser's default limits (alias bombs).
fn parse_index_yaml(bytes: &[u8]) -> Result<IndexFile, String> {
    if bytes.len() > MAX_INDEX_BYTES {
        return Err(format!("index is {} bytes", bytes.len()));
    }
    let mut budget = serde_saphyr::Budget::default();
    budget.max_events = 50_000_000;
    budget.max_nodes = 25_000_000;
    budget.max_total_scalar_bytes = MAX_INDEX_BYTES;
    let mut options = serde_saphyr::Options::default();
    options.budget = Some(budget);
    let index: IndexFile =
        serde_saphyr::from_slice_with_options(bytes, options).map_err(|e| e.to_string())?;
    if index.api_version.is_empty() {
        return Err("no apiVersion".to_string());
    }
    Ok(index)
}

/// Chart names as Helm writes them: letters, digits, `-`, `_`, `.`, not starting with `.`.
fn is_valid_chart_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 250
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// SemVer characters (`+` build metadata included), not starting with `.`.
fn is_valid_chart_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 128
        && !version.starts_with('.')
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+'))
}

fn chart_file(name: &str, version: &str) -> String {
    format!("{name}-{version}.tgz")
}

/// Hide internal-namespace charts, versions whose digest is `held`, and (when the
/// repo's `created` is `dated`) versions younger than `min_release_age`; point every
/// chart URL back at NORA. A version NORA could not serve (a name or version it does
/// not route, or no digest to check the archive against) is left out.
fn render_index(
    engine: &crate::curation::CurationEngine,
    index: &mut IndexFile,
    dated: bool,
    held: impl Fn(&str) -> bool,
) {
    index.entries.retain(|name, versions| {
        if !is_valid_chart_name(name)
            || crate::curation::is_internal_namespace(engine, RegistryType::Helm, name)
        {
            return false;
        }
        versions.retain(|v| {
            is_valid_chart_version(&v.version)
                && v.sha256().is_some_and(|d| !held(d))
                && !(dated
                    && engine.hides_from_metadata(
                        RegistryType::Helm,
                        name,
                        &v.version,
                        v.created_unix(),
                    ))
        });
        for v in versions.iter_mut() {
            v.urls = vec![format!("charts/{name}/{}", chart_file(name, &v.version))];
        }
        !versions.is_empty()
    });
}

/// The URL of a chart `url` from the index of the upstream at `base`: relative URLs
/// resolve against the repository URL as Helm resolves them. Only https is fetched,
/// or plain http from an upstream configured as plain http.
fn resolve_chart_url(base: &str, url: &str) -> Option<String> {
    let base = reqwest::Url::parse(&format!("{}/", base.trim_end_matches('/'))).ok()?;
    let resolved = base.join(url).ok()?;
    (resolved.scheme() == "https" || (resolved.scheme() == "http" && base.scheme() == "http"))
        .then(|| resolved.to_string())
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

/// The client for every chart download: it never connects to a
/// loopback, private, link-local or metadata address, on the first request or on any
/// redirect hop (DNS pinned; the `nora import` guard, `crate::import::http`).
fn guarded_client(state: &AppState) -> Result<&'static reqwest::Client, String> {
    static CLIENT: std::sync::OnceLock<Result<reqwest::Client, String>> =
        std::sync::OnceLock::new();
    CLIENT
        .get_or_init(|| {
            crate::import::http::build_import_client(
                &state.config.tls,
                Duration::from_secs(10),
                Duration::from_secs(state.config.helm.proxy_timeout.max(1)),
                false,
            )
        })
        .as_ref()
        .map_err(Clone::clone)
}

fn upstream<'a>(state: &'a AppState, repo: &str) -> Option<&'a RepoProxyEntry> {
    state.config.helm.proxies.get(repo)
}

/// Whether `repo`'s index `created` is a release date (`[helm] trust_created`).
fn dated(state: &AppState, repo: &str) -> bool {
    state.config.helm.trust_created.iter().any(|r| r == repo)
}

/// The effective `(mode, ttl_secs)` of the helm quarantine.
fn quarantine(state: &AppState) -> (crate::digest_quarantine::QuarantineMode, i64) {
    let curation = &state.config.curation;
    crate::digest_quarantine::resolve_global(
        curation
            .helm
            .quarantine
            .as_ref()
            .or(curation.quarantine.as_ref()),
        curation
            .helm
            .quarantine_ttl
            .as_deref()
            .or(curation.quarantine_ttl.as_deref()),
    )
}

/// The ledger key of an index digest (hex sha256).
fn ledger_digest(sha256: &str) -> String {
    format!("sha256:{}", sha256.to_lowercase())
}

fn index_key(repo: &str) -> String {
    format!("helm/index/{repo}.json")
}

/// Parse the cached JSON form of an index off the async runtime (several MB for the
/// largest repositories).
async fn parse_cached_index(data: Bytes) -> Option<IndexFile> {
    tokio::task::spawn_blocking(move || serde_json::from_slice(&data).ok())
        .await
        .ok()
        .flatten()
}

/// The cached index of `key` if it is younger than `metadata_ttl`.
async fn fresh_index(state: &AppState, key: &str) -> Option<IndexFile> {
    let meta = state.storage.stat(key).await?;
    if !is_within_ttl(meta.modified, state.config.helm.metadata_ttl) {
        return None;
    }
    parse_cached_index(state.storage.get(key).await.ok()?).await
}

/// The last cached index of `key` whatever its age, when `serve_stale` allows it.
async fn stale_index(state: &AppState, key: &str) -> Option<IndexFile> {
    if !state.config.helm.serve_stale {
        return None;
    }
    parse_cached_index(state.storage.get(key).await.ok()?).await
}

/// The upstream index of `repo` (JSON form) and whether it is a stale copy, or the
/// response to give when there is none. One refresh per repo runs at a time: a request
/// arriving meanwhile gets the stale copy at once, or (with none) waits for the
/// refresh and reads what it cached.
async fn load_index(
    state: &AppState,
    repo: &str,
    up: &RepoProxyEntry,
) -> Result<(IndexFile, bool), Response> {
    let key = index_key(repo);
    if let Some(index) = fresh_index(state, &key).await {
        return Ok((index, false));
    }
    let lock = state.publish_lock(&key);
    let _refresh = match lock.try_lock() {
        Ok(guard) => guard,
        Err(_) => {
            if let Some(index) = stale_index(state, &key).await {
                return Ok((index, true));
            }
            lock.lock().await
        }
    };
    if let Some(index) = fresh_index(state, &key).await {
        return Ok((index, false));
    }

    let base = up.url().trim_end_matches('/');
    let url = format!("{base}/index.yaml");
    let fetched = crate::registry::proxy_fetch_capped(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.helm.proxy_timeout),
        up.auth().map(UpstreamAuth::Basic),
        &state.circuit_breaker,
        BreakerScope::upstream(RegistryType::Helm, up.url()),
        MAX_INDEX_BYTES as u64,
    )
    .await;
    let err = match fetched {
        Ok(body) => match tokio::task::spawn_blocking(move || {
            let index = parse_index_yaml(&body)?;
            let json = serde_json::to_vec(&index).map_err(|e| e.to_string())?;
            Ok::<_, String>((index, json))
        })
        .await
        {
            Ok(Ok((index, json))) => {
                if let Err(e) = state.storage.put(&key, &json).await {
                    tracing::warn!(key = %key, error = %e, "helm: failed to cache index");
                }
                return Ok((index, false));
            }
            Ok(Err(e)) => {
                tracing::warn!(repo, url = %url, error = %e, "helm: upstream index unreadable");
                ProxyError::Upstream(502)
            }
            Err(e) => ProxyError::Network(e.to_string()),
        },
        Err(e) => e,
    };
    // Any failure, a 404 included (a static host mid-deploy), falls back to the last copy.
    if let Some(index) = stale_index(state, &key).await {
        tracing::warn!(registry = "helm", repo, error = ?err, "Helm upstream error, serving stale index");
        return Ok((index, true));
    }
    Err(match err {
        ProxyError::NotFound => StatusCode::NOT_FOUND.into_response(),
        ProxyError::CircuitOpen(reg) => circuit_open_response(&reg),
        e => proxy_error_response("helm", &url, &e),
    })
}

async fn index(State(state): State<AppState>, Path(repo): Path<String>) -> Response {
    let Some(up) = upstream(&state, &repo) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let (mut index, stale) = match load_index(&state, &repo, up).await {
        Ok(loaded) => loaded,
        Err(response) => return response,
    };
    let (q_mode, q_secs) = quarantine(&state);
    let enforce = matches!(q_mode, crate::digest_quarantine::QuarantineMode::Enforce);
    // Only a digest already seen and still young is held: an unseen one must stay
    // visible, or nothing would ever fetch it and start its clock.
    let held = |sha256: &str| {
        enforce
            && matches!(
                state
                    .digest_store
                    .check("helm", &ledger_digest(sha256), q_secs),
                crate::digest_quarantine::QuarantineStatus::Pending { .. }
            )
    };
    render_index(
        &state.curation().curation_engine,
        &mut index,
        dated(&state, &repo),
        held,
    );
    let body = match tokio::task::spawn_blocking(move || serde_json::to_vec(&index)).await {
        Ok(Ok(body)) => body,
        _ => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let mut response = (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/x-yaml"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=0, must-revalidate"),
            ),
        ],
        body,
    )
        .into_response();
    if stale {
        response.headers_mut().insert(
            HeaderName::from_static("x-nora-stale"),
            HeaderValue::from_static("true"),
        );
    }
    response
}

async fn chart(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((repo, name, file)): Path<(String, String, String)>,
) -> Response {
    let Some(up) = upstream(&state, &repo) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let version = file
        .strip_prefix(&format!("{name}-"))
        .and_then(|rest| rest.strip_suffix(".tgz"));
    let Some(version) = version.filter(|v| is_valid_chart_version(v)) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !is_valid_chart_name(&name) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let engine = &state.curation().curation_engine;

    // An internal chart name is never fetched from an upstream (dependency confusion).
    if let Some(response) =
        crate::curation::check_namespace_isolation(engine, RegistryType::Helm, &name)
    {
        return response;
    }

    // The index names the chart's date, digest and upstream URL. A cached chart needs
    // it only for its date, which only a `trust_created` repo has: there the index (a
    // stale copy will do) is required, as serving without the date would skip the
    // release age; elsewhere a cached chart is served without asking the upstream.
    let lookup = |index: IndexFile| {
        index
            .entries
            .get(&name)
            .and_then(|versions| versions.iter().find(|v| v.version == version).cloned())
    };
    let dated = dated(&state, &repo);
    let mut entry = None;
    if dated {
        match load_index(&state, &repo, up).await {
            Ok((index, _)) => entry = Some(lookup(index)),
            Err(response) => return response,
        }
    }
    // `created` dates a chart only in a repo that does not re-stamp it: there it is the
    // release age, and with `trust_upstream_dates` also the quarantine's first seen.
    let created = entry
        .as_ref()
        .and_then(Option::as_ref)
        .and_then(ChartVersion::created_unix);
    let publish_date = created.filter(|_| state.config.server.trust_upstream_dates);

    if let Some(response) = crate::curation::check_download(
        engine,
        state.bypass_token().as_deref(),
        &headers,
        RegistryType::Helm,
        &name,
        crate::curation::RequestVersion::Known(version.to_string()),
        created,
    ) {
        return response;
    }

    let (q_mode, q_secs) = quarantine(&state);
    let key = format!("helm/charts/{name}/{repo}/{file}");
    let label = format!("{repo}/{file}");

    // Integrity-gated: a copy failing its pin is dropped and refetched, a storage
    // fault answers 503.
    let cached = match crate::registry::read_cached_artifact(&state, "helm", &key, false).await {
        Ok(cached) => cached,
        Err(response) => return response,
    };
    if let Some(cached) = cached {
        let digest = cached.digest();
        if let Some(response) = crate::curation::verify_integrity_by_hash(
            engine,
            RegistryType::Helm,
            &name,
            Some(version),
            &digest,
        ) {
            return response;
        }
        state.metrics.record_download("helm");
        state.metrics.record_cache_hit("helm");
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            label,
            RegistryType::Helm,
            "CACHE",
        ));
        state
            .audit
            .log(AuditEntry::new("cache_hit", "proxy", "", "helm", ""));
        if let Some(resp) = crate::digest_quarantine::proxy_gate_digest(
            &state.digest_store,
            "helm",
            &digest,
            &q_mode,
            q_secs,
            "cache",
            publish_date,
        ) {
            return resp;
        }
        let len = cached.len();
        return chart_response(len, cached.into_body(&state, "helm", &key, false));
    }

    let entry = match entry {
        Some(entry) => entry,
        // No index and no copy: the upstream's failure, not a 404 Helm would read as
        // "no such version".
        None => match load_index(&state, &repo, up).await {
            Ok((index, _)) => lookup(index),
            Err(response) => return response,
        },
    };
    let Some(entry) = entry else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // Without a digest nothing vouches for the archive (and the index leaves it out).
    let Some(expected) = entry.sha256() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(url) = entry
        .urls
        .first()
        .and_then(|u| resolve_chart_url(up.url(), u))
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // The upstream's credential goes to its own origin only, never to a host its index
    // names. Every chart, the upstream's own included, is fetched through the SSRF
    // guard: an own-origin URL may still redirect to a private address.
    let auth = same_origin(&url, up.url())
        .then(|| up.auth().map(UpstreamAuth::Basic))
        .flatten();
    let client = if state.config.helm.allow_private_chart_hosts {
        &state.http_client
    } else if crate::import::http::is_blocked_url_host(&url, false) {
        // An IP literal never reaches the guard's resolver: checked here.
        tracing::warn!(repo, chart = %name, version, url = %url, "Helm index names a chart on a loopback/private address, refusing it");
        return StatusCode::BAD_GATEWAY.into_response();
    } else {
        match guarded_client(&state) {
            Ok(client) => client,
            Err(e) => {
                tracing::error!(error = %e, "helm: no SSRF-guarded client, refusing a chart");
                return StatusCode::BAD_GATEWAY.into_response();
            }
        }
    };
    let (data, fetched) = match crate::registry::proxy_fetch_artifact_with(
        &state,
        client,
        &key,
        "helm",
        &url,
        state.config.helm.proxy_timeout,
        auth,
        BreakerScope::upstream(RegistryType::Helm, up.url()),
    )
    .await
    {
        Ok(fetched) => fetched,
        Err(e) => return proxy_error_response("helm", &url, &e),
    };
    // The index published the chart's digest: a body that does not match it (truncated,
    // corrupted, swapped) is neither served nor cached.
    let sha256 = data.sha256();
    if !sha256.eq_ignore_ascii_case(expected) {
        tracing::warn!(repo, chart = %name, version, url = %url, %expected, actual = %sha256, "Helm chart does not match the index digest, refusing it");
        return StatusCode::BAD_GATEWAY.into_response();
    }
    let digest = format!("sha256:{sha256}");
    if let Some(response) = crate::curation::verify_integrity_by_hash(
        engine,
        RegistryType::Helm,
        &name,
        Some(version),
        &digest,
    ) {
        return response;
    }
    state.metrics.record_download("helm");
    state.metrics.record_cache_miss("helm");
    state.activity.push(ActivityEntry::new(
        ActionType::ProxyFetch,
        label,
        RegistryType::Helm,
        "PROXY",
    ));
    state
        .audit
        .log(AuditEntry::new("proxy_fetch", "proxy", "", "helm", ""));
    // Only the caller whose fetch ran caches; coalesced followers share its body.
    if fetched {
        let (cache_state, cache_key, body) = (state.clone(), key.clone(), data.clone());
        tokio::spawn(async move {
            match body.cache(&cache_state, &cache_key, true).await {
                Ok(true) => cache_state.repo_index.invalidate("helm"),
                Ok(false) => {}
                Err(e) => crate::record_cache_write_error("helm", &cache_key, &e),
            }
        });
    }
    if let Some(resp) = crate::digest_quarantine::proxy_gate_digest(
        &state.digest_store,
        "helm",
        &digest,
        &q_mode,
        q_secs,
        &url,
        publish_date,
    ) {
        return resp;
    }
    let len = data.len();
    match data.into_body(&key).await {
        Ok(body) => chart_response(len, body),
        Err(e) => {
            tracing::warn!(key = %key, error = %e, "helm: spooled chart unreadable");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn chart_response(len: u64, body: axum::body::Body) -> Response {
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/gzip"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=31536000, immutable"),
            ),
            (header::CONTENT_LENGTH, HeaderValue::from(len)),
        ],
        body,
    )
        .into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::{Config, CurationMode};
    use sha2::Digest;

    const INDEX: &str = r#"apiVersion: v1
entries:
  cert-manager:
  - apiVersion: v2
    appVersion: "1.10"
    created: 2020-01-01T00:00:00.123456789Z
    digest: abc
    name: cert-manager
    urls:
    - charts/cert-manager-v1.10.0.tgz
    version: v1.10.0
    annotations:
      artifacthub.io/license: Apache-2.0
  - created: "2999-01-01T00:00:00Z"
    digest: def
    name: cert-manager
    urls:
    - https://example.com/cert-manager-v1.11.0.tgz
    version: 1.10
  - name: cert-manager
    urls:
    - cert-manager-0.1.0.tgz
    version: 0.1.0
  - null
  empty: null
generated: "2024-01-01T00:00:00Z"
serverInfo:
  contextPath: /x
"#;

    fn engine(cfg: impl FnOnce(&mut Config)) -> crate::curation::CurationEngine {
        let mut config = Config::default();
        config.curation.mode = CurationMode::Enforce;
        config.curation.min_release_age = Some("3d".to_string());
        config.curation.internal_namespaces = vec!["corp-*".to_string()];
        cfg(&mut config);
        crate::build_curation_engine(&config).unwrap()
    }

    #[test]
    fn parses_an_index_keeping_scalar_spelling_and_unknown_fields() {
        let index = parse_index_yaml(INDEX.as_bytes()).unwrap();
        let versions = &index.entries["cert-manager"];
        assert_eq!(versions[0].app_version.as_deref(), Some("1.10"));
        assert_eq!(
            versions[0].created.as_deref(),
            Some("2020-01-01T00:00:00.123456789Z")
        );
        // An unquoted number stays as written in a string field.
        assert_eq!(versions[1].version, "1.10");
        assert_eq!(versions[0].extra["apiVersion"], "v2");
        assert_eq!(
            versions[0].extra["annotations"]["artifacthub.io/license"],
            "Apache-2.0"
        );
        assert_eq!(index.extra["serverInfo"]["contextPath"], "/x");
        // A null item or list is skipped, as Helm skips it.
        assert_eq!(versions.len(), 3);
        assert!(index.entries["empty"].is_empty());
        let lenient = parse_index_yaml(b"apiVersion: v1\nentries:\n  a:\n  - name: a\n    version: 1.0.0\n    urls: null\n    digest: null\n").unwrap();
        assert!(lenient.entries["a"][0].urls.is_empty());
        assert_eq!(lenient.entries["a"][0].sha256(), None);
        // The JSON form reads back as the same index (what is cached and served).
        let json = serde_json::to_vec(&index).unwrap();
        let back: IndexFile = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.entries["cert-manager"][1].version, "1.10");
        assert!(parse_index_yaml(b"entries: {}\n").is_err(), "no apiVersion");
        assert!(parse_index_yaml(b"apiVersion: [").is_err());
    }

    #[test]
    fn renders_urls_back_to_nora_and_hides_young_versions_of_dated_repos() {
        let e = engine(|_| {});
        let mut index = parse_index_yaml(INDEX.as_bytes()).unwrap();
        render_index(&e, &mut index, false, |_| false);
        assert!(!index.entries.contains_key("empty"));
        let v = &index.entries["cert-manager"];
        assert_eq!(
            v.len(),
            2,
            "an undated repo's created hides nothing; no digest, not served"
        );
        assert_eq!(v[0].urls, ["charts/cert-manager/cert-manager-v1.10.0.tgz"]);
        assert_eq!(v[1].urls, ["charts/cert-manager/cert-manager-1.10.tgz"]);

        let mut index = parse_index_yaml(INDEX.as_bytes()).unwrap();
        render_index(&e, &mut index, true, |_| false);
        let v = &index.entries["cert-manager"];
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].version, "v1.10.0");
    }

    #[test]
    fn renders_without_held_digests_internal_names_and_unroutable_versions() {
        let e = engine(|_| {});
        let mut index = parse_index_yaml(INDEX.as_bytes()).unwrap();
        index
            .entries
            .insert("corp-lib".into(), index.entries["cert-manager"].clone());
        let mut bad = index.entries["cert-manager"][0].clone();
        bad.version = "1.0/../x".into();
        index.entries.get_mut("cert-manager").unwrap().push(bad);
        render_index(&e, &mut index, false, |d| d == "abc");
        assert!(!index.entries.contains_key("corp-lib"), "internal name");
        let v = &index.entries["cert-manager"];
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].version, "1.10");

        // Nothing left of a chart: the chart is gone.
        let mut index = parse_index_yaml(INDEX.as_bytes()).unwrap();
        render_index(&e, &mut index, true, |d| d == "abc");
        assert!(index.entries.is_empty());
    }

    #[test]
    fn resolves_chart_urls_like_helm() {
        let base = "https://charts.example.com/stable";
        assert_eq!(
            resolve_chart_url(base, "charts/a-1.0.0.tgz").unwrap(),
            "https://charts.example.com/stable/charts/a-1.0.0.tgz"
        );
        assert_eq!(
            resolve_chart_url(&format!("{base}/"), "a-1.0.0.tgz").unwrap(),
            "https://charts.example.com/stable/a-1.0.0.tgz"
        );
        assert_eq!(
            resolve_chart_url(base, "https://github.com/o/r/releases/download/a/a.tgz").unwrap(),
            "https://github.com/o/r/releases/download/a/a.tgz"
        );
        assert_eq!(resolve_chart_url(base, "file:///etc/passwd"), None);
        assert_eq!(resolve_chart_url(base, "ftp://x/a.tgz"), None);
        // Plain http only from an upstream configured as plain http.
        assert_eq!(resolve_chart_url(base, "http://x/a.tgz"), None);
        assert_eq!(
            resolve_chart_url("http://charts.lan", "http://x/a.tgz").unwrap(),
            "http://x/a.tgz"
        );
    }

    #[test]
    fn reads_the_index_digest() {
        let sha = hex::encode(sha2::Sha256::digest(b"chart"));
        let mut v = parse_index_yaml(INDEX.as_bytes()).unwrap().entries["cert-manager"][0].clone();
        for (digest, read) in [
            (Some(sha.clone()), Some(sha.as_str())),
            (Some(format!("sha256:{sha}")), Some(sha.as_str())),
            (Some(String::new()), None),
            (Some("sha256:".to_string()), None),
            (None, None),
        ] {
            v.digest = digest;
            assert_eq!(v.sha256(), read);
        }
        assert_eq!(
            ledger_digest(&sha.to_uppercase()),
            format!("sha256:{sha}"),
            "the ledger key of an index digest"
        );
    }

    #[test]
    fn chart_names_and_versions() {
        assert!(is_valid_chart_name("kube-prometheus-stack"));
        assert!(is_valid_chart_name("my_chart.v2"));
        assert!(!is_valid_chart_name(""));
        assert!(!is_valid_chart_name(".."));
        assert!(!is_valid_chart_name("a/b"));
        assert!(is_valid_chart_version("v1.21.2"));
        assert!(is_valid_chart_version("1.0.0-rc.1+build.5"));
        assert!(!is_valid_chart_version(".."));
        assert!(!is_valid_chart_version("1.0/x"));
        assert!(!is_valid_chart_version(""));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use crate::config::{CurationMode, RepoProxy, RepoProxyEntry};
    use crate::digest_quarantine::QuarantineMode;
    use crate::test_helpers::*;
    use axum::http::{Method, StatusCode};
    use sha2::Digest;
    use wiremock::matchers::{header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const OLD: &str = "2020-01-01T00:00:00Z";

    fn now_iso() -> String {
        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
    }

    fn index_yaml(versions: &[(&str, &str, &str, &[u8])]) -> String {
        let mut s = String::from("apiVersion: v1\nentries:\n  demo:\n");
        for (version, created, url, body) in versions {
            let digest = hex::encode(sha2::Sha256::digest(body));
            s.push_str(&format!(
                "  - name: demo\n    version: {version}\n    created: \"{created}\"\n    digest: {digest}\n    urls:\n    - {url}\n"
            ));
        }
        s
    }

    async fn upstream(index: &str) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repo/index.yaml"))
            .respond_with(ResponseTemplate::new(200).set_body_string(index))
            .mount(&server)
            .await;
        server
    }

    fn proxy(server: &MockServer) -> RepoProxyEntry {
        RepoProxyEntry::Simple(format!("{}/repo", server.uri()))
    }

    async fn index_json(ctx: &TestContext) -> serde_json::Value {
        let resp = send(&ctx.app, Method::GET, "/helm/demo/index.yaml", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        serde_json::from_slice(&body_bytes(resp).await).unwrap()
    }

    #[tokio::test]
    async fn serves_a_rewritten_index_and_charts_from_any_host_it_names() {
        let files = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/dl/demo-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"one".to_vec()))
            .expect(1)
            .mount(&files)
            .await;
        let index = index_yaml(&[
            (
                "1.0.0",
                OLD,
                &format!("{}/dl/demo-1.0.0.tgz", files.uri()),
                b"one",
            ),
            ("2.0.0", OLD, "charts/demo-2.0.0.tgz", b"two"),
        ]);
        let up = upstream(&index).await;
        Mock::given(method("GET"))
            .and(path("/repo/charts/demo-2.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"two".to_vec()))
            .mount(&up)
            .await;
        let entry = proxy(&up);
        let ctx = create_test_context_with_config(|cfg| {
            cfg.helm.enabled = true;
            cfg.helm.proxies.insert("demo".into(), entry);
            // The file host is another local mock server.
            cfg.helm.allow_private_chart_hosts = true;
        });

        let doc = index_json(&ctx).await;
        assert_eq!(doc["apiVersion"], "v1");
        let urls: Vec<&str> = doc["entries"]["demo"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["urls"][0].as_str().unwrap())
            .collect();
        assert_eq!(
            urls,
            ["charts/demo/demo-1.0.0.tgz", "charts/demo/demo-2.0.0.tgz"]
        );

        for (file, body) in [("demo-1.0.0.tgz", "one"), ("demo-2.0.0.tgz", "two")] {
            let uri = format!("/helm/demo/charts/demo/{file}");
            let resp = send(&ctx.app, Method::GET, &uri, "").await;
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
            assert_eq!(body_bytes(resp).await, body.as_bytes());
        }
        // Cached: the second read never reaches the file host (`expect(1)`).
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let resp = send(
            &ctx.app,
            Method::GET,
            "/helm/demo/charts/demo/demo-1.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = send(
            &ctx.app,
            Method::HEAD,
            "/helm/demo/charts/demo/demo-1.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        for uri in [
            "/helm/other/index.yaml",
            "/helm/demo/charts/demo/demo-9.9.9.tgz",
            "/helm/demo/charts/demo/other-1.0.0.tgz",
        ] {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{uri}");
        }
    }

    #[tokio::test]
    async fn a_chart_that_does_not_match_the_index_digest_is_refused_and_not_cached() {
        let index = index_yaml(&[("1.0.0", OLD, "demo-1.0.0.tgz", b"published")]);
        let up = upstream(&index).await;
        Mock::given(method("GET"))
            .and(path("/repo/demo-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"swapped".to_vec()))
            .mount(&up)
            .await;
        let entry = proxy(&up);
        let ctx = create_test_context_with_config(|cfg| {
            cfg.helm.enabled = true;
            cfg.helm.proxies.insert("demo".into(), entry);
            // mock upstreams listen on loopback
            cfg.helm.allow_private_chart_hosts = true;
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/helm/demo/charts/demo/demo-1.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(ctx
            .state
            .storage
            .stat("helm/charts/demo/demo/demo-1.0.0.tgz")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn the_credential_goes_to_the_upstream_origin_only() {
        let files = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/demo-1.0.0.tgz"))
            .and(header_exists("authorization"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&files)
            .await;
        Mock::given(method("GET"))
            .and(path("/demo-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"one".to_vec()))
            .mount(&files)
            .await;
        let index = index_yaml(&[(
            "1.0.0",
            OLD,
            &format!("{}/demo-1.0.0.tgz", files.uri()),
            b"one",
        )]);
        let up = upstream(&index).await;
        let entry = RepoProxyEntry::Full(RepoProxy {
            url: format!("{}/repo", up.uri()),
            auth: Some("user:pass".into()),
        });
        let ctx = create_test_context_with_config(|cfg| {
            cfg.helm.enabled = true;
            cfg.helm.proxies.insert("demo".into(), entry);
            cfg.helm.allow_private_chart_hosts = true;
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/helm/demo/charts/demo/demo-1.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the other host got no credential"
        );
    }

    #[tokio::test]
    async fn an_index_cannot_aim_nora_at_a_private_address() {
        let files = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"one".to_vec()))
            .expect(0)
            .mount(&files)
            .await;
        let index = index_yaml(&[(
            "1.0.0",
            OLD,
            &format!("{}/demo-1.0.0.tgz", files.uri()),
            b"one",
        )]);
        let up = upstream(&index).await;
        let entry = proxy(&up);
        let ctx = create_test_context_with_config(|cfg| {
            cfg.helm.enabled = true;
            cfg.helm.proxies.insert("demo".into(), entry);
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/helm/demo/charts/demo/demo-1.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn an_own_origin_chart_cannot_redirect_nora_to_a_private_address() {
        let files = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"one".to_vec()))
            .expect(0)
            .mount(&files)
            .await;
        let up = upstream(&index_yaml(&[("1.0.0", OLD, "demo-1.0.0.tgz", b"one")])).await;
        Mock::given(method("GET"))
            .and(path("/repo/demo-1.0.0.tgz"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/demo-1.0.0.tgz", files.uri())),
            )
            .mount(&up)
            .await;
        let entry = proxy(&up);
        let ctx = create_test_context_with_config(|cfg| {
            cfg.helm.enabled = true;
            cfg.helm.proxies.insert("demo".into(), entry);
        });
        // The upstream's own chart goes through the guard as well (here it already
        // refuses the loopback upstream; per-hop redirect checks: import::http).
        let resp = send(
            &ctx.app,
            Method::GET,
            "/helm/demo/charts/demo/demo-1.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn the_quarantine_holds_a_new_chart_and_hides_it_from_the_index() {
        let index = index_yaml(&[
            ("1.0.0", OLD, "demo-1.0.0.tgz", b"one"),
            ("2.0.0", OLD, "demo-2.0.0.tgz", b"two"),
        ]);
        let up = upstream(&index).await;
        Mock::given(method("GET"))
            .and(path("/repo/demo-2.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"two".to_vec()))
            .mount(&up)
            .await;
        let entry = proxy(&up);
        let ctx = create_test_context_with_config(|cfg| {
            cfg.helm.enabled = true;
            cfg.helm.proxies.insert("demo".into(), entry);
            // mock upstreams listen on loopback
            cfg.helm.allow_private_chart_hosts = true;
            cfg.curation.helm.quarantine = Some(QuarantineMode::Enforce);
            cfg.curation.helm.quarantine_ttl = Some("3d".into());
        });
        // Unseen: listed, so a client can ask for it and start its clock.
        assert_eq!(
            index_json(&ctx).await["entries"]["demo"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        let resp = send(
            &ctx.app,
            Method::GET,
            "/helm/demo/charts/demo/demo-2.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(resp.headers().contains_key("x-nora-quarantine"));
        // Seen and held: gone from the index until it matures, and still refused.
        let doc = index_json(&ctx).await;
        let versions = doc["entries"]["demo"].as_array().unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0]["version"], "1.0.0");
        let resp = send(
            &ctx.app,
            Method::GET,
            "/helm/demo/charts/demo/demo-2.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "cached copy still held"
        );
    }

    #[tokio::test]
    async fn min_release_age_applies_by_created_only_to_trusted_repos() {
        let young = now_iso();
        let index = index_yaml(&[
            ("1.0.0", OLD, "demo-1.0.0.tgz", b"one"),
            ("2.0.0", &young, "demo-2.0.0.tgz", b"two"),
        ]);
        let up = upstream(&index).await;
        Mock::given(method("GET"))
            .and(path("/repo/demo-2.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"two".to_vec()))
            .mount(&up)
            .await;
        for trusted in [false, true] {
            let entry = proxy(&up);
            let ctx = create_test_context_with_config(|cfg| {
                cfg.helm.enabled = true;
                cfg.helm.proxies.insert("demo".into(), entry);
                // mock upstreams listen on loopback
                cfg.helm.allow_private_chart_hosts = true;
                if trusted {
                    cfg.helm.trust_created = vec!["demo".into()];
                }
                cfg.curation.mode = CurationMode::Enforce;
                cfg.curation.helm.min_release_age = Some("3d".into());
                // The age comes from `created` itself, not the quarantine seeding.
                cfg.server.trust_upstream_dates = false;
            });
            let listed = index_json(&ctx).await["entries"]["demo"]
                .as_array()
                .unwrap()
                .len();
            let resp = send(
                &ctx.app,
                Method::GET,
                "/helm/demo/charts/demo/demo-2.0.0.tgz",
                "",
            )
            .await;
            if trusted {
                assert_eq!(listed, 1);
                assert_eq!(resp.status(), StatusCode::FORBIDDEN);
            } else {
                assert_eq!(listed, 2, "a re-stamped created must not hide anything");
                assert_eq!(resp.status(), StatusCode::OK);
            }
        }
    }

    #[tokio::test]
    async fn a_stale_index_is_served_when_the_upstream_fails() {
        for failure in [500, 404] {
            let index = index_yaml(&[("1.0.0", OLD, "demo-1.0.0.tgz", b"one")]);
            let up = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/repo/index.yaml"))
                .respond_with(ResponseTemplate::new(200).set_body_string(index))
                .up_to_n_times(1)
                .mount(&up)
                .await;
            Mock::given(method("GET"))
                .and(path("/repo/index.yaml"))
                .respond_with(ResponseTemplate::new(failure))
                .mount(&up)
                .await;
            let entry = proxy(&up);
            let ctx = create_test_context_with_config(|cfg| {
                cfg.helm.enabled = true;
                cfg.helm.metadata_ttl = 0;
                cfg.helm.proxies.insert("demo".into(), entry);
                // mock upstreams listen on loopback
                cfg.helm.allow_private_chart_hosts = true;
            });
            index_json(&ctx).await;
            let resp = send(&ctx.app, Method::GET, "/helm/demo/index.yaml", "").await;
            assert_eq!(resp.status(), StatusCode::OK, "upstream {failure}");
            assert_eq!(resp.headers()["x-nora-stale"], "true");
        }
    }

    #[tokio::test]
    async fn an_upstream_outage_is_not_a_missing_chart() {
        let up = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repo/index.yaml"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&up)
            .await;
        let entry = proxy(&up);
        let ctx = create_test_context_with_config(|cfg| {
            cfg.helm.enabled = true;
            cfg.helm.proxies.insert("demo".into(), entry);
            // mock upstreams listen on loopback
            cfg.helm.allow_private_chart_hosts = true;
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/helm/demo/charts/demo/demo-1.0.0.tgz",
            "",
        )
        .await;
        // No index and no cached copy: the upstream's error, never a 404 that Helm
        // and Flux read as "no such version".
        assert_ne!(resp.status(), StatusCode::NOT_FOUND);
        assert!(resp.status().is_server_error(), "{}", resp.status());
    }

    #[tokio::test]
    async fn an_internal_chart_name_is_never_proxied() {
        let index = index_yaml(&[("1.0.0", OLD, "demo-1.0.0.tgz", b"one")]);
        let up = upstream(&index).await;
        let entry = proxy(&up);
        let ctx = create_test_context_with_config(|cfg| {
            cfg.helm.enabled = true;
            cfg.helm.proxies.insert("demo".into(), entry);
            // mock upstreams listen on loopback
            cfg.helm.allow_private_chart_hosts = true;
            cfg.curation.internal_namespaces = vec!["demo".into()];
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/helm/demo/charts/demo/demo-1.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(index_json(&ctx).await["entries"]
            .as_object()
            .unwrap()
            .is_empty());
    }
}
