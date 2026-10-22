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
use crate::registry::{circuit_open_response, proxy_error_response, proxy_fetch, ProxyError};
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
use sha2::Digest;
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
/// as `version: 1.10` keeps its spelling; everything else passes through as is.
#[derive(Debug, Serialize, Deserialize)]
struct IndexFile {
    #[serde(rename = "apiVersion", default)]
    api_version: String,
    #[serde(default)]
    entries: BTreeMap<String, Vec<ChartVersion>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    generated: Option<String>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChartVersion {
    #[serde(default)]
    name: String,
    #[serde(default)]
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
    #[serde(default)]
    urls: Vec<String>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl ChartVersion {
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
/// not route) is left out.
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
                && !v.digest.as_deref().is_some_and(&held)
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
/// resolve against the repository URL as Helm resolves them; only http(s) is fetched.
fn resolve_chart_url(base: &str, url: &str) -> Option<String> {
    let base = reqwest::Url::parse(&format!("{}/", base.trim_end_matches('/'))).ok()?;
    let resolved = base.join(url).ok()?;
    matches!(resolved.scheme(), "http" | "https").then(|| resolved.to_string())
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

/// Whether `data` is what the index digest (hex sha256, optionally `sha256:`) names.
/// An index without a digest names nothing to check.
fn digest_matches(expected: Option<&str>, data: &[u8]) -> bool {
    let Some(expected) = expected.filter(|d| !d.is_empty()) else {
        return true;
    };
    let expected = expected.strip_prefix("sha256:").unwrap_or(expected);
    hex::encode(sha2::Sha256::digest(data)).eq_ignore_ascii_case(expected)
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

/// The ledger key of an index digest (hex sha256, optionally `sha256:`).
fn ledger_digest(digest: &str) -> String {
    format!(
        "sha256:{}",
        digest
            .strip_prefix("sha256:")
            .unwrap_or(digest)
            .to_lowercase()
    )
}

fn index_key(repo: &str) -> String {
    format!("helm/index/{repo}.json")
}

/// The upstream index of `repo` (JSON form) and whether it is a stale copy, or the
/// response to give when there is none.
async fn load_index(
    state: &AppState,
    repo: &str,
    up: &RepoProxyEntry,
) -> Result<(IndexFile, bool), Response> {
    let key = index_key(repo);
    let cached = state.storage.get(&key).await.ok();
    if let Some(ref data) = cached {
        if let Some(meta) = state.storage.stat(&key).await {
            if is_within_ttl(meta.modified, state.config.helm.metadata_ttl) {
                if let Ok(index) = serde_json::from_slice(data) {
                    return Ok((index, false));
                }
            }
        }
    }
    let stale = || {
        cached
            .as_ref()
            .filter(|_| state.config.helm.serve_stale)
            .and_then(|data| serde_json::from_slice::<IndexFile>(data).ok())
    };

    let base = up.url().trim_end_matches('/');
    let url = format!("{base}/index.yaml");
    let fetched = proxy_fetch(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.helm.proxy_timeout),
        up.auth().map(UpstreamAuth::Basic),
        &state.circuit_breaker,
        BreakerScope::upstream(RegistryType::Helm, up.url()),
    )
    .await;
    let err = match fetched {
        Ok(body) => match tokio::task::spawn_blocking(move || parse_index_yaml(&body)).await {
            Ok(Ok(index)) => {
                match serde_json::to_vec(&index) {
                    Ok(json) => {
                        if let Err(e) = state.storage.put(&key, &json).await {
                            tracing::warn!(key = %key, error = %e, "helm: failed to cache index");
                        }
                    }
                    Err(e) => tracing::warn!(repo, error = %e, "helm: index not serializable"),
                }
                return Ok((index, false));
            }
            Ok(Err(e)) => {
                tracing::warn!(repo, url = %url, error = %e, "helm: upstream index unreadable");
                ProxyError::Upstream(502)
            }
            Err(e) => ProxyError::Network(e.to_string()),
        },
        Err(ProxyError::NotFound) => return Err(StatusCode::NOT_FOUND.into_response()),
        Err(e) => e,
    };
    if let Some(index) = stale() {
        tracing::warn!(registry = "helm", repo, error = ?err, "Helm upstream error, serving stale index");
        return Ok((index, true));
    }
    Err(match err {
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
    let held = |digest: &str| {
        enforce
            && matches!(
                state
                    .digest_store
                    .check("helm", &ledger_digest(digest), q_secs),
                crate::digest_quarantine::QuarantineStatus::Pending { .. }
            )
    };
    render_index(
        &state.curation().curation_engine,
        &mut index,
        dated(&state, &repo),
        held,
    );
    let body = match serde_json::to_vec(&index) {
        Ok(body) => body,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
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

    // The index names the chart's date, digest and upstream URL; a cached chart is
    // still served when the index cannot be had.
    let entry = match load_index(&state, &repo, up).await {
        Ok((index, _)) => index
            .entries
            .get(&name)
            .and_then(|versions| versions.iter().find(|v| v.version == version).cloned()),
        Err(_) => None,
    };
    // `created` dates a chart only in a repo that does not re-stamp it.
    let created = entry
        .as_ref()
        .filter(|_| dated(&state, &repo))
        .and_then(ChartVersion::created_unix);
    let publish_date = created.filter(|_| state.config.server.trust_upstream_dates);

    if let Some(response) = crate::curation::check_download(
        engine,
        state.bypass_token().as_deref(),
        &headers,
        RegistryType::Helm,
        &name,
        crate::curation::RequestVersion::Known(version.to_string()),
        publish_date,
    ) {
        return response;
    }

    let (q_mode, q_secs) = quarantine(&state);
    let key = format!("helm/charts/{name}/{repo}/{file}");
    let label = format!("{repo}/{file}");

    if let Ok(outcome) = state.storage.get_verified(&key).await {
        use nora_registry::verified::{verified_body, GateOutcome};
        let data = match outcome {
            GateOutcome::Verified(blob) => verified_body(blob),
            GateOutcome::Unpinned(blob) => blob.into_inner(),
        };
        if let Some(response) = crate::curation::verify_integrity(
            engine,
            RegistryType::Helm,
            &name,
            Some(version),
            &data,
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
        if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
            &state.digest_store,
            "helm",
            &data,
            &q_mode,
            q_secs,
            "cache",
            publish_date,
        ) {
            return resp;
        }
        return chart_response(data.to_vec());
    }

    let Some(entry) = entry else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(url) = entry
        .urls
        .first()
        .and_then(|u| resolve_chart_url(up.url(), u))
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // The upstream's credential goes to its own origin only, never to a host its index names.
    let auth = if same_origin(&url, up.url()) {
        up.auth().map(UpstreamAuth::Basic)
    } else {
        None
    };
    let data = match proxy_fetch(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.helm.proxy_timeout),
        auth,
        &state.circuit_breaker,
        BreakerScope::upstream(RegistryType::Helm, up.url()),
    )
    .await
    {
        Ok(data) => data,
        Err(e) => return proxy_error_response("helm", &url, &e),
    };
    // The index published the chart's digest: a body that does not match it (truncated,
    // corrupted, swapped) is neither served nor cached.
    if !digest_matches(entry.digest.as_deref(), &data) {
        tracing::warn!(repo, chart = %name, version, url = %url, "Helm chart does not match the index digest, refusing it");
        return StatusCode::BAD_GATEWAY.into_response();
    }
    if let Some(response) =
        crate::curation::verify_integrity(engine, RegistryType::Helm, &name, Some(version), &data)
    {
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
    state.spawn_cache_immutable("helm", key, Bytes::from(data.clone()));
    if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
        &state.digest_store,
        "helm",
        &data,
        &q_mode,
        q_secs,
        &url,
        publish_date,
    ) {
        return resp;
    }
    chart_response(data)
}

fn chart_response(data: Vec<u8>) -> Response {
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
        ],
        data,
    )
        .into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::{Config, CurationMode};

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
    name: cert-manager
    urls:
    - https://example.com/cert-manager-v1.11.0.tgz
    version: 1.10
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
        let v = &index.entries["cert-manager"];
        assert_eq!(v.len(), 2, "an undated repo's created hides nothing");
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
    }

    #[test]
    fn checks_the_index_digest() {
        let sha = hex::encode(sha2::Sha256::digest(b"chart"));
        assert!(digest_matches(Some(&sha), b"chart"));
        assert!(digest_matches(Some(&sha.to_uppercase()), b"chart"));
        assert!(digest_matches(Some(&format!("sha256:{sha}")), b"chart"));
        assert!(!digest_matches(Some(&sha), b"other"));
        assert!(digest_matches(None, b"anything"), "no digest to check");
        assert!(digest_matches(Some(""), b"anything"));
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
                if trusted {
                    cfg.helm.trust_created = vec!["demo".into()];
                }
                cfg.curation.mode = CurationMode::Enforce;
                cfg.curation.helm.min_release_age = Some("3d".into());
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
            .respond_with(ResponseTemplate::new(500))
            .mount(&up)
            .await;
        let entry = proxy(&up);
        let ctx = create_test_context_with_config(|cfg| {
            cfg.helm.enabled = true;
            cfg.helm.metadata_ttl = 0;
            cfg.helm.proxies.insert("demo".into(), entry);
        });
        index_json(&ctx).await;
        let resp = send(&ctx.app, Method::GET, "/helm/demo/index.yaml", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()["x-nora-stale"], "true");
    }

    #[tokio::test]
    async fn an_internal_chart_name_is_never_proxied() {
        let index = index_yaml(&[("1.0.0", OLD, "demo-1.0.0.tgz", b"one")]);
        let up = upstream(&index).await;
        let entry = proxy(&up);
        let ctx = create_test_context_with_config(|cfg| {
            cfg.helm.enabled = true;
            cfg.helm.proxies.insert("demo".into(), entry);
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
