// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! GitHub Releases proxy (maestra): release assets of public repositories, pull-through
//! only, so CI downloads toolchains (`gitleaks`, `kustomize`, `trivy`…) through NORA's
//! curation instead of straight from github.com.
//!
//!   GET /github/{owner}/{repo}/releases/download/{tag}/{asset}
//!
//! The same path as on github.com: a client swaps `https://github.com` for
//! `https://nora.example.com/github`. A tag with a `/` (`kustomize/v5.4.3`) is sent
//! percent-encoded, as GitHub's own download URLs carry it.
//!
//! Every download first reads the release record from the REST API
//! (`/repos/{owner}/{repo}/releases/tags/{tag}`, cached under `github/meta/` for
//! `metadata_ttl`, a stale copy served on upstream error): its `published_at` is the
//! release date for `min_release_age` (`[curation.github]`, package `owner/repo`,
//! version = tag) and, with `server.trust_upstream_dates`, the quarantine's first seen;
//! an asset it does not list is a 404 and never fetched; its asset `digest` (sha256)
//! must match the body. Assets are fetched only from `download_url` through the SSRF
//! guard, every redirect hop pinned to that host, the API host and GitHub's asset CDN,
//! cached under `github/releases/{owner}/{repo}/{tag}/` and held by the first-seen
//! digest quarantine like any proxy artifact.
//!
//! The release-record cache, the pinned client and the download tail ([`serve_asset`])
//! are shared with the HashiCorp releases proxy (`registry/hashicorp.rs`).

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::cache_ttl::is_within_ttl;
use crate::circuit_breaker::BreakerScope;
use crate::config::{RegistryCurationOverride, UpstreamAuth};
use crate::digest_quarantine::QuarantineMode;
use crate::registry::{circuit_open_response, proxy_error_response, ProxyError};
use crate::registry_type::RegistryType;
use crate::AppState;
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;

/// Cached assets, one directory per owner: the repo index counts them by owner.
pub const INDEX_PATTERN: (&str, &str) = ("github/releases/", "");

/// Largest release record read from an API (a release with hundreds of assets is
/// well under 1 MiB).
pub(crate) const MAX_RECORD_BYTES: u64 = 8 * 1024 * 1024;

/// GitHub's release asset CDN: where `github.com/…/releases/download/…` redirects.
const ASSET_CDN_HOSTS: [&str; 2] = [
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
];

pub fn routes() -> Router<AppState> {
    Router::new().route(
        "/github/{owner}/{repo}/releases/download/{tag}/{asset}",
        get(asset),
    )
}

/// What NORA keeps of a release: its date and its assets' digests.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
struct Release {
    published_at: Option<String>,
    /// Asset file name (as in its download URL) → hex sha256, when GitHub has one.
    assets: BTreeMap<String, Option<String>>,
}

#[derive(Deserialize)]
struct ApiRelease {
    published_at: Option<String>,
    #[serde(default)]
    assets: Vec<ApiAsset>,
}

#[derive(Deserialize)]
struct ApiAsset {
    name: String,
    browser_download_url: Option<String>,
    digest: Option<String>,
}

/// `s` as a lowercase hex sha256, when it is one.
pub(crate) fn hex_sha256(s: &str) -> Option<String> {
    (s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())).then(|| s.to_ascii_lowercase())
}

impl Release {
    fn from_api(body: &[u8]) -> Result<Self, String> {
        let api: ApiRelease = serde_json::from_slice(body).map_err(|e| e.to_string())?;
        let assets = api
            .assets
            .into_iter()
            .map(|a| {
                // The file name clients request is the last segment of the download
                // URL; GitHub may have rewritten the uploaded `name`.
                let file = a
                    .browser_download_url
                    .as_deref()
                    .and_then(|u| u.rsplit('/').next())
                    .filter(|f| !f.is_empty())
                    .map(str::to_string)
                    .unwrap_or(a.name);
                let sha256 = a
                    .digest
                    .as_deref()
                    .and_then(|d| d.strip_prefix("sha256:"))
                    .and_then(hex_sha256);
                (file, sha256)
            })
            .collect();
        Ok(Self {
            published_at: api.published_at,
            assets,
        })
    }
}

/// An owner as GitHub allows it: letters, digits and `-`.
fn is_valid_owner(s: &str) -> bool {
    !s.is_empty() && s.len() <= 39 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// A repository name: letters, digits, `-`, `_`, `.`, not `.`/`..`-led.
fn is_valid_repo(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && !s.starts_with('.')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// A tag: printable ASCII from a safe set (`/` allowed: `kustomize/v5.4.3`), no `..`,
/// no empty or `.`-led path segment.
fn is_valid_tag(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && !s.contains("..")
        && s.split('/')
            .all(|seg| !seg.is_empty() && !seg.starts_with('.'))
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'+' | b'/' | b'@')
        })
}

/// An asset file name: letters, digits, `-`, `_`, `.`, `+`, not `.`-led, no `..`.
pub(crate) fn is_valid_asset(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && !s.starts_with('.')
        && !s.contains("..")
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'+'))
}

/// `base` with `segments` appended, each percent-encoded (a `/` in a tag is `%2F`).
pub(crate) fn join_segments(base: &str, segments: &[&str]) -> Option<String> {
    let mut url = reqwest::Url::parse(base).ok()?;
    if !matches!(url.scheme(), "https" | "http") {
        return None;
    }
    url.path_segments_mut()
        .ok()?
        .pop_if_empty()
        .extend(segments);
    Some(url.into())
}

/// A tag as one storage key segment: `/` (the only separator a valid tag has) is `%2F`.
fn tag_key(tag: &str) -> String {
    tag.replace('/', "%2F")
}

/// The hosts of `urls`, plus `extra`.
pub(crate) fn hosts_of(urls: &[&str], extra: &[&str]) -> Vec<String> {
    urls.iter()
        .filter_map(|u| reqwest::Url::parse(u).ok()?.host_str().map(str::to_string))
        .chain(extra.iter().map(|h| h.to_string()))
        .collect()
}

/// The upstream settings a release proxy fetches with.
pub(crate) struct Upstream {
    pub allow_private: bool,
    pub timeout: u64,
    /// The only hosts a request may reach, its redirects included.
    pub hosts: Vec<String>,
}

/// The client for every request of `up`: SSRF-guarded (no loopback, private,
/// link-local or metadata address, DNS pinned) and redirected only within its hosts.
/// Built once per distinct setting (one per proxy in a server; tests vary it).
fn pinned_client(state: &AppState, up: &Upstream) -> Result<reqwest::Client, String> {
    type Key = (bool, u64, Vec<String>);
    static CLIENTS: std::sync::LazyLock<std::sync::Mutex<BTreeMap<Key, reqwest::Client>>> =
        std::sync::LazyLock::new(Default::default);
    let key = (up.allow_private, up.timeout, up.hosts.clone());
    let mut clients = CLIENTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(client) = clients.get(&key) {
        return Ok(client.clone());
    }
    let client = crate::import::http::build_host_pinned_client(
        &state.config.tls,
        Duration::from_secs(10),
        Duration::from_secs(up.timeout.max(1)),
        up.allow_private,
        up.hosts.clone(),
    )?;
    clients.insert(key, client.clone());
    Ok(client)
}

/// The client for `url`, or the status to answer when `url` may not be fetched.
pub(crate) fn client_for(
    state: &AppState,
    up: &Upstream,
    url: &str,
) -> Result<reqwest::Client, StatusCode> {
    if !up.allow_private && crate::import::http::is_blocked_url_host(url, false) {
        // An IP literal never reaches the guard's resolver: checked here.
        tracing::warn!(url = %url, "release proxy: upstream is a loopback/private address, refusing it");
        return Err(StatusCode::BAD_GATEWAY);
    }
    pinned_client(state, up).map_err(|e| {
        tracing::error!(error = %e, "release proxy: no SSRF-guarded client, refusing a download");
        StatusCode::BAD_GATEWAY
    })
}

fn github_upstream(state: &AppState) -> Upstream {
    let cfg = &state.config.github;
    Upstream {
        allow_private: cfg.allow_private_hosts,
        timeout: cfg.proxy_timeout,
        hosts: hosts_of(&[&cfg.download_url, &cfg.api_url], &ASSET_CDN_HOSTS),
    }
}

/// The effective `(mode, ttl_secs)` of a registry's quarantine.
pub(crate) fn quarantine(
    state: &AppState,
    own: &RegistryCurationOverride,
) -> (QuarantineMode, i64) {
    let curation = &state.config.curation;
    crate::digest_quarantine::resolve_global(
        own.quarantine.as_ref().or(curation.quarantine.as_ref()),
        own.quarantine_ttl
            .as_deref()
            .or(curation.quarantine_ttl.as_deref()),
    )
}

async fn cached_record<T: DeserializeOwned>(
    state: &AppState,
    key: &str,
    ttl: Option<i64>,
) -> Option<T> {
    if let Some(ttl) = ttl {
        let meta = state.storage.stat(key).await?;
        if !is_within_ttl(meta.modified, ttl) {
            return None;
        }
    }
    serde_json::from_slice(&state.storage.get(key).await.ok()?).ok()
}

/// The release record under `key`, fetched by `fetch` (which names the URL it failed
/// on) once `ttl` seconds have passed, or the response to give when there is none.
/// One refresh per record runs at a time; a request arriving meanwhile gets the stale
/// copy at once, or (with none) waits for the refresh. Any upstream failure falls back
/// to the last copy: a record only dates a release and lists its digests.
pub(crate) async fn load_record<T, F, Fut>(
    state: &AppState,
    registry: &'static str,
    key: &str,
    ttl: i64,
    fetch: F,
) -> Result<T, Response>
where
    T: Serialize + DeserializeOwned,
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<T, (String, ProxyError)>>,
{
    if let Some(record) = cached_record(state, key, Some(ttl)).await {
        return Ok(record);
    }
    let lock = state.publish_lock(key);
    let _refresh = match lock.try_lock() {
        Ok(guard) => guard,
        Err(_) => {
            if let Some(record) = cached_record(state, key, None).await {
                return Ok(record);
            }
            lock.lock().await
        }
    };
    if let Some(record) = cached_record(state, key, Some(ttl)).await {
        return Ok(record);
    }
    let (url, err) = match fetch().await {
        Ok(record) => {
            match serde_json::to_vec(&record) {
                Ok(json) => {
                    if let Err(e) = state.storage.put(key, &json).await {
                        tracing::warn!(registry, key = %key, error = %e, "failed to cache a release record");
                    }
                }
                Err(e) => {
                    tracing::warn!(registry, key = %key, error = %e, "release record not serializable")
                }
            }
            return Ok(record);
        }
        Err(failed) => failed,
    };
    if let Some(record) = cached_record(state, key, None).await {
        tracing::warn!(registry, url = %url, error = ?err, "release API error, using the stale release record");
        return Ok(record);
    }
    Err(match err {
        ProxyError::NotFound => StatusCode::NOT_FOUND.into_response(),
        ProxyError::CircuitOpen(reg) => circuit_open_response(&reg),
        e => proxy_error_response(registry, &url, &e),
    })
}

/// GET `url` capped at [`MAX_RECORD_BYTES`], the URL named on failure.
pub(crate) async fn fetch_record(
    state: &AppState,
    up: &Upstream,
    registry: RegistryType,
    url: &str,
    auth: Option<UpstreamAuth<'_>>,
) -> Result<axum::body::Bytes, (String, ProxyError)> {
    let fail = |e| (url.to_string(), e);
    let client = client_for(state, up, url).map_err(|_| fail(ProxyError::Upstream(502)))?;
    crate::registry::proxy_fetch_capped(
        &client,
        url,
        Duration::from_secs(up.timeout),
        auth,
        &state.circuit_breaker,
        BreakerScope::upstream(registry, url),
        MAX_RECORD_BYTES,
    )
    .await
    .map_err(fail)
}

async fn asset(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((owner, repo, tag, file)): Path<(String, String, String, String)>,
) -> Response {
    if !(is_valid_owner(&owner)
        && is_valid_repo(&repo)
        && is_valid_tag(&tag)
        && is_valid_asset(&file))
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    // GitHub matches owner and repo names case-insensitively: curation rules and the
    // cache see one lowercase identity, the upstream URLs keep the client's spelling.
    let (owner_key, repo_key) = (owner.to_ascii_lowercase(), repo.to_ascii_lowercase());
    let name = format!("{owner_key}/{repo_key}");
    let engine = &state.curation().curation_engine;
    // An internal name is never fetched from an upstream (dependency confusion).
    if let Some(response) =
        crate::curation::check_namespace_isolation(engine, RegistryType::Github, &name)
    {
        return response;
    }

    let cfg = &state.config.github;
    let up = github_upstream(&state);
    // The release record is required even for a cached asset: it is the release date.
    let key = format!("github/meta/{owner_key}/{repo_key}/{}.json", tag_key(&tag));
    let release: Release = match load_record(&state, "github", &key, cfg.metadata_ttl, || async {
        let url = join_segments(
            &cfg.api_url,
            &["repos", &owner, &repo, "releases", "tags", &tag],
        )
        .ok_or_else(|| (cfg.api_url.clone(), ProxyError::Upstream(502)))?;
        let body = fetch_record(
            &state,
            &up,
            RegistryType::Github,
            &url,
            crate::secrets::expose_opt(&cfg.token).map(UpstreamAuth::Bearer),
        )
        .await?;
        Release::from_api(&body).map_err(|e| {
            tracing::warn!(url = %url, error = %e, "github: release record unreadable");
            (url.clone(), ProxyError::Upstream(502))
        })
    })
    .await
    {
        Ok(release) => release,
        Err(response) => return response,
    };
    let Some(expected) = release.assets.get(&file).cloned() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(url) = join_segments(
        &cfg.download_url,
        &[&owner, &repo, "releases", "download", &tag, &file],
    ) else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    serve_asset(
        &state,
        &headers,
        Asset {
            registry: RegistryType::Github,
            name: &name,
            version: &tag,
            published: release
                .published_at
                .as_deref()
                .and_then(crate::curation::parse_iso8601_to_unix),
            expected,
            key: format!(
                "github/releases/{owner_key}/{repo_key}/{}/{file}",
                tag_key(&tag)
            ),
            label: format!("{name}@{tag}/{file}"),
            url,
            upstream: &up,
            breaker_base: &cfg.download_url,
            quarantine: quarantine(&state, &state.config.curation.github),
        },
    )
    .await
}

/// One release asset to serve: its curation identity, date, digest and source.
pub(crate) struct Asset<'a> {
    pub registry: RegistryType,
    /// Curation package name and version.
    pub name: &'a str,
    pub version: &'a str,
    /// Release date (unix seconds) from the upstream's own record.
    pub published: Option<i64>,
    /// Hex sha256 the upstream publishes for the file, when it has one.
    pub expected: Option<String>,
    pub key: String,
    pub label: String,
    pub url: String,
    pub upstream: &'a Upstream,
    pub breaker_base: &'a str,
    pub quarantine: (QuarantineMode, i64),
}

/// Serve `a`: release age, a cached copy (integrity-checked) or a fetch checked against
/// the published digest, then the digest quarantine.
pub(crate) async fn serve_asset(state: &AppState, headers: &HeaderMap, a: Asset<'_>) -> Response {
    let reg = a.registry.as_str();
    let engine = &state.curation().curation_engine;
    let publish_date = crate::digest_quarantine::first_seen_seed(
        state.config.server.trust_upstream_dates,
        a.published,
    );
    if let Some(response) = crate::curation::check_download(
        engine,
        state.bypass_token().as_deref(),
        headers,
        a.registry,
        a.name,
        crate::curation::RequestVersion::Known(a.version.to_string()),
        a.published,
    ) {
        return response;
    }
    let (q_mode, q_secs) = a.quarantine;

    // Integrity-gated: a copy failing its pin is dropped and refetched, a storage
    // fault answers 503.
    let cached = match crate::registry::read_cached_artifact(state, reg, &a.key, false).await {
        Ok(cached) => cached,
        Err(response) => return response,
    };
    if let Some(cached) = cached {
        let digest = cached.digest();
        if let Some(response) = crate::curation::verify_integrity_by_hash(
            engine,
            a.registry,
            a.name,
            Some(a.version),
            &digest,
        ) {
            return response;
        }
        state.metrics.record_download(reg);
        state.metrics.record_cache_hit(reg);
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            a.label,
            a.registry,
            "CACHE",
        ));
        state
            .audit
            .log(AuditEntry::new("cache_hit", "proxy", "", reg, ""));
        if let Some(resp) = crate::digest_quarantine::proxy_gate_digest(
            &state.digest_store,
            reg,
            &digest,
            &q_mode,
            q_secs,
            "cache",
            publish_date,
        ) {
            return resp;
        }
        let len = cached.len();
        return asset_response(len, cached.into_body(state, reg, &a.key, false));
    }

    let client = match client_for(state, a.upstream, &a.url) {
        Ok(client) => client,
        Err(status) => return status.into_response(),
    };
    let (data, fetched) = match crate::registry::proxy_fetch_artifact_with(
        state,
        &client,
        &a.key,
        reg,
        &a.url,
        a.upstream.timeout,
        None,
        BreakerScope::upstream(a.registry, a.breaker_base),
    )
    .await
    {
        Ok(fetched) => fetched,
        Err(e) => return proxy_error_response(reg, &a.url, &e),
    };
    // The upstream publishes the file's digest: a body that does not match it
    // (truncated, swapped) is neither served nor cached.
    let sha256 = data.sha256();
    if let Some(expected) = a.expected.as_deref() {
        if !sha256.eq_ignore_ascii_case(expected) {
            tracing::warn!(registry = reg, url = %a.url, %expected, actual = %sha256, "release asset does not match its published digest, refusing it");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    }
    let digest = format!("sha256:{sha256}");
    if let Some(response) = crate::curation::verify_integrity_by_hash(
        engine,
        a.registry,
        a.name,
        Some(a.version),
        &digest,
    ) {
        return response;
    }
    state.metrics.record_download(reg);
    state.metrics.record_cache_miss(reg);
    state.activity.push(ActivityEntry::new(
        ActionType::ProxyFetch,
        a.label,
        a.registry,
        "PROXY",
    ));
    state
        .audit
        .log(AuditEntry::new("proxy_fetch", "proxy", "", reg, ""));
    // Only the caller whose fetch ran caches; coalesced followers share its body.
    if fetched {
        let (cache_state, cache_key, body) = (state.clone(), a.key.clone(), data.clone());
        tokio::spawn(async move {
            match body.cache(&cache_state, &cache_key, true).await {
                Ok(true) => cache_state.repo_index.invalidate(reg),
                Ok(false) => {}
                Err(e) => crate::record_cache_write_error(reg, &cache_key, &e),
            }
        });
    }
    if let Some(resp) = crate::digest_quarantine::proxy_gate_digest(
        &state.digest_store,
        reg,
        &digest,
        &q_mode,
        q_secs,
        &a.url,
        publish_date,
    ) {
        return resp;
    }
    let len = data.len();
    match data.into_body(&a.key).await {
        Ok(body) => asset_response(len, body),
        Err(e) => {
            tracing::warn!(key = %a.key, error = %e, "release proxy: spooled asset unreadable");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn asset_response(len: u64, body: axum::body::Body) -> Response {
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

    #[test]
    fn validates_path_parts() {
        assert!(is_valid_owner("kubernetes-sigs"));
        assert!(!is_valid_owner("a_b") && !is_valid_owner(""));
        assert!(is_valid_repo("kustomize") && is_valid_repo("cosign.dev"));
        assert!(!is_valid_repo(".github") && !is_valid_repo("a/b"));
        for tag in [
            "v8.28.0",
            "kustomize/v5.4.3",
            "v1.0.0+build.1",
            "release-2024@1",
        ] {
            assert!(is_valid_tag(tag), "{tag}");
        }
        for tag in ["", "../x", "a//b", "a/.b", "v1 0", "v1%2F0", "a\\b"] {
            assert!(!is_valid_tag(tag), "{tag}");
        }
        assert!(is_valid_asset("gitleaks_8.28.0_linux_x64.tar.gz"));
        for asset in ["", ".hidden", "a..b", "a/b", "a%20b"] {
            assert!(!is_valid_asset(asset), "{asset}");
        }
    }

    #[test]
    fn joins_percent_encoded_segments() {
        assert_eq!(
            join_segments(
                "https://github.com",
                &["kubernetes-sigs", "kustomize", "releases", "download", "kustomize/v5.4.3", "k.tar.gz"]
            )
            .unwrap(),
            "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2Fv5.4.3/k.tar.gz"
        );
        assert_eq!(
            join_segments("https://ghe.example.com/api/v3/", &["repos", "o", "r"]).unwrap(),
            "https://ghe.example.com/api/v3/repos/o/r"
        );
        assert!(join_segments("file:///etc", &["x"]).is_none());
        assert_eq!(tag_key("kustomize/v5.4.3"), "kustomize%2Fv5.4.3");
    }

    #[test]
    fn reads_a_release_record() {
        let body = br#"{"published_at":"2025-07-20T16:18:38Z","assets":[
            {"name":"a b.txt","browser_download_url":"https://github.com/o/r/releases/download/v1/a.b.txt","digest":"sha256:4EA55CD2E433EDBE3151E0FF49B044DF310E29967A38F38B68B1434A3660DCB8"},
            {"name":"old.tgz","browser_download_url":null,"digest":null},
            {"name":"bad.tgz","digest":"md5:abc"}]}"#;
        let release = Release::from_api(body).unwrap();
        assert_eq!(
            release.published_at.as_deref(),
            Some("2025-07-20T16:18:38Z")
        );
        assert_eq!(
            release.assets.get("a.b.txt").unwrap().as_deref(),
            Some("4ea55cd2e433edbe3151e0ff49b044df310e29967a38f38b68b1434a3660dcb8")
        );
        assert_eq!(release.assets.get("old.tgz"), Some(&None));
        assert_eq!(release.assets.get("bad.tgz"), Some(&None));
        assert!(Release::from_api(b"not json").is_err());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use crate::config::CurationMode;
    use crate::digest_quarantine::QuarantineMode;
    use crate::test_helpers::*;
    use axum::http::{Method, StatusCode};
    use sha2::Digest;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const OLD: &str = "2020-01-01T00:00:00Z";

    fn sha(body: &[u8]) -> String {
        hex::encode(sha2::Sha256::digest(body))
    }

    /// A mock GitHub: one release `o/r@tag` with `assets` (file, body, digest
    /// published), API under `/api`, downloads under `/dl` redirecting to `/cdn`.
    async fn github(
        tag_path: &str,
        tag: &str,
        published: &str,
        assets: &[(&str, &[u8], bool)],
    ) -> MockServer {
        let server = MockServer::start().await;
        let list: Vec<serde_json::Value> = assets
            .iter()
            .map(|(file, body, digest)| {
                serde_json::json!({
                    "name": file,
                    "browser_download_url": format!("https://github.com/o/r/releases/download/{tag_path}/{file}"),
                    "digest": digest.then(|| format!("sha256:{}", sha(body))),
                })
            })
            .collect();
        Mock::given(method("GET"))
            .and(path(format!("/api/repos/o/r/releases/tags/{tag_path}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"tag_name": tag, "published_at": published, "assets": list}),
            ))
            .mount(&server)
            .await;
        for (file, body, _) in assets {
            Mock::given(method("GET"))
                .and(path(format!("/dl/o/r/releases/download/{tag_path}/{file}")))
                .respond_with(
                    ResponseTemplate::new(302)
                        .insert_header("location", format!("{}/cdn/{file}", server.uri())),
                )
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/cdn/{file}")))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
                .mount(&server)
                .await;
        }
        server
    }

    fn configure(cfg: &mut crate::config::Config, server: &MockServer) {
        cfg.github.enabled = true;
        cfg.github.api_url = format!("{}/api", server.uri());
        cfg.github.download_url = format!("{}/dl", server.uri());
        // mock upstreams listen on loopback
        cfg.github.allow_private_hosts = true;
    }

    async fn get(ctx: &TestContext, uri: &str) -> axum::response::Response {
        send(&ctx.app, Method::GET, uri, "").await
    }

    #[tokio::test]
    async fn serves_listed_assets_through_the_redirect_and_caches_them() {
        let server = github(
            "v1.0.0",
            "v1.0.0",
            OLD,
            &[
                ("tool_linux_amd64.tar.gz", b"tool", true),
                ("plain.txt", b"plain", false),
            ],
        )
        .await;
        let ctx = create_test_context_with_config(|cfg| configure(cfg, &server));

        for (file, body) in [("tool_linux_amd64.tar.gz", "tool"), ("plain.txt", "plain")] {
            let uri = format!("/github/o/r/releases/download/v1.0.0/{file}");
            let resp = get(&ctx, &uri).await;
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
            assert_eq!(body_bytes(resp).await, body.as_bytes());
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(ctx
            .state
            .storage
            .stat("github/releases/o/r/v1.0.0/tool_linux_amd64.tar.gz")
            .await
            .is_some());
        // Cached: served again with the upstream gone (the release record is cached too).
        drop(server);
        let resp = get(
            &ctx,
            "/github/o/r/releases/download/v1.0.0/tool_linux_amd64.tar.gz",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await, b"tool".as_slice());

        // Not in the release, a malformed path: 404 without asking the upstream.
        for uri in [
            "/github/o/r/releases/download/v1.0.0/other.tar.gz",
            "/github/o/r/releases/download/v1.0.0/.hidden",
            "/github/o_x/r/releases/download/v1.0.0/plain.txt",
        ] {
            assert_eq!(
                get(&ctx, uri).await.status(),
                StatusCode::NOT_FOUND,
                "{uri}"
            );
        }
    }

    /// GitHub owner and repo names are case-insensitive: `O/R` is the same cached
    /// release and asset as `o/r`, never a second copy.
    #[tokio::test]
    async fn owner_and_repo_case_shares_one_cache_entry() {
        let server = github("v1.0.0", "v1.0.0", OLD, &[("t.tar.gz", b"t", true)]).await;
        let ctx = create_test_context_with_config(|cfg| configure(cfg, &server));
        let resp = get(&ctx, "/github/o/r/releases/download/v1.0.0/t.tar.gz").await;
        assert_eq!(resp.status(), StatusCode::OK);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        drop(server);
        let resp = get(&ctx, "/github/O/R/releases/download/v1.0.0/t.tar.gz").await;
        assert_eq!(resp.status(), StatusCode::OK);
        // Served with the upstream gone: the lowercase release record and asset.
        assert_eq!(body_bytes(resp).await, b"t".as_slice());
    }

    #[tokio::test]
    async fn a_tag_with_a_slash_is_one_percent_encoded_segment() {
        let server = github(
            "kustomize%2Fv5.4.3",
            "kustomize/v5.4.3",
            OLD,
            &[("kustomize_v5.4.3_linux_amd64.tar.gz", b"k", true)],
        )
        .await;
        let ctx = create_test_context_with_config(|cfg| configure(cfg, &server));
        let resp = get(
            &ctx,
            "/github/o/r/releases/download/kustomize%2Fv5.4.3/kustomize_v5.4.3_linux_amd64.tar.gz",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await, b"k".as_slice());
    }

    #[tokio::test]
    async fn a_body_that_differs_from_the_release_digest_is_refused() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/repos/o/r/releases/tags/v1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "published_at": OLD,
                "assets": [{"name": "a.bin", "digest": format!("sha256:{}", sha(b"good"))}],
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/dl/o/r/releases/download/v1/a.bin"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"evil".to_vec()))
            .mount(&server)
            .await;
        let ctx = create_test_context_with_config(|cfg| configure(cfg, &server));
        let resp = get(&ctx, "/github/o/r/releases/download/v1/a.bin").await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(ctx
            .state
            .storage
            .stat("github/releases/o/r/v1/a.bin")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn min_release_age_dates_by_published_at() {
        let young = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        for (published, want) in [
            (young.as_str(), StatusCode::FORBIDDEN),
            (OLD, StatusCode::OK),
        ] {
            let server = github("v2", "v2", published, &[("a.bin", b"a", true)]).await;
            let ctx = create_test_context_with_config(|cfg| {
                configure(cfg, &server);
                cfg.curation.mode = CurationMode::Enforce;
                cfg.curation.github.min_release_age = Some("3d".into());
            });
            let resp = get(&ctx, "/github/o/r/releases/download/v2/a.bin").await;
            assert_eq!(resp.status(), want, "published {published}");
        }
    }

    #[tokio::test]
    async fn the_quarantine_holds_a_new_digest() {
        let server = github("v3", "v3", OLD, &[("a.bin", b"a", true)]).await;
        let ctx = create_test_context_with_config(|cfg| {
            configure(cfg, &server);
            cfg.curation.github.quarantine = Some(QuarantineMode::Enforce);
            cfg.curation.github.quarantine_ttl = Some("3d".into());
            // A release date does not seed the clock unless trusted.
            cfg.server.trust_upstream_dates = false;
        });
        for _ in 0..2 {
            let resp = get(&ctx, "/github/o/r/releases/download/v3/a.bin").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
            assert!(resp.headers().contains_key("x-nora-quarantine"));
        }
    }

    #[tokio::test]
    async fn the_api_token_goes_to_the_api_only() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/repos/o/r/releases/tags/v1"))
            .and(header("authorization", "Bearer t0ken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "published_at": OLD,
                "assets": [{"name": "a.bin", "digest": null}],
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/dl/o/r/releases/download/v1/a.bin"))
            .and(header("authorization", "Bearer t0ken"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/dl/o/r/releases/download/v1/a.bin"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"a".to_vec()))
            .mount(&server)
            .await;
        let ctx = create_test_context_with_config(|cfg| {
            configure(cfg, &server);
            cfg.github.token = Some(crate::secrets::ProtectedString::new("t0ken".to_string()));
        });
        let resp = get(&ctx, "/github/o/r/releases/download/v1/a.bin").await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn an_unknown_release_is_a_404_and_a_failing_api_is_not() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/repos/o/r/releases/tags/v404"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/repos/o/r/releases/tags/v500"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let ctx = create_test_context_with_config(|cfg| configure(cfg, &server));
        let resp = get(&ctx, "/github/o/r/releases/download/v404/a.bin").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let resp = get(&ctx, "/github/o/r/releases/download/v500/a.bin").await;
        assert!(resp.status().is_server_error(), "{}", resp.status());
    }
}
