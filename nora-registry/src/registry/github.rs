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

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::cache_ttl::is_within_ttl;
use crate::circuit_breaker::BreakerScope;
use crate::config::UpstreamAuth;
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
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;

/// Cached assets, one directory per owner: the repo index counts them by owner.
pub const INDEX_PATTERN: (&str, &str) = ("github/releases/", "");

/// Largest release record read from the API (a release with hundreds of assets is
/// well under 1 MiB).
const MAX_RELEASE_BYTES: u64 = 8 * 1024 * 1024;

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
                    .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
                    .map(str::to_ascii_lowercase);
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
fn is_valid_asset(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && !s.starts_with('.')
        && !s.contains("..")
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'+'))
}

/// `base` with `segments` appended, each percent-encoded (a `/` in a tag is `%2F`).
fn join_segments(base: &str, segments: &[&str]) -> Option<String> {
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

/// The hosts an asset download may reach, its redirects included.
fn allowed_hosts(state: &AppState) -> Vec<String> {
    let cfg = &state.config.github;
    [cfg.download_url.as_str(), cfg.api_url.as_str()]
        .iter()
        .filter_map(|u| reqwest::Url::parse(u).ok()?.host_str().map(str::to_string))
        .chain(ASSET_CDN_HOSTS.iter().map(|h| h.to_string()))
        .collect()
}

/// The client for every GitHub request: SSRF-guarded (no loopback, private,
/// link-local or metadata address, DNS pinned) and redirected only within
/// [`allowed_hosts`]. Built once per distinct setting (one in a server; tests vary it).
fn guarded_client(state: &AppState) -> Result<reqwest::Client, String> {
    type Key = (bool, u64, Vec<String>);
    static CLIENTS: std::sync::LazyLock<std::sync::Mutex<BTreeMap<Key, reqwest::Client>>> =
        std::sync::LazyLock::new(Default::default);
    let cfg = &state.config.github;
    let key = (
        cfg.allow_private_hosts,
        cfg.proxy_timeout,
        allowed_hosts(state),
    );
    let mut clients = CLIENTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(client) = clients.get(&key) {
        return Ok(client.clone());
    }
    let client = crate::import::http::build_host_pinned_client(
        &state.config.tls,
        Duration::from_secs(10),
        Duration::from_secs(cfg.proxy_timeout.max(1)),
        cfg.allow_private_hosts,
        key.2.clone(),
    )?;
    clients.insert(key, client.clone());
    Ok(client)
}

/// The client for `url`, or the answer when `url` may not be fetched.
fn client_for(state: &AppState, url: &str) -> Result<reqwest::Client, StatusCode> {
    if !state.config.github.allow_private_hosts
        && crate::import::http::is_blocked_url_host(url, false)
    {
        // An IP literal never reaches the guard's resolver: checked here.
        tracing::warn!(url = %url, "github: upstream is a loopback/private address, refusing it");
        return Err(StatusCode::BAD_GATEWAY);
    }
    guarded_client(state).map_err(|e| {
        tracing::error!(error = %e, "github: no SSRF-guarded client, refusing a download");
        StatusCode::BAD_GATEWAY
    })
}

/// The effective `(mode, ttl_secs)` of the github quarantine.
fn quarantine(state: &AppState) -> (crate::digest_quarantine::QuarantineMode, i64) {
    let curation = &state.config.curation;
    crate::digest_quarantine::resolve_global(
        curation
            .github
            .quarantine
            .as_ref()
            .or(curation.quarantine.as_ref()),
        curation
            .github
            .quarantine_ttl
            .as_deref()
            .or(curation.quarantine_ttl.as_deref()),
    )
}

fn release_key(owner: &str, repo: &str, tag: &str) -> String {
    format!("github/meta/{owner}/{repo}/{}.json", tag_key(tag))
}

async fn cached_release(state: &AppState, key: &str, fresh: bool) -> Option<Release> {
    if fresh {
        let meta = state.storage.stat(key).await?;
        if !is_within_ttl(meta.modified, state.config.github.metadata_ttl) {
            return None;
        }
    }
    serde_json::from_slice(&state.storage.get(key).await.ok()?).ok()
}

/// The release record of `owner/repo@tag`, or the response to give when there is none.
/// One refresh per release runs at a time; a request arriving meanwhile gets the stale
/// copy at once, or (with none) waits for the refresh. Any upstream failure falls back
/// to the last copy: the record only dates the release and lists its digests.
async fn load_release(
    state: &AppState,
    owner: &str,
    repo: &str,
    tag: &str,
) -> Result<Release, Response> {
    let key = release_key(owner, repo, tag);
    if let Some(release) = cached_release(state, &key, true).await {
        return Ok(release);
    }
    let lock = state.publish_lock(&key);
    let _refresh = match lock.try_lock() {
        Ok(guard) => guard,
        Err(_) => {
            if let Some(release) = cached_release(state, &key, false).await {
                return Ok(release);
            }
            lock.lock().await
        }
    };
    if let Some(release) = cached_release(state, &key, true).await {
        return Ok(release);
    }

    let cfg = &state.config.github;
    let Some(url) = join_segments(
        &cfg.api_url,
        &["repos", owner, repo, "releases", "tags", tag],
    ) else {
        return Err(StatusCode::BAD_GATEWAY.into_response());
    };
    let client = client_for(state, &url).map_err(IntoResponse::into_response)?;
    let fetched = crate::registry::proxy_fetch_capped(
        &client,
        &url,
        Duration::from_secs(cfg.proxy_timeout),
        cfg.token.as_deref().map(UpstreamAuth::Bearer),
        &state.circuit_breaker,
        BreakerScope::upstream(RegistryType::Github, &cfg.api_url),
        MAX_RELEASE_BYTES,
    )
    .await;
    let err = match fetched {
        Ok(body) => match Release::from_api(&body) {
            Ok(release) => {
                match serde_json::to_vec(&release) {
                    Ok(json) => {
                        if let Err(e) = state.storage.put(&key, &json).await {
                            tracing::warn!(key = %key, error = %e, "github: failed to cache a release record");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(key = %key, error = %e, "github: release record not serializable")
                    }
                }
                return Ok(release);
            }
            Err(e) => {
                tracing::warn!(url = %url, error = %e, "github: release record unreadable");
                ProxyError::Upstream(502)
            }
        },
        Err(e) => e,
    };
    if let Some(release) = cached_release(state, &key, false).await {
        tracing::warn!(registry = "github", url = %url, error = ?err, "GitHub API error, using the stale release record");
        return Ok(release);
    }
    Err(match err {
        ProxyError::NotFound => StatusCode::NOT_FOUND.into_response(),
        ProxyError::CircuitOpen(reg) => circuit_open_response(&reg),
        e => proxy_error_response("github", &url, &e),
    })
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
    let name = format!("{owner}/{repo}");
    let engine = &state.curation().curation_engine;

    // An internal name is never fetched from an upstream (dependency confusion).
    if let Some(response) =
        crate::curation::check_namespace_isolation(engine, RegistryType::Github, &name)
    {
        return response;
    }

    // The release record is required even for a cached asset: it is the release date.
    let release = match load_release(&state, &owner, &repo, &tag).await {
        Ok(release) => release,
        Err(response) => return response,
    };
    let Some(expected) = release.assets.get(&file).cloned() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let published = release
        .published_at
        .as_deref()
        .and_then(crate::curation::parse_iso8601_to_unix);
    let publish_date = published.filter(|_| state.config.server.trust_upstream_dates);

    if let Some(response) = crate::curation::check_download(
        engine,
        state.bypass_token().as_deref(),
        &headers,
        RegistryType::Github,
        &name,
        crate::curation::RequestVersion::Known(tag.clone()),
        published,
    ) {
        return response;
    }

    let (q_mode, q_secs) = quarantine(&state);
    let key = format!("github/releases/{owner}/{repo}/{}/{file}", tag_key(&tag));
    let label = format!("{name}@{tag}/{file}");

    // Integrity-gated: a copy failing its pin is dropped and refetched, a storage
    // fault answers 503.
    let cached = match crate::registry::read_cached_artifact(&state, "github", &key, false).await {
        Ok(cached) => cached,
        Err(response) => return response,
    };
    if let Some(cached) = cached {
        let digest = cached.digest();
        if let Some(response) = crate::curation::verify_integrity_by_hash(
            engine,
            RegistryType::Github,
            &name,
            Some(&tag),
            &digest,
        ) {
            return response;
        }
        state.metrics.record_download("github");
        state.metrics.record_cache_hit("github");
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            label,
            RegistryType::Github,
            "CACHE",
        ));
        state
            .audit
            .log(AuditEntry::new("cache_hit", "proxy", "", "github", ""));
        if let Some(resp) = crate::digest_quarantine::proxy_gate_digest(
            &state.digest_store,
            "github",
            &digest,
            &q_mode,
            q_secs,
            "cache",
            publish_date,
        ) {
            return resp;
        }
        let len = cached.len();
        return asset_response(len, cached.into_body(&state, "github", &key, false));
    }

    let cfg = &state.config.github;
    let Some(url) = join_segments(
        &cfg.download_url,
        &[&owner, &repo, "releases", "download", &tag, &file],
    ) else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    let client = match client_for(&state, &url) {
        Ok(client) => client,
        Err(status) => return status.into_response(),
    };
    let (data, fetched) = match crate::registry::proxy_fetch_artifact_with(
        &state,
        &client,
        &key,
        "github",
        &url,
        cfg.proxy_timeout,
        None,
        BreakerScope::upstream(RegistryType::Github, &cfg.download_url),
    )
    .await
    {
        Ok(fetched) => fetched,
        Err(e) => return proxy_error_response("github", &url, &e),
    };
    // GitHub publishes the asset's digest: a body that does not match it (truncated,
    // swapped) is neither served nor cached.
    let sha256 = data.sha256();
    if let Some(expected) = expected.as_deref() {
        if !sha256.eq_ignore_ascii_case(expected) {
            tracing::warn!(url = %url, %expected, actual = %sha256, "GitHub asset does not match its release digest, refusing it");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    }
    let digest = format!("sha256:{sha256}");
    if let Some(response) = crate::curation::verify_integrity_by_hash(
        engine,
        RegistryType::Github,
        &name,
        Some(&tag),
        &digest,
    ) {
        return response;
    }
    state.metrics.record_download("github");
    state.metrics.record_cache_miss("github");
    state.activity.push(ActivityEntry::new(
        ActionType::ProxyFetch,
        label,
        RegistryType::Github,
        "PROXY",
    ));
    state
        .audit
        .log(AuditEntry::new("proxy_fetch", "proxy", "", "github", ""));
    // Only the caller whose fetch ran caches; coalesced followers share its body.
    if fetched {
        let (cache_state, cache_key, body) = (state.clone(), key.clone(), data.clone());
        tokio::spawn(async move {
            match body.cache(&cache_state, &cache_key, true).await {
                Ok(true) => cache_state.repo_index.invalidate("github"),
                Ok(false) => {}
                Err(e) => crate::record_cache_write_error("github", &cache_key, &e),
            }
        });
    }
    if let Some(resp) = crate::digest_quarantine::proxy_gate_digest(
        &state.digest_store,
        "github",
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
        Ok(body) => asset_response(len, body),
        Err(e) => {
            tracing::warn!(key = %key, error = %e, "github: spooled asset unreadable");
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
            cfg.github.token = Some("t0ken".into());
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
