// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

pub(crate) mod ansible;
mod cargo_registry;
mod conan;
pub(crate) mod cpan;
#[cfg(feature = "deb")]
pub(crate) mod deb;
pub mod docker;
pub mod docker_auth;
pub(crate) mod gems;
mod go;
mod maven;
pub(crate) mod npm;
pub(crate) mod nuget;
pub(crate) mod pub_dart;
pub(crate) mod pypi;
pub(crate) mod range;
pub(crate) mod raw;
#[cfg(feature = "rpm")]
pub(crate) mod rpm;
pub(crate) mod terraform;

// Cross-registry regression suite for namespace isolation on metadata paths (contrib-kit#68).
#[cfg(test)]
mod ns_isolation_metadata_tests;

pub use ansible::routes as ansible_routes;
pub use cargo_registry::routes as cargo_routes;
pub use conan::routes as conan_routes;
pub use cpan::routes as cpan_routes;
#[cfg(feature = "deb")]
pub use deb::routes as deb_routes;
pub use docker::routes as docker_routes;
pub use docker_auth::DockerAuth;
pub use gems::routes as gems_routes;
pub use go::routes as go_routes;
pub use maven::routes as maven_routes;
pub use npm::routes as npm_routes;

// Storage-key builders reused by `nora import` so imported keys are
// byte-identical to the keys these handlers serve — GC/retention/UI browse walk
// keys as strings (review R7, contract `import-key-format-equals-handler-key-format`).
pub(crate) use maven::storage_key as maven_storage_key;
pub use nuget::alias_routes as nuget_alias_routes;
pub use nuget::routes as nuget_routes;
pub(crate) use nuget::HostedIndex as NugetHostedIndex;
pub use pub_dart::routes as pub_dart_routes;
pub use pypi::routes as pypi_routes;
// Retention retires a PyPI file's hash markers together with the file.
pub(crate) use pypi::HASH_MARKER_PREFIX as PYPI_HASH_MARKER_PREFIX;
// Retention and the repo index tell distribution files from sidecars and group releases.
pub(crate) use pypi::is_valid_pypi_filename as is_pypi_dist_filename;
pub(crate) use pypi::version_from_filename as pypi_version_from_filename;
pub use raw::routes as raw_routes;
pub(crate) use raw::storage_key as raw_storage_key;
#[cfg(feature = "rpm")]
pub use rpm::routes as rpm_routes;
pub use terraform::routes as terraform_routes;

use crate::circuit_breaker::{BreakerScope, CircuitBreakerRegistry};
use crate::config::UpstreamAuth;
use crate::metrics::{UPSTREAM_POLICY_BLOCKED_TOTAL, UPSTREAM_REQUEST_DURATION};
use crate::AppState;
use axum::body::{Body, Bytes};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use futures::StreamExt;
use std::time::{Duration, Instant};

/// The body of a publish handler that needs it whole in memory (npm, Maven, Cargo,
/// deb, rpm), capped at `server.publish_body_limit_mb` instead of the global
/// `body_limit_mb` that streamed Docker uploads need. A bigger body is a 413 as soon
/// as the cap is crossed, before it is buffered whole.
pub(crate) struct PublishBody(pub Bytes);

impl axum::extract::FromRequest<AppState> for PublishBody {
    type Rejection = Response;

    async fn from_request(req: axum::extract::Request, state: &AppState) -> Result<Self, Response> {
        let cap = state.config.server.publish_body_limit();
        match axum::body::to_bytes(req.into_body(), cap).await {
            Ok(body) => Ok(Self(body)),
            Err(_) => Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("Publish body too large. Max size: {cap} bytes"),
            )
                .into_response()),
        }
    }
}

/// Remove the files directly in `dir` whose last write is at least `max_age` ago.
///
/// For the dedicated temp directories of streamed uploads and proxy fetches: a
/// transfer in progress keeps writing its file, so it never gets that old, while a
/// file orphaned by a crash (SIGKILL, OOM) or a failed commit stops changing and is
/// reaped. A missing directory is not an error. Returns how many files were removed.
pub(crate) fn remove_stale_temp_files(dir: &std::path::Path, max_age: Duration) -> u64 {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return 0,
        Err(e) => {
            tracing::warn!(path = %dir.display(), error = %e, "Failed to read temp directory for cleanup");
            return 0;
        }
    };
    let mut removed = 0u64;
    for entry in entries.flatten() {
        let is_stale = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age >= max_age);
        if is_stale && std::fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// 405 Method Not Allowed with `Allow` header (RFC 9110 §15.5.6).
pub(crate) fn method_not_allowed(allow: &'static str) -> Response {
    (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, allow)]).into_response()
}

/// How many JSON sidecars an index rebuild fetches from storage at once.
/// The rpm/deb rebuild runs inside every publish request; sequential reads
/// made each PUT O(repo size) in storage round-trips (~2 min per upload at
/// ~1.7k packages on GCS).
const SIDECAR_READ_CONCURRENCY: usize = 32;

#[cfg(any(feature = "rpm", feature = "deb"))]
/// Read and parse every JSON sidecar under `prefix`, fetching concurrently.
///
/// Returns records in arbitrary order — callers sort for deterministic
/// index output, so ordering here is free to follow fetch completion.
pub(crate) async fn read_json_sidecars<T: serde::de::DeserializeOwned>(
    storage: &crate::storage::Storage,
    prefix: &str,
) -> Result<Vec<T>, String> {
    use futures::TryStreamExt;
    let keys = storage
        .list(prefix)
        .await
        .map_err(|e| format!("list sidecars: {e}"))?;
    futures::stream::iter(keys)
        .map(|key| async move {
            let data = storage
                .get(&key)
                .await
                .map_err(|e| format!("read sidecar {key}: {e}"))?;
            serde_json::from_slice::<T>(&data).map_err(|e| format!("parse sidecar {key}: {e}"))
        })
        .buffer_unordered(SIDECAR_READ_CONCURRENCY)
        .try_collect()
        .await
}

/// Read every key under `prefix` concurrently, returning the pairs that came back.
///
/// [`read_json_sidecars`] drops the key and fails the whole batch on the first bad
/// entry, which suits an index rebuild that parses records. A packument rebuild needs
/// neither: the key *is* the version, and one unreadable version must not turn a
/// partial packument into no packument — the sequential loop this replaces skipped
/// such a key and carried on. Same concurrency, same reason: on an object store each
/// read is a network round-trip, and a package with a few thousand versions paid them
/// one at a time.
pub(crate) async fn read_keyed_blobs(
    storage: &crate::storage::Storage,
    prefix: &str,
) -> Vec<(String, axum::body::Bytes)> {
    use futures::StreamExt;
    let Ok(keys) = storage.list(prefix).await else {
        return Vec::new();
    };
    futures::stream::iter(keys)
        .map(|key| async move {
            let data = storage.get(&key).await.ok()?;
            Some((key, data))
        })
        .buffer_unordered(SIDECAR_READ_CONCURRENCY)
        .filter_map(|pair| async move { pair })
        .collect()
        .await
}

#[cfg(any(feature = "rpm", feature = "deb"))]
/// 409 for a write against a pull-through repo (rpm/deb `proxies` entry) —
/// its content mirrors the upstream; local publish/delete/reindex would
/// diverge from (and be clobbered by) the next upstream metadata refresh.
pub(crate) fn proxied_repo_conflict() -> Response {
    (
        StatusCode::CONFLICT,
        "Repository is a pull-through proxy (read-only)",
    )
        .into_response()
}

/// Replace `from`→`to` in raw JSON text, matching BOTH the plain form and the
/// JSON slash-escaped form (`\/`) of `from`.
///
/// Raw-text registry rewrites (ansible, nuget) `.replace()` on the unparsed
/// upstream response. A valid JSON escaping that many origins emit —
/// `"https:\/\/host\/path"` — dodges a plain `https://host/path` needle, so the
/// upstream URL survives the rewrite and leaks the host once the client's JSON
/// parser unescapes `\/`→`/` (#385, class of #377/#379/#380/#381). Handling the
/// `\/` form here closes that. NB: `\uXXXX`-escaped separators are a documented
/// residual — see `rewrite-drops-upstream-host` — caught by the runtime
/// `UPSTREAM_URL_LEAK_TOTAL` detector, not by this string pass.
pub(crate) fn replace_url_escape_aware(text: &str, from: &str, to: &str) -> String {
    let plain = text.replace(from, to);
    let esc_from = from.replace('/', "\\/");
    if !plain.contains(&esc_from) {
        return plain;
    }
    let esc_to = to.replace('/', "\\/");
    plain.replace(&esc_from, &esc_to)
}

/// Build NORA base URL from config (for URL rewriting).
///
/// Thin wrapper over [`ServerConfig::public_base_url`] — the single source of
/// truth for client-facing URLs.
pub(crate) fn nora_base_url(state: &AppState) -> String {
    state.config.server.public_base_url()
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum ProxyError {
    NotFound,
    Upstream(u16),
    Network(String),
    CircuitOpen(String),
    /// The request (connect, headers or body) exceeded its timeout.
    Timeout(String),
    /// Upstream answered 429; carries its `Retry-After` value, if any.
    RateLimited(Option<String>),
    /// Upstream answered 401/403: a credential or policy refusal, not a missing artifact.
    Denied(u16),
    /// The body could not be spooled locally: nora's own disk or budget, not upstream.
    Spool(SpoolError),
}

/// Classify a transport-level reqwest failure.
fn transport_error(e: reqwest::Error) -> ProxyError {
    if e.is_timeout() {
        ProxyError::Timeout(e.to_string())
    } else {
        ProxyError::Network(e.to_string())
    }
}

/// Classify an upstream 4xx. Only a plain 4xx (404/410…) means "no such artifact";
/// throttling and auth refusals must not reach clients as a cacheable 404.
pub(crate) fn upstream_4xx(status: u16, headers: &reqwest::header::HeaderMap) -> ProxyError {
    match status {
        429 => ProxyError::RateLimited(
            headers
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
        ),
        401 | 403 => ProxyError::Denied(status),
        _ => ProxyError::NotFound,
    }
}

/// Client response for an upstream fetch that failed with nothing cached to fall
/// back on. Only an upstream not-found is a 404: NuGet, npm and pip treat 404 as
/// "package does not exist" and do not retry, while they retry 502/503/504.
pub(crate) fn proxy_error_response(registry: &str, url: &str, err: &ProxyError) -> Response {
    let status = match err {
        ProxyError::NotFound => return StatusCode::NOT_FOUND.into_response(),
        ProxyError::CircuitOpen(reg) => return circuit_open_response(reg),
        ProxyError::Spool(e) => return e.response(registry),
        ProxyError::RateLimited(retry_after) => {
            tracing::warn!(
                registry,
                url,
                ?retry_after,
                "upstream rate-limited the request, returning 503"
            );
            let value = retry_after
                .as_deref()
                .and_then(|v| HeaderValue::from_str(v).ok())
                .unwrap_or_else(|| HeaderValue::from_static("30"));
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                [(header::RETRY_AFTER, value)],
                format!("upstream {registry} rate limited"),
            )
                .into_response();
        }
        ProxyError::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
        ProxyError::Denied(_) | ProxyError::Upstream(_) | ProxyError::Network(_) => {
            StatusCode::BAD_GATEWAY
        }
    };
    tracing::warn!(registry, url, error = ?err, status = status.as_u16(), "upstream fetch failed");
    status.into_response()
}

/// Outcome of a cache read on a proxy path: `Ok(Some)` hit, `Ok(None)` go upstream,
/// `Err` respond now. A storage fault is a retryable 503, never a 404; a cached
/// object failing its pin is refetched, except for an internal (never proxied) name.
#[allow(clippy::result_large_err)] // the Err is the response returned at once
pub(crate) fn cache_read<T>(
    result: crate::storage::Result<T>,
    registry: &str,
    key: &str,
    internal: bool,
) -> Result<Option<T>, Response> {
    use crate::storage::StorageError;
    match result {
        Ok(v) => Ok(Some(v)),
        Err(StorageError::NotFound) => Ok(None),
        Err(StorageError::IntegrityViolation) => {
            tracing::warn!(registry, key, "cached object failed integrity verification");
            if internal {
                Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
            } else {
                Ok(None)
            }
        }
        Err(e) => {
            tracing::warn!(registry, key, error = %e, "cache read failed, returning 503");
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                [(header::RETRY_AFTER, HeaderValue::from_static("10"))],
                "storage temporarily unavailable",
            )
                .into_response())
        }
    }
}

/// The `Authorization` value for an upstream request, built before the breaker is
/// consulted: a credential that cannot be a header is a configuration fault, not an
/// upstream outage, so it must neither reach the wire nor count toward opening the
/// breaker. Config loading rejects such tokens first (#1055); this is the backstop.
fn upstream_auth_header(
    auth: Option<UpstreamAuth<'_>>,
) -> Result<Option<reqwest::header::HeaderValue>, ProxyError> {
    auth.map(UpstreamAuth::header_value)
        .transpose()
        // `InvalidHeaderValue` displays a fixed text, never the header bytes — the
        // token cannot leak into the error (http 1.5 `header/value.rs`).
        .map_err(|e| ProxyError::Network(format!("upstream credential rejected: {e}")))
}

/// What the upstreams of a cold miss said, to answer it once every upstream was asked. A
/// miss is "not found" only when an upstream said so; when every upstream failed (5xx after
/// the retry, unreachable, breaker open) it is a gateway failure: a client that records a
/// 404 as "this artifact does not exist" (Maven) must not learn that from an outage.
/// One upstream answering "not found" decides 404 while another failed, as a group
/// repository skips a member that is down; with no upstream configured it is 404.
#[derive(Debug, Default)]
pub(crate) struct UpstreamMiss {
    not_found: bool,
    failed: bool,
}

impl UpstreamMiss {
    /// The miss of a format with a single upstream, from its one answer.
    pub(crate) fn of(e: &ProxyError) -> Self {
        let mut miss = Self::default();
        miss.record(e);
        miss
    }

    /// Record one upstream's answer. Any 4xx is an answer, even where a fetch reports it as
    /// `Upstream(4xx)` rather than `NotFound` (Docker manifests); 5xx, network errors and an
    /// open breaker are failures.
    pub(crate) fn record(&mut self, e: &ProxyError) {
        match e {
            ProxyError::NotFound => self.not_found = true,
            ProxyError::Upstream(code) if (400..500).contains(code) => self.not_found = true,
            // Throttling, auth refusals, timeouts and nora's own spool are never "not found".
            ProxyError::Upstream(_)
            | ProxyError::Network(_)
            | ProxyError::CircuitOpen(_)
            | ProxyError::Timeout(_)
            | ProxyError::RateLimited(_)
            | ProxyError::Denied(_)
            | ProxyError::Spool(_) => self.failed = true,
        }
    }

    /// Fold in one upstream that was asked under several names (Docker's `library/` fallback
    /// asks it for `alpine` and `library/alpine`): it said "not found" only if it failed
    /// under none of them, since a 4xx for one name says nothing about the other.
    pub(crate) fn record_upstream(&mut self, asked: &UpstreamMiss) {
        if asked.failed {
            self.failed = true;
        } else if asked.not_found {
            self.not_found = true;
        }
    }

    /// The status for the miss: 502 when upstreams were asked and every one failed.
    pub(crate) fn status(&self) -> StatusCode {
        if self.failed && !self.not_found {
            StatusCode::BAD_GATEWAY
        } else {
            StatusCode::NOT_FOUND
        }
    }

    /// The response for the miss, logging a gateway failure for the operator.
    pub(crate) fn response(&self, registry: &str, path: &str) -> Response {
        let status = self.status();
        if status == StatusCode::BAD_GATEWAY {
            tracing::warn!(registry, path, "every upstream failed, returning 502");
        }
        status.into_response()
    }
}

/// 503 response for circuit breaker open state with Retry-After header.
pub(crate) fn circuit_open_response(registry: &str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [("retry-after", "30")],
        format!("upstream {} temporarily unavailable", registry),
    )
        .into_response()
}

/// Detect a policy/geo block signature on an upstream 4xx response, returning a
/// bounded reason label (low metric cardinality) or `None` for a genuine 4xx.
///
/// Currently keys off `x-amzn-waf-reason`, which AWS CloudFront + WAF sets when a
/// rule blocks a request — a trade-control/geo rule returns it as a 404 that is
/// otherwise indistinguishable from a not-found (#881). More signatures can be
/// added here without touching the call site.
fn policy_block_reason(headers: &reqwest::header::HeaderMap) -> Option<&'static str> {
    let reason = headers.get("x-amzn-waf-reason")?;
    let is_geo = reason
        .to_str()
        .map(|v| v.eq_ignore_ascii_case("geo"))
        .unwrap_or(false);
    Some(if is_geo { "geo" } else { "waf" })
}

/// Core fetch logic with retry. Callers provide a response extractor.
///
/// `timeout` bounds each attempt from connect to the end of the body, or, with
/// `headers_only`, to the response headers: the extractor then reads the body
/// under its own idle timeout, so a large artifact is bounded by progress, not by
/// `timeout` x bandwidth (R2-39).
#[allow(clippy::too_many_arguments)]
async fn proxy_fetch_core<T, F, Fut>(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
    headers_only: bool,
    auth: Option<UpstreamAuth<'_>>,
    extra_headers: Option<(&str, &str)>,
    extract: F,
    cb: &CircuitBreakerRegistry,
    scope: impl Into<BreakerScope<'_>>,
) -> Result<T, ProxyError>
where
    F: Fn(reqwest::Response) -> Fut + Copy,
    Fut: std::future::Future<Output = Result<T, ProxyError>>,
{
    let auth_header = upstream_auth_header(auth)?;
    let scope = scope.into();
    let registry_str = scope.registry().as_str();
    let cb_key = scope.key();
    let probe = cb.check(&cb_key)?;

    for attempt in 0..2 {
        let mut request = client.get(url);
        if !headers_only {
            request = request.timeout(timeout);
        }
        if let Some(value) = &auth_header {
            request = request.header(header::AUTHORIZATION, value.clone());
        }
        if let Some((key, val)) = extra_headers {
            request = request.header(key, val);
        }

        let upstream_start = Instant::now();
        let sent = if headers_only {
            match tokio::time::timeout(timeout, request.send()).await {
                Ok(sent) => sent.map_err(transport_error),
                Err(_) => Err(ProxyError::Timeout(format!(
                    "no response headers within {timeout:?}"
                ))),
            }
        } else {
            request.send().await.map_err(transport_error)
        };
        match sent {
            Ok(response) => {
                let elapsed = upstream_start.elapsed().as_secs_f64();
                if response.status().is_success() {
                    UPSTREAM_REQUEST_DURATION
                        .with_label_values(&[registry_str, "2xx"])
                        .observe(elapsed);
                    let result = extract(response).await;
                    match &result {
                        // A local spool refusal or failure is nora's, not upstream's.
                        Ok(_) | Err(ProxyError::Spool(_)) => cb.record_success(&cb_key, probe),
                        // 2xx but the body could not be read (e.g. a mid-stream
                        // drop) — treat as a fetch failure for the breaker.
                        Err(_) => cb.record_failure(&cb_key, probe),
                    }
                    return result;
                }
                let status = response.status().as_u16();
                if (400..500).contains(&status) {
                    UPSTREAM_REQUEST_DURATION
                        .with_label_values(&[registry_str, "4xx"])
                        .observe(elapsed);
                    // A policy/geo block (e.g. an AWS WAF geo rule) is a 4xx that is
                    // effectively an outage dressed up as a not-found: it logs nothing,
                    // never moves the breaker, and only bumps the 4xx metric — so an
                    // operator cannot tell it apart from a genuine 404. Surface it
                    // distinctly when the response carries a block signature (#881).
                    // A plain 4xx (no signature) stays silent, exactly as before.
                    if let Some(reason) = policy_block_reason(response.headers()) {
                        UPSTREAM_POLICY_BLOCKED_TOTAL
                            .with_label_values(&[registry_str, reason])
                            .inc();
                        tracing::warn!(
                            registry = registry_str,
                            url,
                            status,
                            reason,
                            "upstream returned a policy/geo block (not a genuine not-found) — check egress/region"
                        );
                    }
                    // A 4xx means the upstream is alive and answered — not an
                    // availability failure. `record_alive` closes the breaker
                    // from HalfOpen (so it recovers instead of slow-probing) but
                    // is a no-op in Closed, so a 4xx never clears a real failure
                    // tally (#606). A 429 is the exception: back off.
                    let err = upstream_4xx(status, response.headers());
                    if matches!(err, ProxyError::RateLimited(_)) {
                        cb.record_failure(&cb_key, probe);
                    } else {
                        cb.record_alive(&cb_key, probe);
                    }
                    return Err(err);
                }
                if attempt == 0 {
                    UPSTREAM_REQUEST_DURATION
                        .with_label_values(&[registry_str, "5xx"])
                        .observe(elapsed);
                    tracing::debug!(url, status, "upstream 5xx, retrying in 1s");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                UPSTREAM_REQUEST_DURATION
                    .with_label_values(&[registry_str, "5xx"])
                    .observe(elapsed);
                cb.record_failure(&cb_key, probe);
                return Err(ProxyError::Upstream(status));
            }
            Err(e) => {
                let elapsed = upstream_start.elapsed().as_secs_f64();
                let status_label = if matches!(e, ProxyError::Timeout(_)) {
                    "timeout"
                } else {
                    "error"
                };
                UPSTREAM_REQUEST_DURATION
                    .with_label_values(&[registry_str, status_label])
                    .observe(elapsed);
                if attempt == 0 {
                    tracing::debug!(url, error = ?e, "upstream error, retrying in 1s");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                cb.record_failure(&cb_key, probe);
                return Err(e);
            }
        }
    }
    cb.record_failure(&cb_key, probe);
    Err(ProxyError::Network("max retries exceeded".into()))
}

/// Fetch binary content from upstream proxy with timeout and 1 retry.
pub(crate) async fn proxy_fetch(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
    auth: Option<UpstreamAuth<'_>>,
    cb: &CircuitBreakerRegistry,
    scope: impl Into<BreakerScope<'_>>,
) -> Result<Vec<u8>, ProxyError> {
    proxy_fetch_core(
        client,
        url,
        timeout,
        false,
        auth,
        None,
        |r| async { r.bytes().await.map(|b| b.to_vec()).map_err(transport_error) },
        cb,
        scope,
    )
    .await
}

/// [`proxy_fetch`] returning the body as one refcounted `Bytes`, so the
/// response and the cache write can share it instead of each copying it.
pub(crate) async fn proxy_fetch_bytes(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
    auth: Option<UpstreamAuth<'_>>,
    cb: &CircuitBreakerRegistry,
    scope: impl Into<BreakerScope<'_>>,
) -> Result<Bytes, ProxyError> {
    proxy_fetch_core(
        client,
        url,
        timeout,
        false,
        auth,
        None,
        |r| async { r.bytes().await.map_err(transport_error) },
        cb,
        scope,
    )
    .await
}

/// Run a cold-miss artifact `fetch` for storage `key` under single-flight (#595):
/// concurrent misses share one upstream fetch and one in-memory body. The flag is
/// true for the caller whose own `fetch` ran — the only one that should cache it.
pub(crate) async fn proxy_fetch_shared(
    state: &AppState,
    key: &str,
    registry: &'static str,
    proxy_timeout_secs: u64,
    fetch: impl std::future::Future<Output = Result<Bytes, ProxyError>>,
) -> Result<(Bytes, bool), ProxyError> {
    if !state.config.server.proxy_coalesce {
        return fetch.await.map(|b| (b, true));
    }
    // `fetch` runs at most once per caller: as the leader, or as a follower whose
    // leader failed. Its own result (error included) wins over a shared one.
    let mut own = None;
    let own_slot = &mut own;
    let shared = state
        .proxy_coalesce
        .coalesced(
            &format!("fetch:{key}"),
            registry,
            crate::proxy_coalesce::follower_budget(proxy_timeout_secs),
            move || async move {
                let result = fetch.await;
                let value = result.as_ref().ok().cloned();
                *own_slot = Some(result);
                value
            },
        )
        .await;
    match own {
        Some(result) => result.map(|b| (b, true)),
        None => shared
            .map(|b| (b, false))
            .ok_or_else(|| ProxyError::Network("coalesced fetch returned nothing".into())),
    }
}

// ============================================================================
// Bounded-memory proxied artifacts (C17/C74)
// ============================================================================

/// Subdirectories of `server.spool_dir`: proxied downloads, NuGet pushes, PyPI uploads.
pub(crate) const PROXY_SPOOL_SUBDIR: &str = "proxy-spool";
pub(crate) const NUGET_UPLOAD_SUBDIR: &str = "nuget-uploads";
pub(crate) const PYPI_UPLOAD_SUBDIR: &str = "pypi-uploads";

/// Spool files older than this are orphans (crash, OOM) and reaped: a transfer in
/// progress keeps writing, and a served download is unlinked when its last reader ends.
const SPOOL_MAX_AGE: Duration = Duration::from_secs(4 * 60 * 60);

/// Remove orphaned spool files from every spool directory (startup and the
/// periodic maintenance tick).
pub(crate) fn cleanup_spool_dirs(spool_dir: &std::path::Path) {
    for sub in [PROXY_SPOOL_SUBDIR, NUGET_UPLOAD_SUBDIR, PYPI_UPLOAD_SUBDIR] {
        let dir = spool_dir.join(sub);
        let removed = remove_stale_temp_files(&dir, SPOOL_MAX_AGE);
        if removed > 0 {
            tracing::info!(removed, dir = %dir.display(), "Cleaned up stale spool files");
        }
    }
}

const MIB: u64 = 1024 * 1024;
/// A spool of unknown length reserves budget in steps of this many MiB.
const SPOOL_STEP_MIB: u64 = 8;
/// Free space a spool always leaves on its filesystem, so that with `spool_dir` on
/// the data volume the tokens and the quarantine ledger can still be written.
const SPOOL_FREE_FLOOR: u64 = 64 * MIB;

/// Why a body could not be spooled. Never an upstream failure.
#[derive(Debug)]
pub(crate) enum SpoolError {
    /// `server.spool_max_mb` is in use by other transfers: retry shortly.
    Busy,
    /// Larger than the cap (bytes) or than the whole budget: no retry can fit it.
    TooLarge(u64),
    /// Local disk failure (path in the message).
    Io(std::io::Error),
}

impl SpoolError {
    /// A local I/O error on `path`, the path kept in its message for the log.
    pub(crate) fn io(path: &std::path::Path) -> impl FnOnce(std::io::Error) -> Self + '_ {
        move |e| {
            SpoolError::Io(std::io::Error::new(
                e.kind(),
                format!("{}: {e}", path.display()),
            ))
        }
    }

    /// The client response, logged and counted in `nora_spool_failures_total`:
    /// 503 + `Retry-After` while the budget is busy (NuGet, npm and pip retry it),
    /// 507 when the body cannot fit or the volume is full, 500 for another local
    /// failure. Never 502: nothing here is upstream's fault.
    pub(crate) fn response(&self, registry: &str) -> Response {
        let (reason, response) = match self {
            SpoolError::Busy => (
                "busy",
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [(header::RETRY_AFTER, HeaderValue::from_static("10"))],
                    "spool budget in use, retry shortly",
                )
                    .into_response(),
            ),
            SpoolError::TooLarge(cap) => (
                "too_large",
                (
                    StatusCode::INSUFFICIENT_STORAGE,
                    format!("body exceeds the {} MiB spool cap", cap / MIB),
                )
                    .into_response(),
            ),
            SpoolError::Io(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::StorageFull | std::io::ErrorKind::QuotaExceeded
                ) =>
            {
                ("no_space", StatusCode::INSUFFICIENT_STORAGE.into_response())
            }
            SpoolError::Io(_) => ("io", StatusCode::INTERNAL_SERVER_ERROR.into_response()),
        };
        if let SpoolError::Io(e) = self {
            tracing::error!(registry, reason, error = %e, "local spool failure (not upstream)");
        } else {
            tracing::warn!(registry, reason, error = ?self, "spool refused the body");
        }
        crate::metrics::SPOOL_FAILURES
            .with_label_values(&[registry, reason])
            .inc();
        response
    }
}

/// The disk spool directory and its byte budget (`server.spool_dir`,
/// `server.spool_max_mb`), shared by proxied downloads, NuGet pushes and PyPI uploads.
#[derive(Debug)]
pub(crate) struct SpoolBudget {
    dir: std::path::PathBuf,
    /// One permit per MiB; `None` = no budget.
    permits: Option<std::sync::Arc<tokio::sync::Semaphore>>,
    total_mib: u64,
}

impl SpoolBudget {
    pub(crate) fn new(config: &crate::config::Config) -> Self {
        let total_mib = config
            .server
            .spool_max_mb
            .min(tokio::sync::Semaphore::MAX_PERMITS as u64);
        Self {
            dir: config.server.spool_dir(&config.storage.path),
            permits: (total_mib > 0)
                .then(|| std::sync::Arc::new(tokio::sync::Semaphore::new(total_mib as usize))),
            total_mib,
        }
    }

    /// `{spool_dir}/{sub}`.
    pub(crate) fn dir(&self, sub: &str) -> std::path::PathBuf {
        self.dir.join(sub)
    }

    /// Reserve room for a spool of `len` bytes; [`SpoolReservation::grow`] adds more.
    /// Never waits: a busy budget is an immediate [`SpoolError::Busy`].
    pub(crate) fn reserve(&self, len: u64) -> Result<SpoolReservation, SpoolError> {
        let mut reservation = SpoolReservation {
            permits: self.permits.clone(),
            held: None,
            mib: 0,
            total_mib: self.total_mib,
            dir: self.dir.clone(),
        };
        reservation.grow(len)?;
        Ok(reservation)
    }
}

/// Budget held by one spool file; released when dropped.
#[derive(Debug)]
pub(crate) struct SpoolReservation {
    permits: Option<std::sync::Arc<tokio::sync::Semaphore>>,
    held: Option<tokio::sync::OwnedSemaphorePermit>,
    mib: u64,
    total_mib: u64,
    dir: std::path::PathBuf,
}

impl SpoolReservation {
    /// Make room for `len` bytes in all, if the budget and the filesystem's free
    /// space (above [`SPOOL_FREE_FLOOR`]) have it.
    pub(crate) fn grow(&mut self, len: u64) -> Result<(), SpoolError> {
        let need = len.div_ceil(MIB);
        if need <= self.mib {
            return Ok(());
        }
        if self.total_mib > 0 && need > self.total_mib {
            return Err(SpoolError::TooLarge(self.total_mib * MIB));
        }
        // ponytail: concurrent spools check the free space independently; the
        // budget, sized below the spool volume, is the hard bound.
        if free_space(&self.dir)
            .is_some_and(|free| free < (need - self.mib) * MIB + SPOOL_FREE_FLOOR)
        {
            return Err(SpoolError::Io(std::io::Error::new(
                std::io::ErrorKind::StorageFull,
                format!("{}: below the spool free-space floor", self.dir.display()),
            )));
        }
        // A step ahead when the budget has it, else exactly what is needed.
        let step = need.next_multiple_of(SPOOL_STEP_MIB);
        let step = if self.total_mib > 0 {
            step.min(self.total_mib)
        } else {
            step
        };
        if let Some(permits) = &self.permits {
            let acquire = |mib: u64| {
                std::sync::Arc::clone(permits).try_acquire_many_owned((mib - self.mib) as u32)
            };
            let (permit, got) = match acquire(step) {
                Ok(p) => (p, step),
                Err(_) => (acquire(need).map_err(|_| SpoolError::Busy)?, need),
            };
            match &mut self.held {
                Some(held) => held.merge(permit),
                None => self.held = Some(permit),
            }
            self.mib = got;
        } else {
            self.mib = step;
        }
        Ok(())
    }
}

/// Bytes available to an unprivileged writer on the filesystem of `dir` (or of its
/// nearest existing ancestor); `None` where that cannot be told.
fn free_space(dir: &std::path::Path) -> Option<u64> {
    #[cfg(unix)]
    {
        dir.ancestors()
            .find_map(|p| rustix::fs::statvfs(p).ok())
            .map(|s| s.f_bavail.saturating_mul(s.f_frsize))
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        None
    }
}

/// An upstream body spooled to a temp file with its SHA-256 computed on the way in.
/// The file is removed, and its budget released, when the last holder (response,
/// follower, cache write) drops.
#[derive(Debug)]
pub(crate) struct SpoolFile {
    path: std::path::PathBuf,
    sha256: String,
    len: u64,
    _reservation: SpoolReservation,
}

impl Drop for SpoolFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A proxied artifact body: in memory, or spooled to disk when it is larger than
/// `server.stream_threshold_mb`. Cloning is O(1) either way.
#[derive(Clone, Debug)]
pub(crate) enum ProxyBody {
    Mem(Bytes),
    File(std::sync::Arc<SpoolFile>),
}

/// The next body chunk, failing as a timeout when upstream sends nothing for `idle`.
async fn next_chunk(
    response: &mut reqwest::Response,
    idle: Duration,
) -> Result<Option<Bytes>, ProxyError> {
    match tokio::time::timeout(idle, response.chunk()).await {
        Ok(chunk) => chunk.map_err(transport_error),
        Err(_) => Err(ProxyError::Timeout(format!(
            "upstream body stalled for {idle:?}"
        ))),
    }
}

/// Read an upstream response body, each chunk under the `idle` timeout: whole into
/// memory up to `threshold` bytes (0 = always), else to a spool file under `spool`'s
/// budget with a running SHA-256, never holding more than one chunk of it. A body
/// above `cap` is refused on its `Content-Length` before any of it is read, or as
/// soon as the running count crosses the cap.
async fn read_or_spool(
    mut response: reqwest::Response,
    spool: &SpoolBudget,
    threshold: u64,
    cap: Option<u64>,
    idle: Duration,
) -> Result<ProxyBody, ProxyError> {
    use sha2::Digest;
    use tokio::io::AsyncWriteExt;
    let over_cap = |len: u64| cap.is_some_and(|cap| len > cap);
    let too_large = || ProxyError::Spool(SpoolError::TooLarge(cap.unwrap_or_default()));
    let in_memory = |len: u64| threshold == 0 || len <= threshold;
    let declared = response.content_length();
    if declared.is_some_and(over_cap) {
        return Err(too_large());
    }
    // A body known to spill reserves its whole length before any of it is read.
    let mut reservation = match declared.filter(|&n| !in_memory(n)) {
        Some(n) => Some(spool.reserve(n).map_err(ProxyError::Spool)?),
        None => None,
    };
    // Buffer until the threshold, then spill.
    let mut head = Vec::with_capacity(declared.unwrap_or(0).min(threshold) as usize);
    loop {
        let Some(chunk) = next_chunk(&mut response, idle).await? else {
            return Ok(ProxyBody::Mem(Bytes::from(head)));
        };
        head.extend_from_slice(&chunk);
        if over_cap(head.len() as u64) {
            return Err(too_large());
        }
        if !in_memory(head.len() as u64) {
            break;
        }
    }
    let mut len = head.len() as u64;
    let mut reservation = match reservation.take() {
        Some(r) => r,
        None => spool.reserve(len).map_err(ProxyError::Spool)?,
    };
    let dir = spool.dir(PROXY_SPOOL_SUBDIR);
    let path = dir.join(uuid::Uuid::new_v4().to_string());
    let local = |e| ProxyError::Spool(SpoolError::io(&path)(e));
    let mut guard = TempFileGuard::new(path.clone());
    tokio::fs::create_dir_all(&dir).await.map_err(local)?;
    let mut file = tokio::fs::File::create(&path).await.map_err(local)?;
    let mut hasher = sha2::Sha256::new();
    hasher.update(&head);
    file.write_all(&head).await.map_err(local)?;
    drop(head);
    while let Some(chunk) = next_chunk(&mut response, idle).await? {
        len += chunk.len() as u64;
        if over_cap(len) {
            return Err(too_large());
        }
        reservation.grow(len).map_err(ProxyError::Spool)?;
        hasher.update(&chunk);
        file.write_all(&chunk).await.map_err(local)?;
    }
    // Durable before the cache write renames a link to it into place (local backend).
    file.sync_all().await.map_err(local)?;
    guard.disarm();
    Ok(ProxyBody::File(std::sync::Arc::new(SpoolFile {
        path,
        sha256: hex::encode(hasher.finalize()),
        len,
        _reservation: reservation,
    })))
}

/// How long a coalesced follower waits for the leader's artifact download. The
/// leader is bounded by progress (idle timeout) rather than total time, and a
/// follower that gave up would download and spool the same body again.
const ARTIFACT_FOLLOWER_BUDGET: Duration = Duration::from_secs(30 * 60);

/// Cold-miss fetch of a proxied artifact (NuGet `.nupkg`, npm tarball, PyPI file)
/// for storage `key`, with bounded memory and under single-flight (#595).
///
/// A body above `server.stream_threshold_mb` is spooled to disk instead of
/// buffered, within the spool budget; concurrent misses on one key share one
/// upstream fetch and one body (the same spool file). `timeout_secs` bounds the
/// response headers of each attempt and every stall of the body, not the whole
/// download. The flag is true for the caller whose own fetch ran — the only one
/// that should cache it.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn proxy_fetch_artifact(
    state: &AppState,
    key: &str,
    registry: &'static str,
    url: &str,
    timeout_secs: u64,
    auth: Option<UpstreamAuth<'_>>,
    scope: impl Into<BreakerScope<'_>>,
) -> Result<(ProxyBody, bool), ProxyError> {
    let spool = state.spool.as_ref();
    let threshold = state.config.server.stream_threshold();
    let cap = state.config.server.proxy_max_artifact();
    let timeout = Duration::from_secs(timeout_secs);
    let fetch = proxy_fetch_core(
        &state.http_client,
        url,
        timeout,
        true,
        auth,
        None,
        |r| read_or_spool(r, spool, threshold, cap, timeout),
        &state.circuit_breaker,
        scope,
    );
    if !state.config.server.proxy_coalesce {
        return fetch.await.map(|b| (b, true));
    }
    // As `proxy_fetch_shared`: the caller's own result (error included) wins.
    let mut own = None;
    let own_slot = &mut own;
    let shared = state
        .artifact_flights
        .coalesced(
            &format!("fetch:{key}"),
            registry,
            crate::proxy_coalesce::follower_budget(timeout_secs).max(ARTIFACT_FOLLOWER_BUDGET),
            move || async move {
                let result = fetch.await;
                let value = result.as_ref().ok().cloned();
                *own_slot = Some(result);
                value
            },
        )
        .await;
    match own {
        Some(result) => result.map(|b| (b, true)),
        None => shared
            .map(|b| (b, false))
            .ok_or_else(|| ProxyError::Network("coalesced fetch returned nothing".into())),
    }
}

impl ProxyBody {
    /// Lowercase hex SHA-256 of the body (computed now for an in-memory one).
    pub(crate) fn sha256(&self) -> String {
        use sha2::Digest;
        match self {
            ProxyBody::Mem(b) => hex::encode(sha2::Sha256::digest(b)),
            ProxyBody::File(f) => f.sha256.clone(),
        }
    }

    /// `sha256:<hex>`, the form the digest gates take.
    pub(crate) fn digest(&self) -> String {
        format!("sha256:{}", self.sha256())
    }

    pub(crate) fn len(&self) -> u64 {
        match self {
            ProxyBody::Mem(b) => b.len() as u64,
            ProxyBody::File(f) => f.len,
        }
    }

    /// Response body: the buffer itself, or the spool file streamed through an EOF
    /// check against the digest taken while spooling.
    pub(crate) async fn into_body(self, key: &str) -> std::io::Result<Body> {
        match self {
            ProxyBody::Mem(b) => Ok(Body::from(b)),
            ProxyBody::File(spool) => {
                // Open while holding the Arc: once open, the data outlives the unlink.
                let file = tokio::fs::File::open(&spool.path).await?;
                let stream = raw::verify_while_streaming(
                    Box::pin(file),
                    Some(spool.sha256.clone()),
                    key.to_string(),
                    None,
                );
                Ok(nora_registry::verified::stream_body(stream))
            }
        }
    }

    /// Cache the body at `key`; when `immutable`, only if nothing is stored there
    /// yet. A spool file goes in through `put_from_path`, pinned to its digest, from a
    /// hard link (or a copy) of the spool, because the backend consumes its source
    /// while followers may still be reading the spool. Returns whether it wrote.
    ///
    /// An immutable write runs under the key's publish lock, as an upload of the same
    /// file does (PyPI `store_file`): whichever comes first wins and the other leaves
    /// it as is, also for a spool file, whose multipart put cannot be conditional (C53).
    // ponytail: process-local lock, enough for one replica; a second replica would need
    // a conditional multipart complete.
    pub(crate) async fn cache(
        &self,
        state: &AppState,
        key: &str,
        immutable: bool,
    ) -> crate::storage::Result<bool> {
        let storage = &state.storage;
        let lock = immutable.then(|| state.publish_lock(key));
        let _guard = match &lock {
            Some(lock) => Some(lock.lock().await),
            None => None,
        };
        let spool = match self {
            ProxyBody::Mem(b) if immutable => return storage.put_if_absent(key, b.clone()).await,
            ProxyBody::Mem(b) => return storage.put_bytes(key, b.clone()).await.map(|()| true),
            ProxyBody::File(spool) => spool,
        };
        if immutable && storage.stat(key).await.is_some() {
            return Ok(false);
        }
        let src = spool.path.with_extension("put");
        let mut guard = TempFileGuard::new(src.clone());
        if tokio::fs::hard_link(&spool.path, &src).await.is_err() {
            tokio::fs::copy(&spool.path, &src).await?;
        }
        storage
            .put_from_path(key, &src, Some(&spool.sha256))
            .await?;
        guard.disarm();
        Ok(true)
    }
}

/// [`ProxyBody::cache`] (immutable) in the background, as `spawn_cache_immutable`
/// does for a buffer: index invalidated after the write, failures counted.
pub(crate) fn spawn_cache_body(
    state: &AppState,
    registry: &'static str,
    key: String,
    body: ProxyBody,
) {
    let state = state.clone();
    tokio::spawn(async move {
        match body.cache(&state, &key, true).await {
            Ok(true) => state.repo_index.invalidate(registry),
            Ok(false) => {}
            Err(e) => crate::record_cache_write_error(registry, &key, &e),
        }
    });
}

/// A cached proxied artifact: read whole and gated, or (above
/// `server.stream_threshold_mb`) an open reader to stream with its pin.
pub(crate) enum CachedArtifact {
    Buffered(Bytes),
    Streamed {
        len: u64,
        sha256: String,
        reader: std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
    },
}

impl CachedArtifact {
    /// `sha256:<hex>` of the artifact: the verified pin, or hashed now.
    pub(crate) fn digest(&self) -> String {
        use sha2::Digest;
        match self {
            CachedArtifact::Buffered(b) => {
                format!("sha256:{}", hex::encode(sha2::Sha256::digest(b)))
            }
            CachedArtifact::Streamed { sha256, .. } => format!("sha256:{sha256}"),
        }
    }

    pub(crate) fn len(&self) -> u64 {
        match self {
            CachedArtifact::Buffered(b) => b.len() as u64,
            CachedArtifact::Streamed { len, .. } => *len,
        }
    }

    /// Response body. A streamed one is checked against its pin as it goes: a
    /// mismatch aborts the body one frame short, counts as an integrity failure and,
    /// for a provable proxy copy of a non-internal name, deletes the bad copy so the
    /// next request refetches it (C54, [`drop_proxied_copy`]).
    pub(crate) fn into_body(
        self,
        state: &AppState,
        registry: &'static str,
        key: &str,
        internal: bool,
    ) -> Body {
        match self {
            CachedArtifact::Buffered(b) => Body::from(b),
            CachedArtifact::Streamed { sha256, reader, .. } => {
                let state = state.clone();
                let heal_key = key.to_string();
                let heal: Box<dyn FnOnce() + Send + Sync> = Box::new(move || {
                    crate::metrics::STORAGE_OPERATIONS
                        .with_label_values(&["get", "integrity_fail"])
                        .inc();
                    if !internal {
                        tokio::spawn(async move {
                            drop_proxied_copy(&state, registry, &heal_key).await;
                        });
                    }
                });
                nora_registry::verified::stream_body(raw::verify_while_streaming(
                    reader,
                    Some(sha256),
                    key.to_string(),
                    Some(heal),
                ))
            }
        }
    }
}

/// Whether the cached copy at `key` provably came from an upstream. NuGet's flat
/// container holds only proxy fills (hosted packages live under `nuget/hosted/`).
/// npm tarballs and PyPI files share their key space with publishes, uploads and
/// imports: only the provenance record a proxy fill writes (`.nora-origins/<key>`,
/// whose last line is the digest it cached, as GC's eviction reads it) proves one,
/// and only while that digest is still the object's pin.
pub(crate) async fn is_proxied_copy(storage: &crate::Storage, key: &str) -> bool {
    if key.starts_with("nuget/flatcontainer/") {
        return true;
    }
    let Ok(record) = storage.get(&npm::origin_key(key)).await else {
        return false;
    };
    let cached = std::str::from_utf8(&record)
        .ok()
        .and_then(|r| r.lines().last());
    cached.is_some() && storage.pin(key).await.as_deref() == cached
}

/// Delete a cached copy at `key` that failed its pin, so the refetch that follows
/// can cache the upstream bytes again — the immutable write never overwrites a key
/// (C54). Only a provable proxy copy ([`is_proxied_copy`]): anything else may be the
/// only copy of a published or uploaded artifact, so it is kept (and answered with a
/// 500) for an operator to restore. Check and delete run under the key's publish
/// lock, which every writer that can replace the object (npm publish, PyPI upload,
/// an immutable cache fill) holds, so a replacement landing in between is never the
/// one deleted. Returns whether it was dropped.
async fn drop_proxied_copy(state: &AppState, registry: &str, key: &str) -> bool {
    let storage = &state.storage;
    let lock = state.publish_lock(key);
    let _guard = lock.lock().await;
    if !is_proxied_copy(storage, key).await {
        tracing::error!(
            registry,
            key,
            "hosted artifact failed integrity verification: kept, not refetched; restore it from a backup"
        );
        return false;
    }
    if let Err(e) = storage.delete(key).await {
        tracing::warn!(registry, key, error = %e, "could not drop a cached copy failing integrity");
    }
    true
}

/// Cache read of a proxied artifact with bounded memory: [`cache_read`] over
/// `Storage::get_verified_bounded`. A copy failing its integrity pin is dropped
/// and refetched only when it is a provable proxy copy of a non-internal name
/// ([`drop_proxied_copy`]); otherwise the read fails closed with a 500.
pub(crate) async fn read_cached_artifact(
    state: &AppState,
    registry: &str,
    key: &str,
    internal: bool,
) -> Result<Option<CachedArtifact>, Response> {
    use crate::storage::{BoundedRead, StorageError};
    let read = state
        .storage
        .get_verified_bounded(key, state.config.server.stream_threshold())
        .await;
    let fail_closed = internal
        || (matches!(read, Err(StorageError::IntegrityViolation))
            && !drop_proxied_copy(state, registry, key).await);
    Ok(
        cache_read(read, registry, key, fail_closed)?.map(|read| match read {
            BoundedRead::Buffered(outcome) => {
                use nora_registry::verified::{verified_body, GateOutcome};
                CachedArtifact::Buffered(match outcome {
                    GateOutcome::Verified(blob) => verified_body(blob),
                    GateOutcome::Unpinned(blob) => blob.into_inner(),
                })
            }
            BoundedRead::Streamed { len, pin, reader } => CachedArtifact::Streamed {
                len,
                sha256: pin,
                reader,
            },
        }),
    )
}

/// Fetch text content from upstream proxy with timeout and 1 retry.
pub(crate) async fn proxy_fetch_text(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
    auth: Option<UpstreamAuth<'_>>,
    extra_headers: Option<(&str, &str)>,
    cb: &CircuitBreakerRegistry,
    scope: impl Into<BreakerScope<'_>>,
) -> Result<String, ProxyError> {
    proxy_fetch_core(
        client,
        url,
        timeout,
        false,
        auth,
        extra_headers,
        |r| async { r.text().await.map_err(transport_error) },
        cb,
        scope,
    )
    .await
}

/// One pull-through download for a per-repo proxied rpm/deb repository.
///
/// Shared by `rpm::download` and `deb::download` — the flow is the Maven proxy
/// flow minus name-based curation (a proxied repo is declared in config and
/// disjoint from hosted repos, so dependency-confusion gating does not apply;
/// the digest quarantine still gates immutable packages):
/// fresh-cache serve → upstream fetch → background cache → stale fallback.
#[cfg(any(feature = "rpm", feature = "deb"))]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn repo_proxy_download(
    state: &AppState,
    registry: &'static str,
    rt: crate::registry_type::RegistryType,
    display: String,
    key: String,
    url: String,
    auth: Option<UpstreamAuth<'_>>,
    timeout_secs: u64,
    metadata_ttl: i64,
    immutable: bool,
    content_type: &'static str,
) -> Response {
    use crate::activity_log::{ActionType, ActivityEntry};
    use crate::audit::AuditEntry;

    let q_override = match registry {
        "rpm" => &state.config.curation.rpm,
        _ => &state.config.curation.deb,
    };
    let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
        q_override
            .quarantine
            .as_ref()
            .or(state.config.curation.quarantine.as_ref()),
        q_override
            .quarantine_ttl
            .as_deref()
            .or(state.config.curation.quarantine_ttl.as_deref()),
    );

    let serve = |data: Bytes| {
        let mut builder = axum::http::Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type);
        if !immutable {
            builder = builder.header(header::CACHE_CONTROL, "no-cache");
        }
        builder.body(Body::from(data)).expect("valid response")
    };

    let cached = state.storage.get(&key).await.ok();
    let cache_fresh = match &cached {
        None => false,
        Some(_) if immutable => true,
        Some(_) => {
            let modified = state.storage.stat(&key).await.map(|m| m.modified);
            crate::cache_ttl::mutable_ref_fresh(true, metadata_ttl, modified)
        }
    };

    if let Some(ref data) = cached {
        if cache_fresh {
            state.metrics.record_download(registry);
            state.metrics.record_cache_hit(registry);
            state.activity.push(ActivityEntry::new(
                ActionType::CacheHit,
                display,
                rt,
                "CACHE",
            ));
            state
                .audit
                .log(AuditEntry::new("cache_hit", "proxy", "", registry, ""));
            // Quarantine only immutable packages — metadata is rewritten
            // upstream on every sync and its digest would change forever.
            if immutable {
                if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
                    &state.digest_store,
                    registry,
                    data,
                    &q_mode,
                    q_secs,
                    "cache",
                    None,
                ) {
                    return resp;
                }
            }
            return serve(data.clone()).into_response();
        }
    }

    match proxy_fetch(
        &state.http_client,
        &url,
        Duration::from_secs(timeout_secs),
        auth,
        &state.circuit_breaker,
        rt,
    )
    .await
    {
        Ok(data) => {
            let data = Bytes::from(data);
            state.metrics.record_download(registry);
            state.metrics.record_cache_miss(registry);
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                display,
                rt,
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "proxy", "", registry, ""));
            if immutable {
                state.spawn_cache_immutable(registry, key, data.clone());
                if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
                    &state.digest_store,
                    registry,
                    &data,
                    &q_mode,
                    q_secs,
                    &url,
                    None,
                ) {
                    return resp;
                }
            } else {
                state.spawn_cache(registry, key, data.clone());
            }
            serve(data).into_response()
        }
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => {
            // Upstream failed — serve the stale cached copy if we have one.
            if let Some(data) = cached {
                tracing::warn!(registry, url = %url, error = ?e, "upstream failed, serving stale cached copy");
                if immutable {
                    if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
                        &state.digest_store,
                        registry,
                        &data,
                        &q_mode,
                        q_secs,
                        "cache-stale",
                        None,
                    ) {
                        return resp;
                    }
                }
                let mut response = serve(data).into_response();
                response.headers_mut().insert(
                    header::HeaderName::from_static("x-nora-stale"),
                    header::HeaderValue::from_static("true"),
                );
                return response;
            }
            tracing::debug!(registry, url = %url, error = ?e, "proxy fetch failed with no cached copy");
            StatusCode::NOT_FOUND.into_response()
        }
    }
}

/// Forward a POST (request body + an allowlist of headers) to an upstream and
/// return its `(status, body, content-type)` verbatim. Mirrors `proxy_fetch_core`'s
/// circuit-breaker discipline (`check` → send → `record_success`/`record_alive`/
/// `record_failure`, one retry on 5xx/network).
///
/// Used for `npm audit` (#597): a query POST that must return the upstream's answer
/// as-is — including a 4xx (a real audit response, upstream is alive) — with only
/// 5xx / network / circuit-open surfaced as `ProxyError`.
///
/// `auth` is the configured proxy credential (Basic or Bearer); the caller's own
/// `Authorization` is never forwarded — pass only the intended headers in
/// `fwd_headers` (allowlist). The body is not inspected or decompressed here.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn proxy_forward_post(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
    auth: Option<UpstreamAuth<'_>>,
    fwd_headers: &[(&str, &str)],
    body: &[u8],
    cb: &CircuitBreakerRegistry,
    scope: impl Into<BreakerScope<'_>>,
) -> Result<(u16, Vec<u8>, Option<String>), ProxyError> {
    let auth_header = upstream_auth_header(auth)?;
    let scope = scope.into();
    let registry_str = scope.registry().as_str();
    let cb_key = scope.key();
    let probe = cb.check(&cb_key)?;

    for attempt in 0..2 {
        let mut request = client.post(url).timeout(timeout).body(body.to_vec());
        if let Some(value) = &auth_header {
            request = request.header(header::AUTHORIZATION, value.clone());
        }
        for (k, v) in fwd_headers {
            request = request.header(*k, *v);
        }

        let upstream_start = Instant::now();
        match request.send().await {
            Ok(response) => {
                let elapsed = upstream_start.elapsed().as_secs_f64();
                let code = response.status().as_u16();
                let content_type = response
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned);
                if response.status().is_success() {
                    UPSTREAM_REQUEST_DURATION
                        .with_label_values(&[registry_str, "2xx"])
                        .observe(elapsed);
                    match response.bytes().await {
                        Ok(b) => {
                            cb.record_success(&cb_key, probe);
                            return Ok((code, b.to_vec(), content_type));
                        }
                        Err(e) => {
                            cb.record_failure(&cb_key, probe);
                            return Err(ProxyError::Network(e.to_string()));
                        }
                    }
                }
                if (400..500).contains(&code) {
                    UPSTREAM_REQUEST_DURATION
                        .with_label_values(&[registry_str, "4xx"])
                        .observe(elapsed);
                    // Upstream is alive and answered — a 4xx audit response is a real
                    // answer, forward it verbatim (not an availability failure). #606.
                    cb.record_alive(&cb_key, probe);
                    let b = response
                        .bytes()
                        .await
                        .map(|b| b.to_vec())
                        .unwrap_or_default();
                    return Ok((code, b, content_type));
                }
                UPSTREAM_REQUEST_DURATION
                    .with_label_values(&[registry_str, "5xx"])
                    .observe(elapsed);
                if attempt == 0 {
                    tracing::debug!(url, status = code, "upstream 5xx on POST, retrying in 1s");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                cb.record_failure(&cb_key, probe);
                return Err(ProxyError::Upstream(code));
            }
            Err(e) => {
                let elapsed = upstream_start.elapsed().as_secs_f64();
                let status_label = if e.is_timeout() { "timeout" } else { "error" };
                UPSTREAM_REQUEST_DURATION
                    .with_label_values(&[registry_str, status_label])
                    .observe(elapsed);
                if attempt == 0 {
                    tracing::debug!(url, error = %e, "upstream error on POST, retrying in 1s");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                cb.record_failure(&cb_key, probe);
                return Err(transport_error(e));
            }
        }
    }
    cb.record_failure(&cb_key, probe);
    Err(ProxyError::Network("max retries exceeded".into()))
}

// ============================================================================
// Streaming upload helpers (shared by docker blob uploads and raw uploads)
// ============================================================================

/// Outcome of streaming a request body to a temp file with a byte budget.
pub(crate) enum StreamOutcome {
    /// Wrote N bytes successfully.
    Ok(u64),
    /// Budget exceeded — aborted before writing the offending frame (413).
    TooLarge,
    /// Request-body stream errored mid-flight (client disconnect).
    ClientGone,
    /// Local write/flush failure (500).
    Io(std::io::Error),
}

/// Stream `body` into `file`, bounded to `budget` bytes, never holding more than
/// one frame in RAM (#817). The running total is checked BEFORE each write, so at
/// most `budget` bytes ever reach disk — a request over budget aborts without
/// writing the offending frame.
///
/// CANCEL-SAFETY: a pure per-frame read→write loop with no lock held and no
/// shared state mutated. If the future is dropped mid-stream, the partially
/// written file is reclaimed by the caller's `TempFileGuard`; nothing is left
/// half-set.
pub(crate) async fn stream_body_to_file(
    body: Body,
    file: &mut tokio::fs::File,
    budget: u64,
) -> StreamOutcome {
    use tokio::io::AsyncWriteExt;
    let mut stream = body.into_data_stream();
    let mut written: u64 = 0;
    while let Some(frame) = stream.next().await {
        let chunk = match frame {
            Ok(c) => c,
            Err(_) => return StreamOutcome::ClientGone,
        };
        written = written.saturating_add(chunk.len() as u64);
        if written > budget {
            return StreamOutcome::TooLarge;
        }
        if let Err(e) = file.write_all(&chunk).await {
            return StreamOutcome::Io(e);
        }
    }
    if let Err(e) = file.flush().await {
        return StreamOutcome::Io(e);
    }
    // Durability: put_from_path's direct-rename commit relies on the caller
    // having fsync'd the source — without this, a power loss just after the
    // rename can leave the key's directory entry pointing at data that never
    // reached disk (latent for docker since the switch to streaming; #846).
    if let Err(e) = file.sync_all().await {
        return StreamOutcome::Io(e);
    }
    // Postcondition: a successful stream never exceeds the budget — the loop
    // returns TooLarge before writing any frame that would cross it.
    debug_assert!(
        written <= budget,
        "stream_body_to_file wrote {written} bytes > budget {budget}"
    );
    StreamOutcome::Ok(written)
}

/// Parse the `Content-Length` header, if present and well-formed.
pub(crate) fn content_length(headers: &axum::http::HeaderMap) -> Option<u64> {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
}

/// RAII: delete a temp file on drop unless disarmed.
///
/// Ensures temp files are cleaned up on ALL error paths (network errors,
/// hash mismatch, panics, early returns via `?` operator) — #580.
pub(crate) struct TempFileGuard {
    path: Option<std::path::PathBuf>,
}

impl TempFileGuard {
    pub(crate) fn new(path: std::path::PathBuf) -> Self {
        Self { path: Some(path) }
    }

    /// Disarm the guard — caller takes ownership of cleanup.
    /// Call this after successful `put_from_path` (which moves/deletes the file).
    pub(crate) fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(ref path) = self.path {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// sha256 of a file's contents, read in 256 KiB chunks — used to hash a
/// streamed upload without ever holding the body in memory.
pub(crate) async fn sha256_of_file(path: &std::path::Path) -> std::io::Result<String> {
    use sha2::Digest;
    use tokio::io::AsyncReadExt;
    let file = tokio::fs::File::open(path).await?;
    let mut reader = tokio::io::BufReader::new(file);
    let mut hasher = sha2::Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        match reader.read(&mut buf).await? {
            0 => break,
            n => hasher.update(&buf[..n]),
        }
    }
    Ok(hex::encode(hasher.finalize()))
}

// ============================================================================
// Conditional revalidation (#596)
// ============================================================================

/// Upstream cache validators persisted next to a cached object so a later
/// revalidation can send `If-None-Match` / `If-Modified-Since`. Stored as a
/// `<key>.meta` JSON sidecar — filesystem-first, survives restarts (ADR-2).
#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Validators {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
}

impl Validators {
    /// True if at least one validator is present to drive a conditional request.
    pub fn is_some(&self) -> bool {
        self.etag.is_some() || self.last_modified.is_some()
    }
}

/// Outcome of a conditional upstream request.
pub(crate) enum Revalidation {
    /// Upstream answered `304 Not Modified` — the cached body is still valid.
    NotModified,
    /// Upstream answered `200` with a (possibly) new body and fresh validators.
    Modified {
        body: Vec<u8>,
        validators: Validators,
    },
}

/// Storage key of the validator sidecar for a cached object.
pub(crate) fn validators_key(key: &str) -> String {
    format!("{key}.meta")
}

/// Read the stored upstream validators for `key`, if any. Fail-open: any
/// read/parse error yields `None` (caller does a full fetch).
pub(crate) async fn read_validators(storage: &crate::Storage, key: &str) -> Option<Validators> {
    let data = storage.get(&validators_key(key)).await.ok()?;
    serde_json::from_slice::<Validators>(&data).ok()
}

/// Persist upstream validators next to `key`. Written AFTER the body so a
/// sidecar never advertises freshness for a body that is not there. A no-op
/// when there is nothing to store.
pub(crate) async fn write_validators(storage: &crate::Storage, key: &str, v: &Validators) {
    if !v.is_some() {
        return;
    }
    if let Ok(data) = serde_json::to_vec(v) {
        if let Err(e) = storage.put(&validators_key(key), &data).await {
            tracing::warn!(key = %key, error = ?e, "failed to write validator sidecar");
        }
    }
}

/// Record that the cached `key` was just revalidated (upstream answered 304) by
/// stamping `validated_at` (Unix seconds) into its `.meta` sidecar, next to the
/// validators it keeps. Only that small sidecar is written: re-uploading the whole
/// body to bump its mtime cost one full object PUT per key per TTL window (C56).
pub(crate) async fn mark_revalidated(storage: &crate::Storage, registry: &str, key: &str) {
    let sidecar = validators_key(key);
    let mut doc = match storage
        .get(&sidecar)
        .await
        .ok()
        .map(|d| serde_json::from_slice(&d))
    {
        Some(Ok(serde_json::Value::Object(map))) => map,
        _ => serde_json::Map::new(),
    };
    doc.insert("validated_at".into(), crate::cache_ttl::now_unix().into());
    let data = serde_json::Value::Object(doc).to_string();
    if let Err(e) = storage.put(&sidecar, data.as_bytes()).await {
        crate::record_cache_write_error(registry, &sidecar, &e);
    }
}

/// Whether the cached `key`, last written at `modified`, is still fresh under
/// `ttl_secs`: written within the TTL, or revalidated (a 304, see
/// [`mark_revalidated`]) within it. The sidecar is read only when the write time
/// alone says stale.
pub(crate) async fn fresh_within_ttl(
    storage: &crate::Storage,
    key: &str,
    modified: u64,
    ttl_secs: i64,
) -> bool {
    if crate::cache_ttl::is_within_ttl(modified, ttl_secs) {
        return true;
    }
    if ttl_secs <= 0 {
        return false;
    }
    #[derive(serde::Deserialize)]
    struct Freshness {
        validated_at: Option<u64>,
    }
    let Ok(data) = storage.get(&validators_key(key)).await else {
        return false;
    };
    serde_json::from_slice::<Freshness>(&data)
        .ok()
        .and_then(|f| f.validated_at)
        .is_some_and(|t| crate::cache_ttl::is_within_ttl(t, ttl_secs))
}

fn header_string(resp: &reqwest::Response, name: reqwest::header::HeaderName) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// Conditional upstream fetch (#596). Sends `If-None-Match`/`If-Modified-Since`
/// from `validators`; returns `NotModified` on 304 (no body downloaded) or
/// `Modified { body, validators }` on 200. With empty `validators` it sends no
/// conditional headers, so it always yields `Modified` — that is how the full
/// fetch path captures validators for the first time.
///
/// Circuit breaker: 304/200 record success; transport/5xx and a 200 whose body
/// cannot be read record failure; 4xx returns `NotFound` (matching
/// `proxy_fetch_core`). A 5xx or transport error is retried once after 1 s, as in
/// `proxy_fetch_core`: this is also the first (validator-less) fetch of a NuGet
/// registration or version list, where one blip would otherwise be a 5xx.
pub(crate) async fn proxy_fetch_conditional(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
    auth: Option<UpstreamAuth<'_>>,
    validators: &Validators,
    cb: &CircuitBreakerRegistry,
    scope: impl Into<BreakerScope<'_>>,
) -> Result<Revalidation, ProxyError> {
    let auth_header = upstream_auth_header(auth)?;
    let cb_key = scope.into().key();
    let probe = cb.check(&cb_key)?;

    for attempt in 0..2 {
        let mut request = client.get(url).timeout(timeout);
        if let Some(value) = &auth_header {
            request = request.header(header::AUTHORIZATION, value.clone());
        }
        if let Some(ref etag) = validators.etag {
            request = request.header(header::IF_NONE_MATCH, etag);
        }
        if let Some(ref lm) = validators.last_modified {
            request = request.header(header::IF_MODIFIED_SINCE, lm);
        }

        let err = match request.send().await {
            Ok(response) => {
                let status = response.status();
                if status == reqwest::StatusCode::NOT_MODIFIED {
                    cb.record_success(&cb_key, probe);
                    return Ok(Revalidation::NotModified);
                }
                if status.is_success() {
                    let new_validators = Validators {
                        etag: header_string(&response, header::ETAG),
                        last_modified: header_string(&response, header::LAST_MODIFIED),
                    };
                    return match response.bytes().await {
                        Ok(body) => {
                            cb.record_success(&cb_key, probe);
                            Ok(Revalidation::Modified {
                                body: body.to_vec(),
                                validators: new_validators,
                            })
                        }
                        Err(e) => {
                            // 2xx but the body could not be read (e.g. a mid-stream
                            // drop) — a fetch failure for the breaker, as in
                            // proxy_fetch_core; unreported, a half-open probe would
                            // hold its slot until the #585 stall recovery.
                            cb.record_failure(&cb_key, probe);
                            Err(transport_error(e))
                        }
                    };
                }
                let code = status.as_u16();
                if (400..500).contains(&code) {
                    // 4xx — upstream alive; recover the breaker without clearing a
                    // real failure tally, consistent with proxy_fetch_core (#606).
                    let err = upstream_4xx(code, response.headers());
                    if matches!(err, ProxyError::RateLimited(_)) {
                        cb.record_failure(&cb_key, probe);
                    } else {
                        cb.record_alive(&cb_key, probe);
                    }
                    return Err(err);
                }
                ProxyError::Upstream(code)
            }
            Err(e) => transport_error(e),
        };
        if attempt == 0 {
            tracing::debug!(url, error = ?err, "conditional upstream fetch failed, retrying in 1s");
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        cb.record_failure(&cb_key, probe);
        return Err(err);
    }
    cb.record_failure(&cb_key, probe);
    Err(ProxyError::Network("max retries exceeded".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry_type::RegistryType;

    /// Every publish handler that buffers its body answers 413 once the body passes
    /// `server.publish_body_limit_mb`, well below the global `body_limit_mb` (C66).
    #[tokio::test]
    async fn buffered_publish_bodies_are_capped_at_the_publish_limit() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::Method;
        let ctx = create_test_context_with_config(|c| {
            c.server.publish_body_limit_mb = 1;
            c.deb.enabled = true;
            c.rpm.enabled = true;
        });
        let over = vec![b'x'; 1024 * 1024 + 1];
        #[allow(unused_mut)]
        let mut uris = vec![
            "/npm/pkg",
            "/maven2/com/acme/lib/1.0/lib-1.0.jar",
            "/cargo/api/v1/crates/new",
        ];
        // Not mounted on a --no-default-features (release) build.
        #[cfg(feature = "deb")]
        uris.push("/deb/repo/pool/x.deb");
        #[cfg(feature = "rpm")]
        uris.push("/rpm/repo/x.rpm");
        for uri in uris {
            let resp = send(&ctx.app, Method::PUT, uri, over.clone()).await;
            assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE, "{uri}");
        }
        // Under the cap the body reaches the handler (here: invalid JSON).
        let resp = send(&ctx.app, Method::PUT, "/npm/pkg", vec![b'x'; 1024]).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// C54: only NuGet's flat container, or a provenance record whose digest is still
    /// the object's pin, proves a cached copy came from an upstream.
    #[tokio::test]
    async fn only_a_recorded_proxy_fill_is_a_proxied_copy() {
        use sha2::Digest;
        let ctx = crate::test_helpers::create_test_context();
        let storage = &ctx.state.storage;
        let digest = |b: &[u8]| hex::encode(sha2::Sha256::digest(b));
        assert!(is_proxied_copy(storage, "nuget/flatcontainer/a/1.0.0/a.1.0.0.nupkg").await);

        let tgz = "npm/a/tarballs/a-1.0.0.tgz";
        storage.put(tgz, b"published").await.unwrap();
        assert!(!is_proxied_copy(storage, tgz).await, "no provenance");
        let record = format!("npm:https://r.example\n{}", digest(b"upstream"));
        storage
            .put(&npm::origin_key(tgz), record.as_bytes())
            .await
            .unwrap();
        assert!(
            !is_proxied_copy(storage, tgz).await,
            "provenance of other bytes"
        );
        storage.put(tgz, b"upstream").await.unwrap();
        assert!(is_proxied_copy(storage, tgz).await);

        let whl = "pypi/a/a-1.0-py3-none-any.whl";
        storage.put(whl, b"wheel").await.unwrap();
        assert!(
            !is_proxied_copy(storage, whl).await,
            "an upload has no marker"
        );
        storage
            .put(&pypi::proxied_marker_key(whl), digest(b"wheel").as_bytes())
            .await
            .unwrap();
        assert!(is_proxied_copy(storage, whl).await);
    }

    /// C53: an immutable cache write of a spooled body serialises with an upload of the
    /// same file on its publish lock, so an upload that got there first wins: the fill
    /// neither overwrites it nor reports a write (after which provenance would follow).
    #[tokio::test]
    async fn spooled_immutable_cache_write_never_overwrites_an_upload() {
        use sha2::Digest;
        let ctx = crate::test_helpers::create_test_context();
        let state = ctx.state.clone();
        let key = "pypi/race/race-1.0.tar.gz";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool");
        std::fs::write(&path, b"upstream").unwrap();
        let body = ProxyBody::File(std::sync::Arc::new(SpoolFile {
            path,
            sha256: hex::encode(sha2::Sha256::digest(b"upstream")),
            len: 8,
            _reservation: state.spool.reserve(8).unwrap(),
        }));

        // An upload holds the lock from its existence check through its write.
        let lock = state.publish_lock(key);
        let upload = lock.lock().await;
        let fill = tokio::spawn({
            let state = state.clone();
            async move { body.cache(&state, key, true).await }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!fill.is_finished(), "the fill waits for the upload");
        state.storage.put(key, b"uploaded").await.unwrap();
        drop(upload);
        assert!(!fill.await.unwrap().unwrap(), "the fill does not write");
        assert_eq!(&state.storage.get(key).await.unwrap()[..], b"uploaded");
    }

    /// 404 only when an upstream said "not found"; 502 when upstreams were asked and every
    /// one failed; 404 with no upstream at all.
    #[test]
    fn a_miss_is_not_found_only_when_an_upstream_said_so() {
        use axum::http::StatusCode;
        let miss = |answers: &[ProxyError]| {
            let mut m = UpstreamMiss::default();
            for a in answers {
                m.record(a);
            }
            m.status()
        };
        let down = || ProxyError::Upstream(503);
        let unreachable = || ProxyError::Network("refused".into());
        let open = || ProxyError::CircuitOpen("maven".into());
        assert_eq!(miss(&[]), StatusCode::NOT_FOUND);
        assert_eq!(miss(&[ProxyError::NotFound]), StatusCode::NOT_FOUND);
        assert_eq!(miss(&[ProxyError::Upstream(401)]), StatusCode::NOT_FOUND);
        assert_eq!(miss(&[ProxyError::Upstream(499)]), StatusCode::NOT_FOUND);
        assert_eq!(miss(&[ProxyError::Upstream(500)]), StatusCode::BAD_GATEWAY);
        assert_eq!(miss(&[ProxyError::Upstream(399)]), StatusCode::BAD_GATEWAY);
        assert_eq!(miss(&[down()]), StatusCode::BAD_GATEWAY);
        assert_eq!(miss(&[unreachable()]), StatusCode::BAD_GATEWAY);
        assert_eq!(miss(&[open()]), StatusCode::BAD_GATEWAY);
        assert_eq!(miss(&[down(), unreachable()]), StatusCode::BAD_GATEWAY);
        assert_eq!(miss(&[down(), ProxyError::NotFound]), StatusCode::NOT_FOUND);
        assert_eq!(miss(&[ProxyError::NotFound, down()]), StatusCode::NOT_FOUND);

        // One upstream asked under two names: not found under one and failed under the
        // other is a failed upstream; another upstream's "not found" still decides 404.
        let asked = |answers: &[ProxyError]| {
            let mut m = UpstreamMiss::default();
            for a in answers {
                m.record(a);
            }
            m
        };
        let folded = |upstreams: &[UpstreamMiss]| {
            let mut m = UpstreamMiss::default();
            for u in upstreams {
                m.record_upstream(u);
            }
            m.status()
        };
        let hub = asked(&[ProxyError::NotFound, down()]);
        let gone = asked(&[ProxyError::NotFound, ProxyError::NotFound]);
        assert_eq!(folded(&[]), StatusCode::NOT_FOUND);
        assert_eq!(folded(&[asked(&[])]), StatusCode::NOT_FOUND);
        assert_eq!(
            folded(&[asked(&[ProxyError::NotFound, down()])]),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(folded(&[gone]), StatusCode::NOT_FOUND);
        assert_eq!(
            folded(&[hub, asked(&[ProxyError::NotFound])]),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn test_proxy_fetch_invalid_url() {
        let client = reqwest::Client::new();
        let cb = crate::circuit_breaker::CircuitBreakerRegistry::new(
            crate::config::CircuitBreakerConfig::default(),
        );
        let result = proxy_fetch(
            &client,
            "http://127.0.0.1:1/nonexistent",
            Duration::from_secs(2),
            None,
            &cb,
            RegistryType::Docker, // arbitrary variant, testing proxy logic not registry type
        )
        .await;
        assert!(matches!(result, Err(ProxyError::Network(_))));
    }

    // --- Policy/geo upstream block observability (#881) ---

    #[test]
    fn policy_block_reason_detects_waf_geo() {
        use reqwest::header::HeaderMap;
        let mut geo = HeaderMap::new();
        geo.insert("x-amzn-waf-reason", "geo".parse().unwrap());
        assert_eq!(policy_block_reason(&geo), Some("geo"));

        let mut other = HeaderMap::new();
        other.insert("x-amzn-waf-reason", "rate-based".parse().unwrap());
        assert_eq!(policy_block_reason(&other), Some("waf"));

        // A genuine 4xx (no WAF signature) is not a policy block.
        assert_eq!(policy_block_reason(&HeaderMap::new()), None);
    }

    /// A geo-blocked upstream 4xx (WAF `x-amzn-waf-reason: geo`) bumps the policy-block
    /// metric and is still relayed as `NotFound`; a plain 4xx does neither (#881).
    #[tokio::test]
    async fn upstream_waf_geo_block_surfaced_but_plain_4xx_silent() {
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Geo-blocked upstream: 404 + x-amzn-waf-reason: geo.
        let blocked = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(404).insert_header("x-amzn-waf-reason", "geo"))
            .mount(&blocked)
            .await;
        let reg = RegistryType::Terraform;
        let before = UPSTREAM_POLICY_BLOCKED_TOTAL
            .with_label_values(&[reg.as_str(), "geo"])
            .get();
        let r = proxy_fetch_text(
            &reqwest::Client::new(),
            &blocked.uri(),
            Duration::from_secs(5),
            None,
            None,
            &noop_cb(),
            reg,
        )
        .await;
        assert!(matches!(r, Err(ProxyError::NotFound)));
        assert_eq!(
            UPSTREAM_POLICY_BLOCKED_TOTAL
                .with_label_values(&[reg.as_str(), "geo"])
                .get(),
            before + 1,
            "a WAF geo 4xx must bump the policy-block metric"
        );

        // Control: a plain 404 (no WAF signature) must NOT bump the metric.
        let plain = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(404))
            .mount(&plain)
            .await;
        let reg2 = RegistryType::Cargo;
        let before2 = UPSTREAM_POLICY_BLOCKED_TOTAL
            .with_label_values(&[reg2.as_str(), "geo"])
            .get();
        let r2 = proxy_fetch_text(
            &reqwest::Client::new(),
            &plain.uri(),
            Duration::from_secs(5),
            None,
            None,
            &noop_cb(),
            reg2,
        )
        .await;
        assert!(matches!(r2, Err(ProxyError::NotFound)));
        assert_eq!(
            UPSTREAM_POLICY_BLOCKED_TOTAL
                .with_label_values(&[reg2.as_str(), "geo"])
                .get(),
            before2,
            "a plain 4xx must NOT bump the policy-block metric"
        );
    }

    // --- Conditional revalidation (#596) ---

    fn noop_cb() -> CircuitBreakerRegistry {
        CircuitBreakerRegistry::new(crate::config::CircuitBreakerConfig::default())
    }

    /// Concurrent cold misses on one key share one upstream fetch and one body;
    /// exactly one caller is told it fetched (and so owns the cache write).
    #[tokio::test]
    async fn proxy_fetch_shared_coalesces_concurrent_misses() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(b"artifact".to_vec())
                    .set_delay(Duration::from_millis(300)),
            )
            .mount(&upstream)
            .await;
        let ctx = crate::test_helpers::create_test_context_with_config(|_| {});
        let state = &ctx.state;
        let url = upstream.uri();

        let calls = (0..8).map(|_| {
            let fetch = proxy_fetch_bytes(
                &state.http_client,
                &url,
                Duration::from_secs(5),
                None,
                &state.circuit_breaker,
                RegistryType::Npm,
            );
            proxy_fetch_shared(state, "npm/x/-/x-1.0.0.tgz", "npm", 5, fetch)
        });
        let results = futures::future::join_all(calls).await;

        assert_eq!(upstream.received_requests().await.unwrap().len(), 1);
        let mut fetchers = 0;
        for r in results {
            let (body, fetched) = r.unwrap();
            assert_eq!(&body[..], b"artifact");
            fetchers += usize::from(fetched);
        }
        assert_eq!(fetchers, 1, "only the leader owns the cache write");
    }

    /// An upstream on a raw socket that answers 200 with a chunked body: `chunks`
    /// chunks of `chunk_len` bytes, `gap` apart. No `Content-Length`, so the reader
    /// learns the size only by counting.
    async fn chunked_upstream(chunks: usize, chunk_len: usize, gap: Duration) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
                    if sock.write_all(head.as_bytes()).await.is_err() {
                        return;
                    }
                    for _ in 0..chunks {
                        tokio::time::sleep(gap).await;
                        let mut chunk = format!("{chunk_len:x}\r\n").into_bytes();
                        chunk.extend(std::iter::repeat_n(b'x', chunk_len));
                        chunk.extend_from_slice(b"\r\n");
                        if sock.write_all(&chunk).await.is_err() {
                            return;
                        }
                    }
                    let _ = sock.write_all(b"0\r\n\r\n").await;
                });
            }
        });
        format!("http://{addr}/a")
    }

    async fn fetch_artifact(
        state: &AppState,
        key: &str,
        url: &str,
        timeout_secs: u64,
    ) -> Result<(ProxyBody, bool), ProxyError> {
        proxy_fetch_artifact(
            state,
            key,
            "npm",
            url,
            timeout_secs,
            None,
            RegistryType::Npm,
        )
        .await
    }

    fn spool_files(state: &AppState) -> usize {
        std::fs::read_dir(state.spool.dir(PROXY_SPOOL_SUBDIR))
            .map(|d| d.count())
            .unwrap_or(0)
    }

    /// R2-05: the spool budget is shared, never waited on, and released with the
    /// spool: a second reservation over it is `Busy`, one bigger than all of it is
    /// `TooLarge`, and dropping the first frees the room.
    #[test]
    fn spool_budget_refuses_busy_and_oversized_and_releases_on_drop() {
        let ctx = crate::test_helpers::create_test_context_with_config(|c| {
            c.server.spool_max_mb = 20;
        });
        let budget = &ctx.state.spool;
        let mut first = budget.reserve(MIB).unwrap();
        first.grow(12 * MIB).unwrap();
        assert!(matches!(budget.reserve(9 * MIB), Err(SpoolError::Busy)));
        assert!(matches!(budget.reserve(21 * MIB), Err(SpoolError::TooLarge(n)) if n == 20 * MIB));
        // A step past the remaining room falls back to exactly what is needed.
        let second = budget.reserve(3 * MIB).unwrap();
        drop(second);
        drop(first);
        budget.reserve(20 * MIB).unwrap();

        let unlimited = crate::test_helpers::create_test_context_with_config(|c| {
            c.server.spool_max_mb = 0;
        });
        // No budget, but the free-space floor still holds.
        let err = unlimited.state.spool.reserve(1 << 50).unwrap_err();
        assert!(
            matches!(err, SpoolError::Io(ref e) if e.kind() == std::io::ErrorKind::StorageFull)
        );
        unlimited.state.spool.reserve(64 * MIB).unwrap();
    }

    /// R2-05/R2-60: spool refusals and local failures answer for nora's disk, never
    /// a 502 "upstream" error, and count in `nora_spool_failures_total`.
    #[test]
    fn spool_error_responses_are_local_statuses_with_a_metric() {
        let count = |reason: &str| {
            crate::metrics::SPOOL_FAILURES
                .with_label_values(&["spooltest", reason])
                .get()
        };
        let enospc = || std::io::Error::new(std::io::ErrorKind::StorageFull, "full");
        let cases = [
            (SpoolError::Busy, StatusCode::SERVICE_UNAVAILABLE, "busy"),
            (
                SpoolError::TooLarge(MIB),
                StatusCode::INSUFFICIENT_STORAGE,
                "too_large",
            ),
            (
                SpoolError::Io(enospc()),
                StatusCode::INSUFFICIENT_STORAGE,
                "no_space",
            ),
            (
                SpoolError::Io(std::io::Error::other("eio")),
                StatusCode::INTERNAL_SERVER_ERROR,
                "io",
            ),
        ];
        for (err, status, reason) in cases {
            let before = count(reason);
            let resp = proxy_error_response("spooltest", "u", &ProxyError::Spool(err));
            assert_eq!(resp.status(), status, "{reason}");
            assert_eq!(count(reason), before + 1, "{reason}");
            if reason == "busy" {
                assert_eq!(resp.headers()[header::RETRY_AFTER], "10");
            }
        }
    }

    /// R2-05: a spooled artifact holds its share of `spool_max_mb` until its last
    /// holder drops; meanwhile another big miss is a 503 + Retry-After, not a fill
    /// of the volume, and the breaker does not count it against upstream.
    #[tokio::test]
    async fn proxy_fetch_artifact_holds_the_spool_budget_until_the_body_drops() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![7u8; 2 * MIB as usize]))
            .mount(&upstream)
            .await;
        let ctx = crate::test_helpers::create_test_context_with_config(|c| {
            c.server.stream_threshold_mb = 1;
            c.server.spool_max_mb = 3;
        });
        let state = &ctx.state;
        let a = format!("{}/a", upstream.uri());
        let b = format!("{}/b", upstream.uri());
        let (held, _) = fetch_artifact(state, "npm/a", &a, 5).await.unwrap();
        assert!(matches!(held, ProxyBody::File(_)));
        let err = fetch_artifact(state, "npm/b", &b, 5).await.unwrap_err();
        assert!(
            matches!(err, ProxyError::Spool(SpoolError::Busy)),
            "{err:?}"
        );
        assert_eq!(
            proxy_error_response("npm", &b, &err).status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            spool_files(state),
            1,
            "the refused body never touched the disk"
        );
        drop(held);
        let (body, _) = fetch_artifact(state, "npm/b", &b, 5).await.unwrap();
        assert_eq!(body.len(), 2 * MIB);
    }

    /// R2-05: `proxy_max_artifact_mb` refuses a body on its Content-Length before
    /// reading it, and a chunked one as soon as the running count crosses the cap;
    /// both are a 507 and leave no spool file.
    #[tokio::test]
    async fn proxy_fetch_artifact_refuses_a_body_over_the_cap() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![1u8; 3 * MIB as usize]))
            .mount(&upstream)
            .await;
        let ctx = crate::test_helpers::create_test_context_with_config(|c| {
            c.server.stream_threshold_mb = 1;
            c.server.proxy_max_artifact_mb = 2;
        });
        let state = &ctx.state;
        let declared = format!("{}/big", upstream.uri());
        let chunked = chunked_upstream(48, 64 * 1024, Duration::ZERO).await;
        for url in [declared, chunked] {
            let err = fetch_artifact(state, "npm/big", &url, 5).await.unwrap_err();
            assert!(
                matches!(err, ProxyError::Spool(SpoolError::TooLarge(n)) if n == 2 * MIB),
                "{url}: {err:?}"
            );
            assert_eq!(
                proxy_error_response("npm", &url, &err).status(),
                StatusCode::INSUFFICIENT_STORAGE
            );
            assert_eq!(spool_files(state), 0, "{url}");
        }
    }

    /// R2-60: a spool directory nora cannot write is its own failure (500 with a
    /// distinct log and metric), not a 502 blamed on upstream.
    #[tokio::test]
    async fn proxy_fetch_artifact_local_spool_failure_is_not_an_upstream_error() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![1u8; 2 * MIB as usize]))
            .mount(&upstream)
            .await;
        let blocker = tempfile::NamedTempFile::new().unwrap();
        let spool_dir = blocker.path().to_str().unwrap().to_string();
        let ctx = crate::test_helpers::create_test_context_with_config(|c| {
            c.server.stream_threshold_mb = 1;
            c.server.spool_dir = Some(spool_dir); // a file: no directory can be made under it
        });
        let url = format!("{}/a", upstream.uri());
        let err = fetch_artifact(&ctx.state, "npm/a", &url, 5)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ProxyError::Spool(SpoolError::Io(_))),
            "{err:?}"
        );
        assert_eq!(
            proxy_error_response("npm", &url, &err).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    /// R2-39: the per-attempt timeout bounds the response headers and each stall of
    /// the body, not the whole download: a body trickling in over twice the timeout
    /// is proxied, a body that stops for longer than the timeout is not.
    #[tokio::test]
    async fn proxy_fetch_artifact_times_out_on_stalls_not_on_total_time() {
        let ctx = crate::test_helpers::create_test_context_with_config(|c| {
            c.server.stream_threshold_mb = 1;
        });
        let slow = chunked_upstream(6, 512 * 1024, Duration::from_millis(400)).await;
        let (body, _) = fetch_artifact(&ctx.state, "npm/slow", &slow, 1)
            .await
            .unwrap();
        assert_eq!(
            body.len(),
            3 * MIB,
            "2.4 s of steady progress under a 1 s timeout"
        );

        let stalled = chunked_upstream(2, 1024, Duration::from_millis(1500)).await;
        let err = fetch_artifact(&ctx.state, "npm/stall", &stalled, 1)
            .await
            .unwrap_err();
        assert!(matches!(err, ProxyError::Timeout(_)), "{err:?}");
    }

    /// R2-10/R2-34/R2-58: the maintenance sweep reaps orphans in every spool
    /// directory, NuGet push and PyPI upload included, and leaves fresh files.
    #[test]
    fn cleanup_spool_dirs_reaps_orphans_in_every_spool_dir() {
        let root = tempfile::tempdir().unwrap();
        let old = std::time::SystemTime::now() - SPOOL_MAX_AGE - Duration::from_secs(60);
        for sub in [PROXY_SPOOL_SUBDIR, NUGET_UPLOAD_SUBDIR, PYPI_UPLOAD_SUBDIR] {
            let dir = root.path().join(sub);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("fresh"), b"x").unwrap();
            let orphan = dir.join("orphan");
            std::fs::write(&orphan, b"x").unwrap();
            std::fs::File::options()
                .write(true)
                .open(&orphan)
                .unwrap()
                .set_modified(old)
                .unwrap();
        }
        cleanup_spool_dirs(root.path());
        for sub in [PROXY_SPOOL_SUBDIR, NUGET_UPLOAD_SUBDIR, PYPI_UPLOAD_SUBDIR] {
            let dir = root.path().join(sub);
            assert!(!dir.join("orphan").exists(), "{sub}");
            assert!(dir.join("fresh").exists(), "{sub}");
        }
    }

    /// C17: the artifact fetch keeps a body up to `server.stream_threshold_mb` in
    /// memory and spools a bigger one to disk with its digest — the large body is
    /// never one in-memory buffer.
    #[tokio::test]
    async fn proxy_fetch_artifact_spools_bodies_above_the_threshold() {
        use sha2::Digest;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let big: Vec<u8> = (0..(2 * 1024 * 1024 + 5))
            .map(|i| (i % 253) as u8)
            .collect();
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/big"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(big.clone()))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/small"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"small".to_vec()))
            .mount(&upstream)
            .await;
        let ctx = crate::test_helpers::create_test_context_with_config(|c| {
            c.server.stream_threshold_mb = 1;
        });
        let state = &ctx.state;

        let url = format!("{}/big", upstream.uri());
        let (body, fetched) = proxy_fetch_artifact(
            state,
            "npm/b/-/b-1.tgz",
            "npm",
            &url,
            5,
            None,
            RegistryType::Npm,
        )
        .await
        .unwrap();
        assert!(fetched);
        let ProxyBody::File(spool) = &body else {
            panic!("a body above the threshold must be spooled, got {body:?}");
        };
        assert_eq!(spool.len, big.len() as u64);
        assert_eq!(spool.sha256, hex::encode(sha2::Sha256::digest(&big)));
        assert_eq!(std::fs::read(&spool.path).unwrap(), big);
        let path_on_disk = spool.path.clone();
        drop(body);
        assert!(
            !path_on_disk.exists(),
            "the spool file goes with its last holder"
        );

        let url = format!("{}/small", upstream.uri());
        let (body, _) = proxy_fetch_artifact(
            state,
            "npm/s/-/s-1.tgz",
            "npm",
            &url,
            5,
            None,
            RegistryType::Npm,
        )
        .await
        .unwrap();
        assert!(matches!(body, ProxyBody::Mem(ref b) if &b[..] == b"small"));
    }

    /// With no stored validators, the conditional fetch sends no `If-None-Match`,
    /// always gets a 200, and captures the upstream validators (this is also the
    /// full-fetch path that seeds the sidecar for next time).
    #[tokio::test]
    async fn conditional_200_captures_validators() {
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"v1\"")
                    .set_body_string("BODY-V1"),
            )
            .mount(&upstream)
            .await;

        let cb = noop_cb();
        let out = proxy_fetch_conditional(
            &reqwest::Client::new(),
            &upstream.uri(),
            Duration::from_secs(5),
            None,
            &Validators::default(),
            &cb,
            RegistryType::Npm,
        )
        .await
        .unwrap();

        match out {
            Revalidation::Modified { body, validators } => {
                assert_eq!(body, b"BODY-V1");
                assert_eq!(validators.etag.as_deref(), Some("\"v1\""));
            }
            Revalidation::NotModified => panic!("expected Modified"),
        }
    }

    /// When validators are present they are sent as `If-None-Match`, and a 304
    /// yields `NotModified` with NO body download. The mock only answers 304 when
    /// the header is present, so a pass proves the header was sent.
    #[tokio::test]
    async fn conditional_304_sends_if_none_match_and_returns_not_modified() {
        use wiremock::matchers::{header_exists, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(header_exists("if-none-match"))
            .respond_with(ResponseTemplate::new(304))
            .mount(&upstream)
            .await;

        let validators = Validators {
            etag: Some("\"v1\"".to_string()),
            last_modified: None,
        };
        let cb = noop_cb();
        let out = proxy_fetch_conditional(
            &reqwest::Client::new(),
            &upstream.uri(),
            Duration::from_secs(5),
            None,
            &validators,
            &cb,
            RegistryType::Npm,
        )
        .await
        .unwrap();

        assert!(matches!(out, Revalidation::NotModified));
    }

    /// A 5xx on the conditional fetch (also the first, validator-less fetch of a
    /// NuGet registration or version list) is retried once, as `proxy_fetch_core`
    /// does, instead of surfacing the first blip as a 502 (C46).
    #[tokio::test]
    async fn conditional_fetch_retries_once_on_5xx() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("BODY"))
            .mount(&upstream)
            .await;

        let out = proxy_fetch_conditional(
            &reqwest::Client::new(),
            &upstream.uri(),
            Duration::from_secs(5),
            None,
            &Validators::default(),
            &noop_cb(),
            RegistryType::Nuget,
        )
        .await;
        assert!(
            matches!(out, Ok(Revalidation::Modified { ref body, .. }) if body == b"BODY"),
            "{:?}",
            out.as_ref().err()
        );
        assert_eq!(upstream.received_requests().await.unwrap().len(), 2);
    }

    /// Run one half-open probe through `proxy_fetch_conditional` against an
    /// upstream that answers with a 200 declaring `declared_len` bytes, writes
    /// `body`, and hangs up — with `declared_len > body.len()` the body breaks off
    /// mid-stream. The breaker (threshold 1, reset 1 h, so the #585 stall
    /// recovery cannot release the slot during the test) is tripped and its open
    /// timer backdated first, so the call IS the probe.
    async fn conditional_half_open_probe(
        cb: &CircuitBreakerRegistry,
        declared_len: usize,
        body: &[u8],
    ) -> Result<Revalidation, ProxyError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = format!("http://{}", listener.local_addr().unwrap());
        let serve_once = async {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut req = [0u8; 4096];
            let _ = sock.read(&mut req).await;
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {declared_len}\r\nconnection: close\r\n\r\n"
            );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(body).await;
            let _ = sock.shutdown().await;
        };

        cb.record_failure("npm", crate::circuit_breaker::ProbeToken::BACKGROUND);
        cb.expire_open_for_test("npm");
        let client = reqwest::Client::new();
        let validators = Validators::default();
        let fetch = proxy_fetch_conditional(
            &client,
            &upstream,
            Duration::from_secs(5),
            None,
            &validators,
            cb,
            RegistryType::Npm,
        );
        let ((), out) = tokio::join!(serve_once, fetch);
        out
    }

    fn half_open_test_cb() -> CircuitBreakerRegistry {
        CircuitBreakerRegistry::new(crate::config::CircuitBreakerConfig {
            enabled: true,
            failure_threshold: 1,
            reset_timeout: 3600,
            overrides: std::collections::HashMap::new(),
        })
    }

    /// A half-open probe that gets a 200 whose body breaks off must report back
    /// as a failure, exactly like `proxy_fetch_core` ("2xx but the body could not
    /// be read"). Unreported, the probe slot stays held, and every request is
    /// rejected with CircuitOpen until the #585 stall recovery (reset_timeout)
    /// gives up on it.
    #[tokio::test]
    async fn conditional_truncated_200_returns_the_probe_as_a_failure() {
        let cb = half_open_test_cb();

        match conditional_half_open_probe(&cb, 64, b"only-part-of-the-body").await {
            Err(ProxyError::Network(_)) => {}
            Err(e) => panic!("a broken-off body is a network error, got {e:?}"),
            Ok(_) => panic!("a broken-off body must not be returned as a revalidation"),
        }

        // The breaker counted the failed probe: back to Open, not stuck HalfOpen.
        let health = cb.health_snapshot("npm").expect("breaker recorded");
        assert_eq!(
            health.status, "open",
            "the failed probe must re-open the breaker"
        );

        // The probe slot came back: once the open timer runs out, a new probe is
        // granted. A probe that never reported keeps the slot and this check is
        // CircuitOpen for the whole reset_timeout.
        cb.expire_open_for_test("npm");
        assert!(
            cb.check("npm").is_ok(),
            "the probe slot must be released, not held by the lost probe"
        );
    }

    /// Control for the harness above: the same raw upstream with a complete body
    /// is a successful probe that closes the breaker, so the failure above comes
    /// from the broken-off body and not from the harness.
    #[tokio::test]
    async fn conditional_complete_200_closes_the_half_open_breaker() {
        let body: &[u8] = b"the-whole-body";
        let cb = half_open_test_cb();

        match conditional_half_open_probe(&cb, body.len(), body).await {
            Ok(Revalidation::Modified { body: got, .. }) => assert_eq!(got, body),
            Ok(Revalidation::NotModified) => panic!("expected Modified, got NotModified"),
            Err(e) => panic!("expected Modified, got {e:?}"),
        }
        assert_eq!(cb.health_snapshot("npm").unwrap().status, "closed");
    }

    /// Every shared upstream helper sends the credential with its own scheme (#1055).
    /// The mock answers only when the exact `Authorization` value arrives, so each
    /// `Ok` proves the header went out as `Bearer <token>` / `Basic <b64>` — a helper
    /// that dropped the header or forced Basic would get a 404 instead.
    #[tokio::test]
    async fn every_upstream_helper_sends_the_configured_scheme() {
        use wiremock::matchers::{header, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        for (auth, expected) in [
            (UpstreamAuth::Bearer("npm_tok-1"), "Bearer npm_tok-1"),
            (UpstreamAuth::Basic("user:pass"), "Basic dXNlcjpwYXNz"),
        ] {
            let upstream = MockServer::start().await;
            Mock::given(method("GET"))
                .and(header("authorization", expected))
                .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
                .mount(&upstream)
                .await;
            Mock::given(method("POST"))
                .and(header("authorization", expected))
                .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
                .mount(&upstream)
                .await;
            let client = reqwest::Client::new();
            let cb = noop_cb();
            let url = upstream.uri();
            let t = Duration::from_secs(5);

            let bytes = proxy_fetch(&client, &url, t, Some(auth), &cb, RegistryType::Npm).await;
            assert_eq!(bytes.unwrap(), b"ok", "proxy_fetch with {expected}");

            let text =
                proxy_fetch_text(&client, &url, t, Some(auth), None, &cb, RegistryType::Npm).await;
            assert_eq!(text.unwrap(), "ok", "proxy_fetch_text with {expected}");

            let cond = proxy_fetch_conditional(
                &client,
                &url,
                t,
                Some(auth),
                &Validators::default(),
                &cb,
                RegistryType::Npm,
            )
            .await;
            assert!(
                matches!(cond, Ok(Revalidation::Modified { .. })),
                "proxy_fetch_conditional with {expected}"
            );

            let post = proxy_forward_post(
                &client,
                &url,
                t,
                Some(auth),
                &[],
                b"{}",
                &cb,
                RegistryType::Npm,
            )
            .await;
            assert_eq!(post.unwrap().0, 200, "proxy_forward_post with {expected}");
        }
    }

    /// A credential that cannot be a header never reaches the wire and is not an
    /// upstream outage: with a breaker that opens on the first failure, repeated
    /// bad-credential calls leave it closed. Control: one real network failure under
    /// the same config does open it, so the config is live and the test not vacuous.
    #[tokio::test]
    async fn invalid_credential_neither_sent_nor_counted_by_breaker() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&upstream)
            .await;
        let client = reqwest::Client::new();
        let t = Duration::from_secs(5);
        let strict = || {
            CircuitBreakerRegistry::new(crate::config::CircuitBreakerConfig {
                enabled: true,
                failure_threshold: 1,
                reset_timeout: 300,
                overrides: Default::default(),
            })
        };

        let cb = strict();
        for _ in 0..3 {
            let bad = proxy_fetch(
                &client,
                &upstream.uri(),
                t,
                Some(UpstreamAuth::Bearer("tok\n")),
                &cb,
                RegistryType::Npm,
            )
            .await;
            assert!(matches!(bad, Err(ProxyError::Network(_))));
        }
        let requests = upstream.received_requests().await.unwrap();
        assert!(
            requests.is_empty(),
            "a bad credential must not reach the upstream"
        );
        let good = proxy_fetch(&client, &upstream.uri(), t, None, &cb, RegistryType::Npm).await;
        assert_eq!(good.unwrap(), b"ok", "breaker must still be closed");

        // Control: a genuine transport failure opens the same strict breaker.
        let cb = strict();
        let refused = proxy_fetch(
            &client,
            "http://127.0.0.1:1/x",
            t,
            None,
            &cb,
            RegistryType::Npm,
        )
        .await;
        assert!(matches!(refused, Err(ProxyError::Network(_))));
        let after = proxy_fetch(&client, &upstream.uri(), t, None, &cb, RegistryType::Npm).await;
        assert!(
            matches!(after, Err(ProxyError::CircuitOpen(_))),
            "control: breaker opens"
        );
    }

    /// C56: a 304 is recorded as `validated_at` in the `.meta` sidecar, keeping the
    /// validators, and that is what keeps a body whose write time is past the TTL
    /// fresh — no re-upload of the body needed.
    #[tokio::test]
    async fn revalidation_freshness_lives_in_the_sidecar() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = crate::Storage::new_local(dir.path().to_str().unwrap());
        let key = "nuget/flatcontainer/pkg/index.json";
        storage.put(key, b"{}").await.unwrap();
        let v = Validators {
            etag: Some("\"e1\"".to_string()),
            last_modified: None,
        };
        write_validators(&storage, key, &v).await;
        // The body was written two hours ago.
        let two_hours_ago = std::time::SystemTime::now() - Duration::from_secs(7200);
        std::fs::File::options()
            .write(true)
            .open(dir.path().join(key))
            .unwrap()
            .set_modified(two_hours_ago)
            .unwrap();
        let modified = storage.stat(key).await.unwrap().modified;

        assert!(!fresh_within_ttl(&storage, key, modified, 3600).await);
        mark_revalidated(&storage, "nuget", key).await;
        assert!(fresh_within_ttl(&storage, key, modified, 3600).await);
        assert!(
            !fresh_within_ttl(&storage, key, modified, 0).await,
            "ttl 0 is always stale"
        );
        assert_eq!(
            read_validators(&storage, key).await,
            Some(v),
            "validators kept"
        );
        assert_eq!(
            storage.stat(key).await.unwrap().modified,
            modified,
            "the body is not rewritten"
        );
    }

    /// Validators round-trip through storage (the sidecar lives on disk, so they
    /// survive a restart) — acceptance criterion for #596.
    #[tokio::test]
    async fn validators_sidecar_roundtrips_through_storage() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = crate::Storage::new_local(dir.path().to_str().unwrap());

        // No body yet, but the sidecar is just another key — write then read.
        let key = "npm/pkg/metadata.json";
        let v = Validators {
            etag: Some("\"abc\"".to_string()),
            last_modified: Some("Wed, 21 Oct 2026 07:28:00 GMT".to_string()),
        };
        write_validators(&storage, key, &v).await;

        // Fresh Storage over the same dir = "after restart".
        let reloaded = crate::Storage::new_local(dir.path().to_str().unwrap());
        let got = read_validators(&reloaded, key)
            .await
            .expect("sidecar persists");
        assert_eq!(got, v);
        assert_eq!(validators_key(key), "npm/pkg/metadata.json.meta");
    }

    /// An empty validator set writes no sidecar (nothing to persist).
    #[tokio::test]
    async fn empty_validators_write_no_sidecar() {
        let dir = tempfile::TempDir::new().unwrap();
        let storage = crate::Storage::new_local(dir.path().to_str().unwrap());
        write_validators(&storage, "npm/x/metadata.json", &Validators::default()).await;
        assert!(read_validators(&storage, "npm/x/metadata.json")
            .await
            .is_none());
    }

    /// Throttling, auth refusals and timeouts are not "no such artifact": each gets
    /// its own error so handlers never answer them with a cacheable 404.
    #[tokio::test]
    async fn test_proxy_fetch_classifies_upstream_failures() {
        use wiremock::matchers::path;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        for (p, resp) in [
            ("/gone", ResponseTemplate::new(404)),
            (
                "/throttled",
                ResponseTemplate::new(429).insert_header("retry-after", "7"),
            ),
            ("/denied", ResponseTemplate::new(401)),
            ("/forbidden", ResponseTemplate::new(403)),
            (
                "/slow",
                ResponseTemplate::new(200).set_delay(Duration::from_secs(3)),
            ),
        ] {
            Mock::given(path(p))
                .respond_with(resp)
                .mount(&upstream)
                .await;
        }
        let client = reqwest::Client::new();
        let cb = crate::circuit_breaker::CircuitBreakerRegistry::new(
            crate::config::CircuitBreakerConfig::default(),
        );
        let fetch = |p: &'static str| {
            let url = format!("{}{p}", upstream.uri());
            let (client, cb) = (&client, &cb);
            async move {
                proxy_fetch(
                    client,
                    &url,
                    Duration::from_secs(1),
                    None,
                    cb,
                    RegistryType::Npm,
                )
                .await
            }
        };

        assert!(matches!(fetch("/gone").await, Err(ProxyError::NotFound)));
        assert!(matches!(
            fetch("/throttled").await,
            Err(ProxyError::RateLimited(Some(ref v))) if v == "7"
        ));
        assert!(matches!(
            fetch("/denied").await,
            Err(ProxyError::Denied(401))
        ));
        assert!(matches!(
            fetch("/forbidden").await,
            Err(ProxyError::Denied(403))
        ));
        assert!(matches!(fetch("/slow").await, Err(ProxyError::Timeout(_))));

        let resp = proxy_error_response("npm", "u", &ProxyError::RateLimited(Some("7".into())));
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(resp.headers()[header::RETRY_AFTER], "7");
        for (err, want) in [
            (ProxyError::NotFound, StatusCode::NOT_FOUND),
            (ProxyError::Upstream(500), StatusCode::BAD_GATEWAY),
            (ProxyError::Network("x".into()), StatusCode::BAD_GATEWAY),
            (ProxyError::Denied(403), StatusCode::BAD_GATEWAY),
            (ProxyError::Timeout("x".into()), StatusCode::GATEWAY_TIMEOUT),
        ] {
            assert_eq!(proxy_error_response("npm", "u", &err).status(), want);
        }
    }

    /// A storage fault on a cache read is a retryable 503, never a fall-through to a
    /// 404; a pin mismatch refetches a proxied artifact but fails an internal one.
    #[test]
    fn test_cache_read_maps_storage_errors() {
        use crate::storage::StorageError;
        let ok: Result<Option<u8>, _> = cache_read(Ok(1u8), "npm", "k", false);
        assert!(matches!(ok, Ok(Some(1))));
        assert!(matches!(
            cache_read::<u8>(Err(StorageError::NotFound), "npm", "k", true),
            Ok(None)
        ));
        let status = |r: Result<Option<u8>, Response>| r.err().map(|resp| resp.status());
        assert_eq!(
            status(cache_read(
                Err(StorageError::Network("r2".into())),
                "npm",
                "k",
                false
            )),
            Some(StatusCode::SERVICE_UNAVAILABLE)
        );
        assert!(matches!(
            cache_read::<u8>(Err(StorageError::IntegrityViolation), "npm", "k", false),
            Ok(None)
        ));
        assert_eq!(
            status(cache_read(
                Err(StorageError::IntegrityViolation),
                "npm",
                "k",
                true
            )),
            Some(StatusCode::INTERNAL_SERVER_ERROR)
        );
    }
}

/// The upstream-failure class as one table: every proxied cold-miss path of Maven, Docker,
/// Cargo, PyPI and Terraform, against every shape an upstream can answer in, alone and mixed
/// with another upstream. The expected status is the invariant itself: 404 when an upstream
/// answered 4xx ("not found"), 502 when every upstream failed — 5xx, refused, timed out.
#[cfg(test)]
mod upstream_failure_matrix {
    #![allow(clippy::unwrap_used)]

    use crate::config::{Config, DockerUpstream, MavenProxyEntry};
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::body::Body;
    use axum::http::{Method, StatusCode};
    use sha2::Digest;
    use std::time::Duration;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// How one upstream answers every request.
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Shape {
        Status(u16),
        Refused,
        /// Answers after the 1 s proxy timeout every case configures.
        Timeout,
    }

    /// The status a cold miss must get from upstreams answering in `shapes`.
    fn expected(shapes: &[Shape]) -> StatusCode {
        if shapes
            .iter()
            .any(|s| matches!(s, Shape::Status(code) if (400..500).contains(code)))
        {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::BAD_GATEWAY
        }
    }

    /// An upstream answering in `shape`; the server is returned so it lives as long as the case.
    async fn upstream(shape: Shape) -> (String, Option<MockServer>) {
        let template = match shape {
            Shape::Refused => return ("http://127.0.0.1:9".to_string(), None),
            Shape::Status(code) => ResponseTemplate::new(code),
            Shape::Timeout => ResponseTemplate::new(200).set_delay(Duration::from_secs(5)),
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(template)
            .mount(&server)
            .await;
        (server.uri(), Some(server))
    }

    const ALONE: &[&[Shape]] = &[
        &[Shape::Status(503)],
        &[Shape::Refused],
        &[Shape::Timeout],
        &[Shape::Status(400)],
        &[Shape::Status(404)],
    ];

    const MIXED: &[&[Shape]] = &[
        &[Shape::Status(503), Shape::Status(404)],
        &[Shape::Status(404), Shape::Status(503)],
        &[Shape::Timeout, Shape::Status(404)],
        &[Shape::Status(400), Shape::Refused],
        &[Shape::Status(503), Shape::Refused],
        &[Shape::Refused, Shape::Timeout],
    ];

    /// Runs every case for one path; `configure` points the format at the upstream URLs (in
    /// order) with a 1 s proxy timeout. One test per path, so the timed-out cases run side by side.
    async fn run(path: &str, configure: fn(&mut Config, Vec<String>), several: bool) {
        let mut cases: Vec<&[Shape]> = ALONE.to_vec();
        if several {
            cases.extend_from_slice(MIXED);
        }
        for shapes in cases {
            let mut urls = Vec::new();
            let mut servers = Vec::new();
            for shape in shapes {
                let (url, server) = upstream(*shape).await;
                urls.push(url);
                servers.push(server);
            }
            let ctx = create_test_context_with_config(move |cfg| configure(cfg, urls));
            let resp = send(&ctx.app, Method::GET, path, Body::empty()).await;
            let want = expected(shapes);
            // Maestra: formats answering through proxy_error_response report a timed-out
            // upstream as 504; the matrix only requires a failed upstream to be no 404.
            let timed_out = want == StatusCode::BAD_GATEWAY
                && resp.status() == StatusCode::GATEWAY_TIMEOUT
                && shapes.contains(&Shape::Timeout);
            if !timed_out {
                assert_eq!(resp.status(), want, "{path} {shapes:?}");
            }
            drop(servers);
        }
    }

    fn maven(cfg: &mut Config, urls: Vec<String>) {
        cfg.maven.proxies = urls.into_iter().map(MavenProxyEntry::Simple).collect();
        cfg.maven.proxy_timeout = 1;
    }

    fn docker(cfg: &mut Config, urls: Vec<String>) {
        cfg.docker.upstreams = urls
            .into_iter()
            .map(|url| DockerUpstream {
                url,
                auth: None,
                namespace: None,
                prefix: None,
            })
            .collect();
        cfg.docker.proxy_timeout = 1;
    }

    fn cargo(cfg: &mut Config, urls: Vec<String>) {
        cfg.cargo.proxy = urls.into_iter().next();
        cfg.cargo.proxy_timeout = 1;
    }

    fn pypi(cfg: &mut Config, urls: Vec<String>) {
        // Plain URL entries, as `proxies = ["https://..."]` reads from the config file.
        cfg.pypi.proxies = serde_json::from_value(serde_json::json!(urls)).unwrap();
        cfg.pypi.proxy_timeout = 1;
    }

    fn terraform(cfg: &mut Config, urls: Vec<String>) {
        cfg.terraform.enabled = true;
        cfg.terraform.proxy = urls.into_iter().next();
        cfg.terraform.proxy_timeout = 1;
    }

    #[tokio::test]
    async fn maven_artifact() {
        run("/maven2/com/example/lib/1.0.0/lib-1.0.0.jar", maven, true).await;
    }

    #[tokio::test]
    async fn maven_metadata() {
        run("/maven2/com/example/lib/maven-metadata.xml", maven, true).await;
    }

    #[tokio::test]
    async fn maven_metadata_checksum() {
        run(
            "/maven2/com/example/lib/maven-metadata.xml.sha1",
            maven,
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn docker_manifest() {
        run("/v2/myorg/app/manifests/1.0", docker, true).await;
    }

    #[tokio::test]
    async fn docker_blob() {
        let blob = format!("sha256:{}", hex::encode(sha2::Sha256::digest(b"layer")));
        run(&format!("/v2/myorg/app/blobs/{blob}"), docker, true).await;
    }

    #[tokio::test]
    async fn cargo_sparse_index() {
        run("/cargo/index/se/rd/serde", cargo, false).await;
    }

    #[tokio::test]
    async fn cargo_crate_metadata() {
        run("/cargo/api/v1/crates/serde", cargo, false).await;
    }

    #[tokio::test]
    async fn cargo_crate_download() {
        run("/cargo/api/v1/crates/serde/1.0.0/download", cargo, false).await;
    }

    #[tokio::test]
    async fn pypi_simple_index() {
        run("/simple/flask/", pypi, true).await;
    }

    #[tokio::test]
    async fn pypi_file() {
        run("/simple/flask/flask-2.0.tar.gz", pypi, true).await;
    }

    #[tokio::test]
    async fn terraform_module_download() {
        run(
            "/terraform/v1/modules/hashicorp/consul/aws/0.1.0/download",
            terraform,
            false,
        )
        .await;
    }
}
