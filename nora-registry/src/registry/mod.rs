// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
// Production code only: tests may seed storage and build a backend. Handlers name no concrete storage backend (clippy.toml).
#![cfg_attr(not(test), deny(clippy::disallowed_types))]

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
pub(crate) mod helm;
pub(crate) mod hf;
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

// Cross-registry regression suite for namespace isolation on metadata paths (#732).
#[cfg(test)]
mod ns_isolation_metadata_tests;

pub use ansible::routes as ansible_routes;
pub(crate) use cargo_registry::canonical_crate_name;
pub use cargo_registry::rebuild_crate_name_records as rebuild_cargo_name_records;
pub use cargo_registry::routes as cargo_routes;
pub use conan::routes as conan_routes;
pub use cpan::routes as cpan_routes;
#[cfg(feature = "deb")]
pub use deb::routes as deb_routes;
pub use docker::routes as docker_routes;
pub use docker_auth::DockerAuth;
pub use gems::routes as gems_routes;
pub use go::routes as go_routes;
pub use helm::routes as helm_routes;
pub use hf::routes as hf_routes;
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

/// [`proxy_fetch_bytes`] refusing a body above `cap` bytes, on its `Content-Length` or
/// as soon as the running count crosses it, instead of buffering it whole.
pub(crate) async fn proxy_fetch_capped(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
    auth: Option<UpstreamAuth<'_>>,
    cb: &CircuitBreakerRegistry,
    scope: impl Into<BreakerScope<'_>>,
    cap: u64,
) -> Result<Bytes, ProxyError> {
    proxy_fetch_core(
        client,
        url,
        timeout,
        false,
        auth,
        None,
        move |mut r| async move {
            let too_large = || ProxyError::Spool(SpoolError::TooLarge(cap));
            if r.content_length().is_some_and(|n| n > cap) {
                return Err(too_large());
            }
            let mut body = Vec::new();
            while let Some(chunk) = r.chunk().await.map_err(transport_error)? {
                body.extend_from_slice(&chunk);
                if body.len() as u64 > cap {
                    return Err(too_large());
                }
            }
            Ok(Bytes::from(body))
        },
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
    proxy_fetch_artifact_with(
        state,
        &state.http_client,
        key,
        registry,
        url,
        timeout_secs,
        auth,
        scope,
    )
    .await
}

/// [`proxy_fetch_artifact`] over `client` instead of the shared one (helm: an
/// SSRF-guarded client for a host the upstream's index names).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn proxy_fetch_artifact_with(
    state: &AppState,
    client: &reqwest::Client,
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
        client,
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
                let stream = nora_registry::verified::verify_while_streaming(
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
                nora_registry::verified::stream_body(
                    nora_registry::verified::verify_while_streaming(
                        reader,
                        Some(sha256),
                        key.to_string(),
                        Some(heal),
                    ),
                )
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
    // Pull-through only: nothing is published under these.
    if key.starts_with("nuget/flatcontainer/") || key.starts_with("helm/charts/") {
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
        assert!(is_proxied_copy(storage, "helm/charts/demo/repo/demo-1.0.0.tgz").await);

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

    /// What the router hands a handler for paths with empty segments (axum 0.8 / matchit 0.8):
    /// a `{param}` followed by a literal `/` matches an EMPTY segment; `Path` percent-decodes,
    /// so `%2F` puts `/` inside a single `{param}`; `{*rest}` keeps `//`, a leading `/` and a
    /// trailing `/`; nothing normalizes. Every handler must refuse such names itself.
    #[tokio::test]
    async fn the_router_hands_empty_segments_to_handlers_as_sent() {
        use crate::test_helpers::{body_bytes, send};
        use axum::extract::Path;
        use axum::http::{Method, StatusCode};
        use axum::routing::get;

        async fn one(Path(p): Path<String>) -> String {
            format!("[{p}]")
        }
        async fn two(Path((a, b)): Path<(String, String)>) -> String {
            format!("[{a}][{b}]")
        }
        let app: axum::Router = axum::Router::new()
            .route("/simple/{name}/", get(one))
            .route("/simple/{name}/{filename}", get(two))
            .route("/gems/info/{name}", get(one))
            .route("/w/{*path}", get(one))
            .route("/r/{repo}/{*path}", get(two));
        let cases = [
            ("/simple//", Some("[]")),
            ("/simple//x", Some("[][x]")),
            ("/simple/foo%2F/", Some("[foo/]")),
            ("/simple/%2Ffoo/x", Some("[/foo][x]")),
            ("/gems/info/", None),
            ("/gems/info/x%2F%2Fy", Some("[x//y]")),
            ("/w/a//b", Some("[a//b]")),
            ("/w//a", Some("[/a]")),
            ("/w/a/b/", Some("[a/b/]")),
            ("/w/a%2F%2Fb", Some("[a//b]")),
            ("/r//x", Some("[][x]")),
            ("/r/a//b", Some("[a][/b]")),
        ];
        for (uri, want) in cases {
            let resp = send(&app, Method::GET, uri, axum::body::Body::empty()).await;
            match want {
                Some(body) => {
                    assert_eq!(resp.status(), StatusCode::OK, "{uri}");
                    assert_eq!(&body_bytes(resp).await[..], body.as_bytes(), "{uri}");
                }
                None => assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{uri}"),
            }
        }
    }
}

/// An allowlist entry that pins an artifact's SHA-256 refuses other bytes on the first download
/// from the upstream, in every format that checks it on a cache hit: the pin is the operator's
/// statement of what the artifact is, and the first client (often CI) is the one it protects.
#[cfg(test)]
mod first_download_integrity {
    #![allow(clippy::unwrap_used)]

    use crate::config::{Config, CurationMode, MavenProxyEntry};
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use sha2::Digest;
    use wiremock::matchers::{any, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SERVED: &[u8] = b"TAMPERED";

    /// An upstream that answers every request with bytes other than the pinned ones.
    async fn upstream() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(SERVED.to_vec()))
            .mount(&server)
            .await;
        server
    }

    /// Requests `uri` twice under an allowlist that pins `name@version` to the SHA-256 of
    /// b"GOOD"; both answers are 403 and neither carries the upstream's bytes.
    async fn refused(
        server: &MockServer,
        registry: &str,
        name: &str,
        version: &str,
        uri: &str,
        configure: fn(&mut Config, String),
    ) {
        let entries = serde_json::json!([
            {"registry": registry, "name": name, "version": version, "integrity": pinned()}
        ]);
        refused_entries(server, registry, entries, uri, configure).await;
    }

    fn pinned() -> String {
        format!("sha256:{}", hex::encode(sha2::Sha256::digest(b"GOOD")))
    }

    /// A context in enforce mode with an allowlist of `entries`, its upstream at `url`.
    fn enforced(
        entries: serde_json::Value,
        url: String,
        configure: fn(&mut Config, String),
    ) -> crate::test_helpers::TestContext {
        let dir = tempfile::tempdir().unwrap();
        let allowlist = dir.path().join("allowlist.json");
        std::fs::write(
            &allowlist,
            serde_json::json!({"version": 1, "entries": entries}).to_string(),
        )
        .unwrap();
        let allowlist = allowlist.to_string_lossy().into_owned();
        // The allowlist is read when the context is built; the directory may go after that.
        let ctx = create_test_context_with_config(move |cfg| {
            configure(cfg, url);
            cfg.curation.mode = CurationMode::Enforce;
            cfg.curation.allowlist_path = Some(allowlist);
        });
        drop(dir);
        ctx
    }

    async fn refused_entries(
        server: &MockServer,
        registry: &str,
        entries: serde_json::Value,
        uri: &str,
        configure: fn(&mut Config, String),
    ) {
        let ctx = enforced(entries, server.uri(), configure);
        for attempt in ["first download", "second download"] {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            let status = resp.status();
            let body = body_bytes(resp).await;
            assert!(
                !body.windows(SERVED.len()).any(|w| w == SERVED),
                "{registry} {attempt}: the upstream's bytes were served"
            );
            assert_eq!(status, StatusCode::FORBIDDEN, "{registry} {attempt}");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    #[tokio::test]
    async fn maven() {
        let s = upstream().await;
        let uri = "/maven2/com/corp/lib/1.0.0/lib-1.0.0.jar";
        refused(&s, "maven", "com.corp:lib", "1.0.0", uri, |c, u| {
            c.maven.proxies = vec![MavenProxyEntry::Simple(u)];
        })
        .await;
    }

    #[tokio::test]
    async fn cargo() {
        let s = upstream().await;
        let uri = "/cargo/api/v1/crates/corp-lib/1.0.0/download";
        refused(&s, "cargo", "corp-lib", "1.0.0", uri, |c, u| {
            c.cargo.proxy = Some(u);
        })
        .await;
    }

    #[tokio::test]
    async fn npm() {
        let s = upstream().await;
        let uri = "/npm/corp-lib/-/corp-lib-1.0.0.tgz";
        refused(&s, "npm", "corp-lib", "1.0.0", uri, |c, u| {
            c.npm.proxy = Some(u);
        })
        .await;
    }

    #[tokio::test]
    async fn pypi() {
        let s = MockServer::start().await;
        let file = format!("{}/files/corp_lib-1.0.0.tar.gz", s.uri());
        Mock::given(method("GET"))
            .and(path("/corp-lib/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"<html><body><a href="{file}">corp_lib-1.0.0.tar.gz</a></body></html>"#
            )))
            .mount(&s)
            .await;
        Mock::given(method("GET"))
            .and(path("/files/corp_lib-1.0.0.tar.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(SERVED.to_vec()))
            .mount(&s)
            .await;
        let uri = "/simple/corp-lib/corp_lib-1.0.0.tar.gz";
        refused(&s, "pypi", "corp-lib", "1.0.0", uri, |c, u| {
            c.pypi.proxies = serde_json::from_value(serde_json::json!([u])).unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn gems() {
        let s = upstream().await;
        refused(
            &s,
            "gems",
            "corp",
            "1.0.0",
            "/gems/gems/corp-1.0.0.gem",
            |c, u| {
                c.gems.enabled = true;
                c.gems.proxy = Some(u);
            },
        )
        .await;
    }

    #[tokio::test]
    async fn nuget() {
        let s = upstream().await;
        let uri = "/nuget/v3/flatcontainer/corp.lib/1.0.0/corp.lib.1.0.0.nupkg";
        refused(&s, "nuget", "corp.lib", "1.0.0", uri, |c, u| {
            c.nuget.enabled = true;
            c.nuget.proxy = Some(u);
        })
        .await;
    }

    #[tokio::test]
    async fn pub_dart() {
        let s = upstream().await;
        let uri = "/pub/packages/corp/versions/1.0.0.tar.gz";
        refused(&s, "pub", "corp", "1.0.0", uri, |c, u| {
            c.pub_dart.enabled = true;
            c.pub_dart.proxy = Some(u);
        })
        .await;
    }

    #[tokio::test]
    async fn ansible() {
        let s = upstream().await;
        let uri = "/ansible/download/corp-lib-1.0.0.tar.gz";
        refused(&s, "ansible", "corp.lib", "1.0.0", uri, |c, u| {
            c.ansible.enabled = true;
            c.ansible.proxy = Some(u);
        })
        .await;
    }

    #[tokio::test]
    async fn cpan() {
        let s = upstream().await;
        let uri = "/cpan/authors/id/C/CO/CORP/Corp-Lib-1.0.tar.gz";
        refused(&s, "cpan", "Corp-Lib", "1.0", uri, |c, u| {
            c.cpan.enabled = true;
            c.cpan.proxy = Some(u);
        })
        .await;
    }

    #[tokio::test]
    async fn docker_manifest() {
        let s = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(
                        "content-type",
                        "application/vnd.docker.distribution.manifest.v2+json",
                    )
                    .set_body_bytes(SERVED.to_vec()),
            )
            .mount(&s)
            .await;
        refused(
            &s,
            "docker",
            "corp/app",
            "1.0",
            "/v2/corp/app/manifests/1.0",
            |c, u| {
                c.docker.upstreams = vec![crate::config::DockerUpstream {
                    url: u,
                    auth: None,
                    auth_env: None,
                    namespace: None,
                    prefix: None,
                }];
            },
        )
        .await;
    }

    /// A gem file name read two ways: the pin of the second reading holds.
    #[tokio::test]
    async fn gems_every_reading_of_the_file_name() {
        let s = upstream().await;
        let entries = serde_json::json!([
            {"registry": "gems", "name": "evil", "version": "1"},
            {"registry": "gems", "name": "evil-1", "version": "2.0", "integrity": pinned()}
        ]);
        refused_entries(
            &s,
            "gems",
            entries,
            "/gems/gems/evil-1-2.0-java.gem",
            |c, u| {
                c.gems.enabled = true;
                c.gems.proxy = Some(u);
            },
        )
        .await;
    }

    /// The package file in any case of its extension.
    #[tokio::test]
    async fn nuget_upper_case_extension() {
        let s = upstream().await;
        let uri = "/nuget/v3/flatcontainer/corp.lib/1.0.0/corp.lib.1.0.0.NUPKG";
        refused(&s, "nuget", "corp.lib", "1.0.0", uri, |c, u| {
            c.nuget.enabled = true;
            c.nuget.proxy = Some(u);
        })
        .await;
    }

    /// Every file of a pinned Maven version, the pom as well as the jar.
    #[tokio::test]
    async fn maven_pom() {
        let s = upstream().await;
        let uri = "/maven2/com/corp/lib/1.0.0/lib-1.0.0.pom";
        refused(&s, "maven", "com.corp:lib", "1.0.0", uri, |c, u| {
            c.maven.proxies = vec![MavenProxyEntry::Simple(u)];
        })
        .await;
    }

    /// A conan package file, as well as the recipe files.
    #[tokio::test]
    async fn conan_package_file() {
        let s = upstream().await;
        let uri = "/conan/v2/conans/corp/1.0/_/_/revisions/r1/packages/p1/revisions/pr1/files/conan_package.tgz";
        refused(&s, "conan", "corp", "1.0", uri, |c, u| {
            c.conan.enabled = true;
            c.conan.proxy = Some(u);
        })
        .await;
    }

    /// An official image asked of the upstream under its `library/` name: the pin is on the name
    /// the client asked for.
    #[tokio::test]
    async fn docker_official_image() {
        let s = MockServer::start().await;
        Mock::given(path("/v2/library/app/manifests/1.0"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(
                        "content-type",
                        "application/vnd.docker.distribution.manifest.v2+json",
                    )
                    .set_body_bytes(SERVED.to_vec()),
            )
            .mount(&s)
            .await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(404))
            .mount(&s)
            .await;
        refused(
            &s,
            "docker",
            "app",
            "1.0",
            "/v2/app/manifests/1.0",
            |c, u| {
                c.docker.upstreams = vec![crate::config::DockerUpstream {
                    url: u,
                    auth: None,
                    auth_env: None,
                    namespace: None,
                    prefix: None,
                }];
            },
        )
        .await;
    }

    /// A copy stored before the pin (an older release cached it on its first download): a range of
    /// it is refused like the whole file, while a range of an unpinned file is still served.
    async fn range_refused(
        registry: &str,
        name: &str,
        version: &str,
        uri: &str,
        key: &str,
        configure: fn(&mut Config, String),
    ) {
        for pin in [true, false] {
            let mut entry =
                serde_json::json!({"registry": registry, "name": name, "version": version});
            if pin {
                entry["integrity"] = serde_json::Value::String(pinned());
            }
            let ctx = enforced(
                serde_json::json!([entry]),
                "http://127.0.0.1:9".to_string(),
                configure,
            );
            ctx.state.storage.put(key, SERVED).await.unwrap();
            let resp = crate::test_helpers::send_with_headers(
                &ctx.app,
                Method::GET,
                uri,
                vec![("range", "bytes=0-")],
                "",
            )
            .await;
            let status = resp.status();
            let body = body_bytes(resp).await;
            if pin {
                assert_eq!(
                    status,
                    StatusCode::FORBIDDEN,
                    "{registry} range of a pinned file"
                );
                assert!(
                    !body.windows(SERVED.len()).any(|w| w == SERVED),
                    "{registry}: a range served the stored bytes"
                );
            } else {
                assert_eq!(
                    status,
                    StatusCode::PARTIAL_CONTENT,
                    "{registry} range of an unpinned file"
                );
            }
        }
    }

    /// In audit mode a pin refuses nothing, so a range of a pinned file is still a range: the range
    /// serve stands down only where a byte check could refuse.
    #[tokio::test]
    async fn range_of_a_pinned_file_in_audit_mode_is_still_served() {
        let dir = tempfile::tempdir().unwrap();
        let allowlist = dir.path().join("allowlist.json");
        std::fs::write(
            &allowlist,
            serde_json::json!({"version": 1, "entries": [
                {"registry": "gems", "name": "corp", "version": "1.0.0", "integrity": pinned()}
            ]})
            .to_string(),
        )
        .unwrap();
        let allowlist = allowlist.to_string_lossy().into_owned();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.gems.enabled = true;
            cfg.gems.proxy = Some("http://127.0.0.1:9".to_string());
            cfg.curation.mode = CurationMode::Audit;
            cfg.curation.allowlist_path = Some(allowlist);
        });
        ctx.state
            .storage
            .put("gems/gems/corp-1.0.0.gem", SERVED)
            .await
            .unwrap();
        let resp = crate::test_helpers::send_with_headers(
            &ctx.app,
            Method::GET,
            "/gems/gems/corp-1.0.0.gem",
            vec![("range", "bytes=0-")],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    }

    /// A gem file name read two ways, a stored copy and a range: the pin of the second reading
    /// holds the range too.
    #[tokio::test]
    async fn range_of_a_gem_with_two_readings() {
        let entries = serde_json::json!([
            {"registry": "gems", "name": "evil", "version": "1"},
            {"registry": "gems", "name": "evil-1", "version": "2.0", "integrity": pinned()}
        ]);
        let ctx = enforced(entries, "http://127.0.0.1:9".to_string(), |c, u| {
            c.gems.enabled = true;
            c.gems.proxy = Some(u);
        });
        ctx.state
            .storage
            .put("gems/gems/evil-1-2.0-java.gem", SERVED)
            .await
            .unwrap();
        let resp = crate::test_helpers::send_with_headers(
            &ctx.app,
            Method::GET,
            "/gems/gems/evil-1-2.0-java.gem",
            vec![("range", "bytes=0-")],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// A blocklist ahead of the allowlist in the chain (it skips this artifact): the pin still
    /// holds the range, as it holds a full download.
    #[tokio::test]
    async fn range_with_a_blocklist_ahead_of_the_pin() {
        let dir = tempfile::tempdir().unwrap();
        let blocklist = dir.path().join("blocklist.json");
        std::fs::write(
            &blocklist,
            serde_json::json!({"version": 1, "rules": [
                {"registry": "pypi", "name": "other-lib", "version": "*", "reason": "test"}
            ]})
            .to_string(),
        )
        .unwrap();
        let allowlist = dir.path().join("allowlist.json");
        std::fs::write(
            &allowlist,
            serde_json::json!({"version": 1, "entries": [
                {"registry": "pypi", "name": "corp-lib", "version": "1.0.0", "integrity": pinned()}
            ]})
            .to_string(),
        )
        .unwrap();
        let (blocklist, allowlist) = (
            blocklist.to_string_lossy().into_owned(),
            allowlist.to_string_lossy().into_owned(),
        );
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.pypi.proxies =
                serde_json::from_value(serde_json::json!(["http://127.0.0.1:9"])).unwrap();
            cfg.curation.mode = CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist);
            cfg.curation.allowlist_path = Some(allowlist);
        });
        ctx.state
            .storage
            .put("pypi/corp-lib/corp_lib-1.0.0.tar.gz", SERVED)
            .await
            .unwrap();
        let resp = crate::test_helpers::send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/corp-lib/corp_lib-1.0.0.tar.gz",
            vec![("range", "bytes=0-")],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// A stale copy of a pinned SNAPSHOT, served because every upstream failed: the pin holds it.
    #[tokio::test]
    async fn maven_stale_snapshot_holds_the_pin() {
        let entries = serde_json::json!([
            {"registry": "maven", "name": "com.corp:lib", "version": "1.0-SNAPSHOT", "integrity": pinned()}
        ]);
        let ctx = enforced(entries, "http://127.0.0.1:9".to_string(), |c, u| {
            c.maven.proxies = vec![MavenProxyEntry::Simple(u)];
            c.maven.metadata_ttl = 0;
        });
        ctx.state
            .storage
            .put(
                "maven/com/corp/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar",
                SERVED,
            )
            .await
            .unwrap();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/maven2/com/corp/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar",
            "",
        )
        .await;
        let status = resp.status();
        let body = body_bytes(resp).await;
        assert!(
            !body.windows(SERVED.len()).any(|w| w == SERVED),
            "stale bytes served"
        );
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn range_gems() {
        range_refused(
            "gems",
            "corp",
            "1.0.0",
            "/gems/gems/corp-1.0.0.gem",
            "gems/gems/corp-1.0.0.gem",
            |c, u| {
                c.gems.enabled = true;
                c.gems.proxy = Some(u);
            },
        )
        .await;
    }

    #[tokio::test]
    async fn range_maven() {
        range_refused(
            "maven",
            "com.corp:lib",
            "1.0.0",
            "/maven2/com/corp/lib/1.0.0/lib-1.0.0.jar",
            "maven/com/corp/lib/1.0.0/lib-1.0.0.jar",
            |c, u| c.maven.proxies = vec![MavenProxyEntry::Simple(u)],
        )
        .await;
    }

    #[tokio::test]
    async fn range_pypi() {
        range_refused(
            "pypi",
            "corp-lib",
            "1.0.0",
            "/simple/corp-lib/corp_lib-1.0.0.tar.gz",
            "pypi/corp-lib/corp_lib-1.0.0.tar.gz",
            |c, u| c.pypi.proxies = serde_json::from_value(serde_json::json!([u])).unwrap(),
        )
        .await;
    }

    #[tokio::test]
    async fn range_npm() {
        range_refused(
            "npm",
            "corp-lib",
            "1.0.0",
            "/npm/corp-lib/-/corp-lib-1.0.0.tgz",
            "npm/corp-lib/tarballs/corp-lib-1.0.0.tgz",
            |c, u| c.npm.proxy = Some(u),
        )
        .await;
    }

    #[tokio::test]
    async fn conan() {
        let s = upstream().await;
        let uri = "/conan/v2/conans/corp/1.0/_/_/revisions/r1/files/conan_sources.tgz";
        refused(&s, "conan", "corp", "1.0", uri, |c, u| {
            c.conan.enabled = true;
            c.conan.proxy = Some(u);
        })
        .await;
    }
}

/// An empty `NORA_<FORMAT>_PROXY` switches the format's upstream off: the config then reads the
/// format as having no upstream, and a request for something not stored is answered 404 without
/// asking anyone. Each case names an artifact the public default upstream does serve, so a
/// fallback to that default answers 200 (or 502 offline) instead of 404.
#[cfg(test)]
mod proxy_off_means_off {
    #![allow(clippy::unwrap_used)]

    use crate::config::Config;
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};

    async fn not_found(uri: &str, configure: fn(&mut Config)) {
        let ctx = create_test_context_with_config(configure);
        let resp = send(&ctx.app, Method::GET, uri, "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{uri}");
    }

    #[tokio::test]
    async fn gems() {
        not_found("/gems/gems/rake-13.0.6.gem", |c| {
            c.gems.enabled = true;
            c.gems.proxy = None;
        })
        .await;
    }

    #[tokio::test]
    async fn nuget() {
        let uri = "/nuget/v3/flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg";
        not_found(uri, |c| {
            c.nuget.enabled = true;
            c.nuget.proxy = None;
        })
        .await;
    }

    #[tokio::test]
    async fn conan() {
        not_found("/conan/v2/conans/zlib/1.3.1/_/_/latest", |c| {
            c.conan.enabled = true;
            c.conan.proxy = None;
        })
        .await;
    }

    #[tokio::test]
    async fn terraform() {
        not_found("/terraform/v1/providers/hashicorp/null/versions", |c| {
            c.terraform.enabled = true;
            c.terraform.proxy = None;
        })
        .await;
    }

    #[tokio::test]
    async fn ansible() {
        let uri =
            "/ansible/api/v3/plugin/ansible/content/published/collections/index/community/general/";
        not_found(uri, |c| {
            c.ansible.enabled = true;
            c.ansible.proxy = None;
        })
        .await;
    }

    /// What is stored keeps being served, whatever its age: with the upstream off it is all
    /// there is, and nothing reaches an upstream to refresh it.
    async fn stored(uri: &str, key: &str, body: &[u8], configure: fn(&mut Config)) {
        let ctx = create_test_context_with_config(configure);
        ctx.state.storage.put(key, body).await.unwrap();
        let resp = send(&ctx.app, Method::GET, uri, "").await;
        assert_eq!(resp.status(), StatusCode::OK, "{uri}");
        let served = crate::test_helpers::body_bytes(resp).await;
        assert_eq!(served.as_ref(), body, "{uri}");
    }

    #[tokio::test]
    async fn gems_stored_index() {
        stored("/gems/specs.4.8.gz", "gems/specs.4.8.gz", b"SPECS", |c| {
            c.gems.enabled = true;
            c.gems.proxy = None;
            c.gems.metadata_ttl = 0;
        })
        .await;
    }

    #[tokio::test]
    async fn cpan_stored_index() {
        let key = "cpan/modules/02packages.details.txt.gz";
        stored(
            "/cpan/modules/02packages.details.txt.gz",
            key,
            b"PKGS",
            |c| {
                c.cpan.enabled = true;
                c.cpan.proxy = None;
                c.cpan.metadata_ttl = 0;
            },
        )
        .await;
    }

    #[tokio::test]
    async fn terraform_stored_versions() {
        let key = "terraform/providers/corp/thing/versions.json";
        let body = br#"{"versions":[{"version":"1.0.0"}]}"#;
        stored(
            "/terraform/v1/providers/corp/thing/versions",
            key,
            body,
            |c| {
                c.terraform.enabled = true;
                c.terraform.proxy = None;
                c.terraform.metadata_ttl = 0;
            },
        )
        .await;
    }

    #[tokio::test]
    async fn nuget_stored_version_list() {
        let key = "nuget/flatcontainer/corp.lib/index.json";
        let body = br#"{"versions":["1.0.0"]}"#;
        stored(
            "/nuget/v3/flatcontainer/corp.lib/index.json",
            key,
            body,
            |c| {
                c.nuget.enabled = true;
                c.nuget.proxy = None;
                c.nuget.metadata_ttl = 0;
            },
        )
        .await;
    }

    #[tokio::test]
    async fn cpan() {
        not_found("/cpan/authors/id/H/HA/HAARG/Moo-2.005005.tar.gz", |c| {
            c.cpan.enabled = true;
            c.cpan.proxy = None;
        })
        .await;
    }

    // ---- Every route, measured: nothing leaves NORA ----

    const TF_PROVIDER_META: &[u8] = br#"{"_nora_upstream_url":"https://releases.example/p.zip","_nora_upstream_shasums_url":"https://releases.example/SHA256SUMS","_nora_upstream_shasums_sig_url":"https://releases.example/SHA256SUMS.sig"}"#;

    /// How the upstream setting is written: absent, blank (whatever wrote it: a file, the
    /// environment or code — handlers must read it as off too), or the public default.
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Mode {
        Off,
        Blank,
        On,
    }

    fn set_upstream(proxy: &mut Option<String>, mode: Mode) {
        match mode {
            Mode::Off => *proxy = None,
            Mode::Blank => *proxy = Some("  ".to_string()),
            Mode::On => {}
        }
    }

    /// Where an address goes when the upstream is on: nowhere (answered locally), to the upstream
    /// over an empty store, or to an address an earlier configuration stored (needs the seeds).
    #[derive(Clone, Copy)]
    enum Reach {
        Local,
        Cold,
        Seeded,
    }

    /// Every route of a format with its upstream switched off, over an empty store and over one
    /// holding stale copies and the upstream addresses an earlier configuration stored: no request
    /// leaves NORA, whatever host a handler meant to ask (the client goes through a recording proxy
    /// without idle connections, so each request is seen), and the answer is the stored copy (200)
    /// or 404. The control, per address: with the public default upstream on and nothing stored,
    /// every address not marked local reaches the upstream.
    async fn no_egress(
        format: &str,
        uris: &[(&str, Reach)],
        seeds: &[(&str, &[u8])],
        configure: fn(&mut Config, Mode),
    ) {
        use crate::test_helpers::{create_test_context_with_egress_proxy, EgressRecorder};
        for mode in [Mode::Off, Mode::Blank, Mode::On] {
            let upstream_on = mode == Mode::On;
            let recorder = EgressRecorder::start().await;
            let ctx =
                create_test_context_with_egress_proxy(&recorder.url, move |c| configure(c, mode));
            for seeded in [false, true] {
                if seeded {
                    for (key, body) in seeds {
                        ctx.state.storage.put(key, body).await.unwrap();
                    }
                }
                for (uri, reach) in uris {
                    let before = recorder.seen().await.len();
                    let status = send(&ctx.app, Method::GET, uri, "").await.status();
                    // Revalidations and cache fills that run off the request path.
                    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                    let seen = recorder.seen().await;
                    let asked = &seen[before..];
                    if upstream_on {
                        let expected = match reach {
                            Reach::Cold => !seeded,
                            Reach::Seeded => seeded,
                            Reach::Local => false,
                        };
                        if expected {
                            assert!(
                                !asked.is_empty(),
                                "{format} control: {uri} never reached the default upstream (seeded: {seeded})"
                            );
                        }
                    } else {
                        assert!(
                            asked.is_empty(),
                            "{format} {uri} asked with the upstream {mode:?}: {asked:?}"
                        );
                        // 200: a stored copy; 204: Terraform's module answer pointing at NORA's own
                        // source route; 404: nothing stored.
                        assert!(
                            [StatusCode::OK, StatusCode::NO_CONTENT, StatusCode::NOT_FOUND]
                                .contains(&status),
                            "{format} {uri} with the upstream {mode:?} answered {status} (seeded: {seeded})"
                        );
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn gems_every_route() {
        no_egress(
            "gems",
            &[
                ("/gems/specs.4.8.gz", Reach::Cold),
                ("/gems/latest_specs.4.8.gz", Reach::Cold),
                ("/gems/prerelease_specs.4.8.gz", Reach::Cold),
                ("/gems/info/rake", Reach::Cold),
                ("/gems/gems/rake-13.0.6.gem", Reach::Cold),
                (
                    "/gems/quick/Marshal.4.8/rake-13.0.6.gemspec.rz",
                    Reach::Cold,
                ),
            ],
            &[
                ("gems/specs.4.8.gz", b"SPECS"),
                ("gems/latest_specs.4.8.gz", b"SPECS"),
                ("gems/info/rake", b"---\n13.0.6 |checksum:00"),
            ],
            |c, mode| {
                c.gems.enabled = true;
                c.gems.metadata_ttl = 0;
                set_upstream(&mut c.gems.proxy, mode);
            },
        )
        .await;
    }

    #[tokio::test]
    async fn nuget_every_route() {
        let mut uris = Vec::new();
        for prefix in ["nuget", "chocolatey", "pwsh"] {
            for (path, reach) in [
                ("v3/index.json", Reach::Local),
                ("v3/query?q=newtonsoft", Reach::Cold),
                ("v3/autocomplete?q=newt", Reach::Cold),
                ("v3/registration/newtonsoft.json/index.json", Reach::Cold),
                (
                    "v3/registration/awssdk.core/page/3.7.0/3.7.400.json",
                    Reach::Cold,
                ),
                ("v3/flatcontainer/newtonsoft.json/index.json", Reach::Cold),
                (
                    "v3/flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nupkg",
                    Reach::Cold,
                ),
                (
                    "v3/flatcontainer/newtonsoft.json/13.0.1/newtonsoft.json.nuspec",
                    Reach::Cold,
                ),
                ("v3/other/resource.json", Reach::Local),
            ] {
                uris.push((format!("/{prefix}/{path}"), reach));
            }
        }
        let uris: Vec<(&str, Reach)> = uris.iter().map(|(u, r)| (u.as_str(), *r)).collect();
        no_egress(
            "nuget",
            &uris,
            &[(
                "nuget/flatcontainer/newtonsoft.json/index.json",
                br#"{"versions":["13.0.1"]}"#,
            )],
            |c, mode| {
                c.nuget.enabled = true;
                c.nuget.metadata_ttl = 0;
                set_upstream(&mut c.nuget.proxy, mode);
            },
        )
        .await;
    }

    #[tokio::test]
    async fn conan_every_route() {
        let r = "/conan/v2/conans/zlib/1.3.1/_/_";
        let uris = [
            ("/conan/v1/ping".to_string(), Reach::Local),
            ("/conan/v2/ping".to_string(), Reach::Local),
            ("/conan/v2/conans/search?q=zlib".to_string(), Reach::Cold),
            (format!("{r}/latest"), Reach::Cold),
            (format!("{r}/revisions"), Reach::Cold),
            (format!("{r}/revisions/r1/files"), Reach::Cold),
            (format!("{r}/revisions/r1/files/conanfile.py"), Reach::Cold),
            (format!("{r}/revisions/r1/packages/p1/latest"), Reach::Cold),
            (
                format!("{r}/revisions/r1/packages/p1/revisions"),
                Reach::Cold,
            ),
            (
                format!("{r}/revisions/r1/packages/p1/revisions/pr1/files"),
                Reach::Cold,
            ),
            (
                format!("{r}/revisions/r1/packages/p1/revisions/pr1/files/conan_package.tgz"),
                Reach::Cold,
            ),
        ];
        let uris: Vec<(&str, Reach)> = uris.iter().map(|(u, r)| (u.as_str(), *r)).collect();
        no_egress("conan", &uris, &[], |c, mode| {
            c.conan.enabled = true;
            c.conan.metadata_ttl = 0;
            set_upstream(&mut c.conan.proxy, mode);
        })
        .await;
    }

    #[tokio::test]
    async fn terraform_every_route() {
        let d = "/terraform/v1/providers/download/hashicorp/null/3.2.2";
        let uris = [
            (
                "/terraform/.well-known/terraform.json".to_string(),
                Reach::Local,
            ),
            (
                "/terraform/v1/providers/hashicorp/null/versions".to_string(),
                Reach::Cold,
            ),
            (
                "/terraform/v1/providers/hashicorp/null/3.2.2/download/linux/amd64".to_string(),
                Reach::Cold,
            ),
            (
                format!("{d}/terraform-provider-null_3.2.2_linux_amd64.zip"),
                Reach::Cold,
            ),
            (
                format!("{d}/terraform-provider-null_3.2.2_SHA256SUMS"),
                Reach::Cold,
            ),
            (
                format!("{d}/terraform-provider-null_3.2.2_SHA256SUMS.sig"),
                Reach::Cold,
            ),
            (
                "/terraform/v1/modules/corp/net/aws/versions".to_string(),
                Reach::Cold,
            ),
            (
                "/terraform/v1/modules/corp/net/aws/1.0.0/download".to_string(),
                Reach::Cold,
            ),
            (
                "/terraform/v1/modules/download/corp/net/aws/1.0.0/source".to_string(),
                Reach::Seeded,
            ),
            (
                "/terraform/registry.terraform.io/hashicorp/null/index.json".to_string(),
                Reach::Cold,
            ),
            (
                "/terraform/registry.terraform.io/hashicorp/null/3.2.2.json".to_string(),
                Reach::Cold,
            ),
            // A version whose platforms are listed but whose archives are not stored: the mirror
            // asks for each archive (`mirror_fetch_archive`).
            (
                "/terraform/registry.terraform.io/hashicorp/random/1.0.0.json".to_string(),
                Reach::Cold,
            ),
        ];
        let uris: Vec<(&str, Reach)> = uris.iter().map(|(u, r)| (u.as_str(), *r)).collect();
        no_egress(
            "terraform",
            &uris,
            &[
                (
                    "terraform/modules/corp/net/aws/1.0.0/_source_url",
                    b"https://source.example/net.tar.gz",
                ),
                (
                    "terraform/providers/hashicorp/null/3.2.2/linux_amd64.json",
                    TF_PROVIDER_META,
                ),
                (
                    "terraform/providers/hashicorp/null/versions.json",
                    br#"{"versions":[{"version":"3.2.2","platforms":[{"os":"linux","arch":"amd64"}]}]}"#,
                ),
                (
                    "terraform/providers/hashicorp/random/versions.json",
                    br#"{"versions":[{"version":"1.0.0","platforms":[{"os":"linux","arch":"amd64"}]}]}"#,
                ),
            ],
            |c, mode| {
                c.terraform.enabled = true;
                c.terraform.metadata_ttl = 0;
                set_upstream(&mut c.terraform.proxy, mode);
            },
        )
        .await;
    }

    #[tokio::test]
    async fn ansible_every_route() {
        let v3 = "/ansible/v3/collections/community/general";
        let idx = "/ansible/api/v3/plugin/ansible/content/published/collections/index";
        let uris = [
            ("/ansible/".to_string(), Reach::Local),
            ("/ansible/api/".to_string(), Reach::Local),
            ("/ansible/v3/collections/".to_string(), Reach::Cold),
            (format!("{v3}/"), Reach::Cold),
            (format!("{v3}/versions/"), Reach::Cold),
            (format!("{v3}/versions/8.0.0/"), Reach::Cold),
            (format!("{idx}/"), Reach::Cold),
            (format!("{idx}/community/general/"), Reach::Cold),
            (format!("{idx}/community/general/versions/"), Reach::Cold),
            (format!("{idx}/community/general/versions/8.0.0/"), Reach::Cold),
            ("/ansible/download/community-general-8.0.0.tar.gz".to_string(), Reach::Cold),
            (
                "/ansible/api/v3/plugin/ansible/content/published/collections/artifacts/community-general-8.0.0.tar.gz"
                    .to_string(),
                Reach::Cold,
            ),
        ];
        let uris: Vec<(&str, Reach)> = uris.iter().map(|(u, r)| (u.as_str(), *r)).collect();
        no_egress("ansible", &uris, &[], |c, mode| {
            c.ansible.enabled = true;
            c.ansible.metadata_ttl = 0;
            set_upstream(&mut c.ansible.proxy, mode);
        })
        .await;
    }

    #[tokio::test]
    async fn cpan_every_route() {
        no_egress(
            "cpan",
            &[
                ("/cpan/modules/02packages.details.txt.gz", Reach::Cold),
                ("/cpan/modules/03modlist.data.gz", Reach::Cold),
                ("/cpan/authors/01mailrc.txt.gz", Reach::Cold),
                (
                    "/cpan/authors/id/H/HA/HAARG/Moo-2.005005.tar.gz",
                    Reach::Cold,
                ),
            ],
            &[("cpan/modules/02packages.details.txt.gz", b"PKGS")],
            |c, mode| {
                c.cpan.enabled = true;
                c.cpan.metadata_ttl = 0;
                set_upstream(&mut c.cpan.proxy, mode);
            },
        )
        .await;
    }

    /// Only `upstream_url` reads a format's upstream setting in its handler: every decision about
    /// asking an upstream goes through the one rule that reads a blank setting as switched off.
    #[test]
    fn only_upstream_url_reads_the_upstream_setting() {
        for (format, field, source) in [
            ("gems", "gems", include_str!("gems.rs")),
            ("nuget", "nuget", include_str!("nuget.rs")),
            ("conan", "conan", include_str!("conan.rs")),
            ("terraform", "terraform", include_str!("terraform.rs")),
            ("ansible", "ansible", include_str!("ansible.rs")),
            ("cpan", "cpan", include_str!("cpan.rs")),
        ] {
            let code = source.split("#[cfg(test)]").next().unwrap();
            let read = format!("state.config.{field}.proxy");
            // The field itself, not `proxy_timeout` or `proxy_auth`.
            let at: Vec<usize> = code
                .match_indices(&read)
                .map(|(i, _)| i)
                .filter(|i| {
                    !code[i + read.len()..]
                        .starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
                })
                .collect();
            assert_eq!(at.len(), 1, "{format}: {read} read {} times", at.len());
            let before = &code[..at[0]];
            let function = before.rfind("\nfn ").unwrap_or(0);
            assert!(
                before[function..].starts_with("\nfn upstream_url(state: &AppState)"),
                "{format}: {read} read outside upstream_url"
            );
        }
    }
}

/// An upstream's credential goes only to that upstream: a PyPI index may name its files on
/// another host, and that host must not receive the index's Basic credential.
#[cfg(test)]
mod pypi_credential_host {
    #![allow(clippy::unwrap_used)]

    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::Method;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn a_file_on_another_host_is_fetched_without_the_index_credential() {
        let files = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/files/corp_lib-1.0.0.tar.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"SDIST".to_vec()))
            .mount(&files)
            .await;
        let index = MockServer::start().await;
        let href = format!("{}/files/corp_lib-1.0.0.tar.gz", files.uri());
        Mock::given(method("GET"))
            .and(path("/corp-lib/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"<html><body><a href="{href}">corp_lib-1.0.0.tar.gz</a></body></html>"#
            )))
            .mount(&index)
            .await;
        let url = index.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.pypi.proxies = serde_json::from_value(serde_json::json!([
                {"url": url, "auth": "corp:s3cret"}
            ]))
            .unwrap();
        });
        let _ = send(
            &ctx.app,
            Method::GET,
            "/simple/corp-lib/corp_lib-1.0.0.tar.gz",
            "",
        )
        .await;
        let leaked: Vec<_> = files
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.headers.get("authorization").is_some())
            .collect();
        assert!(
            leaked.is_empty(),
            "the index credential reached another host"
        );
    }

    /// Several upstreams: the credential of the upstream whose index named the file goes only to
    /// that upstream's origin — never to another configured upstream's host.
    #[tokio::test]
    async fn a_credential_never_reaches_another_configured_upstream() {
        let first = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/files/corp_lib-1.0.0.tar.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"SDIST".to_vec()))
            .mount(&first)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&first)
            .await;
        let second = MockServer::start().await;
        let href = format!("{}/files/corp_lib-1.0.0.tar.gz", first.uri());
        Mock::given(method("GET"))
            .and(path("/corp-lib/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"<html><body><a href="{href}">corp_lib-1.0.0.tar.gz</a></body></html>"#
            )))
            .mount(&second)
            .await;
        let (a, b) = (first.uri(), second.uri());
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.pypi.proxies = serde_json::from_value(serde_json::json!([
                {"url": a},
                {"url": b, "auth": "corp:s3cret"}
            ]))
            .unwrap();
        });
        let _ = send(
            &ctx.app,
            Method::GET,
            "/simple/corp-lib/corp_lib-1.0.0.tar.gz",
            "",
        )
        .await;
        let requests = first.received_requests().await.unwrap();
        assert!(
            requests
                .iter()
                .any(|r| r.url.path() == "/files/corp_lib-1.0.0.tar.gz"),
            "control: the file was asked of the first upstream's host"
        );
        assert!(
            requests
                .iter()
                .all(|r| r.headers.get("authorization").is_none()),
            "the second upstream's credential reached the first"
        );
    }

    #[tokio::test]
    async fn a_file_on_the_index_host_is_fetched_with_the_credential() {
        let index = MockServer::start().await;
        let href = format!("{}/files/corp_lib-1.0.0.tar.gz", index.uri());
        Mock::given(method("GET"))
            .and(path("/corp-lib/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"<html><body><a href="{href}">corp_lib-1.0.0.tar.gz</a></body></html>"#
            )))
            .mount(&index)
            .await;
        Mock::given(method("GET"))
            .and(path("/files/corp_lib-1.0.0.tar.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"SDIST".to_vec()))
            .mount(&index)
            .await;
        let url = index.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.pypi.proxies = serde_json::from_value(serde_json::json!([
                {"url": url, "auth": "corp:s3cret"}
            ]))
            .unwrap();
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/simple/corp-lib/corp_lib-1.0.0.tar.gz",
            "",
        )
        .await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let file_requests: Vec<_> = index
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.url.path().starts_with("/files/"))
            .collect();
        assert!(!file_requests.is_empty());
        assert!(
            file_requests
                .iter()
                .all(|r| r.headers.get("authorization").is_some()),
            "the index host must receive its credential for its own files"
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
                auth_env: None,
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

/// Every handler names its own registry to curation: per-registry thresholds, quarantine
/// and rules are looked up by that label, so a handler passing another registry's would
/// apply another registry's settings (#1098). In the code of `registry/<format>.rs`
/// (before its test module) the only `RegistryType::` variant is its own.
#[cfg(test)]
mod curation_label_whitelist {
    use crate::registry_type::RegistryType;
    use std::collections::BTreeSet;

    const HANDLERS: &[(&str, RegistryType, &str)] = &[
        (
            "ansible.rs",
            RegistryType::Ansible,
            include_str!("ansible.rs"),
        ),
        (
            "cargo_registry.rs",
            RegistryType::Cargo,
            include_str!("cargo_registry.rs"),
        ),
        ("conan.rs", RegistryType::Conan, include_str!("conan.rs")),
        ("cpan.rs", RegistryType::Cpan, include_str!("cpan.rs")),
        ("deb.rs", RegistryType::Deb, include_str!("deb.rs")),
        ("docker.rs", RegistryType::Docker, include_str!("docker.rs")),
        ("gems.rs", RegistryType::Gems, include_str!("gems.rs")),
        ("go.rs", RegistryType::Go, include_str!("go.rs")),
        ("helm.rs", RegistryType::Helm, include_str!("helm.rs")),
        ("hf.rs", RegistryType::HuggingFace, include_str!("hf.rs")),
        ("maven.rs", RegistryType::Maven, include_str!("maven.rs")),
        ("npm.rs", RegistryType::Npm, include_str!("npm.rs")),
        ("nuget.rs", RegistryType::Nuget, include_str!("nuget.rs")),
        (
            "pub_dart.rs",
            RegistryType::PubDart,
            include_str!("pub_dart.rs"),
        ),
        ("pypi.rs", RegistryType::PyPI, include_str!("pypi.rs")),
        ("raw.rs", RegistryType::Raw, include_str!("raw.rs")),
        ("rpm.rs", RegistryType::Rpm, include_str!("rpm.rs")),
        (
            "terraform.rs",
            RegistryType::Terraform,
            include_str!("terraform.rs"),
        ),
    ];

    /// The file up to its first test module: a module-level `#[cfg(test)]` whose item,
    /// after any further attributes, is a `mod`. A `#[cfg(test)]` helper function between
    /// production items (go.rs has one) does not end the production code.
    fn code(src: &str) -> &str {
        let mut at = 0;
        while let Some(i) = src[at..].find("\n#[cfg(test)]") {
            let start = at + i + 1;
            let item = src[start..]
                .lines()
                .skip(1)
                .find(|l| !l.trim_start().starts_with("#["))
                .unwrap_or("");
            if item.starts_with("mod ") || item.starts_with("pub mod ") {
                return &src[..start];
            }
            at = start;
        }
        src
    }

    /// The variants named as `RegistryType::<Variant>` in `code`.
    fn variants(code: &str) -> BTreeSet<String> {
        code.split("RegistryType::")
            .skip(1)
            .map(|rest| {
                rest.chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect()
            })
            .collect()
    }

    #[test]
    fn the_production_code_ends_at_the_first_test_module() {
        let src = "fn a() {}\n#[cfg(test)]\nfn helper() {}\nfn b() { RegistryType::Go }\n#[cfg(test)]\n#[allow(x)]\nmod tests {\n    fn t() { RegistryType::Npm }\n}\n";
        let code = code(src);
        assert!(code.contains("fn b()"), "{code}");
        assert!(!code.contains("mod tests"), "{code}");
        assert_eq!(variants(code), BTreeSet::from(["Go".to_string()]));
    }

    #[test]
    fn every_handler_names_only_its_own_registry() {
        let owns: BTreeSet<String> = HANDLERS
            .iter()
            .map(|(_, rt, _)| format!("{rt:?}"))
            .collect();
        assert_eq!(
            owns.len(),
            RegistryType::all().len(),
            "every registry has its handler here"
        );
        for (file, own, src) in HANDLERS {
            let code = code(src);
            for alias in ["RegistryType as", "RegistryType::{", "RegistryType::*"] {
                assert!(!code.contains(alias), "{file}: `{alias}` hides the label");
            }
            assert_eq!(
                variants(code),
                BTreeSet::from([format!("{own:?}")]),
                "{file} names another registry to curation"
            );
        }
    }
}
