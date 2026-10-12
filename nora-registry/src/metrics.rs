// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use axum::{
    body::Body,
    extract::{MatchedPath, State},
    http::Request,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use memchr::memmem;
use prometheus::{
    register_histogram_vec, register_int_counter, register_int_counter_vec, register_int_gauge,
    register_int_gauge_vec, Encoder, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    IntGaugeVec, TextEncoder,
};
use std::sync::{Arc, LazyLock};
use std::time::Instant;

use crate::AppState;

/// Total HTTP requests counter
pub static HTTP_REQUESTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_http_requests_total",
        "Total number of HTTP requests",
        &["registry", "method", "status"]
    )
    .expect("failed to create HTTP_REQUESTS_TOTAL metric at startup")
});

/// Curation engine decisions, by effective outcome. Makes allow/deny visible in
/// telemetry — previously curation only kept internal counters, so an operator
/// could not see from Prometheus how often curation allowed vs blocked.
/// Labels: `decision` ∈ {allow, block, audit (would-block, allowed in audit
/// mode), skip}.
pub static CURATION_DECISIONS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_curation_decisions_total",
        "Curation engine decisions by effective outcome",
        &["decision"]
    )
    .expect("failed to create CURATION_DECISIONS_TOTAL metric at startup")
});

/// Downloads younger than `min_release_age` let through because their exact version is
/// on `[curation.<registry>] allow` — each one a deliberate cooldown exemption.
pub static CURATION_MIN_AGE_ALLOWED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_curation_min_age_allowed_total",
        "Downloads exempted from min_release_age by the curation allow list, by registry",
        &["registry"]
    )
    .expect("failed to create CURATION_MIN_AGE_ALLOWED_TOTAL metric at startup")
});

/// Internal-namespace requests refused by namespace isolation — the
/// dependency-confusion defense firing: an internal name that was neither served
/// from local storage nor proxied upstream (blocked / 404'd). Previously the guard
/// was invisible in Prometheus (only a client 403/404 and a test-internal counter
/// existed), so an operator could neither alert on nor graph it. By registry.
pub static NAMESPACE_ISOLATION_REFUSED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_namespace_isolation_refused_total",
        "Internal-namespace requests refused by namespace isolation (never served locally, never proxied upstream), by registry",
        &["registry"]
    )
    .expect("failed to create NAMESPACE_ISOLATION_REFUSED_TOTAL metric at startup")
});

/// Record one namespace-isolation refusal for `registry` (dependency-confusion
/// defense). `registry` must be a [`crate::registry_type::RegistryType::as_str`] value.
pub fn record_namespace_isolation_refused(registry: &str) {
    NAMESPACE_ISOLATION_REFUSED_TOTAL
        .with_label_values(&[registry])
        .inc();
}

/// OIDC token-validation rejections, by bounded reason (#994). The full reason
/// is logged; this counter keeps a low-cardinality, alertable breakdown so a
/// lifetime ceiling, a wrong audience and a missing role rule are
/// distinguishable. No issuer/subject/provider is ever put in the label.
pub static AUTH_OIDC_REJECTED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_auth_oidc_rejected_total",
        "OIDC token validation rejections, by reason",
        &["reason"]
    )
    .expect("failed to create AUTH_OIDC_REJECTED_TOTAL metric at startup")
});

/// Record one OIDC token rejection under its bounded `reason` bucket (#994).
/// `reason` ∈ {disabled, no_provider, lifetime_exceeded, no_role_rule,
/// algorithm, jwt_invalid, jwks, other}.
pub fn record_oidc_rejection(reason: &'static str) {
    AUTH_OIDC_REJECTED_TOTAL.with_label_values(&[reason]).inc();
}

/// Proxy artifacts held by the digest quarantine, by registry and outcome
/// (`blocked` = enforce returned 403; `observed` = observe served but recorded).
/// Gives the operator an alertable/graphable signal — the quarantine was
/// previously visible only in WARN logs.
pub static QUARANTINE_HOLDS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_quarantine_holds_total",
        "Proxy artifacts held by the digest quarantine, by registry and outcome",
        &["registry", "outcome"]
    )
    .expect("failed to create QUARANTINE_HOLDS_TOTAL metric at startup")
});

/// Conditional revalidations where upstream answered 304 Not Modified — the
/// cached body was reused and no body bytes were downloaded (#596).
pub static PROXY_UPSTREAM_304_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_proxy_upstream_304_total",
        "Upstream 304 Not Modified responses on revalidation",
        &["registry"]
    )
    .expect("failed to create PROXY_UPSTREAM_304_TOTAL metric at startup")
});

/// Upstream 4xx responses that carried a policy/geo block signature (e.g. an AWS
/// WAF geo rule via `x-amzn-waf-reason`) and were relayed as a bare 404. Lets an
/// operator tell an effective region/policy outage apart from a genuine not-found
/// — which is otherwise invisible (a 4xx logs nothing and never trips the breaker).
/// Labels: `registry`, `reason` (bounded: `geo` | `waf`) (#881).
pub static UPSTREAM_POLICY_BLOCKED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_upstream_policy_blocked_total",
        "Upstream 4xx responses bearing a policy/geo block signature, relayed as 404",
        &["registry", "reason"]
    )
    .expect("failed to create UPSTREAM_POLICY_BLOCKED_TOTAL metric at startup")
});

/// Body bytes saved by revalidation (size of the cached body that did NOT have
/// to be re-downloaded because upstream returned 304) (#596).
pub static PROXY_REVALIDATION_BYTES_SAVED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_proxy_revalidation_bytes_saved_total",
        "Body bytes not re-downloaded thanks to a 304 revalidation",
        &["registry"]
    )
    .expect("failed to create PROXY_REVALIDATION_BYTES_SAVED_TOTAL metric at startup")
});

/// Revalidation attempts that failed (conditional request error, corrupt
/// validator sidecar, missing cached body) and fell back to a full fetch.
/// Nonzero signals the feature is silently degrading (#596).
pub static PROXY_REVALIDATION_ERRORS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_proxy_revalidation_errors_total",
        "Revalidation attempts that fell back to a full fetch",
        &["registry"]
    )
    .expect("failed to create PROXY_REVALIDATION_ERRORS_TOTAL metric at startup")
});

/// Concurrent upstream fetches collapsed into one by the single-flight
/// coalescer: a follower served the leader's in-memory result without making
/// its own upstream round-trip (#595).
pub static PROXY_COALESCED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_proxy_coalesced_total",
        "Follower requests served from the single-flight leader without an upstream fetch",
        &["registry"]
    )
    .expect("failed to create PROXY_COALESCED_TOTAL metric at startup")
});

/// Current number of in-flight single-flight leaders (distinct keys being
/// fetched right now). A flat zero under load means coalescing is not engaging;
/// a monotonic climb signals a guard leak (#595).
pub static PROXY_INFLIGHT: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "nora_proxy_inflight",
        "Distinct keys currently being fetched under single-flight coalescing",
        &["registry"]
    )
    .expect("failed to create PROXY_INFLIGHT metric at startup")
});

/// Followers that did NOT get the leader's result and fell through to their own
/// upstream fetch — because the leader failed/cancelled (`leader`) or the wait
/// budget elapsed while the leader was still fetching (`budget`). A `budget`
/// rate rivalling `PROXY_COALESCED_TOTAL` means a slow upstream is re-stampeding
/// past the coalescer; without this it degrades silently (#595).
pub static PROXY_COALESCE_FALLTHROUGH_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_proxy_coalesce_fallthrough_total",
        "Followers that fell through to their own fetch instead of coalescing",
        &["registry", "reason"]
    )
    .expect("failed to create PROXY_COALESCE_FALLTHROUGH_TOTAL metric at startup")
});

/// HTTP request duration histogram
pub static HTTP_REQUEST_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "nora_http_request_duration_seconds",
        "HTTP request latency in seconds",
        &["registry", "method"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )
    .expect("failed to create HTTP_REQUEST_DURATION metric at startup")
});

/// Cache requests counter (hit/miss)
pub static CACHE_REQUESTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_cache_requests_total",
        "Total cache requests",
        &["registry", "result"]
    )
    .expect("failed to create CACHE_REQUESTS metric at startup")
});

/// Storage operations counter
pub static STORAGE_OPERATIONS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_storage_operations_total",
        "Total storage operations",
        &["operation", "status"]
    )
    .expect("failed to create STORAGE_OPERATIONS metric at startup")
});

/// OIDC namespace_scope enforcement decisions, by provider and decision.
/// `decision` is one of: allow | deny | would_deny (audit mode). Lets operators
/// watch a staged rollout before switching a provider from audit to enforce (#583).
pub static NAMESPACE_SCOPE_DECISIONS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_auth_namespace_scope_total",
        "OIDC namespace_scope enforcement decisions",
        &["provider", "decision"]
    )
    .expect("failed to create NAMESPACE_SCOPE_DECISIONS metric at startup")
});

/// Current number of artifacts by registry (gauge — rises and falls with GC)
pub static ARTIFACTS_TOTAL: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "nora_artifacts_total",
        "Current number of artifacts by registry",
        &["registry"]
    )
    .expect("failed to create ARTIFACTS_TOTAL metric at startup")
});

/// Circuit breaker state per registry (0=closed, 1=open, 2=half_open)
pub static CIRCUIT_BREAKER_STATE: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "nora_circuit_breaker_state",
        "Circuit breaker state (0=closed, 1=open, 2=half_open)",
        &["registry"]
    )
    .expect("failed to create CIRCUIT_BREAKER_STATE metric at startup")
});

/// Total requests rejected by circuit breaker
pub static CIRCUIT_BREAKER_REJECTIONS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_circuit_breaker_rejections_total",
        "Total requests rejected by circuit breaker",
        &["registry"]
    )
    .expect("failed to create CIRCUIT_BREAKER_REJECTIONS metric at startup")
});

/// Upstream URL leak detections in responses (#386)
pub static UPSTREAM_URL_LEAK_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_response_upstream_url_leak_total",
        "Upstream hostname detected in outgoing response body",
        &["registry"]
    )
    .expect("failed to create UPSTREAM_URL_LEAK_TOTAL metric at startup")
});

/// Upstream proxy request latency (#431)
pub static UPSTREAM_REQUEST_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "nora_upstream_request_duration_seconds",
        "Upstream proxy request latency in seconds",
        &["registry", "status"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0]
    )
    .expect("failed to create UPSTREAM_REQUEST_DURATION metric at startup")
});

/// Wall-clock time of the integrity-verify step on a buffered `Storage::get()`
/// — the `spawn_blocking` re-hash. Includes blocking-pool queue time, so a
/// rising p99 under read load signals pool saturation, not just hash cost.
/// Recorded only for a pinned key; an unpinned one skips the gate and observes
/// nothing. Quantifies the #602 perf question before any change is made (#602).
pub static STORAGE_VERIFY_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "nora_storage_verify_duration_seconds",
        "Integrity-verify (SHA-256) wall-clock per buffered get, including blocking-pool queue",
        &["registry"],
        vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5]
    )
    .expect("failed to create STORAGE_VERIFY_DURATION_SECONDS metric at startup")
});

/// Size in bytes of bodies served through the buffered `Storage::get()` path.
/// Shows how much read traffic is large enough for inline hashing to matter —
/// the data needed to decide whether a size threshold is worthwhile (#602).
pub static STORAGE_GET_BYTES: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "nora_storage_get_bytes",
        "Body size of buffered Storage::get() reads",
        &["registry"],
        vec![
            1024.0,
            16_384.0,
            262_144.0,
            1_048_576.0,
            8_388_608.0,
            67_108_864.0,
            536_870_912.0
        ]
    )
    .expect("failed to create STORAGE_GET_BYTES metric at startup")
});

/// Total artifact downloads by registry (#431)
pub static DOWNLOADS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_downloads_total",
        "Total artifact downloads",
        &["registry"]
    )
    .expect("failed to create DOWNLOADS_TOTAL metric at startup")
});

/// Total artifact uploads by registry (#431)
pub static UPLOADS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_uploads_total",
        "Total artifact uploads",
        &["registry"]
    )
    .expect("failed to create UPLOADS_TOTAL metric at startup")
});

/// Storage size in bytes by registry (#431)
pub static STORAGE_BYTES: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "nora_storage_bytes",
        "Stored artifact bytes per registry (label \"total\" = full storage footprint incl. metadata)",
        &["registry"]
    )
    .expect("failed to create STORAGE_BYTES metric at startup")
});

/// Storage reachability as `/ready` sees it: 1 reachable, 0 not (readiness
/// fails with 503). Set on every readiness check and once a minute by the
/// maintenance loop, so it is current without a prober.
pub static STORAGE_REACHABLE: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "nora_storage_reachable",
        "1 when the storage backend is reachable (readiness passes), 0 when not"
    )
    .expect("failed to create STORAGE_REACHABLE metric at startup")
});

/// Process uptime in seconds (gauge)
pub static UPTIME_SECONDS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!("nora_uptime_seconds", "Process uptime in seconds")
        .expect("failed to create UPTIME_SECONDS metric at startup")
});

/// Cache write errors by registry and operation (#500)
pub static CACHE_WRITE_ERRORS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_cache_write_errors_total",
        "Cache write failures in background cache tasks",
        &["registry", "operation"]
    )
    .expect("failed to create CACHE_WRITE_ERRORS metric at startup")
});

/// Disk spool refusals and failures by registry and reason: `busy` (the
/// `server.spool_max_mb` budget is in use, 503), `too_large` (507 / 413),
/// `no_space` (the spool volume is full, 507) and `io` (any other local failure, 500).
pub static SPOOL_FAILURES: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_spool_failures_total",
        "Disk spool refusals and local failures (proxied artifacts, NuGet pushes, PyPI uploads)",
        &["registry", "reason"]
    )
    .expect("failed to create SPOOL_FAILURES metric at startup")
});

/// Corrupt metadata detected during publish (#533)
pub static METADATA_CORRUPT_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_metadata_corrupt_total",
        "Corrupt metadata detected during publish (parse failure on existing data)",
        &["registry"]
    )
    .expect("failed to create METADATA_CORRUPT_TOTAL metric at startup")
});

/// Packuments rebuilt from per-version keys because the derived
/// `metadata.json` was absent (#956). A non-zero rate points at storage that
/// was written or restored outside NORA.
pub static PACKUMENT_REBUILT_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_packument_rebuilt_total",
        "Packuments reassembled from per-version keys after a missing derived packument",
        &["registry"]
    )
    .expect("failed to create PACKUMENT_REBUILT_TOTAL metric at startup")
});

/// Leak detection scans skipped (#517)
static LEAK_DETECTION_SKIPPED: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "nora_leak_detection_skipped_total",
        "Leak detection scans skipped (body too large or unknown size)",
        &["reason"]
    )
    .expect("failed to create LEAK_DETECTION_SKIPPED metric at startup")
});

/// Active streaming proxy downloads in progress (#580).
///
/// Incremented when `fetch_blob_from_upstream` starts streaming, decremented
/// on completion or error. Used to detect concurrent download pressure.
pub static PROXY_ACTIVE_DOWNLOADS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "nora_proxy_active_downloads",
        "Number of Docker blob proxy downloads currently in progress"
    )
    .expect("failed to create PROXY_ACTIVE_DOWNLOADS metric at startup")
});

/// Open Docker blob upload sessions, sampled on scrape.
///
/// Compare against `NORA_MAX_UPLOAD_SESSIONS`: a level that tracks concurrent
/// pushes is healthy, one that ratchets toward the ceiling and only drops on the
/// 30-minute TTL sweep means sessions are leaking rather than finalizing.
pub static UPLOAD_SESSIONS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "nora_upload_sessions",
        "Docker blob upload sessions currently held in the session map"
    )
    .expect("failed to create UPLOAD_SESSIONS metric at startup")
});

/// Docker blob uploads streaming to disk right now, sampled on scrape.
///
/// Bounded by the same ceiling as the session map. Unlike `UPLOAD_SESSIONS` this
/// counts only requests actively moving bytes, so the gap between the two is the
/// idle-session backlog.
pub static UPLOAD_IN_FLIGHT: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "nora_upload_in_flight",
        "Docker blob uploads currently streaming to disk"
    )
    .expect("failed to create UPLOAD_IN_FLIGHT metric at startup")
});

/// Total bytes successfully downloaded from upstream via proxy (#580).
///
/// Only incremented after a complete, verified download (not on failures).
/// Use with `rate()` in Prometheus to track upstream bandwidth consumption.
pub static PROXY_DOWNLOAD_BYTES: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "nora_proxy_download_bytes_total",
        "Total bytes successfully downloaded from upstream Docker registries"
    )
    .expect("failed to create PROXY_DOWNLOAD_BYTES metric at startup")
});

/// Maximum response body size to scan for upstream URL leaks (2 MB).
const LEAK_SCAN_MAX_BYTES: usize = 2 * 1024 * 1024;

/// Pre-compiled substring searchers for upstream hostname leak detection.
///
/// Built once at startup from `Config::upstream_hostnames()` and stored in `AppState`.
#[derive(Clone)]
pub struct LeakFinders {
    entries: Arc<Vec<LeakFinderEntry>>,
}

#[derive(Clone)]
struct LeakFinderEntry {
    registry: String,
    hostname: String,
    finder: memmem::Finder<'static>,
    /// URL paths that may follow the hostname: the registry's intentional
    /// pass-throughs, plain and `\/`-escaped.
    passthrough: Vec<String>,
}

/// Upstream URL paths a registry's rewriter leaves in its responses on purpose.
/// npm and PyPI have none: npm rewrites tarball links and leaves other mentions of
/// the upstream (a readme) untouched as text, PyPI rewrites every file URL.
fn passthrough_paths(registry: &str) -> &'static [&'static str] {
    match registry {
        "nuget" => crate::registry::nuget::UPSTREAM_PASSTHROUGH_PATHS,
        _ => &[],
    }
}

impl LeakFinders {
    /// Build leak finders from (registry, hostname) pairs.
    pub fn new(hostnames: Vec<(String, String)>) -> Self {
        let entries = hostnames
            .into_iter()
            .map(|(registry, hostname)| {
                let finder = memmem::Finder::new(hostname.as_bytes()).into_owned();
                let passthrough = passthrough_paths(&registry)
                    .iter()
                    .flat_map(|p| [p.to_string(), p.replace('/', "\\/")])
                    .collect();
                LeakFinderEntry {
                    registry,
                    hostname,
                    finder,
                    passthrough,
                }
            })
            .collect();
        Self {
            entries: Arc::new(entries),
        }
    }

    /// Scan bytes for any upstream hostname not followed by one of the registry's
    /// intentional pass-through paths. Returns first match.
    fn scan(&self, haystack: &[u8]) -> Option<(&str, &str)> {
        for entry in self.entries.iter() {
            let leaked = entry.finder.find_iter(haystack).any(|at| {
                let rest = &haystack[at + entry.hostname.len()..];
                !entry
                    .passthrough
                    .iter()
                    .any(|p| rest.starts_with(p.as_bytes()))
            });
            if leaked {
                return Some((&entry.registry, &entry.hostname));
            }
        }
        None
    }

    /// Returns true if no finders are configured.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Routes for metrics endpoint
pub fn routes() -> Router<AppState> {
    Router::new().route("/metrics", get(metrics_handler))
}

/// Handler for /metrics endpoint
async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    UPLOAD_SESSIONS.set(state.upload_sessions.read().len() as i64);
    UPLOAD_IN_FLIGHT.set(crate::registry::docker::in_flight_uploads() as i64);

    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();

    encoder
        .encode(&metric_families, &mut buffer)
        .unwrap_or_default();

    ([("content-type", "text/plain; charset=utf-8")], buffer)
}

/// The `method` label: the standard methods, anything else (any RFC 9110 token an
/// unauthenticated client sends) as `OTHER`, so it cannot mint series at will.
fn method_label(method: &axum::http::Method) -> &'static str {
    use axum::http::Method;
    match *method {
        Method::GET => "GET",
        Method::HEAD => "HEAD",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::PATCH => "PATCH",
        Method::DELETE => "DELETE",
        Method::OPTIONS => "OPTIONS",
        _ => "OTHER",
    }
}

/// Middleware to record request metrics
pub async fn metrics_middleware(
    matched_path: Option<MatchedPath>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let start = Instant::now();
    let method = method_label(request.method());
    let path = matched_path
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| request.uri().path().to_string());

    // Determine registry from path
    let registry = detect_registry(&path);

    // Process request
    let response = next.run(request).await;

    let duration = start.elapsed().as_secs_f64();
    let status = response.status().as_u16().to_string();

    // Record metrics
    HTTP_REQUESTS_TOTAL
        .with_label_values(&[&registry, method, &status])
        .inc();

    HTTP_REQUEST_DURATION
        .with_label_values(&[&registry, method])
        .observe(duration);

    response
}

/// Middleware to detect upstream URL leaks in JSON response bodies (#386).
///
/// Scans outgoing JSON responses for configured upstream hostnames.
/// Detection only — never blocks responses. Increments counter and logs WARN.
pub async fn leak_detection_middleware(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();
    let response = next.run(request).await;

    // Fast path: skip if no finders configured
    if state.leak_finders.is_empty() {
        return response;
    }

    // Only scan JSON responses
    let is_json = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.contains("json"));
    if !is_json {
        return response;
    }

    // Skip NORA's own admin/UI/observability surface (#624). These endpoints
    // (the dashboard, stats, OpenAPI spec, health) legitimately echo the
    // configured upstream URLs in their JSON — that is expected output, not a
    // failed rewrite. Proxying only ever happens inside registry handlers on
    // registry-protocol paths (ADR-4), so a configured upstream hostname here is
    // never a leak. Scanning them poisons UPSTREAM_URL_LEAK_TOTAL with false
    // positives and drowns the signal for genuine proxy-response leaks.
    //
    // Denylist (skip own-surface), not allowlist (scan only known registry
    // paths): a security detector must fail toward over-scanning. An allowlist
    // would silently blind the detector on any newly added registry path whose
    // prefix nobody remembered to register — a missed leak is far worse than a
    // stray scan. The skip is counted so it never goes silent.
    if is_own_surface(&path) {
        LEAK_DETECTION_SKIPPED
            .with_label_values(&["own_surface"])
            .inc();
        return response;
    }

    // Determine body size BEFORE consuming it (#517).
    // Primary: body.size_hint().exact() — works for handler-built responses (Full<Bytes>).
    // Fallback: Content-Length header — works for proxy responses where upstream set it.
    // If both are None (streaming/chunked without CL), skip scan to avoid body loss.
    use axum::body::HttpBody as _;
    let size_hint_exact = response.body().size_hint().exact().map(|s| s as usize);
    let content_length = response
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok());
    let known_size = size_hint_exact.or(content_length);

    match known_size {
        Some(size) if size > LEAK_SCAN_MAX_BYTES => {
            LEAK_DETECTION_SKIPPED
                .with_label_values(&["too_large"])
                .inc();
            return response;
        }
        None => {
            // Unknown body size — cannot safely consume (body is one-shot stream).
            LEAK_DETECTION_SKIPPED
                .with_label_values(&["unknown_size"])
                .inc();
            return response;
        }
        Some(_) => {} // Size known and within limit — proceed to scan
    }

    let is_gzip = response
        .headers()
        .get(axum::http::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ce| ce.contains("gzip"));

    // CANCEL-SAFETY: to_bytes consumes the body stream (one-shot). If this future is
    // dropped, the body is partially consumed and cannot be restored. The size pre-check
    // above ensures we only reach here for known-size bodies within the limit, so
    // cancellation would only occur from external timeout, not from exceeding the limit.
    let (parts, body) = response.into_parts();
    let body_bytes = match axum::body::to_bytes(body, LEAK_SCAN_MAX_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            // Defense-in-depth: should be unreachable with correct size pre-check.
            // Body is already consumed — cannot restore. Return 502 so clients
            // know the response is broken, not 200-with-empty-body (#540).
            LEAK_DETECTION_SKIPPED
                .with_label_values(&["body_read_error"])
                .inc();
            tracing::error!(
                path = path.as_str(),
                size_hint = ?size_hint_exact,
                content_length = ?content_length,
                "leak_detection: body read failed after size pre-check passed — response body lost"
            );
            return (
                axum::http::StatusCode::BAD_GATEWAY,
                "upstream response error",
            )
                .into_response();
        }
    };

    // Skip tiny bodies
    if body_bytes.len() < 20 {
        return Response::from_parts(parts, Body::from(body_bytes));
    }

    // Decompress gzip if needed, scan decompressed bytes
    let scan_bytes: Vec<u8>;
    let haystack = if is_gzip {
        match decompress_gzip(&body_bytes) {
            Some(decompressed) => {
                scan_bytes = decompressed;
                &scan_bytes
            }
            None => &body_bytes[..],
        }
    } else {
        &body_bytes[..]
    };

    if let Some((registry, hostname)) = state.leak_finders.scan(haystack) {
        UPSTREAM_URL_LEAK_TOTAL.with_label_values(&[registry]).inc();
        tracing::warn!(
            registry = registry,
            upstream = hostname,
            path = path.as_str(),
            body_len = haystack.len(),
            "upstream URL leak detected in response"
        );
    }

    // Return original (possibly gzip-compressed) body unchanged
    Response::from_parts(parts, Body::from(body_bytes))
}

/// Decompress gzip bytes; returns None on failure or if decompressed size exceeds limit.
///
/// Capped at `LEAK_SCAN_MAX_BYTES` to prevent gzip bomb attacks (#517).
fn decompress_gzip(data: &[u8]) -> Option<Vec<u8>> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    let decoder = GzDecoder::new(data);
    // Cap decompression to prevent gzip bombs (e.g. 42KB compressed → 4.5GB decompressed).
    let mut limited = decoder.take(LEAK_SCAN_MAX_BYTES as u64);
    let mut buf = Vec::new();
    limited.read_to_end(&mut buf).ok()?;
    // Check if data was truncated (more bytes available beyond cap)
    let mut probe = [0u8; 1];
    if limited.into_inner().read(&mut probe).unwrap_or(0) > 0 {
        LEAK_DETECTION_SKIPPED
            .with_label_values(&["gzip_truncated"])
            .inc();
        tracing::debug!(
            compressed_len = data.len(),
            decompressed_cap = LEAK_SCAN_MAX_BYTES,
            "leak_detection: gzip decompression truncated at scan limit"
        );
    }
    debug_assert!(buf.len() <= LEAK_SCAN_MAX_BYTES);
    Some(buf)
}

/// Returns true for NORA's own admin / UI / observability endpoints.
///
/// These surfaces may legitimately include configured upstream URLs in their
/// responses (e.g. the dashboard listing which upstreams a registry proxies),
/// so an upstream hostname appearing here is expected output, not a rewrite
/// leak. Proxying happens exclusively inside registry handlers on
/// registry-protocol paths (ADR-4); none of those paths share these prefixes,
/// so excluding the own surface cannot blind leak detection on a proxy path —
/// the `every_registry_prefix_stays_scannable` test guards that invariant.
///
/// Prefixes are matched with a boundary (`/api/`, not bare `/api`) so a
/// hypothetical registry path like `/apiv2foo` is not skipped by accident.
///
/// INVARIANT (deliberate fail-open by prefix): the `/api/` prefix excludes every
/// current and future endpoint under it. Any future `/api/*` route that serves
/// *proxied upstream* content (not NORA's own config/data) MUST therefore be
/// kept off the own surface — either route it under a registry prefix or exclude
/// it from this function explicitly — or its upstream-URL leaks will go unscanned.
fn is_own_surface(path: &str) -> bool {
    path.starts_with("/api/")          // HTMX JSON backend: dashboard, stats, list, detail, search, tokens
        || path.starts_with("/api-docs") // Swagger UI + /api-docs/openapi.json spec
        || path == "/ui"
        || path.starts_with("/ui/")    // UI pages (HTML, scanned defensively)
        || path == "/health"
        || path == "/ready"
        || path == "/metrics"
}

/// Detect registry type from path, using [`RegistryType::mount_point`] as the single
/// source of truth: matching the registry whose mount point prefixes the path (adding a
/// format extends this automatically via `all()`, no new arm here). PyPI has a second
/// prefix (`/packages`) beyond its mount point; `/ui` and anything else are non-registry.
fn detect_registry(path: &str) -> String {
    use crate::registry_type::RegistryType;
    if path.starts_with("/packages") {
        return RegistryType::PyPI.as_str().to_string();
    }
    for rt in RegistryType::all() {
        // Match on the full mount point (with trailing slash) so a bare or lookalike
        // prefix (`/goblin`, `/rawdata`) does not match a registry — matching the original.
        if path.starts_with(rt.mount_point()) {
            return rt.as_str().to_string();
        }
    }
    if path.starts_with("/ui") {
        "ui".to_string()
    } else {
        "other".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_method_label_is_bounded() {
        use axum::http::Method;
        assert_eq!(method_label(&Method::GET), "GET");
        assert_eq!(method_label(&Method::DELETE), "DELETE");
        assert_eq!(
            method_label(&Method::from_bytes(b"FOO123").unwrap()),
            "OTHER"
        );
        assert_eq!(method_label(&Method::CONNECT), "OTHER");
    }

    #[test]
    fn test_detect_registry_docker() {
        assert_eq!(detect_registry("/v2/nginx/manifests/latest"), "docker");
        assert_eq!(detect_registry("/v2/"), "docker");
        assert_eq!(
            detect_registry("/v2/library/alpine/blobs/sha256:abc"),
            "docker"
        );
    }

    #[test]
    fn test_detect_registry_maven() {
        assert_eq!(detect_registry("/maven2/com/example/artifact"), "maven");
    }

    #[test]
    fn test_detect_registry_npm() {
        assert_eq!(detect_registry("/npm/lodash"), "npm");
        assert_eq!(detect_registry("/npm/@scope/package"), "npm");
    }

    #[test]
    fn test_detect_registry_cargo_path() {
        assert_eq!(detect_registry("/cargo/api/v1/crates"), "cargo");
    }

    #[test]
    fn test_detect_registry_pypi() {
        assert_eq!(detect_registry("/simple/requests/"), "pypi");
        assert_eq!(
            detect_registry("/packages/requests/1.0/requests-1.0.tar.gz"),
            "pypi"
        );
    }

    #[test]
    fn test_detect_registry_ui() {
        assert_eq!(detect_registry("/ui/dashboard"), "ui");
        assert_eq!(detect_registry("/ui"), "ui");
    }

    #[test]
    fn test_detect_registry_other() {
        assert_eq!(detect_registry("/health"), "other");
        assert_eq!(detect_registry("/ready"), "other");
        assert_eq!(detect_registry("/unknown/path"), "other");
    }

    #[test]
    fn test_detect_registry_go_path() {
        assert_eq!(
            detect_registry("/go/github.com/user/repo/@v/v1.0.0.info"),
            "go"
        );
        assert_eq!(detect_registry("/go/github.com/user/repo/@latest"), "go");
        // Bare prefix without trailing slash should not match
        assert_eq!(detect_registry("/goblin/something"), "other");
    }

    #[test]
    fn test_detect_registry_raw_path() {
        assert_eq!(detect_registry("/raw/my-project/artifact.tar.gz"), "raw");
        assert_eq!(detect_registry("/raw/data/file.bin"), "raw");
        // Bare prefix without trailing slash should not match
        assert_eq!(detect_registry("/rawdata/file"), "other");
    }

    #[test]
    fn test_leak_finders_detects_upstream_hostname() {
        let finders = LeakFinders::new(vec![
            ("nuget".to_string(), "api.nuget.org".to_string()),
            ("npm".to_string(), "registry.npmjs.org".to_string()),
        ]);
        let body = br#"{"@id":"https://api.nuget.org/v3/registration/newtonsoft.json"}"#;
        let result = finders.scan(body);
        assert!(result.is_some());
        let (registry, hostname) = result.unwrap();
        assert_eq!(registry, "nuget");
        assert_eq!(hostname, "api.nuget.org");
    }

    #[test]
    fn test_leak_finders_no_match_returns_none() {
        let finders = LeakFinders::new(vec![("nuget".to_string(), "api.nuget.org".to_string())]);
        let body = br#"{"@id":"http://localhost:4000/nuget/v3/registration/newtonsoft.json"}"#;
        assert!(finders.scan(body).is_none());
    }

    #[test]
    fn test_leak_finders_empty_has_no_match() {
        let finders = LeakFinders::new(vec![]);
        assert!(finders.is_empty());
        assert!(finders.scan(b"anything").is_none());
    }

    #[test]
    fn test_decompress_gzip_roundtrip() {
        use flate2::write::GzEncoder;
        use std::io::Write;
        let original = b"hello upstream api.nuget.org world";
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed = decompress_gzip(&compressed).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_leak_finders_detects_in_decompressed_gzip() {
        use flate2::write::GzEncoder;
        use std::io::Write;
        let finders = LeakFinders::new(vec![("nuget".to_string(), "api.nuget.org".to_string())]);
        let body = br#"{"packageContent":"https://api.nuget.org/v3-flatcontainer/pkg/1.0.0/pkg.1.0.0.nupkg"}"#;
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(body).unwrap();
        let compressed = encoder.finish().unwrap();

        // Compressed bytes should NOT match (gzip obfuscates)
        assert!(finders.scan(&compressed).is_none());

        // Decompressed bytes should match
        let decompressed = decompress_gzip(&compressed).unwrap();
        let result = finders.scan(&decompressed);
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "nuget");
    }

    #[test]
    fn test_decompress_gzip_capped_at_limit() {
        use flate2::write::GzEncoder;
        use std::io::Write;
        // Create data larger than LEAK_SCAN_MAX_BYTES
        let large_data = vec![b'A'; LEAK_SCAN_MAX_BYTES + 1024];
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&large_data).expect("gzip encode");
        let compressed = encoder.finish().expect("gzip finish");

        // decompress_gzip must cap output at LEAK_SCAN_MAX_BYTES
        let result = decompress_gzip(&compressed).expect("decompress");
        assert!(result.len() <= LEAK_SCAN_MAX_BYTES);
    }

    #[test]
    fn test_decompress_gzip_invalid_data_returns_none() {
        // Random bytes are not valid gzip
        assert!(decompress_gzip(b"not gzip data at all").is_none());
        assert!(decompress_gzip(b"").is_none());
    }

    #[test]
    fn test_decompress_gzip_normal_data_unchanged() {
        use flate2::write::GzEncoder;
        use std::io::Write;
        // Data well under the limit should decompress fully
        let original = b"small payload for leak scanning test";
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(original).expect("gzip encode");
        let compressed = encoder.finish().expect("gzip finish");

        let result = decompress_gzip(&compressed).expect("decompress");
        assert_eq!(result, original);
    }

    // --- #624: own-surface exclusion from upstream-URL leak detection ---

    #[test]
    fn is_own_surface_covers_admin_ui_and_observability() {
        // Exact strings as produced by axum `Uri::path()` (query stripped).
        assert!(is_own_surface("/api/ui/dashboard"));
        assert!(is_own_surface("/api/ui/stats"));
        assert!(is_own_surface("/api/ui/cargo/list"));
        assert!(is_own_surface("/api-docs/openapi.json"));
        assert!(is_own_surface("/ui"));
        assert!(is_own_surface("/ui/"));
        assert!(is_own_surface("/ui/cargo"));
        assert!(is_own_surface("/health"));
        assert!(is_own_surface("/ready"));
        assert!(is_own_surface("/metrics"));
    }

    #[test]
    fn is_own_surface_does_not_over_match_at_prefix_boundary() {
        // Boundary-aware: must not skip paths that merely start with the letters.
        assert!(!is_own_surface("/apiv2foo")); // not "/api/"
        assert!(!is_own_surface("/uikit/widget")); // not "/ui" or "/ui/"
        assert!(!is_own_surface("/metrics-export"));
        assert!(!is_own_surface("/healthcheck-proxy"));
    }

    #[test]
    fn every_registry_prefix_stays_scannable() {
        // Guard: the own-surface denylist must never swallow a registry-protocol
        // path, or the leak detector would go silently blind on that format.
        // These are the prefixes registry handlers actually route on.
        for p in [
            "/v2/library/alpine/manifests/latest",
            "/maven2/com/example/artifact/1.0/artifact-1.0.jar",
            "/npm/lodash",
            "/cargo/api/v1/crates/serde",
            "/simple/requests/",
            "/packages/requests/1.0/requests-1.0.tar.gz",
            "/go/github.com/user/repo/@v/v1.0.0.info",
            "/raw/my-project/artifact.tar.gz",
            "/gems/rails-7.0.0.gem",
            "/terraform/example/aws/1.0.0",
            "/ansible/community/general/1.0.0",
            "/nuget/v3/index.json",
            "/pub/api/packages/http",
            "/conan/v2/conans/zlib",
            "/rpm/myrepo/repodata/repomd.xml",
            "/deb/myrepo/Packages",
        ] {
            assert!(
                !is_own_surface(p),
                "registry path must remain scannable: {p}"
            );
        }
    }

    /// Build a minimal router that drives the REAL `leak_detection_middleware`
    /// over a single handler-built JSON response (PM-4: test the call-path, not
    /// the helper in isolation). A unique canary hostname per test keeps the
    /// global counter assertions free of cross-test races.
    fn leak_test_app(
        route: &'static str,
        registry_label: &'static str,
        canary_host: &'static str,
        body: &'static str,
    ) -> (axum::Router, AppState) {
        use axum::routing::get;
        let mut ctx = crate::test_helpers::create_test_context();
        ctx.state.leak_finders =
            LeakFinders::new(vec![(registry_label.to_string(), canary_host.to_string())]);
        let state = ctx.state.clone();
        // The leak middleware only inspects the response body — it never touches
        // storage — so the context's tempdir may drop at the end of this helper
        // without affecting the test.
        let app = axum::Router::new()
            .route(
                route,
                get(move || async move {
                    (
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        body,
                    )
                }),
            )
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                leak_detection_middleware,
            ))
            .with_state(state.clone());
        (app, state)
    }

    /// NuGet registration indexes keep `catalogEntry.@id` on the upstream's catalog0
    /// on purpose (no NORA handler, never fetched by restore): every proxied index
    /// fired NoraUpstreamUrlLeak. Only a pass-through path is exempt: a leftover
    /// registration URL on the same host is still a leak.
    #[test]
    fn nuget_catalog0_ids_are_not_a_leak() {
        let finders = LeakFinders::new(vec![("nuget".into(), "api.nuget.org".into())]);
        let index = r#"{"items":[{"items":[{"catalogEntry":{"@id":"https://api.nuget.org/v3/catalog0/data/2024.01.01/a.1.0.0.json","packageContent":"https://nora/nuget/v3/flatcontainer/a/1.0.0/a.1.0.0.nupkg"}}]}]}"#;
        assert_eq!(finders.scan(index.as_bytes()), None);
        let escaped = r#"{"@id":"https:\/\/api.nuget.org\/v3\/catalog0\/data\/a.json"}"#;
        assert_eq!(finders.scan(escaped.as_bytes()), None);
        let leftover = index.replace(
            "https://nora/nuget/v3/flatcontainer/a/1.0.0/a.1.0.0.nupkg",
            "https://api.nuget.org/v3/registration5-gz-semver2/a/index.json",
        );
        assert_eq!(
            finders.scan(leftover.as_bytes()),
            Some(("nuget", "api.nuget.org"))
        );
        // The exemption is NuGet's: another registry's finder on the same path flags it.
        let other = LeakFinders::new(vec![("npm".into(), "api.nuget.org".into())]);
        assert!(other.scan(index.as_bytes()).is_some());
    }

    /// Through the middleware: a leftover registration URL next to catalog0 @ids
    /// still counts as a NuGet leak.
    #[tokio::test]
    async fn nuget_leftover_registration_url_counts_as_leak() {
        use tower::ServiceExt;
        let (app, _state) = leak_test_app(
            "/nuget/v3/registration/a/index.json",
            "nuget",
            "api.nuget.org",
            r#"{"items":[{"catalogEntry":{"@id":"https://api.nuget.org/v3/catalog0/data/a.json"},"registration":"https://api.nuget.org/v3/registration5-gz-semver2/a/index.json"}]}"#,
        );
        let before = UPSTREAM_URL_LEAK_TOTAL.with_label_values(&["nuget"]).get();
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/nuget/v3/registration/a/index.json")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let after = UPSTREAM_URL_LEAK_TOTAL.with_label_values(&["nuget"]).get();
        assert!(after > before, "leak counter not incremented");
    }

    #[tokio::test]
    async fn own_surface_dashboard_json_is_not_flagged_as_leak() {
        use tower::ServiceExt;
        let (app, _state) = leak_test_app(
            "/api/ui/dashboard",
            "canary624a",
            "leak-canary-624a.invalid",
            r#"{"registries":[{"name":"cargo","upstream":"leak-canary-624a.invalid"}]}"#,
        );
        let leak_before = UPSTREAM_URL_LEAK_TOTAL
            .with_label_values(&["canary624a"])
            .get();
        let skip_before = LEAK_DETECTION_SKIPPED
            .with_label_values(&["own_surface"])
            .get();

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/ui/dashboard?lang=en")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let leak_after = UPSTREAM_URL_LEAK_TOTAL
            .with_label_values(&["canary624a"])
            .get();
        let skip_after = LEAK_DETECTION_SKIPPED
            .with_label_values(&["own_surface"])
            .get();
        assert_eq!(
            leak_before, leak_after,
            "dashboard echoing an upstream URL must NOT be counted as a leak"
        );
        assert!(
            skip_after > skip_before,
            "own-surface skip must be observable via LEAK_DETECTION_SKIPPED"
        );
    }

    #[tokio::test]
    async fn registry_proxy_json_with_upstream_url_is_still_flagged() {
        use tower::ServiceExt;
        let (app, _state) = leak_test_app(
            "/npm/leftpad",
            "canary624b",
            "leak-canary-624b.invalid",
            r#"{"dist":{"tarball":"https://leak-canary-624b.invalid/leftpad-1.0.0.tgz"}}"#,
        );
        let leak_before = UPSTREAM_URL_LEAK_TOTAL
            .with_label_values(&["canary624b"])
            .get();

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/npm/leftpad")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let leak_after = UPSTREAM_URL_LEAK_TOTAL
            .with_label_values(&["canary624b"])
            .get();
        assert_eq!(
            leak_after,
            leak_before + 1,
            "a registry proxy response leaking an upstream URL must be flagged"
        );
    }

    /// Metric name -> "counter" | "gauge" | "histogram", read off every
    /// `register_*!("nora_...")` in the crate source.
    fn registered_metrics() -> std::collections::HashMap<String, &'static str> {
        fn walk(dir: &std::path::Path, out: &mut std::collections::HashMap<String, &'static str>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, out);
                    continue;
                }
                if path.extension().is_none_or(|e| e != "rs") {
                    continue;
                }
                let src = std::fs::read_to_string(&path).unwrap();
                for (i, _) in src.match_indices("register_") {
                    let rest = &src[i..];
                    let Some(bang) = rest.find("!(") else {
                        continue;
                    };
                    let kind = &rest[..bang];
                    let kind = if kind.contains("histogram") {
                        "histogram"
                    } else if kind.contains("gauge") {
                        "gauge"
                    } else if kind.contains("counter") {
                        "counter"
                    } else {
                        continue;
                    };
                    let args = &rest[bang + 2..];
                    let Some(open) = args.find('"') else { continue };
                    let name = &args[open + 1..];
                    let name = &name[..name.find('"').unwrap()];
                    if name.starts_with("nora_") {
                        out.insert(name.to_string(), kind);
                    }
                }
            }
        }
        let mut out = std::collections::HashMap::new();
        walk(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut out,
        );
        out
    }

    fn repo_file(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join(name);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    /// `(start offset, name)` of every `nora_*` identifier in `text`.
    fn metric_tokens(text: &str) -> Vec<(usize, &str)> {
        let is_ident = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_';
        text.match_indices("nora_")
            .filter(|(i, _)| !text[..*i].ends_with(is_ident))
            .map(|(i, _)| {
                let end = text[i..]
                    .find(|c| !is_ident(c))
                    .map_or(text.len(), |n| i + n);
                (i, &text[i..end])
            })
            .collect()
    }

    /// The shipped alert rules, and our own in the chart's
    /// ci/maestra-values.yaml, only use metrics nora registers, with the right
    /// type: `rate`/`increase` over counters (or histogram series), `_bucket`
    /// only on histograms. The alerts match the table in MONITORING.md.
    #[test]
    fn prometheus_rules_use_registered_metrics() {
        let registered = registered_metrics();
        assert!(registered.len() > 20, "source scan found {registered:?}");
        for file in [
            "deploy/prometheus-rules.yml",
            "maestra/charts/nora/ci/maestra-values.yaml",
        ] {
            let rules = repo_file(file);
            let tokens = metric_tokens(&rules);
            assert!(!tokens.is_empty(), "{file}");
            for (at, name) in tokens {
                let series = ["_bucket", "_sum", "_count"]
                    .iter()
                    .find_map(|sfx| name.strip_suffix(sfx))
                    .filter(|base| registered.get(*base) == Some(&"histogram"));
                let kind = match (registered.get(name), series) {
                    (Some(kind), _) => *kind,
                    (None, Some(_)) => "counter", // histogram series are counters
                    (None, None) => panic!("{name} is not a registered metric"),
                };
                let before = rules[..at].trim_end();
                if before.ends_with("rate(") || before.ends_with("increase(") {
                    assert_eq!(kind, "counter", "{name} is a {kind}, not a counter");
                }
                if name.ends_with("_bucket") {
                    assert!(series.is_some(), "{name} is not a histogram series");
                }
            }
        }
        let rules = repo_file("deploy/prometheus-rules.yml");

        let alerts = |text: &str, marker: &str| -> Vec<String> {
            let mut v: Vec<String> = text
                .lines()
                .filter_map(|l| l.trim().strip_prefix(marker))
                .map(|l| {
                    l.trim()
                        .trim_matches(|c| c == '`' || c == '|' || c == ' ')
                        .split(['`', ' '])
                        .next()
                        .unwrap()
                        .to_string()
                })
                .collect();
            v.sort();
            v
        };
        let shipped = alerts(&rules, "- alert:");
        let documented = alerts(&repo_file("MONITORING.md"), "| `Nora");
        let documented: Vec<String> = documented.iter().map(|a| format!("Nora{a}")).collect();
        assert_eq!(
            shipped, documented,
            "deploy/prometheus-rules.yml vs MONITORING.md"
        );
    }

    /// MONITORING.md states each metric's type; it must be the registered one
    /// (`nora_artifacts_total` is a gauge, so `rate()` on it is meaningless).
    #[test]
    fn monitoring_doc_types_match_registered_metrics() {
        let registered = registered_metrics();
        let doc = repo_file("MONITORING.md");
        let mut rows = 0;
        for line in doc.lines() {
            let cells: Vec<&str> = line.split('|').map(str::trim).collect();
            let [_, name, kind, ..] = cells[..] else {
                continue;
            };
            let Some(name) = name
                .strip_prefix("`nora_")
                .and_then(|n| n.strip_suffix('`'))
            else {
                continue;
            };
            let name = format!("nora_{name}");
            let Some(actual) = registered.get(&name) else {
                panic!("MONITORING.md documents {name}, which is not registered");
            };
            assert_eq!(&kind, actual, "MONITORING.md types {name} as {kind}");
            rows += 1;
        }
        assert!(rows > 20, "parsed only {rows} metric rows");
    }
}
