// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Go module proxy (GOPROXY protocol).
//!
//! Implements the 5 required endpoints:
//!   GET /go/{module}/@v/list        — list known versions
//!   GET /go/{module}/@v/{ver}.info  — version metadata (JSON)
//!   GET /go/{module}/@v/{ver}.mod   — go.mod file
//!   GET /go/{module}/@v/{ver}.zip   — module zip archive
//!   GET /go/{module}/@latest        — latest version info

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::config::UpstreamAuth;
use crate::registry::{circuit_open_response, proxy_fetch, proxy_fetch_text, ProxyError};
use crate::registry_type::RegistryType;
use crate::secrets::expose_opt;
use crate::validation::ends_with_ci;
use crate::AppState;
use axum::body::Bytes;
use axum::{
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use percent_encoding::percent_decode;
use std::time::Duration;

pub fn routes() -> Router<AppState> {
    Router::new().route("/go/{*path}", get(handle_filtered))
}

/// Q04 for Go: under `curation.mode = "enforce"` with a release age, the `@v/list`, `@latest`
/// and revision-query (`@v/<branch>.info`) answers of a proxied module offer only versions the
/// `.zip` gate admits ([`go_version_hidden`]): `go install x@latest` resolved a version the
/// gate then refused with 403 for its first three days. `@latest` whose version is held moves
/// to the newest admitted listed version; with none, or a held revision query, the `.zip`
/// gate's own 403 (a 404 tells a `GOPROXY=…,direct` client to fetch it elsewhere, go.dev/ref/
/// mod#goproxy-protocol). Audit mode only logs. Internal
/// modules and a proxy-less (hosted) setup are never filtered.
async fn handle_filtered(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(path): Path<String>,
) -> Response {
    let resp = handle(State(state.clone()), headers.clone(), Path(path.clone())).await;
    let path = percent_decode(path.as_bytes())
        .decode_utf8()
        .map(|s| s.into_owned())
        .unwrap_or(path);
    let Some((module_encoded, file)) = split_go_path(&path) else {
        return resp;
    };
    let listing = file == "@v/list";
    let module_path =
        decode_module_path(&module_encoded).unwrap_or_else(|_| module_encoded.clone());
    let filtered = {
        let curation = state.curation();
        let engine = &curation.curation_engine;
        engine.metadata_filter_active()
            && !crate::curation::is_internal_namespace(engine, RegistryType::Go, &module_path)
    };
    if resp.status() != StatusCode::OK
        || !(listing || file == "@latest" || is_noncanonical_info_query(&file))
        || !filtered
        || state.config.go.proxy.is_none()
    {
        return resp;
    }
    let (mut parts, body) = resp.into_parts();
    // The body is a document NORA already holds in memory.
    let Ok(body) = axum::body::to_bytes(body, usize::MAX).await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if listing {
        let text = String::from_utf8_lossy(&body);
        let versions: Vec<&str> = text.lines().map(str::trim).collect();
        let hidden = go_hidden_versions(&state, &module_encoded, &module_path, &versions).await;
        if hidden.is_empty() {
            return Response::from_parts(parts, axum::body::Body::from(body));
        }
        let kept: String = versions
            .iter()
            .filter(|v| !v.is_empty() && !hidden.contains(**v))
            .map(|v| format!("{v}\n"))
            .collect();
        parts.headers.remove(header::CONTENT_LENGTH);
        return Response::from_parts(parts, axum::body::Body::from(kept));
    }
    let resolved = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|j| j.get("Version")?.as_str().map(String::from))
        .filter(|v| is_canonical_go_version(v));
    let Some(version) = resolved else {
        return Response::from_parts(parts, axum::body::Body::from(body));
    };
    if !go_version_hidden(&state, &module_encoded, &module_path, &version).await {
        return Response::from_parts(parts, axum::body::Body::from(body));
    }
    // A held revision query, or a held `@latest` with no admitted version, answers what the
    // `.zip` gate answers (403, not 404: on 404 a `GOPROXY=…,direct` client would fetch the
    // held version from elsewhere). The bypass header passes it as it passes the `.zip`.
    let held = || async {
        let judged = go_gate_date(&state, &module_encoded, &version).await;
        crate::curation::check_download(
            &state.curation().curation_engine,
            state.bypass_token().as_deref(),
            &headers,
            RegistryType::Go,
            &module_path,
            crate::curation::RequestVersion::of_artifact(Some(&version)),
            judged,
        )
    };
    if file != "@latest" {
        return match held().await {
            Some(refused) => refused,
            None => Response::from_parts(parts, axum::body::Body::from(body)),
        };
    }
    // `@latest`: the newest admitted listed version, release before pre-release, as the go
    // command itself picks from `@v/list`.
    let list = handle(
        State(state.clone()),
        headers.clone(),
        Path(format!("{module_encoded}/@v/list")),
    )
    .await;
    if list.status() != StatusCode::OK {
        return list;
    }
    let Ok(list) = axum::body::to_bytes(list.into_body(), usize::MAX).await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let text = String::from_utf8_lossy(&list);
    let versions: Vec<&str> = text.lines().map(str::trim).collect();
    let hidden = go_hidden_versions(&state, &module_encoded, &module_path, &versions).await;
    let best = versions
        .iter()
        .filter(|v| is_canonical_go_version(v) && !hidden.contains(**v))
        .max_by(|a, b| {
            (!a.contains('-'))
                .cmp(&!b.contains('-'))
                .then_with(|| go_semver_cmp(a, b))
        });
    let Some(best) = best else {
        return match held().await {
            Some(refused) => refused,
            None => Response::from_parts(parts, axum::body::Body::from(body)),
        };
    };
    let mut info = handle(
        State(state.clone()),
        headers.clone(),
        Path(format!("{module_encoded}/@v/{best}.info")),
    )
    .await;
    // The `.info` of a canonical version is immutable; `@latest` is not.
    info.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=60, must-revalidate"),
    );
    info
}

/// Whether the `.zip` gate would refuse `ver` for its release age: the same date
/// ([`go_publish_date`], [`go_judged_date`]) through
/// [`crate::curation::CurationEngine::hides_from_metadata`] (`allow` entries and audit mode
/// included). Like the gate it may cache the version's `.info` and attested date.
async fn go_version_hidden(
    state: &AppState,
    module_encoded: &str,
    module_path: &str,
    ver: &str,
) -> bool {
    let judged = go_gate_date(state, module_encoded, ver).await;
    state
        .curation()
        .curation_engine
        .hides_from_metadata(RegistryType::Go, module_path, ver, judged)
}

/// The date the `.zip` gate judges `ver` by.
async fn go_gate_date(state: &AppState, module_encoded: &str, ver: &str) -> Option<i64> {
    let date = go_publish_date(state, module_encoded, ver, true).await;
    go_judged_date(state, date, &format!("go/{module_encoded}/@v/{ver}.zip")).await
}

/// The listed versions to leave out of `@v/list`. Versions are grouped by major.minor and
/// release vs pre-release, and each group is dated from its newest version down to the first
/// one admitted: the go command picks the newest of a group (`latest`, `v1.2`, `upgrade`,
/// `patch`), so every group's newest offered version is one the gate admits.
// ponytail: a held version below an admitted one in its group stays listed (reachable only by
// `<`/`<=` queries); dating every listed version costs one `.info` + HEAD per version on a
// module's first listing (k8s.io/client-go: ~700). Date them all if such queries matter.
async fn go_hidden_versions(
    state: &AppState,
    module_encoded: &str,
    module_path: &str,
    versions: &[&str],
) -> std::collections::HashSet<String> {
    use futures::StreamExt;
    let mut groups: std::collections::BTreeMap<(u64, u64, bool), Vec<String>> = Default::default();
    for v in versions
        .iter()
        .copied()
        .filter(|v| is_canonical_go_version(v))
    {
        let (core, _) = go_semver_parts(v);
        groups
            .entry((core[0], core[1], v.contains('-')))
            .or_default()
            .push(v.to_string());
    }
    futures::stream::iter(groups.into_values())
        .map(|mut group| async move {
            group.sort_by(|a, b| go_semver_cmp(b, a));
            let mut hidden = Vec::new();
            for v in group {
                if !go_version_hidden(state, module_encoded, module_path, &v).await {
                    break;
                }
                hidden.push(v);
            }
            hidden
        })
        .buffer_unordered(8)
        .flat_map(futures::stream::iter)
        .collect()
        .await
}

/// A canonical Go version's `[major, minor, patch]` and pre-release (build metadata dropped).
fn go_semver_parts(v: &str) -> ([u64; 3], Option<&str>) {
    let v = v.trim_start_matches('v');
    let v = v.split('+').next().unwrap_or(v);
    let (core, pre) = match v.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (v, None),
    };
    let mut n = core.split('.').map(|s| s.parse().unwrap_or(0));
    let mut next = || n.next().unwrap_or(0);
    ([next(), next(), next()], pre)
}

/// Semantic version order of two canonical Go versions (golang.org/x/mod/semver `Compare`).
fn go_semver_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering::{Equal, Greater, Less};
    let ((ca, pa), (cb, pb)) = (go_semver_parts(a), go_semver_parts(b));
    ca.cmp(&cb).then_with(|| match (pa, pb) {
        (None, None) => Equal,
        (None, Some(_)) => Greater,
        (Some(_), None) => Less,
        (Some(pa), Some(pb)) => {
            let (mut xs, mut ys) = (pa.split('.'), pb.split('.'));
            loop {
                let (x, y) = match (xs.next(), ys.next()) {
                    (None, None) => return Equal,
                    (None, Some(_)) => return Less,
                    (Some(_), None) => return Greater,
                    (Some(x), Some(y)) => (x, y),
                };
                let order = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(x), Ok(y)) => x.cmp(&y),
                    (Ok(_), Err(_)) => Less,
                    (Err(_), Ok(_)) => Greater,
                    _ => x.cmp(y),
                };
                if order != Equal {
                    return order;
                }
            }
        }
    })
}

/// Main handler — parses the wildcard path and dispatches to the right logic.
async fn handle(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(path): Path<String>,
) -> Response {
    // URL-decode the path: Go client sends %21 for !, Axum wildcard may not decode it
    let path = percent_decode(path.as_bytes())
        .decode_utf8()
        .map(|s| s.into_owned())
        .unwrap_or(path);

    tracing::debug!(path = %path, "Go proxy request");

    // Validate path: no traversal, no null bytes
    if !is_safe_path(&path) {
        tracing::debug!(path = %path, "Go proxy: unsafe path");
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Split: "github.com/!azure/sdk/@v/v1.0.0.info" → module + file
    let (module_encoded, file) = match split_go_path(&path) {
        Some(parts) => parts,
        None => {
            tracing::debug!(path = %path, "Go proxy: cannot split path");
            return StatusCode::NOT_FOUND.into_response();
        }
    };

    // The module path as written in go.mod (`!a` decoded to `A`): curation and the internal
    // namespaces match this one spelling, on every branch below.
    let module_path =
        decode_module_path(&module_encoded).unwrap_or_else(|_| module_encoded.clone());

    // Parse curation coords for .zip downloads (used in both pre-download and integrity checks)
    let go_curation = if ends_with_ci(&file, ".zip") {
        let module_name = module_path.clone();
        // `ends_with_ci` above: the extension in any case (`.ZIP` too).
        let version = file
            .strip_prefix("@v/")
            .and_then(|f| f.get(..f.len().checked_sub(4)?))
            .map(|v| v.to_string());
        Some((module_name, version))
    } else {
        None
    };

    let storage_key = format!("go/{}", path);

    // Hoisted to function scope so the digest-quarantine serve gate can seed
    // first_seen from a trusted upstream release date (#750).
    let mut publish_date: Option<i64> = None;
    // Curation check — .zip downloads only (metadata passes through)
    if let Some((ref module_name, ref version)) = go_curation {
        // #733: an internal-namespace module is operator-owned — skip curation; the namespace
        // guard below (after the cache serve) serves any local copy and blocks the upstream branch.
        let internal = crate::curation::is_internal_namespace(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Go,
            module_name,
        );
        publish_date = match version {
            Some(ver) => go_publish_date(&state, &module_encoded, ver, !internal).await,
            None => None,
        };

        if !internal {
            let judged = go_judged_date(&state, publish_date, &storage_key).await;
            if let Some(response) = crate::curation::check_download(
                &state.curation().curation_engine,
                state.bypass_token().as_deref(),
                &headers,
                crate::curation::RegistryType::Go,
                module_name,
                crate::curation::RequestVersion::of_artifact(version.as_deref()),
                judged,
            ) {
                return response;
            }
        }
    }

    let content_type = content_type_for(&file);

    // Mutable endpoints: @v/list, @latest, and a non-canonical `@v/<query>.info` (a branch,
    // revision, or partial version like `v1`/`v1.2`) all resolve to a moving target and may be
    // refreshed from upstream. A canonical-version .info/.mod/.zip names an immutable snapshot.
    let is_mutable = file == "@v/list" || file == "@latest" || is_noncanonical_info_query(&file);
    // Immutable: once cached, never overwrite.
    let is_immutable = !is_mutable;

    // 1. Try local cache.
    //    Immutable files (.info/.mod/.zip) are content-addressed by an exact version and are
    //    authoritative once cached. The mutable listing endpoints (@v/list, @latest) must be
    //    revalidated against upstream before serving — otherwise a newly published version never
    //    appears — unless there is no upstream (locally authoritative) or the cached copy is still
    //    within the positive `metadata_ttl` window. `cached` is kept for the stale-on-error path.
    let (cached, read_failure) =
        crate::registry::cached_read(state.storage.get(&storage_key).await);
    let modified = if cached.is_some() && is_mutable {
        state.storage.stat(&storage_key).await.map(|m| m.modified)
    } else {
        None
    };
    let cache_fresh = cached.is_some()
        && go_cache_fresh(
            is_immutable,
            state.config.go.proxy.is_some(),
            state.config.go.metadata_ttl,
            modified,
        );
    if let Some(ref data) = cached {
        if cache_fresh {
            // Curation integrity verification (issue #189)
            if let Some((ref module_name, ref version)) = go_curation {
                if let Some(response) = crate::curation::verify_integrity(
                    &state.curation().curation_engine,
                    crate::curation::RegistryType::Go,
                    module_name,
                    version.as_deref(),
                    data,
                ) {
                    return response;
                }
            }

            state.metrics.record_download("go");
            state.metrics.record_cache_hit("go");
            state.activity.push(ActivityEntry::new(
                ActionType::CacheHit,
                format_artifact(&module_encoded, &file),
                crate::registry_type::RegistryType::Go,
                "CACHE",
            ));
            // Quarantine only the .zip module archive (the artifact). The
            // .info/.mod/@v/list/@latest endpoints serve metadata — never gate them.
            if ends_with_ci(&file, ".zip") {
                let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
                    state.config.curation.go.quarantine.as_ref().or(state
                        .config
                        .curation
                        .quarantine
                        .as_ref()),
                    state.config.curation.go.quarantine_ttl.as_deref().or(state
                        .config
                        .curation
                        .quarantine_ttl
                        .as_deref()),
                );
                // A digest with no record counts from when its copy was cached (R4-C05).
                if let Some(resp) = crate::digest_quarantine::cache_gate_dated(
                    &state.digest_store,
                    &state.storage,
                    &storage_key,
                    "go",
                    data,
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

                // Resume support: 206 for a `Range` request, 416 when the client asks
                // past the end. Only the .zip archive — the metadata endpoints are not
                // resumable payloads. It sits after the gates above because the
                // quarantine digest check needs the whole object. A partial body cannot
                // be rehashed, so the serve relies on the go.sum hash the client checks
                // itself (docker did the same in #657). An absent/malformed range falls
                // through to the full 200.
                if let Some(response) = crate::registry::range::range_response_from_bytes(
                    data,
                    &headers,
                    content_type,
                    &[(
                        header::CACHE_CONTROL,
                        "public, max-age=31536000, immutable".to_string(),
                    )],
                ) {
                    return response;
                }

                let mut response = with_content_type(data.to_vec(), content_type, is_mutable);
                response
                    .headers_mut()
                    .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
                return response;
            }
            return with_content_type(data.to_vec(), content_type, is_mutable);
        }
    }

    // 2. Try upstream proxy
    // An internal-namespace module whose copy the store could not read is unavailable, not
    // absent — with or without an upstream.
    if let Some(e) = &read_failure {
        if crate::curation::is_internal_namespace(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Go,
            &module_path,
        ) {
            return crate::registry::local_copy_unreadable("go", &storage_key, e);
        }
    }

    let proxy_url = match &state.config.go.proxy {
        Some(url) => url.clone(),
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    // Validate module path encoding (but keep encoded for upstream — proxy.golang.org expects ! encoding)
    if decode_module_path(&module_encoded).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // #68 namespace isolation: an internal-namespace module must never be fetched
    // upstream (dependency confusion). The fresh-cache fast path above already served
    // a fresh copy; here, serve any stale cached copy rather than re-proxying, and
    // block only when nothing is cached — never proxy. (The .zip artifact path also
    // runs check_download.)
    if crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Go,
        &module_path,
    ) {
        if let Some(ref data) = cached {
            state.metrics.record_cache_hit("go");
            return with_content_type(data.to_vec(), content_type, is_mutable);
        }
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Go,
            &module_path,
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
    }

    let upstream_url = format!(
        "{}/{}",
        proxy_url.trim_end_matches('/'),
        format_upstream_path(&module_encoded, &file)
    );

    // Use longer timeout for .zip files
    let timeout = Duration::from_secs(if ends_with_ci(&file, ".zip") {
        state.config.go.proxy_timeout_zip
    } else {
        state.config.go.proxy_timeout
    });

    // Fetch: binary for .zip, text for everything else
    let data = if ends_with_ci(&file, ".zip") {
        proxy_fetch(
            &state.http_client,
            &upstream_url,
            timeout,
            expose_opt(&state.config.go.proxy_auth).map(UpstreamAuth::Basic),
            &state.circuit_breaker,
            RegistryType::Go,
        )
        .await
    } else {
        proxy_fetch_text(
            &state.http_client,
            &upstream_url,
            timeout,
            expose_opt(&state.config.go.proxy_auth).map(UpstreamAuth::Basic),
            None,
            &state.circuit_breaker,
            RegistryType::Go,
        )
        .await
        .map(|s| s.into_bytes())
    };

    match data {
        Ok(bytes) => {
            // Enforce size limit for .zip
            if ends_with_ci(&file, ".zip") && bytes.len() as u64 > state.config.go.max_zip_size {
                tracing::warn!(
                    module = module_encoded,
                    size = bytes.len(),
                    limit = state.config.go.max_zip_size,
                    "Go module zip exceeds size limit"
                );
                return StatusCode::PAYLOAD_TOO_LARGE.into_response();
            }

            // The allowlist's pinned integrity holds on the first download too, before anything
            // is cached: the cache-hit branch checks the same rule.
            if let Some((ref module_name, ref version)) = go_curation {
                if let Some(response) = crate::curation::verify_integrity(
                    &state.curation().curation_engine,
                    crate::curation::RegistryType::Go,
                    module_name,
                    version.as_deref(),
                    &bytes,
                ) {
                    return response;
                }
            }

            state.metrics.record_download("go");
            state.metrics.record_cache_miss("go");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                format_artifact(&module_encoded, &file),
                crate::registry_type::RegistryType::Go,
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "proxy", "", "go", ""));

            // Background cache: immutable = put_if_absent, mutable = always overwrite
            if is_immutable {
                state.spawn_cache_immutable("go", storage_key, Bytes::from(bytes.clone()));
            } else {
                state.spawn_cache("go", storage_key, Bytes::from(bytes.clone()));
            }

            // Quarantine only the .zip module archive; metadata endpoints pass through.
            if ends_with_ci(&file, ".zip") {
                let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
                    state.config.curation.go.quarantine.as_ref().or(state
                        .config
                        .curation
                        .quarantine
                        .as_ref()),
                    state.config.curation.go.quarantine_ttl.as_deref().or(state
                        .config
                        .curation
                        .quarantine_ttl
                        .as_deref()),
                );
                if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
                    &state.digest_store,
                    "go",
                    &bytes,
                    &q_mode,
                    q_secs,
                    &upstream_url,
                    crate::digest_quarantine::first_seen_seed(
                        state.config.server.trust_upstream_dates,
                        publish_date,
                    ),
                )
                .await
                {
                    return resp;
                }
            }
            with_content_type(bytes, content_type, is_mutable)
        }
        Err(e) => {
            // Upstream unreachable — serve the stale cached copy if we have one (graceful).
            // Only the mutable listing endpoints reach here with a cached copy; immutable hits
            // returned above, so this never serves a wrong content-addressed file.
            if let Some(ref data) = cached {
                tracing::warn!(
                    module = module_encoded,
                    file = file,
                    "Go upstream failed, serving stale cached copy"
                );
                let mut response = with_content_type(data.to_vec(), content_type, is_mutable);
                response.headers_mut().insert(
                    axum::http::header::HeaderName::from_static("x-nora-stale"),
                    axum::http::header::HeaderValue::from_static("true"),
                );
                return response;
            }
            match e {
                ProxyError::NotFound => StatusCode::NOT_FOUND.into_response(),
                ProxyError::CircuitOpen(reg) => circuit_open_response(&reg),
                _ => {
                    tracing::debug!(
                        module = module_encoded,
                        file = file,
                        error = ?e,
                        "Go upstream proxy error"
                    );
                    StatusCode::BAD_GATEWAY.into_response()
                }
            }
        }
    }
}

// ============================================================================
// Module path encoding/decoding
// ============================================================================

/// The publisher's `.info` `Time` of a cached version, and NORA's first sight of it.
///
/// Go .info JSON has a `Time` field in RFC 3339 format:
/// ```json
/// { "Version": "v1.0.0", "Time": "2024-01-15T10:30:00Z" }
/// ```
///
/// `Time` is the publisher's commit date, which the publisher sets: it bounds the release
/// from below only. A canonical .info is cached once (`put_if_absent`) and never rewritten,
/// so its write time is NORA's first sight of the version (now when it cannot be read).
async fn go_info_dates(storage: &crate::storage::Storage, info_key: &str) -> Option<(i64, i64)> {
    let data = storage.get(info_key).await.ok()?;
    let json: serde_json::Value = serde_json::from_slice(&data).ok()?;
    let time = crate::curation::parse_iso8601_to_unix(json.get("Time")?.as_str()?)?;
    let first_seen = crate::curation::extract_mtime_as_publish_date(storage, info_key)
        .await
        .unwrap_or_else(|| crate::cache_ttl::now_unix() as i64);
    Some((time, first_seen))
}

/// A version's release date from its `.info`: the later of `Time` and NORA's first sight
/// (A066). With `fetch` (a proxied module) and a release age to judge, an `.info` NORA has
/// none of is fetched first: a `.zip` asked for first, or cached without its `.info`, is
/// dated too. With `[go] attested_dates` on proxy.golang.org, a first sight still inside the
/// release age gives way to the proxy's own first fetch when that is earlier
/// ([`go_attested_date`]): the date is then `max(Time, min(attested, first sight))`, never
/// earlier than `Time` nor later than what A066 alone would judge. #513: untrusted upstream
/// dates give no date: never upstream .info Time, nor the cache mtime.
async fn go_publish_date(
    state: &AppState,
    module_encoded: &str,
    ver: &str,
    fetch: bool,
) -> Option<i64> {
    if !state.config.server.trust_upstream_dates {
        return None;
    }
    let file = format!("@v/{ver}.info");
    let info_key = format!("go/{module_encoded}/{file}");
    let curation = state.curation();
    let engine = &curation.curation_engine;
    let aged = fetch && engine.reads_release_date(RegistryType::Go);
    if aged {
        ensure_go_info_cached(state, module_encoded, &file, &info_key).await;
    }
    let (time, mut seen) = go_info_dates(&state.storage, &info_key).await?;
    let held = engine
        .min_release_age_secs(RegistryType::Go)
        .is_some_and(|age| crate::cache_ttl::now_unix() as i64 - seen < age);
    if aged && held && go_attests(state) {
        if let Some(at) = go_attested_date(state, module_encoded, ver).await {
            seen = seen.min(at);
        }
    }
    Some(time.max(seen))
}

/// `[go] attested_dates` is on and `go.proxy` is one whose zip `Last-Modified` is its own
/// first fetch ([`crate::config::GoConfig::attests_first_fetch`]); elsewhere it is ignored.
fn go_attests(state: &AppState) -> bool {
    state.config.go.attested_dates
        && state
            .config
            .go
            .proxy
            .as_deref()
            .is_some_and(crate::config::GoConfig::attests_first_fetch)
}

/// `go/{module}/@nora-dates/{version}`: the attested date of a version, Unix seconds. Never
/// served nor written by a GOPROXY request: `split_go_path` takes the last `/@v/` and wants a
/// single segment after it (so a key ending in `@nora-dates/<version>` is no `@v/` file), and
/// a path holding `/@latest` is the `@latest` endpoint.
fn attested_key(module_encoded: &str, ver: &str) -> String {
    format!("go/{module_encoded}/@nora-dates/{ver}")
}

/// proxy.golang.org opened on 2019-04-10: a `Last-Modified` before it is no first fetch of
/// that proxy (an epoch placeholder, say) and is not taken.
const GO_PROXY_EPOCH: i64 = 1_554_854_400;

/// The `Last-Modified` of the version's `.zip` on proxy.golang.org: the proxy's first fetch
/// of the version (the index.golang.org `Timestamp`), which no publisher sets. Kept at
/// [`attested_key`] once known (a kept value that does not parse or is out of range is
/// replaced); a lookup goes
/// through [`super::upstream_dates::dates`], so concurrent requests share one HEAD and a miss
/// (404, no or unusable `Last-Modified`, 5xx, timeout, open breaker) is asked again at most
/// once a minute. The HEAD is reported to the proxy's `#dates` breaker, never the download one.
async fn go_attested_date(state: &AppState, module_encoded: &str, ver: &str) -> Option<i64> {
    let key = attested_key(module_encoded, ver);
    let kept = state.storage.get(&key).await.ok();
    if let Some(at) = kept
        .as_deref()
        .and_then(|d| std::str::from_utf8(d).ok())
        .and_then(|t| t.trim().parse::<i64>().ok())
        .filter(|at| go_attested_in_range(*at))
    {
        return Some(at);
    }
    let proxy = state.config.go.proxy.clone()?;
    let url = format!(
        "{}/{}",
        proxy.trim_end_matches('/'),
        format_upstream_path(module_encoded, &format!("@v/{ver}.zip"))
    );
    // A good answer is kept in storage; the memo only joins concurrent requests and paces
    // misses, so it holds one a minute (Go's 1024 memo keys, one per version here).
    let ttl = Duration::from_secs(60);
    let fetching = state.clone();
    let memo_key = url.clone();
    let version = ver.to_owned();
    let at = super::upstream_dates::dates(
        state,
        RegistryType::Go,
        &memo_key,
        ttl,
        &[],
        move || async move {
            match go_zip_last_modified(&fetching, &proxy, &url).await {
                Ok(at) => Some(std::collections::HashMap::from([(version, at)])),
                Err(miss) => {
                    tracing::info!(url, miss, "Go attested release date unavailable");
                    None
                }
            }
        },
    )
    .await
    .dates?
    .get(ver)
    .copied()?;
    let bytes = Bytes::from(at.to_string().into_bytes());
    let _ = if kept.is_some() {
        state.storage.put(&key, &bytes).await
    } else {
        state.storage.put_if_absent(&key, bytes).await.map(|_| ())
    };
    Some(at)
}

/// HEAD `url` and parse its `Last-Modified`; the error names the miss for the log.
async fn go_zip_last_modified(
    state: &AppState,
    proxy: &str,
    url: &str,
) -> Result<i64, &'static str> {
    let mut request = state
        .http_client
        .head(url)
        .timeout(Duration::from_secs(state.config.go.proxy_timeout));
    if let Some(credentials) = expose_opt(&state.config.go.proxy_auth) {
        let value = UpstreamAuth::Basic(credentials)
            .header_value()
            .map_err(|_| "transport")?;
        request = request.header(header::AUTHORIZATION, value);
    }
    let cb = &state.circuit_breaker;
    let key = super::upstream_dates::breaker_key(RegistryType::Go, proxy);
    let probe = cb.check(&key).map_err(|_| {
        super::upstream_dates::count(RegistryType::Go, "breaker_open");
        "breaker_open"
    })?;
    let resp = match request.send().await {
        Ok(resp) => resp,
        Err(e) => {
            cb.record_failure(&key, probe);
            return Err(if e.is_timeout() {
                "timeout"
            } else {
                "transport"
            });
        }
    };
    let status = resp.status();
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        cb.record_failure(&key, probe);
    } else if status.is_success() {
        cb.record_success(&key, probe);
    } else {
        // Answered: alive, but no proof a failure tally is over (as `proxy_fetch`).
        cb.record_alive(&key, probe);
    }
    if !status.is_success() {
        return Err("status");
    }
    let lm = resp
        .headers()
        .get(header::LAST_MODIFIED)
        .ok_or("missing")?
        .to_str()
        .map_err(|_| "parse")?;
    let at = chrono::DateTime::parse_from_rfc2822(lm)
        .map(|at| at.timestamp())
        .map_err(|_| "parse")?;
    if !go_attested_in_range(at) {
        return Err("out_of_range");
    }
    Ok(at)
}

/// An attested date NORA takes, from the HEAD or from storage alike: not before
/// proxy.golang.org opened, and not past now (plus a minute of clock skew). Anything else is
/// no first fetch of that proxy: taken, it would let the publisher's `Time` decide (A066).
fn go_attested_in_range(at: i64) -> bool {
    (GO_PROXY_EPOCH..=crate::cache_ttl::now_unix() as i64 + 60).contains(&at)
}

/// The date min-release-age judges a `.zip` by: `date`, else the write time of NORA's copy
/// of the zip (NORA's clock, never earlier than the release), then what
/// `[curation.go] unknown_date` makes of a date still unknown. Not the quarantine's seed:
/// a cached copy's age is the quarantine's own business (R4-C05).
async fn go_judged_date(state: &AppState, date: Option<i64>, zip_key: &str) -> Option<i64> {
    let trust = state.config.server.trust_upstream_dates;
    let curation = state.curation();
    let engine = &curation.curation_engine;
    let date = match date {
        None if trust && engine.reads_release_date(RegistryType::Go) => {
            crate::curation::extract_mtime_as_publish_date(&state.storage, zip_key).await
        }
        date => date,
    };
    engine.judged_release_date(RegistryType::Go, trust, date)
}

/// Store the upstream `.info` (`file`) at `info_key` when NORA has none, synchronously, so the
/// release date is readable on this request (cargo's `ensure_cargo_metadata_cached`).
/// Best-effort: a failed fetch leaves it absent. The caller keeps internal modules out.
async fn ensure_go_info_cached(state: &AppState, module_encoded: &str, file: &str, info_key: &str) {
    if state.storage.get(info_key).await.is_ok() {
        return;
    }
    let Some(proxy_url) = &state.config.go.proxy else {
        return;
    };
    let url = format!(
        "{}/{}",
        proxy_url.trim_end_matches('/'),
        format_upstream_path(module_encoded, file)
    );
    if let Ok(text) = proxy_fetch_text(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.go.proxy_timeout),
        expose_opt(&state.config.go.proxy_auth).map(UpstreamAuth::Basic),
        None,
        &state.circuit_breaker,
        RegistryType::Go,
    )
    .await
    {
        let _ = state
            .storage
            .put_if_absent(info_key, Bytes::from(text.into_bytes()))
            .await;
    }
}

/// Decode Go module path: `!x` → `X`
///
/// Go module proxy spec requires uppercase letters to be encoded as `!`
/// followed by the lowercase letter. Raw uppercase in encoded path is invalid.
fn decode_module_path(encoded: &str) -> Result<String, ()> {
    let mut result = String::with_capacity(encoded.len());
    let mut chars = encoded.chars();
    while let Some(c) = chars.next() {
        if c == '!' {
            match chars.next() {
                Some(next) if next.is_ascii_lowercase() => {
                    result.push(next.to_ascii_uppercase());
                }
                _ => return Err(()),
            }
        } else if c.is_ascii_uppercase() {
            // Raw uppercase in encoded path is invalid per spec
            return Err(());
        } else {
            result.push(c);
        }
    }
    Ok(result)
}

/// Encode Go module path: `X` → `!x`
#[cfg(test)]
fn encode_module_path(path: &str) -> String {
    let mut result = String::with_capacity(path.len() + 8);
    for c in path.chars() {
        if c.is_ascii_uppercase() {
            result.push('!');
            result.push(c.to_ascii_lowercase());
        } else {
            result.push(c);
        }
    }
    result
}

// ============================================================================
// Path parsing helpers
// ============================================================================

/// Split Go path into (encoded_module, file).
///
/// Examples:
///   "github.com/user/repo/@v/v1.0.0.info" → ("github.com/user/repo", "@v/v1.0.0.info")
///   "github.com/user/repo/v2/@v/list"     → ("github.com/user/repo/v2", "@v/list")
///   "github.com/user/repo/@latest"        → ("github.com/user/repo", "@latest")
fn split_go_path(path: &str) -> Option<(String, String)> {
    // Try @latest first (it's simpler)
    if let Some(pos) = path.rfind("/@latest") {
        let module = &path[..pos];
        if !module.is_empty() {
            return Some((module.to_string(), "@latest".to_string()));
        }
    }

    // Try @v/ — find the last occurrence (handles /v2/@v/ correctly). What follows `@v/` is
    // one file (`list`, `<version>.info|.mod|.zip`): a `/` in it (a `%2F` in the version)
    // would hand curation another version than the one the upstream path names.
    if let Some(pos) = path.rfind("/@v/") {
        let module = &path[..pos];
        let file = &path[pos + 1..]; // "@v/..."
        let one_file = crate::validation::is_one_segment(&file["@v/".len()..]);
        if !module.is_empty() && one_file {
            return Some((module.to_string(), file.to_string()));
        }
    }

    None
}

/// Path validation: a Go proxy path is a valid storage key — no traversal, no null byte, and
/// no empty segment anywhere: `a//b` and a trailing `/` (no Go proxy path ends in one) would
/// name another module's file, and `x.zip/` is no longer a `.zip` to curation. Nor a byte the
/// upstream URL parser reads differently (control, space, `#`, `?`): curation judges this
/// string, and the upstream must be asked for the same one.
fn is_safe_path(path: &str) -> bool {
    crate::validation::is_url_path_stable(path)
        && crate::validation::validate_storage_key(path).is_ok()
}

/// Content-Type for Go proxy responses
fn content_type_for(file: &str) -> &'static str {
    if ends_with_ci(file, ".info") || file == "@latest" {
        "application/json"
    } else if ends_with_ci(file, ".zip") {
        "application/zip"
    } else {
        // .mod, @v/list
        "text/plain; charset=utf-8"
    }
}

/// Build upstream URL path (uses decoded module path)
fn format_upstream_path(module_decoded: &str, file: &str) -> String {
    format!("{}/{}", module_decoded, file)
}

/// Human-readable artifact name for activity log
fn format_artifact(module: &str, file: &str) -> String {
    if file == "@v/list" || file == "@latest" {
        format!("{} {}", module, file)
    } else if let Some(version_file) = file.strip_prefix("@v/") {
        // "v1.0.0.info" → "module@v1.0.0"
        let version = version_file
            .rsplit_once('.')
            .map(|(v, _ext)| v)
            .unwrap_or(version_file);
        format!("{}@{}", module, version)
    } else {
        format!("{}/{}", module, file)
    }
}

/// Whether a Go version string is a canonical semantic version — one that names an immutable
/// snapshot.
///
/// Canonical = `vMAJOR.MINOR.PATCH` (all three present, each a digit run with no leading zeros)
/// with an optional `-prerelease` and/or `+build` suffix. This admits pseudo-versions
/// (`v0.0.0-20210101000000-abcdef123456`) and `+incompatible`. It rejects branch names
/// (`master`), revisions (`abcdef`), partial queries (`v1`, `v1.2`), and operators (`latest`),
/// all of which resolve to a moving target. When in doubt this returns `false` (treat as mutable
/// → revalidate), which is the fail-safe for freshness.
fn is_canonical_go_version(v: &str) -> bool {
    let Some(rest) = v.strip_prefix('v') else {
        return false;
    };
    // Peel off the optional `+build` then the optional `-prerelease`; the remainder is the core.
    let core_pre = rest.split('+').next().unwrap_or(rest);
    let core = core_pre.split('-').next().unwrap_or(core_pre);
    // The suffix (everything after the core) must be non-empty if a separator was present.
    if core.len() != core_pre.len() && core_pre[core.len()..].len() < 2 {
        return false; // a bare trailing `-` or empty prerelease
    }
    if core_pre.len() != rest.len() && rest[core_pre.len()..].len() < 2 {
        return false; // a bare trailing `+` or empty build
    }
    // Core must be exactly MAJOR.MINOR.PATCH, each a digit run with no leading zeros.
    let mut segments = core.split('.');
    let (Some(major), Some(minor), Some(patch), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return false;
    };
    [major, minor, patch].iter().all(|s| is_numeric_id(s))
}

/// A numeric identifier: a non-empty run of ASCII digits with no leading zero (except `"0"`).
fn is_numeric_id(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s.len() == 1 || s.as_bytes()[0] != b'0')
}

/// Whether `file` is a `@v/<version>.info` request whose version is NON-canonical — a branch,
/// revision, or partial query that resolves to a moving target and so must be revalidated, unlike
/// a canonical-version `.info` (or any `.mod`/`.zip`) which names an immutable snapshot.
fn is_noncanonical_info_query(file: &str) -> bool {
    file.strip_prefix("@v/")
        .and_then(|rest| rest.strip_suffix(".info"))
        .is_some_and(|ver| !is_canonical_go_version(ver))
}

/// Whether a cached Go proxy response may be served without revalidating against upstream.
///
/// Immutable per-version files (`.info`/`.mod`/`.zip`) are content-addressed by an exact version
/// and are authoritative once cached. The mutable listing endpoints (`@v/list`, `@latest`) defer
/// to [`crate::cache_ttl::mutable_ref_fresh`]: a hosted registry (no upstream) is locally
/// authoritative, a positive `metadata_ttl` allows a bounded staleness window, and otherwise the
/// listing is revalidated against upstream so a newly published version appears.
fn go_cache_fresh(
    is_immutable: bool,
    has_upstream: bool,
    metadata_ttl: i64,
    modified: Option<u64>,
) -> bool {
    is_immutable || crate::cache_ttl::mutable_ref_fresh(has_upstream, metadata_ttl, modified)
}

/// Build response with Content-Type and Cache-Control headers.
/// `is_mutable` controls caching: mutable endpoints (@v/list, @latest) get short TTL,
/// immutable content (.zip, .mod, .info) gets long TTL.
fn with_content_type(data: Vec<u8>, content_type: &'static str, is_mutable: bool) -> Response {
    let cache_control = if is_mutable {
        "public, max-age=60, must-revalidate"
    } else {
        "public, max-age=31536000, immutable"
    };

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static(cache_control),
            ),
        ],
        data,
    )
        .into_response()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ── Encoding/decoding ───────────────────────────────────────────────

    #[test]
    fn test_decode_azure() {
        assert_eq!(
            decode_module_path("github.com/!azure/sdk").unwrap(),
            "github.com/Azure/sdk"
        );
    }

    #[test]
    fn test_decode_multiple_uppercase() {
        assert_eq!(
            decode_module_path("!google!cloud!platform/foo").unwrap(),
            "GoogleCloudPlatform/foo"
        );
    }

    #[test]
    fn test_decode_no_uppercase() {
        assert_eq!(
            decode_module_path("github.com/user/repo").unwrap(),
            "github.com/user/repo"
        );
    }

    #[test]
    fn test_decode_invalid_bang_at_end() {
        assert!(decode_module_path("foo!").is_err());
    }

    #[test]
    fn test_decode_invalid_bang_followed_by_uppercase() {
        assert!(decode_module_path("foo!A").is_err());
    }

    #[test]
    fn test_decode_raw_uppercase_is_invalid() {
        assert!(decode_module_path("github.com/Azure/sdk").is_err());
    }

    #[test]
    fn test_encode_roundtrip() {
        let original = "github.com/Azure/azure-sdk-for-go";
        let encoded = encode_module_path(original);
        assert_eq!(encoded, "github.com/!azure/azure-sdk-for-go");
        assert_eq!(decode_module_path(&encoded).unwrap(), original);
    }

    #[test]
    fn test_encode_no_change() {
        assert_eq!(
            encode_module_path("github.com/user/repo"),
            "github.com/user/repo"
        );
    }

    // ── Path splitting ──────────────────────────────────────────────────

    #[test]
    fn test_split_version_info() {
        let (module, file) = split_go_path("github.com/user/repo/@v/v1.0.0.info").unwrap();
        assert_eq!(module, "github.com/user/repo");
        assert_eq!(file, "@v/v1.0.0.info");
    }

    #[test]
    fn test_split_version_list() {
        let (module, file) = split_go_path("github.com/user/repo/@v/list").unwrap();
        assert_eq!(module, "github.com/user/repo");
        assert_eq!(file, "@v/list");
    }

    #[test]
    fn test_split_latest() {
        let (module, file) = split_go_path("github.com/user/repo/@latest").unwrap();
        assert_eq!(module, "github.com/user/repo");
        assert_eq!(file, "@latest");
    }

    #[test]
    fn test_split_major_version_suffix() {
        let (module, file) = split_go_path("github.com/user/repo/v2/@v/list").unwrap();
        assert_eq!(module, "github.com/user/repo/v2");
        assert_eq!(file, "@v/list");
    }

    #[test]
    fn test_split_incompatible_version() {
        let (module, file) =
            split_go_path("github.com/user/repo/@v/v4.1.2+incompatible.info").unwrap();
        assert_eq!(module, "github.com/user/repo");
        assert_eq!(file, "@v/v4.1.2+incompatible.info");
    }

    #[test]
    fn test_split_pseudo_version() {
        let (module, file) =
            split_go_path("github.com/user/repo/@v/v0.0.0-20210101000000-abcdef123456.info")
                .unwrap();
        assert_eq!(module, "github.com/user/repo");
        assert_eq!(file, "@v/v0.0.0-20210101000000-abcdef123456.info");
    }

    #[test]
    fn test_split_no_at() {
        assert!(split_go_path("github.com/user/repo/v1.0.0").is_none());
    }

    #[test]
    fn test_split_empty_module() {
        assert!(split_go_path("/@v/list").is_none());
    }

    // ── Path safety ─────────────────────────────────────────────────────

    #[test]
    fn test_safe_path_normal() {
        assert!(is_safe_path("github.com/user/repo/@v/list"));
    }

    #[test]
    fn test_reject_traversal() {
        assert!(!is_safe_path("../../etc/passwd"));
    }

    #[test]
    fn test_reject_absolute() {
        assert!(!is_safe_path("/etc/passwd"));
    }

    #[test]
    fn test_reject_double_slash() {
        assert!(!is_safe_path("github.com//evil/@v/list"));
        for path in [
            "example.com/evil/@v/v1.0.0.zip/",
            "example.com/evil/@v/v1.0.0.mod/",
            "example.com/evil/@v/v1.0.0.info/",
            "example.com/evil/@v/list/",
            "example.com/./evil/@v/list",
        ] {
            assert!(!is_safe_path(path), "{path}");
        }
    }

    #[test]
    fn test_reject_null() {
        assert!(!is_safe_path("github.com/\0evil/@v/list"));
    }

    #[test]
    fn test_reject_empty() {
        assert!(!is_safe_path(""));
    }

    // ── Content-Type ────────────────────────────────────────────────────

    #[test]
    fn test_content_type_info() {
        assert_eq!(content_type_for("@v/v1.0.0.info"), "application/json");
    }

    #[test]
    fn test_content_type_latest() {
        assert_eq!(content_type_for("@latest"), "application/json");
    }

    #[test]
    fn test_content_type_zip() {
        assert_eq!(content_type_for("@v/v1.0.0.zip"), "application/zip");
    }

    #[test]
    fn test_content_type_mod() {
        assert_eq!(
            content_type_for("@v/v1.0.0.mod"),
            "text/plain; charset=utf-8"
        );
    }

    #[test]
    fn test_content_type_list() {
        assert_eq!(content_type_for("@v/list"), "text/plain; charset=utf-8");
    }

    // ── Cache freshness (revalidation) ────────────────────────────────────

    #[test]
    fn test_go_cache_fresh_immutable_always() {
        // Per-version files are content-addressed → always servable from cache, even proxied.
        assert!(go_cache_fresh(true, true, -1, Some(0)));
        assert!(go_cache_fresh(true, true, 0, None));
    }

    #[test]
    fn test_go_cache_fresh_mutable_hosted() {
        // Hosted (no upstream) listing is locally authoritative → fresh regardless of ttl.
        assert!(go_cache_fresh(false, false, 0, None));
    }

    #[test]
    fn test_go_cache_fresh_mutable_proxied_revalidates() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Proxied listing with non-positive ttl → revalidate every pull (the fix).
        assert!(!go_cache_fresh(false, true, 0, Some(now)));
        // Proxied listing within a positive ttl window → bounded staleness, served from cache.
        assert!(go_cache_fresh(false, true, 300, Some(now - 10)));
        // Proxied listing beyond the window → revalidate.
        assert!(!go_cache_fresh(false, true, 300, Some(now - 600)));
    }

    // ── Canonical version / non-canonical .info mutability ─────────────────

    #[test]
    fn test_is_canonical_go_version() {
        // Canonical: full vMAJOR.MINOR.PATCH, pseudo-versions, +incompatible, prerelease.
        for v in [
            "v1.0.0",
            "v0.0.0",
            "v10.20.30",
            "v1.2.3-rc.1",
            "v2.0.0+incompatible",
            "v0.0.0-20210101000000-abcdef123456",
            "v1.2.4-0.20210101000000-abcdef123456",
            "v1.0.0-rc.1+build.5",
        ] {
            assert!(is_canonical_go_version(v), "expected canonical: {v}");
        }
        // Non-canonical: partial queries, branches, revisions, operators, malformed.
        for v in [
            "v1",
            "v1.2",
            "master",
            "main",
            "latest",
            "abcdef123456",
            "v2",
            "1.0.0",
            "v01.2.3",
            "v1.0.0-",
            "v1.0.0+",
            "v1.2.3.4",
            "",
        ] {
            assert!(!is_canonical_go_version(v), "expected non-canonical: {v}");
        }
    }

    #[test]
    fn test_is_noncanonical_info_query() {
        // Non-canonical .info → mutable (the fix).
        assert!(is_noncanonical_info_query("@v/v1.info"));
        assert!(is_noncanonical_info_query("@v/v1.2.info"));
        assert!(is_noncanonical_info_query("@v/master.info"));
        assert!(is_noncanonical_info_query("@v/abcdef123456.info"));
        // Canonical .info → not mutable (immutable snapshot).
        assert!(!is_noncanonical_info_query("@v/v1.2.3.info"));
        assert!(!is_noncanonical_info_query(
            "@v/v0.0.0-20210101000000-abcdef123456.info"
        ));
        // Non-.info files are never matched here (handled by the immutable path).
        assert!(!is_noncanonical_info_query("@v/v1.2.3.mod"));
        assert!(!is_noncanonical_info_query("@v/master.zip"));
        assert!(!is_noncanonical_info_query("@v/list"));
        assert!(!is_noncanonical_info_query("@latest"));
    }

    proptest! {
        // Any fully-formed vMAJOR.MINOR.PATCH (no leading zeros) is canonical → immutable.
        #[test]
        fn canonical_triples_are_immutable(
            maj in 0u32..100000, min in 0u32..100000, pat in 0u32..100000
        ) {
            let v = format!("v{maj}.{min}.{pat}");
            let info = format!("@v/{}.info", v);
            prop_assert!(is_canonical_go_version(&v));
            prop_assert!(!is_noncanonical_info_query(&info));
        }

        // A two-segment query (vMAJOR.MINOR) is never canonical → always revalidated.
        #[test]
        fn partial_queries_are_mutable(maj in 0u32..100000, min in 0u32..100000) {
            let v = format!("v{maj}.{min}");
            let info = format!("@v/{}.info", v);
            prop_assert!(!is_canonical_go_version(&v));
            prop_assert!(is_noncanonical_info_query(&info));
        }

        // Branch/revision-like names (the charset has no `.`, so no MAJOR.MINOR.PATCH core can
        // form) are never canonical → always revalidated.
        #[test]
        fn branch_names_are_mutable(name in "[a-zA-Z][a-zA-Z0-9_/-]{0,30}") {
            prop_assert!(!is_canonical_go_version(&name));
        }
    }

    // ── Cache-Control headers ─────────────────────────────────────────────

    #[test]
    fn test_cache_control_immutable() {
        let resp = with_content_type(b"data".to_vec(), "application/zip", false);
        let cc = resp.headers().get(header::CACHE_CONTROL).unwrap();
        assert_eq!(cc, "public, max-age=31536000, immutable");
    }

    #[test]
    fn test_cache_control_mutable_list() {
        let resp = with_content_type(b"v1.0.0\n".to_vec(), "text/plain; charset=utf-8", true);
        let cc = resp.headers().get(header::CACHE_CONTROL).unwrap();
        assert_eq!(cc, "public, max-age=60, must-revalidate");
    }

    #[test]
    fn test_cache_control_mutable_latest() {
        let resp = with_content_type(b"{}".to_vec(), "application/json", true);
        let cc = resp.headers().get(header::CACHE_CONTROL).unwrap();
        assert_eq!(cc, "public, max-age=60, must-revalidate");
    }

    #[test]
    fn test_cache_control_immutable_mod() {
        // .mod is text/plain but immutable — must get long TTL
        let resp = with_content_type(
            b"module example".to_vec(),
            "text/plain; charset=utf-8",
            false,
        );
        let cc = resp.headers().get(header::CACHE_CONTROL).unwrap();
        assert_eq!(cc, "public, max-age=31536000, immutable");
    }

    // ── Artifact formatting ─────────────────────────────────────────────

    #[test]
    fn test_format_artifact_version() {
        assert_eq!(
            format_artifact("github.com/user/repo", "@v/v1.0.0.info"),
            "github.com/user/repo@v1.0.0"
        );
    }

    #[test]
    fn test_format_artifact_list() {
        assert_eq!(
            format_artifact("github.com/user/repo", "@v/list"),
            "github.com/user/repo @v/list"
        );
    }

    #[test]
    fn test_format_artifact_latest() {
        assert_eq!(
            format_artifact("github.com/user/repo", "@latest"),
            "github.com/user/repo @latest"
        );
    }

    #[test]
    fn test_format_artifact_zip() {
        assert_eq!(
            format_artifact("github.com/user/repo", "@v/v1.0.0.zip"),
            "github.com/user/repo@v1.0.0"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use crate::test_helpers::{body_bytes, create_test_context, send, send_with_headers};
    use axum::http::{Method, StatusCode};

    /// A cached module .zip resumes: 206 for a satisfiable range, 416 once the
    /// client already holds the whole archive, `Accept-Ranges` on the full 200.
    #[tokio::test]
    async fn test_go_zip_range_request() {
        let ctx = create_test_context();
        let zip = b"0123456789";
        ctx.state
            .storage
            .put("go/example.com/mod/@v/v1.0.0.zip", zip)
            .await
            .unwrap();
        let url = "/go/example.com/mod/@v/v1.0.0.zip";

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
        assert_eq!(&body_bytes(resp).await[..], zip);
    }

    /// Metadata endpoints are not resumable payloads: a .mod ignores `Range`.
    #[tokio::test]
    async fn test_go_mod_ignores_range() {
        let ctx = create_test_context();
        ctx.state
            .storage
            .put(
                "go/example.com/mod/@v/v1.0.0.mod",
                b"module example.com/mod",
            )
            .await
            .unwrap();

        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/go/example.com/mod/@v/v1.0.0.mod",
            vec![("range", "bytes=2-5")],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get("accept-ranges").is_none());
    }

    /// `.../v1.0.0.zip/` is refused: it is no `.zip` to the handler, so curation, the integrity
    /// check and the quarantine gate would not run, and on an object store the key reads the
    /// cached archive (the local backend answers ENOTDIR — the control).
    #[tokio::test]
    async fn a_trailing_slash_archive_is_refused_before_curation() {
        use crate::storage::{ObjectStorage, Storage};
        let dir = tempfile::tempdir().unwrap();
        let blocklist = dir.path().join("blocklist.json");
        std::fs::write(
            &blocklist,
            r#"{"version": 1, "rules": [{"registry": "go", "name": "example.com/evil", "version": "*", "reason": "malware"}]}"#,
        )
        .unwrap();
        let bp = blocklist.to_string_lossy().into_owned();
        let configure = |cfg: &mut crate::config::Config| {
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(bp.clone());
        };
        let key = "go/example.com/evil/@v/v1.0.0.zip";
        let canonical = "/go/example.com/evil/@v/v1.0.0.zip";
        let alias = "/go/example.com/evil/@v/v1.0.0.zip/";

        let local = crate::test_helpers::create_test_context_with_config(configure);
        local.state.storage.put(key, b"MALWARE").await.unwrap();
        let resp = send(&local.app, Method::GET, alias, "").await;
        assert_ne!(resp.status(), StatusCode::OK, "control: local backend");

        let object = crate::test_helpers::create_test_context_with_storage_and_config(
            Storage::from_backend(std::sync::Arc::new(ObjectStorage::in_memory())),
            configure,
        );
        object.state.storage.put(key, b"MALWARE").await.unwrap();
        let resp = send(&object.app, Method::GET, canonical, "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "control: canonical");
        let resp = send(&object.app, Method::GET, alias, "").await;
        assert_ne!(
            resp.status(),
            StatusCode::OK,
            "blocklisted module archive served: {:?}",
            body_bytes(resp).await
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod index_cost_tests {
    //! Serving a cached @v/list must cost the same storage round-trips for 1 and 100 versions.
    use crate::test_helpers::{create_test_context_with_storage, op_counting_storage, send};
    use axum::http::{Method, StatusCode};

    async fn version_list_ops(n: usize) -> (usize, String) {
        let (storage, ops) = op_counting_storage();
        let ctx = create_test_context_with_storage(storage);
        let mut list = String::new();
        for i in 0..n {
            let version = format!("v1.0.{i}");
            let base = format!("go/example.com/costmod/@v/{version}");
            let info = format!("{{\"Version\":\"{version}\",\"Time\":\"2026-01-01T00:00:00Z\"}}");
            ctx.state
                .storage
                .put(&format!("{base}.info"), info.as_bytes())
                .await
                .unwrap();
            ctx.state
                .storage
                .put(&format!("{base}.mod"), b"module example.com/costmod\n")
                .await
                .unwrap();
            ctx.state
                .storage
                .put(&format!("{base}.zip"), b"ZIP")
                .await
                .unwrap();
            list.push_str(&format!("{version}\n"));
        }
        ctx.state
            .storage
            .put("go/example.com/costmod/@v/list", list.as_bytes())
            .await
            .unwrap();
        ops.reset();
        let resp = send(&ctx.app, Method::GET, "/go/example.com/costmod/@v/list", "").await;
        assert_eq!(resp.status(), StatusCode::OK, "@v/list with {n} versions");
        (ops.total(), format!("{:?}", ops.snapshot()))
    }

    #[tokio::test]
    async fn go_version_list_cost_is_independent_of_version_count() {
        let (small, small_ops) = version_list_ops(1).await;
        let (large, large_ops) = version_list_ops(100).await;
        assert_eq!(
            small, large,
            "a cached @v/list must cost the same storage round-trips for 1 and 100 versions: {small_ops} vs {large_ops}"
        );
    }
}

/// A name or path with an empty segment (or, where the name is one segment, any `/`) never
/// reaches curation, storage or an upstream: it would name another artifact's files, and an
/// upstream that normalises paths would answer for that other artifact.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod empty_segment_requests {
    use crate::test_helpers::{
        blocklist_file, create_test_context_with_config, send, upstream_paths,
    };
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // The file after `@v/` is one segment: a `%2F` in the version decodes to `/`, and
    // `v1.0.0%2F.zip` would reach curation as version `v1.0.0/` — past a rule for `v1.0.0` —
    // and the upstream as `.../@v/v1.0.0/.zip`.
    #[tokio::test]
    async fn a_version_with_an_inner_slash_never_reaches_upstream() {
        let up = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"EVIL-ZIP".to_vec()))
            .mount(&up)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let blocklist = dir.path().join("blocklist.json");
        std::fs::write(
            &blocklist,
            r#"{"version": 1, "rules": [{"registry": "go", "name": "example.com/evil", "version": "v1.0.0", "reason": "malware"}]}"#,
        )
        .unwrap();
        let ctx = create_test_context_with_config(|cfg| {
            cfg.go.proxy = Some(up.uri());
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist.to_string_lossy().into_owned());
        });
        let control = "/go/example.com/evil/@v/v1.0.0.zip";
        let resp = send(&ctx.app, Method::GET, control, "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "control");
        // Such a path is no Go proxy path: 404, as any path that does not split.
        for uri in [
            "/go/example.com/evil/@v/v1.0.0%2F.zip",
            "/go/example.com/evil/@v/v1.0.0%2F.mod",
            "/go/example.com/evil/@v/v1.0.0%2Fx.info",
        ] {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{uri}");
        }
        let sent = upstream_paths(&up).await;
        assert!(sent.is_empty(), "sent upstream: {sent:?}");
    }

    // No Go proxy path ends in `/` or has an empty segment: `.../v1.0.0.zip/` is no longer a
    // `.zip` to curation, and none of these forms reaches the upstream.
    #[tokio::test]
    async fn no_module_path_with_an_empty_segment_reaches_upstream() {
        let up = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"EVIL-ZIP".to_vec()))
            .mount(&up)
            .await;
        let (_dir, blocklist) = blocklist_file("go", "example.com/evil");
        let ctx = create_test_context_with_config(|cfg| {
            cfg.go.proxy = Some(up.uri());
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist);
        });
        let control = "/go/example.com/evil/@v/v1.0.0.zip";
        let resp = send(&ctx.app, Method::GET, control, "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "control");
        for uri in [
            "/go/example.com/evil/@v/v1.0.0.zip/",
            "/go/example.com/evil/@v/v1.0.0.mod/",
            "/go/example.com/evil/@v/v1.0.0.info/",
            "/go/example.com/evil/@v/list/",
            "/go/example.com//evil/@v/list",
        ] {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{uri}");
        }
        let sent = upstream_paths(&up).await;
        assert!(sent.is_empty(), "sent upstream: {sent:?}");
    }

    // A byte the upstream URL parser strips or reads as a delimiter (tab, LF, CR, `#`, `?`, a
    // space) would let curation judge one module or version and the upstream serve another.
    #[tokio::test]
    async fn a_path_byte_the_url_parser_reinterprets_never_reaches_upstream() {
        let up = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"EVIL-ZIP".to_vec()))
            .mount(&up)
            .await;
        let (_dir, blocklist) = blocklist_file("go", "example.com/evil");
        let ctx = create_test_context_with_config(|cfg| {
            cfg.go.proxy = Some(up.uri());
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist);
        });
        let control = "/go/example.com/evil/@v/v1.0.0.zip";
        let resp = send(&ctx.app, Method::GET, control, "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "control");
        for uri in [
            "/go/example.com/ev%09il/@v/v1.0.0.zip",
            "/go/example.com/ev%0Ail/@v/v1.0.0.zip",
            "/go/example.com/ev%0Dil/@v/v1.0.0.zip",
            "/go/example.com/evil%20/@v/v1.0.0.zip",
            "/go/example.com/evil/@v/v1.0.0.zip%23x.zip",
            "/go/example.com/evil/@v/v1.0.0.zip%3Fx.zip",
            "/go/a/.%09./example.com/evil/@v/v1.0.0.zip",
        ] {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{uri}");
        }
        let sent = upstream_paths(&up).await;
        assert!(sent.is_empty(), "sent upstream: {sent:?}");
        // A plain module still reaches the upstream.
        let resp = send(&ctx.app, Method::GET, "/go/example.com/good/@v/list", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(upstream_paths(&up).await, ["/example.com/good/@v/list"]);
    }
}

/// A Go module version is the version the go command reads: `module.CanonicalVersion` gives
/// `v1` and `v1.2` as `v1.0.0` and `v1.2.0` and drops build metadata other than `+incompatible`,
/// so a rule or an allowlist entry holds however it spells its version.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod go_version_curation {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn upstream() -> MockServer {
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ZIP".to_vec()))
            .mount(&upstream)
            .await;
        upstream
    }

    fn write(dir: &tempfile::TempDir, file: &str, body: &str) -> String {
        let path = dir.path().join(file);
        std::fs::write(&path, body).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[tokio::test]
    async fn a_rule_holds_however_it_spells_its_version() {
        let upstream = upstream().await;
        let dir = tempfile::tempdir().unwrap();
        let blocklist = write(
            &dir,
            "blocklist.json",
            r#"{"version": 1, "rules": [
                {"registry": "go", "name": "example.com/evil", "version": "v1.2", "reason": "r"},
                {"registry": "go", "name": "example.com/evil", "version": "v1.3.0+meta", "reason": "r"},
                {"registry": "go", "name": "example.com/evil", "version": "v2", "reason": "r"}
            ]}"#,
        );
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.go.proxy = Some(uri);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist);
        });
        for version in ["v1.2.0", "v1.3.0", "v2.0.0"] {
            let path = format!("/go/example.com/evil/@v/{version}.zip");
            let resp = send(&ctx.app, Method::GET, &path, "").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{version}");
        }
        for version in ["v1.2.1", "v2.0.0+incompatible"] {
            let path = format!("/go/example.com/evil/@v/{version}.zip");
            let resp = send(&ctx.app, Method::GET, &path, "").await;
            assert_ne!(resp.status(), StatusCode::FORBIDDEN, "{version}");
        }
    }

    /// An allowlist entry that pins the archive's SHA-256 refuses other bytes on the first
    /// download from the upstream, not only once they are cached.
    #[tokio::test]
    async fn a_pinned_integrity_refuses_other_bytes_on_the_first_download() {
        use sha2::Digest;
        let upstream = upstream().await; // serves b"ZIP"
        let dir = tempfile::tempdir().unwrap();
        let pinned = format!("sha256:{}", hex::encode(sha2::Sha256::digest(b"GOOD")));
        let allowlist = write(
            &dir,
            "allowlist.json",
            &format!(
                r#"{{"version": 1, "entries": [{{"registry": "go", "name": "example.com/good", "version": "v1.0.0", "integrity": "{pinned}"}}]}}"#
            ),
        );
        // The module archive in any case of its extension: NORA reads `.ZIP` as the archive
        // everywhere else (selection, size limit, quarantine, content type).
        for path in [
            "/go/example.com/good/@v/v1.0.0.zip",
            "/go/example.com/good/@v/v1.0.0.ZIP",
        ] {
            let uri = upstream.uri();
            let allowlist = allowlist.clone();
            let ctx = create_test_context_with_config(move |cfg| {
                cfg.go.proxy = Some(uri);
                cfg.curation.mode = crate::config::CurationMode::Enforce;
                cfg.curation.allowlist_path = Some(allowlist);
            });
            let holders = ctx.state.storage.holders();
            let first = send(&ctx.app, Method::GET, path, "").await;
            crate::test_helpers::background_writes_done(&ctx.state.storage, holders).await;
            let second = send(&ctx.app, Method::GET, path, "").await;
            assert_eq!(
                second.status(),
                StatusCode::FORBIDDEN,
                "{path}: cached copy"
            );
            assert_eq!(
                first.status(),
                StatusCode::FORBIDDEN,
                "{path}: first download"
            );
        }
    }

    #[tokio::test]
    async fn an_allowlist_entry_admits_its_version_however_spelled() {
        let upstream = upstream().await;
        let dir = tempfile::tempdir().unwrap();
        let allowlist = write(
            &dir,
            "allowlist.json",
            r#"{"version": 1, "entries": [{"registry": "go", "name": "example.com/good", "version": "v1"}]}"#,
        );
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.go.proxy = Some(uri);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.allowlist_path = Some(allowlist);
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/go/example.com/good/@v/v1.0.0.zip",
            "",
        )
        .await;
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
        let resp = send(
            &ctx.app,
            Method::GET,
            "/go/example.com/good/@v/v1.0.1.zip",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
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

    const DOWNLOAD: &str = "/go/example.com/oldmod/@v/v1.0.0.zip";
    const INFO: &[u8] = br#"{"Version":"v1.0.0","Time":"2019-01-01T00:00:00Z"}"#;

    async fn context(trust: bool) -> (MockServer, TestContext) {
        let up = MockServer::start().await;
        serve(&up, "/example.com/oldmod/@v/v1.0.0.zip", b"ZIP".to_vec()).await;
        serve(&up, "/example.com/oldmod/@v/v1.0.0.info", INFO.to_vec()).await;
        let uri = up.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.go.proxy = Some(uri);
            cfg.server.trust_upstream_dates = trust;
            quarantine_7d(cfg);
        });
        put_written_days_ago(&ctx, "go/example.com/oldmod/@v/v1.0.0.info", INFO, 30).await;
        (up, ctx)
    }

    #[tokio::test]
    async fn without_trusted_dates_a_cached_info_does_not_date_the_quarantine() {
        let (_up, ctx) = context(false).await;
        assert_eq!(status(&ctx, DOWNLOAD).await, StatusCode::FORBIDDEN);
    }

    /// A zip cached before the quarantine recorded it is counted from now on the cache path.
    #[tokio::test]
    async fn a_file_cached_before_the_quarantine_saw_it_counts_from_now() {
        let (up, ctx) = context(false).await;
        put_written_days_ago(&ctx, "go/example.com/oldmod/@v/v1.0.0.zip", b"ZIP", 30).await;
        assert_eq!(status(&ctx, DOWNLOAD).await, StatusCode::FORBIDDEN);
        assert!(crate::test_helpers::upstream_paths(&up).await.is_empty());
    }

    #[tokio::test]
    async fn with_trusted_dates_an_old_release_matures_in_the_quarantine() {
        let (_up, ctx) = context(true).await;
        assert_eq!(status(&ctx, DOWNLOAD).await, StatusCode::OK);
    }
}

/// A Go version's release date under trusted upstream dates (audit A066, A067): the `.info`
/// `Time` bounded below by NORA's first sight of the version, the `.info` fetched before a
/// `.zip` asked for first, and a date still unknown judged by `[curation.go] unknown_date`.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod release_date_judged {
    use crate::test_helpers::{
        create_test_context_with_config, put_written_days_ago, quarantine_7d, send, upstream_paths,
        TestContext,
    };
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const ZIP: &str = "/go/example.org/mod/@v/v2.3.4.zip";
    const INFO: &str = "/go/example.org/mod/@v/v2.3.4.info";
    const ZIP_KEY: &str = "go/example.org/mod/@v/v2.3.4.zip";
    const INFO_KEY: &str = "go/example.org/mod/@v/v2.3.4.info";
    const UP_INFO: &str = "/example.org/mod/@v/v2.3.4.info";

    fn info(age: chrono::Duration) -> Vec<u8> {
        let t = (chrono::Utc::now() - age).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        format!(r#"{{"Version":"v2.3.4","Time":"{t}"}}"#).into_bytes()
    }

    /// An upstream serving the zip and, when `info_body` is set, the `.info` (else 500).
    async fn upstream(info_body: Option<Vec<u8>>) -> MockServer {
        let up = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/example.org/mod/@v/v2.3.4.zip"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ZIP".to_vec()))
            .mount(&up)
            .await;
        let info = match info_body {
            Some(body) => ResponseTemplate::new(200).set_body_bytes(body),
            None => ResponseTemplate::new(500),
        };
        Mock::given(method("GET"))
            .and(path(UP_INFO))
            .respond_with(info)
            .mount(&up)
            .await;
        up
    }

    /// Live shape: enforce, go min_release_age 3d, quarantine observe, trusted dates.
    fn min_age(up: &MockServer, hold: bool) -> TestContext {
        let uri = up.uri();
        create_test_context_with_config(move |cfg| {
            cfg.go.proxy = Some(uri);
            cfg.server.trust_upstream_dates = true;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.go.min_release_age = Some("3d".to_string());
            cfg.curation.go.quarantine = Some(crate::digest_quarantine::QuarantineMode::Observe);
            cfg.curation.go.quarantine_ttl = Some("3d".to_string());
            if hold {
                cfg.curation.go.unknown_date = Some(crate::config::UnknownDate::Hold);
            }
        })
    }

    async fn status(ctx: &TestContext, uri: &str) -> StatusCode {
        send(&ctx.app, Method::GET, uri, "").await.status()
    }

    /// The `.info` through NORA, as `go mod download` asks, and its background write done.
    async fn info_through_nora(ctx: &TestContext) {
        let holders = ctx.state.storage.holders();
        assert_eq!(status(ctx, INFO).await, StatusCode::OK);
        crate::test_helpers::background_writes_done(&ctx.state.storage, holders).await;
        assert!(ctx.state.storage.get(INFO_KEY).await.is_ok(), "info cached");
    }

    // A066: a `Time` 30 days back on a version NORA first sees now does not age it.
    #[tokio::test]
    async fn a_backdated_info_time_does_not_skip_min_release_age() {
        let up = upstream(Some(info(chrono::Duration::days(30)))).await;
        let ctx = min_age(&up, false);
        info_through_nora(&ctx).await;
        assert_eq!(status(&ctx, ZIP).await, StatusCode::FORBIDDEN);

        // Control: the same `.info` NORA cached 30 days ago.
        let ctx = min_age(&up, false);
        put_written_days_ago(&ctx, INFO_KEY, &info(chrono::Duration::days(30)), 30).await;
        assert_eq!(status(&ctx, ZIP).await, StatusCode::OK);
    }

    // A066: nor does it seed an enforcing quarantine as mature.
    #[tokio::test]
    async fn a_backdated_info_time_does_not_seed_the_quarantine() {
        let body = br#"{"Version":"v2.3.4","Time":"2019-01-01T00:00:00Z"}"#.to_vec();
        let up = upstream(Some(body)).await;
        let uri = up.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.go.proxy = Some(uri);
            cfg.server.trust_upstream_dates = true;
            quarantine_7d(cfg);
        });
        info_through_nora(&ctx).await;
        assert_eq!(status(&ctx, ZIP).await, StatusCode::FORBIDDEN);
    }

    // A067 (A): a `.zip` asked for first fetches its `.info` and is judged by it.
    #[tokio::test]
    async fn a_zip_first_is_dated_by_its_fetched_info() {
        let up = upstream(Some(info(chrono::Duration::hours(1)))).await;
        let ctx = min_age(&up, false);
        assert_eq!(status(&ctx, ZIP).await, StatusCode::FORBIDDEN);
        assert!(upstream_paths(&up).await.iter().any(|p| p == UP_INFO));
        assert!(ctx.state.storage.get(INFO_KEY).await.is_ok());
    }

    // A067 (B): the `.info` through NORA first, then the `.zip`.
    #[tokio::test]
    async fn an_info_then_zip_is_refused() {
        let up = upstream(Some(info(chrono::Duration::hours(1)))).await;
        let ctx = min_age(&up, false);
        info_through_nora(&ctx).await;
        assert_eq!(status(&ctx, ZIP).await, StatusCode::FORBIDDEN);
    }

    // A067 (C): a zip cached without its `.info` is dated, not served undated.
    #[tokio::test]
    async fn a_cached_zip_without_info_is_dated() {
        let up = upstream(Some(info(chrono::Duration::hours(1)))).await;
        let ctx = min_age(&up, false);
        ctx.state.storage.put(ZIP_KEY, b"ZIP").await.unwrap();
        assert_eq!(status(&ctx, ZIP).await, StatusCode::FORBIDDEN);
    }

    // A067: with no `.info` to be had, `hold` refuses a version NORA has no copy of.
    #[tokio::test]
    async fn an_unknown_date_is_held_under_hold() {
        let up = upstream(None).await;
        let ctx = min_age(&up, true);
        assert_eq!(status(&ctx, ZIP).await, StatusCode::FORBIDDEN);
    }

    /// `log` (Go's default) serves it, and counts it.
    #[tokio::test]
    async fn an_unknown_date_is_counted_under_log() {
        let up = upstream(None).await;
        let ctx = min_age(&up, false);
        let counter =
            crate::metrics::CURATION_UNKNOWN_RELEASE_DATE_TOTAL.with_label_values(&["go"]);
        let before = counter.get();
        assert_eq!(status(&ctx, ZIP).await, StatusCode::OK);
        assert!(counter.get() > before);
    }

    // `[go] attested_dates`: proxy.golang.org served by the mock under this path.
    const GO_PROXY: &str = "/proxy.golang.org";
    const KEPT: &str = "go/example.org/mod/@nora-dates/v2.3.4";
    const GO_PROXY_EPOCH_FOR_TESTS: i64 = super::GO_PROXY_EPOCH;

    fn last_modified(age: chrono::Duration) -> ResponseTemplate {
        let at = (chrono::Utc::now() - age).format("%a, %d %b %Y %H:%M:%S GMT");
        ResponseTemplate::new(200).insert_header("last-modified", at.to_string())
    }

    /// proxy.golang.org (under [`GO_PROXY`]) serving the zip, an `.info` `info_age` old and
    /// `head` for the zip's HEAD.
    async fn golang_proxy(info_age: chrono::Duration, head: ResponseTemplate) -> MockServer {
        let up = MockServer::start().await;
        let zip = format!("{GO_PROXY}/example.org/mod/@v/v2.3.4.zip");
        Mock::given(method("GET"))
            .and(path(zip.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ZIP".to_vec()))
            .mount(&up)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{GO_PROXY}{UP_INFO}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(info(info_age)))
            .mount(&up)
            .await;
        Mock::given(method("HEAD"))
            .and(path(zip))
            .respond_with(head)
            .mount(&up)
            .await;
        up
    }

    /// The live shape of [`min_age`] with `[go] attested_dates`, `go.proxy` = `proxy`.
    fn attested_ctx(
        proxy: String,
        customize: impl FnOnce(&mut crate::config::Config),
    ) -> TestContext {
        create_test_context_with_config(move |cfg| {
            cfg.go.proxy = Some(proxy);
            cfg.go.attested_dates = true;
            cfg.server.trust_upstream_dates = true;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.go.min_release_age = Some("3d".to_string());
            cfg.curation.go.quarantine = Some(crate::digest_quarantine::QuarantineMode::Observe);
            cfg.curation.go.quarantine_ttl = Some("3d".to_string());
            customize(cfg);
        })
    }

    async fn attested(
        info_age: chrono::Duration,
        head: ResponseTemplate,
    ) -> (MockServer, TestContext) {
        let up = golang_proxy(info_age, head).await;
        let ctx = attested_ctx(format!("{}{GO_PROXY}", up.uri()), |_| {});
        (up, ctx)
    }

    async fn heads(up: &MockServer) -> usize {
        let asked = up.received_requests().await.unwrap_or_default();
        asked.iter().filter(|r| r.method.as_str() == "HEAD").count()
    }

    async fn kept(ctx: &TestContext) -> Option<i64> {
        let data = ctx.state.storage.get(KEPT).await.ok()?;
        std::str::from_utf8(&data).ok()?.trim().parse().ok()
    }

    fn days_ago(days: i64) -> i64 {
        (chrono::Utc::now() - chrono::Duration::days(days)).timestamp()
    }

    // An old version NORA first sees now is dated by the proxy's first fetch, asked once and kept.
    #[tokio::test]
    async fn an_attested_old_version_first_seen_now_is_served() {
        // Taken with the header, not after the test: under a parallel run the pooled mock
        // server can take seconds to start, which a later `days_ago(30)` would count.
        let last_modified_at = days_ago(30);
        let (up, ctx) = attested(
            chrono::Duration::days(30),
            last_modified(chrono::Duration::days(30)),
        )
        .await;
        info_through_nora(&ctx).await;
        assert_eq!(status(&ctx, ZIP).await, StatusCode::OK);
        // Past the memo: the second request is answered by the kept date alone.
        ctx.state.upstream_dates.lock().clear();
        assert_eq!(status(&ctx, ZIP).await, StatusCode::OK);
        assert_eq!(heads(&up).await, 1, "one HEAD, then the kept date");
        let at = kept(&ctx).await.expect("attested date kept");
        // The header has one-second resolution.
        assert!((at - last_modified_at).abs() <= 1, "kept the Last-Modified");
    }

    // A066 holds: a back-dated `Time` does not age a version the proxy fetched an hour ago.
    #[tokio::test]
    async fn a_backdated_info_time_is_bounded_by_the_attested_date() {
        let (up, ctx) = attested(
            chrono::Duration::days(30),
            last_modified(chrono::Duration::hours(1)),
        )
        .await;
        info_through_nora(&ctx).await;
        assert_eq!(status(&ctx, ZIP).await, StatusCode::FORBIDDEN);
        assert_eq!(heads(&up).await, 1);
        let at = kept(&ctx).await.expect("attested date kept");
        assert!(chrono::Utc::now().timestamp() - at < 3700);
    }

    // The publisher's `Time` still bounds from below: an earlier attested date is not used.
    #[tokio::test]
    async fn an_attested_date_never_predates_the_info_time() {
        let (_up, ctx) = attested(
            chrono::Duration::hours(1),
            last_modified(chrono::Duration::days(30)),
        )
        .await;
        assert_eq!(status(&ctx, ZIP).await, StatusCode::FORBIDDEN);
    }

    // The option only ever makes a date earlier: a first sight 10 days back stands against a
    // proxy that re-stored the zip an hour ago, and no HEAD is sent for a version past the age.
    #[tokio::test]
    async fn an_old_first_sight_is_not_made_younger() {
        let (up, ctx) = attested(
            chrono::Duration::days(30),
            last_modified(chrono::Duration::hours(1)),
        )
        .await;
        put_written_days_ago(&ctx, INFO_KEY, &info(chrono::Duration::days(30)), 10).await;
        assert_eq!(status(&ctx, ZIP).await, StatusCode::OK);
        assert_eq!(heads(&up).await, 0);
    }

    // No `Last-Modified`: first sight dates it, nothing is kept, and the miss is asked again
    // at most once a minute, however many requests.
    #[tokio::test]
    async fn without_an_attested_date_first_sight_dates_it() {
        let (up, ctx) = attested(chrono::Duration::days(30), ResponseTemplate::new(200)).await;
        info_through_nora(&ctx).await;
        for _ in 0..3 {
            assert_eq!(status(&ctx, ZIP).await, StatusCode::FORBIDDEN);
        }
        assert_eq!(heads(&up).await, 1);
        assert_eq!(kept(&ctx).await, None);
    }

    // A `Last-Modified` before proxy.golang.org existed is no first fetch: not taken.
    #[tokio::test]
    async fn an_epoch_last_modified_is_not_taken() {
        let epoch = ResponseTemplate::new(200)
            .insert_header("last-modified", "Thu, 01 Jan 1970 00:00:00 GMT");
        let (up, ctx) = attested(chrono::Duration::days(30), epoch).await;
        info_through_nora(&ctx).await;
        assert_eq!(status(&ctx, ZIP).await, StatusCode::FORBIDDEN);
        assert_eq!(heads(&up).await, 1);
        assert_eq!(kept(&ctx).await, None);
    }

    // A HEAD answered 404 (or 5xx) dates nothing.
    #[tokio::test]
    async fn a_missing_zip_on_the_proxy_dates_nothing() {
        for code in [404, 503] {
            let (up, ctx) = attested(chrono::Duration::days(30), ResponseTemplate::new(code)).await;
            info_through_nora(&ctx).await;
            assert_eq!(status(&ctx, ZIP).await, StatusCode::FORBIDDEN, "{code}");
            assert_eq!(heads(&up).await, 1, "{code}");
            assert_eq!(kept(&ctx).await, None, "{code}");
        }
    }

    // Another proxy's `Last-Modified` is never read: the option is ignored there.
    #[tokio::test]
    async fn another_proxy_is_not_asked() {
        let up = golang_proxy(
            chrono::Duration::days(30),
            last_modified(chrono::Duration::days(30)),
        )
        .await;
        let other =
            format!("{}{GO_PROXY}", up.uri()).replace("/proxy.golang.org", "/goproxy.example");
        let ctx = attested_ctx(other, |_| {});
        assert!(!crate::config::GoConfig::attests_first_fetch(
            "https://goproxy.example"
        ));
        assert!(!crate::config::GoConfig::attests_first_fetch(
            "http://proxy.golang.org"
        ));
        assert!(crate::config::GoConfig::attests_first_fetch(
            "https://proxy.golang.org/"
        ));
        let _ = status(&ctx, ZIP).await;
        assert_eq!(heads(&up).await, 0);
    }

    // Untrusted upstream dates: no date is read, so none is asked for.
    #[tokio::test]
    async fn untrusted_dates_send_no_head() {
        let up = golang_proxy(
            chrono::Duration::days(30),
            last_modified(chrono::Duration::days(30)),
        )
        .await;
        let ctx = attested_ctx(format!("{}{GO_PROXY}", up.uri()), |cfg| {
            cfg.server.trust_upstream_dates = false;
        });
        let _ = status(&ctx, ZIP).await;
        assert_eq!(heads(&up).await, 0);
    }

    // A kept value that does not parse is asked again and replaced.
    #[tokio::test]
    async fn a_corrupt_kept_date_is_replaced() {
        let (up, ctx) = attested(
            chrono::Duration::days(30),
            last_modified(chrono::Duration::days(30)),
        )
        .await;
        ctx.state.storage.put(KEPT, b"not a date").await.unwrap();
        assert_eq!(status(&ctx, ZIP).await, StatusCode::OK);
        assert_eq!(heads(&up).await, 1);
        assert!(kept(&ctx).await.is_some());
    }

    // A kept date out of range (0, or in the future) is no first fetch: it would let a
    // back-dated `Time` through (A066). It is asked again and replaced.
    #[tokio::test]
    async fn an_out_of_range_kept_date_is_not_taken() {
        let future = (chrono::Utc::now() + chrono::Duration::days(365)).timestamp();
        for bad in [0, GO_PROXY_EPOCH_FOR_TESTS - 1, future] {
            let (up, ctx) = attested(
                chrono::Duration::days(30),
                last_modified(chrono::Duration::hours(1)),
            )
            .await;
            ctx.state
                .storage
                .put(KEPT, bad.to_string().as_bytes())
                .await
                .unwrap();
            info_through_nora(&ctx).await;
            assert_eq!(status(&ctx, ZIP).await, StatusCode::FORBIDDEN, "{bad}");
            assert_eq!(heads(&up).await, 1, "{bad}");
            let at = kept(&ctx).await.expect("replaced");
            assert!(chrono::Utc::now().timestamp() - at < 3700, "{bad}");
        }
    }

    // #733: an internal module's name never reaches proxy.golang.org, `.info` cached or not.
    #[tokio::test]
    async fn an_internal_module_sends_no_head() {
        let up = golang_proxy(
            chrono::Duration::days(30),
            last_modified(chrono::Duration::days(30)),
        )
        .await;
        let ctx = attested_ctx(format!("{}{GO_PROXY}", up.uri()), |cfg| {
            cfg.curation.internal_namespaces = vec!["example.org/mod".to_string()];
        });
        ctx.state
            .storage
            .put(INFO_KEY, &info(chrono::Duration::days(30)))
            .await
            .unwrap();
        let _ = status(&ctx, ZIP).await;
        assert_eq!(heads(&up).await, 0);
        assert_eq!(kept(&ctx).await, None);
    }

    // An enforcing quarantine is seeded by the same bounded date: a back-dated `Time` on a
    // version the proxy fetched an hour ago is held, an attested old one is not.
    #[tokio::test]
    async fn the_quarantine_seed_is_the_bounded_date() {
        for (lm_age, want) in [
            (chrono::Duration::hours(1), StatusCode::FORBIDDEN),
            (chrono::Duration::days(30), StatusCode::OK),
        ] {
            let up = golang_proxy(chrono::Duration::days(30), last_modified(lm_age)).await;
            let ctx = attested_ctx(format!("{}{GO_PROXY}", up.uri()), |cfg| {
                cfg.curation.go.min_release_age = Some("1h".to_string());
                quarantine_7d(cfg);
                cfg.curation.go.quarantine =
                    Some(crate::digest_quarantine::QuarantineMode::Enforce);
                cfg.curation.go.quarantine_ttl = Some("7d".to_string());
            });
            info_through_nora(&ctx).await;
            assert_eq!(status(&ctx, ZIP).await, want, "{lm_age}");
        }
    }

    // The kept date is not a GOPROXY path.
    #[tokio::test]
    async fn the_attested_date_is_not_served() {
        let (_up, ctx) = attested(
            chrono::Duration::days(30),
            last_modified(chrono::Duration::days(30)),
        )
        .await;
        assert_eq!(status(&ctx, ZIP).await, StatusCode::OK);
        assert!(kept(&ctx).await.is_some());
        assert_eq!(
            status(&ctx, "/go/example.org/mod/@nora-dates/v2.3.4").await,
            StatusCode::NOT_FOUND
        );
    }

    /// A zip NORA cached more than 3 days ago is as old as that, `.info` or not.
    #[tokio::test]
    async fn a_zip_cached_long_ago_is_dated_by_its_copy() {
        let up = upstream(None).await;
        let ctx = min_age(&up, true);
        put_written_days_ago(&ctx, ZIP_KEY, b"ZIP", 4).await;
        assert_eq!(status(&ctx, ZIP).await, StatusCode::OK);
    }
}

/// Q04 for Go: `@v/list`, `@latest` and a revision query offer only versions the `.zip` gate
/// admits for their release age (govulncheck v1.10.0, 17.11.2026: `go install …@latest`
/// resolved a version NORA then refused with 403 for three days).
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod metadata_hides_young_versions {
    use crate::config::CurationMode;
    use crate::test_helpers::{
        body_bytes, create_test_context_with_config, put_written_days_ago, send, TestContext,
    };
    use axum::http::{header, Method, StatusCode};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const MODULE: &str = "example.org/fresh";
    /// Old enough and cached 30 days ago: admitted.
    const MATURE: [&str; 3] = ["v1.0.0", "v1.1.0", "v1.3.0-rc.1"];
    /// Published an hour ago and new to NORA: held.
    const YOUNG: [&str; 4] = ["v1.1.1", "v1.2.0", "v1.3.0-rc.2", "v1.3.0-rc.10"];
    const PSEUDO: &str = "v1.2.1-0.20261118100000-abcdef123456";

    fn info(version: &str, age: chrono::Duration) -> String {
        let t = (chrono::Utc::now() - age).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        format!(r#"{{"Version":"{version}","Time":"{t}"}}"#)
    }

    async fn serve(up: &MockServer, at: String, body: String) {
        Mock::given(method("GET"))
            .and(path(at))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(up)
            .await;
    }

    /// An upstream listing `listed` (and, for `@latest`, naming the newest young release),
    /// serving every version's `.info` and `.zip`; the mature ones cached 30 days ago.
    async fn context(
        listed: &[&str],
        mode: CurationMode,
        allow: &[&str],
    ) -> (MockServer, TestContext) {
        let up = MockServer::start().await;
        let list: String = listed.iter().map(|v| format!("{v}\n")).collect();
        serve(&up, format!("/{MODULE}/@v/list"), list).await;
        let young = chrono::Duration::hours(1);
        serve(&up, format!("/{MODULE}/@latest"), info("v1.2.0", young)).await;
        serve(&up, format!("/{MODULE}/@v/main.info"), info(PSEUDO, young)).await;
        let old = chrono::Duration::days(30);
        serve(
            &up,
            format!("/{MODULE}/@v/stable.info"),
            info("v1.1.0", old),
        )
        .await;
        for v in MATURE.iter().chain(&YOUNG).chain(&[PSEUDO]) {
            let age = if MATURE.contains(v) { old } else { young };
            serve(&up, format!("/{MODULE}/@v/{v}.info"), info(v, age)).await;
            serve(&up, format!("/{MODULE}/@v/{v}.zip"), "ZIP".into()).await;
        }
        let uri = up.uri();
        let allow: Vec<String> = allow.iter().map(|a| a.to_string()).collect();
        let ctx = create_test_context_with_config(move |cfg| {
            // Live shape: enforce, go min_release_age 3d, quarantine observe, trusted dates.
            cfg.go.proxy = Some(uri);
            cfg.server.trust_upstream_dates = true;
            cfg.curation.mode = mode;
            cfg.curation.go.min_release_age = Some("3d".to_string());
            cfg.curation.go.quarantine = Some(crate::digest_quarantine::QuarantineMode::Observe);
            cfg.curation.go.quarantine_ttl = Some("3d".to_string());
            cfg.curation.go.allow = allow;
        });
        for v in MATURE {
            let key = format!("go/{MODULE}/@v/{v}.info");
            put_written_days_ago(&ctx, &key, info(v, old).as_bytes(), 30).await;
        }
        (up, ctx)
    }

    async fn get(ctx: &TestContext, file: &str) -> (StatusCode, String, String) {
        let resp = send(&ctx.app, Method::GET, &format!("/go/{MODULE}/{file}"), "").await;
        let status = resp.status();
        let cache = resp
            .headers()
            .get(header::CACHE_CONTROL)
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default();
        let body = String::from_utf8(body_bytes(resp).await.to_vec()).unwrap();
        (status, body, cache)
    }

    fn version_of(info: &str) -> String {
        let json: serde_json::Value = serde_json::from_str(info).unwrap();
        json["Version"].as_str().unwrap().to_string()
    }

    fn all() -> Vec<&'static str> {
        MATURE.iter().chain(&YOUNG).copied().collect()
    }

    #[tokio::test]
    async fn the_version_list_leaves_out_held_versions() {
        let (_up, ctx) = context(&all(), CurationMode::Enforce, &[]).await;
        let (status, body, _) = get(&ctx, "@v/list").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.lines().collect::<Vec<_>>(), MATURE);
        // What is listed is what the gate admits, and the reverse.
        for v in MATURE {
            assert_eq!(
                get(&ctx, &format!("@v/{v}.zip")).await.0,
                StatusCode::OK,
                "{v}"
            );
        }
        for v in YOUNG {
            let zip = get(&ctx, &format!("@v/{v}.zip")).await.0;
            assert_eq!(zip, StatusCode::FORBIDDEN, "{v}");
        }
    }

    #[tokio::test]
    async fn latest_moves_to_the_newest_admitted_release() {
        let (_up, ctx) = context(&all(), CurationMode::Enforce, &[]).await;
        let (status, body, cache) = get(&ctx, "@latest").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(version_of(&body), "v1.1.0");
        assert_eq!(cache, "public, max-age=60, must-revalidate");
    }

    #[tokio::test]
    async fn latest_with_no_admitted_version_is_refused_as_the_zip_is() {
        let (_up, ctx) = context(&YOUNG, CurationMode::Enforce, &[]).await;
        let (status, body, _) = get(&ctx, "@latest").await;
        // 403, not 404: a `GOPROXY=…,direct` client falls back to `direct` only after a 404/410.
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(body.contains("v1.2.0"), "{body}");
        assert_eq!(get(&ctx, "@v/list").await.1, "");
    }

    #[tokio::test]
    async fn a_branch_resolving_to_a_held_pseudo_version_is_refused_as_the_zip_is() {
        let (_up, ctx) = context(&all(), CurationMode::Enforce, &[]).await;
        let (status, body, _) = get(&ctx, "@v/main.info").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(
            get(&ctx, &format!("@v/{PSEUDO}.zip")).await.0,
            StatusCode::FORBIDDEN
        );
        assert!(body.contains(PSEUDO), "{body}");
        let (status, body, _) = get(&ctx, "@v/stable.info").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(version_of(&body), "v1.1.0");
    }

    #[tokio::test]
    async fn an_allowed_version_stays_offered() {
        let allow = [format!("{MODULE}@v1.2.0")];
        let allow: Vec<&str> = allow.iter().map(String::as_str).collect();
        let (_up, ctx) = context(&all(), CurationMode::Enforce, &allow).await;
        let (_, body, _) = get(&ctx, "@v/list").await;
        assert!(body.lines().any(|v| v == "v1.2.0"), "{body}");
        assert!(!body.lines().any(|v| v == "v1.1.1"), "{body}");
        assert_eq!(version_of(&get(&ctx, "@latest").await.1), "v1.2.0");
        assert_eq!(get(&ctx, "@v/v1.2.0.zip").await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn audit_mode_offers_everything_as_the_upstream_does() {
        let (_up, ctx) = context(&all(), CurationMode::Audit, &[]).await;
        let (_, body, _) = get(&ctx, "@v/list").await;
        assert_eq!(body.lines().collect::<Vec<_>>(), all());
        assert_eq!(version_of(&get(&ctx, "@latest").await.1), "v1.2.0");
        assert_eq!(version_of(&get(&ctx, "@v/main.info").await.1), PSEUDO);
    }

    #[test]
    fn go_semver_order() {
        use super::go_semver_cmp;
        use std::cmp::Ordering::{Equal, Greater, Less};
        assert_eq!(go_semver_cmp("v1.3.0-rc.2", "v1.3.0-rc.10"), Less);
        assert_eq!(go_semver_cmp("v1.3.0", "v1.3.0-rc.10"), Greater);
        assert_eq!(go_semver_cmp("v1.10.0", "v1.9.0"), Greater);
        assert_eq!(go_semver_cmp("v1.0.0-alpha", "v1.0.0-alpha.1"), Less);
        assert_eq!(go_semver_cmp("v1.0.0-1", "v1.0.0-alpha"), Less);
        assert_eq!(go_semver_cmp("v2.0.0+incompatible", "v2.0.0"), Equal);
    }
}
