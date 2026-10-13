// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::auth::{enforce_namespace_scope, AuthenticatedUser, NamespaceAuthority};
use crate::circuit_breaker::BreakerScope;
use crate::config::npm_scope_of;
use crate::metrics::{METADATA_CORRUPT_TOTAL, PACKUMENT_REBUILT_TOTAL};
use crate::registry::{
    cache_read, circuit_open_response, method_not_allowed, nora_base_url, proxy_error_response,
    proxy_fetch, proxy_fetch_artifact, proxy_fetch_bytes, proxy_fetch_conditional,
    proxy_fetch_shared, proxy_forward_post, read_cached_artifact, read_validators, validators_key,
    write_validators, CachedArtifact, ProxyBody, ProxyError, Revalidation, Validators,
};
use crate::registry_type::RegistryType;
use crate::AppState;
use axum::{
    body::Bytes,
    extract::{Path, RawQuery, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Extension, Router,
};
use base64::Engine;
use sha2::Digest;
use std::sync::Arc;
use std::time::Duration;

pub fn routes() -> Router<AppState> {
    Router::new().route(
        "/npm/{*path}",
        get(handle_request)
            .put(handle_publish)
            .post(handle_npm_post)
            .delete(handle_npm_delete)
            .fallback(|| async { method_not_allowed("GET, PUT, POST, DELETE") }),
    )
}

/// Max body accepted on the `npm audit` POST. Real audit payloads are well under
/// 1 MB; the global `body_limit_mb` (default 2 GB, for tarball PUTs) must not let a
/// client shove a huge body through NORA into the upstream (#597 SEC).
const NPM_AUDIT_BODY_CAP: usize = 8 * 1024 * 1024;

/// `npm audit` proxy (#597). npm sends its audit request as a POST — npm7 to
/// `/-/npm/v1/security/advisories/bulk` (body `{"<pkg>":["<ver>",…]}`), npm6 to
/// `/-/npm/v1/security/audits/quick` (body = a possibly-gzipped lockfile).
///
/// NORA keeps no advisory DB, so for a remote/proxy repo it forwards the request to
/// the configured upstream and returns the response verbatim. Any other POST path
/// is a 405. Dependency-confusion guard (#68/#733): internal-namespace package
/// names must not leak upstream — see `strip_internal_bulk` / the quick refuse.
async fn handle_npm_post(
    State(state): State<AppState>,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> Response {
    let is_bulk = path == "-/npm/v1/security/advisories/bulk";
    let is_quick = path == "-/npm/v1/security/audits/quick";
    // pnpm posts an npm6 dependency tree here (measured with pnpm 10.17, #1055).
    let is_full = path == "-/npm/v1/security/audits";
    if !is_bulk && !is_quick && !is_full {
        // POST is only meaningful on the audit endpoints.
        return method_not_allowed("GET, PUT");
    }

    // Bound the body AT READ TIME. The global DefaultBodyLimit is 2 GB (for tarball
    // PUTs); audit bodies are <1 MB. `to_bytes` aborts collection past the cap, so a
    // chunked / no-Content-Length client cannot force NORA to buffer gigabytes (#597).
    let body = match axum::body::to_bytes(body, NPM_AUDIT_BODY_CAP).await {
        Ok(b) => b,
        Err(_) => {
            return audit_refused(
                StatusCode::PAYLOAD_TOO_LARGE,
                "audit body is larger than NORA accepts (8 MB)",
            )
        }
    };

    // Only a remote/proxy repo can answer audits (advisories come from upstream).
    // Hosted-only (no proxy) → npm-compatible empty result so `npm audit` doesn't
    // hard-fail — npm treats a 200 `{}` as "no advisories".
    let Some(upstream) = state.config.npm.route(&path) else {
        return npm_empty_audit();
    };

    // #68/#733 dependency-confusion: never send internal package names upstream.
    // #1055: the same holds for scopes owned by a private upstream — the audit goes
    // to the default upstream, which must not learn the private package names.
    // When a namespace filter is configured we must SEE plaintext names to strip
    // them, so ANY body we cannot verify — the quick lockfile, an encoded bulk body,
    // or a bulk body that is not the expected JSON object — is refused (fail CLOSED,
    // symmetric across both paths). With no filter, nothing is internal → forward
    // verbatim.
    let engine = &state.curation().curation_engine;
    let owned_scopes: Vec<&str> = state.config.npm.owned_scopes().collect();
    let filter_active =
        crate::curation::namespace_filter_active(engine) || !owned_scopes.is_empty();
    let encoding = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.eq_ignore_ascii_case("identity"));
    // npm 7+ always gzips the bulk body (measured with real clients, #1055): refusing
    // every encoded body made `npm audit` report no vulnerabilities whenever a filter
    // was active. Gzip is decoded under the same cap and checked like plain JSON; any
    // other encoding, or a body that does not decode, is still refused.
    let mut decoded = false;
    // A body that cannot be checked is refused with a 4xx and a JSON `error` — never
    // `200 {}`, which npm and yarn render as "0 vulnerabilities" (Pavel 10.10). 4xx,
    // not 5xx: pnpm retries a 5xx for about 70 s before failing anyway, and every
    // client prints the error text on a 4xx (kit npm-audit-matrix).
    let forward_body: Vec<u8> = if !filter_active {
        body.to_vec()
    } else if is_quick || is_full {
        return audit_refused(
            StatusCode::UNPROCESSABLE_ENTITY,
            "this audit format carries a whole dependency tree that NORA cannot strip of \
             private or internal package names; use npm 7+ (bulk advisories) or yarn npm audit",
        );
    } else {
        let plain = match encoding {
            None => body.to_vec(),
            Some(enc) if enc.eq_ignore_ascii_case("gzip") => {
                match gunzip_bounded(&body, NPM_AUDIT_BODY_CAP) {
                    Ok(plain) => {
                        decoded = true;
                        plain
                    }
                    Err(GunzipError::TooLarge) => {
                        return audit_refused(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "decompressed audit body is larger than NORA accepts (8 MB)",
                        )
                    }
                    Err(GunzipError::Corrupt(e)) => {
                        tracing::debug!(error = %e, "npm audit: gzip body does not decompress");
                        return audit_refused(
                            StatusCode::UNPROCESSABLE_ENTITY,
                            "audit body says gzip but does not decompress",
                        );
                    }
                }
            }
            Some(_) => {
                return audit_refused(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "audit body encoding is not supported; send it plain or gzip",
                )
            }
        };
        match strip_internal_bulk(&state.storage, &plain, engine, &owned_scopes).await {
            Some(stripped) => stripped,
            None => {
                return audit_refused(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "audit body is not the expected JSON object of package versions",
                )
            }
        }
    };

    // Allowlist the forwarded headers; carry the configured proxy credential only —
    // NEVER the client's Authorization (it's the caller's NORA token).
    let mut fwd: Vec<(&str, &str)> = Vec::new();
    if let Some(v) = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    {
        fwd.push(("content-type", v));
    }
    // A body decoded above goes out as the plain JSON it was checked as.
    if let Some(v) = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .filter(|_| !decoded)
    {
        fwd.push(("content-encoding", v));
    }
    if let Some(v) = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()) {
        fwd.push(("accept", v));
    }

    let url = format!("{}/{}", upstream.url.trim_end_matches('/'), path);
    match proxy_forward_post(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.npm.proxy_timeout),
        upstream.auth,
        &fwd,
        &forward_body,
        &state.circuit_breaker,
        BreakerScope::upstream(RegistryType::Npm, upstream.url),
    )
    .await
    {
        Ok((code, resp_body, resp_ct)) => {
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "proxy", "", "npm", "audit"));
            let status = StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_GATEWAY);
            let ct = resp_ct
                .as_deref()
                .and_then(|v| HeaderValue::from_str(v).ok())
                .unwrap_or_else(|| HeaderValue::from_static("application/json"));
            (status, [(header::CONTENT_TYPE, ct)], resp_body).into_response()
        }
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        // Upstream failure must NOT be masked as `200 {}` — that renders in npm as
        // "0 vulnerabilities" (a false-clean security signal). Surface 502 so npm
        // reports an audit-endpoint error instead (non-fatal to the install), and
        // log it so the failure is observable.
        Err(e) => {
            tracing::warn!(error = ?e, "npm audit upstream forward failed");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// npm-compatible "no advisories" response — a `200 {}` that `npm audit` accepts
/// without erroring.
fn npm_empty_audit() -> Response {
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        b"{}".to_vec(),
    )
        .into_response()
}

/// Why a gzip audit body was not decoded.
#[derive(Debug)]
enum GunzipError {
    /// Not gzip, or a corrupt stream.
    Corrupt(std::io::Error),
    /// Expands past the cap (a small gzip can inflate into gigabytes).
    TooLarge,
}

/// Gunzip an audit body, refusing output past `cap` bytes.
fn gunzip_bounded(data: &[u8], cap: usize) -> Result<Vec<u8>, GunzipError> {
    use std::io::Read;
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data)
        .take(cap as u64 + 1)
        .read_to_end(&mut out)
        .map_err(GunzipError::Corrupt)?;
    if out.len() > cap {
        return Err(GunzipError::TooLarge);
    }
    Ok(out)
}

/// An audit NORA will not forward: the status and a JSON `error` the clients print
/// (npm `npm warn audit <code> … - <error>`, pnpm `responded with <code>: …`,
/// yarn 4 `[Error]: <error>`).
fn audit_refused(status: StatusCode, reason: &str) -> Response {
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        serde_json::json!({ "error": reason }).to_string(),
    )
        .into_response()
}

/// Strip internal-namespace, private-scope and published-here (C24/R2-20) package keys
/// from an npm7 bulk-advisories body (`{"<pkg>":[…]}`). `Some(bytes)` = the (possibly
/// unchanged) body safe to forward; `None` = the body is NOT the expected JSON object,
/// so the caller must fail closed under an active namespace filter (we could not verify
/// no internal name is present).
async fn strip_internal_bulk(
    storage: &crate::Storage,
    body: &[u8],
    engine: &crate::curation::CurationEngine,
    owned_scopes: &[&str],
) -> Option<Vec<u8>> {
    use futures::StreamExt;
    let mut map =
        serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(body).ok()?;
    let before = map.len();
    map.retain(|k, _| {
        let private = npm_scope_of(k).is_some_and(|scope| owned_scopes.contains(&scope));
        !private
            && !crate::curation::is_internal_namespace(
                engine,
                crate::curation::RegistryType::Npm,
                k,
            )
    });
    // One listing per remaining name, concurrently, as a packument rebuild reads.
    let names: Vec<String> = map.keys().cloned().collect();
    let hosted: std::collections::HashSet<String> = futures::stream::iter(names)
        .map(|name| async move { has_local_versions(storage, &name).await.then_some(name) })
        .buffer_unordered(super::SIDECAR_READ_CONCURRENCY)
        .filter_map(|name| async move { name })
        .collect()
        .await;
    map.retain(|k, _| !hosted.contains(k));
    if map.len() == before {
        Some(body.to_vec())
    } else {
        // Re-serializing a just-parsed JSON map cannot fail in practice, but if it
        // ever did, refuse (`None`) rather than fall back to the ORIGINAL body —
        // that still contains the internal names. Keep the invariant fail-closed.
        serde_json::to_vec(&map).ok()
    }
}

/// GitHub Packages' tarball path, `download/<@scope/name>/<version>/<sha1>`: the package
/// name and version, or `None` for any other path. It has no `/-/`, so without this it
/// would be taken for the packument of a package named `download/…` and skip every
/// tarball check, curation included.
fn github_packages_tarball(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("download/")?;
    let mut segments = rest.split('/');
    let (scope, name, version, sha) = (
        segments.next()?,
        segments.next()?,
        segments.next()?,
        segments.next()?,
    );
    if segments.next().is_some()
        || scope.len() < 2
        || !scope.starts_with('@')
        || name.is_empty()
        || version.is_empty()
        || sha.is_empty()
        || !sha.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    Some((&rest[..scope.len() + 1 + name.len()], version))
}

/// Stand-in for `server.public_url` in every stored npm document: published
/// `versions/<v>.json`, regenerated and proxied packuments. [`with_public_base`] swaps
/// it for the current base on every packument serve, so a `public_url` change never
/// strands a tarball URL in storage or behind an upstream 304.
const PUBLIC_BASE: &str = "nora://public-url";

/// Substitute the current `public_url` for [`PUBLIC_BASE`]. A byte scan, not a JSON
/// parse: it runs on every packument serve, and proxied packuments run to megabytes.
fn with_public_base(data: Bytes, nora_base: &str) -> Bytes {
    if memchr::memmem::find(&data, PUBLIC_BASE.as_bytes()).is_none() {
        return data;
    }
    Bytes::from(replace_upstream_bytes(
        &data,
        PUBLIC_BASE,
        nora_base.trim_end_matches('/'),
    ))
}

/// Upstream URL paths a proxied packument keeps on purpose: Sigstore provenance
/// (`versions.*.dist.attestations.url`, `/-/npm/v1/attestations/<pkg>@<ver>`) has no
/// NORA handler, so `npm audit signatures` fetches it from the upstream directly.
/// The bare registry root right before a closing quote (`publishConfig.registry`,
/// `@scope:registry`) is read only by `npm publish` in the author's own tree, never
/// by a client installing the package.
/// One list for the leak detector (`metrics::UPSTREAM_PASSTHROUGH`) and the air-gap
/// invariant test.
pub(crate) const UPSTREAM_PASSTHROUGH_PATHS: &[&str] = &["/-/npm/v1/attestations/", "/\"", "\""];

/// Rewrite tarball URLs in npm metadata to point to NORA.
///
/// Replaces upstream registry URLs (e.g. `https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz`)
/// with NORA URLs (e.g. `http://nora:5000/npm/lodash/-/lodash-4.17.21.tgz`).
///
/// Two-layer approach (#439):
/// 1. Targeted: parse JSON, rewrite `versions.*.dist.tarball`
/// 2. Safety net: byte-level rewrite of every upstream tarball link
///    (`<upstream>/<pkg>/-/<file>`, any package, http or https) in the serialized
///    output: `_resolved`, an http `dist.bin` tarball, a dependency given as another
///    package's tarball URL. Other mentions of the upstream (a readme, the
///    `publishConfig` registry) are left alone.
fn rewrite_tarball_urls(data: &[u8], nora_base: &str, upstream_url: &str) -> Result<Vec<u8>, ()> {
    let mut json: serde_json::Value = serde_json::from_slice(data).map_err(|e| {
        tracing::warn!(error = %e, "npm: JSON parse failed in rewrite_tarball_urls");
    })?;

    let upstream_trimmed = upstream_url.trim_end_matches('/');
    let nora_npm_base = format!("{}/npm", nora_base.trim_end_matches('/'));

    if let Some(versions) = json.get_mut("versions").and_then(|v| v.as_object_mut()) {
        for (_ver, version_data) in versions.iter_mut() {
            if let Some(tarball_url) = version_data
                .get("dist")
                .and_then(|d| d.get("tarball"))
                .and_then(|t| t.as_str())
                .map(|s| s.to_string())
            {
                let rewritten = tarball_url.replace(upstream_trimmed, &nora_npm_base);
                if let Some(dist) = version_data.get_mut("dist") {
                    dist["tarball"] = serde_json::Value::String(rewritten);
                }
            }
        }
    }

    let output = serde_json::to_vec(&json).map_err(|e| {
        tracing::warn!(error = %e, "npm: JSON serialize failed in rewrite_tarball_urls");
    })?;

    // Safety net: byte-level rewrite of any remaining upstream tarball link (#439).
    // Catches edge cases where targeted rewrite missed (e.g. new npm metadata fields).
    Ok(rewrite_upstream_tarball_links(
        &output,
        upstream_trimmed,
        &nora_npm_base,
    ))
}

/// Rewrite every `http(s)://<upstream host+path>/<pkg>/-/<file>` link in `data` to
/// `<nora_npm_base>/<pkg>/-/<file>`, whatever the package: a dependency spec can be
/// another package's upstream tarball URL, and npm fetches it as is.
fn rewrite_upstream_tarball_links(data: &[u8], upstream: &str, nora_npm_base: &str) -> Vec<u8> {
    let Some((_, host)) = upstream.split_once("://").filter(|(_, h)| !h.is_empty()) else {
        return data.to_vec();
    };
    let mut out = Vec::with_capacity(data.len());
    let mut copied = 0;
    for at in memchr::memmem::find_iter(data, host.as_bytes()) {
        let start = match &data[..at] {
            d if d.ends_with(b"https://") => at - 8,
            d if d.ends_with(b"http://") => at - 7,
            _ => continue,
        };
        let path_start = at + host.len();
        let path_end = data[path_start..]
            .iter()
            .position(|b| {
                matches!(b, b'"' | b'\\' | b'\'' | b'<' | b'>' | b')') || b.is_ascii_whitespace()
            })
            .map_or(data.len(), |n| path_start + n);
        if start < copied || !is_tarball_path(&data[path_start..path_end]) {
            continue;
        }
        out.extend_from_slice(&data[copied..start]);
        out.extend_from_slice(nora_npm_base.as_bytes());
        copied = path_start;
    }
    out.extend_from_slice(&data[copied..]);
    out
}

/// `/<pkg>/-/<file>` with `<pkg>` = `name`, `@scope/name` or `@scope%2fname`.
fn is_tarball_path(path: &[u8]) -> bool {
    let Some((pkg, file)) = std::str::from_utf8(path)
        .ok()
        .and_then(|p| p.strip_prefix('/'))
        .and_then(|p| p.split_once("/-/"))
    else {
        return false;
    };
    let name = match pkg.strip_prefix('@') {
        Some(scoped) => scoped
            .split_once('/')
            .or_else(|| scoped.split_once("%2f"))
            .or_else(|| scoped.split_once("%2F"))
            .filter(|(scope, _)| !scope.is_empty())
            .map(|(_, name)| name),
        None => Some(pkg),
    };
    name.is_some_and(|n| !n.is_empty() && !n.contains('/'))
        && !file.is_empty()
        && !file.contains('/')
}

/// Byte-level replace of upstream URL prefix in response body (#439).
///
/// Used as safety net after targeted JSON rewrite, and as fallback when JSON
/// parsing fails. Replaces full URL prefix (e.g. `https://registry.npmjs.org`)
/// rather than bare hostname to avoid corrupting unrelated fields.
fn replace_upstream_bytes(data: &[u8], upstream_url: &str, nora_npm_base: &str) -> Vec<u8> {
    if upstream_url.is_empty() {
        return data.to_vec();
    }
    let needle = upstream_url.as_bytes();
    if memchr::memmem::find(data, needle).is_none() {
        return data.to_vec();
    }
    // Replace all occurrences of the upstream URL prefix
    let replacement = nora_npm_base.as_bytes();
    let mut result = Vec::with_capacity(data.len());
    let mut start = 0;
    let finder = memchr::memmem::Finder::new(needle);
    while let Some(pos) = finder.find(&data[start..]) {
        result.extend_from_slice(&data[start..start + pos]);
        result.extend_from_slice(replacement);
        start += pos + needle.len();
    }
    result.extend_from_slice(&data[start..]);
    result
}

/// npm whoami handler: returns `{"username": "..."}`
async fn handle_whoami(user: &AuthenticatedUser) -> Response {
    // Serialize via serde_json, NOT format!: a username can contain `"` (e.g. the
    // OIDC `sub` claim, which is not charset-validated) and would otherwise break
    // the JSON or inject extra fields into the response.
    axum::Json(serde_json::json!({ "username": user.0 })).into_response()
}

/// `npm search` (`GET /-/v1/search?text=…`): forwarded to the upstream with its query,
/// never cached. The text is free-form, so, as with the audit, nothing is sent while a
/// namespace filter or an owned scope makes some names private: it could carry them.
async fn handle_search(state: &AppState, query: &str) -> Response {
    if crate::curation::namespace_filter_active(&state.curation().curation_engine)
        || state.config.npm.owned_scopes().next().is_some()
    {
        return audit_refused(
            StatusCode::NOT_IMPLEMENTED,
            "npm search is not forwarded while internal namespaces or private scopes are configured",
        );
    }
    let Some(upstream) = state.config.npm.route("-/v1/search") else {
        return audit_refused(StatusCode::NOT_IMPLEMENTED, "npm search needs an upstream");
    };
    let url = format!("{}/-/v1/search?{query}", upstream.url.trim_end_matches('/'));
    match proxy_fetch(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.npm.proxy_timeout),
        upstream.auth,
        &state.circuit_breaker,
        BreakerScope::upstream(RegistryType::Npm, upstream.url),
    )
    .await
    {
        Ok(body) => ([(header::CONTENT_TYPE, "application/json")], body).into_response(),
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(e) => proxy_error_response("npm", &url, &e),
    }
}

// LOCK-SAFE: cache-through proxy — get miss → fetch upstream → put; no RMW race
//
// Q04: a proxied packument is served without versions younger than `min_release_age`
// (see `crate::metadata_filter`), filtered on the full document in hand before it is
// abbreviated (`packument_body`); hosted and internal-namespace packuments as is.
async fn handle_request(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(path): Path<String>,
    RawQuery(query): RawQuery,
    Extension(user): Extension<AuthenticatedUser>,
) -> Response {
    // Handle npm whoami endpoint
    if path == "-/whoami" {
        return handle_whoami(&user).await;
    }
    if path == "-/ping" {
        return axum::Json(serde_json::json!({})).into_response();
    }
    if path == "-/v1/search" {
        return handle_search(&state, query.as_deref().unwrap_or("")).await;
    }

    // `npm dist-tag ls`: answered from local versions only, never proxied (the name
    // would leak upstream).
    if let Some(name) = path
        .strip_prefix("-/package/")
        .and_then(|rest| rest.strip_suffix("/dist-tags"))
    {
        let packument = state
            .storage
            .get(&format!("npm/{name}/metadata.json"))
            .await;
        let tags = match packument {
            Ok(data) if has_local_versions(&state.storage, name).await => {
                serde_json::from_slice::<serde_json::Value>(&data)
                    .ok()
                    .and_then(|p| p.get("dist-tags").cloned())
            }
            _ => None,
        };
        return match tags {
            Some(tags) => axum::Json(tags).into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    // Any other registry endpoint (`-/user/…`, `-/v1/login`, `-/org/…`): never a
    // packument, never proxied (it can carry private names) or cached. `-/-/…` is
    // still the tarball of the package named `-`.
    if path.starts_with("-/") && !path.starts_with("-/-/") {
        return audit_refused(StatusCode::NOT_FOUND, "not supported by this registry");
    }

    let github_packages = github_packages_tarball(&path);
    let is_tarball = github_packages.is_some() || path.contains("/-/");

    let key = if let Some((name, version)) = github_packages {
        // Stored under the npmjs file name of that version, like any other tarball.
        let bare = name.rsplit('/').next().unwrap_or(name);
        format!("npm/{name}/tarballs/{bare}-{version}.tgz")
    } else if is_tarball {
        let parts: Vec<&str> = path.splitn(2, "/-/").collect();
        if parts.len() == 2 {
            format!("npm/{}/tarballs/{}", parts[0], parts[1])
        } else {
            format!("npm/{}", path)
        }
    } else {
        format!("npm/{}/metadata.json", path)
    };
    // A path with an empty segment (`npm//x`, `npm/x/`) would name another package's files
    // and slip past name-based checks (`internal*` does not match `/x`): refuse it before
    // curation, storage or any upstream request sees the name.
    if let Err(e) = crate::validation::validate_storage_key(&key) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let package_name = if let Some((name, _)) = github_packages {
        name.to_string()
    } else if is_tarball {
        path.split("/-/").next().unwrap_or(&path).to_string()
    } else {
        path.clone()
    };

    // Parse tarball version (used for both pre-download and integrity checks)
    let tarball_version = if let Some((_, version)) = github_packages {
        Some(version.to_string())
    } else if is_tarball {
        let filename = path.split("/-/").nth(1).unwrap_or("");
        crate::curation::parse_npm_tarball_version(&package_name, filename)
    } else {
        None
    };

    let internal = crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Npm,
        &package_name,
    );
    // A hosted tarball (internal namespace, or this version published here) is our
    // own publish, not a new upstream artifact: neither curation nor the quarantine
    // holds it (R2-18: its `time` is the local publish time, not an upstream release
    // date), as NuGet's hosted downloads.
    let hosted = is_tarball
        && (internal
            || match tarball_version.as_deref() {
                Some(v) => state
                    .storage
                    .stat(&format!("npm/{package_name}/versions/{v}.json"))
                    .await
                    .is_some(),
                None => false,
            });

    // Upstream release date of the tarball's version, for curation and to seed the
    // digest quarantine's first_seen (#750). Packuments have no version: `None`
    // without any storage read.
    let publish_date = match tarball_version.as_deref() {
        Some(ver) if !hosted => npm_publish_date(&state, &package_name, ver).await,
        _ => None,
    };

    // Curation check — upstream tarball downloads only (metadata passes through).
    // #733: an internal-namespace package is operator-owned — the cache-hit serve below
    // handles a locally-published tarball, and the namespace guard at the cache-miss
    // boundary (below) blocks the upstream branch for internal names.
    if is_tarball && !hosted {
        if let Some(response) = crate::curation::check_download(
            &state.curation().curation_engine,
            state.bypass_token().as_deref(),
            &headers,
            crate::curation::RegistryType::Npm,
            &package_name,
            crate::curation::RequestVersion::of_artifact(tarball_version.as_deref()),
            publish_date,
        ) {
            return response;
        }
    }

    // Resolved here, not at the serve site, so the range branch below can see it.
    let (mut q_mode, q_secs) =
        crate::digest_quarantine::resolve_global(
            state.config.curation.npm.quarantine.as_ref().or(state
                .config
                .curation
                .quarantine
                .as_ref()),
            state.config.curation.npm.quarantine_ttl.as_deref().or(state
                .config
                .curation
                .quarantine_ttl
                .as_deref()),
        );
    if hosted {
        q_mode = crate::digest_quarantine::QuarantineMode::Off;
    }

    // Resumable download (#657): serve the requested bytes from the backend and skip
    // the full read below. Tarballs only — a packument is mutable and has a TTL. A
    // partial read cannot be hashed, so neither the quarantine gate nor the .sha256
    // sidecar / curation integrity checks can run on it: the range serve stands down
    // while quarantine holds artifacts, and integrity is the client's own lockfile
    // hash, as docker does.
    // #1055: in a scope owned by a private upstream, only what that owner delivered
    // (or what was published here) may be served from cache — never a copy cached
    // from another upstream before the scope had an owner.
    let cache_trusted = cached_copy_trusted(
        &state,
        &path,
        &key,
        &package_name,
        tarball_version.as_deref(),
    )
    .await;
    if is_tarball
        && cache_trusted
        && headers.contains_key(header::RANGE)
        && matches!(q_mode, crate::digest_quarantine::QuarantineMode::Off)
    {
        if let Some(meta) = state.storage.stat(&key).await {
            if let Some(response) = crate::registry::range::range_response(
                &state.storage,
                &[&key],
                &headers,
                meta.size,
                "application/octet-stream",
                &[(
                    header::CACHE_CONTROL,
                    "public, max-age=31536000, immutable".to_string(),
                )],
            )
            .await
            {
                if response.status() == StatusCode::PARTIAL_CONTENT {
                    state.metrics.record_download("npm");
                    state.metrics.record_cache_hit("npm");
                }
                return response;
            }
        }
    }

    // Every packument served below gets this base in place of `PUBLIC_BASE`.
    let base = nora_base_url(&state);

    // --- Cache hit path ---
    // get_verified discharges the integrity witness at the serve site (compile-time
    // guarantee — see crate::verified). Both the tarball serve (pinned, Verified arm)
    // and the metadata serve (unpinned, Unpinned arm) flow the discharged bytes. The
    // .sha256 sidecar check below stays: it is the integrity check on S3 (storage
    // pins are local-only).
    let cached = if cache_trusted {
        if is_tarball {
            // A tarball above `server.stream_threshold_mb` streams from storage (C17).
            match read_cached_artifact(&state, "npm", &key, internal).await {
                Ok(Some(CachedArtifact::Buffered(data))) => Some(data),
                Ok(Some(streamed)) => {
                    let gates = TarballGates {
                        package_name: &package_name,
                        version: tarball_version.as_deref(),
                        q_mode: &q_mode,
                        q_secs,
                        publish_date,
                    };
                    return serve_streamed_tarball(&state, &key, streamed, internal, gates).await;
                }
                Ok(None) => None,
                Err(resp) => return resp,
            }
        } else {
            match cache_read(
                state.storage.get_verified(&key).await,
                "npm",
                &key,
                internal,
            ) {
                Ok(cached) => cached.map(|outcome| {
                    use nora_registry::verified::{verified_body, GateOutcome};
                    match outcome {
                        GateOutcome::Verified(blob) => verified_body(blob),
                        GateOutcome::Unpinned(blob) => blob.into_inner(),
                    }
                }),
                Err(resp) => return resp,
            }
        }
    } else {
        None
    };
    if let Some(data) = cached {
        // Metadata TTL: if stale, try to refetch from upstream
        if !is_tarball {
            let ttl = state.config.npm.metadata_ttl;
            if let Some(meta) = state.storage.stat(&key).await {
                if !crate::registry::fresh_within_ttl(&state.storage, &key, meta.modified, ttl)
                    .await
                {
                    // #68 namespace isolation: a stale internal-namespace package must
                    // NOT be revalidated upstream (dependency confusion) — refetch_metadata
                    // proxies the name. Serve the cached copy already in hand instead; an
                    // internal package is owned/hosted locally, never upstream-refreshed.
                    // (The cache-miss proxy path is guarded separately below.)
                    // The same holds for any package published here, internal
                    // namespace or not: an upstream copy must never replace it.
                    if has_local_versions(&state.storage, &package_name).await {
                        return packument_response(
                            &headers,
                            rebase_hosted_tarballs(data, PUBLIC_BASE, &package_name),
                            &base,
                            None,
                        );
                    }
                    if internal {
                        return packument_response(&headers, data, &base, None);
                    }
                    // Single-flight: when a popular packument expires and a CI
                    // fleet stampedes the same key, one request revalidates
                    // upstream and the rest serve its in-memory result (#595).
                    let fresh = if state.config.server.proxy_coalesce {
                        let budget =
                            crate::proxy_coalesce::follower_budget(state.config.npm.proxy_timeout);
                        state
                            .proxy_coalesce
                            .coalesced(&key, "npm", budget, || async {
                                refetch_metadata(&state, &path, &key).await
                            })
                            .await
                    } else {
                        refetch_metadata(&state, &path, &key).await
                    };
                    // Filtered on this fresh document, `time` included: the cached
                    // copy may predate the version it brings (R2-16).
                    let curation = state.curation();
                    let hide = Some((&curation.curation_engine, path.as_str()));
                    if let Some(fresh) = fresh {
                        return packument_response(&headers, fresh, &base, hide);
                    }
                    // Upstream failed — serve stale if configured, otherwise 502
                    if state.config.npm.serve_stale {
                        tracing::warn!(
                            registry = "npm",
                            path = %path,
                            "npm upstream unavailable, serving stale metadata"
                        );
                        // Degraded, but still the representation that was asked
                        // for: body and Content-Type must agree here too.
                        let (stale_body, stale_type) = packument_body(&headers, data, &base, hide);
                        return (
                            StatusCode::OK,
                            [
                                (
                                    header::CONTENT_TYPE,
                                    axum::http::HeaderValue::from_static(stale_type),
                                ),
                                (header::VARY, axum::http::HeaderValue::from_static("Accept")),
                                (
                                    header::CACHE_CONTROL,
                                    axum::http::HeaderValue::from_static(
                                        "public, max-age=0, must-revalidate",
                                    ),
                                ),
                                (
                                    axum::http::header::HeaderName::from_static("x-nora-stale"),
                                    axum::http::HeaderValue::from_static("true"),
                                ),
                            ],
                            stale_body.to_vec(),
                        )
                            .into_response();
                    }
                    return StatusCode::BAD_GATEWAY.into_response();
                }
            }
            // Fresh: a proxied packument is filtered; one published here is not.
            let hosted_packument = !internal
                && state.curation().curation_engine.metadata_filter_active()
                && has_local_versions(&state.storage, &package_name).await;
            let curation = state.curation();
            let hide = (!internal && !hosted_packument)
                .then_some((&curation.curation_engine, path.as_str()));
            return packument_response(&headers, data, &base, hide);
        }

        // Tarball: integrity check if hash exists
        let hash_key = format!("{}.sha256", key);
        if let Ok(stored_hash) = state.storage.get(&hash_key).await {
            let computed = hex::encode(sha2::Sha256::digest(&data));
            let expected = String::from_utf8_lossy(&stored_hash);
            if computed != expected.as_ref() {
                tracing::error!(
                    key = %key,
                    expected = %expected,
                    computed = %computed,
                    "SECURITY: npm tarball integrity check FAILED — possible tampering"
                );
                return (StatusCode::INTERNAL_SERVER_ERROR, "Integrity check failed")
                    .into_response();
            }
        }

        // Curation integrity verification (issue #189)
        if let Some(response) = crate::curation::verify_integrity(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Npm,
            &package_name,
            tarball_version.as_deref(),
            &data,
        ) {
            return response;
        }

        state.metrics.record_download("npm");
        state.metrics.record_cache_hit("npm");
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            package_name,
            crate::registry_type::RegistryType::Npm,
            "CACHE",
        ));
        state
            .audit
            .log(AuditEntry::new("cache_hit", "proxy", "", "npm", ""));
        if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
            &state.digest_store,
            "npm",
            &data,
            &q_mode,
            q_secs,
            "cache",
            publish_date,
        ) {
            return resp;
        }
        let mut response = with_content_type(true, data).into_response();
        response
            .headers_mut()
            .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        return response;
    }

    // --- Hosted packument rebuild (#956) ---
    // The packument is derived state: `versions/{v}.json` are the immutable
    // originals and `metadata.json` is only their assembled form. When the
    // assembled form is absent — direct-storage import, a migration, an operator
    // deleting a derived object — the package is still fully described by the keys
    // that remain, and `regenerate_packument` already knows how to reassemble it.
    // Rebuild here rather than falling through to the proxy, which would answer
    // 404 for a package that exists only in this registry.
    //
    // Runs before the namespace guard on purpose: serving locally-owned bytes is
    // always allowed, and the guard exists to stop the *upstream* fetch below.
    // Whether this package has locally published versions. Read once here and kept
    // for the proxy branch below, which must not cache an upstream packument over a
    // key that a local rebuild owns (#975).
    let mut local_versions = false;
    if !is_tarball {
        let has_versions = has_local_versions(&state.storage, &package_name).await;
        local_versions = has_versions;

        if has_versions {
            // Same lock the publish path takes: a CI fleet stampeding one package
            // rebuilds it once, not once per request.
            let lock = state.publish_lock(&key);
            let _guard = lock.lock().await;

            // A concurrent request may have rebuilt it while this one waited.
            let data = match state.storage.get(&key).await {
                Ok(data) => Some(data),
                Err(_) => match regenerate_packument(&state.storage, &package_name).await {
                    Ok(()) => state.storage.get(&key).await.ok(),
                    Err(()) => {
                        tracing::warn!(
                            registry = "npm",
                            package = %package_name,
                            "packument rebuild failed; falling through"
                        );
                        None
                    }
                },
            };

            if let Some(data) = data {
                PACKUMENT_REBUILT_TOTAL.with_label_values(&["npm"]).inc();
                tracing::info!(
                    registry = "npm",
                    package = %package_name,
                    "Rebuilt packument from per-version keys"
                );
                state.metrics.record_cache_hit("npm");
                return packument_response(
                    &headers,
                    rebase_hosted_tarballs(data, PUBLIC_BASE, &package_name),
                    &base,
                    None,
                );
            }
        }
    }

    // --- Namespace isolation: prevent proxying internal namespaces ---
    // Metadata requests skip the curation check_download (which only runs for
    // tarballs), so we must protect the proxy path separately. This runs after
    // cache lookup so locally-published packages are still served from cache.
    if let Some(response) = crate::curation::check_namespace_isolation(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Npm,
        &package_name,
    ) {
        return response;
    }
    // C24/R2-20: a package published here owns its name. A tarball of a version it
    // does not have is not fetched upstream, where the name may be someone else's
    // (and would learn of ours).
    if is_tarball && (hosted || has_local_versions(&state.storage, &package_name).await) {
        return StatusCode::NOT_FOUND.into_response();
    }

    // --- Proxy fetch path ---
    if let Some(upstream) = state.config.npm.route(&path) {
        let proxy_url = upstream.url;
        let url = format!("{}/{}", proxy_url.trim_end_matches('/'), path);

        let timeout = state.config.npm.proxy_timeout;
        let scope = BreakerScope::upstream(RegistryType::Npm, upstream.url);
        let result = if is_tarball {
            // A tarball above `server.stream_threshold_mb` is spooled to disk (C17).
            proxy_fetch_artifact(&state, &key, "npm", &url, timeout, upstream.auth, scope).await
        } else {
            let fetch = proxy_fetch_bytes(
                &state.http_client,
                &url,
                Duration::from_secs(timeout),
                upstream.auth,
                &state.circuit_breaker,
                scope,
            );
            proxy_fetch_shared(&state, &key, "npm", timeout, fetch)
                .await
                .map(|(data, fetched)| (ProxyBody::Mem(data), fetched))
        };
        match result {
            Ok((spooled @ ProxyBody::File(_), fetched)) => {
                let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
                    state.config.curation.npm.quarantine.as_ref().or(state
                        .config
                        .curation
                        .quarantine
                        .as_ref()),
                    state.config.curation.npm.quarantine_ttl.as_deref().or(state
                        .config
                        .curation
                        .quarantine_ttl
                        .as_deref()),
                );
                let gates = TarballGates {
                    package_name: &package_name,
                    version: tarball_version.as_deref(),
                    q_mode: &q_mode,
                    q_secs,
                    publish_date,
                };
                let origin = fetched.then(|| origin_of(proxy_url));
                return serve_spooled_tarball(&state, &key, &url, spooled, origin, gates).await;
            }
            Ok((ProxyBody::Mem(data), fetched)) => {
                let data_to_cache;
                let data_to_serve;

                if is_tarball {
                    // Curation integrity runs on the first serve too, not only on cache
                    // hits: a blocked body is neither served nor cached.
                    if let Some(response) = crate::curation::verify_integrity(
                        &state.curation().curation_engine,
                        crate::curation::RegistryType::Npm,
                        &package_name,
                        tarball_version.as_deref(),
                        &data,
                    ) {
                        return response;
                    }
                    // Compute and store sha256
                    if fetched {
                        let hash = hex::encode(sha2::Sha256::digest(&data));
                        let hash_key = format!("{}.sha256", key);
                        let storage = state.storage.clone();
                        tokio::spawn(async move {
                            if let Err(e) = storage.put(&hash_key, hash.as_bytes()).await {
                                tracing::warn!(key = %hash_key, error = ?e, "npm proxy: failed to cache hash sidecar");
                            }
                        });
                    }

                    state.metrics.record_download("npm");
                    state.metrics.record_cache_miss("npm");
                    state.activity.push(ActivityEntry::new(
                        ActionType::ProxyFetch,
                        package_name,
                        crate::registry_type::RegistryType::Npm,
                        "PROXY",
                    ));
                    state
                        .audit
                        .log(AuditEntry::new("proxy_fetch", "proxy", "", "npm", ""));

                    data_to_cache = data.clone();
                    data_to_serve = data;
                } else {
                    // Metadata: rewrite tarball URLs to point to NORA
                    let nora_base = PUBLIC_BASE;
                    let rewritten = rewrite_tarball_urls(&data, nora_base, proxy_url)
                        .unwrap_or_else(|()| {
                            tracing::warn!(
                                path = %path,
                                "npm metadata JSON parse failed, using byte-level URL rewrite"
                            );
                            let upstream_trimmed = proxy_url.trim_end_matches('/');
                            let nora_npm_base = format!("{}/npm", nora_base.trim_end_matches('/'));
                            replace_upstream_bytes(&data, upstream_trimmed, &nora_npm_base)
                        });

                    let rewritten = Bytes::from(rewritten);
                    data_to_cache = rewritten.clone();
                    data_to_serve = rewritten;
                }

                // #975: `npm/{name}/metadata.json` belongs to the local rebuild whenever
                // `versions/` is non-empty — it is the assembled form of keys this
                // registry owns. Reaching here on the metadata path with local versions
                // present means the rebuild above fell through (its write failed, or the
                // read-back missed), and caching the upstream document at that key would
                // drop every locally published version from the packument. It would also
                // land unserialized against the `publish_lock` released a few lines above,
                // so a concurrent publish could be overwritten. The upstream bytes are
                // still served for this request; only the write is skipped, so the next
                // request retries the rebuild instead of finding a wrong document cached.
                let owns_key_locally = !is_tarball && local_versions;
                if !fetched {
                    // A concurrent request fetched these bytes and caches them.
                } else if owns_key_locally {
                    tracing::warn!(
                        registry = "npm",
                        key = %key,
                        "serving upstream packument without caching: local versions own this key"
                    );
                } else if !is_tarball {
                    // LOCK-SAFE: `!has_local_versions` here, so the `publish_lock` above
                    // was never taken on this path.
                    //
                    // Awaited, not spawned: the tarball requests that follow date their
                    // version from this document, and a write still in flight sent each
                    // of them upstream for the packument again (R2-11, R2-40).
                    if let Err(e) =
                        cache_packument(&state.storage, &path, data_to_cache, &origin_of(proxy_url))
                            .await
                    {
                        tracing::warn!(key = %key, error = ?e, "npm proxy: failed to cache metadata");
                    }
                } else {
                    // LOCK-SAFE: a tarball; the `publish_lock` above guards packuments
                    // only and was never taken on this path.
                    //
                    // Cache in background, invalidate index AFTER write completes
                    let storage = state.storage.clone();
                    let key_clone = key.clone();
                    let repo_index = Arc::clone(&state.repo_index);
                    let origin = origin_of(proxy_url);
                    tokio::spawn(async move {
                        if let Err(e) =
                            put_with_origin(&storage, &key_clone, data_to_cache, &origin).await
                        {
                            tracing::warn!(key = %key_clone, error = ?e, "npm proxy: failed to cache artifact");
                        } else {
                            repo_index.invalidate("npm");
                        }
                    });
                }

                if is_tarball {
                    let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
                        state.config.curation.npm.quarantine.as_ref().or(state
                            .config
                            .curation
                            .quarantine
                            .as_ref()),
                        state.config.curation.npm.quarantine_ttl.as_deref().or(state
                            .config
                            .curation
                            .quarantine_ttl
                            .as_deref()),
                    );
                    if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
                        &state.digest_store,
                        "npm",
                        &data_to_serve,
                        &q_mode,
                        q_secs,
                        &url,
                        publish_date,
                    ) {
                        return resp;
                    }
                }
                if is_tarball {
                    return with_content_type(true, data_to_serve).into_response();
                }
                let curation = state.curation();
                let hide = (!local_versions).then_some((&curation.curation_engine, path.as_str()));
                return packument_response(&headers, data_to_serve, &base, hide);
            }
            Err(ProxyError::CircuitOpen(reg)) => return circuit_open_response(&reg),
            // The upstream answered "no such package": a real 404.
            Err(ProxyError::NotFound) => {}
            // The upstream is down, slow, throttling or refusing us: a gateway failure,
            // not a missing package — npm retries a 5xx and reports E502 instead of E404 (#1055).
            Err(e) => return proxy_error_response("npm", &url, &e),
        }
    }

    StatusCode::NOT_FOUND.into_response()
}

/// Internal prefix holding npm cache provenance sidecars (#1055).
pub(crate) const ORIGINS_PREFIX: &str = ".nora-origins/";

/// Provenance sidecar of a cached npm object: which upstream delivered it (#1055).
///
/// `<key>` → `.nora-origins/<key>`: one-to-one, and outside every registry's key space
/// — every npm key starts with `npm/`, so no request can read or overwrite a sidecar,
/// and listings hide `.nora-` keys, so no retention, GC, UI or stats walk of this or an
/// older release counts one. A sidecar next to its tarball made 1.3.3's retention keep
/// fewer real versions after a rollback (measured: keep_last=2 kept one).
pub(crate) fn origin_key(key: &str) -> String {
    format!("{ORIGINS_PREFIX}{key}")
}

/// The cached object a provenance sidecar describes — the inverse of [`origin_key`].
pub(crate) fn origin_primary(sidecar: &str) -> Option<&str> {
    sidecar
        .strip_prefix(ORIGINS_PREFIX)
        .filter(|key| key.starts_with("npm/"))
}

/// The identity recorded in the sidecar — the breaker's canonical upstream key, so
/// userinfo and a trailing slash do not make one upstream look like two.
fn origin_of(upstream_url: &str) -> String {
    crate::circuit_breaker::upstream_key("npm", upstream_url)
}

/// Cache an upstream object, then record where it came from. Data first: a sidecar
/// that exists always describes bytes already written; a failed sidecar write only
/// costs a refetch.
async fn put_with_origin(
    storage: &crate::Storage,
    key: &str,
    data: impl Into<Bytes>,
    origin: &str,
) -> Result<(), crate::storage::StorageError> {
    let data = data.into();
    let record = provenance_record(origin, &data);
    storage.put_bytes(key, data).await?;
    if let Err(e) = storage.put(&origin_key(key), record.as_bytes()).await {
        tracing::warn!(key = %key, error = ?e, "npm: failed to record cache provenance");
    }
    Ok(())
}

/// Inputs of the tarball gates (curation integrity, digest quarantine).
struct TarballGates<'a> {
    package_name: &'a str,
    version: Option<&'a str>,
    q_mode: &'a crate::digest_quarantine::QuarantineMode,
    q_secs: i64,
    publish_date: Option<i64>,
}

impl TarballGates<'_> {
    /// Curation integrity, then the digest quarantine, on the tarball's digest.
    fn check(&self, state: &AppState, digest: &str, upstream: &str) -> Option<Response> {
        let engine = &state.curation().curation_engine;
        if engine.is_active() {
            if let Some(response) = crate::curation::verify_integrity_by_hash(
                engine,
                crate::curation::RegistryType::Npm,
                self.package_name,
                self.version,
                digest,
            ) {
                return Some(response);
            }
        }
        crate::digest_quarantine::proxy_gate_digest(
            &state.digest_store,
            "npm",
            digest,
            self.q_mode,
            self.q_secs,
            upstream,
            self.publish_date,
        )
    }
}

/// A tarball response with a streamed body of `len` bytes.
fn tarball_stream_response(body: axum::body::Body, len: u64) -> Response {
    let mut response = (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        body,
    )
        .into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    response
}

/// Cache hit on a tarball too big to buffer (C17): the gates run on its pin, and the
/// body streams from storage, checked against the pin as it goes.
async fn serve_streamed_tarball(
    state: &AppState,
    key: &str,
    cached: CachedArtifact,
    internal: bool,
    gates: TarballGates<'_>,
) -> Response {
    let digest = cached.digest();
    // The legacy .sha256 sidecar must agree with the pin the stream is checked against.
    if let Ok(stored_hash) = state.storage.get(&format!("{key}.sha256")).await {
        if digest.strip_prefix("sha256:") != Some(String::from_utf8_lossy(&stored_hash).as_ref()) {
            tracing::error!(key = %key, "SECURITY: npm tarball integrity check FAILED — possible tampering");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Integrity check failed").into_response();
        }
    }
    if let Some(response) = gates.check(state, &digest, "cache") {
        return response;
    }
    state.metrics.record_download("npm");
    state.metrics.record_cache_hit("npm");
    state.activity.push(ActivityEntry::new(
        ActionType::CacheHit,
        gates.package_name.to_string(),
        crate::registry_type::RegistryType::Npm,
        "CACHE",
    ));
    state
        .audit
        .log(AuditEntry::new("cache_hit", "proxy", "", "npm", ""));
    let len = cached.len();
    tarball_stream_response(cached.into_body(state, "npm", key, internal), len)
}

/// Cold miss on a tarball spooled to disk (C17). `origin` is set for the caller
/// that fetched it, which caches it with its `.sha256` and provenance sidecars.
async fn serve_spooled_tarball(
    state: &AppState,
    key: &str,
    url: &str,
    body: ProxyBody,
    origin: Option<String>,
    gates: TarballGates<'_>,
) -> Response {
    let digest = body.digest();
    let engine = &state.curation().curation_engine;
    if engine.is_active() {
        if let Some(response) = crate::curation::verify_integrity_by_hash(
            engine,
            crate::curation::RegistryType::Npm,
            gates.package_name,
            gates.version,
            &digest,
        ) {
            return response;
        }
    }
    if let Some(origin) = origin {
        let state = state.clone();
        let (key, body, sha) = (key.to_string(), body.clone(), body.sha256());
        tokio::spawn(async move {
            let (storage, repo_index) = (&state.storage, &state.repo_index);
            if let Err(e) = body.cache(&state, &key, false).await {
                tracing::warn!(key = %key, error = ?e, "npm proxy: failed to cache artifact");
                return;
            }
            let _ = storage.put(&format!("{key}.sha256"), sha.as_bytes()).await;
            let record = format!("{origin}\n{sha}");
            if let Err(e) = storage.put(&origin_key(&key), record.as_bytes()).await {
                tracing::warn!(key = %key, error = ?e, "npm: failed to record cache provenance");
            }
            repo_index.invalidate("npm");
        });
    }
    state.metrics.record_download("npm");
    state.metrics.record_cache_miss("npm");
    state.activity.push(ActivityEntry::new(
        ActionType::ProxyFetch,
        gates.package_name.to_string(),
        crate::registry_type::RegistryType::Npm,
        "PROXY",
    ));
    state
        .audit
        .log(AuditEntry::new("proxy_fetch", "proxy", "", "npm", ""));
    if let Some(response) = crate::digest_quarantine::proxy_gate_digest(
        &state.digest_store,
        "npm",
        &digest,
        gates.q_mode,
        gates.q_secs,
        url,
        gates.publish_date,
    ) {
        return response;
    }
    let len = body.len();
    match body.into_body(key).await {
        Ok(body) => tarball_stream_response(body, len),
        Err(e) => {
            tracing::warn!(key = %key, error = %e, "npm: spooled tarball unreadable");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// The provenance record of `data` cached from `origin`: the upstream identity, then
/// the SHA-256 of exactly these bytes. The digest makes a record vouch only for the
/// bytes it was written with: whatever replaces the object later — an older release
/// after a rollback, which knows nothing of these records — changes the object's
/// pin, and the record no longer matches it.
fn provenance_record(origin: &str, data: &[u8]) -> String {
    format!("{origin}\n{}", hex::encode(sha2::Sha256::digest(data)))
}

/// May the cached copy at `key` be served for `path`?
///
/// Outside scopes owned by an `npm.proxies` entry: yes, as before. Inside one: only
/// what that owner delivered (sidecar names it) or what was published here
/// (`versions/` keys). A copy cached from another upstream — a squatter on the public
/// registry cached before the scope got an owner, any cache from before provenance
/// was recorded, or bytes that replaced the owner's after its record was written —
/// is treated as absent: refetched from the owner, and never served as a stale
/// fallback when the owner is down.
async fn cached_copy_trusted(
    state: &AppState,
    path: &str,
    key: &str,
    package_name: &str,
    tarball_version: Option<&str>,
) -> bool {
    let Some(scope) = npm_scope_of(path) else {
        return true;
    };
    if !state.config.npm.owned_scopes().any(|owned| owned == scope) {
        return true;
    }
    let published_here = match tarball_version {
        Some(version) => state
            .storage
            .stat(&format!("npm/{package_name}/versions/{version}.json"))
            .await
            .is_some(),
        None => !state
            .storage
            .list(&format!("npm/{package_name}/versions/"))
            .await
            .unwrap_or_default()
            .is_empty(),
    };
    if published_here {
        return true;
    }
    let Some(owner) = state.config.npm.route(path) else {
        return false;
    };
    let Ok(recorded) = state.storage.get(&origin_key(key)).await else {
        return false;
    };
    let Some((origin, digest)) = std::str::from_utf8(&recorded)
        .ok()
        .and_then(|record| record.split_once('\n'))
    else {
        return false;
    };
    origin == origin_of(owner.url) && state.storage.pin(key).await.as_deref() == Some(digest)
}

/// Whether `name` has versions published here. Such a packument is owned locally:
/// it is never revalidated against, or overwritten by, an upstream document.
async fn has_local_versions(storage: &crate::Storage, name: &str) -> bool {
    !storage
        .list(&format!("npm/{name}/versions/"))
        .await
        .unwrap_or_default()
        .is_empty()
}

/// Point every `dist.tarball` of a hosted packument at the current `public_url`:
/// publish stores the URL absolute, so a host/scheme/prefix change would strand it.
fn rebase_hosted_tarballs(data: Bytes, nora_base: &str, name: &str) -> Bytes {
    let Ok(mut packument) = serde_json::from_slice::<serde_json::Value>(&data) else {
        return data;
    };
    let prefix = format!("{}/npm/{name}/-/", nora_base.trim_end_matches('/'));
    let mut changed = false;
    let versions = packument
        .get_mut("versions")
        .and_then(|v| v.as_object_mut());
    for version in versions.into_iter().flat_map(|v| v.values_mut()) {
        changed |= rebase_tarball(version, &prefix);
    }
    match changed.then(|| serde_json::to_vec(&packument)) {
        Some(Ok(bytes)) => Bytes::from(bytes),
        _ => data,
    }
}

/// Point one version's `dist.tarball` at `<prefix><file>`; whether it changed.
fn rebase_tarball(version: &mut serde_json::Value, prefix: &str) -> bool {
    let Some(tarball) = version.pointer_mut("/dist/tarball") else {
        return false;
    };
    let Some(file) = tarball
        .as_str()
        .and_then(|t| t.rsplit_once("/-/"))
        .map(|(_, f)| f)
    else {
        return false;
    };
    let rebased = format!("{prefix}{file}");
    if tarball.as_str() == Some(rebased.as_str()) {
        return false;
    }
    *tarball = serde_json::Value::String(rebased);
    true
}

/// Refetch metadata from upstream, rewrite URLs, update cache.
/// Returns None if upstream is unavailable (caller serves stale cache).
async fn refetch_metadata(state: &AppState, path: &str, key: &str) -> Option<Bytes> {
    let upstream = state.config.npm.route(path)?;
    let proxy_url = upstream.url;
    let url = format!("{}/{}", proxy_url.trim_end_matches('/'), path);

    // Revalidate with a conditional request when enabled and we have stored
    // validators. Empty validators ⇒ no conditional headers ⇒ always a 200,
    // which is also how the first fetch captures validators for next time (#596).
    let validators = if state.config.npm.revalidate {
        read_validators(&state.storage, key)
            .await
            .unwrap_or_default()
    } else {
        Validators::default()
    };
    let had_validators = validators.is_some();

    match proxy_fetch_conditional(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.npm.proxy_timeout),
        upstream.auth,
        &validators,
        &state.circuit_breaker,
        BreakerScope::upstream(RegistryType::Npm, upstream.url),
    )
    .await
    {
        // Upstream unchanged — serve the cached (already-rewritten) body and
        // record the revalidation so we don't revalidate again until the next TTL
        // window. No body was downloaded, and none is re-uploaded (C56).
        Ok(Revalidation::NotModified) => {
            match state.storage.get(key).await {
                Ok(cached) => {
                    crate::metrics::PROXY_UPSTREAM_304_TOTAL
                        .with_label_values(&["npm"])
                        .inc();
                    crate::metrics::PROXY_REVALIDATION_BYTES_SAVED_TOTAL
                        .with_label_values(&["npm"])
                        .inc_by(cached.len() as u64);
                    // Cached before PUBLIC_BASE: its tarball URLs carry the public_url
                    // of that day, and a 304 would keep them forever. Without
                    // validators the next revalidation refetches it in the current form.
                    // ponytail: a packument with no tarball NORA rewrites never carries
                    // PUBLIC_BASE, so it loses conditional revalidation.
                    if memchr::memmem::find(&cached, PUBLIC_BASE.as_bytes()).is_none() {
                        let _ = state.storage.delete(&validators_key(key)).await;
                    }
                    let storage = state.storage.clone();
                    let key_clone = key.to_string();
                    tokio::spawn(async move {
                        crate::registry::mark_revalidated(&storage, "npm", &key_clone).await;
                    });
                    Some(cached)
                }
                Err(_) => {
                    // Body gone (GC, retention, corruption). Delete the stale
                    // validator sidecar so the next revalidation cycle does a
                    // full unconditional fetch instead of looping on 304 (#867).
                    let vkey = validators_key(key);
                    let _ = state.storage.delete(&vkey).await;
                    tracing::warn!(
                        key = %key,
                        "304 but cached body missing; cleared validators for full refetch"
                    );
                    None
                }
            }
        }
        // New body — rewrite, cache it, then persist the fresh validators.
        Ok(Revalidation::Modified { body, validators }) => {
            // A publish may have landed since the caller checked: never let the
            // upstream document replace a packument this registry owns.
            if has_local_versions(&state.storage, path).await {
                return None;
            }
            let nora_base = PUBLIC_BASE;
            let rewritten =
                rewrite_tarball_urls(&body, nora_base, proxy_url).unwrap_or_else(|()| {
                    tracing::warn!(
                        path = %path,
                        "npm metadata refetch: JSON parse failed, using byte-level URL rewrite"
                    );
                    let upstream_trimmed = proxy_url.trim_end_matches('/');
                    let nora_npm_base = format!("{}/npm", nora_base.trim_end_matches('/'));
                    replace_upstream_bytes(&body, upstream_trimmed, &nora_npm_base)
                });

            let rewritten = Bytes::from(rewritten);
            // Awaited: the tarball requests that follow date their version from the
            // cached document (R2-16). Body first; the validator sidecar must never
            // advertise freshness for a body that isn't there (#596).
            match cache_packument(
                &state.storage,
                path,
                rewritten.clone(),
                &origin_of(proxy_url),
            )
            .await
            {
                Ok(()) => write_validators(&state.storage, key, &validators).await,
                Err(e) => {
                    tracing::warn!(key = %key, error = ?e, "npm proxy: failed to cache metadata")
                }
            }

            Some(rewritten)
        }
        // Upstream unavailable / error — fall back to the caller's serve_stale /
        // 502 path exactly as before.
        Err(_) => {
            if had_validators {
                crate::metrics::PROXY_REVALIDATION_ERRORS_TOTAL
                    .with_label_values(&["npm"])
                    .inc();
            }
            None
        }
    }
}

// ============================================================================
// npm publish
// ============================================================================

/// Validate attachment filename: only safe characters, no path traversal.
pub(crate) fn is_valid_attachment_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains("..")
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@'))
}

async fn handle_publish(
    State(state): State<AppState>,
    Path(path): Path<String>,
    Extension(authority): Extension<NamespaceAuthority>,
    user: Option<Extension<crate::auth::AuthenticatedUser>>,
    super::PublishBody(body): super::PublishBody,
) -> Response {
    if let Some(rest) = path.strip_prefix("-/package/") {
        // `npm dist-tag add`: the body is the version, as a JSON string.
        let Ok(version) = serde_json::from_slice::<String>(&body) else {
            return (
                StatusCode::BAD_REQUEST,
                "dist-tag body must be a JSON string",
            )
                .into_response();
        };
        return set_dist_tag(&state, &authority, &user, rest, Some(&version)).await;
    }
    // `npm login` / `npm adduser` (CouchDB user document): NORA has no user database.
    if path.starts_with("-/user/") {
        return audit_refused(StatusCode::METHOD_NOT_ALLOWED, NPM_LOGIN_UNSUPPORTED);
    }
    if let Some((name, _rev)) = path.rsplit_once("/-rev/") {
        return unpublish_put(&state, &authority, &user, name, &body).await;
    }
    let package_name = path;

    // Enforce OIDC namespace_scope on the package coordinate (#583).
    if enforce_namespace_scope(&authority, &package_name).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }

    let payload: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("Invalid JSON: {}", e)).into_response(),
    };
    // The parsed payload holds everything needed; free the raw body before decoding.
    drop(body);

    // Security: verify payload name matches URL path (required field)
    match payload.get("name").and_then(|n| n.as_str()) {
        Some(payload_name) if payload_name == package_name => {}
        Some(payload_name) => {
            tracing::warn!(
                url_name = %package_name,
                payload_name = %payload_name,
                "SECURITY: npm publish name mismatch — possible spoofing attempt"
            );
            return (
                StatusCode::BAD_REQUEST,
                "Package name in URL does not match payload",
            )
                .into_response();
        }
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "Missing required 'name' field in publish payload",
            )
                .into_response();
        }
    }

    let attachments = match payload.get("_attachments").and_then(|a| a.as_object()) {
        Some(a) if !a.is_empty() => a,
        // `npm deprecate` PUTs the packument back without attachments.
        _ if has_local_versions(&state.storage, &package_name).await => {
            return deprecate_versions(&state, &user, &package_name, &payload).await;
        }
        _ => return (StatusCode::BAD_REQUEST, "Missing _attachments").into_response(),
    };

    // Decode the attachments: scoped packages (e.g. @scope/name) may have attachment
    // filenames like "@scope/name-1.0.0.tgz". Strip the scope prefix since it is
    // already captured in the package name — the filename part must be a flat name
    // without path separators to prevent path traversal.
    let mut tarballs = Vec::with_capacity(attachments.len());
    for (filename, attachment_data) in attachments {
        let normalized_name = if let Some(scope_end) = package_name.find('/') {
            let scope_prefix = &package_name[..=scope_end];
            filename.strip_prefix(scope_prefix).unwrap_or(filename)
        } else {
            filename
        };

        if !is_valid_attachment_name(normalized_name) {
            tracing::warn!(
                filename = %filename,
                package = %package_name,
                "SECURITY: npm publish rejected — invalid attachment filename"
            );
            return (StatusCode::BAD_REQUEST, "Invalid attachment filename").into_response();
        }

        let base64_data = match attachment_data.get("data").and_then(|d| d.as_str()) {
            Some(d) => d,
            None => continue,
        };

        match base64::engine::general_purpose::STANDARD.decode(base64_data) {
            Ok(b) => tarballs.push((normalized_name.to_string(), Bytes::from(b))),
            Err(_) => {
                return (StatusCode::BAD_REQUEST, "Invalid base64 in attachment").into_response()
            }
        }
    }

    // Lock per package to serialize the packument regeneration within one process.
    let lock = state.publish_lock(&format!("npm/{}/metadata.json", package_name));
    let _guard = lock.lock().await;
    if let Err(e) = publish_versions(
        &state.storage,
        &state.publish_locks,
        &package_name,
        &payload,
        tarballs,
    )
    .await
    {
        return e.into_response();
    }

    state.metrics.record_upload("npm");
    state.audit.log(AuditEntry::new(
        "push",
        crate::auth::audit_actor(&user),
        &package_name,
        "npm",
        "",
    ));
    state.activity.push(ActivityEntry::new(
        ActionType::Push,
        package_name,
        crate::registry_type::RegistryType::Npm,
        "LOCAL",
    ));
    state.repo_index.invalidate("npm");

    StatusCode::CREATED.into_response()
}

/// The storage half of `npm publish`, shared with `nora import`: refuse on a corrupt
/// packument or a version that exists or existed, then write the tarballs (attachment
/// name, bytes), each new version as its own key with its publish time, the dist-tags
/// and package fields of `payload`, regenerate the packument and check that it lists
/// the new versions; on a failure after the first write, undo them (R2-21). The
/// caller holds the package's publish lock.
pub(crate) async fn publish_versions(
    storage: &crate::storage::Storage,
    locks: &crate::PublishLocks,
    package_name: &str,
    payload: &serde_json::Value,
    tarballs: Vec<(String, Bytes)>,
) -> Result<(), (StatusCode, String)> {
    let new_versions = match payload.get("versions").and_then(|v| v.as_object()) {
        Some(v) => v,
        None => return Err((StatusCode::BAD_REQUEST, "Missing versions".to_string())),
    };
    let metadata_key = format!("npm/{}/metadata.json", package_name);

    // Read the existing packument ONCE — only to (a) refuse on corruption and (b) enforce version
    // immutability against versions still embedded in an un-migrated packument. The new versions
    // are NOT merged into it: each is written to its own immutable key and the packument is
    // regenerated by listing those keys, so concurrent publishers never read-modify-write the same
    // shared file (the multi-replica lost-update of #39).
    // A packument with a provenance sidecar is a proxy cache of an upstream document,
    // not local state: its versions are neither local nor immutable here (#27).
    let proxied = storage.stat(&origin_key(&metadata_key)).await.is_some();
    let existing_meta: Option<serde_json::Value> = match storage.get(&metadata_key).await {
        Ok(_) if proxied => None,
        Ok(existing) => match serde_json::from_slice::<serde_json::Value>(&existing) {
            Ok(val) => Some(val),
            Err(e) => {
                // Corrupt metadata — refuse publish to protect existing versions (#533).
                tracing::error!(
                    registry = "npm",
                    key = %metadata_key,
                    error = %e,
                    bytes = existing.len(),
                    "Corrupt metadata detected during publish — refusing to overwrite"
                );
                METADATA_CORRUPT_TOTAL.with_label_values(&["npm"]).inc();
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Existing package metadata is corrupt; publish blocked to prevent data loss"
                        .to_string(),
                ));
            }
        },
        Err(_) => None, // No existing metadata — first publish
    };

    // Version immutability: a version already published — as its own immutable key, or still
    // embedded in an un-migrated packument — may not be overwritten.
    for ver in new_versions.keys() {
        let version_key = format!("npm/{}/versions/{}.json", package_name, ver);
        let in_keys = storage.stat(&version_key).await.is_some();
        let in_embedded = existing_meta
            .as_ref()
            .and_then(|m| m.get("versions"))
            .and_then(|v| v.as_object())
            .map(|o| o.contains_key(ver))
            .unwrap_or(false);
        if in_keys || in_embedded {
            return Err((
                StatusCode::CONFLICT,
                format!("Version {} already exists", ver),
            ));
        }
        // As on npmjs, a version string once published is never reused, even after
        // an unpublish: a lockfile pinning it must not resolve to different bytes.
        if storage.stat(&time_key(package_name, ver)).await.is_some() {
            return Err((
                StatusCode::CONFLICT,
                format!("Version {ver} was published before and cannot be reused"),
            ));
        }
    }

    // R2-19: one tarball per new version, named as its `dist.tarball` below. An
    // attachment named for any other file would overwrite another version's bytes.
    let short_name = package_name.split('/').next_back().unwrap_or(package_name);
    let mut expected: Vec<String> = new_versions
        .keys()
        .map(|ver| format!("{short_name}-{ver}.tgz"))
        .collect();
    let mut given: Vec<&str> = tarballs.iter().map(|(name, _)| name.as_str()).collect();
    expected.sort_unstable();
    given.sort_unstable();
    if given != expected {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("each version needs exactly one attachment, named {short_name}-<version>.tgz"),
        ));
    }

    // Lazily migrate an old embedded-packument package to per-version keys BEFORE writing the new
    // version, so the regenerate below lists both the migrated and the new versions (no loss).
    if let Some(existing) = &existing_meta {
        migrate_embedded_packument(storage, package_name, existing).await;
    }

    let mut writes = PublishWrites::default();
    match write_publish(storage, locks, package_name, payload, tarballs, &mut writes).await {
        Ok(()) => {}
        Err(e) => {
            writes.undo(storage, package_name).await;
            return Err(e);
        }
    }
    if proxied {
        // The packument is local now: drop what described the upstream copy.
        let _ = storage.delete(&origin_key(&metadata_key)).await;
        let _ = storage.delete(&validators_key(&metadata_key)).await;
    }
    Ok(())
}

/// What a publish has written so far, undone when it fails (R2-21): a retry must find
/// the version unpublished, not a 409 for a version the packument never listed.
#[derive(Default)]
struct PublishWrites {
    /// Keys this publish created.
    created: Vec<String>,
    /// Dist-tag pointers it moved, with the target they had.
    tags: Vec<(String, Option<Bytes>)>,
}

impl PublishWrites {
    /// Best-effort: delete what was created, point the tags back, and bring the
    /// packument back to the versions left (none: removed, as an unpublish does).
    async fn undo(self, storage: &crate::Storage, package_name: &str) {
        for key in self.created.iter().rev() {
            let _ = storage.delete(key).await;
        }
        for (key, old) in self.tags {
            let _ = match old {
                Some(target) => storage.put_bytes(&key, target).await,
                None => storage.delete(&key).await,
            };
        }
        if has_local_versions(storage, package_name).await {
            let _ = regenerate_packument(storage, package_name).await;
        } else {
            let _ = storage
                .delete(&format!("npm/{package_name}/pkg.json"))
                .await;
            let _ = storage
                .delete(&format!("npm/{package_name}/metadata.json"))
                .await;
        }
        tracing::warn!(package = %package_name, "npm publish failed; its writes were rolled back");
    }
}

/// The writes of [`publish_versions`] once its checks passed, each recorded in
/// `writes` so the caller can undo them.
async fn write_publish(
    storage: &crate::storage::Storage,
    locks: &crate::PublishLocks,
    package_name: &str,
    payload: &serde_json::Value,
    tarballs: Vec<(String, Bytes)>,
    writes: &mut PublishWrites,
) -> Result<(), (StatusCode, String)> {
    let internal_error = || {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "npm publish failed".to_string(),
        )
    };
    let new_versions = payload
        .get("versions")
        .and_then(|v| v.as_object())
        .ok_or_else(internal_error)?;
    let metadata_key = format!("npm/{}/metadata.json", package_name);

    // Store tarballs.
    for (name, tarball_bytes) in tarballs {
        let tarball_key = format!("npm/{}/tarballs/{}", package_name, name);
        let hash = hex::encode(sha2::Sha256::digest(&tarball_bytes));
        // A proxied copy (provenance recorded) is a cache of an upstream file, not a
        // publish: it is replaced, and its provenance dropped first, or GC and the
        // integrity heal would treat the publish as one (C54); a provenance that cannot
        // be removed aborts the publish. Anything else under this name was published
        // here and is never replaced (R2-19): the same bytes are a retry of an
        // interrupted publish, different ones a 409. Under the tarball's publish lock,
        // so the heal of a failing proxied copy and a cache fill of the same key
        // serialise with the replacement.
        let lock = crate::acquire_publish_lock(locks, &tarball_key);
        let guard = lock.lock().await;
        let proxied_copy = storage.stat(&origin_key(&tarball_key)).await.is_some();
        if proxied_copy {
            match storage.delete(&origin_key(&tarball_key)).await {
                Ok(()) | Err(crate::storage::StorageError::NotFound) => {}
                Err(e) => {
                    tracing::error!(key = %tarball_key, error = ?e, "npm publish: failed to remove stale provenance");
                    return Err(internal_error());
                }
            }
        }
        let written = if proxied_copy {
            storage
                .put_bytes(&tarball_key, tarball_bytes)
                .await
                .map(|()| true)
        } else {
            storage.put_if_absent(&tarball_key, tarball_bytes).await
        };
        match written {
            Ok(true) => writes.created.push(tarball_key.clone()),
            Ok(false) => {
                let same = storage
                    .get(&tarball_key)
                    .await
                    .is_ok_and(|stored| hex::encode(sha2::Sha256::digest(&stored)) == hash);
                if !same {
                    tracing::warn!(key = %tarball_key, "npm publish refused: a different tarball is stored under this name");
                    return Err((
                        StatusCode::CONFLICT,
                        format!("{name} already exists with different contents"),
                    ));
                }
            }
            Err(e) => {
                tracing::error!(key = %tarball_key, error = ?e, "npm publish: failed to store tarball");
                return Err(internal_error());
            }
        }
        drop(guard);

        // Store sha256
        let hash_key = format!("{}.sha256", tarball_key);
        if let Err(e) = storage.put(&hash_key, hash.as_bytes()).await {
            tracing::warn!(key = %hash_key, error = ?e, "npm publish: failed to store hash sidecar");
        }
        writes.created.push(hash_key);
    }

    // Write each new version as its OWN immutable key, with the tarball URL rewritten to point at
    // this registry. Concurrent publishes of DIFFERENT versions write distinct keys, so none is
    // lost — the heart of the #39 fix (vs the old read-merge-write of the shared packument).
    let nora_base = PUBLIC_BASE;
    let short_name = package_name.split('/').next_back().unwrap_or(package_name);
    let now = npm_time_now();
    for (ver, ver_data) in new_versions {
        let mut vd = ver_data.clone();
        if let Some(dist) = vd.get_mut("dist") {
            let tarball_url = format!(
                "{}/npm/{}/-/{}-{}.tgz",
                nora_base.trim_end_matches('/'),
                package_name,
                short_name,
                ver
            );
            dist["tarball"] = serde_json::Value::String(tarball_url);
        }
        let version_key = format!("npm/{}/versions/{}.json", package_name, ver);
        match serde_json::to_vec(&vd) {
            Ok(bytes) => {
                writes.created.push(version_key.clone());
                if let Err(e) = storage.put(&version_key, &bytes).await {
                    tracing::error!(key = %version_key, error = ?e, "npm publish: failed to store version");
                    return Err(internal_error());
                }
                // The packument's `time[<ver>]`; best-effort, an unpublish writes it
                // if missing.
                let key = time_key(package_name, ver);
                writes.created.push(key.clone());
                if let Err(e) = storage.put(&key, now.as_bytes()).await {
                    tracing::warn!(key = %key, error = ?e, "npm publish: failed to store publish time");
                }
            }
            Err(e) => {
                tracing::error!(error = ?e, "npm publish: failed to serialize version");
                return Err(internal_error());
            }
        }
    }

    // dist-tags: one small mutable pointer per tag (tag -> version). Last-writer-wins on a single
    // tag is an acceptable pointer-flip — it never loses a version (each version is its own key).
    if let Some(new_dist_tags) = payload.get("dist-tags").and_then(|d| d.as_object()) {
        for (tag, ver) in new_dist_tags {
            if let Some(ver_str) = ver.as_str() {
                let tag_key = format!("npm/{}/dist-tags/{}", package_name, tag);
                let old = storage.get(&tag_key).await.ok();
                if let Err(e) = storage.put(&tag_key, ver_str.as_bytes()).await {
                    tracing::warn!(key = %tag_key, error = ?e, "npm publish: failed to store dist-tag");
                }
                writes.tags.push((tag_key, old));
            }
        }
    }

    // Package-level descriptive fields (not per-version) — overwrite (last-writer-wins is fine).
    let mut pkg_fields = serde_json::Map::new();
    for field in &["name", "_id", "description", "readme", "license"] {
        if let Some(val) = payload.get(*field) {
            pkg_fields.insert(field.to_string(), val.clone());
        }
    }
    if let Ok(bytes) = serde_json::to_vec(&serde_json::Value::Object(pkg_fields)) {
        let pkg_key = format!("npm/{}/pkg.json", package_name);
        if let Err(e) = storage.put(&pkg_key, &bytes).await {
            tracing::warn!(key = %pkg_key, error = ?e, "npm publish: failed to store package fields");
        }
    }

    // Regenerate the packument (metadata.json) by listing the immutable per-version keys.
    if regenerate_packument(storage, package_name).await.is_err() {
        tracing::error!(package = %package_name, "npm publish: failed to regenerate packument");
        return Err(internal_error());
    }

    // Fail-closed (#878): a 201 MUST mean the published version is actually visible in
    // the packument. scan-regenerate derives `versions` by LISTING the per-version keys
    // and reading each back; a storage key-encoding round-trip bug (the object_store
    // `%40`->`%2540` double-encoding for `@scope/...` keys) silently produced an empty
    // `versions` map, yet publish still returned 201 and `npm install` then failed
    // ENOVERSIONS. Read the regenerated packument back and refuse (500) unless every
    // just-published version is present, so a regen round-trip defect can never again
    // hide behind a 201.
    let published_visible = match storage.get(&metadata_key).await {
        Ok(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|m| {
                m.get("versions")
                    .and_then(|v| v.as_object())
                    .map(|vs| new_versions.keys().all(|v| vs.contains_key(v)))
            })
            .unwrap_or(false),
        Err(_) => false,
    };
    if !published_visible {
        tracing::error!(
            package = %package_name,
            "npm publish: regenerated packument does not list the just-published version(s) — refusing 201 (scan-regenerate round-trip broke, see #878)"
        );
        return Err(internal_error());
    }

    Ok(())
}

/// Shown to `npm login` / `npm adduser`.
const NPM_LOGIN_UNSUPPORTED: &str = "npm login is not supported by this registry: create an \
     API token in the NORA UI and set //<host>/npm/:_authToken=<token> in .npmrc";

/// `DELETE /-/package/<name>/dist-tags/<tag>` (`npm dist-tag rm`), and the DELETEs of
/// `npm unpublish`: `/<name>/-rev/<rev>` (the whole package) and
/// `/<tarball path>/-rev/<rev>` (the tarball of a version already unpublished).
async fn handle_npm_delete(
    State(state): State<AppState>,
    Path(path): Path<String>,
    Extension(authority): Extension<NamespaceAuthority>,
    user: Option<Extension<crate::auth::AuthenticatedUser>>,
) -> Response {
    if let Some(rest) = path.strip_prefix("-/package/") {
        return set_dist_tag(&state, &authority, &user, rest, None).await;
    }
    let Some((target, _rev)) = path.rsplit_once("/-rev/") else {
        return method_not_allowed("GET, PUT, POST");
    };
    if let Some((prefix, file)) = target.rsplit_once("/-/") {
        return unpublish_tarball(&state, &authority, prefix, file).await;
    }
    let name = target;
    if enforce_namespace_scope(&authority, name).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let lock = state.publish_lock(&format!("npm/{name}/metadata.json"));
    let _guard = lock.lock().await;
    let versions = local_version_list(&state.storage, name).await;
    if versions.is_empty() {
        return not_published_here(name);
    }
    unpublish(&state, &user, name, &versions).await
}

/// `npm unpublish <pkg>@<ver>`, first step: `PUT /<name>/-rev/<rev>` with the packument
/// minus that version. NORA keeps no revisions, so the version missing from the body
/// is the one removed; a body missing more than one (a version published after the
/// client read the packument) is a conflict, as a stale `_rev` is on npmjs. A body
/// missing none (`npm owner`) applies only `deprecated`, as `npm deprecate` does.
async fn unpublish_put(
    state: &AppState,
    authority: &NamespaceAuthority,
    user: &Option<Extension<crate::auth::AuthenticatedUser>>,
    name: &str,
    body: &[u8],
) -> Response {
    if enforce_namespace_scope(authority, name).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(body) else {
        return (StatusCode::BAD_REQUEST, "Invalid JSON").into_response();
    };
    if payload.get("name").and_then(|n| n.as_str()) != Some(name) {
        return (
            StatusCode::BAD_REQUEST,
            "Package name in URL does not match payload",
        )
            .into_response();
    }
    let Some(kept) = payload.get("versions").and_then(|v| v.as_object()) else {
        return (StatusCode::BAD_REQUEST, "Missing versions").into_response();
    };
    let lock = state.publish_lock(&format!("npm/{name}/metadata.json"));
    let guard = lock.lock().await;
    let local = local_version_list(&state.storage, name).await;
    if local.is_empty() {
        return not_published_here(name);
    }
    let missing: Vec<String> = local
        .into_iter()
        .filter(|v| !kept.contains_key(v))
        .collect();
    match missing.len() {
        0 => {
            drop(guard);
            deprecate_versions(state, user, name, &payload).await
        }
        1 => unpublish(state, user, name, &missing).await,
        _ => audit_refused(
            StatusCode::CONFLICT,
            "the packument changed since it was read; unpublish one version at a time",
        ),
    }
}

/// Remove `versions` of a package published here: each version's document, tarball
/// and the dist-tags pointing at it. `time[<ver>]` stays as the tombstone that keeps
/// the version string from being published again. With no version left the packument,
/// package fields and tags go too. The caller holds the package's publish lock.
async fn unpublish(
    state: &AppState,
    user: &Option<Extension<crate::auth::AuthenticatedUser>>,
    name: &str,
    versions: &[String],
) -> Response {
    let storage = &state.storage;
    let short = name.rsplit('/').next().unwrap_or(name);
    for ver in versions {
        let tombstone = time_key(name, ver);
        if storage.stat(&tombstone).await.is_none()
            && storage
                .put(&tombstone, npm_time_now().as_bytes())
                .await
                .is_err()
        {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        if storage
            .delete(&format!("npm/{name}/versions/{ver}.json"))
            .await
            .is_err()
        {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        let tarball = format!("npm/{name}/tarballs/{short}-{ver}.tgz");
        let _ = storage.delete(&format!("{tarball}.sha256")).await;
        let _ = storage.delete(&tarball).await;
    }
    let remaining = has_local_versions(storage, name).await;
    for (tag_key, data) in super::read_keyed_blobs(storage, &format!("npm/{name}/dist-tags/")).await
    {
        let target = String::from_utf8_lossy(&data);
        if !remaining || versions.iter().any(|v| *v == target.trim()) {
            let _ = storage.delete(&tag_key).await;
        }
    }
    let rebuilt = if remaining {
        // `latest` pointed at a removed version: regenerate derives the highest left.
        regenerate_packument(storage, name).await.is_ok()
    } else {
        let _ = storage.delete(&format!("npm/{name}/pkg.json")).await;
        storage
            .delete(&format!("npm/{name}/metadata.json"))
            .await
            .is_ok()
    };
    if !rebuilt {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let detail = if remaining {
        versions.join(",")
    } else {
        "*".to_string()
    };
    let actor = crate::auth::audit_actor(user);
    state
        .audit
        .log(AuditEntry::new("unpublish", actor, name, "npm", &detail));
    state.repo_index.invalidate("npm");
    axum::Json(serde_json::json!({})).into_response()
}

/// `npm unpublish <pkg>@<ver>`, last step: `DELETE /<tarball path>/-rev/<rev>`. The
/// path is the tarball URL's (so it may carry `public_url`'s path and `npm/`); the
/// package is its last segment, or last two when scoped. The PUT already removed the
/// tarball, so this only clears what is left of a version unpublished here.
async fn unpublish_tarball(
    state: &AppState,
    authority: &NamespaceAuthority,
    prefix: &str,
    file: &str,
) -> Response {
    let mut tail = prefix.rsplit('/');
    let name = match (tail.next(), tail.next()) {
        (Some(last), Some(scope)) if scope.starts_with('@') => format!("{scope}/{last}"),
        (Some(last), _) => last.to_string(),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    if enforce_namespace_scope(authority, &name).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let version = crate::curation::parse_npm_tarball_version(&name, file);
    let (Some(ver), true) = (version, is_valid_attachment_name(file)) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let lock = state.publish_lock(&format!("npm/{name}/metadata.json"));
    let _guard = lock.lock().await;
    if state
        .storage
        .stat(&format!("npm/{name}/versions/{ver}.json"))
        .await
        .is_some()
    {
        return audit_refused(StatusCode::CONFLICT, "this version is still published");
    }
    if state.storage.stat(&time_key(&name, &ver)).await.is_none() {
        return not_published_here(&name);
    }
    let tarball = format!("npm/{name}/tarballs/{file}");
    let _ = state.storage.delete(&format!("{tarball}.sha256")).await;
    let _ = state.storage.delete(&tarball).await;
    axum::Json(serde_json::json!({})).into_response()
}

/// Unpublish refused: only what was published to this registry can be removed, and a
/// proxied package is never touched (nor its name sent upstream). 403, not 404: npm
/// treats a 404 on unpublish as already done and would report success.
fn not_published_here(name: &str) -> Response {
    audit_refused(
        StatusCode::FORBIDDEN,
        &format!("{name} has no versions published to this registry"),
    )
}

/// The versions published here, from their `versions/<v>.json` keys.
async fn local_version_list(storage: &crate::Storage, name: &str) -> Vec<String> {
    storage
        .list(&format!("npm/{name}/versions/"))
        .await
        .unwrap_or_default()
        .iter()
        .filter_map(|key| key.rsplit('/').next()?.strip_suffix(".json"))
        .map(str::to_string)
        .collect()
}

/// `npm/<name>/time/<ver>`: when the version was published, as the packument's
/// `time[<ver>]`. Kept after an unpublish, so a version string is never reused.
fn time_key(name: &str, ver: &str) -> String {
    format!("npm/{name}/time/{ver}")
}

/// Now, as npm writes `time` entries (`2024-01-15T10:30:00.000Z`).
fn npm_time_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Point (`Some(version)`) or remove (`None`) a dist-tag of a package published here.
async fn set_dist_tag(
    state: &AppState,
    authority: &NamespaceAuthority,
    user: &Option<Extension<crate::auth::AuthenticatedUser>>,
    rest: &str,
    version: Option<&str>,
) -> Response {
    let Some((name, tag)) = rest.rsplit_once("/dist-tags/") else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if enforce_namespace_scope(authority, name).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    // npm refuses to remove `latest`; the tag is a storage key segment.
    if !is_valid_attachment_name(tag) || (tag == "latest" && version.is_none()) {
        return (StatusCode::BAD_REQUEST, "Invalid dist-tag").into_response();
    }
    let lock = state.publish_lock(&format!("npm/{name}/metadata.json"));
    let _guard = lock.lock().await;
    let tag_key = format!("npm/{name}/dist-tags/{tag}");
    let written = match version {
        Some(v)
            if state
                .storage
                .stat(&format!("npm/{name}/versions/{v}.json"))
                .await
                .is_some() =>
        {
            state.storage.put(&tag_key, v.as_bytes()).await
        }
        None if state.storage.stat(&tag_key).await.is_some() => {
            state.storage.delete(&tag_key).await
        }
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    if written.is_err() || regenerate_packument(&state.storage, name).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let action = if version.is_some() {
        "dist_tag_add"
    } else {
        "dist_tag_rm"
    };
    let actor = crate::auth::audit_actor(user);
    state
        .audit
        .log(AuditEntry::new(action, actor, name, "npm", tag));
    axum::Json(serde_json::json!({})).into_response()
}

/// `npm deprecate`: apply only the `deprecated` field of each version published here
/// (`""` clears it); every other difference in the PUT packument is ignored.
async fn deprecate_versions(
    state: &AppState,
    user: &Option<Extension<crate::auth::AuthenticatedUser>>,
    name: &str,
    payload: &serde_json::Value,
) -> Response {
    let Some(versions) = payload.get("versions").and_then(|v| v.as_object()) else {
        return (StatusCode::BAD_REQUEST, "Missing versions").into_response();
    };
    let lock = state.publish_lock(&format!("npm/{name}/metadata.json"));
    let _guard = lock.lock().await;
    for (ver, data) in versions {
        let key = format!("npm/{name}/versions/{ver}.json");
        let Ok(stored) = state.storage.get(&key).await else {
            continue;
        };
        let Ok(mut stored) = serde_json::from_slice::<serde_json::Value>(&stored) else {
            continue;
        };
        let wanted = data
            .get("deprecated")
            .and_then(|d| d.as_str())
            .unwrap_or("");
        let current = stored
            .get("deprecated")
            .and_then(|d| d.as_str())
            .unwrap_or("");
        if wanted == current {
            continue;
        }
        let Some(obj) = stored.as_object_mut() else {
            continue;
        };
        if wanted.is_empty() {
            obj.remove("deprecated");
        } else {
            obj.insert("deprecated".into(), wanted.into());
        }
        let Ok(bytes) = serde_json::to_vec(&stored) else {
            continue;
        };
        if state.storage.put(&key, &bytes).await.is_err() {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }
    if regenerate_packument(&state.storage, name).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let actor = crate::auth::audit_actor(user);
    state
        .audit
        .log(AuditEntry::new("deprecate", actor, name, "npm", ""));
    axum::Json(serde_json::json!({})).into_response()
}

// ============================================================================
// Helpers
// ============================================================================

/// Regenerate the npm packument (`metadata.json`) by LISTING the immutable per-version keys, the
/// dist-tag pointers and the package-level fields — never by read-modify-write of the shared file.
/// Concurrent publishers each write their own `versions/{v}.json`; whoever regenerates last lists
/// them all, so no version is permanently lost (the maven scan-regenerate guarantee, #39). Old
/// embedded-packument packages are migrated to per-version keys by `migrate_embedded_packument`
/// in the publish handler BEFORE the new version is written, so this stays a pure list-derive.
pub(crate) async fn regenerate_packument(
    storage: &crate::storage::Storage,
    package_name: &str,
) -> Result<(), ()> {
    // versions map, keyed by the filename (version) without the .json suffix. Read
    // concurrently: on an object store every version is a round-trip, and this path now
    // runs on a read (#956), so a package with thousands of versions used to pay them
    // one after another. An unreadable or unparsable key is skipped, as before.
    let versions_prefix = format!("npm/{}/versions/", package_name);
    // A version stored with an absolute tarball URL (published before PUBLIC_BASE)
    // follows `public_url` like the rest.
    let tarball_prefix = format!("{PUBLIC_BASE}/npm/{package_name}/-/");
    let mut versions = serde_json::Map::new();
    for (key, data) in super::read_keyed_blobs(storage, &versions_prefix).await {
        let Ok(mut vd) = serde_json::from_slice::<serde_json::Value>(&data) else {
            continue;
        };
        rebase_tarball(&mut vd, &tarball_prefix);
        if let Some(ver) = key.rsplit('/').next().and_then(|f| f.strip_suffix(".json")) {
            versions.insert(ver.to_string(), vd);
        }
    }

    // dist-tags from the pointer keys (+ derive `latest` if publish left it unset).
    let dt_prefix = format!("npm/{}/dist-tags/", package_name);
    let mut dist_tags = serde_json::Map::new();
    for (key, data) in super::read_keyed_blobs(storage, &dt_prefix).await {
        if let (Some(tag), Ok(ver)) = (key.rsplit('/').next(), String::from_utf8(data.to_vec())) {
            dist_tags.insert(tag.to_string(), serde_json::Value::String(ver));
        }
    }
    if !dist_tags.contains_key("latest") {
        if let Some(latest) = max_semver(versions.keys()) {
            dist_tags.insert("latest".to_string(), serde_json::Value::String(latest));
        }
    }

    // Package-level fields + the assembled maps -> the packument.
    let mut packument = match storage.get(&format!("npm/{}/pkg.json", package_name)).await {
        Ok(d) => serde_json::from_slice(&d).unwrap_or_else(|_| serde_json::json!({})),
        Err(_) => serde_json::json!({}),
    };
    let obj = packument.as_object_mut().ok_or(())?;
    obj.insert(
        "name".to_string(),
        serde_json::Value::String(package_name.to_string()),
    );
    obj.insert(
        "dist-tags".to_string(),
        serde_json::Value::Object(dist_tags),
    );
    obj.insert("versions".to_string(), serde_json::Value::Object(versions));

    // `time`: when each version was published here (unpublished ones included, as on
    // npmjs), plus `created`/`modified`. The values share one format, so the string
    // order is the time order.
    let mut time = serde_json::Map::new();
    for (key, data) in super::read_keyed_blobs(storage, &format!("npm/{package_name}/time/")).await
    {
        if let (Some(ver), Ok(at)) = (key.rsplit('/').next(), String::from_utf8(data.to_vec())) {
            time.insert(ver.to_string(), serde_json::Value::String(at));
        }
    }
    let span = time.values().filter_map(|t| t.as_str());
    if let (Some(created), Some(modified)) = (span.clone().min(), span.max()) {
        let (created, modified) = (created.to_string(), modified.to_string());
        time.insert("created".to_string(), created.into());
        time.insert("modified".to_string(), modified.into());
        obj.insert("time".to_string(), serde_json::Value::Object(time));
    }

    let bytes = serde_json::to_vec(&packument).map_err(|_| ())?;

    storage
        .put(&format!("npm/{}/metadata.json", package_name), &bytes)
        .await
        .map_err(|_| ())
}

/// Seed per-version keys from an old embedded packument (versions inside `metadata.json`, no
/// per-version keys) so the scan-regenerate path does not drop them. Idempotent; a no-op once the
/// package has per-version keys. Runs BEFORE the new version is written.
async fn migrate_embedded_packument(
    storage: &crate::storage::Storage,
    package_name: &str,
    existing: &serde_json::Value,
) {
    let versions_prefix = format!("npm/{}/versions/", package_name);
    if !storage
        .list(&versions_prefix)
        .await
        .unwrap_or_default()
        .is_empty()
    {
        return; // already migrated
    }
    if let Some(embedded) = existing.get("versions").and_then(|v| v.as_object()) {
        for (ver, data) in embedded {
            if let Ok(bytes) = serde_json::to_vec(data) {
                let vkey = format!("npm/{}/versions/{}.json", package_name, ver);
                let _ = storage.put(&vkey, &bytes).await;
            }
        }
    }
    if let Some(tags) = existing.get("dist-tags").and_then(|d| d.as_object()) {
        for (tag, ver) in tags {
            if let Some(vs) = ver.as_str() {
                let tkey = format!("npm/{}/dist-tags/{}", package_name, tag);
                let _ = storage.put(&tkey, vs.as_bytes()).await;
            }
        }
    }
}

/// Highest version by a naive numeric semver comparison (a release outranks a prerelease at the
/// same core). Used only as the `latest` dist-tag fallback when publish did not set one.
fn max_semver<'a>(versions: impl Iterator<Item = &'a String>) -> Option<String> {
    versions
        .max_by(|a, b| semver_key(a).cmp(&semver_key(b)))
        .cloned()
}

pub(crate) fn semver_key(v: &str) -> (u64, u64, u64, bool) {
    let core = v.split(['-', '+']).next().unwrap_or(v);
    let mut it = core.trim_start_matches('v').split('.');
    let n = |x: Option<&str>| x.and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    (n(it.next()), n(it.next()), n(it.next()), !v.contains('-'))
}

/// `npm/{name}/dates.json`: the `time` map (version → ISO 8601) of the cached proxied
/// packument, written with it. The tarball gates date a version from this, not from a
/// packument that runs to megabytes (R2-17), as PyPI does with its `dates.json`.
fn dates_key(name: &str) -> String {
    format!("npm/{name}/dates.json")
}

/// The `time` map of a packument, scanned without building the whole document.
fn packument_times(data: &[u8]) -> serde_json::Map<String, serde_json::Value> {
    #[derive(serde::Deserialize)]
    struct Times {
        #[serde(default)]
        time: serde_json::Map<String, serde_json::Value>,
    }
    serde_json::from_slice::<Times>(data)
        .map(|t| t.time)
        .unwrap_or_default()
}

/// Cache a proxied packument (already rewritten to [`PUBLIC_BASE`]) with its
/// provenance and its [`dates_key`] companion. A failed companion write only costs
/// a read of the packument later.
async fn cache_packument(
    storage: &crate::Storage,
    name: &str,
    data: Bytes,
    origin: &str,
) -> Result<(), crate::storage::StorageError> {
    let times = packument_times(&data);
    put_with_origin(storage, &format!("npm/{name}/metadata.json"), data, origin).await?;
    write_dates(storage, name, &times).await;
    Ok(())
}

async fn write_dates(
    storage: &crate::Storage,
    name: &str,
    times: &serde_json::Map<String, serde_json::Value>,
) {
    let key = dates_key(name);
    if let Ok(bytes) = serde_json::to_vec(times) {
        if let Err(e) = storage.put(&key, &bytes).await {
            tracing::warn!(key = %key, error = ?e, "npm: failed to cache release dates");
        }
    }
}

/// The upstream release date of `name@version` for the tarball gates, or `None`.
///
/// #513: untrusted upstream dates → no date: never the (spoofable) upstream date, nor
/// the cache mtime (refreshed with the metadata, not a release date).
///
/// #748: a tarball download may arrive without a prior packument request
/// (direct/locked fetch), so the packument is self-primed here, synchronously, so
/// the date is readable on this same request; it joins a packument fetch already in
/// flight for the same name. Best-effort: any failure leaves the date `None`
/// (fail-safe — the package is held as new). Namespace-safe: an internal-namespace
/// package, or one published here, is never fetched upstream (#68). Mirrors Cargo's
/// `ensure_cargo_metadata_cached` and PyPI's `ensure_pypi_dates_cached`.
async fn npm_publish_date(state: &AppState, name: &str, version: &str) -> Option<i64> {
    if !state.config.server.trust_upstream_dates {
        return None;
    }
    let times = npm_release_times(state, name).await?;
    crate::curation::parse_iso8601_to_unix(times.get(version)?.as_str()?)
}

/// The `time` map of `name`: its [`dates_key`], else the cached packument's (stored
/// as the companion for next time), else the packument fetched upstream and cached.
async fn npm_release_times(
    state: &AppState,
    name: &str,
) -> Option<serde_json::Map<String, serde_json::Value>> {
    let key = format!("npm/{name}/metadata.json");
    // #1055: inside a scope owned by a private upstream, only the owner's copy counts.
    if cached_copy_trusted(state, name, &key, name, None).await {
        if let Ok(dates) = state.storage.get(&dates_key(name)).await {
            if let Ok(times) = serde_json::from_slice(&dates) {
                return Some(times);
            }
        }
        // Cached before the companion existed.
        if let Ok(data) = state.storage.get(&key).await {
            let times = packument_times(&data);
            write_dates(&state.storage, name, &times).await;
            return Some(times);
        }
    }
    if crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Npm,
        name,
    ) || has_local_versions(&state.storage, name).await
    {
        return None;
    }
    let upstream = state.config.npm.route(name)?;
    let proxy_url = upstream.url;
    let url = format!("{}/{}", proxy_url.trim_end_matches('/'), name);
    let timeout = state.config.npm.proxy_timeout;
    let fetch = proxy_fetch_bytes(
        &state.http_client,
        &url,
        Duration::from_secs(timeout),
        upstream.auth,
        &state.circuit_breaker,
        BreakerScope::upstream(RegistryType::Npm, upstream.url),
    );
    // The packument request's own key: a concurrent cold miss on it fetches once.
    let (data, fetched) = proxy_fetch_shared(state, &key, "npm", timeout, fetch)
        .await
        .ok()?;
    let times = packument_times(&data);
    if fetched {
        // Rewrite tarball URLs to point at NORA, exactly as the proxy path and
        // refetch_metadata do, so a subsequent client reading the cached
        // packument is not sent back to the upstream.
        let nora_base = PUBLIC_BASE;
        let rewritten = rewrite_tarball_urls(&data, nora_base, proxy_url).unwrap_or_else(|()| {
            tracing::warn!(
                package = %name,
                "npm metadata self-prime: JSON parse failed, using byte-level URL rewrite",
            );
            let upstream_trimmed = proxy_url.trim_end_matches('/');
            let nora_npm_base = format!("{}/npm", nora_base.trim_end_matches('/'));
            replace_upstream_bytes(&data, upstream_trimmed, &nora_npm_base)
        });
        let _ = cache_packument(
            &state.storage,
            name,
            rewritten.into(),
            &origin_of(proxy_url),
        )
        .await;
    }
    Some(times)
}

/// npm's abbreviated packument — `application/vnd.npm.install-v1+json`, the
/// document an installer actually reads. Everything else (readme, maintainers,
/// repository, per-version `description`, `scripts`, `gitHead`) is dropped, and
/// on a package with many versions that is most of the bytes.
const NPM_INSTALL_V1: &str = "application/vnd.npm.install-v1+json";

/// The per-version fields npm keeps in the abbreviated form. This is an
/// allowlist on purpose: dropping a field an installer consults — `os`, `cpu`,
/// `engines`, `peerDependenciesMeta` — silently changes what gets resolved and
/// installed, so a field is added here, once, rather than at a call site.
const INSTALL_V1_VERSION_FIELDS: &[&str] = &[
    "name",
    "version",
    "dependencies",
    "optionalDependencies",
    "devDependencies",
    "bundleDependencies",
    "peerDependencies",
    "peerDependenciesMeta",
    "acceptDependencies",
    "bin",
    "directories",
    "dist",
    "engines",
    "os",
    "cpu",
    "libc",
    "funding",
    "deprecated",
    "hasInstallScript",
    "_hasShrinkwrap",
];

/// Top-level fields kept alongside `versions`.
const INSTALL_V1_TOP_FIELDS: &[&str] = &["name", "dist-tags", "modified"];

/// True when the client asked for the abbreviated packument.
fn wants_install_v1(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|accept| accept.contains(NPM_INSTALL_V1))
}

/// Project a full packument down to the abbreviated form. `None` when the document
/// is not an object — the caller then serves the body unchanged.
fn abbreviate_packument(doc: &serde_json::Value) -> Option<Vec<u8>> {
    let obj = doc.as_object()?;

    let mut out = serde_json::Map::new();
    for field in INSTALL_V1_TOP_FIELDS {
        if let Some(value) = obj.get(*field) {
            out.insert((*field).to_string(), value.clone());
        }
    }

    let mut versions = serde_json::Map::new();
    if let Some(source) = obj.get("versions").and_then(|v| v.as_object()) {
        for (version, manifest) in source {
            let Some(manifest) = manifest.as_object() else {
                continue;
            };
            let mut kept = serde_json::Map::new();
            for field in INSTALL_V1_VERSION_FIELDS {
                if let Some(value) = manifest.get(*field) {
                    kept.insert((*field).to_string(), value.clone());
                }
            }
            versions.insert(version.clone(), serde_json::Value::Object(kept));
        }
    }
    out.insert("versions".to_string(), serde_json::Value::Object(versions));

    serde_json::to_vec(&serde_json::Value::Object(out)).ok()
}

/// Q04 filter of a proxied packument: the curation engine and the package name.
type HideYoung<'a> = Option<(&'a crate::curation::CurationEngine, &'a str)>;

/// Serve a packument, honouring the abbreviated form when the client asks for it.
/// `hide`: a proxied packument, filtered by `min_release_age` (Q04) on the full
/// document before it is abbreviated. The body is parsed at most once.
///
/// `Vary: Accept` is not decoration here: the body depends on a request header
/// and NORA marks metadata `Cache-Control: public`, so without it a shared cache
/// can hand the abbreviated document to a client that asked for the full one.
fn packument_body(
    headers: &HeaderMap,
    data: Bytes,
    nora_base: &str,
    hide: HideYoung<'_>,
) -> (Bytes, &'static str) {
    let install_v1 = wants_install_v1(headers);
    let hide = hide.filter(|(engine, _)| engine.metadata_filter_active());
    let parsed = if install_v1 || hide.is_some() {
        serde_json::from_slice::<serde_json::Value>(&data).ok()
    } else {
        None
    };
    // Unparsable body: serve it unchanged. The client asked for a projection of
    // this document, not for an error.
    let (body, content_type) = match parsed {
        None => (data, "application/json"),
        Some(mut doc) => {
            let hidden = hide.is_some_and(|(engine, name)| {
                crate::metadata_filter::npm_packument(engine, name, &mut doc)
            });
            if install_v1 {
                match abbreviate_packument(&doc) {
                    Some(short) => (Bytes::from(short), NPM_INSTALL_V1),
                    None => (data, "application/json"),
                }
            } else if hidden {
                match serde_json::to_vec(&doc) {
                    Ok(filtered) => (Bytes::from(filtered), "application/json"),
                    Err(_) => (data, "application/json"),
                }
            } else {
                (data, "application/json")
            }
        }
    };
    (with_public_base(body, nora_base), content_type)
}

fn packument_response(
    headers: &HeaderMap,
    data: Bytes,
    nora_base: &str,
    hide: HideYoung<'_>,
) -> Response {
    let (body, content_type) = packument_body(headers, data, nora_base, hide);

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=60, must-revalidate"),
            ),
            (header::VARY, HeaderValue::from_static("Accept")),
        ],
        body,
    )
        .into_response()
}

fn with_content_type(
    is_tarball: bool,
    data: Bytes,
) -> (StatusCode, [(header::HeaderName, &'static str); 2], Bytes) {
    let (content_type, cache_control) = if is_tarball {
        (
            "application/octet-stream",
            "public, max-age=31536000, immutable",
        )
    } else {
        ("application/json", "public, max-age=60, must-revalidate")
    };

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, cache_control),
        ],
        data,
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_rewrite_tarball_urls_regular_package() {
        let metadata = serde_json::json!({
            "name": "lodash",
            "versions": {
                "4.17.21": {
                    "dist": {
                        "tarball": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                        "shasum": "abc123"
                    }
                }
            }
        });
        let data = serde_json::to_vec(&metadata).unwrap();
        let result =
            rewrite_tarball_urls(&data, "http://nora:5000", "https://registry.npmjs.org").unwrap();
        let json: serde_json::Value = serde_json::from_slice(&result).unwrap();

        assert_eq!(
            json["versions"]["4.17.21"]["dist"]["tarball"],
            "http://nora:5000/npm/lodash/-/lodash-4.17.21.tgz"
        );
        assert_eq!(json["versions"]["4.17.21"]["dist"]["shasum"], "abc123");
    }

    #[test]
    fn test_rewrite_tarball_urls_scoped_package() {
        let metadata = serde_json::json!({
            "name": "@babel/core",
            "versions": {
                "7.26.0": {
                    "dist": {
                        "tarball": "https://registry.npmjs.org/@babel/core/-/core-7.26.0.tgz",
                        "integrity": "sha512-test"
                    }
                }
            }
        });
        let data = serde_json::to_vec(&metadata).unwrap();
        let result =
            rewrite_tarball_urls(&data, "http://nora:5000", "https://registry.npmjs.org").unwrap();
        let json: serde_json::Value = serde_json::from_slice(&result).unwrap();

        assert_eq!(
            json["versions"]["7.26.0"]["dist"]["tarball"],
            "http://nora:5000/npm/@babel/core/-/core-7.26.0.tgz"
        );
    }

    #[test]
    fn test_rewrite_tarball_urls_multiple_versions() {
        let metadata = serde_json::json!({
            "name": "express",
            "versions": {
                "4.18.2": { "dist": { "tarball": "https://registry.npmjs.org/express/-/express-4.18.2.tgz" } },
                "4.19.0": { "dist": { "tarball": "https://registry.npmjs.org/express/-/express-4.19.0.tgz" } }
            }
        });
        let data = serde_json::to_vec(&metadata).unwrap();
        let result = rewrite_tarball_urls(
            &data,
            "https://demo.getnora.io",
            "https://registry.npmjs.org",
        )
        .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&result).unwrap();

        assert_eq!(
            json["versions"]["4.18.2"]["dist"]["tarball"],
            "https://demo.getnora.io/npm/express/-/express-4.18.2.tgz"
        );
        assert_eq!(
            json["versions"]["4.19.0"]["dist"]["tarball"],
            "https://demo.getnora.io/npm/express/-/express-4.19.0.tgz"
        );
    }

    #[test]
    fn test_rewrite_tarball_urls_no_versions() {
        let metadata = serde_json::json!({ "name": "empty-pkg" });
        let data = serde_json::to_vec(&metadata).unwrap();
        let result =
            rewrite_tarball_urls(&data, "http://nora:5000", "https://registry.npmjs.org").unwrap();
        let json: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(json["name"], "empty-pkg");
    }

    #[test]
    fn test_rewrite_invalid_json() {
        assert!(rewrite_tarball_urls(
            b"not json",
            "http://nora:5000",
            "https://registry.npmjs.org"
        )
        .is_err());
    }

    #[test]
    fn rebase_hosted_tarballs_follows_public_url() {
        let stored = serde_json::json!({ "versions": {
            "1.0.0": { "dist": { "tarball": "http://old:4000/npm/@s/p/-/p-1.0.0.tgz" } },
            "2.0.0": { "dist": {} }
        } });
        let data = Bytes::from(serde_json::to_vec(&stored).unwrap());
        let out = rebase_hosted_tarballs(data, "https://new.example/", "@s/p");
        let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(
            json["versions"]["1.0.0"]["dist"]["tarball"],
            "https://new.example/npm/@s/p/-/p-1.0.0.tgz"
        );
        // Already current: bytes untouched.
        let again = rebase_hosted_tarballs(out.clone(), "https://new.example", "@s/p");
        assert_eq!(again, out);
    }

    #[test]
    fn test_valid_attachment_names() {
        assert!(is_valid_attachment_name("lodash-4.17.21.tgz"));
        assert!(is_valid_attachment_name("core-7.26.0.tgz"));
        assert!(is_valid_attachment_name("my_package-1.0.0.tgz"));
        assert!(is_valid_attachment_name("@scope-pkg-1.0.0.tgz"));
    }

    #[test]
    fn test_path_traversal_attachment_names() {
        assert!(!is_valid_attachment_name("../../etc/passwd"));
        assert!(!is_valid_attachment_name(
            "../docker/nginx/manifests/latest.json"
        ));
        assert!(!is_valid_attachment_name("foo/bar.tgz"));
        assert!(!is_valid_attachment_name("foo\\bar.tgz"));
    }

    #[test]
    fn test_empty_and_null_attachment_names() {
        assert!(!is_valid_attachment_name(""));
        assert!(!is_valid_attachment_name("foo\0bar.tgz"));
    }

    #[test]
    fn test_with_content_type_tarball() {
        let data = Bytes::from("tarball-data");
        let (status, headers, body) = with_content_type(true, data.clone());
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[0].1, "application/octet-stream");
        assert_eq!(body, data);
    }

    #[test]
    fn test_with_content_type_json() {
        let data = Bytes::from("json-data");
        let (status, headers, body) = with_content_type(false, data.clone());
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[0].1, "application/json");
        assert_eq!(body, data);
    }

    #[test]
    fn test_rewrite_tarball_urls_trailing_slash() {
        let metadata = serde_json::json!({
            "name": "test",
            "versions": {
                "1.0.0": {
                    "dist": {
                        "tarball": "https://registry.npmjs.org/test/-/test-1.0.0.tgz"
                    }
                }
            }
        });
        let data = serde_json::to_vec(&metadata).unwrap();
        let result =
            rewrite_tarball_urls(&data, "http://nora:5000/", "https://registry.npmjs.org/")
                .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&result).unwrap();
        let tarball = json["versions"]["1.0.0"]["dist"]["tarball"]
            .as_str()
            .unwrap();
        assert!(tarball.starts_with("http://nora:5000/npm/"));
    }

    #[test]
    fn test_rewrite_tarball_urls_preserves_other_fields() {
        let metadata = serde_json::json!({
            "name": "test",
            "description": "A test package",
            "versions": {
                "1.0.0": {
                    "dist": {
                        "tarball": "https://registry.npmjs.org/test/-/test-1.0.0.tgz",
                        "shasum": "abc123"
                    },
                    "dependencies": {"lodash": "^4.0.0"}
                }
            }
        });
        let data = serde_json::to_vec(&metadata).unwrap();
        let result =
            rewrite_tarball_urls(&data, "http://nora:5000", "https://registry.npmjs.org").unwrap();
        let json: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(json["description"], "A test package");
        assert_eq!(json["versions"]["1.0.0"]["dist"]["shasum"], "abc123");
    }

    // ── Safety net tests (#439) ──

    #[test]
    fn test_replace_upstream_bytes_basic() {
        let data = b"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz";
        let result =
            replace_upstream_bytes(data, "https://registry.npmjs.org", "http://nora:5000/npm");
        assert_eq!(
            String::from_utf8(result).unwrap(),
            "http://nora:5000/npm/lodash/-/lodash-4.17.21.tgz"
        );
    }

    #[test]
    fn test_replace_upstream_bytes_no_match() {
        let data = b"no upstream urls here";
        let result = replace_upstream_bytes(data, "https://registry.npmjs.org", "http://nora/npm");
        assert_eq!(result, data);
    }

    #[test]
    fn test_replace_upstream_bytes_empty_upstream() {
        let data = b"https://registry.npmjs.org/test";
        let result = replace_upstream_bytes(data, "", "http://nora/npm");
        assert_eq!(result, data);
    }

    #[test]
    fn test_replace_upstream_bytes_multiple_occurrences() {
        let data = b"url1: https://registry.npmjs.org/a url2: https://registry.npmjs.org/b";
        let result =
            replace_upstream_bytes(data, "https://registry.npmjs.org", "http://nora:5000/npm");
        let s = String::from_utf8(result).unwrap();
        assert!(!s.contains("registry.npmjs.org"));
        assert!(s.contains("http://nora:5000/npm/a"));
        assert!(s.contains("http://nora:5000/npm/b"));
    }

    #[test]
    fn test_rewrite_tarball_urls_safety_net_catches_unknown_fields() {
        // Simulate metadata with upstream URL in an unexpected field
        let metadata = serde_json::json!({
            "name": "test",
            "versions": {
                "1.0.0": {
                    "dist": {
                        "tarball": "https://registry.npmjs.org/test/-/test-1.0.0.tgz"
                    },
                    "_resolved": "https://registry.npmjs.org/test/-/test-1.0.0.tgz"
                }
            }
        });
        let data = serde_json::to_vec(&metadata).unwrap();
        let result =
            rewrite_tarball_urls(&data, "http://nora:5000", "https://registry.npmjs.org").unwrap();
        let body = String::from_utf8(result).unwrap();
        // Safety net should catch the _resolved field too
        assert!(
            !body.contains("registry.npmjs.org"),
            "upstream URL leaked through _resolved field: {}",
            &body[..body.len().min(500)]
        );
    }

    /// GitHub Packages' tarball path, as public lockfiles record it
    /// (`https://npm.pkg.github.com/download/@microsoft/…/1.11.0/<sha1>`).
    #[test]
    fn github_packages_tarball_path_is_recognised() {
        assert_eq!(
            github_packages_tarball(
                "download/@microsoft/security-devops-actions-toolkit/1.11.0/04fef883382f5a7c9b9ac2015dcc419009e2a858"
            ),
            Some(("@microsoft/security-devops-actions-toolkit", "1.11.0"))
        );
        assert_eq!(
            github_packages_tarball(
                "download/@CookieMonsterTeam/cookiemonsterframework/0.2.3/46a211d57dac557c86fc55f1622a6cccdf7dd25f"
            ),
            Some(("@CookieMonsterTeam/cookiemonsterframework", "0.2.3"))
        );
        // The npm package named `download`, its tarball and anything else.
        for path in [
            "download",
            "download/-/download-8.0.0.tgz",
            "download/@vendor/a/1.0.0",
            "download/@vendor/a/1.0.0/not-hex",
            "download/@vendor/a//04fef883382f5a7c9b9ac2015dcc419009e2a858",
            "download/@vendor/a/1.0.0/04fef883382f5a7c9b9ac2015dcc419009e2a858/x",
            "download/vendor/a/1.0.0/04fef883382f5a7c9b9ac2015dcc419009e2a858",
            "@vendor/a/-/a-1.0.0.tgz",
        ] {
            assert_eq!(github_packages_tarball(path), None, "{path}");
        }
    }

    #[test]
    fn test_rewrite_tarball_urls_preserves_non_upstream_urls() {
        // homepage and repository.url should NOT be mangled
        let metadata = serde_json::json!({
            "name": "test",
            "homepage": "https://github.com/test/test",
            "repository": { "url": "git+https://github.com/test/test.git" },
            "versions": {
                "1.0.0": {
                    "dist": {
                        "tarball": "https://registry.npmjs.org/test/-/test-1.0.0.tgz"
                    }
                }
            }
        });
        let data = serde_json::to_vec(&metadata).unwrap();
        let result =
            rewrite_tarball_urls(&data, "http://nora:5000", "https://registry.npmjs.org").unwrap();
        let json: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(json["homepage"], "https://github.com/test/test");
        assert_eq!(
            json["repository"]["url"],
            "git+https://github.com/test/test.git"
        );
    }

    /// The byte-level safety net rewrites this package's upstream tarball links only:
    /// a readme that mentions the upstream registry is not touched.
    #[test]
    fn rewrite_safety_net_touches_only_tarball_links() {
        let metadata = serde_json::json!({
            "name": "test",
            "readme": "npm config set registry https://registry.npmjs.org/",
            "versions": { "1.0.0": {
                "dist": { "tarball": "https://registry.npmjs.org/test/-/test-1.0.0.tgz" },
                "_resolved": "https://registry.npmjs.org/test/-/test-1.0.0.tgz"
            } }
        });
        let data = serde_json::to_vec(&metadata).unwrap();
        let out =
            rewrite_tarball_urls(&data, "http://nora:5000", "https://registry.npmjs.org/").unwrap();
        let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(json["readme"], metadata["readme"]);
        assert_eq!(
            json["versions"]["1.0.0"]["_resolved"],
            "http://nora:5000/npm/test/-/test-1.0.0.tgz"
        );
    }

    /// mixin-deep 1.1.0 depends on another package by its upstream tarball URL: npm
    /// would fetch it straight from registry.npmjs.org (NoraUpstreamUrlLeak, 13.10).
    #[test]
    fn rewrite_safety_net_rewrites_foreign_package_tarball_links() {
        let packument = br#"{"name":"mixin-deep","versions":{"1.1.0":{"dependencies":{"is-plain-object":"https://registry.npmjs.org/is-plain-object/-/is-plain-object-2.0.0.tgz","@shopify/generate-docs":"https://registry.npmjs.org/@shopify/generate-docs/-/generate-docs-0.11.1.tgz"},"dist":{"tarball":"https://registry.npmjs.org/mixin-deep/-/mixin-deep-1.1.0.tgz"}}}}"#;
        let out = rewrite_tarball_urls(packument, "http://nora:5000", "https://registry.npmjs.org")
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let deps = &json["versions"]["1.1.0"]["dependencies"];
        assert_eq!(
            deps["is-plain-object"],
            "http://nora:5000/npm/is-plain-object/-/is-plain-object-2.0.0.tgz"
        );
        assert_eq!(
            deps["@shopify/generate-docs"],
            "http://nora:5000/npm/@shopify/generate-docs/-/generate-docs-0.11.1.tgz"
        );
    }

    /// uuid 0.0.2 keeps an http `dist.bin` tarball on the upstream (13.10 leak).
    #[test]
    fn rewrite_safety_net_rewrites_http_tarball_links() {
        let packument = br#"{"name":"uuid","versions":{"0.0.2":{"dist":{"bin":{"0.4-sunos-5.11":{"shasum":"2ff8d977261ddadfd1446cee661ab87863659e45","tarball":"http://registry.npmjs.org/uuid/-/uuid-0.0.2-0.4-sunos-5.11.tgz"}},"tarball":"https://registry.npmjs.org/uuid/-/uuid-0.0.2.tgz"}}}}"#;
        let out = rewrite_tarball_urls(packument, "http://nora:5000", "https://registry.npmjs.org")
            .unwrap();
        let body = String::from_utf8(out).unwrap();
        assert!(!body.contains("registry.npmjs.org"), "{body}");
        assert!(body.contains("http://nora:5000/npm/uuid/-/uuid-0.0.2-0.4-sunos-5.11.tgz"));
    }

    /// Mentions of the upstream that are not tarball links stay as they are.
    #[test]
    fn rewrite_safety_net_leaves_non_tarball_mentions() {
        let metadata = serde_json::json!({
            "name": "test",
            "readme": "see https://registry.npmjs.org/test and https://registry.npmjs.org/-/v1/search",
            "versions": { "1.0.0": {
                "publishConfig": { "registry": "https://registry.npmjs.org/" },
                "dist": { "tarball": "https://registry.npmjs.org/test/-/test-1.0.0.tgz" }
            } }
        });
        let data = serde_json::to_vec(&metadata).unwrap();
        let out =
            rewrite_tarball_urls(&data, "http://nora:5000", "https://registry.npmjs.org").unwrap();
        let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(json["readme"], metadata["readme"]);
        assert_eq!(
            json["versions"]["1.0.0"]["publishConfig"],
            metadata["versions"]["1.0.0"]["publishConfig"]
        );
    }

    #[test]
    fn tarball_path_shapes() {
        for ok in [
            "/a/-/a-1.tgz",
            "/@s/a/-/a-1.tgz",
            "/@s%2fa/-/a-1.tgz",
            "/@s%2Fa/-/a-1.tgz",
        ] {
            assert!(is_tarball_path(ok.as_bytes()), "{ok}");
        }
        for bad in [
            "",
            "/",
            "/a",
            "/a/-/",
            "/-/npm/v1/attestations/a@1",
            "/a/b/-/a.tgz",
            "/@/a/-/a.tgz",
            "/a/-/x/y.tgz",
        ] {
            assert!(!is_tarball_path(bad.as_bytes()), "{bad}");
        }
    }

    #[test]
    fn test_is_valid_attachment_name_valid() {
        assert!(is_valid_attachment_name("package-1.0.0.tgz"));
        assert!(is_valid_attachment_name("@scope-pkg-2.0.tgz"));
        assert!(is_valid_attachment_name("my_pkg.tgz"));
    }

    #[test]
    fn test_is_valid_attachment_name_traversal() {
        assert!(!is_valid_attachment_name("../etc/passwd"));
        assert!(!is_valid_attachment_name("foo/../bar"));
    }

    #[test]
    fn test_is_valid_attachment_name_slash() {
        assert!(!is_valid_attachment_name("path/file.tgz"));
        assert!(!is_valid_attachment_name("path\\file.tgz"));
    }

    #[test]
    fn test_is_valid_attachment_name_null_byte() {
        assert!(!is_valid_attachment_name("file\0.tgz"));
    }

    #[test]
    fn test_is_valid_attachment_name_empty() {
        assert!(!is_valid_attachment_name(""));
    }

    #[test]
    fn test_is_valid_attachment_name_special_chars() {
        assert!(!is_valid_attachment_name("file name.tgz")); // space
        assert!(!is_valid_attachment_name("file;cmd.tgz")); // semicolon
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use crate::test_helpers::{
        body_bytes, create_test_context, create_test_context_with_auth, send, send_with_headers,
    };

    #[tokio::test]
    async fn test_npm_namespace_scope_enforced() {
        use crate::auth::NamespaceAuthority;
        use crate::config::ScopeEnforcement;
        use axum::body::Bytes;
        use axum::extract::{Path, State};
        use axum::http::StatusCode;
        use axum::Extension;

        let ctx = create_test_context();
        let scoped = NamespaceAuthority::from_oidc_scope(
            "ci",
            &["@myorg/**".to_string()],
            ScopeEnforcement::Enforce,
        );

        // Out of scope -> 403, decided before any payload parsing.
        let resp = super::handle_publish(
            State(ctx.state.clone()),
            Path("@other/pkg".to_string()),
            Extension(scoped.clone()),
            None,
            crate::registry::PublishBody(Bytes::from_static(b"{}")),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // In scope -> enforcement passes (then fails payload validation, not 403).
        let resp = super::handle_publish(
            State(ctx.state.clone()),
            Path("@myorg/pkg".to_string()),
            Extension(scoped),
            None,
            crate::registry::PublishBody(Bytes::from_static(b"{}")),
        )
        .await;
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
    }
    use axum::body::Body;
    use axum::http::{header, Method, StatusCode};
    use base64::Engine;

    #[tokio::test]
    async fn test_npm_metadata_from_cache() {
        let ctx = create_test_context();

        let metadata = serde_json::json!({
            "name": "lodash",
            "versions": {
                "4.17.21": { "dist": { "tarball": "http://example.com/lodash.tgz" } }
            }
        });
        let metadata_bytes = serde_json::to_vec(&metadata).unwrap();

        ctx.state
            .storage
            .put("npm/lodash/metadata.json", &metadata_bytes)
            .await
            .unwrap();

        let response = send(&ctx.app, Method::GET, "/npm/lodash", "").await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["name"], "lodash");
    }

    #[tokio::test]
    async fn test_npm_tarball_from_cache() {
        let ctx = create_test_context();

        let tarball_data = b"fake-tarball-bytes";
        ctx.state
            .storage
            .put("npm/lodash/tarballs/lodash-4.17.21.tgz", tarball_data)
            .await
            .unwrap();

        let response = send(
            &ctx.app,
            Method::GET,
            "/npm/lodash/-/lodash-4.17.21.tgz",
            "",
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        assert_eq!(&body[..], tarball_data);
    }

    #[tokio::test]
    async fn test_npm_tarball_range_request() {
        let ctx = create_test_context();
        let tarball = b"0123456789abcdef";
        ctx.state
            .storage
            .put("npm/lodash/tarballs/lodash-4.17.21.tgz", tarball)
            .await
            .unwrap();
        let url = "/npm/lodash/-/lodash-4.17.21.tgz";

        let resp =
            send_with_headers(&ctx.app, Method::GET, url, vec![("range", "bytes=2-5")], "").await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_RANGE)
                .unwrap()
                .to_str()
                .unwrap(),
            format!("bytes 2-5/{}", tarball.len())
        );
        assert_eq!(
            resp.headers()
                .get(header::ACCEPT_RANGES)
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes"
        );
        assert_eq!(body_bytes(resp).await.as_ref(), &tarball[2..=5]);

        // A client that already holds the whole tarball resumes with `bytes=<size>-`.
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            url,
            vec![("range", &format!("bytes={}-", tarball.len())[..])],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_RANGE)
                .unwrap()
                .to_str()
                .unwrap(),
            format!("bytes */{}", tarball.len())
        );

        let resp = send(&ctx.app, Method::GET, url, "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::ACCEPT_RANGES)
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes"
        );
        assert_eq!(body_bytes(resp).await.as_ref(), &tarball[..]);
    }

    #[tokio::test]
    async fn test_npm_not_found_no_proxy() {
        let ctx = create_test_context();

        // No proxy configured, no local data
        let response = send(&ctx.app, Method::GET, "/npm/nonexistent", "").await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_npm_publish_basic() {
        let ctx = create_test_context();

        let tarball_data = b"fake-tarball";
        let base64_data = base64::engine::general_purpose::STANDARD.encode(tarball_data);

        let payload = serde_json::json!({
            "name": "mypkg",
            "versions": {
                "1.0.0": { "dist": {} }
            },
            "_attachments": {
                "mypkg-1.0.0.tgz": { "data": base64_data }
            },
            "dist-tags": { "latest": "1.0.0" }
        });

        let body_bytes = serde_json::to_vec(&payload).unwrap();
        let response = send(&ctx.app, Method::PUT, "/npm/mypkg", Body::from(body_bytes)).await;

        assert_eq!(response.status(), StatusCode::CREATED);

        // Verify tarball was stored
        let stored_tarball = ctx
            .state
            .storage
            .get("npm/mypkg/tarballs/mypkg-1.0.0.tgz")
            .await
            .unwrap();
        assert_eq!(&stored_tarball[..], tarball_data);
    }

    #[tokio::test]
    async fn test_npm_publish_multi_version_scan_regenerate() {
        // Two separate publishes of different versions must BOTH survive in the regenerated
        // packument — the version data lives in immutable per-version keys, not a merged file
        // (the #39 multi-replica lost-update fix).
        let ctx = create_test_context();
        for v in ["1.0.0", "2.0.0"] {
            let b64 = base64::engine::general_purpose::STANDARD.encode(b"tgz");
            let mut versions = serde_json::Map::new();
            versions.insert(v.to_string(), serde_json::json!({ "dist": {} }));
            let mut atts = serde_json::Map::new();
            atts.insert(
                format!("multi-{}.tgz", v),
                serde_json::json!({ "data": b64 }),
            );
            let payload =
                serde_json::json!({ "name": "multi", "versions": versions, "_attachments": atts });
            let resp = send(
                &ctx.app,
                Method::PUT,
                "/npm/multi",
                Body::from(serde_json::to_vec(&payload).unwrap()),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::CREATED);
        }
        // both per-version keys exist (immutable, distinct — no merge)
        assert!(ctx
            .state
            .storage
            .get("npm/multi/versions/1.0.0.json")
            .await
            .is_ok());
        assert!(ctx
            .state
            .storage
            .get("npm/multi/versions/2.0.0.json")
            .await
            .is_ok());
        // the regenerated packument lists BOTH
        let meta = ctx
            .state
            .storage
            .get("npm/multi/metadata.json")
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&meta).unwrap();
        let versions = json["versions"].as_object().unwrap();
        assert!(versions.contains_key("1.0.0"), "v1 lost from packument");
        assert!(versions.contains_key("2.0.0"), "v2 lost from packument");
    }

    #[tokio::test]
    async fn test_npm_publish_migrates_embedded_packument() {
        // An old-layout package (versions embedded in metadata.json, no per-version keys) is
        // lazily migrated on the next publish, preserving the old versions.
        let ctx = create_test_context();
        let old = serde_json::json!({
            "name": "legacy",
            "versions": { "1.0.0": { "name": "legacy", "version": "1.0.0", "dist": {} } },
            "dist-tags": { "latest": "1.0.0" }
        });
        ctx.state
            .storage
            .put(
                "npm/legacy/metadata.json",
                &serde_json::to_vec(&old).unwrap(),
            )
            .await
            .unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"tgz");
        let payload = serde_json::json!({
            "name": "legacy",
            "versions": { "2.0.0": { "dist": {} } },
            "_attachments": { "legacy-2.0.0.tgz": { "data": b64 } },
        });
        let resp = send(
            &ctx.app,
            Method::PUT,
            "/npm/legacy",
            Body::from(serde_json::to_vec(&payload).unwrap()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        // old version migrated to its own per-version key
        assert!(
            ctx.state
                .storage
                .get("npm/legacy/versions/1.0.0.json")
                .await
                .is_ok(),
            "old embedded version not migrated to a per-version key"
        );
        // packument has BOTH the migrated old and the new version
        let meta = ctx
            .state
            .storage
            .get("npm/legacy/metadata.json")
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&meta).unwrap();
        let versions = json["versions"].as_object().unwrap();
        assert!(versions.contains_key("1.0.0"), "migrated v1 lost");
        assert!(versions.contains_key("2.0.0"), "new v2 lost");
    }

    #[tokio::test]
    async fn test_npm_publish_scoped_with_prefixed_attachment() {
        use crate::auth::NamespaceAuthority;
        use axum::body::Bytes;
        use axum::extract::{Path, State};
        use axum::http::StatusCode;
        use axum::Extension;

        let ctx = create_test_context();

        let tarball_data = b"fake-tarball";
        let base64_data = base64::engine::general_purpose::STANDARD.encode(tarball_data);

        // Scoped package where the attachment filename includes the scope prefix
        // (e.g. "@scope/pkg-1.0.0.tgz" instead of "pkg-1.0.0.tgz"). The handler
        // must normalize this by stripping the scope prefix.
        let payload = serde_json::json!({
            "name": "@scope/mypkg",
            "versions": {
                "1.0.0": { "dist": {} }
            },
            "_attachments": {
                "@scope/mypkg-1.0.0.tgz": { "data": base64_data }
            },
            "dist-tags": { "latest": "1.0.0" }
        });

        let body_bytes = serde_json::to_vec(&payload).unwrap();

        let resp = super::handle_publish(
            State(ctx.state.clone()),
            Path("@scope/mypkg".to_string()),
            Extension(NamespaceAuthority::Unrestricted),
            None,
            crate::registry::PublishBody(Bytes::from(body_bytes)),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Verify tarball was stored with the normalized (scope-stripped) filename
        let stored_tarball = ctx
            .state
            .storage
            .get("npm/@scope/mypkg/tarballs/mypkg-1.0.0.tgz")
            .await
            .unwrap();
        assert_eq!(&stored_tarball[..], tarball_data);
    }

    #[tokio::test]
    async fn test_npm_publish_name_mismatch() {
        let ctx = create_test_context();

        let tarball_data = b"fake-tarball";
        let base64_data = base64::engine::general_purpose::STANDARD.encode(tarball_data);

        let payload = serde_json::json!({
            "name": "other",
            "versions": {
                "1.0.0": { "dist": {} }
            },
            "_attachments": {
                "other-1.0.0.tgz": { "data": base64_data }
            },
            "dist-tags": { "latest": "1.0.0" }
        });

        let body_bytes = serde_json::to_vec(&payload).unwrap();
        let response = send(&ctx.app, Method::PUT, "/npm/mypkg", Body::from(body_bytes)).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Corrupt metadata in storage → publish returns 500 (#533).
    #[tokio::test]
    async fn test_publish_corrupt_metadata_returns_500() {
        let ctx = create_test_context();

        // Plant corrupt (non-JSON) data in metadata key
        ctx.state
            .storage
            .put("npm/mypkg/metadata.json", b"NOT VALID JSON{{{")
            .await
            .unwrap();

        let tarball_data = b"fake-tarball";
        let base64_data = base64::engine::general_purpose::STANDARD.encode(tarball_data);

        let payload = serde_json::json!({
            "name": "mypkg",
            "versions": {
                "2.0.0": { "dist": {} }
            },
            "_attachments": {
                "mypkg-2.0.0.tgz": { "data": base64_data }
            },
            "dist-tags": { "latest": "2.0.0" }
        });

        let body_bytes = serde_json::to_vec(&payload).unwrap();
        let response = send(&ctx.app, Method::PUT, "/npm/mypkg", Body::from(body_bytes)).await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        // Corrupt data must NOT be overwritten — preserved for forensics
        let stored = ctx
            .state
            .storage
            .get("npm/mypkg/metadata.json")
            .await
            .unwrap();
        assert_eq!(&stored[..], b"NOT VALID JSON{{{");
    }

    /// First publish (no existing metadata) still works (#533 regression guard).
    #[tokio::test]
    async fn test_first_publish_no_existing_metadata() {
        let ctx = create_test_context();

        let tarball_data = b"fake-tarball";
        let base64_data = base64::engine::general_purpose::STANDARD.encode(tarball_data);

        let payload = serde_json::json!({
            "name": "newpkg",
            "versions": {
                "1.0.0": { "dist": {} }
            },
            "_attachments": {
                "newpkg-1.0.0.tgz": { "data": base64_data }
            },
            "dist-tags": { "latest": "1.0.0" }
        });

        let body_bytes = serde_json::to_vec(&payload).unwrap();
        let response = send(&ctx.app, Method::PUT, "/npm/newpkg", Body::from(body_bytes)).await;

        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_npm_whoami_anonymous() {
        use axum::http::StatusCode;

        let ctx = create_test_context();
        let resp = send(&ctx.app, axum::http::Method::GET, "/npm/-/whoami", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["username"], "anonymous");
    }

    #[tokio::test]
    async fn test_npm_whoami_authenticated() {
        use axum::http::StatusCode;
        use base64::Engine;

        let ctx = create_test_context_with_auth(&[("alice", "hunter2")]);

        let basic = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("alice:hunter2")
        );
        let resp = send_with_headers(
            &ctx.app,
            axum::http::Method::GET,
            "/npm/-/whoami",
            vec![("authorization", &basic)],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["username"], "alice");
    }

    #[tokio::test]
    async fn test_npm_whoami_requires_auth() {
        use axum::http::StatusCode;

        let ctx = create_test_context_with_auth(&[("alice", "hunter2")]);

        let resp = send(&ctx.app, axum::http::Method::GET, "/npm/-/whoami", "").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // A username containing `"` (reachable via the OIDC `sub` claim) must NOT
    // break the JSON or inject extra fields — handle_whoami serializes via serde.
    #[tokio::test]
    async fn test_npm_whoami_escapes_username() {
        use crate::auth::AuthenticatedUser;

        let evil = r#"a","admin":"x"#;
        let resp = super::handle_whoami(&AuthenticatedUser(evil.to_string())).await;
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["username"], evil);
        assert!(json.get("admin").is_none());
    }

    // ── ensure_npm_metadata_cached self-prime (#748) ──
    //
    // A tarball download (direct/locked fetch) arrives without a prior packument
    // request, so metadata.json is uncached. ensure_npm_metadata_cached fetches
    // the packument upstream and caches it (rewritten to NORA URLs) so the
    // per-version `time[version]` date is readable on the same request.

    /// C17: a tarball above `server.stream_threshold_mb` is spooled on the cold miss
    /// and cached with its `.sha256` and provenance sidecars; the next request
    /// streams it from storage without touching the upstream.
    #[tokio::test]
    async fn test_large_tarball_spooled_then_streamed_from_cache() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let tarball: Vec<u8> = (0..(2 * 1024 * 1024 + 3))
            .map(|i| (i % 249) as u8)
            .collect();
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/bigpkg/-/bigpkg-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball.clone()))
            .mount(&upstream)
            .await;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.server.stream_threshold_mb = 1;
        });
        let uri = "/npm/bigpkg/-/bigpkg-1.0.0.tgz";
        let resp = send(&ctx.app, Method::GET, uri, "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_bytes(resp).await[..] == tarball[..]);

        use sha2::Digest;
        let key = "npm/bigpkg/tarballs/bigpkg-1.0.0.tgz";
        let sha = hex::encode(sha2::Sha256::digest(&tarball));
        let mut cached = false;
        for _ in 0..100 {
            if ctx.state.storage.get(&super::origin_key(key)).await.is_ok() {
                cached = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(cached, "tarball and provenance are cached");
        assert_eq!(
            ctx.state.storage.pin(key).await.as_deref(),
            Some(sha.as_str())
        );
        assert_eq!(
            &ctx.state
                .storage
                .get(&format!("{key}.sha256"))
                .await
                .unwrap()[..],
            sha.as_bytes()
        );

        let resp = send(&ctx.app, Method::GET, uri, "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_bytes(resp).await[..] == tarball[..]);
        let tarball_fetches = upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path().ends_with(".tgz"))
            .count();
        assert_eq!(tarball_fetches, 1, "the hit is served from storage");
    }

    /// Happy path: tarball cache-miss → ensure_npm_metadata_cached fetches and
    /// caches the packument; tarball is also proxied and served. The cached
    /// metadata must carry the upstream release date AND have its tarball URLs
    /// rewritten to NORA.
    #[tokio::test]
    async fn test_npm_tarball_self_primes_metadata_on_cache_miss() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;

        // Packument (fetched by ensure_npm_metadata_cached → GET {proxy}/testpkg).
        let packument = serde_json::json!({
            "name": "testpkg",
            "versions": {
                "1.0.0": {
                    "dist": {
                        "tarball": format!("{}/testpkg/-/testpkg-1.0.0.tgz", upstream.uri())
                    }
                }
            },
            "time": { "1.0.0": "2020-01-15T10:30:00.000Z" }
        });
        Mock::given(method("GET"))
            .and(path("/testpkg"))
            .respond_with(ResponseTemplate::new(200).set_body_string(packument.to_string()))
            .mount(&upstream)
            .await;

        // Tarball (fetched by the cache-miss proxy path → GET {proxy}/testpkg/-/testpkg-1.0.0.tgz).
        let tarball = b"TGZ-BYTES";
        Mock::given(method("GET"))
            .and(path("/testpkg/-/testpkg-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball.to_vec()))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
        });

        // Direct/locked tarball fetch — no prior packument request.
        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/testpkg/-/testpkg-1.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], tarball);

        // ensure_npm_metadata_cached must have synchronously cached the packument.
        let cached = ctx
            .state
            .storage
            .get("npm/testpkg/metadata.json")
            .await
            .expect("metadata.json must be self-primed");
        let json: serde_json::Value = serde_json::from_slice(&cached).unwrap();
        assert_eq!(
            json["time"]["1.0.0"].as_str().unwrap(),
            "2020-01-15T10:30:00.000Z",
            "upstream release date must survive into the cached packument"
        );
        // Tarball URLs must be rewritten to NORA, not left pointing upstream.
        let tarball_url = json["versions"]["1.0.0"]["dist"]["tarball"]
            .as_str()
            .unwrap();
        assert!(
            !tarball_url.contains(&upstream.uri()[..]),
            "upstream tarball URL leaked into cached metadata: {tarball_url}"
        );
        // Stored against PUBLIC_BASE; every serve substitutes the current public_url.
        assert_eq!(
            tarball_url,
            format!("{}/npm/testpkg/-/testpkg-1.0.0.tgz", super::PUBLIC_BASE),
            "tarball URL not rewritten to NORA"
        );

        // The release dates are cached beside it, and the date resolves from them.
        let dates = ctx
            .state
            .storage
            .get("npm/testpkg/dates.json")
            .await
            .unwrap();
        let dates: serde_json::Value = serde_json::from_slice(&dates).unwrap();
        assert_eq!(dates["1.0.0"], "2020-01-15T10:30:00.000Z");
        let date = super::npm_publish_date(&ctx.state, "testpkg", "1.0.0").await;
        assert_eq!(
            date,
            Some(1579084200),
            "ISO 8601 → Unix for 2020-01-15T10:30:00Z"
        );
    }

    /// C49: with untrusted dates neither the packument's `time` nor its cache mtime
    /// (moved to now by every metadata refresh) is a publish date.
    #[tokio::test]
    async fn test_extract_npm_publish_date_untrusted_ignores_mtime() {
        for trust in [false, true] {
            let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
                cfg.server.trust_upstream_dates = trust;
            });
            let meta = serde_json::json!({ "time": { "1.0.0": "2020-01-15T10:30:00.000Z" } });
            ctx_seed_metadata(&ctx, "p", &meta).await;
            let date = super::npm_publish_date(&ctx.state, "p", "1.0.0").await;
            assert_eq!(date, trust.then_some(1579084200), "trust={trust}");
        }
    }

    /// Cached metadata short-circuits ensure_npm_metadata_cached — no upstream
    /// hit on a second tarball fetch (the packument is already in storage).
    #[tokio::test]
    async fn test_npm_tarball_self_prime_skips_when_metadata_cached() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;

        // Pre-seed the packument so ensure_npm_metadata_cached early-returns.
        let packument = serde_json::json!({
            "name": "cachedpkg",
            "versions": { "1.0.0": { "dist": {} } },
            "time": { "1.0.0": "2019-05-01T00:00:00.000Z" }
        });

        let tarball = b"TGZ";
        Mock::given(method("GET"))
            .and(path("/cachedpkg/-/cachedpkg-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball.to_vec()))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
        });
        ctx_seed_metadata(&ctx, "cachedpkg", &packument).await;

        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/cachedpkg/-/cachedpkg-1.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], tarball);

        let packument_hits = upstream
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.url.path() == "/cachedpkg")
            .count();
        assert_eq!(
            packument_hits, 0,
            "metadata already cached → ensure_npm_metadata_cached must NOT hit upstream"
        );
    }

    /// Font Awesome's registry serves tarballs at `<name>/-/<version>/<file>.tgz`.
    /// The allowlist must read the version from that form too: without it the
    /// request carries no version and passes as a metadata request.
    #[tokio::test]
    async fn allowlist_checks_a_tarball_under_a_version_directory() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        for version in ["0.9.0", "1.0.0"] {
            Mock::given(method("GET"))
                .and(path(format!(
                    "/@fortawesome/pro-test/-/{version}/pro-test-{version}.tgz"
                )))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_bytes(format!("TGZ {version}").into_bytes()),
                )
                .mount(&upstream)
                .await;
        }
        let dir = tempfile::tempdir().unwrap();
        let allowlist = dir.path().join("allowlist.json");
        std::fs::write(
            &allowlist,
            r#"{"version": 1, "entries": [
                {"registry": "npm", "name": "@fortawesome/pro-test", "version": "0.9.0"}
            ]}"#,
        )
        .unwrap();
        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.allowlist_path = Some(allowlist.to_string_lossy().into_owned());
        });
        let tarball_requests = || async {
            upstream
                .received_requests()
                .await
                .unwrap()
                .into_iter()
                .filter(|r| r.url.path().ends_with(".tgz"))
                .count()
        };

        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/@fortawesome/pro-test/-/1.0.0/pro-test-1.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "unlisted version");
        assert_eq!(
            tarball_requests().await,
            0,
            "a blocked tarball is not fetched"
        );

        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/@fortawesome/pro-test/-/0.9.0/pro-test-0.9.0.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "control: the listed version");
        assert_eq!(&body_bytes(resp).await[..], b"TGZ 0.9.0");
    }

    /// The allowlist matches name and version. A tarball whose version cannot be
    /// read from its path is refused rather than passed on as a metadata request —
    /// including a version directory that names another version than the file.
    /// GitHub Packages serves tarballs at `download/<@scope/name>/<version>/<sha1>`, with
    /// no `/-/`. That is a tarball download: curation sees its version, and the object is
    /// stored as that version's tarball with its hash sidecar and served as one.
    #[tokio::test]
    async fn a_github_packages_tarball_is_a_download() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::{header, Method, StatusCode};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        const SHA: &str = "04fef883382f5a7c9b9ac2015dcc419009e2a858";
        let upstream = MockServer::start().await;
        for version in ["0.9.0", "1.0.0"] {
            Mock::given(method("GET"))
                .and(path(format!("/download/@vendor/a/{version}/{SHA}")))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_bytes(format!("TGZ {version}").into_bytes()),
                )
                .mount(&upstream)
                .await;
        }
        let dir = tempfile::tempdir().unwrap();
        let allowlist = dir.path().join("allowlist.json");
        std::fs::write(
            &allowlist,
            r#"{"version": 1, "entries": [{"registry": "npm", "name": "@vendor/a", "version": "0.9.0"}]}"#,
        )
        .unwrap();
        let allowlist = allowlist.to_string_lossy().into_owned();
        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.allowlist_path = Some(allowlist);
        });

        let resp = send(
            &ctx.app,
            Method::GET,
            &format!("/npm/download/@vendor/a/1.0.0/{SHA}"),
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "unlisted version");
        let fetched = upstream.received_requests().await.unwrap();
        assert!(
            fetched
                .iter()
                .all(|r| !r.url.path().starts_with("/download/")),
            "a refused tarball is not fetched"
        );

        let resp = send(
            &ctx.app,
            Method::GET,
            &format!("/npm/download/@vendor/a/0.9.0/{SHA}"),
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "control: the listed version");
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/octet-stream"
        );
        assert_eq!(&body_bytes(resp).await[..], b"TGZ 0.9.0");
        let storage = &ctx.state.storage;
        // The cache write runs in the background: wait for it, with a deadline.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        for key in [
            "npm/@vendor/a/tarballs/a-0.9.0.tgz",
            "npm/@vendor/a/tarballs/a-0.9.0.tgz.sha256",
        ] {
            while storage.stat(key).await.is_none() {
                assert!(tokio::time::Instant::now() < deadline, "{key} never stored");
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
        assert!(
            storage.list("npm/download/").await.unwrap().is_empty(),
            "no tarball stored as a packument"
        );
    }

    #[tokio::test]
    async fn allowlist_refuses_a_tarball_whose_version_it_cannot_read() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r#"{"name":"pkg","versions":{}}"#),
            )
            .mount(&upstream)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let allowlist = dir.path().join("allowlist.json");
        std::fs::write(&allowlist, r#"{"version": 1, "entries": [{"registry": "npm", "name": "pkg", "version": "1.0.0"}]}"#).unwrap();
        let allowlist = allowlist.to_string_lossy().into_owned();
        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.allowlist_path = Some(allowlist);
        });
        for path in ["/npm/pkg/-/pkg.tgz", "/npm/pkg/-/9.9.9/pkg-1.0.0.tgz"] {
            let resp = send(&ctx.app, Method::GET, path, "").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{path}");
        }
        let fetched = upstream.received_requests().await.unwrap();
        assert!(
            fetched.iter().all(|r| !r.url.path().ends_with(".tgz")),
            "a refused tarball is not fetched: {:?}",
            fetched
                .iter()
                .map(|r| r.url.path().to_string())
                .collect::<Vec<_>>()
        );
        let resp = send(&ctx.app, Method::GET, "/npm/pkg", "").await;
        assert_ne!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "control: the packument passes"
        );
    }

    /// In audit mode the same tarball is logged, not refused.
    #[tokio::test]
    async fn audit_mode_lets_a_tarball_with_an_unread_version_through() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pkg/-/pkg.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"TGZ".to_vec()))
            .mount(&upstream)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let allowlist = dir.path().join("allowlist.json");
        std::fs::write(&allowlist, r#"{"version": 1, "entries": [{"registry": "npm", "name": "pkg", "version": "1.0.0"}]}"#).unwrap();
        let allowlist = allowlist.to_string_lossy().into_owned();
        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.curation.mode = crate::config::CurationMode::Audit;
            cfg.curation.allowlist_path = Some(allowlist);
        });
        let resp = send(&ctx.app, Method::GET, "/npm/pkg/-/pkg.tgz", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Internal-namespace package: ensure_npm_metadata_cached must never fetch
    /// the packument upstream (#68 dependency confusion).
    #[tokio::test]
    async fn test_npm_tarball_self_prime_skips_internal_namespace() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        // Any upstream hit would be a dependency-confusion leak — mount a canary.
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_string("LEAKED"))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.internal_namespaces = vec!["@internal/*".to_string()];
        });

        // Tarball not in cache → proxy path, but ensure_npm_metadata_cached must
        // skip the packument fetch for the internal name. Namespace isolation
        // blocks the upstream branch for an internal name → 403 (not 404).
        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/@internal/secret/-/secret-1.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let packument_hits = upstream
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.url.path().contains("@internal/secret"))
            .count();
        assert_eq!(
            packument_hits, 0,
            "internal-namespace packument must never be fetched upstream (#68)"
        );
    }

    /// `trust_upstream_dates = false` → ensure_npm_metadata_cached is never
    /// called (the gating `if` in handle_request is false).
    #[tokio::test]
    async fn test_npm_tarball_self_prime_skipped_when_distrust_upstream_dates() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        let tarball = b"TGZ";
        Mock::given(method("GET"))
            .and(path("/distrust/-/distrust-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball.to_vec()))
            .mount(&upstream)
            .await;
        // A packument hit would prove ensure_npm_metadata_cached ran.
        Mock::given(method("GET"))
            .and(path("/distrust"))
            .respond_with(ResponseTemplate::new(200).set_body_string("LEAKED"))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.server.trust_upstream_dates = false; // gate closed
        });

        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/distrust/-/distrust-1.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], tarball);

        let packument_hits = upstream
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.url.path() == "/distrust")
            .count();
        assert_eq!(
            packument_hits, 0,
            "trust_upstream_dates=false must skip ensure_npm_metadata_cached"
        );
    }

    /// No upstream proxy configured → ensure_npm_metadata_cached early-returns
    /// (proxy_url is None) and the tarball cache-miss yields 404.
    #[tokio::test]
    async fn test_npm_tarball_self_prime_skipped_when_no_proxy() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};

        // No proxy → both the tarball and the self-prime fetch have nowhere to go.
        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = None;
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/noproxy/-/noproxy-1.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        // metadata.json must NOT exist (self-prime had no upstream to fetch from).
        assert!(
            ctx.state
                .storage
                .get("npm/noproxy/metadata.json")
                .await
                .is_err(),
            "no proxy → metadata.json must not be self-primed"
        );
    }

    /// JSON-parse failure in the upstream packument falls back to byte-level URL
    /// rewrite (replace_upstream_bytes), so the cached metadata still has NORA
    /// URLs and the body is preserved (fail-safe, not dropped).
    #[tokio::test]
    async fn test_npm_tarball_self_prime_byte_level_rewrite_on_invalid_json() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;

        // Malformed packument (not valid JSON) carrying an upstream tarball URL
        // that the byte-level rewrite must still replace.
        let upstream_uri = upstream.uri();
        let upstream_uri_trimmed = upstream_uri.trim_end_matches('/');
        let bogus_packument = format!(
            "{{ not-valid-json \"tarball\": \"{upstream_uri_trimmed}/badpkg/-/badpkg-1.0.0.tgz\" }}"
        );
        Mock::given(method("GET"))
            .and(path("/badpkg"))
            .respond_with(ResponseTemplate::new(200).set_body_string(bogus_packument.clone()))
            .mount(&upstream)
            .await;

        let tarball = b"TGZ";
        Mock::given(method("GET"))
            .and(path("/badpkg/-/badpkg-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball.to_vec()))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
        });

        let resp = send(&ctx.app, Method::GET, "/npm/badpkg/-/badpkg-1.0.0.tgz", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], tarball);

        let cached = ctx
            .state
            .storage
            .get("npm/badpkg/metadata.json")
            .await
            .expect("metadata.json must be cached even for non-JSON packument");
        let cached_str = String::from_utf8_lossy(&cached);
        assert!(
            !cached_str.contains(upstream_uri_trimmed),
            "upstream URL leaked through byte-level rewrite: {cached_str}"
        );
        // Body preserved (byte-level rewrite is a prefix replace, not a drop).
        assert!(
            cached_str.contains("/npm/badpkg/-/badpkg-1.0.0.tgz"),
            "byte-level rewrite must substitute the NORA npm base: {cached_str}"
        );
    }

    // ── ensure_npm_metadata_cached test helpers ──

    async fn ctx_seed_metadata(
        ctx: &crate::test_helpers::TestContext,
        name: &str,
        packument: &serde_json::Value,
    ) {
        ctx.state
            .storage
            .put(
                &format!("npm/{name}/metadata.json"),
                &serde_json::to_vec(packument).unwrap(),
            )
            .await
            .unwrap();
    }

    /// #975: `npm/{name}/metadata.json` is the assembled form of keys this registry
    /// owns, so the proxy branch must never cache an upstream packument there while
    /// `versions/` is non-empty. That branch is reached on the metadata path only by
    /// falling through the rebuild — its write failed, or the read-back missed — and a
    /// cached upstream document drops every locally published version. It does not
    /// self-heal either: the read-path rebuild triggers on the key being absent, and
    /// after such a write it exists with the wrong content.
    #[tokio::test]
    async fn npm_proxy_does_not_cache_upstream_packument_over_local_versions() {
        use crate::storage::{FileMeta, ObjectStorage, Storage, StorageBackend};
        use std::sync::{Arc, Mutex};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        const UPSTREAM_MARKER: &str = "upstream-only-packument";
        const PACKUMENT_KEY: &str = "npm/hybrid/metadata.json";

        /// Reproduces the fall-through with no timing games: reads of the packument key
        /// always miss, so the rebuild runs, writes, and the read-back still misses.
        /// Every write is recorded so the test can assert what reached the key.
        struct PackumentReadAlwaysMisses {
            inner: ObjectStorage,
            writes: Arc<Mutex<Vec<(String, String)>>>,
        }

        #[async_trait::async_trait]
        impl StorageBackend for PackumentReadAlwaysMisses {
            async fn get(
                &self,
                key: &str,
            ) -> crate::storage::Result<(axum::body::Bytes, Option<String>)> {
                if key == PACKUMENT_KEY {
                    return Err(crate::storage::StorageError::NotFound);
                }
                self.inner.get(key).await
            }
            async fn put(&self, k: &str, d: &[u8], sha256: &str) -> crate::storage::Result<()> {
                self.writes
                    .lock()
                    .expect("writes mutex")
                    .push((k.to_string(), String::from_utf8_lossy(d).to_string()));
                self.inner.put(k, d, sha256).await
            }
            async fn pin(&self, k: &str) -> Option<String> {
                self.inner.pin(k).await
            }
            async fn delete(&self, k: &str) -> crate::storage::Result<()> {
                self.inner.delete(k).await
            }
            async fn list(&self, prefix: &str) -> crate::storage::Result<Vec<String>> {
                self.inner.list(prefix).await
            }
            async fn list_with_meta(
                &self,
                prefix: &str,
            ) -> crate::storage::Result<Vec<(String, FileMeta)>> {
                self.inner.list_with_meta(prefix).await
            }
            async fn stat(&self, k: &str) -> Option<FileMeta> {
                self.inner.stat(k).await
            }
            async fn health_check(&self) -> bool {
                self.inner.health_check().await
            }
            async fn total_size(&self) -> u64 {
                self.inner.total_size().await
            }
            fn backend_name(&self) -> &'static str {
                "packument-read-misses-test"
            }
            async fn put_from_path(
                &self,
                k: &str,
                src: &std::path::Path,
                sha256: Option<&str>,
            ) -> crate::storage::Result<()> {
                self.inner.put_from_path(k, src, sha256).await
            }
            async fn copy(
                &self,
                src: &str,
                dst: &str,
                sha256: Option<&str>,
            ) -> crate::storage::Result<()> {
                self.inner.copy(src, dst, sha256).await
            }
            async fn get_reader(
                &self,
                k: &str,
            ) -> crate::storage::Result<(
                u64,
                Option<String>,
                std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
            )> {
                self.inner.get_reader(k).await
            }
        }

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/hybrid"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                concat!(
                    r#"{{"name":"hybrid","description":"{}","dist-tags":{{"latest":"9.9.9"}},"#,
                    r#""versions":{{"9.9.9":{{"name":"hybrid","version":"9.9.9","#,
                    r#""dist":{{"tarball":"http://up/hybrid/-/hybrid-9.9.9.tgz"}}}}}}}}"#
                ),
                UPSTREAM_MARKER
            )))
            .mount(&upstream)
            .await;

        let writes = Arc::new(Mutex::new(Vec::new()));
        let storage = Storage::from_backend(Arc::new(PackumentReadAlwaysMisses {
            inner: ObjectStorage::in_memory(),
            writes: Arc::clone(&writes),
        }));
        let ctx =
            crate::test_helpers::create_test_context_with_storage_and_config(storage, |cfg| {
                cfg.npm.proxy = Some(upstream.uri());
            });

        // One locally published version, so `versions/` is non-empty and the packument
        // key belongs to the local rebuild.
        ctx.state
            .storage
            .put(
                "npm/hybrid/versions/1.0.0.json",
                br#"{"name":"hybrid","version":"1.0.0","dist":{"tarball":"http://nora/npm/hybrid/-/hybrid-1.0.0.tgz"}}"#,
            )
            .await
            .unwrap();

        let response = send(&ctx.app, Method::GET, "/npm/hybrid", "").await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "the request is still served"
        );

        // The proxy cache write is detached; give it room to land.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let recorded = writes.lock().expect("writes mutex").clone();
        let to_packument: Vec<&(String, String)> = recorded
            .iter()
            .filter(|(k, _)| k == PACKUMENT_KEY)
            .collect();
        // Positive control: the rebuild really ran and wrote the assembled document,
        // which is what puts this request on the fall-through path in the first place.
        assert!(
            to_packument.iter().any(|(_, body)| body.contains("1.0.0")),
            "the local rebuild must have written the assembled packument: {to_packument:?}"
        );
        assert!(
            !to_packument
                .iter()
                .any(|(_, body)| body.contains(UPSTREAM_MARKER)),
            "#975: the upstream packument must never be cached over a key the local versions own — found: {to_packument:?}"
        );
    }

    /// The packument rebuild reads `versions/` concurrently. It used to walk the keys
    /// one at a time, which on an object store is a round-trip per version, and #956
    /// put that walk on a read path — so a package with a few thousand versions paid
    /// them serially on the first request after the packument went missing. A backend
    /// that records how many reads are in flight at once proves the fan-out is real; a
    /// sequential walk never exceeds one.
    #[tokio::test]
    async fn npm_packument_rebuild_reads_versions_concurrently() {
        use crate::storage::{FileMeta, ObjectStorage, Storage, StorageBackend};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct TracksInFlight {
            inner: ObjectStorage,
            in_flight: AtomicUsize,
            peak: AtomicUsize,
        }

        #[async_trait::async_trait]
        impl StorageBackend for TracksInFlight {
            async fn get(
                &self,
                key: &str,
            ) -> crate::storage::Result<(axum::body::Bytes, Option<String>)> {
                let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                self.peak.fetch_max(now, Ordering::SeqCst);
                // Hold the slot briefly so overlapping reads actually overlap.
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                let out = self.inner.get(key).await;
                self.in_flight.fetch_sub(1, Ordering::SeqCst);
                out
            }
            async fn put(&self, k: &str, d: &[u8], sha256: &str) -> crate::storage::Result<()> {
                self.inner.put(k, d, sha256).await
            }
            async fn pin(&self, k: &str) -> Option<String> {
                self.inner.pin(k).await
            }
            async fn delete(&self, k: &str) -> crate::storage::Result<()> {
                self.inner.delete(k).await
            }
            async fn list(&self, prefix: &str) -> crate::storage::Result<Vec<String>> {
                self.inner.list(prefix).await
            }
            async fn list_with_meta(
                &self,
                prefix: &str,
            ) -> crate::storage::Result<Vec<(String, FileMeta)>> {
                self.inner.list_with_meta(prefix).await
            }
            async fn stat(&self, k: &str) -> Option<FileMeta> {
                self.inner.stat(k).await
            }
            async fn health_check(&self) -> bool {
                self.inner.health_check().await
            }
            async fn total_size(&self) -> u64 {
                self.inner.total_size().await
            }
            fn backend_name(&self) -> &'static str {
                "in-flight-tracking-test"
            }
            async fn put_from_path(
                &self,
                k: &str,
                src: &std::path::Path,
                sha256: Option<&str>,
            ) -> crate::storage::Result<()> {
                self.inner.put_from_path(k, src, sha256).await
            }
            async fn copy(
                &self,
                src: &str,
                dst: &str,
                sha256: Option<&str>,
            ) -> crate::storage::Result<()> {
                self.inner.copy(src, dst, sha256).await
            }
            async fn get_reader(
                &self,
                k: &str,
            ) -> crate::storage::Result<(
                u64,
                Option<String>,
                std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
            )> {
                self.inner.get_reader(k).await
            }
        }

        let backend = Arc::new(TracksInFlight {
            inner: ObjectStorage::in_memory(),
            in_flight: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        });
        let storage = Storage::from_backend(Arc::clone(&backend) as Arc<dyn StorageBackend>);

        for i in 1..=8 {
            storage
                .put(
                    &format!("npm/conc/versions/1.0.{i}.json"),
                    format!(r#"{{"name":"conc","version":"1.0.{i}"}}"#).as_bytes(),
                )
                .await
                .unwrap();
        }
        backend.peak.store(0, Ordering::SeqCst);

        crate::registry::npm::regenerate_packument(&storage, "conc")
            .await
            .expect("rebuild succeeds");

        assert!(
            backend.peak.load(Ordering::SeqCst) > 1,
            "the rebuild must read versions concurrently — peak in-flight reads was {}",
            backend.peak.load(Ordering::SeqCst)
        );
        // Correctness is unchanged: every version is still in the assembled document.
        let packument = storage.get("npm/conc/metadata.json").await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&packument).unwrap();
        let versions = json["versions"].as_object().expect("versions object");
        assert_eq!(versions.len(), 8, "all versions assembled: {versions:?}");
    }

    async fn publish(app: &axum::Router, name: &str, ver: &str) -> StatusCode {
        let short = name.rsplit('/').next().unwrap();
        let payload = serde_json::json!({
            "name": name,
            "versions": { ver: { "name": name, "version": ver, "dist": {} } },
            "_attachments": { format!("{short}-{ver}.tgz"): {
                "data": base64::engine::general_purpose::STANDARD.encode(b"tgz")
            } },
        });
        let body = Body::from(serde_json::to_vec(&payload).unwrap());
        send(app, Method::PUT, &format!("/npm/{name}"), body)
            .await
            .status()
    }

    async fn packument(app: &axum::Router, name: &str) -> serde_json::Value {
        let resp = send(app, Method::GET, &format!("/npm/{name}"), "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        serde_json::from_slice(&body_bytes(resp).await).unwrap()
    }

    /// A package published here, outside any internal namespace, is never
    /// revalidated upstream once its packument is stale: an upstream squatter of the
    /// same name must not replace it, and the name must not leak upstream.
    #[tokio::test]
    async fn hosted_packument_is_never_revalidated_upstream() {
        use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "corp-pkg", "versions": { "9.9.9": { "dist": {} } },
                "dist-tags": { "latest": "9.9.9" }
            })))
            .mount(&upstream)
            .await;
        let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.npm.metadata_ttl = 0; // every cache hit is stale
        });
        assert_eq!(
            publish(&ctx.app, "corp-pkg", "1.0.0").await,
            StatusCode::CREATED
        );
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

        let json = packument(&ctx.app, "corp-pkg").await;
        assert!(json["versions"].get("1.0.0").is_some(), "{json}");
        assert!(json["versions"].get("9.9.9").is_none(), "{json}");
        assert!(upstream.received_requests().await.unwrap().is_empty());
    }

    /// Invariant: an internal-namespace package published here never depends on the
    /// upstream. With a dead upstream and every cache hit stale, its packument (full
    /// and abbreviated) and tarball are 200 and the upstream sees no request at all.
    #[tokio::test]
    async fn internal_package_never_touches_a_dead_upstream() {
        use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(503))
            .mount(&upstream)
            .await;
        let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.npm.metadata_ttl = 0;
            cfg.curation.internal_namespaces = vec!["@corp/*".to_string()];
        });
        assert_eq!(
            publish(&ctx.app, "@corp/lib", "1.0.0").await,
            StatusCode::CREATED
        );
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

        let resp = send(&ctx.app, Method::GET, "/npm/@corp/lib", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = crate::test_helpers::send_with_headers(
            &ctx.app,
            Method::GET,
            "/npm/@corp/lib",
            vec![("accept", "application/vnd.npm.install-v1+json")],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = send(&ctx.app, Method::GET, "/npm/@corp/lib/-/lib-1.0.0.tgz", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], b"tgz");
        let seen = upstream.received_requests().await.unwrap();
        assert!(
            seen.is_empty(),
            "upstream contacted: {:?}",
            seen.iter()
                .map(|r| r.url.path().to_string())
                .collect::<Vec<_>>()
        );
    }

    /// Publishing a name whose packument is a proxy cache (provenance sidecar) must not
    /// adopt the upstream versions as local ones, nor refuse them as already published.
    #[tokio::test]
    async fn publish_over_proxied_packument_does_not_adopt_upstream_versions() {
        let ctx = create_test_context();
        let key = "npm/adopted/metadata.json";
        let upstream_doc = serde_json::json!({
            "name": "adopted",
            "versions": { "1.0.0": { "dist": {} }, "2.0.0": { "dist": {} } }
        });
        let doc = serde_json::to_vec(&upstream_doc).unwrap();
        ctx.state.storage.put(key, &doc).await.unwrap();
        let sidecar = super::origin_key(key);
        ctx.state
            .storage
            .put(&sidecar, b"npm:x\nabc")
            .await
            .unwrap();

        assert_eq!(
            publish(&ctx.app, "adopted", "1.0.0").await,
            StatusCode::CREATED
        );
        let stored = ctx.state.storage.get(key).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&stored).unwrap();
        assert_eq!(json["versions"].as_object().unwrap().len(), 1, "{json}");
        assert!(ctx
            .state
            .storage
            .stat("npm/adopted/versions/2.0.0.json")
            .await
            .is_none());
        assert!(ctx.state.storage.stat(&sidecar).await.is_none());
    }

    /// `npm dist-tag add|ls|rm` on a hosted package; `ls` is never proxied.
    #[tokio::test]
    async fn dist_tag_add_ls_rm() {
        let ctx = create_test_context();
        assert_eq!(
            publish(&ctx.app, "@corp/tagged", "1.0.0").await,
            StatusCode::CREATED
        );
        assert_eq!(
            publish(&ctx.app, "@corp/tagged", "2.0.0").await,
            StatusCode::CREATED
        );
        let tag_url = "/npm/-/package/@corp/tagged/dist-tags/beta";
        let ls_url = "/npm/-/package/@corp/tagged/dist-tags";

        let resp = send(&ctx.app, Method::PUT, tag_url, "\"1.0.0\"").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let tags: serde_json::Value = serde_json::from_slice(
            &body_bytes(send(&ctx.app, Method::GET, ls_url, "").await).await,
        )
        .unwrap();
        assert_eq!(tags["beta"], "1.0.0");
        assert_eq!(tags["latest"], "2.0.0");
        assert_eq!(
            packument(&ctx.app, "@corp/tagged").await["dist-tags"]["beta"],
            "1.0.0"
        );

        // Unknown version, removing `latest`, unknown package: refused.
        let resp = send(&ctx.app, Method::PUT, tag_url, "\"3.0.0\"").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let latest = "/npm/-/package/@corp/tagged/dist-tags/latest";
        let resp = send(&ctx.app, Method::DELETE, latest, "").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let resp = send(&ctx.app, Method::GET, "/npm/-/package/nope/dist-tags", "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let resp = send(&ctx.app, Method::DELETE, tag_url, "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(packument(&ctx.app, "@corp/tagged").await["dist-tags"]
            .get("beta")
            .is_none());
    }

    /// `npm deprecate` PUTs the packument back without attachments; only the
    /// `deprecated` field is applied, and `""` clears it.
    #[tokio::test]
    async fn deprecate_sets_and_clears() {
        let ctx = create_test_context();
        assert_eq!(
            publish(&ctx.app, "old-pkg", "1.0.0").await,
            StatusCode::CREATED
        );
        let put = |msg: &str| {
            serde_json::to_vec(&serde_json::json!({
                "name": "old-pkg",
                "versions": { "1.0.0": { "deprecated": msg, "description": "ignored" } }
            }))
            .unwrap()
        };
        let resp = send(
            &ctx.app,
            Method::PUT,
            "/npm/old-pkg",
            Body::from(put("use v2")),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json = packument(&ctx.app, "old-pkg").await;
        assert_eq!(json["versions"]["1.0.0"]["deprecated"], "use v2");
        assert!(json["versions"]["1.0.0"].get("description").is_none());

        let resp = send(&ctx.app, Method::PUT, "/npm/old-pkg", Body::from(put(""))).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json = packument(&ctx.app, "old-pkg").await;
        assert!(json["versions"]["1.0.0"].get("deprecated").is_none());
    }

    /// `npm unpublish` as the npm CLI drives it: PUT the packument minus a version to
    /// `/-rev/`, DELETE the tarball by its URL path, DELETE `/-rev/` for the rest. A
    /// version string is never published again.
    #[tokio::test]
    async fn unpublish_version_then_package() {
        let ctx = create_test_context();
        let name = "@corp/gone";
        for ver in ["1.0.0", "2.0.0"] {
            assert_eq!(publish(&ctx.app, name, ver).await, StatusCode::CREATED);
        }
        let tag = "/npm/-/package/@corp/gone/dist-tags/beta";
        assert_eq!(
            send(&ctx.app, Method::PUT, tag, "\"2.0.0\"").await.status(),
            StatusCode::OK
        );
        let put = |doc: &serde_json::Value| Body::from(serde_json::to_vec(doc).unwrap());
        let rev = "/npm/@corp/gone/-rev/undefined";

        // A body missing two versions is a stale read: refused, nothing removed.
        let mut doc = packument(&ctx.app, name).await;
        doc["versions"] = serde_json::json!({});
        let resp = send(&ctx.app, Method::PUT, rev, put(&doc)).await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        let mut doc = packument(&ctx.app, name).await;
        doc["versions"].as_object_mut().unwrap().remove("2.0.0");
        let resp = send(&ctx.app, Method::PUT, rev, put(&doc)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json = packument(&ctx.app, name).await;
        assert_eq!(json["versions"].as_object().unwrap().len(), 1, "{json}");
        assert_eq!(json["dist-tags"]["latest"], "1.0.0", "{json}");
        assert!(json["dist-tags"].get("beta").is_none(), "{json}");
        assert!(
            json["time"].get("2.0.0").is_some(),
            "tombstone kept: {json}"
        );
        let storage = &ctx.state.storage;
        assert!(storage
            .stat("npm/@corp/gone/tarballs/gone-2.0.0.tgz")
            .await
            .is_none());
        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/@corp/gone/-/gone-2.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // The tarball DELETE carries the tarball URL's path (`npm/` included).
        let del = "/npm/npm/@corp/gone/-/gone-2.0.0.tgz/-rev/2-x";
        assert_eq!(
            send(&ctx.app, Method::DELETE, del, "").await.status(),
            StatusCode::OK
        );
        let live = "/npm/npm/@corp/gone/-/gone-1.0.0.tgz/-rev/2-x";
        assert_eq!(
            send(&ctx.app, Method::DELETE, live, "").await.status(),
            StatusCode::CONFLICT,
            "a published version's tarball is not deleted"
        );

        assert_eq!(publish(&ctx.app, name, "2.0.0").await, StatusCode::CONFLICT);
        assert_eq!(publish(&ctx.app, name, "3.0.0").await, StatusCode::CREATED);

        let resp = send(&ctx.app, Method::DELETE, rev, "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = send(&ctx.app, Method::GET, "/npm/@corp/gone", "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(storage
            .list("npm/@corp/gone/tarballs/")
            .await
            .unwrap()
            .is_empty());
        assert_eq!(publish(&ctx.app, name, "1.0.0").await, StatusCode::CONFLICT);

        // A package not published here is never unpublished (403: npm takes a 404
        // as already done).
        let resp = send(&ctx.app, Method::DELETE, "/npm/lodash/-rev/1", "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// Hosted packuments carry `time` (per version, `created`, `modified`).
    #[tokio::test]
    async fn hosted_packument_has_time_map() {
        let ctx = create_test_context();
        assert_eq!(
            publish(&ctx.app, "timed", "1.0.0").await,
            StatusCode::CREATED
        );
        assert_eq!(
            publish(&ctx.app, "timed", "1.1.0").await,
            StatusCode::CREATED
        );
        let json = packument(&ctx.app, "timed").await;
        let time = &json["time"];
        assert_eq!(time["created"], time["1.0.0"], "{json}");
        assert_eq!(time["modified"], time["1.1.0"], "{json}");
    }

    fn iso_ago(secs: i64) -> String {
        (chrono::Utc::now() - chrono::Duration::seconds(secs))
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string()
    }

    /// R2-18: with the npm cooldown enforced on trusted dates, a version published
    /// here (outside any internal namespace) downloads at once — its `time` is the
    /// local publish time — while an upstream version that young is still refused.
    #[tokio::test]
    async fn hosted_version_is_exempt_from_min_release_age() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/young"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "young", "dist-tags": { "latest": "1.0.0" },
                "versions": { "1.0.0": { "dist": {} } },
                "time": { "1.0.0": iso_ago(3600) }
            })))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/young/-/young-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"tgz".to_vec()))
            .mount(&upstream)
            .await;
        let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.min_release_age = Some("7d".to_string());
            cfg.server.trust_upstream_dates = true;
        });
        assert_eq!(
            publish(&ctx.app, "ours", "1.0.0").await,
            StatusCode::CREATED
        );
        let resp = send(&ctx.app, Method::GET, "/npm/ours/-/ours-1.0.0.tgz", "").await;
        assert_eq!(resp.status(), StatusCode::OK, "our own publish is not held");
        assert_eq!(&body_bytes(resp).await[..], b"tgz");

        let resp = send(&ctx.app, Method::GET, "/npm/young/-/young-1.0.0.tgz", "").await;
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "upstream cooldown stays"
        );
    }

    /// R2-19: an attachment named for another version's tarball is refused, and the
    /// bytes already published under that name are left alone; a different tarball
    /// stored (not proxied) under a new version's name is a 409.
    #[tokio::test]
    async fn publish_cannot_overwrite_another_tarball() {
        let ctx = create_test_context();
        assert_eq!(publish(&ctx.app, "imm", "1.0.0").await, StatusCode::CREATED);
        let key = "npm/imm/tarballs/imm-1.0.0.tgz";
        let before = ctx.state.storage.get(key).await.unwrap();

        let payload = serde_json::json!({
            "name": "imm",
            "versions": { "1.0.1": { "name": "imm", "version": "1.0.1", "dist": {} } },
            "_attachments": { "imm-1.0.0.tgz": {
                "data": base64::engine::general_purpose::STANDARD.encode(b"evil")
            } },
        });
        let body = Body::from(serde_json::to_vec(&payload).unwrap());
        let resp = send(&ctx.app, Method::PUT, "/npm/imm", body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(ctx.state.storage.get(key).await.unwrap(), before);
        assert!(ctx
            .state
            .storage
            .stat("npm/imm/versions/1.0.1.json")
            .await
            .is_none());

        // A tarball already cached under the name of a version now published here.
        ctx.state
            .storage
            .put("npm/imm/tarballs/imm-2.0.0.tgz", b"upstream bytes")
            .await
            .unwrap();
        assert_eq!(
            publish(&ctx.app, "imm", "2.0.0").await,
            StatusCode::CONFLICT
        );
        assert_eq!(
            &ctx.state
                .storage
                .get("npm/imm/tarballs/imm-2.0.0.tgz")
                .await
                .unwrap()[..],
            b"upstream bytes"
        );
    }

    /// R2-20: a package published here never fetches a tarball it does not have from
    /// the upstream, and its name is kept out of the audit forwarded there.
    #[tokio::test]
    async fn hosted_package_never_reaches_upstream() {
        use wiremock::matchers::{any, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let upstream = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/-/npm/v1/security/advisories/bulk"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&upstream)
            .await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"squatted".to_vec()))
            .mount(&upstream)
            .await;
        let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.internal_namespaces = vec!["@corp/*".to_string()];
        });
        assert_eq!(
            publish(&ctx.app, "owned", "1.0.0").await,
            StatusCode::CREATED
        );

        let resp = send(&ctx.app, Method::GET, "/npm/owned/-/owned-0.9.0.tgz", "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let resp = send(&ctx.app, Method::GET, "/npm/owned/-/owned-1.0.0.tgz", "").await;
        assert_eq!(resp.status(), StatusCode::OK);

        let audit = serde_json::json!({ "owned": ["1.0.0"], "lodash": ["4.17.20"] });
        let resp = send(
            &ctx.app,
            Method::POST,
            "/npm/-/npm/v1/security/advisories/bulk",
            audit.to_string(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let requests = upstream.received_requests().await.unwrap();
        assert!(
            requests.iter().all(|r| !r.url.path().contains("owned")),
            "no request for the hosted name: {:?}",
            requests.iter().map(|r| r.url.path()).collect::<Vec<_>>()
        );
        let forwarded: serde_json::Value = serde_json::from_slice(
            &requests
                .iter()
                .find(|r| r.method.as_str() == "POST")
                .expect("the audit was forwarded")
                .body,
        )
        .unwrap();
        assert_eq!(forwarded, serde_json::json!({ "lodash": ["4.17.20"] }));
    }

    /// Tarball URLs follow the current `public_url` on every serve path: a fresh
    /// hosted packument, a version stored with an absolute URL before PUBLIC_BASE, a
    /// fresh proxied packument and one an upstream 304 keeps.
    #[tokio::test]
    async fn tarball_urls_follow_public_url() {
        use crate::test_helpers::{
            create_test_context_with_config, create_test_context_with_storage_and_config,
        };
        use wiremock::matchers::{header, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(header("if-none-match", "\"v1\""))
            .respond_with(ResponseTemplate::new(304))
            .with_priority(1)
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"v1\"")
                    .set_body_json(serde_json::json!({
                        "name": "lodash",
                        "versions": { "1.0.0": { "dist": {
                            "tarball": format!("{}/lodash/-/lodash-1.0.0.tgz", upstream.uri())
                        } } }
                    })),
            )
            .mount(&upstream)
            .await;
        let old = create_test_context_with_config(|cfg| {
            cfg.server.public_url = Some("https://old.example".into());
            cfg.npm.proxy = Some(upstream.uri());
        });
        let storage = old.state.storage.clone();
        let tarball =
            |json: &serde_json::Value| json["versions"]["1.0.0"]["dist"]["tarball"].clone();

        assert_eq!(
            publish(&old.app, "hosted", "1.0.0").await,
            StatusCode::CREATED
        );
        assert_eq!(
            tarball(&packument(&old.app, "hosted").await),
            "https://old.example/npm/hosted/-/hosted-1.0.0.tgz"
        );
        assert_eq!(
            tarball(&packument(&old.app, "lodash").await),
            "https://old.example/npm/lodash/-/lodash-1.0.0.tgz"
        );
        // Published before PUBLIC_BASE: an absolute URL in the version document.
        storage
            .put(
                "npm/legacy/versions/1.0.0.json",
                br#"{"dist":{"tarball":"http://older:4000/npm/legacy/-/legacy-1.0.0.tgz"}}"#,
            )
            .await
            .unwrap();
        super::regenerate_packument(&storage, "legacy")
            .await
            .unwrap();
        // The proxy cache write is spawned; wait for it.
        for _ in 0..50 {
            if storage.stat("npm/lodash/metadata.json").await.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        let new = create_test_context_with_storage_and_config(storage.clone(), |cfg| {
            cfg.server.public_url = Some("https://new.example/".into());
            cfg.npm.proxy = Some(upstream.uri());
        });
        for name in ["hosted", "legacy", "lodash"] {
            assert_eq!(
                tarball(&packument(&new.app, name).await),
                format!("https://new.example/npm/{name}/-/{name}-1.0.0.tgz"),
                "fresh {name}"
            );
        }

        // Stale: the upstream answers 304 and the cached body is served.
        crate::registry::write_validators(
            &storage,
            "npm/lodash/metadata.json",
            &crate::registry::Validators {
                etag: Some("\"v1\"".to_string()),
                last_modified: None,
            },
        )
        .await;
        let stale = create_test_context_with_storage_and_config(storage, |cfg| {
            cfg.server.public_url = Some("https://stale.example".into());
            cfg.npm.proxy = Some(upstream.uri());
            cfg.npm.metadata_ttl = 0;
        });
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        let before = crate::metrics::PROXY_UPSTREAM_304_TOTAL
            .with_label_values(&["npm"])
            .get();
        assert_eq!(
            tarball(&packument(&stale.app, "lodash").await),
            "https://stale.example/npm/lodash/-/lodash-1.0.0.tgz"
        );
        let after = crate::metrics::PROXY_UPSTREAM_304_TOTAL
            .with_label_values(&["npm"])
            .get();
        assert!(after > before, "served through a 304");
    }

    /// Digest quarantine never holds a tarball published here.
    #[tokio::test]
    async fn quarantine_skips_hosted_tarballs() {
        let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
            cfg.curation.quarantine = Some(crate::digest_quarantine::QuarantineMode::Enforce);
            cfg.curation.quarantine_ttl = Some("1h".to_string());
        });
        assert_eq!(
            publish(&ctx.app, "fresh", "1.0.0").await,
            StatusCode::CREATED
        );
        let resp = send(&ctx.app, Method::GET, "/npm/fresh/-/fresh-1.0.0.tgz", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], b"tgz");
    }

    /// An allowlisted integrity pin is checked on the first proxied download too: a
    /// mismatching body is neither served nor cached.
    #[tokio::test]
    async fn integrity_pin_checked_on_first_proxied_download() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"TAMPERED".to_vec()))
            .mount(&upstream)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let allowlist = dir.path().join("allowlist.json");
        let pin = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(b"GENUINE"));
        std::fs::write(
            &allowlist,
            format!(
                r#"{{"version": 1, "entries": [{{"registry": "npm", "name": "pinned",
                "version": "1.0.0", "integrity": "sha256:{pin}"}}]}}"#
            ),
        )
        .unwrap();
        let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.allowlist_path = Some(allowlist.to_string_lossy().into_owned());
        });
        let resp = send(&ctx.app, Method::GET, "/npm/pinned/-/pinned-1.0.0.tgz", "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(ctx
            .state
            .storage
            .stat("npm/pinned/tarballs/pinned-1.0.0.tgz")
            .await
            .is_none());
    }

    /// C54: a tarball published here that fails its pin may be the only copy: it is
    /// kept, answered 500 when read whole and cut off when streamed, and its name never
    /// goes upstream.
    #[tokio::test]
    async fn tampered_hosted_tarball_is_kept_not_refetched() {
        use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"upstream".to_vec()))
            .mount(&upstream)
            .await;
        let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.server.stream_threshold_mb = 1;
        });
        let root = std::path::Path::new(&ctx.state.config.storage.path).to_path_buf();
        assert_eq!(
            publish(&ctx.app, "corp", "1.0.0").await,
            StatusCode::CREATED
        );
        let small = "npm/corp/tarballs/corp-1.0.0.tgz";
        std::fs::write(root.join(small), b"rot").unwrap();
        let resp = send(&ctx.app, Method::GET, "/npm/corp/-/corp-1.0.0.tgz", "").await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let big = "npm/corpbig/tarballs/corpbig-1.0.0.tgz";
        let mut bytes = vec![7u8; 2 * 1024 * 1024];
        ctx.state.storage.put(big, &bytes).await.unwrap();
        bytes[1_500_000] ^= 0xff;
        std::fs::write(root.join(big), &bytes).unwrap();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/corpbig/-/corpbig-1.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "headers go out before EOF");
        assert!(axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .is_err());

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        for key in [small, big] {
            assert!(ctx.state.storage.stat(key).await.is_some(), "{key} kept");
        }
        // Metadata lookups (publish dates) aside, no tarball is fetched.
        let requests = upstream.received_requests().await.unwrap();
        assert!(!requests.iter().any(|r| r.url.path().ends_with(".tgz")));
    }

    /// C54: a proxied tarball (provenance recorded for the bytes it holds) that fails
    /// its pin is dropped and refetched. A publish over a proxied copy drops that
    /// provenance, so the published tarball is never taken for one.
    #[tokio::test]
    async fn tampered_proxied_tarball_is_refetched() {
        use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"upstream".to_vec()))
            .mount(&upstream)
            .await;
        let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
        });
        let key = "npm/prox/tarballs/prox-1.0.0.tgz";
        let uri = "/npm/prox/-/prox-1.0.0.tgz";
        let origin = super::origin_key(key);
        let resp = send(&ctx.app, Method::GET, uri, "").await;
        assert_eq!(&body_bytes(resp).await[..], b"upstream");
        for _ in 0..100 {
            if ctx.state.storage.get(&origin).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        std::fs::write(
            std::path::Path::new(&ctx.state.config.storage.path).join(key),
            b"rotten!!",
        )
        .unwrap();

        let resp = send(&ctx.app, Method::GET, uri, "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], b"upstream");
        let requests = upstream.received_requests().await.unwrap();
        let fetches = requests
            .iter()
            .filter(|r| r.url.path() == "/prox/-/prox-1.0.0.tgz");
        assert_eq!(fetches.count(), 2, "fetched, then refetched");
        // Let the background re-cache (tarball, then its provenance) land.
        let mut recached = false;
        for _ in 0..100 {
            if ctx.state.storage.get(key).await.is_ok() {
                recached = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(recached, "the refetched tarball is cached again");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        assert_eq!(
            publish(&ctx.app, "prox", "1.0.0").await,
            StatusCode::CREATED
        );
        assert!(ctx.state.storage.get(&origin).await.is_err());
    }

    /// `npm ping`, `npm search` and `npm login` are registry endpoints, not packuments:
    /// nothing under `npm/-/` is cached, and only search reaches the upstream, with
    /// its query, while no name is private.
    #[tokio::test]
    async fn registry_endpoints_are_not_packuments() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/-/v1/search"))
            .and(query_param("text", "left pad"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "objects": [], "total": 0
            })))
            .mount(&upstream)
            .await;
        let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
        });

        let resp = send(&ctx.app, Method::GET, "/npm/-/ping", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], b"{}");
        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/-/v1/search?text=left%20pad",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["total"], 0);
        let resp = send(&ctx.app, Method::GET, "/npm/-/org/corp/package", "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let requests = upstream.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1, "only the search went upstream");
        assert!(ctx.state.storage.list("npm/-/").await.unwrap().is_empty());

        // Under a namespace filter the search text could carry a private name.
        let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.curation.internal_namespaces = vec!["@corp/*".to_string()];
        });
        let resp = send(&ctx.app, Method::GET, "/npm/-/v1/search?text=%40corp", "").await;
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        assert_eq!(upstream.received_requests().await.unwrap().len(), 1);
    }

    /// `npm login` gets a 405 that says how to set up a token, without credentials,
    /// and the PUT never becomes a publish.
    #[tokio::test]
    async fn npm_login_points_at_token_setup() {
        let ctx = create_test_context_with_auth(&[("admin", "secret")]);
        let user = serde_json::json!({
            "_id": "org.couchdb.user:bob", "name": "bob", "password": "x",
            "_attachments": { "x.tgz": { "data": "eA==" } }, "versions": {}
        });
        let resp = send(
            &ctx.app,
            Method::PUT,
            "/npm/-/user/org.couchdb.user:bob",
            Body::from(serde_json::to_vec(&user).unwrap()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        let error = body_json(resp).await["error"].as_str().unwrap().to_string();
        assert!(error.contains("_authToken"), "{error}");
        assert!(ctx.state.storage.list("npm/").await.unwrap().is_empty());
    }

    async fn body_json(resp: axum::http::Response<Body>) -> serde_json::Value {
        serde_json::from_slice(&body_bytes(resp).await).unwrap()
    }
}

// ── Spec conformance tests (#390) ─────────────────────────────────────
//
// Invariant: after tarball URL rewriting, no upstream registry domains
// remain in the response. Uses golden fixtures from testdata/npm/.

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod spec_conformance_tests {
    use super::*;

    const NPM_UPSTREAM_DOMAIN: &str = "registry.npmjs.org";

    /// Assert that no upstream URLs remain in rewritten response body, apart from
    /// the intentional pass-throughs (`UPSTREAM_PASSTHROUGH_PATHS`).
    fn assert_no_upstream_urls(body: &str, context: &str) {
        let leaked = body.match_indices(NPM_UPSTREAM_DOMAIN).any(|(at, _)| {
            let rest = &body[at + NPM_UPSTREAM_DOMAIN.len()..];
            !UPSTREAM_PASSTHROUGH_PATHS
                .iter()
                .any(|p| rest.starts_with(p))
        });
        assert!(
            !leaked,
            "upstream domain '{}' leaked in {}: {}",
            NPM_UPSTREAM_DOMAIN,
            context,
            &body[..body.len().min(500)]
        );
    }

    fn load_fixture(name: &str) -> Vec<u8> {
        let path = format!("{}/testdata/npm/{}", env!("CARGO_MANIFEST_DIR"), name);
        std::fs::read(&path).unwrap_or_else(|e| panic!("failed to load fixture {}: {}", path, e))
    }

    // ── Regular package rewrite ──

    #[test]
    fn attestations_url_passes_through_and_tarball_is_rewritten() {
        let packument = br#"{"name":"vite-node","versions":{"1.0.0":{"dist":{"tarball":"https://registry.npmjs.org/vite-node/-/vite-node-1.0.0.tgz","attestations":{"url":"https://registry.npmjs.org/-/npm/v1/attestations/vite-node@1.0.0"}}}}}"#;
        let body = String::from_utf8(
            rewrite_tarball_urls(packument, "http://nora:4000", "https://registry.npmjs.org")
                .unwrap(),
        )
        .unwrap();
        assert!(body.contains("http://nora:4000/npm/vite-node/-/vite-node-1.0.0.tgz"));
        assert!(body.contains("https://registry.npmjs.org/-/npm/v1/attestations/vite-node@1.0.0"));
        assert_no_upstream_urls(&body, "attestations pass-through");
    }

    #[test]
    fn test_regular_package_golden_no_upstream_leak() {
        let fixture = load_fixture("package-metadata.json");
        let result =
            rewrite_tarball_urls(&fixture, "http://nora:4000", "https://registry.npmjs.org")
                .unwrap();
        let body = String::from_utf8(result).unwrap();
        assert_no_upstream_urls(&body, "regular package rewrite");
    }

    #[test]
    fn test_regular_package_golden_all_tarballs_rewritten() {
        let fixture = load_fixture("package-metadata.json");
        let result =
            rewrite_tarball_urls(&fixture, "http://nora:4000", "https://registry.npmjs.org")
                .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&result).unwrap();

        let versions = json["versions"].as_object().unwrap();
        for (ver, data) in versions {
            let tarball = data["dist"]["tarball"].as_str().unwrap();
            assert!(
                tarball.starts_with("http://nora:4000/npm/"),
                "version {} tarball not rewritten: {}",
                ver,
                tarball
            );
        }
    }

    #[test]
    fn test_regular_package_golden_preserves_integrity() {
        let fixture = load_fixture("package-metadata.json");
        let result =
            rewrite_tarball_urls(&fixture, "http://nora:4000", "https://registry.npmjs.org")
                .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&result).unwrap();

        // integrity and shasum must survive rewriting
        let dist = &json["versions"]["4.17.21"]["dist"];
        assert!(
            dist["shasum"].as_str().is_some(),
            "shasum must be preserved"
        );
        assert!(
            dist["integrity"].as_str().is_some(),
            "integrity must be preserved"
        );
    }

    #[test]
    fn test_regular_package_golden_snapshot() {
        let fixture = load_fixture("package-metadata.json");
        let result =
            rewrite_tarball_urls(&fixture, "http://nora:4000", "https://registry.npmjs.org")
                .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&result).unwrap();

        // Snapshot only tarball URLs (stable against other metadata changes)
        let tarball_urls: Vec<&str> = json["versions"]
            .as_object()
            .unwrap()
            .values()
            .filter_map(|v| v["dist"]["tarball"].as_str())
            .collect();
        insta::assert_json_snapshot!("npm_regular_tarball_urls", tarball_urls);
    }

    // ── Scoped package rewrite ──

    #[test]
    fn test_scoped_package_golden_no_upstream_leak() {
        let fixture = load_fixture("scoped-package-metadata.json");
        let result = rewrite_tarball_urls(
            &fixture,
            "https://registry.airgap.local",
            "https://registry.npmjs.org",
        )
        .unwrap();
        let body = String::from_utf8(result).unwrap();
        assert_no_upstream_urls(&body, "scoped package rewrite");
    }

    #[test]
    fn test_scoped_package_golden_all_tarballs_rewritten() {
        let fixture = load_fixture("scoped-package-metadata.json");
        let result =
            rewrite_tarball_urls(&fixture, "http://nora:4000", "https://registry.npmjs.org")
                .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&result).unwrap();

        let versions = json["versions"].as_object().unwrap();
        for (ver, data) in versions {
            let tarball = data["dist"]["tarball"].as_str().unwrap();
            assert!(
                tarball.starts_with("http://nora:4000/npm/"),
                "scoped version {} tarball not rewritten: {}",
                ver,
                tarball
            );
            // Scoped packages must preserve the @scope prefix in the path
            assert!(
                tarball.contains("@babel/core"),
                "scoped package path lost: {}",
                tarball
            );
        }
    }

    #[test]
    fn test_scoped_package_golden_snapshot() {
        let fixture = load_fixture("scoped-package-metadata.json");
        let result =
            rewrite_tarball_urls(&fixture, "http://nora:4000", "https://registry.npmjs.org")
                .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&result).unwrap();

        let tarball_urls: Vec<&str> = json["versions"]
            .as_object()
            .unwrap()
            .values()
            .filter_map(|v| v["dist"]["tarball"].as_str())
            .collect();
        insta::assert_json_snapshot!("npm_scoped_tarball_urls", tarball_urls);
    }

    // ── Content-Type assertions ──

    #[test]
    fn test_with_content_type_metadata_is_json() {
        let data = Bytes::from(b"{}".to_vec());
        let (status, headers, _body) = with_content_type(false, data);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[0].1, "application/json");
    }

    #[test]
    fn test_with_content_type_tarball_is_octet() {
        let data = Bytes::from(b"\x1f\x8b".to_vec());
        let (status, headers, _body) = with_content_type(true, data);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[0].1, "application/octet-stream");
    }

    // ── Edge cases for URL rewriting ──

    #[test]
    fn test_rewrite_custom_upstream_no_leak() {
        let metadata = serde_json::json!({
            "name": "pkg",
            "versions": {
                "1.0.0": {
                    "dist": {
                        "tarball": "https://private.npm.corp/pkg/-/pkg-1.0.0.tgz"
                    }
                }
            }
        });
        let data = serde_json::to_vec(&metadata).unwrap();
        let result =
            rewrite_tarball_urls(&data, "http://nora:4000", "https://private.npm.corp").unwrap();
        let body = String::from_utf8(result).unwrap();
        assert!(
            !body.contains("private.npm.corp"),
            "custom upstream domain leaked"
        );
    }

    #[test]
    fn test_rewrite_preserves_non_dist_urls() {
        let metadata = serde_json::json!({
            "name": "pkg",
            "repository": {"url": "https://github.com/test/pkg.git"},
            "homepage": "https://pkg.example.com",
            "versions": {
                "1.0.0": {
                    "dist": {
                        "tarball": "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"
                    },
                    "repository": {"url": "https://github.com/test/pkg.git"}
                }
            }
        });
        let data = serde_json::to_vec(&metadata).unwrap();
        let result =
            rewrite_tarball_urls(&data, "http://nora:4000", "https://registry.npmjs.org").unwrap();
        let json: serde_json::Value = serde_json::from_slice(&result).unwrap();

        // Non-dist URLs must be untouched
        assert_eq!(
            json["repository"]["url"].as_str().unwrap(),
            "https://github.com/test/pkg.git"
        );
        assert_eq!(
            json["homepage"].as_str().unwrap(),
            "https://pkg.example.com"
        );
    }

    /// #596 acceptance: with a cached metadata body + stored validators, a stale
    /// request revalidates with `If-None-Match`; on upstream 304 the cached body
    /// is served and NO 200-with-body is ever fetched. Drives the real handler.
    #[tokio::test]
    async fn test_npm_revalidation_304_serves_cache_no_body_download() {
        use crate::registry::{write_validators, Validators};
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::{header_exists, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        // Conditional request (has If-None-Match) → 304. A request WITHOUT it
        // would 404 here (no mount), so any full fetch would visibly fail —
        // proving the 304 path served from cache.
        Mock::given(method("GET"))
            .and(header_exists("if-none-match"))
            .respond_with(ResponseTemplate::new(304))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.npm.metadata_ttl = 0; // always stale → always revalidate
            cfg.npm.revalidate = true;
            cfg.npm.serve_stale = false;
        });

        // Pre-seed the cache body + validator sidecar (as a prior 200 would have).
        let key = "npm/testpkg/metadata.json";
        ctx.state
            .storage
            .put(key, b"CACHED-PACKUMENT")
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
            .with_label_values(&["npm"])
            .get();

        let resp = send(&ctx.app, Method::GET, "/npm/testpkg", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(&body[..], b"CACHED-PACKUMENT", "must serve the cached body");

        let after = crate::metrics::PROXY_UPSTREAM_304_TOTAL
            .with_label_values(&["npm"])
            .get();
        assert!(after > before, "a 304 revalidation must be recorded");
    }

    /// #595: a thundering herd of concurrent requests for the same expired
    /// metadata key must collapse to a SINGLE upstream fetch. M clients race
    /// `GET /npm/testpkg` while the key is stale; a counting mock upstream
    /// (delayed so followers pile up) must observe exactly one request, and
    /// every client must receive the leader's body.
    #[tokio::test]
    async fn test_npm_concurrent_metadata_miss_coalesces_to_one_upstream_fetch() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use std::sync::Arc;
        use std::time::Duration;
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        // Delay the response so all followers reach the single-flight election
        // while the leader is still fetching. Body is not valid JSON, so the
        // handler's byte-level URL rewrite passes it through unchanged.
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("FRESH-PACKUMENT")
                    .set_delay(Duration::from_millis(400)),
            )
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.npm.metadata_ttl = 0; // always stale → always refetch
            cfg.npm.revalidate = false; // plain 200, no conditional headers
            cfg.npm.serve_stale = false;
            // proxy_coalesce defaults to true.
        });

        // Pre-seed a stale cached body so the stale-metadata refetch path runs.
        let key = "npm/testpkg/metadata.json";
        ctx.state.storage.put(key, b"STALE").await.unwrap();

        let before = crate::metrics::PROXY_COALESCED_TOTAL
            .with_label_values(&["npm"])
            .get();

        const M: usize = 16;
        let app = Arc::new(ctx.app.clone());
        let mut handles = Vec::new();
        for _ in 0..M {
            let app = Arc::clone(&app);
            handles.push(tokio::spawn(async move {
                let resp = send(&app, Method::GET, "/npm/testpkg", "").await;
                let status = resp.status();
                let body = body_bytes(resp).await;
                (status, body)
            }));
        }

        for h in handles {
            let (status, body) = h.await.unwrap();
            assert_eq!(status, StatusCode::OK);
            assert_eq!(&body[..], b"FRESH-PACKUMENT", "every client gets the body");
        }

        let upstream_hits = upstream.received_requests().await.unwrap().len();
        assert_eq!(
            upstream_hits, 1,
            "M concurrent requests for one key must hit upstream exactly once"
        );

        let after = crate::metrics::PROXY_COALESCED_TOTAL
            .with_label_values(&["npm"])
            .get();
        assert_eq!(
            after - before,
            (M - 1) as u64,
            "M-1 followers must be served without their own upstream fetch"
        );
    }

    /// #595 kill-switch: with `server.proxy_coalesce = false`, the coalescer is
    /// bypassed and every concurrent request fetches independently — so the
    /// counting upstream observes one hit per client (proves the gate works).
    #[tokio::test]
    async fn test_npm_coalesce_disabled_lets_every_request_fetch() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use std::sync::Arc;
        use std::time::Duration;
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("FRESH-PACKUMENT")
                    .set_delay(Duration::from_millis(200)),
            )
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.npm.metadata_ttl = 0;
            cfg.npm.revalidate = false;
            cfg.npm.serve_stale = false;
            cfg.server.proxy_coalesce = false; // kill-switch off
        });

        let key = "npm/testpkg/metadata.json";
        ctx.state.storage.put(key, b"STALE").await.unwrap();

        const M: usize = 8;
        let app = Arc::new(ctx.app.clone());
        let mut handles = Vec::new();
        for _ in 0..M {
            let app = Arc::clone(&app);
            handles.push(tokio::spawn(async move {
                let resp = send(&app, Method::GET, "/npm/testpkg", "").await;
                let status = resp.status();
                let _ = body_bytes(resp).await;
                status
            }));
        }
        for h in handles {
            assert_eq!(h.await.unwrap(), StatusCode::OK);
        }

        let upstream_hits = upstream.received_requests().await.unwrap().len();
        assert_eq!(
            upstream_hits, M,
            "with coalescing disabled every request fetches independently"
        );
    }

    // ── npm audit proxy (#597) ──

    /// bulk audit is forwarded to upstream and returned verbatim; internal-namespace
    /// package names are stripped from the forwarded body (dependency-confusion).
    #[tokio::test]
    async fn test_npm_audit_bulk_forwards_and_strips_internal() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/-/npm/v1/security/advisories/bulk"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"lodash":[]}"#))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.internal_namespaces = vec!["@internal/*".to_string()];
        });

        let resp = send(
            &ctx.app,
            Method::POST,
            "/npm/-/npm/v1/security/advisories/bulk",
            r#"{"lodash":["4.17.0"],"@internal/secret":["1.0.0"]}"#,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(
            &body[..],
            br#"{"lodash":[]}"#,
            "upstream body returned verbatim"
        );

        // The forwarded request must NOT carry the internal package name.
        let reqs = upstream.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 1);
        let fwd = String::from_utf8_lossy(&reqs[0].body);
        assert!(fwd.contains("lodash"), "public pkg forwarded: {fwd}");
        assert!(
            !fwd.contains("@internal/secret"),
            "internal pkg name must be stripped before forwarding: {fwd}"
        );
    }

    /// Hosted-only repo (no upstream proxy) → npm-compatible empty result, not 405/500.
    #[tokio::test]
    async fn test_npm_audit_no_proxy_returns_empty() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = None;
        });
        let resp = send(
            &ctx.app,
            Method::POST,
            "/npm/-/npm/v1/security/advisories/bulk",
            r#"{"lodash":["4.17.0"]}"#,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], b"{}");
    }

    /// quick audit (gzipped lockfile — cannot per-name strip) is refused with an
    /// empty result when an internal-namespace filter is configured; upstream is
    /// never contacted (no internal-name leak).
    #[tokio::test]
    async fn test_npm_audit_quick_refused_under_filter() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_string("SHOULD-NOT-BE-CALLED"))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.internal_namespaces = vec!["@internal/*".to_string()];
        });
        let resp = send(
            &ctx.app,
            Method::POST,
            "/npm/-/npm/v1/security/audits/quick",
            "lockfile-payload",
        )
        .await;
        // Refused explicitly, not "0 vulnerabilities" (Pavel 10.10; client matrix:
        // every client exits 1 and prints the error text on a 4xx).
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(String::from_utf8_lossy(&body_bytes(resp).await).contains("\"error\""));
        assert_eq!(
            upstream.received_requests().await.unwrap().len(),
            0,
            "quick must not reach upstream under a namespace filter"
        );
    }

    /// POST on a non-audit npm path → 405 (POST is only valid on the audit endpoints).
    #[tokio::test]
    async fn test_npm_audit_non_audit_post_405() {
        use crate::test_helpers::{create_test_context, send};
        use axum::http::{Method, StatusCode};

        let ctx = create_test_context();
        let resp = send(&ctx.app, Method::POST, "/npm/lodash", "x").await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    /// An oversized audit body is rejected with 413 before any upstream forward.
    #[tokio::test]
    async fn test_npm_audit_body_too_large() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some("http://127.0.0.1:1".to_string());
        });
        let big = "x".repeat(NPM_AUDIT_BODY_CAP + 1);
        let resp = send(
            &ctx.app,
            Method::POST,
            "/npm/-/npm/v1/security/advisories/bulk",
            big,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// Review #1 regression: a Content-Encoded (e.g. gzipped) bulk body under an
    /// active namespace filter cannot be name-verified → must fail CLOSED (refuse,
    /// upstream never contacted), not forward internal names.
    #[tokio::test]
    async fn test_npm_audit_bulk_encoded_refused_under_filter() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send_with_headers};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_string("LEAKED"))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.internal_namespaces = vec!["@internal/*".to_string()];
        });
        // Claims gzip encoding → NORA cannot see the names → must refuse.
        let resp = send_with_headers(
            &ctx.app,
            Method::POST,
            "/npm/-/npm/v1/security/advisories/bulk",
            vec![("content-encoding", "gzip")],
            "gzipped-body-not-inspected-because-refused",
        )
        .await;
        // Refused explicitly, not "0 vulnerabilities" (Pavel 10.10; client matrix:
        // every client exits 1 and prints the error text on a 4xx).
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(String::from_utf8_lossy(&body_bytes(resp).await).contains("\"error\""));
        assert_eq!(
            upstream.received_requests().await.unwrap().len(),
            0,
            "encoded bulk under a filter must NOT be forwarded"
        );
    }

    /// Review #3 regression: upstream 5xx must surface as 502 (audit-endpoint error),
    /// NOT `200 {}` (which npm renders as a false "0 vulnerabilities").
    #[tokio::test]
    async fn test_npm_audit_upstream_5xx_returns_502() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(500))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
        });
        let resp = send(
            &ctx.app,
            Method::POST,
            "/npm/-/npm/v1/security/advisories/bulk",
            r#"{"lodash":["4.17.0"]}"#,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    /// Review #5: the client's Authorization (its NORA token) must never be
    /// forwarded upstream — only the allowlisted headers + configured proxy_auth.
    #[tokio::test]
    async fn test_npm_audit_client_authorization_not_forwarded() {
        use crate::test_helpers::{create_test_context_with_config, send_with_headers};
        use axum::http::{Method, StatusCode};
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
        });
        let resp = send_with_headers(
            &ctx.app,
            Method::POST,
            "/npm/-/npm/v1/security/advisories/bulk",
            vec![("authorization", "Bearer nora-client-token")],
            r#"{"lodash":["4.17.0"]}"#,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let reqs = upstream.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 1);
        assert!(
            reqs[0].headers.get("authorization").is_none(),
            "client Authorization must not be forwarded upstream"
        );
    }

    /// Under `anonymous_read`, an unauthenticated `npm audit` POST must pass the
    /// auth gate (audit is a read-semantics query) and reach the handler — hosted-
    /// only (no proxy) → 200 `{}`. A non-audit npm POST stays gated → 401.
    #[tokio::test]
    async fn test_npm_audit_anonymous_read_allows_post() {
        use crate::test_helpers::{create_test_context_with_config, send};
        use axum::http::{Method, StatusCode};

        let ctx = create_test_context_with_config(|cfg| {
            cfg.auth.enabled = true;
            cfg.auth.anonymous_read = true;
            cfg.npm.proxy = None; // hosted-only → handler returns 200 {}
        });
        let audit = send(
            &ctx.app,
            Method::POST,
            "/npm/-/npm/v1/security/advisories/bulk",
            r#"{"lodash":["4.17.0"]}"#,
        )
        .await;
        assert_eq!(
            audit.status(),
            StatusCode::OK,
            "anonymous npm audit must pass the auth gate under anonymous_read"
        );
        // A non-audit npm POST is not read-eligible → still requires auth.
        let other = send(&ctx.app, Method::POST, "/npm/somepkg", "x").await;
        assert_eq!(other.status(), StatusCode::UNAUTHORIZED);
    }

    /// #867: when a 304 revalidation finds the cached body missing (deleted by
    /// GC, retention, or corruption between the handler's `get_verified` and
    /// `refetch_metadata`'s second read), the stale `.meta` validator sidecar
    /// must be deleted so the next revalidation cycle does a full unconditional
    /// GET instead of looping on 304 forever.
    ///
    /// The handler's cache-hit gate (`get_verified`) requires the body to be
    /// present, so the GC race can't be reproduced through the HTTP layer.
    /// We call `refetch_metadata` directly with `.meta` seeded but body absent.
    #[tokio::test]
    async fn test_867_304_body_miss_clears_validators() {
        use crate::registry::{read_validators, write_validators, Validators};
        use crate::test_helpers::create_test_context_with_config;
        use wiremock::matchers::{header_exists, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        // Respond 304 to any conditional request (has If-None-Match).
        Mock::given(method("GET"))
            .and(header_exists("if-none-match"))
            .respond_with(ResponseTemplate::new(304))
            .mount(&upstream)
            .await;

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.npm.metadata_ttl = 0;
            cfg.npm.revalidate = true;
            cfg.npm.serve_stale = false;
        });

        let key = "npm/ghost-pkg/metadata.json";

        // Seed validator sidecar WITHOUT the body — simulates GC/retention
        // deleting the cached body while .meta survives.
        write_validators(
            &ctx.state.storage,
            key,
            &Validators {
                etag: Some("\"stale-etag\"".to_string()),
                last_modified: None,
            },
        )
        .await;

        // Preconditions: .meta exists, body does not.
        assert!(
            read_validators(&ctx.state.storage, key).await.is_some(),
            "precondition: .meta must exist"
        );
        assert!(
            ctx.state.storage.get(key).await.is_err(),
            "precondition: body must be absent"
        );

        // Call refetch_metadata directly — simulates the race where the handler
        // entered the cache-hit path (body was present at get_verified), TTL
        // expired, but GC deleted the body before refetch_metadata re-reads it.
        let result = refetch_metadata(&ctx.state, "ghost-pkg", key).await;
        assert!(
            result.is_none(),
            "must return None when body is missing on 304"
        );

        // The critical assertion: .meta must be gone after the 304 body-miss.
        // Before the fix, `.ok()?` silently returned None but left .meta intact,
        // causing an infinite 304 loop on every subsequent TTL expiry.
        assert!(
            read_validators(&ctx.state.storage, key).await.is_none(),
            "#867: validators must be cleared after 304 body-miss to break the infinite loop"
        );
    }
    /// #956: a hosted package whose derived packument is gone is still fully
    /// described by its per-version keys. Answering 404 loses data that is
    /// sitting in storage; the reassembly already exists and must be reached.
    #[tokio::test]
    async fn test_npm_packument_rebuilt_when_metadata_missing() {
        use crate::test_helpers::{body_bytes, create_test_context, send};
        use axum::http::{Method, StatusCode};

        let ctx = create_test_context();

        // Seed the immutable originals directly — what a direct-storage import
        // or a restore that skipped derived objects leaves behind.
        for ver in ["1.0.0", "2.0.0"] {
            let doc = serde_json::json!({ "name": "imported", "version": ver, "dist": {} });
            ctx.state
                .storage
                .put(
                    &format!("npm/imported/versions/{}.json", ver),
                    &serde_json::to_vec(&doc).unwrap(),
                )
                .await
                .unwrap();
        }
        ctx.state
            .storage
            .put(
                "npm/imported/pkg.json",
                &serde_json::to_vec(&serde_json::json!({ "description": "seeded" })).unwrap(),
            )
            .await
            .unwrap();
        assert!(
            ctx.state
                .storage
                .get("npm/imported/metadata.json")
                .await
                .is_err(),
            "precondition: the derived packument is absent"
        );

        let response = send(&ctx.app, Method::GET, "/npm/imported", "").await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "every version is in storage — a 404 here loses the package"
        );

        let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(json["name"], "imported");
        let versions = json["versions"].as_object().unwrap();
        assert!(versions.contains_key("1.0.0"), "1.0.0 missing from rebuild");
        assert!(versions.contains_key("2.0.0"), "2.0.0 missing from rebuild");
        assert_eq!(
            json["dist-tags"]["latest"], "2.0.0",
            "latest must be derived from the version keys"
        );
        assert_eq!(
            json["description"], "seeded",
            "package-level fields must survive the rebuild"
        );

        assert!(
            ctx.state
                .storage
                .get("npm/imported/metadata.json")
                .await
                .is_ok(),
            "the rebuild must persist, or every request pays for it again"
        );
    }

    /// The rebuild must not invent a package out of an empty prefix.
    #[tokio::test]
    async fn test_npm_packument_absent_package_still_404() {
        use crate::test_helpers::{create_test_context, send};
        use axum::http::{Method, StatusCode};

        let ctx = create_test_context();

        let response = send(&ctx.app, Method::GET, "/npm/never-published", "").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(
            ctx.state
                .storage
                .get("npm/never-published/metadata.json")
                .await
                .is_err(),
            "a 404 must not leave a derived object behind"
        );
    }

    /// Concurrent readers of a package with a missing packument must all get the
    /// same correct answer — the rebuild is serialized on the publish lock.
    #[tokio::test]
    async fn test_npm_packument_rebuild_is_serialized() {
        use crate::test_helpers::{body_bytes, create_test_context, send};
        use axum::http::{Method, StatusCode};

        let ctx = create_test_context();
        for ver in ["1.0.0", "1.1.0", "2.0.0"] {
            let doc = serde_json::json!({ "name": "stampede", "version": ver, "dist": {} });
            ctx.state
                .storage
                .put(
                    &format!("npm/stampede/versions/{}.json", ver),
                    &serde_json::to_vec(&doc).unwrap(),
                )
                .await
                .unwrap();
        }

        let mut handles = Vec::new();
        for _ in 0..8 {
            let app = ctx.app.clone();
            handles.push(tokio::spawn(async move {
                let response = send(&app, Method::GET, "/npm/stampede", "").await;
                let status = response.status();
                (status, body_bytes(response).await)
            }));
        }

        let mut bodies = Vec::new();
        for handle in handles {
            let (status, body) = handle.await.unwrap();
            assert_eq!(status, StatusCode::OK);
            bodies.push(body);
        }
        assert!(
            bodies.windows(2).all(|pair| pair[0] == pair[1]),
            "concurrent rebuilds of the same package must agree"
        );
    }
    /// #957: `npm install` asks for the abbreviated packument. Serving the full
    /// document instead is correct but wasteful — and the fields it carries are
    /// exactly the ones an installer never reads.
    #[tokio::test]
    async fn test_npm_packument_abbreviated_on_install_v1_accept() {
        use crate::test_helpers::{body_bytes, create_test_context, send_with_headers};
        use axum::http::{header, Method, StatusCode};

        let ctx = create_test_context();
        let full = serde_json::json!({
            "name": "corgi",
            "dist-tags": { "latest": "1.0.0" },
            "readme": "a very long readme that no installer reads",
            "maintainers": [{ "name": "someone" }],
            "versions": {
                "1.0.0": {
                    "name": "corgi",
                    "version": "1.0.0",
                    "dist": { "tarball": "http://example/corgi-1.0.0.tgz" },
                    "dependencies": { "left-pad": "^1.0.0" },
                    "engines": { "node": ">=18" },
                    "os": ["linux"],
                    "cpu": ["x64"],
                    "peerDependenciesMeta": { "react": { "optional": true } },
                    "deprecated": "use corgi2",
                    "description": "dropped",
                    "scripts": { "test": "dropped" },
                    "gitHead": "dropped"
                }
            }
        });
        ctx.state
            .storage
            .put(
                "npm/corgi/metadata.json",
                &serde_json::to_vec(&full).unwrap(),
            )
            .await
            .unwrap();

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/npm/corgi",
            vec![("accept", "application/vnd.npm.install-v1+json")],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/vnd.npm.install-v1+json")
        );
        assert_eq!(
            response
                .headers()
                .get(header::VARY)
                .and_then(|v| v.to_str().ok()),
            Some("Accept"),
            "the body varies by Accept and metadata is cacheable — a shared cache \
             must not serve the abbreviated document to a client that wanted the full one"
        );

        let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(json["name"], "corgi");
        assert_eq!(json["dist-tags"]["latest"], "1.0.0");
        assert!(json.get("readme").is_none(), "readme must be dropped");
        assert!(
            json.get("maintainers").is_none(),
            "maintainers must be dropped"
        );

        let manifest = &json["versions"]["1.0.0"];
        // Everything an installer consults survives — losing any of these
        // silently changes what gets resolved and installed.
        assert_eq!(manifest["version"], "1.0.0");
        assert_eq!(manifest["dependencies"]["left-pad"], "^1.0.0");
        assert_eq!(manifest["engines"]["node"], ">=18");
        assert_eq!(manifest["os"][0], "linux");
        assert_eq!(manifest["cpu"][0], "x64");
        assert_eq!(manifest["peerDependenciesMeta"]["react"]["optional"], true);
        assert_eq!(manifest["deprecated"], "use corgi2");
        assert!(manifest["dist"]["tarball"].is_string());
        // ...and what it never reads does not.
        assert!(manifest.get("description").is_none());
        assert!(manifest.get("scripts").is_none());
        assert!(manifest.get("gitHead").is_none());
    }

    /// Without the header the full document is served, unchanged.
    #[tokio::test]
    async fn test_npm_packument_full_without_install_v1_accept() {
        use crate::test_helpers::{body_bytes, create_test_context, send};
        use axum::http::{header, Method, StatusCode};

        let ctx = create_test_context();
        let full = serde_json::json!({
            "name": "corgi",
            "dist-tags": { "latest": "1.0.0" },
            "readme": "kept",
            "versions": {
                "1.0.0": { "name": "corgi", "version": "1.0.0", "description": "kept", "dist": {} }
            }
        });
        ctx.state
            .storage
            .put(
                "npm/corgi/metadata.json",
                &serde_json::to_vec(&full).unwrap(),
            )
            .await
            .unwrap();

        let response = send(&ctx.app, Method::GET, "/npm/corgi", "").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );

        let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(json["readme"], "kept", "the full document must be intact");
        assert_eq!(json["versions"]["1.0.0"]["description"], "kept");
    }

    /// A body that is not a packument is served unchanged rather than failing:
    /// the client asked for a projection of this document, not for an error.
    #[tokio::test]
    async fn test_npm_packument_unparsable_body_served_unchanged() {
        use crate::test_helpers::{body_bytes, create_test_context, send_with_headers};
        use axum::http::{Method, StatusCode};

        let ctx = create_test_context();
        ctx.state
            .storage
            .put("npm/broken/metadata.json", b"not json at all")
            .await
            .unwrap();

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/npm/broken",
            vec![("accept", "application/vnd.npm.install-v1+json")],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(&body_bytes(response).await[..], b"not json at all");
    }
    /// The degraded path is still a representation: when the packument is stale
    /// and upstream is gone, an install-v1 client must get the abbreviated body
    /// *and* the matching Content-Type. Serving the short body under
    /// `application/json` is the bug this guards.
    #[tokio::test]
    async fn test_npm_packument_stale_serve_honours_install_v1() {
        use crate::test_helpers::{body_bytes, create_test_context_with_config, send_with_headers};
        use axum::http::{header, Method, StatusCode};

        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = None; // no upstream to revalidate against
            cfg.npm.metadata_ttl = 0; // always stale
            cfg.npm.serve_stale = true;
        });

        let full = serde_json::json!({
            "name": "stale-corgi",
            "dist-tags": { "latest": "1.0.0" },
            "readme": "dropped in the abbreviated form",
            "versions": {
                "1.0.0": { "name": "stale-corgi", "version": "1.0.0", "dist": {}, "scripts": {} }
            }
        });
        ctx.state
            .storage
            .put(
                "npm/stale-corgi/metadata.json",
                &serde_json::to_vec(&full).unwrap(),
            )
            .await
            .unwrap();

        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/npm/stale-corgi",
            vec![("accept", "application/vnd.npm.install-v1+json")],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("x-nora-stale")
                .and_then(|v| v.to_str().ok()),
            Some("true"),
            "precondition: this test must exercise the stale path"
        );
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/vnd.npm.install-v1+json"),
            "the stale path abbreviated the body — the Content-Type must say so"
        );
        assert_eq!(
            response
                .headers()
                .get(header::VARY)
                .and_then(|v| v.to_str().ok()),
            Some("Accept")
        );

        let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert!(json.get("readme").is_none());
        assert!(json["versions"]["1.0.0"].get("scripts").is_none());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod index_cost_tests {
    //! Serving a stored packument must cost the same storage round-trips for 1 and 100 versions.
    use crate::test_helpers::{
        create_test_context_with_storage, op_counting_storage, send, send_with_headers,
    };
    use axum::http::{Method, StatusCode};

    async fn packument_ops(n: usize) -> (usize, String) {
        let (storage, ops) = op_counting_storage();
        let ctx = create_test_context_with_storage(storage);
        let mut versions = serde_json::Map::new();
        for i in 0..n {
            let version = format!("1.0.{i}");
            let tarball = format!("costpkg-{version}.tgz");
            let tarball_key = format!("npm/costpkg/tarballs/{tarball}");
            ctx.state.storage.put(&tarball_key, b"TGZ").await.unwrap();
            let doc = serde_json::json!({
                "name": "costpkg",
                "version": version,
                "dist": { "tarball": format!("http://localhost/npm/costpkg/-/{tarball}") }
            });
            let doc_key = format!("npm/costpkg/versions/{version}.json");
            let doc_bytes = serde_json::to_vec(&doc).unwrap();
            ctx.state.storage.put(&doc_key, &doc_bytes).await.unwrap();
            versions.insert(version, doc);
        }
        let packument = serde_json::json!({
            "name": "costpkg",
            "dist-tags": { "latest": format!("1.0.{}", n - 1) },
            "versions": versions
        });
        let packument_bytes = serde_json::to_vec(&packument).unwrap();
        ctx.state
            .storage
            .put("npm/costpkg/metadata.json", &packument_bytes)
            .await
            .unwrap();
        ops.reset();
        let resp = send(&ctx.app, Method::GET, "/npm/costpkg", "").await;
        assert_eq!(resp.status(), StatusCode::OK, "packument with {n} versions");
        (ops.total(), format!("{:?}", ops.snapshot()))
    }

    fn iso_ago(secs: i64) -> String {
        (chrono::Utc::now() - chrono::Duration::seconds(secs))
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string()
    }

    /// R2-11/R2-17/R2-40: with the Q04 filter on, a cold packument miss fetches the
    /// upstream document once and writes it once, before the response; a warm GET
    /// reads it once; a tarball download dates its version from the small
    /// `dates.json`, never from the packument.
    #[tokio::test]
    async fn npm_packument_and_tarball_fetch_and_read_once() {
        use crate::test_helpers::{body_bytes, create_test_context_with_storage_and_config};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let upstream = MockServer::start().await;
        let v = |n: &str| serde_json::json!({ "name": "pkg", "version": n, "dist": {} });
        Mock::given(method("GET"))
            .and(path("/pkg"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "pkg",
                "dist-tags": { "latest": "1.1.0" },
                "versions": { "1.0.0": v("1.0.0"), "1.1.0": v("1.1.0") },
                "time": { "1.0.0": iso_ago(30 * 86400), "1.1.0": iso_ago(3600) }
            })))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/pkg/-/pkg-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"tgz".to_vec()))
            .mount(&upstream)
            .await;
        let (storage, ops) = op_counting_storage();
        let ctx = create_test_context_with_storage_and_config(storage, |cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.min_release_age = Some("7d".to_string());
            cfg.server.trust_upstream_dates = true;
        });
        let packument_fetches = || async {
            upstream
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.url.path() == "/pkg")
                .count()
        };
        let meta = "npm/pkg/metadata.json";
        let corgi = vec![("accept", "application/vnd.npm.install-v1+json")];

        let resp = send_with_headers(&ctx.app, Method::GET, "/npm/pkg", corgi.clone(), "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let short: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        assert!(short["versions"].get("1.1.0").is_none(), "{short}");
        assert_eq!(short["dist-tags"]["latest"], "1.0.0");
        assert_eq!(packument_fetches().await, 1, "one upstream fetch");
        assert_eq!(ops.calls("put", meta), 1, "one write: {:?}", ops.snapshot());
        assert_eq!(ops.calls("put", "npm/pkg/dates.json"), 1);

        ops.reset();
        let resp = send_with_headers(&ctx.app, Method::GET, "/npm/pkg", corgi, "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(ops.calls("get", meta), 1, "one read: {:?}", ops.snapshot());

        ops.reset();
        let resp = send(&ctx.app, Method::GET, "/npm/pkg/-/pkg-1.0.0.tgz", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(packument_fetches().await, 1, "the tarball reuses the cache");
        assert_eq!(ops.calls("get", meta), 0, "{:?}", ops.snapshot());
        assert_eq!(ops.calls("get", "npm/pkg/dates.json"), 1);
    }

    /// R2-21: a publish that fails after its first write leaves nothing behind —
    /// version, publish time, tarball, moved dist-tag — so the retry succeeds.
    #[tokio::test]
    async fn failed_publish_is_rolled_back_and_retried() {
        use crate::test_helpers::{body_bytes, create_test_context_with_storage};
        use base64::Engine;
        let (storage, ops) = op_counting_storage();
        let ctx = create_test_context_with_storage(storage);
        let publish = |ver: &str| {
            let payload = serde_json::json!({
                "name": "atom",
                "dist-tags": { "latest": ver },
                "versions": { ver: { "name": "atom", "version": ver, "dist": {} } },
                "_attachments": { format!("atom-{ver}.tgz"): {
                    "data": base64::engine::general_purpose::STANDARD.encode(ver)
                } },
            });
            send(
                &ctx.app,
                Method::PUT,
                "/npm/atom",
                serde_json::to_vec(&payload).unwrap(),
            )
        };
        assert_eq!(publish("1.0.0").await.status(), StatusCode::CREATED);

        ops.fail_puts_ending(Some("metadata.json"));
        assert_eq!(
            publish("1.1.0").await.status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        ops.fail_puts_ending(None);
        for gone in [
            "npm/atom/versions/1.1.0.json",
            "npm/atom/time/1.1.0",
            "npm/atom/tarballs/atom-1.1.0.tgz",
        ] {
            assert!(
                ctx.state.storage.stat(gone).await.is_none(),
                "{gone} left behind"
            );
        }
        let latest = ctx.state.storage.get("npm/atom/dist-tags/latest").await;
        assert_eq!(&latest.unwrap()[..], b"1.0.0", "tag pointed back");

        assert_eq!(publish("1.1.0").await.status(), StatusCode::CREATED);
        let resp = send(&ctx.app, Method::GET, "/npm/atom", "").await;
        let doc: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        assert!(doc["versions"].get("1.1.0").is_some(), "{doc}");
        assert_eq!(doc["dist-tags"]["latest"], "1.1.0");

        // A failed first publish leaves no packument for a package with no version.
        ops.fail_puts_ending(Some("metadata.json"));
        let payload = serde_json::json!({
            "name": "first",
            "versions": { "1.0.0": { "name": "first", "version": "1.0.0", "dist": {} } },
            "_attachments": { "first-1.0.0.tgz": {
                "data": base64::engine::general_purpose::STANDARD.encode(b"tgz")
            } },
        });
        let resp = send(
            &ctx.app,
            Method::PUT,
            "/npm/first",
            serde_json::to_vec(&payload).unwrap(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        ops.fail_puts_ending(None);
        assert!(ctx
            .state
            .storage
            .list("npm/first/")
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn npm_packument_cost_is_independent_of_version_count() {
        let (small, small_ops) = packument_ops(1).await;
        let (large, large_ops) = packument_ops(100).await;
        assert_eq!(
            small, large,
            "a stored packument must cost the same storage round-trips for 1 and 100 versions: {small_ops} vs {large_ops}"
        );
    }
}

#[cfg(test)]
mod origin_layout_tests {
    use super::{origin_key, origin_primary};

    /// Sidecars live outside the npm key space: no client key maps onto one, the
    /// mapping is one-to-one even for package names that look like layout words, and
    /// `list()` (which every older release's retention and GC walk) never shows one.
    #[tokio::test]
    async fn provenance_is_outside_the_npm_key_space_and_round_trips() {
        let keys = [
            "npm/a/tarballs/a-1.0.0.tgz",
            "npm/@vendor/a/tarballs/a-1.0.0.tgz",
            "npm/@vendor/a/tarballs/@vendor/a-1.0.0.tgz",
            "npm/a/metadata.json",
            "npm/@vendor/a/metadata.json",
            // Package names equal to layout words must not alias anything.
            "npm/origins/metadata.json",
            "npm/origins/tarballs/origins-1.0.0.tgz",
            "npm/@x/origins/metadata.json",
            "npm/tarballs/tarballs/tarballs-1.0.0.tgz",
            "npm/x/tarballs/y/tarballs/z.tgz",
        ];
        let mut seen = std::collections::HashSet::new();
        for key in keys {
            let sidecar = origin_key(key);
            assert!(!sidecar.starts_with("npm/"), "{key} -> {sidecar}");
            assert!(sidecar.starts_with(".nora-"), "{key} -> {sidecar}");
            assert_eq!(origin_primary(&sidecar), Some(key), "{sidecar}");
            assert!(seen.insert(sidecar), "{key}: two keys share a sidecar");
            // A real npm key is never mistaken for a sidecar.
            assert_eq!(origin_primary(key), None, "{key}");
        }
        assert_eq!(origin_primary(".nora-origins/maven/x.jar"), None);

        let dir = tempfile::tempdir().unwrap();
        let storage = crate::Storage::new_local(dir.path().to_str().unwrap());
        storage.put(keys[0], b"tgz").await.unwrap();
        storage
            .put(&origin_key(keys[0]), b"npm:https://r.example")
            .await
            .unwrap();
        assert_eq!(storage.list("").await.unwrap(), vec![keys[0].to_string()]);
        // ...and the internal walk shows only internal keys.
        assert_eq!(
            storage.list_internal(".nora-").await.unwrap(),
            vec![origin_key(keys[0])]
        );
        assert!(storage.list_internal("npm/").await.unwrap().is_empty());
    }
}

/// npm multi-upstream with scope routing (#1055), on the real router: a private
/// upstream that only answers the exact Bearer token, and a public one that answers
/// anything — so a request that reached the wrong upstream would succeed and only
/// the request log on the public mock can catch it.
#[cfg(test)]
mod multi_upstream_tests {
    use crate::config::{NpmConfig, NpmProxyEntry};
    use crate::secrets::ProtectedString;
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{any, header, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    const TOKEN: &str = "vendor-tok";

    fn vendor_proxies(public: &str, private: &str) -> Vec<NpmProxyEntry> {
        let mut npm: NpmConfig = toml::from_str(&format!(
            r#"proxies = ["{public}", {{ url = "{private}", scopes = ["@vendor"], auth_bearer_env = "NORA_NPM_VENDOR_TOKEN" }}]"#
        ))
        .unwrap();
        if let NpmProxyEntry::Full(p) = &mut npm.proxies[1] {
            p.auth_bearer = Some(ProtectedString::from(TOKEN));
        }
        npm.proxies
    }

    /// Public upstream: 200 to anything, so only its request log tells.
    async fn public_upstream() -> MockServer {
        let public = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r#"{"name":"lodash","versions":{}}"#),
            )
            .mount(&public)
            .await;
        public
    }

    /// The public upstream must never see a private-scope name or the private token.
    fn assert_public_clean(reqs: &[Request]) {
        for r in reqs {
            let url = r.url.as_str();
            let body = String::from_utf8_lossy(&r.body);
            assert!(
                !url.contains("vendor"),
                "private scope reached public upstream: {url}"
            );
            assert!(
                !body.contains("@vendor"),
                "private scope in a body sent to public: {body}"
            );
            let auth = r
                .headers
                .get("authorization")
                .map(|v| v.to_str().unwrap_or("?").to_string());
            assert!(
                auth.is_none(),
                "public upstream got an Authorization header: {auth:?} on {url}"
            );
        }
    }

    #[tokio::test]
    async fn owned_scope_is_fetched_only_from_its_upstream_with_its_token() {
        let public = public_upstream().await;
        let private = MockServer::start().await;
        let packument = serde_json::json!({
            "name": "@vendor/a",
            "versions": { "1.0.0": { "dist": {
                "tarball": format!("{}/@vendor/a/-/a-1.0.0.tgz", private.uri())
            } } },
            "time": { "1.0.0": "2020-01-15T10:30:00.000Z" }
        });
        Mock::given(method("GET"))
            .and(path("/@vendor/a"))
            .and(header("authorization", "Bearer vendor-tok"))
            .respond_with(ResponseTemplate::new(200).set_body_string(packument.to_string()))
            .mount(&private)
            .await;
        Mock::given(method("GET"))
            .and(path("/@vendor/a/-/a-1.0.0.tgz"))
            .and(header("authorization", "Bearer vendor-tok"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"VENDOR-TGZ".to_vec()))
            .mount(&private)
            .await;

        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.npm.proxies = proxies;
            cfg.npm.metadata_ttl = 0; // always stale → the second pass must refetch
            cfg.npm.serve_stale = false; // …so a refetch that went elsewhere fails loudly
        });

        // Packument twice: the second pass goes through the stale-refetch path,
        // which must route the same way.
        for pass in 0..2 {
            let resp = send(&ctx.app, Method::GET, "/npm/@vendor%2fa", "").await;
            assert_eq!(resp.status(), StatusCode::OK, "packument pass {pass}");
            let body = String::from_utf8_lossy(&body_bytes(resp).await).to_string();
            assert!(
                !body.contains(&private.uri()),
                "private registry host leaked to the client: {body}"
            );
            // The cache write is a background task; wait for it so the next pass
            // deterministically takes the stale-refetch path, not a second cold fetch.
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
            // Settled = body AND provenance sidecar written (#1055: an owned scope's
            // copy is only served once its origin is recorded).
            while ctx
                .state
                .storage
                .get(&super::origin_key("npm/@vendor/a/metadata.json"))
                .await
                .is_err()
            {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "packument never cached"
                );
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
        let resp = send(&ctx.app, Method::GET, "/npm/@vendor/a/-/a-1.0.0.tgz", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], b"VENDOR-TGZ");

        // An unscoped package still goes to the public upstream, without a credential.
        let resp = send(&ctx.app, Method::GET, "/npm/lodash", "").await;
        assert_eq!(resp.status(), StatusCode::OK);

        let packument_fetches = private
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path() == "/@vendor/a")
            .count();
        assert_eq!(
            packument_fetches, 2,
            "first fetch and stale refetch both go to the owner"
        );

        let public_reqs = public.received_requests().await.unwrap();
        assert!(
            !public_reqs.is_empty(),
            "control: lodash must have reached public"
        );
        assert_public_clean(&public_reqs);
    }

    /// A locked install asks for the tarball first; the metadata self-prime that
    /// resolves the release date (#748) must ask the owning upstream too.
    #[tokio::test]
    async fn tarball_first_self_prime_asks_the_owner() {
        let public = public_upstream().await;
        let private = MockServer::start().await;
        let packument = serde_json::json!({
            "name": "@vendor/a",
            "versions": { "1.0.0": { "dist": {
                "tarball": format!("{}/@vendor/a/-/a-1.0.0.tgz", private.uri())
            } } },
            "time": { "1.0.0": "2020-01-15T10:30:00.000Z" }
        });
        Mock::given(method("GET"))
            .and(path("/@vendor/a"))
            .and(header("authorization", "Bearer vendor-tok"))
            .respond_with(ResponseTemplate::new(200).set_body_string(packument.to_string()))
            .mount(&private)
            .await;
        Mock::given(method("GET"))
            .and(path("/@vendor/a/-/a-1.0.0.tgz"))
            .and(header("authorization", "Bearer vendor-tok"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"VENDOR-TGZ".to_vec()))
            .mount(&private)
            .await;
        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.npm.proxies = proxies;
            cfg.server.trust_upstream_dates = true;
        });

        let resp = send(&ctx.app, Method::GET, "/npm/@vendor/a/-/a-1.0.0.tgz", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            ctx.state
                .storage
                .get("npm/@vendor/a/metadata.json")
                .await
                .is_ok(),
            "the self-prime must have cached the owner's packument"
        );
        assert!(public.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_failing_private_upstream_never_falls_back_to_public() {
        let public = public_upstream().await;
        let private = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/@vendor/missing"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&private)
            .await;
        Mock::given(method("GET"))
            .and(path("/@vendor/broken"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&private)
            .await;

        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxies = proxies);

        for uri in [
            "/npm/@vendor%2fmissing",
            "/npm/@vendor%2fbroken",
            "/npm/@vendor/missing/-/missing-1.0.0.tgz",
        ] {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_ne!(
                resp.status(),
                StatusCode::OK,
                "{uri} must not be served from public"
            );
        }
        assert!(
            public.received_requests().await.unwrap().is_empty(),
            "no fallback to the public upstream for an owned scope"
        );
    }

    /// A dead private registry opens its own breaker only: public packages keep
    /// being served (decision Б.3 of #1055 — breaker per upstream).
    #[tokio::test]
    async fn a_dead_private_upstream_does_not_open_the_public_breaker() {
        let public = public_upstream().await;
        let private = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(503))
            .mount(&private)
            .await;
        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.npm.proxies = proxies;
            cfg.circuit_breaker.enabled = true;
            cfg.circuit_breaker.failure_threshold = 1;
            cfg.circuit_breaker.reset_timeout = 300;
        });

        for _ in 0..2 {
            let resp = send(&ctx.app, Method::GET, "/npm/@vendor%2fdown", "").await;
            assert_ne!(resp.status(), StatusCode::OK);
        }
        let resp = send(&ctx.app, Method::GET, "/npm/lodash", "").await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the public upstream must keep serving while the private one is down"
        );
        assert_public_clean(&public.received_requests().await.unwrap());
    }

    /// The second entry points — stale refetch and the tarball-first metadata
    /// self-prime — report to the per-upstream breaker too: after the private
    /// registry dies on both paths, the public one still refetches and self-primes.
    #[tokio::test]
    async fn refetch_and_self_prime_use_the_per_upstream_breaker() {
        let public = public_upstream().await;
        let private = MockServer::start().await;
        let packument = serde_json::json!({
            "name": "@vendor/a",
            "versions": { "1.0.0": { "dist": {
                "tarball": format!("{}/@vendor/a/-/a-1.0.0.tgz", private.uri())
            } } }
        });
        Mock::given(method("GET"))
            .and(path("/@vendor/a"))
            .respond_with(ResponseTemplate::new(200).set_body_string(packument.to_string()))
            .mount(&private)
            .await;
        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.npm.proxies = proxies;
            cfg.npm.metadata_ttl = 0;
            cfg.npm.serve_stale = false;
            cfg.server.trust_upstream_dates = true;
            cfg.circuit_breaker.enabled = true;
            cfg.circuit_breaker.failure_threshold = 1;
            cfg.circuit_breaker.reset_timeout = 300;
        });
        let cached = |key: &str| {
            let storage = ctx.state.storage.clone();
            let key = key.to_string();
            async move {
                let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
                while storage.get(&key).await.is_err() {
                    if tokio::time::Instant::now() >= deadline {
                        return false;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                true
            }
        };

        // Both packuments cached while everything is up.
        for uri in ["/npm/lodash", "/npm/@vendor%2fa"] {
            assert_eq!(
                send(&ctx.app, Method::GET, uri, "").await.status(),
                StatusCode::OK
            );
        }
        assert!(cached("npm/lodash/metadata.json").await);
        let packument_origin = super::origin_key("npm/@vendor/a/metadata.json");
        assert!(cached(&packument_origin).await);

        // The private registry dies; fail it on the refetch and the self-prime paths.
        private.reset().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(503))
            .mount(&private)
            .await;
        let r = send(&ctx.app, Method::GET, "/npm/@vendor%2fa", "").await;
        assert_ne!(r.status(), StatusCode::OK, "stale private refetch fails");
        let r = send(&ctx.app, Method::GET, "/npm/@vendor/b/-/b-1.0.0.tgz", "").await;
        assert_ne!(
            r.status(),
            StatusCode::OK,
            "private self-prime + fetch fail"
        );

        // Public: stale refetch and tarball-first self-prime still work.
        let r = send(&ctx.app, Method::GET, "/npm/lodash", "").await;
        assert_eq!(
            r.status(),
            StatusCode::OK,
            "public refetch after private died"
        );
        let _ = send(
            &ctx.app,
            Method::GET,
            "/npm/lodash2/-/lodash2-1.0.0.tgz",
            "",
        )
        .await;
        assert!(
            cached("npm/lodash2/metadata.json").await,
            "public self-prime after private died"
        );
        assert_public_clean(&public.received_requests().await.unwrap());
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    /// npm 7+ always gzips the bulk audit body (measured, kit npm-client-matrix).
    /// Refusing every encoded body made `npm audit` report "0 vulnerabilities" as
    /// soon as a private scope was configured; it must be decoded, stripped and
    /// forwarded, and the upstream's answer returned.
    #[tokio::test]
    async fn a_gzipped_bulk_audit_is_decoded_stripped_and_forwarded() {
        use crate::test_helpers::send_with_headers;
        let public = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/-/npm/v1/security/advisories/bulk"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"lodash":[{"id":1}]}"#))
            .mount(&public)
            .await;
        let private = MockServer::start().await;
        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxies = proxies);

        let resp = send_with_headers(
            &ctx.app,
            Method::POST,
            "/npm/-/npm/v1/security/advisories/bulk",
            vec![
                ("content-encoding", "gzip"),
                ("content-type", "application/json"),
            ],
            gzip(br#"{"lodash":["4.17.0"],"@vendor/a":["1.0.0"]}"#),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], br#"{"lodash":[{"id":1}]}"#);

        let reqs = public.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 1);
        assert!(
            reqs[0].headers.get("content-encoding").is_none(),
            "the stripped body goes out uncompressed"
        );
        assert!(String::from_utf8_lossy(&reqs[0].body).contains("lodash"));
        assert_public_clean(&reqs);
    }

    /// pnpm posts an npm6 dependency tree to `-/npm/v1/security/audits` (measured,
    /// kit npm-audit-matrix). Without a filter it is forwarded like bulk; with a
    /// private scope configured the tree cannot be stripped reliably, so it is
    /// refused with an error pnpm prints — never a 405 with an empty body.
    #[tokio::test]
    async fn pnpm_full_audit_is_forwarded_or_refused_explicitly() {
        let body = r#"{"dependencies":{".":{"dependencies":{"fixture-pub":{"version":"1.0.0"}}}},"requires":{".":"0.0.0"}}"#;

        // No filter: forwarded verbatim, the upstream's answer returned.
        let public = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/-/npm/v1/security/audits"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"advisories":{},"metadata":{"vulnerabilities":{}}}"#),
            )
            .mount(&public)
            .await;
        let url = public.uri();
        let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxy = Some(url));
        let resp = send(
            &ctx.app,
            Method::POST,
            "/npm/-/npm/v1/security/audits",
            body,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(String::from_utf8_lossy(&body_bytes(resp).await).contains("vulnerabilities"));
        assert_eq!(public.received_requests().await.unwrap().len(), 1);

        // Private scope configured: refused, nothing sent.
        let public = public_upstream().await;
        let private = MockServer::start().await;
        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxies = proxies);
        let resp = send(
            &ctx.app,
            Method::POST,
            "/npm/-/npm/v1/security/audits",
            body,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(String::from_utf8_lossy(&body_bytes(resp).await).contains("\"error\""));
        assert!(public.received_requests().await.unwrap().is_empty());
    }

    /// An encoding NORA does not decode is a 415, a corrupt gzip a 422 — both with
    /// a JSON error the clients print.
    #[tokio::test]
    async fn unverifiable_audit_bodies_get_explicit_errors() {
        use crate::test_helpers::send_with_headers;
        let public = public_upstream().await;
        let private = MockServer::start().await;
        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxies = proxies);
        let bulk = "/npm/-/npm/v1/security/advisories/bulk";

        let resp = send_with_headers(
            &ctx.app,
            Method::POST,
            bulk,
            vec![("content-encoding", "br")],
            "x",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let resp = send_with_headers(
            &ctx.app,
            Method::POST,
            bulk,
            vec![("content-encoding", "gzip")],
            "not-gzip",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let resp = send(&ctx.app, Method::POST, bulk, "[1,2,3]").await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(String::from_utf8_lossy(&body_bytes(resp).await).contains("\"error\""));
        assert!(public.received_requests().await.unwrap().is_empty());
    }

    /// A small gzip that expands past the audit cap is refused, not inflated.
    #[tokio::test]
    async fn a_gzip_bomb_audit_is_refused() {
        use crate::test_helpers::send_with_headers;
        let public = public_upstream().await;
        let private = MockServer::start().await;
        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxies = proxies);

        let mut big = b"{\"lodash\":[\"".to_vec();
        big.extend(std::iter::repeat_n(b'1', super::NPM_AUDIT_BODY_CAP + 1));
        big.extend(b"\"]}");
        let bomb = gzip(&big);
        assert!(
            bomb.len() < 64 * 1024,
            "control: the bomb is small on the wire"
        );

        let resp = send_with_headers(
            &ctx.app,
            Method::POST,
            "/npm/-/npm/v1/security/advisories/bulk",
            vec![("content-encoding", "gzip")],
            bomb,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(String::from_utf8_lossy(&body_bytes(resp).await).contains("\"error\""));
        assert!(public.received_requests().await.unwrap().is_empty());
    }

    /// GitHub Packages puts scoped tarballs under `/download/@scope/name/…`: the
    /// scope is not the first segment, and such a path must still go to the owner,
    /// never to the default upstream (measured leak on the B arm, kit matrix 10.10).
    #[tokio::test]
    async fn a_ghp_form_download_path_goes_to_the_owner() {
        let public = public_upstream().await;
        let private = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/download/@vendor/a/1.0.0/d113f588ab0b17ddabe8d0db55fa83a741df6871",
            ))
            .and(header("authorization", "Bearer vendor-tok"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"VENDOR-TGZ".to_vec()))
            .mount(&private)
            .await;
        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxies = proxies);

        let _ = send(
            &ctx.app,
            Method::GET,
            "/npm/download/@vendor/a/1.0.0/d113f588ab0b17ddabe8d0db55fa83a741df6871",
            "",
        )
        .await;
        // The tarball goes to the owner once; as for any tarball, so does the
        // packument read for the release date.
        let to_owner: Vec<String> = private
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect();
        let tarball = "/download/@vendor/a/1.0.0/d113f588ab0b17ddabe8d0db55fa83a741df6871";
        assert_eq!(
            to_owner.iter().filter(|p| *p == tarball).count(),
            1,
            "{to_owner:?}"
        );
        assert!(
            to_owner.iter().all(|p| p == tarball || p == "/@vendor/a"),
            "{to_owner:?}"
        );
        assert_public_clean(&public.received_requests().await.unwrap());
    }

    /// Seed what a public-registry squatter left in the cache before `@vendor` got
    /// an owner: a packument advertising 1.99.0 and its tarball. `origin` = the
    /// upstream its provenance record names (None = a cache from before #1055);
    /// `recorded_for` = the bytes that record was written for (None = these).
    async fn seed_squatter(
        ctx: &crate::test_helpers::TestContext,
        origin: Option<String>,
        recorded_for: Option<&[u8]>,
    ) {
        let packument = serde_json::json!({
            "name": "@vendor/a",
            "versions": { "1.99.0": { "dist": { "tarball": "http://127.0.0.1/npm/@vendor/a/-/a-1.99.0.tgz" } } },
            "dist-tags": { "latest": "1.99.0" }
        });
        let meta = "npm/@vendor/a/metadata.json";
        let tgz = "npm/@vendor/a/tarballs/a-1.99.0.tgz";
        let packument = packument.to_string();
        let objects: [(&str, &[u8]); 2] = [(meta, packument.as_bytes()), (tgz, b"SQUATTER")];
        for (key, bytes) in objects {
            ctx.state.storage.put(key, bytes).await.unwrap();
            if let Some(origin) = &origin {
                let record = super::provenance_record(origin, recorded_for.unwrap_or(bytes));
                ctx.state
                    .storage
                    .put(&super::origin_key(key), record.as_bytes())
                    .await
                    .unwrap();
            }
        }
    }

    /// Once a scope has an owner, a copy cached from anywhere else — a squatter on
    /// the public registry, a cache from before the scope was owned, or bytes that
    /// replaced the owner's copy under its record (an older release after a
    /// rollback, polygon U9) — is never served: not as a cache hit, not via Range,
    /// not as a stale fallback. The owner's copy replaces it.
    #[tokio::test]
    async fn a_foreign_cached_copy_of_an_owned_scope_is_never_served() {
        use crate::test_helpers::send_with_headers;
        for foreign_origin in [None, Some("PUBLIC"), Some("OWNER, OTHER BYTES")] {
            let public = public_upstream().await;
            let private = MockServer::start().await;
            let owner_packument = serde_json::json!({
                "name": "@vendor/a",
                "versions": { "1.0.0": { "dist": {
                    "tarball": format!("{}/@vendor/a/-/a-1.0.0.tgz", private.uri())
                } } },
                "dist-tags": { "latest": "1.0.0" }
            });
            Mock::given(method("GET"))
                .and(path("/@vendor/a"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_string(owner_packument.to_string()),
                )
                .mount(&private)
                .await;
            Mock::given(method("GET"))
                .and(path("/@vendor/a/-/a-1.99.0.tgz"))
                .respond_with(ResponseTemplate::new(404))
                .mount(&private)
                .await;
            let public_identity = crate::circuit_breaker::upstream_key("npm", &public.uri());
            let owner_identity = crate::circuit_breaker::upstream_key("npm", &private.uri());
            let proxies = vendor_proxies(&public.uri(), &private.uri());
            let ctx = create_test_context_with_config(move |cfg| {
                cfg.npm.proxies = proxies;
                cfg.npm.metadata_ttl = 3600; // fresh: a plain TTL check would serve the squatter
            });
            match foreign_origin {
                None => seed_squatter(&ctx, None, None).await,
                Some("PUBLIC") => seed_squatter(&ctx, Some(public_identity.clone()), None).await,
                // The owner's record, left behind when other bytes replaced its copy.
                Some(_) => {
                    seed_squatter(&ctx, Some(owner_identity.clone()), Some(b"owner bytes")).await
                }
            }

            let resp = send(&ctx.app, Method::GET, "/npm/@vendor%2fa", "").await;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = String::from_utf8_lossy(&body_bytes(resp).await).to_string();
            assert!(
                body.contains("1.0.0") && !body.contains("1.99.0"),
                "owner's packument, not the squatter's: {body}"
            );

            let resp = send(&ctx.app, Method::GET, "/npm/@vendor/a/-/a-1.99.0.tgz", "").await;
            assert_ne!(
                &body_bytes(resp).await[..],
                b"SQUATTER",
                "{foreign_origin:?}"
            );
            let resp = send_with_headers(
                &ctx.app,
                Method::GET,
                "/npm/@vendor/a/-/a-1.99.0.tgz",
                vec![("range", "bytes=0-3")],
                "",
            )
            .await;
            assert_ne!(
                &body_bytes(resp).await[..],
                b"SQUA",
                "range must not serve it either"
            );
            assert_public_clean(&public.received_requests().await.unwrap());
        }
    }

    /// A dead owner is a gateway failure, not a missing package: 5xx or an
    /// unreachable upstream → 502 (npm retries and reports E502), a real upstream
    /// 404 → 404 (npm reports E404). Before, every cold-miss failure was a 404.
    #[tokio::test]
    async fn a_dead_upstream_is_502_and_a_missing_package_is_404() {
        let public = public_upstream().await;
        let private = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/@vendor/missing"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&private)
            .await;
        Mock::given(method("GET"))
            .and(path("/@vendor/throttled"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "7"))
            .mount(&private)
            .await;
        Mock::given(method("GET"))
            .and(path("/@vendor/denied"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&private)
            .await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(503))
            .mount(&private)
            .await;
        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxies = proxies);

        for (uri, want) in [
            ("/npm/@vendor%2fmissing", StatusCode::NOT_FOUND),
            ("/npm/@vendor%2fdown", StatusCode::BAD_GATEWAY),
            // Throttling and auth refusals are not "no such package" either.
            ("/npm/@vendor%2fthrottled", StatusCode::SERVICE_UNAVAILABLE),
            ("/npm/@vendor%2fdenied", StatusCode::BAD_GATEWAY),
            (
                "/npm/@vendor/down/-/down-1.0.0.tgz",
                StatusCode::BAD_GATEWAY,
            ),
        ] {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), want, "{uri}");
        }

        // Unreachable (connection refused) is a gateway failure too.
        let unreachable = vendor_proxies(&public.uri(), "http://127.0.0.1:1");
        let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxies = unreachable);
        let resp = send(&ctx.app, Method::GET, "/npm/@vendor%2fdown", "").await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    /// With the owner down, the foreign copy is still not served (no stale fallback).
    #[tokio::test]
    async fn a_dead_owner_does_not_resurrect_a_foreign_copy() {
        let public = public_upstream().await;
        let private = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(503))
            .mount(&private)
            .await;
        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.npm.proxies = proxies;
            cfg.npm.metadata_ttl = 0;
            cfg.npm.serve_stale = true;
        });
        seed_squatter(&ctx, None, None).await;
        for uri in ["/npm/@vendor%2fa", "/npm/@vendor/a/-/a-1.99.0.tgz"] {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_ne!(resp.status(), StatusCode::OK, "{uri}");
        }
    }

    /// The release date used by min-release-age comes from the owner's packument,
    /// not from a foreign copy left in the cache: a squatter that advertises an old
    /// publish time must not let a brand-new owner release past the age gate.
    #[tokio::test]
    async fn release_age_reads_the_owners_date_not_a_foreign_copy() {
        let public = public_upstream().await;
        let private = MockServer::start().await;
        let now = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S.000Z")
            .to_string();
        let owner_packument = serde_json::json!({
            "name": "@vendor/a",
            "versions": { "1.0.0": { "dist": {
                "tarball": format!("{}/@vendor/a/-/a-1.0.0.tgz", private.uri())
            } } },
            "time": { "1.0.0": now }
        });
        Mock::given(method("GET"))
            .and(path("/@vendor/a"))
            .respond_with(ResponseTemplate::new(200).set_body_string(owner_packument.to_string()))
            .mount(&private)
            .await;
        Mock::given(method("GET"))
            .and(path("/@vendor/a/-/a-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"NEW-TGZ".to_vec()))
            .mount(&private)
            .await;
        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.npm.proxies = proxies;
            cfg.server.trust_upstream_dates = true;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.min_release_age = Some("7d".to_string());
        });
        // A foreign packument claiming 1.0.0 is six years old, no provenance.
        let foreign = serde_json::json!({
            "name": "@vendor/a",
            "versions": { "1.0.0": { "dist": {} } },
            "time": { "1.0.0": "2020-01-01T00:00:00.000Z" }
        });
        ctx.state
            .storage
            .put(
                "npm/@vendor/a/metadata.json",
                foreign.to_string().as_bytes(),
            )
            .await
            .unwrap();

        let resp = send(&ctx.app, Method::GET, "/npm/@vendor/a/-/a-1.0.0.tgz", "").await;
        assert_ne!(
            resp.status(),
            StatusCode::OK,
            "a release the owner dates to today must be held by a 7d age gate"
        );
        assert_public_clean(&public.received_requests().await.unwrap());
    }

    /// What the owner delivered is cached and served without asking again; what was
    /// published here is served even with the owner down.
    #[tokio::test]
    async fn owner_copies_and_local_publishes_are_served_from_cache() {
        use axum::body::Body;
        use base64::Engine as _;
        let public = public_upstream().await;
        let private = MockServer::start().await;
        let packument = serde_json::json!({
            "name": "@vendor/a",
            "versions": { "1.0.0": { "dist": {
                "tarball": format!("{}/@vendor/a/-/a-1.0.0.tgz", private.uri())
            } } }
        });
        Mock::given(method("GET"))
            .and(path("/@vendor/a"))
            .respond_with(ResponseTemplate::new(200).set_body_string(packument.to_string()))
            .mount(&private)
            .await;
        Mock::given(method("GET"))
            .and(path("/@vendor/a/-/a-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"OWNER-TGZ".to_vec()))
            .mount(&private)
            .await;
        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxies = proxies);

        let resp = send(&ctx.app, Method::GET, "/npm/@vendor/a/-/a-1.0.0.tgz", "").await;
        assert_eq!(&body_bytes(resp).await[..], b"OWNER-TGZ");
        let origin_key = super::origin_key("npm/@vendor/a/tarballs/a-1.0.0.tgz");
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while ctx.state.storage.get(&origin_key).await.is_err() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "origin never recorded"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // Owner goes down: its own copy is still served from cache.
        private.reset().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(503))
            .mount(&private)
            .await;
        let resp = send(&ctx.app, Method::GET, "/npm/@vendor/a/-/a-1.0.0.tgz", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], b"OWNER-TGZ");

        // A package published here under the owned scope is ours: served.
        let payload = serde_json::json!({
            "name": "@vendor/local",
            "versions": { "1.0.0": { "dist": {} } },
            "_attachments": { "local-1.0.0.tgz": {
                "data": base64::engine::general_purpose::STANDARD.encode(b"LOCAL-TGZ")
            } },
            "dist-tags": { "latest": "1.0.0" }
        });
        let resp = send(
            &ctx.app,
            Method::PUT,
            "/npm/@vendor%2flocal",
            Body::from(serde_json::to_vec(&payload).unwrap()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/@vendor/local/-/local-1.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], b"LOCAL-TGZ");
        let resp = send(&ctx.app, Method::GET, "/npm/@vendor%2flocal", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_public_clean(&public.received_requests().await.unwrap());
    }

    #[tokio::test]
    async fn audit_to_the_default_upstream_never_carries_private_names() {
        let public = public_upstream().await;
        let private = MockServer::start().await;
        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxies = proxies);

        let resp = send(
            &ctx.app,
            Method::POST,
            "/npm/-/npm/v1/security/advisories/bulk",
            r#"{"lodash":["4.17.0"],"@vendor/a":["1.0.0"]}"#,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // npm6 quick audit is a gzipped lockfile — names cannot be stripped, so it is
        // refused outright while any private scope is configured.
        let resp = send(
            &ctx.app,
            Method::POST,
            "/npm/-/npm/v1/security/audits/quick",
            r#"{"dependencies":{"@vendor/a":{"version":"1.0.0"}}}"#,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let reqs = public.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 1, "only the stripped bulk audit is forwarded");
        assert!(String::from_utf8_lossy(&reqs[0].body).contains("lodash"));
        assert_public_clean(&reqs);
        assert!(private.received_requests().await.unwrap().is_empty());
    }

    // ── A name with an empty segment never names another key's file ─────────

    /// `/npm/evil-pkg//-/evil-pkg-1.0.0.tgz` and `/npm//evil-pkg/-/...` name the canonical
    /// tarball under the package names `evil-pkg/` and `/evil-pkg`, which the rule `evil-pkg`
    /// does not match — refused before curation and storage.
    #[tokio::test]
    async fn a_tarball_path_with_an_empty_segment_is_refused_before_curation() {
        let dir = tempfile::tempdir().unwrap();
        let blocklist = dir.path().join("blocklist.json");
        std::fs::write(
            &blocklist,
            r#"{"version": 1, "rules": [{"registry": "npm", "name": "evil-pkg", "version": "*", "reason": "malware"}]}"#,
        )
        .unwrap();
        let ctx = create_test_context_with_config(|cfg| {
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist.to_string_lossy().into_owned());
        });
        // A tarball cached (or published) before the version was blocklisted.
        ctx.state
            .storage
            .put("npm/evil-pkg/tarballs/evil-pkg-1.0.0.tgz", b"MALWARE")
            .await
            .unwrap();
        let canonical = send(
            &ctx.app,
            Method::GET,
            "/npm/evil-pkg/-/evil-pkg-1.0.0.tgz",
            "",
        )
        .await;
        assert_eq!(canonical.status(), StatusCode::FORBIDDEN, "control");

        let mut served = Vec::new();
        for alias in [
            "/npm/evil-pkg//-/evil-pkg-1.0.0.tgz",
            "/npm//evil-pkg/-/evil-pkg-1.0.0.tgz",
        ] {
            let resp = send(&ctx.app, Method::GET, alias, "").await;
            if resp.status() == StatusCode::OK {
                served.push(format!("{alias} -> {:?}", body_bytes(resp).await));
            }
        }
        assert!(served.is_empty(), "blocklisted tarball served: {served:?}");
    }

    /// `/npm//internalpkg` names `/internalpkg`, which the isolation pattern `internal*` does
    /// not match: it is refused, and the packument of an internal package is never requested
    /// from the public upstream or cached over its own file.
    #[tokio::test]
    async fn a_leading_slash_name_never_takes_an_internal_package_upstream() {
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "internalpkg",
                "versions": {"9.9.9": {"name": "internalpkg", "version": "9.9.9"}}
            })))
            .mount(&upstream)
            .await;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.curation.internal_namespaces = vec!["internal*".to_string()];
        });
        let leaked = || async {
            upstream
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.url.path().contains("internalpkg"))
                .count()
        };

        let resp = send(&ctx.app, Method::GET, "/npm/internalpkg", "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "control");
        assert_eq!(leaked().await, 0, "control: canonical name is not proxied");

        let resp = send(&ctx.app, Method::GET, "/npm//internalpkg", "").await;
        assert_eq!(
            leaked().await,
            0,
            "internal package name sent to the public upstream (alias answered {})",
            resp.status()
        );
    }

    /// Every tarball path form with an empty segment is refused with 400 before curation,
    /// storage or the upstream sees it.
    #[tokio::test]
    async fn every_tarball_path_with_an_empty_segment_never_reaches_upstream() {
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"TARBALL".to_vec()))
            .mount(&upstream)
            .await;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.curation.internal_namespaces = vec!["internal*".to_string()];
        });
        for alias in [
            "/npm//internalpkg/-/internalpkg-1.0.0.tgz",
            "/npm/internalpkg//-/internalpkg-1.0.0.tgz",
            "/npm/lodash/-/lodash-4.17.21.tgz/",
            "/npm/lodash/-/",
        ] {
            let resp = send(&ctx.app, Method::GET, alias, "").await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{alias}");
        }
        let reqs: Vec<String> = upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect();
        assert!(reqs.is_empty(), "sent upstream: {reqs:?}");
        // Legit tarball path still proxies.
        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/lodash/-/lodash-4.17.21.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "control");
    }
}

/// An npm version is the version npm publishes it as: `semver.clean` drops white space, leading
/// `=` and `v`, and build metadata, so a rule or an allowlist entry holds however it spells its
/// version — `v1.3.0`, `=1.3.0` and `1.3.0+build` are `1.3.0`.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod npm_version_curation {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn upstream() -> MockServer {
        let upstream = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"TGZ".to_vec()))
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
                {"registry": "npm", "name": "left-pad", "version": "v1.3.0", "reason": "r"},
                {"registry": "npm", "name": "left-pad", "version": "=1.4.0", "reason": "r"},
                {"registry": "npm", "name": "left-pad", "version": "1.5.0+build.1", "reason": "r"}
            ]}"#,
        );
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.npm.proxy = Some(uri);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(blocklist);
        });
        for version in ["1.3.0", "1.4.0", "1.5.0"] {
            let path = format!("/npm/left-pad/-/left-pad-{version}.tgz");
            let resp = send(&ctx.app, Method::GET, &path, "").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{version}");
        }
        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/left-pad/-/left-pad-1.3.1.tgz",
            "",
        )
        .await;
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn an_allowlist_entry_admits_its_version_however_spelled() {
        let upstream = upstream().await;
        let dir = tempfile::tempdir().unwrap();
        let allowlist = write(
            &dir,
            "allowlist.json",
            r#"{"version": 1, "entries": [{"registry": "npm", "name": "left-pad", "version": "v1.3.0"}]}"#,
        );
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.npm.proxy = Some(uri);
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.allowlist_path = Some(allowlist);
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/left-pad/-/left-pad-1.3.0.tgz",
            "",
        )
        .await;
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
        let resp = send(
            &ctx.app,
            Method::GET,
            "/npm/left-pad/-/left-pad-1.3.1.tgz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
