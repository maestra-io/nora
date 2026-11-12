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
    proxy_fetch, proxy_fetch_artifact_hop, proxy_fetch_bytes, proxy_fetch_conditional,
    proxy_fetch_shared, proxy_forward_post, read_cached_artifact_pinned, read_validators,
    validators_key, write_validators, ArtifactHop, CachedArtifact, ProxyBody, ProxyError,
    Revalidation, Validators,
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
/// The release order of a version, for the metadata filter's `latest`.
pub(crate) use nora_registry::npm_links::semver_key;
use nora_registry::npm_links::{
    self, github_packages_tarball, link_host, max_semver, replace_upstream_bytes, Hop, Links,
    Placed, Refetched, TarballAsk, TarballStep, Unrewritable,
};
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
    // A bulk body is always read: the names of packages published here are stripped from it
    // whether or not a namespace filter is configured.
    let forward_body: Vec<u8> = if !filter_active && !is_bulk {
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
        let Some(stripped) = strip_internal_bulk(&plain, engine, &owned_scopes) else {
            return audit_refused(
                StatusCode::UNPROCESSABLE_ENTITY,
                "audit body is not the expected JSON object of package versions",
            );
        };
        match strip_published_bulk(&state, stripped).await {
            Ok(stripped) => stripped,
            Err(response) => return response,
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

/// Strip internal-namespace and private-scope package keys from an npm7 bulk-advisories body
/// (`{"<pkg>":[…]}`). `Some(bytes)` = the (possibly unchanged) body safe to forward;
/// `None` = the body is NOT the expected JSON object, so the caller must fail closed
/// under an active namespace filter (we could not verify no internal name is present).
/// The packages published here (C24/R2-20) are stripped after it, by [`strip_published_bulk`].
fn strip_internal_bulk(
    body: &[u8],
    engine: &crate::curation::CurationEngine,
    owned_scopes: &[&str],
) -> Option<Vec<u8>> {
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
    if map.len() == before {
        Some(body.to_vec())
    } else {
        // Re-serializing a just-parsed JSON map cannot fail in practice, but if it
        // ever did, refuse (`None`) rather than fall back to the ORIGINAL body —
        // that still contains the internal names. Keep the invariant fail-closed.
        serde_json::to_vec(&map).ok()
    }
}

/// The most packages a bulk audit may name: each is a listing of the store to tell whether it is
/// published here. Lockfiles of large monorepos name a few thousand.
const NPM_AUDIT_MAX_PACKAGES: usize = 10_000;

/// Strip the packages published here from a bulk-advisories body that [`strip_internal_bulk`]
/// returned: a published name is NORA's, and an upstream that learns it can register it. The
/// body is forwarded unchanged when it names none. A name whose published state cannot be read
/// refuses the audit (503): forwarding it could hand the name over, and dropping it would hide
/// its advisories.
async fn strip_published_bulk(state: &AppState, body: Vec<u8>) -> Result<Vec<u8>, Response> {
    use futures::StreamExt;
    let Ok(mut map) = serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(&body)
    else {
        return Err(audit_refused(
            StatusCode::UNPROCESSABLE_ENTITY,
            "audit body is not the expected JSON object of package versions",
        ));
    };
    if map.len() > NPM_AUDIT_MAX_PACKAGES {
        return Err(audit_refused(
            StatusCode::PAYLOAD_TOO_LARGE,
            "audit body names more packages than NORA checks (10000)",
        ));
    }
    let states: Vec<(String, Published)> = futures::stream::iter(map.keys().cloned())
        .map(|name| async move {
            // A name that is no valid key cannot be published here.
            let prefix = format!("npm/{name}/versions/");
            let published = match crate::validation::validate_storage_key(
                crate::validation::listing_key(&prefix),
            ) {
                Ok(()) => published_state(&state.storage, &name).await,
                Err(_) => Published::No,
            };
            (name, published)
        })
        .buffer_unordered(32)
        .collect()
        .await;
    let mut stripped = false;
    for (name, published) in states {
        match published {
            Published::Yes(_) => {
                map.remove(&name);
                stripped = true;
            }
            Published::No => {}
            Published::Unknown => {
                return Err(crate::registry::storage_unavailable(
                    "npm",
                    &format!("npm/{name}/versions/"),
                ))
            }
        }
    }
    if !stripped {
        return Ok(body);
    }
    serde_json::to_vec(&map).map_err(|e| {
        tracing::error!(error = %e, "npm audit: re-serializing the stripped body failed");
        audit_refused(
            StatusCode::INTERNAL_SERVER_ERROR,
            "audit body could not be re-serialized",
        )
    })
}

/// An upstream npm document as NORA serves it: its tarball links placed by
/// [`npm_links::place_document`] (with the server's storage-key check) — a version whose
/// tarball lies outside the upstream left out, `latest` falling back — then every other
/// upstream tarball link in it moved onto NORA by [`rewrite_upstream_tarball_links`]
/// (`_resolved`, an http `dist.bin` tarball, a dependency given as another package's
/// tarball URL).
///
/// Maestra: `npm_links` runs on the fields it reads (`name`, `version`, `dist-tags`,
/// `time`, each `dist.tarball`) only, so its byte-level net over every mention of the
/// upstream does not reach the rest: a readme, `publishConfig.registry` and the Sigstore
/// attestation URLs ([`UPSTREAM_PASSTHROUGH_PATHS`]) keep the upstream's URL, as NORA
/// answers no `-/` endpoint but search.
fn place_document(
    data: &[u8],
    nora_base: &str,
    upstream_url: &str,
    package_asked: Option<&str>,
    links: Links,
) -> Result<Placed, Unrewritable> {
    use serde_json::{Map, Value};
    let key_ok = |key: &str| crate::validation::validate_storage_key(key).is_ok();
    let mut doc: Value = serde_json::from_slice(data).map_err(|e| {
        tracing::warn!(error = %e, "npm: JSON parse failed in place_document");
        Unrewritable::NotJson
    })?;
    let link_of = |item: &Value| -> Value {
        match item.pointer("/dist/tarball") {
            Some(link) => serde_json::json!({ "dist": { "tarball": link } }),
            None => serde_json::json!({}),
        }
    };
    let mut part = Map::new();
    for field in ["name", "version", "dist-tags", "time"] {
        if let Some(value) = doc.get(field) {
            part.insert(field.to_string(), value.clone());
        }
    }
    if let Some(versions) = doc.get("versions").and_then(|v| v.as_object()) {
        let versions: Map<String, Value> = versions
            .iter()
            .map(|(version, item)| (version.clone(), link_of(item)))
            .collect();
        part.insert("versions".to_string(), Value::Object(versions));
    } else if let Some(dist) = link_of(&doc).get("dist") {
        part.insert("dist".to_string(), dist.clone());
    }
    let part = serde_json::to_vec(&Value::Object(part)).map_err(|_| Unrewritable::NotJson)?;
    let placed = npm_links::place_document(
        &part,
        nora_base,
        upstream_url,
        package_asked,
        links,
        &key_ok,
    )?;
    let placed_part: Value =
        serde_json::from_slice(&placed.body).map_err(|_| Unrewritable::NotJson)?;
    let placed_link = |item: &Value| item.pointer("/dist/tarball").cloned();
    if let Some(versions) = doc.get_mut("versions").and_then(|v| v.as_object_mut()) {
        let kept = placed_part.get("versions").and_then(|v| v.as_object());
        versions.retain(|version, _| kept.is_some_and(|kept| kept.contains_key(version)));
        for (version, item) in versions.iter_mut() {
            let link = kept
                .and_then(|kept| kept.get(version))
                .and_then(placed_link);
            if let (Some(link), Some(slot)) = (link, item.pointer_mut("/dist/tarball")) {
                *slot = link;
            }
        }
    } else if let (Some(link), Some(slot)) =
        (placed_link(&placed_part), doc.pointer_mut("/dist/tarball"))
    {
        *slot = link;
    }
    if let Some(top) = doc.as_object_mut() {
        for field in ["dist-tags", "time"] {
            if let Some(value) = placed_part.get(field) {
                top.insert(field.to_string(), value.clone());
            }
        }
    }
    let body = serde_json::to_vec(&doc).map_err(|e| {
        tracing::warn!(error = %e, "npm: JSON serialize failed in place_document");
        Unrewritable::NotJson
    })?;
    let nora_npm_base = format!("{}/npm", nora_base.trim_end_matches('/'));
    Ok(Placed {
        body: rewrite_upstream_tarball_links(
            &body,
            upstream_url.trim_end_matches('/'),
            &nora_npm_base,
        ),
        left_out: placed.left_out,
    })
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

/// Re-run the tarball-link safety net on a revalidated cached document (read from
/// `from_key`) and store the result under `key` when it changed or came from an older
/// release's key, so a 304 never serves upstream links an older rewriter left. Stored
/// like a fresh upstream body (provenance included), under the upstream cache only.
async fn upgrade_cached_packument(
    state: &AppState,
    name: &str,
    key: &str,
    from_key: &str,
    cached: Bytes,
    proxy_url: &str,
) -> Bytes {
    let nora_npm_base = format!("{}/npm", PUBLIC_BASE.trim_end_matches('/'));
    let current =
        rewrite_upstream_tarball_links(&cached, proxy_url.trim_end_matches('/'), &nora_npm_base);
    if current[..] == cached[..] && key == from_key {
        return cached;
    }
    let current = Bytes::from(current);
    let origin = origin_of(proxy_url);
    // LOCK-SAFE: the package lock retention holds while it prunes this cache.
    let lock = state.publish_lock(&package_lock_key(name));
    let _guard = lock.lock().await;
    if let Err(e) =
        cache_upstream_document(&state.storage, name, key, current.clone(), &origin).await
    {
        tracing::warn!(key = %key, error = ?e, "npm: could not store the upgraded cached packument");
    }
    current
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
    // The query goes as the client sent it, encoding kept; none without one (#1148).
    let mut url = format!("{}/-/v1/search", upstream.url.trim_end_matches('/'));
    if !query.is_empty() {
        url.push('?');
        url.push_str(query);
    }
    match proxy_fetch(
        metadata_client(state, upstream.scoped),
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

    // `npm dist-tag ls`: answered from a published package's own keys only, never
    // proxied (the name would leak upstream).
    if let Some(name) = dist_tags_package(&path) {
        return serve_dist_tags(&state, name).await;
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
        legacy_cache_key(&path)
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

    // Every metadata path: a published package's documents come from its own keys and never
    // from an upstream (see `serve_metadata`); any other path is answered by the upstream and
    // not cached. What follows is the tarball path only.
    if !is_tarball {
        return match classify_metadata_path(&path) {
            MetadataPath::Other => {
                let query = query.as_deref().filter(|q| !q.is_empty());
                uncached_upstream_metadata(&state, &headers, &path, &package_name, query).await
            }
            target => serve_metadata(&state, &headers, &path, target).await,
        };
    }

    let internal = is_internal(&state, &package_name);
    // A hosted tarball (internal namespace, or this version published here) is our
    // own publish, not a new upstream artifact: neither curation nor the quarantine
    // holds it (R2-18: its `time` is the local publish time, not an upstream release
    // date), as NuGet's hosted downloads.
    // R4-P07: read together with the first-seen ledger the curation check below dates the
    // version from, one round trip instead of two before the tarball's own read.
    let (published_here, first_seen) = match tarball_version.as_deref() {
        Some(v) if !internal => tokio::join!(
            async {
                state
                    .storage
                    .stat(&format!("npm/{package_name}/versions/{v}.json"))
                    .await
                    .is_some()
            },
            async {
                if first_seen_tracked(&state) {
                    first_seen_date(&state.storage, &upstream_packument_key(&package_name), v).await
                } else {
                    None
                }
            },
        ),
        _ => (false, None),
    };
    let hosted = internal || published_here;

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
    if !hosted {
        // Without trusted dates a release is as old as NORA's first sight of it in a
        // packument: the cache mtime above restarts at every refetch, so a client that
        // asks more often than the minimum age never saw its release mature. The
        // quarantine reads neither: a version listed long ago says nothing about bytes
        // first fetched now, so without trusted dates it counts from the first fetch. A
        // version the ledger lacks keeps the mtime date.
        let release_date = first_seen.or(publish_date);
        if let Some(response) = crate::curation::check_download(
            &state.curation().curation_engine,
            state.bypass_token().as_deref(),
            &headers,
            crate::curation::RegistryType::Npm,
            &package_name,
            crate::curation::RequestVersion::of_artifact(tarball_version.as_deref()),
            release_date,
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
        && !crate::curation::integrity_applies(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Npm,
            &package_name,
            tarball_version.as_deref(),
        )
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

    // --- Cache hit path ---
    // get_verified discharges the integrity witness at the serve site (compile-time
    // guarantee — see crate::verified). Both the tarball serve (pinned, Verified arm)
    // and the metadata serve (unpinned, Unpinned arm) flow the discharged bytes. A copy
    // without a pin (stored before pins) was checked against nothing by the read: for
    // it the .sha256 sidecar check below is the integrity check. A pinned one is not
    // read against the sidecar again (R4-P07).
    let cached = if cache_trusted {
        // A tarball above `server.stream_threshold_mb` streams from storage (C17).
        match read_cached_artifact_pinned(&state, "npm", &key, internal).await {
            Ok(Some((CachedArtifact::Buffered { data, sha256 }, pinned))) => {
                Some((data, sha256, pinned))
            }
            Ok(Some((streamed, _))) => {
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
        None
    };
    // `sha256` is the digest the read verified (pinned) or took once (unpinned): the
    // sidecar, curation and quarantine checks below all use it, none hashes the body
    // again (R4-P05).
    let cached = match cached {
        Some((data, sha256, true)) => Some((data, sha256)),
        Some((data, sha256, false)) => {
            // Tarball: integrity check against the sidecar written with it.
            let digest = sha256.clone();
            match crate::registry::check_sidecar_digest(&state.storage, &key, || digest).await {
                crate::registry::Sidecar::Holds => Some((data, sha256)),
                crate::registry::Sidecar::Differs { expected, computed } => {
                    tracing::error!(
                        key = %key,
                        expected = %expected,
                        computed = %computed,
                        "SECURITY: npm tarball integrity check FAILED — possible tampering"
                    );
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Integrity check failed")
                        .into_response();
                }
                // A copy NORA owns has nowhere else to come from: unavailable, its bytes not sent.
                // A proxied one is fetched again below and checked as on its first download.
                crate::registry::Sidecar::Unreadable(e) => {
                    let own = internal
                        || state.config.npm.route(&path).is_none()
                        || !matches!(
                            published_state(&state.storage, &package_name).await,
                            Published::No
                        );
                    if own {
                        return crate::registry::local_copy_unreadable(
                            "npm",
                            &format!("{key}.sha256"),
                            &e,
                        );
                    }
                    tracing::warn!(key = %key, error = %e, "npm: tarball sidecar unreadable, fetching the tarball again");
                    None
                }
            }
        }
        None => None,
    };
    if let Some((data, sha256)) = cached {
        let digest = format!("sha256:{sha256}");
        // Curation integrity verification (issue #189)
        if let Some(response) = crate::curation::verify_integrity_by_hash(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Npm,
            &package_name,
            tarball_version.as_deref(),
            &digest,
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
        // A digest with no record counts from when its copy was cached (R4-C05).
        if let Some(resp) = crate::digest_quarantine::cache_gate_digest(
            &state.digest_store,
            &state.storage,
            &key,
            "npm",
            &digest,
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
        let mut response = with_content_type(true, data).into_response();
        response
            .headers_mut()
            .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        return response;
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
    if hosted {
        return StatusCode::NOT_FOUND.into_response();
    }

    // A tarball of a published package that NORA does not store is no version of it: the upstream
    // is not asked, so what it has under the name is neither served nor stored beside the published
    // versions (as for cargo, #1158). The packument lists the published versions only, so only a
    // direct or locked URL gets here. When the published versions cannot be listed NORA cannot
    // tell whether the name is its own: unavailable (503), the upstream not asked.
    match published_state(&state.storage, &package_name).await {
        Published::Yes(_) => return StatusCode::NOT_FOUND.into_response(),
        Published::Unknown => {
            return crate::registry::storage_unavailable(
                "npm",
                &format!("npm/{package_name}/versions/"),
            )
        }
        Published::No => {}
    }

    // --- Proxy fetch path ---
    if let Some(upstream) = state.config.npm.route(&path) {
        let proxy_url = upstream.url;
        // Only a version the owner's packument lists is asked for, the redirects walked by
        // `fetch_following`; a tarball above `server.stream_threshold_mb` is spooled to disk (C17).
        let (url, result) = fetch_upstream_tarball(
            &state,
            upstream.url,
            upstream.auth,
            &path,
            &key,
            TarballAsk::parse(&path).as_ref(),
        )
        .await;
        match result {
            Ok((spooled @ ProxyBody::File(_), fetched)) => {
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
                // The allowlist's pinned integrity holds on the first download too, before
                // anything is cached: a blocked body is neither served nor cached.
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

                // A concurrent request that fetched these bytes caches them.
                if fetched {
                    // LOCK-SAFE: a tarball is immutable; no lock is held here.
                    let hash = hex::encode(sha2::Sha256::digest(&data));
                    let hash_key = format!("{}.sha256", key);
                    let storage = state.storage.clone();
                    let key_clone = key.clone();
                    let body = data.clone();
                    let repo_index = Arc::clone(&state.repo_index);
                    let origin = origin_of(proxy_url);
                    tokio::spawn(async move {
                        if let Err(e) = storage.put(&hash_key, hash.as_bytes()).await {
                            tracing::warn!(key = %hash_key, error = ?e, "npm proxy: failed to cache hash sidecar");
                        }
                        // Cache, then invalidate the index AFTER the write completes.
                        if let Err(e) = put_with_origin(&storage, &key_clone, body, &origin).await {
                            tracing::warn!(key = %key_clone, error = ?e, "npm proxy: failed to cache artifact");
                        } else {
                            repo_index.invalidate("npm");
                        }
                    });
                }

                if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
                    &state.digest_store,
                    "npm",
                    &data,
                    &q_mode,
                    q_secs,
                    &url,
                    crate::digest_quarantine::first_seen_seed(
                        state.config.server.trust_upstream_dates,
                        publish_date,
                    ),
                )
                .await
                {
                    return resp;
                }
                return with_content_type(true, data).into_response();
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

/// Fetch the tarball `ask` names from `upstream` where [`npm_links::tarball_step`] decides, with
/// the upstream's credential: only for a version the owner's trusted packument lists, that
/// packument fetched again once when it does not (the version may be newer than the copy).
/// Returns what the download is recorded as, with what it gave; `None` (no tarball of a version)
/// and a version not listed are `NotFound` without a request for the tarball.
///
/// The credential goes as far as the upstream's origin, the redirects followed by
/// [`fetch_following`]. `key` is the tarball's storage key, the download's single-flight.
async fn fetch_upstream_tarball(
    state: &AppState,
    upstream: &str,
    auth: Option<crate::config::UpstreamAuth<'_>>,
    path: &str,
    key: &str,
    ask: Option<&TarballAsk<'_>>,
) -> (String, Result<(ProxyBody, bool), ProxyError>) {
    let at_upstream = format!("{}/{}", upstream.trim_end_matches('/'), path);
    let Some(ask) = ask else {
        return (at_upstream, Err(ProxyError::NotFound));
    };
    let nora_base = nora_base_url(state);
    let nora_npm_base = format!("{}/npm", nora_base.trim_end_matches('/'));
    let key_ok = |key: &str| crate::validation::validate_storage_key(key).is_ok();
    // A cached packument names NORA by `PUBLIC_BASE`: read against the base it is served under.
    let on_nora = |link: String| match link.strip_prefix(PUBLIC_BASE) {
        Some(rest) => format!("{}{rest}", nora_base.trim_end_matches('/')),
        None => link,
    };
    let listed = trusted_copy(state, ask.package())
        .await
        .and_then(|copy| copy.listed(ask.version()))
        .unwrap_or_default();
    let copy = listed.tarball.map(on_nora);
    // What the packument says the tarball hashes to, and whether that packument was fetched
    // for this download (the cached copy may be older than the file the upstream has now).
    let mut expected = listed.digest;
    let mut current = false;
    let doc_key = upstream_packument_key(ask.package());
    let refetch = || {
        refetch_metadata(
            state,
            ask.package(),
            ask.package(),
            &doc_key,
            &doc_key,
            true,
            false,
        )
    };
    let step = |refetched| {
        npm_links::tarball_step(
            ask,
            upstream,
            &nora_npm_base,
            copy.as_deref(),
            refetched,
            &key_ok,
        )
    };
    let mut decided = step(None);
    if matches!(decided, TarballStep::Refetch) {
        let refetched = match refetch().await {
            Ok(doc) => {
                let listed = npm_links::listed(&doc, ask.version()).unwrap_or_default();
                expected = listed.digest;
                current = true;
                Refetched::Packument(listed.tarball.map(on_nora))
            }
            Err(ProxyError::NotFound) => Refetched::NoPackument,
            Err(e) => Refetched::Failed(e),
        };
        decided = step(Some(refetched));
    }
    let (asked, named) = match decided {
        TarballStep::Ask { asked, named } => (asked, named),
        TarballStep::UpstreamFailed(e) => return (at_upstream, Err(e)),
        TarballStep::NotFound | TarballStep::Refetch => {
            tracing::info!(
                registry = "npm",
                package = %ask.package(),
                version = %ask.version(),
                "tarball not listed by its upstream's packument, not asked for"
            );
            return (at_upstream, Err(ProxyError::NotFound));
        }
    };
    let fetched = fetch_following(state, upstream, &asked, auth, &nora_npm_base, key).await;
    // R4-R03: the body is the file the packument lists, or it is neither served nor cached. A
    // body shared by a concurrent request is checked too: its leader's refusal is not ours.
    if let (Ok((body, _)), Some(want)) = (&fetched, &expected) {
        let mut holds = tarball_matches(body, want).await;
        if !holds && !current {
            // The cached packument may predate a file its upstream replaced: asked once more.
            if let Ok(doc) = refetch().await {
                holds = match npm_links::listed(&doc, ask.version()).and_then(|l| l.digest) {
                    Some(want) => tarball_matches(body, &want).await,
                    None => false,
                };
            }
        }
        if !holds {
            tracing::warn!(
                registry = "npm",
                package = %ask.package(),
                version = %ask.version(),
                "upstream tarball does not match the integrity its packument gives, refusing it"
            );
            let refused = "tarball does not match the integrity its packument gives";
            return (named, Err(ProxyError::Network(refused.to_string())));
        }
    }
    (named, fetched)
}

/// Whether `body` hashes to `want`. A body that cannot be read back does not.
async fn tarball_matches(body: &ProxyBody, want: &npm_links::TarballDigest) -> bool {
    use npm_links::TarballDigest;
    let (got, want) = match want {
        TarballDigest::Sha512(want) => (body.hash::<sha2::Sha512>().await, want),
        TarballDigest::Sha1(want) => (body.hash::<sha1::Sha1>().await, want),
    };
    got.is_ok_and(|got| &got == want)
}

/// Download `asked` from `upstream` with its credential, following the redirects here, one at
/// a time: the client follows none, so the whole chain has one budget and every hop is decided
/// by [`npm_links::next_hop`] — ten redirects pass and the eleventh is a failure (502), and the
/// credential goes only while the chain is on `asked`'s origin. A registry keeping its files on
/// a storage host is reached without it, and so is its origin again from there: reqwest drops
/// the header on the hop to another host but puts it back on the next hop within that host.
/// The chain shares one `proxy_timeout` for its response headers; the body of the last hop is
/// bounded by its progress and spooled above `server.stream_threshold_mb` (C17), under the
/// single-flight of `key`.
async fn fetch_following(
    state: &AppState,
    upstream: &str,
    asked: &str,
    mut auth: Option<crate::config::UpstreamAuth<'_>>,
    nora_npm_base: &str,
    key: &str,
) -> Result<(ProxyBody, bool), ProxyError> {
    let origin = reqwest::Url::parse(asked)
        .map_err(|e| ProxyError::Network(format!("tarball URL not readable: {e}")))?;
    let deadline = std::time::Instant::now() + Duration::from_secs(state.config.npm.proxy_timeout);
    let mut url = asked.to_string();
    let mut left_origin = false;
    let mut hop = 0;
    loop {
        hop += 1;
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let scope = BreakerScope::upstream(RegistryType::Npm, upstream);
        // One request per hop: a body is spooled as any artifact's, a redirect handed back.
        let next = match proxy_fetch_artifact_hop(
            state,
            &state.http_client_no_redirect,
            key,
            "npm",
            &url,
            left.as_secs().max(1),
            auth,
            scope,
        )
        .await?
        {
            ArtifactHop::Body(body, fetched) => return Ok((body, fetched)),
            ArtifactHop::Redirect(next) => next,
        };
        url = match npm_links::next_hop(hop, &origin, left_origin, &next) {
            // The URL asked carries the upstream's userinfo, if its URL has one; the hop on
            // its origin carries it too.
            Hop::WithCredential => {
                npm_links::with_userinfo_of(next.as_str(), asked).unwrap_or_else(|| next.into())
            }
            Hop::WithoutCredential => {
                if !left_origin {
                    tracing::debug!(
                        registry = "npm",
                        to = %link_host(next.as_str(), nora_npm_base),
                        "tarball on another origin, fetched without the upstream's credential"
                    );
                }
                left_origin = true;
                auth = None;
                next.into()
            }
            Hop::Refuse => {
                tracing::warn!(
                    registry = "npm",
                    hop,
                    to = %link_host(next.as_str(), nora_npm_base),
                    "tarball redirect not followed: past the redirect limit or not http(s)"
                );
                return Err(ProxyError::Network("redirect not followed".to_string()));
            }
        };
    }
}

/// The client an upstream's metadata is fetched with. An upstream bound to a scope answers from
/// its own origin only: a redirect off it is not followed, and the fetch fails with the 3xx (a
/// 502 to the client), so neither the scope's package names nor the credential reach another
/// origin. The default upstream follows redirects.
fn metadata_client(state: &AppState, scoped: bool) -> &reqwest::Client {
    if scoped {
        &state.http_client_same_origin
    } else {
        &state.http_client
    }
}

/// The trusted cached packument of `package`: the copy under the upstream key, else an older
/// release's upstream cache under the legacy key (reached for a package not published here),
/// each trusted on its own provenance ([`trusted::TrustedPackument::at`]).
async fn trusted_copy(state: &AppState, package: &str) -> Option<trusted::TrustedPackument> {
    for key in [upstream_packument_key(package), legacy_cache_key(package)] {
        if let Some(copy) = trusted::TrustedPackument::at(state, package, &key).await {
            return Some(copy);
        }
    }
    None
}

mod trusted {
    use crate::AppState;
    use nora_registry::npm_links;

    /// A cached packument its owner delivered: the only copy a tarball link is taken from.
    /// Its one constructor checks the copy's provenance at the key it is read from.
    pub(super) struct TrustedPackument(axum::body::Bytes);

    impl TrustedPackument {
        /// The copy at `key`, if [`super::cached_copy_trusted`] trusts it and it reads.
        pub(super) async fn at(state: &AppState, package: &str, key: &str) -> Option<Self> {
            if !super::cached_copy_trusted(state, package, key, package, None).await {
                return None;
            }
            let (Some(outcome), _) =
                crate::registry::cached_read(state.storage.get_verified(key).await)
            else {
                return None;
            };
            use nora_registry::verified::{verified_body, GateOutcome};
            Some(Self(match outcome {
                GateOutcome::Verified(blob) => verified_body(blob),
                GateOutcome::Unpinned(blob) => blob.into_inner(),
            }))
        }

        /// What this copy says of the tarball of `version`, if it lists that version.
        pub(super) fn listed(&self, version: &str) -> Option<npm_links::Listed> {
            npm_links::listed(&self.0, version)
        }
    }
}

/// Whether `name` is in an internal namespace: served from its local copies only, never asked of
/// an upstream (#68, #733).
fn is_internal(state: &AppState, name: &str) -> bool {
    crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Npm,
        name,
    )
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

/// Internal prefix holding when NORA first saw each npm version listed upstream.
pub(crate) const FIRST_SEEN_PREFIX: &str = ".nora-first-seen/";

/// First-seen ledger of the package whose packument is cached at `metadata_key`:
/// `.nora-first-seen/npm/<name>/metadata.json`. Internal like [`origin_key`], so no
/// request, listing, retention or GC walk of the npm key space reaches it.
pub(crate) fn first_seen_key(metadata_key: &str) -> String {
    format!("{FIRST_SEEN_PREFIX}{metadata_key}")
}

/// Version → Unix time NORA first saw it listed in an upstream packument.
type FirstSeen = std::collections::BTreeMap<String, i64>;

/// The internal state carried by backup and migrate along with what `list()` shows,
/// with the digest-quarantine ledger's entries (Maestra).
pub(crate) const INTERNAL_PREFIXES: &[&str] = &[
    ORIGINS_PREFIX,
    FIRST_SEEN_PREFIX,
    crate::digest_quarantine::ENTRY_PREFIX,
];

/// Whether release ages come from the first-seen ledger: upstream dates are not trusted
/// and curation runs. Otherwise nothing reads it, and nothing is written.
fn first_seen_tracked(state: &AppState) -> bool {
    !state.config.server.trust_upstream_dates && state.curation().curation_engine.is_active()
}

/// The versions a packument lists, without building their manifests.
fn packument_versions(body: &[u8]) -> Option<Vec<String>> {
    #[derive(serde::Deserialize)]
    struct Listing {
        #[serde(default)]
        versions: std::collections::HashMap<String, serde::de::IgnoredAny>,
    }
    let listing: Listing = serde_json::from_slice(body).ok()?;
    Some(listing.versions.into_keys().collect())
}

/// Record when NORA first saw each version `body` lists — the upstream packument about to
/// be served for `key`. A version keeps the time it was first recorded, so no refetch, 200
/// or 304, makes a release younger; a version the upstream adds later starts now.
///
/// `cached_before`: the copy at `key` is NORA's own earlier one. A cache from before the
/// ledger existed starts the versions it lists at its file time, when NORA last wrote it —
/// never earlier than NORA saw them. Awaited before the packument is served, so a client
/// cannot ask for a version the ledger does not hold yet.
async fn record_first_seen(state: &AppState, key: &str, body: &[u8], seed_from: Option<&str>) {
    if !first_seen_tracked(state) {
        return;
    }
    let Some(versions) = packument_versions(body) else {
        return;
    };
    let ledger_key = first_seen_key(key);
    // LOCK-SAFE: tokio mutex, the one the publish path takes for this packument; it
    // serializes the read-modify-write of the ledger. Nothing else is locked under it.
    let lock = state.publish_lock(key);
    let _guard = lock.lock().await;
    let (mut ledger, existed) = match state.storage.get(&ledger_key).await {
        Ok(bytes) => match serde_json::from_slice::<FirstSeen>(&bytes) {
            Ok(ledger) => (ledger, true),
            Err(e) => {
                // Rewritten from now on: an unreadable time can only make a release younger.
                tracing::warn!(key = %ledger_key, error = %e, "npm: unreadable first-seen ledger");
                (FirstSeen::new(), false)
            }
        },
        // No ledger yet: a cached packument (this key's, or what an older release cached)
        // starts its versions at its own write time.
        Err(crate::storage::StorageError::NotFound) => match seed_from {
            Some(seed) => (cached_first_seen(&state.storage, seed).await, false),
            None => (FirstSeen::new(), false),
        },
        // The bytes do not match their pin: the ledger is known bad, not merely unread.
        // Rewritten from now on, as an unparsable one: every release starts young again,
        // which holds more, never less, and the ledger heals instead of staying unread.
        Err(crate::storage::StorageError::IntegrityViolation) => {
            tracing::warn!(key = %ledger_key, "npm: first-seen ledger failed its pin; rewritten");
            (FirstSeen::new(), false)
        }
        Err(e) => {
            // Not written over a ledger that may exist: a later refetch records the rest.
            tracing::warn!(key = %ledger_key, error = %e, "npm: first-seen ledger unreadable");
            return;
        }
    };
    let now = chrono::Utc::now().timestamp();
    let known = ledger.len();
    for version in versions {
        ledger.entry(version).or_insert(now);
    }
    if existed && ledger.len() == known {
        return;
    }
    match serde_json::to_vec(&ledger) {
        Ok(bytes) => {
            if let Err(e) = state.storage.put(&ledger_key, &bytes).await {
                tracing::warn!(key = %ledger_key, error = ?e, "npm: failed to record first-seen times");
            }
        }
        Err(e) => {
            tracing::warn!(key = %ledger_key, error = %e, "npm: first-seen ledger not encoded")
        }
    }
}

/// First-seen times of a packument cached before the ledger: every version it lists at its
/// file time. The body is read before the time, so a write landing in between can only make
/// the time later.
async fn cached_first_seen(storage: &crate::Storage, key: &str) -> FirstSeen {
    let Ok(body) = storage.get(key).await else {
        return FirstSeen::new();
    };
    let Some(written) = storage.stat(key).await.map(|m| m.modified as i64) else {
        return FirstSeen::new();
    };
    packument_versions(&body)
        .unwrap_or_default()
        .into_iter()
        .map(|version| (version, written))
        .collect()
}

/// When NORA first saw `version` listed in the packument at `metadata_key`.
async fn first_seen_date(
    storage: &crate::Storage,
    metadata_key: &str,
    version: &str,
) -> Option<i64> {
    let bytes = storage.get(&first_seen_key(metadata_key)).await.ok()?;
    let ledger: FirstSeen = serde_json::from_slice(&bytes).ok()?;
    ledger.get(version).copied()
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
    async fn check(&self, state: &AppState, digest: &str, upstream: &str) -> Option<Response> {
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
        .await
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
    // A digest with no record counts from when its copy was cached (R4-C05).
    let cached_at = match gates.q_mode {
        crate::digest_quarantine::QuarantineMode::Off => None,
        _ => {
            crate::digest_quarantine::cached_first_seen(
                &state.digest_store,
                &state.storage,
                key,
                "npm",
                &digest,
            )
            .await
        }
    };
    let gates = TarballGates {
        publish_date: gates.publish_date.or(cached_at),
        ..gates
    };
    if let Some(response) = gates.check(state, &digest, "cache").await {
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
    )
    .await
    {
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
    let recorded = state.storage.get(&origin_key(key)).await.ok();
    let pin = state.storage.pin(key).await;
    npm_links::copy_is_owners(recorded.as_deref(), pin.as_deref(), owner.url)
}

/// Whether `name` may have versions published here: published, or a listing that failed
/// (nothing is decided on a guess). Such a package is owned locally: it is never
/// revalidated against, or overwritten by, an upstream document, and its name never
/// goes upstream.
async fn has_local_versions(storage: &crate::Storage, name: &str) -> bool {
    !matches!(published_state(storage, name).await, Published::No)
}

/// Whether `versions/` still lists a key, as a write path sees it after its own writes: an
/// assembled packument beside an empty listing is the one it is about to rebuild or remove,
/// not a sign of a lying backend. A failed listing counts as versions left, so the packument
/// is rebuilt, never deleted.
async fn versions_left(storage: &crate::Storage, name: &str) -> bool {
    storage
        .list(&format!("npm/{name}/versions/"))
        .await
        .map_or(true, |keys| !keys.is_empty())
}

/// What an npm metadata path names.
#[derive(Debug, PartialEq, Eq)]
enum MetadataPath<'a> {
    /// A packument: `pkg` or `@scope/pkg`.
    Packument { name: &'a str },
    /// One version's manifest: `pkg/<spec>` or `@scope/pkg/<spec>`, spec a version or a dist-tag.
    VersionManifest { name: &'a str, spec: &'a str },
    /// Anything else, such as registry endpoints under `-/`.
    Other,
}

/// Classify an npm metadata path. Pure: which keys a request may read and write hangs on it.
fn classify_metadata_path(path: &str) -> MetadataPath<'_> {
    let segments: Vec<&str> = path.split('/').collect();
    // `-/…` is the registry's own endpoint space; a package name may still start with `-`.
    if segments.iter().any(|s| s.is_empty()) || segments[0] == "-" {
        return MetadataPath::Other;
    }
    let name_segments = if segments[0].starts_with('@') { 2 } else { 1 };
    if segments.len() < name_segments {
        return MetadataPath::Other;
    }
    let name_len = segments[..name_segments]
        .iter()
        .map(|s| s.len())
        .sum::<usize>()
        + name_segments
        - 1;
    let name = &path[..name_len];
    match segments.len() - name_segments {
        0 => MetadataPath::Packument { name },
        1 => MetadataPath::VersionManifest {
            name,
            spec: segments[name_segments],
        },
        _ => MetadataPath::Other,
    }
}

/// The package `npm dist-tag ls` asks about: `-/package/<name>/dist-tags`, name `pkg` or
/// `@scope/pkg`.
fn dist_tags_package(path: &str) -> Option<&str> {
    let name = path
        .strip_prefix("-/package/")?
        .strip_suffix("/dist-tags")?;
    match classify_metadata_path(name) {
        MetadataPath::Packument { name } => Some(name),
        _ => None,
    }
}

/// `GET -/package/<name>/dist-tags`: a published package's tags from its own keys; 404 for
/// any other package, whose name never goes upstream from here.
async fn serve_dist_tags(state: &AppState, name: &str) -> Response {
    let own = match published_state(&state.storage, name).await {
        // Tags derived from the versions (`latest` when no pointer names it) need them all.
        Published::Yes(published) => match assemble_packument(&state.storage, name).await {
            Ok(bytes) if listed_versions(&bytes).as_ref() != Some(&published) => {
                return published_versions_unreadable(state, name, &published, &bytes).await;
            }
            Ok(bytes) => bytes,
            Err(unassembled) => return unassembled.response(name),
        },
        // The listing failed: a packument NORA assembled is still the package's own.
        Published::Unknown => {
            let key = published_packument_key(name);
            match state.storage.get(&key).await {
                Ok(data) if is_assembled_by_nora(&state.storage, &key, &data).await => {
                    data.to_vec()
                }
                // Without one NORA cannot tell whether the tags are its own.
                _ => return crate::registry::storage_unavailable("npm", &key),
            }
        }
        Published::No => return StatusCode::NOT_FOUND.into_response(),
    };
    let tags = serde_json::from_slice::<serde_json::Value>(&own)
        .ok()
        .and_then(|doc| doc.get("dist-tags").cloned())
        .unwrap_or_else(|| serde_json::json!({}));
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        tags.to_string(),
    )
        .into_response()
}

/// The packument NORA assembles for a package published to it. Publish and the rebuild are
/// its only writers.
pub(crate) fn published_packument_key(name: &str) -> String {
    format!("npm/{name}/metadata.json")
}

/// The publish-lock key of a package's metadata: publish, the rebuild, retention's
/// reconciliation and every write of the upstream cache hold it, so none of them
/// interleaves with another.
pub(crate) fn package_lock_key(name: &str) -> String {
    published_packument_key(name)
}

/// Where the packument an upstream serves for a package NORA has not published is cached.
pub(crate) fn upstream_packument_key(name: &str) -> String {
    format!("npm/{name}/upstream/packument.json")
}

/// Where one version's manifest that an upstream serves is cached.
fn upstream_manifest_key(name: &str, spec: &str) -> String {
    format!("npm/{name}/upstream/manifests/{spec}.json")
}

/// Where a release before 1.4.0 cached an upstream document for `path`. Read as a cache until
/// the new key is written, never written or deleted, so a rollback still finds it.
fn legacy_cache_key(path: &str) -> String {
    format!("npm/{path}/metadata.json")
}

/// Whether a package is published to NORA, from its `versions/` listing.
enum Published {
    /// These versions are published.
    Yes(std::collections::BTreeSet<String>),
    No,
    /// The listing failed: nothing is decided on a guess.
    Unknown,
}

async fn published_state(storage: &crate::Storage, name: &str) -> Published {
    let prefix = format!("npm/{name}/versions/");
    // Asked on every proxied tarball, packument and audit name, and "no" for all but the
    // packages published here: a "no" is remembered for `EMPTY_PREFIX_TTL` (R4-P01), the
    // listing and the record read below with it. A version published through this
    // process is seen at once (its write under `versions/` voids the memo before the
    // publish is acknowledged), one published by another replica within the TTL.
    let (listed, claim) = match storage.list_claiming_empty(&prefix).await {
        Ok(listed) => listed,
        Err(e) => {
            tracing::warn!(registry = "npm", package = %name, error = %e, "npm: versions listing failed");
            return Published::Unknown;
        }
    };
    if !listed.is_empty() {
        return Published::Yes(
            listed
                .iter()
                .filter_map(|k| k.strip_prefix(&prefix)?.strip_suffix(".json"))
                .map(str::to_string)
                .collect(),
        );
    }
    // Remembered: the checks below already said "not published" for this listing.
    let Some(claim) = claim else {
        return Published::No;
    };
    // An empty listing beside a packument NORA assembled is not taken at its word: the
    // package was published, and a backend that answers "nothing here" for files it cannot
    // read must not hand its name to an upstream.
    let key = published_packument_key(name);
    // The record decides first: without one naming NORA the document cannot be one it
    // assembled, whatever its bytes. The same key holds the upstream copy a release
    // before 1.4.0 cached (`legacy_cache_key`), megabytes per package.
    let record = storage.get(&origin_key(&key)).await;
    // A "no" is remembered only when the store answered about the record (it is absent,
    // or names another origin), not when it failed to.
    let answered = matches!(record, Ok(_) | Err(crate::storage::StorageError::NotFound));
    let names_nora = record
        .ok()
        .as_deref()
        .and_then(|r| std::str::from_utf8(r).ok())
        .and_then(|r| r.split_once('\n'))
        .is_some_and(|(origin, _)| origin == ASSEMBLED_BY_NORA);
    if !names_nora {
        if answered {
            claim.remember();
        }
        return Published::No;
    }
    match storage.get(&key).await {
        Ok(data) if is_assembled_by_nora(storage, &key, &data).await => {
            tracing::warn!(registry = "npm", package = %name, "npm: no published versions listed beside an assembled packument");
            Published::Unknown
        }
        _ => Published::No,
    }
}

/// The key a reader of a package's packument (release dates, the web UI) reads: the
/// published one, else the upstream cache, else what an older release cached.
pub(crate) async fn packument_key_for_reading(storage: &crate::Storage, name: &str) -> String {
    match published_state(storage, name).await {
        Published::Yes(_) => return published_packument_key(name),
        // The listing failed: a packument NORA assembled is still the one to read.
        Published::Unknown => {
            let key = published_packument_key(name);
            if let Ok(data) = storage.get(&key).await {
                if is_assembled_by_nora(storage, &key, &data).await {
                    return key;
                }
            }
        }
        Published::No => {}
    }
    let cached = upstream_packument_key(name);
    if storage.stat(&cached).await.is_some() {
        cached
    } else {
        legacy_cache_key(name)
    }
}

/// The origin a published packument's provenance record names: NORA assembled these bytes
/// from the package's published keys.
const ASSEMBLED_BY_NORA: &str = "nora-published";

/// Whether a stored published packument may be served as it is. Only bytes NORA assembled are:
/// their record names [`ASSEMBLED_BY_NORA`] and the digest of exactly the bytes stored now.
/// Anything else — no record (an older release, which never wrote one, cached it), an upstream's
/// record, a record written for other bytes — is rebuilt from the published keys. Pure: the
/// whole decision is this function.
fn assembled_by_nora(record: Option<&str>, stored_digest: &str) -> bool {
    record
        .and_then(|r| r.split_once('\n'))
        .is_some_and(|(origin, digest)| {
            origin == ASSEMBLED_BY_NORA && !digest.is_empty() && digest == stored_digest
        })
}

/// [`assembled_by_nora`] for the object at `key` holding `data`.
async fn is_assembled_by_nora(storage: &crate::Storage, key: &str, data: &[u8]) -> bool {
    let record = storage.get(&origin_key(key)).await.ok();
    let record = record.as_deref().and_then(|r| std::str::from_utf8(r).ok());
    let digest = match storage.pin(key).await {
        Some(pin) => pin,
        None => hex::encode(sha2::Sha256::digest(data)),
    };
    assembled_by_nora(record, &digest)
}

/// Store a packument NORA assembled for a published package, with the record that lets it be
/// served as it is (see [`assembled_by_nora`]). Data first: a record always describes bytes
/// already written; a failed record write only costs a rebuild at the next read.
async fn store_assembled_packument(
    storage: &crate::Storage,
    name: &str,
    bytes: &[u8],
) -> Result<(), crate::storage::StorageError> {
    let key = published_packument_key(name);
    storage.put(&key, bytes).await?;
    let record = provenance_record(ASSEMBLED_BY_NORA, bytes);
    if let Err(e) = storage.put(&origin_key(&key), record.as_bytes()).await {
        tracing::warn!(key = %key, error = ?e, "npm: failed to record an assembled packument");
    }
    Ok(())
}

/// Whether the object at `key` was cached from an upstream: its provenance record exists and
/// was written for exactly the bytes stored now (the pin).
async fn is_upstream_copy(storage: &crate::Storage, key: &str) -> bool {
    let Ok(recorded) = storage.get(&origin_key(key)).await else {
        return false;
    };
    let Some((origin, digest)) = std::str::from_utf8(&recorded)
        .ok()
        .and_then(|r| r.split_once('\n'))
    else {
        return false;
    };
    origin != ASSEMBLED_BY_NORA && storage.pin(key).await.as_deref() == Some(digest)
}

/// The version names a packument document lists, or `None` when it does not parse. The
/// version documents are skipped, not built: this runs on every read of a published packument.
fn listed_versions(data: &[u8]) -> Option<std::collections::BTreeSet<String>> {
    #[derive(serde::Deserialize)]
    struct Listing {
        versions: std::collections::BTreeMap<String, serde::de::IgnoredAny>,
    }
    let listing: Listing = serde_json::from_slice(data).ok()?;
    Some(listing.versions.into_keys().collect())
}

/// Answer a packument or version request for a published package, or for one cached from an
/// upstream. `target` is a packument or a version manifest.
async fn serve_metadata(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
    target: MetadataPath<'_>,
) -> Response {
    let (name, spec, cache_key) = match target {
        MetadataPath::Packument { name } => (name, None, upstream_packument_key(name)),
        MetadataPath::VersionManifest { name, spec } => {
            (name, Some(spec), upstream_manifest_key(name, spec))
        }
        MetadataPath::Other => return StatusCode::NOT_FOUND.into_response(),
    };
    if let Err(e) = crate::validation::validate_storage_key(&cache_key) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    let base = nora_base_url(state);
    match published_state(&state.storage, name).await {
        Published::Yes(versions) => match spec {
            None => published_packument_response(state, headers, name, &versions, &base).await,
            Some(spec) => published_version_manifest(state, name, spec, &base).await,
        },
        Published::No => {
            upstream_metadata(state, headers, path, name, &cache_key, spec.is_none()).await
        }
        // The listing failed. A packument NORA assembled is still here: the package is published,
        // and its documents are served as they are, read only. Without one, or with an upstream copy
        // in its place, the package is unavailable and no upstream is asked.
        Published::Unknown => {
            let key = published_packument_key(name);
            match state.storage.get(&key).await {
                Ok(data) if is_assembled_by_nora(&state.storage, &key, &data).await => match spec {
                    None => packument_response(
                        headers,
                        rebase_hosted_tarballs(data, PUBLIC_BASE, name),
                        &base,
                        None,
                    ),
                    Some(spec) => published_version_manifest(state, name, spec, &base).await,
                },
                // Without one NORA cannot tell whether the package is its own: unavailable (503), as
                // cargo answers a crate it cannot tell is published. A published name is never an
                // upstream's to answer for.
                _ => crate::registry::storage_unavailable("npm", &key),
            }
        }
    }
}

/// The packument of a published package. The stored document is served when it lists exactly
/// the published versions and NORA assembled it (an older release, or another replica running
/// one, could still have cached an upstream copy over it); otherwise it is rebuilt from the
/// published keys under the publish lock. Rebuilt bytes are served even when they cannot be
/// stored; 503 only when they cannot be assembled.
async fn published_packument_response(
    state: &AppState,
    headers: &HeaderMap,
    name: &str,
    published: &std::collections::BTreeSet<String>,
    base: &str,
) -> Response {
    let key = published_packument_key(name);
    let respond = |data: Bytes| {
        packument_response(
            headers,
            rebase_hosted_tarballs(data, PUBLIC_BASE, name),
            base,
            None,
        )
    };
    let current = |data: &Bytes| listed_versions(data).as_ref() == Some(published);
    if let Ok(data) = state.storage.get(&key).await {
        if current(&data) && is_assembled_by_nora(&state.storage, &key, &data).await {
            state.metrics.record_cache_hit("npm");
            return respond(data);
        }
    }
    // LOCK-SAFE: tokio mutex, the one publish holds while it writes this package; a CI fleet
    // reading a stale packument rebuilds it once. Nothing else is locked under it.
    let lock = state.publish_lock(&key);
    let _guard = lock.lock().await;
    // A publish or a retention pass may have changed the versions while this read waited.
    let relisted = match published_state(&state.storage, name).await {
        Published::Yes(versions) => versions,
        _ => published.clone(),
    };
    let published = &relisted;
    let current = |data: &Bytes| listed_versions(data).as_ref() == Some(published);
    if let Ok(data) = state.storage.get(&key).await {
        if current(&data) && is_assembled_by_nora(&state.storage, &key, &data).await {
            state.metrics.record_cache_hit("npm");
            return respond(data);
        }
    }
    match assemble_packument(&state.storage, name).await {
        // A version whose document cannot be read would silently leave the packument, and every
        // read would rebuild it again: the package is unavailable until it is repaired, and says
        // which versions keep it so.
        Ok(bytes) if listed_versions(&bytes).as_ref() != Some(published) => {
            published_versions_unreadable(state, name, published, &bytes).await
        }
        Ok(bytes) => {
            PACKUMENT_REBUILT_TOTAL.with_label_values(&["npm"]).inc();
            tracing::info!(registry = "npm", package = %name, "Rebuilt packument from per-version keys");
            if let Err(e) = store_assembled_packument(&state.storage, name, &bytes).await {
                tracing::warn!(registry = "npm", package = %name, error = %e, "rebuilt packument not stored; served anyway");
            }
            state.metrics.record_cache_hit("npm");
            respond(Bytes::from(bytes))
        }
        Err(unassembled) => unassembled.response(name),
    }
}

/// The answer for a published package whose assembled packument `bytes` left out some of its
/// `published` versions: their documents could not be read. Each is read again and its failure
/// says why — 500 for a copy that fails its integrity check, else 503. The package is
/// unavailable until it is repaired, never served without the versions.
async fn published_versions_unreadable(
    state: &AppState,
    name: &str,
    published: &std::collections::BTreeSet<String>,
    bytes: &[u8],
) -> Response {
    let assembled = listed_versions(bytes).unwrap_or_default();
    let unreadable: Vec<&String> = published.difference(&assembled).collect();
    tracing::error!(
        registry = "npm",
        package = %name,
        versions = ?unreadable,
        "published versions cannot be read; packument not served"
    );
    let mut failure = None;
    for version in unreadable {
        let key = format!("npm/{name}/versions/{version}.json");
        match state.storage.get(&key).await {
            Err(e @ crate::storage::StorageError::IntegrityViolation) => {
                return crate::registry::local_copy_unreadable("npm", &key, &e);
            }
            Err(e) => failure = failure.or(Some((key, e))),
            Ok(_) => {}
        }
    }
    match failure {
        Some((key, e)) => crate::registry::local_copy_unreadable("npm", &key, &e),
        None => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

/// The manifest of one version of a published package, by version or by dist-tag, from its
/// own keys; 404 when neither names a published version. No upstream is asked. A tag or a
/// document the store cannot read is unavailable (503, 500 for a copy that fails its integrity
/// check), not absent.
async fn published_version_manifest(
    state: &AppState,
    name: &str,
    spec: &str,
    base: &str,
) -> Response {
    use crate::storage::StorageError;
    let tag_key = format!("npm/{name}/dist-tags/{spec}");
    let version = match state.storage.get(&tag_key).await {
        Ok(tagged) => String::from_utf8_lossy(&tagged).trim().to_string(),
        Err(StorageError::NotFound | StorageError::Validation(_)) => spec.to_string(),
        Err(e) => return crate::registry::local_copy_unreadable("npm", &tag_key, &e),
    };
    let key = format!("npm/{name}/versions/{version}.json");
    let doc = match state.storage.get(&key).await {
        Ok(doc) => doc,
        Err(StorageError::NotFound | StorageError::Validation(_)) => {
            return StatusCode::NOT_FOUND.into_response();
        }
        Err(e) => return crate::registry::local_copy_unreadable("npm", &key, &e),
    };
    // Stored with `PUBLIC_BASE` (or, published before it, an absolute URL): pointed at
    // the current `public_url` as the packument is.
    let doc = match serde_json::from_slice::<serde_json::Value>(&doc) {
        Ok(mut vd) => match rebase_tarball(&mut vd, &format!("{PUBLIC_BASE}/npm/{name}/-/")) {
            true => serde_json::to_vec(&vd).map(Bytes::from).unwrap_or(doc),
            false => doc,
        },
        Err(_) => doc,
    };
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        with_public_base(doc, base),
    )
        .into_response()
}

/// Rewrite an upstream document's tarball URLs to point at NORA, leaving out the versions whose
/// tarball lies outside the upstream. `None` for a version manifest whose tarball does: no version
/// NORA serves. A stored document names NORA by [`PUBLIC_BASE`].
fn rewrite_for_nora(
    state: &AppState,
    data: &[u8],
    proxy_url: &str,
    path: &str,
    links: Links,
) -> Option<Vec<u8>> {
    place_for_nora(state, data, proxy_url, path, links).map(|placed| placed.body)
}

/// [`rewrite_for_nora`], saying whether a version was left out.
fn place_for_nora(
    state: &AppState,
    data: &[u8],
    proxy_url: &str,
    path: &str,
    links: Links,
) -> Option<Placed> {
    let nora_base = nora_base_url(state);
    let package = match classify_metadata_path(path) {
        MetadataPath::Packument { name } | MetadataPath::VersionManifest { name, .. } => Some(name),
        MetadataPath::Other => None,
    };
    let nora_npm_base = format!("{}/npm", nora_base.trim_end_matches('/'));
    let mut placed = match place_document(data, &nora_base, proxy_url, package, links) {
        Ok(placed) => placed,
        Err(Unrewritable::OffUpstream) => return None,
        Err(Unrewritable::NotJson) => {
            tracing::warn!(path = %path, "npm metadata JSON parse failed, using byte-level URL rewrite");
            let upstream_trimmed = proxy_url.trim_end_matches('/');
            Placed {
                body: replace_upstream_bytes(data, upstream_trimmed, &nora_npm_base),
                left_out: false,
            }
        }
    };
    // Placed against the base served now, stored under `PUBLIC_BASE`: `with_public_base` puts
    // the base of the day back on every serve, so a `public_url` change strands no link.
    if matches!(links, Links::Stored) {
        placed.body = replace_upstream_bytes(
            &placed.body,
            &format!("{nora_npm_base}/"),
            &format!("{PUBLIC_BASE}/npm/"),
        );
    }
    Some(placed)
}

/// Whether every tarball link of a cached document is already on NORA, as NORA writes it. Only the
/// links are read (the rest is skipped unbuilt), so a cached document is placed again
/// ([`served_copy`]) only when it holds a link of another form (a relative one) or one past NORA,
/// cached by a release that kept it — or does not read as a packument or manifest at all.
fn links_on_nora(data: &[u8], nora_base: &str) -> bool {
    #[derive(serde::Deserialize)]
    struct Dist {
        tarball: Option<String>,
    }
    #[derive(serde::Deserialize)]
    struct Version {
        dist: Option<Dist>,
    }
    #[derive(serde::Deserialize)]
    struct Document {
        versions: Option<std::collections::HashMap<String, Version>>,
        dist: Option<Dist>,
    }
    let Ok(doc) = serde_json::from_slice::<Document>(data) else {
        return false;
    };
    let nora = format!("{}/npm/", nora_base.trim_end_matches('/'));
    let on_nora = |dist: &Option<Dist>| {
        dist.as_ref()
            .and_then(|d| d.tarball.as_deref())
            .is_none_or(|link| link.starts_with(&nora))
    };
    on_nora(&doc.dist) && doc.versions.iter().flatten().all(|(_, v)| on_nora(&v.dist))
}

/// What NORA serves of an upstream document it cached, on the current `public_url`: the document
/// itself when every tarball link in it is NORA's, else the document placed again, as a fresh one
/// is — the versions whose tarball lies outside the upstream left out. `None` for a version
/// manifest whose tarball does. The flag says whether the copy held such a link (cached by a
/// release that kept one).
fn served_copy(state: &AppState, path: &str, data: Bytes) -> (Option<Bytes>, bool) {
    let nora_base = nora_base_url(state);
    let data = with_public_base(data, &nora_base);
    if links_on_nora(&data, &nora_base) {
        return (Some(data), false);
    }
    let upstream = state
        .config
        .npm
        .route(path)
        .map(|u| u.url)
        .unwrap_or_default();
    match place_for_nora(state, &data, upstream, path, Links::Served) {
        Some(placed) => (Some(Bytes::from(placed.body)), placed.left_out),
        None => (None, true),
    }
}

/// The document an upstream serves for `path` and the client's `query`, for this request only:
/// nothing is cached. Used for metadata paths that are neither a packument nor a version
/// manifest. The query goes as the client sent it (#1148), unless it names a private package (ADR-8,
/// [`search_names_private`]).
async fn uncached_upstream_metadata(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
    name: &str,
    query: Option<&str>,
) -> Response {
    if let Some(response) = crate::curation::check_namespace_isolation(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Npm,
        name,
    ) {
        return response;
    }
    if query.is_some_and(|q| search_names_private(state, q)) {
        return audit_refused(
            StatusCode::UNPROCESSABLE_ENTITY,
            "this search names an internal package or a scope of a private upstream; \
             NORA does not send such names to the upstream",
        );
    }
    let Some(upstream) = state.config.npm.route(path) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let mut url = format!("{}/{}", upstream.url.trim_end_matches('/'), path);
    if let Some(query) = query {
        url.push('?');
        url.push_str(query);
    }
    match proxy_fetch(
        metadata_client(state, upstream.scoped),
        &url,
        Duration::from_secs(state.config.npm.proxy_timeout),
        upstream.auth,
        &state.circuit_breaker,
        BreakerScope::upstream(RegistryType::Npm, upstream.url),
    )
    .await
    {
        Ok(data) => match rewrite_for_nora(state, &data, upstream.url, path, Links::Served) {
            Some(rewritten) => {
                packument_response(headers, Bytes::from(rewritten), &nora_base_url(state), None)
            }
            None => StatusCode::NOT_FOUND.into_response(),
        },
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => proxy_error_response("npm", &url, &e),
    }
}

/// Whether a query names a package that must not reach the upstream: under a namespace filter
/// or a scope owned by a private upstream, a word of any value (`text=react @corp/x`,
/// `scope:corp`, `keywords:corp-x`) that is an internal name, or an owned scope. A value that
/// does not decode as UTF-8 cannot be checked and counts as naming one (fail closed). With no
/// filter and no owned scope, nothing is private.
fn search_names_private(state: &AppState, query: &str) -> bool {
    let engine = &state.curation().curation_engine;
    let owned: Vec<&str> = state.config.npm.owned_scopes().collect();
    if !crate::curation::namespace_filter_active(engine) && owned.is_empty() {
        return false;
    }
    let internal = |name: &str| {
        crate::curation::is_internal_namespace(engine, crate::curation::RegistryType::Npm, name)
    };
    let scope_is_private =
        |scope: &str| owned.contains(&scope) || internal(&format!("{scope}/x")) || internal(scope);
    query.split('&').any(|pair| {
        let value = pair
            .split_once('=')
            .map_or("", |(_, v)| v)
            .replace('+', " ");
        let Ok(value) = percent_encoding::percent_decode_str(&value).decode_utf8() else {
            return true;
        };
        value.split_whitespace().any(|word| {
            let (qualifier, term) = word.split_once(':').unwrap_or(("", word));
            if qualifier == "scope" {
                let scope = format!("@{}", term.trim_start_matches('@'));
                return scope_is_private(&scope);
            }
            let scope = if term.starts_with('@') {
                term.split('/').next()
            } else {
                None
            };
            internal(term) || scope.is_some_and(scope_is_private)
        })
    })
}

/// What a render of the proxied document at `path` depends on besides the document: the
/// form asked for, whether `min_release_age` filters it, the base it is served under and
/// the curation loaded (a reload swaps the snapshot, so its address names it; the render's
/// minute of life bounds a reused address). The memo key is this and the document's digest.
fn render_variant(state: &AppState, headers: &HeaderMap, path: &str, filtered: bool) -> String {
    let curation = state.curation();
    format!(
        "{path}\n{}\n{}{}\n{:p}\n",
        nora_base_url(state),
        u8::from(wants_install_v1(headers)),
        u8::from(filtered && curation.curation_engine.metadata_filter_active()),
        Arc::as_ptr(&*curation),
    )
}

/// What NORA serves of the proxied document `data` ([`served_copy`], then
/// [`packument_body`]), rendered once per document and `variant` and shared by concurrent
/// and repeated requests ([`crate::packument_memo`]), on the blocking pool: the parse of a
/// large packument is not run on a runtime worker (R4-P02). `pin` is the document's storage
/// pin when it was read from storage; without one the document is hashed here.
async fn shared_render(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
    hide: HideYoung<'_>,
    variant: &str,
    data: Bytes,
    pin: Option<String>,
) -> crate::packument_memo::Rendered {
    use crate::packument_memo::Rendered;
    let digest = match pin {
        Some(pin) => pin,
        // ponytail: every follower of a shared refetch hashes its copy; share the digest
        // with the fetch if a stampede on an expired packument shows up in CPU.
        None => {
            let data = data.clone();
            on_blocking_pool(move || hex::encode(sha2::Sha256::digest(&data))).await
        }
    };
    let name = hide.map(|(_, name)| name.to_string());
    let (state_, headers, path) = (state.clone(), headers.clone(), path.to_string());
    let render = move || {
        let curation = state_.curation();
        let hide = name
            .as_deref()
            .map(|name| (&curation.curation_engine, name));
        let (served, past_nora) = served_copy(&state_, &path, data);
        let base = nora_base_url(&state_);
        Rendered {
            body: served.map(|data| packument_body(&headers, data, &base, hide)),
            past_nora,
        }
    };
    state
        .packument_memo
        .render(&format!("{variant}{digest}"), || on_blocking_pool(render))
        .await
}

/// `work` run on the blocking pool; its panic is this task's.
async fn on_blocking_pool<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    match tokio::task::spawn_blocking(work).await {
        Ok(done) => done,
        Err(e) => std::panic::resume_unwind(e.into_panic()),
    }
}

/// The response for a rendered proxied document; 404 for one NORA does not serve.
fn rendered_response(rendered: crate::packument_memo::Rendered) -> Response {
    match rendered.body {
        Some(body) => packument_body_response(body),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// A packument or version manifest of a package NORA has not published: from its cache under
/// `npm/<name>/upstream/` (or, until that is written, what an older release cached),
/// revalidated after the metadata TTL, else fetched from the upstream and cached. `packument`
/// says whether the document is a packument: filtered by `min_release_age` (Q04), dated by
/// its `time` map, and its versions recorded in the first-seen ledger.
async fn upstream_metadata(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
    name: &str,
    cache_key: &str,
    packument: bool,
) -> Response {
    let internal = is_internal(state, name);
    let curation = state.curation();
    let hide = (packument && !internal).then_some((&curation.curation_engine, name));

    let legacy_key = legacy_cache_key(path);
    let variant = render_variant(state, headers, path, hide.is_some());
    let mut cached = None;
    for key in [cache_key, legacy_key.as_str()] {
        // #1055: in a scope owned by a private upstream, only what that owner delivered
        // may be served from cache.
        if !cached_copy_trusted(state, path, key, name, None).await {
            continue;
        }
        // R4-P02: a render kept for the copy with this pin is served without reading the
        // copy (39 MB for `vite`), hashing or parsing it again. Not for an internal name:
        // its copy is read, and fails closed, on every request.
        let pin = state.storage.pin(key).await;
        let kept = pin
            .as_deref()
            .filter(|_| !internal)
            .and_then(|pin| state.packument_memo.lookup(&format!("{variant}{pin}")));
        if let Some(kept) = kept {
            cached = Some((Ok(kept), key.to_string()));
            break;
        }
        // Single-flight: a CI fleet asking for one big packument at once reads it from
        // storage once, not once per client — 46 concurrent reads of a 39 MB `vite`
        // packument held ~1.8 GB (OOM 2026-10-23). Only a successful read is shared: on
        // any other outcome every caller reads, and answers, on its own as before.
        let shared = if packument && state.config.server.proxy_coalesce {
            let budget = crate::proxy_coalesce::follower_budget(state.config.npm.proxy_timeout);
            state
                .proxy_coalesce
                // Its own metrics label: `npm` counts followers spared an upstream fetch.
                .coalesced(
                    &format!("cache-read:{key}"),
                    "npm_cache",
                    budget,
                    || async {
                        match cache_read(
                            state.storage.get_verified(key).await,
                            "npm",
                            key,
                            internal,
                        ) {
                            Ok(Some(outcome)) => Some(verified_data(outcome)),
                            _ => None,
                        }
                    },
                )
                .await
        } else {
            None
        };
        if let Some(data) = shared {
            cached = Some((Err((data, pin)), key.to_string()));
            break;
        }
        // A store fault is a retryable 503, never a 404 nor a guess sent upstream; for an
        // internal name a copy failing its pin is a 500 (`cache_read`).
        match cache_read(state.storage.get_verified(key).await, "npm", key, internal) {
            Ok(Some(outcome)) => {
                cached = Some((Err((verified_data(outcome), pin)), key.to_string()));
                break;
            }
            Ok(None) => {}
            Err(resp) => return resp,
        }
    }

    if let Some((copy, from_key)) = cached {
        // A copy holding a link past NORA (cached by a release that kept one) is served placed
        // again, and refetched in full whatever its age: a 304 would keep it as it is.
        let rendered = match copy {
            Ok(kept) => kept,
            Err((data, pin)) => {
                shared_render(state, headers, path, hide, &variant, data, pin).await
            }
        };
        let past_nora = rendered.past_nora;
        let ttl = state.config.npm.metadata_ttl;
        let fresh = !past_nora
            && match state.storage.stat(&from_key).await {
                Some(meta) => {
                    crate::registry::fresh_within_ttl(&state.storage, &from_key, meta.modified, ttl)
                        .await
                }
                None => false,
            };
        // #68 namespace isolation: an internal-namespace package is never revalidated
        // upstream (dependency confusion); it is owned locally.
        if fresh || internal {
            return rendered_response(rendered);
        }
        // Single-flight: a CI fleet stampeding one expired packument revalidates it once (#595).
        let refetch = || async {
            refetch_metadata(
                state, path, name, cache_key, &from_key, packument, !past_nora,
            )
            .await
            .ok()
        };
        let refreshed = if state.config.server.proxy_coalesce {
            let budget = crate::proxy_coalesce::follower_budget(state.config.npm.proxy_timeout);
            state
                .proxy_coalesce
                .coalesced(cache_key, "npm", budget, refetch)
                .await
        } else {
            refetch().await
        };
        // Filtered on the fresh document, `time` included: the cached copy may predate
        // the version it brings (R2-16).
        if let Some(refreshed) = refreshed {
            return rendered_response(
                shared_render(state, headers, path, hide, &variant, refreshed, None).await,
            );
        }
        if state.config.npm.serve_stale {
            tracing::warn!(registry = "npm", path = %path, "npm upstream unavailable, serving stale metadata");
            // Degraded, but still the representation that was asked for: body and
            // Content-Type must agree here too.
            let Some((stale_body, stale_type)) = rendered.body else {
                return StatusCode::NOT_FOUND.into_response();
            };
            return (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, HeaderValue::from_static(stale_type)),
                    (header::VARY, HeaderValue::from_static("Accept")),
                    (
                        header::CACHE_CONTROL,
                        HeaderValue::from_static("public, max-age=0, must-revalidate"),
                    ),
                    (
                        axum::http::header::HeaderName::from_static("x-nora-stale"),
                        HeaderValue::from_static("true"),
                    ),
                ],
                stale_body,
            )
                .into_response();
        }
        return StatusCode::BAD_GATEWAY.into_response();
    }

    // --- Namespace isolation: an internal name is never proxied ---
    if let Some(response) = crate::curation::check_namespace_isolation(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Npm,
        name,
    ) {
        return response;
    }
    let Some(upstream) = state.config.npm.route(path) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let proxy_url = upstream.url;
    let url = format!("{}/{}", proxy_url.trim_end_matches('/'), path);
    let timeout = state.config.npm.proxy_timeout;
    let fetch = proxy_fetch_bytes(
        metadata_client(state, upstream.scoped),
        &url,
        Duration::from_secs(timeout),
        upstream.auth,
        &state.circuit_breaker,
        BreakerScope::upstream(RegistryType::Npm, upstream.url),
    );
    match proxy_fetch_shared(state, cache_key, "npm", timeout, fetch).await {
        Ok((data, fetched)) => {
            // A version manifest whose tarball lies outside the upstream: no version NORA serves.
            let Some(rewritten) = rewrite_for_nora(state, &data, proxy_url, path, Links::Stored)
            else {
                return StatusCode::NOT_FOUND.into_response();
            };
            let rewritten = Bytes::from(rewritten);
            // A concurrent request fetched these bytes and caches them.
            if fetched {
                if packument {
                    record_first_seen(state, cache_key, &rewritten, None).await;
                }
                // Awaited, not spawned: the tarball requests that follow date their
                // version from this document, and a write still in flight sent each of
                // them upstream for the packument again (R2-11, R2-40).
                // LOCK-SAFE: the package lock retention holds while it prunes this cache.
                let lock = state.publish_lock(&package_lock_key(name));
                let _guard = lock.lock().await;
                if let Err(e) = cache_upstream_document(
                    &state.storage,
                    name,
                    cache_key,
                    rewritten.clone(),
                    &origin_of(proxy_url),
                )
                .await
                {
                    tracing::warn!(key = %cache_key, error = ?e, "npm proxy: failed to cache metadata");
                }
            }
            // The copy cached keeps an upstream's link on its origin; the one served has it
            // on NORA.
            rendered_response(
                shared_render(state, headers, path, hide, &variant, rewritten, None).await,
            )
        }
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        // The upstream answered "no such package": a real 404.
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        // The upstream is down, slow, throttling or refusing us: a gateway failure, not a
        // missing package (#1055).
        Err(e) => proxy_error_response("npm", &url, &e),
    }
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

/// Refetch metadata from upstream, rewrite URLs, update cache. An error says why there is no
/// document: `NotFound` for one the upstream does not have or NORA does not serve, the
/// upstream's failure otherwise (a caller with a cached copy serves it stale). The document is
/// the stored form: NORA named by [`PUBLIC_BASE`].
///
/// `key` is the cache written; `seed_key` holds the copy being revalidated (`key`, or what an
/// older release cached), from which a missing first-seen ledger starts. `ledger` says whether
/// the document is a packument, whose versions the ledger records. `conditional` says whether the
/// cached copy may be kept on a 304: not one holding a link past NORA.
async fn refetch_metadata(
    state: &AppState,
    path: &str,
    name: &str,
    key: &str,
    seed_key: &str,
    ledger: bool,
    conditional: bool,
) -> Result<Bytes, ProxyError> {
    let upstream = state.config.npm.route(path).ok_or(ProxyError::NotFound)?;
    let proxy_url = upstream.url;
    let url = format!("{}/{}", proxy_url.trim_end_matches('/'), path);

    // Revalidate with a conditional request when enabled and we have stored
    // validators. Empty validators ⇒ no conditional headers ⇒ always a 200,
    // which is also how the first fetch captures validators for next time (#596).
    let validators = if state.config.npm.revalidate && conditional {
        read_validators(&state.storage, key)
            .await
            .unwrap_or_default()
    } else {
        Validators::default()
    };
    let had_validators = validators.is_some();

    match proxy_fetch_conditional(
        metadata_client(state, upstream.scoped),
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
            match state.storage.get(seed_key).await {
                Ok(cached) => {
                    crate::metrics::PROXY_UPSTREAM_304_TOTAL
                        .with_label_values(&["npm"])
                        .inc();
                    crate::metrics::PROXY_REVALIDATION_BYTES_SAVED_TOTAL
                        .with_label_values(&["npm"])
                        .inc_by(cached.len() as u64);
                    // The release ages are not in the cache's file time: before anything
                    // is written, the ledger takes over a cache from before it existed.
                    if ledger {
                        record_first_seen(state, key, &cached, Some(seed_key)).await;
                    }
                    // A body cached by an older rewriter (or an older release, at its old
                    // key) keeps its upstream tarball links through every 304: bring it to
                    // the current form, under the current key, once.
                    let cached =
                        upgrade_cached_packument(state, name, key, seed_key, cached, proxy_url)
                            .await;
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
                    Ok(cached)
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
                    Err(ProxyError::NotFound)
                }
            }
        }
        // New body — rewrite, cache it, then persist the fresh validators.
        Ok(Revalidation::Modified { body, validators }) => {
            // Published and upstream documents never share a key: whatever a publish did
            // meanwhile, this write lands under the upstream cache only. A version manifest
            // whose tarball is now outside the upstream is not cached.
            let rewritten = rewrite_for_nora(state, &body, proxy_url, path, Links::Stored)
                .map(Bytes::from)
                .ok_or(ProxyError::NotFound)?;
            // Before the cached copy is replaced: it may be the one a ledger starts from.
            if ledger {
                record_first_seen(state, key, &rewritten, Some(seed_key)).await;
            }
            // Awaited: the tarball requests that follow date their version from the
            // cached document (R2-16). Body first; the validator sidecar must never
            // advertise freshness for a body that isn't there (#596).
            // LOCK-SAFE: the package lock retention holds while it prunes this cache, held
            // through the validators; nothing else is locked under it.
            let lock = state.publish_lock(&package_lock_key(name));
            let _guard = lock.lock().await;
            match cache_upstream_document(
                &state.storage,
                name,
                key,
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

            Ok(rewritten)
        }
        // Upstream unavailable / error — fall back to the caller's serve_stale /
        // 502 path exactly as before.
        Err(e) => {
            if had_validators {
                crate::metrics::PROXY_REVALIDATION_ERRORS_TOTAL
                    .with_label_values(&["npm"])
                    .inc();
            }
            Err(e)
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

/// Why an npm tarball cannot be imported as a published version.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ImportedTarballError {
    #[error("{0} is not the key of an npm tarball")]
    NotATarball(String),
    #[error("the tarball holds no package.json")]
    NoManifest,
    #[error("reading the tarball: {0}")]
    Read(#[from] std::io::Error),
    #[error("package.json: {0}")]
    Manifest(#[from] serde_json::Error),
    #[error("package.json names {found}, the tarball's key {expected}")]
    Mismatch { found: String, expected: String },
}

/// The most bytes of `package.json` an imported tarball is read for.
const IMPORTED_MANIFEST_MAX: u64 = 16 * 1024 * 1024;

/// The package, version and file name an npm tarball key (`npm/<name>/tarballs/<file>`) names.
fn tarball_key_parts(tarball_key: &str) -> Option<(&str, String, &str)> {
    let (name, file) = tarball_key
        .strip_prefix("npm/")?
        .rsplit_once("/tarballs/")?;
    let version = crate::curation::parse_npm_tarball_version(name, file)?;
    Some((name, version, file))
}

/// The key of the version document that publishes the npm tarball at `tarball_key`.
pub(crate) fn imported_version_key(tarball_key: &str) -> Option<String> {
    let (name, version, _) = tarball_key_parts(tarball_key)?;
    Some(format!("npm/{name}/versions/{version}.json"))
}

/// Maestra: the `time` key of the version the npm tarball at `tarball_key` publishes, written
/// by the import as a publish writes it (C73).
pub(crate) fn imported_time_key(tarball_key: &str) -> Option<String> {
    let (name, version, _) = tarball_key_parts(tarball_key)?;
    Some(time_key(name, &version))
}

/// What an npm tarball imported from another registry publishes: the key of its version
/// document, and the document — the tarball's own `package.json` with the `dist` a publish
/// records: the tarball's URL at `public_base`, its SHA-1 (`shasum`) and SHA-512 (`integrity`).
/// The manifest must name the package and version the key does. Once the document is stored the
/// package is published: its packument is assembled from its own keys and never asked of an
/// upstream (see [`published_state`]).
pub(crate) fn imported_version_document(
    tarball_key: &str,
    tarball: impl std::io::Read,
    sha1_hex: &str,
    sha512: &[u8],
    public_base: &str,
) -> Result<(String, Vec<u8>), ImportedTarballError> {
    use std::io::Read;
    use std::path::Component;
    let (name, version, file) = tarball_key_parts(tarball_key)
        .ok_or_else(|| ImportedTarballError::NotATarball(tarball_key.to_string()))?;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(tarball));
    let mut manifest = None;
    for entry in archive.entries()? {
        let entry = entry?;
        // `npm pack` puts the manifest at `package/package.json`; older tarballs use another
        // top directory.
        let at_top = {
            let path = entry.path()?;
            let mut parts = path.components();
            matches!(
                (parts.next(), parts.next(), parts.next()),
                (Some(Component::Normal(_)), Some(Component::Normal(file)), None)
                    if file == "package.json"
            )
        };
        if at_top {
            let mut text = Vec::new();
            entry.take(IMPORTED_MANIFEST_MAX).read_to_end(&mut text)?;
            manifest = Some(serde_json::from_slice::<serde_json::Value>(&text)?);
            break;
        }
    }
    let mut doc = manifest.ok_or(ImportedTarballError::NoManifest)?;
    let found = format!(
        "{}@{}",
        doc.get("name").and_then(|v| v.as_str()).unwrap_or_default(),
        doc.get("version")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
    );
    let expected = format!("{name}@{version}");
    let Some(obj) = doc.as_object_mut().filter(|_| found == expected) else {
        return Err(ImportedTarballError::Mismatch { found, expected });
    };
    obj.insert("_id".to_string(), serde_json::Value::String(expected));
    obj.insert(
        "dist".to_string(),
        serde_json::json!({
            "tarball": format!("{}/npm/{name}/-/{file}", public_base.trim_end_matches('/')),
            "shasum": sha1_hex,
            "integrity": format!(
                "sha512-{}",
                base64::engine::general_purpose::STANDARD.encode(sha512)
            ),
        }),
    );
    Ok((
        format!("npm/{name}/versions/{version}.json"),
        serde_json::to_vec(&doc)?,
    ))
}

/// Why a publish's attachments were refused.
#[derive(Debug, thiserror::Error)]
enum AttachmentRefused {
    #[error("Invalid attachment filename")]
    InvalidName,
    #[error("attachment {0} is not the tarball of a version this publish carries")]
    NotThisPublish(String),
    #[error("Invalid base64 in attachment")]
    Base64(#[from] base64::DecodeError),
}

/// The file name a publish's attachment `filename` is stored under: the tarball
/// (`<name>-<version>.tgz`, the name with or without its scope) of one of the `versions` the
/// payload publishes. Anything else — another version's tarball, a key beside one, a path,
/// another scope's or another package's tarball — is refused.
fn tarball_of_this_publish<'a>(
    package_name: &str,
    filename: &'a str,
    versions: &serde_json::Map<String, serde_json::Value>,
) -> Result<&'a str, AttachmentRefused> {
    // A scoped package's attachment may carry its scope (`@scope/name-1.0.0.tgz`); without it
    // the name must be flat, with no path separator to traverse with.
    let (scope, short_name) = match package_name.split_once('/') {
        Some((scope, name)) => (Some(scope), name),
        None => (None, package_name),
    };
    let normalized_name = scope
        .and_then(|scope| filename.strip_prefix(scope)?.strip_prefix('/'))
        .unwrap_or(filename);
    if !is_valid_attachment_name(normalized_name) {
        return Err(AttachmentRefused::InvalidName);
    }
    if !versions
        .keys()
        .any(|version| normalized_name == format!("{short_name}-{version}.tgz"))
    {
        return Err(AttachmentRefused::NotThisPublish(
            normalized_name.to_string(),
        ));
    }
    Ok(normalized_name)
}

/// The tarballs a publish stores: each attachment decoded, under its tarball key. Every attachment,
/// with bytes or without, must be [`tarball_of_this_publish`]; one that is not refuses the whole
/// publish before anything is stored, so a publish cannot replace bytes clients installed or the
/// pin they are checked against.
fn publish_tarballs(
    package_name: &str,
    attachments: &serde_json::Map<String, serde_json::Value>,
    versions: &serde_json::Map<String, serde_json::Value>,
) -> Result<Vec<(String, Vec<u8>)>, AttachmentRefused> {
    let mut tarballs = Vec::with_capacity(attachments.len());
    for (filename, attachment) in attachments {
        let tarball = tarball_of_this_publish(package_name, filename, versions)?;
        let Some(data) = attachment.get("data").and_then(|d| d.as_str()) else {
            continue;
        };
        let bytes = base64::engine::general_purpose::STANDARD.decode(data)?;
        tarballs.push((format!("npm/{package_name}/tarballs/{tarball}"), bytes));
    }
    Ok(tarballs)
}

/// Whether `name` is a package name as npm writes one: `name` or `@scope/name`, of URL-safe
/// characters, 214 at most, no part starting with `.` and an unscoped name not with `_`
/// either. Upper case passes, as npm's rule for names published before it required lower case.
fn is_package_name(name: &str) -> bool {
    let part = |p: &str| {
        !p.is_empty()
            && !p.starts_with('.')
            && p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
    };
    if name.len() > 214 {
        return false;
    }
    match name.strip_prefix('@') {
        Some(scoped) => scoped
            .split_once('/')
            .is_some_and(|(scope, name)| part(scope) && part(name)),
        None => part(name) && !name.starts_with('_'),
    }
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
    // Every key of the package is built from this name: one that is not a package name
    // (`foo/versions`) would write under another package's keys.
    if !is_package_name(&package_name) {
        return (StatusCode::BAD_REQUEST, "Invalid package name").into_response();
    }

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

    let Some(new_versions) = payload.get("versions").and_then(|v| v.as_object()) else {
        return (StatusCode::BAD_REQUEST, "Missing versions").into_response();
    };
    // Every attachment, with bytes or without, is checked, and decoded, before anything is
    // stored: only the tarball of a version this publish carries. Stored by its file name
    // (the scope, already in the package name, stripped).
    let tarballs = match publish_tarballs(&package_name, attachments, new_versions) {
        Ok(tarballs) => tarballs
            .into_iter()
            .map(|(key, bytes)| {
                let file = key
                    .rsplit_once("/tarballs/")
                    .map_or(key.as_str(), |(_, f)| f);
                (file.to_string(), Bytes::from(bytes))
            })
            .collect::<Vec<_>>(),
        Err(refused) => {
            tracing::warn!(
                package = %package_name,
                reason = %refused,
                "SECURITY: npm publish rejected — attachment refused"
            );
            return (StatusCode::BAD_REQUEST, refused.to_string()).into_response();
        }
    };

    // Lock per package to serialize the packument regeneration within one process.
    let lock = state.publish_lock(&published_packument_key(&package_name));
    let _guard = lock.lock().await;
    let import_embedded = state.config.npm.import_embedded.contains(&package_name);
    if let Err(e) = publish_versions(
        &state.storage,
        &state.publish_locks,
        &package_name,
        &payload,
        tarballs,
        import_embedded,
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

/// The storage half of `npm publish`: refuse on a corrupt
/// packument or a version that exists or existed, then write the tarballs (attachment
/// name, bytes), each new version as its own key with its publish time, the dist-tags
/// and package fields of `payload`, regenerate the packument and check that it lists
/// the new versions; on a failure after the first write, undo them (R2-21). The
/// caller holds the package's publish lock.
///
/// `import_embedded`: the operator said a packument of unknown origin at the package's
/// key is its own (`npm.import_embedded`): its embedded versions are imported.
async fn publish_versions(
    storage: &crate::storage::Storage,
    locks: &crate::PublishLocks,
    package_name: &str,
    payload: &serde_json::Value,
    tarballs: Vec<(String, Bytes)>,
    import_embedded: bool,
) -> Result<(), (StatusCode, String)> {
    let new_versions = match payload.get("versions").and_then(|v| v.as_object()) {
        Some(v) => v,
        None => return Err((StatusCode::BAD_REQUEST, "Missing versions".to_string())),
    };
    let metadata_key = published_packument_key(package_name);

    // Read the existing packument ONCE — only to (a) refuse on corruption and (b) enforce version
    // immutability against versions still embedded in an un-migrated packument. The new versions
    // are NOT merged into it: each is written to its own immutable key and the packument is
    // regenerated by listing those keys, so concurrent publishers never read-modify-write the same
    // shared file (the multi-replica lost-update of #39).
    // A packument an upstream left at this key (an older release cached it there) is a
    // proxy cache, not local state: its versions are neither imported nor immutable here
    // (#27).
    let proxied = is_upstream_copy(storage, &metadata_key).await;
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

    // Any other packument on a package with no per-version keys (no record of where it came
    // from, or one written for other bytes) may be a package published to NORA 0.9.3 or older,
    // or an upstream one an older release cached: nothing tells them apart, and importing the
    // second would publish an upstream's versions. The publish is refused until the operator
    // says which it is.
    if existing_meta.is_some()
        && matches!(published_state(storage, package_name).await, Published::No)
        && !import_embedded
    {
        tracing::warn!(
            registry = "npm",
            package = %package_name,
            key = %metadata_key,
            "publish refused: packument of unknown origin"
        );
        return Err((
            StatusCode::CONFLICT,
            format!(
                "{metadata_key} holds a packument with no record of where it came from: an upstream package an older release cached, or a package published to NORA 0.9.3 or older. Publishing over it would import its versions as published ones. If it is a cache, delete {metadata_key} and publish again; if it is your own package, set NORA_NPM_IMPORT_EMBEDDED={package_name} and publish again."
            ),
        ));
    }

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
        // The packument is local now: drop the upstream validators of the copy it replaced
        // (its provenance record was replaced with the assembled one).
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
        if versions_left(storage, package_name).await {
            let _ = regenerate_packument(storage, package_name).await;
        } else {
            let _ = storage
                .delete(&format!("npm/{package_name}/pkg.json"))
                .await;
            let key = published_packument_key(package_name);
            let _ = storage.delete(&key).await;
            let _ = storage.delete(&origin_key(&key)).await;
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
    let metadata_key = published_packument_key(package_name);

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
                // The target the tag had, for the undo. Unreadable, it is unknown: an undo
                // could neither restore the tag nor tell it was new, so the publish fails
                // before moving it.
                let old = match storage.get(&tag_key).await {
                    Ok(target) => Some(target),
                    Err(
                        crate::storage::StorageError::NotFound
                        | crate::storage::StorageError::Validation(_),
                    ) => None,
                    Err(e) => {
                        tracing::error!(key = %tag_key, error = %e, "npm publish: failed to read dist-tag");
                        return Err(internal_error());
                    }
                };
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
    let lock = state.publish_lock(&published_packument_key(name));
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
    let lock = state.publish_lock(&published_packument_key(name));
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
    let remaining = versions_left(storage, name).await;
    let tags = match super::read_keyed_blobs(storage, &format!("npm/{name}/dist-tags/")).await {
        Ok(tags) => tags,
        Err((key, e)) => return super::local_copy_unreadable("npm", &key, &e),
    };
    for (tag_key, data) in tags {
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
        let key = published_packument_key(name);
        let _ = storage.delete(&origin_key(&key)).await;
        storage.delete(&key).await.is_ok()
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
    let lock = state.publish_lock(&published_packument_key(&name));
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
pub(crate) fn time_key(name: &str, ver: &str) -> String {
    format!("npm/{name}/time/{ver}")
}

/// Now, as npm writes `time` entries (`2024-01-15T10:30:00.000Z`).
pub(crate) fn npm_time_now() -> String {
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
    let lock = state.publish_lock(&published_packument_key(name));
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
    let lock = state.publish_lock(&published_packument_key(name));
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
    let bytes = match assemble_packument(storage, package_name).await {
        Ok(bytes) => bytes,
        Err(unassembled) => {
            tracing::error!(registry = "npm", package = %package_name, reason = %unassembled, "packument not regenerated");
            return Err(());
        }
    };
    store_assembled_packument(storage, package_name, &bytes)
        .await
        .map_err(|_| ())
}

/// Why a published package's packument could not be assembled.
#[derive(Debug, thiserror::Error)]
enum Unassembled {
    /// The store could not read this key (or list this prefix).
    #[error("{0} cannot be read: {1}")]
    Unreadable(String, crate::storage::StorageError),
    /// The package fields are not a JSON object.
    #[error("the package fields are not a JSON object")]
    Malformed,
    /// The assembled document could not be encoded.
    #[error("the packument cannot be encoded: {0}")]
    Encode(#[from] serde_json::Error),
}

impl Unassembled {
    /// The answer for a read that needed the packument: 503, 500 for a copy that fails its
    /// integrity check.
    fn response(&self, name: &str) -> Response {
        match self {
            Unassembled::Unreadable(key, e) => {
                crate::registry::local_copy_unreadable("npm", key, e)
            }
            Unassembled::Malformed | Unassembled::Encode(_) => {
                tracing::warn!(registry = "npm", package = %name, reason = %self, "published packument cannot be assembled");
                StatusCode::SERVICE_UNAVAILABLE.into_response()
            }
        }
    }
}

/// The packument of a published package, assembled from its published keys (`versions/`,
/// `dist-tags/`, `pkg.json`, `time/`). A key the store cannot read fails it: a document without
/// a tag or the package fields would be served, or stored, as complete.
async fn assemble_packument(
    storage: &crate::storage::Storage,
    package_name: &str,
) -> Result<Vec<u8>, Unassembled> {
    let unreadable = |(key, e)| Unassembled::Unreadable(key, e);
    // versions map, keyed by the filename (version) without the .json suffix. Read
    // concurrently: on an object store every version is a round-trip, and this path now
    // runs on a read (#956), so a package with thousands of versions used to pay them
    // one after another. An unparsable document is skipped; the reader that compares the
    // versions with the published ones refuses the packument.
    let versions_prefix = format!("npm/{}/versions/", package_name);
    // A version stored with an absolute tarball URL (published before PUBLIC_BASE)
    // follows `public_url` like the rest.
    let tarball_prefix = format!("{PUBLIC_BASE}/npm/{package_name}/-/");
    let mut versions = serde_json::Map::new();
    for (key, data) in super::read_keyed_blobs(storage, &versions_prefix)
        .await
        .map_err(unreadable)?
    {
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
    for (key, data) in super::read_keyed_blobs(storage, &dt_prefix)
        .await
        .map_err(unreadable)?
    {
        if let (Some(tag), Ok(ver)) = (key.rsplit('/').next(), String::from_utf8(data.to_vec())) {
            dist_tags.insert(tag.to_string(), serde_json::Value::String(ver));
        }
    }
    // Maestra: the fallback is the highest release, a prerelease only when there is none — an
    // import writes no tags, and a PR build must not become `latest` (C73).
    if !dist_tags.contains_key("latest") {
        let releases = versions.keys().filter(|v| !v.contains('-'));
        if let Some(latest) = max_semver(releases).or_else(|| max_semver(versions.keys())) {
            dist_tags.insert("latest".to_string(), serde_json::Value::String(latest));
        }
    }

    // Package-level fields + the assembled maps -> the packument.
    let pkg_key = format!("npm/{}/pkg.json", package_name);
    let mut packument = match storage.get(&pkg_key).await {
        Ok(d) => serde_json::from_slice(&d).unwrap_or_else(|_| serde_json::json!({})),
        Err(crate::storage::StorageError::NotFound) => serde_json::json!({}),
        Err(e) => return Err(Unassembled::Unreadable(pkg_key, e)),
    };
    let obj = packument.as_object_mut().ok_or(Unassembled::Malformed)?;
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
    for (key, data) in super::read_keyed_blobs(storage, &format!("npm/{package_name}/time/"))
        .await
        .map_err(unreadable)?
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

    Ok(serde_json::to_vec(&packument)?)
}

/// Why retention could not bring a packument back in line with storage.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PackumentReconcileError {
    #[error("storage: {0}")]
    Storage(#[from] crate::storage::StorageError),
    #[error("cached packument is not JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("cached packument is not a JSON object")]
    NotAnObject,
    #[error("regenerating the packument from published versions failed")]
    Regenerate,
}

/// Bring a package's packument back in line with storage after retention removed the
/// tarballs of `retired` versions. Runs under the package's packument `publish_lock`.
///
/// A package with published versions owns its packument (#975): it is reassembled from
/// `versions/`, as publish does. A proxied package has no `versions/` keys — its
/// packument is the cached upstream document, so it is edited instead of rebuilt:
/// regenerating it from `versions/` emptied it, and with the upstream unreachable the
/// surviving version could not be installed.
pub(crate) async fn reconcile_packument_after_retention(
    storage: &crate::storage::Storage,
    package_name: &str,
    retired: &std::collections::BTreeSet<String>,
) -> Result<(), PackumentReconcileError> {
    let published = storage
        .list(&format!("npm/{}/versions/", package_name))
        .await?;
    if published.is_empty() {
        prune_cached_packument(storage, package_name, retired).await
    } else {
        regenerate_packument(storage, package_name)
            .await
            .or(Err(PackumentReconcileError::Regenerate))
    }
}

/// Remove from a cached upstream packument the `retired` versions whose tarball is gone,
/// keeping every other version document as the upstream sent it.
///
/// Only what retention removed leaves the document: a version that was never fetched
/// through the proxy has no tarball here either, and that is a normal proxy cache, not
/// a retired version. A dist-tag left pointing at a removed version is dropped, and a
/// dropped `latest` is re-pointed at the highest version still advertised.
///
/// The upstream validators of the old document are cleared before it is replaced, so a
/// 304 cannot re-serve the edited copy as the upstream's. The provenance record is
/// carried over to the new bytes only when it vouched for the old ones.
async fn prune_cached_packument(
    storage: &crate::storage::Storage,
    package_name: &str,
    retired: &std::collections::BTreeSet<String>,
) -> Result<(), PackumentReconcileError> {
    // The upstream cache only: what an older release cached is never written (a rollback reads it).
    let key = upstream_packument_key(package_name);
    let old = match storage.get(&key).await {
        Ok(old) => old,
        // Nothing cached: the next read fetches the packument from the upstream.
        Err(crate::storage::StorageError::NotFound) => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let tarballs = storage
        .list(&format!("npm/{}/tarballs/", package_name))
        .await?;
    let on_disk: std::collections::BTreeSet<String> = tarballs
        .iter()
        .filter_map(|key| key.rsplit('/').next())
        .filter_map(|file| crate::curation::parse_npm_tarball_version(package_name, file))
        .collect();

    let mut packument: serde_json::Value = serde_json::from_slice(&old)?;
    let obj = packument
        .as_object_mut()
        .ok_or(PackumentReconcileError::NotAnObject)?;
    let Some(versions) = obj.get_mut("versions").and_then(|v| v.as_object_mut()) else {
        return Ok(());
    };
    let before = versions.len();
    versions.retain(|version, _| !retired.contains(version) || on_disk.contains(version));
    if versions.len() == before {
        return Ok(());
    }
    let remaining: Vec<String> = versions.keys().cloned().collect();
    if let Some(tags) = obj.get_mut("dist-tags").and_then(|t| t.as_object_mut()) {
        tags.retain(|_, version| {
            version
                .as_str()
                .is_some_and(|v| remaining.iter().any(|r| r == v))
        });
        if !tags.contains_key("latest") {
            if let Some(latest) = max_semver(remaining.iter()) {
                tags.insert("latest".to_string(), serde_json::Value::String(latest));
            }
        }
    }
    let bytes = serde_json::to_vec(&packument)?;

    let validators = super::validators_key(&key);
    match storage.delete(&validators).await {
        Ok(()) | Err(crate::storage::StorageError::NotFound) => {}
        Err(e) => return Err(e.into()),
    }
    storage.put(&key, &bytes).await?;

    let record_key = origin_key(&key);
    if let Ok(record) = storage.get(&record_key).await {
        let vouched_origin = std::str::from_utf8(&record)
            .ok()
            .and_then(|record| record.split_once('\n'))
            .filter(|(_, digest)| *digest == hex::encode(sha2::Sha256::digest(&old)))
            .map(|(origin, _)| origin.to_string());
        if let Some(origin) = vouched_origin {
            if let Err(e) = storage
                .put(&record_key, provenance_record(&origin, &bytes).as_bytes())
                .await
            {
                tracing::warn!(key = %key, error = ?e, "npm: failed to record cache provenance");
            }
        }
    }
    Ok(())
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

/// `npm/{name}/upstream/dates.json`: the `time` map (version → ISO 8601) of the cached
/// upstream packument, written with it. The tarball gates date a version from this, not
/// from a packument that runs to megabytes (R2-17), as PyPI does with its `dates.json`.
fn dates_key(name: &str) -> String {
    format!("npm/{name}/upstream/dates.json")
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

/// Cache an upstream document (already rewritten to [`PUBLIC_BASE`]) at `key`, under
/// `npm/<name>/upstream/`, with its provenance; the packument also with its
/// [`dates_key`] companion. A failed companion write only costs a read of the packument
/// later.
async fn cache_upstream_document(
    storage: &crate::Storage,
    name: &str,
    key: &str,
    data: Bytes,
    origin: &str,
) -> Result<(), crate::storage::StorageError> {
    let packument = key == upstream_packument_key(name);
    let times = packument.then(|| packument_times(&data));
    put_with_origin(storage, key, data, origin).await?;
    if let Some(times) = times {
        write_dates(storage, name, &times).await;
    }
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
    // A published package's dates are not an upstream's: nothing upstream is read or
    // cached for it.
    if has_local_versions(&state.storage, name).await {
        return None;
    }
    let key = upstream_packument_key(name);
    // #1055: inside a scope owned by a private upstream, only the owner's copy counts.
    if cached_copy_trusted(state, name, &key, name, None).await {
        if let Ok(dates) = state.storage.get(&dates_key(name)).await {
            if let Ok(times) = serde_json::from_slice(&dates) {
                return Some(times);
            }
        }
    }
    // Cached before the companion existed, or by an older release at its old key: the
    // companion is written once from it.
    for cached in [key.clone(), legacy_cache_key(name)] {
        if !cached_copy_trusted(state, name, &cached, name, None).await {
            continue;
        }
        if let Ok(data) = state.storage.get(&cached).await {
            let times = packument_times(&data);
            write_dates(&state.storage, name, &times).await;
            return Some(times);
        }
    }
    if crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Npm,
        name,
    ) {
        return None;
    }
    let upstream = state.config.npm.route(name)?;
    let proxy_url = upstream.url;
    let url = format!("{}/{}", proxy_url.trim_end_matches('/'), name);
    let timeout = state.config.npm.proxy_timeout;
    let fetch = proxy_fetch_bytes(
        metadata_client(state, upstream.scoped),
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
        if let Some(rewritten) = rewrite_for_nora(state, &data, proxy_url, name, Links::Stored) {
            // LOCK-SAFE: the package lock retention holds while it prunes this cache.
            let lock = state.publish_lock(&package_lock_key(name));
            let _guard = lock.lock().await;
            let _ = cache_upstream_document(
                &state.storage,
                name,
                &key,
                rewritten.into(),
                &origin_of(proxy_url),
            )
            .await;
        }
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

/// The bytes of a cache read that passed its gate, pinned or not.
fn verified_data(outcome: nora_registry::verified::GateOutcome) -> Bytes {
    use nora_registry::verified::{verified_body, GateOutcome};
    match outcome {
        GateOutcome::Verified(blob) => verified_body(blob),
        GateOutcome::Unpinned(blob) => blob.into_inner(),
    }
}

/// The part of a packument the abbreviated form and the Q04 filter read: the
/// [`INSTALL_V1_TOP_FIELDS`], `time`, and per version the [`INSTALL_V1_VERSION_FIELDS`].
/// Everything else (readme, per-version descriptions, scripts, maintainers) is skipped
/// while parsing, never built as a `Value`: a whole `vite` packument (39 MB) parsed into
/// a `Value` held ~120 MB per request, and ~300 concurrent installs OOMKilled a 4Gi pod
/// (2026-10-23). `None` when the body is not a JSON object, as a failed full parse.
fn install_v1_view(data: &[u8]) -> Option<serde_json::Value> {
    use serde::de::{DeserializeSeed, Deserializer, IgnoredAny, MapAccess, Visitor};
    use serde_json::{Map, Value};

    /// A version manifest cut to the install-v1 fields. A manifest that is not an
    /// object becomes `null`: `abbreviate_packument` skips it either way.
    struct Manifest;
    impl<'de> DeserializeSeed<'de> for Manifest {
        type Value = Value;
        fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
            d.deserialize_any(self)
        }
    }
    impl<'de> Visitor<'de> for Manifest {
        type Value = Value;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a version manifest")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
            let mut kept = Map::new();
            while let Some(key) = map.next_key::<String>()? {
                if INSTALL_V1_VERSION_FIELDS.contains(&key.as_str()) {
                    let value = map.next_value::<Value>()?;
                    kept.insert(key, value);
                } else {
                    map.next_value::<IgnoredAny>()?;
                }
            }
            Ok(Value::Object(kept))
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
            while seq.next_element::<IgnoredAny>()?.is_some() {}
            Ok(Value::Null)
        }
        fn visit_bool<E>(self, _: bool) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_i64<E>(self, _: i64) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_u64<E>(self, _: u64) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_f64<E>(self, _: f64) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_str<E>(self, _: &str) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_unit<E>(self) -> Result<Value, E> {
            Ok(Value::Null)
        }
    }

    /// `versions`: every version kept, each manifest cut by [`Manifest`]. Not an
    /// object: kept as parsed, `abbreviate_packument` ignores it as before.
    struct Versions;
    impl<'de> DeserializeSeed<'de> for Versions {
        type Value = Value;
        fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
            d.deserialize_any(self)
        }
    }
    impl<'de> Visitor<'de> for Versions {
        type Value = Value;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a versions map")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
            let mut versions = Map::new();
            while let Some(version) = map.next_key::<String>()? {
                let manifest = map.next_value_seed(Manifest)?;
                versions.insert(version, manifest);
            }
            Ok(Value::Object(versions))
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
            while seq.next_element::<IgnoredAny>()?.is_some() {}
            Ok(Value::Null)
        }
        fn visit_bool<E>(self, _: bool) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_i64<E>(self, _: i64) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_u64<E>(self, _: u64) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_f64<E>(self, _: f64) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_str<E>(self, _: &str) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_unit<E>(self) -> Result<Value, E> {
            Ok(Value::Null)
        }
    }

    struct Packument;
    impl<'de> Visitor<'de> for Packument {
        type Value = Value;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a packument object")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
            let mut out = Map::new();
            while let Some(key) = map.next_key::<String>()? {
                if key == "versions" {
                    let versions = map.next_value_seed(Versions)?;
                    out.insert(key, versions);
                } else if key == "time" || INSTALL_V1_TOP_FIELDS.contains(&key.as_str()) {
                    let value = map.next_value::<Value>()?;
                    out.insert(key, value);
                } else {
                    map.next_value::<IgnoredAny>()?;
                }
            }
            Ok(Value::Object(out))
        }
    }

    let mut de = serde_json::Deserializer::from_slice(data);
    let doc = de.deserialize_map(Packument).ok()?;
    de.end().ok()?;
    Some(doc)
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
    let parsed = if install_v1 {
        install_v1_view(&data)
    } else if hide.is_some() {
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
    packument_body_response(packument_body(headers, data, nora_base, hide))
}

fn packument_body_response((body, content_type): (Bytes, &'static str)) -> Response {
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

/// Rewrite tarball URLs in npm metadata to point to NORA ([`place_document`]): the body alone,
/// as the tests read it.
#[cfg(test)]
fn rewrite_tarball_urls(
    data: &[u8],
    nora_base: &str,
    upstream_url: &str,
) -> Result<Vec<u8>, Unrewritable> {
    let package = serde_json::from_slice::<serde_json::Value>(data)
        .ok()
        .and_then(|doc| doc.get("name")?.as_str().map(str::to_string));
    place_document(
        data,
        nora_base,
        upstream_url,
        package.as_deref(),
        Links::Served,
    )
    .map(|placed| placed.body)
}

/// Serve at `<server>/<package>` a packument listing each `(version, at)`, its tarball at
/// `<server>/<at>`: NORA downloads an upstream tarball only for a listed version.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) async fn mount_listing(
    server: &wiremock::MockServer,
    package: &str,
    files: &[(&str, &str)],
) {
    let versions: serde_json::Map<String, serde_json::Value> = files
        .iter()
        .map(|(version, at)| {
            let tarball = format!("{}/{at}", server.uri());
            (
                version.to_string(),
                serde_json::json!({"dist": {"tarball": tarball}}),
            )
        })
        .collect();
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(format!("/{package}")))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"name": package, "versions": versions})),
        )
        .with_priority(1)
        .mount(server)
        .await;
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests;

// ── Spec conformance tests (#390) ─────────────────────────────────────
//
// Invariant: after tarball URL rewriting, no upstream registry domains
// remain in the response. Uses golden fixtures from testdata/npm/.

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod spec_conformance_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod index_cost_tests;

#[cfg(test)]
mod origin_layout_tests;

/// npm multi-upstream with scope routing (#1055), on the real router: a private
/// upstream that only answers the exact Bearer token, and a public one that answers
/// anything — so a request that reached the wrong upstream would succeed and only
/// the request log on the public mock can catch it.
#[cfg(test)]
mod multi_upstream_tests;

/// An npm version is the version npm publishes it as: `semver.clean` drops white space, leading
/// `=` and `v`, and build metadata, so a rule or an allowlist entry holds however it spells its
/// version — `v1.3.0`, `=1.3.0` and `1.3.0+build` are `1.3.0`.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod npm_version_curation;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod release_age_first_seen;

/// Published and upstream metadata in separate keys: a published package's packument and
/// version manifests come from its own keys and never from an upstream, whatever its TTL,
/// whatever an older release left in the store; an unpublished package's are cached under
/// `upstream/` and never at the published key.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod published_and_upstream_keys;

/// Without trusted upstream dates the quarantine counts from NORA's own first fetch of an
/// artifact's bytes: metadata cached a month ago says when NORA last wrote it, not when it first
/// fetched this file, and its age would let a file first fetched now pass as mature. With trusted
/// dates the release date seeds it (#750), so an old release is not held as new to this mirror.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod quarantine_first_seen;

/// A publish stores the tarballs of the versions it publishes, and nothing else. An
/// attachment named for another version — one already published included — or for a key beside
/// a tarball would replace bytes clients already installed, and the pin NORA checks them against.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod publish_attachments;

/// A package published here is NORA's: its name is never an upstream's to answer for. A
/// tarball of it that NORA does not store is no version of it — the upstream is not asked, so a
/// squatter's bytes are neither served nor stored beside the published ones — and a bulk audit
/// does not hand its name to the upstream.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod published_names_stay_local;

/// A packument from an upstream may name its tarballs under the other scheme of the upstream's
/// own host (an https registry behind a TLS terminator writes `http://` links). Those links are the
/// upstream's too: left as they are, the client fetches the tarball past NORA.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod rewrite_both_schemes;

/// A cached tarball without a storage pin (stored before pins) whose `.sha256` sidecar the store
/// cannot read is not served unchecked; a pinned one was checked by its read and needs no
/// sidecar (R4-P07). NORA's
/// own copy (an internal or published package, or any package without an upstream) has nowhere
/// else to come from: unavailable (503), its bytes not sent. A proxied copy is fetched again and
/// checked as on its first download; an upstream that fails then answers as on a cache miss.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod unreadable_sidecar;

/// A version whose tarball an upstream document places outside that upstream (another host, or
/// a URL that only starts like the upstream's) is no version NORA serves: npm would download it
/// from there, past NORA. It is left out of the packument — `versions`, `time` and the tags — and
/// its manifest is not found; a tarball on the upstream under either scheme, on NORA or at a
/// relative path is served as before. No document NORA serves for an upstream package sends the
/// client anywhere but NORA, however it was cached.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod off_upstream_versions;

/// A tarball link on the upstream's own origin but outside its path — GitLab's instance-level
/// npm endpoint names each tarball under the project that holds it — is the upstream's: served on
/// NORA, and fetched by NORA from exactly that link with the upstream's credential. A link on any
/// other origin, another upstream's included, is left out and never asked.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod upstream_origin_tarballs;

/// A tarball is fetched only for a version the upstream's trusted packument lists, from the link
/// it names. A redirect on the upstream's origin is followed with the upstream's credential; one
/// to another origin (a registry keeping its files on a storage host) is followed without it, on
/// that hop and every later one. A version the packument does not list, even once fetched again,
/// is not asked for at all.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tarball_redirects;

/// An upstream bound to a scope answers that scope's metadata from its own origin only: a
/// redirect off it is not followed — 502, nothing asked of the other origin, nothing cached —
/// for a packument, a version manifest, any other metadata path and the packument a tarball
/// download reads. The default upstream follows redirects as before.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod scoped_metadata_origin;

/// `trust_upstream_dates` decides whose clock judges an upstream release: trusted, a direct
/// tarball download reads the date in the upstream's packument, which it caches first (#748) so
/// the date is there on the same request; untrusted, the date is NORA's own (when NORA cached
/// the packument), never the upstream's, and a download does not fetch the packument for a date.
/// Judged by the min-release-age verdict on the first download of a version.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod upstream_dates_gate;

/// R4-R03: a proxied tarball is the file its upstream's packument lists (`dist.integrity`'s
/// sha512, else `dist.shasum`), or it is neither served nor cached: 502, as an upstream that
/// failed. A cached packument older than the file is fetched again once before the refusal.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tarball_integrity;

/// R4-P02: a proxied packument is rendered once per stored document and form asked for, and the
/// render is kept for a minute: a repeated request is answered without reading the document
/// from storage, a changed document (another pin) is rendered again.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod shared_packument_render;

#[cfg(test)]
mod published_memo_tests;
