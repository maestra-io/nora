// Copyright (c) 2026 The Nora Authors
// SPDX-License-Identifier: MIT

//! Hosted NuGet feed (#983): `dotnet nuget push`, `dotnet nuget delete` (unlist) and
//! relist, served ahead of the nuget.org proxy from the same `/nuget/v3/index.json`.
//!
//!   PUT    /nuget/v3/package                 — push (multipart, first part = .nupkg)
//!   DELETE /nuget/v3/package/{id}/{version}  — unlist (blob kept, NuGet semantics)
//!   POST   /nuget/v3/package/{id}/{version}  — relist
//!
//! Storage:
//!   nuget/hosted/{id}/{ver}/{id}.{ver}.nupkg — package blob (immutable)
//!   nuget/hosted/{id}/{ver}/{id}.nuspec      — extracted manifest
//!   nuget/hosted-meta/{id}.json              — per-ID state, the single source for the
//!                                              flat-container version list, registration
//!                                              and search. Written last, under the
//!                                              per-ID publish lock, after the blobs.
//!
//! An ID with a hosted state document is owned by this feed: its metadata and downloads
//! are never proxied upstream (no dependency confusion through a public namesake).

use super::{is_valid_package_id, with_json, with_json_gzip};
use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::auth::{enforce_namespace_scope, AuthenticatedUser, NamespaceAuthority};
use crate::registry::nora_base_url;
use crate::registry_type::RegistryType;
use crate::storage::{Storage, StorageError};
use crate::validation::ends_with_ci;
use crate::AppState;
use axum::{
    extract::{Multipart, Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{post, put},
    Extension, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::cmp::Ordering;
use std::io::Read;

const META_PREFIX: &str = "nuget/hosted-meta/";
const BLOB_PREFIX: &str = "nuget/hosted/";
/// Registration leaves per page, and the count from which pages stop being inlined
/// (nuget.org's thresholds, learn.microsoft.com/nuget/api/registration-base-url-resource).
const PAGE_SIZE: usize = 64;
const INLINE_BELOW: usize = 128;
/// A .nuspec is a few KB; the cap stops a zip bomb disguised as one.
const MAX_NUSPEC_BYTES: u64 = 1024 * 1024;
const MAX_ID_LEN: usize = 100;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/nuget/v3/package", put(push))
        // The NuGet client PUTs to `{@id}/`, with the trailing slash.
        .route("/nuget/v3/package/", put(push))
        .route(
            "/nuget/v3/package/{id}/{version}",
            post(relist).delete(unlist),
        )
}

// ── State document ─────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Default, Debug)]
pub(super) struct HostedPackage {
    /// ID as first pushed (original case); lookups go through the lowercase key.
    id: String,
    /// Sorted ascending by NuGet version order.
    versions: Vec<HostedVersion>,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
struct HostedVersion {
    /// Normalized version, original case (no build metadata).
    version: String,
    listed: bool,
    published: String,
    /// SemVer 2.0.0-only version: hidden from search unless `semVerLevel=2.0.0`.
    semver2: bool,
    #[serde(default)]
    package_size: u64,
    #[serde(default)]
    authors: String,
    #[serde(default)]
    description: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    title: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    summary: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    tags: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    project_url: String,
    #[serde(default)]
    dependency_groups: Vec<DependencyGroup>,
}

/// Serialized as-is into the registration `catalogEntry.dependencyGroups`.
#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
struct DependencyGroup {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target_framework: Option<String>,
    #[serde(default)]
    dependencies: Vec<Dependency>,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
struct Dependency {
    id: String,
    /// The nuspec `version` attribute verbatim; NuGet's VersionRange parser reads both
    /// `1.0.0` (= `[1.0.0, )`) and interval notation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    range: Option<String>,
}

fn meta_key(id_lower: &str) -> String {
    format!("{META_PREFIX}{id_lower}.json")
}

/// `Ok(None)` = the ID is not hosted. `Err` = storage failure: callers must neither
/// proxy (the ID may be ours) nor overwrite (a rewrite would drop every version).
pub(super) async fn load(storage: &Storage, id_lower: &str) -> Result<Option<HostedPackage>, ()> {
    match storage.get(&meta_key(id_lower)).await {
        Ok(data) => serde_json::from_slice(&data).map(Some).map_err(|e| {
            tracing::error!(id = %id_lower, error = %e, "nuget hosted: state document unparsable");
        }),
        Err(StorageError::NotFound) => Ok(None),
        Err(e) => {
            tracing::error!(id = %id_lower, error = %e, "nuget hosted: state document unreadable");
            Err(())
        }
    }
}

fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "hosted package state unavailable",
    )
        .into_response()
}

// ── Push / unlist / relist ─────────────────────────────────────────────

async fn push(
    State(state): State<AppState>,
    Extension(authority): Extension<NamespaceAuthority>,
    user: Option<Extension<AuthenticatedUser>>,
    mut multipart: Multipart,
) -> Response {
    // Per the protocol the first part is the package; names and later parts are ignored.
    let data = match multipart.next_field().await {
        Ok(Some(field)) => match field.bytes().await {
            Ok(b) => b,
            Err(e) => return bad_request(format!("failed to read package: {e}")),
        },
        _ => return bad_request("expected multipart/form-data with the .nupkg as the first part"),
    };

    let spec = match parse_nupkg(&data) {
        Ok(s) => s,
        Err(e) => return bad_request(e),
    };
    if spec
        .package_types
        .iter()
        .any(|t| t.eq_ignore_ascii_case("SymbolsPackage"))
    {
        return bad_request(
            "symbol packages (.snupkg) are not accepted by this feed; push the .nupkg only",
        );
    }
    let id_lower = spec.id.to_lowercase();
    if spec.id.len() > MAX_ID_LEN || !is_valid_package_id(&id_lower) {
        return bad_request(format!("invalid package id '{}'", spec.id));
    }
    let Some((version, semver2)) = normalize_version(&spec.version) else {
        return bad_request(format!("invalid package version '{}'", spec.version));
    };
    if enforce_namespace_scope(&authority, &id_lower).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }

    let ver_lower = version.to_lowercase();
    let key = meta_key(&id_lower);
    let lock = state.publish_lock(&key);
    let _guard = lock.lock().await;

    let mut pkg = match load(&state.storage, &id_lower).await {
        Ok(p) => p.unwrap_or_default(),
        Err(()) => return unavailable(),
    };
    if pkg
        .versions
        .iter()
        .any(|v| v.version.eq_ignore_ascii_case(&version))
    {
        return (
            StatusCode::CONFLICT,
            format!("{} {} already exists", pkg_id(&pkg, &spec.id), version),
        )
            .into_response();
    }

    // Blobs first, state document last: the index never names a blob that is not
    // durable. A failure in between leaves an unreferenced blob a retry overwrites.
    let dir = format!("{BLOB_PREFIX}{id_lower}/{ver_lower}");
    if let Err(e) = state
        .storage
        .put(&format!("{dir}/{id_lower}.{ver_lower}.nupkg"), &data)
        .await
    {
        tracing::error!(error = %e, "nuget hosted: failed to store nupkg");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if let Err(e) = state
        .storage
        .put(&format!("{dir}/{id_lower}.nuspec"), spec.raw.as_bytes())
        .await
    {
        tracing::error!(error = %e, "nuget hosted: failed to store nuspec");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    if pkg.id.is_empty() {
        pkg.id = spec.id.clone();
    }
    pkg.versions.push(HostedVersion {
        version: version.clone(),
        listed: true,
        published: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        semver2,
        package_size: data.len() as u64,
        authors: spec.authors,
        description: spec.description,
        title: spec.title,
        summary: spec.summary,
        tags: spec.tags,
        project_url: spec.project_url,
        dependency_groups: spec.dependency_groups,
    });
    pkg.versions
        .sort_by(|a, b| compare_versions(&a.version, &b.version));
    if let Err(resp) = save(&state.storage, &key, &pkg).await {
        return resp;
    }

    let artifact = format!("{}@{}", pkg.id, version);
    state.metrics.record_upload("nuget");
    state.audit.log(AuditEntry::new(
        "push",
        crate::auth::audit_actor(&user),
        &artifact,
        "nuget",
        "",
    ));
    state.activity.push(ActivityEntry::new(
        ActionType::Push,
        artifact,
        RegistryType::Nuget,
        "LOCAL",
    ));
    StatusCode::CREATED.into_response()
}

async fn unlist(
    state: State<AppState>,
    authority: Extension<NamespaceAuthority>,
    user: Option<Extension<AuthenticatedUser>>,
    path: Path<(String, String)>,
) -> Response {
    set_listed(state, authority, user, path, false).await
}

async fn relist(
    state: State<AppState>,
    authority: Extension<NamespaceAuthority>,
    user: Option<Extension<AuthenticatedUser>>,
    path: Path<(String, String)>,
) -> Response {
    set_listed(state, authority, user, path, true).await
}

async fn set_listed(
    State(state): State<AppState>,
    Extension(authority): Extension<NamespaceAuthority>,
    user: Option<Extension<AuthenticatedUser>>,
    Path((id, raw_version)): Path<(String, String)>,
    listed: bool,
) -> Response {
    let id_lower = id.to_lowercase();
    if !is_valid_package_id(&id_lower) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Some((version, _)) = normalize_version(&raw_version) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if enforce_namespace_scope(&authority, &id_lower).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }

    let key = meta_key(&id_lower);
    let lock = state.publish_lock(&key);
    let _guard = lock.lock().await;
    let mut pkg = match load(&state.storage, &id_lower).await {
        Ok(Some(p)) => p,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(()) => return unavailable(),
    };
    let Some(entry) = pkg
        .versions
        .iter_mut()
        .find(|v| v.version.eq_ignore_ascii_case(&version))
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    entry.listed = listed;
    if let Err(resp) = save(&state.storage, &key, &pkg).await {
        return resp;
    }

    let action = if listed { "relist" } else { "unlist" };
    state.audit.log(AuditEntry::new(
        action,
        crate::auth::audit_actor(&user),
        &format!("{}@{}", pkg.id, version),
        "nuget",
        "",
    ));
    // Protocol: delete (= unlist) answers 204, relist answers 200.
    if listed {
        StatusCode::OK.into_response()
    } else {
        StatusCode::NO_CONTENT.into_response()
    }
}

async fn save(storage: &Storage, key: &str, pkg: &HostedPackage) -> Result<(), Response> {
    let body =
        serde_json::to_vec(pkg).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
    // Local backend: temp file + rename; S3: single-object PUT — both atomic.
    storage.put(key, &body).await.map_err(|e| {
        tracing::error!(key = %key, error = %e, "nuget hosted: failed to write state document");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })
}

fn pkg_id<'a>(pkg: &'a HostedPackage, fallback: &'a str) -> &'a str {
    if pkg.id.is_empty() {
        fallback
    } else {
        &pkg.id
    }
}

fn bad_request(msg: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, msg.into()).into_response()
}

// ── Read hooks (called by the proxy handlers before they go upstream) ──

/// Flat-container `{id}/index.json`: every version, unlisted included (as nuget.org).
pub(super) async fn version_list(state: &AppState, id_lower: &str) -> Option<Response> {
    match load(&state.storage, id_lower).await {
        Ok(Some(pkg)) => {
            let versions: Vec<String> = pkg
                .versions
                .iter()
                .map(|v| v.version.to_lowercase())
                .collect();
            Some(with_json(
                json!({ "versions": versions }).to_string().into_bytes(),
            ))
        }
        Ok(None) => None,
        Err(()) => Some(unavailable()),
    }
}

pub(super) async fn registration_index(state: &AppState, id_lower: &str) -> Option<Response> {
    match load(&state.storage, id_lower).await {
        Ok(Some(pkg)) => {
            let body = build_registration_index(&pkg, &nuget_base(state));
            Some(with_json_gzip(body.to_string().into_bytes()))
        }
        Ok(None) => None,
        Err(()) => Some(unavailable()),
    }
}

pub(super) async fn registration_page(
    state: &AppState,
    id_lower: &str,
    lower: &str,
    upper: &str,
) -> Option<Response> {
    match load(&state.storage, id_lower).await {
        Ok(Some(pkg)) => Some(
            match build_registration_page(&pkg, &nuget_base(state), lower, upper) {
                Some(body) => with_json_gzip(body.to_string().into_bytes()),
                None => StatusCode::NOT_FOUND.into_response(),
            },
        ),
        Ok(None) => None,
        Err(()) => Some(unavailable()),
    }
}

/// `.nupkg` / `.nuspec` download. `path` is the flat-container path below the base.
pub(super) async fn download(state: &AppState, path: &str, id_lower: &str) -> Option<Response> {
    let key = format!("{BLOB_PREFIX}{}", path.to_lowercase());
    match state.storage.get(&key).await {
        Ok(data) => {
            let content_type = if ends_with_ci(path, ".nuspec") {
                "application/xml"
            } else {
                "application/octet-stream"
            };
            state.metrics.record_download("nuget");
            Some(
                (
                    StatusCode::OK,
                    [
                        (header::CONTENT_TYPE, content_type),
                        (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
                    ],
                    data,
                )
                    .into_response(),
            )
        }
        // A hosted ID never falls through to the upstream, even for a version it lacks.
        Err(StorageError::NotFound) => match load(&state.storage, id_lower).await {
            Ok(Some(_)) => Some(StatusCode::NOT_FOUND.into_response()),
            Ok(None) => None,
            Err(()) => Some(unavailable()),
        },
        Err(e) => {
            tracing::error!(key = %key, error = %e, "nuget hosted: blob unreadable");
            Some(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

fn nuget_base(state: &AppState) -> String {
    format!("{}/nuget", nora_base_url(state).trim_end_matches('/'))
}

// ── Registration documents ─────────────────────────────────────────────

fn registration_url(nuget: &str, id_lower: &str) -> String {
    format!("{nuget}/v3/registration/{id_lower}/index.json")
}

fn leaf(pkg: &HostedPackage, v: &HostedVersion, nuget: &str) -> Value {
    let id_lower = pkg.id.to_lowercase();
    let ver_lower = v.version.to_lowercase();
    let leaf_url = format!("{nuget}/v3/registration/{id_lower}/{ver_lower}.json");
    let content =
        format!("{nuget}/v3/flatcontainer/{id_lower}/{ver_lower}/{id_lower}.{ver_lower}.nupkg");
    let mut entry = json!({
        "@id": format!("{leaf_url}#catalogEntry"),
        "@type": "PackageDetails",
        "id": pkg.id,
        "version": v.version,
        "authors": v.authors,
        "description": v.description,
        "listed": v.listed,
        "published": v.published,
        "packageContent": content,
        "dependencyGroups": v.dependency_groups,
        "tags": v.tags.split_whitespace().collect::<Vec<_>>(),
    });
    for (field, value) in [
        ("title", &v.title),
        ("summary", &v.summary),
        ("projectUrl", &v.project_url),
    ] {
        if !value.is_empty() {
            entry[field] = json!(value);
        }
    }
    json!({
        "@id": leaf_url,
        "@type": "Package",
        "catalogEntry": entry,
        "packageContent": content,
        "registration": registration_url(nuget, &id_lower),
    })
}

fn page_bounds(chunk: &[HostedVersion]) -> (String, String) {
    let lower = chunk
        .first()
        .map(|v| v.version.to_lowercase())
        .unwrap_or_default();
    let upper = chunk
        .last()
        .map(|v| v.version.to_lowercase())
        .unwrap_or_default();
    (lower, upper)
}

fn page_url(nuget: &str, id_lower: &str, lower: &str, upper: &str) -> String {
    format!("{nuget}/v3/registration/{id_lower}/page/{lower}/{upper}.json")
}

fn build_registration_index(pkg: &HostedPackage, nuget: &str) -> Value {
    let id_lower = pkg.id.to_lowercase();
    let index_url = registration_url(nuget, &id_lower);
    let inline = pkg.versions.len() < INLINE_BELOW;
    let pages: Vec<Value> = pkg
        .versions
        .chunks(PAGE_SIZE)
        .map(|chunk| {
            let (lower, upper) = page_bounds(chunk);
            if inline {
                json!({
                    "@id": format!("{index_url}#page/{lower}/{upper}"),
                    "count": chunk.len(),
                    "lower": lower,
                    "upper": upper,
                    "parent": index_url,
                    "items": chunk.iter().map(|v| leaf(pkg, v, nuget)).collect::<Vec<_>>(),
                })
            } else {
                json!({
                    "@id": page_url(nuget, &id_lower, &lower, &upper),
                    "count": chunk.len(),
                    "lower": lower,
                    "upper": upper,
                })
            }
        })
        .collect();
    json!({ "@id": index_url, "count": pages.len(), "items": pages })
}

fn build_registration_page(
    pkg: &HostedPackage,
    nuget: &str,
    lower: &str,
    upper: &str,
) -> Option<Value> {
    let id_lower = pkg.id.to_lowercase();
    let chunk = pkg.versions.chunks(PAGE_SIZE).find(|chunk| {
        let (l, u) = page_bounds(chunk);
        l.eq_ignore_ascii_case(lower) && u.eq_ignore_ascii_case(upper)
    })?;
    let (l, u) = page_bounds(chunk);
    Some(json!({
        "@id": page_url(nuget, &id_lower, &l, &u),
        "count": chunk.len(),
        "lower": l,
        "upper": u,
        "parent": registration_url(nuget, &id_lower),
        "items": chunk.iter().map(|v| leaf(pkg, v, nuget)).collect::<Vec<_>>(),
    }))
}

// ── Search ─────────────────────────────────────────────────────────────

/// Search results for hosted packages: listed versions only, matched on the ID.
/// Every whitespace-separated term (an `id:`/`packageid:` prefix is accepted) must be
/// a substring of the ID.
// ponytail: one list of nuget/hosted-meta/ + one read per matching ID per query; fine for
// hundreds of IDs, cache the docs in memory if search traffic or ID count grows.
pub(super) async fn search(
    state: &AppState,
    q: &str,
    prerelease: bool,
    semver2: bool,
) -> Vec<Value> {
    let terms: Vec<String> = q
        .split_whitespace()
        .map(|t| {
            let t = t.to_lowercase();
            ["packageid:", "id:"]
                .iter()
                .find_map(|p| t.strip_prefix(p).map(str::to_string))
                .unwrap_or(t)
        })
        .collect();
    let keys = match state.storage.list(META_PREFIX).await {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(error = %e, "nuget hosted: search listing failed");
            return Vec::new();
        }
    };
    let nuget = nuget_base(state);
    let mut out = Vec::new();
    for key in keys {
        let Some(id_lower) = key
            .strip_prefix(META_PREFIX)
            .and_then(|k| k.strip_suffix(".json"))
        else {
            continue;
        };
        if !terms.iter().all(|t| id_lower.contains(t.as_str())) {
            continue;
        }
        let Ok(Some(pkg)) = load(&state.storage, id_lower).await else {
            continue;
        };
        let visible: Vec<&HostedVersion> = pkg
            .versions
            .iter()
            .filter(|v| {
                v.listed && (prerelease || !v.version.contains('-')) && (semver2 || !v.semver2)
            })
            .collect();
        let Some(latest) = visible.last() else {
            continue;
        };
        let versions: Vec<Value> = visible
            .iter()
            .map(|v| {
                json!({
                    "version": v.version,
                    "downloads": 0,
                    "@id": format!("{nuget}/v3/registration/{id_lower}/{}.json", v.version.to_lowercase()),
                })
            })
            .collect();
        out.push(json!({
            "@id": registration_url(&nuget, id_lower),
            "@type": "Package",
            "registration": registration_url(&nuget, id_lower),
            "id": pkg.id,
            "version": latest.version,
            "description": latest.description,
            "summary": latest.summary,
            "title": latest.title,
            "authors": [latest.authors],
            "tags": latest.tags.split_whitespace().collect::<Vec<_>>(),
            "projectUrl": latest.project_url,
            "totalDownloads": 0,
            "verified": false,
            "packageTypes": [{ "name": "Dependency" }],
            "versions": versions,
        }));
    }
    out
}

/// Put hosted hits in front of a search/autocomplete body from the proxy or local cache.
/// Hosted IDs replace any upstream entry with the same ID. `names` = autocomplete shape.
// ponytail: hosted hits only on the first page (skip == 0) and the page is cut back to
// `take`, so deep paging over a mixed result is approximate; exact for hosted-only feeds.
pub(super) fn merge_search(
    hosted: &[Value],
    body: Vec<u8>,
    skip: usize,
    take: usize,
    names: bool,
) -> Vec<u8> {
    if hosted.is_empty() {
        return body;
    }
    let Ok(mut doc) = serde_json::from_slice::<Value>(&body) else {
        return body;
    };
    let hosted_ids: Vec<String> = hosted
        .iter()
        .filter_map(|h| h["id"].as_str().map(str::to_lowercase))
        .collect();
    let entry_id = |e: &Value| {
        e.as_str()
            .or_else(|| e["id"].as_str())
            .map(str::to_lowercase)
    };
    let upstream: Vec<Value> = doc["data"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|e| !entry_id(e).is_some_and(|id| hosted_ids.contains(&id)))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    let dropped = doc["data"].as_array().map_or(0, |a| a.len()) - upstream.len();
    let mut data: Vec<Value> = if skip == 0 {
        hosted
            .iter()
            .map(|h| if names { h["id"].clone() } else { h.clone() })
            .collect()
    } else {
        Vec::new()
    };
    data.extend(upstream);
    data.truncate(take);
    let upstream_total = doc["totalHits"].as_u64().unwrap_or(0) as usize;
    doc["totalHits"] = json!(upstream_total.saturating_sub(dropped) + hosted.len());
    doc["data"] = Value::Array(data);
    serde_json::to_vec(&doc).unwrap_or(body)
}

// ── .nupkg / .nuspec parsing ───────────────────────────────────────────

#[derive(Debug, Default, PartialEq)]
struct Nuspec {
    id: String,
    version: String,
    authors: String,
    description: String,
    title: String,
    summary: String,
    tags: String,
    project_url: String,
    dependency_groups: Vec<DependencyGroup>,
    package_types: Vec<String>,
    raw: String,
}

/// Read the single root-level `.nuspec` out of a `.nupkg` (a zip) and parse it.
fn parse_nupkg(data: &[u8]) -> Result<Nuspec, String> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(data))
        .map_err(|e| format!("package is not a valid zip archive: {e}"))?;
    let names: Vec<String> = zip
        .file_names()
        .filter(|n| !n.contains('/') && ends_with_ci(n, ".nuspec"))
        .map(str::to_string)
        .collect();
    let [name] = names.as_slice() else {
        return Err(format!(
            "package must contain exactly one .nuspec at its root, found {}",
            names.len()
        ));
    };
    let entry = zip
        .by_name(name)
        .map_err(|e| format!("cannot read {name}: {e}"))?;
    let mut raw = String::new();
    entry
        .take(MAX_NUSPEC_BYTES + 1)
        .read_to_string(&mut raw)
        .map_err(|e| format!("cannot read {name}: {e}"))?;
    if raw.len() as u64 > MAX_NUSPEC_BYTES {
        return Err(format!("{name} exceeds {MAX_NUSPEC_BYTES} bytes"));
    }
    let mut spec = parse_nuspec(&raw)?;
    spec.raw = raw;
    Ok(spec)
}

fn parse_nuspec(xml: &str) -> Result<Nuspec, String> {
    use quick_xml::{events::Event, Reader};

    let attr = |e: &quick_xml::events::BytesStart, name: &str| -> Option<String> {
        e.try_get_attribute(name)
            .ok()
            .flatten()
            .and_then(|a| {
                a.normalized_value(quick_xml::XmlVersion::Implicit1_0)
                    .ok()
                    .map(|v| v.trim().to_string())
            })
            .filter(|v| !v.is_empty())
    };

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut spec = Nuspec::default();
    // Element path below the document root, local names only (the nuspec namespace
    // changed across schema versions).
    let mut path: Vec<String> = Vec::new();
    loop {
        let event = reader
            .read_event()
            .map_err(|e| format!("invalid nuspec XML: {e}"))?;
        let (start, empty) = match &event {
            Event::Start(e) => (e.clone(), false),
            Event::Empty(e) => (e.clone(), true),
            Event::End(_) => {
                path.pop();
                continue;
            }
            Event::Eof => break,
            _ => continue,
        };
        let name = String::from_utf8_lossy(start.local_name().as_ref()).into_owned();
        let parent: Vec<&str> = path.iter().map(String::as_str).collect();
        match (parent.as_slice(), name.as_str()) {
            (["package", "metadata"], field)
                if !empty
                    && matches!(
                        field,
                        "id" | "version"
                            | "authors"
                            | "description"
                            | "title"
                            | "summary"
                            | "tags"
                            | "projectUrl"
                    ) =>
            {
                let text = read_field_text(&mut reader, field)?;
                let slot = match field {
                    "id" => &mut spec.id,
                    "version" => &mut spec.version,
                    "authors" => &mut spec.authors,
                    "description" => &mut spec.description,
                    "title" => &mut spec.title,
                    "summary" => &mut spec.summary,
                    "tags" => &mut spec.tags,
                    _ => &mut spec.project_url,
                };
                *slot = text;
                continue; // read_field_text consumed the end tag
            }
            (["package", "metadata", "dependencies"], "group") => {
                spec.dependency_groups.push(DependencyGroup {
                    target_framework: attr(&start, "targetFramework"),
                    dependencies: Vec::new(),
                });
            }
            (["package", "metadata", "dependencies", ..], "dependency") => {
                let Some(id) = attr(&start, "id") else {
                    return Err("nuspec <dependency> without id".to_string());
                };
                let dep = Dependency {
                    id,
                    range: attr(&start, "version"),
                };
                let in_group = parent.len() == 4;
                // A flat <dependencies> list is one group without a target framework.
                if !in_group
                    && spec
                        .dependency_groups
                        .last()
                        .is_none_or(|g| g.target_framework.is_some())
                {
                    spec.dependency_groups.push(DependencyGroup::default());
                }
                if let Some(group) = spec.dependency_groups.last_mut() {
                    group.dependencies.push(dep);
                }
            }
            (["package", "metadata", "packageTypes"], "packageType") => {
                if let Some(t) = attr(&start, "name") {
                    spec.package_types.push(t);
                }
            }
            _ => {}
        }
        if !empty {
            path.push(name);
        }
    }
    if spec.id.is_empty() || spec.version.is_empty() {
        return Err("nuspec must declare <id> and <version>".to_string());
    }
    Ok(spec)
}

/// Text of a leaf element up to its end tag: text, entity and character references,
/// and CDATA sections (taken verbatim) concatenated, then trimmed. Trimming is off while
/// reading so the spaces around an entity (`A &amp; B`) survive.
fn read_field_text(reader: &mut quick_xml::Reader<&[u8]>, field: &str) -> Result<String, String> {
    use quick_xml::events::Event;

    let bad = |e: &dyn std::fmt::Display| format!("invalid nuspec <{field}>: {e}");
    reader.config_mut().trim_text(false);
    let mut text = String::new();
    let mut depth = 0usize;
    let result = loop {
        let event = match reader.read_event() {
            Ok(e) => e,
            Err(e) => break Err(bad(&e)),
        };
        match event {
            Event::Text(t) => match t.decode() {
                Ok(t) => text.push_str(&t),
                Err(e) => break Err(bad(&e)),
            },
            Event::CData(c) => match c.decode() {
                Ok(c) => text.push_str(&c),
                Err(e) => break Err(bad(&e)),
            },
            Event::GeneralRef(r) => {
                let resolved = match r.resolve_char_ref() {
                    Ok(Some(c)) => Some(c.to_string()),
                    Ok(None) => r
                        .decode()
                        .ok()
                        .and_then(|name| quick_xml::escape::resolve_predefined_entity(&name))
                        .map(str::to_string),
                    Err(_) => None,
                };
                match resolved {
                    Some(v) => text.push_str(&v),
                    None => break Err(format!("invalid nuspec <{field}>: unknown entity")),
                }
            }
            Event::Start(_) => depth += 1,
            Event::End(_) if depth == 0 => break Ok(text.trim().to_string()),
            Event::End(_) => depth -= 1,
            Event::Eof => break Err(format!("unterminated nuspec <{field}>")),
            _ => {}
        }
    };
    reader.config_mut().trim_text(true);
    result
}

// ── Versions ───────────────────────────────────────────────────────────

/// NuGet version normalization (learn.microsoft.com/nuget/concepts/package-versioning):
/// leading zeros dropped, missing parts filled to three, a zero fourth part omitted,
/// build metadata removed. Returns the normalized string (pre-release case kept) and
/// whether the version is SemVer 2.0.0-only (dotted pre-release or build metadata).
pub(super) fn normalize_version(raw: &str) -> Option<(String, bool)> {
    let raw = raw.trim();
    let (rest, metadata) = match raw.split_once('+') {
        Some((r, m)) => (r, Some(m)),
        None => (raw, None),
    };
    let (core, pre) = match rest.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (rest, None),
    };
    let label_ok = |s: &str| {
        s.split('.')
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
    };
    if !metadata.is_none_or(label_ok) || !pre.is_none_or(label_ok) {
        return None;
    }
    let mut nums = core
        .split('.')
        .map(|p| {
            if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) {
                p.parse::<u32>().ok()
            } else {
                None
            }
        })
        .collect::<Option<Vec<u32>>>()?;
    if nums.len() > 4 {
        return None;
    }
    nums.resize(4, 0);
    let mut out = format!("{}.{}.{}", nums[0], nums[1], nums[2]);
    if nums[3] != 0 {
        out.push_str(&format!(".{}", nums[3]));
    }
    if let Some(p) = pre {
        out.push('-');
        out.push_str(p);
    }
    let semver2 = metadata.is_some() || pre.is_some_and(|p| p.contains('.'));
    Some((out, semver2))
}

/// NuGet version order over normalized versions: numeric parts, then a release sorts
/// above its pre-releases; pre-release identifiers compare numerically when both are
/// numeric, numeric below alphanumeric, alphanumerics case-insensitively.
pub(super) fn compare_versions(a: &str, b: &str) -> Ordering {
    fn split(v: &str) -> ([u64; 4], Option<&str>) {
        let (core, pre) = match v.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (v, None),
        };
        let mut nums = [0u64; 4];
        for (slot, part) in nums.iter_mut().zip(core.split('.')) {
            *slot = part.parse().unwrap_or(0);
        }
        (nums, pre)
    }
    let (an, ap) = split(a);
    let (bn, bp) = split(b);
    an.cmp(&bn).then_with(|| match (ap, bp) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(x), Some(y)) => {
            let mut xs = x.split('.');
            let mut ys = y.split('.');
            loop {
                match (xs.next(), ys.next()) {
                    (None, None) => return Ordering::Equal,
                    (None, Some(_)) => return Ordering::Less,
                    (Some(_), None) => return Ordering::Greater,
                    (Some(p), Some(q)) => {
                        let ord = match (p.parse::<u64>(), q.parse::<u64>()) {
                            (Ok(m), Ok(n)) => m.cmp(&n),
                            (Ok(_), Err(_)) => Ordering::Less,
                            (Err(_), Ok(_)) => Ordering::Greater,
                            (Err(_), Err(_)) => p.to_lowercase().cmp(&q.to_lowercase()),
                        };
                        if ord != Ordering::Equal {
                            return ord;
                        }
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_version_follows_nuget_rules() {
        let n = |v: &str| normalize_version(v).map(|(s, _)| s);
        assert_eq!(n("1").as_deref(), Some("1.0.0"));
        assert_eq!(n("1.0").as_deref(), Some("1.0.0"));
        assert_eq!(n("1.00").as_deref(), Some("1.0.0"));
        assert_eq!(n("1.01.1").as_deref(), Some("1.1.1"));
        assert_eq!(n("1.00.0.1").as_deref(), Some("1.0.0.1"));
        assert_eq!(n("1.0.0.0").as_deref(), Some("1.0.0"));
        assert_eq!(n("1.0.01.0").as_deref(), Some("1.0.1"));
        assert_eq!(n("1.0.7+r3456").as_deref(), Some("1.0.7"));
        assert_eq!(n("2.1.0-Beta-1").as_deref(), Some("2.1.0-Beta-1"));
        assert_eq!(n(" 3.0.0-pr.12+sha.abc ").as_deref(), Some("3.0.0-pr.12"));
        for bad in [
            "",
            "a",
            "1.2.3.4.5",
            "1..2",
            "1.0-",
            "1.0+",
            "1.0.0-a..b",
            "1.0.0-é",
            "-1.0",
            "1.0/x",
        ] {
            assert_eq!(n(bad), None, "{bad:?} must be rejected");
        }
    }

    #[test]
    fn semver2_detection() {
        let s = |v: &str| normalize_version(v).map(|(_, s)| s);
        assert_eq!(s("1.0.0"), Some(false));
        assert_eq!(s("1.0.0-beta1"), Some(false));
        assert_eq!(s("1.0.0-alpha.1"), Some(true));
        assert_eq!(s("1.0.0+githash"), Some(true));
    }

    #[test]
    fn compare_versions_orders_like_nuget() {
        let mut v = vec![
            "1.0.0",
            "1.0.0-beta.10",
            "1.0.0-beta.2",
            "1.0.0-Alpha",
            "1.0.0-beta",
            "0.9.0",
            "1.0.0.1",
            "1.0.0-1",
            "10.0.0",
            "2.0.0",
        ];
        v.sort_by(|a, b| compare_versions(a, b));
        assert_eq!(
            v,
            [
                "0.9.0",
                "1.0.0-1",
                "1.0.0-Alpha",
                "1.0.0-beta",
                "1.0.0-beta.2",
                "1.0.0-beta.10",
                "1.0.0",
                "1.0.0.1",
                "2.0.0",
                "10.0.0"
            ]
        );
        assert_eq!(compare_versions("1.0.0-RC", "1.0.0-rc"), Ordering::Equal);
    }

    const NUSPEC: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata minClientVersion="2.12">
    <id>Maestra.Sample</id>
    <version>1.02.0-pr.7+abc</version>
    <authors>Maestra &amp; Co</authors>
    <description>Sample package</description>
    <tags>one two</tags>
    <packageTypes><packageType name="Dependency" /></packageTypes>
    <dependencies>
      <group targetFramework="net8.0">
        <dependency id="Newtonsoft.Json" version="13.0.1" exclude="Build,Analyzers" />
        <dependency id="Maestra.Core" version="[2.0.0, 3.0.0)" />
      </group>
      <group targetFramework=".NETStandard2.0" />
    </dependencies>
  </metadata>
</package>"#;

    #[test]
    fn parse_nuspec_reads_metadata_and_dependency_groups() {
        let spec = parse_nuspec(NUSPEC).unwrap();
        assert_eq!(spec.id, "Maestra.Sample");
        assert_eq!(spec.version, "1.02.0-pr.7+abc");
        assert_eq!(spec.authors, "Maestra & Co");
        assert_eq!(spec.tags, "one two");
        assert_eq!(spec.package_types, ["Dependency"]);
        assert_eq!(
            spec.dependency_groups,
            [
                DependencyGroup {
                    target_framework: Some("net8.0".into()),
                    dependencies: vec![
                        Dependency {
                            id: "Newtonsoft.Json".into(),
                            range: Some("13.0.1".into())
                        },
                        Dependency {
                            id: "Maestra.Core".into(),
                            range: Some("[2.0.0, 3.0.0)".into())
                        },
                    ],
                },
                DependencyGroup {
                    target_framework: Some(".NETStandard2.0".into()),
                    dependencies: vec![]
                },
            ]
        );
    }

    /// CDATA is valid nuspec text: kept verbatim (a bare `&` included), mixed with
    /// escaped text and character references.
    #[test]
    fn parse_nuspec_reads_cdata_and_references() {
        let xml = r#"<package><metadata><id>A</id><version>1.0.0</version>
            <description><![CDATA[Foo & <Bar>]]> &amp; baz &#169;</description>
            <title><![CDATA[plain]]></title></metadata></package>"#;
        let spec = parse_nuspec(xml).unwrap();
        assert_eq!(spec.description, "Foo & <Bar> & baz \u{a9}");
        assert_eq!(spec.title, "plain");
        assert!(parse_nuspec(
            "<package><metadata><id>A</id><version>1</version><title>&nope;</title></metadata></package>"
        )
        .is_err());
    }

    #[test]
    fn parse_nuspec_flat_dependencies_form_one_group() {
        let xml = r#"<package><metadata><id>A</id><version>1.0.0</version>
            <dependencies><dependency id="B" version="1.0" /><dependency id="C" /></dependencies>
            </metadata></package>"#;
        let spec = parse_nuspec(xml).unwrap();
        assert_eq!(spec.dependency_groups.len(), 1);
        assert_eq!(spec.dependency_groups[0].target_framework, None);
        assert_eq!(spec.dependency_groups[0].dependencies.len(), 2);
        assert_eq!(spec.dependency_groups[0].dependencies[1].range, None);
    }

    #[test]
    fn parse_nuspec_rejects_missing_id_or_broken_xml() {
        assert!(
            parse_nuspec("<package><metadata><version>1.0.0</version></metadata></package>")
                .is_err()
        );
        assert!(parse_nuspec("<package><metadata><id>A</id>").is_err());
    }

    #[test]
    fn parse_nupkg_requires_exactly_one_root_nuspec() {
        assert!(parse_nupkg(b"not a zip").is_err());
        assert!(parse_nupkg(&test_support::zip(&[("lib/a.nuspec", NUSPEC)])).is_err());
        assert!(parse_nupkg(&test_support::zip(&[
            ("a.nuspec", NUSPEC),
            ("b.nuspec", NUSPEC)
        ]))
        .is_err());
        let spec = parse_nupkg(&test_support::zip(&[("Maestra.Sample.nuspec", NUSPEC)])).unwrap();
        assert_eq!(spec.id, "Maestra.Sample");
        assert_eq!(spec.raw, NUSPEC);
    }

    fn pkg_with(n: usize) -> HostedPackage {
        HostedPackage {
            id: "Big.Pkg".into(),
            versions: (0..n)
                .map(|i| HostedVersion {
                    version: format!("1.0.{i}"),
                    listed: true,
                    ..Default::default()
                })
                .collect(),
        }
    }

    #[test]
    fn registration_inlines_below_128_and_pages_above() {
        let nuget = "http://nora/nuget";
        let small = build_registration_index(&pkg_with(127), nuget);
        assert_eq!(small["count"], 2);
        assert_eq!(small["items"][0]["items"].as_array().unwrap().len(), 64);
        assert_eq!(small["items"][1]["items"].as_array().unwrap().len(), 63);

        let big_pkg = pkg_with(130);
        let big = build_registration_index(&big_pkg, nuget);
        assert_eq!(big["count"], 3);
        assert!(big["items"][0].get("items").is_none());
        assert_eq!(
            big["items"][0]["@id"],
            "http://nora/nuget/v3/registration/big.pkg/page/1.0.0/1.0.63.json"
        );
        let page = build_registration_page(&big_pkg, nuget, "1.0.128", "1.0.129").unwrap();
        assert_eq!(page["count"], 2);
        assert_eq!(
            page["parent"],
            "http://nora/nuget/v3/registration/big.pkg/index.json"
        );
        assert_eq!(
            page["items"][1]["packageContent"],
            "http://nora/nuget/v3/flatcontainer/big.pkg/1.0.129/big.pkg.1.0.129.nupkg"
        );
        assert!(build_registration_page(&big_pkg, nuget, "1.0.1", "1.0.2").is_none());
    }

    #[test]
    fn merge_search_puts_hosted_first_and_drops_upstream_namesakes() {
        let hosted = vec![json!({"id": "Maestra.A"})];
        let upstream =
            br#"{"totalHits":3,"data":[{"id":"maestra.a"},{"id":"X"},{"id":"Y"}]}"#.to_vec();
        let out: Value =
            serde_json::from_slice(&merge_search(&hosted, upstream.clone(), 0, 20, false)).unwrap();
        assert_eq!(out["totalHits"], 3);
        let ids: Vec<&str> = out["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["Maestra.A", "X", "Y"]);
        let names: Value = serde_json::from_slice(&merge_search(
            &hosted,
            br#"{"totalHits":1,"data":["Z"]}"#.to_vec(),
            0,
            20,
            true,
        ))
        .unwrap();
        assert_eq!(names["data"], json!(["Maestra.A", "Z"]));
        let page2: Value =
            serde_json::from_slice(&merge_search(&hosted, upstream, 20, 20, false)).unwrap();
        assert!(!page2["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["id"] == "Maestra.A"));
    }
}

#[cfg(test)]
pub(super) mod test_support {
    use std::io::Write;

    pub fn zip(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, body) in entries {
            w.start_file(*name, opts).unwrap();
            w.write_all(body.as_bytes()).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    pub fn nupkg(id: &str, version: &str, extra_metadata: &str) -> Vec<u8> {
        let nuspec = format!(
            r#"<?xml version="1.0"?><package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata><id>{id}</id><version>{version}</version><authors>t</authors><description>d</description>{extra_metadata}</metadata></package>"#
        );
        zip(&[
            (&format!("{id}.nuspec"), &nuspec),
            ("lib/net8.0/a.dll", "x"),
        ])
    }

    /// multipart/form-data body the way `dotnet nuget push` sends it.
    pub fn multipart(nupkg: &[u8]) -> (String, Vec<u8>) {
        let boundary = "nora-test-boundary";
        let mut body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"package\"; filename=\"package.nupkg\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .into_bytes();
        body.extend_from_slice(nupkg);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        (format!("multipart/form-data; boundary={boundary}"), body)
    }
}

#[cfg(test)]
mod integration_tests {
    use super::test_support::{multipart, nupkg};
    use crate::test_helpers::{
        body_bytes, create_test_context_with_anonymous_read_and_config,
        create_test_context_with_config, send, send_with_headers,
    };
    use axum::http::{Method, StatusCode};
    use serde_json::Value;

    async fn push(app: &axum::Router, pkg: &[u8], headers: &[(&str, &str)]) -> StatusCode {
        let (ct, body) = multipart(pkg);
        let mut h = vec![("content-type", ct.as_str())];
        h.extend_from_slice(headers);
        send_with_headers(app, Method::PUT, "/nuget/v3/package/", h, body)
            .await
            .status()
    }

    async fn get_json(app: &axum::Router, uri: &str) -> (StatusCode, Value) {
        let resp = send(app, Method::GET, uri, "").await;
        let status = resp.status();
        let gz = resp.headers().get("content-encoding").is_some();
        let raw = body_bytes(resp).await;
        let raw = if gz {
            let mut out = Vec::new();
            std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&raw[..]), &mut out)
                .unwrap();
            out
        } else {
            raw.to_vec()
        };
        (status, serde_json::from_slice(&raw).unwrap_or(Value::Null))
    }

    /// Hosted feed in front of an unreachable proxy: hosted IDs never touch upstream.
    fn ctx() -> crate::test_helpers::TestContext {
        create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.nuget.proxy_timeout = 1;
            cfg.nuget.metadata_proxy_timeout = 1;
        })
    }

    #[tokio::test]
    async fn push_then_restore_endpoints_serve_the_package() {
        let ctx = ctx();
        let pkg = nupkg(
            "Maestra.Lib",
            "1.0.0",
            r#"<dependencies><group targetFramework="net8.0"><dependency id="Maestra.Core" version="2.0.0"/></group></dependencies>"#,
        );
        assert_eq!(push(&ctx.app, &pkg, &[]).await, StatusCode::CREATED);
        assert_eq!(
            push(&ctx.app, &nupkg("Maestra.Lib", "1.1.0-pr.3", ""), &[]).await,
            StatusCode::CREATED
        );
        // Same version, different spelling → duplicate.
        assert_eq!(
            push(&ctx.app, &nupkg("maestra.lib", "1.0", ""), &[]).await,
            StatusCode::CONFLICT
        );

        let (s, idx) = get_json(&ctx.app, "/nuget/v3/flatcontainer/maestra.lib/index.json").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(idx["versions"], serde_json::json!(["1.0.0", "1.1.0-pr.3"]));

        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/flatcontainer/maestra.lib/1.0.0/maestra.lib.1.0.0.nupkg",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], &pkg[..]);
        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/flatcontainer/maestra.lib/1.0.0/maestra.lib.nuspec",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(String::from_utf8_lossy(&body_bytes(resp).await).contains("<id>Maestra.Lib</id>"));
        // A version the hosted ID lacks is a 404, not an upstream fetch.
        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/flatcontainer/maestra.lib/9.0.0/maestra.lib.9.0.0.nupkg",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let (s, reg) = get_json(&ctx.app, "/nuget/v3/registration/Maestra.Lib/index.json").await;
        assert_eq!(s, StatusCode::OK);
        let leaves = reg["items"][0]["items"].as_array().unwrap();
        assert_eq!(leaves.len(), 2);
        let entry = &leaves[0]["catalogEntry"];
        assert_eq!(entry["id"], "Maestra.Lib");
        assert_eq!(entry["listed"], true);
        assert_eq!(
            entry["dependencyGroups"][0]["dependencies"][0]["range"],
            "2.0.0"
        );
        assert!(leaves[1]["packageContent"].as_str().unwrap().ends_with(
            "/nuget/v3/flatcontainer/maestra.lib/1.1.0-pr.3/maestra.lib.1.1.0-pr.3.nupkg"
        ));
    }

    #[tokio::test]
    async fn push_rejects_invalid_packages() {
        let ctx = ctx();
        assert_eq!(
            push(&ctx.app, b"not a zip", &[]).await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            push(&ctx.app, &nupkg("Bad", "not-a-version", ""), &[]).await,
            StatusCode::BAD_REQUEST
        );
        let symbols = nupkg(
            "Sym",
            "1.0.0",
            r#"<packageTypes><packageType name="SymbolsPackage"/></packageTypes>"#,
        );
        assert_eq!(push(&ctx.app, &symbols, &[]).await, StatusCode::BAD_REQUEST);
        let resp = send_with_headers(&ctx.app, Method::PUT, "/nuget/v3/package", vec![], "").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn delete_unlists_and_post_relists() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = None;
        });
        assert_eq!(
            push(&ctx.app, &nupkg("Maestra.Tool", "2.0.0", ""), &[]).await,
            StatusCode::CREATED
        );

        let (_, hits) = get_json(&ctx.app, "/nuget/v3/query?q=maestra.tool").await;
        assert_eq!(hits["data"][0]["id"], "Maestra.Tool");
        assert_eq!(hits["data"][0]["version"], "2.0.0");

        let resp = send(
            &ctx.app,
            Method::DELETE,
            "/nuget/v3/package/Maestra.Tool/2.0.0",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let resp = send(
            &ctx.app,
            Method::DELETE,
            "/nuget/v3/package/Maestra.Tool/3.0.0",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let (_, hits) = get_json(&ctx.app, "/nuget/v3/query?q=maestra.tool").await;
        assert_eq!(hits["totalHits"], 0);
        let (_, reg) = get_json(&ctx.app, "/nuget/v3/registration/maestra.tool/index.json").await;
        assert_eq!(reg["items"][0]["items"][0]["catalogEntry"]["listed"], false);
        // Unlisted stays restorable.
        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/flatcontainer/maestra.tool/2.0.0/maestra.tool.2.0.0.nupkg",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = send(
            &ctx.app,
            Method::POST,
            "/nuget/v3/package/maestra.tool/2.0.0",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let (_, hits) = get_json(&ctx.app, "/nuget/v3/query?q=maestra.tool").await;
        assert_eq!(hits["totalHits"], 1);
    }

    #[tokio::test]
    async fn search_filters_prerelease_and_semver2() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = None;
        });
        assert_eq!(
            push(&ctx.app, &nupkg("Maestra.Pre", "1.0.0-pr.1", ""), &[]).await,
            StatusCode::CREATED
        );
        let (_, hits) = get_json(&ctx.app, "/nuget/v3/query?q=pre").await;
        assert_eq!(hits["totalHits"], 0);
        let (_, hits) = get_json(&ctx.app, "/nuget/v3/query?q=pre&prerelease=true").await;
        assert_eq!(
            hits["totalHits"], 0,
            "dotted pre-release is SemVer 2.0.0-only"
        );
        let (_, hits) = get_json(
            &ctx.app,
            "/nuget/v3/query?q=id:maestra.pre&prerelease=true&semVerLevel=2.0.0",
        )
        .await;
        assert_eq!(hits["data"][0]["version"], "1.0.0-pr.1");
        let (_, names) = get_json(
            &ctx.app,
            "/nuget/v3/autocomplete?q=maestra&prerelease=true&semVerLevel=2.0.0",
        )
        .await;
        assert_eq!(names["data"], serde_json::json!(["Maestra.Pre"]));
    }

    /// Concurrent pushes of one ID serialize on the per-ID publish lock: no version
    /// is lost to a read-modify-write race on the state document.
    #[tokio::test]
    async fn concurrent_pushes_keep_every_version() {
        let ctx = ctx();
        let pushes = (0..16).map(|i| {
            let app = ctx.app.clone();
            tokio::spawn(async move {
                push(&app, &nupkg("Maestra.Race", &format!("1.0.{i}"), ""), &[]).await
            })
        });
        for p in futures::future::join_all(pushes).await {
            assert_eq!(p.unwrap(), StatusCode::CREATED);
        }
        let (_, idx) = get_json(&ctx.app, "/nuget/v3/flatcontainer/maestra.race/index.json").await;
        assert_eq!(idx["versions"].as_array().unwrap().len(), 16);
        assert_eq!(
            idx["versions"][15], "1.0.15",
            "sorted by version, not push order"
        );
    }

    #[tokio::test]
    async fn api_key_header_authenticates_push() {
        let ctx = create_test_context_with_anonymous_read_and_config(&[("ci", "secret")], |cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = None;
        });
        let pkg = nupkg("Maestra.Auth", "1.0.0", "");
        assert_eq!(push(&ctx.app, &pkg, &[]).await, StatusCode::UNAUTHORIZED);
        assert_eq!(
            push(&ctx.app, &pkg, &[("X-NuGet-ApiKey", "nra_wrong")]).await,
            StatusCode::UNAUTHORIZED
        );
        let tokens = ctx.state.tokens.as_ref().unwrap();
        let read = tokens
            .create_token("ci", 1, None, crate::tokens::Role::Read)
            .unwrap();
        assert_eq!(
            push(&ctx.app, &pkg, &[("X-NuGet-ApiKey", &read)]).await,
            StatusCode::FORBIDDEN
        );
        let write = tokens
            .create_token("ci", 1, None, crate::tokens::Role::Write)
            .unwrap();
        assert_eq!(
            push(&ctx.app, &pkg, &[("X-NuGet-ApiKey", &write)]).await,
            StatusCode::CREATED
        );
        // Anonymous read still restores.
        let (s, idx) = get_json(&ctx.app, "/nuget/v3/flatcontainer/maestra.auth/index.json").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(idx["versions"], serde_json::json!(["1.0.0"]));
        let resp = send(
            &ctx.app,
            Method::DELETE,
            "/nuget/v3/package/maestra.auth/1.0.0",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
