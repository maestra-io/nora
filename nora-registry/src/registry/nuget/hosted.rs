// Copyright (c) 2026 The Nora Authors
// SPDX-License-Identifier: MIT

//! Hosted NuGet feed: `dotnet nuget push`, `dotnet nuget delete` (unlist) and relist,
//! served ahead of the nuget.org proxy from the same `/nuget/v3/index.json`.
//!
//!   PUT    /nuget/v3/package[/]                  — push (multipart, first part = .nupkg)
//!   DELETE /nuget/v3/package/{id}/{version}      — unlist (blob kept, NuGet semantics)
//!   POST   /nuget/v3/package/{id}/{version}      — relist
//!   GET    /nuget/v3/registration/{id}/{ver}.json — registration leaf
//!   GET    /nuget/v3/query, /autocomplete         — hosted hits first, then the proxy
//!
//! Storage:
//!   nuget/hosted/{id}/{ver}/{id}.{ver}.nupkg — package blob (immutable)
//!   nuget/hosted/{id}/{ver}/{id}.nuspec      — extracted manifest
//!   nuget/hosted-meta/{id}.json              — per-ID state, the single source for the
//!                                              flat-container version list, registration
//!                                              and search. Written last, under the
//!                                              per-ID publish lock, after the blobs.
//!
//! [`HostedIndex`] keeps every state document in memory (loaded on first use, updated
//! on every write), so a request for a non-hosted ID costs no storage call and search
//! never reads storage. An ID with a state document is owned by this feed: its metadata
//! and downloads are never proxied upstream. An internal ID that has not been pushed
//! yet is only kept off nuget.org by `curation.internal_namespaces`.

use super::{is_valid_package_id, with_json, with_json_gzip, SearchParams};
use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::auth::{enforce_namespace_scope, AuthenticatedUser, NamespaceAuthority};
use crate::registry::nora_base_url;
use crate::registry_type::RegistryType;
use crate::storage::{Storage, StorageError};
use crate::validation::ends_with_ci;
use crate::AppState;
use axum::{
    body::Body,
    extract::{Multipart, Path, Query, RawQuery, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Extension, Router,
};
use futures::StreamExt;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Digest;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::io::{Read, Seek};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

const META_PREFIX: &str = "nuget/hosted-meta/";
const BLOB_PREFIX: &str = "nuget/hosted/";
/// Registration leaves per page, and the count from which pages stop being inlined
/// (nuget.org's thresholds, learn.microsoft.com/nuget/api/registration-base-url-resource).
const PAGE_SIZE: usize = 64;
const INLINE_BELOW: usize = 128;
/// A .nuspec is a few KB; the cap stops a zip bomb disguised as one.
const MAX_NUSPEC_BYTES: u64 = 1024 * 1024;
/// nuget.org's package size limit. The upload is spooled to disk, never buffered.
const MAX_PACKAGE_BYTES: u64 = 250 * 1024 * 1024;
const MAX_ID_LEN: usize = 100;
/// State documents read in parallel while the index loads.
const LOAD_CONCURRENCY: usize = 16;
/// Cap on an upstream search/autocomplete body read back for merging.
const MAX_UPSTREAM_SEARCH_BYTES: usize = 16 * 1024 * 1024;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/nuget/v3/package", put(push))
        // The NuGet client PUTs to `{@id}/`, with the trailing slash.
        .route("/nuget/v3/package/", put(push))
        .route(
            "/nuget/v3/package/{id}/{version}",
            post(relist).delete(unlist),
        )
        .route("/nuget/v3/registration/{id}/{leaf}", get(registration_leaf))
}

// ── State document ─────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
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
    /// nuspec `<packageTypes>`; empty means `Dependency`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    package_types: Vec<String>,
}

impl HostedVersion {
    fn package_types(&self) -> Vec<&str> {
        if self.package_types.is_empty() {
            vec!["Dependency"]
        } else {
            self.package_types.iter().map(String::as_str).collect()
        }
    }
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

#[derive(Debug, PartialEq)]
enum LoadError {
    /// Storage did not answer: transient, retry.
    Storage,
    /// The document exists but does not parse: the ID fails closed until repaired.
    Corrupt,
}

/// `Ok(None)` = the ID is not hosted. An error must neither proxy the ID (it may be
/// ours) nor be overwritten (a rewrite would drop every version).
async fn load(storage: &Storage, id_lower: &str) -> Result<Option<HostedPackage>, LoadError> {
    match storage.get(&meta_key(id_lower)).await {
        Ok(data) => serde_json::from_slice(&data).map(Some).map_err(|e| {
            tracing::error!(id = %id_lower, error = %e, "nuget hosted: state document unparsable");
            LoadError::Corrupt
        }),
        Err(StorageError::NotFound) => Ok(None),
        Err(e) => {
            tracing::error!(id = %id_lower, error = %e, "nuget hosted: state document unreadable");
            Err(LoadError::Storage)
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

// ── In-memory index ────────────────────────────────────────────────────

/// In-memory view of `nuget/hosted-meta/`, keyed by lowercase ID. `None` marks a
/// document that exists but does not parse (fail closed: 503 for that ID).
///
/// Loaded from storage on first use (one LIST, parallel GETs) and updated after every
/// successful write. nora runs a single writer replica, so nothing invalidates it from
/// outside; a document written to storage behind nora's back is seen after a restart.
#[derive(Default)]
pub(crate) struct HostedIndex {
    docs: tokio::sync::OnceCell<RwLock<HashMap<String, Option<Arc<HostedPackage>>>>>,
}

type IndexMap = RwLock<HashMap<String, Option<Arc<HostedPackage>>>>;

async fn index(state: &AppState) -> Result<&IndexMap, ()> {
    state
        .nuget_hosted
        .docs
        .get_or_try_init(|| async {
            let keys = state.storage.list(META_PREFIX).await.map_err(|e| {
                tracing::error!(error = %e, "nuget hosted: index listing failed");
            })?;
            let ids = keys.into_iter().filter_map(|k| {
                k.strip_prefix(META_PREFIX)?
                    .strip_suffix(".json")
                    .map(str::to_string)
            });
            let loaded: Vec<_> = futures::stream::iter(ids)
                .map(|id| async move {
                    let doc = load(&state.storage, &id).await;
                    (id, doc)
                })
                .buffer_unordered(LOAD_CONCURRENCY)
                .collect()
                .await;
            let mut map = HashMap::new();
            for (id, doc) in loaded {
                match doc {
                    Ok(Some(pkg)) => {
                        map.insert(id, Some(Arc::new(pkg)));
                    }
                    Ok(None) => {} // deleted between LIST and GET
                    Err(LoadError::Corrupt) => {
                        map.insert(id, None);
                    }
                    Err(LoadError::Storage) => return Err(()),
                }
            }
            tracing::info!(ids = map.len(), "nuget hosted: index loaded");
            Ok(RwLock::new(map))
        })
        .await
}

enum Lookup {
    NotHosted,
    Hosted(Arc<HostedPackage>),
    Unavailable,
}

async fn lookup(state: &AppState, id_lower: &str) -> Lookup {
    let Ok(map) = index(state).await else {
        return Lookup::Unavailable;
    };
    match map.read().get(id_lower) {
        None => Lookup::NotHosted,
        Some(Some(pkg)) => Lookup::Hosted(pkg.clone()),
        Some(None) => Lookup::Unavailable,
    }
}

// ── Push / unlist / relist ─────────────────────────────────────────────

/// Upload spool file, removed when dropped (after `put_from_path` moved it, the
/// remove is a harmless NotFound).
struct Spool(std::path::PathBuf);

impl Drop for Spool {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

async fn push(
    State(state): State<AppState>,
    Extension(authority): Extension<NamespaceAuthority>,
    user: Option<Extension<AuthenticatedUser>>,
    mut multipart: Multipart,
) -> Response {
    // Per the protocol the first part is the package; names and later parts are ignored.
    let mut field = match multipart.next_field().await {
        Ok(Some(field)) => field,
        _ => return bad_request("expected multipart/form-data with the .nupkg as the first part"),
    };

    // Spool to disk with a running hash: memory stays flat however large the package.
    let dir = std::path::PathBuf::from(&state.config.storage.path).join("tmp/nuget-uploads");
    if let Err(e) = tokio::fs::create_dir_all(&dir).await {
        tracing::error!(path = %dir.display(), error = %e, "nuget hosted: cannot create spool dir");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let spool = Spool(dir.join(uuid::Uuid::new_v4().to_string()));
    let mut file = match tokio::fs::File::create(&spool.0).await {
        Ok(f) => f,
        Err(e) => {
            tracing::error!(error = %e, "nuget hosted: cannot create spool file");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let mut hasher = sha2::Sha256::new();
    let mut size = 0u64;
    loop {
        match field.chunk().await {
            Ok(Some(chunk)) => {
                size += chunk.len() as u64;
                if size > MAX_PACKAGE_BYTES {
                    return (
                        StatusCode::PAYLOAD_TOO_LARGE,
                        format!("package exceeds {} MiB", MAX_PACKAGE_BYTES >> 20),
                    )
                        .into_response();
                }
                hasher.update(&chunk);
                if let Err(e) = file.write_all(&chunk).await {
                    tracing::error!(error = %e, "nuget hosted: spool write failed");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            }
            Ok(None) => break,
            Err(e) => return bad_request(format!("failed to read package: {e}")),
        }
    }
    // Durable before the rename into storage publishes it.
    if let Err(e) = file.sync_all().await {
        tracing::error!(error = %e, "nuget hosted: spool fsync failed");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    drop(file);
    let sha256 = hex::encode(hasher.finalize());

    let path = spool.0.clone();
    let spec = match tokio::task::spawn_blocking(move || {
        std::fs::File::open(&path)
            .map_err(|e| format!("cannot reopen package: {e}"))
            .and_then(parse_nupkg)
    })
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return bad_request(e),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
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
    if !scope_allows(&authority, &id_lower) {
        return StatusCode::FORBIDDEN.into_response();
    }
    // Loaded before the write, so the update below cannot race the initial load.
    let Ok(map) = index(&state).await else {
        return unavailable();
    };

    let ver_lower = version.to_lowercase();
    let key = meta_key(&id_lower);
    let lock = state.publish_lock(&key);
    let _guard = lock.lock().await;

    let mut pkg = match load(&state.storage, &id_lower).await {
        Ok(p) => p.unwrap_or_default(),
        Err(_) => return unavailable(),
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
    // durable. A failure in between leaves an unreferenced blob a retry overwrites;
    // downloads resolve through the state document, so it is never served.
    let dir = format!("{BLOB_PREFIX}{id_lower}/{ver_lower}");
    if let Err(e) = state
        .storage
        .put_from_path(
            &format!("{dir}/{id_lower}.{ver_lower}.nupkg"),
            &spool.0,
            Some(&sha256),
        )
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
        package_size: size,
        authors: spec.authors,
        description: spec.description,
        title: spec.title,
        summary: spec.summary,
        tags: spec.tags,
        project_url: spec.project_url,
        dependency_groups: spec.dependency_groups,
        package_types: spec.package_types,
    });
    pkg.versions
        .sort_by(|a, b| compare_versions(&a.version, &b.version));
    if let Err(resp) = save(&state.storage, map, &id_lower, &pkg).await {
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

/// OIDC `namespace_scope` for NuGet: IDs are case-insensitive, so the lowercase ID is
/// matched against lowercased patterns (`Maestra.*` and `maestra.*` are the same scope).
fn scope_allows(authority: &NamespaceAuthority, id_lower: &str) -> bool {
    let lowered = match authority {
        NamespaceAuthority::Unrestricted => return true,
        NamespaceAuthority::Scoped {
            scopes,
            provider,
            mode,
        } => NamespaceAuthority::Scoped {
            scopes: scopes
                .iter()
                .map(|set| {
                    set.iter()
                        .map(|p| p.to_lowercase())
                        .collect::<Vec<_>>()
                        .into()
                })
                .collect::<Vec<_>>()
                .into(),
            provider: provider.clone(),
            mode: *mode,
        },
    };
    enforce_namespace_scope(&lowered, id_lower).is_ok()
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
    if !scope_allows(&authority, &id_lower) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(map) = index(&state).await else {
        return unavailable();
    };

    let key = meta_key(&id_lower);
    let lock = state.publish_lock(&key);
    let _guard = lock.lock().await;
    let mut pkg = match load(&state.storage, &id_lower).await {
        Ok(Some(p)) => p,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return unavailable(),
    };
    let Some(entry) = pkg
        .versions
        .iter_mut()
        .find(|v| v.version.eq_ignore_ascii_case(&version))
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    entry.listed = listed;
    if let Err(resp) = save(&state.storage, map, &id_lower, &pkg).await {
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

/// Write the state document, then publish it to the in-memory index. Called under the
/// ID's publish lock.
async fn save(
    storage: &Storage,
    map: &IndexMap,
    id_lower: &str,
    pkg: &HostedPackage,
) -> Result<(), Response> {
    let body =
        serde_json::to_vec(pkg).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
    let key = meta_key(id_lower);
    // Local backend: temp file + rename; S3: single-object PUT — both atomic.
    storage.put(&key, &body).await.map_err(|e| {
        tracing::error!(key = %key, error = %e, "nuget hosted: failed to write state document");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;
    map.write()
        .insert(id_lower.to_string(), Some(Arc::new(pkg.clone())));
    Ok(())
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
// A non-hosted ID returns `None` from memory, without a storage call.

/// Flat-container `{id}/index.json`: every version, unlisted included (as nuget.org).
pub(super) async fn version_list(state: &AppState, id_lower: &str) -> Option<Response> {
    match lookup(state, id_lower).await {
        Lookup::NotHosted => None,
        Lookup::Unavailable => Some(unavailable()),
        Lookup::Hosted(pkg) => {
            let versions: Vec<String> = pkg
                .versions
                .iter()
                .map(|v| v.version.to_lowercase())
                .collect();
            Some(with_json(
                json!({ "versions": versions }).to_string().into_bytes(),
            ))
        }
    }
}

pub(super) async fn registration_index(state: &AppState, id_lower: &str) -> Option<Response> {
    match lookup(state, id_lower).await {
        Lookup::NotHosted => None,
        Lookup::Unavailable => Some(unavailable()),
        Lookup::Hosted(pkg) => {
            let body = build_registration_index(&pkg, &nuget_base(state));
            Some(with_json_gzip(body.to_string().into_bytes()))
        }
    }
}

pub(super) async fn registration_page(
    state: &AppState,
    id_lower: &str,
    lower: &str,
    upper: &str,
) -> Option<Response> {
    match lookup(state, id_lower).await {
        Lookup::NotHosted => None,
        Lookup::Unavailable => Some(unavailable()),
        Lookup::Hosted(pkg) => Some(
            match build_registration_page(&pkg, &nuget_base(state), lower, upper) {
                Some(body) => with_json_gzip(body.to_string().into_bytes()),
                None => StatusCode::NOT_FOUND.into_response(),
            },
        ),
    }
}

/// `GET /nuget/v3/registration/{id}/{version}.json`. Proxied IDs have no leaf route
/// upstream-side either, so a non-hosted ID stays a 404.
async fn registration_leaf(
    State(state): State<AppState>,
    Path((id, leaf_name)): Path<(String, String)>,
) -> Response {
    let id_lower = id.to_lowercase();
    let Some((version, _)) = leaf_name.strip_suffix(".json").and_then(normalize_version) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !is_valid_package_id(&id_lower) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match lookup(&state, &id_lower).await {
        Lookup::NotHosted => StatusCode::NOT_FOUND.into_response(),
        Lookup::Unavailable => unavailable(),
        Lookup::Hosted(pkg) => match pkg
            .versions
            .iter()
            .find(|v| v.version.eq_ignore_ascii_case(&version))
        {
            Some(v) => with_json_gzip(leaf(&pkg, v, &nuget_base(&state)).to_string().into_bytes()),
            None => StatusCode::NOT_FOUND.into_response(),
        },
    }
}

/// `.nupkg` / `.nuspec` download. `path` is the flat-container path below the base
/// (`{id}/{ver}/{file}`). Resolved through the state document: only an indexed version
/// is served, so a blob left by a failed push is never handed out.
pub(super) async fn download(state: &AppState, path: &str, id_lower: &str) -> Option<Response> {
    let pkg = match lookup(state, id_lower).await {
        Lookup::NotHosted => return None,
        Lookup::Unavailable => return Some(unavailable()),
        Lookup::Hosted(pkg) => pkg,
    };
    let path = path.to_lowercase();
    let mut parts = path.splitn(3, '/');
    let (_, ver, file) = (parts.next(), parts.next()?, parts.next()?);
    let indexed = pkg.versions.iter().any(|v| v.version.to_lowercase() == ver);
    let expected =
        file == format!("{id_lower}.{ver}.nupkg") || file == format!("{id_lower}.nuspec");
    if !indexed || !expected {
        return Some(StatusCode::NOT_FOUND.into_response());
    }
    let key = format!("{BLOB_PREFIX}{path}");
    match state.storage.get(&key).await {
        Ok(data) => {
            let content_type = if ends_with_ci(&path, ".nuspec") {
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
        Err(e) => {
            // Indexed but unreadable (or missing): never a silent 404.
            tracing::error!(key = %key, error = %e, "nuget hosted: indexed blob unreadable");
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

fn leaf_url(nuget: &str, id_lower: &str, ver_lower: &str) -> String {
    format!("{nuget}/v3/registration/{id_lower}/{ver_lower}.json")
}

fn leaf(pkg: &HostedPackage, v: &HostedVersion, nuget: &str) -> Value {
    let id_lower = pkg.id.to_lowercase();
    let ver_lower = v.version.to_lowercase();
    let leaf_url = leaf_url(nuget, &id_lower, &ver_lower);
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

/// A page is any `[lower, upper]` range over the current versions, not only a current
/// 64-chunk: a client holding a cached index keeps resolving its page URLs after later
/// pushes re-partition the chunks. Empty range → `None` (404).
fn build_registration_page(
    pkg: &HostedPackage,
    nuget: &str,
    lower: &str,
    upper: &str,
) -> Option<Value> {
    let id_lower = pkg.id.to_lowercase();
    let items: Vec<&HostedVersion> = pkg
        .versions
        .iter()
        .filter(|v| {
            compare_versions(&v.version, lower) != Ordering::Less
                && compare_versions(&v.version, upper) != Ordering::Greater
        })
        .collect();
    if items.is_empty() {
        return None;
    }
    Some(json!({
        "@id": page_url(nuget, &id_lower, &lower.to_lowercase(), &upper.to_lowercase()),
        "count": items.len(),
        "lower": lower.to_lowercase(),
        "upper": upper.to_lowercase(),
        "parent": registration_url(nuget, &id_lower),
        "items": items.iter().map(|v| leaf(pkg, v, nuget)).collect::<Vec<_>>(),
    }))
}

// ── Search / autocomplete ──────────────────────────────────────────────
// Wrappers around the proxy handlers (routed in place of them), so the upstream
// handlers stay untouched: the result is hosted hits ++ upstream hits.

#[derive(Deserialize)]
pub(super) struct HostedSearchParams {
    q: Option<String>,
    skip: Option<usize>,
    take: Option<usize>,
    prerelease: Option<bool>,
    #[serde(rename = "semVerLevel")]
    sem_ver_level: Option<String>,
    #[serde(rename = "packageType")]
    package_type: Option<String>,
    /// Autocomplete version-enumeration mode (`?id=`).
    id: Option<String>,
}

pub(super) async fn search_query(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(p): Query<HostedSearchParams>,
    raw: RawQuery,
) -> Response {
    merged_search(state, headers, p, raw, false).await
}

pub(super) async fn autocomplete_query(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(p): Query<HostedSearchParams>,
    raw: RawQuery,
) -> Response {
    merged_search(state, headers, p, raw, true).await
}

async fn upstream_search(
    state: AppState,
    headers: HeaderMap,
    params: SearchParams,
    raw: RawQuery,
    names: bool,
) -> Response {
    if names {
        super::autocomplete_query(State(state), Query(params), raw).await
    } else {
        super::search_query(State(state), headers, Query(params), raw).await
    }
}

async fn merged_search(
    state: AppState,
    headers: HeaderMap,
    p: HostedSearchParams,
    raw: RawQuery,
    names: bool,
) -> Response {
    let prerelease = p.prerelease.unwrap_or(false);
    let semver2 = p.sem_ver_level.as_deref() == Some("2.0.0");
    let upstream_params = |skip, take| SearchParams {
        q: p.q.clone(),
        skip,
        take,
        prerelease: p.prerelease,
        sem_ver_level: p.sem_ver_level.clone(),
    };

    // Autocomplete `?id=`: versions of one package, never package IDs.
    if let (true, Some(id)) = (names, p.id.as_deref()) {
        return match lookup(&state, &id.to_lowercase()).await {
            Lookup::NotHosted => {
                upstream_search(state, headers, upstream_params(p.skip, p.take), raw, names).await
            }
            Lookup::Unavailable => unavailable(),
            Lookup::Hosted(pkg) => {
                let versions: Vec<&str> = pkg
                    .versions
                    .iter()
                    .filter(|v| visible(v, prerelease, semver2))
                    .map(|v| v.version.as_str())
                    .collect();
                with_json(
                    json!({ "totalHits": versions.len(), "data": versions })
                        .to_string()
                        .into_bytes(),
                )
            }
        };
    }

    let hits = match hosted_hits(
        &state,
        p.q.as_deref().unwrap_or(""),
        prerelease,
        semver2,
        p.package_type.as_deref(),
    )
    .await
    {
        Ok(h) => h,
        // Fail the query rather than hide hosted IDs behind their public namesakes.
        Err(()) => return unavailable(),
    };
    if hits.is_empty() {
        return upstream_search(state, headers, upstream_params(p.skip, p.take), raw, names).await;
    }

    // Paging over hosted ++ upstream: hosted rows fill the front, upstream gets the
    // remainder of the window, shifted by the hosted count.
    let skip = p.skip.unwrap_or(0);
    let take = p.take.unwrap_or(20);
    let page: Vec<Value> = hits
        .iter()
        .skip(skip)
        .take(take)
        .map(|h| if names { h["id"].clone() } else { h.clone() })
        .collect();
    let up_skip = skip.saturating_sub(hits.len());
    let up_take = take - page.len();
    // take=0 is not honoured by every upstream; ask for one row and drop it.
    let ask = up_take.max(1);
    let qs = with_paging(raw.0.as_deref().unwrap_or(""), up_skip, ask);
    let resp = upstream_search(
        state,
        headers,
        upstream_params(Some(up_skip), Some(ask)),
        RawQuery(Some(qs)),
        names,
    )
    .await;
    let (mut parts, body) = resp.into_parts();
    let upstream: Value = if parts.status == StatusCode::OK {
        match axum::body::to_bytes(body, MAX_UPSTREAM_SEARCH_BYTES).await {
            Ok(b) => serde_json::from_slice(&b).unwrap_or(Value::Null),
            Err(_) => Value::Null,
        }
    } else {
        // Upstream down or refused: hosted results still answer.
        parts = Response::new(Body::empty()).into_parts().0;
        Value::Null
    };
    let body = merge_page(&hits, page, &upstream, up_take);
    parts.headers.remove(header::CONTENT_LENGTH);
    parts.headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    Response::from_parts(parts, Body::from(body))
}

/// Replace `skip`/`take` in a raw query string, keeping every other pair verbatim.
fn with_paging(raw: &str, skip: usize, take: usize) -> String {
    let mut pairs: Vec<String> = raw
        .split('&')
        .filter(|kv| {
            let k = kv.split('=').next().unwrap_or("");
            !kv.is_empty() && !k.eq_ignore_ascii_case("skip") && !k.eq_ignore_ascii_case("take")
        })
        .map(str::to_string)
        .collect();
    pairs.push(format!("skip={skip}"));
    pairs.push(format!("take={take}"));
    pairs.join("&")
}

/// One response page: `page` (hosted rows already sliced) then up to `up_take` upstream
/// rows, minus upstream entries that are hosted IDs. `totalHits` = hosted + upstream
/// total, less the namesakes seen on this page (the rest cannot be known per page).
fn merge_page(hits: &[Value], page: Vec<Value>, upstream: &Value, up_take: usize) -> Vec<u8> {
    let hosted_ids: Vec<String> = hits
        .iter()
        .filter_map(|h| h["id"].as_str().map(str::to_lowercase))
        .collect();
    let entry_id = |e: &Value| {
        e.as_str()
            .or_else(|| e["id"].as_str())
            .map(str::to_lowercase)
    };
    let rows = upstream["data"].as_array().cloned().unwrap_or_default();
    let before = rows.len();
    let rows: Vec<Value> = rows
        .into_iter()
        .filter(|e| !entry_id(e).is_some_and(|id| hosted_ids.contains(&id)))
        .collect();
    let dropped = before - rows.len();
    let upstream_total = upstream["totalHits"].as_u64().unwrap_or(0) as usize;
    let mut data = page;
    data.extend(rows.into_iter().take(up_take));
    let doc = json!({
        "totalHits": hits.len() + upstream_total.saturating_sub(dropped),
        "data": data,
    });
    doc.to_string().into_bytes()
}

fn visible(v: &HostedVersion, prerelease: bool, semver2: bool) -> bool {
    v.listed && (prerelease || !v.version.contains('-')) && (semver2 || !v.semver2)
}

/// Hosted search results from the in-memory index, sorted by ID. Each whitespace-
/// separated term must be a substring of the ID; `packageid:`/`id:` terms must equal
/// it (case-insensitive). Listed versions only; `packageType` matches the latest
/// visible version's types.
async fn hosted_hits(
    state: &AppState,
    q: &str,
    prerelease: bool,
    semver2: bool,
    package_type: Option<&str>,
) -> Result<Vec<Value>, ()> {
    let mut exact: Vec<String> = Vec::new();
    let mut terms: Vec<String> = Vec::new();
    for t in q.split_whitespace().map(str::to_lowercase) {
        match ["packageid:", "id:"].iter().find_map(|p| t.strip_prefix(p)) {
            Some(id) => exact.push(id.to_string()),
            None => terms.push(t),
        }
    }
    let map = index(state).await?;
    let mut pkgs: Vec<(String, Arc<HostedPackage>)> = Vec::new();
    for (id, doc) in map.read().iter() {
        if !(exact.iter().all(|e| id == e) && terms.iter().all(|t| id.contains(t.as_str()))) {
            continue;
        }
        // A matching hosted ID we cannot read: fail rather than let its namesake through.
        let Some(pkg) = doc else { return Err(()) };
        pkgs.push((id.clone(), pkg.clone()));
    }
    pkgs.sort_by(|a, b| a.0.cmp(&b.0));

    let nuget = nuget_base(state);
    let mut out = Vec::new();
    for (id_lower, pkg) in pkgs {
        let visible: Vec<&HostedVersion> = pkg
            .versions
            .iter()
            .filter(|v| visible(v, prerelease, semver2))
            .collect();
        let Some(latest) = visible.last() else {
            continue;
        };
        if let Some(t) = package_type {
            if !latest
                .package_types()
                .iter()
                .any(|pt| pt.eq_ignore_ascii_case(t))
            {
                continue;
            }
        }
        let versions: Vec<Value> = visible
            .iter()
            .map(|v| {
                json!({
                    "version": v.version,
                    "downloads": 0,
                    "@id": leaf_url(&nuget, &id_lower, &v.version.to_lowercase()),
                })
            })
            .collect();
        out.push(json!({
            "@id": registration_url(&nuget, &id_lower),
            "@type": "Package",
            "registration": registration_url(&nuget, &id_lower),
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
            "packageTypes": latest
                .package_types()
                .iter()
                .map(|t| json!({ "name": t }))
                .collect::<Vec<_>>(),
            "versions": versions,
        }));
    }
    Ok(out)
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
fn parse_nupkg(data: impl Read + Seek) -> Result<Nuspec, String> {
    let mut zip = zip::ZipArchive::new(data)
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
                // NuGetVersion parts are Int32: a larger part is unreadable to clients.
                p.parse::<i32>().ok()
            } else {
                None
            }
        })
        .collect::<Option<Vec<i32>>>()?;
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
        let zip = |entries: &[(&str, &str)]| std::io::Cursor::new(test_support::zip(entries));
        assert!(parse_nupkg(std::io::Cursor::new(b"not a zip")).is_err());
        assert!(parse_nupkg(zip(&[("lib/a.nuspec", NUSPEC)])).is_err());
        assert!(parse_nupkg(zip(&[("a.nuspec", NUSPEC), ("b.nuspec", NUSPEC)])).is_err());
        let spec = parse_nupkg(zip(&[("Maestra.Sample.nuspec", NUSPEC)])).unwrap();
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
        // Any range resolves, not only current chunk bounds: a cached index whose
        // chunks moved after later pushes keeps working.
        let stale = build_registration_page(&big_pkg, nuget, "1.0.1", "1.0.2").unwrap();
        assert_eq!(stale["count"], 2);
        assert!(build_registration_page(&big_pkg, nuget, "2.0.0", "3.0.0").is_none());
    }

    #[test]
    fn normalize_version_rejects_parts_beyond_int32() {
        assert_eq!(
            normalize_version("1.0.2147483647")
                .map(|(v, _)| v)
                .as_deref(),
            Some("1.0.2147483647")
        );
        assert_eq!(normalize_version("1.0.2147483648"), None);
    }

    #[test]
    fn with_paging_replaces_only_skip_and_take() {
        assert_eq!(
            with_paging("q=a%20b&skip=5&Take=20&semVerLevel=2.0.0", 0, 3),
            "q=a%20b&semVerLevel=2.0.0&skip=0&take=3"
        );
        assert_eq!(with_paging("", 1, 2), "skip=1&take=2");
    }

    #[test]
    fn merge_page_drops_upstream_namesakes_and_counts_both() {
        let hits = vec![json!({"id": "Maestra.A"}), json!({"id": "Maestra.B"})];
        let upstream =
            json!({"totalHits": 3, "data": [{"id": "maestra.a"}, {"id": "X"}, {"id": "Y"}]});
        let out: Value =
            serde_json::from_slice(&merge_page(&hits, hits.clone(), &upstream, 2)).unwrap();
        assert_eq!(out["totalHits"], 4);
        let ids: Vec<&str> = out["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["Maestra.A", "Maestra.B", "X", "Y"]);
        let names = json!({"totalHits": 1, "data": ["Z"]});
        let out: Value =
            serde_json::from_slice(&merge_page(&hits, vec![json!("Maestra.A")], &names, 5))
                .unwrap();
        assert_eq!(out["data"], json!(["Maestra.A", "Z"]));
    }

    #[test]
    fn scope_matches_nuget_ids_case_insensitively() {
        let scoped = NamespaceAuthority::from_oidc_scope(
            "ci",
            &["Maestra.*".to_string()],
            crate::config::ScopeEnforcement::Enforce,
        );
        assert!(scope_allows(&scoped, "maestra.core"));
        assert!(scope_allows(&scoped, "maestra.core.abstractions"));
        assert!(!scope_allows(&scoped, "newtonsoft.json"));
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

    fn local_ctx() -> crate::test_helpers::TestContext {
        create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = None;
        })
    }

    /// Paging walks hosted ++ upstream: every hosted ID is reachable and totalHits
    /// counts all of them.
    #[tokio::test]
    async fn search_pages_through_all_hosted_hits() {
        let ctx = local_ctx();
        for i in 0..5 {
            let id = format!("Maestra.P{i}");
            assert_eq!(
                push(&ctx.app, &nupkg(&id, "1.0.0", ""), &[]).await,
                StatusCode::CREATED
            );
        }
        let mut seen = Vec::new();
        for skip in [0, 2, 4] {
            let (_, page) = get_json(
                &ctx.app,
                &format!("/nuget/v3/query?q=maestra&skip={skip}&take=2"),
            )
            .await;
            assert_eq!(page["totalHits"], 5);
            for e in page["data"].as_array().unwrap() {
                seen.push(e["id"].as_str().unwrap().to_string());
            }
        }
        assert_eq!(
            seen,
            [
                "Maestra.P0",
                "Maestra.P1",
                "Maestra.P2",
                "Maestra.P3",
                "Maestra.P4"
            ]
        );
    }

    #[tokio::test]
    async fn search_exact_id_and_package_type() {
        let ctx = local_ctx();
        let tool = r#"<packageTypes><packageType name="DotnetTool"/></packageTypes>"#;
        assert_eq!(
            push(&ctx.app, &nupkg("Maestra.Core", "1.0.0", ""), &[]).await,
            StatusCode::CREATED
        );
        assert_eq!(
            push(&ctx.app, &nupkg("Maestra.Core.Tool", "1.0.0", tool), &[]).await,
            StatusCode::CREATED
        );
        let (_, hits) = get_json(&ctx.app, "/nuget/v3/query?q=packageid:maestra.core").await;
        assert_eq!(hits["totalHits"], 1);
        assert_eq!(hits["data"][0]["packageTypes"][0]["name"], "Dependency");
        let (_, hits) =
            get_json(&ctx.app, "/nuget/v3/query?q=maestra&packageType=dotnettool").await;
        assert_eq!(hits["totalHits"], 1);
        assert_eq!(hits["data"][0]["id"], "Maestra.Core.Tool");
        assert_eq!(hits["data"][0]["packageTypes"][0]["name"], "DotnetTool");
    }

    #[tokio::test]
    async fn autocomplete_id_mode_lists_versions() {
        let ctx = local_ctx();
        for v in ["1.0.0", "1.1.0-beta", "2.0.0"] {
            assert_eq!(
                push(&ctx.app, &nupkg("Maestra.Ver", v, ""), &[]).await,
                StatusCode::CREATED
            );
        }
        let (_, out) = get_json(&ctx.app, "/nuget/v3/autocomplete?id=Maestra.Ver").await;
        assert_eq!(out["data"], serde_json::json!(["1.0.0", "2.0.0"]));
        let (_, out) = get_json(
            &ctx.app,
            "/nuget/v3/autocomplete?id=maestra.ver&prerelease=true",
        )
        .await;
        assert_eq!(
            out["data"],
            serde_json::json!(["1.0.0", "1.1.0-beta", "2.0.0"])
        );
    }

    #[tokio::test]
    async fn registration_leaf_is_served() {
        let ctx = local_ctx();
        assert_eq!(
            push(&ctx.app, &nupkg("Maestra.Leaf", "1.0.0-RC", ""), &[]).await,
            StatusCode::CREATED
        );
        let (s, leaf) = get_json(
            &ctx.app,
            "/nuget/v3/registration/maestra.leaf/1.0.0-rc.json",
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(leaf["catalogEntry"]["version"], "1.0.0-RC");
        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/registration/maestra.leaf/9.0.0.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/registration/not.hosted/1.0.0.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// A blob the state document does not name (a push that died before the save) is
    /// never served.
    #[tokio::test]
    async fn orphan_blob_is_not_served() {
        let ctx = local_ctx();
        assert_eq!(
            push(&ctx.app, &nupkg("Maestra.Orphan", "1.0.0", ""), &[]).await,
            StatusCode::CREATED
        );
        ctx.state
            .storage
            .put(
                "nuget/hosted/maestra.orphan/2.0.0/maestra.orphan.2.0.0.nupkg",
                b"half-pushed",
            )
            .await
            .unwrap();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/flatcontainer/maestra.orphan/2.0.0/maestra.orphan.2.0.0.nupkg",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Once the index is loaded, the hosted lookup is a memory read: a hosted version
    /// list costs zero storage calls, and a non-hosted ID's hook (same lookup) adds none
    /// in front of the proxy path.
    #[tokio::test]
    async fn hosted_lookup_costs_no_storage_call() {
        let (storage, ops) = crate::test_helpers::op_counting_storage();
        let ctx =
            crate::test_helpers::create_test_context_with_storage_and_config(storage, |cfg| {
                cfg.nuget.enabled = true;
                cfg.nuget.proxy = None;
            });
        assert_eq!(
            push(&ctx.app, &nupkg("Maestra.Hot", "1.0.0", ""), &[]).await,
            StatusCode::CREATED
        );
        ops.reset();
        let (s, _) = get_json(&ctx.app, "/nuget/v3/flatcontainer/maestra.hot/index.json").await;
        assert_eq!(s, StatusCode::OK);
        let (s, _) = get_json(&ctx.app, "/nuget/v3/registration/maestra.hot/index.json").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(ops.total(), 0, "{:?}", ops.snapshot());
        // Search reads no hosted state from storage (the remaining op is the upstream
        // handler's own local-cache index rebuild, not ours).
        let (s, hits) = get_json(&ctx.app, "/nuget/v3/query?q=maestra").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(hits["data"][0]["id"], "Maestra.Hot");
        assert_eq!(ops.snapshot().get("get"), None, "{:?}", ops.snapshot());
    }

    /// An unparsable state document fails its ID closed (503), never falls through to
    /// the upstream or to search namesakes.
    #[tokio::test]
    async fn corrupt_state_document_fails_closed() {
        let ctx = ctx();
        ctx.state
            .storage
            .put("nuget/hosted-meta/maestra.broken.json", b"{not json")
            .await
            .unwrap();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/flatcontainer/maestra.broken/index.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/query?q=maestra.broken",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        // Other IDs are unaffected.
        let resp = send(&ctx.app, Method::GET, "/nuget/v3/query?q=other", "").await;
        assert_ne!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Migration window: an internal ID not pushed yet is blocked by
    /// `curation.internal_namespaces`, never proxied; once pushed, it is served.
    #[tokio::test]
    async fn internal_namespace_covers_unpushed_ids() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = Some("http://127.0.0.1:1".to_string());
            cfg.curation.internal_namespaces = vec!["maestra.*".to_string()];
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/nuget/v3/flatcontainer/maestra.later/index.json",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            push(&ctx.app, &nupkg("Maestra.Later", "1.0.0", ""), &[]).await,
            StatusCode::CREATED
        );
        let (s, idx) = get_json(&ctx.app, "/nuget/v3/flatcontainer/maestra.later/index.json").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(idx["versions"], serde_json::json!(["1.0.0"]));
    }

    // ── OIDC workload identity over Basic (key pair copied from auth::oidc_tests) ──

    const TEST_RSA_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7657FVL7gwmjj
PEfl4A+ajG3DFj6YHmS9gargHMChpdLMbt8ybqu1hHPUNKQyndUvFJ6q+xJFEds3
eBtjB5GLLtlj9lScvGPsV7386rypeHq30IErgm2beQJyF9ldtrVHBBPbz7eAo4+i
wCJ/m5IsuoLCYZPQrDUdpax0dUEa/eP6badqjZ2r0recnHw1+zGyozzSHNvPtK9I
PsKwBcbGjt5n5+9nWN322/mISAuLNwtv7l3Lja8U7m0ixH0ZLwFSgTLtzEfJISux
+ngGR4k2PBVeo+yDOZtuatx7Aixa1FerOwiq2xsoGOs2dhXagwFGdwbs8x/MvEj0
67Mm3OrLAgMBAAECggEAHXZkjyWpQ43XagESeKz3ZVCtCNAdAjaJrth8lOSNIwrf
kOO1JLALRcs9acDTGYh7WwVNlxsEE0Yoa3ruOEmAfSTcOnrtayFyPSTIibW33I4i
F12eUtcBHkYLpx2sG7BAnaC7CFR5vbZnF6ot/nnCojaft6Aaz7WgIkTOU/fqPDPb
WOSn4PQmgZS34non7y0NWmxxeIwqJk3aBeeEKisO2AS0YCHOgx2uBTIt2lcIzjK8
RHwQjLRRfhzxuhHuQtz/hMVQ17W3l7ehYTnW0D+UJJTXBjPgElICmWdGm9NMX9YH
HzVSBdH+tzTZ/hUhKe+nEZ5vrWT2wqx/h0med2P3eQKBgQDYNURqK7dfo2QBsy/F
pdUg7UaXfWe+c6guu32aZhnxYsHUE68cuV7Bz/awjMJYvF9VKhoJ+iuHI0myo9In
HITzbSDwFrWCme7DAIPbfbQU9nQqJLK/g3nUpYSpjFQEnIPJSr1aS/fVpUURAoBg
RSktyRTY3ak7+6x1I54HLxPk3QKBgQDegZEqK6B28fQklCPgdimwnNr92oJe5hoY
9cHUDz3A1Uyek40LQ1yR7W/imDCJMcQXqM7Lo54+55eHEkBvh6H/TTmnGMzj5L7t
HoKYMjYdBK7waFYGM6ULfVXqs6JqVmKFU7LX+ZVmOB5kgcQMQrAhio0GrG97iDqz
aKHqOthfxwKBgQDKa+SnulIumlzRMqAxXfdSopOK1YBB0SrOxf7shVcYpitukRdL
v0m2DyyZUs/KIGLo60gBu1TxatpfA/2HXK4k8jD6V2iM4+2kaGELKH9neO59Xmpz
33Y63tR7oMQwpRDFbtIlLibUwa0OJddnSpkpIq//8le1rwVhjn0voKXxiQKBgQDS
2qPO+6LHtQewdjX9atydAjfAooYzGgkXKCTzKTJS/47pI1hgmQgrPX9uktxD1sZF
yXGWpsm6QMtmc5ReXIDWp77/q0/WkpmfqO8G/WYsX5jMN4N1wxEfbzmw/WPnM0+P
mz56zoiWYo3intpC6Bty3ZJBBb1rqjA+feQaTINpVwKBgF/M0Lj9Sq9G2Ec7yBnm
xhBlLwCNzAk33Fy+6w6ANXTsGRwMm0zGdTjC3e6LHMrD0ZtF0M2blWAUh3sZ6ItQ
2Ak5ScO0q3MRQvo4HZkFK2wuZvNLYExq6gGy3P6l8xXbvQTzg5nl9UWDKfY1gifz
Jd74nq6dNCjpWG4drIsyhqX+
-----END PRIVATE KEY-----"#;

    // Corresponding JWKS (public key in JWK format)
    const TEST_JWKS_JSON: &str = r#"{"keys":[{"kty":"RSA","kid":"test-key-1","use":"sig","alg":"RS256","n":"u-uexVS-4MJo4zxH5eAPmoxtwxY-mB5kvYGq4BzAoaXSzG7fMm6rtYRz1DSkMp3VLxSeqvsSRRHbN3gbYweRiy7ZY_ZUnLxj7Fe9_Oq8qXh6t9CBK4Jtm3kCchfZXba1RwQT28-3gKOPosAif5uSLLqCwmGT0Kw1HaWsdHVBGv3j-m2nao2dq9K3nJx8NfsxsqM80hzbz7SvSD7CsAXGxo7eZ-fvZ1jd9tv5iEgLizcLb-5dy42vFO5tIsR9GS8BUoEy7cxHySErsfp4BkeJNjwVXqPsgzmbbmrcewIsWtRXqzsIqtsbKBjrNnYV2oMBRncG7PMfzLxI9OuzJtzqyw","e":"AQAB"}]}"#;

    fn github_jwt(issuer: &str, sub: &str, aud: &str) -> String {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-key-1".to_string());
        let claims = serde_json::json!({
            "iss": issuer, "sub": sub, "aud": aud, "iat": now, "exp": now + 300,
            "repository_owner": "maestra-io",
        });
        let key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY.as_bytes()).unwrap();
        encode(&header, &claims, &key).unwrap()
    }

    /// The production shape: GitHub Actions ID tokens with `aud=packages.maestra.io`,
    /// any maestra-io repo may publish under `Maestra.*`/`Mindbox.*` only, reads need
    /// a token (no anonymous read).
    async fn oidc_ctx() -> (crate::test_helpers::TestContext, wiremock::MockServer) {
        use crate::config::{OidcConfig, OidcProvider, OidcRoleRule, ScopeEnforcement};
        let jwks = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::path("/.well-known/jwks.json"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_raw(TEST_JWKS_JSON, "application/json"),
            )
            .mount(&jwks)
            .await;
        let issuer = jwks.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = None;
            cfg.auth.enabled = true;
            cfg.auth.anonymous_read = false;
            cfg.auth.oidc = OidcConfig {
                enabled: true,
                providers: vec![OidcProvider {
                    name: "github-actions".into(),
                    issuer,
                    jwks_uri: None,
                    audience: "packages.maestra.io".into(),
                    algorithms: vec!["RS256".into()],
                    max_token_lifetime_secs: 900,
                    namespace_scope: vec!["Maestra.*".into(), "Mindbox.*".into()],
                    namespace_scope_enforcement: ScopeEnforcement::Enforce,
                    enabled: true,
                    role_rules: vec![OidcRoleRule {
                        pattern: "repo:maestra-io/*".into(),
                        role: "write".into(),
                        namespace_scope: None,
                    }],
                }],
                ..Default::default()
            };
        });
        (ctx, jwks)
    }

    fn basic(password: &str) -> String {
        use base64::Engine;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("oidc:{password}"))
        )
    }

    #[tokio::test]
    async fn oidc_jwt_as_basic_password_pushes_and_restores() {
        let (ctx, jwks) = oidc_ctx().await;
        let jwt = github_jwt(
            &jwks.uri(),
            "repo:maestra-io/app:ref:refs/heads/main",
            "packages.maestra.io",
        );
        let auth = basic(&jwt);
        let pkg = nupkg("Maestra.Oidc", "1.0.0", "");
        assert_eq!(
            push(&ctx.app, &pkg, &[("authorization", &auth)]).await,
            StatusCode::CREATED
        );

        // Restore with the same Basic credential (anonymous read is off).
        let uri = "/nuget/v3/flatcontainer/maestra.oidc/1.0.0/maestra.oidc.1.0.0.nupkg";
        let resp = send(&ctx.app, Method::GET, uri, "").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            uri,
            vec![("authorization", &auth)],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(&body_bytes(resp).await[..], &pkg[..]);

        // Same namespace_scope as Bearer: outside Maestra.*/Mindbox.* is refused.
        let other = nupkg("Newtonsoft.Json", "99.0.0", "");
        assert_eq!(
            push(&ctx.app, &other, &[("authorization", &auth)]).await,
            StatusCode::FORBIDDEN
        );
        // Scope patterns match NuGet IDs case-insensitively.
        let mixed = nupkg("mindbox.lower", "1.0.0", "");
        assert_eq!(
            push(&ctx.app, &mixed, &[("authorization", &auth)]).await,
            StatusCode::CREATED
        );
    }

    #[tokio::test]
    async fn oidc_jwt_wrong_audience_or_owner_is_refused() {
        let (ctx, jwks) = oidc_ctx().await;
        let pkg = nupkg("Maestra.Oidc", "1.0.0", "");
        let wrong_aud = github_jwt(
            &jwks.uri(),
            "repo:maestra-io/app:ref:refs/heads/main",
            "nora",
        );
        assert_eq!(
            push(&ctx.app, &pkg, &[("authorization", &basic(&wrong_aud))]).await,
            StatusCode::UNAUTHORIZED
        );
        let foreign = github_jwt(
            &jwks.uri(),
            "repo:evil-org/app:ref:refs/heads/main",
            "packages.maestra.io",
        );
        assert_eq!(
            push(&ctx.app, &pkg, &[("authorization", &basic(&foreign))]).await,
            StatusCode::UNAUTHORIZED
        );
        // The JWT also works as the NuGet API key.
        let ok = github_jwt(
            &jwks.uri(),
            "repo:maestra-io/app:pull_request",
            "packages.maestra.io",
        );
        assert_eq!(
            push(&ctx.app, &pkg, &[("X-NuGet-ApiKey", &ok)]).await,
            StatusCode::CREATED
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
