// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! maestra: the handler bodies the rpm and deb registries share (R4-T11). Both keep
//! one metadata sidecar per package and rebuild the whole index under the repo
//! publish lock; they differ in parsing, key names and which paths are indexes,
//! which [`OsRepo`] carries. The axum handlers stay in `rpm.rs` / `deb.rs`.

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::auth::{enforce_namespace_scope, AuthenticatedUser, NamespaceAuthority};
use crate::config::{Config, RepoProxyEntry, UpstreamAuth};
use crate::registry::proxied_repo_conflict;
use crate::registry_type::RegistryType;
use crate::validation::validate_storage_key;
use crate::AppState;
use axum::{
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;

/// Sidecar prefix inside a repo. Rejected as an upload path component, so it
/// can never collide with package files.
pub(super) const META_DIR: &str = ".nora-meta";

/// The config fields both formats have.
pub(super) struct Settings<'a> {
    pub enabled: bool,
    pub max_file_size: u64,
    pub proxies: &'a BTreeMap<String, RepoProxyEntry>,
    pub proxy_timeout: u64,
    pub metadata_ttl: i64,
}

pub(super) trait OsRepo {
    /// Storage prefix and the metrics, audit and repo-index label.
    const NAME: &'static str;
    const REGISTRY_TYPE: RegistryType;
    /// What a publish rebuilds, as the messages name it.
    const INDEX: &'static str;
    /// The signing key's path in a hosted repo.
    const PUBKEY_PATH: &'static str;
    /// The parsed package fields stored as its sidecar.
    type Record: Serialize + Send;

    fn settings(config: &Config) -> Settings<'_>;
    fn package_key(repo: &str, path: &str) -> String;
    fn sidecar_key(repo: &str, path: &str) -> String;
    /// The key the repo's publish lock is named after.
    fn lock_key(repo: &str) -> String;
    fn content_type(path: &str) -> &'static str;
    /// The format's rules for the `{repo}` segment and the path of a write.
    fn validate_package_path(repo: &str, path: &str) -> Result<(), &'static str>;
    /// A package payload (immutable, Range-served), from its lowercased path.
    fn is_package(lower: &str) -> bool;
    /// A stored path (relative to the repo) the reindex treats as a package.
    fn is_stored_package(rest: &str) -> bool;
    /// An index rewritten in place: served `no-cache`.
    fn revalidate(path: &str) -> bool;
    /// "name-version…" of a record, for the audit and activity log.
    fn display(record: &Self::Record) -> String;
    /// Parse a package the reindex found in storage without a sidecar.
    #[allow(clippy::result_large_err)] // the Err is the response returned at once
    fn reindex_record(
        state: &AppState,
        repo: &str,
        path: &str,
        body: &[u8],
    ) -> Result<Self::Record, Response>;
    fn regenerate<'a>(
        storage: &'a crate::Storage,
        signer: Option<&'a crate::signing::RepoSigner>,
        repo: &'a str,
    ) -> impl Future<Output = Result<(), String>> + Send + 'a;

    /// The path a read names in storage.
    fn read_path(path: &str) -> &str {
        path
    }

    /// Runs before a pull-through read goes upstream; `Some` answers the request.
    fn proxy_gate<'a>(
        _state: &'a AppState,
        _headers: &'a HeaderMap,
        _repo: &'a str,
        _entry: &'a RepoProxyEntry,
        _path: &'a str,
        _immutable: bool,
    ) -> impl Future<Output = Option<Response>> + Send + 'a {
        std::future::ready(None)
    }
}

/// GET: a pull-through repo proxies every path; a hosted one serves the signing
/// key, Range on package payloads, and the pinned body otherwise.
pub(super) async fn download<F: OsRepo>(
    state: AppState,
    headers: HeaderMap,
    repo: String,
    path: String,
) -> Response {
    let settings = F::settings(&state.config);
    if !settings.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let path = F::read_path(&path).to_string();
    // Pull-through repo: every path (including the indexes and the signing key,
    // which are server-generated only for hosted repos) proxies to the
    // configured upstream. Packages are immutable; metadata is TTL-bounded.
    if let Some(entry) = settings.proxies.get(&repo) {
        let key = F::package_key(&repo, &path);
        if validate_storage_key(&key).is_err() || path.starts_with(META_DIR) {
            return StatusCode::BAD_REQUEST.into_response();
        }
        let immutable = F::is_package(&path.to_ascii_lowercase());
        if let Some(response) =
            F::proxy_gate(&state, &headers, &repo, entry, &path, immutable).await
        {
            return response;
        }
        let url = format!("{}/{}", entry.url().trim_end_matches('/'), path);
        return crate::registry::repo_proxy_download(
            &state,
            F::NAME,
            F::REGISTRY_TYPE,
            format!("{repo}/{path}"),
            key,
            url,
            entry.auth().map(UpstreamAuth::Basic),
            settings.proxy_timeout,
            settings.metadata_ttl,
            immutable,
            F::content_type(&path),
        )
        .await;
    }
    if path == F::PUBKEY_PATH {
        return match &state.signer {
            Some(signer) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/pgp-keys")],
                signer.public_key_armored().to_string(),
            )
                .into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    let key = F::package_key(&repo, &path);
    if validate_storage_key(&key).is_err() || path.starts_with(META_DIR) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Range applies to package payloads only — the indexes are rewritten on every
    // publish, so a resumed range could splice two generations.
    let is_package = F::is_package(&path.to_ascii_lowercase());

    // 206 Partial Content, or 416 when the client asks past the end, straight from
    // the backend's ranged read — a resumed apt/dnf download transfers only the
    // bytes it is missing. A partial body cannot be rehashed, so this path skips
    // the pin check `get_verified` does below and relies on the client's own
    // checksum (the index records one) — the docker #657 precedent.
    if is_package {
        if let Some(meta) = state.storage.stat(&key).await {
            if let Some(response) = crate::registry::range::range_response(
                &state.storage,
                &[&key],
                &headers,
                meta.size,
                F::content_type(&path),
                &[],
            )
            .await
            {
                if response.status() == StatusCode::PARTIAL_CONTENT {
                    state.metrics.record_download(F::NAME);
                }
                return response;
            }
        }
    }

    match state.storage.get_verified(&key).await {
        Ok(outcome) => {
            state.metrics.record_download(F::NAME);
            state.activity.push(ActivityEntry::new(
                ActionType::Pull,
                format!("{repo}/{path}"),
                F::REGISTRY_TYPE,
                "LOCAL",
            ));
            use nora_registry::verified::{verified_body, GateOutcome};
            let data = match outcome {
                GateOutcome::Verified(blob) => verified_body(blob),
                GateOutcome::Unpinned(blob) => blob.into_inner(),
            };
            let mut builder = axum::http::Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, F::content_type(&path));
            if is_package {
                builder = builder.header(header::ACCEPT_RANGES, "bytes");
            }
            if F::revalidate(&path) {
                builder = builder.header(header::CACHE_CONTROL, "no-cache");
            }
            builder
                .body(axum::body::Body::from(data))
                .expect("valid response")
                .into_response()
        }
        Err(crate::storage::StorageError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(error = %e, key = %key, "{}: failed to read artifact", F::NAME);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// HEAD: existence and size.
pub(super) async fn check_exists<F: OsRepo>(
    state: AppState,
    repo: String,
    path: String,
) -> Response {
    if !F::settings(&state.config).enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let path = F::read_path(&path).to_string();
    let key = F::package_key(&repo, &path);
    if validate_storage_key(&key).is_err() || path.starts_with(META_DIR) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match state.storage.stat(&key).await {
        Some(meta) => (
            StatusCode::OK,
            [
                (header::CONTENT_LENGTH, meta.size.to_string()),
                (header::CONTENT_TYPE, F::content_type(&path).to_string()),
            ],
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// The checks a publish or delete runs before anything format-specific: the
/// registry is on, the repo is hosted, the path is valid.
#[allow(clippy::result_large_err)] // the Err is the response returned at once
pub(super) fn write_preflight<F: OsRepo>(
    state: &AppState,
    repo: &str,
    path: &str,
) -> Result<(), Response> {
    let settings = F::settings(&state.config);
    if !settings.enabled {
        return Err(StatusCode::NOT_FOUND.into_response());
    }
    if settings.proxies.contains_key(repo) {
        return Err(proxied_repo_conflict());
    }
    if let Err(msg) = F::validate_package_path(repo, path) {
        return Err((StatusCode::BAD_REQUEST, msg).into_response());
    }
    Ok(())
}

/// PUT after [`write_preflight`] and the format's own query checks: namespace
/// scope, size cap, parse, then package + sidecar + index rebuild under the lock.
pub(super) async fn publish<F: OsRepo>(
    state: &AppState,
    repo: &str,
    path: &str,
    authority: &NamespaceAuthority,
    user: &Option<Extension<AuthenticatedUser>>,
    body: &[u8],
    parse: impl FnOnce(&[u8]) -> Result<F::Record, Response>,
) -> Response {
    // Enforce OIDC namespace_scope on the repository name (#583).
    if enforce_namespace_scope(authority, repo).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let max_file_size = F::settings(&state.config).max_file_size;
    if body.len() as u64 > max_file_size {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("File too large. Max size: {max_file_size} bytes"),
        )
            .into_response();
    }

    let record = match parse(body) {
        Ok(r) => r,
        Err(response) => return response,
    };
    let sidecar = match serde_json::to_vec(&record) {
        Ok(j) => j,
        Err(e) => {
            tracing::error!(error = %e, "{}: failed to serialize package record", F::NAME);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let key = F::package_key(repo, path);
    if validate_storage_key(&key).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Serialize publishes/deletes per repo: the index rebuild is a
    // list-read-generate-write cycle over the whole repo (same TOCTOU
    // rationale as the maven-metadata.xml lock).
    let lock = state.publish_lock(&F::lock_key(repo));
    let _guard = lock.lock().await;

    if let Err(e) = state.storage.put(&key, body).await {
        tracing::error!(error = %e, key = %key, "{}: failed to store package", F::NAME);
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if let Err(e) = state
        .storage
        .put(&F::sidecar_key(repo, path), &sidecar)
        .await
    {
        tracing::error!(error = %e, key = %key, "{}: failed to store metadata sidecar", F::NAME);
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if let Err(e) = F::regenerate(&state.storage, state.signer.as_deref(), repo).await {
        tracing::error!(repo = %repo, error = %e, "{}: {} regeneration failed", F::NAME, F::INDEX);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Package stored but {} regeneration failed", F::INDEX),
        )
            .into_response();
    }

    let display = F::display(&record);
    state.metrics.record_upload(F::NAME);
    state.audit.log(AuditEntry::new(
        "push",
        crate::auth::audit_actor(user),
        &display,
        F::NAME,
        "",
    ));
    state.activity.push(ActivityEntry::new(
        ActionType::Push,
        format!("{repo}/{display}"),
        F::REGISTRY_TYPE,
        "LOCAL",
    ));
    state.repo_index.invalidate(F::NAME);

    StatusCode::CREATED.into_response()
}

/// DELETE: package, then its sidecar, then the index rebuild, under the lock.
pub(super) async fn delete_package<F: OsRepo>(
    state: AppState,
    repo: String,
    path: String,
    authority: NamespaceAuthority,
    user: Option<Extension<AuthenticatedUser>>,
) -> Response {
    if let Err(response) = write_preflight::<F>(&state, &repo, &path) {
        return response;
    }
    if enforce_namespace_scope(&authority, &repo).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let key = F::package_key(&repo, &path);
    if validate_storage_key(&key).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let lock = state.publish_lock(&F::lock_key(&repo));
    let _guard = lock.lock().await;

    match state.storage.delete(&key).await {
        Ok(()) => {}
        Err(crate::storage::StorageError::NotFound) => {
            return StatusCode::NOT_FOUND.into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, key = %key, "{}: failed to delete package", F::NAME);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }
    if let Err(e) = state.storage.delete(&F::sidecar_key(&repo, &path)).await {
        tracing::warn!(error = %e, key = %key, "{}: failed to delete metadata sidecar", F::NAME);
    }
    if let Err(e) = F::regenerate(&state.storage, state.signer.as_deref(), &repo).await {
        tracing::error!(repo = %repo, error = %e, "{}: {} regeneration failed", F::NAME, F::INDEX);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Package deleted but {} regeneration failed", F::INDEX),
        )
            .into_response();
    }

    state.audit.log(AuditEntry::new(
        "delete",
        crate::auth::audit_actor(&user),
        &path,
        F::NAME,
        "",
    ));
    state.repo_index.invalidate(F::NAME);
    StatusCode::NO_CONTENT.into_response()
}

/// Reconcile a repository with what is actually in storage, then rebuild
/// (and re-sign) its indexes. Heals out-of-band changes the publish path
/// never saw: packages deleted directly from storage (their stale sidecars
/// are dropped) and packages added directly to storage (parsed, sidecar
/// created). Also the re-sign hook after a signing-key change. Runs under
/// the repo publish lock, like every rebuild.
pub(super) async fn reindex<F: OsRepo>(
    state: AppState,
    repo: String,
    authority: NamespaceAuthority,
    user: Option<Extension<AuthenticatedUser>>,
) -> Response {
    let settings = F::settings(&state.config);
    if !settings.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    if repo.is_empty() || !repo.is_ascii() || repo.contains('/') || repo.starts_with('.') {
        return (StatusCode::BAD_REQUEST, "Invalid repository name").into_response();
    }
    if settings.proxies.contains_key(&repo) {
        return proxied_repo_conflict();
    }
    if enforce_namespace_scope(&authority, &repo).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }

    let lock = state.publish_lock(&F::lock_key(&repo));
    let _guard = lock.lock().await;

    let name = F::NAME;
    let prefix = format!("{name}/{repo}/");
    let keys = match state.storage.list(&prefix).await {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(error = %e, repo = %repo, "{name} reindex: list failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    if keys.is_empty() {
        return (StatusCode::NOT_FOUND, "No such repository").into_response();
    }

    let meta_prefix = format!("{name}/{repo}/{META_DIR}/");
    let mut packages: BTreeSet<String> = BTreeSet::new();
    let mut sidecars: BTreeSet<String> = BTreeSet::new();
    for key in &keys {
        if let Some(rest) = key.strip_prefix(&meta_prefix) {
            if let Some(pkg) = rest.strip_suffix(".json") {
                sidecars.insert(pkg.to_string());
            }
        } else if let Some(rest) = key.strip_prefix(&prefix) {
            if F::is_stored_package(rest) {
                packages.insert(rest.to_string());
            }
        }
    }

    // Drop sidecars whose package is gone (deleted out-of-band).
    let mut orphans_removed = 0usize;
    for stale in sidecars.difference(&packages) {
        match state.storage.delete(&F::sidecar_key(&repo, stale)).await {
            Ok(()) => orphans_removed += 1,
            Err(e) => {
                tracing::error!(error = %e, repo = %repo, pkg = %stale, "{name} reindex: orphan sidecar delete failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    }

    // Parse packages that have no sidecar (added out-of-band).
    let mut sidecars_created = 0usize;
    for missing in packages.difference(&sidecars) {
        let body = match state.storage.get(&F::package_key(&repo, missing)).await {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(error = %e, repo = %repo, pkg = %missing, "{name} reindex: package read failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        let record = match F::reindex_record(&state, &repo, missing, &body) {
            Ok(r) => r,
            Err(response) => return response,
        };
        let json = match serde_json::to_vec(&record) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!(error = %e, "{name} reindex: sidecar serialize failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        if let Err(e) = state
            .storage
            .put(&F::sidecar_key(&repo, missing), &json)
            .await
        {
            tracing::error!(error = %e, repo = %repo, pkg = %missing, "{name} reindex: sidecar write failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        sidecars_created += 1;
    }

    if let Err(e) = F::regenerate(&state.storage, state.signer.as_deref(), &repo).await {
        tracing::error!(repo = %repo, error = %e, "{name} reindex: {} regeneration failed", F::INDEX);
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    state.audit.log(AuditEntry::new(
        "reindex",
        crate::auth::audit_actor(&user),
        &repo,
        name,
        "",
    ));
    state.repo_index.invalidate(name);

    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "packages": packages.len(),
            "sidecars_created": sidecars_created,
            "orphans_removed": orphans_removed,
            "signed": state.signer.is_some(),
        })),
    )
        .into_response()
}
