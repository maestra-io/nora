// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Maestra: OIDC session tokens (issues-maestra#1649).
//!
//! A GitHub Actions JWT lives about five minutes, and a build that writes its
//! credential into a config file once (Maven `settings.xml`, `.npmrc`, a docker
//! login) outlives it. `POST /api/oidc/session` exchanges a valid JWT for an
//! `nrs_` token that lives the provider's `session_lifetime_secs`.
//!
//! A session keeps the JWT's identity, not a copy of its grant: every request
//! re-resolves the provider and its role rules from the current config, so a
//! disabled provider or a removed rule ends its sessions at once, and the
//! namespace scope is the JWT's. A session cannot mint a session, and token
//! management stays refused, as for the JWT (R2-01).
//!
//! Records are immutable and written with `put_if_absent`, so replicas share
//! them; the expiry is part of the token and of the key, so a sweep deletes
//! expired records from a listing alone.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::oidc::{OidcIdentity, OidcValidator};
use crate::audit::AuditEntry;
use crate::config::OidcProvider;
use crate::storage::{Storage, StorageError};
use crate::AppState;

/// Prefix of a session token: `nrs_<expires_at>_<64 hex>`.
pub const SESSION_TOKEN_PREFIX: &str = "nrs_";
/// The longest `session_lifetime_secs` config accepts: a GitHub-hosted job's limit.
pub const MAX_SESSION_LIFETIME_SECS: u64 = 6 * 60 * 60;
const STORAGE_PREFIX: &str = ".nora-oidc-sessions/";
pub const SESSION_ROUTE: &str = "/api/oidc/session";

/// What a session remembers of the JWT it was exchanged for.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionRecord {
    provider: String,
    issuer: String,
    subject: String,
    created_at: u64,
    expires_at: u64,
}

/// Verified records by token digest. Records never change, so an entry holds
/// until the sweep drops it at expiry.
#[derive(Default)]
pub struct SessionCache(RwLock<HashMap<String, SessionRecord>>);

#[derive(Debug)]
pub enum SessionError {
    /// Unknown, malformed or expired, or its provider no longer grants it.
    Invalid,
    /// The store did not answer: not a verdict on the credential.
    Storage(String),
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// The token's expiry, read from the token itself.
fn token_expiry(token: &str) -> Option<u64> {
    let (expires_at, secret) = token.strip_prefix(SESSION_TOKEN_PREFIX)?.split_once('_')?;
    (secret.len() == 64 && secret.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| expires_at.parse().ok())
        .flatten()
}

fn digest(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// `.nora-oidc-sessions/<expires_at>-<sha256(token)>.json`: the key carries no secret.
fn record_key(expires_at: u64, digest: &str) -> String {
    format!("{STORAGE_PREFIX}{expires_at}-{digest}.json")
}

/// The expiry a record key names, `None` for a key the sweep does not own.
fn key_expiry(key: &str) -> Option<u64> {
    key.strip_prefix(STORAGE_PREFIX)?
        .split_once('-')?
        .0
        .parse()
        .ok()
}

impl OidcValidator {
    /// The enabled provider `name`/`issuer` names, if it grants sessions. Provider
    /// names are not unique, so the issuer is matched too.
    fn session_provider(&self, name: &str, issuer: &str) -> Option<&OidcProvider> {
        self.config.providers.iter().find(|p| {
            p.enabled && p.name == name && p.issuer == issuer && p.session_lifetime_secs > 0
        })
    }

    /// Mint a session for a JWT identity. `Ok(None)`: its provider grants none.
    pub async fn mint_session(
        &self,
        storage: &Storage,
        identity: &OidcIdentity,
    ) -> Result<Option<(String, u64)>, String> {
        let Some(provider) = self.session_provider(&identity.provider, &identity.issuer) else {
            return Ok(None);
        };
        let created_at = now();
        let expires_at = created_at
            + provider
                .session_lifetime_secs
                .min(MAX_SESSION_LIFETIME_SECS);
        let token = format!(
            "{SESSION_TOKEN_PREFIX}{expires_at}_{}{}",
            Uuid::new_v4().simple(),
            Uuid::new_v4().simple()
        );
        let record = SessionRecord {
            provider: identity.provider.clone(),
            issuer: identity.issuer.clone(),
            subject: identity.subject.clone(),
            created_at,
            expires_at,
        };
        let json = serde_json::to_vec(&record).map_err(|e| e.to_string())?;
        match storage
            .put_if_absent(&record_key(expires_at, &digest(&token)), Bytes::from(json))
            .await
        {
            Ok(true) => Ok(Some((token, expires_at))),
            Ok(false) => Err("session id collision".to_string()),
            Err(e) => Err(e.to_string()),
        }
    }

    /// The identity a session token carries now, under the current config.
    pub async fn verify_session(
        &self,
        storage: &Storage,
        token: &str,
    ) -> Result<OidcIdentity, SessionError> {
        let expires_at = token_expiry(token).ok_or(SessionError::Invalid)?;
        if now() > expires_at {
            return Err(SessionError::Invalid);
        }
        let digest = digest(token);
        let cached = self.sessions.0.read().get(&digest).cloned();
        let record = match cached {
            Some(record) => record,
            None => {
                let data = match storage.get(&record_key(expires_at, &digest)).await {
                    Ok(data) => data,
                    Err(StorageError::NotFound) => return Err(SessionError::Invalid),
                    Err(e) => return Err(SessionError::Storage(e.to_string())),
                };
                let record: SessionRecord = serde_json::from_slice(&data)
                    .map_err(|e| SessionError::Storage(e.to_string()))?;
                self.sessions.0.write().insert(digest, record.clone());
                record
            }
        };
        let provider = self
            .session_provider(&record.provider, &record.issuer)
            .ok_or(SessionError::Invalid)?;
        let (role, rule_namespace_scope) = self
            .match_role(provider, &record.subject)
            .ok_or(SessionError::Invalid)?;
        Ok(OidcIdentity {
            provider: provider.name.clone(),
            subject: record.subject,
            issuer: provider.issuer.clone(),
            role,
            namespace_scope: provider.namespace_scope.clone(),
            rule_namespace_scope,
            namespace_scope_enforcement: provider.namespace_scope_enforcement,
            max_token_lifetime_secs: provider.max_token_lifetime_secs,
            expires_at: record.expires_at,
        })
    }

    /// Delete expired session records and forget them. Idempotent across replicas.
    pub async fn sweep_sessions(&self, storage: &Storage) -> usize {
        let now = now();
        self.sessions.0.write().retain(|_, r| r.expires_at >= now);
        let keys = match storage.list_internal(STORAGE_PREFIX).await {
            Ok(keys) => keys,
            Err(e) => {
                tracing::warn!(error = %e, "oidc session sweep: listing failed");
                return 0;
            }
        };
        let mut deleted = 0;
        for key in keys {
            if key_expiry(&key).is_some_and(|exp| exp < now) && storage.delete(&key).await.is_ok() {
                deleted += 1;
            }
        }
        deleted
    }
}

#[derive(Serialize)]
struct SessionResponse {
    token: String,
    expires_at: u64,
    expires_in: u64,
}

/// `POST /api/oidc/session` with `Authorization: Bearer <JWT>` (or Basic with the
/// JWT as password): a public path, the handler checks the JWT itself.
async fn exchange(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(oidc) = state.oidc.as_deref().filter(|o| o.is_active()) else {
        return (StatusCode::NOT_FOUND, "OIDC is not enabled").into_response();
    };
    let Some(jwt) = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
    else {
        return (StatusCode::UNAUTHORIZED, "An OIDC JWT is required").into_response();
    };
    if jwt.starts_with(SESSION_TOKEN_PREFIX) || jwt.starts_with("nra_") {
        return (
            StatusCode::FORBIDDEN,
            "Only an OIDC JWT is exchanged for a session",
        )
            .into_response();
    }
    let identity = match oidc.validate_token(jwt).await {
        Ok(identity) => identity,
        Err(reason) => {
            crate::metrics::record_oidc_rejection(super::oidc::classify_rejection(&reason));
            tracing::warn!(%reason, "oidc session exchange refused");
            return (StatusCode::UNAUTHORIZED, "Invalid or expired token").into_response();
        }
    };
    match oidc.mint_session(&state.storage, &identity).await {
        Ok(Some((token, expires_at))) => {
            let expires_in = expires_at.saturating_sub(now());
            state.audit.log(AuditEntry::token_mint(
                &identity.subject,
                "oidc-session",
                &identity.subject,
                &identity.role,
                expires_in,
            ));
            Json(SessionResponse {
                token,
                expires_at,
                expires_in,
            })
            .into_response()
        }
        Ok(None) => (
            StatusCode::FORBIDDEN,
            format!("OIDC provider {} grants no sessions", identity.provider),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "oidc session exchange: cannot store the session");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Session storage unavailable",
            )
                .into_response()
        }
    }
}

pub fn routes() -> Router<AppState> {
    Router::new().route(SESSION_ROUTE, post(exchange))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_names_its_expiry_and_a_key_too() {
        let secret = "a".repeat(64);
        assert_eq!(
            token_expiry(&format!("nrs_1700000000_{secret}")),
            Some(1_700_000_000)
        );
        assert_eq!(
            token_expiry(&format!("nrs_1700000000_{}", "a".repeat(63))),
            None
        );
        assert_eq!(token_expiry(&format!("nrs_x_{secret}")), None);
        assert_eq!(token_expiry(&format!("nra_1700000000_{secret}")), None);
        assert_eq!(key_expiry(&record_key(42, &digest("t"))), Some(42));
        assert_eq!(key_expiry(".nora-tokens/42-x.json"), None);
    }
}
