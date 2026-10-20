// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::storage::{Storage, StorageError};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::body::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Default TTL for cached token verifications (avoids Argon2 per request).
/// Overridable per-store via [`TokenStore::with_cache_ttl`] (config
/// `auth.token_cache_ttl`) to bound the cross-replica revocation window.
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(300);

/// Maestra: storage prefix of the token state. One immutable record per token
/// (`<16hex>.json`) plus [`LAST_USED_KEY`] and [`IMPORTED_KEY`]. `.nora-` keys are
/// internal: hidden from `Storage::list`, walked with `list_internal`.
pub const STORAGE_PREFIX: &str = ".nora-tokens/";
/// `{id: unix secs}` of every token's last use, merged into listings.
const LAST_USED_KEY: &str = ".nora-tokens/last_used.json";
/// Ids of the `auth.token_storage` files already imported once, so a token revoked
/// after the import is not brought back by the next boot.
const IMPORTED_KEY: &str = ".nora-tokens/legacy_imported.json";

fn record_key(id: &str) -> String {
    format!("{STORAGE_PREFIX}{id}.json")
}

/// Cached verification result
#[derive(Clone)]
struct CachedToken {
    user: String,
    role: Role,
    expires_at: u64,
    cached_at: Instant,
}

const TOKEN_PREFIX: &str = "nra_";

/// Longest token lifetime any mint path may request (10 years).
pub const MAX_TOKEN_TTL_DAYS: u64 = 3650;

/// Access role for API tokens
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Role {
    Read,
    Write,
    Admin,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Read => write!(f, "read"),
            Role::Write => write!(f, "write"),
            Role::Admin => write!(f, "admin"),
        }
    }
}

impl Role {
    pub fn can_write(&self) -> bool {
        matches!(self, Role::Write | Role::Admin)
    }

    pub fn can_admin(&self) -> bool {
        matches!(self, Role::Admin)
    }
}

/// API token record, stored as `.nora-tokens/<16hex>.json`. Written once at creation
/// (and by the legacy SHA-256 -> Argon2 rewrite), never by the last_used flush.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    pub token_hash: String,
    pub user: String,
    pub created_at: u64,
    pub expires_at: u64,
    /// Set only in records written before last_used moved to [`LAST_USED_KEY`].
    pub last_used: Option<u64>,
    pub description: Option<String>,
    #[serde(default = "default_role")]
    pub role: Role,
}

fn default_role() -> Role {
    Role::Read
}

/// Token list entry for UI display (no hash exposed)
#[derive(Debug, Clone, Serialize)]
pub struct TokenListEntry {
    pub file_id: String,
    pub user: String,
    pub role: Role,
    pub created_at: u64,
    pub expires_at: u64,
    pub last_used: Option<u64>,
    pub description: Option<String>,
}

/// Token store for managing API tokens
#[derive(Clone)]
pub struct TokenStore {
    storage: Storage,
    /// In-memory cache: SHA256(token) -> verified result (avoids Argon2 per request)
    cache: Arc<RwLock<HashMap<String, CachedToken>>>,
    /// How long a cached verification is trusted before the slow path re-reads
    /// storage. Shorter = smaller cross-replica revocation window.
    cache_ttl: Duration,
    /// Pending last_used updates: file_id_prefix -> timestamp (flushed periodically)
    pending_last_used: Arc<RwLock<HashMap<String, u64>>>,
}

impl TokenStore {
    /// Create a new token store over `storage` with the default verify-cache TTL.
    pub fn new(storage: Storage) -> Self {
        Self::with_cache_ttl(storage, DEFAULT_CACHE_TTL)
    }

    /// Create a token store with an explicit verify-cache TTL. A shorter TTL
    /// bounds the window in which a token revoked on another replica is still
    /// served from this replica's cache.
    pub fn with_cache_ttl(storage: Storage, cache_ttl: Duration) -> Self {
        Self {
            storage,
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl,
            pending_last_used: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate a new API token for a user. `ttl_days` is clamped to
    /// `1..=MAX_TOKEN_TTL_DAYS` for every caller (an unbounded value overflows).
    pub async fn create_token(
        &self,
        user: &str,
        ttl_days: u64,
        description: Option<String>,
        role: Role,
    ) -> Result<String, TokenError> {
        // Generate random token
        let raw_token = format!(
            "{}{}",
            TOKEN_PREFIX,
            Uuid::new_v4().to_string().replace("-", "")
        );
        let token_hash = hash_token_argon2(&raw_token)?;
        // Use SHA256 of token as the record id (deterministic, for lookup)
        let file_id = sha256_hex(&raw_token);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let ttl_days = ttl_days.clamp(1, MAX_TOKEN_TTL_DAYS);
        let expires_at = now + (ttl_days * 24 * 60 * 60);

        let info = TokenInfo {
            token_hash,
            user: user.to_string(),
            created_at: now,
            expires_at,
            last_used: None,
            description,
            role,
        };

        let json =
            serde_json::to_vec_pretty(&info).map_err(|e| TokenError::Storage(e.to_string()))?;
        // Never overwrite a record: an existing one is a 64-bit id collision.
        match self
            .storage
            .put_if_absent(&record_key(&file_id[..16]), Bytes::from(json))
            .await
        {
            Ok(true) => Ok(raw_token),
            Ok(false) => Err(TokenError::Storage("token id collision".into())),
            Err(e) => Err(TokenError::Storage(e.to_string())),
        }
    }

    /// Verify a token and return user info if valid.
    ///
    /// Uses an in-memory cache to avoid Argon2 verification on every request.
    /// The `last_used` timestamp is updated in batch via `flush_last_used()`.
    pub async fn verify_token(&self, token: &str) -> Result<(String, Role), TokenError> {
        if !token.starts_with(TOKEN_PREFIX) {
            return Err(TokenError::InvalidFormat);
        }

        let cache_key = sha256_hex(token);

        // Fast path: check in-memory cache
        {
            let cache = self.cache.read();
            if let Some(cached) = cache.get(&cache_key) {
                if cached.cached_at.elapsed() < self.cache_ttl {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    if now > cached.expires_at {
                        return Err(TokenError::Expired);
                    }
                    // Schedule deferred last_used update
                    self.pending_last_used
                        .write()
                        .insert(cache_key[..16].to_string(), now);
                    return Ok((cached.user.clone(), cached.role.clone()));
                }
            }
        }

        // Slow path: one storage read and Argon2. Misses are not cached (no negative
        // cache): an unknown token costs a read each time, and brute force is bounded
        // by the auth rate limiter, not here.
        let key = record_key(&cache_key[..16]);
        let content = match self.storage.get(&key).await {
            Ok(c) => c,
            Err(StorageError::NotFound) => return Err(TokenError::NotFound),
            Err(e) => return Err(TokenError::Storage(e.to_string())),
        };

        let mut info: TokenInfo =
            serde_json::from_slice(&content).map_err(|e| TokenError::Storage(e.to_string()))?;

        // Verify hash: try Argon2id first, fall back to legacy SHA256
        let hash_valid = if info.token_hash.starts_with("$argon2") {
            verify_token_argon2(token, &info.token_hash)
        } else {
            // Legacy SHA256 hash (no salt) — verify and migrate
            let legacy_hash = sha256_hex(token);
            if info.token_hash == legacy_hash {
                // Migrate to Argon2id
                if let Ok(new_hash) = hash_token_argon2(token) {
                    info.token_hash = new_hash;
                    if let Ok(json) = serde_json::to_vec_pretty(&info) {
                        let _ = self.storage.put(&key, &json).await;
                    }
                }
                true
            } else {
                false
            }
        };

        if !hash_valid {
            return Err(TokenError::NotFound);
        }

        // Check expiration
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now > info.expires_at {
            return Err(TokenError::Expired);
        }

        // Populate cache (key must match the fast-path lookup: full 64-char SHA-256 hex)
        self.cache.write().insert(
            cache_key.clone(),
            CachedToken {
                user: info.user.clone(),
                role: info.role.clone(),
                expires_at: info.expires_at,
                cached_at: Instant::now(),
            },
        );

        // Schedule deferred last_used update
        self.pending_last_used
            .write()
            .insert(cache_key[..16].to_string(), now);

        Ok((info.user, info.role))
    }

    /// List all tokens for a user (returns TokenListEntry with file_id)
    pub async fn list_tokens(&self, user: &str) -> Vec<TokenListEntry> {
        self.list_all_tokens()
            .await
            .into_iter()
            .filter(|t| t.user == user)
            .collect()
    }

    /// List all tokens across all users (for admin UI)
    // ponytail: one GET per record, concurrently; fine for hundreds of tokens, an
    // in-memory index if it ever has to serve thousands.
    pub async fn list_all_tokens(&self) -> Vec<TokenListEntry> {
        let keys = match self.storage.list_internal(STORAGE_PREFIX).await {
            Ok(keys) => keys,
            Err(e) => {
                tracing::warn!(error = %e, "token list failed");
                return Vec::new();
            }
        };
        let ids = keys.iter().filter_map(|k| {
            k.strip_prefix(STORAGE_PREFIX)
                .and_then(|n| n.strip_suffix(".json"))
                .filter(|id| is_valid_hash_prefix(id))
        });
        let records = futures::future::join_all(
            ids.map(|id| async move { (id, self.storage.get(&record_key(id)).await) }),
        )
        .await;
        let last_used: HashMap<String, u64> = self
            .read_state(LAST_USED_KEY)
            .await
            .ok()
            .flatten()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();

        let mut tokens = Vec::new();
        for (id, content) in records {
            let Some(info) = content
                .ok()
                .and_then(|c| serde_json::from_slice::<TokenInfo>(&c).ok())
            else {
                continue;
            };
            tokens.push(TokenListEntry {
                file_id: id.to_string(),
                user: info.user,
                role: info.role,
                created_at: info.created_at,
                expires_at: info.expires_at,
                last_used: last_used.get(id).copied().or(info.last_used),
                description: info.description,
            });
        }

        tokens.sort_by_key(|t| std::cmp::Reverse(t.created_at));
        tokens
    }

    /// A small state object: `None` when it does not exist yet.
    async fn read_state(&self, key: &str) -> Result<Option<Bytes>, StorageError> {
        match self.storage.get(key).await {
            Ok(b) => Ok(Some(b)),
            Err(StorageError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Flush pending last_used timestamps to [`LAST_USED_KEY`]: one read and one
    /// write, only when a token was used since the last flush. Records are never
    /// rewritten, so a flush cannot bring back a token revoked meanwhile.
    /// Called periodically by background task (every 30s).
    // ponytail: replicas flushing at once can drop each other's stamps (advisory
    // data), and ids of revoked tokens stay in the map (a few bytes each).
    pub async fn flush_last_used(&self) {
        let pending: HashMap<String, u64> = {
            let mut map = self.pending_last_used.write();
            std::mem::take(&mut *map)
        };

        if pending.is_empty() {
            return;
        }

        // A map that does not parse is rebuilt; one that cannot be read is not
        // overwritten (that would drop every other token's stamp).
        let mut map: HashMap<String, u64> = match self.read_state(LAST_USED_KEY).await {
            Ok(b) => b
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or_default(),
            Err(e) => {
                tracing::warn!(error = %e, "token last_used read failed, flush skipped");
                return;
            }
        };
        for (id, ts) in &pending {
            let stamp = map.entry(id.clone()).or_insert(0);
            *stamp = (*stamp).max(*ts);
        }
        let result = match serde_json::to_vec(&map) {
            Ok(json) => self.storage.put(LAST_USED_KEY, &json).await,
            Err(e) => Err(StorageError::Io(std::io::Error::other(e))),
        };
        match result {
            Ok(()) => tracing::debug!(count = pending.len(), "Flushed pending last_used updates"),
            Err(e) => tracing::warn!(error = %e, "token last_used flush failed"),
        }
    }

    /// Remove a token from the in-memory cache (called on revoke).
    /// Cache keys are full 64-char SHA-256 hex; revoke only knows the 16-char prefix,
    /// so we must scan for matching entries.
    fn invalidate_cache(&self, hash_prefix: &str) {
        self.cache
            .write()
            .retain(|k, _| !k.starts_with(hash_prefix));
    }

    /// Revoke a token by its hash prefix.
    ///
    /// `hash_prefix` must be exactly 16 lowercase hexadecimal characters (the
    /// first 16 chars of SHA-256(token)). Anything else is rejected to prevent
    /// path-traversal attacks via crafted prefixes like `../../etc/passwd`.
    pub async fn revoke_token(&self, hash_prefix: &str) -> Result<(), TokenError> {
        // SECURITY: validate format before building a storage key
        if !is_valid_hash_prefix(hash_prefix) {
            return Err(TokenError::NotFound);
        }
        let key = record_key(hash_prefix);
        // An object-store delete of a missing key succeeds, so ask first.
        match self.storage.stat(&key).await {
            Some(_) => {}
            None => return Err(TokenError::NotFound),
        }
        match self.storage.delete(&key).await {
            Ok(()) => {
                self.invalidate_cache(hash_prefix);
                Ok(())
            }
            Err(StorageError::NotFound) => Err(TokenError::NotFound),
            Err(e) => Err(TokenError::Storage(e.to_string())),
        }
    }

    /// Revoke all tokens for a user
    pub async fn revoke_all_for_user(&self, user: &str) -> usize {
        let mut count = 0;
        for token in self.list_tokens(user).await {
            if self.revoke_token(&token.file_id).await.is_ok() {
                count += 1;
            }
        }
        count
    }

    /// Maestra: import the token files of the pre-storage layout (`<16hex>.json` in
    /// `auth.token_storage`) at boot. Each file is imported at most once, and never
    /// over an existing record; the files stay. A missing directory is a no-op.
    /// Returns (imported now, imported before or already present).
    pub async fn import_legacy_dir(&self, dir: &Path) -> (usize, usize) {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (0, 0),
            Err(e) => {
                tracing::error!(dir = %dir.display(), error = %e, "legacy token import: cannot read directory");
                return (0, 0);
            }
        };
        // Unreadable set: import nothing rather than re-import a revoked token.
        let done = match self.read_state(IMPORTED_KEY).await {
            Ok(None) => Ok(BTreeSet::new()),
            Ok(Some(b)) => serde_json::from_slice(&b).map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        };
        let mut done: BTreeSet<String> = match done {
            Ok(set) => set,
            Err(e) => {
                tracing::error!(error = %e, "legacy token import: cannot read {IMPORTED_KEY}");
                return (0, 0);
            }
        };
        let before = done.len();
        let (mut imported, mut present, mut failed) = (0, 0, 0);
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(id) = name
                .strip_suffix(".json")
                .filter(|id| is_valid_hash_prefix(id))
            else {
                continue;
            };
            if done.contains(id) {
                present += 1;
                continue;
            }
            let data = match fs::read(entry.path()) {
                Ok(d) if serde_json::from_slice::<TokenInfo>(&d).is_ok() => d,
                _ => {
                    tracing::warn!(file = %entry.path().display(), "legacy token import: unreadable token file skipped");
                    failed += 1;
                    continue;
                }
            };
            match self
                .storage
                .put_if_absent(&record_key(id), Bytes::from(data))
                .await
            {
                Ok(true) => imported += 1,
                Ok(false) => present += 1,
                Err(e) => {
                    tracing::warn!(id, error = %e, "legacy token import failed");
                    failed += 1;
                    continue;
                }
            }
            done.insert(id.to_string());
        }
        if imported + present + failed == 0 {
            return (0, 0);
        }
        if done.len() != before {
            if let Ok(json) = serde_json::to_vec(&done) {
                if let Err(e) = self.storage.put(IMPORTED_KEY, &json).await {
                    tracing::warn!(error = %e, "legacy token import: cannot write {IMPORTED_KEY}");
                }
            }
        }
        tracing::info!(
            dir = %dir.display(),
            imported,
            present,
            failed,
            "imported {imported} tokens from {}, {present} already present",
            dir.display()
        );
        (imported, present)
    }
}

/// Validate a hash prefix: must be exactly 16 lowercase hex characters (`[0-9a-f]`).
///
/// Token records are keyed `{sha256(token)[..16]}.json` (always lowercase via
/// `hex::encode`). We restrict to lowercase only to prevent case-mismatch
/// issues on case-sensitive filesystems.
fn is_valid_hash_prefix(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Store a token record from a pre-storage backup archive (`.nora-local/tokens/<name>`)
/// under [`STORAGE_PREFIX`], replacing a record of the same name. The name and body
/// come from an archive, so both are checked: a flat `<16hex>.json` name and a
/// parsable [`TokenInfo`].
pub async fn import_record(storage: &Storage, name: &str, data: &[u8]) -> Result<(), String> {
    if !name.strip_suffix(".json").is_some_and(is_valid_hash_prefix) {
        return Err(format!("not a token record name: {name:?}"));
    }
    serde_json::from_slice::<TokenInfo>(data)
        .map_err(|e| format!("token record {name} is not valid: {e}"))?;
    storage
        .put(&format!("{STORAGE_PREFIX}{name}"), data)
        .await
        .map_err(|e| format!("token record {name}: {e}"))
}

/// Hash a token using Argon2id with random salt
fn hash_token_argon2(token: &str) -> Result<String, TokenError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(token.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| TokenError::Storage(format!("hash error: {e}")))
}

/// Verify a token against an Argon2id hash
fn verify_token_argon2(token: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(token.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// SHA256 hex digest (used for file naming and legacy hash verification)
fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("Invalid token format")]
    InvalidFormat,

    #[error("Token not found")]
    NotFound,

    #[error("Token expired")]
    Expired,

    #[error("Storage error: {0}")]
    Storage(String),
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// A local-backend storage in `dir` (the token state lives in storage).
    fn local(dir: &TempDir) -> Storage {
        Storage::new_local(dir.path().to_str().unwrap())
    }

    async fn read_record(storage: &Storage, token: &str) -> TokenInfo {
        let key = record_key(&sha256_hex(token)[..16]);
        serde_json::from_slice(&storage.get(&key).await.unwrap()).unwrap()
    }

    async fn write_record(storage: &Storage, id: &str, info: &TokenInfo) {
        let json = serde_json::to_vec_pretty(info).unwrap();
        storage.put(&record_key(id), &json).await.unwrap();
    }

    #[tokio::test]
    async fn test_create_token() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(local(&temp_dir));

        let token = store
            .create_token("testuser", 30, Some("Test token".to_string()), Role::Write)
            .await
            .unwrap();

        assert!(token.starts_with("nra_"));
        assert_eq!(token.len(), 4 + 32); // prefix + uuid without dashes
    }

    /// Every mint path goes through `create_token`, so the TTL clamp lives there:
    /// 0 becomes one day and an overflowing `u64::MAX` becomes 10 years.
    #[tokio::test]
    async fn test_create_token_clamps_ttl() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(local(&temp_dir));
        store
            .create_token("zero", 0, None, Role::Read)
            .await
            .unwrap();
        store
            .create_token("huge", u64::MAX, None, Role::Read)
            .await
            .unwrap();

        for (user, days) in [("zero", 1), ("huge", MAX_TOKEN_TTL_DAYS)] {
            let t = &store.list_tokens(user).await[0];
            assert_eq!((t.expires_at - t.created_at) / 86400, days);
        }
    }

    /// The verify-cache TTL bounds the cross-replica revocation window. Two
    /// stores share one storage (= two HA replicas, each with its own in-memory
    /// cache). A token revoked on replica A is still served from replica B's cache
    /// until B's `cache_ttl` elapses — and a short TTL bounds exactly that window.
    #[tokio::test]
    async fn cache_ttl_bounds_cross_replica_revocation_window() {
        let dir = TempDir::new().unwrap();
        let replica_a = TokenStore::new(local(&dir));
        let replica_b =
            TokenStore::with_cache_ttl(replica_a.storage.clone(), Duration::from_secs(1));

        let token = replica_a
            .create_token("u", 30, None, Role::Write)
            .await
            .unwrap();

        // B verifies and caches the token.
        assert!(replica_b.verify_token(&token).await.is_ok());

        // A revokes it (deletes the record + clears A's cache). B's cache is
        // untouched — there is no cross-pod invalidation.
        let hash_prefix = sha256_hex(&token)[..16].to_string();
        replica_a.revoke_token(&hash_prefix).await.unwrap();

        // WITHIN cache_ttl, B still serves the revoked token from cache — the
        // documented window.
        assert!(
            replica_b.verify_token(&token).await.is_ok(),
            "within cache_ttl, B serves from cache (bounded window)"
        );

        // After cache_ttl, B's entry is stale -> slow path re-reads storage -> the
        // revoked (deleted) token is rejected. The TTL bounds the window.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(
            matches!(
                replica_b.verify_token(&token).await,
                Err(TokenError::NotFound)
            ),
            "after cache_ttl, B re-reads storage and rejects the revoked token"
        );
    }

    #[tokio::test]
    async fn test_token_hash_is_argon2() {
        let temp_dir = TempDir::new().unwrap();
        let storage = local(&temp_dir);
        let store = TokenStore::new(storage.clone());

        let token = store
            .create_token("testuser", 30, None, Role::Write)
            .await
            .unwrap();

        assert!(read_record(&storage, &token)
            .await
            .token_hash
            .starts_with("$argon2"));
        let tokens = store.list_all_tokens().await;
        // Verify file_id is a hex prefix, not an Argon2 hash
        assert!(
            tokens[0].file_id.chars().all(|c| c.is_ascii_hexdigit()),
            "file_id must be hex, got: {}",
            tokens[0].file_id
        );
        assert_eq!(tokens[0].file_id.len(), 16);
    }

    #[tokio::test]
    async fn test_verify_valid_token() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(local(&temp_dir));

        let token = store
            .create_token("testuser", 30, None, Role::Write)
            .await
            .unwrap();
        let (user, role) = store.verify_token(&token).await.unwrap();

        assert_eq!(user, "testuser");
        assert_eq!(role, Role::Write);
    }

    /// A token minted before a restart verifies on the next process: a new store
    /// over the same storage, with a cold cache.
    #[tokio::test]
    async fn token_verifies_after_restart() {
        let temp_dir = TempDir::new().unwrap();
        let token = TokenStore::new(local(&temp_dir))
            .create_token("ci", 30, None, Role::Write)
            .await
            .unwrap();

        let restarted = TokenStore::new(local(&temp_dir));
        assert_eq!(
            restarted.verify_token(&token).await.unwrap(),
            ("ci".to_string(), Role::Write)
        );
        assert_eq!(restarted.list_tokens("ci").await.len(), 1);
    }

    #[tokio::test]
    async fn test_verify_invalid_format() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(local(&temp_dir));

        let result = store.verify_token("invalid_token").await;
        assert!(matches!(result, Err(TokenError::InvalidFormat)));
    }

    #[tokio::test]
    async fn test_verify_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(local(&temp_dir));

        let result = store
            .verify_token("nra_00000000000000000000000000000000")
            .await;
        assert!(matches!(result, Err(TokenError::NotFound)));
    }

    #[tokio::test]
    async fn test_verify_expired_token() {
        let temp_dir = TempDir::new().unwrap();
        let storage = local(&temp_dir);
        let store = TokenStore::new(storage.clone());

        let token = store
            .create_token("testuser", 1, None, Role::Write)
            .await
            .unwrap();
        let mut info = read_record(&storage, &token).await;
        info.expires_at = 0;
        write_record(&storage, &sha256_hex(&token)[..16], &info).await;

        let result = store.verify_token(&token).await;
        assert!(matches!(result, Err(TokenError::Expired)));
    }

    #[tokio::test]
    async fn test_legacy_sha256_migration() {
        let temp_dir = TempDir::new().unwrap();
        let storage = local(&temp_dir);
        let store = TokenStore::new(storage.clone());

        // Simulate a legacy token with SHA256 hash
        let raw_token = "nra_00112233445566778899aabbccddeeff";
        let legacy_hash = sha256_hex(raw_token);
        let file_id = sha256_hex(raw_token);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let info = TokenInfo {
            token_hash: legacy_hash.clone(),
            user: "legacyuser".to_string(),
            created_at: now,
            expires_at: now + 86400,
            last_used: None,
            description: None,
            role: Role::Read,
        };
        write_record(&storage, &file_id[..16], &info).await;

        // Verify should work with legacy hash
        let (user, role) = store.verify_token(raw_token).await.unwrap();
        assert_eq!(user, "legacyuser");
        assert_eq!(role, Role::Read);

        // After verification, hash should be migrated to Argon2id
        let updated = read_record(&storage, raw_token).await;
        assert!(updated.token_hash.starts_with("$argon2"));
    }

    #[tokio::test]
    async fn test_list_tokens() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(local(&temp_dir));

        store
            .create_token("user1", 30, None, Role::Write)
            .await
            .unwrap();
        store
            .create_token("user1", 30, None, Role::Write)
            .await
            .unwrap();
        store
            .create_token("user2", 30, None, Role::Read)
            .await
            .unwrap();

        let user1_tokens = store.list_tokens("user1").await;
        assert_eq!(user1_tokens.len(), 2);

        let user2_tokens = store.list_tokens("user2").await;
        assert_eq!(user2_tokens.len(), 1);

        let unknown_tokens = store.list_tokens("unknown").await;
        assert_eq!(unknown_tokens.len(), 0);
    }

    /// Token keys are internal: no registry walk (`Storage::list`) sees them.
    #[tokio::test]
    async fn test_token_keys_hidden_from_list() {
        let temp_dir = TempDir::new().unwrap();
        let storage = local(&temp_dir);
        let store = TokenStore::new(storage.clone());
        let token = store.create_token("u", 30, None, Role::Read).await.unwrap();
        store.verify_token(&token).await.unwrap();
        store.flush_last_used().await;

        assert!(storage.list("").await.unwrap().is_empty());
        assert_eq!(
            storage.list_internal(STORAGE_PREFIX).await.unwrap().len(),
            2
        );
    }

    #[tokio::test]
    async fn test_list_all_tokens() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(local(&temp_dir));

        store
            .create_token("user1", 30, Some("Token A".to_string()), Role::Write)
            .await
            .unwrap();
        store
            .create_token("user2", 30, None, Role::Read)
            .await
            .unwrap();
        store
            .create_token("user1", 30, Some("Token B".to_string()), Role::Admin)
            .await
            .unwrap();

        let all = store.list_all_tokens().await;
        assert_eq!(all.len(), 3);

        // All file_ids should be 16 hex chars
        for entry in &all {
            assert_eq!(entry.file_id.len(), 16);
            assert!(entry.file_id.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[tokio::test]
    async fn test_file_id_matches_revoke() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(local(&temp_dir));

        let token = store
            .create_token("testuser", 30, None, Role::Write)
            .await
            .unwrap();

        // Get file_id from list
        let entries = store.list_all_tokens().await;
        assert_eq!(entries.len(), 1);
        let file_id = &entries[0].file_id;

        // Revoke using file_id from list
        store.revoke_token(file_id).await.unwrap();

        // Token should be gone
        assert!(store.verify_token(&token).await.is_err());
        assert_eq!(store.list_all_tokens().await.len(), 0);
    }

    #[tokio::test]
    async fn test_revoke_token() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(local(&temp_dir));

        let token = store
            .create_token("testuser", 30, None, Role::Write)
            .await
            .unwrap();
        let file_id = sha256_hex(&token);
        let hash_prefix = &file_id[..16];

        assert!(store.verify_token(&token).await.is_ok());

        store.revoke_token(hash_prefix).await.unwrap();

        let result = store.verify_token(&token).await;
        assert!(matches!(result, Err(TokenError::NotFound)));
    }

    #[tokio::test]
    async fn test_revoke_nonexistent_token() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(local(&temp_dir));

        let result = store.revoke_token("nonexistent12345").await;
        assert!(matches!(result, Err(TokenError::NotFound)));
        let result = store.revoke_token("0123456789abcdef").await;
        assert!(matches!(result, Err(TokenError::NotFound)));
    }

    #[tokio::test]
    async fn test_revoke_all_for_user() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(local(&temp_dir));

        store
            .create_token("user1", 30, None, Role::Write)
            .await
            .unwrap();
        store
            .create_token("user1", 30, None, Role::Write)
            .await
            .unwrap();
        store
            .create_token("user2", 30, None, Role::Read)
            .await
            .unwrap();

        let revoked = store.revoke_all_for_user("user1").await;
        assert_eq!(revoked, 2);

        assert_eq!(store.list_tokens("user1").await.len(), 0);
        assert_eq!(store.list_tokens("user2").await.len(), 1);
    }

    #[tokio::test]
    async fn test_token_updates_last_used() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(local(&temp_dir));

        let token = store
            .create_token("testuser", 30, None, Role::Write)
            .await
            .unwrap();

        store.verify_token(&token).await.unwrap();

        // last_used is deferred — flush to persist
        store.flush_last_used().await;

        let tokens = store.list_tokens("testuser").await;
        assert!(tokens[0].last_used.is_some());
        // and survives a restart
        let restarted = TokenStore::new(store.storage.clone());
        assert_eq!(
            restarted.list_tokens("testuser").await[0].last_used,
            tokens[0].last_used
        );
    }

    /// The flush writes only the last_used map, never a record: a token revoked
    /// between its use and the next flush stays revoked (the old per-record
    /// rewrite renamed a fresh copy over the deleted file and brought it back).
    #[tokio::test]
    async fn revoke_then_flush_does_not_resurrect() {
        let temp_dir = TempDir::new().unwrap();
        let storage = local(&temp_dir);
        let store = TokenStore::new(storage.clone());
        let token = store
            .create_token("ci", 30, None, Role::Write)
            .await
            .unwrap();
        let record = read_record(&storage, &token).await;

        // Used (a pending last_used), then revoked before the flush.
        store.verify_token(&token).await.unwrap();
        let id = &sha256_hex(&token)[..16];
        store.revoke_token(id).await.unwrap();
        store.flush_last_used().await;

        assert!(storage.stat(&record_key(id)).await.is_none());
        assert!(store.list_all_tokens().await.is_empty());
        let cold = TokenStore::new(storage.clone());
        assert!(matches!(
            cold.verify_token(&token).await,
            Err(TokenError::NotFound)
        ));
        // A flush never touched the record before the revoke either.
        assert_eq!(record.last_used, None);
    }

    #[tokio::test]
    async fn test_verify_cache_hit() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(local(&temp_dir));

        let token = store
            .create_token("testuser", 30, None, Role::Write)
            .await
            .unwrap();

        assert_eq!(
            store.cache.read().len(),
            0,
            "cache should be empty before first verify"
        );

        // First call: cold (storage + Argon2)
        let (user1, role1) = store.verify_token(&token).await.unwrap();
        assert_eq!(
            store.cache.read().len(),
            1,
            "cache should have 1 entry after first verify"
        );

        // Second call: should hit cache (no Argon2)
        let (user2, role2) = store.verify_token(&token).await.unwrap();
        assert_eq!(store.cache.read().len(), 1, "cache size unchanged on hit");

        assert_eq!(user1, user2);
        assert_eq!(role1, role2);
        assert_eq!(user1, "testuser");
        assert_eq!(role1, Role::Write);

        // Verify cache key is the full SHA-256 hex (64 chars), not a 16-char prefix
        let expected_key = sha256_hex(&token);
        assert!(
            store.cache.read().contains_key(&expected_key),
            "cache key must be full 64-char SHA-256"
        );
    }

    #[tokio::test]
    async fn test_revoke_invalidates_cache() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(local(&temp_dir));

        let token = store
            .create_token("testuser", 30, None, Role::Write)
            .await
            .unwrap();
        let file_id = sha256_hex(&token);
        let hash_prefix = &file_id[..16];

        // Populate cache
        assert!(store.verify_token(&token).await.is_ok());

        // Revoke
        store.revoke_token(hash_prefix).await.unwrap();

        // Cache should be invalidated
        let result = store.verify_token(&token).await;
        assert!(matches!(result, Err(TokenError::NotFound)));
    }

    #[tokio::test]
    async fn test_revoke_all_clears_cache() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(local(&temp_dir));

        let token1 = store
            .create_token("alice", 30, None, Role::Write)
            .await
            .unwrap();
        let token2 = store
            .create_token("alice", 30, None, Role::Read)
            .await
            .unwrap();
        let token3 = store
            .create_token("bob", 30, None, Role::Write)
            .await
            .unwrap();

        // Populate cache for all tokens
        store.verify_token(&token1).await.unwrap();
        store.verify_token(&token2).await.unwrap();
        store.verify_token(&token3).await.unwrap();
        assert_eq!(store.cache.read().len(), 3);

        // Revoke all tokens for alice
        let revoked = store.revoke_all_for_user("alice").await;
        assert_eq!(revoked, 2);

        // Alice's cache entries should be gone, bob's should remain
        assert_eq!(store.cache.read().len(), 1);
        assert!(
            store.verify_token(&token3).await.is_ok(),
            "bob's token should still work"
        );
        assert!(
            store.verify_token(&token1).await.is_err(),
            "alice's token should be revoked"
        );
    }

    #[tokio::test]
    async fn test_token_with_description() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(local(&temp_dir));

        store
            .create_token(
                "testuser",
                30,
                Some("CI/CD Pipeline".to_string()),
                Role::Admin,
            )
            .await
            .unwrap();

        let tokens = store.list_tokens("testuser").await;
        assert_eq!(tokens[0].description, Some("CI/CD Pipeline".to_string()));
    }

    // -- hash_prefix validation (path traversal prevention) --

    #[test]
    fn test_is_valid_hash_prefix() {
        assert!(is_valid_hash_prefix("0123456789abcdef"));
        assert!(is_valid_hash_prefix("deadbeefcafe1234"));
        // uppercase hex is rejected (token hashes are always lowercase)
        assert!(!is_valid_hash_prefix("0123456789ABCDEF"));
    }

    #[test]
    fn test_is_valid_hash_prefix_rejects_bad() {
        assert!(!is_valid_hash_prefix(""));
        assert!(!is_valid_hash_prefix("short"));
        assert!(!is_valid_hash_prefix("0123456789abcde")); // 15 chars
        assert!(!is_valid_hash_prefix("0123456789abcdef0")); // 17 chars
        assert!(!is_valid_hash_prefix("../../etc/passwd")); // path traversal
        assert!(!is_valid_hash_prefix("..%2f..%2fetcpwd")); // encoded traversal
        assert!(!is_valid_hash_prefix("zzzzzzzzzzzzzzzz")); // non-hex
    }

    /// A corrupt token record must surface as `Storage`, not `NotFound` —
    /// the auth middleware maps `Storage` to 503 (retryable outage) and
    /// everything else to 401 (credential verdict). Misclassifying a corrupt
    /// record as `NotFound` turns a storage blip into an auth denial.
    #[tokio::test]
    async fn verify_reports_storage_error_on_corrupt_file() {
        let temp_dir = TempDir::new().unwrap();
        let storage = local(&temp_dir);
        let store = TokenStore::new(storage.clone());
        let token = store
            .create_token("ci", 30, None, Role::Read)
            .await
            .unwrap();

        let key = record_key(&sha256_hex(&token)[..16]);
        storage.put(&key, b"{\"token_ha").await.unwrap();

        assert!(matches!(
            store.verify_token(&token).await,
            Err(TokenError::Storage(_))
        ));
    }

    /// The boot import copies each legacy `<16hex>.json` file into storage once:
    /// a second boot imports nothing, an existing record is never overwritten,
    /// and a token revoked after the import is not brought back. Other files are
    /// ignored, and a missing directory is a no-op.
    #[tokio::test]
    async fn legacy_dir_import_is_idempotent() {
        let temp_dir = TempDir::new().unwrap();
        let storage = local(&temp_dir);
        let legacy = TempDir::new().unwrap();

        // Two token files of the old layout, one stray file.
        let old = TokenStore::new(Storage::new_local(legacy.path().to_str().unwrap()));
        let t1 = old.create_token("a", 30, None, Role::Write).await.unwrap();
        let t2 = old.create_token("b", 30, None, Role::Read).await.unwrap();
        for t in [&t1, &t2] {
            let id = &sha256_hex(t)[..16];
            let src = legacy.path().join(record_key(id));
            fs::copy(&src, legacy.path().join(format!("{id}.json"))).unwrap();
        }
        fs::write(legacy.path().join("notes.json"), "{}").unwrap();

        let store = TokenStore::new(storage.clone());
        assert_eq!(
            store
                .import_legacy_dir(&legacy.path().join("missing"))
                .await,
            (0, 0)
        );
        assert_eq!(store.import_legacy_dir(legacy.path()).await, (2, 0));
        assert_eq!(store.verify_token(&t1).await.unwrap().0, "a");
        assert_eq!(store.verify_token(&t2).await.unwrap().0, "b");

        // Next boot: nothing new.
        let next = TokenStore::new(storage.clone());
        assert_eq!(next.import_legacy_dir(legacy.path()).await, (0, 2));

        // Revoked after the import: the file is still there, the token stays gone.
        next.revoke_token(&sha256_hex(&t1)[..16]).await.unwrap();
        let after = TokenStore::new(storage.clone());
        assert_eq!(after.import_legacy_dir(legacy.path()).await, (0, 2));
        assert!(matches!(
            after.verify_token(&t1).await,
            Err(TokenError::NotFound)
        ));
        assert!(legacy
            .path()
            .join(format!("{}.json", &sha256_hex(&t1)[..16]))
            .exists());

        // A record already in storage is never overwritten by a file of the same id.
        let fresh = TempDir::new().unwrap();
        let fresh_store = TokenStore::new(local(&fresh));
        let id2 = &sha256_hex(&t2)[..16];
        let mut theirs = read_record(&storage, &t2).await;
        theirs.user = "kept".into();
        write_record(&fresh_store.storage, id2, &theirs).await;
        assert_eq!(fresh_store.import_legacy_dir(legacy.path()).await, (1, 1));
        assert_eq!(fresh_store.verify_token(&t2).await.unwrap().0, "kept");
    }

    #[tokio::test]
    async fn test_revoke_rejects_path_traversal() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(local(&temp_dir));

        // Create a decoy file that path traversal would target
        let decoy = temp_dir.path().join("../decoy.json");
        let _ = std::fs::write(&decoy, "should not be deleted");

        // Attempt path traversal
        let result = store.revoke_token("../decoy").await;
        assert!(matches!(result, Err(TokenError::NotFound)));
        let result = store.revoke_token("../../etc/passwd").await;
        assert!(matches!(result, Err(TokenError::NotFound)));
        let result = store.revoke_token("").await;
        assert!(matches!(result, Err(TokenError::NotFound)));
    }
}
