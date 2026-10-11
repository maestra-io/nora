// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use async_trait::async_trait;
use axum::body::Bytes;
use futures::TryStreamExt;
use object_store::aws::AmazonS3Builder;
use object_store::aws::AwsCredential;
use object_store::gcp::GoogleCloudStorageBuilder;
use object_store::path::Path;
use object_store::CredentialProvider;
use object_store::{
    Attribute, AttributeValue, Attributes, GetOptions, ObjectStore, ObjectStoreExt,
    PutMultipartOptions, PutOptions, PutPayload, WriteMultipart,
};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::{FileMeta, Result, StorageBackend, StorageError};

/// Downloads stream store -> server -> client under backpressure, so a slow
/// download client paces the store read. object_store's request timeout covers
/// the whole body of an attempt, and its retry deadline runs from the FIRST
/// request while gating every transparent ranged resume of a streamed body —
/// with the defaults (30 s attempt, 180 s deadline) any transfer slower than
/// object-size / 180 s is reset mid-stream. Size both for the slowest
/// tolerated download instead.
const STREAM_ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3600);

fn streaming_client_options() -> object_store::ClientOptions {
    object_store::ClientOptions::new().with_timeout(STREAM_ATTEMPT_TIMEOUT)
}

/// Bounds for calls that do not stream a body to a client. The client timeout above
/// is sized for streamed downloads; without these a silently dropped connection holds
/// a HEAD or a small GET for STREAM_ATTEMPT_TIMEOUT. Request-to-headers / small ops:
const METADATA_OP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Whole in-memory body transfers (`put`, the body of `get`).
const BODY_OP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

async fn bounded<T>(
    limit: std::time::Duration,
    fut: impl std::future::Future<Output = object_store::Result<T>>,
) -> object_store::Result<T> {
    tokio::time::timeout(limit, fut).await.unwrap_or_else(|_| {
        Err(object_store::Error::Generic {
            store: "object_store",
            source: format!("request exceeded {} s", limit.as_secs()).into(),
        })
    })
}

fn streaming_retry_config() -> object_store::RetryConfig {
    object_store::RetryConfig {
        retry_timeout: STREAM_ATTEMPT_TIMEOUT.saturating_mul(2),
        ..Default::default()
    }
}

/// S3 credentials read from files in a directory — `access_key_id`,
/// `secret_access_key` and optional `session_token`, e.g. a Kubernetes Secret
/// volume that Vault Secrets Operator rotates in place (Maestra fork: STS-style
/// R2 temp creds need the session token and expire, so they cannot be frozen
/// into env at start). Re-read at most every [`DirCredentialProvider::TTL`]; a
/// failed re-read keeps serving the last good credential.
#[derive(Debug)]
pub struct DirCredentialProvider {
    dir: std::path::PathBuf,
    ttl: Duration,
    cached: Mutex<Option<(Instant, Arc<AwsCredential>)>>,
}

impl DirCredentialProvider {
    pub const TTL: Duration = Duration::from_secs(60);

    pub fn new(dir: &str) -> Self {
        Self {
            dir: dir.into(),
            ttl: Self::TTL,
            cached: Mutex::new(None),
        }
    }

    fn read(&self) -> std::io::Result<AwsCredential> {
        use std::io::{Error, ErrorKind};
        // A Kubernetes Secret volume publishes each generation by swapping the
        // `..data` symlink; resolve it once so all files come from the same
        // generation (a plain directory has no `..data` and is read as is).
        let dir =
            std::fs::canonicalize(self.dir.join("..data")).unwrap_or_else(|_| self.dir.clone());
        let file = |name: &str| -> std::io::Result<String> {
            Ok(std::fs::read_to_string(dir.join(name))?
                .trim_end()
                .to_string())
        };
        let required = |name: &str| -> std::io::Result<String> {
            let v = file(name)?;
            if v.is_empty() {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("{name} is empty"),
                ));
            }
            Ok(v)
        };
        let token = match file("session_token") {
            Ok(t) if t.is_empty() => None,
            // object_store turns the token into a header with unwrap(): reject
            // what would panic there, keep the last good credential instead.
            Ok(t) if axum::http::HeaderValue::from_str(&t).is_err() => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "session_token is not a valid header value",
                ));
            }
            Ok(t) => Some(t),
            Err(e) if e.kind() == ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        Ok(AwsCredential {
            key_id: required("access_key_id")?,
            secret_key: required("secret_access_key")?,
            token,
        })
    }
}

#[async_trait]
impl CredentialProvider for DirCredentialProvider {
    type Credential = AwsCredential;

    async fn get_credential(&self) -> object_store::Result<Arc<AwsCredential>> {
        let mut cached = self.cached.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((at, cred)) = cached.as_ref() {
            if at.elapsed() < self.ttl {
                return Ok(Arc::clone(cred));
            }
        }
        match self.read() {
            Ok(cred) => {
                let cred = Arc::new(cred);
                *cached = Some((Instant::now(), Arc::clone(&cred)));
                Ok(cred)
            }
            Err(e) => match cached.take() {
                Some((_, cred)) => {
                    tracing::warn!(dir = %self.dir.display(), error = %e, "S3 credentials re-read failed, keeping the last good ones");
                    // Restart the TTL: a failing re-read is retried once per TTL,
                    // not on every request.
                    *cached = Some((Instant::now(), Arc::clone(&cred)));
                    Ok(cred)
                }
                None => Err(object_store::Error::Generic {
                    store: "S3",
                    source: format!("reading S3 credentials from {}: {e}", self.dir.display())
                        .into(),
                }),
            },
        }
    }
}

/// Object-store backend (S3-compatible or Google Cloud Storage) using the
/// `object_store` crate. Everything past construction goes through the
/// [`ObjectStore`] trait, so both providers share one implementation.
pub struct ObjectStorage {
    store: Box<dyn ObjectStore>,
    /// "s3" or "gcs" — surfaced in /health.
    name: &'static str,
    /// Cached total size in bytes, refreshed by background task.
    cached_total_size: std::sync::atomic::AtomicU64,
    /// Whether cached_total_size has been initialized at least once.
    size_cache_initialized: std::sync::atomic::AtomicBool,
    /// Outcome of the last background reachability probe, served by `health_check()`.
    /// Starts `false` so readiness gates until the boot probe confirms the store —
    /// kubelet and LB health checks never touch the store themselves (#869).
    cached_reachable: std::sync::atomic::AtomicBool,
    /// Unix seconds of the last background probe (`0` = never probed). Paired with
    /// `cached_reachable`, which is only ever written by the 60s maintenance loop: if that
    /// task stalls or dies, the stale flag would otherwise pin readiness forever. A probe
    /// older than `HEALTH_MAX_STALE_SECS` is treated as unreachable (#872).
    last_refresh_unix: std::sync::atomic::AtomicU64,
}

/// Reachability older than this is treated as unknown → unreachable. 2.5× the 60s background
/// refresh cadence: tolerates one missed refresh + jitter without flapping, but a stalled or
/// dead maintenance loop un-readies the pod within the window instead of pinning a stale
/// `true` (#872).
const HEALTH_MAX_STALE_SECS: i64 = 150;

/// Key the readiness probe HEADs. Nothing writes it: a NotFound answer proves the
/// endpoint, bucket and credentials work at O(1) cost, whatever the bucket size.
const HEALTH_PROBE_KEY: &str = ".nora-health-probe";

/// Upper bound on one readiness probe, so a hung connection cannot stall the
/// maintenance loop that runs it.
const HEALTH_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

impl ObjectStorage {
    /// Create new S3 storage with optional credentials.
    ///
    /// `virtual_hosted` selects the request addressing style: `false` (default) appends
    /// the bucket to the endpoint path (`<endpoint>/<bucket>/<key>`); `true` uses the
    /// endpoint VERBATIM (`<endpoint>/<key>`), so the endpoint itself must include the
    /// bucket host (e.g. `https://<bucket>.oss-<region>.aliyuncs.com`). Needed for
    /// providers that reject signed path-style requests, e.g. Alibaba Cloud OSS.
    // Maestra fork: production goes through `new_s3`; upstream's tests keep this.
    #[cfg(test)]
    pub fn new(
        s3_url: &str,
        bucket: &str,
        region: &str,
        access_key: Option<&str>,
        secret_key: Option<&str>,
        virtual_hosted: bool,
    ) -> Self {
        Self::new_s3(
            s3_url,
            bucket,
            region,
            access_key,
            secret_key,
            None,
            virtual_hosted,
        )
    }

    /// [`ObjectStorage::new`] plus `credentials_dir` (Maestra fork): when set, the
    /// S3 credentials are read from files in that directory and re-read as they
    /// rotate (see [`DirCredentialProvider`]), taking precedence over the static keys.
    pub fn new_s3(
        s3_url: &str,
        bucket: &str,
        region: &str,
        access_key: Option<&str>,
        secret_key: Option<&str>,
        credentials_dir: Option<&str>,
        virtual_hosted: bool,
    ) -> Self {
        let url = s3_url.trim_end_matches('/');
        let allow_http = url.starts_with("http://");

        let mut builder = AmazonS3Builder::new()
            .with_endpoint(url)
            .with_bucket_name(bucket)
            .with_region(region)
            // One combined ClientOptions: with_client_options REPLACES the
            // options with_allow_http would have accumulated.
            .with_client_options(streaming_client_options().with_allow_http(allow_http))
            .with_virtual_hosted_style_request(virtual_hosted)
            .with_retry(streaming_retry_config());

        // `s3_credentials_dir = ""` in TOML means unset, as the env override does.
        let credentials_dir = credentials_dir.filter(|d| !d.is_empty());
        match (credentials_dir, access_key, secret_key) {
            (Some(dir), _, _) => {
                builder = builder.with_credentials(Arc::new(DirCredentialProvider::new(dir)));
            }
            (None, Some(ak), Some(sk)) => {
                builder = builder.with_access_key_id(ak).with_secret_access_key(sk);
            }
            _ => {
                builder = builder.with_skip_signature(true);
            }
        }

        let store = builder.build().expect("Failed to build S3 client");

        Self {
            store: Box::new(store),
            name: "s3",
            cached_total_size: std::sync::atomic::AtomicU64::new(0),
            size_cache_initialized: std::sync::atomic::AtomicBool::new(false),
            cached_reachable: std::sync::atomic::AtomicBool::new(false),
            last_refresh_unix: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Create new Google Cloud Storage backend.
    ///
    /// Credentials resolve in order: explicit `service_account_path` (JSON key
    /// file), ambient `GOOGLE_*` environment (`GOOGLE_SERVICE_ACCOUNT`,
    /// `GOOGLE_APPLICATION_CREDENTIALS`, ...), then the instance metadata
    /// server — so GKE Workload Identity and GCE service accounts work with no
    /// key material at all. `base_url` overrides the endpoint for emulators
    /// (fake-gcs-server) or private access endpoints; an `http://` base_url
    /// also skips request signing (emulators don't verify signatures).
    pub fn new_gcs(
        bucket: &str,
        service_account_path: Option<&str>,
        base_url: Option<&str>,
    ) -> Self {
        let mut builder = GoogleCloudStorageBuilder::from_env()
            .with_bucket_name(bucket)
            .with_retry(streaming_retry_config());
        // `with_client_options` would replace every env-derived client option
        // (`GOOGLE_PROXY_URL`, ...), so merge only the timeout — and only when
        // the operator has not set `GOOGLE_TIMEOUT` themselves.
        if std::env::var_os("GOOGLE_TIMEOUT").is_none() {
            builder = builder.with_config(
                object_store::gcp::GoogleConfigKey::Client(object_store::ClientConfigKey::Timeout),
                format!("{}s", STREAM_ATTEMPT_TIMEOUT.as_secs()),
            );
        }
        if let Some(path) = service_account_path {
            builder = builder.with_service_account_path(path);
        }
        if let Some(url) = base_url {
            let allow_http = url.starts_with("http://");
            builder = builder
                .with_base_url(url)
                .with_client_options(streaming_client_options().with_allow_http(allow_http));
            if allow_http {
                builder = builder.with_skip_signature(true);
            }
        }
        let store = builder.build().expect("Failed to build GCS client");

        Self {
            store: Box::new(store),
            name: "gcs",
            cached_total_size: std::sync::atomic::AtomicU64::new(0),
            size_cache_initialized: std::sync::atomic::AtomicBool::new(false),
            cached_reachable: std::sync::atomic::AtomicBool::new(false),
            last_refresh_unix: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// In-process object store for tests: same code path as S3/GCS, including
    /// user-metadata round-trips and store-side copy.
    #[cfg(test)]
    pub(crate) fn in_memory() -> Self {
        Self {
            store: Box::new(object_store::memory::InMemory::new()),
            name: "s3",
            cached_total_size: std::sync::atomic::AtomicU64::new(0),
            size_cache_initialized: std::sync::atomic::AtomicBool::new(false),
            cached_reachable: std::sync::atomic::AtomicBool::new(true),
            last_refresh_unix: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Test-only handle on the raw store, for writing objects NORA itself would
    /// never write (e.g. one with no pin metadata).
    #[cfg(test)]
    pub(crate) fn store(&self) -> &dyn ObjectStore {
        self.store.as_ref()
    }
}

/// Encode `@` in object keys to `%40` for SeaweedFS compatibility (shared by
/// every object-store backend so all providers use one key scheme).
///
/// SeaweedFS returns 500 on GET/PUT for keys containing `@`
/// (e.g. npm scoped packages like `npm/@babel/core/...`).
///
/// Uses `%40` (URL-encoding style) instead of `_at_` to avoid roundtrip
/// collisions with keys containing literal `_at_` (e.g. `look_at_this`) (#534).
fn encode_object_key(key: &str) -> String {
    key.replace('@', "%40")
}

/// Legacy encoding: `@` → `_at_` (used before #534).
/// Only needed for fallback reads of pre-migration data.
fn encode_object_key_legacy(key: &str) -> String {
    key.replace('@', "_at_")
}

/// Decode S3 keys back to original form.
///
/// `encode_object_key` maps `@` -> `%40`, but `object_store::path::Path` percent-
/// encodes the `%` we introduced (its INVALID set includes `%`, not `@`), so the
/// byte actually written — and returned by `list()`/`list_with_meta()` in
/// `meta.location` — is DOUBLE-encoded `%2540`, not `%40`. Reversing only `%40`
/// left the double form intact, so a follow-up `get()` on the listed key encoded a
/// third time (`%252540`) and 404'd. Net effect: scoped npm packages (`@scope/name`)
/// listed as if they had no versions, so scan-regenerate wrote an EMPTY packument on
/// every publish and `npm install` failed `ENOVERSIONS` (#878, S3/object_store only —
/// local FS has no `%` re-encoding). Reverse the double form FIRST, then the single
/// form (a backend that does not re-encode, e.g. an in-memory mock). Non-scoped keys
/// carry no `%` and are untouched by either replace.
///
/// Legacy `_at_` keys from pre-#534 data are still NOT decoded here — they are
/// handled by fallback reads in `get()`/`stat()`, avoiding the roundtrip collision
/// where a literal `_at_` (e.g. `cargo/look_at_this/`) would be wrongly decoded.
fn decode_object_key(key: &str) -> String {
    key.replace("%2540", "@").replace("%40", "@")
}

/// User-defined object metadata carrying the SHA-256 integrity pin — written
/// atomically with the object and returned with every GET/HEAD, so the pin
/// travels with the bytes (`x-amz-meta-sha256` / `x-goog-meta-sha256`).
const PIN_METADATA_KEY: &str = "sha256";

fn pin_attribute() -> Attribute {
    Attribute::Metadata(PIN_METADATA_KEY.into())
}

fn pin_attributes(sha256: &str) -> Attributes {
    [(
        pin_attribute(),
        AttributeValue::from(sha256.to_ascii_lowercase()),
    )]
    .into_iter()
    .collect()
}

fn read_pin(attributes: &Attributes) -> Option<String> {
    attributes
        .get(&pin_attribute())
        .map(|v| v.as_ref().to_string())
}

/// Map object_store errors to StorageError.
fn map_err(e: object_store::Error) -> StorageError {
    match e {
        object_store::Error::NotFound { .. } => StorageError::NotFound,
        other => StorageError::Network(other.to_string()),
    }
}

#[async_trait]
impl StorageBackend for ObjectStorage {
    async fn put(&self, key: &str, data: &[u8], sha256: &str) -> Result<()> {
        self.put_bytes(key, Bytes::copy_from_slice(data), sha256)
            .await
    }

    async fn put_bytes(&self, key: &str, data: Bytes, sha256: &str) -> Result<()> {
        let encoded = encode_object_key(key);
        let path = Path::from(encoded);
        let payload = PutPayload::from(data);
        let opts = PutOptions {
            attributes: pin_attributes(sha256),
            ..Default::default()
        };
        bounded(BODY_OP_TIMEOUT, self.store.put_opts(&path, payload, opts))
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<(Bytes, Option<String>)> {
        let encoded = encode_object_key(key);
        let path = Path::from(encoded);
        let result = match bounded(METADATA_OP_TIMEOUT, self.store.get(&path)).await {
            Ok(result) => result,
            Err(object_store::Error::NotFound { .. }) if key.contains('@') => {
                // Fallback: try legacy _at_ encoding for pre-#534 data.
                // Only needed when key contains @, since otherwise both schemes produce the same output.
                let legacy_path = Path::from(encode_object_key_legacy(key));
                bounded(METADATA_OP_TIMEOUT, self.store.get(&legacy_path))
                    .await
                    .map_err(map_err)?
            }
            Err(e) => return Err(map_err(e)),
        };
        let pin = read_pin(&result.attributes);
        let bytes = bounded(BODY_OP_TIMEOUT, result.bytes())
            .await
            .map_err(map_err)?;
        Ok((bytes, pin))
    }

    async fn pin(&self, key: &str) -> Option<String> {
        let head = || GetOptions {
            head: true,
            ..Default::default()
        };
        let path = Path::from(encode_object_key(key));
        let result = match bounded(METADATA_OP_TIMEOUT, self.store.get_opts(&path, head())).await {
            Ok(r) => r,
            Err(_) if key.contains('@') => {
                // Fallback: try legacy _at_ encoding for pre-#534 data.
                let legacy_path = Path::from(encode_object_key_legacy(key));
                bounded(
                    METADATA_OP_TIMEOUT,
                    self.store.get_opts(&legacy_path, head()),
                )
                .await
                .ok()?
            }
            Err(_) => return None,
        };
        read_pin(&result.attributes)
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let encoded = encode_object_key(key);
        let path = Path::from(encoded);
        bounded(METADATA_OP_TIMEOUT, self.store.delete(&path))
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let encoded = encode_object_key(prefix);
        let prefix_path = Path::from(encoded);
        let list_prefix = if prefix.is_empty() {
            None
        } else {
            Some(&prefix_path)
        };

        // Collect all objects from the listing stream.
        let objects: Vec<_> = self
            .store
            .list(list_prefix)
            .try_collect()
            .await
            .map_err(|e| StorageError::Network(e.to_string()))?;

        Ok(objects
            .into_iter()
            .map(|meta| decode_object_key(meta.location.as_ref()))
            // The signing key is a secret, never an artifact — keep it out of
            // backup/migrate/GC/UI enumeration (see storage::SIGNING_KEY_PREFIX).
            .filter(|key| !super::is_reserved_signing_key(key))
            .collect())
    }

    async fn list_with_meta(&self, prefix: &str) -> Result<Vec<(String, FileMeta)>> {
        let encoded = encode_object_key(prefix);
        let prefix_path = Path::from(encoded);
        let list_prefix = if prefix.is_empty() {
            None
        } else {
            Some(&prefix_path)
        };

        let objects: Vec<_> = self
            .store
            .list(list_prefix)
            .try_collect()
            .await
            .map_err(|e| StorageError::Network(e.to_string()))?;

        // The LIST response already carries size/last_modified — reuse it
        // instead of issuing a HEAD per key (#738).
        Ok(objects
            .into_iter()
            .map(|meta| {
                let modified = meta.last_modified.timestamp().try_into().unwrap_or(0u64);
                (
                    decode_object_key(meta.location.as_ref()),
                    FileMeta {
                        size: meta.size,
                        modified,
                    },
                )
            })
            .filter(|(key, _)| !super::is_reserved_signing_key(key))
            .collect())
    }

    async fn stat(&self, key: &str) -> Option<FileMeta> {
        let encoded = encode_object_key(key);
        let path = Path::from(encoded);
        let meta = match bounded(METADATA_OP_TIMEOUT, self.store.head(&path)).await {
            Ok(m) => m,
            Err(_) if key.contains('@') => {
                // Fallback: try legacy _at_ encoding for pre-#534 data
                let legacy_path = Path::from(encode_object_key_legacy(key));
                bounded(METADATA_OP_TIMEOUT, self.store.head(&legacy_path))
                    .await
                    .ok()?
            }
            Err(_) => return None,
        };

        let modified = meta.last_modified.timestamp().try_into().unwrap_or(0u64);

        Some(FileMeta {
            size: meta.size,
            modified,
        })
    }

    async fn health_check(&self) -> bool {
        // Cached outcome of the last background probe (#869) — kubelet probes must never hit
        // the store. False until the boot probe succeeds, so readiness still gates a
        // misconfigured store at rollout. Self-expiring (#872): the flag is only written by
        // the 60s maintenance loop, so a stalled or dead loop lets the staleness window lapse
        // and un-readies the pod rather than pinning a stale `true` forever.
        self.cached_reachable
            .load(std::sync::atomic::Ordering::Relaxed)
            && crate::cache_ttl::is_within_ttl(
                self.last_refresh_unix
                    .load(std::sync::atomic::Ordering::Relaxed),
                HEALTH_MAX_STALE_SECS,
            )
    }

    async fn total_size(&self) -> u64 {
        self.cached_total_size
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn backend_name(&self) -> &'static str {
        self.name
    }

    async fn refresh_reachability(&self) {
        let probe = tokio::time::timeout(
            HEALTH_PROBE_TIMEOUT,
            self.store.head(&Path::from(HEALTH_PROBE_KEY)),
        )
        .await;
        let reachable = match probe {
            Ok(Ok(_)) | Ok(Err(object_store::Error::NotFound { .. })) => true,
            Ok(Err(e)) => {
                tracing::warn!(backend = self.name, error = %e, "object store readiness probe failed");
                false
            }
            Err(_) => {
                tracing::warn!(
                    backend = self.name,
                    "object store readiness probe timed out"
                );
                false
            }
        };
        self.cached_reachable
            .store(reachable, std::sync::atomic::Ordering::Relaxed);
        // Stamp every run (success or failure): this marks the maintenance loop as alive so
        // `health_check` can expire the cached verdict if the loop stops (#872).
        self.last_refresh_unix.store(
            crate::cache_ttl::now_unix(),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    async fn refresh_total_size(&self) {
        // Full-bucket walk: runs on its own slow cadence, never on the readiness path.
        let total = self
            .store
            .list(None)
            .try_fold(0u64, |acc, m| async move {
                Ok::<_, object_store::Error>(acc + m.size)
            })
            .await;
        match total {
            Ok(total) => {
                self.cached_total_size
                    .store(total, std::sync::atomic::Ordering::Relaxed);
                self.size_cache_initialized
                    .store(true, std::sync::atomic::Ordering::Relaxed);
            }
            Err(e) => {
                tracing::warn!(backend = self.name, error = %e, "object store size refresh failed");
            }
        }
    }

    async fn put_from_path(
        &self,
        key: &str,
        src: &std::path::Path,
        sha256: Option<&str>,
    ) -> Result<()> {
        let encoded = encode_object_key(key);
        let s3_path = Path::from(encoded);

        // Streaming multipart upload: read file in 8 MiB chunks, feed to
        // WriteMultipart which buffers into 5 MiB parts and uploads in
        // parallel. Never loads the entire file into RAM (#580).
        let mut file = tokio::fs::File::open(src).await?;

        // CANCEL-SAFETY: if dropped between put_multipart and finish,
        // S3 does NOT automatically abort orphaned parts. Cleanup depends
        // on S3 lifecycle policy (AbortIncompleteMultipartUpload rule).
        // No partial objects are visible to readers (upload never completed).
        // finish() calls abort() on its own errors; cancellation (future
        // dropped) relies on lifecycle policy only.
        // The pin rides on the multipart init, so it lands with the object or
        // not at all — no window where the bytes exist unpinned.
        let opts = PutMultipartOptions {
            attributes: sha256.map(pin_attributes).unwrap_or_default(),
            ..Default::default()
        };
        let upload = self
            .store
            .put_multipart_opts(&s3_path, opts)
            .await
            .map_err(map_err)?;
        let mut writer = WriteMultipart::new(upload);

        let mut buf = vec![0u8; 8 * 1024 * 1024]; // 8 MiB read buffer
        loop {
            let n = file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            // Backpressure: without this the read loop outruns the upload and
            // queues the whole file as in-flight parts in RAM.
            writer.wait_for_capacity(8).await.map_err(map_err)?;
            writer.write(&buf[..n]);
        }
        writer.finish().await.map_err(map_err)?;

        let _ = tokio::fs::remove_file(src).await;
        Ok(())
    }

    async fn copy(&self, src: &str, dst: &str, _sha256: Option<&str>) -> Result<()> {
        // Store-side copy (S3 CopyObject / GCS rewrite) — no bytes cross the
        // network through this process. A store-side copy carries the source's
        // user metadata, so `dst` inherits the pin without re-writing it.
        let from_path = Path::from(encode_object_key(src));
        let to_path = Path::from(encode_object_key(dst));
        bounded(BODY_OP_TIMEOUT, self.store.copy(&from_path, &to_path))
            .await
            .map_err(map_err)
    }

    async fn get_reader(
        &self,
        key: &str,
    ) -> Result<(u64, Option<String>, Pin<Box<dyn AsyncRead + Send + Unpin>>)> {
        let encoded = encode_object_key(key);
        let path = Path::from(encoded);
        let result = match bounded(METADATA_OP_TIMEOUT, self.store.get(&path)).await {
            Ok(r) => r,
            Err(object_store::Error::NotFound { .. }) if key.contains('@') => {
                let legacy_path = Path::from(encode_object_key_legacy(key));
                bounded(METADATA_OP_TIMEOUT, self.store.get(&legacy_path))
                    .await
                    .map_err(map_err)?
            }
            Err(e) => return Err(map_err(e)),
        };
        let size = result.meta.size;
        let pin = read_pin(&result.attributes);
        let stream = result.into_stream().map_err(std::io::Error::other);
        let reader = tokio_util::io::StreamReader::new(stream);
        Ok((size as u64, pin, Box::pin(reader)))
    }

    async fn get_range(
        &self,
        key: &str,
        start: u64,
        end: u64,
    ) -> Result<(u64, Pin<Box<dyn AsyncRead + Send + Unpin>>)> {
        let make_opts = || GetOptions {
            range: Some(object_store::GetRange::Bounded(start..(end + 1))),
            ..Default::default()
        };
        let path = Path::from(encode_object_key(key));
        let result =
            match bounded(METADATA_OP_TIMEOUT, self.store.get_opts(&path, make_opts())).await {
                Ok(r) => r,
                Err(object_store::Error::NotFound { .. }) if key.contains('@') => {
                    let legacy_path = Path::from(encode_object_key_legacy(key));
                    bounded(
                        METADATA_OP_TIMEOUT,
                        self.store.get_opts(&legacy_path, make_opts()),
                    )
                    .await
                    .map_err(map_err)?
                }
                Err(e) => return Err(map_err(e)),
            };
        let size = result.meta.size;
        let stream = result.into_stream().map_err(std::io::Error::other);
        let reader = tokio_util::io::StreamReader::new(stream);
        Ok((size as u64, Box::pin(reader)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    /// `put_bytes` uploads the caller's buffer as-is and records the pin; `put`
    /// (slice) goes through it, so both read back identically.
    #[tokio::test]
    async fn test_put_bytes_roundtrip_with_pin() {
        let storage = ObjectStorage::in_memory();
        let data = Bytes::from_static(b"package-bytes");
        storage
            .put_bytes("a/b.tgz", data.clone(), "abc")
            .await
            .unwrap();
        storage.put("a/c.tgz", &data, "def").await.unwrap();
        let (got, pin) = storage.get("a/b.tgz").await.unwrap();
        assert_eq!((got, pin.as_deref()), (data.clone(), Some("abc")));
        let (got, pin) = storage.get("a/c.tgz").await.unwrap();
        assert_eq!((got, pin.as_deref()), (data, Some("def")));
    }

    /// A file spanning many multipart parts uploads whole now that the read loop
    /// waits for part capacity instead of queueing every part in RAM.
    #[tokio::test]
    async fn test_put_from_path_multipart_roundtrip() {
        let storage = ObjectStorage::in_memory();
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("big.bin");
        let data: Vec<u8> = (0..23 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        tokio::fs::write(&src, &data).await.unwrap();
        storage
            .put_from_path("raw/big.bin", &src, None)
            .await
            .unwrap();
        let (got, _) = storage.get("raw/big.bin").await.unwrap();
        assert_eq!(got.len(), data.len());
        assert!(got == data);
    }

    #[test]
    fn test_backend_name() {
        let storage = ObjectStorage::new(
            "http://localhost:9000",
            "test-bucket",
            "us-east-1",
            Some("access"),
            Some("secret"),
            false,
        );
        assert_eq!(storage.backend_name(), "s3");
    }

    /// Maestra fork: credentials come from files, rotate in place, a failed re-read
    /// keeps the last good ones, and a dir that never had them is an error.
    #[tokio::test]
    async fn test_dir_credential_provider_rotates() {
        let dir = tempfile::tempdir().unwrap();
        let write = |k: &str, v: &str| std::fs::write(dir.path().join(k), v).unwrap();
        let mut p = DirCredentialProvider::new(dir.path().to_str().unwrap());
        assert!(p.get_credential().await.is_err());

        write("access_key_id", "ak1\n");
        write("secret_access_key", "sk1\n");
        let c = p.get_credential().await.unwrap();
        assert_eq!((c.key_id.as_str(), c.secret_key.as_str()), ("ak1", "sk1"));
        assert_eq!(c.token, None);

        write("access_key_id", "ak2");
        write("session_token", "tok2\n");
        // Within the TTL the cached credential is served.
        assert_eq!(p.get_credential().await.unwrap().key_id, "ak1");
        p.ttl = Duration::ZERO;
        let c = p.get_credential().await.unwrap();
        assert_eq!(c.key_id, "ak2");
        assert_eq!(c.token.as_deref(), Some("tok2"));

        std::fs::remove_file(dir.path().join("secret_access_key")).unwrap();
        assert_eq!(p.get_credential().await.unwrap().key_id, "ak2");

        // An empty key or an unsendable token is a failed re-read, not a new pair.
        write("secret_access_key", "  \n");
        write("access_key_id", "ak3");
        assert_eq!(p.get_credential().await.unwrap().key_id, "ak2");
        write("secret_access_key", "sk3");
        write("session_token", "tok\nsplit");
        assert_eq!(p.get_credential().await.unwrap().key_id, "ak2");

        // A failed re-read restarts the TTL: no re-read until it expires again.
        p.ttl = Duration::from_secs(3600);
        write("session_token", "tok3");
        assert_eq!(p.get_credential().await.unwrap().key_id, "ak2");
        p.ttl = Duration::ZERO;
        assert_eq!(p.get_credential().await.unwrap().key_id, "ak3");

        // Kubernetes Secret volume layout: files are read through `..data`.
        let gen = dir.path().join("..2026_10_11_gen1");
        std::fs::create_dir(&gen).unwrap();
        for (k, v) in [("access_key_id", "ak4"), ("secret_access_key", "sk4")] {
            std::fs::write(gen.join(k), v).unwrap();
        }
        std::os::unix::fs::symlink(&gen, dir.path().join("..data")).unwrap();
        let c = p.get_credential().await.unwrap();
        assert_eq!((c.key_id.as_str(), c.token.as_deref()), ("ak4", None));

        // The builder accepts the provider (no static keys needed).
        let s = ObjectStorage::new_s3(
            "http://127.0.0.1:1",
            "b",
            "auto",
            None,
            None,
            dir.path().to_str(),
            false,
        );
        assert_eq!(s.backend_name(), "s3");
    }

    /// `health_check` is a cached signal (#869): false at construction (probes do no
    /// store I/O), and still false after a refresh against an unreachable endpoint.
    /// The true-path is the background refresh loop against a live store.
    #[tokio::test]
    async fn test_health_check_cached_not_live() {
        let storage = ObjectStorage::new("http://127.0.0.1:1", "b", "r", None, None, false);
        assert!(!storage.health_check().await);
        storage.refresh_reachability().await;
        assert!(!storage.health_check().await);
    }

    /// Readiness is one HEAD, not a bucket walk: with listing throttled to an hour a
    /// probe still marks the store reachable at once, and the size walk no longer
    /// touches the readiness verdict (#869).
    #[tokio::test]
    async fn test_reachability_probe_does_not_list() {
        use object_store::throttle::{ThrottleConfig, ThrottledStore};
        let inner = object_store::memory::InMemory::new();
        inner
            .put(&Path::from("raw/a"), PutPayload::from_static(b"x"))
            .await
            .unwrap();
        let throttled = ThrottledStore::new(
            inner,
            ThrottleConfig {
                wait_list_per_call: std::time::Duration::from_secs(3600),
                ..Default::default()
            },
        );
        let storage = ObjectStorage {
            store: Box::new(throttled),
            name: "s3",
            cached_total_size: std::sync::atomic::AtomicU64::new(0),
            size_cache_initialized: std::sync::atomic::AtomicBool::new(false),
            cached_reachable: std::sync::atomic::AtomicBool::new(false),
            last_refresh_unix: std::sync::atomic::AtomicU64::new(0),
        };
        assert!(!storage.health_check().await);
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            storage.refresh_reachability(),
        )
        .await
        .expect("probe must not list the bucket");
        assert!(storage.health_check().await);
    }

    /// Cached reachability self-expires (#872): a `true` verdict whose last refresh is older
    /// than `HEALTH_MAX_STALE_SECS` (a stalled or dead maintenance loop) must NOT keep the pod
    /// ready. Only a recent refresh keeps `health_check` true.
    #[tokio::test]
    async fn test_health_check_expires_when_refresh_stalls() {
        use std::sync::atomic::Ordering::Relaxed;
        let storage = ObjectStorage::new("http://127.0.0.1:1", "b", "r", None, None, false);
        let now = crate::cache_ttl::now_unix();

        // A since-dead refresh loop: reachable was true, but the last refresh is ancient.
        storage.cached_reachable.store(true, Relaxed);
        storage
            .last_refresh_unix
            .store(now.saturating_sub(10_000), Relaxed);
        assert!(
            !storage.health_check().await,
            "stale reachability must not keep readiness up"
        );

        // A fresh refresh timestamp → reachable again.
        storage.last_refresh_unix.store(now, Relaxed);
        assert!(storage.health_check().await);
    }

    /// #878 unit guard: `decode_object_key` must reverse the DOUBLE-encoded `%2540`
    /// that `object_store::path::Path` produces from our `%40`, the single `%40`
    /// (a non-re-encoding backend), and must NOT touch a literal `_at_`.
    #[test]
    fn decode_reverses_double_encoded_at() {
        assert_eq!(
            decode_object_key("npm/%2540scope/pkg/metadata.json"),
            "npm/@scope/pkg/metadata.json"
        );
        assert_eq!(decode_object_key("npm/%40scope/x"), "npm/@scope/x");
        assert_eq!(
            decode_object_key("cargo/look_at_this/x"),
            "cargo/look_at_this/x"
        );
    }

    /// #878 regression through the REAL scan-regenerate call path (list -> get) against a
    /// live object_store. The `%`-re-encoding lives in `Path`, not the S3 backend, so the
    /// in-memory store reproduces the double-encoding faithfully — no MinIO needed. Before
    /// the `decode_object_key` fix, `list()` returned the `%2540` key, the follow-up `get()`
    /// re-encoded a third time and 404'd, and every scoped npm publish regenerated an empty
    /// packument (`npm install` -> ENOVERSIONS).
    #[tokio::test]
    async fn scoped_key_lists_and_gets_through_path_encoding() {
        let storage = ObjectStorage::in_memory();

        let body = br#"{"version":"1.0.0"}"#;
        let hash = hex::encode(sha2::Sha256::digest(body));
        let key = "npm/@scope/pkg/versions/1.0.0.json";
        storage.put(key, body, &hash).await.unwrap();

        // Control: a non-scoped key (no `@`, no `%`) is unaffected.
        let plain = "npm/plainpkg/versions/1.0.0.json";
        storage.put(plain, body, &hash).await.unwrap();

        // list() must return the ORIGINAL logical key (with `@`), not the `%2540` form.
        let listed = storage.list("npm/@scope/pkg/versions/").await.unwrap();
        assert_eq!(
            listed,
            vec![key.to_string()],
            "list must decode %2540 back to @ so scan-regenerate can read it"
        );

        // The listed key must be directly get-able — the exact scan-regenerate step that
        // silently dropped scoped versions before the fix.
        let (got, pin) = storage
            .get(&listed[0])
            .await
            .expect("get on the listed key must succeed");
        assert_eq!(&got[..], body);
        assert_eq!(pin.as_deref(), Some(hash.as_str()));

        let listed_plain = storage.list("npm/plainpkg/versions/").await.unwrap();
        assert_eq!(listed_plain, vec![plain.to_string()]);
        assert!(storage.get(&listed_plain[0]).await.is_ok());
    }

    #[test]
    fn test_s3_storage_creation_anonymous() {
        let storage = ObjectStorage::new(
            "http://localhost:9000",
            "test-bucket",
            "us-east-1",
            None,
            None,
            false,
        );
        assert_eq!(storage.backend_name(), "s3");
    }

    /// GCS construction with no credentials and an emulator base_url — the
    /// builder resolves credentials lazily (no build-time I/O), same contract
    /// as the anonymous S3 construction test above.
    #[test]
    fn test_gcs_storage_creation_emulator() {
        let _lock = crate::test_env::env_lock();
        let storage = ObjectStorage::new_gcs("test-bucket", None, Some("http://localhost:4443"));
        assert_eq!(storage.backend_name(), "gcs");
    }

    /// GCS construction against the real endpoint (no base_url, no explicit
    /// service account) — the ambient-credential ladder must also be lazy.
    #[test]
    fn test_gcs_storage_creation_default_endpoint() {
        let _lock = crate::test_env::env_lock();
        let storage = ObjectStorage::new_gcs("test-bucket", None, None);
        assert_eq!(storage.backend_name(), "gcs");
    }

    /// Empty ListObjectsV2 body so `refresh_total_size`'s `list(None)` succeeds against the mock.
    const EMPTY_LIST_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>test-bucket</Name><KeyCount>0</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>"#;

    /// Run one `refresh_total_size` (a ListObjectsV2) against a mock server and return the
    /// request path the client actually used. Also covers the cached-reachability true
    /// path (#869): a successful refresh flips `health_check()` to true.
    async fn observed_list_path(virtual_hosted: bool) -> String {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_raw(EMPTY_LIST_XML, "application/xml"),
            )
            .mount(&server)
            .await;
        let storage = ObjectStorage::new(
            &server.uri(),
            "test-bucket",
            "us-east-1",
            Some("access"),
            Some("secret"),
            virtual_hosted,
        );
        storage.refresh_total_size().await;
        assert!(storage
            .size_cache_initialized
            .load(std::sync::atomic::Ordering::Relaxed));
        let requests = server.received_requests().await.unwrap();
        requests[0].url.path().to_string()
    }

    /// Path-style (default): the bucket is addressed in the URL path.
    #[tokio::test]
    async fn test_path_style_addresses_bucket_in_path() {
        assert_eq!(observed_list_path(false).await, "/test-bucket");
    }

    /// Virtual-hosted: `object_store` uses the configured endpoint VERBATIM — the bucket is
    /// not injected into host or path, so the endpoint itself must carry the bucket host
    /// (e.g. `https://<bucket>.oss-<region>.aliyuncs.com`). This is the contract the docs
    /// describe; if `object_store` ever changes it, this test flags the doc drift.
    #[tokio::test]
    async fn test_virtual_hosted_uses_endpoint_verbatim() {
        assert_eq!(observed_list_path(true).await, "/");
    }

    #[test]
    fn test_s3_total_size_returns_zero_before_init() {
        let storage = ObjectStorage::new(
            "http://localhost:9000",
            "test-bucket",
            "us-east-1",
            Some("access"),
            Some("secret"),
            false,
        );
        assert!(!storage
            .size_cache_initialized
            .load(std::sync::atomic::Ordering::Relaxed));
    }

    #[test]
    fn test_error_mapping_not_found() {
        let err = object_store::Error::NotFound {
            path: "test/key".to_string(),
            source: "not found".into(),
        };
        match map_err(err) {
            StorageError::NotFound => {}
            other => panic!("Expected NotFound, got: {:?}", other),
        }
    }

    #[test]
    fn test_error_mapping_network() {
        let err = object_store::Error::Generic {
            store: "S3",
            source: "connection refused".into(),
        };
        match map_err(err) {
            StorageError::Network(msg) => {
                assert!(msg.contains("connection refused"));
            }
            other => panic!("Expected Network, got: {:?}", other),
        }
    }

    #[test]
    fn test_encode_object_key() {
        assert_eq!(encode_object_key("npm/@scope/pkg"), "npm/%40scope/pkg");
        assert_eq!(
            encode_object_key("npm/@babel/core/metadata.json"),
            "npm/%40babel/core/metadata.json"
        );
    }

    #[test]
    fn test_decode_object_key_new_encoding() {
        assert_eq!(decode_object_key("npm/%40scope/pkg"), "npm/@scope/pkg");
        assert_eq!(
            decode_object_key("npm/%40babel/core/metadata.json"),
            "npm/@babel/core/metadata.json"
        );
    }

    #[test]
    fn test_decode_object_key_legacy_not_decoded() {
        // Legacy _at_ keys are NOT decoded by decode_object_key (avoids #534 collision).
        // They are handled by fallback reads in get()/stat() instead.
        assert_eq!(decode_object_key("npm/_at_scope/pkg"), "npm/_at_scope/pkg");
        assert_eq!(
            decode_object_key("npm/_at_babel/core/metadata.json"),
            "npm/_at_babel/core/metadata.json"
        );
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let keys = [
            "npm/@scope/pkg",
            "npm/@babel/core/metadata.json",
            "simple/key/no-at",
            "raw/@org/file.txt",
            "cargo/look_at_this/1.0.crate", // #534: was broken with _at_ encoding
            "npm/some_at_pkg/metadata.json", // literal _at_ in name
        ];
        for key in keys {
            assert_eq!(
                decode_object_key(&encode_object_key(key)),
                key,
                "roundtrip failed for: {key}"
            );
        }
    }

    /// Regression test for #534: keys with literal `_at_` must not collide.
    #[test]
    fn test_no_roundtrip_collision_with_literal_at() {
        let key = "cargo/look_at_this/1.0.crate";
        let encoded = encode_object_key(key);
        // Must NOT contain _at_ substitution — key has no @
        assert_eq!(encoded, key);
        assert_eq!(decode_object_key(&encoded), key);
    }

    #[test]
    fn test_encode_no_at() {
        let key = "npm/chalk/metadata.json";
        assert_eq!(encode_object_key(key), key);
    }

    #[test]
    fn test_legacy_encode_for_fallback() {
        assert_eq!(
            encode_object_key_legacy("npm/@scope/pkg"),
            "npm/_at_scope/pkg"
        );
        // Key without @ is unchanged in both schemes
        assert_eq!(
            encode_object_key_legacy("npm/chalk/metadata.json"),
            "npm/chalk/metadata.json"
        );
    }

    /// A store call that never answers is cut off at its bound and surfaces as a
    /// storage error, instead of holding the caller for STREAM_ATTEMPT_TIMEOUT.
    #[tokio::test]
    async fn test_bounded_cuts_off_a_hung_request() {
        let hung = std::future::pending::<object_store::Result<()>>();
        let limit = std::time::Duration::from_millis(50);
        let err = bounded(limit, hung).await.unwrap_err();
        assert!(matches!(map_err(err), StorageError::Network(_)));
        assert!(bounded(METADATA_OP_TIMEOUT, async { Ok(1) }).await.is_ok());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// For any key containing @, _, or other ASCII chars, roundtrip must hold (#534).
        #[test]
        fn object_key_roundtrip(key in "[a-z0-9@_./-]{1,100}") {
            prop_assert_eq!(decode_object_key(&encode_object_key(&key)), key);
        }
    }
}
