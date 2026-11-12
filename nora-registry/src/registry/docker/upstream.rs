// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Upstream blob and manifest fetches: the streaming spool, single-flight fills,
//! ranged resume (moved out of docker.rs, R4-T12).

use super::*;

/// Result of a successful streaming blob fetch from upstream (#580).
pub struct FetchedBlob {
    /// Path to temp file containing the complete blob data.
    pub path: std::path::PathBuf,
    /// SHA-256 hex digest computed incrementally during download (64 chars, lowercase).
    pub sha256: String,
    /// RAII guard — deletes temp file on drop unless disarmed.
    pub _guard: TempFileGuard,
}

/// An upstream blob whose response headers have arrived but whose body has not been
/// read: the point at which `download_blob` can answer the client, before the bytes
/// are on disk.
pub struct UpstreamBlob {
    response: reqwest::Response,
    /// Content-Length from upstream, None for a chunked response.
    pub content_length: Option<u64>,
    /// Where to ask for the rest if the body breaks off.
    source: BlobSource,
    cb_key: String,
    probe: ProbeToken,
    _download_gauge_guard: ProxyDownloadGuard,
}

/// Progress of an in-flight spool, published to the response followers reading it.
#[derive(Clone, Debug, Default)]
pub(crate) struct SpoolStatus {
    /// Bytes flushed to the spool file so far.
    pub written: u64,
    /// `Some` once the spool has finished: the upstream body is complete and verified
    /// (`Ok`) or the fetch failed and the file is being discarded (`Err`).
    pub done: Option<Result<(), String>>,
}

/// Temp file a spool writes into. Created by the caller so a follower can open its own
/// handle before the first byte lands and keep reading it after storage moves or the
/// guard deletes the path.
pub(crate) struct SpoolFile {
    pub(super) path: std::path::PathBuf,
    pub(super) file: tokio::fs::File,
    pub(super) guard: TempFileGuard,
}

impl SpoolFile {
    pub(crate) async fn create(temp_dir: &std::path::Path) -> Result<Self, ProxyError> {
        let path = temp_dir.join(format!("proxy-{}", uuid::Uuid::new_v4()));
        let guard = TempFileGuard::new(path.clone());
        let file = tokio::fs::File::create(&path)
            .await
            .map_err(|e| ProxyError::Network(format!("temp file create: {}", e)))?;
        Ok(Self { path, file, guard })
    }

    /// A second, read-only handle on the spool file for a response to follow.
    pub(crate) async fn follower(&self) -> std::io::Result<tokio::fs::File> {
        tokio::fs::File::open(&self.path).await
    }
}

/// Read a spool file as it is being written, ending when the spool reports completion.
///
/// Bytes are released only up to what the spool has flushed, less a one-byte holdback
/// until it reports `done`: with a `Content-Length` body hyper stops reading once the
/// declared bytes are out, so the digest verdict has to gate the final byte, not EOF. A
/// failed spool surfaces as a read error, so the response aborts short instead of ending
/// cleanly. Progress is re-read after every short read, so bytes flushed between a read
/// and the next status check are never waited on.
///
/// `file` is positioned at byte `start` of the blob: a ranged response follows the
/// spool from there. A spool that reports nothing for `stall` fails the read.
pub(crate) fn spool_follower(
    file: tokio::fs::File,
    status: tokio::sync::watch::Receiver<SpoolStatus>,
    start: u64,
    stall: Duration,
) -> impl futures::Stream<Item = std::io::Result<Bytes>> + Send {
    const READ_BUF: usize = 256 * 1024;
    const HOLDBACK_BYTES: u64 = 1;
    // Flushed bytes are visible to a second handle at once; a run of empty reads below
    // the published count means the file is gone or truncated, not still in flight.
    const MAX_EMPTY_READS: u32 = 1_000;
    futures::stream::unfold(
        (file, status, start, 0u32),
        move |(mut file, mut status, mut offset, mut empty_reads)| async move {
            use tokio::io::AsyncReadExt;
            loop {
                let current = status.borrow_and_update().clone();
                let released = match &current.done {
                    Some(Ok(())) => current.written,
                    Some(Err(reason)) => {
                        let err =
                            std::io::Error::other(format!("upstream blob fetch failed: {reason}"));
                        return Some((Err(err), (file, status, offset, empty_reads)));
                    }
                    None => current.written.saturating_sub(HOLDBACK_BYTES),
                };
                if offset < released {
                    let want = usize::try_from(released - offset)
                        .unwrap_or(READ_BUF)
                        .min(READ_BUF);
                    let mut buf = vec![0u8; want];
                    match file.read(&mut buf).await {
                        Ok(0) => {
                            empty_reads += 1;
                            if empty_reads > MAX_EMPTY_READS {
                                let err = std::io::Error::other(format!(
                                    "spool published {} bytes but only {} were readable",
                                    current.written, offset
                                ));
                                return Some((Err(err), (file, status, offset, empty_reads)));
                            }
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                        Ok(n) => {
                            empty_reads = 0;
                            offset += n as u64;
                            buf.truncate(n);
                            return Some((
                                Ok(Bytes::from(buf)),
                                (file, status, offset, empty_reads),
                            ));
                        }
                        Err(e) => return Some((Err(e), (file, status, offset, empty_reads))),
                    }
                    continue;
                }
                if current.done.is_some() {
                    return None;
                }
                // CANCEL-SAFETY: `changed()` only borrows the receiver; a timeout drops the
                // wait and the stream ends with an error, the file handle goes with it.
                match tokio::time::timeout(stall, status.changed()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => {
                        let err = std::io::Error::other("upstream blob fetch abandoned");
                        return Some((Err(err), (file, status, offset, empty_reads)));
                    }
                    Err(_) => {
                        let err = std::io::Error::other(format!(
                            "upstream blob fill reported nothing for {stall:?}"
                        ));
                        return Some((Err(err), (file, status, offset, empty_reads)));
                    }
                }
            }
        },
    )
}

/// Answer a blob cache miss from the spool as it fills.
///
/// The last byte is withheld until the spool has verified the digest, so a poisoned
/// upstream can never complete a `Content-Length` body. A `Range` against a blob whose
/// length upstream declared is served 206 from that offset, or 416 past the end, the
/// way the cache-hit path does: a client resuming a broken pull (containerd sends
/// `bytes=N-`) gets the tail, not the blob again from byte zero, which it would have to
/// read and discard up to N. A ranged body is partial, so it has no whole-blob digest to
/// verify (as on the cache-hit path). Without a declared length, or for a range that
/// does not parse, the whole blob goes out as 200.
async fn spool_response(
    mut follower: tokio::fs::File,
    status: tokio::sync::watch::Receiver<SpoolStatus>,
    content_length: Option<u64>,
    digest: &str,
    headers: &axum::http::HeaderMap,
    stall: Duration,
) -> Response {
    use crate::registry::range::{parse_byte_range, ParsedRange};
    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    // A declared zero length would let hyper complete the response from the headers
    // alone, before the digest verdict; an empty body goes chunked.
    let len = content_length.filter(|&len| len > 0);
    let range = match (
        len,
        headers.get(header::RANGE).and_then(|v| v.to_str().ok()),
    ) {
        (Some(len), Some(value)) => parse_byte_range(value, len),
        _ => ParsedRange::None,
    };
    let builder = Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
        .header("docker-content-digest", digest);
    let response = match (range, len) {
        (ParsedRange::Unsatisfiable, Some(len)) => builder
            .status(StatusCode::RANGE_NOT_SATISFIABLE)
            .header(header::CONTENT_RANGE, format!("bytes */{len}"))
            .body(Body::empty()),
        (ParsedRange::Satisfiable(start, end), Some(len)) => {
            debug_assert!(
                start <= end && end < len,
                "parse_byte_range clamps to the blob"
            );
            if let Err(e) = follower.seek(std::io::SeekFrom::Start(start)).await {
                tracing::error!(error = %e, "Failed to position proxy spool follower");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            let wanted = end - start + 1;
            let reader = tokio_util::io::StreamReader::new(Box::pin(spool_follower(
                follower, status, start, stall,
            )))
            .take(wanted);
            builder
                .status(StatusCode::PARTIAL_CONTENT)
                .header(header::ACCEPT_RANGES, "bytes")
                .header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{len}"))
                .header(header::CONTENT_LENGTH, wanted)
                .body(nora_registry::verified::open_world_stream_body(
                    tokio_util::io::ReaderStream::new(reader),
                ))
        }
        _ => {
            let reader = tokio_util::io::StreamReader::new(Box::pin(spool_follower(
                follower, status, 0, stall,
            )));
            let stream = blob_verifying_stream(
                Box::pin(reader),
                digest,
                format!("docker blob {digest} (fill)"),
            );
            let mut builder = builder.status(StatusCode::OK);
            if let Some(len) = len {
                builder = builder
                    .header(header::CONTENT_LENGTH, len)
                    .header(header::ACCEPT_RANGES, "bytes");
            }
            builder.body(nora_registry::verified::stream_body(stream))
        }
    };
    response.unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// What a request joining a running blob fill needs — the value a fill's leader publishes
/// through `blob_flights` (#1003): the spool file to open its own read handle on, the fill's
/// progress, and upstream's declared length for `Range`.
#[derive(Clone)]
pub(crate) struct SpoolShare {
    pub(super) path: std::path::PathBuf,
    pub(super) status: tokio::sync::watch::Receiver<SpoolStatus>,
    pub(super) content_length: Option<u64>,
}

/// The leader's own part of a fill, never shared: what the spool task consumes and the
/// read handle the leader's response follows.
pub(super) struct LeaderFill {
    pub(super) blob: UpstreamBlob,
    pub(super) spool: SpoolFile,
    pub(super) follower: tokio::fs::File,
    pub(super) progress: tokio::sync::watch::Sender<SpoolStatus>,
}

/// Why [`start_fill`] could not open a fill.
pub(super) enum FillStartError {
    /// The local spool file could not be created or reopened.
    Spool,
    /// Upstream refused or failed before answering headers.
    Upstream(ProxyError),
}

/// Open a fill: the spool file and its first read handle, then the upstream request. The
/// spool exists before upstream answers, so once a circuit-breaker probe is taken the
/// only exits left are the ones the spool task records.
pub(super) async fn start_fill(
    state: &AppState,
    upstream_url: &str,
    upstream_auth: Option<&str>,
    name: &str,
    digest: &str,
    temp_dir: &std::path::Path,
    failure: &mut Option<FillStartError>,
) -> Option<(SpoolShare, LeaderFill)> {
    let spool = match SpoolFile::create(temp_dir).await {
        Ok(spool) => spool,
        Err(e) => {
            tracing::error!(error = ?e, "Failed to create proxy spool file");
            *failure = Some(FillStartError::Spool);
            return None;
        }
    };
    let follower = match spool.follower().await {
        Ok(follower) => follower,
        Err(e) => {
            tracing::error!(error = %e, "Failed to open proxy spool file for streaming");
            *failure = Some(FillStartError::Spool);
            return None;
        }
    };
    match open_blob_from_upstream(
        &state.http_client,
        upstream_url,
        name,
        digest,
        &state.docker_auth,
        state.config.docker.proxy_timeout,
        upstream_auth,
        &state.circuit_breaker,
    )
    .await
    {
        Ok(blob) => {
            let (progress, status) = tokio::sync::watch::channel(SpoolStatus::default());
            let share = SpoolShare {
                path: spool.path.clone(),
                status,
                content_length: blob.content_length,
            };
            Some((
                share,
                LeaderFill {
                    blob,
                    spool,
                    follower,
                    progress,
                },
            ))
        }
        Err(e) => {
            *failure = Some(FillStartError::Upstream(e));
            None
        }
    }
}

/// Run a fill this request leads: start the detached spool task (it holds `lease`, so
/// requests arriving until the blob is stored join this fill) and answer from the spool.
pub(super) async fn lead_fill(
    state: &AppState,
    share: SpoolShare,
    own: LeaderFill,
    lease: Option<crate::proxy_coalesce::Lease<SpoolShare>>,
    blob: &BlobTarget<'_>,
    headers: &axum::http::HeaderMap,
) -> Response {
    let (name, digest, upstream_url) = (blob.upstream_name, blob.digest, blob.upstream_url);
    state.metrics.record_download("docker");
    state.metrics.record_cache_miss("docker");
    state.activity.push(ActivityEntry::new(
        ActionType::ProxyFetch,
        format!("{}@{}", name, &digest[..19.min(digest.len())]),
        crate::registry_type::RegistryType::Docker,
        "PROXY",
    ));
    spawn_blob_spool(
        state.clone(),
        own.blob,
        own.spool,
        blob,
        own.progress,
        lease,
    );
    // Quarantine: the fill continues in the background and lands in the cache;
    // a held digest is answered 403 now (mirrors the manifest proxy path).
    if let Some(resp) = quarantine_proxy_fetch_gate(state, digest, upstream_url).await {
        return resp;
    }
    // Answer as soon as upstream has answered: the body follows the spool file
    // as it grows, so a client that caps time-to-first-header (containerd ≥ 2.3
    // gives up after 30 s) is never left waiting for a multi-GB fill.
    spool_response(
        own.follower,
        share.status,
        share.content_length,
        digest,
        headers,
        fill_stall_ceiling(state.config.docker.read_timeout),
    )
    .await
}

/// Follow a fill another request leads, from the joiner's own read handle on the spool.
/// `None` when the fill can no longer be joined — it failed, or it finished and its spool
/// has already moved into storage — so the caller looks in storage or leads a new fill.
async fn join_fill(
    state: &AppState,
    share: SpoolShare,
    digest: &str,
    upstream_url: &str,
    headers: &axum::http::HeaderMap,
) -> Option<Response> {
    if matches!(share.status.borrow().done, Some(Err(_))) {
        return None;
    }
    // An open handle survives the spool's later rename into storage or its removal.
    let follower = tokio::fs::File::open(&share.path).await.ok()?;
    state.metrics.record_download("docker");
    if let Some(resp) = quarantine_proxy_fetch_gate(state, digest, upstream_url).await {
        return Some(resp);
    }
    Some(
        spool_response(
            follower,
            share.status,
            share.content_length,
            digest,
            headers,
            fill_stall_ceiling(state.config.docker.read_timeout),
        )
        .await,
    )
}

/// The blob a request asked for, as its own request resolved it: the canonical name and
/// storage keys, and the upstream (with the name it goes by there) it is fetched from.
pub(super) struct BlobTarget<'a> {
    pub(super) name: &'a str,
    pub(super) upstream_name: &'a str,
    pub(super) digest: &'a str,
    pub(super) key: &'a str,
    pub(super) legacy_key: &'a str,
    pub(super) upstream_url: &'a str,
}

/// Serve a follower of a running fill: join it, or — when the fill is gone because its
/// spool already moved into storage — serve the stored blob. `None` only when the fill
/// failed and nothing is stored, so the caller leads a new fill.
pub(super) async fn follow_fill(
    state: &AppState,
    share: SpoolShare,
    blob: &BlobTarget<'_>,
    headers: &axum::http::HeaderMap,
) -> Option<Response> {
    if let Some(response) = join_fill(state, share, blob.digest, blob.upstream_url, headers).await {
        return Some(response);
    }
    serve_local_blob(
        state,
        headers,
        blob.name,
        blob.digest,
        blob.key,
        blob.legacy_key,
    )
    .await
}

/// Longest a response may wait on a fill that reports nothing: past the fill's own worst
/// case — a stalled chunk (`read_timeout`) on every resume attempt, plus their back-off —
/// with a margin. The fill always ends in bytes or a verdict before that; the ceiling only
/// guards against a fill that never reports at all.
fn fill_stall_ceiling(read_timeout: u64) -> Duration {
    let backoff: Duration = (1..=UPSTREAM_RESUME_ATTEMPTS)
        .map(|attempt| UPSTREAM_RESUME_BACKOFF * attempt)
        .sum();
    Duration::from_secs(read_timeout * (u64::from(UPSTREAM_RESUME_ATTEMPTS) + 1))
        + backoff
        + Duration::from_secs(30)
}

/// Spool an upstream blob to disk and store it, detached from the request that started
/// it: a client that gives up mid-fill (containerd retries a slow pull from scratch) no
/// longer discards the bytes already fetched, and the next request is a cache hit.
///
/// A panic inside the fill is caught like the other detached tasks (`spawn_cache`, the
/// PyPI backfill): it is logged, counted, and published to the follower as a failed
/// spool, so the response aborts instead of hanging on a dropped sender.
fn spawn_blob_spool(
    state: AppState,
    blob: UpstreamBlob,
    spool: SpoolFile,
    target: &BlobTarget<'_>,
    progress: tokio::sync::watch::Sender<SpoolStatus>,
    lease: Option<crate::proxy_coalesce::Lease<SpoolShare>>,
) {
    use futures::FutureExt as _;
    use std::panic::AssertUnwindSafe;

    let (key, digest, upstream) = (
        target.key.to_string(),
        target.digest.to_string(),
        target.upstream_url.to_string(),
    );

    let read_timeout = state.config.docker.read_timeout;
    let progress = Arc::new(progress);
    let on_panic = Arc::clone(&progress);
    let panic_key = key.clone();
    let task = async move {
        let outcome = spool_upstream_blob(
            blob,
            spool,
            read_timeout,
            &state.circuit_breaker,
            Some(progress.as_ref()),
        )
        .await;
        let mut fetched = match outcome {
            Ok(fetched) => fetched,
            Err(e) => {
                tracing::warn!(error = ?e, key = %key, "Docker blob proxy fetch failed mid-stream");
                // Release the flight before announcing the failure, so a request that sees
                // it can only start a fresh fill, never join this dead one.
                drop(lease);
                progress.send_modify(|s| s.done = Some(Err(format!("{e:?}"))));
                return;
            }
        };
        let expected_hash = digest.strip_prefix("sha256:").unwrap_or(&digest);
        if fetched.sha256 != expected_hash {
            tracing::warn!(
                digest = %digest,
                expected = %expected_hash,
                actual = %fetched.sha256,
                "Docker blob SHA-256 mismatch from upstream — not cached"
            );
            // TempFileGuard drops and cleans up; the follower's own handle still reads
            // to the end, and the verifying stream fails the response before its last frame.
            drop(lease);
            progress.send_modify(|s| s.done = Some(Err("SHA-256 mismatch".to_string())));
            return;
        }
        // The digest is the verdict the response is waiting on; release the last byte
        // now rather than after the storage upload, which can take as long again.
        progress.send_modify(|s| s.done = Some(Ok(())));
        quarantine_record_verified(&state, &digest, &upstream);
        let sha_for_pin = fetched.sha256.clone();
        match state
            .storage
            .put_from_path(&key, &fetched.path, Some(&sha_for_pin))
            .await
        {
            Ok(()) => {
                fetched._guard.disarm();
                state.repo_index.invalidate("docker");
            }
            Err(e) => {
                crate::metrics::CACHE_WRITE_ERRORS
                    .with_label_values(&["docker", "proxy_blob_store"])
                    .inc();
                tracing::error!(
                    error = %e,
                    key = %key,
                    "Failed to store proxied blob — the response still completes from the spool"
                );
            }
        }
        // Held until the blob is in storage (an S3 upload can take as long as the fill),
        // so a request arriving in between still joins instead of refetching.
        drop(lease);
    };
    tokio::spawn(AssertUnwindSafe(task).catch_unwind().map(move |done| {
        if let Err(panic) = done {
            crate::metrics::CACHE_WRITE_ERRORS
                .with_label_values(&["docker", "proxy_blob_spool_panic"])
                .inc();
            tracing::error!(panic = ?panic, key = %panic_key, "Docker blob spool task panicked");
            on_panic.send_modify(|s| {
                if s.done.is_none() {
                    s.done = Some(Err("spool task panicked".to_string()));
                }
            });
        }
    }));
}

/// How to ask upstream for a blob again: kept with an opened blob so a spool that loses
/// the connection mid-body can request the missing tail instead of failing the fill.
struct BlobSource {
    client: reqwest::Client,
    upstream_url: String,
    name: String,
    url: String,
    docker_auth: DockerAuth,
    basic_auth: Option<String>,
    /// Seconds to wait for the response headers of each request.
    timeout: u64,
}

/// Why a blob request produced no response.
enum BlobRequestError {
    /// Connection, TLS or header timeout: counts against the upstream's breaker.
    Network(String),
    /// Upstream answered 401 and no token came of it: refused, or the token server failed.
    Token(TokenError),
}

impl BlobSource {
    /// The error for a blob request: a token failure is logged and told apart (#1196).
    fn proxy_error(&self, e: BlobRequestError) -> ProxyError {
        match e {
            BlobRequestError::Network(reason) => ProxyError::Network(reason),
            BlobRequestError::Token(e) => token_error(
                e,
                &self.upstream_url,
                &self.name,
                self.basic_auth.as_deref(),
            ),
        }
    }
}

/// Why a blob fill stopped, split the way the circuit breaker needs it.
enum FillFailure {
    /// The upstream failed us: connection, stalled or short body, 5xx, bad range.
    Unavailable(ProxyError),
    /// The upstream answered but refused (4xx, no token): alive, not down.
    Refused(ProxyError),
}

impl FillFailure {
    fn as_proxy_error(&self) -> &ProxyError {
        match self {
            FillFailure::Unavailable(e) | FillFailure::Refused(e) => e,
        }
    }

    fn into_proxy_error(self) -> ProxyError {
        match self {
            FillFailure::Unavailable(e) | FillFailure::Refused(e) => e,
        }
    }
}

impl BlobSource {
    /// One blob GET, answering a 401 challenge with a bearer token. `range_from` asks for
    /// the tail from that byte and reuses the cached bearer token that opened the blob.
    async fn send(&self, range_from: Option<u64>) -> Result<reqwest::Response, BlobRequestError> {
        let cached_bearer = match range_from {
            Some(_) => self
                .docker_auth
                .get_token(
                    &self.upstream_url,
                    &self.name,
                    None,
                    self.basic_auth.as_deref(),
                )
                .await
                .ok()
                .map(|token| format!("Bearer {token}")),
            None => None,
        };
        let first_auth =
            cached_bearer.or_else(|| self.basic_auth.as_deref().map(basic_auth_header));
        let response = self.send_once(first_auth, range_from).await?;
        if response.status() != reqwest::StatusCode::UNAUTHORIZED {
            return Ok(response);
        }
        let www_auth = response
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let token = self
            .docker_auth
            .get_token(
                &self.upstream_url,
                &self.name,
                www_auth.as_deref(),
                self.basic_auth.as_deref(),
            )
            .await
            .map_err(BlobRequestError::Token)?;
        self.send_once(Some(format!("Bearer {token}")), range_from)
            .await
    }

    /// `timeout` bounds the wait for the response headers only. The body of a multi-GB
    /// layer is paced by the spool's per-chunk `read_timeout`: reqwest's
    /// `RequestBuilder::timeout` is a total deadline that would cut the body instead.
    async fn send_once(
        &self,
        authorization: Option<String>,
        range_from: Option<u64>,
    ) -> Result<reqwest::Response, BlobRequestError> {
        let mut request = self.client.get(&self.url);
        if let Some(value) = authorization {
            request = request.header(reqwest::header::AUTHORIZATION, value);
        }
        if let Some(from) = range_from {
            request = request.header(reqwest::header::RANGE, format!("bytes={from}-"));
        }
        // CANCEL-SAFETY: `send` resolves once the response headers are in; dropping it on
        // timeout drops the connection attempt before any body byte reaches the spool.
        match tokio::time::timeout(Duration::from_secs(self.timeout), request.send()).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(e)) => Err(BlobRequestError::Network(e.to_string())),
            Err(_) => Err(BlobRequestError::Network(format!(
                "no response headers within {}s",
                self.timeout
            ))),
        }
    }

    /// Ask for the rest of a blob from byte `offset`. Returns the response and how many
    /// leading body bytes to drop: none for a 206 that starts at `offset`, `offset` for an
    /// upstream that ignores `Range` and sends the whole blob again with 200.
    async fn resume(
        &self,
        offset: u64,
        total: Option<u64>,
    ) -> Result<(reqwest::Response, u64), FillFailure> {
        let response = match self.send(Some(offset)).await {
            Ok(response) => response,
            Err(BlobRequestError::Network(reason)) => {
                return Err(FillFailure::Unavailable(ProxyError::Network(reason)))
            }
            Err(e @ BlobRequestError::Token(_)) => {
                return Err(FillFailure::Refused(self.proxy_error(e)))
            }
        };
        match response.status() {
            reqwest::StatusCode::PARTIAL_CONTENT => {
                let range = response
                    .headers()
                    .get(reqwest::header::CONTENT_RANGE)
                    .and_then(|v| v.to_str().ok())
                    .and_then(parse_content_range);
                match range {
                    Some((start, size))
                        if start == offset && (total.is_none() || size == total) =>
                    {
                        Ok((response, 0))
                    }
                    other => Err(FillFailure::Unavailable(ProxyError::Network(format!(
                        "resume from byte {offset}: upstream answered range {other:?}"
                    )))),
                }
            }
            reqwest::StatusCode::OK => match (total, response.content_length()) {
                (Some(want), Some(got)) if want != got => {
                    Err(FillFailure::Unavailable(ProxyError::Network(format!(
                        "resume from byte {offset}: upstream now sends {got} bytes, not {want}"
                    ))))
                }
                _ => Ok((response, offset)),
            },
            // 4xx: upstream is alive and answered (a rejected token, say), as on open (#606)
            status if status.is_client_error() => {
                Err(FillFailure::Refused(ProxyError::Upstream(status.as_u16())))
            }
            status => Err(FillFailure::Unavailable(ProxyError::Upstream(
                status.as_u16(),
            ))),
        }
    }
}

/// `Content-Range: bytes <start>-<end>/<size>` → `(start, size)`; `size` is `None` for `*`.
pub(super) fn parse_content_range(value: &str) -> Option<(u64, Option<u64>)> {
    let (span, size) = value.strip_prefix("bytes ")?.split_once('/')?;
    let (start, end) = span.split_once('-')?;
    let start: u64 = start.trim().parse().ok()?;
    let end: u64 = end.trim().parse().ok()?;
    if end < start {
        return None;
    }
    let size = match size.trim() {
        "*" => None,
        n => {
            let size: u64 = n.parse().ok()?;
            if end >= size {
                return None;
            }
            Some(size)
        }
    };
    Some((start, size))
}

/// Open a blob on an upstream Docker registry: request, token auth and status check,
/// stopping once the response headers are in. The body is read by
/// [`spool_upstream_blob`].
///
/// `timeout` bounds the wait for the response headers; the body itself is paced by the
/// per-chunk `read_timeout` of the spool, which also resumes a cut body.
#[allow(clippy::too_many_arguments)]
pub async fn open_blob_from_upstream(
    client: &reqwest::Client,
    upstream_url: &str,
    name: &str,
    digest: &str,
    docker_auth: &DockerAuth,
    timeout: u64,
    basic_auth: Option<&str>,
    cb: &CircuitBreakerRegistry,
) -> Result<UpstreamBlob, ProxyError> {
    use crate::metrics::PROXY_ACTIVE_DOWNLOADS;

    // Track active concurrent proxy downloads. ProxyDownloadGuard decrements
    // on drop (success, error, or cancellation — all paths).
    PROXY_ACTIVE_DOWNLOADS.inc();
    let _download_gauge_guard = ProxyDownloadGuard;

    tracing::info!(
        blob.name = %name,
        blob.digest = %digest,
        upstream = %upstream_url,
        "Proxy blob download started"
    );

    let cb_key = upstream_key(
        crate::registry_type::RegistryType::Docker.as_str(),
        upstream_url,
    );
    let probe = cb.check(&cb_key)?;

    let source = BlobSource {
        client: client.clone(),
        upstream_url: upstream_url.to_string(),
        name: name.to_string(),
        url: format!(
            "{}/v2/{}/blobs/{}",
            upstream_url.trim_end_matches('/'),
            name,
            digest
        ),
        docker_auth: docker_auth.clone(),
        basic_auth: basic_auth.map(String::from),
        timeout,
    };
    let response = match source.send(None).await {
        Ok(response) => response,
        Err(BlobRequestError::Network(reason)) => {
            cb.record_failure(&cb_key, probe);
            return Err(ProxyError::Network(reason));
        }
        // The registry answered (401) and the token server gave no token: an auth
        // issue, not the registry down — alive, as on resume (`FillFailure::Refused`).
        Err(e @ BlobRequestError::Token(_)) => {
            cb.record_alive(&cb_key, probe);
            return Err(source.proxy_error(e));
        }
    };

    if !response.status().is_success() {
        let status = response.status().as_u16();
        if (400..500).contains(&status) {
            // 4xx — upstream is alive and answered (e.g. blob not found); not an
            // availability failure, so recover the breaker instead of counting
            // it against the upstream (#606).
            cb.record_alive(&cb_key, probe);
        } else {
            cb.record_failure(&cb_key, probe);
        }
        return Err(ProxyError::Upstream(status));
    }

    Ok(UpstreamBlob {
        content_length: response.content_length(),
        response,
        source,
        cb_key,
        probe,
        _download_gauge_guard,
    })
}

/// Resume attempts a spool makes in a row, without receiving a byte, before it fails.
const UPSTREAM_RESUME_ATTEMPTS: u32 = 5;
/// Pause before resume attempt `n` is `n` times this.
const UPSTREAM_RESUME_BACKOFF: Duration = Duration::from_millis(500);

/// A spool write failed on the local disk. The upstream answered and was sending the
/// body, so the probe goes back as alive: counting our disk against the upstream would
/// open its breaker, and dropping the probe would hold the half-open slot (#585).
fn spool_write_failed(
    cb: &CircuitBreakerRegistry,
    cb_key: &str,
    probe: ProbeToken,
    op: &str,
    e: std::io::Error,
) -> ProxyError {
    cb.record_alive(cb_key, probe);
    ProxyError::Network(format!("temp file {op}: {e}"))
}

/// Stream an opened upstream blob to its spool file with a per-chunk `read_timeout` and
/// incremental SHA-256. Never accumulates the blob in RAM. Each chunk is flushed before
/// `progress` advances, so a follower never reads past what is on disk.
///
/// A body that breaks off (connection reset, stalled chunk, short body) is resumed with
/// `Range: bytes=<written>-`, up to [`UPSTREAM_RESUME_ATTEMPTS`] times in a row without
/// progress; the digest is still computed over every byte in order.
pub(crate) async fn spool_upstream_blob(
    blob: UpstreamBlob,
    spool: SpoolFile,
    read_timeout: u64,
    cb: &CircuitBreakerRegistry,
    progress: Option<&tokio::sync::watch::Sender<SpoolStatus>>,
) -> Result<FetchedBlob, ProxyError> {
    use crate::metrics::PROXY_DOWNLOAD_BYTES;
    use sha2::Digest;
    use tokio::io::AsyncWriteExt;

    let UpstreamBlob {
        mut response,
        content_length,
        source,
        cb_key,
        probe,
        _download_gauge_guard,
    } = blob;
    let SpoolFile {
        path: temp_path,
        mut file,
        guard,
    } = spool;
    let mut hasher = sha2::Sha256::new();
    let chunk_timeout = Duration::from_secs(read_timeout);
    let mut bytes_written: u64 = 0;
    // Leading bytes of the current response that are already on disk (a resume that
    // upstream answered with the whole blob).
    let mut skip: u64 = 0;
    let mut stalls: u32 = 0;
    'fill: loop {
        let mut stream = response.bytes_stream();
        let failure = loop {
            // CANCEL-SAFETY: timeout wraps a single stream.next() call. On timeout the
            // spool resumes or fails, and TempFileGuard deletes the partial file.
            match tokio::time::timeout(chunk_timeout, stream.next()).await {
                Ok(Some(Ok(mut chunk))) => {
                    if skip > 0 {
                        let dropped = usize::try_from(skip).unwrap_or(usize::MAX).min(chunk.len());
                        chunk = chunk.slice(dropped..);
                        skip -= dropped as u64;
                        if chunk.is_empty() {
                            continue;
                        }
                    }
                    stalls = 0;
                    hasher.update(&chunk);
                    if let Err(e) = file.write_all(&chunk).await {
                        return Err(spool_write_failed(cb, &cb_key, probe, "write", e));
                    }
                    bytes_written += chunk.len() as u64;
                    if let Some(progress) = progress {
                        if let Err(e) = file.flush().await {
                            return Err(spool_write_failed(cb, &cb_key, probe, "flush", e));
                        }
                        progress.send_modify(|s| s.written = bytes_written);
                    }
                }
                Ok(Some(Err(e))) => {
                    break ProxyError::Network(format!("chunk read error: {}", e));
                }
                Ok(None) => {
                    let short = skip > 0 || content_length.is_some_and(|len| bytes_written < len);
                    if !short {
                        break 'fill;
                    }
                    break ProxyError::Network(format!(
                        "upstream body ended at byte {} of {:?}",
                        bytes_written, content_length
                    ));
                }
                Err(_) => {
                    break ProxyError::Network(format!(
                        "read timeout ({}s per chunk)",
                        read_timeout
                    ));
                }
            }
        };
        let mut last = FillFailure::Unavailable(failure);
        (response, skip) = loop {
            stalls += 1;
            if stalls > UPSTREAM_RESUME_ATTEMPTS {
                match last {
                    FillFailure::Unavailable(_) => cb.record_failure(&cb_key, probe),
                    FillFailure::Refused(_) => cb.record_alive(&cb_key, probe),
                }
                return Err(last.into_proxy_error());
            }
            tracing::warn!(
                error = ?last.as_proxy_error(),
                offset = bytes_written,
                attempt = stalls,
                upstream = %source.upstream_url,
                "Proxy blob body interrupted, resuming from upstream"
            );
            tokio::time::sleep(UPSTREAM_RESUME_BACKOFF * stalls).await;
            match source.resume(bytes_written, content_length).await {
                Ok(next) => break next,
                Err(e) => last = e,
            }
        };
    }
    debug_assert_eq!(skip, 0, "a finished fill has no bytes left to skip");
    if let Err(e) = file.flush().await {
        return Err(spool_write_failed(cb, &cb_key, probe, "flush", e));
    }
    drop(file);
    let sha256 = hex::encode(sha2::Digest::finalize(hasher));
    cb.record_success(&cb_key, probe);
    PROXY_DOWNLOAD_BYTES.inc_by(bytes_written);
    tracing::info!(
        bytes = bytes_written,
        content_length = ?content_length,
        "Proxy blob download complete"
    );
    Ok(FetchedBlob {
        path: temp_path,
        sha256,
        _guard: guard,
    })
}

/// Fetch a blob from an upstream Docker registry into a temp file (#580): open it,
/// spool it, return once the complete, hashed blob is on disk. Callers that want to
/// serve while the spool is still running use [`open_blob_from_upstream`] and
/// [`spool_upstream_blob`] separately.
#[allow(clippy::too_many_arguments)]
pub async fn fetch_blob_from_upstream(
    client: &reqwest::Client,
    upstream_url: &str,
    name: &str,
    digest: &str,
    docker_auth: &DockerAuth,
    timeout: u64,
    read_timeout: u64,
    basic_auth: Option<&str>,
    cb: &CircuitBreakerRegistry,
    temp_dir: &std::path::Path,
) -> Result<FetchedBlob, ProxyError> {
    // The spool first, as in `start_fill`: once `open_blob_from_upstream` takes a
    // circuit-breaker probe, the only exits left are the ones the spool records.
    let spool = SpoolFile::create(temp_dir).await?;
    let blob = open_blob_from_upstream(
        client,
        upstream_url,
        name,
        digest,
        docker_auth,
        timeout,
        basic_auth,
        cb,
    )
    .await?;
    spool_upstream_blob(blob, spool, read_timeout, cb, None).await
}

/// The error for a 401 that got no token. A refusal is logged with the upstream: its cause is
/// the credential configured for that upstream, not an outage (#1196).
fn token_error(
    e: TokenError,
    upstream_url: &str,
    name: &str,
    basic_auth: Option<&str>,
) -> ProxyError {
    match e {
        TokenError::Refused if basic_auth.is_some() => {
            tracing::warn!(upstream = %upstream_url, name, "upstream refused NORA's credentials");
            ProxyError::CredentialsRefused
        }
        TokenError::Refused => {
            tracing::warn!(
                upstream = %upstream_url,
                name,
                "upstream requires credentials and none are configured for it"
            );
            ProxyError::CredentialsRefused
        }
        TokenError::Unavailable => {
            tracing::error!(upstream = %upstream_url, name, "Failed to acquire token");
            ProxyError::Network("token fetch failed".into())
        }
    }
}

/// Fetch a manifest from an upstream Docker registry
/// Returns (manifest_bytes, content_type)
#[allow(clippy::too_many_arguments)]
pub async fn fetch_manifest_from_upstream(
    client: &reqwest::Client,
    upstream_url: &str,
    name: &str,
    reference: &str,
    docker_auth: &DockerAuth,
    timeout: u64,
    basic_auth: Option<&str>,
    cb: &CircuitBreakerRegistry,
) -> Result<(Vec<u8>, String), ProxyError> {
    let cb_key = upstream_key(
        crate::registry_type::RegistryType::Docker.as_str(),
        upstream_url,
    );
    let probe = cb.check(&cb_key)?;

    let url = format!(
        "{}/v2/{}/manifests/{}",
        upstream_url.trim_end_matches('/'),
        name,
        reference
    );

    tracing::debug!(url = %url, "Fetching manifest from upstream");

    // Request with Accept header for manifest types
    let accept_header = "application/vnd.docker.distribution.manifest.v2+json, \
                         application/vnd.docker.distribution.manifest.list.v2+json, \
                         application/vnd.oci.image.manifest.v1+json, \
                         application/vnd.oci.image.index.v1+json";

    // First try — with basic auth if configured
    let mut request = client
        .get(&url)
        .timeout(Duration::from_secs(timeout))
        .header("Accept", accept_header);
    if let Some(credentials) = basic_auth {
        request = request.header("Authorization", basic_auth_header(credentials));
    }
    let response = request.send().await.map_err(|e| {
        tracing::error!(error = %e, url = %url, "Failed to send request to upstream");
        cb.record_failure(&cb_key, probe);
        ProxyError::Network(e.to_string())
    })?;

    tracing::debug!(status = %response.status(), "Initial upstream response");

    let response = if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        // Get Www-Authenticate header and fetch token
        let www_auth = response
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        tracing::debug!(www_auth = ?www_auth, "Got 401, fetching token");

        match docker_auth
            .get_token(upstream_url, name, www_auth.as_deref(), basic_auth)
            .await
        {
            Ok(token) => {
                tracing::debug!("Token acquired, retrying with auth");
                client
                    .get(&url)
                    .timeout(Duration::from_secs(timeout))
                    .header("Accept", accept_header)
                    .header("Authorization", format!("Bearer {}", token))
                    .send()
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "Failed to send authenticated request");
                        cb.record_failure(&cb_key, probe);
                        ProxyError::Network(e.to_string())
                    })?
            }
            // The registry answered (401) and gave no token: an auth issue, not the
            // registry down — alive, so the probe is returned.
            Err(e) => {
                cb.record_alive(&cb_key, probe);
                return Err(token_error(e, upstream_url, name, basic_auth));
            }
        }
    } else {
        response
    };

    tracing::debug!(status = %response.status(), "Final upstream response");

    if !response.status().is_success() {
        let status = response.status().as_u16();
        tracing::warn!(status = %response.status(), "Upstream returned non-success status");
        if status == 429 {
            // Docker Hub pull-rate limit: back off, and tell the client so (C55)
            // instead of letting it read as a missing manifest.
            cb.record_failure(&cb_key, probe);
            return Err(crate::registry::upstream_4xx(status, response.headers()));
        }
        if (400..500).contains(&status) {
            // 4xx — upstream is alive and answered (e.g. manifest not found);
            // recover the breaker rather than counting it as a failure (#606).
            cb.record_alive(&cb_key, probe);
        } else {
            cb.record_failure(&cb_key, probe);
        }
        return Err(ProxyError::Upstream(status));
    }

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/vnd.docker.distribution.manifest.v2+json")
        .to_string();

    // Read under the cap a pushed manifest has: an upstream cannot make NORA buffer more.
    let mut response = response;
    let mut bytes = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) if bytes.len() + chunk.len() > MAX_MANIFEST_BYTES => {
                tracing::warn!(url = %url, cap = MAX_MANIFEST_BYTES, "Upstream manifest exceeds the size cap; not served");
                // The registry answered: alive, though this answer is unusable.
                cb.record_alive(&cb_key, probe);
                return Err(ProxyError::Upstream(502));
            }
            Ok(Some(chunk)) => bytes.extend_from_slice(&chunk),
            Ok(None) => break,
            Err(e) => {
                cb.record_failure(&cb_key, probe);
                return Err(ProxyError::Network(e.to_string()));
            }
        }
    }
    // Only a manifest media type is passed on; anything else is read off the manifest.
    let essence = content_type.split(';').next().unwrap_or_default().trim();
    let content_type = if MANIFEST_MEDIA_TYPES
        .iter()
        .any(|t| essence.eq_ignore_ascii_case(t))
    {
        content_type
    } else {
        detect_manifest_media_type(&bytes)
    };

    cb.record_success(&cb_key, probe);
    Ok((bytes, content_type))
}

/// The media types a manifest is served with.
const MANIFEST_MEDIA_TYPES: [&str; 6] = [
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v1+prettyjws",
];

/// Why an upstream's 200 body is not a manifest, or `None` when it is one: a JSON object with
/// a numeric `schemaVersion` (1 for the schema an old registry may still hold, 2 otherwise).
pub(super) fn upstream_manifest_invalid(body: &[u8]) -> Option<&'static str> {
    match serde_json::from_slice::<Value>(body) {
        Ok(Value::Object(m)) if m.get("schemaVersion").is_some_and(Value::is_u64) => None,
        Ok(Value::Object(_)) => Some("no schemaVersion"),
        _ => Some("not a JSON object"),
    }
}
