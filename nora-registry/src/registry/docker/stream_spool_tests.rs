// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

//! A proxied blob is served while it is still being spooled from upstream.
use super::{blob_key, canonicalize};
use crate::test_helpers::{body_bytes, create_test_context_with_config, send, TestContext};
use axum::body::{Body, Bytes};
use axum::http::{header, Method, StatusCode};
use axum::response::Response;
use axum::Router;
use futures::StreamExt;
use sha2::Digest;
use std::sync::Arc;
use std::time::Duration;

/// Upstream that answers its headers at once and trickles the body in `chunks`
/// pieces `delay` apart, so a test can tell "headers before the body" from
/// "headers after the whole blob".
async fn slow_blob_upstream(blob: Vec<u8>, chunks: usize, delay: Duration) -> String {
    slow_blob_upstream_framed(blob, chunks, delay, true).await
}

/// `declare_length = false` answers chunked, with no `Content-Length`.
async fn slow_blob_upstream_framed(
    blob: Vec<u8>,
    chunks: usize,
    delay: Duration,
    declare_length: bool,
) -> String {
    use axum::routing::get;
    let blob = Arc::new(blob);
    let app = Router::new().route(
        "/v2/{*rest}",
        get(move || {
            let blob = blob.clone();
            async move {
                let piece = blob.len().div_ceil(chunks).max(1);
                let pieces: Vec<Bytes> = blob.chunks(piece).map(Bytes::copy_from_slice).collect();
                let body = futures::stream::iter(pieces).then(move |p| async move {
                    tokio::time::sleep(delay).await;
                    Ok::<_, std::io::Error>(p)
                });
                let mut builder = Response::builder().status(StatusCode::OK);
                if declare_length {
                    builder = builder.header(header::CONTENT_LENGTH, blob.len());
                }
                builder.body(Body::from_stream(body)).unwrap()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

fn slow_upstream_ctx(upstream: String) -> TestContext {
    use crate::config::DockerUpstream;
    create_test_context_with_config(|cfg| {
        cfg.docker.upstreams = vec![DockerUpstream {
            trust_upstream_dates: false,
            date_token_file: None,
            token_hosts: Vec::new(),
            url: upstream,
            auth: None,
            auth_env: None,
            namespace: None,
            prefix: None,
            namespaces: Vec::new(),
        }];
    })
}

async fn wait_until(
    deadline: Duration,
    mut ready: impl FnMut() -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>>,
) -> bool {
    let started = std::time::Instant::now();
    while started.elapsed() < deadline {
        if ready().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

fn proxy_temp_count(ctx: &TestContext) -> usize {
    let proxy_tmp = std::path::Path::new(&ctx.state.config.storage.path).join("tmp/docker-proxy");
    std::fs::read_dir(&proxy_tmp)
        .map(|rd| rd.filter_map(|e| e.ok()).count())
        .unwrap_or(0)
}

/// A cache miss answers with the upstream headers before the blob is on disk and
/// streams the body as the spool grows; the blob is cached once the spool ends.
#[tokio::test]
async fn test_docker_proxy_blob_streams_while_spooling() {
    let blob: Vec<u8> = (0..(4 * 256 * 1024 + 17))
        .map(|i| (i % 251) as u8)
        .collect();
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&blob)));
    let delay = Duration::from_millis(250);
    let upstream = slow_blob_upstream(blob.clone(), 4, delay).await;
    let ctx = slow_upstream_ctx(upstream);

    let started = std::time::Instant::now();
    let response = send(
        &ctx.app,
        Method::GET,
        &format!("/v2/library/test/blobs/{digest}"),
        Body::empty(),
    )
    .await;
    let headers_after = started.elapsed();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_LENGTH].to_str().unwrap(),
        blob.len().to_string()
    );
    assert_eq!(response.headers()["docker-content-digest"], digest.as_str());
    // The whole body takes 4 × delay to arrive from upstream; the headers must not.
    assert!(
        headers_after < delay * 2,
        "headers arrived only after {headers_after:?}, i.e. after the spool"
    );

    let body = body_bytes(response).await;
    assert_eq!(body.len(), blob.len());
    assert_eq!(body.as_ref(), &blob[..]);
    assert!(
        started.elapsed() >= delay * 4,
        "the body cannot be complete before upstream sent it"
    );

    let c = canonicalize("library/test", &ctx.state.config.docker);
    let key = blob_key(c.namespace.as_deref(), &c.name, &digest);
    let storage = ctx.state.storage.clone();
    let k = key.clone();
    assert!(
        wait_until(Duration::from_secs(5), move || {
            let storage = storage.clone();
            let k = k.clone();
            Box::pin(async move { storage.get(&k).await.is_ok() })
        })
        .await,
        "blob must be cached after the spool completes"
    );
    assert_eq!(
        ctx.state.storage.get(&key).await.unwrap().as_ref(),
        &blob[..]
    );
    assert_eq!(
        proxy_temp_count(&ctx),
        0,
        "spool file must be gone once stored"
    );
}

/// A client that drops the response mid-fill (containerd retrying a slow pull from
/// scratch) must not discard the fill: the spool keeps going and the blob is cached.
#[tokio::test]
async fn test_docker_proxy_blob_fill_survives_client_disconnect() {
    let blob: Vec<u8> = (0..(2 * 256 * 1024 + 5)).map(|i| (i % 253) as u8).collect();
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&blob)));
    let upstream = slow_blob_upstream(blob.clone(), 4, Duration::from_millis(150)).await;
    let ctx = slow_upstream_ctx(upstream);

    let response = send(
        &ctx.app,
        Method::GET,
        &format!("/v2/library/test/blobs/{digest}"),
        Body::empty(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    drop(response);

    let c = canonicalize("library/test", &ctx.state.config.docker);
    let key = blob_key(c.namespace.as_deref(), &c.name, &digest);
    let storage = ctx.state.storage.clone();
    let k = key.clone();
    assert!(
        wait_until(Duration::from_secs(5), move || {
            let storage = storage.clone();
            let k = k.clone();
            Box::pin(async move { storage.get(&k).await.is_ok() })
        })
        .await,
        "the fill must complete without a client"
    );
    assert_eq!(
        ctx.state.storage.get(&key).await.unwrap().as_ref(),
        &blob[..]
    );
    assert_eq!(proxy_temp_count(&ctx), 0);
}

/// Over real HTTP framing a poisoned upstream must not yield a complete body: hyper
/// stops reading a `Content-Length` body once the declared bytes are out, so the last
/// byte is withheld until the spool has verified the digest.
#[tokio::test]
async fn test_docker_proxy_blob_mismatch_aborts_framed_body() {
    let real = b"the real layer bytes".to_vec();
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&real)));
    let poisoned = b"poisoned bytes of same len".to_vec();
    assert_ne!(real, poisoned);
    let upstream = slow_blob_upstream(poisoned, 2, Duration::from_millis(50)).await;
    let ctx = slow_upstream_ctx(upstream);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = ctx.app.clone();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    let response = reqwest::Client::new()
        .get(format!("http://{addr}/v2/library/test/blobs/{digest}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert!(
        response.bytes().await.is_err(),
        "a poisoned blob must not arrive as a complete body"
    );

    let c = canonicalize("library/test", &ctx.state.config.docker);
    let key = blob_key(c.namespace.as_deref(), &c.name, &digest);
    let started = std::time::Instant::now();
    while proxy_temp_count(&ctx) > 0 && started.elapsed() < Duration::from_secs(5) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        ctx.state.storage.get(&key).await.is_err(),
        "poisoned blob must not be cached"
    );
    assert_eq!(proxy_temp_count(&ctx), 0);
}

async fn follower_over(
    bytes: &[u8],
    status: super::SpoolStatus,
) -> (
    std::pin::Pin<Box<dyn futures::Stream<Item = std::io::Result<Bytes>> + Send>>,
    tokio::sync::watch::Sender<super::SpoolStatus>,
    tempfile::TempDir,
) {
    follower_over_gated(bytes, status, false).await
}

async fn follower_over_gated(
    bytes: &[u8],
    status: super::SpoolStatus,
    gate_all: bool,
) -> (
    std::pin::Pin<Box<dyn futures::Stream<Item = std::io::Result<Bytes>> + Send>>,
    tokio::sync::watch::Sender<super::SpoolStatus>,
    tempfile::TempDir,
) {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("spool");
    tokio::fs::write(&path, bytes).await.unwrap();
    let file = tokio::fs::File::open(&path).await.unwrap();
    let (tx, rx) = tokio::sync::watch::channel(status);
    (
        Box::pin(super::spool_follower(
            file,
            rx,
            0,
            Duration::from_secs(60),
            gate_all,
        )),
        tx,
        dir,
    )
}

/// A spool that reports nothing past the stall ceiling fails the read instead of
/// holding the response forever.
#[tokio::test]
async fn spool_follower_fails_past_the_stall_ceiling() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("spool");
    tokio::fs::write(&path, b"abc").await.unwrap();
    let file = tokio::fs::File::open(&path).await.unwrap();
    let (_tx, rx) = tokio::sync::watch::channel(super::SpoolStatus {
        written: 3,
        done: None,
    });
    let mut follower = Box::pin(super::spool_follower(
        file,
        rx,
        0,
        Duration::from_millis(100),
        false,
    ));
    // Two bytes are released (one held back), then nothing more ever comes.
    let first = tokio::time::timeout(Duration::from_secs(1), follower.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(first.as_ref(), b"ab");
    let stalled = tokio::time::timeout(Duration::from_secs(2), follower.next())
        .await
        .expect("the ceiling ends the wait")
        .expect("an item, not a clean end");
    assert!(stalled.is_err(), "a silent spool must fail the read");
}

/// The follower withholds the last flushed byte until the spool reports a verified
/// end, so a `Content-Length` body can never complete on unverified bytes.
#[tokio::test]
async fn spool_follower_withholds_last_byte_until_done() {
    let data = b"0123456789";
    let pending = super::SpoolStatus {
        written: data.len() as u64,
        done: None,
    };
    let (mut follower, tx, _dir) = follower_over(data, pending).await;

    let first = follower.next().await.unwrap().unwrap();
    assert_eq!(first.as_ref(), &data[..data.len() - 1]);
    assert!(
        tokio::time::timeout(Duration::from_millis(200), follower.next())
            .await
            .is_err(),
        "the last byte must not be released while the spool is unverified"
    );

    tx.send_modify(|s| s.done = Some(Ok(())));
    let last = follower.next().await.unwrap().unwrap();
    assert_eq!(last.as_ref(), &data[data.len() - 1..]);
    assert!(
        follower.next().await.is_none(),
        "EOF after the verified last byte"
    );
}

/// A spool that ends in failure turns into a read error before the last byte.
#[tokio::test]
async fn spool_follower_errors_on_failed_spool() {
    let data = b"0123456789";
    let pending = super::SpoolStatus {
        written: data.len() as u64,
        done: None,
    };
    let (mut follower, tx, _dir) = follower_over(data, pending).await;
    let first = follower.next().await.unwrap().unwrap();
    assert_eq!(first.len(), data.len() - 1);

    tx.send_modify(|s| s.done = Some(Err("SHA-256 mismatch".to_string())));
    let err = follower.next().await.unwrap().unwrap_err();
    assert!(err.to_string().contains("SHA-256 mismatch"), "{err}");
}

/// Bytes flushed between a short read and the status check are picked up without
/// waiting for a further update.
#[tokio::test]
async fn spool_follower_reads_bytes_published_before_it_waited() {
    let data = b"abcdef";
    let empty = super::SpoolStatus {
        written: 0,
        done: None,
    };
    let (mut follower, tx, _dir) = follower_over(data, empty).await;
    let pending = tokio::time::timeout(Duration::from_millis(100), follower.next());
    assert!(
        pending.await.is_err(),
        "nothing is released before any flush"
    );
    tx.send_modify(|s| s.written = data.len() as u64);
    let chunk = tokio::time::timeout(Duration::from_secs(1), follower.next())
        .await
        .expect("published bytes must be delivered")
        .unwrap()
        .unwrap();
    assert_eq!(chunk.as_ref(), &data[..data.len() - 1]);
}

async fn serve_ctx(ctx: &TestContext) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = ctx.app.clone();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    addr
}

/// An upstream that answers chunked (no `Content-Length`) streams and caches the same
/// way; the response is chunked too and ends only after the verified last byte.
#[tokio::test]
async fn test_docker_proxy_blob_chunked_upstream_streams_and_caches() {
    let blob: Vec<u8> = (0..(300 * 1024 + 3)).map(|i| (i % 249) as u8).collect();
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&blob)));
    let upstream =
        slow_blob_upstream_framed(blob.clone(), 3, Duration::from_millis(100), false).await;
    let ctx = slow_upstream_ctx(upstream);
    let addr = serve_ctx(&ctx).await;

    let response = reqwest::Client::new()
        .get(format!("http://{addr}/v2/library/test/blobs/{digest}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert!(response.headers().get(header::CONTENT_LENGTH).is_none());
    assert_eq!(response.bytes().await.unwrap().as_ref(), &blob[..]);

    let c = canonicalize("library/test", &ctx.state.config.docker);
    let key = blob_key(c.namespace.as_deref(), &c.name, &digest);
    let storage = ctx.state.storage.clone();
    let k = key.clone();
    assert!(
        wait_until(Duration::from_secs(5), move || {
            let storage = storage.clone();
            let k = k.clone();
            Box::pin(async move { storage.get(&k).await.is_ok() })
        })
        .await
    );
}

/// `Content-Length: 0` from upstream for a non-empty digest must not complete as a
/// clean 200: hyper would finish the response from the headers alone, so an empty
/// body is never declared and the verdict still gates the end of the body.
#[tokio::test]
async fn test_docker_proxy_blob_empty_poisoned_body_aborts() {
    let real = b"not empty".to_vec();
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&real)));
    let upstream = slow_blob_upstream(Vec::new(), 1, Duration::from_millis(20)).await;
    let ctx = slow_upstream_ctx(upstream);
    let addr = serve_ctx(&ctx).await;

    let response = reqwest::Client::new()
        .get(format!("http://{addr}/v2/library/test/blobs/{digest}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert!(
        response.bytes().await.is_err(),
        "an empty poisoned body must not complete cleanly"
    );
    let c = canonicalize("library/test", &ctx.state.config.docker);
    let key = blob_key(c.namespace.as_deref(), &c.name, &digest);
    let started = std::time::Instant::now();
    while proxy_temp_count(&ctx) > 0 && started.elapsed() < Duration::from_secs(5) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ctx.state.storage.get(&key).await.is_err());
}

/// Quarantine in enforce mode still holds a digest this mirror has never seen: the
/// streaming path answers 403 before any byte, and the fill still completes and lands
/// in the cache with the digest recorded, so the hold expires on schedule.
#[tokio::test]
async fn test_docker_proxy_blob_new_digest_held_on_streaming_path() {
    use crate::config::DockerUpstream;
    use crate::digest_quarantine::{QuarantineMode, QuarantineStatus};
    let blob: Vec<u8> = (0..(64 * 1024 + 9)).map(|i| (i % 247) as u8).collect();
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&blob)));
    let upstream = slow_blob_upstream(blob.clone(), 2, Duration::from_millis(50)).await;
    let ctx = create_test_context_with_config(|cfg| {
        cfg.docker.upstreams = vec![DockerUpstream {
            trust_upstream_dates: false,
            date_token_file: None,
            token_hosts: Vec::new(),
            url: upstream,
            auth: None,
            auth_env: None,
            namespace: None,
            prefix: None,
            namespaces: Vec::new(),
        }];
        cfg.curation.quarantine = Some(QuarantineMode::Enforce);
        cfg.curation.quarantine_ttl = Some("1h".to_string());
    });

    let response = send(
        &ctx.app,
        Method::GET,
        &format!("/v2/library/test/blobs/{digest}"),
        Body::empty(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a new digest is held"
    );

    let c = canonicalize("library/test", &ctx.state.config.docker);
    let key = blob_key(c.namespace.as_deref(), &c.name, &digest);
    let storage = ctx.state.storage.clone();
    let k = key.clone();
    assert!(
        wait_until(Duration::from_secs(5), move || {
            let storage = storage.clone();
            let k = k.clone();
            Box::pin(async move { storage.get(&k).await.is_ok() })
        })
        .await,
        "the held fill still completes into the cache"
    );
    assert!(
        matches!(
            ctx.state.digest_store.check("docker", &digest, 3600),
            QuarantineStatus::Pending { .. }
        ),
        "first-seen is recorded once the fetch verified"
    );
    let again = send(
        &ctx.app,
        Method::GET,
        &format!("/v2/library/test/blobs/{digest}"),
        Body::empty(),
    )
    .await;
    assert_eq!(
        again.status(),
        StatusCode::FORBIDDEN,
        "still held from the cache"
    );
}

const MIB: u64 = 1024 * 1024;

/// Upstream that answers every blob path with `blob` in `pieces` pieces `delay` apart
/// (`Content-Length` when `declare_length`), counting the blob GETs.
async fn counting_blob_upstream(
    blob: Vec<u8>,
    pieces: usize,
    delay: Duration,
    declare_length: bool,
) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
    use axum::routing::get;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let hits = Arc::new(AtomicUsize::new(0));
    let (blob, h) = (Arc::new(blob), hits.clone());
    let app = Router::new().route(
        "/v2/{*rest}",
        get(move || {
            let (blob, hits) = (blob.clone(), h.clone());
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                let piece = blob.len().div_ceil(pieces).max(1);
                let parts: Vec<Bytes> = blob.chunks(piece).map(Bytes::copy_from_slice).collect();
                let body = futures::stream::iter(parts).then(move |p| async move {
                    tokio::time::sleep(delay).await;
                    Ok::<_, std::io::Error>(p)
                });
                let mut builder = Response::builder().status(StatusCode::OK);
                if declare_length {
                    builder = builder.header(header::CONTENT_LENGTH, blob.len());
                }
                builder.body(Body::from_stream(body)).unwrap()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), hits)
}

/// A context whose Docker fills share a `budget_mb` proxy spool, with a breaker that
/// opens on the first failure.
fn budget_ctx(upstream: String, budget_mb: u64) -> TestContext {
    use crate::config::DockerUpstream;
    create_test_context_with_config(move |cfg| {
        cfg.circuit_breaker.enabled = true;
        cfg.circuit_breaker.failure_threshold = 1;
        cfg.docker.proxy_spool_max_mb = budget_mb;
        cfg.docker.upstreams = vec![DockerUpstream {
            trust_upstream_dates: false,
            date_token_file: None,
            token_hosts: Vec::new(),
            url: upstream,
            auth: None,
            auth_env: None,
            namespace: None,
            prefix: None,
            namespaces: Vec::new(),
        }];
    })
}

fn proxy_temp_bytes(ctx: &TestContext) -> u64 {
    let proxy_tmp = std::path::Path::new(&ctx.state.config.storage.path).join("tmp/docker-proxy");
    std::fs::read_dir(&proxy_tmp)
        .map(|rd| {
            rd.filter_map(|e| e.ok()?.metadata().ok())
                .map(|m| m.len())
                .sum()
        })
        .unwrap_or(0)
}

/// Samples the proxy spool until it is empty (bounded); the largest total seen.
async fn peak_proxy_temp_bytes(ctx: &TestContext) -> u64 {
    let (started, mut peak) = (std::time::Instant::now(), 0);
    loop {
        peak = peak.max(proxy_temp_bytes(ctx));
        if proxy_temp_count(ctx) == 0 || started.elapsed() > Duration::from_secs(15) {
            return peak;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn get_blob(ctx: &TestContext, digest: &str) -> Response<Body> {
    send(
        &ctx.app,
        Method::GET,
        &format!("/v2/library/test/blobs/{digest}"),
        Body::empty(),
    )
    .await
}

/// Audit A060: a blob whose declared length exceeds `docker.proxy_spool_max_mb` is a 507
/// before any byte is spooled, and the upstream's breaker probe goes back as alive.
#[tokio::test]
async fn a060_blob_declared_over_the_proxy_spool_budget_is_507() {
    let blob = vec![7u8; 4 * MIB as usize];
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&blob)));
    let (upstream, _hits) = counting_blob_upstream(blob, 8, Duration::ZERO, true).await;
    let ctx = budget_ctx(upstream.clone(), 1);

    for _ in 0..2 {
        let response = get_blob(&ctx, &digest).await;
        assert_eq!(
            response.status(),
            StatusCode::INSUFFICIENT_STORAGE,
            "a blob over the budget is refused, and an open breaker would make it a 502"
        );
        assert_eq!(proxy_temp_count(&ctx), 0, "no spool file is left");
    }
    let cb_key = crate::circuit_breaker::upstream_key("docker", &upstream);
    assert!(ctx.state.circuit_breaker.check(&cb_key).is_ok());
    let c = canonicalize("library/test", &ctx.state.config.docker);
    let key = blob_key(c.namespace.as_deref(), &c.name, &digest);
    assert!(ctx.state.storage.get(&key).await.is_err());
}

/// Audit A060: while other fills hold the whole budget a new fill is a 503 with
/// `Retry-After`, answered before upstream is asked; once released, the pull works.
#[tokio::test]
async fn a060_busy_proxy_spool_budget_is_503_before_upstream() {
    use std::sync::atomic::Ordering;
    let blob: Vec<u8> = (0..4096).map(|i| (i % 233) as u8).collect();
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&blob)));
    let (upstream, hits) = counting_blob_upstream(blob.clone(), 1, Duration::ZERO, true).await;
    let ctx = budget_ctx(upstream, 1);

    let held = ctx.state.docker_spool.reserve(MIB).unwrap();
    let response = get_blob(&ctx, &digest).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.headers().contains_key(header::RETRY_AFTER));
    assert_eq!(hits.load(Ordering::SeqCst), 0, "upstream is not asked");

    drop(held);
    let response = get_blob(&ctx, &digest).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_bytes(response).await.as_ref(), &blob[..]);
}

/// Audit A060: a chunked body (no `Content-Length`) stops at the budget even with no
/// client left: the spool never holds more than the budget, then it is removed, nothing
/// is stored and the budget is free again.
#[tokio::test]
async fn a060_chunked_body_stops_at_the_proxy_spool_budget() {
    let blob = vec![9u8; 4 * MIB as usize];
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&blob)));
    let (upstream, _hits) =
        counting_blob_upstream(blob, 16, Duration::from_millis(20), false).await;
    let ctx = budget_ctx(upstream, 1);

    let response = get_blob(&ctx, &digest).await;
    assert_eq!(response.status(), StatusCode::OK, "headers go out first");
    drop(response);
    let peak = peak_proxy_temp_bytes(&ctx).await;
    assert!(peak <= MIB, "the spool grew to {peak} bytes");
    assert_eq!(proxy_temp_count(&ctx), 0, "the failed fill is removed");
    let c = canonicalize("library/test", &ctx.state.config.docker);
    let key = blob_key(c.namespace.as_deref(), &c.name, &digest);
    assert!(ctx.state.storage.get(&key).await.is_err());
    assert!(
        ctx.state.docker_spool.reserve(MIB).is_ok(),
        "the failed fill released its budget"
    );
}

/// Audit A060: fills of distinct blobs whose clients all left never hold more than the
/// budget between them; the ones that do not fit are refused.
#[tokio::test]
async fn a060_dropped_fills_never_outgrow_the_proxy_spool_budget() {
    let blob = vec![0x5a_u8; 4 * MIB as usize];
    let (upstream, _hits) = counting_blob_upstream(blob, 8, Duration::from_millis(100), true).await;
    let ctx = budget_ctx(upstream, 5);

    let mut statuses = Vec::new();
    for i in 0..5 {
        let response = get_blob(&ctx, &format!("sha256:{:064x}", i + 1)).await;
        statuses.push(response.status());
        drop(response);
    }
    assert_eq!(statuses[0], StatusCode::OK);
    assert!(
        statuses.contains(&StatusCode::SERVICE_UNAVAILABLE),
        "{statuses:?}"
    );
    let peak = peak_proxy_temp_bytes(&ctx).await;
    assert!(peak <= 5 * MIB, "the spools held {peak} bytes");
}

/// Audit A061: a gated follower (a range) releases nothing until the spool reports a
/// verified end, then everything; a failed spool fails it before its first byte.
#[tokio::test]
async fn a061_gated_follower_releases_nothing_before_the_verdict() {
    let data = b"0123456789";
    let pending = super::SpoolStatus {
        written: data.len() as u64,
        done: None,
    };
    let (mut follower, tx, _dir) = follower_over_gated(data, pending.clone(), true).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(200), follower.next())
            .await
            .is_err(),
        "no byte before the verdict"
    );
    tx.send_modify(|s| s.done = Some(Ok(())));
    let mut got = Vec::new();
    while let Some(chunk) = follower.next().await {
        got.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(got, data);

    let (mut follower, tx, _dir) = follower_over_gated(data, pending, true).await;
    tx.send_modify(|s| s.done = Some(Err("SHA-256 mismatch".to_string())));
    let first = follower.next().await.unwrap();
    assert!(first.is_err(), "the first item is the failure");
}

/// Audit A060: a response that still holds its read handle on a failed fill keeps the
/// fill's budget, since the unlinked file stays on disk until that handle closes; the
/// budget returns once the response is dropped.
#[tokio::test]
async fn a060_an_unread_response_keeps_the_failed_fill_budget() {
    let poisoned = vec![3u8; 256 * 1024];
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(b"other")));
    let (upstream, _hits) =
        counting_blob_upstream(poisoned, 4, Duration::from_millis(20), true).await;
    let ctx = budget_ctx(upstream, 1);

    let response = get_blob(&ctx, &digest).await;
    assert_eq!(response.status(), StatusCode::OK);
    let started = std::time::Instant::now();
    while proxy_temp_count(&ctx) > 0 && started.elapsed() < Duration::from_secs(10) {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        proxy_temp_count(&ctx),
        0,
        "the failed fill removed its spool"
    );
    assert!(
        matches!(
            ctx.state.docker_spool.reserve(MIB),
            Err(crate::registry::SpoolError::Busy)
        ),
        "the unread response still holds the spool's bytes"
    );
    drop(response);
    assert!(ctx.state.docker_spool.reserve(MIB).is_ok());
}
