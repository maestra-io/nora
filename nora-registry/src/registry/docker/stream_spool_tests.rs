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
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("spool");
    tokio::fs::write(&path, bytes).await.unwrap();
    let file = tokio::fs::File::open(&path).await.unwrap();
    let (tx, rx) = tokio::sync::watch::channel(status);
    (
        Box::pin(super::spool_follower(file, rx, 0, Duration::from_secs(60))),
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
