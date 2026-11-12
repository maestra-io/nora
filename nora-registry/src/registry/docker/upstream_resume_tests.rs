// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

//! A multi-GB layer must survive a slow or flaky upstream link: `proxy_timeout` bounds
//! the wait for upstream headers, not the body, and a body cut mid-stream is resumed
//! with `Range` instead of being fetched again from byte zero.
use super::{blob_key, canonicalize};
use crate::test_helpers::{
    body_bytes, create_test_context_with_config, send, send_with_headers, TestContext,
};
use axum::body::{Body, Bytes};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use futures::StreamExt;
use sha2::Digest;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// How the scripted upstream answers one blob GET.
#[derive(Clone, Copy)]
pub(super) struct Plan {
    /// Answer `Range: bytes=N-` with 206; `false` ignores it and sends the whole blob.
    pub(super) honor_range: bool,
    /// Drop the connection after this many body bytes of this response.
    pub(super) cut_after: Option<usize>,
    /// Body piece size and the pause before each piece.
    pub(super) piece: usize,
    pub(super) delay: Duration,
    /// Pause before the response headers.
    pub(super) header_delay: Duration,
}

impl Plan {
    pub(super) fn fast() -> Self {
        Plan {
            honor_range: true,
            cut_after: None,
            piece: 64 * 1024,
            delay: Duration::ZERO,
            header_delay: Duration::ZERO,
        }
    }
    pub(super) fn cut(after: usize) -> Self {
        Plan {
            cut_after: Some(after),
            ..Plan::fast()
        }
    }
}

/// Upstream that answers blob GETs by `plans[hit]` (the last plan repeats) and records
/// the `Range` header of every request. With `bearer = Some(t)` a blob GET without
/// `Authorization: Bearer t` gets a 401 challenge pointing at its own `/token`.
pub(super) struct ScriptedUpstream {
    pub(super) url: String,
    pub(super) hits: Arc<AtomicUsize>,
    ranges: tokio::sync::mpsc::UnboundedReceiver<Option<String>>,
    server: tokio::task::JoinHandle<()>,
}

impl ScriptedUpstream {
    /// `Range` headers of the blob GETs so far, in arrival order.
    fn ranges(&mut self) -> Vec<Option<String>> {
        std::iter::from_fn(|| self.ranges.try_recv().ok()).collect()
    }
}

impl Drop for ScriptedUpstream {
    fn drop(&mut self) {
        self.server.abort();
    }
}

pub(super) async fn scripted_upstream(
    blob: Vec<u8>,
    plans: Vec<Plan>,
    bearer: Option<&'static str>,
) -> ScriptedUpstream {
    use axum::routing::get;
    let blob = Arc::new(blob);
    let hits = Arc::new(AtomicUsize::new(0));
    let (ranges_tx, ranges) = tokio::sync::mpsc::unbounded_channel();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");
    let realm = format!("{url}/token");
    let (h, r) = (hits.clone(), ranges_tx);
    let app =
        Router::new()
            .route(
                "/token",
                get(move || async move {
                    axum::Json(serde_json::json!({ "token": bearer.unwrap_or("") }))
                }),
            )
            .route(
                "/v2/{*rest}",
                get(move |headers: HeaderMap| {
                    let (blob, plans, hits, ranges, realm) = (
                        blob.clone(),
                        plans.clone(),
                        h.clone(),
                        r.clone(),
                        realm.clone(),
                    );
                    async move {
                        if let Some(token) = bearer {
                            let auth = headers
                                .get(header::AUTHORIZATION)
                                .and_then(|v| v.to_str().ok());
                            if auth != Some(format!("Bearer {token}").as_str()) {
                                return Response::builder()
                                    .status(StatusCode::UNAUTHORIZED)
                                    .header(
                                        header::WWW_AUTHENTICATE,
                                        format!("Bearer realm=\"{realm}\",service=\"test\""),
                                    )
                                    .body(Body::empty())
                                    .unwrap();
                            }
                        }
                        let hit = hits.fetch_add(1, Ordering::SeqCst);
                        let plan = plans[hit.min(plans.len() - 1)];
                        let range = headers
                            .get(header::RANGE)
                            .and_then(|v| v.to_str().ok())
                            .map(String::from);
                        let _ = ranges.send(range.clone());
                        tokio::time::sleep(plan.header_delay).await;
                        let from = range
                            .as_deref()
                            .filter(|_| plan.honor_range)
                            .and_then(|r| r.strip_prefix("bytes="))
                            .and_then(|r| r.strip_suffix('-'))
                            .and_then(|n| n.parse::<usize>().ok());
                        let len = blob.len();
                        let mut builder = Response::builder();
                        let start = match from {
                            Some(n) => {
                                builder = builder.status(StatusCode::PARTIAL_CONTENT).header(
                                    header::CONTENT_RANGE,
                                    format!("bytes {n}-{}/{len}", len - 1),
                                );
                                n
                            }
                            None => {
                                builder = builder.status(StatusCode::OK);
                                0
                            }
                        };
                        let body = blob[start..].to_vec();
                        let send_len = plan.cut_after.map_or(body.len(), |c| c.min(body.len()));
                        let mut pieces: Vec<std::io::Result<Bytes>> = body[..send_len]
                            .chunks(plan.piece.max(1))
                            .map(|p| Ok(Bytes::copy_from_slice(p)))
                            .collect();
                        if plan.cut_after.is_some() {
                            pieces.push(Err(std::io::Error::other("connection cut")));
                        }
                        let delay = plan.delay;
                        let stream = futures::stream::iter(pieces).then(move |p| async move {
                            tokio::time::sleep(delay).await;
                            p
                        });
                        builder
                            .header(header::CONTENT_LENGTH, len - start)
                            .body(Body::from_stream(stream))
                            .unwrap()
                    }
                }),
            );
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    ScriptedUpstream {
        url,
        hits,
        ranges,
        server,
    }
}

pub(super) fn ctx_for(upstream: &ScriptedUpstream, proxy_timeout: u64) -> TestContext {
    use crate::config::DockerUpstream;
    let url = upstream.url.clone();
    create_test_context_with_config(move |cfg| {
        cfg.docker.proxy_timeout = proxy_timeout;
        cfg.docker.upstreams = vec![DockerUpstream {
            trust_upstream_dates: false,
            date_token_file: None,
            url,
            auth: None,
            auth_env: None,
            namespace: None,
            prefix: None,
            namespaces: Vec::new(),
        }];
    })
}

pub(super) fn layer(len: usize) -> (Vec<u8>, String) {
    let blob: Vec<u8> = (0..len).map(|i| (i % 241) as u8).collect();
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&blob)));
    (blob, digest)
}

/// Waits (bounded) for the spool task to store the blob; `true` once it is cached.
pub(super) async fn cached(ctx: &TestContext, digest: &str) -> bool {
    let c = canonicalize("library/test", &ctx.state.config.docker);
    let key = blob_key(c.namespace.as_deref(), &c.name, digest);
    let started = std::time::Instant::now();
    while started.elapsed() < Duration::from_secs(10) {
        if ctx.state.storage.get(&key).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

pub(super) fn proxy_temp_count(ctx: &TestContext) -> usize {
    let proxy_tmp = std::path::Path::new(&ctx.state.config.storage.path).join("tmp/docker-proxy");
    std::fs::read_dir(&proxy_tmp)
        .map(|rd| rd.filter_map(|e| e.ok()).count())
        .unwrap_or(0)
}

pub(super) async fn pull(ctx: &TestContext, digest: &str) -> Response<Body> {
    send(
        &ctx.app,
        Method::GET,
        &format!("/v2/library/test/blobs/{digest}"),
        Body::empty(),
    )
    .await
}

/// Maxim's 3.5 GB ollama layer, scaled down: the body takes longer than
/// `proxy_timeout`, but it keeps flowing, so it must arrive whole in one upstream
/// request — the per-chunk `read_timeout` is what guards a stalled body.
#[tokio::test]
async fn slow_body_is_not_cut_by_proxy_timeout() {
    let (blob, digest) = layer(8 * 16 * 1024);
    let upstream = scripted_upstream(
        blob.clone(),
        vec![Plan {
            piece: 16 * 1024,
            delay: Duration::from_millis(250),
            ..Plan::fast()
        }],
        None,
    )
    .await;
    let ctx = ctx_for(&upstream, 1);

    let response = pull(&ctx, &digest).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await;
    assert_eq!(
        body.expect("a body that outlives proxy_timeout must still complete")
            .as_ref(),
        &blob[..]
    );
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 1, "one upstream GET");
    assert!(cached(&ctx, &digest).await, "blob must be cached");
}

/// Headers that never come are still bounded by `proxy_timeout` (not worse than
/// before): the pull fails over instead of hanging, with 502 — the upstream failed,
/// it did not say the blob is missing.
#[tokio::test]
async fn missing_headers_are_bounded_by_proxy_timeout() {
    let (blob, digest) = layer(1024);
    let upstream = scripted_upstream(
        blob,
        vec![Plan {
            header_delay: Duration::from_secs(5),
            ..Plan::fast()
        }],
        None,
    )
    .await;
    let ctx = ctx_for(&upstream, 1);

    let started = std::time::Instant::now();
    let response = pull(&ctx, &digest).await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "headers wait took {:?}, proxy_timeout is 1s",
        started.elapsed()
    );
}

/// A body cut mid-stream is resumed from the byte already on disk with
/// `Range: bytes=N-`: the client sees one clean body, upstream sends each byte once.
#[tokio::test]
async fn cut_body_resumes_with_range() {
    let (blob, digest) = layer(256 * 1024 + 7);
    let half = blob.len() / 2;
    let mut upstream =
        scripted_upstream(blob.clone(), vec![Plan::cut(half), Plan::fast()], None).await;
    let ctx = ctx_for(&upstream, 5);

    let response = pull(&ctx, &digest).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await;
    assert_eq!(
        body.expect("a resumed fill must stream to a clean end")
            .as_ref(),
        &blob[..]
    );
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 2);
    let ranges = upstream.ranges();
    assert_eq!(ranges[0], None, "first GET is a plain GET");
    assert_eq!(
        ranges[1].as_deref(),
        Some(format!("bytes={half}-").as_str()),
        "resume asks only for the missing tail"
    );
    assert!(cached(&ctx, &digest).await, "resumed blob must be cached");
    assert_eq!(proxy_temp_count(&ctx), 0);
}

/// An upstream that ignores `Range` on the resume and answers 200 with the whole
/// blob: the bytes already on disk are skipped, the result is still exact.
#[tokio::test]
async fn resume_skips_prefix_when_upstream_ignores_range() {
    let (blob, digest) = layer(256 * 1024 + 3);
    let half = blob.len() / 2;
    let whole = Plan {
        honor_range: false,
        ..Plan::fast()
    };
    let upstream = scripted_upstream(blob.clone(), vec![Plan::cut(half), whole], None).await;
    let ctx = ctx_for(&upstream, 5);

    let response = pull(&ctx, &digest).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await;
    assert_eq!(body.expect("clean end").as_ref(), &blob[..]);
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 2);
    assert!(cached(&ctx, &digest).await);
}

/// Docker Hub's bearer tokens outlive neither every layer nor every resume: the
/// resume request carries the (cached or re-fetched) bearer token, not bare auth.
#[tokio::test]
async fn resume_carries_bearer_token() {
    let (blob, digest) = layer(128 * 1024 + 1);
    let upstream = scripted_upstream(
        blob.clone(),
        vec![Plan::cut(blob.len() / 3), Plan::fast()],
        Some("tok"),
    )
    .await;
    let ctx = ctx_for(&upstream, 5);

    let response = pull(&ctx, &digest).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await;
    assert_eq!(body.expect("clean end").as_ref(), &blob[..]);
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 2);
}

/// An upstream that keeps dropping the connection without progress exhausts the
/// resume budget: the response aborts, nothing is cached, the spool is removed.
#[tokio::test]
async fn resume_gives_up_without_progress() {
    let (blob, digest) = layer(64 * 1024);
    let upstream = scripted_upstream(blob.clone(), vec![Plan::cut(1024), Plan::cut(0)], None).await;
    let ctx = ctx_for(&upstream, 5);

    let response = pull(&ctx, &digest).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await;
    assert!(
        body.is_err(),
        "a fill that never completes must not end clean"
    );
    let hits = upstream.hits.load(Ordering::SeqCst);
    assert!(
        hits >= 2,
        "a cut body is resumed at least once (hits = {hits})"
    );
    assert!(hits <= 10, "the resume budget is bounded (hits = {hits})");
    let started = std::time::Instant::now();
    while proxy_temp_count(&ctx) > 0 && started.elapsed() < Duration::from_secs(10) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(proxy_temp_count(&ctx), 0, "spool removed");
    let c = canonicalize("library/test", &ctx.state.config.docker);
    let key = blob_key(c.namespace.as_deref(), &c.name, &digest);
    assert!(ctx.state.storage.get(&key).await.is_err(), "not cached");
}

/// A resume that upstream refuses (its token is no longer accepted, and the token
/// server is down) is an auth problem, not the registry being down: exhausting the
/// resume budget on it must not open the registry's circuit breaker, the way a 4xx
/// or a failed token fetch on the initial open does not (#606).
#[tokio::test]
async fn refused_resume_does_not_trip_breaker() {
    use crate::config::DockerUpstream;
    use axum::routing::get;
    let (blob, digest) = layer(96 * 1024);
    let blob = Arc::new(blob);
    let token_calls = Arc::new(AtomicUsize::new(0));
    let blob_hits = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let realm = format!("{url}/token");
    let tc = token_calls.clone();
    let (b, h) = (blob.clone(), blob_hits.clone());
    // One token, once; the blob GET accepts it once and sends a third of the blob.
    // Every later GET is challenged again, and the token server is down by then.
    let app = Router::new()
        .route(
            "/token",
            get(move || {
                let tc = tc.clone();
                async move {
                    if tc.fetch_add(1, Ordering::SeqCst) == 0 {
                        axum::Json(serde_json::json!({ "token": "t1" })).into_response()
                    } else {
                        StatusCode::SERVICE_UNAVAILABLE.into_response()
                    }
                }
            }),
        )
        .route(
            "/v2/{*rest}",
            get(move |headers: HeaderMap| {
                let (blob, hits, realm) = (b.clone(), h.clone(), realm.clone());
                async move {
                    let authed = headers
                        .get(header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        == Some("Bearer t1");
                    if !authed || hits.fetch_add(1, Ordering::SeqCst) > 0 {
                        return Response::builder()
                            .status(StatusCode::UNAUTHORIZED)
                            .header(
                                header::WWW_AUTHENTICATE,
                                format!("Bearer realm=\"{realm}\",service=\"test\""),
                            )
                            .body(Body::empty())
                            .unwrap();
                    }
                    let third = blob.len() / 3;
                    let pieces: Vec<std::io::Result<Bytes>> = vec![
                        Ok(Bytes::copy_from_slice(&blob[..third])),
                        Err(std::io::Error::other("connection cut")),
                    ];
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_LENGTH, blob.len())
                        .body(Body::from_stream(futures::stream::iter(pieces).then(
                            |p| async move {
                                // headers must reach the client before the cut
                                tokio::time::sleep(Duration::from_millis(50)).await;
                                p
                            },
                        )))
                        .unwrap()
                }
            }),
        );
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let upstream_url = url.clone();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.circuit_breaker.enabled = true;
        cfg.circuit_breaker.failure_threshold = 1;
        cfg.docker.proxy_timeout = 5;
        cfg.docker.upstreams = vec![DockerUpstream {
            trust_upstream_dates: false,
            date_token_file: None,
            url: upstream_url,
            auth: None,
            auth_env: None,
            namespace: None,
            prefix: None,
            namespaces: Vec::new(),
        }];
    });

    let response = pull(&ctx, &digest).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await;
    assert!(body.is_err(), "the fill cannot complete without a token");
    assert!(
        blob_hits.load(Ordering::SeqCst) >= 2,
        "the cut body must have been resumed"
    );
    // The spool records its outcome after the body aborts; wait for it to finish.
    let started = std::time::Instant::now();
    while proxy_temp_count(&ctx) > 0 && started.elapsed() < Duration::from_secs(10) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let cb_key = crate::circuit_breaker::upstream_key("docker", &url);
    assert!(
        ctx.state.circuit_breaker.check(&cb_key).is_ok(),
        "a refused resume must not open the registry's breaker"
    );
    server.abort();
}

/// containerd resumes a broken pull with `Range: bytes=N-`. On a cache miss that
/// range is answered 206 from the spool, not 200 from byte zero (which ends in
/// "failed to discard to offset").
#[tokio::test]
async fn client_range_on_cache_miss_is_partial_content() {
    let (blob, digest) = layer(200 * 1024 + 9);
    let upstream = scripted_upstream(blob.clone(), vec![Plan::fast()], None).await;
    let ctx = ctx_for(&upstream, 5);
    let from = 70_000usize;

    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        &format!("/v2/library/test/blobs/{digest}"),
        vec![("range", &format!("bytes={from}-"))],
        Body::empty(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        response.headers()[header::CONTENT_RANGE].to_str().unwrap(),
        format!("bytes {from}-{}/{}", blob.len() - 1, blob.len())
    );
    assert_eq!(
        response.headers()[header::CONTENT_LENGTH].to_str().unwrap(),
        (blob.len() - from).to_string()
    );
    let body = body_bytes(response).await;
    assert_eq!(body.as_ref(), &blob[from..]);
    assert!(
        cached(&ctx, &digest).await,
        "the whole blob is still cached"
    );
}

/// A resume only continues from a 206 whose `Content-Range` names the byte asked for;
/// anything malformed is refused rather than spliced in at the wrong offset.
#[test]
fn parse_content_range_accepts_only_well_formed_spans() {
    use super::parse_content_range;
    assert_eq!(
        parse_content_range("bytes 100-199/200"),
        Some((100, Some(200)))
    );
    assert_eq!(parse_content_range("bytes 0-0/1"), Some((0, Some(1))));
    assert_eq!(parse_content_range("bytes 5-9/*"), Some((5, None)));
    assert_eq!(parse_content_range("bytes 10-5/20"), None, "inverted span");
    assert_eq!(
        parse_content_range("bytes 0-200/200"),
        None,
        "end past size"
    );
    assert_eq!(parse_content_range("bytes */200"), None, "unsatisfied form");
    assert_eq!(parse_content_range("items 0-1/2"), None, "not bytes");
    assert_eq!(parse_content_range("bytes x-1/2"), None);
    assert_eq!(parse_content_range(""), None);
}

/// A range that starts past the end of a blob known only from upstream headers is
/// a 416, like the cache-hit path.
#[tokio::test]
async fn client_range_past_end_on_cache_miss_is_416() {
    let (blob, digest) = layer(4096);
    let upstream = scripted_upstream(blob.clone(), vec![Plan::fast()], None).await;
    let ctx = ctx_for(&upstream, 5);

    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        &format!("/v2/library/test/blobs/{digest}"),
        vec![("range", &format!("bytes={}-", blob.len()))],
        Body::empty(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        response.headers()[header::CONTENT_RANGE].to_str().unwrap(),
        format!("bytes */{}", blob.len())
    );
}
