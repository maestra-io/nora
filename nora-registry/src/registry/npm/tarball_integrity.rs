// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::test_helpers::{body_bytes, create_test_context_with_config, send, TestContext};
use axum::http::{Method, StatusCode};
use base64::Engine;
use sha2::Digest;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const KEY: &str = "npm/pkg/tarballs/pkg-1.0.0.tgz";
const URI: &str = "/npm/pkg/-/pkg-1.0.0.tgz";

fn integrity(bytes: &[u8]) -> serde_json::Value {
    let hash = base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(bytes));
    serde_json::json!({ "integrity": format!("sha512-{hash}"), "shasum": "0".repeat(40) })
}

fn shasum(bytes: &[u8]) -> serde_json::Value {
    serde_json::json!({ "shasum": hex::encode(sha1::Sha1::digest(bytes)) })
}

/// The upstream lists pkg 1.0.0 with `dist` and serves `body` as its tarball.
async fn serve(up: &MockServer, mut dist: serde_json::Value, body: &[u8]) {
    dist["tarball"] = format!("{}/pkg/-/pkg-1.0.0.tgz", up.uri()).into();
    let doc = serde_json::json!({ "name": "pkg", "versions": { "1.0.0": { "dist": dist } } });
    Mock::given(method("GET"))
        .and(path("/pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_json(doc))
        .mount(up)
        .await;
    Mock::given(method("GET"))
        .and(path("/pkg/-/pkg-1.0.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
        .mount(up)
        .await;
}

fn context(up: &MockServer, threshold_mb: u64) -> TestContext {
    let uri = up.uri();
    create_test_context_with_config(move |cfg| {
        cfg.npm.proxy = Some(uri);
        cfg.server.stream_threshold_mb = threshold_mb;
    })
}

async fn get(ctx: &TestContext) -> (StatusCode, axum::body::Bytes) {
    let resp = send(&ctx.app, Method::GET, URI, "").await;
    (resp.status(), body_bytes(resp).await)
}

/// Wait for the cache writes a response left running: each holds the store until it ends.
async fn writes_done(ctx: &TestContext, holders: usize) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while ctx.state.storage.holders() > holders {
        assert!(
            std::time::Instant::now() < deadline,
            "cache writes still run"
        );
        tokio::task::yield_now().await;
    }
}

async fn tarball_requests(up: &MockServer) -> usize {
    let requests = up.received_requests().await.unwrap();
    requests
        .iter()
        .filter(|r| r.url.path().ends_with(".tgz"))
        .count()
}

/// In memory (64 MB threshold) and spooled to disk (1 MB), by integrity and by shasum.
#[tokio::test]
async fn a_tarball_its_packument_lists_is_served_and_cached() {
    let body = vec![7u8; 2 * 1024 * 1024];
    for threshold_mb in [64, 1] {
        for dist in [integrity(&body), shasum(&body)] {
            let up = MockServer::start().await;
            serve(&up, dist.clone(), &body).await;
            let ctx = context(&up, threshold_mb);
            let holders = ctx.state.storage.holders();
            let (status, got) = get(&ctx).await;
            assert_eq!(status, StatusCode::OK, "{threshold_mb} {dist}");
            assert!(got[..] == body[..], "{threshold_mb} {dist}");
            writes_done(&ctx, holders).await;
            assert!(ctx.state.storage.stat(KEY).await.is_some());
            assert_eq!(get(&ctx).await.0, StatusCode::OK);
            assert_eq!(tarball_requests(&up).await, 1, "the second is a cache hit");
        }
    }
}

#[tokio::test]
async fn a_tarball_that_is_not_the_listed_file_is_refused_and_not_cached() {
    let listed = vec![7u8; 2 * 1024 * 1024];
    // A body cut short, as a chunked response that broke off.
    let sent = &listed[..listed.len() - 1];
    for threshold_mb in [64, 1] {
        for dist in [integrity(&listed), shasum(&listed)] {
            let up = MockServer::start().await;
            serve(&up, dist.clone(), sent).await;
            let ctx = context(&up, threshold_mb);
            let holders = ctx.state.storage.holders();
            for asked in 1..=2 {
                let (status, got) = get(&ctx).await;
                assert_eq!(status, StatusCode::BAD_GATEWAY, "{threshold_mb} {dist}");
                assert!(got.len() < 1024, "the body is not sent");
                writes_done(&ctx, holders).await;
                for key in [
                    KEY.to_string(),
                    format!("{KEY}.sha256"),
                    super::origin_key(KEY),
                ] {
                    assert!(ctx.state.storage.stat(&key).await.is_none(), "{key}");
                }
                assert_eq!(tarball_requests(&up).await, asked);
            }
        }
    }
}

/// The cached packument lists the version with the digest of a file its upstream has since
/// replaced: the packument is fetched again, and the file is the one it lists now.
#[tokio::test]
async fn a_packument_older_than_the_file_is_fetched_again_once() {
    let up = MockServer::start().await;
    serve(&up, integrity(b"OLD"), b"OLD").await;
    let ctx = context(&up, 64);
    let resp = send(&ctx.app, Method::GET, "/npm/pkg", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    up.reset().await;
    serve(&up, integrity(b"NEW"), b"NEW").await;
    let (status, got) = get(&ctx).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&got[..], b"NEW");
    let requests = up.received_requests().await.unwrap();
    let packuments = requests.iter().filter(|r| r.url.path() == "/pkg").count();
    assert_eq!(packuments, 1, "fetched again once");
}
