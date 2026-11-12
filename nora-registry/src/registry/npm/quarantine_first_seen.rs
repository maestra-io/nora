// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::test_helpers::{
    create_test_context_with_config, put_written_days_ago, quarantine_7d, send, TestContext,
};
use axum::http::{Method, StatusCode};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn serve(up: &MockServer, at: &str, body: Vec<u8>) {
    Mock::given(method("GET"))
        .and(path(at))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(up)
        .await;
}

async fn status(ctx: &TestContext, uri: &str) -> StatusCode {
    send(&ctx.app, Method::GET, uri, "").await.status()
}

const DOWNLOAD: &str = "/npm/oldpkg/-/oldpkg-1.0.0.tgz";

fn packument(up: &MockServer) -> Vec<u8> {
    serde_json::json!({
        "name": "oldpkg",
        "versions": {"1.0.0": {"name": "oldpkg", "version": "1.0.0",
            "dist": {"tarball": format!("{}/oldpkg/-/oldpkg-1.0.0.tgz", up.uri())}}},
        "time": {"1.0.0": "2019-01-01T00:00:00.000Z"}
    })
    .to_string()
    .into_bytes()
}

async fn upstream() -> MockServer {
    let up = MockServer::start().await;
    serve(&up, "/oldpkg", packument(&up)).await;
    serve(&up, "/oldpkg/-/oldpkg-1.0.0.tgz", b"TGZ".to_vec()).await;
    up
}

fn context(up: &MockServer, trust: bool) -> TestContext {
    let uri = up.uri();
    create_test_context_with_config(move |cfg| {
        cfg.npm.proxy = Some(uri);
        cfg.server.trust_upstream_dates = trust;
        quarantine_7d(cfg);
    })
}

#[tokio::test]
async fn without_trusted_dates_a_cached_packument_does_not_date_the_quarantine() {
    let up = upstream().await;
    let ctx = context(&up, false);
    let body = packument(&up);
    put_written_days_ago(&ctx, "npm/oldpkg/upstream/packument.json", &body, 30).await;
    assert_eq!(status(&ctx, DOWNLOAD).await, StatusCode::FORBIDDEN);
}

/// A tarball cached before the quarantine recorded it is counted from now on the cache path.
#[tokio::test]
async fn a_file_cached_before_the_quarantine_saw_it_counts_from_now() {
    let up = upstream().await;
    let ctx = context(&up, false);
    let body = packument(&up);
    put_written_days_ago(&ctx, "npm/oldpkg/upstream/packument.json", &body, 30).await;
    put_written_days_ago(&ctx, "npm/oldpkg/tarballs/oldpkg-1.0.0.tgz", b"TGZ", 30).await;
    assert_eq!(status(&ctx, DOWNLOAD).await, StatusCode::FORBIDDEN);
    assert!(!crate::test_helpers::upstream_paths(&up)
        .await
        .iter()
        .any(|p| p.ends_with(".tgz")));
}

#[tokio::test]
async fn with_trusted_dates_an_old_release_matures_in_the_quarantine() {
    let up = upstream().await;
    let ctx = context(&up, true);
    assert_eq!(status(&ctx, DOWNLOAD).await, StatusCode::OK);
}
