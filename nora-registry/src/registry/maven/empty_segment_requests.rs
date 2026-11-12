// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::test_helpers::{create_test_context_with_config, send, upstream_paths};
use axum::http::{Method, StatusCode};
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, ResponseTemplate};

// The request path is the upstream path: an empty segment in it is refused before the
// storage lookup and the upstream fetch.
#[tokio::test]
async fn an_artifact_path_with_an_empty_segment_never_reaches_upstream() {
    let up = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"JAR".to_vec()))
        .mount(&up)
        .await;
    let uri = up.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.maven.proxies = vec![crate::config::MavenProxyEntry::Simple(uri)];
    });
    for path in [
        "/maven2/com//acme/foo/1.0/foo-1.0.jar",
        "/maven2/com/acme/foo/1.0/foo-1.0.jar/",
    ] {
        let resp = send(&ctx.app, Method::GET, path, "").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{path}");
    }
    let sent = upstream_paths(&up).await;
    assert!(sent.is_empty(), "sent upstream: {sent:?}");
    let resp = send(
        &ctx.app,
        Method::GET,
        "/maven2/com/acme/foo/1.0/foo-1.0.jar",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "control");
}
