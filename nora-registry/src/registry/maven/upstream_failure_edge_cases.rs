// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::config::MavenProxyEntry;
use crate::test_helpers::{create_test_context_with_config, send};
use axum::http::{Method, StatusCode};
use std::time::Duration;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

/// An upstream that never answers within proxy_timeout timed out, it did
/// not say "not found" — 502.
#[tokio::test]
async fn timeout_is_502() {
    let slow = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
        .mount(&slow)
        .await;
    let url = slow.uri();
    let ctx = create_test_context_with_config(move |c| {
        c.maven.proxy_timeout = 1;
        c.maven.proxies = vec![MavenProxyEntry::Simple(url)];
    });
    let resp = send(
        &ctx.app,
        Method::GET,
        "/maven2/com/example/lib/1.0.0/lib-1.0.0.jar",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}
