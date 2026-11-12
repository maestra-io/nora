// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::circuit_breaker::ProbeToken;
use crate::test_helpers::{create_test_context_with_config, send};
use axum::http::{Method, StatusCode};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The index alone, one upstream's breaker open and the other failed with
/// its own breaker still closed — the open breaker answers 503, as before the change.
#[tokio::test]
async fn index_open_breaker_with_failed_peer_is_503() {
    let down = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&down)
        .await;
    let open = "http://127.0.0.1:1".to_string();
    let urls = vec![open.clone(), down.uri()];
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.circuit_breaker.enabled = true;
        cfg.circuit_breaker.failure_threshold = 2;
        cfg.circuit_breaker.reset_timeout = 3600;
        cfg.pypi.proxies = serde_json::from_value(serde_json::json!(urls)).unwrap();
    });
    let key = crate::circuit_breaker::upstream_key("pypi", &open);
    for _ in 0..2 {
        ctx.state
            .circuit_breaker
            .record_failure(&key, ProbeToken::BACKGROUND);
    }
    let resp = send(&ctx.app, Method::GET, "/simple/flask/", "").await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!down.received_requests().await.unwrap().is_empty());
}
