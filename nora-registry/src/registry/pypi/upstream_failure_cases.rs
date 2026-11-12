// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::circuit_breaker::ProbeToken;
use crate::test_helpers::{create_test_context_with_config, send};
use axum::http::{Method, StatusCode};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// the index lists the file on a host that answers 404 — the upstream said
/// "not found", so 404, not 502.
#[tokio::test]
async fn file_host_answering_404_is_404() {
    let missing = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&missing)
        .await;
    let lists_missing = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/flask/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            r#"<html><body><a href="{}/files/flask-2.0.tar.gz">flask-2.0.tar.gz</a></body></html>"#,
            missing.uri()
        )))
        .mount(&lists_missing)
        .await;
    let urls = vec![lists_missing.uri()];
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.pypi.proxies = serde_json::from_value(serde_json::json!(urls)).unwrap();
    });
    let resp = send(&ctx.app, Method::GET, "/simple/flask/flask-2.0.tar.gz", "").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert!(!missing.received_requests().await.unwrap().is_empty());
}

/// one upstream's breaker is open, the other failed — the open breaker still
/// answers 503 (retryable), as before the change.
#[tokio::test]
async fn open_breaker_with_failed_peer_is_503() {
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
    ctx.state
        .circuit_breaker
        .record_failure(&key, ProbeToken::BACKGROUND);
    ctx.state
        .circuit_breaker
        .record_failure(&key, ProbeToken::BACKGROUND);
    for uri in ["/simple/flask/flask-2.0.tar.gz", "/simple/flask/"] {
        let resp = send(&ctx.app, Method::GET, uri, "").await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "{uri}");
    }
}
