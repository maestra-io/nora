// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::apply_security_headers;
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::routing::get;
use axum::Router;
use tower::ServiceExt;

async fn header_of(app: &Router, path: &str, name: &str) -> Option<String> {
    let req = Request::builder()
        .method(Method::GET)
        .uri(path)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    resp.headers()
        .get(name)
        .map(|v| v.to_str().unwrap().to_string())
}

// A handler that sets its own CSP (the raw download handler, `sandbox`) keeps it; a handler
// that sets none gets the permissive UI default. The default must not override a stricter
// handler policy, or raw's user-uploaded bytes would run under the UI's `unsafe-inline`.
#[tokio::test]
async fn a_handler_csp_survives_the_default() {
    let app = apply_security_headers(
        Router::<()>::new()
            .route(
                "/raw-like",
                get(|| async { ([(header::CONTENT_SECURITY_POLICY, "sandbox")], "bytes") }),
            )
            .route("/ui-like", get(|| async { "page" })),
    );
    assert_eq!(
        header_of(&app, "/raw-like", "content-security-policy").await,
        Some("sandbox".to_string())
    );
    let default = header_of(&app, "/ui-like", "content-security-policy")
        .await
        .expect("a route without its own CSP gets the default");
    assert!(
        default.contains("script-src 'self' 'unsafe-inline'"),
        "default UI CSP expected, got {default}"
    );
    // nosniff is uniform and overrides, on both.
    for path in ["/raw-like", "/ui-like"] {
        assert_eq!(
            header_of(&app, path, "x-content-type-options").await,
            Some("nosniff".to_string())
        );
    }
}
