// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

//! A panic in a handler or in a middleware of `request_layers` answers that request with
//! 500 and leaves the router serving.
use crate::test_helpers::{body_bytes, create_test_context, send};
use axum::http::{Method, StatusCode};
use axum::routing::get;
use axum::Router;

#[tokio::test]
async fn a_panicking_handler_answers_500_and_the_next_request_is_served() {
    let ctx = create_test_context();
    let routes = Router::new()
        .route(
            "/boom",
            get(|| async {
                panic!("secret-detail-of-the-bug");
                #[allow(unreachable_code)]
                "never"
            }),
        )
        .route("/fine", get(|| async { "fine" }));
    let app = crate::request_layers(routes, &ctx.state).with_state(ctx.state.clone());

    let response = send(&app, Method::GET, "/boom", "").await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = body_bytes(response).await;
    assert!(
        !String::from_utf8_lossy(&body).contains("secret-detail"),
        "the panic message goes to the log, not to the client"
    );

    let response = send(&app, Method::GET, "/fine", "").await;
    assert_eq!(response.status(), StatusCode::OK);
}
