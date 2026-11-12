// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::config::DockerUpstream;
use crate::test_helpers::{create_test_context_with_config, send};
use axum::body::Body;
use axum::http::{Method, StatusCode};
use sha2::Digest;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Any 4xx is an answer — an upstream answering 400 for a manifest or a
/// blob said "not here", so 404, not 502.
#[tokio::test]
async fn upstream_400_is_404() {
    let bad = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(400))
        .mount(&bad)
        .await;
    let blob = format!("sha256:{}", hex::encode(sha2::Sha256::digest(b"layer")));
    for uri in [
        "/v2/myorg/app/manifests/1.0".to_string(),
        format!("/v2/myorg/app/blobs/{blob}"),
    ] {
        let url = bad.uri();
        let ctx = create_test_context_with_config(move |cfg| {
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
        });
        let resp = send(&ctx.app, Method::GET, &uri, Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{uri}");
    }
}
