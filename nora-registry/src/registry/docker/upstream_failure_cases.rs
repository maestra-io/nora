// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::config::DockerUpstream;
use crate::test_helpers::{create_test_context_with_config, send};
use axum::body::Body;
use axum::http::{Method, StatusCode};
use sha2::Digest;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// one upstream asked under `alpine` (fails) and `library/alpine` (4xx): it failed
/// under one name, so it did not say "not found" — 502 for manifest and blob.
#[tokio::test]
async fn failed_under_plain_name_404_under_library_is_502() {
    let flip = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("^/v2/library/"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&flip)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&flip)
        .await;
    let blob = format!("sha256:{}", hex::encode(sha2::Sha256::digest(b"layer")));
    for uri in [
        "/v2/alpine/manifests/3".to_string(),
        format!("/v2/alpine/blobs/{blob}"),
    ] {
        let url = flip.uri();
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
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY, "{uri}");
    }
    let asked = flip.received_requests().await.unwrap();
    assert!(asked
        .iter()
        .any(|r| r.url.path().starts_with("/v2/library/alpine/")));
}
