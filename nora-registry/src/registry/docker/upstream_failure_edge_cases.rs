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
                token_hosts: Vec::new(),
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

/// A055: a token answer over 1 MiB (gzip, so no declared length) fails the pull, and the
/// upstream gets no authenticated request; a small one still pulls.
#[tokio::test]
async fn a_token_answer_over_the_cap_fails_the_pull() {
    use std::io::Write as _;
    use wiremock::matchers::{header_exists, path};
    let manifest = br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":2,"digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111"},"layers":[]}"#;
    for (pad, ok) in [(1024usize, true), ((1 << 20) + 1, false)] {
        let doc = serde_json::json!({"access_token": "tok", "x": "p".repeat(pad)});
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(doc.to_string().as_bytes()).unwrap();
        let hub = MockServer::start().await;
        Mock::given(path("/t"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/json")
                    .insert_header("Content-Encoding", "gzip")
                    .set_body_bytes(gz.finish().unwrap()),
            )
            .with_priority(1)
            .mount(&hub)
            .await;
        Mock::given(header_exists("authorization"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/vnd.oci.image.manifest.v1+json")
                    .set_body_bytes(manifest.to_vec()),
            )
            .with_priority(2)
            .mount(&hub)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(401).insert_header(
                "WWW-Authenticate",
                format!(r#"Bearer realm="{}/t",service="s""#, hub.uri()).as_str(),
            ))
            .with_priority(5)
            .mount(&hub)
            .await;
        let url = hub.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.docker.upstreams = vec![DockerUpstream {
                trust_upstream_dates: false,
                date_token_file: None,
                token_hosts: Vec::new(),
                url,
                auth: None,
                auth_env: None,
                namespace: None,
                prefix: None,
                namespaces: Vec::new(),
            }];
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/v2/library/a055/manifests/v1",
            Body::empty(),
        )
        .await;
        assert_eq!(
            resp.status().is_success(),
            ok,
            "pad {pad}: {}",
            resp.status()
        );
        let asked = hub.received_requests().await.unwrap();
        let realm_hits = asked.iter().filter(|r| r.url.path() == "/t").count();
        let authed = asked
            .iter()
            .filter(|r| r.url.path() != "/t" && r.headers.contains_key("authorization"))
            .count();
        assert_eq!((realm_hits, authed), (1, usize::from(ok)), "pad {pad}");
    }
}
