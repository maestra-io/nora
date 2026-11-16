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

// A byte the upstream URL parser strips or reads as a delimiter (tab, LF, CR, `#`, `?`, a
// space) would let curation judge one GAV while the upstream serves another.
#[tokio::test]
async fn an_artifact_path_with_a_byte_the_url_parser_reinterprets_never_reaches_upstream() {
    let up = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"JAR".to_vec()))
        .mount(&up)
        .await;
    let (_dir, blocklist) = crate::test_helpers::blocklist_file("maven", "org.evil:lib");
    let uri = up.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.maven.proxies = vec![crate::config::MavenProxyEntry::Simple(uri)];
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.blocklist_path = Some(blocklist);
    });
    let resp = send(
        &ctx.app,
        Method::GET,
        "/maven2/org/evil/lib/1.0/lib-1.0.jar",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "control");
    for path in [
        "/maven2/org/ev%09il/lib/1.0/lib-1.0.jar",
        "/maven2/org/ev%0Ail/lib/1.0/lib-1.0.jar",
        "/maven2/org/ev%0Dil/lib/1.0/lib-1.0.jar",
        "/maven2/org/evil/lib/1.0/lib-1.0.jar%20",
        "/maven2/org/evil/lib/1.0/lib-1.0.jar%23/a/b/1.0/b-1.0.jar",
        "/maven2/org/good/lib/1.0/lib-1.0.jar%3F/x",
        "/maven2/org/good/lib/1.0/lib-1.0.jar%23",
    ] {
        let resp = send(&ctx.app, Method::GET, path, "").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{path}");
    }
    let sent = upstream_paths(&up).await;
    assert!(sent.is_empty(), "sent upstream: {sent:?}");
}
