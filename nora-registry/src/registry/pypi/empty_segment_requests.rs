// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::test_helpers::{
    blocklist_file, create_test_context_with_config, send, send_with_headers, upstream_paths,
};
use axum::http::{Method, StatusCode};
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Its own server, not one from wiremock's pool: a request another test sent to a pooled
/// server just before handing it back can land after this test took it, and these tests
/// assert the upstream got nothing.
async fn upstream(body: &str) -> MockServer {
    let up = MockServer::builder().start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&up)
        .await;
    up
}

#[tokio::test]
async fn a_download_under_an_empty_segment_name_never_reaches_upstream() {
    let up = upstream("<html></html>").await;
    let ctx = create_test_context_with_config(|cfg| {
        cfg.pypi.proxy = Some(up.uri());
        cfg.curation.internal_namespaces = vec!["internal*".to_string()];
    });
    let control = "/simple/internalpkg/internalpkg-1.0.tar.gz";
    let resp = send(&ctx.app, Method::GET, control, "").await;
    assert!(!resp.status().is_success(), "control");
    let sent = upstream_paths(&up).await;
    assert!(sent.is_empty(), "control sent upstream: {sent:?}");
    for uri in [
        "/simple/%2Finternalpkg/internalpkg-1.0.tar.gz",
        "/simple/internalpkg%2F%2Fx/internalpkg-1.0.tar.gz",
    ] {
        let resp = send(&ctx.app, Method::GET, uri, "").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{uri}");
    }
    let sent = upstream_paths(&up).await;
    assert!(sent.is_empty(), "sent upstream: {sent:?}");
}

// The JSON index fetches release dates from the upstream; the name is refused first.
#[tokio::test]
async fn a_json_index_of_an_empty_segment_name_never_reaches_upstream() {
    let up = upstream(r#"{"files":[]}"#).await;
    let ctx = create_test_context_with_config(|cfg| {
        cfg.pypi.proxy = Some(up.uri());
        cfg.curation.internal_namespaces = vec!["internal*".to_string()];
    });
    let accept = vec![("accept", "application/vnd.pypi.simple.v1+json")];
    let resp = send_with_headers(
        &ctx.app,
        Method::GET,
        "/simple/internalpkg/",
        accept.clone(),
        Vec::new(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "control");
    let sent = upstream_paths(&up).await;
    assert!(sent.is_empty(), "control sent upstream: {sent:?}");
    let resp = send_with_headers(
        &ctx.app,
        Method::GET,
        "/simple/%2Finternalpkg/",
        accept,
        Vec::new(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let sent = upstream_paths(&up).await;
    assert!(sent.is_empty(), "sent upstream: {sent:?}");
}

// A project name is one segment: a `%2F` that decodes to an inner `/` names another
// project's files (`corp-secret/x`, `evilpkg/evilpkg`) and is refused before curation,
// namespace isolation or the upstream see it.
#[tokio::test]
async fn a_project_name_with_an_inner_slash_never_reaches_upstream() {
    let up = upstream("<html></html>").await;
    let (_dir, blocklist) = blocklist_file("pypi", "evilpkg");
    let ctx = create_test_context_with_config(|cfg| {
        cfg.pypi.proxy = Some(up.uri());
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.blocklist_path = Some(blocklist);
        cfg.curation.internal_namespaces = vec!["corp-secret".to_string()];
    });
    let resp = send(&ctx.app, Method::GET, "/simple/corp-secret/", "").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "control");
    let sent = upstream_paths(&up).await;
    assert!(sent.is_empty(), "control sent upstream: {sent:?}");
    for uri in [
        "/simple/corp-secret%2Fx/",
        "/simple/corp-secret%2Fx/corp-secret-1.0.tar.gz",
        "/simple/evilpkg%2Fevilpkg/evilpkg-1.0.tar.gz",
    ] {
        let resp = send(&ctx.app, Method::GET, uri, "").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{uri}");
    }
    let sent = upstream_paths(&up).await;
    assert!(sent.is_empty(), "sent upstream: {sent:?}");
}
