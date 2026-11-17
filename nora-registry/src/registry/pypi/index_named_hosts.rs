// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::test_helpers::{body_bytes, create_test_context_with_config, send, TestContext};
use axum::http::{Method, StatusCode};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SDIST: &str = "pkg-1.0.tar.gz";
const WHEEL: &str = "pkg-1.0-py3-none-any.whl";

/// The host the index names: it answers every file, so a request that reached it shows.
async fn file_host() -> MockServer {
    let files = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"internal".to_vec()))
        .mount(&files)
        .await;
    files
}

/// The configured upstream, whose index names `SDIST` and `WHEEL` (with `.metadata`) at
/// `file_base`, with no digest.
async fn upstream(file_base: &str) -> MockServer {
    let up = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/pkg/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            r#"<a href="{file_base}/internal/status/{SDIST}">s</a>
<a href="{file_base}/internal/status/{WHEEL}" data-core-metadata="true">w</a>"#
        )))
        .mount(&up)
        .await;
    up
}

fn context(up: &MockServer, allow_files: bool, allow_upstreams: bool) -> TestContext {
    let uri = up.uri();
    create_test_context_with_config(move |cfg| {
        cfg.pypi.proxy = Some(uri);
        cfg.pypi.allow_private_file_hosts = allow_files;
        cfg.server.allow_private_upstreams = allow_upstreams;
    })
}

async fn get(ctx: &TestContext, file: &str) -> (StatusCode, Vec<u8>) {
    let resp = send(&ctx.app, Method::GET, &format!("/simple/pkg/{file}"), "").await;
    let status = resp.status();
    (status, body_bytes(resp).await.to_vec())
}

async fn assert_refused(ctx: &TestContext, files: &MockServer) {
    for file in [SDIST.to_string(), format!("{WHEEL}.metadata")] {
        let (status, body) = get(ctx, &file).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{file}");
        assert_ne!(body, b"internal", "{file}");
    }
    assert!(files.received_requests().await.unwrap().is_empty());
    let keys = ctx.state.storage.list("pypi/pkg/").await.unwrap();
    assert!(
        !keys
            .iter()
            .any(|k| k.ends_with(SDIST) || k.ends_with(".metadata")),
        "{keys:?}"
    );
}

/// Audit A100: an IP-literal host the index names is refused before any request.
#[tokio::test]
async fn a_file_the_index_names_on_a_private_address_is_refused() {
    let files = file_host().await;
    let up = upstream(&files.uri()).await;
    for allow_upstreams in [false, true] {
        assert_refused(&context(&up, false, allow_upstreams), &files).await;
    }
}

/// Audit B01: a host name that resolves to a private address is refused at connect, also when
/// the operator allowed private upstreams (those are not the hosts their index names).
#[tokio::test]
async fn a_file_host_name_that_resolves_privately_is_refused() {
    let files = file_host().await;
    let port = files.address().port();
    let up = upstream(&format!("http://localhost:{port}")).await;
    for allow_upstreams in [false, true] {
        assert_refused(&context(&up, false, allow_upstreams), &files).await;
    }
}

/// The switch lets an internal mirror's files through.
#[tokio::test]
async fn allow_private_file_hosts_fetches_them() {
    let files = file_host().await;
    let up = upstream(&files.uri()).await;
    let ctx = context(&up, true, true);
    assert_eq!(
        get(&ctx, SDIST).await,
        (StatusCode::OK, b"internal".to_vec())
    );
    assert_eq!(
        get(&ctx, &format!("{WHEEL}.metadata")).await,
        (StatusCode::OK, b"internal".to_vec())
    );
}
