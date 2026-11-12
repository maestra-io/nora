// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::test_helpers::{
    background_writes_done, body_bytes, create_test_context_with_config, send, TestContext,
};
use axum::http::{Method, StatusCode};
use sha2::Digest;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const FILE: &str = "hm-1.0-py3-none-any.whl";

fn sha256(bytes: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(bytes))
}

/// An upstream whose index names `FILE` with `fragment` and whose file host answers `bytes`.
async fn upstream(fragment: &str, bytes: &[u8]) -> MockServer {
    let up = MockServer::start().await;
    let uri = up.uri();
    Mock::given(method("GET"))
        .and(path("/hm/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            r#"<html><body><a href="{uri}/files/{FILE}{fragment}">{FILE}</a></body></html>"#
        )))
        .mount(&up)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/files/{FILE}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.to_vec()))
        .mount(&up)
        .await;
    up
}

fn context(up: &MockServer) -> TestContext {
    let uri = up.uri();
    create_test_context_with_config(move |cfg| cfg.pypi.proxy = Some(uri))
}

async fn download(ctx: &TestContext) -> (StatusCode, Vec<u8>) {
    let resp = send(&ctx.app, Method::GET, &format!("/simple/hm/{FILE}"), "").await;
    let status = resp.status();
    (status, body_bytes(resp).await.to_vec())
}

#[tokio::test]
async fn bytes_that_do_not_match_the_index_digest_are_refused_and_not_cached() {
    let up = upstream(&format!("#sha256={}", sha256(b"genuine")), b"tampered").await;
    let ctx = context(&up);
    for attempt in 1..=2 {
        let (status, body) = download(&ctx).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "attempt {attempt}");
        assert_ne!(body, b"tampered", "attempt {attempt}");
    }
    assert!(
        ctx.state
            .storage
            .stat(&format!("pypi/hm/{FILE}"))
            .await
            .is_none(),
        "refused bytes are not cached"
    );
}

#[tokio::test]
async fn bytes_that_match_the_index_digest_are_served() {
    // The digest as the index writes it, any case.
    for digest in [sha256(b"genuine"), sha256(b"genuine").to_uppercase()] {
        let up = upstream(&format!("#sha256={digest}"), b"genuine").await;
        let ctx = context(&up);
        assert_eq!(
            download(&ctx).await,
            (StatusCode::OK, b"genuine".to_vec()),
            "{digest}"
        );
    }
}

/// An index that publishes no sha256 for the file leaves nothing to check it against.
#[tokio::test]
async fn a_file_the_index_gives_no_sha256_for_is_served() {
    for fragment in ["", "#md5=0123456789abcdef0123456789abcdef"] {
        let up = upstream(fragment, b"bytes").await;
        let ctx = context(&up);
        assert_eq!(download(&ctx).await.0, StatusCode::OK, "{fragment:?}");
    }
}

/// Every key the store holds that names the file — the file, its digest, its hash marker —
/// once no work the downloads so far started is still running.
async fn stored_under_file(ctx: &TestContext, holders: usize) -> Vec<String> {
    background_writes_done(&ctx.state.storage, holders).await;
    let keys = ctx.state.storage.list("").await.unwrap();
    keys.into_iter().filter(|k| k.contains(FILE)).collect()
}

/// A digest is the whole sha256 the index gives: an empty, shortened or lengthened one, or
/// any part of the bytes' own, matches nothing — the bytes are refused and not cached.
#[tokio::test]
async fn only_the_whole_index_digest_matches() {
    let own = sha256(b"tampered");
    for fragment in [
        "#sha256=".to_string(),
        format!("#sha256={}", &own[..8]),
        format!("#sha256={}", &own[..63]),
        format!("#sha256={}", &own[1..]),
        format!("#sha256={own}00"),
    ] {
        let up = upstream(&fragment, b"tampered").await;
        let ctx = context(&up);
        let holders = ctx.state.storage.holders();
        let (status, body) = download(&ctx).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{fragment}");
        assert_ne!(body, b"tampered", "{fragment}");
        let stored = stored_under_file(&ctx, holders).await;
        assert!(stored.is_empty(), "{fragment}: {stored:?}");
    }
}

/// Refused bytes are written nowhere: not by the request, nor by any work it leaves running.
/// The control: bytes that match are written by that same background work, which the wait
/// sees through.
#[tokio::test]
async fn refused_bytes_leave_nothing_in_the_store() {
    let up = upstream(&format!("#sha256={}", sha256(b"genuine")), b"tampered").await;
    let ctx = context(&up);
    let holders = ctx.state.storage.holders();
    assert_eq!(download(&ctx).await.0, StatusCode::BAD_GATEWAY);
    let stored = stored_under_file(&ctx, holders).await;
    assert!(stored.is_empty(), "refused bytes stored: {stored:?}");

    let up = upstream(&format!("#sha256={}", sha256(b"genuine")), b"genuine").await;
    let ctx = context(&up);
    let holders = ctx.state.storage.holders();
    assert_eq!(download(&ctx).await.0, StatusCode::OK);
    let stored = stored_under_file(&ctx, holders).await;
    for key in [format!("pypi/hm/{FILE}"), format!("pypi/hm/{FILE}.sha256")] {
        assert!(stored.contains(&key), "control: {key} not in {stored:?}");
    }
}
