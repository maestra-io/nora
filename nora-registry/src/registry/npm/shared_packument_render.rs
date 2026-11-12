// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::test_helpers::{
    body_bytes, create_test_context_with_storage_and_config, outage_storage, send_with_headers,
    StorageOutage, TestContext,
};
use axum::http::{Method, StatusCode};
use wiremock::MockServer;

const FORMS: [&str; 2] = ["application/json", super::NPM_INSTALL_V1];

async fn context() -> (MockServer, TestContext, StorageOutage) {
    let up = MockServer::start().await;
    super::mount_listing(&up, "pkg", &[("1.0.0", "pkg/-/pkg-1.0.0.tgz")]).await;
    let uri = up.uri();
    let (storage, outage) = outage_storage();
    let ctx = create_test_context_with_storage_and_config(storage, move |c| {
        c.npm.proxy = Some(uri);
    });
    (up, ctx, outage)
}

async fn get(ctx: &TestContext, accept: &str) -> (StatusCode, String, axum::body::Bytes) {
    let headers = vec![("accept", accept)];
    let resp = send_with_headers(&ctx.app, Method::GET, "/npm/pkg", headers, "").await;
    let form = resp.headers()["content-type"].to_str().unwrap().to_string();
    (resp.status(), form, body_bytes(resp).await)
}

#[tokio::test]
async fn a_kept_render_is_served_without_reading_the_document() {
    let (up, ctx, outage) = context().await;
    let mut first = Vec::new();
    for accept in FORMS {
        let got = get(&ctx, accept).await;
        assert_eq!((got.0, got.1.as_str()), (StatusCode::OK, accept));
        first.push(got);
    }
    outage.fail_reads_of("upstream/packument.json");
    for (accept, first) in FORMS.iter().zip(&first) {
        assert_eq!(&get(&ctx, accept).await, first, "{accept}");
    }
    let requests = up.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "the upstream was asked once");
}

#[tokio::test]
async fn a_changed_document_is_rendered_again() {
    let (_up, ctx, _outage) = context().await;
    let (_, _, before) = get(&ctx, FORMS[0]).await;
    let key = super::upstream_packument_key("pkg");
    let stored = ctx.state.storage.get(&key).await.unwrap();
    let mut doc: serde_json::Value = serde_json::from_slice(&stored).unwrap();
    assert_eq!(doc["versions"].as_object().unwrap().len(), 1);
    doc["versions"]["2.0.0"] = doc["versions"]["1.0.0"].clone();
    let changed = serde_json::to_vec(&doc).unwrap();
    ctx.state.storage.put(&key, &changed).await.unwrap();
    for accept in FORMS {
        let (status, _, body) = get(&ctx, accept).await;
        assert_eq!(status, StatusCode::OK);
        assert_ne!(body, before);
        let served: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(served["versions"].as_object().unwrap().len(), 2, "{accept}");
    }
}
