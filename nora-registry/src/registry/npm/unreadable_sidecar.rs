// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::test_helpers::{
    body_bytes, create_test_context_with_storage_and_config, outage_storage, send, ReadFault,
    StorageOutage, TestContext,
};
use axum::body::Body;
use axum::http::{Method, StatusCode};
use base64::Engine;
use sha2::Digest;
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn upstream(status: u16) -> MockServer {
    let up = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(status).set_body_bytes(b"UPSTREAM".to_vec()))
        .mount(&up)
        .await;
    up
}

fn context(up: Option<&MockServer>) -> (TestContext, StorageOutage) {
    let uri = up.map(MockServer::uri);
    let (storage, outage) = outage_storage();
    let ctx = create_test_context_with_storage_and_config(storage, move |c| {
        c.npm.proxy = uri;
        c.curation.internal_namespaces = vec!["internal*".to_string()];
    });
    (ctx, outage)
}

/// A copy as a release before storage pins cached it: no pin, checked by its sidecar alone.
async fn cache(ctx: &TestContext, name: &str, bytes: &[u8]) {
    let key = format!("npm/{name}/tarballs/{name}-1.0.0.tgz");
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("copy");
    std::fs::write(&src, bytes).unwrap();
    ctx.state
        .storage
        .put_from_path(&key, &src, None)
        .await
        .unwrap();
    assert_eq!(ctx.state.storage.pin(&key).await, None);
    let pin = hex::encode(sha2::Sha256::digest(bytes));
    let sidecar = format!("{key}.sha256");
    ctx.state
        .storage
        .put(&sidecar, pin.as_bytes())
        .await
        .unwrap();
}

async fn publish(ctx: &TestContext, name: &str, version: &str) {
    let payload = serde_json::json!({
        "name": name,
        "versions": { version: { "name": name, "version": version, "dist": {} } },
        "_attachments": { format!("{name}-{version}.tgz"): {
            "data": base64::engine::general_purpose::STANDARD.encode(b"CACHED"),
        } },
    });
    let body = Body::from(serde_json::to_vec(&payload).unwrap());
    let resp = send(&ctx.app, Method::PUT, &format!("/npm/{name}"), body).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

async fn get(ctx: &TestContext, name: &str) -> (StatusCode, Vec<u8>) {
    let uri = format!("/npm/{name}/-/{name}-1.0.0.tgz");
    let resp = send(&ctx.app, Method::GET, &uri, "").await;
    let status = resp.status();
    (status, body_bytes(resp).await.to_vec())
}

/// Tarball requests the upstream received (a tarball download may also ask for the packument,
/// for its release dates).
async fn asked(up: &MockServer) -> usize {
    let requests = up.received_requests().await.unwrap();
    requests
        .iter()
        .filter(|r| r.url.path().ends_with(".tgz"))
        .count()
}

#[tokio::test]
async fn own_copies_whose_sidecar_cannot_be_read_are_unavailable() {
    let up = upstream(200).await;
    let mut wrong = Vec::new();
    for (case, name, upstream) in [
        ("internal", "internal-pkg", Some(&up)),
        ("published beside", "pkg", Some(&up)),
        ("no upstream", "pkg", None),
    ] {
        let (ctx, outage) = context(upstream);
        if case == "published beside" {
            publish(&ctx, name, "2.0.0").await;
        }
        cache(&ctx, name, b"CACHED").await;
        // The copy and its sidecar read: served.
        if get(&ctx, name).await != (StatusCode::OK, b"CACHED".to_vec()) {
            wrong.push(format!("{case}: not served with the store up"));
        }
        outage.fault_reads_of(".tgz.sha256", ReadFault::Network);
        let (status, body) = get(&ctx, name).await;
        if status != StatusCode::SERVICE_UNAVAILABLE || body.windows(6).any(|w| w == b"CACHED") {
            wrong.push(format!(
                "{case}: {status} {:?}",
                String::from_utf8_lossy(&body)
            ));
        }
    }
    assert_eq!(asked(&up).await, 0, "an own package's upstream was asked");
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// R4-P07: a pinned copy, published or cached, was checked against its pin by the read
/// that fetched it: served without a read of the sidecar, readable or not.
#[tokio::test]
async fn a_pinned_copy_is_served_without_its_sidecar() {
    let up = upstream(200).await;
    let (ctx, outage) = context(Some(&up));
    publish(&ctx, "pkg", "1.0.0").await;
    let key = "npm/proxied/tarballs/proxied-1.0.0.tgz";
    ctx.state.storage.put(key, b"CACHED").await.unwrap();
    // A sidecar naming other bytes than the pinned ones is not what decides.
    let sidecar = format!("{key}.sha256");
    ctx.state.storage.put(&sidecar, b"stale").await.unwrap();
    outage.fault_reads_of(".tgz.sha256", ReadFault::Network);
    for name in ["pkg", "proxied"] {
        assert_eq!(
            get(&ctx, name).await,
            (StatusCode::OK, b"CACHED".to_vec()),
            "{name}"
        );
    }
    assert_eq!(asked(&up).await, 0);
}

#[tokio::test]
async fn a_proxied_copy_whose_sidecar_cannot_be_read_is_fetched_again() {
    let up = upstream(200).await;
    let (ctx, outage) = context(Some(&up));
    cache(&ctx, "pkg", b"CACHED").await;
    assert_eq!(get(&ctx, "pkg").await, (StatusCode::OK, b"CACHED".to_vec()));
    assert_eq!(
        asked(&up).await,
        0,
        "a checked copy is served from the cache"
    );
    super::mount_listing(&up, "pkg", &[("1.0.0", "pkg/-/pkg-1.0.0.tgz")]).await;
    outage.fault_reads_of(".tgz.sha256", ReadFault::Network);
    assert_eq!(
        get(&ctx, "pkg").await,
        (StatusCode::OK, b"UPSTREAM".to_vec())
    );
    let paths: Vec<String> = up
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.url.path().to_string())
        .filter(|p| p.ends_with(".tgz"))
        .collect();
    assert_eq!(paths, vec!["/pkg/-/pkg-1.0.0.tgz"]);
}

/// The upstream fails while the copy cannot be checked: the answer a cache miss gets, never
/// the unchecked bytes.
#[tokio::test]
async fn a_failing_upstream_answers_as_on_a_cache_miss() {
    for status in [500, 404] {
        let up = upstream(status).await;
        let (ctx, outage) = context(Some(&up));
        let (miss, _) = get(&ctx, "other").await;
        cache(&ctx, "pkg", b"CACHED").await;
        outage.fault_reads_of(".tgz.sha256", ReadFault::Network);
        let (got, body) = get(&ctx, "pkg").await;
        assert_eq!(got, miss, "upstream {status}");
        assert!(
            !body.windows(6).any(|w| w == b"CACHED"),
            "upstream {status}"
        );
    }
}
