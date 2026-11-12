// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

//! Serving a stored packument must cost the same storage round-trips for 1 and 100 versions.
use crate::test_helpers::{
    create_test_context_with_storage, op_counting_storage, send, send_with_headers,
};
use axum::http::{Method, StatusCode};

async fn packument_ops(n: usize) -> (usize, String) {
    let (storage, ops) = op_counting_storage();
    let ctx = create_test_context_with_storage(storage);
    let mut versions = serde_json::Map::new();
    for i in 0..n {
        let version = format!("1.0.{i}");
        let tarball = format!("costpkg-{version}.tgz");
        let tarball_key = format!("npm/costpkg/tarballs/{tarball}");
        ctx.state.storage.put(&tarball_key, b"TGZ").await.unwrap();
        let doc = serde_json::json!({
            "name": "costpkg",
            "version": version,
            "dist": { "tarball": format!("http://localhost/npm/costpkg/-/{tarball}") }
        });
        let doc_key = format!("npm/costpkg/versions/{version}.json");
        let doc_bytes = serde_json::to_vec(&doc).unwrap();
        ctx.state.storage.put(&doc_key, &doc_bytes).await.unwrap();
        versions.insert(version, doc);
    }
    let packument = serde_json::json!({
        "name": "costpkg",
        "dist-tags": { "latest": format!("1.0.{}", n - 1) },
        "versions": versions
    });
    let packument_bytes = serde_json::to_vec(&packument).unwrap();
    super::store_assembled_packument(&ctx.state.storage, "costpkg", &packument_bytes)
        .await
        .unwrap();
    ops.reset();
    let resp = send(&ctx.app, Method::GET, "/npm/costpkg", "").await;
    assert_eq!(resp.status(), StatusCode::OK, "packument with {n} versions");
    (ops.total(), format!("{:?}", ops.snapshot()))
}

fn iso_ago(secs: i64) -> String {
    (chrono::Utc::now() - chrono::Duration::seconds(secs))
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

/// R2-11/R2-17/R2-40: with the Q04 filter on, a cold packument miss fetches the
/// upstream document once and writes it once, before the response; a warm GET
/// reads it once; a tarball download dates its version from the small
/// `dates.json`, never from the packument.
#[tokio::test]
async fn npm_packument_and_tarball_fetch_and_read_once() {
    use crate::test_helpers::{body_bytes, create_test_context_with_storage_and_config};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    // A tarball is fetched only from the link its version lists (1.4.3).
    let uri = upstream.uri();
    let v = |n: &str| {
        serde_json::json!({
            "name": "pkg", "version": n,
            "dist": { "tarball": format!("{uri}/pkg/-/pkg-{n}.tgz") },
        })
    };
    Mock::given(method("GET"))
        .and(path("/pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "pkg",
            "dist-tags": { "latest": "1.1.0" },
            "versions": { "1.0.0": v("1.0.0"), "1.1.0": v("1.1.0") },
            "time": { "1.0.0": iso_ago(30 * 86400), "1.1.0": iso_ago(3600) }
        })))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/pkg/-/pkg-1.0.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"tgz".to_vec()))
        .mount(&upstream)
        .await;
    let (storage, ops) = op_counting_storage();
    let ctx = create_test_context_with_storage_and_config(storage, |cfg| {
        cfg.npm.proxy = Some(upstream.uri());
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.min_release_age = Some("7d".to_string());
        cfg.server.trust_upstream_dates = true;
    });
    let packument_fetches = || async {
        upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path() == "/pkg")
            .count()
    };
    let meta = "npm/pkg/upstream/packument.json";
    let corgi = vec![("accept", "application/vnd.npm.install-v1+json")];

    let resp = send_with_headers(&ctx.app, Method::GET, "/npm/pkg", corgi.clone(), "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let short: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert!(short["versions"].get("1.1.0").is_none(), "{short}");
    assert_eq!(short["dist-tags"]["latest"], "1.0.0");
    assert_eq!(packument_fetches().await, 1, "one upstream fetch");
    assert_eq!(ops.calls("put", meta), 1, "one write: {:?}", ops.snapshot());
    assert_eq!(ops.calls("put", "npm/pkg/upstream/dates.json"), 1);

    ops.reset();
    let resp = send_with_headers(&ctx.app, Method::GET, "/npm/pkg", corgi, "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    // R4-P02: the render of the first request is kept, the document is not read again.
    assert_eq!(ops.calls("get", meta), 0, "no read: {:?}", ops.snapshot());

    ops.reset();
    let holders = ctx.state.storage.holders();
    let resp = send(&ctx.app, Method::GET, "/npm/pkg/-/pkg-1.0.0.tgz", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(packument_fetches().await, 1, "the tarball reuses the cache");
    // 1.4.3: a cold tarball is fetched only from the link its version lists in the cached
    // packument, read once for it; a cached tarball reads it never.
    assert_eq!(ops.calls("get", meta), 1, "{:?}", ops.snapshot());
    assert_eq!(ops.calls("get", "npm/pkg/upstream/dates.json"), 1);
    // The cold download stores the tarball behind the response.
    crate::test_helpers::background_writes_done(&ctx.state.storage, holders).await;
    ops.reset();
    let resp = send(&ctx.app, Method::GET, "/npm/pkg/-/pkg-1.0.0.tgz", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(ops.calls("get", meta), 0, "{:?}", ops.snapshot());
}

/// OOM 2026-10-23: the upstream copy a release before 1.4.0 cached at
/// `npm/<name>/metadata.json` is never read to learn that a proxied package is not
/// published here: no provenance record names NORA, so nothing it holds could change
/// the answer. It was read in full on every tarball, packument and audit name.
#[tokio::test]
async fn legacy_upstream_copy_is_not_read_to_rule_out_a_published_package() {
    use crate::test_helpers::create_test_context_with_storage_and_config;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    // A tarball is fetched only from the link its version lists (1.4.3).
    let tarball = format!("{}/pkg/-/pkg-1.0.0.tgz", upstream.uri());
    let packument = serde_json::json!({
        "name": "pkg",
        "dist-tags": { "latest": "1.0.0" },
        "versions": { "1.0.0": { "name": "pkg", "version": "1.0.0", "dist": { "tarball": tarball } } },
        "time": { "1.0.0": iso_ago(30 * 86400) }
    });
    Mock::given(method("GET"))
        .and(path("/pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_json(packument.clone()))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/pkg/-/pkg-1.0.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"tgz".to_vec()))
        .mount(&upstream)
        .await;
    let (storage, ops) = op_counting_storage();
    let ctx = create_test_context_with_storage_and_config(storage, |cfg| {
        cfg.npm.proxy = Some(upstream.uri());
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.min_release_age = Some("7d".to_string());
        cfg.server.trust_upstream_dates = true;
        // As in production: the audit body is screened for published names.
        cfg.curation.internal_namespaces = vec!["@corp/*".to_string()];
    });
    // Cached by this release first, as on us-iota: the upstream copy sits at its
    // current key, the old release's copy beside it.
    let resp = send(&ctx.app, Method::GET, "/npm/pkg", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = send(&ctx.app, Method::GET, "/npm/pkg/-/pkg-1.0.0.tgz", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let legacy = crate::registry::npm::legacy_cache_key("pkg");
    ctx.state
        .storage
        .put(&legacy, &serde_json::to_vec(&packument).unwrap())
        .await
        .unwrap();

    ops.reset();
    let resp = send(&ctx.app, Method::GET, "/npm/pkg/-/pkg-1.0.0.tgz", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = send(&ctx.app, Method::GET, "/npm/pkg", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = send(
        &ctx.app,
        Method::POST,
        "/npm/-/npm/v1/security/advisories/bulk",
        r#"{"pkg":["1.0.0"]}"#,
    )
    .await;
    assert_ne!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(ops.calls("get", &legacy), 0, "{:?}", ops.snapshot());
}

/// OOM 2026-10-23: a CI fleet asking for one big cached packument at once reads it
/// from storage once — the followers share the leader's bytes, not one copy each.
#[tokio::test]
async fn concurrent_packument_requests_read_the_cache_once() {
    assert_eq!(concurrent_packument_reads(true).await, 1, "one shared read");
}

/// The kill-switch `server.proxy_coalesce = false`: every request reads on its own.
#[tokio::test]
async fn concurrent_packument_reads_without_coalescing() {
    assert_eq!(concurrent_packument_reads(false).await, 8, "one read each");
}

/// Storage reads of the packument for 8 concurrent abbreviated GETs, all overlapping
/// in a parked read; every client must get the same 200 document.
async fn concurrent_packument_reads(coalesce: bool) -> usize {
    use crate::test_helpers::{body_bytes, create_test_context_with_storage_and_config};
    use std::sync::Arc;
    let (storage, ops) = op_counting_storage();
    let ctx = create_test_context_with_storage_and_config(storage, |cfg| {
        cfg.npm.proxy = Some("http://127.0.0.1:9".to_string());
        cfg.npm.metadata_ttl = 3600;
        cfg.server.proxy_coalesce = coalesce;
    });
    let meta = "npm/pkg/upstream/packument.json";
    let packument = serde_json::json!({
        "name": "pkg",
        "dist-tags": { "latest": "1.0.0" },
        "versions": { "1.0.0": { "name": "pkg", "version": "1.0.0", "dist": {} } },
        "time": { "1.0.0": iso_ago(30 * 86400) }
    });
    ctx.state
        .storage
        .put(meta, &serde_json::to_vec(&packument).unwrap())
        .await
        .unwrap();
    ops.reset();
    ops.stall_gets(Some(meta));

    const M: usize = 8;
    let app = Arc::new(ctx.app.clone());
    let corgi = vec![("accept", "application/vnd.npm.install-v1+json")];
    let handles: Vec<_> = (0..M)
        .map(|_| {
            let (app, corgi) = (Arc::clone(&app), corgi.clone());
            tokio::spawn(async move {
                let resp = send_with_headers(&app, Method::GET, "/npm/pkg", corgi, "").await;
                (resp.status(), body_bytes(resp).await)
            })
        })
        .collect();
    // Every request reaches the read (a reader parks in it) before it is released.
    for _ in 0..200 {
        if ops.calls("get", meta) >= 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    ops.stall_gets(None);

    let mut bodies = std::collections::BTreeSet::new();
    for handle in handles {
        let (status, body) = handle.await.unwrap();
        assert_eq!(status, StatusCode::OK);
        bodies.insert(body.to_vec());
    }
    assert_eq!(bodies.len(), 1, "every client gets the same document");
    ops.calls("get", meta)
}

/// R2-21: a publish that fails after its first write leaves nothing behind —
/// version, publish time, tarball, moved dist-tag — so the retry succeeds.
#[tokio::test]
async fn failed_publish_is_rolled_back_and_retried() {
    use crate::test_helpers::{body_bytes, create_test_context_with_storage};
    use base64::Engine;
    let (storage, ops) = op_counting_storage();
    let ctx = create_test_context_with_storage(storage);
    let publish = |ver: &str| {
        let payload = serde_json::json!({
            "name": "atom",
            "dist-tags": { "latest": ver },
            "versions": { ver: { "name": "atom", "version": ver, "dist": {} } },
            "_attachments": { format!("atom-{ver}.tgz"): {
                "data": base64::engine::general_purpose::STANDARD.encode(ver)
            } },
        });
        send(
            &ctx.app,
            Method::PUT,
            "/npm/atom",
            serde_json::to_vec(&payload).unwrap(),
        )
    };
    assert_eq!(publish("1.0.0").await.status(), StatusCode::CREATED);

    ops.fail_puts_ending(Some("metadata.json"));
    assert_eq!(
        publish("1.1.0").await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    ops.fail_puts_ending(None);
    for gone in [
        "npm/atom/versions/1.1.0.json",
        "npm/atom/time/1.1.0",
        "npm/atom/tarballs/atom-1.1.0.tgz",
    ] {
        assert!(
            ctx.state.storage.stat(gone).await.is_none(),
            "{gone} left behind"
        );
    }
    let latest = ctx.state.storage.get("npm/atom/dist-tags/latest").await;
    assert_eq!(&latest.unwrap()[..], b"1.0.0", "tag pointed back");

    assert_eq!(publish("1.1.0").await.status(), StatusCode::CREATED);
    let resp = send(&ctx.app, Method::GET, "/npm/atom", "").await;
    let doc: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert!(doc["versions"].get("1.1.0").is_some(), "{doc}");
    assert_eq!(doc["dist-tags"]["latest"], "1.1.0");

    // A failed first publish leaves no packument for a package with no version.
    ops.fail_puts_ending(Some("metadata.json"));
    let payload = serde_json::json!({
        "name": "first",
        "versions": { "1.0.0": { "name": "first", "version": "1.0.0", "dist": {} } },
        "_attachments": { "first-1.0.0.tgz": {
            "data": base64::engine::general_purpose::STANDARD.encode(b"tgz")
        } },
    });
    let resp = send(
        &ctx.app,
        Method::PUT,
        "/npm/first",
        serde_json::to_vec(&payload).unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    ops.fail_puts_ending(None);
    assert!(ctx
        .state
        .storage
        .list("npm/first/")
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn npm_packument_cost_is_independent_of_version_count() {
    let (small, small_ops) = packument_ops(1).await;
    let (large, large_ops) = packument_ops(100).await;
    assert_eq!(
        small, large,
        "a stored packument must cost the same storage round-trips for 1 and 100 versions: {small_ops} vs {large_ops}"
    );
}
