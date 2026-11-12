// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

//! The index trusts a file's hash marker only when it has exactly one; every other case
//! is served from the `.sha256` sidecar and repaired in the background.
use super::local_index_cost_tests::{upload_body, BOUNDARY};
use super::{hash_marker_key, parse_hash_marker, HASH_MARKER_PREFIX};
use crate::test_helpers::{
    body_bytes, create_test_context, create_test_context_with_storage,
    create_test_context_with_storage_and_config, op_counting_storage, send, send_with_headers,
    TestContext,
};
use axum::http::{Method, StatusCode};
use sha2::Digest as _;

fn digest(content: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(content))
}

async fn html_index(ctx: &TestContext, project: &str) -> String {
    let resp = send_with_headers(
        &ctx.app,
        Method::GET,
        &format!("/simple/{project}/"),
        vec![("Accept", "text/html")],
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "index of {project}");
    String::from_utf8(body_bytes(resp).await.to_vec()).unwrap()
}

/// Wait for the markers under `pypi-sha256/<project>/` to become exactly `expected`.
///
/// Markers written by a background task appear some time after the response; the
/// deadline only bounds a task that never finishes.
async fn wait_for_markers(ctx: &TestContext, project: &str, expected: &[String]) {
    use std::time::{Duration, Instant};

    let prefix = format!("{HASH_MARKER_PREFIX}{project}/");
    let mut expected = expected.to_vec();
    expected.sort();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut markers = ctx.state.storage.list(&prefix).await.unwrap();
        markers.sort();
        if markers == expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "markers under {prefix}: expected {expected:?}, found {markers:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[test]
fn parse_hash_marker_reads_filename_and_digest() {
    let sha = "ab".repeat(32);
    let prefix = format!("{HASH_MARKER_PREFIX}pkg/");
    let filename = "pkg-1.0+local@x-py3-none-any.whl";
    let key = hash_marker_key("pkg", filename, &sha);
    assert_eq!(
        parse_hash_marker(&prefix, &key),
        Some((filename, sha.as_str()))
    );
    for (malformed, why) in [
        (format!("{prefix}pkg-1.0.tar.gz/abc"), "short digest"),
        (format!("{prefix}pkg-1.0.tar.gz"), "no digest"),
        (format!("{prefix}/{sha}"), "no filename"),
        (format!("{prefix}a/b/{sha}"), "nested path"),
    ] {
        assert_eq!(parse_hash_marker(&prefix, &malformed), None, "{why}");
    }
    assert_eq!(
        parse_hash_marker(&format!("{HASH_MARKER_PREFIX}other/"), &key),
        None,
        "marker of another project"
    );
}

/// Files stored before markers existed are served from their sidecars, backfilled, and
/// then cost no sidecar read.
#[tokio::test]
async fn legacy_sidecar_digests_are_served_then_backfilled() {
    let (storage, ops) = op_counting_storage();
    let ctx = create_test_context_with_storage(storage);
    let mut digests = Vec::new();
    let mut expected = Vec::new();
    for i in 0..3 {
        let filename = format!("legacypkg-1.0.{i}-py3-none-any.whl");
        let content = format!("legacy wheel {i}");
        let sha = digest(content.as_bytes());
        let key = format!("pypi/legacypkg/{filename}");
        ctx.state
            .storage
            .put(&key, content.as_bytes())
            .await
            .unwrap();
        ctx.state
            .storage
            .put(&format!("{key}.sha256"), sha.as_bytes())
            .await
            .unwrap();
        expected.push(hash_marker_key("legacypkg", &filename, &sha));
        digests.push(sha);
    }

    let body = html_index(&ctx, "legacypkg").await;
    for sha in &digests {
        assert!(
            body.contains(sha.as_str()),
            "sidecar digest {sha} served: {body}"
        );
    }
    wait_for_markers(&ctx, "legacypkg", &expected).await;

    ops.reset();
    let body = html_index(&ctx, "legacypkg").await;
    for sha in &digests {
        assert!(
            body.contains(sha.as_str()),
            "marker digest {sha} served: {body}"
        );
    }
    assert!(
        !ops.snapshot().contains_key("get"),
        "no sidecar is read once markers exist: {:?}",
        ops.snapshot()
    );
}

/// A file left with a stale marker next to its own is served from its sidecar, and the
/// stale marker is removed.
#[tokio::test]
async fn conflicting_markers_fall_back_to_the_sidecar_and_are_repaired() {
    // In-memory object store: the repair runs in the background, and a local disk
    // would add fsync latency to what the test waits for.
    let (backend, _ops) = op_counting_storage();
    let ctx = create_test_context_with_storage(backend);
    let filename = "dup-1.0-py3-none-any.whl";
    let key = format!("pypi/dup/{filename}");
    let current = digest(b"current bytes");
    let stale = digest(b"earlier bytes");
    let storage = &ctx.state.storage;
    storage.put(&key, b"current bytes").await.unwrap();
    storage
        .put(&format!("{key}.sha256"), current.as_bytes())
        .await
        .unwrap();
    for sha in [&current, &stale] {
        storage
            .put(&hash_marker_key("dup", filename, sha), b"")
            .await
            .unwrap();
    }

    let body = html_index(&ctx, "dup").await;
    assert!(
        body.contains(current.as_str()),
        "current digest served: {body}"
    );
    assert!(
        !body.contains(stale.as_str()),
        "stale digest not served: {body}"
    );
    wait_for_markers(&ctx, "dup", &[hash_marker_key("dup", filename, &current)]).await;
}

/// C54: an uploaded file that fails its pin is the only copy: it is kept and
/// answered 500, and the file is never fetched from the upstream.
#[tokio::test]
async fn tampered_uploaded_file_is_kept_not_refetched() {
    use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};
    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"upstream".to_vec()))
        .mount(&upstream)
        .await;
    let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
        cfg.pypi.proxy = Some(upstream.uri());
    });
    let filename = "ours-1.0-py3-none-any.whl";
    let content_type = format!("multipart/form-data; boundary={BOUNDARY}");
    let resp = send_with_headers(
        &ctx.app,
        Method::POST,
        "/simple/",
        vec![("content-type", content_type.as_str())],
        upload_body("ours", "1.0", filename, b"our wheel"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let key = format!("pypi/ours/{filename}");
    std::fs::write(
        std::path::Path::new(&ctx.state.config.storage.path).join(&key),
        b"rotten",
    )
    .unwrap();

    let resp = send(
        &ctx.app,
        Method::GET,
        &format!("/simple/ours/{filename}"),
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        ctx.state.storage.stat(&key).await.is_some(),
        "the only copy is kept"
    );
    // The index may be read for release dates; the file is never fetched.
    let requests = upstream.received_requests().await.unwrap();
    assert!(!requests.iter().any(|r| r.url.path().ends_with(".whl")));
}

/// Uploading a filename that was deleted and is stored again with other bytes replaces
/// the marker left by the earlier file.
#[tokio::test]
async fn upload_replaces_a_stale_marker_of_the_same_filename() {
    let ctx = create_test_context();
    let filename = "reup-1.0-py3-none-any.whl";
    let stale = digest(b"earlier bytes");
    ctx.state
        .storage
        .put(&hash_marker_key("reup", filename, &stale), b"")
        .await
        .unwrap();

    let content_type = format!("multipart/form-data; boundary={BOUNDARY}");
    let resp = send_with_headers(
        &ctx.app,
        Method::POST,
        "/simple/",
        vec![("content-type", content_type.as_str())],
        upload_body("reup", "1.0", filename, b"current bytes"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let current = digest(b"current bytes");
    let markers = ctx
        .state
        .storage
        .list(&format!("{HASH_MARKER_PREFIX}reup/"))
        .await
        .unwrap();
    assert_eq!(markers, vec![hash_marker_key("reup", filename, &current)]);
    let body = html_index(&ctx, "reup").await;
    assert!(
        body.contains(current.as_str()) && !body.contains(stale.as_str()),
        "{body}"
    );
}

/// A file cached from the upstream is stored with its hash marker.
#[tokio::test]
async fn proxied_file_is_cached_with_its_hash_marker() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    let filename = "proxied-1.0.tar.gz";
    let content = b"proxied sdist";
    Mock::given(method("GET"))
        .and(path("/proxied/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "<html><body><a href=\"{}/files/{filename}\">{filename}</a></body></html>",
            upstream.uri()
        )))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/files/{filename}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(content.to_vec()))
        .mount(&upstream)
        .await;
    // In-memory object store: the cache write runs in the background, and a local disk
    // would add fsync latency to what the test waits for.
    let (backend, _ops) = op_counting_storage();
    let ctx = create_test_context_with_storage_and_config(backend, |cfg| {
        cfg.pypi.proxy = Some(upstream.uri());
    });

    let resp = send(
        &ctx.app,
        Method::GET,
        &format!("/simple/proxied/{filename}"),
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "proxied download served");
    wait_for_markers(
        &ctx,
        "proxied",
        &[hash_marker_key("proxied", filename, &digest(content))],
    )
    .await;
}

/// A file whose digest comes from its `.sha256` sidecar (no marker yet) is never listed
/// without it because the sidecar could not be read: a client would install it unchecked.
/// The project's index answers 503, 500 for a sidecar that fails its integrity check. A file
/// that has no sidecar at all is listed without a digest, as before.
#[tokio::test]
async fn a_digest_the_store_cannot_read_is_not_left_out_of_the_index() {
    use crate::test_helpers::{outage_storage, ReadFault};
    let filename = "sidecar-1.0.tar.gz";
    let sha = digest(b"sdist");
    for (fault, expected) in [
        (ReadFault::Network, StatusCode::SERVICE_UNAVAILABLE),
        (ReadFault::Tampered, StatusCode::INTERNAL_SERVER_ERROR),
    ] {
        let (storage, outage) = outage_storage();
        let ctx = create_test_context_with_storage(storage);
        let key = format!("pypi/sidecar/{filename}");
        ctx.state.storage.put(&key, b"sdist").await.unwrap();
        ctx.state
            .storage
            .put(&format!("{key}.sha256"), sha.as_bytes())
            .await
            .unwrap();
        ctx.state
            .storage
            .put("pypi/sidecar/bare-1.0.tar.gz", b"bare")
            .await
            .unwrap();
        let body = html_index(&ctx, "sidecar").await;
        assert!(body.contains(&format!("{filename}#sha256={sha}")), "{body}");
        assert!(body.contains("bare-1.0.tar.gz"), "{body}");
        outage.fault_reads_of(&format!("{key}.sha256"), fault);
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/sidecar/",
            vec![("Accept", "text/html")],
            "",
        )
        .await;
        let status = resp.status();
        let body = String::from_utf8_lossy(&body_bytes(resp).await).into_owned();
        assert_eq!(status, expected, "{fault:?}: {body}");
    }
}
