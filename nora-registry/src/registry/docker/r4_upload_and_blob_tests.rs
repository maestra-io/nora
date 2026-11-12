// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::config::DockerUpstream;
use crate::test_helpers::{
    body_bytes, create_test_context, create_test_context_with_config,
    create_test_context_with_storage, send, send_with_headers, TestContext,
};
use axum::body::Body;
use axum::http::{header, Method, StatusCode};
use sha2::Digest;

fn digest_of(body: &[u8]) -> String {
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(body)))
}

fn proxying_ctx() -> TestContext {
    create_test_context_with_config(|cfg| {
        cfg.docker.upstreams = vec![DockerUpstream {
            trust_upstream_dates: false,
            date_token_file: None,
            url: "http://127.0.0.1:1".into(),
            auth: None,
            auth_env: None,
            namespace: Some("docker.io".into()),
            prefix: None,
            namespaces: Vec::new(),
        }];
    })
}

/// Opens an upload and returns its URL.
async fn start(ctx: &TestContext) -> String {
    let resp = send(
        &ctx.app,
        Method::POST,
        "/v2/team/app/blobs/uploads/",
        Body::empty(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    resp.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_string()
}

async fn chunk(
    ctx: &TestContext,
    method: Method,
    uri: &str,
    range: Option<&str>,
    body: &'static [u8],
) -> axum::http::Response<Body> {
    let headers = range
        .map(|r| vec![("content-range", r)])
        .unwrap_or_default();
    send_with_headers(&ctx.app, method, uri, headers, Body::from(body)).await
}

async fn error_code(resp: axum::http::Response<Body>) -> String {
    let json: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    json["errors"][0]["code"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// R4-R08: a retried chunk is refused with 416 and the Range the upload holds, instead of
/// being appended twice; GET on the upload URL reports the same Range; the blob that
/// results is the bytes sent once.
#[tokio::test]
async fn a_retried_chunk_is_416_and_the_upload_reports_its_range() {
    let ctx = create_test_context();
    let upload = start(&ctx).await;

    let resp = send(&ctx.app, Method::GET, &upload, Body::empty()).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(resp.headers()[header::RANGE], "0-0");

    let resp = chunk(&ctx, Method::PATCH, &upload, Some("0-3"), b"abcd").await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    assert_eq!(resp.headers()[header::RANGE], "0-3");

    // The answer was lost: the client sends the chunk again.
    let resp = chunk(&ctx, Method::PATCH, &upload, Some("0-3"), b"abcd").await;
    assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(resp.headers()[header::RANGE], "0-3");
    assert_eq!(resp.headers()[header::LOCATION].to_str().unwrap(), upload);

    let resp = send(&ctx.app, Method::GET, &upload, Body::empty()).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(resp.headers()[header::RANGE], "0-3");
    assert_eq!(resp.headers()[header::LOCATION].to_str().unwrap(), upload);
    assert!(resp.headers().contains_key("docker-upload-uuid"));

    // A final chunk out of order is refused too, and the upload stays open.
    let digest = digest_of(b"abcdefgh");
    let close = format!("{upload}?digest={digest}");
    let resp = chunk(&ctx, Method::PUT, &close, Some("0-3"), b"efgh").await;
    assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);

    let resp = chunk(&ctx, Method::PUT, &close, Some("4-7"), b"efgh").await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let stored = ctx
        .state
        .storage
        .get(&format!("docker/team/app/blobs/{digest}"))
        .await
        .unwrap();
    assert_eq!(&stored[..], b"abcdefgh");

    // A chunk without Content-Range (the docker client) is appended where the upload stands.
    let upload = start(&ctx).await;
    for part in [&b"ab"[..], &b"cd"[..]] {
        let resp = chunk(&ctx, Method::PATCH, &upload, None, part).await;
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }
    let close = format!("{upload}?digest={}", digest_of(b"abcd"));
    let resp = chunk(&ctx, Method::PUT, &close, None, b"").await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

/// R4-R08/R4-R19: an upload NORA does not hold is 404 BLOB_UPLOAD_UNKNOWN for the status
/// GET and for the closing PUT — not DIGEST_INVALID over the PUT body alone.
#[tokio::test]
async fn an_unknown_upload_is_blob_upload_unknown() {
    let ctx = create_test_context();
    let gone = "/v2/team/app/blobs/uploads/00000000-0000-4000-8000-000000000000";
    let resp = send(&ctx.app, Method::GET, gone, Body::empty()).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(error_code(resp).await, "BLOB_UPLOAD_UNKNOWN");

    let close = format!("{gone}?digest={}", digest_of(b"abcd"));
    let resp = chunk(&ctx, Method::PUT, &close, None, b"").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(error_code(resp).await, "BLOB_UPLOAD_UNKNOWN");

    // The single-POST form has no session by design and still stores the blob.
    let post = format!("/v2/team/app/blobs/uploads/?digest={}", digest_of(b"abcd"));
    let resp = chunk(&ctx, Method::POST, &post, None, b"abcd").await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

/// R4-R19: a finalize refused for its digest algorithm leaves the upload open.
#[tokio::test]
async fn a_finalize_refused_for_its_digest_keeps_the_upload() {
    let ctx = create_test_context();
    let upload = start(&ctx).await;
    let resp = chunk(&ctx, Method::PATCH, &upload, None, b"abcd").await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    let sha512 = format!("{upload}?digest=sha512:{}", "a".repeat(128));
    let resp = chunk(&ctx, Method::PUT, &sha512, None, b"").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let resp = send(&ctx.app, Method::GET, &upload, Body::empty()).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let close = format!("{upload}?digest={}", digest_of(b"abcd"));
    let resp = chunk(&ctx, Method::PUT, &close, None, b"").await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

/// R4-R05: with an upstream configured a pushed blob has a namespaced key it is not under.
/// Its delete answers 202, and 404 only once nothing is left.
#[tokio::test]
async fn deleting_a_pushed_blob_is_accepted_with_an_upstream_configured() {
    let ctx = proxying_ctx();
    let digest = digest_of(b"layer");
    let key = format!("docker/team/app/blobs/{digest}");
    ctx.state.storage.put(&key, b"layer").await.unwrap();
    let uri = format!("/v2/team/app/blobs/{digest}");

    let resp = send(&ctx.app, Method::DELETE, &uri, Body::empty()).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    assert!(ctx.state.storage.stat(&key).await.is_none());

    let resp = send(&ctx.app, Method::DELETE, &uri, Body::empty()).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(error_code(resp).await, "BLOB_UNKNOWN");
}

fn image(config: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "size": 6,
            "digest": config
        },
        "layers": []
    }))
    .unwrap()
}

/// R4-R06: HEAD reports a blob cached by a pull, the client skips its upload, and the
/// manifest push is accepted; the blob is copied into the pushed layout so the image does
/// not live off the proxy cache. The same for an index over a cached child manifest.
#[tokio::test]
async fn a_manifest_over_proxy_cached_content_can_be_pushed() {
    let ctx = proxying_ctx();
    let storage = &ctx.state.storage;
    let config = digest_of(b"config");
    let cached = "docker/docker.io/library/alpine";
    storage
        .put(&format!("{cached}/blobs/{config}"), b"config")
        .await
        .unwrap();

    let head = format!("/v2/library/alpine/blobs/{config}");
    let resp = send(&ctx.app, Method::HEAD, &head, Body::empty()).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let child = image(&config);
    let put = "/v2/library/alpine/manifests/prod";
    let resp = send(&ctx.app, Method::PUT, put, Body::from(child.clone())).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let pushed = format!("docker/library/alpine/blobs/{config}");
    assert_eq!(&storage.get(&pushed).await.unwrap()[..], b"config");

    // An index whose child manifest and its blob are only in the cache.
    let other = digest_of(b"other!");
    storage
        .put(&format!("{cached}/blobs/{other}"), b"other!")
        .await
        .unwrap();
    let child = image(&other);
    let child_digest = digest_of(&child);
    storage
        .put(&format!("{cached}/manifests/{child_digest}.json"), &child)
        .await
        .unwrap();
    let index = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "size": child.len(),
            "digest": child_digest
        }]
    }))
    .unwrap();
    let put = "/v2/library/alpine/manifests/multi";
    let resp = send(&ctx.app, Method::PUT, put, Body::from(index)).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    for key in [
        format!("docker/library/alpine/manifests/{child_digest}.json"),
        format!("docker/library/alpine/blobs/{other}"),
    ] {
        assert!(storage.stat(&key).await.is_some(), "{key} not taken over");
    }

    // Content NORA holds nowhere is still refused.
    let absent = image(&digest_of(b"absent"));
    let resp = send(&ctx.app, Method::PUT, put, Body::from(absent)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(error_code(resp).await, "MANIFEST_BLOB_UNKNOWN");
}

/// R4-R21: HEAD of a blob carries the headers of its GET, and curation refuses it as it
/// refuses the GET.
#[tokio::test]
async fn head_blob_has_the_get_headers_and_the_curation_gate() {
    let ctx = create_test_context();
    let digest = digest_of(b"layer");
    let key = format!("docker/team/app/blobs/{digest}");
    ctx.state.storage.put(&key, b"layer").await.unwrap();
    let uri = format!("/v2/team/app/blobs/{digest}");
    let resp = send(&ctx.app, Method::HEAD, &uri, Body::empty()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let headers = resp.headers();
    assert_eq!(headers["docker-content-digest"].to_str().unwrap(), digest);
    assert_eq!(headers[header::CONTENT_LENGTH], "5");
    assert_eq!(headers[header::CONTENT_TYPE], "application/octet-stream");
    assert_eq!(headers[header::ACCEPT_RANGES], "bytes");

    let (_dir, blocklist) = crate::test_helpers::blocklist_file("docker", "team/app");
    let blocked = create_test_context_with_config(|cfg| {
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.blocklist_path = Some(blocklist);
    });
    blocked.state.storage.put(&key, b"layer").await.unwrap();
    for method in [Method::GET, Method::HEAD] {
        let resp = send(&blocked.app, method.clone(), &uri, Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{method}");
    }
}

/// R4-P15: a Range request costs one ranged read and no read of the whole blob; a Range
/// that cannot be used still gets the whole blob.
#[tokio::test]
async fn a_range_request_does_not_open_the_whole_blob() {
    let (storage, counts) = crate::test_helpers::op_counting_storage();
    let ctx = create_test_context_with_storage(storage);
    let digest = digest_of(b"0123456789");
    let key = format!("docker/team/app/blobs/{digest}");
    ctx.state.storage.put(&key, b"0123456789").await.unwrap();
    let uri = format!("/v2/team/app/blobs/{digest}");

    counts.reset();
    let range = vec![("range", "bytes=2-5")];
    let resp = send_with_headers(&ctx.app, Method::GET, &uri, range, Body::empty()).await;
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(&body_bytes(resp).await[..], b"2345");
    assert_eq!(counts.calls("get_reader", &key), 0);
    assert_eq!(counts.calls("get_range", &key), 1);

    let range = vec![("range", "bytes=20-30")];
    let resp = send_with_headers(&ctx.app, Method::GET, &uri, range, Body::empty()).await;
    assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);

    let range = vec![("range", "lines=1-2")];
    let resp = send_with_headers(&ctx.app, Method::GET, &uri, range, Body::empty()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(&body_bytes(resp).await[..], b"0123456789");
}
