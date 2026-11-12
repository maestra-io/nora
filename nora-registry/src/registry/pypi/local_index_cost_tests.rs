// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

//! The simple index over locally stored files must cost the same storage round-trips
//! for 1 and 100 files, in both the HTML and the JSON form.
use crate::test_helpers::{
    body_bytes, create_test_context_with_storage, op_counting_storage, send_with_headers,
    TestContext,
};
use axum::http::{Method, StatusCode};

pub(super) const BOUNDARY: &str = "nora-test-boundary";
const JSON: &str = "application/vnd.pypi.simple.v1+json";
const HTML: &str = "text/html";

pub(super) fn upload_body(name: &str, version: &str, filename: &str, content: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    for (field, value) in [
        (":action", "file_upload"),
        ("name", name),
        ("version", version),
    ] {
        body.extend_from_slice(
            format!(
                "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{field}\"\r\n\r\n{value}\r\n"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(
        format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"content\"; filename=\"{filename}\"\r\n\
                 Content-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
    body
}

async fn upload(ctx: &TestContext, version: &str) {
    let filename = format!("costpkg-{version}-py3-none-any.whl");
    let content_type = format!("multipart/form-data; boundary={BOUNDARY}");
    let body = upload_body(
        "costpkg",
        version,
        &filename,
        format!("wheel {version}").as_bytes(),
    );
    let resp = send_with_headers(
        &ctx.app,
        Method::POST,
        "/simple/",
        vec![("content-type", content_type.as_str())],
        body,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "upload {filename}");
}

async fn index_ops(n: usize, accept: &str) -> (usize, String) {
    let (storage, ops) = op_counting_storage();
    let ctx = create_test_context_with_storage(storage);
    for i in 0..n {
        upload(&ctx, &format!("1.0.{i}")).await;
    }
    ops.reset();
    let resp = send_with_headers(
        &ctx.app,
        Method::GET,
        "/simple/costpkg/",
        vec![("Accept", accept)],
        "",
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "index of {n} local files ({accept})"
    );
    let counted = (ops.total(), format!("{:?}", ops.snapshot()));
    let body = String::from_utf8(body_bytes(resp).await.to_vec()).unwrap();
    assert!(
        body.matches("sha256").count() >= n,
        "every one of the {n} local files must carry its sha256 ({accept})"
    );
    counted
}

#[tokio::test]
async fn pypi_simple_json_cost_is_independent_of_local_file_count() {
    let (small, small_ops) = index_ops(1, JSON).await;
    let (large, large_ops) = index_ops(100, JSON).await;
    assert_eq!(
        small, large,
        "the JSON simple index must cost the same storage round-trips for 1 and 100 local files: {small_ops} vs {large_ops}"
    );
}

#[tokio::test]
async fn pypi_simple_html_cost_is_independent_of_local_file_count() {
    let (small, small_ops) = index_ops(1, HTML).await;
    let (large, large_ops) = index_ops(100, HTML).await;
    assert_eq!(
        small, large,
        "the HTML simple index must cost the same storage round-trips for 1 and 100 local files: {small_ops} vs {large_ops}"
    );
}
