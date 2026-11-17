// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

//! Tag and catalog listings must cost the same storage round-trips for 1 and 100 entries,
//! and the catalog is served from the repository index.
use crate::test_helpers::{
    body_bytes, create_test_context, create_test_context_with_storage, op_counting_storage, send,
};
use axum::body::Body;
use axum::http::{header, Method, StatusCode};

async fn tags_list_ops(n: usize) -> (usize, String) {
    let (storage, ops) = op_counting_storage();
    let ctx = create_test_context_with_storage(storage);
    for i in 0..n {
        let key = format!("docker/costimg/manifests/tag-{i}.json");
        ctx.state.storage.put(&key, b"{}").await.unwrap();
    }
    ops.reset();
    let resp = send(
        &ctx.app,
        Method::GET,
        "/v2/costimg/tags/list",
        Body::empty(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "tags/list with {n} tags");
    (ops.total(), format!("{:?}", ops.snapshot()))
}

async fn catalog_ops(n: usize) -> (usize, String) {
    let (storage, ops) = op_counting_storage();
    let ctx = create_test_context_with_storage(storage);
    for i in 0..n {
        let key = format!("docker/costrepo-{i}/manifests/latest.json");
        ctx.state.storage.put(&key, b"{}").await.unwrap();
    }
    ops.reset();
    let resp = send(&ctx.app, Method::GET, "/v2/_catalog", Body::empty()).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "_catalog with {n} repositories"
    );
    (ops.total(), format!("{:?}", ops.snapshot()))
}

#[tokio::test]
async fn docker_tags_list_cost_is_independent_of_tag_count() {
    let (small, small_ops) = tags_list_ops(1).await;
    let (large, large_ops) = tags_list_ops(100).await;
    assert_eq!(
        small, large,
        "tags/list must cost the same storage round-trips for 1 and 100 tags: {small_ops} vs {large_ops}"
    );
}

#[tokio::test]
async fn docker_catalog_cost_is_independent_of_repository_count() {
    let (small, small_ops) = catalog_ops(1).await;
    let (large, large_ops) = catalog_ops(100).await;
    assert_eq!(
        small, large,
        "_catalog must cost the same storage round-trips for 1 and 100 repositories: {small_ops} vs {large_ops}"
    );
}

/// Audit A053: once the repository index is built, concurrent catalog requests list nothing:
/// they share the index instead of each walking every key under `docker/`.
#[tokio::test]
async fn concurrent_catalog_requests_list_no_storage() {
    let (storage, ops) = op_counting_storage();
    let ctx = create_test_context_with_storage(storage);
    for i in 0..20 {
        let key = format!("docker/catrepo-{i:02}/manifests/latest.json");
        ctx.state.storage.put(&key, b"{}").await.unwrap();
    }
    let warm = send(&ctx.app, Method::GET, "/v2/_catalog", Body::empty()).await;
    assert_eq!(warm.status(), StatusCode::OK);
    ops.reset();
    let requests = (0..8).map(|_| send(&ctx.app, Method::GET, "/v2/_catalog", Body::empty()));
    let mut bodies = Vec::new();
    for resp in futures::future::join_all(requests).await {
        assert_eq!(resp.status(), StatusCode::OK);
        bodies.push(body_bytes(resp).await);
    }
    assert_eq!(ops.total(), 0, "{:?}", ops.snapshot());
    let json: serde_json::Value = serde_json::from_slice(&bodies[0]).unwrap();
    assert_eq!(json["repositories"].as_array().unwrap().len(), 20);
    assert!(bodies.iter().all(|b| b == &bodies[0]));
}

/// Audit A053: before the first index build finishes the catalog is a 503 with Retry-After,
/// not a falsely empty list.
#[tokio::test]
async fn catalog_before_the_index_is_built_is_retry_later() {
    let (storage, ops) = op_counting_storage();
    let ctx = create_test_context_with_storage(storage);
    ctx.state
        .storage
        .put("docker/app/manifests/latest.json", b"{}")
        .await
        .unwrap();
    ops.stall_lists(Some("docker/"));
    let resp = send(&ctx.app, Method::GET, "/v2/_catalog", Body::empty()).await;
    ops.stall_lists(None);
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(resp.headers()[header::RETRY_AFTER], "30");
}

/// The catalog dedups names across upstream namespaces and pages with `n`, `last` and a
/// `Link` to the next page, as tags/list does.
#[tokio::test]
async fn catalog_dedups_and_pages() {
    let ctx = create_test_context();
    for key in [
        "docker/docker.io/library/nginx/manifests/latest.json",
        "docker/ghcr.io/library/nginx/manifests/v1.json",
        "docker/library/nginx/manifests/old.json",
        "docker/alpha/manifests/latest.json",
        "docker/zeta/blobs/sha256:00",
    ] {
        ctx.state.storage.put(key, b"{}").await.unwrap();
    }
    let page = |uri: &'static str| {
        let app = ctx.app.clone();
        async move {
            let resp = send(&app, Method::GET, uri, Body::empty()).await;
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
            let link = resp
                .headers()
                .get(header::LINK)
                .map(|l| l.to_str().unwrap().to_string());
            let json: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
            (json["repositories"].clone(), link)
        }
    };
    let (all, link) = page("/v2/_catalog").await;
    assert_eq!(all, serde_json::json!(["alpha", "library/nginx", "zeta"]));
    assert_eq!(link, None);
    let (first, link) = page("/v2/_catalog?n=2").await;
    assert_eq!(first, serde_json::json!(["alpha", "library/nginx"]));
    assert_eq!(
        link.as_deref(),
        Some("</v2/_catalog?n=2&last=library%2Fnginx>; rel=\"next\"")
    );
    let (rest, link) = page("/v2/_catalog?n=2&last=library%2Fnginx").await;
    assert_eq!(rest, serde_json::json!(["zeta"]));
    assert_eq!(link, None);
    let bad = send(&ctx.app, Method::GET, "/v2/_catalog?n=x", Body::empty()).await;
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
}
