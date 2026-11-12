// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

//! Tag and catalog listings must cost the same storage round-trips for 1 and 100 entries.
use crate::test_helpers::{create_test_context_with_storage, op_counting_storage, send};
use axum::body::Body;
use axum::http::{Method, StatusCode};

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
