// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

//! Serving hosted maven-metadata.xml must cost the same storage round-trips for 1 and 100 versions.
use crate::test_helpers::{create_test_context_with_storage, op_counting_storage, send};
use axum::http::{Method, StatusCode};

async fn metadata_ops(n: usize) -> (usize, String) {
    let (storage, ops) = op_counting_storage();
    let ctx = create_test_context_with_storage(storage);
    let mut versions = String::new();
    for i in 0..n {
        let version = format!("1.0.{i}");
        let jar_key = format!("maven/com/example/costlib/{version}/costlib-{version}.jar");
        ctx.state.storage.put(&jar_key, b"JAR").await.unwrap();
        versions.push_str(&format!("<version>{version}</version>"));
    }
    let last = format!("1.0.{}", n - 1);
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><metadata><groupId>com.example</groupId>\
             <artifactId>costlib</artifactId><versioning><latest>{last}</latest>\
             <release>{last}</release><versions>{versions}</versions></versioning></metadata>"
    );
    ctx.state
        .storage
        .put(
            "maven/com/example/costlib/maven-metadata.xml",
            xml.as_bytes(),
        )
        .await
        .unwrap();
    ops.reset();
    let resp = send(
        &ctx.app,
        Method::GET,
        "/maven2/com/example/costlib/maven-metadata.xml",
        "",
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "maven-metadata.xml with {n} versions"
    );
    (ops.total(), format!("{:?}", ops.snapshot()))
}

#[tokio::test]
async fn maven_hosted_metadata_cost_is_independent_of_version_count() {
    let (small, small_ops) = metadata_ops(1).await;
    let (large, large_ops) = metadata_ops(100).await;
    assert_eq!(
        small, large,
        "hosted maven-metadata.xml must cost the same storage round-trips for 1 and 100 versions: {small_ops} vs {large_ops}"
    );
}
