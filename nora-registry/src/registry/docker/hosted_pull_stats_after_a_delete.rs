// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::config::DockerUpstream;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;

const BLOB: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn ctx() -> crate::test_helpers::TestContext {
    crate::test_helpers::create_test_context_with_config(|cfg| {
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

async fn push_v1(state: &crate::AppState) {
    state
        .storage
        .put(&format!("docker/race-img/blobs/{BLOB}"), b"x")
        .await
        .unwrap();
    let body = Bytes::from(
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": 0,
                "digest": BLOB
            },
            "layers": []
        }))
        .unwrap(),
    );
    let r = super::put_manifest(
        State(state.clone()),
        Path(("race-img".to_string(), "v1".to_string())),
        body,
    )
    .await;
    assert_eq!(r.status(), StatusCode::CREATED);
}

// The pull was served (manifest read, statistics task spawned), then the delete ran first.
#[tokio::test]
async fn a_pull_stats_task_after_the_delete_leaves_no_metadata() {
    let ctx = ctx();
    let state = ctx.state.clone();
    push_v1(&state).await;
    let key = "docker/race-img/manifests/v1.meta.json".to_string();
    let del = super::delete_manifest(
        State(state.clone()),
        Path(("race-img".to_string(), "v1".to_string())),
    )
    .await;
    assert_eq!(del.status(), StatusCode::ACCEPTED);
    // V3: a late pull records into the in-memory accumulator; the flush's
    // deleted-manifest guard must drop it — neither .meta.json nor the
    // .stats.json sidecar may reappear for a manifest that was deleted.
    state.pull_stats.record(&key, 1_700_000_000);
    super::flush_pull_stats(&state).await;
    assert!(
        state.storage.stat(&key).await.is_none(),
        "the deleted manifest's metadata was re-created by a late pull flush"
    );
    assert!(
        state
            .storage
            .stat(&super::manifest_stats_key(&key))
            .await
            .is_none(),
        "the deleted manifest's stats sidecar was created by a late pull flush"
    );
}
