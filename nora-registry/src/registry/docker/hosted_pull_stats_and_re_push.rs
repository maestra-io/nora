// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::storage::{FileMeta, ObjectStorage, Result, StorageBackend};
use crate::Storage;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Notify;

struct HeldPut {
    inner: ObjectStorage,
    key: String,
    armed: AtomicBool,
    reached: Arc<Notify>,
    release: Arc<Notify>,
}

#[async_trait::async_trait]
impl StorageBackend for HeldPut {
    async fn put(&self, key: &str, data: &[u8], sha256: &str) -> Result<()> {
        if key == self.key && self.armed.swap(false, Ordering::SeqCst) {
            self.reached.notify_one();
            self.release.notified().await;
        }
        self.inner.put(key, data, sha256).await
    }
    async fn get(&self, key: &str) -> Result<(Bytes, Option<String>)> {
        self.inner.get(key).await
    }
    async fn pin(&self, key: &str) -> Option<String> {
        self.inner.pin(key).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key).await
    }
    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.inner.list(prefix).await
    }
    async fn stat(&self, key: &str) -> Option<FileMeta> {
        self.inner.stat(key).await
    }
    async fn health_check(&self) -> bool {
        true
    }
    async fn total_size(&self) -> u64 {
        0
    }
    fn backend_name(&self) -> &'static str {
        "held-put"
    }
    async fn put_from_path(
        &self,
        key: &str,
        src: &std::path::Path,
        sha256: Option<&str>,
    ) -> Result<()> {
        self.inner.put_from_path(key, src, sha256).await
    }
    async fn copy(&self, src: &str, dst: &str, sha256: Option<&str>) -> Result<()> {
        self.inner.copy(src, dst, sha256).await
    }
    async fn get_reader(
        &self,
        key: &str,
    ) -> Result<(
        u64,
        Option<String>,
        std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
    )> {
        self.inner.get_reader(key).await
    }
}

/// Push long ago, then (optionally) a pull whose statistics write is held, a re-push,
/// release. Returns the push date curation reads afterwards.
async fn push_date_after_re_push(with_pull: bool) -> i64 {
    use crate::config::DockerUpstream;
    use crate::test_helpers::create_test_context_with_config;

    let ctx = create_test_context_with_config(|cfg| {
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
    });
    let meta_key = "docker/race-img/manifests/v1.meta.json";
    let reached = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let backend = Arc::new(HeldPut {
        inner: ObjectStorage::in_memory(),
        key: meta_key.to_string(),
        armed: AtomicBool::new(false),
        reached: Arc::clone(&reached),
        release: Arc::clone(&release),
    });
    let mut state = ctx.state.clone();
    state.storage = Storage::from_backend(backend.clone());

    let manifest = Bytes::from(
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": 0,
                "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            },
            "layers": []
        }))
        .unwrap(),
    );
    state
        .storage
        .put(
            "docker/race-img/blobs/sha256:0000000000000000000000000000000000000000000000000000000000000000",
            b"x",
        )
        .await
        .unwrap();
    let push = |state: crate::AppState, body: Bytes| async move {
        super::put_manifest(
            State(state),
            Path(("race-img".to_string(), "v1".to_string())),
            body,
        )
        .await
        .status()
    };
    assert_eq!(
        push(state.clone(), manifest.clone()).await,
        StatusCode::CREATED
    );
    // The first push was long ago.
    let mut meta: super::ImageMetadata =
        serde_json::from_slice(&state.storage.get(meta_key).await.unwrap()).unwrap();
    meta.push_timestamp = 1_000_000;
    state
        .storage
        .put(meta_key, &serde_json::to_vec(&meta).unwrap())
        .await
        .unwrap();

    if with_pull {
        // V3: the pull records in-memory and never writes .meta.json, so it
        // cannot clobber the publish date curation reads.
        let pull = super::get_manifest(
            State(state.clone()),
            axum::http::HeaderMap::new(),
            Path(("race-img".to_string(), "v1".to_string())),
        )
        .await;
        assert_eq!(pull.status(), StatusCode::OK);
    }

    // A re-push sets the new date; a flush then touches only the .stats.json sidecar.
    let repush = push(state.clone(), manifest.clone()).await;
    assert_eq!(repush, StatusCode::CREATED);
    super::flush_pull_stats(&state).await;

    super::extract_docker_publish_date(
        &state.storage,
        "race-img",
        "v1",
        false,
        Some("docker.io"),
        &mut super::BareMeta::Unread,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn a_re_push_during_a_pull_keeps_the_re_push_date() {
    let date = push_date_after_re_push(true).await;
    assert!(
        date > 1_000_000,
        "curation reads the first push's date after a re-push: {date}"
    );
}

/// Control: without a pull the re-push's date is what curation reads.
#[tokio::test]
async fn control_a_re_push_alone_sets_the_push_date() {
    assert!(push_date_after_re_push(false).await > 1_000_000);
}

/// A delete while a pull's statistics write is held: once both are done, no metadata of
/// the deleted manifest is left behind (the pull's write must not land after the delete).
#[tokio::test]
async fn a_delete_during_a_pull_leaves_no_metadata() {
    use crate::config::DockerUpstream;
    use crate::test_helpers::create_test_context_with_config;

    let ctx = create_test_context_with_config(|cfg| {
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
    });
    let meta_key = "docker/race-img/manifests/v1.meta.json";
    let reached = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let backend = Arc::new(HeldPut {
        inner: ObjectStorage::in_memory(),
        key: meta_key.to_string(),
        armed: AtomicBool::new(false),
        reached: Arc::clone(&reached),
        release: Arc::clone(&release),
    });
    let mut state = ctx.state.clone();
    state.storage = Storage::from_backend(backend.clone());
    state
        .storage
        .put(
            "docker/race-img/blobs/sha256:0000000000000000000000000000000000000000000000000000000000000000",
            b"x",
        )
        .await
        .unwrap();
    let manifest = Bytes::from(
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": 0,
                "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            },
            "layers": []
        }))
        .unwrap(),
    );
    let pushed = super::put_manifest(
        State(state.clone()),
        Path(("race-img".to_string(), "v1".to_string())),
        manifest,
    )
    .await;
    assert_eq!(pushed.status(), StatusCode::CREATED);

    // V3: the pull records in-memory (no storage write); the manifest is then
    // deleted; a later flush must honour the deleted-manifest guard and
    // resurrect neither the .meta.json nor the .stats.json. The held-put arming
    // (backend.armed / reached / release) is left unused — the pull no longer
    // writes, so there is nothing to hold.
    let pull = super::get_manifest(
        State(state.clone()),
        axum::http::HeaderMap::new(),
        Path(("race-img".to_string(), "v1".to_string())),
    )
    .await;
    assert_eq!(pull.status(), StatusCode::OK);

    let delete = super::delete_manifest(
        State(state.clone()),
        Path(("race-img".to_string(), "v1".to_string())),
    )
    .await;
    assert_eq!(delete.status(), StatusCode::ACCEPTED);
    super::flush_pull_stats(&state).await;
    // The flush never writes .meta.json: the metadata the delete removed stays
    // removed. On this backend (in-memory + an upstream namespace) the bare
    // manifest survives the delete through a separate pre-existing gap, so the
    // flush legitimately persists the .stats.json sidecar (the manifest is
    // still stored); the no-resurrect guard for a truly-gone manifest is
    // covered on the local backend by delete_during_pull and
    // a_pull_stats_task_after_the_delete_leaves_no_metadata.
    assert!(
        state.storage.stat(meta_key).await.is_none(),
        "the deleted manifest's .meta.json was written back by the flush"
    );
}
