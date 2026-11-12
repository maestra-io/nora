// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::config::DockerUpstream;
use crate::storage::{FileMeta, ObjectStorage, Result, StorageBackend};
use crate::Storage;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

const BLOB: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Holds the next put and/or the next delete of one key until released.
struct Held {
    inner: Arc<dyn StorageBackend>,
    key: String,
    hold_put: AtomicBool,
    put_reached: Notify,
    put_release: Notify,
    hold_delete: AtomicBool,
    del_reached: Notify,
    del_release: Notify,
}

#[async_trait::async_trait]
impl StorageBackend for Held {
    async fn put(&self, key: &str, data: &[u8], sha256: &str) -> Result<()> {
        if key == self.key && self.hold_put.swap(false, Ordering::SeqCst) {
            self.put_reached.notify_one();
            self.put_release.notified().await;
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
        if key == self.key && self.hold_delete.swap(false, Ordering::SeqCst) {
            self.del_reached.notify_one();
            self.del_release.notified().await;
        }
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
        "held"
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

struct Fx {
    _ctx: crate::test_helpers::TestContext,
    _dir: Option<tempfile::TempDir>,
    state: crate::AppState,
    held: Arc<Held>,
    manifest: Bytes,
    digest: String,
}

/// Upstream with namespace docker.io configured (so a hosted pull is a bare-key hit);
/// `local` = LocalStorage (delete of a missing key is NotFound) instead of in-memory.
async fn fx(local: bool, held_key: impl Fn(&str) -> String) -> Fx {
    use crate::test_helpers::create_test_context_with_config;
    use sha2::Digest as _;
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
    let manifest = Bytes::from(
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
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&manifest)));
    let (dir, inner): (Option<tempfile::TempDir>, Arc<dyn StorageBackend>) = if local {
        let d = tempfile::tempdir().unwrap();
        let s = crate::storage::LocalStorage::new(d.path().to_str().unwrap());
        (Some(d), Arc::new(s))
    } else {
        (None, Arc::new(ObjectStorage::in_memory()))
    };
    let held = Arc::new(Held {
        inner,
        key: held_key(&digest),
        hold_put: AtomicBool::new(false),
        put_reached: Notify::new(),
        put_release: Notify::new(),
        hold_delete: AtomicBool::new(false),
        del_reached: Notify::new(),
        del_release: Notify::new(),
    });
    let mut state = ctx.state.clone();
    state.storage = Storage::from_backend(held.clone());
    state
        .storage
        .put(&format!("docker/race-img/blobs/{BLOB}"), b"x")
        .await
        .unwrap();
    Fx {
        _ctx: ctx,
        _dir: dir,
        state,
        held,
        manifest,
        digest,
    }
}

async fn push(state: crate::AppState, tag: String, body: Bytes) -> StatusCode {
    super::put_manifest(State(state), Path(("race-img".to_string(), tag)), body)
        .await
        .status()
}

async fn pull(state: &crate::AppState, reference: &str) {
    let r = super::get_manifest(
        State(state.clone()),
        axum::http::HeaderMap::new(),
        Path(("race-img".to_string(), reference.to_string())),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
}

async fn reached(n: &Notify, what: &str) {
    // CANCEL-SAFETY: a timed-out wait drops only the notification future; expect fails.
    tokio::time::timeout(Duration::from_secs(5), n.notified())
        .await
        .expect(what);
}

async fn set_push_ts(state: &crate::AppState, key: &str, ts: u64) {
    let mut m: super::ImageMetadata =
        serde_json::from_slice(&state.storage.get(key).await.unwrap()).unwrap();
    m.push_timestamp = ts;
    state
        .storage
        .put(key, &serde_json::to_vec(&m).unwrap())
        .await
        .unwrap();
}

async fn date(state: &crate::AppState, reference: &str) -> Option<i64> {
    super::extract_docker_publish_date(
        &state.storage,
        "race-img",
        reference,
        false,
        Some("docker.io"),
        &mut super::BareMeta::Unread,
    )
    .await
}

/// Pull (stats write held) ‖ delete `delete_ref`; the held key must be gone afterwards.
async fn delete_during_pull(f: &Fx, pull_ref: &str, delete_ref: &str) {
    let key = f.held.key.clone();
    assert_eq!(
        push(f.state.clone(), "v1".into(), f.manifest.clone()).await,
        StatusCode::CREATED
    );
    assert!(f.state.storage.stat(&key).await.is_some());
    // V3: the pull records in-memory (no storage write); the manifest is then
    // deleted; a later flush must honour the deleted-manifest guard and
    // resurrect neither the .meta.json nor the .stats.json of a gone manifest.
    pull(&f.state, pull_ref).await;
    let del = super::delete_manifest(
        State(f.state.clone()),
        Path(("race-img".to_string(), delete_ref.to_string())),
    )
    .await;
    assert_eq!(del.status(), StatusCode::ACCEPTED);
    super::flush_pull_stats(&f.state).await;
    assert!(
        f.state.storage.stat(&key).await.is_none(),
        "metadata {key} of the deleted manifest was written back"
    );
    assert!(
        f.state
            .storage
            .stat(&super::manifest_stats_key(&key))
            .await
            .is_none(),
        "the stats sidecar of the deleted manifest was written back"
    );
}

/// M02: pull by digest ‖ delete by tag — the digest's metadata must not survive.
#[tokio::test]
async fn a_delete_by_tag_during_a_digest_pull_leaves_no_metadata() {
    let f = fx(false, |d| {
        format!("docker/race-img/manifests/{d}.meta.json")
    })
    .await;
    let d = f.digest.clone();
    delete_during_pull(&f, &d, "v1").await;
}

/// M03: pull by tag ‖ delete by digest (tag dropped via delete_tags_for_digest).
#[tokio::test]
async fn a_delete_by_digest_during_a_tag_pull_leaves_no_tag_metadata() {
    let f = fx(false, |_| "docker/race-img/manifests/v1.meta.json".into()).await;
    let d = f.digest.clone();
    delete_during_pull(&f, "v1", &d).await;
}

/// M06: LocalStorage — delete by tag takes the legacy-key branch.
#[tokio::test]
async fn a_delete_during_a_pull_on_local_storage_leaves_no_metadata() {
    let f = fx(true, |_| "docker/race-img/manifests/v1.meta.json".into()).await;
    delete_during_pull(&f, "v1", "v1").await;
}

/// Pull of `pull_ref` (stats write held) ‖ re-push of `tag`; date for `pull_ref` must be the re-push's.
async fn re_push_during_pull(f: &Fx, tag: &str, pull_ref: &str) {
    let key = f.held.key.clone();
    assert_eq!(
        push(f.state.clone(), tag.into(), f.manifest.clone()).await,
        StatusCode::CREATED
    );
    set_push_ts(&f.state, &key, 1_000_000).await;
    // V3: the pull records in-memory and never writes .meta.json, so it cannot
    // clobber the publish date. A re-push sets the new date; a later flush
    // touches only the .stats.json sidecar, never the publish timestamp.
    pull(&f.state, pull_ref).await;
    assert_eq!(
        push(f.state.clone(), tag.into(), f.manifest.clone()).await,
        StatusCode::CREATED
    );
    super::flush_pull_stats(&f.state).await;
    let got = date(&f.state, pull_ref).await.unwrap();
    assert!(
        got > 1_000_000,
        "stale first-push date after re-push: {got}"
    );
}

/// M04: pull by digest ‖ re-push — the digest's metadata keeps the re-push date.
#[tokio::test]
async fn a_re_push_during_a_digest_pull_keeps_the_re_push_date() {
    let f = fx(false, |d| {
        format!("docker/race-img/manifests/{d}.meta.json")
    })
    .await;
    let d = f.digest.clone();
    re_push_during_pull(&f, "v1", &d).await;
}

/// M08: a tag with upper-case letters — same race, lock key must be the exact meta key.
#[tokio::test]
async fn a_re_push_during_a_pull_of_a_mixed_case_tag_keeps_the_re_push_date() {
    let f = fx(false, |_| "docker/race-img/manifests/V1.meta.json".into()).await;
    re_push_during_pull(&f, "V1", "V1").await;
}

/// A pull's statistics task that starts while the delete is in flight must not read the old
/// metadata and write it back (that would hand the deleted push's date to curation of the
/// same reference): it waits for the delete's lock and then finds the manifest gone.
#[tokio::test(start_paused = true)]
async fn a_delete_holds_the_lock_until_the_metadata_is_gone() {
    // Local storage: on an object backend with an upstream namespace the delete leaves the
    // hosted manifest in place (a separate, older defect), and the task rightly counts it.
    let f = fx(true, |_| "docker/race-img/manifests/v1.meta.json".into()).await;
    let key = f.held.key.clone();
    assert_eq!(
        push(f.state.clone(), "v1".into(), f.manifest.clone()).await,
        StatusCode::CREATED
    );
    set_push_ts(&f.state, &key, 1_000_000).await;
    f.held.hold_delete.store(true, Ordering::SeqCst);
    let del = tokio::spawn(super::delete_manifest(
        State(f.state.clone()),
        Path(("race-img".to_string(), "v1".to_string())),
    ));
    reached(&f.held.del_reached, "metadata delete not reached").await;
    // V3: a pull recorded now; its flush races the in-flight delete. The flush
    // waits on the publish lock the delete holds, then finds the manifest gone
    // and drops the delta — the sidecar must not resurrect the deleted manifest.
    f.state.pull_stats.record(&key, 1_700_000_000);
    let stats = {
        let st = f.state.clone();
        tokio::spawn(async move {
            super::flush_pull_stats(&st).await;
        })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    f.held.del_release.notify_one();
    assert_eq!(del.await.unwrap().status(), StatusCode::ACCEPTED);
    stats.await.unwrap();
    assert!(
        f.state.storage.stat(&key).await.is_none(),
        "the deleted manifest's metadata is back"
    );
    assert!(
        f.state
            .storage
            .stat(&super::manifest_stats_key(&key))
            .await
            .is_none(),
        "a flush resurrected the deleted manifest's stats sidecar"
    );
    assert_eq!(
        date(&f.state, "v1").await,
        None,
        "a deleted push's date survived the delete"
    );
}
