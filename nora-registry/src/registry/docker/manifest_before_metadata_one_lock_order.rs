// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::config::DockerUpstream;
use crate::storage::{FileMeta, ObjectStorage, Result, StorageBackend};
use crate::Storage;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

const BLOB: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const PUT: u8 = 1;
const DELETE: u8 = 2;
const STAT: u8 = 3;
const TAG_MANIFEST: &str = "docker/race-img/manifests/v1.json";
const TAG_META: &str = "docker/race-img/manifests/v1.meta.json";

/// Holds the next armed operation (put / delete / stat-after-result) on one key.
struct Held {
    inner: Arc<dyn StorageBackend>,
    key: std::sync::Mutex<String>,
    op: AtomicU8,
    reached: Notify,
    release: Notify,
}

impl Held {
    fn arm(&self, op: u8, key: &str) {
        *self.key.lock().unwrap() = key.to_string();
        self.op.store(op, Ordering::SeqCst);
    }
    async fn gate(&self, op: u8, key: &str) {
        let same = { *self.key.lock().unwrap() == key };
        if same
            && self
                .op
                .compare_exchange(op, 0, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            self.reached.notify_one();
            self.release.notified().await;
        }
    }
}

#[async_trait::async_trait]
impl StorageBackend for Held {
    async fn put(&self, key: &str, data: &[u8], sha256: &str) -> Result<()> {
        self.gate(PUT, key).await;
        self.inner.put(key, data, sha256).await
    }
    async fn get(&self, key: &str) -> Result<(Bytes, Option<String>)> {
        self.inner.get(key).await
    }
    async fn pin(&self, key: &str) -> Option<String> {
        self.inner.pin(key).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.gate(DELETE, key).await;
        self.inner.delete(key).await
    }
    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.inner.list(prefix).await
    }
    async fn stat(&self, key: &str) -> Option<FileMeta> {
        // The answer is taken first; the hold sits between the answer and its use.
        let r = self.inner.stat(key).await;
        self.gate(STAT, key).await;
        r
    }
    async fn health_check(&self) -> bool {
        true
    }
    async fn total_size(&self) -> u64 {
        0
    }
    fn backend_name(&self) -> &'static str {
        "held-r2"
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

/// `upstream_ns`: an upstream with namespace docker.io (hosted = bare-key hit) vs none;
/// `local`: LocalStorage instead of in-memory.
async fn fx(upstream_ns: bool, local: bool) -> Fx {
    use sha2::Digest as _;
    let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
        cfg.docker.upstreams = if upstream_ns {
            vec![DockerUpstream {
                trust_upstream_dates: false,
                date_token_file: None,
                url: "http://127.0.0.1:1".into(),
                auth: None,
                auth_env: None,
                namespace: Some("docker.io".into()),
                prefix: None,
                namespaces: Vec::new(),
            }]
        } else {
            vec![]
        };
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
        key: std::sync::Mutex::new(String::new()),
        op: AtomicU8::new(0),
        reached: Notify::new(),
        release: Notify::new(),
    });
    let mut state = ctx.state.clone();
    state.storage = Storage::from_backend(held.clone());
    state
        .storage
        .put(&format!("docker/race-img/blobs/{BLOB}"), b"x")
        .await
        .unwrap();
    assert_eq!(
        push(state.clone(), manifest.clone()).await,
        StatusCode::CREATED
    );
    Fx {
        _ctx: ctx,
        _dir: dir,
        state,
        held,
        manifest,
        digest,
    }
}

async fn push(state: crate::AppState, body: Bytes) -> StatusCode {
    super::put_manifest(
        State(state),
        Path(("race-img".to_string(), "v1".to_string())),
        body,
    )
    .await
    .status()
}

async fn delete(state: crate::AppState, reference: String) -> StatusCode {
    super::delete_manifest(State(state), Path(("race-img".to_string(), reference)))
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

async fn finishes<T>(h: tokio::task::JoinHandle<T>, what: &str) -> T {
    // CANCEL-SAFETY: on timeout the handle is dropped (task detached) and the test fails.
    tokio::time::timeout(Duration::from_secs(5), h)
        .await
        .expect(what)
        .unwrap()
}

async fn downloads(state: &crate::AppState, key: &str) -> Option<u64> {
    Some(super::current_pull_stats(state, key).await.downloads)
}

/// The delete is held at `held_manifest`'s removal; a pull of `pull_ref` is served and its
/// statistics task completes meanwhile. Once the delete is done, `meta_key` must be gone.
async fn pull_while_manifest_delete_held(
    f: &Fx,
    held_manifest: &str,
    pull_ref: &str,
    delete_ref: &str,
    meta_key: &str,
) {
    f.held.arm(DELETE, held_manifest);
    let del = tokio::spawn(delete(f.state.clone(), delete_ref.to_string()));
    reached(&f.held.reached, "manifest delete not reached").await;
    pull(&f.state, pull_ref).await;
    // CANCEL-SAFETY: the poll loop holds nothing across its awaits; timeout fails the test.
    tokio::time::timeout(Duration::from_secs(5), async {
        while downloads(&f.state, meta_key).await != Some(1) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("pull statistics not recorded while the manifest was still stored");
    f.held.release.notify_one();
    assert_eq!(finishes(del, "delete hung").await, StatusCode::ACCEPTED);
    assert!(
        f.state.storage.stat(held_manifest).await.is_none(),
        "manifest {held_manifest} still stored"
    );
    assert!(
        f.state.storage.stat(meta_key).await.is_none(),
        "metadata {meta_key} outlived its deleted manifest"
    );
}

/// delete by tag, no upstream (Ok arm): a pull during the delete leaves no tag metadata.
#[tokio::test]
async fn a_pull_during_a_tag_delete_leaves_no_tag_metadata() {
    let f = fx(false, false).await;
    pull_while_manifest_delete_held(&f, TAG_MANIFEST, "v1", "v1", TAG_META).await;
}

/// upstream namespace + local storage (legacy arm deletes the hosted manifest).
#[tokio::test]
async fn a_pull_during_a_legacy_key_delete_leaves_no_metadata() {
    let f = fx(true, true).await;
    pull_while_manifest_delete_held(&f, TAG_MANIFEST, "v1", "v1", TAG_META).await;
}

/// delete by digest drops the tag (delete_tags_for_digest) while a tag pull is served.
#[tokio::test]
async fn a_tag_pull_during_a_digest_delete_leaves_no_tag_metadata() {
    let f = fx(false, false).await;
    let d = f.digest.clone();
    pull_while_manifest_delete_held(&f, TAG_MANIFEST, "v1", &d, TAG_META).await;
}

/// delete by tag drops the digest copy while a digest pull is served.
#[tokio::test]
async fn a_digest_pull_during_a_tag_delete_leaves_no_digest_metadata() {
    let f = fx(false, false).await;
    let d = f.digest.clone();
    let dm = format!("docker/race-img/manifests/{d}.json");
    let dmeta = format!("docker/race-img/manifests/{d}.meta.json");
    pull_while_manifest_delete_held(&f, &dm, &d, "v1", &dmeta).await;
}

// ---- pull-stats sidecar: regression fixtures ----

/// (M1, M2): a FLUSH must not rewrite .meta.json either — not to mirror
/// the counts, not to clear migrated legacy counts.
#[tokio::test]
async fn flush_never_rewrites_the_meta_json() {
    let f = fx(false, true).await;
    let mut m: super::ImageMetadata =
        serde_json::from_slice(&f.state.storage.get(TAG_META).await.unwrap()).unwrap();
    m.downloads = 5;
    m.last_pulled = 1_000;
    f.state
        .storage
        .put(TAG_META, &serde_json::to_vec(&m).unwrap())
        .await
        .unwrap();
    let before = f.state.storage.get(TAG_META).await.unwrap();
    for _ in 0..2 {
        pull(&f.state, "v1").await;
        super::flush_pull_stats(&f.state).await;
    }
    assert_eq!(
        downloads(&f.state, TAG_META).await,
        Some(7),
        "control: the flush ran and migrated"
    );
    assert_eq!(
        f.state.storage.get(TAG_META).await.unwrap(),
        before,
        "a flush rewrote .meta.json"
    );
}

/// the flush's existence answer is held; a whole delete runs; on
/// release the flush must not resurrect the deleted manifest's stats sidecar.
#[tokio::test(start_paused = true)]
async fn delete_while_the_flush_check_is_held_leaves_no_stats() {
    let f = fx(false, true).await;
    pull(&f.state, "v1").await;
    f.held.arm(STAT, TAG_MANIFEST);
    let flush = {
        let st = f.state.clone();
        tokio::spawn(async move { super::flush_pull_stats(&st).await })
    };
    reached(&f.held.reached, "flush existence check not reached").await;
    let del = tokio::spawn(delete(f.state.clone(), "v1".into()));
    tokio::time::sleep(Duration::from_millis(300)).await;
    f.held.release.notify_one();
    finishes(flush, "flush hung").await;
    assert_eq!(finishes(del, "delete hung").await, StatusCode::ACCEPTED);
    assert!(f.state.storage.stat(TAG_MANIFEST).await.is_none());
    assert!(
        f.state
            .storage
            .stat(&super::manifest_stats_key(TAG_META))
            .await
            .is_none(),
        "the flush resurrected the deleted manifest's stats sidecar"
    );
}

/// a delete removes an ALREADY-FLUSHED sidecar; a re-push of the
/// same tag starts from zero, not from the deleted manifest's count.
#[tokio::test]
async fn delete_drops_the_flushed_stats_sidecar() {
    let f = fx(false, true).await;
    pull(&f.state, "v1").await;
    super::flush_pull_stats(&f.state).await;
    let sk = super::manifest_stats_key(TAG_META);
    assert!(
        f.state.storage.stat(&sk).await.is_some(),
        "control: flushed"
    );
    assert_eq!(
        delete(f.state.clone(), "v1".into()).await,
        StatusCode::ACCEPTED
    );
    assert!(
        f.state.storage.stat(&sk).await.is_none(),
        "the deleted manifest's stats sidecar survived the delete"
    );
    assert_eq!(
        push(f.state.clone(), f.manifest.clone()).await,
        StatusCode::CREATED
    );
    assert_eq!(downloads(&f.state, TAG_META).await, Some(0));
}

/// A delete that lands before a flush leaves no metadata and no stats sidecar:
/// the flush re-checks the manifest under the publish lock and skips a gone
/// one. This is the SEQUENTIAL case; the concurrent race — the flush's
/// existence answer held across a whole delete — is covered by
/// `delete_while_the_flush_check_is_held_leaves_no_stats`.
#[tokio::test]
async fn a_delete_between_the_stats_check_and_its_write_leaves_no_metadata() {
    let f = fx(false, false).await;
    // V3: the pull records in-memory; the flush's existence check and its
    // sidecar write are both under the per-key publish lock (a delete takes the
    // same lock), so a delete cannot slip between the check and the write. After
    // a delete, a flush resurrects neither the metadata nor the stats sidecar.
    pull(&f.state, "v1").await;
    assert_eq!(
        delete(f.state.clone(), "v1".into()).await,
        StatusCode::ACCEPTED
    );
    super::flush_pull_stats(&f.state).await;
    assert!(f.state.storage.stat(TAG_MANIFEST).await.is_none());
    assert!(
        f.state.storage.stat(TAG_META).await.is_none(),
        "the deleted manifest's metadata was created after the delete"
    );
    assert!(
        f.state
            .storage
            .stat(&super::manifest_stats_key(TAG_META))
            .await
            .is_none(),
        "the deleted manifest's stats sidecar was created after the delete"
    );
}

/// lock order manifest -> metadata. Pull stats hold the metadata lock; a re-push and a
/// delete of the same tag queue up; both must finish once the pull's write is released.
#[tokio::test]
async fn push_and_delete_during_a_pull_do_not_deadlock() {
    let f = fx(false, false).await;
    // V3: the pull records in-memory; the flush, a re-push, and a delete all
    // take the per-key publish lock, so they serialize without a lock-order
    // deadlock. Run them concurrently and require all three to finish.
    pull(&f.state, "v1").await;
    let flush = {
        let st = f.state.clone();
        tokio::spawn(async move { super::flush_pull_stats(&st).await })
    };
    let rp = tokio::spawn(push(f.state.clone(), f.manifest.clone()));
    let del = tokio::spawn(delete(f.state.clone(), "v1".into()));
    finishes(flush, "flush hung (lock-order deadlock)").await;
    assert_eq!(
        finishes(rp, "re-push hung (lock-order deadlock)").await,
        StatusCode::CREATED
    );
    assert_eq!(
        finishes(del, "delete hung (lock-order deadlock)").await,
        StatusCode::ACCEPTED
    );
}

/// the pull's statistics take only the metadata lock — a pull during a re-push (held at
/// its manifest write) must not leave the push waiting forever.
#[tokio::test(start_paused = true)]
async fn a_pull_during_a_re_push_does_not_deadlock() {
    let f = fx(false, false).await;
    f.held.arm(PUT, TAG_MANIFEST);
    let rp = tokio::spawn(push(f.state.clone(), f.manifest.clone()));
    reached(&f.held.reached, "re-push manifest write not reached").await;
    pull(&f.state, "v1").await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    f.held.release.notify_one();
    assert_eq!(
        finishes(rp, "re-push hung (lock-order deadlock)").await,
        StatusCode::CREATED
    );
}

/// a push writes all of its metadata while it still holds the manifest lock — a delete
/// that arrives mid-push runs after it, and leaves no metadata of the deleted manifest.
#[tokio::test(start_paused = true)]
async fn a_delete_during_a_push_leaves_no_metadata() {
    let f = fx(false, false).await;
    let dm = format!("docker/race-img/manifests/{}.json", f.digest);
    let dmeta = format!("docker/race-img/manifests/{}.meta.json", f.digest);
    f.held.arm(PUT, TAG_META);
    let rp = tokio::spawn(push(f.state.clone(), f.manifest.clone()));
    reached(&f.held.reached, "push metadata write not reached").await;
    let del = tokio::spawn(delete(f.state.clone(), "v1".into()));
    tokio::time::sleep(Duration::from_millis(300)).await;
    f.held.release.notify_one();
    assert_eq!(finishes(rp, "push hung").await, StatusCode::CREATED);
    assert_eq!(finishes(del, "delete hung").await, StatusCode::ACCEPTED);
    tokio::time::sleep(Duration::from_millis(100)).await;
    for (m, meta) in [(TAG_MANIFEST, TAG_META), (dm.as_str(), dmeta.as_str())] {
        if f.state.storage.stat(m).await.is_none() {
            assert!(
                f.state.storage.stat(meta).await.is_none(),
                "metadata {meta} outlived its deleted manifest"
            );
        }
    }
}
