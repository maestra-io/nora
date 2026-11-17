// Copyright (c) 2026 The Nora Authors
// SPDX-License-Identifier: MIT

//! Two NORA processes over one bucket (audit A033): each "process" is its own
//! [`TestContext`], with its own publish locks and hosted index, over one shared object
//! store, as the old and the new pod of a rolling update are. The in-process lock does
//! not reach the other process; the store's conditional writes have to.
//!
//! [`Gate`] parks ONE storage call of process A, so process B runs in exactly the window
//! between A's read or check and its write.

use super::hosted::test_support::{multipart, nupkg, nupkg_with_payload};
use crate::storage::{FileMeta, ObjectStorage, StorageBackend};
use crate::test_helpers::{
    body_bytes, create_test_context_with_storage_and_config, send, send_with_headers, TestContext,
};
use axum::body::Bytes;
use axum::http::{Method, StatusCode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Parks the first call of kind `op` on a key containing `needle` until [`Gate::open`].
struct Gate {
    inner: Arc<dyn StorageBackend>,
    op: &'static str,
    needle: String,
    armed: AtomicBool,
    reached: tokio::sync::Semaphore,
    release: tokio::sync::Semaphore,
}

impl Gate {
    async fn hit(&self, op: &str, key: &str) {
        if op == self.op && key.contains(&self.needle) && self.armed.swap(false, Ordering::SeqCst) {
            self.reached.add_permits(1);
            self.release.acquire().await.unwrap().forget();
        }
    }

    async fn wait_reached(&self) {
        tokio::time::timeout(Duration::from_secs(20), self.reached.acquire())
            .await
            .expect("process A never reached the gated storage call")
            .unwrap()
            .forget();
    }

    fn open(&self) {
        self.release.add_permits(1);
    }
}

#[async_trait::async_trait]
impl StorageBackend for Gate {
    async fn put(&self, key: &str, data: &[u8], sha256: &str) -> crate::storage::Result<()> {
        self.hit("put", key).await;
        self.inner.put(key, data, sha256).await
    }
    async fn put_bytes(&self, key: &str, data: Bytes, sha256: &str) -> crate::storage::Result<()> {
        self.hit("put", key).await;
        self.inner.put_bytes(key, data, sha256).await
    }
    async fn put_if_absent(
        &self,
        key: &str,
        data: Bytes,
        sha256: &str,
    ) -> crate::storage::Result<bool> {
        self.hit("put", key).await;
        self.inner.put_if_absent(key, data, sha256).await
    }
    async fn put_if_version(
        &self,
        key: &str,
        data: Bytes,
        sha256: &str,
        expected: Option<&str>,
    ) -> crate::storage::Result<bool> {
        self.hit("put", key).await;
        self.inner.put_if_version(key, data, sha256, expected).await
    }
    async fn get(&self, key: &str) -> crate::storage::Result<(Bytes, Option<String>)> {
        self.inner.get(key).await
    }
    async fn get_versioned(
        &self,
        key: &str,
    ) -> crate::storage::Result<(Bytes, Option<String>, String)> {
        self.inner.get_versioned(key).await
    }
    async fn pin(&self, key: &str) -> Option<String> {
        self.inner.pin(key).await
    }
    async fn delete(&self, key: &str) -> crate::storage::Result<()> {
        self.inner.delete(key).await
    }
    async fn list(&self, prefix: &str) -> crate::storage::Result<Vec<String>> {
        self.inner.list(prefix).await
    }
    async fn stat(&self, key: &str) -> Option<FileMeta> {
        self.inner.stat(key).await
    }
    async fn list_with_meta(
        &self,
        prefix: &str,
    ) -> crate::storage::Result<Vec<(String, FileMeta)>> {
        self.inner.list_with_meta(prefix).await
    }
    async fn health_check(&self) -> bool {
        true
    }
    async fn total_size(&self) -> u64 {
        0
    }
    fn backend_name(&self) -> &'static str {
        "gate"
    }
    async fn put_from_path(
        &self,
        key: &str,
        src: &std::path::Path,
        sha256: Option<&str>,
    ) -> crate::storage::Result<()> {
        self.hit("put_from_path", key).await;
        self.inner.put_from_path(key, src, sha256).await
    }
    async fn put_from_path_if_absent(
        &self,
        key: &str,
        src: &std::path::Path,
        sha256: &str,
    ) -> crate::storage::Result<bool> {
        self.hit("put_from_path", key).await;
        self.inner.put_from_path_if_absent(key, src, sha256).await
    }
    async fn copy(&self, src: &str, dst: &str, sha256: Option<&str>) -> crate::storage::Result<()> {
        self.inner.copy(src, dst, sha256).await
    }
    async fn get_reader(
        &self,
        key: &str,
    ) -> crate::storage::Result<(
        u64,
        Option<String>,
        std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
    )> {
        self.inner.get_reader(key).await
    }
}

fn bucket() -> Arc<dyn StorageBackend> {
    Arc::new(ObjectStorage::in_memory())
}

fn nuget_cfg(cfg: &mut crate::config::Config) {
    cfg.nuget.enabled = true;
    cfg.nuget.proxy = None;
}

/// One more process over `bucket`.
fn process(bucket: &Arc<dyn StorageBackend>) -> TestContext {
    create_test_context_with_storage_and_config(
        crate::Storage::from_backend(Arc::clone(bucket)),
        nuget_cfg,
    )
}

/// A process whose first `op` on a key containing `needle` parks.
fn gated_process(
    bucket: &Arc<dyn StorageBackend>,
    op: &'static str,
    needle: &str,
) -> (TestContext, Arc<Gate>) {
    let gate = Arc::new(Gate {
        inner: Arc::clone(bucket),
        op,
        needle: needle.to_string(),
        armed: AtomicBool::new(true),
        reached: tokio::sync::Semaphore::new(0),
        release: tokio::sync::Semaphore::new(0),
    });
    let ctx = create_test_context_with_storage_and_config(
        crate::Storage::from_backend(gate.clone()),
        nuget_cfg,
    );
    (ctx, gate)
}

async fn push(app: &axum::Router, pkg: &[u8]) -> StatusCode {
    let (ct, body) = multipart(pkg);
    send_with_headers(
        app,
        Method::PUT,
        "/nuget/v3/package/",
        vec![("content-type", ct.as_str())],
        body,
    )
    .await
    .status()
}

async fn get(app: &axum::Router, uri: &str) -> (StatusCode, Bytes) {
    let resp = send(app, Method::GET, uri, "").await;
    let status = resp.status();
    let gz = resp.headers().get("content-encoding").is_some();
    let raw = body_bytes(resp).await;
    if !gz {
        return (status, raw);
    }
    let mut out = Vec::new();
    std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&raw[..]), &mut out).unwrap();
    (status, Bytes::from(out))
}

async fn versions(app: &axum::Router, id_lower: &str) -> serde_json::Value {
    let uri = format!("/nuget/v3/flatcontainer/{id_lower}/index.json");
    let (status, body) = get(app, &uri).await;
    assert_eq!(status, StatusCode::OK, "{uri}");
    serde_json::from_slice::<serde_json::Value>(&body).unwrap()["versions"].clone()
}

/// T1: one id@version, other bytes, one push through each process, both in flight. One
/// is stored, the other is a 409, and the version keeps the bytes first stored.
#[tokio::test]
async fn one_version_pushed_through_two_processes_keeps_the_first_bytes() {
    let bucket = bucket();
    let (a, gate) = gated_process(&bucket, "put_from_path", ".nupkg");
    let b = process(&bucket);
    let pkg_a = nupkg_with_payload("Maestra.Race", "1.0.0", "", "pushed through A");
    let pkg_b = nupkg_with_payload("Maestra.Race", "1.0.0", "", "pushed through B");
    let url = "/nuget/v3/flatcontainer/maestra.race/1.0.0/maestra.race.1.0.0.nupkg";

    let app_a = a.app.clone();
    let pa = pkg_a.clone();
    let push_a = tokio::spawn(async move { push(&app_a, &pa).await });
    gate.wait_reached().await; // A checked "version exists?" and wrote nothing yet
    assert_eq!(push(&b.app, &pkg_b).await, StatusCode::CREATED);
    gate.open();
    assert_eq!(push_a.await.unwrap(), StatusCode::CONFLICT);

    let c = process(&bucket);
    let (status, served) = get(&c.app, url).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        &served[..],
        &pkg_b[..],
        "a published version changed its bytes"
    );
    assert_eq!(
        versions(&c.app, "maestra.race").await,
        serde_json::json!(["1.0.0"])
    );
}

/// T1b: the same push (same bytes) through both processes at once: both succeed.
#[tokio::test]
async fn the_same_bytes_pushed_through_two_processes_both_succeed() {
    let bucket = bucket();
    let (a, gate) = gated_process(&bucket, "put_from_path", ".nupkg");
    let b = process(&bucket);
    let pkg = nupkg("Maestra.Twice", "1.0.0", "");

    let app_a = a.app.clone();
    let p = pkg.clone();
    let push_a = tokio::spawn(async move { push(&app_a, &p).await });
    gate.wait_reached().await;
    assert_eq!(push(&b.app, &pkg).await, StatusCode::CREATED);
    gate.open();
    assert_eq!(push_a.await.unwrap(), StatusCode::OK, "an identical push");

    let c = process(&bucket);
    let url = "/nuget/v3/flatcontainer/maestra.twice/1.0.0/maestra.twice.1.0.0.nupkg";
    assert_eq!(&get(&c.app, url).await.1[..], &pkg[..]);
    assert_eq!(
        versions(&c.app, "maestra.twice").await,
        serde_json::json!(["1.0.0"])
    );
}

/// T2: two versions of one ID, one through each process, A's document write landing
/// after B's: the document names both, for a process started later.
#[tokio::test]
async fn two_versions_pushed_through_two_processes_are_both_listed() {
    let bucket = bucket();
    let (a, gate) = gated_process(&bucket, "put", "nuget/hosted-meta/maestra.lost.json");
    let b = process(&bucket);

    let app_a = a.app.clone();
    let push_a =
        tokio::spawn(async move { push(&app_a, &nupkg("Maestra.Lost", "1.0.0", "")).await });
    gate.wait_reached().await; // A read the document and is about to write it
    assert_eq!(
        push(&b.app, &nupkg("Maestra.Lost", "2.0.0", "")).await,
        StatusCode::CREATED
    );
    gate.open();
    assert_eq!(push_a.await.unwrap(), StatusCode::CREATED);

    let c = process(&bucket);
    assert_eq!(
        versions(&c.app, "maestra.lost").await,
        serde_json::json!(["1.0.0", "2.0.0"])
    );
    let url = "/nuget/v3/flatcontainer/maestra.lost/2.0.0/maestra.lost.2.0.0.nupkg";
    assert_eq!(get(&c.app, url).await.0, StatusCode::OK);
}

/// T3: the retention pass of one process (a new pod's boot pass) rewrites a document
/// while the other process (the old pod) pushes a version into it: the version stays.
#[tokio::test]
async fn retention_in_one_process_keeps_a_push_through_the_other() {
    let bucket = bucket();
    // 21 PR pre-releases older than hosted_pr_retention_days (30): one expires
    // (hosted_pr_keep_last = 20), so the pass rewrites the document.
    let old: Vec<serde_json::Value> = (1..=21)
        .map(|n| {
            serde_json::json!({ "version": format!("1.0.0-pr.{n}"), "listed": true,
                "published": "2025-01-01T00:00:00Z", "semver2": true })
        })
        .collect();
    let doc =
        serde_json::to_vec(&serde_json::json!({ "id": "Maestra.Ret", "versions": old })).unwrap();
    let key = "nuget/hosted-meta/maestra.ret.json";
    let sha = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&doc));
    bucket.put(key, &doc, &sha).await.unwrap();

    let (a, gate) = gated_process(&bucket, "put", key);
    let b = process(&bucket);
    let state_a = a.state.clone();
    let pass = tokio::spawn(async move { super::hosted::run_retention(&state_a, false).await });
    gate.wait_reached().await; // the pass read the document and is about to write it back
    assert_eq!(
        push(&b.app, &nupkg("Maestra.Ret", "5.0.0", "")).await,
        StatusCode::CREATED
    );
    gate.open();
    let summary = pass.await.unwrap();
    assert_eq!((summary.expired, summary.errors), (1, 0), "{summary:?}");

    let c = process(&bucket);
    let listed = versions(&c.app, "maestra.ret").await;
    let listed: Vec<&str> = listed
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(listed.contains(&"5.0.0"), "{listed:?}");
    assert!(!listed.contains(&"1.0.0-pr.1"), "{listed:?}");
    assert_eq!(listed.len(), 21, "{listed:?}");
    let url = "/nuget/v3/flatcontainer/maestra.ret/5.0.0/maestra.ret.5.0.0.nupkg";
    assert_eq!(get(&c.app, url).await.0, StatusCode::OK);
}

/// T4: an unlist through one process while the other pushes a new version: both land.
#[tokio::test]
async fn an_unlist_in_one_process_keeps_a_push_through_the_other() {
    let bucket = bucket();
    let seed = process(&bucket);
    assert_eq!(
        push(&seed.app, &nupkg("Maestra.Unl", "1.0.0", "")).await,
        StatusCode::CREATED
    );
    let (a, gate) = gated_process(&bucket, "put", "nuget/hosted-meta/maestra.unl.json");
    let b = process(&bucket);
    let app_a = a.app.clone();
    let unlist = tokio::spawn(async move {
        send(
            &app_a,
            Method::DELETE,
            "/nuget/v3/package/Maestra.Unl/1.0.0",
            "",
        )
        .await
        .status()
    });
    gate.wait_reached().await;
    assert_eq!(
        push(&b.app, &nupkg("Maestra.Unl", "2.0.0", "")).await,
        StatusCode::CREATED
    );
    gate.open();
    assert_eq!(unlist.await.unwrap(), StatusCode::NO_CONTENT);

    let c = process(&bucket);
    let (_, body) = get(&c.app, "/nuget/v3/registration/maestra.unl/1.0.0.json").await;
    let leaf: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(leaf["catalogEntry"]["listed"], false, "{leaf}");
    assert_eq!(
        versions(&c.app, "maestra.unl").await,
        serde_json::json!(["1.0.0", "2.0.0"])
    );
}
