// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::{first_seen_key, FirstSeen};
use crate::registry::{write_validators, Validators};
use crate::storage::Storage;
use crate::test_helpers::{
    body_bytes, create_test_context_with_storage_and_config, send, TestContext,
};
use axum::http::{Method, StatusCode};
use std::time::{Duration, SystemTime};
use wiremock::matchers::{header_exists, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Where 1.4.0 caches the upstream packument; `LEGACY` is where an older release did.
const KEY: &str = "npm/agepkg/upstream/packument.json";
const LEGACY: &str = "npm/agepkg/metadata.json";
const HOUR: i64 = 3600;

/// Where a test keeps its packages: a directory whose file times it can set, or an
/// in-process object store (the S3 code path), whose times it cannot.
enum Backend {
    Local(tempfile::TempDir),
    Object,
}

impl Backend {
    fn both() -> [Backend; 2] {
        [
            Backend::Local(tempfile::tempdir().unwrap()),
            Backend::Object,
        ]
    }

    fn storage(&self) -> Storage {
        match self {
            Backend::Local(dir) => Storage::new_local(dir.path().to_str().unwrap()),
            Backend::Object => Storage::from_backend(std::sync::Arc::new(
                crate::storage::ObjectStorage::in_memory(),
            )),
        }
    }

    /// The storage as a restarted process opens it: the directory anew, or the same bucket.
    fn reopen(&self, storage: &Storage) -> Storage {
        match self {
            Backend::Local(_) => self.storage(),
            Backend::Object => storage.clone(),
        }
    }

    /// Set the packument's file time `secs` into the past (local backend only).
    fn age_packument(&self, secs: i64) {
        if let Backend::Local(dir) = self {
            std::fs::File::options()
                .write(true)
                .open(dir.path().join(KEY))
                .unwrap()
                .set_modified(SystemTime::now() - Duration::from_secs(secs as u64))
                .unwrap();
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Backend::Local(_) => "local",
            Backend::Object => "object store",
        }
    }
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn packument(upstream: &str, versions: &[&str]) -> String {
    let versions: serde_json::Map<String, serde_json::Value> = versions
        .iter()
        .map(|v| {
            let tarball = format!("{upstream}/agepkg/-/agepkg-{v}.tgz");
            (
                v.to_string(),
                serde_json::json!({ "name": "agepkg", "version": v, "dist": { "tarball": tarball } }),
            )
        })
        .collect();
    serde_json::json!({ "name": "agepkg", "versions": versions }).to_string()
}

/// The upstream lists `versions`; with `not_modified` it answers only a conditional
/// request, with 304 — a full fetch finds nothing, so the 304 path is the one taken.
async fn upstream(versions: &[&str], not_modified: bool) -> MockServer {
    let server = MockServer::start().await;
    let listing = if not_modified {
        Mock::given(method("GET"))
            .and(path("/agepkg"))
            .and(header_exists("if-none-match"))
            .respond_with(ResponseTemplate::new(304))
    } else {
        Mock::given(method("GET"))
            .and(path("/agepkg"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"v2\"")
                    .set_body_string(packument(&server.uri(), versions)),
            )
    };
    listing.mount(&server).await;
    Mock::given(method("GET"))
        .and(path_regex("^/agepkg/-/"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"TGZ".to_vec()))
        .mount(&server)
        .await;
    server
}

/// The field configuration: 3 days globally and 1 hour for npm, the quarantine
/// observing, upstream dates not trusted. TTL 0 makes every packument request a refetch.
fn context(upstream: &MockServer, storage: Storage) -> TestContext {
    let uri = upstream.uri();
    create_test_context_with_storage_and_config(storage, move |cfg| {
        cfg.npm.proxy = Some(uri);
        cfg.npm.metadata_ttl = 0;
        cfg.npm.revalidate = true;
        cfg.server.trust_upstream_dates = false;
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.min_release_age = Some("3d".to_string());
        cfg.curation.npm.min_release_age = Some("1h".to_string());
        cfg.curation.quarantine = Some(crate::digest_quarantine::QuarantineMode::Observe);
    })
}

/// The cache as NORA left it two hours ago: the packument listing 1.0.0 with its
/// validators, and 1.0.0 first seen then.
async fn seen_two_hours_ago(backend: &Backend, storage: &Storage, upstream: &MockServer) {
    storage
        .put(KEY, packument(&upstream.uri(), &["1.0.0"]).as_bytes())
        .await
        .unwrap();
    write_validators(
        storage,
        KEY,
        &Validators {
            etag: Some("\"v1\"".to_string()),
            last_modified: None,
        },
    )
    .await;
    let ledger: FirstSeen = [("1.0.0".to_string(), now() - 2 * HOUR)].into();
    storage
        .put(&first_seen_key(KEY), &serde_json::to_vec(&ledger).unwrap())
        .await
        .unwrap();
    backend.age_packument(2 * HOUR);
}

/// Ask for the packument and wait until the refetch has rewritten it — the write that
/// used to reset the age.
async fn refetch(ctx: &TestContext, storage: &Storage) {
    let resp = send(&ctx.app, Method::GET, "/npm/agepkg", "").await;
    assert_eq!(resp.status(), StatusCode::OK, "packument");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while storage
        .stat(KEY)
        .await
        .is_none_or(|m| now() - (m.modified as i64) >= 60)
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the refetch never rewrote the packument"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn tarball(ctx: &TestContext, version: &str) -> (StatusCode, String) {
    let uri = format!("/npm/agepkg/-/agepkg-{version}.tgz");
    let resp = send(&ctx.app, Method::GET, &uri, "").await;
    let status = resp.status();
    let body = String::from_utf8_lossy(&body_bytes(resp).await).into_owned();
    (status, body)
}

async fn a_refetch_keeps_the_age(not_modified: bool) {
    for backend in Backend::both() {
        let storage = backend.storage();
        let upstream = upstream(&["1.0.0"], not_modified).await;
        seen_two_hours_ago(&backend, &storage, &upstream).await;
        let ctx = context(&upstream, storage.clone());

        refetch(&ctx, &storage).await;

        let (status, body) = tarball(&ctx, "1.0.0").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{}: seen 2h ago, minimum 1h — {body}",
            backend.name()
        );
    }
}

#[tokio::test]
async fn a_200_refetch_does_not_make_a_release_younger() {
    a_refetch_keeps_the_age(false).await;
}

#[tokio::test]
async fn a_304_refetch_does_not_make_a_release_younger() {
    a_refetch_keeps_the_age(true).await;
}

#[tokio::test]
async fn a_version_the_refetch_adds_starts_at_zero() {
    for backend in Backend::both() {
        let storage = backend.storage();
        let upstream = upstream(&["1.0.0", "2.0.0"], false).await;
        seen_two_hours_ago(&backend, &storage, &upstream).await;
        let ctx = context(&upstream, storage.clone());

        refetch(&ctx, &storage).await;
        // Its age is its own, not the packument file's: an old file time changes nothing.
        backend.age_packument(3 * HOUR);

        let (status, body) = tarball(&ctx, "2.0.0").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{}: {body}", backend.name());
        assert!(body.contains("0h old"), "{}: {body}", backend.name());
        let (status, body) = tarball(&ctx, "1.0.0").await;
        assert_eq!(status, StatusCode::OK, "{}: {body}", backend.name());
    }
}

/// A ledger whose bytes no longer match their pin is rewritten at the next refetch, so it
/// is read again and records new versions; its releases start young, which holds more.
#[tokio::test]
async fn a_ledger_that_fails_its_pin_is_rewritten() {
    let backend = Backend::Local(tempfile::tempdir().unwrap());
    let Backend::Local(dir) = &backend else {
        unreachable!()
    };
    let storage = backend.storage();
    let upstream = upstream(&["1.0.0", "2.0.0"], false).await;
    seen_two_hours_ago(&backend, &storage, &upstream).await;
    let on_disk = dir.path().join(first_seen_key(KEY));
    let mut bytes = std::fs::read(&on_disk).unwrap();
    bytes.push(b' ');
    std::fs::write(&on_disk, &bytes).unwrap();
    assert!(storage.get(&first_seen_key(KEY)).await.is_err(), "tampered");
    let ctx = context(&upstream, storage.clone());

    refetch(&ctx, &storage).await;
    let ledger: FirstSeen =
        serde_json::from_slice(&storage.get(&first_seen_key(KEY)).await.unwrap()).unwrap();
    assert!(
        ledger.contains_key("1.0.0") && ledger.contains_key("2.0.0"),
        "{ledger:?}"
    );
    assert!(
        ledger.values().all(|t| now() - t < 60),
        "started again: {ledger:?}"
    );
}

#[tokio::test]
async fn the_age_survives_a_restart() {
    for backend in Backend::both() {
        let storage = backend.storage();
        let upstream = upstream(&["1.0.0", "2.0.0"], false).await;
        seen_two_hours_ago(&backend, &storage, &upstream).await;
        let first = context(&upstream, storage.clone());
        refetch(&first, &storage).await;
        drop(first);

        // A new process over the same storage; the packument was just rewritten.
        let ctx = context(&upstream, backend.reopen(&storage));
        let (status, body) = tarball(&ctx, "1.0.0").await;
        assert_eq!(status, StatusCode::OK, "{}: {body}", backend.name());
        let (status, body) = tarball(&ctx, "2.0.0").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{}: {body}", backend.name());
    }
}

/// A version no packument NORA fetched has listed has no first-seen time, and the
/// ledger gives it none: never the cached packument's age. Without a trusted date
/// min-release-age defers to the digest quarantine (C49), as for any undated release.
#[tokio::test]
async fn an_unlisted_version_is_no_older_than_the_cache() {
    for backend in Backend::both() {
        let storage = backend.storage();
        let upstream = upstream(&["1.0.0"], false).await;
        seen_two_hours_ago(&backend, &storage, &upstream).await;
        let ctx = context(&upstream, storage.clone());

        refetch(&ctx, &storage).await;

        assert_eq!(
            super::first_seen_date(&storage, KEY, "3.0.0").await,
            None,
            "{}",
            backend.name()
        );
        let (_, body) = tarball(&ctx, "3.0.0").await;
        assert!(!body.contains("old"), "{}: dated: {body}", backend.name());
    }
}

/// A packument cached before NORA kept first-seen times: the versions it already
/// listed start at its file time — when NORA last wrote it — and a version only the
/// refetch brings starts at zero.
async fn a_cache_from_before_the_ledger(not_modified: bool) {
    let backend = Backend::Local(tempfile::tempdir().unwrap());
    let storage = backend.storage();
    let upstream = upstream(&["1.0.0", "2.0.0"], not_modified).await;
    storage
        .put(KEY, packument(&upstream.uri(), &["1.0.0"]).as_bytes())
        .await
        .unwrap();
    write_validators(
        &storage,
        KEY,
        &Validators {
            etag: Some("\"v1\"".to_string()),
            last_modified: None,
        },
    )
    .await;
    backend.age_packument(2 * HOUR);
    let ctx = context(&upstream, storage.clone());

    refetch(&ctx, &storage).await;

    let (status, body) = tarball(&ctx, "1.0.0").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    if !not_modified {
        let (status, body) = tarball(&ctx, "2.0.0").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }
}

#[tokio::test]
async fn a_cache_from_before_the_ledger_keeps_its_age_on_200() {
    a_cache_from_before_the_ledger(false).await;
}

/// A packument an older release cached (at the old key, with no ledger): its versions keep
/// its file time, a version only the refetch brings starts at zero, and the old copy is
/// left byte for byte, so a rollback still reads it.
#[tokio::test]
async fn a_cache_from_an_older_release_keeps_its_age_and_is_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let storage = Storage::new_local(dir.path().to_str().unwrap());
    let upstream = upstream(&["1.0.0", "2.0.0"], false).await;
    let old = packument(&upstream.uri(), &["1.0.0"]);
    storage.put(LEGACY, old.as_bytes()).await.unwrap();
    std::fs::File::options()
        .write(true)
        .open(dir.path().join(LEGACY))
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(2 * HOUR as u64))
        .unwrap();
    let ctx = context(&upstream, storage.clone());

    refetch(&ctx, &storage).await;

    let (status, body) = tarball(&ctx, "1.0.0").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = tarball(&ctx, "2.0.0").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        storage.get(LEGACY).await.unwrap(),
        old.as_bytes(),
        "left alone"
    );
}

#[tokio::test]
async fn a_cache_from_before_the_ledger_keeps_its_age_on_304() {
    a_cache_from_before_the_ledger(true).await;
}

/// The first fetch of a packument starts every version it lists now, and the ledger
/// stays outside the npm key space that listings, retention and GC walk.
#[tokio::test]
async fn a_first_fetch_starts_every_version_at_zero() {
    for backend in Backend::both() {
        let storage = backend.storage();
        let upstream = upstream(&["1.0.0"], false).await;
        let ctx = context(&upstream, storage.clone());

        refetch(&ctx, &storage).await;
        backend.age_packument(3 * HOUR);

        let (status, body) = tarball(&ctx, "1.0.0").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{}: {body}", backend.name());
        assert!(body.contains("0h old"), "{}: {body}", backend.name());
        assert_eq!(
            storage
                .list_internal(super::FIRST_SEEN_PREFIX)
                .await
                .unwrap(),
            vec![first_seen_key(KEY)],
            "{}",
            backend.name()
        );
        assert!(first_seen_key(KEY).starts_with(".nora-"));
    }
}

/// Concurrent fetches of one packument each add what they saw: the read-modify-write
/// of the ledger is serialized, so no version is lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_records_lose_no_version() {
    let backend = Backend::Local(tempfile::tempdir().unwrap());
    let storage = backend.storage();
    let upstream = upstream(&[], false).await;
    let ctx = context(&upstream, storage.clone());
    let mut records = tokio::task::JoinSet::new();
    for i in 0..16 {
        let state = ctx.state.clone();
        let body = packument(&upstream.uri(), &[format!("1.0.{i}").as_str()]);
        records.spawn(async move {
            super::record_first_seen(&state, KEY, body.as_bytes(), None).await;
        });
    }
    while let Some(done) = records.join_next().await {
        done.unwrap();
    }
    let ledger: FirstSeen =
        serde_json::from_slice(&storage.get(&first_seen_key(KEY)).await.unwrap()).unwrap();
    assert_eq!(ledger.len(), 16, "{ledger:?}");
}

/// Nothing is kept where nothing reads it: with curation off, or with trusted
/// upstream dates, a packument fetch writes no first-seen ledger.
#[tokio::test]
async fn no_ledger_without_untrusted_curation() {
    for (curation, trust) in [(false, false), (true, true)] {
        let backend = Backend::Object;
        let storage = backend.storage();
        let upstream = upstream(&["1.0.0"], false).await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_storage_and_config(storage.clone(), move |cfg| {
            cfg.npm.proxy = Some(uri);
            cfg.server.trust_upstream_dates = trust;
            if curation {
                cfg.curation.mode = crate::config::CurationMode::Enforce;
                cfg.curation.min_release_age = Some("1h".to_string());
            }
        });
        let resp = send(&ctx.app, Method::GET, "/npm/agepkg", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            storage.get(&first_seen_key(KEY)).await.is_err(),
            "curation {curation}, trust {trust}"
        );
    }
}
