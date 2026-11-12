// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::{classify_metadata_path, put_with_origin, MetadataPath};
use crate::test_helpers::{body_bytes, create_test_context_with_config, send, TestContext};
use axum::http::{Method, StatusCode};
use std::time::Duration;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn doc(name: &str, versions: &[&str]) -> serde_json::Value {
    let versions: serde_json::Map<String, serde_json::Value> = versions
        .iter()
        .map(|v| {
            (
                v.to_string(),
                serde_json::json!({ "name": name, "version": v, "dist": {} }),
            )
        })
        .collect();
    let latest = versions.keys().next_back().cloned().unwrap_or_default();
    serde_json::json!({ "name": name, "dist-tags": { "latest": latest }, "versions": versions })
}

/// An upstream that serves `versions` of `name` (packument and version manifests) to
/// anyone who asks: a squatter on a published name.
async fn upstream(name: &str, versions: &[&str]) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/{name}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(doc(name, versions)))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(format!("^/{name}/[^-]")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "name": name, "version": "9.9.9" })),
        )
        .mount(&server)
        .await;
    server
}

async fn asked(server: &MockServer, name: &str) -> usize {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().starts_with(&format!("/{name}")) && !r.url.path().contains("/-/"))
        .count()
}

fn context(server: &MockServer, ttl: i64) -> TestContext {
    let uri = server.uri();
    create_test_context_with_config(move |cfg| {
        cfg.npm.proxy = Some(uri);
        cfg.npm.metadata_ttl = ttl;
        cfg.npm.revalidate = true;
    })
}

async fn publish(ctx: &TestContext, name: &str, version: &str) {
    use base64::Engine;
    let payload = serde_json::json!({
        "name": name,
        "versions": { version: { "name": name, "version": version, "dist": {} } },
        "dist-tags": { "latest": version },
        "_attachments": { format!("{name}-{version}.tgz"): {
            "data": base64::engine::general_purpose::STANDARD.encode(b"local-tarball"),
        } }
    });
    let resp = send(
        &ctx.app,
        Method::PUT,
        &format!("/npm/{name}"),
        axum::body::Body::from(serde_json::to_vec(&payload).unwrap()),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "publish {name}@{version}"
    );
}

async fn versions(ctx: &TestContext, uri: &str) -> Vec<String> {
    let resp = send(&ctx.app, Method::GET, uri, "").await;
    assert_eq!(resp.status(), StatusCode::OK, "{uri}");
    let doc: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    doc["versions"]
        .as_object()
        .map(|v| v.keys().cloned().collect())
        .unwrap_or_default()
}

async fn wait_for(ctx: &TestContext, key: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while ctx.state.storage.stat(key).await.is_none() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{key} never written"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

use crate::storage::{FileMeta, ObjectStorage, Storage, StorageBackend};

/// An object store whose `versions/` listing or published-packument writes fail on demand.
struct Faulty {
    inner: ObjectStorage,
    versions_listing_fails: bool,
    published_put_fails: bool,
    versions_listing_empty: bool,
}

#[async_trait::async_trait]
impl StorageBackend for Faulty {
    async fn get(&self, k: &str) -> crate::storage::Result<(axum::body::Bytes, Option<String>)> {
        self.inner.get(k).await
    }
    async fn put(&self, k: &str, d: &[u8], sha256: &str) -> crate::storage::Result<()> {
        if self.published_put_fails && k.ends_with("/metadata.json") {
            return Err(crate::storage::StorageError::Network("put failed".into()));
        }
        self.inner.put(k, d, sha256).await
    }
    async fn pin(&self, k: &str) -> Option<String> {
        self.inner.pin(k).await
    }
    async fn delete(&self, k: &str) -> crate::storage::Result<()> {
        self.inner.delete(k).await
    }
    async fn list(&self, prefix: &str) -> crate::storage::Result<Vec<String>> {
        if self.versions_listing_empty && prefix.ends_with("/versions/") {
            return Ok(Vec::new());
        }
        if self.versions_listing_fails && prefix.ends_with("/versions/") {
            return Err(crate::storage::StorageError::Network(
                "listing failed".into(),
            ));
        }
        self.inner.list(prefix).await
    }
    async fn list_with_meta(&self, p: &str) -> crate::storage::Result<Vec<(String, FileMeta)>> {
        self.inner.list_with_meta(p).await
    }
    async fn stat(&self, k: &str) -> Option<FileMeta> {
        self.inner.stat(k).await
    }
    async fn health_check(&self) -> bool {
        self.inner.health_check().await
    }
    async fn total_size(&self) -> u64 {
        self.inner.total_size().await
    }
    fn backend_name(&self) -> &'static str {
        "faulty-test-store"
    }
    async fn put_from_path(
        &self,
        k: &str,
        src: &std::path::Path,
        sha256: Option<&str>,
    ) -> crate::storage::Result<()> {
        self.inner.put_from_path(k, src, sha256).await
    }
    async fn copy(&self, s: &str, d: &str, sha256: Option<&str>) -> crate::storage::Result<()> {
        self.inner.copy(s, d, sha256).await
    }
    async fn get_reader(
        &self,
        k: &str,
    ) -> crate::storage::Result<(
        u64,
        Option<String>,
        std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
    )> {
        self.inner.get_reader(k).await
    }
}

fn faulty(versions_listing_fails: bool, published_put_fails: bool) -> Storage {
    Storage::from_backend(std::sync::Arc::new(Faulty {
        inner: ObjectStorage::in_memory(),
        versions_listing_fails,
        published_put_fails,
        versions_listing_empty: false,
    }))
}

/// A store whose `versions/` listing answers "nothing here" for files it holds, as a local
/// store did for a directory it could not read.
fn listing_lies() -> Storage {
    Storage::from_backend(std::sync::Arc::new(Faulty {
        inner: ObjectStorage::in_memory(),
        versions_listing_fails: false,
        published_put_fails: false,
        versions_listing_empty: true,
    }))
}

/// Seed a published package directly in the store, its packument as NORA assembles it.
async fn seed_published(storage: &Storage, name: &str) {
    storage
        .put(
            &format!("npm/{name}/versions/1.0.0.json"),
            serde_json::json!({ "name": name, "version": "1.0.0" })
                .to_string()
                .as_bytes(),
        )
        .await
        .unwrap();
    let own = doc(name, &["1.0.0"]);
    super::store_assembled_packument(storage, name, own.to_string().as_bytes())
        .await
        .unwrap();
}

#[test]
fn metadata_paths_name_their_package() {
    use MetadataPath::*;
    assert_eq!(classify_metadata_path("pkg"), Packument { name: "pkg" });
    assert_eq!(
        classify_metadata_path("@s/pkg"),
        Packument { name: "@s/pkg" }
    );
    assert_eq!(classify_metadata_path("-pkg"), Packument { name: "-pkg" });
    assert_eq!(
        classify_metadata_path("pkg/1.0.0"),
        VersionManifest {
            name: "pkg",
            spec: "1.0.0"
        }
    );
    assert_eq!(
        classify_metadata_path("@s/pkg/latest"),
        VersionManifest {
            name: "@s/pkg",
            spec: "latest"
        }
    );
    for other in ["-/v1/search", "pkg/a/b", "@s", "pkg//1.0.0", ""] {
        assert_eq!(classify_metadata_path(other), Other, "{other:?}");
    }
}

/// The reported case: a published name, its metadata TTL expired, an upstream package of
/// the same name. The packument stays the published one and the upstream is never asked.
#[tokio::test]
async fn a_published_packument_never_reaches_the_upstream() {
    let server = upstream("corp-lib", &["9.9.9"]).await;
    let ctx = context(&server, 0);
    publish(&ctx, "corp-lib", "1.0.0").await;
    for _ in 0..3 {
        assert_eq!(versions(&ctx, "/npm/corp-lib").await, ["1.0.0"]);
    }
    assert_eq!(asked(&server, "corp-lib").await, 0);
    assert!(ctx
        .state
        .storage
        .stat("npm/corp-lib/upstream/packument.json")
        .await
        .is_none());
}

#[tokio::test]
async fn a_published_version_manifest_is_answered_from_its_own_keys() {
    let server = upstream("corp-lib", &["9.9.9"]).await;
    let ctx = context(&server, 0);
    publish(&ctx, "corp-lib", "1.0.0").await;
    for spec in ["1.0.0", "latest"] {
        let resp = send(&ctx.app, Method::GET, &format!("/npm/corp-lib/{spec}"), "").await;
        assert_eq!(resp.status(), StatusCode::OK, "{spec}");
        let doc: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        assert_eq!(doc["version"], "1.0.0", "{spec}");
    }
    let resp = send(&ctx.app, Method::GET, "/npm/corp-lib/9.9.9", "").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(asked(&server, "corp-lib").await, 0);
}

/// An older release (or another replica running one) cached an upstream packument over a
/// published one. It is rebuilt from the published keys, never served.
#[tokio::test]
async fn a_published_packument_an_older_release_replaced_is_rebuilt() {
    let server = upstream("corp-lib", &["9.9.9"]).await;
    let ctx = context(&server, 3600);
    publish(&ctx, "corp-lib", "1.0.0").await;
    let key = "npm/corp-lib/metadata.json";
    // With its provenance record (1.3.4 to 1.3.6), and without one (an older release).
    let squatted = serde_json::to_vec(&doc("corp-lib", &["9.9.9"])).unwrap();
    put_with_origin(
        &ctx.state.storage,
        key,
        squatted.clone(),
        "npm|http://upstream",
    )
    .await
    .unwrap();
    assert_eq!(versions(&ctx, "/npm/corp-lib").await, ["1.0.0"]);
    let same_names = serde_json::to_vec(&doc("corp-lib", &["1.0.0"])).unwrap();
    put_with_origin(
        &ctx.state.storage,
        key,
        same_names.clone(),
        "npm|http://upstream",
    )
    .await
    .unwrap();
    let resp = send(&ctx.app, Method::GET, "/npm/corp-lib", "").await;
    let served: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert!(
        served["versions"]["1.0.0"]["dist"]["tarball"].is_string(),
        "rebuilt (publish set the tarball URL), not the copy: {served}"
    );
    assert!(
        !super::is_upstream_copy(&ctx.state.storage, key).await,
        "the copy is replaced"
    );
    ctx.state
        .storage
        .delete(&super::origin_key(key))
        .await
        .unwrap();
    ctx.state.storage.put(key, &squatted).await.unwrap();
    assert_eq!(versions(&ctx, "/npm/corp-lib").await, ["1.0.0"]);
    assert_eq!(asked(&server, "corp-lib").await, 0);
}

/// With the versions listing failing, a packument NORA assembled is served as it is (and a
/// version from its own keys); the upstream is asked only when there is none, or an upstream
/// copy sits in its place.
#[tokio::test]
async fn a_failed_listing_keeps_a_published_packument_local() {
    let server = upstream("corp-lib", &["9.9.9"]).await;
    let uri = server.uri();
    let ctx = crate::test_helpers::create_test_context_with_storage_and_config(
        faulty(true, false),
        move |cfg| cfg.npm.proxy = Some(uri),
    );
    let own = doc("corp-lib", &["1.0.0"]);
    for (key, body) in [
        (
            "npm/corp-lib/metadata.json",
            serde_json::to_string(&own).unwrap(),
        ),
        (
            "npm/corp-lib/versions/1.0.0.json",
            r#"{"name":"corp-lib","version":"1.0.0"}"#.to_string(),
        ),
    ] {
        ctx.state.storage.put(key, body.as_bytes()).await.unwrap();
    }
    // As 1.4.0 assembled and stored it, with its record.
    super::store_assembled_packument(
        &ctx.state.storage,
        "corp-lib",
        serde_json::to_string(&own).unwrap().as_bytes(),
    )
    .await
    .unwrap();
    assert_eq!(versions(&ctx, "/npm/corp-lib").await, ["1.0.0"]);
    let resp = send(&ctx.app, Method::GET, "/npm/corp-lib/1.0.0", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(asked(&server, "corp-lib").await, 0);
    // An upstream copy in its place is not taken for NORA's own, and NORA cannot tell whether
    // the package is published: unavailable, the upstream not asked.
    let copy = serde_json::to_vec(&doc("corp-lib", &["9.9.9"])).unwrap();
    put_with_origin(
        &ctx.state.storage,
        "npm/corp-lib/metadata.json",
        copy.clone(),
        "npm|http://up",
    )
    .await
    .unwrap();
    let resp = send(&ctx.app, Method::GET, "/npm/corp-lib", "").await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(asked(&server, "corp-lib").await, 0);
}

/// Round 1 fixture (M02): with the versions listing failing and the assembled packument
/// gone, a tarball download with trusted dates fetches and caches no upstream packument for
/// a published package.
#[tokio::test]
async fn a_failed_listing_primes_nothing_for_a_published_package() {
    let server = upstream("corp-lib", &["9.9.9"]).await;
    let uri = server.uri();
    let ctx = crate::test_helpers::create_test_context_with_storage_and_config(
        faulty(true, false),
        move |cfg| {
            cfg.npm.proxy = Some(uri);
            cfg.server.trust_upstream_dates = true;
        },
    );
    for (key, body) in [
        (
            "npm/corp-lib/versions/1.0.0.json",
            &br#"{"name":"corp-lib","version":"1.0.0"}"#[..],
        ),
        (
            "npm/corp-lib/tarballs/corp-lib-1.0.0.tgz",
            &b"local-tarball"[..],
        ),
    ] {
        ctx.state.storage.put(key, body).await.unwrap();
    }
    let _ = send(
        &ctx.app,
        Method::GET,
        "/npm/corp-lib/-/corp-lib-1.0.0.tgz",
        "",
    )
    .await;
    assert_eq!(asked(&server, "corp-lib").await, 0);
    assert!(ctx
        .state
        .storage
        .stat("npm/corp-lib/upstream/packument.json")
        .await
        .is_none());
}

/// With the versions listing failing, a published package's release date is read from its
/// own packument, not from an upstream copy cached before it was published.
#[tokio::test]
async fn a_failed_listing_reads_the_release_date_from_the_published_packument() {
    let server = upstream("corp-lib", &["9.9.9"]).await;
    let uri = server.uri();
    let ctx = crate::test_helpers::create_test_context_with_storage_and_config(
        faulty(true, false),
        move |cfg| {
            cfg.npm.proxy = Some(uri);
            cfg.server.trust_upstream_dates = true;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.min_release_age = Some("1h".to_string());
            cfg.curation.quarantine = Some(crate::digest_quarantine::QuarantineMode::Observe);
        },
    );
    let own = serde_json::json!({ "name": "corp-lib", "dist-tags": { "latest": "1.0.0" },
        "versions": { "1.0.0": { "name": "corp-lib", "version": "1.0.0" } },
        "time": { "1.0.0": "2020-01-01T00:00:00.000Z" } });
    let squatted = serde_json::json!({ "name": "corp-lib",
        "versions": { "1.0.0": { "name": "corp-lib", "version": "1.0.0" } },
        "time": { "1.0.0": chrono::Utc::now().to_rfc3339() } });
    for (key, body) in [
        ("npm/corp-lib/metadata.json", own.to_string()),
        ("npm/corp-lib/upstream/packument.json", squatted.to_string()),
        (
            "npm/corp-lib/versions/1.0.0.json",
            r#"{"name":"corp-lib","version":"1.0.0"}"#.to_string(),
        ),
        (
            "npm/corp-lib/tarballs/corp-lib-1.0.0.tgz",
            "local-tarball".to_string(),
        ),
    ] {
        ctx.state.storage.put(key, body.as_bytes()).await.unwrap();
    }
    super::store_assembled_packument(&ctx.state.storage, "corp-lib", own.to_string().as_bytes())
        .await
        .unwrap();
    let resp = send(
        &ctx.app,
        Method::GET,
        "/npm/corp-lib/-/corp-lib-1.0.0.tgz",
        "",
    )
    .await;
    let status = resp.status();
    let body = String::from_utf8_lossy(&body_bytes(resp).await).into_owned();
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// The whole decision on a stored published packument: served only when its record names
/// NORA and the digest of the bytes stored now.
#[test]
fn only_a_packument_nora_assembled_is_served_as_it_is() {
    let d = "aa11";
    let cases: [(Option<&str>, &str, bool); 9] = [
        (Some("nora-published\naa11"), d, true),
        (Some("nora-published\nbb22"), d, false),
        (Some("nora-published\naa11"), "bb22", false),
        (Some("npm|https://registry.npmjs.org\naa11"), d, false),
        (Some("nora-published"), d, false),
        (Some("nora-published\n"), "", false),
        (Some("NORA-published\naa11"), d, false),
        (Some(""), d, false),
        (None, d, false),
    ];
    for (record, digest, want) in cases {
        assert_eq!(
            super::assembled_by_nora(record, digest),
            want,
            "{record:?} {digest}"
        );
    }
}

/// Round 2 finding (G1): an upstream copy an older release cached over the published
/// packument with no record, naming exactly the published versions (here with a dependency
/// of its own), is rebuilt, not served; with the listing failing it is not taken for NORA's.
#[tokio::test]
async fn an_old_copy_with_the_published_version_set_is_rebuilt() {
    let server = upstream("corp-lib", &["1.0.0"]).await;
    let ctx = context(&server, 3600);
    publish(&ctx, "corp-lib", "1.0.0").await;
    let mut copy = doc("corp-lib", &["1.0.0"]);
    copy["versions"]["1.0.0"]["dependencies"] = serde_json::json!({ "evil-dep": "*" });
    ctx.state
        .storage
        .put("npm/corp-lib/metadata.json", copy.to_string().as_bytes())
        .await
        .unwrap();
    let resp = send(&ctx.app, Method::GET, "/npm/corp-lib", "").await;
    let served = String::from_utf8_lossy(&body_bytes(resp).await).into_owned();
    assert!(!served.contains("evil-dep"), "{served}");
    assert_eq!(asked(&server, "corp-lib").await, 0);

    let uri = server.uri();
    let failing = crate::test_helpers::create_test_context_with_storage_and_config(
        faulty(true, false),
        move |cfg| cfg.npm.proxy = Some(uri),
    );
    failing
        .state
        .storage
        .put("npm/corp-lib/metadata.json", copy.to_string().as_bytes())
        .await
        .unwrap();
    let resp = send(&failing.app, Method::GET, "/npm/corp-lib", "").await;
    let served = String::from_utf8_lossy(&body_bytes(resp).await).into_owned();
    assert!(
        !served.contains("evil-dep"),
        "the old copy is not taken for NORA's: {served}"
    );
}

/// Round 2 fixture (m06): a published name with capitals, as npm allowed before 2017.
#[tokio::test]
async fn a_published_name_with_capitals_stays_local() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(doc("Corp-Lib", &["9.9.9"])))
        .mount(&server)
        .await;
    let ctx = context(&server, 0);
    seed_published(&ctx.state.storage, "Corp-Lib").await;
    assert_eq!(versions(&ctx, "/npm/Corp-Lib").await, ["1.0.0"]);
    assert!(server.received_requests().await.unwrap().is_empty());
}

/// Round 2 fixture (m08): with the listing failing, a published package's dist-tags come from
/// the packument NORA assembled; an upstream copy in its place is not NORA's.
#[tokio::test]
async fn dist_tags_with_a_failed_listing_stay_local() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/-/package/corp-lib/dist-tags"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"latest": "9.9.9"})),
        )
        .mount(&server)
        .await;
    let uri = server.uri();
    let ctx = crate::test_helpers::create_test_context_with_storage_and_config(
        faulty(true, false),
        move |cfg| cfg.npm.proxy = Some(uri),
    );
    seed_published(&ctx.state.storage, "corp-lib").await;
    let resp = send(
        &ctx.app,
        Method::GET,
        "/npm/-/package/corp-lib/dist-tags",
        "",
    )
    .await;
    let tags: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(tags["latest"], "1.0.0");
    assert!(server.received_requests().await.unwrap().is_empty());
    let copy = serde_json::to_vec(&doc("corp-lib", &["9.9.9"])).unwrap();
    put_with_origin(
        &ctx.state.storage,
        "npm/corp-lib/metadata.json",
        copy.clone(),
        "npm|http://up",
    )
    .await
    .unwrap();
    // With an upstream copy in its place NORA cannot tell whether the tags are its own.
    let resp = send(
        &ctx.app,
        Method::GET,
        "/npm/-/package/corp-lib/dist-tags",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(server.received_requests().await.unwrap().is_empty());
}

/// R9 finding: a store that lists no versions for a published package (a local directory it
/// could not read) does not make the package unpublished while NORA's assembled packument is
/// there: it is served, and no upstream is asked or cached.
#[tokio::test]
async fn an_empty_listing_beside_an_assembled_packument_stays_local() {
    let server = upstream("corp-lib", &["9.9.9"]).await;
    let uri = server.uri();
    let ctx = crate::test_helpers::create_test_context_with_storage_and_config(
        listing_lies(),
        move |cfg| {
            cfg.npm.proxy = Some(uri);
            cfg.npm.metadata_ttl = 0;
        },
    );
    seed_published(&ctx.state.storage, "corp-lib").await;
    assert_eq!(versions(&ctx, "/npm/corp-lib").await, ["1.0.0"]);
    assert_eq!(asked(&server, "corp-lib").await, 0);
    assert!(ctx
        .state
        .storage
        .stat("npm/corp-lib/upstream/packument.json")
        .await
        .is_none());
}

/// Table row 2.2: a version manifest of a published package, with a listing that answers
/// "nothing here" beside NORA's assembled packument, comes from the package's own keys.
#[tokio::test]
async fn a_version_manifest_with_an_empty_listing_stays_local() {
    let server = upstream("corp-lib", &["1.0.0"]).await;
    let uri = server.uri();
    let ctx = crate::test_helpers::create_test_context_with_storage_and_config(
        listing_lies(),
        move |cfg| cfg.npm.proxy = Some(uri),
    );
    seed_published(&ctx.state.storage, "corp-lib").await;
    let resp = send(&ctx.app, Method::GET, "/npm/corp-lib/1.0.0", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let manifest: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(manifest["version"], "1.0.0");
    assert!(
        manifest.get("dist").is_none(),
        "the stored manifest, not the upstream's: {manifest}"
    );
    assert_eq!(asked(&server, "corp-lib").await, 0);
}

/// Table row 2.5: with the listing failing and no packument NORA assembled, NORA cannot tell
/// whether the package is published: its version manifest is unavailable (503), as cargo
/// answers a crate it cannot tell is published. A published name is never an upstream's to
/// answer for, so the upstream is not asked, and nothing is cached on a guess.
#[tokio::test]
async fn a_version_manifest_with_a_failed_listing_is_unavailable() {
    let server = upstream("corp-lib", &["9.9.9"]).await;
    let uri = server.uri();
    let ctx = crate::test_helpers::create_test_context_with_storage_and_config(
        faulty(true, false),
        move |cfg| cfg.npm.proxy = Some(uri),
    );
    let holders = ctx.state.storage.holders();
    let resp = send(&ctx.app, Method::GET, "/npm/corp-lib/9.9.9", "").await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
    crate::test_helpers::background_writes_done(&ctx.state.storage, holders).await;
    let written = ctx.state.storage.list("npm/").await.unwrap();
    assert!(written.is_empty(), "nothing cached on a guess: {written:?}");
}

/// The same for the packument, the dist-tags and a tarball of a package whose published
/// versions cannot be listed.
#[tokio::test]
async fn a_failed_versions_listing_makes_the_package_unavailable() {
    let server = upstream("left-pad", &["1.3.0"]).await;
    Mock::given(method("GET"))
        .and(path("/left-pad/-/left-pad-1.3.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"upstream".to_vec()))
        .mount(&server)
        .await;
    let uri = server.uri();
    let ctx = crate::test_helpers::create_test_context_with_storage_and_config(
        faulty(true, false),
        move |cfg| cfg.npm.proxy = Some(uri),
    );
    let holders = ctx.state.storage.holders();
    let mut wrong = Vec::new();
    for path in [
        "/npm/left-pad",
        "/npm/-/package/left-pad/dist-tags",
        "/npm/left-pad/-/left-pad-1.3.0.tgz",
    ] {
        let status = send(&ctx.app, Method::GET, path, "").await.status();
        if status != StatusCode::SERVICE_UNAVAILABLE {
            wrong.push(format!("{path} -> {status}"));
        }
    }
    assert!(wrong.is_empty(), "answered other than 503: {wrong:?}");
    let asked: Vec<String> = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.url.path().to_string())
        .collect();
    assert!(asked.is_empty(), "upstream asked: {asked:?}");
    crate::test_helpers::background_writes_done(&ctx.state.storage, holders).await;
    let written = ctx.state.storage.list("npm/").await.unwrap();
    assert!(written.is_empty(), "nothing cached on a guess: {written:?}");
}

/// Second control: a package the listing shows is not published here is proxied as before.
#[tokio::test]
async fn a_package_the_listing_shows_unpublished_is_still_proxied() {
    let server = upstream("left-pad", &["1.3.0"]).await;
    super::mount_listing(
        &server,
        "left-pad",
        &[("1.3.0", "left-pad/-/left-pad-1.3.0.tgz")],
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/left-pad/-/left-pad-1.3.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"upstream".to_vec()))
        .mount(&server)
        .await;
    let uri = server.uri();
    let ctx = crate::test_helpers::create_test_context_with_storage_and_config(
        faulty(false, false),
        move |cfg| cfg.npm.proxy = Some(uri),
    );
    assert_eq!(versions(&ctx, "/npm/left-pad").await, ["1.3.0"]);
    let tarball = send(
        &ctx.app,
        Method::GET,
        "/npm/left-pad/-/left-pad-1.3.0.tgz",
        "",
    )
    .await;
    assert_eq!(tarball.status(), StatusCode::OK);
    assert_eq!(&body_bytes(tarball).await[..], b"upstream");
}

/// Table row 3.2: dist-tags of a published package, with a listing that answers "nothing
/// here" beside NORA's assembled packument, are the packument's own.
#[tokio::test]
async fn dist_tags_with_an_empty_listing_stay_local() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"latest": "9.9.9"})),
        )
        .mount(&server)
        .await;
    let uri = server.uri();
    let ctx = crate::test_helpers::create_test_context_with_storage_and_config(
        listing_lies(),
        move |cfg| cfg.npm.proxy = Some(uri),
    );
    seed_published(&ctx.state.storage, "corp-lib").await;
    let resp = send(
        &ctx.app,
        Method::GET,
        "/npm/-/package/corp-lib/dist-tags",
        "",
    )
    .await;
    let tags: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(tags["latest"], "1.0.0");
    assert!(server.received_requests().await.unwrap().is_empty());
}

/// Round 1 fixture (M10): a published scoped package, in both forms of its path.
#[tokio::test]
async fn a_published_scoped_packument_never_reaches_the_upstream() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(doc("@s/pkg", &["9.9.9"])))
        .mount(&server)
        .await;
    let ctx = context(&server, 0);
    for (key, body) in [
        (
            "npm/@s/pkg/versions/1.0.0.json",
            r#"{"name":"@s/pkg","version":"1.0.0"}"#,
        ),
        ("npm/@s/pkg/dist-tags/latest", "1.0.0"),
    ] {
        ctx.state.storage.put(key, body.as_bytes()).await.unwrap();
    }
    for uri in ["/npm/@s%2fpkg", "/npm/@s/pkg"] {
        assert_eq!(versions(&ctx, uri).await, ["1.0.0"], "{uri}");
    }
    let resp = send(&ctx.app, Method::GET, "/npm/@s/pkg/latest", "").await;
    let doc: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(doc["version"], "1.0.0");
    assert!(server.received_requests().await.unwrap().is_empty());
}

/// Round 1 finding (H3): versions published while a read waited for the lock are not taken
/// for unreadable ones: the set is listed again under the lock.
#[tokio::test]
async fn a_publish_during_a_read_is_not_a_503() {
    let server = upstream("corp-lib", &["9.9.9"]).await;
    let ctx = context(&server, 3600);
    publish(&ctx, "corp-lib", "1.0.0").await;
    publish(&ctx, "corp-lib", "1.1.0").await;
    ctx.state
        .storage
        .delete("npm/corp-lib/metadata.json")
        .await
        .unwrap();
    // The set the read took before the lock: 1.1.0 not yet in it.
    let stale: std::collections::BTreeSet<String> = ["1.0.0".to_string()].into();
    let resp = super::published_packument_response(
        &ctx.state,
        &axum::http::HeaderMap::new(),
        "corp-lib",
        &stale,
        "http://localhost:4000",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let doc: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    let listed: Vec<&String> = doc["versions"].as_object().unwrap().keys().collect();
    assert_eq!(listed, ["1.0.0", "1.1.0"]);
}

/// Round 1 finding (H4): `npm dist-tag ls` of a published package reads its own tags; an
/// unpublished one's come from the upstream, uncached.
#[tokio::test]
async fn dist_tags_of_a_published_package_are_its_own() {
    let server = upstream("corp-lib", &["9.9.9"]).await;
    Mock::given(method("GET"))
        .and(path("/-/package/left-pad/dist-tags"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"latest": "1.3.0"})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/-/package/corp-lib/dist-tags"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"latest": "9.9.9"})),
        )
        .mount(&server)
        .await;
    let ctx = context(&server, 0);
    publish(&ctx, "corp-lib", "1.0.0").await;
    let tags = |uri: &'static str| {
        let app = ctx.app.clone();
        async move {
            let resp = send(&app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
            serde_json::from_slice::<serde_json::Value>(&body_bytes(resp).await).unwrap()
        }
    };
    assert_eq!(
        tags("/npm/-/package/corp-lib/dist-tags").await["latest"],
        "1.0.0"
    );
    // A package not published here: `dist-tag ls` never sends its name upstream.
    let resp = send(
        &ctx.app,
        Method::GET,
        "/npm/-/package/left-pad/dist-tags",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let asked_tags = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().contains("dist-tags"))
        .count();
    assert_eq!(asked_tags, 0);
}

/// Any other metadata path (search, registry endpoints) is answered by the upstream and not
/// cached: no request reaches a key under `npm/` that a packument could share.
#[tokio::test]
async fn other_metadata_paths_are_not_cached() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/-/v1/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"objects": []})))
        .mount(&server)
        .await;
    let ctx = context(&server, 3600);
    let holders = ctx.state.storage.holders();
    for _ in 0..2 {
        let resp = send(&ctx.app, Method::GET, "/npm/-/v1/search?text=x", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
    crate::test_helpers::background_writes_done(&ctx.state.storage, holders).await;
    assert!(ctx.state.storage.list("npm/").await.unwrap().is_empty());
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

/// #1148: a search reaches the upstream with the query the client sent, encoding kept, so
/// `npm search` through NORA returns what the upstream finds; a request without a query is
/// sent without one.
#[tokio::test]
async fn a_search_reaches_the_upstream_with_its_query() {
    use wiremock::matchers::query_param;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/-/v1/search"))
        .and(query_param("text", "@types/node"))
        .and(query_param("size", "20"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            serde_json::json!({"objects": [{"package": {"name": "@types/node"}}], "total": 1}),
        ))
        .mount(&server)
        .await;
    // registry.npmjs.org without `text`: 400 'text' query parameter is required
    Mock::given(method("GET"))
        .and(path("/-/v1/search"))
        .respond_with(ResponseTemplate::new(400))
        .mount(&server)
        .await;
    let ctx = context(&server, 3600);
    let resp = send(
        &ctx.app,
        Method::GET,
        "/npm/-/v1/search?text=%40types%2Fnode&size=20",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(String::from_utf8_lossy(&body_bytes(resp).await).contains("@types/node"));
    let asked = server.received_requests().await.unwrap();
    assert_eq!(asked[0].url.query(), Some("text=%40types%2Fnode&size=20"));
    let resp = send(&ctx.app, Method::GET, "/npm/-/v1/search", "").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let asked = server.received_requests().await.unwrap();
    assert_eq!(asked[1].url.query(), None);
}

/// #1148, ADR-8: a search that names an internal package or a scope owned by a private
/// upstream is refused with the reason and never sent to the upstream, as an audit that
/// carries such names is. Fork policy: while a namespace filter or an owned scope makes
/// some names private, no search is sent at all (501): free-form text may carry a name
/// no word check catches.
#[tokio::test]
async fn a_search_naming_a_private_package_is_refused_and_not_sent() {
    use crate::config::NpmConfig;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"objects": []})))
        .mount(&server)
        .await;
    let uri = server.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        let npm: NpmConfig = toml::from_str(&format!(
            r#"proxies = ["{uri}", {{ url = "{uri}/private", scopes = ["@vendor"] }}]"#
        ))
        .unwrap();
        cfg.npm.proxies = npm.proxies;
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.internal_namespaces = vec!["@internal/*".to_string(), "corp-*".to_string()];
    });
    // (query, names a private package)
    let rows: [(&str, bool); 11] = [
        ("text=%40internal%2Fsecret", true),
        ("text=react+%40internal%2Fsecret", true),
        ("text=corp-billing", true),
        ("text=scope%3Ainternal", true),
        ("text=%40vendor%2Ftool", true),
        ("text=scope%3Avendor+cli", true),
        ("text=%40vendor", true),
        ("text=lodash&size=20", false),
        ("text=corporate", false),
        ("text=keywords%3Acorp-billing", true),
        // cannot be decoded, so cannot be checked
        ("text=%FF", true),
    ];
    for (query, private) in rows {
        let before = server.received_requests().await.unwrap().len();
        let resp = send(
            &ctx.app,
            Method::GET,
            &format!("/npm/-/v1/search?{query}"),
            "",
        )
        .await;
        let status = resp.status();
        let body = String::from_utf8_lossy(&body_bytes(resp).await).to_string();
        let sent = server.received_requests().await.unwrap().len() - before;
        assert_eq!(
            status,
            StatusCode::NOT_IMPLEMENTED,
            "{query} (private: {private})"
        );
        assert!(body.contains("\"error\""), "{query}: {body}");
        assert_eq!(sent, 0, "{query} reached the upstream");
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

/// A published version whose document cannot be read is neither dropped from the packument
/// nor rebuilt at every read: the packument is 503 until it is repaired, and no upstream is
/// asked in its place.
#[tokio::test]
async fn an_unreadable_published_version_is_not_dropped() {
    let server = upstream("corp-lib", &["9.9.9"]).await;
    let ctx = context(&server, 0);
    publish(&ctx, "corp-lib", "1.0.0").await;
    publish(&ctx, "corp-lib", "1.1.0").await;
    ctx.state
        .storage
        .put("npm/corp-lib/versions/1.1.0.json", b"not json")
        .await
        .unwrap();
    ctx.state
        .storage
        .delete("npm/corp-lib/metadata.json")
        .await
        .unwrap();
    for _ in 0..2 {
        let resp = send(&ctx.app, Method::GET, "/npm/corp-lib", "").await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
    assert!(ctx
        .state
        .storage
        .stat("npm/corp-lib/metadata.json")
        .await
        .is_none());
    assert_eq!(asked(&server, "corp-lib").await, 0);
}

/// A rebuilt packument is served even when it cannot be stored: 503 is only for one that
/// cannot be assembled.
#[tokio::test]
async fn a_rebuilt_packument_is_served_when_it_cannot_be_stored() {
    let server = upstream("corp-lib", &["9.9.9"]).await;
    let uri = server.uri();
    let ctx = crate::test_helpers::create_test_context_with_storage_and_config(
        faulty(false, true),
        move |cfg| cfg.npm.proxy = Some(uri),
    );
    for (key, body) in [
        (
            "npm/corp-lib/versions/1.0.0.json",
            r#"{"name":"corp-lib","version":"1.0.0"}"#,
        ),
        ("npm/corp-lib/dist-tags/latest", "1.0.0"),
    ] {
        ctx.state.storage.put(key, body.as_bytes()).await.unwrap();
    }
    assert_eq!(versions(&ctx, "/npm/corp-lib").await, ["1.0.0"]);
    assert!(ctx
        .state
        .storage
        .stat("npm/corp-lib/metadata.json")
        .await
        .is_none());
    assert_eq!(asked(&server, "corp-lib").await, 0);
}

#[tokio::test]
async fn an_unpublished_package_is_cached_under_the_upstream_key_only() {
    let server = upstream("left-pad", &["1.3.0"]).await;
    let ctx = context(&server, 3600);
    assert_eq!(versions(&ctx, "/npm/left-pad").await, ["1.3.0"]);
    wait_for(&ctx, "npm/left-pad/upstream/packument.json").await;
    let resp = send(&ctx.app, Method::GET, "/npm/left-pad/1.3.0", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    wait_for(&ctx, "npm/left-pad/upstream/manifests/1.3.0.json").await;
    for key in [
        "npm/left-pad/metadata.json",
        "npm/left-pad/1.3.0/metadata.json",
    ] {
        assert!(ctx.state.storage.stat(key).await.is_none(), "{key}");
    }
}

/// What 1.3.6 cached at `metadata.json` is served while fresh, revalidated into the new key
/// once stale, and never written: a rollback reads it as it was.
#[tokio::test]
async fn an_older_releases_cache_is_read_and_left_alone() {
    let server = upstream("left-pad", &["1.3.0", "1.4.0"]).await;
    let legacy = serde_json::to_vec(&doc("left-pad", &["1.3.0"])).unwrap();
    let fresh = context(&server, 3600);
    fresh
        .state
        .storage
        .put("npm/left-pad/metadata.json", &legacy)
        .await
        .unwrap();
    assert_eq!(versions(&fresh, "/npm/left-pad").await, ["1.3.0"]);
    assert_eq!(
        asked(&server, "left-pad").await,
        0,
        "a fresh old cache is served"
    );

    let stale = {
        let uri = server.uri();
        crate::test_helpers::create_test_context_with_storage_and_config(
            fresh.state.storage.clone(),
            move |cfg| {
                cfg.npm.proxy = Some(uri);
                cfg.npm.metadata_ttl = 0;
            },
        )
    };
    assert_eq!(versions(&stale, "/npm/left-pad").await, ["1.3.0", "1.4.0"]);
    wait_for(&stale, "npm/left-pad/upstream/packument.json").await;
    assert_eq!(
        stale
            .state
            .storage
            .get("npm/left-pad/metadata.json")
            .await
            .unwrap(),
        legacy
    );
}

/// A publish over an upstream copy an older release cached at the published key: its
/// versions are not imported as published ones, and do not block the publish.
#[tokio::test]
async fn a_publish_over_an_upstream_copy_imports_none_of_it() {
    let server = upstream("corp-lib", &["1.0.0", "9.9.9"]).await;
    let ctx = context(&server, 3600);
    let copy = serde_json::to_vec(&doc("corp-lib", &["1.0.0", "9.9.9"])).unwrap();
    put_with_origin(
        &ctx.state.storage,
        "npm/corp-lib/metadata.json",
        copy.clone(),
        "npm|http://up",
    )
    .await
    .unwrap();
    publish(&ctx, "corp-lib", "1.0.0").await;
    assert_eq!(versions(&ctx, "/npm/corp-lib").await, ["1.0.0"]);
    let published = ctx
        .state
        .storage
        .list("npm/corp-lib/versions/")
        .await
        .unwrap();
    assert_eq!(published, ["npm/corp-lib/versions/1.0.0.json"]);
}

/// Round 1 finding (H2): a packument with no record of where it came from, on a package with
/// no per-version keys, is an upstream cache of NORA 1.3.3 or older or a package published to
/// NORA 0.9.3 or older. A publish over it is refused, naming the key, until the operator says
/// which: delete it, or list the name in `import_embedded`.
#[tokio::test]
async fn a_publish_over_a_packument_of_unknown_origin_waits_for_the_operator() {
    let server = upstream("corp-lib", &["9.9.9"]).await;
    let unknown = serde_json::to_vec(&doc("corp-lib", &["9.9.9"])).unwrap();
    let ctx = context(&server, 3600);
    ctx.state
        .storage
        .put("npm/corp-lib/metadata.json", &unknown)
        .await
        .unwrap();
    let payload = serde_json::json!({
        "name": "corp-lib",
        "versions": { "1.0.0": { "name": "corp-lib", "version": "1.0.0", "dist": {} } },
        "_attachments": { "corp-lib-1.0.0.tgz": { "data": "dGFy" } }
    });
    let put = |ctx: &TestContext| {
        let app = ctx.app.clone();
        let body = serde_json::to_vec(&payload).unwrap();
        async move {
            send(
                &app,
                Method::PUT,
                "/npm/corp-lib",
                axum::body::Body::from(body),
            )
            .await
        }
    };
    let resp = put(&ctx).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let text = String::from_utf8_lossy(&body_bytes(resp).await).into_owned();
    assert!(
        text.contains("npm/corp-lib/metadata.json")
            && text.contains("NORA_NPM_IMPORT_EMBEDDED=corp-lib"),
        "{text}"
    );
    assert!(ctx
        .state
        .storage
        .list("npm/corp-lib/versions/")
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        ctx.state
            .storage
            .get("npm/corp-lib/metadata.json")
            .await
            .unwrap(),
        unknown
    );

    // A name is matched whole: `corp` does not allow `corp-lib`.
    let uri = server.uri();
    let prefix = crate::test_helpers::create_test_context_with_storage_and_config(
        ctx.state.storage.clone(),
        move |cfg| {
            cfg.npm.proxy = Some(uri);
            cfg.npm.import_embedded = vec!["corp".to_string()];
        },
    );
    assert_eq!(put(&prefix).await.status(), StatusCode::CONFLICT);
    // A provenance record written for other bytes does not make it NORA's own either.
    ctx.state
        .storage
        .put(
            &super::origin_key("npm/corp-lib/metadata.json"),
            b"npm|http://up\ndeadbeef",
        )
        .await
        .unwrap();
    assert_eq!(put(&ctx).await.status(), StatusCode::CONFLICT);
    ctx.state
        .storage
        .delete(&super::origin_key("npm/corp-lib/metadata.json"))
        .await
        .unwrap();

    // The operator says it is their own (a package published to NORA 0.9.3 or older).
    let uri = server.uri();
    let allowed = crate::test_helpers::create_test_context_with_storage_and_config(
        ctx.state.storage.clone(),
        move |cfg| {
            cfg.npm.proxy = Some(uri);
            cfg.npm.import_embedded = vec!["corp-lib".to_string()];
        },
    );
    assert_eq!(put(&allowed).await.status(), StatusCode::CREATED);
    assert_eq!(
        versions(&allowed, "/npm/corp-lib").await,
        ["1.0.0", "9.9.9"]
    );
}

/// With trusted dates a tarball download primes the packument for its release date. A
/// published package's dates are its own: nothing is fetched or cached for it.
#[tokio::test]
async fn a_tarball_download_primes_nothing_for_a_published_package() {
    let server = upstream("corp-lib", &["9.9.9"]).await;
    let uri = server.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.npm.proxy = Some(uri);
        cfg.server.trust_upstream_dates = true;
    });
    publish(&ctx, "corp-lib", "1.0.0").await;
    // Its assembled packument is derived state; with it gone, the name still goes nowhere.
    ctx.state
        .storage
        .delete("npm/corp-lib/metadata.json")
        .await
        .unwrap();
    let resp = send(
        &ctx.app,
        Method::GET,
        "/npm/corp-lib/-/corp-lib-1.0.0.tgz",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(&body_bytes(resp).await[..], b"local-tarball");
    assert_eq!(asked(&server, "corp-lib").await, 0);
    assert!(ctx
        .state
        .storage
        .stat("npm/corp-lib/upstream/packument.json")
        .await
        .is_none());
    assert_eq!(versions(&ctx, "/npm/corp-lib").await, ["1.0.0"]);
}

/// The published packument key is named in one function, and only publish, the rebuild,
/// the published-packument answer, the readers that pick a key, and retention's lock call
/// it; the legacy key is named in one function, called only where a cache is read and
/// where a non-package path is proxied. A new path that writes a published packument has
/// to name one of them, here.
#[test]
fn the_published_key_is_reached_only_from_the_published_side() {
    let source = include_str!("../npm.rs");
    let production = &source[..source.find("\n#[cfg(test)]").unwrap()];
    let mut current = "";
    let mut literal_in: Vec<String> = Vec::new();
    let mut published_callers = std::collections::BTreeSet::new();
    let mut legacy_callers = std::collections::BTreeSet::new();
    for line in production.lines() {
        let trimmed = line.trim_start();
        if !line.starts_with(' ') {
            for prefix in [
                "pub(crate) async fn ",
                "pub(crate) fn ",
                "pub async fn ",
                "pub fn ",
                "async fn ",
                "fn ",
            ] {
                if let Some(rest) = trimmed.strip_prefix(prefix) {
                    current = rest.split(['(', '<']).next().unwrap();
                }
            }
        }
        if trimmed.starts_with("//") {
            continue;
        }
        if line.contains("metadata.json\"") {
            literal_in.push(current.to_string());
        }
        if line.contains("published_packument_key(") && !line.contains("fn published_packument_key")
        {
            published_callers.insert(current.to_string());
        }
        if line.contains("legacy_cache_key(") && !line.contains("fn legacy_cache_key") {
            legacy_callers.insert(current.to_string());
        }
    }
    assert_eq!(literal_in, ["published_packument_key", "legacy_cache_key"]);
    assert_eq!(
        published_callers.into_iter().collect::<Vec<_>>(),
        [
            "deprecate_versions",
            "handle_npm_delete",
            "handle_publish",
            "package_lock_key",
            "packument_key_for_reading",
            "publish_versions",
            "published_packument_response",
            "published_state",
            "serve_dist_tags",
            "serve_metadata",
            "set_dist_tag",
            "store_assembled_packument",
            "unpublish",
            "unpublish_put",
            "unpublish_tarball",
            "write_publish",
        ]
    );
    assert_eq!(
        legacy_callers.into_iter().collect::<Vec<_>>(),
        [
            "handle_request",
            "npm_release_times",
            "packument_key_for_reading",
            "trusted_copy",
            "upstream_metadata",
        ]
    );
}
