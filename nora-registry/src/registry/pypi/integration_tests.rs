// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::test_helpers::{body_bytes, create_test_context, send, send_with_headers};
use axum::http::{header, Method, StatusCode};

/// A cold miss is "not found" only when an upstream said so. The simple index and a file
/// whose upstreams all failed (5xx after the retry, unreachable) answer 502, and so does a
/// file the index lists on a host that is down. An index that answers without the file,
/// or a 404, is still 404 — also while another upstream is down.
#[tokio::test]
async fn a_cold_miss_is_404_only_when_an_upstream_said_not_found() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let down = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&down)
        .await;
    let missing = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&missing)
        .await;
    // The index answers and lists the file on the host that is down.
    let lists_down = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/flask/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            r#"<html><body><a href="{}/files/flask-2.0.tar.gz">flask-2.0.tar.gz</a></body></html>"#,
            down.uri()
        )))
        .mount(&lists_down)
        .await;
    // The index answers without the file.
    let lists_other = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/flask/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<html><body><a href="/files/flask-1.0.tar.gz">flask-1.0.tar.gz</a></body></html>"#,
        ))
        .mount(&lists_other)
        .await;
    // The index answers with no files at all.
    let lists_nothing = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/flask/"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html><body></body></html>"))
        .mount(&lists_nothing)
        .await;
    let refused = "http://127.0.0.1:9".to_string();
    let index = "/simple/flask/";
    let file = "/simple/flask/flask-2.0.tar.gz";
    for (upstreams, uri, want) in [
        (vec![down.uri()], index, StatusCode::BAD_GATEWAY),
        (vec![refused.clone()], index, StatusCode::BAD_GATEWAY),
        (vec![missing.uri()], index, StatusCode::NOT_FOUND),
        (
            vec![down.uri(), lists_nothing.uri()],
            index,
            StatusCode::NOT_FOUND,
        ),
        (vec![down.uri()], file, StatusCode::BAD_GATEWAY),
        (vec![refused.clone()], file, StatusCode::BAD_GATEWAY),
        (vec![missing.uri()], file, StatusCode::NOT_FOUND),
        (vec![lists_down.uri()], file, StatusCode::BAD_GATEWAY),
        (vec![lists_other.uri()], file, StatusCode::NOT_FOUND),
        (
            vec![down.uri(), lists_other.uri()],
            file,
            StatusCode::NOT_FOUND,
        ),
    ] {
        let urls = upstreams.clone();
        let ctx = crate::test_helpers::create_test_context_with_config(move |cfg| {
            // Plain URL entries, as `proxies = ["https://..."]` reads from the config file.
            cfg.pypi.proxies = serde_json::from_value(serde_json::json!(urls)).unwrap();
        });
        let resp = send(&ctx.app, Method::GET, uri, "").await;
        assert_eq!(resp.status(), want, "{uri} {upstreams:?}");
    }
    assert!(!down.received_requests().await.unwrap().is_empty());
    assert!(!missing.received_requests().await.unwrap().is_empty());
    assert!(!lists_down.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_pypi_list_empty() {
    let ctx = create_test_context();
    let response = send(&ctx.app, Method::GET, "/simple/", "").await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_bytes(response).await;
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("Simple Index"));
}

#[tokio::test]
async fn test_pypi_list_with_packages() {
    let ctx = create_test_context();

    ctx.state
        .storage
        .put("pypi/flask/flask-2.0.tar.gz", b"fake-tarball-data")
        .await
        .unwrap();

    let response = send(&ctx.app, Method::GET, "/simple/", "").await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_bytes(response).await;
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("flask"));
}

#[tokio::test]
async fn test_pypi_list_json_pep691() {
    let ctx = create_test_context();

    ctx.state
        .storage
        .put("pypi/flask/flask-2.0.tar.gz", b"data")
        .await
        .unwrap();

    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/simple/",
        vec![("Accept", "application/vnd.pypi.simple.v1+json")],
        "",
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_bytes(response).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["meta"]["api-version"].as_str() == Some("1.0"));
    assert!(json["projects"].as_array().unwrap().len() == 1);
}

#[tokio::test]
async fn test_pypi_versions_local() {
    let ctx = create_test_context();

    ctx.state
        .storage
        .put("pypi/flask/flask-2.0.tar.gz", b"fake-data")
        .await
        .unwrap();

    let response = send(&ctx.app, Method::GET, "/simple/flask/", "").await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_bytes(response).await;
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("flask-2.0.tar.gz"));
    // URL should contain base_url + /simple/flask/flask-2.0.tar.gz
    assert!(html.contains("/simple/flask/flask-2.0.tar.gz"));
}

#[tokio::test]
async fn test_pypi_versions_with_hash() {
    let ctx = create_test_context();

    ctx.state
        .storage
        .put("pypi/flask/flask-2.0.tar.gz", b"fake-data")
        .await
        .unwrap();
    ctx.state
        .storage
        .put(
            "pypi/flask/flask-2.0.tar.gz.sha256",
            b"abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
        )
        .await
        .unwrap();

    let response = send(&ctx.app, Method::GET, "/simple/flask/", "").await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_bytes(response).await;
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("#sha256=abc123"));
}

#[tokio::test]
async fn test_pypi_versions_json_pep691() {
    let ctx = create_test_context();

    ctx.state
        .storage
        .put("pypi/flask/flask-2.0.tar.gz", b"data")
        .await
        .unwrap();
    ctx.state
        .storage
        .put("pypi/flask/flask-2.0.tar.gz.sha256", b"deadbeef")
        .await
        .unwrap();

    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/simple/flask/",
        vec![("Accept", "application/vnd.pypi.simple.v1+json")],
        "",
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_bytes(response).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["name"], "flask");
    assert_eq!(json["files"].as_array().unwrap().len(), 1);
    assert_eq!(json["files"][0]["filename"], "flask-2.0.tar.gz");
    assert_eq!(json["files"][0]["hashes"]["sha256"], "deadbeef");
}

/// #1100: every file in the simple JSON carries a `hashes` object, also a file NORA
/// has no digest for — an upstream link without `#sha256=` (a mirror that publishes
/// none) or a stored file without its sidecar. uv reads `hashes` as a required map
/// and refused the whole index (`missing field hashes`) when one file lacked it.
/// Parsed here the way uv parses it: absent or null fails, `{}` is read as no hashes.
#[tokio::test]
async fn test_pypi_json_every_file_has_hashes_object() {
    use crate::test_helpers::create_test_context_with_config;
    use std::collections::BTreeMap;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[derive(serde::Deserialize)]
    struct StrictIndex {
        files: Vec<StrictFile>,
    }
    #[derive(serde::Deserialize)]
    struct StrictFile {
        filename: String,
        hashes: BTreeMap<String, String>,
    }

    let up_sha = "a".repeat(64);
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/flask/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            r#"<html><body>
                <a href="https://up/flask-1.0.tar.gz">flask-1.0.tar.gz</a>
                <a href="https://up/flask-1.1.tar.gz#sha256={up_sha}">flask-1.1.tar.gz</a>
                </body></html>"#
        )))
        .mount(&upstream)
        .await;

    let proxied = create_test_context_with_config(|cfg| {
        cfg.pypi.proxy = Some(upstream.uri());
    });
    let local_only = create_test_context();
    for ctx in [&proxied, &local_only] {
        // Stored before sidecars and markers existed: no digest anywhere.
        ctx.state
            .storage
            .put("pypi/flask/flask-0.9.tar.gz", b"old")
            .await
            .unwrap();
        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz", b"data")
            .await
            .unwrap();
        ctx.state
            .storage
            .put("pypi/flask/flask-2.0.tar.gz.sha256", b"deadbeef")
            .await
            .unwrap();
    }

    let none = BTreeMap::new();
    let sha = |h: &str| BTreeMap::from([("sha256".to_string(), h.to_string())]);
    for (ctx, want) in [
        (
            &proxied,
            vec![
                ("flask-0.9.tar.gz", none.clone()),
                ("flask-1.0.tar.gz", none.clone()),
                ("flask-1.1.tar.gz", sha(&up_sha)),
                ("flask-2.0.tar.gz", sha("deadbeef")),
            ],
        ),
        (
            &local_only,
            vec![
                ("flask-0.9.tar.gz", none.clone()),
                ("flask-2.0.tar.gz", sha("deadbeef")),
            ],
        ),
    ] {
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/flask/",
            vec![("Accept", "application/vnd.pypi.simple.v1+json")],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_bytes(response).await;
        let index: StrictIndex = serde_json::from_slice(&body).unwrap_or_else(|e| {
            panic!(
                "a strict PEP 691 client cannot read the index: {e}\n{}",
                String::from_utf8_lossy(&body)
            )
        });
        let mut got: Vec<(String, BTreeMap<String, String>)> = index
            .files
            .into_iter()
            .map(|f| (f.filename, f.hashes))
            .collect();
        got.sort();
        let want: Vec<(String, BTreeMap<String, String>)> =
            want.into_iter().map(|(f, h)| (f.to_string(), h)).collect();
        assert_eq!(got, want);
    }
}

/// #896: NORA's simple JSON must also carry PEP 700 fields so clients (e.g. Renovate)
/// can compute a minimum release age: `meta.api-version` 1.1, a project-level
/// `versions` list, and per-file `upload-time` + `size`. Upload-time is sourced from
/// the cached `dates.json` (filename → RFC3339), size from storage.
#[tokio::test]
async fn test_pypi_versions_json_pep700() {
    let ctx = create_test_context();
    ctx.state
        .storage
        .put("pypi/flask/flask-2.0.tar.gz", b"data")
        .await
        .unwrap();
    ctx.state
        .storage
        .put("pypi/flask/flask-2.0.tar.gz.sha256", b"deadbeef")
        .await
        .unwrap();
    // PEP 700 upload-time is read from the cached dates.json (filename → RFC3339).
    ctx.state
        .storage
        .put(
            "pypi/flask/dates.json",
            br#"{"flask-2.0.tar.gz":"2021-05-11T13:00:00Z"}"#,
        )
        .await
        .unwrap();

    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/simple/flask/",
        vec![("Accept", "application/vnd.pypi.simple.v1+json")],
        "",
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_bytes(response).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // PEP 700 signals support via api-version 1.1
    assert_eq!(
        json["meta"]["api-version"], "1.1",
        "PEP 700 requires meta.api-version 1.1"
    );
    // project-level versions list (PEP 700)
    let versions = json["versions"]
        .as_array()
        .expect("PEP 700 project versions[] must be present");
    assert!(
        versions.iter().any(|v| v == "2.0"),
        "versions must include 2.0, got {versions:?}"
    );
    // per-file upload-time + size (PEP 700)
    let f = &json["files"][0];
    assert_eq!(
        f["upload-time"], "2021-05-11T13:00:00Z",
        "PEP 700 per-file upload-time from dates.json"
    );
    assert_eq!(f["size"], 4, "PEP 700 per-file size = bytes of 'data'");
}

#[tokio::test]
async fn test_pypi_download_local() {
    let ctx = create_test_context();

    let tarball_data = b"fake-tarball-content";
    ctx.state
        .storage
        .put("pypi/flask/flask-2.0.tar.gz", tarball_data)
        .await
        .unwrap();

    let response = send(&ctx.app, Method::GET, "/simple/flask/flask-2.0.tar.gz", "").await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_bytes(response).await;
    assert_eq!(&body[..], tarball_data);
}

#[tokio::test]
async fn test_pypi_download_range_request() {
    let ctx = create_test_context();
    let sdist = b"0123456789abcdef";
    ctx.state
        .storage
        .put("pypi/flask/flask-2.0.tar.gz", sdist)
        .await
        .unwrap();
    let url = "/simple/flask/flask-2.0.tar.gz";

    let resp =
        send_with_headers(&ctx.app, Method::GET, url, vec![("range", "bytes=2-5")], "").await;
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        resp.headers()
            .get(header::CONTENT_RANGE)
            .unwrap()
            .to_str()
            .unwrap(),
        format!("bytes 2-5/{}", sdist.len())
    );
    assert_eq!(
        resp.headers()
            .get(header::ACCEPT_RANGES)
            .unwrap()
            .to_str()
            .unwrap(),
        "bytes"
    );
    assert_eq!(
        resp.headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap(),
        "application/gzip"
    );
    assert_eq!(body_bytes(resp).await.as_ref(), &sdist[2..=5]);

    // A client that already holds the whole file resumes with `bytes=<size>-`.
    let resp = send_with_headers(
        &ctx.app,
        Method::GET,
        url,
        vec![("range", &format!("bytes={}-", sdist.len())[..])],
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        resp.headers()
            .get(header::CONTENT_RANGE)
            .unwrap()
            .to_str()
            .unwrap(),
        format!("bytes */{}", sdist.len())
    );

    let resp = send(&ctx.app, Method::GET, url, "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(header::ACCEPT_RANGES)
            .unwrap()
            .to_str()
            .unwrap(),
        "bytes"
    );
    assert_eq!(body_bytes(resp).await.as_ref(), &sdist[..]);
}

#[tokio::test]
async fn test_pypi_not_found_no_proxy() {
    let ctx = create_test_context();

    let response = send(&ctx.app, Method::GET, "/simple/nonexistent/", "").await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// Regression test for #891 path 1: internal `dates.json` must not leak
/// into the PEP 691 simple index. `uv` and other strict clients require
/// `hashes` on every file entry; `dates.json` has no sidecar → parse failure.
#[tokio::test]
async fn test_pypi_dates_json_excluded_from_index() {
    let ctx = create_test_context();

    ctx.state
        .storage
        .put("pypi/loguru/loguru-0.7.0.tar.gz", b"fake-sdist")
        .await
        .unwrap();
    ctx.state
        .storage
        .put("pypi/loguru/loguru-0.7.0.tar.gz.sha256", b"aabbccdd")
        .await
        .unwrap();
    ctx.state
        .storage
        .put(
            "pypi/loguru/dates.json",
            br#"{"loguru-0.7.0.tar.gz":"2023-08-20T12:00:00Z"}"#,
        )
        .await
        .unwrap();

    // HTML index must not contain dates.json
    let response = send(&ctx.app, Method::GET, "/simple/loguru/", "").await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_bytes(response).await;
    let html = String::from_utf8_lossy(&body);
    assert!(
        html.contains("loguru-0.7.0.tar.gz"),
        "real package must appear"
    );
    assert!(
        !html.contains("dates.json"),
        "dates.json must NOT appear in index (#891)"
    );

    // PEP 691 JSON index must also exclude dates.json
    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/simple/loguru/",
        vec![("Accept", "application/vnd.pypi.simple.v1+json")],
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_bytes(response).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let files = json["files"].as_array().unwrap();
    assert_eq!(files.len(), 1, "only the real package file, not dates.json");
    assert_eq!(files[0]["filename"], "loguru-0.7.0.tar.gz");
}

/// Regression test for #891 path 2: `GET /simple/{name}/dates.json` must
/// return 404, not serve the internal bookkeeping file.
#[tokio::test]
async fn test_pypi_dates_json_not_downloadable() {
    let ctx = create_test_context();

    ctx.state
        .storage
        .put(
            "pypi/loguru/dates.json",
            br#"{"loguru-0.7.0.tar.gz":"2023-08-20T12:00:00Z"}"#,
        )
        .await
        .unwrap();

    let response = send(&ctx.app, Method::GET, "/simple/loguru/dates.json", "").await;
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "internal dates.json must not be downloadable (#891)"
    );
}

/// Regression test for #905: `ensure_pypi_dates_cached` must never fetch
/// an internal-namespace package's metadata upstream (#68 dependency
/// A file whose version cannot be read from its name is refused by the
/// allowlist, not passed on as a metadata request.
#[tokio::test]
async fn allowlist_refuses_a_file_whose_version_it_cannot_read() {
    use crate::test_helpers::create_test_context_with_config;
    let dir = tempfile::tempdir().unwrap();
    let allowlist = dir.path().join("allowlist.json");
    std::fs::write(
        &allowlist,
        r#"{"version": 1, "entries": [{"registry": "pypi", "name": "pkg", "version": "1.0.0"}]}"#,
    )
    .unwrap();
    let allowlist = allowlist.to_string_lossy().into_owned();
    let ctx = create_test_context_with_config(|cfg| {
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.allowlist_path = Some(allowlist);
    });
    ctx.state
        .storage
        .put("pypi/pkg/weird.tar.gz", b"sdist")
        .await
        .unwrap();
    let resp = send(&ctx.app, Method::GET, "/simple/pkg/weird.tar.gz", "").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let resp = send(&ctx.app, Method::GET, "/simple/pkg/", "").await;
    assert_ne!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "control: the index passes"
    );
}

/// confusion). Verify that a tarball download for an internal-namespace
/// package does not trigger any upstream requests for the dates endpoint.
#[tokio::test]
async fn test_pypi_self_prime_skips_internal_namespace() {
    use crate::test_helpers::create_test_context_with_config;
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;

    // Any request to the upstream = test failure (the guard must prevent it).
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("LEAKED"))
        .mount(&upstream)
        .await;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.pypi.proxy = Some(upstream.uri());
        cfg.server.trust_upstream_dates = true;
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.internal_namespaces = vec!["internal-*".to_string()];
    });

    // Pre-populate a tarball so the download path is exercised.
    ctx.state
        .storage
        .put(
            "pypi/internal-secret/internal_secret-1.0.0.tar.gz",
            b"fake-sdist",
        )
        .await
        .unwrap();
    ctx.state
        .storage
        .put(
            "pypi/internal-secret/internal_secret-1.0.0.tar.gz.sha256",
            b"aabbccdd",
        )
        .await
        .unwrap();

    // Download the tarball — this triggers ensure_pypi_dates_cached.
    let _resp = send(
        &ctx.app,
        Method::GET,
        "/simple/internal-secret/internal_secret-1.0.0.tar.gz",
        "",
    )
    .await;

    // The internal-namespace guard must have prevented any upstream fetch.
    let upstream_hits = upstream.received_requests().await.unwrap().len();
    assert_eq!(
        upstream_hits, 0,
        "internal-namespace package dates must never be fetched upstream (#68, #905)"
    );

    // dates.json must NOT have been written for an internal package.
    assert!(
        ctx.state
            .storage
            .get("pypi/internal-secret/dates.json")
            .await
            .is_err(),
        "dates.json must not be created for internal-namespace packages"
    );
}

/// #969 A/B: the simple JSON must take each file's PEP 700 `size` from the listing
/// (`list_with_meta`) and NEVER `stat()` per file. On S3 a `stat()` is a HEAD
/// round-trip, and they were issued serially over the whole merged file list, so
/// `/simple/{name}/` cost one HEAD per file — hundreds to tens of thousands for a
/// proxied index — and uv timed out. A backend that counts `stat()` proves the JSON
/// index now issues ZERO of them while still emitting the correct size.
/// Same class as #738 on the Docker index rebuild.
#[tokio::test]
async fn pypi_simple_json_uses_list_with_meta_not_per_key_stat() {
    use crate::storage::{FileMeta, ObjectStorage, Storage, StorageBackend};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Delegates every operation to a real in-memory object store, counting
    /// `stat()` calls. `list_with_meta` is inherited from the inner store, so the
    /// listing still carries real sizes.
    struct StatCounting {
        inner: ObjectStorage,
        stat_calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl StorageBackend for StatCounting {
        async fn stat(&self, key: &str) -> Option<FileMeta> {
            self.stat_calls.fetch_add(1, Ordering::SeqCst);
            self.inner.stat(key).await
        }
        async fn put(&self, k: &str, d: &[u8], sha256: &str) -> crate::storage::Result<()> {
            self.inner.put(k, d, sha256).await
        }
        async fn get(
            &self,
            k: &str,
        ) -> crate::storage::Result<(axum::body::Bytes, Option<String>)> {
            self.inner.get(k).await
        }
        async fn pin(&self, k: &str) -> Option<String> {
            self.inner.pin(k).await
        }
        async fn delete(&self, k: &str) -> crate::storage::Result<()> {
            self.inner.delete(k).await
        }
        async fn list(&self, prefix: &str) -> crate::storage::Result<Vec<String>> {
            self.inner.list(prefix).await
        }
        async fn list_with_meta(
            &self,
            prefix: &str,
        ) -> crate::storage::Result<Vec<(String, FileMeta)>> {
            self.inner.list_with_meta(prefix).await
        }
        async fn health_check(&self) -> bool {
            self.inner.health_check().await
        }
        async fn total_size(&self) -> u64 {
            self.inner.total_size().await
        }
        fn backend_name(&self) -> &'static str {
            "stat-counting-test"
        }
        async fn put_from_path(
            &self,
            k: &str,
            src: &std::path::Path,
            sha256: Option<&str>,
        ) -> crate::storage::Result<()> {
            self.inner.put_from_path(k, src, sha256).await
        }
        async fn copy(
            &self,
            src: &str,
            dst: &str,
            sha256: Option<&str>,
        ) -> crate::storage::Result<()> {
            self.inner.copy(src, dst, sha256).await
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

    let stat_calls = Arc::new(AtomicUsize::new(0));
    let ctx = crate::test_helpers::create_test_context_with_storage(Storage::from_backend(
        Arc::new(StatCounting {
            inner: ObjectStorage::in_memory(),
            stat_calls: Arc::clone(&stat_calls),
        }),
    ));
    ctx.state
        .storage
        .put("pypi/flask/flask-2.0.tar.gz", b"data")
        .await
        .unwrap();
    ctx.state
        .storage
        .put("pypi/flask/flask-2.0.tar.gz.sha256", b"deadbeef")
        .await
        .unwrap();
    stat_calls.store(0, Ordering::SeqCst);

    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/simple/flask/",
        vec![("Accept", "application/vnd.pypi.simple.v1+json")],
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    assert_eq!(
        stat_calls.load(Ordering::SeqCst),
        0,
        "#969: the simple JSON must not stat() per file — size comes from list_with_meta"
    );
    // Correctness preserved: the size still reaches the response.
    let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
    assert_eq!(
        json["files"][0]["size"], 4,
        "PEP 700 size must survive the stat-free path"
    );
}

/// #969: an upstream that answers the PEP 691 JSON but carries no `upload-time`
/// (any pre-PEP-700 index) left nothing cached, so EVERY `/simple/{name}/` JSON
/// request re-downloaded the whole upstream JSON index. The answered-but-dateless
/// result is now cached once; the second request must not fetch it again.
#[tokio::test]
async fn test_pypi_dateless_upstream_json_is_fetched_once() {
    use super::PEP691_JSON;
    use crate::test_helpers::create_test_context_with_config;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    // PEP 691 JSON without any `upload-time` — a pre-PEP-700 upstream.
    Mock::given(method("GET"))
        .and(path("/flask/"))
        .and(header("accept", PEP691_JSON))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"meta":{"api-version":"1.0"},"name":"flask","files":[{"filename":"flask-2.0.tar.gz","url":"https://up/flask-2.0.tar.gz"}]}"#,
        ))
        .mount(&upstream)
        .await;
    // The PEP 503 HTML listing the index itself merges.
    Mock::given(method("GET"))
        .and(path("/flask/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<html><body><a href="https://up/flask-2.0.tar.gz">flask-2.0.tar.gz</a></body></html>"#,
        ))
        .mount(&upstream)
        .await;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.pypi.proxy = Some(upstream.uri());
    });

    for _ in 0..2 {
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/flask/",
            vec![("Accept", "application/vnd.pypi.simple.v1+json")],
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    let json_fetches = upstream
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| {
            r.headers
                .get("accept")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v == PEP691_JSON)
        })
        .count();
    assert_eq!(
        json_fetches, 1,
        "#969: a dateless upstream JSON index must be fetched once, not per request"
    );
    // The listing is what got cached, without a date: no upload-time for the file,
    // as for an absent dates.json, while the entry still records that it was listed.
    assert_eq!(
        &ctx.state
            .storage
            .get("pypi/flask/dates.json")
            .await
            .unwrap()[..],
        br#"{"flask-2.0.tar.gz":null}"#,
        "an answered-but-dateless upstream is recorded without dates"
    );
}

/// #969: a failed upstream fetch must cache nothing, so a transient outage stays
/// retryable. Only an upstream that actually answered may record the empty map.
#[tokio::test]
async fn test_pypi_dates_not_cached_when_upstream_fetch_fails() {
    use super::PEP691_JSON;
    use crate::test_helpers::create_test_context_with_config;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    // The JSON index is down; the HTML listing still answers.
    Mock::given(method("GET"))
        .and(path("/flask/"))
        .and(header("accept", PEP691_JSON))
        .respond_with(ResponseTemplate::new(500))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/flask/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<html><body><a href="https://up/flask-2.0.tar.gz">flask-2.0.tar.gz</a></body></html>"#,
        ))
        .mount(&upstream)
        .await;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.pypi.proxy = Some(upstream.uri());
    });

    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/simple/flask/",
        vec![("Accept", PEP691_JSON)],
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "the index still serves");
    assert!(
        ctx.state
            .storage
            .get("pypi/flask/dates.json")
            .await
            .is_err(),
        "#969: a failed upstream fetch must cache nothing — the outage must stay retryable"
    );
}

/// A corrupt `dates.json` (hand-edited, truncated write) must not fail the index:
/// the PEP 700 `upload-time` is optional, so it is simply omitted while `size`
/// still comes from the listing.
#[tokio::test]
async fn test_pypi_simple_json_survives_corrupt_dates_json() {
    let ctx = create_test_context();
    ctx.state
        .storage
        .put("pypi/flask/flask-2.0.tar.gz", b"data")
        .await
        .unwrap();
    ctx.state
        .storage
        .put("pypi/flask/dates.json", b"{ this is not json")
        .await
        .unwrap();

    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/simple/flask/",
        vec![("Accept", "application/vnd.pypi.simple.v1+json")],
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
    assert_eq!(
        json["files"][0]["size"], 4,
        "size survives a corrupt dates.json"
    );
    assert!(
        json["files"][0].get("upload-time").is_none(),
        "an unparsable dates.json omits upload-time instead of failing the index"
    );
}

/// PEP 700 `size` is only knowable for files NORA actually stores. In a merged
/// index the local file carries a size and the upstream-only file does not —
/// the same outcome the old per-file `stat()` produced (it 404'd on those),
/// reached without the round-trip.
#[tokio::test]
async fn test_pypi_simple_json_size_only_for_local_files() {
    use super::PEP691_JSON;
    use crate::test_helpers::create_test_context_with_config;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/flask/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<html><body>
                   <a href="https://up/flask-2.0.tar.gz">flask-2.0.tar.gz</a>
                   <a href="https://up/flask-3.0.tar.gz">flask-3.0.tar.gz</a>
                   </body></html>"#,
        ))
        .mount(&upstream)
        .await;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.pypi.proxy = Some(upstream.uri());
    });
    // Only 2.0 is cached locally.
    ctx.state
        .storage
        .put("pypi/flask/flask-2.0.tar.gz", b"seven!!")
        .await
        .unwrap();

    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/simple/flask/",
        vec![("Accept", PEP691_JSON)],
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
    let files = json["files"].as_array().expect("files array");
    assert_eq!(files.len(), 2, "both files are listed: {files:?}");
    let by_name = |n: &str| {
        files
            .iter()
            .find(|f| f["filename"] == n)
            .unwrap_or_else(|| panic!("{n} missing from {files:?}"))
    };
    assert_eq!(
        by_name("flask-2.0.tar.gz")["size"],
        7,
        "the locally stored file carries its real size"
    );
    assert!(
        by_name("flask-3.0.tar.gz").get("size").is_none(),
        "an upstream-only file has no local size and must omit the field"
    );
}

/// #969 class invariant (the one #738 should have carried): the simple JSON must
/// cost the SAME number of storage round-trips whatever the size of the index it
/// renders. Rendering a 1-file index and a 100-file index must issue an identical
/// op count — anything proportional to the file list is an N+1 by construction,
/// and on S3 every op is a network round-trip.
#[tokio::test]
async fn pypi_simple_json_cost_is_independent_of_index_size() {
    use super::PEP691_JSON;
    use crate::test_helpers::{create_test_context_with_storage_and_config, op_counting_storage};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Serve an upstream index of `n` files and return the storage ops one JSON
    /// index request costs.
    async fn ops_for_index(n: usize) -> usize {
        let links: String = (1..=n)
            .map(|i| format!("<a href=\"https://up/pkg-{i}.0.tar.gz\">pkg-{i}.0.tar.gz</a>\n"))
            .collect();
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pkg/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(format!("<html><body>{links}</body></html>")),
            )
            .mount(&upstream)
            .await;

        let (storage, ops) = op_counting_storage();
        let ctx = create_test_context_with_storage_and_config(storage, |cfg| {
            cfg.pypi.proxy = Some(upstream.uri());
        });
        ops.reset();
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/pkg/",
            vec![("Accept", PEP691_JSON)],
            "",
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "index of {n} files served"
        );
        ops.total()
    }

    let small = ops_for_index(1).await;
    let large = ops_for_index(100).await;
    assert_eq!(
        small, large,
        "#969: rendering the simple JSON must cost the same storage round-trips for a \
             1-file and a 100-file index — {small} vs {large} means the cost scales with N"
    );
}

/// A proxied file whose bytes do not match the index `#sha256` is refused with
/// 502 and never cached; a matching one is served.
#[tokio::test]
async fn test_pypi_proxy_rejects_sha256_mismatch() {
    use crate::test_helpers::create_test_context_with_config;
    use sha2::Digest;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    let good = hex::encode(sha2::Sha256::digest(b"good-bytes"));
    let index = format!(
        r#"<a href="{0}/files/pkg-1.0.tar.gz#sha256={1}">a</a><a href="{0}/files/pkg-1.1.tar.gz#sha256={1}">b</a>"#,
        upstream.uri(),
        good
    );
    Mock::given(method("GET"))
        .and(path("/pkg/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(index))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/files/pkg-1.0.tar.gz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(&b"tampered"[..]))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/files/pkg-1.1.tar.gz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(&b"good-bytes"[..]))
        .mount(&upstream)
        .await;
    let ctx = create_test_context_with_config(|cfg| {
        cfg.pypi.proxy = Some(upstream.uri());
    });

    let bad = send(&ctx.app, Method::GET, "/simple/pkg/pkg-1.0.tar.gz", "").await;
    assert_eq!(bad.status(), StatusCode::BAD_GATEWAY);
    let ok = send(&ctx.app, Method::GET, "/simple/pkg/pkg-1.1.tar.gz", "").await;
    assert_eq!(ok.status(), StatusCode::OK);
    assert_eq!(body_bytes(ok).await.as_ref(), b"good-bytes");

    // Let the background cache write of the good file land, then check neither
    // the bad file nor its sidecar was stored.
    for _ in 0..50 {
        if ctx
            .state
            .storage
            .stat("pypi/pkg/pkg-1.1.tar.gz")
            .await
            .is_some()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(ctx
        .state
        .storage
        .stat("pypi/pkg/pkg-1.1.tar.gz")
        .await
        .is_some());
    assert!(ctx
        .state
        .storage
        .stat("pypi/pkg/pkg-1.0.tar.gz")
        .await
        .is_none());
    assert!(ctx
        .state
        .storage
        .stat("pypi/pkg/pkg-1.0.tar.gz.sha256")
        .await
        .is_none());
}

/// C17: a file above `server.stream_threshold_mb` is spooled on the cold miss,
/// checked against the index `#sha256` by the digest taken while spooling (a
/// mismatch is a 502), cached pinned, then streamed from storage on the next hit.
#[tokio::test]
async fn test_large_file_spooled_then_streamed_from_cache() {
    use crate::test_helpers::{body_bytes, create_test_context_with_config};
    use sha2::Digest;
    use wiremock::matchers::path;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let file: Vec<u8> = (0..(2 * 1024 * 1024 + 9))
        .map(|i| (i % 241) as u8)
        .collect();
    let sha = hex::encode(sha2::Sha256::digest(&file));
    let upstream = MockServer::start().await;
    let page = format!(
        r#"<a href="{0}/files/bigpy-1.0.tar.gz#sha256={sha}">bigpy-1.0.tar.gz</a>
<a href="{0}/files/bigpy-2.0.tar.gz#sha256={1}">bigpy-2.0.tar.gz</a>"#,
        upstream.uri(),
        "0".repeat(64),
    );
    Mock::given(path("/bigpy/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(page))
        .mount(&upstream)
        .await;
    for f in ["bigpy-1.0.tar.gz", "bigpy-2.0.tar.gz"] {
        Mock::given(path(format!("/files/{f}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(file.clone()))
            .mount(&upstream)
            .await;
    }
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.pypi.proxy = Some(uri);
        cfg.server.stream_threshold_mb = 1;
    });

    let resp = send(&ctx.app, Method::GET, "/simple/bigpy/bigpy-2.0.tar.gz", "").await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_GATEWAY,
        "index sha256 mismatch"
    );

    let resp = send(&ctx.app, Method::GET, "/simple/bigpy/bigpy-1.0.tar.gz", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_bytes(resp).await[..] == file[..]);
    let key = "pypi/bigpy/bigpy-1.0.tar.gz";
    let mut cached = false;
    for _ in 0..100 {
        if ctx.state.storage.pin(key).await.as_deref() == Some(sha.as_str()) {
            cached = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(cached, "the spooled file is cached pinned");
    for _ in 0..100 {
        if ctx
            .state
            .storage
            .get(&super::proxied_marker_key(key))
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        ctx.state
            .storage
            .get(&super::proxied_marker_key(key))
            .await
            .is_ok(),
        "a file cached from upstream carries the provenance marker (C22)"
    );

    let resp = send(&ctx.app, Method::GET, "/simple/bigpy/bigpy-1.0.tar.gz", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_bytes(resp).await[..] == file[..]);
    let fetches = upstream
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == "/files/bigpy-1.0.tar.gz")
        .count();
    assert_eq!(fetches, 1, "the hit is served from storage");
}

/// An upstream outage with nothing local is a 502 (pip retries it), and a real
/// upstream 404 stays a 404 — before, both were a 404 pip cached as "no such project".
#[tokio::test]
async fn test_pypi_upstream_outage_is_502_not_404() {
    use crate::test_helpers::create_test_context_with_config;
    use wiremock::matchers::path;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(path("/down/"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&upstream)
        .await;
    Mock::given(path("/gone/"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&upstream)
        .await;
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.pypi.proxy = Some(uri);
    });

    for (uri, want) in [
        ("/simple/down/", StatusCode::BAD_GATEWAY),
        ("/simple/gone/", StatusCode::NOT_FOUND),
        ("/simple/down/down-1.0.tar.gz", StatusCode::BAD_GATEWAY),
        ("/simple/gone/gone-1.0.tar.gz", StatusCode::NOT_FOUND),
    ] {
        let resp = send(&ctx.app, Method::GET, uri, "").await;
        assert_eq!(resp.status(), want, "{uri}");
    }
}

/// A twine multipart body: `fields`, then `content` as `filename`.
fn twine_body(fields: &[(&str, &str)], filename: &str, content: &[u8]) -> (String, Vec<u8>) {
    const B: &str = "nora-r2-boundary";
    let mut body = Vec::new();
    for (field, value) in [(":action", "file_upload")].iter().chain(fields) {
        body.extend_from_slice(
            format!("--{B}\r\nContent-Disposition: form-data; name=\"{field}\"\r\n\r\n{value}\r\n")
                .as_bytes(),
        );
    }
    body.extend_from_slice(
        format!(
            "--{B}\r\nContent-Disposition: form-data; name=\"content\"; filename=\"{filename}\"\r\n\
                 Content-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{B}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={B}"), body)
}

async fn twine_upload(
    app: &axum::Router,
    fields: &[(&str, &str)],
    filename: &str,
    content: &[u8],
) -> axum::http::Response<axum::body::Body> {
    let (content_type, body) = twine_body(fields, filename, content);
    send_with_headers(
        app,
        Method::POST,
        "/simple/",
        vec![("content-type", content_type.as_str())],
        body,
    )
    .await
}

/// R2-05: an upload spools under `server.spool_max_mb`: while other spools hold
/// the budget it is a 503 + Retry-After, a file bigger than the whole budget a
/// 507, and neither leaves a file behind.
#[tokio::test]
async fn upload_over_the_spool_budget_is_refused_and_leaves_no_spool() {
    let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
        cfg.server.spool_max_mb = 4;
    });
    let upload = |mib: usize| {
        let app = ctx.app.clone();
        async move {
            twine_upload(
                &app,
                &[("name", "big"), ("version", "1.0")],
                "big-1.0.tar.gz",
                &vec![0u8; mib * 1024 * 1024],
            )
            .await
        }
    };
    let held = ctx.state.spool.reserve(3 * 1024 * 1024).unwrap();
    let resp = upload(2).await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(resp.headers().contains_key(header::RETRY_AFTER));
    drop(held);
    assert_eq!(upload(5).await.status(), StatusCode::INSUFFICIENT_STORAGE);
    let dir = ctx.state.spool.dir(crate::registry::PYPI_UPLOAD_SUBDIR);
    assert_eq!(std::fs::read_dir(dir).unwrap().count(), 0);
}

/// A wheel holding `{dist_info}/METADATA` and one module.
fn wheel(dist_info: &str, metadata: &str) -> Vec<u8> {
    use std::io::Write;
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    w.start_file(format!("{dist_info}/METADATA"), opts).unwrap();
    w.write_all(metadata.as_bytes()).unwrap();
    w.start_file("pkg/__init__.py", opts).unwrap();
    w.write_all(b"x = 1\n").unwrap();
    w.finish().unwrap().into_inner()
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(data))
}

async fn text(resp: axum::http::Response<axum::body::Body>) -> String {
    String::from_utf8(body_bytes(resp).await.to_vec()).unwrap()
}

/// C36: an uploaded wheel's `.dist-info/METADATA` is served as `<wheel>.metadata`
/// (PEP 658) and advertised with its digest; twine's `requires_python` is kept and
/// listed in both index forms.
#[tokio::test]
async fn hosted_wheel_serves_core_metadata_and_requires_python() {
    let ctx = create_test_context();
    let metadata = "Metadata-Version: 2.1\nName: hostpkg\nVersion: 1.0\nRequires-Python: >=3.9\n";
    let whl = wheel("hostpkg-1.0.dist-info", metadata);
    let resp = twine_upload(
        &ctx.app,
        &[
            ("name", "hostpkg"),
            ("version", "1.0"),
            ("requires_python", ">=3.9"),
        ],
        "hostpkg-1.0-py3-none-any.whl",
        &whl,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = twine_upload(
        &ctx.app,
        &[("name", "hostpkg"), ("version", "1.0")],
        "hostpkg-1.0.tar.gz",
        b"sdist",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let digest = sha256_hex(metadata.as_bytes());
    let html = text(send(&ctx.app, Method::GET, "/simple/hostpkg/", "").await).await;
    let wheel_line = html
        .lines()
        .find(|l| l.contains("hostpkg-1.0-py3-none-any.whl"))
        .unwrap();
    assert!(
        wheel_line.contains(&format!("data-core-metadata=\"sha256={digest}\"")),
        "{wheel_line}"
    );
    assert!(
        wheel_line.contains("data-requires-python=\"&gt;=3.9\""),
        "{wheel_line}"
    );
    let sdist_line = html
        .lines()
        .find(|l| l.contains("hostpkg-1.0.tar.gz"))
        .unwrap();
    assert!(!sdist_line.contains("data-core-metadata"), "{sdist_line}");
    assert!(!sdist_line.contains("data-requires-python"), "{sdist_line}");

    let resp = send_with_headers(
        &ctx.app,
        Method::GET,
        "/simple/hostpkg/",
        vec![("Accept", "application/vnd.pypi.simple.v1+json")],
        "",
    )
    .await;
    let json: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    let file = json["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["filename"] == "hostpkg-1.0-py3-none-any.whl")
        .unwrap();
    assert_eq!(file["core-metadata"]["sha256"], digest.as_str());
    assert_eq!(file["requires-python"], ">=3.9");

    let resp = send(
        &ctx.app,
        Method::GET,
        "/simple/hostpkg/hostpkg-1.0-py3-none-any.whl.metadata",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(text(resp).await, metadata);
    // No metadata for an sdist, and none for a wheel nora does not have.
    for uri in [
        "/simple/hostpkg/hostpkg-1.0.tar.gz.metadata",
        "/simple/hostpkg/hostpkg-2.0-py3-none-any.whl.metadata",
    ] {
        let resp = send(&ctx.app, Method::GET, uri, "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{uri}");
    }
}

/// C36: an upstream-only wheel's `.metadata` is proxied only where the upstream's
/// index advertises one, checked against the advertised digest; a wheel cached from
/// upstream gets its own `.metadata` extracted and advertised.
#[tokio::test]
async fn proxied_core_metadata_follows_the_upstream_advertisement() {
    use crate::test_helpers::create_test_context_with_config;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    let meta = "Metadata-Version: 2.1\nName: uppkg\nVersion: 1.0\n";
    let whl = wheel("uppkg-1.0.dist-info", meta);
    let index = format!(
        r#"<a href="{u}/f/uppkg-1.0-py3-none-any.whl#sha256={w}" data-core-metadata="sha256={m}">a</a>
<a href="{u}/f/uppkg-1.1-py3-none-any.whl" data-dist-info-metadata="sha256={m}">b</a>
<a href="{u}/f/uppkg-1.2-py3-none-any.whl">c</a>"#,
        u = upstream.uri(),
        w = sha256_hex(&whl),
        m = sha256_hex(meta.as_bytes()),
    );
    Mock::given(method("GET"))
        .and(path("/uppkg/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(index))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/f/uppkg-1.0-py3-none-any.whl.metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_string(meta))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/f/uppkg-1.1-py3-none-any.whl.metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_string("tampered"))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/f/uppkg-1.0-py3-none-any.whl"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(whl.clone()))
        .mount(&upstream)
        .await;
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| cfg.pypi.proxy = Some(uri));

    let html = text(send(&ctx.app, Method::GET, "/simple/uppkg/", "").await).await;
    assert_eq!(html.matches("data-core-metadata=").count(), 2, "{html}");

    let ok = send(
        &ctx.app,
        Method::GET,
        "/simple/uppkg/uppkg-1.0-py3-none-any.whl.metadata",
        "",
    )
    .await;
    assert_eq!(ok.status(), StatusCode::OK);
    assert_eq!(text(ok).await, meta);
    let bad = send(
        &ctx.app,
        Method::GET,
        "/simple/uppkg/uppkg-1.1-py3-none-any.whl.metadata",
        "",
    )
    .await;
    assert_eq!(bad.status(), StatusCode::BAD_GATEWAY, "digest mismatch");
    let none = send(
        &ctx.app,
        Method::GET,
        "/simple/uppkg/uppkg-1.2-py3-none-any.whl.metadata",
        "",
    )
    .await;
    assert_eq!(
        none.status(),
        StatusCode::NOT_FOUND,
        "not advertised upstream"
    );

    // Cache the wheel: its metadata is extracted and stored next to it.
    let resp = send(
        &ctx.app,
        Method::GET,
        "/simple/uppkg/uppkg-1.0-py3-none-any.whl",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let sidecar = "pypi/uppkg/uppkg-1.0-py3-none-any.whl.metadata";
    for _ in 0..100 {
        if ctx.state.storage.stat(sidecar).await.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        &ctx.state.storage.get(sidecar).await.unwrap()[..],
        meta.as_bytes()
    );
}

/// C37: the upload body is spooled to disk, stored byte for byte, and the spool file
/// is gone afterwards, also when the upload is refused.
#[tokio::test]
async fn upload_spools_content_and_cleans_up() {
    let ctx = create_test_context();
    let spool = std::path::PathBuf::from(&ctx.state.config.storage.path).join("tmp/pypi-uploads");
    let content: Vec<u8> = (0..3 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    let resp = twine_upload(
        &ctx.app,
        &[
            ("name", "big"),
            ("version", "1.0"),
            ("sha256_digest", &sha256_hex(&content)),
        ],
        "big-1.0.tar.gz",
        &content,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        &ctx.state
            .storage
            .get("pypi/big/big-1.0.tar.gz")
            .await
            .unwrap()[..],
        &content[..]
    );

    let resp = twine_upload(
        &ctx.app,
        &[
            ("name", "big"),
            ("version", "1.1"),
            ("sha256_digest", &"0".repeat(64)),
        ],
        "big-1.1.tar.gz",
        &content,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "digest mismatch");
    assert!(ctx
        .state
        .storage
        .stat("pypi/big/big-1.1.tar.gz")
        .await
        .is_none());
    let left = std::fs::read_dir(&spool).map(|d| d.count()).unwrap_or(0);
    assert_eq!(left, 0, "no spool file is left behind");
}

/// Invariant: an internal-namespace project uploaded here never depends on the
/// upstream. With a dead upstream, its simple index (HTML and JSON) and its file
/// are 200 and the upstream sees no request at all.
#[tokio::test]
async fn internal_project_never_touches_a_dead_upstream() {
    use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};
    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(503))
        .mount(&upstream)
        .await;
    let uri = upstream.uri();
    let ctx = crate::test_helpers::create_test_context_with_config(move |cfg| {
        cfg.pypi.proxy = Some(uri);
        cfg.pypi.metadata_ttl = 0;
        cfg.curation.internal_namespaces = vec!["corp-*".to_string()];
    });
    let content = b"sdist-bytes".to_vec();
    let resp = twine_upload(
        &ctx.app,
        &[("name", "corp-lib"), ("version", "1.0")],
        "corp-lib-1.0.tar.gz",
        &content,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    assert!(
        ctx.state
            .storage
            .get(&super::proxied_marker_key(
                "pypi/corp-lib/corp-lib-1.0.tar.gz"
            ))
            .await
            .is_err(),
        "an uploaded file never carries the provenance marker (C22)"
    );
    let resp = send(&ctx.app, Method::GET, "/simple/corp-lib/", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(String::from_utf8_lossy(&body_bytes(resp).await).contains("corp-lib-1.0.tar.gz"));
    let resp = send_with_headers(
        &ctx.app,
        Method::GET,
        "/simple/corp-lib/",
        vec![("accept", "application/vnd.pypi.simple.v1+json")],
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = send(
        &ctx.app,
        Method::GET,
        "/simple/corp-lib/corp-lib-1.0.tar.gz",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(&body_bytes(resp).await[..], &content[..]);
    let seen = upstream.received_requests().await.unwrap();
    assert!(
        seen.is_empty(),
        "upstream contacted: {:?}",
        seen.iter()
            .map(|r| r.url.path().to_string())
            .collect::<Vec<_>>()
    );
}

/// R4-R17: a text form field is read under a small cap, not buffered whole.
#[tokio::test]
async fn upload_refuses_an_oversized_text_field() {
    let ctx = create_test_context();
    let long = "a".repeat(super::MAX_UPLOAD_TEXT_FIELD + 1);
    for field in [
        "name",
        "version",
        "sha256_digest",
        "requires_python",
        ":action",
    ] {
        let mut fields = vec![("name", "foo"), ("version", "1.0")];
        fields.retain(|(name, _)| *name != field);
        fields.push((field, long.as_str()));
        let resp = twine_upload(&ctx.app, &fields, "foo-1.0.tar.gz", b"data").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{field}");
        let body = crate::test_helpers::body_bytes(resp).await;
        assert!(body.ends_with(b"exceeds 8192 bytes"), "{field}: {body:?}");
    }
    let fits = "a".repeat(super::MAX_UPLOAD_TEXT_FIELD);
    let fields = [
        ("name", "foo"),
        ("version", "1.0"),
        ("requires_python", &fits),
    ];
    let resp = twine_upload(&ctx.app, &fields, "foo-1.0.tar.gz", b"data").await;
    assert_eq!(resp.status(), StatusCode::OK);
}

/// C44: the uploaded filename must name the form's project and version.
#[tokio::test]
async fn upload_rejects_a_filename_of_another_project_or_version() {
    let ctx = create_test_context();
    for (name, version, filename, want) in [
        (
            "foo",
            "1.0",
            "requests-99.0-py3-none-any.whl",
            StatusCode::BAD_REQUEST,
        ),
        ("foo", "1.0", "foo-2.0.tar.gz", StatusCode::BAD_REQUEST),
        ("foo", "1.0", "foo-1.0.0-py3-none-any.whl", StatusCode::OK),
        (
            "Foo.Bar",
            "V1.0-RC.1",
            "foo_bar-1.0rc1.tar.gz",
            StatusCode::OK,
        ),
    ] {
        let resp = twine_upload(
            &ctx.app,
            &[("name", name), ("version", version)],
            filename,
            b"data",
        )
        .await;
        assert_eq!(resp.status(), want, "{name} {version} {filename}");
    }
    assert!(ctx
        .state
        .storage
        .stat("pypi/foo/requests-99.0-py3-none-any.whl")
        .await
        .is_none());
}

/// Q02: a release published upstream after `dates.json` was cached is not in it; a
/// download of it refreshes the dates, so a `min_release_age` cooldown holds it
/// instead of letting an undated file through.
#[tokio::test]
async fn new_release_missing_from_cached_dates_is_held_by_min_release_age() {
    use crate::test_helpers::create_test_context_with_config;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    let u = upstream.uri();
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    Mock::given(method("GET"))
        .and(path("/fresh/"))
        .and(header("accept", super::PEP691_JSON))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            r#"{{"meta":{{"api-version":"1.1"}},"name":"fresh","files":[
                {{"filename":"fresh-1.0.tar.gz","url":"{u}/f/fresh-1.0.tar.gz","upload-time":"2020-01-01T00:00:00Z"}},
                {{"filename":"fresh-2.0.tar.gz","url":"{u}/f/fresh-2.0.tar.gz","upload-time":"{now}"}}]}}"#
        )))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/fresh/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            r#"<a href="{u}/f/fresh-1.0.tar.gz">a</a><a href="{u}/f/fresh-2.0.tar.gz">b</a>"#
        )))
        .mount(&upstream)
        .await;
    for v in ["1.0", "2.0"] {
        Mock::given(method("GET"))
            .and(path(format!("/f/fresh-{v}.tar.gz")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"sdist".to_vec()))
            .mount(&upstream)
            .await;
    }
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.pypi.proxy = Some(u);
        cfg.server.trust_upstream_dates = true;
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.min_release_age = Some("7d".to_string());
    });
    // The snapshot cached before 2.0 was published, an hour ago.
    let dates = "pypi/fresh/dates.json";
    ctx.state
        .storage
        .put(dates, br#"{"fresh-1.0.tar.gz":"2020-01-01T00:00:00Z"}"#)
        .await
        .unwrap();
    let file = std::path::Path::new(&ctx.state.config.storage.path).join(dates);
    std::fs::File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(3600))
        .unwrap();

    let resp = send(&ctx.app, Method::GET, "/simple/fresh/fresh-2.0.tar.gz", "").await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a release published today is held"
    );
    let resp = send(&ctx.app, Method::GET, "/simple/fresh/fresh-1.0.tar.gz", "").await;
    assert_eq!(resp.status(), StatusCode::OK, "an old release passes");
    let cached: serde_json::Value =
        serde_json::from_slice(&ctx.state.storage.get(dates).await.unwrap()).unwrap();
    assert!(
        cached.get("fresh-2.0.tar.gz").is_some(),
        "the dates were refreshed"
    );
}

/// R2-23, R2-45: a file uploaded here (internal namespace or not) is never held by
/// the digest quarantine and never dated upstream: its downloads cost no upstream
/// request, even with a dead upstream. A proxied copy (provenance marker) still is held.
#[tokio::test]
async fn uploaded_files_are_neither_quarantined_nor_dated_upstream() {
    use crate::test_helpers::create_test_context_with_config;
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(500))
        .mount(&upstream)
        .await;
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.pypi.proxy = Some(uri);
        cfg.server.trust_upstream_dates = true;
        cfg.curation.quarantine = Some(crate::digest_quarantine::QuarantineMode::Enforce);
        cfg.curation.quarantine_ttl = Some("1h".to_string());
        cfg.curation.internal_namespaces = vec!["intpkg".to_string()];
    });
    for project in ["intpkg", "ownpkg"] {
        let file = format!("{project}-1.0.tar.gz");
        let resp = twine_upload(
            &ctx.app,
            &[("name", project), ("version", "1.0")],
            &file,
            b"sdist",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        for _ in 0..2 {
            let uri = format!("/simple/{project}/{file}");
            let resp = send(&ctx.app, Method::GET, &uri, "").await;
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
            assert_eq!(text(resp).await, "sdist");
        }
    }
    assert!(
        upstream.received_requests().await.unwrap().is_empty(),
        "an uploaded file is never looked up upstream"
    );

    let key = "pypi/cached/cached-1.0.tar.gz";
    ctx.state.storage.put(key, b"proxied").await.unwrap();
    ctx.state
        .storage
        .put(&super::proxied_marker_key(key), b"")
        .await
        .unwrap();
    let resp = send(
        &ctx.app,
        Method::GET,
        "/simple/cached/cached-1.0.tar.gz",
        "",
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a proxied copy is held"
    );
}

/// R2-24: the index and its dates are one snapshot. A dates map cached before a
/// release (fresh by its own clock) no longer lets an index refresh list the release
/// undated, nor its download through the `min_release_age` cooldown.
#[tokio::test]
async fn index_refresh_dates_the_files_it_lists() {
    use crate::test_helpers::create_test_context_with_config;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    let u = upstream.uri();
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    Mock::given(method("GET"))
        .and(path("/fresh/"))
        .and(header("accept", super::PEP691_JSON))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            r#"{{"files":[
                {{"filename":"fresh-1.0.tar.gz","upload-time":"2020-01-01T00:00:00Z"}},
                {{"filename":"fresh-2.0.tar.gz","upload-time":"{now}"}}]}}"#
        )))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/fresh/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            r#"<a href="{u}/f/fresh-1.0.tar.gz">a</a><a href="{u}/f/fresh-2.0.tar.gz">b</a>"#
        )))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/f/fresh-2.0.tar.gz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"sdist".to_vec()))
        .mount(&upstream)
        .await;
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.pypi.proxy = Some(u);
        cfg.server.trust_upstream_dates = true;
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.min_release_age = Some("7d".to_string());
    });
    // Just cached (by a download miss of another file), before 2.0 was published.
    ctx.state
        .storage
        .put(
            "pypi/fresh/dates.json",
            br#"{"fresh-1.0.tar.gz":"2020-01-01T00:00:00Z"}"#,
        )
        .await
        .unwrap();

    let html = text(send(&ctx.app, Method::GET, "/simple/fresh/", "").await).await;
    assert!(html.contains("fresh-1.0.tar.gz"), "{html}");
    assert!(!html.contains("fresh-2.0.tar.gz"), "listed undated: {html}");
    let resp = send(&ctx.app, Method::GET, "/simple/fresh/fresh-2.0.tar.gz", "").await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "the cooldown holds it"
    );
}

/// R2-27: a cold-miss download and a PEP 658 `.metadata` request are resolved from
/// the cached upstream index: after the index request, no project page is fetched
/// again.
#[tokio::test]
async fn downloads_resolve_from_the_cached_upstream_index() {
    use crate::test_helpers::create_test_context_with_config;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    let meta = "Metadata-Version: 2.1\nName: cold\nVersion: 1.0\n";
    let whl = wheel("cold-1.0.dist-info", meta);
    let index = format!(
        r#"<a href="{u}/f/cold-1.0-py3-none-any.whl#sha256={w}" data-core-metadata="sha256={m}">a</a>
<a href="{u}/f/cold-1.0.tar.gz">b</a>"#,
        u = upstream.uri(),
        w = sha256_hex(&whl),
        m = sha256_hex(meta.as_bytes()),
    );
    Mock::given(method("GET"))
        .and(path("/cold/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(index))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/f/cold-1.0-py3-none-any.whl.metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_string(meta))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/f/cold-1.0-py3-none-any.whl"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(whl.clone()))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/f/cold-1.0.tar.gz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"sdist".to_vec()))
        .mount(&upstream)
        .await;
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| cfg.pypi.proxy = Some(uri));
    let page_fetches = || async {
        upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path() == "/cold/")
            .count()
    };

    assert_eq!(
        send(&ctx.app, Method::GET, "/simple/cold/", "")
            .await
            .status(),
        StatusCode::OK
    );
    let after_index = page_fetches().await;
    for file in [
        "cold-1.0-py3-none-any.whl.metadata",
        "cold-1.0-py3-none-any.whl.metadata",
        "cold-1.0-py3-none-any.whl",
        "cold-1.0.tar.gz",
    ] {
        let uri = format!("/simple/cold/{file}");
        assert_eq!(
            send(&ctx.app, Method::GET, &uri, "").await.status(),
            StatusCode::OK,
            "{uri}"
        );
    }
    assert_eq!(page_fetches().await, after_index, "no project page refetch");
}

/// R2-25: an upload over `server.body_limit_mb` is a 413, not a 400.
#[tokio::test]
async fn oversize_upload_is_413() {
    let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
        cfg.server.body_limit_mb = 1;
    });
    let resp = twine_upload(
        &ctx.app,
        &[("name", "big"), ("version", "1.0")],
        "big-1.0.tar.gz",
        &vec![0u8; 2 * 1024 * 1024],
    )
    .await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let dir = ctx.state.spool.dir(crate::registry::PYPI_UPLOAD_SUBDIR);
    let left = std::fs::read_dir(dir).map_or(0, |d| d.count());
    assert_eq!(left, 0, "no spool left");
}

/// C40: a project only nora holds files of (every upstream answers 404) is looked up
/// upstream once per `metadata_ttl`, not on every index request, for HTML and JSON clients.
/// R4-R04: an uploaded project is hosted, so its name is never looked up at all.
#[tokio::test]
async fn hosted_project_upstream_404_is_cached() {
    use crate::test_helpers::create_test_context_with_config;
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Unpooled: a pooled server can still receive another test's late request.
    let upstream = MockServer::builder().start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(404))
        .mount(&upstream)
        .await;
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| cfg.pypi.proxy = Some(uri));
    let resp = twine_upload(
        &ctx.app,
        &[("name", "priv"), ("version", "1.0")],
        "priv-1.0.tar.gz",
        b"x",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    // A proxy cache copy whose project the upstreams no longer list.
    let key = "pypi/gone/gone-1.0.tar.gz";
    ctx.state.storage.put(key, b"x").await.unwrap();
    ctx.state
        .storage
        .put(&super::proxied_marker_key(key), b"")
        .await
        .unwrap();

    for (project, lookups) in [("priv", 0), ("gone", 1)] {
        let before = upstream.received_requests().await.unwrap().len();
        for _ in 0..3 {
            for accept in ["text/html", "application/vnd.pypi.simple.v1+json"] {
                let resp = send_with_headers(
                    &ctx.app,
                    Method::GET,
                    &format!("/simple/{project}/"),
                    vec![("Accept", accept)],
                    "",
                )
                .await;
                assert_eq!(resp.status(), StatusCode::OK);
                assert!(text(resp).await.contains(&format!("{project}-1.0.tar.gz")));
            }
        }
        let hits = upstream.received_requests().await.unwrap().len() - before;
        assert_eq!(
            hits, lookups,
            "{project}: at most one index lookup in total, not one per request; no \
                 upstream lists it, so there is nothing to date"
        );
    }
}

/// C41: concurrent index requests for one project cost one upstream fetch, and the
/// result is reused within `metadata_ttl`.
#[tokio::test]
async fn upstream_index_is_single_flight_and_cached() {
    use crate::test_helpers::create_test_context_with_config;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/hot/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"<a href="https://up/hot-1.0.tar.gz">hot</a>"#)
                .set_delay(std::time::Duration::from_millis(300)),
        )
        .mount(&upstream)
        .await;
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| cfg.pypi.proxy = Some(uri));

    let requests = (0..8).map(|_| send(&ctx.app, Method::GET, "/simple/hot/", ""));
    for resp in futures::future::join_all(requests).await {
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(text(resp).await.contains("hot-1.0.tar.gz"));
    }
    let resp = send(&ctx.app, Method::GET, "/simple/hot/", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    // One fetch of the index and one of its dates (trusted upstream dates, R2-24).
    let accepts: Vec<String> = upstream
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.headers["accept"].to_str().unwrap().to_string())
        .collect();
    assert_eq!(accepts, ["text/html", super::PEP691_JSON]);
}

/// C41: when the refetch fails, the last good merged index is served (with a
/// `Warning`), never just the local files; with no good copy it is a 5xx.
#[tokio::test]
async fn upstream_failure_serves_last_good_index_or_5xx() {
    use crate::test_helpers::create_test_context_with_config;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/flaky/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<a href="https://up/flaky-2.0.tar.gz">new</a><a href="https://up/flaky-1.0.tar.gz">old</a>"#,
        ))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/down/"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&upstream)
        .await;
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.pypi.proxy = Some(uri);
        cfg.pypi.metadata_ttl = 0; // refetch on every request
    });
    for key in ["pypi/flaky/flaky-1.0.tar.gz", "pypi/down/down-1.0.tar.gz"] {
        ctx.state.storage.put(key, b"cached").await.unwrap();
    }

    let resp = send(&ctx.app, Method::GET, "/simple/flaky/", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get(header::WARNING).is_none());

    upstream.reset().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&upstream)
        .await;
    let resp = send(&ctx.app, Method::GET, "/simple/flaky/", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().get(header::WARNING).is_some(),
        "stale is flagged"
    );
    assert!(
        text(resp).await.contains("flaky-2.0.tar.gz"),
        "the newer upstream release survives"
    );

    let resp = send(&ctx.app, Method::GET, "/simple/down/", "").await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_GATEWAY,
        "no good copy: not a partial local index"
    );
}

/// `/simple/` never runs the index build itself: before the startup build finishes
/// it answers 503 + Retry-After at once (not an empty, cacheable project list).
#[tokio::test]
async fn root_index_answers_503_while_the_first_build_runs() {
    use crate::test_helpers::{create_test_context_with_storage, op_counting_storage};
    let (storage, ops) = op_counting_storage();
    let ctx = create_test_context_with_storage(storage);
    ctx.state
        .storage
        .put("pypi/real/real-1.0.tar.gz", b"x")
        .await
        .unwrap();
    ops.stall_lists(Some("pypi/"));
    let state = ctx.state.clone();
    let startup = tokio::spawn(async move { state.repo_index.refresh(&state).await });

    let resp = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        send(&ctx.app, Method::GET, "/simple/", ""),
    )
    .await
    .expect("/simple/ waited on the index build");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(resp.headers()[header::RETRY_AFTER], "5");

    ops.stall_lists(None);
    startup.await.unwrap();
    let resp = send(&ctx.app, Method::GET, "/simple/", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(text(resp).await.contains("/simple/real/"));
}

/// C45: `/simple/` lists only projects holding a distribution file, with absolute
/// hrefs, from the repo index — not a storage listing per request.
#[tokio::test]
async fn root_index_comes_from_the_repo_index() {
    use crate::test_helpers::{create_test_context_with_storage, op_counting_storage};
    let (storage, ops) = op_counting_storage();
    let ctx = create_test_context_with_storage(storage);
    ctx.state
        .storage
        .put("pypi/real/real-1.0.tar.gz", b"x")
        .await
        .unwrap();
    ctx.state
        .storage
        .put("pypi/ghost/dates.json", b"{}")
        .await
        .unwrap();

    let html = text(send(&ctx.app, Method::GET, "/simple/", "").await).await;
    let base = crate::registry::nora_base_url(&ctx.state);
    let base = base.trim_end_matches('/');
    assert!(
        html.contains(&format!("<a href=\"{base}/simple/real/\">real</a>")),
        "{html}"
    );
    assert!(!html.contains("ghost"), "{html}");

    ops.reset();
    let resp = send(&ctx.app, Method::GET, "/simple/", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        ops.total(),
        0,
        "a warm /simple/ costs no storage round-trip"
    );
}

/// R4-P12: the three listings of an index request run together, not in a row, and the
/// filtered index does not list the project's records a second time.
#[tokio::test]
async fn index_listings_run_together_and_once() {
    use crate::test_helpers::{create_test_context_with_storage_and_config, op_counting_storage};
    let (storage, ops) = op_counting_storage();
    let ctx = create_test_context_with_storage_and_config(storage, |cfg| {
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.min_release_age = Some("7d".to_string());
    });
    let file = "pypi/joined/joined-1.0.tar.gz";
    ctx.state.storage.put(file, b"x").await.unwrap();
    ops.reset();
    ops.stall_lists(Some("pypi/joined/"));
    let app = ctx.app.clone();
    let request = tokio::spawn(async move { send(&app, Method::GET, "/simple/joined/", "").await });
    let listed = || {
        ops.calls("list", "pypi-own/joined/") == 1 && ops.calls("list", "pypi-sha256/joined/") == 1
    };
    for _ in 0..1000 {
        if listed() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        listed(),
        "the listings wait for one another: {:?}",
        ops.snapshot()
    );
    ops.stall_lists(None);
    request.await.unwrap();
    assert_eq!(ops.calls("list", "pypi-own/joined/"), 1);
}

/// R4-P12: a proxied copy is told by its provenance marker alone: one HEAD before the
/// GET of the file, not a HEAD of the file as well. The one exception is the first hit
/// on a digest the quarantine ledger holds no record of (R4-C05): that hit reads the
/// file's write time once to date it, and the record it leaves makes every later hit
/// cost the marker HEAD alone.
#[tokio::test]
async fn a_proxied_hit_costs_one_head_before_its_get() {
    use crate::test_helpers::{create_test_context_with_storage_and_config, op_counting_storage};
    let (storage, ops) = op_counting_storage();
    let ctx = create_test_context_with_storage_and_config(storage, |cfg| {
        cfg.curation.quarantine = Some(crate::digest_quarantine::QuarantineMode::Observe);
    });
    let key = "pypi/hit/hit-1.0.tar.gz";
    let marker = super::proxied_marker_key(key);
    ctx.state.storage.put(key, b"sdist").await.unwrap();
    ctx.state.storage.put(&marker, b"cached").await.unwrap();
    ops.reset();
    let resp = send(&ctx.app, Method::GET, "/simple/hit/hit-1.0.tar.gz", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(ops.calls("stat", &marker), 1, "{:?}", ops.snapshot());
    assert_eq!(
        ops.calls("stat", key),
        1,
        "first sight: {:?}",
        ops.snapshot()
    );

    ops.reset();
    let resp = send(&ctx.app, Method::GET, "/simple/hit/hit-1.0.tar.gz", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(ops.calls("stat", &marker), 1, "{:?}", ops.snapshot());
    assert_eq!(ops.calls("stat", key), 0, "{:?}", ops.snapshot());
}

/// R4-R04: a project with a file uploaded here is owned locally, as a published npm name
/// is. The first upload outside `curation.internal_namespaces` makes it hosted: its index
/// (HTML and PEP 691) and files come from its own files only, a version the upstream lists
/// under the name is neither listed nor fetched, a proxy cache copy from before the upload
/// is no longer served, and an earlier upload (no provenance marker) stays one of its own.
/// That first upload is counted once, with whether the cached upstream index lists the
/// name; an internal name is not claimed; the upstream is never asked.
#[tokio::test]
async fn an_uploaded_project_owns_its_name() {
    use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};
    // Unpooled: a pooled server can still receive another test's late request.
    let upstream = MockServer::builder().start().await;
    Mock::given(any())
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"<a href="https://up/mixed-9.0.tar.gz">mixed-9.0.tar.gz</a>"#),
        )
        .mount(&upstream)
        .await;
    let uri = upstream.uri();
    let ctx = crate::test_helpers::create_test_context_with_config(move |cfg| {
        cfg.pypi.proxy = Some(uri);
        cfg.curation.internal_namespaces = vec!["acme-*".to_string()];
    });
    let index = br#"[{"filename":"mixed-9.0.tar.gz","url":"https://up/mixed-9.0.tar.gz"},
            {"filename":"mixed-0.9.tar.gz","url":"https://up/mixed-0.9.tar.gz"}]"#;
    let storage = &ctx.state.storage;
    storage
        .put("pypi/mixed/upstream-index.json", index)
        .await
        .unwrap();
    // A proxy cache copy, and an upload stored before uploads were recorded.
    storage
        .put("pypi/mixed/mixed-0.9.tar.gz", b"proxied")
        .await
        .unwrap();
    storage
        .put(
            &super::proxied_marker_key("pypi/mixed/mixed-0.9.tar.gz"),
            b"",
        )
        .await
        .unwrap();
    storage
        .put("pypi/mixed/mixed-0.8.tar.gz", b"earlier")
        .await
        .unwrap();
    let count = |label: &str| {
        crate::metrics::PYPI_MIXED_PROJECT_UPLOADS_TOTAL
            .with_label_values(&[label])
            .get()
    };
    let (listed, unknown) = (count("yes"), count("unknown"));

    for (name, version, file) in [
        ("mixed", "1.0", "mixed-1.0.tar.gz"),
        ("mixed", "1.1", "mixed-1.1.tar.gz"),
        ("fresh", "1.0", "fresh-1.0.tar.gz"),
        ("acme-utils", "1.0", "acme_utils-1.0.tar.gz"),
    ] {
        let fields = [("name", name), ("version", version)];
        let resp = twine_upload(&ctx.app, &fields, file, b"data").await;
        assert_eq!(resp.status(), StatusCode::OK, "{file}");
    }
    // Counted, not read from a log capture: tests running alongside emit the same WARN
    // callsite, and a capture can miss it when another thread registers the callsite while
    // the capture starts. Only this test seeds a cached index listing the name ("yes"),
    // so two uploads of `mixed` counting once is exact.
    assert_eq!(
        count("yes") - listed,
        1,
        "one report for two uploads of mixed"
    );
    assert!(count("unknown") > unknown, "fresh is reported");
    let internal = super::own_records(storage, "acme-utils").await.unwrap();
    assert!(!internal.hosted(), "an internal name is not claimed");

    let html = send(&ctx.app, Method::GET, "/simple/mixed/", "").await;
    assert_eq!(html.status(), StatusCode::OK);
    let html = String::from_utf8(body_bytes(html).await.to_vec()).unwrap();
    let json = send_with_headers(
        &ctx.app,
        Method::GET,
        "/simple/mixed/",
        vec![("accept", super::PEP691_JSON)],
        "",
    )
    .await;
    assert_eq!(json.status(), StatusCode::OK);
    let json = String::from_utf8(body_bytes(json).await.to_vec()).unwrap();
    for body in [&html, &json] {
        for own in ["mixed-1.0.tar.gz", "mixed-1.1.tar.gz", "mixed-0.8.tar.gz"] {
            assert!(body.contains(own), "{own} listed: {body}");
        }
        for upstream in ["mixed-9.0.tar.gz", "mixed-0.9.tar.gz"] {
            assert!(!body.contains(upstream), "{upstream} not listed: {body}");
        }
    }
    for (file, status) in [
        ("mixed-1.0.tar.gz", StatusCode::OK),
        ("mixed-0.8.tar.gz", StatusCode::OK),
        ("mixed-0.9.tar.gz", StatusCode::NOT_FOUND),
        ("mixed-9.0.tar.gz", StatusCode::NOT_FOUND),
    ] {
        let resp = send(&ctx.app, Method::GET, &format!("/simple/mixed/{file}"), "").await;
        assert_eq!(resp.status(), status, "{file}");
    }
    assert!(upstream.received_requests().await.unwrap().is_empty());
}

// ── A name with an empty segment never names another key's file ─────────

/// A project name is one segment: `/simple/evilpkg%2F/...` decodes to `evilpkg/` and
/// `%2Fevilpkg` to `/evilpkg`, both naming the canonical file under a name the rule `evilpkg`
/// does not cover — refused before curation and storage.
#[tokio::test]
async fn a_project_name_with_an_empty_segment_is_refused_before_curation() {
    use crate::test_helpers::create_test_context_with_config;
    let dir = tempfile::tempdir().unwrap();
    let blocklist = dir.path().join("blocklist.json");
    std::fs::write(
        &blocklist,
        r#"{"version": 1, "rules": [{"registry": "pypi", "name": "evilpkg", "version": "*", "reason": "malware"}]}"#,
    )
    .unwrap();
    let bp = blocklist.to_string_lossy().into_owned();
    let ctx = create_test_context_with_config(|cfg| {
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.blocklist_path = Some(bp);
    });
    ctx.state
        .storage
        .put("pypi/evilpkg/evilpkg-1.0.tar.gz", b"MALWARE")
        .await
        .unwrap();
    let canonical = send(
        &ctx.app,
        Method::GET,
        "/simple/evilpkg/evilpkg-1.0.tar.gz",
        "",
    )
    .await;
    assert_eq!(canonical.status(), StatusCode::FORBIDDEN, "control");

    let mut served = Vec::new();
    for alias in [
        "/simple/evilpkg%2F/evilpkg-1.0.tar.gz",
        "/simple/%2Fevilpkg/evilpkg-1.0.tar.gz",
    ] {
        let resp = send(&ctx.app, Method::GET, alias, "").await;
        if resp.status() == StatusCode::OK {
            served.push(format!("{alias} -> {:?}", body_bytes(resp).await));
        }
    }
    assert!(served.is_empty(), "blocklisted file served: {served:?}");
}

/// `/simple/%2Finternalpkg/` decodes to `/internalpkg`, which the isolation pattern
/// `internal*` does not match: it is refused, and the index of an internal project is never
/// requested from the public upstream.
#[tokio::test]
async fn a_leading_slash_name_never_takes_an_internal_project_upstream() {
    use crate::test_helpers::create_test_context_with_config;
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("<html></html>"))
        .mount(&upstream)
        .await;
    let ctx = create_test_context_with_config(|cfg| {
        cfg.pypi.proxy = Some(upstream.uri());
        cfg.curation.internal_namespaces = vec!["internal*".to_string()];
    });
    let leaked = || async {
        upstream
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path().contains("internalpkg"))
            .count()
    };
    let resp = send(&ctx.app, Method::GET, "/simple/internalpkg/", "").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "control");
    assert_eq!(leaked().await, 0, "control: canonical name is not proxied");

    let resp = send(&ctx.app, Method::GET, "/simple/%2Finternalpkg/", "").await;
    assert_eq!(
        leaked().await,
        0,
        "internal project name sent to the public upstream (alias answered {})",
        resp.status()
    );
}

/// An upload under `dup/` never replaces the released `dup-1.0.tar.gz`.
#[tokio::test]
async fn an_upload_under_an_empty_segment_name_never_overwrites_a_release() {
    let ctx = create_test_context();
    ctx.state
        .storage
        .put("pypi/dup/dup-1.0.tar.gz", b"original")
        .await
        .unwrap();
    let boundary = "p1aliasboundary";
    let mut body = Vec::new();
    for (name, value) in [
        (":action", "file_upload"),
        ("name", "dup/"),
        ("version", "1.0"),
    ] {
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n")
                .as_bytes(),
        );
    }
    body.extend_from_slice(
        format!("--{boundary}\r\nContent-Disposition: form-data; name=\"content\"; filename=\"dup-1.0.tar.gz\"\r\nContent-Type: application/octet-stream\r\n\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(b"replacement\r\n");
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    let ct = format!("multipart/form-data; boundary={boundary}");
    let resp = send_with_headers(
        &ctx.app,
        Method::POST,
        "/simple/",
        vec![("content-type", ct.as_str())],
        body,
    )
    .await;
    assert!(!resp.status().is_success(), "{}", resp.status());
    assert_eq!(
        &ctx.state
            .storage
            .get("pypi/dup/dup-1.0.tar.gz")
            .await
            .unwrap()[..],
        b"original"
    );
}

/// Uploads of one file at once: the file's lock lets exactly one through and the rest are
/// conflicts; the stored file and its sha256 sidecar come from the same upload.
// lock-audit: concurrent-publish-test
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_uploads_of_one_file_store_it_once() {
    let ctx = create_test_context();
    let uploads = (0..8).map(|i| {
        let app = ctx.app.clone();
        tokio::spawn(async move {
            let content = format!("sdist-{i}").into_bytes();
            twine_upload(
                &app,
                &[
                    ("name", "race"),
                    ("version", "1.0"),
                    ("sha256_digest", &sha256_hex(&content)),
                ],
                "race-1.0.tar.gz",
                &content,
            )
            .await
            .status()
        })
    });
    let mut statuses = Vec::new();
    for u in futures::future::join_all(uploads).await {
        statuses.push(u.unwrap());
    }
    let stored = statuses.iter().filter(|s| **s == StatusCode::OK);
    assert_eq!(stored.count(), 1, "{statuses:?}");
    assert!(
        statuses
            .iter()
            .all(|s| matches!(*s, StatusCode::OK | StatusCode::CONFLICT)),
        "{statuses:?}"
    );
    let storage = &ctx.state.storage;
    let file = storage.get("pypi/race/race-1.0.tar.gz").await.unwrap();
    let sidecar = storage
        .get("pypi/race/race-1.0.tar.gz.sha256")
        .await
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&sidecar), sha256_hex(&file));
}

/// Uploads of different files of one project at once: the project's `requires-python`
/// record, read and rewritten by each, keeps every file's entry. The other uploads run while
/// the first is held between its read of the record and its write.
#[tokio::test(start_paused = true)]
async fn concurrent_uploads_keep_every_requires_python_entry() {
    let (storage, ops) = crate::test_helpers::op_counting_storage();
    let ctx = crate::test_helpers::create_test_context_with_storage(storage);
    let upload = |i: usize| {
        let app = ctx.app.clone();
        async move {
            let content = format!("sdist-{i}").into_bytes();
            let version = format!("1.{i}");
            twine_upload(
                &app,
                &[
                    ("name", "many"),
                    ("version", &version),
                    ("sha256_digest", &sha256_hex(&content)),
                    ("requires_python", ">=3.9"),
                ],
                &format!("many-{version}.tar.gz"),
                &content,
            )
            .await
            .status()
        }
    };
    let statuses = crate::test_helpers::overtake_held_put(
        &ops,
        "pypi/many/requires-python.json",
        upload(0),
        (1..12).map(upload).collect(),
    )
    .await;
    for status in statuses {
        assert_eq!(status, StatusCode::OK);
    }
    let record = ctx
        .state
        .storage
        .get("pypi/many/requires-python.json")
        .await
        .unwrap();
    let record: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(&record).unwrap();
    for i in 0..12 {
        assert!(
            record.contains_key(&format!("many-1.{i}.tar.gz")),
            "1.{i}: {record:?}"
        );
    }
}
