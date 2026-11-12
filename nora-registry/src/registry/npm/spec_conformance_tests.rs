// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::*;

const NPM_UPSTREAM_DOMAIN: &str = "registry.npmjs.org";

/// Assert that no upstream URLs remain in rewritten response body, apart from
/// the intentional pass-throughs (`UPSTREAM_PASSTHROUGH_PATHS`).
fn assert_no_upstream_urls(body: &str, context: &str) {
    let leaked = body.match_indices(NPM_UPSTREAM_DOMAIN).any(|(at, _)| {
        let rest = &body[at + NPM_UPSTREAM_DOMAIN.len()..];
        !UPSTREAM_PASSTHROUGH_PATHS
            .iter()
            .any(|p| rest.starts_with(p))
    });
    assert!(
        !leaked,
        "upstream domain '{}' leaked in {}: {}",
        NPM_UPSTREAM_DOMAIN,
        context,
        &body[..body.len().min(500)]
    );
}

fn load_fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/testdata/npm/{}", env!("CARGO_MANIFEST_DIR"), name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("failed to load fixture {}: {}", path, e))
}

// ── Regular package rewrite ──

#[test]
fn attestations_url_passes_through_and_tarball_is_rewritten() {
    let packument = br#"{"name":"vite-node","versions":{"1.0.0":{"dist":{"tarball":"https://registry.npmjs.org/vite-node/-/vite-node-1.0.0.tgz","attestations":{"url":"https://registry.npmjs.org/-/npm/v1/attestations/vite-node@1.0.0"}}}}}"#;
    let body = String::from_utf8(
        rewrite_tarball_urls(packument, "http://nora:4000", "https://registry.npmjs.org").unwrap(),
    )
    .unwrap();
    assert!(body.contains("http://nora:4000/npm/vite-node/-/vite-node-1.0.0.tgz"));
    assert!(body.contains("https://registry.npmjs.org/-/npm/v1/attestations/vite-node@1.0.0"));
    assert_no_upstream_urls(&body, "attestations pass-through");
}

#[test]
fn test_regular_package_golden_no_upstream_leak() {
    let fixture = load_fixture("package-metadata.json");
    let result =
        rewrite_tarball_urls(&fixture, "http://nora:4000", "https://registry.npmjs.org").unwrap();
    let body = String::from_utf8(result).unwrap();
    assert_no_upstream_urls(&body, "regular package rewrite");
}

#[test]
fn test_regular_package_golden_all_tarballs_rewritten() {
    let fixture = load_fixture("package-metadata.json");
    let result =
        rewrite_tarball_urls(&fixture, "http://nora:4000", "https://registry.npmjs.org").unwrap();
    let json: serde_json::Value = serde_json::from_slice(&result).unwrap();

    let versions = json["versions"].as_object().unwrap();
    for (ver, data) in versions {
        let tarball = data["dist"]["tarball"].as_str().unwrap();
        assert!(
            tarball.starts_with("http://nora:4000/npm/"),
            "version {} tarball not rewritten: {}",
            ver,
            tarball
        );
    }
}

#[test]
fn test_regular_package_golden_preserves_integrity() {
    let fixture = load_fixture("package-metadata.json");
    let result =
        rewrite_tarball_urls(&fixture, "http://nora:4000", "https://registry.npmjs.org").unwrap();
    let json: serde_json::Value = serde_json::from_slice(&result).unwrap();

    // integrity and shasum must survive rewriting
    let dist = &json["versions"]["4.17.21"]["dist"];
    assert!(
        dist["shasum"].as_str().is_some(),
        "shasum must be preserved"
    );
    assert!(
        dist["integrity"].as_str().is_some(),
        "integrity must be preserved"
    );
}

#[test]
fn test_regular_package_golden_snapshot() {
    let fixture = load_fixture("package-metadata.json");
    let result =
        rewrite_tarball_urls(&fixture, "http://nora:4000", "https://registry.npmjs.org").unwrap();
    let json: serde_json::Value = serde_json::from_slice(&result).unwrap();

    // Snapshot only tarball URLs (stable against other metadata changes)
    let tarball_urls: Vec<&str> = json["versions"]
        .as_object()
        .unwrap()
        .values()
        .filter_map(|v| v["dist"]["tarball"].as_str())
        .collect();
    insta::assert_json_snapshot!("npm_regular_tarball_urls", tarball_urls);
}

// ── Scoped package rewrite ──

#[test]
fn test_scoped_package_golden_no_upstream_leak() {
    let fixture = load_fixture("scoped-package-metadata.json");
    let result = rewrite_tarball_urls(
        &fixture,
        "https://registry.airgap.local",
        "https://registry.npmjs.org",
    )
    .unwrap();
    let body = String::from_utf8(result).unwrap();
    assert_no_upstream_urls(&body, "scoped package rewrite");
}

#[test]
fn test_scoped_package_golden_all_tarballs_rewritten() {
    let fixture = load_fixture("scoped-package-metadata.json");
    let result =
        rewrite_tarball_urls(&fixture, "http://nora:4000", "https://registry.npmjs.org").unwrap();
    let json: serde_json::Value = serde_json::from_slice(&result).unwrap();

    let versions = json["versions"].as_object().unwrap();
    for (ver, data) in versions {
        let tarball = data["dist"]["tarball"].as_str().unwrap();
        assert!(
            tarball.starts_with("http://nora:4000/npm/"),
            "scoped version {} tarball not rewritten: {}",
            ver,
            tarball
        );
        // Scoped packages must preserve the @scope prefix in the path
        assert!(
            tarball.contains("@babel/core"),
            "scoped package path lost: {}",
            tarball
        );
    }
}

#[test]
fn test_scoped_package_golden_snapshot() {
    let fixture = load_fixture("scoped-package-metadata.json");
    let result =
        rewrite_tarball_urls(&fixture, "http://nora:4000", "https://registry.npmjs.org").unwrap();
    let json: serde_json::Value = serde_json::from_slice(&result).unwrap();

    let tarball_urls: Vec<&str> = json["versions"]
        .as_object()
        .unwrap()
        .values()
        .filter_map(|v| v["dist"]["tarball"].as_str())
        .collect();
    insta::assert_json_snapshot!("npm_scoped_tarball_urls", tarball_urls);
}

// ── Content-Type assertions ──

#[test]
fn test_with_content_type_metadata_is_json() {
    let data = Bytes::from(b"{}".to_vec());
    let (status, headers, _body) = with_content_type(false, data);
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[0].1, "application/json");
}

#[test]
fn test_with_content_type_tarball_is_octet() {
    let data = Bytes::from(b"\x1f\x8b".to_vec());
    let (status, headers, _body) = with_content_type(true, data);
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[0].1, "application/octet-stream");
}

// ── Edge cases for URL rewriting ──

#[test]
fn test_rewrite_custom_upstream_no_leak() {
    let metadata = serde_json::json!({
        "name": "pkg",
        "versions": {
            "1.0.0": {
                "dist": {
                    "tarball": "https://private.npm.corp/pkg/-/pkg-1.0.0.tgz"
                }
            }
        }
    });
    let data = serde_json::to_vec(&metadata).unwrap();
    let result =
        rewrite_tarball_urls(&data, "http://nora:4000", "https://private.npm.corp").unwrap();
    let body = String::from_utf8(result).unwrap();
    assert!(
        !body.contains("private.npm.corp"),
        "custom upstream domain leaked"
    );
}

#[test]
fn test_rewrite_preserves_non_dist_urls() {
    let metadata = serde_json::json!({
        "name": "pkg",
        "repository": {"url": "https://github.com/test/pkg.git"},
        "homepage": "https://pkg.example.com",
        "versions": {
            "1.0.0": {
                "dist": {
                    "tarball": "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"
                },
                "repository": {"url": "https://github.com/test/pkg.git"}
            }
        }
    });
    let data = serde_json::to_vec(&metadata).unwrap();
    let result =
        rewrite_tarball_urls(&data, "http://nora:4000", "https://registry.npmjs.org").unwrap();
    let json: serde_json::Value = serde_json::from_slice(&result).unwrap();

    // Non-dist URLs must be untouched
    assert_eq!(
        json["repository"]["url"].as_str().unwrap(),
        "https://github.com/test/pkg.git"
    );
    assert_eq!(
        json["homepage"].as_str().unwrap(),
        "https://pkg.example.com"
    );
}

/// #596 acceptance: with a cached metadata body + stored validators, a stale
/// request revalidates with `If-None-Match`; on upstream 304 the cached body
/// is served and NO 200-with-body is ever fetched. Drives the real handler.
#[tokio::test]
async fn test_npm_revalidation_304_serves_cache_no_body_download() {
    use crate::registry::{write_validators, Validators};
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{header_exists, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    // Conditional request (has If-None-Match) → 304. A request WITHOUT it
    // would 404 here (no mount), so any full fetch would visibly fail —
    // proving the 304 path served from cache.
    Mock::given(method("GET"))
        .and(header_exists("if-none-match"))
        .respond_with(ResponseTemplate::new(304))
        .mount(&upstream)
        .await;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
        cfg.npm.metadata_ttl = 0; // always stale → always revalidate
        cfg.npm.revalidate = true;
        cfg.npm.serve_stale = false;
    });

    // Pre-seed the cache body + validator sidecar (as a prior 200 would have).
    let key = "npm/testpkg/upstream/packument.json";
    ctx.state
        .storage
        .put(key, b"CACHED-PACKUMENT")
        .await
        .unwrap();
    write_validators(
        &ctx.state.storage,
        key,
        &Validators {
            etag: Some("\"v1\"".to_string()),
            last_modified: None,
        },
    )
    .await;

    let before = crate::metrics::PROXY_UPSTREAM_304_TOTAL
        .with_label_values(&["npm"])
        .get();

    let resp = send(&ctx.app, Method::GET, "/npm/testpkg", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    assert_eq!(&body[..], b"CACHED-PACKUMENT", "must serve the cached body");

    let after = crate::metrics::PROXY_UPSTREAM_304_TOTAL
        .with_label_values(&["npm"])
        .get();
    assert!(after > before, "a 304 revalidation must be recorded");
}

/// A packument cached by an older rewriter keeps a foreign upstream tarball link;
/// a 304 must not serve it as is, and the cache is upgraded in place (13.10:
/// /npm/mixin-deep kept NoraUpstreamUrlLeak firing after the rewriter fix).
#[tokio::test]
async fn npm_revalidation_304_upgrades_an_old_cached_rewrite() {
    use crate::registry::{write_validators, Validators};
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{header_exists, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(header_exists("if-none-match"))
        .respond_with(ResponseTemplate::new(304))
        .mount(&upstream)
        .await;
    let up = upstream.uri();
    let ctx = create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(up.clone());
        cfg.npm.metadata_ttl = 0;
        cfg.npm.revalidate = true;
        cfg.npm.serve_stale = false;
    });

    let key = "npm/mixin-deep/upstream/packument.json";
    let old = format!(
        r#"{{"name":"mixin-deep","versions":{{"1.1.0":{{"dependencies":{{"is-plain-object":"{up}/is-plain-object/-/is-plain-object-2.0.0.tgz"}},"dist":{{"tarball":"{PUBLIC_BASE}/npm/mixin-deep/-/mixin-deep-1.1.0.tgz"}}}}}}}}"#
    );
    ctx.state.storage.put(key, old.as_bytes()).await.unwrap();
    write_validators(
        &ctx.state.storage,
        key,
        &Validators {
            etag: Some("\"v1\"".to_string()),
            last_modified: None,
        },
    )
    .await;

    let resp = send(&ctx.app, Method::GET, "/npm/mixin-deep", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(body_bytes(resp).await.to_vec()).unwrap();
    assert!(!body.contains(&up), "served: {body}");
    assert!(
        body.contains("/npm/is-plain-object/-/is-plain-object-2.0.0.tgz"),
        "{body}"
    );
    let stored = ctx.state.storage.get(key).await.unwrap();
    assert!(
        memchr::memmem::find(&stored, up.as_bytes()).is_none(),
        "cache not upgraded"
    );
    // The provenance record vouches for the upgraded bytes, not the old ones.
    let record = ctx.state.storage.get(&origin_key(key)).await.unwrap();
    assert_eq!(
        &record[..],
        provenance_record(&origin_of(&up), &stored).as_bytes()
    );
}

/// #595: a thundering herd of concurrent requests for the same expired
/// metadata key must collapse to a SINGLE upstream fetch. M clients race
/// `GET /npm/testpkg` while the key is stale; a counting mock upstream
/// (delayed so followers pile up) must observe exactly one request, and
/// every client must receive the leader's body.
#[tokio::test]
async fn test_npm_concurrent_metadata_miss_coalesces_to_one_upstream_fetch() {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use std::sync::Arc;
    use std::time::Duration;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    // Delay the response so all followers reach the single-flight election
    // while the leader is still fetching. Body is not valid JSON, so the
    // handler's byte-level URL rewrite passes it through unchanged.
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("FRESH-PACKUMENT")
                .set_delay(Duration::from_millis(400)),
        )
        .mount(&upstream)
        .await;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
        cfg.npm.metadata_ttl = 0; // always stale → always refetch
        cfg.npm.revalidate = false; // plain 200, no conditional headers
        cfg.npm.serve_stale = false;
        // proxy_coalesce defaults to true.
    });

    // Pre-seed a stale cached body so the stale-metadata refetch path runs.
    let key = "npm/testpkg/metadata.json";
    ctx.state.storage.put(key, b"STALE").await.unwrap();

    let before = crate::metrics::PROXY_COALESCED_TOTAL
        .with_label_values(&["npm"])
        .get();

    const M: usize = 16;
    let app = Arc::new(ctx.app.clone());
    let mut handles = Vec::new();
    for _ in 0..M {
        let app = Arc::clone(&app);
        handles.push(tokio::spawn(async move {
            let resp = send(&app, Method::GET, "/npm/testpkg", "").await;
            let status = resp.status();
            let body = body_bytes(resp).await;
            (status, body)
        }));
    }

    for h in handles {
        let (status, body) = h.await.unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], b"FRESH-PACKUMENT", "every client gets the body");
    }

    let upstream_hits = upstream.received_requests().await.unwrap().len();
    assert_eq!(
        upstream_hits, 1,
        "M concurrent requests for one key must hit upstream exactly once"
    );

    let after = crate::metrics::PROXY_COALESCED_TOTAL
        .with_label_values(&["npm"])
        .get();
    assert_eq!(
        after - before,
        (M - 1) as u64,
        "M-1 followers must be served without their own upstream fetch"
    );
}

/// #595 kill-switch: with `server.proxy_coalesce = false`, the coalescer is
/// bypassed and every concurrent request fetches independently — so the
/// counting upstream observes one hit per client (proves the gate works).
#[tokio::test]
async fn test_npm_coalesce_disabled_lets_every_request_fetch() {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use std::sync::Arc;
    use std::time::Duration;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("FRESH-PACKUMENT")
                .set_delay(Duration::from_millis(200)),
        )
        .mount(&upstream)
        .await;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
        cfg.npm.metadata_ttl = 0;
        cfg.npm.revalidate = false;
        cfg.npm.serve_stale = false;
        cfg.server.proxy_coalesce = false; // kill-switch off
    });

    let key = "npm/testpkg/metadata.json";
    ctx.state.storage.put(key, b"STALE").await.unwrap();

    const M: usize = 8;
    let app = Arc::new(ctx.app.clone());
    let mut handles = Vec::new();
    for _ in 0..M {
        let app = Arc::clone(&app);
        handles.push(tokio::spawn(async move {
            let resp = send(&app, Method::GET, "/npm/testpkg", "").await;
            let status = resp.status();
            let _ = body_bytes(resp).await;
            status
        }));
    }
    for h in handles {
        assert_eq!(h.await.unwrap(), StatusCode::OK);
    }

    let upstream_hits = upstream.received_requests().await.unwrap().len();
    assert_eq!(
        upstream_hits, M,
        "with coalescing disabled every request fetches independently"
    );
}

// ── npm audit proxy (#597) ──

/// bulk audit is forwarded to upstream and returned verbatim; internal-namespace
/// package names are stripped from the forwarded body (dependency-confusion).
#[tokio::test]
async fn test_npm_audit_bulk_forwards_and_strips_internal() {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/-/npm/v1/security/advisories/bulk"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"lodash":[]}"#))
        .mount(&upstream)
        .await;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.internal_namespaces = vec!["@internal/*".to_string()];
    });

    let resp = send(
        &ctx.app,
        Method::POST,
        "/npm/-/npm/v1/security/advisories/bulk",
        r#"{"lodash":["4.17.0"],"@internal/secret":["1.0.0"]}"#,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    assert_eq!(
        &body[..],
        br#"{"lodash":[]}"#,
        "upstream body returned verbatim"
    );

    // The forwarded request must NOT carry the internal package name.
    let reqs = upstream.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1);
    let fwd = String::from_utf8_lossy(&reqs[0].body);
    assert!(fwd.contains("lodash"), "public pkg forwarded: {fwd}");
    assert!(
        !fwd.contains("@internal/secret"),
        "internal pkg name must be stripped before forwarding: {fwd}"
    );
}

/// Hosted-only repo (no upstream proxy) → npm-compatible empty result, not 405/500.
#[tokio::test]
async fn test_npm_audit_no_proxy_returns_empty() {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};

    let ctx = create_test_context_with_config(|cfg| {
        cfg.npm.proxy = None;
    });
    let resp = send(
        &ctx.app,
        Method::POST,
        "/npm/-/npm/v1/security/advisories/bulk",
        r#"{"lodash":["4.17.0"]}"#,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(&body_bytes(resp).await[..], b"{}");
}

/// quick audit (gzipped lockfile — cannot per-name strip) is refused with an
/// empty result when an internal-namespace filter is configured; upstream is
/// never contacted (no internal-name leak).
#[tokio::test]
async fn test_npm_audit_quick_refused_under_filter() {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("SHOULD-NOT-BE-CALLED"))
        .mount(&upstream)
        .await;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.internal_namespaces = vec!["@internal/*".to_string()];
    });
    let resp = send(
        &ctx.app,
        Method::POST,
        "/npm/-/npm/v1/security/audits/quick",
        "lockfile-payload",
    )
    .await;
    // Refused explicitly, not "0 vulnerabilities" (Pavel 10.10; client matrix:
    // every client exits 1 and prints the error text on a 4xx).
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(String::from_utf8_lossy(&body_bytes(resp).await).contains("\"error\""));
    assert_eq!(
        upstream.received_requests().await.unwrap().len(),
        0,
        "quick must not reach upstream under a namespace filter"
    );
}

/// POST on a non-audit npm path → 405 (POST is only valid on the audit endpoints).
#[tokio::test]
async fn test_npm_audit_non_audit_post_405() {
    use crate::test_helpers::{create_test_context, send};
    use axum::http::{Method, StatusCode};

    let ctx = create_test_context();
    let resp = send(&ctx.app, Method::POST, "/npm/lodash", "x").await;
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

/// An oversized audit body is rejected with 413 before any upstream forward.
#[tokio::test]
async fn test_npm_audit_body_too_large() {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};

    let ctx = create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some("http://127.0.0.1:1".to_string());
    });
    let big = "x".repeat(NPM_AUDIT_BODY_CAP + 1);
    let resp = send(
        &ctx.app,
        Method::POST,
        "/npm/-/npm/v1/security/advisories/bulk",
        big,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

/// Review #1 regression: a Content-Encoded (e.g. gzipped) bulk body under an
/// active namespace filter cannot be name-verified → must fail CLOSED (refuse,
/// upstream never contacted), not forward internal names.
#[tokio::test]
async fn test_npm_audit_bulk_encoded_refused_under_filter() {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send_with_headers};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("LEAKED"))
        .mount(&upstream)
        .await;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.internal_namespaces = vec!["@internal/*".to_string()];
    });
    // Claims gzip encoding → NORA cannot see the names → must refuse.
    let resp = send_with_headers(
        &ctx.app,
        Method::POST,
        "/npm/-/npm/v1/security/advisories/bulk",
        vec![("content-encoding", "gzip")],
        "gzipped-body-not-inspected-because-refused",
    )
    .await;
    // Refused explicitly, not "0 vulnerabilities" (Pavel 10.10; client matrix:
    // every client exits 1 and prints the error text on a 4xx).
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(String::from_utf8_lossy(&body_bytes(resp).await).contains("\"error\""));
    assert_eq!(
        upstream.received_requests().await.unwrap().len(),
        0,
        "encoded bulk under a filter must NOT be forwarded"
    );
}

/// Review #3 regression: upstream 5xx must surface as 502 (audit-endpoint error),
/// NOT `200 {}` (which npm renders as a false "0 vulnerabilities").
#[tokio::test]
async fn test_npm_audit_upstream_5xx_returns_502() {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(500))
        .mount(&upstream)
        .await;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
    });
    let resp = send(
        &ctx.app,
        Method::POST,
        "/npm/-/npm/v1/security/advisories/bulk",
        r#"{"lodash":["4.17.0"]}"#,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

/// Review #5: the client's Authorization (its NORA token) must never be
/// forwarded upstream — only the allowlisted headers + configured proxy_auth.
#[tokio::test]
async fn test_npm_audit_client_authorization_not_forwarded() {
    use crate::test_helpers::{create_test_context_with_config, send_with_headers};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&upstream)
        .await;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
    });
    let resp = send_with_headers(
        &ctx.app,
        Method::POST,
        "/npm/-/npm/v1/security/advisories/bulk",
        vec![("authorization", "Bearer nora-client-token")],
        r#"{"lodash":["4.17.0"]}"#,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let reqs = upstream.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1);
    assert!(
        reqs[0].headers.get("authorization").is_none(),
        "client Authorization must not be forwarded upstream"
    );
}

/// Under `anonymous_read`, an unauthenticated `npm audit` POST must pass the
/// auth gate (audit is a read-semantics query) and reach the handler — hosted-
/// only (no proxy) → 200 `{}`. A non-audit npm POST stays gated → 401.
#[tokio::test]
async fn test_npm_audit_anonymous_read_allows_post() {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};

    let ctx = create_test_context_with_config(|cfg| {
        cfg.auth.enabled = true;
        cfg.auth.anonymous_read = true;
        cfg.npm.proxy = None; // hosted-only → handler returns 200 {}
    });
    let audit = send(
        &ctx.app,
        Method::POST,
        "/npm/-/npm/v1/security/advisories/bulk",
        r#"{"lodash":["4.17.0"]}"#,
    )
    .await;
    assert_eq!(
        audit.status(),
        StatusCode::OK,
        "anonymous npm audit must pass the auth gate under anonymous_read"
    );
    // A non-audit npm POST is not read-eligible → still requires auth.
    let other = send(&ctx.app, Method::POST, "/npm/somepkg", "x").await;
    assert_eq!(other.status(), StatusCode::UNAUTHORIZED);
}

/// #867: when a 304 revalidation finds the cached body missing (deleted by
/// GC, retention, or corruption between the handler's `get_verified` and
/// `refetch_metadata`'s second read), the stale `.meta` validator sidecar
/// must be deleted so the next revalidation cycle does a full unconditional
/// GET instead of looping on 304 forever.
///
/// The handler's cache-hit gate (`get_verified`) requires the body to be
/// present, so the GC race can't be reproduced through the HTTP layer.
/// We call `refetch_metadata` directly with `.meta` seeded but body absent.
#[tokio::test]
async fn test_867_304_body_miss_clears_validators() {
    use crate::registry::{read_validators, write_validators, Validators};
    use crate::test_helpers::create_test_context_with_config;
    use wiremock::matchers::{header_exists, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    // Respond 304 to any conditional request (has If-None-Match).
    Mock::given(method("GET"))
        .and(header_exists("if-none-match"))
        .respond_with(ResponseTemplate::new(304))
        .mount(&upstream)
        .await;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
        cfg.npm.metadata_ttl = 0;
        cfg.npm.revalidate = true;
        cfg.npm.serve_stale = false;
    });

    let key = "npm/ghost-pkg/upstream/packument.json";

    // Seed validator sidecar WITHOUT the body — simulates GC/retention
    // deleting the cached body while .meta survives.
    write_validators(
        &ctx.state.storage,
        key,
        &Validators {
            etag: Some("\"stale-etag\"".to_string()),
            last_modified: None,
        },
    )
    .await;

    // Preconditions: .meta exists, body does not.
    assert!(
        read_validators(&ctx.state.storage, key).await.is_some(),
        "precondition: .meta must exist"
    );
    assert!(
        ctx.state.storage.get(key).await.is_err(),
        "precondition: body must be absent"
    );

    // Call refetch_metadata directly — simulates the race where the handler
    // entered the cache-hit path (body was present at get_verified), TTL
    // expired, but GC deleted the body before refetch_metadata re-reads it.
    let result = refetch_metadata(&ctx.state, "ghost-pkg", "ghost-pkg", key, key, true, true).await;
    assert!(result.is_err(), "must fail when body is missing on 304");

    // The critical assertion: .meta must be gone after the 304 body-miss.
    // Before the fix, `.ok()?` silently returned None but left .meta intact,
    // causing an infinite 304 loop on every subsequent TTL expiry.
    assert!(
        read_validators(&ctx.state.storage, key).await.is_none(),
        "#867: validators must be cleared after 304 body-miss to break the infinite loop"
    );
}
/// #956: a hosted package whose derived packument is gone is still fully
/// described by its per-version keys. Answering 404 loses data that is
/// sitting in storage; the reassembly already exists and must be reached.
#[tokio::test]
async fn test_npm_packument_rebuilt_when_metadata_missing() {
    use crate::test_helpers::{body_bytes, create_test_context, send};
    use axum::http::{Method, StatusCode};

    let ctx = create_test_context();

    // Seed the immutable originals directly — what a direct-storage import
    // or a restore that skipped derived objects leaves behind.
    for ver in ["1.0.0", "2.0.0"] {
        let doc = serde_json::json!({ "name": "imported", "version": ver, "dist": {} });
        ctx.state
            .storage
            .put(
                &format!("npm/imported/versions/{}.json", ver),
                &serde_json::to_vec(&doc).unwrap(),
            )
            .await
            .unwrap();
    }
    ctx.state
        .storage
        .put(
            "npm/imported/pkg.json",
            &serde_json::to_vec(&serde_json::json!({ "description": "seeded" })).unwrap(),
        )
        .await
        .unwrap();
    assert!(
        ctx.state
            .storage
            .get("npm/imported/metadata.json")
            .await
            .is_err(),
        "precondition: the derived packument is absent"
    );

    let response = send(&ctx.app, Method::GET, "/npm/imported", "").await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "every version is in storage — a 404 here loses the package"
    );

    let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
    assert_eq!(json["name"], "imported");
    let versions = json["versions"].as_object().unwrap();
    assert!(versions.contains_key("1.0.0"), "1.0.0 missing from rebuild");
    assert!(versions.contains_key("2.0.0"), "2.0.0 missing from rebuild");
    assert_eq!(
        json["dist-tags"]["latest"], "2.0.0",
        "latest must be derived from the version keys"
    );
    assert_eq!(
        json["description"], "seeded",
        "package-level fields must survive the rebuild"
    );

    assert!(
        ctx.state
            .storage
            .get("npm/imported/metadata.json")
            .await
            .is_ok(),
        "the rebuild must persist, or every request pays for it again"
    );
}

/// The rebuild must not invent a package out of an empty prefix.
#[tokio::test]
async fn test_npm_packument_absent_package_still_404() {
    use crate::test_helpers::{create_test_context, send};
    use axum::http::{Method, StatusCode};

    let ctx = create_test_context();

    let response = send(&ctx.app, Method::GET, "/npm/never-published", "").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(
        ctx.state
            .storage
            .get("npm/never-published/metadata.json")
            .await
            .is_err(),
        "a 404 must not leave a derived object behind"
    );
}

/// Concurrent readers of a package with a missing packument must all get the
/// same correct answer — the rebuild is serialized on the publish lock.
#[tokio::test]
async fn test_npm_packument_rebuild_is_serialized() {
    use crate::test_helpers::{body_bytes, create_test_context, send};
    use axum::http::{Method, StatusCode};

    let ctx = create_test_context();
    for ver in ["1.0.0", "1.1.0", "2.0.0"] {
        let doc = serde_json::json!({ "name": "stampede", "version": ver, "dist": {} });
        ctx.state
            .storage
            .put(
                &format!("npm/stampede/versions/{}.json", ver),
                &serde_json::to_vec(&doc).unwrap(),
            )
            .await
            .unwrap();
    }

    let mut handles = Vec::new();
    for _ in 0..8 {
        let app = ctx.app.clone();
        handles.push(tokio::spawn(async move {
            let response = send(&app, Method::GET, "/npm/stampede", "").await;
            let status = response.status();
            (status, body_bytes(response).await)
        }));
    }

    let mut bodies = Vec::new();
    for handle in handles {
        let (status, body) = handle.await.unwrap();
        assert_eq!(status, StatusCode::OK);
        bodies.push(body);
    }
    assert!(
        bodies.windows(2).all(|pair| pair[0] == pair[1]),
        "concurrent rebuilds of the same package must agree"
    );
}
/// #957: `npm install` asks for the abbreviated packument. Serving the full
/// document instead is correct but wasteful — and the fields it carries are
/// exactly the ones an installer never reads.
#[tokio::test]
async fn test_npm_packument_abbreviated_on_install_v1_accept() {
    use crate::test_helpers::{body_bytes, create_test_context, send_with_headers};
    use axum::http::{header, Method, StatusCode};

    let ctx = create_test_context();
    let full = serde_json::json!({
        "name": "corgi",
        "dist-tags": { "latest": "1.0.0" },
        "readme": "a very long readme that no installer reads",
        "maintainers": [{ "name": "someone" }],
        "versions": {
            "1.0.0": {
                "name": "corgi",
                "version": "1.0.0",
                "dist": { "tarball": "/npm/corgi/-/corgi-1.0.0.tgz" },
                "dependencies": { "left-pad": "^1.0.0" },
                "engines": { "node": ">=18" },
                "os": ["linux"],
                "cpu": ["x64"],
                "peerDependenciesMeta": { "react": { "optional": true } },
                "deprecated": "use corgi2",
                "description": "dropped",
                "scripts": { "test": "dropped" },
                "gitHead": "dropped"
            }
        }
    });
    ctx.state
        .storage
        .put(
            "npm/corgi/metadata.json",
            &serde_json::to_vec(&full).unwrap(),
        )
        .await
        .unwrap();

    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/npm/corgi",
        vec![("accept", "application/vnd.npm.install-v1+json")],
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/vnd.npm.install-v1+json")
    );
    assert_eq!(
        response
            .headers()
            .get(header::VARY)
            .and_then(|v| v.to_str().ok()),
        Some("Accept"),
        "the body varies by Accept and metadata is cacheable — a shared cache \
             must not serve the abbreviated document to a client that wanted the full one"
    );

    let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
    assert_eq!(json["name"], "corgi");
    assert_eq!(json["dist-tags"]["latest"], "1.0.0");
    assert!(json.get("readme").is_none(), "readme must be dropped");
    assert!(
        json.get("maintainers").is_none(),
        "maintainers must be dropped"
    );

    let manifest = &json["versions"]["1.0.0"];
    // Everything an installer consults survives — losing any of these
    // silently changes what gets resolved and installed.
    assert_eq!(manifest["version"], "1.0.0");
    assert_eq!(manifest["dependencies"]["left-pad"], "^1.0.0");
    assert_eq!(manifest["engines"]["node"], ">=18");
    assert_eq!(manifest["os"][0], "linux");
    assert_eq!(manifest["cpu"][0], "x64");
    assert_eq!(manifest["peerDependenciesMeta"]["react"]["optional"], true);
    assert_eq!(manifest["deprecated"], "use corgi2");
    assert!(manifest["dist"]["tarball"].is_string());
    // ...and what it never reads does not.
    assert!(manifest.get("description").is_none());
    assert!(manifest.get("scripts").is_none());
    assert!(manifest.get("gitHead").is_none());
}

/// Without the header the full document is served, unchanged.
#[tokio::test]
async fn test_npm_packument_full_without_install_v1_accept() {
    use crate::test_helpers::{body_bytes, create_test_context, send};
    use axum::http::{header, Method, StatusCode};

    let ctx = create_test_context();
    let full = serde_json::json!({
        "name": "corgi",
        "dist-tags": { "latest": "1.0.0" },
        "readme": "kept",
        "versions": {
            "1.0.0": { "name": "corgi", "version": "1.0.0", "description": "kept", "dist": {} }
        }
    });
    ctx.state
        .storage
        .put(
            "npm/corgi/metadata.json",
            &serde_json::to_vec(&full).unwrap(),
        )
        .await
        .unwrap();

    let response = send(&ctx.app, Method::GET, "/npm/corgi", "").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );

    let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
    assert_eq!(json["readme"], "kept", "the full document must be intact");
    assert_eq!(json["versions"]["1.0.0"]["description"], "kept");
}

/// A body that is not a packument is served unchanged rather than failing:
/// the client asked for a projection of this document, not for an error.
#[tokio::test]
async fn test_npm_packument_unparsable_body_served_unchanged() {
    use crate::test_helpers::{body_bytes, create_test_context, send_with_headers};
    use axum::http::{Method, StatusCode};

    let ctx = create_test_context();
    ctx.state
        .storage
        .put("npm/broken/metadata.json", b"not json at all")
        .await
        .unwrap();

    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/npm/broken",
        vec![("accept", "application/vnd.npm.install-v1+json")],
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(&body_bytes(response).await[..], b"not json at all");
}
/// The degraded path is still a representation: when the packument is stale
/// and upstream is gone, an install-v1 client must get the abbreviated body
/// *and* the matching Content-Type. Serving the short body under
/// `application/json` is the bug this guards.
#[tokio::test]
async fn test_npm_packument_stale_serve_honours_install_v1() {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send_with_headers};
    use axum::http::{header, Method, StatusCode};

    let ctx = create_test_context_with_config(|cfg| {
        cfg.npm.proxy = None; // no upstream to revalidate against
        cfg.npm.metadata_ttl = 0; // always stale
        cfg.npm.serve_stale = true;
    });

    let full = serde_json::json!({
        "name": "stale-corgi",
        "dist-tags": { "latest": "1.0.0" },
        "readme": "dropped in the abbreviated form",
        "versions": {
            "1.0.0": { "name": "stale-corgi", "version": "1.0.0", "dist": {}, "scripts": {} }
        }
    });
    ctx.state
        .storage
        .put(
            "npm/stale-corgi/metadata.json",
            &serde_json::to_vec(&full).unwrap(),
        )
        .await
        .unwrap();

    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/npm/stale-corgi",
        vec![("accept", "application/vnd.npm.install-v1+json")],
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-nora-stale")
            .and_then(|v| v.to_str().ok()),
        Some("true"),
        "precondition: this test must exercise the stale path"
    );
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/vnd.npm.install-v1+json"),
        "the stale path abbreviated the body — the Content-Type must say so"
    );
    assert_eq!(
        response
            .headers()
            .get(header::VARY)
            .and_then(|v| v.to_str().ok()),
        Some("Accept")
    );

    let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
    assert!(json.get("readme").is_none());
    assert!(json["versions"]["1.0.0"].get("scripts").is_none());
}
