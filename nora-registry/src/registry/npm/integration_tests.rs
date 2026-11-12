// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::test_helpers::{
    body_bytes, create_test_context, create_test_context_with_auth, send, send_with_headers,
};

#[tokio::test]
async fn test_npm_namespace_scope_enforced() {
    use crate::auth::NamespaceAuthority;
    use crate::config::ScopeEnforcement;
    use axum::body::Bytes;
    use axum::extract::{Path, State};
    use axum::http::StatusCode;
    use axum::Extension;

    let ctx = create_test_context();
    let scoped = NamespaceAuthority::from_oidc_scope(
        "ci",
        &["@myorg/**".to_string()],
        ScopeEnforcement::Enforce,
    );

    // Out of scope -> 403, decided before any payload parsing.
    let resp = super::handle_publish(
        State(ctx.state.clone()),
        Path("@other/pkg".to_string()),
        Extension(scoped.clone()),
        None,
        crate::registry::PublishBody(Bytes::from_static(b"{}")),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // In scope -> enforcement passes (then fails payload validation, not 403).
    let resp = super::handle_publish(
        State(ctx.state.clone()),
        Path("@myorg/pkg".to_string()),
        Extension(scoped),
        None,
        crate::registry::PublishBody(Bytes::from_static(b"{}")),
    )
    .await;
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
}
use axum::body::Body;
use axum::http::{header, Method, StatusCode};
use base64::Engine;

#[tokio::test]
async fn test_npm_metadata_from_cache() {
    let ctx = create_test_context();

    let metadata = serde_json::json!({
        "name": "lodash",
        "versions": {
            "4.17.21": { "dist": { "tarball": "http://example.com/lodash.tgz" } }
        }
    });
    let metadata_bytes = serde_json::to_vec(&metadata).unwrap();

    ctx.state
        .storage
        .put("npm/lodash/metadata.json", &metadata_bytes)
        .await
        .unwrap();

    let response = send(&ctx.app, Method::GET, "/npm/lodash", "").await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_bytes(response).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["name"], "lodash");
}

#[tokio::test]
async fn test_npm_tarball_from_cache() {
    let ctx = create_test_context();

    let tarball_data = b"fake-tarball-bytes";
    ctx.state
        .storage
        .put("npm/lodash/tarballs/lodash-4.17.21.tgz", tarball_data)
        .await
        .unwrap();

    let response = send(
        &ctx.app,
        Method::GET,
        "/npm/lodash/-/lodash-4.17.21.tgz",
        "",
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_bytes(response).await;
    assert_eq!(&body[..], tarball_data);
}

#[tokio::test]
async fn test_npm_tarball_range_request() {
    let ctx = create_test_context();
    let tarball = b"0123456789abcdef";
    ctx.state
        .storage
        .put("npm/lodash/tarballs/lodash-4.17.21.tgz", tarball)
        .await
        .unwrap();
    let url = "/npm/lodash/-/lodash-4.17.21.tgz";

    let resp =
        send_with_headers(&ctx.app, Method::GET, url, vec![("range", "bytes=2-5")], "").await;
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        resp.headers()
            .get(header::CONTENT_RANGE)
            .unwrap()
            .to_str()
            .unwrap(),
        format!("bytes 2-5/{}", tarball.len())
    );
    assert_eq!(
        resp.headers()
            .get(header::ACCEPT_RANGES)
            .unwrap()
            .to_str()
            .unwrap(),
        "bytes"
    );
    assert_eq!(body_bytes(resp).await.as_ref(), &tarball[2..=5]);

    // A client that already holds the whole tarball resumes with `bytes=<size>-`.
    let resp = send_with_headers(
        &ctx.app,
        Method::GET,
        url,
        vec![("range", &format!("bytes={}-", tarball.len())[..])],
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
        format!("bytes */{}", tarball.len())
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
    assert_eq!(body_bytes(resp).await.as_ref(), &tarball[..]);
}

#[tokio::test]
async fn test_npm_not_found_no_proxy() {
    let ctx = create_test_context();

    // No proxy configured, no local data
    let response = send(&ctx.app, Method::GET, "/npm/nonexistent", "").await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_npm_publish_basic() {
    let ctx = create_test_context();

    let tarball_data = b"fake-tarball";
    let base64_data = base64::engine::general_purpose::STANDARD.encode(tarball_data);

    let payload = serde_json::json!({
        "name": "mypkg",
        "versions": {
            "1.0.0": { "dist": {} }
        },
        "_attachments": {
            "mypkg-1.0.0.tgz": { "data": base64_data }
        },
        "dist-tags": { "latest": "1.0.0" }
    });

    let body_bytes = serde_json::to_vec(&payload).unwrap();
    let response = send(&ctx.app, Method::PUT, "/npm/mypkg", Body::from(body_bytes)).await;

    assert_eq!(response.status(), StatusCode::CREATED);

    // Verify tarball was stored
    let stored_tarball = ctx
        .state
        .storage
        .get("npm/mypkg/tarballs/mypkg-1.0.0.tgz")
        .await
        .unwrap();
    assert_eq!(&stored_tarball[..], tarball_data);
}

#[tokio::test]
async fn test_npm_publish_multi_version_scan_regenerate() {
    // Two separate publishes of different versions must BOTH survive in the regenerated
    // packument — the version data lives in immutable per-version keys, not a merged file
    // (the #39 multi-replica lost-update fix).
    let ctx = create_test_context();
    for v in ["1.0.0", "2.0.0"] {
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"tgz");
        let mut versions = serde_json::Map::new();
        versions.insert(v.to_string(), serde_json::json!({ "dist": {} }));
        let mut atts = serde_json::Map::new();
        atts.insert(
            format!("multi-{}.tgz", v),
            serde_json::json!({ "data": b64 }),
        );
        let payload =
            serde_json::json!({ "name": "multi", "versions": versions, "_attachments": atts });
        let resp = send(
            &ctx.app,
            Method::PUT,
            "/npm/multi",
            Body::from(serde_json::to_vec(&payload).unwrap()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
    }
    // both per-version keys exist (immutable, distinct — no merge)
    assert!(ctx
        .state
        .storage
        .get("npm/multi/versions/1.0.0.json")
        .await
        .is_ok());
    assert!(ctx
        .state
        .storage
        .get("npm/multi/versions/2.0.0.json")
        .await
        .is_ok());
    // the regenerated packument lists BOTH
    let meta = ctx
        .state
        .storage
        .get("npm/multi/metadata.json")
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&meta).unwrap();
    let versions = json["versions"].as_object().unwrap();
    assert!(versions.contains_key("1.0.0"), "v1 lost from packument");
    assert!(versions.contains_key("2.0.0"), "v2 lost from packument");
}

#[tokio::test]
async fn test_npm_publish_migrates_embedded_packument() {
    // An old-layout package (versions embedded in metadata.json, no per-version keys) is
    // migrated on the next publish, preserving the old versions, once the operator has
    // said it is a published package (NORA 0.9.3 or older) and not an upstream's cache.
    let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
        cfg.npm.import_embedded = vec!["legacy".to_string()];
    });
    let old = serde_json::json!({
        "name": "legacy",
        "versions": { "1.0.0": { "name": "legacy", "version": "1.0.0", "dist": {} } },
        "dist-tags": { "latest": "1.0.0" }
    });
    ctx.state
        .storage
        .put(
            "npm/legacy/metadata.json",
            &serde_json::to_vec(&old).unwrap(),
        )
        .await
        .unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(b"tgz");
    let payload = serde_json::json!({
        "name": "legacy",
        "versions": { "2.0.0": { "dist": {} } },
        "_attachments": { "legacy-2.0.0.tgz": { "data": b64 } },
    });
    let resp = send(
        &ctx.app,
        Method::PUT,
        "/npm/legacy",
        Body::from(serde_json::to_vec(&payload).unwrap()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    // old version migrated to its own per-version key
    assert!(
        ctx.state
            .storage
            .get("npm/legacy/versions/1.0.0.json")
            .await
            .is_ok(),
        "old embedded version not migrated to a per-version key"
    );
    // packument has BOTH the migrated old and the new version
    let meta = ctx
        .state
        .storage
        .get("npm/legacy/metadata.json")
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&meta).unwrap();
    let versions = json["versions"].as_object().unwrap();
    assert!(versions.contains_key("1.0.0"), "migrated v1 lost");
    assert!(versions.contains_key("2.0.0"), "new v2 lost");
}

#[tokio::test]
async fn test_npm_publish_scoped_with_prefixed_attachment() {
    use crate::auth::NamespaceAuthority;
    use axum::body::Bytes;
    use axum::extract::{Path, State};
    use axum::http::StatusCode;
    use axum::Extension;

    let ctx = create_test_context();

    let tarball_data = b"fake-tarball";
    let base64_data = base64::engine::general_purpose::STANDARD.encode(tarball_data);

    // Scoped package where the attachment filename includes the scope prefix
    // (e.g. "@scope/pkg-1.0.0.tgz" instead of "pkg-1.0.0.tgz"). The handler
    // must normalize this by stripping the scope prefix.
    let payload = serde_json::json!({
        "name": "@scope/mypkg",
        "versions": {
            "1.0.0": { "dist": {} }
        },
        "_attachments": {
            "@scope/mypkg-1.0.0.tgz": { "data": base64_data }
        },
        "dist-tags": { "latest": "1.0.0" }
    });

    let body_bytes = serde_json::to_vec(&payload).unwrap();

    let resp = super::handle_publish(
        State(ctx.state.clone()),
        Path("@scope/mypkg".to_string()),
        Extension(NamespaceAuthority::Unrestricted),
        None,
        crate::registry::PublishBody(Bytes::from(body_bytes)),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Verify tarball was stored with the normalized (scope-stripped) filename
    let stored_tarball = ctx
        .state
        .storage
        .get("npm/@scope/mypkg/tarballs/mypkg-1.0.0.tgz")
        .await
        .unwrap();
    assert_eq!(&stored_tarball[..], tarball_data);
}

#[tokio::test]
async fn test_npm_publish_name_mismatch() {
    let ctx = create_test_context();

    let tarball_data = b"fake-tarball";
    let base64_data = base64::engine::general_purpose::STANDARD.encode(tarball_data);

    let payload = serde_json::json!({
        "name": "other",
        "versions": {
            "1.0.0": { "dist": {} }
        },
        "_attachments": {
            "other-1.0.0.tgz": { "data": base64_data }
        },
        "dist-tags": { "latest": "1.0.0" }
    });

    let body_bytes = serde_json::to_vec(&payload).unwrap();
    let response = send(&ctx.app, Method::PUT, "/npm/mypkg", Body::from(body_bytes)).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// Corrupt metadata in storage → publish returns 500 (#533).
#[tokio::test]
async fn test_publish_corrupt_metadata_returns_500() {
    let ctx = create_test_context();

    // Plant corrupt (non-JSON) data in metadata key
    ctx.state
        .storage
        .put("npm/mypkg/metadata.json", b"NOT VALID JSON{{{")
        .await
        .unwrap();

    let tarball_data = b"fake-tarball";
    let base64_data = base64::engine::general_purpose::STANDARD.encode(tarball_data);

    let payload = serde_json::json!({
        "name": "mypkg",
        "versions": {
            "2.0.0": { "dist": {} }
        },
        "_attachments": {
            "mypkg-2.0.0.tgz": { "data": base64_data }
        },
        "dist-tags": { "latest": "2.0.0" }
    });

    let body_bytes = serde_json::to_vec(&payload).unwrap();
    let response = send(&ctx.app, Method::PUT, "/npm/mypkg", Body::from(body_bytes)).await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    // Corrupt data must NOT be overwritten — preserved for forensics
    let stored = ctx
        .state
        .storage
        .get("npm/mypkg/metadata.json")
        .await
        .unwrap();
    assert_eq!(&stored[..], b"NOT VALID JSON{{{");
}

/// First publish (no existing metadata) still works (#533 regression guard).
#[tokio::test]
async fn test_first_publish_no_existing_metadata() {
    let ctx = create_test_context();

    let tarball_data = b"fake-tarball";
    let base64_data = base64::engine::general_purpose::STANDARD.encode(tarball_data);

    let payload = serde_json::json!({
        "name": "newpkg",
        "versions": {
            "1.0.0": { "dist": {} }
        },
        "_attachments": {
            "newpkg-1.0.0.tgz": { "data": base64_data }
        },
        "dist-tags": { "latest": "1.0.0" }
    });

    let body_bytes = serde_json::to_vec(&payload).unwrap();
    let response = send(&ctx.app, Method::PUT, "/npm/newpkg", Body::from(body_bytes)).await;

    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_npm_whoami_anonymous() {
    use axum::http::StatusCode;

    let ctx = create_test_context();
    let resp = send(&ctx.app, axum::http::Method::GET, "/npm/-/whoami", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["username"], "anonymous");
}

#[tokio::test]
async fn test_npm_whoami_authenticated() {
    use axum::http::StatusCode;
    use base64::Engine;

    let ctx = create_test_context_with_auth(&[("alice", "hunter2")]);

    let basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("alice:hunter2")
    );
    let resp = send_with_headers(
        &ctx.app,
        axum::http::Method::GET,
        "/npm/-/whoami",
        vec![("authorization", &basic)],
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["username"], "alice");
}

#[tokio::test]
async fn test_npm_whoami_requires_auth() {
    use axum::http::StatusCode;

    let ctx = create_test_context_with_auth(&[("alice", "hunter2")]);

    let resp = send(&ctx.app, axum::http::Method::GET, "/npm/-/whoami", "").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// A username containing `"` (reachable via the OIDC `sub` claim) must NOT
// break the JSON or inject extra fields — handle_whoami serializes via serde.
#[tokio::test]
async fn test_npm_whoami_escapes_username() {
    use crate::auth::AuthenticatedUser;

    let evil = r#"a","admin":"x"#;
    let resp = super::handle_whoami(&AuthenticatedUser(evil.to_string())).await;
    let body = body_bytes(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["username"], evil);
    assert!(json.get("admin").is_none());
}

// ── ensure_npm_metadata_cached self-prime (#748) ──
//
// A tarball download (direct/locked fetch) arrives without a prior packument
// request, so metadata.json is uncached. ensure_npm_metadata_cached fetches
// the packument upstream and caches it (rewritten to NORA URLs) so the
// per-version `time[version]` date is readable on the same request.

/// C17: a tarball above `server.stream_threshold_mb` is spooled on the cold miss
/// and cached with its `.sha256` and provenance sidecars; the next request
/// streams it from storage without touching the upstream.
#[tokio::test]
async fn test_large_tarball_spooled_then_streamed_from_cache() {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let tarball: Vec<u8> = (0..(2 * 1024 * 1024 + 3))
        .map(|i| (i % 249) as u8)
        .collect();
    let upstream = MockServer::start().await;
    // Only a version the upstream's packument lists is downloaded.
    super::mount_listing(
        &upstream,
        "bigpkg",
        &[("1.0.0", "bigpkg/-/bigpkg-1.0.0.tgz")],
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/bigpkg/-/bigpkg-1.0.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball.clone()))
        .mount(&upstream)
        .await;
    let ctx = create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
        cfg.server.stream_threshold_mb = 1;
    });
    let uri = "/npm/bigpkg/-/bigpkg-1.0.0.tgz";
    let resp = send(&ctx.app, Method::GET, uri, "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_bytes(resp).await[..] == tarball[..]);

    use sha2::Digest;
    let key = "npm/bigpkg/tarballs/bigpkg-1.0.0.tgz";
    let sha = hex::encode(sha2::Sha256::digest(&tarball));
    let mut cached = false;
    for _ in 0..100 {
        if ctx.state.storage.get(&super::origin_key(key)).await.is_ok() {
            cached = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(cached, "tarball and provenance are cached");
    assert_eq!(
        ctx.state.storage.pin(key).await.as_deref(),
        Some(sha.as_str())
    );
    assert_eq!(
        &ctx.state
            .storage
            .get(&format!("{key}.sha256"))
            .await
            .unwrap()[..],
        sha.as_bytes()
    );

    let resp = send(&ctx.app, Method::GET, uri, "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_bytes(resp).await[..] == tarball[..]);
    let tarball_fetches = upstream
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().ends_with(".tgz"))
        .count();
    assert_eq!(tarball_fetches, 1, "the hit is served from storage");
}

/// Happy path: tarball cache-miss → ensure_npm_metadata_cached fetches and
/// caches the packument; tarball is also proxied and served. The cached
/// metadata must carry the upstream release date AND have its tarball URLs
/// rewritten to NORA.
#[tokio::test]
async fn test_npm_tarball_self_primes_metadata_on_cache_miss() {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;

    // Packument (fetched by ensure_npm_metadata_cached → GET {proxy}/testpkg).
    let packument = serde_json::json!({
        "name": "testpkg",
        "versions": {
            "1.0.0": {
                "dist": {
                    "tarball": format!("{}/testpkg/-/testpkg-1.0.0.tgz", upstream.uri())
                }
            }
        },
        "time": { "1.0.0": "2020-01-15T10:30:00.000Z" }
    });
    Mock::given(method("GET"))
        .and(path("/testpkg"))
        .respond_with(ResponseTemplate::new(200).set_body_string(packument.to_string()))
        .mount(&upstream)
        .await;

    // Tarball (fetched by the cache-miss proxy path → GET {proxy}/testpkg/-/testpkg-1.0.0.tgz).
    let tarball = b"TGZ-BYTES";
    Mock::given(method("GET"))
        .and(path("/testpkg/-/testpkg-1.0.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball.to_vec()))
        .mount(&upstream)
        .await;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
    });

    // Direct/locked tarball fetch — no prior packument request.
    let resp = send(
        &ctx.app,
        Method::GET,
        "/npm/testpkg/-/testpkg-1.0.0.tgz",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(&body_bytes(resp).await[..], tarball);

    // ensure_npm_metadata_cached must have synchronously cached the packument.
    let cached = ctx
        .state
        .storage
        .get("npm/testpkg/upstream/packument.json")
        .await
        .expect("metadata.json must be self-primed");
    let json: serde_json::Value = serde_json::from_slice(&cached).unwrap();
    assert_eq!(
        json["time"]["1.0.0"].as_str().unwrap(),
        "2020-01-15T10:30:00.000Z",
        "upstream release date must survive into the cached packument"
    );
    // Tarball URLs must be rewritten to NORA, not left pointing upstream.
    let tarball_url = json["versions"]["1.0.0"]["dist"]["tarball"]
        .as_str()
        .unwrap();
    assert!(
        !tarball_url.contains(&upstream.uri()[..]),
        "upstream tarball URL leaked into cached metadata: {tarball_url}"
    );
    // Stored against PUBLIC_BASE; every serve substitutes the current public_url.
    assert_eq!(
        tarball_url,
        format!("{}/npm/testpkg/-/testpkg-1.0.0.tgz", super::PUBLIC_BASE),
        "tarball URL not rewritten to NORA"
    );

    // The release dates are cached beside it, and the date resolves from them.
    let dates = ctx
        .state
        .storage
        .get("npm/testpkg/upstream/dates.json")
        .await
        .unwrap();
    let dates: serde_json::Value = serde_json::from_slice(&dates).unwrap();
    assert_eq!(dates["1.0.0"], "2020-01-15T10:30:00.000Z");
    let date = super::npm_publish_date(&ctx.state, "testpkg", "1.0.0").await;
    assert_eq!(
        date,
        Some(1579084200),
        "ISO 8601 → Unix for 2020-01-15T10:30:00Z"
    );
}

/// C49: with untrusted dates neither the packument's `time` nor its cache mtime
/// (moved to now by every metadata refresh) is a publish date.
#[tokio::test]
async fn test_extract_npm_publish_date_untrusted_ignores_mtime() {
    for trust in [false, true] {
        let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
            cfg.server.trust_upstream_dates = trust;
        });
        let meta = serde_json::json!({ "time": { "1.0.0": "2020-01-15T10:30:00.000Z" } });
        ctx_seed_metadata(&ctx, "p", &meta).await;
        let date = super::npm_publish_date(&ctx.state, "p", "1.0.0").await;
        assert_eq!(date, trust.then_some(1579084200), "trust={trust}");
    }
}

/// Cached metadata short-circuits ensure_npm_metadata_cached — no upstream
/// hit on a second tarball fetch (the packument is already in storage).
#[tokio::test]
async fn test_npm_tarball_self_prime_skips_when_metadata_cached() {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;

    // Pre-seed the packument so ensure_npm_metadata_cached early-returns.
    let link = format!("{}/cachedpkg/-/cachedpkg-1.0.0.tgz", upstream.uri());
    let packument = serde_json::json!({
        "name": "cachedpkg",
        "versions": { "1.0.0": { "dist": { "tarball": link } } },
        "time": { "1.0.0": "2019-05-01T00:00:00.000Z" }
    });

    let tarball = b"TGZ";
    Mock::given(method("GET"))
        .and(path("/cachedpkg/-/cachedpkg-1.0.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball.to_vec()))
        .mount(&upstream)
        .await;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
    });
    ctx_seed_metadata(&ctx, "cachedpkg", &packument).await;

    let resp = send(
        &ctx.app,
        Method::GET,
        "/npm/cachedpkg/-/cachedpkg-1.0.0.tgz",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(&body_bytes(resp).await[..], tarball);

    let packument_hits = upstream
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.url.path() == "/cachedpkg")
        .count();
    assert_eq!(
        packument_hits, 0,
        "metadata already cached → ensure_npm_metadata_cached must NOT hit upstream"
    );
}

/// Font Awesome's registry serves tarballs at `<name>/-/<version>/<file>.tgz`.
/// The allowlist must read the version from that form too: without it the
/// request carries no version and passes as a metadata request.
#[tokio::test]
async fn allowlist_checks_a_tarball_under_a_version_directory() {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    for version in ["0.9.0", "1.0.0"] {
        Mock::given(method("GET"))
            .and(path(format!(
                "/@fortawesome/pro-test/-/{version}/pro-test-{version}.tgz"
            )))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(format!("TGZ {version}").into_bytes()),
            )
            .mount(&upstream)
            .await;
    }
    super::mount_listing(
        &upstream,
        "@fortawesome/pro-test",
        &[
            ("0.9.0", "@fortawesome/pro-test/-/0.9.0/pro-test-0.9.0.tgz"),
            ("1.0.0", "@fortawesome/pro-test/-/1.0.0/pro-test-1.0.0.tgz"),
        ],
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let allowlist = dir.path().join("allowlist.json");
    std::fs::write(
        &allowlist,
        r#"{"version": 1, "entries": [
                {"registry": "npm", "name": "@fortawesome/pro-test", "version": "0.9.0"}
            ]}"#,
    )
    .unwrap();
    let ctx = create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.allowlist_path = Some(allowlist.to_string_lossy().into_owned());
    });
    let tarball_requests = || async {
        upstream
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.url.path().ends_with(".tgz"))
            .count()
    };

    let resp = send(
        &ctx.app,
        Method::GET,
        "/npm/@fortawesome/pro-test/-/1.0.0/pro-test-1.0.0.tgz",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "unlisted version");
    assert_eq!(
        tarball_requests().await,
        0,
        "a blocked tarball is not fetched"
    );

    let resp = send(
        &ctx.app,
        Method::GET,
        "/npm/@fortawesome/pro-test/-/0.9.0/pro-test-0.9.0.tgz",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "control: the listed version");
    assert_eq!(&body_bytes(resp).await[..], b"TGZ 0.9.0");
}

/// The allowlist matches name and version. A tarball whose version cannot be
/// read from its path is refused rather than passed on as a metadata request —
/// including a version directory that names another version than the file.
/// GitHub Packages serves tarballs at `download/<@scope/name>/<version>/<sha1>`, with
/// no `/-/`. That is a tarball download: curation sees its version, and the object is
/// stored as that version's tarball with its hash sidecar and served as one.
#[tokio::test]
async fn a_github_packages_tarball_is_a_download() {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{header, Method, StatusCode};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SHA: &str = "04fef883382f5a7c9b9ac2015dcc419009e2a858";
    let upstream = MockServer::start().await;
    for version in ["0.9.0", "1.0.0"] {
        Mock::given(method("GET"))
            .and(path(format!("/download/@vendor/a/{version}/{SHA}")))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(format!("TGZ {version}").into_bytes()),
            )
            .mount(&upstream)
            .await;
    }
    let at = |version: &str| format!("download/@vendor/a/{version}/{SHA}");
    let (old, new) = (at("0.9.0"), at("1.0.0"));
    super::mount_listing(&upstream, "@vendor/a", &[("0.9.0", &old), ("1.0.0", &new)]).await;
    let dir = tempfile::tempdir().unwrap();
    let allowlist = dir.path().join("allowlist.json");
    std::fs::write(
        &allowlist,
        r#"{"version": 1, "entries": [{"registry": "npm", "name": "@vendor/a", "version": "0.9.0"}]}"#,
    )
    .unwrap();
    let allowlist = allowlist.to_string_lossy().into_owned();
    let ctx = create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.allowlist_path = Some(allowlist);
    });

    let resp = send(
        &ctx.app,
        Method::GET,
        &format!("/npm/download/@vendor/a/1.0.0/{SHA}"),
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "unlisted version");
    let fetched = upstream.received_requests().await.unwrap();
    assert!(
        fetched
            .iter()
            .all(|r| !r.url.path().starts_with("/download/")),
        "a refused tarball is not fetched"
    );

    let resp = send(
        &ctx.app,
        Method::GET,
        &format!("/npm/download/@vendor/a/0.9.0/{SHA}"),
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "control: the listed version");
    assert_eq!(
        resp.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/octet-stream"
    );
    assert_eq!(&body_bytes(resp).await[..], b"TGZ 0.9.0");
    let storage = &ctx.state.storage;
    // The cache write runs in the background: wait for it, with a deadline.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    for key in [
        "npm/@vendor/a/tarballs/a-0.9.0.tgz",
        "npm/@vendor/a/tarballs/a-0.9.0.tgz.sha256",
    ] {
        while storage.stat(key).await.is_none() {
            assert!(tokio::time::Instant::now() < deadline, "{key} never stored");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
    assert!(
        storage.list("npm/download/").await.unwrap().is_empty(),
        "no tarball stored as a packument"
    );
}

/// A GitHub Packages download path of a version the upstream's packument does not list is
/// not asked for, as for the `/-/` form: 404, no `/download/` request.
#[tokio::test]
async fn an_unlisted_github_packages_download_is_not_asked_for() {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SHA: &str = "04fef883382f5a7c9b9ac2015dcc419009e2a858";
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/download/@vendor/a/0.9.0/{SHA}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"UNLISTED".to_vec()))
        .mount(&upstream)
        .await;
    let listed = format!("download/@vendor/a/1.0.0/{SHA}");
    super::mount_listing(&upstream, "@vendor/a", &[("1.0.0", &listed)]).await;
    let ctx = create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
    });
    let resp = send(
        &ctx.app,
        Method::GET,
        &format!("/npm/download/@vendor/a/0.9.0/{SHA}"),
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let fetched = upstream.received_requests().await.unwrap();
    assert!(
        fetched
            .iter()
            .all(|r| !r.url.path().starts_with("/download/")),
        "an unlisted tarball was fetched"
    );
}

/// A GitHub Packages download path of a package whose packument the upstream does not have
/// (404) is not asked for either: 404, no `/download/` request, nothing cached.
#[tokio::test]
async fn a_github_packages_download_without_a_packument_upstream_is_not_asked_for() {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SHA: &str = "04fef883382f5a7c9b9ac2015dcc419009e2a858";
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/download/@vendor/a/1.0.0/{SHA}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"UNLISTED".to_vec()))
        .mount(&upstream)
        .await;
    let ctx = create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
    });
    let resp = send(
        &ctx.app,
        Method::GET,
        &format!("/npm/download/@vendor/a/1.0.0/{SHA}"),
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let fetched = upstream.received_requests().await.unwrap();
    assert!(
        fetched
            .iter()
            .all(|r| !r.url.path().starts_with("/download/")),
        "a tarball without a packument was fetched"
    );
    let cached = ctx.state.storage.list("npm/").await.unwrap();
    assert!(cached.iter().all(|k| !k.contains("tarballs")), "{cached:?}");
}

#[tokio::test]
async fn allowlist_refuses_a_tarball_whose_version_it_cannot_read() {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"name":"pkg","versions":{}}"#))
        .mount(&upstream)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let allowlist = dir.path().join("allowlist.json");
    std::fs::write(
        &allowlist,
        r#"{"version": 1, "entries": [{"registry": "npm", "name": "pkg", "version": "1.0.0"}]}"#,
    )
    .unwrap();
    let allowlist = allowlist.to_string_lossy().into_owned();
    let ctx = create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.allowlist_path = Some(allowlist);
    });
    for path in ["/npm/pkg/-/pkg.tgz", "/npm/pkg/-/9.9.9/pkg-1.0.0.tgz"] {
        let resp = send(&ctx.app, Method::GET, path, "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{path}");
    }
    let fetched = upstream.received_requests().await.unwrap();
    assert!(
        fetched.iter().all(|r| !r.url.path().ends_with(".tgz")),
        "a refused tarball is not fetched: {:?}",
        fetched
            .iter()
            .map(|r| r.url.path().to_string())
            .collect::<Vec<_>>()
    );
    let resp = send(&ctx.app, Method::GET, "/npm/pkg", "").await;
    assert_ne!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "control: the packument passes"
    );
}

/// In audit mode the same tarball is logged, not refused; with no version to look up in the
/// upstream's packument it is not fetched either.
#[tokio::test]
async fn audit_mode_does_not_refuse_a_tarball_with_an_unread_version() {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/pkg/-/pkg.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"TGZ".to_vec()))
        .mount(&upstream)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let allowlist = dir.path().join("allowlist.json");
    std::fs::write(
        &allowlist,
        r#"{"version": 1, "entries": [{"registry": "npm", "name": "pkg", "version": "1.0.0"}]}"#,
    )
    .unwrap();
    let allowlist = allowlist.to_string_lossy().into_owned();
    let ctx = create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
        cfg.curation.mode = crate::config::CurationMode::Audit;
        cfg.curation.allowlist_path = Some(allowlist);
    });
    let resp = send(&ctx.app, Method::GET, "/npm/pkg/-/pkg.tgz", "").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let asked = upstream.received_requests().await.unwrap();
    assert!(asked.iter().all(|r| r.url.path() != "/pkg/-/pkg.tgz"));
}

/// Internal-namespace package: ensure_npm_metadata_cached must never fetch
/// the packument upstream (#68 dependency confusion).
#[tokio::test]
async fn test_npm_tarball_self_prime_skips_internal_namespace() {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    // Any upstream hit would be a dependency-confusion leak — mount a canary.
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("LEAKED"))
        .mount(&upstream)
        .await;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.internal_namespaces = vec!["@internal/*".to_string()];
    });

    // Tarball not in cache → proxy path, but ensure_npm_metadata_cached must
    // skip the packument fetch for the internal name. Namespace isolation
    // blocks the upstream branch for an internal name → 403 (not 404).
    let resp = send(
        &ctx.app,
        Method::GET,
        "/npm/@internal/secret/-/secret-1.0.0.tgz",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let packument_hits = upstream
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.url.path().contains("@internal/secret"))
        .count();
    assert_eq!(
        packument_hits, 0,
        "internal-namespace packument must never be fetched upstream (#68)"
    );
}

/// `trust_upstream_dates = false`: the packument is asked once, for the listing the download
/// is checked against. The count is the same whether or not the self-prime ran, so this does
/// not tell the gate's branches apart; `upstream_dates_gate` does, by the release-age verdict.
#[tokio::test]
async fn with_distrusted_dates_a_tarball_asks_the_packument_once_for_its_listing() {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    let tarball = b"TGZ";
    Mock::given(method("GET"))
        .and(path("/distrust/-/distrust-1.0.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball.to_vec()))
        .mount(&upstream)
        .await;
    super::mount_listing(
        &upstream,
        "distrust",
        &[("1.0.0", "distrust/-/distrust-1.0.0.tgz")],
    )
    .await;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
        cfg.server.trust_upstream_dates = false; // gate closed
    });

    let resp = send(
        &ctx.app,
        Method::GET,
        "/npm/distrust/-/distrust-1.0.0.tgz",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(&body_bytes(resp).await[..], tarball);

    let packument_hits = upstream
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.url.path() == "/distrust")
        .count();
    assert_eq!(packument_hits, 1, "one fetch of the listing, no self-prime");
}

/// No upstream proxy configured → ensure_npm_metadata_cached early-returns
/// (proxy_url is None) and the tarball cache-miss yields 404.
#[tokio::test]
async fn test_npm_tarball_self_prime_skipped_when_no_proxy() {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};

    // No proxy → both the tarball and the self-prime fetch have nowhere to go.
    let ctx = create_test_context_with_config(|cfg| {
        cfg.npm.proxy = None;
    });
    let resp = send(
        &ctx.app,
        Method::GET,
        "/npm/noproxy/-/noproxy-1.0.0.tgz",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    // metadata.json must NOT exist (self-prime had no upstream to fetch from).
    assert!(
        ctx.state
            .storage
            .get("npm/noproxy/metadata.json")
            .await
            .is_err(),
        "no proxy → metadata.json must not be self-primed"
    );
}

/// JSON-parse failure in the upstream packument falls back to byte-level URL
/// rewrite (replace_upstream_bytes), so the cached metadata still has NORA
/// URLs and the body is preserved (fail-safe, not dropped). A packument that does not
/// parse lists no version, so the tarball itself is not asked for.
#[tokio::test]
async fn test_npm_tarball_self_prime_byte_level_rewrite_on_invalid_json() {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;

    // Malformed packument (not valid JSON) carrying an upstream tarball URL
    // that the byte-level rewrite must still replace.
    let upstream_uri = upstream.uri();
    let upstream_uri_trimmed = upstream_uri.trim_end_matches('/');
    let bogus_packument = format!(
        "{{ not-valid-json \"tarball\": \"{upstream_uri_trimmed}/badpkg/-/badpkg-1.0.0.tgz\" }}"
    );
    Mock::given(method("GET"))
        .and(path("/badpkg"))
        .respond_with(ResponseTemplate::new(200).set_body_string(bogus_packument.clone()))
        .mount(&upstream)
        .await;

    let tarball = b"TGZ";
    Mock::given(method("GET"))
        .and(path("/badpkg/-/badpkg-1.0.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball.to_vec()))
        .mount(&upstream)
        .await;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
    });

    let resp = send(&ctx.app, Method::GET, "/npm/badpkg/-/badpkg-1.0.0.tgz", "").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_ne!(&body_bytes(resp).await[..], tarball);
    let asked = upstream.received_requests().await.unwrap();
    assert!(asked.iter().all(|r| !r.url.path().ends_with(".tgz")));

    let cached = ctx
        .state
        .storage
        .get("npm/badpkg/upstream/packument.json")
        .await
        .expect("metadata.json must be cached even for non-JSON packument");
    let cached_str = String::from_utf8_lossy(&cached);
    assert!(
        !cached_str.contains(upstream_uri_trimmed),
        "upstream URL leaked through byte-level rewrite: {cached_str}"
    );
    // Body preserved (byte-level rewrite is a prefix replace, not a drop).
    assert!(
        cached_str.contains("/npm/badpkg/-/badpkg-1.0.0.tgz"),
        "byte-level rewrite must substitute the NORA npm base: {cached_str}"
    );
}

// ── ensure_npm_metadata_cached test helpers ──

async fn ctx_seed_metadata(
    ctx: &crate::test_helpers::TestContext,
    name: &str,
    packument: &serde_json::Value,
) {
    ctx.state
        .storage
        .put(
            &format!("npm/{name}/metadata.json"),
            &serde_json::to_vec(packument).unwrap(),
        )
        .await
        .unwrap();
}

/// #975: `npm/{name}/metadata.json` is the assembled form of keys this registry
/// owns, so the proxy branch must never cache an upstream packument there while
/// `versions/` is non-empty. That branch is reached on the metadata path only by
/// falling through the rebuild — its write failed, or the read-back missed — and a
/// cached upstream document drops every locally published version. It does not
/// self-heal either: the read-path rebuild triggers on the key being absent, and
/// after such a write it exists with the wrong content.
#[tokio::test]
async fn npm_proxy_does_not_cache_upstream_packument_over_local_versions() {
    use crate::storage::{FileMeta, ObjectStorage, Storage, StorageBackend};
    use std::sync::{Arc, Mutex};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const UPSTREAM_MARKER: &str = "upstream-only-packument";
    const PACKUMENT_KEY: &str = "npm/hybrid/metadata.json";

    /// Reproduces the fall-through with no timing games: reads of the packument key
    /// always miss, so the rebuild runs, writes, and the read-back still misses.
    /// Every write is recorded so the test can assert what reached the key.
    struct PackumentReadAlwaysMisses {
        inner: ObjectStorage,
        writes: Arc<Mutex<Vec<(String, String)>>>,
    }

    #[async_trait::async_trait]
    impl StorageBackend for PackumentReadAlwaysMisses {
        async fn get(
            &self,
            key: &str,
        ) -> crate::storage::Result<(axum::body::Bytes, Option<String>)> {
            if key == PACKUMENT_KEY {
                return Err(crate::storage::StorageError::NotFound);
            }
            self.inner.get(key).await
        }
        async fn put(&self, k: &str, d: &[u8], sha256: &str) -> crate::storage::Result<()> {
            self.writes
                .lock()
                .expect("writes mutex")
                .push((k.to_string(), String::from_utf8_lossy(d).to_string()));
            self.inner.put(k, d, sha256).await
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
            "packument-read-misses-test"
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

    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/hybrid"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            concat!(
                r#"{{"name":"hybrid","description":"{}","dist-tags":{{"latest":"9.9.9"}},"#,
                r#""versions":{{"9.9.9":{{"name":"hybrid","version":"9.9.9","#,
                r#""dist":{{"tarball":"http://up/hybrid/-/hybrid-9.9.9.tgz"}}}}}}}}"#
            ),
            UPSTREAM_MARKER
        )))
        .mount(&upstream)
        .await;

    let writes = Arc::new(Mutex::new(Vec::new()));
    let storage = Storage::from_backend(Arc::new(PackumentReadAlwaysMisses {
        inner: ObjectStorage::in_memory(),
        writes: Arc::clone(&writes),
    }));
    let ctx = crate::test_helpers::create_test_context_with_storage_and_config(storage, |cfg| {
        cfg.npm.proxy = Some(upstream.uri());
    });

    // One locally published version, so `versions/` is non-empty and the packument
    // key belongs to the local rebuild.
    ctx.state
        .storage
        .put(
            "npm/hybrid/versions/1.0.0.json",
            br#"{"name":"hybrid","version":"1.0.0","dist":{"tarball":"http://nora/npm/hybrid/-/hybrid-1.0.0.tgz"}}"#,
        )
        .await
        .unwrap();

    let holders = ctx.state.storage.holders();
    let response = send(&ctx.app, Method::GET, "/npm/hybrid", "").await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the request is still served"
    );

    // The proxy cache write is detached: wait until every write the request started has ended.
    crate::test_helpers::background_writes_done(&ctx.state.storage, holders).await;

    let recorded = writes.lock().expect("writes mutex").clone();
    let to_packument: Vec<&(String, String)> = recorded
        .iter()
        .filter(|(k, _)| k == PACKUMENT_KEY)
        .collect();
    // Positive control: the rebuild really ran and wrote the assembled document,
    // which is what puts this request on the fall-through path in the first place.
    assert!(
        to_packument.iter().any(|(_, body)| body.contains("1.0.0")),
        "the local rebuild must have written the assembled packument: {to_packument:?}"
    );
    assert!(
        !to_packument
            .iter()
            .any(|(_, body)| body.contains(UPSTREAM_MARKER)),
        "#975: the upstream packument must never be cached over a key the local versions own — found: {to_packument:?}"
    );
}

/// The packument rebuild reads `versions/` concurrently. It used to walk the keys
/// one at a time, which on an object store is a round-trip per version, and #956
/// put that walk on a read path — so a package with a few thousand versions paid
/// them serially on the first request after the packument went missing. A backend
/// that records how many reads are in flight at once proves the fan-out is real; a
/// sequential walk never exceeds one.
#[tokio::test(start_paused = true)]
async fn npm_packument_rebuild_reads_versions_concurrently() {
    use crate::storage::{FileMeta, ObjectStorage, Storage, StorageBackend};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct TracksInFlight {
        inner: ObjectStorage,
        in_flight: AtomicUsize,
        peak: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl StorageBackend for TracksInFlight {
        async fn get(
            &self,
            key: &str,
        ) -> crate::storage::Result<(axum::body::Bytes, Option<String>)> {
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(now, Ordering::SeqCst);
            // Hold the slot briefly so overlapping reads actually overlap.
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            let out = self.inner.get(key).await;
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            out
        }
        async fn put(&self, k: &str, d: &[u8], sha256: &str) -> crate::storage::Result<()> {
            self.inner.put(k, d, sha256).await
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
            "in-flight-tracking-test"
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

    let backend = Arc::new(TracksInFlight {
        inner: ObjectStorage::in_memory(),
        in_flight: AtomicUsize::new(0),
        peak: AtomicUsize::new(0),
    });
    let storage = Storage::from_backend(Arc::clone(&backend) as Arc<dyn StorageBackend>);

    for i in 1..=8 {
        storage
            .put(
                &format!("npm/conc/versions/1.0.{i}.json"),
                format!(r#"{{"name":"conc","version":"1.0.{i}"}}"#).as_bytes(),
            )
            .await
            .unwrap();
    }
    backend.peak.store(0, Ordering::SeqCst);

    crate::registry::npm::regenerate_packument(&storage, "conc")
        .await
        .expect("rebuild succeeds");

    assert!(
        backend.peak.load(Ordering::SeqCst) > 1,
        "the rebuild must read versions concurrently — peak in-flight reads was {}",
        backend.peak.load(Ordering::SeqCst)
    );
    // Correctness is unchanged: every version is still in the assembled document.
    let packument = storage.get("npm/conc/metadata.json").await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&packument).unwrap();
    let versions = json["versions"].as_object().expect("versions object");
    assert_eq!(versions.len(), 8, "all versions assembled: {versions:?}");
}

async fn publish(app: &axum::Router, name: &str, ver: &str) -> StatusCode {
    let short = name.rsplit('/').next().unwrap();
    let payload = serde_json::json!({
        "name": name,
        "versions": { ver: { "name": name, "version": ver, "dist": {} } },
        "_attachments": { format!("{short}-{ver}.tgz"): {
            "data": base64::engine::general_purpose::STANDARD.encode(b"tgz")
        } },
    });
    let body = Body::from(serde_json::to_vec(&payload).unwrap());
    send(app, Method::PUT, &format!("/npm/{name}"), body)
        .await
        .status()
}

async fn packument(app: &axum::Router, name: &str) -> serde_json::Value {
    let resp = send(app, Method::GET, &format!("/npm/{name}"), "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    serde_json::from_slice(&body_bytes(resp).await).unwrap()
}

/// R4-R13: a publish under a path that is not a package name is refused before anything
/// is stored: `foo/versions` would write its keys among those of `foo`.
#[tokio::test]
async fn publish_refuses_a_path_that_is_not_a_package_name() {
    let ctx = create_test_context();
    for name in [
        "foo/versions",
        "foo/tarballs/x",
        "@scope",
        "@scope/a/b",
        "@/a",
        ".hidden",
        "_private",
        "@scope/.x",
        &"a".repeat(215),
    ] {
        assert_eq!(
            publish(&ctx.app, name, "1.0.0").await,
            StatusCode::BAD_REQUEST,
            "{name}"
        );
    }
    assert!(ctx.state.storage.list("npm/").await.unwrap().is_empty());
    for name in ["foo", "@scope/foo", "@scope/_x", "Legacy.Name-1~x", "-"] {
        assert!(super::is_package_name(name), "{name}");
    }
    for name in ["with space", "caf\u{e9}", "a%2fb", "a\\b", ""] {
        assert!(!super::is_package_name(name), "{name}");
    }
    assert_eq!(publish(&ctx.app, "foo", "1.0.0").await, StatusCode::CREATED);
    assert_eq!(
        publish(&ctx.app, "@scope/foo", "1.0.0").await,
        StatusCode::CREATED
    );
}

/// R4-T05: concurrent publishes of different versions serialize on the package's
/// publish lock: the packument lists every one of them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_publishes_keep_every_version() {
    let ctx = create_test_context();
    let publishes = (0..16).map(|i| {
        let app = ctx.app.clone();
        tokio::spawn(async move { publish(&app, "race", &format!("1.0.{i}")).await })
    });
    for p in futures::future::join_all(publishes).await {
        assert_eq!(p.unwrap(), StatusCode::CREATED);
    }
    let doc = packument(&ctx.app, "race").await;
    assert_eq!(doc["versions"].as_object().unwrap().len(), 16);
}

/// R4-T05: of concurrent publishes of one version exactly one is stored; the rest are
/// conflicts, and the version keeps the first one's tarball.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_publishes_of_one_version_store_it_once() {
    let ctx = create_test_context();
    let publishes = (0..8).map(|_| {
        let app = ctx.app.clone();
        tokio::spawn(async move { publish(&app, "race", "1.0.0").await })
    });
    let mut statuses = Vec::new();
    for p in futures::future::join_all(publishes).await {
        statuses.push(p.unwrap());
    }
    let created = statuses.iter().filter(|s| **s == StatusCode::CREATED);
    assert_eq!(created.count(), 1, "{statuses:?}");
    assert!(
        statuses
            .iter()
            .all(|s| matches!(*s, StatusCode::CREATED | StatusCode::CONFLICT)),
        "{statuses:?}"
    );
    let doc = packument(&ctx.app, "race").await;
    assert_eq!(doc["versions"].as_object().unwrap().len(), 1);
}

/// R4-T13: a dist-tag whose current target cannot be read is not moved: the publish
/// fails and is undone, instead of recording "no tag before" for an undo to delete.
#[tokio::test]
async fn publish_fails_when_the_moved_dist_tag_is_unreadable() {
    let (storage, outage) = crate::test_helpers::outage_storage();
    let ctx = crate::test_helpers::create_test_context_with_storage(storage);
    let tagged = |ver: &str| {
        let payload = serde_json::json!({
            "name": "tagged",
            "dist-tags": { "latest": ver },
            "versions": { ver: { "name": "tagged", "version": ver, "dist": {} } },
            "_attachments": { format!("tagged-{ver}.tgz"): {
                "data": base64::engine::general_purpose::STANDARD.encode(b"tgz")
            } },
        });
        let body = Body::from(serde_json::to_vec(&payload).unwrap());
        send(&ctx.app, Method::PUT, "/npm/tagged", body)
    };
    assert!(tagged("1.0.0").await.status().is_success());

    outage.fail_reads_of("npm/tagged/dist-tags/latest");
    let failed = tagged("1.0.1").await.status();
    outage.end();
    assert_eq!(failed, StatusCode::INTERNAL_SERVER_ERROR);
    let storage = &ctx.state.storage;
    let latest = storage.get("npm/tagged/dist-tags/latest").await.unwrap();
    assert_eq!(&latest[..], b"1.0.0");
    assert!(storage
        .stat("npm/tagged/versions/1.0.1.json")
        .await
        .is_none());
}

/// A package published here, outside any internal namespace, is never
/// revalidated upstream once its packument is stale: an upstream squatter of the
/// same name must not replace it, and the name must not leak upstream.
#[tokio::test]
async fn hosted_packument_is_never_revalidated_upstream() {
    use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};
    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "corp-pkg", "versions": { "9.9.9": { "dist": {} } },
            "dist-tags": { "latest": "9.9.9" }
        })))
        .mount(&upstream)
        .await;
    let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
        cfg.npm.metadata_ttl = 0; // every cache hit is stale
    });
    assert_eq!(
        publish(&ctx.app, "corp-pkg", "1.0.0").await,
        StatusCode::CREATED
    );

    let json = packument(&ctx.app, "corp-pkg").await;
    assert!(json["versions"].get("1.0.0").is_some(), "{json}");
    assert!(json["versions"].get("9.9.9").is_none(), "{json}");
    assert!(upstream.received_requests().await.unwrap().is_empty());
}

/// Invariant: an internal-namespace package published here never depends on the
/// upstream. With a dead upstream and every cache hit stale, its packument (full
/// and abbreviated) and tarball are 200 and the upstream sees no request at all.
#[tokio::test]
async fn internal_package_never_touches_a_dead_upstream() {
    use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};
    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(503))
        .mount(&upstream)
        .await;
    let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
        cfg.npm.metadata_ttl = 0;
        cfg.curation.internal_namespaces = vec!["@corp/*".to_string()];
    });
    assert_eq!(
        publish(&ctx.app, "@corp/lib", "1.0.0").await,
        StatusCode::CREATED
    );

    let resp = send(&ctx.app, Method::GET, "/npm/@corp/lib", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = crate::test_helpers::send_with_headers(
        &ctx.app,
        Method::GET,
        "/npm/@corp/lib",
        vec![("accept", "application/vnd.npm.install-v1+json")],
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = send(&ctx.app, Method::GET, "/npm/@corp/lib/-/lib-1.0.0.tgz", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(&body_bytes(resp).await[..], b"tgz");
    let seen = upstream.received_requests().await.unwrap();
    assert!(
        seen.is_empty(),
        "upstream contacted: {:?}",
        seen.iter()
            .map(|r| r.url.path().to_string())
            .collect::<Vec<_>>()
    );
}

/// Publishing a name whose packument is a proxy cache an older release left at the
/// published key (a provenance record for exactly these bytes) must not adopt the
/// upstream versions as local ones, nor refuse them as already published.
#[tokio::test]
async fn publish_over_proxied_packument_does_not_adopt_upstream_versions() {
    let ctx = create_test_context();
    let key = "npm/adopted/metadata.json";
    let upstream_doc = serde_json::json!({
        "name": "adopted",
        "versions": { "1.0.0": { "dist": {} }, "2.0.0": { "dist": {} } }
    });
    let doc = serde_json::to_vec(&upstream_doc).unwrap();
    ctx.state.storage.put(key, &doc).await.unwrap();
    let sidecar = super::origin_key(key);
    ctx.state
        .storage
        .put(&sidecar, super::provenance_record("npm:x", &doc).as_bytes())
        .await
        .unwrap();

    assert_eq!(
        publish(&ctx.app, "adopted", "1.0.0").await,
        StatusCode::CREATED
    );
    let stored = ctx.state.storage.get(key).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&stored).unwrap();
    assert_eq!(json["versions"].as_object().unwrap().len(), 1, "{json}");
    assert!(ctx
        .state
        .storage
        .stat("npm/adopted/versions/2.0.0.json")
        .await
        .is_none());
    assert!(
        super::is_assembled_by_nora(&ctx.state.storage, key, &stored).await,
        "the upstream record is replaced with the assembled one"
    );
}

/// A packument at the published key with no record of where it came from (or one written
/// for other bytes) on a package with no published versions may be an upstream copy: a
/// publish over it is refused until the operator says it is a package of their own.
#[tokio::test]
async fn a_publish_over_a_packument_of_unknown_origin_waits_for_the_operator() {
    let ctx = create_test_context();
    let key = "npm/unknown/metadata.json";
    let doc = serde_json::to_vec(&serde_json::json!({
        "name": "unknown",
        "versions": { "9.0.0": { "dist": {} } }
    }))
    .unwrap();
    ctx.state.storage.put(key, &doc).await.unwrap();
    ctx.state
        .storage
        .put(&super::origin_key(key), b"npm:x\nabc")
        .await
        .unwrap();
    assert_eq!(
        publish(&ctx.app, "unknown", "1.0.0").await,
        StatusCode::CONFLICT
    );
    assert!(ctx
        .state
        .storage
        .list("npm/unknown/versions/")
        .await
        .unwrap()
        .is_empty());
    assert_eq!(&ctx.state.storage.get(key).await.unwrap()[..], &doc[..]);
}

/// `npm dist-tag add|ls|rm` on a hosted package; `ls` is never proxied.
#[tokio::test]
async fn dist_tag_add_ls_rm() {
    let ctx = create_test_context();
    assert_eq!(
        publish(&ctx.app, "@corp/tagged", "1.0.0").await,
        StatusCode::CREATED
    );
    assert_eq!(
        publish(&ctx.app, "@corp/tagged", "2.0.0").await,
        StatusCode::CREATED
    );
    let tag_url = "/npm/-/package/@corp/tagged/dist-tags/beta";
    let ls_url = "/npm/-/package/@corp/tagged/dist-tags";

    let resp = send(&ctx.app, Method::PUT, tag_url, "\"1.0.0\"").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let tags: serde_json::Value =
        serde_json::from_slice(&body_bytes(send(&ctx.app, Method::GET, ls_url, "").await).await)
            .unwrap();
    assert_eq!(tags["beta"], "1.0.0");
    assert_eq!(tags["latest"], "2.0.0");
    assert_eq!(
        packument(&ctx.app, "@corp/tagged").await["dist-tags"]["beta"],
        "1.0.0"
    );

    // Unknown version, removing `latest`, unknown package: refused.
    let resp = send(&ctx.app, Method::PUT, tag_url, "\"3.0.0\"").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let latest = "/npm/-/package/@corp/tagged/dist-tags/latest";
    let resp = send(&ctx.app, Method::DELETE, latest, "").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let resp = send(&ctx.app, Method::GET, "/npm/-/package/nope/dist-tags", "").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let resp = send(&ctx.app, Method::DELETE, tag_url, "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(packument(&ctx.app, "@corp/tagged").await["dist-tags"]
        .get("beta")
        .is_none());
}

/// `npm deprecate` PUTs the packument back without attachments; only the
/// `deprecated` field is applied, and `""` clears it.
#[tokio::test]
async fn deprecate_sets_and_clears() {
    let ctx = create_test_context();
    assert_eq!(
        publish(&ctx.app, "old-pkg", "1.0.0").await,
        StatusCode::CREATED
    );
    let put = |msg: &str| {
        serde_json::to_vec(&serde_json::json!({
            "name": "old-pkg",
            "versions": { "1.0.0": { "deprecated": msg, "description": "ignored" } }
        }))
        .unwrap()
    };
    let resp = send(
        &ctx.app,
        Method::PUT,
        "/npm/old-pkg",
        Body::from(put("use v2")),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = packument(&ctx.app, "old-pkg").await;
    assert_eq!(json["versions"]["1.0.0"]["deprecated"], "use v2");
    assert!(json["versions"]["1.0.0"].get("description").is_none());

    let resp = send(&ctx.app, Method::PUT, "/npm/old-pkg", Body::from(put(""))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = packument(&ctx.app, "old-pkg").await;
    assert!(json["versions"]["1.0.0"].get("deprecated").is_none());
}

/// `npm unpublish` as the npm CLI drives it: PUT the packument minus a version to
/// `/-rev/`, DELETE the tarball by its URL path, DELETE `/-rev/` for the rest. A
/// version string is never published again.
#[tokio::test]
async fn unpublish_version_then_package() {
    let ctx = create_test_context();
    let name = "@corp/gone";
    for ver in ["1.0.0", "2.0.0"] {
        assert_eq!(publish(&ctx.app, name, ver).await, StatusCode::CREATED);
    }
    let tag = "/npm/-/package/@corp/gone/dist-tags/beta";
    assert_eq!(
        send(&ctx.app, Method::PUT, tag, "\"2.0.0\"").await.status(),
        StatusCode::OK
    );
    let put = |doc: &serde_json::Value| Body::from(serde_json::to_vec(doc).unwrap());
    let rev = "/npm/@corp/gone/-rev/undefined";

    // A body missing two versions is a stale read: refused, nothing removed.
    let mut doc = packument(&ctx.app, name).await;
    doc["versions"] = serde_json::json!({});
    let resp = send(&ctx.app, Method::PUT, rev, put(&doc)).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    let mut doc = packument(&ctx.app, name).await;
    doc["versions"].as_object_mut().unwrap().remove("2.0.0");
    let resp = send(&ctx.app, Method::PUT, rev, put(&doc)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = packument(&ctx.app, name).await;
    assert_eq!(json["versions"].as_object().unwrap().len(), 1, "{json}");
    assert_eq!(json["dist-tags"]["latest"], "1.0.0", "{json}");
    assert!(json["dist-tags"].get("beta").is_none(), "{json}");
    assert!(
        json["time"].get("2.0.0").is_some(),
        "tombstone kept: {json}"
    );
    let storage = &ctx.state.storage;
    assert!(storage
        .stat("npm/@corp/gone/tarballs/gone-2.0.0.tgz")
        .await
        .is_none());
    let resp = send(
        &ctx.app,
        Method::GET,
        "/npm/@corp/gone/-/gone-2.0.0.tgz",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // The tarball DELETE carries the tarball URL's path (`npm/` included).
    let del = "/npm/npm/@corp/gone/-/gone-2.0.0.tgz/-rev/2-x";
    assert_eq!(
        send(&ctx.app, Method::DELETE, del, "").await.status(),
        StatusCode::OK
    );
    let live = "/npm/npm/@corp/gone/-/gone-1.0.0.tgz/-rev/2-x";
    assert_eq!(
        send(&ctx.app, Method::DELETE, live, "").await.status(),
        StatusCode::CONFLICT,
        "a published version's tarball is not deleted"
    );

    assert_eq!(publish(&ctx.app, name, "2.0.0").await, StatusCode::CONFLICT);
    assert_eq!(publish(&ctx.app, name, "3.0.0").await, StatusCode::CREATED);

    let resp = send(&ctx.app, Method::DELETE, rev, "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = send(&ctx.app, Method::GET, "/npm/@corp/gone", "").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert!(storage
        .list("npm/@corp/gone/tarballs/")
        .await
        .unwrap()
        .is_empty());
    assert_eq!(publish(&ctx.app, name, "1.0.0").await, StatusCode::CONFLICT);

    // A package not published here is never unpublished (403: npm takes a 404
    // as already done).
    let resp = send(&ctx.app, Method::DELETE, "/npm/lodash/-rev/1", "").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// Hosted packuments carry `time` (per version, `created`, `modified`).
#[tokio::test]
async fn hosted_packument_has_time_map() {
    let ctx = create_test_context();
    assert_eq!(
        publish(&ctx.app, "timed", "1.0.0").await,
        StatusCode::CREATED
    );
    assert_eq!(
        publish(&ctx.app, "timed", "1.1.0").await,
        StatusCode::CREATED
    );
    let json = packument(&ctx.app, "timed").await;
    let time = &json["time"];
    assert_eq!(time["created"], time["1.0.0"], "{json}");
    assert_eq!(time["modified"], time["1.1.0"], "{json}");
}

fn iso_ago(secs: i64) -> String {
    (chrono::Utc::now() - chrono::Duration::seconds(secs))
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

/// R2-18: with the npm cooldown enforced on trusted dates, a version published
/// here (outside any internal namespace) downloads at once — its `time` is the
/// local publish time — while an upstream version that young is still refused.
#[tokio::test]
async fn hosted_version_is_exempt_from_min_release_age() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/young"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "young", "dist-tags": { "latest": "1.0.0" },
            "versions": { "1.0.0": { "dist": {} } },
            "time": { "1.0.0": iso_ago(3600) }
        })))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/young/-/young-1.0.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"tgz".to_vec()))
        .mount(&upstream)
        .await;
    let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.min_release_age = Some("7d".to_string());
        cfg.server.trust_upstream_dates = true;
    });
    assert_eq!(
        publish(&ctx.app, "ours", "1.0.0").await,
        StatusCode::CREATED
    );
    let resp = send(&ctx.app, Method::GET, "/npm/ours/-/ours-1.0.0.tgz", "").await;
    assert_eq!(resp.status(), StatusCode::OK, "our own publish is not held");
    assert_eq!(&body_bytes(resp).await[..], b"tgz");

    let resp = send(&ctx.app, Method::GET, "/npm/young/-/young-1.0.0.tgz", "").await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "upstream cooldown stays"
    );
}

/// R2-19: an attachment named for another version's tarball is refused, and the
/// bytes already published under that name are left alone; a different tarball
/// stored (not proxied) under a new version's name is a 409.
#[tokio::test]
async fn publish_cannot_overwrite_another_tarball() {
    let ctx = create_test_context();
    assert_eq!(publish(&ctx.app, "imm", "1.0.0").await, StatusCode::CREATED);
    let key = "npm/imm/tarballs/imm-1.0.0.tgz";
    let before = ctx.state.storage.get(key).await.unwrap();

    let payload = serde_json::json!({
        "name": "imm",
        "versions": { "1.0.1": { "name": "imm", "version": "1.0.1", "dist": {} } },
        "_attachments": { "imm-1.0.0.tgz": {
            "data": base64::engine::general_purpose::STANDARD.encode(b"evil")
        } },
    });
    let body = Body::from(serde_json::to_vec(&payload).unwrap());
    let resp = send(&ctx.app, Method::PUT, "/npm/imm", body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(ctx.state.storage.get(key).await.unwrap(), before);
    assert!(ctx
        .state
        .storage
        .stat("npm/imm/versions/1.0.1.json")
        .await
        .is_none());

    // A tarball already cached under the name of a version now published here.
    ctx.state
        .storage
        .put("npm/imm/tarballs/imm-2.0.0.tgz", b"upstream bytes")
        .await
        .unwrap();
    assert_eq!(
        publish(&ctx.app, "imm", "2.0.0").await,
        StatusCode::CONFLICT
    );
    assert_eq!(
        &ctx.state
            .storage
            .get("npm/imm/tarballs/imm-2.0.0.tgz")
            .await
            .unwrap()[..],
        b"upstream bytes"
    );
}

/// R2-20: a package published here never fetches a tarball it does not have from
/// the upstream, and its name is kept out of the audit forwarded there.
#[tokio::test]
async fn hosted_package_never_reaches_upstream() {
    use wiremock::matchers::{any, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/-/npm/v1/security/advisories/bulk"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&upstream)
        .await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"squatted".to_vec()))
        .mount(&upstream)
        .await;
    let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.internal_namespaces = vec!["@corp/*".to_string()];
    });
    assert_eq!(
        publish(&ctx.app, "owned", "1.0.0").await,
        StatusCode::CREATED
    );

    let resp = send(&ctx.app, Method::GET, "/npm/owned/-/owned-0.9.0.tgz", "").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = send(&ctx.app, Method::GET, "/npm/owned/-/owned-1.0.0.tgz", "").await;
    assert_eq!(resp.status(), StatusCode::OK);

    let audit = serde_json::json!({ "owned": ["1.0.0"], "lodash": ["4.17.20"] });
    let resp = send(
        &ctx.app,
        Method::POST,
        "/npm/-/npm/v1/security/advisories/bulk",
        audit.to_string(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let requests = upstream.received_requests().await.unwrap();
    assert!(
        requests.iter().all(|r| !r.url.path().contains("owned")),
        "no request for the hosted name: {:?}",
        requests.iter().map(|r| r.url.path()).collect::<Vec<_>>()
    );
    let forwarded: serde_json::Value = serde_json::from_slice(
        &requests
            .iter()
            .find(|r| r.method.as_str() == "POST")
            .expect("the audit was forwarded")
            .body,
    )
    .unwrap();
    assert_eq!(forwarded, serde_json::json!({ "lodash": ["4.17.20"] }));
}

/// Tarball URLs follow the current `public_url` on every serve path: a fresh
/// hosted packument, a version stored with an absolute URL before PUBLIC_BASE, a
/// fresh proxied packument and one an upstream 304 keeps.
#[tokio::test]
async fn tarball_urls_follow_public_url() {
    use crate::test_helpers::{
        create_test_context_with_config, create_test_context_with_storage_and_config,
    };
    use wiremock::matchers::{header, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(header("if-none-match", "\"v1\""))
        .respond_with(ResponseTemplate::new(304))
        .with_priority(1)
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", "\"v1\"")
                .set_body_json(serde_json::json!({
                    "name": "lodash",
                    "versions": { "1.0.0": { "dist": {
                        "tarball": format!("{}/lodash/-/lodash-1.0.0.tgz", upstream.uri())
                    } } }
                })),
        )
        .mount(&upstream)
        .await;
    let old = create_test_context_with_config(|cfg| {
        cfg.server.public_url = Some("https://old.example".into());
        cfg.npm.proxy = Some(upstream.uri());
    });
    let storage = old.state.storage.clone();
    let tarball = |json: &serde_json::Value| json["versions"]["1.0.0"]["dist"]["tarball"].clone();

    assert_eq!(
        publish(&old.app, "hosted", "1.0.0").await,
        StatusCode::CREATED
    );
    assert_eq!(
        tarball(&packument(&old.app, "hosted").await),
        "https://old.example/npm/hosted/-/hosted-1.0.0.tgz"
    );
    assert_eq!(
        tarball(&packument(&old.app, "lodash").await),
        "https://old.example/npm/lodash/-/lodash-1.0.0.tgz"
    );
    // Published before PUBLIC_BASE: an absolute URL in the version document.
    storage
        .put(
            "npm/legacy/versions/1.0.0.json",
            br#"{"dist":{"tarball":"http://older:4000/npm/legacy/-/legacy-1.0.0.tgz"}}"#,
        )
        .await
        .unwrap();
    super::regenerate_packument(&storage, "legacy")
        .await
        .unwrap();
    // The proxy cache write is spawned; wait for it.
    for _ in 0..50 {
        if storage
            .stat("npm/lodash/upstream/packument.json")
            .await
            .is_some()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let new = create_test_context_with_storage_and_config(storage.clone(), |cfg| {
        cfg.server.public_url = Some("https://new.example/".into());
        cfg.npm.proxy = Some(upstream.uri());
    });
    for name in ["hosted", "legacy", "lodash"] {
        assert_eq!(
            tarball(&packument(&new.app, name).await),
            format!("https://new.example/npm/{name}/-/{name}-1.0.0.tgz"),
            "fresh {name}"
        );
    }

    // Stale: the upstream answers 304 and the cached body is served.
    crate::registry::write_validators(
        &storage,
        "npm/lodash/upstream/packument.json",
        &crate::registry::Validators {
            etag: Some("\"v1\"".to_string()),
            last_modified: None,
        },
    )
    .await;
    let stale = create_test_context_with_storage_and_config(storage, |cfg| {
        cfg.server.public_url = Some("https://stale.example".into());
        cfg.npm.proxy = Some(upstream.uri());
        cfg.npm.metadata_ttl = 0;
    });
    let before = crate::metrics::PROXY_UPSTREAM_304_TOTAL
        .with_label_values(&["npm"])
        .get();
    assert_eq!(
        tarball(&packument(&stale.app, "lodash").await),
        "https://stale.example/npm/lodash/-/lodash-1.0.0.tgz"
    );
    let after = crate::metrics::PROXY_UPSTREAM_304_TOTAL
        .with_label_values(&["npm"])
        .get();
    assert!(after > before, "served through a 304");
}

/// Digest quarantine never holds a tarball published here.
#[tokio::test]
async fn quarantine_skips_hosted_tarballs() {
    let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
        cfg.curation.quarantine = Some(crate::digest_quarantine::QuarantineMode::Enforce);
        cfg.curation.quarantine_ttl = Some("1h".to_string());
    });
    assert_eq!(
        publish(&ctx.app, "fresh", "1.0.0").await,
        StatusCode::CREATED
    );
    let resp = send(&ctx.app, Method::GET, "/npm/fresh/-/fresh-1.0.0.tgz", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(&body_bytes(resp).await[..], b"tgz");
}

/// An allowlisted integrity pin is checked on the first proxied download too: a
/// mismatching body is neither served nor cached.
#[tokio::test]
async fn integrity_pin_checked_on_first_proxied_download() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let upstream = MockServer::start().await;
    // Only a version the upstream's packument lists is downloaded; mounted first, it wins.
    super::mount_listing(
        &upstream,
        "pinned",
        &[("1.0.0", "pinned/-/pinned-1.0.0.tgz")],
    )
    .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"TAMPERED".to_vec()))
        .mount(&upstream)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let allowlist = dir.path().join("allowlist.json");
    let pin = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(b"GENUINE"));
    std::fs::write(
        &allowlist,
        format!(
            r#"{{"version": 1, "entries": [{{"registry": "npm", "name": "pinned",
                "version": "1.0.0", "integrity": "sha256:{pin}"}}]}}"#
        ),
    )
    .unwrap();
    let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.allowlist_path = Some(allowlist.to_string_lossy().into_owned());
    });
    let holders = ctx.state.storage.holders();
    let resp = send(&ctx.app, Method::GET, "/npm/pinned/-/pinned-1.0.0.tgz", "").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    crate::test_helpers::background_writes_done(&ctx.state.storage, holders).await;
    assert!(ctx
        .state
        .storage
        .stat("npm/pinned/tarballs/pinned-1.0.0.tgz")
        .await
        .is_none());
}

/// C54: a tarball published here that fails its pin may be the only copy: it is
/// kept, answered 500 when read whole and cut off when streamed, and its name never
/// goes upstream.
#[tokio::test]
async fn tampered_hosted_tarball_is_kept_not_refetched() {
    use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};
    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"upstream".to_vec()))
        .mount(&upstream)
        .await;
    let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
        cfg.server.stream_threshold_mb = 1;
    });
    let root = std::path::Path::new(&ctx.state.config.storage.path).to_path_buf();
    assert_eq!(
        publish(&ctx.app, "corp", "1.0.0").await,
        StatusCode::CREATED
    );
    let small = "npm/corp/tarballs/corp-1.0.0.tgz";
    std::fs::write(root.join(small), b"rot").unwrap();
    let holders = ctx.state.storage.holders();
    let resp = send(&ctx.app, Method::GET, "/npm/corp/-/corp-1.0.0.tgz", "").await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let big = "npm/corpbig/tarballs/corpbig-1.0.0.tgz";
    let mut bytes = vec![7u8; 2 * 1024 * 1024];
    ctx.state.storage.put(big, &bytes).await.unwrap();
    bytes[1_500_000] ^= 0xff;
    std::fs::write(root.join(big), &bytes).unwrap();
    let resp = send(
        &ctx.app,
        Method::GET,
        "/npm/corpbig/-/corpbig-1.0.0.tgz",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "headers go out before EOF");
    assert!(axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .is_err());

    crate::test_helpers::background_writes_done(&ctx.state.storage, holders).await;
    for key in [small, big] {
        assert!(ctx.state.storage.stat(key).await.is_some(), "{key} kept");
    }
    // Metadata lookups (publish dates) aside, no tarball is fetched.
    let requests = upstream.received_requests().await.unwrap();
    assert!(!requests.iter().any(|r| r.url.path().ends_with(".tgz")));
}

/// C54: a proxied tarball (provenance recorded for the bytes it holds) that fails
/// its pin is dropped and refetched. A publish over a proxied copy drops that
/// provenance, so the published tarball is never taken for one.
#[tokio::test]
async fn tampered_proxied_tarball_is_refetched() {
    use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};
    let upstream = MockServer::start().await;
    // Only a version the upstream's packument lists is downloaded; mounted first, it wins.
    super::mount_listing(&upstream, "prox", &[("1.0.0", "prox/-/prox-1.0.0.tgz")]).await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"upstream".to_vec()))
        .mount(&upstream)
        .await;
    let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
    });
    let key = "npm/prox/tarballs/prox-1.0.0.tgz";
    let uri = "/npm/prox/-/prox-1.0.0.tgz";
    let origin = super::origin_key(key);
    let holders = ctx.state.storage.holders();
    let resp = send(&ctx.app, Method::GET, uri, "").await;
    assert_eq!(&body_bytes(resp).await[..], b"upstream");
    for _ in 0..100 {
        if ctx.state.storage.get(&origin).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    std::fs::write(
        std::path::Path::new(&ctx.state.config.storage.path).join(key),
        b"rotten!!",
    )
    .unwrap();

    let resp = send(&ctx.app, Method::GET, uri, "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(&body_bytes(resp).await[..], b"upstream");
    let requests = upstream.received_requests().await.unwrap();
    let fetches = requests
        .iter()
        .filter(|r| r.url.path() == "/prox/-/prox-1.0.0.tgz");
    assert_eq!(fetches.count(), 2, "fetched, then refetched");
    // Let the background re-cache (tarball, then its provenance) land.
    let mut recached = false;
    for _ in 0..100 {
        if ctx.state.storage.get(key).await.is_ok() {
            recached = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(recached, "the refetched tarball is cached again");
    crate::test_helpers::background_writes_done(&ctx.state.storage, holders).await;

    assert_eq!(
        publish(&ctx.app, "prox", "1.0.0").await,
        StatusCode::CREATED
    );
    assert!(ctx.state.storage.get(&origin).await.is_err());
}

/// `npm ping`, `npm search` and `npm login` are registry endpoints, not packuments:
/// nothing under `npm/-/` is cached, and only search reaches the upstream, with
/// its query, while no name is private.
#[tokio::test]
async fn registry_endpoints_are_not_packuments() {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/-/v1/search"))
        .and(query_param("text", "left pad"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "objects": [], "total": 0
        })))
        .mount(&upstream)
        .await;
    let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
    });

    let resp = send(&ctx.app, Method::GET, "/npm/-/ping", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(&body_bytes(resp).await[..], b"{}");
    let resp = send(
        &ctx.app,
        Method::GET,
        "/npm/-/v1/search?text=left%20pad",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["total"], 0);
    let resp = send(&ctx.app, Method::GET, "/npm/-/org/corp/package", "").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let requests = upstream.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "only the search went upstream");
    assert!(ctx.state.storage.list("npm/-/").await.unwrap().is_empty());

    // Under a namespace filter the search text could carry a private name.
    let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
        cfg.curation.internal_namespaces = vec!["@corp/*".to_string()];
    });
    let resp = send(&ctx.app, Method::GET, "/npm/-/v1/search?text=%40corp", "").await;
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(upstream.received_requests().await.unwrap().len(), 1);
}

/// `npm login` gets a 405 that says how to set up a token, without credentials,
/// and the PUT never becomes a publish.
#[tokio::test]
async fn npm_login_points_at_token_setup() {
    let ctx = create_test_context_with_auth(&[("admin", "secret")]);
    let user = serde_json::json!({
        "_id": "org.couchdb.user:bob", "name": "bob", "password": "x",
        "_attachments": { "x.tgz": { "data": "eA==" } }, "versions": {}
    });
    let resp = send(
        &ctx.app,
        Method::PUT,
        "/npm/-/user/org.couchdb.user:bob",
        Body::from(serde_json::to_vec(&user).unwrap()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    let error = body_json(resp).await["error"].as_str().unwrap().to_string();
    assert!(error.contains("_authToken"), "{error}");
    assert!(ctx.state.storage.list("npm/").await.unwrap().is_empty());
}

async fn body_json(resp: axum::http::Response<Body>) -> serde_json::Value {
    serde_json::from_slice(&body_bytes(resp).await).unwrap()
}
