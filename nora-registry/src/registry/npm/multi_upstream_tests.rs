// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::config::{NpmConfig, NpmProxyEntry};
use crate::secrets::ProtectedString;
use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
use axum::http::{Method, StatusCode};
use wiremock::matchers::{any, header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const TOKEN: &str = "vendor-tok";

fn vendor_proxies(public: &str, private: &str) -> Vec<NpmProxyEntry> {
    let mut npm: NpmConfig = toml::from_str(&format!(
        r#"proxies = ["{public}", {{ url = "{private}", scopes = ["@vendor"], auth_bearer_env = "NORA_NPM_VENDOR_TOKEN" }}]"#
    ))
    .unwrap();
    if let NpmProxyEntry::Full(p) = &mut npm.proxies[1] {
        p.auth_bearer = Some(ProtectedString::from(TOKEN));
    }
    npm.proxies
}

/// Public upstream: 200 to anything, so only its request log tells.
async fn public_upstream() -> MockServer {
    let public = MockServer::start().await;
    Mock::given(any())
        .respond_with(
            ResponseTemplate::new(200).set_body_string(r#"{"name":"lodash","versions":{}}"#),
        )
        .mount(&public)
        .await;
    public
}

/// The public upstream must never see a private-scope name or the private token.
fn assert_public_clean(reqs: &[Request]) {
    for r in reqs {
        let url = r.url.as_str();
        let body = String::from_utf8_lossy(&r.body);
        assert!(
            !url.contains("vendor"),
            "private scope reached public upstream: {url}"
        );
        assert!(
            !body.contains("@vendor"),
            "private scope in a body sent to public: {body}"
        );
        let auth = r
            .headers
            .get("authorization")
            .map(|v| v.to_str().unwrap_or("?").to_string());
        assert!(
            auth.is_none(),
            "public upstream got an Authorization header: {auth:?} on {url}"
        );
    }
}

#[tokio::test]
async fn owned_scope_is_fetched_only_from_its_upstream_with_its_token() {
    let public = public_upstream().await;
    let private = MockServer::start().await;
    let packument = serde_json::json!({
        "name": "@vendor/a",
        "versions": { "1.0.0": { "dist": {
            "tarball": format!("{}/@vendor/a/-/a-1.0.0.tgz", private.uri())
        } } },
        "time": { "1.0.0": "2020-01-15T10:30:00.000Z" }
    });
    Mock::given(method("GET"))
        .and(path("/@vendor/a"))
        .and(header("authorization", "Bearer vendor-tok"))
        .respond_with(ResponseTemplate::new(200).set_body_string(packument.to_string()))
        .mount(&private)
        .await;
    Mock::given(method("GET"))
        .and(path("/@vendor/a/-/a-1.0.0.tgz"))
        .and(header("authorization", "Bearer vendor-tok"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"VENDOR-TGZ".to_vec()))
        .mount(&private)
        .await;

    let proxies = vendor_proxies(&public.uri(), &private.uri());
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.npm.proxies = proxies;
        cfg.npm.metadata_ttl = 0; // always stale → the second pass must refetch
        cfg.npm.serve_stale = false; // …so a refetch that went elsewhere fails loudly
    });

    // Packument twice: the second pass goes through the stale-refetch path,
    // which must route the same way.
    for pass in 0..2 {
        let resp = send(&ctx.app, Method::GET, "/npm/@vendor%2fa", "").await;
        assert_eq!(resp.status(), StatusCode::OK, "packument pass {pass}");
        let body = String::from_utf8_lossy(&body_bytes(resp).await).to_string();
        assert!(
            !body.contains(&private.uri()),
            "private registry host leaked to the client: {body}"
        );
        // The cache write is a background task; wait for it so the next pass
        // deterministically takes the stale-refetch path, not a second cold fetch.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        // Settled = body AND provenance sidecar written (#1055: an owned scope's
        // copy is only served once its origin is recorded).
        while ctx
            .state
            .storage
            .get(&super::origin_key("npm/@vendor/a/upstream/packument.json"))
            .await
            .is_err()
        {
            assert!(
                tokio::time::Instant::now() < deadline,
                "packument never cached"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
    let resp = send(&ctx.app, Method::GET, "/npm/@vendor/a/-/a-1.0.0.tgz", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(&body_bytes(resp).await[..], b"VENDOR-TGZ");

    // An unscoped package still goes to the public upstream, without a credential.
    let resp = send(&ctx.app, Method::GET, "/npm/lodash", "").await;
    assert_eq!(resp.status(), StatusCode::OK);

    let packument_fetches = private
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == "/@vendor/a")
        .count();
    assert_eq!(
        packument_fetches, 2,
        "first fetch and stale refetch both go to the owner"
    );

    let public_reqs = public.received_requests().await.unwrap();
    assert!(
        !public_reqs.is_empty(),
        "control: lodash must have reached public"
    );
    assert_public_clean(&public_reqs);
}

/// A locked install asks for the tarball first; the metadata self-prime that
/// resolves the release date (#748) must ask the owning upstream too.
#[tokio::test]
async fn tarball_first_self_prime_asks_the_owner() {
    let public = public_upstream().await;
    let private = MockServer::start().await;
    let packument = serde_json::json!({
        "name": "@vendor/a",
        "versions": { "1.0.0": { "dist": {
            "tarball": format!("{}/@vendor/a/-/a-1.0.0.tgz", private.uri())
        } } },
        "time": { "1.0.0": "2020-01-15T10:30:00.000Z" }
    });
    Mock::given(method("GET"))
        .and(path("/@vendor/a"))
        .and(header("authorization", "Bearer vendor-tok"))
        .respond_with(ResponseTemplate::new(200).set_body_string(packument.to_string()))
        .mount(&private)
        .await;
    Mock::given(method("GET"))
        .and(path("/@vendor/a/-/a-1.0.0.tgz"))
        .and(header("authorization", "Bearer vendor-tok"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"VENDOR-TGZ".to_vec()))
        .mount(&private)
        .await;
    let proxies = vendor_proxies(&public.uri(), &private.uri());
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.npm.proxies = proxies;
        cfg.server.trust_upstream_dates = true;
    });

    let resp = send(&ctx.app, Method::GET, "/npm/@vendor/a/-/a-1.0.0.tgz", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        ctx.state
            .storage
            .get("npm/@vendor/a/upstream/packument.json")
            .await
            .is_ok(),
        "the self-prime must have cached the owner's packument"
    );
    assert!(public.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_failing_private_upstream_never_falls_back_to_public() {
    let public = public_upstream().await;
    let private = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/@vendor/missing"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&private)
        .await;
    Mock::given(method("GET"))
        .and(path("/@vendor/broken"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&private)
        .await;

    let proxies = vendor_proxies(&public.uri(), &private.uri());
    let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxies = proxies);

    for uri in [
        "/npm/@vendor%2fmissing",
        "/npm/@vendor%2fbroken",
        "/npm/@vendor/missing/-/missing-1.0.0.tgz",
    ] {
        let resp = send(&ctx.app, Method::GET, uri, "").await;
        assert_ne!(
            resp.status(),
            StatusCode::OK,
            "{uri} must not be served from public"
        );
    }
    assert!(
        public.received_requests().await.unwrap().is_empty(),
        "no fallback to the public upstream for an owned scope"
    );
}

/// A dead private registry opens its own breaker only: public packages keep
/// being served (decision Б.3 of #1055 — breaker per upstream).
#[tokio::test]
async fn a_dead_private_upstream_does_not_open_the_public_breaker() {
    let public = public_upstream().await;
    let private = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(503))
        .mount(&private)
        .await;
    let proxies = vendor_proxies(&public.uri(), &private.uri());
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.npm.proxies = proxies;
        cfg.circuit_breaker.enabled = true;
        cfg.circuit_breaker.failure_threshold = 1;
        cfg.circuit_breaker.reset_timeout = 300;
    });

    for _ in 0..2 {
        let resp = send(&ctx.app, Method::GET, "/npm/@vendor%2fdown", "").await;
        assert_ne!(resp.status(), StatusCode::OK);
    }
    let resp = send(&ctx.app, Method::GET, "/npm/lodash", "").await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the public upstream must keep serving while the private one is down"
    );
    assert_public_clean(&public.received_requests().await.unwrap());
}

/// The second entry points — stale refetch and the tarball-first metadata
/// self-prime — report to the per-upstream breaker too: after the private
/// registry dies on both paths, the public one still refetches and self-primes.
#[tokio::test]
async fn refetch_and_self_prime_use_the_per_upstream_breaker() {
    let public = public_upstream().await;
    let private = MockServer::start().await;
    let packument = serde_json::json!({
        "name": "@vendor/a",
        "versions": { "1.0.0": { "dist": {
            "tarball": format!("{}/@vendor/a/-/a-1.0.0.tgz", private.uri())
        } } }
    });
    Mock::given(method("GET"))
        .and(path("/@vendor/a"))
        .respond_with(ResponseTemplate::new(200).set_body_string(packument.to_string()))
        .mount(&private)
        .await;
    let proxies = vendor_proxies(&public.uri(), &private.uri());
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.npm.proxies = proxies;
        cfg.npm.metadata_ttl = 0;
        cfg.npm.serve_stale = false;
        cfg.server.trust_upstream_dates = true;
        cfg.circuit_breaker.enabled = true;
        cfg.circuit_breaker.failure_threshold = 1;
        cfg.circuit_breaker.reset_timeout = 300;
    });
    let cached = |key: &str| {
        let storage = ctx.state.storage.clone();
        let key = key.to_string();
        async move {
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
            while storage.get(&key).await.is_err() {
                if tokio::time::Instant::now() >= deadline {
                    return false;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            true
        }
    };

    // Both packuments cached while everything is up.
    for uri in ["/npm/lodash", "/npm/@vendor%2fa"] {
        assert_eq!(
            send(&ctx.app, Method::GET, uri, "").await.status(),
            StatusCode::OK
        );
    }
    assert!(cached("npm/lodash/upstream/packument.json").await);
    let packument_origin = super::origin_key("npm/@vendor/a/upstream/packument.json");
    assert!(cached(&packument_origin).await);

    // The private registry dies; fail it on the refetch and the self-prime paths.
    private.reset().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(503))
        .mount(&private)
        .await;
    let r = send(&ctx.app, Method::GET, "/npm/@vendor%2fa", "").await;
    assert_ne!(r.status(), StatusCode::OK, "stale private refetch fails");
    let r = send(&ctx.app, Method::GET, "/npm/@vendor/b/-/b-1.0.0.tgz", "").await;
    assert_ne!(
        r.status(),
        StatusCode::OK,
        "private self-prime + fetch fail"
    );

    // Public: stale refetch and tarball-first self-prime still work.
    let r = send(&ctx.app, Method::GET, "/npm/lodash", "").await;
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "public refetch after private died"
    );
    let _ = send(
        &ctx.app,
        Method::GET,
        "/npm/lodash2/-/lodash2-1.0.0.tgz",
        "",
    )
    .await;
    assert!(
        cached("npm/lodash2/upstream/packument.json").await,
        "public self-prime after private died"
    );
    assert_public_clean(&public.received_requests().await.unwrap());
}

fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

/// npm 7+ always gzips the bulk audit body (measured, kit npm-client-matrix).
/// Refusing every encoded body made `npm audit` report "0 vulnerabilities" as
/// soon as a private scope was configured; it must be decoded, stripped and
/// forwarded, and the upstream's answer returned.
#[tokio::test]
async fn a_gzipped_bulk_audit_is_decoded_stripped_and_forwarded() {
    use crate::test_helpers::send_with_headers;
    let public = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/-/npm/v1/security/advisories/bulk"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"lodash":[{"id":1}]}"#))
        .mount(&public)
        .await;
    let private = MockServer::start().await;
    let proxies = vendor_proxies(&public.uri(), &private.uri());
    let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxies = proxies);

    let resp = send_with_headers(
        &ctx.app,
        Method::POST,
        "/npm/-/npm/v1/security/advisories/bulk",
        vec![
            ("content-encoding", "gzip"),
            ("content-type", "application/json"),
        ],
        gzip(br#"{"lodash":["4.17.0"],"@vendor/a":["1.0.0"]}"#),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(&body_bytes(resp).await[..], br#"{"lodash":[{"id":1}]}"#);

    let reqs = public.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1);
    assert!(
        reqs[0].headers.get("content-encoding").is_none(),
        "the stripped body goes out uncompressed"
    );
    assert!(String::from_utf8_lossy(&reqs[0].body).contains("lodash"));
    assert_public_clean(&reqs);
}

/// pnpm posts an npm6 dependency tree to `-/npm/v1/security/audits` (measured,
/// kit npm-audit-matrix). Without a filter it is forwarded like bulk; with a
/// private scope configured the tree cannot be stripped reliably, so it is
/// refused with an error pnpm prints — never a 405 with an empty body.
#[tokio::test]
async fn pnpm_full_audit_is_forwarded_or_refused_explicitly() {
    let body = r#"{"dependencies":{".":{"dependencies":{"fixture-pub":{"version":"1.0.0"}}}},"requires":{".":"0.0.0"}}"#;

    // No filter: forwarded verbatim, the upstream's answer returned.
    let public = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/-/npm/v1/security/audits"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"advisories":{},"metadata":{"vulnerabilities":{}}}"#),
        )
        .mount(&public)
        .await;
    let url = public.uri();
    let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxy = Some(url));
    let resp = send(
        &ctx.app,
        Method::POST,
        "/npm/-/npm/v1/security/audits",
        body,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(String::from_utf8_lossy(&body_bytes(resp).await).contains("vulnerabilities"));
    assert_eq!(public.received_requests().await.unwrap().len(), 1);

    // Private scope configured: refused, nothing sent.
    let public = public_upstream().await;
    let private = MockServer::start().await;
    let proxies = vendor_proxies(&public.uri(), &private.uri());
    let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxies = proxies);
    let resp = send(
        &ctx.app,
        Method::POST,
        "/npm/-/npm/v1/security/audits",
        body,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(String::from_utf8_lossy(&body_bytes(resp).await).contains("\"error\""));
    assert!(public.received_requests().await.unwrap().is_empty());
}

/// An encoding NORA does not decode is a 415, a corrupt gzip a 422 — both with
/// a JSON error the clients print.
#[tokio::test]
async fn unverifiable_audit_bodies_get_explicit_errors() {
    use crate::test_helpers::send_with_headers;
    let public = public_upstream().await;
    let private = MockServer::start().await;
    let proxies = vendor_proxies(&public.uri(), &private.uri());
    let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxies = proxies);
    let bulk = "/npm/-/npm/v1/security/advisories/bulk";

    let resp = send_with_headers(
        &ctx.app,
        Method::POST,
        bulk,
        vec![("content-encoding", "br")],
        "x",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let resp = send_with_headers(
        &ctx.app,
        Method::POST,
        bulk,
        vec![("content-encoding", "gzip")],
        "not-gzip",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let resp = send(&ctx.app, Method::POST, bulk, "[1,2,3]").await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(String::from_utf8_lossy(&body_bytes(resp).await).contains("\"error\""));
    assert!(public.received_requests().await.unwrap().is_empty());
}

/// A small gzip that expands past the audit cap is refused, not inflated.
#[tokio::test]
async fn a_gzip_bomb_audit_is_refused() {
    use crate::test_helpers::send_with_headers;
    let public = public_upstream().await;
    let private = MockServer::start().await;
    let proxies = vendor_proxies(&public.uri(), &private.uri());
    let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxies = proxies);

    let mut big = b"{\"lodash\":[\"".to_vec();
    big.extend(std::iter::repeat_n(b'1', super::NPM_AUDIT_BODY_CAP + 1));
    big.extend(b"\"]}");
    let bomb = gzip(&big);
    assert!(
        bomb.len() < 64 * 1024,
        "control: the bomb is small on the wire"
    );

    let resp = send_with_headers(
        &ctx.app,
        Method::POST,
        "/npm/-/npm/v1/security/advisories/bulk",
        vec![("content-encoding", "gzip")],
        bomb,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(String::from_utf8_lossy(&body_bytes(resp).await).contains("\"error\""));
    assert!(public.received_requests().await.unwrap().is_empty());
}

/// GitHub Packages puts scoped tarballs under `/download/@scope/name/…`: the
/// scope is not the first segment, and such a path must still go to the owner,
/// never to the default upstream (measured leak on the B arm, kit matrix 10.10).
#[tokio::test]
async fn a_ghp_form_download_path_goes_to_the_owner() {
    let public = public_upstream().await;
    let private = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(
            "/download/@vendor/a/1.0.0/d113f588ab0b17ddabe8d0db55fa83a741df6871",
        ))
        .and(header("authorization", "Bearer vendor-tok"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"VENDOR-TGZ".to_vec()))
        .mount(&private)
        .await;
    super::mount_listing(
        &private,
        "@vendor/a",
        &[(
            "1.0.0",
            "download/@vendor/a/1.0.0/d113f588ab0b17ddabe8d0db55fa83a741df6871",
        )],
    )
    .await;
    let proxies = vendor_proxies(&public.uri(), &private.uri());
    let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxies = proxies);

    let _ = send(
        &ctx.app,
        Method::GET,
        "/npm/download/@vendor/a/1.0.0/d113f588ab0b17ddabe8d0db55fa83a741df6871",
        "",
    )
    .await;
    // The tarball goes to the owner once; as for any tarball, so does the
    // packument read for the release date.
    let to_owner: Vec<String> = private
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.url.path().to_string())
        .collect();
    let tarball = "/download/@vendor/a/1.0.0/d113f588ab0b17ddabe8d0db55fa83a741df6871";
    assert_eq!(
        to_owner.iter().filter(|p| *p == tarball).count(),
        1,
        "{to_owner:?}"
    );
    assert!(
        to_owner.iter().all(|p| p == tarball || p == "/@vendor/a"),
        "{to_owner:?}"
    );
    assert_public_clean(&public.received_requests().await.unwrap());
}

/// Seed what a public-registry squatter left in the cache before `@vendor` got
/// an owner: a packument advertising 1.99.0 and its tarball. `origin` = the
/// upstream its provenance record names (None = a cache from before #1055);
/// `recorded_for` = the bytes that record was written for (None = these).
async fn seed_squatter(
    ctx: &crate::test_helpers::TestContext,
    origin: Option<String>,
    recorded_for: Option<&[u8]>,
) {
    let packument = serde_json::json!({
        "name": "@vendor/a",
        "versions": { "1.99.0": { "dist": { "tarball": "http://127.0.0.1/npm/@vendor/a/-/a-1.99.0.tgz" } } },
        "dist-tags": { "latest": "1.99.0" }
    });
    let meta = "npm/@vendor/a/metadata.json";
    let tgz = "npm/@vendor/a/tarballs/a-1.99.0.tgz";
    let packument = packument.to_string();
    let objects: [(&str, &[u8]); 2] = [(meta, packument.as_bytes()), (tgz, b"SQUATTER")];
    for (key, bytes) in objects {
        ctx.state.storage.put(key, bytes).await.unwrap();
        if let Some(origin) = &origin {
            let record = super::provenance_record(origin, recorded_for.unwrap_or(bytes));
            ctx.state
                .storage
                .put(&super::origin_key(key), record.as_bytes())
                .await
                .unwrap();
        }
    }
}

/// Once a scope has an owner, a copy cached from anywhere else — a squatter on
/// the public registry, a cache from before the scope was owned, or bytes that
/// replaced the owner's copy under its record (an older release after a
/// rollback, polygon U9) — is never served: not as a cache hit, not via Range,
/// not as a stale fallback. The owner's copy replaces it.
#[tokio::test]
async fn a_foreign_cached_copy_of_an_owned_scope_is_never_served() {
    use crate::test_helpers::send_with_headers;
    for foreign_origin in [None, Some("PUBLIC"), Some("OWNER, OTHER BYTES")] {
        let public = public_upstream().await;
        let private = MockServer::start().await;
        let owner_packument = serde_json::json!({
            "name": "@vendor/a",
            "versions": { "1.0.0": { "dist": {
                "tarball": format!("{}/@vendor/a/-/a-1.0.0.tgz", private.uri())
            } } },
            "dist-tags": { "latest": "1.0.0" }
        });
        Mock::given(method("GET"))
            .and(path("/@vendor/a"))
            .respond_with(ResponseTemplate::new(200).set_body_string(owner_packument.to_string()))
            .mount(&private)
            .await;
        Mock::given(method("GET"))
            .and(path("/@vendor/a/-/a-1.99.0.tgz"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&private)
            .await;
        let public_identity = crate::circuit_breaker::upstream_key("npm", &public.uri());
        let owner_identity = crate::circuit_breaker::upstream_key("npm", &private.uri());
        let proxies = vendor_proxies(&public.uri(), &private.uri());
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.npm.proxies = proxies;
            cfg.npm.metadata_ttl = 3600; // fresh: a plain TTL check would serve the squatter
        });
        match foreign_origin {
            None => seed_squatter(&ctx, None, None).await,
            Some("PUBLIC") => seed_squatter(&ctx, Some(public_identity.clone()), None).await,
            // The owner's record, left behind when other bytes replaced its copy.
            Some(_) => {
                seed_squatter(&ctx, Some(owner_identity.clone()), Some(b"owner bytes")).await
            }
        }

        let resp = send(&ctx.app, Method::GET, "/npm/@vendor%2fa", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = String::from_utf8_lossy(&body_bytes(resp).await).to_string();
        assert!(
            body.contains("1.0.0") && !body.contains("1.99.0"),
            "owner's packument, not the squatter's: {body}"
        );

        let resp = send(&ctx.app, Method::GET, "/npm/@vendor/a/-/a-1.99.0.tgz", "").await;
        assert_ne!(
            &body_bytes(resp).await[..],
            b"SQUATTER",
            "{foreign_origin:?}"
        );
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/npm/@vendor/a/-/a-1.99.0.tgz",
            vec![("range", "bytes=0-3")],
            "",
        )
        .await;
        assert_ne!(
            &body_bytes(resp).await[..],
            b"SQUA",
            "range must not serve it either"
        );
        assert_public_clean(&public.received_requests().await.unwrap());
    }
}

/// A dead owner is a gateway failure, not a missing package: 5xx or an
/// unreachable upstream → 502 (npm retries and reports E502), a real upstream
/// 404 → 404 (npm reports E404). Before, every cold-miss failure was a 404.
#[tokio::test]
async fn a_dead_upstream_is_502_and_a_missing_package_is_404() {
    let public = public_upstream().await;
    let private = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/@vendor/missing"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&private)
        .await;
    Mock::given(method("GET"))
        .and(path("/@vendor/throttled"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "7"))
        .mount(&private)
        .await;
    Mock::given(method("GET"))
        .and(path("/@vendor/denied"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&private)
        .await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(503))
        .mount(&private)
        .await;
    let proxies = vendor_proxies(&public.uri(), &private.uri());
    let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxies = proxies);

    for (uri, want) in [
        ("/npm/@vendor%2fmissing", StatusCode::NOT_FOUND),
        ("/npm/@vendor%2fdown", StatusCode::BAD_GATEWAY),
        // Throttling and auth refusals are not "no such package" either.
        ("/npm/@vendor%2fthrottled", StatusCode::SERVICE_UNAVAILABLE),
        ("/npm/@vendor%2fdenied", StatusCode::BAD_GATEWAY),
        (
            "/npm/@vendor/down/-/down-1.0.0.tgz",
            StatusCode::BAD_GATEWAY,
        ),
    ] {
        let resp = send(&ctx.app, Method::GET, uri, "").await;
        assert_eq!(resp.status(), want, "{uri}");
    }

    // Unreachable (connection refused) is a gateway failure too.
    let unreachable = vendor_proxies(&public.uri(), "http://127.0.0.1:1");
    let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxies = unreachable);
    let resp = send(&ctx.app, Method::GET, "/npm/@vendor%2fdown", "").await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

/// With the owner down, the foreign copy is still not served (no stale fallback).
#[tokio::test]
async fn a_dead_owner_does_not_resurrect_a_foreign_copy() {
    let public = public_upstream().await;
    let private = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(503))
        .mount(&private)
        .await;
    let proxies = vendor_proxies(&public.uri(), &private.uri());
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.npm.proxies = proxies;
        cfg.npm.metadata_ttl = 0;
        cfg.npm.serve_stale = true;
    });
    seed_squatter(&ctx, None, None).await;
    for uri in ["/npm/@vendor%2fa", "/npm/@vendor/a/-/a-1.99.0.tgz"] {
        let resp = send(&ctx.app, Method::GET, uri, "").await;
        assert_ne!(resp.status(), StatusCode::OK, "{uri}");
    }
}

/// The release date used by min-release-age comes from the owner's packument,
/// not from a foreign copy left in the cache: a squatter that advertises an old
/// publish time must not let a brand-new owner release past the age gate.
#[tokio::test]
async fn release_age_reads_the_owners_date_not_a_foreign_copy() {
    let public = public_upstream().await;
    let private = MockServer::start().await;
    let now = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S.000Z")
        .to_string();
    let owner_packument = serde_json::json!({
        "name": "@vendor/a",
        "versions": { "1.0.0": { "dist": {
            "tarball": format!("{}/@vendor/a/-/a-1.0.0.tgz", private.uri())
        } } },
        "time": { "1.0.0": now }
    });
    Mock::given(method("GET"))
        .and(path("/@vendor/a"))
        .respond_with(ResponseTemplate::new(200).set_body_string(owner_packument.to_string()))
        .mount(&private)
        .await;
    Mock::given(method("GET"))
        .and(path("/@vendor/a/-/a-1.0.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"NEW-TGZ".to_vec()))
        .mount(&private)
        .await;
    let proxies = vendor_proxies(&public.uri(), &private.uri());
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.npm.proxies = proxies;
        cfg.server.trust_upstream_dates = true;
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.min_release_age = Some("7d".to_string());
    });
    // A foreign packument claiming 1.0.0 is six years old, no provenance.
    let foreign = serde_json::json!({
        "name": "@vendor/a",
        "versions": { "1.0.0": { "dist": {} } },
        "time": { "1.0.0": "2020-01-01T00:00:00.000Z" }
    });
    ctx.state
        .storage
        .put(
            "npm/@vendor/a/metadata.json",
            foreign.to_string().as_bytes(),
        )
        .await
        .unwrap();

    let resp = send(&ctx.app, Method::GET, "/npm/@vendor/a/-/a-1.0.0.tgz", "").await;
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "a release the owner dates to today must be held by a 7d age gate"
    );
    assert_public_clean(&public.received_requests().await.unwrap());
}

/// What the owner delivered is cached and served without asking again; what was
/// published here is served even with the owner down.
#[tokio::test]
async fn owner_copies_and_local_publishes_are_served_from_cache() {
    use axum::body::Body;
    use base64::Engine as _;
    let public = public_upstream().await;
    let private = MockServer::start().await;
    let packument = serde_json::json!({
        "name": "@vendor/a",
        "versions": { "1.0.0": { "dist": {
            "tarball": format!("{}/@vendor/a/-/a-1.0.0.tgz", private.uri())
        } } }
    });
    Mock::given(method("GET"))
        .and(path("/@vendor/a"))
        .respond_with(ResponseTemplate::new(200).set_body_string(packument.to_string()))
        .mount(&private)
        .await;
    Mock::given(method("GET"))
        .and(path("/@vendor/a/-/a-1.0.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"OWNER-TGZ".to_vec()))
        .mount(&private)
        .await;
    let proxies = vendor_proxies(&public.uri(), &private.uri());
    let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxies = proxies);

    let resp = send(&ctx.app, Method::GET, "/npm/@vendor/a/-/a-1.0.0.tgz", "").await;
    assert_eq!(&body_bytes(resp).await[..], b"OWNER-TGZ");
    let origin_key = super::origin_key("npm/@vendor/a/tarballs/a-1.0.0.tgz");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while ctx.state.storage.get(&origin_key).await.is_err() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "origin never recorded"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    // Owner goes down: its own copy is still served from cache.
    private.reset().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(503))
        .mount(&private)
        .await;
    let resp = send(&ctx.app, Method::GET, "/npm/@vendor/a/-/a-1.0.0.tgz", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(&body_bytes(resp).await[..], b"OWNER-TGZ");

    // A package published here under the owned scope is ours: served.
    let payload = serde_json::json!({
        "name": "@vendor/local",
        "versions": { "1.0.0": { "dist": {} } },
        "_attachments": { "local-1.0.0.tgz": {
            "data": base64::engine::general_purpose::STANDARD.encode(b"LOCAL-TGZ")
        } },
        "dist-tags": { "latest": "1.0.0" }
    });
    let resp = send(
        &ctx.app,
        Method::PUT,
        "/npm/@vendor%2flocal",
        Body::from(serde_json::to_vec(&payload).unwrap()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let resp = send(
        &ctx.app,
        Method::GET,
        "/npm/@vendor/local/-/local-1.0.0.tgz",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(&body_bytes(resp).await[..], b"LOCAL-TGZ");
    let resp = send(&ctx.app, Method::GET, "/npm/@vendor%2flocal", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_public_clean(&public.received_requests().await.unwrap());
}

#[tokio::test]
async fn audit_to_the_default_upstream_never_carries_private_names() {
    let public = public_upstream().await;
    let private = MockServer::start().await;
    let proxies = vendor_proxies(&public.uri(), &private.uri());
    let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxies = proxies);

    let resp = send(
        &ctx.app,
        Method::POST,
        "/npm/-/npm/v1/security/advisories/bulk",
        r#"{"lodash":["4.17.0"],"@vendor/a":["1.0.0"]}"#,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // npm6 quick audit is a gzipped lockfile — names cannot be stripped, so it is
    // refused outright while any private scope is configured.
    let resp = send(
        &ctx.app,
        Method::POST,
        "/npm/-/npm/v1/security/audits/quick",
        r#"{"dependencies":{"@vendor/a":{"version":"1.0.0"}}}"#,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let reqs = public.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1, "only the stripped bulk audit is forwarded");
    assert!(String::from_utf8_lossy(&reqs[0].body).contains("lodash"));
    assert_public_clean(&reqs);
    assert!(private.received_requests().await.unwrap().is_empty());
}

// ── A name with an empty segment never names another key's file ─────────

/// `/npm/evil-pkg//-/evil-pkg-1.0.0.tgz` and `/npm//evil-pkg/-/...` name the canonical
/// tarball under the package names `evil-pkg/` and `/evil-pkg`, which the rule `evil-pkg`
/// does not match — refused before curation and storage.
#[tokio::test]
async fn a_tarball_path_with_an_empty_segment_is_refused_before_curation() {
    let dir = tempfile::tempdir().unwrap();
    let blocklist = dir.path().join("blocklist.json");
    std::fs::write(
        &blocklist,
        r#"{"version": 1, "rules": [{"registry": "npm", "name": "evil-pkg", "version": "*", "reason": "malware"}]}"#,
    )
    .unwrap();
    let ctx = create_test_context_with_config(|cfg| {
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.blocklist_path = Some(blocklist.to_string_lossy().into_owned());
    });
    // A tarball cached (or published) before the version was blocklisted.
    ctx.state
        .storage
        .put("npm/evil-pkg/tarballs/evil-pkg-1.0.0.tgz", b"MALWARE")
        .await
        .unwrap();
    let canonical = send(
        &ctx.app,
        Method::GET,
        "/npm/evil-pkg/-/evil-pkg-1.0.0.tgz",
        "",
    )
    .await;
    assert_eq!(canonical.status(), StatusCode::FORBIDDEN, "control");

    let mut served = Vec::new();
    for alias in [
        "/npm/evil-pkg//-/evil-pkg-1.0.0.tgz",
        "/npm//evil-pkg/-/evil-pkg-1.0.0.tgz",
    ] {
        let resp = send(&ctx.app, Method::GET, alias, "").await;
        if resp.status() == StatusCode::OK {
            served.push(format!("{alias} -> {:?}", body_bytes(resp).await));
        }
    }
    assert!(served.is_empty(), "blocklisted tarball served: {served:?}");
}

/// `/npm//internalpkg` names `/internalpkg`, which the isolation pattern `internal*` does
/// not match: it is refused, and the packument of an internal package is never requested
/// from the public upstream or cached over its own file.
#[tokio::test]
async fn a_leading_slash_name_never_takes_an_internal_package_upstream() {
    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "internalpkg",
            "versions": {"9.9.9": {"name": "internalpkg", "version": "9.9.9"}}
        })))
        .mount(&upstream)
        .await;
    let ctx = create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
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

    let resp = send(&ctx.app, Method::GET, "/npm/internalpkg", "").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "control");
    assert_eq!(leaked().await, 0, "control: canonical name is not proxied");

    let resp = send(&ctx.app, Method::GET, "/npm//internalpkg", "").await;
    assert_eq!(
        leaked().await,
        0,
        "internal package name sent to the public upstream (alias answered {})",
        resp.status()
    );
}

/// Every tarball path form with an empty segment is refused with 400 before curation,
/// storage or the upstream sees it.
#[tokio::test]
async fn every_tarball_path_with_an_empty_segment_never_reaches_upstream() {
    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"TARBALL".to_vec()))
        .mount(&upstream)
        .await;
    let ctx = create_test_context_with_config(|cfg| {
        cfg.npm.proxy = Some(upstream.uri());
        cfg.curation.internal_namespaces = vec!["internal*".to_string()];
    });
    for alias in [
        "/npm//internalpkg/-/internalpkg-1.0.0.tgz",
        "/npm/internalpkg//-/internalpkg-1.0.0.tgz",
        "/npm/lodash/-/lodash-4.17.21.tgz/",
        "/npm/lodash/-/",
    ] {
        let resp = send(&ctx.app, Method::GET, alias, "").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{alias}");
    }
    let reqs: Vec<String> = upstream
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.url.path().to_string())
        .collect();
    assert!(reqs.is_empty(), "sent upstream: {reqs:?}");
    // Legit tarball path still proxies.
    super::mount_listing(
        &upstream,
        "lodash",
        &[("4.17.21", "lodash/-/lodash-4.17.21.tgz")],
    )
    .await;
    let resp = send(
        &ctx.app,
        Method::GET,
        "/npm/lodash/-/lodash-4.17.21.tgz",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "control");
}
