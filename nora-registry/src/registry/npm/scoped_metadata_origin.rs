// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::config::{NpmConfig, NpmProxyEntry};
use crate::secrets::ProtectedString;
use crate::test_helpers::{create_test_context_with_config, send, TestContext};
use axum::http::{Method, StatusCode};
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A server that sends every request to `to` + its path.
async fn redirecting(to: &str) -> MockServer {
    let server = MockServer::start().await;
    let to = to.to_string();
    Mock::given(any())
        .respond_with(move |req: &wiremock::Request| {
            ResponseTemplate::new(302)
                .insert_header("location", format!("{to}{}", req.url.path()).as_str())
        })
        .mount(&server)
        .await;
    server
}

/// A server that answers anything with a packument listing `@vendor/pkg@1.0.0` and `pkg`'s.
async fn elsewhere() -> MockServer {
    let server = MockServer::start().await;
    let doc = |name: &str| {
        serde_json::json!({
            "name": name,
            "versions": {"1.0.0": {"name": name, "version": "1.0.0", "dist": {}}},
            "dist-tags": {"latest": "1.0.0"},
        })
    };
    Mock::given(any())
        .respond_with(move |req: &wiremock::Request| {
            let name = if req.url.path().contains("@vendor") {
                "@vendor/pkg"
            } else {
                "pkg"
            };
            ResponseTemplate::new(200).set_body_json(doc(name))
        })
        .mount(&server)
        .await;
    server
}

fn context(public: &str, private: &str) -> TestContext {
    let mut npm: NpmConfig = toml::from_str(&format!(
        r#"proxies = ["{public}", {{ url = "{private}", scopes = ["@vendor"], auth_bearer_env = "NORA_NPM_VENDOR_TOKEN" }}]"#
    ))
    .unwrap();
    if let NpmProxyEntry::Full(p) = &mut npm.proxies[1] {
        p.auth_bearer = Some(ProtectedString::from("vendor-tok"));
    }
    let proxies = npm.proxies;
    create_test_context_with_config(move |cfg| {
        cfg.npm.proxies = proxies;
        cfg.server.trust_upstream_dates = true;
    })
}

#[tokio::test]
async fn a_scoped_upstream_redirecting_metadata_elsewhere_is_502() {
    let foreign = elsewhere().await;
    let private = redirecting(&foreign.uri()).await;
    let public = MockServer::start().await;
    let ctx = context(&public.uri(), &private.uri());
    let holders = ctx.state.storage.holders();
    let mut wrong = Vec::new();
    for (uri, expected) in [
        ("/npm/@vendor%2fpkg", StatusCode::BAD_GATEWAY),
        ("/npm/@vendor/pkg", StatusCode::BAD_GATEWAY),
        ("/npm/@vendor/pkg/1.0.0", StatusCode::BAD_GATEWAY),
        ("/npm/@vendor/pkg/a/b", StatusCode::BAD_GATEWAY),
        // Maestra: `npm dist-tag ls` is answered from published packages only and never
        // proxied, so the name reaches no upstream at all.
        (
            "/npm/-/package/@vendor/pkg/dist-tags",
            StatusCode::NOT_FOUND,
        ),
        ("/npm/@vendor/pkg/-/pkg-1.0.0.tgz", StatusCode::BAD_GATEWAY),
    ] {
        let status = send(&ctx.app, Method::GET, uri, "").await.status();
        if status != expected {
            wrong.push(format!("{uri}: {status}, expected {expected}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
    let asked = foreign.received_requests().await.unwrap();
    assert!(asked.is_empty(), "the other origin was asked: {asked:?}");
    assert!(public.received_requests().await.unwrap().is_empty());
    crate::test_helpers::background_writes_done(&ctx.state.storage, holders).await;
    let written = ctx.state.storage.list("npm/").await.unwrap();
    assert!(written.is_empty(), "cached: {written:?}");
}

/// A scoped upstream that answers its packument after `hops` redirects on its own origin
/// (`/hop/1/…`, `/hop/2/…`, …).
async fn walking(hops: usize) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(move |req: &wiremock::Request| {
            let p = req.url.path();
            let (n, rest) = match p.strip_prefix("/hop/").and_then(|r| r.split_once('/')) {
                Some((n, rest)) => (n.parse::<usize>().unwrap(), format!("/{rest}")),
                None => (0, p.to_string()),
            };
            if n < hops {
                ResponseTemplate::new(302)
                    .insert_header("location", format!("/hop/{}{rest}", n + 1).as_str())
            } else {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "name": "@vendor/pkg",
                    "versions": {"1.0.0": {"name": "@vendor/pkg", "version": "1.0.0", "dist": {}}},
                    "dist-tags": {"latest": "1.0.0"},
                }))
            }
        })
        .mount(&server)
        .await;
    server
}

/// On its own origin a scoped upstream's metadata follows ten redirects, each with the
/// token, and the eleventh is 502.
#[tokio::test]
async fn a_scoped_upstreams_metadata_follows_ten_redirects_on_its_origin() {
    for (hops, expected) in [(10, StatusCode::OK), (11, StatusCode::BAD_GATEWAY)] {
        let private = walking(hops).await;
        let public = MockServer::start().await;
        let ctx = context(&public.uri(), &private.uri());
        let status = send(&ctx.app, Method::GET, "/npm/@vendor/pkg", "")
            .await
            .status();
        assert_eq!(status, expected, "{hops} redirects");
        let asked = private.received_requests().await.unwrap();
        assert!(
            asked
                .iter()
                .all(|r| r.headers.contains_key("authorization")),
            "{asked:?}"
        );
        if expected == StatusCode::OK {
            assert_eq!(asked.len(), hops + 1, "{asked:?}");
        }
    }
}

/// Control: the default upstream's redirect is followed, as before.
#[tokio::test]
async fn the_default_upstream_still_follows_a_redirect() {
    let foreign = elsewhere().await;
    let public = redirecting(&foreign.uri()).await;
    let private = MockServer::start().await;
    let ctx = context(&public.uri(), &private.uri());
    let status = send(&ctx.app, Method::GET, "/npm/pkg", "").await.status();
    assert_eq!(status, StatusCode::OK);
    assert!(!foreign.received_requests().await.unwrap().is_empty());
}

/// The audit endpoints name no scope, so they go to the default upstream — never one bound
/// to a scope, whose redirects are not followed.
#[test]
fn the_audit_endpoints_go_to_the_default_upstream() {
    let ctx = context("https://registry.example", "https://vendor.example");
    for path in [
        "-/npm/v1/security/advisories/bulk",
        "-/npm/v1/security/audits/quick",
        "-/npm/v1/security/audits",
    ] {
        let upstream = ctx.state.config.npm.route(path).unwrap();
        assert_eq!(upstream.url, "https://registry.example", "{path}");
        assert!(!upstream.scoped, "{path}");
    }
    assert!(ctx.state.config.npm.route("@vendor/pkg").unwrap().scoped);
}
