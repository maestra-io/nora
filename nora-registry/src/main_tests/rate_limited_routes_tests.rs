// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::*;
use std::net::SocketAddr;
use tower::ServiceExt;

async fn statuses(app: &Router, path: &str, count: usize) -> Vec<u16> {
    let mut out = Vec::new();
    for _ in 0..count {
        let mut req = axum::http::Request::builder()
            .method("PUT") // the upload tier limits write methods only
            .uri(path)
            .body(axum::body::Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(SocketAddr::from((
                [127, 0, 0, 1],
                4000,
            ))));
        out.push(app.clone().oneshot(req).await.unwrap().status().as_u16());
    }
    out
}

/// Every registry answer is inert in a browser: what a client or an upstream put in a
/// registry — HTML, SVG, an XML document with a stylesheet — cannot run script on NORA's
/// origin, whatever type the format serves it as. Package clients do not read the header.
#[tokio::test]
async fn every_registry_answer_carries_a_sandbox_policy() {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::{body::Body, http::Method};
    let ctx = create_test_context_with_config(|c| {
        c.registries = Some(crate::config::RegistriesSection {
            enable: Some(crate::config::EnableSpec::List(
                RegistryType::all()
                    .iter()
                    .map(|r| r.as_str().to_string())
                    .collect(),
            )),
        });
    });
    // RPM and Debian are compiled out without their features (the fork's CI runs both).
    let compiled = |rt: &RegistryType| {
        (cfg!(feature = "rpm") || *rt != RegistryType::Rpm)
            && (cfg!(feature = "deb") || *rt != RegistryType::Deb)
    };
    assert_eq!(
        ctx.state.enabled_registries.len(),
        RegistryType::all().iter().filter(|rt| compiled(rt)).count(),
        "every compiled-in registry is mounted"
    );
    let sandboxed = |resp: &axum::response::Response| {
        resp.headers()
            .get_all("content-security-policy")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .any(|v| v.split(';').any(|d| d.trim() == "sandbox"))
    };
    // One route each registry answers, whatever its status.
    let routes = [
        (RegistryType::Docker, "/v2/_catalog"),
        (RegistryType::Maven, "/maven2/com/example/x/1.0/x.html"),
        (RegistryType::Npm, "/npm/x"),
        (RegistryType::Cargo, "/cargo/index/config.json"),
        (RegistryType::PyPI, "/simple/x/"),
        (RegistryType::Go, "/go/example.com/x/@v/list"),
        (RegistryType::Raw, "/raw/x/x.html"),
        (RegistryType::Gems, "/gems/specs.4.8.gz"),
        (
            RegistryType::Terraform,
            "/terraform/.well-known/terraform.json",
        ),
        (RegistryType::Ansible, "/ansible/"),
        (RegistryType::Nuget, "/nuget/v3/autocomplete"),
        (RegistryType::PubDart, "/pub/api/packages"),
        (RegistryType::Conan, "/conan/v1/ping"),
        (RegistryType::Rpm, "/rpm/x/x.html"),
        (RegistryType::Deb, "/deb/x/x.html"),
        (RegistryType::Cpan, "/cpan/modules/03modlist.data.gz"),
        (RegistryType::HuggingFace, "/hf/api/models/x/y"),
        (RegistryType::Helm, "/helm/x/index.yaml"),
        (
            RegistryType::Apk,
            "/apk/x/v3.22/main/x86_64/APKINDEX.tar.gz",
        ),
        // An invalid owner: answered without reaching GitHub.
        (RegistryType::Github, "/github/_/r/releases/download/v1/a"),
        (RegistryType::Hashicorp, "/hashicorp/_/1.0.0/a.zip"),
    ];
    let covered: std::collections::HashSet<_> = routes.iter().map(|(rt, _)| *rt).collect();
    assert_eq!(
        covered.len(),
        RegistryType::all().len(),
        "a route for every registry"
    );
    for (rt, uri) in routes.into_iter().filter(|(rt, _)| compiled(rt)) {
        let resp = send(&ctx.app, Method::GET, uri, Body::empty()).await;
        assert!(
            sandboxed(&resp),
            "{}: {uri}: {}",
            rt.as_str(),
            resp.status()
        );
    }
    // A stored Maven document, answered inline as XML.
    let pom = b"<?xml version=\"1.0\"?><project/>";
    let uri = "/maven2/com/example/a/1.0/a-1.0.pom";
    let put = send(&ctx.app, Method::PUT, uri, Body::from(&pom[..])).await;
    assert!(put.status().is_success(), "{}", put.status());
    let get = send(&ctx.app, Method::GET, uri, Body::empty()).await;
    assert_eq!(get.status(), axum::http::StatusCode::OK);
    assert_eq!(get.headers()["content-type"], "application/xml");
    assert!(sandboxed(&get));
}

// Registry routes are limited by the upload_* settings and only by
// them; auth routes by auth_* and general_*. Bursts differ (auth 1, upload 2, general 3), one
// request a second, so the first refusal tells which limiter answered.
#[tokio::test]
async fn registry_routes_use_the_upload_limiter_only() {
    let rl = config::RateLimitConfig {
        enabled: true,
        auth_rps: 1,
        auth_burst: 1,
        upload_rps: 1,
        upload_burst: 2,
        general_rps: 1,
        general_burst: 3,
    };
    let auth = Router::new().route("/api/tokens", axum::routing::put(|| async { "ok" }));
    let registry = Router::new().route("/v2/", axum::routing::put(|| async { "ok" }));
    let quotas = rate_limit::limiter_quotas(&rl);
    let (app, enforced, _) = rate_limited_routes(
        auth,
        registry,
        &quotas,
        config::TrustedProxies::default_loopback(),
    );
    assert_eq!(enforced, quotas);
    assert_eq!(
        statuses(&app, "/v2/", 4).await,
        vec![200, 200, 429, 429],
        "registry"
    );
    assert_eq!(
        statuses(&app, "/api/tokens", 2).await,
        vec![200, 429],
        "auth"
    );

    // The general limiter stricter than the upload one must not reach registry routes.
    let rl = config::RateLimitConfig {
        auth_burst: 2,
        upload_burst: 3,
        general_burst: 1,
        ..rl
    };
    let auth = Router::new().route("/api/tokens", axum::routing::put(|| async { "ok" }));
    let registry = Router::new().route("/v2/", axum::routing::put(|| async { "ok" }));
    let quotas = rate_limit::limiter_quotas(&rl);
    let (app, enforced, _) = rate_limited_routes(
        auth,
        registry,
        &quotas,
        config::TrustedProxies::default_loopback(),
    );
    assert_eq!(enforced, quotas);
    assert_eq!(
        statuses(&app, "/v2/", 4).await,
        vec![200, 200, 200, 429],
        "registry"
    );
    assert_eq!(
        statuses(&app, "/api/tokens", 2).await,
        vec![200, 429],
        "auth"
    );
}

// Whatever the rates, the routes are built with the quotas they are given, each from its
// own setting: rates far apart and far above 1000/s, bursts above u16::MAX.
#[test]
fn the_routes_enforce_the_quotas_they_are_given() {
    for (auth, upload, general) in [
        (1_500_000, 5_000_000, 3),
        ((1 << 32) + 200, 7, u64::MAX),
        (999, 1_000_001, 600),
    ] {
        let rl = config::RateLimitConfig {
            enabled: true,
            auth_rps: auth,
            auth_burst: 70_000,
            upload_rps: upload,
            upload_burst: 100_000,
            general_rps: general,
            general_burst: 65_536,
        };
        let quotas = rate_limit::limiter_quotas(&rl);
        let (_, enforced, _) = rate_limited_routes::<()>(
            Router::new(),
            Router::new(),
            &quotas,
            config::TrustedProxies::default_loopback(),
        );
        assert_eq!(enforced, quotas, "{auth} {upload} {general}");
    }
}
