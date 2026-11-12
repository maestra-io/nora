// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]
#![allow(clippy::unwrap_used)]

use crate::circuit_breaker::upstream_key;
use crate::config::MavenProxyEntry;
use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
use axum::http::{Method, StatusCode};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

/// the metadata checksum path is a maven cold miss too — a failed upstream is 502.
#[tokio::test]
async fn metadata_checksum_failed_upstream_is_502() {
    let down = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&down)
        .await;
    let url = down.uri();
    let ctx = create_test_context_with_config(move |c| {
        c.maven.proxies = vec![MavenProxyEntry::Simple(url)];
    });
    for path in [
        "/maven2/com/example/lib/maven-metadata.xml.sha1",
        "/maven2/com/example/lib/1.0.0/lib-1.0.0.jar.sha1",
    ] {
        let resp = send(&ctx.app, Method::GET, path, "").await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY, "{path}");
    }
}

/// an open breaker on a maven upstream is still 503, not 502.
#[tokio::test]
async fn open_breaker_is_still_503() {
    let ctx = create_test_context_with_config(|c| {
        c.circuit_breaker.enabled = true;
        c.circuit_breaker.failure_threshold = 1;
        c.circuit_breaker.reset_timeout = 3600;
        c.maven.proxies = vec![MavenProxyEntry::Simple("http://127.0.0.1:9".into())];
    });
    let path = "/maven2/com/example/lib/1.0.0/lib-1.0.0.jar";
    send(&ctx.app, Method::GET, path, "").await; // trips the breaker
    let resp = send(&ctx.app, Method::GET, path, "").await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

/// #1198: an upstream whose breaker is open is skipped, not asked, and the next one serves.
#[tokio::test]
async fn an_open_upstream_is_skipped_for_the_next() {
    let (skipped, serving) = (MockServer::start().await, MockServer::start().await);
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("from-skipped"))
        .expect(0)
        .mount(&skipped)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("from-next"))
        .mount(&serving)
        .await;
    let urls = vec![skipped.uri(), serving.uri()];
    let ctx = create_test_context_with_config(move |c| {
        c.circuit_breaker.enabled = true;
        c.circuit_breaker.reset_timeout = 3600;
        c.maven.proxies = urls.into_iter().map(MavenProxyEntry::Simple).collect();
    });
    ctx.state
        .circuit_breaker
        .open_for_test(&upstream_key("maven", &skipped.uri()));
    let resp = send(
        &ctx.app,
        Method::GET,
        "/maven2/com/example/lib/1.0.0/lib-1.0.0.jar",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_bytes(resp).await.as_ref(), b"from-next");
}

/// #1198: each Maven upstream reports to a breaker of its own. A dead first upstream opens
/// only its own; the next one keeps serving, on the request that opened it and after.
#[tokio::test]
async fn a_dead_upstream_opens_only_its_own_breaker() {
    let serving = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("from-next"))
        .mount(&serving)
        .await;
    let dead = "http://127.0.0.1:9".to_string();
    let urls = vec![dead.clone(), serving.uri()];
    let ctx = create_test_context_with_config(move |c| {
        c.circuit_breaker.enabled = true;
        c.circuit_breaker.failure_threshold = 1;
        c.circuit_breaker.reset_timeout = 3600;
        c.maven.proxies = urls.into_iter().map(MavenProxyEntry::Simple).collect();
    });
    for version in ["1.0.0", "1.0.1", "1.0.2"] {
        let path = format!("/maven2/com/example/lib/{version}/lib-{version}.jar");
        let resp = send(&ctx.app, Method::GET, &path, "").await;
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
    }
    let mut keys = vec![
        upstream_key("maven", &dead),
        upstream_key("maven", &serving.uri()),
    ];
    keys.sort();
    assert_eq!(ctx.state.circuit_breaker.keys(), keys);
    let cb = &ctx.state.circuit_breaker;
    assert!(cb.check(&upstream_key("maven", &dead)).is_err());
    assert!(cb.check(&upstream_key("maven", &serving.uri())).is_ok());
}

/// #1198: a copy whose revalidation found every upstream skipped is served stale, as when
/// every upstream failed.
#[tokio::test]
async fn an_open_upstream_leaves_the_stale_copy_served() {
    let skipped = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("from-skipped"))
        .expect(0)
        .mount(&skipped)
        .await;
    let url = skipped.uri();
    let ctx = create_test_context_with_config(move |c| {
        c.circuit_breaker.enabled = true;
        c.circuit_breaker.reset_timeout = 3600;
        c.maven.metadata_ttl = 0;
        c.maven.proxies = vec![MavenProxyEntry::Simple(url)];
    });
    let path = "/maven2/com/example/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar";
    ctx.state
        .storage
        .put(
            &super::storage_key("com/example/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar"),
            b"cached-copy",
        )
        .await
        .unwrap();
    ctx.state
        .circuit_breaker
        .open_for_test(&upstream_key("maven", &skipped.uri()));
    let resp = send(&ctx.app, Method::GET, path, "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("x-nora-stale").map(|v| v.as_bytes()),
        Some(b"true".as_slice())
    );
    assert_eq!(body_bytes(resp).await.as_ref(), b"cached-copy");
}
