// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::test_helpers::{create_test_context_with_config, send};
use axum::http::{Method, StatusCode};
use wiremock::matchers::{any, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// An upstream whose packument lists every version the tests ask for, each tarball `TGZ`:
/// a permitted version is then served (200), so a positive control cannot pass on a 404.
async fn upstream() -> MockServer {
    let upstream = MockServer::start().await;
    let uri = upstream.uri();
    let versions: serde_json::Map<String, serde_json::Value> = ["1.3.0", "1.3.1", "1.4.0", "1.5.0"]
        .iter()
        .map(|v| {
            let tarball = format!("{uri}/left-pad/-/left-pad-{v}.tgz");
            (
                v.to_string(),
                serde_json::json!({ "dist": { "tarball": tarball } }),
            )
        })
        .collect();
    Mock::given(path("/left-pad"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "name": "left-pad", "versions": versions })),
        )
        .with_priority(1)
        .mount(&upstream)
        .await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"TGZ".to_vec()))
        .mount(&upstream)
        .await;
    upstream
}

fn write(dir: &tempfile::TempDir, file: &str, body: &str) -> String {
    let path = dir.path().join(file);
    std::fs::write(&path, body).unwrap();
    path.to_string_lossy().into_owned()
}

#[tokio::test]
async fn a_rule_holds_however_it_spells_its_version() {
    let upstream = upstream().await;
    let dir = tempfile::tempdir().unwrap();
    let blocklist = write(
        &dir,
        "blocklist.json",
        r#"{"version": 1, "rules": [
                {"registry": "npm", "name": "left-pad", "version": "v1.3.0", "reason": "r"},
                {"registry": "npm", "name": "left-pad", "version": "=1.4.0", "reason": "r"},
                {"registry": "npm", "name": "left-pad", "version": "1.5.0+build.1", "reason": "r"}
            ]}"#,
    );
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.npm.proxy = Some(uri);
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.blocklist_path = Some(blocklist);
    });
    for version in ["1.3.0", "1.4.0", "1.5.0"] {
        let path = format!("/npm/left-pad/-/left-pad-{version}.tgz");
        let resp = send(&ctx.app, Method::GET, &path, "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{version}");
    }
    let resp = send(
        &ctx.app,
        Method::GET,
        "/npm/left-pad/-/left-pad-1.3.1.tgz",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn an_allowlist_entry_admits_its_version_however_spelled() {
    let upstream = upstream().await;
    let dir = tempfile::tempdir().unwrap();
    let allowlist = write(
        &dir,
        "allowlist.json",
        r#"{"version": 1, "entries": [{"registry": "npm", "name": "left-pad", "version": "v1.3.0"}]}"#,
    );
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.npm.proxy = Some(uri);
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.allowlist_path = Some(allowlist);
    });
    let resp = send(
        &ctx.app,
        Method::GET,
        "/npm/left-pad/-/left-pad-1.3.0.tgz",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = send(
        &ctx.app,
        Method::GET,
        "/npm/left-pad/-/left-pad-1.3.1.tgz",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// #1098: `[curation.npm] min_release_age` without a global value holds a tarball
/// younger than it, and serves one older than it.
#[tokio::test]
async fn a_per_registry_minimum_age_alone_holds_a_young_tarball() {
    let ctx = create_test_context_with_config(|cfg| {
        cfg.npm.proxy = None;
        cfg.server.trust_upstream_dates = true;
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.npm.min_release_age = Some("3d".to_string());
    });
    let iso = |ago: i64| {
        (chrono::Utc::now() - chrono::Duration::seconds(ago))
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string()
    };
    let packument = serde_json::json!({
        "name": "left-pad",
        "versions": { "1.3.0": {}, "1.2.0": {} },
        "time": { "1.3.0": iso(3600), "1.2.0": iso(4 * 86_400) }
    });
    ctx.state
        .storage
        .put(
            "npm/left-pad/upstream/packument.json",
            packument.to_string().as_bytes(),
        )
        .await
        .unwrap();
    for ver in ["1.3.0", "1.2.0"] {
        ctx.state
            .storage
            .put(&format!("npm/left-pad/tarballs/left-pad-{ver}.tgz"), b"TGZ")
            .await
            .unwrap();
    }
    let resp = send(
        &ctx.app,
        Method::GET,
        "/npm/left-pad/-/left-pad-1.3.0.tgz",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(
        String::from_utf8_lossy(&body).contains("min-release-age"),
        "{}",
        String::from_utf8_lossy(&body)
    );
    let resp = send(
        &ctx.app,
        Method::GET,
        "/npm/left-pad/-/left-pad-1.2.0.tgz",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}
