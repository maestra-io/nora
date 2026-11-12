// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::test_helpers::{create_test_context_with_config, send};
use axum::http::{Method, StatusCode};
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn upstream() -> MockServer {
    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"NUPKG".to_vec()))
        .mount(&upstream)
        .await;
    upstream
}

fn write(dir: &tempfile::TempDir, file: &str, body: &str) -> String {
    let path = dir.path().join(file);
    std::fs::write(&path, body).unwrap();
    path.to_string_lossy().into_owned()
}

fn nupkg(id: &str, version: &str) -> String {
    format!("/nuget/v3/flatcontainer/{id}/{version}/{id}.{version}.nupkg")
}

#[tokio::test]
async fn a_rule_holds_however_it_spells_its_version() {
    let upstream = upstream().await;
    let dir = tempfile::tempdir().unwrap();
    let blocklist = write(
        &dir,
        "blocklist.json",
        r#"{"version": 1, "rules": [
                {"registry": "nuget", "name": "Evil.Lib", "version": "13.0", "reason": "malware"},
                {"registry": "nuget", "name": "Evil.Lib", "version": "2.0.0-Beta1+build.7", "reason": "malware"},
                {"registry": "nuget", "name": "Evil.Lib", "version": "3.0.0.0", "reason": "malware"}
            ]}"#,
    );
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some(uri);
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.blocklist_path = Some(blocklist);
    });
    for version in ["13.0.0", "2.0.0-beta1", "3.0.0"] {
        let resp = send(&ctx.app, Method::GET, &nupkg("evil.lib", version), "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{version}");
    }
    for version in ["13.0.1", "2.0.0", "3.0.0.1"] {
        let resp = send(&ctx.app, Method::GET, &nupkg("evil.lib", version), "").await;
        assert_eq!(resp.status(), StatusCode::OK, "{version}");
    }
}

#[tokio::test]
async fn an_allowlist_entry_admits_its_version_however_spelled() {
    let upstream = upstream().await;
    let dir = tempfile::tempdir().unwrap();
    let allowlist = write(
        &dir,
        "allowlist.json",
        r#"{"version": 1, "entries": [
                {"registry": "nuget", "name": "Newtonsoft.Json", "version": "13.0.1.0"},
                {"registry": "nuget", "name": "Newtonsoft.Json", "version": "14.0.0-Preview.2"}
            ]}"#,
    );
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some(uri);
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.allowlist_path = Some(allowlist);
    });
    for version in ["13.0.1", "14.0.0-preview.2"] {
        let resp = send(
            &ctx.app,
            Method::GET,
            &nupkg("newtonsoft.json", version),
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "{version}");
    }
    let resp = send(
        &ctx.app,
        Method::GET,
        &nupkg("newtonsoft.json", "13.0.2"),
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// R5 pairs: a registration page is curated as its index is. A package the curation refuses
/// is refused on the index and on every page, in every hive, and none is asked upstream; the
/// bypass token admits both alike.
#[tokio::test]
async fn a_registration_page_is_curated_as_its_index() {
    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "count": 0,
            "items": []
        })))
        .mount(&upstream)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let blocklist = write(
        &dir,
        "blocklist.json",
        r#"{"version": 1, "rules": [
                {"registry": "nuget", "name": "Evil.Lib", "version": "*", "reason": "malware"}
            ]}"#,
    );
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some(uri);
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.blocklist_path = Some(blocklist);
        cfg.curation.bypass_token = Some(crate::secrets::ProtectedString::from("let-me-in"));
    });
    let mut paths = Vec::new();
    for hive in [
        "registration",
        "registration-semver1",
        "registration-gz-semver1",
    ] {
        paths.push(format!("/nuget/v3/{hive}/evil.lib/index.json"));
        paths.push(format!("/nuget/v3/{hive}/evil.lib/page/1.0.0/2.0.0.json"));
    }
    for path in &paths {
        let resp = send(&ctx.app, Method::GET, path, "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{path}");
    }
    let asked = upstream.received_requests().await.unwrap();
    assert!(asked.is_empty(), "asked upstream: {asked:?}");

    for path in [
        "/nuget/v3/registration/evil.lib/index.json",
        "/nuget/v3/registration/evil.lib/page/1.0.0/2.0.0.json",
    ] {
        let resp = crate::test_helpers::send_with_headers(
            &ctx.app,
            Method::GET,
            path,
            vec![("x-nora-bypass-token", "let-me-in")],
            "",
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "{path} with the bypass token"
        );
    }
}
