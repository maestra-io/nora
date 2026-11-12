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
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"SDIST".to_vec()))
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
async fn a_rule_holds_for_every_spelling_of_its_version() {
    let upstream = upstream().await;
    let dir = tempfile::tempdir().unwrap();
    let blocklist = write(
        &dir,
        "blocklist.json",
        r#"{"version": 1, "rules": [
                {"registry": "pypi", "name": "foo", "version": "1.0.post1", "reason": "malware"},
                {"registry": "pypi", "name": "foo", "version": "2.0rc1", "reason": "malware"}
            ]}"#,
    );
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.pypi.proxy = Some(uri);
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.blocklist_path = Some(blocklist);
    });
    for file in [
        "foo-1.0.post1.tar.gz",
        "foo-1.0-1.tar.gz",
        "foo-1.0.POST1.zip",
        "foo-1.0.0.post1.tar.gz",
        "foo-1.0.0.post01.tar.gz",
        "foo-2.0.0.RC1-py3-none-any.whl",
        "foo-2.0-rc-1.tar.gz",
        "foo-2.0c1.tar.gz",
        "foo-v2.0rc1.tar.gz",
    ] {
        let resp = send(&ctx.app, Method::GET, &format!("/simple/foo/{file}"), "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{file}");
    }
    for file in ["foo-1.0.tar.gz", "foo-2.0.tar.gz", "foo-1.0.post2.tar.gz"] {
        let resp = send(&ctx.app, Method::GET, &format!("/simple/foo/{file}"), "").await;
        assert_ne!(resp.status(), StatusCode::FORBIDDEN, "{file}");
    }
}

#[tokio::test]
async fn an_allowlist_entry_admits_every_spelling_of_its_version() {
    let upstream = upstream().await;
    let dir = tempfile::tempdir().unwrap();
    let allowlist = write(
        &dir,
        "allowlist.json",
        r#"{"version": 1, "entries": [{"registry": "pypi", "name": "foo", "version": "1.0"}]}"#,
    );
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.pypi.proxy = Some(uri);
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.allowlist_path = Some(allowlist);
    });
    for file in ["foo-1.0.tar.gz", "foo-1.0.0.tar.gz", "foo-v1.0.zip"] {
        let resp = send(&ctx.app, Method::GET, &format!("/simple/foo/{file}"), "").await;
        assert_ne!(resp.status(), StatusCode::FORBIDDEN, "{file}");
    }
    for file in ["foo-1.1.tar.gz", "foo-1.0.post1.tar.gz"] {
        let resp = send(&ctx.app, Method::GET, &format!("/simple/foo/{file}"), "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{file}");
    }
}
