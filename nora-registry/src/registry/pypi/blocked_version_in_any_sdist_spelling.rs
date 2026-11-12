// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::test_helpers::{create_test_context_with_config, send};
use axum::http::{Method, StatusCode};
use wiremock::matchers::{any, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn a_blocked_version_is_refused_whatever_the_sdist_spelling() {
    let upstream = MockServer::start().await;
    let links: String = [
        "python_dateutil-2.8.2.tar.gz",
        "python-dateutil-2.8.2.tar.gz",
        "Python.Dateutil-2.8.2.zip",
        "python_dateutil-2.8.2-py2.py3-none-any.whl",
        "python-dateutil-2.8.1.tar.gz",
    ]
    .iter()
    .map(|f| format!(r#"<a href="{}/files/{f}">{f}</a>"#, upstream.uri()))
    .collect();
    Mock::given(path("/python-dateutil/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(format!("<html><body>{links}</body></html>")),
        )
        .mount(&upstream)
        .await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"SDIST".to_vec()))
        .mount(&upstream)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let blocklist = dir.path().join("blocklist.json");
    std::fs::write(
        &blocklist,
        r#"{"version": 1, "rules": [{"registry": "pypi", "name": "python-dateutil", "version": "2.8.2", "reason": "malware"}]}"#,
    )
    .unwrap();
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.pypi.proxy = Some(uri);
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.blocklist_path = Some(blocklist.to_string_lossy().into_owned());
    });
    for file in [
        "python_dateutil-2.8.2.tar.gz",
        "python-dateutil-2.8.2.tar.gz",
        "Python.Dateutil-2.8.2.zip",
        "python_dateutil-2.8.2-py2.py3-none-any.whl",
    ] {
        let resp = send(
            &ctx.app,
            Method::GET,
            &format!("/simple/python-dateutil/{file}"),
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{file}");
    }
    // Another version downloads.
    let resp = send(
        &ctx.app,
        Method::GET,
        "/simple/python-dateutil/python-dateutil-2.8.1.tar.gz",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}
