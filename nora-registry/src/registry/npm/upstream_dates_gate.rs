// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::test_helpers::{create_test_context_with_config, send, TestContext};
use axum::http::{Method, StatusCode};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// An upstream listing `agepkg` 1.0.0, released in 2020, and 2.0.0, released an hour ago.
async fn upstream() -> MockServer {
    let server = MockServer::start().await;
    let fresh = (chrono::Utc::now() - chrono::Duration::hours(1))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let link = |v: &str| format!("{}/agepkg/-/agepkg-{v}.tgz", server.uri());
    let doc = serde_json::json!({
        "name": "agepkg",
        "versions": {
            "1.0.0": {"name": "agepkg", "version": "1.0.0", "dist": {"tarball": link("1.0.0")}},
            "2.0.0": {"name": "agepkg", "version": "2.0.0", "dist": {"tarball": link("2.0.0")}},
        },
        "time": {"1.0.0": "2020-01-15T10:30:00.000Z", "2.0.0": fresh},
        "dist-tags": {"latest": "2.0.0"},
    });
    Mock::given(method("GET"))
        .and(path("/agepkg"))
        .respond_with(ResponseTemplate::new(200).set_body_json(doc))
        .mount(&server)
        .await;
    for v in ["1.0.0", "2.0.0"] {
        Mock::given(method("GET"))
            .and(path(format!("/agepkg/-/agepkg-{v}.tgz")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"TGZ".to_vec()))
            .mount(&server)
            .await;
    }
    server
}

/// What NORA holds of the package before its first tarball download.
#[derive(Clone, Copy, Debug)]
enum Before {
    Nothing,
    /// A client read the packument.
    Packument,
    /// A packument an older release cached.
    OlderCopy,
}

fn context(server: &MockServer, trust: bool) -> TestContext {
    let uri = server.uri();
    create_test_context_with_config(move |cfg| {
        cfg.npm.proxy = Some(uri);
        cfg.server.trust_upstream_dates = trust;
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.min_release_age = Some("7d".to_string());
    })
}

#[tokio::test]
async fn whose_clock_judges_a_release_follows_the_trust_in_upstream_dates() {
    let mut wrong = Vec::new();
    // (trust, what NORA holds before the download, version, verdict, why)
    for (trust, before, version, expected, why) in [
        (
            true,
            Before::Nothing,
            "1.0.0",
            StatusCode::OK,
            "upstream says 2020",
        ),
        (
            true,
            Before::Nothing,
            "2.0.0",
            StatusCode::FORBIDDEN,
            "upstream says an hour ago",
        ),
        (
            true,
            Before::Packument,
            "1.0.0",
            StatusCode::OK,
            "upstream says 2020, cached",
        ),
        (
            false,
            Before::Nothing,
            "2.0.0",
            StatusCode::OK,
            "no date of NORA's own yet",
        ),
        (
            false,
            Before::Packument,
            "1.0.0",
            StatusCode::FORBIDDEN,
            "NORA first saw it now",
        ),
        // Maestra (C49): the mtime of a cached copy is when NORA last wrote it, no
        // release date, so without a first-seen entry the release is undated as above.
        (
            false,
            Before::OlderCopy,
            "1.0.0",
            StatusCode::OK,
            "a copy's mtime is no date",
        ),
    ] {
        let server = upstream().await;
        let ctx = context(&server, trust);
        match before {
            Before::Nothing => {}
            Before::Packument => {
                let resp = send(&ctx.app, Method::GET, "/npm/agepkg", "").await;
                assert_eq!(resp.status(), StatusCode::OK);
            }
            // What an older release cached, with the upstream's dates and no first-seen
            // ledger: a release is as old as NORA's copy, not as the upstream says.
            Before::OlderCopy => {
                let doc = serde_json::json!({
                    "name": "agepkg",
                    "versions": {"1.0.0": {"name": "agepkg", "version": "1.0.0", "dist": {}}},
                    "time": {"1.0.0": "2020-01-15T10:30:00.000Z"},
                });
                ctx.state
                    .storage
                    .put(
                        "npm/agepkg/metadata.json",
                        &serde_json::to_vec(&doc).unwrap(),
                    )
                    .await
                    .unwrap();
            }
        }
        let uri = format!("/npm/agepkg/-/agepkg-{version}.tgz");
        let status = send(&ctx.app, Method::GET, &uri, "").await.status();
        if status != expected {
            wrong.push(format!(
                "trust {trust}, {before:?}, {version}: {status}, expected {expected} ({why})"
            ));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}
