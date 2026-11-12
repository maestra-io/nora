// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::rewrite_tarball_urls;
use crate::test_helpers::{
    body_bytes, create_test_context_with_config, send, send_with_headers, LogCapture,
};
use axum::http::{Method, StatusCode};
use wiremock::matchers::{header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const NORA: &str = "http://nora:5000";

/// Links outside the upstream `https://registry.example.com/repo` or NORA `http://nora:5000`.
const OUTSIDE: &[&str] = &[
    "https://evil.example/pkg/-/pkg-2.0.0.tgz",
    "https://registry.example.com.evil.example/repo/pkg/-/pkg-2.0.0.tgz",
    "https://registry.example.com:8443/repo/pkg/-/pkg-2.0.0.tgz",
    "https://registry.example.com@evil.example/repo/pkg/-/pkg-2.0.0.tgz",
    // The upstream's origin, but not this package's tarball, or not a link NORA can serve.
    "https://registry.example.com/repo-other/other/-/other-2.0.0.tgz",
    "https://registry.example.com/pkg/-/pkg-2.0.0.tgz?token=x",
    "HTTPS://evil.example/pkg/-/pkg-2.0.0.tgz",
    " https://evil.example/pkg/-/pkg-2.0.0.tgz",
    "//evil.example/pkg/-/pkg-2.0.0.tgz",
    "/\\evil.example/pkg/-/pkg-2.0.0.tgz",
    "\\\\evil.example/pkg/-/pkg-2.0.0.tgz",
    "ftp://evil.example/pkg-2.0.0.tgz",
    "http://nora:5000.evil.example/npm/pkg/-/pkg-2.0.0.tgz",
    "http://nora:5000@evil.example/npm/pkg/-/pkg-2.0.0.tgz",
    "http://nora:5001/npm/pkg/-/pkg-2.0.0.tgz",
    // Another host on NORA's own scheme and port.
    "http://evil.example:5000/npm/pkg/-/pkg-2.0.0.tgz",
    "//evil.example:5000/npm/pkg/-/pkg-2.0.0.tgz",
];

fn packument(versions: &[(&str, &str)], tags: serde_json::Value) -> Vec<u8> {
    let mut docs = serde_json::Map::new();
    let mut time = serde_json::Map::new();
    time.insert("created".into(), "2020-01-01T00:00:00.000Z".into());
    for (version, link) in versions {
        docs.insert(
            version.to_string(),
            serde_json::json!({ "name": "pkg", "version": version, "dist": { "tarball": link } }),
        );
        time.insert(version.to_string(), "2020-01-02T00:00:00.000Z".into());
    }
    serde_json::to_vec(&serde_json::json!({
        "name": "pkg", "dist-tags": tags, "versions": docs, "time": time,
    }))
    .unwrap()
}

fn served(versions_kept: &[(&str, &str)], last: (&str, &str)) -> Vec<u8> {
    let mut all = versions_kept.to_vec();
    all.push(last);
    packument(
        &all,
        serde_json::json!({ "latest": last.0, "next": last.0, "beta": "1.1.0-beta.1" }),
    )
}

fn keys(doc: &serde_json::Value, field: &str) -> Vec<String> {
    let mut keys: Vec<String> = doc[field].as_object().unwrap().keys().cloned().collect();
    keys.sort();
    keys
}

const KEPT: &[(&str, &str)] = &[
    (
        "1.0.0",
        "https://registry.example.com/repo/pkg/-/pkg-1.0.0.tgz",
    ),
    (
        "1.0.1",
        "http://registry.example.com/repo/pkg/-/pkg-1.0.1.tgz",
    ),
    ("1.0.2", "/npm/pkg/-/pkg-1.0.2.tgz"),
    ("1.0.3", "http://nora:5000/npm/pkg/-/pkg-1.0.3.tgz"),
    (
        "1.1.0-beta.1",
        "https://registry.example.com/repo/pkg/-/pkg-1.1.0-beta.1.tgz",
    ),
];

#[test]
fn a_version_whose_tarball_is_outside_the_upstream_is_left_out() {
    let mut wrong = Vec::new();
    for link in OUTSIDE {
        let doc = served(KEPT, ("2.0.0", link));
        let out = rewrite_tarball_urls(&doc, NORA, "https://registry.example.com/repo/").unwrap();
        let text = String::from_utf8_lossy(&out).to_string();
        let doc: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let versions = keys(&doc, "versions");
        let mut time = keys(&doc, "time");
        time.retain(|k| k != "created");
        let expected = ["1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.1.0-beta.1"];
        if versions != expected || time != expected {
            wrong.push(format!("{link}: versions {versions:?} time {time:?}"));
        }
        // `latest` falls back to the highest release below the one left out; a tag naming
        // only that version goes; the others stay.
        let tags = &doc["dist-tags"];
        if *tags != serde_json::json!({ "latest": "1.0.3", "beta": "1.1.0-beta.1" }) {
            wrong.push(format!("{link}: tags {tags}"));
        }
        if text.contains("evil") || text.contains(":8443") || text.contains("2.0.0") {
            wrong.push(format!("{link}: {text}"));
        }
        // The kept links: the upstream's under either scheme on NORA, the others as they were.
        let links: Vec<&str> = expected
            .iter()
            .map(|v| doc["versions"][v]["dist"]["tarball"].as_str().unwrap())
            .collect();
        if links
            != [
                "http://nora:5000/npm/pkg/-/pkg-1.0.0.tgz",
                "http://nora:5000/npm/pkg/-/pkg-1.0.1.tgz",
                "/npm/pkg/-/pkg-1.0.2.tgz",
                "http://nora:5000/npm/pkg/-/pkg-1.0.3.tgz",
                "http://nora:5000/npm/pkg/-/pkg-1.1.0-beta.1.tgz",
            ]
        {
            wrong.push(format!("{link}: kept {links:?}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// `latest` on a version left out, with no release below it left: the tag goes.
#[test]
fn latest_without_a_release_below_it_goes() {
    let doc = packument(
        &[
            ("2.0.0", "https://evil.example/pkg-2.0.0.tgz"),
            (
                "3.0.0",
                "https://registry.example.com/repo/pkg/-/pkg-3.0.0.tgz",
            ),
            (
                "1.0.0-rc.1",
                "https://registry.example.com/repo/pkg/-/pkg-1.0.0-rc.1.tgz",
            ),
        ],
        serde_json::json!({ "latest": "2.0.0", "next": "3.0.0" }),
    );
    let out = rewrite_tarball_urls(&doc, NORA, "https://registry.example.com/repo").unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(doc["dist-tags"], serde_json::json!({ "next": "3.0.0" }));
    assert_eq!(keys(&doc, "versions"), ["1.0.0-rc.1", "3.0.0"]);
}

fn upstream_packument(up: &MockServer, last: &str) -> Vec<u8> {
    let base = up.uri();
    let link = |v: &str| format!("{base}/pkg/-/pkg-{v}.tgz");
    packument(
        &[
            ("1.0.0", &link("1.0.0")),
            ("1.1.0", &link("1.1.0")),
            ("2.0.0", last),
        ],
        serde_json::json!({ "latest": "2.0.0" }),
    )
}

async fn upstream() -> MockServer {
    let up = MockServer::start().await;
    let doc = upstream_packument(&up, "https://evil.example/pkg/-/pkg-2.0.0.tgz");
    Mock::given(method("GET"))
        .and(path("/pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(doc.clone()))
        .mount(&up)
        .await;
    let manifest = |v: &str, link: String| {
        serde_json::to_vec(
            &serde_json::json!({ "name": "pkg", "version": v, "dist": { "tarball": link } }),
        )
        .unwrap()
    };
    for (spec, version, link) in [
        (
            "2.0.0",
            "2.0.0",
            "https://evil.example/pkg/-/pkg-2.0.0.tgz".to_string(),
        ),
        (
            "latest",
            "2.0.0",
            "https://evil.example/pkg/-/pkg-2.0.0.tgz".to_string(),
        ),
        (
            "1.1.0",
            "1.1.0",
            format!("{}/pkg/-/pkg-1.1.0.tgz", up.uri()),
        ),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/pkg/{spec}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(manifest(version, link)))
            .mount(&up)
            .await;
    }
    up
}

#[tokio::test]
async fn no_served_document_sends_the_client_past_nora() {
    let up = upstream().await;
    let uri = up.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.npm.proxy = Some(uri);
        cfg.server.public_url = Some("http://nora.example".to_string());
    });
    let mut wrong = Vec::new();
    for accept in ["application/json", "application/vnd.npm.install-v1+json"] {
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/npm/pkg",
            vec![("accept", accept)],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
        if keys(&doc, "versions") != ["1.0.0", "1.1.0"]
            || doc["dist-tags"]["latest"] != "1.1.0"
            || String::from_utf8_lossy(&body).contains("evil")
        {
            wrong.push(format!("{accept}: {}", String::from_utf8_lossy(&body)));
        }
    }
    for spec in ["2.0.0", "latest"] {
        let resp = send(&ctx.app, Method::GET, &format!("/npm/pkg/{spec}"), "").await;
        let status = resp.status();
        let body = body_bytes(resp).await;
        if status != StatusCode::NOT_FOUND || String::from_utf8_lossy(&body).contains("evil") {
            wrong.push(format!(
                "/npm/pkg/{spec}: {status} {}",
                String::from_utf8_lossy(&body)
            ));
        }
    }
    let resp = send(&ctx.app, Method::GET, "/npm/pkg/1.1.0", "").await;
    let body = body_bytes(resp).await;
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    if doc["dist"]["tarball"] != "http://nora.example/npm/pkg/-/pkg-1.1.0.tgz" {
        wrong.push(format!(
            "/npm/pkg/1.1.0: {}",
            String::from_utf8_lossy(&body)
        ));
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// A packument cached with such a link (by a release that kept it) is not served with it.
/// It is fetched again in full whatever its age — a 304 would keep it — and, with the
/// upstream down, served stale without the version.
#[tokio::test]
async fn a_cached_link_past_nora_is_not_served() {
    use crate::registry::{write_validators, Validators};
    for (case, ttl, up_status) in [
        ("fresh", 3600, 200),
        ("expired", 0, 200),
        ("upstream down", 0, 500),
    ] {
        let up = MockServer::start().await;
        let fresh = upstream_packument(&up, &format!("{}/pkg/-/pkg-2.0.0.tgz", up.uri()));
        Mock::given(method("GET"))
            .and(header_exists("if-none-match"))
            .respond_with(ResponseTemplate::new(304))
            .mount(&up)
            .await;
        Mock::given(method("GET"))
            .and(path("/pkg"))
            .respond_with(ResponseTemplate::new(up_status).set_body_bytes(fresh))
            .mount(&up)
            .await;
        let uri = up.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.npm.proxy = Some(uri);
            cfg.npm.metadata_ttl = ttl;
            cfg.npm.serve_stale = true;
            cfg.server.public_url = Some("http://nora.example".to_string());
        });
        let key = "npm/pkg/upstream/packument.json";
        let cached = packument(
            &[
                ("1.0.0", "http://nora.example/npm/pkg/-/pkg-1.0.0.tgz"),
                ("2.0.0", "https://evil.example/pkg/-/pkg-2.0.0.tgz"),
            ],
            serde_json::json!({ "latest": "2.0.0" }),
        );
        ctx.state.storage.put(key, &cached).await.unwrap();
        let validators = Validators {
            etag: Some("\"v1\"".to_string()),
            last_modified: None,
        };
        write_validators(&ctx.state.storage, key, &validators).await;
        let resp = send(&ctx.app, Method::GET, "/npm/pkg", "").await;
        assert_eq!(resp.status(), StatusCode::OK, "{case}");
        let body = body_bytes(resp).await;
        let text = String::from_utf8_lossy(&body);
        assert!(!text.contains("evil"), "{case}: {text}");
        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let expected: &[&str] = if up_status == 200 {
            &["1.0.0", "1.1.0", "2.0.0"]
        } else {
            &["1.0.0"]
        };
        assert_eq!(keys(&doc, "versions"), expected, "{case}");
        if up_status == 200 {
            let conditional = up
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.headers.contains_key("if-none-match"))
                .count();
            assert_eq!(conditional, 0, "{case}: the copy was revalidated");
        }
    }
}

/// Each version left out is logged once, by package and version and the host only — not
/// the link, which may carry a token.
#[tokio::test]
async fn a_version_left_out_is_warned_about_once() {
    let up = MockServer::start().await;
    let doc = packument(
        &[
            ("1.0.0", &format!("{}/warned/-/warned-1.0.0.tgz", up.uri())),
            (
                "2.0.0",
                "https://evil.example/secret-token/warned-2.0.0.tgz",
            ),
        ],
        serde_json::json!({ "latest": "2.0.0" }),
    );
    let doc = String::from_utf8(doc)
        .unwrap()
        .replace("\"pkg\"", "\"warned\"");
    Mock::given(method("GET"))
        .and(path("/warned"))
        .respond_with(ResponseTemplate::new(200).set_body_string(doc))
        .mount(&up)
        .await;
    let uri = up.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.npm.proxy = Some(uri);
        cfg.npm.metadata_ttl = 0;
    });
    let (log, _guard) = LogCapture::start();
    for _ in 0..3 {
        let resp = send(&ctx.app, Method::GET, "/npm/warned", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
    let text = log.text();
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("WARN") && l.contains("warned") && l.contains("2.0.0"))
        .collect();
    assert_eq!(lines.len(), 1, "{text}");
    assert!(lines[0].contains("evil.example"), "{text}");
    assert!(!text.contains("secret-token"), "{text}");
}
