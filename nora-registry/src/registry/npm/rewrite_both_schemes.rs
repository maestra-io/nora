// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::{replace_upstream_bytes, rewrite_tarball_urls};
use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
use axum::http::{Method, StatusCode};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn packument(links: &[(&str, &str)]) -> Vec<u8> {
    let versions: serde_json::Map<String, serde_json::Value> = links
        .iter()
        .map(|(version, link)| {
            (
                version.to_string(),
                serde_json::json!({ "version": version, "dist": { "tarball": link } }),
            )
        })
        .collect();
    serde_json::to_vec(&serde_json::json!({ "name": "pkg", "versions": versions })).unwrap()
}

fn tarballs(doc: &[u8]) -> Vec<String> {
    let doc: serde_json::Value = serde_json::from_slice(doc).unwrap();
    doc["versions"]
        .as_object()
        .unwrap()
        .values()
        .map(|v| v["dist"]["tarball"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn a_link_under_either_scheme_of_the_upstream_host_is_rewritten() {
    for (upstream, own, twin) in [
        (
            "https://registry.example.com",
            "https://registry.example.com",
            "http://registry.example.com",
        ),
        (
            "http://registry.example.com",
            "http://registry.example.com",
            "https://registry.example.com",
        ),
        (
            "https://registry.example.com/api/npm/repo/",
            "https://registry.example.com/api/npm/repo",
            "http://registry.example.com/api/npm/repo",
        ),
    ] {
        let doc = packument(&[
            ("1.0.0", &format!("{own}/pkg/-/pkg-1.0.0.tgz")),
            ("1.0.1", &format!("{twin}/pkg/-/pkg-1.0.1.tgz")),
            ("1.0.2", "http://other.example.com/pkg/-/pkg-1.0.2.tgz"),
        ]);
        let rewritten = rewrite_tarball_urls(&doc, "http://nora:5000", upstream).unwrap();
        assert_eq!(
            tarballs(&rewritten),
            // Another host is not the upstream's to rewrite: its version is left out.
            vec![
                "http://nora:5000/npm/pkg/-/pkg-1.0.0.tgz",
                "http://nora:5000/npm/pkg/-/pkg-1.0.1.tgz",
            ],
            "{upstream}"
        );
        // The byte-level rewrite, for a document that does not parse, does the same.
        let raw = format!("not json {twin}/pkg/-/pkg-1.0.1.tgz {own}/pkg/-/pkg-1.0.0.tgz");
        let rewritten = replace_upstream_bytes(
            raw.as_bytes(),
            upstream.trim_end_matches('/'),
            "http://nora:5000/npm",
        );
        assert_eq!(
            String::from_utf8(rewritten).unwrap(),
            "not json http://nora:5000/npm/pkg/-/pkg-1.0.1.tgz http://nora:5000/npm/pkg/-/pkg-1.0.0.tgz",
            "{upstream}"
        );
    }
}

/// A link is the upstream's only where the upstream URL ends: at a `/`, `?`, `#`, the end of
/// the JSON string, a `\` (a JSON escape such as `\/`), or the end of the text. A longer host,
/// a port, or credentials before another host name somewhere else, under either scheme: the
/// byte-level rewrite leaves them as they are, and the targeted one leaves out the version
/// whose tarball such a link is. A longer last path segment is still the upstream's origin:
/// the byte-level rewrite leaves it too, and the targeted one serves it on NORA when it is
/// under the upstream's own scheme.
#[test]
fn a_host_or_path_that_only_starts_like_the_upstream_is_not_rewritten() {
    let nora = "http://nora:5000/npm";
    for (upstream, links) in [
        (
            "https://registry.example.com",
            [
                "https://registry.example.com.evil.org/pkg/-/pkg-1.0.0.tgz",
                "http://registry.example.com.evil.org/pkg/-/pkg-1.0.0.tgz",
                "https://registry.example.com:8443/pkg/-/pkg-1.0.0.tgz",
                "https://registry.example.com@evil.org/pkg/-/pkg-1.0.0.tgz",
                "http://registry.example.com-mirror.org/pkg/-/pkg-1.0.0.tgz",
                "https://registry.example.company/pkg/-/pkg-1.0.0.tgz",
            ],
        ),
        (
            "https://registry.example.com/api/npm/repo/",
            [
                "https://registry.example.com/api/npm/repo-other/pkg/-/pkg-1.0.0.tgz",
                "http://registry.example.com/api/npm/repo2/pkg/-/pkg-1.0.0.tgz",
                "https://registry.example.com/api/npm/repo.evil/pkg/-/pkg-1.0.0.tgz",
                "https://registry.example.com/api/npm/repo:x/pkg/-/pkg-1.0.0.tgz",
                "https://registry.example.com/api/npm/repo%2Fx/pkg/-/pkg-1.0.0.tgz",
                "https://registry.example.com/api/npm/repository/pkg/-/pkg-1.0.0.tgz",
            ],
        ),
    ] {
        let trimmed = upstream.trim_end_matches('/');
        let same_origin = upstream.contains("/api/");
        for link in links {
            let doc = packument(&[("1.0.0", link)]);
            let rewritten = rewrite_tarball_urls(&doc, "http://nora:5000", upstream).unwrap();
            let expected: &[&str] = if same_origin && link.starts_with("https://") {
                &["http://nora:5000/npm/pkg/-/pkg-1.0.0.tgz"]
            } else {
                &[]
            };
            assert_eq!(tarballs(&rewritten), expected, "{upstream}: {link}");
            let raw = format!("not json {link} {link}");
            let rewritten = replace_upstream_bytes(raw.as_bytes(), trimmed, nora);
            assert_eq!(String::from_utf8(rewritten).unwrap(), raw, "{upstream}");
        }
        // The upstream's own links, wherever its URL ends, under either scheme.
        let twin = trimmed.replacen("https://", "http://", 1);
        for own in [trimmed, twin.as_str()] {
            for (text, expected) in [
                (
                    format!("{own}/pkg/-/pkg-1.0.0.tgz"),
                    format!("{nora}/pkg/-/pkg-1.0.0.tgz"),
                ),
                (format!("{own}?q=pkg"), format!("{nora}?q=pkg")),
                (format!("{own}#pkg"), format!("{nora}#pkg")),
                (format!("\"{own}\""), format!("\"{nora}\"")),
                (format!("\\\"{own}\\\""), format!("\\\"{nora}\\\"")),
                (own.to_string(), nora.to_string()),
            ] {
                let rewritten = replace_upstream_bytes(text.as_bytes(), trimmed, nora);
                assert_eq!(
                    String::from_utf8(rewritten).unwrap(),
                    expected,
                    "{upstream}"
                );
            }
        }
    }
}

#[tokio::test]
async fn a_served_packument_names_no_tarball_of_the_upstream_host_under_either_scheme() {
    let upstream = MockServer::start().await;
    let host = upstream.uri().replacen("http://", "", 1);
    Mock::given(method("GET"))
        .and(path("/pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(packument(&[
            ("1.0.0", &format!("http://{host}/pkg/-/pkg-1.0.0.tgz")),
            ("1.0.1", &format!("https://{host}/pkg/-/pkg-1.0.1.tgz")),
        ])))
        .mount(&upstream)
        .await;
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.npm.proxy = Some(uri);
        cfg.server.public_url = Some("http://nora.example".to_string());
    });
    let resp = send(&ctx.app, Method::GET, "/npm/pkg", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    assert_eq!(
        tarballs(&body),
        vec![
            "http://nora.example/npm/pkg/-/pkg-1.0.0.tgz",
            "http://nora.example/npm/pkg/-/pkg-1.0.1.tgz",
        ]
    );
}
