// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::*;

/// Known upstream domains that MUST NOT appear in rewritten responses.
const NUGET_UPSTREAM_DOMAINS: &[&str] = &[
    "api.nuget.org",
    "azuresearch-usnc.nuget.org",
    "azuresearch-ussc.nuget.org",
];

/// Known URL patterns in NuGet responses that are NOT client-fetchable
/// and intentionally left unrewritten (the leak detector skips them too).
const NUGET_EXCLUDED_PATTERNS: &[&str] = UPSTREAM_PASSTHROUGH_PATHS;

/// Assert that no upstream URLs remain in a rewritten response body,
/// excluding known non-client-fetchable URL patterns.
/// This is the core air-gap invariant: any leaked URL means the client
/// tries to reach the internet and fails in air-gapped environments.
fn assert_no_upstream_urls(body: &str, context: &str) {
    for line in body.lines() {
        if NUGET_EXCLUDED_PATTERNS.iter().any(|p| line.contains(p)) {
            continue;
        }
        for domain in NUGET_UPSTREAM_DOMAINS {
            assert!(
                !line.contains(domain),
                "upstream domain '{}' leaked in {} (line: {})",
                domain,
                context,
                line.trim()
            );
        }
    }
}

/// Load a golden fixture from testdata/nuget/.
fn load_fixture(name: &str) -> String {
    let path = format!("{}/testdata/nuget/{}", env!("CARGO_MANIFEST_DIR"), name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to load fixture {}: {}", path, e))
}

// ── Generated service index: air-gap invariants ──

#[test]
fn test_generated_service_index_no_upstream_leak() {
    let generated = generate_service_index("https://registry.airgap.local");
    assert_no_upstream_urls(&generated, "generated service-index");

    let json: serde_json::Value = serde_json::from_str(&generated).unwrap();
    assert!(json["resources"].is_array());
    assert!(!json["resources"].as_array().unwrap().is_empty());
}

#[test]
fn test_generated_service_index_all_ids_point_to_nora() {
    let generated = generate_service_index("http://nora:4000");
    let json: serde_json::Value = serde_json::from_str(&generated).unwrap();
    let resources = json["resources"].as_array().unwrap();

    // Every @id must start with nora base — no exceptions (air-gap invariant)
    for res in resources {
        let id = res["@id"].as_str().unwrap();
        let res_type = res["@type"].as_str().unwrap_or("");
        assert!(
            id.starts_with("http://nora:4000/nuget/"),
            "resource @id not pointing to NORA: {} (type: {})",
            id,
            res_type
        );
    }
}

#[test]
fn test_generated_service_index_snapshot() {
    let generated = generate_service_index("http://nora:4000");
    let json: serde_json::Value = serde_json::from_str(&generated).unwrap();

    let ids: Vec<&str> = json["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["@id"].as_str().unwrap())
        .collect();
    insta::assert_json_snapshot!("nuget_service_index_ids", ids);
}

#[test]
fn test_search_response_registration_urls_rewritten() {
    let upstream_search = r#"{"totalHits":1,"data":[{"id":"Newtonsoft.Json","version":"13.0.3","registration":"https://api.nuget.org/v3/registration5-gz-semver2/newtonsoft.json/index.json"}]}"#;
    let rewritten =
        rewrite_registration_urls(upstream_search, "https://api.nuget.org", "http://nora:4000");
    assert_no_upstream_urls(&rewritten, "search response rewrite");
    assert!(rewritten.contains("http://nora:4000/nuget/v3/registration/newtonsoft.json/index.json"));
}

#[test]
fn test_autocomplete_response_no_leak() {
    // Autocomplete responses contain only package names, no URLs to rewrite
    let upstream = r#"{"totalHits":5,"data":["Newtonsoft.Json","NUnit","NLog","Nancy","Noda"]}"#;
    let rewritten =
        rewrite_registration_urls(upstream, "https://api.nuget.org", "http://nora:4000");
    assert_no_upstream_urls(&rewritten, "autocomplete response");
}

// ── Registration index rewrite: paginated fixture ──

#[test]
fn test_registration_paginated_golden_no_upstream_leak() {
    let fixture = load_fixture("registration-index-paginated.json");
    let rewritten = rewrite_registration_urls(
        &fixture,
        "https://api.nuget.org",
        "https://registry.airgap.local",
    );
    assert_no_upstream_urls(&rewritten, "registration-index-paginated rewrite");

    let json: serde_json::Value = serde_json::from_str(&rewritten).unwrap();
    assert_eq!(json["count"].as_u64().unwrap(), 2);

    // All page @id must point to NORA
    for item in json["items"].as_array().unwrap() {
        let id = item["@id"].as_str().unwrap();
        assert!(
            id.starts_with("https://registry.airgap.local/nuget/v3/registration/"),
            "page @id not rewritten: {}",
            id
        );
    }
}

#[test]
fn test_registration_paginated_golden_snapshot() {
    let fixture = load_fixture("registration-index-paginated.json");
    let rewritten =
        rewrite_registration_urls(&fixture, "https://api.nuget.org", "http://nora:4000");
    let json: serde_json::Value = serde_json::from_str(&rewritten).unwrap();

    let page_ids: Vec<&str> = json["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["@id"].as_str().unwrap())
        .collect();
    insta::assert_json_snapshot!("nuget_registration_paginated_page_ids", page_ids);
}

// ── Registration index rewrite: inline fixture ──

#[test]
fn test_registration_inline_golden_no_upstream_leak() {
    let fixture = load_fixture("registration-index-inline.json");
    let rewritten =
        rewrite_registration_urls(&fixture, "https://api.nuget.org", "http://nora:4000");

    // registration5-gz-semver2 URLs must be rewritten
    assert!(!rewritten.contains("registration5-gz-semver2"));
    assert!(!rewritten.contains("registration5-semver1"));
    assert!(!rewritten.contains("registration5-gz-semver1"));

    let json: serde_json::Value = serde_json::from_str(&rewritten).unwrap();
    let page = &json["items"][0];
    let entry = &page["items"][0];

    // entry @id must be rewritten to NORA
    let entry_id = entry["@id"].as_str().unwrap();
    assert!(
        entry_id.starts_with("http://nora:4000/nuget/v3/registration/"),
        "inline entry @id not rewritten: {}",
        entry_id
    );
}

// ── Content-Type assertions ──

#[tokio::test]
async fn test_service_index_content_type_no_gzip() {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::Method;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = None;
    });

    // Generated service index — no upstream or fixture needed
    let resp = send(&ctx.app, Method::GET, "/nuget/v3/index.json", "").await;
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let content_type = resp
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap_or(""))
        .unwrap_or("");
    assert!(
        content_type.contains("application/json"),
        "NuGet service index must return application/json, got: {}",
        content_type
    );

    // Service index must NOT be gzip-encoded (only registration endpoints are)
    assert!(
        resp.headers().get("content-encoding").is_none(),
        "service index must not have Content-Encoding header"
    );
}

#[test]
fn test_semver1_registration_drops_semver2_and_fixes_counts_and_bounds() {
    let leaf = |v: &str| {
        serde_json::json!({
            "@id": format!("http://nora:4000/nuget/v3/registration/foo/{v}.json"),
            "catalogEntry": {"version": v},
        })
    };
    // A SemVer 1 version whose dependency range names a SemVer 2 version is SemVer 2.
    let with_range = |v: &str, range: &str| {
        let mut l = leaf(v);
        l["catalogEntry"]["dependencyGroups"] =
            serde_json::json!([{"dependencies": [{"id": "Bar", "range": range}]}]);
        l
    };
    let mut index = serde_json::json!({
        "count": 3,
        "items": [
            {"@id": "http://nora:4000/nuget/v3/registration/foo/index.json#page/1.0.0/2.0.0-rc.1",
             "count": 4, "lower": "1.0.0", "upper": "2.0.0-rc.1",
             "items": [leaf("1.0.0"), with_range("1.1.0", "[1.0.0, 2.0.0)"),
                       with_range("1.2.0", "[1.0.0-alpha.1, )"), leaf("2.0.0-rc.1")]},
            {"@id": "http://nora:4000/nuget/v3/registration/foo/index.json#page/3.0.0-rc.1/3.0.0-rc.2",
             "count": 2, "lower": "3.0.0-rc.1", "upper": "3.0.0-rc.2",
             "items": [leaf("3.0.0-rc.1"), leaf("3.0.0-rc.2")]},
            {"@id": "http://nora:4000/nuget/v3/registration/foo/page/4.0.0/5.0.0.json",
             "count": 64, "lower": "4.0.0", "upper": "5.0.0"}
        ]
    });
    semver1_registration(&mut index);
    // The all-SemVer-2 inlined page is gone; the page served by reference is left
    // to semver1_index.
    assert_eq!(index["count"], 2);
    let pages = index["items"].as_array().unwrap();
    let versions: Vec<&str> = pages[0]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["catalogEntry"]["version"].as_str().unwrap())
        .collect();
    assert_eq!(versions, ["1.0.0", "1.1.0"]);
    assert_eq!(pages[0]["count"], 2);
    assert_eq!(
        (&pages[0]["lower"], &pages[0]["upper"]),
        (&serde_json::json!("1.0.0"), &serde_json::json!("1.1.0"))
    );
    assert_eq!(pages[1]["count"], 64);
    assert_eq!(pages[1]["upper"], "5.0.0");

    // A page document: its own count and bounds follow the leaves kept.
    let mut page = serde_json::json!({"count": 3, "lower": "4.0.0", "upper": "4.2.0",
        "items": [leaf("4.0.0"), leaf("4.1.0"), leaf("4.2.0+build")]});
    semver1_registration(&mut page);
    assert_eq!(page["count"], 2);
    assert_eq!(
        (&page["lower"], &page["upper"]),
        (&serde_json::json!("4.0.0"), &serde_json::json!("4.1.0"))
    );
}

/// Each hive answers by its type's contract: `registration-semver1` (bare,
/// `/3.0.0-beta`, `/3.0.0-rc`) with no Content-Encoding, `registration-gz-semver1`
/// (`/3.4.0`) gzip, both without SemVer 2.0.0 versions; `registration` keeps them.
#[tokio::test]
async fn test_semver1_hives_response_contract() {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::Method;
    use std::io::Read;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = None;
    });
    let leaf = |v: &str| {
        serde_json::json!({
            "@id": format!("https://api.nuget.org/v3/registration5-gz-semver2/foo/{v}.json"),
            "catalogEntry": {"id": "Foo", "version": v},
            "packageContent": format!("https://api.nuget.org/v3-flatcontainer/foo/{v}/foo.{v}.nupkg")
        })
    };
    let index = serde_json::json!({
        "count": 1,
        "items": [{
            "@id": "https://api.nuget.org/v3/registration5-gz-semver2/foo/index.json#page/1.0.0/2.0.0-rc.1",
            "count": 2, "lower": "1.0.0", "upper": "2.0.0-rc.1",
            "items": [leaf("1.0.0"), leaf("2.0.0-rc.1")]
        }]
    });
    ctx.state
        .storage
        .put(
            "nuget/registration/foo/index.json",
            index.to_string().as_bytes(),
        )
        .await
        .unwrap();

    for (hive, gzip, semver2) in [
        ("registration-semver1", false, false),
        ("registration-gz-semver1", true, false),
        ("registration", true, true),
    ] {
        let resp = send(
            &ctx.app,
            Method::GET,
            &format!("/nuget/v3/{hive}/foo/index.json"),
            "",
        )
        .await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK, "{hive}");
        let encoding = resp
            .headers()
            .get("content-encoding")
            .map(|v| v.to_str().unwrap().to_string());
        assert_eq!(
            encoding.as_deref() == Some("gzip"),
            gzip,
            "{hive}: {encoding:?}"
        );
        let body = body_bytes(resp).await;
        let text = if gzip {
            let mut s = String::new();
            flate2::read::GzDecoder::new(&body[..])
                .read_to_string(&mut s)
                .unwrap();
            s
        } else {
            String::from_utf8(body.to_vec()).unwrap()
        };
        let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
        let versions: Vec<&str> = doc["items"][0]["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l["catalogEntry"]["version"].as_str().unwrap())
            .collect();
        let want: &[&str] = if semver2 {
            &["1.0.0", "2.0.0-rc.1"]
        } else {
            &["1.0.0"]
        };
        assert_eq!(versions, want, "{hive}");
        assert_eq!(doc["items"][0]["count"], want.len(), "{hive}");
        assert!(
            text.contains(&format!("/nuget/v3/{hive}/foo/")),
            "{hive}: {text}"
        );
        assert!(
            !text.contains("api.nuget.org/v3/registration"),
            "{hive}: {text}"
        );
    }
}

/// Pages served by reference take the SemVer 1 page's own count and bounds in a
/// SemVer 1 index (an all-SemVer-2 one is dropped), and every leaf `@id` a hive lists
/// answers, with the hive's own visibility.
#[tokio::test]
async fn test_semver1_hives_page_refs_and_leaves() {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use std::io::Read;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = None;
    });
    let up = "https://api.nuget.org/v3/registration5-gz-semver2/foo";
    let leaf = |v: &str| {
        serde_json::json!({
            "@id": format!("{up}/{v}.json"),
            "catalogEntry": {"@id": format!("https://api.nuget.org/v3/catalog0/data/foo.{v}.json"),
                             "id": "Foo", "version": v, "published": "2024-01-01T00:00:00Z"},
            "packageContent": format!("https://api.nuget.org/v3-flatcontainer/foo/{v}/foo.{v}.nupkg"),
            "registration": format!("{up}/index.json")
        })
    };
    let index = serde_json::json!({
        "count": 3,
        "items": [
            {"@id": format!("{up}/index.json#page/1.0.0/2.0.0-rc.1"), "count": 2,
             "lower": "1.0.0", "upper": "2.0.0-rc.1", "items": [leaf("1.0.0"), leaf("2.0.0-rc.1")]},
            {"@id": format!("{up}/page/4.0.0/5.0.0-beta.2.json"), "count": 3,
             "lower": "4.0.0", "upper": "5.0.0-beta.2"},
            {"@id": format!("{up}/page/6.0.0-rc.1/6.0.0-rc.2.json"), "count": 2,
             "lower": "6.0.0-rc.1", "upper": "6.0.0-rc.2"}
        ]
    });
    let page = |lower: &str, upper: &str, versions: &[&str]| {
        serde_json::json!({
            "@id": format!("{up}/page/{lower}/{upper}.json"), "count": versions.len(),
            "lower": lower, "upper": upper,
            "items": versions.iter().map(|v| leaf(v)).collect::<Vec<_>>()
        })
    };
    for (key, doc) in [
        ("nuget/registration/foo/index.json".to_string(), index),
        (
            registration_page_key("foo", "4.0.0", "5.0.0-beta.2"),
            page(
                "4.0.0",
                "5.0.0-beta.2",
                &["4.0.0", "4.5.0-rc.1", "5.0.0-beta.2"],
            ),
        ),
        (
            registration_page_key("foo", "6.0.0-rc.1", "6.0.0-rc.2"),
            page("6.0.0-rc.1", "6.0.0-rc.2", &["6.0.0-rc.1", "6.0.0-rc.2"]),
        ),
    ] {
        ctx.state
            .storage
            .put(&key, doc.to_string().as_bytes())
            .await
            .unwrap();
    }
    let get = |path: String| {
        let app = ctx.app.clone();
        async move {
            let resp = send(&app, Method::GET, &path, "").await;
            let status = resp.status();
            let gzip = resp.headers().get("content-encoding").is_some();
            let body = body_bytes(resp).await;
            let text = if gzip {
                let mut s = String::new();
                flate2::read::GzDecoder::new(&body[..])
                    .read_to_string(&mut s)
                    .unwrap();
                s
            } else {
                String::from_utf8(body.to_vec()).unwrap()
            };
            (
                status,
                serde_json::from_str::<serde_json::Value>(&text).ok(),
            )
        }
    };

    for hive in ["registration-semver1", "registration-gz-semver1"] {
        let (status, doc) = get(format!("/nuget/v3/{hive}/foo/index.json")).await;
        assert_eq!(status, StatusCode::OK, "{hive}");
        let doc = doc.unwrap();
        assert_eq!(doc["count"], 2, "{hive}: {doc}");
        // `count` is the number of pages in `items`: the SemVer 2-only page is gone
        assert_eq!(
            doc["items"].as_array().map(Vec::len),
            Some(2),
            "{hive}: {doc}"
        );
        assert!(!doc.to_string().contains("6.0.0-rc.1"), "{hive}: {doc}");
        let r = &doc["items"][1];
        assert_eq!(r["count"], 1, "{hive}: {r}");
        assert_eq!(
            (r["lower"].as_str(), r["upper"].as_str()),
            (Some("4.0.0"), Some("4.0.0"))
        );
        assert!(r.get("items").is_none(), "{hive}: stays by reference");
        // The page URL keeps the full page's bounds, and the page agrees with the index.
        let page_url = r["@id"].as_str().unwrap();
        assert!(
            page_url.ends_with(&format!("/{hive}/foo/page/4.0.0/5.0.0-beta.2.json")),
            "{page_url}"
        );
        let (status, page) = get(page_url
            .split_once("/nuget/")
            .map(|(_, p)| format!("/nuget/{p}"))
            .unwrap())
        .await;
        assert_eq!(status, StatusCode::OK);
        let page = page.unwrap();
        assert_eq!(
            (page["count"].clone(), page["upper"].clone()),
            (serde_json::json!(1), serde_json::json!("4.0.0"))
        );

        // Leaves: an inlined and a referenced SemVer 1 one answer; a SemVer 2 one is absent.
        for (version, want) in [
            ("1.0.0", StatusCode::OK),
            ("4.0.0", StatusCode::OK),
            ("4.5.0-rc.1", StatusCode::NOT_FOUND),
            ("2.0.0-rc.1", StatusCode::NOT_FOUND),
        ] {
            let (status, body) = get(format!("/nuget/v3/{hive}/foo/{version}.json")).await;
            assert_eq!(status, want, "{hive} {version}");
            if want == StatusCode::OK {
                let body = body.unwrap();
                assert!(
                    body["@id"]
                        .as_str()
                        .unwrap()
                        .ends_with(&format!("/nuget/v3/{hive}/foo/{version}.json")),
                    "{body}"
                );
                assert_eq!(body["listed"], true);
                assert_eq!(body["published"], "2024-01-01T00:00:00Z");
                assert!(
                    body["packageContent"]
                        .as_str()
                        .unwrap()
                        .contains("/v3/flatcontainer/foo/"),
                    "{body}"
                );
                assert!(
                    body["registration"]
                        .as_str()
                        .unwrap()
                        .ends_with(&format!("/{hive}/foo/index.json")),
                    "{body}"
                );
                assert!(
                    body["catalogEntry"].as_str().unwrap().contains("catalog0"),
                    "{body}"
                );
            }
        }
    }
    // The SemVer 2 hive serves its SemVer 2 leaves, inlined and referenced.
    for version in ["2.0.0-rc.1", "4.5.0-rc.1"] {
        let (status, _) = get(format!("/nuget/v3/registration/foo/{version}.json")).await;
        assert_eq!(status, StatusCode::OK, "{version}");
    }
    let (status, _) = get("/nuget/v3/registration/foo/9.9.9.json".to_string()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A registration document past REGISTRATION_INLINE_MAX goes through the hive on the
/// blocking pool and reads the same as a small one.
#[tokio::test]
async fn test_semver1_hive_big_document() {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::Method;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = None;
    });
    let leaves: Vec<_> = (0..1500)
        .map(|i| {
            let v = if i % 2 == 0 { format!("1.0.{i}") } else { format!("1.0.{i}-rc.1") };
            serde_json::json!({"@id": format!("https://api.nuget.org/v3/registration5-gz-semver2/foo/{v}.json"),
                               "catalogEntry": {"id": "Foo", "version": v}})
        })
        .collect();
    let index = serde_json::json!({"count": 1, "items": [{
        "@id": "https://api.nuget.org/v3/registration5-gz-semver2/foo/index.json#page/1.0.0/1.0.1499-rc.1",
        "count": leaves.len(), "lower": "1.0.0", "upper": "1.0.1499-rc.1", "items": leaves}]});
    let raw = index.to_string();
    assert!(raw.len() > REGISTRATION_INLINE_MAX * 2);
    ctx.state
        .storage
        .put("nuget/registration/foo/index.json", raw.as_bytes())
        .await
        .unwrap();
    let resp = send(
        &ctx.app,
        Method::GET,
        "/nuget/v3/registration-semver1/foo/index.json",
        "",
    )
    .await;
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let doc: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(doc["items"][0]["count"], 750);
    assert_eq!(doc["items"][0]["upper"], "1.0.1498");
}

#[tokio::test]
async fn test_cached_registration_content_type_and_gzip() {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::Method;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = None;
    });

    let fixture = load_fixture("registration-index-inline.json");
    ctx.state
        .storage
        .put("nuget/registration/xunit/index.json", fixture.as_bytes())
        .await
        .unwrap();

    let resp = send(
        &ctx.app,
        Method::GET,
        "/nuget/v3/registration/xunit/index.json",
        "",
    )
    .await;

    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let content_type = resp
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap_or(""))
        .unwrap_or("");
    assert!(
        content_type.contains("application/json"),
        "NuGet registration index must return application/json, got: {}",
        content_type
    );

    // Registration must be gzip-encoded (RegistrationsBaseUrl/3.6.0 spec)
    let content_encoding = resp
        .headers()
        .get("content-encoding")
        .map(|v| v.to_str().unwrap_or(""))
        .unwrap_or("");
    assert_eq!(
        content_encoding, "gzip",
        "registration response must have Content-Encoding: gzip"
    );

    // Decompress and verify the rewritten body has no upstream URLs
    let body = body_bytes(resp).await;
    let mut decoder = flate2::read::GzDecoder::new(&body[..]);
    let mut decompressed = String::new();
    std::io::Read::read_to_string(&mut decoder, &mut decompressed).unwrap();
    assert_no_upstream_urls(&decompressed, "cached registration index response");
}

// ── Cache-Control assertions ──

#[tokio::test]
async fn test_nupkg_cache_control_immutable() {
    use crate::test_helpers::{create_test_context_with_config, send};
    use axum::http::Method;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
    });

    ctx.state
        .storage
        .put(
            "nuget/flatcontainer/testpkg/1.0.0/testpkg.1.0.0.nupkg",
            b"fake-nupkg",
        )
        .await
        .unwrap();

    let resp = send(
        &ctx.app,
        Method::GET,
        "/nuget/v3/flatcontainer/testpkg/1.0.0/testpkg.1.0.0.nupkg",
        "",
    )
    .await;
    assert_eq!(resp.status(), axum::http::StatusCode::OK);

    let cache_control = resp
        .headers()
        .get("cache-control")
        .map(|v| v.to_str().unwrap_or(""))
        .unwrap_or("");
    assert!(
        cache_control.contains("immutable"),
        "nupkg must have immutable cache-control, got: {}",
        cache_control
    );
}

/// C56: an upstream 304 writes only the small `.meta` sidecar (one PUT carrying
/// `validated_at`), never the cached body again.
#[tokio::test]
async fn test_nuget_304_writes_only_the_sidecar() {
    use crate::registry::{validators_key, write_validators, Validators};
    use crate::test_helpers::{
        create_test_context_with_storage_and_config, op_counting_storage, send,
    };
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{header_exists, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(header_exists("if-none-match"))
        .respond_with(ResponseTemplate::new(304))
        .mount(&upstream)
        .await;
    let (storage, ops) = op_counting_storage();
    let ctx = create_test_context_with_storage_and_config(storage, |cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some(upstream.uri());
        cfg.nuget.metadata_ttl = 0; // always stale → always revalidate
    });
    let key = "nuget/flatcontainer/sidecar-pkg/index.json";
    ctx.state
        .storage
        .put(key, br#"{"versions":["1.0.0"]}"#)
        .await
        .unwrap();
    let v = Validators {
        etag: Some("\"v1\"".to_string()),
        last_modified: None,
    };
    write_validators(&ctx.state.storage, key, &v).await;
    ops.reset();

    let uri = "/nuget/v3/flatcontainer/sidecar-pkg/index.json";
    let resp = send(&ctx.app, Method::GET, uri, "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let mut stamped = false;
    for _ in 0..100 {
        let sidecar = ctx.state.storage.get(&validators_key(key)).await.unwrap();
        if String::from_utf8_lossy(&sidecar).contains("validated_at") {
            stamped = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(stamped, "the 304 is recorded in the sidecar");
    assert_eq!(
        ops.snapshot().get("put"),
        Some(&1),
        "only the sidecar is written: {:?}",
        ops.snapshot()
    );
}

/// #52 acceptance: with a cached flat-container version list + stored
/// validators, a stale request revalidates with `If-None-Match`; on upstream
/// 304 the cached body is served with no 200-body download. nuget.org returns
/// validators on this endpoint, so this is a real revalidation.
#[tokio::test]
async fn test_nuget_revalidation_304_serves_cache_no_body_download() {
    use crate::registry::{write_validators, Validators};
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{header_exists, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    // Conditional request (has If-None-Match) → 304. A request WITHOUT it
    // would 404 (no other mount), so any full fetch would visibly fail.
    Mock::given(method("GET"))
        .and(header_exists("if-none-match"))
        .respond_with(ResponseTemplate::new(304))
        .mount(&upstream)
        .await;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some(upstream.uri());
        cfg.nuget.metadata_ttl = 0; // always stale → always revalidate
        cfg.nuget.revalidate = true;
        cfg.nuget.serve_stale = false;
    });

    let key = "nuget/flatcontainer/test-package/index.json";
    ctx.state
        .storage
        .put(key, br#"{"versions":["1.0.0","2.0.0"]}"#)
        .await
        .unwrap();
    write_validators(
        &ctx.state.storage,
        key,
        &Validators {
            etag: Some("\"v1\"".to_string()),
            last_modified: None,
        },
    )
    .await;

    let before = crate::metrics::PROXY_UPSTREAM_304_TOTAL
        .with_label_values(&["nuget"])
        .get();
    let observed_before = crate::metrics::UPSTREAM_REQUEST_DURATION
        .with_label_values(&["nuget", "304"])
        .get_sample_count();

    let resp = send(
        &ctx.app,
        Method::GET,
        "/nuget/v3/flatcontainer/test-package/index.json",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    assert!(
        String::from_utf8_lossy(&body).contains("2.0.0"),
        "must serve the cached version list"
    );

    let after = crate::metrics::PROXY_UPSTREAM_304_TOTAL
        .with_label_values(&["nuget"])
        .get();
    assert!(after > before, "a 304 revalidation must be recorded");
    assert!(
        crate::metrics::UPSTREAM_REQUEST_DURATION
            .with_label_values(&["nuget", "304"])
            .get_sample_count()
            > observed_before,
        "the conditional upstream call is observed in nora_upstream_request_duration_seconds"
    );
}

/// A stale version list is served from the cache at once and refreshed behind the
/// response: neither the upstream nor the storage round-trips of the revalidation
/// sit on the client's critical path (NoraHighLatency 03.11.2026). The body proves
/// it: a response that had waited for upstream would carry the new version.
#[tokio::test]
async fn test_nuget_stale_version_list_served_now_refreshed_behind() {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Unpooled: a pooled server may be one an earlier test dropped while its background
    // request (nuget_release_dates' repro.pkg) was still in flight, and the count below
    // would see it.
    let upstream = MockServer::builder().start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"versions":["1.0.0","2.0.0","3.0.0"]}"#)
                .set_delay(std::time::Duration::from_millis(300)),
        )
        .mount(&upstream)
        .await;
    let ctx = create_test_context_with_config(|cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some(upstream.uri());
        cfg.nuget.metadata_ttl = 0; // always stale
    });
    let key = "nuget/flatcontainer/swr-pkg/index.json";
    ctx.state
        .storage
        .put(key, br#"{"versions":["1.0.0","2.0.0"]}"#)
        .await
        .unwrap();

    let resp = send(
        &ctx.app,
        Method::GET,
        "/nuget/v3/flatcontainer/swr-pkg/index.json",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["x-nora-stale"], "true");
    let body = body_bytes(resp).await;
    assert!(
        !String::from_utf8_lossy(&body).contains("3.0.0"),
        "the cached list is served as is, not the upstream's"
    );

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        // A read that lands inside the background write can fail on the local
        // backend (body renamed in, pin recorded after it); the S3 backend writes
        // the pin with the object. Only the refreshed body ends the wait.
        let data = ctx.state.storage.get(key).await.unwrap_or_default();
        if String::from_utf8_lossy(&data).contains("3.0.0") {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "never refreshed");
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let asked: Vec<String> = upstream
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.url.path().to_string())
        .collect();
    assert_eq!(asked.len(), 1, "upstream asked: {asked:?}");
}
