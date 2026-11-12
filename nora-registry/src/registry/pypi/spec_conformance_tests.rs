// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::*;

/// PEP 691 requires the field name `hashes`, NOT `digests`.
/// Regression test for bug where `digests` was used instead.
#[test]
fn test_pep691_uses_hashes_not_digests() {
    let files = vec![FileEntry {
        filename: "pkg-1.0.tar.gz".into(),
        sha256: Some("abcdef1234567890".into()),
        ..Default::default()
    }];
    let response = versions_json_response("pkg", &files, "http://nora:4000", &Default::default());
    let body = response.into_body();
    let bytes = futures::executor::block_on(axum::body::to_bytes(body, 1024 * 1024)).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert!(
        json["files"][0].get("hashes").is_some(),
        "PEP 691 requires 'hashes' field, not 'digests'"
    );
    assert!(
        json["files"][0].get("digests").is_none(),
        "PEP 691 forbids 'digests' — must be 'hashes'"
    );
    assert_eq!(json["files"][0]["hashes"]["sha256"], "abcdef1234567890");
}

/// The simple JSON carries `meta.api-version`. NORA advertises 1.1 (PEP 700,
/// still within the `v1` media type) now that it emits upload-time/size/versions.
#[test]
fn test_pep691_meta_api_version() {
    let files = vec![FileEntry {
        filename: "pkg-1.0.tar.gz".into(),
        sha256: None,
        ..Default::default()
    }];
    let response = versions_json_response("pkg", &files, "http://nora:4000", &Default::default());
    let bytes =
        futures::executor::block_on(axum::body::to_bytes(response.into_body(), 1024 * 1024))
            .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(
        json["meta"]["api-version"], "1.1",
        "PEP 700 support is signalled by meta.api-version = '1.1'"
    );
}

/// PEP 691 JSON Content-Type must be `application/vnd.pypi.simple.v1+json`.
#[test]
fn test_pep691_content_type() {
    let files = vec![];
    let response = versions_json_response("pkg", &files, "http://nora:4000", &Default::default());
    let ct = response
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(
        ct, PEP691_JSON,
        "PEP 691 requires Content-Type: {PEP691_JSON}"
    );
}

/// PEP 691: "The hashes dictionary MUST be present, even if no hashes are
/// available for the file". With no digest it is the empty object — not absent
/// (uv: `missing field hashes`, #1100) and not null.
#[test]
fn test_pep691_hashes_present_as_empty_object_when_none() {
    let files = vec![FileEntry {
        filename: "pkg-1.0.tar.gz".into(),
        sha256: None,
        ..Default::default()
    }];
    let response = versions_json_response("pkg", &files, "http://nora:4000", &Default::default());
    let bytes =
        futures::executor::block_on(axum::body::to_bytes(response.into_body(), 1024 * 1024))
            .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(
        json["files"][0].get("hashes"),
        Some(&serde_json::json!({})),
        "hashes must be present as {{}} when no hash is available"
    );
}

/// Every file carries the CORRECT `hashes` object across the matrix: filename extension
/// (`.tar.gz` / `.whl`) × hash present/absent × each `(size, upload-time)` combination.
/// `hashes` is exactly `{}` when no digest is known and exactly `{"sha256": <hex>}` when
/// one is — never missing, `null`, an array, or an empty-string digest. The no-hash +
/// upload-time cell is the production proxy case uv rejected (#1100).
#[test]
fn test_pep691_hashes_object_present_across_pep700_matrix() {
    use std::collections::HashMap;
    // Both extensions, with and without a hash.
    let specs: [(&str, Option<&str>); 4] = [
        ("hashed-1.0.tar.gz", Some("deadbeef")),
        ("nohash-1.0.tar.gz", None),
        ("hashed-1.0-py3-none-any.whl", Some("cafef00d")),
        ("nohash-1.0-py3-none-any.whl", None),
    ];
    let files: Vec<FileEntry> = specs
        .iter()
        .map(|(name, sha)| FileEntry {
            filename: (*name).into(),
            sha256: sha.map(str::to_string),
            ..Default::default()
        })
        .collect();
    let combos: [(Option<u64>, Option<String>); 4] = [
        (None, None),
        (Some(1234), None),
        (None, Some("2026-01-01T00:00:00Z".to_string())),
        (Some(1234), Some("2026-01-01T00:00:00Z".to_string())),
    ];
    for (size, upload_time) in combos {
        let pep700: HashMap<String, (Option<u64>, Option<String>)> = specs
            .iter()
            .map(|(name, _)| ((*name).to_string(), (size, upload_time.clone())))
            .collect();
        let response = versions_json_response("pkg", &files, "http://nora:4000", &pep700);
        let bytes =
            futures::executor::block_on(axum::body::to_bytes(response.into_body(), 1024 * 1024))
                .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let arr = json["files"].as_array().expect("files array");
        for (name, sha) in specs {
            let file = arr
                .iter()
                .find(|f| f["filename"] == name)
                .unwrap_or_else(|| panic!("file {name} missing from response"));
            let want = match sha {
                Some(h) => serde_json::json!({ "sha256": h }),
                None => serde_json::json!({}),
            };
            assert_eq!(
                file.get("hashes"),
                Some(&want),
                "wrong hashes for {name} (size={size:?} upload_time={upload_time:?})"
            );
        }
    }
}

/// PEP 691: `name` field must match the normalized package name.
#[test]
fn test_pep691_name_is_normalized() {
    let files = vec![];
    let normalized = normalize_name("Flask-RESTful");
    let response =
        versions_json_response(&normalized, &files, "http://nora:4000", &Default::default());
    let bytes =
        futures::executor::block_on(axum::body::to_bytes(response.into_body(), 1024 * 1024))
            .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(json["name"], "flask-restful");
}

/// PEP 691: file URLs must point to NORA, not upstream.
#[test]
fn test_pep691_urls_point_to_nora() {
    let files = vec![
        FileEntry {
            filename: "pkg-1.0.tar.gz".into(),
            sha256: Some("aaa".into()),
            ..Default::default()
        },
        FileEntry {
            filename: "pkg-2.0.whl".into(),
            sha256: Some("bbb".into()),
            ..Default::default()
        },
    ];
    let response = versions_json_response("pkg", &files, "http://nora:4000", &Default::default());
    let bytes =
        futures::executor::block_on(axum::body::to_bytes(response.into_body(), 1024 * 1024))
            .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    for file in json["files"].as_array().unwrap() {
        let url = file["url"].as_str().unwrap();
        assert!(
            url.starts_with("http://nora:4000/simple/"),
            "file URL must point to NORA base: {url}"
        );
    }
}

// ========================================================================
// URL-rewrite systematic tests (#387)
// ========================================================================

/// URLs in HTML response must point to NORA, not upstream (#387).
#[test]
fn test_html_urls_point_to_nora_no_upstream_leak() {
    let files = vec![
        FileEntry {
            filename: "requests-2.31.0.tar.gz".into(),
            sha256: Some("aaa111".into()),
            ..Default::default()
        },
        FileEntry {
            filename: "requests-2.31.0-py3-none-any.whl".into(),
            sha256: Some("bbb222".into()),
            ..Default::default()
        },
    ];
    let response = versions_html_response("requests", &files, "http://nora:4000");
    let bytes =
        futures::executor::block_on(axum::body::to_bytes(response.into_body(), 1024 * 1024))
            .unwrap();
    let html = String::from_utf8(bytes.to_vec()).unwrap();

    assert!(
        html.contains("http://nora:4000/simple/requests/requests-2.31.0.tar.gz"),
        "HTML must contain NORA URL for tarball"
    );
    assert!(
        html.contains("http://nora:4000/simple/requests/requests-2.31.0-py3-none-any.whl"),
        "HTML must contain NORA URL for wheel"
    );
    // No upstream host leak
    assert!(
        !html.contains("pypi.org") && !html.contains("pythonhosted"),
        "HTML must not contain upstream URLs"
    );
}

/// Trailing slash on base_url must not produce double-slash in URLs (#387).
#[test]
fn test_pep691_trailing_slash_handling() {
    let files = vec![FileEntry {
        filename: "pkg-1.0.tar.gz".into(),
        sha256: Some("abc".into()),
        ..Default::default()
    }];
    let response = versions_json_response("pkg", &files, "http://nora:4000/", &Default::default());
    let bytes =
        futures::executor::block_on(axum::body::to_bytes(response.into_body(), 1024 * 1024))
            .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let url = json["files"][0]["url"].as_str().unwrap();
    assert!(
        !url.contains("//simple"),
        "trailing slash on base_url must not produce double-slash: {url}"
    );
    assert!(
        url.starts_with("http://nora:4000/"),
        "URL must start with base: {url}"
    );
}

/// Empty file list produces valid response with no file URLs (#387).
#[test]
fn test_pep691_no_files_clean_response() {
    let files: Vec<FileEntry> = vec![];
    let response =
        versions_json_response("empty-pkg", &files, "http://nora:4000", &Default::default());
    let bytes =
        futures::executor::block_on(axum::body::to_bytes(response.into_body(), 1024 * 1024))
            .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["files"].as_array().unwrap().len(), 0);
    assert_eq!(json["name"], "empty-pkg");
}

/// Upstream HTML with no matching package links → empty file list (#387).
#[test]
fn test_parse_upstream_no_package_links_yields_empty() {
    let html = r#"<html><body>
            <a href="https://example.com/page">Not a package</a>
            <a href="/about">About</a>
        </body></html>"#;
    let files = parse_upstream_files(html, "https://pypi.org/simple/x/");
    assert!(
        files.is_empty(),
        "HTML without package links should yield empty list"
    );
}

/// PEP 691 response must be valid JSON and deserializable back to typed struct.
#[test]
fn test_pep691_response_round_trip() {
    let files = vec![FileEntry {
        filename: "pkg-1.0.tar.gz".into(),
        sha256: Some("abc123".into()),
        ..Default::default()
    }];
    let response = versions_json_response("pkg", &files, "http://nora:4000", &Default::default());
    let bytes =
        futures::executor::block_on(axum::body::to_bytes(response.into_body(), 1024 * 1024))
            .unwrap();

    // Must parse as valid JSON with expected top-level keys
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(json.get("meta").is_some(), "missing 'meta' key");
    assert!(json.get("name").is_some(), "missing 'name' key");
    assert!(json.get("files").is_some(), "missing 'files' key");

    // Snapshot the structure
    insta::assert_json_snapshot!("pypi_pep691_response_structure", json);
}
