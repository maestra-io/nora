// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::*;

/// The slim parse serves the same abbreviated packument as the whole-document parse,
/// with and without the Q04 filter, and never builds the skipped fields.
#[tokio::test]
async fn test_install_v1_view_matches_full_parse() {
    use crate::test_helpers::create_test_context_with_config;
    let ago = |secs: i64| {
        (chrono::Utc::now() - chrono::Duration::seconds(secs))
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string()
    };
    let manifest = |v: &str| {
        serde_json::json!({
            "name": "pkg", "version": v, "description": "x".repeat(4096),
            "readme": "r".repeat(4096), "scripts": { "test": "jest" },
            "dependencies": { "a": "^1" }, "peerDependenciesMeta": { "b": { "optional": true } },
            "engines": { "node": ">=18" }, "os": ["linux"], "cpu": ["x64"],
            "dist": { "tarball": "https://registry.npmjs.org/pkg/-/pkg.tgz", "integrity": "sha512-x" },
            "maintainers": [{ "name": "m" }], "_npmUser": { "name": "m" }
        })
    };
    let packument = serde_json::json!({
        "_id": "pkg", "_rev": "1-a", "name": "pkg", "readme": "R".repeat(65536),
        "description": "d", "maintainers": [{ "name": "m" }], "users": { "u": true },
        "dist-tags": { "latest": "1.1.0", "stable": "1.0.0" },
        "modified": ago(3600),
        "time": { "created": ago(90 * 86400), "modified": ago(3600),
                  "1.0.0": ago(30 * 86400), "1.1.0": ago(3600) },
        "versions": { "1.0.0": manifest("1.0.0"), "1.1.0": manifest("1.1.0"), "0.0.1": "broken" }
    });
    let data = serde_json::to_vec(&packument).unwrap();

    let slim = install_v1_view(&data).unwrap();
    assert!(slim.get("readme").is_none() && slim.get("_rev").is_none());
    assert!(slim["versions"]["1.0.0"].get("readme").is_none());
    assert!(slim["versions"]["1.0.0"].get("scripts").is_none());
    assert_eq!(
        abbreviate_packument(&slim),
        abbreviate_packument(&serde_json::from_slice(&data).unwrap())
    );

    let ctx = create_test_context_with_config(|cfg| {
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.min_release_age = Some("7d".to_string());
    });
    let engine = &ctx.state.curation().curation_engine;
    assert!(engine.metadata_filter_active());
    let mut full: serde_json::Value = serde_json::from_slice(&data).unwrap();
    let mut slim = install_v1_view(&data).unwrap();
    assert!(crate::metadata_filter::npm_packument(
        engine, "pkg", &mut full
    ));
    assert!(crate::metadata_filter::npm_packument(
        engine, "pkg", &mut slim
    ));
    let expected = abbreviate_packument(&full).unwrap();
    assert_eq!(abbreviate_packument(&slim).unwrap(), expected);
    let served: serde_json::Value = serde_json::from_slice(&expected).unwrap();
    assert!(served["versions"].get("1.1.0").is_none());
    assert_eq!(served["dist-tags"]["latest"], "1.0.0");

    // Not an object, or not JSON: no view, the body is served unchanged as before.
    assert!(install_v1_view(b"[1, 2]").is_none());
    assert!(install_v1_view(b"{\"name\": ").is_none());
    assert!(install_v1_view(b"{} trailing").is_none());
}

#[test]
fn test_rewrite_tarball_urls_regular_package() {
    let metadata = serde_json::json!({
        "name": "lodash",
        "versions": {
            "4.17.21": {
                "dist": {
                    "tarball": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "shasum": "abc123"
                }
            }
        }
    });
    let data = serde_json::to_vec(&metadata).unwrap();
    let result =
        rewrite_tarball_urls(&data, "http://nora:5000", "https://registry.npmjs.org").unwrap();
    let json: serde_json::Value = serde_json::from_slice(&result).unwrap();

    assert_eq!(
        json["versions"]["4.17.21"]["dist"]["tarball"],
        "http://nora:5000/npm/lodash/-/lodash-4.17.21.tgz"
    );
    assert_eq!(json["versions"]["4.17.21"]["dist"]["shasum"], "abc123");
}

#[test]
fn test_rewrite_tarball_urls_scoped_package() {
    let metadata = serde_json::json!({
        "name": "@babel/core",
        "versions": {
            "7.26.0": {
                "dist": {
                    "tarball": "https://registry.npmjs.org/@babel/core/-/core-7.26.0.tgz",
                    "integrity": "sha512-test"
                }
            }
        }
    });
    let data = serde_json::to_vec(&metadata).unwrap();
    let result =
        rewrite_tarball_urls(&data, "http://nora:5000", "https://registry.npmjs.org").unwrap();
    let json: serde_json::Value = serde_json::from_slice(&result).unwrap();

    assert_eq!(
        json["versions"]["7.26.0"]["dist"]["tarball"],
        "http://nora:5000/npm/@babel/core/-/core-7.26.0.tgz"
    );
}

#[test]
fn test_rewrite_tarball_urls_multiple_versions() {
    let metadata = serde_json::json!({
        "name": "express",
        "versions": {
            "4.18.2": { "dist": { "tarball": "https://registry.npmjs.org/express/-/express-4.18.2.tgz" } },
            "4.19.0": { "dist": { "tarball": "https://registry.npmjs.org/express/-/express-4.19.0.tgz" } }
        }
    });
    let data = serde_json::to_vec(&metadata).unwrap();
    let result = rewrite_tarball_urls(
        &data,
        "https://demo.getnora.io",
        "https://registry.npmjs.org",
    )
    .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&result).unwrap();

    assert_eq!(
        json["versions"]["4.18.2"]["dist"]["tarball"],
        "https://demo.getnora.io/npm/express/-/express-4.18.2.tgz"
    );
    assert_eq!(
        json["versions"]["4.19.0"]["dist"]["tarball"],
        "https://demo.getnora.io/npm/express/-/express-4.19.0.tgz"
    );
}

#[test]
fn test_rewrite_tarball_urls_no_versions() {
    let metadata = serde_json::json!({ "name": "empty-pkg" });
    let data = serde_json::to_vec(&metadata).unwrap();
    let result =
        rewrite_tarball_urls(&data, "http://nora:5000", "https://registry.npmjs.org").unwrap();
    let json: serde_json::Value = serde_json::from_slice(&result).unwrap();
    assert_eq!(json["name"], "empty-pkg");
}

#[test]
fn test_rewrite_invalid_json() {
    assert!(rewrite_tarball_urls(
        b"not json",
        "http://nora:5000",
        "https://registry.npmjs.org"
    )
    .is_err());
}

#[test]
fn rebase_hosted_tarballs_follows_public_url() {
    let stored = serde_json::json!({ "versions": {
        "1.0.0": { "dist": { "tarball": "http://old:4000/npm/@s/p/-/p-1.0.0.tgz" } },
        "2.0.0": { "dist": {} }
    } });
    let data = Bytes::from(serde_json::to_vec(&stored).unwrap());
    let out = rebase_hosted_tarballs(data, "https://new.example/", "@s/p");
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        json["versions"]["1.0.0"]["dist"]["tarball"],
        "https://new.example/npm/@s/p/-/p-1.0.0.tgz"
    );
    // Already current: bytes untouched.
    let again = rebase_hosted_tarballs(out.clone(), "https://new.example", "@s/p");
    assert_eq!(again, out);
}

#[test]
fn test_valid_attachment_names() {
    assert!(is_valid_attachment_name("lodash-4.17.21.tgz"));
    assert!(is_valid_attachment_name("core-7.26.0.tgz"));
    assert!(is_valid_attachment_name("my_package-1.0.0.tgz"));
    assert!(is_valid_attachment_name("@scope-pkg-1.0.0.tgz"));
}

#[test]
fn test_path_traversal_attachment_names() {
    assert!(!is_valid_attachment_name("../../etc/passwd"));
    assert!(!is_valid_attachment_name(
        "../docker/nginx/manifests/latest.json"
    ));
    assert!(!is_valid_attachment_name("foo/bar.tgz"));
    assert!(!is_valid_attachment_name("foo\\bar.tgz"));
}

#[test]
fn test_empty_and_null_attachment_names() {
    assert!(!is_valid_attachment_name(""));
    assert!(!is_valid_attachment_name("foo\0bar.tgz"));
}

#[test]
fn test_with_content_type_tarball() {
    let data = Bytes::from("tarball-data");
    let (status, headers, body) = with_content_type(true, data.clone());
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[0].1, "application/octet-stream");
    assert_eq!(body, data);
}

#[test]
fn test_with_content_type_json() {
    let data = Bytes::from("json-data");
    let (status, headers, body) = with_content_type(false, data.clone());
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[0].1, "application/json");
    assert_eq!(body, data);
}

#[test]
fn test_rewrite_tarball_urls_trailing_slash() {
    let metadata = serde_json::json!({
        "name": "test",
        "versions": {
            "1.0.0": {
                "dist": {
                    "tarball": "https://registry.npmjs.org/test/-/test-1.0.0.tgz"
                }
            }
        }
    });
    let data = serde_json::to_vec(&metadata).unwrap();
    let result =
        rewrite_tarball_urls(&data, "http://nora:5000/", "https://registry.npmjs.org/").unwrap();
    let json: serde_json::Value = serde_json::from_slice(&result).unwrap();
    let tarball = json["versions"]["1.0.0"]["dist"]["tarball"]
        .as_str()
        .unwrap();
    assert!(tarball.starts_with("http://nora:5000/npm/"));
}

#[test]
fn test_rewrite_tarball_urls_preserves_other_fields() {
    let metadata = serde_json::json!({
        "name": "test",
        "description": "A test package",
        "versions": {
            "1.0.0": {
                "dist": {
                    "tarball": "https://registry.npmjs.org/test/-/test-1.0.0.tgz",
                    "shasum": "abc123"
                },
                "dependencies": {"lodash": "^4.0.0"}
            }
        }
    });
    let data = serde_json::to_vec(&metadata).unwrap();
    let result =
        rewrite_tarball_urls(&data, "http://nora:5000", "https://registry.npmjs.org").unwrap();
    let json: serde_json::Value = serde_json::from_slice(&result).unwrap();
    assert_eq!(json["description"], "A test package");
    assert_eq!(json["versions"]["1.0.0"]["dist"]["shasum"], "abc123");
}

// ── Safety net tests (#439) ──

#[test]
fn test_replace_upstream_bytes_basic() {
    let data = b"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz";
    let result = replace_upstream_bytes(data, "https://registry.npmjs.org", "http://nora:5000/npm");
    assert_eq!(
        String::from_utf8(result).unwrap(),
        "http://nora:5000/npm/lodash/-/lodash-4.17.21.tgz"
    );
}

#[test]
fn test_replace_upstream_bytes_no_match() {
    let data = b"no upstream urls here";
    let result = replace_upstream_bytes(data, "https://registry.npmjs.org", "http://nora/npm");
    assert_eq!(result, data);
}

#[test]
fn test_replace_upstream_bytes_empty_upstream() {
    let data = b"https://registry.npmjs.org/test";
    let result = replace_upstream_bytes(data, "", "http://nora/npm");
    assert_eq!(result, data);
}

#[test]
fn test_replace_upstream_bytes_multiple_occurrences() {
    let data = b"url1: https://registry.npmjs.org/a url2: https://registry.npmjs.org/b";
    let result = replace_upstream_bytes(data, "https://registry.npmjs.org", "http://nora:5000/npm");
    let s = String::from_utf8(result).unwrap();
    assert!(!s.contains("registry.npmjs.org"));
    assert!(s.contains("http://nora:5000/npm/a"));
    assert!(s.contains("http://nora:5000/npm/b"));
}

#[test]
fn test_rewrite_tarball_urls_safety_net_catches_unknown_fields() {
    // Simulate metadata with upstream URL in an unexpected field
    let metadata = serde_json::json!({
        "name": "test",
        "versions": {
            "1.0.0": {
                "dist": {
                    "tarball": "https://registry.npmjs.org/test/-/test-1.0.0.tgz"
                },
                "_resolved": "https://registry.npmjs.org/test/-/test-1.0.0.tgz"
            }
        }
    });
    let data = serde_json::to_vec(&metadata).unwrap();
    let result =
        rewrite_tarball_urls(&data, "http://nora:5000", "https://registry.npmjs.org").unwrap();
    let body = String::from_utf8(result).unwrap();
    // Safety net should catch the _resolved field too
    assert!(
        !body.contains("registry.npmjs.org"),
        "upstream URL leaked through _resolved field: {}",
        &body[..body.len().min(500)]
    );
}

/// GitHub Packages' tarball path, as public lockfiles record it
/// (`https://npm.pkg.github.com/download/@microsoft/…/1.11.0/<sha1>`).
#[test]
fn github_packages_tarball_path_is_recognised() {
    assert_eq!(
        github_packages_tarball(
            "download/@microsoft/security-devops-actions-toolkit/1.11.0/04fef883382f5a7c9b9ac2015dcc419009e2a858"
        ),
        Some(("@microsoft/security-devops-actions-toolkit", "1.11.0"))
    );
    assert_eq!(
        github_packages_tarball(
            "download/@CookieMonsterTeam/cookiemonsterframework/0.2.3/46a211d57dac557c86fc55f1622a6cccdf7dd25f"
        ),
        Some(("@CookieMonsterTeam/cookiemonsterframework", "0.2.3"))
    );
    // The npm package named `download`, its tarball and anything else.
    for path in [
        "download",
        "download/-/download-8.0.0.tgz",
        "download/@vendor/a/1.0.0",
        "download/@vendor/a/1.0.0/not-hex",
        "download/@vendor/a//04fef883382f5a7c9b9ac2015dcc419009e2a858",
        "download/@vendor/a/1.0.0/04fef883382f5a7c9b9ac2015dcc419009e2a858/x",
        "download/vendor/a/1.0.0/04fef883382f5a7c9b9ac2015dcc419009e2a858",
        "@vendor/a/-/a-1.0.0.tgz",
    ] {
        assert_eq!(github_packages_tarball(path), None, "{path}");
    }
}

#[test]
fn test_rewrite_tarball_urls_preserves_non_upstream_urls() {
    // homepage and repository.url should NOT be mangled
    let metadata = serde_json::json!({
        "name": "test",
        "homepage": "https://github.com/test/test",
        "repository": { "url": "git+https://github.com/test/test.git" },
        "versions": {
            "1.0.0": {
                "dist": {
                    "tarball": "https://registry.npmjs.org/test/-/test-1.0.0.tgz"
                }
            }
        }
    });
    let data = serde_json::to_vec(&metadata).unwrap();
    let result =
        rewrite_tarball_urls(&data, "http://nora:5000", "https://registry.npmjs.org").unwrap();
    let json: serde_json::Value = serde_json::from_slice(&result).unwrap();
    assert_eq!(json["homepage"], "https://github.com/test/test");
    assert_eq!(
        json["repository"]["url"],
        "git+https://github.com/test/test.git"
    );
}

/// The byte-level safety net rewrites this package's upstream tarball links only:
/// a readme that mentions the upstream registry is not touched.
#[test]
fn rewrite_safety_net_touches_only_tarball_links() {
    let metadata = serde_json::json!({
        "name": "test",
        "readme": "npm config set registry https://registry.npmjs.org/",
        "versions": { "1.0.0": {
            "dist": { "tarball": "https://registry.npmjs.org/test/-/test-1.0.0.tgz" },
            "_resolved": "https://registry.npmjs.org/test/-/test-1.0.0.tgz"
        } }
    });
    let data = serde_json::to_vec(&metadata).unwrap();
    let out =
        rewrite_tarball_urls(&data, "http://nora:5000", "https://registry.npmjs.org/").unwrap();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(json["readme"], metadata["readme"]);
    assert_eq!(
        json["versions"]["1.0.0"]["_resolved"],
        "http://nora:5000/npm/test/-/test-1.0.0.tgz"
    );
}

/// mixin-deep 1.1.0 depends on another package by its upstream tarball URL: npm
/// would fetch it straight from registry.npmjs.org (NoraUpstreamUrlLeak, 13.10).
#[test]
fn rewrite_safety_net_rewrites_foreign_package_tarball_links() {
    let packument = br#"{"name":"mixin-deep","versions":{"1.1.0":{"dependencies":{"is-plain-object":"https://registry.npmjs.org/is-plain-object/-/is-plain-object-2.0.0.tgz","@shopify/generate-docs":"https://registry.npmjs.org/@shopify/generate-docs/-/generate-docs-0.11.1.tgz"},"dist":{"tarball":"https://registry.npmjs.org/mixin-deep/-/mixin-deep-1.1.0.tgz"}}}}"#;
    let out =
        rewrite_tarball_urls(packument, "http://nora:5000", "https://registry.npmjs.org").unwrap();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let deps = &json["versions"]["1.1.0"]["dependencies"];
    assert_eq!(
        deps["is-plain-object"],
        "http://nora:5000/npm/is-plain-object/-/is-plain-object-2.0.0.tgz"
    );
    assert_eq!(
        deps["@shopify/generate-docs"],
        "http://nora:5000/npm/@shopify/generate-docs/-/generate-docs-0.11.1.tgz"
    );
}

/// uuid 0.0.2 keeps an http `dist.bin` tarball on the upstream (13.10 leak).
#[test]
fn rewrite_safety_net_rewrites_http_tarball_links() {
    let packument = br#"{"name":"uuid","versions":{"0.0.2":{"dist":{"bin":{"0.4-sunos-5.11":{"shasum":"2ff8d977261ddadfd1446cee661ab87863659e45","tarball":"http://registry.npmjs.org/uuid/-/uuid-0.0.2-0.4-sunos-5.11.tgz"}},"tarball":"https://registry.npmjs.org/uuid/-/uuid-0.0.2.tgz"}}}}"#;
    let out =
        rewrite_tarball_urls(packument, "http://nora:5000", "https://registry.npmjs.org").unwrap();
    let body = String::from_utf8(out).unwrap();
    assert!(!body.contains("registry.npmjs.org"), "{body}");
    assert!(body.contains("http://nora:5000/npm/uuid/-/uuid-0.0.2-0.4-sunos-5.11.tgz"));
}

/// Mentions of the upstream that are not tarball links stay as they are.
#[test]
fn rewrite_safety_net_leaves_non_tarball_mentions() {
    let metadata = serde_json::json!({
        "name": "test",
        "readme": "see https://registry.npmjs.org/test and https://registry.npmjs.org/-/v1/search",
        "versions": { "1.0.0": {
            "publishConfig": { "registry": "https://registry.npmjs.org/" },
            "dist": { "tarball": "https://registry.npmjs.org/test/-/test-1.0.0.tgz" }
        } }
    });
    let data = serde_json::to_vec(&metadata).unwrap();
    let out =
        rewrite_tarball_urls(&data, "http://nora:5000", "https://registry.npmjs.org").unwrap();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(json["readme"], metadata["readme"]);
    assert_eq!(
        json["versions"]["1.0.0"]["publishConfig"],
        metadata["versions"]["1.0.0"]["publishConfig"]
    );
}

#[test]
fn tarball_path_shapes() {
    for ok in [
        "/a/-/a-1.tgz",
        "/@s/a/-/a-1.tgz",
        "/@s%2fa/-/a-1.tgz",
        "/@s%2Fa/-/a-1.tgz",
    ] {
        assert!(is_tarball_path(ok.as_bytes()), "{ok}");
    }
    for bad in [
        "",
        "/",
        "/a",
        "/a/-/",
        "/-/npm/v1/attestations/a@1",
        "/a/b/-/a.tgz",
        "/@/a/-/a.tgz",
        "/a/-/x/y.tgz",
    ] {
        assert!(!is_tarball_path(bad.as_bytes()), "{bad}");
    }
}

#[test]
fn test_is_valid_attachment_name_valid() {
    assert!(is_valid_attachment_name("package-1.0.0.tgz"));
    assert!(is_valid_attachment_name("@scope-pkg-2.0.tgz"));
    assert!(is_valid_attachment_name("my_pkg.tgz"));
}

#[test]
fn test_is_valid_attachment_name_traversal() {
    assert!(!is_valid_attachment_name("../etc/passwd"));
    assert!(!is_valid_attachment_name("foo/../bar"));
}

#[test]
fn test_is_valid_attachment_name_slash() {
    assert!(!is_valid_attachment_name("path/file.tgz"));
    assert!(!is_valid_attachment_name("path\\file.tgz"));
}

#[test]
fn test_is_valid_attachment_name_null_byte() {
    assert!(!is_valid_attachment_name("file\0.tgz"));
}

#[test]
fn test_is_valid_attachment_name_empty() {
    assert!(!is_valid_attachment_name(""));
}

#[test]
fn test_is_valid_attachment_name_special_chars() {
    assert!(!is_valid_attachment_name("file name.tgz")); // space
    assert!(!is_valid_attachment_name("file;cmd.tgz")); // semicolon
}
