// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::*;

/// What a package's records say of one of its versions, and the list it serves. A hosted
/// package serves exactly the versions it has records of: with the marker and no record it
/// serves none. A key under its prefix that is neither makes nothing hosted.
#[test]
fn a_hosted_package_serves_only_the_versions_it_records() {
    use super::imported::{Version, Versions};
    // listing, hosted, served versions, version asked, what it is
    let rows: [(&[&str], bool, &[&str], &str, Version); 14] = [
        (&[], false, &[], "1.0.0", Version::Proxied),
        (&["1.0.0.json"], true, &["1.0.0"], "1.0.0", Version::Own),
        (&["1.0.0.json"], true, &["1.0.0"], "2.0.0", Version::Foreign),
        (
            &[
                "10.0.0.json",
                "2.0.0-beta.1.json",
                "1.0.0.json",
                "2.0.0.json",
            ],
            true,
            &["1.0.0", "2.0.0-beta.1", "2.0.0", "10.0.0"],
            "2.0.0-beta.1",
            Version::Own,
        ),
        // The marker alone: an import that stopped before the first version was stored.
        (&["imported"], true, &[], "1.0.0", Version::Foreign),
        (
            &["imported", "1.0.0.json"],
            true,
            &["1.0.0"],
            "1.0.0",
            Version::Own,
        ),
        (
            &["importedx", "x/imported"],
            false,
            &[],
            "1.0.0",
            Version::Proxied,
        ),
        (&["1.0.0.txt"], false, &[], "1.0.0", Version::Proxied),
        (&[".json"], false, &[], "", Version::Proxied),
        (&["x/1.0.0.json"], false, &[], "1.0.0", Version::Proxied),
        (
            &["x/1.0.0.json", "2.0.0.json"],
            true,
            &["2.0.0"],
            "1.0.0",
            Version::Foreign,
        ),
        (
            &["1.0.0.json.tmp", "1.0.0.json"],
            true,
            &["1.0.0"],
            "1.0.0.json",
            Version::Foreign,
        ),
        // A stray `.json` key that names no version is no record: not listed, and alone it
        // makes nothing hosted.
        (
            &["10.0.0.json", "latest.json", "2.0.0.json", "1x.json"],
            true,
            &["2.0.0", "10.0.0"],
            "latest",
            Version::Foreign,
        ),
        (&["latest.json"], false, &[], "latest", Version::Proxied),
    ];
    for (names, hosted, listed, version, want) in rows {
        let versions = Versions::from_listing(names.iter().copied());
        assert_eq!(versions.listed(), listed, "{names:?}");
        assert_eq!(versions.hosted(), hosted, "{names:?}");
        assert_eq!(versions.version(version), want, "{names:?} {version}");
    }
    assert!(!Versions::none().hosted());
    assert_eq!(Versions::none().version("1.0.0"), Version::Proxied);
}

/// Stray `.json` keys among many versions: NuGet order between versions and byte order
/// against a non-version is no total order (`2.0.0` < `10.0.0` < `1x` < `2.0.0`), which
/// `sort_by` may answer with a panic. Only versions are listed, in NuGet's order.
#[test]
fn stray_records_among_many_versions_neither_panic_nor_list() {
    let mut names: Vec<String> = Vec::new();
    for major in (1..=40).rev() {
        names.push(format!("{major}.0.0.json"));
        names.push(format!("{major}x.json"));
    }
    names.push("latest.json".to_string());
    let versions = super::imported::Versions::from_listing(names.iter().map(String::as_str));
    let want: Vec<String> = (1..=40).map(|major| format!("{major}.0.0")).collect();
    assert_eq!(versions.listed(), want.as_slice());
}

/// #385: a slash-escaped upstream registration URL must not survive the
/// raw-text rewrite — otherwise the client, after unescaping `\/`, is sent
/// back to the origin past Nora (host leak + air-gap bypass).
#[test]
fn rewrite_nuget_registration_drops_upstream_host_plain_and_escaped() {
    const HOST: &str = "api.nuget.org";
    let upstream = "https://api.nuget.org";
    let base = "http://nora.test";

    let plain = rewrite_registration_urls(
        r#"{"@id":"https://api.nuget.org/v3/registration5-semver1/pkg/index.json"}"#,
        upstream,
        base,
    );
    assert!(
        !plain.contains(HOST),
        "plain registration host leaked: {plain}"
    );

    let escaped = rewrite_registration_urls(
        r#"{"@id":"https:\/\/api.nuget.org\/v3\/registration5-semver1\/pkg\/index.json"}"#,
        upstream,
        base,
    );
    assert!(
        !escaped.contains(HOST),
        "slash-escaped registration host leaked (#385): {escaped}"
    );
}

/// A host that only starts like the upstream's is another origin: its registration and
/// package links are left as they are.
#[test]
fn a_host_that_only_starts_like_the_upstream_is_not_rewritten() {
    let upstream = "https://api.example.org";
    for other in [
        r#"{"@id":"https://api.example.org.evil.net/v3/registration5-semver1/pkg/index.json"}"#,
        r#"{"@id":"https://api.example.org:8443/v3-flatcontainer/pkg/1.0.0/pkg.1.0.0.nupkg"}"#,
        r#"{"@id":"https:\/\/api.example.org.evil.net\/v3-flatcontainer\/pkg\/x.nupkg"}"#,
    ] {
        assert_eq!(
            rewrite_registration_urls(other, upstream, "http://nora.test"),
            other
        );
    }
}

#[test]
fn test_valid_package_ids() {
    assert!(is_valid_package_id("newtonsoft.json"));
    assert!(is_valid_package_id("system.text.json"));
    assert!(is_valid_package_id("microsoft.extensions.logging"));
    assert!(is_valid_package_id("xunit"));
}

#[test]
fn test_invalid_package_ids() {
    assert!(!is_valid_package_id(""));
    assert!(!is_valid_package_id("../evil"));
    assert!(!is_valid_package_id("foo/bar"));
}

#[test]
fn test_strip_url_path_with_index_json() {
    assert_eq!(
        strip_url_path("https://api.nuget.org/v3/index.json"),
        "https://api.nuget.org"
    );
}

#[test]
fn test_strip_url_path_no_path() {
    assert_eq!(
        strip_url_path("https://api.nuget.org"),
        "https://api.nuget.org"
    );
}

#[test]
fn test_strip_url_path_trailing_slash() {
    assert_eq!(
        strip_url_path("https://api.nuget.org/"),
        "https://api.nuget.org"
    );
}

#[test]
fn test_strip_url_path_custom_port() {
    assert_eq!(
        strip_url_path("https://artifact.company.local:8443/nuget/v3/index.json"),
        "https://artifact.company.local:8443"
    );
}

#[test]
fn test_strip_url_path_http() {
    assert_eq!(
        strip_url_path("http://localhost:4000/nuget/v3/index.json"),
        "http://localhost:4000"
    );
}

#[test]
fn test_generate_service_index_http() {
    let result = generate_service_index("http://nora:4000");
    let json: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert_eq!(json["version"], "3.0.0");
    let resources = json["resources"].as_array().unwrap();
    assert_eq!(resources.len(), 16);
    assert!(result.contains("http://nora:4000/nuget/v3/flatcontainer/"));
    assert!(result.contains("http://nora:4000/nuget/v3/registration/"));
    assert!(result.contains("http://nora:4000/nuget/v3/query"));
    assert!(result.contains("http://nora:4000/nuget/v3/autocomplete"));
}

#[test]
fn test_generate_service_index_https() {
    let result = generate_service_index("https://artifact.company.local");
    assert!(result.contains("https://artifact.company.local/nuget/v3/flatcontainer/"));
    assert!(result.contains("https://artifact.company.local/nuget/v3/registration/"));
    assert!(!result.contains("http://artifact.company.local"));
}

#[test]
fn test_generate_service_index_no_upstream_urls() {
    let result = generate_service_index("http://nora:4000");
    assert!(!result.contains("api.nuget.org"));
    assert!(!result.contains("azuresearch-usnc.nuget.org"));
    assert!(!result.contains("azuresearch-ussc.nuget.org"));
    assert!(!result.contains("www.nuget.org"));
    assert!(!result.contains("nuget.org"));
}

#[test]
fn test_generate_service_index_only_implemented_resources() {
    let result = generate_service_index("http://nora:4000");
    let json: serde_json::Value = serde_json::from_str(&result).unwrap();
    let types: Vec<&str> = json["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["@type"].as_str().unwrap())
        .collect();
    assert!(types.contains(&"PackageBaseAddress/3.0.0"));
    assert!(types.contains(&"RegistrationsBaseUrl/3.6.0"));
    assert!(types.contains(&"SearchQueryService"));
    assert!(types.contains(&"SearchAutocompleteService"));
    assert!(types.contains(&"SearchQueryService/3.5.0"));
    assert!(types.contains(&"PackagePublish/2.0.0"));
    // Must NOT include unimplemented resources
    assert!(!types.iter().any(|t| t.contains("Catalog")));
    assert!(!types.iter().any(|t| t.contains("RepositorySignatures")));
    assert!(!types.iter().any(|t| t.contains("Vulnerability")));
}

#[test]
fn test_generate_service_index_registration_aliases() {
    let result = generate_service_index("http://nora:4000");
    let json: serde_json::Value = serde_json::from_str(&result).unwrap();
    let resources = json["resources"].as_array().unwrap();
    for t in [
        "RegistrationsBaseUrl",
        "RegistrationsBaseUrl/3.0.0-beta",
        "RegistrationsBaseUrl/3.0.0-rc",
        "RegistrationsBaseUrl/3.4.0",
        "RegistrationsBaseUrl/3.6.0",
        "RegistrationsBaseUrl/Versioned",
    ] {
        let r = resources
            .iter()
            .find(|r| r["@type"] == t)
            .unwrap_or_else(|| panic!("{t} missing"));
        let hive = match t {
            "RegistrationsBaseUrl/3.4.0" => "registration-gz-semver1",
            "RegistrationsBaseUrl/3.6.0" | "RegistrationsBaseUrl/Versioned" => "registration",
            _ => "registration-semver1",
        };
        assert_eq!(
            r["@id"],
            format!("http://nora:4000/nuget/v3/{hive}/"),
            "{t}"
        );
    }
    let versioned = resources
        .iter()
        .find(|r| r["@type"] == "RegistrationsBaseUrl/Versioned")
        .unwrap();
    assert_eq!(versioned["clientVersion"], "4.3.0-alpha");
}

/// The ordered @type lists of `NuGet.Protocol.ServiceTypes` in 6.3.4 (pulled by
/// Microsoft.CodeAnalysis.Testing 1.1.3) and on NuGet.Client `dev`: the client takes the
/// first type it finds, so each list must hit at least one resource of the index.
#[test]
fn test_generate_service_index_resolves_for_old_and_new_nuget_clients() {
    let result = generate_service_index("http://nora:4000");
    let json: serde_json::Value = serde_json::from_str(&result).unwrap();
    let types: Vec<&str> = json["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["@type"].as_str().unwrap())
        .collect();
    let client_lists: [(&str, &[&str]); 9] = [
        (
            "6.3.4 RegistrationsBaseUrl",
            &[
                "RegistrationsBaseUrl/Versioned",
                "RegistrationsBaseUrl/3.4.0",
                "RegistrationsBaseUrl/3.0.0-beta",
            ],
        ),
        (
            "dev RegistrationsBaseUrl",
            &[
                "RegistrationsBaseUrl/Versioned",
                "RegistrationsBaseUrl/3.6.0",
                "RegistrationsBaseUrl/3.4.0",
                "RegistrationsBaseUrl/3.0.0-rc",
                "RegistrationsBaseUrl/3.0.0-beta",
                "RegistrationsBaseUrl",
            ],
        ),
        (
            "SearchQueryService",
            &[
                "SearchQueryService/Versioned",
                "SearchQueryService/3.4.0",
                "SearchQueryService/3.0.0-beta",
            ],
        ),
        (
            "SearchAutocompleteService",
            &[
                "SearchAutocompleteService/Versioned",
                "SearchAutocompleteService/3.0.0-beta",
            ],
        ),
        (
            "PackageBaseAddress",
            &["PackageBaseAddress/Versioned", "PackageBaseAddress/3.0.0"],
        ),
        (
            "PackagePublish",
            &["PackagePublish/Versioned", "PackagePublish/2.0.0"],
        ),
        ("dev SearchQueryService350", &["SearchQueryService/3.5.0"]),
        (
            "6.3.4 RegistrationsBaseUrl/3.4.0 only",
            &["RegistrationsBaseUrl/3.4.0"],
        ),
        (
            "6.3.4 RegistrationsBaseUrl/3.0.0-beta only",
            &["RegistrationsBaseUrl/3.0.0-beta"],
        ),
    ];
    for (name, list) in client_lists {
        assert!(
            list.iter().any(|t| types.contains(t)),
            "{name}: none of {list:?} in the index"
        );
    }
}

#[test]
fn test_generate_service_index_trailing_slash() {
    let result = generate_service_index("http://nora:4000/");
    // Should not produce double slashes
    assert!(!result.contains("http://nora:4000//"));
    assert!(result.contains("http://nora:4000/nuget/v3/flatcontainer/"));
}

#[test]
fn test_rewrite_registration_urls_all_variants() {
    let input = r#"{"items":[{"@id":"https://api.nuget.org/v3/registration5-gz-semver2/foo/page/1.0.0/2.0.0.json"},{"@id":"https://api.nuget.org/v3/registration5-semver1/foo/index.json"},{"@id":"https://api.nuget.org/v3/registration5-gz-semver1/foo/page/1.0.0/2.0.0.json"}]}"#;
    let result = rewrite_registration_urls(input, "https://api.nuget.org", "http://nora:4000");
    assert!(!result.contains("api.nuget.org"));
    assert!(result.contains("http://nora:4000/nuget/v3/registration/foo/page/1.0.0/2.0.0.json"));
    assert!(result.contains("http://nora:4000/nuget/v3/registration/foo/index.json"));
}

#[test]
fn test_rewrite_registration_urls_rewrites_flatcontainer() {
    let input =
        r#"{"packageContent":"https://api.nuget.org/v3-flatcontainer/foo/1.0.0/foo.1.0.0.nupkg"}"#;
    let result = rewrite_registration_urls(input, "https://api.nuget.org", "http://nora:4000");
    assert!(!result.contains("api.nuget.org/v3-flatcontainer"));
    assert!(result.contains("http://nora:4000/nuget/v3/flatcontainer/foo/1.0.0/foo.1.0.0.nupkg"));
}

#[test]
fn test_rewrite_registration_urls_custom_upstream() {
    let input =
        r#"{"@id":"https://private.registry.corp/v3/registration5-gz-semver2/bar/index.json"}"#;
    let result =
        rewrite_registration_urls(input, "https://private.registry.corp", "http://nora:4000");
    assert!(!result.contains("private.registry.corp"));
    assert!(result.contains("http://nora:4000/nuget/v3/registration/bar/index.json"));
}

/// Deprecation fields survive URL rewriting — catalog0 @ids left as-is (#424)
#[test]
fn test_rewrite_preserves_deprecation_field() {
    let input = r#"{"items":[{"catalogEntry":{"@id":"https://api.nuget.org/v3/catalog0/data/2024.09.20/ef.4.1.json","version":"4.1.10311","deprecation":{"@id":"https://api.nuget.org/v3/catalog0/data/2024.09.20/ef.4.1.json#deprecation","@type":"deprecation","alternatePackage":{"@id":"https://api.nuget.org/v3/catalog0/data/2024.09.20/ef.4.1.json#deprecation/alternatePackage","@type":"alternatePackage","id":"EntityFramework","range":"[6.5.1, )"},"reasons":["Legacy"]},"packageContent":"https://api.nuget.org/v3-flatcontainer/entityframework/4.1.10311/entityframework.4.1.10311.nupkg"}}]}"#;
    let result = rewrite_registration_urls(input, "https://api.nuget.org", "http://nora:4000");
    // deprecation block preserved intact (catalog0 URLs stay as-is)
    assert!(result.contains(r#""deprecation":{""#));
    assert!(result.contains(r#""reasons":["Legacy"]"#));
    assert!(result.contains(r#""id":"EntityFramework""#));
    assert!(result.contains("https://api.nuget.org/v3/catalog0/data/2024.09.20"));
    assert!(!result.contains("nora:4000/nuget/v3/catalog0"));
    // packageContent rewritten to Nora
    assert!(result.contains("http://nora:4000/nuget/v3/flatcontainer/"));
}

/// Vulnerabilities array survives URL rewriting (#424)
#[test]
fn test_rewrite_preserves_vulnerabilities_field() {
    let input = r#"{"items":[{"catalogEntry":{"@id":"https://api.nuget.org/v3/catalog0/data/2024.01.01/log4net.1.2.10.json","version":"1.2.10","vulnerabilities":[{"advisoryUrl":"https://github.com/advisories/GHSA-2cwj-8chv-9pp9","severity":"3"},{"advisoryUrl":"https://github.com/advisories/GHSA-4f7c-pmjv-c25w","severity":"1"}],"packageContent":"https://api.nuget.org/v3-flatcontainer/log4net/1.2.10/log4net.1.2.10.nupkg"}}]}"#;
    let result = rewrite_registration_urls(input, "https://api.nuget.org", "http://nora:4000");
    // vulnerabilities array preserved intact (external advisory URLs, not upstream registry)
    assert!(result.contains(r#""vulnerabilities":[{"#));
    assert!(result.contains("GHSA-2cwj-8chv-9pp9"));
    assert!(result.contains("GHSA-4f7c-pmjv-c25w"));
    assert!(result.contains(r#""severity":"3""#));
    assert!(result.contains(r#""advisoryUrl":"https://github.com/advisories/"#));
    // packageContent rewritten to Nora
    assert!(result.contains("http://nora:4000/nuget/v3/flatcontainer/"));
}

#[test]
fn test_valid_versions() {
    assert!(is_valid_version("1.0.0"));
    assert!(is_valid_version("1.0.0-alpha"));
    assert!(is_valid_version("1.0.0-beta.1"));
    assert!(is_valid_version("1.0.0+build.123"));
    assert!(is_valid_version("0.0.1-alpha"));
    assert!(is_valid_version("3.1.27"));
}

#[test]
fn test_invalid_versions() {
    assert!(!is_valid_version(""));
    assert!(!is_valid_version("../evil"));
    assert!(!is_valid_version("1.0.0/../../etc/passwd"));
    assert!(!is_valid_version("foo\0bar"));
    assert!(!is_valid_version("1..0"));
    assert!(!is_valid_version("1.0.0\\evil"));
}

#[test]
fn test_is_semver2_version() {
    // SemVer 2.0: dot-separated pre-release identifiers
    assert!(is_semver2_version("1.0.0-rc.1"));
    assert!(is_semver2_version("9.0.0-rc.1.24431.7"));
    assert!(is_semver2_version("1.0.0-beta.2.3"));

    // SemVer 2.0: build metadata
    assert!(is_semver2_version("1.0.0+build"));
    assert!(is_semver2_version("1.0.0-alpha+001"));

    // SemVer 1.0: simple pre-release (no dots after hyphen)
    assert!(!is_semver2_version("1.0.0-alpha"));
    assert!(!is_semver2_version("1.0.0-beta1"));
    assert!(!is_semver2_version("2.0.0-preview"));

    // Stable versions: not SemVer 2.0
    assert!(!is_semver2_version("1.0.0"));
    assert!(!is_semver2_version("13.0.3"));
}

#[test]
fn test_registration_returns_gzip_content_encoding() {
    let resp = with_json_gzip(br#"{"count":1}"#.to_vec());
    let (parts, body) = resp.into_parts();
    assert_eq!(parts.status, StatusCode::OK);
    assert_eq!(
        parts.headers.get("content-encoding").map(|v| v.as_bytes()),
        Some(b"gzip".as_slice()),
    );
    assert_eq!(
        parts.headers.get("content-type").map(|v| v.as_bytes()),
        Some(b"application/json".as_slice()),
    );

    // Decompress body and verify round-trip
    use axum::body::Body;
    use flate2::read::GzDecoder;
    use std::io::Read;

    let body_bytes =
        futures::executor::block_on(axum::body::to_bytes(Body::new(body), 1 << 20)).unwrap();
    let mut decoder = GzDecoder::new(&body_bytes[..]);
    let mut decompressed = String::new();
    decoder.read_to_string(&mut decompressed).unwrap();
    assert_eq!(decompressed, r#"{"count":1}"#);
}

#[test]
fn test_service_index_no_gzip() {
    let resp = with_json(br#"{"version":"3.0.0"}"#.to_vec());
    let (parts, _body) = resp.into_parts();
    assert!(
        parts.headers.get("content-encoding").is_none(),
        "service index (with_json) must NOT have Content-Encoding header"
    );
}
