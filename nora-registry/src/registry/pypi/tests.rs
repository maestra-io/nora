// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::*;
use proptest::prelude::*;

/// The resolved URL and lower-cased `#sha256=` of `target` in an upstream index page.
fn find_file_url(html: &str, target: &str, page_url: &str) -> Option<(String, Option<String>)> {
    parse_upstream_files(html, page_url)
        .into_iter()
        .find(|f| f.filename == target)
        .map(|f| (f.url.unwrap(), f.sha256.map(|h| h.to_ascii_lowercase())))
}

fn find_url(html: &str, target: &str, page_url: &str) -> Option<String> {
    find_file_url(html, target, page_url).map(|(url, _)| url)
}

/// What a project's records say of one of its files. A hosted project owns only the files it
/// has a record of: with the marker and no record at all it owns none, so a file an upstream
/// served under the name is neither listed nor served. Without the marker nothing is decided
/// by the records.
#[test]
fn a_hosted_project_owns_only_the_files_it_records() {
    use super::own::{File, Records};
    let rows: [(&[&str], bool, &str, File); 11] = [
        (&[], false, "a-1.0.whl", File::Proxied),
        (&["imported"], true, "a-1.0.whl", File::Foreign),
        (
            &["imported", "files/a-1.0.whl"],
            true,
            "a-1.0.whl",
            File::Own,
        ),
        (
            &["imported", "files/a-1.0.whl"],
            true,
            "a-2.0.whl",
            File::Foreign,
        ),
        (&["files/a-1.0.whl"], false, "a-1.0.whl", File::Proxied),
        (&["files/a-1.0.whl"], false, "a-2.0.whl", File::Proxied),
        (
            &["importedx", "files/a-1.0.whl"],
            false,
            "a-2.0.whl",
            File::Proxied,
        ),
        (
            &["imported/x", "x/imported"],
            false,
            "a-1.0.whl",
            File::Proxied,
        ),
        (
            &["imported", "files/A-1.0.whl"],
            true,
            "a-1.0.whl",
            File::Foreign,
        ),
        (
            &["imported", "files/a-1.0.whl.sha256"],
            true,
            "a-1.0.whl",
            File::Foreign,
        ),
        (&["imported", "a-1.0.whl"], true, "a-1.0.whl", File::Foreign),
    ];
    for (names, hosted, file, want) in rows {
        let records = Records::from_listing(names.iter().copied());
        assert_eq!(records.hosted(), hosted, "{names:?}");
        assert_eq!(records.file(file), want, "{names:?} {file}");
    }
    assert!(!Records::none().hosted());
    assert_eq!(Records::none().file("a-1.0.whl"), File::Proxied);
}

proptest! {
    #[test]
    fn extract_filename_never_panics(s in "\\PC{0,500}") {
        let _ = extract_filename(&s);
    }

    #[test]
    fn extract_filename_valid_tarball(
        name in "[a-z][a-z0-9_-]{0,20}",
        version in "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"
    ) {
        let url = format!("https://files.example.com/packages/{}-{}.tar.gz", name, version);
        let result = extract_filename(&url);
        prop_assert!(result.is_some());
        prop_assert!(result.unwrap().ends_with(".tar.gz"));
    }

    #[test]
    fn extract_filename_valid_wheel(
        name in "[a-z][a-z0-9_]{0,20}",
        version in "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"
    ) {
        let url = format!("https://files.example.com/{}-{}-py3-none-any.whl", name, version);
        let result = extract_filename(&url);
        prop_assert!(result.is_some());
        prop_assert!(result.unwrap().ends_with(".whl"));
    }

    #[test]
    fn extract_filename_strips_hash(
        name in "[a-z]{1,10}",
        hash in "[a-f0-9]{64}"
    ) {
        let url = format!("https://example.com/{}.tar.gz#sha256={}", name, hash);
        let result = extract_filename(&url);
        prop_assert!(result.is_some());
        let fname = result.unwrap();
        prop_assert!(!fname.contains('#'));
    }

    #[test]
    fn extract_filename_rejects_unknown_ext(
        name in "[a-z]{1,10}",
        ext in "(exe|dll|so|bin|dat)"
    ) {
        let url = format!("https://example.com/{}.{}", name, ext);
        prop_assert!(extract_filename(&url).is_none());
    }
}

#[test]
fn test_normalize_name_lowercase() {
    assert_eq!(normalize_name("Flask"), "flask");
    assert_eq!(normalize_name("REQUESTS"), "requests");
}

#[test]
fn same_origin_compares_scheme_host_and_port() {
    assert!(super::same_origin(
        "https://pypi.corp/files/a.whl",
        "https://pypi.corp/simple/"
    ));
    assert!(super::same_origin(
        "https://pypi.corp:443/x",
        "https://pypi.corp/"
    ));
    assert!(!super::same_origin(
        "https://files.example/x",
        "https://pypi.corp/"
    ));
    // A host is compared whole: a name ending in the upstream's, or extending it, is another.
    assert!(!super::same_origin(
        "https://evilpypi.corp/x",
        "https://pypi.corp/"
    ));
    assert!(!super::same_origin(
        "https://pypi.corp.evil/x",
        "https://pypi.corp/"
    ));
    assert!(!super::same_origin("https://a.corp/x", "https://b.corp/"));
    assert!(!super::same_origin(
        "https://cdn.pypi.corp/x",
        "https://pypi.corp/"
    ));
    assert!(!super::same_origin(
        "https://pypi.corp/x",
        "https://cdn.pypi.corp/"
    ));
    assert!(!super::same_origin(
        "http://pypi.corp/x",
        "https://pypi.corp/"
    ));
    assert!(!super::same_origin(
        "https://pypi.corp:8443/x",
        "https://pypi.corp/"
    ));
    assert!(!super::same_origin(
        "https://pypi.corp.evil/x",
        "https://pypi.corp/"
    ));
    assert!(!super::same_origin("not a url", "https://pypi.corp/"));
}

#[test]
fn find_file_url_matches_percent_encoded_plus() {
    // #664: PyTorch indexes encode '+' as %2B in hrefs, but the requested
    // filename arrives decoded — matching must decode, and the returned URL
    // must stay encoded so the upstream fetch resolves.
    let html = concat!(
        r#"<a href="https://download.pytorch.org/whl/cu124/"#,
        r#"torch-2.4.0%2Bcu124-cp310-cp310-linux_x86_64.whl#sha256=abc">"#,
        r#"torch-2.4.0+cu124-cp310-cp310-linux_x86_64.whl</a>"#,
    );
    assert_eq!(
        find_url(html, "torch-2.4.0+cu124-cp310-cp310-linux_x86_64.whl", "https://pypi.org/simple/torch/").as_deref(),
        Some(
            "https://download.pytorch.org/whl/cu124/torch-2.4.0%2Bcu124-cp310-cp310-linux_x86_64.whl"
        )
    );
    // A plain filename (no encoding) still matches.
    let plain = r#"<a href="https://x/torch-0.1.10-cp36-cp36m-macosx.whl">x</a>"#;
    assert_eq!(
        find_url(
            plain,
            "torch-0.1.10-cp36-cp36m-macosx.whl",
            "https://pypi.org/simple/torch/"
        )
        .as_deref(),
        Some("https://x/torch-0.1.10-cp36-cp36m-macosx.whl")
    );
}

#[test]
fn test_normalize_name_separators() {
    assert_eq!(normalize_name("my-package"), "my-package");
    assert_eq!(normalize_name("my_package"), "my-package");
    assert_eq!(normalize_name("my.package"), "my-package");
}

#[test]
fn test_normalize_name_mixed() {
    assert_eq!(
        normalize_name("My_Complex.Package-Name"),
        "my-complex-package-name"
    );
}

#[test]
fn test_normalize_name_empty() {
    assert_eq!(normalize_name(""), "");
}

#[test]
fn test_normalize_name_already_normal() {
    assert_eq!(normalize_name("simple"), "simple");
}

#[test]
fn test_extract_filename_tarball() {
    assert_eq!(
        extract_filename(
            "https://files.pythonhosted.org/packages/aa/bb/flask-2.0.0.tar.gz#sha256=abc123"
        ),
        Some("flask-2.0.0.tar.gz")
    );
}

#[test]
fn test_extract_filename_wheel() {
    assert_eq!(
        extract_filename(
            "https://files.pythonhosted.org/packages/aa/bb/flask-2.0.0-py3-none-any.whl"
        ),
        Some("flask-2.0.0-py3-none-any.whl")
    );
}

#[test]
fn test_extract_filename_tgz() {
    assert_eq!(
        extract_filename("https://example.com/package-1.0.tgz"),
        Some("package-1.0.tgz")
    );
}

#[test]
fn test_extract_filename_zip() {
    assert_eq!(
        extract_filename("https://example.com/package-1.0.zip"),
        Some("package-1.0.zip")
    );
}

#[test]
fn test_extract_filename_egg() {
    assert_eq!(
        extract_filename("https://example.com/package-1.0.egg"),
        Some("package-1.0.egg")
    );
}

#[test]
fn test_extract_filename_unknown_ext() {
    assert_eq!(extract_filename("https://example.com/readme.txt"), None);
}

#[test]
fn test_extract_filename_no_path() {
    assert_eq!(extract_filename(""), None);
}

#[test]
fn test_extract_filename_bare() {
    assert_eq!(
        extract_filename("package-1.0.tar.gz"),
        Some("package-1.0.tar.gz")
    );
}

#[test]
fn test_find_file_url_found() {
    let html = r#"<a href="https://files.pythonhosted.org/packages/aa/bb/flask-2.0.tar.gz#sha256=abc">flask-2.0.tar.gz</a>"#;
    let result = find_url(html, "flask-2.0.tar.gz", "https://pypi.org/simple/flask/");
    assert_eq!(
        result,
        Some("https://files.pythonhosted.org/packages/aa/bb/flask-2.0.tar.gz".to_string())
    );
}

#[test]
fn test_find_file_url_not_found() {
    let html = r#"<a href="https://example.com/other-1.0.tar.gz">other</a>"#;
    let result = find_url(html, "flask-2.0.tar.gz", "https://pypi.org/simple/flask/");
    assert_eq!(result, None);
}

#[test]
fn test_find_file_url_strips_hash() {
    let html = r#"<a href="https://example.com/pkg-1.0.whl#sha256=DEADBEEF">pkg</a>"#;
    let result = find_url(html, "pkg-1.0.whl", "https://pypi.org/simple/pkg/");
    assert_eq!(result, Some("https://example.com/pkg-1.0.whl".to_string()));
    let (_, sha256) = find_file_url(html, "pkg-1.0.whl", "https://pypi.org/simple/pkg/").unwrap();
    assert_eq!(sha256.as_deref(), Some("deadbeef"));
}

// -- #877: relative URL resolution --

#[test]
fn test_find_file_url_relative() {
    let html = r#"<a href="../../packages/torch-2.4.0.whl#sha256=abc">torch-2.4.0.whl</a>"#;
    let result = find_url(
        html,
        "torch-2.4.0.whl",
        "https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple/torch/",
    );
    assert_eq!(
        result,
        Some("https://mirrors.tuna.tsinghua.edu.cn/pypi/web/packages/torch-2.4.0.whl".to_string())
    );
}

#[test]
fn test_find_file_url_absolute_unchanged() {
    let html =
        r#"<a href="https://files.pythonhosted.org/packages/ab/cd/pkg-1.0.whl">pkg-1.0.whl</a>"#;
    let result = find_url(
        html,
        "pkg-1.0.whl",
        "https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple/pkg/",
    );
    assert_eq!(
        result,
        Some("https://files.pythonhosted.org/packages/ab/cd/pkg-1.0.whl".to_string())
    );
}

#[test]
fn test_find_file_url_path_only() {
    let html = r#"<a href="/packages/pkg-1.0.whl#sha256=ff">pkg-1.0.whl</a>"#;
    let result = find_url(html, "pkg-1.0.whl", "https://pypi.example.com/simple/pkg/");
    assert_eq!(
        result,
        Some("https://pypi.example.com/packages/pkg-1.0.whl".to_string())
    );
}

#[test]
fn test_is_valid_pypi_filename() {
    assert!(is_valid_pypi_filename("flask-2.0.tar.gz"));
    assert!(is_valid_pypi_filename("flask-2.0-py3-none-any.whl"));
    assert!(is_valid_pypi_filename("flask-2.0.tgz"));
    assert!(is_valid_pypi_filename("flask-2.0.zip"));
    assert!(is_valid_pypi_filename("flask-2.0.egg"));
    assert!(!is_valid_pypi_filename(""));
    assert!(!is_valid_pypi_filename("../evil.tar.gz"));
    assert!(!is_valid_pypi_filename("evil/path.tar.gz"));
    assert!(!is_valid_pypi_filename("noext"));
    assert!(!is_valid_pypi_filename("bad.exe"));
}

#[test]
fn test_wants_json_pep691() {
    let mut headers = HeaderMap::new();
    headers.insert(header::ACCEPT, PEP691_JSON.parse().unwrap());
    assert!(wants_json(&headers));
}

#[test]
fn test_wants_json_html() {
    let mut headers = HeaderMap::new();
    headers.insert(header::ACCEPT, "text/html".parse().unwrap());
    assert!(!wants_json(&headers));
}

#[test]
fn test_wants_json_no_header() {
    let headers = HeaderMap::new();
    assert!(!wants_json(&headers));
}

// --- parse_upstream_files ---

#[test]
fn test_parse_upstream_files_basic() {
    let html = r#"<a href="https://files.example.com/pkg-1.0-cp310-cp310-linux_x86_64.whl#sha256=aaa">pkg</a>
<a href="https://files.example.com/pkg-1.0-cp314-cp314-linux_x86_64.whl#sha256=bbb">pkg</a>"#;
    let files = parse_upstream_files(html, "https://pypi.org/simple/x/");
    assert_eq!(files.len(), 2);
    assert_eq!(files[0].filename, "pkg-1.0-cp310-cp310-linux_x86_64.whl");
    assert_eq!(files[0].sha256.as_deref(), Some("aaa"));
    assert_eq!(files[1].filename, "pkg-1.0-cp314-cp314-linux_x86_64.whl");
    assert_eq!(files[1].sha256.as_deref(), Some("bbb"));
}

/// R4-R18: what private indexes and mirrors write: single-quoted and escaped hrefs, a
/// signed URL's query, a bare `data-yanked`.
#[test]
fn test_parse_upstream_files_of_other_indexes() {
    let html = r#"<a href='https://m.example/p/pkg-1.0.tar.gz#sha256=aaa' data-requires-python='&gt;=3.8'>pkg</a>
<a href="https://m.example/p/pkg-2.0-py3-none-any.whl?sig=a%2Fb&amp;exp=1#sha256=bbb" data-yanked>pkg</a>
<a href="pkg-3.0.tar.gz" data-yanked="it's broken">pkg</a>
<a href="pkg-4.0.tar.gz" xdata-yanked>pkg</a>"#;
    let files = parse_upstream_files(html, "https://m.example/simple/pkg/");
    let names: Vec<&str> = files.iter().map(|f| f.filename.as_str()).collect();
    assert_eq!(
        names,
        [
            "pkg-1.0.tar.gz",
            "pkg-2.0-py3-none-any.whl",
            "pkg-3.0.tar.gz",
            "pkg-4.0.tar.gz"
        ]
    );
    assert_eq!(files[0].sha256.as_deref(), Some("aaa"));
    assert_eq!(files[0].requires_python.as_deref(), Some(">=3.8"));
    assert_eq!(files[0].yanked, None);
    assert_eq!(
        files[1].url.as_deref(),
        Some("https://m.example/p/pkg-2.0-py3-none-any.whl?sig=a%2Fb&exp=1")
    );
    assert_eq!(files[1].sha256.as_deref(), Some("bbb"));
    assert_eq!(files[1].yanked.as_deref(), Some(""));
    assert_eq!(files[2].yanked.as_deref(), Some("it's broken"));
    assert_eq!(
        files[2].url.as_deref(),
        Some("https://m.example/simple/pkg/pkg-3.0.tar.gz")
    );
    assert_eq!(files[3].yanked, None);
}

#[test]
fn test_parse_upstream_files_no_hash() {
    let html = r#"<a href="https://example.com/pkg-1.0.tar.gz">pkg</a>"#;
    let files = parse_upstream_files(html, "https://pypi.org/simple/x/");
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].filename, "pkg-1.0.tar.gz");
    assert!(files[0].sha256.is_none());
}

#[test]
fn test_parse_upstream_files_empty() {
    assert!(parse_upstream_files("", "https://pypi.org/simple/x/").is_empty());
    assert!(
        parse_upstream_files("<html><body></body></html>", "https://pypi.org/simple/x/").is_empty()
    );
}

#[test]
fn test_parse_upstream_files_skips_non_package_links() {
    let html = r#"<a href="https://example.com/readme.txt">readme</a>
<a href="https://example.com/pkg-1.0.whl#sha256=abc">pkg</a>"#;
    let files = parse_upstream_files(html, "https://pypi.org/simple/x/");
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].filename, "pkg-1.0.whl");
}

// --- merge_file_lists ---

#[test]
fn test_merge_disjoint() {
    let upstream = vec![FileEntry {
        filename: "pkg-1.0-cp314-cp314-linux_x86_64.whl".to_string(),
        sha256: Some("uuu".to_string()),
        ..Default::default()
    }];
    let local = vec![FileEntry {
        filename: "pkg-1.0-cp310-cp310-linux_x86_64.whl".to_string(),
        sha256: Some("lll".to_string()),
        ..Default::default()
    }];
    let merged = merge_file_lists(upstream, &local);
    assert_eq!(merged.len(), 2);
    // Local first
    assert_eq!(merged[0].filename, "pkg-1.0-cp310-cp310-linux_x86_64.whl");
    assert_eq!(merged[1].filename, "pkg-1.0-cp314-cp314-linux_x86_64.whl");
}

#[test]
fn test_merge_local_wins_on_duplicate() {
    let upstream = vec![FileEntry {
        filename: "pkg-1.0.tar.gz".to_string(),
        sha256: Some("upstream-hash".to_string()),
        ..Default::default()
    }];
    let local = vec![FileEntry {
        filename: "pkg-1.0.tar.gz".to_string(),
        sha256: Some("local-verified-hash".to_string()),
        ..Default::default()
    }];
    let merged = merge_file_lists(upstream, &local);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].sha256.as_deref(), Some("local-verified-hash"));
}

#[test]
fn test_merge_empty_upstream() {
    let local = vec![FileEntry {
        filename: "pkg-1.0.tar.gz".to_string(),
        sha256: None,
        ..Default::default()
    }];
    let merged = merge_file_lists(vec![], &local);
    assert_eq!(merged.len(), 1);
}

#[test]
fn test_merge_empty_local() {
    let upstream = vec![FileEntry {
        filename: "pkg-1.0.tar.gz".to_string(),
        sha256: Some("hash".to_string()),
        ..Default::default()
    }];
    let merged = merge_file_lists(upstream, &[]);
    assert_eq!(merged.len(), 1);
}

#[test]
fn test_merge_both_empty() {
    let merged = merge_file_lists(vec![], &[]);
    assert!(merged.is_empty());
}

#[test]
fn test_merge_first_upstream_wins_and_dedups() {
    // Multi-upstream (#663): `upstream` is the upstreams concatenated in
    // precedence order. The same filename from upstream A (first) and B must
    // be deduped to a single entry, and A wins.
    let upstream = vec![
        FileEntry {
            filename: "torch-1.0.whl".to_string(),
            sha256: Some("from-A".to_string()),
            ..Default::default()
        },
        FileEntry {
            filename: "torch-1.0.whl".to_string(),
            sha256: Some("from-B".to_string()),
            ..Default::default()
        },
        FileEntry {
            filename: "torchvision-1.0.whl".to_string(),
            sha256: Some("from-B".to_string()),
            ..Default::default()
        },
    ];
    let merged = merge_file_lists(upstream, &[]);
    assert_eq!(
        merged.len(),
        2,
        "duplicate filename across upstreams deduped"
    );
    let torch = merged
        .iter()
        .find(|f| f.filename == "torch-1.0.whl")
        .unwrap();
    assert_eq!(
        torch.sha256.as_deref(),
        Some("from-A"),
        "first upstream (A) wins precedence"
    );
    assert!(merged.iter().any(|f| f.filename == "torchvision-1.0.whl"));
}

proptest! {
    #[test]
    fn prop_merge_no_duplicate_filenames_and_local_wins(
        upstream_names in prop::collection::vec("[a-z]{1,6}", 0..20),
        local_names in prop::collection::vec("[a-z]{1,6}", 0..6),
    ) {
        let upstream: Vec<FileEntry> = upstream_names
            .iter()
            .map(|n| FileEntry { filename: n.clone(), sha256: None, ..Default::default() })
            .collect();
        let local: Vec<FileEntry> = local_names
            .iter()
            .map(|n| FileEntry { filename: n.clone(), sha256: Some("L".to_string()), ..Default::default() })
            .collect();
        let merged = merge_file_lists(upstream, &local);
        // No filename appears twice.
        let mut seen = std::collections::HashSet::new();
        for f in &merged {
            prop_assert!(seen.insert(f.filename.clone()), "duplicate filename in merge");
        }
        // Every local file survives, and local wins on collision.
        for ln in &local_names {
            let e = merged.iter().find(|f| &f.filename == ln);
            prop_assert!(e.is_some());
            prop_assert_eq!(e.unwrap().sha256.as_deref(), Some("L"));
        }
    }
}

// --- PEP 503 / 592 attributes on the proxied index ---

#[test]
fn test_normalize_name_collapses_separator_runs() {
    assert_eq!(normalize_name("foo__bar"), "foo-bar");
    assert_eq!(normalize_name("Foo.-Bar"), "foo-bar");
    assert_eq!(normalize_name("a._-b"), "a-b");
    assert_eq!(normalize_name("zope.interface"), "zope-interface");
}

#[test]
fn test_parse_upstream_files_keeps_requires_python_and_yanked() {
    let html = concat!(
        r#"<a href="https://f/pkg-1.0.tar.gz#sha256=aa" data-requires-python="&gt;=3.8,&lt;4">pkg-1.0.tar.gz</a>"#,
        "\n",
        r#"<a data-yanked="" href="https://f/pkg-1.1.tar.gz#sha256=bb">pkg-1.1.tar.gz</a>"#,
        "\n",
        r#"<a href="https://f/pkg-1.2.tar.gz" data-yanked="broken &amp; bad">pkg-1.2.tar.gz</a>"#,
        "\n",
        r#"<a href="https://f/torch-2.4.0%2Bcu124-cp310-none-any.whl">x</a>"#,
        "\n",
        r#"<a data-requires-python="<4" href="https://f/pkg-2.0.tar.gz" data-yanked=">old">x</a>"#,
    );
    let files = parse_upstream_files(html, "https://pypi.org/simple/x/");
    assert_eq!(files.len(), 5);
    // Unescaped `<` / `>` inside attribute values (lenient mirrors).
    assert_eq!(files[4].requires_python.as_deref(), Some("<4"));
    assert_eq!(files[4].yanked.as_deref(), Some(">old"));
    assert_eq!(files[0].requires_python.as_deref(), Some(">=3.8,<4"));
    assert_eq!(files[0].yanked, None);
    // An attribute before href belongs to the same anchor.
    assert_eq!(files[1].yanked.as_deref(), Some(""));
    assert_eq!(files[1].sha256.as_deref(), Some("bb"));
    assert_eq!(files[2].yanked.as_deref(), Some("broken & bad"));
    assert_eq!(files[2].requires_python, None);
    // #664: the index lists the decoded name, the one the download route matches.
    assert_eq!(files[3].filename, "torch-2.4.0+cu124-cp310-none-any.whl");
}

#[test]
fn test_index_attributes_round_trip_html_and_json() {
    let files = vec![
        FileEntry {
            filename: "pkg-1.0.tar.gz".into(),
            sha256: Some("aa".into()),
            requires_python: Some(">=3.8".into()),
            yanked: None,
            core_metadata: Some("sha256=cc".into()),
            ..Default::default()
        },
        FileEntry {
            filename: "pkg-1.1.tar.gz".into(),
            yanked: Some(String::new()),
            core_metadata: Some("true".into()),
            ..Default::default()
        },
        FileEntry {
            filename: "pkg-1.2.tar.gz".into(),
            yanked: Some("bad \"build\"".into()),
            ..Default::default()
        },
    ];
    let body = |r: Response| {
        futures::executor::block_on(axum::body::to_bytes(r.into_body(), 1 << 20)).unwrap()
    };

    let html = body(versions_html_response("pkg", &files, "http://nora"));
    let html = std::str::from_utf8(&html).unwrap();
    assert!(
        html.contains(r#"data-requires-python="&gt;=3.8""#),
        "{html}"
    );
    let parsed = parse_upstream_files(html, "https://pypi.org/simple/x/");
    assert_eq!(parsed.len(), 3);
    assert_eq!(parsed[0].requires_python.as_deref(), Some(">=3.8"));
    assert_eq!(parsed[0].sha256.as_deref(), Some("aa"));
    assert_eq!(parsed[1].yanked.as_deref(), Some(""));
    assert_eq!(parsed[2].yanked.as_deref(), Some("bad \"build\""));
    // PEP 658/714: both attribute names, read back from either.
    assert!(
        html.contains(r#"data-core-metadata="sha256=cc" data-dist-info-metadata="sha256=cc""#),
        "{html}"
    );
    assert_eq!(parsed[0].core_metadata.as_deref(), Some("sha256=cc"));
    assert_eq!(parsed[1].core_metadata.as_deref(), Some("true"));
    assert_eq!(parsed[2].core_metadata, None);
    let legacy = parse_upstream_files(
        r#"<a href="https://up/pkg-1.0-py3-none-any.whl" data-dist-info-metadata="sha256=dd">x</a>"#,
        "https://pypi.org/simple/pkg/",
    );
    assert_eq!(legacy[0].core_metadata.as_deref(), Some("sha256=dd"));

    let json = body(versions_json_response(
        "pkg",
        &files,
        "http://nora",
        &Default::default(),
    ));
    let json: serde_json::Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(json["files"][0]["requires-python"], ">=3.8");
    assert!(json["files"][0].get("yanked").is_none());
    assert_eq!(json["files"][1]["yanked"], true);
    assert_eq!(json["files"][2]["yanked"], "bad \"build\"");
    assert!(json["files"][1].get("requires-python").is_none());
    assert_eq!(json["files"][0]["core-metadata"]["sha256"], "cc");
    assert_eq!(json["files"][0]["dist-info-metadata"]["sha256"], "cc");
    assert_eq!(json["files"][1]["core-metadata"], true);
    assert!(json["files"][2].get("core-metadata").is_none());
}

#[test]
fn test_upload_filename_must_match_project_and_version() {
    // PEP 440 spellings of one version compare equal.
    for (a, b) in [
        ("1.0.0rc1", "V1.0.0-RC.01"),
        ("1.0", "1.0.0"),
        ("2.0b1", "2.0-beta.1"),
        ("1.0.post2", "1.0-r2"),
        ("1.0+local.1", "1.0.0+LOCAL-1"),
    ] {
        assert_eq!(version_key(a), version_key(b), "{a} == {b}");
    }
    for (a, b) in [("1.0", "1.1"), ("1.0rc1", "1.0"), ("1.0+a", "1.0")] {
        assert_ne!(version_key(a), version_key(b), "{a} != {b}");
    }
    assert!(upload_filename_mismatch("foo_bar-1.0-py3-none-any.whl", "foo-bar", "1.0").is_none());
    assert!(upload_filename_mismatch("Foo.Bar-1.0.tar.gz", "foo-bar", "1.0").is_none());
    assert!(upload_filename_mismatch("requests-1.0.tar.gz", "foo", "1.0").is_some());
    assert!(upload_filename_mismatch("foo-1.1.tar.gz", "foo", "1.0").is_some());
    assert!(upload_filename_mismatch("foo.tar.gz", "foo", "1.0").is_some());
}

#[test]
fn test_wheel_core_metadata_reads_the_root_dist_info() {
    use std::io::Write;
    let build = |entries: &[&str]| {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for name in entries {
            w.start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            w.write_all(format!("from {name}").as_bytes()).unwrap();
        }
        w.finish().unwrap().into_inner()
    };
    let one = build(&["pkg/__init__.py", "pkg-1.0.dist-info/METADATA"]);
    assert_eq!(
        wheel_core_metadata(std::io::Cursor::new(&one[..])).as_deref(),
        Some(&b"from pkg-1.0.dist-info/METADATA"[..])
    );
    // Vendored metadata deeper in the tree does not count; two at the root are ambiguous.
    let nested = build(&["pkg/_vendor/x-1.0.dist-info/METADATA"]);
    assert_eq!(wheel_core_metadata(std::io::Cursor::new(&nested[..])), None);
    let two = build(&["a-1.0.dist-info/METADATA", "b-1.0.dist-info/METADATA"]);
    assert_eq!(wheel_core_metadata(std::io::Cursor::new(&two[..])), None);
    assert_eq!(
        wheel_core_metadata(std::io::Cursor::new(&b"not a zip"[..])),
        None
    );
}

#[test]
fn test_merge_cached_file_keeps_upstream_attributes() {
    let upstream = vec![FileEntry {
        filename: "pkg-1.0.whl".into(),
        sha256: Some("up".into()),
        requires_python: Some(">=3.9".into()),
        yanked: Some("cve".into()),
        core_metadata: Some("sha256=up".into()),
        ..Default::default()
    }];
    let local = vec![FileEntry {
        filename: "pkg-1.0.whl".into(),
        sha256: Some("local".into()),
        ..Default::default()
    }];
    let merged = merge_file_lists(upstream, &local);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].sha256.as_deref(), Some("local"));
    assert_eq!(merged[0].requires_python.as_deref(), Some(">=3.9"));
    assert_eq!(merged[0].yanked.as_deref(), Some("cve"));
    assert_eq!(
        merged[0].core_metadata, None,
        "the upstream's core metadata may describe other bytes than the local file"
    );
}
