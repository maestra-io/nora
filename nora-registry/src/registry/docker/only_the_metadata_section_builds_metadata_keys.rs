// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

/// The functions that may build a metadata key: its definition, the three helpers, and the
/// reader of a push date.
const ALLOWED: [&str; 9] = [
    "manifest_meta_key",
    "write_manifest_meta",
    "delete_manifest_and_meta",
    // A push's record and the proxied copy a push takes its tag back from (variant A).
    "read_bare_meta",
    "delete_proxied_tag",
    "extract_docker_publish_date",
    // #1114: pull stats are keyed off the manifest meta key and derive the
    // .stats.json sidecar key from it.
    "serve_cached_manifest",
    "manifest_stats_key",
    "flush_pull_stats",
];

/// The function a line belongs to: the last `fn name` header above it.
fn fn_name(line: &str) -> Option<&str> {
    let at = line.find("fn ")?;
    let before = &line[..at];
    if !before.trim().is_empty()
        && ![
            "pub",
            "pub(crate)",
            "async",
            "pub async",
            "pub(crate) async",
        ]
        .contains(&before.trim())
    {
        return None;
    }
    let rest = &line[at + 3..];
    let end = rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))?;
    Some(&rest[..end])
}

/// Every line of the production part that builds a metadata key outside the white list, and
/// every top-level line after the first test module that is not part of a test module.
fn violations(src: &str) -> Vec<String> {
    let cut = src
        .find("\n#[cfg(test)]\n")
        .expect("docker.rs has test modules");
    let (production, tests) = src.split_at(cut);
    let mut found = Vec::new();
    let mut current: Option<&str> = None;
    for (i, line) in production.lines().enumerate() {
        if let Some(name) = fn_name(line) {
            current = Some(name);
        }
        let code = line.trim_start();
        if code.starts_with("//") {
            continue;
        }
        let builds = (line.contains("manifest_meta_key")
            && fn_name(line) != Some("manifest_meta_key"))
            || line.contains(".meta.json");
        if builds && !current.is_some_and(|f| ALLOWED.contains(&f)) {
            found.push(format!(
                "line {}: {} (in {:?})",
                i + 1,
                line.trim(),
                current
            ));
        }
    }
    // After the first test module only test modules follow.
    let mut attrs_have_cfg_test = false;
    for line in tests.lines() {
        if line.is_empty()
            || line.starts_with(' ')
            || line.starts_with('\t')
            || line.starts_with('}')
        {
            continue;
        }
        if line.starts_with("//") {
            continue;
        }
        if line.starts_with("#[") {
            attrs_have_cfg_test |= line.starts_with("#[cfg(test)]");
            continue;
        }
        if line.starts_with("mod ") && attrs_have_cfg_test {
            attrs_have_cfg_test = false;
            continue;
        }
        found.push(format!("production item after the tests: {line}"));
    }
    found
}

#[test]
fn only_the_metadata_section_builds_metadata_keys() {
    let src = include_str!("../docker.rs");
    assert_eq!(violations(src), Vec::<String>::new());
}

// Controls: a metadata key built in another function, or a production function after the
// tests, is caught; a comment that mentions `.meta.json` is not.
#[test]
fn the_white_list_catches_a_key_built_elsewhere() {
    let src = include_str!("../docker.rs");
    let cut = src.find("\n#[cfg(test)]\n").unwrap();
    let mut built_elsewhere = src.to_string();
    built_elsewhere.insert_str(
        cut,
        "\nasync fn stray(state: &AppState) {\n    let _ = state.storage.delete(&manifest_meta_key(None, \"a\", \"b\")).await;\n}\n",
    );
    assert_eq!(violations(&built_elsewhere).len(), 1);
    let mut literal = src.to_string();
    literal.insert_str(
        cut,
        "\nfn stray() -> &'static str {\n    \"docker/a/manifests/b.meta.json\"\n}\n",
    );
    assert_eq!(violations(&literal).len(), 1);
    let mut after_tests = src.to_string();
    after_tests.push_str("\nasync fn late(state: &AppState) {\n    let _ = state;\n}\n");
    assert_eq!(violations(&after_tests).len(), 1);
    // The function itself handed to another name, too.
    let mut alias = src.to_string();
    alias.insert_str(
        cut,
        "\nfn stray() {\n    let key = manifest_meta_key;\n    let _ = key;\n}\n",
    );
    assert_eq!(violations(&alias).len(), 1);
    let mut comment = src.to_string();
    comment.insert_str(
        cut,
        "\nfn quiet() {\n    // the .meta.json sidecar is written elsewhere\n}\n",
    );
    assert_eq!(violations(&comment), Vec::<String>::new());
}
