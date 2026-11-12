// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::*;

#[test]
fn parse_explain_spec_recovers_each_registrys_at_convention() {
    let cases: &[(&str, RegistryType, &str, Option<&str>)] = &[
        (
            "cargo:serde@1.0.0",
            RegistryType::Cargo,
            "serde",
            Some("1.0.0"),
        ),
        (
            "npm:is-number@7.0.0",
            RegistryType::Npm,
            "is-number",
            Some("7.0.0"),
        ),
        // an '@' that starts the name opens an npm scope, not a version
        (
            "npm:@scope/pkg@1.0.0",
            RegistryType::Npm,
            "@scope/pkg",
            Some("1.0.0"),
        ),
        ("npm:@scope/pkg", RegistryType::Npm, "@scope/pkg", None),
        (
            "docker:library/nginx@sha256:abc",
            RegistryType::Docker,
            "library/nginx",
            Some("sha256:abc"),
        ),
        // #1099 D1: a raw path with '@' and no version must NOT split on the '@'
        // — otherwise the hint explains a different package than the one refused.
        ("raw:dir/a@b.txt", RegistryType::Raw, "dir/a@b.txt", None),
        ("raw:path/to/file", RegistryType::Raw, "path/to/file", None),
        ("gems:rails", RegistryType::Gems, "rails", None),
    ];
    for (spec, reg, name, ver) in cases {
        match parse_explain_spec(spec) {
            ExplainSpec::Parsed {
                registry,
                name: n,
                version: v,
            } => assert_eq!(
                (registry, n.as_str(), v.as_deref()),
                (*reg, *name, *ver),
                "spec={spec}"
            ),
            other => panic!("spec={spec}: expected Parsed, got {other:?}"),
        }
    }
}

#[test]
fn parse_explain_spec_flags_malformed_specs() {
    assert_eq!(parse_explain_spec("no-colon-here"), ExplainSpec::NoColon);
    match parse_explain_spec("bogusreg:thing") {
        ExplainSpec::UnknownRegistry(r) => assert_eq!(r, "bogusreg"),
        other => panic!("expected UnknownRegistry, got {other:?}"),
    }
}

/// Reverse of `shell_word`: a single-quoted token back to its contents, a bare
/// token unchanged — what a shell does before `nora curation explain` runs.
fn shell_unquote(word: &str) -> String {
    match word.strip_prefix('\'').and_then(|w| w.strip_suffix('\'')) {
        Some(inner) => inner.replace(r"'\''", "'"),
        None => word.to_string(),
    }
}

/// #1099: the hint explains the package it NAMES, and its spec is
/// one shell word so pasting it is safe. For each registry over a corpus —
/// single-letter names (`@` at index 1), npm scopes, raw paths with `@`, and
/// shell metacharacters in the name AND in the version — the spec the shell
/// hands back parses to the same registry/name/version, and the spec is one
/// shell word (bare safe chars, or a single-quoted token).
#[test]
fn explain_command_round_trips_and_is_one_shell_word() {
    let cases: &[(RegistryType, &str, Option<&str>)] = &[
        (RegistryType::Npm, "q", Some("1.5.1")), // single-letter: '@' at index 1 (H3)
        (RegistryType::Npm, "@scope/pkg", Some("1.0.0")),
        (RegistryType::Cargo, "serde", Some("1.0.0")),
        (
            RegistryType::Docker,
            "library/nginx",
            Some("sha256:0123abcd"),
        ),
        (RegistryType::Raw, "dir/a@b.txt", None), // raw path with '@', no version
        (RegistryType::Raw, "dir/my file.txt", None),
        (RegistryType::Npm, "is-number", Some("7.0.0$(touch x)")), // metachar version (H9)
        (RegistryType::Npm, "is-number", Some("7.0.0;id")),
        (RegistryType::Raw, "a`id`b", None), // metachar name
    ];
    for &(rt, name, version) in cases {
        let hint = crate::curation::explain_command(rt.as_str(), name, version);
        let spec = hint
            .strip_prefix("nora curation explain ")
            .expect("hint shape");
        // One shell word: bare safe chars, or a single-quoted token. A version
        // with a metacharacter must land INSIDE the quotes (H9), not after.
        let bare_safe = !spec.is_empty()
            && spec
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "@%+=:,./_-".contains(c));
        let quoted = spec.len() >= 2 && spec.starts_with('\'') && spec.ends_with('\'');
        assert!(
            bare_safe || quoted,
            "spec is not one shell word: {spec:?} ({}:{name})",
            rt.as_str()
        );
        match parse_explain_spec(&shell_unquote(spec)) {
            ExplainSpec::Parsed {
                registry,
                name: n,
                version: v,
            } => assert_eq!(
                (registry, n.as_str(), v.as_deref()),
                (rt, name, version),
                "round-trip for {}:{name}",
                rt.as_str()
            ),
            other => panic!("{}:{name}: expected Parsed, got {other:?}", rt.as_str()),
        }
    }
}
