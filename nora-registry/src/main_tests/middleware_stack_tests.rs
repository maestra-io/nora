// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

/// The server applies the audit layer once — in `request_layers`, which the test router
/// shares, so router tests see where the server runs it. A second copy (say outside
/// auth) would record each refusal twice, once as `anonymous`; a missing or commented-out
/// layer is caught by the audit tests themselves. Comments are skipped, and the needle is
/// built at run time so this test's own text does not count.
#[test]
fn the_audit_layer_is_applied_once() {
    let code: String = include_str!("../main.rs")
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let needle = ["curation_refusal", "_middleware"].concat();
    assert!(
        code.matches(&needle).count() <= 1,
        "{needle} applied more than once"
    );
}
