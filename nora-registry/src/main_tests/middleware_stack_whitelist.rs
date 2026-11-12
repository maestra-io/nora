// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

fn squash(s: &str) -> String {
    s.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .flat_map(|l| l.chars())
        .filter(|c| !c.is_whitespace())
        .collect()
}

#[test]
fn the_test_router_builds_its_layers_only_through_request_layers() {
    let code = squash(include_str!("../test_helpers.rs"));
    assert!(code.contains(&["crate::request_layers", "(routes,&state)"].concat()));
    assert_eq!(code.matches(&["from_fn", ""].concat()).count(), 0);
    assert_eq!(
        code.matches(&[".layer", "("].concat()).count(),
        1,
        "only DefaultBodyLimit"
    );
}
