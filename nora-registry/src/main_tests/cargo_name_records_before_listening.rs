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

/// Whether `run_server` rebuilds the records, awaited, before it binds the listener.
fn rebuilt_before_binding(code: &str) -> bool {
    let code = squash(code);
    let Some(start) = code.find(&["async", "fnrun_server("].concat()) else {
        return false;
    };
    let body = &code[start..];
    let rebuild = body.find(
        &[
            "AssertUnwindSafe(registry::rebuild_cargo_name_records",
            "(&state.storage)).catch_unwind().await",
        ]
        .concat(),
    );
    let bind = body.find(&["letlistener=bind_listener", "(&state.config.server.host"].concat());
    matches!((rebuild, bind), (Some(r), Some(b)) if r < b)
}

#[test]
fn the_records_are_rebuilt_before_the_listener_binds() {
    assert!(rebuilt_before_binding(include_str!("../main.rs")));
}

// Controls: without the call, or with it after the bind, the check refuses.
#[test]
fn the_check_refuses_a_missing_or_late_rebuild() {
    let src = include_str!("../main.rs");
    let call = ["registry::rebuild_cargo_name_records", "(&state.storage)"].concat();
    let missing = src.replace(&call, "std::future::ready(())");
    assert!(!rebuilt_before_binding(&missing));
    let bound = [".expect(\"Failed to", " bind\");"].concat();
    let at = missing.find(&bound).unwrap() + bound.len();
    let late = format!(
        "{}\n    let _ = {call});\n{}",
        &missing[..at],
        &missing[at..]
    );
    assert!(!rebuilt_before_binding(&late));
    // named but never awaited: the future is dropped and startup skips the rebuild
    let dropped = src.replace(
        &[
            call.as_str(),
            ")",
            "\n                .catch_unwind()\n                .await",
        ]
        .concat(),
        &["drop(", call.as_str(), "))"].concat(),
    );
    assert_ne!(dropped, src, "the control must change the source");
    assert!(!rebuilt_before_binding(&dropped));
}
