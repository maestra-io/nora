// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

//! Every long-lived task the server starts runs under its supervisor. `run_server` cannot
//! run in a test (it binds a port and waits for a signal), so this reads it, and every
//! function of this file it calls, from the source.
use std::collections::{BTreeMap, BTreeSet};

const SOURCE: &str = include_str!("../main.rs");

/// The tasks the server runs, by the name they are supervised under.
const SUPERVISED: [&str; 7] = [
    "cleanup",
    "internal_listener",
    "maintenance",
    "pull_stats",
    "quarantine_exceptions",
    "repo_index",
    "sighup",
];

/// Spawns in that code that are not long-lived, by the function they are in: the task of
/// one connection, which ends with it, and the temp-file sweep of every tenth maintenance
/// tick, which ends with its sweep.
const SHORT_LIVED: [(&str, &str); 2] = [
    ("serve_with_drain", "connections.spawn("),
    ("maintenance_tick", "tokio::task::spawn_blocking("),
];

/// The top-level functions of this file, by name: the lines from the one that declares
/// it to the closing brace at the start of a line.
fn functions() -> BTreeMap<String, String> {
    let mut found = BTreeMap::new();
    let mut current: Option<(String, Vec<&str>)> = None;
    for line in SOURCE.lines() {
        if let Some((name, mut body)) = current.take() {
            body.push(line);
            if line == "}" {
                found.insert(name, body.join("\n"));
            } else {
                current = Some((name, body));
            }
            continue;
        }
        let declared = ["pub(crate) ", "pub "]
            .iter()
            .fold(line, |l, p| l.strip_prefix(p).unwrap_or(l));
        let declared = declared.strip_prefix("async ").unwrap_or(declared);
        if let Some(rest) = declared.strip_prefix("fn ") {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            current = Some((name, vec![line]));
        }
    }
    found
}

/// `run_server` and every function of this file it reaches.
fn server_code() -> BTreeMap<String, String> {
    let all = functions();
    let mut reached = BTreeMap::new();
    let mut next = vec!["run_server".to_owned()];
    while let Some(name) = next.pop() {
        let Some(body) = all.get(&name) else { continue };
        if reached.insert(name.clone(), body.clone()).is_some() {
            continue;
        }
        for callee in all.keys() {
            let called = body.match_indices(callee.as_str()).any(|(i, _)| {
                let before = body[..i].chars().next_back();
                let after = body[i + callee.len()..].trim_start();
                !before.is_some_and(|c| c.is_alphanumeric() || c == '_')
                    && (after.starts_with('(') || after.starts_with("::<"))
            });
            if called {
                next.push(callee.clone());
            }
        }
    }
    reached
}

/// Each call in `code` whose name starts with `spawn`, written out with the path or
/// receiver before it (`tokio::spawn(`, `state.tasks.spawn(`), and each thread builder.
fn spawns(code: &str) -> Vec<String> {
    let path = |c: char| c.is_alphanumeric() || matches!(c, '_' | ':' | '.');
    let mut found = Vec::new();
    for (i, _) in code.match_indices("spawn") {
        let name_end = i + code[i..]
            .find(|c: char| !(c.is_alphanumeric() || c == '_'))
            .unwrap_or(code.len() - i);
        if !code[name_end..].trim_start().starts_with('(') {
            continue;
        }
        let start = code[..i].rfind(|c: char| !path(c)).map_or(0, |s| s + 1);
        found.push(format!("{}(", &code[start..name_end]));
    }
    for (i, _) in code.match_indices("thread::Builder") {
        let start = code[..i].rfind(|c: char| !path(c)).map_or(0, |s| s + 1);
        found.push(code[start..i + "thread::Builder".len()].to_owned());
    }
    found
}

/// The task name a supervised spawn starts, or `None` for any other call.
fn supervised_name<'a>(call: &str, after: &'a str) -> Option<&'a str> {
    if call != "tasks.spawn(" && !call.ends_with(".tasks.spawn(") {
        return None;
    }
    let name = after.trim_start().strip_prefix('"')?;
    Some(&name[..name.find('"')?])
}

#[test]
fn the_server_starts_every_long_lived_task_under_its_supervisor() {
    let code = server_code();
    for name in ["run_server", "spawn_maintenance", "maintenance_tick"] {
        assert!(code.contains_key(name), "{name} is read");
    }
    let mut supervised = BTreeSet::new();
    for (function, body) in &code {
        let mut rest = body.as_str();
        for call in spawns(body) {
            let at = rest.find(&call).unwrap() + call.len();
            let after = &rest[at..];
            rest = after;
            if code.contains_key(call.trim_end_matches('(')) {
                // A function of this file: read on its own.
                continue;
            }
            match supervised_name(&call, after) {
                Some(name) => {
                    supervised.insert(name.to_owned());
                }
                None => assert!(
                    SHORT_LIVED.contains(&(function.as_str(), call.as_str())),
                    "{function}: {call} starts a task past the supervisor"
                ),
            }
        }
    }
    assert_eq!(supervised, BTreeSet::from(SUPERVISED.map(str::to_owned)));
}

/// The reading finds a task started past the supervisor in each spelling, and tells a
/// supervised one by its name.
#[test]
fn a_spawn_past_the_supervisor_is_found() {
    for (bad, call) in [
        ("let t = tokio::spawn(work());", "tokio::spawn("),
        ("tokio::task::spawn (work());", "tokio::task::spawn("),
        ("handle.spawn(work());", "handle.spawn("),
        (
            "std::thread::Builder::new().spawn(work);",
            "std::thread::Builder",
        ),
        ("set.spawn_local(work());", "set.spawn_local("),
        ("let t = spawn(work());", "spawn("),
    ] {
        let found = spawns(bad);
        assert!(found.contains(&call.to_owned()), "{bad}: {found:?}");
        assert!(
            found
                .iter()
                .all(|c| supervised_name(c, "(\"sighup\"").is_none()),
            "{bad}"
        );
    }
    let good = "state.tasks.spawn(\"sighup\", run);";
    assert_eq!(spawns(good), ["state.tasks.spawn("]);
    assert_eq!(
        supervised_name("state.tasks.spawn(", "\"sighup\", run);"),
        Some("sighup")
    );
    assert!(functions().len() > 20);
}
