// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

//! The shipped build unwinds: under `panic = "abort"` every `catch_unwind` guard
//! and the panic layer are dead code, and one panic ends the only replica. Tests always
//! build with unwind, whatever the profile says, so this reads the build inputs instead:
//! the Cargo manifests and the files that run a release build.
use std::path::{Path, PathBuf};

/// Lines of a build file that select the abort strategy: a profile key, a
/// `CARGO_PROFILE_*_PANIC` variable, `--config profile.*.panic` or `-C panic`. Compared
/// without whitespace, quotes or case, so each spelling of one setting is one form.
fn abort_switches(text: &str) -> Vec<String> {
    text.lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .map(|line| {
            line.chars()
                .filter(|c| !c.is_whitespace() && *c != '"' && *c != '\'')
                .collect::<String>()
                .to_ascii_lowercase()
        })
        .filter(|line| line.contains("panic=abort") || line.contains("panic:abort"))
        .collect()
}

/// The manifests, Cargo configs, Dockerfiles, workflows and Makefile of the workspace.
fn build_inputs(root: &Path) -> Vec<PathBuf> {
    let mut files = vec![
        root.join("Cargo.toml"),
        root.join("nora-registry/Cargo.toml"),
        root.join(".cargo/config.toml"),
        root.join(".cargo/config"),
        root.join("Makefile"),
    ];
    for dir in [root.to_path_buf(), root.join(".github/workflows")] {
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("Dockerfile") || name.ends_with(".yml") || name.ends_with(".yaml") {
                files.push(entry.path());
            }
        }
    }
    files.into_iter().filter(|f| f.is_file()).collect()
}

#[test]
fn no_build_input_selects_panic_abort() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let inputs = build_inputs(root);
    assert!(
        inputs.iter().any(|f| f.ends_with("Dockerfile")),
        "the release Dockerfile is among the inputs read"
    );
    for file in inputs {
        let found = abort_switches(&std::fs::read_to_string(&file).unwrap());
        assert!(found.is_empty(), "{}: {found:?}", file.display());
    }
}

/// The features `name` turns on through the manifest's `[features]`, itself included;
/// `dep:` and `crate/feature` entries are kept as they are written.
fn feature_closure(features: &toml::Table, name: &str) -> std::collections::BTreeSet<String> {
    let mut on = std::collections::BTreeSet::new();
    let mut next = vec![name.to_owned()];
    while let Some(feature) = next.pop() {
        if !on.insert(feature.clone()) {
            continue;
        }
        if let Some(enables) = features.get(&feature).and_then(|f| f.as_array()) {
            next.extend(enables.iter().filter_map(|f| f.as_str()).map(str::to_owned));
        }
    }
    on
}

/// Lines of the build inputs that may pass `--all-features`: cargo-deny's check, which
/// builds nothing.
const ALL_FEATURES_ALLOWED: &[(&str, &str)] = &[
    (".github/workflows/ci.yml", "arguments: --all-features"),
    (
        ".github/workflows/maestra-ci.yml",
        "arguments: --all-features",
    ),
];

/// The one line of the build inputs that may name the feature: the clippy run that keeps
/// its code compiling. It checks, and ships nothing.
const FAULT_INJECTION_ALLOWED: &[(&str, &str)] = &[(
    ".github/workflows/maestra-ci.yml",
    "run: cargo clippy -p nora-registry --all-targets --features fault-injection,demo --locked -- -D warnings",
)];

/// The `/__fi/` panic routes are in no shipped build: neither the default features nor any
/// other feature turn it on, however indirectly; no build file names it, and none builds
/// with `--all-features`.
#[test]
fn no_shipped_build_enables_fault_injection() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let manifest = root.join("nora-registry/Cargo.toml");
    let doc: toml::Table = std::fs::read_to_string(&manifest).unwrap().parse().unwrap();
    let features = doc["features"].as_table().unwrap();
    assert!(features.contains_key("fault-injection"));
    assert!(features.contains_key("default"));
    for name in features.keys().filter(|name| *name != "fault-injection") {
        let on = feature_closure(features, name);
        assert!(
            !on.iter().any(|f| f.contains("fault-injection")),
            "feature {name} turns on {on:?}"
        );
    }
    for file in build_inputs(root).into_iter().filter(|f| *f != manifest) {
        let text = std::fs::read_to_string(&file).unwrap();
        let relative = file
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        for line in text.lines().filter(|l| l.contains("fault-injection")) {
            assert!(
                FAULT_INJECTION_ALLOWED.contains(&(relative.as_str(), line.trim())),
                "{relative}: {line}"
            );
        }
        for line in text.lines().filter(|line| line.contains("--all-features")) {
            assert!(
                ALL_FEATURES_ALLOWED.contains(&(relative.as_str(), line.trim())),
                "{relative}: {line}"
            );
        }
    }
}

/// The manifest's features, exactly: one added, or one turning another on, is read here
/// first.
const FEATURES: &[(&str, &[&str])] = &[
    ("default", &["rpm", "deb", "mimalloc"]),
    ("mimalloc", &["dep:mimalloc"]),
    ("demo", &[]),
    // Maestra: the rpm and deb registries are optional (`--no-default-features`).
    ("rpm", &["dep:rpm", "dep:pgp", "dep:lzma-rs", "dep:ruzstd"]),
    ("deb", &["dep:ar", "dep:pgp", "dep:lzma-rs", "dep:ruzstd"]),
    ("fault-injection", &[]),
];

/// The tables of the crate's manifest. Not among them: `cargo-features` (a profile's
/// `rustflags` could pass `--cfg`), and in `[package]` neither `build` nor `links`.
const CRATE_TABLES: &[&str] = &[
    "package",
    "lib",
    "bin",
    "dependencies",
    "target",
    "dev-dependencies",
    "bench",
    "lints",
    "features",
];
const PACKAGE_KEYS: &[&str] = &[
    "name",
    "version",
    "edition",
    "license",
    "authors",
    "repository",
    "homepage",
    "description",
    "keywords",
    "categories",
    "metadata",
];

/// The tables of the workspace manifest and the keys of its profiles: no `rustflags`.
const WORKSPACE_TABLES: &[&str] = &["workspace", "profile"];
const PROFILE_KEYS: &[&str] = &[
    "inherits",
    "debug",
    "strip",
    "codegen-units",
    "panic",
    "lto",
];

/// The directories of the repository, but build output, git's and npm's.
fn repository_dirs(dir: &Path, out: &mut Vec<PathBuf>) {
    out.push(dir.to_path_buf());
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let name = entry.file_name();
        if entry.path().is_dir()
            && !["target", ".git", "node_modules"].contains(&&*name.to_string_lossy())
        {
            repository_dirs(&entry.path(), out);
        }
    }
}

/// What can turn a feature on without `--features` is held to the forms listed here, and
/// anything else fails: no package of the workspace has a build script (`build.rs`, or
/// `package.build`), which could print `cargo:rustc-cfg=feature="…"`; no directory of the
/// repository has a Cargo config (`.cargo/`), whose `rustflags` or `[env]` would reach every
/// build run under it; the features are [`FEATURES`]; the manifests hold only the listed
/// tables and profile keys.
#[test]
fn the_build_inputs_are_the_listed_ones() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let read =
        |file: PathBuf| -> toml::Table { std::fs::read_to_string(&file).unwrap().parse().unwrap() };
    let workspace = read(root.join("Cargo.toml"));
    let members = workspace["workspace"]["members"].as_array().unwrap();
    assert!(members.len() >= 2, "{members:?}");
    for member in members {
        let dir = root.join(member.as_str().unwrap());
        assert!(
            !dir.join("build.rs").exists(),
            "{}: build.rs",
            dir.display()
        );
        let manifest = read(dir.join("Cargo.toml"));
        for key in ["build", "links"] {
            assert!(
                manifest["package"].get(key).is_none(),
                "{}: package.{key}",
                dir.display()
            );
        }
    }
    let mut dirs = Vec::new();
    repository_dirs(root, &mut dirs);
    assert!(dirs.contains(&root.join("nora-registry/src")));
    for dir in dirs {
        assert!(!dir.join(".cargo").exists(), "{}/.cargo", dir.display());
    }

    let manifest = read(root.join("nora-registry/Cargo.toml"));
    let features: Vec<(String, Vec<String>)> = manifest["features"]
        .as_table()
        .unwrap()
        .iter()
        .map(|(name, on)| {
            let on = on.as_array().unwrap().iter();
            (
                name.clone(),
                on.map(|f| f.as_str().unwrap().to_owned()).collect(),
            )
        })
        .collect();
    let listed: Vec<(String, Vec<String>)> = FEATURES
        .iter()
        .map(|(name, on)| (name.to_string(), on.iter().map(|f| f.to_string()).collect()))
        .collect();
    let sorted = |mut v: Vec<(String, Vec<String>)>| {
        v.sort();
        v
    };
    assert_eq!(sorted(features), sorted(listed));
    for table in manifest.keys() {
        assert!(
            CRATE_TABLES.contains(&table.as_str()),
            "nora-registry: [{table}]"
        );
    }
    for key in manifest["package"].as_table().unwrap().keys() {
        assert!(
            PACKAGE_KEYS.contains(&key.as_str()),
            "nora-registry: package.{key}"
        );
    }
    for table in workspace.keys() {
        assert!(
            WORKSPACE_TABLES.contains(&table.as_str()),
            "workspace: [{table}]"
        );
    }
    for (profile, keys) in workspace["profile"].as_table().unwrap() {
        for key in keys.as_table().unwrap().keys() {
            assert!(
                PROFILE_KEYS.contains(&key.as_str()),
                "profile.{profile}.{key}"
            );
        }
    }
}

/// `--all-features` is found in each build file it can appear in, the release Dockerfile
/// first; the allowed line is the one cargo-deny runs.
#[test]
fn the_build_files_read_include_the_dockerfile_and_ci() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let inputs = build_inputs(root);
    for (file, line) in ALL_FEATURES_ALLOWED {
        let text = std::fs::read_to_string(root.join(file)).unwrap();
        assert!(text.lines().any(|l| l.trim() == *line), "{file}: {line}");
        assert!(inputs.contains(&root.join(file)), "{file}");
    }
    assert!(inputs.contains(&root.join("Dockerfile")));
    assert!(inputs.contains(&root.join(".github/workflows/release.yml")));
}

/// The `cfg` predicates the sources may use, without whitespace. Each decides what a build
/// compiles; one that is not here — an `any(…)` that the default `mimalloc` would satisfy,
/// say — is read before it is added.
const CFG_PREDICATES: &[&str] = &[
    "test",
    "not(test)",
    "unix",
    "not(unix)",
    r#"target_os="linux""#,
    r#"not(target_os="linux")"#,
    "kani",
    r#"feature="mimalloc""#,
    r#"feature="demo""#,
    r#"not(feature="demo")"#,
    r#"feature="fault-injection""#,
    r#"not(feature="fault-injection")"#,
    // Maestra: the optional rpm and deb registries.
    r#"feature="rpm""#,
    r#"feature="deb""#,
    r#"any(feature="rpm",feature="deb")"#,
    r#"not(any(feature="rpm",feature="deb"))"#,
    r#"not(all(feature="rpm",feature="deb"))"#,
];

/// The attributes a `cfg_attr` of the sources may apply: lint levels.
const CFG_ATTR_APPLIES: &[&str] = &["allow(", "deny(", "warn(", "expect("];

/// The macros that may name the fault-injection feature or module: the warning a
/// fault-injection build logs at start.
const NAMES_FAULT_INJECTION: &[&str] = &["warn"];

/// What decides whether code of a source file is compiled, outside the items under
/// `#[cfg(test)]` (in no shipped build): each `cfg` predicate, each `cfg_attr`, each
/// `#[path]` and `include!`, each declaration of the fault-injection module and each
/// macro naming it. Read with syn, so a form split over lines or written in another
/// spacing is the same form.
#[derive(Default)]
struct CompiledWhen {
    /// The `cfg` predicates, `cfg_attr` conditions and `cfg!` arguments, without whitespace.
    predicates: Vec<String>,
    /// What a `cfg_attr` applies, without whitespace.
    applied: Vec<String>,
    /// `#[path]` attributes, `include!` macros and the other macros naming the feature.
    refused: Vec<String>,
    /// The `cfg` predicates of each `mod fault_injection`.
    modules: Vec<Vec<String>>,
}

fn compact(tokens: &impl ToString) -> String {
    tokens.to_string().split_whitespace().collect()
}

/// `text` cut at its commas outside parentheses and brackets, empty parts left out.
fn top_level_parts(text: &str) -> Vec<&str> {
    let (mut depth, mut start, mut parts) = (0usize, 0, Vec::new());
    for (i, c) in text.char_indices() {
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(&text[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&text[start..]);
    parts.retain(|p| !p.is_empty());
    parts
}

fn names_fault_injection(text: &str) -> bool {
    text.contains("fault-injection") || text.contains("fault_injection")
}

impl CompiledWhen {
    /// The `cfg` predicates of `attrs`, and whether one of them is exactly `test`.
    fn cfgs(attrs: &[syn::Attribute]) -> (Vec<String>, bool) {
        let cfgs: Vec<String> = attrs
            .iter()
            .filter(|a| a.path().is_ident("cfg"))
            .map(|a| match &a.meta {
                syn::Meta::List(list) => compact(&list.tokens),
                _ => "cfg without a predicate".to_owned(),
            })
            .collect();
        let test = cfgs.iter().any(|c| c == "test");
        (cfgs, test)
    }

    fn read(text: &str) -> Self {
        let file = syn::parse_file(text).unwrap();
        let mut found = Self::default();
        if !Self::cfgs(&file.attrs).1 {
            syn::visit::Visit::visit_file(&mut found, &file);
        }
        found
    }
}

impl<'ast> syn::visit::Visit<'ast> for CompiledWhen {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        let attrs = match item {
            syn::Item::Mod(m) => &m.attrs,
            syn::Item::Fn(f) => &f.attrs,
            syn::Item::Impl(i) => &i.attrs,
            syn::Item::Use(u) => &u.attrs,
            syn::Item::Const(c) => &c.attrs,
            syn::Item::Static(s) => &s.attrs,
            syn::Item::Struct(s) => &s.attrs,
            syn::Item::Enum(e) => &e.attrs,
            syn::Item::Macro(m) => &m.attrs,
            syn::Item::Trait(t) => &t.attrs,
            syn::Item::Type(t) => &t.attrs,
            _ => {
                syn::visit::visit_item(self, item);
                return;
            }
        };
        let (cfgs, test) = Self::cfgs(attrs);
        if test {
            return;
        }
        if let syn::Item::Mod(m) = item {
            if names_fault_injection(&m.ident.to_string()) {
                self.modules.push(cfgs);
            }
        }
        syn::visit::visit_item(self, item);
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        if let syn::ImplItem::Fn(f) = item {
            if Self::cfgs(&f.attrs).1 {
                return;
            }
        }
        syn::visit::visit_impl_item(self, item);
    }

    fn visit_attribute(&mut self, attr: &'ast syn::Attribute) {
        let path = attr.path();
        if path.is_ident("path") {
            self.refused.push("#[path]".to_owned());
        }
        let syn::Meta::List(list) = &attr.meta else {
            return;
        };
        if path.is_ident("cfg") {
            self.predicates.push(compact(&list.tokens));
        } else if path.is_ident("cfg_attr") {
            let all = compact(&list.tokens);
            // The condition, then every attribute it applies, cut at the commas outside
            // parentheses: an `any(a,b)` condition holds commas of its own, and one
            // `cfg_attr` may apply several attributes.
            let parts = top_level_parts(&all);
            let (predicate, applied) = parts.split_first().unwrap_or((&"", &[]));
            self.predicates.push((*predicate).to_owned());
            if applied.is_empty() {
                self.applied.push(String::new());
            }
            self.applied.extend(applied.iter().map(|a| (*a).to_owned()));
        }
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let name = mac
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        let tokens = compact(&mac.tokens);
        if name == "cfg" {
            self.predicates.push(tokens);
        } else if name == "include" {
            self.refused.push(format!("include!({tokens})"));
        } else if names_fault_injection(&tokens) && !NAMES_FAULT_INJECTION.contains(&name.as_str())
        {
            self.refused.push(format!("{name}!({tokens})"));
        }
    }
}

/// The source files of the crate, but the fault-injection module's own: it is what the
/// feature compiles.
fn crate_sources() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    walk(&src, &mut files);
    files.retain(|f| *f != src.join("fault_injection.rs"));
    files
}

/// The fault-injection module is compiled only under its own feature: it is declared once,
/// under exactly `#[cfg(feature = "fault-injection")]`; no `#[path]` or `include!` brings
/// its file in under another name; every `cfg` of the sources is one of
/// [`CFG_PREDICATES`], so no `any(…)` lets another feature compile it; a `cfg_attr`
/// applies lint levels only; and no macro but the start warning names it. Anything else
/// that uses the module then fails to compile in the default build.
#[test]
fn fault_injection_is_compiled_only_under_its_own_feature() {
    let mut modules = Vec::new();
    for file in crate_sources() {
        let found = CompiledWhen::read(&std::fs::read_to_string(&file).unwrap());
        let place = file.display();
        for predicate in &found.predicates {
            assert!(
                CFG_PREDICATES.contains(&predicate.as_str()),
                "{place}: cfg({predicate})"
            );
        }
        for applied in &found.applied {
            assert!(
                CFG_ATTR_APPLIES.iter().any(|a| applied.starts_with(a)),
                "{place}: cfg_attr(…, {applied})"
            );
        }
        assert!(found.refused.is_empty(), "{place}: {:?}", found.refused);
        modules.extend(found.modules);
    }
    assert_eq!(
        modules,
        [vec![r#"feature="fault-injection""#.to_owned()]],
        "the module is declared once, under its feature alone"
    );
}

/// Each way a source could compile the module under another condition is found, in any
/// spacing or over several lines; what the sources do now is not.
#[test]
fn every_way_to_compile_fault_injection_otherwise_is_found() {
    let fine = CompiledWhen::read(
        r#"
            #[cfg(feature = "fault-injection")]
            mod fault_injection;
            #[cfg(not(feature = "fault-injection"))]
            fn quiet() {}
            #[cfg_attr(test, allow(clippy::unwrap_used))]
            fn f() {
                #[cfg(feature = "fault-injection")]
                warn!("fault-injection build: /__fi/ routes make the server panic");
            }
            #[cfg(test)]
            mod tests {
                #[cfg(any(test, feature = "fault-injection"))]
                fn t() { assert!(text.contains("fault-injection")); }
            }
            "#,
    );
    assert!(fine
        .predicates
        .iter()
        .all(|p| CFG_PREDICATES.contains(&p.as_str())));
    assert!(fine.refused.is_empty(), "{:?}", fine.refused);
    assert_eq!(
        fine.modules,
        [vec![r#"feature="fault-injection""#.to_owned()]]
    );

    for (bad, predicate) in [
        (
            "#[cfg(any(feature = \"mimalloc\",\n feature = \"fault-injection\"))]\nmod fault_injection;",
            r#"any(feature="mimalloc",feature="fault-injection")"#,
        ),
        ("#[cfg(all())] fn f() {}", "all()"),
        (
            "fn f() { #[cfg(not(feature = \"demo-x\"))] let a = 1; }",
            r#"not(feature="demo-x")"#,
        ),
        ("#[cfg_attr(kani_x, allow(x))] fn f() {}", "kani_x"),
        (
            "#[cfg_attr(any(kani_x, unix), allow(x))] fn f() {}",
            "any(kani_x,unix)",
        ),
        ("fn f() { if cfg!(any(unix)) {} }", "any(unix)"),
    ] {
        let found = CompiledWhen::read(bad);
        assert!(
            found.predicates.contains(&predicate.to_owned())
                && !CFG_PREDICATES.contains(&predicate),
            "{bad}: {:?}",
            found.predicates
        );
    }
    for bad in [
        "#[cfg_attr(unix, path = \"fault_injection.rs\")] mod fi;",
        "#[cfg_attr(unix, allow(dead_code), path = \"fault_injection.rs\")] mod fi;",
    ] {
        let found = CompiledWhen::read(bad);
        assert!(
            found
                .applied
                .iter()
                .any(|applied| !CFG_ATTR_APPLIES.iter().any(|a| applied.starts_with(a))),
            "{bad}: {:?}",
            found.applied
        );
    }
    let two = CompiledWhen::read("#[cfg_attr(test, allow(a), deny(b))] fn f() {}");
    assert_eq!(two.applied, ["allow(a)", "deny(b)"]);
    for bad in [
        "#[path = \"fault_injection.rs\"]\nmod fi;",
        "fn f() { include!(concat!(\"fault_\", \"injection.rs\")); }",
        "fn f() { routes.merge(crate::macros::fi!(fault_injection::routes())); }",
    ] {
        assert!(!CompiledWhen::read(bad).refused.is_empty(), "{bad}");
    }
    let twice = CompiledWhen::read(
        "#[cfg(feature = \"fault-injection\")] mod fault_injection;\n#[cfg(feature = \"fault-injection\")] mod fault_injection_b;",
    );
    assert_eq!(twice.modules.len(), 2);
    let ungated = CompiledWhen::read("mod fault_injection;");
    assert_eq!(ungated.modules, [Vec::<String>::new()]);
}

#[test]
fn every_spelling_of_abort_is_found_and_unwind_is_not() {
    for abort in [
        "[profile.release]\npanic = \"abort\"",
        "release = { panic = 'abort' }",
        "ENV CARGO_PROFILE_RELEASE_PANIC=abort",
        "  CARGO_PROFILE_RELEASE_PANIC: abort",
        "cargo build --release --config 'profile.release.panic=\"abort\"'",
        "RUSTFLAGS=\"-C panic=abort\" cargo build --release",
        "PANIC = \"ABORT\"",
    ] {
        assert_eq!(abort_switches(abort).len(), 1, "{abort}");
    }
    for fine in [
        "[profile.release]\npanic = \"unwind\"",
        "# panic = \"abort\" was the setting up to 1.4.2",
        "tracing::error!(\"background cache task panicked\")",
    ] {
        assert!(abort_switches(fine).is_empty(), "{fine}");
    }
}
