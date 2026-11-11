#![deny(clippy::unwrap_used)]
#![forbid(unsafe_code)]
// Test code is linted under `--all-targets` but is not held to the production
// restriction/style lints: `.unwrap()`/`.expect()` are idiomatic in tests, and
// the small style nits (redundant clone/field names, `>= x + 1`, etc.) are not
// worth contorting assertions over. Scoped to `cfg(test)` so production keeps
// the strict profile (incl. the workspace `redundant_clone = deny`).
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::redundant_clone,
        clippy::int_plus_one,
        clippy::field_reassign_with_default,
        clippy::unnecessary_get_then_check,
        clippy::single_match,
        clippy::redundant_field_names,
        clippy::len_zero,
        clippy::items_after_test_module
    )
)]
//! NORA Registry — library interface for fuzzing and testing

pub mod docker_manifest;
pub mod maven_paths;
pub mod npm_links;
pub mod pypi_files;
pub mod upstream_rewrite;
pub mod upstream_url;
pub mod validation;
pub mod verified;

/// Re-export Docker manifest parsing for fuzz targets: the server's own reader.
pub mod docker_fuzz {
    pub use crate::docker_manifest::detect_manifest_media_type;
}

/// Re-export npm metadata rewriting for fuzz targets
pub mod npm_fuzz {
    /// The packument as NORA serves it ([`crate::npm_links::place_document`], the server's own
    /// rewrite, with its storage-key check): `Err` for a document that is not JSON.
    #[allow(clippy::result_unit_err)]
    pub fn rewrite_tarball_urls(
        data: &[u8],
        nora_base: &str,
        upstream_url: &str,
    ) -> Result<Vec<u8>, ()> {
        let package = serde_json::from_slice::<serde_json::Value>(data)
            .ok()
            .and_then(|doc| doc.get("name")?.as_str().map(str::to_string));
        let key_ok = |key: &str| crate::validation::validate_storage_key(key).is_ok();
        crate::npm_links::place_document(
            data,
            nora_base,
            upstream_url,
            package.as_deref(),
            crate::npm_links::Links::Served,
            &key_ok,
        )
        .map(|placed| placed.body)
        .map_err(|_| ())
    }

    #[cfg(test)]
    mod url_leak_tests {
        //! #385: a rewrite must never leak the configured upstream host into
        //! client-facing output. The fuzz target `fuzz_url_leak` explores this;
        //! these deterministic cases enforce it on every CI run (the fuzz job
        //! of maestra-ci is a short smoke run, so this is the front-loop guard).
        use super::rewrite_tarball_urls;

        const UPSTREAM: &str = "https://upstream-host.invalid";
        const NORA: &str = "http://nora.test";

        #[test]
        fn tarball_rewrite_drops_upstream_host() {
            let meta = br#"{"versions":{"1.0.0":{"dist":{"tarball":"https://upstream-host.invalid/p/-/p-1.0.0.tgz"}}}}"#;
            let out = rewrite_tarball_urls(meta, NORA, UPSTREAM).expect("valid json");
            let out = String::from_utf8(out).expect("json is utf-8");
            assert!(!out.contains(UPSTREAM), "upstream host leaked: {out}");
            assert!(
                out.contains("http://nora.test/npm/p/-/p-1.0.0.tgz"),
                "tarball not rewritten to nora base: {out}"
            );
        }

        #[test]
        fn byte_safety_net_scrubs_upstream_outside_dist() {
            // An upstream URL hidden in a non-`dist` field must still be removed
            // by the #439 byte-level safety-net before the client sees it.
            let meta = br#"{"_note":"mirror of https://upstream-host.invalid/x","versions":{}}"#;
            let out = rewrite_tarball_urls(meta, NORA, UPSTREAM).expect("valid json");
            assert!(
                !String::from_utf8_lossy(&out).contains(UPSTREAM),
                "byte safety-net let the upstream host through"
            );
        }
    }
}

/// Re-export PyPI index parsing for fuzz targets: the server's own readers.
pub mod pypi_fuzz {
    pub use crate::pypi_files::{extract_filename, parse_upstream_files};
}

/// Re-export Maven path classification for fuzz targets: the server's own.
pub mod maven_fuzz {
    pub use crate::maven_paths::{
        classify_path, compare_maven_versions, is_checksum_file, is_snapshot, xml_escape,
        MavenCoordinates, MavenPathKind,
    };
}

/// Re-export version parsing for fuzz targets: the server's own readers, so the fuzz targets
/// drive the code that runs.
pub mod version_fuzz {
    pub use crate::npm_links::parse_npm_tarball_version;
    pub use crate::pypi_files::parse_pypi_version;
}

/// Re-export the ansible and NuGet upstream-URL rewrites under the path 1.4.2 gave them: the
/// server's own rewrites, in [`upstream_rewrite`], which the fuzz targets now use directly.
pub mod rewrite_fuzz {
    pub use crate::upstream_rewrite::{rewrite_ansible_urls, rewrite_registration_urls};
}

#[cfg(test)]
mod one_implementation_tests {
    //! The fuzz targets drive the code the server runs. A function with a body in this file is
    //! a copy of server code: a fuzz run explores the copy instead of it, a fix to one is no
    //! fix to the other. Shared code lives in a module the server and the fuzz targets both
    //! compile (`pub mod x;` here, used by the server as `nora_registry::x`), and this file
    //! only re-exports it.

    /// Functions with a body that remain, by name: a new one fails
    /// [`this_file_holds_no_copy_of_server_code_but_these`] until it is listed here. The npm one
    /// holds no rule of its own: it reads the package name and calls the server's rewrite
    /// ([`crate::npm_links::place_document`]). No copy of server code is left.
    const COPIES: &[&str] = &["npm_fuzz::rewrite_tarball_urls"];

    /// The modules of their own files this file declares: the code they hold is compiled once,
    /// for the server and the fuzz targets alike.
    const SHARED: &[&str] = &[
        "docker_manifest",
        "maven_paths",
        "npm_links",
        "pypi_files",
        "upstream_rewrite",
        "upstream_url",
        "validation",
        "verified",
    ];

    /// What a source file defines outside the items under `#[cfg(test)]`: each function with a
    /// body (`module::name`, `module::Type::name` for a method), each macro item or `include!`
    /// that could define one, each `#[path]`, and each module declared in a file of its own.
    /// Read with syn, so a form split over lines or written in another spacing is the same form.
    #[derive(Default, Debug)]
    struct Defined {
        bodies: Vec<String>,
        refused: Vec<String>,
        files: Vec<String>,
        path: Vec<String>,
    }

    fn under_test(attrs: &[syn::Attribute]) -> bool {
        attrs.iter().any(|a| {
            a.path().is_ident("cfg")
                && matches!(&a.meta, syn::Meta::List(l)
                    if l.tokens.to_string().split_whitespace().collect::<String>() == "test")
        })
    }

    impl Defined {
        fn read(text: &str) -> Self {
            let file = syn::parse_file(text).unwrap();
            let mut found = Self::default();
            if !under_test(&file.attrs) {
                syn::visit::Visit::visit_file(&mut found, &file);
            }
            found
        }

        fn name(&self, last: &str) -> String {
            self.path
                .iter()
                .map(String::as_str)
                .chain([last])
                .collect::<Vec<_>>()
                .join("::")
        }
    }

    impl<'ast> syn::visit::Visit<'ast> for Defined {
        fn visit_item(&mut self, item: &'ast syn::Item) {
            let attrs: &[syn::Attribute] = match item {
                syn::Item::Mod(m) => &m.attrs,
                syn::Item::Fn(f) => &f.attrs,
                syn::Item::Impl(i) => &i.attrs,
                syn::Item::Trait(t) => &t.attrs,
                syn::Item::Macro(m) => &m.attrs,
                syn::Item::Use(u) => &u.attrs,
                syn::Item::Const(c) => &c.attrs,
                syn::Item::Static(s) => &s.attrs,
                syn::Item::Struct(s) => &s.attrs,
                syn::Item::Enum(e) => &e.attrs,
                syn::Item::Type(t) => &t.attrs,
                _ => &[],
            };
            if under_test(attrs) {
                return;
            }
            match item {
                syn::Item::Mod(m) => {
                    let ident = m.ident.to_string();
                    if m.content.is_none() {
                        self.files.push(self.name(&ident));
                    }
                    self.path.push(ident);
                    syn::visit::visit_item_mod(self, m);
                    self.path.pop();
                }
                syn::Item::Fn(f) => {
                    self.bodies.push(self.name(&f.sig.ident.to_string()));
                    syn::visit::visit_item_fn(self, f);
                }
                syn::Item::Impl(i) => {
                    let ty = i.self_ty.as_ref();
                    let ty = quote_type(ty);
                    for inner in &i.items {
                        if let syn::ImplItem::Fn(f) = inner {
                            if !under_test(&f.attrs) {
                                self.bodies
                                    .push(self.name(&format!("{ty}::{}", f.sig.ident)));
                            }
                        }
                    }
                    syn::visit::visit_item_impl(self, i);
                }
                syn::Item::Trait(t) => {
                    for inner in &t.items {
                        if let syn::TraitItem::Fn(f) = inner {
                            if f.default.is_some() {
                                self.bodies
                                    .push(self.name(&format!("{}::{}", t.ident, f.sig.ident)));
                            }
                        }
                    }
                    syn::visit::visit_item_trait(self, t);
                }
                syn::Item::Macro(m) => {
                    let mac = m.mac.path.segments.last().map(|s| s.ident.to_string());
                    self.refused
                        .push(self.name(&format!("{}!", mac.unwrap_or_default())));
                }
                _ => syn::visit::visit_item(self, item),
            }
        }

        fn visit_macro(&mut self, mac: &'ast syn::Macro) {
            if mac.path.is_ident("include") {
                self.refused.push(self.name("include!"));
            }
        }

        fn visit_attribute(&mut self, attr: &'ast syn::Attribute) {
            if attr.path().is_ident("path") {
                self.refused.push(self.name("#[path]"));
            }
        }
    }

    fn quote_type(ty: &syn::Type) -> String {
        match ty {
            syn::Type::Path(p) => p
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default(),
            _ => "impl".to_owned(),
        }
    }

    #[test]
    fn this_file_holds_no_copy_of_server_code_but_these() {
        let found = Defined::read(include_str!("lib.rs"));
        let mut bodies = found.bodies.clone();
        bodies.sort();
        let mut copies: Vec<String> = COPIES.iter().map(|c| c.to_string()).collect();
        copies.sort();
        assert_eq!(bodies, copies, "functions with a body in lib.rs");
        assert!(found.refused.is_empty(), "{:?}", found.refused);
        let mut files = found.files.clone();
        files.sort();
        assert_eq!(files, SHARED, "modules of their own files");
    }

    /// Each way to put a copy here is found, in any spacing or over several lines; re-exports,
    /// constants and test code are not.
    #[test]
    fn every_way_to_put_a_copy_here_is_found() {
        let fine = Defined::read(
            r#"
            pub mod upstream_url;
            pub mod rewrite_fuzz {
                pub use crate::upstream_rewrite::{rewrite_ansible_urls, rewrite_registration_urls};
                pub const UP: &str = "https://up.invalid";
                pub type Out = String;
                #[cfg(test)]
                mod tests {
                    fn helper() {}
                    #[test]
                    fn t() { helper() }
                }
            }
            #[cfg(test)]
            fn only_in_tests() {}
            "#,
        );
        assert!(fine.bodies.is_empty(), "{:?}", fine.bodies);
        assert!(fine.refused.is_empty(), "{:?}", fine.refused);
        assert_eq!(fine.files, ["upstream_url"]);

        for (bad, name) in [
            ("pub fn f() {}", "f"),
            (
                "pub mod rewrite_fuzz {\n    fn replace_url_escape_aware(\n        t: &str,\n    ) -> String { t.into() }\n}",
                "rewrite_fuzz::replace_url_escape_aware",
            ),
            (
                "pub mod a { pub mod b { pub(crate) const fn g() -> u8 { 1 } } }",
                "a::b::g",
            ),
            (
                "pub mod a { pub struct S; impl S { pub fn m(&self) {} } }",
                "a::S::m",
            ),
            (
                "pub mod a { pub trait T { fn d(&self) -> u8 { 1 } } }",
                "a::T::d",
            ),
            (
                "pub mod a { #[cfg(not(test))] pub fn h() {} }",
                "a::h",
            ),
            (
                "pub mod a { #[cfg(any(test, fuzzing))] pub fn h() {} }",
                "a::h",
            ),
        ] {
            assert_eq!(Defined::read(bad).bodies, [name], "{bad}");
        }
        for (bad, name) in [
            (
                "pub mod a { macro_rules! m { () => { fn f() {} } } }",
                "a::macro_rules!",
            ),
            (
                "pub mod a { copy_of!(rewrite_ansible_urls); }",
                "a::copy_of!",
            ),
            (
                "pub mod a { pub const X: &str = include!(\"../src/x.rs\"); }",
                "a::include!",
            ),
            (
                "#[path = \"registry/ansible.rs\"]\npub mod ansible;",
                "ansible::#[path]",
            ),
        ] {
            assert!(
                Defined::read(bad).refused.contains(&name.to_owned()),
                "{bad}: {:?}",
                Defined::read(bad).refused
            );
        }
        assert_eq!(Defined::read("pub mod a { mod copy; }").files, ["a::copy"]);
    }
}
