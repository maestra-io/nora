//! Layout translation: source (Artifactory/Nexus) format + artifact → NORA
//! storage key (#599, review R7).
//!
//! The load-bearing rule (contract `import-key-format-equals-handler-key-format`):
//! import MUST write keys in the **same format the format's handler serves**, or
//! GC/retention/UI browse — which walk keys as strings (regression-map semantic
//! row) — will not see the import. For Maven and Raw (Full support) this module
//! calls the handler's own `storage_key` builder directly (the single source of
//! truth). npm, NuGet and PyPI (Partial) are not written by key at all: the
//! transfer step hands each verified file to the format's own publish internals
//! (`import::publish`), so the import writes exactly what `npm publish`,
//! `dotnet nuget push` or `twine upload` would. Their key here is the resume
//! journal's identity for the artifact (for npm and PyPI also the key the file
//! lands at). Unsupported formats are **skipped, not failed**.
//!
//! Every source string is tainted: a `repo`/`path` of `../../etc` must never
//! become a raw path. Traversal/empty segments are rejected pre-key-build
//! (defence-in-depth) and every emitted key additionally passes
//! `validate_storage_key`.

use super::ArtifactRef;
use crate::registry_type::RegistryType;
use crate::validation::{ends_with_ci, validate_storage_key};

/// How well a source repo's format maps onto NORA hosted storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Compat {
    /// Every artifact maps 1:1 to a hosted key (Maven, Raw).
    Full,
    /// Package files are re-published through the format's publish path (npm,
    /// NuGet, PyPI); what that path cannot take is not carried ([`note`]).
    Partial,
    /// NORA does not host this format via import — all artifacts skipped.
    Unsupported,
}

/// Normalize a source-reported format string (Artifactory `maven`, Nexus
/// `maven2`/`raw`/`yum`, ...) to a NORA [`RegistryType`], reusing NORA's shared
/// alias table (`registry_type::from_str_opt`). `None` = NORA hosts no such
/// registry.
pub fn normalize_format(src_format: &str) -> Option<RegistryType> {
    RegistryType::from_str_opt(src_format)
}

/// Compatibility class for a normalized format — drives the `assess` table and
/// whether `run` attempts a key.
pub fn compat(rt: RegistryType) -> Compat {
    match rt {
        RegistryType::Maven | RegistryType::Raw => Compat::Full,
        RegistryType::Npm | RegistryType::Nuget | RegistryType::PyPI => Compat::Partial,
        _ => Compat::Unsupported,
    }
}

/// What a Partial import does not carry over, for the `assess` table.
pub fn note(rt: RegistryType) -> &'static str {
    match rt {
        RegistryType::Npm => {
            "re-published from each tarball's package.json; only `latest` (highest release) \
             is tagged, other dist-tags and publish times are not carried"
        }
        RegistryType::Nuget => {
            "pushed to the hosted feed; publish time and unlisted state are not carried; \
             a running server needs POST /api/v1/admin/reindex"
        }
        RegistryType::PyPI => "uploaded as by twine; yanked state is not carried",
        _ => "",
    }
}

/// Outcome of mapping one source artifact to a NORA storage key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mapping {
    /// Import under this key (already passed `validate_storage_key`).
    Key(String),
    /// Recognized but intentionally not imported (cache-only metadata NORA
    /// regenerates, or a format NORA does not host) → count `skipped`.
    Skip(&'static str),
    /// Source-controlled path is unsafe/invalid (traversal, absolute, empty
    /// segment, bad key) → count `failed`; fail-closed, never emit a raw path.
    Reject(String),
}

/// Map `(format, artifact)` to a NORA key, reusing each handler's own key
/// builder so the import is byte-identical to what the handler serves.
pub fn map_artifact(rt: RegistryType, art: &ArtifactRef) -> Mapping {
    // Defence-in-depth: reject traversal/empty segments in the tainted source
    // strings BEFORE building a key. `validate_storage_key` allows `//` (empty
    // segments) and only catches `..`; we are stricter here so a crafted source
    // path cannot slip an empty/`.` segment into a control key.
    for (label, s) in [("repo", art.repo.as_str()), ("path", art.path.as_str())] {
        if let Some(bad) = first_unsafe_segment(s) {
            return Mapping::Reject(format!("unsafe {label} segment {bad:?} in {s:?}"));
        }
    }

    let key = match rt {
        // Maven coordinates are a global namespace in NORA (the source repo name
        // is dropped — a Maven client fetches `maven/<group>/<artifact>/...`).
        RegistryType::Maven => crate::registry::maven_storage_key(&art.path),
        // Raw has no global coordinate scheme, so fold the source repo into the
        // path to avoid cross-repo collisions; still a valid `raw/<...>` key the
        // Raw handler serves for request path `<repo>/<path>`.
        RegistryType::Raw => crate::registry::raw_storage_key(&join_repo(&art.repo, &art.path)),
        // npm: tarballs only; the packument is built from each tarball's package.json.
        RegistryType::Npm => match npm_tarball_key(&art.path) {
            Some(k) => k,
            None => {
                return Mapping::Skip(
                    "npm non-tarball asset (metadata is rebuilt from the tarballs)",
                )
            }
        },
        // NuGet: `.nupkg` only; the hosted keys come from its nuspec, so the key is
        // the journal identity of the source file.
        RegistryType::Nuget if ends_with_ci(&art.name, ".nupkg") => {
            format!("nuget/{}", join_repo(&art.repo, &art.path))
        }
        RegistryType::Nuget => return Mapping::Skip("NuGet asset that is not a .nupkg"),
        // PyPI: distribution files, at the key an upload of the file writes.
        RegistryType::PyPI => match pypi_file_key(&art.name) {
            Some(k) => k,
            None => return Mapping::Skip("PyPI asset that is not a distribution file"),
        },
        _ => return Mapping::Skip("format not hosted by NORA import"),
    };

    match validate_storage_key(&key) {
        Ok(()) => Mapping::Key(key),
        Err(e) => Mapping::Reject(format!("invalid storage key {key:?}: {e}")),
    }
}

/// Build the npm tarball key `npm/<package>/tarballs/<file>` from a source asset
/// path (`<package>/-/<file>.tgz`, scoped `@scope/<pkg>/-/<file>.tgz` or, as
/// Artifactory stores it, `@scope/<pkg>/-/@scope/<file>.tgz`). Returns `None` for
/// non-tarball npm assets (package metadata).
///
/// MUST match the tarball key the npm handler serves
/// (`registry/npm.rs`: `format!("npm/{}/tarballs/{}", package, file)`); pinned by
/// the `npm_key_matches_handler_format` test.
fn npm_tarball_key(path: &str) -> Option<String> {
    let (package, file) = path.split_once("/-/")?;
    // Publish strips the same scope prefix from a scoped attachment name.
    let file = match package.split_once('/') {
        Some((scope, _)) => file
            .strip_prefix(scope)
            .and_then(|f| f.strip_prefix('/'))
            .unwrap_or(file),
        None => file,
    };
    if package.is_empty() || file.is_empty() || file.contains('/') || !file.ends_with(".tgz") {
        return None;
    }
    Some(format!("npm/{package}/tarballs/{file}"))
}

/// `pypi/<normalized project>/<file>` for a distribution filename (the key an
/// upload writes); `None` for anything else (index pages, signatures).
fn pypi_file_key(name: &str) -> Option<String> {
    use crate::registry::pypi;
    if !pypi::is_valid_pypi_filename(name) {
        return None;
    }
    let (dist, _) = pypi::split_dist_filename(name)?;
    Some(format!("pypi/{}/{name}", pypi::normalize_name(dist)))
}

/// Join a source repo name and a repo-relative path into one relative path,
/// trimming stray separators (both are pre-validated by [`first_unsafe_segment`]).
fn join_repo(repo: &str, path: &str) -> String {
    let repo = repo.trim_matches('/');
    let path = path.trim_start_matches('/');
    if repo.is_empty() {
        path.to_string()
    } else {
        format!("{repo}/{path}")
    }
}

/// First segment of `path` that must never reach key construction from a tainted
/// source string (empty, `.`, `..`, backslash, or NUL). `None` = safe.
fn first_unsafe_segment(path: &str) -> Option<&str> {
    if path.is_empty() {
        return Some("");
    }
    path.split('/').find(|seg| {
        seg.is_empty() || *seg == "." || *seg == ".." || seg.contains('\\') || seg.contains('\0')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn art(repo: &str, path: &str) -> ArtifactRef {
        ArtifactRef {
            repo: repo.to_string(),
            path: path.to_string(),
            name: path.rsplit('/').next().unwrap_or(path).to_string(),
            size: None,
            sha256: None,
            sha1: None,
        }
    }

    #[test]
    fn normalize_covers_source_aliases() {
        assert_eq!(normalize_format("maven"), Some(RegistryType::Maven));
        assert_eq!(normalize_format("maven2"), Some(RegistryType::Maven)); // Nexus
        assert_eq!(normalize_format("raw"), Some(RegistryType::Raw));
        assert_eq!(normalize_format("npm"), Some(RegistryType::Npm));
        assert_eq!(normalize_format("yum"), Some(RegistryType::Rpm));
        assert_eq!(normalize_format("docker"), Some(RegistryType::Docker));
        assert_eq!(normalize_format("nonsense"), None);
    }

    #[test]
    fn compat_classes() {
        assert_eq!(compat(RegistryType::Maven), Compat::Full);
        assert_eq!(compat(RegistryType::Raw), Compat::Full);
        assert_eq!(compat(RegistryType::Npm), Compat::Partial);
        assert_eq!(compat(RegistryType::Nuget), Compat::Partial);
        assert_eq!(compat(RegistryType::PyPI), Compat::Partial);
        assert_eq!(compat(RegistryType::Cargo), Compat::Unsupported);
        assert_eq!(compat(RegistryType::Docker), Compat::Unsupported);
    }

    #[test]
    fn maven_key_matches_handler_and_drops_repo() {
        let a = art("libs-release-local", "com/example/foo/1.0/foo-1.0.jar");
        // Reuses the handler's builder; repo dropped (global Maven namespace).
        assert_eq!(
            map_artifact(RegistryType::Maven, &a),
            Mapping::Key("maven/com/example/foo/1.0/foo-1.0.jar".to_string())
        );
    }

    #[test]
    fn raw_key_matches_handler_and_folds_repo() {
        let a = art("configs", "app/prod/settings.yaml");
        assert_eq!(
            map_artifact(RegistryType::Raw, &a),
            Mapping::Key("raw/configs/app/prod/settings.yaml".to_string())
        );
    }

    #[test]
    fn npm_tarball_maps_scoped_and_unscoped() {
        assert_eq!(
            map_artifact(
                RegistryType::Npm,
                &art("npm-local", "left-pad/-/left-pad-1.3.0.tgz")
            ),
            Mapping::Key("npm/left-pad/tarballs/left-pad-1.3.0.tgz".to_string())
        );
        assert_eq!(
            map_artifact(
                RegistryType::Npm,
                &art("npm-local", "@babel/core/-/core-7.0.0.tgz")
            ),
            Mapping::Key("npm/@babel/core/tarballs/core-7.0.0.tgz".to_string())
        );
    }

    #[test]
    fn npm_artifactory_scoped_tarball_strips_scope_dir() {
        assert_eq!(
            map_artifact(
                RegistryType::Npm,
                &art(
                    "npm-local",
                    "@mindbox-cloud/ui/-/@mindbox-cloud/ui-1.2.0.tgz"
                )
            ),
            Mapping::Key("npm/@mindbox-cloud/ui/tarballs/ui-1.2.0.tgz".to_string())
        );
        // Another scope's directory is not stripped: not a flat file name, skipped.
        assert!(matches!(
            map_artifact(RegistryType::Npm, &art("npm", "@a/ui/-/@b/ui-1.0.0.tgz")),
            Mapping::Skip(_)
        ));
    }

    #[test]
    fn nuget_and_pypi_map_package_files_only() {
        assert_eq!(
            map_artifact(
                RegistryType::Nuget,
                &art("nuget-local", "Mindbox.Foo.1.2.3.nupkg")
            ),
            Mapping::Key("nuget/nuget-local/Mindbox.Foo.1.2.3.nupkg".to_string())
        );
        assert!(matches!(
            map_artifact(
                RegistryType::Nuget,
                &art("nuget-local", "Mindbox.Foo.1.2.3.snupkg")
            ),
            Mapping::Skip(_)
        ));
        assert_eq!(
            map_artifact(
                RegistryType::PyPI,
                &art(
                    "pypi-local",
                    "Mindbox_SDK/1.0/mindbox_sdk-1.0-py3-none-any.whl"
                )
            ),
            Mapping::Key("pypi/mindbox-sdk/mindbox_sdk-1.0-py3-none-any.whl".to_string())
        );
        assert!(matches!(
            map_artifact(
                RegistryType::PyPI,
                &art("pypi-local", ".pypi/mindbox-sdk.html")
            ),
            Mapping::Skip(_)
        ));
    }

    #[test]
    fn npm_key_matches_handler_format() {
        // Pins the coupling to registry/npm.rs (which inlines this literal at its
        // serve + upload sites). If the handler format changes, this must too.
        let handler_literal = format!("npm/{}/tarballs/{}", "left-pad", "left-pad-1.3.0.tgz");
        assert_eq!(
            npm_tarball_key("left-pad/-/left-pad-1.3.0.tgz"),
            Some(handler_literal)
        );
    }

    #[test]
    fn npm_non_tarball_is_skipped_not_failed() {
        // Package metadata document (no `/-/`) — NORA regenerates it.
        match map_artifact(RegistryType::Npm, &art("npm-local", "left-pad")) {
            Mapping::Skip(_) => {}
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn unsupported_format_is_skipped() {
        match map_artifact(
            RegistryType::Cargo,
            &art("crates", "some/crate-1.0.0.crate"),
        ) {
            Mapping::Skip(_) => {}
            other => panic!("expected Skip, got {other:?}"),
        }
    }

    #[test]
    fn traversal_in_path_is_rejected() {
        for bad in [
            "../../etc/passwd",
            "a/../../b",
            "/abs/path",
            "a//b",
            "a/./b",
        ] {
            match map_artifact(RegistryType::Maven, &art("r", bad)) {
                Mapping::Reject(_) => {}
                other => panic!("expected Reject for {bad:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn traversal_in_repo_is_rejected() {
        match map_artifact(RegistryType::Raw, &art("../../etc", "file")) {
            Mapping::Reject(_) => {}
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    #[test]
    fn npm_malformed_tarball_paths() {
        // Slash inside the file component → npm_tarball_key returns None → Skip.
        assert!(matches!(
            map_artifact(RegistryType::Npm, &art("npm", "pkg/-/nested/file.tgz")),
            Mapping::Skip(_)
        ));
        // A trailing empty segment is caught earlier as unsafe → Reject.
        assert!(matches!(
            map_artifact(RegistryType::Npm, &art("npm", "pkg/-/")),
            Mapping::Reject(_)
        ));
    }

    #[test]
    fn empty_path_is_rejected() {
        assert!(matches!(
            map_artifact(RegistryType::Maven, &art("r", "")),
            Mapping::Reject(_)
        ));
    }

    use proptest::prelude::*;

    proptest! {
        // Any path built from safe segments maps to a key that passes the real
        // storage validator — the import can never emit an invalid Maven key.
        #[test]
        fn maven_keys_always_validate(
            segs in prop::collection::vec("[a-zA-Z0-9._-]{1,12}", 1..6)
        ) {
            let path = segs.join("/");
            let a = art("repo", &path);
            match map_artifact(RegistryType::Maven, &a) {
                Mapping::Key(k) => {
                    prop_assert!(validate_storage_key(&k).is_ok());
                    prop_assert!(k.starts_with("maven/"));
                }
                // A segment could still be a lone "." — that's a legal Reject.
                Mapping::Reject(_) => {}
                Mapping::Skip(s) => prop_assert!(false, "unexpected skip: {s}"),
            }
        }
    }
}
