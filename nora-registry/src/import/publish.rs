//! Commit step for the formats NORA hosts through a publish API (C73): an npm
//! tarball, a `.nupkg` or a PyPI distribution file goes through the same storage
//! internals as `npm publish`, `dotnet nuget push` or `twine upload`
//! (`npm::publish_versions`, `nuget::hosted::import_package`, `pypi::store_file`),
//! so an imported package is served exactly like an uploaded one. Maven and Raw
//! keep the plain write of the file at its mapped key.
//!
//! [`prepare`] reads and validates the package before the dry-run cut-off, so a
//! rehearsal reports a package the publish path would refuse; [`commit`] writes it.
//! A version that is already hosted is a skip, not a failure: a rerun after a lost
//! journal line (or a package pushed by other means) must not stall the repo.

use std::io::Read;
use std::path::Path;

use axum::body::Bytes;
use axum::http::StatusCode;
use base64::Engine as _;
use sha2::Digest;

use super::ArtifactRef;
use crate::registry::{npm, nuget::hosted, pypi};
use crate::registry_type::RegistryType;
use crate::storage::Storage;

/// Cap on a manifest (`package.json`, `PKG-INFO`) read out of an archive.
const MAX_MANIFEST_BYTES: u64 = 16 << 20;

/// A verified artifact, read and validated for its commit.
pub(super) enum Prepared {
    /// Maven / Raw: the file is stored at the mapped key as-is.
    File,
    Npm {
        package: String,
        version: String,
        /// The version document: the tarball's `package.json` plus `_id` and `dist`.
        doc: serde_json::Value,
        file: String,
        tarball: Bytes,
    },
    Nuget(hosted::Parsed),
    Pypi {
        project: String,
        filename: String,
        core_meta: Option<Vec<u8>>,
        requires_python: String,
    },
}

/// What [`commit`] did.
pub(super) enum Committed {
    Stored,
    /// The version or file is hosted already; nothing written.
    AlreadyHosted(String),
}

/// Read and validate the staged file at `temp` for its format's publish path.
pub(super) async fn prepare(
    rt: RegistryType,
    art: &ArtifactRef,
    temp: &Path,
) -> Result<Prepared, String> {
    match rt {
        RegistryType::Npm => prepare_npm(art, temp).await,
        RegistryType::Nuget => {
            let path = temp.to_path_buf();
            tokio::task::spawn_blocking(move || hosted::parse_package(&path))
                .await
                .map_err(|e| format!("parse task: {e}"))?
                .map(Prepared::Nuget)
                .map_err(|e| format!("{}: {e}", art.path))
        }
        RegistryType::PyPI => prepare_pypi(art, temp).await,
        _ => Ok(Prepared::File),
    }
}

/// Store a prepared artifact. `key` is the mapped key (written only for
/// [`Prepared::File`]); `temp` is moved into storage or left for the caller's guard.
pub(super) async fn commit(
    prepared: Prepared,
    storage: &Storage,
    locks: &crate::PublishLocks,
    key: &str,
    temp: &Path,
    sha256: &str,
    bytes: u64,
) -> Result<Committed, String> {
    let result = match prepared {
        Prepared::File => {
            return storage
                .put_from_path(key, temp, Some(sha256))
                .await
                .map(|()| Committed::Stored)
                .map_err(|e| format!("commit {key}: {e}"));
        }
        Prepared::Npm {
            package,
            version,
            doc,
            file,
            tarball,
        } => commit_npm(storage, locks, &package, &version, doc, file, tarball).await,
        Prepared::Nuget(parsed) => {
            match hosted::import_package(storage, locks, parsed, temp, sha256, bytes).await {
                Ok(hosted::Stored::Created(_)) => Ok(()),
                Ok(hosted::Stored::Identical(msg)) => return Ok(Committed::AlreadyHosted(msg)),
                Err(e) => Err(e),
            }
        }
        Prepared::Pypi {
            project,
            filename,
            core_meta,
            requires_python,
        } => {
            pypi::store_file(
                storage,
                locks,
                &project,
                &filename,
                temp,
                sha256,
                core_meta,
                &requires_python,
            )
            .await
        }
    };
    match result {
        Ok(()) => Ok(Committed::Stored),
        Err((StatusCode::CONFLICT, msg)) => Ok(Committed::AlreadyHosted(msg)),
        Err((status, msg)) => Err(format!("publish {key}: {status}: {msg}")),
    }
}

/// npm: the version document is the tarball's own `package.json`, whose name must
/// be the package the source path files it under (as publish checks URL vs payload).
async fn prepare_npm(art: &ArtifactRef, temp: &Path) -> Result<Prepared, String> {
    let package = art.path.split("/-/").next().unwrap_or_default().to_string();
    let tarball = Bytes::from(
        tokio::fs::read(temp)
            .await
            .map_err(|e| format!("read {}: {e}", art.path))?,
    );
    let tgz = tarball.clone();
    let manifest = tokio::task::spawn_blocking(move || tgz_root_entry(&tgz, "package.json"))
        .await
        .map_err(|e| format!("read task: {e}"))?
        .ok_or_else(|| format!("{}: no package.json in the tarball", art.path))?;
    let mut doc: serde_json::Value = serde_json::from_slice(&manifest)
        .map_err(|e| format!("{}: package.json: {e}", art.path))?;
    let name = doc.get("name").and_then(|v| v.as_str()).unwrap_or_default();
    if name != package {
        return Err(format!(
            "{}: package.json names {name:?}, not {package:?}",
            art.path
        ));
    }
    let version = doc
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    // The served tarball name; `version` also becomes a storage key segment.
    let short = package.rsplit('/').next().unwrap_or(&package);
    let file = format!("{short}-{version}.tgz");
    if version.is_empty() || !npm::is_valid_attachment_name(&file) {
        return Err(format!("{}: invalid version {version:?}", art.path));
    }
    let obj = doc
        .as_object_mut()
        .ok_or_else(|| format!("{}: package.json is not an object", art.path))?;
    obj.insert("_id".into(), format!("{package}@{version}").into());
    obj.insert(
        "dist".into(),
        serde_json::json!({
            "shasum": hex::encode(sha1::Sha1::digest(&tarball)),
            "integrity": format!(
                "sha512-{}",
                base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(&tarball))
            ),
            // Rewritten by publish to this registry's tarball URL.
            "tarball": "",
        }),
    );
    Ok(Prepared::Npm {
        package,
        version,
        doc,
        file,
        tarball,
    })
}

/// Publish one version under the package's publish lock. `latest` moves to it when
/// it is a release above the current `latest`, as `npm publish` would for the newest
/// release; prereleases leave it alone.
async fn commit_npm(
    storage: &Storage,
    locks: &crate::PublishLocks,
    package: &str,
    version: &str,
    doc: serde_json::Value,
    file: String,
    tarball: Bytes,
) -> Result<(), (StatusCode, String)> {
    let lock = crate::acquire_publish_lock(locks, &format!("npm/{package}/metadata.json"));
    let _guard = lock.lock().await;
    let mut payload = serde_json::json!({ "name": package, "_id": package });
    for field in ["description", "license"] {
        if let Some(v) = doc.get(field) {
            payload[field] = v.clone();
        }
    }
    let latest = storage
        .get(&format!("npm/{package}/dist-tags/latest"))
        .await
        .ok()
        .map(|b| String::from_utf8_lossy(&b).into_owned());
    let release = npm::semver_key(version);
    if release.3 && latest.is_none_or(|l| release > npm::semver_key(&l)) {
        payload["dist-tags"] = serde_json::json!({ "latest": version });
    }
    payload["versions"] = serde_json::json!({ version: doc });
    // An unknown-origin packument at the key is never imported from here: the operator decides.
    npm::publish_versions(
        storage,
        locks,
        package,
        &payload,
        vec![(file, tarball)],
        false,
    )
    .await
}

/// PyPI: project and version come from the filename (as an upload checks them
/// against its form fields); `Requires-Python` from the wheel's `METADATA` or the
/// sdist's `PKG-INFO`.
async fn prepare_pypi(art: &ArtifactRef, temp: &Path) -> Result<Prepared, String> {
    let filename = art.name.clone();
    let project = pypi::split_dist_filename(&filename)
        .filter(|_| pypi::is_valid_pypi_filename(&filename))
        .map(|(dist, _)| pypi::normalize_name(dist))
        .ok_or_else(|| format!("{}: not a distribution filename", art.path))?;
    let path = temp.to_path_buf();
    let lower = filename.to_ascii_lowercase();
    let (core_meta, pkg_info) = tokio::task::spawn_blocking(move || {
        if lower.ends_with(".whl") {
            let meta = std::fs::File::open(&path)
                .ok()
                .and_then(|f| pypi::wheel_core_metadata(std::io::BufReader::new(f)));
            (meta, None)
        } else if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
            let info = std::fs::read(&path)
                .ok()
                .and_then(|data| tgz_root_entry(&data, "PKG-INFO"));
            (None, info)
        } else {
            (None, None)
        }
    })
    .await
    .map_err(|e| format!("read task: {e}"))?;
    let requires_python = core_meta
        .as_deref()
        .or(pkg_info.as_deref())
        .and_then(pypi::metadata_requires_python)
        .unwrap_or_default();
    Ok(Prepared::Pypi {
        project,
        filename,
        core_meta,
        requires_python,
    })
}

/// `<top-level dir>/<name>` out of a `.tar.gz` (npm's `package/package.json`, an
/// sdist's `<name>-<version>/PKG-INFO`), capped at [`MAX_MANIFEST_BYTES`].
fn tgz_root_entry(data: &[u8], name: &str) -> Option<Vec<u8>> {
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(data));
    for entry in archive.entries().ok()? {
        let entry = entry.ok()?;
        let at_root = entry.path().ok().is_some_and(|p| {
            let mut parts = p.components();
            parts.next().is_some()
                && parts.next().is_some_and(|c| c.as_os_str() == name)
                && parts.next().is_none()
        });
        if at_root {
            let mut out = Vec::new();
            entry
                .take(MAX_MANIFEST_BYTES + 1)
                .read_to_end(&mut out)
                .ok()?;
            return (out.len() as u64 <= MAX_MANIFEST_BYTES).then_some(out);
        }
    }
    None
}

#[cfg(test)]
pub(super) mod fixtures {
    //! Minimal package files for the import tests.

    use std::io::Write;

    /// A `.tar.gz` with the given `(path, content)` entries.
    pub fn tgz(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        for (path, content) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, path, content.as_bytes())
                .unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    /// A zip (wheel) with the given `(path, content)` entries.
    pub fn zip(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (path, content) in entries {
            w.start_file(*path, zip::write::SimpleFileOptions::default())
                .unwrap();
            w.write_all(content.as_bytes()).unwrap();
        }
        w.finish().unwrap().into_inner()
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::tgz;
    use super::*;

    #[test]
    fn tgz_root_entry_reads_only_one_level_deep() {
        let data = tgz(&[
            ("package/lib/package.json", "{\"nested\":true}"),
            ("package/package.json", "{\"name\":\"x\"}"),
        ]);
        assert_eq!(
            tgz_root_entry(&data, "package.json").as_deref(),
            Some(&b"{\"name\":\"x\"}"[..])
        );
        assert_eq!(tgz_root_entry(&data, "PKG-INFO"), None);
        assert_eq!(tgz_root_entry(b"not gzip", "package.json"), None);
    }
}
