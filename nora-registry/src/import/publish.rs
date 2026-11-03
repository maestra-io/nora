//! Maestra: what `twine upload` records beside a PyPI file and the import's own flow
//! (`transfer`) would otherwise drop — a wheel's core metadata (PEP 658) and the file's
//! `Requires-Python` — read from the staged file, never from storage (the import reads
//! storage only through `under_key`). Written by `pypi::store_import_metadata`.

use std::io::Read;
use std::path::Path;

/// Cap on a manifest (`PKG-INFO`) read out of an archive.
const MAX_MANIFEST_BYTES: u64 = 16 << 20;

/// The core metadata (a wheel's `.dist-info/METADATA`) and `Requires-Python` (empty = none)
/// of the PyPI distribution file `filename` staged at `temp`. Unreadable = none of either.
pub(super) async fn staged_pypi_metadata(filename: &str, temp: &Path) -> (Option<Vec<u8>>, String) {
    use crate::registry::pypi;
    let path = temp.to_path_buf();
    let lower = filename.to_ascii_lowercase();
    let read = tokio::task::spawn_blocking(move || {
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
    .await;
    let Ok((core_meta, pkg_info)) = read else {
        return (None, String::new());
    };
    let requires_python = core_meta
        .as_deref()
        .or(pkg_info.as_deref())
        .and_then(pypi::metadata_requires_python)
        .unwrap_or_default();
    (core_meta, requires_python)
}

/// `<top-level dir>/<name>` out of a `.tar.gz` (an sdist's `<name>-<version>/PKG-INFO`),
/// capped at [`MAX_MANIFEST_BYTES`].
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
