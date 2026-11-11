// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Maven repository paths and versions: what a path addresses, which files are checksums or
//! snapshots, how versions order. Without I/O, defined once here for the server and the fuzz
//! targets alike.

use crate::validation::ends_with_ci;

/// `group/artifact/version/file`, as the path spells them.
pub struct MavenCoordinates {
    pub group_path: String,
    pub artifact_id: String,
    pub version: String,
    pub filename: String,
}

/// What a Maven repository path addresses.
pub enum MavenPathKind {
    VersionFile(MavenCoordinates),
    ArtifactMeta {
        group_path: String,
        artifact_id: String,
        filename: String,
    },
    Opaque,
}

pub fn classify_path(path: &str) -> MavenPathKind {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    if segments.len() < 2 {
        return MavenPathKind::Opaque;
    }

    let last = segments[segments.len() - 1];

    if (last == "maven-metadata.xml" || last.starts_with("maven-metadata.xml."))
        && segments.len() >= 2
    {
        return MavenPathKind::ArtifactMeta {
            group_path: segments[..segments.len() - 2].join("/"),
            artifact_id: segments[segments.len() - 2].to_string(),
            filename: last.to_string(),
        };
    }

    if segments.len() >= 4 {
        return MavenPathKind::VersionFile(MavenCoordinates {
            group_path: segments[..segments.len() - 3].join("/"),
            artifact_id: segments[segments.len() - 3].to_string(),
            version: segments[segments.len() - 2].to_string(),
            filename: last.to_string(),
        });
    }

    MavenPathKind::Opaque
}

pub fn is_checksum_file(filename: &str) -> bool {
    ends_with_ci(filename, ".md5")
        || ends_with_ci(filename, ".sha1")
        || ends_with_ci(filename, ".sha256")
        || ends_with_ci(filename, ".sha512")
}

pub fn is_snapshot(version: &str) -> bool {
    version.ends_with("-SNAPSHOT")
}

/// Compare Maven versions: split on `.`/`-`, compare numeric segments numerically.
/// SNAPSHOT sorts before release for the same base version.
pub fn compare_maven_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let a_base = a.strip_suffix("-SNAPSHOT").unwrap_or(a);
    let b_base = b.strip_suffix("-SNAPSHOT").unwrap_or(b);

    let a_parts: Vec<&str> = a_base.split(['.', '-']).collect();
    let b_parts: Vec<&str> = b_base.split(['.', '-']).collect();

    for (ap, bp) in a_parts.iter().zip(b_parts.iter()) {
        let ord = match (ap.parse::<u64>(), bp.parse::<u64>()) {
            (Ok(an), Ok(bn)) => an.cmp(&bn),
            _ => ap.cmp(bp),
        };
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
    }

    // If all compared parts equal, shorter version is less (1.0 < 1.0.1)
    let base_ord = a_parts.len().cmp(&b_parts.len());
    if base_ord != std::cmp::Ordering::Equal {
        return base_ord;
    }

    // Same base: SNAPSHOT before release (1.0-SNAPSHOT < 1.0)
    let a_snap = a.ends_with("-SNAPSHOT");
    let b_snap = b.ends_with("-SNAPSHOT");
    b_snap.cmp(&a_snap)
}

/// Escape XML special characters in interpolated values.
pub fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
