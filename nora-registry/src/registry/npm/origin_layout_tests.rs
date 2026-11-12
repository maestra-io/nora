// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::{origin_key, origin_primary};

/// Sidecars live outside the npm key space: no client key maps onto one, the
/// mapping is one-to-one even for package names that look like layout words, and
/// `list()` (which every older release's retention and GC walk) never shows one.
#[tokio::test]
async fn provenance_is_outside_the_npm_key_space_and_round_trips() {
    let keys = [
        "npm/a/tarballs/a-1.0.0.tgz",
        "npm/@vendor/a/tarballs/a-1.0.0.tgz",
        "npm/@vendor/a/tarballs/@vendor/a-1.0.0.tgz",
        "npm/a/metadata.json",
        "npm/@vendor/a/metadata.json",
        // Package names equal to layout words must not alias anything.
        "npm/origins/metadata.json",
        "npm/origins/tarballs/origins-1.0.0.tgz",
        "npm/@x/origins/metadata.json",
        "npm/tarballs/tarballs/tarballs-1.0.0.tgz",
        "npm/x/tarballs/y/tarballs/z.tgz",
    ];
    let mut seen = std::collections::HashSet::new();
    for key in keys {
        let sidecar = origin_key(key);
        assert!(!sidecar.starts_with("npm/"), "{key} -> {sidecar}");
        assert!(sidecar.starts_with(".nora-"), "{key} -> {sidecar}");
        assert_eq!(origin_primary(&sidecar), Some(key), "{sidecar}");
        assert!(seen.insert(sidecar), "{key}: two keys share a sidecar");
        // A real npm key is never mistaken for a sidecar.
        assert_eq!(origin_primary(key), None, "{key}");
    }
    assert_eq!(origin_primary(".nora-origins/maven/x.jar"), None);

    let dir = tempfile::tempdir().unwrap();
    let storage = crate::Storage::new_local(dir.path().to_str().unwrap());
    storage.put(keys[0], b"tgz").await.unwrap();
    storage
        .put(&origin_key(keys[0]), b"npm:https://r.example")
        .await
        .unwrap();
    assert_eq!(storage.list("").await.unwrap(), vec![keys[0].to_string()]);
    // ...and the internal walk shows only internal keys.
    assert_eq!(
        storage.list_internal(".nora-").await.unwrap(),
        vec![origin_key(keys[0])]
    );
    assert!(storage.list_internal("npm/").await.unwrap().is_empty());
}
