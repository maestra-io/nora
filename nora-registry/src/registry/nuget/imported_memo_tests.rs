// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::*;
use crate::test_helpers::op_counting_storage;

/// R4-P01: "is this ID imported?" cost a LIST on every request (two on a version
/// list under the metadata filter). A proxied ID now costs one per
/// `EMPTY_PREFIX_TTL`; and an ID whose marker or record is written through this
/// process is hosted for the very next request, never answered from memory as proxied.
#[tokio::test]
async fn proxied_id_is_listed_once_and_an_import_is_seen_at_once() {
    let (storage, ops) = op_counting_storage();
    let lists = || ops.calls("list", "nuget/hosted/newtonsoft.json/");
    for _ in 0..5 {
        let versions = hosted_versions(&storage, "newtonsoft.json").await.unwrap();
        assert!(!versions.hosted());
    }
    assert_eq!(lists(), 1, "five requests, one LIST: {:?}", ops.snapshot());

    storage
        .put(&hosted_marker_key("newtonsoft.json"), b"")
        .await
        .unwrap();
    assert!(
        hosted_versions(&storage, "newtonsoft.json")
            .await
            .unwrap()
            .hosted(),
        "hosted from the moment the marker write is acknowledged"
    );
    assert_eq!(lists(), 2);
}
