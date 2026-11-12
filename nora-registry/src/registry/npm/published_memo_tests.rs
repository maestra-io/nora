// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::*;
use crate::test_helpers::op_counting_storage;

/// R4-P01: "is this package published here?" cost a LIST and a GET on every proxied
/// tarball, packument and audit name. A proxied package now costs them once per
/// `EMPTY_PREFIX_TTL`; and a version published through this process is seen by the
/// very next request, never answered from memory as "not published" (its name
/// would go to an upstream).
#[tokio::test]
async fn proxied_package_is_asked_once_and_a_publish_is_seen_at_once() {
    let (storage, ops) = op_counting_storage();
    for _ in 0..5 {
        assert!(matches!(
            published_state(&storage, "left-pad").await,
            Published::No
        ));
    }
    assert_eq!(
        ops.calls("list", "npm/left-pad/versions/"),
        1,
        "five requests, one LIST: {:?}",
        ops.snapshot()
    );
    assert_eq!(ops.total(), 2, "and one record read: {:?}", ops.snapshot());

    storage
        .put("npm/left-pad/versions/1.0.0.json", b"{}")
        .await
        .unwrap();
    match published_state(&storage, "left-pad").await {
        Published::Yes(versions) => assert!(versions.contains("1.0.0")),
        _ => panic!("published from the moment the version write is acknowledged"),
    }
}

/// A "no" is remembered only when the store answered about the provenance record:
/// a failed read of it decides this request and is asked again by the next.
#[tokio::test]
async fn unanswered_record_read_is_not_remembered() {
    let (storage, outage) = crate::test_helpers::outage_storage();
    outage.fail_reads_of(&origin_key(&published_packument_key("pkg")));
    assert!(matches!(
        published_state(&storage, "pkg").await,
        Published::No
    ));
    let (_, claim) = storage
        .list_claiming_empty("npm/pkg/versions/")
        .await
        .unwrap();
    assert!(claim.is_some(), "the listing is asked again");
}
