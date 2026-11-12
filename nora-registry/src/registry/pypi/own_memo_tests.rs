// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::*;
use crate::test_helpers::op_counting_storage;

/// R4-P01: "is this project NORA's own?" cost a LIST on every request. A proxied
/// project now costs one per `EMPTY_PREFIX_TTL`; and a project made hosted through
/// this process is hosted for the very next request, never answered from memory as
/// proxied (its name would go to an upstream).
#[tokio::test]
async fn proxied_project_is_listed_once_and_a_claim_is_seen_at_once() {
    let (storage, ops) = op_counting_storage();
    let lists = || ops.calls("list", "pypi-own/requests/");
    for _ in 0..5 {
        let records = own_records(&storage, "requests").await.unwrap();
        assert!(!records.hosted());
    }
    assert_eq!(lists(), 1, "five requests, one LIST: {:?}", ops.snapshot());

    claim_imported_project(&storage, "requests").await.unwrap();
    assert!(
        own_records(&storage, "requests").await.unwrap().hosted(),
        "hosted from the moment the claim is acknowledged"
    );
    assert_eq!(lists(), 2);
    // A hosted project is not memoized: its records are read every time.
    assert!(own_records(&storage, "requests").await.unwrap().hosted());
    assert_eq!(lists(), 3);
}
