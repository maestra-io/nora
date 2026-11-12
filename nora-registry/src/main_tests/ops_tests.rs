// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use axum::body::Bytes;

/// A background cache write that fails is logged and counted, for both helpers —
/// it used to vanish, leaving a proxy that silently never caches.
#[tokio::test]
async fn failed_background_cache_writes_are_counted() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("not-a-dir");
    std::fs::write(&file, b"x").unwrap();
    // Storage root below a regular file: every put fails.
    let storage = crate::storage::Storage::new_local(file.join("root").to_str().unwrap());
    let ctx = crate::test_helpers::create_test_context_with_storage(storage);
    let errors = || {
        crate::metrics::CACHE_WRITE_ERRORS
            .with_label_values(&["ops-test", "put"])
            .get()
    };
    let before = errors();
    let data = Bytes::from_static(b"data");
    ctx.state
        .spawn_cache("ops-test", "raw/a".into(), data.clone());
    ctx.state
        .spawn_cache_immutable("ops-test", "raw/b".into(), data);
    for _ in 0..200 {
        if errors() >= before + 2 {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("cache write failures were not counted");
}

/// The release profile must unwind: with `panic = "abort"` every catch_unwind guard
/// and CatchPanicLayer are dead code and one panic kills the only replica.
#[test]
fn release_profile_unwinds() {
    let manifest = include_str!("../../../Cargo.toml");
    assert!(
        !manifest
            .lines()
            .any(|l| l.trim().starts_with("panic = \"abort\"")),
        "profile.release must not set panic = \"abort\""
    );
}

/// A panicking handler behind CatchPanicLayer answers 500 instead of tearing down
/// the connection (and, with unwinding, the process survives).
#[tokio::test]
async fn handler_panic_is_a_500() {
    use tower::ServiceExt;
    async fn boom() -> &'static str {
        panic!("handler bug")
    }
    let app = axum::Router::new()
        .route("/boom", axum::routing::get(boom))
        .layer(tower_http::catch_panic::CatchPanicLayer::new());
    let req = axum::http::Request::get("/boom")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
}
