// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

//! The server's own maintenance loop and tick over a store that is slow, silent or
//! large, and a tick cut at its deadline.
use crate::test_helpers::{
    body_bytes, create_test_context_with_auth, create_test_context_with_storage_and_config,
    long_count_storage, outage_storage, send, slow_listing_storage,
};
use axum::http::{Method, StatusCode};
use std::sync::atomic::Ordering;
use std::time::Duration;

/// A large bucket: the first page of its listing answers at once, the whole listing
/// (1.6 s) takes longer than a tick may run (633 ms with a 2 s window). Readiness comes
/// from that first page, so `/ready` turns 200 and stays 200; the size, counted from the
/// whole listing apart from the tick, shows once that listing ends.
#[tokio::test(start_paused = true)]
async fn a_large_bucket_is_ready_and_its_size_follows() {
    let storage = slow_listing_storage(Duration::from_millis(400));
    for i in 0..5 {
        storage
            .put(&format!("raw/big/{i}.bin"), &[0u8; 100])
            .await
            .unwrap();
    }
    let ctx = create_test_context_with_storage_and_config(storage, |c| {
        c.server.maintenance_stall_secs = 2
    });
    super::spawn_maintenance(&ctx.state, Duration::from_millis(100), Vec::new());

    let mut ready = StatusCode::SERVICE_UNAVAILABLE;
    for _ in 0..10 {
        ready = send(&ctx.app, Method::GET, "/ready", "").await.status();
        if ready == StatusCode::OK {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(ready, StatusCode::OK, "ready from the first page");

    let mut size = 0;
    for _ in 0..40 {
        let ready = send(&ctx.app, Method::GET, "/ready", "").await.status();
        assert_eq!(
            ready,
            StatusCode::OK,
            "readiness does not wait for the listing"
        );
        let health = send(&ctx.app, Method::GET, "/health", "").await;
        assert_eq!(health.status(), StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body_bytes(health).await).unwrap();
        size = json["storage"]["total_size_bytes"].as_u64().unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(size >= 500, "the size of the whole listing: {size}");
}

/// Counting the store's size panics, late, every time: the panic is logged and counted
/// under `storage_size`, the next count starts again, and the loop and readiness go on.
#[tokio::test(start_paused = true)]
async fn a_panic_counting_the_size_is_reported_and_the_loop_goes_on() {
    let panics = || {
        super::metrics::TASK_PANICS_TOTAL
            .with_label_values(&["storage_size"])
            .get()
    };
    let before = panics();
    let (storage, outage) = outage_storage();
    outage.panic_counting_size();
    let ctx = create_test_context_with_storage_and_config(storage, |c| {
        c.server.maintenance_stall_secs = 2
    });
    super::spawn_maintenance(&ctx.state, Duration::from_millis(100), Vec::new());

    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(
        panics() - before >= 2,
        "each panic counted, and the count starts again after one"
    );
    assert_eq!(ctx.state.tasks.failing(), None);
    let ready = send(&ctx.app, Method::GET, "/ready", "").await.status();
    assert_eq!(ready, StatusCode::OK, "readiness is not the size count");
}

/// A tick panics once while the size count it started still runs: the loop is restarted,
/// and the restarted loop does not start a second count beside the first.
#[tokio::test(start_paused = true)]
async fn a_restarted_loop_does_not_start_a_second_size_count() {
    let (storage, counts) = long_count_storage();
    let ctx = create_test_context_with_storage_and_config(storage, |_| {});
    super::spawn_maintenance(&ctx.state, Duration::from_millis(50), Vec::new());
    // The server's restart backoff is 1 s; the restarted loop's first tick is an odd one,
    // which starts a count.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(
        counts.probes.load(Ordering::SeqCst) >= 3,
        "the loop runs again after the panicking tick"
    );
    assert_eq!(
        counts.most_counting.load(Ordering::SeqCst),
        1,
        "a second count ran beside the first after the restart"
    );
}

/// A store that accepted the connection and went silent: `/health` stays 200 for
/// twice the stall window, `/ready` is 503; once the store answers again `/ready`
/// turns 200 under the same loop, which never failed.
#[tokio::test(start_paused = true)]
async fn a_silent_store_fails_readiness_not_liveness() {
    let (storage, outage) = outage_storage();
    outage.silence();
    let ctx = create_test_context_with_storage_and_config(storage, |c| {
        c.server.maintenance_stall_secs = 2
    });
    super::spawn_maintenance(&ctx.state, Duration::from_millis(100), Vec::new());

    for _ in 0..45 {
        let health = send(&ctx.app, Method::GET, "/health", "").await;
        assert_eq!(
            health.status(),
            StatusCode::OK,
            "liveness while the store is silent"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let ready = send(&ctx.app, Method::GET, "/ready", "").await;
    assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);

    outage.end();
    let mut ready = StatusCode::SERVICE_UNAVAILABLE;
    for _ in 0..50 {
        ready = send(&ctx.app, Method::GET, "/ready", "").await.status();
        if ready == StatusCode::OK {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(ready, StatusCode::OK, "the store answers again");
    assert_eq!(ctx.state.tasks.failing(), None);
}

/// Poll `/ready` until it answers `want`, at most `polls` times 100 ms apart, asserting
/// `/health` 200 at every poll. Returns the last `/ready` status.
///
/// The local-store tests below run a 6 s stall window: its 1.97 s tick deadline stays
/// above what an fsync usually takes on a busy test host, so only a probe that really does
/// not come back is cut. A tick is 100 ms; the poll budgets cover the deadline and stay far
/// inside the 150 s a verdict takes to expire, so only a tick's probe can turn `/ready`.
/// Turning 200 waits for an fsync, which a loaded host can stretch past the deadline: those
/// budgets are the longer ones, and a passing poll ends them early.
async fn ready_becomes(app: &axum::Router, want: StatusCode, polls: usize) -> StatusCode {
    let mut ready = send(app, Method::GET, "/ready", "").await.status();
    for _ in 0..polls {
        if ready == want {
            break;
        }
        let health = send(app, Method::GET, "/health", "").await;
        assert_eq!(health.status(), StatusCode::OK, "liveness meanwhile");
        tokio::time::sleep(Duration::from_millis(100)).await;
        ready = send(app, Method::GET, "/ready", "").await.status();
    }
    ready
}

/// The local store stops taking writes (a read-only remount, a full disk): the next
/// tick's write probe sees it, so `/ready` turns 503 within a tick while `/health` stays
/// 200; writable again, `/ready` turns 200 under the same loop.
#[cfg(unix)]
#[tokio::test]
async fn an_unwritable_local_store_fails_readiness_within_a_tick() {
    use std::os::unix::fs::PermissionsExt;
    let ctx = crate::test_helpers::create_test_context_with_config(|c| {
        c.server.maintenance_stall_secs = 6
    });
    super::spawn_maintenance(&ctx.state, Duration::from_millis(100), Vec::new());
    let ok = ready_becomes(&ctx.app, StatusCode::OK, 150).await;
    assert_eq!(ok, StatusCode::OK, "writable store");

    let dir = ctx._tempdir.path();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let unwritable = ready_becomes(&ctx.app, StatusCode::SERVICE_UNAVAILABLE, 50).await;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        unwritable,
        StatusCode::SERVICE_UNAVAILABLE,
        "read-only store"
    );

    let ok = ready_becomes(&ctx.app, StatusCode::OK, 150).await;
    assert_eq!(ok, StatusCode::OK, "writable again");
    assert_eq!(ctx.state.tasks.failing(), None);
}

/// Each tick, whatever its number, probes the store: the tick right after the local
/// store turns read-only answers `/ready` 503, the next one after it is writable again
/// answers 200.
#[cfg(unix)]
#[tokio::test]
async fn every_tick_sees_a_local_store_change() {
    use std::os::unix::fs::PermissionsExt;
    let ctx = crate::test_helpers::create_test_context();
    let work = super::MaintenanceWork::new(&ctx.state.tasks, Vec::new());
    let dir = ctx._tempdir.path();
    let ready = || async { send(&ctx.app, Method::GET, "/ready", "").await.status() };

    super::maintenance_tick(&ctx.state, 2, &work).await;
    assert_eq!(ready().await, StatusCode::OK);
    for (tick, mode, want) in [
        (3, 0o500, StatusCode::SERVICE_UNAVAILABLE),
        (4, 0o700, StatusCode::OK),
        (5, 0o500, StatusCode::SERVICE_UNAVAILABLE),
        (6, 0o700, StatusCode::OK),
    ] {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode)).unwrap();
        super::maintenance_tick(&ctx.state, tick, &work).await;
        let got = ready().await;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(got, want, "after tick {tick}");
    }
}

/// The local disk stops answering (the write probe blocks): `/ready` turns 503 once the
/// tick after the cut one finds the probe still waiting, and `/health` stays 200 past the
/// whole stall window; when the disk answers again `/ready` turns 200, under the same loop.
#[tokio::test(flavor = "multi_thread")]
async fn a_hung_local_disk_fails_readiness_not_liveness() {
    let ctx = crate::test_helpers::create_test_context_with_config(|c| {
        c.server.maintenance_stall_secs = 6
    });
    super::spawn_maintenance(&ctx.state, Duration::from_millis(100), Vec::new());
    let ok = ready_becomes(&ctx.app, StatusCode::OK, 150).await;
    assert_eq!(ok, StatusCode::OK, "answering disk");

    let disk = crate::test_helpers::hang_health_probe(ctx._tempdir.path());
    // The probe is cut at the 1.97 s tick deadline; the tick after finds it waiting.
    let hung = ready_becomes(&ctx.app, StatusCode::SERVICE_UNAVAILABLE, 50).await;
    assert_eq!(
        hung,
        StatusCode::SERVICE_UNAVAILABLE,
        "disk that does not answer"
    );
    for _ in 0..65 {
        let health = send(&ctx.app, Method::GET, "/health", "").await;
        assert_eq!(health.status(), StatusCode::OK, "liveness on a hung disk");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    disk.answer();
    let ok = ready_becomes(&ctx.app, StatusCode::OK, 150).await;
    assert_eq!(ok, StatusCode::OK, "the disk answers again");
    assert_eq!(ctx.state.tasks.failing(), None);
}

/// A tick cut while the token `last_used` flush runs (its deadline can fall at any await)
/// does not cut the flush: the timestamps it took still land on disk.
#[tokio::test]
async fn a_cut_tick_finishes_its_token_flush() {
    let ctx = create_test_context_with_auth(&[("admin", "pw")]);
    let tokens = ctx.state.tokens.as_ref().unwrap();
    let token = tokens
        .create_token("admin", 30, None, super::tokens::Role::Read)
        .await
        .unwrap();
    tokens.verify_token(&token).await.unwrap();

    // Polled once and dropped, wherever it was: the flush has taken the pending timestamps.
    let work = super::MaintenanceWork::new(&ctx.state.tasks, Vec::new());
    let _ = futures::FutureExt::now_or_never(super::maintenance_tick(&ctx.state, 2, &work));

    let mut last_used = None;
    for _ in 0..50 {
        last_used = tokens.list_tokens("admin").await[0].last_used;
        if last_used.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(last_used.is_some(), "the flush ran to its end");
}
