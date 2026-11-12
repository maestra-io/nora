// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

//! The supervisor and the maintenance heartbeat the server runs with, as `supervision`
//! builds them from the server configuration, on tokio's paused clock: the windows are
//! whole seconds and minutes.
use super::{run_maintenance, supervision, MAINTENANCE_PERIOD};
use crate::config::ServerConfig;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

const SECOND: Duration = Duration::from_secs(1);

/// `/health` fails once no tick has completed for the whole configured window, and not a
/// second before: the default, the smallest the configuration accepts and longer ones.
#[tokio::test(start_paused = true)]
async fn the_stall_window_is_the_whole_configured_window() {
    let default = ServerConfig::default().maintenance_stall_secs;
    assert_eq!(default, 300);
    for secs in [default, 90, 600, 3600] {
        let server = ServerConfig {
            maintenance_stall_secs: secs,
            ..ServerConfig::default()
        };
        let (tasks, heartbeat) = supervision(&server);
        assert_eq!(heartbeat.max_silence(), SECOND * secs as u32);
        tokio::time::sleep(SECOND * (secs as u32 - 1)).await;
        assert_eq!(tasks.failing(), None, "{secs} s window, 1 s before");
        tokio::time::sleep(SECOND * 2).await;
        assert_eq!(
            tasks.failing(),
            Some("maintenance"),
            "{secs} s window, 1 s after"
        );
    }
}

/// The server's restart timing: 1 s before the first restart, doubled after each panic up
/// to a minute; a task panicking at every start fails `/health` at its fifth panic, not
/// before.
#[tokio::test(start_paused = true)]
async fn the_server_restarts_a_task_after_a_doubling_backoff_and_flags_the_fifth_panic() {
    let (tasks, _heartbeat) = supervision(&ServerConfig::default());
    let origin = tokio::time::Instant::now();
    let starts = Arc::new(std::sync::Mutex::new(Vec::new()));
    let s = Arc::clone(&starts);
    let task = tasks.spawn("test_server_timing", move || {
        let mut starts = s.lock().unwrap();
        starts.push(origin.elapsed().as_secs());
        // Past twenty runs, a restart without a pause would spin and stop the paused
        // clock: the run then waits, so the test fails on the starts instead of hanging.
        let spinning = starts.len() > 20;
        async move {
            if spinning {
                std::future::pending::<()>().await;
            }
            panic!("a bug in every run")
        }
    });
    // Panics at 0, 1, 3, 7 and 15 s.
    tokio::time::sleep(Duration::from_millis(14_500)).await;
    assert_eq!(tasks.failing(), None, "four panics in a row");
    tokio::time::sleep(SECOND).await;
    assert_eq!(tasks.failing(), Some("test_server_timing"));
    tokio::time::sleep(SECOND * 230).await;
    task.abort();
    assert_eq!(
        *starts.lock().unwrap(),
        [0, 1, 3, 7, 15, 31, 63, 123, 183, 243]
    );
}

/// One panicking maintenance tick, under the supervisor and heartbeat the server runs
/// with, never fails `/health`: the loop restarts and its ticks go on.
#[tokio::test(start_paused = true)]
async fn one_panicking_tick_keeps_liveness_under_the_server_supervisor() {
    let (tasks, heartbeat) = supervision(&ServerConfig::default());
    let runs = Arc::new(AtomicU64::new(0));
    let ticks = Arc::new(AtomicU64::new(0));
    let (r, t, hb) = (
        Arc::clone(&runs),
        Arc::clone(&ticks),
        Arc::clone(&heartbeat),
    );
    let task = tasks.spawn("maintenance", move || {
        let run = r.fetch_add(1, Ordering::SeqCst);
        let t = Arc::clone(&t);
        run_maintenance(MAINTENANCE_PERIOD, Arc::clone(&hb), move |n| {
            let t = Arc::clone(&t);
            async move {
                assert!(!(run == 0 && n == 1), "a bug in the first tick");
                t.fetch_add(1, Ordering::SeqCst);
            }
        })
    });
    for _ in 0..60 {
        tokio::time::sleep(SECOND * 10).await;
        assert_eq!(tasks.failing(), None);
    }
    task.abort();
    assert_eq!(runs.load(Ordering::SeqCst), 2, "restarted once");
    assert!(
        ticks.load(Ordering::SeqCst) >= 19,
        "ticks every 30 s after the restart"
    );
}
