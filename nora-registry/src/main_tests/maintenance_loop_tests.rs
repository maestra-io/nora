// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

//! The maintenance loop under its supervisor: a panicking tick restarts the
//! loop, ticks that never complete and a hung tick fail `/health`. A 20 ms cadence on
//! tokio's paused clock; the tick that blocks its thread runs on the wall clock.
use super::{run_maintenance, tick_deadline};
use crate::supervise::{Heartbeat, Supervisor, Timing};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

const PERIOD: Duration = Duration::from_millis(20);

fn supervised(silence: Duration) -> (Arc<Supervisor>, Arc<Heartbeat>) {
    let heartbeat = Arc::new(Heartbeat::new(silence));
    let timing = Timing {
        backoff_min: Duration::from_millis(5),
        backoff_max: Duration::from_millis(20),
        stable_run: Duration::from_secs(60),
        crash_loop: 5,
    };
    let tasks = Supervisor::with(vec![("maintenance", Arc::clone(&heartbeat))], timing);
    (Arc::new(tasks), heartbeat)
}

#[tokio::test(start_paused = true)]
async fn a_panicking_tick_restarts_the_loop() {
    let (tasks, heartbeat) = supervised(Duration::from_secs(300));
    let runs = Arc::new(AtomicU64::new(0));
    let completed = Arc::new(AtomicU64::new(0));
    let (r, c, hb) = (
        Arc::clone(&runs),
        Arc::clone(&completed),
        Arc::clone(&heartbeat),
    );
    let task = tasks.spawn("maintenance", move || {
        let run = r.fetch_add(1, Ordering::SeqCst);
        let c = Arc::clone(&c);
        run_maintenance(PERIOD, Arc::clone(&hb), move |n| {
            let c = Arc::clone(&c);
            async move {
                assert!(
                    !(run == 0 && n == 2),
                    "a bug in the second tick of the first run"
                );
                c.fetch_add(1, Ordering::SeqCst);
            }
        })
    });
    tokio::time::sleep(PERIOD * 20).await;
    assert!(
        !task.is_finished(),
        "the loop ended with the panicking tick"
    );
    assert_eq!(runs.load(Ordering::SeqCst), 2, "restarted once");
    assert!(
        completed.load(Ordering::SeqCst) >= 4,
        "ticks after the panic complete"
    );
    assert!(heartbeat.silent_for() < PERIOD * 10, "the loop still beats");
    assert_eq!(tasks.failing(), None);
    task.abort();
}

/// A loop whose every tick panics never flushes tokens or refreshes readiness again,
/// though the supervisor keeps restarting it: that fails liveness.
#[tokio::test(start_paused = true)]
async fn a_tick_that_panics_every_time_fails_liveness() {
    let (tasks, _heartbeat) = supervised(PERIOD * 10);
    let hb = Arc::clone(&_heartbeat);
    let task = tasks.spawn("maintenance", move || {
        run_maintenance(PERIOD, Arc::clone(&hb), |_| async {
            panic!("a bug in every tick");
        })
    });
    tokio::time::sleep(PERIOD * 30).await;
    assert!(!task.is_finished(), "the supervisor goes on restarting it");
    assert_eq!(tasks.failing(), Some("maintenance"));
    task.abort();
}

/// Ticks that each fail only after running a while — past the supervisor's stable run,
/// so no crash loop shows — still never complete: the heartbeat fails liveness.
#[tokio::test(start_paused = true)]
async fn ticks_that_fail_late_every_time_fail_liveness() {
    // A window whose tick deadline (120 ms) is well past the panic.
    let heartbeat = Arc::new(Heartbeat::new(PERIOD * 19));
    let timing = Timing {
        backoff_min: Duration::from_millis(5),
        backoff_max: Duration::from_millis(5),
        stable_run: PERIOD,
        crash_loop: 5,
    };
    let tasks = Arc::new(Supervisor::with(
        vec![("maintenance", Arc::clone(&heartbeat))],
        timing,
    ));
    let hb = Arc::clone(&heartbeat);
    let task = tasks.spawn("maintenance", move || {
        run_maintenance(PERIOD, Arc::clone(&hb), |_| async {
            tokio::time::sleep(PERIOD * 2).await;
            panic!("a bug that shows after a while");
        })
    });
    tokio::time::sleep(PERIOD * 30).await;
    assert_eq!(tasks.failing(), Some("maintenance"));
    task.abort();
}

/// The tick deadline leaves room in every allowed stall window for the wait for the next
/// tick, a tick that panics just inside the deadline, and the restarted loop's first tick
/// cut at it, plus the restart backoff.
#[test]
fn the_tick_deadline_fits_a_panic_and_a_cut_tick_in_the_window() {
    let period = super::MAINTENANCE_PERIOD;
    let backoff = Timing::default().backoff_min;
    // 90: the smallest window the configuration accepts; 300: the default.
    for secs in [90, 300, 3600] {
        let window = Duration::from_secs(secs);
        let deadline = tick_deadline(period, window);
        assert!(
            deadline >= Duration::from_secs(20),
            "{secs} s: {deadline:?}"
        );
        assert!(
            period + deadline * 2 + backoff < window,
            "{secs} s: a panic and a cut tick overrun the window"
        );
    }
    assert_eq!(
        tick_deadline(period, Duration::from_secs(300)),
        Duration::from_secs(90)
    );
}

/// A tick that waits on something that never answers (a silent store) is cut at its
/// deadline: the loop goes on ticking on schedule, so liveness holds.
#[tokio::test(start_paused = true)]
async fn a_tick_waiting_on_a_silent_store_is_cut_and_liveness_holds() {
    let (tasks, heartbeat) = supervised(PERIOD * 10);
    let hb = Arc::clone(&heartbeat);
    let last = Arc::new(AtomicU64::new(0));
    let l = Arc::clone(&last);
    let task = tasks.spawn("maintenance", move || {
        let l = Arc::clone(&l);
        run_maintenance(PERIOD, Arc::clone(&hb), move |n| {
            l.store(n, Ordering::SeqCst);
            async move {
                if n == 2 {
                    std::future::pending::<()>().await;
                }
            }
        })
    });
    tokio::time::sleep(PERIOD * 30).await;
    assert_eq!(
        tasks.failing(),
        None,
        "a tick waiting on the store is not a dead loop"
    );
    assert!(
        last.load(Ordering::SeqCst) >= 10,
        "ticks after the cut one run on schedule"
    );
    task.abort();
}

/// Every tick waiting, none ever completing: each cut tick is progress, so liveness holds.
#[tokio::test(start_paused = true)]
async fn ticks_that_all_wait_on_the_store_keep_liveness() {
    let (tasks, heartbeat) = supervised(PERIOD * 10);
    let hb = Arc::clone(&heartbeat);
    let task = tasks.spawn("maintenance", move || {
        run_maintenance(PERIOD, Arc::clone(&hb), |_| std::future::pending::<()>())
    });
    tokio::time::sleep(PERIOD * 30).await;
    assert_eq!(tasks.failing(), None, "a loop of cut ticks is alive");
    task.abort();
}

/// `nora_maintenance_timeouts_total` is exported from the loop's start, at 0, before any
/// tick is cut, so an alert on its `increase` sees the first cut. The counter is the
/// process's: run alone (`--exact`), this test sees a series no other test created.
#[tokio::test(start_paused = true)]
async fn the_cut_counter_is_exported_before_the_first_cut() {
    let heartbeat = Arc::new(Heartbeat::new(Duration::from_secs(90)));
    let task = tokio::spawn(run_maintenance(
        super::MAINTENANCE_PERIOD,
        heartbeat,
        |_| async {},
    ));
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        prometheus::gather()
            .iter()
            .any(|family| family.name() == "nora_maintenance_timeouts_total"),
        "the counter appears only with the first cut tick"
    );
    task.abort();
}

/// A tick cut at its deadline is counted in `nora_maintenance_timeouts_total`, which an
/// alert on a store that does not answer reads. The counter is the process's, shared with
/// tests running beside this one, which only add to it.
#[tokio::test(start_paused = true)]
async fn a_cut_tick_is_counted() {
    let period = super::MAINTENANCE_PERIOD;
    let silence = Duration::from_secs(90);
    let cuts = || super::metrics::MAINTENANCE_TIMEOUTS_TOTAL.get();
    let before = cuts();
    let heartbeat = Arc::new(Heartbeat::new(silence));
    let task = tokio::spawn(run_maintenance(period, heartbeat, |n| async move {
        if n == 1 {
            std::future::pending::<()>().await;
        }
    }));
    tokio::time::sleep(tick_deadline(period, silence) + Duration::from_secs(1)).await;
    assert!(cuts() > before, "a cut tick is not counted");
    task.abort();
}

/// After a cut tick the next one starts at its slot: the slots the cut tick overran are
/// skipped, not run back to back against a store that is not answering. On tokio's
/// paused clock: with 50 ms slots on the wall clock a loaded runner (the coverage job)
/// measured 24 ms between two starts that are one slot apart.
#[tokio::test(start_paused = true)]
async fn a_cut_tick_keeps_the_cadence() {
    const SLOT: Duration = Duration::from_millis(50);
    // A 150 ms deadline: tick 2 (at 50 ms) is cut at 200 ms, past the slots at 100 and 150.
    let (tasks, heartbeat) = supervised(SLOT * 10);
    let hb = Arc::clone(&heartbeat);
    let (started, mut start_times) = tokio::sync::mpsc::unbounded_channel();
    let task = tasks.spawn("maintenance", move || {
        let started = started.clone();
        run_maintenance(SLOT, Arc::clone(&hb), move |n| {
            let _ = started.send(tokio::time::Instant::now());
            async move {
                if n == 2 {
                    std::future::pending::<()>().await;
                }
            }
        })
    });
    tokio::time::sleep(SLOT * 8).await;
    task.abort();
    let mut starts = Vec::new();
    while let Ok(start) = start_times.try_recv() {
        starts.push(start);
    }
    assert!(
        starts.len() >= 4,
        "ticks after the cut one: {}",
        starts.len()
    );
    assert!(
        starts[3] - starts[2] >= SLOT / 2,
        "the tick after the cut one is followed by the next slot, not at once: {:?}",
        starts[3] - starts[2]
    );
}

/// A tick that holds its thread cannot be cut: the loop starts no new tick, and that
/// fails liveness.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tick_that_blocks_its_thread_fails_liveness() {
    let (tasks, heartbeat) = supervised(PERIOD * 10);
    let hb = Arc::clone(&heartbeat);
    let task = tasks.spawn("maintenance", move || {
        run_maintenance(PERIOD, Arc::clone(&hb), |n| async move {
            if n == 2 {
                std::thread::sleep(PERIOD * 40);
            }
        })
    });
    // The test thread waits on its own clock: a blocked worker can hold up tokio's timers.
    std::thread::sleep(PERIOD * 2);
    assert_eq!(tasks.failing(), None, "within the silence it may keep");
    std::thread::sleep(PERIOD * 20);
    assert_eq!(
        tasks.failing(),
        Some("maintenance"),
        "a loop that starts no tick stops the beats"
    );
    task.abort();
}
