//! Unified periodic cleanup scheduler.
//!
//! Retention and GC used to run as two independent tasks with the same
//! default interval, sharing one `cleanup_lock`. Both ticked at the same
//! instant every cycle and the periodic path used `try_lock`: GC won the
//! race every time and retention logged "cleanup lock held ... skipping"
//! with no retry, so age-based retention never ran on a default schedule.
//!
//! One task removes that race by construction — every due pass runs in
//! order under a single lock acquisition, and the acquisition waits instead
//! of skipping. Retention runs before GC because retention deletes expired
//! versions, which creates the orphans GC then sweeps: one cycle now
//! reclaims what the split design needed two cycles for.

use futures::future::BoxFuture;
use futures::FutureExt;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::warn;

/// What a pass with a zero interval waits between two runs. Config validation refuses an
/// interval of 0 for an enabled pass; this floor holds for any caller.
const ZERO_INTERVAL_FLOOR: Duration = Duration::from_secs(1);

pub(crate) struct CleanupPass {
    pub name: &'static str,
    pub interval: Duration,
    /// Runs one pass. Owns its own start/done logging.
    pub run: Box<dyn Fn() -> BoxFuture<'static, ()> + Send + Sync>,
}

/// The scheduler as a task of its own, for the tests of the schedule; the server runs
/// [`run_cleanup_scheduler`] under its supervisor.
#[cfg(test)]
pub(crate) fn spawn_cleanup_scheduler(
    passes: Vec<CleanupPass>,
    cleanup_lock: Arc<tokio::sync::Mutex<()>>,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_cleanup_scheduler(
        Arc::new(passes),
        cleanup_lock,
        cancel,
    ))
}

/// Run every due pass, in order, under one acquisition of `cleanup_lock`, until `cancel`.
/// Every pass is due when this starts, so a restart runs them again.
pub(crate) async fn run_cleanup_scheduler(
    passes: Arc<Vec<CleanupPass>>,
    cleanup_lock: Arc<tokio::sync::Mutex<()>>,
    cancel: CancellationToken,
) {
    {
        // Every pass is due at boot: a process restarting more often than its
        // interval must still clean.
        let mut due: Vec<Instant> = vec![Instant::now(); passes.len()];

        loop {
            let Some(next) = due.iter().min().copied() else {
                return;
            };

            // CANCEL-SAFETY: sleep_until and cancelled() hold no state between
            // polls, and pass work runs to completion inside one iteration.
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep_until(next) => {}
            }

            // Waiting on the lock cannot starve the cycle: this task is the
            // only periodic contender. Racing the wait against cancellation
            // keeps SIGTERM prompt when a manual cleanup holds the lock.
            let guard = tokio::select! {
                _ = cancel.cancelled() => return,
                g = cleanup_lock.lock() => g,
            };

            let now = Instant::now();
            for (i, pass) in passes.iter().enumerate() {
                if due[i] > now {
                    continue;
                }
                // Wake-time based, so same-interval passes stay phase-locked
                // and a pass overrunning its interval fires on the next loop.
                due[i] = now + pass.interval;
                // A panicking pass is reported like a task panic, and the others still run.
                if let Err(panic) = std::panic::AssertUnwindSafe((pass.run)())
                    .catch_unwind()
                    .await
                {
                    crate::supervise::report_panic("cleanup", &panic);
                    warn!(
                        pass = pass.name,
                        "cleanup pass panicked — continuing with remaining passes"
                    );
                }
                // A zero interval would make the pass due again the moment it ends, and the
                // scheduler a busy loop under the lock: its floor counts from the end of the
                // pass, however long the pass took.
                if pass.interval.is_zero() {
                    due[i] = Instant::now() + ZERO_INTERVAL_FLOOR;
                }
            }

            drop(guard);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    type Recorder = Arc<parking_lot::Mutex<Vec<&'static str>>>;

    fn recorder() -> Recorder {
        Arc::new(parking_lot::Mutex::new(Vec::new()))
    }

    fn recording_pass(name: &'static str, interval: Duration, rec: &Recorder) -> CleanupPass {
        let rec = rec.clone();
        CleanupPass {
            name,
            interval,
            run: Box::new(move || {
                let rec = rec.clone();
                async move {
                    rec.lock().push(name);
                }
                .boxed()
            }),
        }
    }

    fn panicking_pass(name: &'static str, interval: Duration, rec: &Recorder) -> CleanupPass {
        let rec = rec.clone();
        CleanupPass {
            name,
            interval,
            run: Box::new(move || {
                let rec = rec.clone();
                async move {
                    rec.lock().push(name);
                    panic!("pass exploded");
                }
                .boxed()
            }),
        }
    }

    async fn wait_for(rec: &Recorder, count: usize) -> Vec<&'static str> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let seen = rec.lock().clone();
            if seen.len() >= count {
                return seen;
            }
            assert!(Instant::now() < deadline, "only recorded {seen:?}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// R4-C13: a pass with a zero interval is not due again the moment it ends. Without the
    /// floor the scheduler spins and the pass cancels it after 100 runs within one instant.
    #[tokio::test(start_paused = true)]
    async fn a_zero_interval_is_not_a_busy_loop() {
        let runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cancel = CancellationToken::new();
        let pass = {
            let (runs, cancel) = (runs.clone(), cancel.clone());
            CleanupPass {
                name: "gc",
                interval: Duration::ZERO,
                run: Box::new(move || {
                    if runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= 100 {
                        cancel.cancel();
                    }
                    // Longer than the floor: the wait counts from the end of the pass.
                    tokio::time::sleep(Duration::from_secs(2)).boxed()
                }),
            }
        };
        let handle = spawn_cleanup_scheduler(
            vec![pass],
            Arc::new(tokio::sync::Mutex::new(())),
            cancel.clone(),
        );
        tokio::time::sleep(Duration::from_millis(7500)).await;
        cancel.cancel();
        handle.await.unwrap();
        assert_eq!(
            runs.load(std::sync::atomic::Ordering::SeqCst),
            3,
            "at 0 s, 3 s and 6 s: two seconds of pass, then one second of floor"
        );
    }

    /// The first cycle runs at boot and chains retention → GC in order.
    #[tokio::test]
    async fn cycle_runs_passes_in_order_at_boot() {
        let rec = recorder();
        let interval = Duration::from_secs(10);
        let cancel = CancellationToken::new();
        let start = Instant::now();
        let handle = spawn_cleanup_scheduler(
            vec![
                recording_pass("retention", interval, &rec),
                recording_pass("gc", interval, &rec),
            ],
            Arc::new(tokio::sync::Mutex::new(())),
            cancel.clone(),
        );

        let seen = wait_for(&rec, 2).await;
        assert_eq!(&seen[..2], &["retention", "gc"]);
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "boot cycle waited for the interval"
        );

        cancel.cancel();
        handle.await.unwrap();
    }

    /// A panicking pass must not skip the later passes of its own cycle, nor
    /// kill the scheduler.
    #[tokio::test]
    async fn pass_panic_does_not_prevent_later_passes() {
        let (log, _capture) = crate::test_helpers::LogCapture::start();
        let panics = || crate::supervise::panics_counted("cleanup");
        let before = panics();
        let rec = recorder();
        let interval = Duration::from_millis(100);
        let cancel = CancellationToken::new();
        let handle = spawn_cleanup_scheduler(
            vec![
                panicking_pass("retention", interval, &rec),
                recording_pass("gc", interval, &rec),
            ],
            Arc::new(tokio::sync::Mutex::new(())),
            cancel.clone(),
        );

        let seen = wait_for(&rec, 4).await;
        assert_eq!(&seen[..4], &["retention", "gc", "retention", "gc"]);

        cancel.cancel();
        handle.await.unwrap();
        // Each panic is reported like a task's: counted, and an error naming the task.
        assert!(
            panics() >= before + 2,
            "{} panics counted",
            panics() - before
        );
        let errors: Vec<_> = log
            .text()
            .lines()
            .filter(|line| line.contains("ERROR") && line.contains("task=\"cleanup\""))
            .map(str::to_owned)
            .collect();
        assert!(errors.len() >= 2, "{}", log.text());
    }

    /// The periodic cycle parks on a held cleanup lock instead of skipping —
    /// the starvation the split schedulers had is gone.
    #[tokio::test(start_paused = true)]
    async fn cycle_waits_for_cleanup_lock_instead_of_skipping() {
        let rec = recorder();
        let interval = Duration::from_millis(100);
        let cleanup_lock = Arc::new(tokio::sync::Mutex::new(()));
        let held = cleanup_lock.clone().lock_owned().await;

        let cancel = CancellationToken::new();
        let handle = spawn_cleanup_scheduler(
            vec![
                recording_pass("retention", interval, &rec),
                recording_pass("gc", interval, &rec),
            ],
            cleanup_lock,
            cancel.clone(),
        );

        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(rec.lock().is_empty(), "ran while the lock was held");

        drop(held);
        let seen = wait_for(&rec, 2).await;
        assert_eq!(&seen[..2], &["retention", "gc"]);

        cancel.cancel();
        handle.await.unwrap();
    }

    /// A shutdown requested while the cycle is parked on the lock must break
    /// promptly, not wait out the holder.
    #[tokio::test(start_paused = true)]
    async fn cancel_while_parked_on_lock_stops_scheduler() {
        let rec = recorder();
        let cleanup_lock = Arc::new(tokio::sync::Mutex::new(()));
        let held = cleanup_lock.clone().lock_owned().await;

        let cancel = CancellationToken::new();
        let handle = spawn_cleanup_scheduler(
            vec![recording_pass(
                "retention",
                Duration::from_millis(100),
                &rec,
            )],
            cleanup_lock,
            cancel.clone(),
        );

        tokio::time::sleep(Duration::from_millis(300)).await;
        cancel.cancel();

        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("scheduler did not stop when cancelled while parked on the lock")
            .unwrap();

        assert!(rec.lock().is_empty());
        drop(held);
    }
}
