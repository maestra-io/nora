// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! In-memory single-flight coalescing for the proxy cache-miss path (#595).
//!
//! When `M` concurrent clients ask for the same expired or missing artifact,
//! the naive path sends `M` independent upstream fetches and `M` redundant
//! storage writes for one logical refresh — a classic thundering herd /
//! cache stampede. This module collapses that to **one** upstream fetch: the
//! first caller for a key ("leader") performs the fetch; concurrent callers
//! ("followers") wait for the leader's in-memory result and serve a clone of
//! it without touching the upstream or the cache.
//!
//! ## Why in-memory, not "followers re-read storage"
//!
//! NORA's registries cache proxied bytes with a fire-and-forget
//! `tokio::spawn(storage.put(..))` *after* the response is returned (e.g.
//! `registry/npm.rs`). A follower that polled storage would race that detached
//! task — the object may not be written yet. So the leader publishes its
//! finished serve-bytes into a shared [`Slot`] and followers read *that*; the
//! background cache write stays exactly as it was (leader does it once).
//!
//! ## Correctness & cancel-safety
//!
//! - Leader election is a single `Entry::Vacant`/`Occupied` decision under the
//!   map mutex (never `Arc::strong_count`, which races) — exactly one leader.
//! - The map mutex (`parking_lot`) is never held across an `.await`; its guard
//!   is `!Send`, so the compiler rejects accidental holds on the multi-thread
//!   runtime. `parking_lot` also does not poison, so a leader panic still runs
//!   the guard's `Drop`.
//! - [`FetchGuard`] removes the key (ABA-safe via `Arc::ptr_eq`) and wakes
//!   waiters **on `Drop`**, so a cancelled leader (client disconnect) frees the
//!   slot instead of poisoning the key. The slot is never left dangling.
//! - A follower registers its `Notified` *before* the fast-path result check,
//!   so it cannot miss a `notify_waiters()` that fires in the gap (tokio
//!   guarantees a `Notified` receives `notify_waiters` wakeups from the moment
//!   it is created, not first poll).
//! - A leader whose fetch FAILS publishes the failure to the followers already
//!   attached to its slot, so a failing upstream gets one fetch per flight, not
//!   one per waiter. The slot leaves the map with the leader: this is no negative
//!   cache, the next request fetches again. A leader that is CANCELLED publishes
//!   nothing, and its waiters elect one new leader among themselves.
//! - State is purely in-memory and rebuildable — an empty map after restart is
//!   correct (matches the "in-memory indexes are rebuildable from disk"
//!   invariant). No storage-format change.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::Notify;

/// One in-flight key's shared state: the leader's published result plus a
/// notifier woken when the leader resolves (success, failure, or cancel).
struct Slot<T, E> {
    /// `Some` once the leader resolved: its value, or its failure (`Err(None)` when
    /// the failure carries no detail). Followers clone it.
    result: Mutex<Option<Result<T, Option<E>>>>,
    /// Notified when the leader finishes or its slot is released.
    ready: Notify,
}

impl<T, E> Slot<T, E> {
    fn new() -> Self {
        Slot {
            result: Mutex::new(None),
            ready: Notify::new(),
        }
    }
}

impl<T: Clone, E: Clone> Slot<T, E> {
    /// The leader's published value, if any. The lock is held only for the clone.
    fn value(&self) -> Option<T> {
        self.result.lock().as_ref()?.as_ref().ok().cloned()
    }

    /// The leader's published outcome, value or failure, if it resolved.
    fn outcome(&self) -> Option<Result<T, Option<E>>> {
        self.result.lock().clone()
    }

    /// Publish the leader's value for followers to clone.
    fn publish(&self, value: T) {
        *self.result.lock() = Some(Ok(value));
    }

    /// Publish the leader's failure for the followers already waiting on this slot.
    fn publish_failure(&self, failure: Option<E>) {
        *self.result.lock() = Some(Err(failure));
    }
}

type SlotMap<T, E> = Arc<Mutex<HashMap<String, Arc<Slot<T, E>>>>>;

/// Per-key single-flight coordinator. Cheap to clone (shares one map).
///
/// `T` is the value followers receive — for the proxy path this is the
/// ready-to-serve response body (`axum::body::Bytes`, an `Arc`-backed buffer
/// whose clone is O(1)). `E` is the failure a leader shares with the followers of
/// its flight ([`InflightMap::coalesced_try`]).
pub struct InflightMap<T, E = ()> {
    map: SlotMap<T, E>,
}

impl<T, E> Clone for InflightMap<T, E> {
    fn clone(&self) -> Self {
        InflightMap {
            map: Arc::clone(&self.map),
        }
    }
}

impl<T, E> Default for InflightMap<T, E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, E> InflightMap<T, E> {
    /// Create an empty coordinator.
    pub fn new() -> Self {
        InflightMap {
            map: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

/// RAII slot lease held by the leader for the duration of its fetch.
///
/// On `Drop` — whether from a normal return, a panic unwind, or the future
/// being cancelled mid-fetch — it removes its own slot from the map and wakes
/// every waiter, then decrements the in-flight gauge. Removal is ABA-safe: if
/// the key was already reused by a newer leader, `Arc::ptr_eq` prevents this
/// guard from evicting that newer slot.
struct FetchGuard<T, E> {
    map: SlotMap<T, E>,
    key: String,
    slot: Arc<Slot<T, E>>,
    registry: &'static str,
}

impl<T, E> Drop for FetchGuard<T, E> {
    fn drop(&mut self) {
        {
            let mut map = self.map.lock();
            if let Entry::Occupied(occ) = map.entry(self.key.clone()) {
                // Only evict our own slot — a newer leader may have re-inserted
                // the same key after we removed/before this drop (ABA).
                if Arc::ptr_eq(occ.get(), &self.slot) {
                    occ.remove();
                }
            }
        } // map lock released before notifying
          // Wake followers. Those that already observed `result` ignore it; the
          // rest re-check `result`: the leader's value or failure, or nothing when
          // it was cancelled, and then they elect a new leader.
        self.slot.ready.notify_waiters();
        crate::metrics::PROXY_INFLIGHT
            .with_label_values(&[self.registry])
            .dec();
    }
}

impl<T, E> InflightMap<T, E>
where
    T: Clone,
    E: Clone,
{
    /// Run `fetch` under single-flight for `key`.
    ///
    /// Exactly one concurrent caller per key (the leader) executes `fetch`;
    /// the rest (followers) wait up to `budget` for the leader's published
    /// outcome and return a clone of it, incrementing
    /// [`PROXY_COALESCED_TOTAL`](crate::metrics::PROXY_COALESCED_TOTAL). A leader
    /// that fails (`None`) fails the followers already waiting on it too (R4-P08:
    /// a failing upstream is asked once per flight, not once per waiter); nothing
    /// is remembered past the flight. If the leader is cancelled, the waiters elect
    /// one new leader among themselves; a follower whose wait exceeds `budget`
    /// runs its **own** `fetch` (a request never hangs on a dead leader).
    ///
    /// `budget` should comfortably exceed the leader's worst-case wall-clock
    /// (upstream timeout + retry) so followers wake on the leader's
    /// notification rather than on the budget ceiling; the ceiling is only a
    /// safety net against a leader that never notifies.
    ///
    /// `registry` is the metric label for the in-flight gauge and coalesced
    /// counter.
    /// Leader election: one decision under the map lock, zero awaits. The first caller
    /// for `key` inserts the slot and leads; the rest follow the slot already there.
    fn elect(&self, key: &str) -> Role<T, E> {
        let mut map = self.map.lock();
        match map.entry(key.to_string()) {
            Entry::Vacant(v) => {
                let slot = Arc::new(Slot::new());
                v.insert(Arc::clone(&slot));
                Role::Leader(slot)
            }
            Entry::Occupied(o) => Role::Follower(Arc::clone(o.get())),
        }
    } // map lock dropped here — before any `.await`

    pub async fn coalesced<F, Fut>(
        &self,
        key: &str,
        registry: &'static str,
        budget: Duration,
        fetch: F,
    ) -> Option<T>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Option<T>>,
    {
        self.coalesced_try(key, registry, budget, || async {
            fetch().await.ok_or(None)
        })
        .await
        .ok()
    }

    /// [`coalesced`](Self::coalesced) for a fetch whose failure has a detail worth
    /// sharing: followers of a failed leader get a clone of its `Err`, so they answer
    /// what the leader answers (a 404 stays a 404). `Err(None)` is a failure without
    /// detail, which the caller maps itself.
    pub async fn coalesced_try<F, Fut>(
        &self,
        key: &str,
        registry: &'static str,
        budget: Duration,
        fetch: F,
    ) -> Result<T, Option<E>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, Option<E>>>,
    {
        self.coalesced_try_leased(key, registry, budget, fetch)
            .await
            .map(|(value, _lease)| value)
        // The leader's lease drops here: the slot is released with the fetch.
    }

    /// [`coalesced_try`](Self::coalesced_try) handing the leader of a successful fetch
    /// a [`Lease`] on its slot: until it is dropped, a caller arriving later still gets
    /// the leader's value instead of fetching again (R4-P03: a fill whose client went
    /// away is kept for the retry). `None` for a follower, and for a caller that
    /// fetched alone after its budget.
    pub async fn coalesced_try_leased<F, Fut>(
        &self,
        key: &str,
        registry: &'static str,
        budget: Duration,
        fetch: F,
    ) -> Result<(T, Option<Lease<T, E>>), Option<E>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, Option<E>>>,
    {
        // --- PRECONDITIONS ---
        debug_assert!(!key.is_empty(), "coalesce key must not be empty");

        loop {
            match self.elect(key) {
                Role::Leader(slot) => {
                    crate::metrics::PROXY_INFLIGHT
                        .with_label_values(&[registry])
                        .inc();
                    // Guard frees the slot + notifies waiters on every exit path,
                    // including cancellation of `fetch().await` below.
                    // CANCEL-SAFETY: slot release happens in `FetchGuard::drop`,
                    // not after the await point.
                    let guard = FetchGuard {
                        map: Arc::clone(&self.map),
                        key: key.to_string(),
                        slot: Arc::clone(&slot),
                        registry,
                    };
                    // Publish BEFORE the guard drops so a follower woken by the
                    // guard's `notify_waiters()` always observes the final outcome.
                    return match fetch().await {
                        Ok(value) => {
                            slot.publish(value.clone());
                            // The guard may outlive this call as a lease: wake the
                            // waiters now, at publish.
                            slot.ready.notify_waiters();
                            Ok((value, Some(Lease { _guard: guard })))
                        }
                        Err(failure) => {
                            slot.publish_failure(failure.clone());
                            Err(failure)
                            // `guard` drops here: removes key (ptr_eq) + notify_waiters.
                        }
                    };
                }
                Role::Follower(slot) => {
                    // Register interest BEFORE checking `result`: a `Notified`
                    // created now is guaranteed to receive a `notify_waiters()`
                    // that fires before we await. If the leader already published,
                    // the fast-path check below sees it regardless.
                    let notified = slot.ready.notified();
                    tokio::pin!(notified);

                    if let Some(outcome) = slot.outcome() {
                        return Self::record_follower(registry, outcome).map(|v| (v, None));
                    }

                    // CANCEL-SAFETY: a follower holds nothing but its `Arc<Slot>`.
                    match tokio::time::timeout(budget, &mut notified).await {
                        Ok(()) => {
                            if let Some(outcome) = slot.outcome() {
                                return Self::record_follower(registry, outcome).map(|v| (v, None));
                            }
                            // The leader was cancelled (client disconnect) before it
                            // resolved and its slot is gone: elect again, so the
                            // waiters produce one new fetch, not one each.
                            crate::metrics::PROXY_COALESCE_FALLTHROUGH_TOTAL
                                .with_label_values(&[registry, "leader"])
                                .inc();
                        }
                        Err(_) => {
                            // Budget elapsed while the leader was still fetching:
                            // fetch alone. A rising `budget` rate means a slow
                            // upstream is re-stampeding past the coalescer.
                            crate::metrics::PROXY_COALESCE_FALLTHROUGH_TOTAL
                                .with_label_values(&[registry, "budget"])
                                .inc();
                            return fetch().await.map(|v| (v, None));
                        }
                    }
                }
            }
        }
    }

    /// Single-flight whose shared value outlives the fetch: the leader gets a [`Lease`],
    /// and until it is dropped the slot stays in the map, so a caller arriving later gets
    /// the leader's value instead of fetching again. Built for a result that is still being
    /// produced after `fetch` returns (a blob spool: headers now, bytes as they land), where
    /// the callers that matter are the ones that come seconds later — a client retry,
    /// another node — not only the ones racing the leader's first await.
    ///
    /// `fetch` yields the value to share plus a part only the leader keeps. Fail-open like
    /// [`coalesced`](Self::coalesced): if the leader fails before publishing, the callers
    /// waiting on it elect one new leader among themselves (not one fetch each); a caller
    /// whose wait exceeds `budget` fetches alone ([`Flight::Alone`]).
    pub async fn leased<F, Fut, X>(
        &self,
        key: &str,
        registry: &'static str,
        budget: Duration,
        fetch: F,
    ) -> Option<Flight<T, X, E>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Option<(T, X)>>,
    {
        // --- PRECONDITIONS ---
        debug_assert!(!key.is_empty(), "coalesce key must not be empty");

        let mut fetch = Some(fetch);
        loop {
            match self.elect(key) {
                Role::Leader(slot) => {
                    let fetch = fetch.take()?;
                    crate::metrics::PROXY_INFLIGHT
                        .with_label_values(&[registry])
                        .inc();
                    // CANCEL-SAFETY: as in `coalesced`, the slot is released by the guard's
                    // `Drop` if this future is cancelled during `fetch().await`.
                    let guard = FetchGuard {
                        map: Arc::clone(&self.map),
                        key: key.to_string(),
                        slot: Arc::clone(&slot),
                        registry,
                    };
                    let (value, own) = fetch().await?; // `guard` drops on `None`
                    slot.publish(value.clone());
                    // The guard is not dropped here, so wake the waiters now: they must get
                    // the value when it is published, not when the lease ends.
                    slot.ready.notify_waiters();
                    return Some(Flight::Leader {
                        value,
                        own,
                        lease: Lease { _guard: guard },
                    });
                }
                Role::Follower(slot) => {
                    let notified = slot.ready.notified();
                    tokio::pin!(notified);
                    if let Some(value) = slot.value() {
                        return Some(Flight::Follower(Self::record_value(registry, value)));
                    }
                    // CANCEL-SAFETY: a follower holds nothing but its `Arc<Slot>`; dropping
                    // this wait leaves the slot and the leader untouched.
                    match tokio::time::timeout(budget, &mut notified).await {
                        Ok(()) => {
                            if let Some(value) = slot.value() {
                                return Some(Flight::Follower(Self::record_value(registry, value)));
                            }
                            // The leader failed before publishing and its slot is gone:
                            // elect again, so the waiters produce one new fetch.
                            crate::metrics::PROXY_COALESCE_FALLTHROUGH_TOTAL
                                .with_label_values(&[registry, "leader"])
                                .inc();
                        }
                        Err(_) => {
                            crate::metrics::PROXY_COALESCE_FALLTHROUGH_TOTAL
                                .with_label_values(&[registry, "budget"])
                                .inc();
                            let fetch = fetch.take()?;
                            let (value, own) = fetch().await?;
                            return Some(Flight::Alone { value, own });
                        }
                    }
                }
            }
        }
    }

    /// A follower served from its leader: counted whether it shares a value or a
    /// failure, as either way it was spared an upstream fetch.
    fn record_follower<V>(registry: &'static str, outcome: V) -> V {
        crate::metrics::PROXY_COALESCED_TOTAL
            .with_label_values(&[registry])
            .inc();
        outcome
    }

    fn record_value(registry: &'static str, value: T) -> T {
        Self::record_follower(registry, value)
    }
}

enum Role<T, E> {
    Leader(Arc<Slot<T, E>>),
    Follower(Arc<Slot<T, E>>),
}

/// What [`InflightMap::leased`] handed a caller.
pub enum Flight<T, X, E = ()> {
    /// This caller fetched. `own` is the part of the fetch only it keeps (never
    /// published); while `lease` lives, later callers for the key still get `value`.
    Leader {
        value: T,
        own: X,
        lease: Lease<T, E>,
    },
    /// Another caller fetched, or still holds its lease: a clone of its value.
    Follower(T),
    /// The wait for a leader ran out of budget, so this caller fetched on its own,
    /// outside the map: nobody shares its value.
    Alone { value: T, own: X },
}

/// A leader's hold on its slot past the end of its fetch ([`InflightMap::leased`]).
///
/// Dropping it — when the work it covers is done, on an early return, or in a panic
/// unwind — removes the slot (ABA-safe) and wakes waiters: the same release as the end
/// of a [`InflightMap::coalesced`] fetch.
pub struct Lease<T, E = ()> {
    _guard: FetchGuard<T, E>,
}

/// Follower wait budget for a registry whose upstream timeout is `proxy_timeout`
/// seconds. Sized above the leader's worst-case wall-clock with headroom: the
/// npm metadata path wired today uses the no-retry `proxy_fetch_conditional`
/// (leader ≈ `proxy_timeout`), but `proxy_fetch_core` (binary/tarball fetches)
/// retries once with a 1 s back-off (≈ `2 * proxy_timeout + 1 s`). We size for
/// the latter so the budget stays correct if coalescing is later wired onto a
/// retrying path. The leader notifies followers the instant it resolves, so
/// this is only a ceiling, not the expected wait — a follower that hits it is
/// counted under `PROXY_COALESCE_FALLTHROUGH_TOTAL{reason="budget"}`.
pub fn follower_budget(proxy_timeout_secs: u64) -> Duration {
    Duration::from_secs(2 * proxy_timeout_secs + 3)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::sync::Barrier;

    fn budget() -> Duration {
        Duration::from_secs(5)
    }

    /// M concurrent callers on the same key → `fetch` runs exactly once; the
    /// other M-1 receive the leader's value. (Acceptance: M→1 fetch.)
    #[tokio::test(start_paused = true)]
    async fn coalesces_concurrent_callers_to_single_fetch() {
        let map: InflightMap<u64> = InflightMap::new();
        let calls = Arc::new(AtomicUsize::new(0));
        const M: usize = 32;
        // Barrier ensures all tasks reach election before the leader finishes,
        // so they genuinely contend (otherwise a fast leader could complete
        // before followers arrive).
        let gate = Arc::new(Barrier::new(M));

        let mut handles = Vec::new();
        for _ in 0..M {
            let map = map.clone();
            let calls = Arc::clone(&calls);
            let gate = Arc::clone(&gate);
            handles.push(tokio::spawn(async move {
                gate.wait().await;
                map.coalesced("pkg", "test", budget(), || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    // Hold the slot so followers pile up behind the leader.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    Some(7u64)
                })
                .await
            }));
        }

        let results: Vec<_> = futures::future::join_all(handles).await;
        for r in results {
            assert_eq!(r.unwrap(), Some(7u64), "every caller gets the value");
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "exactly one upstream fetch for M concurrent callers"
        );
        assert!(
            map.map.lock().is_empty(),
            "slot is removed after the leader finishes"
        );
    }

    /// Distinct keys never block each other — two keys fetched concurrently
    /// each run their own fetch. (Acceptance: distinct keys independent.)
    #[tokio::test]
    async fn distinct_keys_do_not_block() {
        let map: InflightMap<u64> = InflightMap::new();
        let calls = Arc::new(AtomicUsize::new(0));

        let a = {
            let map = map.clone();
            let calls = Arc::clone(&calls);
            tokio::spawn(async move {
                map.coalesced("a", "test", budget(), || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Some(1u64)
                })
                .await
            })
        };
        let b = {
            let map = map.clone();
            let calls = Arc::clone(&calls);
            tokio::spawn(async move {
                map.coalesced("b", "test", budget(), || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Some(2u64)
                })
                .await
            })
        };

        assert_eq!(a.await.unwrap(), Some(1));
        assert_eq!(b.await.unwrap(), Some(2));
        assert_eq!(calls.load(Ordering::SeqCst), 2, "each distinct key fetched");
    }

    /// R4-P08: a leader that fails shares the failure with the followers already
    /// waiting on it: one fetch for the flight, not one per waiter (a failing upstream
    /// was hit M times at once). Nothing is remembered: the next caller fetches again.
    #[tokio::test(start_paused = true)]
    async fn leader_failure_is_shared_with_its_followers() {
        let map: InflightMap<u64> = InflightMap::new();
        let calls = Arc::new(AtomicUsize::new(0));
        const M: usize = 8;
        let gate = Arc::new(Barrier::new(M));

        let mut handles = Vec::new();
        for _ in 0..M {
            let map = map.clone();
            let calls = Arc::clone(&calls);
            let gate = Arc::clone(&gate);
            handles.push(tokio::spawn(async move {
                gate.wait().await;
                map.coalesced("pkg", "test", budget(), || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    None
                })
                .await
            }));
        }

        let results: Vec<_> = futures::future::join_all(handles).await;
        assert!(
            results.iter().all(|r| r.as_ref().unwrap().is_none()),
            "every caller of the flight gets the leader's failure"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a failed leader costs one fetch, not one per follower"
        );

        // No negative cache: the failure died with the flight.
        assert!(map.map.lock().is_empty());
        let next = map
            .coalesced("pkg", "test", budget(), || async {
                calls.fetch_add(1, Ordering::SeqCst);
                Some(5u64)
            })
            .await;
        assert_eq!(next, Some(5), "the next request fetches again");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// The failure followers get is the leader's own (`coalesced_try`): a 404 stays a
    /// 404 for the whole flight instead of becoming a generic error.
    #[tokio::test(start_paused = true)]
    async fn followers_get_the_leaders_error_detail() {
        let map: InflightMap<u64, &'static str> = InflightMap::new();
        let calls = Arc::new(AtomicUsize::new(0));
        const M: usize = 4;
        let gate = Arc::new(Barrier::new(M));
        let mut handles = Vec::new();
        for _ in 0..M {
            let (map, calls, gate) = (map.clone(), Arc::clone(&calls), Arc::clone(&gate));
            handles.push(tokio::spawn(async move {
                gate.wait().await;
                map.coalesced_try("pkg", "test", budget(), || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    Err(Some("not found"))
                })
                .await
            }));
        }
        for r in futures::future::join_all(handles).await {
            assert_eq!(r.unwrap(), Err(Some("not found")));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// A leader cancelled mid-fetch (client disconnect) shares nothing, and its waiters
    /// elect ONE new leader among themselves, not one fetch each.
    #[tokio::test(start_paused = true)]
    async fn cancelled_leader_hands_over_to_one_new_leader() {
        let map: InflightMap<u64> = InflightMap::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let leader = tokio::spawn({
            let map = map.clone();
            async move {
                map.coalesced("pkg", "test", budget(), || async {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    Some(1u64)
                })
                .await
            }
        });
        tokio::task::yield_now().await;
        assert_eq!(slots_held(&map), 1, "leader registered its slot");

        const M: usize = 8;
        let mut handles = Vec::new();
        for _ in 0..M {
            let (map, calls) = (map.clone(), Arc::clone(&calls));
            handles.push(tokio::spawn(async move {
                map.coalesced("pkg", "test", budget(), || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    Some(42u64)
                })
                .await
            }));
        }
        // Let every follower attach to the leader's slot, then cancel the leader.
        tokio::time::sleep(Duration::from_millis(1)).await;
        leader.abort();
        for r in futures::future::join_all(handles).await {
            assert_eq!(r.unwrap(), Some(42), "every waiter shares the new fetch");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1, "ONE new leader");
    }

    /// Leader cancellation (its future dropped mid-fetch) releases the key, so
    /// a subsequent request fetches cleanly with no permanent stall.
    /// (Acceptance: cancellation releases the key.)
    #[tokio::test(start_paused = true)]
    async fn leader_cancellation_releases_key() {
        let map: InflightMap<u64> = InflightMap::new();
        let calls = Arc::new(AtomicUsize::new(0));

        // Spawn a leader that sleeps long, then cancel it mid-fetch.
        let leader = {
            let map = map.clone();
            let calls = Arc::clone(&calls);
            tokio::spawn(async move {
                map.coalesced("pkg", "test", budget(), || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    Some(1u64)
                })
                .await
            })
        };

        // Let the leader register and start fetching, then cancel it.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!map.map.lock().is_empty(), "leader registered its slot");
        leader.abort();
        // Give the abort time to run the guard's Drop.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            map.map.lock().is_empty(),
            "cancelled leader's slot is released on drop"
        );

        // A fresh request becomes the new leader and fetches cleanly.
        let fresh = map
            .coalesced("pkg", "test", budget(), || async {
                calls.fetch_add(1, Ordering::SeqCst);
                Some(2u64)
            })
            .await;
        assert_eq!(fresh, Some(2), "subsequent request fetches with no stall");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "cancelled leader + one clean refetch"
        );
    }

    /// Slots currently in the map (held by a fetch or a lease).
    fn slots_held<T, E>(map: &InflightMap<T, E>) -> usize {
        map.map.lock().len()
    }

    fn leader_value(flight: Option<Flight<u64, ()>>) -> (u64, Lease<u64>) {
        match flight {
            Some(Flight::Leader { value, lease, .. }) => (value, lease),
            _ => panic!("expected to lead"),
        }
    }

    /// While the leader holds its lease, a caller arriving after the fetch returned still
    /// gets the leader's value; once the lease drops, the next caller leads a new fetch.
    #[tokio::test(start_paused = true)]
    async fn lease_keeps_the_slot_for_late_callers() {
        let map: InflightMap<u64> = InflightMap::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let fetch = |n: u64| {
            let calls = Arc::clone(&calls);
            move || async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Some((n, ()))
            }
        };

        let (value, lease) = leader_value(map.leased("blob", "test", budget(), fetch(7)).await);
        assert_eq!(value, 7);
        // Long after the leader's fetch returned, the slot is still there.
        tokio::time::sleep(Duration::from_millis(50)).await;
        match map.leased("blob", "test", budget(), fetch(8)).await {
            Some(Flight::Follower(v)) => assert_eq!(v, 7, "late caller gets the leader's value"),
            _ => panic!("a late caller must follow while the lease lives"),
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        drop(lease);
        assert!(
            slots_held(&map) == 0,
            "dropping the lease releases the slot"
        );
        let (value, _lease) = leader_value(map.leased("blob", "test", budget(), fetch(9)).await);
        assert_eq!(
            value, 9,
            "after release the next caller leads a fresh fetch"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// R4-P03: while the leader of a successful fetch keeps its lease, a caller that
    /// arrives after the fetch ended still gets its value; a failed fetch gives no lease.
    #[tokio::test]
    async fn try_lease_keeps_a_fetched_value_for_late_callers() {
        let map: InflightMap<u64, &'static str> = InflightMap::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let fetch = |out: Result<u64, Option<&'static str>>| {
            let calls = Arc::clone(&calls);
            move || async move {
                calls.fetch_add(1, Ordering::SeqCst);
                out
            }
        };
        let (value, lease) = map
            .coalesced_try_leased("pkg", "test", budget(), fetch(Ok(7)))
            .await
            .unwrap();
        assert_eq!(value, 7);
        assert!(lease.is_some(), "the leader holds the slot");
        let (late, none) = map
            .coalesced_try_leased("pkg", "test", budget(), fetch(Ok(8)))
            .await
            .unwrap();
        assert_eq!(late, 7, "a late caller follows the held value");
        assert!(none.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        drop(lease);
        assert_eq!(slots_held(&map), 0);

        let failed = map
            .coalesced_try_leased("pkg", "test", budget(), fetch(Err(Some("down"))))
            .await;
        assert!(matches!(failed, Err(Some("down"))));
        assert_eq!(slots_held(&map), 0, "a failure is not held");
    }

    /// Followers waiting on a leader are woken when it publishes, not when its lease ends.
    #[tokio::test(start_paused = true)]
    async fn followers_get_the_value_at_publish_not_at_release() {
        let map: InflightMap<u64> = InflightMap::new();
        let leader_map = map.clone();
        let leader = tokio::spawn({
            let map = leader_map;
            async move {
                let (_, lease) = leader_value(
                    map.leased("blob", "test", budget(), || async {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        Some((1u64, ()))
                    })
                    .await,
                );
                // Hold the lease far longer than the follower is willing to wait.
                tokio::time::sleep(Duration::from_secs(30)).await;
                drop(lease);
            }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        let got = tokio::time::timeout(
            Duration::from_secs(2),
            map.leased("blob", "test", budget(), || async { Some((2u64, ())) }),
        )
        .await
        .expect("follower must not wait for the lease to end");
        assert!(matches!(got, Some(Flight::Follower(1))));
        leader.abort();
    }

    /// A lease dropped by a panic unwind (the spool task's `catch_unwind`) releases the
    /// slot and the in-flight gauge, so the key is never stranded.
    #[tokio::test]
    async fn lease_released_by_panic_unwind() {
        use futures::FutureExt as _;
        let map: InflightMap<u64> = InflightMap::new();
        let gauge = || {
            crate::metrics::PROXY_INFLIGHT
                .with_label_values(&["lease-panic"])
                .get()
        };
        let (_, lease) = leader_value(
            map.leased("blob", "lease-panic", budget(), || async {
                Some((1u64, ()))
            })
            .await,
        );
        assert_eq!(gauge(), 1);
        let task = async move {
            let _lease = lease;
            panic!("spool task panicked");
        };
        let joined = tokio::spawn(std::panic::AssertUnwindSafe(task).catch_unwind()).await;
        assert!(joined.unwrap().is_err(), "the task panicked");
        assert!(slots_held(&map) == 0, "slot released by the unwind");
        assert_eq!(gauge(), 0, "in-flight gauge back to zero");
    }

    /// A leader that fails before publishing makes its waiters elect ONE new leader
    /// among themselves, not one fetch each.
    #[tokio::test(start_paused = true)]
    async fn failed_leader_hands_over_to_one_new_leader() {
        let map: InflightMap<u64> = InflightMap::new();
        let calls = Arc::new(AtomicUsize::new(0));
        const M: usize = 8;
        let gate = Arc::new(Barrier::new(M));
        let mut handles = Vec::new();
        for _ in 0..M {
            let (map, calls, gate) = (map.clone(), Arc::clone(&calls), Arc::clone(&gate));
            handles.push(tokio::spawn(async move {
                gate.wait().await;
                let flight = map
                    .leased("blob", "test", budget(), || async {
                        let n = calls.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        (n > 0).then_some((42u64, ()))
                    })
                    .await;
                // Keep a won lease until everyone has looked, like a spool in progress.
                tokio::time::sleep(Duration::from_millis(200)).await;
                flight.map(|f| match f {
                    Flight::Leader { value, .. } | Flight::Follower(value) => value,
                    Flight::Alone { value, .. } => value + 1000,
                })
            }));
        }
        let results: Vec<_> = futures::future::join_all(handles).await;
        let values: Vec<_> = results.into_iter().map(|r| r.unwrap()).collect();
        assert_eq!(
            values.iter().filter(|v| v.is_none()).count(),
            1,
            "only the failed leader gets None"
        );
        assert!(
            values.iter().flatten().all(|v| *v == 42),
            "everyone else shares the second fetch"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "failed leader + ONE new leader"
        );
    }

    #[test]
    fn budget_scales_with_timeout() {
        // 2 * timeout + 3s margin.
        assert_eq!(follower_budget(30), Duration::from_secs(63));
        assert_eq!(follower_budget(0), Duration::from_secs(3));
    }
}
