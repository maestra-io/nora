// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Shared renders of proxied npm packuments.
//!
//! Serving a proxied packument parses the whole document into a
//! `serde_json::Value` to drop versions younger than `min_release_age` and to
//! project the abbreviated (`install-v1`) form. A `Value` costs several times the
//! JSON it came from, and the parse ran once per request: a CI fleet asking for a
//! large packument at once (`vite`, `@types/node`: 10–37 MiB served) held one
//! parsed copy per request, and the 4 GiB pod was OOM-killed three times in two
//! minutes (us-iota, 22.10.2026, `anon-rss` 4.15 GB at each kill).
//!
//! The proxy single-flight (#595) only covers revalidation of an expired copy; a
//! fresh cached copy was rendered again by every request. Here a render is keyed
//! by the document's digest (its storage pin, so a kept render is found without
//! reading the document, R4-P02) and the variant asked for, and is done once:
//!
//! - concurrent requests for the same render share one parse
//!   ([`InflightMap::coalesced`]);
//! - the result is kept for [`RENDER_TTL`], within [`RENDER_CACHE_BYTES`], so
//!   requests arriving one after another reuse it too.
//!
//! The age filter compares versions with the clock, so a kept render can show a
//! version up to [`RENDER_TTL`] after it became old enough — the same window the
//! response's own `Cache-Control: max-age=60` already gives downstream caches.
//! State is in-memory and rebuildable: empty after a restart.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::time::Duration;

use axum::body::Bytes;
use parking_lot::Mutex;
use tokio::time::Instant;

use crate::proxy_coalesce::InflightMap;

/// A rendered proxied document.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Rendered {
    /// The body and its `Content-Type`; `None` for a document NORA does not serve (a
    /// version manifest whose tarball lies outside its upstream).
    pub(crate) body: Option<(Bytes, &'static str)>,
    /// The stored document held a tarball link past NORA: it is refetched whatever its age.
    pub(crate) past_nora: bool,
}

impl Rendered {
    fn len(&self) -> usize {
        self.body.as_ref().map_or(0, |(body, _)| body.len())
    }
}

/// How long a render is reused: the `max-age` the packument response carries.
pub(crate) const RENDER_TTL: Duration = Duration::from_secs(60);

/// Bytes of renders kept at once. The largest packument served in the 22.10.2026
/// burst was 37 MiB (`vite`); 128 MiB keeps three of those, against a 4 GiB pod
/// whose steady working set was ~550 MiB.
pub(crate) const RENDER_CACHE_BYTES: usize = 128 * 1024 * 1024;

/// Label of the in-flight gauge and coalesced counter for these renders.
const REGISTRY_LABEL: &str = "npm_packument";

/// How long a follower waits for the leader's render before rendering alone.
const FOLLOWER_BUDGET: Duration = Duration::from_secs(60);

struct Kept {
    value: Rendered,
    at: Instant,
}

#[derive(Default)]
struct Recent {
    entries: HashMap<String, Kept>,
    /// `(key, kept at)` in insertion order, oldest first. A pair whose entry was
    /// replaced since is skipped when it reaches the front.
    order: VecDeque<(String, Instant)>,
    bytes: usize,
}

impl Recent {
    fn remove(&mut self, key: &str) {
        if let Some(old) = self.entries.remove(key) {
            self.bytes -= old.value.len();
        }
    }

    /// Drop expired renders, then the oldest ones until the kept bytes fit `max_bytes`.
    fn evict(&mut self, now: Instant, ttl: Duration, max_bytes: usize) {
        while let Some((key, at)) = self.order.front() {
            let current = self.entries.get(key).is_some_and(|kept| kept.at == *at);
            if current && now.duration_since(*at) < ttl && self.bytes <= max_bytes {
                break;
            }
            if let Some((key, _)) = self.order.pop_front() {
                if current {
                    self.remove(&key);
                }
            }
        }
    }
}

/// Renders of proxied packuments, shared between requests. Cheap to share by reference.
pub(crate) struct PackumentMemo {
    flights: InflightMap<Rendered>,
    recent: Mutex<Recent>,
    ttl: Duration,
    max_bytes: usize,
}

impl Default for PackumentMemo {
    fn default() -> Self {
        Self::new(RENDER_TTL, RENDER_CACHE_BYTES)
    }
}

impl PackumentMemo {
    pub(crate) fn new(ttl: Duration, max_bytes: usize) -> Self {
        PackumentMemo {
            flights: InflightMap::new(),
            recent: Mutex::new(Recent::default()),
            ttl,
            max_bytes,
        }
    }

    /// The render kept for `key`, if one is and has not expired.
    pub(crate) fn lookup(&self, key: &str) -> Option<Rendered> {
        let recent = self.recent.lock();
        let kept = recent.entries.get(key)?;
        (kept.at.elapsed() < self.ttl).then(|| kept.value.clone())
    }

    fn remember(&self, key: &str, value: &Rendered) {
        if value.len() > self.max_bytes {
            return;
        }
        let now = Instant::now();
        let mut recent = self.recent.lock();
        recent.remove(key);
        recent.bytes += value.len();
        recent.entries.insert(
            key.to_string(),
            Kept {
                value: value.clone(),
                at: now,
            },
        );
        recent.order.push_back((key.to_string(), now));
        recent.evict(now, self.ttl, self.max_bytes);
    }

    /// The render for `key`: a kept one, the one a concurrent request is producing,
    /// or `render()` run here. `render` runs at most once per call.
    pub(crate) async fn render<F, Fut>(&self, key: &str, render: F) -> Rendered
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Rendered>,
    {
        if let Some(value) = self.lookup(key) {
            return value;
        }
        let mut render = Some(render);
        let shared = self
            .flights
            .coalesced(key, REGISTRY_LABEL, FOLLOWER_BUDGET, || {
                let render = render.take();
                async move {
                    let value = render?().await;
                    self.remember(key, &value);
                    Some(value)
                }
            })
            .await;
        // A follower whose leader gave nothing within the budget renders alone.
        match (shared, render) {
            (Some(value), _) => value,
            (None, Some(render)) => render().await,
            (None, None) => Rendered::default(),
        }
    }

    #[cfg(test)]
    fn kept(&self) -> (usize, usize) {
        let recent = self.recent.lock();
        (recent.entries.len(), recent.bytes)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn body(n: usize) -> Rendered {
        Rendered {
            body: Some((Bytes::from(vec![b'x'; n]), "application/json")),
            past_nora: false,
        }
    }

    #[tokio::test]
    async fn concurrent_requests_share_one_render() {
        let memo = Arc::new(PackumentMemo::default());
        let renders = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(tokio::sync::Notify::new());
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let (memo, renders, release) = (memo.clone(), renders.clone(), release.clone());
            tasks.push(tokio::spawn(async move {
                memo.render("vite", || async {
                    renders.fetch_add(1, Ordering::SeqCst);
                    release.notified().await;
                    body(10)
                })
                .await
            }));
        }
        // Every task is at its await: one in the render, seven waiting for it.
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        release.notify_one();
        for task in tasks {
            assert_eq!(task.await.unwrap(), body(10));
        }
        assert_eq!(renders.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn sequential_requests_reuse_the_render() {
        let memo = PackumentMemo::default();
        let renders = AtomicUsize::new(0);
        for _ in 0..3 {
            let out = memo
                .render("vite", || async {
                    renders.fetch_add(1, Ordering::SeqCst);
                    body(10)
                })
                .await;
            assert_eq!(out, body(10));
        }
        assert_eq!(renders.load(Ordering::SeqCst), 1);
        assert_eq!(memo.lookup("vite"), Some(body(10)));
        assert_eq!(memo.lookup("other"), None);
    }

    #[tokio::test(start_paused = true)]
    async fn an_expired_render_is_redone() {
        let memo = PackumentMemo::default();
        memo.render("k", || async { body(1) }).await;
        tokio::time::advance(RENDER_TTL - Duration::from_secs(1)).await;
        assert_eq!(memo.render("k", || async { body(2) }).await, body(1));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(memo.lookup("k"), None);
        assert_eq!(memo.render("k", || async { body(2) }).await, body(2));
    }

    #[tokio::test]
    async fn kept_bytes_stay_within_the_budget() {
        let memo = PackumentMemo::new(RENDER_TTL, 25);
        for i in 0..5 {
            memo.render(&format!("k{i}"), || async { body(10) }).await;
        }
        let (entries, bytes) = memo.kept();
        assert!(bytes <= 25, "kept {bytes} bytes");
        assert_eq!(entries, 2);
        // The newest render is the one kept.
        assert_eq!(memo.render("k4", || async { body(99) }).await, body(10));
        // A render larger than the whole budget is served, not kept.
        assert_eq!(memo.render("big", || async { body(30) }).await, body(30));
        assert_eq!(memo.kept().0, 2);
    }
}
