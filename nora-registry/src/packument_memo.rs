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
//! by the document's digest and the variant asked for, and is done once:
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
use std::time::{Duration, Instant};

use axum::body::Bytes;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};

use crate::proxy_coalesce::InflightMap;

/// A rendered packument: the body and its `Content-Type`.
pub(crate) type Rendered = (Bytes, &'static str);

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
            self.bytes -= old.value.0.len();
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

    /// The key of one render: package, variant and the digest of the source document,
    /// so a changed document never reuses an old render.
    pub(crate) fn key(name: &str, variant: &str, document: &[u8]) -> String {
        let digest = Sha256::digest(document);
        format!("{name}\n{variant}\n{}", hex::encode(digest))
    }

    fn lookup(&self, key: &str) -> Option<Rendered> {
        let recent = self.recent.lock();
        let kept = recent.entries.get(key)?;
        (kept.at.elapsed() < self.ttl).then(|| kept.value.clone())
    }

    fn remember(&self, key: &str, value: &Rendered) {
        if value.0.len() > self.max_bytes {
            return;
        }
        let now = Instant::now();
        let mut recent = self.recent.lock();
        recent.remove(key);
        recent.bytes += value.0.len();
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
    pub(crate) async fn render<F>(&self, key: &str, render: F) -> Rendered
    where
        F: FnOnce() -> Rendered,
    {
        if let Some(value) = self.lookup(key) {
            return value;
        }
        let mut render = Some(render);
        let mut own = None;
        let shared = self
            .flights
            .coalesced(key, REGISTRY_LABEL, FOLLOWER_BUDGET, || {
                let value = render.take().map(|render| render());
                if let Some(ref value) = value {
                    self.remember(key, value);
                }
                own.clone_from(&value);
                std::future::ready(value)
            })
            .await;
        // `coalesced` yields `None` only when this caller's own render did not run,
        // which cannot happen; fall back to rendering here rather than failing.
        match (shared, own, render) {
            (Some(value), _, _) | (None, Some(value), _) => value,
            (None, None, Some(render)) => render(),
            (None, None, None) => (Bytes::new(), "application/json"),
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
        (Bytes::from(vec![b'x'; n]), "application/json")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_requests_share_one_render() {
        let memo = Arc::new(PackumentMemo::default());
        let renders = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Barrier::new(8));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let (memo, renders, gate) = (memo.clone(), renders.clone(), gate.clone());
            tasks.push(tokio::spawn(async move {
                gate.wait().await;
                memo.render("vite\nfull\nabc", || {
                    renders.fetch_add(1, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(50));
                    body(10)
                })
                .await
            }));
        }
        for task in tasks {
            assert_eq!(task.await.unwrap().0.len(), 10);
        }
        assert!(
            renders.load(Ordering::SeqCst) < 8,
            "every request rendered alone"
        );
    }

    #[tokio::test]
    async fn sequential_requests_reuse_the_render() {
        let memo = PackumentMemo::default();
        let renders = AtomicUsize::new(0);
        for _ in 0..3 {
            let out = memo
                .render("vite\nfull\nabc", || {
                    renders.fetch_add(1, Ordering::SeqCst);
                    body(10)
                })
                .await;
            assert_eq!(out.0.len(), 10);
        }
        assert_eq!(renders.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_changed_document_is_rendered_again() {
        let memo = PackumentMemo::default();
        let a = PackumentMemo::key("vite", "full", b"{\"v\":1}");
        let b = PackumentMemo::key("vite", "full", b"{\"v\":2}");
        assert_ne!(a, b);
        assert_ne!(a, PackumentMemo::key("vite", "install-v1", b"{\"v\":1}"));
        memo.render(&a, || body(1)).await;
        assert_eq!(memo.render(&b, || body(2)).await.0.len(), 2);
    }

    #[tokio::test]
    async fn an_expired_render_is_redone() {
        let memo = PackumentMemo::new(Duration::from_millis(20), RENDER_CACHE_BYTES);
        memo.render("k", || body(1)).await;
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(memo.render("k", || body(2)).await.0.len(), 2);
    }

    #[tokio::test]
    async fn kept_bytes_stay_within_the_budget() {
        let memo = PackumentMemo::new(RENDER_TTL, 25);
        for i in 0..5 {
            memo.render(&format!("k{i}"), || body(10)).await;
        }
        let (entries, bytes) = memo.kept();
        assert!(bytes <= 25, "kept {bytes} bytes");
        assert_eq!(entries, 2);
        // The newest render is the one kept.
        assert_eq!(memo.render("k4", || body(99)).await.0.len(), 10);
        // A render larger than the whole budget is served, not kept.
        assert_eq!(memo.render("big", || body(30)).await.0.len(), 30);
        assert_eq!(memo.kept().0, 2);
    }
}
