// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Pull statistics: the in-memory accumulator flushed into `.stats.json` sidecars
//! (#1114; moved out of docker.rs, R4-T12).

use super::*;

/// How often the background task folds accumulated pull counts into the
/// sidecars (#1114). Soft state: a crash loses at most this much (accepted).
pub(crate) const PULL_STATS_FLUSH_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(45);

/// Fold accumulated pull counts into their `.stats.json` sidecars every
/// `interval`, and once more on shutdown, so a hard crash loses at most one
/// interval of counts. Extracted from `main` (with the interval injected) so a
/// test can drive the tick path (not only the shutdown path): the loss bound
/// depends on the tick flush running, not just the final flush on cancel (#1114).
pub(crate) async fn pull_stats_flush_loop(state: AppState, interval: std::time::Duration) {
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        // CANCEL-SAFETY: both arms are cancel-safe (an interval tick and a
        // cancellation token). On shutdown we run one final flush, then stop.
        tokio::select! {
            _ = tick.tick() => {
                flush_pull_stats(&state).await;
            }
            _ = state.cancel_token.cancelled() => {
                flush_pull_stats(&state).await;
                break;
            }
        }
    }
}

/// Cumulative pull statistics for one manifest, stored in a `.stats.json`
/// sidecar beside its `.meta.json` (#1114). Kept out of `.meta.json` so a pull
/// never rewrites the integrity metadata a concurrent request reads.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub(crate) struct StatsSidecar {
    pub downloads: u64,
    pub last_pulled: u64,
}

/// The `.stats.json` sidecar key for a manifest's `.meta.json` key.
pub(super) fn manifest_stats_key(meta_key: &str) -> String {
    let base = meta_key.strip_suffix(".meta.json").unwrap_or(meta_key);
    format!("{base}.stats.json")
}

/// Cumulative stats for a manifest: the `.stats.json` sidecar if present, else
/// the legacy counts still in a pre-V3 `.meta.json` (migrated on the next flush),
/// else zero.
async fn read_cumulative_stats(storage: &Storage, meta_key: &str) -> StatsSidecar {
    let stats_key = manifest_stats_key(meta_key);
    if let Ok(data) = storage.get(&stats_key).await {
        if let Ok(s) = serde_json::from_slice::<StatsSidecar>(&data) {
            return s;
        }
    }
    // Migration: a manifest pushed before V3 still carries counts in .meta.json.
    if let Ok(data) = storage.get(meta_key).await {
        if let Ok(m) = serde_json::from_slice::<ImageMetadata>(&data) {
            return StatsSidecar {
                downloads: m.downloads,
                last_pulled: m.last_pulled,
            };
        }
    }
    StatsSidecar::default()
}

/// Current pull stats for the UI and reports: the flushed cumulative value plus
/// the un-flushed in-memory delta.
pub(crate) async fn current_pull_stats(state: &AppState, meta_key: &str) -> StatsSidecar {
    let base = read_cumulative_stats(&state.storage, meta_key).await;
    let delta = state.pull_stats.peek(meta_key);
    StatsSidecar {
        downloads: base.downloads + delta.downloads,
        last_pulled: base.last_pulled.max(delta.last_pulled),
    }
}

/// Drain the pull-stats accumulator and fold each delta into its `.stats.json`
/// sidecar (#1114). Keeps the deleted-manifest guard of the old per-pull
/// writer: a delta for a manifest no longer stored is dropped, never
/// resurrecting its stats. Replaces the per-pull `.meta.json` rewrite.
pub(crate) async fn flush_pull_stats(state: &AppState) {
    for (meta_key, delta) in state.pull_stats.drain() {
        if delta.downloads == 0 && delta.last_pulled == 0 {
            continue;
        }
        // Serialize with push/delete on this manifest, as the old per-pull writer
        // did: take the publish lock, THEN re-check the manifest is stored, so a
        // delete that landed since the pull cannot be undone by writing a stale
        // sidecar after it (the sidecar is removed under the same lock on delete).
        let lock = state.publish_lock(&meta_key);
        let _guard = lock.lock().await;
        // The manifest blob key is the meta key with `.meta.json` → `.json`
        // (what `manifest_key` builds); stripping only `.meta.json` would check
        // `…/<ref>` and always miss, so the guard would skip every flush and the
        // sidecar would never be written (the stats would be silently lost).
        let manifest_key = format!(
            "{}.json",
            meta_key.strip_suffix(".meta.json").unwrap_or(&meta_key)
        );
        // Deleted-manifest guard: never resurrect a gone manifest's stats.
        if state.storage.stat(&manifest_key).await.is_none() {
            continue;
        }
        let mut stats = read_cumulative_stats(&state.storage, &meta_key).await;
        stats.downloads += delta.downloads;
        stats.last_pulled = stats.last_pulled.max(delta.last_pulled);
        let stats_key = manifest_stats_key(&meta_key);
        if let Ok(json) = serde_json::to_vec(&stats) {
            if let Err(e) = state.storage.put(&stats_key, &json).await {
                tracing::warn!(key = %stats_key, error = %e, "pull-stats sidecar write failed");
                crate::metrics::CACHE_WRITE_ERRORS
                    .with_label_values(&["docker", "stats"])
                    .inc();
            }
        }
    }
}
