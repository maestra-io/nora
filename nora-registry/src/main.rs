// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![deny(clippy::unwrap_used)]
// The storage boundary lists of clippy.toml are denied by ui/ and registry/ only.
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]
#![forbid(unsafe_code)]
#![warn(clippy::large_stack_frames, clippy::large_futures)]
// Test code is linted under `--all-targets` but is not held to the production
// restriction/style lints (see lib.rs for rationale). Scoped to `cfg(test)`.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::redundant_clone,
        clippy::int_plus_one,
        clippy::field_reassign_with_default,
        clippy::unnecessary_get_then_check,
        clippy::single_match,
        clippy::redundant_field_names,
        clippy::len_zero,
        clippy::items_after_test_module
    )
)]

// musl's mallocng serializes every allocation on one global lock, which collapses into kernel
// futex contention under many async workers; mimalloc's per-thread heaps avoid it. Feature
// `mimalloc` is on by default; `--no-default-features` falls back to the system allocator.
// Declaring the static needs no unsafe here (the GlobalAlloc impl lives in the crate), so
// `#![forbid(unsafe_code)]` still holds.
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod activity_log;
mod admin;
mod audit;
mod auth;
mod backup;
mod cache_ttl;
mod circuit_breaker;
mod cleanup;
mod config;
mod curation;
mod dashboard_metrics;
mod digest_quarantine;
mod docker_key_migration;
#[cfg(feature = "fault-injection")]
mod fault_injection;
mod gc;
mod hash_pin_store;
mod health;
mod import;
mod log_redact;
mod metadata_filter;
mod metrics;
mod migrate;
mod mirror;
mod openapi;
mod packument_memo;
mod proxy_coalesce;
mod quarantine_exceptions;
mod rate_limit;
mod registry;
mod registry_type;
mod repo_index;
mod request_id;
mod retention;
mod secrets;
mod server_conn;
#[cfg(any(feature = "rpm", feature = "deb"))]
mod signing;
/// Without rpm/deb nothing is signed: an uninhabited signer keeps `AppState.signer`
/// (always `None`) and every `Option<&RepoSigner>` signature unchanged.
#[cfg(not(any(feature = "rpm", feature = "deb")))]
mod signing {
    pub enum RepoSigner {}
}
mod storage;
mod supervise;
mod tokens;
mod ui;
mod validation;

#[cfg(test)]
mod test_env;
#[cfg(test)]
mod test_helpers;

use arc_swap::ArcSwap;
use axum::{body::Bytes, extract::DefaultBodyLimit, http::HeaderValue, middleware, Router};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::signal;
use tracing::{error, info, warn};
use tracing_subscriber::{prelude::*, EnvFilter};

use activity_log::ActivityLog;
use audit::AuditLog;
use auth::HtpasswdAuth;
use config::{Config, CurationMode, StorageMode, TlsConfig};
use dashboard_metrics::DashboardMetrics;
use registry_type::RegistryType;
use repo_index::RepoIndex;
use secrets::{expose_opt, ProtectedString};
use server_conn::ConnLimits;
pub use storage::Storage;
use tokens::TokenStore;

use futures::FutureExt;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};

#[derive(Parser)]
#[command(name = "nora", version, about = "Multi-protocol artifact registry")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the registry server (default)
    Serve,
    /// Backup all artifacts to a tar.gz file
    Backup {
        /// Output file path (e.g., backup.tar.gz)
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Restore artifacts from a backup file
    Restore {
        /// Input backup file path
        #[arg(short, long)]
        input: PathBuf,
    },
    /// Garbage collect orphaned blobs and checksum sidecars
    Gc {
        /// Actually delete orphans (default: dry-run only)
        #[arg(long, default_value = "false")]
        apply: bool,
    },
    /// Show retention plan (dry-run)
    RetentionPlan,
    /// Apply retention policies (delete old versions)
    RetentionApply {
        /// Confirm deletion (required to actually delete)
        #[arg(long)]
        yes: bool,
    },
    /// Migrate artifacts between storage backends
    Migrate {
        /// Source storage: local or s3
        #[arg(long)]
        from: String,
        /// Destination storage: local or s3
        #[arg(long)]
        to: String,
        /// Dry run - show what would be migrated without copying
        #[arg(long, default_value = "false")]
        dry_run: bool,
        /// Also delete destination keys the source does not have (with --dry-run: list them)
        #[arg(long, default_value = "false")]
        delete_extraneous: bool,
    },
    /// Pre-fetch dependencies through NORA proxy cache
    Mirror {
        #[command(subcommand)]
        format: mirror::MirrorFormat,
        /// NORA registry URL
        #[arg(long, default_value = "http://localhost:4000", global = true)]
        registry: String,
        /// Max concurrent downloads
        #[arg(long, default_value = "8", global = true)]
        concurrency: usize,
        /// Output results as JSON (for CI pipelines)
        #[arg(long, global = true)]
        json: bool,
    },
    /// Import artifacts from an external registry (Artifactory / Nexus) into NORA (#599)
    Import {
        #[command(subcommand)]
        action: import::ImportCommand,
    },
    /// Hosted NuGet feed maintenance
    Nuget {
        #[command(subcommand)]
        action: NugetCommand,
    },
    /// Curation tools: validate files, explain decisions
    Curation {
        #[command(subcommand)]
        action: CurationCommand,
    },
    /// Migrate legacy Docker storage keys to namespaced format
    MigrateDockerKeys {
        /// Dry run — show what would be migrated without modifying storage
        #[arg(long, default_value = "false")]
        dry_run: bool,
    },
    /// Recover an artifact whose hash pin no longer matches its bytes (#601).
    ///
    /// Updates the pin to `--expected` only if the on-disk bytes already hash
    /// to it. If the disk is genuinely corrupt (does not match), it refuses —
    /// re-pin cannot heal corruption; restore from backup first.
    RePin {
        /// Storage key, e.g. `raw/myorg/app-1.0.0.bin`
        key: String,
        /// The SHA-256 (64-char hex) the operator knows to be canonical for
        /// this key — from a CI manifest, upstream checksum, or lockfile.
        #[arg(long)]
        expected: String,
        /// Apply the change. Without this, prints what would change (dry run).
        #[arg(long)]
        yes: bool,
    },
    /// Check a running NORA server's health endpoint (for Docker HEALTHCHECK).
    ///
    /// Reads `NORA_HOST`/`NORA_PORT` the same way the server does, probes
    /// `GET /health`, and exits 0 on a 2xx response, 1 otherwise. Needs no
    /// external tools (curl/wget) and no hardcoded address.
    Healthcheck {
        /// Request timeout in seconds.
        #[arg(long, default_value = "5")]
        timeout_secs: u64,
    },
}

#[derive(Subcommand)]
enum NugetCommand {
    /// Rewrite a hosted ID's state document (`nuget/hosted-meta/{id}.json`) from its
    /// stored .nuspec/.nupkg blobs. `published` = blob last-modified; `listed` is kept
    /// where the current document still reads as JSON, else every version is listed.
    Rebuild {
        /// Package ID (case-insensitive)
        id: String,
        /// Write the document. Without this, prints what would be written (dry run).
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum CurationCommand {
    /// Validate blocklist/allowlist JSON files
    Validate {
        /// Path to the JSON file to validate
        file: PathBuf,
    },
    /// Explain curation decision for a specific package
    Explain {
        /// Package in format "registry:name@version" (e.g., "cargo:serde@1.0.0")
        package: String,
    },
}

/// Per-key publish locks — shared between AppState and GC to serialize
/// metadata read-modify-write operations on the same artifact.
///
/// # Lock ordering
///
/// `cleanup_lock` → `publish_lock`. Never acquire `cleanup_lock` while
/// holding a `publish_lock` (handlers never touch `cleanup_lock`).
pub type PublishLocks = Arc<parking_lot::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>;

/// One GC pass of the scheduler. A pass that removed anything marks every repository index
/// stale, so the dashboard, `/api/ui/stats` and the artifact gauges show the store and not
/// what it held before the pass; a write marks its own registry the same way.
#[allow(clippy::too_many_arguments)]
async fn gc_pass(
    storage: &Storage,
    publish_locks: &PublishLocks,
    repo_index: &RepoIndex,
    dry_run: bool,
    grace_secs: u64,
    npm_is_proxy: bool,
    go_is_proxy: bool,
    proxy_cache_max_bytes: u64,
    docker_cache: (u64, &[String]),
    curation: &curation::CurationEngine,
) -> gc::GcResult {
    let result = gc::run_gc(
        storage,
        publish_locks,
        dry_run,
        grace_secs,
        npm_is_proxy,
        go_is_proxy,
        proxy_cache_max_bytes,
        curation,
    )
    .await;
    let docker = gc::evict_docker_proxy_cache(
        storage,
        publish_locks,
        docker_cache.0,
        docker_cache.1,
        dry_run,
    )
    .await;
    if !dry_run && (result.removed_anything() || docker.evicted_files > 0) {
        repo_index.invalidate_all();
    }
    result
}

/// Storage namespaces of the Docker upstreams (`docker/<ns>/` holds what each proxied),
/// for `[gc] docker_proxy_cache_max_bytes`; none while Docker is disabled. Reads the
/// resolved enable-set (`NORA_REGISTRIES_ENABLE`, `[registries].enable`), which `nora gc`
/// never applies to `docker.enabled`.
fn docker_proxy_namespaces(config: &config::Config) -> Vec<String> {
    if !config
        .enabled_registries_quiet()
        .contains(&RegistryType::Docker)
    {
        return Vec::new();
    }
    config
        .docker
        .upstreams
        .iter()
        .map(|u| u.resolved_namespace())
        .collect()
}

/// The line the GC scheduler logs when a pass ends. Files evicted by
/// `[gc] proxy_cache_max_bytes` are counted apart from the orphans: they are neither in
/// `deleted` nor in its `bytes_freed`.
fn gc_done_line(result: &gc::GcResult, dry_run: bool) -> String {
    let eviction = &result.proxy_cache_eviction;
    if dry_run {
        // A dry pass deletes nothing: its counts are what a real pass would take.
        return format!(
            "GC scheduler: dry run in {:.1}s — {} orphans ({} bytes would be freed), {} would be evicted from the proxy cache ({} bytes), {} metadata phantoms, {} skipped (grace)",
            result.duration_secs,
            result.orphaned,
            result.bytes_freed,
            eviction.evicted_files,
            eviction.bytes_freed,
            result.metadata_phantoms_removed,
            result.skipped_recent
        );
    }
    format!(
        "GC scheduler: done in {:.1}s — {} orphans ({} deleted, {} bytes freed), {} evicted from the proxy cache ({} bytes freed), {} metadata phantoms, {} skipped (grace)",
        result.duration_secs,
        result.orphaned,
        result.deleted,
        result.bytes_freed,
        eviction.evicted_files,
        eviction.bytes_freed,
        result.metadata_phantoms_removed,
        result.skipped_recent
    )
}

/// One retention pass of the scheduler; a pass that deleted keys marks every repository
/// index stale, as `gc_pass` does. A pass that found versions to delete leaves one audit
/// entry: `retention-apply` when it deleted them, `retention-dry-run` when `dry_run` only
/// planned it, so the trail never records a deletion that did not happen.
async fn retention_pass(
    storage: &Storage,
    publish_locks: &PublishLocks,
    repo_index: &RepoIndex,
    signer: Option<&signing::RepoSigner>,
    rules: &[config::RetentionRule],
    dry_run: bool,
    audit: &AuditLog,
) -> retention::RetentionResult {
    let result = retention::run_retention(storage, publish_locks, signer, rules, dry_run).await;
    if !dry_run && result.deleted_keys > 0 {
        repo_index.invalidate_all();
    }
    if result.planned > 0 {
        audit.log(audit::AuditEntry::new(
            if dry_run {
                "retention-dry-run"
            } else {
                "retention-apply"
            },
            "scheduler",
            &format!("{} versions", result.planned),
            "*",
            &if dry_run {
                // Nothing was deleted: the bytes are what an applied pass would free.
                format!(
                    "would_free_bytes={} duration={:.1}s",
                    result.bytes_freed, result.duration_secs
                )
            } else {
                format!(
                    "keys={} bytes_freed={} duration={:.1}s",
                    result.deleted_keys, result.bytes_freed, result.duration_secs
                )
            },
        ));
    }
    result
}

/// Set `nora_artifacts_total` and the per-registry `nora_storage_bytes` from the
/// repository index, first starting a rebuild of each enabled registry's index that a
/// restart, a write or a cleanup pass marked stale, as a read of `/api/ui/stats` does. An
/// index nothing touched since its last rebuild is served from memory without a storage
/// round-trip; a stale one costs one listing of its registry.
async fn refresh_artifact_gauges(state: &AppState) {
    let repo_index = &state.repo_index;
    // Rebuilds start in the background and are waited for a bounded time: a stale index
    // still sets its gauges, the rebuilt one at the next tick.
    repo_index
        .settle(state.enabled_registries.iter().copied(), state)
        .await;
    for (rt, count) in repo_index.counts() {
        metrics::ARTIFACTS_TOTAL
            .with_label_values(&[rt.as_str()])
            .set(count as i64);
    }
    for (rt, bytes) in repo_index.sizes() {
        metrics::STORAGE_BYTES
            .with_label_values(&[rt.as_str()])
            .set(bytes as i64);
    }
}

/// Get or create a per-key publish lock for TOCTOU protection.
///
/// Used by both `AppState::publish_lock()` and GC metadata cleanup to ensure
/// all metadata writes to the same key are serialized.
pub fn acquire_publish_lock(locks: &PublishLocks, key: &str) -> Arc<tokio::sync::Mutex<()>> {
    let mut map = locks.lock();
    map.entry(key.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

/// Curation-related config that can be hot-reloaded via SIGHUP.
pub struct ReloadableConfig {
    pub curation_engine: curation::CurationEngine,
    pub bypass_token: Option<ProtectedString>,
}

/// deb proxy held versions: young-file key → (loaded at, index → filename → (name,
/// version, first_seen)).
pub(crate) type DebYoungCache = HashMap<
    String,
    (
        Instant,
        Arc<
            std::collections::BTreeMap<
                String,
                std::collections::BTreeMap<String, (String, String, i64)>,
            >,
        >,
    ),
>;

#[derive(Clone)]
pub struct AppState {
    pub storage: Storage,
    pub config: Arc<Config>,
    pub enabled_registries: Arc<HashSet<RegistryType>>,
    pub start_time: Instant,
    pub startup_duration_ms: u64,
    pub auth: Option<Arc<HtpasswdAuth>>,
    pub tokens: Option<TokenStore>,
    pub metrics: Arc<DashboardMetrics>,
    pub activity: Arc<ActivityLog>,
    pub audit: Arc<AuditLog>,
    pub docker_auth: Arc<registry::DockerAuth>,
    /// Docker publish-date listings walked per repository (ghcr, mcr, public.ecr.aws).
    pub docker_date_walks: Arc<registry::DockerDateWalks>,
    pub repo_index: Arc<RepoIndex>,
    pub http_client: reqwest::Client,
    /// The same client, except that it never follows a redirect: for a format whose answer
    /// depends on what each hop said (hf: the commit rides on the Hub's redirect).
    pub http_client_no_redirect: reqwest::Client,
    /// The same client, except that it follows a redirect only on the origin of the URL asked
    /// (npm tarballs: a private package's name goes to no other host).
    pub http_client_same_origin: reqwest::Client,
    /// Canonical repo ids the Hugging Face upstream named, for curation of aliases (#579).
    pub hf_canonical_ids: Arc<registry::hf::CanonicalIds>,
    pub upload_sessions: Arc<RwLock<HashMap<String, registry::docker::UploadSession>>>,
    /// Per-key publish locks for TOCTOU protection (immutable releases)
    publish_locks: PublishLocks,
    /// Hot-reloadable curation config (swapped atomically on SIGHUP).
    pub reloadable: Arc<ArcSwap<ReloadableConfig>>,
    /// Per-IP failed auth attempt tracker for brute-force protection
    pub auth_failures: Arc<auth::AuthFailureTracker>,
    /// OIDC validator for workload identity (CI/CD)
    pub oidc: Option<Arc<auth::OidcValidator>>,
    /// Maestra fork: Teleport app-access identity for the web UI.
    pub teleport: Option<Arc<auth::TeleportValidator>>,
    pub(crate) circuit_breaker: Arc<circuit_breaker::CircuitBreakerRegistry>,
    /// Single-flight coalescer for the proxy cache-miss path: collapses a
    /// thundering herd of concurrent requests for the same key into one
    /// upstream fetch (#595). In-memory and rebuildable (empty after restart).
    pub(crate) proxy_coalesce: proxy_coalesce::InflightMap<Bytes, registry::ProxyError>,
    /// Single-flight of proxied artifact cold misses, whose body may be spooled to disk.
    pub(crate) artifact_flights:
        proxy_coalesce::InflightMap<registry::ArtifactFill, registry::ProxyError>,
    /// Disk spool directory and byte budget (proxied artifacts, NuGet pushes, PyPI uploads).
    pub(crate) spool: Arc<registry::SpoolBudget>,
    /// Docker blob fills in flight, shared by every request for the blob (#1003).
    pub(crate) blob_flights: proxy_coalesce::InflightMap<registry::docker::SpoolShare>,
    /// Renders of proxied npm packuments, shared by concurrent and repeated requests.
    pub(crate) packument_memo: Arc<packument_memo::PackumentMemo>,
    pub digest_store: Arc<digest_quarantine::DigestStore>,
    /// Break-glass exceptions to the docker quarantine, re-read from `[docker] quarantine_exceptions`.
    pub quarantine_exceptions: Arc<quarantine_exceptions::QuarantineExceptions>,
    /// Repository index signer (rpm/deb). `None` = indexes are unsigned.
    pub signer: Option<Arc<signing::RepoSigner>>,
    /// Pre-compiled upstream hostname searchers for leak detection (#386)
    pub leak_finders: metrics::LeakFinders,
    /// Shared shutdown signal so on-demand background tasks (e.g. the admin
    /// reindex warm-up) stop promptly on SIGTERM/SIGINT (#306).
    pub cancel_token: tokio_util::sync::CancellationToken,
    /// In-memory index of hosted NuGet packages (maestra fork).
    pub(crate) nuget_hosted: Arc<registry::NugetHostedIndex>,
    /// deb proxy: versions held per repository, read on each package download
    /// (registry/deb_proxy.rs). Per state, so two servers in one process never share it.
    #[allow(dead_code)] // read only with the deb feature
    pub(crate) deb_young: Arc<parking_lot::Mutex<DebYoungCache>>,
    /// Off-request-path docker pull-stats accumulator (#1114): a manifest GET
    /// bumps the per-key counter here; a background task flushes it in batches
    /// to a `.stats.json` sidecar, so `.meta.json` is never rewritten by a pull.
    /// In-memory, rebuildable-empty after a restart.
    pub(crate) pull_stats: Arc<registry::docker::PullStatsAccumulator>,
    /// The supervisor of the long-lived background tasks; `/health` asks it (supervise.rs).
    pub(crate) tasks: Arc<supervise::Supervisor>,
    /// The maintenance loop's heartbeat, which `tasks` reads.
    pub(crate) maintenance: Arc<supervise::Heartbeat>,
}

impl AppState {
    /// Load a snapshot of the current curation engine (lock-free read via ArcSwap).
    pub fn curation(&self) -> arc_swap::Guard<Arc<ReloadableConfig>> {
        self.reloadable.load()
    }

    /// Shorthand for the curation bypass token from the reloadable config.
    pub fn bypass_token(&self) -> Option<String> {
        self.reloadable
            .load()
            .bypass_token
            .as_ref()
            .map(|s| s.expose().to_string())
    }

    /// Get or create a per-key publish lock for TOCTOU protection.
    pub fn publish_lock(&self, key: &str) -> Arc<tokio::sync::Mutex<()>> {
        acquire_publish_lock(&self.publish_locks, key)
    }

    /// Background-cache proxy data and invalidate the registry index.
    ///
    /// Use for ALL proxy caching instead of manual `tokio::spawn` + `storage.put`.
    /// Guarantees that `repo_index.invalidate()` is called AFTER the write completes,
    /// avoiding the race condition where invalidation fires before the file lands on S3.
    pub fn spawn_cache(&self, registry: &'static str, key: String, data: Bytes) {
        let storage = self.storage.clone();
        let repo_index = Arc::clone(&self.repo_index);
        tokio::spawn(
            std::panic::AssertUnwindSafe(async move {
                match storage.put_bytes(&key, data).await {
                    Ok(()) => repo_index.invalidate(registry),
                    Err(e) => record_cache_write_error(registry, &key, &e),
                }
            })
            .catch_unwind()
            .map(|r| {
                if let Err(e) = r {
                    tracing::error!(panic = ?e, "background cache task panicked");
                }
            }),
        );
    }

    /// Like [`spawn_cache`], but never overwrites an existing key (immutable artifacts).
    pub fn spawn_cache_immutable(&self, registry: &'static str, key: String, data: Bytes) {
        let storage = self.storage.clone();
        let repo_index = Arc::clone(&self.repo_index);
        tokio::spawn(
            std::panic::AssertUnwindSafe(async move {
                // One create-only write: two fills of the same key cannot both land.
                match storage.put_if_absent(&key, data).await {
                    Ok(true) => repo_index.invalidate(registry),
                    Ok(false) => {}
                    Err(e) => record_cache_write_error(registry, &key, &e),
                }
            })
            .catch_unwind()
            .map(|r| {
                if let Err(e) = r {
                    tracing::error!(panic = ?e, "background cache task panicked");
                }
            }),
        );
    }
}

/// Cadence of the full-bucket size walk behind `nora_storage_bytes{registry="total"}`.
const STORAGE_SIZE_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);

/// A background cache write failed: the client was already served from upstream,
/// so without this the proxy silently degrades to pass-through (e.g. expired bucket
/// credentials). Logged and counted in `nora_cache_write_errors_total`.
pub(crate) fn record_cache_write_error(registry: &str, key: &str, err: &dyn std::fmt::Display) {
    tracing::warn!(registry, key, error = %err, "background cache write failed");
    metrics::CACHE_WRITE_ERRORS
        .with_label_values(&[registry, "put"])
        .inc();
}

/// Mask credentials in a proxy URL for safe logging.
///
/// `http://user:pass@proxy:3128` → `http://***@proxy:3128`
fn sanitize_proxy_url(url: &str) -> String {
    // Try to find userinfo (anything before @ in authority)
    if let Some(at_pos) = url.find('@') {
        // Find the scheme separator
        let scheme_end = url.find("://").map(|p| p + 3).unwrap_or(0);
        if at_pos > scheme_end {
            return format!("{}***@{}", &url[..scheme_end], &url[at_pos + 1..]);
        }
    }
    url.to_string()
}

/// Log detected outbound proxy configuration from environment variables.
fn log_outbound_proxy() {
    let vars = [
        "ALL_PROXY",
        "all_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
    ];
    for var in &vars {
        if let Ok(val) = std::env::var(var) {
            if !val.is_empty() {
                info!(var = %var, proxy = %sanitize_proxy_url(&val), "Outbound proxy detected from environment");
                break;
            }
        }
    }
    let no_proxy = std::env::var("NO_PROXY")
        .or_else(|_| std::env::var("no_proxy"))
        .unwrap_or_default();
    if !no_proxy.is_empty() {
        info!(no_proxy = %no_proxy, "NO_PROXY exclusions configured");
    }
}

/// User-Agent sent by all outbound HTTP clients. Compile-time `&'static str`
/// via `concat!`/`env!` — no per-call heap allocation.
const USER_AGENT: &str = concat!("nora/", env!("CARGO_PKG_VERSION"));

/// Build HTTP client with optional custom CA certificate support.
///
/// When `timeout` is `Some`, a default request timeout is set on the client
/// (used by `nora mirror` for long-running downloads). When `no_proxy` is true
/// the client ignores any `HTTP(S)_PROXY` env — required for loopback probes
/// (the healthcheck) that must reach the local server directly, not via an
/// upstream proxy. `redirect` is reqwest's own default (`Policy::default()`) for
/// every client but the one in [`build_no_redirect_client`].
fn build_http_client(
    tls: &TlsConfig,
    timeout: Option<std::time::Duration>,
    no_proxy: bool,
    redirect: reqwest::redirect::Policy,
) -> reqwest::Client {
    // A black-holed upstream fails the connect in seconds instead of eating the
    // whole per-request timeout (twice, with the proxy retry).
    // Idle pooled connections are dropped after 30 s, before the usual 60 s idle
    // cut of upstream load balancers/CDNs: reusing one they already closed fails the
    // request (reqwest's default keeps them 90 s).
    let mut builder = reqwest::ClientBuilder::new()
        .user_agent(USER_AGENT)
        .connect_timeout(std::time::Duration::from_secs(10))
        .pool_idle_timeout(std::time::Duration::from_secs(30))
        .redirect(redirect);

    if let Some(t) = timeout {
        builder = builder.timeout(t);
    }

    if no_proxy {
        builder = builder.no_proxy();
    }

    if let Some(ref ca_path) = tls.ca_cert {
        match std::fs::read(ca_path) {
            Ok(pem) => match reqwest::tls::Certificate::from_pem(&pem) {
                Ok(cert) => {
                    builder = builder.add_root_certificate(cert);
                    info!(path = %ca_path, "Custom CA certificate loaded");
                }
                Err(e) => {
                    error!(path = %ca_path, error = %e, "Failed to parse CA certificate");
                    panic!("Cannot start with invalid CA certificate: {}", ca_path);
                }
            },
            Err(e) => {
                error!(path = %ca_path, error = %e, "Failed to read CA certificate file");
                panic!(
                    "Cannot start: CA certificate file not readable: {}",
                    ca_path
                );
            }
        }
    }

    builder.build().expect("Failed to build HTTP client")
}

/// The client that never follows a redirect, for a format whose answer depends on what each
/// hop said (hf: the commit rides on the Hub's redirect). Built by [`build_http_client`]
/// (custom CA, user agent, proxy settings); the test context builds it here too, so the
/// tests run against the very client the server uses.
pub(crate) fn build_no_redirect_client(tls: &TlsConfig) -> reqwest::Client {
    build_http_client(tls, None, false, reqwest::redirect::Policy::none())
}

/// The client that follows a redirect only on the origin (scheme, host and port) of the URL
/// asked, up to reqwest's default ten hops, for a format whose upstream names a private package
/// in the path: a hop to another origin is handed back unfollowed, so that name and the request
/// go to no host NORA was not given. Built by [`build_http_client`], here for the test context
/// too.
pub(crate) fn build_same_origin_client(tls: &TlsConfig) -> reqwest::Client {
    build_http_client(tls, None, false, same_origin_redirects())
}

/// Each redirect is decided by [`nora_registry::npm_links::next_hop`]: one the credential may go
/// along is followed, one off the origin is handed back, and past the tenth the request fails.
pub(crate) fn same_origin_redirects() -> reqwest::redirect::Policy {
    use nora_registry::npm_links::{self, Hop};
    reqwest::redirect::Policy::custom(|attempt| {
        // The previous URLs are the one asked, first, and every hop followed since: the
        // redirect being decided is the `len()`-th.
        let previous = attempt.previous();
        let Some(asked) = previous.first() else {
            return attempt.stop();
        };
        let left_origin = previous.iter().any(|u| !npm_links::same_origin(asked, u));
        match npm_links::next_hop(previous.len(), asked, left_origin, attempt.url()) {
            Hop::WithCredential => attempt.follow(),
            Hop::WithoutCredential => attempt.stop(),
            Hop::Refuse => attempt.error("redirect not followed"),
        }
    })
}

/// Build the `/health` probe URL from the configured listen host. Wildcard
/// binds are probed over loopback — you cannot connect *to* `0.0.0.0` / `::`.
/// Both wildcards probe `127.0.0.1`: a `::` server is dual-stack (or falls back
/// to `0.0.0.0`), so IPv4 loopback reaches it in every case, whereas `::1` would
/// miss the fallback.
fn healthcheck_url(host: &str, port: u16) -> String {
    let h = match host {
        "0.0.0.0" | "::" | "[::]" => "127.0.0.1",
        other => other,
    };
    // Bracket a bare IPv6 literal for the URL authority.
    if h.contains(':') && !h.starts_with('[') {
        format!("http://[{h}]:{port}/health")
    } else {
        format!("http://{h}:{port}/health")
    }
}

/// Probe a running server's `/health` and map the result to a process exit
/// code: 0 if it returns 2xx (server up), 1 otherwise. Backs the `healthcheck`
/// subcommand so Docker HEALTHCHECK needs no curl/wget and no hardcoded address.
async fn run_healthcheck(timeout_secs: u64) -> i32 {
    // Read the listen host/port the same way the server does (env vars), without
    // loading or validating the full config — a probe must not abort on a missing
    // NORA_PUBLIC_URL or any other server-only requirement.
    let host = std::env::var("NORA_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port: u16 = std::env::var("NORA_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(4000);
    let url = healthcheck_url(&host, port);
    // Reuse the central HTTP client builder, but with no_proxy: a loopback probe
    // must reach the local server directly, never through an upstream HTTP proxy
    // (which would 502 the local address when HTTP_PROXY is set).
    let client = build_http_client(
        &TlsConfig::default(),
        Some(std::time::Duration::from_secs(timeout_secs)),
        true,
        reqwest::redirect::Policy::default(),
    );
    match client.get(&url).send().await {
        // /health returns 200 when healthy, 503 when storage is unreachable.
        Ok(resp) if resp.status().is_success() => 0,
        Ok(resp) => {
            eprintln!("healthcheck: {url} -> HTTP {}", resp.status());
            1
        }
        Err(e) => {
            eprintln!("healthcheck: {url} -> {e}");
            1
        }
    }
}

/// The request layers inside metrics, shared by the server and the test router so the
/// tests run the order the server runs (#542). Innermost first: curation_refusal (audit)
/// → request_id → leak_detection → rewrite_ui_base_path → auth → catch_panic. auth runs
/// first of these after catch_panic;
/// the audit layer sits inside it so it knows who was refused, and request_id runs before
/// the handler so the ID is available to it.
/// Response security headers applied to every route, outermost. `nosniff`,
/// `DENY` framing and the referrer policy are uniform and override whatever a
/// handler set. The Content-Security-Policy is added only when a handler set
/// none (`if_not_present`): the UI's permissive policy (it needs `unsafe-inline`)
/// is the default, but the raw download handler sets its own `sandbox` policy on
/// user-uploaded bytes and that stricter one must survive. Kept in one function
/// so the server and its test run the same layering.
pub(crate) fn apply_security_headers<S>(router: Router<S>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    use tower_http::set_header::SetResponseHeaderLayer;
    router
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'"),
        ))
}

pub(crate) fn request_layers(router: Router<AppState>, state: &AppState) -> Router<AppState> {
    router
        .layer(middleware::from_fn_with_state(
            state.clone(),
            audit::curation_refusal_middleware,
        ))
        .layer(middleware::from_fn(request_id::request_id_middleware))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            metrics::leak_detection_middleware,
        ))
        // Prefix the UI's root-absolute self-links + redirects with the public_url
        // path so the UI works under a sub-path behind a proxy. No-op when unset;
        // only buffers text/html (UI pages), so blob streams pass through untouched.
        .layer(middleware::from_fn_with_state(
            state.clone(),
            ui::rewrite_ui_base_path,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ))
        // Outermost of these, so a panic in auth, a middleware or a handler answers 500
        // (counted by the metrics layer outside) and the panic message goes to the log only.
        .layer(tower_http::catch_panic::CatchPanicLayer::new())
}

#[cfg(test)]
#[path = "main_tests/panic_strategy_tests.rs"]
mod panic_strategy_tests;

#[cfg(test)]
#[path = "main_tests/panic_layer_tests.rs"]
mod panic_layer_tests;

#[cfg(test)]
#[path = "main_tests/middleware_stack_tests.rs"]
mod middleware_stack_tests;

#[cfg(test)]
#[path = "main_tests/ops_tests.rs"]
mod ops_tests;

#[cfg(test)]
#[path = "main_tests/security_header_tests.rs"]
mod security_header_tests;

#[cfg(test)]
#[path = "main_tests/healthcheck_tests.rs"]
mod healthcheck_tests;

/// Bind the server's TCP listener, preferring dual-stack for the IPv6 wildcard.
///
/// For `::` we create the socket explicitly and clear `IPV6_V6ONLY`, so the
/// listener accepts both IPv4 and IPv6 regardless of the host's `bindv6only`
/// sysctl (#574). If IPv6 is unavailable, we fall back to `0.0.0.0` (IPv4-only)
/// rather than failing to start. Any other host (specific IP or name) binds
/// normally.
async fn bind_listener(host: &str, port: u16) -> std::io::Result<tokio::net::TcpListener> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    if host == "::" || host == "0:0:0:0:0:0:0:0" {
        let v6 = SocketAddr::from((Ipv6Addr::UNSPECIFIED, port));
        match bind_v6_dual_stack(v6) {
            Ok(listener) => return Ok(listener),
            Err(e) => {
                warn!(
                    error = %e,
                    "dual-stack bind on [::] failed; falling back to 0.0.0.0 (IPv4-only)"
                );
                let v4 = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
                return tokio::net::TcpListener::bind(v4).await;
            }
        }
    }
    tokio::net::TcpListener::bind((host, port)).await
}

/// Create a dual-stack (`IPV6_V6ONLY = false`) IPv6 listener via `socket2`,
/// returning it as a non-blocking `tokio` listener.
fn bind_v6_dual_stack(addr: std::net::SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    use socket2::{Domain, Socket, Type};

    let socket = Socket::new(Domain::IPV6, Type::STREAM, None)?;
    socket.set_only_v6(false)?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    let std_listener: std::net::TcpListener = socket.into();
    tokio::net::TcpListener::from_std(std_listener)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[path = "main_tests/shutdown_drain_tests.rs"]
mod shutdown_drain_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[path = "main_tests/connection_limit_tests.rs"]
mod connection_limit_tests;

#[cfg(test)]
#[path = "main_tests/bind_tests.rs"]
mod bind_tests;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize logging (JSON for server, plain for CLI commands)
    let is_server = matches!(cli.command, None | Some(Commands::Serve));
    let _log_guard = init_logging(is_server);

    // Healthcheck is a client-side probe (Docker HEALTHCHECK) — handle it before
    // loading the full server config, which it does not need and which can abort
    // (e.g. NORA_PUBLIC_URL is required on a 0.0.0.0 bind).
    if let Some(Commands::Healthcheck { timeout_secs }) = &cli.command {
        std::process::exit(run_healthcheck(*timeout_secs).await);
    }

    let config = match Config::load() {
        Ok(config) => config,
        Err(e) => {
            // A clean, non-retried stop: the units list EXIT_CONFIG in
            // RestartPreventExitStatus= (#1025).
            error!(error = %e, "Cannot start with this configuration");
            eprintln!("nora: {e}");
            std::process::exit(config::EXIT_CONFIG);
        }
    };

    // Initialize storage based on mode
    let storage = match config.storage.mode {
        StorageMode::Local => {
            if is_server {
                info!(path = %config.storage.path, "Using local storage");
            }
            Storage::new_local(&config.storage.path)
        }
        StorageMode::S3 => {
            if is_server {
                info!(
                    s3_url = %config.storage.s3_url,
                    bucket = %config.storage.bucket,
                    region = %config.storage.s3_region,
                    has_credentials = config.storage.s3_access_key.is_some(),
                    credentials_dir = ?config.storage.s3_credentials_dir,
                    virtual_hosted = config.storage.s3_virtual_hosted,
                    "Using S3 storage"
                );
            }
            Storage::new_s3(
                &config.storage.s3_url,
                &config.storage.bucket,
                &config.storage.s3_region,
                expose_opt(&config.storage.s3_access_key),
                expose_opt(&config.storage.s3_secret_key),
                config.storage.s3_credentials_dir.as_deref(),
                config.storage.s3_virtual_hosted,
            )
        }
        StorageMode::Gcs => {
            if is_server {
                info!(
                    bucket = %config.storage.bucket,
                    has_service_account = config.storage.gcs_service_account_path.is_some(),
                    base_url = %config.storage.gcs_base_url.as_deref().unwrap_or("https://storage.googleapis.com"),
                    "Using Google Cloud Storage"
                );
            }
            Storage::new_gcs(
                &config.storage.bucket,
                config.storage.gcs_service_account_path.as_deref(),
                config.storage.gcs_base_url.as_deref(),
            )
        }
    };

    // Dispatch to command
    match cli.command {
        None | Some(Commands::Serve) => {
            // Boxed: the server's start future is past clippy's large-future bound.
            Box::pin(run_server(config, storage)).await;
        }
        Some(Commands::Backup { output }) => {
            if let Err(e) = backup::create_backup(&storage, &output).await {
                error!("Backup failed: {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::Restore { input }) => {
            if let Err(e) = backup::restore_backup(&storage, &input).await {
                error!("Restore failed: {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::Gc { apply }) => {
            let dry_run = !apply;
            let cli_publish_locks: PublishLocks = Arc::new(parking_lot::Mutex::new(HashMap::new()));
            // Proxy-cache eviction must know the internal namespaces it never evicts.
            let curation = build_curation_engine(&config).unwrap_or_else(|e| {
                error!("GC: {}", e);
                std::process::exit(1);
            });
            // Grace applies to manual GC too: `nora gc --apply` is often run while
            // traffic is live, when in-flight pushes are most likely (#584).
            let result = gc::run_gc(
                &storage,
                &cli_publish_locks,
                dry_run,
                config.gc.grace_secs,
                !config.npm.upstream_urls().is_empty(),
                config.go.proxy.is_some(),
                config.gc.proxy_cache_max_bytes,
                &curation,
            )
            .await;
            let docker = gc::evict_docker_proxy_cache(
                &storage,
                &cli_publish_locks,
                config.gc.docker_proxy_cache_max_bytes,
                &docker_proxy_namespaces(&config),
                dry_run,
            )
            .await;
            println!("GC Summary{}:", if dry_run { " (dry-run)" } else { "" });
            if docker.evicted_files > 0 {
                println!(
                    "  Docker proxy cache: {} blobs, {} bytes {}",
                    docker.evicted_files,
                    docker.bytes_freed,
                    if dry_run {
                        "would be evicted"
                    } else {
                        "evicted"
                    }
                );
            }
            println!("  Candidates:       {}", result.total_candidates);
            println!("  Orphaned:          {}", result.orphaned);
            println!("  Deleted:           {}", result.deleted);
            println!("  Bytes freed:       {}", result.bytes_freed);
            if result.docker_mark_failed {
                println!("  Docker sweep:      skipped (manifest graph incomplete; all Docker objects kept)");
            }
            if result.skipped_recent > 0 {
                println!(
                    "  Skipped (grace):   {} (younger than {}s — likely in-flight uploads)",
                    result.skipped_recent, config.gc.grace_secs
                );
            }
            if result.stat_failures > 0 {
                println!(
                    "  Stat failures:     {} (kept, age unknown — GC may be unable to reclaim space)",
                    result.stat_failures
                );
            }
            println!("  Duration:          {:.1}s", result.duration_secs);
            if dry_run && !result.orphan_keys.is_empty() {
                println!("\nOrphan keys:");
                for key in &result.orphan_keys {
                    println!("  {}", key);
                }
                println!("\nRun with --apply to delete orphans.");
            }
            if result.proxy_cache_eviction.evicted_files > 0
                || result.proxy_cache_eviction.total_bytes > 0
            {
                let e = &result.proxy_cache_eviction;
                println!(
                    "  Proxy cache:       {} bytes total, {} files evicted, {} bytes freed",
                    e.total_bytes, e.evicted_files, e.bytes_freed
                );
            }
            if !result.uncovered.is_empty() {
                let parts: Vec<String> = result
                    .uncovered
                    .iter()
                    .map(|(name, count)| format!("{} ({} files)", name, count))
                    .collect();
                println!("\nNote: GC does not scan: {}", parts.join(", "));
            }
            if result.docker_mark_failed {
                std::process::exit(1);
            }
        }
        Some(Commands::RetentionPlan) => {
            let cli_publish_locks: PublishLocks = Arc::new(parking_lot::Mutex::new(HashMap::new()));
            // Dry-run: plans only, no deletions and no index regeneration —
            // no signer needed.
            let result = retention::run_retention(
                &storage,
                &cli_publish_locks,
                None,
                &config.retention.rules,
                true,
            )
            .await;
            println!("Retention Plan (dry-run):");
            println!("  Versions to delete: {}", result.planned);
            println!("  Bytes to free:      {}", result.bytes_freed);
            for (group, plans) in &result.plans {
                for plan in plans {
                    println!(
                        "  {} / {} — {} ({})",
                        group, plan.version_name, plan.reason, plan.size
                    );
                }
            }
            if result.planned == 0 {
                println!("\nNothing to delete.");
            } else {
                println!("\nRun `nora retention-apply` to execute.");
            }
            print_retention_coverage(&storage, &config.retention.rules).await;
        }
        Some(Commands::RetentionApply { yes }) => {
            let cli_publish_locks: PublishLocks = Arc::new(parking_lot::Mutex::new(HashMap::new()));
            if !yes {
                // Show plan first, require --yes to execute
                let result = retention::run_retention(
                    &storage,
                    &cli_publish_locks,
                    None,
                    &config.retention.rules,
                    true,
                )
                .await;
                println!("Retention Plan:");
                println!("  Versions to delete: {}", result.planned);
                println!("  Bytes to free:      {}", result.bytes_freed);
                for (group, plans) in &result.plans {
                    for plan in plans {
                        println!(
                            "  {} / {} — {} ({})",
                            group, plan.version_name, plan.reason, plan.size
                        );
                    }
                }
                if result.planned > 0 {
                    println!(
                        "\nThis will delete {} versions. Run with --yes to confirm.",
                        result.planned
                    );
                } else {
                    println!("\nNothing to delete.");
                }
                print_retention_coverage(&storage, &config.retention.rules).await;
            } else {
                // Real deletions rebuild rpm/deb indexes — sign them with the
                // same key the server would, or clients start failing
                // verification after a CLI retention pass.
                let signer = build_signer(&config, &config.enabled_registries());
                let result = retention::run_retention(
                    &storage,
                    &cli_publish_locks,
                    signer.as_deref(),
                    &config.retention.rules,
                    false,
                )
                .await;
                println!("Retention Applied:");
                println!("  Versions deleted:   {}", result.planned);
                println!("  Keys deleted:       {}", result.deleted_keys);
                if result.delete_failures > 0 {
                    println!(
                        "  Deletes refused:    {} version(s), deletion incomplete; see the warnings in the log",
                        result.delete_failures
                    );
                }
                println!("  Bytes freed:        {}", result.bytes_freed);
                if result.planned > 0 {
                    let audit = AuditLog::new(&config.storage.path, config.audit.mode.clone());
                    audit.log(audit::AuditEntry::new(
                        "retention-apply",
                        "cli",
                        &format!("{} versions", result.planned),
                        "*",
                        &format!(
                            "keys={} bytes_freed={} duration={:.1}s",
                            result.deleted_keys, result.bytes_freed, result.duration_secs
                        ),
                    ));
                    audit.shutdown().await;
                }
                print_retention_coverage(&storage, &config.retention.rules).await;
            }
        }
        Some(Commands::Mirror {
            format,
            registry,
            concurrency,
            json,
        }) => {
            let client = build_http_client(
                &config.tls,
                Some(std::time::Duration::from_secs(300)),
                false,
                reqwest::redirect::Policy::default(),
            );
            if let Err(e) = mirror::run_mirror(format, &registry, concurrency, json, &client).await
            {
                error!("Mirror failed: {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::Migrate {
            from,
            to,
            dry_run,
            delete_extraneous,
        }) => {
            let source = match from.as_str() {
                "local" => Storage::new_local(&config.storage.path),
                "s3" => Storage::new_s3(
                    &config.storage.s3_url,
                    &config.storage.bucket,
                    &config.storage.s3_region,
                    expose_opt(&config.storage.s3_access_key),
                    expose_opt(&config.storage.s3_secret_key),
                    config.storage.s3_credentials_dir.as_deref(),
                    config.storage.s3_virtual_hosted,
                ),
                "gcs" => Storage::new_gcs(
                    &config.storage.bucket,
                    config.storage.gcs_service_account_path.as_deref(),
                    config.storage.gcs_base_url.as_deref(),
                ),
                _ => {
                    error!("Invalid source: '{}'. Use 'local', 's3', or 'gcs'", from);
                    std::process::exit(1);
                }
            };

            let dest = match to.as_str() {
                "local" => Storage::new_local(&config.storage.path),
                "s3" => Storage::new_s3(
                    &config.storage.s3_url,
                    &config.storage.bucket,
                    &config.storage.s3_region,
                    expose_opt(&config.storage.s3_access_key),
                    expose_opt(&config.storage.s3_secret_key),
                    config.storage.s3_credentials_dir.as_deref(),
                    config.storage.s3_virtual_hosted,
                ),
                "gcs" => Storage::new_gcs(
                    &config.storage.bucket,
                    config.storage.gcs_service_account_path.as_deref(),
                    config.storage.gcs_base_url.as_deref(),
                ),
                _ => {
                    error!("Invalid destination: '{}'. Use 'local', 's3', or 'gcs'", to);
                    std::process::exit(1);
                }
            };

            if from == to {
                error!("Source and destination cannot be the same");
                std::process::exit(1);
            }

            let options = migrate::MigrateOptions {
                dry_run,
                delete_extraneous,
            };

            if let Err(e) = migrate::migrate(&source, &dest, options).await {
                error!("Migration failed: {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::Nuget {
            action: NugetCommand::Rebuild { id, yes },
        }) => match registry::nuget::hosted::rebuild(&storage, &id, yes).await {
            Ok(versions) => {
                for (version, listed) in &versions {
                    println!(
                        "  {id} {version}{}",
                        if *listed { "" } else { " (unlisted)" }
                    );
                }
                if yes {
                    println!(
                        "Rebuilt {} versions. A running server re-reads a corrupt document on the next request for the ID; otherwise run POST /api/v1/admin/reindex?registry=nuget.",
                        versions.len()
                    );
                } else {
                    println!(
                        "Would write {} versions. Re-run with --yes to apply.",
                        versions.len()
                    );
                }
            }
            Err(e) => {
                error!("nuget rebuild failed: {e}");
                std::process::exit(1);
            }
        },
        Some(Commands::Curation { action }) => match action {
            CurationCommand::Validate { file } => {
                run_curation_validate(&file);
            }
            CurationCommand::Explain { package } => {
                run_curation_explain(&config, &package);
            }
        },
        Some(Commands::Import { action }) => {
            if let Err(e) = import::run(action, &storage, &config).await {
                error!("Import failed: {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::MigrateDockerKeys { dry_run }) => {
            let namespace = config
                .docker
                .upstreams
                .first()
                .map(|u| u.resolved_namespace())
                .unwrap_or_else(|| "docker.io".to_string());

            if config.docker.upstreams.len() > 1 {
                warn!(
                    namespace = %namespace,
                    upstream_count = config.docker.upstreams.len(),
                    "Multiple Docker upstreams configured; using first upstream namespace for migration"
                );
            }

            match docker_key_migration::migrate_docker_keys(
                &storage,
                &namespace,
                docker_key_migration::MigrateDockerKeysOptions { dry_run },
            )
            .await
            {
                Ok(stats) => {
                    if stats.failed > 0 {
                        error!("{} keys failed to migrate", stats.failed);
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    error!("Docker key migration failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Some(Commands::RePin { key, expected, yes }) => {
            let expected = expected.to_ascii_lowercase();
            if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
                error!("--expected must be a 64-character hex SHA-256");
                std::process::exit(2);
            }
            match storage.repin(&key, &expected, yes).await {
                Ok(storage::RepinOutcome::DiskMismatch { disk, expected }) => {
                    error!(
                        key = %key,
                        on_disk = %disk,
                        expected = %expected,
                        "re-pin refused: on-disk bytes do not match --expected — the artifact is corrupt. Restore it from backup, then re-pin."
                    );
                    std::process::exit(1);
                }
                Ok(storage::RepinOutcome::AlreadyPinned { hash }) => {
                    println!("Pin already matches {hash} — nothing to do.");
                }
                Ok(storage::RepinOutcome::WouldUpdate { old, new }) => {
                    println!(
                        "Would re-pin {key}:\n  old: {}\n  new: {new}\nRe-run with --yes to apply.",
                        old.as_deref().unwrap_or("(none)")
                    );
                }
                Ok(storage::RepinOutcome::Updated { old, new }) => {
                    // Loud audit trail — re-pin is a privileged integrity override.
                    warn!(
                        key = %key,
                        old = ?old,
                        new = %new,
                        "INTEGRITY RE-PIN: hash pin updated by operator (#601)"
                    );
                    println!(
                        "Re-pinned {key}:\n  old: {}\n  new: {new}",
                        old.as_deref().unwrap_or("(none)")
                    );
                }
                Err(e) => {
                    error!(key = %key, "re-pin failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        // Handled before storage init by the early dispatch above; the process
        // has already exited by the time control would reach here.
        Some(Commands::Healthcheck { .. }) => unreachable!(),
    }
}

/// Build the repository index signer (#128). `None` disables signing:
/// explicitly via config, when no signing-capable registry (rpm/deb) is
/// enabled, or on S3 storage without a configured `signing.key_path` (warned
/// — there is no local data directory to keep a generated key in). A present
/// but unreadable/corrupt key is fatal: silently serving unsigned (or with a
/// silently rotated key) would break every client pinning the public key.
#[cfg(any(feature = "rpm", feature = "deb"))]
fn build_signer(
    config: &config::Config,
    enabled: &std::collections::HashSet<RegistryType>,
) -> Option<Arc<signing::RepoSigner>> {
    if !enabled.contains(&RegistryType::Rpm) && !enabled.contains(&RegistryType::Deb) {
        return None;
    }
    if !config.signing.enabled {
        info!("repository index signing disabled by config");
        return None;
    }
    let path = if !config.signing.key_path.is_empty() {
        std::path::PathBuf::from(&config.signing.key_path)
    } else if config.storage.mode == config::StorageMode::Local {
        std::path::Path::new(&config.storage.path).join(".signing/nora.key")
    } else {
        tracing::warn!(
            "repository index signing disabled: storage is not local and signing.key_path \
             is not set (NORA_SIGNING_KEY_PATH)"
        );
        return None;
    };
    match signing::RepoSigner::load_or_generate(&path) {
        Ok(signer) => {
            info!(
                fingerprint = %signer.fingerprint(),
                path = %path.display(),
                "repository index signing enabled"
            );
            if signer.was_generated() && config.storage.mode != config::StorageMode::Local {
                tracing::warn!(
                    path = %path.display(),
                    "signing key was GENERATED on this boot while artifacts live in an \
                     object store — if this path is per-pod/ephemeral, every replica or \
                     reschedule mints a new identity and clients fail verification. \
                     Provision one key and mount it read-only on every replica."
                );
            }
            Some(Arc::new(signer))
        }
        Err(e) => {
            eprintln!("Fatal: repository index signing key error: {e}");
            // A key file NORA will not sign with is refused on every restart:
            // EXIT_CONFIG, which the units do not restart into (#1025). A key
            // that could not be read may appear on a restart, so that keeps 1.
            let code = match e {
                signing::KeyLoadError::Refused(_) => config::EXIT_CONFIG,
                signing::KeyLoadError::Io(_) => 1,
            };
            std::process::exit(code);
        }
    }
}

#[cfg(not(any(feature = "rpm", feature = "deb")))]
fn build_signer(
    _config: &config::Config,
    _enabled: &std::collections::HashSet<RegistryType>,
) -> Option<Arc<signing::RepoSigner>> {
    None
}

fn run_curation_validate(file: &Path) {
    let content = match std::fs::read_to_string(file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ERROR: Cannot read '{}': {}", file.display(), e);
            std::process::exit(1);
        }
    };

    // Try as blocklist first
    if let Ok(parsed) = serde_json::from_str::<curation::BlocklistFile>(&content) {
        if parsed.version != 1 {
            eprintln!(
                "ERROR: Unsupported blocklist version {} (expected 1)",
                parsed.version
            );
            std::process::exit(1);
        }
        println!("OK: Valid blocklist — {} rules", parsed.rules.len());
        for (i, rule) in parsed.rules.iter().enumerate() {
            println!(
                "  [{}] {}/{}@{} — {}",
                i + 1,
                rule.registry,
                rule.name,
                rule.version,
                rule.reason
            );
        }
        return;
    }

    // Try as allowlist
    if let Ok(parsed) = serde_json::from_str::<curation::AllowlistFile>(&content) {
        if parsed.version != 1 {
            eprintln!(
                "ERROR: Unsupported allowlist version {} (expected 1)",
                parsed.version
            );
            std::process::exit(1);
        }
        let with_integrity = parsed
            .entries
            .iter()
            .filter(|e| e.integrity.is_some())
            .count();
        println!(
            "OK: Valid allowlist — {} entries ({} with integrity)",
            parsed.entries.len(),
            with_integrity
        );
        for (i, entry) in parsed.entries.iter().enumerate() {
            let integrity_flag = if entry.integrity.is_some() {
                " [hash]"
            } else {
                ""
            };
            println!(
                "  [{}] {}/{}@{}{}",
                i + 1,
                entry.registry,
                entry.name,
                entry.version,
                integrity_flag
            );
        }
        return;
    }

    eprintln!(
        "ERROR: '{}' is not a valid blocklist or allowlist JSON",
        file.display()
    );
    eprintln!("  Expected {{ \"version\": 1, \"rules\": [...] }} or {{ \"version\": 1, \"entries\": [...] }}");
    std::process::exit(1);
}

/// The parts of a `registry:name@version` curation-explain spec.
#[derive(Debug, PartialEq)]
enum ExplainSpec {
    Parsed {
        registry: RegistryType,
        name: String,
        version: Option<String>,
    },
    NoColon,
    UnknownRegistry(String),
}

/// Parse a `registry:name@version` spec (the command a refusal's hint names) back
/// into its parts. The version follows the LAST `@`, except: an `@` that starts
/// the name opens an npm scope (`npm:@scope/pkg`), and a `raw` name carries no
/// version — its path may itself contain `@` (`raw:dir/a@b.txt`), so the whole
/// remainder is the name. Pure, so a table test pins every registry's convention
/// and the round-trip of the hint `explain_command` builds (#1099).
fn parse_explain_spec(spec: &str) -> ExplainSpec {
    let Some((registry_str, rest)) = spec.split_once(':') else {
        return ExplainSpec::NoColon;
    };
    let Some(registry) = RegistryType::from_str_opt(registry_str) else {
        return ExplainSpec::UnknownRegistry(registry_str.to_string());
    };
    let (name, version) = if registry == RegistryType::Raw {
        // A raw name is a path and carries no version; it may itself contain '@'.
        (rest.to_string(), None)
    } else {
        match rest.rfind('@') {
            Some(at) if at > 0 => (rest[..at].to_string(), Some(rest[at + 1..].to_string())),
            _ => (rest.to_string(), None),
        }
    };
    ExplainSpec::Parsed {
        registry,
        name,
        version,
    }
}

fn run_curation_explain(config: &Config, package_spec: &str) {
    let (registry, name, version) = match parse_explain_spec(package_spec) {
        ExplainSpec::Parsed {
            registry,
            name,
            version,
        } => (registry, name, version),
        ExplainSpec::NoColon => {
            eprintln!("ERROR: Expected format 'registry:name@version' (e.g., 'cargo:serde@1.0.0')");
            std::process::exit(1);
        }
        ExplainSpec::UnknownRegistry(registry_str) => {
            eprintln!(
                "ERROR: Unknown registry '{}'. Use: {}",
                registry_str,
                RegistryType::all()
                    .iter()
                    .map(|r| r.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            std::process::exit(1);
        }
    };

    // What is configured, for the reader. The decision below comes from the engine the server
    // builds (`build_curation_engine`), so explain answers what the server would decide.
    if let Some(ref path) = config.curation.blocklist_path {
        match curation::BlocklistFilter::from_file(path) {
            Ok(filter) => println!("Blocklist: {} ({} rules)", path, filter.rule_count()),
            Err(e) => println!("Blocklist: {} (ERROR: {})", path, e),
        }
    } else {
        println!("Blocklist: not configured");
    }

    if let Some(ref path) = config.curation.allowlist_path {
        match curation::AllowlistFilter::from_file(path, config.curation.require_integrity) {
            Ok(filter) => println!("Allowlist: {} ({} entries)", path, filter.entry_count()),
            Err(e) => println!("Allowlist: {} (ERROR: {})", path, e),
        }
    } else {
        println!("Allowlist: not configured");
    }

    if config.curation.internal_namespaces.is_empty() {
        println!("Namespaces: not configured");
    } else {
        println!(
            "Namespaces: {} patterns",
            config.curation.internal_namespaces.len()
        );
    }

    let (min_age, problems) = curation::MinReleaseAgeFilter::from_config(&config.curation);
    for problem in &problems {
        println!("Min-release-age: ERROR: {}", problem);
    }
    match &min_age {
        Some(filter) => match filter.global_only() {
            Some((secs, value)) => println!("Min-release-age: {} ({}s)", value, secs),
            None => println!("Min-release-age: {}", filter.summary()),
        },
        None if problems.is_empty() => println!("Min-release-age: not configured"),
        None => {}
    }

    let engine = match build_curation_engine(config) {
        Ok(engine) => engine,
        Err(e) => {
            println!("Mode: {}", config.curation.mode);
            println!("Decision: the server refuses this configuration and does not start: {e}");
            std::process::exit(78);
        }
    };

    println!("Mode: {}", config.curation.mode);
    println!("---");

    let request = curation::FilterRequest {
        registry,
        upstream: None,
        name: name.clone(),
        version: curation::RequestVersion::named(version.as_deref()),
        integrity: None,
        bypass: false,
        publish_date: None,
    };

    let result = engine.evaluate(&request);
    println!(
        "Package: {}:{}@{}",
        registry.as_str(),
        name,
        version.as_deref().unwrap_or("*")
    );
    println!("Decision: {:?}", result.decision);
    println!(
        "Decided by: {}",
        result.decided_by.as_deref().unwrap_or("(default)")
    );
    if result.audited {
        println!("Mode: AUDIT (would block but logs only)");
    }
    // The decision above has no publish date, so the age check never runs here:
    // say whether a young release of this version would be exempt from it.
    if let (Some(filter), Some(version)) = (&min_age, version.as_deref()) {
        match filter.allow_rule(registry, &name, version) {
            Some(rule) => println!(
                "Min-release-age allow: {rule:?} exempts this version from the age check \
                 (quarantine, blocklist and internal namespaces still apply)"
            ),
            None => println!("Min-release-age allow: no entry matches"),
        }
    }
}

#[cfg(test)]
#[path = "main_tests/explain_spec_tests.rs"]
mod explain_spec_tests;

/// Initialize tracing subscriber with stdout + optional file output.
///
/// When `NORA_LOG_FILE` is set, logs are duplicated to the specified file path
/// (non-blocking for the server, written in place for a command). The file layer uses the same format and level
/// filter as stdout. Returns a guard that must be held for the process lifetime
/// to ensure the non-blocking writer flushes on shutdown.
fn init_logging(json_format: bool) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    // Optional file output via NORA_LOG_FILE
    let file_writer = match std::env::var("NORA_LOG_FILE") {
        Ok(path) if !path.is_empty() => open_log_file(&path),
        _ => None,
    };

    // Every layer comes from `log_redact::layer`, the one that writes through the redaction:
    // stdout always, `NORA_LOG_FILE` when set, JSON for the server and text for the commands.
    let file_filter =
        || EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let (file_layer, guard) = match file_writer {
        // The server (JSON) writes the file from a worker thread, flushed when the guard drops.
        Some(file) if json_format => {
            let (non_blocking, guard) = tracing_appender::non_blocking(file);
            (
                Some(log_redact::layer(json_format, non_blocking).with_filter(file_filter())),
                Some(guard),
            )
        }
        // Maestra: a command writes each line as it logs it. Its failures end in
        // `process::exit`, which drops no guard, so a worker thread could lose the last lines.
        Some(file) => (
            Some(
                log_redact::layer(json_format, std::sync::Mutex::new(file))
                    .with_filter(file_filter()),
            ),
            None,
        ),
        None => (None, None),
    };
    tracing_subscriber::registry()
        .with(env_filter)
        .with(log_redact::layer(json_format, std::io::stdout))
        .with(file_layer)
        .init();
    guard
}

/// Open a log file for appending. Creates parent directories as needed.
fn open_log_file(path: &str) -> Option<std::fs::File> {
    let file_path = std::path::Path::new(path);

    // Create parent directories if needed
    if let Some(parent) = file_path.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!(
                    "WARNING: cannot create log directory {}: {e}",
                    parent.display()
                );
                return None;
            }
        }
    }

    let file = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(file_path)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("WARNING: cannot open log file {}: {e}", file_path.display());
            return None;
        }
    };

    eprintln!("Log file: {path}");
    Some(file)
}

/// Auth routes behind the auth and general limiters, registry routes behind the upload limiter,
/// each limiter built for its quota. Returns the quotas the built limiters enforce, read back
/// from them, for the startup log.
fn rate_limited_routes<S: Clone + Send + Sync + 'static>(
    auth_routes: Router<S>,
    registry_routes: Router<S>,
    quotas: &rate_limit::LimiterQuotas,
    trusted_proxies: config::TrustedProxies,
) -> (
    Router<S>,
    rate_limit::LimiterQuotas,
    Vec<rate_limit::RateLimiterState>,
) {
    // All tiers key on the client IP resolved through auth.trusted_proxies, like the
    // auth lockout.
    let (auth_limiter, auth, auth_state) =
        rate_limit::auth_rate_limiter(quotas.auth, trusted_proxies.clone());
    let (upload_limiter, upload, upload_state) =
        rate_limit::upload_rate_limiter(quotas.upload, trusted_proxies.clone());
    let (general_limiter, general, general_state) =
        rate_limit::general_rate_limiter(quotas.general, trusted_proxies);

    // Auth routes: auth_limiter (strict 1rps) + general_limiter
    let auth_routes = auth_routes.layer(auth_limiter).layer(general_limiter);
    // Registry routes: upload_limiter only (200rps/500burst), write methods only.
    // Reads are not limited here: a warm-cache dotnet restore / npm ci of a large
    // project exceeds any per-IP read budget and NuGet reports 429 as a failure.
    let limited_registry = registry_routes.layer(upload_limiter);

    let enforced = rate_limit::LimiterQuotas {
        auth,
        upload,
        general,
    };
    (
        Router::new().merge(auth_routes).merge(limited_registry),
        enforced,
        vec![auth_state, upload_state, general_state],
    )
}

#[cfg(test)]
#[path = "main_tests/rate_limited_routes_tests.rs"]
mod rate_limited_routes_tests;

async fn run_server(mut config: Config, storage: Storage) {
    let start_time = Instant::now();

    // Log rate limiting configuration
    info!(
        enabled = config.rate_limit.enabled,
        auth_rps = config.rate_limit.auth_rps,
        auth_burst = config.rate_limit.auth_burst,
        upload_rps = config.rate_limit.upload_rps,
        upload_burst = config.rate_limit.upload_burst,
        general_rps = config.rate_limit.general_rps,
        general_burst = config.rate_limit.general_burst,
        "Rate limiting configured"
    );

    // Load auth if enabled
    let auth = if config.auth.enabled {
        let path = Path::new(&config.auth.htpasswd_file);
        match HtpasswdAuth::from_file(path) {
            Some(auth) => {
                info!(users = auth.list_users().len(), "Auth enabled");
                Some(auth)
            }
            None if config.auth.oidc.is_active() => {
                // #996 — OIDC-only is the intended setup; a missing htpasswd is
                // not a misconfiguration, so log at info rather than a warning
                // that trains operators to ignore auth warnings. Basic still
                // takes API tokens as the password (#1094).
                info!(
                    oidc_providers = config.auth.oidc.providers.len(),
                    "No htpasswd (OIDC-only): Basic auth accepts API tokens only"
                );
                None
            }
            None => {
                warn!(file = %config.auth.htpasswd_file, "Auth enabled but htpasswd file not found or empty");
                None
            }
        }
    } else {
        warn!("Authentication is DISABLED — all endpoints are publicly accessible. Set [auth] enabled=true for production.");
        None
    };

    // #590: a loopback bind without NORA_PUBLIC_URL makes the registry service index
    // advertise unreachable URLs to clients behind a reverse proxy. Warn (not fatal —
    // local-only use is the default and valid). A public_url that itself points at
    // loopback is caught separately by config validation.
    if config.server.public_url.is_none() && Config::is_loopback_host(&config.server.host) {
        warn!(
            "server.host is loopback ('{}') and NORA_PUBLIC_URL is not set — behind a reverse \
             proxy the service index (/nuget/v3/index.json and others) will advertise \
             unreachable http://{}:{} URLs to remote clients. Set \
             NORA_PUBLIC_URL=https://registry.example.com if proxied; ignore this if NORA is \
             only used locally.",
            config.server.host, config.server.host, config.server.port
        );
    }

    // Initialize token store if auth is enabled. Maestra: tokens live in the
    // storage backend (`.nora-tokens/`); `auth.token_storage` is only the legacy
    // directory whose token files are imported at boot (a missing one is fine).
    let tokens = if config.auth.enabled {
        let store = TokenStore::with_cache_ttl(
            storage.clone(),
            std::time::Duration::from_secs(config.auth.token_cache_ttl),
        );
        store
            .import_legacy_dir(Path::new(&config.auth.token_storage))
            .await;
        Some(store)
    } else {
        None
    };

    let storage_path = config.storage.path.clone();
    let rate_limit_enabled = config.rate_limit.enabled;

    // Warn about plaintext credentials in config.toml
    config.warn_plaintext_credentials();

    let http_client = build_http_client(
        &config.tls,
        None,
        false,
        reqwest::redirect::Policy::default(),
    );
    let http_client_no_redirect = build_no_redirect_client(&config.tls);
    let http_client_same_origin = build_same_origin_client(&config.tls);
    log_outbound_proxy();

    // Initialize Docker auth with shared HTTP client (includes custom CA certs)
    let docker_auth = registry::DockerAuth::new(http_client.clone(), config.docker.proxy_timeout);

    // Discover NuGet search endpoints from upstream service index
    if config.nuget.enabled {
        registry::nuget::discover_search_endpoints(&http_client, &mut config.nuget).await;
    }

    // Build curation engine (shared helper, also used by SIGHUP reload).
    // Fail-closed: in enforce mode an unparsable filter aborts boot rather
    // than starting in a silent allow-all state (#586) — with EXIT_CONFIG, a
    // clean stop the units do not restart into, as for any other configuration
    // NORA cannot start with (#1025).
    let curation_engine = match build_curation_engine(&config) {
        Ok(engine) => engine,
        Err(e) => {
            error!(error = %e, "Cannot start in enforce mode");
            eprintln!("nora: cannot start in enforce mode: {e}");
            std::process::exit(config::EXIT_CONFIG);
        }
    };
    if curation_engine.is_active() {
        info!(
            mode = %config.curation.mode,
            "Curation layer active"
        );
    }

    // Determine enabled registries from config
    let enabled_registries = config.enabled_registries();

    // Back-propagate the resolved set into the per-registry `enabled` flags so
    // hosted handlers (rpm/deb/raw) that re-check `config.<reg>.enabled` agree
    // with route mounting. Without this, an enable-set from
    // NORA_REGISTRIES_ENABLE / [registries].enable mounts the routes but leaves
    // the flags at their defaults, so rpm/deb 404. (#856)
    config.apply_enabled_registries(&enabled_registries);

    // An open proxy is announced on every start (#1135): written down, it is the operator's
    // decision; left at the default, 1.5.0 refuses to start with it, and the gauge lets an alert
    // see that before the upgrade does.
    let curation_mode_implicit = match config.curation_mode_notice() {
        Some(config::CurationModeNotice::Implicit(proxies)) => {
            let names: Vec<&str> = proxies.iter().map(|rt| rt.as_str()).collect();
            warn!(
                registries = %names.join(", "),
                "curation.mode is not set and proxy registries are enabled: upstream packages are served unchecked. From 1.5.0 NORA will not start without curation.mode; set it (NORA_CURATION_MODE or [curation] mode) to \"off\" to keep this behaviour, or to \"audit\" or \"enforce\""
            );
            true
        }
        Some(config::CurationModeNotice::ExplicitOff(proxies)) => {
            let names: Vec<&str> = proxies.iter().map(|rt| rt.as_str()).collect();
            warn!(
                registries = %names.join(", "),
                "curation.mode=off is set: upstream packages are served unchecked"
            );
            false
        }
        None => false,
    };
    metrics::CONFIG_DEPRECATED
        .with_label_values(&["curation_mode_implicit"])
        .set(i64::from(curation_mode_implicit));

    // Make the enabled set available to the UI sidebar so its nav lists exactly
    // the enabled registries (matching the dashboard body). Set once, immutable.
    ui::components::set_enabled_registries(enabled_registries.clone());

    // Registry routes — only merge enabled registries
    // Maestra: the OIDC session exchange rides the registry tier (the upload limiter on
    // POST), not the 1 rps auth tier: every CI job behind one egress address calls it.
    let registry_routes = registry_routes(&enabled_registries).merge(auth::oidc_session::routes());

    // Routes WITHOUT rate limiting (health, metrics, UI)
    let public_routes = Router::new()
        .merge(health::public_routes(config.server.internal_port))
        .merge(ui::routes())
        .merge(openapi::routes());
    #[cfg(feature = "fault-injection")]
    let public_routes = {
        warn!("fault-injection build: /__fi/ routes make the server panic, not for production");
        public_routes.merge(fault_injection::routes())
    };

    // Keyed limiter state, pruned by the maintenance tick below.
    let mut rate_limiter_states = Vec::new();
    let app_routes = if rate_limit_enabled {
        let (routes, enforced, states) = rate_limited_routes(
            auth::token_routes(),
            registry_routes,
            &rate_limit::limiter_quotas(&config.rate_limit),
            config.auth.trusted_proxies.clone(),
        );
        // What the built limiters enforce, read back from them: any narrowing between the
        // configuration and the limiters shows here, next to "Rate limiting configured".
        info!(
            auth_rps = enforced.auth.per_second(),
            auth_burst = enforced.auth.burst,
            upload_rps = enforced.upload.per_second(),
            upload_burst = enforced.upload.burst,
            general_rps = enforced.general.per_second(),
            general_burst = enforced.general.burst,
            "Rate limits enforced"
        );
        rate_limiter_states = states;
        routes
    } else {
        info!("Rate limiting DISABLED");
        Router::new()
            .merge(auth::token_routes())
            .merge(registry_routes)
    };

    let startup_duration_ms = start_time.elapsed().as_millis() as u64;

    let cb_config = config.circuit_breaker.clone();
    let audit_mode = config.audit.mode.clone();
    let audit_rotation = audit::Rotation::from(&config.audit);

    // Initialize digest quarantine store. Load the durable store (in `storage`) whenever
    // ANY quarantine is effectively active — global OR a per-registry override
    // (e.g. docker-only [curation.docker] quarantine). Gating on the global field
    // alone built an empty() store for per-registry-only configs, so after a
    // restart a still-young cached digest read as `New` and was served early —
    // a fail-open the check-only cache-serve gate cannot catch (#765). The
    // predicate is the same one config validation uses, so they cannot diverge.
    let digest_store = if config.any_quarantine_active() {
        Arc::new(digest_quarantine::DigestStore::load_in_background(
            storage.clone(),
            &storage_path,
        ))
    } else {
        Arc::new(digest_quarantine::DigestStore::empty(storage.clone()))
    };

    let oidc_validator = if config.auth.oidc.enabled {
        Some(auth::OidcValidator::new(
            config.auth.oidc.clone(),
            http_client.clone(),
        ))
    } else {
        None
    };

    let teleport_validator = if config.auth.teleport.enabled {
        match auth::TeleportValidator::new(config.auth.teleport.clone(), http_client.clone()) {
            Ok(v) => Some(Arc::new(v)),
            Err(e) => {
                error!("{}", e);
                std::process::exit(config::EXIT_CONFIG);
            }
        }
    } else {
        None
    };

    let bypass_token = config.curation.bypass_token.clone();
    let reloadable = Arc::new(ArcSwap::from_pointee(ReloadableConfig {
        curation_engine,
        bypass_token,
    }));

    let leak_finders = metrics::LeakFinders::new(config.upstream_hostnames());
    registry::set_max_buffered_body(config.server.proxy_max_buffered());

    let enabled_registries = Arc::new(enabled_registries);
    // Cancellation token for graceful shutdown of background tasks (#306). Created
    // before AppState so on-demand handlers (admin reindex warm-up) can observe it.
    let cancel_token = tokio_util::sync::CancellationToken::new();
    let signer = build_signer(&config, &enabled_registries);

    let (tasks, maintenance) = supervision(&config.server);
    let state = AppState {
        storage,
        spool: Arc::new(registry::SpoolBudget::new(&config)),
        config: Arc::new(config),
        enabled_registries,
        start_time,
        startup_duration_ms,
        auth: auth.map(Arc::new),
        tokens,
        metrics: Arc::new(DashboardMetrics::new()),
        activity: Arc::new(ActivityLog::new(50)),
        audit: Arc::new(AuditLog::with_rotation(
            &storage_path,
            audit_mode,
            audit_rotation,
        )),
        docker_auth: Arc::new(docker_auth),
        docker_date_walks: Default::default(),
        repo_index: Arc::new(RepoIndex::new()),
        http_client,
        http_client_no_redirect,
        http_client_same_origin,
        hf_canonical_ids: Arc::default(),
        upload_sessions: Arc::new(RwLock::new(HashMap::new())),
        publish_locks: Arc::new(parking_lot::Mutex::new(HashMap::new())),
        reloadable,
        auth_failures: Arc::new(auth::AuthFailureTracker::new(5, 900)),
        oidc: oidc_validator.map(Arc::new),
        teleport: teleport_validator,
        circuit_breaker: Arc::new(circuit_breaker::CircuitBreakerRegistry::new(cb_config)),
        proxy_coalesce: proxy_coalesce::InflightMap::new(),
        artifact_flights: proxy_coalesce::InflightMap::new(),
        blob_flights: proxy_coalesce::InflightMap::new(),
        packument_memo: Arc::default(),
        digest_store,
        quarantine_exceptions: Default::default(),
        signer,
        leak_finders,
        cancel_token: cancel_token.clone(),
        nuget_hosted: Default::default(),
        deb_young: Default::default(),
        pull_stats: Arc::new(registry::docker::PullStatsAccumulator::default()),
        tasks,
        maintenance,
    };

    // Initialize circuit breaker gauge to 0 (Closed) for every breaker key (#441)
    let breaker_keys = circuit_breaker::initial_gauge_keys(&state.config);
    let breaker_keys: Vec<&str> = breaker_keys.iter().map(String::as_str).collect();
    state.circuit_breaker.init_gauges(&breaker_keys);

    // Shared lock: nothing that calls storage.delete may run concurrently.
    // The periodic cleanup cycle takes it once per cycle and runs every due
    // pass under it; it also serializes future manual/admin cleanup entry
    // points against that cycle.
    let cleanup_lock = Arc::new(tokio::sync::Mutex::new(()));

    let mut scheduler_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    // #1114: fold accumulated docker pull counts into their .stats.json sidecars
    // every PULL_STATS_FLUSH_INTERVAL and once more on shutdown. Pushed to the
    // scheduler handles so the final flush completes within the shutdown drain,
    // keeping the stats loss to at most one interval only on a hard crash.
    let flush_state = state.clone();
    scheduler_handles.push(state.tasks.spawn("pull_stats", move || {
        registry::docker::pull_stats_flush_loop(
            flush_state.clone(),
            registry::docker::PULL_STATS_FLUSH_INTERVAL,
        )
    }));

    let cleanup_passes = cleanup_passes(&state);

    if !cleanup_passes.is_empty() {
        let passes = Arc::new(cleanup_passes);
        let cancel = cancel_token.clone();
        scheduler_handles.push(state.tasks.spawn("cleanup", move || {
            cleanup::run_cleanup_scheduler(
                Arc::clone(&passes),
                Arc::clone(&cleanup_lock),
                cancel.clone(),
            )
        }));
    }

    let app = Router::new()
        .merge(public_routes)
        .merge(app_routes)
        // Admin control-plane routes — gated admin-only by auth_middleware
        // (auth::is_admin_path); abuse is bounded by the in-handler reindex
        // debounce rather than the optional HTTP rate limiter.
        .merge(admin::routes())
        .layer(DefaultBodyLimit::max(
            state.config.server.body_limit_mb * 1024 * 1024,
        ));
    let app = apply_security_headers(app);
    // Middleware layer order — LOAD-BEARING, do not reorder (#542).
    //
    // In axum, last .layer() = outermost (runs first). Execution order:
    //   reject_null_bytes → metrics → [request_layers: catch_panic → auth
    //   → rewrite_ui_base_path → leak_detection → request_id → curation_refusal (audit)]
    //   → handler
    //
    // reject_null_bytes MUST be outermost to block null-byte path attacks
    // before any processing occurs.
    // metrics MUST be next-outermost so it counts ALL responses including
    // auth rejections (401/403/429) in nora_http_requests_total.
    // The layers inside metrics are built by `request_layers`, which the test
    // router uses too, so the tests run the order the server runs. The order of
    // the two outer ones is held by the shipped server with auth on
    // (tests/edge_double_encoding.rs): a refused path is 400, not 401, and is not
    // counted; a 401 is.
    let app = request_layers(app, &state)
        .layer(middleware::from_fn(metrics::metrics_middleware))
        .layer(middleware::from_fn(
            validation::reject_null_bytes_middleware,
        ))
        .with_state(state.clone());

    clear_dead_instance_files(&state).await;

    // Cargo: the name record of every crate published before records existed (`-` and `_` name one
    // crate), before the first request: until then another spelling of such a crate would reach the
    // upstream, and a publish of it would pass. A panic there must not take the server down.
    if state.enabled_registries.contains(&RegistryType::Cargo) {
        let started = std::time::Instant::now();
        let rebuilt =
            std::panic::AssertUnwindSafe(registry::rebuild_cargo_name_records(&state.storage))
                .catch_unwind()
                .await;
        match rebuilt {
            Ok(()) => tracing::info!(
                elapsed_ms = started.elapsed().as_millis() as u64,
                "cargo name records checked"
            ),
            Err(e) => tracing::error!(panic = ?e, "cargo name-record rebuild panicked"),
        }
    }

    let listener = bind_listener(&state.config.server.host, state.config.server.port)
        .await
        .expect("Failed to bind");
    // Report the address actually bound (reflects any IPv6 -> IPv4 fallback).
    let addr = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| state.config.server.bind_addr());

    info!(
        address = %addr,
        version = env!("CARGO_PKG_VERSION"),
        storage = state.storage.backend_name(),
        auth_enabled = state.auth.is_some(),
        body_limit_mb = state.config.server.body_limit_mb,
        "Nora started"
    );

    // Log enabled registries and their mount points
    let enabled_names: Vec<String> = state
        .enabled_registries
        .iter()
        .map(|r| format!("{} ({})", r.display_name(), r.mount_point()))
        .collect();
    info!(
        registries = ?enabled_names,
        count = state.enabled_registries.len(),
        "Enabled registries"
    );

    info!(
        health = "/health",
        ready = "/ready",
        metrics = "/metrics",
        ui = "/ui/",
        api_docs = "/api-docs",
        "System endpoints"
    );

    spawn_maintenance(&state, MAINTENANCE_PERIOD, rate_limiter_states);

    // Background task: build the repo index (and with it the hosted NuGet index) at
    // startup, then refresh it on a slow cadence. Requests never build it: on R2 a full
    // rebuild of a large registry takes minutes (97 s for NuGet on packages.maestra.io,
    // past the 36 s Teleport proxy timeout).
    let index_state = state.clone();
    state.tasks.spawn("repo_index", move || {
        let index_state = index_state.clone();
        async move {
            let mut interval = tokio::time::interval(repo_index::REFRESH_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                index_state.repo_index.refresh(&index_state).await;
            }
        }
    });

    // Maestra: break-glass quarantine exceptions, re-read from their own file (a ConfigMap
    // mounted as a directory), so a change needs neither a restart nor a SIGHUP.
    if let Some(path) = state.config.docker.quarantine_exceptions.clone() {
        state.quarantine_exceptions.reload(&path);
        let exceptions = state.quarantine_exceptions.clone();
        state.tasks.spawn("quarantine_exceptions", move || {
            let (exceptions, path) = (exceptions.clone(), path.clone());
            async move {
                let mut tick = tokio::time::interval(quarantine_exceptions::RELOAD_EVERY);
                tick.tick().await;
                loop {
                    tick.tick().await;
                    exceptions.reload(&path);
                }
            }
        });
    }

    // SIGHUP handler: hot-reload curation policy
    #[cfg(unix)]
    {
        let slot = state.reloadable.clone();
        let held = Arc::new(HeldQuarantine::of(&state.config.curation));
        state.tasks.spawn("sighup", move || {
            let (slot, held) = (slot.clone(), held.clone());
            async move {
                let mut sighup = signal::unix::signal(signal::unix::SignalKind::hangup())
                    .expect("Failed to install SIGHUP handler");
                loop {
                    sighup.recv().await;
                    info!("SIGHUP received — reloading curation policy");
                    match reload_curation(&slot, &held, Config::path_from_env()) {
                        Ok(()) => info!("Curation policy reloaded successfully"),
                        Err(e) => {
                            error!(error = %e, "Curation policy reload failed, keeping previous config")
                        }
                    }
                }
            }
        });
    }

    // Maestra: detailed /health and /metrics on an internal port, off the public hostname.
    // Bound here, so a taken port fails the start; served under the supervisor from a
    // clone of that socket, so a restart after a panic serves the same port.
    if let Some(port) = state.config.server.internal_port {
        let internal_listener = bind_listener(&state.config.server.host, port)
            .await
            .and_then(|l| l.into_std())
            .expect("Failed to bind server.internal_port");
        info!(port, "Internal listener: /health, /ready, /metrics");
        let internal = health::internal_routes().with_state(state.clone());
        let limits = ConnLimits::from_config(&state.config.server);
        let stop = cancel_token.clone();
        state.tasks.spawn("internal_listener", move || {
            let (internal, stop) = (internal.clone(), stop.clone());
            let listener = internal_listener
                .try_clone()
                .and_then(tokio::net::TcpListener::from_std);
            async move {
                let listener = listener.expect("clone server.internal_port listener");
                let drain = std::time::Duration::from_secs(1);
                if let Err(e) =
                    serve_with_drain(listener, internal, stop.cancelled_owned(), drain, limits)
                        .await
                {
                    error!(error = %e, "internal listener failed");
                }
            }
        });
    }

    // Graceful shutdown on SIGTERM/SIGINT, draining for at most `shutdown_timeout` (#1016)
    let drain = std::time::Duration::from_secs(state.config.server.shutdown_timeout);
    let limits = ConnLimits::from_config(&state.config.server);
    info!(
        header_read_timeout_secs = state.config.server.header_read_timeout,
        keep_alive_timeout_secs = state.config.server.keep_alive_timeout,
        max_connections = state.config.server.max_connections,
        "Connection limits"
    );
    match serve_with_drain(listener, app, shutdown_signal(), drain, limits)
        .await
        .expect("Server error")
    {
        ServeEnd::Drained => {}
        ServeEnd::DeadlinePassed => warn!(
            shutdown_timeout_secs = state.config.server.shutdown_timeout,
            "Connections still open after the shutdown timeout are closed; finishing shutdown"
        ),
    }

    // Signal background schedulers to stop and wait for them (#306)
    cancel_token.cancel();
    if !scheduler_handles.is_empty() {
        info!("Waiting for background schedulers to finish (10s timeout)...");
        let join_all = futures::future::join_all(scheduler_handles);
        // CANCEL-SAFETY: timeout wraps join_all of scheduler handles. On timeout,
        // the JoinHandles are dropped which cancels the spawned tasks — this is
        // intentional since we're shutting down and don't need their results.
        if tokio::time::timeout(std::time::Duration::from_secs(10), join_all)
            .await
            .is_err()
        {
            warn!("Background schedulers did not finish within 10s, proceeding with shutdown");
        }
    }

    // Drain audit log — AFTER schedulers finish so their final entries are captured (#543)
    state.audit.shutdown().await;

    // Flush token last_used timestamps to disk
    if let Some(ref token_store) = state.tokens {
        token_store.flush_last_used().await;
    }

    info!(
        uptime_seconds = state.start_time.elapsed().as_secs(),
        "Nora shutdown complete"
    );
}

/// The passes of the periodic cleanup cycle. Retention is pushed first: it deletes expired
/// versions, creating the orphans the GC pass then sweeps in the same cycle.
fn cleanup_passes(state: &AppState) -> Vec<cleanup::CleanupPass> {
    let mut cleanup_passes: Vec<cleanup::CleanupPass> = Vec::new();

    if state.config.retention.enabled && !state.config.retention.rules.is_empty() {
        let storage = state.storage.clone();
        let publish_locks = state.publish_locks.clone();
        let signer = state.signer.clone();
        let rules = state.config.retention.rules.clone();
        let dry_run = state.config.retention.dry_run;
        let audit = state.audit.clone();
        let repo_index = state.repo_index.clone();
        cleanup_passes.push(cleanup::CleanupPass {
            name: "retention",
            interval: std::time::Duration::from_secs(state.config.retention.interval),
            run: Box::new(move || {
                let storage = storage.clone();
                let publish_locks = publish_locks.clone();
                let signer = signer.clone();
                let rules = rules.clone();
                let audit = audit.clone();
                let repo_index = repo_index.clone();
                async move {
                    info!(
                        dry_run = dry_run,
                        "Retention scheduler: starting periodic run"
                    );
                    let result = retention_pass(
                        &storage,
                        &publish_locks,
                        &repo_index,
                        signer.as_deref(),
                        &rules,
                        dry_run,
                        &audit,
                    )
                    .await;
                    info!(
                        "Retention scheduler: done in {:.1}s — {} versions, {} keys, {} bytes freed, {} versions with refused deletes",
                        result.duration_secs, result.planned, result.deleted_keys, result.bytes_freed, result.delete_failures
                    );
                }
                .boxed()
            }),
        });
        info!(
            interval_secs = state.config.retention.interval,
            rules = state.config.retention.rules.len(),
            dry_run = state.config.retention.dry_run,
            "Retention scheduler started"
        );
    }

    // Hosted NuGet feed (maestra fork): PR pre-release expiry per `[nuget] hosted_pr_*`
    // plus the orphan blob sweep, on the retention interval and dry-run switch. Its own
    // knobs gate it (`hosted_pr_retention_days = 0` keeps every version), not the rules.
    if state.config.nuget.enabled {
        let state = state.clone();
        let dry_run = state.config.retention.dry_run;
        cleanup_passes.push(cleanup::CleanupPass {
            name: "nuget-hosted-retention",
            interval: std::time::Duration::from_secs(state.config.retention.interval),
            run: Box::new(move || {
                let state = state.clone();
                async move {
                    registry::nuget::hosted::run_retention(&state, dry_run).await;
                }
                .boxed()
            }),
        });
    }

    if state.config.gc.enabled {
        let storage = state.storage.clone();
        let publish_locks = state.publish_locks.clone();
        let dry_run = state.config.gc.dry_run;
        let grace_secs = state.config.gc.grace_secs;
        let npm_is_proxy = !state.config.npm.upstream_urls().is_empty();
        let go_is_proxy = state.config.go.proxy.is_some();
        let proxy_cache_max_bytes = state.config.gc.proxy_cache_max_bytes;
        let docker_cache_max_bytes = state.config.gc.docker_proxy_cache_max_bytes;
        let docker_namespaces = docker_proxy_namespaces(&state.config);
        let reloadable = Arc::clone(&state.reloadable);
        let repo_index = state.repo_index.clone();
        cleanup_passes.push(cleanup::CleanupPass {
            name: "gc",
            interval: std::time::Duration::from_secs(state.config.gc.interval),
            run: Box::new(move || {
                let storage = storage.clone();
                let publish_locks = publish_locks.clone();
                // The current (SIGHUP-reloadable) internal namespaces, for eviction.
                let curation = reloadable.load_full();
                let repo_index = repo_index.clone();
                let docker_namespaces = docker_namespaces.clone();
                async move {
                    info!("GC scheduler: starting periodic run");
                    let result = gc_pass(
                        &storage,
                        &publish_locks,
                        &repo_index,
                        dry_run,
                        grace_secs,
                        npm_is_proxy,
                        go_is_proxy,
                        proxy_cache_max_bytes,
                        (docker_cache_max_bytes, &docker_namespaces),
                        &curation.curation_engine,
                    )
                    .await;
                    info!("{}", gc_done_line(&result, dry_run));
                }
                .boxed()
            }),
        });
        info!(
            interval_secs = state.config.gc.interval,
            dry_run = state.config.gc.dry_run,
            "GC scheduler started"
        );
    }
    cleanup_passes
}

/// What an instance that died (SIGKILL, OOM, power cut) left behind, cleared before the
/// first request.
async fn clear_dead_instance_files(state: &AppState) {
    // Open this instance's staging directory, removing what dead instances (SIGKILL,
    // OOM, power cut) left in theirs.
    state.storage.prepare().await;

    // Clean up stale Docker temp files from previous runs (#530, #580).
    if state.config.docker.enabled {
        registry::docker::cleanup_upload_temp_dir(&state.config.storage.path);
        registry::docker::cleanup_proxy_temp_dir(&state.config.storage.path);
    }
    // Spool files (proxied downloads, NuGet pushes, PyPI uploads) of an instance
    // that died mid-transfer.
    registry::cleanup_spool_dirs(&state.config.server.spool_dir(&state.config.storage.path));
    // ...and streamed raw uploads a crash cut off mid-request.
    if state.config.raw.enabled {
        registry::raw::cleanup_upload_temp_dir(&state.config.storage.path);
    }
    // ...and Hugging Face cache fills a crash cut off mid-file.
    if state.config.hf.enabled {
        registry::hf::cleanup_fill_temp_dir(&state.config.storage.path);
    }
}

/// Cadence of the maintenance loop.
const MAINTENANCE_PERIOD: std::time::Duration = std::time::Duration::from_secs(30);

/// The supervisor of the server's long-lived tasks, and the maintenance loop's heartbeat it
/// reads: stalled after `server.maintenance_stall_secs` without a completed tick.
/// The server and the test router both get them here: the process's one
/// ([`supervise::of_process`]).
pub(crate) fn supervision(
    server: &config::ServerConfig,
) -> (Arc<supervise::Supervisor>, Arc<supervise::Heartbeat>) {
    let stall = std::time::Duration::from_secs(server.maintenance_stall_secs);
    #[cfg(feature = "fault-injection")]
    let stall = fault_injection::maintenance_max_silence().unwrap_or(stall);
    supervise::of_process(stall)
}

/// Background task: flush token last_used + periodic maintenance every `period`.
/// Under the supervisor: a panicking tick restarts the loop, and the heartbeat fails
/// /health when the loop stops starting ticks or every tick panics.
fn spawn_maintenance(
    state: &AppState,
    period: std::time::Duration,
    limiters: Vec<rate_limit::RateLimiterState>,
) {
    let maintenance_state = state.clone();
    // The supervisor's detached work: a run still going after a restart of the loop is not
    // joined by a second.
    let work = Arc::new(MaintenanceWork::new(&state.tasks, limiters));
    state.tasks.spawn("maintenance", move || {
        let state = maintenance_state.clone();
        let work = Arc::clone(&work);
        run_maintenance(period, Arc::clone(&state.maintenance), move |tick_count| {
            let state = state.clone();
            let work = Arc::clone(&work);
            async move { maintenance_tick(&state, tick_count, &work).await }
        })
    });
}

/// The work a maintenance tick starts and does not wait for: each runs apart from the tick,
/// one run at a time, and reports its own panics (`nora_task_panics_total{task}`).
struct MaintenanceWork {
    /// Token `last_used` to disk; its file rewrites must not be cut halfway.
    token_flush: supervise::Detached,
    /// Maestra: expired OIDC session records deleted (auth/oidc_session.rs).
    session_sweep: supervise::Detached,
    /// The store's size and the per-registry gauges: a whole listing, as long as it takes.
    storage_size: supervise::Detached,
    /// Keyed rate-limiter state, pruned of idle clients every tick (Maestra fork).
    limiters: Vec<rate_limit::RateLimiterState>,
    /// The whole-store size is due (Maestra fork): set every STORAGE_SIZE_REFRESH_INTERVAL,
    /// cleared when a count completes, so a count that panicked is retried at the next one.
    size_due: Arc<std::sync::atomic::AtomicBool>,
}

impl MaintenanceWork {
    fn new(tasks: &supervise::Supervisor, limiters: Vec<rate_limit::RateLimiterState>) -> Self {
        Self {
            token_flush: tasks.detached("token_flush"),
            session_sweep: tasks.detached("oidc_session_sweep"),
            storage_size: tasks.detached("storage_size"),
            limiters,
            size_due: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        }
    }
}

/// How long a maintenance tick may run before it is cut, for a loop ticking every `period`
/// whose heartbeat may be silent for `max_silence`: a third of what the window leaves after
/// one period. Between two beats then fit the wait for the next tick, a tick that panics
/// just inside its deadline and the restarted loop's first tick cut at it, with one more
/// deadline to spare for the restart backoff (1 s after a single panic) and scheduling. So a
/// store that never answers, or one panic, keeps `/health` 200. With the default 300 s window
/// that is 90 s; with the smallest, 90 s, it is 20 s. The tick waits on one cheap storage
/// request only, so its deadline does not depend on how much the store holds.
fn tick_deadline(
    period: std::time::Duration,
    max_silence: std::time::Duration,
) -> std::time::Duration {
    max_silence.saturating_sub(period) / 3
}

/// Run `tick` every `period`, numbering the ticks from 1, and record on `heartbeat` each one
/// that completes or is cut at its deadline ([`tick_deadline`]). The first tick fires at once;
/// a tick that runs past its slot delays the next to the following one. A cut tick is logged
/// and counted, and the next starts on schedule: waiting on a store is not a dead loop, and
/// `/ready` reports the store. A panicking tick ends the loop, which its supervisor restarts.
/// The beats stop when ticks keep panicking or one holds its thread so that it cannot be cut,
/// since the work they stand for (readiness refresh, starting the token flush and the size
/// count) is no longer done.
async fn run_maintenance<F, Fut>(
    period: std::time::Duration,
    heartbeat: Arc<supervise::Heartbeat>,
    mut tick: F,
) where
    F: FnMut(u64) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let deadline = tick_deadline(period, heartbeat.max_silence());
    // Exported from the start, at 0, so that `increase` over it sees the first cut tick.
    std::sync::LazyLock::force(&metrics::MAINTENANCE_TIMEOUTS_TOTAL);
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut tick_count: u64 = 0;
    loop {
        interval.tick().await;
        tick_count += 1;
        // CANCEL-SAFETY: a tick cut here is dropped at whatever await it was in, which is
        // the reachability request: dropped unanswered, it publishes the store unreachable
        // (object store), or the next tick does, finding the probe still running (local disk). The token
        // flush and the size count run in tasks of their own (`MaintenanceWork`) that the
        // cut does not stop, session and lock expiry do not await, and the temp-file sweep is
        // a detached blocking task.
        if tokio::time::timeout(deadline, tick(tick_count))
            .await
            .is_err()
        {
            metrics::MAINTENANCE_TIMEOUTS_TOTAL.inc();
            warn!(
                tick = tick_count,
                deadline_ms = deadline.as_millis() as u64,
                "maintenance tick cut at its deadline: storage too slow or not answering"
            );
        }
        heartbeat.beat();
    }
}

/// One tick of the maintenance loop: start the token `last_used` flush, expire upload
/// sessions and failure-tracker entries, and ask the store whether it answers; every second
/// tick start the count of the store's size and gauges, every tenth evict unused publish
/// locks and stale temp files.
async fn maintenance_tick(state: &AppState, tick_count: u64, work: &MaintenanceWork) {
    #[cfg(feature = "fault-injection")]
    fault_injection::maintenance_fault().await;
    if let Some(ref token_store) = state.tokens {
        let token_store = token_store.clone();
        work.token_flush
            .start(async move { token_store.flush_last_used().await });
    }
    registry::docker::cleanup_expired_sessions(&state.upload_sessions);
    state.auth_failures.cleanup();
    for limiter in &work.limiters {
        limiter.retain_recent();
    }

    // Every 60s (odd ticks — the interval's first tick fires immediately, so the storage
    // gauge is counted right after boot): the store's whole size and the per-registry
    // artifact counts and logical bytes from the index (#446). The "total" storage_bytes
    // label is the full physical footprint; per-registry is summed artifact size. Started,
    // not awaited: on a large bucket or directory tree the count takes longer than a tick
    // may run, and readiness does not depend on it. Skipped while the previous count still runs.
    if !tick_count.is_multiple_of(2) {
        // Maestra: the whole-store size is a full listing of the bucket on R2, so it is
        // counted every STORAGE_SIZE_REFRESH_INTERVAL (the first tick included), and again
        // at the next odd tick while a count has not completed; the per-registry gauges come
        // from the repo index and follow every 60 s.
        use std::sync::atomic::Ordering::Relaxed;
        if (tick_count - 1)
            .is_multiple_of(STORAGE_SIZE_REFRESH_INTERVAL.as_secs() / MAINTENANCE_PERIOD.as_secs())
        {
            work.size_due.store(true, Relaxed);
        }
        let size_due = work
            .size_due
            .load(Relaxed)
            .then(|| Arc::clone(&work.size_due));
        let gauge_state = state.clone();
        work.storage_size.start(async move {
            if let Some(due) = size_due {
                gauge_state.storage.refresh_total_size_cache().await;
                metrics::STORAGE_BYTES
                    .with_label_values(&["total"])
                    .set(gauge_state.storage.total_size().await as i64);
                due.store(false, Relaxed);
            }
            refresh_artifact_gauges(&gauge_state).await;
        });
        metrics::UPTIME_SECONDS.set(state.start_time.elapsed().as_secs() as i64);
    }

    // Every tick, the boot tick included so readiness is known before the first probe:
    // one cheap request to the store (#869) — the first page of a listing, or a write probe
    // on the local disk. The tick waits on nothing else.
    state.storage.refresh_reachability().await;
    // Samples nora_storage_reachable without waiting for a /ready probe.
    state.storage.health_check().await;

    // Every 5 minutes (tick_count % 10 == 0): evict unused publish locks
    // + clean up stale proxy and upload temp files (#580)
    if tick_count.is_multiple_of(10) {
        if let Some(oidc) = state.oidc.clone() {
            let storage = state.storage.clone();
            work.session_sweep.start(async move {
                oidc.sweep_sessions(&storage).await;
            });
        }
        let mut locks = state.publish_locks.lock();
        locks.retain(|_, arc| Arc::strong_count(arc) > 1);
        drop(locks);
        state.storage.prune_locks();
        gc::forget_old_confirmations(state.config.gc.grace_secs);
        let storage_path = state.config.storage.path.clone();
        let spool_dir = state.config.server.spool_dir(&storage_path);
        tokio::task::spawn_blocking(move || {
            registry::docker::cleanup_proxy_temp_dir(&storage_path);
            registry::hf::cleanup_fill_temp_dir(&storage_path);
            // Reclaim upload temp files orphaned by a storage-write failure
            // without waiting for a restart. cleanup_expired_sessions only
            // frees temps still tracked by a live (expired) session, so an
            // orphan whose session entry is already gone would otherwise
            // survive on disk until the next boot. Age-guarded by SESSION_TTL,
            // so in-progress uploads are never reaped.
            registry::docker::cleanup_upload_temp_dir(&storage_path);
            registry::raw::cleanup_upload_temp_dir(&storage_path);
            registry::cleanup_spool_dirs(&spool_dir);
        });
    }
}

#[cfg(test)]
#[path = "main_tests/background_task_tests.rs"]
mod background_task_tests;

#[cfg(test)]
#[path = "main_tests/maintenance_loop_tests.rs"]
mod maintenance_loop_tests;

#[cfg(test)]
#[path = "main_tests/server_supervision_tests.rs"]
mod server_supervision_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[path = "main_tests/maintenance_storage_tests.rs"]
mod maintenance_storage_tests;

/// How serving ended after the shutdown signal.
#[derive(Debug, PartialEq, Eq)]
enum ServeEnd {
    /// Every in-flight request finished within the drain window.
    Drained,
    /// The drain window passed with connections still open.
    DeadlinePassed,
}

/// Serve `app` until `shutdown` resolves, then give in-flight requests `drain` to finish.
///
/// Each connection is served under `limits` (header and keep-alive timeouts, see
/// [`server_conn`]); past `max_connections` open ones, no new connection is accepted until
/// one closes. At the signal the listener closes and every connection finishes the request
/// in flight and closes. A client that stops reading a response would hold its connection
/// forever, so connections still open when the window passes are not waited for: they are
/// dropped, and the shutdown steps (schedulers, audit drain, token flush) run.
async fn serve_with_drain<F>(
    listener: tokio::net::TcpListener,
    app: Router,
    shutdown: F,
    drain: std::time::Duration,
    limits: ConnLimits,
) -> std::io::Result<ServeEnd>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let permits = Arc::new(tokio::sync::Semaphore::new(limits.max_connections));
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let mut connections = tokio::task::JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        // CANCEL-SAFETY: `next_connection` only waits for a permit and an accept, both
        // cancel-safe: dropped at the signal it releases the permit it may hold and loses no
        // accepted connection. `shutdown` stays pinned; `join_next` loses no task.
        tokio::select! {
            () = &mut shutdown => break,
            (permit, stream, remote) = next_connection(&listener, &permits) => {
                let (app, stopped) = (app.clone(), stopped.clone());
                connections.spawn(async move {
                    let _permit = permit;
                    server_conn::serve_connection(stream, remote, app, limits, stopped).await;
                });
            }
            Some(ended) = connections.join_next(), if !connections.is_empty() => {
                log_connection_end(ended);
            }
        }
    }
    drop(listener);
    // Receivers are closed only by dropping them, so `send` cannot fail while the
    // connections hold theirs; afterwards nobody needs the signal.
    let _ = stop.send(true);
    // CANCEL-SAFETY: on timeout the wait ends and `connections` is dropped, which drops
    // the connections still open; nothing else is lost.
    let drained = tokio::time::timeout(drain, async {
        while let Some(ended) = connections.join_next().await {
            log_connection_end(ended);
        }
    })
    .await;
    Ok(match drained {
        Ok(()) => ServeEnd::Drained,
        Err(_) => ServeEnd::DeadlinePassed,
    })
}

/// The next client connection, once fewer than `max_connections` are open.
async fn next_connection(
    listener: &tokio::net::TcpListener,
    permits: &Arc<tokio::sync::Semaphore>,
) -> (
    tokio::sync::OwnedSemaphorePermit,
    tokio::net::TcpStream,
    std::net::SocketAddr,
) {
    let permit = Arc::clone(permits)
        .acquire_owned()
        .await
        .expect("the connection semaphore is never closed");
    loop {
        match listener.accept().await {
            Ok((stream, remote)) => return (permit, stream, remote),
            // One client's connection went away before it was accepted.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::ConnectionReset
                ) => {}
            // Out of file descriptors and the like: wait instead of spinning on it.
            Err(e) => {
                error!(error = %e, "accepting a connection failed, retrying in 1 s");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    }
}

/// A connection task that panicked is logged; the server goes on.
fn log_connection_end(ended: Result<(), tokio::task::JoinError>) {
    if let Err(e) = ended {
        if e.is_panic() {
            error!(panic = ?e, "connection task panicked");
        }
    }
}

/// Wait for shutdown signal (SIGTERM or SIGINT)
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    // CANCEL-SAFETY: Both futures (ctrl_c and terminate) are signal listeners
    // with no intermediate state. Dropping either loses nothing — the process
    // is about to shut down regardless.
    tokio::select! {
        _ = ctrl_c => {
            info!("Received SIGINT, starting graceful shutdown...");
        }
        _ = terminate => {
            info!("Received SIGTERM, starting graceful shutdown...");
        }
    }
}

/// The quarantine settings NORA started with, by key. Every format reads the quarantine from
/// the configuration NORA started with, and the start decides whether the store of first-seen
/// digests is loaded, so a SIGHUP does not apply a change to it: the reload holds these — and
/// nothing else of that configuration — to name what it leaves for a restart.
pub(crate) struct HeldQuarantine(Vec<(String, String)>);

impl HeldQuarantine {
    fn of(curation: &config::CurationConfig) -> Self {
        Self(curation.unreloaded_settings())
    }

    /// The keys whose setting in `loaded` is not the one NORA started with: set, changed or
    /// removed, globally or in a registry's own section.
    fn unapplied(&self, loaded: &config::CurationConfig) -> Vec<String> {
        let loaded = loaded.unreloaded_settings();
        self.0
            .iter()
            .filter(|(key, held)| {
                loaded
                    .iter()
                    .find(|(name, _)| name == key)
                    .is_none_or(|(_, value)| value != held)
            })
            .map(|(key, _)| key.clone())
            .collect()
    }
}

/// Reload curation policy from the configuration file at `path` (triggered by SIGHUP).
///
/// Re-reads the file, rebuilds the CurationEngine with new filters, and atomically swaps it,
/// with the bypass token, into `slot`. It is handed the slot and the quarantine NORA started
/// with, not the state: the rest of the start configuration is out of its reach, so the engine
/// it installs is the one the file it read describes. Tests reload through this function, not
/// a copy of it.
/// Storage, auth, port, and other settings are NOT reloaded — only curation, and of it not the
/// digest quarantine: a setting the file changes there is named in a warning, it waits for a
/// restart ([`HeldQuarantine::unapplied`]).
fn reload_curation(
    slot: &ArcSwap<ReloadableConfig>,
    held: &HeldQuarantine,
    path: Option<String>,
) -> Result<(), String> {
    let config = Config::try_load_from(path)?;

    // Fail-closed: `build_curation_engine` returns Err in enforce mode if any
    // filter no longer parses, so a broken allowlist surfaces here and the
    // `?` short-circuits BEFORE the `store` below — the previous (working)
    // engine is kept and never swapped for an allow-all one (#586).
    let engine = build_curation_engine(&config)?;
    let unreloaded = held.unapplied(&config.curation);

    slot.store(Arc::new(ReloadableConfig {
        curation_engine: engine,
        bypass_token: config.curation.bypass_token,
    }));

    if !unreloaded.is_empty() {
        warn!(
            keys = ?unreloaded,
            "Changed curation keys are not applied by a reload; they apply after a restart"
        );
    }
    Ok(())
}

/// Build a CurationEngine from the given config (used at startup and reload).
///
/// Fail-closed in enforce mode: if a configured filter fails to parse, this
/// returns `Err` instead of silently dropping it. Dropping a deny-by-default
/// allowlist would turn the engine into allow-all, so callers must refuse to
/// boot (startup) or refuse to swap (SIGHUP reload) — see #586. The file is
/// parsed exactly once here, so there is no validate-then-rebuild TOCTOU
/// window: the same parse that is checked is the one that is installed.
///
/// In audit/off mode a parse error is logged and the filter dropped (the
/// engine is advisory there), so this never returns `Err`.
fn build_curation_engine(config: &Config) -> Result<curation::CurationEngine, String> {
    let enforce = config.curation.mode == CurationMode::Enforce;
    let mut engine = curation::CurationEngine::new(config.curation.clone());

    // Load blocklist filter if configured
    if let Some(ref path) = config.curation.blocklist_path {
        match curation::BlocklistFilter::from_file(path) {
            Ok(filter) => {
                let count = filter.rule_count();
                engine.add_filter(Box::new(filter));
                info!(path = %path, rules = count, "Blocklist filter loaded");
            }
            Err(e) if enforce => return Err(format!("invalid blocklist {path}: {e}")),
            Err(e) => error!(path = %path, error = %e, "Failed to load blocklist"),
        }
    }

    // Load allowlist filter if configured
    if let Some(ref path) = config.curation.allowlist_path {
        match curation::AllowlistFilter::from_file(path, config.curation.require_integrity) {
            Ok(filter) => {
                let count = filter.entry_count();
                engine.add_filter(Box::new(filter));
                info!(path = %path, entries = count, "Allowlist filter loaded");
            }
            Err(e) if enforce => return Err(format!("invalid allowlist {path}: {e}")),
            Err(e) => error!(path = %path, error = %e, "Failed to load allowlist"),
        }
    }

    // Load namespace isolation filter if configured
    if !config.curation.internal_namespaces.is_empty() {
        let ns_filter = curation::NamespaceFilter::new(config.curation.internal_namespaces.clone());
        let count = ns_filter.pattern_count();
        engine.set_namespace_filter(Box::new(ns_filter));
        info!(patterns = count, "Namespace isolation filter loaded");
    }

    // Load the min-release-age filter if the global value or any per-registry one
    // is set: a per-registry value applies on its own (#1098).
    let (min_age, problems) = curation::MinReleaseAgeFilter::from_config(&config.curation);
    if enforce && !problems.is_empty() {
        return Err(format!("invalid min_release_age: {}", problems.join("; ")));
    }
    for problem in &problems {
        error!(problem = %problem, "Invalid min_release_age");
    }
    if let Some(filter) = min_age {
        match filter.global_only() {
            Some((secs, value)) => {
                info!(min_age = %value, seconds = secs, "Min-release-age filter loaded")
            }
            None => info!(min_age = %filter.summary(), "Min-release-age filter loaded"),
        }
        engine.set_min_release_age(filter);
    }

    Ok(engine)
}

/// The routes of the enabled registries — one assembly for the server and the tests, so a test
/// reaches every route a client does (the NuGet aliases included).
fn registry_routes(enabled: &HashSet<RegistryType>) -> Router<AppState> {
    let mut registry_routes = Router::new();
    for reg in enabled {
        match reg {
            RegistryType::Docker => {
                registry_routes = registry_routes.merge(registry::docker_routes())
            }
            RegistryType::Maven => {
                registry_routes = registry_routes.merge(registry::maven_routes())
            }
            RegistryType::Npm => registry_routes = registry_routes.merge(registry::npm_routes()),
            RegistryType::Cargo => {
                registry_routes = registry_routes.merge(registry::cargo_routes())
            }
            RegistryType::PyPI => registry_routes = registry_routes.merge(registry::pypi_routes()),
            RegistryType::Raw => registry_routes = registry_routes.merge(registry::raw_routes()),
            RegistryType::Go => registry_routes = registry_routes.merge(registry::go_routes()),
            RegistryType::Gems => registry_routes = registry_routes.merge(registry::gems_routes()),
            RegistryType::Terraform => {
                registry_routes = registry_routes.merge(registry::terraform_routes())
            }
            RegistryType::Ansible => {
                registry_routes = registry_routes.merge(registry::ansible_routes())
            }
            RegistryType::Nuget => {
                registry_routes = registry_routes
                    .merge(registry::nuget_routes())
                    .merge(registry::nuget_alias_routes())
            }
            RegistryType::PubDart => {
                registry_routes = registry_routes.merge(registry::pub_dart_routes())
            }
            RegistryType::Conan => {
                registry_routes = registry_routes.merge(registry::conan_routes())
            }
            #[cfg(feature = "rpm")]
            RegistryType::Rpm => registry_routes = registry_routes.merge(registry::rpm_routes()),
            #[cfg(feature = "deb")]
            RegistryType::Deb => registry_routes = registry_routes.merge(registry::deb_routes()),
            // Compiled out: `Config::enabled_registries` never returns it.
            #[cfg(not(all(feature = "rpm", feature = "deb")))]
            #[allow(unreachable_patterns)]
            RegistryType::Rpm | RegistryType::Deb => {}
            RegistryType::Cpan => registry_routes = registry_routes.merge(registry::cpan_routes()),
            RegistryType::Helm => registry_routes = registry_routes.merge(registry::helm_routes()),
            RegistryType::Apk => registry_routes = registry_routes.merge(registry::apk_routes()),
            RegistryType::Github => {
                registry_routes = registry_routes.merge(registry::github_routes())
            }
            RegistryType::Hashicorp => {
                registry_routes = registry_routes.merge(registry::hashicorp_routes())
            }
            RegistryType::HuggingFace => {
                tracing::info!(
                    "Hugging Face proxy enabled: public models only (datasets answer 501), \
                     files over plain HTTP (Xet is never proxied)"
                );
                registry_routes = registry_routes.merge(registry::hf_routes())
            }
        }
    }
    // A registry answer is never a page of NORA's: whatever a client or an upstream stored —
    // HTML, SVG, an XML document with a stylesheet — a browser runs no script from it, on any
    // format and any type the format serves it as. Package clients ignore the header; the
    // UI's own pages are not under these routes.
    registry_routes.layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
        axum::http::header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("sandbox"),
    ))
}

/// Print note about registries that have data but no retention rules configured.
async fn print_retention_coverage(storage: &Storage, rules: &[config::RetentionRule]) {
    let covered: HashSet<&str> = rules.iter().map(|r| r.registry.as_str()).collect();
    if covered.contains("*") {
        return;
    }
    let all_registries = RegistryType::all()
        .iter()
        .map(|r| r.as_str())
        .collect::<Vec<_>>();
    let mut uncovered = Vec::new();
    for name in &all_registries {
        if !covered.contains(name) {
            let count = storage
                .list(&format!("{}/", name))
                .await
                .unwrap_or_default()
                .len();
            if count > 0 {
                uncovered.push(format!("{} ({} files)", name, count));
            }
        }
    }
    if !uncovered.is_empty() {
        println!("\nNote: No retention rules for: {}", uncovered.join(", "));
    }
}

#[cfg(test)]
#[path = "main_tests/log_file_tests.rs"]
mod log_file_tests;

#[cfg(test)]
#[path = "main_tests/proxy_tests.rs"]
mod proxy_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[path = "main_tests/curation_reload_tests.rs"]
mod curation_reload_tests;

/// the production stack is `request_layers` plus exactly metrics and
/// reject_null_bytes outside it (white list), and the test router builds its layers only
/// through `request_layers`. Needles are built at run time so this text does not match.
#[cfg(test)]
#[path = "main_tests/middleware_stack_whitelist.rs"]
mod middleware_stack_whitelist;

#[cfg(test)]
#[path = "main_tests/cleanup_pass_tests.rs"]
mod cleanup_pass_tests;

/// The cargo name records (`-` and `_` name one crate) of a store from an older release are written
/// before the server listens: a request before them would reach the upstream for another spelling of
/// a published crate, and a publish of it would pass. Needles are built at run time so this text
/// does not match.
#[cfg(test)]
#[path = "main_tests/cargo_name_records_before_listening.rs"]
mod cargo_name_records_before_listening;
