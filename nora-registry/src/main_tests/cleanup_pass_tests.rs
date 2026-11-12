// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

//! A scheduled GC or retention pass that takes files out of the store marks the
//! repository indexes stale: the dashboard counts what is there after the pass.
use super::*;

/// `nora gc` never applies the enable-set to `docker.enabled`: Docker enabled only by
/// `[registries].enable` still has its proxy namespaces capped.
#[test]
fn docker_proxy_namespaces_follow_the_resolved_enable_set() {
    let _env = crate::test_env::env_lock();
    let mut config = Config::default();
    config.docker.enabled = false;
    config.docker.upstreams = vec![config::DockerUpstream {
        trust_upstream_dates: false,
        date_token_file: None,
        url: "https://registry-1.docker.io".into(),
        auth: None,
        auth_env: None,
        namespace: Some("docker.io".into()),
        prefix: Some("docker-hub".into()),
        namespaces: Vec::new(),
    }];
    config.registries = Some(config::RegistriesSection {
        enable: Some(config::EnableSpec::from_env_str("npm")),
    });
    assert!(docker_proxy_namespaces(&config).is_empty());
    config.registries = Some(config::RegistriesSection {
        enable: Some(config::EnableSpec::from_env_str("docker,npm")),
    });
    assert_eq!(
        docker_proxy_namespaces(&config),
        vec!["docker.io".to_string()]
    );
}
#[cfg(feature = "rpm")]
use std::time::{Duration, UNIX_EPOCH};

fn locks() -> PublishLocks {
    Arc::new(parking_lot::Mutex::new(HashMap::new()))
}

#[cfg(feature = "rpm")]
fn no_curation() -> curation::CurationEngine {
    curation::CurationEngine::new(config::CurationConfig::default())
}

#[cfg(feature = "rpm")]
/// `n` proxy-cached rpm files of 100 bytes, the first one the oldest.
async fn rpm_cache(data: &Path, n: u32) -> Storage {
    let storage = Storage::new_local(data.to_str().unwrap());
    for i in 0..n {
        let key = format!("rpm/repo/Packages/{i}-1.0.rpm");
        storage.put(&key, &[0u8; 100]).await.unwrap();
        std::fs::File::options()
            .write(true)
            .open(data.join(&key))
            .unwrap()
            .set_modified(UNIX_EPOCH + Duration::from_secs(1_000_000 + u64::from(i) * 1000))
            .unwrap();
    }
    storage
}

/// A context serving `storage`: its index is the one the passes mark stale.
fn context(storage: Storage) -> test_helpers::TestContext {
    test_helpers::create_test_context_with_storage(storage)
}

/// What the index counts for `registry` once every pending rebuild has finished.
async fn counted(state: &AppState, registry: &str) -> usize {
    let rt = RegistryType::from_str_opt(registry).unwrap();
    state.repo_index.rebuild(rt, state).await;
    state
        .repo_index
        .get(registry, state)
        .await
        .iter()
        .map(|r| r.versions)
        .sum()
}

#[cfg(feature = "rpm")]
#[tokio::test]
async fn a_gc_pass_that_evicts_marks_the_index_stale() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = context(rpm_cache(dir.path(), 5).await);
    let (storage, index) = (&ctx.state.storage, &ctx.state.repo_index);
    assert_eq!(counted(&ctx.state, "rpm").await, 5);
    let result = gc_pass(
        storage,
        &locks(),
        index,
        false,
        0,
        false,
        false,
        300,
        (0, &[]),
        &no_curation(),
    )
    .await;
    assert_eq!(result.proxy_cache_eviction.evicted_files, 2);
    assert_eq!(counted(&ctx.state, "rpm").await, 3);
}

#[cfg(feature = "rpm")]
#[tokio::test]
async fn a_dry_gc_pass_leaves_the_store_and_its_counts() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = context(rpm_cache(dir.path(), 5).await);
    let (storage, index) = (&ctx.state.storage, &ctx.state.repo_index);
    assert_eq!(counted(&ctx.state, "rpm").await, 5);
    let result = gc_pass(
        storage,
        &locks(),
        index,
        true,
        0,
        false,
        false,
        300,
        (0, &[]),
        &no_curation(),
    )
    .await;
    assert_eq!(
        result.proxy_cache_eviction.evicted_files, 2,
        "what would go"
    );
    assert!(storage.get("rpm/repo/Packages/0-1.0.rpm").await.is_ok());
    assert_eq!(counted(&ctx.state, "rpm").await, 5);
}

#[tokio::test]
async fn a_retention_pass_that_deletes_marks_the_index_stale() {
    let dir = tempfile::tempdir().unwrap();
    let (storage, rules) = go_versions(dir.path()).await;
    let ctx = context(storage);
    let (storage, index) = (&ctx.state.storage, &ctx.state.repo_index);
    let before = counted(&ctx.state, "go").await;
    assert!(before >= 3, "{before}");
    let audit = AuditLog::new(dir.path().to_str().unwrap(), audit::AuditMode::Off);
    let result = retention_pass(storage, &locks(), index, None, &rules, false, &audit).await;
    assert_eq!(result.planned, 2);
    let after = counted(&ctx.state, "go").await;
    assert_eq!(
        after,
        before / 3,
        "one version of three left: {before} -> {after}"
    );
}

/// Three go module versions and a `keep_last = 1` rule: a pass finds two to delete.
async fn go_versions(data: &Path) -> (Storage, Vec<config::RetentionRule>) {
    let storage = Storage::new_local(data.to_str().unwrap());
    for ver in ["v1.0.0", "v2.0.0", "v3.0.0"] {
        for ext in ["info", "mod", "zip"] {
            let key = format!("go/github.com/user/repo/@v/{ver}.{ext}");
            storage.put(&key, b"x").await.unwrap();
        }
    }
    let rules = vec![config::RetentionRule {
        registry: "go".to_string(),
        name_glob: None,
        keep_last: Some(1),
        older_than_days: None,
        include_tags: Vec::new(),
        exclude_tags: Vec::new(),
    }];
    (storage, rules)
}

/// The actions a retention pass wrote to `audit.jsonl` under `audit_dir`.
async fn audited_actions(
    storage: &Storage,
    rules: &[config::RetentionRule],
    dry_run: bool,
    audit_dir: &Path,
) -> Vec<String> {
    let audit = AuditLog::new(audit_dir.to_str().unwrap(), audit::AuditMode::File);
    let result = retention_pass(
        storage,
        &locks(),
        &RepoIndex::new(),
        None,
        rules,
        dry_run,
        &audit,
    )
    .await;
    assert_eq!(result.planned, 2, "two of three versions are due");
    let path = audit.path().clone();
    audit.shutdown().await;
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|line| {
            let entry: serde_json::Value = serde_json::from_str(line).unwrap();
            format!(
                "{} {}",
                entry["action"].as_str().unwrap(),
                entry["detail"].as_str().unwrap()
            )
        })
        .collect()
}

#[tokio::test]
async fn a_dry_retention_pass_is_not_audited_as_applied() {
    let data = tempfile::tempdir().unwrap();
    let audit_dir = tempfile::tempdir().unwrap();
    let (storage, rules) = go_versions(data.path()).await;
    let actions = audited_actions(&storage, &rules, true, audit_dir.path()).await;
    assert_eq!(actions.len(), 1, "{actions:?}");
    assert!(
        actions[0].starts_with("retention-dry-run would_free_bytes="),
        "{actions:?}"
    );
    assert!(
        !actions[0].contains("bytes_freed") && !actions[0].contains("keys="),
        "{actions:?}"
    );
    assert!(
        storage
            .get("go/github.com/user/repo/@v/v1.0.0.zip")
            .await
            .is_ok(),
        "a dry run deletes nothing"
    );
}

#[tokio::test]
async fn an_applied_retention_pass_is_audited_as_applied() {
    let data = tempfile::tempdir().unwrap();
    let audit_dir = tempfile::tempdir().unwrap();
    let (storage, rules) = go_versions(data.path()).await;
    let actions = audited_actions(&storage, &rules, false, audit_dir.path()).await;
    assert_eq!(actions.len(), 1, "{actions:?}");
    assert!(
        actions[0].starts_with("retention-apply keys=6 bytes_freed="),
        "{actions:?}"
    );
    assert!(storage
        .get("go/github.com/user/repo/@v/v1.0.0.zip")
        .await
        .is_err());
}

#[test]
fn the_gc_done_line_names_the_proxy_cache_evictions_apart_from_the_orphans() {
    let result = gc::GcResult {
        total_candidates: 10,
        orphaned: 3,
        deleted: 2,
        bytes_freed: 700,
        orphan_keys: Vec::new(),
        duration_secs: 0.5,
        uncovered: Vec::new(),
        metadata_phantoms_removed: 1,
        skipped_recent: 1,
        stat_failures: 0,
        docker_mark_failed: false,
        proxy_cache_eviction: gc::ProxyCacheEviction {
            total_bytes: 9_000,
            evicted_files: 5,
            bytes_freed: 4_096,
        },
    };
    let line = gc_done_line(&result, false);
    assert!(
        line.contains("3 orphans (2 deleted, 700 bytes freed)"),
        "{line}"
    );
    assert!(
        line.contains("5 evicted from the proxy cache (4096 bytes freed)"),
        "{line}"
    );
    // A dry pass freed nothing: the line says what an applied pass would.
    let dry = gc_done_line(&result, true);
    assert!(dry.contains("dry run"), "{dry}");
    assert!(dry.contains("700 bytes would be freed"), "{dry}");
    assert!(
        dry.contains("5 would be evicted from the proxy cache (4096 bytes)"),
        "{dry}"
    );
    assert!(
        !dry.contains("deleted") && !dry.contains("bytes freed"),
        "{dry}"
    );
}

#[cfg(feature = "rpm")]
fn artifacts_gauge(rt: RegistryType) -> i64 {
    metrics::ARTIFACTS_TOTAL
        .with_label_values(&[rt.as_str()])
        .get()
}

#[cfg(feature = "rpm")]
fn bytes_gauge(rt: RegistryType) -> i64 {
    metrics::STORAGE_BYTES
        .with_label_values(&[rt.as_str()])
        .get()
}

#[cfg(feature = "rpm")]
/// Maintenance ticks until the rpm gauge reads `expected`: a tick waits for a rebuild
/// a bounded time, so the gauge may follow one tick later. Fails after five seconds.
async fn tick_until(state: &AppState, expected: i64) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        refresh_artifact_gauges(state).await;
        if artifacts_gauge(RegistryType::Rpm) == expected {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "rpm gauge {} never reached {expected}",
            artifacts_gauge(RegistryType::Rpm)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[cfg(feature = "rpm")]
/// The only test that sets the per-registry gauges: they are process-wide.
#[tokio::test]
async fn the_artifact_gauges_follow_the_store_without_a_read_of_the_ui() {
    let (storage, ops) = test_helpers::op_counting_storage();
    // Five proxy-cached rpm repositories of one 100-byte file each, and go data
    // of a registry that is not enabled.
    for i in 0..5 {
        storage
            .put(&format!("rpm/repo{i}/Packages/{i}-1.0.rpm"), &[0u8; 100])
            .await
            .unwrap();
    }
    storage
        .put("go/github.com/user/repo/@v/v1.0.0.zip", b"x")
        .await
        .unwrap();
    let enabled: HashSet<RegistryType> = [RegistryType::Rpm].into_iter().collect();
    // A fresh process: nothing has read the index yet.
    let ctx = test_helpers::create_test_context_with_storage(storage);
    // The enable-set is given here, not resolved from the config: that reads
    // NORA_REGISTRIES_ENABLE, which config tests running beside this one set.
    let mut state = ctx.state.clone();
    state.enabled_registries = Arc::new(enabled);
    let state = &state;
    let (storage, index) = (&state.storage, &state.repo_index);

    ops.reset();
    tick_until(state, 5).await;
    assert_eq!(bytes_gauge(RegistryType::Rpm), 500);
    assert_eq!(
        ops.snapshot(),
        [("list_with_meta", 1)].into_iter().collect(),
        "one listing, of the enabled registry only"
    );

    ops.reset();
    refresh_artifact_gauges(state).await;
    assert_eq!(
        ops.total(),
        0,
        "nothing changed: no storage round-trip, {:?}",
        ops.snapshot()
    );
    assert_eq!(artifacts_gauge(RegistryType::Rpm), 5);

    // A write marks its registry stale, as every handler does.
    storage
        .put("rpm/repo5/Packages/5-1.0.rpm", &[0u8; 100])
        .await
        .unwrap();
    index.invalidate("rpm");
    tick_until(state, 6).await;
    assert_eq!(bytes_gauge(RegistryType::Rpm), 600);

    // A GC pass evicts the proxy cache down to 300 bytes.
    let result = gc_pass(
        storage,
        &locks(),
        index,
        false,
        0,
        false,
        false,
        300,
        (0, &[]),
        &no_curation(),
    )
    .await;
    assert_eq!(result.proxy_cache_eviction.evicted_files, 3);
    tick_until(state, 3).await;
    assert_eq!(bytes_gauge(RegistryType::Rpm), 300);
}
