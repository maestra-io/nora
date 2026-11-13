// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Migration between storage backends
//!
//! Supports migrating artifacts from one storage backend to another
//! (e.g., local filesystem to S3 or vice versa).

use crate::storage::Storage;
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

/// Migration options
#[derive(Default)]
pub struct MigrateOptions {
    /// If true, show what would be migrated without copying
    pub dry_run: bool,
    /// Also delete the destination keys the source does not have (listed, not deleted, in a
    /// dry run). Off by default: a catch-up run then keeps what the source deleted since.
    pub delete_extraneous: bool,
}

/// Migration statistics
#[derive(Debug, Default)]
pub struct MigrateStats {
    /// Total number of keys found
    pub total_keys: usize,
    /// Number of keys successfully migrated
    pub migrated: usize,
    /// Number of keys skipped (the destination holds the same bytes)
    pub skipped: usize,
    /// Number of keys the source no longer had when they were read
    pub gone: usize,
    /// Number of keys that failed to migrate
    pub failed: usize,
    /// Destination keys the source does not have, deleted (or, in a dry run, to delete)
    pub extraneous: usize,
    /// Total bytes transferred
    pub total_bytes: u64,
}

/// Migrate artifacts from source to destination storage
pub async fn migrate(
    from: &Storage,
    to: &Storage,
    options: MigrateOptions,
) -> Result<MigrateStats, String> {
    println!(
        "Migration: {} -> {}",
        from.backend_name(),
        to.backend_name()
    );

    if options.dry_run {
        println!("DRY RUN - no data will be copied");
    }

    // List all keys from source
    println!("Scanning source storage...");
    let listed = from
        .list_with_meta("")
        .await
        .map_err(|e| format!("failed to list source: {e}"))?;
    // When the source wrote each artifact: the destination writes it now, and the quarantine
    // dates a copy it no longer has a record of by that time.
    let written: std::collections::HashMap<String, u64> = listed
        .iter()
        .map(|(key, meta)| (key.clone(), meta.modified))
        .collect();
    let mut writes = crate::digest_quarantine::CarriedWrites::default();
    let mut keys: Vec<String> = listed.into_iter().map(|(key, _)| key).collect();
    // npm cache provenance (#1055) and first-seen times sit under internal prefixes that
    // list() hides; without them the destination refetches every owned-scope object from
    // its owner, and every npm release age starts over. API tokens (Maestra) too.
    for prefix in crate::registry::npm::INTERNAL_PREFIXES
        .iter()
        .chain(&[crate::tokens::STORAGE_PREFIX])
    {
        keys.extend(
            from.list_internal(prefix)
                .await
                .map_err(|e| format!("failed to list source: {e}"))?,
        );
    }

    // Maestra: copying skips keys the destination has, so a token revoked in the
    // source after an earlier run would stay valid there. A token record the source
    // no longer has is deleted from the destination.
    for key in to
        .list_internal(crate::tokens::STORAGE_PREFIX)
        .await
        .map_err(|e| format!("failed to list destination: {e}"))?
    {
        if !crate::tokens::is_record_key(&key) || keys.contains(&key) {
            continue;
        }
        if options.dry_run {
            println!("Would delete revoked token record {key}");
        } else {
            to.delete(&key)
                .await
                .map_err(|e| format!("failed to delete revoked token {key}: {e}"))?;
            println!("Deleted revoked token record {key}");
        }
    }

    if keys.is_empty() {
        println!("No artifacts found in source storage.");
        if options.delete_extraneous {
            // A source that lists nothing is as likely a wrong path or bucket as an empty
            // store: nothing is deleted from the destination on its word.
            println!("Source is empty: --delete-extraneous deletes nothing.");
        }
        return Ok(MigrateStats::default());
    }

    println!("Found {} artifacts to migrate", keys.len());

    let pb = ProgressBar::new(keys.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )
            .expect("Invalid progress bar template")
            .progress_chars("#>-"),
    );

    let mut stats = MigrateStats {
        total_keys: keys.len(),
        ..Default::default()
    };

    for key in &keys {
        // Skipped only when the destination holds the same bytes, by pin: a key that
        // changed in the source since an earlier run (a tag, a packument, an index) is
        // copied again. An absent or unpinned destination object has no pin.
        let dst_pin = to.pin(key).await;
        if dst_pin.is_some() && dst_pin == from.pin(key).await {
            stats.skipped += 1;
            pb.inc(1);
            continue;
        }

        if options.dry_run {
            // Just count what would be migrated
            if let Some(meta) = from.stat(key).await {
                stats.total_bytes += meta.size;
            }
            stats.migrated += 1;
            pb.inc(1);
            continue;
        }

        // Fetch from source
        match from.get(key).await {
            // A source object without a pin: compare the bytes themselves.
            Ok(data)
                if dst_pin
                    .as_deref()
                    .is_some_and(|pin| pin == hex::encode(Sha256::digest(&data))) =>
            {
                stats.skipped += 1;
            }
            // A write time an earlier copy carried: written below, merged with this run's.
            Ok(data) if writes.carried(key, &data) => stats.migrated += 1,
            Ok(data) => {
                // Write to destination
                match to.put(key, &data).await {
                    Ok(()) => {
                        stats.migrated += 1;
                        stats.total_bytes += data.len() as u64;
                        if let Some(at) = written.get(key).and_then(|t| i64::try_from(*t).ok()) {
                            writes.object(&data, at);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to write {}: {}", key, e);
                        stats.failed += 1;
                    }
                }
            }
            // Deleted in the source since the listing (a live source: GC, eviction).
            Err(crate::storage::StorageError::NotFound) => {
                pb.println(format!("Gone from the source since the listing: {key}"));
                stats.gone += 1;
            }
            Err(e) => {
                warn!("Failed to read {}: {}", key, e);
                stats.failed += 1;
            }
        }

        pb.inc(1);
    }

    pb.finish_with_message("Migration complete");
    // Each copied artifact was written now: the quarantine keeps the source's time.
    stats.failed += writes.write(to).await;

    println!();
    println!("Migration summary:");
    println!("  Total artifacts: {}", stats.total_keys);
    println!("  Migrated: {}", stats.migrated);
    println!("  Skipped (same bytes in destination): {}", stats.skipped);
    println!("  Gone from the source meanwhile: {}", stats.gone);
    println!("  Failed: {}", stats.failed);
    println!("  Total bytes: {} KB", stats.total_bytes / 1024);

    // A migration that left objects behind is a failed one: the caller must not cut over.
    if stats.failed > 0 {
        return Err(format!(
            "{} of {} objects could not be read or written; the destination is incomplete, \
             run the migration again",
            stats.failed, stats.total_keys
        ));
    }

    if options.delete_extraneous {
        delete_extraneous(to, &keys, options.dry_run, &mut stats).await?;
    }

    if options.dry_run {
        info!("Dry run complete. Re-run without --dry-run to perform actual migration.");
    }

    Ok(stats)
}

/// Delete from `to` the keys the source listing (`source_keys`) does not hold, over the same
/// key space the copy reads: the visible keys and the npm internal prefixes. Token records are
/// reconciled by `migrate` itself, and the other internal prefixes are not listed, so they stay.
/// Runs only after a copy without failures. A dry run prints each key and deletes nothing.
async fn delete_extraneous(
    to: &Storage,
    source_keys: &[String],
    dry_run: bool,
    stats: &mut MigrateStats,
) -> Result<(), String> {
    let source: std::collections::HashSet<&str> = source_keys.iter().map(String::as_str).collect();
    let mut dest = to
        .list("")
        .await
        .map_err(|e| format!("failed to list destination: {e}"))?;
    for prefix in crate::registry::npm::INTERNAL_PREFIXES {
        dest.extend(
            to.list_internal(prefix)
                .await
                .map_err(|e| format!("failed to list destination: {e}"))?,
        );
    }
    let mut failed = 0usize;
    // The carried write times are the copy's own, written by `migrate` itself.
    for key in dest
        .iter()
        .filter(|k| !source.contains(k.as_str()) && !crate::digest_quarantine::is_written_key(k))
    {
        stats.extraneous += 1;
        if dry_run {
            println!("Would delete extraneous {key}");
            continue;
        }
        match to.delete(key).await {
            Ok(()) | Err(crate::storage::StorageError::NotFound) => {
                println!("Deleted extraneous {key}");
            }
            Err(e) => {
                warn!("Failed to delete extraneous {}: {}", key, e);
                failed += 1;
            }
        }
    }
    println!(
        "  Extraneous in the destination: {}{}",
        stats.extraneous,
        if dry_run { " (dry run, kept)" } else { "" }
    );
    if failed > 0 {
        return Err(format!(
            "{failed} of {} extraneous destination objects could not be deleted; run the \
             migration again",
            stats.extraneous
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_migrate_local_to_local() {
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();

        let src = Storage::new_local(src_dir.path().to_str().unwrap());
        let dst = Storage::new_local(dst_dir.path().to_str().unwrap());

        // Add test data to source
        src.put("test/file1", b"data1").await.unwrap();
        src.put("test/file2", b"data2").await.unwrap();

        let stats = migrate(&src, &dst, MigrateOptions::default())
            .await
            .unwrap();

        assert_eq!(stats.migrated, 2);
        assert_eq!(stats.failed, 0);
        assert_eq!(stats.skipped, 0);

        // Verify destination has the files
        assert!(dst.get("test/file1").await.is_ok());
        assert!(dst.get("test/file2").await.is_ok());
    }

    /// npm cache provenance (#1055) is hidden from list() but migrates with its object.
    #[tokio::test]
    async fn test_migrate_carries_npm_provenance() {
        use crate::registry::npm::origin_key;
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();
        let src = Storage::new_local(src_dir.path().to_str().unwrap());
        let dst = Storage::new_local(dst_dir.path().to_str().unwrap());
        let key = "npm/@vendor/a/metadata.json";
        src.put(key, b"{}").await.unwrap();
        src.put(&origin_key(key), b"npm:https://owner.example\nrecord")
            .await
            .unwrap();

        let stats = migrate(&src, &dst, MigrateOptions::default())
            .await
            .unwrap();

        assert_eq!(stats.migrated, 2);
        assert_eq!(
            &dst.get(&origin_key(key)).await.unwrap()[..],
            b"npm:https://owner.example\nrecord"
        );
        assert_eq!(dst.pin(key).await, src.pin(key).await);
    }

    /// npm first-seen times are hidden from list() too, and migrate with the packument.
    #[tokio::test]
    async fn test_migrate_carries_npm_first_seen() {
        use crate::registry::npm::first_seen_key;
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();
        let src = Storage::new_local(src_dir.path().to_str().unwrap());
        let dst = Storage::new_local(dst_dir.path().to_str().unwrap());
        let key = "npm/a/metadata.json";
        src.put(key, b"{}").await.unwrap();
        src.put(&first_seen_key(key), br#"{"1.0.0":1700000000}"#)
            .await
            .unwrap();

        let stats = migrate(&src, &dst, MigrateOptions::default())
            .await
            .unwrap();

        assert_eq!(stats.migrated, 2);
        assert_eq!(
            &dst.get(&first_seen_key(key)).await.unwrap()[..],
            br#"{"1.0.0":1700000000}"#
        );
    }

    /// API tokens (Maestra) are internal keys too: a migrated token verifies.
    #[tokio::test]
    async fn test_migrate_carries_tokens() {
        use crate::tokens::{Role, TokenStore};
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();
        let src = Storage::new_local(src_dir.path().to_str().unwrap());
        let dst = Storage::new_local(dst_dir.path().to_str().unwrap());
        let raw = TokenStore::new(src.clone())
            .create_token("ci", 30, None, Role::Read)
            .await
            .unwrap();

        let stats = migrate(&src, &dst, MigrateOptions::default())
            .await
            .unwrap();

        assert_eq!(stats.migrated, 1);
        let (user, _) = TokenStore::new(dst).verify_token(&raw).await.unwrap();
        assert_eq!(user, "ci");
    }

    /// A token revoked in the source after an earlier migration does not stay
    /// valid in the destination on the next run; the destination's other token
    /// state objects are left alone.
    #[tokio::test]
    async fn test_migrate_drops_tokens_revoked_since_last_run() {
        use crate::tokens::{Role, TokenStore};
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();
        let src = Storage::new_local(src_dir.path().to_str().unwrap());
        let dst = Storage::new_local(dst_dir.path().to_str().unwrap());
        let source = TokenStore::new(src.clone());
        let kept = source
            .create_token("a", 30, None, Role::Read)
            .await
            .unwrap();
        let revoked = source
            .create_token("b", 30, None, Role::Read)
            .await
            .unwrap();
        migrate(&src, &dst, MigrateOptions::default())
            .await
            .unwrap();
        let state = ".nora-tokens/legacy_imported.json";
        dst.put(state, b"[]").await.unwrap();

        let id = source.list_tokens("b").await[0].file_id.clone();
        source.revoke_token(&id).await.unwrap();
        let dry = MigrateOptions {
            dry_run: true,
            ..Default::default()
        };
        migrate(&src, &dst, dry).await.unwrap();
        assert!(TokenStore::new(dst.clone())
            .verify_token(&revoked)
            .await
            .is_ok());
        migrate(&src, &dst, MigrateOptions::default())
            .await
            .unwrap();

        let target = TokenStore::new(dst.clone());
        assert!(target.verify_token(&kept).await.is_ok());
        assert!(target.verify_token(&revoked).await.is_err());
        assert!(dst.stat(state).await.is_some());
    }

    /// A copy the ledger forgot (cached more than 90 days ago) is dated by when the store
    /// wrote it, and a migration writes it now: the source's time goes with it, over a
    /// second migration too, and `--delete-extraneous` keeps it. Without it the copy would be
    /// held for a new TTL in the destination.
    #[tokio::test]
    async fn test_migrate_carries_write_times() {
        use crate::digest_quarantine::{cache_gate_dated, DigestStore, QuarantineMode};
        let held = |storage: Storage| async move {
            let key = "nuget/old/old.1.0.0.nupkg";
            let store = DigestStore::load(storage.clone(), "/nonexistent").await;
            let data = storage.get(key).await.unwrap();
            let mode = QuarantineMode::Enforce;
            cache_gate_dated(
                &store,
                &storage,
                key,
                "nuget",
                &data,
                &mode,
                14 * 86400,
                None,
            )
            .await
            .is_some()
        };
        let dirs: Vec<TempDir> = (0..3).map(|_| TempDir::new().unwrap()).collect();
        let stores: Vec<Storage> = dirs
            .iter()
            .map(|d| Storage::new_local(d.path().to_str().unwrap()))
            .collect();
        stores[0]
            .put("nuget/old/old.1.0.0.nupkg", b"package")
            .await
            .unwrap();
        let then = std::time::SystemTime::now() - std::time::Duration::from_secs(100 * 86400);
        std::fs::File::options()
            .write(true)
            .open(dirs[0].path().join("nuget/old/old.1.0.0.nupkg"))
            .unwrap()
            .set_modified(then)
            .unwrap();
        assert!(!held(stores[0].clone()).await);

        let options = || MigrateOptions {
            delete_extraneous: true,
            ..Default::default()
        };
        migrate(&stores[0], &stores[1], options()).await.unwrap();
        assert!(!held(stores[1].clone()).await, "not held after a migration");
        migrate(&stores[1], &stores[2], options()).await.unwrap();
        assert!(!held(stores[2].clone()).await, "nor after a second one");
    }

    /// R4-C10: a key the destination already has is skipped only when it holds the same
    /// bytes. One that changed in the source since an earlier run is copied again, so a
    /// catch-up run does not leave the destination on the first run's tags and packuments.
    #[tokio::test]
    async fn test_migrate_skips_existing() {
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();

        let src = Storage::new_local(src_dir.path().to_str().unwrap());
        let dst = Storage::new_local(dst_dir.path().to_str().unwrap());

        src.put("test/same", b"bytes").await.unwrap();
        src.put("docker/app/manifests/latest.json", b"monday")
            .await
            .unwrap();
        // A source object without a pin is compared by its bytes.
        let unpinned = src_dir.path().join("upload");
        std::fs::write(&unpinned, b"blob").unwrap();
        src.put_from_path("test/unpinned", &unpinned, None)
            .await
            .unwrap();
        let stats = migrate(&src, &dst, MigrateOptions::default())
            .await
            .unwrap();
        assert_eq!((stats.migrated, stats.skipped), (3, 0));

        src.put("docker/app/manifests/latest.json", b"friday")
            .await
            .unwrap();
        let dry = migrate(
            &src,
            &dst,
            MigrateOptions {
                dry_run: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(dry.migrated, 2, "a dry run reads no bytes to compare");
        let stats = migrate(&src, &dst, MigrateOptions::default())
            .await
            .unwrap();

        assert_eq!((stats.migrated, stats.skipped), (1, 2));
        let data = dst.get("docker/app/manifests/latest.json").await.unwrap();
        assert_eq!(&*data, b"friday");
    }

    /// R4-C11: a migration that could not read an object fails, and says how many.
    #[tokio::test]
    async fn test_migrate_fails_when_an_object_cannot_be_read() {
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();
        let src = Storage::new_local(src_dir.path().to_str().unwrap());
        let dst = Storage::new_local(dst_dir.path().to_str().unwrap());
        src.put("test/good", b"good").await.unwrap();
        src.put("test/tampered", b"body").await.unwrap();
        // The bytes no longer match the pin: the read is refused.
        std::fs::write(src_dir.path().join("test/tampered"), b"else").unwrap();

        let err = migrate(&src, &dst, MigrateOptions::default())
            .await
            .unwrap_err();

        assert!(err.contains("1 of 2 objects"), "{err}");
        assert!(dst.get("test/good").await.is_ok(), "the rest is copied");
    }

    /// `--delete-extraneous`: a key the source no longer has goes from the destination (npm
    /// internal records too), a dry run only counts it, and the default keeps it. Token state
    /// objects and an empty source delete nothing.
    #[tokio::test]
    async fn test_migrate_delete_extraneous() {
        use crate::registry::npm::first_seen_key;
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();
        let src = Storage::new_local(src_dir.path().to_str().unwrap());
        let dst = Storage::new_local(dst_dir.path().to_str().unwrap());
        src.put("test/kept", b"kept").await.unwrap();
        let gone = ["test/gone", &first_seen_key("npm/gone/metadata.json")];
        for key in gone {
            dst.put(key, b"deleted in the source").await.unwrap();
        }
        let state = ".nora-tokens/legacy_imported.json";
        dst.put(state, b"[]").await.unwrap();
        let run = |dry_run, delete_extraneous| {
            migrate(
                &src,
                &dst,
                MigrateOptions {
                    dry_run,
                    delete_extraneous,
                },
            )
        };

        let default = run(false, false).await.unwrap();
        assert_eq!(default.extraneous, 0);
        let dry = run(true, true).await.unwrap();
        assert_eq!(dry.extraneous, 2);
        for key in gone {
            assert!(
                dst.stat(key).await.is_some(),
                "{key}: the default and a dry run keep it"
            );
        }

        let stats = run(false, true).await.unwrap();
        assert_eq!(stats.extraneous, 2);
        for key in gone {
            assert!(dst.stat(key).await.is_none(), "{key}");
        }
        assert!(dst.get("test/kept").await.is_ok());
        assert!(dst.stat(state).await.is_some());

        let empty_dir = TempDir::new().unwrap();
        let empty = Storage::new_local(empty_dir.path().to_str().unwrap());
        let options = MigrateOptions {
            dry_run: false,
            delete_extraneous: true,
        };
        migrate(&empty, &dst, options).await.unwrap();
        assert!(
            dst.get("test/kept").await.is_ok(),
            "an empty source deletes nothing"
        );
    }

    /// `--delete-extraneous` after a copy that failed deletes nothing: the run is an error.
    #[tokio::test]
    async fn test_migrate_delete_extraneous_not_after_a_failed_copy() {
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();
        let src = Storage::new_local(src_dir.path().to_str().unwrap());
        let dst = Storage::new_local(dst_dir.path().to_str().unwrap());
        src.put("test/tampered", b"body").await.unwrap();
        std::fs::write(src_dir.path().join("test/tampered"), b"else").unwrap();
        dst.put("test/gone", b"x").await.unwrap();
        let options = MigrateOptions {
            dry_run: false,
            delete_extraneous: true,
        };

        assert!(migrate(&src, &dst, options).await.is_err());
        assert!(dst.stat("test/gone").await.is_some());
    }

    #[tokio::test]
    async fn test_migrate_dry_run() {
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();

        let src = Storage::new_local(src_dir.path().to_str().unwrap());
        let dst = Storage::new_local(dst_dir.path().to_str().unwrap());

        src.put("test/file", b"data").await.unwrap();

        let stats = migrate(
            &src,
            &dst,
            MigrateOptions {
                dry_run: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(stats.migrated, 1);

        // Destination should be empty (dry run)
        assert!(dst.get("test/file").await.is_err());
    }

    #[tokio::test]
    async fn test_migrate_empty_source() {
        let src_dir = TempDir::new().unwrap();
        let dst_dir = TempDir::new().unwrap();

        let src = Storage::new_local(src_dir.path().to_str().unwrap());
        let dst = Storage::new_local(dst_dir.path().to_str().unwrap());

        let stats = migrate(&src, &dst, MigrateOptions::default())
            .await
            .unwrap();

        assert_eq!(stats.total_keys, 0);
        assert_eq!(stats.migrated, 0);
    }
}
