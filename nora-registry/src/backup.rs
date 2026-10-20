// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Backup and restore functionality for Nora
//!
//! Exports all artifacts to a tar.gz file and restores from backups.
//!
//! API token records (Argon2 hashes, `.nora-tokens/`) and the digest quarantine
//! ledger (`.nora-quarantine/`) are internal storage keys and ride along with the
//! artifacts. An archive from before they moved to storage carries them under
//! [`LOCAL_PREFIX`] (`tokens/<16hex>.json`, `quarantine.jsonl`), which a restore
//! writes into storage. The repository signing key is deliberately left out
//! (`test_backup_omits_signing_key`): keep it in a secret store.

use crate::digest_quarantine::{self, LEDGER_FILE};
use crate::storage::Storage;
use crate::tokens;
use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use tar::{Archive, Builder, Header};

/// Backup metadata stored in metadata.json
#[derive(Debug, Serialize, Deserialize)]
pub struct BackupMetadata {
    pub version: String,
    pub created_at: DateTime<Utc>,
    pub artifact_count: usize,
    pub total_bytes: u64,
    pub storage_backend: String,
}

/// Archive prefix of node-local state in archives from before it moved to storage.
/// `.nora-` keys are internal, so no artifact key can collide with it.
const LOCAL_PREFIX: &str = ".nora-local/";
const LOCAL_TOKENS: &str = "tokens/";

/// Statistics returned after backup
#[derive(Debug)]
pub struct BackupStats {
    pub artifact_count: usize,
    pub total_bytes: u64,
    pub output_size: u64,
}

/// Statistics returned after restore
#[derive(Debug)]
pub struct RestoreStats {
    pub artifact_count: usize,
    pub total_bytes: u64,
    pub local_files: usize,
}

/// Create a backup of all artifacts to a tar.gz file
pub async fn create_backup(storage: &Storage, output: &Path) -> Result<BackupStats, String> {
    println!("Creating backup to: {}", output.display());
    println!("Storage backend: {}", storage.backend_name());

    // List all keys
    println!("Scanning storage...");
    let mut keys = storage
        .list("")
        .await
        .map_err(|e| format!("storage list failed: {}", e))?;
    // npm cache provenance (#1055) and first-seen times sit under internal prefixes that
    // list() hides. Without them a restored owned scope is not trusted — refetched from
    // its owner, and served by no one while that owner is down — and every npm release
    // age starts over. API tokens (Maestra) are internal keys too.
    for prefix in crate::registry::npm::INTERNAL_PREFIXES
        .iter()
        .chain(&[tokens::STORAGE_PREFIX])
    {
        keys.extend(
            storage
                .list_internal(prefix)
                .await
                .map_err(|e| format!("storage list failed: {}", e))?,
        );
    }
    // With local storage the legacy ledger file sits at the storage root; its entries
    // are in storage since the first start that imported it.
    keys.retain(|k| k != LEDGER_FILE);

    if keys.is_empty() {
        println!("No artifacts found in storage. Creating empty backup.");
    } else {
        println!("Found {} artifacts", keys.len());
    }

    // Write to a sibling temp file, then fsync + atomically rename, so a crash
    // mid-write leaves the previous backup (or nothing) intact — never a truncated
    // archive at the real path. `output_size > 0` is the only success signal and is
    // true for a truncated file too, so a partial archive at `output` reads as valid.
    let tmp_output = {
        let mut p = output.as_os_str().to_owned();
        p.push(".tmp");
        PathBuf::from(p)
    };
    // 0600: the archive carries token hashes.
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp_output)
        .map_err(|e| format!("Failed to create output file: {}", e))?;
    let encoder = GzEncoder::new(file, Compression::default());
    let mut archive = Builder::new(encoder);

    // Progress bar
    let pb = ProgressBar::new(keys.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )
            .expect("Invalid progress template")
            .progress_chars("#>-"),
    );

    let mut total_bytes: u64 = 0;
    let mut artifact_count = 0;

    for key in &keys {
        // Get file data
        let data = match storage.get(key).await {
            Ok(data) => data,
            Err(e) => {
                pb.println(format!("Warning: Failed to read {}: {}", key, e));
                continue;
            }
        };

        // Create tar header
        let mut header = Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
        header.set_cksum();

        // Add to archive
        archive
            .append_data(&mut header, key, &*data)
            .map_err(|e| format!("Failed to add {} to archive: {}", key, e))?;

        total_bytes += data.len() as u64;
        artifact_count += 1;
        pb.inc(1);
    }

    // Add metadata.json
    let metadata = BackupMetadata {
        version: env!("CARGO_PKG_VERSION").to_string(),
        created_at: Utc::now(),
        artifact_count,
        total_bytes,
        storage_backend: storage.backend_name().to_string(),
    };

    let metadata_json = serde_json::to_vec_pretty(&metadata)
        .map_err(|e| format!("Failed to serialize metadata: {}", e))?;

    let mut header = Header::new_gnu();
    header.set_size(metadata_json.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    );
    header.set_cksum();

    archive
        .append_data(&mut header, "metadata.json", metadata_json.as_slice())
        .map_err(|e| format!("Failed to add metadata.json: {}", e))?;

    // Finish archive
    let encoder = archive
        .into_inner()
        .map_err(|e| format!("Failed to finish archive: {}", e))?;
    let file = encoder
        .finish()
        .map_err(|e| format!("Failed to finish compression: {}", e))?;
    // Durability + atomic publish: fsync the archive bytes, rename into place, then
    // fsync the parent directory so the rename itself survives power-loss.
    file.sync_all()
        .map_err(|e| format!("Failed to fsync backup archive: {}", e))?;
    drop(file);
    std::fs::rename(&tmp_output, output)
        .map_err(|e| format!("Failed to publish backup archive: {}", e))?;
    {
        let dir = output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
    }

    pb.finish_with_message("Backup complete");

    // Get output file size
    let output_size = std::fs::metadata(output).map(|m| m.len()).unwrap_or(0);

    let stats = BackupStats {
        artifact_count,
        total_bytes,
        output_size,
    };

    println!();
    println!("Backup complete:");
    println!("  Artifacts: {}", stats.artifact_count);
    println!("  Total data: {} bytes", stats.total_bytes);
    println!("  Backup file: {} bytes", stats.output_size);
    println!(
        "  Compression ratio: {:.1}%",
        if stats.total_bytes > 0 {
            (stats.output_size as f64 / stats.total_bytes as f64) * 100.0
        } else {
            100.0
        }
    );

    Ok(stats)
}

/// Restore artifacts from a backup file
pub async fn restore_backup(storage: &Storage, input: &Path) -> Result<RestoreStats, String> {
    println!("Restoring from: {}", input.display());
    println!("Storage backend: {}", storage.backend_name());

    // Open backup file
    let file = File::open(input).map_err(|e| format!("Failed to open backup file: {}", e))?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);

    // First pass: count entries and read metadata
    let file = File::open(input).map_err(|e| format!("Failed to open backup file: {}", e))?;
    let decoder = GzDecoder::new(file);
    let mut archive_count = Archive::new(decoder);

    let mut entry_count = 0;
    let mut metadata: Option<BackupMetadata> = None;

    for entry in archive_count
        .entries()
        .map_err(|e| format!("Failed to read archive: {}", e))?
    {
        let mut entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
        let path = entry
            .path()
            .map_err(|e| format!("Failed to read path: {}", e))?
            .to_string_lossy()
            .to_string();

        if path == "metadata.json" {
            let mut data = Vec::new();
            entry
                .read_to_end(&mut data)
                .map_err(|e| format!("Failed to read metadata: {}", e))?;
            metadata = serde_json::from_slice(&data).ok();
        } else {
            entry_count += 1;
        }
    }

    if let Some(ref meta) = metadata {
        println!("Backup info:");
        println!("  Version: {}", meta.version);
        println!("  Created: {}", meta.created_at);
        println!("  Artifacts: {}", meta.artifact_count);
        println!("  Original size: {} bytes", meta.total_bytes);
        println!();
    }

    // Progress bar
    let pb = ProgressBar::new(entry_count as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )
            .expect("Invalid progress template")
            .progress_chars("#>-"),
    );

    let mut total_bytes: u64 = 0;
    let mut artifact_count = 0;
    let mut local_files = 0;
    let mut quarantine_restored = false;

    // Second pass: restore files
    for entry in archive
        .entries()
        .map_err(|e| format!("Failed to read archive: {}", e))?
    {
        let mut entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
        let path = entry
            .path()
            .map_err(|e| format!("Failed to read path: {}", e))?
            .to_string_lossy()
            .to_string();

        // Skip metadata file
        if path == "metadata.json" {
            continue;
        }

        // Read data
        let mut data = Vec::new();
        entry
            .read_to_end(&mut data)
            .map_err(|e| format!("Failed to read {}: {}", path, e))?;

        if path.strip_prefix(LOCAL_PREFIX) == Some(LEDGER_FILE) {
            // An archive from before the ledger moved to storage. The backup's
            // first-seen wins over a later re-recording.
            let (_, _, failed) =
                digest_quarantine::import_jsonl(storage, &data, &Default::default(), true).await;
            if failed > 0 {
                return Err(format!("Failed to restore {failed} quarantine entries"));
            }
            quarantine_restored = true;
            local_files += 1;
            pb.inc(1);
            continue;
        }
        if let Some(name) = path.strip_prefix(LOCAL_PREFIX) {
            // Older archives: a token record goes into storage; anything else is refused.
            match name.strip_prefix(LOCAL_TOKENS) {
                Some(record) => tokens::import_record(storage, record, &data).await?,
                None => return Err(format!("Unknown local-state entry {path}")),
            }
            local_files += 1;
            pb.inc(1);
            continue;
        }
        quarantine_restored |= path.starts_with(digest_quarantine::ENTRY_PREFIX);

        // Put to storage
        storage
            .put(&path, &data)
            .await
            .map_err(|e| format!("Failed to store {}: {}", path, e))?;

        total_bytes += data.len() as u64;
        artifact_count += 1;
        pb.inc(1);
    }

    // The snapshot would shadow the entries just overwritten: the next start reads
    // every entry once and writes a new one.
    if quarantine_restored {
        match storage.delete(digest_quarantine::SNAPSHOT_KEY).await {
            Ok(()) | Err(crate::storage::StorageError::NotFound) => {}
            Err(e) => return Err(format!("Failed to drop the quarantine snapshot: {e}")),
        }
    }

    pb.finish_with_message("Restore complete");

    let stats = RestoreStats {
        artifact_count,
        total_bytes,
        local_files,
    };

    println!();
    println!("Restore complete:");
    println!("  Artifacts: {}", stats.artifact_count);
    println!(
        "  Local state: {} (older archive: tokens, quarantine ledger)",
        stats.local_files
    );
    println!("  Total data: {} bytes", stats.total_bytes);

    Ok(stats)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_backup_metadata_serialization() {
        let meta = BackupMetadata {
            version: "0.3.0".to_string(),
            created_at: chrono::Utc::now(),
            artifact_count: 42,
            total_bytes: 1024000,
            storage_backend: "local".to_string(),
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains("\"version\":\"0.3.0\""));
        assert!(json.contains("\"artifact_count\":42"));
        assert!(json.contains("\"storage_backend\":\"local\""));
    }

    #[test]
    fn test_backup_metadata_deserialization() {
        let json = r#"{
            "version": "0.3.0",
            "created_at": "2026-01-01T00:00:00Z",
            "artifact_count": 10,
            "total_bytes": 5000,
            "storage_backend": "s3"
        }"#;
        let meta: BackupMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.version, "0.3.0");
        assert_eq!(meta.artifact_count, 10);
        assert_eq!(meta.total_bytes, 5000);
        assert_eq!(meta.storage_backend, "s3");
    }

    #[test]
    fn test_backup_metadata_roundtrip() {
        let meta = BackupMetadata {
            version: "1.0.0".to_string(),
            created_at: chrono::Utc::now(),
            artifact_count: 100,
            total_bytes: 999999,
            storage_backend: "local".to_string(),
        };
        let json = serde_json::to_value(&meta).unwrap();
        let restored: BackupMetadata = serde_json::from_value(json).unwrap();
        assert_eq!(meta.version, restored.version);
        assert_eq!(meta.artifact_count, restored.artifact_count);
        assert_eq!(meta.total_bytes, restored.total_bytes);
    }

    #[tokio::test]
    async fn test_create_backup_empty_storage() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());
        let output = dir.path().join("backup.tar.gz");

        let stats = create_backup(&storage, &output).await.unwrap();
        assert_eq!(stats.artifact_count, 0);
        assert_eq!(stats.total_bytes, 0);
        assert!(output.exists());
        assert!(stats.output_size > 0); // at least metadata.json
    }

    /// A backup archive is outside input: an entry naming the local staging
    /// directory must not be restored into it, where the next start would delete it
    /// as a dead instance's write. The key is refused up front, by validation.
    #[tokio::test]
    async fn restore_refuses_an_entry_in_the_staging_directory() {
        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("crafted.tar.gz");
        {
            let gz = GzEncoder::new(File::create(&archive_path).unwrap(), Compression::default());
            let mut tar = tar::Builder::new(gz);
            let body = b"planted";
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, ".nora-staging/0b1c/17.tmp", &body[..])
                .unwrap();
            tar.into_inner().unwrap().finish().unwrap();
        }
        let root = dir.path().join("data");
        let storage = Storage::new_local(root.to_str().unwrap());

        let err = restore_backup(&storage, &archive_path)
            .await
            .expect_err("an entry in the staging directory must be refused");
        assert!(
            err.contains("Reserved path"),
            "refused for another reason: {err}"
        );
        assert!(!root.join(".nora-staging/0b1c/17.tmp").exists());
    }

    #[tokio::test]
    async fn test_backup_restore_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());

        // Put some test data
        storage
            .put("maven/com/example/1.0/test.jar", b"test-content")
            .await
            .unwrap();
        storage
            .put("docker/test/blobs/sha256:abc123", b"blob-data")
            .await
            .unwrap();

        // Create backup
        let backup_file = dir.path().join("backup.tar.gz");
        let backup_stats = create_backup(&storage, &backup_file).await.unwrap();
        assert_eq!(backup_stats.artifact_count, 2);

        // Restore to different storage
        let restore_storage = Storage::new_local(dir.path().join("restored").to_str().unwrap());
        let restore_stats = restore_backup(&restore_storage, &backup_file)
            .await
            .unwrap();
        assert_eq!(restore_stats.artifact_count, 2);

        // Verify data
        let data = restore_storage
            .get("maven/com/example/1.0/test.jar")
            .await
            .unwrap();
        assert_eq!(&data[..], b"test-content");
    }

    /// npm cache provenance (#1055) is hidden from list() but must survive a backup,
    /// with the restored object's pin still equal to the one the record was bound to.
    #[tokio::test]
    async fn test_backup_restore_carries_npm_provenance() {
        use crate::registry::npm::origin_key;
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());
        let key = "npm/@vendor/a/tarballs/a-1.0.0.tgz";
        storage.put(key, b"owner-tgz").await.unwrap();
        storage
            .put(&origin_key(key), b"npm:https://owner.example\nrecord")
            .await
            .unwrap();

        let backup_file = dir.path().join("backup.tar.gz");
        create_backup(&storage, &backup_file).await.unwrap();
        let restored = Storage::new_local(dir.path().join("restored").to_str().unwrap());
        restore_backup(&restored, &backup_file).await.unwrap();

        assert_eq!(
            &restored.get(&origin_key(key)).await.unwrap()[..],
            b"npm:https://owner.example\nrecord"
        );
        assert_eq!(restored.pin(key).await, storage.pin(key).await);
        assert!(restored.pin(key).await.is_some());
    }

    /// npm first-seen times are hidden from list() too, and survive a backup.
    #[tokio::test]
    async fn test_backup_restore_carries_npm_first_seen() {
        use crate::registry::npm::first_seen_key;
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());
        let key = "npm/a/metadata.json";
        storage.put(key, b"{}").await.unwrap();
        storage
            .put(&first_seen_key(key), br#"{"1.0.0":1700000000}"#)
            .await
            .unwrap();

        let backup_file = dir.path().join("backup.tar.gz");
        create_backup(&storage, &backup_file).await.unwrap();
        let restored = Storage::new_local(dir.path().join("restored").to_str().unwrap());
        restore_backup(&restored, &backup_file).await.unwrap();

        assert_eq!(
            &restored.get(&first_seen_key(key)).await.unwrap()[..],
            br#"{"1.0.0":1700000000}"#
        );
    }

    #[tokio::test]
    async fn test_backup_omits_signing_key() {
        // A backup tar must never carry the repository signing key: it would ship at
        // 0644 (mode-widened from the on-disk 0600) and restore/migrate would expose
        // it (plaintext S3 object on migrate). #891-class: the unit test guarded key
        // creation mode, not the export path. Regression guard.
        use flate2::read::GzDecoder;
        use std::fs::File;
        use tar::Archive;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("data");
        let storage = Storage::new_local(root.to_str().unwrap());

        storage
            .put("maven/com/example/1.0/test.jar", b"artifact")
            .await
            .unwrap();
        // Signing key under the storage root, as main.rs places it by default.
        std::fs::create_dir_all(root.join(".signing")).unwrap();
        std::fs::write(root.join(".signing/nora.key"), b"SECRET-SIGNING-KEY").unwrap();

        let output = dir.path().join("backup.tar.gz");
        let stats = create_backup(&storage, &output).await.unwrap();

        // Only the real artifact is backed up, not the key.
        assert_eq!(
            stats.artifact_count, 1,
            "signing key must not be counted or backed up as an artifact"
        );

        let f = File::open(&output).unwrap();
        let mut archive = Archive::new(GzDecoder::new(f));
        let names: Vec<String> = archive
            .entries()
            .unwrap()
            .filter_map(|e| e.ok())
            .filter_map(|e| e.path().ok().map(|p| p.to_string_lossy().into_owned()))
            .collect();
        assert!(
            !names.iter().any(|n| n.contains(".signing")),
            "backup tar must not contain the signing key: {names:?}"
        );
        assert!(
            names.iter().any(|n| n.contains("test.jar")),
            "backup tar must contain the real artifact: {names:?}"
        );
    }

    /// Tokens and the quarantine ledger are internal keys `list()` hides; a backup
    /// must carry them, and a restore onto a fresh node must bring back tokens that
    /// verify and the original first-seen times.
    #[tokio::test]
    async fn test_backup_restore_carries_tokens_and_quarantine_ledger() {
        use crate::digest_quarantine::{DigestStore, QuarantineStatus};
        use crate::tokens::{Role, TokenStore};
        use std::os::unix::fs::PermissionsExt;

        let src = tempfile::tempdir().unwrap();
        let storage = Storage::new_local(src.path().join("data").to_str().unwrap());
        storage.put("raw/a/1.bin", b"artifact").await.unwrap();
        let raw = TokenStore::new(storage.clone())
            .create_token("ci", 30, Some("deploy".into()), Role::Write)
            .await
            .unwrap();
        let ledger = DigestStore::empty(storage.clone());
        let old = chrono::Utc::now().timestamp() - 10 * 86400;
        ledger.record("docker", "sha256:aa", "registry-1.docker.io", Some(old));
        drop(ledger);
        // record writes from a spawned task.
        for _ in 0..500 {
            if storage
                .stat(".nora-quarantine/docker/sha256:aa")
                .await
                .is_some()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let backup_file = src.path().join("backup.tar.gz");
        let stats = create_backup(&storage, &backup_file).await.unwrap();
        assert_eq!(
            stats.artifact_count, 3,
            "the artifact, the token record and the ledger entry"
        );
        let mode = fs::metadata(&backup_file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "archive carries token hashes");

        // Fresh node: no tokens. It already re-recorded the digest with a fresh
        // first-seen, saw one more since the backup, and wrote its snapshot.
        let dst = tempfile::tempdir().unwrap();
        let restored = Storage::new_local(dst.path().join("data").to_str().unwrap());
        let fresh = DigestStore::empty(restored.clone());
        fresh.record("docker", "sha256:aa", "u", None);
        fresh.record("docker", "sha256:bb", "u", None);
        for _ in 0..500 {
            if restored
                .list_internal(".nora-quarantine/")
                .await
                .is_ok_and(|k| k.len() == 2)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        drop(fresh);
        assert_eq!(
            DigestStore::load(restored.clone(), "/nonexistent")
                .await
                .len(),
            2
        );

        let rstats = restore_backup(&restored, &backup_file).await.unwrap();
        assert_eq!(rstats.artifact_count, 3);
        assert_eq!(rstats.local_files, 0);

        let (user, role) = TokenStore::new(restored.clone())
            .verify_token(&raw)
            .await
            .expect("restored token must verify");
        assert_eq!((user.as_str(), role), ("ci", Role::Write));

        let ledger = DigestStore::load(restored, "/nonexistent").await;
        assert_eq!(
            ledger.len(),
            2,
            "digests recorded since the backup are kept"
        );
        assert_eq!(
            ledger.check("docker", "sha256:aa", 86400),
            QuarantineStatus::Mature,
            "the backup's original first-seen wins"
        );
    }

    /// An archive from before the ledger moved to storage carries it as
    /// `.nora-local/quarantine.jsonl`: a restore writes it into storage, and its
    /// first-seen wins over the one the node recorded since.
    #[tokio::test]
    async fn test_restore_writes_a_legacy_ledger_into_storage() {
        use crate::digest_quarantine::{DigestStore, QuarantineStatus};

        let dir = tempfile::tempdir().unwrap();
        let old = chrono::Utc::now().timestamp() - 10 * 86400;
        let body = format!(
            "{{\"registry\":\"docker\",\"digest\":\"sha256:aa\",\"first_seen\":{old},\"upstream\":\"u\"}}\n"
        );
        let archive_path = dir.path().join("legacy.tar.gz");
        {
            let gz = GzEncoder::new(File::create(&archive_path).unwrap(), Compression::default());
            let mut tar = tar::Builder::new(gz);
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o600);
            header.set_cksum();
            tar.append_data(&mut header, ".nora-local/quarantine.jsonl", body.as_bytes())
                .unwrap();
            tar.into_inner().unwrap().finish().unwrap();
        }
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());
        let fresh = DigestStore::empty(storage.clone());
        fresh.record("docker", "sha256:aa", "u", None);
        for _ in 0..500 {
            if storage
                .stat(".nora-quarantine/docker/sha256:aa")
                .await
                .is_some()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let stats = restore_backup(&storage, &archive_path).await.unwrap();
        assert_eq!((stats.artifact_count, stats.local_files), (0, 1));
        let ledger = DigestStore::load(storage, "/nonexistent").await;
        assert_eq!(
            ledger.check("docker", "sha256:aa", 86400),
            QuarantineStatus::Mature
        );
    }

    /// Local-state entries come from an archive: only flat token record names
    /// (and a legacy ledger) are written, anything else is refused.
    #[tokio::test]
    async fn restore_refuses_unexpected_local_state_entries() {
        let dir = tempfile::tempdir().unwrap();
        for (name, body) in [
            (".nora-local/tokens/not-a-record.json", &b"{}"[..]),
            (".nora-local/tokens/0123456789abcdef.json", &b"garbage"[..]),
            (".nora-local/signing/nora.key", &b"key"[..]),
        ] {
            let archive_path = dir.path().join("crafted.tar.gz");
            {
                let gz =
                    GzEncoder::new(File::create(&archive_path).unwrap(), Compression::default());
                let mut tar = tar::Builder::new(gz);
                let mut header = tar::Header::new_gnu();
                header.set_size(body.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                tar.append_data(&mut header, name, body).unwrap();
                tar.into_inner().unwrap().finish().unwrap();
            }
            let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());
            restore_backup(&storage, &archive_path)
                .await
                .expect_err(name);
            let written = storage.list_internal(tokens::STORAGE_PREFIX).await.unwrap();
            assert!(written.is_empty(), "{name} wrote a token record");
            assert!(storage.list("").await.unwrap().is_empty(), "{name}");
        }
    }

    /// An archive from before tokens moved into storage carries them as
    /// `.nora-local/tokens/<16hex>.json`: restore puts them under the token prefix.
    #[tokio::test]
    async fn restore_brings_old_archive_tokens_into_storage() {
        use crate::tokens::{Role, TokenStore};
        let dir = tempfile::tempdir().unwrap();
        let minted = Storage::new_local(dir.path().join("old").to_str().unwrap());
        let raw = TokenStore::new(minted.clone())
            .create_token("ci", 30, None, Role::Read)
            .await
            .unwrap();
        let key = minted.list_internal(tokens::STORAGE_PREFIX).await.unwrap()[0].clone();
        let body = minted.get(&key).await.unwrap();
        let name = key.strip_prefix(tokens::STORAGE_PREFIX).unwrap();

        let archive_path = dir.path().join("old.tar.gz");
        {
            let gz = GzEncoder::new(File::create(&archive_path).unwrap(), Compression::default());
            let mut tar = tar::Builder::new(gz);
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o600);
            header.set_cksum();
            tar.append_data(&mut header, format!(".nora-local/tokens/{name}"), &body[..])
                .unwrap();
            tar.into_inner().unwrap().finish().unwrap();
        }
        let storage = Storage::new_local(dir.path().join("data").to_str().unwrap());
        let stats = restore_backup(&storage, &archive_path).await.unwrap();
        assert_eq!(stats.local_files, 1);
        let (user, _) = TokenStore::new(storage).verify_token(&raw).await.unwrap();
        assert_eq!(user, "ci");
    }
}
