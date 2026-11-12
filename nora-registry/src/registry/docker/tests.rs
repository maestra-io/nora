// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::*;

/// A file under `manifests/` stores a tag only if its name is a valid tag and not a sidecar.
#[test]
fn tag_from_manifest_file_accepts_only_tags() {
    let digest = format!("sha256:{}", "a".repeat(64));
    let long = "a".repeat(129);
    let longest = "a".repeat(128);
    let cases: Vec<(String, Option<&str>)> = vec![
        ("1.0.0.json".into(), Some("1.0.0")),
        ("latest.json".into(), Some("latest")),
        ("v1.2.3-rc.1.json".into(), Some("v1.2.3-rc.1")),
        ("a.meta.b.json".into(), Some("a.meta.b")),
        (format!("{longest}.json"), Some(longest.as_str())),
        ("1.0.0.stats.json".into(), None),
        ("1.0.0.STATS.json".into(), None),
        ("1.0.0.meta.json".into(), None),
        ("x.meta.json".into(), None),
        (format!("{digest}.json"), None),
        (format!("{digest}.meta.json"), None),
        (format!("{digest}.stats.json"), None),
        (".json".into(), None),
        ("".into(), None),
        (format!("{long}.json"), None),
        ("latest".into(), None),
        ("-dash.json".into(), None),
        ("a..b.json".into(), None),
        ("a b.json".into(), None),
    ];
    for (file, want) in &cases {
        assert_eq!(tag_from_manifest_file(file), *want, "{file:?}");
    }
}

#[tokio::test]
async fn a_blob_stream_passes_its_digest_and_withholds_the_end_of_another() {
    use futures::StreamExt as _;
    use sha2::Digest as _;
    let data = vec![9u8; 600_000];
    let good = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&data)));
    let bad = format!("sha256:{}", hex::encode(sha2::Sha256::digest(b"other")));
    for (digest, intact) in [(&good, true), (&bad, false)] {
        let reader: std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>> =
            Box::pin(std::io::Cursor::new(data.clone()));
        let mut stream = blob_verifying_stream(reader, digest, "docker/alpine/blobs/x".into());
        let (mut got, mut failed) = (0usize, false);
        while let Some(frame) = stream.next().await {
            match frame {
                Ok(bytes) => got += bytes.len(),
                Err(_) => failed = true,
            }
        }
        if intact {
            assert!(
                !failed && got == data.len(),
                "intact: {got} of {}",
                data.len()
            );
        } else {
            assert!(
                failed && got < data.len(),
                "mismatch: {got} of {} sent",
                data.len()
            );
        }
    }
}

#[test]
fn test_image_metadata_default() {
    let meta = ImageMetadata::default();
    assert_eq!(meta.push_timestamp, 0);
    assert_eq!(meta.last_pulled, 0);
    assert_eq!(meta.downloads, 0);
    assert_eq!(meta.size_bytes, 0);
    assert_eq!(meta.os, "");
    assert_eq!(meta.arch, "");
    assert!(meta.variant.is_none());
    assert!(meta.layers.is_empty());
}

#[test]
fn test_image_metadata_serialization() {
    let meta = ImageMetadata {
        push_timestamp: 1700000000,
        last_pulled: 1700001000,
        downloads: 42,
        size_bytes: 1024000,
        os: "linux".to_string(),
        arch: "amd64".to_string(),
        variant: None,
        layers: vec![LayerInfo {
            digest: "sha256:abc123".to_string(),
            size: 512000,
        }],
        pushed_digest: None,
    };
    let json = serde_json::to_string(&meta).unwrap();
    assert!(json.contains("\"os\":\"linux\""));
    assert!(json.contains("\"arch\":\"amd64\""));
    assert!(!json.contains("variant")); // None => skipped
}

#[test]
fn test_image_metadata_with_variant() {
    let meta = ImageMetadata {
        variant: Some("v8".to_string()),
        ..Default::default()
    };
    let json = serde_json::to_string(&meta).unwrap();
    assert!(json.contains("\"variant\":\"v8\""));
}

#[test]
fn test_image_metadata_deserialization() {
    let json = r#"{
            "push_timestamp": 1700000000,
            "last_pulled": 0,
            "downloads": 5,
            "size_bytes": 2048,
            "os": "linux",
            "arch": "arm64",
            "variant": "v8",
            "layers": [
                {"digest": "sha256:aaa", "size": 1024},
                {"digest": "sha256:bbb", "size": 1024}
            ]
        }"#;
    let meta: ImageMetadata = serde_json::from_str(json).unwrap();
    assert_eq!(meta.os, "linux");
    assert_eq!(meta.arch, "arm64");
    assert_eq!(meta.variant, Some("v8".to_string()));
    assert_eq!(meta.layers.len(), 2);
    assert_eq!(meta.layers[0].digest, "sha256:aaa");
    assert_eq!(meta.layers[1].size, 1024);
}

#[test]
fn test_layer_info_serialization_roundtrip() {
    let layer = LayerInfo {
        digest: "sha256:deadbeef".to_string(),
        size: 999999,
    };
    let json = serde_json::to_value(&layer).unwrap();
    let restored: LayerInfo = serde_json::from_value(json).unwrap();
    assert_eq!(layer.digest, restored.digest);
    assert_eq!(layer.size, restored.size);
}

#[test]
fn test_cleanup_expired_sessions_empty() {
    let sessions: RwLock<HashMap<String, UploadSession>> = RwLock::new(HashMap::new());
    cleanup_expired_sessions(&sessions);
    assert_eq!(sessions.read().len(), 0);
}

#[test]
fn test_cleanup_expired_sessions_fresh() {
    let sessions: RwLock<HashMap<String, UploadSession>> = RwLock::new(HashMap::new());
    let temp_dir = tempfile::TempDir::new().unwrap();
    let temp_path = temp_dir.path().join("uuid-1");
    std::fs::write(&temp_path, b"test data").unwrap();
    sessions.write().insert(
        "uuid-1".to_string(),
        UploadSession {
            temp_path,
            size: 9,
            name: "test/image".to_string(),
            created_at: std::time::Instant::now(),
        },
    );
    cleanup_expired_sessions(&sessions);
    assert_eq!(sessions.read().len(), 1); // not expired
}

#[test]
fn test_max_upload_sessions_default() {
    let _lock = crate::test_env::env_lock();
    // Without env var set, should return default
    let max = max_upload_sessions();
    assert!(max > 0);
    assert_eq!(max, DEFAULT_MAX_UPLOAD_SESSIONS);
}

#[tokio::test]
async fn test_cancel_upload_frees_session_and_temp() {
    use crate::test_helpers::{create_test_context, send};

    let ctx = create_test_context();
    let resp = send(
        &ctx.app,
        Method::POST,
        "/v2/alpine/blobs/uploads/",
        Body::empty(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let location = resp.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();

    let temp_path = {
        let sessions = ctx.state.upload_sessions.read();
        assert_eq!(sessions.len(), 1);
        sessions.values().next().unwrap().temp_path.clone()
    };
    assert!(temp_path.exists());

    let resp = send(&ctx.app, Method::DELETE, &location, Body::empty()).await;
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "cancel must be honoured, not 405 — a refused cancel holds a session slot until SESSION_TTL"
    );
    assert_eq!(ctx.state.upload_sessions.read().len(), 0);
    assert!(!temp_path.exists(), "cancel must reclaim the temp file");

    // Cancelling twice is a 404, not a panic or a second free.
    let resp = send(&ctx.app, Method::DELETE, &location, Body::empty()).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[test]
fn test_upload_session_limit_returns_oci_429() {
    // The handler reads the limit from env while the request runs, so the lock is
    // held across the whole request; a runtime of its own keeps that off an `.await`.
    let _lock = crate::test_env::env_lock();
    use crate::test_helpers::{body_bytes, create_test_context, send};

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        // Pre-fill the session map to the ceiling — no env mutation, so this is
        // safe under parallel tests.
        let ctx = create_test_context();
        {
            let mut sessions = ctx.state.upload_sessions.write();
            for i in 0..max_upload_sessions() {
                sessions.insert(
                    format!("fill-{i}"),
                    UploadSession {
                        temp_path: std::env::temp_dir().join(format!("fill-{i}")),
                        size: 0,
                        name: "alpine".to_string(),
                        created_at: std::time::Instant::now(),
                    },
                );
            }
        }
        let resp = send(
            &ctx.app,
            Method::POST,
            "/v2/alpine/blobs/uploads/",
            Body::empty(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers()[header::CONTENT_TYPE].to_str().unwrap(),
            "application/json"
        );
        assert!(
            resp.headers().contains_key(header::RETRY_AFTER),
            "429 must carry Retry-After so clients back off"
        );
        let body: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        assert_eq!(body["errors"][0]["code"], "TOOMANYREQUESTS");
        assert_eq!(
            body["errors"][0]["detail"]["limit"],
            max_upload_sessions() as u64
        );
    });
}

#[test]
fn test_max_session_size_default() {
    let _lock = crate::test_env::env_lock();
    let max = max_session_size();
    assert_eq!(max, DEFAULT_MAX_SESSION_SIZE_MB * 1024 * 1024);
}

// --- validate_upload_uuid tests ---

#[test]
fn test_validate_upload_uuid_valid() {
    assert!(validate_upload_uuid("550e8400-e29b-41d4-a716-446655440000").is_ok());
    assert!(validate_upload_uuid("abcdef01-2345-4678-9abc-def012345678").is_ok());
}

#[test]
fn test_validate_upload_uuid_rejects_path_traversal() {
    assert!(validate_upload_uuid("../../../etc/passwd").is_err());
    assert!(validate_upload_uuid("x/../../etc/cron.d/backdoor").is_err());
    assert!(validate_upload_uuid("..").is_err());
}

#[test]
fn test_validate_upload_uuid_rejects_invalid() {
    assert!(validate_upload_uuid("").is_err()); // empty
    assert!(validate_upload_uuid("ABCDEF01-2345-4678-9ABC-DEF012345678").is_err()); // uppercase
    assert!(validate_upload_uuid("hello world").is_err()); // spaces
    assert!(validate_upload_uuid("a".repeat(37).as_str()).is_err()); // too long
}

// --- cleanup_upload_temp_dir tests ---

#[test]
fn test_cleanup_upload_temp_dir_removes_old_files() {
    use std::fs::FileTimes;
    use std::time::SystemTime;

    let temp_dir = tempfile::TempDir::new().unwrap();
    let upload_dir = temp_dir.path().join("tmp/docker-uploads");
    std::fs::create_dir_all(&upload_dir).unwrap();

    // Create an old file (set mtime to 2 hours ago)
    let old_file = upload_dir.join("old-uuid");
    std::fs::write(&old_file, b"stale data").unwrap();
    let old_time = SystemTime::now() - std::time::Duration::from_secs(7200);
    let times = FileTimes::new().set_modified(old_time);
    std::fs::File::options()
        .write(true)
        .open(&old_file)
        .unwrap()
        .set_times(times)
        .unwrap();

    // Create a recent file
    let new_file = upload_dir.join("new-uuid");
    std::fs::write(&new_file, b"fresh data").unwrap();

    cleanup_upload_temp_dir(temp_dir.path().to_str().unwrap());

    assert!(!old_file.exists(), "old file should be removed");
    assert!(new_file.exists(), "recent file should be preserved");
}

#[test]
fn test_cleanup_upload_temp_dir_nonexistent_dir() {
    let data = tempfile::tempdir().unwrap();
    let data_dir = data.path().join("never-created");
    cleanup_upload_temp_dir(data_dir.to_str().unwrap());
    // A cleanup of a directory that is not there removes nothing and creates nothing.
    assert!(!data_dir.exists());
}

// --- detect_manifest_media_type tests ---

#[test]
fn test_detect_manifest_explicit_media_type() {
    let manifest = serde_json::json!({
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "schemaVersion": 2
    });
    let result = detect_manifest_media_type(manifest.to_string().as_bytes());
    assert_eq!(
        result,
        "application/vnd.docker.distribution.manifest.v2+json"
    );
}

#[test]
fn test_detect_manifest_oci_media_type() {
    let manifest = serde_json::json!({
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "schemaVersion": 2
    });
    let result = detect_manifest_media_type(manifest.to_string().as_bytes());
    assert_eq!(result, "application/vnd.oci.image.manifest.v1+json");
}

#[test]
fn test_detect_manifest_schema_v1() {
    let manifest = serde_json::json!({
        "schemaVersion": 1,
        "name": "test/image"
    });
    let result = detect_manifest_media_type(manifest.to_string().as_bytes());
    assert_eq!(
        result,
        "application/vnd.docker.distribution.manifest.v1+json"
    );
}

#[test]
fn test_detect_manifest_docker_v2_from_config() {
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "digest": "sha256:abc"
        }
    });
    let result = detect_manifest_media_type(manifest.to_string().as_bytes());
    assert_eq!(
        result,
        "application/vnd.docker.distribution.manifest.v2+json"
    );
}

#[test]
fn test_detect_manifest_oci_from_config() {
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": "sha256:abc"
        }
    });
    let result = detect_manifest_media_type(manifest.to_string().as_bytes());
    assert_eq!(result, "application/vnd.oci.image.manifest.v1+json");
}

#[test]
fn test_detect_manifest_no_config_media_type() {
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "config": {
            "digest": "sha256:abc"
        }
    });
    let result = detect_manifest_media_type(manifest.to_string().as_bytes());
    assert_eq!(
        result,
        "application/vnd.docker.distribution.manifest.v2+json"
    );
}

#[test]
fn test_detect_manifest_index() {
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "manifests": [
            {"digest": "sha256:aaa", "platform": {"os": "linux", "architecture": "amd64"}}
        ]
    });
    let result = detect_manifest_media_type(manifest.to_string().as_bytes());
    assert_eq!(result, "application/vnd.oci.image.index.v1+json");
}

#[test]
fn test_detect_manifest_invalid_json() {
    let result = detect_manifest_media_type(b"not json at all");
    assert_eq!(
        result,
        "application/vnd.docker.distribution.manifest.v2+json"
    );
}

#[test]
fn test_detect_manifest_empty() {
    let result = detect_manifest_media_type(b"{}");
    assert_eq!(
        result,
        "application/vnd.docker.distribution.manifest.v2+json"
    );
}

#[test]
fn test_detect_manifest_helm_chart() {
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "config": {
            "mediaType": "application/vnd.cncf.helm.config.v1+json",
            "digest": "sha256:abc"
        }
    });
    let result = detect_manifest_media_type(manifest.to_string().as_bytes());
    assert_eq!(result, "application/vnd.oci.image.manifest.v1+json");
}
