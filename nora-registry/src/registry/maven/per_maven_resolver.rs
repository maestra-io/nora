// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::{classify_path, MavenPathKind};
use crate::storage::{ObjectStorage, Storage};
use crate::test_helpers::{create_test_context_with_storage_and_config, send, upstream_paths};
use axum::http::{Method, StatusCode};
use wiremock::matchers::{any, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn corpus(file: &str) -> Vec<Vec<String>> {
    let path = format!("{}/testdata/maven/{file}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|row| !row.starts_with('#'))
        .map(|row| row.split('\t').map(String::from).collect())
        .collect()
}

// Every artifact and checksum path the resolver builds reads back as its coordinates: the
// group, the artifact, the base version (the directory; a timestamped snapshot's file lives
// in its `-SNAPSHOT` directory) and the file name; every artifact-level metadata path as its
// group and artifact.
#[test]
fn every_path_maven_resolver_builds_reads_as_its_coordinates() {
    let rows = corpus("layout.tsv");
    assert_eq!(rows.len(), 680);
    let mut files = 0;
    let mut metadata = 0;
    for row in &rows {
        let (kind, group, artifact, base_version, path) =
            (&row[0], &row[1], &row[2], &row[3], &row[7]);
        let file_name = path.rsplit('/').next().unwrap();
        match (kind.as_str(), classify_path(path)) {
            ("artifact" | "checksum", MavenPathKind::VersionFile(c)) => {
                assert_eq!(c.group_path.replace('/', "."), *group, "{path}");
                assert_eq!(c.artifact_id, *artifact, "{path}");
                assert_eq!(c.version, *base_version, "{path}");
                assert_eq!(c.filename, file_name, "{path}");
                files += 1;
            }
            (
                "metadata",
                MavenPathKind::ArtifactMeta {
                    group_path,
                    artifact_id,
                    filename,
                },
            ) if !artifact.is_empty() && base_version.is_empty() => {
                assert_eq!(group_path.replace('/', "."), *group, "{path}");
                assert_eq!(artifact_id, *artifact, "{path}");
                assert_eq!(filename, "maven-metadata.xml", "{path}");
                metadata += 1;
            }
            ("metadata", _) => {}
            (kind, _) => panic!("{kind} {path} is not read as a version file"),
        }
    }
    assert_eq!((files, metadata), (660, 5));
}

const SNAPSHOT_METADATA: &str = "<metadata><groupId>org.example</groupId><artifactId>snap</artifactId>\
        <version>1.0-SNAPSHOT</version><versioning><snapshot><timestamp>20261012.120000</timestamp>\
        <buildNumber>1</buildNumber></snapshot><lastUpdated>20261012120000</lastUpdated></versioning></metadata>";

async fn upstream() -> MockServer {
    let up = MockServer::start().await;
    Mock::given(path_regex(r"maven-metadata\.xml$"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SNAPSHOT_METADATA))
        .mount(&up)
        .await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"file".to_vec()))
        .mount(&up)
        .await;
    up
}

/// Whether a request names a file of a version (not metadata nor a checksum of metadata).
fn is_version_file(path: &str) -> bool {
    !path.contains("maven-metadata.xml")
}

// Every request Maven sends reaches upstream at the path it sent (a metadata checksum as its
// metadata document, from which NORA answers the checksum).
#[tokio::test]
async fn every_request_maven_sends_is_asked_upstream_as_sent() {
    let rows = corpus("client-requests.tsv");
    assert_eq!(rows.len(), 28);
    let up = upstream().await;
    let uri = up.uri();
    let storage = Storage::from_backend(std::sync::Arc::new(ObjectStorage::in_memory()));
    let ctx = create_test_context_with_storage_and_config(storage, |cfg| {
        cfg.maven.proxies = vec![crate::config::MavenProxyEntry::Simple(uri)];
    });
    for row in rows {
        let (coordinate, path) = (&row[0], &row[2]);
        assert_eq!(row[1], "GET");
        let resp = send(&ctx.app, Method::GET, path, "").await;
        assert_eq!(resp.status(), StatusCode::OK, "{coordinate}: {path}");
        let sent = path.strip_prefix("/maven2").unwrap();
        let asked = super::metadata_document_key(sent)
            .filter(|_| !is_version_file(sent))
            .unwrap_or(sent);
        assert!(
            upstream_paths(&up).await.iter().any(|p| p == asked),
            "{coordinate}: {path}"
        );
    }
}

// Every version file Maven fetches is curated as `groupId:artifactId` and the version it
// asked for (a snapshot's `-SNAPSHOT` version): a rule naming them refuses it before upstream
// is asked.
#[tokio::test]
async fn every_file_maven_fetches_is_curated_as_its_coordinate() {
    let rows: Vec<Vec<String>> = corpus("client-requests.tsv")
        .into_iter()
        .filter(|row| is_version_file(&row[2]))
        .collect();
    assert_eq!(rows.len(), 26);
    let rules: Vec<serde_json::Value> = rows
        .iter()
        .map(|row| {
            let parts: Vec<&str> = row[0].split(':').collect();
            serde_json::json!({"registry": "maven", "name": format!("{}:{}", parts[0], parts[1]), "version": parts[2], "reason": "test"})
        })
        .collect();
    let dir = tempfile::TempDir::new().unwrap();
    let blocklist = dir.path().join("blocklist.json");
    std::fs::write(
        &blocklist,
        serde_json::json!({"version": 1, "rules": rules}).to_string(),
    )
    .unwrap();
    let up = upstream().await;
    let uri = up.uri();
    let storage = Storage::from_backend(std::sync::Arc::new(ObjectStorage::in_memory()));
    let ctx = create_test_context_with_storage_and_config(storage, |cfg| {
        cfg.maven.proxies = vec![crate::config::MavenProxyEntry::Simple(uri)];
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.blocklist_path = Some(blocklist.to_string_lossy().into_owned());
    });
    for row in rows {
        let resp = send(&ctx.app, Method::GET, &row[2], "").await;
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "{}: {}",
            row[0],
            row[2]
        );
    }
    let sent = upstream_paths(&up).await;
    assert!(sent.is_empty(), "{sent:?}");
}
