// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::*;

#[test]
fn test_url_is_maven_central() {
    // canonical Central hosts → true (date source available)
    assert!(url_is_maven_central("https://repo1.maven.org/maven2"));
    assert!(url_is_maven_central("https://repo.maven.apache.org/maven2"));
    assert!(url_is_maven_central("https://search.maven.org"));
    assert!(url_is_maven_central("https://central.sonatype.com"));
    // private mirrors → false: their coordinates must NEVER reach search.maven.org (#68/#733)
    assert!(!url_is_maven_central(
        "https://nexus.internal.corp/repository/maven"
    ));
    assert!(!url_is_maven_central("https://artifactory.acme.io/maven"));
    assert!(!url_is_maven_central("https://maven.pkg.github.com/acme"));
    assert!(!url_is_maven_central(""));
}

mod central_date {
    use super::*;
    use std::sync::{Arc, Mutex};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const JAR: &str = "/maven2/org/x/a/1.0/a-1.0.jar";
    const GAV: (&str, &str, &str) = ("org.x", "a", "1.0");

    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Runs the lookup with a log capture; returns (date, elapsed, log).
    async fn lookup(server: &MockServer, budget: Duration) -> (Option<i64>, Duration, String) {
        let sink = Sink::default();
        let writer = sink.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let started = std::time::Instant::now();
        let date = maven_central_publish_date(
            &reqwest::Client::new(),
            &format!("{}{}", server.uri(), JAR),
            None,
            &server.uri(),
            GAV,
            budget,
        )
        .await;
        let log = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        (date, started.elapsed(), log)
    }

    fn search_hit() -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "response": {"docs": [{"timestamp": 1_173_268_800_000_i64}]}
        }))
    }

    /// The date comes from the file's `Last-Modified`; the search API is not asked.
    #[tokio::test]
    async fn last_modified_is_the_date() {
        let server = MockServer::start().await;
        Mock::given(method("HEAD"))
            .and(path(JAR))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("last-modified", "Wed, 07 Mar 2007 12:00:00 GMT"),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/solrsearch/select"))
            .respond_with(search_hit())
            .expect(0)
            .mount(&server)
            .await;
        let (date, _, log) = lookup(&server, Duration::from_secs(5)).await;
        assert_eq!(date, Some(1_173_268_800));
        assert!(!log.contains("WARN"), "{log}");
    }

    /// No `Last-Modified` → the search API answers; the miss is logged with its reason.
    #[tokio::test]
    async fn search_is_the_fallback() {
        let server = MockServer::start().await;
        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        Mock::given(path("/solrsearch/select"))
            .respond_with(search_hit())
            .expect(1)
            .mount(&server)
            .await;
        let (date, _, log) = lookup(&server, Duration::from_secs(5)).await;
        assert_eq!(date, Some(1_173_268_800));
        assert!(
            log.contains("WARN") && log.contains("last_modified") && log.contains("missing"),
            "{log}"
        );
    }

    /// A throttled HEAD and a hung search (the 11.11.2026 30 s misses) give no date
    /// within the lookup budget, each failure logged at WARN with its reason and counted.
    #[tokio::test]
    async fn hung_search_is_bounded_by_the_budget() {
        let server = MockServer::start().await;
        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        Mock::given(path("/solrsearch/select"))
            .respond_with(search_hit().set_delay(Duration::from_secs(30)))
            .mount(&server)
            .await;
        let timeouts = || {
            crate::metrics::MAVEN_DATE_LOOKUP_TOTAL
                .with_label_values(&["search", "timeout"])
                .get()
        };
        let before = timeouts();
        let (date, elapsed, log) = lookup(&server, Duration::from_secs(1)).await;
        assert_eq!(date, None, "no date → first_seen");
        // 1 s budget against a 30 s hang; the margin absorbs a loaded CI runner.
        assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
        assert!(timeouts() > before);
        let warns: Vec<&str> = log.lines().filter(|l| l.contains("WARN")).collect();
        assert_eq!(warns.len(), 2, "{log}");
        assert!(
            warns[0].contains("last_modified") && warns[0].contains("status=Some(403)"),
            "{log}"
        );
        assert!(
            warns[1].contains("search") && warns[1].contains("timeout"),
            "{log}"
        );
    }

    /// A HEAD that times out spends the whole budget: no search after it.
    #[tokio::test]
    async fn hung_head_skips_the_search() {
        let server = MockServer::start().await;
        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
            .mount(&server)
            .await;
        Mock::given(path("/solrsearch/select"))
            .respond_with(search_hit())
            .expect(0)
            .mount(&server)
            .await;
        let (date, elapsed, log) = lookup(&server, Duration::from_secs(1)).await;
        assert_eq!(date, None);
        // 1 s budget against a 30 s hang; the margin absorbs a loaded CI runner.
        assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
        assert!(log.contains("WARN") && log.contains("timeout"), "{log}");
    }

    /// A cached artifact held on first_seen is dated again, once per retry window: a
    /// Central date matures it, no date keeps it held, a mature one is not looked up.
    #[tokio::test]
    async fn held_cached_artifact_is_dated_again() {
        use crate::digest_quarantine::{DigestStore, QuarantineStatus};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let tmp = tempfile::TempDir::new().unwrap();
        let store = DigestStore::empty(crate::storage::Storage::new_local(
            tmp.path().to_str().unwrap(),
        ));
        let ttl = 7 * 86400;
        let calls = AtomicUsize::new(0);
        let lookup = |date: Option<i64>| {
            let calls = &calls;
            move || async move {
                calls.fetch_add(1, Ordering::SeqCst);
                date
            }
        };
        let held = |d: &str| {
            matches!(
                store.check("maven", d, ttl),
                QuarantineStatus::Pending { .. }
            )
        };

        let undated = "sha256:redate-undated";
        store.record("maven", undated, "u", None);
        redate_held(&store, undated, ttl, lookup(None)).await;
        assert!(held(undated), "no date keeps first_seen");
        redate_held(&store, undated, ttl, lookup(Some(1_173_268_800))).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1, "retried within the window");
        assert!(held(undated));

        let old = "sha256:redate-old";
        store.record("maven", old, "u", None);
        redate_held(&store, old, ttl, lookup(Some(1_173_268_800))).await;
        assert_eq!(store.check("maven", old, ttl), QuarantineStatus::Mature);
        redate_held(&store, old, ttl, lookup(Some(1_173_268_800))).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a mature digest is not looked up"
        );

        // No entry (a restart forgot one dated past the prune line): dated, not held.
        let unrecorded = "sha256:redate-unrecorded";
        redate_held(&store, unrecorded, ttl, lookup(Some(1_173_268_800))).await;
        assert_eq!(
            store.check("maven", unrecorded, ttl),
            QuarantineStatus::Mature
        );
        // No entry and no date: left to the gate, which starts first_seen at now.
        let unrecorded_undated = "sha256:redate-unrecorded-undated";
        redate_held(&store, unrecorded_undated, ttl, lookup(None)).await;
        assert_eq!(
            store.check("maven", unrecorded_undated, ttl),
            QuarantineStatus::New
        );

        // While the ledger loads, a dated digest is not marked tried: the merge may
        // prune its entry, and the next hit dates it again.
        let loading = "sha256:redate-loading";
        store.set_loaded(false);
        redate_held(&store, loading, ttl, lookup(Some(1_173_268_800))).await;
        store.set_loaded(true);
        assert!(!REDATE_TRIED.lock().contains_key(loading));

        let young = "sha256:redate-young";
        store.record("maven", young, "u", None);
        let yesterday = crate::cache_ttl::now_unix() as i64 - 86400;
        redate_held(&store, young, ttl, lookup(Some(yesterday))).await;
        assert!(held(young), "a young Central date still holds");
    }

    /// Not on Central (a maven.google.com artifact): no date, no search, no WARN.
    #[tokio::test]
    async fn not_on_central_is_quiet() {
        let server = MockServer::start().await;
        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(path("/solrsearch/select"))
            .respond_with(search_hit())
            .expect(0)
            .mount(&server)
            .await;
        let (date, _, log) = lookup(&server, Duration::from_secs(5)).await;
        assert_eq!(date, None);
        assert!(!log.contains("WARN"), "{log}");
    }
}

#[test]
fn test_content_type_pom() {
    let (status, headers, _) =
        with_content_type("com/example/1.0/example-1.0.pom", Bytes::from("data"));
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[0].1, "application/xml");
}

#[test]
fn test_content_type_jar() {
    let (_, headers, _) = with_content_type("com/example/1.0/example-1.0.jar", Bytes::from("data"));
    assert_eq!(headers[0].1, "application/java-archive");
}

#[test]
fn test_content_type_xml() {
    let (_, headers, _) = with_content_type("com/example/maven-metadata.xml", Bytes::from("data"));
    assert_eq!(headers[0].1, "application/xml");
}

#[test]
fn test_content_type_sha1() {
    let (_, headers, _) =
        with_content_type("com/example/1.0/example-1.0.jar.sha1", Bytes::from("data"));
    assert_eq!(headers[0].1, "text/plain");
}

#[test]
fn test_content_type_md5() {
    let (_, headers, _) =
        with_content_type("com/example/1.0/example-1.0.jar.md5", Bytes::from("data"));
    assert_eq!(headers[0].1, "text/plain");
}

#[test]
fn test_content_type_sha256() {
    let (_, headers, _) = with_content_type(
        "com/example/1.0/example-1.0.jar.sha256",
        Bytes::from("data"),
    );
    assert_eq!(headers[0].1, "text/plain");
}

#[test]
fn test_content_type_unknown() {
    let (_, headers, _) = with_content_type("some/random/file.bin", Bytes::from("data"));
    assert_eq!(headers[0].1, "application/octet-stream");
}

#[test]
fn test_content_type_preserves_body() {
    let body = Bytes::from("test-jar-content");
    let (_, _, data) = with_content_type("test.jar", body.clone());
    assert_eq!(data, body);
}

#[test]
fn test_is_mutable_maven_path() {
    // maven-metadata.xml and its checksums are mutable (rewritten as versions deploy).
    assert!(is_mutable_maven_path(
        "com/example/mylib/maven-metadata.xml"
    ));
    assert!(is_mutable_maven_path(
        "com/example/mylib/maven-metadata.xml.sha1"
    ));
    // SNAPSHOT version files are republished in place → mutable.
    assert!(is_mutable_maven_path(
        "com/example/mylib/1.0.0-SNAPSHOT/mylib-1.0.0-SNAPSHOT.jar"
    ));
    // Released artifacts are immutable.
    assert!(!is_mutable_maven_path(
        "com/example/mylib/1.0.0/mylib-1.0.0.jar"
    ));
    assert!(!is_mutable_maven_path(
        "com/example/mylib/1.0.0/mylib-1.0.0.pom"
    ));
}

// ── Path classification ─────────────────────────────────────────────

#[test]
fn test_classify_version_file() {
    match classify_path("com/example/mylib/1.0.0/mylib-1.0.0.jar") {
        MavenPathKind::VersionFile(c) => {
            assert_eq!(c.group_path, "com/example");
            assert_eq!(c.artifact_id, "mylib");
            assert_eq!(c.version, "1.0.0");
            assert_eq!(c.filename, "mylib-1.0.0.jar");
        }
        _ => panic!("expected VersionFile"),
    }
}

#[test]
fn test_classify_version_checksum() {
    match classify_path("com/example/mylib/1.0.0/mylib-1.0.0.jar.sha1") {
        MavenPathKind::VersionFile(c) => {
            assert!(is_checksum_file(&c.filename));
            assert_eq!(c.version, "1.0.0");
        }
        _ => panic!("expected VersionFile"),
    }
}

#[test]
fn test_classify_artifact_metadata() {
    match classify_path("com/example/mylib/maven-metadata.xml") {
        MavenPathKind::ArtifactMeta {
            group_path,
            artifact_id,
            filename,
        } => {
            assert_eq!(group_path, "com/example");
            assert_eq!(artifact_id, "mylib");
            assert_eq!(filename, "maven-metadata.xml");
        }
        _ => panic!("expected ArtifactMeta"),
    }
}

#[test]
fn test_classify_metadata_checksum() {
    match classify_path("com/example/mylib/maven-metadata.xml.sha256") {
        MavenPathKind::ArtifactMeta {
            artifact_id,
            filename,
            ..
        } => {
            assert_eq!(artifact_id, "mylib");
            assert_eq!(filename, "maven-metadata.xml.sha256");
        }
        _ => panic!("expected ArtifactMeta"),
    }
}

#[test]
fn test_classify_deep_group() {
    match classify_path(
        "org/apache/maven/plugins/maven-compiler-plugin/3.11.0/maven-compiler-plugin-3.11.0.jar",
    ) {
        MavenPathKind::VersionFile(c) => {
            assert_eq!(c.group_path, "org/apache/maven/plugins");
            assert_eq!(c.artifact_id, "maven-compiler-plugin");
            assert_eq!(c.version, "3.11.0");
        }
        _ => panic!("expected VersionFile"),
    }
}

#[test]
fn test_classify_snapshot() {
    match classify_path("com/example/mylib/1.0-SNAPSHOT/mylib-1.0-SNAPSHOT.jar") {
        MavenPathKind::VersionFile(c) => {
            assert!(is_snapshot(&c.version));
        }
        _ => panic!("expected VersionFile"),
    }
}

#[test]
fn test_classify_opaque_short_path() {
    assert!(matches!(classify_path("a"), MavenPathKind::Opaque));
}

// ── Checksum detection ──────────────────────────────────────────────

#[test]
fn test_is_checksum_file() {
    assert!(is_checksum_file("foo.md5"));
    assert!(is_checksum_file("foo.sha1"));
    assert!(is_checksum_file("foo.sha256"));
    assert!(is_checksum_file("foo.sha512"));
    assert!(!is_checksum_file("foo.jar"));
    assert!(!is_checksum_file("foo.pom"));
}

// ── Version sorting ─────────────────────────────────────────────────

#[test]
fn test_sort_versions_lexicographic() {
    let mut v = vec!["1.0.0".into(), "0.9.0".into(), "1.1.0".into()];
    sort_maven_versions(&mut v);
    assert_eq!(v, vec!["0.9.0", "1.0.0", "1.1.0"]);
}

#[test]
fn test_sort_snapshot_before_release() {
    let mut v = vec!["1.0.0-SNAPSHOT".into(), "1.0.0".into(), "0.9.0".into()];
    sort_maven_versions(&mut v);
    assert_eq!(v, vec!["0.9.0", "1.0.0-SNAPSHOT", "1.0.0"]);
}

#[test]
fn test_sort_numeric_segments() {
    let mut v = vec!["10.0.0".into(), "9.0.0".into(), "2.1.0".into()];
    sort_maven_versions(&mut v);
    assert_eq!(v, vec!["2.1.0", "9.0.0", "10.0.0"]);
}

// ── Metadata XML generation ─────────────────────────────────────────

#[test]
fn test_generate_metadata_xml() {
    let xml = generate_metadata_xml("com.example", "mylib", &["0.9.0".into(), "1.0.0".into()]);
    assert!(xml.contains("<groupId>com.example</groupId>"));
    assert!(xml.contains("<artifactId>mylib</artifactId>"));
    assert!(xml.contains("<latest>1.0.0</latest>"));
    assert!(xml.contains("<release>1.0.0</release>"));
    assert!(xml.contains("<version>0.9.0</version>"));
    assert!(xml.contains("<version>1.0.0</version>"));
    assert!(xml.contains("<lastUpdated>"));
}

#[test]
fn test_generate_metadata_snapshot_only() {
    let xml = generate_metadata_xml("com.example", "mylib", &["1.0.0-SNAPSHOT".into()]);
    assert!(xml.contains("<latest>1.0.0-SNAPSHOT</latest>"));
    assert!(xml.contains("<release></release>"));
}

#[test]
fn test_merge_artifact_metadata_keeps_public_and_hosted_versions() {
    let upstream = br#"<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>com.example</groupId>
  <artifactId>library</artifactId>
  <versioning>
    <latest>2.0.0</latest>
    <release>2.0.0</release>
    <versions>
      <version>1.0.0</version>
      <version>2.0.0</version>
    </versions>
    <lastUpdated>20260728010000</lastUpdated>
  </versioning>
</metadata>
"#;
    let stored = BTreeSet::from(["0.5.0-internal".to_string(), "9.0.0-internal".to_string()]);

    let merged =
        merge_artifact_metadata("com.example", "library", Some(upstream), &stored, None).unwrap();

    assert!(merged.contains("<version>1.0.0</version>"));
    assert!(merged.contains("<version>2.0.0</version>"));
    assert!(merged.contains("<version>0.5.0-internal</version>"));
    assert!(merged.contains("<version>9.0.0-internal</version>"));
    assert!(merged.contains("<latest>9.0.0-internal</latest>"));
    assert!(merged.contains("<release>9.0.0-internal</release>"));
    assert!(merged.contains("<lastUpdated>20260728010000</lastUpdated>"));

    let lower_only = BTreeSet::from(["0.5.0-internal".to_string()]);
    let merged =
        merge_artifact_metadata("com.example", "library", Some(upstream), &lower_only, None)
            .unwrap();
    assert!(merged.contains("<latest>2.0.0</latest>"));
    assert!(merged.contains("<release>2.0.0</release>"));
}

#[test]
fn test_classify_artifact_level_metadata() {
    let xml = br#"
            <metadata xmlns="http://maven.apache.org/METADATA/1.1.0">
              <groupId>com.example</groupId>
              <artifactId>library</artifactId>
              <versioning>
                <versions><version>1.0.0</version></versions>
              </versioning>
            </metadata>
        "#;
    assert_eq!(
        classify_metadata_level(xml),
        Some(MavenMetadataLevel::Artifact)
    );
}

#[test]
fn test_classify_version_level_metadata() {
    let xml = br#"
            <metadata>
              <groupId>com.example</groupId>
              <artifactId>library</artifactId>
              <version>1.0-SNAPSHOT</version>
              <versioning><snapshot><buildNumber>1</buildNumber></snapshot></versioning>
            </metadata>
        "#;
    assert_eq!(
        classify_metadata_level(xml),
        Some(MavenMetadataLevel::Version)
    );
}

#[test]
fn test_classify_group_level_metadata() {
    let xml = br#"
            <metadata>
              <plugins>
                <plugin>
                  <prefix>example</prefix>
                  <artifactId>example-maven-plugin</artifactId>
                </plugin>
              </plugins>
            </metadata>
        "#;
    assert_eq!(
        classify_metadata_level(xml),
        Some(MavenMetadataLevel::Group)
    );
}

#[test]
fn test_reject_malformed_metadata() {
    assert_eq!(classify_metadata_level(b"<metadata>"), None);
    assert_eq!(classify_metadata_level(b"<project/>"), None);
}
