// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::test_helpers::{
    body_bytes, create_test_context, create_test_context_with_config, send, send_with_headers,
};

#[tokio::test]
async fn test_maven_namespace_scope_enforced() {
    use crate::auth::NamespaceAuthority;
    use crate::config::ScopeEnforcement;
    use axum::body::Bytes;
    use axum::extract::{Path, State};
    use axum::http::StatusCode;
    use axum::Extension;

    let ctx = create_test_context();
    let scoped = NamespaceAuthority::from_oidc_scope(
        "ci",
        &["com/myorg/**".to_string()],
        ScopeEnforcement::Enforce,
    );

    // Out of scope (different group) -> 403.
    let resp = super::upload(
        State(ctx.state.clone()),
        Path("com/other/lib/1.0/lib-1.0.jar".to_string()),
        Extension(scoped.clone()),
        None,
        axum::body::Body::from(Bytes::from_static(b"x")),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Opaque (unrecognized) path under a real scope -> fail-closed 403.
    let resp = super::upload(
        State(ctx.state.clone()),
        Path("foo".to_string()),
        Extension(scoped.clone()),
        None,
        axum::body::Body::from(Bytes::from_static(b"x")),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // In scope -> enforcement passes (not 403).
    let resp = super::upload(
        State(ctx.state.clone()),
        Path("com/myorg/lib/1.0/lib-1.0.jar".to_string()),
        Extension(scoped),
        None,
        axum::body::Body::from(Bytes::from_static(b"x")),
    )
    .await;
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
}
use axum::body::Body;
use axum::http::{header, Method, StatusCode};
use sha2::Digest;

#[tokio::test]
async fn test_maven_put_get_roundtrip() {
    let ctx = create_test_context();
    let jar_data = b"fake-jar-content";

    let put = send(
        &ctx.app,
        Method::PUT,
        "/maven2/com/example/mylib/1.0/mylib-1.0.jar",
        Body::from(&jar_data[..]),
    )
    .await;
    assert_eq!(put.status(), StatusCode::CREATED);

    let get = send(
        &ctx.app,
        Method::GET,
        "/maven2/com/example/mylib/1.0/mylib-1.0.jar",
        "",
    )
    .await;
    assert_eq!(get.status(), StatusCode::OK);
    let body = body_bytes(get).await;
    assert_eq!(&body[..], jar_data);
}

/// A cached artifact above `server.stream_threshold_mb` is streamed from storage,
/// not read whole into memory: a wave of CI clients pulling one 125 MB jar
/// OOM-killed the pod at 4Gi (03.11).
#[tokio::test]
async fn test_maven_large_cached_artifact_streams_whole() {
    let ctx = create_test_context_with_config(|cfg| cfg.server.stream_threshold_mb = 1);
    let jar: Vec<u8> = (0..2 * 1024 * 1024 + 17).map(|i| (i % 251) as u8).collect();
    let uri = "/maven2/com/example/big/1.0/big-1.0.jar";
    let put = send(&ctx.app, Method::PUT, uri, Body::from(jar.clone())).await;
    assert_eq!(put.status(), StatusCode::CREATED);

    let get = send(&ctx.app, Method::GET, uri, "").await;
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(
        get.headers()[header::CONTENT_LENGTH],
        jar.len().to_string().as_str()
    );
    assert_eq!(
        get.headers()[header::CONTENT_TYPE],
        "application/java-archive"
    );
    assert_eq!(body_bytes(get).await, jar);
}

#[tokio::test]
async fn test_maven_not_found_no_proxy() {
    let ctx = create_test_context();
    let resp = send(
        &ctx.app,
        Method::GET,
        "/maven2/missing/artifact/1.0/artifact-1.0.jar",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_maven_content_type_pom() {
    let ctx = create_test_context();
    send(
        &ctx.app,
        Method::PUT,
        "/maven2/com/ex/1.0/ex-1.0.pom",
        Body::from("<project/>"),
    )
    .await;

    let get = send(&ctx.app, Method::GET, "/maven2/com/ex/1.0/ex-1.0.pom", "").await;
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(
        get.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/xml"
    );
}

#[tokio::test]
async fn test_maven_content_type_jar() {
    let ctx = create_test_context();
    send(
        &ctx.app,
        Method::PUT,
        "/maven2/org/test/app/2.0/app-2.0.jar",
        Body::from("jar-data"),
    )
    .await;

    let get = send(
        &ctx.app,
        Method::GET,
        "/maven2/org/test/app/2.0/app-2.0.jar",
        "",
    )
    .await;
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(
        get.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/java-archive"
    );
}

// ── Checksums ───────────────────────────────────────────────────────

#[tokio::test]
async fn test_maven_auto_checksums() {
    let ctx = create_test_context();
    let data = b"test-jar-for-checksum";

    send(
        &ctx.app,
        Method::PUT,
        "/maven2/com/example/ck/1.0/ck-1.0.jar",
        Body::from(&data[..]),
    )
    .await;

    // SHA-256
    let resp = send(
        &ctx.app,
        Method::GET,
        "/maven2/com/example/ck/1.0/ck-1.0.jar.sha256",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let hash = body_bytes(resp).await;
    let expected = hex::encode(sha2::Sha256::digest(data));
    assert_eq!(String::from_utf8_lossy(&hash), expected);

    // SHA-1
    let resp = send(
        &ctx.app,
        Method::GET,
        "/maven2/com/example/ck/1.0/ck-1.0.jar.sha1",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // MD5
    let resp = send(
        &ctx.app,
        Method::GET,
        "/maven2/com/example/ck/1.0/ck-1.0.jar.md5",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_maven_checksum_verify_ok() {
    let ctx = create_test_context();
    let data = b"checksum-test-jar";

    send(
        &ctx.app,
        Method::PUT,
        "/maven2/com/example/cv/1.0/cv-1.0.jar",
        Body::from(&data[..]),
    )
    .await;

    let sha1 = hex::encode(sha1::Sha1::digest(data));
    let resp = send(
        &ctx.app,
        Method::PUT,
        "/maven2/com/example/cv/1.0/cv-1.0.jar.sha1",
        Body::from(sha1),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_maven_checksum_verify_mismatch() {
    let ctx = create_test_context();
    let data = b"checksum-mismatch-test";

    send(
        &ctx.app,
        Method::PUT,
        "/maven2/com/example/cm/1.0/cm-1.0.jar",
        Body::from(&data[..]),
    )
    .await;

    let resp = send(
        &ctx.app,
        Method::PUT,
        "/maven2/com/example/cm/1.0/cm-1.0.jar.sha1",
        Body::from("0000000000000000000000000000000000000000"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// R4-R22: a checksum that does not match removes the artifact just stored, so the deploy
/// is retried instead of meeting `immutable_releases`; the digest is compared in either
/// case and without the file name some clients append.
#[tokio::test]
async fn a_checksum_mismatch_rolls_the_fresh_artifact_back() {
    let ctx = create_test_context();
    let jar = "/maven2/com/example/rb/1.0/rb-1.0.jar";
    let app = &ctx.app;
    let put =
        move |path: String, body: Vec<u8>| async move { send(app, Method::PUT, &path, body).await };

    assert_eq!(
        put(jar.into(), b"v1".to_vec()).await.status(),
        StatusCode::CREATED
    );
    let bad = put(format!("{jar}.sha1"), b"0000".to_vec()).await;
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
    let get = send(&ctx.app, Method::GET, jar, "").await;
    assert_eq!(
        get.status(),
        StatusCode::NOT_FOUND,
        "the artifact is removed"
    );
    let sums = ctx.state.storage.list("maven/com/example/rb/1.0/").await;
    assert_eq!(sums.unwrap(), Vec::<String>::new(), "with its checksums");

    // The retry is not a 409, and its checksum is accepted in the forms clients write.
    assert_eq!(
        put(jar.into(), b"v1".to_vec()).await.status(),
        StatusCode::CREATED
    );
    let sha1 = hex::encode(sha1::Sha1::digest(b"v1"));
    for form in [
        sha1.clone(),
        sha1.to_uppercase(),
        format!("{sha1}  rb-1.0.jar\n"),
    ] {
        let ok = put(format!("{jar}.sha1"), form.clone().into_bytes()).await;
        assert_eq!(ok.status(), StatusCode::CREATED, "{form:?}");
    }
    let stored = ctx
        .state
        .storage
        .get("maven/com/example/rb/1.0/rb-1.0.jar.sha1");
    assert_eq!(&stored.await.unwrap()[..], sha1.as_bytes());
}

/// R4-R22: a mismatching checksum for a release that settled long ago removes nothing.
#[tokio::test]
async fn a_checksum_mismatch_keeps_a_settled_artifact() {
    let ctx = create_test_context();
    let key = "maven/com/example/old/1.0/old-1.0.jar";
    crate::test_helpers::put_written_days_ago(&ctx, key, b"v1", 1).await;
    let sha1 = hex::encode(sha1::Sha1::digest(b"v1"));
    let sidecar = format!("{key}.sha1");
    ctx.state
        .storage
        .put(&sidecar, sha1.as_bytes())
        .await
        .unwrap();

    let path = "/maven2/com/example/old/1.0/old-1.0.jar.sha1";
    let bad = send(&ctx.app, Method::PUT, path, "0000").await;
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
    assert!(ctx.state.storage.stat(key).await.is_some());
    assert_eq!(
        &ctx.state.storage.get(&sidecar).await.unwrap()[..],
        sha1.as_bytes()
    );
}

/// R4-C05, a streamed cache hit gated by its digest: an artifact cached for longer than the
/// quarantine ledger remembers (90 days) is not held for a new TTL after a restart.
#[tokio::test]
async fn an_artifact_cached_past_the_ledgers_memory_is_not_held_again() {
    let ctx = crate::test_helpers::create_test_context_with_config(|cfg| {
        // With a proxy the copy is a cached one: hosted-only dates by the file time itself.
        cfg.maven.proxies = vec![crate::config::MavenProxyEntry::Simple(
            "http://127.0.0.1:1".to_string(),
        )];
        cfg.curation.maven.quarantine = Some(crate::digest_quarantine::QuarantineMode::Enforce);
        cfg.curation.maven.quarantine_ttl = Some("7d".to_string());
    });
    let key = "maven/com/example/aged/1.0/aged-1.0.jar";
    crate::test_helpers::put_written_days_ago(&ctx, key, b"jar", 100).await;
    for _ in 0..2 {
        let path = "/maven2/com/example/aged/1.0/aged-1.0.jar";
        let resp = send(&ctx.app, Method::GET, path, "").await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

/// R4-T13: an unreadable stored `maven-metadata.xml` is logged, and the upload still
/// regenerates the document with its version.
#[tokio::test]
async fn an_unreadable_stored_metadata_is_logged_and_regenerated() {
    let (storage, outage) = crate::test_helpers::outage_storage();
    let ctx = crate::test_helpers::create_test_context_with_storage(storage);
    let app = &ctx.app;
    let put = move |v: &'static str| async move {
        let path = format!("/maven2/com/example/um/{v}/um-{v}.jar");
        send(app, Method::PUT, &path, "jar").await
    };
    assert_eq!(put("1.0").await.status(), StatusCode::CREATED);
    outage.fail_reads_of("um/maven-metadata.xml");
    let (logs, _guard) = crate::test_helpers::LogCapture::start();
    assert_eq!(put("2.0").await.status(), StatusCode::CREATED);
    outage.end();
    assert!(
        logs.text().contains("stored metadata unreadable"),
        "{}",
        logs.text()
    );
    let xml = ctx
        .state
        .storage
        .get("maven/com/example/um/maven-metadata.xml");
    let xml = String::from_utf8(xml.await.unwrap().to_vec()).unwrap();
    assert!(xml.contains("<version>1.0</version>") && xml.contains("<version>2.0</version>"));
}

// ── Immutability ────────────────────────────────────────────────────

#[tokio::test]
async fn test_maven_release_immutability() {
    let ctx = create_test_context();

    let r1 = send(
        &ctx.app,
        Method::PUT,
        "/maven2/com/example/imm/1.0.0/imm-1.0.0.jar",
        Body::from("v1"),
    )
    .await;
    assert_eq!(r1.status(), StatusCode::CREATED);

    let r2 = send(
        &ctx.app,
        Method::PUT,
        "/maven2/com/example/imm/1.0.0/imm-1.0.0.jar",
        Body::from("v2"),
    )
    .await;
    assert_eq!(r2.status(), StatusCode::CONFLICT);

    let get = send(
        &ctx.app,
        Method::GET,
        "/maven2/com/example/imm/1.0.0/imm-1.0.0.jar",
        "",
    )
    .await;
    let body = body_bytes(get).await;
    assert_eq!(&body[..], b"v1");
}

#[tokio::test]
async fn test_maven_snapshot_overwrite() {
    let ctx = create_test_context();

    let r1 = send(
        &ctx.app,
        Method::PUT,
        "/maven2/com/example/snap/1.0-SNAPSHOT/snap-1.0-SNAPSHOT.jar",
        Body::from("snapshot-v1"),
    )
    .await;
    assert_eq!(r1.status(), StatusCode::CREATED);

    let r2 = send(
        &ctx.app,
        Method::PUT,
        "/maven2/com/example/snap/1.0-SNAPSHOT/snap-1.0-SNAPSHOT.jar",
        Body::from("snapshot-v2"),
    )
    .await;
    assert_eq!(r2.status(), StatusCode::CREATED);

    let get = send(
        &ctx.app,
        Method::GET,
        "/maven2/com/example/snap/1.0-SNAPSHOT/snap-1.0-SNAPSHOT.jar",
        "",
    )
    .await;
    let body = body_bytes(get).await;
    assert_eq!(&body[..], b"snapshot-v2");
}

// ── Metadata generation ─────────────────────────────────────────────

#[tokio::test]
async fn test_maven_metadata_generated() {
    let ctx = create_test_context();

    send(
        &ctx.app,
        Method::PUT,
        "/maven2/com/example/meta/1.0.0/meta-1.0.0.jar",
        Body::from("v1"),
    )
    .await;

    send(
        &ctx.app,
        Method::PUT,
        "/maven2/com/example/meta/2.0.0/meta-2.0.0.jar",
        Body::from("v2"),
    )
    .await;

    let resp = send(
        &ctx.app,
        Method::GET,
        "/maven2/com/example/meta/maven-metadata.xml",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_bytes(resp).await;
    let xml = String::from_utf8_lossy(&body);
    assert!(xml.contains("<groupId>com.example</groupId>"));
    assert!(xml.contains("<artifactId>meta</artifactId>"));
    assert!(xml.contains("<version>1.0.0</version>"));
    assert!(xml.contains("<version>2.0.0</version>"));
    assert!(xml.contains("<latest>2.0.0</latest>"));
    assert!(xml.contains("<release>2.0.0</release>"));
}

#[tokio::test]
async fn test_maven_metadata_checksums() {
    let ctx = create_test_context();

    send(
        &ctx.app,
        Method::PUT,
        "/maven2/com/example/mck/1.0.0/mck-1.0.0.jar",
        Body::from("data"),
    )
    .await;

    let resp = send(
        &ctx.app,
        Method::GET,
        "/maven2/com/example/mck/maven-metadata.xml.sha256",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let hash = body_bytes(resp).await;
    assert_eq!(hash.len(), 64);
}

/// A cold miss is "not found" only when an upstream said so. When every upstream failed
/// (5xx after the retry, refused connection) the answer is 502: Maven records a 404 as
/// "this artifact does not exist" and stops asking until its update interval or `-U`.
/// One upstream that answers "not found" still decides 404 while another has failed,
/// as a group repository skips a member that is down.
#[tokio::test]
async fn a_cold_miss_is_404_only_when_an_upstream_said_not_found() {
    use crate::config::MavenProxyEntry;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let down = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&down)
        .await;
    let missing = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&missing)
        .await;
    let refused = "http://127.0.0.1:9".to_string();

    for (upstreams, want) in [
        (vec![down.uri()], StatusCode::BAD_GATEWAY),
        (vec![refused.clone()], StatusCode::BAD_GATEWAY),
        (vec![down.uri(), refused.clone()], StatusCode::BAD_GATEWAY),
        (vec![missing.uri()], StatusCode::NOT_FOUND),
        (vec![down.uri(), missing.uri()], StatusCode::NOT_FOUND),
        (vec![missing.uri(), down.uri()], StatusCode::NOT_FOUND),
    ] {
        for path in [
            "/maven2/com/example/lib/1.0.0/lib-1.0.0.jar",
            "/maven2/com/example/lib/maven-metadata.xml",
        ] {
            let entries = upstreams.clone();
            let ctx = create_test_context_with_config(move |config| {
                config.maven.proxies = entries.into_iter().map(MavenProxyEntry::Simple).collect();
            });
            let resp = send(&ctx.app, Method::GET, path, "").await;
            assert_eq!(resp.status(), want, "{path} {upstreams:?}");
        }
    }
    assert!(!down.received_requests().await.unwrap().is_empty());
    assert!(!missing.received_requests().await.unwrap().is_empty());
}

/// Two upstreams for a jar: one has it (`big` bytes), the other answers 404.
async fn has_and_missing(big: &[u8]) -> (wiremock::MockServer, wiremock::MockServer) {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let has = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(big.to_vec()))
        .mount(&has)
        .await;
    let missing = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&missing)
        .await;
    (has, missing)
}

/// A jar over `proxy_max_buffered_mb` is spooled to disk and served whole, and the
/// quarantine still holds it by the spooled body's digest. Buffered whole it was refused,
/// and the next upstream's 404 made it a 404 (awssdk bundle-2.29.52.jar, 641 MB).
#[tokio::test]
async fn an_artifact_over_the_buffer_cap_is_spooled_and_still_quarantined() {
    use crate::config::MavenProxyEntry;
    use crate::digest_quarantine::QuarantineMode;
    let big = vec![7u8; 3 * 1024 * 1024];
    let (has, missing) = has_and_missing(&big).await;
    for (mode, want) in [
        (QuarantineMode::Off, StatusCode::OK),
        (QuarantineMode::Enforce, StatusCode::FORBIDDEN),
    ] {
        let proxies = vec![
            MavenProxyEntry::Simple(has.uri()),
            MavenProxyEntry::Simple(missing.uri()),
        ];
        let ctx = create_test_context_with_config(move |c| {
            c.server.proxy_max_buffered_mb = 1;
            c.server.stream_threshold_mb = 1;
            c.maven.proxies = proxies;
            c.curation.maven.quarantine = Some(mode);
            c.curation.maven.quarantine_ttl = Some("3d".to_string());
        });
        let spool = ctx.state.spool.dir(crate::registry::PROXY_SPOOL_SUBDIR);
        let path = "/maven2/com/example/big/1.0/big-1.0.jar";
        let resp = send(&ctx.app, Method::GET, path, "").await;
        assert_eq!(resp.status(), want);
        if want == StatusCode::OK {
            assert_eq!(&body_bytes(resp).await[..], &big[..]);
        }
        assert!(spool.is_dir(), "the jar went through the spool");
    }
}

/// A body over NORA's own artifact cap is the 507 the cap is, whichever upstream answers
/// 404 and in whatever order: the upstream has the artifact, so it is never "not found".
/// The miss is logged with each upstream's answer.
#[tokio::test]
async fn an_artifact_over_the_cap_is_507_never_404() {
    use crate::config::MavenProxyEntry;
    let (has, missing) = has_and_missing(&vec![7u8; 3 * 1024 * 1024]).await;
    for order in [[&has, &missing], [&missing, &has]] {
        let proxies = order
            .iter()
            .map(|up| MavenProxyEntry::Simple(up.uri()))
            .collect();
        let ctx = create_test_context_with_config(move |c| {
            c.server.proxy_max_artifact_mb = 1;
            c.maven.proxies = proxies;
        });
        let (logs, _guard) = crate::test_helpers::LogCapture::start();
        let path = "/maven2/com/example/big/1.0/big-1.0.jar";
        let resp = send(&ctx.app, Method::GET, path, "").await;
        assert_eq!(resp.status(), StatusCode::INSUFFICIENT_STORAGE);
        let text = logs.text();
        assert!(
            text.lines().any(|line| line.contains(" WARN ")
                && line.contains("proxy miss")
                && line.contains(&format!("{}: Spool(TooLarge", has.uri()))
                && line.contains(&format!("{}: NotFound", missing.uri()))),
            "{text}"
        );
    }
}

#[tokio::test]
async fn test_maven_hosted_proxy_metadata_collision_in_both_orders() {
    use crate::config::MavenProxyEntry;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    let upstream_metadata = r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>com.example</groupId>
  <artifactId>collision</artifactId>
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
    Mock::given(method("GET"))
        .and(path("/com/example/collision/maven-metadata.xml"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(upstream_metadata, "application/xml"))
        .mount(&upstream)
        .await;

    let new_context = || {
        let upstream_url = upstream.uri();
        create_test_context_with_config(move |config| {
            config.maven.proxies = vec![MavenProxyEntry::Simple(upstream_url)];
            config.maven.metadata_ttl = 0;
        })
    };

    let hosted_first = new_context();
    let upload = send(
        &hosted_first.app,
        Method::PUT,
        "/maven2/com/example/collision/9.0.0-internal/collision-9.0.0-internal.jar",
        Body::from("hosted-first"),
    )
    .await;
    assert_eq!(upload.status(), StatusCode::CREATED);

    let response = send(
        &hosted_first.app,
        Method::GET,
        "/maven2/com/example/collision/maven-metadata.xml",
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let metadata = body_bytes(response).await;
    let metadata_text = String::from_utf8_lossy(&metadata);
    assert!(metadata_text.contains("<version>1.0.0</version>"));
    assert!(metadata_text.contains("<version>2.0.0</version>"));
    assert!(metadata_text.contains("<version>9.0.0-internal</version>"));

    let checksum = body_bytes(
        send(
            &hosted_first.app,
            Method::GET,
            "/maven2/com/example/collision/maven-metadata.xml.sha1",
            "",
        )
        .await,
    )
    .await;
    assert_eq!(
        String::from_utf8_lossy(&checksum),
        hex::encode(sha1::Sha1::digest(&metadata))
    );

    let proxy_first = new_context();
    let response = send(
        &proxy_first.app,
        Method::GET,
        "/maven2/com/example/collision/maven-metadata.xml",
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let upload = send(
        &proxy_first.app,
        Method::PUT,
        "/maven2/com/example/collision/9.1.0-internal/collision-9.1.0-internal.jar",
        Body::from("proxy-first"),
    )
    .await;
    assert_eq!(upload.status(), StatusCode::CREATED);

    let response = send(
        &proxy_first.app,
        Method::GET,
        "/maven2/com/example/collision/maven-metadata.xml",
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let metadata = String::from_utf8_lossy(&body_bytes(response).await).into_owned();
    assert!(metadata.contains("<version>1.0.0</version>"));
    assert!(metadata.contains("<version>2.0.0</version>"));
    assert!(metadata.contains("<version>9.1.0-internal</version>"));
}

#[tokio::test]
async fn test_client_artifact_metadata_does_not_overwrite_generated_metadata() {
    let ctx = create_test_context();

    send(
        &ctx.app,
        Method::PUT,
        "/maven2/com/example/race/1.0.0/race-1.0.0.jar",
        Body::from("v1"),
    )
    .await;

    let stale = body_bytes(
        send(
            &ctx.app,
            Method::GET,
            "/maven2/com/example/race/maven-metadata.xml",
            "",
        )
        .await,
    )
    .await;

    send(
        &ctx.app,
        Method::PUT,
        "/maven2/com/example/race/2.0.0/race-2.0.0.jar",
        Body::from("v2"),
    )
    .await;

    let upload = send(
        &ctx.app,
        Method::PUT,
        "/maven2/com/example/race/maven-metadata.xml",
        Body::from(stale),
    )
    .await;
    assert_eq!(upload.status(), StatusCode::CREATED);

    let metadata = body_bytes(
        send(
            &ctx.app,
            Method::GET,
            "/maven2/com/example/race/maven-metadata.xml",
            "",
        )
        .await,
    )
    .await;
    let metadata = String::from_utf8_lossy(&metadata);
    assert!(metadata.contains("<version>1.0.0</version>"));
    assert!(metadata.contains("<version>2.0.0</version>"));
    assert!(metadata.contains("<latest>2.0.0</latest>"));
    assert!(metadata.contains("<release>2.0.0</release>"));
}

#[tokio::test]
async fn test_client_artifact_metadata_checksum_does_not_overwrite_generated_checksum() {
    let ctx = create_test_context();

    send(
        &ctx.app,
        Method::PUT,
        "/maven2/com/example/race-checksum/1.0.0/race-checksum-1.0.0.jar",
        Body::from("v1"),
    )
    .await;
    let stale = body_bytes(
        send(
            &ctx.app,
            Method::GET,
            "/maven2/com/example/race-checksum/maven-metadata.xml.sha256",
            "",
        )
        .await,
    )
    .await;

    send(
        &ctx.app,
        Method::PUT,
        "/maven2/com/example/race-checksum/2.0.0/race-checksum-2.0.0.jar",
        Body::from("v2"),
    )
    .await;
    let expected = body_bytes(
        send(
            &ctx.app,
            Method::GET,
            "/maven2/com/example/race-checksum/maven-metadata.xml.sha256",
            "",
        )
        .await,
    )
    .await;
    assert_ne!(stale, expected);

    let upload = send(
        &ctx.app,
        Method::PUT,
        "/maven2/com/example/race-checksum/maven-metadata.xml.sha256",
        Body::from(stale),
    )
    .await;
    assert_eq!(upload.status(), StatusCode::CREATED);

    let actual = body_bytes(
        send(
            &ctx.app,
            Method::GET,
            "/maven2/com/example/race-checksum/maven-metadata.xml.sha256",
            "",
        )
        .await,
    )
    .await;
    assert_eq!(actual, expected);
}

#[tokio::test]
async fn test_snapshot_version_metadata_and_checksum_are_preserved() {
    let ctx = create_test_context();
    let metadata = r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>com.example</groupId>
  <artifactId>snapshot</artifactId>
  <version>1.0-SNAPSHOT</version>
  <versioning>
    <snapshot><timestamp>20260728.120000</timestamp><buildNumber>1</buildNumber></snapshot>
    <lastUpdated>20260728120000</lastUpdated>
  </versioning>
</metadata>
"#;

    let upload = send(
        &ctx.app,
        Method::PUT,
        "/maven2/com/example/snapshot/1.0-SNAPSHOT/maven-metadata.xml",
        Body::from(metadata),
    )
    .await;
    assert_eq!(upload.status(), StatusCode::CREATED);

    let checksum = hex::encode(sha1::Sha1::digest(metadata.as_bytes()));
    let checksum_upload = send(
        &ctx.app,
        Method::PUT,
        "/maven2/com/example/snapshot/1.0-SNAPSHOT/maven-metadata.xml.sha1",
        Body::from(checksum.clone()),
    )
    .await;
    assert_eq!(checksum_upload.status(), StatusCode::CREATED);

    let stored_metadata = body_bytes(
        send(
            &ctx.app,
            Method::GET,
            "/maven2/com/example/snapshot/1.0-SNAPSHOT/maven-metadata.xml",
            "",
        )
        .await,
    )
    .await;
    assert_eq!(&stored_metadata[..], metadata.as_bytes());

    let stored_checksum = body_bytes(
        send(
            &ctx.app,
            Method::GET,
            "/maven2/com/example/snapshot/1.0-SNAPSHOT/maven-metadata.xml.sha1",
            "",
        )
        .await,
    )
    .await;
    assert_eq!(String::from_utf8_lossy(&stored_checksum), checksum);
}

#[tokio::test]
async fn test_group_plugin_metadata_is_preserved() {
    let ctx = create_test_context();
    let metadata = r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <plugins>
    <plugin>
      <name>Example Maven Plugin</name>
      <prefix>example</prefix>
      <artifactId>example-maven-plugin</artifactId>
    </plugin>
  </plugins>
</metadata>
"#;

    let upload = send(
        &ctx.app,
        Method::PUT,
        "/maven2/org/example/plugins/maven-metadata.xml",
        Body::from(metadata),
    )
    .await;
    assert_eq!(upload.status(), StatusCode::CREATED);

    let stored = body_bytes(
        send(
            &ctx.app,
            Method::GET,
            "/maven2/org/example/plugins/maven-metadata.xml",
            "",
        )
        .await,
    )
    .await;
    assert_eq!(&stored[..], metadata.as_bytes());
}

#[tokio::test]
async fn test_maven_different_versions_different_artifacts() {
    let ctx = create_test_context();

    send(
        &ctx.app,
        Method::PUT,
        "/maven2/com/example/multi/1.0.0/multi-1.0.0.jar",
        Body::from("v1-jar"),
    )
    .await;
    send(
        &ctx.app,
        Method::PUT,
        "/maven2/com/example/multi/1.0.0/multi-1.0.0.pom",
        Body::from("<pom/>"),
    )
    .await;
    send(
        &ctx.app,
        Method::PUT,
        "/maven2/com/example/multi/2.0.0/multi-2.0.0.jar",
        Body::from("v2-jar"),
    )
    .await;

    let r1 = send(
        &ctx.app,
        Method::GET,
        "/maven2/com/example/multi/1.0.0/multi-1.0.0.jar",
        "",
    )
    .await;
    assert_eq!(r1.status(), StatusCode::OK);

    let r2 = send(
        &ctx.app,
        Method::GET,
        "/maven2/com/example/multi/1.0.0/multi-1.0.0.pom",
        "",
    )
    .await;
    assert_eq!(r2.status(), StatusCode::OK);

    let r3 = send(
        &ctx.app,
        Method::GET,
        "/maven2/com/example/multi/2.0.0/multi-2.0.0.jar",
        "",
    )
    .await;
    assert_eq!(r3.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_maven_range_request() {
    let ctx = create_test_context();
    let jar = b"0123456789abcdef";
    ctx.state
        .storage
        .put("maven/com/example/rng/1.0/rng-1.0.jar", jar)
        .await
        .unwrap();
    let url = "/maven2/com/example/rng/1.0/rng-1.0.jar";

    let resp =
        send_with_headers(&ctx.app, Method::GET, url, vec![("range", "bytes=2-5")], "").await;
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        resp.headers()
            .get(header::CONTENT_RANGE)
            .unwrap()
            .to_str()
            .unwrap(),
        format!("bytes 2-5/{}", jar.len())
    );
    assert_eq!(
        resp.headers()
            .get(header::ACCEPT_RANGES)
            .unwrap()
            .to_str()
            .unwrap(),
        "bytes"
    );
    assert_eq!(
        resp.headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap(),
        "application/java-archive"
    );
    assert_eq!(body_bytes(resp).await.as_ref(), &jar[2..=5]);

    // A client that already holds the whole artifact resumes with `bytes=<size>-`.
    let resp = send_with_headers(
        &ctx.app,
        Method::GET,
        url,
        vec![("range", &format!("bytes={}-", jar.len())[..])],
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        resp.headers()
            .get(header::CONTENT_RANGE)
            .unwrap()
            .to_str()
            .unwrap(),
        format!("bytes */{}", jar.len())
    );

    let resp = send(&ctx.app, Method::GET, url, "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(header::ACCEPT_RANGES)
            .unwrap()
            .to_str()
            .unwrap(),
        "bytes"
    );
    assert_eq!(body_bytes(resp).await.as_ref(), &jar[..]);
}

#[tokio::test]
async fn test_maven_range_ignored_on_mutable_path() {
    let ctx = create_test_context();
    let xml = b"<metadata>0123456789</metadata>";
    ctx.state
        .storage
        .put("maven/com/example/rng/maven-metadata.xml", xml)
        .await
        .unwrap();

    let resp = send_with_headers(
        &ctx.app,
        Method::GET,
        "/maven2/com/example/rng/maven-metadata.xml",
        vec![("range", "bytes=2-5")],
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get(header::ACCEPT_RANGES).is_none());
    assert_eq!(body_bytes(resp).await.as_ref(), &xml[..]);
}

/// An upload to `com//acme/...` is refused: written, it would replace the canonical
/// SNAPSHOT's bytes and record their pins under another string, so the canonical read
/// would fail its pin gate and answer 404.
#[tokio::test]
async fn a_snapshot_upload_under_an_empty_segment_never_breaks_the_canonical_read() {
    use axum::http::{Method, StatusCode};
    let ctx = create_test_context();
    let canonical = "/maven2/com/acme/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar";
    let put = send(&ctx.app, Method::PUT, canonical, b"v1".to_vec()).await;
    assert_eq!(put.status(), StatusCode::CREATED);
    let _ = send(
        &ctx.app,
        Method::PUT,
        "/maven2/com//acme/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar",
        b"v2".to_vec(),
    )
    .await;

    let mut broken = Vec::new();
    for path in [canonical.to_string(), format!("{canonical}.sha1")] {
        let resp = send(&ctx.app, Method::GET, &path, "").await;
        if resp.status() != StatusCode::OK {
            broken.push(format!("{path} -> {}", resp.status()));
        }
    }
    assert!(broken.is_empty(), "canonical keys unservable: {broken:?}");
}

/// An upload path with an empty segment, inside or at the end, is refused at the door
/// (400), not turned into a failed write (500).
#[tokio::test]
async fn an_upload_path_with_an_empty_segment_is_refused_with_400() {
    let ctx = crate::test_helpers::create_test_context();
    for uri in [
        "/maven2/com/example//p/1.0/p-1.0.jar",
        "/maven2/com/example/p/1.0/p-1.0.jar/",
    ] {
        let resp = crate::test_helpers::send(
            &ctx.app,
            axum::http::Method::PUT,
            uri,
            axum::body::Body::from("x"),
        )
        .await;
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST, "{uri}");
    }
}

/// A release upload under `com//acme/...` never replaces the existing release.
#[tokio::test]
async fn a_release_upload_under_an_empty_segment_never_overwrites() {
    use axum::http::{Method, StatusCode};
    let ctx = create_test_context();
    let put = send(
        &ctx.app,
        Method::PUT,
        "/maven2/com/acme/lib/1.0/lib-1.0.jar",
        b"v1".to_vec(),
    )
    .await;
    assert_eq!(put.status(), StatusCode::CREATED);
    let alias = send(
        &ctx.app,
        Method::PUT,
        "/maven2/com//acme/lib/1.0/lib-1.0.jar",
        b"v2".to_vec(),
    )
    .await;
    assert!(!alias.status().is_success(), "{}", alias.status());
    let get = send(
        &ctx.app,
        Method::GET,
        "/maven2/com/acme/lib/1.0/lib-1.0.jar",
        "",
    )
    .await;
    assert_eq!(&body_bytes(get).await[..], b"v1");
}

/// Deploys of different versions of one artifact at once serialize on its metadata lock:
/// `maven-metadata.xml`, rebuilt from a listing on every deploy, names every version. The
/// other deploys run while the first is held between its listing and its metadata write.
#[tokio::test(start_paused = true)]
async fn concurrent_deploys_keep_every_version_in_the_metadata() {
    let (storage, ops) = crate::test_helpers::op_counting_storage();
    let ctx = crate::test_helpers::create_test_context_with_storage(storage);
    let deploy = |i: usize| {
        let app = ctx.app.clone();
        async move {
            let uri = format!("/maven2/com/example/race/1.0.{i}/race-1.0.{i}.jar");
            send(&app, Method::PUT, &uri, Body::from(format!("v{i}")))
                .await
                .status()
        }
    };
    let statuses = crate::test_helpers::overtake_held_put(
        &ops,
        "maven/com/example/race/maven-metadata.xml",
        deploy(0),
        (1..16).map(deploy).collect(),
    )
    .await;
    for status in statuses {
        assert_eq!(status, StatusCode::CREATED);
    }
    let resp = send(
        &ctx.app,
        Method::GET,
        "/maven2/com/example/race/maven-metadata.xml",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let xml = String::from_utf8(body_bytes(resp).await.to_vec()).unwrap();
    for i in 0..16 {
        assert!(
            xml.contains(&format!("<version>1.0.{i}</version>")),
            "1.0.{i}: {xml}"
        );
    }
}

/// Deploys of one release version at once: exactly one is stored, the rest are
/// conflicts, and the stored jar and its checksum come from the same deploy.
// lock-audit: concurrent-publish-test
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_deploys_of_one_release_store_it_once() {
    let ctx = create_test_context();
    let uri = "/maven2/com/example/once/1.0.0/once-1.0.0.jar";
    let deploys = (0..8).map(|i| {
        let app = ctx.app.clone();
        tokio::spawn(async move {
            send(&app, Method::PUT, uri, Body::from(format!("deploy-{i}")))
                .await
                .status()
        })
    });
    let mut statuses = Vec::new();
    for d in futures::future::join_all(deploys).await {
        statuses.push(d.unwrap());
    }
    let created = statuses.iter().filter(|s| **s == StatusCode::CREATED);
    assert_eq!(created.count(), 1, "{statuses:?}");
    assert!(
        statuses
            .iter()
            .all(|s| matches!(*s, StatusCode::CREATED | StatusCode::CONFLICT)),
        "{statuses:?}"
    );
    let jar = body_bytes(send(&ctx.app, Method::GET, uri, "").await).await;
    let sum = body_bytes(send(&ctx.app, Method::GET, &format!("{uri}.sha256"), "").await).await;
    assert_eq!(
        String::from_utf8_lossy(&sum).trim(),
        hex::encode(sha2::Sha256::digest(&jar))
    );
}

/// A context whose `[maven]` proxies to `upstream`, with `ru.mindbox.**` internal and
/// `io.delta.**` hosted, uploads outside them refused (A017).
fn hosted_groups_context(
    upstream: &str,
    enforcement: crate::config::HostedGroupsEnforcement,
) -> crate::test_helpers::TestContext {
    let upstream = upstream.to_string();
    create_test_context_with_config(move |c| {
        c.maven.proxies = vec![crate::config::MavenProxyEntry::Simple(upstream)];
        c.maven.hosted_groups = vec!["io.delta.**".to_string()];
        c.maven.hosted_groups_enforcement = enforcement;
        c.curation.internal_namespaces = vec!["ru.mindbox.**".to_string()];
    })
}

/// A017: with a proxy configured, an upload is for a coordinate under
/// `curation.internal_namespaces` or `maven.hosted_groups` only. A Write credential does not
/// seat its own file under a coordinate the upstream serves, so the upstream's stays served.
#[tokio::test]
async fn an_upload_outside_the_hosted_groups_is_refused_and_the_upstream_stays_served() {
    use crate::config::HostedGroupsEnforcement;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/com/example/lib/1.1.0/lib-1.1.0.jar"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"upstream jar".to_vec()))
        .mount(&upstream)
        .await;
    let ctx = hosted_groups_context(&upstream.uri(), HostedGroupsEnforcement::Enforce);
    let refused = || {
        crate::metrics::MAVEN_UNHOSTED_UPLOADS_TOTAL
            .with_label_values(&["refused"])
            .get()
    };
    let before = refused();

    for uri in [
        "/maven2/com/example/lib/1.1.0/lib-1.1.0.jar",
        "/maven2/com/example/lib/2.0.0/lib-2.0.0.jar",
        "/maven2/com/example/lib/1.1.0/lib-1.1.0.jar.sha1",
        "/maven2/com/example/lib/maven-metadata.xml",
        "/maven2/com/example/lib",
    ] {
        let resp = send(&ctx.app, Method::PUT, uri, "planted").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{uri}");
    }
    assert_eq!(refused() - before, 5);
    assert!(ctx
        .state
        .storage
        .list("maven/com/example/")
        .await
        .unwrap()
        .is_empty());
    let get = send(
        &ctx.app,
        Method::GET,
        "/maven2/com/example/lib/1.1.0/lib-1.1.0.jar",
        "",
    )
    .await;
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(&body_bytes(get).await[..], b"upstream jar");

    for uri in [
        "/maven2/ru/mindbox/x/1.0/x-1.0.jar",
        "/maven2/io/delta/delta-spark_2.12/3.2.0-mindbox.1/delta-spark_2.12-3.2.0-mindbox.1.jar",
        "/maven2/io/delta/delta-spark_2.12/maven-metadata.xml",
        // A group's own (plugin list) metadata names the hosted group itself.
        "/maven2/io/delta/maven-metadata.xml",
    ] {
        let resp = send(&ctx.app, Method::PUT, uri, "hosted").await;
        assert_eq!(resp.status(), StatusCode::CREATED, "{uri}");
    }
}

/// Review R38: a SNAPSHOT version's own `maven-metadata.xml` (and its checksums) is the
/// artifact's, so an exact `group:artifact` or a `group:*` hosted pattern admits the whole
/// SNAPSHOT deploy, not only its jar.
#[tokio::test]
async fn a_snapshot_deploy_under_an_exact_or_group_star_hosted_pattern_stores_its_metadata() {
    use crate::config::HostedGroupsEnforcement;
    for pattern in ["com.corp:lib", "com.corp:*"] {
        let ctx = create_test_context_with_config(move |c| {
            c.maven.proxies = vec![crate::config::MavenProxyEntry::Simple(
                "http://127.0.0.1:9".to_string(),
            )];
            c.maven.hosted_groups = vec![pattern.to_string()];
            c.maven.hosted_groups_enforcement = HostedGroupsEnforcement::Enforce;
        });
        for uri in [
            "/maven2/com/corp/lib/1.0-SNAPSHOT/lib-1.0-20261118.120000-1.jar",
            "/maven2/com/corp/lib/1.0-SNAPSHOT/maven-metadata.xml",
            "/maven2/com/corp/lib/1.0-SNAPSHOT/maven-metadata.xml.sha1",
            "/maven2/com/corp/lib/1.0-SNAPSHOT/maven-metadata.xml.md5",
        ] {
            let resp = send(&ctx.app, Method::PUT, uri, "snapshot").await;
            assert_eq!(resp.status(), StatusCode::CREATED, "{pattern} {uri}");
        }
    }
}

/// A017: `hosted_groups_enforcement = "warn"` (the default) stores the upload and reports it,
/// so the groups in use can be listed before `enforce`; a hosted-only registry hosts every
/// coordinate, also under `enforce`.
#[tokio::test]
async fn an_unhosted_upload_is_reported_under_warn_and_any_group_is_hosted_without_proxies() {
    use crate::config::HostedGroupsEnforcement;
    assert_eq!(
        crate::config::MavenConfig::default().hosted_groups_enforcement,
        HostedGroupsEnforcement::Warn
    );
    let ctx = hosted_groups_context("http://127.0.0.1:9", HostedGroupsEnforcement::Warn);
    let warned = || {
        crate::metrics::MAVEN_UNHOSTED_UPLOADS_TOTAL
            .with_label_values(&["warned"])
            .get()
    };
    let before = warned();
    let (logs, _guard) = crate::test_helpers::LogCapture::start();
    let uri = "/maven2/com/example/warned/1.0/warned-1.0.jar";
    let resp = send(&ctx.app, Method::PUT, uri, "jar").await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert!(warned() > before);
    let text = logs.text();
    assert!(
        text.lines().any(|line| line.contains(" WARN ")
            && line.contains("[SECURITY] Maven upload outside")
            && line.contains("com/example/warned")),
        "{text}"
    );

    let hosted_only = create_test_context_with_config(|c| {
        c.maven.proxies = vec![];
        c.maven.hosted_groups_enforcement = HostedGroupsEnforcement::Enforce;
    });
    let resp = send(&hosted_only.app, Method::PUT, uri, "jar").await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

/// A017: a checksum file is the server's own value. The client's is compared with the
/// stored artifact's digest: 404 with no artifact, 400 on a mismatch (the computed digest is
/// what gets stored), 201 on a match. With `checksum_verify = false` it is not compared, and
/// still never stored.
#[tokio::test]
async fn a_checksum_upload_never_stores_the_clients_value() {
    for verify in [true, false] {
        let ctx = create_test_context_with_config(move |c| c.maven.checksum_verify = verify);
        let jar_key = "maven/com/example/sum/1.0/sum-1.0.jar";
        let sidecar = format!("{jar_key}.sha1");
        let uri = "/maven2/com/example/sum/1.0/sum-1.0.jar.sha1";
        let zeros = "0000000000000000000000000000000000000000";

        let resp = send(&ctx.app, Method::PUT, uri, zeros).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "verify={verify}");
        assert!(ctx.state.storage.stat(&sidecar).await.is_none());

        // A file stored without its checksums, as a cache copy can be.
        crate::test_helpers::put_written_days_ago(&ctx, jar_key, b"jar", 1).await;
        let sha1 = hex::encode(sha1::Sha1::digest(b"jar"));
        let want = if verify {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::CREATED
        };
        let resp = send(&ctx.app, Method::PUT, uri, zeros).await;
        assert_eq!(resp.status(), want, "verify={verify}");
        assert!(ctx.state.storage.stat(jar_key).await.is_some());
        let stored = ctx.state.storage.get(&sidecar).await.unwrap();
        assert_eq!(&stored[..], sha1.as_bytes(), "verify={verify}");

        let upper = "/maven2/com/example/sum/1.0/sum-1.0.jar.SHA256";
        let resp = send(&ctx.app, Method::PUT, upper, zeros).await;
        assert_eq!(resp.status(), want, "verify={verify}");
        let stored = ctx.state.storage.get(&format!("{jar_key}.SHA256")).await;
        assert_eq!(
            &stored.unwrap()[..],
            hex::encode(sha2::Sha256::digest(b"jar")).as_bytes()
        );

        let resp = send(&ctx.app, Method::PUT, uri, sha1.clone()).await;
        assert_eq!(resp.status(), StatusCode::CREATED, "verify={verify}");
    }
}

/// A035: a release deploy takes the file's own lock, the one a proxy fill of the same file
/// holds across its stat and spooled write (`ProxyBody::cache`). A fill that found nothing
/// stored finishes before the deploy looks, so the deploy meets `immutable_releases` instead of
/// having its file and pin replaced by the fill's afterwards.
#[tokio::test]
async fn a_release_deploy_waits_for_a_fill_of_the_same_file() {
    let ctx = create_test_context();
    let key = "maven/org/race/widget/2.3.4/widget-2.3.4.jar";
    let uri = "/maven2/org/race/widget/2.3.4/widget-2.3.4.jar";
    let fill_lock = ctx.state.publish_lock(key);
    let fill = fill_lock.lock().await;

    let app = ctx.app.clone();
    let mut deploy =
        tokio::spawn(async move { send(&app, Method::PUT, uri, "hosted jar").await.status() });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(200), &mut deploy)
            .await
            .is_err(),
        "the deploy waits while a fill of its file holds the lock"
    );
    assert!(ctx.state.storage.stat(key).await.is_none());
    ctx.state.storage.put(key, b"upstream jar").await.unwrap();
    drop(fill);

    assert_eq!(deploy.await.unwrap(), StatusCode::CONFLICT);
    let stored = ctx.state.storage.get(key).await.unwrap();
    assert_eq!(&stored[..], b"upstream jar");
}
