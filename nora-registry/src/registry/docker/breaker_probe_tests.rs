// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

//! Every exit of a Docker upstream fetch that took a circuit-breaker probe reports
//! it back, so a half-open breaker never waits out the #585 stall recovery behind a
//! probe nobody returned. A refused token is the registry answering (alive), and a
//! failed local spool write says nothing against the upstream (alive, not a failure).
use super::{
    fetch_blob_from_upstream, fetch_manifest_from_upstream, open_blob_from_upstream,
    spool_upstream_blob, SpoolFile, SpoolStatus,
};
use crate::circuit_breaker::{upstream_key, CircuitBreakerRegistry, ProbeToken};
use crate::config::CircuitBreakerConfig;
use crate::registry::docker_auth::DockerAuth;
use crate::registry::TempFileGuard;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const NAME: &str = "library/alpine";
const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// A breaker whose next `check` for `upstream` is the half-open probe. Reset is 1 h,
/// so the #585 stall recovery cannot hand the slot back during a test.
fn half_open_cb(upstream: &str) -> (CircuitBreakerRegistry, String) {
    let cb = CircuitBreakerRegistry::new(CircuitBreakerConfig {
        enabled: true,
        failure_threshold: 1,
        reset_timeout: 3600,
        overrides: std::collections::HashMap::new(),
    });
    let key = upstream_key("docker", upstream);
    cb.record_failure(&key, ProbeToken::BACKGROUND);
    cb.expire_open_for_test(&key);
    (cb, key)
}

fn status(cb: &CircuitBreakerRegistry, key: &str) -> &'static str {
    let snapshot = cb.health_snapshot("docker").unwrap();
    assert!(cb.keys().iter().any(|k| k == key));
    snapshot.status
}

/// An upstream whose blob and manifest endpoints answer 401 with a bearer challenge,
/// and whose token endpoint fails: the token server gives no token.
async fn upstream_without_token() -> wiremock::MockServer {
    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let server = MockServer::start().await;
    let challenge = format!("Bearer realm=\"{}/token\",service=\"test\"", server.uri());
    Mock::given(method("GET"))
        .and(path_regex(r"^/v2/.*/(blobs|manifests)/"))
        .respond_with(ResponseTemplate::new(401).insert_header("www-authenticate", challenge))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn blob_open_without_token_returns_the_probe_as_alive() {
    let server = upstream_without_token().await;
    let (cb, key) = half_open_cb(&server.uri());
    let auth = DockerAuth::default();
    let opened = open_blob_from_upstream(
        &reqwest::Client::new(),
        &server.uri(),
        NAME,
        DIGEST,
        &auth,
        5,
        None,
        &cb,
    )
    .await;
    assert!(opened.is_err(), "no token, no blob");
    assert_eq!(
        status(&cb, &key),
        "closed",
        "the registry answered (401): the probe proves it alive"
    );
}

#[tokio::test]
async fn manifest_without_token_returns_the_probe_as_alive() {
    let server = upstream_without_token().await;
    let (cb, key) = half_open_cb(&server.uri());
    let auth = DockerAuth::default();
    let fetched = fetch_manifest_from_upstream(
        &reqwest::Client::new(),
        &server.uri(),
        NAME,
        "latest",
        &auth,
        5,
        None,
        &cb,
    )
    .await;
    assert!(fetched.is_err(), "no token, no manifest");
    assert_eq!(
        status(&cb, &key),
        "closed",
        "the registry answered (401): the probe proves it alive"
    );
}

/// Open the blob as the half-open probe against an upstream that sends `pieces` (a
/// pause before each), then spool it into a handle that cannot be written (opened
/// read-only), so the local write fails while the upstream is healthy.
async fn spool_into_unwritable(
    pieces: &[&[u8]],
    progress: bool,
) -> (CircuitBreakerRegistry, String) {
    let total: usize = pieces.iter().map(|p| p.len()).sum();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = format!("http://{}", listener.local_addr().unwrap());
    let (cb, key) = half_open_cb(&upstream);
    let serve_once = async {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut req = [0u8; 4096];
        let _ = sock.read(&mut req).await;
        let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {total}\r\n\r\n");
        let _ = sock.write_all(head.as_bytes()).await;
        for piece in pieces {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = sock.write_all(piece).await;
            let _ = sock.flush().await;
        }
        // Hold the connection until the client is done with it.
        let _ = sock.read(&mut req).await;
    };
    let fill = async {
        let auth = DockerAuth::default();
        let blob = open_blob_from_upstream(
            &reqwest::Client::new(),
            &upstream,
            NAME,
            DIGEST,
            &auth,
            5,
            None,
            &cb,
        )
        .await
        .unwrap();
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("spool");
        std::fs::write(&path, b"").unwrap();
        let spool = SpoolFile {
            path: path.clone(),
            file: tokio::fs::File::open(&path).await.unwrap(),
            guard: TempFileGuard::new(path),
        };
        let (tx, _rx) = tokio::sync::watch::channel(SpoolStatus::default());
        let outcome = spool_upstream_blob(blob, spool, 5, &cb, progress.then_some(&tx)).await;
        assert!(outcome.is_err(), "the spool write must fail");
    };
    tokio::join!(serve_once, fill);
    (cb, key)
}

#[tokio::test]
async fn spool_write_error_returns_the_probe_as_alive() {
    let (cb, key) = spool_into_unwritable(&[b"first-chunk", b"second-chunk"], false).await;
    assert_eq!(
        status(&cb, &key),
        "closed",
        "a failed local write is not the upstream's failure"
    );
}

#[tokio::test]
async fn spool_progress_flush_error_returns_the_probe_as_alive() {
    let (cb, key) = spool_into_unwritable(&[b"only-chunk"], true).await;
    assert_eq!(
        status(&cb, &key),
        "closed",
        "a failed local flush is not the upstream's failure"
    );
}

#[tokio::test]
async fn spool_final_flush_error_returns_the_probe_as_alive() {
    let (cb, key) = spool_into_unwritable(&[b"only-chunk"], false).await;
    assert_eq!(
        status(&cb, &key),
        "closed",
        "a failed local flush is not the upstream's failure"
    );
}

/// The spool file is local: when it cannot be created, no probe may have been taken
/// yet and the upstream is not asked at all.
#[tokio::test]
async fn fetch_blob_without_a_spool_takes_no_probe() {
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"blob".to_vec()))
        .expect(0)
        .mount(&server)
        .await;
    let (cb, key) = half_open_cb(&server.uri());
    let missing = tempfile::TempDir::new().unwrap().path().join("no-such-dir");
    let auth = DockerAuth::default();
    let fetched = fetch_blob_from_upstream(
        &reqwest::Client::new(),
        &server.uri(),
        NAME,
        DIGEST,
        &auth,
        5,
        5,
        None,
        &cb,
        &missing,
    )
    .await;
    assert!(fetched.is_err(), "no spool, no fetch");
    assert!(
        cb.check(&key).is_ok(),
        "no probe may be held: the next request must be allowed to probe"
    );
}
