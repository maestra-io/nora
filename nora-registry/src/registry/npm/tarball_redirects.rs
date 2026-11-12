// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::config::{NpmConfig, NpmProxyEntry};
use crate::secrets::ProtectedString;
use crate::test_helpers::{body_bytes, create_test_context_with_config, send, TestContext};
use axum::http::{Method, StatusCode};
use wiremock::matchers::{any, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TARBALL: &str = "/pkg/-/pkg-1.0.0.tgz";
const SCOPED: &str = "/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz";

/// 200 to anything, so only its request log tells.
async fn open_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ELSEWHERE".to_vec()))
        .mount(&server)
        .await;
    server
}

fn packument(name: &str, link: &str) -> String {
    serde_json::json!({
        "name": name,
        "dist-tags": { "latest": "1.0.0" },
        "versions": { "1.0.0": {
            "name": name, "version": "1.0.0", "dist": { "tarball": link },
        } },
        "time": { "1.0.0": "2020-01-02T00:00:00.000Z" },
    })
    .to_string()
}

/// A registry at the root of its origin with `pkg` and `@vendor/pkg` 1.0.0, whose tarball
/// paths answer what `answer` makes of the registry.
async fn registry(answer: impl Fn(&MockServer) -> ResponseTemplate) -> MockServer {
    let server = MockServer::start().await;
    for (name, file) in [("pkg", TARBALL), ("@vendor/pkg", SCOPED)] {
        Mock::given(method("GET"))
            .and(path(format!("/{name}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(packument(name, &format!("{}{file}", server.uri()))),
            )
            .mount(&server)
            .await;
        let answer = answer(&server);
        Mock::given(method("GET"))
            .and(path(file))
            .respond_with(answer)
            .mount(&server)
            .await;
    }
    server
}

fn redirect(to: &str) -> ResponseTemplate {
    ResponseTemplate::new(302).insert_header("location", to)
}

fn port_of(server: &MockServer) -> u16 {
    reqwest::Url::parse(&server.uri()).unwrap().port().unwrap()
}

/// The default upstream `public` (its URL may carry userinfo) and `@vendor`'s `private`,
/// with a Bearer token. The upstream's circuit breaker is on, at its default threshold.
fn context(public: &str, private: &str) -> TestContext {
    let mut npm: NpmConfig = toml::from_str(&format!(
        r#"proxies = ["{public}", {{ url = "{private}", scopes = ["@vendor"], auth_bearer_env = "NORA_NPM_VENDOR_TOKEN" }}]"#
    ))
    .unwrap();
    if let NpmProxyEntry::Full(p) = &mut npm.proxies[1] {
        p.auth_bearer = Some(ProtectedString::from("vendor-tok"));
    }
    let proxies = npm.proxies;
    create_test_context_with_config(move |cfg| {
        cfg.npm.proxies = proxies;
        cfg.server.public_url = Some("http://nora.example".to_string());
        cfg.circuit_breaker.enabled = true;
    })
}

fn with_userinfo(server: &MockServer) -> String {
    server
        .uri()
        .replacen("http://", "http://nora-user:s3cret@", 1)
}

async fn get(ctx: &TestContext, uri: &str) -> (StatusCode, Vec<u8>) {
    let resp = send(&ctx.app, Method::GET, uri, "").await;
    let status = resp.status();
    (status, body_bytes(resp).await.to_vec())
}

/// Requests a server received, by path, with whether each carried a credential.
async fn asked(server: &MockServer) -> Vec<(String, bool)> {
    let requests = server.received_requests().await.unwrap();
    requests
        .iter()
        .map(|r| {
            (
                r.url.path().to_string(),
                r.headers.contains_key("authorization"),
            )
        })
        .collect()
}

async fn asks_of(server: &MockServer, file: &str) -> usize {
    asked(server)
        .await
        .iter()
        .filter(|(p, _)| p == file)
        .count()
}

/// Tarballs and their digests NORA keeps.
async fn cached_tarballs(ctx: &TestContext) -> Vec<String> {
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let keys = ctx.state.storage.list("npm/").await.unwrap();
    keys.into_iter().filter(|k| k.contains(".tgz")).collect()
}

/// The tarballs cached once the background write lands, within a deadline: a full test run
/// can delay the spawned write past any fixed wait.
async fn cached_tarballs_eventually(ctx: &TestContext) -> Vec<String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let cached = cached_tarballs(ctx).await;
        if !cached.is_empty() || std::time::Instant::now() > deadline {
            return cached;
        }
    }
}

/// A file storage on another origin: `/a` forwards to `/b` on the same host, which answers.
async fn storage_host() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/a"))
        .respond_with(redirect(&format!("{}/b", server.uri())))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/b"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"STORED-TGZ".to_vec()))
        .mount(&server)
        .await;
    server
}

/// A listed version whose upstream keeps the file on a storage host: downloaded from there,
/// and no hop on the storage host — the first or the one after — gets the upstream's
/// credential, the userinfo of the default upstream or the scope's token alike.
#[tokio::test]
async fn a_listed_tarball_on_another_origin_is_fetched_without_the_credential() {
    for (uri, file) in [
        ("/npm/pkg/-/pkg-1.0.0.tgz", TARBALL),
        ("/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz", SCOPED),
    ] {
        let storage = storage_host().await;
        let to = format!("{}/a", storage.uri());
        let upstream = registry(|_| redirect(&to)).await;
        let ctx = context(&with_userinfo(&upstream), &upstream.uri());
        let (status, body) = get(&ctx, uri).await;
        assert_eq!(
            (status, String::from_utf8_lossy(&body).into_owned()),
            (StatusCode::OK, "STORED-TGZ".to_string()),
            "{uri}"
        );
        let tarball_asks: Vec<_> = asked(&upstream)
            .await
            .into_iter()
            .filter(|(p, _)| p == file)
            .collect();
        assert_eq!(tarball_asks, vec![(file.to_string(), true)], "{uri}");
        assert_eq!(
            asked(&storage).await,
            vec![("/a".to_string(), false), ("/b".to_string(), false)],
            "{uri}"
        );
        assert!(!cached_tarballs_eventually(&ctx).await.is_empty(), "{uri}");
    }
}

/// The same host on another port, or the same port under another scheme, is another origin:
/// the credential stays behind there too.
#[tokio::test]
async fn another_host_or_port_is_another_origin_for_the_credential() {
    let storage = storage_host().await;
    let port = port_of(&storage);
    for to in [
        format!("http://localhost:{port}/a"),
        format!("http://127.0.0.1:{port}/a"),
    ] {
        let upstream = registry(|_| redirect(&to)).await;
        let ctx = context(&with_userinfo(&upstream), &upstream.uri());
        let (status, _) = get(&ctx, "/npm/pkg/-/pkg-1.0.0.tgz").await;
        assert_eq!(status, StatusCode::OK, "{to}");
    }
    assert!(
        asked(&storage)
            .await
            .iter()
            .all(|(_, credential)| !credential),
        "{:?}",
        asked(&storage).await
    );
}

/// On the upstream's own origin the credential goes along, relative Location or absolute.
#[tokio::test]
async fn a_redirect_on_the_same_origin_keeps_the_credential() {
    for to in [
        "/files/pkg-1.0.0.tgz".to_string(),
        "http://127.0.0.1:{port}/files/pkg-1.0.0.tgz".to_string(),
    ] {
        let upstream =
            registry(|server| redirect(&to.replace("{port}", &port_of(server).to_string()))).await;
        Mock::given(method("GET"))
            .and(path("/files/pkg-1.0.0.tgz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"UPSTREAM-TGZ".to_vec()))
            .mount(&upstream)
            .await;
        let ctx = context(&with_userinfo(&upstream), &open_server().await.uri());
        let (status, body) = get(&ctx, "/npm/pkg/-/pkg-1.0.0.tgz").await;
        assert_eq!(
            (status, body.as_slice()),
            (StatusCode::OK, b"UPSTREAM-TGZ".as_slice()),
            "{to}"
        );
        let hop: Vec<_> = asked(&upstream)
            .await
            .into_iter()
            .filter(|(p, _)| p == "/files/pkg-1.0.0.tgz")
            .collect();
        assert_eq!(
            hop,
            vec![("/files/pkg-1.0.0.tgz".to_string(), true)],
            "{to}"
        );
    }
}

/// A walk on the origin is cut off after ten hops, as any chain of a download is.
#[tokio::test]
async fn a_walk_on_the_origin_ends() {
    let upstream = registry(|_| redirect(TARBALL)).await;
    let ctx = context(&upstream.uri(), &open_server().await.uri());
    let (status, _) = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        get(&ctx, "/npm/pkg/-/pkg-1.0.0.tgz"),
    )
    .await
    .expect("a redirect loop never ends");
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(asks_of(&upstream, TARBALL).await <= 2 * 11);
}

/// A version the packument does not list is not asked for, wherever its path would lead —
/// GitLab forwards it to the public registry (302, measured on 19.5): 404, the packument
/// asked once more for a version published since, nothing cached. The breaker sees no
/// failure, however often it is asked.
#[tokio::test]
async fn a_version_the_packument_does_not_list_is_not_asked_for() {
    let public = open_server().await;
    let gitlab =
        registry(|_| ResponseTemplate::new(200).set_body_bytes(b"GITLAB-TGZ".to_vec())).await;
    Mock::given(any())
        .respond_with(redirect(&format!("{}/forwarded", public.uri())))
        .mount(&gitlab)
        .await;
    let ctx = context(&public.uri(), &gitlab.uri());
    let downloads = crate::config::CircuitBreakerConfig::default().failure_threshold + 1;
    for _ in 0..downloads {
        let (status, _) = get(&ctx, "/npm/@vendor/pkg/-/@vendor/pkg-9.9.9.tgz").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
    let gitlab_asks = asked(&gitlab).await;
    assert!(
        gitlab_asks.iter().all(|(p, _)| p == "/@vendor/pkg"),
        "{gitlab_asks:?}"
    );
    assert!(
        gitlab_asks.len() <= 2 * downloads as usize,
        "{gitlab_asks:?}"
    );
    assert!(
        asked(&public).await.is_empty(),
        "{:?}",
        asked(&public).await
    );
    assert!(cached_tarballs(&ctx).await.is_empty());
    // The breaker is closed: the listed version still downloads.
    let (status, _) = get(&ctx, "/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz").await;
    assert_eq!(status, StatusCode::OK);
}

/// A version published after the packument was cached is found in the packument fetched
/// again, once.
#[tokio::test]
async fn a_version_published_since_the_packument_was_cached_is_found() {
    let upstream = MockServer::start().await;
    let link = |v: &str| format!("{}/pkg/-/pkg-{v}.tgz", upstream.uri());
    Mock::given(method("GET"))
        .and(path("/pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_string(packument("pkg", &link("1.0.0"))))
        .up_to_n_times(1)
        .mount(&upstream)
        .await;
    let later = serde_json::json!({
        "name": "pkg",
        "dist-tags": { "latest": "1.1.0" },
        "versions": {
            "1.0.0": { "name": "pkg", "version": "1.0.0", "dist": { "tarball": link("1.0.0") } },
            "1.1.0": { "name": "pkg", "version": "1.1.0", "dist": { "tarball": link("1.1.0") } },
        },
        "time": { "1.0.0": "2020-01-02T00:00:00.000Z", "1.1.0": "2020-02-02T00:00:00.000Z" },
    });
    Mock::given(method("GET"))
        .and(path("/pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_string(later.to_string()))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/pkg/-/pkg-1.1.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"NEW-TGZ".to_vec()))
        .mount(&upstream)
        .await;
    let ctx = context(&upstream.uri(), &open_server().await.uri());
    let holders = ctx.state.storage.holders();
    let (status, _) = get(&ctx, "/npm/pkg").await;
    assert_eq!(status, StatusCode::OK);
    crate::test_helpers::background_writes_done(&ctx.state.storage, holders).await;
    let (status, body) = get(&ctx, "/npm/pkg/-/pkg-1.1.0.tgz").await;
    assert_eq!(
        (status, body.as_slice()),
        (StatusCode::OK, b"NEW-TGZ".as_slice())
    );
    let packument_asks = asked(&upstream)
        .await
        .iter()
        .filter(|(p, _)| p == "/pkg")
        .count();
    assert_eq!(packument_asks, 2);
}

/// GitHub Packages' tarball path (`download/<@scope/name>/<version>/<sha1>`), listed and
/// forwarded to a storage host: downloaded from there without the scope's token.
#[tokio::test]
async fn a_github_packages_tarball_on_a_storage_host_is_fetched_without_the_token() {
    const SHA: &str = "04fef883382f5a7c9b9ac2015dcc419009e2a858";
    let storage = storage_host().await;
    let ghp = MockServer::start().await;
    let file = format!("/download/@vendor/pkg/1.0.0/{SHA}");
    Mock::given(method("GET"))
        .and(path("/@vendor/pkg"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(packument("@vendor/pkg", &format!("{}{file}", ghp.uri()))),
        )
        .mount(&ghp)
        .await;
    Mock::given(method("GET"))
        .and(path(file.as_str()))
        .respond_with(redirect(&format!("{}/a", storage.uri())))
        .mount(&ghp)
        .await;
    let ctx = context(&open_server().await.uri(), &ghp.uri());
    let (status, body) = get(&ctx, &format!("/npm{file}")).await;
    assert_eq!(
        (status, String::from_utf8_lossy(&body).into_owned()),
        (StatusCode::OK, "STORED-TGZ".to_string())
    );
    assert_eq!(
        asked(&storage).await,
        vec![("/a".to_string(), false), ("/b".to_string(), false)]
    );
    let tarball_asks: Vec<_> = asked(&ghp)
        .await
        .into_iter()
        .filter(|(p, _)| *p == file)
        .collect();
    assert_eq!(tarball_asks, vec![(file.clone(), true)]);
}

/// Invariant 2: the whole redirect chain of a tarball download is bounded (≤10 hops) → 502.
/// 8 hops on the upstream's origin, one to a storage host, 8 more there: 17 hops in all.
#[tokio::test]
async fn a_chain_longer_than_ten_hops_across_origins_is_502() {
    let storage = MockServer::start().await;
    for i in 0..8 {
        Mock::given(method("GET"))
            .and(path(format!("/h{i}")))
            .respond_with(redirect(&format!("{}/h{}", storage.uri(), i + 1)))
            .mount(&storage)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/h8"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"FAR-TGZ".to_vec()))
        .mount(&storage)
        .await;
    let s = storage.uri();
    let upstream = registry(|_| redirect("/r1")).await;
    for i in 1..8 {
        Mock::given(method("GET"))
            .and(path(format!("/r{i}")))
            .respond_with(redirect(&format!("/r{}", i + 1)))
            .mount(&upstream)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/r8"))
        .respond_with(redirect(&format!("{s}/h0")))
        .mount(&upstream)
        .await;
    let ctx = context(&upstream.uri(), &open_server().await.uri());
    let (status, body) = get(&ctx, "/npm/pkg/-/pkg-1.0.0.tgz").await;
    assert_eq!(
        (status, String::from_utf8_lossy(&body).into_owned()),
        (StatusCode::BAD_GATEWAY, String::new()),
        "17 redirects were followed"
    );
}

/// Invariant 2: the hops on the storage host count too — a chain that goes on there past ten
/// hops ends in 502, it is not walked to its end.
#[tokio::test]
async fn a_walk_on_the_storage_host_ends() {
    let storage = MockServer::start().await;
    for i in 0..30 {
        Mock::given(method("GET"))
            .and(path(format!("/h{i}")))
            .respond_with(redirect(&format!("{}/h{}", storage.uri(), i + 1)))
            .mount(&storage)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/h30"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"FAR-TGZ".to_vec()))
        .mount(&storage)
        .await;
    let to = format!("{}/h0", storage.uri());
    let upstream = registry(|_| redirect(&to)).await;
    let ctx = context(&upstream.uri(), &open_server().await.uri());
    let (status, _) = get(&ctx, "/npm/pkg/-/pkg-1.0.0.tgz").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
}

/// A download whose first `on` redirects stay on the upstream's origin (`/r1`…) and whose
/// next `off` go to a storage host (`/h1`…), the last URL answering the file: what NORA
/// answers, with the requests each server received.
async fn walk(on: usize, off: usize) -> (StatusCode, Vec<(String, bool)>, Vec<(String, bool)>) {
    let storage = MockServer::start().await;
    let s = storage.uri();
    let first = match (on, off) {
        (0, 0) => ResponseTemplate::new(200).set_body_bytes(b"TGZ".to_vec()),
        (0, _) => redirect(&format!("{s}/h1")),
        _ => redirect("/r1"),
    };
    let upstream = registry(|_| first.clone()).await;
    for i in 1..=on {
        let answer = if i < on {
            redirect(&format!("/r{}", i + 1))
        } else if off > 0 {
            redirect(&format!("{s}/h1"))
        } else {
            ResponseTemplate::new(200).set_body_bytes(b"TGZ".to_vec())
        };
        Mock::given(method("GET"))
            .and(path(format!("/r{i}")))
            .respond_with(answer)
            .mount(&upstream)
            .await;
    }
    for j in 1..=off {
        let answer = if j < off {
            redirect(&format!("{s}/h{}", j + 1))
        } else {
            ResponseTemplate::new(200).set_body_bytes(b"TGZ".to_vec())
        };
        Mock::given(method("GET"))
            .and(path(format!("/h{j}")))
            .respond_with(answer)
            .mount(&storage)
            .await;
    }
    let ctx = context(&with_userinfo(&upstream), &open_server().await.uri());
    let (status, _) = get(&ctx, "/npm/pkg/-/pkg-1.0.0.tgz").await;
    (status, asked(&upstream).await, asked(&storage).await)
}

/// Invariant 2: ten redirects of one download pass and the eleventh is 502, however the
/// chain is split between the upstream's origin and a storage host; the credential goes on
/// each hop on the origin and on none on the storage host.
#[tokio::test]
async fn ten_redirects_pass_and_the_eleventh_is_502_across_origins() {
    for (on, off, expected) in [
        (10, 0, StatusCode::OK),
        (11, 0, StatusCode::BAD_GATEWAY),
        (0, 10, StatusCode::OK),
        (0, 11, StatusCode::BAD_GATEWAY),
        (4, 6, StatusCode::OK),
        (4, 7, StatusCode::BAD_GATEWAY),
        (9, 1, StatusCode::OK),
        (10, 1, StatusCode::BAD_GATEWAY),
    ] {
        let (status, upstream, storage) = walk(on, off).await;
        assert_eq!(status, expected, "{on} on the origin, {off} off it");
        let hops: Vec<_> = upstream
            .iter()
            .filter(|(p, _)| p.starts_with("/r"))
            .collect();
        assert!(hops.iter().all(|(_, credential)| *credential), "{hops:?}");
        assert!(
            storage.iter().all(|(_, credential)| !credential),
            "{storage:?}"
        );
        if expected == StatusCode::BAD_GATEWAY {
            // The eleventh redirect is not followed.
            assert_eq!(
                hops.len() + storage.len(),
                10,
                "{on} {off}: {upstream:?} {storage:?}"
            );
        }
    }
}

/// A chain that leaves the upstream's origin and comes back to it goes on without the
/// credential: the hop back is asked on behalf of the storage host's answer.
#[tokio::test]
async fn a_hop_back_to_the_origin_goes_without_the_credential() {
    for (uri, file) in [
        ("/npm/pkg/-/pkg-1.0.0.tgz", TARBALL),
        ("/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz", SCOPED),
    ] {
        let storage = MockServer::start().await;
        let upstream = registry(|_| redirect(&format!("{}/a", storage.uri()))).await;
        Mock::given(method("GET"))
            .and(path("/a"))
            .respond_with(redirect(&format!("{}/back", upstream.uri())))
            .mount(&storage)
            .await;
        Mock::given(method("GET"))
            .and(path("/back"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"BACK-TGZ".to_vec()))
            .mount(&upstream)
            .await;
        let ctx = context(&with_userinfo(&upstream), &upstream.uri());
        let (status, body) = get(&ctx, uri).await;
        assert_eq!(
            (status, body.as_slice()),
            (StatusCode::OK, b"BACK-TGZ".as_slice()),
            "{uri}"
        );
        let hops: Vec<_> = asked(&upstream)
            .await
            .into_iter()
            .filter(|(p, _)| p == file || p == "/back")
            .collect();
        assert_eq!(
            hops,
            vec![(file.to_string(), true), ("/back".to_string(), false)],
            "{uri}"
        );
    }
}

/// An upstream that has no packument for the package lists no version of it: the tarball
/// is not asked for, 404, nothing cached.
#[tokio::test]
async fn a_package_without_a_packument_upstream_is_not_asked_for_a_tarball() {
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/pkg/-/pkg-1.0.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"UNLISTED".to_vec()))
        .mount(&upstream)
        .await;
    let ctx = context(&upstream.uri(), &open_server().await.uri());
    let (status, _) = get(&ctx, "/npm/pkg/-/pkg-1.0.0.tgz").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(asks_of(&upstream, "/pkg/-/pkg-1.0.0.tgz").await, 0);
    assert!(cached_tarballs(&ctx).await.is_empty());
}
