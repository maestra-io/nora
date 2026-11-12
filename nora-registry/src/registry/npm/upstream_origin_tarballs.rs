// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::rewrite_tarball_urls;
use crate::config::{NpmConfig, NpmProxyEntry};
use crate::secrets::ProtectedString;
use crate::test_helpers::{body_bytes, create_test_context_with_config, send, TestContext};
use axum::http::{Method, StatusCode};
use wiremock::matchers::{any, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "vendor-tok";
const NORA: &str = "http://nora.example";
const NAME: &str = "@vendor/pkg";
const PROJECT: &str = "/api/v4/projects/7/packages/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz";
const ON_NORA: &str = "http://nora.example/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz";

fn instance(gitlab: &MockServer) -> String {
    format!("{}/api/v4/packages/npm", gitlab.uri())
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

const VERSIONS: &[&str] = &["1.0.0", "1.1.0", "1.2.0", "1.3.0"];

/// Where the project keeps the tarball of `version`.
fn project(version: &str) -> String {
    format!("/api/v4/projects/7/packages/npm/@vendor/pkg/-/@vendor/pkg-{version}.tgz")
}

/// What the project's tarball of `version` holds.
fn tgz(version: &str) -> Vec<u8> {
    match version {
        "1.0.0" => b"GITLAB-TGZ".to_vec(),
        other => format!("GITLAB-TGZ {other}").into_bytes(),
    }
}

fn packument_of(name: &str, links: &[(&str, String)]) -> String {
    let versions: serde_json::Map<String, serde_json::Value> = links
        .iter()
        .map(|(v, link)| {
            let doc = serde_json::json!({
                "name": name, "version": v, "dist": { "tarball": link },
            });
            (v.to_string(), doc)
        })
        .collect();
    let time: serde_json::Map<String, serde_json::Value> = links
        .iter()
        .map(|(v, _)| (v.to_string(), "2020-01-02T00:00:00.000Z".into()))
        .collect();
    serde_json::json!({
        "name": name,
        "dist-tags": { "latest": links.last().map(|(v, _)| *v) },
        "versions": versions,
        "time": time,
    })
    .to_string()
}

/// A GitLab instance-level endpoint for `@vendor`, answering only with the token: the
/// packument and version manifests (naming each tarball on the origin `origin` gives) at the
/// instance level, the tarballs under the project.
async fn gitlab(origin: impl FnOnce(&MockServer) -> String) -> MockServer {
    let gitlab = MockServer::start().await;
    let origin = origin(&gitlab);
    let links: Vec<(&str, String)> = VERSIONS
        .iter()
        .map(|v| (*v, format!("{origin}{}", project(v))))
        .collect();
    Mock::given(method("GET"))
        .and(path("/api/v4/packages/npm/@vendor/pkg"))
        .and(header("authorization", "Bearer vendor-tok"))
        .respond_with(ResponseTemplate::new(200).set_body_string(packument_of(NAME, &links)))
        .mount(&gitlab)
        .await;
    for (version, link) in &links {
        let manifest = serde_json::json!({
            "name": NAME, "version": version, "dist": { "tarball": link },
        });
        Mock::given(method("GET"))
            .and(path(format!("/api/v4/packages/npm/@vendor/pkg/{version}")))
            .and(header("authorization", "Bearer vendor-tok"))
            .respond_with(ResponseTemplate::new(200).set_body_string(manifest.to_string()))
            .mount(&gitlab)
            .await;
        Mock::given(method("GET"))
            .and(path(project(version)))
            .and(header("authorization", "Bearer vendor-tok"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tgz(version)))
            .mount(&gitlab)
            .await;
    }
    gitlab
}

/// 200 to anything, so only its request log tells.
async fn open_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ELSEWHERE".to_vec()))
        .mount(&server)
        .await;
    server
}

fn context(public: &str, private: &str) -> TestContext {
    context_with_ttl(public, private, 3600)
}

fn context_with_ttl(public: &str, private: &str, ttl: i64) -> TestContext {
    context_with(public, private, ttl, true)
}

/// `trust`: whether upstream release dates are trusted — then a tarball download caches its
/// packument first, for the date.
fn context_with(public: &str, private: &str, ttl: i64, trust: bool) -> TestContext {
    let mut npm: NpmConfig = toml::from_str(&format!(
        r#"proxies = ["{public}", {{ url = "{private}", scopes = ["@vendor"], auth_bearer_env = "NORA_NPM_VENDOR_TOKEN" }}]"#
    ))
    .unwrap();
    if let NpmProxyEntry::Full(p) = &mut npm.proxies[1] {
        p.auth_bearer = Some(ProtectedString::from(TOKEN));
    }
    let proxies = npm.proxies;
    create_test_context_with_config(move |cfg| {
        cfg.npm.proxies = proxies;
        cfg.npm.metadata_ttl = ttl;
        cfg.server.trust_upstream_dates = trust;
        cfg.server.public_url = Some(NORA.to_string());
    })
}

async fn get(ctx: &TestContext, uri: &str) -> (StatusCode, Vec<u8>) {
    let resp = send(&ctx.app, Method::GET, uri, "").await;
    let status = resp.status();
    (status, body_bytes(resp).await.to_vec())
}

async fn versions(ctx: &TestContext) -> serde_json::Value {
    let (status, body) = get(ctx, "/npm/@vendor%2fpkg").await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    doc["versions"].clone()
}

/// Requests a server received, by path, with whether each carried a credential.
async fn log(server: &MockServer) -> Vec<(String, bool)> {
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

async fn settle() {
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

/// Each version's tarball from its own link, whether the packument served was fetched first
/// or fetched again (an expired copy).
#[tokio::test]
async fn a_tarball_on_the_upstream_origin_is_fetched_from_its_own_link() {
    for ttl in [3600, 0] {
        let public = open_server().await;
        let gitlab = gitlab(MockServer::uri).await;
        let ctx = context_with_ttl(&public.uri(), &instance(&gitlab), ttl);
        for _ in 0..2 {
            let versions = versions(&ctx).await;
            assert_eq!(
                versions["1.0.0"]["dist"]["tarball"], ON_NORA,
                "{ttl}: {versions}"
            );
            settle().await;
        }
        let (status, manifest) = get(&ctx, "/npm/@vendor%2fpkg/1.0.0").await;
        assert_eq!(status, StatusCode::OK, "{ttl}");
        let doc: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
        assert_eq!(doc["dist"]["tarball"], ON_NORA, "{ttl}: {doc}");
        let mut expected = Vec::new();
        for version in VERSIONS {
            let uri = format!("/npm/@vendor/pkg/-/@vendor/pkg-{version}.tgz");
            let (status, body) = get(&ctx, &uri).await;
            assert_eq!(
                (status, body),
                (StatusCode::OK, tgz(version)),
                "{ttl}: {version}"
            );
            expected.push((project(version), true));
        }
        let tarballs: Vec<(String, bool)> = log(&gitlab)
            .await
            .into_iter()
            .filter(|(p, _)| p.ends_with(".tgz"))
            .collect();
        assert_eq!(tarballs, expected, "{ttl}");
        assert!(
            log(&public).await.is_empty(),
            "{ttl}: {:?}",
            log(&public).await
        );
    }
}

/// A lockfile install asks for the tarball first, with nothing cached: NORA reads the
/// packument to find where the upstream keeps it.
#[tokio::test]
async fn a_tarball_asked_before_its_packument_is_found_on_the_upstream_origin() {
    for trust in [true, false] {
        let public = open_server().await;
        let gitlab = gitlab(MockServer::uri).await;
        let ctx = context_with(&public.uri(), &instance(&gitlab), 3600, trust);
        let (status, body) = get(&ctx, "/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz").await;
        assert_eq!(
            (status, body.as_slice()),
            (StatusCode::OK, b"GITLAB-TGZ".as_slice()),
            "trust {trust}: {}",
            String::from_utf8_lossy(&body)
        );
        assert!(log(&public).await.is_empty(), "{:?}", log(&public).await);
    }
}

/// GitLab answers its instance-level tarball path by forwarding to the public registry (302,
/// measured on 19.5). A tarball asked before its packument is cached — a lockfile install, or
/// npm asking for it before the packument NORA just served is written — is looked up in the
/// packument first: neither that path nor the public registry is asked.
#[tokio::test]
async fn a_tarball_asked_first_does_not_follow_the_upstream_to_the_public_registry() {
    let public = open_server().await;
    let gitlab = gitlab(MockServer::uri).await;
    Mock::given(method("GET"))
        .and(path(
            "/api/v4/packages/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz",
        ))
        .respond_with(ResponseTemplate::new(302).insert_header(
            "location",
            format!("{}/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz", public.uri()).as_str(),
        ))
        .mount(&gitlab)
        .await;
    let ctx = context_with(&public.uri(), &instance(&gitlab), 3600, false);
    let (status, body) = get(&ctx, "/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz").await;
    assert_eq!(
        (status, body.as_slice()),
        (StatusCode::OK, b"GITLAB-TGZ".as_slice())
    );
    let tarballs: Vec<(String, bool)> = log(&gitlab)
        .await
        .into_iter()
        .filter(|(p, _)| p.ends_with(".tgz"))
        .collect();
    assert_eq!(tarballs, vec![(PROJECT.to_string(), true)]);
    assert!(log(&public).await.is_empty(), "{:?}", log(&public).await);
}

/// The same project path on another origin — the other upstream's, or one no upstream has —
/// is left out, and nothing is asked of it.
#[tokio::test]
async fn the_same_path_on_another_origin_is_left_out() {
    let elsewhere = open_server().await;
    for (case, on_public) in [("another upstream", true), ("no upstream", false)] {
        let public = open_server().await;
        let target = if on_public {
            public.uri()
        } else {
            elsewhere.uri()
        };
        let gitlab = gitlab(|_| target.clone()).await;
        let ctx = context(&public.uri(), &instance(&gitlab));
        let versions = versions(&ctx).await;
        assert!(
            versions.as_object().unwrap().is_empty(),
            "{case}: {versions}"
        );
        settle().await;
        let (status, _) = get(&ctx, "/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz").await;
        assert_ne!(status, StatusCode::OK, "{case}");
        assert!(
            log(&public).await.is_empty(),
            "{case}: {:?}",
            log(&public).await
        );
        assert!(
            log(&elsewhere).await.is_empty(),
            "{case}: {:?}",
            log(&elsewhere).await
        );
    }
}

/// The default upstream's packument naming the private upstream's origin: left out, and the
/// private upstream is never asked (with or without its token).
#[tokio::test]
async fn a_packument_from_one_upstream_cannot_name_the_origin_of_another() {
    let gitlab = gitlab(MockServer::uri).await;
    let public = MockServer::start().await;
    let link = format!(
        "{}/api/v4/projects/7/packages/npm/pkg/-/pkg-1.0.0.tgz",
        gitlab.uri()
    );
    Mock::given(method("GET"))
        .and(path("/pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_string(packument("pkg", &link)))
        .mount(&public)
        .await;
    let ctx = context(&public.uri(), &instance(&gitlab));
    let (status, body) = get(&ctx, "/npm/pkg").await;
    assert_eq!(status, StatusCode::OK);
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(doc["versions"].as_object().unwrap().is_empty(), "{doc}");
    settle().await;
    let (status, _) = get(&ctx, "/npm/pkg/-/pkg-1.0.0.tgz").await;
    assert_ne!(status, StatusCode::OK);
    assert!(log(&gitlab).await.is_empty(), "{:?}", log(&gitlab).await);
}

/// A packument cached with the upstream's own link as it is (by the release before this
/// one, which kept every link it did not recognise; under the key an older release still
/// wrote, too) is served on NORA, and its tarball fetched from that link.
#[tokio::test]
async fn a_copy_cached_with_the_link_as_it_is_is_served_on_nora() {
    for key in [
        super::upstream_packument_key(NAME),
        super::legacy_cache_key(NAME),
    ] {
        let public = open_server().await;
        let gitlab = gitlab(MockServer::uri).await;
        let upstream = instance(&gitlab);
        let ctx = context(&public.uri(), &upstream);
        let cached = packument(NAME, &format!("{}{PROJECT}", gitlab.uri()));
        super::put_with_origin(
            &ctx.state.storage,
            &key,
            cached.clone().into_bytes(),
            &super::origin_of(&upstream),
        )
        .await
        .unwrap();
        let versions = versions(&ctx).await;
        assert_eq!(
            versions["1.0.0"]["dist"]["tarball"], ON_NORA,
            "{key}: {versions}"
        );
        let (status, body) = get(&ctx, "/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz").await;
        assert_eq!(
            (status, body.as_slice()),
            (StatusCode::OK, b"GITLAB-TGZ".as_slice()),
            "{key}"
        );
        let packuments = log(&gitlab)
            .await
            .into_iter()
            .filter(|(p, _)| !p.ends_with(".tgz"))
            .count();
        assert_eq!(packuments, 0, "{key}: a fresh copy was asked for again");
    }
}

/// A copy cached as it is with the project path on another origin (by the release before
/// this one): a download of that tarball never asks that origin.
#[tokio::test]
async fn a_cached_link_on_another_origin_is_never_asked() {
    let public = open_server().await;
    let elsewhere = open_server().await;
    let gitlab = gitlab(MockServer::uri).await;
    let upstream = instance(&gitlab);
    let ctx = context(&public.uri(), &upstream);
    let cached = packument(NAME, &format!("{}{PROJECT}", elsewhere.uri()));
    super::put_with_origin(
        &ctx.state.storage,
        &super::upstream_packument_key(NAME),
        cached.clone().into_bytes(),
        &super::origin_of(&upstream),
    )
    .await
    .unwrap();
    let _ = get(&ctx, "/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz").await;
    assert!(
        log(&elsewhere).await.is_empty(),
        "{:?}",
        log(&elsewhere).await
    );
    assert!(log(&public).await.is_empty(), "{:?}", log(&public).await);
}

/// A scope's copy cached before its upstream owned it (no record of that owner) names a link
/// on the owner's origin: NORA does not follow it with the owner's token — it asks the owner
/// for the packument and follows the link that names.
#[tokio::test]
async fn a_copy_the_owner_did_not_deliver_does_not_say_where_to_fetch() {
    for trust in [true, false] {
        the_owner_is_asked_instead(trust).await;
    }
}

async fn the_owner_is_asked_instead(trust: bool) {
    let public = open_server().await;
    let gitlab = gitlab(MockServer::uri).await;
    let squatted = "/api/v4/projects/666/packages/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz";
    Mock::given(method("GET"))
        .and(path(squatted))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"SQUATTED".to_vec()))
        .mount(&gitlab)
        .await;
    let ctx = context_with(&public.uri(), &instance(&gitlab), 3600, trust);
    let cached = packument(NAME, &format!("{}{squatted}", gitlab.uri()));
    ctx.state
        .storage
        .put(&super::upstream_packument_key(NAME), cached.as_bytes())
        .await
        .unwrap();
    let (status, body) = get(&ctx, "/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz").await;
    assert_eq!(
        (status, body.as_slice()),
        (StatusCode::OK, b"GITLAB-TGZ".as_slice()),
        "trust {trust}: {}",
        String::from_utf8_lossy(&body)
    );
    let asked: Vec<String> = log(&gitlab).await.into_iter().map(|(p, _)| p).collect();
    assert!(
        !asked.iter().any(|p| p == squatted),
        "trust {trust}: {asked:?}"
    );
}

/// After the upstream moved, a copy cached from the old one keeps no link to it: with the
/// new upstream down, the version is served stale without it, and the old origin is never
/// asked — the new upstream's credential does not go there.
#[tokio::test]
async fn after_the_upstream_moved_the_old_origin_is_not_asked() {
    let old = open_server().await;
    let moved = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(503))
        .mount(&moved)
        .await;
    let upstream = format!("{}/api/v4/packages/npm", moved.uri());
    let ctx = create_test_context_with_config({
        let upstream = upstream.clone();
        move |cfg| {
            cfg.npm.proxy = Some(upstream);
            cfg.npm.proxy_auth = Some(ProtectedString::from("user:pass"));
            cfg.npm.metadata_ttl = 3600;
            cfg.npm.serve_stale = true;
            cfg.server.public_url = Some(NORA.to_string());
        }
    });
    let cached = packument(
        "pkg",
        &format!(
            "{}/api/v4/projects/7/packages/npm/pkg/-/pkg-1.0.0.tgz",
            old.uri()
        ),
    );
    ctx.state
        .storage
        .put(&super::upstream_packument_key("pkg"), cached.as_bytes())
        .await
        .unwrap();
    let (status, body) = get(&ctx, "/npm/pkg").await;
    assert_eq!(status, StatusCode::OK);
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(doc["versions"].as_object().unwrap().is_empty(), "{doc}");
    let (status, _) = get(&ctx, "/npm/pkg/-/pkg-1.0.0.tgz").await;
    assert_ne!(status, StatusCode::OK);
    assert!(log(&old).await.is_empty(), "{:?}", log(&old).await);
}

/// After `NORA_PUBLIC_URL` moved, with the upstream down: a cached packument is served
/// without the versions it names at the old address, or not at all without `serve_stale` —
/// the limit the deploy guide states, with its workaround.
#[tokio::test]
async fn after_nora_moved_with_the_upstream_down_its_old_links_are_left_out() {
    for serve_stale in [true, false] {
        let down = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(503))
            .mount(&down)
            .await;
        let uri = down.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.npm.proxy = Some(uri);
            cfg.npm.serve_stale = serve_stale;
            cfg.server.public_url = Some(NORA.to_string());
        });
        let cached = packument("pkg", "http://old-nora.example/npm/pkg/-/pkg-1.0.0.tgz");
        ctx.state
            .storage
            .put(&super::upstream_packument_key("pkg"), cached.as_bytes())
            .await
            .unwrap();
        let (status, body) = get(&ctx, "/npm/pkg").await;
        if serve_stale {
            assert_eq!(status, StatusCode::OK);
            let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(doc["versions"].as_object().unwrap().is_empty(), "{doc}");
        } else {
            assert_eq!(status, StatusCode::BAD_GATEWAY);
        }
    }
}

/// An upstream whose credential is the userinfo of its URL: the link it names is asked with
/// the same userinfo, which is the upstream's credential (sent as Basic).
#[tokio::test]
async fn the_credential_in_the_upstream_url_goes_with_its_link() {
    let gitlab = MockServer::start().await;
    let basic = format!(
        "Basic {}",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "u:p")
    );
    let link = format!(
        "{}/api/v4/projects/7/packages/npm/pkg/-/pkg-1.0.0.tgz",
        gitlab.uri()
    );
    Mock::given(method("GET"))
        .and(path("/api/v4/packages/npm/pkg"))
        .and(header("authorization", basic.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_string(packument("pkg", &link)))
        .mount(&gitlab)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/7/packages/npm/pkg/-/pkg-1.0.0.tgz"))
        .and(header("authorization", basic.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"GITLAB-TGZ".to_vec()))
        .mount(&gitlab)
        .await;
    let upstream = gitlab.uri().replacen("http://", "http://u:p@", 1) + "/api/v4/packages/npm";
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.npm.proxy = Some(upstream);
        cfg.server.public_url = Some(NORA.to_string());
    });
    let (status, body) = get(&ctx, "/npm/pkg").await;
    assert_eq!(status, StatusCode::OK);
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        doc["versions"]["1.0.0"]["dist"]["tarball"],
        "http://nora.example/npm/pkg/-/pkg-1.0.0.tgz"
    );
    settle().await;
    let (status, body) = get(&ctx, "/npm/pkg/-/pkg-1.0.0.tgz").await;
    assert_eq!(
        (status, body.as_slice()),
        (StatusCode::OK, b"GITLAB-TGZ".as_slice())
    );
}

/// Which links on the upstream's origin are its own: an absolute link as a URL parser writes
/// it, without userinfo, query or fragment, on the upstream's scheme, host and port (the
/// credential goes there with it), naming this package and one of its tarballs. Anything
/// else is left out.
#[test]
fn which_links_on_the_upstream_origin_are_its_own() {
    let upstream = "https://gitlab.example/api/v4/packages/npm";
    let project = "/api/v4/projects/7/packages/npm";
    let doc = |link: &str| packument(NAME, link).into_bytes();
    let mut wrong = Vec::new();
    for (link, served) in [
        (format!("https://gitlab.example{PROJECT}"), Some(ON_NORA)),
        (format!("http://gitlab.example{PROJECT}"), None),
        (
            format!("https://gitlab.example{project}/@vendor%2fpkg/-/@vendor/pkg-1.0.0.tgz"),
            Some(ON_NORA),
        ),
        (
            format!("https://gitlab.example{project}/@vendor/pkg/-/@vendor%2Fpkg-1.0.0.tgz"),
            Some("http://nora.example/npm/@vendor/pkg/-/@vendor%2Fpkg-1.0.0.tgz"),
        ),
        (format!("https://gitlab.example:8443{PROJECT}"), None),
        (
            format!("https://gitlab.example.evil.example{PROJECT}"),
            None,
        ),
        (format!("https://user@gitlab.example{PROJECT}"), None),
        (format!("https://gitlab.example{PROJECT}?x=1"), None),
        (format!("https://gitlab.example{PROJECT}#x"), None),
        (format!("//gitlab.example{PROJECT}"), None),
        (format!(" https://gitlab.example{PROJECT}"), None),
        (format!("HTTPS://gitlab.example{PROJECT}"), None),
        (
            format!("https://gitlab.example{project}/other/-/other-1.0.0.tgz"),
            None,
        ),
        (
            format!("https://gitlab.example{project}/other/-/@vendor/pkg-1.0.0.tgz"),
            None,
        ),
        (
            format!("https://gitlab.example{project}/@vendor/pkgx/-/@vendor/pkg-1.0.0.tgz"),
            None,
        ),
        (
            format!("https://gitlab.example{project}/@vendor/pkg/-/other-1.0.0.tgz"),
            None,
        ),
        (
            format!("https://gitlab.example{project}/@vendor/pkg/-/"),
            None,
        ),
        (
            format!("https://gitlab.example{project}/@vendor/pkg/-/README.md"),
            None,
        ),
        (
            format!("https://gitlab.example{project}/@vendor/pkg/-/../../@vendor/pkg-1.0.0.tgz"),
            None,
        ),
        (
            format!("https://gitlab.example{project}/@vendor/pkg/-/%2e%2e/@vendor/pkg-1.0.0.tgz"),
            None,
        ),
        (format!("https://gitlab.example{project}/@vendor/pkg"), None),
        (format!("ftp://gitlab.example{PROJECT}"), None),
    ] {
        let out = rewrite_tarball_urls(&doc(&link), NORA, upstream).unwrap();
        let out: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let got = out["versions"]["1.0.0"]["dist"]["tarball"].as_str();
        if got != served {
            wrong.push(format!("{link}: {got:?}, expected {served:?}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// A path whose last segments only end like the package — a longer name before `@`, or an
/// encoded `@` after one — holds another package: its link is left out.
#[test]
fn a_holder_that_only_ends_like_the_package_is_not_its_own() {
    let upstream = "https://gitlab.example/api/v4/packages/npm";
    for link in [
        "https://gitlab.example/api/v4/projects/7/packages/npm/evil@vendor/pkg/-/@vendor/pkg-1.0.0.tgz",
        "https://gitlab.example/api/v4/projects/7/packages/npm/x%40vendor/pkg/-/@vendor/pkg-1.0.0.tgz",
        "https://gitlab.example/api/v4/projects/7/packages/npm/x%2F@vendor/pkg/-/@vendor/pkg-1.0.0.tgz",
    ] {
        let out =
            rewrite_tarball_urls(packument(NAME, link).as_bytes(), NORA, upstream).unwrap();
        let out: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(
            out["versions"]["1.0.0"]["dist"]["tarball"].as_str(),
            None,
            "{link}"
        );
    }
}

/// An upstream with a credential in its URL and no path of its own: a link on its origin is
/// still fetched exactly as the packument names it, with that credential, never at
/// `<upstream>/<path>`.
#[tokio::test]
async fn an_upstream_with_userinfo_and_no_path_fetches_from_its_link() {
    let gitlab = MockServer::start().await;
    let basic = format!(
        "Basic {}",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "u:p")
    );
    let link = format!(
        "{}/api/v4/projects/7/packages/npm/pkg/-/pkg-1.0.0.tgz",
        gitlab.uri()
    );
    Mock::given(method("GET"))
        .and(path("/pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_string(packument("pkg", &link)))
        .mount(&gitlab)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/7/packages/npm/pkg/-/pkg-1.0.0.tgz"))
        .and(header("authorization", basic.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"GITLAB-TGZ".to_vec()))
        .mount(&gitlab)
        .await;
    Mock::given(method("GET"))
        .and(path("/pkg/-/pkg-1.0.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ELSEWHERE".to_vec()))
        .mount(&gitlab)
        .await;
    let upstream = gitlab.uri().replacen("http://", "http://u:p@", 1);
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.npm.proxy = Some(upstream);
        cfg.server.public_url = Some(NORA.to_string());
    });
    let (status, body) = get(&ctx, "/npm/pkg").await;
    assert_eq!(status, StatusCode::OK);
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        doc["versions"]["1.0.0"]["dist"]["tarball"],
        "http://nora.example/npm/pkg/-/pkg-1.0.0.tgz"
    );
    settle().await;
    let (status, body) = get(&ctx, "/npm/pkg/-/pkg-1.0.0.tgz").await;
    assert_eq!(
        (status, String::from_utf8_lossy(&body).into_owned()),
        (StatusCode::OK, "GITLAB-TGZ".to_string())
    );
}

/// A copy an older release cached under the legacy key, not delivered by the scope's owner,
/// does not say where to fetch either: the owner's own listing does, with its token.
#[tokio::test]
async fn a_legacy_copy_the_owner_did_not_deliver_does_not_say_where_to_fetch() {
    let public = open_server().await;
    let gitlab = gitlab(MockServer::uri).await;
    let squatted = "/api/v4/projects/666/packages/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz";
    Mock::given(method("GET"))
        .and(path(squatted))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"SQUATTED".to_vec()))
        .mount(&gitlab)
        .await;
    let ctx = context_with(&public.uri(), &instance(&gitlab), 3600, false);
    let cached = packument(NAME, &format!("{}{squatted}", gitlab.uri()));
    ctx.state
        .storage
        .put(&super::legacy_cache_key(NAME), cached.as_bytes())
        .await
        .unwrap();
    let (status, body) = get(&ctx, "/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz").await;
    assert_eq!(
        (status, body.as_slice()),
        (StatusCode::OK, b"GITLAB-TGZ".as_slice()),
        "{}",
        String::from_utf8_lossy(&body)
    );
    let asked: Vec<String> = log(&gitlab).await.into_iter().map(|(p, _)| p).collect();
    assert!(!asked.iter().any(|p| p == squatted), "{asked:?}");
}

/// The public upstream at the root of the owner's host is another upstream: a copy it
/// delivered (its provenance names `npm:http://host:port`, a prefix of the owner's
/// `…/api/v4/packages/npm`) is not the owner's.
#[tokio::test]
async fn a_copy_from_an_upstream_whose_url_prefixes_the_owners_is_not_trusted() {
    let gitlab = gitlab(MockServer::uri).await;
    let squatted = "/api/v4/projects/666/packages/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz";
    Mock::given(method("GET"))
        .and(path(squatted))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"SQUATTED".to_vec()))
        .mount(&gitlab)
        .await;
    let ctx = context_with(&gitlab.uri(), &instance(&gitlab), 3600, false);
    let cached = packument(NAME, &format!("{}{squatted}", gitlab.uri()));
    super::put_with_origin(
        &ctx.state.storage,
        &super::upstream_packument_key(NAME),
        cached.clone().into_bytes(),
        &super::origin_of(&gitlab.uri()),
    )
    .await
    .unwrap();
    let (status, body) = get(&ctx, "/npm/@vendor/pkg/-/@vendor/pkg-1.0.0.tgz").await;
    assert_eq!(
        (status, body.as_slice()),
        (StatusCode::OK, b"GITLAB-TGZ".as_slice()),
        "{}",
        String::from_utf8_lossy(&body)
    );
    let asked: Vec<String> = log(&gitlab).await.into_iter().map(|(p, _)| p).collect();
    assert!(!asked.iter().any(|p| p == squatted), "{asked:?}");
}
