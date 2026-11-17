//! The server's upstream clients refuse loopback/private targets (audit A034): a redirect hop
//! to such an address and a host name that resolves only to such addresses fail the fetch,
//! unless `server.allow_private_upstreams` is set. The fixtures are wiremock servers on
//! 127.0.0.1: the upstream is reached by its IP literal (the operator's own URL, not checked),
//! the "internal" listener stands for an address NORA was never given.

use super::*;
use crate::config::{DockerUpstream, MavenProxyEntry};
use crate::test_helpers::{body_bytes, create_test_context_with_config, send, TestContext};
use axum::http::Method;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const MARKER: &str = "INTERNAL-ONLY-LISTENER";

async fn internal() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!("marker {MARKER}\n")))
        .mount(&server)
        .await;
    server
}

async fn redirect_all(upstream: &MockServer, to: String) {
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", to.as_str()))
        .mount(upstream)
        .await;
}

async fn hits(server: &MockServer) -> usize {
    server.received_requests().await.unwrap_or_default().len()
}

async fn get(ctx: &TestContext, uri: &str) -> (u16, String) {
    let resp = send(&ctx.app, Method::GET, uri, "").await;
    let status = resp.status().as_u16();
    (
        status,
        String::from_utf8_lossy(&body_bytes(resp).await).into_owned(),
    )
}

/// No stored object holds the internal listener's body (cache writes are detached tasks).
async fn assert_nothing_cached(ctx: &TestContext, label: &str) {
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    for key in ctx.state.storage.list("").await.unwrap_or_default() {
        if let Ok(data) = ctx.state.storage.get(&key).await {
            assert!(
                !String::from_utf8_lossy(&data).contains(MARKER),
                "{label}: the internal body was cached under {key}"
            );
        }
    }
}

fn docker_upstream(url: String) -> DockerUpstream {
    DockerUpstream {
        trust_upstream_dates: false,
        date_token_file: None,
        token_hosts: Vec::new(),
        url,
        auth: None,
        auth_env: None,
        namespace: None,
        prefix: None,
        namespaces: Vec::new(),
    }
}

type Setup = fn(&mut Config, String);

/// One format per row, each on its own client: the default one (maven, go, docker manifest),
/// the same-origin one (docker tags/list) and the npm tarball walk on the no-redirect client.
fn formats() -> [(&'static str, Setup, &'static str); 4] {
    [
        (
            "maven",
            |cfg, uri| cfg.maven.proxies = vec![MavenProxyEntry::Simple(uri)],
            "/maven2/com/acme/demo/1.0/demo-1.0.jar",
        ),
        (
            "go",
            |cfg, uri| cfg.go.proxy = Some(uri),
            "/go/example.com/demo/@v/v1.0.0.zip",
        ),
        (
            "docker-manifest",
            |cfg, uri| cfg.docker.upstreams = vec![docker_upstream(uri)],
            "/v2/library/demo/manifests/latest",
        ),
        (
            "npm-packument",
            |cfg, uri| cfg.npm.proxy = Some(uri),
            "/npm/demo",
        ),
    ]
}

/// A redirect from a configured upstream to a loopback address is not followed: the internal
/// listener gets no request, the reader gets no 2xx and nothing of its body is cached.
#[tokio::test]
async fn a034_redirect_to_a_private_address_is_refused() {
    for (label, setup, uri) in formats() {
        let inner = internal().await;
        let upstream = MockServer::start().await;
        redirect_all(&upstream, format!("{}/metrics", inner.uri())).await;
        let up = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.server.allow_private_upstreams = false;
            setup(cfg, up);
        });
        let (status, body) = get(&ctx, uri).await;
        assert!(
            hits(&upstream).await > 0,
            "{label}: the upstream was not asked"
        );
        assert_eq!(hits(&inner).await, 0, "{label}: the hop was followed");
        assert!(!(200..300).contains(&status), "{label}: {status}");
        assert!(!body.contains(MARKER), "{label}: {body}");
        assert_nothing_cached(&ctx, label).await;
    }
}

/// The same fixture with the switch on reaches the internal listener, so the refusal above is
/// the guard's and not the fixture's.
#[tokio::test]
async fn a034_allow_private_upstreams_restores_the_hop() {
    let inner = internal().await;
    let upstream = MockServer::start().await;
    redirect_all(&upstream, format!("{}/metrics", inner.uri())).await;
    let up = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.server.allow_private_upstreams = true;
        cfg.maven.proxies = vec![MavenProxyEntry::Simple(up)];
    });
    let (status, body) = get(&ctx, "/maven2/com/acme/demo/1.0/demo-1.0.jar").await;
    assert_eq!(status, 200);
    assert!(body.contains(MARKER));
    assert_eq!(hits(&inner).await, 1);
}

/// The same-origin client (docker tags/list): a hop on the upstream's own origin is refused
/// when that origin is a private address.
#[tokio::test]
async fn a034_same_origin_hop_to_a_private_address_is_refused() {
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/elsewhere"))
        .respond_with(ResponseTemplate::new(200).set_body_string(MARKER))
        .with_priority(1)
        .mount(&upstream)
        .await;
    redirect_all(&upstream, format!("{}/elsewhere", upstream.uri())).await;
    let up = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.server.allow_private_upstreams = false;
        cfg.docker.upstreams = vec![docker_upstream(up)];
    });
    let (status, body) = get(&ctx, "/v2/library/demo/tags/list").await;
    let paths: Vec<String> = upstream
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .map(|r| r.url.path().to_string())
        .collect();
    assert!(!paths.is_empty(), "the upstream was not asked");
    assert!(!paths.iter().any(|p| p == "/elsewhere"), "{paths:?}");
    assert!(!body.contains(MARKER), "{status}: {body}");
}

/// The npm tarball walk (fetch_following, hop by hop on the no-redirect client): the packument
/// is the upstream's own, the tarball request is redirected to the internal listener.
#[tokio::test]
async fn a034_npm_tarball_hop_to_a_private_address_is_refused() {
    let inner = internal().await;
    let upstream = MockServer::start().await;
    let link = format!("{}/demo/-/demo-1.0.0.tgz", upstream.uri());
    let packument = serde_json::json!({
        "name": "demo",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": { "name": "demo", "version": "1.0.0", "dist": { "tarball": link } },
        },
        "time": { "1.0.0": "2020-01-02T00:00:00.000Z" },
    });
    Mock::given(method("GET"))
        .and(path("/demo"))
        .respond_with(ResponseTemplate::new(200).set_body_string(packument.to_string()))
        .with_priority(1)
        .mount(&upstream)
        .await;
    redirect_all(&upstream, format!("{}/metrics", inner.uri())).await;
    let up = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.server.allow_private_upstreams = false;
        cfg.npm.proxy = Some(up);
    });
    let (status, body) = get(&ctx, "/npm/demo/-/demo-1.0.0.tgz").await;
    assert_eq!(hits(&inner).await, 0, "the tarball hop was followed");
    assert!(!(200..300).contains(&status), "{status}");
    assert!(!body.contains(MARKER));
    assert_nothing_cached(&ctx, "npm-tarball").await;
}

/// A host name that resolves only to loopback is refused at connect, before any request.
#[tokio::test]
async fn a034_upstream_name_resolving_to_loopback_is_refused() {
    let upstream = internal().await;
    let up = format!("http://localhost:{}", upstream.address().port());
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.server.allow_private_upstreams = false;
        cfg.maven.proxies = vec![MavenProxyEntry::Simple(up)];
    });
    let (status, body) = get(&ctx, "/maven2/com/acme/demo/1.0/demo-1.0.jar").await;
    assert_eq!(hits(&upstream).await, 0);
    assert!(!(200..300).contains(&status), "{status}");
    assert!(!body.contains(MARKER));
}

/// The startup check names every configured upstream and JWKS host the guard would refuse.
#[tokio::test]
async fn a034_startup_warns_about_private_upstream_hosts() {
    let mut cfg = Config::default();
    cfg.go.proxy = Some("http://10.1.2.3:8081/go".into());
    cfg.maven.proxies = vec![MavenProxyEntry::Simple("https://8.8.8.8/maven2".into())];
    cfg.auth.teleport.enabled = true;
    cfg.auth.teleport.jwks_url = "https://169.254.169.254/.well-known/jwks.json".into();
    let hosts = outbound_hosts(&cfg);
    for host in ["10.1.2.3", "8.8.8.8", "169.254.169.254"] {
        assert!(hosts.iter().any(|h| h == host), "{host} not in {hosts:?}");
    }
    let mut refused = warn_private_upstreams(hosts).await;
    refused.sort();
    assert_eq!(refused, ["10.1.2.3", "169.254.169.254"]);
    assert_eq!(
        warn_private_upstreams(vec!["localhost".into()]).await,
        ["localhost"]
    );
}
