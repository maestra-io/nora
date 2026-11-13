// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::circuit_breaker::ProbeToken;
use crate::test_helpers::{body_bytes, create_test_context, create_test_context_with_config, send};
use axum::body::Body;
use axum::http::{header, Method, StatusCode};
use sha2::Digest;

#[tokio::test]
async fn test_docker_namespace_scope_enforced() {
    use crate::auth::NamespaceAuthority;
    use crate::config::ScopeEnforcement;
    use axum::extract::{Path, State};
    use axum::http::Uri;
    use axum::Extension;

    let ctx = create_test_context();
    let scoped = NamespaceAuthority::from_oidc_scope(
        "ci",
        &["myorg/**".to_string()],
        ScopeEnforcement::Enforce,
    );

    // Out-of-scope blob upload (POST) -> 403.
    let resp = super::docker_v2_dispatch(
        State(ctx.state.clone()),
        Method::POST,
        Path("other/app/blobs/uploads/".to_string()),
        Extension(scoped.clone()),
        "/v2/other/app/blobs/uploads/".parse::<Uri>().unwrap(),
        axum::http::HeaderMap::new(),
        Body::empty(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // In-scope blob upload start -> not denied (enforcement passes).
    let resp = super::docker_v2_dispatch(
        State(ctx.state.clone()),
        Method::POST,
        Path("myorg/app/blobs/uploads/".to_string()),
        Extension(scoped.clone()),
        "/v2/myorg/app/blobs/uploads/".parse::<Uri>().unwrap(),
        axum::http::HeaderMap::new(),
        Body::empty(),
    )
    .await;
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);

    // Reads are never gated, even out of scope (404, not 403).
    let resp = super::docker_v2_dispatch(
        State(ctx.state.clone()),
        Method::GET,
        Path("other/app/manifests/latest".to_string()),
        Extension(scoped.clone()),
        "/v2/other/app/manifests/latest".parse::<Uri>().unwrap(),
        axum::http::HeaderMap::new(),
        Body::empty(),
    )
    .await;
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_docker_v2_check() {
    let ctx = create_test_context();
    let resp = send(&ctx.app, Method::GET, "/v2/", Body::empty()).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_docker_catalog_empty() {
    let ctx = create_test_context();
    let resp = send(&ctx.app, Method::GET, "/v2/_catalog", Body::empty()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["repositories"].as_array().unwrap().is_empty());
}

/// Seed the all-zero config blob a test manifest references, so the manifest PUT passes
/// the OCI blob-existence check (real clients push referenced blobs before the manifest).
async fn seed_zero_config(state: &crate::AppState, name: &str) {
    let _ = state
        .storage
        .put(
            &format!(
                "docker/{}/blobs/sha256:0000000000000000000000000000000000000000000000000000000000000000",
                name
            ),
            b"x",
        )
        .await;
}

#[tokio::test]
async fn test_docker_put_get_manifest() {
    let ctx = create_test_context();
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 0,
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "layers": []
    });
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();

    seed_zero_config(&ctx.state, "alpine").await;
    let put_resp = send(
        &ctx.app,
        Method::PUT,
        "/v2/alpine/manifests/latest",
        Body::from(manifest_bytes.clone()),
    )
    .await;
    assert_eq!(put_resp.status(), StatusCode::CREATED);
    let digest_header = put_resp
        .headers()
        .get("docker-content-digest")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(digest_header.starts_with("sha256:"));

    let get_resp = send(
        &ctx.app,
        Method::GET,
        "/v2/alpine/manifests/latest",
        Body::empty(),
    )
    .await;
    assert_eq!(get_resp.status(), StatusCode::OK);
    let get_digest = get_resp
        .headers()
        .get("docker-content-digest")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(get_digest, digest_header);
    let body = body_bytes(get_resp).await;
    assert_eq!(body.as_ref(), manifest_bytes.as_slice());
}

/// C55: Docker Hub pull-rate limiting (429) reaches the client as 429
/// TOOMANYREQUESTS with the upstream Retry-After, not as 404 MANIFEST_UNKNOWN.
#[tokio::test]
async fn test_upstream_429_is_429_not_404() {
    use crate::config::DockerUpstream;
    use crate::test_helpers::create_test_context_with_config;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "42"))
        .mount(&upstream)
        .await;
    let ctx = create_test_context_with_config(|cfg| {
        cfg.docker.upstreams = vec![DockerUpstream {
            trust_upstream_dates: false,
            date_token_file: None,
            url: upstream.uri(),
            auth: None,
            auth_env: None,
            namespace: None,
            prefix: None,
            namespaces: Vec::new(),
        }];
    });
    let resp = send(
        &ctx.app,
        Method::GET,
        "/v2/library/limited/manifests/latest",
        Body::empty(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(resp.headers().get("retry-after").unwrap(), "42");
    let body = body_bytes(resp).await;
    assert!(String::from_utf8_lossy(&body).contains("TOOMANYREQUESTS"));
}

/// A cold miss is "not found" only when an upstream said so: a manifest or blob whose
/// every upstream failed is 502. One upstream answering "not found" decides 404 while
/// another is down. Docker Hub answers a single-segment name (`alpine`) with a 4xx and
/// serves it as `library/alpine`, so that 4xx does not make the image missing while
/// `library/alpine` failed.
#[tokio::test]
async fn a_cold_miss_is_404_only_when_an_upstream_said_not_found() {
    use crate::config::DockerUpstream;
    use wiremock::matchers::{method, path_regex};
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
    let hub_down = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("^/v2/library/"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&hub_down)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&hub_down)
        .await;
    let refused = "http://127.0.0.1:9".to_string();
    let blob = format!("sha256:{}", hex::encode(sha2::Sha256::digest(b"layer")));
    let manifest = "/v2/myorg/app/manifests/1.0".to_string();
    let layer = format!("/v2/myorg/app/blobs/{blob}");
    let official = "/v2/alpine/manifests/3".to_string();
    let official_layer = format!("/v2/alpine/blobs/{blob}");

    for (upstreams, uri, want) in [
        (vec![down.uri()], &manifest, StatusCode::BAD_GATEWAY),
        (vec![refused.clone()], &manifest, StatusCode::BAD_GATEWAY),
        (vec![missing.uri()], &manifest, StatusCode::NOT_FOUND),
        (
            vec![down.uri(), missing.uri()],
            &manifest,
            StatusCode::NOT_FOUND,
        ),
        (vec![down.uri()], &layer, StatusCode::BAD_GATEWAY),
        (vec![refused.clone()], &layer, StatusCode::BAD_GATEWAY),
        (vec![missing.uri()], &layer, StatusCode::NOT_FOUND),
        (
            vec![down.uri(), missing.uri()],
            &layer,
            StatusCode::NOT_FOUND,
        ),
        (vec![hub_down.uri()], &official, StatusCode::BAD_GATEWAY),
        (vec![missing.uri()], &official, StatusCode::NOT_FOUND),
        (
            vec![hub_down.uri()],
            &official_layer,
            StatusCode::BAD_GATEWAY,
        ),
        (vec![missing.uri()], &official_layer, StatusCode::NOT_FOUND),
    ] {
        let entries = upstreams.clone();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.docker.upstreams = entries
                .into_iter()
                .map(|url| DockerUpstream {
                    trust_upstream_dates: false,
                    date_token_file: None,
                    url,
                    auth: None,
                    auth_env: None,
                    namespace: None,
                    prefix: None,
                    namespaces: Vec::new(),
                })
                .collect();
        });
        let resp = send(&ctx.app, Method::GET, uri, Body::empty()).await;
        assert_eq!(resp.status(), want, "{uri} {upstreams:?}");
    }
    assert!(!down.received_requests().await.unwrap().is_empty());
    assert!(!missing.received_requests().await.unwrap().is_empty());
    let hub = hub_down.received_requests().await.unwrap();
    assert!(hub
        .iter()
        .any(|r| r.url.path().starts_with("/v2/library/alpine/")));
}

/// #1188: a name in a namespace an upstream owns is asked of that upstream only, whole, and
/// whatever it answers is final. Docker Hub here serves every name — the squatter who
/// registered `team-a` — and must never be asked, whether the private registry comes first
/// or last, whatever it fails with, under `allow`.
#[tokio::test]
async fn a_bound_namespace_never_falls_through_to_another_upstream() {
    use crate::config::DockerUpstream;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let squatter = MockServer::start().await;
    let blob = format!("sha256:{}", hex::encode(sha2::Sha256::digest(b"layer")));
    Mock::given(method("GET"))
        .and(wiremock::matchers::path_regex("/blobs/"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"layer".to_vec()))
        .mount(&squatter)
        .await;
    Mock::given(wiremock::matchers::any())
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/vnd.oci.image.manifest.v1+json")
                .set_body_bytes(
                    br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:aaaa"},"layers":[]}"#.to_vec(),
                ),
        )
        .mount(&squatter)
        .await;
    let refused = "http://127.0.0.1:9".to_string();
    let requests = [
        (Method::GET, "/v2/team-a/service/manifests/1.0".to_string()),
        (Method::HEAD, "/v2/team-a/service/manifests/1.0".to_string()),
        (Method::GET, format!("/v2/team-a/service/blobs/{blob}")),
        (Method::HEAD, format!("/v2/team-a/service/blobs/{blob}")),
    ];

    for status in [
        Some(401),
        Some(403),
        Some(404),
        Some(429),
        Some(500),
        Some(503),
        None,
    ] {
        let harbor = MockServer::start().await;
        if let Some(status) = status {
            Mock::given(wiremock::matchers::any())
                .respond_with(ResponseTemplate::new(status))
                .mount(&harbor)
                .await;
        }
        let harbor_url = if status.is_some() {
            harbor.uri()
        } else {
            refused.clone()
        };
        for harbor_first in [true, false] {
            let bound = DockerUpstream {
                url: harbor_url.clone(),
                auth: None,
                namespace: None,
                prefix: None,
                namespaces: vec!["team-*".to_string()],
                auth_env: None,
                trust_upstream_dates: false,
                date_token_file: None,
            };
            let hub = DockerUpstream {
                url: squatter.uri(),
                auth: None,
                namespace: None,
                prefix: None,
                namespaces: Vec::new(),
                auth_env: None,
                trust_upstream_dates: false,
                date_token_file: None,
            };
            let upstreams = if harbor_first {
                vec![bound, hub]
            } else {
                vec![hub, bound]
            };
            let ctx = create_test_context_with_config(move |cfg| {
                cfg.docker.upstreams = upstreams;
            });
            for (m, uri) in &requests {
                let resp = send(&ctx.app, m.clone(), uri, Body::empty()).await;
                assert!(
                    !resp.status().is_success(),
                    "{m} {uri}: harbor {status:?} first={harbor_first} served {}",
                    resp.status()
                );
            }
        }
        for r in harbor.received_requests().await.unwrap() {
            assert!(
                r.url.path().starts_with("/v2/team-a/service/"),
                "harbor asked for {}",
                r.url.path()
            );
        }
    }
    let asked: Vec<String> = squatter
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.url.path().to_string())
        .collect();
    assert!(asked.is_empty(), "the public upstream was asked: {asked:?}");
}

/// Under `deny` a name that no prefix, namespaces or host routes is refused with `DENIED`
/// before any upstream is asked, and the refusal names what would have routed it; a bound
/// name is routed, so `deny` does not refuse it (#1188).
#[tokio::test]
async fn under_deny_an_unrouted_name_is_refused_and_a_bound_name_is_not() {
    use crate::config::{DefaultAction, DockerUpstream};
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let ct = "application/vnd.oci.image.manifest.v1+json";
    let manifest =
        br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:aaaa"},"layers":[]}"#.to_vec();
    let serving = || {
        ResponseTemplate::new(200)
            .insert_header("Content-Type", ct)
            .set_body_bytes(manifest.clone())
    };
    let (hub, harbor) = (MockServer::start().await, MockServer::start().await);
    Mock::given(method("GET"))
        .respond_with(serving())
        .mount(&hub)
        .await;
    Mock::given(method("GET"))
        .respond_with(serving())
        .mount(&harbor)
        .await;
    let (hub_url, harbor_url) = (hub.uri(), harbor.uri());
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.docker.default_action = DefaultAction::Deny;
        cfg.docker.upstreams = vec![
            DockerUpstream {
                url: hub_url,
                auth: None,
                namespace: Some("docker.io".to_string()),
                prefix: None,
                namespaces: Vec::new(),
                auth_env: None,
                trust_upstream_dates: false,
                date_token_file: None,
            },
            DockerUpstream {
                url: harbor_url,
                auth: None,
                namespace: Some("harbor.example".to_string()),
                prefix: None,
                namespaces: vec!["team-*".to_string()],
                auth_env: None,
                trust_upstream_dates: false,
                date_token_file: None,
            },
        ];
    });

    for uri in ["/v2/aquasec/trivy/manifests/1.0", "/v2/nginx/manifests/1.0"] {
        let resp = send(&ctx.app, Method::GET, uri, Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{uri}");
        let body: serde_json::Value =
            serde_json::from_slice(&body_bytes(resp).await).expect("an OCI error body");
        let error = &body["errors"][0];
        assert_eq!(error["code"], "DENIED", "{uri}");
        let message = error["message"].as_str().unwrap_or_default();
        for route in ["prefix", "namespaces", "host"] {
            assert!(
                message.contains(route),
                "{uri}: {message:?} does not name {route}"
            );
        }
    }
    let asked = hub.received_requests().await.unwrap();
    assert!(
        asked.is_empty(),
        "a refused name reached the upstream: {asked:?}"
    );

    let resp = send(
        &ctx.app,
        Method::GET,
        "/v2/team-a/service/manifests/1.0",
        Body::empty(),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a bound name is routed under deny"
    );
    assert_eq!(body_bytes(resp).await.as_ref(), manifest.as_slice());
}

/// #1188: the owner of a namespace is asked for the whole name, its copy is stored under its
/// own namespace, and a public name is not asked of it.
#[tokio::test]
async fn a_bound_namespace_is_fetched_whole_and_cached_under_its_owner() {
    use crate::config::DockerUpstream;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let ct = "application/vnd.oci.image.manifest.v1+json";
    let manifest =
        br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:aaaa"},"layers":[]}"#.to_vec();
    let harbor = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/team-a/service/manifests/1.0"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", ct)
                .set_body_bytes(manifest.clone()),
        )
        .mount(&harbor)
        .await;
    let hub = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/aquasec/trivy/manifests/1.0"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", ct)
                .set_body_bytes(manifest.clone()),
        )
        .mount(&hub)
        .await;
    let (harbor_url, hub_url) = (harbor.uri(), hub.uri());
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.docker.upstreams = vec![
            DockerUpstream {
                url: hub_url,
                auth: None,
                namespace: Some("docker.io".to_string()),
                prefix: None,
                namespaces: Vec::new(),
                auth_env: None,
                trust_upstream_dates: false,
                date_token_file: None,
            },
            DockerUpstream {
                url: harbor_url,
                auth: None,
                namespace: Some("harbor.example".to_string()),
                prefix: None,
                namespaces: vec!["team-*".to_string()],
                auth_env: None,
                trust_upstream_dates: false,
                date_token_file: None,
            },
        ];
    });

    let resp = send(
        &ctx.app,
        Method::GET,
        "/v2/team-a/service/manifests/1.0",
        Body::empty(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_bytes(resp).await.as_ref(), manifest.as_slice());
    let resp = send(
        &ctx.app,
        Method::GET,
        "/v2/aquasec/trivy/manifests/1.0",
        Body::empty(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // The copies are written in the background: wait for both, with a deadline.
    let owned = super::manifest_key(Some("harbor.example"), "team-a/service", "1.0");
    let public = super::manifest_key(Some("docker.io"), "aquasec/trivy", "1.0");
    let mut cached = false;
    for _ in 0..200 {
        if ctx.state.storage.get(&owned).await.is_ok()
            && ctx.state.storage.get(&public).await.is_ok()
        {
            cached = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(cached, "{owned} and {public}");
    let harbor_asked: Vec<String> = harbor
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.url.path().to_string())
        .collect();
    assert_eq!(harbor_asked, ["/v2/team-a/service/manifests/1.0"]);
    let hub_asked: Vec<String> = hub
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.url.path().to_string())
        .collect();
    assert_eq!(hub_asked, ["/v2/aquasec/trivy/manifests/1.0"]);
}

/// #1188: an image pushed to NORA under a name a private registry owns stays NORA's: it is
/// served from local storage and the owner is not asked.
#[tokio::test]
async fn a_hosted_image_under_a_bound_namespace_is_served_locally() {
    use crate::config::DockerUpstream;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let harbor = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(500))
        .mount(&harbor)
        .await;
    let harbor_url = harbor.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.docker.serve_stale = false;
        cfg.docker.upstreams = vec![DockerUpstream {
            url: harbor_url,
            auth: None,
            namespace: None,
            prefix: None,
            namespaces: vec!["team-*".to_string()],
            auth_env: None,
            trust_upstream_dates: false,
            date_token_file: None,
        }];
    });
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 0,
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "layers": []
    }))
    .unwrap();
    seed_zero_config(&ctx.state, "team-a/hosted").await;
    let put = send(
        &ctx.app,
        Method::PUT,
        "/v2/team-a/hosted/manifests/v1",
        Body::from(manifest.clone()),
    )
    .await;
    assert_eq!(put.status(), StatusCode::CREATED);

    for m in [Method::GET, Method::HEAD] {
        let resp = send(
            &ctx.app,
            m.clone(),
            "/v2/team-a/hosted/manifests/v1",
            Body::empty(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "{m}");
    }
    // A pushed layer lives under the bare key, which every blob read falls back to.
    let layer = b"hosted-layer".to_vec();
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&layer)));
    ctx.state
        .storage
        .put(&format!("docker/team-a/hosted/blobs/{digest}"), &layer)
        .await
        .unwrap();
    let resp = send(
        &ctx.app,
        Method::GET,
        &format!("/v2/team-a/hosted/blobs/{digest}"),
        Body::empty(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_bytes(resp).await.as_ref(), layer.as_slice());
    assert!(harbor.received_requests().await.unwrap().is_empty());
}

/// #1195: a name behind a registry host no upstream serves is not answered by another
/// registry. Docker Hub here holds every name — whoever registered `library/alpine` and
/// `project1/service1` there — and is asked for none of them under `quay.io/…`, nor is its
/// cached copy served under that host; an image pushed to NORA under the host is still served.
#[tokio::test]
async fn a_name_behind_an_unknown_registry_host_is_not_answered_by_another_registry() {
    use crate::config::DockerUpstream;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let hub = MockServer::start().await;
    let layer = b"hub-layer".to_vec();
    let blob = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&layer)));
    Mock::given(method("GET"))
        .and(wiremock::matchers::path_regex("/blobs/"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(layer.clone()))
        .mount(&hub)
        .await;
    Mock::given(wiremock::matchers::path_regex("/tags/list$"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"name": "x", "tags": ["3.20"]})),
        )
        .mount(&hub)
        .await;
    Mock::given(wiremock::matchers::any())
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/vnd.oci.image.manifest.v1+json")
                .set_body_bytes(
                    br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:aaaa"},"layers":[]}"#.to_vec(),
                ),
        )
        .mount(&hub)
        .await;
    let hub_url = hub.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.docker.upstreams = vec![DockerUpstream {
            url: hub_url,
            auth: None,
            namespace: Some("docker.io".to_string()),
            prefix: None,
            namespaces: Vec::new(),
            auth_env: None,
            trust_upstream_dates: false,
            date_token_file: None,
        }];
    });

    // Docker Hub's copies are in the cache, under each of its hosts.
    for uri in [
        "/v2/library/alpine/manifests/3.20".to_string(),
        "/v2/index.docker.io/library/alpine/manifests/3.20".to_string(),
        format!("/v2/library/alpine/blobs/{blob}"),
    ] {
        let resp = send(&ctx.app, Method::GET, &uri, Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK, "{uri}");
    }
    let asked_before = hub.received_requests().await.unwrap().len();

    for (m, uri) in [
        (
            Method::GET,
            "/v2/quay.io/library/alpine/manifests/3.20".to_string(),
        ),
        (
            Method::HEAD,
            "/v2/quay.io/library/alpine/manifests/3.20".to_string(),
        ),
        (
            Method::GET,
            "/v2/quay.io/project1/service1/manifests/1.0".to_string(),
        ),
        (
            Method::GET,
            format!("/v2/quay.io/library/alpine/blobs/{blob}"),
        ),
        (
            Method::HEAD,
            format!("/v2/quay.io/library/alpine/blobs/{blob}"),
        ),
    ] {
        let resp = send(&ctx.app, m.clone(), &uri, Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{m} {uri}");
    }
    let resp = send(
        &ctx.app,
        Method::GET,
        "/v2/quay.io/library/alpine/tags/list",
        Body::empty(),
    )
    .await;
    let tags = body_bytes(resp).await;
    assert!(
        !String::from_utf8_lossy(&tags).contains("3.20"),
        "Docker Hub's tags listed under quay.io: {}",
        String::from_utf8_lossy(&tags)
    );

    // Pushed under the host, an image is NORA's own and is served.
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 0,
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "layers": []
    }))
    .unwrap();
    seed_zero_config(&ctx.state, "myteam/app").await;
    let put = send(
        &ctx.app,
        Method::PUT,
        "/v2/quay.io/myteam/app/manifests/v1",
        Body::from(manifest.clone()),
    )
    .await;
    assert_eq!(put.status(), StatusCode::CREATED);
    let resp = send(
        &ctx.app,
        Method::GET,
        "/v2/quay.io/myteam/app/manifests/v1",
        Body::empty(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_bytes(resp).await.as_ref(), manifest.as_slice());

    let asked: Vec<String> = hub.received_requests().await.unwrap()[asked_before..]
        .iter()
        .map(|r| r.url.path().to_string())
        .collect();
    assert!(asked.is_empty(), "Docker Hub was asked: {asked:?}");
}

/// #1196: an upstream that will not let NORA in answers with one status whatever its
/// challenge scheme — 502 with an OCI `DENIED` body that names the refused credential — and
/// is not an outage to the circuit breaker. A 401 that a token did not lift stays "not found":
/// Docker Hub answers a repository that does not exist that way (measured 31.10.2026).
#[tokio::test]
async fn an_upstream_that_refuses_noras_credentials_is_a_502_that_says_so() {
    use crate::config::DockerUpstream;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let blob = format!("sha256:{}", hex::encode(sha2::Sha256::digest(b"layer")));
    let uris = [
        "/v2/project1/service1/manifests/1.0".to_string(),
        format!("/v2/project1/service1/blobs/{blob}"),
    ];
    // challenge on /v2 (None = 401 without one); token server answer; credential; status;
    // whether the answer names a refused credential
    #[rustfmt::skip]
    let rows: [(Option<&str>, Option<u16>, bool, StatusCode, bool); 8] = [
        (Some("Basic realm=\"harbor\""), None,      true,  StatusCode::BAD_GATEWAY, true),
        (Some("Basic realm=\"harbor\""), None,      false, StatusCode::BAD_GATEWAY, true),
        (None,                           None,      true,  StatusCode::BAD_GATEWAY, true),
        (Some("Bearer"),                 Some(401), true,  StatusCode::BAD_GATEWAY, true),
        (Some("Bearer"),                 Some(403), false, StatusCode::BAD_GATEWAY, true),
        (Some("Bearer"),                 Some(500), true,  StatusCode::BAD_GATEWAY, false),
        // a token that does not lift the 401: the same as a missing repository on Docker Hub
        (Some("Bearer"),                 Some(200), true,  StatusCode::NOT_FOUND,   false),
        (Some("Bearer"),                 Some(200), false, StatusCode::NOT_FOUND,   false),
    ];
    for (challenge, token, credential, status, named) in rows {
        let registry = MockServer::start().await;
        let mut refusal = ResponseTemplate::new(401);
        if let Some(challenge) = challenge {
            let challenge = if challenge == "Bearer" {
                format!(
                    "Bearer realm=\"{}/token\",service=\"registry\"",
                    registry.uri()
                )
            } else {
                challenge.to_string()
            };
            refusal = refusal.insert_header("Www-Authenticate", challenge.as_str());
        }
        if let Some(token) = token {
            Mock::given(path("/token"))
                .respond_with(
                    ResponseTemplate::new(token).set_body_json(serde_json::json!({"token": "t"})),
                )
                .mount(&registry)
                .await;
        }
        Mock::given(method("GET"))
            .respond_with(refusal)
            .mount(&registry)
            .await;
        let registry_url = registry.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.circuit_breaker.enabled = true;
            cfg.circuit_breaker.failure_threshold = 3;
            cfg.docker.upstreams = vec![DockerUpstream {
                url: registry_url,
                auth: credential.then(|| "robot:secret".to_string().into()),
                namespace: None,
                prefix: None,
                namespaces: Vec::new(),
                auth_env: None,
                trust_upstream_dates: false,
                date_token_file: None,
            }];
        });
        let case = format!("{challenge:?} token={token:?} credential={credential}");
        // Well past the breaker's threshold: a refusal never opens it (no 503).
        for _ in 0..8 {
            for uri in &uris {
                let resp = send(&ctx.app, Method::GET, uri, Body::empty()).await;
                assert_eq!(resp.status(), status, "{case} {uri}");
                let body = body_bytes(resp).await;
                let error: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                assert_eq!(
                    error["errors"][0]["code"] == "DENIED"
                        && error["errors"][0]["message"]
                            .as_str()
                            .unwrap_or_default()
                            .contains("refused NORA's credentials"),
                    named,
                    "{case} {uri}: {}",
                    String::from_utf8_lossy(&body)
                );
            }
        }
        let asked = registry
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path().starts_with("/v2/"))
            .count();
        assert!(asked >= 16, "{case}: the upstream was asked {asked} times");
    }

    // In the fallback chain another upstream's answer still decides.
    let refusing = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(
            ResponseTemplate::new(401).insert_header("Www-Authenticate", "Basic realm=\"harbor\""),
        )
        .mount(&refusing)
        .await;
    let (missing, serving) = (MockServer::start().await, MockServer::start().await);
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(404))
        .mount(&missing)
        .await;
    let manifest =
        br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:aaaa"},"layers":[]}"#.to_vec();
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/vnd.oci.image.manifest.v1+json")
                .set_body_bytes(manifest.clone()),
        )
        .mount(&serving)
        .await;
    for (second, want) in [
        (missing.uri(), StatusCode::NOT_FOUND),
        (serving.uri(), StatusCode::OK),
    ] {
        let first = refusing.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.docker.upstreams = [first, second]
                .into_iter()
                .map(|url| DockerUpstream {
                    url,
                    auth: Some("robot:secret".to_string().into()),
                    namespace: None,
                    prefix: None,
                    namespaces: Vec::new(),
                    auth_env: None,
                    trust_upstream_dates: false,
                    date_token_file: None,
                })
                .collect();
        });
        let resp = send(&ctx.app, Method::GET, &uris[0], Body::empty()).await;
        assert_eq!(resp.status(), want);
    }
}

/// An upstream of `upstreams` (url, namespaces it owns) per entry, unauthenticated.
fn upstreams_of(entries: Vec<(String, Vec<String>)>) -> Vec<crate::config::DockerUpstream> {
    entries
        .into_iter()
        .map(|(url, namespaces)| crate::config::DockerUpstream {
            url,
            auth: None,
            namespace: None,
            prefix: None,
            namespaces,
            auth_env: None,
            trust_upstream_dates: false,
            date_token_file: None,
        })
        .collect()
}

/// #1198: in the fallback chain an upstream whose breaker is open is skipped, not asked, and
/// the next one serves the manifest and its blob.
#[tokio::test]
async fn an_open_upstream_is_skipped_for_the_next() {
    use crate::circuit_breaker::upstream_key;
    use wiremock::matchers::{any, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let blob = format!("sha256:{}", hex::encode(sha2::Sha256::digest(b"layer")));
    let manifest =
        br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:aaaa"},"layers":[]}"#.to_vec();
    let (skipped, serving) = (MockServer::start().await, MockServer::start().await);
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&skipped)
        .await;
    Mock::given(method("GET"))
        .and(path("/v2/myorg/app/manifests/1.0"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/vnd.oci.image.manifest.v1+json")
                .set_body_bytes(manifest.clone()),
        )
        .mount(&serving)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v2/myorg/app/blobs/{blob}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"layer".to_vec()))
        .mount(&serving)
        .await;
    let entries = vec![(skipped.uri(), Vec::new()), (serving.uri(), Vec::new())];
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.circuit_breaker.enabled = true;
        cfg.circuit_breaker.reset_timeout = 3600;
        cfg.docker.upstreams = upstreams_of(entries);
    });
    ctx.state
        .circuit_breaker
        .open_for_test(&upstream_key("docker", &skipped.uri()));

    let resp = send(
        &ctx.app,
        Method::GET,
        "/v2/myorg/app/manifests/1.0",
        Body::empty(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_bytes(resp).await.as_ref(), manifest.as_slice());
    let resp = send(
        &ctx.app,
        Method::GET,
        &format!("/v2/myorg/app/blobs/{blob}"),
        Body::empty(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_bytes(resp).await.as_ref(), b"layer");
}

/// #1198: a name bound to one upstream has no next upstream; its open breaker is a 503, and
/// the chain is not asked in its place.
#[tokio::test]
async fn a_bound_name_behind_an_open_breaker_is_503() {
    use crate::circuit_breaker::upstream_key;
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let (owner, chain) = (MockServer::start().await, MockServer::start().await);
    for server in [&owner, &chain] {
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(server)
            .await;
    }
    let entries = vec![
        (chain.uri(), Vec::new()),
        (owner.uri(), vec!["team-*".to_string()]),
    ];
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.circuit_breaker.enabled = true;
        cfg.circuit_breaker.reset_timeout = 3600;
        cfg.docker.upstreams = upstreams_of(entries);
    });
    ctx.state
        .circuit_breaker
        .open_for_test(&upstream_key("docker", &owner.uri()));
    let resp = send(
        &ctx.app,
        Method::GET,
        "/v2/team-a/service/manifests/1.0",
        Body::empty(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(resp.headers().get("retry-after").is_some());
}

/// #1198: a cached tag whose revalidation found its upstream skipped is served stale, as when
/// the upstream failed.
#[tokio::test]
async fn an_open_upstream_leaves_the_stale_manifest_served() {
    use crate::circuit_breaker::upstream_key;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let manifest =
        br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:aaaa"},"layers":[]}"#.to_vec();
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/vnd.oci.image.manifest.v1+json")
                .set_body_bytes(manifest.clone()),
        )
        .expect(1)
        .mount(&upstream)
        .await;
    let entries = vec![(upstream.uri(), Vec::new())];
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.circuit_breaker.enabled = true;
        cfg.circuit_breaker.reset_timeout = 3600;
        cfg.docker.upstreams = upstreams_of(entries);
    });
    let uri = "/v2/myorg/app/manifests/1.0";
    let resp = send(&ctx.app, Method::GET, uri, Body::empty()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    // The copy is written in the background: wait for it, with a deadline.
    let mut cached = false;
    for _ in 0..200 {
        if ctx
            .state
            .storage
            .list("docker/")
            .await
            .is_ok_and(|keys| !keys.is_empty())
        {
            cached = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(cached, "the manifest was not cached");

    ctx.state
        .circuit_breaker
        .open_for_test(&upstream_key("docker", &upstream.uri()));
    let resp = send(&ctx.app, Method::GET, uri, Body::empty()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("x-nora-stale").map(|v| v.as_bytes()),
        Some(b"true".as_slice())
    );
    assert_eq!(body_bytes(resp).await.as_ref(), manifest.as_slice());
}

/// #1189: every miss on the proxy path answers an OCI error body with
/// `Content-Type: application/json`, so a client prints the reason instead of `unknown:`. A
/// missing manifest or blob is the `MANIFEST_UNKNOWN` / `BLOB_UNKNOWN` a hosted miss
/// answers; a failed or skipped upstream is `UNAVAILABLE`; a refused credential stays
/// `DENIED` (#1196). The table is pinned in a snapshot.
#[tokio::test]
async fn a_proxied_miss_is_an_oci_error() {
    use crate::circuit_breaker::upstream_key;
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let blob = format!("sha256:{}", hex::encode(sha2::Sha256::digest(b"layer")));
    let manifest = "/v2/myorg/app/manifests/9.9".to_string();
    let layer = format!("/v2/myorg/app/blobs/{blob}");
    // (row, upstream answer, path, status, OCI code)
    let rows: [(&str, Option<u16>, &String, StatusCode, &str); 8] = [
        (
            "manifest-404",
            Some(404),
            &manifest,
            StatusCode::NOT_FOUND,
            "MANIFEST_UNKNOWN",
        ),
        (
            "blob-404",
            Some(404),
            &layer,
            StatusCode::NOT_FOUND,
            "BLOB_UNKNOWN",
        ),
        (
            "manifest-503",
            Some(503),
            &manifest,
            StatusCode::BAD_GATEWAY,
            "UNAVAILABLE",
        ),
        (
            "blob-503",
            Some(503),
            &layer,
            StatusCode::BAD_GATEWAY,
            "UNAVAILABLE",
        ),
        (
            "manifest-unreachable",
            None,
            &manifest,
            StatusCode::BAD_GATEWAY,
            "UNAVAILABLE",
        ),
        (
            "manifest-breaker-open",
            Some(200),
            &manifest,
            StatusCode::SERVICE_UNAVAILABLE,
            "UNAVAILABLE",
        ),
        (
            "manifest-refused",
            Some(401),
            &manifest,
            StatusCode::BAD_GATEWAY,
            "DENIED",
        ),
        (
            "unknown-host",
            Some(200),
            &"/v2/quay.io/myorg/app/manifests/9.9".to_string(),
            StatusCode::NOT_FOUND,
            "MANIFEST_UNKNOWN",
        ),
    ];
    let mut pinned = Vec::new();
    for (row, answer, uri, status, code) in rows {
        let server = MockServer::start().await;
        let mut template = ResponseTemplate::new(answer.unwrap_or(500));
        if answer == Some(401) {
            template = template.insert_header("Www-Authenticate", "Basic realm=\"harbor\"");
        }
        Mock::given(any())
            .respond_with(template)
            .mount(&server)
            .await;
        let url = if answer.is_some() {
            server.uri()
        } else {
            "http://127.0.0.1:9".to_string()
        };
        let key = upstream_key("docker", &url);
        let open = row.ends_with("breaker-open");
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.circuit_breaker.enabled = open;
            cfg.circuit_breaker.reset_timeout = 3600;
            cfg.docker.proxy_timeout = 1;
            cfg.docker.upstreams = vec![crate::config::DockerUpstream {
                url,
                auth: None,
                namespace: None,
                prefix: None,
                namespaces: Vec::new(),
                auth_env: None,
                trust_upstream_dates: false,
                date_token_file: None,
            }];
        });
        if open {
            ctx.state.circuit_breaker.open_for_test(&key);
        }
        let resp = send(&ctx.app, Method::GET, uri, Body::empty()).await;
        let got = resp.status();
        let content_type = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let retry_after = resp.headers().get("retry-after").is_some();
        let body: serde_json::Value =
            serde_json::from_slice(&body_bytes(resp).await).unwrap_or(serde_json::Value::Null);
        assert_eq!(got, status, "{row}");
        assert_eq!(body["errors"][0]["code"], code, "{row}: {body}");
        assert!(
            content_type.starts_with("application/json"),
            "{row}: {content_type}"
        );
        assert_eq!(retry_after, got == StatusCode::SERVICE_UNAVAILABLE, "{row}");
        // the upstream URL carries a random port: pin the key's shape, not the port
        let mut body = body;
        if let Some(m) = body["errors"][0]["message"].as_str() {
            body["errors"][0]["message"] =
                serde_json::Value::from(m.replace(&key, "docker:<upstream>"));
        }
        pinned.push(serde_json::json!({
            "row": row, "status": got.as_u16(), "content_type": content_type,
            "retry_after": retry_after, "body": body,
        }));
    }
    insta::assert_json_snapshot!("docker_proxied_miss_oci_errors", pinned);
}

/// A locally pushed manifest is authoritative: with global pull-through upstreams
/// configured, GET must serve it without revalidating against upstream — an unreachable
/// upstream must neither 404 the tag (serve_stale = false) nor stale-mark it.
#[tokio::test]
async fn test_hosted_manifest_skips_upstream_revalidation() {
    use crate::config::DockerUpstream;
    use crate::test_helpers::create_test_context_with_config;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.docker.serve_stale = false;
        cfg.docker.upstreams = vec![DockerUpstream {
            trust_upstream_dates: false,
            date_token_file: None,
            url: "http://127.0.0.1:1".into(),
            auth: None,
            auth_env: None,
            namespace: None,
            prefix: None,
            namespaces: Vec::new(),
        }];
    });

    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 0,
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "layers": []
    });
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();

    seed_zero_config(&ctx.state, "hosted-img").await;
    let put_resp = send(
        &ctx.app,
        Method::PUT,
        "/v2/hosted-img/manifests/v1",
        Body::from(manifest_bytes.clone()),
    )
    .await;
    assert_eq!(put_resp.status(), StatusCode::CREATED);

    let resp = send(
        &ctx.app,
        Method::GET,
        "/v2/hosted-img/manifests/v1",
        Body::empty(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().get("x-nora-stale").is_none(),
        "hosted manifest must not be served via the stale-while-error path"
    );
    let body = body_bytes(resp).await;
    assert_eq!(body.as_ref(), manifest_bytes.as_slice());
}

#[test]
fn push_record_is_a_record_naming_a_digest() {
    let meta = |digest: Option<&str>| {
        serde_json::to_vec(&super::ImageMetadata {
            push_timestamp: 7,
            pushed_digest: digest.map(str::to_string),
            ..Default::default()
        })
        .unwrap()
    };
    let sha256 = format!("sha256:{}", "a".repeat(64));
    let sha512 = format!("sha512:{}", "b".repeat(128));
    assert_eq!(
        super::push_record(&meta(Some(&sha256))).map(|m| m.push_timestamp),
        Some(7)
    );
    assert!(super::push_record(&meta(Some(&sha512))).is_some());
    for not_a_record in [
        meta(None),
        meta(Some("")),
        meta(Some("md5:abc")),
        meta(Some("SHA256:abc")),
        b"not json".to_vec(),
    ] {
        assert!(
            super::push_record(&not_a_record).is_none(),
            "{}",
            String::from_utf8_lossy(&not_a_record)
        );
    }
}

#[test]
fn content_has_digest_holds_digests_and_passes_tags() {
    use sha2::Digest;
    let body = b"manifest";
    let s256 = format!("sha256:{}", hex::encode(sha2::Sha256::digest(body)));
    let s512 = format!("sha512:{}", hex::encode(sha2::Sha512::digest(body)));
    assert!(super::content_has_digest(&s256, body));
    assert!(super::content_has_digest(&s512, body));
    assert!(!super::content_has_digest(&s256, b"other"));
    assert!(!super::content_has_digest(&s512, b"other"));
    assert!(!super::content_has_digest(
        &s256.to_uppercase().replace("SHA256", "sha256"),
        body
    ));
    assert!(!super::content_has_digest("sha256:", body));
    // The whole digest is compared: a reference that matches only in part, at any position,
    // is another digest.
    let hex = s256.strip_prefix("sha256:").unwrap();
    for i in 0..hex.len() {
        let mut other: Vec<u8> = hex.as_bytes().to_vec();
        other[i] = if other[i] == b'0' { b'1' } else { b'0' };
        let other = format!("sha256:{}", String::from_utf8(other).unwrap());
        assert!(!super::content_has_digest(&other, body), "position {i}");
    }
    assert!(!super::content_has_digest(
        &format!("sha256:{}", &hex[..12]),
        body
    ));
    assert!(!super::content_has_digest(&format!("{s256}0"), body));
    assert!(super::content_has_digest("latest", b"anything"));
    assert!(super::content_has_digest("v1.0", b""));
}

/// A manifest requested by digest is content-addressed: bytes from an upstream that hash to
/// another digest are neither served under the requested one nor cached there — on every way
/// an upstream is asked: the name as requested, the `library/` name of an official image, the
/// next upstream after a miss, and an upstream addressed by its prefix.
#[tokio::test]
async fn a_manifest_by_digest_is_served_only_if_it_has_that_digest() {
    use crate::config::DockerUpstream;
    use crate::test_helpers::create_test_context_with_config;
    use sha2::Digest;
    use wiremock::matchers::{any, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let wanted = b"{\"schemaVersion\":2,\"layers\":[]}".to_vec();
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&wanted)));
    let other = b"{\"schemaVersion\":2,\"layers\":[],\"x\":1}".to_vec();
    let manifest = |body: &[u8]| {
        ResponseTemplate::new(200)
            .insert_header(
                "content-type",
                "application/vnd.docker.distribution.manifest.v2+json",
            )
            .set_body_bytes(body.to_vec())
    };
    let upstream = |url: String, prefix: Option<&str>| DockerUpstream {
        trust_upstream_dates: false,
        date_token_file: None,
        url,
        auth: None,
        auth_env: None,
        namespace: None,
        prefix: prefix.map(str::to_string),
        namespaces: Vec::new(),
    };
    // (case, upstream answer for the asked name, request path, whether the answer is honest)
    for (case, honest) in [
        ("one upstream", false),
        ("library name", false),
        ("next upstream", false),
        ("prefixed upstream", false),
        ("one upstream", true),
        ("library name", true),
    ] {
        let body = if honest { &wanted } else { &other };
        let first = MockServer::start().await;
        let second = MockServer::start().await;
        let (upstreams, request) = match case {
            "one upstream" => {
                Mock::given(any())
                    .respond_with(manifest(body))
                    .mount(&first)
                    .await;
                (
                    vec![upstream(first.uri(), None)],
                    format!("/v2/corp/app/manifests/{digest}"),
                )
            }
            "library name" => {
                Mock::given(path(format!("/v2/library/nginx/manifests/{digest}")))
                    .respond_with(manifest(body))
                    .mount(&first)
                    .await;
                Mock::given(any())
                    .respond_with(ResponseTemplate::new(404))
                    .mount(&first)
                    .await;
                (
                    vec![upstream(first.uri(), None)],
                    format!("/v2/nginx/manifests/{digest}"),
                )
            }
            "next upstream" => {
                Mock::given(any())
                    .respond_with(ResponseTemplate::new(404))
                    .mount(&first)
                    .await;
                Mock::given(any())
                    .respond_with(manifest(body))
                    .mount(&second)
                    .await;
                (
                    vec![upstream(first.uri(), None), upstream(second.uri(), None)],
                    format!("/v2/corp/app/manifests/{digest}"),
                )
            }
            _ => {
                Mock::given(any())
                    .respond_with(manifest(body))
                    .mount(&first)
                    .await;
                (
                    vec![upstream(first.uri(), Some("hub"))],
                    format!("/v2/hub/corp/app/manifests/{digest}"),
                )
            }
        };
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.docker.upstreams = upstreams;
        });
        let holders = ctx.state.storage.holders();
        let resp = send(&ctx.app, Method::GET, &request, Body::empty()).await;
        let status = resp.status();
        let served = body_bytes(resp).await;
        if honest {
            assert_eq!(status, StatusCode::OK, "{case}: honest answer refused");
            assert_eq!(served.as_ref(), wanted.as_slice(), "{case}");
            continue;
        }
        assert_ne!(
            served.as_ref(),
            other.as_slice(),
            "{case}: served bytes of another digest ({status})"
        );
        crate::test_helpers::background_writes_done(&ctx.state.storage, holders).await;
        let cached: Vec<String> = ctx
            .state
            .storage
            .list("docker/")
            .await
            .unwrap()
            .into_iter()
            .filter(|k| k.contains(&digest))
            .collect();
        assert!(
            cached.is_empty(),
            "{case}: cached under the digest: {cached:?}"
        );
    }
}

/// A copy stored under a digest reference that hashes to another digest (cached before the
/// fetch checked it) is not that manifest: it is not served, and an honest upstream answer
/// replaces it; with no upstream it is a missing manifest.
#[tokio::test]
async fn a_stored_copy_by_digest_is_served_only_if_it_has_that_digest() {
    use crate::config::DockerUpstream;
    use crate::test_helpers::create_test_context_with_config;
    use sha2::Digest;
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let wanted = b"{\"schemaVersion\":2,\"layers\":[]}".to_vec();
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&wanted)));
    let other = b"{\"schemaVersion\":2,\"layers\":[],\"x\":1}".to_vec();
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header(
                    "content-type",
                    "application/vnd.docker.distribution.manifest.v2+json",
                )
                .set_body_bytes(wanted.clone()),
        )
        .mount(&server)
        .await;
    let upstream = DockerUpstream {
        trust_upstream_dates: false,
        date_token_file: None,
        url: server.uri(),
        auth: None,
        auth_env: None,
        namespace: None,
        prefix: None,
        namespaces: Vec::new(),
    };
    let ns = upstream.resolved_namespace();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.docker.upstreams = vec![upstream];
    });
    let proxied = super::manifest_key(Some(&ns), "corp/app", &digest);
    ctx.state.storage.put(&proxied, &other).await.unwrap();
    let request = format!("/v2/corp/app/manifests/{digest}");
    let resp = send(&ctx.app, Method::GET, &request, Body::empty()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_bytes(resp).await.as_ref(), wanted.as_slice());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    // Err while the background write replaces the file counts as "not yet".
    while ctx.state.storage.get(&proxied).await.ok().as_deref() != Some(wanted.as_slice()) {
        assert!(
            std::time::Instant::now() < deadline,
            "the other digest's bytes stayed under the digest"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let hosted = create_test_context_with_config(|cfg| cfg.docker.upstreams = Vec::new());
    hosted
        .state
        .storage
        .put(&super::manifest_key(None, "corp/app", &digest), &other)
        .await
        .unwrap();
    let resp = send(&hosted.app, Method::GET, &request, Body::empty()).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// A manifest pushed by digest is that digest's content: other bytes are refused with OCI
/// DIGEST_INVALID and nothing is stored.
#[tokio::test]
async fn a_manifest_pushed_by_digest_must_have_that_digest() {
    use sha2::Digest;
    let ctx = crate::test_helpers::create_test_context_with_config(|_| {});
    let pushed = table_manifest(PUSHED_CFG);
    seed_zero_config(&ctx.state, "corp/app").await;
    let other = format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(table_manifest(UPSTREAM_CFG)))
    );
    let resp = send(
        &ctx.app,
        Method::PUT,
        &format!("/v2/corp/app/manifests/{other}"),
        Body::from(pushed.clone()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = String::from_utf8_lossy(&body_bytes(resp).await).into_owned();
    assert!(body.contains("DIGEST_INVALID"), "{body}");
    let stored: Vec<String> = ctx
        .state
        .storage
        .list("docker/corp/app/manifests/")
        .await
        .unwrap();
    assert!(stored.is_empty(), "stored: {stored:?}");

    let own = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&pushed)));
    let resp = send(
        &ctx.app,
        Method::PUT,
        &format!("/v2/corp/app/manifests/{own}"),
        Body::from(pushed),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

/// COMPAT.md: pushing to a name that would otherwise proxy pins that tag to the pushed copy.
/// Also when the tag was pulled through the proxy before the push.
#[tokio::test]
async fn a_push_pins_a_tag_that_was_pulled_through_the_proxy() {
    use crate::config::DockerUpstream;
    use crate::test_helpers::create_test_context_with_config;
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let manifest = |config_digest: &str| {
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": 0,
                "digest": config_digest
            },
            "layers": []
        }))
        .unwrap()
    };
    let upstream_manifest =
        manifest("sha256:1111111111111111111111111111111111111111111111111111111111111111");
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header(
                    "content-type",
                    "application/vnd.docker.distribution.manifest.v2+json",
                )
                .set_body_bytes(upstream_manifest.clone()),
        )
        .mount(&server)
        .await;
    let uri = server.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.docker.upstreams = vec![DockerUpstream {
            trust_upstream_dates: false,
            date_token_file: None,
            url: uri,
            auth: None,
            auth_env: None,
            namespace: None,
            prefix: None,
            namespaces: Vec::new(),
        }];
    });

    let holders = ctx.state.storage.holders();
    let resp = send(
        &ctx.app,
        Method::GET,
        "/v2/corp/app/manifests/1.0",
        Body::empty(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        body_bytes(resp).await.as_ref(),
        upstream_manifest.as_slice()
    );
    // The proxied copy is cached first, so the push below must replace it.
    crate::test_helpers::background_writes_done(&ctx.state.storage, holders).await;

    let pushed =
        manifest("sha256:0000000000000000000000000000000000000000000000000000000000000000");
    seed_zero_config(&ctx.state, "corp/app").await;
    let put = send(
        &ctx.app,
        Method::PUT,
        "/v2/corp/app/manifests/1.0",
        Body::from(pushed.clone()),
    )
    .await;
    assert_eq!(put.status(), StatusCode::CREATED);

    let resp = send(
        &ctx.app,
        Method::GET,
        "/v2/corp/app/manifests/1.0",
        Body::empty(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        body_bytes(resp).await.as_ref(),
        pushed.as_slice(),
        "the pushed manifest answers its tag"
    );
}

/// Decision table for a pushed tag: helpers.
fn table_manifest(config_digest: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 0,
            "digest": config_digest
        },
        "layers": []
    }))
    .unwrap()
}

const PUSHED_CFG: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const UPSTREAM_CFG: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";

/// An upstream serving the same tag with its own manifest, and a context pointing at it.
async fn table_context() -> (
    wiremock::MockServer,
    crate::test_helpers::TestContext,
    String,
) {
    use crate::config::DockerUpstream;
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header(
                    "content-type",
                    "application/vnd.docker.distribution.manifest.v2+json",
                )
                .set_body_bytes(table_manifest(UPSTREAM_CFG)),
        )
        .mount(&server)
        .await;
    let upstream = DockerUpstream {
        trust_upstream_dates: false,
        date_token_file: None,
        url: server.uri(),
        auth: None,
        auth_env: None,
        namespace: None,
        prefix: None,
        namespaces: Vec::new(),
    };
    let ns = upstream.resolved_namespace();
    let ctx = crate::test_helpers::create_test_context_with_config(move |cfg| {
        cfg.docker.upstreams = vec![upstream];
    });
    (server, ctx, ns)
}

async fn table_push(ctx: &crate::test_helpers::TestContext) -> Vec<u8> {
    let pushed = table_manifest(PUSHED_CFG);
    seed_zero_config(&ctx.state, "corp/app").await;
    let put = send(
        &ctx.app,
        Method::PUT,
        "/v2/corp/app/manifests/1.0",
        Body::from(pushed.clone()),
    )
    .await;
    assert_eq!(put.status(), StatusCode::CREATED);
    pushed
}

async fn table_get(ctx: &crate::test_helpers::TestContext) -> Vec<u8> {
    let resp = send(
        &ctx.app,
        Method::GET,
        "/v2/corp/app/manifests/1.0",
        Body::empty(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    body_bytes(resp).await.to_vec()
}

/// Row 7: a push removes the proxied copy of its tag and the copy's metadata.
#[tokio::test]
async fn row7_a_push_removes_the_proxied_copy_of_its_tag() {
    let (_server, ctx, ns) = table_context().await;
    assert_eq!(table_get(&ctx).await, table_manifest(UPSTREAM_CFG));
    let proxied = super::manifest_key(Some(&ns), "corp/app", "1.0");
    let proxied_meta = super::manifest_meta_key(Some(&ns), "corp/app", "1.0");
    // The proxied copy is cached off the request path; its metadata is the task's last write.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while ctx.state.storage.stat(&proxied).await.is_none()
        || ctx.state.storage.stat(&proxied_meta).await.is_none()
    {
        assert!(
            std::time::Instant::now() < deadline,
            "proxied copy and its metadata cached"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    table_push(&ctx).await;
    assert!(
        ctx.state.storage.stat(&proxied).await.is_none(),
        "proxied copy left beside the push"
    );
    assert!(
        ctx.state.storage.stat(&proxied_meta).await.is_none(),
        "proxied copy's metadata left beside the push"
    );
}

/// Row 1, cost: a pull of a pushed tag reads its push record once (it answers the tag and dates
/// it for curation) and the pushed manifest — two reads. Reading the bare metadata a second time,
/// or the namespaced metadata a push makes moot, costs every pull of a pushed image a round trip.
#[tokio::test]
async fn row1_a_pull_of_a_pushed_tag_reads_its_metadata_once() {
    use crate::config::DockerUpstream;
    let (storage, ops) = crate::test_helpers::op_counting_storage();
    let upstream = DockerUpstream {
        trust_upstream_dates: false,
        date_token_file: None,
        url: "http://127.0.0.1:9".to_string(),
        auth: None,
        auth_env: None,
        namespace: None,
        prefix: None,
        namespaces: Vec::new(),
    };
    let ns = upstream.resolved_namespace();
    let ctx =
        crate::test_helpers::create_test_context_with_storage_and_config(storage, move |cfg| {
            cfg.docker.upstreams = vec![upstream];
        });
    assert_ne!(
        super::manifest_key(Some(&ns), "corp/app", "1.0"),
        super::manifest_key(None, "corp/app", "1.0")
    );
    let pushed = table_push(&ctx).await;
    ops.reset();
    assert_eq!(table_get(&ctx).await, pushed);
    assert_eq!(
        ops.snapshot().get("get").copied(),
        Some(2),
        "{:?}",
        ops.snapshot()
    );
}

/// Cost: a pull by digest of a proxied copy reads its metadata and the manifest — two reads.
/// The bare metadata is read up front only where the push record answers (a tag), never on
/// every pull.
#[tokio::test]
async fn a_pull_by_digest_of_a_proxied_copy_reads_two_documents() {
    use crate::config::DockerUpstream;
    use sha2::Digest;
    let (storage, ops) = crate::test_helpers::op_counting_storage();
    let upstream = DockerUpstream {
        trust_upstream_dates: false,
        date_token_file: None,
        url: "http://127.0.0.1:9".to_string(),
        auth: None,
        auth_env: None,
        namespace: None,
        prefix: None,
        namespaces: Vec::new(),
    };
    let ns = upstream.resolved_namespace();
    let ctx =
        crate::test_helpers::create_test_context_with_storage_and_config(storage, move |cfg| {
            cfg.docker.upstreams = vec![upstream];
        });
    let proxied = table_manifest(UPSTREAM_CFG);
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&proxied)));
    let meta = super::ImageMetadata {
        push_timestamp: 100,
        ..Default::default()
    };
    ctx.state
        .storage
        .put(
            &super::manifest_key(Some(&ns), "corp/app", &digest),
            &proxied,
        )
        .await
        .unwrap();
    ctx.state
        .storage
        .put(
            &super::manifest_meta_key(Some(&ns), "corp/app", &digest),
            &serde_json::to_vec(&meta).unwrap(),
        )
        .await
        .unwrap();
    ops.reset();
    let resp = send(
        &ctx.app,
        Method::GET,
        &format!("/v2/corp/app/manifests/{digest}"),
        Body::empty(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_bytes(resp).await.to_vec(), proxied);
    assert_eq!(
        ops.snapshot().get("get").copied(),
        Some(2),
        "{:?}",
        ops.snapshot()
    );
}

/// The sidecar publish date follows its decision table on every combination of the two metadata
/// documents (dated, undated, with a push record, absent, unreadable), with and without a
/// namespace, both when the request already holds the bare metadata and when the date reads it.
#[tokio::test]
async fn a_publish_date_follows_its_table_with_the_bare_metadata_read_once() {
    use std::sync::Arc;
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Doc {
        Absent,
        Dated,
        // Present but without a date: a namespaced one still wins over the bare one.
        Undated,
        // Dated, with a push record: here only a dated document.
        Pushed,
        // A push record without a date: here only an undated document.
        PushedUndated,
        Unreadable,
    }
    let (name, reference) = ("date-img", "v1");
    let mut seen = std::collections::BTreeSet::new();
    for ns in [Some("docker.io"), None] {
        let ns_key = super::manifest_meta_key(ns, name, reference);
        let bare_key = super::manifest_meta_key(None, name, reference);
        let docs = [
            Doc::Absent,
            Doc::Dated,
            Doc::Undated,
            Doc::Pushed,
            Doc::PushedUndated,
            Doc::Unreadable,
        ];
        for ns_doc in docs {
            for bare_doc in docs {
                if ns_key == bare_key && ns_doc != Doc::Absent {
                    continue;
                }
                let dir = tempfile::TempDir::new().unwrap();
                let path = dir.path().to_str().unwrap().to_string();
                let writer = crate::storage::Storage::from_backend(Arc::new(
                    crate::storage::LocalStorage::new(&path),
                ));
                for (key, doc, ts) in [(&ns_key, ns_doc, 100u64), (&bare_key, bare_doc, 200)] {
                    if doc != Doc::Absent {
                        let meta = super::ImageMetadata {
                            push_timestamp: if matches!(doc, Doc::Undated | Doc::PushedUndated) {
                                0
                            } else {
                                ts
                            },
                            pushed_digest: matches!(doc, Doc::Pushed | Doc::PushedUndated)
                                .then(|| format!("sha256:{}", "a".repeat(64))),
                            ..Default::default()
                        };
                        writer
                            .put(key, &serde_json::to_vec(&meta).unwrap())
                            .await
                            .unwrap();
                    }
                }
                let fail_prefix = match (
                    ns_doc == Doc::Unreadable && ns_key != bare_key,
                    bare_doc == Doc::Unreadable,
                ) {
                    (true, true) => "docker/".to_string(),
                    (true, false) => ns_key.clone(),
                    (false, true) => bare_key.clone(),
                    (false, false) => "\u{0}none".to_string(),
                };
                let storage =
                    crate::storage::Storage::from_backend(Arc::new(FailingPrefixBackend {
                        inner: crate::storage::LocalStorage::new(&path),
                        fail_prefix,
                    }));
                let unread = super::extract_docker_publish_date(
                    &storage,
                    name,
                    reference,
                    false,
                    ns,
                    &mut super::BareMeta::Unread,
                )
                .await;
                let mut once =
                    super::BareMeta::Read(super::read_bare_meta(&storage, name, reference).await);
                let read = super::extract_docker_publish_date(
                    &storage, name, reference, false, ns, &mut once,
                )
                .await;
                // The decision table: the namespaced document decides when it exists (a date, or none when
                // it has no date or cannot be read), and the bare one only when it does not. A push record
                // in a document changes nothing here: a tag a push answers is dated before this is asked.
                let date =
                    |doc: Doc, ts: i64| matches!(doc, Doc::Dated | Doc::Pushed).then_some(ts);
                let expected = if ns_key != bare_key && ns_doc != Doc::Absent {
                    date(ns_doc, 100)
                } else {
                    date(bare_doc, 200)
                };
                let case = format!("ns {ns:?}, namespaced {ns_doc:?}, bare {bare_doc:?}");
                assert_eq!(unread, expected, "unread: {case}");
                assert_eq!(read, expected, "read once: {case}");
                seen.insert(format!("{unread:?}"));
            }
        }
    }
    // The grid reaches every answer: the namespaced date, the bare one, and none.
    assert_eq!(seen.len(), 3, "{seen:?}");
}

/// A backend that, the first time `trigger` is read, applies `writes` before answering: a
/// concurrent push whose writes land while the request reads that document.
struct WriteOnReadBackend {
    inner: crate::storage::LocalStorage,
    trigger: String,
    writes: std::sync::Mutex<Option<Vec<(String, Vec<u8>)>>>,
}

#[async_trait::async_trait]
impl crate::storage::StorageBackend for WriteOnReadBackend {
    async fn put(&self, key: &str, data: &[u8], sha256: &str) -> crate::storage::Result<()> {
        self.inner.put(key, data, sha256).await
    }
    async fn get(&self, key: &str) -> crate::storage::Result<(axum::body::Bytes, Option<String>)> {
        if key == self.trigger {
            let pending = self.writes.lock().unwrap().take();
            for (k, v) in pending.unwrap_or_default() {
                use sha2::Digest;
                let sha = hex::encode(sha2::Sha256::digest(&v));
                self.inner.put(&k, &v, &sha).await.unwrap();
            }
        }
        self.inner.get(key).await
    }
    async fn pin(&self, key: &str) -> Option<String> {
        self.inner.pin(key).await
    }
    async fn delete(&self, key: &str) -> crate::storage::Result<()> {
        self.inner.delete(key).await
    }
    async fn list(&self, prefix: &str) -> crate::storage::Result<Vec<String>> {
        self.inner.list(prefix).await
    }
    async fn stat(&self, key: &str) -> Option<crate::storage::FileMeta> {
        self.inner.stat(key).await
    }
    async fn health_check(&self) -> bool {
        true
    }
    async fn total_size(&self) -> u64 {
        self.inner.total_size().await
    }
    async fn copy(&self, src: &str, dst: &str, sha256: Option<&str>) -> crate::storage::Result<()> {
        self.inner.copy(src, dst, sha256).await
    }
    async fn put_from_path(
        &self,
        key: &str,
        src: &std::path::Path,
        sha256: Option<&str>,
    ) -> crate::storage::Result<()> {
        self.inner.put_from_path(key, src, sha256).await
    }
    async fn get_reader(
        &self,
        key: &str,
    ) -> crate::storage::Result<(
        u64,
        Option<String>,
        std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
    )> {
        self.inner.get_reader(key).await
    }
    fn backend_name(&self) -> &'static str {
        "write-on-read"
    }
}

/// Rows 7b and R3, through curation (`min_release_age` 7d): a tag a push answers is dated by its
/// record, whatever its proxied copy's metadata says; a record without its manifest dates
/// nothing — the tag is dated by its proxied copy, which answers it. The answer's status is the
/// oracle: 200 for an old date, 403 for a fresh one.
#[tokio::test]
async fn row7b_curation_dates_a_tag_by_the_push_that_answers_it() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let old = now - 30 * 86_400;
    // (push record date, bare manifest kept, proxied copy's date, expected status)
    let rows = [
        (old, true, now, StatusCode::OK),
        (now, true, old, StatusCode::FORBIDDEN),
        (old, false, now, StatusCode::FORBIDDEN),
        (now, false, old, StatusCode::OK),
    ];
    for (pushed_at, manifest_kept, proxied_at, expected) in rows {
        use crate::config::DockerUpstream;
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header(
                        "content-type",
                        "application/vnd.docker.distribution.manifest.v2+json",
                    )
                    .set_body_bytes(table_manifest(UPSTREAM_CFG)),
            )
            .mount(&server)
            .await;
        let upstream = DockerUpstream {
            trust_upstream_dates: false,
            date_token_file: None,
            url: server.uri(),
            auth: None,
            auth_env: None,
            namespace: None,
            prefix: None,
            namespaces: Vec::new(),
        };
        let ns = upstream.resolved_namespace();
        let ctx = crate::test_helpers::create_test_context_with_config(move |cfg| {
            cfg.docker.upstreams = vec![upstream];
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.min_release_age = Some("7d".to_string());
        });
        let pushed = table_manifest(PUSHED_CFG);
        use sha2::Digest;
        let record = super::ImageMetadata {
            push_timestamp: pushed_at,
            pushed_digest: Some(format!(
                "sha256:{}",
                hex::encode(sha2::Sha256::digest(&pushed))
            )),
            ..Default::default()
        };
        let proxied_meta = super::ImageMetadata {
            push_timestamp: proxied_at,
            ..Default::default()
        };
        let storage = &ctx.state.storage;
        storage
            .put(
                &super::manifest_meta_key(None, "corp/app", "1.0"),
                &serde_json::to_vec(&record).unwrap(),
            )
            .await
            .unwrap();
        if manifest_kept {
            storage
                .put(&super::manifest_key(None, "corp/app", "1.0"), &pushed)
                .await
                .unwrap();
        }
        storage
            .put(
                &super::manifest_key(Some(&ns), "corp/app", "1.0"),
                &table_manifest(UPSTREAM_CFG),
            )
            .await
            .unwrap();
        storage
            .put(
                &super::manifest_meta_key(Some(&ns), "corp/app", "1.0"),
                &serde_json::to_vec(&proxied_meta).unwrap(),
            )
            .await
            .unwrap();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/v2/corp/app/manifests/1.0",
            Body::empty(),
        )
        .await;
        assert_eq!(
            resp.status(),
            expected,
            "pushed {pushed_at}, manifest kept {manifest_kept}, proxied {proxied_at}"
        );
    }
}

/// The second pull of a proxied tag is dated by NORA's own first fetch, so a global
/// `min_release_age` holds it (403) until the tag is that old; `[curation.docker]
/// min_release_age = "0d"` turns the age check off for docker alone (200).
#[tokio::test]
async fn docker_zero_min_release_age_lets_the_second_pull_of_a_fresh_tag_through() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for (docker_age, expected) in [(None, StatusCode::FORBIDDEN), (Some("0d"), StatusCode::OK)] {
        use crate::config::DockerUpstream;
        let upstream = DockerUpstream {
            trust_upstream_dates: false,
            date_token_file: None,
            url: "http://127.0.0.1:9".to_string(),
            auth: None,
            auth_env: None,
            namespace: None,
            prefix: None,
            namespaces: Vec::new(),
        };
        let ns = upstream.resolved_namespace();
        let ctx = crate::test_helpers::create_test_context_with_config(move |cfg| {
            cfg.docker.upstreams = vec![upstream];
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.min_release_age = Some("7d".to_string());
            cfg.curation.docker.min_release_age = docker_age.map(str::to_string);
        });
        let storage = &ctx.state.storage;
        storage
            .put(
                &super::manifest_key(Some(&ns), "corp/app", "1.0"),
                &table_manifest(UPSTREAM_CFG),
            )
            .await
            .unwrap();
        let cached = super::ImageMetadata {
            push_timestamp: now,
            ..Default::default()
        };
        storage
            .put(
                &super::manifest_meta_key(Some(&ns), "corp/app", "1.0"),
                &serde_json::to_vec(&cached).unwrap(),
            )
            .await
            .unwrap();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/v2/corp/app/manifests/1.0",
            Body::empty(),
        )
        .await;
        assert_eq!(
            resp.status(),
            expected,
            "docker min_release_age {docker_age:?}"
        );
    }
}

/// Row R3: a push record left without its bare manifest (a delete interrupted between the two)
/// answers nothing; the tag goes on as if it had no record — here its proxied copy answers.
#[tokio::test]
async fn row_r3_a_record_without_its_manifest_hands_the_tag_on() {
    let (_server, ctx, ns) = table_context().await;
    table_push(&ctx).await;
    ctx.state
        .storage
        .put(
            &super::manifest_key(Some(&ns), "corp/app", "1.0"),
            &table_manifest(UPSTREAM_CFG),
        )
        .await
        .unwrap();
    ctx.state
        .storage
        .delete(&super::manifest_key(None, "corp/app", "1.0"))
        .await
        .unwrap();
    assert!(ctx
        .state
        .storage
        .stat(&super::manifest_meta_key(None, "corp/app", "1.0"))
        .await
        .is_some());
    assert_eq!(table_get(&ctx).await, table_manifest(UPSTREAM_CFG));
}

/// Row R2, race: a pushed tag with a proxied copy beside it, re-pushed (its bare manifest, then
/// its record; the proxied copy not yet removed) between the pull's read of the push record and
/// its read of the manifest. The record still names the old digest, the bare bytes are the new
/// push: the tag is the push's, so the new bytes answer — never the proxied copy.
#[tokio::test]
async fn row_r2_a_re_push_between_the_record_and_the_manifest_answers_the_new_push() {
    use sha2::Digest;
    use std::sync::Arc;
    let (_server, ctx, ns) = table_context().await;
    table_push(&ctx).await;
    ctx.state
        .storage
        .put(
            &super::manifest_key(Some(&ns), "corp/app", "1.0"),
            &table_manifest(UPSTREAM_CFG),
        )
        .await
        .unwrap();
    let repushed =
        table_manifest("sha256:2222222222222222222222222222222222222222222222222222222222222222");
    let meta = super::ImageMetadata {
        push_timestamp: 1,
        pushed_digest: Some(format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(&repushed))
        )),
        ..Default::default()
    };
    let mut racy = ctx.state.clone();
    racy.storage = crate::storage::Storage::from_backend(Arc::new(WriteOnReadBackend {
        inner: crate::storage::LocalStorage::new(ctx._tempdir.path().to_str().unwrap()),
        trigger: super::manifest_key(None, "corp/app", "1.0"),
        writes: std::sync::Mutex::new(Some(vec![
            (
                super::manifest_key(None, "corp/app", "1.0"),
                repushed.clone(),
            ),
            (
                super::manifest_meta_key(None, "corp/app", "1.0"),
                serde_json::to_vec(&meta).unwrap(),
            ),
        ])),
    }));
    let resp = get_manifest_via_dispatch(&racy, "corp/app/manifests/1.0").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let got = body_bytes(resp).await.to_vec();
    assert!(
        got != table_manifest(UPSTREAM_CFG),
        "the proxied copy answered a pushed tag"
    );
    assert_eq!(got, repushed);
}

/// Row 1, race: a proxied copy written after the push (a fetch that was in flight) does not
/// take the tag back.
#[tokio::test]
async fn row1_a_proxied_copy_written_after_the_push_does_not_win() {
    let (_server, ctx, ns) = table_context().await;
    let pushed = table_push(&ctx).await;
    let proxied = super::manifest_key(Some(&ns), "corp/app", "1.0");
    ctx.state
        .storage
        .put(&proxied, &table_manifest(UPSTREAM_CFG))
        .await
        .unwrap();
    assert_eq!(table_get(&ctx).await, pushed);
    let head = send(
        &ctx.app,
        Method::HEAD,
        "/v2/corp/app/manifests/1.0",
        Body::empty(),
    )
    .await;
    use sha2::Digest;
    let want = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&pushed)));
    assert_eq!(
        head.headers()
            .get("docker-content-digest")
            .unwrap()
            .to_str()
            .unwrap(),
        want
    );
}

/// Row 1, failed reads: with a proxied copy beside a push, a storage error reading the push
/// record or the pushed manifest is a 500 — never the proxied copy.
#[tokio::test]
async fn row1_a_failed_read_of_the_push_is_a_500_not_the_proxied_copy() {
    use std::sync::Arc;
    for failing in [
        "docker/corp/app/manifests/1.0.meta.json",
        "docker/corp/app/manifests/1.0.json",
    ] {
        let (_server, ctx, ns) = table_context().await;
        table_push(&ctx).await;
        ctx.state
            .storage
            .put(
                &super::manifest_key(Some(&ns), "corp/app", "1.0"),
                &table_manifest(UPSTREAM_CFG),
            )
            .await
            .unwrap();
        let mut flaky = ctx.state.clone();
        flaky.storage = crate::storage::Storage::from_backend(Arc::new(FailingPrefixBackend {
            inner: crate::storage::LocalStorage::new(ctx._tempdir.path().to_str().unwrap()),
            fail_prefix: failing.to_string(),
        }));
        let resp = get_manifest_via_dispatch(&flaky, "corp/app/manifests/1.0").await;
        assert_eq!(
            resp.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "{failing} unreadable"
        );
    }
}

/// Row 5.3: a delete of a pushed tag whose push record cannot be read answers 500 and removes
/// nothing — the tag, its metadata and the pushed manifest under its digest stay, as a pull of
/// the tag answers 500. Control: with the record readable the same delete answers 202.
#[tokio::test]
async fn row5_a_delete_that_cannot_read_the_push_record_removes_nothing() {
    use sha2::Digest;
    use std::sync::Arc;
    for failing in [true, false] {
        let (_server, ctx, ns) = table_context().await;
        let pushed = table_push(&ctx).await;
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&pushed)));
        let mut state = ctx.state.clone();
        if failing {
            state.storage = crate::storage::Storage::from_backend(Arc::new(FailingPrefixBackend {
                inner: crate::storage::LocalStorage::new(ctx._tempdir.path().to_str().unwrap()),
                fail_prefix: "docker/corp/app/manifests/1.0.meta.json".to_string(),
            }));
        }
        let resp = {
            use axum::extract::{Path, State};
            use axum::http::Uri;
            use axum::Extension;
            super::docker_v2_dispatch(
                State(state),
                Method::DELETE,
                Path("corp/app/manifests/1.0".to_string()),
                Extension(crate::auth::NamespaceAuthority::Unrestricted),
                "/v2/corp/app/manifests/1.0".parse::<Uri>().unwrap(),
                axum::http::HeaderMap::new(),
                Body::empty(),
            )
            .await
        };
        let kept = [
            super::manifest_key(None, "corp/app", "1.0"),
            super::manifest_meta_key(None, "corp/app", "1.0"),
            super::manifest_key(None, "corp/app", &digest),
        ];
        if failing {
            assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
            for key in &kept {
                assert!(ctx.state.storage.stat(key).await.is_some(), "{key} removed");
            }
        } else {
            assert_eq!(resp.status(), StatusCode::ACCEPTED);
            for key in &kept {
                assert!(ctx.state.storage.stat(key).await.is_none(), "{key} left");
            }
        }
        let _ = ns;
    }
}

/// Row 5.4: a delete by digest whose tags cannot all be read (here the push record of the tag
/// that answers with it) answers 500 and removes nothing; with the record readable it removes
/// the tag with the manifest (#658).
#[tokio::test]
async fn row5_a_delete_by_digest_that_cannot_read_a_tag_removes_nothing() {
    use sha2::Digest;
    use std::sync::Arc;
    // The tag's push record unreadable, the bare listing unreadable, the namespaced listing
    // unreadable, nothing failing.
    for case in 0..4 {
        let (_server, ctx, ns) = table_context().await;
        let fail_prefix = match case {
            0 => Some("docker/corp/app/manifests/1.0.meta.json".to_string()),
            1 => Some("docker/corp/app/manifests/".to_string()),
            2 => Some(format!("docker/{ns}/corp/app/manifests/")),
            _ => None,
        };
        let failing = fail_prefix.is_some();
        let pushed = table_push(&ctx).await;
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&pushed)));
        let mut state = ctx.state.clone();
        if let Some(fail_prefix) = fail_prefix {
            state.storage = crate::storage::Storage::from_backend(Arc::new(FailingPrefixBackend {
                inner: crate::storage::LocalStorage::new(ctx._tempdir.path().to_str().unwrap()),
                fail_prefix,
            }));
        }
        let path = format!("corp/app/manifests/{digest}");
        let resp = {
            use axum::extract::{Path, State};
            use axum::http::Uri;
            use axum::Extension;
            super::docker_v2_dispatch(
                State(state),
                Method::DELETE,
                Path(path.clone()),
                Extension(crate::auth::NamespaceAuthority::Unrestricted),
                format!("/v2/{path}").parse::<Uri>().unwrap(),
                axum::http::HeaderMap::new(),
                Body::empty(),
            )
            .await
        };
        let tag = super::manifest_key(None, "corp/app", "1.0");
        let by_digest = super::manifest_key(None, "corp/app", &digest);
        if failing {
            assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert!(ctx.state.storage.stat(&tag).await.is_some());
            assert!(ctx.state.storage.stat(&by_digest).await.is_some());
        } else {
            assert_eq!(resp.status(), StatusCode::ACCEPTED);
            assert!(ctx.state.storage.stat(&tag).await.is_none());
            assert!(ctx.state.storage.stat(&by_digest).await.is_none());
        }
    }
}

/// A push by digest with other bytes is refused also where an upstream is configured (the
/// name then has an upstream namespace).
#[tokio::test]
async fn a_push_by_digest_with_other_bytes_is_refused_beside_an_upstream() {
    use sha2::Digest;
    let (_server, ctx, ns) = table_context().await;
    seed_zero_config(&ctx.state, "corp/app").await;
    let pushed = table_manifest(PUSHED_CFG);
    let other = format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(table_manifest(UPSTREAM_CFG)))
    );
    let resp = send(
        &ctx.app,
        Method::PUT,
        &format!("/v2/corp/app/manifests/{other}"),
        Body::from(pushed),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    for key in [
        super::manifest_key(None, "corp/app", &other),
        super::manifest_key(Some(&ns), "corp/app", &other),
    ] {
        assert!(
            ctx.state.storage.stat(&key).await.is_none(),
            "{key} written"
        );
    }
}

/// Deleting a pushed manifest by its digest takes its tag back to the upstream, also when a
/// proxied copy of the tag was written after the push: the tag resolves as a read does.
#[tokio::test]
async fn a_delete_by_digest_of_a_push_gives_the_tag_back_to_the_upstream() {
    use sha2::Digest;
    let (_server, ctx, ns) = table_context().await;
    let pushed = table_push(&ctx).await;
    ctx.state
        .storage
        .put(
            &super::manifest_key(Some(&ns), "corp/app", "1.0"),
            &table_manifest(UPSTREAM_CFG),
        )
        .await
        .unwrap();
    assert_eq!(table_get(&ctx).await, pushed);
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&pushed)));
    let resp = send(
        &ctx.app,
        Method::DELETE,
        &format!("/v2/corp/app/manifests/{digest}"),
        Body::empty(),
    )
    .await;
    assert!(resp.status().is_success(), "{}", resp.status());
    assert_eq!(table_get(&ctx).await, table_manifest(UPSTREAM_CFG));
    assert!(ctx
        .state
        .storage
        .stat(&super::manifest_key(None, "corp/app", "1.0"))
        .await
        .is_none());
}

/// Row 3: a bare manifest without the push record (pushed before 1.4.0, or a flat proxy
/// cache before #349) beside a proxied copy keeps today's answer: the proxied copy.
#[tokio::test]
async fn row3_a_bare_manifest_without_a_record_keeps_todays_answer() {
    let (_server, ctx, ns) = table_context().await;
    let old = table_manifest(PUSHED_CFG);
    ctx.state
        .storage
        .put("docker/corp/app/manifests/1.0.json", &old)
        .await
        .unwrap();
    let meta = serde_json::to_vec(&super::ImageMetadata::default()).unwrap();
    ctx.state
        .storage
        .put("docker/corp/app/manifests/1.0.meta.json", &meta)
        .await
        .unwrap();
    let proxied = super::manifest_key(Some(&ns), "corp/app", "1.0");
    ctx.state
        .storage
        .put(&proxied, &table_manifest(UPSTREAM_CFG))
        .await
        .unwrap();
    assert_eq!(table_get(&ctx).await, table_manifest(UPSTREAM_CFG));
}

/// Row 1a: a bare manifest other than the bytes its push record names is a re-push in progress
/// (the bare key is written only by a push): the tag is still the push's, and those bytes answer
/// it — never the proxied copy beside it.
#[tokio::test]
async fn row1a_a_record_for_other_bytes_still_answers_with_the_bare_manifest() {
    let (_server, ctx, ns) = table_context().await;
    table_push(&ctx).await;
    ctx.state
        .storage
        .put(
            "docker/corp/app/manifests/1.0.json",
            &table_manifest(UPSTREAM_CFG.replace('1', "2").as_str()),
        )
        .await
        .unwrap();
    let proxied = super::manifest_key(Some(&ns), "corp/app", "1.0");
    ctx.state
        .storage
        .put(&proxied, &table_manifest(UPSTREAM_CFG))
        .await
        .unwrap();
    assert_eq!(
        table_get(&ctx).await,
        table_manifest(UPSTREAM_CFG.replace('1', "2").as_str())
    );
}

/// A deleted push gives the tag back to the upstream.
#[tokio::test]
async fn a_deleted_push_gives_the_tag_back_to_the_upstream() {
    let (_server, ctx, _ns) = table_context().await;
    table_push(&ctx).await;
    let del = send(
        &ctx.app,
        Method::DELETE,
        "/v2/corp/app/manifests/1.0",
        Body::empty(),
    )
    .await;
    assert!(del.status().is_success(), "{}", del.status());
    assert_eq!(table_get(&ctx).await, table_manifest(UPSTREAM_CFG));
}

/// A pull of a locally pushed image counts against that image. With an upstream configured
/// every name resolves to the upstream's namespace, but a hosted manifest is served from its
/// bare key, and its pull statistics go to the pushed manifest's own metadata — by tag and
/// by digest — with nothing written under the namespace.
#[tokio::test]
async fn a_hosted_pull_counts_against_the_pushed_image() {
    use crate::config::DockerUpstream;
    use crate::test_helpers::create_test_context_with_config;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.docker.upstreams = vec![DockerUpstream {
            trust_upstream_dates: false,
            date_token_file: None,
            url: "http://127.0.0.1:1".into(),
            auth: None,
            auth_env: None,
            namespace: Some("docker.io".into()),
            prefix: None,
            namespaces: Vec::new(),
        }];
    });
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 0,
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "layers": []
    });
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let digest = format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(&manifest_bytes))
    );
    seed_zero_config(&ctx.state, "hosted-img").await;
    let put = send(
        &ctx.app,
        Method::PUT,
        "/v2/hosted-img/manifests/v1",
        Body::from(manifest_bytes),
    )
    .await;
    assert_eq!(put.status(), StatusCode::CREATED);
    let pushed_at = |state: crate::AppState| async move {
        super::extract_docker_publish_date(
            &state.storage,
            "hosted-img",
            "v1",
            false,
            Some("docker.io"),
            &mut super::BareMeta::Unread,
        )
        .await
    };
    let date = pushed_at(ctx.state.clone()).await;
    assert!(date.is_some(), "a pushed image has a publish date");

    for uri in [
        "/v2/hosted-img/manifests/v1".to_string(),
        "/v2/hosted-img/manifests/v1".to_string(),
        format!("/v2/hosted-img/manifests/{digest}"),
    ] {
        let resp = send(&ctx.app, Method::GET, &uri, Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK, "{uri}");
    }

    // #1114: pull stats live in the in-memory accumulator (flushed to a
    // .stats.json sidecar), read via current_pull_stats. record() runs
    // synchronously on the GET path, so the counts are already visible.
    let downloads = |key: String| {
        let state = ctx.state.clone();
        async move { Some(super::current_pull_stats(&state, &key).await.downloads) }
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let by_tag = downloads("docker/hosted-img/manifests/v1.meta.json".into()).await;
        let by_digest = downloads(format!("docker/hosted-img/manifests/{digest}.meta.json")).await;
        if by_tag == Some(2) && by_digest == Some(1) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "pushed image's own metadata: by tag {by_tag:?}, by digest {by_digest:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let elsewhere = ctx.state.storage.list("docker/docker.io/").await.unwrap();
    assert!(
        elsewhere.is_empty(),
        "written under the namespace: {elsewhere:?}"
    );
    // Curation still reads the push date after the pulls.
    assert_eq!(pushed_at(ctx.state.clone()).await, date);
}

/// #1114: a manifest pull must NOT rewrite its `.meta.json`. Pull statistics
/// (downloads, last_pulled) are accumulated off the request path and flushed in
/// batches to a separate sidecar, so the integrity-relevant `.meta.json` that a
/// concurrent request reads (`extract_docker_publish_date`) is never rewritten by
/// a pull — the source of the false INTEGRITY VIOLATION on healthy data (33-41
/// per 100 GETs on 1.3.5). RED before V3: `update_metadata_on_pull` rewrites the
/// `.meta.json` on every GET (downloads += 1, last_pulled = now).
#[tokio::test]
async fn a_pull_does_not_rewrite_the_manifest_meta_json() {
    let ctx = create_test_context();
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 0,
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "layers": []
    });
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    seed_zero_config(&ctx.state, "stable-img").await;
    let put = send(
        &ctx.app,
        Method::PUT,
        "/v2/stable-img/manifests/v1",
        Body::from(manifest_bytes),
    )
    .await;
    assert_eq!(put.status(), StatusCode::CREATED);

    let meta_key = "docker/stable-img/manifests/v1.meta.json";
    let before = ctx
        .state
        .storage
        .get(meta_key)
        .await
        .expect("meta written at push");

    let holders = ctx.state.storage.holders();
    for _ in 0..5 {
        let resp = send(
            &ctx.app,
            Method::GET,
            "/v2/stable-img/manifests/v1",
            Body::empty(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
    // Every off-request-path stats write has ended before the assertion.
    crate::test_helpers::background_writes_done(&ctx.state.storage, holders).await;

    let after = ctx
        .state
        .storage
        .get(meta_key)
        .await
        .expect("meta still present");
    assert_eq!(
        before, after,
        "a pull rewrote the manifest .meta.json (stats must go to the off-path sidecar, not the integrity meta)"
    );
}

/// #1114: the same holds under the real trigger — a herd of parallel pulls
/// of one manifest (the docker proxy's thundering herd). On 1.3.5 each pull's
/// off-path stats write raced the others and the request-path publish-date read,
/// logging INTEGRITY VIOLATION on healthy data (19 even from one client pulling
/// back-to-back). A batched off-path sidecar leaves `.meta.json` byte-identical
/// no matter how many concurrent pulls land.
#[tokio::test]
async fn concurrent_pulls_do_not_rewrite_the_manifest_meta_json() {
    let ctx = create_test_context();
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 0,
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "layers": []
    });
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    seed_zero_config(&ctx.state, "herd-img").await;
    let put = send(
        &ctx.app,
        Method::PUT,
        "/v2/herd-img/manifests/v1",
        Body::from(manifest_bytes),
    )
    .await;
    assert_eq!(put.status(), StatusCode::CREATED);

    let meta_key = "docker/herd-img/manifests/v1.meta.json";
    let before = ctx
        .state
        .storage
        .get(meta_key)
        .await
        .expect("meta written at push");

    let holders = ctx.state.storage.holders();
    let mut handles = Vec::new();
    for _ in 0..12 {
        let app = ctx.app.clone();
        handles.push(tokio::spawn(async move {
            send(
                &app,
                Method::GET,
                "/v2/herd-img/manifests/v1",
                Body::empty(),
            )
            .await
            .status()
        }));
    }
    for h in handles {
        assert_eq!(h.await.unwrap(), StatusCode::OK);
    }
    // Every off-request-path stats write has ended before the assertion.
    crate::test_helpers::background_writes_done(&ctx.state.storage, holders).await;

    let after = ctx
        .state
        .storage
        .get(meta_key)
        .await
        .expect("meta still present");
    assert_eq!(
        before, after,
        "concurrent pulls rewrote the manifest .meta.json"
    );
}

/// #1114 unit: the pull-stats accumulator counts, peeks the un-flushed
/// delta, keeps last_pulled as the max seen, and drains to empty.
#[test]
fn pull_stats_accumulator_counts_peeks_and_drains() {
    let acc = super::PullStatsAccumulator::default();
    acc.record("k1", 100);
    acc.record("k1", 200);
    acc.record("k2", 150);
    assert_eq!(
        acc.peek("k1"),
        super::PullDelta {
            downloads: 2,
            last_pulled: 200
        }
    );
    assert_eq!(
        acc.peek("k2"),
        super::PullDelta {
            downloads: 1,
            last_pulled: 150
        }
    );
    assert_eq!(acc.peek("absent"), super::PullDelta::default());

    let mut drained = acc.drain();
    drained.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        drained,
        vec![
            (
                "k1".to_string(),
                super::PullDelta {
                    downloads: 2,
                    last_pulled: 200
                }
            ),
            (
                "k2".to_string(),
                super::PullDelta {
                    downloads: 1,
                    last_pulled: 150
                }
            ),
        ]
    );
    assert_eq!(acc.peek("k1"), super::PullDelta::default());
    assert!(acc.drain().is_empty());

    // last_pulled is the max seen, never regressed by a later-but-smaller now.
    acc.record("k1", 50);
    acc.record("k1", 40);
    assert_eq!(
        acc.peek("k1"),
        super::PullDelta {
            downloads: 2,
            last_pulled: 50
        }
    );
}

/// Minimal hosted manifest for the flush tests: push `stable-img:v1`, return
/// its meta key. Mirrors the push the other V3 tests use.
async fn push_stable_img(ctx: &crate::test_helpers::TestContext) -> &'static str {
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 0,
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "layers": []
    });
    seed_zero_config(&ctx.state, "stable-img").await;
    let put = send(
        &ctx.app,
        Method::PUT,
        "/v2/stable-img/manifests/v1",
        Body::from(serde_json::to_vec(&manifest).unwrap()),
    )
    .await;
    assert_eq!(put.status(), StatusCode::CREATED);
    "docker/stable-img/manifests/v1.meta.json"
}

/// #1114 (M5): the flush LOOP persists on an interval tick, not only on
/// shutdown. Without the tick flush a crash loses every count since start,
/// not "at most one interval" as the soft-state contract promises. A short
/// interval drives a real tick; the assert is taken before any cancellation,
/// so a loop that flushes only on shutdown fails it.
#[tokio::test]
async fn a_flush_loop_tick_persists_the_sidecar_before_shutdown() {
    let ctx = create_test_context();
    let meta_key = push_stable_img(&ctx).await;
    ctx.state.pull_stats.record(meta_key, 100);
    let handle = tokio::spawn(super::pull_stats_flush_loop(
        ctx.state.clone(),
        std::time::Duration::from_millis(10),
    ));
    let stats_key = "docker/stable-img/manifests/v1.stats.json";
    let mut persisted = false;
    for _ in 0..200 {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        if ctx.state.storage.get(stats_key).await.is_ok() {
            persisted = true;
            break;
        }
    }
    ctx.state.cancel_token.cancel();
    let _ = handle.await;
    assert!(
        persisted,
        "a tick must flush the sidecar before any shutdown (the loss bound depends on it)"
    );
}

/// #1114 positive control: a flush actually PERSISTS the stats to the
/// `.stats.json` sidecar for a live manifest (the guard must find the
/// manifest at `…/v1.json`, not `…/v1`). This is the control that was
/// missing — without it the flush guard was vacuous and the stats were
/// silently dropped. RED if the flush never writes the sidecar.
#[tokio::test]
async fn a_flush_persists_the_pull_stats_sidecar() {
    let ctx = create_test_context();
    let meta_key = push_stable_img(&ctx).await;
    let stats_key = "docker/stable-img/manifests/v1.stats.json";

    for _ in 0..3 {
        let r = send(
            &ctx.app,
            Method::GET,
            "/v2/stable-img/manifests/v1",
            Body::empty(),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
    }
    // Batched: nothing in the sidecar until a flush runs.
    assert!(
        ctx.state.storage.get(stats_key).await.is_err(),
        "sidecar must not exist before a flush"
    );

    super::flush_pull_stats(&ctx.state).await;

    let raw = ctx
        .state
        .storage
        .get(stats_key)
        .await
        .expect("flush must persist the .stats.json sidecar");
    let sidecar: super::StatsSidecar = serde_json::from_slice(&raw).unwrap();
    assert_eq!(sidecar.downloads, 3, "three pulls persisted");
    assert!(sidecar.last_pulled > 0, "last_pulled persisted");
    // current_pull_stats equals the flushed value (accumulator drained).
    assert_eq!(
        super::current_pull_stats(&ctx.state, meta_key)
            .await
            .downloads,
        3
    );
}

/// (M8, M12): the read path SUMS the flushed count and the pending delta;
/// a later flush ADVANCES last_pulled past the flushed value.
#[tokio::test]
async fn read_sums_pending_and_flush_advances_last_pulled() {
    let ctx = create_test_context();
    let meta_key = push_stable_img(&ctx).await;
    ctx.state.pull_stats.record(meta_key, 100);
    ctx.state.pull_stats.record(meta_key, 100);
    super::flush_pull_stats(&ctx.state).await;
    ctx.state.pull_stats.record(meta_key, 200);
    assert_eq!(
        super::current_pull_stats(&ctx.state, meta_key)
            .await
            .downloads,
        3
    );
    super::flush_pull_stats(&ctx.state).await;
    let raw = ctx
        .state
        .storage
        .get("docker/stable-img/manifests/v1.stats.json")
        .await
        .unwrap();
    let s: super::StatsSidecar = serde_json::from_slice(&raw).unwrap();
    assert_eq!((s.downloads, s.last_pulled), (3, 200));
}

/// #1114: legacy counts in a pre-V3 `.meta.json` are migrated into the
/// sidecar on the first flush — not lost, and not re-migrated (doubled) on
/// later flushes (the sidecar becomes authoritative once written).
#[tokio::test]
async fn flush_migrates_legacy_meta_counts_once() {
    let ctx = create_test_context();
    let meta_key = push_stable_img(&ctx).await;
    let stats_key = "docker/stable-img/manifests/v1.stats.json";

    // Seed a pre-V3 .meta.json carrying 5 downloads.
    let mut m: super::ImageMetadata =
        serde_json::from_slice(&ctx.state.storage.get(meta_key).await.unwrap()).unwrap();
    m.downloads = 5;
    m.last_pulled = 1_000;
    ctx.state
        .storage
        .put(meta_key, &serde_json::to_vec(&m).unwrap())
        .await
        .unwrap();

    let pull = || async {
        let r = send(
            &ctx.app,
            Method::GET,
            "/v2/stable-img/manifests/v1",
            Body::empty(),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
    };

    pull().await;
    super::flush_pull_stats(&ctx.state).await;
    let read = |k: &'static str| {
        let st = ctx.state.storage.clone();
        async move { serde_json::from_slice::<super::StatsSidecar>(&st.get(k).await.unwrap()).unwrap() }
    };
    assert_eq!(
        read(stats_key).await.downloads,
        6,
        "legacy 5 migrated + 1 new, not lost"
    );

    pull().await;
    super::flush_pull_stats(&ctx.state).await;
    assert_eq!(
        read(stats_key).await.downloads,
        7,
        "second flush adds 1 to the sidecar, does not re-migrate the legacy 5"
    );
}

/// A pull leaves the push date curation reads where it was, even when the
/// pull comes long after the push (the date is seeded in the past, so a pull that
/// rewrote it cannot match by landing in the same second).
#[tokio::test]
async fn a_later_pull_keeps_the_push_date() {
    use crate::config::DockerUpstream;
    use crate::test_helpers::create_test_context_with_config;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.docker.upstreams = vec![DockerUpstream {
            trust_upstream_dates: false,
            date_token_file: None,
            url: "http://127.0.0.1:1".into(),
            auth: None,
            auth_env: None,
            namespace: Some("docker.io".into()),
            prefix: None,
            namespaces: Vec::new(),
        }];
    });
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 0,
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "layers": []
    });
    seed_zero_config(&ctx.state, "aged-img").await;
    let put = send(
        &ctx.app,
        Method::PUT,
        "/v2/aged-img/manifests/v1",
        Body::from(serde_json::to_vec(&manifest).unwrap()),
    )
    .await;
    assert_eq!(put.status(), StatusCode::CREATED);
    let meta_key = "docker/aged-img/manifests/v1.meta.json";
    let mut meta: super::ImageMetadata =
        serde_json::from_slice(&ctx.state.storage.get(meta_key).await.unwrap()).unwrap();
    meta.push_timestamp = 1_000_000;
    ctx.state
        .storage
        .put(meta_key, &serde_json::to_vec(&meta).unwrap())
        .await
        .unwrap();

    let resp = send(
        &ctx.app,
        Method::GET,
        "/v2/aged-img/manifests/v1",
        Body::empty(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let downloads = Some(
            super::current_pull_stats(&ctx.state, meta_key)
                .await
                .downloads,
        );
        if downloads == Some(1) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "downloads {downloads:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let date = super::extract_docker_publish_date(
        &ctx.state.storage,
        "aged-img",
        "v1",
        false,
        Some("docker.io"),
        &mut super::BareMeta::Unread,
    )
    .await;
    assert_eq!(date, Some(1_000_000));
}

/// Control for the test above: a proxied copy, served from its namespaced key, keeps
/// counting against that copy's metadata, not against a bare (hosted) key.
#[tokio::test]
async fn a_proxied_pull_counts_against_the_proxied_copy() {
    use crate::config::DockerUpstream;
    use crate::test_helpers::create_test_context_with_config;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.docker.upstreams = vec![DockerUpstream {
            trust_upstream_dates: false,
            date_token_file: None,
            url: "http://127.0.0.1:1".into(),
            auth: None,
            auth_env: None,
            namespace: Some("docker.io".into()),
            prefix: None,
            namespaces: Vec::new(),
        }];
    });
    let manifest = br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:aaaa"},"layers":[]}"#;
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(manifest)));
    let key = super::manifest_key(Some("docker.io"), "library/proxied", &digest);
    ctx.state.storage.put(&key, manifest).await.unwrap();

    let uri = format!("/v2/library/proxied/manifests/{digest}");
    for _ in 0..2 {
        let resp = send(&ctx.app, Method::GET, &uri, Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
    let meta_key = super::manifest_meta_key(Some("docker.io"), "library/proxied", &digest);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let downloads = Some(
            super::current_pull_stats(&ctx.state, &meta_key)
                .await
                .downloads,
        );
        if downloads == Some(2) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "proxied copy's metadata: {downloads:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let bare = super::manifest_meta_key(None, "library/proxied", &digest);
    assert!(ctx.state.storage.stat(&bare).await.is_none(), "{bare}");
}

/// Provenance invariant that #868's hosted/proxied inference depends on: a local push
/// writes the BARE manifest key (`docker/{name}/manifests/{ref}.json`, no namespace
/// segment). `get_manifest` reads a bare-key hit as a hosted (locally pushed) manifest —
/// served authoritatively, no upstream revalidation. If `put_manifest` ever wrote a
/// namespaced key, hosted and proxied manifests would become indistinguishable and a
/// proxied tag could be served stale forever — so this must fail loudly.
#[tokio::test]
async fn test_local_push_writes_bare_manifest_key() {
    let ctx = create_test_context();
    seed_zero_config(&ctx.state, "prov-img").await;

    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 0,
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "layers": []
    });
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let put_resp = send(
        &ctx.app,
        Method::PUT,
        "/v2/prov-img/manifests/v1",
        Body::from(manifest_bytes),
    )
    .await;
    assert_eq!(put_resp.status(), StatusCode::CREATED);

    // The bare tag key — what get_manifest treats as the hosted/legacy key — is populated.
    assert!(
        ctx.state
            .storage
            .get("docker/prov-img/manifests/v1.json")
            .await
            .is_ok(),
        "local push must write the bare manifest key (hosted provenance)"
    );
}

#[tokio::test]
async fn test_manifest_push_rejects_absent_blob() {
    let ctx = create_test_context();
    // A manifest referencing a config blob we never uploaded must be rejected
    // (OCI MANIFEST_BLOB_UNKNOWN) rather than stored as a broken image.
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 0,
            "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
        },
        "layers": []
    });
    let resp = send(
        &ctx.app,
        Method::PUT,
        "/v2/reject/manifests/latest",
        Body::from(serde_json::to_vec(&manifest).unwrap()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_bytes(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["errors"][0]["code"], "MANIFEST_BLOB_UNKNOWN");
}

#[tokio::test]
async fn test_docker_list_tags() {
    let ctx = create_test_context();
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 0,
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "layers": []
    });
    seed_zero_config(&ctx.state, "alpine").await;
    send(
        &ctx.app,
        Method::PUT,
        "/v2/alpine/manifests/latest",
        Body::from(serde_json::to_vec(&manifest).unwrap()),
    )
    .await;

    let list_resp = send(&ctx.app, Method::GET, "/v2/alpine/tags/list", Body::empty()).await;
    assert_eq!(list_resp.status(), StatusCode::OK);
    let body = body_bytes(list_resp).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["name"], "alpine");
    let tags = json["tags"].as_array().unwrap();
    assert!(tags.contains(&serde_json::json!("latest")));
}

/// A pull's statistics land in a `.stats.json` sidecar beside the tag's manifest (#1114).
/// After the flush, tags/list and the UI must still show only the real tag — the sidecar is
/// not a tag — and the pull count must still be read from it.
#[tokio::test]
async fn tags_list_hides_the_pull_stats_sidecar() {
    let ctx = create_test_context();
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 0,
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "layers": []
    });
    seed_zero_config(&ctx.state, "alpine").await;
    let put = send(
        &ctx.app,
        Method::PUT,
        "/v2/alpine/manifests/1.0.0",
        Body::from(serde_json::to_vec(&manifest).unwrap()),
    )
    .await;
    assert_eq!(put.status(), StatusCode::CREATED);
    let pull = send(
        &ctx.app,
        Method::GET,
        "/v2/alpine/manifests/1.0.0",
        Body::empty(),
    )
    .await;
    assert_eq!(pull.status(), StatusCode::OK);
    super::flush_pull_stats(&ctx.state).await;
    let stats_key = "docker/alpine/manifests/1.0.0.stats.json";
    assert!(
        ctx.state.storage.stat(stats_key).await.is_some(),
        "control: the flush wrote the pull-stats sidecar"
    );

    let resp = send(&ctx.app, Method::GET, "/v2/alpine/tags/list", Body::empty()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(json["tags"], serde_json::json!(["1.0.0"]), "{json}");

    let detail = crate::ui::api::get_docker_detail(&ctx.state, "alpine").await;
    let names: Vec<_> = detail.tags.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, vec!["1.0.0"]);
    assert_eq!(detail.tags[0].downloads, 1, "the pull count is kept");
}

/// #932: tags/list must not include digest references (sha256:…).
/// put_manifest stores both {tag}.json and {digest}.json — only tags
/// belong in the OCI tags API response.
#[tokio::test]
async fn test_list_tags_excludes_digests() {
    let ctx = create_test_context();
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 0,
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "layers": []
    });
    seed_zero_config(&ctx.state, "nginx").await;
    // Push two tags — each also stores a digest copy
    for tag in ["stable", "mainline"] {
        send(
            &ctx.app,
            Method::PUT,
            &format!("/v2/nginx/manifests/{}", tag),
            Body::from(serde_json::to_vec(&manifest).unwrap()),
        )
        .await;
    }

    let resp = send(&ctx.app, Method::GET, "/v2/nginx/tags/list", Body::empty()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let tags = json["tags"].as_array().unwrap();
    // Must contain the real tags
    assert!(
        tags.iter().any(|t| t.as_str() == Some("stable")),
        "{tags:?}"
    );
    assert!(
        tags.iter().any(|t| t.as_str() == Some("mainline")),
        "{tags:?}"
    );
    // Must NOT contain any digest reference
    for tag in tags {
        let t = tag.as_str().unwrap_or("");
        assert!(
            !t.starts_with("sha256:") && !t.starts_with("sha512:"),
            "digest leaked into tags list: {}",
            t
        );
    }
}

#[tokio::test]
async fn test_docker_delete_manifest() {
    let ctx = create_test_context();
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 0,
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "layers": []
    });
    seed_zero_config(&ctx.state, "alpine").await;
    let put_resp = send(
        &ctx.app,
        Method::PUT,
        "/v2/alpine/manifests/latest",
        Body::from(serde_json::to_vec(&manifest).unwrap()),
    )
    .await;
    let digest = put_resp
        .headers()
        .get("docker-content-digest")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let del = send(
        &ctx.app,
        Method::DELETE,
        &format!("/v2/alpine/manifests/{}", digest),
        Body::empty(),
    )
    .await;
    assert_eq!(del.status(), StatusCode::ACCEPTED);
}

/// The binary's default Docker upstream, keeping its namespace, at a fixture that answers
/// every request `404`, as Docker Hub answers for a name it does not hold: a name without a
/// prefix gets the upstream's namespace as under a shipped config, and a miss is asked of the
/// fixture. Asked of Docker Hub, its 5xx or silence turned the miss into a `502`.
async fn default_upstream_fixture() -> (wiremock::MockServer, Vec<crate::config::DockerUpstream>) {
    let hub = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::any())
        .respond_with(wiremock::ResponseTemplate::new(404))
        .mount(&hub)
        .await;
    let mut upstreams = crate::config::DockerConfig::default().upstreams;
    for upstream in &mut upstreams {
        upstream.namespace = Some(upstream.resolved_namespace());
        upstream.url = hub.uri();
    }
    (hub, upstreams)
}

/// A delete removes the manifest on every backend. An object store answers a delete of an
/// absent key with success, so a delete that falls back to the second copy only on "not
/// found" never reaches it there: with the default upstream a pushed name gets a namespace,
/// the push writes the bare key, and the delete removed the namespaced one (absent) only.
#[tokio::test]
async fn a_deleted_manifest_is_gone_on_local_and_object_storage() {
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 0,
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "layers": []
    });
    let (_hub, upstreams) = default_upstream_fixture().await;
    for object in [false, true] {
        // The binary's default upstream, which the test context leaves out: with it a name
        // without a prefix gets the upstream's namespace, and the delete has two keys.
        let upstreams = upstreams.clone();
        let default_upstream =
            move |cfg: &mut crate::config::Config| cfg.docker.upstreams = upstreams;
        let ctx = if object {
            crate::test_helpers::create_test_context_with_storage_and_config(
                crate::storage::Storage::from_backend(std::sync::Arc::new(
                    crate::storage::ObjectStorage::in_memory(),
                )),
                default_upstream,
            )
        } else {
            crate::test_helpers::create_test_context_with_config(default_upstream)
        };
        seed_zero_config(&ctx.state, "rc/app").await;
        for (tag, by) in [("v1", "digest"), ("v2", "tag")] {
            let body = serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "mediaType": manifest["mediaType"],
                "config": manifest["config"],
                "layers": [],
                "annotations": { "tag": tag },
            }))
            .unwrap();
            let put = send(
                &ctx.app,
                Method::PUT,
                &format!("/v2/rc/app/manifests/{tag}"),
                Body::from(body),
            )
            .await;
            assert_eq!(put.status(), StatusCode::CREATED, "object={object} {tag}");
            let digest = put.headers()["docker-content-digest"]
                .to_str()
                .unwrap()
                .to_string();
            let target = if by == "digest" {
                digest.clone()
            } else {
                tag.to_string()
            };
            let del = send(
                &ctx.app,
                Method::DELETE,
                &format!("/v2/rc/app/manifests/{target}"),
                Body::empty(),
            )
            .await;
            assert_eq!(
                del.status(),
                StatusCode::ACCEPTED,
                "object={object} by {by}"
            );
            for reference in [digest.as_str(), tag] {
                let get = send(
                    &ctx.app,
                    Method::GET,
                    &format!("/v2/rc/app/manifests/{reference}"),
                    Body::empty(),
                )
                .await;
                assert_eq!(
                    get.status(),
                    StatusCode::NOT_FOUND,
                    "object={object}: {reference} still served after a delete by {by}"
                );
            }
        }
    }
}

/// A delete by digest removes the namespaced copy and a pre-migration bare copy alike: a read
/// falls back to the bare copy, so leaving it kept the manifest served (local and object).
#[tokio::test]
async fn a_delete_removes_both_copies_of_a_manifest() {
    let body = b"{\"schemaVersion\":2}".to_vec();
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&body)));
    let (_hub, upstreams) = default_upstream_fixture().await;
    for object in [false, true] {
        let upstreams = upstreams.clone();
        let default_upstream =
            move |cfg: &mut crate::config::Config| cfg.docker.upstreams = upstreams;
        let ctx = if object {
            crate::test_helpers::create_test_context_with_storage_and_config(
                crate::storage::Storage::from_backend(std::sync::Arc::new(
                    crate::storage::ObjectStorage::in_memory(),
                )),
                default_upstream,
            )
        } else {
            crate::test_helpers::create_test_context_with_config(default_upstream)
        };
        let c = super::canonicalize("rc/two", &ctx.state.config.docker);
        assert!(
            c.namespace.is_some(),
            "the default upstream gives the name a namespace"
        );
        for key in [
            super::manifest_key(c.namespace.as_deref(), &c.name, &digest),
            super::manifest_key(None, &c.name, &digest),
        ] {
            ctx.state.storage.put(&key, &body).await.unwrap();
        }
        let del = send(
            &ctx.app,
            Method::DELETE,
            &format!("/v2/rc/two/manifests/{digest}"),
            Body::empty(),
        )
        .await;
        assert_eq!(del.status(), StatusCode::ACCEPTED, "object={object}");
        let get = send(
            &ctx.app,
            Method::GET,
            &format!("/v2/rc/two/manifests/{digest}"),
            Body::empty(),
        )
        .await;
        assert_eq!(
            get.status(),
            StatusCode::NOT_FOUND,
            "object={object}: a copy is still served"
        );
    }
}

/// A tag named like another tag's sidecar (`v1.meta`, `v1.stats`) is refused on every manifest
/// route: its key is that sidecar's key, so a push would overwrite `v1`'s metadata, a delete
/// would remove it, and a read would serve it as a manifest.
#[tokio::test]
async fn a_tag_named_like_a_sidecar_cannot_reach_another_tags_metadata() {
    let ctx = create_test_context();
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 0,
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "layers": []
    });
    seed_zero_config(&ctx.state, "app").await;
    let body = serde_json::to_vec(&manifest).unwrap();
    let put = send(
        &ctx.app,
        Method::PUT,
        "/v2/app/manifests/v1",
        Body::from(body.clone()),
    )
    .await;
    assert_eq!(put.status(), StatusCode::CREATED);
    let meta_key = super::manifest_meta_key(None, "app", "v1");
    let meta_before = ctx.state.storage.get(&meta_key).await.unwrap();
    for tag in ["v1.meta", "v1.stats"] {
        let put = send(
            &ctx.app,
            Method::PUT,
            &format!("/v2/app/manifests/{tag}"),
            Body::from(body.clone()),
        )
        .await;
        assert_eq!(put.status(), StatusCode::BAD_REQUEST, "PUT {tag}");
        let get = send(
            &ctx.app,
            Method::GET,
            &format!("/v2/app/manifests/{tag}"),
            Body::empty(),
        )
        .await;
        assert_eq!(get.status(), StatusCode::BAD_REQUEST, "GET {tag}");
        let del = send(
            &ctx.app,
            Method::DELETE,
            &format!("/v2/app/manifests/{tag}"),
            Body::empty(),
        )
        .await;
        assert_eq!(del.status(), StatusCode::BAD_REQUEST, "DELETE {tag}");
    }
    assert_eq!(
        ctx.state.storage.get(&meta_key).await.unwrap(),
        meta_before,
        "v1's metadata changed"
    );
    let get = send(&ctx.app, Method::GET, "/v2/app/manifests/v1", Body::empty()).await;
    assert_eq!(get.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_docker_delete_by_digest_removes_tag() {
    // #658: deleting a manifest by digest must also drop the tags that
    // resolve to it, so the registry stops serving a now-gone manifest.
    let ctx = create_test_context();
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 0,
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "layers": []
    });
    seed_zero_config(&ctx.state, "alpine").await;
    let put_resp = send(
        &ctx.app,
        Method::PUT,
        "/v2/alpine/manifests/v1",
        Body::from(serde_json::to_vec(&manifest).unwrap()),
    )
    .await;
    let digest = put_resp
        .headers()
        .get("docker-content-digest")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // Delete the manifest by digest.
    let del = send(
        &ctx.app,
        Method::DELETE,
        &format!("/v2/alpine/manifests/{}", digest),
        Body::empty(),
    )
    .await;
    assert_eq!(del.status(), StatusCode::ACCEPTED);

    // The tag must no longer resolve.
    let tag_get = send(
        &ctx.app,
        Method::GET,
        "/v2/alpine/manifests/v1",
        Body::empty(),
    )
    .await;
    assert_eq!(
        tag_get.status(),
        StatusCode::NOT_FOUND,
        "tag must 404 after its manifest is deleted by digest (#658)"
    );

    // ...and it must not appear in tags/list.
    let list = send(&ctx.app, Method::GET, "/v2/alpine/tags/list", Body::empty()).await;
    let body = body_bytes(list).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let tags = json["tags"].as_array().unwrap();
    assert!(
        !tags.contains(&serde_json::json!("v1")),
        "v1 must be gone from tags/list after digest delete (#658)"
    );
}

/// A blob changed on disk never reaches the client complete: the stream checks the digest
/// before its last bytes go out. Served over a real socket, as a client sees it: hyper
/// stops reading the body once the declared length is out, so a check that waits for one
/// more read after the last byte never runs (R19).
#[tokio::test]
async fn a_tampered_blob_never_arrives_complete() {
    for size in [855usize, 300_000] {
        let ctx = create_test_context();
        let blob: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&blob)));
        let url = format!("/v2/alpine/blobs/uploads/?digest={digest}");
        let resp = send(&ctx.app, Method::POST, &url, Body::from(blob.clone())).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = ctx.app.clone();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = reqwest::Client::new();
        let get = || {
            client
                .get(format!("http://{addr}/v2/alpine/blobs/{digest}"))
                .send()
        };

        let on_disk = std::path::Path::new(&ctx.state.config.storage.path)
            .join(format!("docker/alpine/blobs/{digest}"));
        let mut tampered = std::fs::read(&on_disk).unwrap();
        tampered[size / 2] ^= 0xFF;
        std::fs::write(&on_disk, &tampered).unwrap();
        match get().await {
            Err(_) => {}
            Ok(resp) => match resp.bytes().await {
                Err(_) => {}
                Ok(bytes) => assert!(
                    bytes.len() < size,
                    "{size}: a tampered blob arrived complete ({} of {size} bytes)",
                    bytes.len()
                ),
            },
        }

        // An intact blob still arrives whole.
        std::fs::write(&on_disk, &blob).unwrap();
        let bytes = get().await.unwrap().bytes().await.unwrap();
        assert_eq!(&bytes[..], &blob[..], "{size}");
    }
}

#[tokio::test]
async fn test_docker_monolithic_upload() {
    let ctx = create_test_context();
    let blob_data = b"test blob data";
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(blob_data)));

    let post_resp = send(
        &ctx.app,
        Method::POST,
        "/v2/alpine/blobs/uploads/",
        Body::empty(),
    )
    .await;
    assert_eq!(post_resp.status(), StatusCode::ACCEPTED);
    let location = post_resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let uuid = location.rsplit('/').next().unwrap();

    let put_url = format!("/v2/alpine/blobs/uploads/{}?digest={}", uuid, digest);
    let put_resp = send(&ctx.app, Method::PUT, &put_url, Body::from(&blob_data[..])).await;
    assert_eq!(put_resp.status(), StatusCode::CREATED);
}

/// #1154: an uploaded blob is pinned to the digest it was checked against, whichever form
/// the upload took (monolithic PUT, chunked PATCH then PUT, single POST).
#[tokio::test]
async fn an_uploaded_blob_is_pinned_to_its_digest() {
    let ctx = create_test_context();
    let session = |ctx: &crate::test_helpers::TestContext| {
        let app = ctx.app.clone();
        async move {
            let resp = send(
                &app,
                Method::POST,
                "/v2/alpine/blobs/uploads/",
                Body::empty(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::ACCEPTED);
            let location = resp.headers().get("location").unwrap().to_str().unwrap();
            location.rsplit('/').next().unwrap().to_string()
        }
    };
    let digest_of = |data: &[u8]| hex::encode(sha2::Sha256::digest(data));

    let monolithic = b"pinned monolithic blob";
    let uuid = session(&ctx).await;
    let url = format!(
        "/v2/alpine/blobs/uploads/{uuid}?digest=sha256:{}",
        digest_of(monolithic)
    );
    let resp = send(&ctx.app, Method::PUT, &url, Body::from(&monolithic[..])).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let chunked = b"pinned chunked blob";
    let uuid = session(&ctx).await;
    let url = format!("/v2/alpine/blobs/uploads/{uuid}");
    let resp = send(&ctx.app, Method::PATCH, &url, Body::from(&chunked[..])).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let url = format!("{url}?digest=sha256:{}", digest_of(chunked));
    let resp = send(&ctx.app, Method::PUT, &url, Body::empty()).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let single = b"pinned single-post blob";
    let url = format!(
        "/v2/alpine/blobs/uploads/?digest=sha256:{}",
        digest_of(single)
    );
    let resp = send(&ctx.app, Method::POST, &url, Body::from(&single[..])).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    for data in [&monolithic[..], &chunked[..], &single[..]] {
        let hex = digest_of(data);
        let key = format!("docker/alpine/blobs/sha256:{hex}");
        assert_eq!(ctx.state.storage.pin(&key).await, Some(hex), "{key}");
    }
}

#[tokio::test]
async fn test_docker_single_post_monolithic_upload() {
    // #688: POST /blobs/uploads/?digest= with the blob in the body must store
    // it and return 201 in one request (the OCI "single POST" form).
    let ctx = create_test_context();
    let blob_data = b"single-post monolithic blob";
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(blob_data)));

    let resp = send(
        &ctx.app,
        Method::POST,
        &format!("/v2/alpine/blobs/uploads/?digest={}", digest),
        Body::from(&blob_data[..]),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "single-POST monolithic upload must return 201"
    );
    assert_eq!(
        resp.headers()
            .get("docker-content-digest")
            .unwrap()
            .to_str()
            .unwrap(),
        digest
    );

    // The blob must now exist.
    let head = send(
        &ctx.app,
        Method::HEAD,
        &format!("/v2/alpine/blobs/{}", digest),
        Body::empty(),
    )
    .await;
    assert_eq!(
        head.status(),
        StatusCode::OK,
        "blob must exist after a single-POST upload"
    );
}

#[tokio::test]
async fn test_docker_cross_repo_blob_mount() {
    let ctx = create_test_context();
    let blob_data = b"cross-repo mounted layer";
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(blob_data)));

    let resp = send(
        &ctx.app,
        Method::POST,
        &format!("/v2/srcrepo/blobs/uploads/?digest={}", digest),
        Body::from(&blob_data[..]),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let mount_url = format!("/v2/dstrepo/blobs/uploads/?mount={}&from=srcrepo", digest);
    let resp = send(&ctx.app, Method::POST, &mount_url, Body::empty()).await;
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "a blob the source repo holds must mount without an upload"
    );
    assert_eq!(
        resp.headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap(),
        format!("/v2/dstrepo/blobs/{}", digest)
    );
    assert_eq!(
        resp.headers()
            .get("docker-content-digest")
            .unwrap()
            .to_str()
            .unwrap(),
        digest
    );

    let get = send(
        &ctx.app,
        Method::GET,
        &format!("/v2/dstrepo/blobs/{}", digest),
        Body::empty(),
    )
    .await;
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(&body_bytes(get).await[..], &blob_data[..]);

    // Already in the destination: answered from the destination copy, so a
    // source that holds nothing still yields 201.
    let resp = send(
        &ctx.app,
        Method::POST,
        &format!("/v2/dstrepo/blobs/uploads/?mount={}&from=otherrepo", digest),
        Body::empty(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_docker_mount_unknown_blob_falls_back_to_upload() {
    let ctx = create_test_context();
    let digest = format!("sha256:{}", "b".repeat(64));

    let resp = send(
        &ctx.app,
        Method::POST,
        &format!("/v2/dstrepo/blobs/uploads/?mount={}&from=srcrepo", digest),
        Body::empty(),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::ACCEPTED,
        "an unmountable blob must degrade to a normal upload session"
    );
    assert!(resp.headers().contains_key("docker-upload-uuid"));
}

#[tokio::test]
async fn test_docker_mount_invalid_source_repo_falls_back_to_upload() {
    let ctx = create_test_context();
    let blob_data = b"blob behind an unusable source name";
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(blob_data)));
    let resp = send(
        &ctx.app,
        Method::POST,
        &format!("/v2/srcrepo/blobs/uploads/?digest={}", digest),
        Body::from(&blob_data[..]),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = send(
        &ctx.app,
        Method::POST,
        &format!("/v2/dstrepo/blobs/uploads/?mount={}&from=SRCREPO", digest),
        Body::empty(),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::ACCEPTED,
        "an invalid source repository must degrade to an upload session, not 4xx"
    );
    assert!(resp.headers().contains_key("docker-upload-uuid"));
}

#[tokio::test]
async fn test_docker_single_post_digest_mismatch_rejected() {
    // A single-POST upload whose body does not match ?digest= must be rejected.
    let ctx = create_test_context();
    let wrong = format!("sha256:{}", "0".repeat(64));
    let resp = send(
        &ctx.app,
        Method::POST,
        &format!("/v2/alpine/blobs/uploads/?digest={}", wrong),
        Body::from(&b"some other bytes"[..]),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_docker_chunked_upload() {
    let ctx = create_test_context();
    let blob_data = b"test chunked blob";
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(blob_data)));

    let post_resp = send(
        &ctx.app,
        Method::POST,
        "/v2/alpine/blobs/uploads/",
        Body::empty(),
    )
    .await;
    assert_eq!(post_resp.status(), StatusCode::ACCEPTED);
    let location = post_resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let uuid = location.rsplit('/').next().unwrap();

    let patch_url = format!("/v2/alpine/blobs/uploads/{}", uuid);
    let patch_resp = send(
        &ctx.app,
        Method::PATCH,
        &patch_url,
        Body::from(&blob_data[..]),
    )
    .await;
    assert_eq!(patch_resp.status(), StatusCode::ACCEPTED);

    let put_url = format!("/v2/alpine/blobs/uploads/{}?digest={}", uuid, digest);
    let put_resp = send(&ctx.app, Method::PUT, &put_url, Body::empty()).await;
    assert_eq!(put_resp.status(), StatusCode::CREATED);
}

// --- #817: blob-upload memory/disk bounds (streaming) ---

#[tokio::test]
async fn test_monolithic_upload_over_cap_rejected_fast() {
    // A monolithic PUT whose Content-Length exceeds the effective cap is
    // rejected up front (413), before any body is read.
    let ctx = create_test_context_with_config(|c| c.server.body_limit_mb = 1); // 1 MiB
    let blob = vec![0u8; 2 * 1024 * 1024]; // 2 MiB > cap
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&blob)));
    let resp = send(
        &ctx.app,
        Method::POST,
        &format!("/v2/alpine/blobs/uploads/?digest={}", digest),
        Body::from(blob),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn test_monolithic_upload_over_cap_streamed_rejected() {
    // The incremental cap must bound a STREAMING body with no Content-Length
    // — DefaultBodyLimit does not apply to a Body extractor (#817). Without
    // the in-loop guard this would write unbounded bytes to disk.
    let ctx = create_test_context_with_config(|c| c.server.body_limit_mb = 1); // 1 MiB
    let chunks: Vec<Result<axum::body::Bytes, std::io::Error>> = (0..4)
        .map(|_| Ok(axum::body::Bytes::from(vec![0u8; 512 * 1024])))
        .collect(); // 2 MiB total, streamed
    let body = Body::from_stream(futures::stream::iter(chunks));
    let digest = format!("sha256:{}", "0".repeat(64)); // irrelevant — rejected before verify
    let resp = send(
        &ctx.app,
        Method::POST,
        &format!("/v2/alpine/blobs/uploads/?digest={}", digest),
        body,
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "streamed body over cap must 413 via the incremental guard, not OOM"
    );
}

#[tokio::test]
async fn test_patch_over_cap_rejected() {
    // Chunked PATCH accumulating past the cap → 413.
    let ctx = create_test_context_with_config(|c| c.server.body_limit_mb = 1); // 1 MiB
    let post = send(
        &ctx.app,
        Method::POST,
        "/v2/alpine/blobs/uploads/",
        Body::empty(),
    )
    .await;
    assert_eq!(post.status(), StatusCode::ACCEPTED);
    let loc = post
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let uuid = loc.rsplit('/').next().unwrap();
    let big = vec![0u8; 2 * 1024 * 1024]; // 2 MiB > cap
    let resp = send(
        &ctx.app,
        Method::PATCH,
        &format!("/v2/alpine/blobs/uploads/{}", uuid),
        Body::from(big),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn test_manifest_over_cap_rejected() {
    // Manifests stay bounded: a body over MAX_MANIFEST_BYTES → 413, not OOM
    // (the streaming Body dispatcher bounds the collect explicitly, #817).
    let ctx = create_test_context();
    let huge = vec![b'{'; super::MAX_MANIFEST_BYTES + 1]; // just over 4 MiB
    let resp = send(
        &ctx.app,
        Method::PUT,
        "/v2/alpine/manifests/latest",
        Body::from(huge),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn test_streaming_upload_multiframe_ok() {
    // A multi-frame streamed blob (no Content-Length) is assembled and
    // digest-verified correctly — the streaming path is not tiny-body-only.
    let ctx = create_test_context();
    let blob = vec![7u8; 1024 * 1024]; // 1 MiB
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&blob)));
    let chunks: Vec<Result<axum::body::Bytes, std::io::Error>> = blob
        .chunks(64 * 1024)
        .map(|c| Ok(axum::body::Bytes::copy_from_slice(c)))
        .collect();
    let body = Body::from_stream(futures::stream::iter(chunks));
    let resp = send(
        &ctx.app,
        Method::POST,
        &format!("/v2/alpine/blobs/uploads/?digest={}", digest),
        body,
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "multi-frame streamed blob must store and verify"
    );
}

#[tokio::test]
async fn test_docker_check_blob() {
    let ctx = create_test_context();
    let blob_data = b"test blob for head";
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(blob_data)));

    let post_resp = send(
        &ctx.app,
        Method::POST,
        "/v2/alpine/blobs/uploads/",
        Body::empty(),
    )
    .await;
    let location = post_resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let uuid = location.rsplit('/').next().unwrap();
    let put_url = format!("/v2/alpine/blobs/uploads/{}?digest={}", uuid, digest);
    send(&ctx.app, Method::PUT, &put_url, Body::from(&blob_data[..])).await;

    let head_url = format!("/v2/alpine/blobs/{}", digest);
    let head_resp = send(&ctx.app, Method::HEAD, &head_url, Body::empty()).await;
    assert_eq!(head_resp.status(), StatusCode::OK);
    let cl = head_resp
        .headers()
        .get(header::CONTENT_LENGTH)
        .unwrap()
        .to_str()
        .unwrap()
        .parse::<usize>()
        .unwrap();
    assert_eq!(cl, blob_data.len());
}

#[tokio::test]
async fn test_docker_download_blob() {
    let ctx = create_test_context();
    let blob_data = b"test blob for download";
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(blob_data)));

    let post_resp = send(
        &ctx.app,
        Method::POST,
        "/v2/alpine/blobs/uploads/",
        Body::empty(),
    )
    .await;
    let location = post_resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let uuid = location.rsplit('/').next().unwrap();
    let put_url = format!("/v2/alpine/blobs/uploads/{}?digest={}", uuid, digest);
    send(&ctx.app, Method::PUT, &put_url, Body::from(&blob_data[..])).await;

    let get_url = format!("/v2/alpine/blobs/{}", digest);
    let get_resp = send(&ctx.app, Method::GET, &get_url, Body::empty()).await;
    assert_eq!(get_resp.status(), StatusCode::OK);
    let body = body_bytes(get_resp).await;
    assert_eq!(body.as_ref(), &blob_data[..]);
}

#[tokio::test]
async fn test_docker_blob_range_request() {
    use tower::ServiceExt;
    let ctx = create_test_context();
    let blob = b"0123456789abcdef";
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(blob)));

    let post = send(
        &ctx.app,
        Method::POST,
        "/v2/rng/blobs/uploads/",
        Body::empty(),
    )
    .await;
    let loc = post
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let uuid = loc.rsplit('/').next().unwrap();
    let put_url = format!("/v2/rng/blobs/uploads/{}?digest={}", uuid, digest);
    send(&ctx.app, Method::PUT, &put_url, Body::from(&blob[..])).await;

    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri(format!("/v2/rng/blobs/{}", digest))
        .header(header::RANGE, "bytes=4-7")
        .body(Body::empty())
        .unwrap();
    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        resp.headers()
            .get(header::CONTENT_RANGE)
            .unwrap()
            .to_str()
            .unwrap(),
        format!("bytes 4-7/{}", blob.len())
    );
    let body = body_bytes(resp).await;
    assert_eq!(body.as_ref(), &blob[4..=7]);

    // A client holding the whole blob resumes with `bytes=<size>-`: 416, not a
    // full re-download (#657, matches the reference `distribution` registry).
    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri(format!("/v2/rng/blobs/{}", digest))
        .header(header::RANGE, format!("bytes={}-", blob.len()))
        .body(Body::empty())
        .unwrap();
    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        resp.headers()
            .get(header::CONTENT_RANGE)
            .unwrap()
            .to_str()
            .unwrap(),
        format!("bytes */{}", blob.len())
    );

    // A malformed range is ignored: full 200 (RFC 9110 §14.2).
    let req = axum::http::Request::builder()
        .method(Method::GET)
        .uri(format!("/v2/rng/blobs/{}", digest))
        .header(header::RANGE, "kilobytes=1-2")
        .body(Body::empty())
        .unwrap();
    let resp = ctx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_docker_blob_not_found() {
    let ctx = create_test_context();
    let fake_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let head_url = format!("/v2/alpine/blobs/{}", fake_digest);
    let resp = send(&ctx.app, Method::HEAD, &head_url, Body::empty()).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_docker_delete_blob() {
    let ctx = create_test_context();
    let blob_data = b"test blob for delete";
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(blob_data)));

    let post_resp = send(
        &ctx.app,
        Method::POST,
        "/v2/alpine/blobs/uploads/",
        Body::empty(),
    )
    .await;
    let location = post_resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let uuid = location.rsplit('/').next().unwrap();
    let put_url = format!("/v2/alpine/blobs/uploads/{}?digest={}", uuid, digest);
    send(&ctx.app, Method::PUT, &put_url, Body::from(&blob_data[..])).await;

    let delete_url = format!("/v2/alpine/blobs/{}", digest);
    let delete_resp = send(&ctx.app, Method::DELETE, &delete_url, Body::empty()).await;
    assert_eq!(delete_resp.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn test_docker_namespaced_routes() {
    let ctx = create_test_context();
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 0,
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "layers": []
    });
    seed_zero_config(&ctx.state, "library/alpine").await;
    let put_resp = send(
        &ctx.app,
        Method::PUT,
        "/v2/library/alpine/manifests/latest",
        Body::from(serde_json::to_vec(&manifest).unwrap()),
    )
    .await;
    assert_eq!(put_resp.status(), StatusCode::CREATED);
    assert!(put_resp
        .headers()
        .get("docker-content-digest")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("sha256:"));
}

#[tokio::test]
async fn test_extract_docker_publish_date_from_meta() {
    let dir = tempfile::tempdir().unwrap();
    let storage = crate::storage::Storage::new_local(dir.path().join("data").to_str().unwrap());
    let meta = super::ImageMetadata {
        push_timestamp: 1700000000,
        ..Default::default()
    };
    storage
        .put(
            "docker/library/nginx/manifests/latest.meta.json",
            serde_json::to_vec(&meta).unwrap().as_slice(),
        )
        .await
        .unwrap();

    let result = super::extract_docker_publish_date(
        &storage,
        "library/nginx",
        "latest",
        true, // no upstreams
        None, // no namespace
        &mut super::BareMeta::Unread,
    )
    .await;
    assert_eq!(result, Some(1700000000));
}

#[tokio::test]
async fn test_extract_docker_publish_date_mtime_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let storage = crate::storage::Storage::new_local(dir.path().join("data").to_str().unwrap());

    // No .meta.json, but manifest exists — should fall back to mtime (hosted mode)
    storage
        .put("docker/library/nginx/manifests/latest.json", b"{}")
        .await
        .unwrap();

    let result = super::extract_docker_publish_date(
        &storage,
        "library/nginx",
        "latest",
        true, // hosted mode (no upstreams)
        None, // no namespace
        &mut super::BareMeta::Unread,
    )
    .await;
    assert!(result.is_some());
    assert!(result.unwrap() > 0);
}

#[tokio::test]
async fn test_extract_docker_publish_date_proxy_no_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let storage = crate::storage::Storage::new_local(dir.path().join("data").to_str().unwrap());

    // No .meta.json, manifest exists, but proxy mode — no fallback
    storage
        .put("docker/library/nginx/manifests/latest.json", b"{}")
        .await
        .unwrap();

    let result = super::extract_docker_publish_date(
        &storage,
        "library/nginx",
        "latest",
        false, // proxy mode (has upstreams)
        None,  // no namespace
        &mut super::BareMeta::Unread,
    )
    .await;
    assert!(result.is_none());
}

/// Circuit breaker open on Docker upstream MUST return 503 + Retry-After.
#[tokio::test]
async fn test_docker_circuit_breaker_trips() {
    use crate::config::DockerUpstream;
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};

    let ctx = create_test_context_with_config(|cfg| {
        cfg.circuit_breaker.enabled = true;
        cfg.circuit_breaker.failure_threshold = 2;
        cfg.circuit_breaker.reset_timeout = 3600;
        // Unreachable upstream
        cfg.docker.upstreams = vec![DockerUpstream {
            trust_upstream_dates: false,
            date_token_file: None,
            url: "http://127.0.0.1:1".into(),
            auth: None,
            auth_env: None,
            namespace: None,
            prefix: None,
            namespaces: Vec::new(),
        }];
    });

    // Trip the breaker for this upstream
    ctx.state
        .circuit_breaker
        .record_failure("docker:http://127.0.0.1:1", ProbeToken::BACKGROUND);
    ctx.state
        .circuit_breaker
        .record_failure("docker:http://127.0.0.1:1", ProbeToken::BACKGROUND);

    // Request a manifest NOT in local storage → proxy path → cb.check() → 503
    let response = send(
        &ctx.app,
        Method::GET,
        "/v2/library/nonexistent/manifests/latest",
        Body::empty(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok()),
        Some("30")
    );
    let body = body_bytes(response).await;
    let body = String::from_utf8_lossy(&body);
    assert!(
        body.contains("upstream docker temporarily unavailable"),
        "{body}"
    );
    assert!(
        !body.contains("127.0.0.1"),
        "the upstream's URL is logged, not answered: {body}"
    );
}

// ── OCI Distribution Spec conformance ──

/// OCI spec: GET /v2/ must return `Docker-Distribution-API-Version: registry/2.0`.
#[tokio::test]
async fn test_oci_v2_api_version_header() {
    let ctx = create_test_context();
    let resp = send(&ctx.app, Method::GET, "/v2/", Body::empty()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let api_ver = resp
        .headers()
        .get("docker-distribution-api-version")
        .expect("OCI spec requires Docker-Distribution-API-Version header")
        .to_str()
        .unwrap();
    assert_eq!(api_ver, "registry/2.0");
}

/// OCI spec: GET /v2/_catalog must return `{"repositories": [...]}`.
#[tokio::test]
async fn test_oci_catalog_json_structure() {
    let ctx = create_test_context();
    let resp = send(&ctx.app, Method::GET, "/v2/_catalog", Body::empty()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json.get("repositories").is_some(),
        "OCI spec requires 'repositories' key in catalog response"
    );
    assert!(json["repositories"].is_array());
}

/// OCI spec: GET /v2/{name}/tags/list must return `{"name": ..., "tags": [...]}`.
#[tokio::test]
async fn test_oci_tags_list_json_structure() {
    let ctx = create_test_context();
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 0,
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "layers": []
    });
    seed_zero_config(&ctx.state, "myapp").await;
    send(
        &ctx.app,
        Method::PUT,
        "/v2/myapp/manifests/v1",
        Body::from(serde_json::to_vec(&manifest).unwrap()),
    )
    .await;

    let resp = send(&ctx.app, Method::GET, "/v2/myapp/tags/list", Body::empty()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(
        json.get("name").is_some(),
        "OCI spec requires 'name' in tags/list"
    );
    assert!(
        json.get("tags").is_some(),
        "OCI spec requires 'tags' in tags/list"
    );
    assert_eq!(json["name"], "myapp");
    assert!(json["tags"].is_array());
}

/// OCI spec: manifest response MUST include Docker-Content-Digest = sha256 of body.
#[tokio::test]
async fn test_oci_manifest_digest_matches_body() {
    let ctx = create_test_context();
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 0,
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "layers": []
    });
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    seed_zero_config(&ctx.state, "verify").await;
    send(
        &ctx.app,
        Method::PUT,
        "/v2/verify/manifests/latest",
        Body::from(manifest_bytes),
    )
    .await;

    let resp = send(
        &ctx.app,
        Method::GET,
        "/v2/verify/manifests/latest",
        Body::empty(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let digest_header = resp
        .headers()
        .get("docker-content-digest")
        .expect("OCI spec requires Docker-Content-Digest header")
        .to_str()
        .unwrap()
        .to_string();

    let body = body_bytes(resp).await;
    let computed = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&body)));
    assert_eq!(
        digest_header, computed,
        "Docker-Content-Digest must equal sha256 of response body"
    );
}

/// OCI spec: Content-Type of manifest response must match the manifest's mediaType.
#[tokio::test]
async fn test_oci_manifest_content_type_matches_media_type() {
    let ctx = create_test_context();
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 0,
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "layers": []
    });
    seed_zero_config(&ctx.state, "ctcheck").await;
    send(
        &ctx.app,
        Method::PUT,
        "/v2/ctcheck/manifests/v1",
        Body::from(serde_json::to_vec(&manifest).unwrap()),
    )
    .await;

    let resp = send(
        &ctx.app,
        Method::GET,
        "/v2/ctcheck/manifests/v1",
        Body::empty(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .expect("OCI spec requires Content-Type header on manifest")
        .to_str()
        .unwrap();
    assert_eq!(ct, "application/vnd.docker.distribution.manifest.v2+json");
}

/// OCI spec: Content-Length must match actual body length.
#[tokio::test]
async fn test_oci_manifest_content_length_matches() {
    let ctx = create_test_context();
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 0,
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "layers": []
    });
    seed_zero_config(&ctx.state, "clcheck").await;
    send(
        &ctx.app,
        Method::PUT,
        "/v2/clcheck/manifests/v1",
        Body::from(serde_json::to_vec(&manifest).unwrap()),
    )
    .await;

    let resp = send(
        &ctx.app,
        Method::GET,
        "/v2/clcheck/manifests/v1",
        Body::empty(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let cl: usize = resp
        .headers()
        .get(header::CONTENT_LENGTH)
        .expect("OCI spec requires Content-Length on manifest")
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let body = body_bytes(resp).await;
    assert_eq!(cl, body.len(), "Content-Length must match body size");
}

/// Per-upstream circuit breaker isolation: upstream A down, upstream B serves.
#[tokio::test]
async fn test_docker_circuit_breaker_per_upstream() {
    use crate::config::DockerUpstream;
    use crate::test_helpers::create_test_context_with_config;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.circuit_breaker.enabled = true;
        cfg.circuit_breaker.failure_threshold = 2;
        cfg.circuit_breaker.reset_timeout = 3600;
        cfg.docker.upstreams = vec![
            DockerUpstream {
                trust_upstream_dates: false,
                date_token_file: None,
                url: "http://127.0.0.1:1".into(), // upstream A (will be tripped)
                auth: None,
                auth_env: None,
                namespace: None,
                prefix: None,
                namespaces: Vec::new(),
            },
            DockerUpstream {
                trust_upstream_dates: false,
                date_token_file: None,
                url: "http://127.0.0.1:2".into(), // upstream B (stays closed)
                auth: None,
                auth_env: None,
                namespace: None,
                prefix: None,
                namespaces: Vec::new(),
            },
        ];
    });

    // Trip only upstream A
    ctx.state
        .circuit_breaker
        .record_failure("docker:http://127.0.0.1:1", ProbeToken::BACKGROUND);
    ctx.state
        .circuit_breaker
        .record_failure("docker:http://127.0.0.1:1", ProbeToken::BACKGROUND);

    // Upstream A should be open
    assert!(ctx
        .state
        .circuit_breaker
        .check("docker:http://127.0.0.1:1")
        .is_err());

    // Upstream B should still be closed (requests allowed)
    assert!(ctx
        .state
        .circuit_breaker
        .check("docker:http://127.0.0.1:2")
        .is_ok());
}

#[test]
fn test_strip_docker_namespace() {
    // Namespace prefix (hostname with dot) should be stripped
    assert_eq!(
        super::strip_docker_namespace("docker.io/library/nginx"),
        "library/nginx"
    );
    assert_eq!(
        super::strip_docker_namespace("ghcr.io/requarks/wiki"),
        "requarks/wiki"
    );
    assert_eq!(
        super::strip_docker_namespace("registry.example.com/myapp"),
        "myapp"
    );

    // No namespace prefix — returned as-is
    assert_eq!(
        super::strip_docker_namespace("library/nginx"),
        "library/nginx"
    );
    assert_eq!(super::strip_docker_namespace("alpine"), "alpine");

    // Edge: empty or slash-only
    assert_eq!(super::strip_docker_namespace(""), "");
    assert_eq!(super::strip_docker_namespace("docker.io/"), "docker.io/");

    // Org name with no dots — not a namespace
    assert_eq!(
        super::strip_docker_namespace("myorg/myimage"),
        "myorg/myimage"
    );
}

#[tokio::test]
async fn test_catalog_dedup_across_namespaces() {
    use crate::test_helpers::create_test_context;

    let ctx = create_test_context();

    // Simulate keys from two different upstream namespaces for the same image
    ctx.state
        .storage
        .put(
            "docker/docker.io/library/nginx/manifests/latest.json",
            b"{}",
        )
        .await
        .unwrap();
    ctx.state
        .storage
        .put("docker/ghcr.io/library/nginx/manifests/v1.json", b"{}")
        .await
        .unwrap();
    // And a non-namespaced (legacy) key for the same image
    ctx.state
        .storage
        .put("docker/library/nginx/manifests/old.json", b"{}")
        .await
        .unwrap();

    let keys = ctx.state.storage.list("docker/").await.unwrap();
    let mut repos: Vec<String> = keys
        .iter()
        .filter_map(|k| {
            let rest = k.strip_prefix("docker/")?;
            let name = if let Some(idx) = rest.find("/manifests/") {
                &rest[..idx]
            } else {
                return None;
            };
            if name.is_empty() {
                return None;
            }
            Some(super::strip_docker_namespace(name).to_string())
        })
        .collect();
    repos.sort();
    repos.dedup();

    // All three keys should resolve to a single repo: "library/nginx"
    assert_eq!(repos, vec!["library/nginx"]);
}

/// Build a DockerConfig with the given upstreams and default_action = Allow.
fn docker_config_allow(
    upstreams: Vec<crate::config::DockerUpstream>,
) -> crate::config::DockerConfig {
    crate::config::DockerConfig {
        upstreams,
        default_action: crate::config::DefaultAction::Allow,
        ..Default::default()
    }
}

/// Build a DockerConfig with the given upstreams and default_action = Deny.
fn docker_config_deny(
    upstreams: Vec<crate::config::DockerUpstream>,
) -> crate::config::DockerConfig {
    crate::config::DockerConfig {
        upstreams,
        default_action: crate::config::DefaultAction::Deny,
        ..Default::default()
    }
}

#[test]
fn test_canonicalize_prefix_routing() {
    let upstreams = vec![crate::config::DockerUpstream {
        trust_upstream_dates: false,
        date_token_file: None,
        url: "https://registry-1.docker.io".to_string(),
        auth: None,
        auth_env: None,
        namespace: Some("docker.io".to_string()),
        prefix: Some("docker-hub".to_string()),
        namespaces: Vec::new(),
    }];
    let cfg = docker_config_allow(upstreams.clone());

    let c = super::canonicalize("docker-hub/library/nginx", &cfg);
    assert_eq!(c.name, "library/nginx");
    assert_eq!(c.namespace.as_deref(), Some("docker.io"));
    assert_eq!(c.upstreams_to_try(&upstreams).len(), 1);
    assert!(!c.denied);
}

#[test]
fn test_canonicalize_hostname_detection() {
    let upstreams = vec![crate::config::DockerUpstream {
        trust_upstream_dates: false,
        date_token_file: None,
        url: "https://registry-1.docker.io".to_string(),
        auth: None,
        auth_env: None,
        namespace: Some("docker.io".to_string()),
        prefix: None,
        namespaces: Vec::new(),
    }];
    let cfg = docker_config_allow(upstreams.clone());

    let c = super::canonicalize("docker.io/library/nginx", &cfg);
    assert_eq!(c.name, "library/nginx");
    assert_eq!(c.namespace.as_deref(), Some("docker.io"));
    // Known namespace matches specific upstream
    assert_eq!(c.upstreams_to_try(&upstreams).len(), 1);
    assert!(!c.denied);

    // A host no upstream serves is stripped and asked of no upstream (#1195)
    let c2 = super::canonicalize("ghcr.io/requarks/wiki", &cfg);
    assert_eq!(c2.name, "requarks/wiki");
    assert_eq!(c2.namespace, None);
    assert!(c2.upstreams_to_try(&upstreams).is_empty());
    assert!(!c2.denied); // Allow mode → not denied
}

#[test]
fn test_canonicalize_fallback() {
    let upstreams = vec![crate::config::DockerUpstream {
        trust_upstream_dates: false,
        date_token_file: None,
        url: "https://registry-1.docker.io".to_string(),
        auth: None,
        auth_env: None,
        namespace: Some("docker.io".to_string()),
        prefix: None,
        namespaces: Vec::new(),
    }];
    let cfg = docker_config_allow(upstreams.clone());

    // No prefix, no dot in first segment → fallback
    let c = super::canonicalize("library/nginx", &cfg);
    assert_eq!(c.name, "library/nginx");
    assert_eq!(c.namespace.as_deref(), Some("docker.io"));
    assert_eq!(c.upstreams_to_try(&upstreams).len(), 1);
    assert!(!c.denied);

    // Single segment
    let c2 = super::canonicalize("alpine", &cfg);
    assert_eq!(c2.name, "alpine");
    assert_eq!(c2.namespace.as_deref(), Some("docker.io"));
    assert!(!c2.denied);
}

#[test]
fn test_canonicalize_empty_upstreams() {
    let upstreams: Vec<crate::config::DockerUpstream> = vec![];
    let cfg = docker_config_allow(upstreams.clone());

    let c = super::canonicalize("library/nginx", &cfg);
    assert_eq!(c.name, "library/nginx");
    assert!(c.namespace.is_none());
    assert!(c.upstreams_to_try(&upstreams).is_empty());
    assert!(!c.denied);
}

#[test]
fn test_manifest_cache_fresh_tag_vs_digest() {
    use super::manifest_cache_fresh;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Digest references are immutable → always fresh, regardless of upstream/ttl.
    assert!(manifest_cache_fresh(true, true, -1, Some(now)));
    assert!(manifest_cache_fresh(true, true, 0, None));

    // Hosted tag (no upstream to revalidate against) is authoritative → fresh.
    assert!(manifest_cache_fresh(false, false, -1, Some(now)));

    // Proxied tag with the default ttl (-1) must REVALIDATE (#638) — not fresh.
    assert!(!manifest_cache_fresh(false, true, -1, Some(now)));
    // ttl=0 also revalidates every pull.
    assert!(!manifest_cache_fresh(false, true, 0, Some(now)));

    // Proxied tag within a POSITIVE ttl window → may serve from cache.
    assert!(manifest_cache_fresh(false, true, 3600, Some(now)));
    // Proxied tag beyond the window → revalidate.
    assert!(!manifest_cache_fresh(
        false,
        true,
        3600,
        Some(now.saturating_sub(7200))
    ));
    // Proxied tag with unknown mtime → revalidate.
    assert!(!manifest_cache_fresh(false, true, 3600, None));
}

#[test]
fn test_canonicalize_multi_upstream() {
    let upstreams = vec![
        crate::config::DockerUpstream {
            trust_upstream_dates: false,
            date_token_file: None,
            url: "https://registry-1.docker.io".to_string(),
            auth: None,
            auth_env: None,
            namespace: Some("docker.io".to_string()),
            prefix: Some("docker-hub".to_string()),
            namespaces: Vec::new(),
        },
        crate::config::DockerUpstream {
            trust_upstream_dates: false,
            date_token_file: None,
            url: "https://ghcr.io".to_string(),
            auth: None,
            auth_env: None,
            namespace: Some("ghcr.io".to_string()),
            prefix: Some("ghcr".to_string()),
            namespaces: Vec::new(),
        },
    ];
    let cfg = docker_config_allow(upstreams.clone());

    // Prefix routes to specific upstream
    let c1 = super::canonicalize("ghcr/requarks/wiki", &cfg);
    assert_eq!(c1.name, "requarks/wiki");
    assert_eq!(c1.namespace.as_deref(), Some("ghcr.io"));
    let targets = c1.upstreams_to_try(&upstreams);
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].url, "https://ghcr.io");
    assert!(!c1.denied);

    // No prefix match → all upstreams (allow mode)
    let c2 = super::canonicalize("library/nginx", &cfg);
    assert_eq!(c2.name, "library/nginx");
    assert_eq!(c2.upstreams_to_try(&upstreams).len(), 2);
    assert!(!c2.denied);
}

#[test]
fn test_canonicalize_deny_mode_blocks_unmatched() {
    let upstreams = vec![
        crate::config::DockerUpstream {
            trust_upstream_dates: false,
            date_token_file: None,
            url: "https://registry-1.docker.io".to_string(),
            auth: None,
            auth_env: None,
            namespace: Some("docker.io".to_string()),
            prefix: Some("docker-hub".to_string()),
            namespaces: Vec::new(),
        },
        crate::config::DockerUpstream {
            trust_upstream_dates: false,
            date_token_file: None,
            url: "https://ghcr.io".to_string(),
            auth: None,
            auth_env: None,
            namespace: Some("ghcr.io".to_string()),
            prefix: Some("ghcr".to_string()),
            namespaces: Vec::new(),
        },
    ];
    let cfg = docker_config_deny(upstreams.clone());

    // Prefix match → allowed even in deny mode
    let c1 = super::canonicalize("ghcr/requarks/wiki", &cfg);
    assert!(!c1.denied);
    assert_eq!(c1.name, "requarks/wiki");

    // No prefix match → denied
    let c2 = super::canonicalize("library/nginx", &cfg);
    assert!(c2.denied);
    assert!(c2.denied_response().is_some());

    // Single segment (no slash) → denied
    let c3 = super::canonicalize("alpine", &cfg);
    assert!(c3.denied);

    // Unknown hostname → denied
    let c4 = super::canonicalize("quay.io/prometheus/node-exporter", &cfg);
    assert!(c4.denied);
}

#[test]
fn test_canonicalize_deny_mode_allows_known_hostname() {
    let upstreams = vec![crate::config::DockerUpstream {
        trust_upstream_dates: false,
        date_token_file: None,
        url: "https://registry-1.docker.io".to_string(),
        auth: None,
        auth_env: None,
        namespace: Some("docker.io".to_string()),
        prefix: None,
        namespaces: Vec::new(),
    }];
    let cfg = docker_config_deny(upstreams.clone());

    // Known namespace hostname → matched upstream → allowed
    let c = super::canonicalize("docker.io/library/nginx", &cfg);
    assert!(!c.denied);
    assert_eq!(c.name, "library/nginx");
    assert_eq!(c.namespace.as_deref(), Some("docker.io"));
}

/// A private registry that owns `team-*` (#1188), a public one with a prefix, and Docker Hub,
/// in an order where the private registry is neither first nor last.
fn bound_upstreams() -> Vec<crate::config::DockerUpstream> {
    let entry =
        |url: &str, ns: &str, prefix: Option<&str>, masks: &[&str]| crate::config::DockerUpstream {
            url: url.to_string(),
            auth: None,
            namespace: Some(ns.to_string()),
            prefix: prefix.map(str::to_string),
            namespaces: masks.iter().map(|m| m.to_string()).collect(),
            auth_env: None,
            trust_upstream_dates: false,
            date_token_file: None,
        };
    vec![
        entry("https://ghcr.io", "ghcr.io", Some("ghcr"), &[]),
        entry(
            "https://harbor.example",
            "harbor.example",
            None,
            &["team-*", "ops"],
        ),
        entry("https://registry-1.docker.io", "docker.io", None, &[]),
    ]
}

/// Routing with namespaces, one row per case of the #1188 decision table: the upstreams
/// asked (by url), the name they are asked for, the storage namespace, and whether the
/// request is denied.
#[test]
fn test_canonicalize_namespaces_decision_table() {
    let upstreams = bound_upstreams();
    let harbor = vec!["https://harbor.example"];
    let chain = vec!["https://ghcr.io", "https://registry-1.docker.io"];
    let ghcr = vec!["https://ghcr.io"];
    #[rustfmt::skip]
    let rows: &[(&str, bool, &str, &[&str], &str, bool)] = &[
        // raw name,             deny,  name sent,           upstreams, namespace, denied
        ("team-a/service",       false, "team-a/service",    &harbor,   "harbor.example", false),
        ("team-a/service",       true,  "team-a/service",    &harbor,   "harbor.example", false),
        ("team-b/x/y",           false, "team-b/x/y",        &harbor,   "harbor.example", false),
        ("ops/tool",             false, "ops/tool",          &harbor,   "harbor.example", false),
        // not owned: a mask holds for the whole first segment only
        ("opsx/tool",            false, "opsx/tool",         &chain,    "ghcr.io", false),
        ("teamx/service",        false, "teamx/service",     &chain,    "ghcr.io", false),
        // a single-segment name has no namespace: Docker Hub's library/ path
        ("team-a",               false, "team-a",            &chain,    "ghcr.io", false),
        ("nginx",                false, "nginx",             &chain,    "ghcr.io", false),
        // a public name is never asked of the private registry
        ("aquasec/trivy",        false, "aquasec/trivy",     &chain,    "ghcr.io", false),
        ("aquasec/trivy",        true,  "aquasec/trivy",     &chain,    "ghcr.io", true),
        // an explicit prefix is an explicit choice of upstream, and goes first
        ("ghcr/team-a/service",  false, "team-a/service",    &ghcr,     "ghcr.io", false),
        // an unknown host never reaches the private registry: see the #1195 table
        // the private registry's own host picks it explicitly, under deny too
        ("harbor.example/x/svc", true,  "x/svc",             &harbor,   "harbor.example", false),
    ];
    for &(raw, deny, name, asked, ns, denied) in rows {
        let cfg = if deny {
            docker_config_deny(upstreams.clone())
        } else {
            docker_config_allow(upstreams.clone())
        };
        let c = super::canonicalize(raw, &cfg);
        let urls: Vec<&str> = c
            .upstreams_to_try(&upstreams)
            .iter()
            .map(|u| u.url.as_str())
            .collect();
        assert_eq!(c.name, name, "{raw} deny={deny}: name");
        assert_eq!(urls, asked, "{raw} deny={deny}: upstreams");
        assert_eq!(c.namespace.as_deref(), Some(ns), "{raw} deny={deny}: ns");
        assert_eq!(c.denied, denied, "{raw} deny={deny}: denied");
    }
}

/// Copies of public names are stored under the first upstream that serves them, not under
/// a private registry that happens to come first (#1188).
#[test]
fn test_canonicalize_fallback_namespace_skips_bound_upstream() {
    let mut upstreams = bound_upstreams();
    upstreams.rotate_left(1); // harbor, docker.io, ghcr
    let cfg = docker_config_allow(upstreams.clone());
    let c = super::canonicalize("library/nginx", &cfg);
    assert_eq!(c.namespace.as_deref(), Some("docker.io"));
    assert_eq!(c.upstreams_to_try(&upstreams).len(), 2);
    let c = super::canonicalize("team-a/service", &cfg);
    assert_eq!(c.namespace.as_deref(), Some("harbor.example"));
}

/// With every upstream bound, a name nobody owns has no upstream: it is served from
/// local storage or not at all, never by a private registry.
#[test]
fn test_canonicalize_every_upstream_bound_leaves_public_names_local() {
    let upstreams: Vec<_> = bound_upstreams()
        .into_iter()
        .filter(|u| u.is_bound())
        .collect();
    let cfg = docker_config_allow(upstreams.clone());
    let c = super::canonicalize("aquasec/trivy", &cfg);
    assert!(c.upstreams_to_try(&upstreams).is_empty());
    assert_eq!(c.namespace, None);
    assert!(!c.denied);
}

/// Routing by the registry host in front of a name, one row per case of the #1195 decision
/// table: a host names the upstream whose namespace or url host it is (Docker Hub by any of
/// its hosts); Docker Hub without an upstream of its own is the fallback chain, as a bare name
/// is; any other host has no upstream, and its name is answered from local storage only.
#[test]
fn test_canonicalize_registry_host_decision_table() {
    let entry = |url: &str, ns: Option<&str>, masks: &[&str]| crate::config::DockerUpstream {
        url: url.to_string(),
        auth: None,
        namespace: ns.map(str::to_string),
        prefix: None,
        namespaces: masks.iter().map(|m| m.to_string()).collect(),
        auth_env: None,
        trust_upstream_dates: false,
        date_token_file: None,
    };
    let with_hub = vec![
        entry("https://registry.gitlab.com", None, &[]),
        entry("https://harbor.example", None, &["team-*"]),
        entry("https://quay.io", Some("quay"), &[]),
        entry("https://registry-1.docker.io", None, &[]),
        entry("http://registry.local:5000", None, &[]),
    ];
    // Docker Hub only through a mirror, which no host names.
    let no_hub = vec![
        entry("https://mirror.gcr.io", None, &[]),
        entry("https://harbor.example", None, &["team-*"]),
    ];
    let (hub, gitlab, quay, local5000, harbor) = (
        vec!["https://registry-1.docker.io"],
        vec!["https://registry.gitlab.com"],
        vec!["https://quay.io"],
        vec!["http://registry.local:5000"],
        vec!["https://harbor.example"],
    );
    let (with_hub_chain, mirror): (Vec<&str>, Vec<&str>) = (
        vec![
            "https://registry.gitlab.com",
            "https://quay.io",
            "https://registry-1.docker.io",
            "http://registry.local:5000",
        ],
        vec!["https://mirror.gcr.io"],
    );
    let none: Vec<&str> = Vec::new();
    /// Upstreams, raw name, deny, name sent, upstreams asked, namespace, denied.
    type Row<'a> = (
        &'a [crate::config::DockerUpstream],
        &'a str,
        bool,
        &'a str,
        &'a [&'a str],
        Option<&'a str>,
        bool,
    );
    #[rustfmt::skip]
    let rows: &[Row] = &[
        // upstreams, raw name,                       deny,  name sent,        upstreams asked,  namespace,          denied
        // Docker Hub by each of its hosts
        (&with_hub, "docker.io/library/nginx",            false, "library/nginx",  &hub,           Some("docker.io"),   false),
        (&with_hub, "index.docker.io/library/nginx",      false, "library/nginx",  &hub,           Some("docker.io"),   false),
        (&with_hub, "registry-1.docker.io/library/nginx", false, "library/nginx",  &hub,           Some("docker.io"),   false),
        (&with_hub, "index.docker.io/library/nginx",      true,  "library/nginx",  &hub,           Some("docker.io"),   false),
        // an upstream by the host of its url, whatever its namespace is, port or not
        (&with_hub, "registry.gitlab.com/group/proj",     false, "group/proj",     &gitlab,        Some("gitlab.com"),  false),
        (&with_hub, "gitlab.com/group/proj",              false, "group/proj",     &gitlab,        Some("gitlab.com"),  false),
        (&with_hub, "quay.io/prometheus/node-exporter",   false, "prometheus/node-exporter", &quay, Some("quay"),       false),
        (&with_hub, "registry.local/x/y",                 false, "x/y",            &local5000,     Some("local"),       false),
        // a bound upstream is still named by its host
        (&with_hub, "harbor.example/x/svc",               false, "x/svc",          &harbor,        Some("harbor.example"), false),
        // a host no upstream serves: no upstream, local copies only; refused under deny
        (&with_hub, "ghcr.io/requarks/wiki",              false, "requarks/wiki",  &none,          None,                false),
        (&with_hub, "ghcr.io/team-a/svc",                 false, "team-a/svc",     &none,          None,                false),
        (&with_hub, "ghcr.io/requarks/wiki",              true,  "requarks/wiki",  &none,          None,                true),
        (&with_hub, "docker.io.evil/library/nginx",       false, "library/nginx",  &none,          None,                false),
        // the chain is unchanged for bare names
        (&with_hub, "library/nginx",                      false, "library/nginx",  &with_hub_chain, Some("gitlab.com"), false),
        // Docker Hub with no upstream of its own: the chain, as a bare name, never the owner
        (&no_hub,   "docker.io/library/alpine",           false, "library/alpine", &mirror,        Some("mirror.gcr.io"), false),
        (&no_hub,   "index.docker.io/library/alpine",     false, "library/alpine", &mirror,        Some("mirror.gcr.io"), false),
        (&no_hub,   "docker.io/team-a/svc",               false, "team-a/svc",     &mirror,        Some("mirror.gcr.io"), false),
        (&no_hub,   "docker.io/library/alpine",           true,  "library/alpine", &mirror,        Some("mirror.gcr.io"), true),
        (&no_hub,   "quay.io/library/alpine",             false, "library/alpine", &none,          None,                false),
    ];
    for &(upstreams, raw, deny, name, asked, ns, denied) in rows {
        let cfg = if deny {
            docker_config_deny(upstreams.to_vec())
        } else {
            docker_config_allow(upstreams.to_vec())
        };
        let c = super::canonicalize(raw, &cfg);
        let urls: Vec<&str> = c
            .upstreams_to_try(upstreams)
            .iter()
            .map(|u| u.url.as_str())
            .collect();
        assert_eq!(c.name, name, "{raw} deny={deny}: name");
        assert_eq!(urls, asked, "{raw} deny={deny}: upstreams");
        assert_eq!(c.namespace.as_deref(), ns, "{raw} deny={deny}: ns");
        assert_eq!(c.denied, denied, "{raw} deny={deny}: denied");
    }
}

#[test]
fn test_denied_response_format() {
    let upstreams = vec![crate::config::DockerUpstream {
        trust_upstream_dates: false,
        date_token_file: None,
        url: "https://registry-1.docker.io".to_string(),
        auth: None,
        auth_env: None,
        namespace: Some("docker.io".to_string()),
        prefix: Some("hub".to_string()),
        namespaces: Vec::new(),
    }];
    let cfg = docker_config_deny(upstreams);

    let c = super::canonicalize("library/nginx", &cfg);
    assert!(c.denied);

    // denied_response returns Some for denied requests
    let resp = c.denied_response();
    assert!(resp.is_some());

    // Non-denied request returns None
    let c2 = super::canonicalize("hub/library/nginx", &cfg);
    assert!(!c2.denied);
    assert!(c2.denied_response().is_none());
}

// ── #580/#581: streaming proxy blob integrity (content-addressable) ──

/// Security-critical (#581): an upstream that returns bytes whose SHA-256 does
/// not match the requested content-addressable digest must be rejected with
/// 502, and the poisoned bytes must never enter the cache, the pin store, or
/// be served — and the streaming temp file must be cleaned up.
#[tokio::test]
async fn test_docker_proxy_blob_sha256_mismatch_rejected() {
    use crate::config::DockerUpstream;
    use crate::test_helpers::create_test_context_with_config;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;

    // The requested digest is the SHA-256 of the *real* content...
    let requested_digest = format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(b"the real layer"))
    );
    // ...but the upstream serves unrelated (poisoned) bytes for that digest.
    let poisoned = b"poisoned bytes that do not hash to the requested digest".to_vec();

    Mock::given(method("GET"))
        .and(path(format!("/v2/library/test/blobs/{requested_digest}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(poisoned))
        .mount(&upstream)
        .await;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.docker.upstreams = vec![DockerUpstream {
            trust_upstream_dates: false,
            date_token_file: None,
            url: upstream.uri(),
            auth: None,
            auth_env: None,
            namespace: None,
            prefix: None,
            namespaces: Vec::new(),
        }];
    });

    let response = send(
        &ctx.app,
        Method::GET,
        &format!("/v2/library/test/blobs/{requested_digest}"),
        Body::empty(),
    )
    .await;

    // The headers go out as soon as upstream answers (the digest is only known at
    // the end of the spool), so a mismatch cannot be a 502 any more: the body aborts
    // instead of ending as a clean 200, and the poisoned bytes are never cached.
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await;
    assert!(
        body.is_err(),
        "a poisoned blob must not stream to a clean end"
    );
    // Poisoned blob must NOT have been cached under the docker blob key
    // (computed via the same canonicalize/blob_key path the handler uses).
    let c = super::canonicalize("library/test", &ctx.state.config.docker);
    let key = super::blob_key(c.namespace.as_deref(), &c.name, &requested_digest);
    // The spool task finishes after the response; give it a moment to clean up.
    let proxy_tmp = std::path::Path::new(&ctx.state.config.storage.path).join("tmp/docker-proxy");
    let leftover = || {
        std::fs::read_dir(&proxy_tmp)
            .map(|rd| rd.filter_map(|e| e.ok()).count())
            .unwrap_or(0)
    };
    let started = std::time::Instant::now();
    while leftover() > 0 && started.elapsed() < std::time::Duration::from_secs(5) {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        ctx.state.storage.get(&key).await.is_err(),
        "poisoned blob must not be cached"
    );
    // TempFileGuard must have cleaned up — no leftover proxy temp files.
    assert_eq!(
        leftover(),
        0,
        "temp files must be cleaned up after rejection"
    );
}

/// #638 regression: a proxied tag whose cached manifest is outdated must be revalidated
/// against upstream, not served stale. The cache is pre-seeded with the OLD manifest
/// (deterministic — manifest caching on the proxy path is spawned async, so a back-to-back
/// pull would race the write). RED on the pre-fix code (a cached tag was served forever
/// because the metadata_ttl default is -1), GREEN after proxied tags are revalidated.
#[tokio::test]
async fn test_docker_proxy_tag_revalidates_on_upstream_change() {
    use crate::config::DockerUpstream;
    use crate::test_helpers::create_test_context_with_config;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    let ct = "application/vnd.oci.image.manifest.v1+json";
    let manifest_old =
        br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:aaaa"},"layers":[]}"#.to_vec();
    let manifest_new =
        br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:bbbb"},"layers":[{"digest":"sha256:cccc"}]}"#.to_vec();

    // Upstream now serves the NEW manifest for the tag.
    Mock::given(method("GET"))
        .and(path("/v2/library/test/manifests/latest"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", ct)
                .set_body_bytes(manifest_new.clone()),
        )
        .mount(&upstream)
        .await;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.docker.upstreams = vec![DockerUpstream {
            trust_upstream_dates: false,
            date_token_file: None,
            url: upstream.uri(),
            auth: None,
            auth_env: None,
            namespace: None,
            prefix: None,
            namespaces: Vec::new(),
        }];
    });

    // Pre-seed the cache with the OLD manifest (what NORA fetched earlier).
    let c = super::canonicalize("library/test", &ctx.state.config.docker);
    let key = super::manifest_key(c.namespace.as_deref(), &c.name, "latest");
    ctx.state
        .storage
        .put(&key, &manifest_old)
        .await
        .expect("seed cache");

    // Pull the tag: the cached manifest is outdated, so a proxied (mutable) tag must be
    // revalidated and return the upstream NEW manifest — not the stale cached OLD one (#638).
    let resp = send(
        &ctx.app,
        Method::GET,
        "/v2/library/test/manifests/latest",
        Body::empty(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        body_bytes(resp).await.as_ref(),
        manifest_new.as_slice(),
        "a proxied tag with an outdated cached manifest must revalidate and return the upstream version (#638)"
    );
}

/// A proxied manifest dates every digest it names at its own first-seen, so under
/// enforce a multi-arch image waits one TTL, not one per level (index, platform
/// manifest, blobs). RED before: the platform manifest read as new when the client
/// asked for it after the index matured, and was held for another TTL.
#[tokio::test]
async fn quarantine_dates_what_a_manifest_names_at_its_own_first_seen() {
    use crate::config::DockerUpstream;
    use crate::digest_quarantine::{QuarantineMode, QuarantineStatus};
    use crate::test_helpers::{create_test_context_with_config, TestContext};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let sha = |b: &[u8]| format!("sha256:{}", hex::encode(sha2::Sha256::digest(b)));
    let config = br#"{"architecture":"amd64","os":"linux"}"#.to_vec();
    let layer = b"layer bytes".to_vec();
    let image = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{}","size":{}}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"{}","size":{}}}]}}"#,
        sha(&config),
        config.len(),
        sha(&layer),
        layer.len()
    )
    .into_bytes();
    let index = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{}","size":{},"platform":{{"architecture":"amd64","os":"linux"}}}}]}}"#,
        sha(&image),
        image.len()
    )
    .into_bytes();

    let upstream = MockServer::start().await;
    let index_ct = "application/vnd.oci.image.index.v1+json";
    for (route, body, ct) in [
        ("manifests/latest".to_string(), index.clone(), index_ct),
        (
            format!("manifests/{}", sha(&image)),
            image.clone(),
            "application/vnd.oci.image.manifest.v1+json",
        ),
        (
            format!("blobs/{}", sha(&config)),
            config.clone(),
            "application/octet-stream",
        ),
        (
            format!("blobs/{}", sha(&layer)),
            layer.clone(),
            "application/octet-stream",
        ),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/v2/library/demo/{route}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", ct)
                    .set_body_bytes(body),
            )
            .mount(&upstream)
            .await;
    }
    let enforcing = || {
        create_test_context_with_config(|cfg| {
            cfg.docker.upstreams = vec![DockerUpstream {
                trust_upstream_dates: false,
                date_token_file: None,
                url: upstream.uri(),
                auth: None,
                auth_env: None,
                namespace: None,
                prefix: None,
                namespaces: Vec::new(),
            }];
            cfg.curation.quarantine = Some(QuarantineMode::Enforce);
            cfg.curation.quarantine_ttl = Some("1h".to_string());
        })
    };
    async fn status(ctx: &TestContext, rest: String) -> StatusCode {
        let uri = format!("/v2/library/demo/{rest}");
        send(&ctx.app, Method::GET, &uri, Body::empty())
            .await
            .status()
    }

    // First sight: the index is held, and what it names is already counting, not new.
    let fresh = enforcing();
    assert_eq!(
        status(&fresh, "manifests/latest".into()).await,
        StatusCode::FORBIDDEN
    );
    assert!(matches!(
        fresh.state.digest_store.check("docker", &sha(&image), 3600),
        QuarantineStatus::Pending { .. }
    ));

    // An index NORA first saw two hours ago: the index, then the platform manifest,
    // then its blobs are served in one pass, each dated by what named it.
    let aged = enforcing();
    let two_hours_ago = chrono::Utc::now().timestamp() - 7200;
    aged.state
        .digest_store
        .record("docker", &sha(&index), "seed", Some(two_hours_ago));
    assert_eq!(
        status(&aged, "manifests/latest".into()).await,
        StatusCode::OK,
        "index"
    );
    assert_eq!(
        status(&aged, format!("manifests/{}", sha(&image))).await,
        StatusCode::OK,
        "the platform manifest the index named"
    );
    for blob in [&config, &layer] {
        assert_eq!(
            status(&aged, format!("blobs/{}", sha(blob))).await,
            StatusCode::OK,
            "a blob the platform manifest named"
        );
    }
}

/// A break-glass exception (`[docker] quarantine_exceptions`) admits a held index under
/// enforce, with the platform manifest and blobs a pull of it needs, says `exception` on
/// the manifest answer, and counts each use; removed from the file, it admits nothing.
#[tokio::test]
async fn a_quarantine_exception_admits_the_image_and_what_it_names() {
    use crate::config::DockerUpstream;
    use crate::digest_quarantine::QuarantineMode;
    use crate::test_helpers::{create_test_context_with_config, TestContext};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let sha = |b: &[u8]| format!("sha256:{}", hex::encode(sha2::Sha256::digest(b)));
    let config = br#"{"architecture":"amd64","os":"linux"}"#.to_vec();
    let layer = b"layer bytes".to_vec();
    let image = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{}","size":{}}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"{}","size":{}}}]}}"#,
        sha(&config),
        config.len(),
        sha(&layer),
        layer.len()
    )
    .into_bytes();
    let index = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{}","size":{},"platform":{{"architecture":"amd64","os":"linux"}}}}]}}"#,
        sha(&image),
        image.len()
    )
    .into_bytes();

    let upstream = MockServer::start().await;
    let index_ct = "application/vnd.oci.image.index.v1+json";
    for (route, body, ct) in [
        ("manifests/latest".to_string(), index.clone(), index_ct),
        (
            format!("manifests/{}", sha(&image)),
            image.clone(),
            "application/vnd.oci.image.manifest.v1+json",
        ),
        (
            format!("blobs/{}", sha(&config)),
            config.clone(),
            "application/octet-stream",
        ),
        (
            format!("blobs/{}", sha(&layer)),
            layer.clone(),
            "application/octet-stream",
        ),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/v2/library/demo/{route}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", ct)
                    .set_body_bytes(body),
            )
            .mount(&upstream)
            .await;
    }
    let enforcing = || {
        create_test_context_with_config(|cfg| {
            cfg.docker.upstreams = vec![DockerUpstream {
                trust_upstream_dates: false,
                date_token_file: None,
                url: upstream.uri(),
                auth: None,
                auth_env: None,
                namespace: None,
                prefix: None,
                namespaces: Vec::new(),
            }];
            cfg.curation.quarantine = Some(QuarantineMode::Enforce);
            cfg.curation.quarantine_ttl = Some("1h".to_string());
        })
    };
    async fn status(ctx: &TestContext, rest: String) -> StatusCode {
        let uri = format!("/v2/library/demo/{rest}");
        send(&ctx.app, Method::GET, &uri, Body::empty())
            .await
            .status()
    }

    let ctx = enforcing();
    let dir = tempfile::TempDir::new().unwrap();
    let file = dir.path().join("exceptions.toml");
    let file = file.to_str().unwrap();
    let used = || {
        crate::metrics::DOCKER_QUARANTINE_EXCEPTION_USED_TOTAL
            .with_label_values(&[sha(&index).as_str(), "hotfix"])
            .get()
    };
    assert_eq!(
        status(&ctx, "manifests/latest".into()).await,
        StatusCode::FORBIDDEN,
        "held, no exception"
    );

    let expires = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    std::fs::write(
        file,
        format!(
            "[[exception]]\ndigest = {:?}\nreason = \"hotfix\"\nexpires = {expires:?}\n",
            sha(&index)
        ),
    )
    .unwrap();
    {
        let _gauges = crate::quarantine_exceptions::GAUGES.lock();
        ctx.state.quarantine_exceptions.reload(file);
    }
    let before = used();
    let r = send(
        &ctx.app,
        Method::GET,
        "/v2/library/demo/manifests/latest",
        Body::empty(),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK, "the listed index");
    assert_eq!(r.headers().get("x-nora-quarantine").unwrap(), "exception");
    assert!(r.headers().get("x-nora-quarantine-until").is_none());
    assert_eq!(
        status(&ctx, format!("manifests/{}", sha(&image))).await,
        StatusCode::OK,
        "the platform manifest the index names"
    );
    for blob in [&config, &layer] {
        assert_eq!(
            status(&ctx, format!("blobs/{}", sha(blob))).await,
            StatusCode::OK,
            "a blob the platform manifest names"
        );
    }
    assert!(used() >= before + 4, "{} uses", used() - before);

    std::fs::write(file, "").unwrap();
    {
        let _gauges = crate::quarantine_exceptions::GAUGES.lock();
        ctx.state.quarantine_exceptions.reload(file);
    }
    assert_eq!(
        status(&ctx, "manifests/latest".into()).await,
        StatusCode::FORBIDDEN,
        "the entry is gone"
    );
    assert_eq!(
        status(&ctx, format!("blobs/{}", sha(&layer))).await,
        StatusCode::FORBIDDEN,
        "and with it what the index named"
    );
}

/// `trust_upstream_dates` (issues-maestra#1649): the registry's own publish date
/// starts the quarantine clock of a manifest NORA sees for the first time; anything
/// short of a usable past date leaves NORA's first-seen. Driven through quay.io's
/// tag API (`/api/v1/repository/<repo>/tag/`), which the upstream host serves itself.
mod trust_upstream_dates {
    use super::super::manifest_key;
    use super::*;
    use crate::config::DockerUpstream;
    use crate::digest_quarantine::{QuarantineMode, QuarantineStatus};
    use crate::test_helpers::{create_test_context_with_config, send_with_headers, TestContext};
    use axum::response::Response;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TAG_API: &str = "/api/v1/repository/library/demo/tag/";

    fn sha(b: &[u8]) -> String {
        format!("sha256:{}", hex::encode(sha2::Sha256::digest(b)))
    }

    /// An image (manifest + one layer) at `library/demo:v1`, served by a mock upstream.
    async fn upstream_with_image() -> (MockServer, Vec<u8>, Vec<u8>) {
        let layer = b"layer bytes".to_vec();
        let image = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{l}","size":11}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"{l}","size":11}}]}}"#,
            l = sha(&layer)
        )
        .into_bytes();
        let server = MockServer::start().await;
        for (route, body, ct) in [
            (
                "manifests/v1".to_string(),
                image.clone(),
                "application/vnd.oci.image.manifest.v1+json",
            ),
            (
                format!("manifests/{}", sha(&image)),
                image.clone(),
                "application/vnd.oci.image.manifest.v1+json",
            ),
            (
                format!("blobs/{}", sha(&layer)),
                layer.clone(),
                "application/octet-stream",
            ),
        ] {
            Mock::given(method("GET"))
                .and(path(format!("/v2/library/demo/{route}")))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("Content-Type", ct)
                        .set_body_bytes(body),
                )
                .mount(&server)
                .await;
        }
        (server, image, layer)
    }

    /// quay's answer for tag `v1`: `digest`, last modified `at` (unix seconds).
    fn quay_tag(digest: &str, at: i64) -> serde_json::Value {
        let when = chrono::DateTime::from_timestamp(at, 0)
            .unwrap()
            .to_rfc2822();
        serde_json::json!({"tags": [{"name": "v1", "manifest_digest": digest, "last_modified": when}]})
    }

    fn context(server: &MockServer, trust: bool, mode: QuarantineMode) -> TestContext {
        let url = server.uri();
        create_test_context_with_config(move |cfg| {
            cfg.docker.upstreams = vec![DockerUpstream {
                trust_upstream_dates: trust,
                date_token_file: None,
                url: url.clone(),
                auth: None,
                auth_env: None,
                namespace: Some("quay.io".into()),
                prefix: None,
                namespaces: Vec::new(),
            }];
            cfg.curation.quarantine = Some(mode);
            cfg.curation.quarantine_ttl = Some("3d".to_string());
        })
    }

    /// The upstream as `namespace` (a registry that dates by walking the repository),
    /// with `token` in its `date_token_file`.
    fn walked(server: &MockServer, namespace: &str, token: Option<&str>) -> TestContext {
        let url = server.uri();
        let namespace = namespace.to_string();
        let file = token.map(|t| {
            let dir = tempfile::tempdir().unwrap().keep();
            let file = dir.join("token");
            std::fs::write(&file, format!("{t}\n")).unwrap();
            file.to_string_lossy().into_owned()
        });
        create_test_context_with_config(move |cfg| {
            cfg.docker.upstreams = vec![DockerUpstream {
                trust_upstream_dates: true,
                date_token_file: file.clone(),
                url: url.clone(),
                auth: None,
                auth_env: None,
                namespace: Some(namespace.clone()),
                prefix: None,
                namespaces: Vec::new(),
            }];
            cfg.curation.quarantine = Some(QuarantineMode::Enforce);
            cfg.curation.quarantine_ttl = Some("3d".to_string());
        })
    }

    fn rfc3339(at: i64) -> String {
        chrono::DateTime::from_timestamp(at, 0)
            .unwrap()
            .to_rfc3339()
    }

    const GHCR_API: &str = "/users/library/packages/container/demo/versions";

    /// ghcr.io: the image's digest is a package version created `at`, listed on the
    /// second page; the API wants the token.
    async fn ghcr_versions(server: &MockServer, image: &[u8], at: i64) {
        let filler: Vec<_> = (0..100)
            .map(|i| serde_json::json!({"name": format!("sha256:{i:064x}"), "created_at": rfc3339(at)}))
            .collect();
        Mock::given(method("GET"))
            .and(path(GHCR_API))
            .and(wiremock::matchers::query_param("page", "1"))
            .and(wiremock::matchers::header(
                "authorization",
                "Bearer ghs_test",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(filler))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(GHCR_API))
            .and(wiremock::matchers::query_param("page", "2"))
            .and(wiremock::matchers::header(
                "authorization",
                "Bearer ghs_test",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"name": sha(image), "created_at": rfc3339(at)}
            ])))
            .expect(1)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn ghcr_dates_a_digest_request_by_its_package_version() {
        let (server, image, layer) = upstream_with_image().await;
        ghcr_versions(&server, &image, days_ago(30)).await;
        let ctx = walked(&server, "ghcr.io", Some("ghs_test"));
        assert_eq!(
            get(&ctx, &format!("manifests/{}", sha(&image))).await,
            StatusCode::OK
        );
        assert_eq!(
            get(&ctx, &format!("blobs/{}", sha(&layer))).await,
            StatusCode::OK
        );
        // Each page once (`expect(1)`): the ledger keeps the date for the tag request.
        assert_eq!(get(&ctx, "manifests/v1").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_fresh_ghcr_version_is_held_from_its_created_at() {
        let (server, image, _) = upstream_with_image().await;
        let pushed = days_ago(1);
        ghcr_versions(&server, &image, pushed).await;
        let ctx = walked(&server, "ghcr.io", Some("ghs_test"));
        assert_eq!(get(&ctx, "manifests/v1").await, StatusCode::FORBIDDEN);
        let entry = ctx
            .state
            .digest_store
            .record("docker", &sha(&image), "x", None);
        assert_eq!(entry.first_seen, pushed);
    }

    /// No token, a refusing API, a digest no version names: first-seen, never a pass.
    #[tokio::test]
    async fn an_undated_ghcr_digest_stays_first_seen() {
        let (server, image, _) = upstream_with_image().await;
        let ctx = walked(&server, "ghcr.io", None);
        assert_eq!(get(&ctx, "manifests/v1").await, StatusCode::FORBIDDEN);

        let (server, _, _) = upstream_with_image().await;
        Mock::given(method("GET"))
            .and(path(GHCR_API))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;
        let ctx = walked(&server, "ghcr.io", Some("ghs_test"));
        assert_eq!(get(&ctx, "manifests/v1").await, StatusCode::FORBIDDEN);

        let (server, _, _) = upstream_with_image().await;
        Mock::given(method("GET"))
            .and(path(GHCR_API))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"name": "sha256:other", "created_at": rfc3339(days_ago(30))}
            ])))
            .mount(&server)
            .await;
        let ctx = walked(&server, "ghcr.io", Some("ghs_test"));
        assert_eq!(get(&ctx, "manifests/v1").await, StatusCode::FORBIDDEN);
        let entry = ctx
            .state
            .digest_store
            .record("docker", &sha(&image), "x", None);
        assert!(entry.first_seen > days_ago(1), "first-seen: {entry:?}");
    }

    /// A digest NORA held by its own clock before its registry had a date source: the
    /// next fetch dates it, and what it names matures with it.
    #[tokio::test]
    async fn a_held_digest_is_dated_by_a_later_fetch() {
        let (server, image, layer) = upstream_with_image().await;
        ghcr_versions(&server, &image, days_ago(30)).await;
        let ctx = walked(&server, "ghcr.io", Some("ghs_test"));
        for digest in [sha(&image), sha(&layer)] {
            ctx.state.digest_store.record("docker", &digest, "x", None);
        }
        assert_eq!(get(&ctx, "manifests/v1").await, StatusCode::OK);
        assert_eq!(
            get(&ctx, &format!("blobs/{}", sha(&layer))).await,
            StatusCode::OK
        );
        let entry = ctx
            .state
            .digest_store
            .record("docker", &sha(&image), "x", None);
        assert!(entry.first_seen <= days_ago(29), "{entry:?}");
    }

    /// A tag is the first request of a repository, so it starts the walk; a walk slower
    /// than the request's wait still dates the digest, and what it names, when it lands,
    /// and the date outlives the process (#1649: gha-runner-scale-set-controller 0.15.1
    /// read as first-seen by tag and as ghcr_created_at by digest a second later).
    #[tokio::test]
    async fn a_tag_whose_walk_outlasts_the_request_is_dated_when_it_lands() {
        let (server, image, layer) = upstream_with_image().await;
        let pushed = days_ago(30);
        let filler: Vec<_> = (0..100)
            .map(|i| serde_json::json!({"name": format!("sha256:{i:064x}"), "created_at": rfc3339(pushed)}))
            .collect();
        Mock::given(method("GET"))
            .and(path(GHCR_API))
            .and(wiremock::matchers::query_param("page", "1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(filler)
                    .set_delay(std::time::Duration::from_secs(6)),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(GHCR_API))
            .and(wiremock::matchers::query_param("page", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"name": sha(&image), "created_at": rfc3339(pushed)}
            ])))
            .expect(1)
            .mount(&server)
            .await;
        let ctx = walked(&server, "ghcr.io", Some("ghs_test"));
        assert_eq!(get(&ctx, "manifests/v1").await, StatusCode::FORBIDDEN);
        for _ in 0..500 {
            if ctx.state.digest_store.check("docker", &sha(&image), 3600)
                == crate::digest_quarantine::QuarantineStatus::Mature
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        for digest in [sha(&image), sha(&layer)] {
            let entry = ctx.state.digest_store.record("docker", &digest, "x", None);
            assert_eq!(entry.first_seen, pushed, "{entry:?}");
            let dated = format!(".nora-quarantine/docker/{digest}.dated");
            let mut stored = false;
            for _ in 0..500 {
                if ctx.state.storage.stat(&dated).await.is_some() {
                    stored = true;
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            assert!(stored, "{dated} was never written");
        }
        assert_eq!(get(&ctx, "manifests/v1").await, StatusCode::OK);
        assert_eq!(
            get(&ctx, &format!("blobs/{}", sha(&layer))).await,
            StatusCode::OK
        );
    }

    /// ghcr pages past the first are asked at once: three pages of 2 s date a tag within
    /// the request's 5 s wait, where one after another they took 6.
    #[tokio::test]
    async fn ghcr_pages_after_the_first_are_asked_at_once() {
        let (server, image, _) = upstream_with_image().await;
        let pushed = days_ago(30);
        for page in 1..=3 {
            let versions: Vec<_> = if page < 3 {
                (0..100)
                    .map(|i| serde_json::json!({"name": format!("sha256:{page}{i:063x}"), "created_at": rfc3339(pushed)}))
                    .collect()
            } else {
                vec![serde_json::json!({"name": sha(&image), "created_at": rfc3339(pushed)})]
            };
            Mock::given(method("GET"))
                .and(path(GHCR_API))
                .and(wiremock::matchers::query_param("page", page.to_string()))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(versions)
                        .set_delay(std::time::Duration::from_secs(2)),
                )
                .expect(1)
                .mount(&server)
                .await;
        }
        let ctx = walked(&server, "ghcr.io", Some("ghs_test"));
        assert_eq!(get(&ctx, "manifests/v1").await, StatusCode::OK);
    }

    /// A digest pull of a cached manifest never reaches the upstream: one held by NORA's
    /// clock in the ledger (a lookup that missed before) is dated before it is served.
    #[tokio::test]
    async fn a_cached_held_digest_is_dated_on_a_digest_pull() {
        let (server, image, _) = upstream_with_image().await;
        ghcr_versions(&server, &image, days_ago(30)).await;
        let ctx = walked(&server, "ghcr.io", Some("ghs_test"));
        ctx.state
            .storage
            .put(
                &manifest_key(Some("ghcr.io"), "library/demo", &sha(&image)),
                &image,
            )
            .await
            .unwrap();
        ctx.state
            .digest_store
            .record("docker", &sha(&image), &server.uri(), None);
        assert_eq!(
            get(&ctx, &format!("manifests/{}", sha(&image))).await,
            StatusCode::OK
        );
        let entry = ctx
            .state
            .digest_store
            .record("docker", &sha(&image), "x", None);
        assert!(entry.first_seen <= days_ago(29), "{entry:?}");
    }

    /// The date only ever moves a hold back: a registry date later than NORA's clock (a
    /// digest moved between repositories) leaves the entry.
    #[tokio::test]
    async fn a_later_registry_date_leaves_a_held_digest_alone() {
        let (server, image, _) = upstream_with_image().await;
        ghcr_versions(&server, &image, days_ago(1)).await;
        let ctx = walked(&server, "ghcr.io", Some("ghs_test"));
        let seen = days_ago(2);
        ctx.state
            .digest_store
            .record("docker", &sha(&image), "x", Some(seen));
        assert_eq!(get(&ctx, "manifests/v1").await, StatusCode::FORBIDDEN);
        let entry = ctx
            .state
            .digest_store
            .record("docker", &sha(&image), "x", None);
        assert_eq!(entry.first_seen, seen);
    }

    /// public.ecr.aws: the gallery's `describeImageTags`, paged by `nextToken`, cosign
    /// tags skipped.
    #[tokio::test]
    async fn ecr_public_dates_a_digest_across_pages() {
        let (server, image, _) = upstream_with_image().await;
        let tag = |name: &str, digest: &str, at: i64| serde_json::json!({"imageTag": name, "imageDetail": {"imageDigest": digest, "imagePushedAt": rfc3339(at)}});
        Mock::given(method("POST"))
            .and(path("/describeImageTags"))
            .and(wiremock::matchers::body_partial_json(serde_json::json!({"registryAliasName": "library", "repositoryName": "demo", "nextToken": "p2"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "imageTagDetails": [tag("v1", &sha(&image), days_ago(30))]
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/describeImageTags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "imageTagDetails": [tag(&format!("sha256-{}.sig", &sha(&image)[7..]), &sha(&image), days_ago(1))],
                "nextToken": "p2"
            })))
            .mount(&server)
            .await;
        let ctx = walked(&server, "public.ecr.aws", None);
        assert_eq!(
            get(&ctx, &format!("manifests/{}", sha(&image))).await,
            StatusCode::OK
        );
    }

    /// cgr.dev time as its history writes it: milliseconds, `Z`.
    fn cgr_time(at: i64) -> String {
        chrono::DateTime::from_timestamp(at, 0)
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }

    /// cgr.dev's anonymous token for library/demo, and `tags` on its tags/list.
    async fn cgr_repository(server: &MockServer, tags: &[&str], listed: u64) {
        Mock::given(method("GET"))
            .and(path("/token"))
            .and(wiremock::matchers::query_param(
                "scope",
                "repository:library/demo:pull",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"token": "cgr_anon", "expires_in": 3600})),
            )
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v2/library/demo/tags/list"))
            .and(wiremock::matchers::header(
                "authorization",
                "Bearer cgr_anon",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"name": "library/demo", "tags": tags})),
            )
            .expect(listed)
            .mount(server)
            .await;
    }

    /// The history of tag `v1`: `records` (digest, time), oldest first.
    fn cgr_history(records: &[(String, i64)]) -> ResponseTemplate {
        let history: Vec<_> = records
            .iter()
            .map(|(d, at)| serde_json::json!({"updateTimestamp": cgr_time(*at), "digest": d}))
            .collect();
        ResponseTemplate::new(200).set_body_json(serde_json::json!({"history": history}))
    }

    const CGR_HISTORY: &str = "/v2/library/demo/_chainguard/history/v1";

    /// A digest request (a kubelet pull, `:latest@sha256`) names no tag: the history of
    /// the repository's tags dates it, cosign tags skipped, a full page of 1000 followed
    /// from its last record.
    #[tokio::test]
    async fn cgr_dates_a_digest_request_by_the_history_of_its_tags() {
        let (server, image, layer) = upstream_with_image().await;
        let old = days_ago(400);
        let filler: Vec<_> = (0..1000)
            .map(|i| (format!("sha256:{i:064x}"), old + i))
            .collect();
        let last = cgr_time(old + 999);
        cgr_repository(&server, &["v1", "sha256-0000.sig"], 1).await;
        Mock::given(method("GET"))
            .and(path(CGR_HISTORY))
            .and(wiremock::matchers::query_param_is_missing("start"))
            .and(wiremock::matchers::header(
                "authorization",
                "Bearer cgr_anon",
            ))
            .respond_with(cgr_history(&filler))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(CGR_HISTORY))
            .and(wiremock::matchers::query_param("start", last.as_str()))
            .respond_with(cgr_history(&[
                (format!("sha256:{:064x}", 999), old + 999),
                (sha(&image), days_ago(30)),
            ]))
            .expect(1)
            .mount(&server)
            .await;
        let ctx = walked(&server, "cgr.dev", None);
        assert_eq!(
            get(&ctx, &format!("manifests/{}", sha(&image))).await,
            StatusCode::OK
        );
        assert_eq!(
            get(&ctx, &format!("blobs/{}", sha(&layer))).await,
            StatusCode::OK
        );
    }

    /// A tag request reads that tag's history alone.
    #[tokio::test]
    async fn cgr_dates_a_tag_request_by_its_own_history() {
        let (server, image, _) = upstream_with_image().await;
        cgr_repository(&server, &["v1"], 0).await;
        Mock::given(method("GET"))
            .and(path(CGR_HISTORY))
            .respond_with(cgr_history(&[(sha(&image), days_ago(30))]))
            .expect(1)
            .mount(&server)
            .await;
        let ctx = walked(&server, "cgr.dev", None);
        assert_eq!(get(&ctx, "manifests/v1").await, StatusCode::OK);
    }

    /// chainguard/nginx@0352063c on 09.11.2026: cached and held from NORA's first fetch
    /// by digest, a day after cgr.dev published it. A digest pull moves it back to the
    /// history's date; still younger than the TTL, it stays held.
    #[tokio::test]
    async fn a_cached_cgr_digest_held_by_first_seen_takes_the_history_date() {
        let (server, image, _) = upstream_with_image().await;
        let pushed = days_ago(2);
        cgr_repository(&server, &["v1"], 1).await;
        Mock::given(method("GET"))
            .and(path(CGR_HISTORY))
            .respond_with(cgr_history(&[(sha(&image), pushed)]))
            .mount(&server)
            .await;
        let ctx = walked(&server, "cgr.dev", None);
        ctx.state
            .storage
            .put(
                &manifest_key(Some("cgr.dev"), "library/demo", &sha(&image)),
                &image,
            )
            .await
            .unwrap();
        ctx.state
            .digest_store
            .record("docker", &sha(&image), &server.uri(), Some(days_ago(1)));
        assert_eq!(
            get(&ctx, &format!("manifests/{}", sha(&image))).await,
            StatusCode::FORBIDDEN
        );
        let entry = ctx
            .state
            .digest_store
            .record("docker", &sha(&image), "x", None);
        assert_eq!(entry.first_seen, pushed);
    }

    /// A refused token, a failing history, a digest no history names: first-seen, never
    /// a pass and never a failed pull.
    #[tokio::test]
    async fn an_undated_cgr_digest_stays_first_seen() {
        let (server, image, _) = upstream_with_image().await;
        Mock::given(method("GET"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let ctx = walked(&server, "cgr.dev", None);
        assert_eq!(
            get(&ctx, &format!("manifests/{}", sha(&image))).await,
            StatusCode::FORBIDDEN
        );

        for history in [
            ResponseTemplate::new(429),
            cgr_history(&[("sha256:other".to_owned(), days_ago(30))]),
        ] {
            let (server, image, _) = upstream_with_image().await;
            cgr_repository(&server, &["v1"], 1).await;
            Mock::given(method("GET"))
                .and(path(CGR_HISTORY))
                .respond_with(history)
                .mount(&server)
                .await;
            let ctx = walked(&server, "cgr.dev", None);
            assert_eq!(
                get(&ctx, &format!("manifests/{}", sha(&image))).await,
                StatusCode::FORBIDDEN
            );
            let entry = ctx
                .state
                .digest_store
                .record("docker", &sha(&image), "x", None);
            assert!(entry.first_seen > days_ago(1), "first-seen: {entry:?}");
        }
    }

    async fn get(ctx: &TestContext, rest: &str) -> StatusCode {
        let uri = format!("/v2/library/demo/{rest}");
        send(&ctx.app, Method::GET, &uri, Body::empty())
            .await
            .status()
    }

    fn days_ago(d: i64) -> i64 {
        chrono::Utc::now().timestamp() - d * 86400
    }

    #[tokio::test]
    async fn a_registry_date_older_than_the_ttl_admits_the_image_at_once() {
        let (server, image, layer) = upstream_with_image().await;
        Mock::given(method("GET"))
            .and(path(TAG_API))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(quay_tag(&sha(&image), days_ago(30))),
            )
            .expect(1)
            .mount(&server)
            .await;
        let ctx = context(&server, true, QuarantineMode::Enforce);
        assert_eq!(get(&ctx, "manifests/v1").await, StatusCode::OK);
        // What the manifest names matures with it (#112), and the date is looked up once:
        // the ledger keeps it for the digest.
        assert_eq!(
            get(&ctx, &format!("blobs/{}", sha(&layer))).await,
            StatusCode::OK
        );
        assert_eq!(get(&ctx, "manifests/v1").await, StatusCode::OK);
        assert_eq!(
            get(&ctx, &format!("manifests/{}", sha(&image))).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn a_fresh_image_is_held_from_its_registry_date() {
        let (server, image, _) = upstream_with_image().await;
        let pushed = days_ago(1);
        Mock::given(method("GET"))
            .and(path(TAG_API))
            .respond_with(ResponseTemplate::new(200).set_body_json(quay_tag(&sha(&image), pushed)))
            .mount(&server)
            .await;
        let ctx = context(&server, true, QuarantineMode::Enforce);
        assert_eq!(get(&ctx, "manifests/v1").await, StatusCode::FORBIDDEN);
        let entry = ctx
            .state
            .digest_store
            .record("docker", &sha(&image), "x", None);
        assert_eq!(
            entry.first_seen, pushed,
            "the clock starts at the registry's date"
        );
    }

    /// A floating tag at `library/demo:v1` that answers `body`, replacing what the
    /// upstream served before: the tag moved.
    async fn tag_answers(server: &MockServer, body: &[u8]) {
        server.reset().await;
        for route in ["v1".to_string(), sha(body)] {
            Mock::given(method("GET"))
                .and(path(format!("/v2/library/demo/manifests/{route}")))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("Content-Type", "application/vnd.oci.image.manifest.v1+json")
                        .set_body_bytes(body.to_vec()),
                )
                .mount(server)
                .await;
        }
    }

    fn moved_manifest() -> Vec<u8> {
        br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":1},"layers":[]}"#.to_vec()
    }

    /// `v1` cached at `image`, a digest past the TTL. The cache write is off the request
    /// path, so wait for it.
    async fn mature_tag_cached(ctx: &TestContext, image: &[u8]) {
        ctx.state
            .digest_store
            .record("docker", &sha(image), "x", Some(days_ago(30)));
        assert_eq!(get(ctx, "manifests/v1").await, StatusCode::OK);
        let key = manifest_key(Some("quay.io"), "library/demo", "v1");
        for _ in 0..200 {
            if ctx.state.storage.get(&key).await.is_ok() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("tag copy never cached");
    }

    async fn manifest(ctx: &TestContext, rest: &str) -> Response {
        let uri = format!("/v2/library/demo/{rest}");
        send(&ctx.app, Method::GET, &uri, Body::empty()).await
    }

    fn header<'a>(resp: &'a Response, name: &str) -> Option<&'a str> {
        resp.headers().get(name).and_then(|v| v.to_str().ok())
    }

    /// Enforce on a floating tag: the tag keeps the digest that was admitted until the
    /// new one matures, and says which digest it is holding back.
    #[tokio::test]
    async fn a_moved_tag_keeps_its_mature_digest_under_enforce() {
        let (server, image, _) = upstream_with_image().await;
        let ctx = context(&server, false, QuarantineMode::Enforce);
        mature_tag_cached(&ctx, &image).await;
        let moved = moved_manifest();
        tag_answers(&server, &moved).await;

        let resp = manifest(&ctx, "manifests/v1").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            header(&resp, "docker-content-digest"),
            Some(sha(&image).as_str())
        );
        assert_eq!(header(&resp, "x-nora-quarantine"), Some("mature"));
        assert_eq!(
            header(&resp, "x-nora-quarantine-held"),
            Some(sha(&moved).as_str())
        );
        assert!(header(&resp, "x-nora-quarantine-held-until").is_some());

        // Asked for by digest, the held manifest stays refused, and asking again by
        // tag still answers the mature one.
        assert_eq!(
            get(&ctx, &format!("manifests/{}", sha(&moved))).await,
            StatusCode::FORBIDDEN
        );
        let again = manifest(&ctx, "manifests/v1").await;
        assert_eq!(
            header(&again, "docker-content-digest"),
            Some(sha(&image).as_str())
        );
    }

    /// A previous digest that is itself still held is no fallback.
    #[tokio::test]
    async fn a_moved_tag_with_only_a_held_digest_behind_it_is_refused() {
        let (server, image, _) = upstream_with_image().await;
        let ctx = context(&server, false, QuarantineMode::Enforce);
        mature_tag_cached(&ctx, &image).await;
        let key = manifest_key(Some("quay.io"), "library/demo", "v1");
        let held = b"{\"schemaVersion\":2,\"layers\":[]}".to_vec();
        ctx.state
            .digest_store
            .record("docker", &sha(&held), "x", Some(days_ago(1)));
        ctx.state.storage.put(&key, &held).await.unwrap();
        tag_answers(&server, &moved_manifest()).await;
        assert_eq!(get(&ctx, "manifests/v1").await, StatusCode::FORBIDDEN);
    }

    /// Once the new digest is past the TTL the tag moves to it.
    #[tokio::test]
    async fn a_moved_tag_follows_the_new_digest_when_it_matures() {
        let (server, image, _) = upstream_with_image().await;
        let ctx = context(&server, false, QuarantineMode::Enforce);
        mature_tag_cached(&ctx, &image).await;
        let moved = moved_manifest();
        ctx.state
            .digest_store
            .record("docker", &sha(&moved), "x", Some(days_ago(4)));
        tag_answers(&server, &moved).await;
        let resp = manifest(&ctx, "manifests/v1").await;
        assert_eq!(
            header(&resp, "docker-content-digest"),
            Some(sha(&moved).as_str())
        );
        assert_eq!(header(&resp, "x-nora-quarantine-held"), None);
    }

    /// Observe serves the new digest as before, but the tag copy stays the admitted
    /// one: otherwise a tag that moved in the days before enforce has nothing behind it.
    #[tokio::test]
    async fn observe_serves_a_moved_tag_and_keeps_the_mature_copy() {
        let (server, image, _) = upstream_with_image().await;
        let ctx = context(&server, false, QuarantineMode::Observe);
        mature_tag_cached(&ctx, &image).await;
        let moved = moved_manifest();
        tag_answers(&server, &moved).await;
        let resp = manifest(&ctx, "manifests/v1").await;
        assert_eq!(
            header(&resp, "docker-content-digest"),
            Some(sha(&moved).as_str())
        );
        let digest_key = manifest_key(Some("quay.io"), "library/demo", &sha(&moved));
        for _ in 0..200 {
            if ctx.state.storage.get(&digest_key).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let key = manifest_key(Some("quay.io"), "library/demo", "v1");
        assert_eq!(
            ctx.state.storage.get(&key).await.unwrap().as_ref(),
            &image[..]
        );
    }

    /// No usable date — the tag names another digest, a date in the future, the API
    /// throttled or down — leaves NORA's first-seen: held, never a failed pull.
    #[tokio::test]
    async fn anything_but_a_past_date_for_this_digest_leaves_first_seen() {
        for label in ["another digest", "future date", "throttled", "down"] {
            let (server, image, _) = upstream_with_image().await;
            let answer = match label {
                "another digest" => ResponseTemplate::new(200)
                    .set_body_json(quay_tag(&sha(b"another manifest"), days_ago(30))),
                "future date" => {
                    ResponseTemplate::new(200).set_body_json(quay_tag(&sha(&image), days_ago(-30)))
                }
                "throttled" => ResponseTemplate::new(429),
                _ => ResponseTemplate::new(503),
            };
            Mock::given(method("GET"))
                .and(path(TAG_API))
                .respond_with(answer)
                .mount(&server)
                .await;
            let before = chrono::Utc::now().timestamp();
            let enforcing = context(&server, true, QuarantineMode::Enforce);
            assert_eq!(
                get(&enforcing, "manifests/v1").await,
                StatusCode::FORBIDDEN,
                "{label}"
            );
            let entry = enforcing
                .state
                .digest_store
                .record("docker", &sha(&image), "x", None);
            assert!(
                entry.first_seen >= before,
                "{label}: first-seen, not {}",
                entry.first_seen
            );
            let observing = context(&server, true, QuarantineMode::Observe);
            assert_eq!(
                get(&observing, "manifests/v1").await,
                StatusCode::OK,
                "{label}"
            );
        }
    }

    /// `Cache-Control: only-if-cached` reads the verdict of what NORA holds and never asks
    /// the upstream: a digest NORA has not seen is a 504 and gets no first-seen record
    /// (the github-actions base-image check, issues-maestra#1649).
    #[tokio::test]
    async fn only_if_cached_never_reaches_the_upstream_nor_starts_a_clock() {
        let (server, image, _) = upstream_with_image().await;
        let ctx = context(&server, false, QuarantineMode::Observe);
        let probe = |rest: String, m: Method| {
            let app = ctx.app.clone();
            async move {
                send_with_headers(
                    &app,
                    m,
                    &format!("/v2/library/demo/{rest}"),
                    vec![("cache-control", "no-cache, Only-If-Cached")],
                    Body::empty(),
                )
                .await
            }
        };
        let by_digest = format!("manifests/{}", sha(&image));
        for m in [Method::GET, Method::HEAD] {
            for rest in [by_digest.clone(), "manifests/v1".to_string()] {
                let r = probe(rest.clone(), m.clone()).await;
                assert_eq!(r.status(), StatusCode::GATEWAY_TIMEOUT, "{m} {rest}");
            }
        }
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            0,
            "the upstream was asked"
        );
        assert_eq!(
            ctx.state.digest_store.check("docker", &sha(&image), 1),
            QuarantineStatus::New,
            "a probe recorded a first sight"
        );

        // A real pull caches it (tag and digest copy) and starts the clock: the probe
        // then reads the verdict, still without the upstream.
        assert_eq!(get(&ctx, "manifests/v1").await, StatusCode::OK);
        let key = manifest_key(Some("quay.io"), "library/demo", &sha(&image));
        for _ in 0..200 {
            if ctx.state.storage.get(&key).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let asked = server.received_requests().await.unwrap().len();
        for m in [Method::GET, Method::HEAD] {
            for rest in [by_digest.clone(), "manifests/v1".to_string()] {
                let r = probe(rest.clone(), m.clone()).await;
                assert_eq!(r.status(), StatusCode::OK, "{m} {rest}");
                assert_eq!(
                    header(&r, "x-nora-quarantine"),
                    Some("pending"),
                    "{m} {rest}"
                );
                assert!(
                    header(&r, "x-nora-quarantine-until").is_some(),
                    "{m} {rest}"
                );
                assert_eq!(
                    header(&r, "docker-content-digest"),
                    Some(sha(&image).as_str())
                );
            }
        }
        assert_eq!(server.received_requests().await.unwrap().len(), asked);
    }

    /// The verdict rides on every manifest answer, 200 included, so `observe` can be
    /// read by a client: pending + until while held, mature once admitted.
    #[tokio::test]
    async fn the_quarantine_verdict_is_on_every_manifest_answer() {
        let verdict = |r: &Response| {
            let h = |n: &str| r.headers().get(n).map(|v| v.to_str().unwrap().to_owned());
            (
                r.status(),
                h("x-nora-quarantine"),
                h("x-nora-quarantine-until"),
            )
        };
        let in_three_days = || chrono::Utc::now().timestamp() + 3 * 86400;
        let (server, image, _) = upstream_with_image().await;
        Mock::given(method("GET"))
            .and(path(TAG_API))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(quay_tag(&sha(&image), days_ago(30))),
            )
            .mount(&server)
            .await;
        for m in [Method::GET, Method::HEAD] {
            // observe, first sight, no trusted date: served, pending until first-seen + TTL.
            let fresh = context(&server, false, QuarantineMode::Observe);
            let r = send(
                &fresh.app,
                m.clone(),
                "/v2/library/demo/manifests/v1",
                Body::empty(),
            )
            .await;
            let (status, v, until) = verdict(&r);
            assert_eq!(
                (status, v.as_deref()),
                (StatusCode::OK, Some("pending")),
                "{m}"
            );
            let until: i64 = until.expect("until").parse().unwrap();
            assert!((until - in_three_days()).abs() < 60, "{m}: {until}");
            // the same digest again, now by digest: still pending
            let r = send(
                &fresh.app,
                m.clone(),
                &format!("/v2/library/demo/manifests/{}", sha(&image)),
                Body::empty(),
            )
            .await;
            assert_eq!(verdict(&r).1.as_deref(), Some("pending"), "{m}");

            // observe, dated 30 days ago by the registry: mature, no until.
            let old = context(&server, true, QuarantineMode::Observe);
            let r = send(
                &old.app,
                m.clone(),
                "/v2/library/demo/manifests/v1",
                Body::empty(),
            )
            .await;
            assert_eq!(
                verdict(&r),
                (StatusCode::OK, Some("mature".into()), None),
                "{m}"
            );

            // quarantine off: mature.
            let off = context(&server, false, QuarantineMode::Off);
            let r = send(
                &off.app,
                m.clone(),
                "/v2/library/demo/manifests/v1",
                Body::empty(),
            )
            .await;
            assert_eq!(
                verdict(&r),
                (StatusCode::OK, Some("mature".into()), None),
                "{m}"
            );

            // enforce: the 403 keeps its value and now names the end of the hold too.
            let held = context(&server, false, QuarantineMode::Enforce);
            let r = send(
                &held.app,
                m.clone(),
                "/v2/library/demo/manifests/v1",
                Body::empty(),
            )
            .await;
            let (status, v, until) = verdict(&r);
            assert_eq!(
                (status, v.as_deref()),
                (StatusCode::FORBIDDEN, Some("pending")),
                "{m}"
            );
            let until: i64 = until.expect("until").parse().unwrap();
            assert!((until - in_three_days()).abs() < 60, "{m}: {until}");
        }
    }

    /// A ledger entry older than 90 days is gone after a restart, while the manifest
    /// stays cached. What an admitted copy names is admitted with it: an uncached blob
    /// of an old image must not start a new TTL, through an index and its platform too.
    #[tokio::test]
    async fn a_cached_manifest_without_a_record_admits_what_it_names() {
        let (server, image, layer) = upstream_with_image().await;
        let index = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{}","size":1}}]}}"#,
            sha(&image)
        )
        .into_bytes();
        let ctx = context(&server, false, QuarantineMode::Enforce);
        for body in [&index, &image] {
            let key = manifest_key(Some("quay.io"), "library/demo", &sha(body));
            ctx.state.storage.put(&key, body).await.unwrap();
        }
        for rest in [
            format!("manifests/{}", sha(&index)),
            format!("manifests/{}", sha(&image)),
            format!("blobs/{}", sha(&layer)),
        ] {
            assert_eq!(get(&ctx, &rest).await, StatusCode::OK, "{rest}");
        }
    }

    /// A copy still held admits nothing, under observe too, where it is served.
    #[tokio::test]
    async fn a_held_cached_manifest_admits_nothing() {
        let (server, image, layer) = upstream_with_image().await;
        let ctx = context(&server, false, QuarantineMode::Observe);
        let key = manifest_key(Some("quay.io"), "library/demo", &sha(&image));
        ctx.state.storage.put(&key, &image).await.unwrap();
        ctx.state
            .digest_store
            .record("docker", &sha(&image), "x", Some(days_ago(1)));
        assert_eq!(
            get(&ctx, &format!("manifests/{}", sha(&image))).await,
            StatusCode::OK
        );
        assert!(matches!(
            ctx.state
                .digest_store
                .check("docker", &sha(&layer), 3 * 86400),
            crate::digest_quarantine::QuarantineStatus::New
        ));
    }

    /// While the ledger loads a held manifest reads as unrecorded too: nothing is
    /// admitted until it is known.
    #[tokio::test]
    async fn nothing_is_admitted_while_the_ledger_loads() {
        let (server, image, layer) = upstream_with_image().await;
        let ctx = context(&server, false, QuarantineMode::Enforce);
        ctx.state.digest_store.set_loaded(false);
        let key = manifest_key(Some("quay.io"), "library/demo", &sha(&image));
        ctx.state.storage.put(&key, &image).await.unwrap();
        assert_eq!(
            get(&ctx, &format!("manifests/{}", sha(&image))).await,
            StatusCode::OK
        );
        assert!(matches!(
            ctx.state
                .digest_store
                .check("docker", &sha(&layer), 3 * 86400),
            crate::digest_quarantine::QuarantineStatus::New
        ));
    }

    /// A blob fetched while the ledger loads, with no record in memory yet, may be one the
    /// ledger holds as mature (an uncached layer of an old image): the gate waits for the
    /// load, and past the bound answers 503 with Retry-After, never the 403 Docker treats as
    /// final. Once the load ends in time, the ledger's date admits it.
    #[tokio::test(start_paused = true)]
    async fn a_blob_fetched_while_the_ledger_loads_waits_for_it() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.curation.quarantine = Some(QuarantineMode::Enforce);
            cfg.curation.quarantine_ttl = Some("3d".to_string());
        });
        let bound = std::time::Duration::from_secs(30);
        let load = ctx.state.digest_store.begin_load(bound);
        let blob = sha(b"layer of an old image");
        let gate = || {
            let (state, blob) = (ctx.state.clone(), blob.clone());
            async move {
                super::super::quarantine_proxy_fetch_gate(&state, &blob, "up")
                    .await
                    .map(|r| (r.status(), r.headers().contains_key(header::RETRY_AFTER)))
            }
        };

        let started = tokio::time::Instant::now();
        assert_eq!(gate().await, Some((StatusCode::SERVICE_UNAVAILABLE, true)));
        assert!(started.elapsed() >= bound, "waited the whole bound");
        assert!(matches!(
            ctx.state.digest_store.check("docker", &blob, 3 * 86400),
            QuarantineStatus::New
        ));

        let pending = tokio::spawn(gate());
        tokio::time::sleep(bound / 2).await;
        assert!(!pending.is_finished(), "waits for the load");
        ctx.state
            .digest_store
            .record("docker", &blob, "x", Some(days_ago(30)));
        load.cancel();
        assert_eq!(pending.await.unwrap(), None, "the ledger's date admits it");
    }

    /// A load that ended without the whole ledger: a blob with no record in memory is judged
    /// by its own entry object, read from storage, not held as new.
    #[tokio::test(start_paused = true)]
    async fn a_blob_of_an_incomplete_ledger_is_judged_by_its_entry() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.curation.quarantine = Some(QuarantineMode::Enforce);
            cfg.curation.quarantine_ttl = Some("3d".to_string());
        });
        let blob = sha(b"layer of an old image");
        let entry = serde_json::json!({
            "registry": "docker", "digest": blob, "first_seen": days_ago(30), "upstream": "up"
        });
        ctx.state
            .storage
            .put(
                &format!(".nora-quarantine/docker/{blob}"),
                entry.to_string().as_bytes(),
            )
            .await
            .unwrap();
        ctx.state.digest_store.set_loaded(false);
        assert!(
            super::super::quarantine_proxy_fetch_gate(&ctx.state, &blob, "up")
                .await
                .is_none(),
            "the stored date admits it"
        );
        let unseen = sha(b"a layer nobody saw");
        let held = super::super::quarantine_proxy_fetch_gate(&ctx.state, &unseen, "up").await;
        assert_eq!(held.map(|r| r.status()), Some(StatusCode::FORBIDDEN));
    }

    /// The manifest path the same: 503 with Retry-After while the ledger cannot judge the
    /// digest (here a load that is given no time), judged by the ledger once it ends.
    #[tokio::test]
    async fn a_manifest_fetched_while_the_ledger_loads_is_a_503() {
        let (server, image, _) = upstream_with_image().await;
        let ctx = context(&server, false, QuarantineMode::Enforce);
        let load = ctx.state.digest_store.begin_load(std::time::Duration::ZERO);
        let resp = send(
            &ctx.app,
            Method::GET,
            "/v2/library/demo/manifests/v1",
            Body::empty(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(resp.headers().contains_key(header::RETRY_AFTER));
        ctx.state
            .digest_store
            .record("docker", &sha(&image), "x", Some(days_ago(30)));
        load.cancel();
        assert_eq!(get(&ctx, "manifests/v1").await, StatusCode::OK);
    }

    /// Off by default.
    #[tokio::test]
    async fn no_lookup_without_trust() {
        let (server, image, _) = upstream_with_image().await;
        Mock::given(method("GET"))
            .and(path(TAG_API))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(quay_tag(&sha(&image), days_ago(30))),
            )
            .expect(0)
            .mount(&server)
            .await;
        let untrusted = context(&server, false, QuarantineMode::Enforce);
        assert_eq!(get(&untrusted, "manifests/v1").await, StatusCode::FORBIDDEN);
        assert_eq!(
            get(&untrusted, &format!("manifests/{}", sha(&image))).await,
            StatusCode::FORBIDDEN
        );
    }

    /// A digest reference names no tag, so the repository's tags are searched for it.
    #[tokio::test]
    async fn a_digest_reference_is_dated_by_the_tag_that_names_it() {
        let (server, image, layer) = upstream_with_image().await;
        Mock::given(method("GET"))
            .and(path(TAG_API))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(quay_tag(&sha(&image), days_ago(30))),
            )
            .expect(1)
            .mount(&server)
            .await;
        let ctx = context(&server, true, QuarantineMode::Enforce);
        let by_digest = format!("manifests/{}", sha(&image));
        assert_eq!(get(&ctx, &by_digest).await, StatusCode::OK);
        assert_eq!(
            get(&ctx, &format!("blobs/{}", sha(&layer))).await,
            StatusCode::OK
        );
        assert_eq!(get(&ctx, &by_digest).await, StatusCode::OK, "asked once");
    }

    /// A digest no tag names stays first-seen, after a bounded search: untagged says
    /// nothing about its age.
    #[tokio::test]
    async fn a_digest_no_tag_names_is_held_after_a_bounded_search() {
        let (server, image, _) = upstream_with_image().await;
        let mut page = quay_tag(&sha(b"another manifest"), days_ago(30));
        page["has_additional"] = true.into();
        Mock::given(method("GET"))
            .and(path(TAG_API))
            .respond_with(ResponseTemplate::new(200).set_body_json(page))
            .expect(3)
            .mount(&server)
            .await;
        let ctx = context(&server, true, QuarantineMode::Enforce);
        assert_eq!(
            get(&ctx, &format!("manifests/{}", sha(&image))).await,
            StatusCode::FORBIDDEN
        );
    }
}

/// Positive control for the integrity check: when the upstream bytes hash to
/// the requested digest, the blob is verified, cached, and streamed back to
/// the client via the get_reader path (#580) with a 200.
#[tokio::test]
async fn test_docker_proxy_blob_sha256_match_served_and_cached() {
    use crate::config::DockerUpstream;
    use crate::test_helpers::create_test_context_with_config;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let upstream = MockServer::start().await;
    let content = b"a genuine docker layer payload".to_vec();
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&content)));

    Mock::given(method("GET"))
        .and(path(format!("/v2/library/ok/blobs/{digest}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(content.clone()))
        .mount(&upstream)
        .await;

    let ctx = create_test_context_with_config(|cfg| {
        cfg.docker.upstreams = vec![DockerUpstream {
            trust_upstream_dates: false,
            date_token_file: None,
            url: upstream.uri(),
            auth: None,
            auth_env: None,
            namespace: None,
            prefix: None,
            namespaces: Vec::new(),
        }];
    });

    let response = send(
        &ctx.app,
        Method::GET,
        &format!("/v2/library/ok/blobs/{digest}"),
        Body::empty(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_bytes(response).await;
    assert_eq!(
        body.as_ref(),
        content.as_slice(),
        "served body must match upstream"
    );

    // The verified blob is cached under the docker blob key (computed via the same
    // canonicalize/blob_key path the handler uses) once the detached spool stores it,
    // which completes just after the response body.
    let c = super::canonicalize("library/ok", &ctx.state.config.docker);
    let key = super::blob_key(c.namespace.as_deref(), &c.name, &digest);
    let started = std::time::Instant::now();
    while ctx.state.storage.get(&key).await.is_err()
        && started.elapsed() < std::time::Duration::from_secs(5)
    {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        ctx.state.storage.get(&key).await.is_ok(),
        "verified blob must be cached"
    );
}

/// Storage backend that delegates to local storage but fails `get`/`get_reader`
/// with a transient (non-`NotFound`) error for keys under a given prefix —
/// models an object-store blip on the namespaced key while the legacy key
/// stays readable.
struct FailingPrefixBackend {
    inner: crate::storage::LocalStorage,
    fail_prefix: String,
}

#[async_trait::async_trait]
impl crate::storage::StorageBackend for FailingPrefixBackend {
    async fn put(&self, key: &str, data: &[u8], sha256: &str) -> crate::storage::Result<()> {
        self.inner.put(key, data, sha256).await
    }
    async fn get(&self, key: &str) -> crate::storage::Result<(axum::body::Bytes, Option<String>)> {
        if key.starts_with(&self.fail_prefix) {
            return Err(crate::storage::StorageError::Network("injected".into()));
        }
        self.inner.get(key).await
    }
    async fn pin(&self, key: &str) -> Option<String> {
        self.inner.pin(key).await
    }
    async fn delete(&self, key: &str) -> crate::storage::Result<()> {
        self.inner.delete(key).await
    }
    async fn list(&self, prefix: &str) -> crate::storage::Result<Vec<String>> {
        if prefix.starts_with(&self.fail_prefix) {
            return Err(crate::storage::StorageError::Network("injected".into()));
        }
        self.inner.list(prefix).await
    }
    async fn stat(&self, key: &str) -> Option<crate::storage::FileMeta> {
        self.inner.stat(key).await
    }
    async fn health_check(&self) -> bool {
        true
    }
    async fn total_size(&self) -> u64 {
        self.inner.total_size().await
    }
    fn backend_name(&self) -> &'static str {
        "failing-prefix-test"
    }
    async fn copy(&self, src: &str, dst: &str, sha256: Option<&str>) -> crate::storage::Result<()> {
        self.inner.copy(src, dst, sha256).await
    }
    async fn put_from_path(
        &self,
        key: &str,
        src: &std::path::Path,
        sha256: Option<&str>,
    ) -> crate::storage::Result<()> {
        self.inner.put_from_path(key, src, sha256).await
    }
    async fn get_reader(
        &self,
        key: &str,
    ) -> crate::storage::Result<(
        u64,
        Option<String>,
        std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
    )> {
        if key.starts_with(&self.fail_prefix) {
            return Err(crate::storage::StorageError::Network("injected".into()));
        }
        self.inner.get_reader(key).await
    }
}

fn unreachable_upstream() -> crate::config::DockerUpstream {
    crate::config::DockerUpstream {
        trust_upstream_dates: false,
        date_token_file: None,
        // Reserved port on localhost — connect fails fast, no real network.
        url: "http://127.0.0.1:9".to_string(),
        auth: None,
        auth_env: None,
        namespace: None,
        prefix: None,
        namespaces: Vec::new(),
    }
}

async fn get_manifest_via_dispatch(
    state: &crate::AppState,
    path: &str,
) -> axum::response::Response {
    use axum::extract::{Path, State};
    use axum::http::Uri;
    use axum::Extension;
    super::docker_v2_dispatch(
        State(state.clone()),
        Method::GET,
        Path(path.to_string()),
        Extension(crate::auth::NamespaceAuthority::Unrestricted),
        format!("/v2/{path}").parse::<Uri>().unwrap(),
        axum::http::HeaderMap::new(),
        Body::empty(),
    )
    .await
}

/// A transient storage error on the namespaced manifest key must fail closed
/// (500) — NOT silently serve the legacy (flat-key) copy. The two keys can
/// hold different bytes (proxied-current vs pre-migration), so an
/// error-driven fallback makes tag resolution flip per request with backend
/// weather. Drives the real `get_manifest` read via `docker_v2_dispatch`.
#[tokio::test]
async fn manifest_get_fails_closed_on_transient_storage_error() {
    use std::sync::Arc;
    let ctx = create_test_context_with_config(|cfg| {
        cfg.docker.upstreams = vec![unreachable_upstream()];
    });

    // Legacy (flat) copy exists and is readable.
    ctx.state
        .storage
        .put("docker/app/manifests/latest.json", b"{\"legacy\":true}")
        .await
        .unwrap();

    // Same files, but the namespaced key errors transiently. Namespace for
    // an http://127.0.0.1:9 upstream is "127.0.0.1".
    let mut flaky = ctx.state.clone();
    flaky.storage = crate::storage::Storage::from_backend(Arc::new(FailingPrefixBackend {
        inner: crate::storage::LocalStorage::new(ctx._tempdir.path().to_str().unwrap()),
        fail_prefix: "docker/127.0.0.1/".to_string(),
    }));

    let resp = get_manifest_via_dispatch(&flaky, "app/manifests/latest").await;
    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "transient error on the namespaced key must fail closed, not fall back"
    );
}

/// The legacy-key fallback still works for the case it exists for: the
/// namespaced key is genuinely absent (`NotFound`) and a flat-key hosted
/// copy exists. Served as locally authoritative — no upstream round trip,
/// so no `x-nora-stale` even though the configured upstream is unreachable.
#[tokio::test]
async fn manifest_get_serves_hosted_legacy_on_ns_not_found() {
    let ctx = create_test_context_with_config(|cfg| {
        cfg.docker.upstreams = vec![unreachable_upstream()];
    });

    ctx.state
        .storage
        .put("docker/app/manifests/latest.json", b"{\"legacy\":true}")
        .await
        .unwrap();

    let resp = get_manifest_via_dispatch(&ctx.state, "app/manifests/latest").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().get("x-nora-stale").is_none(),
        "hosted copy is authoritative — must not be served via the stale path"
    );
    let body = body_bytes(resp).await;
    assert_eq!(body.as_ref(), b"{\"legacy\":true}");
}
