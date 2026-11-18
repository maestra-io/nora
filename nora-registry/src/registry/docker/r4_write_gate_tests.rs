// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::auth::NamespaceAuthority;
use crate::config::{DockerUpstream, ScopeEnforcement};
use crate::test_helpers::{body_bytes, create_test_context_with_config, TestContext};
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{Method, StatusCode, Uri};
use axum::Extension;

const CFG: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn upstream(namespace: &str, prefix: Option<&str>) -> DockerUpstream {
    DockerUpstream {
        trust_upstream_dates: false,
        date_token_file: None,
        token_hosts: Vec::new(),
        url: "http://127.0.0.1:1".into(),
        auth: None,
        auth_env: None,
        namespace: Some(namespace.into()),
        prefix: prefix.map(String::from),
        namespaces: Vec::new(),
    }
}

fn ctx(upstreams: Vec<DockerUpstream>) -> TestContext {
    create_test_context_with_config(move |cfg| cfg.docker.upstreams = upstreams)
}

fn scoped(pattern: &str) -> NamespaceAuthority {
    let scope = [pattern.to_string()];
    NamespaceAuthority::from_oidc_scopes("ci", [&scope[..]], ScopeEnforcement::Enforce)
}

async fn call(
    ctx: &TestContext,
    authority: NamespaceAuthority,
    method: Method,
    path: &str,
    body: Vec<u8>,
) -> (StatusCode, String) {
    let resp = super::docker_v2_dispatch(
        State(ctx.state.clone()),
        method,
        // The wildcard is the path; a query (`?mount=…`) reaches the handler through the URI.
        Path(path.split('?').next().unwrap_or_default().to_string()),
        Extension(authority),
        None,
        format!("/v2/{path}").parse::<Uri>().unwrap(),
        axum::http::HeaderMap::new(),
        Body::from(body),
    )
    .await;
    let status = resp.status();
    let json: serde_json::Value =
        serde_json::from_slice(&body_bytes(resp).await).unwrap_or_default();
    let code = json["errors"][0]["code"].as_str().unwrap_or_default();
    (status, code.to_string())
}

fn manifest() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 0,
            "digest": CFG
        },
        "layers": []
    }))
    .unwrap()
}

async fn stored(ctx: &TestContext) -> Vec<String> {
    ctx.state.storage.list("docker/").await.unwrap()
}

/// A scope that names a registry host or a routing prefix does not reach the repository
/// behind it: `harbor.corp/payments/api` and `ghcr/payments/api` land in `payments/api`.
#[tokio::test]
async fn the_scope_is_checked_on_the_name_the_write_lands_in() {
    let ctx = ctx(vec![upstream("ghcr.io", Some("ghcr"))]);
    for (scope, path) in [
        ("harbor.corp/*", "harbor.corp/payments/api/manifests/latest"),
        ("ghcr/*", "ghcr/payments/api/manifests/latest"),
        ("ghcr/*", "ghcr/payments/api/blobs/uploads/"),
    ] {
        let method = if path.ends_with('/') {
            Method::POST
        } else {
            Method::PUT
        };
        let (status, _) = call(&ctx, scoped(scope), method, path, manifest()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{scope} {path}");
    }
    assert_eq!(stored(&ctx).await, Vec::<String>::new());

    // The scope of the repository itself lets a push to it through. Pushed under the prefix,
    // the same name is the upstream's pull-through, refused whatever the scope (A011).
    ctx.state
        .storage
        .put(&format!("docker/payments/api/blobs/{CFG}"), b"x")
        .await
        .unwrap();
    let path = "payments/api/manifests/latest";
    let (status, _) = call(&ctx, scoped("payments/*"), Method::PUT, path, manifest()).await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(ctx
        .state
        .storage
        .stat("docker/payments/api/manifests/latest.json")
        .await
        .is_some());
}

/// A write under an upstream's storage namespace would overwrite that upstream's proxy
/// cache: `mirror/library/alpine` is the cache of `library/alpine` when the namespace is
/// `mirror`, and `docker.io/docker.io/x` strips to `docker.io/x`. A repository merely named
/// like the namespace is not under it.
#[tokio::test]
async fn a_write_under_an_upstream_cache_namespace_is_refused() {
    let ctx = ctx(vec![upstream("mirror", None), upstream("docker.io", None)]);
    let open = || NamespaceAuthority::Unrestricted;
    for path in [
        "mirror/library/alpine/blobs/uploads/",
        "docker.io/docker.io/x/blobs/uploads/",
    ] {
        let (status, code) = call(&ctx, open(), Method::POST, path, Vec::new()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(code, "NAME_INVALID", "{path}");
    }
    for path in ["mirror/blobs/uploads/", "team/mirror/blobs/uploads/"] {
        let (status, _) = call(&ctx, open(), Method::POST, path, Vec::new()).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{path}");
    }
}

/// R4-R11: a write behind a registry host no upstream serves is refused. Routing drops the
/// host, so `quay.io/team/app` would land in `team/app`. Docker Hub's host without an upstream
/// of its own is the fallback chain, as a bare name is, and takes the write; a host an
/// upstream serves is that upstream's pull-through (A011).
#[tokio::test]
async fn a_write_behind_an_unserved_registry_host_is_refused() {
    let ctx = ctx(vec![upstream("ghcr.io", Some("ghcr"))]);
    let open = || NamespaceAuthority::Unrestricted;
    let blob = format!("quay.io/team/app/blobs/{CFG}");
    for (method, path) in [
        (Method::POST, "quay.io/team/app/blobs/uploads/"),
        (Method::PUT, "quay.io/team/app/manifests/v1"),
        (Method::DELETE, "quay.io/team/app/manifests/v1"),
        (Method::DELETE, blob.as_str()),
    ] {
        let (status, code) = call(&ctx, open(), method.clone(), path, manifest()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{method} {path}");
        assert_eq!(code, "NAME_INVALID", "{method} {path}");
    }
    assert_eq!(stored(&ctx).await, Vec::<String>::new());
    for path in [
        "docker.io/team/app/blobs/uploads/",
        "team/app/blobs/uploads/",
    ] {
        let (status, _) = call(&ctx, open(), Method::POST, path, Vec::new()).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{path}");
    }
    let path = "ghcr.io/team/app/blobs/uploads/";
    let (status, code) = call(&ctx, open(), Method::POST, path, Vec::new()).await;
    assert_eq!((status, code.as_str()), (StatusCode::FORBIDDEN, "DENIED"));
}

/// A011: a name a prefix, `namespaces` or a served registry host routes is the upstream's
/// pull-through. No write lands on it — push, upload, mount or delete, with any scope — so the
/// upstream's tag stays what every puller gets. `curation.internal_namespaces` opts a name in.
#[tokio::test]
async fn a_write_to_an_upstream_routed_name_is_refused() {
    let mut bound = upstream("harbor.corp", None);
    bound.namespaces = vec!["corp".into()];
    let ctx = ctx(vec![upstream("ghcr.io", Some("ghcr")), bound]);
    ctx.state
        .storage
        .put(&format!("docker/ghcr.io/payments/api/blobs/{CFG}"), b"x")
        .await
        .unwrap();
    let before = stored(&ctx).await;
    let blob = format!("ghcr/payments/api/blobs/{CFG}");
    let mount = format!("ghcr/payments/api/blobs/uploads/?mount={CFG}&from=team/app");
    for (method, path) in [
        (Method::POST, "ghcr/payments/api/blobs/uploads/"),
        (Method::POST, mount.as_str()),
        (Method::PUT, "ghcr/payments/api/manifests/latest"),
        (Method::DELETE, "ghcr/payments/api/manifests/latest"),
        (Method::DELETE, blob.as_str()),
        (Method::POST, "ghcr.io/team/app/blobs/uploads/"),
        (Method::PUT, "corp/app/manifests/v1"),
    ] {
        let (status, code) = call(
            &ctx,
            NamespaceAuthority::Unrestricted,
            method.clone(),
            path,
            manifest(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}");
        assert_eq!(code, "DENIED", "{method} {path}");
    }
    assert_eq!(stored(&ctx).await, before, "nothing written or deleted");

    // Listed in `curation.internal_namespaces`, the routed name is the operator's to push.
    let ctx = create_test_context_with_config(|cfg| {
        cfg.docker.upstreams = vec![upstream("ghcr.io", Some("ghcr"))];
        cfg.curation.internal_namespaces = vec!["payments/*".into()];
    });
    ctx.state
        .storage
        .put(&format!("docker/payments/api/blobs/{CFG}"), b"x")
        .await
        .unwrap();
    let path = "ghcr/payments/api/manifests/latest";
    let (status, _) = call(
        &ctx,
        NamespaceAuthority::Unrestricted,
        Method::PUT,
        path,
        manifest(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
}

async fn pull(ctx: &TestContext, path: &str) -> (StatusCode, Vec<u8>) {
    let resp = super::docker_v2_dispatch(
        State(ctx.state.clone()),
        Method::GET,
        Path(path.to_string()),
        Extension(NamespaceAuthority::Unrestricted),
        None,
        format!("/v2/{path}").parse::<Uri>().unwrap(),
        axum::http::HeaderMap::new(),
        Body::empty(),
    )
    .await;
    (resp.status(), body_bytes(resp).await.to_vec())
}

/// A011 (review R02): the bare name shares its keys with the name a prefix routes to the
/// fallback upstream. A push of the bare name answers the bare name only; the routed name stays
/// the upstream's, never the push or its bare copy, unless `curation.internal_namespaces` lists it.
#[tokio::test]
async fn a_bare_push_does_not_answer_the_routed_name() {
    let upstream_copy = br#"{"schemaVersion":2,"layers":[]}"#;
    for internal in [false, true] {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.docker.upstreams = vec![upstream("ghcr.io", Some("ghcr"))];
            if internal {
                cfg.curation.internal_namespaces = vec!["payments/*".into()];
            }
        });
        let storage = &ctx.state.storage;
        storage
            .put(&format!("docker/payments/api/blobs/{CFG}"), b"x")
            .await
            .unwrap();
        storage
            .put(
                "docker/ghcr.io/payments/api/manifests/latest.json",
                upstream_copy,
            )
            .await
            .unwrap();
        let pushed = manifest();
        let path = "payments/api/manifests/latest";
        let (status, _) = call(
            &ctx,
            NamespaceAuthority::Unrestricted,
            Method::PUT,
            path,
            pushed.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        assert_eq!(pull(&ctx, path).await, (StatusCode::OK, pushed.clone()));
        let (status, body) = pull(&ctx, "ghcr/payments/api/manifests/latest").await;
        if internal {
            assert_eq!((status, body), (StatusCode::OK, pushed));
        } else {
            assert_ne!(
                body, pushed,
                "the routed name answered the bare push ({status})"
            );
        }
    }
}
