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
        Path(path.to_string()),
        Extension(authority),
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

    // The scope of the repository itself lets the same push through.
    ctx.state
        .storage
        .put(&format!("docker/payments/api/blobs/{CFG}"), b"x")
        .await
        .unwrap();
    let path = "ghcr/payments/api/manifests/latest";
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
