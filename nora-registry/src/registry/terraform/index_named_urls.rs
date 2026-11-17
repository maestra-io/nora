// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::test_helpers::{
    body_bytes, create_test_context_with_config, create_test_context_with_storage_and_config,
    op_counting_storage, send, TestContext,
};
use axum::http::{Method, StatusCode};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ZIP: &str = "terraform-provider-tool_1.0.0_linux_amd64.zip";
const ARCHIVE: [u8; 4] = [0x1f, 0x8b, b'm', b'd'];
const CRED: &str = "reguser:DUMMY-PASSWORD";
const META_KEY: &str = "terraform/providers/acme/tool/1.0.0/linux_amd64.json";

/// The Authorization header of every request `server` received (`-` when none).
async fn auth_seen(server: &MockServer) -> Vec<String> {
    let requests = server.received_requests().await.unwrap();
    requests
        .iter()
        .map(|r| {
            r.headers
                .get("authorization")
                .map_or_else(|| "-".to_string(), |v| v.to_str().unwrap().to_string())
        })
        .collect()
}

fn basic() -> String {
    use base64::Engine;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(CRED)
    )
}

/// A host answering every GET with `ARCHIVE`.
async fn file_host() -> MockServer {
    let files = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(ARCHIVE.to_vec()))
        .mount(&files)
        .await;
    files
}

/// The registry upstream: `acme/tool` 1.0.0 linux/amd64 has its archive at `download_url`,
/// and module `acme/mod/aws` 1.0.0 its source at `source_url`.
async fn registry(download_url: &str, source_url: &str) -> MockServer {
    let up = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/providers/acme/tool/versions"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"versions":[{"version":"1.0.0","protocols":["5.0"],"platforms":[{"os":"linux","arch":"amd64"}]}]}"#,
        ))
        .mount(&up)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/providers/acme/tool/1.0.0/download/linux/amd64"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "download_url": download_url,
            "shasum": "00",
        })))
        .mount(&up)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/modules/acme/mod/aws/1.0.0/download"))
        .respond_with(ResponseTemplate::new(204).insert_header("x-terraform-get", source_url))
        .mount(&up)
        .await;
    up
}

fn context(up: &MockServer, allow_private_hosts: bool) -> TestContext {
    let uri = up.uri();
    create_test_context_with_config(move |cfg| {
        cfg.terraform.enabled = true;
        cfg.terraform.proxy = Some(uri);
        cfg.terraform.proxy_auth = Some(crate::secrets::ProtectedString::new(CRED.into()));
        cfg.terraform.allow_private_hosts = allow_private_hosts;
    })
}

async fn get(ctx: &TestContext, uri: &str) -> (StatusCode, Vec<u8>) {
    let resp = send(&ctx.app, Method::GET, uri, "").await;
    let status = resp.status();
    (status, body_bytes(resp).await.to_vec())
}

/// The provider archive, after its download metadata.
async fn provider_file(ctx: &TestContext) -> (StatusCode, Vec<u8>) {
    let meta = "/terraform/v1/providers/acme/tool/1.0.0/download/linux/amd64";
    assert_eq!(get(ctx, meta).await.0, StatusCode::OK);
    let file = format!("/terraform/v1/providers/download/acme/tool/1.0.0/{ZIP}");
    get(ctx, &file).await
}

/// The module archive, after its download answer stored the source URL.
async fn module_file(ctx: &TestContext) -> (StatusCode, Vec<u8>) {
    let dl = "/terraform/v1/modules/acme/mod/aws/1.0.0/download";
    assert_eq!(get(ctx, dl).await.0, StatusCode::NO_CONTENT);
    let key = "terraform/modules/acme/mod/aws/1.0.0/_source_url";
    for _ in 0..100 {
        if ctx.state.storage.stat(key).await.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    get(
        ctx,
        "/terraform/v1/modules/download/acme/mod/aws/1.0.0/source",
    )
    .await
}

/// Audit A104: the registry credential goes to the upstream's own origin only.
#[tokio::test]
async fn an_archive_on_another_origin_gets_no_credential() {
    let files = file_host().await;
    let up = registry(
        &format!("{}/x/{ZIP}", files.uri()),
        &format!("{}/x/mod.tar.gz", files.uri()),
    )
    .await;
    let ctx = context(&up, true);
    assert_eq!(
        provider_file(&ctx).await,
        (StatusCode::OK, ARCHIVE.to_vec())
    );
    assert_eq!(module_file(&ctx).await, (StatusCode::OK, ARCHIVE.to_vec()));
    assert_eq!(auth_seen(&files).await, vec!["-", "-"]);
}

/// Audit A104: an archive on the upstream's own origin still gets it.
#[tokio::test]
async fn an_archive_on_the_upstreams_own_origin_keeps_the_credential() {
    let up = MockServer::start().await;
    let own = up.uri();
    Mock::given(method("GET"))
        .and(path("/v1/providers/acme/tool/1.0.0/download/linux/amd64"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "download_url": format!("{own}/x/{ZIP}"),
            "shasum": "00",
        })))
        .mount(&up)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/x/{ZIP}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(ARCHIVE.to_vec()))
        .mount(&up)
        .await;
    let ctx = context(&up, true);
    assert_eq!(
        provider_file(&ctx).await,
        (StatusCode::OK, ARCHIVE.to_vec())
    );
    assert_eq!(auth_seen(&up).await, vec![basic(), basic()]);
}

/// Audit A104: metadata cannot aim NORA at a loopback/private address, by IP literal or by a
/// name that resolves to one, unless `allow_private_hosts`.
#[tokio::test]
async fn metadata_cannot_aim_nora_at_a_private_address() {
    let files = file_host().await;
    let port = files.address().port();
    for host in [format!("127.0.0.1:{port}"), format!("localhost:{port}")] {
        let up = registry(
            &format!("http://{host}/x/{ZIP}"),
            &format!("http://{host}/x/mod.tar.gz"),
        )
        .await;
        let ctx = context(&up, false);
        assert_eq!(
            provider_file(&ctx).await.0,
            StatusCode::BAD_GATEWAY,
            "{host}"
        );
        assert_eq!(module_file(&ctx).await.0, StatusCode::BAD_GATEWAY, "{host}");
        for key in [
            format!("terraform/download/acme/tool/1.0.0/{ZIP}"),
            "terraform/modules/acme/mod/aws/1.0.0/source.tar.gz".to_string(),
        ] {
            assert!(ctx.state.storage.stat(&key).await.is_none(), "{key}");
        }
    }
    assert!(files.received_requests().await.unwrap().is_empty());
}

/// The switch lets them through, whether or not private upstreams are allowed (the shared
/// client refuses private addresses unless they are).
#[tokio::test]
async fn allow_private_hosts_fetches_a_private_archive() {
    let files = file_host().await;
    let port = files.address().port();
    let up = registry(
        &format!("http://localhost:{port}/x/{ZIP}"),
        &format!("http://localhost:{port}/x/mod.tar.gz"),
    )
    .await;
    let uri = up.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.terraform.enabled = true;
        cfg.terraform.proxy = Some(uri);
        cfg.terraform.allow_private_hosts = true;
        cfg.server.allow_private_upstreams = false;
    });
    // The registry upstream itself is an IP literal, which the shared client does not check.
    assert_eq!(
        provider_file(&ctx).await,
        (StatusCode::OK, ARCHIVE.to_vec())
    );
    assert_eq!(module_file(&ctx).await, (StatusCode::OK, ARCHIVE.to_vec()));
}

/// Audit A106: with no metadata, a file outside the `hashicorp` namespace is not guessed from
/// releases.hashicorp.com by type and version: 404, nothing fetched or cached.
#[tokio::test]
async fn a_file_with_no_metadata_outside_hashicorp_is_404() {
    let up = MockServer::start().await;
    let ctx = context(&up, true);
    let key = format!("terraform/download/other-ns/tool/1.0.0/{ZIP}");
    let uri = format!("/terraform/v1/providers/download/other-ns/tool/1.0.0/{ZIP}");
    assert_eq!(get(&ctx, &uri).await.0, StatusCode::NOT_FOUND);
    assert!(ctx.state.storage.stat(&key).await.is_none());
    assert!(up.received_requests().await.unwrap().is_empty());

    let resolve = |ns: &'static str| {
        super::resolve_upstream_download_url(&ctx.state, ns, "tool", "1.0.0", ZIP)
    };
    assert_eq!(
        resolve("hashicorp").await.as_deref(),
        Some(
            format!("https://releases.hashicorp.com/terraform-provider-tool/1.0.0/{ZIP}").as_str()
        )
    );
    assert_eq!(resolve("other-ns").await, None);
}

/// Audit A106: the file path's namespace, type and version are checked like the metadata's.
#[tokio::test]
async fn a_file_path_with_an_invalid_name_is_refused() {
    let up = MockServer::start().await;
    let ctx = context(&up, true);
    for uri in [
        format!("/terraform/v1/providers/download/ac!me/tool/1.0.0/{ZIP}"),
        format!("/terraform/v1/providers/download/acme/to%20ol/1.0.0/{ZIP}"),
        format!("/terraform/v1/providers/download/acme/tool/1.0.0!/{ZIP}"),
    ] {
        assert_eq!(get(&ctx, &uri).await.0, StatusCode::BAD_REQUEST, "{uri}");
    }
}

/// Audit A106: the platform metadata is stored before the answer that names its archive goes
/// out, on the registry protocol and on the network mirror: while its write is held, the
/// answer does not complete.
#[tokio::test]
async fn platform_metadata_is_stored_before_the_answer() {
    let files = file_host().await;
    let up = registry(&format!("{}/x/{ZIP}", files.uri()), "").await;
    for uri in [
        "/terraform/v1/providers/acme/tool/1.0.0/download/linux/amd64",
        "/terraform/registry.terraform.io/acme/tool/1.0.0.json",
    ] {
        let (storage, ops) = op_counting_storage();
        let url = up.uri();
        let ctx = create_test_context_with_storage_and_config(storage, move |cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some(url);
        });
        ops.hold_next_put(META_KEY);
        let app = ctx.app.clone();
        let mut answer =
            tokio::spawn(async move { send(&app, Method::GET, uri, "").await.status() });
        ops.put_parked().await;
        let early = tokio::time::timeout(std::time::Duration::from_millis(200), &mut answer).await;
        assert!(
            early.is_err(),
            "{uri}: answered before its metadata was stored"
        );
        ops.release_put();
        assert_eq!(answer.await.unwrap(), StatusCode::OK, "{uri}");
        assert!(ctx.state.storage.stat(META_KEY).await.is_some(), "{uri}");
    }
}

/// Audit A106: a platform metadata write that fails answers a retryable 503 outside the
/// `hashicorp` namespace (its archive could not be resolved later), on both routes.
#[tokio::test]
async fn a_failed_metadata_write_is_retryable_outside_hashicorp() {
    let files = file_host().await;
    let up = registry(&format!("{}/x/{ZIP}", files.uri()), "").await;
    for uri in [
        "/terraform/v1/providers/acme/tool/1.0.0/download/linux/amd64",
        "/terraform/registry.terraform.io/acme/tool/1.0.0.json",
    ] {
        let (storage, ops) = op_counting_storage();
        let url = up.uri();
        let ctx = create_test_context_with_storage_and_config(storage, move |cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some(url);
        });
        ops.fail_puts_ending(Some("linux_amd64.json"));
        let resp = send(&ctx.app, Method::GET, uri, "").await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "{uri}");
        assert!(resp.headers().contains_key("retry-after"), "{uri}");
    }
}
