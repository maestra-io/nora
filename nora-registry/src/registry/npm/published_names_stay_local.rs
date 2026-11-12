// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::test_helpers::{
    body_bytes, create_test_context_with_config, create_test_context_with_storage_and_config,
    outage_storage, send, send_with_headers, TestContext,
};
use axum::body::Body;
use axum::http::{Method, StatusCode};
use base64::Engine;
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, ResponseTemplate};

const BULK: &str = "/npm/-/npm/v1/security/advisories/bulk";

async fn recording_upstream() -> MockServer {
    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&upstream)
        .await;
    upstream
}

async fn publish(ctx: &TestContext, name: &str, version: &str) {
    let short = name.rsplit('/').next().unwrap();
    let payload = serde_json::json!({
        "name": name,
        "versions": { version: { "name": name, "version": version, "dist": {} } },
        "_attachments": { format!("{short}-{version}.tgz"): {
            "data": base64::engine::general_purpose::STANDARD.encode(b"published"),
        } },
    });
    let resp = send(
        &ctx.app,
        Method::PUT,
        &format!("/npm/{name}"),
        Body::from(serde_json::to_vec(&payload).unwrap()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

async fn asked(upstream: &MockServer) -> Vec<String> {
    upstream
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.url.path().to_string())
        .collect()
}

/// A published package's tag or package fields the store cannot read are not left out: the
/// packument rebuilt without a stored one and the tags answer 503 (500 for a copy that fails
/// its integrity check) rather than a document without them — a `latest` derived from the
/// versions names another version than the one tagged — and a publish stores no packument
/// without them, so the tag is there once the store reads again.
#[tokio::test]
async fn a_published_tag_that_cannot_be_read_is_unavailable_not_left_out() {
    use crate::test_helpers::ReadFault;
    async fn latest(ctx: &TestContext) -> (StatusCode, serde_json::Value) {
        let resp = send(&ctx.app, Method::GET, "/npm/pkg", "").await;
        let status = resp.status();
        let doc: serde_json::Value =
            serde_json::from_slice(&body_bytes(resp).await).unwrap_or_default();
        (status, doc["dist-tags"]["latest"].clone())
    }
    let mut wrong = Vec::new();
    for (fault, expected) in [
        (ReadFault::Network, StatusCode::SERVICE_UNAVAILABLE),
        (ReadFault::Tampered, StatusCode::INTERNAL_SERVER_ERROR),
    ] {
        for unreadable in ["npm/pkg/dist-tags/latest", "npm/pkg/pkg.json"] {
            let upstream = recording_upstream().await;
            let uri = upstream.uri();
            let (storage, outage) = outage_storage();
            let ctx = create_test_context_with_storage_and_config(storage, move |c| {
                c.npm.proxy = Some(uri);
            });
            publish(&ctx, "pkg", "1.0.0").await;
            publish(&ctx, "pkg", "1.0.1").await;
            // The older version is the one tagged.
            ctx.state
                .storage
                .put("npm/pkg/dist-tags/latest", b"1.0.0")
                .await
                .unwrap();
            ctx.state
                .storage
                .delete("npm/pkg/metadata.json")
                .await
                .unwrap();
            let (status, tagged) = latest(&ctx).await;
            if (status, tagged.as_str()) != (StatusCode::OK, Some("1.0.0")) {
                wrong.push(format!("with the store up: {status} latest {tagged}"));
            }
            ctx.state
                .storage
                .delete("npm/pkg/metadata.json")
                .await
                .unwrap();
            outage.fault_reads_of(unreadable, fault);
            for path in ["/npm/pkg", "/npm/-/package/pkg/dist-tags"] {
                let status = send(&ctx.app, Method::GET, path, "").await.status();
                if status != expected {
                    wrong.push(format!("{path}, {unreadable} {fault:?} -> {status}"));
                }
            }
            // A publish while the tag cannot be read.
            let payload = serde_json::json!({
                "name": "pkg",
                "versions": { "1.0.2": { "name": "pkg", "version": "1.0.2", "dist": {} } },
                "_attachments": { "pkg-1.0.2.tgz": {
                    "data": base64::engine::general_purpose::STANDARD.encode(b"published"),
                } },
            });
            let published = send(
                &ctx.app,
                Method::PUT,
                "/npm/pkg",
                Body::from(serde_json::to_vec(&payload).unwrap()),
            )
            .await
            .status();
            outage.end();
            let (status, tagged) = latest(&ctx).await;
            if (status, tagged.as_str()) != (StatusCode::OK, Some("1.0.0")) {
                wrong.push(format!(
                    "after a publish ({published}) with {unreadable} {fault:?}: {status} latest {tagged}"
                ));
            }
            let asked = asked(&upstream).await;
            if !asked.is_empty() {
                wrong.push(format!("upstream asked, {unreadable} {fault:?}: {asked:?}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// A listing of a published package's tags that fails is not taken for no tags: the
/// packument rebuilt without a stored one answers 503 rather than a `latest` derived from
/// the versions.
#[tokio::test]
async fn a_published_package_whose_tags_cannot_be_listed_is_unavailable() {
    let (storage, outage) = outage_storage();
    let ctx = create_test_context_with_storage_and_config(storage, |_| {});
    publish(&ctx, "pkg", "1.0.0").await;
    publish(&ctx, "pkg", "1.0.1").await;
    ctx.state
        .storage
        .put("npm/pkg/dist-tags/latest", b"1.0.0")
        .await
        .unwrap();
    ctx.state
        .storage
        .delete("npm/pkg/metadata.json")
        .await
        .unwrap();
    outage.fail_listings_of("npm/pkg/dist-tags/");
    for path in ["/npm/pkg", "/npm/-/package/pkg/dist-tags"] {
        let status = send(&ctx.app, Method::GET, path, "").await.status();
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{path}");
    }
    outage.end();
    let resp = send(&ctx.app, Method::GET, "/npm/pkg", "").await;
    let doc: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(doc["dist-tags"]["latest"], "1.0.0");
}

/// A published version whose document the store cannot read is unavailable, not absent and
/// not left out: its manifest (by version or by tag), the packument rebuilt without a stored
/// one and the tags answer 503 for a store that cannot be asked and 500 for a copy that fails
/// its integrity check — never 404 or a document without the version — and the upstream is
/// not asked. Another version still reads.
#[tokio::test]
async fn a_published_version_whose_document_cannot_be_read_is_unavailable_not_absent() {
    use crate::test_helpers::ReadFault;
    let mut wrong = Vec::new();
    for (fault, expected) in [
        (ReadFault::Network, StatusCode::SERVICE_UNAVAILABLE),
        (ReadFault::Tampered, StatusCode::INTERNAL_SERVER_ERROR),
    ] {
        for (unreadable, paths) in [
            (
                "npm/pkg/versions/1.0.0.json",
                &["/npm/pkg/1.0.0", "/npm/pkg", "/npm/-/package/pkg/dist-tags"][..],
            ),
            ("npm/pkg/dist-tags/latest", &["/npm/pkg/latest"][..]),
        ] {
            let upstream = recording_upstream().await;
            let uri = upstream.uri();
            let (storage, outage) = outage_storage();
            let ctx = create_test_context_with_storage_and_config(storage, move |c| {
                c.npm.proxy = Some(uri);
            });
            publish(&ctx, "pkg", "1.0.0").await;
            publish(&ctx, "pkg", "1.0.1").await;
            // The tag a client's publish sets.
            ctx.state
                .storage
                .put("npm/pkg/dist-tags/latest", b"1.0.1")
                .await
                .unwrap();
            // No stored packument: it is rebuilt from the published keys.
            ctx.state
                .storage
                .delete("npm/pkg/metadata.json")
                .await
                .unwrap();
            for path in paths {
                let status = send(&ctx.app, Method::GET, path, "").await.status();
                if status != StatusCode::OK {
                    wrong.push(format!("{path} with the store up -> {status}"));
                }
            }
            // Rebuilt and stored again where the reads above read the packument.
            let _ = ctx.state.storage.delete("npm/pkg/metadata.json").await;
            outage.fault_reads_of(unreadable, fault);
            for path in paths {
                let status = send(&ctx.app, Method::GET, path, "").await.status();
                if status != expected {
                    wrong.push(format!("{path}, {unreadable} {fault:?} -> {status}"));
                }
            }
            let other = send(&ctx.app, Method::GET, "/npm/pkg/1.0.1", "").await;
            if other.status() != StatusCode::OK {
                wrong.push(format!(
                    "/npm/pkg/1.0.1, {unreadable} {fault:?} -> {}",
                    other.status()
                ));
            }
            let asked = asked(&upstream).await;
            if !asked.is_empty() {
                wrong.push(format!("upstream asked, {unreadable} {fault:?}: {asked:?}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[tokio::test]
async fn a_tarball_a_published_package_does_not_store_is_not_fetched() {
    let upstream = recording_upstream().await;
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxy = Some(uri));
    publish(&ctx, "corp-lib", "1.0.0").await;
    publish(&ctx, "@corp/lib", "1.0.0").await;

    for path in [
        "/npm/corp-lib/-/corp-lib-9.9.9.tgz",
        "/npm/@corp/lib/-/lib-9.9.9.tgz",
        "/npm/download/@corp/lib/9.9.9/0123abcd",
    ] {
        let resp = send(&ctx.app, Method::GET, path, "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
    }
    assert_eq!(asked(&upstream).await, Vec::<String>::new());
    let tarballs = ctx
        .state
        .storage
        .list("npm/corp-lib/tarballs/")
        .await
        .unwrap();
    assert!(
        tarballs.iter().all(|key| !key.contains("9.9.9")),
        "{tarballs:?}"
    );

    // Controls: the published version is served from its own bytes, and a package that is
    // not published is still fetched from the upstream.
    let own = send(
        &ctx.app,
        Method::GET,
        "/npm/corp-lib/-/corp-lib-1.0.0.tgz",
        "",
    )
    .await;
    assert_eq!(own.status(), StatusCode::OK);
    assert_eq!(&body_bytes(own).await[..], b"published");
    super::mount_listing(&upstream, "other", &[("1.0.0", "other/-/other-1.0.0.tgz")]).await;
    let other = send(&ctx.app, Method::GET, "/npm/other/-/other-1.0.0.tgz", "").await;
    assert_eq!(other.status(), StatusCode::OK);
    assert!(asked(&upstream)
        .await
        .contains(&"/other/-/other-1.0.0.tgz".to_string()));
}

/// The JSON object the upstream received as the bulk audit body.
async fn forwarded(upstream: &MockServer) -> serde_json::Value {
    let requests = upstream.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "one audit forwarded");
    serde_json::from_slice(&requests[0].body).unwrap()
}

#[tokio::test]
async fn a_bulk_audit_does_not_name_a_published_package_to_the_upstream() {
    let body = serde_json::json!({
        "corp-lib": ["1.0.0"],
        "@corp/lib": ["1.0.0"],
        "plain-pkg": ["1.0.0"],
    });
    let gzipped = {
        use std::io::Write;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(body.to_string().as_bytes()).unwrap();
        gz.finish().unwrap()
    };
    // Without a namespace filter, and with one that does not cover the published names.
    for filter in [vec![], vec!["@internal/*".to_string()]] {
        for gzip in [false, true] {
            let upstream = recording_upstream().await;
            let uri = upstream.uri();
            let namespaces = filter.clone();
            let ctx = create_test_context_with_config(move |cfg| {
                cfg.npm.proxy = Some(uri);
                cfg.curation.internal_namespaces = namespaces;
            });
            publish(&ctx, "corp-lib", "1.0.0").await;
            publish(&ctx, "@corp/lib", "1.0.0").await;
            let resp = if gzip {
                send_with_headers(
                    &ctx.app,
                    Method::POST,
                    BULK,
                    vec![("content-encoding", "gzip")],
                    gzipped.clone(),
                )
                .await
            } else {
                send(&ctx.app, Method::POST, BULK, body.to_string()).await
            };
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "filter {filter:?} gzip {gzip}"
            );
            assert_eq!(
                forwarded(&upstream).await,
                serde_json::json!({ "plain-pkg": ["1.0.0"] }),
                "filter {filter:?} gzip {gzip}"
            );
        }
    }
}

#[tokio::test]
async fn a_bulk_audit_naming_no_published_package_is_forwarded_as_sent() {
    let upstream = recording_upstream().await;
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| cfg.npm.proxy = Some(uri));
    publish(&ctx, "corp-lib", "1.0.0").await;
    let sent = r#"{"plain-pkg":["1.0.0"],"lodash":["4.17.0"]}"#;
    let resp = send(&ctx.app, Method::POST, BULK, sent).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let requests = upstream.received_requests().await.unwrap();
    assert_eq!(&requests[0].body[..], sent.as_bytes());
}

#[tokio::test]
async fn a_bulk_audit_is_refused_while_the_store_cannot_tell_what_is_published() {
    let upstream = recording_upstream().await;
    let uri = upstream.uri();
    let (storage, outage) = outage_storage();
    let ctx =
        create_test_context_with_storage_and_config(storage, move |cfg| cfg.npm.proxy = Some(uri));
    publish(&ctx, "corp-lib", "1.0.0").await;
    outage.begin();
    let resp = send(
        &ctx.app,
        Method::POST,
        BULK,
        r#"{"corp-lib":["1.0.0"],"plain-pkg":["1.0.0"]}"#,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(asked(&upstream).await, Vec::<String>::new());
}
