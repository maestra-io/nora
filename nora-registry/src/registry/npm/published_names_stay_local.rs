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
    let twin = crate::test_helpers::npm_first_publish_twin(ctx, name).await;
    let resp = send(
        &twin.as_ref().unwrap_or(ctx).app,
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

/// A tarball belongs to a package `pkg` or `@scope/pkg`: a deeper name (`pkg/versions`) is
/// refused before any upstream request or cache write, so nothing lands under another
/// package's `versions/`. A key nested under `versions/` that is already there is no
/// version of that package and does not make it published.
#[tokio::test]
async fn a_tarball_under_a_nested_name_writes_nothing_under_another_package() {
    let upstream = recording_upstream().await;
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |c| {
        c.npm.proxy = Some(uri);
    });
    for path in [
        "/npm/dummy/versions/-/versions-1.0.0.tgz",
        "/npm/@scope/dummy/versions/-/versions-1.0.0.tgz",
        "/npm/@scope/-/scope-1.0.0.tgz",
    ] {
        let resp = send(&ctx.app, Method::GET, path, "").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{path}");
    }
    assert!(asked(&upstream).await.is_empty());
    for prefix in ["npm/dummy/versions/", "npm/@scope/dummy/versions/"] {
        assert!(ctx.state.storage.list(prefix).await.unwrap().is_empty());
    }
    // The package `-` and a scoped name still reach the tarball path.
    for path in ["/npm/-/-/--1.0.0.tgz", "/npm/@scope/pkg/-/pkg-1.0.0.tgz"] {
        let resp = send(&ctx.app, Method::GET, path, "").await;
        assert_ne!(resp.status(), StatusCode::BAD_REQUEST, "{path}");
    }

    ctx.state
        .storage
        .put("npm/stray/versions/upstream/packument.json", b"{}")
        .await
        .unwrap();
    assert!(matches!(
        super::published_state(&ctx.state.storage, "stray").await,
        super::Published::No
    ));
    publish(&ctx, "stray", "1.0.0").await;
    match super::published_state(&ctx.state.storage, "stray").await {
        super::Published::Yes(versions) => {
            assert_eq!(versions.into_iter().collect::<Vec<_>>(), ["1.0.0"]);
        }
        _ => panic!("stray 1.0.0 is published"),
    }
}

/// A name byte the upstream URL parser strips or reads as a delimiter (control, space, `#`,
/// `?`) would let curation judge one package and the upstream serve another: refused.
#[tokio::test]
async fn a_path_byte_the_url_parser_reinterprets_never_reaches_upstream() {
    let upstream = recording_upstream().await;
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |c| {
        c.npm.proxy = Some(uri);
        c.curation.internal_namespaces = vec!["internalpkg".to_string()];
    });
    for path in [
        "/npm/internal%09pkg",
        "/npm/internal%0Apkg",
        "/npm/internal%0Dpkg",
        "/npm/internalpkg%20",
        "/npm/x%23",
        "/npm/x%3Fy",
        "/npm/internal%09pkg/-/internalpkg-1.0.0.tgz",
        "/npm/x/-/x-1.0.0.tgz%23",
    ] {
        let resp = send(&ctx.app, Method::GET, path, "").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{path}");
    }
    assert!(asked(&upstream).await.is_empty());
}

const A091_USERS: &[(&str, &str)] = &[("pub", "pw-pub"), ("ro", "pw-ro")];

/// `user`'s request (one of [`A091_USERS`]); the status and body.
async fn as_user(
    ctx: &TestContext,
    m: Method,
    uri: &str,
    user: &str,
    body: Vec<u8>,
) -> (StatusCode, Vec<u8>) {
    let pw = A091_USERS.iter().find(|(u, _)| *u == user).unwrap().1;
    let auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pw}"))
    );
    let resp = send_with_headers(
        &ctx.app,
        m,
        uri,
        vec![("authorization", auth.as_str())],
        Body::from(body),
    )
    .await;
    let status = resp.status();
    (status, body_bytes(resp).await.to_vec())
}

fn publish_body(name: &str, version: &str, tarball: &[u8]) -> Vec<u8> {
    let short = name.rsplit('/').next().unwrap();
    serde_json::to_vec(&serde_json::json!({
        "name": name,
        "versions": { version: { "name": name, "version": version, "dist": {} } },
        "dist-tags": { "latest": version },
        "_attachments": { format!("{short}-{version}.tgz"): {
            "data": base64::engine::general_purpose::STANDARD.encode(tarball),
        } }
    }))
    .unwrap()
}

/// An upstream serving `is-odd@3.0.1` (released long ago) and its tarball.
async fn is_odd_upstream() -> MockServer {
    use wiremock::matchers::{method, path};
    let up = MockServer::start().await;
    let doc = serde_json::json!({
        "name": "is-odd",
        "dist-tags": { "latest": "3.0.1" },
        "versions": { "3.0.1": { "name": "is-odd", "version": "3.0.1",
            "dist": { "tarball": format!("{}/is-odd/-/is-odd-3.0.1.tgz", up.uri()) } } },
        "time": { "created": "2015-01-01T00:00:00.000Z", "modified": "2018-01-01T00:00:00.000Z",
                  "3.0.1": "2018-01-01T00:00:00.000Z" }
    });
    Mock::given(method("GET"))
        .and(path("/is-odd"))
        .respond_with(ResponseTemplate::new(200).set_body_json(doc))
        .mount(&up)
        .await;
    Mock::given(method("GET"))
        .and(path("/is-odd/-/is-odd-3.0.1.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"FROM-UPSTREAM".to_vec()))
        .mount(&up)
        .await;
    up
}

fn a091_context(up: &MockServer, mode: crate::config::CurationMode) -> TestContext {
    let uri = up.uri();
    crate::test_helpers::create_test_context_with_auth_and_config(A091_USERS, move |cfg| {
        cfg.auth.read_only_users = vec!["ro".to_string()];
        cfg.server.trust_upstream_dates = true;
        cfg.curation.mode = mode;
        cfg.curation.min_release_age = Some("7d".to_string());
        cfg.curation.internal_namespaces = vec!["@corp/*".to_string()];
        cfg.npm.proxy = Some(uri);
    })
}

const IS_ODD_TGZ: &str = "/npm/is-odd/-/is-odd-3.0.1.tgz";

/// Wait for the background cache write of the proxied `is-odd` tarball and its provenance.
async fn is_odd_cached(ctx: &TestContext) {
    let key = super::origin_key("npm/is-odd/tarballs/is-odd-3.0.1.tgz");
    for _ in 0..250 {
        if ctx.state.storage.stat(&key).await.is_some() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("the proxied tarball was never cached");
}

/// A091: a Write credential with no namespace scope does not take over a name an upstream
/// serves. The first publish of such a name is a 403 unless it is in
/// `curation.internal_namespaces`; the proxied bytes stay; a name already published here
/// keeps publishing; an unreadable versions listing is a 503.
#[tokio::test]
async fn a_first_publish_of_an_upstream_name_outside_internal_namespaces_is_refused() {
    let up = is_odd_upstream().await;
    let ctx = a091_context(&up, crate::config::CurationMode::Enforce);

    // (a) The reader gets the upstream's tarball.
    let (s, t) = as_user(&ctx, Method::GET, IS_ODD_TGZ, "ro", vec![]).await;
    assert_eq!(
        (s, t.as_slice()),
        (StatusCode::OK, b"FROM-UPSTREAM".as_slice())
    );
    is_odd_cached(&ctx).await;

    // (b) Neither the proxied version nor a new one is published under the name.
    for version in ["3.0.1", "99.0.0"] {
        let body = publish_body("is-odd", version, b"FROM-WRITER");
        let (s, b) = as_user(&ctx, Method::PUT, "/npm/is-odd", "pub", body).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "is-odd@{version}");
        let text = String::from_utf8_lossy(&b);
        assert!(text.contains("curation.internal_namespaces"), "{text}");
    }
    // (c) The upstream's bytes are still what readers get; nothing is published.
    let (s, t) = as_user(&ctx, Method::GET, IS_ODD_TGZ, "ro", vec![]).await;
    assert_eq!(
        (s, t.as_slice()),
        (StatusCode::OK, b"FROM-UPSTREAM".as_slice())
    );
    assert!(ctx
        .state
        .storage
        .list("npm/is-odd/versions/")
        .await
        .unwrap()
        .is_empty());
    // (d) A name the upstream never served here is refused just the same.
    let body = publish_body("never-seen-pkg", "1.0.0", b"X");
    let (s, _) = as_user(&ctx, Method::PUT, "/npm/never-seen-pkg", "pub", body).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // (e) An internal name publishes.
    let body = publish_body("@corp/lib", "1.0.0", b"CORP");
    let (s, _) = as_user(&ctx, Method::PUT, "/npm/@corp%2flib", "pub", body).await;
    assert_eq!(s, StatusCode::CREATED);
    // (f) A name already published here takes a new version.
    publish(&ctx, "legacy-pkg", "1.0.0").await;
    let body = publish_body("legacy-pkg", "1.0.1", b"NEXT");
    let (s, _) = as_user(&ctx, Method::PUT, "/npm/legacy-pkg", "pub", body).await;
    assert_eq!(s, StatusCode::CREATED);

    // (h) Whether the name is published cannot be read: unavailable, not decided.
    let (storage, outage) = outage_storage();
    let uri = up.uri();
    let blind = create_test_context_with_storage_and_config(storage, move |cfg| {
        cfg.npm.proxy = Some(uri);
        cfg.curation.mode = crate::config::CurationMode::Enforce;
    });
    outage.fail_listings_of("npm/is-odd/versions/");
    let resp = send(
        &blind.app,
        Method::PUT,
        "/npm/is-odd",
        Body::from(publish_body("is-odd", "99.0.0", b"X")),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

/// A091 with `curation.mode = "audit"`: the first publish of an upstream's name only logs a
/// `[SECURITY]` WARN, and a tarball cached from the upstream is still not replaced (409).
#[tokio::test]
async fn in_audit_mode_a_first_publish_of_an_upstream_name_is_logged_and_never_replaces_its_bytes()
{
    let up = is_odd_upstream().await;
    let ctx = a091_context(&up, crate::config::CurationMode::Audit);
    let (s, _) = as_user(&ctx, Method::GET, IS_ODD_TGZ, "ro", vec![]).await;
    assert_eq!(s, StatusCode::OK);
    is_odd_cached(&ctx).await;

    let (logs, _guard) = crate::test_helpers::LogCapture::start();
    let body = publish_body("is-odd", "3.0.1", b"FROM-WRITER");
    let (s, b) = as_user(&ctx, Method::PUT, "/npm/is-odd", "pub", body).await;
    assert_eq!(s, StatusCode::CONFLICT, "{}", String::from_utf8_lossy(&b));
    assert!(String::from_utf8_lossy(&b).contains("cached from an upstream"));
    let body = publish_body("is-odd", "99.0.0", b"FROM-WRITER");
    let (s, _) = as_user(&ctx, Method::PUT, "/npm/is-odd", "pub", body).await;
    assert_eq!(s, StatusCode::CREATED);
    assert!(
        logs.text().contains("[SECURITY] npm first publish"),
        "{}",
        logs.text()
    );
    let stored = ctx
        .state
        .storage
        .get("npm/is-odd/tarballs/is-odd-3.0.1.tgz")
        .await
        .unwrap();
    assert_eq!(&stored[..], b"FROM-UPSTREAM");
}
