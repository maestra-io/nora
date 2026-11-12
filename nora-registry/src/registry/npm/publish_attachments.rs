// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::test_helpers::{create_test_context, send, TestContext};
use axum::body::Body;
use axum::http::{Method, StatusCode};
use base64::Engine;
use sha2::Digest;
use std::collections::BTreeMap;

/// PUT a publish of `name` carrying `versions` and `attachments` (file name, bytes).
async fn publish(
    ctx: &TestContext,
    name: &str,
    versions: &[&str],
    attachments: &[(&str, &[u8])],
) -> StatusCode {
    let versions: serde_json::Map<String, serde_json::Value> = versions
        .iter()
        .map(|v| {
            (
                v.to_string(),
                serde_json::json!({ "name": name, "version": v, "dist": {} }),
            )
        })
        .collect();
    let attachments: serde_json::Map<String, serde_json::Value> = attachments
        .iter()
        .map(|(file, data)| {
            (
                file.to_string(),
                serde_json::json!({
                    "data": base64::engine::general_purpose::STANDARD.encode(data)
                }),
            )
        })
        .collect();
    let payload = serde_json::json!({
        "name": name,
        "versions": versions,
        "_attachments": attachments,
    });
    send(
        &ctx.app,
        Method::PUT,
        &format!("/npm/{name}"),
        Body::from(serde_json::to_vec(&payload).unwrap()),
    )
    .await
    .status()
}

/// Every object stored for `name`, and its bytes.
async fn stored(ctx: &TestContext, name: &str) -> BTreeMap<String, Vec<u8>> {
    let mut objects = BTreeMap::new();
    for key in ctx
        .state
        .storage
        .list(&format!("npm/{name}/"))
        .await
        .unwrap()
    {
        let data = ctx.state.storage.get(&key).await.unwrap();
        objects.insert(key, data.to_vec());
    }
    objects
}

#[tokio::test]
async fn a_publish_cannot_replace_a_published_tarball_or_its_pin() {
    let ctx = create_test_context();
    assert_eq!(
        publish(&ctx, "foo", &["1.0.0"], &[("foo-1.0.0.tgz", b"good")]).await,
        StatusCode::CREATED
    );
    let before = stored(&ctx, "foo").await;
    assert_eq!(before["npm/foo/tarballs/foo-1.0.0.tgz"], b"good");
    let evil_pin = hex::encode(sha2::Sha256::digest(b"evil"));
    let refused: [&[(&str, &[u8])]; 6] = [
        // The tarball of a version already published, beside the one being published.
        &[("foo-1.0.1.tgz", b"next"), ("foo-1.0.0.tgz", b"evil")],
        // The pin beside a published tarball.
        &[
            ("foo-1.0.1.tgz", b"next"),
            ("foo-1.0.0.tgz.sha256", evil_pin.as_bytes()),
        ],
        // Another package's tarball.
        &[("foo-1.0.1.tgz", b"next"), ("bar-1.0.1.tgz", b"bar")],
        // A key beside the tarball being published.
        &[("foo-1.0.1.tgz", b"next"), ("foo-1.0.1.tgz.sha256", b"pin")],
        // Only a published version's tarball.
        &[("foo-1.0.0.tgz", b"evil")],
        // A version's tarball under another name.
        &[("foo-1.0.1.tar.gz", b"next")],
    ];
    for attachments in refused {
        let names: Vec<&str> = attachments.iter().map(|(file, _)| *file).collect();
        assert_eq!(
            publish(&ctx, "foo", &["1.0.1"], attachments).await,
            StatusCode::BAD_REQUEST,
            "{names:?}"
        );
        assert_eq!(
            stored(&ctx, "foo").await,
            before,
            "a refused publish stored something: {names:?}"
        );
    }
    // An attachment that does not decode refuses the publish before its other tarballs are
    // stored.
    let payload = serde_json::json!({
        "name": "foo",
        "versions": {
            "1.0.1": { "name": "foo", "version": "1.0.1", "dist": {} },
            "1.0.2": { "name": "foo", "version": "1.0.2", "dist": {} },
        },
        "_attachments": {
            "foo-1.0.1.tgz": { "data": base64::engine::general_purpose::STANDARD.encode(b"next") },
            "foo-1.0.2.tgz": { "data": "not base64!" },
        },
    });
    let resp = send(
        &ctx.app,
        Method::PUT,
        "/npm/foo",
        Body::from(serde_json::to_vec(&payload).unwrap()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(stored(&ctx, "foo").await, before);
    // The tarball of the version it publishes is all a publish needs.
    assert_eq!(
        publish(&ctx, "foo", &["1.0.1"], &[("foo-1.0.1.tgz", b"next")]).await,
        StatusCode::CREATED
    );
    let after = stored(&ctx, "foo").await;
    assert_eq!(after["npm/foo/tarballs/foo-1.0.0.tgz"], b"good");
    assert_eq!(after["npm/foo/tarballs/foo-1.0.1.tgz"], b"next");
}

/// Which attachments a publish stores, each case with its bytes and without them: only the
/// tarball (`<name>-<version>.tgz`, the name with its scope or without it) of a version the
/// payload publishes. Anything else refuses the whole publish, whether or not it carries
/// bytes, and beside a tarball that would be stored.
#[test]
fn an_attachment_is_stored_only_as_a_tarball_of_this_publish() {
    use super::publish_tarballs;
    let encoded = base64::engine::general_purpose::STANDARD.encode(b"bytes");
    let cases: [(&str, &str, Option<&str>); 24] = [
        (
            "foo",
            "foo-1.0.1.tgz",
            Some("npm/foo/tarballs/foo-1.0.1.tgz"),
        ),
        (
            "@s/pkg",
            "@s/pkg-1.0.1.tgz",
            Some("npm/@s/pkg/tarballs/pkg-1.0.1.tgz"),
        ),
        (
            "@s/pkg",
            "pkg-1.0.1.tgz",
            Some("npm/@s/pkg/tarballs/pkg-1.0.1.tgz"),
        ),
        // Another version's tarball, or a key beside a tarball.
        ("foo", "foo-1.0.0.tgz", None),
        ("foo", "foo-1.0.1.tgz.sha256", None),
        ("foo", "foo-1.0.0.tgz.sha256", None),
        ("foo", "foo-1.0.1.tar.gz", None),
        // Another package's tarball, under any scope or path.
        ("foo", "bar-1.0.1.tgz", None),
        ("foo", "@s/foo-1.0.1.tgz", None),
        ("foo", "x/foo-1.0.1.tgz", None),
        ("foo", "../foo-1.0.1.tgz", None),
        ("foo", "FOO-1.0.1.tgz", None),
        ("foo", "", None),
        ("@s/pkg", "@other/pkg-1.0.1.tgz", None),
        ("@s/pkg", "x/pkg-1.0.1.tgz", None),
        ("@s/pkg", "s/pkg-1.0.1.tgz", None),
        ("@s/pkg", "@s/x/pkg-1.0.1.tgz", None),
        ("@s/pkg", "@s/@s/pkg-1.0.1.tgz", None),
        ("@s/pkg", "@s/../pkg-1.0.1.tgz", None),
        ("@s/pkg", "@spkg-1.0.1.tgz", None),
        ("@s/pkg", "@s-pkg-1.0.1.tgz", None),
        ("@s/pkg", "@s/pkg-1.0.0.tgz", None),
        ("@s/pkg", "@s/pkg-1.0.1.tgz.sha256", None),
        ("@s/pkg", "other-1.0.1.tgz", None),
    ];
    let versions: serde_json::Map<String, serde_json::Value> =
        [("1.0.1".to_string(), serde_json::json!({}))]
            .into_iter()
            .collect();
    let attachments = |entries: &[(&str, serde_json::Value)]| {
        entries
            .iter()
            .map(|(file, attachment)| (file.to_string(), attachment.clone()))
            .collect::<serde_json::Map<String, serde_json::Value>>()
    };
    let with_data = serde_json::json!({ "data": encoded });
    let without_data = serde_json::json!({ "length": 5 });
    for (package, file, stored_as) in cases {
        let own = format!("{}-1.0.1.tgz", package.rsplit('/').next().unwrap());
        for attachment in [&with_data, &without_data] {
            let alone = publish_tarballs(
                package,
                &attachments(&[(file, attachment.clone())]),
                &versions,
            );
            let beside_own = publish_tarballs(
                package,
                &attachments(&[(&own, with_data.clone()), (file, attachment.clone())]),
                &versions,
            );
            let has_data = attachment.get("data").is_some();
            match stored_as {
                Some(key) => {
                    let expected: Vec<(String, Vec<u8>)> = if has_data {
                        vec![(key.to_string(), b"bytes".to_vec())]
                    } else {
                        Vec::new()
                    };
                    assert_eq!(alone.unwrap(), expected, "{package}: {file:?}");
                    assert!(beside_own.is_ok(), "{package}: {file:?} beside its own");
                }
                None => {
                    assert!(alone.is_err(), "{package}: {file:?}, data: {has_data}");
                    assert!(
                        beside_own.is_err(),
                        "{package}: {file:?} beside its own, data: {has_data}"
                    );
                }
            }
        }
    }
}

/// Through the endpoint: a scoped publish carrying another scope's tarball, or a refused
/// attachment without bytes, is refused and stores nothing.
#[tokio::test]
async fn a_publish_with_a_foreign_attachment_stores_nothing() {
    let ctx = create_test_context();
    for file in [
        "@other/pkg-1.0.0.tgz",
        "x/pkg-1.0.0.tgz",
        "@s/x/pkg-1.0.0.tgz",
    ] {
        assert_eq!(
            publish(&ctx, "@s/pkg", &["1.0.0"], &[(file, b"evil")]).await,
            StatusCode::BAD_REQUEST,
            "{file}"
        );
        assert!(stored(&ctx, "@s/pkg").await.is_empty(), "{file} stored");
    }
    let payload = serde_json::json!({
        "name": "foo",
        "versions": { "1.0.1": { "name": "foo", "version": "1.0.1", "dist": {} } },
        "_attachments": {
            "foo-1.0.1.tgz": { "data": base64::engine::general_purpose::STANDARD.encode(b"next") },
            "foo-1.0.0.tgz.sha256": { "length": 64 },
        },
    });
    let resp = send(
        &ctx.app,
        Method::PUT,
        "/npm/foo",
        Body::from(serde_json::to_vec(&payload).unwrap()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(stored(&ctx, "foo").await.is_empty());
}

#[tokio::test]
async fn a_scoped_publish_carries_its_own_tarball_only() {
    let ctx = create_test_context();
    assert_eq!(
        publish(&ctx, "@s/pkg", &["1.0.0"], &[("@s/pkg-1.0.0.tgz", b"good")]).await,
        StatusCode::CREATED
    );
    let before = stored(&ctx, "@s/pkg").await;
    assert_eq!(
        publish(
            &ctx,
            "@s/pkg",
            &["1.0.1"],
            &[("@s/pkg-1.0.1.tgz", b"next"), ("@s/pkg-1.0.0.tgz", b"evil")]
        )
        .await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(stored(&ctx, "@s/pkg").await, before);
    // The attachment may name the package with its scope or without it.
    assert_eq!(
        publish(&ctx, "@s/pkg", &["1.0.1"], &[("pkg-1.0.1.tgz", b"next")]).await,
        StatusCode::CREATED
    );
    assert_eq!(
        stored(&ctx, "@s/pkg").await["npm/@s/pkg/tarballs/pkg-1.0.1.tgz"],
        b"next"
    );
}
