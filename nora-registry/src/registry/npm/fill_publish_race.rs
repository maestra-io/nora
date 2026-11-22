// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

//! A075: a version published while the upstream was asked for its tarball keeps the published
//! bytes. The fill that fetched the upstream's caches nothing over them, and leaves no
//! provenance record or `.sha256` sidecar beside them.

use crate::registry::npm::origin_key;
use crate::test_helpers::{
    background_writes_done, body_bytes, create_test_context_with_config, send, MockUpstream,
    TestContext,
};
use axum::body::Body;
use axum::http::{Method, StatusCode};
use base64::Engine;
use sha2::Digest;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, Request, Respond, ResponseTemplate};

fn sha(b: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(b))
}

/// Whether the tarball was asked for, and whether its answer may go.
#[derive(Default)]
struct Gate {
    state: Mutex<(bool, bool)>,
    changed: Condvar,
}

impl Gate {
    fn set(&self, asked: Option<bool>, open: Option<bool>) {
        let mut state = self.state.lock().unwrap();
        state.0 |= asked.unwrap_or(false);
        state.1 |= open.unwrap_or(false);
        self.changed.notify_all();
    }

    /// Wait (at most 30 s) until `done` holds of (asked, open).
    fn wait(&self, done: impl Fn(&(bool, bool)) -> bool) -> bool {
        let state = self.state.lock().unwrap();
        let (state, _) = self
            .changed
            .wait_timeout_while(state, Duration::from_secs(30), |s| !done(s))
            .unwrap();
        done(&state)
    }
}

/// The upstream's tarball, answered once the test opens the gate. wiremock runs each server on
/// a thread of its own, so the wait blocks only the upstream.
struct GatedTarball(Vec<u8>, Arc<Gate>);

impl Respond for GatedTarball {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        self.1.set(Some(true), None);
        self.1.wait(|s| s.1);
        ResponseTemplate::new(200).set_body_bytes(self.0.clone())
    }
}

async fn upstream_with(name: &str, body: &[u8], gate: &Arc<Gate>) -> MockUpstream {
    let upstream = MockUpstream::start().await;
    let at = format!("{name}/-/{name}-1.0.0.tgz");
    crate::registry::npm::mount_listing(&upstream, name, &[("1.0.0", &at)]).await;
    Mock::given(method("GET"))
        .and(path(format!("/{at}")))
        .respond_with(GatedTarball(body.to_vec(), Arc::clone(gate)))
        .mount(&upstream)
        .await;
    upstream
}

/// Publish 1.0.0 with `own` as its tarball, as a package published here before an upstream
/// served the name (A091 refuses a first publish under a proxied name on `ctx` itself).
async fn publish(ctx: &TestContext, name: &str, own: &[u8]) -> StatusCode {
    let payload = serde_json::json!({
        "name": name,
        "versions": { "1.0.0": { "name": name, "version": "1.0.0", "dist": {} } },
        "_attachments": { format!("{name}-1.0.0.tgz"): {
            "data": base64::engine::general_purpose::STANDARD.encode(own),
        } },
    });
    let body = Body::from(serde_json::to_vec(&payload).unwrap());
    let twin = crate::test_helpers::npm_first_publish_twin(ctx, name).await;
    let app = &twin.as_ref().unwrap_or(ctx).app;
    send(app, Method::PUT, &format!("/npm/{name}"), body)
        .await
        .status()
}

async fn race(name: &'static str, upstream_body: Vec<u8>, threshold_mb: Option<u64>) {
    let own = b"the published tarball".to_vec();
    let gate = Arc::new(Gate::default());
    let upstream = upstream_with(name, &upstream_body, &gate).await;
    let uri = upstream.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.npm.proxy = Some(uri);
        if let Some(mb) = threshold_mb {
            cfg.server.stream_threshold_mb = mb;
        }
    });
    let holders = ctx.state.storage.holders();
    let app = ctx.app.clone();
    let reader = tokio::spawn(async move {
        let resp = send(
            &app,
            Method::GET,
            &format!("/npm/{name}/-/{name}-1.0.0.tgz"),
            "",
        )
        .await;
        (resp.status(), body_bytes(resp).await)
    });
    // The upstream is asked for the tarball; the version is published before it answers.
    let waiting = Arc::clone(&gate);
    let asked = tokio::task::spawn_blocking(move || waiting.wait(|s| s.0))
        .await
        .unwrap();
    let published = if asked {
        publish(&ctx, name, &own).await
    } else {
        StatusCode::REQUEST_TIMEOUT
    };
    gate.set(None, Some(true));
    assert!(asked, "the upstream was never asked for the tarball");
    assert_eq!(published, StatusCode::CREATED);
    let (status, body) = reader.await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        sha(&body),
        sha(&upstream_body),
        "the reader gets what it fetched"
    );
    background_writes_done(&ctx.state.storage, holders).await;

    let storage = &ctx.state.storage;
    let key = format!("npm/{name}/tarballs/{name}-1.0.0.tgz");
    assert_eq!(
        sha(&storage.get(&key).await.unwrap()),
        sha(&own),
        "stored bytes"
    );
    let sidecar = storage.get(&format!("{key}.sha256")).await.ok();
    assert!(
        sidecar.as_deref().is_none_or(|s| s == sha(&own).as_bytes()),
        "sidecar of other bytes"
    );
    assert!(
        storage.stat(&origin_key(&key)).await.is_none(),
        "provenance record beside a published version"
    );
    let resp = send(
        &ctx.app,
        Method::GET,
        &format!("/npm/{name}/-/{name}-1.0.0.tgz"),
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(&body_bytes(resp).await[..], &own[..]);
}

#[tokio::test]
async fn publish_during_buffered_fill_keeps_published_bytes() {
    race("race-pkg", b"the upstream's tarball".to_vec(), None).await;
}

#[tokio::test]
async fn publish_during_spooled_fill_keeps_published_bytes() {
    let big: Vec<u8> = (0..(2 * 1024 * 1024 + 7))
        .map(|i| (i % 251) as u8)
        .collect();
    race("race-big", big, Some(1)).await;
}
