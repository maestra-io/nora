// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

//! One upstream fetch per cold blob, shared by every client that asks while it fills
//! (#1003): concurrent pulls, a client that arrives mid-fill, a ranged resume. A failed
//! or poisoned fill never strands a client, and joining a fill never skips the joiner's
//! own per-request checks.
use super::upstream_resume_tests::{
    cached, ctx_for, layer, proxy_temp_count, pull, scripted_upstream, Plan,
};
use super::{blob_key, canonicalize};
use crate::test_helpers::send_with_headers;
use axum::body::Body;
use axum::http::{header, Method, StatusCode};
use std::sync::atomic::Ordering;
use std::time::Duration;

/// A body that takes ~1.6 s to arrive, long enough for later clients to find it filling.
fn slow() -> Plan {
    Plan {
        piece: 16 * 1024,
        delay: Duration::from_millis(100),
        ..Plan::fast()
    }
}

async fn body_of(response: axum::response::Response) -> Result<Vec<u8>, axum::Error> {
    axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .map(|b| b.to_vec())
}

/// N cold pulls of one layer at once → one upstream GET, every client gets the blob.
#[tokio::test]
async fn concurrent_cold_pulls_share_one_upstream_fetch() {
    let (blob, digest) = layer(256 * 1024);
    let upstream = scripted_upstream(blob.clone(), vec![slow()], None).await;
    let ctx = ctx_for(&upstream, 5);
    let joined_before = crate::metrics::PROXY_COALESCED_TOTAL
        .with_label_values(&["docker"])
        .get();

    let pulls: Vec<_> = (0..8)
        .map(|_| {
            let app = ctx.app.clone();
            let digest = digest.clone();
            let handle = tokio::spawn(async move {
                let response = crate::test_helpers::send(
                    &app,
                    Method::GET,
                    &format!("/v2/library/test/blobs/{digest}"),
                    Body::empty(),
                )
                .await;
                (response.status(), body_of(response).await)
            });
            handle
        })
        .collect();
    for pull in pulls {
        let (status, body) = pull.await.unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.expect("clean body"), blob);
    }
    assert_eq!(
        upstream.hits.load(Ordering::SeqCst),
        1,
        "8 concurrent pulls of one cold layer must cost one upstream fetch"
    );
    assert!(
        crate::metrics::PROXY_COALESCED_TOTAL
            .with_label_values(&["docker"])
            .get()
            >= joined_before + 7,
        "the 7 clients that joined are counted"
    );
    assert!(cached(&ctx, &digest).await);
}

/// A client that asks after the first one already has its headers (a containerd
/// retry, a second node) joins the running fill instead of starting another one.
#[tokio::test]
async fn late_client_joins_running_fill() {
    let (blob, digest) = layer(256 * 1024);
    let upstream = scripted_upstream(blob.clone(), vec![slow()], None).await;
    let ctx = ctx_for(&upstream, 5);

    let first = pull(&ctx, &digest).await;
    assert_eq!(first.status(), StatusCode::OK);
    let first = tokio::spawn(body_of(first));
    tokio::time::sleep(Duration::from_millis(400)).await;

    let second = pull(&ctx, &digest).await;
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(body_of(second).await.expect("clean body"), blob);
    assert_eq!(first.await.unwrap().expect("clean body"), blob);
    assert_eq!(
        upstream.hits.load(Ordering::SeqCst),
        1,
        "joined, not refetched"
    );
}

/// containerd resuming a broken pull mid-fill: its `Range` is served 206 from the
/// shared fill, still without a second upstream fetch.
#[tokio::test]
async fn late_ranged_client_gets_206_from_shared_fill() {
    let (blob, digest) = layer(256 * 1024);
    let upstream = scripted_upstream(blob.clone(), vec![slow()], None).await;
    let ctx = ctx_for(&upstream, 5);

    let first = pull(&ctx, &digest).await;
    let first = tokio::spawn(body_of(first));
    tokio::time::sleep(Duration::from_millis(400)).await;

    let from = 100_000usize;
    let ranged = send_with_headers(
        &ctx.app,
        Method::GET,
        &format!("/v2/library/test/blobs/{digest}"),
        vec![("range", &format!("bytes={from}-"))],
        Body::empty(),
    )
    .await;
    assert_eq!(ranged.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        ranged.headers()[header::CONTENT_RANGE].to_str().unwrap(),
        format!("bytes {from}-{}/{}", blob.len() - 1, blob.len())
    );
    assert_eq!(body_of(ranged).await.expect("clean body"), &blob[from..]);
    assert_eq!(first.await.unwrap().expect("clean body"), blob);
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 1);
}

/// A poisoned upstream shared by three clients: one upstream fetch, every client's
/// body aborts (the last byte waits for the digest verdict), nothing is cached.
#[tokio::test]
async fn poisoned_fill_aborts_every_joined_client() {
    let (_, digest) = layer(128 * 1024);
    let (poison, _) = layer(128 * 1024 + 1);
    let upstream = scripted_upstream(poison, vec![slow()], None).await;
    let ctx = ctx_for(&upstream, 5);

    let first = tokio::spawn(body_of(pull(&ctx, &digest).await));
    tokio::time::sleep(Duration::from_millis(300)).await;
    let second = tokio::spawn(body_of(pull(&ctx, &digest).await));
    tokio::time::sleep(Duration::from_millis(300)).await;
    let third = body_of(pull(&ctx, &digest).await).await;
    assert!(third.is_err(), "a poisoned fill must not end clean");
    assert!(second.await.unwrap().is_err());
    assert!(first.await.unwrap().is_err());
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 1);
    let started = std::time::Instant::now();
    while proxy_temp_count(&ctx) > 0 && started.elapsed() < Duration::from_secs(10) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let c = canonicalize("library/test", &ctx.state.config.docker);
    let key = blob_key(c.namespace.as_deref(), &c.name, &digest);
    assert!(ctx.state.storage.get(&key).await.is_err(), "not cached");
}

/// A fill that fails releases its slot: the next pull starts a fresh fetch and
/// succeeds (fail-open — no client waits on a dead fill).
#[tokio::test]
async fn failed_fill_releases_slot_for_the_next_pull() {
    let (blob, digest) = layer(64 * 1024);
    // hit 0 cuts, hits 1..=5 are the resume budget, hit 6 serves
    let mut plans = vec![Plan::cut(1024)];
    plans.extend(std::iter::repeat_n(Plan::cut(0), 5));
    plans.push(Plan::fast());
    let upstream = scripted_upstream(blob.clone(), plans, None).await;
    let ctx = ctx_for(&upstream, 5);

    assert!(body_of(pull(&ctx, &digest).await).await.is_err());
    let started = std::time::Instant::now();
    while proxy_temp_count(&ctx) > 0 && started.elapsed() < Duration::from_secs(20) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let again = pull(&ctx, &digest).await;
    assert_eq!(again.status(), StatusCode::OK);
    assert_eq!(body_of(again).await.expect("clean body"), blob);
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 7);
}

/// Joining a fill never skips the joiner's own curation: with the name blocked, a
/// client carrying the bypass token starts the fill and a client without it is still
/// refused while that fill runs.
#[tokio::test]
async fn joiner_is_curated_on_its_own_request() {
    use crate::config::{CurationMode, DockerUpstream};
    use crate::secrets::ProtectedString;
    let (blob, digest) = layer(256 * 1024);
    let upstream = scripted_upstream(blob.clone(), vec![slow()], None).await;
    let dir = tempfile::TempDir::new().unwrap();
    let blocklist = dir.path().join("blocklist.json");
    std::fs::write(
        &blocklist,
        r#"{"version": 1, "rules": [{"registry": "docker", "name": "library/test", "version": "*", "reason": "blocked"}]}"#,
    )
    .unwrap();
    let (bl, url) = (
        blocklist.to_str().unwrap().to_string(),
        upstream.url.clone(),
    );
    let ctx = crate::test_helpers::create_test_context_with_config(move |cfg| {
        cfg.curation.mode = CurationMode::Enforce;
        cfg.curation.blocklist_path = Some(bl);
        cfg.curation.bypass_token = Some(ProtectedString::from("let-me-in"));
        cfg.docker.upstreams = vec![DockerUpstream {
            trust_upstream_dates: false,
            date_token_file: None,
            url,
            auth: None,
            auth_env: None,
            namespace: None,
            prefix: None,
            namespaces: Vec::new(),
        }];
    });
    let path = format!("/v2/library/test/blobs/{digest}");

    let leader = send_with_headers(
        &ctx.app,
        Method::GET,
        &path,
        vec![("x-nora-bypass-token", "let-me-in")],
        Body::empty(),
    )
    .await;
    assert_eq!(leader.status(), StatusCode::OK);
    let leader = tokio::spawn(body_of(leader));
    tokio::time::sleep(Duration::from_millis(400)).await;

    let joiner = pull(&ctx, &digest).await;
    assert_eq!(
        joiner.status(),
        StatusCode::FORBIDDEN,
        "a running fill must not serve a client its own curation refuses"
    );
    assert_eq!(leader.await.unwrap().expect("clean body"), blob);
}

/// Clients trickling in across the whole fill — the shape of a node pool rolling one
/// image — still cost a single upstream fetch.
#[tokio::test]
async fn staggered_clients_share_one_upstream_fetch() {
    let (blob, digest) = layer(256 * 1024);
    let upstream = scripted_upstream(blob.clone(), vec![slow()], None).await;
    let ctx = ctx_for(&upstream, 5);
    let mut pulls = Vec::new();
    for _ in 0..20 {
        let (app, digest) = (ctx.app.clone(), digest.clone());
        let handle = tokio::spawn(async move {
            let response = crate::test_helpers::send(
                &app,
                Method::GET,
                &format!("/v2/library/test/blobs/{digest}"),
                Body::empty(),
            )
            .await;
            body_of(response).await
        });
        pulls.push(handle);
        tokio::time::sleep(Duration::from_millis(60)).await;
    }
    for pull in pulls {
        assert_eq!(pull.await.unwrap().expect("clean body"), blob);
    }
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 1);
}

/// A request can land on a fill whose spool has already moved into storage (the
/// lease is released just after the move): it is served from storage, not failed and
/// not refetched. A failed fill with nothing stored hands back to the caller (`None`).
#[tokio::test]
async fn follower_of_a_moved_spool_is_served_from_storage() {
    let (blob, digest) = layer(32 * 1024);
    let upstream = scripted_upstream(blob.clone(), vec![Plan::fast()], None).await;
    let ctx = ctx_for(&upstream, 5);
    let c = canonicalize("library/test", &ctx.state.config.docker);
    let key = blob_key(c.namespace.as_deref(), &c.name, &digest);
    let legacy_key = blob_key(None, &c.name, &digest);
    let share = |ok: bool| {
        let done = if ok {
            Ok(())
        } else {
            Err("fill failed".to_string())
        };
        let (tx, status) = tokio::sync::watch::channel(super::SpoolStatus {
            written: blob.len() as u64,
            done: Some(done),
        });
        std::mem::forget(tx);
        super::SpoolShare {
            path: std::path::PathBuf::from("/nonexistent/spool-moved-into-storage"),
            status,
            content_length: Some(blob.len() as u64),
        }
    };
    let target = super::BlobTarget {
        name: &c.name,
        upstream_name: "library/test",
        digest: &digest,
        key: &key,
        legacy_key: &legacy_key,
        upstream_url: &upstream.url,
    };
    let headers = axum::http::HeaderMap::new();

    let failed = super::follow_fill(&ctx.state, share(false), &target, &headers).await;
    assert!(
        failed.is_none(),
        "a failed fill with nothing stored hands back"
    );

    ctx.state.storage.put(&key, &blob).await.unwrap();
    let response = super::follow_fill(&ctx.state, share(true), &target, &headers)
        .await
        .expect("served from storage");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_of(response).await.unwrap(), blob);
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 0, "no refetch");
}

/// Once the fill is stored, a later pull is a plain cache hit.
#[tokio::test]
async fn pull_after_store_is_a_cache_hit() {
    let (blob, digest) = layer(64 * 1024);
    let upstream = scripted_upstream(blob.clone(), vec![Plan::fast()], None).await;
    let ctx = ctx_for(&upstream, 5);
    assert_eq!(body_of(pull(&ctx, &digest).await).await.unwrap(), blob);
    assert!(cached(&ctx, &digest).await);
    assert_eq!(body_of(pull(&ctx, &digest).await).await.unwrap(), blob);
    assert_eq!(upstream.hits.load(Ordering::SeqCst), 1);
}
