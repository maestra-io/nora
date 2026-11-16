// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

//! The side listeners (`server.internal_port`, `server.teleport_port`): bound at the start,
//! served from a clone of that socket by every run of the supervised task.
use super::side_listener;
use crate::server_conn::ConnLimits;
use axum::http::Request;
use axum::{middleware, routing::get, Router};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

const LIMITS: ConnLimits = ConnLimits {
    header_read_timeout: Duration::from_secs(5),
    keep_alive_timeout: Duration::from_secs(5),
    max_connections: 8,
};

/// What the handler saw of the client address: the forwarding header and the marker.
async fn seen(request: Request<axum::body::Body>) -> String {
    format!(
        "xff={} marked={}",
        request.headers().contains_key("x-forwarded-for"),
        request
            .extensions()
            .get::<crate::auth::teleport::TeleportListener>()
            .is_some()
    )
}

async fn get_body(addr: std::net::SocketAddr) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            b"GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 198.51.100.77\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut answer = String::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_string(&mut answer))
        .await
        .unwrap()
        .unwrap();
    answer
}

// Audit A007: the app served on the Teleport listener never sees a forwarding header, and every
// run of the task (a restart after a panic) serves the same bound port.
#[tokio::test]
async fn the_teleport_listener_drops_forwarding_headers_on_every_run() {
    let app = Router::new()
        .route("/", get(seen))
        .layer(middleware::map_request(
            crate::auth::teleport::mark_teleport_listener,
        ));
    let stop = CancellationToken::new();
    let (addr, mut serve) = side_listener(
        "server.teleport_port",
        "127.0.0.1",
        0,
        app,
        stop.clone(),
        LIMITS,
    )
    .await;

    let first = tokio::spawn(serve());
    let answer = get_body(addr).await;
    assert!(answer.ends_with("xff=false marked=true"), "{answer}");
    first.abort();
    let _ = first.await;

    let second = tokio::spawn(serve());
    let answer = get_body(addr).await;
    assert!(answer.ends_with("xff=false marked=true"), "{answer}");
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(10), second)
        .await
        .expect("the task ends at the stop signal")
        .unwrap();
}

#[tokio::test]
async fn a_taken_side_port_fails_the_start() {
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port();
    let bind = tokio::spawn(async move {
        let _ = side_listener(
            "server.teleport_port",
            "127.0.0.1",
            port,
            Router::new(),
            CancellationToken::new(),
            LIMITS,
        )
        .await;
    });
    let panic = bind.await.unwrap_err().into_panic();
    let message = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .unwrap_or_default();
    assert!(
        message.starts_with("Failed to bind server.teleport_port"),
        "{message}"
    );
}

/// The status line of a GET of `path` on `addr`.
async fn status_line(addr: std::net::SocketAddr, path: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut answer = String::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_string(&mut answer))
        .await
        .unwrap()
        .unwrap();
    answer.lines().next().unwrap_or_default().to_string()
}

// The server binds and serves exactly the side listeners its config names.
#[tokio::test]
async fn the_server_serves_the_side_listeners_it_is_configured_with() {
    let off = crate::test_helpers::create_test_context();
    assert_eq!(
        super::spawn_side_listeners(&off.state, &off.app).await,
        (None, None)
    );

    let ctx = crate::test_helpers::create_test_context_with_config(|config| {
        config.server.host = "127.0.0.1".to_string();
        config.server.internal_port = Some(0);
        config.server.teleport_port = Some(0);
    });
    let (internal, teleport) = super::spawn_side_listeners(&ctx.state, &ctx.app).await;
    assert!(status_line(internal.unwrap(), "/metrics")
        .await
        .contains(" 200 "));
    assert!(status_line(teleport.unwrap(), "/health")
        .await
        .contains(" 200 "));
    ctx.state.cancel_token.cancel();
}
