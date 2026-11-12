// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

//! Graceful shutdown drains in-flight requests for at most the shutdown timeout
//! (#1016): a client that stops reading can no longer hold the process past it.
use super::{serve_with_drain, ServeEnd};
use axum::body::{Body, Bytes};
use axum::routing::get;
use axum::Router;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A body that never ends, in 64 KiB pieces.
async fn endless() -> Body {
    let piece = Bytes::from(vec![7u8; 64 * 1024]);
    Body::from_stream(futures::stream::repeat_with(move || {
        Ok::<_, std::io::Error>(piece.clone())
    }))
}

/// Three pieces 100 ms apart: a download that finishes on its own.
async fn short() -> Body {
    use futures::StreamExt;
    Body::from_stream(futures::stream::iter(0..3u8).then(|i| async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok::<_, std::io::Error>(Bytes::from(vec![i; 1024]))
    }))
}

async fn start(
    drain: Duration,
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<std::io::Result<ServeEnd>>,
) {
    let app = Router::new()
        .route("/endless", get(endless))
        .route("/short", get(short));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve_with_drain(
        listener,
        app,
        async move {
            let _ = rx.await;
        },
        drain,
        super::ConnLimits {
            header_read_timeout: Duration::from_secs(30),
            keep_alive_timeout: Duration::from_secs(120),
            max_connections: 64,
        },
    ));
    (addr, tx, server)
}

/// A client reads the start of an endless body and then stops reading, keeping the
/// connection open (dockerd after a failed layer). After the signal, serving ends
/// at the deadline instead of waiting on that connection forever.
#[tokio::test]
async fn stalled_client_cannot_hold_shutdown_past_the_deadline() {
    let drain = Duration::from_millis(300);
    let (addr, stop, server) = start(drain).await;
    let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
    client
        .write_all(b"GET /endless HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut head = [0u8; 4096];
    let _ = client.read(&mut head).await.unwrap(); // started, then never read again

    let signalled = Instant::now();
    stop.send(()).unwrap();
    let end = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("serving must end at the drain deadline, not wait on the stalled client")
        .unwrap()
        .unwrap();
    assert_eq!(end, ServeEnd::DeadlinePassed);
    assert!(
        signalled.elapsed() >= drain,
        "in-flight requests get the whole drain window"
    );
    drop(client);
}

/// An idle keep-alive connection is closed at the signal and does not hold serving
/// until the deadline.
#[tokio::test]
async fn an_idle_keep_alive_connection_does_not_hold_shutdown() {
    let (addr, stop, server) = start(Duration::from_secs(5)).await;
    let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
    client
        .write_all(b"GET /short HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut seen = Vec::new();
    let mut buf = [0u8; 4096];
    while !seen.windows(5).any(|w| w == b"0\r\n\r\n") {
        let n = client.read(&mut buf).await.unwrap();
        assert!(n > 0, "closed before the response ended");
        seen.extend_from_slice(&buf[..n]);
    }
    let signalled = Instant::now();
    stop.send(()).unwrap();
    // CANCEL-SAFETY: awaiting the server task's handle; a timeout fails the test.
    let end = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(end, ServeEnd::Drained);
    assert!(signalled.elapsed() < Duration::from_secs(2));
}

/// A download already in flight when the signal comes, and short enough to finish
/// within the deadline, completes whole; serving ends as drained.
#[tokio::test]
async fn in_flight_download_finishes_within_the_deadline() {
    let (addr, stop, server) = start(Duration::from_secs(5)).await;
    let download = tokio::spawn(async move {
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET /short HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut all = Vec::new();
        client.read_to_end(&mut all).await.unwrap();
        all
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    stop.send(()).unwrap();
    let end = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(end, ServeEnd::Drained);
    let response = download.await.unwrap();
    let body_bytes = response.iter().filter(|b| matches!(b, 0..=2)).count();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert!(body_bytes >= 3 * 1024, "the whole body arrived");
}
