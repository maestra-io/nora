// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

//! A connection whose request head does not arrive in time is closed, an idle keep-alive
//! connection lives longer than that, and open connections are capped.
use super::{serve_with_drain, ConnLimits, ServeEnd};
use axum::extract::ConnectInfo;
use axum::routing::get;
use axum::Router;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const HEAD: Duration = Duration::from_millis(300);
const IDLE: Duration = Duration::from_millis(1500);
const REQUEST: &[u8] = b"GET /ok HTTP/1.1\r\nHost: x\r\n\r\n";

/// A server under test, stopped when the test drops it.
struct TestServer {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<std::io::Result<ServeEnd>>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start(max_connections: usize) -> TestServer {
    start_with(ConnLimits {
        header_read_timeout: HEAD,
        keep_alive_timeout: IDLE,
        max_connections,
    })
    .await
}

async fn start_with(limits: ConnLimits) -> TestServer {
    let app = Router::new().route("/ok", get(|| async { "ok" })).route(
        "/peer",
        get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.ip().to_string() }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(serve_with_drain(
        listener,
        app,
        std::future::pending(),
        Duration::from_secs(1),
        limits,
    ));
    TestServer { addr, task }
}

/// One response off a keep-alive connection: its head and its `content-length` body.
async fn read_response(stream: &mut TcpStream) -> String {
    let mut raw = Vec::new();
    let mut byte = [0u8; 1];
    while !raw.ends_with(b"\r\n\r\n") {
        assert_eq!(
            stream.read(&mut byte).await.unwrap(),
            1,
            "closed mid-response"
        );
        raw.push(byte[0]);
    }
    let head = String::from_utf8(raw).unwrap();
    let length: usize = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length: ")
                .map(str::to_owned)
        })
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).await.unwrap();
    head + &String::from_utf8(body).unwrap()
}

/// How long until the server closes `stream`, if it does within `limit`.
async fn closed_within(stream: &mut TcpStream, limit: Duration) -> Option<Duration> {
    let start = Instant::now();
    let mut buf = [0u8; 1024];
    loop {
        let left = limit.saturating_sub(start.elapsed());
        // CANCEL-SAFETY: a read on the test's own socket; on timeout nothing is lost
        // that the test still needs.
        match tokio::time::timeout(left, stream.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return Some(start.elapsed()),
            Ok(Ok(_)) => continue,
            Err(_) => return None,
        }
    }
}

#[tokio::test]
async fn a_head_that_never_completes_is_closed() {
    let server = start(16).await;
    let addr = server.addr;
    let mut client = TcpStream::connect(addr).await.unwrap();
    client
        .write_all(b"GET /ok HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();
    let closed = closed_within(&mut client, Duration::from_secs(5)).await;
    assert!(
        closed.is_some_and(|d| d < HEAD * 4),
        "an unfinished head holds the connection: {closed:?}"
    );
}

/// A fresh connection that sends nothing gets the header timeout, not the idle one.
#[tokio::test]
async fn a_connection_that_sends_nothing_is_closed_at_the_header_timeout() {
    let server = start(16).await;
    let addr = server.addr;
    let mut client = TcpStream::connect(addr).await.unwrap();
    let closed = closed_within(&mut client, Duration::from_secs(5)).await;
    assert!(
        closed.is_some_and(|d| d < HEAD * 4),
        "a silent connection was kept: {closed:?}"
    );
}

/// The first head's timeout runs from the accept: a client that waits before its first
/// byte has that much less time for the rest.
#[tokio::test]
async fn the_first_head_is_timed_from_the_accept() {
    let head = Duration::from_secs(1);
    let server = start_with(ConnLimits {
        header_read_timeout: head,
        keep_alive_timeout: IDLE,
        max_connections: 16,
    })
    .await;
    let addr = server.addr;
    let mut client = TcpStream::connect(addr).await.unwrap();
    let connected = Instant::now();
    tokio::time::sleep(Duration::from_millis(800)).await;
    client.write_all(b"GET /ok HTTP/1.1\r\n").await.unwrap();
    let closed = closed_within(&mut client, Duration::from_secs(5)).await;
    let since_connect = connected.elapsed();
    assert!(closed.is_some(), "an unfinished head held the connection");
    assert!(
        since_connect < head + Duration::from_millis(400),
        "closed {since_connect:?} after the connect"
    );
}

/// A slow client sending its head a byte at a time gains nothing by it.
#[tokio::test]
async fn a_head_sent_a_byte_at_a_time_is_closed_at_the_header_timeout() {
    let server = start(16).await;
    let addr = server.addr;
    let mut client = TcpStream::connect(addr).await.unwrap();
    let start = Instant::now();
    for byte in b"GET /ok HTTP/1.1\r\nHost: x\r\nX-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
        if client.write_all(&[*byte]).await.is_err() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let closed = closed_within(&mut client, Duration::from_secs(5)).await;
    let total = start.elapsed();
    assert!(closed.is_some(), "a trickled head holds the connection");
    assert!(total < HEAD * 8, "closed after {total:?}");
}

/// The header timeout is not an idle timeout: a proxy reuses an idle connection after
/// longer than that (traefik up to 90 s), and NORA must not close it first.
#[tokio::test]
async fn an_idle_keep_alive_connection_outlives_the_header_timeout() {
    let server = start(16).await;
    let addr = server.addr;
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(REQUEST).await.unwrap();
    assert!(read_response(&mut client).await.starts_with("HTTP/1.1 200"));

    tokio::time::sleep(HEAD * 3).await;
    client.write_all(REQUEST).await.unwrap();
    assert!(
        read_response(&mut client).await.starts_with("HTTP/1.1 200"),
        "the idle connection was reused"
    );

    let closed = closed_within(&mut client, IDLE * 3).await;
    assert!(
        closed.is_some_and(|d| d >= IDLE - HEAD),
        "idle past the keep-alive timeout, closed after {closed:?}"
    );
}

/// A later head on a keep-alive connection gets the header timeout from its first byte,
/// not the idle allowance.
#[tokio::test]
async fn a_later_head_is_timed_from_its_first_byte() {
    let server = start(16).await;
    let addr = server.addr;
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(REQUEST).await.unwrap();
    assert!(read_response(&mut client).await.starts_with("HTTP/1.1 200"));

    tokio::time::sleep(HEAD).await;
    client.write_all(b"GET /ok HTTP/1.1\r\n").await.unwrap();
    let closed = closed_within(&mut client, IDLE * 3).await;
    assert!(
        closed.is_some_and(|d| d < HEAD * 2),
        "a started head got more than the header timeout: {closed:?}"
    );
}

#[tokio::test]
async fn past_max_connections_a_new_client_waits_until_one_closes() {
    let server = start(1).await;
    let addr = server.addr;
    let mut first = TcpStream::connect(addr).await.unwrap();
    first.write_all(REQUEST).await.unwrap();
    assert!(read_response(&mut first).await.starts_with("HTTP/1.1 200"));

    let mut second = TcpStream::connect(addr).await.unwrap();
    second.write_all(REQUEST).await.unwrap();
    let mut byte = [0u8; 1];
    // CANCEL-SAFETY: a read on the test's own socket, retried below.
    let early = tokio::time::timeout(HEAD, second.read(&mut byte)).await;
    assert!(
        early.is_err(),
        "the second connection was served past the cap"
    );

    drop(first);
    // CANCEL-SAFETY: as above.
    let response = tokio::time::timeout(Duration::from_secs(5), read_response(&mut second))
        .await
        .expect("served once the first connection closed");
    assert!(response.starts_with("HTTP/1.1 200"));
}

/// A client speaking HTTP/2 from its first byte (prior knowledge) is served, as it
/// was by axum's server.
#[tokio::test]
async fn an_http2_prior_knowledge_client_is_served() {
    let server = start(16).await;
    let addr = server.addr;
    let client = reqwest::Client::builder() // nosemgrep: reqwest-client-bypass
        .http2_prior_knowledge()
        .no_proxy()
        .build()
        .unwrap();
    let response = client
        .get(format!("http://{addr}/peer"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.version(), reqwest::Version::HTTP_2);
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "127.0.0.1");
}

/// The first bytes are read under the header timeout too.
#[tokio::test]
async fn a_partial_http2_preface_is_closed_at_the_header_timeout() {
    let server = start(16).await;
    let addr = server.addr;
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(b"PRI * HTTP/2.0\r\n").await.unwrap();
    let closed = closed_within(&mut client, Duration::from_secs(5)).await;
    assert!(
        closed.is_some_and(|d| d < HEAD * 4),
        "a partial preface held the connection: {closed:?}"
    );
}

/// An HTTP/2 peer that goes silent and answers no ping is closed.
#[tokio::test]
async fn a_silent_http2_peer_is_closed_when_it_answers_no_ping() {
    let server = start(16).await;
    let addr = server.addr;
    let mut client = TcpStream::connect(addr).await.unwrap();
    client
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00")
        .await
        .unwrap();
    let closed = closed_within(&mut client, IDLE * 4).await;
    assert!(
        closed.is_some_and(|d| d < IDLE + HEAD * 4),
        "a silent HTTP/2 peer was kept: {closed:?}"
    );
}

/// The HTTP/2 preface and an empty SETTINGS frame.
const H2_START: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00";

/// A HEADERS frame on stream 1 ending its stream: `GET http://x/`, HPACK-coded from the
/// static table.
const H2_GET: &[u8] = b"\x00\x00\x06\x01\x05\x00\x00\x00\x01\x82\x86\x84\x41\x01x";

/// Play an HTTP/2 client that is alive: acknowledge each SETTINGS, answer each PING.
/// Returns how long after `from` the server closed the connection, if it did within
/// `limit`, and when the response to stream 1 ended, if it came.
async fn h2_alive_until_closed(
    stream: &mut TcpStream,
    from: Instant,
    limit: Duration,
) -> (Option<Duration>, Option<Instant>) {
    let mut answered = None;
    loop {
        let left = limit.saturating_sub(from.elapsed());
        let mut head = [0u8; 9];
        // CANCEL-SAFETY: a read on the test's own socket; on timeout the test ends.
        match tokio::time::timeout(left, stream.read_exact(&mut head)).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => return (Some(from.elapsed()), answered),
            Err(_) => return (None, answered),
        }
        let length = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
        let mut payload = vec![0u8; length];
        if stream.read_exact(&mut payload).await.is_err() {
            return (Some(from.elapsed()), answered);
        }
        let (kind, flags, id) = (head[3], head[4], &head[5..9]);
        let reply: Option<Vec<u8>> = match kind {
            0x4 if flags & 1 == 0 => Some(b"\x00\x00\x00\x04\x01\x00\x00\x00\x00".to_vec()),
            0x6 if flags & 1 == 0 => {
                Some([&b"\x00\x00\x08\x06\x01\x00\x00\x00\x00"[..], &payload].concat())
            }
            0x0 | 0x1 if flags & 1 == 1 && id == [0, 0, 0, 1] => {
                answered = Some(Instant::now());
                None
            }
            _ => None,
        };
        if let Some(reply) = reply {
            if stream.write_all(&reply).await.is_err() {
                return (Some(from.elapsed()), answered);
            }
        }
    }
}

/// An HTTP/2 client that answers every ping but opens no stream is closed as an HTTP/1
/// one that sends no head: at the header timeout from the accept. It does not hold a
/// connection, and a place under `max_connections`, for as long as it answers.
#[tokio::test]
async fn an_http2_client_that_opens_no_stream_is_closed_at_the_header_timeout() {
    let server = start(16).await;
    let mut client = TcpStream::connect(server.addr).await.unwrap();
    let connected = Instant::now();
    client.write_all(H2_START).await.unwrap();
    let (closed, _) = h2_alive_until_closed(&mut client, connected, IDLE * 4).await;
    assert!(
        closed.is_some_and(|d| d < HEAD * 4),
        "an HTTP/2 client with no stream was kept: {closed:?}"
    );
}

/// After its last stream an HTTP/2 connection is idle as a keep-alive one: kept at least
/// the keep-alive timeout (past the header timeout), and closed once that has passed,
/// although the client answers every ping.
#[tokio::test]
async fn an_idle_http2_connection_is_closed_at_the_keep_alive_timeout() {
    let server = start(16).await;
    let mut client = TcpStream::connect(server.addr).await.unwrap();
    let connected = Instant::now();
    client.write_all(H2_START).await.unwrap();
    client.write_all(H2_GET).await.unwrap();
    let (closed, answered) = h2_alive_until_closed(&mut client, connected, IDLE * 4).await;
    let answered = answered.expect("the request on stream 1 is answered");
    let closed = closed.map(|at| connected + at - answered);
    assert!(
        closed.is_some_and(|d| d >= IDLE - HEAD && d < IDLE + HEAD * 4),
        "idle after its stream for {closed:?}, keep-alive {IDLE:?}"
    );
}

/// Handlers (the lockout, token routes) still see the client's address.
#[tokio::test]
async fn a_request_carries_the_peer_address() {
    let server = start(16).await;
    let addr = server.addr;
    let mut client = TcpStream::connect(addr).await.unwrap();
    client
        .write_all(b"GET /peer HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    assert!(read_response(&mut client).await.ends_with("127.0.0.1"));
}
