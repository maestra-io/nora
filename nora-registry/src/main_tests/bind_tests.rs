// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::bind_listener;

#[tokio::test]
async fn dual_stack_listener_accepts_ipv4() {
    // A "::" bind must accept IPv4 clients — via dual-stack, or via the
    // 0.0.0.0 fallback when IPv6 is unavailable. Guards against an IPv4
    // regression from defaulting the container bind to "::".
    let listener = bind_listener("::", 0).await.expect("bind ::");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { while listener.accept().await.is_ok() {} });
    tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("IPv4 loopback connects to a :: listener");
}
