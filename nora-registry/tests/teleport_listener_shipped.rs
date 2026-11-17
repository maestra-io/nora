// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! `server.teleport_port` on the server as it ships: `nora serve` binds the Teleport
//! listener next to the main one and serves the same routes there.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

fn status(port: u16, path: &str) -> u16 {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(common::DEADLINE)).unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Forwarded-For: 198.51.100.77\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    answer[9..12].parse().unwrap()
}

#[test]
fn the_shipped_server_serves_the_teleport_port() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    let teleport_port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
        .to_string();
    let mut nora = match common::start(
        dir.path(),
        &[
            ("NORA_STORAGE_PATH", store.to_str().unwrap()),
            ("NORA_TELEPORT_PORT", &teleport_port),
        ],
    ) {
        common::Started::Serving(nora) => nora,
        common::Started::Exited(code, stderr) => panic!("nora exited {code:?}: {stderr}"),
    };
    nora.until(|log| log.contains("Teleport listener"))
        .expect("the Teleport listener was not bound");
    assert_eq!(status(teleport_port.parse().unwrap(), "/health"), 200);
    assert_eq!(status(nora.port, "/health"), 200);
}
