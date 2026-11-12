// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::sanitize_proxy_url;

#[test]
fn sanitize_with_credentials() {
    assert_eq!(
        sanitize_proxy_url("http://user:p%40ss@proxy:3128"),
        "http://***@proxy:3128"
    );
}

#[test]
fn sanitize_user_only() {
    assert_eq!(
        sanitize_proxy_url("http://admin@proxy:3128"),
        "http://***@proxy:3128"
    );
}

#[test]
fn sanitize_no_credentials() {
    assert_eq!(sanitize_proxy_url("http://proxy:3128"), "http://proxy:3128");
}

#[test]
fn sanitize_socks5() {
    assert_eq!(
        sanitize_proxy_url("socks5://user:pass@proxy:1080"),
        "socks5://***@proxy:1080"
    );
}

#[test]
fn sanitize_empty() {
    assert_eq!(sanitize_proxy_url(""), "");
}
