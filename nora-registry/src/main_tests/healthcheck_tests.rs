// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::healthcheck_url;

#[test]
fn wildcard_hosts_probe_loopback() {
    assert_eq!(
        healthcheck_url("0.0.0.0", 4000),
        "http://127.0.0.1:4000/health"
    );
    // Both wildcards probe IPv4 loopback (reaches dual-stack and the
    // 0.0.0.0 fallback alike).
    assert_eq!(healthcheck_url("::", 4000), "http://127.0.0.1:4000/health");
    assert_eq!(
        healthcheck_url("[::]", 4000),
        "http://127.0.0.1:4000/health"
    );
}

#[test]
fn specific_hosts_pass_through_with_ipv6_bracketing() {
    assert_eq!(
        healthcheck_url("127.0.0.1", 8080),
        "http://127.0.0.1:8080/health"
    );
    assert_eq!(
        healthcheck_url("example.com", 80),
        "http://example.com:80/health"
    );
    assert_eq!(healthcheck_url("::1", 4000), "http://[::1]:4000/health");
    assert_eq!(
        healthcheck_url("[2001:db8::1]", 4000),
        "http://[2001:db8::1]:4000/health"
    );
}
