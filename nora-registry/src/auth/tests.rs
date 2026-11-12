// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::*;

/// A Basic `nrs_` session password is a Bearer credential on every peer, an
/// htpasswd one included; an `nra_` one only with the shortcut.
#[test]
fn a_basic_session_password_is_always_a_bearer() {
    let basic = |password: &str| {
        let mut headers = HeaderMap::new();
        let value = format!("Basic {}", STANDARD.encode(format!("ci:{password}")));
        headers.insert(header::AUTHORIZATION, value.parse().unwrap());
        headers
    };
    let session = format!("nrs_1700000000_{}", "a".repeat(64));
    let bearer = basic_token_as_bearer(&basic(&session), false).unwrap();
    assert_eq!(bearer.to_str().unwrap(), format!("Bearer {session}"));
    assert!(basic_token_as_bearer(&basic("nra_x"), false).is_none());
    assert!(basic_token_as_bearer(&basic("nrs_password"), false).is_none());
}

/// #1094: an OIDC caller's lifetime ceiling caps the minted token; a
/// caller with no ceiling (Basic/opaque) is unchanged.
#[test]
fn audit_actor_resolves_user_or_anonymous() {
    // #985 — the audit actor is the authenticated username (whatever auth
    // transport set AuthenticatedUser: API token or Basic-auth), or
    // `anonymous` when the request carries no identity.
    let token_user = Some(axum::Extension(AuthenticatedUser("ci-bot".to_string())));
    assert_eq!(audit_actor(&token_user), "ci-bot");

    let basic_user = Some(axum::Extension(AuthenticatedUser("alice".to_string())));
    assert_eq!(audit_actor(&basic_user), "alice");

    let anonymous: Option<axum::Extension<AuthenticatedUser>> = None;
    assert_eq!(audit_actor(&anonymous), "anonymous");
}

#[test]
fn test_public_path_classification() {
    // Unconditional publics: probes + token endpoints only.
    for p in [
        "/",
        "/health",
        "/ready",
        "/api/tokens",
        "/api/tokens/list",
        "/api/tokens/revoke",
    ] {
        assert!(is_public_path(p), "{p}");
    }
    // The web surface is NOT unconditionally public any more — it is
    // config-gated in the middleware (repository enumeration).
    for p in [
        "/ui",
        "/ui/dashboard",
        "/api-docs",
        "/api-docs/openapi.json",
        "/api/ui/stats",
        "/metrics",
    ] {
        assert!(!is_public_path(p), "{p}");
    }
    for p in ["/ui", "/ui/rpm", "/api/ui/stats", "/api-docs"] {
        assert!(is_web_surface(p), "{p}");
    }
    // The UI's embedded assets and the favicon carry no data: always public.
    for p in [
        "/favicon.ico",
        "/ui/static/tailwind.css",
        "/ui/static/htmx.min.js",
    ] {
        assert!(is_public_path(p), "{p}");
    }
    for p in ["/ui/static/", "/ui/static/../tokens", "/favicon.ico/x"] {
        assert!(!is_public_path(p), "{p}");
    }
    // Token pages are part of the always-gated set, not the web surface.
    assert!(!is_web_surface("/ui/tokens"));
    assert!(!is_web_surface("/api/ui/tokens"));
    // Docker /v2/ is neither.
    assert!(!is_public_path("/v2/"));
    assert!(!is_web_surface("/v2/"));
}

#[test]
fn test_is_public_path_health() {
    assert!(is_public_path("/health"));
    assert!(is_public_path("/ready"));
    // /metrics is config-gated now (auth.public_metrics), not unconditional.
    assert!(!is_public_path("/metrics"));
}

#[test]
fn test_v2_is_not_public_path() {
    // Docker /v2/ must NOT be public — it needs auth challenge per V2 spec
    assert!(!is_public_path("/v2/"));
    assert!(!is_public_path("/v2"));
    // The /v2/ ping and all sub-paths are Docker registry paths, gated as a
    // group by docker_anon_pull.
    assert!(is_docker_path("/v2/"));
    assert!(is_docker_path("/v2"));
    assert!(is_docker_path("/v2/alpine/manifests/latest"));
    // Non-Docker paths are not.
    assert!(!is_docker_path("/raw/file.txt"));
    assert!(!is_docker_path("/v2x/sneaky"));
}

#[test]
fn test_is_public_path_ui() {
    // The UI is the config-gated web surface, not unconditionally public.
    for p in ["/ui", "/ui/dashboard", "/ui/repos"] {
        assert!(!is_public_path(p), "{p}");
        assert!(is_web_surface(p), "{p}");
    }
}

#[test]
fn test_is_public_path_api_docs() {
    for p in ["/api-docs", "/api-docs/openapi.json", "/api/ui"] {
        assert!(!is_public_path(p), "{p}");
        assert!(is_web_surface(p), "{p}");
    }
}

#[test]
fn test_is_public_path_tokens() {
    assert!(is_public_path("/api/tokens"));
    assert!(is_public_path("/api/tokens/list"));
    assert!(is_public_path("/api/tokens/revoke"));
}

#[test]
fn test_is_public_path_root() {
    assert!(is_public_path("/"));
}

#[test]
fn test_is_not_public_path_registry() {
    assert!(!is_public_path("/v2/library/alpine/manifests/latest"));
    assert!(is_public_path("/apk/keys/nora.rsa.pub"));
    assert!(!is_public_path("/apk/keys/"));
    assert!(!is_public_path("/apk/keys/x/y"));
    assert!(!is_public_path(
        "/apk/alpine/v3.22/main/x86_64/APKINDEX.tar.gz"
    ));
    assert!(!is_public_path("/npm/lodash"));
    assert!(!is_public_path("/maven/com/example"));
    assert!(!is_public_path("/pypi/simple/flask"));
}

#[test]
fn test_is_not_public_path_random() {
    assert!(!is_public_path("/admin"));
    assert!(!is_public_path("/secret"));
    assert!(!is_public_path("/api/data"));
}

#[test]
fn test_token_ui_paths_not_public() {
    // Token management UI must require authentication
    assert!(!is_public_path("/ui/tokens"));
    assert!(!is_public_path("/ui/tokens/"));
    assert!(!is_public_path("/api/ui/tokens/create"));
    assert!(!is_public_path("/api/ui/tokens/list"));
    assert!(!is_public_path("/api/ui/tokens/abcd1234abcd1234/revoke"));
}

#[test]
fn test_xff_trusted_proxy_uses_forwarded_ip() {
    use crate::config::TrustedProxies;
    let proxies = TrustedProxies::parse("127.0.0.1,::1");
    let mut request = Request::builder()
        .uri("/test")
        .header("x-forwarded-for", "1.2.3.4, 127.0.0.1")
        .body(Body::empty())
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        "127.0.0.1".parse().unwrap(),
        1234,
    )));
    let ip = extract_client_ip(&request, &proxies);
    assert_eq!(ip, Some("1.2.3.4".parse().unwrap()));
}

/// A reverse proxy appends the address it received the request from to whatever
/// X-Forwarded-For the client sent, so the left part of the header is the client's to choose.
/// The client is the rightmost address that is not a trusted proxy.
#[test]
fn a_client_behind_a_trusted_proxy_cannot_choose_its_address() {
    use crate::config::TrustedProxies;
    let loopback = TrustedProxies::default_loopback();
    let hops = TrustedProxies::parse("127.0.0.1,10.0.0.0/8");
    let peer: IpAddr = "127.0.0.1".parse().unwrap();
    let resolve = |lines: &[&str], real_ip: Option<&str>, trusted: &TrustedProxies| {
        let mut headers = HeaderMap::new();
        for line in lines {
            headers.append("x-forwarded-for", line.parse().unwrap());
        }
        if let Some(ip) = real_ip {
            headers.insert("x-real-ip", ip.parse().unwrap());
        }
        resolve_client_ip(peer, &headers, trusted).to_string()
    };
    let cases: [(&[&str], Option<&str>, &TrustedProxies, &str); 9] = [
        // nginx `$proxy_add_x_forwarded_for`: the client's header, then the real address
        (&["6.6.6.6, 203.0.113.9"], None, &loopback, "203.0.113.9"),
        (&["6.6.6.6,203.0.113.9"], None, &loopback, "203.0.113.9"),
        // a proxy that adds its own header line after the client's
        (&["6.6.6.6", "203.0.113.9"], None, &loopback, "203.0.113.9"),
        // a chain of trusted hops is walked past
        (
            &["6.6.6.6, 198.51.100.7, 10.0.0.5"],
            None,
            &hops,
            "198.51.100.7",
        ),
        // every address a trusted proxy: the leftmost
        (&["10.0.0.7, 10.0.0.5"], None, &hops, "10.0.0.7"),
        // a proxy that replaces the header: its one address
        (&["203.0.113.9"], None, &loopback, "203.0.113.9"),
        // an entry that is not an address ends the walk at the hop that wrote it
        (&["6.6.6.6, unknown, 10.0.0.5"], None, &hops, "10.0.0.5"),
        // nothing readable in X-Forwarded-For: X-Real-IP, as before
        (&["unknown"], Some("203.0.113.9"), &loopback, "203.0.113.9"),
        (&[], None, &loopback, "127.0.0.1"),
    ];
    for (lines, real_ip, trusted, want) in cases {
        assert_eq!(resolve(lines, real_ip, trusted), want, "{lines:?}");
    }
}

/// The client of a request, as a table over the peer, the forwarding
/// headers and `auth.trusted_proxies`: every address is canonical (an
/// IPv4-mapped one is its IPv4 address, any other IPv6 one is itself), and
/// the headers count only from a trusted peer.
#[test]
fn the_client_address_is_canonical_wherever_it_comes_from() {
    for (trusted, peer, header, value, client) in [
        (
            "::a00:1/128",
            "10.0.0.1",
            "x-forwarded-for",
            "1.2.3.4",
            "10.0.0.1",
        ),
        (
            "::a00:1/128",
            "::a00:1",
            "x-forwarded-for",
            "1.2.3.4",
            "1.2.3.4",
        ),
        ("::1/128", "::1", "x-forwarded-for", "1.2.3.4", "1.2.3.4"),
        (
            "::1/128",
            "0.0.0.1",
            "x-forwarded-for",
            "1.2.3.4",
            "0.0.0.1",
        ),
        (
            "10.0.0.0/8",
            "::ffff:10.0.0.9",
            "x-forwarded-for",
            "::ffff:1.2.3.4",
            "1.2.3.4",
        ),
        (
            "10.0.0.0/8",
            "::ffff:10.0.0.9",
            "x-real-ip",
            "::ffff:5.6.7.8",
            "5.6.7.8",
        ),
        (
            "10.0.0.0/8",
            "::ffff:10.0.0.9",
            "x-forwarded-for",
            "::a01:203",
            "::a01:203",
        ),
        ("10.0.0.0/8", "::ffff:10.0.0.9", "x-real-ip", "::1", "::1"),
        (
            "10.0.0.0/8",
            "10.0.0.9",
            "x-forwarded-for",
            "1.2.3.4, ::ffff:10.0.0.5",
            "1.2.3.4",
        ),
        (
            "10.0.0.0/8",
            "10.0.0.9",
            "x-forwarded-for",
            "1.2.3.4, ::a00:5",
            "::a00:5",
        ),
        (
            "10.0.0.0/8",
            "::a00:9",
            "x-forwarded-for",
            "1.2.3.4",
            "::a00:9",
        ),
        (
            "::ffff:10.0.0.0/104",
            "10.0.0.9",
            "x-forwarded-for",
            "1.2.3.4",
            "1.2.3.4",
        ),
    ] {
        let proxies = crate::config::TrustedProxies::parse(trusted);
        let mut headers = HeaderMap::new();
        headers.insert(header, value.parse().unwrap());
        assert_eq!(
            resolve_client_ip(peer.parse().unwrap(), &headers, &proxies),
            client.parse::<IpAddr>().unwrap(),
            "{trusted}, peer {peer}, {header}: {value}"
        );
    }
}

#[test]
fn test_xff_ignores_client_supplied_entries_left_of_trusted_hops() {
    use crate::config::TrustedProxies;
    // An appending proxy chain: the client spoofed "9.9.9.9", the edge proxy
    // (trusted 10.60.8.1) appended the real client 1.2.3.4.
    let proxies = TrustedProxies::parse("10.60.8.0/24");
    let mut request = Request::builder()
        .uri("/test")
        .header("x-forwarded-for", "9.9.9.9, 1.2.3.4, 10.60.8.2")
        .body(Body::empty())
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        "10.60.8.1".parse().unwrap(),
        1234,
    )));
    let ip = extract_client_ip(&request, &proxies);
    assert_eq!(ip, Some("1.2.3.4".parse().unwrap()));
}

#[test]
fn test_xff_untrusted_proxy_uses_peer_ip() {
    use crate::config::TrustedProxies;
    let proxies = TrustedProxies::parse("127.0.0.1,::1");
    let mut request = Request::builder()
        .uri("/test")
        .header("x-forwarded-for", "1.2.3.4")
        .body(Body::empty())
        .unwrap();
    // Peer is NOT in trusted list
    request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        "5.6.7.8".parse().unwrap(),
        1234,
    )));
    let ip = extract_client_ip(&request, &proxies);
    assert_eq!(ip, Some("5.6.7.8".parse().unwrap()));
}

#[test]
fn test_xff_no_header_uses_peer_ip() {
    use crate::config::TrustedProxies;
    let proxies = TrustedProxies::parse("127.0.0.1,::1");
    let mut request = Request::builder().uri("/test").body(Body::empty()).unwrap();
    request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        "127.0.0.1".parse().unwrap(),
        1234,
    )));
    let ip = extract_client_ip(&request, &proxies);
    assert_eq!(ip, Some("127.0.0.1".parse().unwrap()));
}

#[test]
fn test_trusted_proxies_parse_cidr() {
    use crate::config::TrustedProxies;
    let proxies = TrustedProxies::parse("10.0.0.0/8");
    assert!(proxies.contains("10.1.2.3".parse().unwrap()));
    assert!(proxies.contains("10.255.255.255".parse().unwrap()));
    assert!(!proxies.contains("11.0.0.1".parse().unwrap()));
}

#[test]
fn test_trusted_proxies_parse_single_ip() {
    use crate::config::TrustedProxies;
    let proxies = TrustedProxies::parse("192.168.1.1");
    assert!(proxies.contains("192.168.1.1".parse().unwrap()));
    assert!(!proxies.contains("192.168.1.2".parse().unwrap()));
}

#[test]
fn test_trusted_proxies_match_ipv4_mapped_peers() {
    // A `[::]` listener reports IPv4 peers as `::ffff:a.b.c.d`.
    use crate::config::TrustedProxies;
    let pods = TrustedProxies::parse("10.62.0.0/16");
    assert!(pods.contains("::ffff:10.62.2.90".parse().unwrap()));
    assert!(!pods.contains("::ffff:10.63.0.1".parse().unwrap()));
    let loopback = TrustedProxies::parse("127.0.0.1");
    assert!(loopback.contains("::ffff:127.0.0.1".parse().unwrap()));
    // Real IPv6 peers still match IPv6 entries only.
    let v6 = TrustedProxies::parse("fd00:62::/32");
    assert!(v6.contains("fd00:62::5".parse().unwrap()));
    assert!(!v6.contains("fd00:63::5".parse().unwrap()));
    assert!(!pods.contains("fd00:62::5".parse().unwrap()));
    // Mapped notation in the config means the IPv4 address / net.
    let mapped_cfg = TrustedProxies::parse("::ffff:10.62.0.0/112,::ffff:127.0.0.1");
    assert!(mapped_cfg.contains("10.62.9.9".parse().unwrap()));
    assert!(mapped_cfg.contains("127.0.0.1".parse().unwrap()));
    assert!(!mapped_cfg.contains("10.63.0.1".parse().unwrap()));
    // A v6 CIDR wider than /96 keeps covering mapped peers (CodeRabbit #44).
    let wide = TrustedProxies::parse("::ffff:0:0/95");
    assert!(wide.contains("::ffff:10.62.2.90".parse().unwrap()));
    let all_v6 = TrustedProxies::parse("::/0");
    assert!(all_v6.contains("::ffff:10.62.2.90".parse().unwrap()));
    assert!(!all_v6.contains("10.62.2.90".parse().unwrap()));
}

#[test]
fn test_resolve_client_ip_canonicalises_mapped_addresses() {
    use crate::config::TrustedProxies;
    let trusted = TrustedProxies::parse("10.62.0.0/16");
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", "203.0.113.7".parse().unwrap());
    // traefik on cilium_host, seen as a mapped peer: XFF is honoured.
    assert_eq!(
        resolve_client_ip("::ffff:10.62.2.90".parse().unwrap(), &headers, &trusted),
        "203.0.113.7".parse::<IpAddr>().unwrap()
    );
    // A mapped XFF hop keys the same as its plain IPv4 form.
    headers.insert("x-forwarded-for", "::ffff:203.0.113.7".parse().unwrap());
    assert_eq!(
        resolve_client_ip("10.62.2.90".parse().unwrap(), &headers, &trusted),
        "203.0.113.7".parse::<IpAddr>().unwrap()
    );
    // An untrusted mapped peer is keyed by its IPv4 form, one bucket per client.
    assert_eq!(
        resolve_client_ip("::ffff:198.51.100.1".parse().unwrap(), &headers, &trusted),
        "198.51.100.1".parse::<IpAddr>().unwrap()
    );
}

#[test]
fn test_trusted_proxies_default_loopback() {
    use crate::config::TrustedProxies;
    let proxies = TrustedProxies::default_loopback();
    assert!(proxies.contains("127.0.0.1".parse().unwrap()));
    assert!(proxies.contains("::1".parse().unwrap()));
    assert!(!proxies.contains("10.0.0.1".parse().unwrap()));
}

#[test]
fn test_auth_failure_tracker_allows_under_threshold() {
    let tracker = AuthFailureTracker::new(5, 900);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    for _ in 0..4 {
        tracker.record_failure(ip, "alice");
    }
    assert!(tracker.check_blocked(&ip, "alice").is_none());
}

#[test]
fn test_auth_failure_tracker_blocks_at_threshold() {
    let tracker = AuthFailureTracker::new(5, 900);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    for _ in 0..5 {
        tracker.record_failure(ip, "alice");
    }
    assert!(tracker.check_blocked(&ip, "alice").is_some());
}

#[test]
fn test_auth_failure_tracker_reports_lockout_once_per_lockout() {
    let tracker = AuthFailureTracker::new(5, 900);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    let started: Vec<_> = (0..5).map(|_| tracker.record_failure(ip, "u")).collect();
    assert_eq!(started, [None, None, None, None, Some(1)]);
    // Next failure (after the lockout ran out) starts the next, longer lockout.
    assert_eq!(tracker.record_failure(ip, "u"), Some(2));
    // The 429s of one lockout are logged once; a new failure starts a new lockout
    // whose first 429 is logged again.
    assert!(tracker.first_refusal(&ip, "u"));
    assert!(!tracker.first_refusal(&ip, "u"));
    assert!(tracker.first_refusal(&ip, "other"));
    tracker.record_failure(ip, "u");
    assert!(tracker.first_refusal(&ip, "u"));
}

#[test]
fn test_auth_failure_tracker_success_clears() {
    let tracker = AuthFailureTracker::new(5, 900);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    for _ in 0..10 {
        tracker.record_failure(ip, "alice");
    }
    assert!(tracker.check_blocked(&ip, "alice").is_some());
    tracker.record_success(&ip, "alice");
    assert!(tracker.check_blocked(&ip, "alice").is_none());
}

#[test]
fn test_auth_failure_tracker_independent_ips() {
    let tracker = AuthFailureTracker::new(3, 900);
    let ip1: IpAddr = "10.0.0.1".parse().unwrap();
    let ip2: IpAddr = "10.0.0.2".parse().unwrap();
    for _ in 0..3 {
        tracker.record_failure(ip1, "alice");
    }
    assert!(tracker.check_blocked(&ip1, "alice").is_some());
    assert!(tracker.check_blocked(&ip2, "alice").is_none());
}

/// The lockout counts by the whole username: a name sharing a prefix or
/// a suffix with a locked-out one, differing in case or in one trailing
/// byte of a long name, is another account and is not held.
#[test]
fn the_lockout_keys_the_whole_username() {
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    let long = "ci-deploy-production-runner-01";
    for (locked, others) in [
        (
            "alice",
            &["alicia", "ali", "alice2", "Alice", "alice ", "", "xalice"][..],
        ),
        (
            long,
            &[
                "ci-deploy-production-runner-02",
                "ci-deploy-production-runner-0",
            ][..],
        ),
    ] {
        let tracker = AuthFailureTracker::new(5, 900);
        for _ in 0..5 {
            tracker.record_failure(ip, locked);
        }
        assert!(tracker.check_blocked(&ip, locked).is_some(), "{locked}");
        for other in others {
            assert!(
                tracker.check_blocked(&ip, other).is_none(),
                "locking out {locked:?} held {other:?}"
            );
        }
    }
}

#[test]
fn test_auth_failure_tracker_cleanup() {
    let tracker = AuthFailureTracker::new(3, 1); // 1 sec max lockout
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    for _ in 0..5 {
        tracker.record_failure(ip, "alice");
    }
    // Cleanup should remove entries older than 2x max_lockout_secs: the last failure is
    // dated 3 s back (the clock the tracker reads), not waited for.
    let backdate = |last: &mut Instant| *last -= std::time::Duration::from_secs(3);
    {
        let mut entries = tracker.entries.lock();
        entries.accounts.values_mut().for_each(|(_, l)| backdate(l));
        entries
            .addresses
            .values_mut()
            .for_each(|(_, l)| backdate(l));
    }
    tracker.cleanup();
    let entries = tracker.entries.lock();
    assert!(entries.accounts.is_empty() && entries.addresses.is_empty());
    drop(entries);
    assert!(tracker.check_blocked(&ip, "alice").is_none());
}

#[test]
fn test_auth_failure_tracker_exponential_backoff() {
    let tracker = AuthFailureTracker::new(5, 900);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    // 5 failures = threshold, lockout = 2^0 = 1 sec
    for _ in 0..5 {
        tracker.record_failure(ip, "alice");
    }
    let retry1 = tracker.check_blocked(&ip, "alice").unwrap();
    assert!(
        retry1 <= 1,
        "first lockout should be ~1 sec, got {}",
        retry1
    );

    // 6 failures = 2^1 = 2 sec
    tracker.record_failure(ip, "alice");
    let retry2 = tracker.check_blocked(&ip, "alice").unwrap();
    assert!(
        retry2 <= 2,
        "second lockout should be ~2 sec, got {}",
        retry2
    );

    // 7 failures = 2^2 = 4 sec
    tracker.record_failure(ip, "alice");
    let retry3 = tracker.check_blocked(&ip, "alice").unwrap();
    assert!(
        retry3 <= 4,
        "third lockout should be ~4 sec, got {}",
        retry3
    );
}
