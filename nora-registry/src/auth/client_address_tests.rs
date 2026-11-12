// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::resolve_client_ip;
use crate::config::TrustedProxies;
use crate::test_helpers::*;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

/// A dual-stack socket (`NORA_HOST=::`, the image default) sees an IPv4
/// peer as `::ffff:a.b.c.d`.
const MAPPED_LOOPBACK: &str = "::ffff:127.0.0.1";

fn resolve(peer: &str, xff: &[&str], real_ip: Option<&str>, trusted: &TrustedProxies) -> IpAddr {
    let mut headers = HeaderMap::new();
    for line in xff {
        headers.append("x-forwarded-for", line.parse().unwrap());
    }
    if let Some(ip) = real_ip {
        headers.insert("x-real-ip", ip.parse().unwrap());
    }
    resolve_client_ip(peer.parse().unwrap(), &headers, trusted)
}

/// Measured in kind (ingress behind the image's `::` listener): the peer, the
/// trusted_proxies entry and the X-Forwarded-For entries meet in IPv4 form.
#[test]
fn an_ipv4_peer_on_a_dual_stack_listener_is_the_ipv4_address() {
    let resolve = |peer: &str, xff: Option<&str>, trusted: &str| {
        let mut headers = HeaderMap::new();
        if let Some(xff) = xff {
            headers.insert("x-forwarded-for", xff.parse().unwrap());
        }
        let peer: IpAddr = peer.parse().unwrap();
        resolve_client_ip(peer, &headers, &TrustedProxies::parse(trusted)).to_string()
    };
    // the ingress, trusted by its IPv4 address, seen on a `::` listener
    assert_eq!(
        resolve("::ffff:10.244.0.5", Some("10.244.0.7"), "10.244.0.5/32"),
        "10.244.0.7"
    );
    assert_eq!(
        resolve("::ffff:10.244.0.5", Some("10.244.0.7"), "10.244.0.0/16"),
        "10.244.0.7"
    );
    // a trusted proxy written in the mapped form, seen as IPv4
    assert_eq!(
        resolve("10.244.0.5", Some("10.244.0.7"), "::ffff:10.244.0.5"),
        "10.244.0.7"
    );
    // a hop that writes its peer in the mapped form is walked past
    assert_eq!(
        resolve(
            "::ffff:10.244.0.5",
            Some("10.244.0.7, ::ffff:10.244.0.6"),
            "10.244.0.0/16"
        ),
        "10.244.0.7"
    );
    // an untrusted peer is its IPv4 address, so it shares its limits with itself only
    assert_eq!(
        resolve("::ffff:203.0.113.9", None, "10.0.0.0/8"),
        "203.0.113.9"
    );
    // a proxy that writes the client in the mapped form names it in IPv4
    assert_eq!(
        resolve(
            "::ffff:10.244.0.5",
            Some("::ffff:10.244.0.7"),
            "10.244.0.0/16"
        ),
        "10.244.0.7"
    );
    // the list itself, asked directly
    let ipv4 = TrustedProxies::parse("10.0.0.0/8");
    assert!(ipv4.contains("::ffff:10.1.2.3".parse().unwrap()));
    assert!(!ipv4.contains("::ffff:11.1.2.3".parse().unwrap()));
    // a real IPv6 peer stays IPv6 and is not an IPv4 network's member
    assert_eq!(
        resolve("2001:db8::1", Some("10.244.0.7"), "10.0.0.0/8"),
        "2001:db8::1"
    );
}

/// An IPv4 address is one client whether it arrives over an IPv4 or a
/// dual-stack socket, as the peer, in X-Forwarded-For, in X-Real-IP or in
/// `trusted_proxies`: the resolved address is the plain IPv4 one.
#[test]
fn a_v4_mapped_address_is_its_ipv4_address() {
    let loopback = TrustedProxies::default_loopback();
    let pods = TrustedProxies::parse("10.0.0.0/8");
    let mapped_pods = TrustedProxies::parse("::ffff:10.0.0.0/104");
    let v4 = |s: &str| s.parse::<IpAddr>().unwrap();
    let cases: [(&str, &[&str], Option<&str>, &TrustedProxies, IpAddr); 7] = [
        // the loopback proxy over a dual-stack socket is still trusted
        (
            MAPPED_LOOPBACK,
            &["198.51.100.7"],
            None,
            &loopback,
            v4("198.51.100.7"),
        ),
        // a direct client over a dual-stack socket keys as its IPv4 address
        (
            "::ffff:203.0.113.5",
            &[],
            None,
            &loopback,
            v4("203.0.113.5"),
        ),
        // a mapped address written by a proxy
        (
            "127.0.0.1",
            &["::ffff:198.51.100.7"],
            None,
            &loopback,
            v4("198.51.100.7"),
        ),
        (
            "127.0.0.1",
            &[],
            Some("::ffff:203.0.113.9"),
            &loopback,
            v4("203.0.113.9"),
        ),
        // a mapped trusted hop in the chain is walked past
        (
            "10.1.2.3",
            &["198.51.100.7, ::ffff:10.0.0.5"],
            None,
            &pods,
            v4("198.51.100.7"),
        ),
        // a pod network named in either form trusts the other
        (
            "::ffff:10.1.2.3",
            &["198.51.100.7"],
            None,
            &pods,
            v4("198.51.100.7"),
        ),
        (
            "10.1.2.3",
            &["198.51.100.7"],
            None,
            &mapped_pods,
            v4("198.51.100.7"),
        ),
    ];
    for (peer, xff, real_ip, trusted, want) in cases {
        let got = resolve(peer, xff, real_ip, trusted);
        assert_eq!(got, want, "peer {peer} xff {xff:?} real_ip {real_ip:?}");
        assert!(got.is_ipv4(), "{got} is not canonical");
    }
    // The setting answers for a mapped address as for its IPv4 address.
    assert!(loopback.contains(MAPPED_LOOPBACK.parse().unwrap()));
    assert!(pods.contains("::ffff:10.1.2.3".parse().unwrap()));
    assert!(!pods.contains("::ffff:11.0.0.1".parse().unwrap()));
    // A real IPv6 client stays itself.
    assert_eq!(
        resolve("2001:db8::7", &[], None, &loopback),
        "2001:db8::7".parse::<IpAddr>().unwrap()
    );
}

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Captured;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// The warnings `run` logs.
fn warnings_of(run: impl FnOnce()) -> Vec<String> {
    use tracing_subscriber::prelude::*;
    let sink = Captured::default();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(sink.clone()),
    );
    tracing::subscriber::with_default(subscriber, || {
        // Another test's thread may have cached the callsites as
        // uninteresting while no subscriber was installed; recount them.
        tracing::callsite::rebuild_interest_cache();
        run()
    });
    let out = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    out.lines()
        .filter(|l| l.contains("WARN"))
        .map(str::to_string)
        .collect()
}

/// X-Forwarded-For from a peer outside `trusted_proxies` is ignored, and
/// NORA says so once: the warning names the peer and the setting, and
/// never the header, which the client wrote.
#[test]
fn forwarding_from_an_untrusted_peer_is_warned_about_once() {
    let trusted = TrustedProxies::parse("10.9.9.9");
    let warnings = warnings_of(|| {
        for _ in 0..3 {
            let ip = resolve("127.0.0.1", &["203.0.113.10"], None, &trusted);
            assert_eq!(ip, "127.0.0.1".parse::<IpAddr>().unwrap());
        }
        // a clone is the same setting (the limiters hold clones)
        let _ = resolve("127.0.0.1", &["203.0.113.10"], None, &trusted.clone());
    });
    assert_eq!(warnings.len(), 1, "{warnings:#?}");
    assert!(warnings[0].contains("127.0.0.1"), "{}", warnings[0]);
    assert!(warnings[0].contains("trusted_proxies"), "{}", warnings[0]);
    assert!(!warnings[0].contains("203.0.113.10"), "{}", warnings[0]);

    // No warning when there is nothing to ignore.
    let quiet = warnings_of(|| {
        let loopback = TrustedProxies::default_loopback();
        let _ = resolve("127.0.0.1", &["203.0.113.10"], None, &loopback);
        let _ = resolve(MAPPED_LOOPBACK, &["203.0.113.10"], None, &loopback);
        let _ = resolve("203.0.113.5", &[], None, &TrustedProxies::parse("10.9.9.9"));
    });
    assert!(quiet.is_empty(), "{quiet:#?}");
}

/// Each forwarding header NORA reads is ignored from a peer outside
/// `trusted_proxies`, sent alone or with the other, and the setting
/// records that it warned. Read from the setting, not from a log capture,
/// which other tests' threads can race; the warning's text is held by
/// `forwarding_from_an_untrusted_peer_is_warned_about_once`.
#[test]
fn every_forwarding_header_from_an_untrusted_peer_is_warned_about() {
    let sent: [(&[&str], Option<&str>); 3] = [
        (&["203.0.113.10"], None),
        (&[], Some("203.0.113.10")),
        (&["203.0.113.10"], Some("203.0.113.10")),
    ];
    for (xff, real_ip) in sent {
        let trusted = TrustedProxies::parse("10.9.9.9");
        let ip = resolve("127.0.0.1", xff, real_ip, &trusted);
        assert_eq!(ip, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert!(
            trusted.warned_untrusted_forwarding(),
            "xff {xff:?} real_ip {real_ip:?} ignored without a warning"
        );
    }
    // Controls: nothing to ignore, nothing to warn about.
    let untrusted = TrustedProxies::parse("10.9.9.9");
    let _ = resolve("127.0.0.1", &[], None, &untrusted);
    assert!(!untrusted.warned_untrusted_forwarding());
    let loopback = TrustedProxies::default_loopback();
    let _ = resolve(
        "127.0.0.1",
        &["203.0.113.10"],
        Some("203.0.113.10"),
        &loopback,
    );
    assert!(!loopback.warned_untrusted_forwarding());
}

/// Send a request from `peer` (the TCP address the server sees).
async fn send_from(
    app: &axum::Router,
    peer: &str,
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
) -> StatusCode {
    use tower::ServiceExt;
    let mut builder = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let mut request = builder.body(Body::empty()).unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(peer.parse().unwrap(), 4000)));
    app.clone().oneshot(request).await.unwrap().status()
}

fn basic(user: &str, pass: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{user}:{pass}")))
}

/// Behind the loopback proxy on a dual-stack socket, one client's
/// wrong passwords lock out that client only: the same account from
/// another client behind the same proxy still gets in.
#[tokio::test]
async fn a_v4_mapped_proxy_keeps_its_clients_apart() {
    let ctx = create_test_context_with_auth(&[("alice", "alicepw"), ("bob", "bobpw")]);
    let wrong = basic("bob", "wrong");
    for _ in 0..6 {
        let status = send_from(
            &ctx.app,
            MAPPED_LOOPBACK,
            Method::GET,
            "/v2/",
            &[
                ("authorization", &wrong),
                ("x-forwarded-for", "203.0.113.10"),
            ],
        )
        .await;
        assert!(
            matches!(
                status,
                StatusCode::UNAUTHORIZED | StatusCode::TOO_MANY_REQUESTS
            ),
            "{status}"
        );
    }
    // The same account, from another client behind the same proxy.
    let good = basic("bob", "bobpw");
    let other = send_from(
        &ctx.app,
        MAPPED_LOOPBACK,
        Method::GET,
        "/v2/",
        &[
            ("authorization", &good),
            ("x-forwarded-for", "198.51.100.7"),
        ],
    )
    .await;
    assert_eq!(
        other,
        StatusCode::OK,
        "another client behind the proxy is locked out"
    );
    let same = send_from(
        &ctx.app,
        MAPPED_LOOPBACK,
        Method::GET,
        "/v2/",
        &[
            ("authorization", &good),
            ("x-forwarded-for", "203.0.113.10"),
        ],
    )
    .await;
    assert_eq!(
        same,
        StatusCode::TOO_MANY_REQUESTS,
        "the guessing client is not locked out"
    );
}

/// The lockout counts wrong passwords: while an address is locked
/// out, a valid API token sent as Bearer is served, and wrong Bearer tokens
/// do not lock an address out at all. A password stays refused.
#[tokio::test]
async fn a_valid_bearer_token_is_served_while_passwords_are_locked_out() {
    let ctx = create_test_context_with_auth(&[("alice", "alicepw")]);
    let token = ctx
        .state
        .tokens
        .as_ref()
        .unwrap()
        .create_token("ci", 30, None, crate::tokens::Role::Write)
        .await
        .unwrap();
    let bearer = format!("Bearer {token}");
    let wrong = basic("alice", "wrong");
    for _ in 0..6 {
        let _ = send_from(
            &ctx.app,
            "127.0.0.1",
            Method::GET,
            "/v2/",
            &[("authorization", &wrong)],
        )
        .await;
    }
    assert!(
        ctx.state
            .auth_failures
            .check_blocked(&"127.0.0.1".parse().unwrap(), "alice")
            .is_some(),
        "wrong passwords did not lock the address out"
    );
    // Lengthen the lockout past the Argon2 check of the Bearer token
    // below, which can outlast a lockout of a second or two under load.
    lock_out_alice(&ctx.state.auth_failures, "127.0.0.1");
    let good = basic("alice", "alicepw");
    assert_eq!(
        send_from(
            &ctx.app,
            "127.0.0.1",
            Method::GET,
            "/v2/",
            &[("authorization", &good)]
        )
        .await,
        StatusCode::TOO_MANY_REQUESTS,
        "passwords from a locked-out address are refused"
    );
    assert_eq!(
        send_from(
            &ctx.app,
            "127.0.0.1",
            Method::GET,
            "/v2/",
            &[("authorization", &bearer)]
        )
        .await,
        StatusCode::OK,
        "a valid Bearer token from a locked-out address is refused"
    );
    // The served token did not lift the lockout of passwords.
    assert_eq!(
        send_from(
            &ctx.app,
            "127.0.0.1",
            Method::GET,
            "/v2/",
            &[("authorization", &good)]
        )
        .await,
        StatusCode::TOO_MANY_REQUESTS,
        "a Bearer token lifted the password lockout"
    );
}

#[tokio::test]
async fn wrong_bearer_tokens_do_not_lock_an_address_out() {
    let ctx = create_test_context_with_auth(&[("alice", "alicepw")]);
    let bad = "Bearer nra_00000000000000000000000000000000";
    for _ in 0..8 {
        assert_eq!(
            send_from(
                &ctx.app,
                "127.0.0.1",
                Method::GET,
                "/v2/",
                &[("authorization", bad)]
            )
            .await,
            StatusCode::UNAUTHORIZED
        );
    }
    let good = basic("alice", "alicepw");
    assert_eq!(
        send_from(
            &ctx.app,
            "127.0.0.1",
            Method::GET,
            "/v2/",
            &[("authorization", &good)]
        )
        .await,
        StatusCode::OK,
        "wrong Bearer tokens locked the address out"
    );
}

/// Every client of these tests sits behind one NAT address, as a company
/// behind its egress does; the loopback proxy in front of NORA is trusted.
const NAT: &str = "198.51.100.50";

/// GET /v2/ from a client behind `xff` with Basic `user:pass`.
async fn login(app: &axum::Router, xff: &str, user: &str, pass: &str) -> StatusCode {
    let auth = basic(user, pass);
    send_from(
        app,
        "127.0.0.1",
        Method::GET,
        "/v2/",
        &[("authorization", &auth), ("x-forwarded-for", xff)],
    )
    .await
}

/// Wrong passwords for one account lock out that account on that address,
/// not another account behind the same NAT.
#[tokio::test]
async fn guessing_one_accounts_password_leaves_other_accounts_alone() {
    let ctx = create_test_context_with_auth(&[("alice", "alicepw"), ("bob", "bobpw")]);
    for _ in 0..6 {
        let _ = login(&ctx.app, NAT, "alice", "wrong").await;
    }
    assert_eq!(
        login(&ctx.app, NAT, "bob", "bobpw").await,
        StatusCode::OK,
        "guesses at alice locked bob out"
    );
    assert_eq!(
        login(&ctx.app, NAT, "alice", "alicepw").await,
        StatusCode::TOO_MANY_REQUESTS,
        "the guessed account is not locked out"
    );
}

/// A login by one account does not clear the failures of another.
#[tokio::test]
async fn a_login_does_not_clear_another_accounts_failures() {
    let ctx = create_test_context_with_auth(&[("alice", "alicepw"), ("bob", "bobpw")]);
    for _ in 0..4 {
        assert_eq!(
            login(&ctx.app, NAT, "alice", "wrong").await,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(login(&ctx.app, NAT, "bob", "bobpw").await, StatusCode::OK);
    assert_eq!(
        login(&ctx.app, NAT, "alice", "wrong").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        login(&ctx.app, NAT, "alice", "alicepw").await,
        StatusCode::TOO_MANY_REQUESTS,
        "bob's login cleared alice's failures"
    );
}

/// Guessing across many usernames from one address is still held: past a
/// ceiling of failed passwords per address (ten accounts' worth of the
/// per-account threshold) the address gets no password checked, whatever
/// the username. Below it, the address is not held, and another address is
/// never held by it.
#[tokio::test]
async fn guessing_many_usernames_from_one_address_is_capped() {
    let ctx = create_test_context_with_auth(&[("bob", "bobpw")]);
    // 49 failures, never more than 4 for one username: no account is
    // locked out and the address is one below its ceiling of 50.
    for n in 0..49 {
        let user = format!("u{}", n / 4);
        assert_eq!(
            login(&ctx.app, NAT, &user, "wrong").await,
            StatusCode::UNAUTHORIZED,
            "guess {n}"
        );
    }
    assert_eq!(
        login(&ctx.app, NAT, "bob", "bobpw").await,
        StatusCode::OK,
        "the address was held below its ceiling"
    );
    // The 50th failure, for yet another username, reaches the ceiling.
    assert_eq!(
        login(&ctx.app, NAT, "fresh", "wrong").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        login(&ctx.app, NAT, "bob", "bobpw").await,
        StatusCode::TOO_MANY_REQUESTS,
        "guessing across usernames is not held per address"
    );
    assert_eq!(
        login(&ctx.app, NAT, "other", "wrong").await,
        StatusCode::TOO_MANY_REQUESTS,
        "a new username escapes the address ceiling"
    );
    assert_eq!(
        login(&ctx.app, "192.0.2.77", "bob", "bobpw").await,
        StatusCode::OK,
        "another address is held"
    );
}

/// Control: an empty username is an account like any other, and a header
/// with no username at all (no `:`) is malformed and not counted.
#[tokio::test]
async fn an_empty_or_missing_username_is_held_like_any_other() {
    let ctx = create_test_context_with_auth(&[("alice", "alicepw")]);
    let mut statuses = Vec::new();
    for _ in 0..6 {
        statuses.push(login(&ctx.app, NAT, "", "wrong").await.as_u16());
    }
    assert_eq!(statuses, [401, 401, 401, 401, 401, 429], "empty username");
    assert_eq!(
        login(&ctx.app, NAT, "alice", "alicepw").await,
        StatusCode::OK
    );

    let no_username = format!("Basic {}", STANDARD.encode("no-colon-here"));
    for _ in 0..8 {
        let status = send_from(
            &ctx.app,
            "127.0.0.1",
            Method::GET,
            "/v2/",
            &[
                ("authorization", &no_username),
                ("x-forwarded-for", "192.0.2.80"),
            ],
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a malformed header is counted"
        );
    }
    assert_eq!(
        login(&ctx.app, "192.0.2.80", "alice", "alicepw").await,
        StatusCode::OK
    );
}

/// Docker sends an API token as the Basic password, under a username CI
/// jobs share ("docker", "token"). A valid token is served while that
/// username is locked out, as over Bearer; a password is not.
#[tokio::test]
async fn a_valid_api_token_as_the_basic_password_is_served_while_locked_out() {
    let ctx = create_test_context_with_auth(&[("alice", "alicepw")]);
    let token = ctx
        .state
        .tokens
        .as_ref()
        .unwrap()
        .create_token("ci", 30, None, crate::tokens::Role::Write)
        .await
        .unwrap();
    for _ in 0..6 {
        let _ = login(
            &ctx.app,
            NAT,
            "docker",
            "nra_00000000000000000000000000000000",
        )
        .await;
    }
    assert_eq!(
        login(&ctx.app, NAT, "docker", "not-a-token").await,
        StatusCode::TOO_MANY_REQUESTS,
        "the username is not locked out"
    );
    assert_eq!(
        login(&ctx.app, NAT, "docker", &token).await,
        StatusCode::OK,
        "a valid token as the Basic password is refused while locked out"
    );
}

/// The routes that take a username and password in their JSON body, and
/// the status each answers once the password is accepted (the revoke names
/// a token alice does not have).
const TOKEN_ROUTES: [(&str, StatusCode); 3] = [
    ("/api/tokens", StatusCode::OK),
    ("/api/tokens/list", StatusCode::OK),
    ("/api/tokens/revoke", StatusCode::NOT_FOUND),
];

/// POST a token-route body for `alice` with `password` from `peer`.
async fn token_route_from(
    app: &axum::Router,
    peer: &str,
    uri: &str,
    password: &str,
    headers: &[(&str, &str)],
) -> StatusCode {
    use tower::ServiceExt;
    let body = format!(
        r#"{{"username":"alice","password":"{password}","hash_prefix":"0123456789abcdef"}}"#
    );
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/json");
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let mut request = builder.body(Body::from(body)).unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(peer.parse().unwrap(), 4000)));
    app.clone().oneshot(request).await.unwrap().status()
}

/// Lock alice out at `ip` for half a minute (ten failures), so no test
/// step races the end of the lockout.
fn lock_out_alice(tracker: &super::AuthFailureTracker, ip: &str) {
    for _ in 0..10 {
        tracker.record_failure(ip.parse().unwrap(), "alice");
    }
}

/// Every token route keeps the lockout as the middleware does: it counts
/// a wrong password, a login clears the count, and a locked-out username
/// gets no password checked, however the lockout was earned. Another
/// address is not held.
#[tokio::test]
async fn every_token_route_keeps_the_lockout() {
    let client = "203.0.113.5";
    let ip: IpAddr = client.parse().unwrap();
    for (uri, served) in TOKEN_ROUTES {
        let ctx = create_test_context_with_auth(&[("alice", "alicepw")]);
        let tracker = &ctx.state.auth_failures;

        // The wrong password that reaches the threshold is counted here.
        for _ in 0..4 {
            tracker.record_failure(ip, "alice");
        }
        assert_eq!(
            token_route_from(&ctx.app, client, uri, "wrong", &[]).await,
            StatusCode::UNAUTHORIZED,
            "{uri}"
        );
        assert!(
            tracker.check_blocked(&ip, "alice").is_some(),
            "{uri} does not count a wrong password"
        );

        // A login clears the account's count.
        let ctx = create_test_context_with_auth(&[("alice", "alicepw")]);
        let tracker = &ctx.state.auth_failures;
        for _ in 0..4 {
            tracker.record_failure(ip, "alice");
        }
        assert_eq!(
            token_route_from(&ctx.app, client, uri, "alicepw", &[]).await,
            served,
            "{uri}"
        );
        tracker.record_failure(ip, "alice");
        assert!(
            tracker.check_blocked(&ip, "alice").is_none(),
            "{uri}: a login did not clear the failures"
        );

        // Locked out: the right password is refused, the address is
        // named in no way the client chooses, another address is served.
        let ctx = create_test_context_with_auth(&[("alice", "alicepw")]);
        lock_out_alice(&ctx.state.auth_failures, client);
        assert_eq!(
            token_route_from(&ctx.app, client, uri, "alicepw", &[]).await,
            StatusCode::TOO_MANY_REQUESTS,
            "{uri} checks the password of a locked-out username"
        );
        assert_eq!(
            token_route_from(
                &ctx.app,
                client,
                uri,
                "alicepw",
                &[
                    ("x-forwarded-for", "198.51.100.7"),
                    ("x-real-ip", "198.51.100.7")
                ]
            )
            .await,
            StatusCode::TOO_MANY_REQUESTS,
            "{uri}: forwarding headers from an untrusted peer escape the lockout"
        );
        assert_eq!(
            token_route_from(&ctx.app, "192.0.2.77", uri, "alicepw", &[]).await,
            served,
            "{uri}: another address is held"
        );
    }
}

/// A lockout earned on one token route holds on every other, and on the
/// middleware's Basic login: it is one count per account, whichever route
/// the guesses came by.
#[tokio::test]
async fn a_lockout_earned_on_one_token_route_holds_on_every_route() {
    let client = "203.0.113.5";
    for (earned_on, _) in TOKEN_ROUTES {
        let ctx = create_test_context_with_auth(&[("alice", "alicepw")]);
        for _ in 0..4 {
            ctx.state
                .auth_failures
                .record_failure(client.parse().unwrap(), "alice");
        }
        assert_eq!(
            token_route_from(&ctx.app, client, earned_on, "wrong", &[]).await,
            StatusCode::UNAUTHORIZED
        );
        assert!(
            ctx.state
                .auth_failures
                .check_blocked(&client.parse().unwrap(), "alice")
                .is_some(),
            "{earned_on} does not count a wrong password"
        );
        // Lengthen the lockout so no step below races its end.
        lock_out_alice(&ctx.state.auth_failures, client);
        for (uri, _) in TOKEN_ROUTES {
            assert_eq!(
                token_route_from(&ctx.app, client, uri, "alicepw", &[]).await,
                StatusCode::TOO_MANY_REQUESTS,
                "locked out on {earned_on}, served on {uri}"
            );
        }
        let auth = basic("alice", "alicepw");
        assert_eq!(
            send_from(
                &ctx.app,
                client,
                Method::GET,
                "/v2/",
                &[("authorization", &auth)]
            )
            .await,
            StatusCode::TOO_MANY_REQUESTS,
            "locked out on {earned_on}, served by the middleware"
        );
    }
}

/// The token routes key a client by its canonical address, as the
/// middleware does: `::ffff:a.b.c.d` from a dual-stack socket is the
/// client `a.b.c.d`, for the failures it adds and the lockout it meets.
#[tokio::test]
async fn the_token_routes_key_a_v4_mapped_peer_as_its_ipv4_address() {
    for (uri, _) in TOKEN_ROUTES {
        // Locked out as 203.0.113.5, refused as ::ffff:203.0.113.5.
        let ctx = create_test_context_with_auth(&[("alice", "alicepw")]);
        lock_out_alice(&ctx.state.auth_failures, "203.0.113.5");
        assert_eq!(
            token_route_from(&ctx.app, "::ffff:203.0.113.5", uri, "alicepw", &[]).await,
            StatusCode::TOO_MANY_REQUESTS,
            "{uri}: the mapped peer is another client"
        );

        // A wrong password from ::ffff:198.51.100.9 counts for 198.51.100.9.
        let ctx = create_test_context_with_auth(&[("alice", "alicepw")]);
        let ip: IpAddr = "198.51.100.9".parse().unwrap();
        for _ in 0..4 {
            ctx.state.auth_failures.record_failure(ip, "alice");
        }
        assert_eq!(
            token_route_from(&ctx.app, "::ffff:198.51.100.9", uri, "wrong", &[]).await,
            StatusCode::UNAUTHORIZED,
            "{uri}"
        );
        assert!(
            ctx.state
                .auth_failures
                .check_blocked(&ip, "alice")
                .is_some(),
            "{uri}: a failure from the mapped peer is counted elsewhere"
        );
    }
}
