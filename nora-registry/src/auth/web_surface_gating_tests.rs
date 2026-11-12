// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::test_helpers::{
    body_bytes, create_test_context_with_anonymous_read,
    create_test_context_with_anonymous_read_and_config, create_test_context_with_auth, send,
    send_with_headers,
};
use axum::http::{Method, StatusCode};
use base64::{engine::general_purpose::STANDARD, Engine};

fn basic(user: &str, pass: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"))
    )
}

/// With auth on and no anonymous read, the whole web surface requires
/// credentials — it enumerates every repository — while probes stay open.
#[tokio::test]
async fn test_web_surface_gated_when_private() {
    let ctx = create_test_context_with_auth(&[("alice", "pw")]);

    for p in [
        "/ui/",
        "/ui/rpm",
        "/api/ui/stats",
        "/api/ui/dashboard",
        "/api-docs/openapi.json",
    ] {
        let resp = send(&ctx.app, Method::GET, p, "").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{p}");
        assert!(
            resp.headers().get("www-authenticate").is_some(),
            "{p} must challenge so browsers prompt"
        );
    }
    // Probes stay unconditionally open (LB/liveness would break). The storage
    // verdict is the one the maintenance loop's first tick takes.
    ctx.state.storage.refresh_reachability().await;
    for p in ["/health", "/ready"] {
        let resp = send(&ctx.app, Method::GET, p, "").await;
        assert_eq!(resp.status(), StatusCode::OK, "{p}");
    }
    // /metrics defaults to open for scrapers.
    let resp = send(&ctx.app, Method::GET, "/metrics", "").await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Valid credentials open the web surface.
    let cred = basic("alice", "pw");
    let resp = send_with_headers(
        &ctx.app,
        Method::GET,
        "/api/ui/stats",
        vec![("authorization", cred.as_str())],
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

/// anonymous_read (which already exposes repo names through the registry
/// read APIs) or the explicit public_web_ui switch reopen the surface;
/// public_metrics=false closes /metrics.
#[tokio::test]
async fn test_gating_switches() {
    let ctx = crate::test_helpers::create_test_context_with_config(|c| {
        c.auth.enabled = true;
        c.auth.anonymous_read = true;
    });
    let resp = send(&ctx.app, Method::GET, "/ui/", "").await;
    assert_eq!(resp.status(), StatusCode::OK, "anonymous_read opens the UI");

    let ctx = crate::test_helpers::create_test_context_with_config(|c| {
        c.auth.enabled = true;
        c.auth.public_web_ui = true;
    });
    let resp = send(&ctx.app, Method::GET, "/api/ui/stats", "").await;
    assert_eq!(resp.status(), StatusCode::OK, "public_web_ui opens the UI");

    let ctx = crate::test_helpers::create_test_context_with_config(|c| {
        c.auth.enabled = true;
        c.auth.public_metrics = false;
    });
    let resp = send(&ctx.app, Method::GET, "/metrics", "").await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "public_metrics=false gates metrics"
    );
}

/// Token management pages stay gated even when the web surface is open.
#[tokio::test]
async fn test_token_pages_stay_gated() {
    let ctx = crate::test_helpers::create_test_context_with_config(|c| {
        c.auth.enabled = true;
        c.auth.public_web_ui = true;
    });
    let resp = send(&ctx.app, Method::GET, "/api/ui/tokens", "").await;
    assert_ne!(resp.status(), StatusCode::OK);
}

// -- #934: opportunistic auth on open web surfaces --

/// try_basic_auth returns the username for valid htpasswd credentials once htpasswd
/// has checked them, and runs no bcrypt itself: before the check, the caller is
/// anonymous.
#[tokio::test]
async fn test_try_basic_auth_valid() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("htpasswd");
    let hash = bcrypt::hash("secret", 4).unwrap();
    std::fs::write(&path, format!("admin:{hash}\n")).unwrap();
    let htpasswd = super::HtpasswdAuth::from_file(&path).unwrap();
    let encoded = STANDARD.encode("admin:secret");
    assert_eq!(super::try_basic_auth(&encoded, Some(&htpasswd)), None);
    assert!(htpasswd.verify("admin", "secret").await);
    assert_eq!(
        super::try_basic_auth(&encoded, Some(&htpasswd)),
        Some("admin".to_string())
    );
    assert_eq!(
        htpasswd
            .bcrypt_runs
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "only the check ran bcrypt"
    );
}

/// try_basic_auth returns None for wrong password.
#[test]
fn test_try_basic_auth_wrong_password() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("htpasswd");
    let hash = bcrypt::hash("secret", 4).unwrap();
    std::fs::write(&path, format!("admin:{hash}\n")).unwrap();
    let htpasswd = super::HtpasswdAuth::from_file(&path).unwrap();
    let encoded = STANDARD.encode("admin:wrong");
    assert_eq!(super::try_basic_auth(&encoded, Some(&htpasswd)), None);
}

/// try_basic_auth returns None when no htpasswd store is available.
#[test]
fn test_try_basic_auth_no_store() {
    let encoded = STANDARD.encode("admin:secret");
    assert_eq!(super::try_basic_auth(&encoded, None), None);
}

/// try_basic_auth returns None for garbage base64.
#[test]
fn test_try_basic_auth_invalid_base64() {
    assert_eq!(super::try_basic_auth("%%%not-base64%%%", None), None);
}

/// A bcrypt hash at cost 31: verifying it takes days, so any test that
/// finishes while this user is in htpasswd proves bcrypt never ran.
fn unverifiable_hash() -> String {
    bcrypt::hash("irrelevant", 4)
        .unwrap()
        .replacen("$04$", "$31$", 1)
}

/// Run `f` on its own runtime with a deadline; on timeout the runtime is
/// abandoned instead of joined, so a stray bcrypt fails the test, not hangs it.
fn within_deadline<F: std::future::Future<Output = ()>>(f: F) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let res =
        rt.block_on(async { tokio::time::timeout(std::time::Duration::from_secs(10), f).await });
    rt.shutdown_background();
    assert!(res.is_ok(), "request ran an htpasswd bcrypt verify");
}

/// An `nra_` token as the Basic password works when no htpasswd is loaded
/// (missing or empty file): the token store does not depend on htpasswd.
#[tokio::test]
async fn test_basic_api_token_without_htpasswd() {
    let ctx = create_test_context_with_auth(&[]);
    assert!(ctx.state.auth.is_none());
    let token = ctx
        .state
        .tokens
        .as_ref()
        .unwrap()
        .create_token("ci", 30, None, crate::tokens::Role::Write)
        .await
        .unwrap();
    let good = format!("Basic {}", STANDARD.encode(format!("token:{token}")));
    let resp = send_with_headers(
        &ctx.app,
        Method::PUT,
        "/raw/t.txt",
        vec![("authorization", &good)],
        b"x".to_vec(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let bad = format!("Basic {}", STANDARD.encode("token:nra_bogus"));
    let resp = send_with_headers(
        &ctx.app,
        Method::GET,
        "/raw/t.txt",
        vec![("authorization", &bad)],
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// Probes never validate a Basic header: no bcrypt, no lockout bookkeeping.
#[test]
fn test_probe_ignores_basic_credentials() {
    let hash = unverifiable_hash();
    let ctx = create_test_context_with_auth(&[("admin", hash.as_str())]);
    let header_val = format!("Basic {}", STANDARD.encode("admin:wrong"));
    within_deadline(async {
        for _ in 0..6 {
            let resp = send_with_headers(
                &ctx.app,
                Method::GET,
                "/health",
                vec![("authorization", &header_val)],
                "",
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK);
        }
    });
    let ip: std::net::IpAddr = [127, 0, 0, 1].into();
    assert!(ctx
        .state
        .auth_failures
        .check_blocked(&ip, "admin")
        .is_none());
}

/// The open path is no password oracle: it runs no bcrypt for a Basic header, so a
/// right and a wrong password htpasswd has not checked get the same answer, and
/// nothing is counted toward the lockout (there is no verdict to count).
#[tokio::test]
async fn test_open_path_basic_is_no_password_oracle() {
    let ctx = create_test_context_with_auth(&[("admin", "secret")]);
    let mut answers = Vec::new();
    for password in ["wrong", "secret", "wrong", "wrong", "wrong", "wrong"] {
        let header_val = format!("Basic {}", STANDARD.encode(format!("admin:{password}")));
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/",
            vec![("authorization", &header_val)],
            "",
        )
        .await;
        assert_ne!(resp.status(), StatusCode::UNAUTHORIZED);
        answers.push(resp.status());
    }
    assert!(answers.iter().all(|s| *s == answers[0]), "{answers:?}");
    let runs = ctx
        .state
        .auth
        .as_ref()
        .unwrap()
        .bcrypt_runs
        .load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(runs, 0, "the open path ran bcrypt");
    let ip: std::net::IpAddr = [127, 0, 0, 1].into();
    assert!(ctx
        .state
        .auth_failures
        .check_blocked(&ip, "admin")
        .is_none());
}

/// On an open web surface (anonymous_read=true), valid Basic credentials that
/// htpasswd has checked must produce a real AuthenticatedUser — not "anonymous". Verified via
/// /api/ui/dashboard: anonymous sees empty proxy_upstreams; authenticated
/// sees the configured npm upstream.
#[tokio::test]
async fn test_opportunistic_basic_auth_on_open_surface() {
    let ctx = create_test_context_with_anonymous_read_and_config(&[("admin", "secret")], |c| {
        c.npm.proxy = Some("https://registry.npmjs.org".into());
    });

    // Anonymous: proxy_upstreams redacted
    let resp = send(&ctx.app, Method::GET, "/api/ui/dashboard", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    for mp in json["mount_points"].as_array().unwrap() {
        assert!(
            mp["proxy_upstreams"].as_array().unwrap().is_empty(),
            "anonymous must see empty proxy_upstreams"
        );
    }

    // Valid Basic creds htpasswd has not checked yet: the open path runs no bcrypt,
    // so the caller browses as anonymous.
    let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));
    let dashboard = || {
        send_with_headers(
            &ctx.app,
            Method::GET,
            "/api/ui/dashboard",
            vec![("authorization", &header_val)],
            "",
        )
    };
    let npm_upstreams = |json: serde_json::Value| {
        json["mount_points"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["registry"].as_str() == Some("npm"))
            .expect("npm mount")["proxy_upstreams"]
            .as_array()
            .unwrap()
            .len()
    };
    let resp = dashboard().await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert_eq!(
        npm_upstreams(json),
        0,
        "unchecked credentials are anonymous"
    );

    // A gated page checks them (a browser sends them after its challenge); from then on
    // the open surface knows the caller: proxy_upstreams populated.
    let resp = send_with_headers(
        &ctx.app,
        Method::GET,
        "/api/ui/tokens",
        vec![("authorization", &header_val)],
        "",
    )
    .await;
    assert_ne!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = dashboard().await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let npm = json["mount_points"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["registry"].as_str() == Some("npm"))
        .expect("npm mount");
    assert!(
        !npm["proxy_upstreams"].as_array().unwrap().is_empty(),
        "authenticated must see populated proxy_upstreams for npm"
    );
}

/// On an open web surface, invalid Basic credentials fall through to
/// anonymous (the path is open — no 401).
#[tokio::test]
async fn test_opportunistic_bad_creds_fall_through_to_anonymous() {
    let ctx = create_test_context_with_anonymous_read(&[("admin", "secret")]);

    let bad = format!("Basic {}", STANDARD.encode("admin:wrong"));
    let resp = send_with_headers(
        &ctx.app,
        Method::GET,
        "/api/ui/dashboard",
        vec![("authorization", &bad)],
        "",
    )
    .await;
    // Open path — no 401 even with bad creds
    assert_eq!(resp.status(), StatusCode::OK);
}

/// On an open web surface, a valid Bearer token must produce a real
/// AuthenticatedUser, enabling proxy_upstreams disclosure.
#[tokio::test]
async fn test_opportunistic_bearer_auth_on_open_surface() {
    let ctx = create_test_context_with_anonymous_read_and_config(&[("admin", "secret")], |c| {
        c.npm.proxy = Some("https://registry.npmjs.org".into());
    });

    let token = ctx
        .state
        .tokens
        .as_ref()
        .unwrap()
        .create_token("admin", 30, None, crate::tokens::Role::Write)
        .await
        .unwrap();

    let header_val = format!("Bearer {token}");
    let resp = send_with_headers(
        &ctx.app,
        Method::GET,
        "/api/ui/dashboard",
        vec![("authorization", &header_val)],
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let npm = json["mount_points"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["registry"].as_str() == Some("npm"))
        .expect("npm mount");
    assert!(
        !npm["proxy_upstreams"].as_array().unwrap().is_empty(),
        "bearer-authenticated must see populated proxy_upstreams"
    );
}

/// Captures the formatted log of the current thread (tokio::test is single-threaded).
#[derive(Clone, Default)]
struct LogSink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogSink {
    type Writer = LogSink;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl LogSink {
    fn install(&self) -> tracing::subscriber::DefaultGuard {
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(self.clone())
            .with_max_level(tracing::Level::WARN)
            .finish();
        tracing::subscriber::set_default(subscriber)
    }
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

async fn get_with_auth(ctx: &crate::test_helpers::TestContext, auth: &str) -> StatusCode {
    send_with_headers(
        &ctx.app,
        Method::GET,
        "/raw/test.txt",
        vec![("authorization", auth)],
        "",
    )
    .await
    .status()
}

/// A refused credential is logged with its client, kind and reason, and the
/// secret itself (password, nra_ token, JWT) never reaches the log.
#[tokio::test]
async fn rejected_credentials_are_logged_without_the_secret() {
    let ctx = create_test_context_with_auth(&[("admin", "secret")]);
    let sink = LogSink::default();
    let _guard = sink.install();
    let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJjYW5hcnktc3ViIn0.c2lnbmF0dXJlLWNhbmFyeQ"; // gitleaks:allow (made-up token)
    let basic = |p: &str| format!("Basic {}", STANDARD.encode(format!("admin:{p}")));
    let tried = [
        (basic("canary-pass-1"), "basic_htpasswd", "wrong_password"),
        (
            basic("nra_canarytoken0000000000000000"),
            "basic_nra",
            "token_invalid",
        ),
        (
            "Bearer nra_canarytoken1111111111111111".to_string(),
            "bearer_nra",
            "token_invalid",
        ),
        (format!("Bearer {jwt}"), "bearer_jwt", "no_oidc"),
        ("Digest canary-digest".to_string(), "malformed", "malformed"),
    ];
    for (auth, kind, reason) in &tried {
        assert_eq!(get_with_auth(&ctx, auth).await, StatusCode::UNAUTHORIZED);
        let out = sink.text();
        let line = out
            .lines()
            .rfind(|l| l.contains("auth rejected: credential refused"))
            .unwrap_or_else(|| panic!("{kind}: no rejection logged in {out}"));
        assert!(line.contains(&format!(r#""kind":"{kind}""#)), "{line}");
        assert!(line.contains(&format!(r#""reason":"{reason}""#)), "{line}");
        assert!(line.contains(r#""client_ip":"127.0.0.1""#), "{line}");
    }
    let out = sink.text();
    for secret in ["canary", "nra_", "eyJ", "c2lnbmF0dXJl", "Basic ", "Bearer "] {
        assert!(!out.contains(secret), "{secret} leaked: {out}");
    }
}

/// The anonymous round of the NuGet/Docker challenge (no Authorization) is half
/// of all traffic: answered 401, never logged.
#[tokio::test]
async fn anonymous_challenge_is_not_logged() {
    let ctx = create_test_context_with_auth(&[("admin", "secret")]);
    let sink = LogSink::default();
    let _guard = sink.install();
    let response = send(&ctx.app, Method::GET, "/raw/test.txt", "").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(sink.text(), "");
}

/// One lockout: one WARN at its start, one for its refusals, however many 429s.
#[tokio::test]
async fn lockout_refusals_are_logged_once() {
    let ctx = create_test_context_with_auth(&[("admin", "secret")]);
    let sink = LogSink::default();
    let _guard = sink.install();
    let wrong = format!("Basic {}", STANDARD.encode("admin:wrong"));
    for _ in 0..5 {
        assert_eq!(get_with_auth(&ctx, &wrong).await, StatusCode::UNAUTHORIZED);
    }
    for _ in 0..3 {
        assert_eq!(
            get_with_auth(&ctx, &wrong).await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }
    let out = sink.text();
    assert_eq!(out.matches("auth lockout:").count(), 1, "{out}");
    assert_eq!(out.matches(r#""reason":"locked_out""#).count(), 1, "{out}");
    assert_eq!(
        out.matches(r#""reason":"wrong_password""#).count(),
        5,
        "{out}"
    );
}
