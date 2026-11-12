// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::test_helpers::*;
use axum::http::{Method, StatusCode};
use base64::{engine::general_purpose::STANDARD, Engine};

#[tokio::test]
async fn test_auth_disabled_passes_all() {
    let ctx = create_test_context();
    let response = send(&ctx.app, Method::PUT, "/raw/test.txt", b"data".to_vec()).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_auth_public_paths_always_pass() {
    let ctx = create_test_context_with_auth(&[("admin", "secret")]);
    // The storage verdict the maintenance loop's first tick takes.
    ctx.state.storage.refresh_reachability().await;
    let response = send(&ctx.app, Method::GET, "/health", "").await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = send(&ctx.app, Method::GET, "/ready", "").await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// Docker Registry V2 spec: GET /v2/ without credentials must return 401
/// with WWW-Authenticate header when auth is enabled (issue #219)
#[tokio::test]
async fn test_docker_v2_requires_auth_when_enabled() {
    let ctx = create_test_context_with_auth(&[("admin", "secret")]);

    // Without credentials: must return 401 + WWW-Authenticate
    let response = send(&ctx.app, Method::GET, "/v2/", "").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().contains_key("www-authenticate"));

    // With valid credentials: must return 200
    let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));
    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/v2/",
        vec![("authorization", &header_val)],
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// Docker /v2/ must NOT pass through anonymous_read bypass.
/// Even with anonymous_read=true, /v2/ must require auth so Docker
/// clients know to send credentials on subsequent push/pull requests.
#[tokio::test]
async fn test_docker_v2_ignores_anonymous_read() {
    let ctx = create_test_context_with_anonymous_read(&[("admin", "secret")]);

    // /v2/ without auth: must still return 401 even with anonymous_read=true
    let response = send(&ctx.app, Method::GET, "/v2/", "").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().contains_key("www-authenticate"));

    // Other read endpoints should still work anonymously
    let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));
    let response = send_with_headers(
        &ctx.app,
        Method::PUT,
        "/raw/test.txt",
        vec![("authorization", &header_val)],
        b"data".to_vec(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = send(&ctx.app, Method::GET, "/raw/test.txt", "").await;
    assert_eq!(response.status(), StatusCode::OK);
}

// --- #778: anonymous Docker pull via the `docker_anon_pull` opt-in ---

/// docker_anon_pull=true: the `GET /v2/` ping is served anonymously
/// (200, no challenge) so the Docker client proceeds without credentials.
#[tokio::test]
async fn test_docker_anon_pull_allows_v2_ping() {
    let ctx = create_test_context_with_docker_anon_pull(&[("admin", "secret")]);
    let response = send(&ctx.app, Method::GET, "/v2/", "").await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// docker_anon_pull=true: an anonymous manifest read passes the auth
/// gate and reaches the handler (404 for a missing tag, NOT 401).
#[tokio::test]
async fn test_docker_anon_pull_allows_manifest_read() {
    let ctx = create_test_context_with_docker_anon_pull(&[("admin", "secret")]);
    let response = send(&ctx.app, Method::GET, "/v2/alpine/manifests/latest", "").await;
    assert_ne!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "anonymous manifest read must pass the auth gate under docker_anon_pull"
    );
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// docker_anon_pull=true: writes are not read methods → still require
/// auth. The Docker handler does not self-check role, so the middleware is
/// the only write-stop — anonymous push/delete MUST be rejected.
#[tokio::test]
async fn test_docker_anon_pull_blocks_anonymous_writes() {
    let ctx = create_test_context_with_docker_anon_pull(&[("admin", "secret")]);

    // Start a blob upload (push) anonymously -> 401.
    let response = send(&ctx.app, Method::POST, "/v2/alpine/blobs/uploads/", "").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Push a manifest anonymously -> 401.
    let response = send(
        &ctx.app,
        Method::PUT,
        "/v2/alpine/manifests/latest",
        b"{}".to_vec(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Delete a manifest anonymously -> 401.
    let response = send(
        &ctx.app,
        Method::DELETE,
        "/v2/alpine/manifests/sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// docker_anon_pull=true must NOT break authenticated push: a write with
/// valid credentials starts the upload (202), exactly as without the flag.
#[tokio::test]
async fn test_docker_anon_pull_authenticated_push_still_works() {
    let ctx = create_test_context_with_docker_anon_pull(&[("admin", "secret")]);
    let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));
    let response = send_with_headers(
        &ctx.app,
        Method::POST,
        "/v2/alpine/blobs/uploads/",
        vec![("authorization", &header_val)],
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

/// docker_anon_pull=true: `/v2/_catalog` stays authenticated — anonymous
/// repository enumeration is not part of anonymous pull-by-name.
#[tokio::test]
async fn test_docker_anon_pull_catalog_requires_auth() {
    let ctx = create_test_context_with_docker_anon_pull(&[("admin", "secret")]);

    let response = send(&ctx.app, Method::GET, "/v2/_catalog", "").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));
    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/v2/_catalog",
        vec![("authorization", &header_val)],
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// docker_anon_pull=true: presented credentials are still validated —
/// the anonymous bypass applies only when no Authorization header is sent.
/// Wrong creds on the `/v2/` ping return 401 (honest `docker login`).
#[tokio::test]
async fn test_docker_anon_pull_validates_presented_credentials() {
    let ctx = create_test_context_with_docker_anon_pull(&[("admin", "secret")]);

    let bad = format!("Basic {}", STANDARD.encode("admin:wrong"));
    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/v2/",
        vec![("authorization", &bad)],
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let good = format!("Basic {}", STANDARD.encode("admin:secret"));
    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/v2/",
        vec![("authorization", &good)],
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// The general `anonymous_read` switch must NOT open Docker (#778): with
/// anonymous_read=true but docker_anon_pull=false, Docker `/v2` paths
/// still require auth, so exposing Maven/raw never exposes images.
#[tokio::test]
async fn test_anonymous_read_does_not_open_docker() {
    let ctx = create_test_context_with_anonymous_read(&[("admin", "secret")]);

    // /v2/ ping still challenges.
    let response = send(&ctx.app, Method::GET, "/v2/", "").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Manifest read still requires auth — the general flag does not open Docker.
    let response = send(&ctx.app, Method::GET, "/v2/alpine/manifests/latest", "").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// When auth is disabled, /v2/ should pass through normally
#[tokio::test]
async fn test_docker_v2_passes_when_auth_disabled() {
    let ctx = create_test_context();
    let response = send(&ctx.app, Method::GET, "/v2/", "").await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_auth_blocks_without_credentials() {
    let ctx = create_test_context_with_auth(&[("admin", "secret")]);
    let response = send(&ctx.app, Method::PUT, "/raw/test.txt", b"data".to_vec()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().contains_key("www-authenticate"));
}

#[tokio::test]
async fn test_auth_basic_works() {
    let ctx = create_test_context_with_auth(&[("admin", "secret")]);
    let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));
    let response = send_with_headers(
        &ctx.app,
        Method::PUT,
        "/raw/test.txt",
        vec![("authorization", &header_val)],
        b"data".to_vec(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_auth_basic_wrong_password() {
    let ctx = create_test_context_with_auth(&[("admin", "secret")]);
    let header_val = format!("Basic {}", STANDARD.encode("admin:wrong"));
    let response = send_with_headers(
        &ctx.app,
        Method::PUT,
        "/raw/test.txt",
        vec![("authorization", &header_val)],
        b"data".to_vec(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// R2-48: the lockout is per client IP and username, and never refuses a Bearer
/// credential. Five wrong passwords for alice lock out alice only; bob behind the
/// same IP and a valid API token from it still authenticate (404 = past auth).
#[tokio::test]
async fn test_lockout_is_per_user_and_skips_bearer() {
    let ctx = create_test_context_with_auth(&[("alice", "pw-a"), ("bob", "pw-b")]);
    let get = |auth: String| {
        let app = &ctx.app;
        async move {
            send_with_headers(
                app,
                Method::GET,
                "/raw/missing.txt",
                vec![("authorization", &auth)],
                "",
            )
            .await
            .status()
        }
    };
    let basic = |cred: &str| format!("Basic {}", STANDARD.encode(cred));
    for _ in 0..5 {
        assert_eq!(get(basic("alice:wrong")).await, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(
        get(basic("alice:pw-a")).await,
        StatusCode::TOO_MANY_REQUESTS,
        "alice is locked out, even with her password"
    );
    assert_eq!(get(basic("bob:pw-b")).await, StatusCode::NOT_FOUND);
    let token = ctx
        .state
        .tokens
        .as_ref()
        .unwrap()
        .create_token("ci", 30, None, crate::tokens::Role::Write)
        .await
        .unwrap();
    for _ in 0..10 {
        assert_eq!(
            get("Bearer nra_stale".to_string()).await,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(get(format!("Bearer {token}")).await, StatusCode::NOT_FOUND);
    assert_eq!(
        get(basic(&format!("ci:{token}"))).await,
        StatusCode::NOT_FOUND
    );
}

/// #736: an API token presented as the Basic-auth password (any username) must
/// authenticate — Docker/twine/Maven send the token as the Basic password and never
/// use Bearer, so without this the documented `docker login -u token -p nra_…` fails.
#[tokio::test]
async fn test_basic_auth_accepts_api_token() {
    let ctx = create_test_context_with_auth(&[("admin", "secret")]);
    let token = ctx
        .state
        .tokens
        .as_ref()
        .unwrap()
        .create_token("admin", 30, None, crate::tokens::Role::Write)
        .await
        .unwrap();
    // Docker sends Basic base64("<user>:<token>"); the username is ignored.
    let header_val = format!("Basic {}", STANDARD.encode(format!("token:{token}")));
    let response = send_with_headers(
        &ctx.app,
        Method::PUT,
        "/raw/test.txt",
        vec![("authorization", &header_val)],
        b"data".to_vec(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// #736: a read-only API token as the Basic-auth password must be rejected for writes,
/// matching the Bearer path's role gate.
#[tokio::test]
async fn test_basic_auth_read_only_token_cannot_write() {
    let ctx = create_test_context_with_auth(&[("admin", "secret")]);
    let token = ctx
        .state
        .tokens
        .as_ref()
        .unwrap()
        .create_token("admin", 30, None, crate::tokens::Role::Read)
        .await
        .unwrap();
    let header_val = format!("Basic {}", STANDARD.encode(format!("token:{token}")));
    let response = send_with_headers(
        &ctx.app,
        Method::PUT,
        "/raw/test.txt",
        vec![("authorization", &header_val)],
        b"data".to_vec(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// The storage key of a token's record.
fn token_key(token: &str) -> String {
    use sha2::Digest;
    let prefix = hex::encode(sha2::Sha256::digest(token.as_bytes()));
    format!("{}{}.json", crate::tokens::STORAGE_PREFIX, &prefix[..16])
}

async fn put_token_record(ctx: &crate::test_helpers::TestContext, token: &str, body: &[u8]) {
    ctx.state
        .storage
        .put(&token_key(token), body)
        .await
        .unwrap();
}

/// A token-store read failure (torn/corrupt file, I/O error) is an outage,
/// not a credential verdict: Basic auth with a valid-format token must
/// answer 503 (retryable), never 401 — a 401 makes valid creds flap and
/// walks the per-IP failure tracker toward lockout for the duration of a
/// storage blip. Regression for the 2026-08 same-creds 200↔401 flap.
#[tokio::test]
async fn test_basic_auth_token_store_error_returns_503_not_401() {
    let ctx = create_test_context_with_auth(&[("admin", "secret")]);
    let token = ctx
        .state
        .tokens
        .as_ref()
        .unwrap()
        .create_token("ci", 30, None, crate::tokens::Role::Read)
        .await
        .unwrap();
    // Corrupt the file the way a torn in-place rewrite would. The token was
    // never verified, so the in-memory cache is cold and the disk is read.
    put_token_record(&ctx, &token, b"{\"token_ha").await;

    let header_val = format!("Basic {}", STANDARD.encode(format!("ci:{token}")));
    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/raw/test.txt",
        vec![("authorization", &header_val)],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

/// Same rule on the Bearer path: an `nra_` token that cannot be verified
/// because the store read failed must 503, not fall through to OIDC and 401.
#[tokio::test]
async fn test_bearer_token_store_error_returns_503_not_401() {
    let ctx = create_test_context_with_auth(&[("admin", "secret")]);
    let token = ctx
        .state
        .tokens
        .as_ref()
        .unwrap()
        .create_token("ci", 30, None, crate::tokens::Role::Read)
        .await
        .unwrap();
    put_token_record(&ctx, &token, b"{\"token_ha").await;

    let header_val = format!("Bearer {token}");
    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/raw/test.txt",
        vec![("authorization", &header_val)],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

/// htpasswd is verified BEFORE the token store: when both exist, a password
/// that merely *looks* like an API token (`nra_…`) authenticates against
/// htpasswd and never reaches token verification. The order has held since
/// #736 (htpasswd first, token on fallback), but no test pinned it — an
/// acceptance mutant that tried the token store first survived the #1094 net
/// (M12). Without the order a token-store blip would turn a valid htpasswd
/// login into a 503, and an htpasswd password that collided with a live token
/// would borrow the token's role and owner instead of the htpasswd identity.
/// Correct order: htpasswd matches, store never read → 200. Token-first: the
/// corrupt token file is read → Storage error → 503.
#[tokio::test]
async fn test_basic_auth_htpasswd_checked_before_token_store() {
    // htpasswd user whose password is shaped like an `nra_` token, so a
    // token-first order would try to verify it against the store.
    let ctx = create_test_context_with_auth(&[("svc", "nra_witness")]);
    assert!(ctx.state.auth.is_some(), "htpasswd provider present");
    assert!(ctx.state.tokens.is_some(), "token store present");
    // Corrupt the file the store would read for this password: reaching it at
    // all yields a Storage error (→503). htpasswd-first never reads it.
    put_token_record(&ctx, "nra_witness", b"{\"token_ha").await;

    let header_val = basic_header("svc", "nra_witness");
    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/v2/",
        vec![("authorization", &header_val)],
        Vec::new(),
    )
    .await;
    // htpasswd matched first → authenticated; the token store was never
    // consulted, so the corrupt file never mattered.
    assert_eq!(response.status(), StatusCode::OK);
}

/// Write a legacy token file (unsalted SHA-256 hash) for `token`: the first
/// time the store reads it, it rewrites the file with an Argon2 hash.
async fn write_legacy_token(ctx: &crate::test_helpers::TestContext, token: &str, owner: &str) {
    use sha2::Digest;
    let info = serde_json::json!({
        "token_hash": hex::encode(sha2::Sha256::digest(token.as_bytes())),
        "user": owner,
        "created_at": 0,
        "expires_at": u64::MAX,
        "last_used": null,
        "description": null,
        "role": "admin",
    });
    put_token_record(ctx, token, info.to_string().as_bytes()).await;
}

async fn token_file_migrated(ctx: &crate::test_helpers::TestContext, token: &str) -> bool {
    let record = ctx.state.storage.get(&token_key(token)).await.unwrap();
    String::from_utf8_lossy(&record).contains("$argon2")
}

/// htpasswd matched → the token store is not read at all, not even for a
/// result that is then thrown away (H4), and the identity is the htpasswd
/// user (H3). The password is a live admin token of another owner, kept as a
/// legacy file: any store read migrates it to Argon2, so a file still legacy
/// after the requests was never read. The control token proves the witness:
/// one store read migrates its file.
#[tokio::test]
async fn test_basic_auth_htpasswd_match_never_reads_token_store() {
    let ctx = create_test_context_with_auth(&[("svc", "nra_witness")]);
    write_legacy_token(&ctx, "nra_witness", "token-owner").await;
    write_legacy_token(&ctx, "nra_control", "token-owner").await;
    let store = ctx.state.tokens.as_ref().unwrap();
    assert_eq!(
        store.verify_token("nra_control").await.unwrap().0,
        "token-owner"
    );
    assert!(
        token_file_migrated(&ctx, "nra_control").await,
        "witness control"
    );

    let header_val = basic_header("svc", "nra_witness");
    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/npm/-/whoami",
        vec![("authorization", &header_val)],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
    assert_eq!(json["username"], "svc");

    // The token is admin; the htpasswd identity is not.
    let response = send_with_headers(
        &ctx.app,
        Method::POST,
        "/api/v1/admin/tokens",
        vec![
            ("authorization", &header_val),
            ("content-type", "application/json"),
        ],
        br#"{"username":"x","ttl_days":1,"role":"read"}"#.to_vec(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    assert!(
        !token_file_migrated(&ctx, "nra_witness").await,
        "htpasswd matched, yet the token store read the password's token file"
    );
}

/// bcrypt verifications the context's htpasswd provider has run.
fn bcrypt_runs(ctx: &crate::test_helpers::TestContext) -> usize {
    ctx.state
        .auth
        .as_ref()
        .unwrap()
        .bcrypt_runs
        .load(std::sync::atomic::Ordering::SeqCst)
}

/// Every route path the server registers, its parameters filled in: read from the
/// `.route("…")` calls of the sources, so a route added later is in it as well.
fn every_route_path() -> Vec<String> {
    fn sources(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                sources(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let mut files = Vec::new();
    sources(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    let mut paths = std::collections::BTreeSet::new();
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        for (at, _) in text.match_indices(".route(") {
            let rest = text[at + ".route(".len()..].trim_start();
            let Some(rest) = rest.strip_prefix('"') else {
                continue;
            };
            let template = &rest[..rest.find('"').unwrap()];
            let mut path = String::new();
            for segment in template.split('/').skip(1) {
                path.push('/');
                path.push_str(match segment {
                    s if s.starts_with("{*") => "a/b",
                    s if s.starts_with('{') => "x",
                    s => s,
                });
            }
            paths.insert(if path.is_empty() { "/".into() } else { path });
        }
    }
    paths.into_iter().collect()
}

/// No route served without credentials pays bcrypt for a Basic header it carries,
/// right or wrong: the probes, `/`, the public `/metrics`, the web surface and the
/// registry reads under `anonymous_read`, every method. Which routes are open is what
/// the server answers without credentials, not a list kept here; only the gated ones
/// check htpasswd credentials.
#[tokio::test]
async fn an_open_path_never_runs_bcrypt() {
    let ctx = create_test_context_with_anonymous_read_and_config(&[("admin", "secret")], |c| {
        c.auth.public_metrics = true
    });
    let routes = every_route_path();
    assert!(routes.len() > 100, "{} routes read", routes.len());
    let methods = [
        Method::GET,
        Method::HEAD,
        Method::POST,
        Method::PUT,
        Method::PATCH,
        Method::DELETE,
    ];
    let mut open = Vec::new();
    for path in &routes {
        for method in &methods {
            let status = send(&ctx.app, method.clone(), path, Vec::new())
                .await
                .status();
            if status != StatusCode::UNAUTHORIZED && status != StatusCode::FORBIDDEN {
                open.push((method.clone(), path.as_str()));
            }
        }
    }
    for served in [
        "/",
        "/health",
        "/ready",
        "/metrics",
        "/ui/",
        "/api/ui/dashboard",
        "/api-docs/openapi.json",
        "/raw/a/b",
    ] {
        assert!(
            open.contains(&(Method::GET, served)),
            "{served} is served without credentials"
        );
    }
    assert_eq!(bcrypt_runs(&ctx), 0);
    for creds in ["admin:wrong", "admin:secret"] {
        let header_val = format!("Basic {}", STANDARD.encode(creds));
        for (method, path) in &open {
            let response = send_with_headers(
                &ctx.app,
                method.clone(),
                path,
                vec![("authorization", &header_val)],
                Vec::new(),
            )
            .await;
            assert_ne!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {path}"
            );
        }
        assert_eq!(bcrypt_runs(&ctx), 0, "an open path ran bcrypt ({creds})");
    }
    // The counter counts: a gated path checks the same header.
    let header_val = format!("Basic {}", STANDARD.encode("admin:wrong"));
    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/npm/-/whoami",
        vec![("authorization", &header_val)],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(bcrypt_runs(&ctx), 1);
}

/// Under every combination of the switches that open routes without credentials
/// (`anonymous_read`, `public_web_ui`, `public_metrics`, `docker_anon_pull`), a route
/// served without credentials pays no bcrypt for a Basic header it carries, right or
/// wrong, whatever the method. The one exception is the Docker API under
/// `docker_anon_pull`, whose answer depends on who asks: credentials it is given are
/// checked, under the lockout. Which routes are open is what the server answers without
/// credentials; a gated one shows the counter counts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_switch_makes_a_route_served_without_credentials_run_bcrypt() {
    let routes = std::sync::Arc::new(every_route_path());
    let configs = (0..16u8).map(|bits| {
        let routes = std::sync::Arc::clone(&routes);
        let config = tokio::spawn(async move {
            let switches = [bits & 1 != 0, bits & 2 != 0, bits & 4 != 0, bits & 8 != 0];
            let [anonymous_read, public_web_ui, public_metrics, docker_anon_pull] = switches;
            let ctx = create_test_context_with_auth_and_config(&[("admin", "secret")], |c| {
                c.auth.anonymous_read = anonymous_read;
                c.auth.public_web_ui = public_web_ui;
                c.auth.public_metrics = public_metrics;
                c.auth.docker_anon_pull = docker_anon_pull;
            });
            let mut open = Vec::new();
            for path in routes.iter() {
                if docker_anon_pull && super::is_docker_path(path) {
                    continue;
                }
                for method in [
                    Method::GET,
                    Method::HEAD,
                    Method::POST,
                    Method::PUT,
                    Method::PATCH,
                    Method::DELETE,
                ] {
                    let status = send(&ctx.app, method.clone(), path, Vec::new())
                        .await
                        .status();
                    if status != StatusCode::UNAUTHORIZED && status != StatusCode::FORBIDDEN {
                        open.push((method, path.clone()));
                    }
                }
            }
            for always in ["/health", "/ready", "/"] {
                assert!(
                    open.contains(&(Method::GET, always.to_owned())),
                    "{switches:?}: {always} is served without credentials"
                );
            }
            for creds in ["admin:wrong", "admin:secret"] {
                let header_val = format!("Basic {}", STANDARD.encode(creds));
                for (method, path) in &open {
                    send_with_headers(
                        &ctx.app,
                        method.clone(),
                        path,
                        vec![("authorization", &header_val)],
                        Vec::new(),
                    )
                    .await;
                    assert_eq!(
                        bcrypt_runs(&ctx),
                        0,
                        "{switches:?}: {method} {path} ran bcrypt ({creds})"
                    );
                }
            }
            let header_val = format!("Basic {}", STANDARD.encode("admin:wrong"));
            let response = send_with_headers(
                &ctx.app,
                Method::GET,
                "/npm/-/whoami",
                vec![("authorization", &header_val)],
                Vec::new(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{switches:?}");
            assert_eq!(bcrypt_runs(&ctx), 1, "{switches:?}: the counter counts");
        });
        config
    });
    for config in futures::future::join_all(configs).await {
        config.unwrap();
    }
}

/// A CI job whose Basic username is an htpasswd user and whose password is an
/// API token pays bcrypt once, not on every request; it still authenticates as the
/// token's owner each time.
#[tokio::test]
async fn basic_with_an_api_token_pays_bcrypt_once() {
    let ctx = create_test_context_with_auth(&[("alice", "alicepw")]);
    let token = mint(&ctx, crate::tokens::Role::Read).await;
    let header_val = basic_header("alice", &token);
    for _ in 0..5 {
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/npm/-/whoami",
            vec![("authorization", &header_val)],
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(json["username"], TOKEN_OWNER);
    }
    assert_eq!(bcrypt_runs(&ctx), 1);
}

/// The same for a valid htpasswd login: one bcrypt, then the verdict is remembered.
#[tokio::test]
async fn a_valid_htpasswd_login_pays_bcrypt_once() {
    let ctx = create_test_context_with_auth(&[("alice", "alicepw")]);
    let header_val = basic_header("alice", "alicepw");
    for _ in 0..5 {
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/npm/-/whoami",
            vec![("authorization", &header_val)],
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }
    assert_eq!(bcrypt_runs(&ctx), 1);
}

/// Bcrypt does not run on an async worker. On a one-thread runtime a probe sent
/// while a Basic login is being checked against a slow hash answers at once, instead
/// of after the hash.
#[tokio::test]
async fn a_probe_is_not_held_up_by_a_bcrypt_check() {
    use std::time::{Duration, Instant};
    let ctx = create_test_context_with_auth(&[("alice", "alicepw")]);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("htpasswd");
    let hash = bcrypt::hash("slowpw", 10).unwrap();
    std::fs::write(&path, format!("slow:{hash}\n")).unwrap();
    let started = Instant::now();
    assert!(!bcrypt::verify("wrong", &hash).unwrap());
    let one_check = started.elapsed();
    assert!(one_check >= Duration::from_millis(20), "{one_check:?}");

    let mut state = ctx.state.clone();
    state.auth = Some(std::sync::Arc::new(
        super::HtpasswdAuth::from_file(&path).unwrap(),
    ));
    // The probe is the open path `/` with no I/O of its own (`/health` fsyncs a probe
    // file, which under a loaded disk takes long enough to blur the measure).
    let routes = axum::Router::new()
        .route("/raw/x", axum::routing::get(|| async { "x" }))
        .route("/", axum::routing::get(|| async { "probe" }));
    let app = crate::request_layers(routes, &state).with_state(state);

    // One thread: the login is polled first. Checked on this thread, its bcrypt runs
    // before the probe is polled at all, and the probe's time since t0 includes it.
    let header_val = basic_header("slow", "wrong");
    let t0 = Instant::now();
    let (login, (probe, probe_took)) = tokio::join!(
        send_with_headers(
            &app,
            Method::GET,
            "/raw/x",
            vec![("authorization", &header_val)],
            Vec::new(),
        ),
        async {
            let response = send_with_headers(&app, Method::GET, "/", vec![], Vec::new()).await;
            (response.status(), t0.elapsed())
        }
    );
    assert_eq!(login.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(probe, StatusCode::OK);
    assert!(
        probe_took < one_check / 2,
        "the probe waited for bcrypt: {probe_took:?} (one check {one_check:?})"
    );
}

/// R4-C09: `public_metrics = false` closes /metrics to everything but real
/// credentials. `anonymous_read` opens registry reads, not metrics, whatever
/// Authorization header the request carries.
#[tokio::test]
async fn anonymous_read_does_not_open_closed_metrics() {
    let ctx = create_test_context_with_auth_and_config(&[("admin", "secret")], |c| {
        c.auth.anonymous_read = true;
        c.auth.public_metrics = false;
    });
    let get = |authorization: Option<String>| {
        let app = ctx.app.clone();
        async move {
            let headers: Vec<(&str, &str)> = authorization
                .as_deref()
                .map(|value| ("authorization", value))
                .into_iter()
                .collect();
            send_with_headers(&app, Method::GET, "/metrics", headers, Vec::new())
                .await
                .status()
        }
    };
    assert_eq!(get(None).await, StatusCode::UNAUTHORIZED);
    for bogus in [
        basic_header("x", "y"),
        "Bearer nra_0123456789abcdef0123456789abcdef".to_owned(),
        "Bearer not-a-token".to_owned(),
        "Negotiate abc".to_owned(),
    ] {
        assert_eq!(
            get(Some(bogus.clone())).await,
            StatusCode::UNAUTHORIZED,
            "{bogus}"
        );
    }
    assert_eq!(
        get(Some(basic_header("admin", "secret"))).await,
        StatusCode::OK
    );
}

/// R4-C18: `/` and the static assets sit behind no rate limiter and their handlers
/// use no identity, so a token sent there is not looked up in storage. A gated path
/// shows the counter counts.
#[tokio::test]
async fn a_token_on_the_unlimited_open_paths_costs_no_storage_read() {
    use sha2::{Digest, Sha256};
    let ctx = create_test_context_with_auth(&[("alice", "alicepw")]);
    let (storage, counts) = op_counting_storage();
    let mut state = ctx.state.clone();
    state.tokens = Some(crate::tokens::TokenStore::new(storage));
    let routes = axum::Router::new()
        .route("/raw/x", axum::routing::get(|| async { "x" }))
        .route(
            "/ui/static/htmx.min.js",
            axum::routing::get(|| async { "js" }),
        )
        .route("/", axum::routing::get(|| async { "root" }));
    let app = crate::request_layers(routes, &state).with_state(state);

    // A made-up token no store holds, spelled so that no secret scanner reads a key.
    let token = &format!("nra_{}", "0123456789abcdef".repeat(2));
    let id = hex::encode(Sha256::digest(token.as_bytes()));
    let record = format!("{}{}.json", crate::tokens::STORAGE_PREFIX, &id[..16]);
    for authorization in [format!("Bearer {token}"), basic_header("ci", token)] {
        for path in ["/", "/ui/static/htmx.min.js"] {
            let response = send_with_headers(
                &app,
                Method::GET,
                path,
                vec![("authorization", &authorization)],
                Vec::new(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(
                counts.calls("get", &record),
                0,
                "{path} read the token store"
            );
        }
    }
    let authorization = format!("Bearer {token}");
    let response = send_with_headers(
        &app,
        Method::GET,
        "/raw/x",
        vec![("authorization", &authorization)],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(counts.calls("get", &record), 1, "the counter counts");
}

/// R4-C17: a revoke that cannot reach the store answers 503, never "Token not
/// found": the record is still there and the token still works.
#[tokio::test]
async fn revoke_answers_503_while_the_store_is_down() {
    use axum::extract::ConnectInfo;
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;
    let ctx = create_test_context_with_auth(&[("alice", "alicepw")]);
    let (storage, outage) = outage_storage();
    let store = crate::tokens::TokenStore::new(storage);
    let token = store
        .create_token("alice", 30, None, crate::tokens::Role::Read)
        .await
        .unwrap();
    let id = hex::encode(Sha256::digest(token.as_bytes()));
    let mut state = ctx.state.clone();
    state.tokens = Some(store.clone());
    let app = crate::request_layers(super::token_routes::token_routes(), &state).with_state(state);
    let revoke = || {
        let body = format!(
            r#"{{"username":"alice","password":"alicepw","hash_prefix":"{}"}}"#,
            &id[..16]
        );
        let mut request = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/api/tokens/revoke")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body))
            .unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                4000,
            ))));
        app.clone().oneshot(request)
    };

    outage.begin();
    assert_eq!(
        revoke().await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    outage.end();
    assert!(store.verify_token(&token).await.is_ok(), "still valid");
    assert_eq!(revoke().await.unwrap().status(), StatusCode::OK);
    assert_eq!(revoke().await.unwrap().status(), StatusCode::NOT_FOUND);
    assert!(store.verify_token(&token).await.is_err());
}

/// A password sent for a locked-out username is refused unchecked, so it
/// is not a wrong password and counts neither for the username nor toward
/// the address ceiling: however many arrive, another username behind the
/// same address still logs in.
#[tokio::test]
async fn an_unchecked_password_counts_for_nobody() {
    let ctx = create_test_context_with_auth(&[("alice", "alicepw"), ("bob", "bobpw")]);
    let tracker = &ctx.state.auth_failures;
    let ip = CLIENT_IP;
    for _ in 0..5 {
        tracker.record_failure(ip, "alice");
    }
    assert!(tracker.check_blocked(&ip, "alice").is_some());
    for _ in 0..60 {
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/v2/",
            vec![("authorization", &basic_header("alice", "guess"))],
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }
    assert!(
        tracker.check_blocked(&ip, "bob").is_none(),
        "passwords refused unchecked were counted toward the address ceiling"
    );
    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/v2/",
        vec![("authorization", &basic_header("bob", "bobpw"))],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// Auth enabled with no htpasswd file — the OIDC-only setup (#996). The
/// token store is there, as main.rs always creates it when auth is enabled.
fn create_test_context_without_htpasswd() -> crate::test_helpers::TestContext {
    let ctx = create_test_context_with_auth(&[]);
    assert!(ctx.state.auth.is_none(), "no htpasswd provider");
    assert!(ctx.state.tokens.is_some(), "token store present");
    ctx
}

/// Owner of the tokens `mint` creates. The Basic username the tests send
/// (`docker`) differs, so a request attributed to the Basic username
/// instead of the token's owner shows.
const TOKEN_OWNER: &str = "ci-bot";

async fn mint(ctx: &crate::test_helpers::TestContext, role: crate::tokens::Role) -> String {
    ctx.state
        .tokens
        .as_ref()
        .unwrap()
        .create_token(TOKEN_OWNER, 30, None, role)
        .await
        .unwrap()
}

fn basic_header(user: &str, pass: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{user}:{pass}")))
}

/// The test client's address (`send_with_headers` connects from it).
const CLIENT_IP: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

/// The Basic username these tests send with an API token as the password.
const BASIC_USER: &str = "docker";

/// Record failures for the test client's `BASIC_USER` up to one short of
/// lockout: the test tracker locks out at its 5th, so whether the next
/// request counts as a failure decides whether the account ends up blocked.
fn one_failure_from_lockout(tracker: &super::AuthFailureTracker) {
    for _ in 0..4 {
        tracker.record_failure(CLIENT_IP, BASIC_USER);
    }
    assert!(tracker.check_blocked(&CLIENT_IP, BASIC_USER).is_none());
}

/// #1094: without htpasswd, an API token sent as the Basic password is
/// still a credential — `docker login` (the `/v2/` ping) and a write with a
/// write token pass, as they do with htpasswd (#736).
#[tokio::test]
async fn test_basic_auth_api_token_without_htpasswd() {
    let ctx = create_test_context_without_htpasswd();
    let token = mint(&ctx, crate::tokens::Role::Write).await;
    let header_val = basic_header("docker", &token);

    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/v2/",
        vec![("authorization", &header_val)],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let response = send_with_headers(
        &ctx.app,
        Method::PUT,
        "/raw/test.txt",
        vec![("authorization", &header_val)],
        b"data".to_vec(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/raw/test.txt",
        vec![("authorization", &header_val)],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_bytes(response).await.as_ref(), b"data");
}

/// #1094: a write identity may not mint an ADMIN token through the
/// UI create path, even over a Basic-token credential in OIDC-only — the
/// caller's role gates the request, not the form. Without the gate any write
/// token escalates to admin (GHSA-78cx-cfhm-rgmx class, the UI create path
/// had missed it).
#[tokio::test]
async fn test_ui_token_create_write_caller_cannot_mint_admin() {
    let ctx = create_test_context_without_htpasswd();
    let write_token = mint(&ctx, crate::tokens::Role::Write).await;
    let header_val = basic_header("victim-admin", &write_token);
    let response = send_with_headers(
        &ctx.app,
        Method::POST,
        "/api/ui/tokens/create",
        vec![
            ("authorization", &header_val),
            ("hx-request", "true"),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        b"description=test&role=admin".to_vec(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a write identity minted an admin token via the UI"
    );
    // Nothing was minted: only the original write token remains.
    assert_eq!(
        ctx.state
            .tokens
            .as_ref()
            .unwrap()
            .list_all_tokens()
            .await
            .len(),
        1,
        "a token was created despite the 403"
    );
}

/// #1094: the UI create path owns the new token to the AUTHENTICATED
/// caller (the token owner), never to the forgeable Basic-header username (H3).
#[tokio::test]
async fn test_ui_token_create_owner_is_the_caller_not_the_basic_username() {
    let ctx = create_test_context_without_htpasswd();
    let write_token = mint(&ctx, crate::tokens::Role::Write).await;
    let header_val = basic_header("not-the-owner", &write_token);
    let response = send_with_headers(
        &ctx.app,
        Method::POST,
        "/api/ui/tokens/create",
        vec![
            ("authorization", &header_val),
            ("hx-request", "true"),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        b"description=test&role=write".to_vec(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let owners: Vec<String> = ctx
        .state
        .tokens
        .as_ref()
        .unwrap()
        .list_all_tokens()
        .await
        .into_iter()
        .map(|t| t.user)
        .collect();
    assert!(
        !owners.iter().any(|u| u == "not-the-owner"),
        "the new token was owned by the forged Basic username: {owners:?}"
    );
}

/// #1094: the new token is owned by EXACTLY the authenticated
/// token owner — not merely "not the forged Basic username" (F2). A mutant
/// that sets the owner to any other constant source (`"admin"`,
/// `x-remote-user`, a form field) passes F2 but fails here.
#[tokio::test]
async fn ui_token_create_owner_is_exactly_the_token_owner() {
    let ctx = create_test_context_without_htpasswd();
    let write_token = mint(&ctx, crate::tokens::Role::Write).await;
    let header_val = basic_header("not-the-owner", &write_token);
    let response = send_with_headers(
        &ctx.app,
        Method::POST,
        "/api/ui/tokens/create",
        vec![
            ("authorization", &header_val),
            ("hx-request", "true"),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        b"description=test&role=write".to_vec(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let owners: Vec<String> = ctx
        .state
        .tokens
        .as_ref()
        .unwrap()
        .list_all_tokens()
        .await
        .into_iter()
        .map(|t| t.user)
        .collect();
    assert_eq!(
        owners,
        vec![TOKEN_OWNER.to_string(), TOKEN_OWNER.to_string()],
        "the minted token's owner is not exactly the authenticated caller"
    );
}

/// #1094: the admin gate is by ROLE, not by name. A write
/// identity whose name happens to be `admin` (an htpasswd user, an OIDC
/// subject, or a token owner called `admin`) still cannot mint an admin
/// token. A mutant that gates on `user != "admin"` passes F1 (which only
/// exercises the `ci-bot` caller) but fails here.
#[tokio::test]
async fn ui_token_create_admin_named_write_caller_cannot_mint_admin() {
    let ctx = create_test_context_without_htpasswd();
    let write_token = ctx
        .state
        .tokens
        .as_ref()
        .unwrap()
        .create_token("admin", 30, None, crate::tokens::Role::Write)
        .await
        .unwrap();
    let header_val = basic_header("docker", &write_token);
    let response = send_with_headers(
        &ctx.app,
        Method::POST,
        "/api/ui/tokens/create",
        vec![
            ("authorization", &header_val),
            ("hx-request", "true"),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        b"description=test&role=admin".to_vec(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a write identity named 'admin' minted an admin token via the UI"
    );
    assert_eq!(
        ctx.state
            .tokens
            .as_ref()
            .unwrap()
            .list_all_tokens()
            .await
            .len(),
        1,
        "a token was created despite the 403"
    );
}

/// #1094: the role gate holds on the htpasswd-less Basic path — a read
/// token reads but cannot write (403), as over Bearer and with htpasswd.
/// The 403 is about the request, not the credential: it is not counted as
/// a failure, so a client with a valid read token is never locked out for
/// trying to write.
#[tokio::test]
async fn test_basic_auth_read_only_token_cannot_write_without_htpasswd() {
    let ctx = create_test_context_without_htpasswd();
    let token = mint(&ctx, crate::tokens::Role::Read).await;
    let header_val = basic_header("docker", &token);
    let tracker = &ctx.state.auth_failures;

    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/v2/",
        vec![("authorization", &header_val)],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    one_failure_from_lockout(tracker);
    for method in [Method::PUT, Method::POST, Method::DELETE, Method::PATCH] {
        let response = send_with_headers(
            &ctx.app,
            method.clone(),
            "/raw/test.txt",
            vec![("authorization", &header_val)],
            b"data".to_vec(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method}");
        assert!(
            tracker.check_blocked(&CLIENT_IP, BASIC_USER).is_none(),
            "{method}: a valid read token's 403 counted as a failure"
        );
    }
}

/// #1094: a token over Basic without htpasswd authenticates as the token's
/// owner with the token's role, not as the Basic username: npm whoami
/// names the owner, and the token list shows a write token only its
/// owner's tokens while an admin token sees every user's (GHSA-78cx).
#[tokio::test]
async fn test_basic_auth_token_identity_without_htpasswd() {
    let ctx = create_test_context_without_htpasswd();
    let store = ctx.state.tokens.as_ref().unwrap();
    store
        .create_token(
            "other",
            30,
            Some("theirs".into()),
            crate::tokens::Role::Read,
        )
        .await
        .unwrap();
    let write = basic_header("docker", &mint(&ctx, crate::tokens::Role::Write).await);
    let admin = basic_header("docker", &mint(&ctx, crate::tokens::Role::Admin).await);

    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/npm/-/whoami",
        vec![("authorization", &write)],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
    assert_eq!(json["username"], TOKEN_OWNER);

    for (header_val, sees_theirs) in [(&write, false), (&admin, true)] {
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/api/ui/tokens/list",
            vec![("authorization", header_val)],
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = String::from_utf8(body_bytes(response).await.to_vec()).unwrap();
        assert!(body.contains(TOKEN_OWNER), "{body}");
        assert_eq!(body.contains("theirs"), sees_theirs, "{body}");
    }
}

/// #1094: the admin gate holds too — a write token over Basic cannot reach
/// /api/v1/admin/*, an admin token can (an OIDC-only admin mints tokens
/// there, #808, and hands them to Basic-only clients).
#[tokio::test]
async fn test_basic_auth_token_admin_gate_without_htpasswd() {
    let ctx = create_test_context_without_htpasswd();
    let body = br#"{"username":"svc","ttl_days":1,"role":"read"}"#;
    for (role, want) in [
        (crate::tokens::Role::Write, StatusCode::FORBIDDEN),
        (crate::tokens::Role::Admin, StatusCode::OK),
    ] {
        let header_val = basic_header("docker", &mint(&ctx, role.clone()).await);
        let response = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/v1/admin/tokens",
            vec![
                ("authorization", &header_val),
                ("content-type", "application/json"),
            ],
            body.to_vec(),
        )
        .await;
        assert_eq!(response.status(), want, "{role:?}");
    }
}

/// #1094: a token-store failure on the htpasswd-less Basic path is an
/// outage (503), not a credential verdict (401), and is not counted.
#[tokio::test]
async fn test_basic_auth_token_store_error_returns_503_without_htpasswd() {
    let ctx = create_test_context_without_htpasswd();
    let token = mint(&ctx, crate::tokens::Role::Read).await;
    put_token_record(&ctx, &token, b"{\"token_ha").await;

    one_failure_from_lockout(&ctx.state.auth_failures);
    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/v2/",
        vec![("authorization", &basic_header("docker", &token))],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(ctx
        .state
        .auth_failures
        .check_blocked(&CLIENT_IP, BASIC_USER)
        .is_none());
}

/// #1094: an unknown, malformed or expired token over Basic without
/// htpasswd answers 401. Maestra: it is NOT counted toward the lockout
/// (as over Bearer): an nra_ token cannot be guessed, and counting a stale
/// one would lock out the valid credentials sharing its egress IP (CI
/// runners). A valid token leaves the count alone too.
#[tokio::test]
async fn test_basic_auth_bad_token_without_htpasswd_is_401_and_not_counted() {
    let ctx = create_test_context_without_htpasswd();
    let tracker = &ctx.state.auth_failures;
    let expired = mint(&ctx, crate::tokens::Role::Write).await;
    let record = ctx.state.storage.get(&token_key(&expired)).await.unwrap();
    let mut info: serde_json::Value = serde_json::from_slice(&record).unwrap();
    info["expires_at"] = 0.into();
    put_token_record(&ctx, &expired, info.to_string().as_bytes()).await;

    let bad = [
        "nra_00000000000000000000000000000000".to_string(),
        "secret".to_string(),
        expired,
    ];
    for password in &bad {
        one_failure_from_lockout(tracker);
        let response = send_with_headers(
            &ctx.app,
            Method::GET,
            "/v2/",
            vec![("authorization", &basic_header("docker", password))],
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{password}");
        assert!(response.headers().contains_key("www-authenticate"));
        assert!(
            tracker.check_blocked(&CLIENT_IP, BASIC_USER).is_none(),
            "{password}: a token was counted as a failure"
        );
        tracker.record_success(&CLIENT_IP, BASIC_USER);
    }

    one_failure_from_lockout(tracker);
    let token = mint(&ctx, crate::tokens::Role::Read).await;
    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/v2/",
        vec![("authorization", &basic_header("docker", &token))],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        tracker.check_blocked(&CLIENT_IP, BASIC_USER).is_none(),
        "a valid token added to the count"
    );
}

/// With neither htpasswd nor a token store, Basic has nothing to check
/// against: the answer stays 401 "Basic auth not configured", uncounted.
#[tokio::test]
async fn test_basic_auth_without_htpasswd_or_token_store_not_configured() {
    let ctx = create_test_context_without_htpasswd();
    let mut state = ctx.state.clone();
    state.tokens = None;
    let app =
        crate::request_layers(crate::registry::docker_routes(), &state).with_state(state.clone());

    one_failure_from_lockout(&state.auth_failures);
    let response = send_with_headers(
        &app,
        Method::GET,
        "/v2/",
        vec![(
            "authorization",
            &basic_header("docker", "nra_00000000000000000000000000000000"),
        )],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        body_bytes(response).await.as_ref(),
        br#"{"error":"Basic auth not configured"}"#
    );
    assert!(state
        .auth_failures
        .check_blocked(&CLIENT_IP, BASIC_USER)
        .is_none());
}

/// `npm install`/`npm audit`/`pnpm audit` POST their audit with the same read
/// token they install with; the write-method gate must not refuse it.
#[tokio::test]
async fn test_read_token_may_post_npm_audit() {
    let ctx = create_test_context_with_auth(&[("admin", "secret")]);
    let token = ctx
        .state
        .tokens
        .as_ref()
        .unwrap()
        .create_token("ci", 30, None, crate::tokens::Role::Read)
        .await
        .unwrap();
    let bearer = format!("Bearer {token}");
    let basic = format!("Basic {}", STANDARD.encode(format!("ci:{token}")));
    for path in [
        "/npm/-/npm/v1/security/advisories/bulk",
        "/npm/-/npm/v1/security/audits",
    ] {
        for header_val in [&bearer, &basic] {
            let response = send_with_headers(
                &ctx.app,
                Method::POST,
                path,
                vec![("authorization", header_val)],
                b"{}".to_vec(),
            )
            .await;
            assert_ne!(response.status(), StatusCode::FORBIDDEN, "{path}");
            assert_ne!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
        }
    }
    // Any other write with the same token is still refused.
    let response = send_with_headers(
        &ctx.app,
        Method::PUT,
        "/npm/some-pkg",
        vec![("authorization", &bearer)],
        b"{}".to_vec(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_auth_anonymous_read() {
    let ctx = create_test_context_with_anonymous_read(&[("admin", "secret")]);
    // Upload with auth
    let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));
    let response = send_with_headers(
        &ctx.app,
        Method::PUT,
        "/raw/test.txt",
        vec![("authorization", &header_val)],
        b"data".to_vec(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    // Read without auth should work
    let response = send(&ctx.app, Method::GET, "/raw/test.txt", "").await;
    assert_eq!(response.status(), StatusCode::OK);
    // Write without auth should fail
    let response = send(&ctx.app, Method::PUT, "/raw/test2.txt", b"data".to_vec()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// Token management must require auth even with anonymous_read=true (#221)
#[tokio::test]
async fn test_token_ui_requires_auth_with_anonymous_read() {
    let ctx = create_test_context_with_anonymous_read(&[("admin", "secret")]);

    // GET /ui/tokens without auth must return 401 even with anonymous_read
    let response = send(&ctx.app, Method::GET, "/ui/tokens", "").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // GET /api/ui/tokens/list without auth must also return 401
    let response = send(&ctx.app, Method::GET, "/api/ui/tokens/list", "").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // With auth, token UI should work
    let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));
    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/ui/tokens",
        vec![("authorization", &header_val)],
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    // Other read endpoints should still work anonymously
    let response = send(&ctx.app, Method::GET, "/health", "").await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_token_ui_requires_auth() {
    let ctx = create_test_context_with_auth(&[("admin", "secret")]);

    // Token UI page without auth should return 401
    let response = send(&ctx.app, Method::GET, "/ui/tokens", "").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Token UI page with auth should work
    let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));
    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/ui/tokens",
        vec![("authorization", &header_val)],
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_token_ui_create_requires_htmx() {
    let ctx = create_test_context_with_auth(&[("admin", "secret")]);
    let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));

    // POST without HX-Request header should be rejected (CSRF)
    let response = send_with_headers(
        &ctx.app,
        Method::POST,
        "/api/ui/tokens/create",
        vec![
            ("authorization", &header_val),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        "description=test&role=read&ttl_days=30",
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // POST with HX-Request header should work
    let response = send_with_headers(
        &ctx.app,
        Method::POST,
        "/api/ui/tokens/create",
        vec![
            ("authorization", &header_val),
            ("content-type", "application/x-www-form-urlencoded"),
            ("hx-request", "true"),
        ],
        "description=test&role=read&ttl_days=30",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_token_ui_revoke_validates_file_id() {
    let ctx = create_test_context_with_auth(&[("admin", "secret")]);
    let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));

    // Invalid file_id (not hex, no slashes so route matches)
    let response = send_with_headers(
        &ctx.app,
        Method::POST,
        "/api/ui/tokens/not_valid_hex_xx/revoke",
        vec![("authorization", &header_val), ("hx-request", "true")],
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Valid hex but non-existent
    let response = send_with_headers(
        &ctx.app,
        Method::POST,
        "/api/ui/tokens/abcd1234abcd1234/revoke",
        vec![("authorization", &header_val), ("hx-request", "true")],
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// Token API endpoints are public (in is_public_path) because they validate
/// credentials in the handler body. Verify that empty/missing credentials
/// are properly rejected with 401 — defense-in-depth against any future
/// refactor that might accidentally remove body-level auth checks.
#[tokio::test]
async fn test_token_create_without_credentials_returns_401() {
    let ctx = create_test_context_with_auth(&[("admin", "secret")]);
    let response = send_with_headers(
        &ctx.app,
        Method::POST,
        "/api/tokens",
        vec![("content-type", "application/json")],
        r#"{}"#,
    )
    .await;
    // Empty JSON body has no username/password — serde fails or handler rejects
    assert!(
        response.status() == StatusCode::UNAUTHORIZED
            || response.status() == StatusCode::UNPROCESSABLE_ENTITY
            || response.status() == StatusCode::BAD_REQUEST,
        "Expected 401/422/400, got {}",
        response.status()
    );
}

#[tokio::test]
async fn test_token_list_without_credentials_returns_401() {
    let ctx = create_test_context_with_auth(&[("admin", "secret")]);
    let response = send_with_headers(
        &ctx.app,
        Method::POST,
        "/api/tokens/list",
        vec![("content-type", "application/json")],
        r#"{}"#,
    )
    .await;
    assert!(
        response.status() == StatusCode::UNAUTHORIZED
            || response.status() == StatusCode::UNPROCESSABLE_ENTITY
            || response.status() == StatusCode::BAD_REQUEST,
        "Expected 401/422/400, got {}",
        response.status()
    );
}

#[tokio::test]
async fn test_token_revoke_without_credentials_returns_401() {
    let ctx = create_test_context_with_auth(&[("admin", "secret")]);
    let response = send_with_headers(
        &ctx.app,
        Method::POST,
        "/api/tokens/revoke",
        vec![("content-type", "application/json")],
        r#"{}"#,
    )
    .await;
    assert!(
        response.status() == StatusCode::UNAUTHORIZED
            || response.status() == StatusCode::UNPROCESSABLE_ENTITY
            || response.status() == StatusCode::BAD_REQUEST,
        "Expected 401/422/400, got {}",
        response.status()
    );
}

#[tokio::test]
async fn test_token_ui_full_lifecycle() {
    let ctx = create_test_context_with_auth(&[("admin", "secret")]);
    let header_val = format!("Basic {}", STANDARD.encode("admin:secret"));

    // Create a token via UI endpoint
    let response = send_with_headers(
        &ctx.app,
        Method::POST,
        "/api/ui/tokens/create",
        vec![
            ("authorization", &header_val),
            ("content-type", "application/x-www-form-urlencoded"),
            ("hx-request", "true"),
        ],
        "description=CI+Pipeline&role=write&ttl_days=30",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = String::from_utf8(body_bytes(response).await.to_vec()).unwrap();
    assert!(body.contains("nra_"), "Response should contain raw token");

    // List tokens
    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/api/ui/tokens/list",
        vec![("authorization", &header_val)],
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = String::from_utf8(body_bytes(response).await.to_vec()).unwrap();
    assert!(body.contains("CI Pipeline"), "List should show description");

    // Get file_id from the token store directly for revoke test
    let tokens = ctx.state.tokens.as_ref().unwrap().list_all_tokens().await;
    assert_eq!(tokens.len(), 1);
    let file_id = &tokens[0].file_id;

    // Revoke
    let revoke_url = format!("/api/ui/tokens/{}/revoke", file_id);
    let response = send_with_headers(
        &ctx.app,
        Method::POST,
        &revoke_url,
        vec![("authorization", &header_val), ("hx-request", "true")],
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    // Verify token is gone
    let tokens = ctx.state.tokens.as_ref().unwrap().list_all_tokens().await;
    assert_eq!(tokens.len(), 0);
}

/// POST a UI token-create form with the given Authorization header.
pub(super) async fn ui_create_token(
    ctx: &TestContext,
    authorization: &str,
    role: &str,
) -> axum::http::Response<axum::body::Body> {
    send_with_headers(
        &ctx.app,
        Method::POST,
        "/api/ui/tokens/create",
        vec![
            ("authorization", authorization),
            ("content-type", "application/x-www-form-urlencoded"),
            ("hx-request", "true"),
        ],
        format!("description=x&role={}&ttl_days=30", role),
    )
    .await
}

/// A write token sent as the Basic password under a made-up username must
/// not mint an admin token, and whatever it mints belongs to the token's
/// verified owner, not to the Basic username.
#[tokio::test]
async fn test_token_ui_create_uses_verified_owner_and_refuses_admin() {
    let ctx = create_test_context_with_auth_and_config(&[("admin", "secret")], |cfg| {
        cfg.auth.admin_users = vec!["mallory".to_string()];
    });
    let store = ctx.state.tokens.as_ref().unwrap();
    let write_token = store
        .create_token("ci", 30, None, crate::tokens::Role::Write)
        .await
        .unwrap();
    let spoofed = format!(
        "Basic {}",
        STANDARD.encode(format!("mallory:{}", write_token))
    );

    let response = ui_create_token(&ctx, &spoofed, "admin").await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = ui_create_token(&ctx, &spoofed, "write").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(store.list_tokens("mallory").await.is_empty());
    assert_eq!(store.list_tokens("ci").await.len(), 2);

    // htpasswd identities are Write-role: no admin mint either.
    let basic = format!("Basic {}", STANDARD.encode("admin:secret"));
    let response = ui_create_token(&ctx, &basic, "admin").await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// Admin mint needs an admin-role credential AND an auth.admin_users entry.
#[tokio::test]
async fn test_token_ui_create_admin_requires_admin_role_and_allowlist() {
    let ctx = create_test_context_with_auth_and_config(&[("admin", "secret")], |cfg| {
        cfg.auth.admin_users = vec!["boss".to_string()];
    });
    let store = ctx.state.tokens.as_ref().unwrap();
    let boss = store
        .create_token("boss", 30, None, crate::tokens::Role::Admin)
        .await
        .unwrap();
    let eve = store
        .create_token("eve", 30, None, crate::tokens::Role::Admin)
        .await
        .unwrap();

    let response = ui_create_token(&ctx, &format!("Bearer {}", eve), "admin").await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = ui_create_token(&ctx, &format!("Bearer {}", boss), "admin").await;
    assert_eq!(response.status(), StatusCode::OK);
    let minted = store.list_tokens("boss").await;
    assert_eq!(minted.len(), 2);
    assert!(minted.iter().all(|t| t.role == crate::tokens::Role::Admin));
}

/// An htpasswd account in auth.read_only_users authenticates as Read: it
/// pulls but cannot push; other htpasswd accounts keep Write.
#[tokio::test]
async fn test_htpasswd_read_only_user_cannot_write() {
    let ctx =
        create_test_context_with_auth_and_config(&[("admin", "secret"), ("viewer", "pw")], |cfg| {
            cfg.auth.read_only_users = vec!["viewer".to_string()]
        });
    let admin = format!("Basic {}", STANDARD.encode("admin:secret"));
    let viewer = format!("Basic {}", STANDARD.encode("viewer:pw"));
    let app = &ctx.app;
    let put = |auth: String| async move {
        send_with_headers(
            app,
            Method::PUT,
            "/raw/test.txt",
            vec![("authorization", &auth)],
            b"data".to_vec(),
        )
        .await
        .status()
    };
    assert_eq!(put(viewer.clone()).await, StatusCode::FORBIDDEN);
    assert_eq!(put(admin).await, StatusCode::OK);
    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/raw/test.txt",
        vec![("authorization", &viewer)],
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// No self-service mint outranks the caller: a read-only htpasswd account
/// gets read tokens only from POST /api/tokens, and a read credential
/// cannot mint write through the UI. Write accounts are unchanged.
#[tokio::test]
async fn test_token_mint_capped_at_caller_role() {
    let ctx =
        create_test_context_with_auth_and_config(&[("admin", "secret"), ("viewer", "pw")], |cfg| {
            cfg.auth.read_only_users = vec!["viewer".to_string()]
        });
    let store = ctx.state.tokens.as_ref().unwrap();
    let app = &ctx.app;
    let api_mint = |user: &'static str, pass: &'static str, role: &'static str| async move {
        send_with_headers(
            app,
            Method::POST,
            "/api/tokens",
            vec![("content-type", "application/json")],
            format!(r#"{{"username":"{user}","password":"{pass}","role":"{role}"}}"#),
        )
        .await
        .status()
    };
    assert_eq!(
        api_mint("viewer", "pw", "write").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        api_mint("viewer", "pw", "admin").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(api_mint("viewer", "pw", "read").await, StatusCode::OK);
    let minted = store.list_tokens("viewer").await;
    assert_eq!(minted.len(), 1);
    assert_eq!(minted[0].role, crate::tokens::Role::Read);
    assert_eq!(api_mint("admin", "secret", "write").await, StatusCode::OK);

    let viewer = format!("Basic {}", STANDARD.encode("viewer:pw"));
    let response = ui_create_token(&ctx, &viewer, "write").await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let read_token = store
        .create_token("ro", 30, None, crate::tokens::Role::Read)
        .await
        .unwrap();
    let response = ui_create_token(&ctx, &format!("Bearer {read_token}"), "write").await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(store.list_tokens("viewer").await.len(), 1);
    assert_eq!(store.list_tokens("ro").await.len(), 1);
}
