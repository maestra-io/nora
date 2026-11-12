// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::auth::oidc::OidcValidator;
use crate::config::{OidcConfig, OidcProvider, OidcRoleRule};
use crate::test_helpers::*;
use axum::http::{Method, StatusCode};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::json;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// Test RSA private key (2048-bit, for test JWT signing only)
pub(crate) const TEST_RSA_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7657FVL7gwmjj
PEfl4A+ajG3DFj6YHmS9gargHMChpdLMbt8ybqu1hHPUNKQyndUvFJ6q+xJFEds3
eBtjB5GLLtlj9lScvGPsV7386rypeHq30IErgm2beQJyF9ldtrVHBBPbz7eAo4+i
wCJ/m5IsuoLCYZPQrDUdpax0dUEa/eP6badqjZ2r0recnHw1+zGyozzSHNvPtK9I
PsKwBcbGjt5n5+9nWN322/mISAuLNwtv7l3Lja8U7m0ixH0ZLwFSgTLtzEfJISux
+ngGR4k2PBVeo+yDOZtuatx7Aixa1FerOwiq2xsoGOs2dhXagwFGdwbs8x/MvEj0
67Mm3OrLAgMBAAECggEAHXZkjyWpQ43XagESeKz3ZVCtCNAdAjaJrth8lOSNIwrf
kOO1JLALRcs9acDTGYh7WwVNlxsEE0Yoa3ruOEmAfSTcOnrtayFyPSTIibW33I4i
F12eUtcBHkYLpx2sG7BAnaC7CFR5vbZnF6ot/nnCojaft6Aaz7WgIkTOU/fqPDPb
WOSn4PQmgZS34non7y0NWmxxeIwqJk3aBeeEKisO2AS0YCHOgx2uBTIt2lcIzjK8
RHwQjLRRfhzxuhHuQtz/hMVQ17W3l7ehYTnW0D+UJJTXBjPgElICmWdGm9NMX9YH
HzVSBdH+tzTZ/hUhKe+nEZ5vrWT2wqx/h0med2P3eQKBgQDYNURqK7dfo2QBsy/F
pdUg7UaXfWe+c6guu32aZhnxYsHUE68cuV7Bz/awjMJYvF9VKhoJ+iuHI0myo9In
HITzbSDwFrWCme7DAIPbfbQU9nQqJLK/g3nUpYSpjFQEnIPJSr1aS/fVpUURAoBg
RSktyRTY3ak7+6x1I54HLxPk3QKBgQDegZEqK6B28fQklCPgdimwnNr92oJe5hoY
9cHUDz3A1Uyek40LQ1yR7W/imDCJMcQXqM7Lo54+55eHEkBvh6H/TTmnGMzj5L7t
HoKYMjYdBK7waFYGM6ULfVXqs6JqVmKFU7LX+ZVmOB5kgcQMQrAhio0GrG97iDqz
aKHqOthfxwKBgQDKa+SnulIumlzRMqAxXfdSopOK1YBB0SrOxf7shVcYpitukRdL
v0m2DyyZUs/KIGLo60gBu1TxatpfA/2HXK4k8jD6V2iM4+2kaGELKH9neO59Xmpz
33Y63tR7oMQwpRDFbtIlLibUwa0OJddnSpkpIq//8le1rwVhjn0voKXxiQKBgQDS
2qPO+6LHtQewdjX9atydAjfAooYzGgkXKCTzKTJS/47pI1hgmQgrPX9uktxD1sZF
yXGWpsm6QMtmc5ReXIDWp77/q0/WkpmfqO8G/WYsX5jMN4N1wxEfbzmw/WPnM0+P
mz56zoiWYo3intpC6Bty3ZJBBb1rqjA+feQaTINpVwKBgF/M0Lj9Sq9G2Ec7yBnm
xhBlLwCNzAk33Fy+6w6ANXTsGRwMm0zGdTjC3e6LHMrD0ZtF0M2blWAUh3sZ6ItQ
2Ak5ScO0q3MRQvo4HZkFK2wuZvNLYExq6gGy3P6l8xXbvQTzg5nl9UWDKfY1gifz
Jd74nq6dNCjpWG4drIsyhqX+
-----END PRIVATE KEY-----"#; // gitleaks:allow (test-only signing key)

// Corresponding JWKS (public key in JWK format)
pub(crate) const TEST_JWKS_JSON: &str = r#"{"keys":[{"kty":"RSA","kid":"test-key-1","use":"sig","alg":"RS256","n":"u-uexVS-4MJo4zxH5eAPmoxtwxY-mB5kvYGq4BzAoaXSzG7fMm6rtYRz1DSkMp3VLxSeqvsSRRHbN3gbYweRiy7ZY_ZUnLxj7Fe9_Oq8qXh6t9CBK4Jtm3kCchfZXba1RwQT28-3gKOPosAif5uSLLqCwmGT0Kw1HaWsdHVBGv3j-m2nao2dq9K3nJx8NfsxsqM80hzbz7SvSD7CsAXGxo7eZ-fvZ1jd9tv5iEgLizcLb-5dy42vFO5tIsR9GS8BUoEy7cxHySErsfp4BkeJNjwVXqPsgzmbbmrcewIsWtRXqzsIqtsbKBjrNnYV2oMBRncG7PMfzLxI9OuzJtzqyw","e":"AQAB"}]}"#;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Create a signed JWT with given claims.
fn make_jwt(issuer: &str, subject: &str, audience: &str, iat: u64, exp: u64) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-1".to_string());

    let claims = json!({
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "iat": iat,
        "exp": exp,
    });

    let key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY.as_bytes()).unwrap();
    encode(&header, &claims, &key).unwrap()
}

/// Build a TestContext with OIDC enabled, pointing at the given mock JWKS URL.
fn create_oidc_test_context(mock_issuer_url: &str) -> TestContext {
    create_oidc_test_context_scoped(mock_issuer_url, &["*"], None)
}

/// Like [`create_oidc_test_context`], with the provider `namespace_scope`
/// and the main-branch rule's `namespace_scope` injectable.
fn create_oidc_test_context_scoped(
    mock_issuer_url: &str,
    provider_scope: &[&str],
    main_rule_scope: Option<Vec<String>>,
) -> TestContext {
    create_oidc_test_context_with(mock_issuer_url, provider_scope, main_rule_scope, |_| {})
}

/// Like [`create_oidc_test_context`], with `tweak` applied to the provider.
fn create_oidc_test_context_tweaked(
    mock_issuer_url: &str,
    tweak: impl FnOnce(&mut OidcProvider),
) -> TestContext {
    create_oidc_test_context_with(mock_issuer_url, &["*"], None, tweak)
}

fn create_oidc_test_context_with(
    mock_issuer_url: &str,
    provider_scope: &[&str],
    main_rule_scope: Option<Vec<String>>,
    tweak: impl FnOnce(&mut OidcProvider),
) -> TestContext {
    let issuer = mock_issuer_url.to_string();
    let provider_scope: Vec<String> = provider_scope.iter().map(|s| s.to_string()).collect();
    let mut ctx = create_test_context_with_config(move |cfg| {
        cfg.auth.enabled = true;
        cfg.auth.anonymous_read = false;
        cfg.auth.oidc = OidcConfig {
            enabled: true,
            leeway_secs: 60,
            jwks_cache_secs: 300,
            providers: vec![OidcProvider {
                name: "test-ci".to_string(),
                issuer: issuer.clone(),
                jwks_uri: None,
                audience: "nora".to_string(),
                any_audience: false,
                algorithms: vec!["RS256".to_string()],
                max_token_lifetime_secs: 900,
                session_lifetime_secs: 0,
                namespace_scope: provider_scope.clone(),
                namespace_scope_enforcement: crate::config::ScopeEnforcement::Enforce,
                enabled: true,
                role_rules: vec![
                    // Admin ROLE with a RESTRICTED scope, and admin role with
                    // no rule scope (unrestricted under provider `["*"]`).
                    // Distinct `admin-scoped`/`admin-free` segments so these
                    // never match the `repo:myorg/app:*` subjects other OIDC
                    // tests mint (first-match-wins). Used by the admin-mint
                    // scope-escape test.
                    OidcRoleRule {
                        pattern: "repo:myorg/admin-scoped:*".to_string(),
                        role: "admin".to_string(),
                        namespace_scope: Some(vec!["ci-transport/**".to_string()]),
                    },
                    OidcRoleRule {
                        pattern: "repo:myorg/admin-free:*".to_string(),
                        role: "admin".to_string(),
                        namespace_scope: None,
                    },
                    OidcRoleRule {
                        pattern: "repo:myorg/*:ref:refs/heads/main".to_string(),
                        role: "write".to_string(),
                        namespace_scope: main_rule_scope.clone(),
                    },
                    OidcRoleRule {
                        pattern: "repo:myorg/*:pull_request".to_string(),
                        role: "write".to_string(),
                        namespace_scope: Some(vec!["ci-transport/**".to_string()]),
                    },
                    OidcRoleRule {
                        pattern: "repo:myorg/*".to_string(),
                        role: "read".to_string(),
                        namespace_scope: None,
                    },
                ],
            }],
        };
        tweak(&mut cfg.auth.oidc.providers[0]);
    });

    // Wire up the OidcValidator on the existing state
    let oidc_validator =
        OidcValidator::new(ctx.state.config.auth.oidc.clone(), reqwest::Client::new());
    // We need to rebuild the state with oidc set — use Arc::get_mut or rebuild
    let state = crate::AppState {
        storage: ctx.state.storage.clone(),
        config: ctx.state.config.clone(),
        enabled_registries: ctx.state.enabled_registries.clone(),
        start_time: ctx.state.start_time,
        startup_duration_ms: ctx.state.startup_duration_ms,
        auth: ctx.state.auth.clone(),
        // Prod builds a token store whenever `auth.enabled` (main.rs:1782);
        // the base builder keyed it off its `auth_enabled` arg (false here,
        // the `enabled` tweak comes from `customize`), leaving OIDC
        // identities' token operations untested. Mirror prod so the store is
        // present for an OIDC caller that reaches a token handler.
        tokens: Some(crate::tokens::TokenStore::new(ctx.state.storage.clone())),
        metrics: Arc::new(crate::dashboard_metrics::DashboardMetrics::new()),
        activity: Arc::new(crate::activity_log::ActivityLog::new(50)),
        audit: ctx.state.audit.clone(),
        docker_auth: Arc::new(crate::registry::DockerAuth::new(reqwest::Client::new(), 5)),
        docker_date_walks: Default::default(),
        repo_index: Arc::new(crate::repo_index::RepoIndex::new()),
        http_client: reqwest::Client::new(),
        http_client_no_redirect: reqwest::Client::new(),
        http_client_same_origin: reqwest::Client::new(),
        hf_canonical_ids: Arc::default(),
        upload_sessions: Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new())),
        publish_locks: Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new())),
        reloadable: Arc::new(arc_swap::ArcSwap::from_pointee(crate::ReloadableConfig {
            curation_engine: crate::curation::CurationEngine::new(
                crate::config::CurationConfig::default(),
            ),
            bypass_token: None,
        })),
        auth_failures: Arc::new(crate::auth::AuthFailureTracker::new(5, 900)),
        oidc: Some(Arc::new(oidc_validator)),
        teleport: None,
        circuit_breaker: Arc::new(crate::circuit_breaker::CircuitBreakerRegistry::new(
            ctx.state.config.circuit_breaker.clone(),
        )),
        proxy_coalesce: crate::proxy_coalesce::InflightMap::new(),
        artifact_flights: crate::proxy_coalesce::InflightMap::new(),
        spool: ctx.state.spool.clone(),
        blob_flights: crate::proxy_coalesce::InflightMap::new(),
        packument_memo: Arc::default(),
        digest_store: ctx.state.digest_store.clone(),
        quarantine_exceptions: ctx.state.quarantine_exceptions.clone(),
        signer: ctx.state.signer.clone(),
        leak_finders: ctx.state.leak_finders.clone(),
        cancel_token: tokio_util::sync::CancellationToken::new(),
        nuget_hosted: Default::default(),
        deb_young: Default::default(),
        pull_stats: std::sync::Arc::new(crate::registry::docker::PullStatsAccumulator::default()),
        tasks: ctx.state.tasks.clone(),
        maintenance: ctx.state.maintenance.clone(),
    };

    // Rebuild router with new state
    use axum::{extract::DefaultBodyLimit, middleware, Router};
    let mut registry_routes = Router::new();
    for reg in state.enabled_registries.iter() {
        match reg {
            crate::registry_type::RegistryType::Raw => {
                registry_routes = registry_routes.merge(crate::registry::raw_routes());
            }
            _ => {}
        }
    }
    let public_routes = Router::new().merge(crate::health::routes());
    let app_routes = Router::new()
        .merge(crate::auth::token_routes())
        .merge(crate::auth::oidc_session::routes())
        .merge(crate::ui::routes())
        .merge(crate::admin::routes())
        .merge(registry_routes);
    let app = Router::new()
        .merge(public_routes)
        .merge(app_routes)
        .layer(DefaultBodyLimit::max(
            state.config.server.body_limit_mb * 1024 * 1024,
        ))
        .layer(middleware::from_fn(
            crate::request_id::request_id_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::auth::auth_middleware,
        ))
        .with_state(state.clone());

    ctx.state = state;
    ctx.app = app;
    ctx
}

#[tokio::test]
async fn test_oidc_valid_jwt_write_access() {
    let mock_server = MockServer::start().await;

    // Serve JWKS at /.well-known/jwks.json
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"))
        .mount(&mock_server)
        .await;

    let ctx = create_oidc_test_context(&mock_server.uri());
    let now = now_secs();
    let token = make_jwt(
        &mock_server.uri(),
        "repo:myorg/app:ref:refs/heads/main",
        "nora",
        now,
        now + 600,
    );

    let bearer = format!("Bearer {}", token);
    let response = send_with_headers(
        &ctx.app,
        Method::PUT,
        "/raw/oidc-test.txt",
        vec![("authorization", &bearer)],
        b"hello from ci".to_vec(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Write with main-branch OIDC token should succeed"
    );
}

#[tokio::test]
async fn test_oidc_rule_scope_narrows_writes() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"))
        .mount(&mock_server)
        .await;

    let ctx = create_oidc_test_context(&mock_server.uri());
    let now = now_secs();
    // pull_request rule: role=write, namespace_scope=["ci-transport/**"]
    let token = make_jwt(
        &mock_server.uri(),
        "repo:myorg/app:pull_request",
        "nora",
        now,
        now + 600,
    );
    let bearer = format!("Bearer {}", token);

    // In-scope write is allowed…
    let response = send_with_headers(
        &ctx.app,
        Method::PUT,
        "/raw/ci-transport/run-1/artifact.txt",
        vec![("authorization", &bearer)],
        b"transport".to_vec(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "PR token should write inside its rule scope"
    );

    // …but the same identity cannot write outside the rule's scope, even
    // though the provider scope is ["*"].
    let response = send_with_headers(
        &ctx.app,
        Method::PUT,
        "/raw/prod/artifact.txt",
        vec![("authorization", &bearer)],
        b"escape".to_vec(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "PR token must not write outside its rule scope"
    );
}

/// #1094: a namespace-scoped OIDC identity must not escalate by
/// minting an unrestricted opaque token through the UI create path. The
/// write handlers enforce the scope (the control below), and the UI mint
/// now refuses a scoped caller (`decide_ui_token_mint`) instead of handing
/// it an `nra_` token that writes anywhere. Before the fix the mint returned
/// 200 and that token wrote to `prod/`; on `github/main` the UI path
/// required Basic auth and returned 400.
#[tokio::test]
async fn test_oidc_scoped_identity_cannot_mint_unrestricted_token_via_ui() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"))
        .mount(&mock_server)
        .await;

    let ctx = create_oidc_test_context(&mock_server.uri());
    let now = now_secs();
    // pull_request rule: role=write, namespace_scope=["ci-transport/**"].
    let jwt = make_jwt(
        &mock_server.uri(),
        "repo:myorg/app:pull_request",
        "nora",
        now,
        now + 600,
    );
    let bearer = format!("Bearer {}", jwt);

    // Control: the identity cannot write to prod/ directly — scope enforced.
    let response = send_with_headers(
        &ctx.app,
        Method::PUT,
        "/raw/prod/a.txt",
        vec![("authorization", &bearer)],
        b"x".to_vec(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "control: a ci-transport-scoped identity must not write to prod/"
    );

    // The UI mint refuses the scoped caller: nothing is handed out.
    let response = send_with_headers(
        &ctx.app,
        Method::POST,
        "/api/ui/tokens/create",
        vec![
            ("authorization", &bearer),
            ("hx-request", "true"),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        b"description=test&role=write&ttl_days=3650".to_vec(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a namespace-scoped identity minted an unrestricted token via the UI"
    );
    assert!(
        ctx.state
            .tokens
            .as_ref()
            .unwrap()
            .list_all_tokens()
            .await
            .is_empty(),
        "a token was minted for a scoped caller despite the 403"
    );
}

/// #1094 (admin sibling): the admin-gated mint route `POST
/// /api/v1/admin/tokens` is reachable by every identity the admin gate
/// admits — including an OIDC identity assigned the `admin` ROLE with a
/// RESTRICTED `namespace_scope`. Admin role is not admin authority: the
/// opaque token minted here is always namespace-unrestricted, so a scoped
/// admin must be refused (403, nothing minted) or it escalates past its own
/// `ci-transport/**` scope through the token. The non-vacuous pair: an
/// UNRESTRICTED admin (rule scope `None`, provider `["*"]`) is NOT refused —
/// the refusal keys on the caller's scope, not on the route.
#[tokio::test]
async fn test_oidc_scoped_admin_cannot_mint_unrestricted_token_via_admin_route() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"))
        .mount(&mock_server)
        .await;

    let ctx = create_oidc_test_context(&mock_server.uri());
    let now = now_secs();

    // Scoped admin: role=admin WITH namespace_scope=["ci-transport/**"].
    let scoped = make_jwt(
        &mock_server.uri(),
        "repo:myorg/admin-scoped:deploy",
        "nora",
        now,
        now + 600,
    );
    let scoped_bearer = format!("Bearer {}", scoped);
    let response = send_with_headers(
        &ctx.app,
        Method::POST,
        "/api/v1/admin/tokens",
        vec![
            ("authorization", &scoped_bearer),
            ("content-type", "application/json"),
        ],
        br#"{"username":"svc","role":"write","ttl_days":36500}"#.to_vec(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a namespace-scoped admin minted an unrestricted token via the admin route"
    );
    assert!(
        ctx.state
            .tokens
            .as_ref()
            .unwrap()
            .list_all_tokens()
            .await
            .is_empty(),
        "a token was minted for a scoped admin despite the 403"
    );

    // Non-vacuous pair: an unrestricted admin (rule scope None, provider
    // ["*"]) IS allowed — the refusal keys on scope, not on the route.
    let free = make_jwt(
        &mock_server.uri(),
        "repo:myorg/admin-free:deploy",
        "nora",
        now,
        now + 600,
    );
    let free_bearer = format!("Bearer {}", free);
    let response = send_with_headers(
        &ctx.app,
        Method::POST,
        "/api/v1/admin/tokens",
        vec![
            ("authorization", &free_bearer),
            ("content-type", "application/json"),
        ],
        br#"{"username":"svc","role":"write","ttl_days":30}"#.to_vec(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "an unrestricted admin must still be able to mint via the admin route"
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
        "exactly one token minted by the unrestricted admin"
    );
}

/// #1094: a token minted by an OIDC identity through the UI must not outlive
/// the provider's `max_token_lifetime_secs` (900s here). An unrestricted
/// write identity (main-ref rule, provider `["*"]`) may mint — it is not
/// scope-refused — but the 3650-day request is capped to the 1-day floor.
/// Maestra (R2-01): the mint is refused outright instead — a workload
/// identity never exchanges itself for an nra_ token, capped or not.
#[tokio::test]
async fn test_oidc_identity_cannot_mint_tokens() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"))
        .mount(&mock_server)
        .await;

    let ctx = create_oidc_test_context(&mock_server.uri());
    let now = now_secs();
    // main-ref rule: role=write, no rule scope, provider scope ["*"] -> an
    // UNRESTRICTED identity (not refused by the scope gate).
    let jwt = make_jwt(
        &mock_server.uri(),
        "repo:myorg/app:ref:refs/heads/main",
        "nora",
        now,
        now + 600,
    );
    let bearer = format!("Bearer {}", jwt);

    let response = send_with_headers(
        &ctx.app,
        Method::POST,
        "/api/ui/tokens/create",
        vec![
            ("authorization", &bearer),
            ("hx-request", "true"),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        b"description=test&role=write&ttl_days=3650".to_vec(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a workload identity minted a token (R2-01)"
    );
    assert!(
        ctx.state
            .tokens
            .as_ref()
            .unwrap()
            .list_all_tokens()
            .await
            .is_empty(),
        "a token was minted despite the 403"
    );
}

/// The admin route holds an OIDC admin to the same lifetime as the UI: a
/// token it mints lives no longer than what is left of the JWT (600s here,
/// under the 900s ceiling) whatever it asks for, and a JWT accepted only
/// inside the leeway mints nothing.
#[tokio::test]
async fn an_oidc_admin_mint_on_the_admin_route_never_outlives_the_jwt() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"))
        .mount(&mock_server)
        .await;
    let mint = |ctx: &TestContext, jwt: String| {
        let app = ctx.app.clone();
        async move {
            send_with_headers(
                &app,
                Method::POST,
                "/api/v1/admin/tokens",
                vec![
                    ("authorization", &format!("Bearer {jwt}")),
                    ("content-type", "application/json"),
                ],
                br#"{"username":"svc","role":"read","ttl_days":3650}"#.to_vec(),
            )
            .await
            .status()
        }
    };
    let subject = "repo:myorg/admin-free:ref:refs/heads/main";
    // The clock is read after the context is built: under a loaded test run the build
    // takes seconds, which are no part of the JWT's life at the mint.
    let ctx = create_oidc_test_context(&mock_server.uri());
    let now = now_secs();
    let jwt = make_jwt(&mock_server.uri(), subject, "nora", now, now + 600);
    assert_eq!(mint(&ctx, jwt).await, StatusCode::OK);
    let entries = ctx.state.tokens.as_ref().unwrap().list_all_tokens().await;
    assert_eq!(entries.len(), 1, "exactly one token minted");
    let lifetime = entries[0].expires_at - entries[0].created_at;
    assert!(
        (590..=600).contains(&lifetime),
        "an OIDC admin minted a {lifetime}s token on the admin route (JWT 600s, ceiling 900s)"
    );

    let ctx = create_oidc_test_context(&mock_server.uri());
    // Read again: the mint above and this build take seconds under load, and a JWT dated
    // from the first reading would by now be past the 60 s leeway, a 401 and not this 403.
    let now = now_secs();
    let expired = make_jwt(&mock_server.uri(), subject, "nora", now - 630, now - 30);
    assert_eq!(mint(&ctx, expired).await, StatusCode::FORBIDDEN);
    assert!(
        ctx.state
            .tokens
            .as_ref()
            .unwrap()
            .list_all_tokens()
            .await
            .is_empty(),
        "an expired JWT minted a token on the admin route"
    );
}

/// The admin route answers the lifetime it granted in seconds: an OIDC admin
/// whose JWT has 600 s left asks for 30 days and is told what the token store
/// holds, which `expires_in_days` (kept as it was) rounds down to 0; an admin
/// holding an opaque token, with no JWT to outlive, is told the 30 days.
#[tokio::test]
async fn the_admin_route_answers_the_lifetime_granted_in_seconds() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"))
        .mount(&mock_server)
        .await;
    let mint = |ctx: &TestContext, bearer: String| {
        let app = ctx.app.clone();
        async move {
            let response = send_with_headers(
                &app,
                Method::POST,
                "/api/v1/admin/tokens",
                vec![
                    ("authorization", &bearer),
                    ("content-type", "application/json"),
                ],
                br#"{"username":"svc","role":"read","ttl_days":30}"#.to_vec(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            serde_json::from_slice::<serde_json::Value>(&body_bytes(response).await).unwrap()
        }
    };
    let stored = |ctx: &TestContext| {
        let tokens = ctx.state.tokens.clone();
        async move {
            let entries = tokens.as_ref().unwrap().list_tokens("svc").await;
            assert_eq!(entries.len(), 1, "exactly one token minted for svc");
            entries[0].expires_at - entries[0].created_at
        }
    };
    let now = now_secs();

    let ctx = create_oidc_test_context(&mock_server.uri());
    let jwt = make_jwt(
        &mock_server.uri(),
        "repo:myorg/admin-free:ref:refs/heads/main",
        "nora",
        now,
        now + 600,
    );
    let json = mint(&ctx, format!("Bearer {jwt}")).await;
    let secs = json["expires_in_secs"].as_u64().expect("expires_in_secs");
    assert!(secs <= 600, "the answer outlives the JWT: {json}");
    assert_eq!(
        secs,
        stored(&ctx).await,
        "the answer is not what the store holds"
    );
    assert_eq!(json["expires_in_days"], 0, "{json}");

    let ctx = create_oidc_test_context(&mock_server.uri());
    let admin = ctx
        .state
        .tokens
        .as_ref()
        .unwrap()
        .create_token("root", 30, None, crate::tokens::Role::Admin)
        .await
        .unwrap();
    let json = mint(&ctx, format!("Bearer {admin}")).await;
    assert_eq!(json["expires_in_secs"], 30 * 86_400, "{json}");
    assert_eq!(stored(&ctx).await, 30 * 86_400);
    assert_eq!(json["expires_in_days"], 30, "{json}");
}

/// A JWT the validator still accepts inside its leeway, though its `exp`
/// has passed, mints nothing: the token would outlive the credential that
/// minted it from its first second. Fail closed: 403, no token.
#[tokio::test]
async fn test_oidc_identity_already_expired_cannot_mint() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"))
        .mount(&mock_server)
        .await;
    let ctx = create_oidc_test_context(&mock_server.uri());
    let now = now_secs();
    // Lifetime 600s (under the 900s ceiling), expired 30s ago, inside the
    // 60s leeway: authentication still accepts it.
    let jwt = make_jwt(
        &mock_server.uri(),
        "repo:myorg/app:ref:refs/heads/main",
        "nora",
        now - 630,
        now - 30,
    );
    let bearer = format!("Bearer {jwt}");
    let read = send_with_headers(
        &ctx.app,
        Method::GET,
        "/raw/none.txt",
        vec![("authorization", &bearer)],
        Vec::new(),
    )
    .await;
    assert_eq!(
        read.status(),
        StatusCode::NOT_FOUND,
        "the JWT authenticates"
    );
    let response = send_with_headers(
        &ctx.app,
        Method::POST,
        "/api/ui/tokens/create",
        vec![
            ("authorization", &bearer),
            ("hx-request", "true"),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        b"description=test&role=write&ttl_days=1".to_vec(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        ctx.state
            .tokens
            .as_ref()
            .unwrap()
            .list_all_tokens()
            .await
            .is_empty(),
        "an expired JWT minted a token"
    );
}

/// A JWT without `exp` is refused at authentication (the validator
/// requires it), so it never reaches the mint.
#[tokio::test]
async fn test_oidc_jwt_without_exp_cannot_mint() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"))
        .mount(&mock_server)
        .await;
    let ctx = create_oidc_test_context(&mock_server.uri());
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-1".to_string());
    let claims = json!({
        "iss": mock_server.uri(),
        "sub": "repo:myorg/app:ref:refs/heads/main",
        "aud": "nora",
        "iat": now_secs(),
    });
    let key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY.as_bytes()).unwrap();
    let jwt = encode(&header, &claims, &key).unwrap();
    let response = send_with_headers(
        &ctx.app,
        Method::POST,
        "/api/ui/tokens/create",
        vec![
            ("authorization", &format!("Bearer {jwt}")),
            ("hx-request", "true"),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        b"description=test&role=write&ttl_days=1".to_vec(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(ctx
        .state
        .tokens
        .as_ref()
        .unwrap()
        .list_all_tokens()
        .await
        .is_empty());
}

#[tokio::test]
async fn test_oidc_rule_scope_cannot_widen_provider_ceiling() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"))
        .mount(&mock_server)
        .await;

    // Narrow provider ceiling, rule that tries to widen to ["*"].
    let ctx = create_oidc_test_context_scoped(
        &mock_server.uri(),
        &["myorg/**"],
        Some(vec!["*".to_string()]),
    );
    let now = now_secs();
    let token = make_jwt(
        &mock_server.uri(),
        "repo:myorg/app:ref:refs/heads/main",
        "nora",
        now,
        now + 600,
    );
    let bearer = format!("Bearer {}", token);

    // Inside the provider ceiling: allowed.
    let response = send_with_headers(
        &ctx.app,
        Method::PUT,
        "/raw/myorg/repo/artifact.txt",
        vec![("authorization", &bearer)],
        b"inside".to_vec(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    // The rule's ["*"] must not lift the provider ceiling.
    let response = send_with_headers(
        &ctx.app,
        Method::PUT,
        "/raw/other/artifact.txt",
        vec![("authorization", &bearer)],
        b"escape".to_vec(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a rule namespace_scope of [\"*\"] must not widen past the provider scope"
    );
}

#[tokio::test]
async fn test_oidc_valid_jwt_read_only_blocks_write() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"))
        .mount(&mock_server)
        .await;

    let ctx = create_oidc_test_context(&mock_server.uri());
    let now = now_secs();
    // dev branch → read-only role
    let token = make_jwt(
        &mock_server.uri(),
        "repo:myorg/app:ref:refs/heads/dev",
        "nora",
        now,
        now + 600,
    );

    let bearer = format!("Bearer {}", token);
    let response = send_with_headers(
        &ctx.app,
        Method::PUT,
        "/raw/oidc-test.txt",
        vec![("authorization", &bearer)],
        b"hello".to_vec(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "Write with read-only OIDC token should be forbidden"
    );
}

#[tokio::test]
async fn test_oidc_valid_jwt_read_only_allows_get() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"))
        .mount(&mock_server)
        .await;

    let ctx = create_oidc_test_context(&mock_server.uri());
    let now = now_secs();
    let token = make_jwt(
        &mock_server.uri(),
        "repo:myorg/app:ref:refs/heads/dev",
        "nora",
        now,
        now + 600,
    );

    let bearer = format!("Bearer {}", token);
    // GET should succeed (even if file doesn't exist — 404 not 401/403)
    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/raw/nonexistent.txt",
        vec![("authorization", &bearer)],
        "",
    )
    .await;
    assert_ne!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Read with valid OIDC token should not be 401"
    );
    assert_ne!(
        response.status(),
        StatusCode::FORBIDDEN,
        "Read with read-only OIDC token should not be 403"
    );
}

#[tokio::test]
async fn test_oidc_expired_token_rejected() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"))
        .mount(&mock_server)
        .await;

    let ctx = create_oidc_test_context(&mock_server.uri());
    // Token expired 2 minutes ago (beyond 60s leeway)
    let now = now_secs();
    let token = make_jwt(
        &mock_server.uri(),
        "repo:myorg/app:ref:refs/heads/main",
        "nora",
        now - 600,
        now - 120,
    );

    let bearer = format!("Bearer {}", token);
    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/raw/test.txt",
        vec![("authorization", &bearer)],
        "",
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Expired OIDC token should be rejected"
    );
}

#[tokio::test]
async fn test_oidc_wrong_issuer_rejected() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"))
        .mount(&mock_server)
        .await;

    let ctx = create_oidc_test_context(&mock_server.uri());
    let now = now_secs();
    // Token has a different issuer than configured
    let token = make_jwt(
        "https://evil-issuer.example.com",
        "repo:myorg/app:ref:refs/heads/main",
        "nora",
        now,
        now + 600,
    );

    let bearer = format!("Bearer {}", token);
    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/raw/test.txt",
        vec![("authorization", &bearer)],
        "",
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Token with wrong issuer should be rejected"
    );
}

#[tokio::test]
async fn test_oidc_wrong_audience_rejected() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"))
        .mount(&mock_server)
        .await;

    let ctx = create_oidc_test_context(&mock_server.uri());
    let now = now_secs();
    // Token has wrong audience
    let token = make_jwt(
        &mock_server.uri(),
        "repo:myorg/app:ref:refs/heads/main",
        "wrong-audience",
        now,
        now + 600,
    );

    let bearer = format!("Bearer {}", token);
    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/raw/test.txt",
        vec![("authorization", &bearer)],
        "",
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Token with wrong audience should be rejected"
    );
}

/// The router answer to a write-role token with `aud`, against a mock
/// issuer whose provider gets `tweak`.
async fn oidc_status_for_aud(aud: &str, tweak: impl FnOnce(&mut OidcProvider)) -> StatusCode {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"))
        .mount(&mock_server)
        .await;
    let ctx = create_oidc_test_context_tweaked(&mock_server.uri(), tweak);
    let now = now_secs();
    let token = make_jwt(
        &mock_server.uri(),
        "repo:myorg/app:ref:refs/heads/main",
        aud,
        now,
        now + 600,
    );
    let bearer = format!("Bearer {token}");
    send_with_headers(
        &ctx.app,
        Method::PUT,
        "/raw/aud/file.txt",
        vec![("authorization", &bearer)],
        "data",
    )
    .await
    .status()
}

/// With an audience set, a token minted for that audience writes and one
/// minted for another service is refused.
#[tokio::test]
async fn test_oidc_audience_admits_only_its_own_aud() {
    assert!(oidc_status_for_aud("nora", |_| {}).await.is_success());
    assert_eq!(
        oidc_status_for_aud("another-service", |_| {}).await,
        StatusCode::UNAUTHORIZED
    );
}

/// `any_audience = true` turns the `aud` check off: a token minted for
/// another service writes.
#[tokio::test]
async fn test_oidc_any_audience_admits_any_aud() {
    let any = |p: &mut OidcProvider| {
        p.audience = String::new();
        p.any_audience = true;
    };
    assert!(oidc_status_for_aud("another-service", any)
        .await
        .is_success());
    assert!(oidc_status_for_aud("nora", any).await.is_success());
}

/// Beside an audience, `any_audience = true` changes nothing: the audience
/// is still checked.
#[tokio::test]
async fn test_oidc_audience_wins_over_any_audience() {
    let both = |p: &mut OidcProvider| p.any_audience = true;
    assert_eq!(
        oidc_status_for_aud("another-service", both).await,
        StatusCode::UNAUTHORIZED
    );
    assert!(oidc_status_for_aud("nora", both).await.is_success());
}

/// A provider with neither an audience nor `any_audience` admits no token,
/// even if it reaches the validator without passing config validation.
#[tokio::test]
async fn test_oidc_provider_without_audience_admits_no_token() {
    let none = |p: &mut OidcProvider| p.audience = String::new();
    assert_eq!(
        oidc_status_for_aud("another-service", none).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        oidc_status_for_aud("nora", none).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn test_oidc_no_matching_role_rejected() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"))
        .mount(&mock_server)
        .await;

    let ctx = create_oidc_test_context(&mock_server.uri());
    let now = now_secs();
    // Subject from a different org → no role_rules match
    let token = make_jwt(
        &mock_server.uri(),
        "repo:otherorg/app:ref:refs/heads/main",
        "nora",
        now,
        now + 600,
    );

    let bearer = format!("Bearer {}", token);
    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/raw/test.txt",
        vec![("authorization", &bearer)],
        "",
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Token with no matching role should be rejected"
    );
}

/// A valid OIDC JWT is served while the client address is locked out for
/// wrong passwords: the lockout counts passwords, not signed tokens.
#[tokio::test]
async fn test_oidc_valid_jwt_served_while_passwords_locked_out() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"))
        .mount(&mock_server)
        .await;
    let ctx = create_oidc_test_context(&mock_server.uri());
    // Lock the address out for every username.
    for n in 0..60 {
        ctx.state
            .auth_failures
            .record_failure("127.0.0.1".parse().unwrap(), &format!("u{n}"));
    }
    let now = now_secs();
    let jwt = make_jwt(
        &mock_server.uri(),
        "repo:myorg/app:ref:refs/heads/main",
        "nora",
        now,
        now + 600,
    );
    let bearer = format!("Bearer {jwt}");
    let response = send_with_headers(
        &ctx.app,
        Method::PUT,
        "/raw/locked-out/a.txt",
        vec![("authorization", &bearer)],
        b"data".to_vec(),
    )
    .await;
    assert!(
        response.status().is_success(),
        "a valid OIDC JWT from a locked-out address is refused: {}",
        response.status()
    );
}

#[tokio::test]
async fn test_oidc_token_lifetime_exceeded() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"))
        .mount(&mock_server)
        .await;

    let ctx = create_oidc_test_context(&mock_server.uri());
    let now = now_secs();
    // Token lifetime = 2000s, exceeds max_token_lifetime_secs = 900
    let token = make_jwt(
        &mock_server.uri(),
        "repo:myorg/app:ref:refs/heads/main",
        "nora",
        now,
        now + 2000,
    );

    let bearer = format!("Bearer {}", token);
    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/raw/test.txt",
        vec![("authorization", &bearer)],
        "",
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Token exceeding max lifetime should be rejected"
    );
}

#[tokio::test]
async fn test_oidc_jwks_fetch_failure_returns_401() {
    let mock_server = MockServer::start().await;

    // Don't mount any mock → JWKS fetch will 404
    let ctx = create_oidc_test_context(&mock_server.uri());
    let now = now_secs();
    let token = make_jwt(
        &mock_server.uri(),
        "repo:myorg/app:ref:refs/heads/main",
        "nora",
        now,
        now + 600,
    );

    let bearer = format!("Bearer {}", token);
    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/raw/test.txt",
        vec![("authorization", &bearer)],
        "",
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Should fail gracefully when JWKS cannot be fetched"
    );
}

#[tokio::test]
async fn test_oidc_symmetric_algorithm_rejected() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"))
        .mount(&mock_server)
        .await;

    let ctx = create_oidc_test_context(&mock_server.uri());
    let now = now_secs();

    // Create token signed with HS256 (symmetric) — should be rejected
    // even before JWKS fetch because of algorithm whitelist
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("test-key-1".to_string());
    let claims = json!({
        "iss": mock_server.uri(),
        "sub": "repo:myorg/app:ref:refs/heads/main",
        "aud": "nora",
        "iat": now,
        "exp": now + 600,
    });
    let key = EncodingKey::from_secret(b"fake-secret");
    let token = encode(&header, &claims, &key).unwrap();

    let bearer = format!("Bearer {}", token);
    let response = send_with_headers(
        &ctx.app,
        Method::GET,
        "/raw/test.txt",
        vec![("authorization", &bearer)],
        "",
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "HS256 tokens must be rejected for OIDC"
    );
}

/// A rejected JWT (unknown `kid` after the JWKS refetch, wrong audience, expiry,
/// bad signature) stays 401 but never feeds the lockout (R2-48): a JWT cannot
/// be guessed, so a stream of stale ones from a shared CI egress IP must not
/// lock out the valid JWT that follows from the same IP.
#[tokio::test]
async fn test_oidc_rejected_jwts_never_lock_out_a_valid_one() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"))
        .mount(&mock_server)
        .await;
    let ctx = create_oidc_test_context(&mock_server.uri());
    let issuer = mock_server.uri();
    let sub = "repo:myorg/app:ref:refs/heads/main";
    let now = now_secs();
    let get = |token: String| {
        let app = &ctx.app;
        async move {
            let bearer = format!("Bearer {token}");
            send_with_headers(
                app,
                Method::GET,
                "/raw/test.txt",
                vec![("authorization", &bearer)],
                "",
            )
            .await
            .status()
        }
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("rotated-key-2".to_string());
    let claims = json!({"iss": issuer, "sub": sub, "aud": "nora", "iat": now, "exp": now + 600});
    let key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY.as_bytes()).unwrap();
    let unknown_kid = encode(&header, &claims, &key).unwrap();
    for _ in 0..10 {
        assert_eq!(get(unknown_kid.clone()).await, StatusCode::UNAUTHORIZED);
    }

    let valid = make_jwt(&issuer, sub, "nora", now, now + 600);
    let (signed, _) = valid.rsplit_once('.').unwrap();
    let bad_signature = format!("{signed}.{}", "A".repeat(342));
    for token in [
        make_jwt(&issuer, sub, "wrong-audience", now, now + 600),
        make_jwt(&issuer, sub, "wrong-audience", now, now + 600),
        make_jwt(&issuer, sub, "nora", now - 600, now - 120),
        make_jwt(&issuer, sub, "nora", now - 600, now - 120),
        bad_signature,
    ] {
        assert_eq!(get(token).await, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(
        get(valid).await,
        StatusCode::NOT_FOUND,
        "valid JWT authenticates"
    );
}

/// R2-01: a workload identity (CI OIDC JWT, 15-min, namespace-scoped) must not
/// exchange itself for a long-lived, unscoped nra_ token, nor list/revoke tokens.
async fn jwks_server() -> MockServer {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"))
        .mount(&mock_server)
        .await;
    mock_server
}

fn basic_with(secret: &str) -> String {
    format!(
        "Basic {}",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("x:{secret}")
        )
    )
}

/// POST the OIDC session exchange with `auth`: the status and the JSON answer.
async fn exchange(ctx: &TestContext, auth: &str) -> (StatusCode, serde_json::Value) {
    let resp = send_with_headers(
        &ctx.app,
        Method::POST,
        crate::auth::oidc_session::SESSION_ROUTE,
        vec![("authorization", auth)],
        "",
    )
    .await;
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
    )
}

/// A session for `subject` from a JWT that has 30 s left.
async fn session_for(ctx: &TestContext, issuer: &str, subject: &str) -> String {
    let now = now_secs();
    let jwt = make_jwt(issuer, subject, "nora", now - 270, now + 30);
    let (status, body) = exchange(ctx, &format!("Bearer {jwt}")).await;
    assert_eq!(status, StatusCode::OK, "exchange for {subject}: {body}");
    let expires_in = body["expires_in"].as_u64().unwrap();
    assert!(
        (3590..=3600).contains(&expires_in),
        "expires_in={expires_in}"
    );
    body["token"].as_str().unwrap().to_string()
}

fn session_context(issuer: &str) -> TestContext {
    create_oidc_test_context_tweaked(issuer, |p| p.session_lifetime_secs = 3600)
}

/// #1649: a session lives the provider's session lifetime, not the JWT's, and
/// carries the JWT's grant: role, rule scope, read-only, over Bearer and Basic.
#[tokio::test]
async fn an_oidc_session_outlives_its_jwt_with_the_jwt_grant() {
    let mock_server = jwks_server().await;
    let issuer = mock_server.uri();
    let ctx = session_context(&issuer);

    let main = session_for(&ctx, &issuer, "repo:myorg/app:ref:refs/heads/main").await;
    assert!(main.starts_with("nrs_"));
    for auth in [format!("Bearer {main}"), basic_with(&main)] {
        let resp = send_with_headers(
            &ctx.app,
            Method::PUT,
            "/raw/session/a.txt",
            vec![("authorization", &auth)],
            b"from a session".to_vec(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "write via {auth:.6}");
    }

    let pr = session_for(&ctx, &issuer, "repo:myorg/app:pull_request").await;
    let bearer = format!("Bearer {pr}");
    for (uri, want) in [
        ("/raw/ci-transport/run-1/a.txt", StatusCode::OK),
        ("/raw/prod/a.txt", StatusCode::FORBIDDEN),
    ] {
        let resp = send_with_headers(
            &ctx.app,
            Method::PUT,
            uri,
            vec![("authorization", &bearer)],
            b"x".to_vec(),
        )
        .await;
        assert_eq!(resp.status(), want, "pull_request session PUT {uri}");
    }

    // A read-only identity exchanges too, and its session only reads.
    let dev = session_for(&ctx, &issuer, "repo:myorg/app:ref:refs/heads/dev").await;
    let bearer = format!("Bearer {dev}");
    let resp = send_with_headers(
        &ctx.app,
        Method::PUT,
        "/raw/session/b.txt",
        vec![("authorization", &bearer)],
        b"x".to_vec(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let resp = send_with_headers(
        &ctx.app,
        Method::GET,
        "/raw/session/a.txt",
        vec![("authorization", &bearer)],
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

/// A session never buys another session or an API token, and a forged or
/// expired one is a 401.
#[tokio::test]
async fn a_session_mints_nothing_and_a_forged_one_is_refused() {
    let mock_server = jwks_server().await;
    let issuer = mock_server.uri();
    let ctx = session_context(&issuer);
    let session = session_for(&ctx, &issuer, "repo:myorg/app:ref:refs/heads/main").await;

    for auth in [format!("Bearer {session}"), basic_with(&session)] {
        let (status, _) = exchange(&ctx, &auth).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "re-exchange via {auth:.6}");
        let resp = super::integration_tests::ui_create_token(&ctx, &auth, "write").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "mint via {auth:.6}");
    }

    let secret = "0".repeat(64);
    let far = now_secs() + 3000;
    let (expires_at, _) = session
        .strip_prefix("nrs_")
        .unwrap()
        .split_once('_')
        .unwrap();
    let moved = session.replacen(expires_at, &far.to_string(), 1);
    for forged in [
        format!("nrs_{far}_{secret}"),
        format!("nrs_1_{secret}"),
        moved,
    ] {
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/raw/session/a.txt",
            vec![("authorization", &format!("Bearer {forged}"))],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{forged:.20}");
    }
}

/// A JWT past its exp but inside the validation leeway buys no session.
#[tokio::test]
async fn an_expired_jwt_buys_no_session() {
    let mock_server = jwks_server().await;
    let issuer = mock_server.uri();
    let ctx = session_context(&issuer);
    let now = now_secs();
    let jwt = make_jwt(
        &issuer,
        "repo:myorg/app:ref:refs/heads/main",
        "nora",
        now - 300,
        now - 10,
    );
    let (status, _) = exchange(&ctx, &format!("Bearer {jwt}")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// No `session_lifetime_secs`: the provider grants no session, and a session
/// minted while it did stops working once its config no longer grants one.
#[tokio::test]
async fn a_provider_without_a_session_lifetime_grants_none() {
    let mock_server = jwks_server().await;
    let issuer = mock_server.uri();
    let ctx = create_oidc_test_context(&issuer);
    let now = now_secs();
    let jwt = make_jwt(
        &issuer,
        "repo:myorg/app:ref:refs/heads/main",
        "nora",
        now,
        now + 300,
    );
    let (status, _) = exchange(&ctx, &format!("Bearer {jwt}")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A session minted while the provider granted sessions is refused once its
    // config grants none: the grant is read from the config at every request.
    let granting = session_context(&issuer);
    let granting = granting.state.oidc.clone().unwrap();
    let identity = granting.validate_token(&jwt).await.unwrap();
    let (session, _) = granting
        .mint_session(&ctx.state.storage, &identity)
        .await
        .unwrap()
        .unwrap();
    assert!(granting
        .verify_session(&ctx.state.storage, &session)
        .await
        .is_ok());
    let resp = send_with_headers(
        &ctx.app,
        Method::GET,
        "/raw/anything.txt",
        vec![("authorization", &format!("Bearer {session}"))],
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// The sweep deletes expired session records and leaves live ones.
#[tokio::test]
async fn the_sweep_deletes_only_expired_sessions() {
    let mock_server = jwks_server().await;
    let issuer = mock_server.uri();
    let ctx = session_context(&issuer);
    let session = session_for(&ctx, &issuer, "repo:myorg/app:ref:refs/heads/main").await;
    let expired = ".nora-oidc-sessions/1-00.json";
    ctx.state.storage.put(expired, b"{}").await.unwrap();

    let oidc = ctx.state.oidc.clone().unwrap();
    assert_eq!(oidc.sweep_sessions(&ctx.state.storage).await, 1);
    assert!(ctx.state.storage.get(expired).await.is_err());
    let resp = send_with_headers(
        &ctx.app,
        Method::PUT,
        "/raw/session/c.txt",
        vec![("authorization", &format!("Bearer {session}"))],
        b"x".to_vec(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_oidc_identity_cannot_manage_api_tokens() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(TEST_JWKS_JSON, "application/json"))
        .mount(&mock_server)
        .await;
    let ctx = create_oidc_test_context(&mock_server.uri());
    let now = now_secs();
    let jwt = make_jwt(
        &mock_server.uri(),
        "repo:myorg/app:ref:refs/heads/main",
        "nora",
        now,
        now + 600,
    );
    let bearer = format!("Bearer {jwt}");
    let basic = format!(
        "Basic {}",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("x:{jwt}")
        )
    );
    for auth in [&bearer, &basic] {
        let resp = super::integration_tests::ui_create_token(&ctx, auth, "write").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "mint via {auth:.6}");
        // Nor through /ui/setup's "Generate token" (JS or JS-free post).
        for extra in [("hx-request", "true"), ("sec-fetch-site", "same-origin")] {
            let resp = send_with_headers(
                &ctx.app,
                Method::POST,
                "/api/ui/tokens/create",
                vec![
                    ("authorization", auth),
                    ("content-type", "application/x-www-form-urlencoded"),
                    ("accept", "application/json"),
                    extra,
                ],
                "description=x&role=read&ui=setup",
            )
            .await;
            assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "setup mint via {auth:.6}"
            );
        }
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/api/ui/tokens/list",
            vec![("authorization", auth)],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let resp = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/ui/tokens/0123456789abcdef/revoke",
            vec![("authorization", auth), ("hx-request", "true")],
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
    // The same JWT still writes to the registry.
    let resp = send_with_headers(
        &ctx.app,
        Method::PUT,
        "/raw/ci.txt",
        vec![("authorization", &bearer)],
        b"x".to_vec(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}
