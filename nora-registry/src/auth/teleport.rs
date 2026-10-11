// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Maestra fork: web UI identity from Teleport application access.
//!
//! A Teleport app agent adds `Teleport-Jwt-Assertion` (a JWT signed by the
//! cluster's JWT CA) to every request it proxies. On UI paths, from a peer in
//! `auth.teleport.trusted_proxies`, nora verifies it against the proxy JWKS and
//! takes `username` as the identity; `roles` ∩ `write_roles` decides write vs read.
//! Registry paths never look at the header: they keep token / OIDC auth.

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, HeaderMap, Request, StatusCode},
    response::{IntoResponse, Response},
};
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use parking_lot::RwLock;
use reqwest::Client;
use serde::Deserialize;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::config::TeleportConfig;
use crate::tokens::Role;

const HEADER: &str = "teleport-jwt-assertion";
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// On an unknown `kid`, refetch the JWKS if the cached set is older than this.
const KID_MISS_REFETCH: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq)]
pub struct TeleportIdentity {
    pub username: String,
    pub role: Role,
}

#[derive(Deserialize)]
struct Claims {
    #[serde(default)]
    username: String,
    #[serde(default)]
    roles: Vec<String>,
}

pub struct TeleportValidator {
    config: TeleportConfig,
    http: Client,
    jwks: RwLock<Option<(JwkSet, Instant)>>,
}

impl TeleportValidator {
    pub fn new(config: TeleportConfig, http: Client) -> Result<Self, String> {
        let missing: Vec<&str> = [
            ("jwks_url", config.jwks_url.is_empty()),
            ("issuer", config.issuer.is_empty()),
            ("audience", config.audience.is_empty()),
            ("trusted_proxies", config.trusted_proxies.is_empty()),
        ]
        .into_iter()
        .filter_map(|(k, empty)| empty.then_some(k))
        .collect();
        if !missing.is_empty() {
            return Err(format!(
                "auth.teleport is enabled but {} not set",
                missing.join(", ")
            ));
        }
        Ok(Self {
            config,
            http,
            jwks: RwLock::new(None),
        })
    }

    pub fn require_for_ui(&self) -> bool {
        self.config.require_for_ui
    }

    /// The verified identity behind a `trusted_header`, or `None` (logged).
    pub async fn identify(&self, jwt: &str) -> Option<TeleportIdentity> {
        match self.validate(jwt).await {
            Ok(identity) => Some(identity),
            Err(reason) => {
                tracing::warn!(reason = %reason, "Teleport JWT rejected");
                None
            }
        }
    }

    /// The `Teleport-Jwt-Assertion` value, when a trusted peer sent one.
    /// Returned owned: `Request<Body>` is not `Sync`, so it cannot be held
    /// across the verification await.
    pub fn trusted_header(&self, request: &Request<Body>) -> Option<String> {
        let jwt = request.headers().get(HEADER)?.to_str().ok()?;
        let peer = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip())?;
        if !self.config.trusted_proxies.contains(peer) {
            tracing::warn!(peer = %peer, "Teleport-Jwt-Assertion from a peer outside auth.teleport.trusted_proxies ignored");
            return None;
        }
        Some(jwt.to_string())
    }

    pub async fn validate(&self, jwt: &str) -> Result<TeleportIdentity, String> {
        let header = decode_header(jwt).map_err(|e| format!("invalid JWT header: {e}"))?;
        if !matches!(header.alg, Algorithm::ES256 | Algorithm::RS256) {
            return Err(format!("algorithm {:?} not allowed", header.alg));
        }
        let kid = header.kid.unwrap_or_default();
        let ttl = Duration::from_secs(self.config.jwks_cache_secs);
        let mut jwks = self.get_jwks(ttl).await?;
        if !has_key(&jwks, &kid) {
            // The CA may have rotated: refetch once, bounded against forged kids.
            jwks = self.get_jwks(ttl.min(KID_MISS_REFETCH)).await?;
        }

        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.validate_nbf = true;
        validation.leeway = self.config.leeway_secs;

        // Teleport publishes each key twice, with and without `kid`: a JWT
        // without `kid` is tried against every key.
        let mut last_err = format!("no key in JWKS for kid '{kid}'");
        for jwk in jwks
            .keys
            .iter()
            .filter(|k| kid.is_empty() || k.common.key_id.as_deref() == Some(kid.as_str()))
        {
            let Ok(key) = DecodingKey::from_jwk(jwk) else {
                continue;
            };
            match decode::<Claims>(jwt, &key, &validation) {
                Ok(data) => return self.identity(data.claims),
                Err(e) => last_err = format!("JWT validation failed: {e}"),
            }
        }
        Err(last_err)
    }

    fn identity(&self, claims: Claims) -> Result<TeleportIdentity, String> {
        if claims.username.is_empty() {
            return Err("JWT has no username claim".to_string());
        }
        let write = claims
            .roles
            .iter()
            .any(|r| self.config.write_roles.contains(r));
        Ok(TeleportIdentity {
            username: claims.username,
            role: if write { Role::Write } else { Role::Read },
        })
    }

    async fn get_jwks(&self, ttl: Duration) -> Result<JwkSet, String> {
        if let Some((jwks, at)) = self.jwks.read().as_ref() {
            if at.elapsed() < ttl {
                return Ok(jwks.clone());
            }
        }
        match self.fetch_jwks().await {
            Ok(jwks) => {
                *self.jwks.write() = Some((jwks.clone(), Instant::now()));
                Ok(jwks)
            }
            // Stale keys beat a UI outage while the proxy is unreachable.
            Err(e) => match self.jwks.read().as_ref() {
                Some((jwks, _)) => {
                    tracing::warn!(error = %e, "Teleport JWKS fetch failed, serving stale keys");
                    Ok(jwks.clone())
                }
                None => Err(format!("Teleport JWKS fetch failed: {e}")),
            },
        }
    }

    async fn fetch_jwks(&self) -> Result<JwkSet, String> {
        let resp = self
            .http
            .get(&self.config.jwks_url)
            .timeout(FETCH_TIMEOUT)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("JWKS endpoint returned {}", resp.status()));
        }
        resp.json::<JwkSet>().await.map_err(|e| e.to_string())
    }
}

fn has_key(jwks: &JwkSet, kid: &str) -> bool {
    kid.is_empty()
        || jwks
            .keys
            .iter()
            .any(|k| k.common.key_id.as_deref() == Some(kid))
}

/// The browse web surface served to people: the UI, its JSON/HTMX API, API docs.
pub fn is_ui_path(path: &str) -> bool {
    path == "/"
        || path.starts_with("/ui")
        || path.starts_with("/api/ui")
        || path.starts_with("/api-docs")
}

/// A browser rather than a package client: browsers send `Sec-Fetch-Mode`
/// and put `text/html` first in `Accept`; pip lists it last with q=0.01.
pub fn is_browser(headers: &HeaderMap) -> bool {
    headers.contains_key("sec-fetch-mode")
        || headers
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .is_some_and(|first| first.trim().starts_with("text/html"))
}

/// What a UI path answers without a Teleport identity under `require_for_ui`.
pub fn ui_only_response() -> Response {
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "Not found. The web UI is available only through Teleport application access.\n",
    )
        .into_response()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::{TeleportConfig, TrustedProxies};
    use crate::test_helpers::*;
    use axum::http::Method;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Test-only P-256 key; Teleport's JWT CA signs ES256.
    const TEST_EC_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgYLAqAJHSqDb0v3J7
LVxA8UAW0VHm48xBn9HQvT6aufuhRANCAAQZci8wvQzcOiZJuq4dDW9i6XIaFZ61
AJvDZc4Bbdm5PNsOvQZYEIacnJLnu7vP0RqnkhSbTJ0lRhSmCMjFDCjQ
-----END PRIVATE KEY-----"#;
    const KID: &str = "test-kid";
    pub(crate) const ISSUER: &str = "teleport.example.com";
    pub(crate) const AUDIENCE: &str = "http://nora-teleport.nora.svc.cluster.local:80";

    fn jwks_json() -> String {
        // Same key twice, with and without kid, as teleport.maestra.io serves it.
        let key = |kid: &str| {
            json!({"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": kid,
                   "x": "GXIvML0M3DomSbquHQ1vYulyGhWetQCbw2XOAW3ZuTw", "y": "2w69BlgQhpyckue7u8_RGqeSFJtMnSVGFKYIyMUMKNA"})
        };
        json!({"keys": [key(KID), key("")]}).to_string()
    }

    pub(crate) fn make_jwt(kid: Option<&str>, claims: serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = kid.map(str::to_string);
        let key = EncodingKey::from_ec_pem(TEST_EC_PRIVATE_KEY.as_bytes()).unwrap();
        encode(&header, &claims, &key).unwrap()
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    pub(crate) fn claims(username: &str, roles: &[&str]) -> serde_json::Value {
        json!({
            "iss": ISSUER, "aud": [AUDIENCE], "sub": username, "username": username,
            "roles": roles, "traits": {"logins": ["x"]},
            "nbf": now() - 10, "exp": now() + 3600,
        })
    }

    pub(crate) async fn jwks_server() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(jwks_json()))
            .mount(&server)
            .await;
        server
    }

    pub(crate) fn config(server: &MockServer, trusted: &str) -> TeleportConfig {
        TeleportConfig {
            enabled: true,
            jwks_url: format!("{}/.well-known/jwks.json", server.uri()),
            issuer: ISSUER.to_string(),
            audience: AUDIENCE.to_string(),
            trusted_proxies: TrustedProxies::parse(trusted),
            write_roles: vec!["apps".to_string()],
            require_for_ui: true,
            ..TeleportConfig::default()
        }
    }

    async fn validator() -> (MockServer, TeleportValidator) {
        let server = jwks_server().await;
        let v = TeleportValidator::new(config(&server, "127.0.0.1"), Client::new()).unwrap();
        (server, v)
    }

    #[tokio::test]
    async fn maps_roles_to_write_or_read() {
        let (_s, v) = validator().await;
        let jwt = make_jwt(Some(KID), claims("alice", &["apps", "auditor"]));
        assert_eq!(
            v.validate(&jwt).await.unwrap(),
            TeleportIdentity {
                username: "alice".into(),
                role: Role::Write
            }
        );
        let jwt = make_jwt(Some(KID), claims("bob", &["apps-ai"]));
        assert_eq!(v.validate(&jwt).await.unwrap().role, Role::Read);
    }

    #[tokio::test]
    async fn accepts_a_jwt_without_kid() {
        let (_s, v) = validator().await;
        let jwt = make_jwt(None, claims("alice", &["apps"]));
        assert_eq!(v.validate(&jwt).await.unwrap().username, "alice");
    }

    #[tokio::test]
    async fn rejects_wrong_audience_issuer_expiry_and_unknown_kid() {
        let (_s, v) = validator().await;
        let mut c = claims("alice", &["apps"]);
        c["aud"] = json!(["http://other-app:80"]);
        assert!(v.validate(&make_jwt(Some(KID), c)).await.is_err());
        let mut c = claims("alice", &["apps"]);
        c["iss"] = json!("evil.example.com");
        assert!(v.validate(&make_jwt(Some(KID), c)).await.is_err());
        let mut c = claims("alice", &["apps"]);
        c["exp"] = json!(now() - 3600);
        assert!(v.validate(&make_jwt(Some(KID), c)).await.is_err());
        let mut c = claims("alice", &["apps"]);
        c["username"] = json!("");
        assert!(v.validate(&make_jwt(Some(KID), c)).await.is_err());
        assert!(v
            .validate(&make_jwt(Some("rotated"), claims("alice", &["apps"])))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn rejects_a_jwt_signed_by_another_key() {
        let (_s, v) = validator().await;
        // Same claims, HS256 with a guessable secret: the algorithm gate refuses it.
        let jwt = encode(
            &Header::new(Algorithm::HS256),
            &claims("alice", &["apps"]),
            &EncodingKey::from_secret(b"x"),
        )
        .unwrap();
        assert!(v.validate(&jwt).await.is_err());
    }

    #[test]
    fn parses_the_deployed_config_shape() {
        let cfg: crate::config::AuthConfig = toml::from_str(
            r#"
            enabled = true
            htpasswd_allowed_peers = "127.0.0.1,::1"
            [teleport]
            enabled = true
            jwks_url = "https://teleport.maestra.io/.well-known/jwks.json"
            issuer = "teleport.maestra.io"
            audience = "http://nora-teleport.nora.svc.cluster.local:80"
            trusted_proxies = "10.62.0.0/16"
            write_roles = ["apps"]
            require_for_ui = true
            "#,
        )
        .unwrap();
        let peers = cfg.htpasswd_allowed_peers.unwrap();
        assert!(peers.contains("127.0.0.1".parse().unwrap()));
        assert!(!peers.contains("10.62.0.5".parse().unwrap()));
        assert!(cfg
            .teleport
            .trusted_proxies
            .contains("10.62.3.54".parse().unwrap()));
        assert!(TeleportValidator::new(cfg.teleport, Client::new()).is_ok());
        // Absent: upstream behaviour, passwords from any peer; Teleport off.
        let cfg: crate::config::AuthConfig = toml::from_str("enabled = true").unwrap();
        assert!(cfg.htpasswd_allowed_peers.is_none() && !cfg.teleport.enabled);
        assert!(cfg.teleport.trusted_proxies.is_empty());
    }

    #[test]
    fn incomplete_config_is_refused() {
        let err = TeleportValidator::new(
            TeleportConfig {
                enabled: true,
                ..TeleportConfig::default()
            },
            Client::new(),
        )
        .err()
        .unwrap();
        assert!(
            err.contains("jwks_url") && err.contains("trusted_proxies"),
            "{err}"
        );
    }

    #[test]
    fn browser_detection() {
        let h = |pairs: &[(&'static str, &'static str)]| {
            let mut m = HeaderMap::new();
            for (k, v) in pairs {
                m.insert(*k, v.parse().unwrap());
            }
            m
        };
        assert!(is_browser(&h(&[(
            "accept",
            "text/html,application/xhtml+xml,*/*;q=0.8"
        )])));
        assert!(is_browser(&h(&[("sec-fetch-mode", "navigate")])));
        assert!(!is_browser(&h(&[(
            "accept",
            "application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html; q=0.1, text/html; q=0.01"
        )])));
        assert!(!is_browser(&h(&[("accept", "application/json")])));
        assert!(!is_browser(&h(&[])));
    }

    // --- through the auth middleware -------------------------------------

    async fn setup(
        trusted: &str,
        customize: impl FnOnce(&mut crate::config::Config),
    ) -> (MockServer, TestContext) {
        let server = jwks_server().await;
        let tp = config(&server, trusted);
        let ctx = create_test_context_with_auth_and_config(&[("admin", "secret")], move |cfg| {
            cfg.auth.teleport = tp;
            cfg.auth.htpasswd_allowed_peers = Some(TrustedProxies::parse("10.255.255.1"));
            customize(cfg);
        });
        (server, ctx)
    }

    fn jwt_header(username: &str, roles: &[&str]) -> (&'static str, String) {
        (HEADER, make_jwt(Some(KID), claims(username, roles)))
    }

    async fn get(
        ctx: &TestContext,
        uri: &str,
        headers: Vec<(&str, String)>,
    ) -> axum::response::Response {
        let headers: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        send_with_headers(&ctx.app, Method::GET, uri, headers, vec![]).await
    }

    #[tokio::test]
    async fn ui_is_teleport_only() {
        let (_s, ctx) = setup("127.0.0.1", |_| {}).await;
        // No JWT: 404 on every UI path, never a Basic challenge.
        for uri in ["/", "/ui/", "/api/ui/stats", "/ui/tokens"] {
            let resp = get(&ctx, uri, vec![("accept", "text/html".into())]).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{uri}");
        }
        // A valid JWT opens the UI.
        let resp = get(&ctx, "/ui/", vec![jwt_header("alice", &["apps"])]).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = get(&ctx, "/api/ui/stats", vec![jwt_header("bob", &["apps-ai"])]).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn jwt_from_an_untrusted_peer_is_ignored() {
        let (_s, ctx) = setup("10.0.0.0/8", |_| {}).await;
        let resp = get(&ctx, "/ui/", vec![jwt_header("alice", &["apps"])]).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn registry_paths_ignore_the_jwt() {
        let (_s, ctx) = setup("127.0.0.1", |_| {}).await;
        let resp = get(&ctx, "/raw/some/file", vec![jwt_header("alice", &["apps"])]).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn no_basic_challenge_for_browsers_only() {
        let (_s, ctx) = setup("127.0.0.1", |_| {}).await;
        let resp = get(
            &ctx,
            "/raw/some/file",
            vec![("accept", "text/html,*/*".into())],
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(resp.headers().get(header::WWW_AUTHENTICATE).is_none());
        let resp = get(&ctx, "/raw/some/file", vec![]).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(resp.headers().get(header::WWW_AUTHENTICATE).is_some());
    }

    #[tokio::test]
    async fn teleport_user_mints_lists_and_revokes_own_tokens() {
        let (_s, ctx) = setup("127.0.0.1", |_| {}).await;
        let alice = jwt_header("alice", &["apps"]);
        let resp = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/ui/tokens/create",
            vec![
                (alice.0, alice.1.as_str()),
                ("hx-request", "true"),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            b"description=laptop&role=write&ttl_days=7".to_vec(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let html = String::from_utf8(body_bytes(resp).await.to_vec()).unwrap();
        let token = html
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .find(|w| w.starts_with("nra_"))
            .expect("minted token in the fragment")
            .to_string();
        // The token belongs to the Teleport identity and works on registry paths.
        let (owner, role) = ctx
            .state
            .tokens
            .as_ref()
            .unwrap()
            .verify_token(&token)
            .unwrap();
        assert_eq!((owner.as_str(), role), ("alice", Role::Write));
        let mine = ctx.state.tokens.as_ref().unwrap().list_tokens("alice");
        assert_eq!(mine.len(), 1);

        // Another user's token is invisible to alice: revoke answers 404.
        ctx.state
            .tokens
            .as_ref()
            .unwrap()
            .create_token("carol", 1, None, Role::Read)
            .unwrap();
        let carol_id = ctx.state.tokens.as_ref().unwrap().list_tokens("carol")[0]
            .file_id
            .clone();
        let revoke = |id: String| {
            let app = ctx.app.clone();
            let jwt = alice.1.clone();
            async move {
                send_with_headers(
                    &app,
                    Method::POST,
                    &format!("/api/ui/tokens/{id}/revoke"),
                    vec![(HEADER, jwt.as_str()), ("hx-request", "true")],
                    vec![],
                )
                .await
                .status()
            }
        };
        assert_eq!(revoke(carol_id).await, StatusCode::NOT_FOUND);
        assert_eq!(revoke(mine[0].file_id.clone()).await, StatusCode::OK);
        assert!(ctx
            .state
            .tokens
            .as_ref()
            .unwrap()
            .verify_token(&token)
            .is_err());
    }

    #[tokio::test]
    async fn read_identity_cannot_mint_a_write_token() {
        let (_s, ctx) = setup("127.0.0.1", |_| {}).await;
        let bob = jwt_header("bob", &["apps-ai"]);
        let mint = |role: &'static str| {
            let bob = bob.1.clone();
            let app = ctx.app.clone();
            async move {
                send_with_headers(
                    &app,
                    Method::POST,
                    "/api/ui/tokens/create",
                    vec![
                        (HEADER, bob.as_str()),
                        ("hx-request", "true"),
                        ("content-type", "application/x-www-form-urlencoded"),
                    ],
                    format!("description=x&role={role}").into_bytes(),
                )
                .await
                .status()
            }
        };
        assert_eq!(mint("write").await, StatusCode::FORBIDDEN);
        assert_eq!(mint("read").await, StatusCode::OK);
    }

    #[tokio::test]
    async fn htpasswd_only_from_allowed_peers() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let basic = format!("Basic {}", STANDARD.encode("admin:secret"));
        // Peer 127.0.0.1 is outside htpasswd_allowed_peers (10.255.255.1).
        let (_s, ctx) = setup("127.0.0.1", |_| {}).await;
        let resp = get(
            &ctx,
            "/raw/some/file",
            vec![("authorization", basic.clone())],
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let resp = send_with_headers(
            &ctx.app,
            Method::POST,
            "/api/tokens",
            vec![("content-type", "application/json")],
            br#"{"username":"admin","password":"secret"}"#.to_vec(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        // An nra_ token as the Basic password still works from anywhere.
        let token = ctx
            .state
            .tokens
            .as_ref()
            .unwrap()
            .create_token("ci", 1, None, Role::Read)
            .unwrap();
        let basic = format!("Basic {}", STANDARD.encode(format!("x:{token}")));
        let resp = get(&ctx, "/raw/some/file", vec![("authorization", basic)]).await;
        assert_ne!(resp.status(), StatusCode::UNAUTHORIZED);

        // Loopback allowed (kubectl port-forward): the password works again.
        let (_s, ctx) = setup("127.0.0.1", |cfg| {
            cfg.auth.htpasswd_allowed_peers = Some(TrustedProxies::parse("127.0.0.1,::1"));
        })
        .await;
        let basic = format!("Basic {}", STANDARD.encode("admin:secret"));
        let resp = get(&ctx, "/raw/some/file", vec![("authorization", basic)]).await;
        assert_ne!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
