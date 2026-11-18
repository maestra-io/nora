// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::config::basic_auth_header;
use nora_registry::npm_links::same_origin;
use parking_lot::RwLock;
use reqwest::Url;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Cached Docker registry token
struct CachedToken {
    token: String,
    expires_at: Instant,
}

/// Why a 401 challenge got no token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    /// The upstream will not let NORA in with what it has (#1196): its challenge is not one
    /// that a token answers (`Basic`, another scheme, none at all), or its token server refused
    /// the credentials with 401 or 403. A configuration fault, not an outage.
    Refused,
    /// The token server could not be reached, or its challenge or answer was unusable.
    Unavailable,
}

/// Docker registry authentication handler
/// Manages Bearer token acquisition and caching for upstream registries
#[derive(Clone)]
pub struct DockerAuth {
    /// Shared by every clone, so a spool resuming a blob reuses the token that opened it.
    tokens: Arc<RwLock<HashMap<String, CachedToken>>>,
    client: reqwest::Client,
    timeout: Duration,
    /// Per upstream url: the hosts besides its own origin whose `https` realm it may name.
    token_hosts: Arc<HashMap<String, Vec<String>>>,
}

/// The most tokens cached at once: past it, expired ones are dropped, and when every one is
/// still live a new token is used uncached.
const TOKEN_CACHE_MAX: usize = 4096;

/// The largest token answer read. Real ones are a few KiB.
const MAX_TOKEN_BODY: u64 = 1 << 20;

impl DockerAuth {
    /// Create a new DockerAuth using the provided HTTP client.
    ///
    /// The client should be pre-configured with any required TLS settings
    /// (e.g. custom CA certificates). The timeout is applied per-request.
    pub fn new(client: reqwest::Client, timeout: u64) -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            client,
            timeout: Duration::from_secs(timeout),
            token_hosts: Arc::default(),
        }
    }

    /// The `token_hosts` of each upstream, so its token server may sit off its own origin.
    pub fn with_token_hosts(mut self, upstreams: &[crate::config::DockerUpstream]) -> Self {
        self.token_hosts = Arc::new(
            upstreams
                .iter()
                .filter(|u| !u.token_hosts.is_empty())
                .map(|u| {
                    let hosts = u.token_hosts.iter();
                    let hosts = hosts.map(|h| h.trim().to_ascii_lowercase()).collect();
                    (u.url.trim_end_matches('/').to_string(), hosts)
                })
                .collect(),
        );
        self
    }

    /// Drop expired tokens (maintenance tick).
    pub fn prune_expired(&self) {
        let now = Instant::now();
        self.tokens.write().retain(|_, t| t.expires_at > now);
    }

    /// Get a valid token for the given registry and repository scope
    /// Returns cached token if still valid, otherwise fetches a new one
    pub async fn get_token(
        &self,
        registry_url: &str,
        name: &str,
        www_authenticate: Option<&str>,
        basic_auth: Option<&str>,
    ) -> Result<String, TokenError> {
        // A token is the credential's that fetched it: two upstream entries on one url with
        // different credentials (or none) do not share it.
        let cache_key = match basic_auth {
            Some(credentials) => {
                use sha2::Digest as _;
                let id = hex::encode(sha2::Sha256::digest(credentials.as_bytes()));
                format!("{registry_url}:{name}#{}", &id[..16])
            }
            None => format!("{registry_url}:{name}"),
        };

        // Check cache first
        {
            let tokens = self.tokens.read();
            if let Some(cached) = tokens.get(&cache_key) {
                if cached.expires_at > Instant::now() {
                    return Ok(cached.token.clone());
                }
            }
        }

        // Need to fetch a new token. A 401 without a challenge names no way in.
        let www_auth = www_authenticate.ok_or(TokenError::Refused)?;
        let (token, lifetime) = self
            .fetch_token(registry_url, www_auth, name, basic_auth)
            .await?;

        // Cache the token for the lifetime the token server gave it, less a margin
        // for the request that will carry it.
        // Every name a reader asks for is a key: the map is bounded.
        if let Some(ttl) = lifetime.checked_sub(TOKEN_EXPIRY_MARGIN) {
            let mut tokens = self.tokens.write();
            let now = Instant::now();
            if tokens.len() >= TOKEN_CACHE_MAX && !tokens.contains_key(&cache_key) {
                tokens.retain(|_, t| t.expires_at > now);
            }
            if tokens.len() < TOKEN_CACHE_MAX || tokens.contains_key(&cache_key) {
                let token = token.clone();
                let expires_at = now + ttl;
                tokens.insert(cache_key, CachedToken { token, expires_at });
            }
        }

        Ok(token)
    }

    /// Parse Www-Authenticate header and fetch token from auth server
    /// Format: Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull"
    ///
    /// Returns the token and its remaining lifetime (see [`token_lifetime`]).
    async fn fetch_token(
        &self,
        registry_url: &str,
        www_authenticate: &str,
        name: &str,
        basic_auth: Option<&str>,
    ) -> Result<(String, Duration), TokenError> {
        // Not a Bearer challenge (Harbor answers `Basic realm="harbor"` to a robot account
        // without access): no token can answer it.
        let params = parse_www_authenticate(www_authenticate).ok_or(TokenError::Refused)?;

        let realm = params.get("realm").ok_or(TokenError::Unavailable)?;

        // Validate realm URL scheme — only HTTP(S) allowed
        let mut url = match Url::parse(realm) {
            Ok(url) if matches!(url.scheme(), "https" | "http") => url,
            _ => {
                tracing::warn!(realm = %realm, "Rejecting auth realm with non-HTTP(S) scheme");
                return Err(TokenError::Unavailable);
            }
        };

        // The upstream's credential goes, and the answer comes back to it, only where the
        // upstream itself or its operator-listed token server answers.
        let extra = self.token_hosts.get(registry_url.trim_end_matches('/'));
        let extra = extra.map(Vec::as_slice).unwrap_or_default();
        let upstream = Url::parse(registry_url).ok();
        if !upstream.is_some_and(|up| realm_allowed(&url, &up, extra)) {
            tracing::warn!(
                upstream = %registry_url,
                realm_host = url.host_str().unwrap_or(""),
                "Refusing a token realm off the upstream's origin; if it is the upstream's \
                 own token server, list its host in the upstream's token_hosts"
            );
            return Err(TokenError::Refused);
        }

        let service = params.get("service").map(|s| s.as_str()).unwrap_or("");

        // Build token request URL
        let scope = format!("repository:{}:pull", name);
        url.query_pairs_mut()
            .append_pair("service", service)
            .append_pair("scope", &scope);

        tracing::debug!(url = %url, "Fetching auth token");

        let mut request = self.client.get(url).timeout(self.timeout);
        if let Some(credentials) = basic_auth {
            request = request.header("Authorization", basic_auth_header(credentials));
            tracing::debug!("Using basic auth for token request");
        }

        let response = request.send().await.map_err(|_| TokenError::Unavailable)?;

        let status = response.status();
        if !status.is_success() {
            tracing::warn!(status = %status, "Token request failed");
            // Docker Hub answers wrong credentials with 401 "incorrect username or password".
            return Err(match status {
                reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => {
                    TokenError::Refused
                }
                _ => TokenError::Unavailable,
            });
        }

        let body = super::read_capped(response, MAX_TOKEN_BODY)
            .await
            .map_err(|e| {
                tracing::warn!(upstream = %registry_url, error = ?e, "Unreadable token answer");
                TokenError::Unavailable
            })?;
        let json: serde_json::Value =
            serde_json::from_slice(&body).map_err(|_| TokenError::Unavailable)?;

        // Docker Hub returns "token", some registries return "access_token"
        let token = json
            .get("token")
            .or_else(|| json.get("access_token"))
            .and_then(|v| v.as_str())
            .map(String::from)
            .ok_or(TokenError::Unavailable)?;
        Ok((token, token_lifetime(&json, chrono::Utc::now())))
    }
}

/// Subtracted from a token's lifetime before caching it, so a cached token is not
/// sent in the last seconds of its validity.
const TOKEN_EXPIRY_MARGIN: Duration = Duration::from_secs(10);

/// Remaining lifetime of a token response at `now`, per the Docker token spec:
/// `expires_in` seconds (60 when absent) counted from `issued_at` (now when absent
/// or unparsable). A token issued with a 60 s lifetime must not be cached for 300 s.
fn token_lifetime(json: &serde_json::Value, now: chrono::DateTime<chrono::Utc>) -> Duration {
    let expires_in = json
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(60);
    let age = json
        .get("issued_at")
        .and_then(|v| v.as_str())
        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
        .map(|issued| {
            (now - issued.with_timezone(&chrono::Utc))
                .num_seconds()
                .max(0) as u64
        })
        .unwrap_or(0);
    Duration::from_secs(expires_in.saturating_sub(age))
}

/// A realm NORA asks for a token: on the upstream's own origin, or `https` on a listed
/// token host (`registry-1.docker.io` → `auth.docker.io` built in). Never with a fragment,
/// which would cut off the query NORA appends.
fn realm_allowed(realm: &Url, upstream: &Url, token_hosts: &[String]) -> bool {
    if realm.fragment().is_some() {
        return false;
    }
    if same_origin(realm, upstream) {
        return true;
    }
    let Some(host) = realm.host_str() else {
        return false;
    };
    let authority = match realm.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    let builtin =
        upstream.host_str() == Some("registry-1.docker.io") && authority == "auth.docker.io";
    realm.scheme() == "https" && (builtin || token_hosts.contains(&authority))
}

impl Default for DockerAuth {
    fn default() -> Self {
        Self::new(reqwest::Client::new(), 60)
    }
}

/// Parse Www-Authenticate header into key-value pairs
/// Example: Bearer realm="https://auth.docker.io/token",service="registry.docker.io"
fn parse_www_authenticate(header: &str) -> Option<HashMap<String, String>> {
    let header = header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))?;

    let mut params = HashMap::new();

    for part in header.split(',') {
        let part = part.trim();
        if let Some((key, value)) = part.split_once('=') {
            let value = value.trim_matches('"');
            params.insert(key.to_string(), value.to_string());
        }
    }

    Some(params)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_www_authenticate() {
        let header = r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull""#;
        let params = parse_www_authenticate(header).unwrap();

        assert_eq!(
            params.get("realm"),
            Some(&"https://auth.docker.io/token".to_string())
        );
        assert_eq!(
            params.get("service"),
            Some(&"registry.docker.io".to_string())
        );
    }

    #[test]
    fn test_parse_www_authenticate_lowercase() {
        let header = r#"bearer realm="https://ghcr.io/token",service="ghcr.io""#;
        let params = parse_www_authenticate(header).unwrap();

        assert_eq!(
            params.get("realm"),
            Some(&"https://ghcr.io/token".to_string())
        );
    }

    #[test]
    fn test_parse_www_authenticate_no_bearer() {
        assert!(parse_www_authenticate("Basic realm=\"test\"").is_none());
    }

    #[test]
    fn test_parse_www_authenticate_empty() {
        assert!(parse_www_authenticate("").is_none());
    }

    #[test]
    fn test_parse_www_authenticate_partial() {
        let header = r#"Bearer realm="https://example.com/token""#;
        let params = parse_www_authenticate(header).unwrap();
        assert_eq!(
            params.get("realm"),
            Some(&"https://example.com/token".to_string())
        );
        assert!(!params.contains_key("service"));
    }

    /// C55: the cache lifetime comes from `expires_in`/`issued_at`, not a fixed 300 s.
    #[test]
    fn test_token_lifetime_honours_expires_in_and_issued_at() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-11T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let life = |j: serde_json::Value| token_lifetime(&j, now).as_secs();
        assert_eq!(
            life(serde_json::json!({"token": "t", "expires_in": 300})),
            300
        );
        assert_eq!(life(serde_json::json!({"token": "t"})), 60, "spec default");
        assert_eq!(
            life(serde_json::json!({"expires_in": 300, "issued_at": "2026-10-11T11:59:00Z"})),
            240,
            "counted from issued_at"
        );
        assert_eq!(
            life(serde_json::json!({"expires_in": 60, "issued_at": "2026-10-11T11:00:00Z"})),
            0,
            "already expired"
        );
    }

    /// A token server answering a 30 s `expires_in` is cached for 20 s (margin 10 s),
    /// and a lifetime within the margin is not cached at all.
    #[tokio::test]
    async fn test_get_token_caches_for_the_token_lifetime() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        for (expires_in, cached) in [(30u64, true), (5, false)] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(
                        serde_json::json!({"token": "tok", "expires_in": expires_in}),
                    ),
                )
                .mount(&server)
                .await;
            let auth = DockerAuth::default();
            let header = format!(r#"Bearer realm="{}/token",service="s""#, server.uri());
            let token = auth
                .get_token(&server.uri(), "lib/x", Some(&header), None)
                .await;
            assert_eq!(token.as_deref().ok(), Some("tok"));
            let tokens = auth.tokens.read();
            match tokens.get(&format!("{}:lib/x", server.uri())) {
                Some(t) => {
                    assert!(cached, "expires_in {expires_in} must not be cached");
                    let left = t.expires_at.saturating_duration_since(Instant::now());
                    assert!(left <= Duration::from_secs(20) && left > Duration::from_secs(15));
                }
                None => assert!(!cached, "expires_in {expires_in} must be cached"),
            }
        }
    }

    /// R4-R09 (review): a token is cached per credential: an entry without credentials, or
    /// with others, on the same registry and repository fetches its own.
    #[tokio::test]
    async fn test_get_token_is_cached_per_credential() {
        use wiremock::matchers::{header, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        for (user, token) in [("a", "tok-a"), ("b", "tok-b")] {
            Mock::given(method("GET"))
                .and(header(
                    "authorization",
                    basic_auth_header(&format!("{user}:x")).as_str(),
                ))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({"token": token, "expires_in": 300})),
                )
                .mount(&server)
                .await;
        }
        Mock::given(method("GET"))
            .and(wiremock::matchers::any())
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"token": "anonymous", "expires_in": 300})),
            )
            .mount(&server)
            .await;
        let auth = DockerAuth::default();
        let challenge = format!(r#"Bearer realm="{}/token",service="s""#, server.uri());
        for (credentials, want) in [
            (Some("a:x"), "tok-a"),
            (Some("b:x"), "tok-b"),
            (None, "anonymous"),
            (Some("a:x"), "tok-a"),
        ] {
            let token = auth
                .get_token(&server.uri(), "lib/x", Some(&challenge), credentials)
                .await;
            assert_eq!(token.as_deref().ok(), Some(want), "{credentials:?}");
        }
    }

    #[test]
    fn test_docker_auth_default() {
        let auth = DockerAuth::default();
        assert!(auth.tokens.read().is_empty());
    }

    #[test]
    fn test_docker_auth_new() {
        let auth = DockerAuth::new(reqwest::Client::new(), 30);
        assert!(auth.tokens.read().is_empty());
    }

    #[tokio::test]
    async fn test_get_token_no_www_authenticate() {
        let auth = DockerAuth::default();
        let result = auth
            .get_token("https://registry.example.com", "library/test", None, None)
            .await;
        assert_eq!(result, Err(TokenError::Refused));
    }

    #[tokio::test]
    async fn test_get_token_cache_hit() {
        let auth = DockerAuth::default();
        // Manually insert a cached token
        {
            let mut tokens = auth.tokens.write();
            tokens.insert(
                "https://registry.example.com:library/test".to_string(),
                CachedToken {
                    token: "cached-token-123".to_string(),
                    expires_at: Instant::now() + Duration::from_secs(300),
                },
            );
        }
        let result = auth
            .get_token("https://registry.example.com", "library/test", None, None)
            .await;
        assert_eq!(result, Ok("cached-token-123".to_string()));
    }

    #[tokio::test]
    async fn test_get_token_cache_expired() {
        let auth = DockerAuth::default();
        {
            let mut tokens = auth.tokens.write();
            tokens.insert(
                "https://registry.example.com:library/test".to_string(),
                CachedToken {
                    token: "expired-token".to_string(),
                    expires_at: Instant::now() - Duration::from_secs(1),
                },
            );
        }
        // Without www_authenticate, no new token can be fetched
        let result = auth
            .get_token("https://registry.example.com", "library/test", None, None)
            .await;
        assert_eq!(result, Err(TokenError::Refused));
    }

    #[test]
    fn test_parse_www_authenticate_bearer_only() {
        let params = parse_www_authenticate("Bearer ").unwrap();
        assert!(params.is_empty());
    }

    #[test]
    fn test_parse_www_authenticate_missing_realm() {
        let header = r#"Bearer service="registry.docker.io""#;
        let params = parse_www_authenticate(header).unwrap();
        assert!(params.get("realm").is_none());
        assert_eq!(
            params.get("service"),
            Some(&"registry.docker.io".to_string())
        );
    }

    #[test]
    fn test_parse_www_authenticate_missing_service() {
        let header = r#"Bearer realm="https://auth.docker.io/token""#;
        let params = parse_www_authenticate(header).unwrap();
        assert_eq!(
            params.get("realm"),
            Some(&"https://auth.docker.io/token".to_string())
        );
        assert!(params.get("service").is_none());
    }

    #[test]
    fn test_parse_www_authenticate_malformed_kv() {
        let header = r#"Bearer garbage,realm="https://auth.docker.io/token""#;
        let params = parse_www_authenticate(header).unwrap();
        assert_eq!(
            params.get("realm"),
            Some(&"https://auth.docker.io/token".to_string())
        );
    }

    #[tokio::test]
    async fn test_fetch_token_invalid_url() {
        let auth = DockerAuth::new(reqwest::Client::new(), 1);
        let result = auth
            .get_token(
                "http://127.0.0.1:1",
                "library/test",
                Some(r#"Bearer realm="http://127.0.0.1:1/token",service="test""#),
                None,
            )
            .await;
        assert_eq!(result, Err(TokenError::Unavailable));
    }

    /// #1196: how a challenge that yields no token is told apart. A refusal is the upstream
    /// keeping NORA out (a challenge no token answers, the token server's 401 or 403); anything
    /// else that yields no token is the token server failing.
    #[tokio::test]
    async fn a_refused_token_is_told_from_an_unavailable_one() {
        use wiremock::{Mock, MockServer, ResponseTemplate};

        for (challenge, token_answer, want) in [
            ("Basic realm=\"harbor\"", None, Err(TokenError::Refused)),
            ("Negotiate", None, Err(TokenError::Refused)),
            ("", None, Err(TokenError::Refused)),
            (
                "Bearer",
                Some(ResponseTemplate::new(401)),
                Err(TokenError::Refused),
            ),
            (
                "Bearer",
                Some(ResponseTemplate::new(403)),
                Err(TokenError::Refused),
            ),
            (
                "Bearer",
                Some(ResponseTemplate::new(500)),
                Err(TokenError::Unavailable),
            ),
            (
                "Bearer",
                Some(ResponseTemplate::new(429)),
                Err(TokenError::Unavailable),
            ),
            (
                "Bearer",
                Some(ResponseTemplate::new(404)),
                Err(TokenError::Unavailable),
            ),
            (
                "Bearer",
                Some(ResponseTemplate::new(200).set_body_string("not json")),
                Err(TokenError::Unavailable),
            ),
            (
                "Bearer",
                Some(ResponseTemplate::new(200).set_body_json(serde_json::json!({}))),
                Err(TokenError::Unavailable),
            ),
            (
                "Bearer",
                Some(ResponseTemplate::new(200).set_body_json(serde_json::json!({"token": "t"}))),
                Ok("t".to_string()),
            ),
            (
                "Bearer",
                Some(
                    ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({"access_token": "a"})),
                ),
                Ok("a".to_string()),
            ),
        ] {
            let server = MockServer::start().await;
            let challenge = if challenge == "Bearer" {
                format!("Bearer realm=\"{}/token\",service=\"s\"", server.uri())
            } else {
                challenge.to_string()
            };
            let asked_token_server = token_answer.is_some();
            if let Some(answer) = token_answer {
                Mock::given(wiremock::matchers::any())
                    .respond_with(answer)
                    .mount(&server)
                    .await;
            }
            let auth = DockerAuth::new(reqwest::Client::new(), 5);
            let got = auth
                .get_token(
                    &server.uri(),
                    "project1/service1",
                    Some(&challenge),
                    Some("robot:secret"),
                )
                .await;
            assert_eq!(got, want, "{challenge:?}");
            assert_eq!(
                !server.received_requests().await.unwrap().is_empty(),
                asked_token_server,
                "{challenge:?}: token server asked"
            );
        }
    }

    #[tokio::test]
    async fn test_fetch_token_missing_realm_in_header() {
        let auth = DockerAuth::default();
        let result = auth
            .get_token(
                "https://registry.example.com",
                "library/test",
                Some(r#"Bearer service="registry.docker.io""#),
                None,
            )
            .await;
        assert_eq!(result, Err(TokenError::Unavailable));
    }

    /// A014: a realm is followed on the upstream's own origin, or over https on a token host
    /// (built-in Docker Hub, or listed); never with a fragment or a downgrade.
    #[test]
    fn a_realm_is_bound_to_the_upstream() {
        let url = |u: &str| Url::parse(u).unwrap();
        let listed = ["ghcr.io".to_string(), "tok.example:8443".to_string()];
        let hub = url("https://registry-1.docker.io");
        let own = url("https://reg.example");
        for (upstream, realm, ok) in [
            (&hub, "https://auth.docker.io/token", true),
            (&hub, "http://auth.docker.io/token", false),
            (&hub, "https://auth.docker.io:8443/token", false),
            (&own, "https://auth.docker.io/token", false),
            (&own, "https://reg.example/token?x=1", true),
            (&own, "https://reg.example/token#", false),
            (&own, "http://reg.example/token", false),
            (&own, "https://reg.example:8443/token", false),
            (&own, "https://ghcr.io/token", true),
            (&own, "http://ghcr.io/token", false),
            (&own, "https://ghcr.io:8443/token", false),
            (&own, "https://tok.example:8443/token", true),
            (&own, "https://tok.example/token", false),
            (&own, "https://elsewhere.example/token", false),
            // Audit R07: a realm on a metadata/loopback IP literal is off the origin too.
            (&own, "http://169.254.169.254/latest/meta-data", false),
            (&own, "https://127.0.0.1:9100/metrics", false),
        ] {
            assert_eq!(
                realm_allowed(&url(realm), upstream, &listed),
                ok,
                "{upstream} {realm}"
            );
        }
    }

    /// A014: a realm off the upstream's origin gets no request and no credential; a listed
    /// token host is matched per upstream url; service and scope are encoded.
    #[tokio::test]
    async fn get_token_follows_only_a_realm_bound_to_the_upstream() {
        use wiremock::matchers::{any, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let other = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"token": "MARKER"})),
            )
            .mount(&other)
            .await;
        let upstream = MockServer::start().await;
        let auth = DockerAuth::default();
        for realm in [
            format!("{}/t", other.uri()),
            format!("{}/t?x=1#", other.uri()),
            format!("{}/t#", upstream.uri()),
        ] {
            let challenge = format!(r#"Bearer realm="{realm}",service="s""#);
            let got = auth
                .get_token(
                    &upstream.uri(),
                    "library/x",
                    Some(&challenge),
                    Some("u:dummy"),
                )
                .await;
            assert_eq!(got, Err(TokenError::Refused), "{realm}");
        }
        assert!(other.received_requests().await.unwrap().is_empty());
        assert!(upstream.received_requests().await.unwrap().is_empty());

        // Listing the other origin's host for this upstream does not admit plain http.
        let other_host = other.address().to_string();
        let mut entry: crate::config::DockerUpstream =
            toml::from_str(&format!("url = \"{}/\"", upstream.uri())).unwrap();
        entry.token_hosts = vec![format!(" {other_host} ")];
        let listed = DockerAuth::default().with_token_hosts(&[entry]);
        assert_eq!(
            listed.token_hosts.get(&upstream.uri()),
            Some(&vec![other_host])
        );
        let challenge = format!(r#"Bearer realm="{}/t",service="s""#, other.uri());
        let got = listed
            .get_token(&upstream.uri(), "library/x", Some(&challenge), None)
            .await;
        assert_eq!(got, Err(TokenError::Refused));
        assert!(other.received_requests().await.unwrap().is_empty());

        // The upstream's own realm: answered, with the query encoded pair by pair.
        Mock::given(query_param("service", "s&scope=evil"))
            .and(query_param("scope", "repository:library/x:pull"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"token": "own"})),
            )
            .mount(&upstream)
            .await;
        let challenge = format!(
            r#"Bearer realm="{}/token",service="s&scope=evil""#,
            upstream.uri()
        );
        let got = auth
            .get_token(&upstream.uri(), "library/x", Some(&challenge), None)
            .await;
        assert_eq!(got.as_deref(), Ok("own"));
        let asked = upstream.received_requests().await.unwrap();
        let pairs: Vec<_> = asked[0].url.query_pairs().collect();
        assert_eq!(pairs.iter().filter(|(k, _)| k == "scope").count(), 1);
    }

    /// A055: a token answer is read up to 1 MiB, declared length or not.
    #[tokio::test]
    async fn a_token_answer_over_the_cap_is_unavailable() {
        use std::io::Write as _;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        for (pad, want) in [
            (1024, Ok("tok".to_string())),
            (MAX_TOKEN_BODY as usize + 1, Err(TokenError::Unavailable)),
        ] {
            let doc = serde_json::json!({"access_token": "tok", "x": "p".repeat(pad)});
            let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            gz.write_all(doc.to_string().as_bytes()).unwrap();
            let server = MockServer::start().await;
            Mock::given(wiremock::matchers::any())
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("Content-Type", "application/json")
                        .insert_header("Content-Encoding", "gzip")
                        .set_body_bytes(gz.finish().unwrap()),
                )
                .mount(&server)
                .await;
            let challenge = format!(r#"Bearer realm="{}/t",service="s""#, server.uri());
            let got = DockerAuth::default()
                .get_token(&server.uri(), "library/x", Some(&challenge), None)
                .await;
            assert_eq!(got, want, "pad {pad}");
        }
    }

    fn cached(expires_at: Instant) -> CachedToken {
        let token = "old".to_string();
        CachedToken { token, expires_at }
    }

    async fn token_server() -> wiremock::MockServer {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(wiremock::matchers::any())
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"token": "tok", "expires_in": 30})),
            )
            .mount(&server)
            .await;
        server
    }

    /// A062: a cache full of live tokens stays at the cap and the new token is still used.
    #[tokio::test]
    async fn test_get_token_cache_is_bounded() {
        let server = token_server().await;
        let auth = DockerAuth::default();
        let live = Instant::now() + Duration::from_secs(300);
        auth.tokens
            .write()
            .extend((0..TOKEN_CACHE_MAX).map(|i| (format!("k{i}"), cached(live))));
        let challenge = format!(r#"Bearer realm="{}/t",service="s""#, server.uri());
        for name in ["lib/new", "lib/other"] {
            let got = auth
                .get_token(&server.uri(), name, Some(&challenge), None)
                .await;
            assert_eq!(got.as_deref(), Ok("tok"));
        }
        let tokens = auth.tokens.read();
        assert_eq!(tokens.len(), TOKEN_CACHE_MAX);
        assert!(!tokens.contains_key(&format!("{}:lib/new", server.uri())));
    }

    /// A062: at the cap, expired tokens make room for the new one.
    #[tokio::test]
    async fn test_get_token_drops_expired_at_cap() {
        let server = token_server().await;
        let auth = DockerAuth::default();
        let gone = Instant::now() - Duration::from_secs(1);
        auth.tokens
            .write()
            .extend((0..TOKEN_CACHE_MAX).map(|i| (format!("k{i}"), cached(gone))));
        let challenge = format!(r#"Bearer realm="{}/t",service="s""#, server.uri());
        let got = auth
            .get_token(&server.uri(), "lib/new", Some(&challenge), None)
            .await;
        assert_eq!(got.as_deref(), Ok("tok"));
        let tokens = auth.tokens.read();
        assert_eq!(tokens.len(), 1);
        assert!(tokens.contains_key(&format!("{}:lib/new", server.uri())));
    }

    /// A062: the maintenance sweep drops expired tokens only.
    #[test]
    fn test_prune_expired() {
        let auth = DockerAuth::default();
        let now = Instant::now();
        auth.tokens.write().extend([
            ("gone".to_string(), cached(now - Duration::from_secs(1))),
            ("live".to_string(), cached(now + Duration::from_secs(300))),
        ]);
        auth.prune_expired();
        let tokens = auth.tokens.read();
        assert_eq!(tokens.keys().collect::<Vec<_>>(), ["live"]);
    }
}
