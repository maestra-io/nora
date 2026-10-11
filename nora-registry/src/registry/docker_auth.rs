// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::config::basic_auth_header;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Cached Docker registry token
struct CachedToken {
    token: String,
    expires_at: Instant,
}

/// Docker registry authentication handler
/// Manages Bearer token acquisition and caching for upstream registries
#[derive(Clone)]
pub struct DockerAuth {
    /// Shared by every clone, so a spool resuming a blob reuses the token that opened it.
    tokens: Arc<RwLock<HashMap<String, CachedToken>>>,
    client: reqwest::Client,
    timeout: Duration,
}

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
        }
    }

    /// Get a valid token for the given registry and repository scope
    /// Returns cached token if still valid, otherwise fetches a new one
    pub async fn get_token(
        &self,
        registry_url: &str,
        name: &str,
        www_authenticate: Option<&str>,
        basic_auth: Option<&str>,
    ) -> Option<String> {
        let cache_key = format!("{}:{}", registry_url, name);

        // Check cache first
        {
            let tokens = self.tokens.read();
            if let Some(cached) = tokens.get(&cache_key) {
                if cached.expires_at > Instant::now() {
                    return Some(cached.token.clone());
                }
            }
        }

        // Need to fetch a new token
        let www_auth = www_authenticate?;
        let (token, lifetime) = self.fetch_token(www_auth, name, basic_auth).await?;

        // Cache the token for the lifetime the token server gave it, less a margin
        // for the request that will carry it.
        if let Some(ttl) = lifetime.checked_sub(TOKEN_EXPIRY_MARGIN) {
            let mut tokens = self.tokens.write();
            tokens.insert(
                cache_key,
                CachedToken {
                    token: token.clone(),
                    expires_at: Instant::now() + ttl,
                },
            );
        }

        Some(token)
    }

    /// Parse Www-Authenticate header and fetch token from auth server
    /// Format: Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull"
    ///
    /// Returns the token and its remaining lifetime (see [`token_lifetime`]).
    async fn fetch_token(
        &self,
        www_authenticate: &str,
        name: &str,
        basic_auth: Option<&str>,
    ) -> Option<(String, Duration)> {
        let params = parse_www_authenticate(www_authenticate)?;

        let realm = params.get("realm")?;

        // Validate realm URL scheme — only HTTP(S) allowed
        if !realm.starts_with("https://") && !realm.starts_with("http://") {
            tracing::warn!(realm = %realm, "Rejecting auth realm with non-HTTP(S) scheme");
            return None;
        }

        let service = params.get("service").map(|s| s.as_str()).unwrap_or("");

        // Build token request URL
        let scope = format!("repository:{}:pull", name);
        let url = format!("{}?service={}&scope={}", realm, service, scope);

        tracing::debug!(url = %url, "Fetching auth token");

        let mut request = self.client.get(&url).timeout(self.timeout);
        if let Some(credentials) = basic_auth {
            request = request.header("Authorization", basic_auth_header(credentials));
            tracing::debug!("Using basic auth for token request");
        }

        let response = request.send().await.ok()?;

        if !response.status().is_success() {
            tracing::warn!(status = %response.status(), "Token request failed");
            return None;
        }

        let json: serde_json::Value = response.json().await.ok()?;

        // Docker Hub returns "token", some registries return "access_token"
        let token = json
            .get("token")
            .or_else(|| json.get("access_token"))
            .and_then(|v| v.as_str())
            .map(String::from)?;
        Some((token, token_lifetime(&json, chrono::Utc::now())))
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
        .map(|issued| (now - issued.with_timezone(&chrono::Utc)).num_seconds().max(0) as u64)
        .unwrap_or(0);
    Duration::from_secs(expires_in.saturating_sub(age))
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
        assert_eq!(life(serde_json::json!({"token": "t", "expires_in": 300})), 300);
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
                .respond_with(ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({"token": "tok", "expires_in": expires_in}),
                ))
                .mount(&server)
                .await;
            let auth = DockerAuth::default();
            let header = format!(r#"Bearer realm="{}/token",service="s""#, server.uri());
            let token = auth
                .get_token("https://r.example", "lib/x", Some(&header), None)
                .await;
            assert_eq!(token.as_deref(), Some("tok"));
            let tokens = auth.tokens.read();
            match tokens.get("https://r.example:lib/x") {
                Some(t) => {
                    assert!(cached, "expires_in {expires_in} must not be cached");
                    let left = t.expires_at.saturating_duration_since(Instant::now());
                    assert!(left <= Duration::from_secs(20) && left > Duration::from_secs(15));
                }
                None => assert!(!cached, "expires_in {expires_in} must be cached"),
            }
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
        assert!(result.is_none());
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
        assert_eq!(result, Some("cached-token-123".to_string()));
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
        // Without www_authenticate, returns None (can't fetch new token)
        let result = auth
            .get_token("https://registry.example.com", "library/test", None, None)
            .await;
        assert!(result.is_none());
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
                "https://registry.example.com",
                "library/test",
                Some(r#"Bearer realm="http://127.0.0.1:1/token",service="test""#),
                None,
            )
            .await;
        assert!(result.is_none());
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
        assert!(result.is_none());
    }
}
