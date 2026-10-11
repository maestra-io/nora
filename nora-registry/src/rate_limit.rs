// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Rate limiting configuration and middleware
//!
//! Provides rate limiting to protect against:
//! - Brute-force authentication attacks
//! - DoS attacks on upload endpoints
//! - General API abuse

use crate::auth::resolve_client_ip;
use crate::config::{RateLimitConfig, TrustedProxies};
use axum::http::Method;
use std::net::IpAddr;
use tower_governor::errors::GovernorError;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::KeyExtractor;

/// Convert a "requests per second" value to a replenishment period.
///
/// `GovernorConfigBuilder::per_second(N)` sets the replenishment interval to
/// N *seconds*, not N requests/second. So `per_second(200)` means 1 token
/// every 200 seconds = 0.005 rps — the opposite of what we want.
///
/// For N rps we need: interval = 1000/N milliseconds per token.
/// For rps > 1000 the result is clamped to 1ms (= 1000 rps effective max).
fn rps_to_period(rps: u64) -> u64 {
    debug_assert!(rps > 0, "rate limit rps must be > 0");
    (1000 / rps.max(1)).max(1)
}

/// Key extractor that resolves the real client IP using NORA's trusted proxy
/// configuration, rather than blindly trusting X-Forwarded-For headers (#541).
///
/// Uses [`resolve_client_ip`] which only honors XFF/X-Real-IP from peers in
/// the configured `trusted_proxies` list. Untrusted peers always get rate-limited
/// by their TCP peer IP, preventing XFF spoofing to bypass rate limits.
#[derive(Debug, Clone)]
pub struct TrustedProxyKeyExtractor {
    trusted_proxies: TrustedProxies,
}

impl TrustedProxyKeyExtractor {
    pub fn new(trusted_proxies: TrustedProxies) -> Self {
        Self { trusted_proxies }
    }
}

impl KeyExtractor for TrustedProxyKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &axum::http::Request<T>) -> Result<Self::Key, GovernorError> {
        let peer_ip = req
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|ci| ci.0.ip())
            .ok_or(GovernorError::UnableToExtractKey)?;

        let client_ip = resolve_client_ip(peer_ip, req.headers(), &self.trusted_proxies);

        debug_assert!(
            client_ip.is_ipv4() || client_ip.is_ipv6(),
            "resolved IP must be valid"
        );

        Ok(client_ip)
    }
}

/// A built rate-limit tier: the layer to mount plus a handle to its keyed state.
pub type RateLimiterLayer = tower_governor::GovernorLayer<
    TrustedProxyKeyExtractor,
    governor::middleware::StateInformationMiddleware,
    axum::body::Body,
>;

/// Shared keyed state of one tier; call `retain_recent()` periodically so entries for
/// clients that went quiet are dropped instead of accumulating for the process lifetime.
pub type RateLimiterState = tower_governor::governor::SharedRateLimiter<
    IpAddr,
    governor::middleware::StateInformationMiddleware,
>;

/// Every tier keys on the client IP resolved through `trusted_proxies`, the same key
/// the auth lockout uses, so X-Forwarded-For is honoured only from configured proxies.
fn build_tier(
    rps: u64,
    burst: u32,
    trusted_proxies: TrustedProxies,
    methods: Option<Vec<Method>>,
    name: &str,
) -> (RateLimiterLayer, RateLimiterState) {
    let mut builder = GovernorConfigBuilder::default();
    builder
        .per_millisecond(rps_to_period(rps))
        .burst_size(burst);
    if let Some(methods) = methods {
        builder.methods(methods);
    }
    let gov_config = builder
        .key_extractor(TrustedProxyKeyExtractor::new(trusted_proxies))
        .use_headers()
        .finish()
        .unwrap_or_else(|| panic!("failed to build {name} rate limiter: invalid RateLimitConfig"));
    let state = gov_config.limiter().clone();
    (tower_governor::GovernorLayer::new(gov_config), state)
}

/// Create rate limiter layer for auth endpoints (strict protection against brute-force).
///
/// Uses [`TrustedProxyKeyExtractor`] to resolve real client IPs, preventing
/// both proxy-IP-sharing (all clients in one bucket) and XFF spoofing.
pub fn auth_rate_limiter(
    config: &RateLimitConfig,
    trusted_proxies: TrustedProxies,
) -> (RateLimiterLayer, RateLimiterState) {
    build_tier(
        config.auth_rps,
        config.auth_burst,
        trusted_proxies,
        None,
        "auth",
    )
}

/// Create rate limiter layer for upload endpoints
///
/// High limits to accommodate Docker client's aggressive parallel layer uploads.
/// Applies to write methods only: reads (GET/HEAD) pass through, so a large
/// `dotnet restore`/`npm ci` against a warm cache is never answered 429.
pub fn upload_rate_limiter(
    config: &RateLimitConfig,
    trusted_proxies: TrustedProxies,
) -> (RateLimiterLayer, RateLimiterState) {
    build_tier(
        config.upload_rps,
        config.upload_burst,
        trusted_proxies,
        Some(vec![
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ]),
        "upload",
    )
}

/// Create rate limiter layer for general endpoints (lenient)
pub fn general_rate_limiter(
    config: &RateLimitConfig,
    trusted_proxies: TrustedProxies,
) -> (RateLimiterLayer, RateLimiterState) {
    build_tier(
        config.general_rps,
        config.general_burst,
        trusted_proxies,
        None,
        "general",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RateLimitConfig;
    use std::net::SocketAddr;

    #[test]
    fn test_default_config() {
        let config = RateLimitConfig::default();
        assert_eq!(config.auth_rps, 1);
        assert_eq!(config.auth_burst, 5);
        assert_eq!(config.upload_rps, 200);
        assert_eq!(config.general_rps, 100);
    }

    #[test]
    fn test_auth_rate_limiter_creation() {
        let config = RateLimitConfig::default();
        let _limiter = auth_rate_limiter(&config, TrustedProxies::default_loopback());
    }

    #[test]
    fn test_upload_rate_limiter_creation() {
        let config = RateLimitConfig::default();
        let _limiter = upload_rate_limiter(&config, TrustedProxies::default_loopback());
    }

    #[test]
    fn test_general_rate_limiter_creation() {
        let config = RateLimitConfig::default();
        let _limiter = general_rate_limiter(&config, TrustedProxies::default_loopback());
    }

    #[test]
    fn test_custom_config() {
        let config = RateLimitConfig {
            enabled: true,
            auth_rps: 10,
            auth_burst: 20,
            upload_rps: 500,
            upload_burst: 1000,
            general_rps: 200,
            general_burst: 400,
        };
        let _auth = auth_rate_limiter(&config, TrustedProxies::default_loopback());
        let _upload = upload_rate_limiter(&config, TrustedProxies::default_loopback());
        let _general = general_rate_limiter(&config, TrustedProxies::default_loopback());
    }

    #[test]
    fn test_rps_to_period() {
        // 1 rps → 1000ms per token
        assert_eq!(rps_to_period(1), 1000);
        // 200 rps → 5ms per token
        assert_eq!(rps_to_period(200), 5);
        // 100 rps → 10ms per token
        assert_eq!(rps_to_period(100), 10);
        // 10 rps → 100ms per token
        assert_eq!(rps_to_period(10), 100);
        // 1000 rps → 1ms per token
        assert_eq!(rps_to_period(1000), 1);
        // >1000 rps → clamped to 1ms (prevents zero period)
        assert_eq!(rps_to_period(2000), 1);
        assert_eq!(rps_to_period(10000), 1);
    }

    #[test]
    fn test_trusted_proxy_extractor_uses_peer_for_untrusted() {
        use axum::http::Request;

        let proxies = TrustedProxies::parse("10.0.0.0/8");
        let extractor = TrustedProxyKeyExtractor::new(proxies);

        // Untrusted peer (192.168.1.1) with spoofed XFF — should use peer IP
        let mut req = Request::builder().body(()).unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(SocketAddr::from((
                [192, 168, 1, 1],
                1234,
            ))));
        req.headers_mut()
            .insert("x-forwarded-for", "1.2.3.4".parse().unwrap());

        let key = extractor.extract(&req).unwrap();
        assert_eq!(key, IpAddr::from([192, 168, 1, 1]));
    }

    #[test]
    fn test_trusted_proxy_extractor_uses_xff_for_trusted() {
        use axum::http::Request;

        let proxies = TrustedProxies::parse("10.0.0.0/8");
        let extractor = TrustedProxyKeyExtractor::new(proxies);

        // Trusted peer (10.0.0.1) with real XFF — should use XFF client IP
        let mut req = Request::builder().body(()).unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(SocketAddr::from((
                [10, 0, 0, 1],
                1234,
            ))));
        req.headers_mut()
            .insert("x-forwarded-for", "5.6.7.8".parse().unwrap());

        let key = extractor.extract(&req).unwrap();
        assert_eq!(key, IpAddr::from([5, 6, 7, 8]));
    }

    #[tokio::test]
    async fn test_upload_tier_limits_writes_not_reads() {
        use axum::{body::Body, http::Request, routing::get, Router};
        use tower::ServiceExt;

        let config = RateLimitConfig {
            upload_rps: 1,
            upload_burst: 1,
            ..RateLimitConfig::default()
        };
        let (layer, state) = upload_rate_limiter(&config, TrustedProxies::default_loopback());
        let app = Router::new()
            .route("/x", get(|| async { "ok" }).put(|| async { "ok" }))
            .layer(layer);
        let send = |method: &str| {
            let mut req = Request::builder()
                .method(method)
                .uri("/x")
                .body(Body::empty())
                .unwrap();
            req.extensions_mut()
                .insert(axum::extract::ConnectInfo(SocketAddr::from((
                    [192, 168, 1, 1],
                    1234,
                ))));
            app.clone().oneshot(req)
        };

        assert_eq!(send("PUT").await.unwrap().status(), 200);
        assert_eq!(send("PUT").await.unwrap().status(), 429);
        for _ in 0..5 {
            assert_eq!(send("GET").await.unwrap().status(), 200);
        }
        assert_eq!(state.len(), 1);
        state.retain_recent();
    }

    #[test]
    fn test_trusted_proxy_extractor_no_connect_info() {
        use axum::http::Request;

        let proxies = TrustedProxies::default_loopback();
        let extractor = TrustedProxyKeyExtractor::new(proxies);

        let req = Request::builder().body(()).unwrap();
        let result = extractor.extract(&req);
        assert!(result.is_err());
    }
}
