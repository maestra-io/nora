// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Server and TLS configuration.

use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_server_host")]
    pub host: String,
    #[serde(default = "default_server_port")]
    pub port: u16,
    /// Public URL for generating pull commands (e.g., "registry.example.com")
    #[serde(default)]
    pub public_url: Option<String>,
    /// Maximum request body size in MB (default: 2048 = 2GB)
    #[serde(default = "default_body_limit_mb")]
    pub body_limit_mb: usize,
    /// Coalesce concurrent upstream fetches for the same key on a cache miss
    /// (single-flight, #595). Default `true`; set `false` to disable and let
    /// every concurrent request fetch independently (kill-switch).
    #[serde(default = "default_proxy_coalesce")]
    pub proxy_coalesce: bool,
    /// Trust upstream-provided publish dates (`published`/`time`/`created_at`/
    /// `upload_time`/etc.) when enforcing `min_release_age` curation. Default
    /// `false` (secure, ADR-8): an attacker controlling/MITM-ing an upstream
    /// registry could spoof an OLD date so a freshly-published malicious package
    /// appears old and bypasses the new-package quarantine. When `false`, NORA
    /// derives the package age from its OWN cache timestamp (mtime) instead.
    /// Set `true` to restore the legacy behavior of trusting upstream dates.
    /// NB: with `false`, age is measured from when NORA first cached the
    /// artifact (cache-age), not its real publish date — a long-published
    /// package just cached will be quarantined for `min_release_age`.
    #[serde(default = "default_trust_upstream_dates")]
    pub trust_upstream_dates: bool,
    /// Seconds in-flight requests get to finish after SIGTERM/SIGINT before the
    /// connections still open are closed and shutdown continues (#1016). A client that
    /// stops reading could otherwise hold the process until the orchestrator kills it,
    /// losing the audit drain and the token flush. Default 15: with the scheduler wait
    /// (up to 10 s) it fits Kubernetes' default 30 s grace period.
    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_timeout: u64,
    /// Seconds a client gets to send a request's headers, on a new connection and
    /// between keep-alive requests; a client that is slower is disconnected
    /// (slowloris). Default 30 (hyper's own default, which `axum::serve` never armed).
    /// 0 disables the timeout.
    #[serde(default = "default_header_read_timeout")]
    pub header_read_timeout: u64,
    /// Open client connections served at once. Past it NORA stops accepting until
    /// one closes; new clients wait in the listen backlog. Default 4096; 0 = no limit.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Maximum body in MB of a publish that is buffered in memory (npm, Maven,
    /// Cargo, deb, rpm); a bigger one is answered 413. Bounded by `body_limit_mb`.
    /// Streamed uploads (Docker blobs, raw, NuGet push, PyPI upload) have their own
    /// caps. Default 512.
    #[serde(default = "default_publish_body_limit_mb")]
    pub publish_body_limit_mb: usize,
    /// Proxied NuGet/npm/PyPI artifacts larger than this many MB are never held in
    /// memory whole: a cold miss is spooled to a temp file under `{storage.path}/tmp/`
    /// and served from it, a cache hit is streamed from storage with its digest
    /// checked as it streams. Smaller ones are buffered as before. Default 16;
    /// 0 buffers everything.
    #[serde(default = "default_stream_threshold_mb")]
    pub stream_threshold_mb: u64,
}

pub(super) fn default_server_host() -> String {
    String::from("127.0.0.1")
}

pub(super) fn default_server_port() -> u16 {
    4000
}

pub(super) fn default_body_limit_mb() -> usize {
    2048 // 2GB - enough for any Docker image
}

pub(super) fn default_proxy_coalesce() -> bool {
    true
}

pub(super) fn default_trust_upstream_dates() -> bool {
    false
}

pub(super) fn default_shutdown_timeout() -> u64 {
    15
}

pub(super) fn default_header_read_timeout() -> u64 {
    30
}

pub(super) fn default_max_connections() -> usize {
    4096
}

pub(super) fn default_publish_body_limit_mb() -> usize {
    512
}

pub(super) fn default_stream_threshold_mb() -> u64 {
    16
}

/// TLS configuration for outbound connections to upstream registries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to PEM-encoded CA certificate bundle (appended to system CAs)
    #[serde(default)]
    pub ca_cert: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_server_host(),
            port: default_server_port(),
            public_url: None,
            body_limit_mb: default_body_limit_mb(),
            proxy_coalesce: default_proxy_coalesce(),
            shutdown_timeout: default_shutdown_timeout(),
            trust_upstream_dates: default_trust_upstream_dates(),
            header_read_timeout: default_header_read_timeout(),
            max_connections: default_max_connections(),
            publish_body_limit_mb: default_publish_body_limit_mb(),
            stream_threshold_mb: default_stream_threshold_mb(),
        }
    }
}

impl ServerConfig {
    /// Byte cap of a buffered publish body: `publish_body_limit_mb`, never above
    /// the global `body_limit_mb`.
    pub fn publish_body_limit(&self) -> usize {
        self.publish_body_limit_mb
            .min(self.body_limit_mb)
            .saturating_mul(1024 * 1024)
    }

    /// `stream_threshold_mb` in bytes; 0 = never stream.
    pub fn stream_threshold(&self) -> u64 {
        self.stream_threshold_mb.saturating_mul(1024 * 1024)
    }

    /// Format bind address for `TcpListener::bind`.
    ///
    /// IPv6 addresses contain colons and need bracket notation (`[::]:4000`)
    /// to avoid ambiguity with the host:port separator (#569).
    pub fn bind_addr(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Build the base URL advertised to clients (npm/docker/nuget service
    /// index, UI install commands). Single source of truth for client-facing
    /// URLs — handlers and UI must not reconstruct it inline.
    ///
    /// Returns `public_url` (trailing slash trimmed) if set, otherwise falls
    /// back to `http://{host}:{port}`. The fallback only makes sense for a
    /// routable bind address; `validate()` rejects a wildcard bind without a
    /// public_url and warns on a loopback public_url (#510, #590), so a broken
    /// URL never silently ships.
    pub fn public_base_url(&self) -> String {
        let base = self
            .public_url
            .as_deref()
            .map(|u| u.trim_end_matches('/').to_string())
            // Reuse bind_addr() so IPv6 literals get bracket notation
            // (`http://[::1]:4000`) — keeping the authority format consistent
            // with the listen address and avoiding drift.
            .unwrap_or_else(|| format!("http://{}", self.bind_addr()));
        debug_assert!(
            base.starts_with("http://") || base.starts_with("https://"),
            "public_base_url must carry an http(s) scheme: {base}"
        );
        base
    }

    /// Host authority (`host[:port]`) advertised to clients, without scheme.
    ///
    /// For registry references that take no URL scheme — e.g.
    /// `docker pull {host}/repo:tag`. Derived from [`Self::public_base_url`]
    /// so it shares the single source of truth.
    pub fn public_host(&self) -> String {
        let base = self.public_base_url();
        base.strip_prefix("https://")
            .or_else(|| base.strip_prefix("http://"))
            .unwrap_or(&base)
            .trim_end_matches('/')
            .to_string()
    }

    /// Path prefix the UI must prepend to its root-absolute self-links so it
    /// works when NORA is mounted under a sub-path behind a reverse proxy
    /// (`location /nora/ { proxy_pass http://nora:4000/; }`, trailing slash
    /// strips `/nora`). Derived from the path component of `public_url`, trailing
    /// slash trimmed. Empty when `public_url` is unset or has no path — a no-op
    /// for every root-vhost deploy, which is the common case.
    pub fn base_path(&self) -> String {
        let Some(url) = self.public_url.as_deref() else {
            return String::new();
        };
        // Delegate to the shared "drop scheme + authority, keep path" helper so
        // this and the ansible metadata rewriter cannot drift; trim trailing slash.
        super::url_path_component(url)
            .trim_end_matches('/')
            .to_string()
    }

    /// Apply environment variable overrides for server config.
    pub(super) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_HOST") {
            self.host = val;
        }
        if let Ok(val) = env::var("NORA_PORT") {
            super::parse_env_warn("NORA_PORT", &val, &mut self.port);
        }
        if let Ok(val) = env::var("NORA_PUBLIC_URL") {
            self.public_url = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_BODY_LIMIT_MB") {
            super::parse_env_warn("NORA_BODY_LIMIT_MB", &val, &mut self.body_limit_mb);
        }
        if let Ok(val) = env::var("NORA_SHUTDOWN_TIMEOUT") {
            super::parse_env_warn("NORA_SHUTDOWN_TIMEOUT", &val, &mut self.shutdown_timeout);
        }
        if let Ok(val) = env::var("NORA_HEADER_READ_TIMEOUT") {
            super::parse_env_warn(
                "NORA_HEADER_READ_TIMEOUT",
                &val,
                &mut self.header_read_timeout,
            );
        }
        if let Ok(val) = env::var("NORA_MAX_CONNECTIONS") {
            super::parse_env_warn("NORA_MAX_CONNECTIONS", &val, &mut self.max_connections);
        }
        if let Ok(val) = env::var("NORA_STREAM_THRESHOLD_MB") {
            super::parse_env_warn(
                "NORA_STREAM_THRESHOLD_MB",
                &val,
                &mut self.stream_threshold_mb,
            );
        }
        if let Ok(val) = env::var("NORA_PUBLISH_BODY_LIMIT_MB") {
            super::parse_env_warn(
                "NORA_PUBLISH_BODY_LIMIT_MB",
                &val,
                &mut self.publish_body_limit_mb,
            );
        }
        if let Ok(val) = env::var("NORA_TRUST_UPSTREAM_DATES") {
            super::parse_env_warn(
                "NORA_TRUST_UPSTREAM_DATES",
                &val,
                &mut self.trust_upstream_dates,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The drain window defaults to 15 s (fits Kubernetes' default 30 s grace period
    /// together with the scheduler wait and the audit drain) and follows the env.
    #[test]
    fn shutdown_timeout_default_and_env_override() {
        let _lock = crate::test_env::env_lock();
        assert_eq!(ServerConfig::default().shutdown_timeout, 15);
        let mut config = ServerConfig::default();
        std::env::set_var("NORA_SHUTDOWN_TIMEOUT", "4");
        config.apply_env_overrides();
        std::env::remove_var("NORA_SHUTDOWN_TIMEOUT");
        assert_eq!(config.shutdown_timeout, 4);
    }

    /// The header-read timeout and the connection limit have safe defaults and
    /// follow the env.
    #[test]
    fn connection_limits_default_and_env_override() {
        let _lock = crate::test_env::env_lock();
        let d = ServerConfig::default();
        assert_eq!((d.header_read_timeout, d.max_connections), (30, 4096));
        let mut config = ServerConfig::default();
        std::env::set_var("NORA_HEADER_READ_TIMEOUT", "5");
        std::env::set_var("NORA_MAX_CONNECTIONS", "10");
        config.apply_env_overrides();
        std::env::remove_var("NORA_HEADER_READ_TIMEOUT");
        std::env::remove_var("NORA_MAX_CONNECTIONS");
        assert_eq!(
            (config.header_read_timeout, config.max_connections),
            (5, 10)
        );
    }

    /// The publish cap defaults to 512 MB, follows the env and never exceeds the
    /// global body limit.
    #[test]
    fn publish_body_limit_default_env_override_and_ceiling() {
        let _lock = crate::test_env::env_lock();
        assert_eq!(
            ServerConfig::default().publish_body_limit(),
            512 * 1024 * 1024
        );
        let mut config = ServerConfig::default();
        std::env::set_var("NORA_PUBLISH_BODY_LIMIT_MB", "64");
        config.apply_env_overrides();
        std::env::remove_var("NORA_PUBLISH_BODY_LIMIT_MB");
        assert_eq!(config.publish_body_limit(), 64 * 1024 * 1024);
        config.body_limit_mb = 8;
        assert_eq!(config.publish_body_limit(), 8 * 1024 * 1024);
    }

    fn server(host: &str, port: u16) -> ServerConfig {
        ServerConfig {
            host: host.to_string(),
            port,
            public_url: None,
            body_limit_mb: 2048,
            proxy_coalesce: true,
            trust_upstream_dates: false,
            shutdown_timeout: 15,
            header_read_timeout: 30,
            max_connections: 4096,
            publish_body_limit_mb: 512,
            stream_threshold_mb: 16,
        }
    }

    #[test]
    fn bind_addr_ipv4() {
        assert_eq!(server("0.0.0.0", 4000).bind_addr(), "0.0.0.0:4000");
        assert_eq!(server("127.0.0.1", 8080).bind_addr(), "127.0.0.1:8080");
    }

    #[test]
    fn bind_addr_ipv6() {
        assert_eq!(server("::", 4000).bind_addr(), "[::]:4000");
        assert_eq!(server("::1", 4000).bind_addr(), "[::1]:4000");
        assert_eq!(
            server("2001:db8::1", 4000).bind_addr(),
            "[2001:db8::1]:4000"
        );
    }

    #[test]
    fn bind_addr_hostname() {
        assert_eq!(server("localhost", 4000).bind_addr(), "localhost:4000");
        assert_eq!(
            server("registry.example.com", 443).bind_addr(),
            "registry.example.com:443"
        );
    }

    #[test]
    fn public_base_url_falls_back_to_host_port() {
        // No public_url → http://{host}:{port}.
        assert_eq!(
            server("127.0.0.1", 4000).public_base_url(),
            "http://127.0.0.1:4000"
        );
    }

    #[test]
    fn public_base_url_brackets_ipv6_fallback() {
        // IPv6 literal host without public_url must be bracketed, matching
        // bind_addr() — otherwise the authority is ambiguous/malformed.
        assert_eq!(
            server("2001:db8::1", 4000).public_base_url(),
            "http://[2001:db8::1]:4000"
        );
        assert_eq!(server("::1", 4000).public_host(), "[::1]:4000");
    }

    #[test]
    fn base_path_extracts_public_url_path_or_empty() {
        // No public_url → empty (no-op for root-vhost deploys).
        assert_eq!(server("127.0.0.1", 4000).base_path(), "");

        let mut s = server("h", 4000);
        // public_url with no path → empty.
        s.public_url = Some("https://nora.example.com".into());
        assert_eq!(s.base_path(), "");
        s.public_url = Some("https://nora.example.com:8443".into());
        assert_eq!(s.base_path(), "");
        // Sub-path mount → the path prefix, trailing slash trimmed.
        s.public_url = Some("https://example.com/nora".into());
        assert_eq!(s.base_path(), "/nora");
        s.public_url = Some("https://example.com/nora/".into());
        assert_eq!(s.base_path(), "/nora");
        s.public_url = Some("https://example.com:8443/team/nora".into());
        assert_eq!(s.base_path(), "/team/nora");
    }

    #[test]
    fn public_base_url_uses_public_url_and_trims_slash() {
        let mut cfg = server("0.0.0.0", 4000);
        cfg.public_url = Some("https://registry.example.com/".to_string());
        // public_url wins over the bind address; trailing slash trimmed.
        assert_eq!(cfg.public_base_url(), "https://registry.example.com");
    }

    #[test]
    fn public_host_strips_scheme_for_docker_pull() {
        // Fallback case: scheme stripped, host:port kept.
        assert_eq!(
            server("registry.example.com", 4000).public_host(),
            "registry.example.com:4000"
        );

        // public_url case: scheme and trailing slash stripped — `docker pull`
        // takes a bare host, not a URL.
        let mut cfg = server("0.0.0.0", 4000);
        cfg.public_url = Some("https://nora.example.com/".to_string());
        assert_eq!(cfg.public_host(), "nora.example.com");

        cfg.public_url = Some("http://nora.example.com:8080".to_string());
        assert_eq!(cfg.public_host(), "nora.example.com:8080");
    }
}

impl TlsConfig {
    /// Apply environment variable overrides for TLS config.
    pub(super) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_TLS_CA_CERT") {
            self.ca_cert = if val.is_empty() { None } else { Some(val) };
        }
    }
}
