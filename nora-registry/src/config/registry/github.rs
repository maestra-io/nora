// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use serde::{Deserialize, Serialize};
use std::env;

/// GitHub Releases proxy (maestra): release assets of public repositories, served at
/// `/github/<owner>/<repo>/releases/download/<tag>/<asset>`. Pull-through only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GithubConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Where release assets are downloaded from. Its host, plus GitHub's asset CDN
    /// hosts, are the only hosts an asset download may reach or redirect to.
    #[serde(default = "default_download_url")]
    pub download_url: String,
    /// The REST API that dates a release (`published_at`) and lists its assets.
    #[serde(default = "default_api_url")]
    pub api_url: String,
    #[serde(default = "super::super::default_timeout")]
    pub proxy_timeout: u64,
    /// Seconds a release's API record is used before it is fetched again.
    #[serde(default = "default_release_ttl")]
    pub metadata_ttl: i64,
    /// API token (`NORA_GITHUB_TOKEN` only, never in config.toml): lifts the API rate
    /// limit from 60 to 5000 requests per hour. Read-only access to public repos is enough.
    #[serde(skip)]
    pub token: Option<crate::secrets::ProtectedString>,
    /// Let downloads reach loopback, private and link-local addresses (tests, a lab
    /// GitHub Enterprise); off: refused on the first request and every redirect hop.
    #[serde(default)]
    pub allow_private_hosts: bool,
}

fn default_download_url() -> String {
    "https://github.com".into()
}

fn default_api_url() -> String {
    "https://api.github.com".into()
}

fn default_release_ttl() -> i64 {
    86400
}

impl Default for GithubConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            download_url: default_download_url(),
            api_url: default_api_url(),
            proxy_timeout: 30,
            metadata_ttl: default_release_ttl(),
            token: None,
            allow_private_hosts: false,
        }
    }
}

impl GithubConfig {
    pub(in crate::config) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_GITHUB_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_GITHUB_DOWNLOAD_URL") {
            self.download_url = val;
        }
        if let Ok(val) = env::var("NORA_GITHUB_API_URL") {
            self.api_url = val;
        }
        if let Ok(val) = env::var("NORA_GITHUB_PROXY_TIMEOUT") {
            super::super::parse_env_warn(
                "NORA_GITHUB_PROXY_TIMEOUT",
                &val,
                &mut self.proxy_timeout,
            );
        }
        if let Ok(val) = env::var("NORA_GITHUB_METADATA_TTL") {
            super::super::parse_env_warn("NORA_GITHUB_METADATA_TTL", &val, &mut self.metadata_ttl);
        }
        if let Ok(val) = env::var("NORA_GITHUB_TOKEN") {
            let val = val.trim();
            self.token =
                (!val.is_empty()).then(|| crate::secrets::ProtectedString::new(val.to_string()));
        }
    }
}
