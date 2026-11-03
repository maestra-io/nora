// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use serde::{Deserialize, Serialize};
use std::env;

/// HashiCorp releases proxy (maestra): product archives of releases.hashicorp.com
/// (`terraform`, `vault`, `consul`…), served at `/hashicorp/<product>/<version>/<file>`.
/// Pull-through only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashicorpConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Where archives and `SHA256SUMS` are downloaded from. It and the API host are the
    /// only hosts a download may reach or redirect to.
    #[serde(default = "default_download_url")]
    pub download_url: String,
    /// The releases API that dates a version (`timestamp_created`).
    #[serde(default = "default_api_url")]
    pub api_url: String,
    #[serde(default = "super::super::default_timeout")]
    pub proxy_timeout: u64,
    /// Seconds a version's record (date + `SHA256SUMS`) is used before it is fetched again.
    #[serde(default = "default_release_ttl")]
    pub metadata_ttl: i64,
    /// Let downloads reach loopback, private and link-local addresses (tests, a lab
    /// mirror); off: refused on the first request and every redirect hop.
    #[serde(default)]
    pub allow_private_hosts: bool,
}

fn default_download_url() -> String {
    "https://releases.hashicorp.com".into()
}

fn default_api_url() -> String {
    "https://api.releases.hashicorp.com".into()
}

fn default_release_ttl() -> i64 {
    86400
}

impl Default for HashicorpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            download_url: default_download_url(),
            api_url: default_api_url(),
            proxy_timeout: 30,
            metadata_ttl: default_release_ttl(),
            allow_private_hosts: false,
        }
    }
}

impl HashicorpConfig {
    pub(in crate::config) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_HASHICORP_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_HASHICORP_DOWNLOAD_URL") {
            self.download_url = val;
        }
        if let Ok(val) = env::var("NORA_HASHICORP_API_URL") {
            self.api_url = val;
        }
        if let Ok(val) = env::var("NORA_HASHICORP_PROXY_TIMEOUT") {
            super::super::parse_env_warn(
                "NORA_HASHICORP_PROXY_TIMEOUT",
                &val,
                &mut self.proxy_timeout,
            );
        }
        if let Ok(val) = env::var("NORA_HASHICORP_METADATA_TTL") {
            super::super::parse_env_warn(
                "NORA_HASHICORP_METADATA_TTL",
                &val,
                &mut self.metadata_ttl,
            );
        }
    }
}
