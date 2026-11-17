// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::secrets::ProtectedString;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoConfig {
    #[serde(default = "super::super::default_true")]
    pub enabled: bool,
    #[serde(default = "default_go_proxy")]
    pub proxy: Option<String>,
    #[serde(default, skip_serializing)]
    pub proxy_auth: Option<ProtectedString>,
    #[serde(default = "super::super::default_timeout")]
    pub proxy_timeout: u64,
    #[serde(default = "default_go_zip_timeout")]
    pub proxy_timeout_zip: u64,
    #[serde(default = "default_go_max_zip_size")]
    pub max_zip_size: u64,
    /// Staleness window (seconds) for the mutable listing endpoints (`@v/list`, `@latest`); a
    /// non-positive value revalidates every pull. Per-version files (.info/.mod/.zip) are
    /// content-addressed and always immutable.
    #[serde(default = "super::super::default_metadata_ttl")]
    pub metadata_ttl: i64,
    /// Date a version NORA has not seen before by the `Last-Modified` of its `.zip` on `proxy`
    /// (a HEAD, cached once per version), not by NORA's first sight. On proxy.golang.org that
    /// is the proxy's own first fetch of the version (the index.golang.org `Timestamp`), which
    /// the publisher cannot set, unlike the `.info` `Time` (A066). Only for a `proxy` whose
    /// `Last-Modified` means that; off, a new version ages from NORA's first sight.
    #[serde(default)]
    pub attested_dates: bool,
}

fn default_go_proxy() -> Option<String> {
    Some("https://proxy.golang.org".to_string())
}

pub(in crate::config) fn default_go_zip_timeout() -> u64 {
    120
}

fn default_go_max_zip_size() -> u64 {
    104_857_600 // 100MB
}

impl Default for GoConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            proxy: default_go_proxy(),
            proxy_auth: None,
            proxy_timeout: 30,
            proxy_timeout_zip: 120,
            max_zip_size: 104_857_600,
            metadata_ttl: 300,
            attested_dates: false,
        }
    }
}

impl GoConfig {
    pub(in crate::config) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_GO_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_GO_PROXY") {
            self.proxy = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_GO_PROXY_AUTH") {
            self.proxy_auth = if val.is_empty() {
                None
            } else {
                Some(ProtectedString::new(val))
            };
        }
        if let Ok(val) = env::var("NORA_GO_PROXY_TIMEOUT") {
            super::super::parse_env_warn("NORA_GO_PROXY_TIMEOUT", &val, &mut self.proxy_timeout);
        }
        if let Ok(val) = env::var("NORA_GO_PROXY_TIMEOUT_ZIP") {
            super::super::parse_env_warn(
                "NORA_GO_PROXY_TIMEOUT_ZIP",
                &val,
                &mut self.proxy_timeout_zip,
            );
        }
        if let Ok(val) = env::var("NORA_GO_MAX_ZIP_SIZE") {
            super::super::parse_env_warn("NORA_GO_MAX_ZIP_SIZE", &val, &mut self.max_zip_size);
        }
        if let Ok(val) = env::var("NORA_GO_ATTESTED_DATES") {
            self.attested_dates = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_GO_METADATA_TTL") {
            super::super::parse_env_warn("NORA_GO_METADATA_TTL", &val, &mut self.metadata_ttl);
        }
    }
}
