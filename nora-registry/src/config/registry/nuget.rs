// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::secrets::ProtectedString;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NugetConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_nuget_proxy")]
    pub proxy: Option<String>,
    #[serde(default, skip_serializing)]
    pub proxy_auth: Option<ProtectedString>,
    #[serde(default = "super::super::default_timeout")]
    pub proxy_timeout: u64,
    #[serde(default = "default_nuget_metadata_timeout")]
    pub metadata_proxy_timeout: u64,
    #[serde(default = "super::super::default_metadata_ttl")]
    pub metadata_ttl: i64,
    #[serde(default = "super::super::default_true")]
    pub serve_stale: bool,
    /// Revalidate stale metadata with a conditional request (`If-None-Match` /
    /// `If-Modified-Since`) instead of always re-downloading the full body.
    /// Fail-open: any error falls back to a full fetch. nuget.org returns
    /// validators (ETag + Last-Modified) on both the flat-container version list
    /// and the registration index, so a 304 avoids the download.
    #[serde(default = "super::super::default_true")]
    pub revalidate: bool,
    #[serde(default = "default_nuget_search")]
    pub search_service: String,
    #[serde(default = "default_nuget_autocomplete")]
    pub autocomplete: String,
    /// Hosted feed (Maestra fork): PR pre-release versions (`X.Y.Z-pr.*`) older than
    /// this many days are deleted by the hosted retention pass, unless they are among
    /// the `hosted_pr_keep_last` newest of their ID. Stable and other pre-release
    /// versions are never touched. 0 = keep every PR version. Env:
    /// `NORA_NUGET_HOSTED_PR_RETENTION_DAYS`.
    #[serde(default = "default_hosted_pr_retention_days")]
    pub hosted_pr_retention_days: u32,
    /// Newest PR pre-release versions per ID kept regardless of age. 0 = age alone
    /// decides. Env: `NORA_NUGET_HOSTED_PR_KEEP_LAST`.
    #[serde(default = "default_hosted_pr_keep_last")]
    pub hosted_pr_keep_last: u32,
}

fn default_hosted_pr_retention_days() -> u32 {
    30
}

fn default_hosted_pr_keep_last() -> u32 {
    20
}

fn default_nuget_proxy() -> Option<String> {
    Some("https://api.nuget.org".to_string())
}

fn default_nuget_search() -> String {
    "https://azuresearch-usnc.nuget.org/query".to_string()
}

fn default_nuget_autocomplete() -> String {
    "https://azuresearch-usnc.nuget.org/autocomplete".to_string()
}

fn default_nuget_metadata_timeout() -> u64 {
    2
}

impl Default for NugetConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            proxy: default_nuget_proxy(),
            proxy_auth: None,
            proxy_timeout: 30,
            metadata_proxy_timeout: 2,
            metadata_ttl: 300,
            serve_stale: true,
            revalidate: true,
            search_service: default_nuget_search(),
            autocomplete: default_nuget_autocomplete(),
            hosted_pr_retention_days: default_hosted_pr_retention_days(),
            hosted_pr_keep_last: default_hosted_pr_keep_last(),
        }
    }
}

impl NugetConfig {
    pub(in crate::config) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_NUGET_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_NUGET_PROXY") {
            self.proxy = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_NUGET_PROXY_AUTH") {
            self.proxy_auth = if val.is_empty() {
                None
            } else {
                Some(ProtectedString::new(val))
            };
        }
        if let Ok(val) = env::var("NORA_NUGET_PROXY_TIMEOUT") {
            super::super::parse_env_warn("NORA_NUGET_PROXY_TIMEOUT", &val, &mut self.proxy_timeout);
        }
        if let Ok(val) = env::var("NORA_NUGET_METADATA_TIMEOUT") {
            super::super::parse_env_warn(
                "NORA_NUGET_METADATA_TIMEOUT",
                &val,
                &mut self.metadata_proxy_timeout,
            );
        }
        if let Ok(val) = env::var("NORA_NUGET_METADATA_TTL") {
            super::super::parse_env_warn("NORA_NUGET_METADATA_TTL", &val, &mut self.metadata_ttl);
        }
        if let Ok(val) = env::var("NORA_NUGET_SERVE_STALE") {
            self.serve_stale = !matches!(val.as_str(), "false" | "0");
        }
        if let Ok(val) = env::var("NORA_NUGET_REVALIDATE") {
            self.revalidate = !matches!(val.as_str(), "false" | "0");
        }
        if let Ok(val) = env::var("NORA_NUGET_SEARCH_SERVICE") {
            if !val.is_empty() {
                self.search_service = val;
            }
        }
        if let Ok(val) = env::var("NORA_NUGET_AUTOCOMPLETE") {
            if !val.is_empty() {
                self.autocomplete = val;
            }
        }
        if let Ok(val) = env::var("NORA_NUGET_HOSTED_PR_RETENTION_DAYS") {
            super::super::parse_env_warn(
                "NORA_NUGET_HOSTED_PR_RETENTION_DAYS",
                &val,
                &mut self.hosted_pr_retention_days,
            );
        }
        if let Ok(val) = env::var("NORA_NUGET_HOSTED_PR_KEEP_LAST") {
            super::super::parse_env_warn(
                "NORA_NUGET_HOSTED_PR_KEEP_LAST",
                &val,
                &mut self.hosted_pr_keep_last,
            );
        }
    }
}
