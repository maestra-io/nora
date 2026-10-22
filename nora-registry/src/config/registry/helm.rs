// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use super::RepoProxyEntry;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env;

/// Helm chart repository proxy (maestra): each `[helm.proxies]` entry maps a path
/// segment to a classic chart repository (`index.yaml` + `.tgz`), served at
/// `/helm/<name>/index.yaml`. Pull-through only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelmConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Proxied repos: local repo name → upstream chart repository base URL.
    #[serde(default)]
    pub proxies: BTreeMap<String, RepoProxyEntry>,
    #[serde(default = "super::super::default_timeout")]
    pub proxy_timeout: u64,
    /// Seconds an upstream `index.yaml` is served before it is fetched again.
    #[serde(default = "super::super::default_metadata_ttl")]
    pub metadata_ttl: i64,
    #[serde(default = "super::super::default_true")]
    pub serve_stale: bool,
    /// `[helm.proxies]` names whose index `created` is a release date. Only these get
    /// `min_release_age` (hidden from the index, refused on download) and, with
    /// `server.trust_upstream_dates`, a quarantine clock seeded from it. Off by default:
    /// several repositories re-stamp every `created` on each index rebuild (teleport,
    /// ory, crossplane), which would hold every version they have.
    #[serde(default)]
    pub trust_created: Vec<String>,
    /// Let chart downloads reach loopback, private and link-local addresses, on the
    /// first request or any redirect hop (off: refused, so a compromised upstream or
    /// index cannot aim NORA at internal services). Needed for an upstream on a
    /// private address.
    #[serde(default)]
    pub allow_private_chart_hosts: bool,
}

impl Default for HelmConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            proxies: BTreeMap::new(),
            proxy_timeout: 30,
            metadata_ttl: 300,
            serve_stale: true,
            trust_created: Vec::new(),
            allow_private_chart_hosts: false,
        }
    }
}

impl HelmConfig {
    pub(in crate::config) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_HELM_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_HELM_PROXIES") {
            self.proxies = super::parse_repo_proxies_env(&val);
        }
        if let Ok(val) = env::var("NORA_HELM_PROXY_TIMEOUT") {
            super::super::parse_env_warn("NORA_HELM_PROXY_TIMEOUT", &val, &mut self.proxy_timeout);
        }
        if let Ok(val) = env::var("NORA_HELM_METADATA_TTL") {
            super::super::parse_env_warn("NORA_HELM_METADATA_TTL", &val, &mut self.metadata_ttl);
        }
        if let Ok(val) = env::var("NORA_HELM_SERVE_STALE") {
            self.serve_stale = !matches!(val.as_str(), "false" | "0");
        }
        if let Ok(val) = env::var("NORA_HELM_TRUST_CREATED") {
            self.trust_created = val
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();
        }
    }
}
