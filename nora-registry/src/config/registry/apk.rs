// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use super::RepoProxyEntry;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env;

/// Alpine (apk) repository proxy (maestra): each `[apk.proxies]` entry maps a path
/// segment to an Alpine mirror root (`https://dl-cdn.alpinelinux.org/alpine`), served at
/// `/apk/<name>/<branch>/<repo>/<arch>/`. Pull-through only. The upstream index is
/// verified against `upstream_keys_dir`, filtered and re-signed with `signing_key_path`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Proxied mirrors: local name → mirror root URL (the directory holding `v3.22/`, `edge/`).
    #[serde(default)]
    pub proxies: BTreeMap<String, RepoProxyEntry>,
    #[serde(default = "super::super::default_timeout")]
    pub proxy_timeout: u64,
    /// Seconds an upstream `APKINDEX.tar.gz` is served before it is fetched again.
    #[serde(default = "super::super::default_metadata_ttl")]
    pub metadata_ttl: i64,
    #[serde(default = "super::super::default_true")]
    pub serve_stale: bool,
    /// PEM RSA private key (PKCS#1 or PKCS#8) that signs every served index. Required:
    /// a filtered index no longer matches the upstream signature.
    #[serde(default)]
    pub signing_key_path: String,
    /// File name of the public key in clients' `/etc/apk/keys/`; apk finds the key by the
    /// name in the index signature. Served at `/apk/keys/<key_name>` without auth.
    #[serde(default = "default_key_name")]
    pub key_name: String,
    /// Directory (searched recursively) of the upstream's `*.rsa.pub` keys: an upstream
    /// index whose signature none of them verifies is refused. Alpine's own keys sit in
    /// `/usr/share/apk/keys` of any Alpine image (package alpine-keys), NORA's included.
    #[serde(default = "default_upstream_keys_dir")]
    pub upstream_keys_dir: String,
}

fn default_key_name() -> String {
    "nora.rsa.pub".to_string()
}

fn default_upstream_keys_dir() -> String {
    "/usr/share/apk/keys".to_string()
}

impl Default for ApkConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            proxies: BTreeMap::new(),
            proxy_timeout: 30,
            metadata_ttl: 300,
            serve_stale: true,
            signing_key_path: String::new(),
            key_name: default_key_name(),
            upstream_keys_dir: default_upstream_keys_dir(),
        }
    }
}

impl ApkConfig {
    pub(in crate::config) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_APK_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_APK_PROXIES") {
            self.proxies = super::parse_repo_proxies_env(&val);
        }
        if let Ok(val) = env::var("NORA_APK_PROXY_TIMEOUT") {
            super::super::parse_env_warn("NORA_APK_PROXY_TIMEOUT", &val, &mut self.proxy_timeout);
        }
        if let Ok(val) = env::var("NORA_APK_METADATA_TTL") {
            super::super::parse_env_warn("NORA_APK_METADATA_TTL", &val, &mut self.metadata_ttl);
        }
        if let Ok(val) = env::var("NORA_APK_SERVE_STALE") {
            self.serve_stale = !matches!(val.as_str(), "false" | "0");
        }
        if let Ok(val) = env::var("NORA_APK_SIGNING_KEY_PATH") {
            self.signing_key_path = val;
        }
        if let Ok(val) = env::var("NORA_APK_KEY_NAME") {
            self.key_name = val;
        }
        if let Ok(val) = env::var("NORA_APK_UPSTREAM_KEYS_DIR") {
            self.upstream_keys_dir = val;
        }
    }
}
