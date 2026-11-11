// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Secrets in memory: [`ProtectedString`] zeroizes a credential on drop and keeps it out of
//! `Debug` output. Credentials come from the config file and `NORA_*` environment variables;
//! there is no secrets provider (Vault, AWS Secrets Manager, Kubernetes).

pub mod protected;

pub use protected::{expose_opt, ProtectedString};

use serde::{Deserialize, Serialize};

/// The `[secrets]` config section. Parsed so that configs written for upstream NORA load
/// without an unknown-key report; nothing reads its fields.
///
/// # Example config.toml
///
/// ```toml
/// [secrets]
/// provider = "env"
/// clear_env = false
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsConfig {
    /// Provider type: "env", "aws-secrets", "vault", "k8s"
    #[serde(default = "default_provider")]
    pub provider: String,

    /// Clear environment variables after reading (for env provider)
    #[serde(default)]
    pub clear_env: bool,
}

fn default_provider() -> String {
    "env".to_string()
}

impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            provider: default_provider(),
            clear_env: false,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SecretsConfig::default();
        assert_eq!(config.provider, "env");
        assert!(!config.clear_env);
    }

    #[test]
    fn test_config_from_toml() {
        let toml = r#"
            provider = "env"
            clear_env = true
        "#;
        let config: SecretsConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.provider, "env");
        assert!(config.clear_env);
    }
}
