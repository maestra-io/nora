// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Audit log configuration.
//!
//! Named `audit_cfg` to avoid collision with `crate::audit` module.

use serde::{Deserialize, Serialize};
use std::env;

/// Audit log configuration.
///
/// Controls where audit events are written:
/// - `file`   — write to {storage_path}/audit.jsonl (default)
/// - `stdout` — write JSONL to stderr (12-factor compatible)
/// - `both`   — write to file AND stderr
/// - `off`    — disable audit logging
///
/// ENV: `NORA_AUDIT_LOG=file|stdout|both|off`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    #[serde(default)]
    pub mode: crate::audit::AuditMode,
    /// `file`/`both`: once `audit.jsonl` would grow past this many MiB it is
    /// renamed to `audit.jsonl.1` (older files shift up) and a new file is
    /// started. 0 disables rotation (unbounded file).
    /// Default 100. ENV: NORA_AUDIT_MAX_SIZE_MB.
    #[serde(default = "default_max_size_mb")]
    pub max_size_mb: u64,
    /// Rotated files kept (`audit.jsonl.1` .. `audit.jsonl.N`); the oldest is
    /// deleted on rotation. Disk use is bounded by `(max_files + 1) * max_size_mb`.
    /// Default 5. ENV: NORA_AUDIT_MAX_FILES.
    #[serde(default = "default_max_files")]
    pub max_files: u32,
}

fn default_max_size_mb() -> u64 {
    100
}

fn default_max_files() -> u32 {
    5
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            mode: crate::audit::AuditMode::File,
            max_size_mb: default_max_size_mb(),
            max_files: default_max_files(),
        }
    }
}

impl AuditConfig {
    /// Apply environment variable overrides for audit config.
    pub(super) fn apply_env_overrides(&mut self) -> Result<(), String> {
        if let Ok(val) = env::var("NORA_AUDIT_LOG") {
            self.mode = val
                .parse::<crate::audit::AuditMode>()
                .map_err(|e| format!("NORA_AUDIT_LOG={:?}: {}", val, e))?;
        }
        if let Ok(val) = env::var("NORA_AUDIT_MAX_SIZE_MB") {
            self.max_size_mb = val
                .parse()
                .map_err(|e| format!("NORA_AUDIT_MAX_SIZE_MB={:?}: {}", val, e))?;
        }
        if let Ok(val) = env::var("NORA_AUDIT_MAX_FILES") {
            self.max_files = val
                .parse()
                .map_err(|e| format!("NORA_AUDIT_MAX_FILES={:?}: {}", val, e))?;
        }
        Ok(())
    }
}
