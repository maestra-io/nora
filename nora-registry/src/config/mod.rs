// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! NORA registry configuration module.
//!
//! Configuration is loaded with three-tier priority: ENV > config file > defaults.
//! Each subsystem (server, storage, auth, registries, etc.) is defined in its own
//! submodule for maintainability.

mod audit_cfg;
mod auth;
mod circuit_breaker;
mod curation;
mod gc;
mod rate_limit;
mod registries;
pub mod registry;
mod retention;
mod server;
mod signing_cfg;
mod storage;

// Infrastructure configs
pub use self::audit_cfg::AuditConfig;
pub use self::signing_cfg::SigningConfig;
// Re-exports maintain API surface: `crate::config::OidcRoleRule` etc. used by test code in auth/, circuit_breaker/
pub(crate) use self::auth::canonical_ip;
#[allow(unused_imports)]
pub use self::auth::{
    AudienceCheck, AuthConfig, OidcConfig, OidcProvider, OidcRoleRule, ScopeEnforcement,
    TeleportConfig, TrustedProxies,
};
#[allow(unused_imports)]
pub use self::circuit_breaker::{CircuitBreakerConfig, CircuitBreakerOverride};
pub use self::curation::{
    CurationConfig, CurationMode, CurationOnFailure, RegistryCurationOverride,
};
pub use self::gc::GcConfig;
pub use self::rate_limit::RateLimitConfig;
pub use self::registries::{EnableSpec, RegistriesSection};
pub use self::retention::{RetentionConfig, RetentionRule};
pub use self::server::{ServerConfig, TlsConfig};
pub use self::storage::{StorageConfig, StorageMode};

// Registry configs (re-exported from registry/ submodule tree)
pub use self::registry::*;

// Secrets config lives in crate::secrets — just re-export
pub use crate::secrets::SecretsConfig;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::fs;

use crate::registry_type::RegistryType;

/// Exit status for a configuration NORA cannot start with: EX_CONFIG from sysexits.h.
/// The unit files name it in `RestartPreventExitStatus=`, so systemd stops the service
/// on it instead of restarting into the same error every few seconds (#1025).
pub const EXIT_CONFIG: i32 = 78;

/// Why [`Config::load`] could not produce a configuration to start with.
#[derive(Debug, thiserror::Error)]
pub enum ConfigLoadError {
    /// `NORA_CONFIG_PATH` names a file that cannot be read.
    #[error("NORA_CONFIG_PATH={path} but file cannot be read: {source}")]
    Unreadable {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// `NORA_CONFIG_PATH` names a file that is not valid TOML.
    #[error("NORA_CONFIG_PATH={path} contains invalid TOML: {source}")]
    InvalidToml {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    /// An environment override has a value that cannot be applied.
    #[error("fatal env override error: {0}")]
    EnvOverride(String),
    /// Validation found errors that make the configuration unusable.
    #[error("fatal configuration errors: {}", .0.join("; "))]
    Invalid(Vec<String>),
    /// The config file has keys no setting reads, and `NORA_CONFIG_STRICT` refuses them.
    #[error(
        "{path} has unknown keys: {} (NORA_CONFIG_STRICT is on)",
        .keys.join(", ")
    )]
    UnknownKeys { path: String, keys: Vec<String> },
}

/// The config file read from the working directory when `NORA_CONFIG_PATH` is unset.
const DEFAULT_CONFIG_FILE: &str = "config.toml";

/// Whether `NORA_CONFIG_STRICT` asks to refuse a config file with unknown keys.
fn config_strict_from_env() -> bool {
    env::var("NORA_CONFIG_STRICT").is_ok_and(|val| val.to_lowercase() == "true" || val == "1")
}

/// Parses a config file into a [`Config`] and the paths of the keys no setting reads,
/// such as `curation.mdoe` for a typo of `mode`.
fn parse_config(content: &str) -> Result<(Config, Vec<String>), toml::de::Error> {
    let mut unknown = Vec::new();
    let mut config: Config =
        serde_ignored::deserialize(toml::Deserializer::parse(content)?, |path| {
            unknown.push(key_path(&path))
        })?;
    // serde fills a missing `mode` with its default; whether it was written down is read from
    // the file itself (#1135).
    config.curation.mode_explicit = content
        .parse::<toml::Table>()
        .ok()
        .and_then(|table| table.get("curation")?.get("mode").cloned())
        .is_some();
    Ok((config, unknown))
}

/// What startup says about `curation.mode` while proxy registries are enabled (#1135).
#[derive(Debug, PartialEq, Eq)]
pub enum CurationModeNotice {
    /// `mode` is off only by default: from 1.5.0 such a configuration stops at startup.
    Implicit(Vec<RegistryType>),
    /// `mode = "off"` is written down: the operator accepts serving upstream packages unchecked.
    ExplicitOff(Vec<RegistryType>),
}

/// `curation.mdoe`, `docker.upstreams.0.auht`: map keys and sequence indices joined by
/// dots. `serde_ignored` prints `Option` layers as `?`; they are not part of the file.
fn key_path(path: &serde_ignored::Path<'_>) -> String {
    use serde_ignored::Path;
    let mut segments = Vec::new();
    let mut at = path;
    loop {
        at = match at {
            Path::Root => break,
            Path::Seq { parent, index } => {
                segments.push(index.to_string());
                parent
            }
            Path::Map { parent, key } => {
                segments.push(key.clone());
                parent
            }
            Path::Some { parent }
            | Path::NewtypeStruct { parent }
            | Path::NewtypeVariant { parent } => parent,
        };
    }
    segments.reverse();
    segments.join(".")
}

/// The per-registry curation variables a Hugging Face section would read if there were one.
fn hf_curation_env_vars() -> [&'static str; 3] {
    [
        "NORA_CURATION_HF_MIN_RELEASE_AGE",
        "NORA_CURATION_HF_QUARANTINE",
        "NORA_CURATION_HF_QUARANTINE_TTL",
    ]
}

/// Why a Hugging Face curation setting is refused: it would hold nothing.
fn hf_curation_refusal(setting: &str) -> String {
    format!(
        "{setting} cannot apply: Hugging Face has no curation section of its own (a Hub commit has no publish date NORA reads, and hf has no quarantine path), so it would hold nothing. Remove it; the allowlist and blocklist hold Hugging Face models by repository id and commit. (#579)"
    )
}

/// `[curation.hf]` in a config file: refused, not reported as an unknown key and ignored.
fn refuse_hf_curation_keys(path: &str, unknown: &[String]) -> Result<(), ConfigLoadError> {
    let refused: Vec<String> = unknown
        .iter()
        .filter(|k| *k == "curation.hf" || k.starts_with("curation.hf."))
        .map(|k| format!("{path}: {}", hf_curation_refusal(k)))
        .collect();
    if refused.is_empty() {
        Ok(())
    } else {
        Err(ConfigLoadError::Invalid(refused))
    }
}

/// Reports the unknown keys of the config file at `path`: one warning listing them all,
/// or, when `strict`, an error. Returns them for the caller.
fn surface_unknown_keys(
    path: &str,
    keys: Vec<String>,
    strict: bool,
) -> Result<Vec<String>, ConfigLoadError> {
    if keys.is_empty() {
        return Ok(keys);
    }
    if strict {
        return Err(ConfigLoadError::UnknownKeys {
            path: path.to_string(),
            keys,
        });
    }
    tracing::warn!(
        path = %path,
        keys = %keys.join(", "),
        "Config has unknown keys, ignored; NORA_CONFIG_STRICT=true refuses them"
    );
    Ok(keys)
}

// --- Shared defaults (used by submodules via `super::default_*`) ---

/// Returns `true` — used as serde default for boolean fields that should default to enabled.
/// An upstream setting as written: empty (or only whitespace) switches the upstream off. One rule
/// for the environment variable and the config file, so `NORA_<FMT>_PROXY=""` and `proxy = ""`
/// mean the same.
pub(crate) fn upstream_setting(value: String) -> Option<String> {
    (!value.trim().is_empty()).then_some(value)
}

/// The upstream a handler may ask: None when the setting is absent or blank, whatever wrote it
/// (environment, config file, or code). Every handler reads its upstream through this, so a blank
/// value can never reach a request.
pub(crate) fn configured_upstream(setting: &Option<String>) -> Option<&str> {
    setting.as_deref().filter(|value| !value.trim().is_empty())
}

/// `proxy = ""` in the config file reads as no upstream, like the empty environment variable.
pub(crate) fn deserialize_upstream<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value: Option<String> = serde::Deserialize::deserialize(deserializer)?;
    Ok(value.and_then(upstream_setting))
}

pub(crate) fn default_true() -> bool {
    true
}

/// Default proxy timeout in seconds (30s).
pub(crate) fn default_timeout() -> u64 {
    30
}

/// Default metadata TTL in seconds (300s = 5 minutes).
pub(crate) fn default_metadata_ttl() -> i64 {
    300
}

/// Encode "user:pass" into a Basic Auth header value, e.g. "Basic dXNlcjpwYXNz".
pub fn basic_auth_header(credentials: &str) -> String {
    format!("Basic {}", STANDARD.encode(credentials))
}

/// The credential NORA presents to an upstream it proxies, with its scheme (#1055).
///
/// Borrowed from the config's protected secret for the length of one request. There is
/// deliberately no `Debug` impl (guarded below at compile time): a `{:?}` on a request
/// context must not be able to print a token.
#[derive(Clone, Copy)]
pub enum UpstreamAuth<'a> {
    /// `user:pass`, sent as `Authorization: Basic base64(user:pass)`.
    Basic(&'a str),
    /// An opaque token (npm `_authToken`), sent as `Authorization: Bearer <token>`.
    Bearer(&'a str),
}

impl UpstreamAuth<'_> {
    /// The `Authorization` header value, marked sensitive so `HeaderValue`'s `Debug`
    /// prints `Sensitive` instead of the credential.
    ///
    /// Fails only for a Bearer token with bytes a header cannot carry (a newline left by
    /// a secret file, say); Basic is base64 and always valid.
    pub fn header_value(
        self,
    ) -> Result<reqwest::header::HeaderValue, reqwest::header::InvalidHeaderValue> {
        let raw = match self {
            UpstreamAuth::Basic(credentials) => basic_auth_header(credentials),
            UpstreamAuth::Bearer(token) => format!("Bearer {token}"),
        };
        let mut value = reqwest::header::HeaderValue::from_str(&raw)?;
        value.set_sensitive(true);
        Ok(value)
    }
}

// Compile-time guard: `UpstreamAuth` must not implement `Debug`. If it did, both impls
// below would apply and the type of `_` could not be inferred — a build error, not a
// review comment.
const _: fn() = || {
    trait AmbiguousIfDebug<A> {
        fn some_item() {}
    }
    impl<T: ?Sized> AmbiguousIfDebug<()> for T {}
    impl<T: ?Sized + std::fmt::Debug> AmbiguousIfDebug<u8> for T {}
    let _ = <UpstreamAuth<'static> as AmbiguousIfDebug<_>>::some_item;
};

/// Path component of a URL ([`nora_registry::upstream_rewrite::url_path_component`]): one
/// definition for [`ServerConfig::base_path`](server::ServerConfig::base_path) and the ansible
/// metadata rewrite, so the two cannot drift.
pub(crate) use nora_registry::upstream_rewrite::url_path_component;

/// Parse an env var value into `target`, warning on failure (#537).
///
/// If `val` parses successfully, `*target` is updated. If parsing fails,
/// a `warn!` is emitted with the variable name and invalid value, and
/// `*target` is left unchanged (keeps the TOML/default value).
pub(crate) fn parse_env_warn<T: std::str::FromStr + std::fmt::Display>(
    name: &str,
    val: &str,
    target: &mut T,
) {
    match val.parse::<T>() {
        Ok(parsed) => {
            *target = parsed;
        }
        Err(_) => {
            tracing::warn!(
                var = name,
                value = val,
                "env override ignored: failed to parse value"
            );
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub maven: MavenConfig,
    #[serde(default)]
    pub npm: NpmConfig,
    #[serde(default)]
    pub pypi: PypiConfig,
    #[serde(default)]
    pub docker: DockerConfig,
    #[serde(default)]
    pub go: GoConfig,
    #[serde(default)]
    pub cargo: CargoConfig,
    #[serde(default)]
    pub raw: RawConfig,
    #[serde(default)]
    pub gems: GemsConfig,
    #[serde(default)]
    pub terraform: TerraformConfig,
    #[serde(default)]
    pub ansible: AnsibleConfig,
    #[serde(default)]
    pub nuget: NugetConfig,
    #[serde(default)]
    pub pub_dart: PubDartConfig,
    #[serde(default)]
    pub conan: ConanConfig,
    #[serde(default)]
    pub rpm: RpmConfig,
    #[serde(default)]
    pub deb: DebConfig,
    #[serde(default)]
    pub cpan: CpanConfig,
    #[serde(default)]
    pub hf: HfConfig,
    #[serde(default)]
    pub helm: HelmConfig,
    #[serde(default)]
    pub apk: ApkConfig,
    #[serde(default)]
    pub github: GithubConfig,
    #[serde(default)]
    pub hashicorp: HashicorpConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub secrets: SecretsConfig,
    #[serde(default)]
    pub gc: GcConfig,
    #[serde(default)]
    pub retention: RetentionConfig,
    #[serde(default)]
    pub curation: CurationConfig,
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub signing: SigningConfig,
    /// Declarative registry selection: `[registries] enable = ["docker", "npm"]`
    #[serde(default)]
    pub registries: Option<RegistriesSection>,
}

/// Whether a registry's downloads are checked against a release date at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReleaseDateCheck {
    /// Checked by name and release date.
    Dated,
    /// Not checked by name or release date: only the digest quarantine holds them (rpm, deb).
    NoNameOrDate,
    /// Checked by name, but no release date reaches the check (cpan, hf).
    NoDate,
}

/// The environment variable of `rt`'s own `enabled` flag.
/// One path segment: letters, digits, '-', '_', '.', not starting with '.'.
fn is_plain_segment(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

pub(crate) fn legacy_enable_var(rt: RegistryType) -> &'static str {
    match rt {
        RegistryType::Docker => "NORA_DOCKER_ENABLED",
        RegistryType::Maven => "NORA_MAVEN_ENABLED",
        RegistryType::Npm => "NORA_NPM_ENABLED",
        RegistryType::Cargo => "NORA_CARGO_ENABLED",
        RegistryType::PyPI => "NORA_PYPI_ENABLED",
        RegistryType::Go => "NORA_GO_ENABLED",
        RegistryType::Raw => "NORA_RAW_ENABLED",
        RegistryType::Gems => "NORA_GEMS_ENABLED",
        RegistryType::Terraform => "NORA_TF_ENABLED",
        RegistryType::Ansible => "NORA_ANSIBLE_ENABLED",
        RegistryType::Nuget => "NORA_NUGET_ENABLED",
        RegistryType::PubDart => "NORA_PUB_ENABLED",
        RegistryType::Conan => "NORA_CONAN_ENABLED",
        RegistryType::Rpm => "NORA_RPM_ENABLED",
        RegistryType::Deb => "NORA_DEB_ENABLED",
        RegistryType::Cpan => "NORA_CPAN_ENABLED",
        RegistryType::HuggingFace => "NORA_HF_ENABLED",
        RegistryType::Helm => "NORA_HELM_ENABLED",
        RegistryType::Apk => "NORA_APK_ENABLED",
        RegistryType::Github => "NORA_GITHUB_ENABLED",
        RegistryType::Hashicorp => "NORA_HASHICORP_ENABLED",
    }
}

/// The release-date check of `rt`'s downloads, as each handler calls curation.
pub(crate) fn release_date_check(rt: RegistryType) -> ReleaseDateCheck {
    match rt {
        RegistryType::Rpm => ReleaseDateCheck::NoNameOrDate,
        // maestra: a proxied apt version is dated by NORA's first sight of it in an
        // upstream index (registry/deb_proxy.rs).
        RegistryType::Deb => ReleaseDateCheck::Dated,
        // registry/cpan.rs passes no publish date; a Hub commit has none NORA reads.
        RegistryType::Cpan | RegistryType::HuggingFace => ReleaseDateCheck::NoDate,
        RegistryType::Docker
        | RegistryType::Maven
        | RegistryType::Npm
        | RegistryType::Cargo
        | RegistryType::PyPI
        | RegistryType::Go
        | RegistryType::Raw
        | RegistryType::Gems
        | RegistryType::Terraform
        | RegistryType::Ansible
        | RegistryType::Nuget
        | RegistryType::PubDart
        | RegistryType::Conan
        | RegistryType::Helm
        | RegistryType::Apk
        | RegistryType::Github
        | RegistryType::Hashicorp => ReleaseDateCheck::Dated,
    }
}

/// What startup knows about one registry for its own `[curation.<registry>]
/// min_release_age`, as plain facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RegistryMinAgeFacts {
    /// The registry's own `min_release_age` is set.
    pub value_set: bool,
    /// Whether its downloads are checked against a release date.
    pub dated: ReleaseDateCheck,
    /// The registry is enabled.
    pub enabled: bool,
    /// The registry is an enabled proxy: it has an upstream.
    pub proxy: bool,
    /// The registry's effective quarantine — its own or the global one — is on.
    pub quarantined: bool,
}

/// What startup does with a registry's own `min_release_age`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RegistryMinAgeVerdict {
    /// No value set.
    NotSet,
    /// Applied to the registry's downloads: an active control.
    Applies,
    /// The registry is disabled: the value holds nothing (a warning, not a control).
    Unused,
    /// The value can never apply to these downloads (an error).
    CannotApply,
    /// An enabled proxy without a quarantine of its own (an error, #741): what the
    /// filter cannot date, nothing would hold.
    NeedsQuarantine,
}

/// The verdict on a registry's own `min_release_age`, from its facts alone (#1098).
pub(crate) fn registry_min_age_verdict(facts: RegistryMinAgeFacts) -> RegistryMinAgeVerdict {
    if !facts.value_set {
        RegistryMinAgeVerdict::NotSet
    } else if facts.dated != ReleaseDateCheck::Dated {
        RegistryMinAgeVerdict::CannotApply
    } else if !facts.enabled {
        RegistryMinAgeVerdict::Unused
    } else if facts.proxy && !facts.quarantined {
        RegistryMinAgeVerdict::NeedsQuarantine
    } else {
        RegistryMinAgeVerdict::Applies
    }
}

impl Config {
    /// Returns the set of enabled registry types.
    ///
    /// Resolution priority (three tiers):
    /// 1. `NORA_REGISTRIES_ENABLE` env var (highest)
    /// 2. `[registries].enable` from TOML config
    /// 3. Legacy per-registry `enabled` flags (backward compatible)
    ///
    /// A format this build was compiled without (cargo features `rpm`/`deb`)
    /// is dropped with an error log: its routes do not exist.
    pub fn enabled_registries(&self) -> HashSet<RegistryType> {
        self.resolve_enabled_registries(env::var("NORA_REGISTRIES_ENABLE").ok(), true)
    }

    /// [`Self::enabled_registries`] without logging: `load` resolves it before validation,
    /// and `main` logs the selection once at start.
    pub(crate) fn enabled_registries_quiet(&self) -> HashSet<RegistryType> {
        self.resolve_enabled_registries(env::var("NORA_REGISTRIES_ENABLE").ok(), false)
    }

    /// The enable-set from `NORA_REGISTRIES_ENABLE` (`env_spec`), else `[registries].enable`,
    /// else the per-registry flags; the selection and a fallback are logged when `log`.
    fn resolve_enabled_registries(
        &self,
        env_spec: Option<String>,
        log: bool,
    ) -> HashSet<RegistryType> {
        // Tier 1: NORA_REGISTRIES_ENABLE env var
        if let Some(val) = env_spec {
            if !val.is_empty() {
                let spec = EnableSpec::from_env_str(&val);
                match spec.resolve() {
                    Ok(set) => {
                        if log {
                            Self::warn_legacy_env_vars_if_present();
                            tracing::info!(
                                registries = ?set.iter().map(|r| r.as_str()).collect::<Vec<_>>(),
                                "Registry selection from NORA_REGISTRIES_ENABLE"
                            );
                        }
                        return Self::compiled_in_only(set);
                    }
                    Err(e) => {
                        if log {
                            tracing::error!(
                                "NORA_REGISTRIES_ENABLE is invalid: {} — falling back",
                                e
                            );
                        }
                    }
                }
            }
        }

        // Tier 2: [registries].enable from TOML
        if let Some(ref section) = self.registries {
            if let Some(ref spec) = section.enable {
                match spec.resolve() {
                    Ok(set) => {
                        if log {
                            Self::warn_legacy_env_vars_if_present();
                            tracing::info!(
                                registries = ?set.iter().map(|r| r.as_str()).collect::<Vec<_>>(),
                                "Registry selection from [registries].enable"
                            );
                        }
                        return Self::compiled_in_only(set);
                    }
                    Err(e) => {
                        if log {
                            tracing::error!(
                                "[registries].enable is invalid: {} — falling back to legacy",
                                e
                            );
                        }
                    }
                }
            }
        }

        // Tier 3: legacy per-registry enabled flags
        Self::compiled_in_only(self.enabled_registries_legacy())
    }

    fn compiled_in_only(mut set: HashSet<RegistryType>) -> HashSet<RegistryType> {
        set.retain(|rt| {
            let on = rt.compiled_in();
            if !on {
                tracing::error!(
                    registry = rt.as_str(),
                    "registry is enabled in config but this build was compiled without it \
                     (cargo feature `{}`); not serving it",
                    rt.as_str()
                );
            }
            on
        });
        set
    }

    /// Materialize the resolved enable-set into the per-registry `enabled` flags.
    ///
    /// Route mounting is driven by [`Self::enabled_registries`], but the hosted
    /// handlers (rpm/deb/raw) additionally re-check `config.<reg>.enabled`. When
    /// the enable-set is resolved from `NORA_REGISTRIES_ENABLE` or
    /// `[registries].enable`, those per-registry flags stay at their struct
    /// defaults, so a mounted rpm/deb route still 404s on every request. Writing
    /// the resolved set back keeps the two in sync. Call once at startup, right
    /// after [`Self::enabled_registries`]. The `match` is exhaustive over
    /// [`RegistryType`], so a new variant is a compile error until its flag is
    /// wired here. (#856)
    pub fn apply_enabled_registries(&mut self, set: &HashSet<RegistryType>) {
        for rt in RegistryType::all() {
            let on = set.contains(rt);
            match rt {
                RegistryType::Docker => self.docker.enabled = on,
                RegistryType::Maven => self.maven.enabled = on,
                RegistryType::Npm => self.npm.enabled = on,
                RegistryType::Cargo => self.cargo.enabled = on,
                RegistryType::PyPI => self.pypi.enabled = on,
                RegistryType::Go => self.go.enabled = on,
                RegistryType::Raw => self.raw.enabled = on,
                RegistryType::Gems => self.gems.enabled = on,
                RegistryType::Terraform => self.terraform.enabled = on,
                RegistryType::Ansible => self.ansible.enabled = on,
                RegistryType::Nuget => self.nuget.enabled = on,
                RegistryType::PubDart => self.pub_dart.enabled = on,
                RegistryType::Conan => self.conan.enabled = on,
                RegistryType::Rpm => self.rpm.enabled = on,
                RegistryType::Deb => self.deb.enabled = on,
                RegistryType::Cpan => self.cpan.enabled = on,
                RegistryType::HuggingFace => self.hf.enabled = on,
                RegistryType::Helm => self.helm.enabled = on,
                RegistryType::Apk => self.apk.enabled = on,
                RegistryType::Github => self.github.enabled = on,
                RegistryType::Hashicorp => self.hashicorp.enabled = on,
            }
        }
    }

    /// Legacy registry resolution from individual `*.enabled` flags.
    fn enabled_registries_legacy(&self) -> HashSet<RegistryType> {
        let mut set = HashSet::new();
        if self.docker.enabled {
            set.insert(RegistryType::Docker);
        }
        if self.maven.enabled {
            set.insert(RegistryType::Maven);
        }
        if self.npm.enabled {
            set.insert(RegistryType::Npm);
        }
        if self.cargo.enabled {
            set.insert(RegistryType::Cargo);
        }
        if self.pypi.enabled {
            set.insert(RegistryType::PyPI);
        }
        if self.go.enabled {
            set.insert(RegistryType::Go);
        }
        if self.raw.enabled {
            set.insert(RegistryType::Raw);
        }
        if self.gems.enabled {
            set.insert(RegistryType::Gems);
        }
        if self.terraform.enabled {
            set.insert(RegistryType::Terraform);
        }
        if self.ansible.enabled {
            set.insert(RegistryType::Ansible);
        }
        if self.nuget.enabled {
            set.insert(RegistryType::Nuget);
        }
        if self.pub_dart.enabled {
            set.insert(RegistryType::PubDart);
        }
        if self.conan.enabled {
            set.insert(RegistryType::Conan);
        }
        if self.rpm.enabled {
            set.insert(RegistryType::Rpm);
        }
        if self.deb.enabled {
            set.insert(RegistryType::Deb);
        }
        if self.cpan.enabled {
            set.insert(RegistryType::Cpan);
        }
        if self.hf.enabled {
            set.insert(RegistryType::HuggingFace);
        }
        if self.helm.enabled {
            set.insert(RegistryType::Helm);
        }
        if self.apk.enabled {
            set.insert(RegistryType::Apk);
        }
        if self.github.enabled {
            set.insert(RegistryType::Github);
        }
        if self.hashicorp.enabled {
            set.insert(RegistryType::Hashicorp);
        }
        if set.is_empty() {
            tracing::warn!("No registries enabled! All registries are disabled.");
        }
        set
    }

    /// Whether `rt` is an enabled registry with at least one upstream proxy configured.
    ///
    /// The `match` is exhaustive over [`RegistryType`], so adding a variant is a
    /// compile error until its proxy shape is declared here — the single source of
    /// truth for "is this an enabled proxy?". Raw has no upstream and is always false.
    /// Per-registry shapes differ: most carry `proxy: Option<String>`, PyPI also has a
    /// multi-upstream `proxies` list, Maven uses `proxies`, Docker uses `upstreams`.
    /// The startup notice on `curation.mode` (#1135): none when curation is on or no proxy
    /// registry is enabled; otherwise which registries are served unchecked, and whether `off`
    /// was the operator's choice or only the default.
    pub fn curation_mode_notice(&self) -> Option<CurationModeNotice> {
        if self.curation.mode != CurationMode::Off {
            return None;
        }
        let proxies: Vec<RegistryType> = RegistryType::all()
            .iter()
            .copied()
            .filter(|&rt| self.is_enabled_proxy(rt))
            .collect();
        if proxies.is_empty() {
            None
        } else if self.curation.mode_explicit {
            Some(CurationModeNotice::ExplicitOff(proxies))
        } else {
            Some(CurationModeNotice::Implicit(proxies))
        }
    }

    fn is_enabled_proxy(&self, rt: RegistryType) -> bool {
        match rt {
            RegistryType::Docker => self.docker.enabled && !self.docker.upstreams.is_empty(),
            RegistryType::Maven => self.maven.enabled && !self.maven.proxies.is_empty(),
            RegistryType::Npm => self.npm.enabled && !self.npm.upstream_urls().is_empty(),
            RegistryType::Cargo => self.cargo.enabled && self.cargo.proxy.is_some(),
            RegistryType::PyPI => {
                self.pypi.enabled && (self.pypi.proxy.is_some() || !self.pypi.proxies.is_empty())
            }
            RegistryType::Go => self.go.enabled && self.go.proxy.is_some(),
            RegistryType::Raw => false, // raw file storage has no upstream
            RegistryType::Gems => self.gems.enabled && self.gems.proxy.is_some(),
            RegistryType::Terraform => self.terraform.enabled && self.terraform.proxy.is_some(),
            RegistryType::Ansible => self.ansible.enabled && self.ansible.proxy.is_some(),
            RegistryType::Nuget => self.nuget.enabled && self.nuget.proxy.is_some(),
            RegistryType::PubDart => self.pub_dart.enabled && self.pub_dart.proxy.is_some(),
            RegistryType::Conan => self.conan.enabled && self.conan.proxy.is_some(),
            RegistryType::Rpm => self.rpm.enabled && !self.rpm.proxies.is_empty(),
            RegistryType::Deb => self.deb.enabled && !self.deb.proxies.is_empty(),
            RegistryType::Cpan => self.cpan.enabled && self.cpan.proxy.is_some(),
            RegistryType::HuggingFace => self.hf.enabled && self.hf.proxy.is_some(),
            RegistryType::Helm => self.helm.enabled && !self.helm.proxies.is_empty(),
            RegistryType::Apk => self.apk.enabled && !self.apk.proxies.is_empty(),
            RegistryType::Github => self.github.enabled && !self.github.download_url.is_empty(),
            RegistryType::Hashicorp => {
                self.hashicorp.enabled && !self.hashicorp.download_url.is_empty()
            }
        }
    }

    /// The effective quarantine mode for `rt`: the per-registry override if set,
    /// else the global `curation.quarantine`, else `Off`.
    ///
    /// The `match` is exhaustive over [`RegistryType`] and the precedence is
    /// byte-identical to the handler resolution (`per.or(global)`, e.g.
    /// `registry/docker.rs::resolve_quarantine`), so config validation and the
    /// runtime DigestStore gate compute the SAME value and cannot diverge — that
    /// divergence was the #765 bug (docker dropped from the hand-rolled chains).
    /// `Raw` has no curation override and no quarantine-enforcing path → always
    /// `Off` (counting it would be a phantom control: `any_quarantine_active`
    /// true while nothing enforces).
    pub(crate) fn quarantine_mode_for(
        &self,
        rt: RegistryType,
    ) -> crate::digest_quarantine::QuarantineMode {
        use crate::digest_quarantine::QuarantineMode;
        let global = self.curation.quarantine.as_ref();
        let per = match rt {
            RegistryType::Docker => self.curation.docker.quarantine.as_ref(),
            RegistryType::Maven => self.curation.maven.quarantine.as_ref(),
            RegistryType::Npm => self.curation.npm.quarantine.as_ref(),
            RegistryType::Cargo => self.curation.cargo.quarantine.as_ref(),
            RegistryType::PyPI => self.curation.pypi.quarantine.as_ref(),
            RegistryType::Go => self.curation.go.quarantine.as_ref(),
            RegistryType::Gems => self.curation.gems.quarantine.as_ref(),
            RegistryType::Terraform => self.curation.terraform.quarantine.as_ref(),
            RegistryType::Ansible => self.curation.ansible.quarantine.as_ref(),
            RegistryType::Nuget => self.curation.nuget.quarantine.as_ref(),
            RegistryType::PubDart => self.curation.pub_dart.quarantine.as_ref(),
            RegistryType::Conan => self.curation.conan.quarantine.as_ref(),
            RegistryType::Rpm => self.curation.rpm.quarantine.as_ref(),
            RegistryType::Deb => self.curation.deb.quarantine.as_ref(),
            // Raw is hosted-only: no curation override, no quarantine gate in
            // its handlers (quarantine gates proxy downloads).
            RegistryType::Raw => return QuarantineMode::Off,
            RegistryType::Cpan => self.curation.cpan.quarantine.as_ref(),
            // Hugging Face has no curation section and its handler no quarantine path
            // (files are kept by the digest the Hub names and checked on the way in), so
            // nothing in it enforces a quarantine; counting it would be the same phantom
            // control as Raw.
            RegistryType::HuggingFace => return QuarantineMode::Off,
            RegistryType::Helm => self.curation.helm.quarantine.as_ref(),
            RegistryType::Apk => self.curation.apk.quarantine.as_ref(),
            RegistryType::Github => self.curation.github.quarantine.as_ref(),
            RegistryType::Hashicorp => self.curation.hashicorp.quarantine.as_ref(),
        };
        per.or(global).cloned().unwrap_or(QuarantineMode::Off)
    }

    /// Whether any registry has an effective quarantine mode other than `Off`.
    ///
    /// Single source of truth for both config validation (the #741 min-release-age
    /// guard and the enforce "at least one control" check) and the runtime
    /// DigestStore gate in `main.rs`. Because it folds [`Self::quarantine_mode_for`]
    /// over [`RegistryType::all`], a per-registry quarantine (e.g. docker-only)
    /// counts everywhere it should: the durable store is loaded iff some registry
    /// actually enforces, closing the #765 fail-open where a docker-only quarantine
    /// got an empty (non-durable) store.
    pub(crate) fn any_quarantine_active(&self) -> bool {
        use crate::digest_quarantine::QuarantineMode;
        RegistryType::all()
            .iter()
            .any(|&rt| self.quarantine_mode_for(rt) != QuarantineMode::Off)
    }

    /// What startup knows about `rt` for its own `min_release_age`; the verdict is
    /// [`registry_min_age_verdict`] of these facts (#1098).
    fn registry_min_age_facts(&self, rt: RegistryType) -> RegistryMinAgeFacts {
        RegistryMinAgeFacts {
            value_set: self
                .curation
                .registry_override(rt)
                .and_then(|o| o.min_release_age.as_deref())
                // "0d" turns the registry's age check off: not a control.
                .is_some_and(|v| crate::curation::parse_duration_or_zero(v) != Ok(0)),
            dated: release_date_check(rt),
            enabled: self.enabled_registries_legacy().contains(&rt),
            proxy: self.is_enabled_proxy(rt),
            quarantined: self.quarantine_mode_for(rt)
                != crate::digest_quarantine::QuarantineMode::Off,
        }
    }

    /// Warn if legacy NORA_*_ENABLED env vars are set while using the new
    /// `[registries].enable` or `NORA_REGISTRIES_ENABLE`.
    fn warn_legacy_env_vars_if_present() {
        // Every registry's flag: the hand-written list left out rpm, deb, cpan and hf, so
        // NORA_HF_ENABLED=true beside an enable-set was ignored without a word.
        let legacy_vars: Vec<&str> = RegistryType::all()
            .iter()
            .map(|&rt| legacy_enable_var(rt))
            .collect();
        let found: Vec<&str> = legacy_vars
            .iter()
            .filter(|v| env::var(v).is_ok())
            .copied()
            .collect();
        if !found.is_empty() {
            tracing::warn!(
                vars = ?found,
                "Legacy NORA_*_ENABLED env vars are set but ignored — \
                 [registries].enable or NORA_REGISTRIES_ENABLE takes precedence"
            );
        }
    }

    /// Warn if credentials are configured via config.toml (not env vars)
    pub fn warn_plaintext_credentials(&self) {
        // Docker upstreams
        for (i, upstream) in self.docker.upstreams.iter().enumerate() {
            if upstream.auth.is_some()
                && upstream.auth_env.is_none()
                && std::env::var("NORA_DOCKER_PROXIES").is_err()
                && std::env::var("NORA_DOCKER_UPSTREAMS").is_err()
            {
                tracing::warn!(
                    upstream_index = i,
                    url = %upstream.url,
                    "Docker upstream credentials in config.toml are plaintext — consider NORA_DOCKER_PROXIES env var"
                );
            }
        }
        // Maven proxies
        for proxy in &self.maven.proxies {
            if proxy.auth().is_some() && std::env::var("NORA_MAVEN_PROXIES").is_err() {
                tracing::warn!(
                    url = %proxy.url(),
                    "Maven proxy credentials in config.toml are plaintext — consider NORA_MAVEN_PROXIES env var"
                );
            }
        }
        // Go
        if self.go.proxy_auth.is_some() && std::env::var("NORA_GO_PROXY_AUTH").is_err() {
            tracing::warn!("Go proxy credentials in config.toml are plaintext — consider NORA_GO_PROXY_AUTH env var");
        }
        // npm
        if self.npm.proxy_auth.is_some() && std::env::var("NORA_NPM_PROXY_AUTH").is_err() {
            tracing::warn!("npm proxy credentials in config.toml are plaintext — consider NORA_NPM_PROXY_AUTH env var");
        }
        // npm multi-upstream (#1055): Basic `auth` on an entry is plaintext; Bearer is env-only.
        for proxy in &self.npm.proxies {
            if let NpmProxyEntry::Full(p) = proxy {
                if p.auth.is_some() {
                    tracing::warn!(
                        url = %p.url,
                        "npm upstream credentials in config.toml are plaintext — consider auth_bearer_env"
                    );
                }
            }
        }
        // PyPI
        if self.pypi.proxy_auth.is_some() && std::env::var("NORA_PYPI_PROXY_AUTH").is_err() {
            tracing::warn!("PyPI proxy credentials in config.toml are plaintext — consider NORA_PYPI_PROXY_AUTH env var");
        }
        // PyPI multi-upstream proxies (#663)
        for proxy in &self.pypi.proxies {
            if proxy.auth().is_some() && std::env::var("NORA_PYPI_PROXIES").is_err() {
                tracing::warn!(
                    url = %proxy.url(),
                    "PyPI upstream credentials in config.toml are plaintext — consider NORA_PYPI_PROXIES env var"
                );
            }
        }
        // Cargo
        if self.cargo.proxy_auth.is_some() && std::env::var("NORA_CARGO_PROXY_AUTH").is_err() {
            tracing::warn!("Cargo proxy credentials in config.toml are plaintext — consider NORA_CARGO_PROXY_AUTH env var");
        }
        // Auth posture: a silently-unauthenticated instance must not look safe.
        // The zero-config default is auth.enabled=false, which accepts BOTH reads
        // and writes from anyone; surface it loudly so it is a deliberate choice.
        if !self.auth.enabled {
            tracing::warn!(
                "auth.enabled=false — NORA is accepting UNAUTHENTICATED reads AND writes. \
                 Set auth.enabled=true (with htpasswd/tokens/OIDC) before exposing this instance."
            );
        } else if self.auth.anonymous_read {
            tracing::warn!(
                "auth.anonymous_read=true — pulls/downloads are served without authentication \
                 (writes still require a token); ensure this is intended for this deployment."
            );
        }
        // Independent of anonymous_read: anonymous Docker pull serves container
        // images to anyone (push still requires auth). Surface it on its own.
        if self.auth.enabled && self.auth.docker_anon_pull {
            tracing::warn!(
                "auth.docker_anon_pull=true — Docker/OCI images are served on anonymous \
                 `docker pull` without authentication (push still requires a token); ensure this \
                 is intended for this deployment."
            );
        }
    }

    /// Collect all configured upstream hostnames for leak detection (#386).
    ///
    /// Returns `(registry_name, hostname)` pairs extracted from proxy URLs.
    /// Used once at startup to pre-compile substring searchers.
    pub fn upstream_hostnames(&self) -> Vec<(String, String)> {
        let mut result = Vec::new();

        let extract_host = |url: &str| -> Option<String> {
            let without_scheme = url
                .strip_prefix("https://")
                .or_else(|| url.strip_prefix("http://"))
                .unwrap_or(url);
            let host = without_scheme.split('/').next()?;
            let host = host.split(':').next()?;
            if host.is_empty() || host == "localhost" || host == "127.0.0.1" {
                return None;
            }
            Some(host.to_lowercase())
        };

        // Simple proxy: Option<String>
        let simple = [
            ("cargo", self.cargo.proxy.as_deref()),
            ("go", self.go.proxy.as_deref()),
            ("gems", self.gems.proxy.as_deref()),
            ("terraform", self.terraform.proxy.as_deref()),
            ("ansible", self.ansible.proxy.as_deref()),
            ("nuget", self.nuget.proxy.as_deref()),
            ("pub", self.pub_dart.proxy.as_deref()),
            ("conan", self.conan.proxy.as_deref()),
            ("cpan", self.cpan.proxy.as_deref()),
            // Not hf: its metadata carries the Hub's host as content (a model card's
            // `license_link`), so a body scan reports leaks that are not; the URLs NORA
            // hands an hf client travel in headers, which the handler lists by name.
        ];
        for (name, url) in simple {
            if let Some(url) = url {
                if let Some(host) = extract_host(url) {
                    result.push((name.to_string(), host));
                }
            }
        }
        // npm: every upstream, private ones included (#1055) — a private registry
        // host in a served packument is exactly the leak this list exists to catch.
        for url in self.npm.upstream_urls() {
            if let Some(host) = extract_host(url) {
                result.push((RegistryType::Npm.as_str().to_string(), host));
            }
        }

        // NuGet extra search/autocomplete URLs
        if let Some(host) = extract_host(&self.nuget.search_service) {
            result.push((
                crate::registry_type::RegistryType::Nuget
                    .as_str()
                    .to_string(),
                host,
            ));
        }
        if let Some(host) = extract_host(&self.nuget.autocomplete) {
            result.push((
                crate::registry_type::RegistryType::Nuget
                    .as_str()
                    .to_string(),
                host,
            ));
        }

        // Docker upstreams: Vec<DockerUpstream>
        for upstream in &self.docker.upstreams {
            if let Some(host) = extract_host(&upstream.url) {
                result.push((
                    crate::registry_type::RegistryType::Docker
                        .as_str()
                        .to_string(),
                    host,
                ));
            }
        }

        // Maven proxies: Vec<MavenProxyEntry>
        for proxy in &self.maven.proxies {
            if let Some(host) = extract_host(proxy.url()) {
                result.push((
                    crate::registry_type::RegistryType::Maven
                        .as_str()
                        .to_string(),
                    host,
                ));
            }
        }

        // RPM/DEB per-repo proxies: BTreeMap<repo, RepoProxyEntry>
        // Not helm: an index names its upstream host as content (a dependency's
        // `repository`, a chart's `home`), while every chart URL NORA serves is rewritten.
        for (name, proxies) in [("rpm", &self.rpm.proxies), ("deb", &self.deb.proxies)] {
            for entry in proxies.values() {
                if let Some(host) = extract_host(entry.url()) {
                    result.push((name.to_string(), host));
                }
            }
        }

        // PyPI upstreams: Vec<PypiProxyEntry> via upstreams() so the multi-upstream
        // list (#663) AND the legacy single `proxy` are both registered with the
        // leak detector — otherwise a secondary upstream's host (e.g. an internal
        // mirror with embedded credentials) would be invisible to leak scanning.
        for up in self.pypi.upstreams() {
            if let Some(host) = extract_host(up.url()) {
                result.push((
                    crate::registry_type::RegistryType::PyPI
                        .as_str()
                        .to_string(),
                    host,
                ));
            }
        }

        // Deduplicate
        result.sort();
        result.dedup();
        result
    }

    /// Validate configuration and return (warnings, errors).
    ///
    /// Warnings are logged but do not prevent startup.
    /// Errors indicate a fatal misconfiguration and should cause a panic.
    pub fn validate(&self) -> (Vec<String>, Vec<String>) {
        self.validate_with_config_path(env::var("NORA_CONFIG_PATH").ok())
    }

    /// True if `host` is a loopback address (the 127.0.0.0/8 block or ::1) or
    /// the `localhost` hostname (case-insensitive). Used to warn when a service
    /// index would be built from a loopback bind address, unreachable by remote
    /// clients (#590). Callers passing a URL host must strip IPv6 brackets first
    /// (`url::host_str()` returns "[::1]", which does not parse as an `IpAddr`).
    pub(crate) fn is_loopback_host(host: &str) -> bool {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or(false)
    }

    /// Validate configuration with explicit config_path to avoid env var
    /// dependency in tests (env vars are process-global, tests run in parallel).
    pub fn validate_with_config_path(
        &self,
        config_path: Option<String>,
    ) -> (Vec<String>, Vec<String>) {
        let mut warnings = Vec::new();
        let mut errors = Vec::new();

        // 1. Port must not be 0
        if self.server.port == 0 {
            errors.push("server.port must not be 0".to_string());
        }
        if let Some(internal) = self.server.internal_port {
            if internal == 0 || internal == self.server.port {
                errors.push("server.internal_port must not be 0 nor equal server.port".to_string());
            }
        }

        // 1a. Connection limits: a zero would close every connection at once or accept none.
        for (key, value) in [
            (
                "server.header_read_timeout",
                self.server.header_read_timeout,
            ),
            ("server.keep_alive_timeout", self.server.keep_alive_timeout),
            ("server.max_connections", self.server.max_connections as u64),
        ] {
            if value == 0 {
                errors.push(format!("{key} must not be 0"));
            }
        }

        let keep_alive = self.server.keep_alive_timeout;
        if (1..=server::PROXY_IDLE_SECS).contains(&keep_alive) {
            warnings.push(format!(
                "server.keep_alive_timeout is {keep_alive} s, not above the {} s a reverse proxy \
                 such as traefik keeps an idle connection to NORA: the proxy may send a request \
                 into a connection NORA is closing and answer 502. Set it above {} (default 120)",
                server::PROXY_IDLE_SECS,
                server::PROXY_IDLE_SECS
            ));
        }

        if self.server.maintenance_stall_secs < server::MIN_MAINTENANCE_STALL_SECS {
            errors.push(format!(
                "server.maintenance_stall_secs must be at least {} (three maintenance ticks), got {}",
                server::MIN_MAINTENANCE_STALL_SECS,
                self.server.maintenance_stall_secs
            ));
        }

        // 1b. Wildcard host requires public_url (non-routable address → broken client URLs)
        {
            let host = &self.server.host;
            let is_wildcard = host == "0.0.0.0" || host == "::" || host == "0:0:0:0:0:0:0:0";

            if is_wildcard && self.server.public_url.is_none() {
                errors.push(format!(
                    "NORA_PUBLIC_URL is required when host is '{}' (not routable). \
                     Set: NORA_PUBLIC_URL=http://your-registry:{}",
                    host, self.server.port
                ));
            }
        }

        // 1c. Validate public_url format if set
        if let Some(ref url_str) = self.server.public_url {
            match reqwest::Url::parse(url_str) {
                Ok(parsed) => {
                    let scheme = parsed.scheme();
                    if scheme != "http" && scheme != "https" {
                        errors.push(format!(
                            "NORA_PUBLIC_URL must use http:// or https:// scheme, got: '{}'",
                            scheme
                        ));
                    }
                    // public_url explicitly set to a loopback host is also broken for
                    // remote clients — the operator configured the footgun directly (#590).
                    // host_str() returns IPv6 literals with brackets ("[::1]"), which do
                    // not parse as an IpAddr — strip them before the loopback check.
                    if let Some(h) = parsed.host_str() {
                        let h = h.trim_start_matches('[').trim_end_matches(']');
                        if Self::is_loopback_host(h) {
                            warnings.push(format!(
                                "NORA_PUBLIC_URL points at loopback ('{}') — clients behind a \
                                 reverse proxy cannot reach it. Use the externally-reachable \
                                 hostname, e.g. https://registry.example.com",
                                h
                            ));
                        }
                    }
                }
                Err(e) => {
                    errors.push(format!(
                        "NORA_PUBLIC_URL is not a valid URL: '{}' — {}",
                        url_str, e
                    ));
                }
            }
        }

        // 2. Storage path must not be empty when mode = Local
        if self.storage.mode == StorageMode::Local && self.storage.path.trim().is_empty() {
            errors.push("storage.path must not be empty when storage mode is local".to_string());
        }

        // 3. Bucket must not be empty when mode = S3 or GCS
        if matches!(self.storage.mode, StorageMode::S3 | StorageMode::Gcs)
            && self.storage.bucket.trim().is_empty()
        {
            errors.push(
                "storage.bucket must not be empty when storage mode is s3 or gcs".to_string(),
            );
        }

        // 3b. s3 mode without credentials signs nothing: a mistyped key variable must
        // not silently turn every request anonymous (the bucket then answers 403 and
        // /ready stays 503). An explicit `s3_anonymous` opts in.
        if self.storage.mode == StorageMode::S3 && !self.storage.s3_anonymous {
            let has_dir = self
                .storage
                .s3_credentials_dir
                .as_deref()
                .is_some_and(|d| !d.is_empty());
            let keys = match (
                self.storage.s3_access_key.is_some(),
                self.storage.s3_secret_key.is_some(),
            ) {
                (true, true) => None,
                (true, false) => Some("only storage.s3_access_key is set"),
                (false, true) => Some("only storage.s3_secret_key is set"),
                (false, false) => Some("no S3 credentials are set"),
            };
            if let (false, Some(what)) = (has_dir, keys) {
                let msg = format!(
                    "storage mode is s3 but {what}: requests go unsigned. Set \
                     NORA_STORAGE_S3_ACCESS_KEY and NORA_STORAGE_S3_SECRET_KEY, or \
                     storage.s3_credentials_dir, or storage.s3_anonymous = true for a \
                     public bucket"
                );
                if config_strict_from_env() {
                    errors.push(msg);
                } else {
                    warnings.push(msg);
                }
            }
        }

        // 3a. raw.cache_control is sent as a header on every raw GET and HEAD.
        if axum::http::HeaderValue::from_str(&self.raw.cache_control).is_err() {
            let msg = format!(
                "raw.cache_control {:?} is not a valid header value (a control character or \
                 a line break)",
                self.raw.cache_control
            );
            if config_strict_from_env() {
                errors.push(msg);
            } else {
                warnings.push(format!("{msg}: \"no-cache\" is sent instead"));
            }
        }

        // 4. Rate limit values must be > 0 when rate limiting is enabled
        if self.rate_limit.enabled {
            if self.rate_limit.auth_rps == 0 {
                warnings
                    .push("rate_limit.auth_rps is 0 while rate limiting is enabled".to_string());
            }
            if self.rate_limit.auth_burst == 0 {
                warnings
                    .push("rate_limit.auth_burst is 0 while rate limiting is enabled".to_string());
            }
            if self.rate_limit.upload_rps == 0 {
                warnings
                    .push("rate_limit.upload_rps is 0 while rate limiting is enabled".to_string());
            }
            if self.rate_limit.upload_burst == 0 {
                warnings.push(
                    "rate_limit.upload_burst is 0 while rate limiting is enabled".to_string(),
                );
            }
            if self.rate_limit.general_rps == 0 {
                warnings
                    .push("rate_limit.general_rps is 0 while rate limiting is enabled".to_string());
            }
            if self.rate_limit.general_burst == 0 {
                warnings.push(
                    "rate_limit.general_burst is 0 while rate limiting is enabled".to_string(),
                );
            }
        }

        // 5. Body limit must be > 0
        if self.server.body_limit_mb == 0 {
            warnings
                .push("server.body_limit_mb is 0, no request bodies will be accepted".to_string());
        }

        // 6. Relative paths — may resolve unexpectedly.
        // The storage.path hint is scoped to explicit-config starts, to avoid noise
        // on the relative default of a bare `nora serve`.
        if config_path.is_some()
            && self.storage.mode == StorageMode::Local
            && !self.storage.path.starts_with('/')
        {
            warnings.push(format!(
                "storage.path=\"{}\" is relative — will resolve from CWD. Use absolute path for predictable behavior",
                self.storage.path
            ));
        }
        // The token_storage hint fires whenever auth is enabled with a relative
        // path, regardless of config source: env-only (systemd) starts have
        // config_path=None yet are exactly where a relative token_storage resolves
        // somewhere else (#816). Maestra: it is the legacy token import directory.
        if self.auth.enabled && !self.auth.token_storage.starts_with('/') {
            warnings.push(format!(
                "auth.token_storage=\"{}\" is relative — will resolve from CWD, and the boot \
                 import of legacy token files reads that directory. Set an absolute path, e.g. \
                 NORA_AUTH_TOKEN_STORAGE=/var/lib/nora/tokens",
                self.auth.token_storage
            ));
        }

        // 7. Trusted proxies /0 — security footgun
        if self.auth.trusted_proxies.has_prefix_zero() {
            warnings.push(
                "auth.trusted_proxies contains a /0 CIDR — all peers are trusted proxies. \
                 X-Forwarded-For will be honored from any source, disabling IP-based brute-force protection"
                    .to_string(),
            );
        }

        // 7b. An OIDC provider without an audience would accept a token its
        // issuer minted for any other service — on a shared issuer such as
        // GitHub Actions, any repository on the host. It is refused; turning
        // the check off takes `any_audience = true`, which is warned about.
        if self.auth.oidc.enabled {
            for provider in self.auth.oidc.providers.iter().filter(|p| p.enabled) {
                match provider.audience_check() {
                    AudienceCheck::Missing => errors.push(format!(
                        "auth.oidc provider \"{}\" has no audience, so a token its issuer \
                         minted for any other service would be accepted. Set audience = \"<the aud \
                         your CI jobs request>\" (e.g. audience = \"nora\"), or any_audience = true \
                         to accept a token for any audience",
                        provider.name
                    )),
                    AudienceCheck::Any => warnings.push(format!(
                        "auth.oidc provider \"{}\" has any_audience = true — the `aud` claim is \
                         not checked, so a token its issuer minted for any other service is \
                         accepted",
                        provider.name
                    )),
                    AudienceCheck::Expect(_) if provider.any_audience => warnings.push(format!(
                        "auth.oidc provider \"{}\" sets both audience and any_audience — \
                         any_audience is ignored and the audience is checked",
                        provider.name
                    )),
                    AudienceCheck::Expect(_) => {}
                }
                if provider.session_lifetime_secs
                    > crate::auth::oidc_session::MAX_SESSION_LIFETIME_SECS
                {
                    errors.push(format!(
                        "auth.oidc provider \"{}\" has session_lifetime_secs = {}, more than {}",
                        provider.name,
                        provider.session_lifetime_secs,
                        crate::auth::oidc_session::MAX_SESSION_LIFETIME_SECS
                    ));
                }
            }
        }

        // An interval of 0 is not "disabled": every pass would be due again the moment it
        // ends, listing the whole store back to back under the cleanup lock. The hosted NuGet
        // cleanup runs on the retention interval, with or without retention rules.
        if self.gc.enabled && self.gc.interval == 0 {
            errors.push(
                "gc.interval must be at least 1 second, got 0 (to turn GC off set gc.enabled=false)"
                    .to_string(),
            );
        }
        if (self.retention.enabled || self.nuget.enabled) && self.retention.interval == 0 {
            errors.push(
                "retention.interval must be at least 1 second, got 0 (to turn retention off set retention.enabled=false; the hosted NuGet cleanup runs on this interval whenever nuget.enabled)"
                    .to_string(),
            );
        }

        // 8. "Enabled but empty" — subsystems that silently do nothing
        if self.gc.enabled && self.gc.dry_run {
            warnings.push(
                "gc.enabled=true with gc.dry_run=true — GC will run but never delete anything. Set gc.dry_run=false to actually free space".to_string(),
            );
        }
        if self.retention.enabled && self.retention.dry_run && !self.retention.rules.is_empty() {
            warnings.push(
                "retention.enabled=true with retention.dry_run=true — retention will run but never delete anything. Set retention.dry_run=false to actually enforce policies".to_string(),
            );
        }
        if self.retention.enabled && self.retention.rules.is_empty() {
            warnings.push(
                "retention.enabled=true but no retention rules configured — retention scheduler will run but do nothing. Add [retention.rules] or set retention.enabled=false".to_string(),
            );
        }

        // 8. Curation validation.
        // Compute once: is any first-seen quarantine active (global or per-registry)?
        // Used by both the enforce "at least one control" check and the
        // min-release-age age-control requirement below.
        // Exhaustive over RegistryType via any_quarantine_active (a compiler-enforced
        // match): the hand-rolled OR-chain here previously omitted docker, so a
        // docker-only [curation.docker] quarantine read as "inactive" and falsely
        // failed this validation (#765). Counts a registry iff its effective mode
        // (per-registry override .or(global)) is not Off — the same value the
        // handlers and the main.rs store gate use.
        let quarantine_active = self.any_quarantine_active();

        // Every curation duration parses, in every mode: a typo in one is a
        // configuration error naming it, never a silent default (#1099).
        errors.extend(self.curation.duration_errors());

        // Enforce mode must have at least ONE active control, otherwise it blocks
        // nothing. An allowlist is one option, not the only one — a blocklist,
        // min-release-age, an active quarantine, namespace isolation, or integrity
        // checking each make enforce meaningful, so a deny-list-only / age-only /
        // quarantine-only policy is valid (#740).
        // A per-registry min_release_age is a control on its own when it applies
        // (#1098): not on a disabled registry, nor where it is refused below.
        let any_registry_min_age = RegistryType::all().iter().any(|&rt| {
            registry_min_age_verdict(self.registry_min_age_facts(rt))
                == RegistryMinAgeVerdict::Applies
        });
        // require_integrity asks for an integrity hash on every allowlist entry; the allowlist
        // filter is its only reader. Without an allowlist it holds nothing, so it is refused
        // instead of counted as a control (enforce with it alone used to start and block nothing).
        if self.curation.require_integrity && self.curation.allowlist_path.is_none() {
            errors.push(
                "curation.require_integrity is set, but it applies only to allowlist entries (an integrity hash on each) and curation.allowlist_path is not set, so it would hold nothing. Set curation.allowlist_path, or unset require_integrity.".to_string(),
            );
        }
        if self.curation.mode == CurationMode::Enforce {
            let any_control = self.curation.allowlist_path.is_some()
                || self.curation.blocklist_path.is_some()
                || self.curation.min_release_age.is_some()
                || any_registry_min_age
                || quarantine_active
                || !self.curation.internal_namespaces.is_empty();
            if !any_control {
                errors.push(
                    "curation.mode=enforce but no active control is configured — enforce would block nothing. Set at least one of: allowlist_path, blocklist_path, min_release_age, quarantine, or internal_namespaces.".to_string(),
                );
            }
            if let Some(ref path) = self.curation.allowlist_path {
                if !std::path::Path::new(path).exists() {
                    errors.push(format!(
                        "curation.allowlist_path=\"{}\" does not exist (required for enforce mode)",
                        path
                    ));
                }
            }
        }
        if self.curation.bypass_token.is_some() && env::var("NORA_CURATION_BYPASS_TOKEN").is_err() {
            warnings.push(
                "curation.bypass_token is set in config file — consider using NORA_CURATION_BYPASS_TOKEN env var instead".to_string(),
            );
        }
        if self.curation.mode == CurationMode::Audit && self.curation.allowlist_path.is_none() {
            warnings.push(
                "curation.mode=audit but no allowlist_path configured — no allowlist filter will be active".to_string(),
            );
        }
        if self.curation.on_failure != CurationOnFailure::Closed {
            errors.push(
                "curation.on_failure=\"open\" is not implemented and would silently degrade to fail-closed. Remove the setting or set on_failure=\"closed\" explicitly. This field will be removed in v0.9".to_string(),
            );
        }
        // min_release_age on a proxy registry requires an active quarantine. On the
        // proxy path the upstream publish date is unsigned/spoofable AND, for most
        // registries, not resolvable at all (the date-bearing upstream metadata is
        // not cached at the curation point — the same root cause as #741), so
        // min-age DEFERS (Skip). server.trust_upstream_dates yields a real date only
        // where the registry caches one (npm); for pypi/cargo/nuget/gems/… it stays
        // None and min-age silently does nothing — so trust is NOT a sufficient age
        // control, only the unspoofable quarantine is. Refuse min-age on an enabled
        // proxy without a quarantine (curation-minage-real-age-defer, #741).
        {
            // Exhaustive over RegistryType via is_enabled_proxy (a compiler-enforced
            // match): adding a registry variant forces a new arm, so this guard can
            // never silently forget one again. The hand-rolled list here previously
            // omitted docker, leaving a docker-only proxy with min_release_age and no
            // quarantine unwarned (#741 follow-up).
            let any_enabled_proxy = RegistryType::all()
                .iter()
                .any(|&rt| self.is_enabled_proxy(rt));
            if self.curation.min_release_age.is_some() && !quarantine_active && any_enabled_proxy {
                errors.push(
                    "curation.min_release_age is set with an enabled proxy registry but no age control would be active: on the proxy path an upstream publish date is unsigned/spoofable and is not resolved for most registries, so min-release-age silently does nothing without a quarantine. Enable curation.quarantine=\"observe\"|\"enforce\" (the unspoofable first-seen age control). server.trust_upstream_dates enhances min-release-age with real upstream dates where a registry caches one (e.g. npm) but is NOT a substitute for the quarantine. (#741)".to_string(),
                );
            }
            // A registry's own value applies without a global one (#1098). What startup
            // does with it is registry_min_age_verdict of the registry's facts: it needs
            // a quarantine of that registry — its own or the global one — when that
            // registry is an enabled proxy (a quarantine on another registry holds none
            // of its downloads, and trusted upstream dates are no substitute, #741); it
            // can never apply where the downloads carry no release date; on a disabled
            // registry it holds nothing.
            for &rt in RegistryType::all() {
                let Some(age) = self
                    .curation
                    .registry_override(rt)
                    .and_then(|o| o.min_release_age.as_deref())
                else {
                    continue;
                };
                match registry_min_age_verdict(self.registry_min_age_facts(rt)) {
                    RegistryMinAgeVerdict::NotSet | RegistryMinAgeVerdict::Applies => {}
                    RegistryMinAgeVerdict::CannotApply => {
                        let why = match release_date_check(rt) {
                            ReleaseDateCheck::NoNameOrDate => format!(
                                "{rt} downloads are not checked by name or release date. Remove it; curation.{rt}.quarantine holds new {rt} packages"
                            ),
                            ReleaseDateCheck::NoDate | ReleaseDateCheck::Dated => format!(
                                "{rt} downloads carry no release date to check. Remove it; a quarantine holds new {rt} packages"
                            ),
                        };
                        errors.push(format!(
                            "curation.{rt}.min_release_age=\"{age}\" cannot apply: {why}. (#1098)"
                        ));
                    }
                    RegistryMinAgeVerdict::Unused => warnings.push(format!(
                        "curation.{rt}.min_release_age=\"{age}\" is set but {rt} is not enabled: it holds nothing and is not an active control. (#1098)"
                    )),
                    RegistryMinAgeVerdict::NeedsQuarantine => errors.push(format!(
                        "curation.{rt}.min_release_age=\"{age}\" is set and {rt} is an enabled proxy registry, but no age control would be active: on the proxy path an upstream publish date is unsigned/spoofable and is not resolved for most registries, so min-release-age silently does nothing without a quarantine of {rt} (one on another registry does not hold {rt} downloads). Enable curation.quarantine or curation.{rt}.quarantine=\"observe\"|\"enforce\". (#741, #1098)"
                    )),
                }
            }
        }

        // Hugging Face: a Hub commit has no publish date NORA reads, and hf has no quarantine
        // path, so min_release_age would hold nothing there — refused rather than ignored
        // (hf-curation-applies).
        if self.curation.min_release_age.is_some()
            && self.is_enabled_proxy(RegistryType::HuggingFace)
        {
            errors.push(
                "curation.min_release_age cannot hold the Hugging Face proxy: a Hub commit has no publish date NORA reads, and hf has no quarantine path. Unset curation.min_release_age, or disable [hf]. (#579)".to_string(),
            );
        }
        // Hugging Face has no curation section of its own, so NORA_CURATION_HF_* is read by
        // nothing: refused rather than ignored, as [curation.hf] is at load.
        for var in hf_curation_env_vars() {
            if env::var(var).is_ok() {
                errors.push(hf_curation_refusal(var));
            }
        }

        // A redirect of a Hugging Face file request leaves the upstream only for these hosts.
        for host in self.hf.invalid_cdn_hosts() {
            errors.push(format!(
                "hf.cdn_hosts entry {host:?} is not a host name or IP address (no scheme, port, path or wildcard): it names the hosts a file request's redirect may go to"
            ));
        }

        // A helm repo is served at `/helm/<name>/`: the name is one plain path segment,
        // and `trust_created` can only name a configured repo.
        for name in self.helm.proxies.keys() {
            if name.is_empty()
                || name.starts_with('.')
                || !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            {
                errors.push(format!(
                    "helm.proxies name {name:?} is not a plain path segment (letters, digits, '-', '_', '.')"
                ));
            }
        }
        for name in &self.helm.trust_created {
            if !self.helm.proxies.contains_key(name) {
                warnings.push(format!(
                    "helm.trust_created names {name:?}, which is not in [helm.proxies]: it trusts nothing"
                ));
            }
        }
        // An apk mirror is served at `/apk/<name>/`, its public key at `/apk/keys/<key_name>`;
        // every served index is signed, so an enabled proxy without loadable keys is an error.
        for name in self.apk.proxies.keys() {
            if !is_plain_segment(name) || name == "keys" {
                errors.push(format!(
                    "apk.proxies name {name:?} is not a plain path segment (letters, digits, '-', '_', '.'; not \"keys\")"
                ));
            }
        }
        if self.apk.enabled && !self.apk.proxies.is_empty() {
            if !is_plain_segment(&self.apk.key_name) {
                errors.push(format!(
                    "apk.key_name {:?} is not a plain file name",
                    self.apk.key_name
                ));
            }
            if let Err(e) = crate::registry::apk::check_keys(&self.apk) {
                errors.push(e);
            }
        }
        // maestra: a filtered apt proxy verifies the upstream InRelease with
        // deb.upstream_keyring_dir and signs its own with the [signing] key.
        #[cfg(feature = "deb")]
        if self.deb.enabled
            && !self.deb.proxies.is_empty()
            && self.curation.deb.min_release_age.is_some()
        {
            if let Err(e) =
                crate::registry::deb_proxy::check_keyring(&self.deb.upstream_keyring_dir)
            {
                errors.push(format!(
                    "curation.deb.min_release_age filters the [deb.proxies] repositories, which needs the upstream archive keys: {e}"
                ));
            }
            if !self.signing.enabled
                || (self.signing.key_path.is_empty() && self.storage.mode != StorageMode::Local)
            {
                errors.push(
                    "curation.deb.min_release_age filters the [deb.proxies] repositories, which NORA re-signs: enable [signing] and set signing.key_path (required off local storage)".to_string(),
                );
            }
            if self.deb.architectures.is_empty() {
                errors.push(
                    "deb.architectures is empty: a filtered apt proxy would serve no index"
                        .to_string(),
                );
            }
        }
        for u in &self.docker.upstreams {
            let undated = u.date_source().is_none();
            let tokenless =
                u.date_source() == Some(DateSource::GhcrCreatedAt) && u.date_token_file.is_none();
            if u.trust_upstream_dates && (undated || tokenless) {
                let msg = if undated {
                    format!(
                        "docker.upstreams {:?} sets trust_upstream_dates, but {} publishes no date NORA reads (Docker Hub, quay.io, registry.k8s.io, gcr.io, Artifact Registry, ghcr.io, mcr.microsoft.com, public.ecr.aws and cgr.dev do): first-seen applies",
                        u.url,
                        u.resolved_namespace()
                    )
                } else {
                    format!(
                        "docker.upstreams {:?} sets trust_upstream_dates without date_token_file: the GitHub packages API answers only with a token, so first-seen applies",
                        u.url
                    )
                };
                if config_strict_from_env() {
                    errors.push(msg);
                } else {
                    warnings.push(msg);
                }
            }
        }

        // 8b. Per-registry `allow` entries (Maestra fork): an entry nora cannot read
        // exempts nothing (the versions it meant stay held), so it is a warning and
        // is refused under NORA_CONFIG_STRICT. `*` alone, an empty prefix, a `*`
        // inside a name and version globs are such entries: a pattern exempts every
        // version of the names it covers, so its syntax is kept narrow.
        for &rt in RegistryType::all() {
            let Some(registry) = self.curation.registry_override(rt) else {
                continue;
            };
            for entry in &registry.allow {
                if let Err(e) = crate::curation::AllowEntry::parse(rt, entry) {
                    if config_strict_from_env() {
                        errors.push(format!("{e} (NORA_CONFIG_STRICT is on)"));
                    } else {
                        warnings.push(format!("{e} (the entry is ignored)"));
                    }
                }
            }
        }

        // 9. Docker upstream prefix validation
        {
            use registry::RESERVED_DOCKER_SEGMENTS as RESERVED_PREFIXES;
            let mut seen_prefixes = std::collections::HashSet::new();
            for (i, upstream) in self.docker.upstreams.iter().enumerate() {
                if let Some(var) = &upstream.auth_env {
                    if upstream.auth.is_none() {
                        errors.push(format!(
                            "docker.upstreams[{i}]: auth_env names {var}, which is unset or empty"
                        ));
                    }
                }
                if let Some(ref prefix) = upstream.prefix {
                    if prefix.is_empty() {
                        errors.push(format!(
                            "docker.upstreams[{}]: prefix must not be empty (omit the field instead)",
                            i
                        ));
                    } else if prefix.contains('/') {
                        errors.push(format!(
                            "docker.upstreams[{}]: prefix \"{}\" must not contain '/'",
                            i, prefix
                        ));
                    } else if prefix != &prefix.to_lowercase() {
                        errors.push(format!(
                            "docker.upstreams[{}]: prefix \"{}\" must be lowercase (Docker names are lowercase)",
                            i, prefix
                        ));
                    } else if RESERVED_PREFIXES.contains(&prefix.as_str()) {
                        errors.push(format!(
                            "docker.upstreams[{}]: prefix \"{}\" is a reserved Docker API path segment",
                            i, prefix
                        ));
                    } else if !seen_prefixes.insert(prefix.clone()) {
                        errors.push(format!(
                            "docker.upstreams[{}]: duplicate prefix \"{}\"",
                            i, prefix
                        ));
                    }
                }
            }
        }

        // 9b. Docker default_action=deny without any prefixed or bound upstream is a no-op trap
        if self.docker.default_action == DefaultAction::Deny
            && self.docker.enabled
            && !self
                .docker
                .upstreams
                .iter()
                .any(|u| u.prefix.is_some() || u.is_bound())
        {
            warnings.push(
                "docker.default_action=\"deny\" but no upstream has a prefix or namespaces configured — \
                 all requests will be denied. Add prefix= or namespaces= to at least one [[docker.upstreams]]"
                    .to_string(),
            );
        }

        // 9b'. Docker upstream namespaces (#1188): one owner per name, no pattern in prefix
        {
            let (w, e) = self
                .docker
                .namespaces_problems(&self.curation.internal_namespaces);
            warnings.extend(w);
            errors.extend(e);
        }

        // 9c. npm multi-upstream (#1055): scope ownership, one default, credentials
        {
            let (w, e) = self.npm.proxies_problems();
            warnings.extend(w);
            errors.extend(e);
        }

        // 10. [registries].enable validation
        if let Some(ref section) = self.registries {
            if let Some(ref spec) = section.enable {
                if let Err(e) = spec.resolve() {
                    errors.push(format!("[registries].enable: {}", e));
                }
            }
        }

        (warnings, errors)
    }

    /// Load configuration with priority: ENV > config file > defaults
    ///
    /// Config file resolution order:
    /// 1. `NORA_CONFIG_PATH` env var (fatal if set but file not found)
    /// 2. `config.toml` in current working directory (optional)
    /// 3. Built-in defaults
    ///
    /// A configuration NORA cannot start with is an error, for the caller to report and
    /// exit on with [`EXIT_CONFIG`].
    pub fn load() -> Result<Self, ConfigLoadError> {
        let (config, _unknown_keys) = Self::load_from(
            Self::path_from_env(),
            DEFAULT_CONFIG_FILE,
            config_strict_from_env(),
        )?;
        Ok(config)
    }

    /// [`Config::load`] with `NORA_CONFIG_PATH`, the fallback file and `NORA_CONFIG_STRICT`
    /// passed in, so tests can drive it without setting process-wide state that `validate`
    /// also reads. Also returns the unknown keys of the file it read: logged once, or
    /// refused in strict mode.
    fn load_from(
        config_path: Option<String>,
        fallback: &str,
        strict: bool,
    ) -> Result<(Self, Vec<String>), ConfigLoadError> {
        let mut unknown_keys = Vec::new();
        // 1. Start with defaults
        // 2. Override with config file if exists
        let mut config: Config = if let Some(config_path) = config_path {
            let content =
                fs::read_to_string(&config_path).map_err(|source| ConfigLoadError::Unreadable {
                    path: config_path.clone(),
                    source,
                })?;
            let (cfg, unknown) =
                parse_config(&content).map_err(|source| ConfigLoadError::InvalidToml {
                    path: config_path.clone(),
                    source,
                })?;
            refuse_hf_curation_keys(&config_path, &unknown)?;
            unknown_keys = surface_unknown_keys(&config_path, unknown, strict)?;
            tracing::info!(path = %config_path, "Loaded config from NORA_CONFIG_PATH");
            cfg
        } else {
            match fs::read_to_string(fallback) {
                Ok(content) => match parse_config(&content) {
                    Ok((cfg, unknown)) => {
                        refuse_hf_curation_keys(fallback, &unknown)?;
                        unknown_keys = surface_unknown_keys(fallback, unknown, strict)?;
                        tracing::info!(path = %fallback, "Loaded config");
                        cfg
                    }
                    Err(e) => {
                        tracing::warn!(path = %fallback, error = %e, "config exists but contains invalid TOML, using defaults");
                        Config::default()
                    }
                },
                Err(_) => Config::default(),
            }
        };

        // 3. Override with ENV vars (highest priority)
        config
            .apply_env_overrides()
            .map_err(ConfigLoadError::EnvOverride)?;

        // 4. The per-registry `enabled` flags follow the enable-set (NORA_REGISTRIES_ENABLE,
        //    [registries].enable) before validation, so every rule that reads them or
        //    is_enabled_proxy judges the registries the server mounts (#1098). main applies
        //    the same set again at start; it is idempotent.
        let set = config.enabled_registries_quiet();
        config.apply_enabled_registries(&set);

        // 5. Validate configuration
        Ok((config.checked()?, unknown_keys))
    }

    /// Validate: warnings are logged, errors reject the configuration.
    fn checked(self) -> Result<Self, ConfigLoadError> {
        let (warnings, errors) = self.validate();
        for w in &warnings {
            tracing::warn!("Config validation: {}", w);
        }
        if !errors.is_empty() {
            for e in &errors {
                tracing::error!("Config validation: {}", e);
            }
            return Err(ConfigLoadError::Invalid(errors));
        }
        Ok(self)
    }

    /// The configuration file `NORA_CONFIG_PATH` names; `None` reads `config.toml` of the
    /// working directory when there is one. Start and SIGHUP read the same file.
    pub fn path_from_env() -> Option<String> {
        env::var("NORA_CONFIG_PATH").ok()
    }

    /// Non-panicking config reload for SIGHUP handler, of the file at `path` (see
    /// [`Config::path_from_env`]), passed in so a test reloads a file of its own without
    /// setting process-wide state. Returns Err on invalid file/TOML/validation instead of
    /// panicking.
    pub fn try_load_from(path: Option<String>) -> Result<Self, String> {
        let file = match path {
            Some(path) => {
                let content = fs::read_to_string(&path)
                    .map_err(|e| format!("Cannot read {}: {}", path, e))?;
                Some((path, content))
            }
            None => fs::read_to_string(DEFAULT_CONFIG_FILE)
                .ok()
                .map(|content| (DEFAULT_CONFIG_FILE.to_string(), content)),
        };
        // one path for both sources, so neither can skip the unknown-key check
        let mut config: Config = match file {
            Some((path, content)) => {
                let (config, unknown) = parse_config(&content)
                    .map_err(|e| format!("Invalid TOML in {}: {}", path, e))?;
                // As at start: `[curation.hf]` is refused, not ignored as an unknown key.
                refuse_hf_curation_keys(&path, &unknown)
                    .map_err(|e| format!("Reload refused: {}", e))?;
                surface_unknown_keys(&path, unknown, config_strict_from_env())
                    .map_err(|e| format!("Reload refused: {}", e))?;
                config
            }
            None => Config::default(),
        };
        config.apply_env_overrides()?;
        // As in `load`: validation judges the registries the enable-set mounts (#1098).
        let set = config.enabled_registries_quiet();
        config.apply_enabled_registries(&set);
        let (_, errors) = config.validate();
        if !errors.is_empty() {
            return Err(format!("Validation errors: {}", errors.join("; ")));
        }
        Ok(config)
    }

    /// Apply environment variable overrides.
    ///
    /// Returns `Err` if a security-critical enum (curation mode, quarantine mode,
    /// audit mode, storage mode) has an unrecognized value — typos must not silently
    /// disable security or misconfigure storage.
    fn apply_env_overrides(&mut self) -> Result<(), String> {
        // Server + TLS
        self.server.apply_env_overrides();
        self.tls.apply_env_overrides();

        // Storage (fail-closed: unknown NORA_STORAGE_MODE is fatal)
        self.storage.apply_env_overrides()?;

        // Auth
        self.auth.apply_env_overrides();

        // Registry configs (each handles its own NORA_*_ENABLED + format-specific vars)
        self.docker.apply_env_overrides();
        self.maven.apply_env_overrides();
        self.npm.apply_env_overrides();
        self.pypi.apply_env_overrides();
        self.go.apply_env_overrides();
        self.cargo.apply_env_overrides();
        self.raw.apply_env_overrides();
        self.gems.apply_env_overrides();
        self.terraform.apply_env_overrides();
        self.ansible.apply_env_overrides();
        self.nuget.apply_env_overrides();
        self.pub_dart.apply_env_overrides();
        self.conan.apply_env_overrides();
        self.rpm.apply_env_overrides();
        self.deb.apply_env_overrides();
        self.cpan.apply_env_overrides();
        self.hf.apply_env_overrides();
        self.helm.apply_env_overrides();
        self.apk.apply_env_overrides();
        self.github.apply_env_overrides();
        self.hashicorp.apply_env_overrides();

        // Rate limit, GC, retention
        self.rate_limit.apply_env_overrides();
        self.signing.apply_env_overrides();
        self.gc.apply_env_overrides();
        self.retention.apply_env_overrides();

        // Secrets — SecretsConfig lives in crate::secrets, no apply_env_overrides method
        if let Ok(val) = env::var("NORA_SECRETS_PROVIDER") {
            self.secrets.provider = val;
        }
        if let Ok(val) = env::var("NORA_SECRETS_CLEAR_ENV") {
            self.secrets.clear_env = val.to_lowercase() == "true" || val == "1";
        }

        // Security-critical: parse errors are fatal (fail-fatal security enums)
        self.curation.apply_env_overrides()?;
        self.circuit_breaker.apply_env_overrides();
        self.audit.apply_env_overrides()?;

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
