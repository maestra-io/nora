// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::*;
use crate::digest_quarantine::QuarantineMode;
use crate::secrets::ProtectedString;
use crate::test_env::env_lock;

/// `trust_upstream_dates` on a registry that publishes no date is a warning, not silence.
#[test]
fn trust_upstream_dates_without_a_date_source_warns() {
    let _lock = env_lock();
    let toml =
        |url: &str| format!("[[docker.upstreams]]\nurl = \"{url}\"\ntrust_upstream_dates = true\n");
    let (ghcr, _) = parse_config(&toml("https://docker.dragonflydb.io")).unwrap();
    let (warnings, _) = ghcr.validate();
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("docker.dragonflydb.io publishes no date")),
        "{warnings:?}"
    );
    std::env::set_var("NORA_CONFIG_STRICT", "true");
    let (_, strict) = ghcr.validate();
    std::env::remove_var("NORA_CONFIG_STRICT");
    assert!(
        strict
            .iter()
            .any(|e| e.contains("docker.dragonflydb.io publishes no date")),
        "strict refuses: {strict:?}"
    );
    // cgr.dev dates by its tag history, with no token of ours.
    let (cgr, _) = parse_config(&toml("https://cgr.dev")).unwrap();
    let (warnings, _) = cgr.validate();
    assert!(
        !warnings.iter().any(|w| w.contains("trust_upstream_dates")),
        "{warnings:?}"
    );
    // ghcr.io dates only with a token for the GitHub packages API.
    let (ghcr, _) = parse_config(&toml("https://ghcr.io")).unwrap();
    let (warnings, _) = ghcr.validate();
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("without date_token_file")),
        "{warnings:?}"
    );
    let (ghcr, _) = parse_config(&format!(
        "{}date_token_file = \"/run/gh/token\"\n",
        toml("https://ghcr.io")
    ))
    .unwrap();
    let (warnings, _) = ghcr.validate();
    assert!(
        !warnings.iter().any(|w| w.contains("trust_upstream_dates")),
        "{warnings:?}"
    );
    let (quay, _) = parse_config(&toml("https://quay.io")).unwrap();
    assert!(quay.docker.upstreams[0].trust_upstream_dates);
    let (warnings, _) = quay.validate();
    assert!(
        !warnings.iter().any(|w| w.contains("trust_upstream_dates")),
        "{warnings:?}"
    );
}

/// #1135: whether `curation.mode` was written down is read from the file and from
/// `NORA_CURATION_MODE`; the startup notice follows it while proxy registries are enabled.
#[test]
fn curation_mode_notice_tells_the_default_from_the_operators_off() {
    let _lock = env_lock();
    let (written, _) = parse_config("[curation]\nmode = \"off\"\n").unwrap();
    assert!(written.curation.mode_explicit);
    let (other, _) = parse_config("[curation]\nmin_release_age = \"3d\"\n").unwrap();
    assert!(!other.curation.mode_explicit);
    let (empty, _) = parse_config("").unwrap();
    assert!(!empty.curation.mode_explicit);

    let mut from_env = Config::default();
    std::env::set_var("NORA_CURATION_MODE", "off");
    let applied = from_env.curation.apply_env_overrides();
    std::env::remove_var("NORA_CURATION_MODE");
    applied.unwrap();
    assert!(from_env.curation.mode_explicit);

    // The defaults proxy public registries: off by default is announced as implicit.
    match Config::default().curation_mode_notice() {
        Some(CurationModeNotice::Implicit(proxies)) => {
            assert!(proxies.contains(&RegistryType::Npm), "{proxies:?}");
            assert!(proxies.contains(&RegistryType::Docker), "{proxies:?}");
        }
        other => panic!("default config: {other:?}"),
    }
    let mut off = Config::default();
    off.curation.mode_explicit = true;
    assert!(matches!(
        off.curation_mode_notice(),
        Some(CurationModeNotice::ExplicitOff(_))
    ));
    for mode in [CurationMode::Audit, CurationMode::Enforce] {
        let mut on = Config::default();
        on.curation.mode = mode;
        assert_eq!(on.curation_mode_notice(), None);
    }
    // Nothing proxied: nothing is served unchecked, and nothing is said.
    let mut hosted = Config::default();
    hosted.apply_enabled_registries(&std::collections::HashSet::from([RegistryType::Raw]));
    assert_eq!(hosted.curation_mode_notice(), None, "only raw mounted");
}

/// The empty setting switches the upstream off in both places it can be written, for all six
/// formats: the environment variable and the config file.
#[test]
fn an_empty_setting_reads_as_no_upstream_in_env_and_file() {
    let _lock = env_lock();
    for var in [
        "NORA_GEMS_PROXY",
        "NORA_NUGET_PROXY",
        "NORA_CONAN_PROXY",
        "NORA_TF_PROXY",
        "NORA_ANSIBLE_PROXY",
        "NORA_CPAN_PROXY",
    ] {
        std::env::set_var(var, "");
    }
    let mut cfg = Config::default();
    cfg.apply_env_overrides().unwrap();
    let mut spaced = Config::default();
    for var in [
        "NORA_GEMS_PROXY",
        "NORA_NUGET_PROXY",
        "NORA_CONAN_PROXY",
        "NORA_TF_PROXY",
        "NORA_ANSIBLE_PROXY",
        "NORA_CPAN_PROXY",
    ] {
        std::env::set_var(var, "  ");
    }
    spaced.apply_env_overrides().unwrap();
    for proxy in [
        &spaced.gems.proxy,
        &spaced.nuget.proxy,
        &spaced.conan.proxy,
        &spaced.terraform.proxy,
        &spaced.ansible.proxy,
        &spaced.cpan.proxy,
    ] {
        assert_eq!(proxy, &None, "a value of spaces in the environment");
    }
    for var in [
        "NORA_GEMS_PROXY",
        "NORA_NUGET_PROXY",
        "NORA_CONAN_PROXY",
        "NORA_TF_PROXY",
        "NORA_ANSIBLE_PROXY",
        "NORA_CPAN_PROXY",
    ] {
        std::env::remove_var(var);
    }
    let env = [
        ("gems", cfg.gems.proxy.clone()),
        ("nuget", cfg.nuget.proxy.clone()),
        ("conan", cfg.conan.proxy.clone()),
        ("terraform", cfg.terraform.proxy.clone()),
        ("ansible", cfg.ansible.proxy.clone()),
        ("cpan", cfg.cpan.proxy.clone()),
    ];
    for (format, proxy) in env {
        assert_eq!(proxy, None, "{format}: empty environment variable");
    }

    let file: Config = toml::from_str(
        "[gems]\nproxy = \"\"\n[nuget]\nproxy = \" \"\n[conan]\nproxy = \"\"\n[terraform]\nproxy = \"\"\n[ansible]\nproxy = \"\"\n[cpan]\nproxy = \"\"\n",
    )
    .unwrap();
    for (format, proxy) in [
        ("gems", file.gems.proxy),
        ("nuget", file.nuget.proxy),
        ("conan", file.conan.proxy),
        ("terraform", file.terraform.proxy),
        ("ansible", file.ansible.proxy),
        ("cpan", file.cpan.proxy),
    ] {
        assert_eq!(proxy, None, "{format}: empty value in the config file");
    }
    // Control: a missing key keeps the public default.
    let file: Config = toml::from_str("[gems]\nenabled = true\n").unwrap();
    assert!(file.gems.proxy.is_some());
}

#[test]
fn test_rate_limit_default() {
    let config = RateLimitConfig::default();
    assert_eq!(config.auth_rps, 1);
    assert_eq!(config.auth_burst, 5);
    assert_eq!(config.upload_rps, 200);
    assert_eq!(config.upload_burst, 500);
    assert_eq!(config.general_rps, 100);
    assert_eq!(config.general_burst, 200);
}

// NORA_RATE_LIMIT_*_RPS/_BURST reach the config unchanged, also far
// above 1000/s — a clamp at the source would undo the exact limiter downstream.
#[test]
fn rate_limit_env_overrides_are_kept_as_given() {
    let _lock = env_lock();
    let vars = [
        ("NORA_RATE_LIMIT_AUTH_RPS", "1500"),
        ("NORA_RATE_LIMIT_AUTH_BURST", "7"),
        ("NORA_RATE_LIMIT_UPLOAD_RPS", "5000000"),
        ("NORA_RATE_LIMIT_UPLOAD_BURST", "4000"),
        ("NORA_RATE_LIMIT_GENERAL_RPS", "18446744073709551615"),
        ("NORA_RATE_LIMIT_GENERAL_BURST", "900"),
    ];
    for (k, v) in vars {
        std::env::set_var(k, v);
    }
    let mut config = RateLimitConfig::default();
    config.apply_env_overrides();
    for (k, _) in vars {
        std::env::remove_var(k);
    }
    assert_eq!(config.auth_rps, 1500);
    assert_eq!(config.auth_burst, 7);
    assert_eq!(config.upload_rps, 5_000_000);
    assert_eq!(config.upload_burst, 4000);
    assert_eq!(config.general_rps, u64::MAX);
    assert_eq!(config.general_burst, 900);
}

// The env overrides reach the *loaded* configuration unchanged: through load_from, which
// runs Config::apply_env_overrides and the checks after the rate limit section.
#[test]
fn rate_limit_env_reaches_the_loaded_config_unchanged() {
    let _lock = env_lock();
    let vars = [
        ("NORA_RATE_LIMIT_AUTH_RPS", "1500"),
        ("NORA_RATE_LIMIT_AUTH_BURST", "70000"),
        ("NORA_RATE_LIMIT_UPLOAD_RPS", "5000000"),
        ("NORA_RATE_LIMIT_UPLOAD_BURST", "4000"),
        ("NORA_RATE_LIMIT_GENERAL_RPS", "18446744073709551615"),
        ("NORA_RATE_LIMIT_GENERAL_BURST", "900"),
    ];
    for (k, v) in vars {
        std::env::set_var(k, v);
    }
    let loaded = Config::load_from(None, NO_FALLBACK, false);
    for (k, _) in vars {
        std::env::remove_var(k);
    }
    let rl = loaded.unwrap().0.rate_limit;
    assert_eq!(rl.auth_rps, 1500);
    assert_eq!(rl.auth_burst, 70_000);
    assert_eq!(rl.upload_rps, 5_000_000);
    assert_eq!(rl.upload_burst, 4000);
    assert_eq!(rl.general_rps, u64::MAX);
    assert_eq!(rl.general_burst, 900);
}

#[test]
fn test_rate_limit_from_toml() {
    let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"

            [rate_limit]
            auth_rps = 10
            upload_burst = 1000
        "#;

    let config: Config = toml::from_str(toml).unwrap();
    assert_eq!(config.rate_limit.auth_rps, 10);
    assert_eq!(config.rate_limit.upload_burst, 1000);
    assert_eq!(config.rate_limit.auth_burst, 5); // default
}

#[test]
fn test_basic_auth_header() {
    let header = basic_auth_header("user:pass");
    assert_eq!(header, "Basic dXNlcjpwYXNz");
}

#[test]
fn test_basic_auth_header_empty() {
    let header = basic_auth_header("");
    assert!(header.starts_with("Basic "));
}

/// require_integrity is read only by the allowlist filter: alone it holds nothing, so it
/// stops startup in every mode and is not counted as enforce's active control.
#[test]
fn require_integrity_without_an_allowlist_is_refused() {
    let _lock = env_lock();
    let dir = tempfile::TempDir::new().unwrap();
    let allowlist = dir.path().join("allow.json");
    std::fs::write(&allowlist, r#"{"version":1,"rules":[]}"#).unwrap();
    for mode in [
        CurationMode::Off,
        CurationMode::Audit,
        CurationMode::Enforce,
    ] {
        let mut c = Config::default();
        c.curation.mode = mode.clone();
        c.curation.require_integrity = true;
        let (_, errors) = c.validate();
        assert!(
            errors
                .iter()
                .any(|e| e.starts_with("curation.require_integrity is set")),
            "{mode:?}: {errors:?}"
        );
        if mode == CurationMode::Enforce {
            assert!(
                errors.iter().any(|e| e.contains("no active control")),
                "require_integrity alone is no control: {errors:?}"
            );
        }
        c.curation.allowlist_path = Some(allowlist.to_string_lossy().into_owned());
        let (_, errors) = c.validate();
        assert!(
            !errors.iter().any(|e| e.contains("require_integrity")),
            "{mode:?} with an allowlist: {errors:?}"
        );
    }
}

/// #579: a Hugging Face curation setting of its own holds nothing, so it stops startup
/// instead of being ignored — the env variables in validate, `[curation.hf]` at load.
#[test]
fn a_hugging_face_curation_setting_is_refused_not_ignored() {
    let _lock = env_lock();
    for var in hf_curation_env_vars() {
        std::env::set_var(var, "3d");
        let (_, errors) = Config::default().validate();
        std::env::remove_var(var);
        assert!(
            errors
                .iter()
                .any(|e| e.starts_with(var) && e.contains("cannot apply")),
            "{var}: {errors:?}"
        );
    }
    assert!(
        !Config::default()
            .validate()
            .1
            .iter()
            .any(|e| e.contains("NORA_CURATION_HF_")),
        "nothing set, nothing refused"
    );

    let dir = tempfile::TempDir::new().unwrap();
    for (name, body, refused) in [
        (
            "age.toml",
            "[curation.hf]\nmin_release_age = \"3d\"\n",
            true,
        ),
        (
            "quarantine.toml",
            "[curation.hf]\nquarantine = \"enforce\"\n",
            true,
        ),
        (
            "npm.toml",
            "[curation.npm]\nmin_release_age = \"3d\"\n[curation]\nquarantine = \"observe\"\n",
            false,
        ),
    ] {
        let path = dir.path().join(name);
        std::fs::write(&path, body).unwrap();
        let loaded = Config::load_from(
            Some(path.to_string_lossy().into_owned()),
            NO_FALLBACK,
            false,
        );
        match (&loaded, refused) {
            (Err(ConfigLoadError::Invalid(errors)), true) => assert!(
                errors
                    .iter()
                    .any(|e| e.contains("curation.hf cannot apply")),
                "{name}: {errors:?}"
            ),
            (Ok(_), false) => {}
            _ => panic!(
                "{name}: refused={refused}, got {:?}",
                loaded.as_ref().map(|_| ())
            ),
        }
    }
}

/// #1055: the npm `proxies` checks are part of `validate()`, private hosts feed the
/// upstream-leak detector, and a Bearer token is read from its env var at load.
#[test]
fn npm_proxies_are_validated_leak_checked_and_load_their_token() {
    let _lock = env_lock();
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("nora.toml");
    std::fs::write(
        &path,
        r#"
[npm]
proxies = [
  "https://registry.npmjs.org",
  { url = "https://npm.vendor.example", scopes = ["@vendor"], auth_bearer_env = "NORA_TEST_NPM_VENDOR_TOKEN" },
]
"#,
    )
    .unwrap();
    let path = path.to_string_lossy().into_owned();

    std::env::set_var("NORA_TEST_NPM_VENDOR_TOKEN", "tok-from-env");
    let loaded = Config::load_from(Some(path.clone()), NO_FALLBACK, false).map(|(c, _)| c);
    std::env::remove_var("NORA_TEST_NPM_VENDOR_TOKEN");
    let config = loaded.expect("a set token loads");
    let up = config.npm.route("@vendor/a").unwrap();
    assert_eq!(
        up.auth.unwrap().header_value().unwrap(),
        "Bearer tok-from-env"
    );
    assert!(config
        .upstream_hostnames()
        .contains(&("npm".to_string(), "npm.vendor.example".to_string())));

    // Unset token: the config is rejected at load, not served with silent 401s.
    assert!(Config::load_from(Some(path), NO_FALLBACK, false).is_err());

    let mut bad = Config::default();
    bad.npm.proxies = vec![
        NpmProxyEntry::Simple("https://registry.npmjs.org".into()),
        NpmProxyEntry::Simple("https://mirror.example".into()),
    ];
    let (_, errors) = bad.validate_with_config_path(None);
    assert!(
        errors.iter().any(|e| e.contains("have no scopes")),
        "{errors:?}"
    );
}

#[test]
fn upstream_auth_header_carries_its_scheme_and_is_sensitive() {
    let basic = UpstreamAuth::Basic("user:pass").header_value().unwrap();
    assert_eq!(basic, "Basic dXNlcjpwYXNz");
    assert!(basic.is_sensitive());
    assert_eq!(format!("{basic:?}"), "Sensitive");

    let bearer = UpstreamAuth::Bearer("npm_tok-1").header_value().unwrap();
    assert_eq!(bearer, "Bearer npm_tok-1");
    assert!(bearer.is_sensitive());
    assert_eq!(format!("{bearer:?}"), "Sensitive");
}

#[test]
fn upstream_auth_bearer_with_newline_is_rejected_not_sent() {
    assert!(UpstreamAuth::Bearer("tok\n").header_value().is_err());
    assert!(UpstreamAuth::Bearer("tok\r\nX-Injected: 1")
        .header_value()
        .is_err());
}

#[test]
fn test_config_default() {
    let config = Config::default();
    assert_eq!(config.server.host, "127.0.0.1");
    assert_eq!(config.server.port, 4000);
    assert_eq!(config.server.body_limit_mb, 2048);
    assert!(config.server.public_url.is_none());
    assert_eq!(config.storage.path, "data/storage");
    assert_eq!(config.storage.mode, StorageMode::Local);
    assert_eq!(config.storage.bucket, "registry");
    assert_eq!(config.storage.s3_region, "us-east-1");
    assert!(!config.auth.enabled);
    assert_eq!(config.auth.htpasswd_file, "users.htpasswd");
    assert_eq!(config.auth.token_storage, "data/tokens");
    assert!(!config.cpan.enabled, "CPAN defaults to disabled");
    assert!(!config.hf.enabled, "Hugging Face defaults to disabled");
}

#[test]
fn test_maven_config_default() {
    let m = MavenConfig::default();
    assert_eq!(m.proxy_timeout, 30);
    assert_eq!(m.date_lookup_timeout, 5);
    let parsed: MavenConfig = toml::from_str("").unwrap();
    assert_eq!(
        parsed.date_lookup_timeout, 5,
        "serde default matches Default"
    );
    assert_eq!(m.proxies.len(), 1);
    assert_eq!(m.proxies[0].url(), "https://repo1.maven.org/maven2");
    assert!(m.proxies[0].auth().is_none());
}

#[test]
fn test_npm_config_default() {
    let n = NpmConfig::default();
    assert_eq!(n.proxy, Some("https://registry.npmjs.org".to_string()));
    assert!(n.proxy_auth.is_none());
    assert_eq!(n.proxy_timeout, 30);
    assert_eq!(n.metadata_ttl, 300);
}

#[test]
fn test_pypi_config_default() {
    let p = PypiConfig::default();
    assert_eq!(p.proxy, Some("https://pypi.org/simple/".to_string()));
    assert!(p.proxy_auth.is_none());
    assert_eq!(p.proxy_timeout, 30);
}

#[test]
fn test_docker_config_default() {
    let d = DockerConfig::default();
    assert_eq!(d.proxy_timeout, 300);
    assert_eq!(d.upstreams.len(), 1);
    assert_eq!(d.upstreams[0].url, "https://registry-1.docker.io");
    assert!(d.upstreams[0].auth.is_none());
}

#[test]
fn test_raw_config_default() {
    let r = RawConfig::default();
    assert!(r.enabled);
    assert_eq!(r.max_file_size, 104_857_600);
}

#[test]
fn test_auth_config_default() {
    let a = AuthConfig::default();
    assert!(!a.enabled);
    assert!(!a.anonymous_read);
    assert_eq!(a.htpasswd_file, "users.htpasswd");
    assert_eq!(a.token_storage, "data/tokens");
}

#[test]
fn test_auth_anonymous_read_from_toml() {
    let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"

            [auth]
            enabled = true
            anonymous_read = true
        "#;

    let config: Config = toml::from_str(toml).unwrap();
    assert!(config.auth.enabled);
    assert!(config.auth.anonymous_read);
}

#[test]
fn test_env_override_anonymous_read() {
    let _lock = env_lock();
    let mut config = Config::default();
    std::env::set_var("NORA_AUTH_ANONYMOUS_READ", "true");
    config.apply_env_overrides().unwrap();
    assert!(config.auth.anonymous_read);
    std::env::remove_var("NORA_AUTH_ANONYMOUS_READ");
}

#[test]
fn test_audit_rotation_defaults_toml_and_env() {
    let _lock = env_lock();
    let config: Config = toml::from_str("[storage]\nmode = \"local\"").unwrap();
    assert_eq!(config.audit.max_size_mb, 100);
    assert_eq!(config.audit.max_files, 5);

    let mut config: Config =
        toml::from_str("[audit]\nmode = \"both\"\nmax_size_mb = 0\nmax_files = 2").unwrap();
    assert_eq!(config.audit.max_size_mb, 0);
    assert_eq!(config.audit.max_files, 2);

    std::env::set_var("NORA_AUDIT_MAX_SIZE_MB", "7");
    std::env::set_var("NORA_AUDIT_MAX_FILES", "3");
    let applied = config.apply_env_overrides();
    std::env::set_var("NORA_AUDIT_MAX_SIZE_MB", "7MB");
    let typo = config.clone().apply_env_overrides();
    std::env::remove_var("NORA_AUDIT_MAX_SIZE_MB");
    std::env::remove_var("NORA_AUDIT_MAX_FILES");
    applied.unwrap();
    assert_eq!(config.audit.max_size_mb, 7);
    assert_eq!(config.audit.max_files, 3);
    assert!(typo.unwrap_err().contains("NORA_AUDIT_MAX_SIZE_MB"));
}

#[test]
fn test_docker_anon_pull_defaults_false() {
    // Fail-closed: absent from config => off, and independent of anonymous_read.
    let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"

            [auth]
            enabled = true
            anonymous_read = true
        "#;
    let config: Config = toml::from_str(toml).unwrap();
    assert!(config.auth.anonymous_read);
    assert!(
        !config.auth.docker_anon_pull,
        "docker_anon_pull must NOT be implied by anonymous_read"
    );
}

#[test]
fn test_docker_anon_pull_from_toml() {
    let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"

            [auth]
            enabled = true
            docker_anon_pull = true
        "#;
    let config: Config = toml::from_str(toml).unwrap();
    assert!(config.auth.docker_anon_pull);
    assert!(!config.auth.anonymous_read);
}

#[test]
fn test_env_override_docker_anon_pull() {
    let _lock = env_lock();
    let mut config = Config::default();
    std::env::set_var("NORA_AUTH_DOCKER_ANON_PULL", "true");
    config.apply_env_overrides().unwrap();
    assert!(config.auth.docker_anon_pull);
    std::env::remove_var("NORA_AUTH_DOCKER_ANON_PULL");
}

#[test]
fn test_maven_proxy_entry_simple() {
    let entry = MavenProxyEntry::Simple("https://repo.example.com".to_string());
    assert_eq!(entry.url(), "https://repo.example.com");
    assert!(entry.auth().is_none());
}

#[test]
fn test_maven_proxy_entry_full() {
    let entry = MavenProxyEntry::Full(MavenProxy {
        url: "https://private.repo.com".to_string(),
        auth: Some(ProtectedString::from("user:secret")),
    });
    assert_eq!(entry.url(), "https://private.repo.com");
    assert_eq!(entry.auth(), Some("user:secret"));
}

#[test]
fn test_maven_proxy_entry_full_no_auth() {
    let entry = MavenProxyEntry::Full(MavenProxy {
        url: "https://repo.com".to_string(),
        auth: None,
    });
    assert_eq!(entry.url(), "https://repo.com");
    assert!(entry.auth().is_none());
}

#[test]
fn test_storage_mode_default() {
    let mode = StorageMode::default();
    assert_eq!(mode, StorageMode::Local);
}

#[test]
fn test_env_override_server() {
    let _lock = env_lock();
    let mut config = Config::default();
    std::env::set_var("NORA_HOST", "0.0.0.0");
    std::env::set_var("NORA_PORT", "8080");
    std::env::set_var("NORA_PUBLIC_URL", "registry.example.com");
    std::env::set_var("NORA_BODY_LIMIT_MB", "4096");
    config.apply_env_overrides().unwrap();
    assert_eq!(config.server.host, "0.0.0.0");
    assert_eq!(config.server.port, 8080);
    assert_eq!(
        config.server.public_url,
        Some("registry.example.com".to_string())
    );
    assert_eq!(config.server.body_limit_mb, 4096);
    std::env::remove_var("NORA_HOST");
    std::env::remove_var("NORA_PORT");
    std::env::remove_var("NORA_PUBLIC_URL");
    std::env::remove_var("NORA_BODY_LIMIT_MB");
}

#[test]
fn test_env_override_storage() {
    let _lock = env_lock();
    let mut config = Config::default();
    std::env::set_var("NORA_STORAGE_MODE", "s3");
    std::env::set_var("NORA_STORAGE_PATH", "/data/nora");
    std::env::set_var("NORA_STORAGE_BUCKET", "my-bucket");
    std::env::set_var("NORA_STORAGE_S3_REGION", "eu-west-1");
    std::env::set_var("NORA_STORAGE_S3_VIRTUAL_HOSTED", "true");
    config.apply_env_overrides().unwrap();
    assert_eq!(config.storage.mode, StorageMode::S3);
    assert_eq!(config.storage.path, "/data/nora");
    assert_eq!(config.storage.bucket, "my-bucket");
    assert_eq!(config.storage.s3_region, "eu-west-1");
    assert!(config.storage.s3_virtual_hosted);
    std::env::remove_var("NORA_STORAGE_MODE");
    std::env::remove_var("NORA_STORAGE_PATH");
    std::env::remove_var("NORA_STORAGE_BUCKET");
    std::env::remove_var("NORA_STORAGE_S3_REGION");
    std::env::remove_var("NORA_STORAGE_S3_VIRTUAL_HOSTED");
}

#[test]
fn test_env_override_storage_virtual_hosted_default_off() {
    let _lock = env_lock();
    let mut config = Config::default();
    config.apply_env_overrides().unwrap();
    assert!(!config.storage.s3_virtual_hosted);
    std::env::set_var("NORA_STORAGE_S3_VIRTUAL_HOSTED", "false");
    config.apply_env_overrides().unwrap();
    assert!(!config.storage.s3_virtual_hosted);
    std::env::set_var("NORA_STORAGE_S3_VIRTUAL_HOSTED", "1");
    config.apply_env_overrides().unwrap();
    assert!(config.storage.s3_virtual_hosted);
    std::env::remove_var("NORA_STORAGE_S3_VIRTUAL_HOSTED");
}

/// R4-T10: a `raw.cache_control` that cannot be a header value is a warning (an error
/// under NORA_CONFIG_STRICT), and the default is what a request sends.
#[test]
fn test_raw_cache_control_must_be_a_header_value() {
    let _lock = env_lock();
    std::env::remove_var("NORA_CONFIG_STRICT");
    let mut config = Config::default();
    assert_eq!(config.raw.cache_control(), "no-cache");
    config.raw.cache_control = "public, max-age=60".into();
    assert_eq!(config.raw.cache_control(), "public, max-age=60");
    let hit = |list: &[String]| list.iter().any(|m| m.contains("raw.cache_control"));
    let (warnings, errors) = config.validate_with_config_path(None);
    assert!(!hit(&warnings) && !hit(&errors));

    config.raw.cache_control = "public,\nmax-age=60\n".into();
    assert_eq!(config.raw.cache_control(), "no-cache");
    let (warnings, errors) = config.validate_with_config_path(None);
    assert!(hit(&warnings) && !hit(&errors), "{warnings:?} {errors:?}");

    std::env::set_var("NORA_CONFIG_STRICT", "1");
    let (warnings, errors) = config.validate_with_config_path(None);
    std::env::remove_var("NORA_CONFIG_STRICT");
    assert!(!hit(&warnings) && hit(&errors), "{warnings:?} {errors:?}");
}

/// C71: s3 mode without usable credentials is a warning (an error under
/// NORA_CONFIG_STRICT) unless `s3_anonymous` says unsigned requests are intended.
#[test]
fn test_s3_without_credentials_warns_unless_anonymous() {
    let _lock = env_lock();
    std::env::remove_var("NORA_CONFIG_STRICT");
    let s3 = |customize: &dyn Fn(&mut StorageConfig)| {
        let mut config = Config::default();
        config.storage.mode = StorageMode::S3;
        customize(&mut config.storage);
        config.validate_with_config_path(None)
    };
    let unsigned = |(warnings, errors): (Vec<String>, Vec<String>)| {
        let hit = |list: &[String]| list.iter().any(|m| m.contains("requests go unsigned"));
        (hit(&warnings), hit(&errors))
    };

    assert_eq!(unsigned(s3(&|_| {})), (true, false));
    assert_eq!(
        unsigned(s3(&|c| c.s3_access_key = Some(ProtectedString::from("ak")))),
        (true, false),
        "one key without the other is the typo case"
    );
    assert_eq!(
        unsigned(s3(&|c| {
            c.s3_access_key = Some(ProtectedString::from("ak"));
            c.s3_secret_key = Some(ProtectedString::from("sk"));
        })),
        (false, false)
    );
    assert_eq!(
        unsigned(s3(&|c| c.s3_credentials_dir = Some("/creds".into()))),
        (false, false)
    );
    assert_eq!(unsigned(s3(&|c| c.s3_anonymous = true)), (false, false));

    std::env::set_var("NORA_CONFIG_STRICT", "true");
    let strict = unsigned(s3(&|_| {}));
    let strict_anonymous = unsigned(s3(&|c| c.s3_anonymous = true));
    std::env::remove_var("NORA_CONFIG_STRICT");
    assert_eq!(strict, (false, true), "strict mode refuses");
    assert_eq!(strict_anonymous, (false, false));

    let mut config = Config::default();
    std::env::set_var("NORA_STORAGE_S3_ANONYMOUS", "true");
    let r = config.apply_env_overrides();
    std::env::remove_var("NORA_STORAGE_S3_ANONYMOUS");
    r.unwrap();
    assert!(config.storage.s3_anonymous);
}

#[test]
fn test_env_override_storage_mode_local() {
    let _lock = env_lock();
    let mut config = Config::default();
    std::env::set_var("NORA_STORAGE_MODE", "local");
    config.apply_env_overrides().unwrap();
    assert_eq!(config.storage.mode, StorageMode::Local);
    std::env::remove_var("NORA_STORAGE_MODE");
}

#[test]
fn test_env_override_storage_mode_case_insensitive() {
    let _lock = env_lock();
    let mut config = Config::default();
    std::env::set_var("NORA_STORAGE_MODE", "S3");
    config.apply_env_overrides().unwrap();
    assert_eq!(config.storage.mode, StorageMode::S3);
    std::env::remove_var("NORA_STORAGE_MODE");
}

#[test]
fn test_env_override_storage_mode_rejects_unknown() {
    let _lock = env_lock();
    let mut config = Config::default();
    std::env::set_var("NORA_STORAGE_MODE", "redis");
    let result = config.apply_env_overrides();
    assert!(result.is_err(), "unknown storage mode must be rejected");
    assert!(result.unwrap_err().contains("NORA_STORAGE_MODE"));
    std::env::remove_var("NORA_STORAGE_MODE");
}

#[test]
fn test_parse_env_warn_valid_u16() {
    let mut port: u16 = 5000;
    parse_env_warn("NORA_PORT", "8080", &mut port);
    assert_eq!(port, 8080);
}

#[test]
fn test_parse_env_warn_invalid_keeps_original() {
    let mut port: u16 = 5000;
    parse_env_warn("NORA_PORT", "not-a-number", &mut port);
    assert_eq!(port, 5000, "invalid parse must keep original value");
}

#[test]
fn test_parse_env_warn_empty_keeps_original() {
    let mut timeout: u64 = 30;
    parse_env_warn("NORA_TIMEOUT", "", &mut timeout);
    assert_eq!(timeout, 30, "empty string must keep original value");
}

#[test]
fn test_env_override_auth() {
    let _lock = env_lock();
    let mut config = Config::default();
    std::env::set_var("NORA_AUTH_ENABLED", "true");
    std::env::set_var("NORA_AUTH_HTPASSWD_FILE", "/etc/nora/users");
    std::env::set_var("NORA_AUTH_TOKEN_STORAGE", "/data/tokens");
    config.apply_env_overrides().unwrap();
    assert!(config.auth.enabled);
    assert_eq!(config.auth.htpasswd_file, "/etc/nora/users");
    assert_eq!(config.auth.token_storage, "/data/tokens");
    std::env::remove_var("NORA_AUTH_ENABLED");
    std::env::remove_var("NORA_AUTH_HTPASSWD_FILE");
    std::env::remove_var("NORA_AUTH_TOKEN_STORAGE");
}

#[test]
fn test_env_override_trusted_proxies_cidr_list() {
    let _lock = env_lock();
    let mut config = Config::default();
    std::env::set_var("NORA_AUTH_TRUSTED_PROXIES", "10.60.8.0/24, 10.62.0.0/16");
    config.apply_env_overrides().unwrap();
    std::env::remove_var("NORA_AUTH_TRUSTED_PROXIES");
    let proxies = &config.auth.trusted_proxies;
    assert!(proxies.contains("10.60.8.3".parse().unwrap()));
    assert!(proxies.contains("10.62.2.17".parse().unwrap()));
    assert!(!proxies.contains("10.60.9.1".parse().unwrap()));
    assert!(!proxies.contains("127.0.0.1".parse().unwrap()));
}

#[test]
fn test_env_override_maven_proxies() {
    let _lock = env_lock();
    let mut config = Config::default();
    std::env::set_var(
        "NORA_MAVEN_PROXIES",
        "https://repo1.com,https://repo2.com|user:pass",
    );
    config.apply_env_overrides().unwrap();
    assert_eq!(config.maven.proxies.len(), 2);
    assert_eq!(config.maven.proxies[0].url(), "https://repo1.com");
    assert!(config.maven.proxies[0].auth().is_none());
    assert_eq!(config.maven.proxies[1].url(), "https://repo2.com");
    assert_eq!(config.maven.proxies[1].auth(), Some("user:pass"));
    std::env::remove_var("NORA_MAVEN_PROXIES");
}

#[test]
fn test_env_override_maven_checksum_and_immutable() {
    let _lock = env_lock();
    let mut config = Config::default();
    assert!(config.maven.checksum_verify); // default true
    assert!(config.maven.immutable_releases); // default true
    std::env::set_var("NORA_MAVEN_CHECKSUM_VERIFY", "false");
    std::env::set_var("NORA_MAVEN_IMMUTABLE_RELEASES", "false");
    config.apply_env_overrides().unwrap();
    assert!(!config.maven.checksum_verify);
    assert!(!config.maven.immutable_releases);
    std::env::remove_var("NORA_MAVEN_CHECKSUM_VERIFY");
    std::env::remove_var("NORA_MAVEN_IMMUTABLE_RELEASES");
}

#[test]
fn test_s3_default_url() {
    let config = Config::default();
    assert_eq!(config.storage.s3_url, "http://127.0.0.1:9000");
}

#[test]
fn test_env_override_npm() {
    let _lock = env_lock();
    let mut config = Config::default();
    std::env::set_var("NORA_NPM_PROXY", "https://npm.company.com");
    std::env::set_var("NORA_NPM_PROXY_AUTH", "user:token");
    std::env::set_var("NORA_NPM_PROXY_TIMEOUT", "60");
    std::env::set_var("NORA_NPM_METADATA_TTL", "600");
    config.apply_env_overrides().unwrap();
    assert_eq!(
        config.npm.proxy,
        Some("https://npm.company.com".to_string())
    );
    assert_eq!(
        crate::secrets::expose_opt(&config.npm.proxy_auth),
        Some("user:token")
    );
    assert_eq!(config.npm.proxy_timeout, 60);
    assert_eq!(config.npm.metadata_ttl, 600);
    std::env::remove_var("NORA_NPM_PROXY");
    std::env::remove_var("NORA_NPM_PROXY_AUTH");
    std::env::remove_var("NORA_NPM_PROXY_TIMEOUT");
    std::env::remove_var("NORA_NPM_METADATA_TTL");
}

#[test]
fn test_env_override_raw() {
    let _lock = env_lock();
    let mut config = Config::default();
    std::env::set_var("NORA_RAW_ENABLED", "false");
    std::env::set_var("NORA_RAW_MAX_FILE_SIZE", "524288000");
    std::env::set_var("NORA_RAW_CACHE_CONTROL", "no-cache");
    config.apply_env_overrides().unwrap();
    assert!(!config.raw.enabled);
    assert_eq!(config.raw.max_file_size, 524288000);
    assert_eq!(config.raw.cache_control, "no-cache");
    std::env::remove_var("NORA_RAW_ENABLED");
    std::env::remove_var("NORA_RAW_MAX_FILE_SIZE");
    std::env::remove_var("NORA_RAW_CACHE_CONTROL");
}

#[test]
fn test_env_override_rate_limit() {
    let _lock = env_lock();
    let mut config = Config::default();
    std::env::set_var("NORA_RATE_LIMIT_ENABLED", "false");
    std::env::set_var("NORA_RATE_LIMIT_AUTH_RPS", "10");
    std::env::set_var("NORA_RATE_LIMIT_GENERAL_BURST", "500");
    config.apply_env_overrides().unwrap();
    assert!(!config.rate_limit.enabled);
    assert_eq!(config.rate_limit.auth_rps, 10);
    assert_eq!(config.rate_limit.general_burst, 500);
    std::env::remove_var("NORA_RATE_LIMIT_ENABLED");
    std::env::remove_var("NORA_RATE_LIMIT_AUTH_RPS");
    std::env::remove_var("NORA_RATE_LIMIT_GENERAL_BURST");
}

#[test]
fn test_config_from_toml_full() {
    let toml = r#"
            [server]
            host = "0.0.0.0"
            port = 8080
            public_url = "nora.example.com"
            body_limit_mb = 4096

            [storage]
            mode = "s3"
            path = "/data"
            s3_url = "http://s3.example.com:9000"
            bucket = "artifacts"
            s3_region = "eu-central-1"

            [auth]
            enabled = true
            htpasswd_file = "/etc/nora/users.htpasswd"

            [raw]
            enabled = false
            max_file_size = 500000000
        "#;

    let config: Config = toml::from_str(toml).unwrap();
    assert_eq!(config.server.host, "0.0.0.0");
    assert_eq!(config.server.port, 8080);
    assert_eq!(
        config.server.public_url,
        Some("nora.example.com".to_string())
    );
    assert_eq!(config.server.body_limit_mb, 4096);
    assert_eq!(config.storage.mode, StorageMode::S3);
    assert_eq!(config.storage.s3_url, "http://s3.example.com:9000");
    assert_eq!(config.storage.bucket, "artifacts");
    assert!(config.auth.enabled);
    assert!(!config.raw.enabled);
    assert_eq!(config.raw.max_file_size, 500000000);
}

#[test]
fn test_config_from_toml_minimal() {
    let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"
        "#;

    let config: Config = toml::from_str(toml).unwrap();
    // Defaults should be filled
    assert_eq!(config.storage.path, "data/storage");
    assert_eq!(config.maven.proxies.len(), 1);
    assert_eq!(
        config.npm.proxy,
        Some("https://registry.npmjs.org".to_string())
    );
    assert_eq!(config.docker.upstreams.len(), 1);
    assert!(config.raw.enabled);
    assert!(!config.auth.enabled);
}

#[test]
fn test_config_from_toml_partial() {
    // Missing host and port in [server] — should use defaults
    let toml = r#"
            [server]
            [storage]
            mode = "local"
        "#;
    let config: Config = toml::from_str(toml).unwrap();
    assert_eq!(config.server.host, "127.0.0.1");
    assert_eq!(config.server.port, 4000);
    assert_eq!(config.storage.path, "data/storage");

    // Missing [server] entirely — should use defaults
    let toml = r#"
            [storage]
            mode = "local"
        "#;
    let config: Config = toml::from_str(toml).unwrap();
    assert_eq!(config.server.host, "127.0.0.1");
    assert_eq!(config.server.port, 4000);

    // Missing [storage] entirely — should use defaults
    let toml = r#"
            [server]
            host = "0.0.0.0"
            port = 8080
        "#;
    let config: Config = toml::from_str(toml).unwrap();
    assert_eq!(config.server.host, "0.0.0.0");
    assert_eq!(config.server.port, 8080);
    assert_eq!(config.storage.mode, StorageMode::Local);
}

/// Assert that a config section's field-level serde-default path equals its
/// `Default` impl — i.e. writing `[section]` with no keys behaves the same as
/// omitting the section entirely. A bare `#[serde(default)]` on an `Option`
/// field yields `None`, which silently diverges from a `Default` impl that
/// returns `Some(..)` (the npm/pypi proxy bug). Comparison via
/// `serde_json::Value` tolerates `ProtectedString` secrets (`skip_serializing`
/// → absent on both sides) and auto-covers future fields.
fn assert_serde_default_eq_default<T>(section: &str)
where
    T: serde::Serialize + serde::de::DeserializeOwned + Default,
{
    let from_empty: T = toml::from_str("").unwrap_or_else(|e| {
        panic!("[{section}] empty table must deserialize — every field needs a serde default: {e}")
    });
    assert_eq!(
        serde_json::to_value(&from_empty).unwrap(),
        serde_json::to_value(T::default()).unwrap(),
        "[{section}]: serde field-defaults diverge from the Default impl — a present-but-empty \
             [{section}] table behaves differently from omitting the section",
    );
}

/// Invariant (whole class, not just the leaves that were caught): for EVERY
/// config section, the field-level `#[serde(default)]` path and the `Default`
/// impl must agree, so `[section]` with no keys == omitting `[section]`. The
/// only way to drift is a `serde(default = ...)`/`Default` mismatch — this
/// fails loudly if it ever happens. Previously this only covered
/// server/storage, which let the npm/pypi `proxy` divergence through.
#[test]
fn test_serde_defaults_match_default_impl() {
    assert_serde_default_eq_default::<ServerConfig>("server");
    assert_serde_default_eq_default::<StorageConfig>("storage");
    // All 13 registries — this is where the proxy-default class lives.
    assert_serde_default_eq_default::<MavenConfig>("maven");
    assert_serde_default_eq_default::<NpmConfig>("npm");
    assert_serde_default_eq_default::<PypiConfig>("pypi");
    assert_serde_default_eq_default::<DockerConfig>("docker");
    assert_serde_default_eq_default::<GoConfig>("go");
    assert_serde_default_eq_default::<CargoConfig>("cargo");
    assert_serde_default_eq_default::<RawConfig>("raw");
    assert_serde_default_eq_default::<GemsConfig>("gems");
    assert_serde_default_eq_default::<TerraformConfig>("terraform");
    assert_serde_default_eq_default::<AnsibleConfig>("ansible");
    assert_serde_default_eq_default::<NugetConfig>("nuget");
    assert_serde_default_eq_default::<PubDartConfig>("pub_dart");
    assert_serde_default_eq_default::<ConanConfig>("conan");
    assert_serde_default_eq_default::<RpmConfig>("rpm");
    assert_serde_default_eq_default::<DebConfig>("deb");
    assert_serde_default_eq_default::<CpanConfig>("cpan");
    assert_serde_default_eq_default::<HfConfig>("hf");
    assert_serde_default_eq_default::<SigningConfig>("signing");

    // Whole-Config fallback agrees with deserializing an empty file.
    let from_empty_cfg: Config = toml::from_str("").unwrap();
    assert_eq!(from_empty_cfg.server, ServerConfig::default());
}

/// The config shipped in the container image (deploy/config.docker.toml,
/// loaded via NORA_CONFIG_PATH) must be valid for THIS struct and yield the
/// intended container defaults — so the image is zero-config out of the box
/// without baking config values as env (#719). A renamed/typo'd key would
/// otherwise fall back to a default silently, reintroducing the bug. Host is
/// deliberately absent (the container sets it via NORA_HOST).
#[test]
fn test_shipped_docker_config_is_valid() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../deploy/config.docker.toml");
    let content =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    let config: Config = toml::from_str(&content).unwrap();
    assert_eq!(config.server.port, 4000);
    assert_eq!(
        config.server.public_url.as_deref(),
        Some("http://localhost:4000")
    );
    assert_eq!(config.storage.mode, StorageMode::Local);
    assert_eq!(config.storage.path, "/data/storage");
    assert_eq!(config.auth.token_storage, "/data/tokens");
}

#[test]
fn test_config_toml_docker_upstreams() {
    let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"

            [docker]
            proxy_timeout = 120

            [[docker.upstreams]]
            url = "https://mirror.gcr.io"

            [[docker.upstreams]]
            url = "https://private.registry.io"
            auth = "user:pass"
        "#;

    let config: Config = toml::from_str(toml).unwrap();
    assert_eq!(config.docker.proxy_timeout, 120);
    assert_eq!(config.docker.upstreams.len(), 2);
    assert!(config.docker.upstreams[0].auth.is_none());
    assert_eq!(
        crate::secrets::expose_opt(&config.docker.upstreams[1].auth),
        Some("user:pass")
    );
}

/// `KEY=VALUE` lines of an env file (comments and blanks skipped).
fn env_file(text: &str) -> Vec<(String, String)> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// A default config with the server settings an env file sets (#1025).
fn with_env_file(text: &str) -> Config {
    let mut config = Config::default();
    for (key, value) in env_file(text) {
        match key.as_str() {
            "NORA_HOST" => config.server.host = value,
            "NORA_PORT" => config.server.port = value.parse().unwrap(),
            "NORA_PUBLIC_URL" => config.server.public_url = Some(value),
            _ => {}
        }
    }
    config
}

/// The defaults we ship must start: a fresh package install or `install.sh` run
/// used to crash-loop on its own nora.env (#1025).
#[test]
fn shipped_env_defaults_pass_validation() {
    let _lock = env_lock();
    let deb = include_str!("../../../dist/nora.env.example");
    let script = include_str!("../../../dist/install.sh");
    let heredoc = script
        .split("cat > /tmp/nora.env << 'ENVEOF'")
        .nth(1)
        .and_then(|rest| rest.split("\nENVEOF").next())
        .expect("install.sh writes a default nora.env");
    for (name, text) in [("dist/nora.env.example", deb), ("dist/install.sh", heredoc)] {
        let (_, errors) = with_env_file(text).validate();
        assert!(
            errors.is_empty(),
            "{name} defaults fail validation: {errors:?}"
        );
    }
}

/// Both unit files stop instead of restarting on a configuration error.
#[test]
fn units_do_not_restart_on_a_config_error() {
    let unit = include_str!("../../../dist/nora.service");
    let script = include_str!("../../../dist/install.sh");
    let wanted = format!("RestartPreventExitStatus={EXIT_CONFIG}");
    assert!(unit.contains(&wanted), "dist/nora.service lacks {wanted}");
    assert!(script.contains(&wanted), "install.sh's unit lacks {wanted}");
}

/// #1190: every unit NORA ships answers `systemctl reload` with the SIGHUP that re-reads the
/// configuration, as the deployment guide says; without `ExecReload` systemd refuses the job.
#[test]
fn units_reload_with_sighup() {
    let wanted = "ExecReload=/bin/kill -HUP $MAINPID";
    for (name, unit) in [
        (
            "dist/nora.service",
            include_str!("../../../dist/nora.service"),
        ),
        (
            "deploy/nora.service",
            include_str!("../../../deploy/nora.service"),
        ),
        ("dist/install.sh", include_str!("../../../dist/install.sh")),
    ] {
        assert!(
            unit.lines().any(|line| line.trim() == wanted),
            "{name} lacks {wanted}"
        );
    }
}

/// Every fatal case of loading comes back as its own typed error, never a panic:
/// an unreadable config file, invalid TOML, and a configuration validation rejects.
#[test]
fn load_reports_each_fatal_case_as_a_typed_error() {
    // load() applies NORA_* overrides; other tests set invalid ones under this lock.
    let _lock = env_lock();
    let dir = tempfile::TempDir::new().unwrap();
    let path = |name: &str| dir.path().join(name).to_string_lossy().into_owned();

    let missing =
        Config::load_from(Some(path("absent.toml")), NO_FALLBACK, false).expect_err("missing file");
    assert!(
        matches!(missing, ConfigLoadError::Unreadable { .. }),
        "{missing}"
    );

    std::fs::write(path("broken.toml"), "[server\nport = ").unwrap();
    let broken =
        Config::load_from(Some(path("broken.toml")), NO_FALLBACK, false).expect_err("invalid TOML");
    assert!(
        matches!(broken, ConfigLoadError::InvalidToml { .. }),
        "{broken}"
    );

    // An error no test's temporary NORA_* variables can mask.
    std::fs::write(path("empty-path.toml"), "[storage]\npath = \"\"\n").unwrap();
    let invalid = Config::load_from(Some(path("empty-path.toml")), NO_FALLBACK, false)
        .expect_err("validation");
    assert!(matches!(invalid, ConfigLoadError::Invalid(_)), "{invalid}");
    assert!(invalid.to_string().contains("storage.path"), "{invalid}");
}

/// A typo in a Docker upstream refuses the file instead of being listed and ignored (#1188):
/// a misspelt `namespaces` leaves a private registry in the fallback chain, where a public
/// upstream answers its names.
#[test]
fn a_typo_in_a_docker_upstream_refuses_the_file() {
    for key in ["namespace_s = [\"team-*\"]", "auht = \"user:pass\""] {
        let content = format!("[[docker.upstreams]]\nurl = \"https://harbor.example\"\n{key}\n");
        let err = parse_config(&content).expect_err(&content).to_string();
        let field = key.split(' ').next().unwrap();
        assert!(err.contains(field), "{err}");
    }
}

/// Paths of the unknown keys of `content`, sorted; panics if it does not parse.
fn unknown_keys(content: &str) -> Vec<String> {
    let (_, mut keys) = parse_config(content).unwrap_or_else(|e| panic!("{e}\n{content}"));
    keys.sort();
    keys
}

/// A typo is reported with the full path to it, at every depth: top level, a section,
/// an array of tables, a whole unknown section (reported once, not key by key).
#[test]
fn unknown_keys_are_listed_with_their_full_path() {
    let content = r#"
            typo_top = 1

            [curation]
            mdoe = "enforce"

            [[auth.oidc.providers]]
            name = "gh"
            issuer = "https://gh.example"
            aduience = "nora"

            [unknwon_section]
            a = 1
            b = 2
        "#;
    assert_eq!(
        unknown_keys(content),
        [
            "auth.oidc.providers.0.aduience",
            "curation.mdoe",
            "typo_top",
            "unknwon_section"
        ]
    );
    // the hazard the list exists for: the typo leaves curation at its default
    let (config, _) = parse_config(content).unwrap();
    assert_eq!(config.curation.mode, CurationMode::default());
}

/// A typo in any table of the config is listed — derived from the serialized default
/// config, so a new section or nested table is covered without editing this test.
/// Tables whose keys are names (maps) cannot hold an unknown key; they are pinned
/// below, so a struct table cannot hide among them. A struct with `deny_unknown_fields`
/// refuses the file instead of listing the key, and is pinned separately.
#[test]
fn a_typo_in_any_table_is_listed() {
    fn strip_nulls(v: &mut serde_json::Value) {
        match v {
            serde_json::Value::Object(m) => {
                m.retain(|_, x| !x.is_null());
                m.values_mut().for_each(strip_nulls);
            }
            serde_json::Value::Array(a) => a.iter_mut().for_each(strip_nulls),
            _ => {}
        }
    }
    fn tables(v: &serde_json::Value, path: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
        match v {
            serde_json::Value::Object(m) => {
                out.push(path.clone());
                for (k, x) in m {
                    path.push(k.clone());
                    tables(x, path, out);
                    path.pop();
                }
            }
            serde_json::Value::Array(a) => {
                for (i, x) in a.iter().enumerate() {
                    path.push(i.to_string());
                    tables(x, path, out);
                    path.pop();
                }
            }
            _ => {}
        }
    }
    fn insert_typo(v: &mut serde_json::Value, path: &[String]) {
        let target = path.iter().fold(v, |v, seg| match v {
            serde_json::Value::Array(a) => &mut a[seg.parse::<usize>().unwrap()],
            other => &mut other[seg.as_str()],
        });
        target["zz_typo"] = serde_json::json!(1);
    }

    let mut default = serde_json::to_value(Config::default()).unwrap();
    strip_nulls(&mut default);
    let mut all = Vec::new();
    tables(&default, &mut Vec::new(), &mut all);
    assert!(all.len() > 25, "the walk stopped seeing tables: {all:?}");

    let mut maps = Vec::new();
    let mut refused = Vec::new();
    for table in &all {
        let mut doc = default.clone();
        insert_typo(&mut doc, table);
        let content = toml::to_string(&doc).unwrap();
        let dotted = table.join(".");
        match parse_config(&content) {
            Ok((_, keys)) => {
                let want = if dotted.is_empty() {
                    "zz_typo".to_string()
                } else {
                    format!("{dotted}.zz_typo")
                };
                assert_eq!(keys, [want], "typo in [{dotted}]");
            }
            // a struct with deny_unknown_fields refuses the file and names the key
            Err(e) if e.to_string().contains("unknown field `zz_typo`") => refused.push(dotted),
            Err(_) => maps.push(dotted),
        }
    }
    assert_eq!(
        maps,
        [
            "apk.proxies",
            "circuit_breaker.overrides",
            "deb.proxies",
            "helm.proxies",
            "rpm.proxies"
        ],
        "only name-keyed maps may refuse a typo key; a struct here hides its typos"
    );
    assert_eq!(
        refused,
        ["docker.upstreams.0"],
        "a struct that refuses must name the key"
    );
}

/// Every key the config reads is not listed: an empty file, the full default config,
/// and every secret — secrets are `skip_serializing`, so the round trip cannot see them.
#[test]
fn known_keys_are_not_listed() {
    assert!(unknown_keys("").is_empty());
    let default = toml::to_string(&{
        let mut v = serde_json::to_value(Config::default()).unwrap();
        fn strip(v: &mut serde_json::Value) {
            if let serde_json::Value::Object(m) = v {
                m.retain(|_, x| !x.is_null());
                m.values_mut().for_each(strip);
            } else if let serde_json::Value::Array(a) = v {
                a.iter_mut().for_each(strip);
            }
        }
        strip(&mut v);
        v
    })
    .unwrap();
    assert!(unknown_keys(&default).is_empty(), "{default}");

    // one `# secret` line per `skip_serializing` field of the config structs
    const SECRETS: &str = r#"
            [storage]
            s3_access_key = "ak"  # secret
            s3_secret_key = "sk"  # secret
            [curation]
            bypass_token = "t"  # secret
            [npm]
            proxy_auth = "u:p"  # secret
            proxies = [{ url = "https://npm.example", scopes = ["@x"], auth = "u:p" }]  # secret
            [pypi]
            proxy_auth = "u:p"  # secret
            proxies = [{ url = "https://pypi.example", auth = "u:p" }]  # secret
            [maven]
            proxies = [{ url = "https://maven.example", auth = "u:p" }]  # secret
            [[docker.upstreams]]
            url = "https://docker.example"
            auth = "u:p"  # secret
            [go]
            proxy_auth = "u:p"  # secret
            [cargo]
            proxy_auth = "u:p"  # secret
            [gems]
            proxy_auth = "u:p"  # secret
            [terraform]
            proxy_auth = "u:p"  # secret
            [ansible]
            proxy_auth = "u:p"  # secret
            [nuget]
            proxy_auth = "u:p"  # secret
            [pub_dart]
            proxy_auth = "u:p"  # secret
            [conan]
            proxy_auth = "u:p"  # secret
            [cpan]
            proxy_auth = "u:p"  # secret
            [rpm.proxies]
            fedora = { url = "https://rpm.example", auth = "u:p" }  # secret
        "#;
    assert!(unknown_keys(SECRETS).is_empty());

    let mut in_source = 0;
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/config");
    let mut stack = vec![std::path::PathBuf::from(dir)];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let src = std::fs::read_to_string(&p).unwrap();
                in_source += src
                    .lines()
                    .filter(|l| l.trim_start().starts_with("#[serde("))
                    .filter(|l| l.contains("skip_serializing)") || l.contains("skip_serializing,"))
                    .count();
            }
        }
    }
    assert_eq!(
        SECRETS.matches("# secret").count(),
        in_source,
        "a secret field was added or removed: list it in SECRETS"
    );
}

/// A typo inside a proxy entry given as a table is listed with its full path, like any
/// other typo — the entry is a URL string or a table, and the table's keys are tracked.
#[test]
fn typo_inside_a_proxy_entry_is_listed() {
    let content = r#"
            [maven]
            proxies = ["https://m1.example", { url = "https://m2.example", auht = "u:p" }]
            [pypi]
            proxies = [{ url = "https://p.example", auht = "u:p" }]
            [rpm.proxies]
            fedora = { url = "https://r.example", auht = "u:p" }
            [deb.proxies]
            debian = { url = "https://d.example", atuh = "u:p" }
        "#;
    assert_eq!(
        unknown_keys(content),
        [
            "deb.proxies.debian.atuh",
            "maven.proxies.1.auht",
            "pypi.proxies.0.auht",
            "rpm.proxies.fedora.auht",
        ]
    );
}

/// Proxy entries written before keep loading the same: a URL string, a table with
/// `url` and `auth`, both mixed in one list; and what was refused stays refused.
#[test]
fn proxy_entries_load_as_before() {
    let (config, keys) = parse_config(
        r#"
            [maven]
            proxies = ["https://m1.example", { url = "https://m2.example", auth = "u:p" }]
            [pypi]
            proxies = ["https://p1.example", { url = "https://p2.example", auth = "u:p" }]
            [rpm.proxies]
            fedora = "https://r1.example"
            epel = { url = "https://r2.example", auth = "u:p" }
            [deb.proxies]
            debian = "https://d1.example"
            local = { url = "https://d2.example" }
            "#,
    )
    .unwrap();
    assert!(keys.is_empty(), "{keys:?}");
    let maven: Vec<_> = config
        .maven
        .proxies
        .iter()
        .map(|p| (p.url(), p.auth()))
        .collect();
    assert_eq!(
        maven,
        [
            ("https://m1.example", None),
            ("https://m2.example", Some("u:p"))
        ]
    );
    assert!(matches!(
        config.maven.proxies[0],
        MavenProxyEntry::Simple(_)
    ));
    assert!(matches!(config.maven.proxies[1], MavenProxyEntry::Full(_)));
    let pypi: Vec<_> = config
        .pypi
        .proxies
        .iter()
        .map(|p| (p.url(), p.auth()))
        .collect();
    assert_eq!(
        pypi,
        [
            ("https://p1.example", None),
            ("https://p2.example", Some("u:p"))
        ]
    );
    assert_eq!(config.rpm.proxies["fedora"].url(), "https://r1.example");
    assert_eq!(config.rpm.proxies["fedora"].auth(), None);
    assert_eq!(config.rpm.proxies["epel"].url(), "https://r2.example");
    assert_eq!(config.rpm.proxies["epel"].auth(), Some("u:p"));
    assert_eq!(config.deb.proxies["debian"].url(), "https://d1.example");
    assert_eq!(config.deb.proxies["local"].url(), "https://d2.example");
    assert_eq!(config.deb.proxies["local"].auth(), None);

    for refused in [
        "[maven]\nproxies = [1]\n",
        "[maven]\nproxies = [{ auth = \"u:p\" }]\n",
        "[pypi]\nproxies = [true]\n",
        "[rpm.proxies]\nfedora = 1\n",
        "[deb.proxies]\ndebian = { auth = \"u:p\" }\n",
    ] {
        assert!(
            parse_config(refused).is_err(),
            "must stay refused: {refused}"
        );
    }
}

/// Serialization is unchanged: a string entry stays a string, a table keeps its `url`
/// and never writes the secret.
#[test]
fn proxy_entries_serialize_as_before() {
    let (config, _) = parse_config(
        "[maven]\nproxies = [\"https://m1.example\", { url = \"https://m2.example\", auth = \"u:p\" }]\n",
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&config.maven.proxies).unwrap(),
        serde_json::json!(["https://m1.example", { "url": "https://m2.example" }])
    );
}

/// Strict mode refuses a typo inside a proxy entry like any other.
#[test]
fn strict_mode_refuses_a_typo_inside_a_proxy_entry() {
    let _lock = env_lock();
    let dir = tempfile::TempDir::new().unwrap();
    let typo = dir.path().join("typo.toml").to_string_lossy().into_owned();
    std::fs::write(
        &typo,
        "[maven]\nproxies = [{ url = \"https://m.example\", auht = \"u:p\" }]\n",
    )
    .unwrap();
    match Config::load_from(Some(typo), NO_FALLBACK, true) {
        Err(ConfigLoadError::UnknownKeys { keys, .. }) => {
            assert_eq!(keys, ["maven.proxies.0.auht"])
        }
        other => panic!("strict mode must refuse the typo, got {other:?}"),
    }
}

/// The config shipped in the image has no unknown keys: strict mode must start on it.
#[test]
fn shipped_docker_config_has_no_unknown_keys() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../deploy/config.docker.toml");
    assert!(unknown_keys(&std::fs::read_to_string(path).unwrap()).is_empty());
}

/// Without strict mode the server starts and the keys come back for the warning;
/// with it, loading fails with a typed error that names every key.
#[test]
fn strict_mode_refuses_unknown_keys_and_default_mode_lists_them() {
    // load_from applies NORA_* overrides; other tests set invalid ones under this lock.
    let _lock = env_lock();
    let dir = tempfile::TempDir::new().unwrap();
    let typo = dir.path().join("typo.toml").to_string_lossy().into_owned();
    std::fs::write(
        &typo,
        "[curation]\nmdoe = \"enforce\"\n[gc]\nenabeld = true\n",
    )
    .unwrap();

    let (_, keys) =
        Config::load_from(Some(typo.clone()), NO_FALLBACK, false).expect("default mode starts");
    assert_eq!(keys, ["curation.mdoe", "gc.enabeld"]);

    match Config::load_from(Some(typo.clone()), NO_FALLBACK, true) {
        Err(ConfigLoadError::UnknownKeys { path, keys }) => {
            assert_eq!(path, typo);
            assert_eq!(keys, ["curation.mdoe", "gc.enabeld"]);
        }
        other => panic!("strict mode must refuse unknown keys, got {other:?}"),
    }

    let valid = dir.path().join("valid.toml").to_string_lossy().into_owned();
    std::fs::write(&valid, "[curation]\nmode = \"off\"\n").unwrap();
    let (_, keys) =
        Config::load_from(Some(valid), NO_FALLBACK, true).expect("strict starts on valid");
    assert!(keys.is_empty());
}

/// A fallback path no test creates, for tests that pass `NORA_CONFIG_PATH`.
const NO_FALLBACK: &str = "/nonexistent/nora-test/config.toml";

/// The working-directory `config.toml` (no `NORA_CONFIG_PATH`) is held to the same
/// rule at start. (On reload both sources share one code path; see the reload test.)
#[test]
fn fallback_config_file_is_held_to_the_same_rule() {
    let _lock = env_lock();
    let dir = tempfile::TempDir::new().unwrap();
    let typo = dir
        .path()
        .join("config.toml")
        .to_string_lossy()
        .into_owned();
    std::fs::write(&typo, "[curation]\nmdoe = \"enforce\"\n").unwrap();

    let (_, keys) = Config::load_from(None, &typo, false).expect("default mode starts");
    assert_eq!(keys, ["curation.mdoe"]);
    assert!(matches!(
        Config::load_from(None, &typo, true),
        Err(ConfigLoadError::UnknownKeys { .. })
    ));
}

/// OIDC config text with a provider `gh` (extra keys appended) and a
/// provider `gl` that names its audience.
fn oidc_config_with(gh_keys: &str) -> String {
    format!(
        "[auth]\nenabled = true\n[auth.oidc]\nenabled = true\n\
             [[auth.oidc.providers]]\nname = \"gh\"\nissuer = \"https://gh.example\"\n{gh_keys}\n\
             [[auth.oidc.providers]]\nname = \"gl\"\nissuer = \"https://gl.example\"\naudience = \"nora\"\n"
    )
}

/// The messages that speak about the `aud` check.
fn about_audience(msgs: &[String]) -> Vec<String> {
    msgs.iter()
        .filter(|m| m.contains("audience"))
        .cloned()
        .collect()
}

/// An enabled OIDC provider without an audience would accept a token its
/// issuer minted for any other service: NORA refuses to start, naming the
/// provider and both ways to fix it, in default and strict mode alike.
#[test]
fn an_oidc_provider_without_audience_refuses_to_start() {
    let _lock = env_lock();
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("oidc.toml").to_string_lossy().into_owned();
    std::fs::write(&path, oidc_config_with("")).unwrap();
    for strict in [false, true] {
        let err = Config::load_from(Some(path.clone()), "", strict)
            .expect_err("a provider without an audience must refuse to start");
        let ConfigLoadError::Invalid(errors) = &err else {
            panic!("expected a validation error, got {err}");
        };
        let refused = about_audience(errors);
        assert_eq!(refused.len(), 1, "{errors:#?}");
        assert!(refused[0].contains("\"gh\""), "{}", refused[0]);
        assert!(!refused[0].contains("\"gl\""), "{}", refused[0]);
        assert!(refused[0].contains("audience = \""), "{}", refused[0]);
        assert!(refused[0].contains("any_audience = true"), "{}", refused[0]);
    }

    // A disabled provider, or OIDC switched off, validates no token.
    let mut config: Config = toml::from_str(&oidc_config_with("enabled = false")).unwrap();
    let (warnings, errors) = config.validate_with_config_path(None);
    assert!(about_audience(&errors).is_empty(), "{errors:#?}");
    assert!(about_audience(&warnings).is_empty(), "{warnings:#?}");
    config.auth.oidc.providers[0].enabled = true;
    config.auth.oidc.enabled = false;
    assert!(about_audience(&config.validate_with_config_path(None).1).is_empty());
}

/// `any_audience = true` is the explicit way to run a provider without the
/// `aud` check: NORA starts and warns naming the provider.
#[test]
fn any_audience_starts_with_a_warning() {
    let _lock = env_lock();
    std::env::remove_var("NORA_CONFIG_STRICT");
    let config: Config = toml::from_str(&oidc_config_with("any_audience = true")).unwrap();
    let (warnings, errors) = config.validate_with_config_path(None);
    assert!(about_audience(&errors).is_empty(), "{errors:#?}");
    let warned = about_audience(&warnings);
    assert_eq!(warned.len(), 1, "{warnings:#?}");
    assert!(warned[0].contains("\"gh\""), "{}", warned[0]);
    assert!(warned[0].contains("any_audience"), "{}", warned[0]);
}

/// `any_audience = true` beside an `audience` does nothing: the audience is
/// checked. NORA starts and says the key is ignored.
#[test]
fn any_audience_beside_an_audience_is_reported_unused() {
    let _lock = env_lock();
    let config: Config = toml::from_str(&oidc_config_with(
        "audience = \"nora\"\nany_audience = true",
    ))
    .unwrap();
    let (warnings, errors) = config.validate_with_config_path(None);
    assert!(about_audience(&errors).is_empty(), "{errors:#?}");
    let warned = about_audience(&warnings);
    assert_eq!(warned.len(), 1, "{warnings:#?}");
    assert!(warned[0].contains("\"gh\""), "{}", warned[0]);
    assert!(warned[0].contains("ignored"), "{}", warned[0]);
}

/// A SIGHUP reload whose file has a provider without an audience is refused,
/// so the running configuration stays.
#[test]
fn reload_refuses_an_oidc_provider_without_audience() {
    let _lock = env_lock();
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("oidc.toml").to_string_lossy().into_owned();
    std::fs::write(&path, oidc_config_with("")).unwrap();
    std::env::set_var("NORA_CONFIG_PATH", &path);
    let refused = Config::try_load_from(Config::path_from_env());
    std::fs::write(&path, oidc_config_with("any_audience = true")).unwrap();
    let opted_out = Config::try_load_from(Config::path_from_env());
    std::env::remove_var("NORA_CONFIG_PATH");
    let err = refused.expect_err("a reload without an audience must be refused");
    assert!(err.contains("\"gh\"") && err.contains("audience"), "{err}");
    assert!(opted_out.is_ok(), "{:?}", opted_out.err());
}

/// `NORA_CONFIG_STRICT` follows the other boolean switches: `true` (any case) or `1`.
#[test]
fn config_strict_reads_its_env_switch() {
    let _lock = env_lock();
    let read = |v: Option<&str>| {
        match v {
            Some(v) => std::env::set_var("NORA_CONFIG_STRICT", v),
            None => std::env::remove_var("NORA_CONFIG_STRICT"),
        }
        let on = config_strict_from_env();
        std::env::remove_var("NORA_CONFIG_STRICT");
        on
    };
    assert!(!read(None));
    assert!(read(Some("true")));
    assert!(read(Some("TRUE")));
    assert!(read(Some("1")));
    assert!(!read(Some("false")));
    assert!(!read(Some("0")));
}

/// `Config::load` itself reads `NORA_CONFIG_STRICT`: the switch reaches the start path,
/// not only the helper the other tests drive.
#[test]
fn load_reads_the_strict_switch_from_env() {
    let _lock = env_lock();
    let dir = tempfile::TempDir::new().unwrap();
    let typo = dir.path().join("typo.toml").to_string_lossy().into_owned();
    std::fs::write(&typo, "[curation]\nmdoe = \"enforce\"\n").unwrap();
    std::env::set_var("NORA_CONFIG_PATH", &typo);
    std::env::set_var("NORA_CONFIG_STRICT", "true");
    let strict = Config::load();
    std::env::remove_var("NORA_CONFIG_STRICT");
    let lenient = Config::load();
    std::env::remove_var("NORA_CONFIG_PATH");
    assert!(
        matches!(&strict, Err(ConfigLoadError::UnknownKeys { keys, .. }) if keys == &["curation.mdoe"]),
        "{strict:?}"
    );
    assert!(lenient.is_ok(), "{:?}", lenient.err());
}

/// SIGHUP reload honours strict mode too: a reload with a typo is refused, so the
/// running configuration stays.
#[test]
fn reload_refuses_unknown_keys_in_strict_mode() {
    let _lock = env_lock();
    let dir = tempfile::TempDir::new().unwrap();
    let typo = dir.path().join("typo.toml").to_string_lossy().into_owned();
    std::fs::write(&typo, "[curation]\nmdoe = \"enforce\"\n").unwrap();
    std::env::set_var("NORA_CONFIG_PATH", &typo);
    std::env::set_var("NORA_CONFIG_STRICT", "true");
    let strict = Config::try_load_from(Config::path_from_env());
    std::env::remove_var("NORA_CONFIG_STRICT");
    let lenient = Config::try_load_from(Config::path_from_env());
    std::env::remove_var("NORA_CONFIG_PATH");
    let err = strict.expect_err("strict reload must refuse unknown keys");
    assert!(err.contains("curation.mdoe"), "{err}");
    assert!(lenient.is_ok(), "{:?}", lenient.err());
}

/// A fatal configuration error is a typed error for `main` to exit on with
/// EX_CONFIG, not a panic (which aborted with SIGABRT and made systemd retry).
#[test]
fn fatal_validation_is_an_error_not_a_panic() {
    assert_eq!(EXIT_CONFIG, 78, "EX_CONFIG from sysexits.h");
    let mut config = Config::default();
    config.server.host = "0.0.0.0".to_string();
    config.server.public_url = None;
    let err = config
        .checked()
        .expect_err("wildcard host without public_url");
    assert!(matches!(err, ConfigLoadError::Invalid(_)));
    assert!(err.to_string().contains("NORA_PUBLIC_URL"), "{err}");

    let mut ok = Config::default();
    ok.server.host = "::".to_string();
    ok.server.public_url = Some("http://localhost:4000".to_string());
    assert!(ok.checked().is_ok());
}

#[test]
fn test_validate_default_config_ok() {
    let _lock = env_lock();
    let config = Config::default();
    let (warnings, errors) = config.validate();
    assert!(
        errors.is_empty(),
        "default config should have no errors: {:?}",
        errors
    );
    assert!(
        warnings.is_empty(),
        "default config should have no warnings: {:?}",
        warnings
    );
}

#[test]
fn test_is_loopback_host() {
    // loopback forms (caller strips IPv6 brackets before calling)
    assert!(Config::is_loopback_host("127.0.0.1"));
    assert!(Config::is_loopback_host("127.1.2.3")); // whole 127.0.0.0/8
    assert!(Config::is_loopback_host("::1"));
    assert!(Config::is_loopback_host("localhost"));
    assert!(Config::is_loopback_host("LocalHost")); // case-insensitive (#590 review)
                                                    // not loopback
    assert!(!Config::is_loopback_host("0.0.0.0")); // wildcard → handled as error elsewhere
    assert!(!Config::is_loopback_host("192.168.1.10"));
    assert!(!Config::is_loopback_host("8.8.8.8"));
    assert!(!Config::is_loopback_host("registry.example.com"));
}

#[test]
fn test_validate_public_url_loopback_warns() {
    let _lock = env_lock();
    // public_url explicitly pointing at loopback is broken for remote clients (#590):
    // a warning, not an error, since local-only use is valid. Tested through
    // validate() (not is_loopback_host directly) to cover the real host_str() path,
    // including IPv6 literals whose brackets must be stripped (#590 review).
    for url in [
        "http://localhost:4000",
        "http://127.0.0.1:4000",
        "http://[::1]:4000",
    ] {
        let mut config = Config::default();
        config.server.public_url = Some(url.to_string());
        let (warnings, errors) = config.validate_with_config_path(None);
        assert!(
            errors.is_empty(),
            "loopback public_url '{url}' is a warning, not an error: {:?}",
            errors
        );
        assert!(
            warnings.iter().any(|w| w.contains("loopback")),
            "expected loopback warning for public_url '{url}': {:?}",
            warnings
        );
    }
}

/// An enabled OIDC provider with an empty audience would skip `aud` validation: it is
/// refused, strict mode or not (upstream 1.4.3 made the fork's warning an error).
#[test]
fn test_validate_oidc_empty_audience_is_refused() {
    let _lock = env_lock();
    let mut config = Config::default();
    config.auth.oidc = toml::from_str(
        "enabled = true\n[[providers]]\nname = \"gha\"\nissuer = \"https://issuer.example\"",
    )
    .unwrap();
    let (_, errors) = config.validate_with_config_path(None);
    assert!(
        errors.iter().any(|e| e.contains("\"gha\" has no audience")),
        "{errors:?}"
    );

    config.auth.oidc.providers[0].audience = "packages.example.com".to_string();
    let (warnings, errors) = config.validate_with_config_path(None);
    assert!(
        !warnings
            .iter()
            .chain(&errors)
            .any(|w| w.contains("audience")),
        "{warnings:?} {errors:?}"
    );
}

#[test]
fn test_validate_port_zero() {
    let _lock = env_lock();
    let mut config = Config::default();
    config.server.port = 0;
    let (_, errors) = config.validate();
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("port"));
}

#[test]
fn test_validate_internal_port_equal_to_port() {
    let _lock = env_lock();
    let mut config = Config::default();
    config.server.internal_port = Some(config.server.port);
    let (_, errors) = config.validate();
    assert!(
        errors.iter().any(|e| e.contains("internal_port")),
        "{errors:?}"
    );
}

#[test]
fn test_validate_empty_storage_path_local() {
    let _lock = env_lock();
    let mut config = Config::default();
    config.storage.mode = StorageMode::Local;
    config.storage.path = String::new();
    let (_, errors) = config.validate();
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("storage.path"));
}

#[test]
fn test_validate_whitespace_storage_path_local() {
    let _lock = env_lock();
    let mut config = Config::default();
    config.storage.mode = StorageMode::Local;
    config.storage.path = "   ".to_string();
    let (_, errors) = config.validate();
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("storage.path"));
}

#[test]
fn test_validate_empty_bucket_s3() {
    let _lock = env_lock();
    let mut config = Config::default();
    config.storage.mode = StorageMode::S3;
    config.storage.bucket = String::new();
    let (_, errors) = config.validate();
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("storage.bucket"));
}

#[test]
fn test_validate_empty_storage_path_s3_ok() {
    let _lock = env_lock();
    // Empty path is fine when mode is S3
    let mut config = Config::default();
    config.storage.mode = StorageMode::S3;
    config.storage.path = String::new();
    let (_, errors) = config.validate();
    assert!(errors.is_empty());
}

#[test]
fn test_validate_rate_limit_zero_rps() {
    let _lock = env_lock();
    let mut config = Config::default();
    config.rate_limit.enabled = true;
    config.rate_limit.auth_rps = 0;
    let (warnings, errors) = config.validate();
    assert!(errors.is_empty());
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("auth_rps"));
}

#[test]
fn test_validate_rate_limit_disabled_zero_ok() {
    let _lock = env_lock();
    // Zero rate limit values are fine when rate limiting is disabled
    let mut config = Config::default();
    config.rate_limit.enabled = false;
    config.rate_limit.auth_rps = 0;
    config.rate_limit.auth_burst = 0;
    let (warnings, errors) = config.validate();
    assert!(errors.is_empty());
    assert!(warnings.is_empty());
}

#[test]
fn test_validate_rate_limit_all_zeros() {
    let _lock = env_lock();
    let mut config = Config::default();
    config.rate_limit.enabled = true;
    config.rate_limit.auth_rps = 0;
    config.rate_limit.auth_burst = 0;
    config.rate_limit.upload_rps = 0;
    config.rate_limit.upload_burst = 0;
    config.rate_limit.general_rps = 0;
    config.rate_limit.general_burst = 0;
    let (warnings, errors) = config.validate();
    assert!(errors.is_empty());
    assert_eq!(warnings.len(), 6);
}

#[test]
fn test_validate_body_limit_zero() {
    let _lock = env_lock();
    let mut config = Config::default();
    config.server.body_limit_mb = 0;
    let (warnings, errors) = config.validate();
    assert!(errors.is_empty());
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("body_limit_mb"));
}

/// A zero connection limit would close every connection at once or accept none.
#[test]
fn test_validate_connection_limits_zero() {
    let _lock = env_lock();
    for key in [
        "header_read_timeout",
        "keep_alive_timeout",
        "max_connections",
    ] {
        let mut config = Config::default();
        match key {
            "header_read_timeout" => config.server.header_read_timeout = 0,
            "keep_alive_timeout" => config.server.keep_alive_timeout = 0,
            _ => config.server.max_connections = 0,
        }
        let (_, errors) = config.validate();
        assert_eq!(errors, vec![format!("server.{key} must not be 0")]);
    }
}

/// An idle keep-alive not above the 90 s traefik keeps an idle backend connection is
/// warned about, not refused: the proxy may send a request into a connection NORA is
/// closing and answer 502. Above it, the default included, nothing is said.
#[test]
fn a_keep_alive_not_above_the_proxy_idle_timeout_is_warned_about() {
    let _lock = env_lock();
    let warned = |secs: u64| {
        let mut config = Config::default();
        config.server.keep_alive_timeout = secs;
        let (warnings, errors) = config.validate();
        assert!(errors.is_empty(), "{secs}: {errors:?}");
        warnings
            .iter()
            .filter(|w| w.contains("server.keep_alive_timeout"))
            .count()
    };
    for secs in [1, 5, 30, 89, 90] {
        assert_eq!(warned(secs), 1, "{secs} s");
    }
    for secs in [91, 120, 3600] {
        assert_eq!(warned(secs), 0, "{secs} s");
    }
    assert_eq!(warned(Config::default().server.keep_alive_timeout), 0);
}

/// R4-C13: an enabled cleanup pass with interval 0 is a config error, not a busy loop.
#[test]
fn test_validate_cleanup_interval_zero_is_an_error() {
    let _lock = env_lock();
    let gc = "gc.interval must be at least 1 second, got 0 (to turn GC off set gc.enabled=false)";
    let retention = "retention.interval must be at least 1 second, got 0 (to turn retention off set retention.enabled=false; the hosted NuGet cleanup runs on this interval whenever nuget.enabled)";
    let mut config = Config::default();
    config.nuget.enabled = false;
    config.gc.interval = 0;
    config.retention.interval = 0;
    assert!(
        config.validate().1.is_empty(),
        "disabled passes: any interval"
    );
    // The hosted NuGet cleanup is a pass on the retention interval of its own.
    config.nuget.enabled = true;
    assert_eq!(config.validate().1, vec![retention]);
    config.nuget.enabled = false;
    config.gc.enabled = true;
    config.retention.enabled = true;
    assert_eq!(config.validate().1, vec![gc, retention]);
    config.gc.interval = 1;
    config.retention.interval = 1;
    assert!(config.validate().1.is_empty());
}

/// Below three maintenance ticks one failing tick would fail liveness.
#[test]
fn test_validate_maintenance_stall_floor() {
    let _lock = env_lock();
    let mut config = Config::default();
    config.server.maintenance_stall_secs = 89;
    let (_, errors) = config.validate();
    assert_eq!(
        errors,
        vec!["server.maintenance_stall_secs must be at least 90 (three maintenance ticks), got 89"]
    );
    config.server.maintenance_stall_secs = 90;
    assert!(config.validate().1.is_empty());
}

#[test]
fn test_validate_multiple_errors() {
    let _lock = env_lock();
    let mut config = Config::default();
    config.server.port = 0;
    config.storage.mode = StorageMode::Local;
    config.storage.path = String::new();
    let (_, errors) = config.validate();
    assert_eq!(errors.len(), 2);
}

#[test]
fn test_validate_warnings_and_errors_together() {
    let _lock = env_lock();
    let mut config = Config::default();
    config.server.port = 0;
    config.server.body_limit_mb = 0;
    config.rate_limit.enabled = true;
    config.rate_limit.auth_rps = 0;
    let (warnings, errors) = config.validate();
    assert_eq!(errors.len(), 1);
    assert_eq!(warnings.len(), 2); // body_limit + auth_rps
}
#[test]
fn test_validate_gc_enabled_dry_run() {
    let _lock = env_lock();
    let mut config = Config::default();
    config.gc.enabled = true;
    config.gc.dry_run = true;
    let (warnings, errors) = config.validate();
    assert!(errors.is_empty());
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("gc.dry_run"));
}

#[test]
fn test_validate_gc_enabled_no_dry_run_ok() {
    let _lock = env_lock();
    let mut config = Config::default();
    config.gc.enabled = true;
    config.gc.dry_run = false;
    let (warnings, errors) = config.validate();
    assert!(errors.is_empty());
    assert!(warnings.is_empty());
}

#[test]
fn test_validate_retention_enabled_empty_rules() {
    let _lock = env_lock();
    let mut config = Config::default();
    config.retention.enabled = true;
    config.retention.rules = Vec::new();
    let (warnings, errors) = config.validate();
    assert!(errors.is_empty());
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("retention"));
}

#[test]
fn test_validate_retention_enabled_with_rules_ok() {
    let _lock = env_lock();
    let mut config = Config::default();
    config.retention.enabled = true;
    config.retention.rules = vec![RetentionRule {
        registry: "docker".to_string(),
        name_glob: None,
        keep_last: Some(5),
        older_than_days: None,
        include_tags: Vec::new(),
        exclude_tags: Vec::new(),
    }];
    let (warnings, errors) = config.validate();
    assert!(errors.is_empty());
    assert!(warnings.is_empty());
}

#[test]
fn test_validate_relative_paths_with_config_path() {
    let _lock = env_lock();
    let mut config = Config::default();
    config.auth.enabled = true;
    // default paths are relative: "data/storage", "data/tokens"
    let (warnings, _) = config.validate_with_config_path(Some("/tmp/test-config.toml".to_string()));
    assert!(
        warnings.iter().any(|w| w.contains("storage.path")),
        "should warn about relative storage.path"
    );
    assert!(
        warnings.iter().any(|w| w.contains("token_storage")),
        "should warn about relative token_storage"
    );
}

#[test]
fn test_relative_token_storage_warns_without_config_path() {
    let _lock = env_lock();
    // #816: env-only (systemd) starts have config_path=None. A relative
    // token_storage with auth enabled must still warn — that is exactly the
    // case that escapes the sandbox and breaks token writes.
    let mut config = Config::default();
    config.auth.enabled = true; // default token_storage = "data/tokens" (relative)
    let (warnings, _) = config.validate_with_config_path(None);
    assert!(
        warnings.iter().any(|w| w.contains("token_storage")),
        "relative token_storage must warn even with no config file (env-only deploy)"
    );
    // The storage.path hint stays scoped to explicit-config starts (no noise on
    // the bare-serve relative default).
    assert!(
        !warnings.iter().any(|w| w.contains("storage.path")),
        "storage.path hint should remain gated behind an explicit config file"
    );
}

#[test]
fn test_validate_absolute_paths_no_warning() {
    let _lock = env_lock();
    let mut config = Config::default();
    config.storage.path = "/data/storage".to_string();
    config.auth.enabled = true;
    config.auth.token_storage = "/data/tokens".to_string();
    let (warnings, _) = config.validate_with_config_path(Some("/tmp/test-config.toml".to_string()));
    assert!(
        !warnings.iter().any(|w| w.contains("storage.path")),
        "should not warn about absolute storage.path"
    );
    assert!(
        !warnings.iter().any(|w| w.contains("token_storage")),
        "should not warn about absolute token_storage"
    );
}

/// One `[[docker.upstreams]]` entry as `(prefix, namespaces)`.
type Entry<'a> = (Option<&'a str>, &'a [&'a str]);

/// `docker` config whose upstreams are `(prefix, namespaces)` pairs, through the production
/// validation; returns (warnings, errors) that mention docker.
fn docker_problems(
    entries: &[Entry<'_>],
    action: DefaultAction,
    internal: &[&str],
) -> (Vec<String>, Vec<String>) {
    let mut config = Config::default();
    config.docker.default_action = action;
    config.curation.internal_namespaces = internal.iter().map(|p| p.to_string()).collect();
    config.docker.upstreams = entries
        .iter()
        .enumerate()
        .map(|(i, (prefix, masks))| DockerUpstream {
            trust_upstream_dates: false,
            date_token_file: None,
            url: format!("https://r{i}.example"),
            auth: None,
            auth_env: None,
            namespace: None,
            prefix: prefix.map(str::to_string),
            namespaces: masks.iter().map(|m| m.to_string()).collect(),
        })
        .collect();
    let (warnings, errors) = config.validate();
    let docker = |v: Vec<String>| v.into_iter().filter(|m| m.contains("docker")).collect();
    (docker(warnings), docker(errors))
}

/// #1188: a name has one owner, a pattern lives in `namespaces` and nowhere else, and an
/// entry must be a first path segment or one followed by `*`.
#[test]
fn docker_namespaces_are_refused_unless_every_name_has_one_owner() {
    let allow = DefaultAction::Allow;
    #[rustfmt::skip]
    let refused: &[(&[Entry], &str)] = &[
        (&[(None, &["team-*"]), (None, &["te*"])],         "overlaps \"te*\""),
        (&[(None, &["team-a"]), (None, &["team-*"])],      "overlaps \"team-*\""),
        (&[(None, &["ops"]), (None, &["ops"])],            "overlaps \"ops\""),
        (&[(Some("team-a"), &[]), (None, &["team-*"])],    "holds for prefix \"team-a\""),
        (&[(Some("hub"), &["hub"])],                       "holds for prefix \"hub\""),
        (&[(Some("*"), &[]), (None, &[])],                 "matched literally"),
        (&[(Some("team-?"), &[])],                         "matched literally"),
        (&[(None, &["v*"])],                               "reserved"),
        (&[(None, &["blob*"])],                            "reserved"),
    ];
    for (entries, want) in refused {
        let (_, errors) = docker_problems(entries, allow, &[]);
        assert!(
            errors.iter().any(|e| e.contains(want)),
            "{entries:?}: {errors:?}"
        );
    }
    for mask in [
        "",
        "*",
        "Team-a",
        "team/a",
        "team.example",
        "team**",
        "*-a",
        "te*m",
        "-team",
        "team-a ",
    ] {
        let (_, errors) = docker_problems(&[(None, &[mask])], allow, &[]);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("is not a first path segment")),
            "{mask:?}: {errors:?}"
        );
    }
    #[rustfmt::skip]
    let accepted: &[&[Entry]] = &[
        &[(None, &["team-*", "ops"]), (None, &[])],
        &[(None, &["team-a*"]), (None, &["team-b*"]), (None, &[])],
        &[(Some("ghcr"), &[]), (None, &["team-*"]), (None, &[])],
        // one entry may repeat itself, and may also be reached by its own prefix
        &[(Some("harbor"), &["team-*", "team-a"]), (None, &[])],
        &[(None, &["a_b", "x1-*"]), (None, &[])],
    ];
    for entries in accepted {
        let (_, errors) = docker_problems(entries, allow, &[]);
        assert!(errors.is_empty(), "{entries:?}: {errors:?}");
    }
}

/// #1188 warnings: deny with only bound upstreams is not a deny-everything trap; every entry
/// bound leaves public names local; a namespace curation calls internal is never proxied.
#[test]
fn docker_namespaces_warn_where_the_config_does_not_say_what_it_seems() {
    let (warnings, _) = docker_problems(
        &[(None, &["team-*"]), (None, &[])],
        DefaultAction::Deny,
        &[],
    );
    assert!(
        !warnings
            .iter()
            .any(|w| w.contains("all requests will be denied")),
        "{warnings:?}"
    );
    let (warnings, _) = docker_problems(&[(None, &[])], DefaultAction::Deny, &[]);
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("all requests will be denied")),
        "{warnings:?}"
    );

    let (warnings, _) = docker_problems(&[(None, &["team-*"])], DefaultAction::Allow, &[]);
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("every entry has namespaces")),
        "{warnings:?}"
    );
    let (warnings, _) = docker_problems(
        &[(None, &["team-*"]), (None, &[])],
        DefaultAction::Allow,
        &[],
    );
    assert!(
        !warnings
            .iter()
            .any(|w| w.contains("every entry has namespaces")),
        "{warnings:?}"
    );

    for (pattern, meets) in [
        ("*", true),
        ("*-internal", true),
        ("team-a/**", true),
        ("team-a/secret", true),
        ("team-a/*", true),
        ("te*", true),
        ("team-b*", true),
        ("other/**", false),
        ("teamx*", false),
        ("team-a", false),
        ("com.corp.**", false),
    ] {
        let (warnings, _) = docker_problems(
            &[(None, &["team-*"]), (None, &[])],
            DefaultAction::Allow,
            &[pattern],
        );
        let warned = warnings.iter().any(|w| w.contains("internal_namespaces"));
        assert_eq!(warned, meets, "{pattern}: {warnings:?}");
    }
}

#[test]
fn test_env_override_docker_proxies_namespaces_field() {
    let _lock = env_lock();
    std::env::remove_var("NORA_DOCKER_UPSTREAMS");
    std::env::set_var(
        "NORA_DOCKER_PROXIES",
        "https://harbor.example|robot:pw||team-*;ops,https://registry-1.docker.io,https://ghcr.io||ghcr",
    );
    let mut config = Config::default();
    config.apply_env_overrides().unwrap();
    std::env::remove_var("NORA_DOCKER_PROXIES");
    let u = &config.docker.upstreams;
    assert_eq!(u.len(), 3);
    assert_eq!(u[0].namespaces, ["team-*", "ops"]);
    assert_eq!(u[0].prefix, None);
    assert_eq!(crate::secrets::expose_opt(&u[0].auth), Some("robot:pw"));
    assert!(u[1].namespaces.is_empty());
    assert_eq!(u[2].prefix.as_deref(), Some("ghcr"));
    assert!(u[2].namespaces.is_empty());
}

#[test]
fn docker_upstream_auth_env_reads_the_credential_and_rejects_a_missing_one() {
    let _lock = env_lock();
    std::env::remove_var("NORA_DOCKER_PROXIES");
    std::env::remove_var("NORA_DOCKER_UPSTREAMS");
    let toml = r#"
            [docker]
            default_action = "deny"

            [[docker.upstreams]]
            url = "https://registry-1.docker.io"
            prefix = "docker-hub"
            namespace = "docker.io"
            auth_env = "NORA_TEST_DOCKER_HUB_AUTH"

            [[docker.upstreams]]
            url = "https://ghcr.io"
            prefix = "ghcr"
        "#;
    std::env::set_var("NORA_TEST_DOCKER_HUB_AUTH", "user:token");
    let mut config: Config = toml::from_str(toml).unwrap();
    config.apply_env_overrides().unwrap();
    assert_eq!(
        crate::secrets::expose_opt(&config.docker.upstreams[0].auth),
        Some("user:token")
    );
    assert!(config.docker.upstreams[1].auth.is_none());
    let (_, errors) = config.validate();
    assert!(!errors.iter().any(|e| e.contains("auth_env")), "{errors:?}");

    std::env::remove_var("NORA_TEST_DOCKER_HUB_AUTH");
    let mut config: Config = toml::from_str(toml).unwrap();
    config.apply_env_overrides().unwrap();
    assert!(config.docker.upstreams[0].auth.is_none());
    let (_, errors) = config.validate();
    assert!(
        errors.iter().any(|e| e
            == "docker.upstreams[0]: auth_env names NORA_TEST_DOCKER_HUB_AUTH, which is unset or empty"),
        "{errors:?}"
    );
}

#[test]
fn test_env_override_docker_proxies_and_backward_compat() {
    let _lock = env_lock();
    // Test new NORA_DOCKER_PROXIES name
    std::env::remove_var("NORA_DOCKER_UPSTREAMS");
    std::env::set_var(
        "NORA_DOCKER_PROXIES",
        "https://mirror.gcr.io,https://private.io|token123",
    );
    let mut config = Config::default();
    config.apply_env_overrides().unwrap();
    assert_eq!(config.docker.upstreams.len(), 2);
    assert_eq!(config.docker.upstreams[0].url, "https://mirror.gcr.io");
    assert!(config.docker.upstreams[0].auth.is_none());
    assert_eq!(config.docker.upstreams[1].url, "https://private.io");
    assert_eq!(
        crate::secrets::expose_opt(&config.docker.upstreams[1].auth),
        Some("token123")
    );
    std::env::remove_var("NORA_DOCKER_PROXIES");

    // Test backward compat: old NORA_DOCKER_UPSTREAMS still works
    std::env::remove_var("NORA_DOCKER_PROXIES");
    std::env::set_var("NORA_DOCKER_UPSTREAMS", "https://legacy.io|secret");
    let mut config2 = Config::default();
    config2.apply_env_overrides().unwrap();
    assert_eq!(config2.docker.upstreams.len(), 1);
    assert_eq!(config2.docker.upstreams[0].url, "https://legacy.io");
    assert_eq!(
        crate::secrets::expose_opt(&config2.docker.upstreams[0].auth),
        Some("secret")
    );
    std::env::remove_var("NORA_DOCKER_UPSTREAMS");
}

#[test]
fn test_env_override_go_proxy() {
    let _lock = env_lock();
    let mut config = Config::default();
    std::env::set_var("NORA_GO_PROXY", "https://goproxy.company.com");
    config.apply_env_overrides().unwrap();
    assert_eq!(
        config.go.proxy,
        Some("https://goproxy.company.com".to_string()),
    );
    std::env::remove_var("NORA_GO_PROXY");
}

#[test]
fn test_env_override_go_proxy_auth() {
    let _lock = env_lock();
    let mut config = Config::default();
    std::env::set_var("NORA_GO_PROXY_AUTH", "user:pass");
    config.apply_env_overrides().unwrap();
    assert_eq!(
        crate::secrets::expose_opt(&config.go.proxy_auth),
        Some("user:pass")
    );
    std::env::remove_var("NORA_GO_PROXY_AUTH");
}

#[test]
fn test_cargo_config_default() {
    let c = CargoConfig::default();
    assert_eq!(c.proxy, Some("https://crates.io".to_string()));
    assert_eq!(c.proxy_timeout, 30);
}

#[test]
fn test_config_file_sets_s3_mode_without_env() {
    let _lock = env_lock();
    // Regression test for issue #4: config.toml mode="s3" must work
    // without NORA_STORAGE_MODE env var (previously overridden by
    // Dockerfile ENV NORA_STORAGE_MODE=local)
    std::env::remove_var("NORA_STORAGE_MODE");

    let toml = r#"
            [server]
            host = "0.0.0.0"
            port = 4000

            [storage]
            mode = "s3"
            s3_url = "http://s3.example.com:9000"
            bucket = "nora"
        "#;

    let mut config: Config = toml::from_str(toml).unwrap();
    config.apply_env_overrides().unwrap();
    assert_eq!(
        config.storage.mode,
        StorageMode::S3,
        "config.toml mode=s3 must not be overridden when NORA_STORAGE_MODE is unset"
    );
}

// ========================================================================
// Curation config tests
// ========================================================================

#[test]
fn test_curation_config_default() {
    let c = CurationConfig::default();
    assert_eq!(c.mode, CurationMode::Off);
    assert_eq!(c.on_failure, CurationOnFailure::Closed);
    assert!(c.allowlist_path.is_none());
    assert!(c.blocklist_path.is_none());
    assert!(c.bypass_token.is_none());
    assert!(!c.require_integrity);
}

#[test]
fn test_curation_config_from_toml() {
    let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"

            [curation]
            mode = "audit"
            on_failure = "open"
            require_integrity = true
        "#;

    let config: Config = toml::from_str(toml).unwrap();
    assert_eq!(config.curation.mode, CurationMode::Audit);
    assert_eq!(config.curation.on_failure, CurationOnFailure::Open);
    assert!(config.curation.require_integrity);
    assert_eq!(config.curation.quarantine, None);
}

#[test]
fn test_curation_quarantine_from_toml() {
    let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"

            [curation]
            quarantine = "enforce"
            quarantine_ttl = "14d"

            [curation.docker]
            quarantine = "observe"
            quarantine_ttl = "7d"
        "#;

    let config: Config = toml::from_str(toml).unwrap();
    assert_eq!(config.curation.quarantine, Some(QuarantineMode::Enforce));
    assert_eq!(config.curation.quarantine_ttl, Some("14d".to_string()));
    assert_eq!(
        config.curation.docker.quarantine,
        Some(QuarantineMode::Observe)
    );
    assert_eq!(
        config.curation.docker.quarantine_ttl,
        Some("7d".to_string())
    );
    // Other registries should be None
    assert_eq!(config.curation.npm.quarantine, None);
}

#[test]
fn test_curation_allow_from_toml_and_env() {
    let _lock = env_lock();
    let toml = r#"
            [curation.nuget]
            allow = ["Newtonsoft.Json@13.0.4"]

            [curation.npm]
            allow = ["left-pad@1.3.0", "@scope/pkg@2.0.0"]
        "#;
    let mut config: Config = toml::from_str(toml).unwrap();
    assert_eq!(config.curation.nuget.allow, ["Newtonsoft.Json@13.0.4"]);
    assert_eq!(
        config.curation.npm.allow,
        ["left-pad@1.3.0", "@scope/pkg@2.0.0"]
    );
    assert!(config.curation.pypi.allow.is_empty());

    std::env::set_var("NORA_CURATION_PYPI_ALLOW", "requests@2.32.3, numpy@2.1.0,");
    let applied = config.apply_env_overrides();
    std::env::remove_var("NORA_CURATION_PYPI_ALLOW");
    applied.unwrap();
    assert_eq!(
        config.curation.pypi.allow,
        ["requests@2.32.3", "numpy@2.1.0"]
    );
    assert_eq!(config.curation.nuget.allow, ["Newtonsoft.Json@13.0.4"]);
}

/// Pattern `allow` entries parse from TOML and env; an entry nora cannot read is a
/// warning naming it, an error under NORA_CONFIG_STRICT.
#[test]
fn test_curation_allow_patterns_validated() {
    let _lock = env_lock();
    std::env::remove_var("NORA_CONFIG_STRICT");
    let toml = r#"
            [curation.nuget]
            allow = ["Microsoft.NETCore.*", "Microsoft.AspNetCore.*@*", "Newtonsoft.Json"]
        "#;
    let config: Config = toml::from_str(toml).unwrap();
    let (warnings, errors) = config.validate_with_config_path(None);
    let about_allow = |list: &[String]| {
        list.iter()
            .filter(|m| m.contains(".allow entry"))
            .cloned()
            .collect::<Vec<_>>()
    };
    assert!(about_allow(&warnings).is_empty(), "{warnings:?}");
    assert!(about_allow(&errors).is_empty(), "{errors:?}");

    let mut config = Config::default();
    config.curation.nuget.allow = vec![
        "Microsoft.NETCore.*".to_string(),
        "*".to_string(),
        "Microsoft.*.App".to_string(),
        "Microsoft.NETCore.App.Ref@10.*".to_string(),
    ];
    config.curation.npm.allow = vec!["@*".to_string()];
    let (warnings, errors) = config.validate_with_config_path(None);
    let warned = about_allow(&warnings);
    assert_eq!(warned.len(), 4, "{warned:?}");
    assert!(
        warned[0].contains("curation.npm.allow entry \"@*\""),
        "{warned:?}"
    );
    assert!(warned
        .iter()
        .any(|m| m.contains("curation.nuget.allow entry \"*\"")));
    assert!(about_allow(&errors).is_empty(), "{errors:?}");

    std::env::set_var("NORA_CONFIG_STRICT", "true");
    let (warnings, errors) = config.validate_with_config_path(None);
    std::env::remove_var("NORA_CONFIG_STRICT");
    assert!(about_allow(&warnings).is_empty(), "{warnings:?}");
    let refused = about_allow(&errors);
    assert_eq!(refused.len(), 4, "{refused:?}");
    assert!(refused
        .iter()
        .all(|m| m.contains("NORA_CONFIG_STRICT is on")));

    std::env::set_var(
        "NORA_CURATION_NUGET_ALLOW",
        "Microsoft.NETCore.*,Microsoft.AspNetCore.*",
    );
    let mut config = Config::default();
    let applied = config.apply_env_overrides();
    std::env::remove_var("NORA_CURATION_NUGET_ALLOW");
    applied.unwrap();
    assert_eq!(
        config.curation.nuget.allow,
        ["Microsoft.NETCore.*", "Microsoft.AspNetCore.*"]
    );
}

#[test]
fn test_curation_config_missing_defaults_to_off() {
    let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"
        "#;

    let config: Config = toml::from_str(toml).unwrap();
    assert_eq!(config.curation.mode, CurationMode::Off);
}

#[test]
fn test_curation_env_override_mode() {
    let _lock = env_lock();
    let mut config = Config::default();
    std::env::set_var("NORA_CURATION_MODE", "enforce");
    config.apply_env_overrides().unwrap();
    assert_eq!(config.curation.mode, CurationMode::Enforce);
    std::env::remove_var("NORA_CURATION_MODE");
}

#[test]
fn test_curation_env_override_on_failure() {
    let _lock = env_lock();
    let mut config = Config::default();
    std::env::set_var("NORA_CURATION_ON_FAILURE", "open");
    config.apply_env_overrides().unwrap();
    assert_eq!(config.curation.on_failure, CurationOnFailure::Open);
    std::env::remove_var("NORA_CURATION_ON_FAILURE");
}

#[test]
fn test_curation_on_failure_open_emits_error() {
    let _lock = env_lock();
    let mut config = Config::default();
    config.curation.on_failure = CurationOnFailure::Open;
    let (_warnings, errors) = config.validate_with_config_path(None);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("on_failure=\"open\" is not implemented")),
        "expected hard error for on_failure=open"
    );
}

#[test]
fn test_curation_env_override_paths() {
    let _lock = env_lock();
    let mut config = Config::default();
    std::env::set_var("NORA_CURATION_ALLOWLIST_PATH", "/etc/nora/allow.json");
    std::env::set_var("NORA_CURATION_BLOCKLIST_PATH", "/etc/nora/block.json");
    config.apply_env_overrides().unwrap();
    assert_eq!(
        config.curation.allowlist_path,
        Some("/etc/nora/allow.json".to_string())
    );
    assert_eq!(
        config.curation.blocklist_path,
        Some("/etc/nora/block.json".to_string())
    );
    std::env::remove_var("NORA_CURATION_ALLOWLIST_PATH");
    std::env::remove_var("NORA_CURATION_BLOCKLIST_PATH");
}

#[test]
fn test_curation_env_override_bypass_token() {
    let _lock = env_lock();
    let mut config = Config::default();
    std::env::set_var("NORA_CURATION_BYPASS_TOKEN", "secret-bypass");
    config.apply_env_overrides().unwrap();
    assert_eq!(
        crate::secrets::expose_opt(&config.curation.bypass_token),
        Some("secret-bypass")
    );
    std::env::remove_var("NORA_CURATION_BYPASS_TOKEN");
}

#[test]
fn test_curation_env_override_require_integrity() {
    let _lock = env_lock();
    let mut config = Config::default();
    std::env::set_var("NORA_CURATION_REQUIRE_INTEGRITY", "true");
    config.apply_env_overrides().unwrap();
    assert!(config.curation.require_integrity);
    std::env::remove_var("NORA_CURATION_REQUIRE_INTEGRITY");
}

#[test]
fn test_curation_env_override_quarantine() {
    let _lock = env_lock();
    let mut config = Config::default();
    std::env::set_var("NORA_CURATION_QUARANTINE", "observe");
    config.apply_env_overrides().unwrap();
    assert_eq!(config.curation.quarantine, Some(QuarantineMode::Observe));
    std::env::remove_var("NORA_CURATION_QUARANTINE");
}

#[test]
fn test_curation_env_override_quarantine_ttl() {
    let _lock = env_lock();
    let mut config = Config::default();
    std::env::set_var("NORA_CURATION_QUARANTINE_TTL", "14d");
    config.apply_env_overrides().unwrap();
    assert_eq!(config.curation.quarantine_ttl, Some("14d".to_string()));
    std::env::remove_var("NORA_CURATION_QUARANTINE_TTL");
}

#[test]
fn test_curation_env_override_per_registry_quarantine() {
    let _lock = env_lock();
    let mut config = Config::default();
    std::env::set_var("NORA_CURATION_DOCKER_QUARANTINE", "enforce");
    std::env::set_var("NORA_CURATION_DOCKER_QUARANTINE_TTL", "7d");
    config.apply_env_overrides().unwrap();
    assert_eq!(
        config.curation.docker.quarantine,
        Some(QuarantineMode::Enforce)
    );
    assert_eq!(
        config.curation.docker.quarantine_ttl,
        Some("7d".to_string())
    );
    // Global should remain None
    assert_eq!(config.curation.quarantine, None);
    std::env::remove_var("NORA_CURATION_DOCKER_QUARANTINE");
    std::env::remove_var("NORA_CURATION_DOCKER_QUARANTINE_TTL");
}

#[test]
fn test_quarantine_toml_rejects_typo() {
    let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"

            [curation]
            quarantine = "eforce"
        "#;
    let result: Result<Config, _> = toml::from_str(toml);
    assert!(result.is_err(), "typo 'eforce' should be rejected by serde");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown variant"),
        "error should mention unknown variant: {err}"
    );
}

#[test]
fn test_curation_mode_env_rejects_typo() {
    let _lock = env_lock();
    let mut config = Config::default();
    std::env::set_var("NORA_CURATION_MODE", "enforec");
    let result = config.apply_env_overrides();
    assert!(result.is_err(), "typo 'enforec' should be rejected");
    let err = result.unwrap_err();
    assert!(
        err.contains("NORA_CURATION_MODE"),
        "error should name the env var: {err}"
    );
    std::env::remove_var("NORA_CURATION_MODE");
}

#[test]
fn test_quarantine_env_rejects_typo() {
    let _lock = env_lock();
    let mut config = Config::default();
    std::env::set_var("NORA_CURATION_QUARANTINE", "enfocre");
    let result = config.apply_env_overrides();
    assert!(result.is_err(), "typo 'enfocre' should be rejected");
    std::env::remove_var("NORA_CURATION_QUARANTINE");
}

#[test]
fn test_curation_mode_fromstr() {
    assert_eq!("off".parse::<CurationMode>().unwrap(), CurationMode::Off);
    assert_eq!(
        "audit".parse::<CurationMode>().unwrap(),
        CurationMode::Audit
    );
    assert_eq!(
        "enforce".parse::<CurationMode>().unwrap(),
        CurationMode::Enforce
    );
    assert_eq!(
        "ENFORCE".parse::<CurationMode>().unwrap(),
        CurationMode::Enforce
    );
    assert!("typo".parse::<CurationMode>().is_err());
    assert!("".parse::<CurationMode>().is_err());
}

#[test]
fn test_validate_curation_enforce_no_controls() {
    let _lock = env_lock();
    // Enforce with no control of any kind enforces nothing → error (#740).
    let mut config = Config::default();
    config.curation.mode = CurationMode::Enforce;
    config.curation.allowlist_path = None;
    let (_, errors) = config.validate_with_config_path(None);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("no active control is configured")),
        "enforce with no controls should be an error"
    );
}

#[test]
fn test_validate_curation_enforce_blocklist_only_ok() {
    let _lock = env_lock();
    // #740: enforce must NOT require an allowlist — a blocklist alone is a valid
    // control. A deny-list-only (or min-age-only / quarantine-only) policy is legit.
    let mut config = Config::default();
    config.curation.mode = CurationMode::Enforce;
    config.curation.allowlist_path = None;
    config.curation.blocklist_path = Some("/etc/nora/blocklist.json".to_string());
    let (_, errors) = config.validate_with_config_path(None);
    assert!(
        !errors
            .iter()
            .any(|e| e.contains("no active control is configured")),
        "a blocklist alone should satisfy enforce — no allowlist required"
    );
}

#[test]
fn test_validate_minage_proxy_without_date_source_or_quarantine_rejected() {
    let _lock = env_lock();
    // min_release_age on an enabled proxy registry with neither
    // trust_upstream_dates nor an active quarantine = no age control would be
    // active => rejected (curation-minage-real-age-defer, #741).
    let mut config = Config::default();
    config.npm.enabled = true;
    config.npm.proxy = Some("https://registry.npmjs.org".to_string());
    config.curation.min_release_age = Some("7d".to_string());
    config.server.trust_upstream_dates = false;
    config.curation.quarantine = None;
    let (_, errors) = config.validate_with_config_path(None);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("no age control would be active")),
        "min-age on a proxy with neither trust nor quarantine must be rejected"
    );
}

#[test]
fn test_validate_minage_proxy_with_quarantine_ok() {
    let _lock = env_lock();
    // Escape hatch 1: an active quarantine is the unspoofable age control.
    let mut config = Config::default();
    config.npm.enabled = true;
    config.npm.proxy = Some("https://registry.npmjs.org".to_string());
    config.curation.min_release_age = Some("7d".to_string());
    config.server.trust_upstream_dates = false;
    config.curation.quarantine = Some(crate::digest_quarantine::QuarantineMode::Enforce);
    let (_, errors) = config.validate_with_config_path(None);
    assert!(
        !errors
            .iter()
            .any(|e| e.contains("no age control would be active")),
        "an active quarantine should satisfy the age-control requirement"
    );
}

#[test]
fn test_validate_minage_proxy_trust_alone_still_rejected() {
    let _lock = env_lock();
    // trust_upstream_dates is NOT a sufficient substitute for the quarantine: it
    // yields a real date only where a registry caches one (npm); for pypi/cargo/
    // nuget/gems/… publish_date stays None and min-age silently does nothing, so
    // min-age on a proxy still requires an active quarantine. (#741)
    let mut config = Config::default();
    config.npm.enabled = true;
    config.npm.proxy = Some("https://registry.npmjs.org".to_string());
    config.curation.min_release_age = Some("7d".to_string());
    config.server.trust_upstream_dates = true;
    config.curation.quarantine = None;
    let (_, errors) = config.validate_with_config_path(None);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("no age control would be active")),
        "trust alone (no quarantine) must still be rejected — trust is not a substitute"
    );
}

#[test]
fn test_is_enabled_proxy_counts_docker_and_excludes_raw() {
    // #765: docker was dropped from the any_enabled_proxy chain. The exhaustive
    // helper must count docker (enabled + has upstream) and never count raw.
    let mut config = Config::default();
    // Config::default() already carries the registry-1.docker.io upstream.
    assert!(
        config.is_enabled_proxy(RegistryType::Docker),
        "enabled docker with an upstream is a proxy"
    );
    config.docker.upstreams = vec![];
    assert!(
        !config.is_enabled_proxy(RegistryType::Docker),
        "docker without upstreams is not a proxy"
    );
    assert!(
        !config.is_enabled_proxy(RegistryType::Raw),
        "raw has no upstream and is never a proxy"
    );
}

#[test]
fn test_quarantine_mode_for_docker_precedence_and_raw_off() {
    // Per-registry override wins over global (.or precedence, matching
    // docker.rs::resolve_quarantine); raw is always Off (no enforcement path).
    let mut config = Config::default();
    config.curation.quarantine = Some(QuarantineMode::Off);
    config.curation.docker.quarantine = Some(QuarantineMode::Enforce);
    assert_eq!(
        config.quarantine_mode_for(RegistryType::Docker),
        QuarantineMode::Enforce,
        "docker override Enforce beats global Off"
    );
    assert_eq!(
        config.quarantine_mode_for(RegistryType::Npm),
        QuarantineMode::Off,
        "npm with no override inherits global Off"
    );
    // raw stays Off even under a global Enforce — counting it would be a phantom control.
    config.curation.quarantine = Some(QuarantineMode::Enforce);
    assert_eq!(
        config.quarantine_mode_for(RegistryType::Raw),
        QuarantineMode::Off,
        "raw must never report an active quarantine"
    );
}

#[test]
fn test_any_quarantine_active_counts_docker_only_override() {
    // #765 core: a docker-only [curation.docker] quarantine, no global, must count.
    // The main.rs DigestStore gate depends on this — otherwise it builds an
    // empty() (non-durable) store and serves young digests early after restart.
    let mut config = Config::default();
    config.curation.quarantine = None;
    config.curation.docker.quarantine = Some(QuarantineMode::Enforce);
    assert!(
        config.any_quarantine_active(),
        "docker-only quarantine override must count as active"
    );
}

#[test]
fn test_any_quarantine_active_false_when_global_fully_overridden_off() {
    // A global Enforce with EVERY registry overridden to Off enforces nothing,
    // so quarantine is not active. (The old flat-OR counted the global term and
    // wrongly reported active — which would suppress the #741 min-age guard.)
    let mut config = Config::default();
    config.curation.quarantine = Some(QuarantineMode::Enforce);
    for o in [
        &mut config.curation.docker,
        &mut config.curation.maven,
        &mut config.curation.npm,
        &mut config.curation.cargo,
        &mut config.curation.pypi,
        &mut config.curation.go,
        &mut config.curation.gems,
        &mut config.curation.terraform,
        &mut config.curation.ansible,
        &mut config.curation.nuget,
        &mut config.curation.pub_dart,
        &mut config.curation.conan,
        &mut config.curation.rpm,
        &mut config.curation.deb,
        &mut config.curation.cpan,
        &mut config.curation.helm,
        &mut config.curation.apk,
        &mut config.curation.github,
        &mut config.curation.hashicorp,
    ] {
        o.quarantine = Some(QuarantineMode::Off);
    }
    assert!(
        !config.any_quarantine_active(),
        "global Enforce fully overridden to Off everywhere enforces nothing"
    );
}

#[test]
fn test_validate_minage_docker_only_quarantine_ok() {
    let _lock = env_lock();
    // #765: a docker-only quarantine must SATISFY the #741 min-age guard. The
    // old quarantine_active chain omitted docker and falsely rejected this config.
    let mut config = Config::default();
    config.curation.min_release_age = Some("7d".to_string());
    config.server.trust_upstream_dates = false;
    config.curation.quarantine = None;
    config.curation.docker.quarantine = Some(QuarantineMode::Enforce);
    let (_, errors) = config.validate_with_config_path(None);
    assert!(
        !errors
            .iter()
            .any(|e| e.contains("no age control would be active")),
        "a docker-only quarantine should satisfy the age-control requirement (#765)"
    );
}

/// A config with npm hosted only (no upstream) and nothing else that curates.
fn npm_hosted_only() -> Config {
    let mut config = Config::default();
    config.npm.enabled = true;
    config.npm.proxy = None;
    config.npm.proxies.clear();
    config.server.trust_upstream_dates = false;
    config.curation.quarantine = None;
    config
}

#[test]
fn a_per_registry_min_release_age_is_an_active_control_in_enforce() {
    let _lock = env_lock();
    // #1098: `[curation.npm] min_release_age` alone is a control enforce can apply.
    let mut config = npm_hosted_only();
    config.curation.mode = CurationMode::Enforce;
    config.curation.npm.min_release_age = Some("3d".to_string());
    let (_, errors) = config.validate_with_config_path(None);
    assert!(
        !errors
            .iter()
            .any(|e| e.contains("no active control is configured")),
        "{errors:?}"
    );
}

#[test]
fn a_per_registry_min_release_age_on_a_proxy_needs_a_quarantine() {
    let _lock = env_lock();
    // #1098: the #741 rule covers a per-registry value too, and names it.
    let mut config = npm_hosted_only();
    config.npm.proxy = Some("https://registry.npmjs.org".to_string());
    config.curation.npm.min_release_age = Some("3d".to_string());
    let (_, errors) = config.validate_with_config_path(None);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("curation.npm.min_release_age")
                && e.contains("no age control would be active")),
        "{errors:?}"
    );
    // A quarantine of npm satisfies it — npm's own or the global one. One on
    // another registry does not: it holds none of npm's downloads.
    for (npm, global, docker, satisfied) in [
        (Some(QuarantineMode::Observe), None, None, true),
        (None, Some(QuarantineMode::Enforce), None, true),
        (None, None, Some(QuarantineMode::Enforce), false),
        (
            Some(QuarantineMode::Off),
            Some(QuarantineMode::Enforce),
            None,
            false,
        ),
    ] {
        config.curation.npm.quarantine = npm.clone();
        config.curation.quarantine = global.clone();
        config.curation.docker.quarantine = docker.clone();
        let (_, errors) = config.validate_with_config_path(None);
        let refused = errors.iter().any(|e| {
            e.contains("curation.npm.min_release_age")
                && e.contains("no age control would be active")
        });
        assert_eq!(
            refused, !satisfied,
            "npm {npm:?}, global {global:?}, docker {docker:?}: {errors:?}"
        );
    }
}

#[test]
fn a_per_registry_min_release_age_on_a_hosted_registry_needs_no_quarantine() {
    let _lock = env_lock();
    // Hosted packages are dated by NORA's own clock: nothing for a quarantine to back.
    let mut config = npm_hosted_only();
    config.curation.npm.min_release_age = Some("3d".to_string());
    let (_, errors) = config.validate_with_config_path(None);
    assert!(
        !errors.iter().any(|e| e.contains("min_release_age")),
        "{errors:?}"
    );
}

#[test]
fn a_min_release_age_for_rpm_is_refused() {
    let _lock = env_lock();
    // rpm downloads are not checked by name or release date: the value could
    // never apply, so startup says so instead of accepting it (#1098). (maestra:
    // deb is dated by its filtered proxy, registry/deb_proxy.rs.)
    {
        let registry = "rpm";
        let mut config = npm_hosted_only();
        config.curation.quarantine = Some(QuarantineMode::Enforce);
        config.curation.rpm.min_release_age = Some("3d".to_string());
        let (_, errors) = config.validate_with_config_path(None);
        let key = format!("curation.{registry}.min_release_age");
        assert!(
            errors.iter().any(|e| e.contains(&key)
                && e.contains("not checked by name or release date")
                && !e.contains("no age control would be active")),
            "{registry}: {errors:?}"
        );
    }
}

/// The registries with a `[curation.<registry>]` section: all but Raw and Hugging Face.
fn registries_with_a_curation_section() -> Vec<RegistryType> {
    RegistryType::all()
        .iter()
        .copied()
        .filter(|rt| !matches!(rt, RegistryType::Raw | RegistryType::HuggingFace))
        .collect()
}

/// #1098: the verdict on a registry's own min_release_age, row by row, from facts
/// alone (value set, release-date check, enabled, proxy, quarantine of that registry).
#[test]
fn registry_min_age_verdict_is_decided_by_the_facts_alone() {
    use RegistryMinAgeVerdict::{Applies, CannotApply, NeedsQuarantine, NotSet, Unused};
    use ReleaseDateCheck::{Dated, NoDate, NoNameOrDate};
    let facts = |value_set, dated, enabled, proxy, quarantined| RegistryMinAgeFacts {
        value_set,
        dated,
        enabled,
        proxy,
        quarantined,
    };
    // (dated, enabled, proxy, quarantined) -> verdict, with the value set.
    let rows = [
        (Dated, true, true, true, Applies),
        (Dated, true, true, false, NeedsQuarantine),
        (Dated, true, false, true, Applies),
        (Dated, true, false, false, Applies),
        (Dated, false, true, true, Unused),
        (Dated, false, true, false, Unused),
        (Dated, false, false, true, Unused),
        (Dated, false, false, false, Unused),
        (NoDate, true, true, true, CannotApply),
        (NoDate, true, true, false, CannotApply),
        (NoDate, true, false, true, CannotApply),
        (NoDate, true, false, false, CannotApply),
        (NoDate, false, true, true, CannotApply),
        (NoDate, false, true, false, CannotApply),
        (NoDate, false, false, true, CannotApply),
        (NoDate, false, false, false, CannotApply),
        (NoNameOrDate, true, true, true, CannotApply),
        (NoNameOrDate, true, true, false, CannotApply),
        (NoNameOrDate, true, false, true, CannotApply),
        (NoNameOrDate, true, false, false, CannotApply),
        (NoNameOrDate, false, true, true, CannotApply),
        (NoNameOrDate, false, true, false, CannotApply),
        (NoNameOrDate, false, false, true, CannotApply),
        (NoNameOrDate, false, false, false, CannotApply),
    ];
    for (dated, enabled, proxy, quarantined, verdict) in rows {
        let f = facts(true, dated, enabled, proxy, quarantined);
        assert_eq!(registry_min_age_verdict(f), verdict, "{f:?}");
        // Without a value there is nothing to decide.
        let f = facts(false, dated, enabled, proxy, quarantined);
        assert_eq!(registry_min_age_verdict(f), NotSet, "{f:?}");
    }
}

/// Whether each registry's downloads reach curation with a release date, as the
/// handlers call it: rpm and deb are not checked by name or date, cpan passes no date.
#[test]
fn the_release_date_check_of_every_registry() {
    use ReleaseDateCheck::{Dated, NoDate, NoNameOrDate};
    let expected = [
        (RegistryType::Docker, Dated),
        (RegistryType::Maven, Dated),
        (RegistryType::Npm, Dated),
        (RegistryType::Cargo, Dated),
        (RegistryType::PyPI, Dated),
        (RegistryType::Go, Dated),
        (RegistryType::Raw, Dated),
        (RegistryType::Gems, Dated),
        (RegistryType::Terraform, Dated),
        (RegistryType::Ansible, Dated),
        (RegistryType::Nuget, Dated),
        (RegistryType::PubDart, Dated),
        (RegistryType::Conan, Dated),
        (RegistryType::Rpm, NoNameOrDate),
        (RegistryType::Deb, Dated),
        (RegistryType::Cpan, NoDate),
        (RegistryType::HuggingFace, NoDate),
        (RegistryType::Helm, Dated),
        (RegistryType::Apk, Dated),
        (RegistryType::Github, Dated),
        (RegistryType::Hashicorp, Dated),
    ];
    assert_eq!(expected.len(), RegistryType::all().len());
    for (rt, check) in expected {
        assert_eq!(release_date_check(rt), check, "{rt}");
    }
}

/// Each registry made an enabled proxy in each form its config accepts, written out
/// per registry: the expectation is this table, not `is_enabled_proxy`.
fn proxy_forms() -> Vec<(RegistryType, &'static str, fn(&mut Config))> {
    fn none(_: &mut Config) {}
    vec![
        (RegistryType::Docker, "[docker]\nenabled = true\n[[docker.upstreams]]\nurl = \"https://registry-1.docker.io\"\n", none),
        (RegistryType::Maven, "[maven]\nenabled = true\nproxies = [\"https://repo1.maven.org/maven2\"]\n", none),
        (RegistryType::Npm, "[npm]\nenabled = true\nproxy = \"https://registry.npmjs.org\"\n", |c| c.npm.proxies.clear()),
        (RegistryType::Npm, "[npm]\nenabled = true\nproxies = [\"https://registry.npmjs.org\"]\n", |c| c.npm.proxy = None),
        (RegistryType::Cargo, "[cargo]\nenabled = true\nproxy = \"https://index.crates.io\"\n", none),
        (RegistryType::PyPI, "[pypi]\nenabled = true\nproxy = \"https://pypi.org/simple/\"\n", |c| c.pypi.proxies.clear()),
        (RegistryType::PyPI, "[pypi]\nenabled = true\nproxies = [\"https://pypi.org/simple/\"]\n", |c| c.pypi.proxy = None),
        (RegistryType::Go, "[go]\nenabled = true\nproxy = \"https://proxy.golang.org\"\n", none),
        (RegistryType::Gems, "[gems]\nenabled = true\nproxy = \"https://rubygems.org\"\n", none),
        (RegistryType::Terraform, "[terraform]\nenabled = true\nproxy = \"https://registry.terraform.io\"\n", none),
        (RegistryType::Ansible, "[ansible]\nenabled = true\nproxy = \"https://galaxy.ansible.com\"\n", none),
        (RegistryType::Nuget, "[nuget]\nenabled = true\nproxy = \"https://api.nuget.org/v3/index.json\"\n", none),
        (RegistryType::PubDart, "[pub_dart]\nenabled = true\nproxy = \"https://pub.dev\"\n", none),
        (RegistryType::Conan, "[conan]\nenabled = true\nproxy = \"https://center2.conan.io\"\n", none),
        (RegistryType::Rpm, "[rpm]\nenabled = true\n[rpm.proxies]\nfedora = \"https://repo.example.com/fedora\"\n", none),
        (RegistryType::Deb, "[deb]\nenabled = true\n[deb.proxies]\ndebian = \"https://deb.debian.org/debian\"\n", none),
        (RegistryType::Cpan, "[cpan]\nenabled = true\nproxy = \"https://www.cpan.org\"\n", none),
        (RegistryType::Helm, "[helm]\nenabled = true\n[helm.proxies]\njetstack = \"https://charts.jetstack.io\"\n", none),
        (RegistryType::Apk, "[apk]\nenabled = true\n[apk.proxies]\nalpine = \"https://dl-cdn.alpinelinux.org/alpine\"\n", none),
        (RegistryType::Github, "[github]\nenabled = true\n", none),
        (RegistryType::Hashicorp, "[hashicorp]\nenabled = true\n", none),
    ]
}

/// Each registry enabled with no upstream at all, written out per registry.
fn make_hosted(rt: RegistryType, c: &mut Config) {
    match rt {
        RegistryType::Docker => (c.docker.enabled, c.docker.upstreams) = (true, vec![]),
        RegistryType::Maven => (c.maven.enabled, c.maven.proxies) = (true, vec![]),
        RegistryType::Npm => (c.npm.enabled, c.npm.proxy, c.npm.proxies) = (true, None, vec![]),
        RegistryType::Cargo => (c.cargo.enabled, c.cargo.proxy) = (true, None),
        RegistryType::PyPI => (c.pypi.enabled, c.pypi.proxy, c.pypi.proxies) = (true, None, vec![]),
        RegistryType::Go => (c.go.enabled, c.go.proxy) = (true, None),
        RegistryType::Gems => (c.gems.enabled, c.gems.proxy) = (true, None),
        RegistryType::Terraform => (c.terraform.enabled, c.terraform.proxy) = (true, None),
        RegistryType::Ansible => (c.ansible.enabled, c.ansible.proxy) = (true, None),
        RegistryType::Nuget => (c.nuget.enabled, c.nuget.proxy) = (true, None),
        RegistryType::PubDart => (c.pub_dart.enabled, c.pub_dart.proxy) = (true, None),
        RegistryType::Conan => (c.conan.enabled, c.conan.proxy) = (true, None),
        RegistryType::Rpm => (c.rpm.enabled, c.rpm.proxies) = (true, Default::default()),
        RegistryType::Deb => (c.deb.enabled, c.deb.proxies) = (true, Default::default()),
        RegistryType::Cpan => (c.cpan.enabled, c.cpan.proxy) = (true, None),
        RegistryType::Raw => c.raw.enabled = true,
        RegistryType::HuggingFace => (c.hf.enabled, c.hf.proxy) = (true, None),
        RegistryType::Helm => (c.helm.enabled, c.helm.proxies) = (true, Default::default()),
        RegistryType::Apk => (c.apk.enabled, c.apk.proxies) = (true, Default::default()),
        RegistryType::Github => (c.github.enabled, c.github.download_url) = (true, String::new()),
        RegistryType::Hashicorp => {
            (c.hashicorp.enabled, c.hashicorp.download_url) = (true, String::new())
        }
    }
}

/// Each registry disabled, written out per registry.
fn make_disabled(rt: RegistryType, c: &mut Config) {
    match rt {
        RegistryType::Docker => c.docker.enabled = false,
        RegistryType::Maven => c.maven.enabled = false,
        RegistryType::Npm => c.npm.enabled = false,
        RegistryType::Cargo => c.cargo.enabled = false,
        RegistryType::PyPI => c.pypi.enabled = false,
        RegistryType::Go => c.go.enabled = false,
        RegistryType::Gems => c.gems.enabled = false,
        RegistryType::Terraform => c.terraform.enabled = false,
        RegistryType::Ansible => c.ansible.enabled = false,
        RegistryType::Nuget => c.nuget.enabled = false,
        RegistryType::PubDart => c.pub_dart.enabled = false,
        RegistryType::Conan => c.conan.enabled = false,
        RegistryType::Rpm => c.rpm.enabled = false,
        RegistryType::Deb => c.deb.enabled = false,
        RegistryType::Cpan => c.cpan.enabled = false,
        RegistryType::Raw => c.raw.enabled = false,
        RegistryType::HuggingFace => c.hf.enabled = false,
        RegistryType::Helm => c.helm.enabled = false,
        RegistryType::Apk => c.apk.enabled = false,
        RegistryType::Github => c.github.enabled = false,
        RegistryType::Hashicorp => c.hashicorp.enabled = false,
    }
}

/// A config from `toml`, then `fixup`.
fn config_from(toml: &str, fixup: fn(&mut Config)) -> Config {
    let (mut config, unknown) = parse_config(toml).unwrap_or_else(|e| panic!("{e}\n{toml}"));
    assert!(unknown.is_empty(), "{toml}: {unknown:?}");
    fixup(&mut config);
    config
}

#[test]
fn every_proxy_form_of_every_registry_is_an_enabled_proxy() {
    let _lock = env_lock();
    let forms = proxy_forms();
    // Every registry with a section has at least one form here.
    for rt in registries_with_a_curation_section() {
        assert!(
            forms.iter().any(|(r, _, _)| *r == rt),
            "{rt} has no proxy form"
        );
    }
    for (rt, toml, fixup) in forms {
        let mut config = config_from(toml, fixup);
        assert!(config.is_enabled_proxy(rt), "{rt}: {toml}");
        let facts = config.registry_min_age_facts(rt);
        assert!(facts.enabled && facts.proxy, "{rt}: {facts:?}");
        make_hosted(rt, &mut config);
        assert!(!config.is_enabled_proxy(rt), "{rt} hosted");
        assert!(config.registry_min_age_facts(rt).enabled, "{rt} hosted");
        make_disabled(rt, &mut config);
        let facts = config.registry_min_age_facts(rt);
        assert!(!facts.enabled && !facts.proxy, "{rt} disabled: {facts:?}");
    }
}

/// Startup, end to end, for every registry with a section in every proxy form: the
/// verdict the facts call for, under the message that names its key. The
/// expectation comes from the scenario and the release-date table above.
#[test]
fn every_per_registry_min_release_age_gets_its_verdict_at_startup() {
    let _lock = env_lock();
    #[derive(Clone, Copy, Debug)]
    enum Setup {
        ProxyNoQuarantine,
        ProxyNoQuarantineTrustedDates,
        ProxyOwnQuarantine,
        ProxyGlobalQuarantine,
        ProxyOwnOffGlobalOn,
        ProxyOtherRegistryQuarantine,
        Hosted,
        Disabled,
    }
    let mut seen = std::collections::BTreeSet::new();
    for (rt, toml, fixup) in proxy_forms() {
        let dated = !matches!(rt, RegistryType::Rpm | RegistryType::Cpan);
        let other = if rt == RegistryType::Docker {
            "npm"
        } else {
            "docker"
        };
        for setup in [
            Setup::ProxyNoQuarantine,
            Setup::ProxyNoQuarantineTrustedDates,
            Setup::ProxyOwnQuarantine,
            Setup::ProxyGlobalQuarantine,
            Setup::ProxyOwnOffGlobalOn,
            Setup::ProxyOtherRegistryQuarantine,
            Setup::Hosted,
            Setup::Disabled,
        ] {
            for mode in ["off", "enforce"] {
                let mut curation = format!("[curation]\nmode = \"{mode}\"\n");
                let mut own = format!("[curation.{rt}]\nmin_release_age = \"3d\"\n");
                match setup {
                    Setup::ProxyOwnQuarantine => own.push_str("quarantine = \"observe\"\n"),
                    Setup::ProxyGlobalQuarantine => curation.push_str("quarantine = \"enforce\"\n"),
                    Setup::ProxyOwnOffGlobalOn => {
                        curation.push_str("quarantine = \"enforce\"\n");
                        own.push_str("quarantine = \"off\"\n");
                    }
                    Setup::ProxyOtherRegistryQuarantine => {
                        own.push_str(&format!("[curation.{other}]\nquarantine = \"enforce\"\n"))
                    }
                    _ => {}
                }
                let content = format!("{toml}{curation}{own}");
                let mut config = config_from(&content, fixup);
                match setup {
                    Setup::ProxyNoQuarantineTrustedDates => {
                        config.server.trust_upstream_dates = true
                    }
                    Setup::Hosted => make_hosted(rt, &mut config),
                    Setup::Disabled => make_disabled(rt, &mut config),
                    _ => {}
                }
                let key = format!("curation.{rt}.min_release_age=\"3d\"");
                let (warnings, errors) = config.validate_with_config_path(None);
                let named = |list: &[String], what: &str| {
                    list.iter().any(|e| e.contains(&key) && e.contains(what))
                };
                let cannot = named(&errors, "cannot apply");
                let needs = named(&errors, "no age control would be active");
                let unused = named(&warnings, "is not enabled");
                let no_control = errors
                    .iter()
                    .any(|e| e.contains("no active control is configured"));
                let (e_cannot, e_needs, e_unused, applies) = if !dated {
                    (true, false, false, false)
                } else {
                    match setup {
                        Setup::Disabled => (false, false, true, false),
                        Setup::ProxyNoQuarantine
                        | Setup::ProxyNoQuarantineTrustedDates
                        | Setup::ProxyOwnOffGlobalOn
                        | Setup::ProxyOtherRegistryQuarantine => (false, true, false, false),
                        Setup::ProxyOwnQuarantine
                        | Setup::ProxyGlobalQuarantine
                        | Setup::Hosted => (false, false, false, true),
                    }
                };
                let case = format!(
                    "{rt} {setup:?} {mode}: {content}\nwarnings {warnings:?}\nerrors {errors:?}"
                );
                assert_eq!(
                    (cannot, needs, unused),
                    (e_cannot, e_needs, e_unused),
                    "{case}"
                );
                // In enforce, the value is the only control unless a quarantine is
                // configured: it counts exactly when it applies.
                let quarantine_configured = matches!(
                    setup,
                    Setup::ProxyOwnQuarantine
                        | Setup::ProxyGlobalQuarantine
                        | Setup::ProxyOwnOffGlobalOn
                        | Setup::ProxyOtherRegistryQuarantine
                );
                if mode == "enforce" && !quarantine_configured {
                    assert_eq!(no_control, !applies, "{case}");
                }
                seen.insert(rt.to_string());
            }
        }
    }
    assert_eq!(seen.len(), registries_with_a_curation_section().len());
}

/// How a test enables (or disables) one registry.
#[derive(Clone, Copy, Debug)]
enum EnableWay {
    /// `NORA_REGISTRIES_ENABLE`.
    Env,
    /// `[registries] enable` in the file.
    Section,
    /// The registry's own `enabled` flag.
    Flag,
}

/// `Config::load_from` a file holding `toml`, with `NORA_REGISTRIES_ENABLE` set to
/// `env` for the call: the config, or the errors that refused it.
fn load_toml(toml: &str, env: Option<&str>) -> Result<Config, Vec<String>> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, toml).unwrap();
    match env {
        Some(v) => std::env::set_var("NORA_REGISTRIES_ENABLE", v),
        None => std::env::remove_var("NORA_REGISTRIES_ENABLE"),
    }
    let loaded = Config::load_from(
        Some(path.to_string_lossy().into_owned()),
        NO_FALLBACK,
        false,
    );
    std::env::remove_var("NORA_REGISTRIES_ENABLE");
    match loaded {
        Ok((config, _)) => Ok(config),
        Err(ConfigLoadError::Invalid(errors)) => Err(errors),
        Err(e) => panic!("{e}\n{toml}"),
    }
}

/// The verdict on a registry's own value does not depend on how the registry is
/// enabled: NORA_REGISTRIES_ENABLE, [registries].enable and its own flag give the same
/// answer, for the registry on and off (the first two used to be judged by the flags'
/// defaults, before the enable-set was applied).
#[test]
fn a_per_registry_min_release_age_is_judged_by_the_registries_the_server_mounts() {
    let _lock = env_lock();
    let mut seen = 0;
    for (rt, form, _) in proxy_forms() {
        if !matches!(release_date_check(rt), ReleaseDateCheck::Dated) {
            continue;
        }
        // The upstream stays configured; only the way it is enabled changes.
        let section: String = form
            .lines()
            .filter(|l| !l.starts_with("enabled = "))
            .map(|l| format!("{l}\n"))
            .collect();
        let value = format!("[curation.{rt}]\nmin_release_age = \"3d\"\n");
        let key = format!("curation.{rt}.min_release_age=\"3d\"");
        let other = if rt == RegistryType::Raw {
            "docker"
        } else {
            "raw"
        };
        for way in [EnableWay::Env, EnableWay::Section, EnableWay::Flag] {
            for on in [true, false] {
                let flag = |v: bool| section.replacen("\n", &format!("\nenabled = {v}\n"), 1);
                let (toml, env) = match (way, on) {
                    (EnableWay::Env, true) => {
                        (format!("{section}{value}"), Some(rt.as_str().to_string()))
                    }
                    (EnableWay::Env, false) => {
                        (format!("{section}{value}"), Some(other.to_string()))
                    }
                    (EnableWay::Section, true) => (
                        format!("[registries]\nenable = [\"{rt}\"]\n{section}{value}"),
                        None,
                    ),
                    (EnableWay::Section, false) => (
                        format!("[registries]\nenable = [\"{other}\"]\n{section}{value}"),
                        None,
                    ),
                    (EnableWay::Flag, true) => (format!("{}{value}", flag(true)), None),
                    (EnableWay::Flag, false) => (format!("{}{value}", flag(false)), None),
                };
                let case = format!("{rt} {way:?} on={on}: {toml} env={env:?}");
                match load_toml(&toml, env.as_deref()) {
                    Err(errors) => {
                        assert!(on, "{case}: refused although {rt} is off: {errors:?}");
                        assert!(
                            errors.iter().any(|e| e.contains(&key)
                                && e.contains("no age control would be active")),
                            "{case}: {errors:?}"
                        );
                    }
                    Ok(config) => {
                        assert!(
                            !on,
                            "{case}: started without a quarantine of an enabled proxy"
                        );
                        let (warnings, errors) = config.validate();
                        assert!(errors.is_empty(), "{case}: {errors:?}");
                        assert!(
                            warnings
                                .iter()
                                .any(|w| w.contains(&key) && w.contains("is not enabled")),
                            "{case}: {warnings:?}"
                        );
                    }
                }
                seen += 1;
            }
        }
    }
    assert!(seen >= 60, "{seen} cases");
}

/// A reload (SIGHUP) judges the same registries as the start.
#[test]
fn a_reload_judges_the_registries_the_server_mounts() {
    let _lock = env_lock();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    // docker is on by its flag's default and a proxy; the enable-set decides.
    std::fs::write(&path, "[curation.docker]\nmin_release_age = \"3d\"\n").unwrap();
    std::env::set_var("NORA_CONFIG_PATH", &path);
    std::env::set_var("NORA_REGISTRIES_ENABLE", "raw");
    let off = Config::try_load_from(Config::path_from_env());
    std::env::set_var("NORA_REGISTRIES_ENABLE", "docker");
    let on = Config::try_load_from(Config::path_from_env());
    std::env::remove_var("NORA_REGISTRIES_ENABLE");
    std::env::remove_var("NORA_CONFIG_PATH");
    assert!(off.is_ok(), "docker is not mounted: {:?}", off.err());
    let err = on.expect_err("docker is a mounted proxy without a quarantine");
    assert!(err.contains("curation.docker.min_release_age"), "{err}");
}

/// The Hugging Face rule and the global #741 rule judge the mounted registries too.
#[test]
fn the_global_min_release_age_rules_judge_the_registries_the_server_mounts() {
    let _lock = env_lock();
    let hf = "[hf]\nproxy = \"http://127.0.0.1:9\"\n[curation]\nmin_release_age = \"3d\"\nquarantine = \"enforce\"\n";
    for (toml, env) in [
        (hf.to_string(), Some("all,hf")),
        (
            format!("[registries]\nenable = [\"all\", \"hf\"]\n{hf}"),
            None,
        ),
        (hf.replacen("[hf]\n", "[hf]\nenabled = true\n", 1), None),
    ] {
        let errors = load_toml(&toml, env)
            .err()
            .unwrap_or_else(|| panic!("hf with a global min_release_age started: {toml} {env:?}"));
        assert!(
            errors
                .iter()
                .any(|e| e.contains("cannot hold the Hugging Face proxy")),
            "{errors:?}"
        );
    }
    // Control: hf off, the same global value starts.
    assert!(load_toml(hf, Some("all")).is_ok());
    // #741: every per-registry flag off in the file, NORA_REGISTRIES_ENABLE=all mounts
    // the proxies, so a global value without a quarantine is refused.
    let mut all_off = String::new();
    for rt in RegistryType::all() {
        let section = match rt {
            RegistryType::PubDart => "pub_dart".to_string(),
            _ => rt.as_str().to_string(),
        };
        all_off.push_str(&format!("[{section}]\nenabled = false\n"));
    }
    all_off.push_str("[curation]\nmin_release_age = \"3d\"\n");
    let errors = load_toml(&all_off, Some("all")).expect_err("the proxies are mounted");
    assert!(
        errors.iter().any(
            |e| e.starts_with("curation.min_release_age is set with an enabled proxy registry")
        ),
        "{errors:?}"
    );
    // And only raw mounted: no proxy is served, nothing to refuse.
    assert!(load_toml("[curation]\nmin_release_age = \"3d\"\n", Some("raw")).is_ok());
}

#[test]
fn a_min_release_age_for_rpm_is_refused_for_its_own_reason_without_a_quarantine() {
    let _lock = env_lock();
    // On an enabled rpm proxy with no quarantine, the refusal still gives the
    // reason the value can never apply, not the quarantine one.
    {
        let registry = "rpm";
        let content = format!(
            "[{registry}]\nenabled = true\n[{registry}.proxies]\nupstream = \"https://repo.example.com/{registry}\"\n[curation.{registry}]\nmin_release_age = \"3d\"\n"
        );
        let (config, unknown) = parse_config(&content).unwrap();
        assert!(unknown.is_empty(), "{content}: {unknown:?}");
        let rt = RegistryType::from_str_opt(registry).unwrap();
        assert!(config.is_enabled_proxy(rt), "{content}");
        let (_, errors) = config.validate_with_config_path(None);
        let key = format!("curation.{registry}.min_release_age");
        assert!(
            errors
                .iter()
                .any(|e| e.contains(&key) && e.contains("not checked by name or release date")),
            "{registry}: {errors:?}"
        );
        assert!(
            !errors
                .iter()
                .any(|e| e.contains(&key) && e.contains("no age control would be active")),
            "{registry}: {errors:?}"
        );
    }
}

#[test]
fn a_min_release_age_for_cpan_is_refused_its_downloads_carry_no_release_date() {
    let _lock = env_lock();
    // registry/cpan.rs asks curation with no publish date, so a cpan threshold is
    // never compared: refused like rpm, for its own reason, with or
    // without a quarantine, enabled or not (#1098).
    for quarantine in ["", "quarantine = \"enforce\"\n"] {
        for enabled in [true, false] {
            let content = format!(
                "[cpan]\nenabled = {enabled}\nproxy = \"https://www.cpan.org\"\n[curation.cpan]\nmin_release_age = \"3d\"\n{quarantine}"
            );
            let (config, unknown) = parse_config(&content).unwrap();
            assert!(unknown.is_empty(), "{content}: {unknown:?}");
            let (warnings, errors) = config.validate_with_config_path(None);
            let key = "curation.cpan.min_release_age=\"3d\" cannot apply";
            assert!(
                errors
                    .iter()
                    .any(|e| e.contains(key) && e.contains("carry no release date")),
                "{content}: {errors:?}"
            );
            assert!(
                !errors
                    .iter()
                    .chain(&warnings)
                    .any(|e| e.contains("curation.cpan.min_release_age")
                        && (e.contains("no age control would be active")
                            || e.contains("is not enabled"))),
                "{content}: {warnings:?} {errors:?}"
            );
        }
    }
}

/// The environment variable of each `[curation.<registry>]` section, as documented.
fn curation_env_name(rt: RegistryType) -> Option<&'static str> {
    match rt {
        RegistryType::Docker => Some("DOCKER"),
        RegistryType::Maven => Some("MAVEN"),
        RegistryType::Npm => Some("NPM"),
        RegistryType::Cargo => Some("CARGO"),
        RegistryType::PyPI => Some("PYPI"),
        RegistryType::Go => Some("GO"),
        RegistryType::Raw => None,
        RegistryType::Gems => Some("GEMS"),
        RegistryType::Terraform => Some("TERRAFORM"),
        RegistryType::Ansible => Some("ANSIBLE"),
        RegistryType::Nuget => Some("NUGET"),
        RegistryType::PubDart => Some("PUB"),
        RegistryType::Conan => Some("CONAN"),
        RegistryType::Rpm => Some("RPM"),
        RegistryType::Deb => Some("DEB"),
        RegistryType::Cpan => Some("CPAN"),
        RegistryType::HuggingFace => None,
        RegistryType::Helm => Some("HELM"),
        RegistryType::Apk => Some("APK"),
        RegistryType::Github => Some("GITHUB"),
        RegistryType::Hashicorp => Some("HASHICORP"),
    }
}

#[test]
fn every_per_registry_min_release_age_is_read_from_its_environment_variable() {
    let _lock = env_lock();
    for rt in registries_with_a_curation_section() {
        let var = format!(
            "NORA_CURATION_{}_MIN_RELEASE_AGE",
            curation_env_name(rt).unwrap()
        );
        let mut curation = CurationConfig::default();
        std::env::set_var(&var, "3d");
        let applied = curation.apply_env_overrides();
        std::env::remove_var(&var);
        applied.unwrap();
        // Its own section has it, and no other does.
        for &other in RegistryType::all() {
            let value = curation
                .registry_override(other)
                .and_then(|o| o.min_release_age.as_deref());
            assert_eq!(value, (other == rt).then_some("3d"), "{var}: {other}");
        }
    }
}

/// A request for `registry` published `publish_date`.
fn age_request(
    registry: RegistryType,
    publish_date: Option<i64>,
) -> crate::curation::FilterRequest {
    crate::curation::FilterRequest {
        registry,
        upstream: None,
        name: "pkg".to_string(),
        version: crate::curation::RequestVersion::Known("1.0.0".to_string()),
        integrity: None,
        bypass: false,
        publish_date,
    }
}

#[test]
fn every_per_registry_min_release_age_alone_holds_its_registry_and_names_it() {
    use crate::curation::{Decision, MinReleaseAgeFilter, ProxyFilter};
    let _lock = env_lock();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    for rt in registries_with_a_curation_section() {
        let config = curation_toml(&format!("curation.{rt}.min_release_age"), "3d", "off");
        let (filter, problems) = MinReleaseAgeFilter::from_config(&config.curation);
        assert!(problems.is_empty(), "{rt}: {problems:?}");
        let filter = filter.unwrap_or_else(|| panic!("{rt}: no filter"));
        // The log line and `curation explain` show it.
        assert_eq!(filter.summary(), format!("{rt}: 3d"));
        // A release an hour old is held in its registry and not filtered by age
        // anywhere else.
        for &other in RegistryType::all() {
            let decision = filter.evaluate(&age_request(other, Some(now - 3600)));
            if other == rt {
                assert!(
                    matches!(&decision, Decision::Block { rule, .. } if rule == "min-release-age"),
                    "{rt}: {decision:?}"
                );
            } else {
                assert_eq!(decision, Decision::Skip, "{rt} set, {other} asked");
            }
        }
        // Beside a global value, the registry's own wins in its registry, and the
        // global one holds the others: a release two hours old, 3d against 1h.
        let held =
            |d: &Decision| matches!(d, Decision::Block { rule, .. } if rule == "min-release-age");
        for (own, global) in [("3d", "1h"), ("1h", "3d")] {
            let mut config = curation_toml(&format!("curation.{rt}.min_release_age"), own, "off");
            config.curation.min_release_age = Some(global.to_string());
            let (filter, problems) = MinReleaseAgeFilter::from_config(&config.curation);
            assert!(problems.is_empty(), "{rt}: {problems:?}");
            let filter = filter.unwrap();
            assert_eq!(filter.summary(), format!("{global} ({rt}: {own})"));
            for &other in RegistryType::all() {
                let decision = filter.evaluate(&age_request(other, Some(now - 2 * 3600)));
                let threshold = if other == rt { own } else { global };
                assert_eq!(
                    held(&decision),
                    threshold == "3d",
                    "{rt} {own}, global {global}, {other} asked: {decision:?}"
                );
            }
        }
    }
}

#[test]
fn the_summary_names_every_value_and_a_global_one_alone_keeps_its_old_line() {
    use crate::curation::MinReleaseAgeFilter;
    let _lock = env_lock();
    let build = |global: Option<&str>, values: &[(&str, &str)]| {
        let mut content = String::from("[curation]\n");
        if let Some(g) = global {
            content.push_str(&format!("min_release_age = \"{g}\"\n"));
        }
        for (rt, v) in values {
            content.push_str(&format!("[curation.{rt}]\nmin_release_age = \"{v}\"\n"));
        }
        let (config, unknown) = parse_config(&content).unwrap();
        assert!(unknown.is_empty(), "{content}: {unknown:?}");
        let (filter, problems) = MinReleaseAgeFilter::from_config(&config.curation);
        assert!(problems.is_empty(), "{problems:?}");
        filter.unwrap()
    };
    let three = [("npm", "3d"), ("pypi", "2d"), ("gems", "1w")];
    let f = build(None, &three);
    assert_eq!(f.summary(), "npm: 3d, pypi: 2d, gems: 1w");
    assert_eq!(f.global_only(), None);
    let f = build(Some("7d"), &three);
    assert_eq!(f.summary(), "7d (npm: 3d, pypi: 2d, gems: 1w)");
    assert_eq!(f.global_only(), None);
    let f = build(Some("7d"), &[]);
    assert_eq!(f.summary(), "7d");
    assert_eq!(f.global_only(), Some((7 * 86400, "7d")));
}

#[test]
fn an_unknown_publish_date_is_left_to_the_quarantine_whatever_value_applies() {
    use crate::curation::{Decision, MinReleaseAgeFilter, ProxyFilter};
    let _lock = env_lock();
    // Without a date the filter has no opinion (the quarantine holds what is new),
    // whether the threshold is npm's own, the global one, or both (#741, #1098).
    for (global, npm) in [
        (Some("3d"), None),
        (None, Some("3d")),
        (Some("3d"), Some("1h")),
    ] {
        let mut curation = CurationConfig::default();
        curation.min_release_age = global.map(str::to_string);
        curation.npm.min_release_age = npm.map(str::to_string);
        let (filter, problems) = MinReleaseAgeFilter::from_config(&curation);
        assert!(problems.is_empty(), "{problems:?}");
        let filter = filter.unwrap();
        for rt in [RegistryType::Npm, RegistryType::PyPI] {
            assert_eq!(
                filter.evaluate(&age_request(rt, None)),
                Decision::Skip,
                "global {global:?}, npm {npm:?}: {rt}"
            );
        }
    }
}

#[test]
fn test_validate_curation_enforce_missing_allowlist_file() {
    let _lock = env_lock();
    let mut config = Config::default();
    config.curation.mode = CurationMode::Enforce;
    config.curation.allowlist_path = Some("/nonexistent/allow.json".to_string());
    let (_, errors) = config.validate_with_config_path(None);
    assert!(
        errors.iter().any(|e| e.contains("does not exist")),
        "enforce with missing allowlist file should be an error"
    );
}

/// Every curation duration key: global, then each `[curation.<registry>]` section.
/// Raw and Hugging Face have none.
fn curation_duration_keys() -> Vec<String> {
    let mut keys = vec![
        "curation.min_release_age".to_string(),
        "curation.quarantine_ttl".to_string(),
    ];
    for rt in RegistryType::all() {
        if !matches!(rt, RegistryType::Raw | RegistryType::HuggingFace) {
            keys.push(format!("curation.{rt}.min_release_age"));
            keys.push(format!("curation.{rt}.quarantine_ttl"));
        }
    }
    keys
}

/// A config file setting `key` (a dotted curation key) to `value`, in `mode`.
fn curation_toml(key: &str, value: &str, mode: &str) -> Config {
    let (table, field) = key.rsplit_once('.').unwrap();
    let mut content = format!("[curation]\nmode = \"{mode}\"\n");
    if table != "curation" {
        content.push_str(&format!("[{table}]\n"));
    }
    content.push_str(&format!("{field} = \"{value}\"\n"));
    let (config, unknown) = parse_config(&content).unwrap_or_else(|e| panic!("{e}\n{content}"));
    assert!(unknown.is_empty(), "{content}: {unknown:?}");
    config
}

/// `[curation.hf]` is no section of the config: reported as an unknown key, as
/// `[curation.raw]` is, not read as a minimum age that holds nothing.
#[test]
fn curation_hf_is_an_unknown_section() {
    for table in ["curation.hf", "curation.raw"] {
        let content = format!("[{table}]\nmin_release_age = \"7d\"\n");
        let (_, unknown) = parse_config(&content).unwrap();
        assert_eq!(unknown, vec![table.to_string()], "{content}");
    }
}

#[test]
fn an_unparsable_curation_duration_is_a_config_error_naming_it() {
    let _lock = env_lock();
    // #1099: `quarantine_ttl = "30m"` became 14 days without a word, and an
    // unparsable min_release_age stopped startup only in enforce mode.
    for key in curation_duration_keys() {
        for mode in ["off", "audit", "enforce"] {
            let config = curation_toml(&key, "30m", mode);
            let (_, errors) = config.validate_with_config_path(None);
            let named = format!("{key}=\"30m\" is not a duration");
            assert!(
                errors.iter().any(|e| e.contains(&named)),
                "{key} in {mode}: {errors:?}"
            );
        }
    }
}

/// #1099: the validator accepts EXACTLY what the consumer's
/// `parse_duration` accepts — no normalization (case, trim, sign) the consumer
/// does not do, or a value the validator passes is silently taken as 14 days
/// by `digest_quarantine`/`docker`.
#[test]
fn the_duration_validator_accepts_exactly_what_the_consumer_parses() {
    let _lock = env_lock();
    for s in ["7d", "7D", " 2d", "2d ", "+2d", "30m", "1w2d", "0d", "２d"] {
        let config = curation_toml("curation.quarantine_ttl", s, "off");
        let (_, errors) = config.validate_with_config_path(None);
        let flagged = errors.iter().any(|e| e.contains("curation.quarantine_ttl"));
        let consumer_ok = crate::curation::parse_duration(s).is_ok();
        assert_eq!(
            flagged, !consumer_ok,
            "validator flagged {s:?}={flagged}, but consumer parse_duration Ok={consumer_ok}"
        );
    }
}

/// A registry's own `min_release_age = "0d"` turns its age check off (not an
/// error, not a control); a zero global age or quarantine TTL is still an error.
#[test]
fn a_zero_registry_min_release_age_is_off_and_other_zero_durations_are_errors() {
    let _lock = env_lock();
    let config = curation_toml("curation.docker.min_release_age", "0d", "enforce");
    let (_, errors) = config.validate_with_config_path(None);
    assert!(
        !errors
            .iter()
            .any(|e| e.contains("curation.docker.min_release_age")),
        "{errors:?}"
    );
    assert!(
        !config
            .registry_min_age_facts(crate::curation::RegistryType::Docker)
            .value_set
    );
    for key in [
        "curation.min_release_age",
        "curation.quarantine_ttl",
        "curation.docker.quarantine_ttl",
    ] {
        let config = curation_toml(key, "0d", "audit");
        let (_, errors) = config.validate_with_config_path(None);
        assert!(
            errors
                .iter()
                .any(|e| e.contains(&format!("{key}=\"0d\" is not a duration"))),
            "{key}: {errors:?}"
        );
    }
}

#[test]
fn valid_curation_durations_are_not_errors() {
    let _lock = env_lock();
    for key in curation_duration_keys() {
        for value in ["14d", "36h", "1w2d"] {
            let config = curation_toml(&key, value, "audit");
            let (_, errors) = config.validate_with_config_path(None);
            let named = format!("{key}=\"{value}\" is not a duration");
            assert!(
                !errors.iter().any(|e| e.contains(&named)),
                "{key}={value}: {errors:?}"
            );
        }
    }
}

#[test]
fn test_validate_curation_audit_no_allowlist_warning() {
    let _lock = env_lock();
    let mut config = Config::default();
    config.curation.mode = CurationMode::Audit;
    let (warnings, errors) = config.validate_with_config_path(None);
    assert!(errors.is_empty());
    assert!(
        warnings.iter().any(|w| w.contains("no allowlist_path")),
        "audit without allowlist should be a warning"
    );
}

#[test]
fn test_validate_curation_off_no_warnings() {
    let _lock = env_lock();
    let config = Config::default();
    let (warnings, errors) = config.validate_with_config_path(None);
    assert!(errors.is_empty());
    assert!(
        !warnings.iter().any(|w| w.contains("curation")),
        "mode=off should produce no curation warnings"
    );
}

#[test]
fn test_curation_mode_display() {
    assert_eq!(CurationMode::Off.to_string(), "off");
    assert_eq!(CurationMode::Audit.to_string(), "audit");
    assert_eq!(CurationMode::Enforce.to_string(), "enforce");
}

// ========================================================================
// EnableSpec + [registries] tests
// ========================================================================

/// How many registries `all` switches on: every one except the opt-in ones.
fn in_all_count() -> usize {
    RegistryType::all().iter().filter(|rt| rt.in_all()).count()
}

#[test]
fn test_enable_spec_single_all() {
    let spec = EnableSpec::Single("all".to_string());
    let set = spec.resolve().unwrap();
    for rt in RegistryType::all() {
        assert_eq!(set.contains(rt), rt.in_all(), "{:?}", rt);
    }
}

/// `EnableSpec::resolve` is the one place `all`, inclusions, exclusions and aliases
/// meet: every combination an operator writes, with the set or the refusal it gives.
#[test]
fn test_enable_spec_resolve_table() {
    let in_all: HashSet<RegistryType> = RegistryType::all()
        .iter()
        .copied()
        .filter(|rt| rt.in_all())
        .collect();
    let plus = |extra: &[RegistryType]| -> HashSet<RegistryType> {
        in_all.iter().chain(extra).copied().collect()
    };
    let minus = |gone: &[RegistryType]| -> HashSet<RegistryType> {
        in_all
            .iter()
            .filter(|rt| !gone.contains(rt))
            .copied()
            .collect()
    };
    let set = |rts: &[RegistryType]| -> HashSet<RegistryType> { rts.iter().copied().collect() };
    use RegistryType::{Docker, HuggingFace as Hf, Maven, Npm};
    let ok: &[(&[&str], HashSet<RegistryType>)] = &[
        (&["all"], in_all.clone()),
        (&["all", "hf"], plus(&[Hf])),
        (&["all", "huggingface"], plus(&[Hf])),
        (&["all", "HF"], plus(&[Hf])),
        (&["all", "-maven"], minus(&[Maven])),
        (&["all", "-hf"], in_all.clone()),
        (&["all", "hf", "-hf"], in_all.clone()),
        (
            &["all", "hf", "-maven"],
            plus(&[Hf]).difference(&set(&[Maven])).copied().collect(),
        ),
        (&["hf"], set(&[Hf])),
        (&["hf", "npm"], set(&[Hf, Npm])),
        (&["docker"], set(&[Docker])),
    ];
    for (items, want) in ok {
        let spec = EnableSpec::List(items.iter().map(|s| s.to_string()).collect());
        assert_eq!(spec.resolve().as_ref(), Ok(want), "{items:?}");
    }
    let refused: &[(&[&str], &str)] = &[
        (&["all", "docker"], "cannot be combined"),
        (&["all", "dokcer"], "cannot be combined"),
        (&["all", "hf", "dokcer"], "cannot be combined"),
        (&["all", "hf", "npm"], "cannot be combined"),
        (&["all", "-dokcer"], "unknown registry"),
        (&["-hf"], "require \"all\""),
        (&["dokcer"], "unknown registry"),
        (&[], "must not be empty"),
    ];
    for (items, why) in refused {
        let spec = EnableSpec::List(items.iter().map(|s| s.to_string()).collect());
        let err = spec
            .resolve()
            .expect_err(&format!("{items:?} must be refused"));
        assert!(err.contains(why), "{items:?}: {err}");
    }
}

/// An opt-in format is never switched on by `all`: an operator who wrote `all` before
/// it existed did not opt in. It is named beside `all` to have both.
#[test]
fn test_all_leaves_out_opt_in_formats_until_named() {
    assert!(!RegistryType::HuggingFace.in_all());
    let all = EnableSpec::Single("all".to_string()).resolve().unwrap();
    assert!(!all.contains(&RegistryType::HuggingFace));
    let with_hf = EnableSpec::List(vec!["all".to_string(), "hf".to_string()])
        .resolve()
        .unwrap();
    assert!(with_hf.contains(&RegistryType::HuggingFace));
    assert_eq!(with_hf.len(), all.len() + 1);
    // A format `all` already covers still cannot be named beside it.
    let err = EnableSpec::List(vec!["all".to_string(), "docker".to_string()])
        .resolve()
        .unwrap_err();
    assert!(err.contains("cannot be combined"), "got: {}", err);
}

#[test]
fn test_enable_spec_single_registry() {
    let spec = EnableSpec::Single("docker".to_string());
    let set = spec.resolve().unwrap();
    assert_eq!(set.len(), 1);
    assert!(set.contains(&RegistryType::Docker));
}

#[test]
fn test_enable_spec_list_explicit() {
    let spec = EnableSpec::List(vec![
        "docker".to_string(),
        "npm".to_string(),
        "pypi".to_string(),
    ]);
    let set = spec.resolve().unwrap();
    assert_eq!(set.len(), 3);
    assert!(set.contains(&RegistryType::Docker));
    assert!(set.contains(&RegistryType::Npm));
    assert!(set.contains(&RegistryType::PyPI));
}

#[test]
fn test_enable_spec_all_minus() {
    let spec = EnableSpec::List(vec!["all".to_string(), "-maven".to_string()]);
    let set = spec.resolve().unwrap();
    assert_eq!(set.len(), in_all_count() - 1);
    assert!(!set.contains(&RegistryType::Maven));
    assert!(set.contains(&RegistryType::Docker));
}

#[test]
fn test_enable_spec_all_minus_multiple() {
    let spec = EnableSpec::List(vec![
        "all".to_string(),
        "-maven".to_string(),
        "-conan".to_string(),
    ]);
    let set = spec.resolve().unwrap();
    assert_eq!(set.len(), in_all_count() - 2);
    assert!(!set.contains(&RegistryType::Maven));
    assert!(!set.contains(&RegistryType::Conan));
}

#[test]
fn test_enable_spec_unknown_error() {
    let spec = EnableSpec::Single("bogus".to_string());
    assert!(spec.resolve().is_err());
}

#[test]
fn test_enable_spec_exclusion_without_all() {
    let spec = EnableSpec::List(vec!["docker".to_string(), "-maven".to_string()]);
    let err = spec.resolve().unwrap_err();
    assert!(err.contains("require \"all\""), "got: {}", err);
}

#[test]
fn test_enable_spec_empty_error() {
    let spec = EnableSpec::List(vec![]);
    assert!(spec.resolve().is_err());
}

#[test]
fn test_enable_spec_aliases() {
    let spec = EnableSpec::Single("rubygems".to_string());
    let set = spec.resolve().unwrap();
    assert!(set.contains(&RegistryType::Gems));

    let spec2 = EnableSpec::Single("dart".to_string());
    let set2 = spec2.resolve().unwrap();
    assert!(set2.contains(&RegistryType::PubDart));

    let spec3 = EnableSpec::Single("pub_dart".to_string());
    let set3 = spec3.resolve().unwrap();
    assert!(set3.contains(&RegistryType::PubDart));
}

#[test]
fn test_enable_spec_all_with_inclusions_error() {
    let spec = EnableSpec::List(vec!["all".to_string(), "docker".to_string()]);
    let err = spec.resolve().unwrap_err();
    assert!(err.contains("cannot be combined"), "got: {}", err);
}

#[test]
fn test_registries_toml_list() {
    let _lock = env_lock();
    let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"

            [registries]
            enable = ["docker", "npm"]
        "#;

    let config: Config = toml::from_str(toml).unwrap();
    assert!(config.registries.is_some());
    let section = config.registries.as_ref().unwrap();
    assert_eq!(
        section.enable,
        Some(EnableSpec::List(vec![
            "docker".to_string(),
            "npm".to_string()
        ]))
    );
    let set = config.enabled_registries();
    assert_eq!(set.len(), 2);
    assert!(set.contains(&RegistryType::Docker));
    assert!(set.contains(&RegistryType::Npm));
}

#[test]
fn apply_enabled_registries_materializes_flags() {
    // #856: the resolved enable-set must land in the per-registry `enabled`
    // flags — hosted handlers (rpm/deb/raw) gate on those, not on the set.
    let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"
        "#;
    let mut config: Config = toml::from_str(toml).unwrap();
    // rpm/deb default `enabled = false`; docker defaults `true`.
    assert!(!config.rpm.enabled);
    assert!(config.docker.enabled);

    config.apply_enabled_registries(&std::collections::HashSet::from([RegistryType::Rpm]));

    assert!(
        config.rpm.enabled,
        "rpm must be flagged enabled after apply (#856)"
    );
    assert!(!config.deb.enabled, "deb was not in the set");
    assert!(
        !config.docker.enabled,
        "docker was not in the set — must be cleared"
    );
}

/// C86: a format compiled out of this build (cargo features `rpm`/`deb`,
/// default on) is never in the enabled set, whichever tier asked for it, so
/// its routes are not mounted and its handler flag is cleared.
#[test]
fn enabled_registries_drops_compiled_out_formats() {
    let _lock = env_lock();
    let base = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"
        "#;
    for extra in [
        "[registries]\nenable = [\"npm\", \"rpm\", \"deb\"]",
        "[rpm]\nenabled = true\n[deb]\nenabled = true",
    ] {
        let mut config: Config = toml::from_str(&format!("{base}\n{extra}")).unwrap();
        let set = config.enabled_registries();
        config.apply_enabled_registries(&set);
        assert_eq!(
            set.contains(&RegistryType::Rpm),
            cfg!(feature = "rpm"),
            "{extra}"
        );
        assert_eq!(
            set.contains(&RegistryType::Deb),
            cfg!(feature = "deb"),
            "{extra}"
        );
        assert_eq!(config.rpm.enabled, cfg!(feature = "rpm"), "{extra}");
        assert_eq!(config.deb.enabled, cfg!(feature = "deb"), "{extra}");
    }
}

#[cfg(feature = "rpm")]
#[test]
fn registries_toml_enable_backpropagates_to_flags() {
    let _lock = env_lock();
    // #856 at the config layer: `[registries].enable = ["rpm"]` resolves rpm
    // into the set AND (after apply) into `config.rpm.enabled`, so the mounted
    // rpm route no longer 404s in the handler gate.
    let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"

            [registries]
            enable = ["rpm"]
        "#;
    let mut config: Config = toml::from_str(toml).unwrap();
    assert!(!config.rpm.enabled, "precondition: rpm flag defaults off");

    let set = config.enabled_registries();
    config.apply_enabled_registries(&set);

    assert!(set.contains(&RegistryType::Rpm));
    assert!(
        config.rpm.enabled,
        "rpm flag must be set from [registries].enable (#856)"
    );
}

#[test]
fn test_registries_toml_string() {
    let _lock = env_lock();
    let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"

            [registries]
            enable = "all"
        "#;

    let config: Config = toml::from_str(toml).unwrap();
    let set = config.enabled_registries();
    let in_all = RegistryType::all()
        .iter()
        .filter(|rt| rt.in_all() && rt.compiled_in())
        .count();
    assert_eq!(set.len(), in_all);
}

/// `enabled_registries_legacy` is a chain of `if` blocks, not a `match`: a format left
/// out of it is never enabled by its own `[x] enabled = true`, and nothing fails to
/// compile. Every flag switched on through the exhaustive `apply_enabled_registries`
/// has to come back as the full set.
#[test]
fn test_legacy_flags_cover_every_registry() {
    let mut config = Config::default();
    let all: HashSet<RegistryType> = RegistryType::all().iter().copied().collect();
    config.apply_enabled_registries(&all);
    assert_eq!(config.enabled_registries_legacy(), all);
}

/// Each `[x] enabled` flag switches on its own format and no other: a chain slot that
/// read a neighbour's flag would pass a test that switches every flag on at once.
#[test]
fn test_each_legacy_flag_enables_only_its_own_format() {
    for rt in RegistryType::all() {
        let mut config = Config::default();
        let one: HashSet<RegistryType> = [*rt].into_iter().collect();
        config.apply_enabled_registries(&one);
        assert_eq!(config.enabled_registries_legacy(), one, "{:?}", rt);
    }
}

#[test]
fn test_hf_enabled_only_by_true_or_one() {
    let _lock = env_lock();
    for (val, on) in [
        ("true", true),
        ("TRUE", true),
        ("1", true),
        ("false", false),
        ("0", false),
        ("no", false),
        ("off", false),
        ("", false),
    ] {
        let mut config = Config::default();
        config.hf.enabled = !on;
        std::env::set_var("NORA_HF_ENABLED", val);
        let applied = config.apply_env_overrides();
        std::env::remove_var("NORA_HF_ENABLED");
        applied.unwrap();
        assert_eq!(config.hf.enabled, on, "NORA_HF_ENABLED={val:?}");
    }
}

/// A blank `[hf] proxy`, in the file or the environment, is no upstream, as in every
/// other format.
#[test]
fn test_hf_blank_proxy_is_no_upstream() {
    let _lock = env_lock();
    let config: Config = toml::from_str("[hf]\nenabled = true\nproxy = \"  \"\n").unwrap();
    assert_eq!(config.hf.proxy, None);
    let mut config = Config::default();
    std::env::set_var("NORA_HF_PROXY", "  ");
    let applied = config.apply_env_overrides();
    std::env::remove_var("NORA_HF_PROXY");
    applied.unwrap();
    assert_eq!(config.hf.proxy, None);
}

#[test]
fn test_hf_proxy_from_toml_is_the_upstream() {
    let config: Config =
        toml::from_str("[hf]\nenabled = true\nproxy = \"https://hf-mirror.example\"\n").unwrap();
    assert_eq!(
        config.hf.proxy.as_deref(),
        Some("https://hf-mirror.example")
    );
    // An `[hf]` section that does not name a timeout keeps the default: zero would
    // time out every request.
    assert_eq!(config.hf.proxy_timeout, 30);
    assert!(
        !config
            .upstream_hostnames()
            .iter()
            .any(|(reg, _)| reg == "hf"),
        "hf bodies are not scanned for the upstream host"
    );
}

/// The keys of `[hf]`, held by the compiler: destructured without `..`, so adding a
/// field — a credential among them — does not build until this line names it. The first
/// release proxies public repositories only.
#[test]
fn test_hf_config_keys_are_exactly_these() {
    let HfConfig {
        enabled: _,
        proxy: _,
        proxy_timeout: _,
        // Host names a file redirect may go to, not a credential.
        cdn_hosts: _,
    } = HfConfig::default();
}

#[test]
fn hf_cdn_hosts_come_from_the_env_and_a_malformed_one_is_refused() {
    let _lock = env_lock();
    assert_eq!(
        HfConfig::default().cdn_hosts,
        vec!["hf.co", "huggingface.co"]
    );
    // Trimmed and lowercased, a blank item dropped wherever it is.
    std::env::set_var("NORA_HF_CDN_HOSTS", " CDN.Example.com, ,10.0.0.5 ,");
    let mut config = Config::default();
    config.hf.apply_env_overrides();
    std::env::remove_var("NORA_HF_CDN_HOSTS");
    assert_eq!(config.hf.cdn_hosts, vec!["cdn.example.com", "10.0.0.5"]);
    assert!(config.hf.invalid_cdn_hosts().is_empty());
    for good in [
        "cdn-lfs.example",
        "x1.hf.co",
        "hf.co",
        "127.0.0.1",
        "::1",
        "0:0:0:0:0:0:0:1",
    ] {
        let mut config = Config::default();
        config.hf.cdn_hosts = vec![good.to_string()];
        assert!(config.hf.invalid_cdn_hosts().is_empty(), "{good:?}");
    }
    // A TOML entry is taken as written: a capital letter would match no host, a trailing
    // dot neither, so both are errors rather than entries that silently hold nothing.
    for bad in [
        "https://cdn.example.com",
        "cdn.example.com:443",
        "cdn.example.com/x",
        "*.hf.co",
        ".hf.co",
        "hf.co.",
        "HF.co",
        "[::1]",
        "cdn example.com",
        "",
    ] {
        let mut config = Config::default();
        config.hf.cdn_hosts = vec![bad.to_string()];
        let (_, errors) = config.validate_with_config_path(None);
        assert!(
            errors.iter().any(|e| e.contains("hf.cdn_hosts entry")),
            "{bad:?}: {errors:?}"
        );
    }
    let (_, errors) = Config::default().validate_with_config_path(None);
    assert!(
        !errors.iter().any(|e| e.contains("hf.cdn_hosts")),
        "{errors:?}"
    );
}

/// A Hub commit has no publish date NORA reads and hf has no quarantine path, so a
/// min_release_age would hold nothing there: refused, not ignored.
#[test]
fn test_min_release_age_is_refused_with_hf() {
    let _lock = env_lock();
    let mut config = Config::default();
    config.curation.min_release_age = Some("7d".to_string());
    config.curation.quarantine = Some(crate::digest_quarantine::QuarantineMode::Enforce);
    let (_, errors) = config.validate_with_config_path(None);
    assert!(
        !errors.iter().any(|e| e.contains("Hugging Face")),
        "{errors:?}"
    );
    config.hf.enabled = true;
    let (_, errors) = config.validate_with_config_path(None);
    assert!(
        errors.iter().any(|e| e.contains("Hugging Face")),
        "{errors:?}"
    );
    config.curation.min_release_age = None;
    let (_, errors) = config.validate_with_config_path(None);
    assert!(
        !errors.iter().any(|e| e.contains("Hugging Face")),
        "{errors:?}"
    );
}

#[test]
fn test_hf_enabled_from_toml_and_env() {
    let _lock = env_lock();
    let config: Config = toml::from_str("[hf]\nenabled = true\n").unwrap();
    assert!(config
        .enabled_registries()
        .contains(&RegistryType::HuggingFace));
    assert_eq!(config.hf.proxy.as_deref(), Some("https://huggingface.co"));

    let mut config = Config::default();
    std::env::set_var("NORA_HF_ENABLED", "true");
    std::env::set_var("NORA_HF_PROXY", "http://127.0.0.1:9");
    std::env::set_var("NORA_HF_PROXY_TIMEOUT", "7");
    let applied = config.apply_env_overrides();
    std::env::remove_var("NORA_HF_ENABLED");
    std::env::remove_var("NORA_HF_PROXY");
    std::env::remove_var("NORA_HF_PROXY_TIMEOUT");
    applied.unwrap();
    assert!(config.hf.enabled);
    assert_eq!(config.hf.proxy.as_deref(), Some("http://127.0.0.1:9"));
    assert_eq!(config.hf.proxy_timeout, 7);
}

/// The first release proxies public repositories only: a server-side Hub token would let
/// the cache hand gated repositories to every NORA user. Until that is decided otherwise,
/// `[hf]` has no credential key, and a file that sets one is told so.
#[test]
fn test_hf_has_no_server_side_token() {
    let (_, unknown) = parse_config("[hf]\nenabled = true\nproxy_auth = \"user:token\"\n").unwrap();
    assert_eq!(unknown, vec!["hf.proxy_auth".to_string()]);
}

#[test]
fn test_registries_toml_absent() {
    let _lock = env_lock();
    // No [registries] section → legacy mode
    let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"
        "#;

    let config: Config = toml::from_str(toml).unwrap();
    assert!(config.registries.is_none());
    // Legacy: 7 core enabled by default
    let set = config.enabled_registries();
    assert_eq!(set.len(), 7);
    assert!(set.contains(&RegistryType::Docker));
    assert!(set.contains(&RegistryType::Maven));
    assert!(!set.contains(&RegistryType::Gems)); // new registries default disabled
}

#[test]
fn test_registries_toml_empty_section() {
    let _lock = env_lock();
    // [registries] without enable → legacy mode
    let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"

            [registries]
        "#;

    let config: Config = toml::from_str(toml).unwrap();
    assert!(config.registries.is_some());
    assert!(config.registries.as_ref().unwrap().enable.is_none());
    // Falls through to legacy
    let set = config.enabled_registries();
    assert_eq!(set.len(), 7);
}

#[test]
fn test_env_overrides_toml_registries() {
    let _lock = env_lock();
    // NORA_REGISTRIES_ENABLE should take precedence over [registries].enable
    let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"

            [registries]
            enable = ["docker", "npm"]
        "#;

    let config: Config = toml::from_str(toml).unwrap();
    std::env::set_var("NORA_REGISTRIES_ENABLE", "cargo,pypi");
    let set = config.enabled_registries();
    assert_eq!(set.len(), 2);
    assert!(set.contains(&RegistryType::Cargo));
    assert!(set.contains(&RegistryType::PyPI));
    assert!(!set.contains(&RegistryType::Docker));
    std::env::remove_var("NORA_REGISTRIES_ENABLE");
}

#[test]
fn test_from_env_str_parsing() {
    let spec = EnableSpec::from_env_str("docker, npm , pypi");
    assert_eq!(
        spec,
        EnableSpec::List(vec![
            "docker".to_string(),
            "npm".to_string(),
            "pypi".to_string()
        ])
    );

    // Single value
    let spec2 = EnableSpec::from_env_str("all");
    assert_eq!(spec2, EnableSpec::Single("all".to_string()));

    // Uppercase → lowercase
    let spec3 = EnableSpec::from_env_str("Docker,NPM");
    assert_eq!(
        spec3,
        EnableSpec::List(vec!["docker".to_string(), "npm".to_string()])
    );

    // With exclusions
    let spec4 = EnableSpec::from_env_str("all,-maven,-conan");
    assert_eq!(
        spec4,
        EnableSpec::List(vec![
            "all".to_string(),
            "-maven".to_string(),
            "-conan".to_string()
        ])
    );
}

#[test]
fn test_validate_unknown_registry_in_enable() {
    let _lock = env_lock();
    let mut config = Config::default();
    config.registries = Some(RegistriesSection {
        enable: Some(EnableSpec::List(vec![
            "docker".to_string(),
            "bogus".to_string(),
        ])),
    });
    let (_, errors) = config.validate_with_config_path(None);
    assert!(
        errors.iter().any(|e| e.contains("[registries].enable")),
        "should report validation error: {:?}",
        errors
    );
}

#[test]
fn test_registries_toml_all_minus() {
    let _lock = env_lock();
    let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            mode = "local"

            [registries]
            enable = ["all", "-maven", "-conan"]
        "#;

    let config: Config = toml::from_str(toml).unwrap();
    let set = config.enabled_registries();
    let compiled = RegistryType::all()
        .iter()
        .filter(|rt| rt.in_all() && rt.compiled_in())
        .count();
    assert_eq!(set.len(), compiled - 2);
    assert!(!set.contains(&RegistryType::Maven));
    assert!(!set.contains(&RegistryType::Conan));
    assert!(set.contains(&RegistryType::Docker));
}

#[test]
fn test_upstream_hostnames_extracts_from_defaults() {
    let config = Config::default();
    let hosts = config.upstream_hostnames();
    // Default config has proxy URLs for several registries
    let hostnames: Vec<&str> = hosts.iter().map(|(_, h)| h.as_str()).collect();
    assert!(hostnames.contains(&"crates.io"), "cargo default missing");
    assert!(
        hostnames.contains(&"api.nuget.org"),
        "nuget default missing"
    );
    assert!(
        hostnames.contains(&"azuresearch-usnc.nuget.org"),
        "nuget search default missing"
    );
    assert!(
        hostnames.contains(&"proxy.golang.org"),
        "go default missing"
    );
    // Hugging Face metadata carries the Hub's host as content (a model card's
    // `license_link`), and its proxy URLs travel in headers, not bodies.
    assert!(
        !hostnames.contains(&"huggingface.co"),
        "hf bodies are not scanned for the upstream host"
    );
    // localhost should be excluded
    assert!(!hostnames.contains(&"localhost"));
    assert!(!hostnames.contains(&"127.0.0.1"));
}

#[test]
fn test_upstream_hostnames_deduplicates() {
    let config = Config::default();
    let hosts = config.upstream_hostnames();
    let mut seen = std::collections::HashSet::new();
    for pair in &hosts {
        assert!(seen.insert(pair), "duplicate: {:?}", pair);
    }
}

#[test]
fn test_upstream_hostnames_docker_upstreams() {
    let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            path = "/tmp/nora-test"

            [docker]
            enabled = true

            [[docker.upstreams]]
            url = "https://registry-1.docker.io"

            [[docker.upstreams]]
            url = "https://ghcr.io"
        "#;
    let config: Config = toml::from_str(toml).unwrap();
    let hosts = config.upstream_hostnames();
    let docker_hosts: Vec<&str> = hosts
        .iter()
        .filter(|(r, _)| r == "docker")
        .map(|(_, h)| h.as_str())
        .collect();
    assert!(docker_hosts.contains(&"registry-1.docker.io"));
    assert!(docker_hosts.contains(&"ghcr.io"));
}

#[test]
fn test_upstream_hostnames_pypi_multi_upstream() {
    // #663: every configured pypi upstream host must reach the leak detector,
    // not just the legacy single `proxy`. A secondary upstream (e.g. an internal
    // mirror carrying credentials) was previously invisible to leak scanning.
    let toml = r#"
            [server]
            host = "127.0.0.1"
            port = 4000

            [storage]
            path = "/tmp/nora-test"

            [[pypi.proxies]]
            url = "https://pypi.org/simple"

            [[pypi.proxies]]
            url = "https://internal-nexus.corp/pypi"
            auth = "secret-token"
        "#;
    let config: Config = toml::from_str(toml).unwrap();
    let hosts = config.upstream_hostnames();
    let pypi_hosts: Vec<&str> = hosts
        .iter()
        .filter(|(r, _)| r == "pypi")
        .map(|(_, h)| h.as_str())
        .collect();
    assert!(
        pypi_hosts.contains(&"pypi.org"),
        "primary upstream registered"
    );
    assert!(
        pypi_hosts.contains(&"internal-nexus.corp"),
        "secondary upstream host must be registered with the leak detector"
    );
}

#[test]
fn test_storage_config_debug_redacts_credentials() {
    let config = StorageConfig {
        mode: StorageMode::Local,
        path: String::new(),
        s3_url: String::new(),
        bucket: String::new(),
        s3_access_key: Some(ProtectedString::from("AKIAIOSFODNN7EXAMPLE")),
        s3_secret_key: Some(ProtectedString::from(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )),
        s3_credentials_dir: None,
        s3_region: String::new(),
        s3_virtual_hosted: false,
        s3_anonymous: false,
        gcs_service_account_path: None,
        gcs_base_url: None,
    };
    let debug_output = format!("{:?}", config);
    assert!(
        !debug_output.contains("AKIAIOSFODNN7EXAMPLE"),
        "Debug output must not contain access key"
    );
    assert!(
        !debug_output.contains("wJalrXUtnFEMI"),
        "Debug output must not contain secret key"
    );
    assert!(
        debug_output.contains("REDACTED"),
        "Debug output should show REDACTED for credential fields"
    );
}

// ========================================================================
// Wildcard host + public_url validation (#510)
// ========================================================================

#[test]
fn test_validate_wildcard_host_requires_public_url() {
    let _lock = env_lock();
    for host in &["0.0.0.0", "::", "0:0:0:0:0:0:0:0"] {
        let mut config = Config::default();
        config.server.host = host.to_string();
        config.server.public_url = None;
        let (_, errors) = config.validate_with_config_path(None);
        assert!(
            errors.iter().any(|e| e.contains("NORA_PUBLIC_URL")),
            "host='{}' without public_url should produce NORA_PUBLIC_URL error, got: {:?}",
            host,
            errors
        );
    }
}

#[test]
fn test_validate_wildcard_host_with_public_url_ok() {
    let _lock = env_lock();
    let mut config = Config::default();
    config.server.host = "0.0.0.0".to_string();
    config.server.public_url = Some("http://registry.example.com:4000".to_string());
    let (_, errors) = config.validate_with_config_path(None);
    assert!(
        !errors.iter().any(|e| e.contains("NORA_PUBLIC_URL")),
        "0.0.0.0 with valid public_url should not error: {:?}",
        errors
    );
}

#[test]
fn test_validate_non_wildcard_host_no_public_url_ok() {
    let _lock = env_lock();
    let mut config = Config::default();
    config.server.host = "192.168.1.10".to_string();
    config.server.public_url = None;
    let (_, errors) = config.validate_with_config_path(None);
    assert!(
        errors.is_empty(),
        "non-wildcard host without public_url should have no errors: {:?}",
        errors
    );
}

#[test]
fn test_validate_public_url_rejects_bad_scheme() {
    let _lock = env_lock();
    for scheme_url in &["ftp://registry.example.com", "javascript://alert(1)"] {
        let mut config = Config::default();
        config.server.public_url = Some(scheme_url.to_string());
        let (_, errors) = config.validate_with_config_path(None);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("http://") || e.contains("https://")),
            "public_url='{}' should be rejected for bad scheme: {:?}",
            scheme_url,
            errors
        );
    }
}

#[test]
fn test_validate_public_url_rejects_garbage() {
    let _lock = env_lock();
    let mut config = Config::default();
    config.server.public_url = Some("not-a-url".to_string());
    let (_, errors) = config.validate_with_config_path(None);
    assert!(
        errors.iter().any(|e| e.contains("not a valid URL")),
        "garbage public_url should produce validation error: {:?}",
        errors
    );
}

#[test]
fn test_validate_public_url_accepts_valid() {
    let _lock = env_lock();
    for url in &[
        "http://registry:4000",
        "https://nora.example.com",
        "http://10.0.0.1:4000",
        "https://nora.example.com:8443/",
    ] {
        let mut config = Config::default();
        config.server.public_url = Some(url.to_string());
        let (_, errors) = config.validate_with_config_path(None);
        assert!(
            !errors.iter().any(|e| e.contains("NORA_PUBLIC_URL")),
            "valid public_url='{}' should not produce errors: {:?}",
            url,
            errors
        );
    }
}

// --- TrustedProxies: prefix=0 overflow fix (#525) ---

#[test]
fn test_trusted_proxies_prefix_zero_v4() {
    let proxies = TrustedProxies::parse("0.0.0.0/0");
    assert!(proxies.contains("192.168.1.1".parse().unwrap()));
    assert!(proxies.contains("10.0.0.1".parse().unwrap()));
    assert!(proxies.contains("255.255.255.255".parse().unwrap()));
    assert!(proxies.contains("127.0.0.1".parse().unwrap()));
}

#[test]
fn test_trusted_proxies_prefix_zero_v6() {
    let proxies = TrustedProxies::parse("::/0");
    assert!(proxies.contains("::1".parse().unwrap()));
    assert!(proxies.contains("fe80::1".parse().unwrap()));
    assert!(proxies.contains("2001:db8::1".parse().unwrap()));
}

#[test]
fn test_trusted_proxies_prefix_zero_no_cross_family() {
    // 0.0.0.0/0 must NOT match IPv6 addresses
    let v4_all = TrustedProxies::parse("0.0.0.0/0");
    assert!(!v4_all.contains("::1".parse().unwrap()));
    assert!(!v4_all.contains("2001:db8::1".parse().unwrap()));

    // ::/0 must NOT match IPv4 addresses
    let v6_all = TrustedProxies::parse("::/0");
    assert!(!v6_all.contains("127.0.0.1".parse().unwrap()));
    assert!(!v6_all.contains("10.0.0.1".parse().unwrap()));
}

#[test]
fn test_trusted_proxies_prefix_zero_non_canonical_network() {
    // Non-zero network address with /0 still matches everything in that family
    let proxies = TrustedProxies::parse("192.168.1.1/0");
    assert!(proxies.contains("10.0.0.1".parse().unwrap()));
    assert!(proxies.contains("172.16.0.1".parse().unwrap()));
}

#[test]
fn test_trusted_proxies_prefix_zero_parse_accepted() {
    // /0 must not be dropped by parse()
    let proxies = TrustedProxies::parse("0.0.0.0/0");
    assert!(proxies.has_prefix_zero());

    let proxies = TrustedProxies::parse("::/0");
    assert!(proxies.has_prefix_zero());

    // Normal CIDR must not trigger has_prefix_zero
    let proxies = TrustedProxies::parse("10.0.0.0/8");
    assert!(!proxies.has_prefix_zero());
}

#[test]
fn test_trusted_proxies_existing_behavior_unchanged() {
    // Verify existing prefix values still work correctly
    let proxies = TrustedProxies::parse("10.0.0.0/8");
    assert!(proxies.contains("10.255.255.255".parse().unwrap()));
    assert!(!proxies.contains("11.0.0.1".parse().unwrap()));

    let proxies = TrustedProxies::parse("192.168.1.0/24");
    assert!(proxies.contains("192.168.1.100".parse().unwrap()));
    assert!(!proxies.contains("192.168.2.1".parse().unwrap()));

    // Exact match (no CIDR)
    let proxies = TrustedProxies::parse("10.0.0.1");
    assert!(proxies.contains("10.0.0.1".parse().unwrap()));
    assert!(!proxies.contains("10.0.0.2".parse().unwrap()));
}

#[test]
fn test_validate_warns_on_prefix_zero() {
    let _lock = env_lock();
    let mut config = Config::default();
    config.auth.trusted_proxies = TrustedProxies::parse("0.0.0.0/0");
    let (warnings, _) = config.validate_with_config_path(None);
    assert!(
        warnings.iter().any(|w| w.contains("/0 CIDR")),
        "validate() should warn about /0 in trusted_proxies: {:?}",
        warnings
    );
}

#[test]
fn test_validate_no_warn_on_normal_proxies() {
    let _lock = env_lock();
    let mut config = Config::default();
    config.auth.trusted_proxies = TrustedProxies::parse("10.0.0.0/8,192.168.1.0/24");
    let (warnings, _) = config.validate_with_config_path(None);
    assert!(
        !warnings.iter().any(|w| w.contains("/0 CIDR")),
        "validate() should not warn about normal CIDRs: {:?}",
        warnings
    );
}

mod proptest_trusted_proxies {
    use super::*;
    use proptest::prelude::*;

    /// Reference implementation for CIDR matching (avoids the shift overflow).
    fn cidr_matches_reference(net: u32, addr: u32, prefix: u8) -> bool {
        if prefix == 0 {
            return true;
        }
        if prefix >= 32 {
            return net == addr;
        }
        // Right-shift is safe for prefix 1..=31
        (net >> (32 - prefix)) == (addr >> (32 - prefix))
    }

    fn cidr_matches_reference_v6(net: u128, addr: u128, prefix: u8) -> bool {
        if prefix == 0 {
            return true;
        }
        if prefix >= 128 {
            return net == addr;
        }
        (net >> (128 - prefix)) == (addr >> (128 - prefix))
    }

    proptest! {
        #[test]
        fn cidr_v4_matches_oracle(
            net_raw in any::<u32>(),
            addr_raw in any::<u32>(),
            prefix in 0u8..=32,
        ) {
            let net = std::net::Ipv4Addr::from(net_raw);
            let addr = std::net::Ipv4Addr::from(addr_raw);
            let cidr = format!("{}/{}", net, prefix);
            let proxies = TrustedProxies::parse(&cidr);
            let actual = proxies.contains(std::net::IpAddr::V4(addr));
            let expected = cidr_matches_reference(net_raw, addr_raw, prefix);
            prop_assert_eq!(actual, expected,
                "CIDR {} vs addr {}: expected={}, actual={}",
                cidr, addr, expected, actual);
        }

        #[test]
        fn cidr_v6_matches_oracle(
            net_raw in any::<u128>(),
            addr_raw in any::<u128>(),
            prefix in 0u8..=128,
        ) {
            let net = std::net::Ipv6Addr::from(net_raw);
            let addr = std::net::Ipv6Addr::from(addr_raw);
            let cidr = format!("{}/{}", net, prefix);
            let proxies = TrustedProxies::parse(&cidr);
            let actual = proxies.contains(std::net::IpAddr::V6(addr));
            let expected = cidr_matches_reference_v6(net_raw, addr_raw, prefix);
            prop_assert_eq!(actual, expected,
                "CIDR {} vs addr {}: expected={}, actual={}",
                cidr, addr, expected, actual);
        }
    }
}
