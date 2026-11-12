// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::build_curation_engine;
use crate::config::{Config, CurationConfig, CurationMode};

fn config_with_allowlist(mode: CurationMode, allowlist_path: String) -> Config {
    Config {
        curation: CurationConfig {
            mode,
            allowlist_path: Some(allowlist_path),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Regression for #586: a SIGHUP reload must NOT swap to an allow-all engine
/// when the allowlist no longer parses. `reload_curation()` gates its
/// `ArcSwap::store` on `build_curation_engine(&config)?`, so this is the
/// exact function the production reload path runs: in enforce mode a
/// malformed allowlist must return `Err` (so `?` short-circuits before the
/// swap and the previous engine survives), not a silently-dropped,
/// deny-by-default-defeating filter.
#[test]
fn enforce_rejects_malformed_allowlist() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("allowlist.json");
    std::fs::write(&path, b"{ not valid json").unwrap();

    let config = config_with_allowlist(CurationMode::Enforce, path.to_str().unwrap().into());
    let result = build_curation_engine(&config);
    assert!(
        result.is_err(),
        "enforce mode must reject a malformed allowlist, got an engine"
    );
}

/// A well-formed allowlist still builds, and the filter is actually
/// installed (engine active) — the fix must not reject valid reloads.
#[test]
fn enforce_accepts_valid_allowlist() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("allowlist.json");
    std::fs::write(&path, br#"{"version": 1, "entries": []}"#).unwrap();

    let config = config_with_allowlist(CurationMode::Enforce, path.to_str().unwrap().into());
    let engine = build_curation_engine(&config).expect("valid allowlist must build");
    assert!(engine.is_active(), "allowlist filter must be installed");
    // and it decides: a version the empty allowlist does not list is held
    use crate::curation::{Decision, FilterRequest, RegistryType, RequestVersion};
    let request = FilterRequest {
        registry: RegistryType::Npm,
        upstream: None,
        name: "left-pad".into(),
        version: RequestVersion::Known("1.3.0".into()),
        integrity: None,
        bypass: false,
        publish_date: None,
    };
    assert!(
        matches!(engine.evaluate(&request).decision, Decision::Block { .. }),
        "an empty allowlist admits nothing in enforce mode"
    );
}

/// Q03: the per-registry `allow` list rides the engine `reload_curation()` swaps
/// in on SIGHUP: an allowlisted young version passes, its neighbour is held.
#[test]
fn engine_carries_min_age_allow_list() {
    use crate::curation::{Decision, FilterRequest, RegistryType, RequestVersion};
    let mut config = Config::default();
    config.curation.mode = CurationMode::Enforce;
    config.curation.min_release_age = Some("7d".into());
    config.curation.nuget.allow = vec!["Newtonsoft.Json@13.0.4".into()];
    let engine = build_curation_engine(&config).unwrap();
    let young = |version: &str| FilterRequest {
        registry: RegistryType::Nuget,
        upstream: None,
        name: "newtonsoft.json".into(),
        version: RequestVersion::Known(version.into()),
        integrity: None,
        bypass: false,
        publish_date: Some(crate::cache_ttl::now_unix() as i64 - 60),
    };
    assert_eq!(engine.evaluate(&young("13.0.4")).decision, Decision::Allow);
    assert!(matches!(
        engine.evaluate(&young("13.0.5")).decision,
        Decision::Block { .. }
    ));
}

/// Audit/off mode stays lenient (matches boot behavior): a broken file
/// there is logged and dropped, never blocking the build, since the engine
/// is advisory.
#[test]
fn non_enforce_is_lenient_on_malformed_allowlist() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("allowlist.json");
    std::fs::write(&path, b"garbage").unwrap();

    let config = config_with_allowlist(CurationMode::Off, path.to_str().unwrap().into());
    assert!(build_curation_engine(&config).is_ok());
}

/// Ages given in seconds, keyed by registry: what the engine decides for a
/// release of that age.
fn blocked(config: &Config, registry: crate::curation::RegistryType, age_secs: i64) -> bool {
    use crate::curation::{Decision, FilterRequest, RequestVersion};
    let engine = build_curation_engine(config).expect("engine builds");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let result = engine.evaluate(&FilterRequest {
        registry,
        upstream: None,
        name: "pkg".to_string(),
        version: RequestVersion::named(Some("1.0.0")),
        integrity: None,
        bypass: false,
        publish_date: Some(now - age_secs),
    });
    match result.decision {
        Decision::Block { rule, .. } => {
            assert_eq!(rule, "min-release-age");
            true
        }
        _ => false,
    }
}

fn enforce() -> Config {
    Config {
        curation: CurationConfig {
            mode: CurationMode::Enforce,
            ..Default::default()
        },
        ..Default::default()
    }
}

/// #1098: a per-registry minimum age without a global one is applied to its
/// registry, and only to it.
#[test]
fn a_per_registry_min_release_age_alone_is_applied_to_its_registry() {
    use crate::curation::RegistryType;
    let mut config = enforce();
    config.curation.npm.min_release_age = Some("3d".to_string());
    assert!(blocked(&config, RegistryType::Npm, 3_600));
    assert!(!blocked(&config, RegistryType::Npm, 4 * 86_400));
    for other in [RegistryType::PyPI, RegistryType::Cargo, RegistryType::Raw] {
        assert!(!blocked(&config, other, 3_600), "{other}");
    }
}

/// With a global value, an override applies to its registry and the global
/// value to the others — every registry that has an override, cpan included.
#[test]
fn an_override_applies_to_its_registry_and_the_global_value_to_the_others() {
    use crate::curation::RegistryType;
    let mut config = enforce();
    config.curation.min_release_age = Some("1h".to_string());
    config.curation.npm.min_release_age = Some("3d".to_string());
    config.curation.cpan.min_release_age = Some("3d".to_string());
    config.curation.pypi.min_release_age = Some("1d".to_string());
    let two_hours = 2 * 3_600;
    assert!(blocked(&config, RegistryType::Npm, two_hours));
    assert!(blocked(&config, RegistryType::Cpan, two_hours));
    assert!(blocked(&config, RegistryType::PyPI, two_hours));
    assert!(!blocked(&config, RegistryType::PyPI, 2 * 86_400));
    assert!(!blocked(&config, RegistryType::Cargo, two_hours));
    assert!(blocked(&config, RegistryType::Cargo, 1_800));
}

/// In enforce mode an unparsable per-registry value refuses the build and
/// names the value, as an unparsable global one does — it is never dropped.
#[test]
fn enforce_rejects_an_unparsable_per_registry_min_release_age() {
    // With a global value and without one: the per-registry value is read either way.
    for global in [Some("7d"), None] {
        let mut config = enforce();
        config.curation.min_release_age = global.map(str::to_string);
        config.curation.npm.min_release_age = Some("3x".to_string());
        let err = build_curation_engine(&config).err().unwrap_or_else(|| {
            panic!("global {global:?}: an unparsable value must refuse the build")
        });
        assert!(err.contains("curation.npm.min_release_age"), "{err}");
        assert!(err.contains("3x"), "{err}");
    }
}

/// The line a reload logs about keys it leaves for a restart, if it logs one.
fn restart_warning(log: &str) -> Option<&str> {
    log.lines()
        .find(|line| line.contains("WARN") && line.contains("restart"))
}

/// A reload does not apply the quarantine: the handlers read it from the
/// configuration NORA started with. A SIGHUP that changes it says so, naming
/// each changed key, the global ones and a registry's own, and only those.
#[tokio::test]
async fn a_reload_that_changes_the_quarantine_warns_it_waits_for_a_restart() {
    use crate::digest_quarantine::QuarantineMode;
    let ctx =
        crate::test_helpers::create_test_context_with_config(crate::test_helpers::quarantine_7d);
    let (log, _capture) = crate::test_helpers::LogCapture::start();
    crate::test_helpers::reload_curation(&ctx, |config| {
        config.curation.quarantine_ttl = Some("14d".to_string());
        config.curation.npm.quarantine = Some(QuarantineMode::Observe);
        config.curation.pub_dart.quarantine_ttl = Some("1d".to_string());
    });

    let text = log.text();
    let warning = restart_warning(&text)
        .unwrap_or_else(|| panic!("no restart warning after a quarantine change:\n{text}"));
    for key in [
        "curation.quarantine_ttl",
        "curation.npm.quarantine",
        "curation.pub.quarantine_ttl",
    ] {
        assert!(warning.contains(&format!("\"{key}\"")), "{key}: {warning}");
    }
    for unchanged in ["curation.quarantine", "curation.npm.quarantine_ttl"] {
        assert!(
            !warning.contains(&format!("\"{unchanged}\"")),
            "{unchanged} did not change: {warning}"
        );
    }
}

/// `min_release_age`, global or a registry's own, is in the engine a reload
/// builds: a SIGHUP that changes only it applies it and warns of no restart.
#[tokio::test]
async fn a_reload_that_changes_only_the_release_age_warns_of_no_restart() {
    let ctx =
        crate::test_helpers::create_test_context_with_config(crate::test_helpers::quarantine_7d);
    let npm = crate::curation::RegistryType::Npm;
    assert!(!ctx.state.curation().curation_engine.reads_release_date(npm));
    let (log, _capture) = crate::test_helpers::LogCapture::start();
    crate::test_helpers::reload_curation(&ctx, |config| {
        config.curation.min_release_age = Some("3d".to_string());
        config.curation.npm.min_release_age = Some("1d".to_string());
    });

    let text = log.text();
    assert_eq!(restart_warning(&text), None, "{text}");
    assert!(
        ctx.state.curation().curation_engine.reads_release_date(npm),
        "the reload did not install the release-age rule"
    );
}

/// The settings a reload leaves for a restart, decided from the two configurations alone:
/// a quarantine key set, changed or removed — globally and in each registry's own
/// section — is named, by the key config.toml spells it with; an unchanged one, and every
/// key a reload applies (the engine's and the bypass token), is not.
#[test]
fn a_reload_names_each_quarantine_setting_it_leaves_for_a_restart() {
    use crate::curation::RegistryType;
    let curation = |text: &str| {
        toml::from_str::<Config>(text)
            .unwrap_or_else(|e| panic!("{text}: {e}"))
            .curation
    };
    let unapplied = |started: &str, loaded: &str| {
        super::HeldQuarantine::of(&curation(started)).unapplied(&curation(loaded))
    };
    let none: Vec<String> = Vec::new();
    let plain = "[curation]\nmode = \"enforce\"\n";
    let set = format!("{plain}quarantine = \"enforce\"\nquarantine_ttl = \"7d\"\n");
    let other = format!("{plain}quarantine = \"observe\"\nquarantine_ttl = \"3d\"\n");
    let both = ["curation.quarantine", "curation.quarantine_ttl"];
    for (started, loaded, want, row) in [
        (plain, plain.to_string(), none.clone(), "global: neither"),
        (&set, set.clone(), none.clone(), "global: unchanged"),
        (plain, set.clone(), both.map(String::from).to_vec(), "global: set"),
        (&set, plain.to_string(), both.map(String::from).to_vec(), "global: removed"),
        (&set, other.clone(), both.map(String::from).to_vec(), "global: changed"),
        (
            &set,
            format!("{plain}quarantine = \"enforce\"\n"),
            vec!["curation.quarantine_ttl".to_string()],
            "global: ttl removed alone",
        ),
        (
            plain,
            "[curation]\nmode = \"audit\"\nallowlist_path = \"a.json\"\nblocklist_path = \"b.json\"\n\
                 require_integrity = true\ninternal_namespaces = [\"corp/*\"]\nmin_release_age = \"1d\"\n\
                 [curation.npm]\nmin_release_age = \"2d\"\n"
                .to_string(),
            none.clone(),
            "keys a reload applies",
        ),
    ] {
        assert_eq!(unapplied(started, &loaded), want, "{row}");
    }
    for &rt in RegistryType::all() {
        if curation(plain).registry_override(rt).is_none() {
            continue;
        }
        let own = |body: &str| format!("{plain}[curation.{rt}]\n{body}");
        let set = own("quarantine = \"enforce\"\nquarantine_ttl = \"7d\"\n");
        let other = own("quarantine = \"off\"\nquarantine_ttl = \"1d\"\n");
        let keys = vec![
            format!("curation.{rt}.quarantine"),
            format!("curation.{rt}.quarantine_ttl"),
        ];
        for (started, loaded, want, row) in [
            (set.clone(), set.clone(), none.clone(), "unchanged"),
            (plain.to_string(), set.clone(), keys.clone(), "set"),
            (set.clone(), plain.to_string(), keys.clone(), "removed"),
            (set.clone(), other.clone(), keys.clone(), "changed"),
            (
                set.clone(),
                own("quarantine = \"enforce\"\n"),
                vec![format!("curation.{rt}.quarantine_ttl")],
                "ttl removed alone",
            ),
        ] {
            assert_eq!(unapplied(&started, &loaded), want, "{rt}: {row}");
        }
    }
}

/// What a SIGHUP installs is the engine of the file it reads: a release-age rule the file
/// brings in applies from then on, one the file drops no longer does, and a file that does
/// not load leaves the running engine in place.
#[test]
fn a_reload_installs_the_engine_of_the_file_it_reads() {
    use crate::curation::RegistryType;
    let slot = arc_swap::ArcSwap::from_pointee(super::ReloadableConfig {
        curation_engine: build_curation_engine(&enforce()).unwrap(),
        bypass_token: None,
    });
    let reads = |slot: &arc_swap::ArcSwap<super::ReloadableConfig>| {
        RegistryType::all()
            .iter()
            .filter(|&&rt| slot.load().curation_engine.reads_release_date(rt))
            .count()
    };
    let all = RegistryType::all().len();
    let held = super::HeldQuarantine::of(&enforce().curation);
    assert_eq!(reads(&slot), 0, "started without a release-age rule");
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("config.toml");
    let file = Some(path.to_string_lossy().into_owned());
    // The reload applies the env overrides, so no other test may change them meanwhile.
    let _lock = crate::test_env::env_lock();
    for (text, loads, want, why) in [
        (
            "[curation]\nmode = \"enforce\"\nquarantine = \"observe\"\nmin_release_age = \"1h\"\n",
            true,
            all,
            "brought in",
        ),
        (
            "[curation]\nmode = \"enforce\"\nquarantine = \"observe\"\n",
            true,
            0,
            "dropped",
        ),
        (
            "[curation]\nmode = \"enforce\"\nquarantine = \"observe\"\n[curation.npm]\nmin_release_age = \"1h\"\n",
            true,
            1,
            "npm's own",
        ),
        (
            "[curation\nmode = \"enforce\"\n",
            false,
            1,
            "a file that does not parse keeps npm's",
        ),
    ] {
        std::fs::write(&path, text).unwrap();
        let reloaded = super::reload_curation(&slot, &held, file.clone());
        assert_eq!(reloaded.is_ok(), loads, "{why}: {reloaded:?}");
        assert_eq!(reads(&slot), want, "{why}");
    }
    assert!(slot
        .load()
        .curation_engine
        .reads_release_date(RegistryType::Npm));
}
