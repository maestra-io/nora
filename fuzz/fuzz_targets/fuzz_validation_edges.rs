#![no_main]
use libfuzzer_sys::fuzz_target;
use nora_registry::validation::{
    ends_with_ci, validate_digest, validate_docker_name, validate_docker_reference,
    validate_storage_key,
};

fuzz_target!(|data: &str| {
    // Edge cases fuzz_validation does not reach: `ends_with_ci`, and the validators on
    // compound keys. (Formerly `fuzz_config_toml`, a name it never lived up to: `Config` is
    // compiled into the binary only, so the library the targets link cannot parse it; config
    // parsing is covered by the unit tests in config/tests.rs.)

    // ends_with_ci with arbitrary suffix — must never panic
    let _ = ends_with_ci(data, ".tar.gz");
    let _ = ends_with_ci(data, ".whl");
    let _ = ends_with_ci(data, ".nupkg");
    let _ = ends_with_ci(data, "");
    let _ = ends_with_ci("", data);

    // Validators with pathological inputs
    // Long strings, unicode, null bytes, control chars
    let _ = validate_storage_key(data);
    let _ = validate_docker_name(data);
    let _ = validate_digest(data);
    let _ = validate_docker_reference(data);

    // Compound: path-like strings through storage key
    if data.len() < 512 {
        let compound = format!("docker/{}/manifests/latest", data);
        let _ = validate_storage_key(&compound);
        let maven_path = format!("com/example/{}/1.0/file.jar", data);
        let _ = validate_storage_key(&maven_path);
    }
});
