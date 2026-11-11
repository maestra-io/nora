#![no_main]
use libfuzzer_sys::fuzz_target;
use nora_registry::pypi_fuzz::{extract_filename, parse_upstream_files};
use nora_registry::version_fuzz::parse_pypi_version;

fuzz_target!(|data: &str| {
    // Fuzz PyPI filename extraction from URLs — must never panic
    let _ = extract_filename(data);

    // Fuzz the server's index parser — must never panic on any HTML. A page URL that does not parse leaves hrefs unresolved.
    for page_url in ["https://pypi.org/simple/pkg/", "not a url"] {
        let _ = parse_upstream_files(data, page_url);
    }

    // Fuzz PyPI version parsing from filenames
    let _ = parse_pypi_version("my-package", data);
    let _ = parse_pypi_version("numpy", data);
});
