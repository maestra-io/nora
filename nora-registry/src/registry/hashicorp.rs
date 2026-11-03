// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! HashiCorp releases proxy (maestra): product archives of releases.hashicorp.com,
//! pull-through only, so CI and image builds take `terraform`, `vault`, `consul`…
//! through NORA's curation.
//!
//!   GET /hashicorp/{product}/{version}/{file}
//!
//! The same path as on releases.hashicorp.com: a client swaps
//! `https://releases.hashicorp.com` for `https://nora.example.com/hashicorp`.
//!
//! Every download first reads the version's record, cached under `hashicorp/meta/` for
//! `metadata_ttl` (stale on upstream error): `timestamp_created` from the releases API
//! (`/v1/releases/{product}/{version}`) is the release date for `min_release_age`
//! (`[curation.hashicorp]`, package = product, version = version) and, with
//! `server.trust_upstream_dates`, the quarantine's first seen; the version's
//! `{product}_{version}_SHA256SUMS` names every file and its sha256. A file it does not
//! list is a 404 and never fetched, a body that differs from its sum is a 502, and the
//! `SHA256SUMS` file itself is served as NORA read it. Files are fetched only from
//! `download_url` through the SSRF guard (redirects pinned to the download and API
//! hosts), cached under `hashicorp/releases/{product}/{version}/` and held by the
//! first-seen digest quarantine. The shared machinery is in `registry/github.rs`.

use crate::registry::github::{
    fetch_record, hex_sha256, hosts_of, is_valid_asset, join_segments, load_record, quarantine,
    serve_asset, Asset, Upstream,
};
use crate::registry::ProxyError;
use crate::registry_type::RegistryType;
use crate::AppState;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::BTreeMap;

/// Cached files, one directory per product.
pub const INDEX_PATTERN: (&str, &str) = ("hashicorp/releases/", "");

pub fn routes() -> Router<AppState> {
    Router::new().route("/hashicorp/{product}/{version}/{file}", get(file))
}

/// What NORA keeps of a version: its date and the sha256 of every file.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
struct Version {
    created: Option<String>,
    /// File name → hex sha256: the `SHA256SUMS` lines, plus that file itself.
    files: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct ApiVersion {
    timestamp_created: Option<String>,
}

/// A product name: lowercase letters, digits and `-`.
fn is_valid_product(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A version: letters, digits, `.`, `-`, `+`, starting with a digit.
fn is_valid_version(s: &str) -> bool {
    s.len() <= 64
        && s.starts_with(|c: char| c.is_ascii_digit())
        && !s.contains("..")
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
}

/// `<sha256>  <file>` lines; anything else is skipped.
fn parse_sums(body: &[u8]) -> BTreeMap<String, String> {
    String::from_utf8_lossy(body)
        .lines()
        .filter_map(|line| {
            let (sum, file) = line.split_once(char::is_whitespace)?;
            let file = file.trim_start().trim_start_matches('*');
            Some((file.to_string(), hex_sha256(sum)?))
        })
        .filter(|(file, _)| is_valid_asset(file))
        .collect()
}

fn hashicorp_upstream(state: &AppState) -> Upstream {
    let cfg = &state.config.hashicorp;
    Upstream {
        allow_private: cfg.allow_private_hosts,
        timeout: cfg.proxy_timeout,
        hosts: hosts_of(&[&cfg.download_url, &cfg.api_url], &[]),
    }
}

async fn file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((product, version, file)): Path<(String, String, String)>,
) -> Response {
    if !(is_valid_product(&product) && is_valid_version(&version) && is_valid_asset(&file)) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let engine = &state.curation().curation_engine;
    if let Some(response) =
        crate::curation::check_namespace_isolation(engine, RegistryType::Hashicorp, &product)
    {
        return response;
    }

    let cfg = &state.config.hashicorp;
    let up = hashicorp_upstream(&state);
    let key = format!("hashicorp/meta/{product}/{version}.json");
    let record: Version = match load_record(&state, "hashicorp", &key, cfg.metadata_ttl, || async {
        let bad = |url: &str| (url.to_string(), ProxyError::Upstream(502));
        let api = join_segments(&cfg.api_url, &["v1", "releases", &product, &version])
            .ok_or_else(|| bad(&cfg.api_url))?;
        let body = fetch_record(&state, &up, RegistryType::Hashicorp, &api, None).await?;
        let created = serde_json::from_slice::<ApiVersion>(&body)
            .map_err(|e| {
                tracing::warn!(url = %api, error = %e, "hashicorp: release record unreadable");
                bad(&api)
            })?
            .timestamp_created;
        let sums_file = format!("{product}_{version}_SHA256SUMS");
        let sums_url = join_segments(&cfg.download_url, &[&product, &version, &sums_file])
            .ok_or_else(|| bad(&cfg.download_url))?;
        let sums = fetch_record(&state, &up, RegistryType::Hashicorp, &sums_url, None).await?;
        let mut files = parse_sums(&sums);
        if files.is_empty() {
            tracing::warn!(url = %sums_url, "hashicorp: SHA256SUMS lists no file");
            return Err(bad(&sums_url));
        }
        files.insert(sums_file, hex::encode(sha2::Sha256::digest(&sums)));
        Ok(Version { created, files })
    })
    .await
    {
        Ok(record) => record,
        Err(response) => return response,
    };
    let Some(expected) = record.files.get(&file).cloned() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(url) = join_segments(&cfg.download_url, &[&product, &version, &file]) else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    serve_asset(
        &state,
        &headers,
        Asset {
            registry: RegistryType::Hashicorp,
            name: &product,
            version: &version,
            published: record
                .created
                .as_deref()
                .and_then(crate::curation::parse_iso8601_to_unix),
            expected: Some(expected),
            key: format!("hashicorp/releases/{product}/{version}/{file}"),
            label: format!("{product}@{version}/{file}"),
            url,
            upstream: &up,
            breaker_base: &cfg.download_url,
            quarantine: quarantine(&state, &state.config.curation.hashicorp),
        },
    )
    .await
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn validates_path_parts() {
        assert!(is_valid_product("terraform") && is_valid_product("consul-template"));
        assert!(!is_valid_product("Terraform") && !is_valid_product("a/b"));
        for v in ["1.9.8", "1.10.0-rc1", "1.18.1+ent"] {
            assert!(is_valid_version(v), "{v}");
        }
        for v in ["", "v1.9.8", "1..2", "1.0/2"] {
            assert!(!is_valid_version(v), "{v}");
        }
    }

    #[test]
    fn reads_sha256sums() {
        let a = "a".repeat(64);
        let body = format!(
            "{a}  terraform_1.9.8_linux_amd64.zip\n{a} *t_1_darwin.zip\nbad line\nxyz  x.zip\n"
        );
        let sums = parse_sums(body.as_bytes());
        assert_eq!(sums.len(), 2);
        assert_eq!(sums["terraform_1.9.8_linux_amd64.zip"], a);
        assert!(sums.contains_key("t_1_darwin.zip"));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use crate::config::CurationMode;
    use crate::test_helpers::*;
    use axum::http::{Method, StatusCode};
    use sha2::Digest;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn hashicorp(created: &str, zip: &[u8], listed: &[u8]) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/releases/terraform/1.9.8"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"timestamp_created": created})),
            )
            .mount(&server)
            .await;
        let sums = format!(
            "{}  terraform_1.9.8_linux_amd64.zip\n",
            hex::encode(sha2::Sha256::digest(listed))
        );
        Mock::given(method("GET"))
            .and(path("/dl/terraform/1.9.8/terraform_1.9.8_SHA256SUMS"))
            .respond_with(ResponseTemplate::new(200).set_body_string(sums))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/dl/terraform/1.9.8/terraform_1.9.8_linux_amd64.zip"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(zip.to_vec()))
            .mount(&server)
            .await;
        server
    }

    fn configure(cfg: &mut crate::config::Config, server: &MockServer) {
        cfg.hashicorp.enabled = true;
        cfg.hashicorp.api_url = format!("{}/api", server.uri());
        cfg.hashicorp.download_url = format!("{}/dl", server.uri());
        // mock upstreams listen on loopback
        cfg.hashicorp.allow_private_hosts = true;
    }

    const ZIP: &str = "/hashicorp/terraform/1.9.8/terraform_1.9.8_linux_amd64.zip";

    #[tokio::test]
    async fn serves_listed_files_and_the_sums_file() {
        let server = hashicorp("2024-10-16T14:25:00.739Z", b"zip", b"zip").await;
        let ctx = create_test_context_with_config(|cfg| configure(cfg, &server));
        let resp = send(&ctx.app, Method::GET, ZIP, "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await, b"zip".as_slice());
        let resp = send(
            &ctx.app,
            Method::GET,
            "/hashicorp/terraform/1.9.8/terraform_1.9.8_SHA256SUMS",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(String::from_utf8(body_bytes(resp).await.to_vec())
            .unwrap()
            .ends_with("terraform_1.9.8_linux_amd64.zip\n"));
        for uri in [
            "/hashicorp/terraform/1.9.8/terraform_1.9.8_windows_amd64.zip",
            "/hashicorp/Terraform/1.9.8/x.zip",
            "/hashicorp/terraform/v1.9.8/x.zip",
        ] {
            let resp = send(&ctx.app, Method::GET, uri, "").await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{uri}");
        }
    }

    #[tokio::test]
    async fn a_file_that_differs_from_its_sum_is_refused() {
        let server = hashicorp("2024-10-16T14:25:00.739Z", b"evil", b"zip").await;
        let ctx = create_test_context_with_config(|cfg| configure(cfg, &server));
        let resp = send(&ctx.app, Method::GET, ZIP, "").await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn min_release_age_dates_by_timestamp_created() {
        let young = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();
        for (created, want) in [
            (young.as_str(), StatusCode::FORBIDDEN),
            ("2024-10-16T14:25:00.739Z", StatusCode::OK),
        ] {
            let server = hashicorp(created, b"zip", b"zip").await;
            let ctx = create_test_context_with_config(|cfg| {
                configure(cfg, &server);
                cfg.curation.mode = CurationMode::Enforce;
                cfg.curation.hashicorp.min_release_age = Some("3d".into());
            });
            let resp = send(&ctx.app, Method::GET, ZIP, "").await;
            assert_eq!(resp.status(), want, "created {created}");
        }
    }
}
