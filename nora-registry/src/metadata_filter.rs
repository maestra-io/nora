// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Q04: hide versions younger than `curation.min_release_age` from package metadata.
//!
//! The download gate alone answers a client that resolved a range to a fresh version
//! with a 403, so `npm install express` failed instead of picking the newest allowed
//! release. Each format's metadata handler passes its proxied (non-internal,
//! non-hosted) response through here; versions that
//! [`CurationEngine::hides_from_metadata`] rejects are removed on SERVE. The cache
//! keeps the upstream original, so a version shows up as soon as it ages in, without
//! waiting for the metadata TTL. The download 403 stays as the backstop.
//!
//! The dates are the upstream ones in the document (or its cached companion), used
//! whatever `server.trust_upstream_dates` says: hiding cannot let anything through,
//! so a spoofed date can at worst leave a version visible to the download gates.

use crate::curation::{parse_iso8601_to_unix, CurationEngine, RegistryType};
use axum::body::Body;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::io::{Read, Write};

/// Rewrite a 200 metadata response's body with `filter` (`None` = leave it as is).
/// A gzip-encoded body (NuGet registration) is decoded, filtered and re-encoded.
pub async fn rewrite_body(
    resp: Response,
    filter: impl FnOnce(&[u8]) -> Option<Vec<u8>>,
) -> Response {
    if resp.status() != StatusCode::OK {
        return resp;
    }
    let (mut parts, body) = resp.into_parts();
    // The body is a document nora already holds in memory.
    let bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(b) => b,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let gzip = parts
        .headers
        .get(header::CONTENT_ENCODING)
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"gzip"));
    let plain = if gzip {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(&bytes[..])
            .read_to_end(&mut out)
            .ok()
            .map(|_| out)
    } else {
        Some(bytes.to_vec())
    };
    let Some(filtered) = plain.and_then(|p| filter(&p)) else {
        return Response::from_parts(parts, Body::from(bytes));
    };
    let out = if gzip {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        match enc.write_all(&filtered).and_then(|_| enc.finish()) {
            Ok(z) => z,
            Err(_) => {
                parts.headers.remove(header::CONTENT_ENCODING);
                filtered
            }
        }
    } else {
        filtered
    };
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(out))
}

fn date_of(time: Option<&Map<String, Value>>, key: &str) -> Option<i64> {
    time?.get(key)?.as_str().and_then(parse_iso8601_to_unix)
}

/// The FULL npm packument, parsed once by the caller, which abbreviates it to
/// `install-v1` afterwards (the abbreviated form carries no `time`). Hidden versions
/// leave `versions` and `time`; `latest` moves to the newest allowed release (a
/// pre-release only when no release is left); any other tag on a hidden version is
/// dropped. Whether anything was hidden.
pub fn npm_packument(engine: &CurationEngine, name: &str, doc: &mut Value) -> bool {
    use crate::registry::npm::semver_key as version_key;
    let Some(obj) = doc.as_object_mut() else {
        return false;
    };
    let hidden: HashSet<String> = {
        let time = obj.get("time").and_then(Value::as_object);
        match obj.get("versions").and_then(Value::as_object) {
            Some(versions) => versions
                .keys()
                .filter(|v| {
                    engine.hides_from_metadata(RegistryType::Npm, name, v, date_of(time, v))
                })
                .cloned()
                .collect(),
            None => return false,
        }
    };
    if hidden.is_empty() {
        return false;
    }
    if let Some(versions) = obj.get_mut("versions").and_then(Value::as_object_mut) {
        versions.retain(|v, _| !hidden.contains(v));
    }
    if let Some(time) = obj.get_mut("time").and_then(Value::as_object_mut) {
        time.retain(|v, _| !hidden.contains(v));
    }
    let newest = {
        let kept: Vec<&String> = obj
            .get("versions")
            .and_then(Value::as_object)
            .map(|m| m.keys().collect())
            .unwrap_or_default();
        let best = |stable_only: bool| {
            kept.iter()
                .filter(|v| !stable_only || version_key(v).3)
                .max_by_key(|v| version_key(v))
                .map(|v| v.to_string())
        };
        best(true).or_else(|| best(false))
    };
    if let Some(tags) = obj.get_mut("dist-tags").and_then(Value::as_object_mut) {
        let moved: Vec<String> = tags
            .iter()
            .filter(|(_, v)| v.as_str().is_some_and(|v| hidden.contains(v)))
            .map(|(t, _)| t.clone())
            .collect();
        for tag in moved {
            match (&*tag, &newest) {
                ("latest", Some(v)) => {
                    tags.insert(tag, Value::String(v.clone()));
                }
                _ => {
                    tags.remove(&tag);
                }
            }
        }
    }
    true
}

/// The PyPI files to hide: young by their `dates.json` upload-time (filename → ISO).
fn pypi_hidden(
    engine: &CurationEngine,
    name: &str,
    filenames: impl Iterator<Item = String>,
    dates: &Map<String, Value>,
) -> HashSet<String> {
    filenames
        .filter(|f| {
            let version = crate::curation::parse_pypi_version(name, f);
            let version = version.as_deref().unwrap_or(f);
            engine.hides_from_metadata(RegistryType::PyPI, name, version, date_of(Some(dates), f))
        })
        .collect()
}

/// The filename an anchor line of nora's simple HTML index links to.
fn anchor_filename(line: &str) -> Option<&str> {
    let rest = line.trim_start().strip_prefix("<a ")?;
    let text = &rest[rest.find('>')? + 1..];
    Some(&text[..text.find("</a>")?])
}

/// PyPI simple index, HTML (PEP 503) or JSON (PEP 691): drop young files, and from
/// the JSON `versions` a version none of whose files is left.
pub fn pypi_index(
    engine: &CurationEngine,
    name: &str,
    body: &[u8],
    dates: &Map<String, Value>,
) -> Option<Vec<u8>> {
    if let Ok(mut doc) = serde_json::from_slice::<Value>(body) {
        let files = doc.get_mut("files")?.as_array_mut()?;
        let filename = |f: &Value| f.get("filename").and_then(Value::as_str).map(String::from);
        let hidden = pypi_hidden(engine, name, files.iter().filter_map(filename), dates);
        if hidden.is_empty() {
            return None;
        }
        files.retain(|f| filename(f).is_none_or(|n| !hidden.contains(&n)));
        let kept: HashSet<String> = files
            .iter()
            .filter_map(filename)
            .filter_map(|f| crate::curation::parse_pypi_version(name, &f))
            .collect();
        let gone: HashSet<String> = hidden
            .iter()
            .filter_map(|f| crate::curation::parse_pypi_version(name, f))
            .filter(|v| !kept.contains(v))
            .collect();
        if let Some(versions) = doc.get_mut("versions").and_then(Value::as_array_mut) {
            versions.retain(|v| v.as_str().is_none_or(|v| !gone.contains(v)));
        }
        return serde_json::to_vec(&doc).ok();
    }
    let html = std::str::from_utf8(body).ok()?;
    let hidden = pypi_hidden(
        engine,
        name,
        html.lines().filter_map(anchor_filename).map(String::from),
        dates,
    );
    if hidden.is_empty() {
        return None;
    }
    let kept: Vec<&str> = html
        .split_inclusive('\n')
        .filter(|l| anchor_filename(l).is_none_or(|f| !hidden.contains(f)))
        .collect();
    Some(kept.concat().into_bytes())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::config::{Config, CurationMode};
    use crate::test_helpers::{
        body_bytes, create_test_context_with_config, send, send_with_headers,
    };
    use axum::http::{Method, StatusCode};
    use serde_json::{json, Value};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn iso_ago(secs: i64) -> String {
        (chrono::Utc::now() - chrono::Duration::seconds(secs))
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string()
    }

    const OLD: i64 = 30 * 86400;
    const YOUNG: i64 = 3600;

    fn cooldown(cfg: &mut Config, mode: CurationMode) {
        cfg.curation.mode = mode;
        cfg.curation.min_release_age = Some("7d".to_string());
    }

    async fn json_of(resp: axum::http::Response<axum::body::Body>) -> Value {
        assert_eq!(resp.status(), StatusCode::OK);
        serde_json::from_slice(&body_bytes(resp).await).unwrap()
    }

    // ── npm ──

    async fn npm_upstream() -> MockServer {
        let upstream = MockServer::start().await;
        let v = |n: &str| json!({ "name": "pkg", "version": n, "dist": {} });
        let packument = json!({
            "name": "pkg",
            "dist-tags": { "latest": "1.1.0", "next": "2.0.0-beta.1", "stable": "1.0.0" },
            "versions": { "0.9.0": v("0.9.0"), "1.0.0": v("1.0.0"), "1.1.0": v("1.1.0"), "2.0.0-beta.1": v("2.0.0-beta.1") },
            "time": { "created": iso_ago(OLD), "modified": iso_ago(YOUNG),
                      "0.9.0": iso_ago(OLD + 10), "1.0.0": iso_ago(OLD),
                      "1.1.0": iso_ago(YOUNG), "2.0.0-beta.1": iso_ago(YOUNG) }
        });
        Mock::given(method("GET"))
            .and(path("/pkg"))
            .respond_with(ResponseTemplate::new(200).set_body_json(packument))
            .mount(&upstream)
            .await;
        upstream
    }

    fn version_keys(doc: &Value) -> Vec<String> {
        let mut v: Vec<String> = doc["versions"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        v.sort();
        v
    }

    #[tokio::test]
    async fn npm_packument_hides_young_versions_and_repoints_latest() {
        let upstream = npm_upstream().await;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cooldown(cfg, CurationMode::Enforce);
        });
        let doc = json_of(send(&ctx.app, Method::GET, "/npm/pkg", "").await).await;
        assert_eq!(version_keys(&doc), ["0.9.0", "1.0.0"]);
        assert!(doc["time"].get("1.1.0").is_none());
        assert_eq!(
            doc["dist-tags"],
            json!({ "latest": "1.0.0", "stable": "1.0.0" })
        );

        // The abbreviated form npm install reads: same versions, same tags.
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/npm/pkg",
            vec![("accept", "application/vnd.npm.install-v1+json")],
            "",
        )
        .await;
        let short = json_of(resp).await;
        assert_eq!(version_keys(&short), ["0.9.0", "1.0.0"]);
        assert_eq!(short["dist-tags"]["latest"], "1.0.0");

        // The cache keeps the upstream original: a version shows once it ages in.
        let cached = ctx
            .state
            .storage
            .get("npm/pkg/metadata.json")
            .await
            .unwrap();
        let cached: Value = serde_json::from_slice(&cached).unwrap();
        assert!(cached["versions"].get("1.1.0").is_some());
    }

    #[tokio::test]
    async fn npm_abbreviated_cold_miss_is_filtered() {
        let upstream = npm_upstream().await;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cooldown(cfg, CurationMode::Enforce);
        });
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/npm/pkg",
            vec![("accept", "application/vnd.npm.install-v1+json")],
            "",
        )
        .await;
        let short = json_of(resp).await;
        assert_eq!(version_keys(&short), ["0.9.0", "1.0.0"]);
        assert_eq!(short["dist-tags"]["latest"], "1.0.0");
    }

    /// R2-16: the abbreviated packument served by the TTL refetch that brings a
    /// young version is filtered on that fresh document, not on the cached `time`
    /// that predates the version.
    #[tokio::test]
    async fn npm_abbreviated_ttl_refetch_is_filtered() {
        let upstream = npm_upstream().await;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cfg.npm.metadata_ttl = 0;
            cooldown(cfg, CurationMode::Enforce);
        });
        let v = |n: &str| json!({ "name": "pkg", "version": n, "dist": {} });
        let cached = json!({
            "name": "pkg", "dist-tags": { "latest": "1.0.0" },
            "versions": { "0.9.0": v("0.9.0"), "1.0.0": v("1.0.0") },
            "time": { "0.9.0": iso_ago(OLD + 10), "1.0.0": iso_ago(OLD) }
        });
        ctx.state
            .storage
            .put("npm/pkg/metadata.json", cached.to_string().as_bytes())
            .await
            .unwrap();
        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/npm/pkg",
            vec![("accept", "application/vnd.npm.install-v1+json")],
            "",
        )
        .await;
        let short = json_of(resp).await;
        assert_eq!(version_keys(&short), ["0.9.0", "1.0.0"]);
        assert_eq!(short["dist-tags"]["latest"], "1.0.0");
        // The fresh document is cached before the response.
        let stored = ctx.state.storage.get("npm/pkg/metadata.json").await;
        let stored: Value = serde_json::from_slice(&stored.unwrap()).unwrap();
        assert!(stored["versions"].get("1.1.0").is_some());
    }

    #[tokio::test]
    async fn npm_allowlisted_young_version_stays_visible() {
        let upstream = npm_upstream().await;
        let ctx = create_test_context_with_config(|cfg| {
            cfg.npm.proxy = Some(upstream.uri());
            cooldown(cfg, CurationMode::Enforce);
            cfg.curation.npm.allow = vec!["pkg@1.1.0".to_string()];
        });
        let doc = json_of(send(&ctx.app, Method::GET, "/npm/pkg", "").await).await;
        assert_eq!(version_keys(&doc), ["0.9.0", "1.0.0", "1.1.0"]);
        assert_eq!(doc["dist-tags"]["latest"], "1.1.0");
        assert!(doc["dist-tags"].get("next").is_none());
    }

    #[tokio::test]
    async fn npm_audit_mode_and_internal_packages_are_not_filtered() {
        let upstream = npm_upstream().await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.npm.proxy = Some(uri);
            cooldown(cfg, CurationMode::Audit);
        });
        let doc = json_of(send(&ctx.app, Method::GET, "/npm/pkg", "").await).await;
        assert_eq!(version_keys(&doc).len(), 4, "audit mode only logs");
        assert_eq!(doc["dist-tags"]["latest"], "1.1.0");

        // An internal (operator-owned) package is served as stored.
        let ctx = create_test_context_with_config(|cfg| {
            cooldown(cfg, CurationMode::Enforce);
            cfg.curation.internal_namespaces = vec!["@corp/*".to_string()];
        });
        let own = json!({
            "name": "@corp/lib", "dist-tags": { "latest": "1.0.0" },
            "versions": { "1.0.0": { "version": "1.0.0" } },
            "time": { "1.0.0": iso_ago(60) }
        });
        ctx.state
            .storage
            .put("npm/@corp/lib/metadata.json", own.to_string().as_bytes())
            .await
            .unwrap();
        let doc = json_of(send(&ctx.app, Method::GET, "/npm/@corp%2flib", "").await).await;
        assert_eq!(version_keys(&doc), ["1.0.0"]);
    }

    // ── PyPI ──

    async fn pypi_ctx(
        mode: CurationMode,
        allow: &[&str],
    ) -> (MockServer, crate::test_helpers::TestContext) {
        let upstream = MockServer::start().await;
        let html = "<html><body>\
            <a href=\"/f/pkg-1.0.tar.gz#sha256=aa\">pkg-1.0.tar.gz</a><br>\
            <a href=\"/f/pkg-1.0-py3-none-any.whl#sha256=bb\">pkg-1.0-py3-none-any.whl</a><br>\
            <a href=\"/f/pkg-1.1.tar.gz#sha256=cc\">pkg-1.1.tar.gz</a><br>\
            </body></html>";
        // The dates come with the index, from the upstream's PEP 691 JSON (R2-24).
        let dated = |f: &str, ago: i64| json!({ "filename": f, "upload-time": iso_ago(ago) });
        let pep691 = json!({ "files": [
            dated("pkg-1.0.tar.gz", OLD), dated("pkg-1.0-py3-none-any.whl", OLD),
            dated("pkg-1.1.tar.gz", YOUNG)
        ]});
        Mock::given(method("GET"))
            .and(path("/pkg/"))
            .and(wiremock::matchers::header(
                "accept",
                "application/vnd.pypi.simple.v1+json",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(pep691))
            .mount(&upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/pkg/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(html))
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let allow: Vec<String> = allow.iter().map(|s| s.to_string()).collect();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.pypi.proxy = Some(uri);
            cooldown(cfg, mode);
            cfg.curation.pypi.allow = allow;
        });
        (upstream, ctx)
    }

    async fn simple_html(ctx: &crate::test_helpers::TestContext) -> String {
        let resp = send(&ctx.app, Method::GET, "/simple/pkg/", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        String::from_utf8(body_bytes(resp).await.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn pypi_simple_index_hides_young_files_html_and_json() {
        let (_up, ctx) = pypi_ctx(CurationMode::Enforce, &[]).await;
        let html = simple_html(&ctx).await;
        assert!(html.contains("pkg-1.0.tar.gz") && html.contains("pkg-1.0-py3-none-any.whl"));
        assert!(!html.contains("pkg-1.1.tar.gz"), "{html}");

        let resp = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/pkg/",
            vec![("accept", "application/vnd.pypi.simple.v1+json")],
            "",
        )
        .await;
        let doc = json_of(resp).await;
        let files: Vec<&str> = doc["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["filename"].as_str().unwrap())
            .collect();
        assert_eq!(files.len(), 2, "{files:?}");
        assert!(!files.contains(&"pkg-1.1.tar.gz"));
        assert_eq!(doc["versions"], json!(["1.0"]));
    }

    #[tokio::test]
    async fn pypi_allowlist_and_audit_mode_keep_young_files() {
        let (_up, ctx) = pypi_ctx(CurationMode::Enforce, &["PKG@1.1"]).await;
        assert!(simple_html(&ctx).await.contains("pkg-1.1.tar.gz"));
        let (_up, ctx) = pypi_ctx(CurationMode::Audit, &[]).await;
        assert!(simple_html(&ctx).await.contains("pkg-1.1.tar.gz"));
    }

    #[tokio::test]
    async fn pypi_internal_package_is_not_filtered() {
        let ctx = create_test_context_with_config(|cfg| {
            cooldown(cfg, CurationMode::Enforce);
            cfg.curation.internal_namespaces = vec!["corp-*".to_string()];
        });
        let s = &ctx.state.storage;
        s.put("pypi/corp-lib/corp_lib-1.0.tar.gz", b"sdist")
            .await
            .unwrap();
        let dates = json!({ "corp_lib-1.0.tar.gz": iso_ago(60) });
        s.put("pypi/corp-lib/dates.json", dates.to_string().as_bytes())
            .await
            .unwrap();
        let resp = send(&ctx.app, Method::GET, "/simple/corp-lib/", "").await;
        let html = String::from_utf8(body_bytes(resp).await.to_vec()).unwrap();
        assert!(html.contains("corp_lib-1.0.tar.gz"), "{html}");
    }
}
