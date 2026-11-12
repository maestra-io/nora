// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use super::PEP691_JSON;
use crate::digest_quarantine::QuarantineMode;
use crate::test_helpers::TestContext;
use crate::test_helpers::{
    create_test_context_with_config, reload_curation, send, send_with_headers,
};
use axum::http::{Method, StatusCode};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// What pip 22.0 sends for the index.
const PIP_HTML: &str = "text/html";

/// An upstream index for `foo` listing `files` (filename, upload-time); `json` is the
/// body its PEP 691 request gets, `None` for an upstream that answers it with HTML.
async fn upstream(files: &[(&str, Option<&str>)], json: bool) -> MockServer {
    let up = MockServer::start().await;
    let uri = up.uri();
    let links: String = files
        .iter()
        .map(|(f, _)| format!(r#"<a href="{uri}/files/{f}">{f}</a>"#))
        .collect();
    let html = format!("<html><body>{links}</body></html>");
    if json {
        let entries: Vec<serde_json::Value> = files
            .iter()
            .map(|(f, ut)| match ut {
                Some(ut) => serde_json::json!({"filename": f, "url": format!("{uri}/files/{f}"), "hashes": {}, "upload-time": ut}),
                None => serde_json::json!({"filename": f, "url": format!("{uri}/files/{f}"), "hashes": {}}),
            })
            .collect();
        let body =
            serde_json::json!({"meta": {"api-version": "1.1"}, "name": "foo", "files": entries});
        Mock::given(method("GET"))
            .and(path("/foo/"))
            .and(header("accept", PEP691_JSON))
            .respond_with(ResponseTemplate::new(200).set_body_string(body.to_string()))
            .mount(&up)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/foo/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(html))
        .mount(&up)
        .await;
    for (f, _) in files {
        Mock::given(method("GET"))
            .and(path(format!("/files/{f}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(format!("BYTES {f}")))
            .mount(&up)
            .await;
    }
    up
}

fn context(
    up: &MockServer,
    trust: bool,
    customize: impl FnOnce(&mut crate::config::Config),
) -> TestContext {
    let uri = up.uri();
    create_test_context_with_config(move |cfg| {
        cfg.pypi.proxy = Some(uri);
        cfg.server.trust_upstream_dates = trust;
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        customize(cfg);
    })
}

fn min_age(cfg: &mut crate::config::Config) {
    cfg.curation.min_release_age = Some("3d".to_string());
}

/// The index the client reads, then the download it makes from it.
async fn index_then_download(ctx: &TestContext, accept: &str, file: &str) -> StatusCode {
    let index = send_with_headers(
        &ctx.app,
        Method::GET,
        "/simple/foo/",
        vec![("Accept", accept)],
        "",
    )
    .await;
    assert_eq!(index.status(), StatusCode::OK);
    send(&ctx.app, Method::GET, &format!("/simple/foo/{file}"), "")
        .await
        .status()
}

/// `dates.json` as an earlier request cached it `days` ago.
async fn cached_listing(ctx: &TestContext, body: &str, days: u64) {
    ctx.state
        .storage
        .put("pypi/foo/dates.json", body.as_bytes())
        .await
        .unwrap();
    let then = std::time::SystemTime::now() - std::time::Duration::from_secs(days * 86400);
    std::fs::File::options()
        .write(true)
        .open(std::path::Path::new(&ctx.state.config.storage.path).join("pypi/foo/dates.json"))
        .unwrap()
        .set_modified(then)
        .unwrap();
}

fn hour_ago() -> String {
    (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339()
}

#[tokio::test]
async fn an_html_client_is_held_like_a_json_client() {
    for accept in [PIP_HTML, PEP691_JSON] {
        let up = upstream(&[("foo-1.0.tar.gz", Some("2019-01-01T00:00:00Z"))], true).await;
        let ctx = context(&up, false, min_age);
        assert_eq!(
            index_then_download(&ctx, accept, "foo-1.0.tar.gz").await,
            StatusCode::FORBIDDEN,
            "{accept}: a file NORA first saw just now is younger than 3d on its own clock"
        );
    }
}

/// Requests the upstream got for the JSON listing, which NORA asks for the dates.
async fn json_listings(up: &MockServer) -> usize {
    up.received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| {
            r.url.path() == "/foo/"
                && r.headers.get("accept").and_then(|v| v.to_str().ok()) == Some(PEP691_JSON)
        })
        .count()
}

/// The listing is asked for on a download only when a release-age rule reads the date:
/// with none, or with curation off, the download asks the upstream nothing more.
#[tokio::test]
async fn a_download_asks_for_the_dates_only_when_a_release_age_rule_reads_them() {
    type Setup = fn(&mut crate::config::Config);
    let cases: [(&str, Setup, usize); 4] = [
        ("enforce, no rule", |_| {}, 0),
        (
            "off, rule set",
            |cfg| {
                cfg.curation.mode = crate::config::CurationMode::Off;
                cfg.curation.min_release_age = Some("3d".to_string());
            },
            0,
        ),
        ("enforce, global rule", min_age, 1),
        (
            "enforce, pypi rule",
            |cfg| {
                cfg.curation.pypi.min_release_age = Some("3d".to_string());
            },
            1,
        ),
    ];
    for (name, setup, want) in cases {
        let up = upstream(&[("foo-1.0.tar.gz", Some("2019-01-01T00:00:00Z"))], true).await;
        let ctx = context(&up, false, setup);
        // A release-age rule filters the index too, which reads the dates there: the
        // HTML client's index and download together ask for them once, or never.
        let before = json_listings(&up).await;
        let index = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/foo/",
            vec![("Accept", PIP_HTML)],
            "",
        )
        .await;
        assert_eq!(index.status(), StatusCode::OK);
        let _ = send(&ctx.app, Method::GET, "/simple/foo/foo-1.0.tar.gz", "").await;
        assert_eq!(json_listings(&up).await - before, want, "{name}");
    }
}

/// A release-age rule a reload brings in reads the dates from then on: the engine the reload
/// installs decides, not the configuration NORA started with — the global rule and PyPI's own
/// alike.
#[tokio::test]
async fn a_release_age_rule_a_reload_brings_in_asks_for_the_dates() {
    type Setup = fn(&mut crate::config::Config);
    // A release-age rule on a proxy needs a quarantine: a reload without one is refused.
    fn observe(cfg: &mut crate::config::Config) {
        cfg.curation.quarantine = Some(crate::digest_quarantine::QuarantineMode::Observe);
    }
    let rules: [(&str, Setup); 2] = [
        ("global", |cfg| {
            min_age(cfg);
            observe(cfg);
        }),
        ("PyPI's own", |cfg| {
            cfg.curation.pypi.min_release_age = Some("3d".to_string());
            observe(cfg);
        }),
    ];
    for (rule, add) in rules {
        let up = upstream(&[("foo-1.0.tar.gz", Some("2019-01-01T00:00:00Z"))], true).await;
        let ctx = context(&up, false, |_| {});
        reload_curation(&ctx, add);
        // Maestra: the rule filters the HTML index too (as at start, above), so the index and
        // the download together ask for the dates once.
        let before = json_listings(&up).await;
        let index = send_with_headers(
            &ctx.app,
            Method::GET,
            "/simple/foo/",
            vec![("Accept", PIP_HTML)],
            "",
        )
        .await;
        assert_eq!(index.status(), StatusCode::OK);
        assert_eq!(
            send(&ctx.app, Method::GET, "/simple/foo/foo-1.0.tar.gz", "")
                .await
                .status(),
            StatusCode::FORBIDDEN,
            "{rule}: a file NORA first saw just now is younger than 3d on its own clock"
        );
        assert_eq!(json_listings(&up).await - before, 1, "{rule}");
    }
}

#[tokio::test]
async fn an_html_client_gets_a_file_nora_listed_long_ago() {
    let up = upstream(&[("foo-1.0.tar.gz", Some("2019-01-01T00:00:00Z"))], true).await;
    let ctx = context(&up, false, min_age);
    cached_listing(&ctx, r#"{"foo-1.0.tar.gz":"2019-01-01T00:00:00Z"}"#, 30).await;
    assert_eq!(
        index_then_download(&ctx, PIP_HTML, "foo-1.0.tar.gz").await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn an_html_client_gets_the_upstream_date_when_dates_are_trusted() {
    let fresh = hour_ago();
    let up = upstream(
        &[
            ("foo-1.0.tar.gz", Some("2019-01-01T00:00:00Z")),
            ("foo-2.0.tar.gz", Some(fresh.as_str())),
        ],
        true,
    )
    .await;
    let ctx = context(&up, true, min_age);
    assert_eq!(
        index_then_download(&ctx, PIP_HTML, "foo-2.0.tar.gz").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        index_then_download(&ctx, PIP_HTML, "foo-1.0.tar.gz").await,
        StatusCode::OK
    );
}

/// Without trusted dates the quarantine counts from NORA's first fetch of a file, whether
/// or not a cached listing names it: the listing's age says when NORA wrote it, not when it
/// first fetched these bytes.
#[tokio::test]
async fn without_trusted_dates_a_cached_listing_does_not_date_the_quarantine() {
    let up = upstream(
        &[
            ("foo-1.0.tar.gz", Some("2019-01-01T00:00:00Z")),
            ("foo-2.0.tar.gz", Some("2019-01-02T00:00:00Z")),
        ],
        true,
    )
    .await;
    let ctx = context(&up, false, |cfg| {
        cfg.curation.quarantine = Some(QuarantineMode::Enforce);
        cfg.curation.quarantine_ttl = Some("7d".to_string());
    });
    cached_listing(&ctx, r#"{"foo-1.0.tar.gz":"2019-01-01T00:00:00Z"}"#, 30).await;
    for file in ["foo-2.0.tar.gz", "foo-1.0.tar.gz"] {
        assert_eq!(
            index_then_download(&ctx, PIP_HTML, file).await,
            StatusCode::FORBIDDEN,
            "{file}: first fetched now, held for 7d whatever the listing's age"
        );
    }
}

/// A file cached before the quarantine recorded it is counted from now on the cache path.
/// Maestra: a proxy cache copy carries its provenance marker; one without it is hosted.
#[tokio::test]
async fn a_file_cached_before_the_quarantine_saw_it_counts_from_now() {
    let up = upstream(&[("foo-1.0.tar.gz", Some("2019-01-01T00:00:00Z"))], true).await;
    let ctx = context(&up, false, |cfg| {
        cfg.curation.quarantine = Some(QuarantineMode::Enforce);
        cfg.curation.quarantine_ttl = Some("7d".to_string());
    });
    cached_listing(&ctx, r#"{"foo-1.0.tar.gz":"2019-01-01T00:00:00Z"}"#, 30).await;
    let key = "pypi/foo/foo-1.0.tar.gz";
    ctx.state
        .storage
        .put(key, b"BYTES foo-1.0.tar.gz")
        .await
        .unwrap();
    ctx.state
        .storage
        .put(&super::proxied_marker_key(key), b"")
        .await
        .unwrap();
    assert_eq!(
        send(&ctx.app, Method::GET, "/simple/foo/foo-1.0.tar.gz", "")
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert!(!crate::test_helpers::upstream_paths(&up)
        .await
        .iter()
        .any(|p| p.starts_with("/files/")));
}

/// R4-C05: the ledger forgets a digest 90 days after its first sight. A file cached for
/// longer than that is not held for a new TTL by the first cache hit after a restart.
#[tokio::test]
async fn a_file_cached_past_the_ledgers_memory_is_not_held_again() {
    let up = upstream(&[("foo-1.0.tar.gz", Some("2019-01-01T00:00:00Z"))], true).await;
    let ctx = context(&up, false, |cfg| {
        cfg.curation.quarantine = Some(QuarantineMode::Enforce);
        cfg.curation.quarantine_ttl = Some("7d".to_string());
    });
    cached_listing(&ctx, r#"{"foo-1.0.tar.gz":"2019-01-01T00:00:00Z"}"#, 30).await;
    let key = "pypi/foo/foo-1.0.tar.gz";
    crate::test_helpers::put_written_days_ago(&ctx, key, b"BYTES foo-1.0.tar.gz", 100).await;
    ctx.state
        .storage
        .put(&super::proxied_marker_key(key), b"")
        .await
        .unwrap();
    for _ in 0..2 {
        assert_eq!(
            send(&ctx.app, Method::GET, "/simple/foo/foo-1.0.tar.gz", "")
                .await
                .status(),
            StatusCode::OK
        );
    }
}

/// With trusted dates the upload time seeds the quarantine (#750): a file uploaded years
/// ago is not held as new to this mirror.
#[tokio::test]
async fn with_trusted_dates_an_old_release_matures_in_the_quarantine() {
    let up = upstream(&[("foo-1.0.tar.gz", Some("2019-01-01T00:00:00Z"))], true).await;
    let ctx = context(&up, true, |cfg| {
        cfg.curation.quarantine = Some(QuarantineMode::Enforce);
        cfg.curation.quarantine_ttl = Some("7d".to_string());
    });
    assert_eq!(
        index_then_download(&ctx, PIP_HTML, "foo-1.0.tar.gz").await,
        StatusCode::OK
    );
}

/// An upstream index without PEP 700 dates (devpi, Artifactory) or without PEP 691 at
/// all (it answers the JSON request with its HTML) still lists the file.
#[tokio::test]
async fn an_upstream_without_dates_still_lists_the_file() {
    for json in [true, false] {
        let up = upstream(&[("foo-1.0.tar.gz", None)], json).await;
        let ctx = context(&up, false, min_age);
        assert_eq!(
            index_then_download(&ctx, PIP_HTML, "foo-1.0.tar.gz").await,
            StatusCode::FORBIDDEN,
            "json={json}"
        );
    }
}

/// An upstream that lists the file without a date does not stop the search: the
/// date comes from the next upstream that has one, as when the first listed nothing.
#[tokio::test]
async fn a_listing_without_dates_does_not_hide_a_later_upstreams_date() {
    let fresh = hour_ago();
    let undated = upstream(&[("foo-1.0.tar.gz", None)], true).await;
    let dated = upstream(&[("foo-1.0.tar.gz", Some(fresh.as_str()))], true).await;
    let urls = vec![undated.uri(), dated.uri()];
    let ctx = context(&undated, true, move |cfg| {
        cfg.pypi.proxies = serde_json::from_value(serde_json::json!(urls)).unwrap();
        min_age(cfg);
    });
    assert_eq!(
        index_then_download(&ctx, PIP_HTML, "foo-1.0.tar.gz").await,
        StatusCode::FORBIDDEN
    );
}

/// A cache hit with no listing cached (a hosted package, or a file cached by an earlier
/// version) must not start asking an upstream on every download.
#[tokio::test]
async fn a_cache_hit_does_not_fetch_the_listing() {
    let up = upstream(&[("foo-1.0.tar.gz", None)], true).await;
    let ctx = context(&up, false, min_age);
    ctx.state
        .storage
        .put("pypi/foo/foo-1.0.tar.gz", b"LOCAL")
        .await
        .unwrap();
    let resp = send(&ctx.app, Method::GET, "/simple/foo/foo-1.0.tar.gz", "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(up.received_requests().await.unwrap().is_empty());
}
