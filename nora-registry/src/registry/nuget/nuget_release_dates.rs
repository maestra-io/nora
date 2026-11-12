// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]

use crate::digest_quarantine::QuarantineMode;
use crate::test_helpers::{
    create_test_context_with_config, put_written_days_ago, reload_curation, send, upstream_paths,
    TestContext,
};
use axum::http::{Method, StatusCode};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ID: &str = "repro.pkg";
const REGISTRATION: &str = "/v3/registration5-gz-semver2/repro.pkg/index.json";
const UNLISTED: &str = "1900-01-01T00:00:00+00:00";

fn minutes_ago(minutes: i64) -> String {
    (chrono::Utc::now() - chrono::Duration::minutes(minutes)).to_rfc3339()
}

fn leaf(version: &str, published: &str) -> serde_json::Value {
    serde_json::json!({"catalogEntry": {"version": version, "published": published}})
}

fn inline_page(lower: &str, upper: &str, leaves: Vec<serde_json::Value>) -> serde_json::Value {
    serde_json::json!({"lower": lower, "upper": upper, "count": leaves.len(), "items": leaves})
}

/// A page the index names by its bounds only. Its `@id` is on `elsewhere`, a host that is
/// not the configured upstream, at the path the page has there: the page is asked of the
/// configured upstream, so `elsewhere` gets no request.
fn remote_page(elsewhere: &str, lower: &str, upper: &str) -> serde_json::Value {
    serde_json::json!({
        "@id": format!("{elsewhere}/v3/registration5-gz-semver2/{ID}/page/{lower}/{upper}.json"),
        "lower": lower, "upper": upper, "count": 64
    })
}

/// A live host other than the configured upstream, which dates every version a page of it
/// is asked about — both bounds — as old: a page fetched from it lets a new version pass.
/// Tests count only its registration requests: wiremock hands a dropped server on to the
/// next one started, and a background request of an earlier context may still reach it.
async fn elsewhere() -> MockServer {
    let elsewhere = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"/page/[^/]+/[^/]+\.json$"))
        .respond_with(|req: &wiremock::Request| {
            let bounds: Vec<&str> = req.url.path().rsplit('/').take(2).collect();
            let (upper, lower) = (bounds[0].trim_end_matches(".json"), bounds[1]);
            let page = serde_json::json!({
                "lower": lower, "upper": upper,
                "items": [leaf(lower, "2019-01-01T00:00:00Z"), leaf(upper, "2019-01-01T00:00:00Z")]
            });
            ResponseTemplate::new(200).set_body_string(page.to_string())
        })
        .mount(&elsewhere)
        .await;
    elsewhere
}

/// The prefixes a client reaches the NuGet routes by: its own and the aliases.
const PREFIXES: [&str; 3] = ["nuget", "chocolatey", "pwsh"];

fn registration(pages: Vec<serde_json::Value>) -> String {
    serde_json::json!({"count": pages.len(), "items": pages}).to_string()
}

/// An upstream whose every package is its own bytes: two versions never share a digest.
/// Unpooled: wiremock hands a dropped pooled server on to the next one started, and the
/// version-list fetch an earlier context spawned behind a download may still reach it,
/// where a test asserts that it asked the upstream for nothing.
async fn upstream() -> MockServer {
    let upstream = MockServer::builder().start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/v3-flatcontainer/[^/]+/[^/]+/[^/]+\.nupkg$"))
        .respond_with(|req: &wiremock::Request| {
            ResponseTemplate::new(200).set_body_bytes(format!("NUPKG {}", req.url.path()))
        })
        .mount(&upstream)
        .await;
    upstream
}

async fn serve_registration(upstream: &MockServer, at: &str, body: String) {
    Mock::given(method("GET"))
        .and(path(at))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(upstream)
        .await;
}

fn context(
    upstream: &MockServer,
    trust: bool,
    customize: fn(&mut crate::config::Config),
) -> TestContext {
    let uri = upstream.uri();
    create_test_context_with_config(move |cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some(uri);
        cfg.server.trust_upstream_dates = trust;
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        customize(cfg);
    })
}

fn quarantine_7d(cfg: &mut crate::config::Config) {
    cfg.curation.quarantine = Some(QuarantineMode::Enforce);
    cfg.curation.quarantine_ttl = Some("7d".to_string());
}

fn min_age_1h(cfg: &mut crate::config::Config) {
    cfg.curation.min_release_age = Some("1h".to_string());
    cfg.curation.quarantine = Some(QuarantineMode::Observe);
}

fn min_age_1h_quarantine_7d(cfg: &mut crate::config::Config) {
    cfg.curation.min_release_age = Some("1h".to_string());
    quarantine_7d(cfg);
}

/// The registration index as an earlier request cached it `days` ago.
async fn cached_registration(ctx: &TestContext, body: &str, days: u64) {
    let key = format!("nuget/registration/{ID}/index.json");
    ctx.state.storage.put(&key, body.as_bytes()).await.unwrap();
    let then = std::time::SystemTime::now() - std::time::Duration::from_secs(days * 86400);
    std::fs::File::options()
        .write(true)
        .open(std::path::Path::new(&ctx.state.config.storage.path).join(&key))
        .unwrap()
        .set_modified(then)
        .unwrap();
}

async fn download(ctx: &TestContext, version: &str) -> StatusCode {
    download_via(ctx, "nuget", version).await
}

async fn download_via(ctx: &TestContext, prefix: &str, version: &str) -> StatusCode {
    let uri = format!("/{prefix}/v3/flatcontainer/{ID}/{version}/{ID}.{version}.nupkg");
    send(&ctx.app, Method::GET, &uri, "").await.status()
}

async fn registration_requests(upstream: &MockServer) -> usize {
    upstream
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path().starts_with("/v3/registration5-gz-semver2/"))
        .count()
}

/// Without trusted dates the quarantine counts from NORA's own first sight of the bytes: a
/// cached registration's age says when NORA last wrote a listing, not when it first fetched
/// this package, and a month-old index would let a version first fetched now pass as mature.
#[tokio::test]
async fn without_trusted_dates_the_quarantine_counts_from_the_first_fetch() {
    let up = upstream().await;
    let ctx = context(&up, false, quarantine_7d);
    let listed = registration(vec![inline_page(
        "1.2.3",
        "1.2.4",
        vec![
            leaf("1.2.3", "2019-01-01T00:00:00Z"),
            leaf("1.2.4", "2019-01-02T00:00:00Z"),
        ],
    )]);
    cached_registration(&ctx, &listed, 30).await;
    for version in ["1.2.4", "1.2.5"] {
        assert_eq!(
            download(&ctx, version).await,
            StatusCode::FORBIDDEN,
            "{version}: first fetched now, held for 7d whatever the index's age"
        );
    }
}

/// A package cached before the quarantine recorded it is counted from now on the cache path
/// too: without trusted dates neither the month-old registration that lists it nor the
/// package's own age seeds first-seen.
#[tokio::test]
async fn a_package_cached_before_the_quarantine_saw_it_counts_from_now() {
    let up = upstream().await;
    let ctx = context(&up, false, quarantine_7d);
    let listed = registration(vec![inline_page(
        "1.2.4",
        "1.2.4",
        vec![leaf("1.2.4", "2019-01-01T00:00:00Z")],
    )]);
    cached_registration(&ctx, &listed, 30).await;
    put_written_days_ago(
        &ctx,
        &format!("nuget/flatcontainer/{ID}/1.2.4/{ID}.1.2.4.nupkg"),
        b"stored",
        30,
    )
    .await;
    assert_eq!(download(&ctx, "1.2.4").await, StatusCode::FORBIDDEN);
    assert!(
        upstream_paths(&up).await.is_empty(),
        "served from the cache"
    );
}

/// R4-C05: the ledger forgets a digest 90 days after its first sight. A package cached for
/// longer than that is not held for a new TTL by the first cache hit after a restart: its
/// clock is the day NORA wrote the copy.
#[tokio::test]
async fn a_package_cached_past_the_ledgers_memory_is_not_held_again() {
    let up = upstream().await;
    let ctx = context(&up, false, quarantine_7d);
    put_written_days_ago(
        &ctx,
        &format!("nuget/flatcontainer/{ID}/1.2.4/{ID}.1.2.4.nupkg"),
        b"stored",
        100,
    )
    .await;
    for _ in 0..2 {
        assert_eq!(download(&ctx, "1.2.4").await, StatusCode::OK);
    }
    assert!(
        upstream_paths(&up).await.is_empty(),
        "served from the cache"
    );
}

/// With trusted dates a version the cache has no date for is dated by the upstream
/// registration: `dotnet restore` reads only the flat container, so a package published
/// minutes ago would otherwise pass `min_release_age` undated.
#[tokio::test]
async fn an_undated_version_is_dated_by_the_upstream_registration() {
    let up = upstream().await;
    serve_registration(
        &up,
        REGISTRATION,
        registration(vec![inline_page(
            "1.0.0",
            "2.0.0",
            vec![
                leaf("1.0.0", "2019-01-01T00:00:00Z"),
                leaf("2.0.0", &minutes_ago(10)),
            ],
        )]),
    )
    .await;
    let ctx = context(&up, true, min_age_1h);
    assert_eq!(
        download(&ctx, "2.0.0").await,
        StatusCode::FORBIDDEN,
        "published 10 minutes ago, younger than 1h"
    );
    assert_eq!(download(&ctx, "1.0.0").await, StatusCode::OK);
}

/// A release-age rule of NuGet's own reads the date as the global one does: without a
/// global rule or a quarantine, the upstream registration still dates the version.
#[tokio::test]
async fn a_release_age_rule_of_nuget_alone_asks_the_upstream_for_the_date() {
    let up = upstream().await;
    serve_registration(
        &up,
        REGISTRATION,
        registration(vec![inline_page(
            "1.0.0",
            "2.0.0",
            vec![
                leaf("1.0.0", "2019-01-01T00:00:00Z"),
                leaf("2.0.0", &minutes_ago(10)),
            ],
        )]),
    )
    .await;
    let ctx = context(&up, true, |cfg| {
        cfg.curation.nuget.min_release_age = Some("1h".to_string());
    });
    assert_eq!(
        download(&ctx, "2.0.0").await,
        StatusCode::FORBIDDEN,
        "published 10 minutes ago, younger than NuGet's 1h"
    );
    assert_eq!(download(&ctx, "1.0.0").await, StatusCode::OK);
}

/// A cached registration that predates the version does not date it either: the
/// upstream one, which lists it, does.
#[tokio::test]
async fn a_version_newer_than_the_cached_registration_is_dated_by_the_upstream() {
    let up = upstream().await;
    serve_registration(
        &up,
        REGISTRATION,
        registration(vec![inline_page(
            "1.0.0",
            "2.0.0",
            vec![
                leaf("1.0.0", "2019-01-01T00:00:00Z"),
                leaf("2.0.0", &minutes_ago(10)),
            ],
        )]),
    )
    .await;
    let ctx = context(&up, true, min_age_1h);
    let stale = registration(vec![inline_page(
        "1.0.0",
        "1.0.0",
        vec![leaf("1.0.0", "2019-01-01T00:00:00Z")],
    )]);
    cached_registration(&ctx, &stale, 1).await;
    assert_eq!(download(&ctx, "2.0.0").await, StatusCode::FORBIDDEN);
    assert_eq!(download(&ctx, "1.0.0").await, StatusCode::OK);
}

/// Past 128 versions the registration index carries only page bounds: the version's date
/// is on the page whose range holds it, its bounds included.
#[tokio::test]
async fn a_version_on_a_page_the_index_does_not_inline_is_dated_by_that_page() {
    let up = upstream().await;
    let elsewhere = elsewhere().await;
    serve_registration(
        &up,
        REGISTRATION,
        registration(vec![
            remote_page(&elsewhere.uri(), "1.0.0", "1.0.128"),
            remote_page(&elsewhere.uri(), "1.0.129", "1.0.140"),
        ]),
    )
    .await;
    serve_registration(
        &up,
        "/v3/registration5-gz-semver2/repro.pkg/page/1.0.129/1.0.140.json",
        serde_json::json!({
            "lower": "1.0.129", "upper": "1.0.140", "count": 3,
            "items": [
                leaf("1.0.129", &minutes_ago(10)),
                leaf("1.0.130", "2019-01-01T00:00:00Z"),
                leaf("1.0.140", &minutes_ago(10))
            ]
        })
        .to_string(),
    )
    .await;
    let ctx = context(&up, true, min_age_1h);
    assert_eq!(
        download(&ctx, "1.0.129").await,
        StatusCode::FORBIDDEN,
        "lower bound"
    );
    assert_eq!(download(&ctx, "1.0.130").await, StatusCode::OK);
    assert_eq!(
        download(&ctx, "1.0.140").await,
        StatusCode::FORBIDDEN,
        "upper bound"
    );
    let pages: Vec<String> = up
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .map(|r| r.url.path().to_string())
        .filter(|p| p.contains("/page/"))
        .collect();
    assert!(
        pages
            .iter()
            .all(|p| p.ends_with("/page/1.0.129/1.0.140.json")),
        "only the page whose range holds the version is asked for: {pages:?}"
    );
    assert_eq!(registration_requests(&elsewhere).await, 0);
}

/// NuGet publishes an unlisted version as `1900-01-01`: that marks the date unknown, it
/// does not make the version 126 years old, nor as old as the cached document carrying the
/// marker — the index or the page that lists it.
#[tokio::test]
async fn the_unlisted_marker_does_not_date_a_version() {
    let leaves = || {
        vec![
            leaf("0.9.0", "2019-01-01T00:00:00Z"),
            leaf("1.0.0", UNLISTED),
        ]
    };
    for on_page in [false, true] {
        let up = upstream().await;
        let elsewhere = elsewhere().await;
        let ctx = context(&up, true, min_age_1h_quarantine_7d);
        if on_page {
            let index = registration(vec![remote_page(&elsewhere.uri(), "0.9.0", "1.0.0")]);
            cached_registration(&ctx, &index, 30).await;
            let page = serde_json::json!({"lower": "0.9.0", "upper": "1.0.0", "items": leaves()});
            put_written_days_ago(
                &ctx,
                &format!("nuget/registration/{ID}/page/0.9.0/1.0.0.json"),
                page.to_string().as_bytes(),
                30,
            )
            .await;
        } else {
            let index = registration(vec![inline_page("0.9.0", "1.0.0", leaves())]);
            cached_registration(&ctx, &index, 30).await;
        }
        assert_eq!(
            download(&ctx, "1.0.0").await,
            StatusCode::FORBIDDEN,
            "on a page: {on_page}; an undated version is held on NORA's own clock"
        );
        assert_eq!(
            download(&ctx, "0.9.0").await,
            StatusCode::OK,
            "on a page: {on_page}"
        );
        assert_eq!(registration_requests(&up).await, 0, "on a page: {on_page}");
        assert_eq!(
            registration_requests(&elsewhere).await,
            0,
            "on a page: {on_page}"
        );
    }
}

/// A package NORA already stores asks the upstream for no date, whatever case the client
/// spells its path in and whichever prefix it comes by: its digest is recorded, and a cache
/// hit does not pay an upstream round-trip.
#[tokio::test]
async fn a_stored_package_asks_the_upstream_for_no_date() {
    let up = upstream().await;
    let ctx = context(&up, true, min_age_1h);
    for version in ["3.0.0", "3.0.1-beta"] {
        ctx.state
            .storage
            .put(
                &format!("nuget/flatcontainer/{ID}/{version}/{ID}.{version}.nupkg"),
                b"stored",
            )
            .await
            .unwrap();
    }
    for uri in [
        "/nuget/v3/flatcontainer/repro.pkg/3.0.0/repro.pkg.3.0.0.nupkg",
        "/nuget/v3/flatcontainer/Repro.Pkg/3.0.0/Repro.Pkg.3.0.0.nupkg",
        "/nuget/v3/flatcontainer/repro.pkg/3.0.0/REPRO.PKG.3.0.0.NUPKG",
        "/nuget/v3/flatcontainer/Repro.Pkg/3.0.1-Beta/Repro.Pkg.3.0.1-Beta.nupkg",
        "/chocolatey/v3/flatcontainer/Repro.Pkg/3.0.0/Repro.Pkg.3.0.0.nupkg",
        "/pwsh/v3/flatcontainer/REPRO.PKG/3.0.1-BETA/repro.pkg.3.0.1-beta.nupkg",
    ] {
        assert_eq!(
            send(&ctx.app, Method::GET, uri, "").await.status(),
            StatusCode::OK,
            "{uri}"
        );
        assert_eq!(registration_requests(&up).await, 0, "{uri}");
    }
    assert!(
        upstream_paths(&up).await.is_empty(),
        "served from the cache"
    );
}

/// With trusted dates the quarantine takes the release date too (#750): a version published
/// years ago is not held as new to this mirror, also when only the upstream dates it.
#[tokio::test]
async fn with_trusted_dates_an_old_version_matures_in_the_quarantine() {
    let up = upstream().await;
    serve_registration(
        &up,
        REGISTRATION,
        registration(vec![inline_page(
            "1.0.0",
            "2.0.0",
            vec![
                leaf("1.0.0", "2019-01-01T00:00:00Z"),
                leaf("2.0.0", &minutes_ago(10)),
            ],
        )]),
    )
    .await;
    let ctx = context(&up, true, quarantine_7d);
    assert_eq!(download(&ctx, "1.0.0").await, StatusCode::OK);
    assert_eq!(download(&ctx, "2.0.0").await, StatusCode::FORBIDDEN);
}

/// Nothing reads a date without a release-age rule or the quarantine: the upstream is not
/// asked for one.
#[tokio::test]
async fn no_date_is_asked_for_when_nothing_reads_it() {
    let up = upstream().await;
    let uri = up.uri();
    let ctx = create_test_context_with_config(move |cfg| {
        cfg.nuget.enabled = true;
        cfg.nuget.proxy = Some(uri);
        cfg.server.trust_upstream_dates = true;
    });
    assert_eq!(download(&ctx, "4.0.0").await, StatusCode::OK);
    assert_eq!(registration_requests(&up).await, 0);
}

/// A release-age rule a reload brings in asks the upstream for the date from then on: the
/// engine the reload installs is what curation decides with, not the configuration NORA
/// started with — the global rule and NuGet's own alike.
#[tokio::test]
async fn a_release_age_rule_a_reload_brings_in_asks_the_upstream_for_the_date() {
    let rules: [(&str, fn(&mut crate::config::Config)); 2] = [
        ("global", min_age_1h),
        ("NuGet's own", |cfg| {
            cfg.curation.nuget.min_release_age = Some("1h".to_string());
            cfg.curation.quarantine = Some(QuarantineMode::Observe);
        }),
    ];
    for (rule, add) in rules {
        let up = upstream().await;
        serve_registration(
            &up,
            REGISTRATION,
            registration(vec![inline_page(
                "1.0.0",
                "2.0.0",
                vec![
                    leaf("1.0.0", "2019-01-01T00:00:00Z"),
                    leaf("2.0.0", &minutes_ago(10)),
                ],
            )]),
        )
        .await;
        let ctx = context(&up, true, |_| {});
        reload_curation(&ctx, add);
        assert_eq!(
            download(&ctx, "2.0.0").await,
            StatusCode::FORBIDDEN,
            "{rule}: published 10 minutes ago, younger than 1h"
        );
        assert_eq!(download(&ctx, "1.0.0").await, StatusCode::OK, "{rule}");
    }
}

/// A quarantine switched off reads no date, and neither does a release-age rule while
/// curation is off: the upstream is not asked for one. NuGet's own `off` overrides a global
/// quarantine.
#[tokio::test]
async fn a_policy_switched_off_asks_for_no_date() {
    let switched_off: [(&str, fn(&mut crate::config::Config)); 3] = [
        ("quarantine off", |cfg| {
            cfg.curation.quarantine = Some(QuarantineMode::Off);
        }),
        ("NuGet's quarantine off", |cfg| {
            cfg.curation.quarantine = Some(QuarantineMode::Enforce);
            cfg.curation.nuget.quarantine = Some(QuarantineMode::Off);
        }),
        ("curation off", |cfg| {
            cfg.curation.mode = crate::config::CurationMode::Off;
            cfg.curation.min_release_age = Some("1h".to_string());
            cfg.curation.nuget.min_release_age = Some("1h".to_string());
        }),
    ];
    for (policy, customize) in switched_off {
        let up = upstream().await;
        let ctx = context(&up, true, customize);
        assert_eq!(download(&ctx, "4.0.0").await, StatusCode::OK, "{policy}");
        assert_eq!(registration_requests(&up).await, 0, "{policy}");
    }
}

/// The date is asked of the configured upstream only: with the upstream switched off —
/// absent or blank — no request leaves NORA for a date, the public default host included.
#[tokio::test]
async fn the_date_is_asked_of_the_configured_upstream_only() {
    use crate::test_helpers::{create_test_context_with_egress_proxy, EgressRecorder};
    for proxy in [None, Some("  ".to_string())] {
        let recorder = EgressRecorder::start().await;
        let switched_off = proxy.clone();
        let ctx = create_test_context_with_egress_proxy(&recorder.url, move |cfg| {
            cfg.nuget.enabled = true;
            cfg.nuget.proxy = switched_off;
            cfg.nuget.metadata_proxy_timeout = 2;
            cfg.server.trust_upstream_dates = true;
            cfg.circuit_breaker.enabled = true;
            min_age_1h_quarantine_7d(cfg);
        });
        assert_eq!(
            download(&ctx, "1.0.0").await,
            StatusCode::NOT_FOUND,
            "{proxy:?}"
        );
        // The breaker is asked before every upstream request; the recorder sees any request.
        assert!(
            ctx.state.circuit_breaker.keys().is_empty(),
            "{proxy:?}: {:?}",
            ctx.state.circuit_breaker.keys()
        );
        assert!(
            recorder.seen().await.is_empty(),
            "{proxy:?}: {:?}",
            recorder.seen().await
        );
    }
}

/// The upstream index dates a version on whichever of its inline pages lists it, through
/// every prefix a client comes by: one on the second page, published minutes ago, is held.
#[tokio::test]
async fn a_version_on_a_later_inline_page_of_the_upstream_index_is_dated() {
    for prefix in PREFIXES {
        let up = upstream().await;
        serve_registration(
            &up,
            REGISTRATION,
            registration(vec![
                inline_page(
                    "1.0.0",
                    "1.0.0",
                    vec![leaf("1.0.0", "2019-01-01T00:00:00Z")],
                ),
                inline_page("2.0.0", "2.0.0", vec![leaf("2.0.0", &minutes_ago(10))]),
            ]),
        )
        .await;
        let ctx = context(&up, true, min_age_1h);
        assert_eq!(
            download_via(&ctx, prefix, "2.0.0").await,
            StatusCode::FORBIDDEN,
            "{prefix}: on the second page, published 10 minutes ago"
        );
        assert_eq!(
            download_via(&ctx, prefix, "1.0.0").await,
            StatusCode::OK,
            "{prefix}"
        );
    }
}

/// A version is dated by its own leaf, not one whose version begins with it: listed after
/// a 2019 `1.0.10` and a 2019 `1.0.1-beta`, a `1.0.1` published minutes ago is held.
#[tokio::test]
async fn a_version_is_not_dated_by_one_it_prefixes() {
    for prefix in PREFIXES {
        let up = upstream().await;
        serve_registration(
            &up,
            REGISTRATION,
            registration(vec![inline_page(
                "1.0.1-beta",
                "1.0.10",
                vec![
                    leaf("1.0.10", "2019-01-01T00:00:00Z"),
                    leaf("1.0.1-beta", "2019-01-01T00:00:00Z"),
                    leaf("1.0.1", &minutes_ago(10)),
                ],
            )]),
        )
        .await;
        let ctx = context(&up, true, min_age_1h);
        assert_eq!(
            download_via(&ctx, prefix, "1.0.1").await,
            StatusCode::FORBIDDEN,
            "{prefix}: 1.0.1 is not 1.0.10 nor 1.0.1-beta"
        );
        assert_eq!(
            download_via(&ctx, prefix, "1.0.10").await,
            StatusCode::OK,
            "{prefix}"
        );
    }
}

/// The page a version is on is asked of the configured upstream, never of the host the
/// upstream index names in the page's `@id`: that host, live and dating the version as
/// old, gets no request, and the version published minutes ago is held.
#[tokio::test]
async fn the_page_is_asked_of_the_configured_upstream_not_the_index_s_at_id() {
    for prefix in PREFIXES {
        let up = upstream().await;
        let elsewhere = elsewhere().await;
        serve_registration(
            &up,
            REGISTRATION,
            registration(vec![remote_page(&elsewhere.uri(), "1.0.129", "1.0.140")]),
        )
        .await;
        serve_registration(
            &up,
            "/v3/registration5-gz-semver2/repro.pkg/page/1.0.129/1.0.140.json",
            serde_json::json!({
                "lower": "1.0.129", "upper": "1.0.140",
                "items": [leaf("1.0.129", &minutes_ago(10))]
            })
            .to_string(),
        )
        .await;
        let ctx = context(&up, true, min_age_1h);
        assert_eq!(
            download_via(&ctx, prefix, "1.0.129").await,
            StatusCode::FORBIDDEN,
            "{prefix}"
        );
        assert_eq!(
            registration_requests(&elsewhere).await,
            0,
            "{prefix}: the host of the page's @id was asked"
        );
    }
}

#[test]
fn nuget_versions_order_as_nuget_orders_them() {
    use super::nuget_version_order;
    use std::cmp::Ordering::{Equal, Greater, Less};
    for (a, b, want) in [
        ("1.0.0", "1.0.0", Equal),
        ("1.0", "1.0.0.0", Equal),
        ("1.0.0+build", "1.0.0", Equal),
        ("1.0.0-Beta", "1.0.0-beta", Equal),
        ("1.0.9", "1.0.10", Less),
        ("1.0.0.1", "1.0.0", Greater),
        ("1.0.0-alpha", "1.0.0", Less),
        ("1.0.0-alpha", "1.0.0-alpha.1", Less),
        ("1.0.0-alpha.2", "1.0.0-alpha.10", Less),
        ("1.0.0-2", "1.0.0-alpha", Less),
        ("1.0.0-beta", "1.0.0-alpha", Greater),
        ("2.0.0", "10.0.0", Less),
    ] {
        assert_eq!(nuget_version_order(a, b), Some(want), "{a} vs {b}");
    }
    assert_eq!(nuget_version_order("not.a.version.x", "1.0.0"), None);
}
