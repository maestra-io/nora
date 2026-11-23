// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
#![cfg(test)]
#![allow(clippy::unwrap_used)]

use crate::circuit_breaker::upstream_key;
use crate::config::MavenProxyEntry;
use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
use axum::http::{Method, StatusCode};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

/// the metadata checksum path is a maven cold miss too — a failed upstream is 502.
#[tokio::test]
async fn metadata_checksum_failed_upstream_is_502() {
    let down = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&down)
        .await;
    let url = down.uri();
    let ctx = create_test_context_with_config(move |c| {
        c.maven.proxies = vec![MavenProxyEntry::Simple(url)];
    });
    for path in [
        "/maven2/com/example/lib/maven-metadata.xml.sha1",
        "/maven2/com/example/lib/1.0.0/lib-1.0.0.jar.sha1",
    ] {
        let resp = send(&ctx.app, Method::GET, path, "").await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY, "{path}");
    }
}

/// an open breaker on a maven upstream is still 503, not 502.
#[tokio::test]
async fn open_breaker_is_still_503() {
    let ctx = create_test_context_with_config(|c| {
        c.circuit_breaker.enabled = true;
        c.circuit_breaker.failure_threshold = 1;
        c.circuit_breaker.reset_timeout = 3600;
        c.maven.proxies = vec![MavenProxyEntry::Simple("http://127.0.0.1:9".into())];
    });
    let path = "/maven2/com/example/lib/1.0.0/lib-1.0.0.jar";
    send(&ctx.app, Method::GET, path, "").await; // trips the breaker
    let resp = send(&ctx.app, Method::GET, path, "").await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

/// #1198: an upstream whose breaker is open is skipped, not asked, and the next one serves.
#[tokio::test]
async fn an_open_upstream_is_skipped_for_the_next() {
    let (skipped, serving) = (MockServer::start().await, MockServer::start().await);
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("from-skipped"))
        .expect(0)
        .mount(&skipped)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("from-next"))
        .mount(&serving)
        .await;
    let urls = vec![skipped.uri(), serving.uri()];
    let ctx = create_test_context_with_config(move |c| {
        c.circuit_breaker.enabled = true;
        c.circuit_breaker.reset_timeout = 3600;
        c.maven.proxies = urls.into_iter().map(MavenProxyEntry::Simple).collect();
    });
    ctx.state
        .circuit_breaker
        .open_for_test(&upstream_key("maven", &skipped.uri()));
    let resp = send(
        &ctx.app,
        Method::GET,
        "/maven2/com/example/lib/1.0.0/lib-1.0.0.jar",
        "",
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_bytes(resp).await.as_ref(), b"from-next");
}

/// #1198: each Maven upstream reports to a breaker of its own. A dead first upstream opens
/// only its own; the next one keeps serving, on the request that opened it and after.
#[tokio::test]
async fn a_dead_upstream_opens_only_its_own_breaker() {
    let serving = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("from-next"))
        .mount(&serving)
        .await;
    let dead = "http://127.0.0.1:9".to_string();
    let urls = vec![dead.clone(), serving.uri()];
    let ctx = create_test_context_with_config(move |c| {
        c.circuit_breaker.enabled = true;
        c.circuit_breaker.failure_threshold = 1;
        c.circuit_breaker.reset_timeout = 3600;
        c.maven.proxies = urls.into_iter().map(MavenProxyEntry::Simple).collect();
    });
    for version in ["1.0.0", "1.0.1", "1.0.2"] {
        let path = format!("/maven2/com/example/lib/{version}/lib-{version}.jar");
        let resp = send(&ctx.app, Method::GET, &path, "").await;
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
    }
    let mut keys = vec![
        upstream_key("maven", &dead),
        upstream_key("maven", &serving.uri()),
    ];
    keys.sort();
    assert_eq!(ctx.state.circuit_breaker.keys(), keys);
    let cb = &ctx.state.circuit_breaker;
    assert!(cb.check(&upstream_key("maven", &dead)).is_err());
    assert!(cb.check(&upstream_key("maven", &serving.uri())).is_ok());
}

/// #1198: a copy whose revalidation found every upstream skipped is served stale, as when
/// every upstream failed.
#[tokio::test]
async fn an_open_upstream_leaves_the_stale_copy_served() {
    let skipped = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("from-skipped"))
        .expect(0)
        .mount(&skipped)
        .await;
    let url = skipped.uri();
    let ctx = create_test_context_with_config(move |c| {
        c.circuit_breaker.enabled = true;
        c.circuit_breaker.reset_timeout = 3600;
        c.maven.metadata_ttl = 0;
        c.maven.proxies = vec![MavenProxyEntry::Simple(url)];
    });
    let path = "/maven2/com/example/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar";
    ctx.state
        .storage
        .put(
            &super::storage_key("com/example/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar"),
            b"cached-copy",
        )
        .await
        .unwrap();
    ctx.state
        .circuit_breaker
        .open_for_test(&upstream_key("maven", &skipped.uri()));
    let resp = send(&ctx.app, Method::GET, path, "").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("x-nora-stale").map(|v| v.as_bytes()),
        Some(b"true".as_slice())
    );
    assert_eq!(body_bytes(resp).await.as_ref(), b"cached-copy");
}

/// A070: a file on Maven Central (mounted under `/repo1.maven.org/maven2`, so
/// `url_is_maven_central` matches) whose date lookup gives no answer.
mod a070_central_undated {
    use super::*;
    use crate::config::UnknownDate;
    use crate::test_helpers::TestContext;
    use wiremock::matchers::path;

    const CENTRAL: &str = "/repo1.maven.org/maven2";
    const FILE: &str = "org/example/fresh/1.0.0/fresh-1.0.0.jar";

    /// Live shape: enforce, maven min_release_age 3d, quarantine observe, trusted dates.
    fn min_age(proxies: Vec<String>, unknown: Option<UnknownDate>) -> TestContext {
        create_test_context_with_config(move |c| {
            c.maven.proxies = proxies.into_iter().map(MavenProxyEntry::Simple).collect();
            c.maven.date_lookup_timeout = 1;
            c.server.trust_upstream_dates = true;
            c.curation.mode = crate::config::CurationMode::Enforce;
            c.curation.maven.min_release_age = Some("3d".into());
            c.curation.maven.quarantine = Some(crate::digest_quarantine::QuarantineMode::Observe);
            c.curation.maven.quarantine_ttl = Some("3d".into());
            c.curation.maven.unknown_date = unknown;
        })
    }

    /// Central serving the jar while its HEAD (the date) fails; the search is not asked
    /// after a 503.
    async fn central_undated() -> MockServer {
        let up = MockServer::start().await;
        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&up)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{CENTRAL}/{FILE}")))
            .respond_with(ResponseTemplate::new(200).set_body_string("FRESH-JAR-BYTES"))
            .mount(&up)
            .await;
        up
    }

    async fn get(ctx: &TestContext) -> StatusCode {
        let holders = ctx.state.storage.holders();
        let status = send(&ctx.app, Method::GET, &format!("/maven2/{FILE}"), "")
            .await
            .status();
        crate::test_helpers::background_writes_done(&ctx.state.storage, holders).await;
        status
    }

    async fn cached(ctx: &TestContext) -> bool {
        ctx.state
            .storage
            .stat(&super::super::storage_key(FILE))
            .await
            .is_some()
    }

    /// `hold`: refused, not cached, refused again.
    #[tokio::test]
    async fn held_under_hold_and_not_cached() {
        let up = central_undated().await;
        let ctx = min_age(
            vec![format!("{}{CENTRAL}", up.uri())],
            Some(UnknownDate::Hold),
        );
        assert_eq!(get(&ctx).await, StatusCode::FORBIDDEN);
        assert!(!cached(&ctx).await);
        assert_eq!(get(&ctx).await, StatusCode::FORBIDDEN);
        assert!(!cached(&ctx).await);
    }

    /// `log` (Maven's default): served and cached, the undated download counted.
    #[tokio::test]
    async fn served_and_counted_under_log() {
        let up = central_undated().await;
        let ctx = min_age(vec![format!("{}{CENTRAL}", up.uri())], None);
        let counter =
            crate::metrics::CURATION_UNKNOWN_RELEASE_DATE_TOTAL.with_label_values(&["maven"]);
        let before = counter.get();
        assert_eq!(get(&ctx).await, StatusCode::OK);
        assert!(counter.get() > before);
        assert!(cached(&ctx).await);
    }

    /// Not on Central, served by a second, non-Central proxy: the quarantine path, even
    /// under `hold`.
    #[tokio::test]
    async fn another_proxy_stays_on_the_quarantine_path() {
        let central = MockServer::start().await;
        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&central)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&central)
            .await;
        let google = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/{FILE}")))
            .respond_with(ResponseTemplate::new(200).set_body_string("GOOGLE-JAR"))
            .mount(&google)
            .await;
        let ctx = min_age(
            vec![format!("{}{CENTRAL}", central.uri()), google.uri()],
            Some(UnknownDate::Hold),
        );
        assert_eq!(get(&ctx).await, StatusCode::OK);
        assert!(cached(&ctx).await);
    }
}

/// A file only maven.google.com has (mounted under `/maven.google.com`, so
/// `url_is_google_maven` matches): its `Last-Modified` there is its publish date.
mod google_dates {
    use super::*;
    use crate::config::UnknownDate;
    use crate::test_helpers::TestContext;
    use wiremock::matchers::path;

    const CENTRAL: &str = "/repo1.maven.org/maven2";
    const GOOGLE: &str = "/maven.google.com";
    const FILE: &str = "androidx/x/lib/1.0.0/lib-1.0.0.aar";
    const OLD: &str = "Wed, 17 Apr 2024 17:00:43 GMT";

    /// Live shape: Central, then Google; enforce, maven min_release_age 3d, trusted dates.
    /// The quarantine enforces, so a seed of "now" refuses the file.
    fn context(up: &MockServer, unknown: Option<UnknownDate>) -> TestContext {
        let proxies = [CENTRAL, GOOGLE].map(|base| format!("{}{base}", up.uri()));
        context_with(proxies.to_vec(), unknown)
    }

    fn context_with(proxies: Vec<String>, unknown: Option<UnknownDate>) -> TestContext {
        create_test_context_with_config(move |c| {
            c.maven.proxies = proxies.into_iter().map(MavenProxyEntry::Simple).collect();
            c.maven.date_lookup_timeout = 5;
            c.server.trust_upstream_dates = true;
            c.curation.mode = crate::config::CurationMode::Enforce;
            c.curation.maven.min_release_age = Some("3d".into());
            c.curation.maven.quarantine = Some(crate::digest_quarantine::QuarantineMode::Enforce);
            c.curation.maven.quarantine_ttl = Some("3d".into());
            c.curation.maven.unknown_date = unknown;
        })
    }

    /// `base` answers the file's HEAD with `head` and its GET with a body.
    async fn serve(up: &MockServer, base: &str, head: ResponseTemplate) {
        Mock::given(method("HEAD"))
            .and(path(format!("{base}/{FILE}")))
            .respond_with(head)
            .mount(up)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{base}/{FILE}")))
            .respond_with(ResponseTemplate::new(200).set_body_string(base))
            .mount(up)
            .await;
    }

    fn modified(at: &str) -> ResponseTemplate {
        ResponseTemplate::new(200).insert_header("last-modified", at)
    }

    async fn get(ctx: &TestContext) -> (StatusCode, bool) {
        let holders = ctx.state.storage.holders();
        let status = send(&ctx.app, Method::GET, &format!("/maven2/{FILE}"), "")
            .await
            .status();
        crate::test_helpers::background_writes_done(&ctx.state.storage, holders).await;
        let key = super::super::storage_key(FILE);
        (status, ctx.state.storage.stat(&key).await.is_some())
    }

    /// An old artifact is served on its first fetch and from the cache: the date passes the
    /// age check and seeds the quarantine.
    #[tokio::test]
    async fn an_old_artifact_is_served_at_once() {
        let up = MockServer::start().await;
        serve(&up, GOOGLE, modified(OLD)).await;
        let ctx = context(&up, Some(UnknownDate::Hold));
        assert_eq!(get(&ctx).await, (StatusCode::OK, true));
        assert_eq!(get(&ctx).await, (StatusCode::OK, true));
    }

    /// A young one is refused before the download, under `log` too, and not cached.
    #[tokio::test]
    async fn a_young_artifact_is_refused_and_not_cached() {
        let up = MockServer::start().await;
        let day_old = (chrono::Utc::now() - chrono::Duration::days(1)).to_rfc2822();
        serve(&up, GOOGLE, modified(&day_old.replace("+0000", "GMT"))).await;
        let ctx = context(&up, None);
        assert_eq!(get(&ctx).await, (StatusCode::FORBIDDEN, false));
        let gets = up.received_requests().await.unwrap();
        assert!(gets.iter().all(|r| r.method.as_str() == "HEAD"));
    }

    /// Google served it with no date: `unknown_date` decides.
    #[tokio::test]
    async fn an_undated_artifact_goes_through_unknown_date() {
        let up = MockServer::start().await;
        serve(&up, GOOGLE, ResponseTemplate::new(503)).await;
        let ctx = context(&up, Some(UnknownDate::Hold));
        assert_eq!(get(&ctx).await, (StatusCode::FORBIDDEN, false));
    }

    /// The date names the upstream that gave it: Central's HEAD failed or said 404, Google has
    /// an old file of that name, and Central serves the bytes.
    #[tokio::test]
    async fn googles_date_is_not_centrals() {
        for head in [503, 404] {
            let up = MockServer::start().await;
            serve(&up, GOOGLE, modified(OLD)).await;
            serve(&up, CENTRAL, ResponseTemplate::new(head)).await;
            let ctx = context(&up, Some(UnknownDate::Hold));
            assert_eq!(get(&ctx).await, (StatusCode::FORBIDDEN, false), "{head}");
        }
    }

    /// The same bytes cached under `log` stay held: a cache hit does not date them by Google's
    /// file either.
    #[tokio::test]
    async fn googles_date_does_not_release_centrals_cached_copy() {
        for head in [503, 404] {
            let up = MockServer::start().await;
            serve(&up, GOOGLE, modified(OLD)).await;
            serve(&up, CENTRAL, ResponseTemplate::new(head)).await;
            let ctx = context(&up, None);
            for _ in 0..2 {
                assert_eq!(get(&ctx).await, (StatusCode::FORBIDDEN, true), "{head}");
            }
        }
    }

    /// Google dated the file and an undated proxy served it: its first-seen clock, not Google's
    /// date.
    #[tokio::test]
    async fn googles_date_is_not_an_undated_proxys() {
        let up = MockServer::start().await;
        Mock::given(method("HEAD"))
            .and(path(format!("{GOOGLE}/{FILE}")))
            .respond_with(modified(OLD))
            .mount(&up)
            .await;
        serve(&up, "/other", ResponseTemplate::new(200)).await;
        let mut proxies = vec![format!("{}{GOOGLE}", up.uri())];
        proxies.push(format!("{}/other", up.uri()));
        let ctx = context_with(proxies, None);
        assert_eq!(get(&ctx).await.0, StatusCode::FORBIDDEN);
    }
}
