// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
//! One memoised lookup of an upstream's release dates (the RubyGems versions API, the
//! registry.terraform.io `/v2` API, Maven Central, a Go zip's `Last-Modified` on
//! proxy.golang.org), shared by every request that needs it.
//!
//! A key is fetched once at a time: concurrent callers await the same fetch. An answer is
//! kept for the format's `metadata_ttl`, a miss (404, 429, 5xx, timeout, an open breaker) for
//! [`RETRY`]. A version missing from a kept answer fetches the key again at most once per
//! [`RETRY`], so a release published after the answer is dated without waiting out the TTL;
//! inside that window the answer comes back [`Answer::unasked`]: the version was never asked
//! about, and callers hold it as released now rather than leave it undated (R01).
//! Each registry keeps at most [`KEYS`] keys: past it its expired ones go, then its
//! longest-finished one, never one in flight, nor another registry's (R06).
//! The fetches read through [`get`]: capped at [`MAX_BODY`] and reported to a breaker of
//! their own (`<upstream>#dates`), so a throttled date API never opens the download breaker.
//! [`crate::metrics::UPSTREAM_DATE_LOOKUP_TOTAL`] counts answers from the memo, fetches and
//! breaker skips.

use super::ProxyError;
use crate::circuit_breaker::BreakerScope;
use crate::registry_type::RegistryType;
use crate::AppState;
use futures::future::{BoxFuture, FutureExt, Shared};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The largest date answer read. The biggest real ones (RubyGems versions of a gem with
/// thousands of releases, a terraform provider's full version list) are a few MiB.
pub(super) const MAX_BODY: u64 = 32 << 20;
/// A miss is fetched again after this; so is a kept answer that lacks a wanted version.
const RETRY: Duration = Duration::from_secs(60);
/// One fetch, retry included; it runs on its own task, so a caller that gives up leaves it
/// to the next one.
const DEADLINE: Duration = Duration::from_secs(120);
/// Keys kept per registry.
const KEYS: usize = 1024;

/// Version (as the format keys it) -> its release date, unix seconds.
pub(super) type Dates = HashMap<String, i64>;
type Lookup = Shared<BoxFuture<'static, Option<Arc<Dates>>>>;
/// When a lookup started, then when it finished: what its answer's age is counted from.
type Stamp = Arc<Mutex<Instant>>;

/// Lookups by registry, then key (`AppState::upstream_dates`): their [`Stamp`], and the fetch
/// every caller of that key awaits.
pub type Memo = Mutex<HashMap<RegistryType, HashMap<String, (Stamp, Lookup)>>>;

/// What [`dates`] gives.
pub(super) struct Answer {
    /// The dates fetched or kept; `None`: no answer.
    pub dates: Option<Arc<Dates>>,
    /// A kept answer lacking a wanted version, given without asking the upstream again: a
    /// version it lacks may be newer than the answer, so it is held, never left undated.
    pub unasked: bool,
}

/// The dates of `key` of `registry`: the kept answer while it is fresh (`ttl` for an answer
/// holding every `wanted` version, [`RETRY`] for a miss or one lacking a wanted version),
/// the fetch in flight, else a new `fetch()`.
pub(super) async fn dates<F, Fut>(
    state: &AppState,
    registry: RegistryType,
    key: &str,
    ttl: Duration,
    wanted: &[&str],
    fetch: F,
) -> Answer
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Option<Dates>> + Send + 'static,
{
    let (lookup, unasked) = {
        let mut memo = state.upstream_dates.lock();
        let keys = memo.entry(registry).or_default();
        let kept = keys.get(key).and_then(|(stamp, lookup)| {
            let (fresh_for, unasked) = match lookup.peek() {
                // In flight: join it.
                None => return Some((lookup.clone(), false)),
                Some(Some(dates)) if wanted.iter().all(|w| dates.contains_key(*w)) => (ttl, false),
                Some(Some(_)) => (RETRY, true),
                Some(None) => (RETRY, false),
            };
            (stamp.lock().elapsed() < fresh_for).then(|| (lookup.clone(), unasked))
        });
        match kept {
            Some(kept) => {
                count(registry, "memo");
                kept
            }
            None => {
                count(registry, "fetch");
                if !keys.contains_key(key) && keys.len() >= KEYS {
                    make_room(keys, ttl.max(RETRY));
                }
                let stamp: Stamp = Arc::new(Mutex::new(Instant::now()));
                let finished = Arc::clone(&stamp);
                let fetching = tokio::time::timeout(DEADLINE, fetch());
                let lookup = tokio::spawn(async move {
                    let done = fetching.await;
                    // A slow miss is kept a full RETRY too.
                    *finished.lock() = Instant::now();
                    done
                })
                .map(|done| done.ok().and_then(Result::ok).flatten().map(Arc::new))
                .boxed()
                .shared();
                keys.insert(key.to_owned(), (stamp, lookup.clone()));
                (lookup, false)
            }
        }
    };
    Answer {
        dates: lookup.await,
        unasked,
    }
}

/// One registry's keys at [`KEYS`]: the finished ones older than `kept_for` go, else the
/// longest-finished one. A lookup in flight stays (its next caller would fetch it twice).
// ponytail: a scan per insert at the bound; an LRU list if 1024 keys churn inside a TTL.
fn make_room(keys: &mut HashMap<String, (Stamp, Lookup)>, kept_for: Duration) {
    let finished = |lookup: &Lookup| lookup.peek().is_some();
    keys.retain(|_, (stamp, lookup)| !finished(lookup) || stamp.lock().elapsed() < kept_for);
    if keys.len() < KEYS {
        return;
    }
    let oldest = keys
        .iter()
        .filter(|(_, (_, lookup))| finished(lookup))
        .max_by_key(|(_, (stamp, _))| stamp.lock().elapsed())
        .map(|(key, _)| key.clone());
    if let Some(oldest) = oldest {
        keys.remove(&oldest);
    }
}

/// GET `url` of `upstream` for a date lookup: at most [`MAX_BODY`], on the breaker
/// `<upstream>#dates`. Only a 404 is `NotFound`: any other 4xx (a 400, 410, 451, a block)
/// answers nothing about the name, and is `Upstream(status)` (R40).
pub(super) async fn get(
    state: &AppState,
    registry: RegistryType,
    upstream: &str,
    url: &str,
    timeout: Duration,
) -> Result<axum::body::Bytes, ProxyError> {
    let scope = format!("{}#dates", upstream.trim_end_matches('/'));
    let fetched = super::proxy_fetch_capped_as(
        &state.http_client,
        url,
        timeout,
        None,
        (
            &state.circuit_breaker,
            BreakerScope::upstream(registry, &scope),
        ),
        MAX_BODY,
        true,
    )
    .await;
    if let Err(e) = &fetched {
        if matches!(e, ProxyError::CircuitOpen(_)) {
            count(registry, "breaker_open");
        }
        tracing::info!(url, error = ?e, registry = registry.as_str(), "upstream release-date lookup failed");
    }
    fetched
}

/// The breaker key [`get`] reports to.
pub(super) fn breaker_key(registry: RegistryType, upstream: &str) -> String {
    let scope = format!("{}#dates", upstream.trim_end_matches('/'));
    BreakerScope::upstream(registry, &scope).key().into_owned()
}

pub(super) fn count(registry: RegistryType, outcome: &str) {
    crate::metrics::UPSTREAM_DATE_LOOKUP_TOTAL
        .with_label_values(&[registry.as_str(), outcome])
        .inc();
}

/// A085: a date lookup is asked once per key and window, whatever the number or order of
/// requests that need it; a refusing API opens its own breaker. A055: its answer is capped.
/// R01: a kept answer never passes a version it lacks. R06: each registry has its own bound.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::config::MavenProxyEntry;
    use crate::test_helpers::{
        create_test_context_with_config, create_test_context_with_egress_proxy, send,
        EgressRecorder,
    };
    use crate::AppState;
    use axum::http::{Method, StatusCode};
    use std::time::Duration;
    use wiremock::matchers::{any, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn enforce_age(cfg: &mut crate::config::Config) {
        cfg.curation.mode = crate::config::CurationMode::Enforce;
        cfg.curation.min_release_age = Some("3d".into());
        cfg.curation.quarantine = Some(crate::digest_quarantine::QuarantineMode::Observe);
        cfg.curation.quarantine_ttl = Some("3d".into());
    }

    /// Moves every kept lookup `by` into the past.
    fn age(state: &AppState, by: Duration) {
        for (stamp, _) in state
            .upstream_dates
            .lock()
            .values()
            .flat_map(|keys| keys.values())
        {
            let mut at = stamp.lock();
            *at = at.checked_sub(by).unwrap();
        }
    }

    async fn hits(server: &MockServer, verb: &str, p: &str) -> usize {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method.as_str() == verb && r.url.path() == p)
            .count()
    }

    fn versions(created: &[(&str, String)]) -> ResponseTemplate {
        let rows: Vec<_> = created
            .iter()
            .map(|(number, at)| serde_json::json!({"number": number, "platform": "ruby", "created_at": at}))
            .collect();
        ResponseTemplate::new(200).set_body_json(rows)
    }

    #[tokio::test]
    async fn a085_gems_one_versions_call_per_gem_and_window() {
        const API: &str = "/api/v1/versions/a085gem.json";
        let upstream = MockServer::start().await;
        let old = "2022-01-01T00:00:00Z".to_string();
        Mock::given(method("GET"))
            .and(path(API))
            .respond_with(versions(&[("7.0.0", old.clone())]))
            .with_priority(1)
            .mount(&upstream)
            .await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(404))
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.gems.enabled = true;
            cfg.gems.proxy = Some(uri);
            enforce_age(cfg);
        });
        let get = |file: &'static str| send(&ctx.app, Method::GET, file, "");

        // An absent version, asked in sequence and at once: one API call.
        for _ in 0..4 {
            get("/gems/gems/a085gem-8.0.0.gem").await;
        }
        futures::future::join_all((0..4).map(|_| get("/gems/gems/a085gem-8.0.0.gem"))).await;
        assert_eq!(hits(&upstream, "GET", API).await, 1);

        // 8.0.0 is published: the kept answer lacks it, so the next request past the retry
        // window asks once more, and dates it.
        upstream.reset().await;
        let now = chrono::Utc::now().to_rfc3339();
        Mock::given(method("GET"))
            .and(path(API))
            .respond_with(versions(&[("7.0.0", old), ("8.0.0", now)]))
            .with_priority(1)
            .mount(&upstream)
            .await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"GEM".to_vec()))
            .mount(&upstream)
            .await;
        age(&ctx.state, Duration::from_secs(61));
        let young = get("/gems/gems/a085gem-8.0.0.gem").await;
        assert_eq!(
            young.status(),
            StatusCode::FORBIDDEN,
            "dated by the refetch"
        );
        // A version the kept answer holds is answered by it for the TTL.
        age(&ctx.state, Duration::from_secs(61));
        assert_eq!(
            get("/gems/gems/a085gem-7.0.0.gem").await.status(),
            StatusCode::OK
        );
        get("/gems/gems/a085gem-8.0.0.gem").await;
        assert_eq!(hits(&upstream, "GET", API).await, 1);
    }

    #[tokio::test]
    async fn a085_terraform_one_v2_lookup_per_provider_and_window() {
        let recorder = EgressRecorder::start().await;
        let ctx = create_test_context_with_egress_proxy(&recorder.url, |cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some("http://registry.terraform.io".into());
            enforce_age(cfg);
        });
        let storage = &ctx.state.storage;
        storage
            .put(
                "terraform/providers/hashicorp/null/3.2.3/linux_amd64.json",
                br#"{"download_url":"http://nora.local/x.zip","shasum":"00"}"#,
            )
            .await
            .unwrap();
        storage
            .put(
                "terraform/providers/hashicorp/null/versions.json",
                br#"{"versions":[{"version":"3.2.3","platforms":[{"os":"linux","arch":"amd64"}]}]}"#,
            )
            .await
            .unwrap();
        let get = |uri: &'static str| send(&ctx.app, Method::GET, uri, "");
        let meta = "/terraform/v1/providers/hashicorp/null/3.2.3/download/linux/amd64";
        let list = "/terraform/v1/providers/hashicorp/null/versions";
        for _ in 0..4 {
            get(meta).await;
            get(list).await;
        }
        futures::future::join_all((0..4).map(|_| get(list))).await;
        for _ in 0..3 {
            get("/terraform/v1/providers/absent/absent/9.9.9/download/linux/amd64").await;
        }
        let seen = recorder.seen().await;
        let v2 = seen
            .iter()
            .filter(|l| l.starts_with("CONNECT registry.terraform.io:443"))
            .count();
        // Two providers, one lookup each; a lookup that fails is tried twice.
        assert!((2..=4).contains(&v2), "{seen:?}");
    }

    #[tokio::test]
    async fn a085_terraform_refusing_v2_api_opens_its_own_breaker() {
        let recorder = EgressRecorder::start().await;
        let ctx = create_test_context_with_egress_proxy(&recorder.url, |cfg| {
            cfg.terraform.enabled = true;
            cfg.terraform.proxy = Some("http://registry.terraform.io".into());
            cfg.circuit_breaker.enabled = true;
            cfg.circuit_breaker.failure_threshold = 1;
            cfg.circuit_breaker.reset_timeout = 600;
            enforce_age(cfg);
        });
        let skipped = || {
            crate::metrics::UPSTREAM_DATE_LOOKUP_TOTAL
                .with_label_values(&["terraform", "breaker_open"])
                .get()
        };
        let before = skipped();
        for n in 0..4 {
            let uri = format!("/terraform/v1/providers/absent/p{n}/1.0.0/download/linux/amd64");
            send(&ctx.app, Method::GET, &uri, "").await;
        }
        let seen = recorder.seen().await;
        let v2 = seen
            .iter()
            .filter(|l| l.starts_with("CONNECT registry.terraform.io:443"))
            .count();
        assert!(
            (1..=2).contains(&v2),
            "only the first provider asks: {seen:?}"
        );
        assert!(skipped() >= before + 3);
        // The download breaker is another one.
        let cb = &ctx.state.circuit_breaker;
        assert!(cb
            .check(&super::breaker_key(
                crate::registry_type::RegistryType::Terraform,
                "https://registry.terraform.io"
            ))
            .is_err());
        assert!(cb.check("terraform").is_ok());
    }

    #[tokio::test]
    async fn a085_maven_one_central_head_per_file_and_window() {
        let central = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(404))
            .mount(&central)
            .await;
        // A Central proxy by its URL (`url_is_maven_central`), served by the mock.
        let proxy = format!("{}/repo1.maven.org/maven2", central.uri());
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.maven.proxies = vec![MavenProxyEntry::Simple(proxy)];
        });
        let jar = "/maven2/com/example/a085/1.0/a085-1.0.jar";
        for _ in 0..4 {
            send(&ctx.app, Method::GET, jar, "").await;
        }
        futures::future::join_all((0..4).map(|_| send(&ctx.app, Method::GET, jar, ""))).await;
        let head = "/repo1.maven.org/maven2/com/example/a085/1.0/a085-1.0.jar";
        assert_eq!(hits(&central, "HEAD", head).await, 1);
    }

    /// R01: a version a kept answer lacks, published inside the retry window, is held as
    /// released now, never served (and cached) undated on the strength of that answer.
    #[tokio::test]
    async fn r01_gems_a_release_inside_the_retry_window_is_held() {
        const API: &str = "/api/v1/versions/r01gem.json";
        let upstream = MockServer::start().await;
        let old = "2022-01-01T00:00:00Z".to_string();
        Mock::given(method("GET"))
            .and(path(API))
            .respond_with(versions(&[("7.0.0", old.clone())]))
            .with_priority(1)
            .mount(&upstream)
            .await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(404))
            .mount(&upstream)
            .await;
        let uri = upstream.uri();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.gems.enabled = true;
            cfg.gems.proxy = Some(uri);
            enforce_age(cfg);
        });
        let gem = "/gems/gems/r01gem-9.9.9.gem";
        assert_eq!(
            send(&ctx.app, Method::GET, gem, "").await.status(),
            StatusCode::NOT_FOUND
        );

        // 9.9.9 is published seconds later.
        upstream.reset().await;
        let now = chrono::Utc::now().to_rfc3339();
        Mock::given(method("GET"))
            .and(path(API))
            .respond_with(versions(&[("7.0.0", old), ("9.9.9", now)]))
            .with_priority(1)
            .mount(&upstream)
            .await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"GEM".to_vec()))
            .mount(&upstream)
            .await;
        let resp = send(&ctx.app, Method::GET, gem, "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "held, not undated");
        assert!(ctx
            .state
            .storage
            .get("gems/gems/r01gem-9.9.9.gem")
            .await
            .is_err());
        assert_eq!(hits(&upstream, "GET", API).await, 0, "the kept answer");
    }

    /// R01 for Maven: a kept "not on Central" does not date a file Central serves a few
    /// seconds later; the file is held, not served and cached undated.
    #[tokio::test]
    async fn r01_maven_a_file_on_central_inside_the_retry_window_is_held() {
        let central = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(404))
            .mount(&central)
            .await;
        let proxy = format!("{}/repo1.maven.org/maven2", central.uri());
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.maven.proxies = vec![MavenProxyEntry::Simple(proxy)];
            enforce_age(cfg);
        });
        let jar = "/maven2/com/example/r01/1.0/r01-1.0.jar";
        assert_eq!(
            send(&ctx.app, Method::GET, jar, "").await.status(),
            StatusCode::NOT_FOUND
        );

        central.reset().await;
        let now = chrono::Utc::now().to_rfc2822();
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Last-Modified", now.as_str())
                    .set_body_bytes(b"JAR".to_vec()),
            )
            .mount(&central)
            .await;
        let resp = send(&ctx.app, Method::GET, jar, "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "held, not undated");
        let key = crate::registry::maven::storage_key("com/example/r01/1.0/r01-1.0.jar");
        assert!(ctx.state.storage.stat(&key).await.is_none());
        let head = "/repo1.maven.org/maven2/com/example/r01/1.0/r01-1.0.jar";
        assert_eq!(hits(&central, "HEAD", head).await, 0, "the kept miss");
    }

    /// R06: each registry keeps its own keys. Another registry's churn never drops them, and
    /// a registry at its bound drops its longest-finished key, never one in flight.
    #[tokio::test]
    async fn r06_a_full_registry_keeps_other_registries_and_lookups_in_flight() {
        use crate::registry_type::RegistryType::{Gems, Maven};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let ctx = create_test_context_with_config(|_| {});
        let ttl = Duration::from_secs(300);
        let fetches = Arc::new(AtomicUsize::new(0));
        let counted = |gate: Option<Arc<tokio::sync::Notify>>| {
            let fetches = Arc::clone(&fetches);
            move || async move {
                fetches.fetch_add(1, Ordering::SeqCst);
                if let Some(gate) = gate {
                    gate.notified().await;
                }
                Some(super::Dates::new())
            }
        };
        super::dates(&ctx.state, Gems, "kept", ttl, &[], counted(None)).await;
        let gate = Arc::new(tokio::sync::Notify::new());
        let mut slow = Box::pin(super::dates(
            &ctx.state,
            Maven,
            "slow",
            ttl,
            &[],
            counted(Some(Arc::clone(&gate))),
        ));
        assert!(futures::poll!(&mut slow).is_pending());
        for n in 0..super::KEYS + 8 {
            super::dates(&ctx.state, Maven, &format!("k{n}"), ttl, &[], || async {
                Some(super::Dates::new())
            })
            .await;
        }
        assert!(ctx.state.upstream_dates.lock()[&Maven].len() <= super::KEYS);
        assert_eq!(fetches.load(Ordering::SeqCst), 2);

        super::dates(&ctx.state, Gems, "kept", ttl, &[], counted(None)).await;
        let joined = super::dates(&ctx.state, Maven, "slow", ttl, &[], counted(None));
        gate.notify_one();
        let (first, second) = futures::join!(slow, joined);
        assert!(first.dates.is_some() && second.dates.is_some());
        assert_eq!(
            fetches.load(Ordering::SeqCst),
            2,
            "kept, and joined in flight"
        );
    }

    /// A miss is kept for its window from when the fetch ended, not when it began: a slow
    /// failure is not asked again by the next request.
    #[tokio::test]
    async fn a085_a_kept_lookup_ages_from_its_completion() {
        let ctx = create_test_context_with_config(|_| {});
        let begun = std::time::Instant::now();
        let fetch = || async {
            tokio::time::sleep(Duration::from_millis(400)).await;
            None
        };
        let got = super::dates(
            &ctx.state,
            crate::registry_type::RegistryType::Gems,
            "slow",
            Duration::from_secs(300),
            &[],
            fetch,
        )
        .await;
        assert!(got.dates.is_none());
        let memo = ctx.state.upstream_dates.lock();
        let (stamp, _) = memo[&crate::registry_type::RegistryType::Gems]
            .get("slow")
            .unwrap();
        let age = stamp.lock().elapsed();
        assert!(
            age + Duration::from_millis(300) < begun.elapsed(),
            "{age:?}"
        );
    }

    #[tokio::test]
    async fn a055_date_answer_over_the_cap_is_refused() {
        let upstream = MockServer::start().await;
        let pad = "x".repeat(super::MAX_BODY as usize + 1);
        Mock::given(path("/big"))
            .respond_with(ResponseTemplate::new(200).set_body_string(pad))
            .mount(&upstream)
            .await;
        Mock::given(path("/small"))
            .respond_with(ResponseTemplate::new(200).set_body_string("[]"))
            .mount(&upstream)
            .await;
        let ctx = create_test_context_with_config(|_| {});
        let get = |p: &str| {
            let url = format!("{}{p}", upstream.uri());
            let (state, base) = (ctx.state.clone(), upstream.uri());
            async move {
                super::get(
                    &state,
                    crate::registry_type::RegistryType::Gems,
                    &base,
                    &url,
                    Duration::from_secs(10),
                )
                .await
            }
        };
        assert!(get("/big").await.is_err());
        assert_eq!(get("/small").await.unwrap().as_ref(), b"[]");
    }
}
