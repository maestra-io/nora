// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
//! A docker upstream's own publish date for a manifest (`trust_upstream_dates`,
//! issues-maestra#1649). Read from the registry's record of the push, never from the
//! image (`created` is the builder's, 1970 for some). Best effort: any failure (429,
//! 5xx, timeout, an answer about another digest) is `None`, and the quarantine falls
//! back to NORA's first-seen; the pull itself never waits on more than one lookup.
//!
//! ghcr.io, mcr.microsoft.com and public.ecr.aws date a digest only in a listing of the
//! whole repository, so that listing is walked once per repository ([`WALK_TTL`]) off the
//! request path and shared by every first sight of the repository; a request waits
//! [`TIMEOUT`] for it.

use crate::circuit_breaker::BreakerScope;
use crate::config::{DateSource, DockerUpstream, UpstreamAuth};
use crate::registry_type::RegistryType;
use crate::AppState;
use futures::future::{BoxFuture, FutureExt, Shared};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A gcr.io tags/list names every digest of the repository: megabytes for the largest;
/// the mcr catalog of dotnet/aspnet was 6.9 MB on 05.11.2026.
const MAX_BODY: u64 = 32 << 20;
const TIMEOUT: Duration = Duration::from_secs(5);
const HUB_API: &str = "https://hub.docker.com";
const GITHUB_API: &str = "https://api.github.com";
const ECR_PUBLIC_API: &str = "https://api.us-east-1.gallery.ecr.aws";
/// A walked repository answers first sights this long; a digest pushed since reads as
/// no date (first-seen, so never younger than it is).
const WALK_TTL: Duration = Duration::from_secs(600);
/// A walk that got nothing (401, 429, 5xx) is retried after this.
const WALK_RETRY: Duration = Duration::from_secs(60);
/// One walk, all its pages; it runs on its own task, so a request never waits on it longer
/// than [`TIMEOUT`].
const WALK_DEADLINE: Duration = Duration::from_secs(120);
const WALK_PAGE_TIMEOUT: Duration = Duration::from_secs(20);
/// ghcr lists versions newest first, 100 a page: the newest 1000 are dated.
const GHCR_PAGES: u32 = 10;
/// public.ecr.aws lists tags in no date order, 1000 a page (4 s each): gravitational's
/// teleport-distroless was 17 pages on 05.11.2026, 16140 of them cosign `.sig` tags. 25
/// pages fit in [`WALK_DEADLINE`].
const ECR_PAGES: u32 = 25;
const ECR_PER_PAGE: u32 = 1000;
/// Walked repositories kept; past it the expired ones go, then all.
const WALK_REPOS: usize = 256;
/// A digest reference names no tag, so the newest tags are searched for it. Every hit on
/// the held list of 04.11.2026 sat on the first page; a miss costs all of them, once per
/// digest, inside the one [`TIMEOUT`].
const TAG_PAGES: u32 = 3;
const TAGS_PER_PAGE: u32 = 100;

/// When `upstream` published `digest`, which NORA fetched as `name:reference` with the
/// body `manifest`, by the registry's own record. `None` when the registry has no date for
/// it or the lookup failed; a date in the future is `None` too.
pub(super) async fn published_at(
    state: &AppState,
    upstream: &DockerUpstream,
    source: DateSource,
    name: &str,
    reference: &str,
    digest: &str,
    manifest: &[u8],
) -> Option<i64> {
    if source.walks_repository() {
        let dates = tokio::time::timeout(TIMEOUT, walk(state, upstream, source, name))
            .await
            .ok()
            .flatten()?;
        return dates
            .get(digest)
            .copied()
            .filter(|date| *date <= chrono::Utc::now().timestamp());
    }
    let runnable = runnable_digests(manifest, digest);
    let date = if reference.contains(':') && source != DateSource::GcrTimeUploaded {
        tokio::time::timeout(
            TIMEOUT,
            search_tags(state, upstream, source, name, digest, &runnable),
        )
        .await
        .ok()
        .flatten()
    } else {
        let url = lookup_url(upstream, source, name, reference)?;
        let body = fetch(state, upstream, source, &url, None, TIMEOUT).await?;
        parse(source, &body, reference, digest, &runnable)
    };
    date.filter(|date| *date <= chrono::Utc::now().timestamp())
}

async fn fetch(
    state: &AppState,
    upstream: &DockerUpstream,
    source: DateSource,
    url: &str,
    auth: Option<UpstreamAuth<'_>>,
    timeout: Duration,
) -> Option<axum::body::Bytes> {
    // Its own breaker: a throttled date API must not open the upstream's pull breaker.
    let scope = format!("{}#{}", upstream.url, source.label());
    super::proxy_fetch_capped(
        &state.http_client,
        url,
        timeout,
        auth,
        &state.circuit_breaker,
        BreakerScope::upstream(RegistryType::Docker, &scope),
        MAX_BODY,
    )
    .await
    .inspect_err(|e| {
        tracing::info!(url = %url, error = ?e, source = source.label(), "docker publish date lookup failed: first-seen applies");
    })
    .ok()
}

/// The date of `digest` from the newest [`TAG_PAGES`] pages of the repository's tags. A
/// digest no tag names any more has no date on Docker Hub: being untagged says nothing
/// about its age, so it stays first-seen.
async fn search_tags(
    state: &AppState,
    upstream: &DockerUpstream,
    source: DateSource,
    name: &str,
    digest: &str,
    runnable: &[String],
) -> Option<i64> {
    for page in 1..=TAG_PAGES {
        let url = tags_page_url(upstream, source, name, page);
        let body = fetch(state, upstream, source, &url, None, TIMEOUT).await?;
        let (date, more) = search_page(source, &body, digest, runnable)?;
        if date.is_some() || !more {
            return date;
        }
    }
    None
}

/// Digest -> the registry's date for it, of one repository.
type Dates = HashMap<String, i64>;
type Walk = Shared<BoxFuture<'static, Option<Arc<Dates>>>>;

/// Walks by repository (`AppState::docker_date_walks`): when each started, and the walk
/// every first sight of the repository awaits.
pub type Walks = Mutex<HashMap<String, (Instant, Walk)>>;

/// The walk of `name` that answers now: the cached one while it is fresh, else a new one
/// on its own task, so that a request giving up on it after [`TIMEOUT`] leaves it running
/// for the next first sight.
fn walk(state: &AppState, upstream: &DockerUpstream, source: DateSource, name: &str) -> Walk {
    let key = format!("{}#{}/{name}", upstream.url, source.label());
    let mut walks = state.docker_date_walks.lock();
    if let Some((started, walk)) = walks.get(&key) {
        let ttl = match walk.peek() {
            Some(None) => WALK_RETRY,
            _ => WALK_TTL,
        };
        if started.elapsed() < ttl {
            return walk.clone();
        }
    }
    if walks.len() >= WALK_REPOS {
        walks.retain(|_, (started, _)| started.elapsed() < WALK_TTL);
    }
    if walks.len() >= WALK_REPOS {
        // ponytail: drops every walk at once; an LRU when 256 repositories churn in 10 min.
        walks.clear();
    }
    let task = tokio::spawn(tokio::time::timeout(
        WALK_DEADLINE,
        walk_repository(state.clone(), upstream.clone(), source, name.to_owned()),
    ));
    let walk = task
        .map(|done| done.ok().and_then(Result::ok).flatten().map(Arc::new))
        .boxed()
        .shared();
    walks.insert(key, (Instant::now(), walk.clone()));
    walk
}

/// Every date the repository's listing gives, page by page within the source's bound. A
/// page that fails ends the walk with what came before it (`None` when that is nothing):
/// a digest it misses stays first-seen.
async fn walk_repository(
    state: AppState,
    upstream: DockerUpstream,
    source: DateSource,
    name: String,
) -> Option<Dates> {
    let base = upstream.url.trim_end_matches('/');
    let mut dates = Dates::new();
    match source {
        DateSource::GhcrCreatedAt => {
            let token = date_token(&upstream)?;
            let (owner, package) = name.split_once('/')?;
            let api = if base.ends_with("ghcr.io") {
                GITHUB_API
            } else {
                base
            };
            // `/users/` answers for an organisation too; a nested name is one package.
            let package = package.replace('/', "%2F");
            for page in 1..=GHCR_PAGES {
                let url = format!(
                    "{api}/users/{owner}/packages/container/{package}/versions?per_page=100&page={page}"
                );
                let auth = Some(UpstreamAuth::Bearer(&token));
                let Some(body) =
                    fetch(&state, &upstream, source, &url, auth, WALK_PAGE_TIMEOUT).await
                else {
                    break;
                };
                let Some(listed) = ghcr_page(&body, &mut dates) else {
                    break;
                };
                if listed < 100 {
                    break;
                }
            }
        }
        DateSource::McrLastModified => {
            let url = format!("{base}/api/v1/catalog/{name}/tags?reg=mar");
            let body = fetch(&state, &upstream, source, &url, None, WALK_PAGE_TIMEOUT).await?;
            mcr_catalog(&body, &mut dates)?;
        }
        DateSource::EcrPublicPushedAt => {
            let (alias, repository) = name.split_once('/')?;
            let api = if base.ends_with("public.ecr.aws") {
                ECR_PUBLIC_API
            } else {
                base
            };
            let url = format!("{api}/describeImageTags");
            let mut next: Option<String> = None;
            for _ in 0..ECR_PAGES {
                let mut request = serde_json::json!({
                    "registryAliasName": alias,
                    "repositoryName": repository,
                    "maxResults": ECR_PER_PAGE,
                });
                if let Some(token) = &next {
                    request["nextToken"] = token.as_str().into();
                }
                let Some(body) = post_json(&state, &url, &request).await else {
                    break;
                };
                let Some(more) = ecr_page(&body, &mut dates) else {
                    break;
                };
                next = more;
                if next.is_none() {
                    break;
                }
            }
        }
        _ => return None,
    }
    tracing::info!(upstream = %upstream.url, name = %name, source = source.label(), digests = dates.len(), "docker publish dates walked");
    (!dates.is_empty()).then_some(dates)
}

/// The upstream's `date_token_file`, read at each walk: a mounted Secret that rotates.
fn date_token(upstream: &DockerUpstream) -> Option<String> {
    let path = upstream.date_token_file.as_deref()?;
    match std::fs::read_to_string(path) {
        Ok(token) if !token.trim().is_empty() => Some(token.trim().to_owned()),
        Ok(_) => {
            tracing::info!(path, "docker date_token_file is empty: first-seen applies");
            None
        }
        Err(e) => {
            tracing::info!(path, error = %e, "docker date_token_file unreadable: first-seen applies");
            None
        }
    }
}

/// The public.ecr.aws gallery API is a POST; it has no breaker of its own (a failed walk
/// is retried after [`WALK_RETRY`] only).
async fn post_json(
    state: &AppState,
    url: &str,
    request: &serde_json::Value,
) -> Option<axum::body::Bytes> {
    let sent = state
        .http_client
        .post(url)
        .json(request)
        .timeout(WALK_PAGE_TIMEOUT)
        .send()
        .await;
    let response = match sent {
        Ok(response) if response.status().is_success() => response,
        Ok(response) => {
            tracing::info!(url, status = %response.status(), "docker publish date lookup failed: first-seen applies");
            return None;
        }
        Err(e) => {
            tracing::info!(url, error = %e, "docker publish date lookup failed: first-seen applies");
            return None;
        }
    };
    if response.content_length().is_some_and(|n| n > MAX_BODY) {
        return None;
    }
    response.bytes().await.ok()
}

fn rfc3339(at: &serde_json::Value) -> Option<i64> {
    Some(
        chrono::DateTime::parse_from_rfc3339(at.as_str()?)
            .ok()?
            .timestamp(),
    )
}

/// One page of ghcr package versions: each version is a digest (an index and each of its
/// platform manifests apart) with the `created_at` GitHub set when it was pushed. How many
/// versions the page listed, `None` for an answer that is not a page.
fn ghcr_page(body: &[u8], dates: &mut Dates) -> Option<usize> {
    let doc: serde_json::Value = serde_json::from_slice(body).ok()?;
    let versions = doc.as_array()?;
    for v in versions {
        if let (Some(digest), Some(at)) = (v["name"].as_str(), rfc3339(&v["created_at"])) {
            dates.entry(digest.to_owned()).or_insert(at);
        }
    }
    Some(versions.len())
}

/// The mcr catalog of a repository: every tag with the digest it names and when the tag
/// last moved (`createdDate` is the tag's first push, not the digest's). A digest takes
/// the earliest move of the tags naming it: no tag moved onto it before it was pushed.
fn mcr_catalog(body: &[u8], dates: &mut Dates) -> Option<()> {
    let doc: serde_json::Value = serde_json::from_slice(body).ok()?;
    for tag in doc.as_array()? {
        if let (Some(digest), Some(at)) =
            (tag["digest"].as_str(), rfc3339(&tag["lastModifiedDate"]))
        {
            dates
                .entry(digest.to_owned())
                .and_modify(|d| *d = (*d).min(at))
                .or_insert(at);
        }
    }
    Some(())
}

/// One page of public.ecr.aws `describeImageTags`: the digest each tag names with its
/// `imagePushedAt`. Cosign tags (`.sig`, `.att`, `.sbom`) name signatures, not images. The
/// next page's token, `None` for an answer that is not a page.
fn ecr_page(body: &[u8], dates: &mut Dates) -> Option<Option<String>> {
    let doc: serde_json::Value = serde_json::from_slice(body).ok()?;
    for tag in doc["imageTagDetails"].as_array()? {
        let name = tag["imageTag"].as_str().unwrap_or_default();
        if [".sig", ".att", ".sbom"].iter().any(|s| name.ends_with(s)) {
            continue;
        }
        let image = &tag["imageDetail"];
        if let (Some(digest), Some(at)) = (
            image["imageDigest"].as_str(),
            rfc3339(&image["imagePushedAt"]),
        ) {
            dates.entry(digest.to_owned()).or_insert(at);
        }
    }
    Some(doc["nextToken"].as_str().map(str::to_owned))
}

/// The manifests a client can run from `manifest`: an index's platform manifests without
/// its attestations (the tag record does not list those), else the manifest itself.
fn runnable_digests(manifest: &[u8], digest: &str) -> Vec<String> {
    let doc: serde_json::Value = serde_json::from_slice(manifest).unwrap_or_default();
    match doc["manifests"].as_array() {
        Some(listed) => listed
            .iter()
            .filter(|m| {
                m["annotations"]["vnd.docker.reference.type"].as_str()
                    != Some("attestation-manifest")
            })
            .filter_map(|m| m["digest"].as_str().map(str::to_owned))
            .collect(),
        None => vec![digest.to_owned()],
    }
}

fn hub_api(base: &str) -> &str {
    // The Hub API lives on its own host; a non-Hub URL (a mirror, a test) is asked itself.
    if base.ends_with("docker.io") {
        HUB_API
    } else {
        base
    }
}

fn tags_page_url(upstream: &DockerUpstream, source: DateSource, name: &str, page: u32) -> String {
    let base = upstream.url.trim_end_matches('/');
    if source == DateSource::QuayLastModified {
        // Inactive tags too: quay keeps the history, so a digest its tag moved off is dated.
        format!("{base}/api/v1/repository/{name}/tag/?limit={TAGS_PER_PAGE}&page={page}&onlyActiveTags=false")
    } else {
        format!(
            "{}/v2/repositories/{name}/tags?page_size={TAGS_PER_PAGE}&ordering=last_updated&page={page}",
            hub_api(base)
        )
    }
}

/// The request that answers the date: Docker Hub and quay.io date a tag (a digest
/// reference has no lookup), the gcr family dates every digest of the repository.
fn lookup_url(
    upstream: &DockerUpstream,
    source: DateSource,
    name: &str,
    reference: &str,
) -> Option<String> {
    let base = upstream.url.trim_end_matches('/');
    let tag = (!reference.contains(':')).then_some(reference);
    match source {
        DateSource::HubTagLastPushed => Some(format!(
            "{}/v2/repositories/{name}/tags/{}",
            hub_api(base),
            tag?
        )),
        DateSource::QuayLastModified => Some(format!(
            "{base}/api/v1/repository/{name}/tag/?specificTag={}&onlyActiveTags=true",
            tag?
        )),
        DateSource::GcrTimeUploaded => Some(format!("{base}/v2/{name}/tags/list")),
        _ => None,
    }
}

/// Whether every manifest in `runnable` is in the images of a Hub tag record.
fn hub_lists(tag: &serde_json::Value, runnable: &[String]) -> bool {
    let images = tag["images"].as_array().map_or(&[][..], Vec::as_slice);
    !runnable.is_empty()
        && runnable
            .iter()
            .all(|d| images.iter().any(|i| i["digest"].as_str() == Some(d)))
}

fn hub_date(tag: &serde_json::Value) -> Option<i64> {
    let at = tag["tag_last_pushed"].as_str()?;
    Some(chrono::DateTime::parse_from_rfc3339(at).ok()?.timestamp())
}

/// One page of tags: the date it gives `digest`, and whether another page follows. `None`
/// for an answer that is not a page. A Hub tag dates what it lists: the digest itself, a
/// platform manifest of it, or an index all of whose platforms it carries, because the
/// tag's last push is no older than anything it names.
fn search_page(
    source: DateSource,
    body: &[u8],
    digest: &str,
    runnable: &[String],
) -> Option<(Option<i64>, bool)> {
    let doc: serde_json::Value = serde_json::from_slice(body).ok()?;
    if source == DateSource::QuayLastModified {
        let date = doc["tags"]
            .as_array()?
            .iter()
            .find(|t| t["manifest_digest"].as_str() == Some(digest))
            .and_then(|t| t["last_modified"].as_str())
            .and_then(|at| chrono::DateTime::parse_from_rfc2822(at).ok())
            .map(|at| at.timestamp());
        return Some((date, doc["has_additional"].as_bool().unwrap_or(false)));
    }
    let date = doc["results"]
        .as_array()?
        .iter()
        .find(|t| t["digest"].as_str() == Some(digest) || hub_lists(t, runnable))
        .and_then(hub_date);
    Some((date, doc["next"].is_string()))
}

/// The date `body` gives `digest`, only when the registry says `reference` is `digest`
/// now (a tag moved since NORA fetched it reads as no date). A Hub tag last pushed before
/// the API recorded digests has none: its images stand in for it, so a stale answer about
/// a re-pushed tag still reads as no date.
fn parse(
    source: DateSource,
    body: &[u8],
    reference: &str,
    digest: &str,
    runnable: &[String],
) -> Option<i64> {
    let doc: serde_json::Value = serde_json::from_slice(body).ok()?;
    match source {
        DateSource::HubTagLastPushed => {
            let same = match doc["digest"].as_str() {
                Some(named) => named == digest,
                None => hub_lists(&doc, runnable),
            };
            same.then(|| hub_date(&doc)).flatten()
        }
        DateSource::QuayLastModified => {
            let tag = doc["tags"].as_array()?.iter().find(|t| {
                t["name"].as_str() == Some(reference)
                    && t["manifest_digest"].as_str() == Some(digest)
            })?;
            let at = tag["last_modified"].as_str()?;
            Some(chrono::DateTime::parse_from_rfc2822(at).ok()?.timestamp())
        }
        DateSource::GcrTimeUploaded => {
            let ms: i64 = doc["manifest"][digest]["timeUploadedMs"]
                .as_str()?
                .parse()
                .ok()?;
            (ms > 0).then_some(ms / 1000)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: &str = "sha256:ed9b00c609e77e99c79b93f1178255ebc271868920f2c69a8d166bd5634ed10d";

    fn upstream(url: &str, ns: &str) -> DockerUpstream {
        DockerUpstream {
            trust_upstream_dates: true,
            date_token_file: None,
            url: url.into(),
            auth: None,
            auth_env: None,
            namespace: Some(ns.into()),
            prefix: None,
            namespaces: Vec::new(),
        }
    }

    #[test]
    fn each_registry_family_has_its_lookup() {
        let hub = upstream("https://registry-1.docker.io", "docker.io");
        assert_eq!(hub.date_source(), Some(DateSource::HubTagLastPushed));
        assert_eq!(
            lookup_url(
                &hub,
                DateSource::HubTagLastPushed,
                "axllent/mailpit",
                "v1.31.3"
            )
            .as_deref(),
            Some("https://hub.docker.com/v2/repositories/axllent/mailpit/tags/v1.31.3")
        );
        assert_eq!(
            lookup_url(&hub, DateSource::HubTagLastPushed, "a/b", D),
            None
        );
        let quay = upstream("https://quay.io", "quay.io");
        assert_eq!(quay.date_source(), Some(DateSource::QuayLastModified));
        assert_eq!(
            lookup_url(&quay, DateSource::QuayLastModified, "strimzi/operator", "0.51.0").as_deref(),
            Some("https://quay.io/api/v1/repository/strimzi/operator/tag/?specificTag=0.51.0&onlyActiveTags=true")
        );
        let k8s = upstream("https://registry.k8s.io", "registry.k8s.io");
        assert_eq!(k8s.date_source(), Some(DateSource::GcrTimeUploaded));
        assert_eq!(
            lookup_url(&k8s, DateSource::GcrTimeUploaded, "pause", D).as_deref(),
            Some("https://registry.k8s.io/v2/pause/tags/list")
        );
        let gar = upstream("https://x", "europe-west1-docker.pkg.dev");
        assert_eq!(gar.date_source(), Some(DateSource::GcrTimeUploaded));
        for (ns, source) in [
            ("ghcr.io", DateSource::GhcrCreatedAt),
            ("mcr.microsoft.com", DateSource::McrLastModified),
            ("public.ecr.aws", DateSource::EcrPublicPushedAt),
        ] {
            assert_eq!(
                upstream("https://x", ns).date_source(),
                Some(source),
                "{ns}"
            );
            assert!(source.walks_repository());
        }
        for ns in ["cgr.dev", "docker.dragonflydb.io", "xpkg.upbound.io"] {
            assert_eq!(upstream("https://x", ns).date_source(), None, "{ns}");
        }
    }

    /// Bodies trimmed from the live answers of 05.11.2026.
    #[test]
    fn walked_listings_date_each_digest_by_the_registry() {
        // ghcr: actions/actions-runner 2.338.2, the index and a platform manifest apart.
        let ghcr = br#"[{"name":"sha256:759a1d94a15b","created_at":"2026-10-26T14:50:37Z","metadata":{"container":{"tags":["2.338.2","latest"]}}},
            {"name":"sha256:69add0c05ce2","created_at":"2026-10-26T14:50:46Z","metadata":{"container":{"tags":[]}}}]"#;
        let mut dates = Dates::new();
        assert_eq!(ghcr_page(ghcr, &mut dates), Some(2));
        assert_eq!(dates["sha256:759a1d94a15b"], 1_793_026_237);
        assert_eq!(dates.len(), 2);
        assert_eq!(
            ghcr_page(br#"{"message":"Bad credentials"}"#, &mut dates),
            None
        );

        // mcr: dotnet/monitor `10`, `10.0` and `latest` name one digest and moved within two
        // minutes of each other; `createdDate` (the tag's first push, 2025) is not used.
        let mcr = br#"[{"name":"10","digest":"sha256:200dbc2060a2","lastModifiedDate":"2026-10-29T02:54:08.0000000+00:00","createdDate":"2025-11-11T14:19:49.0000000+00:00"},
            {"name":"10.0.5","digest":"sha256:200dbc2060a2","lastModifiedDate":"2026-10-29T02:52:42.0000000+00:00","createdDate":"2026-10-29T02:52:42.0000000+00:00"},
            {"name":"9","digest":"sha256:d9a6daf51bfa","lastModifiedDate":"2026-10-29T02:52:47.0000000+00:00","createdDate":"2024-11-12T00:00:00.0000000+00:00"}]"#;
        let mut dates = Dates::new();
        assert_eq!(mcr_catalog(mcr, &mut dates), Some(()));
        assert_eq!(
            dates["sha256:200dbc2060a2"], 1_793_242_362,
            "the earliest move"
        );
        assert_eq!(dates.len(), 2);
        assert_eq!(mcr_catalog(b"<html>", &mut dates), None);

        // public.ecr.aws: gravitational/teleport-distroless, a cosign tag skipped.
        let ecr = br#"{"imageTagDetails":[
            {"imageTag":"sha256-97c78f0f46cf.sig","createdAt":"2026-06-09T16:37:55.974Z","imageDetail":{"imageDigest":"sha256:a87cd31fc783","imagePushedAt":"2026-06-09T16:37:55.815Z"}},
            {"imageTag":"18.2.2","createdAt":"2025-09-24T10:00:00Z","imageDetail":{"imageDigest":"sha256:f8f3974301fd","imagePushedAt":"2025-09-24T10:00:00.000Z"}}],
            "nextToken":"opaque"}"#;
        let mut dates = Dates::new();
        assert_eq!(ecr_page(ecr, &mut dates), Some(Some("opaque".to_owned())));
        assert_eq!(dates.len(), 1);
        assert_eq!(dates["sha256:f8f3974301fd"], 1_758_708_000);
        assert_eq!(
            ecr_page(br#"{"imageTagDetails":[]}"#, &mut dates),
            Some(None)
        );
    }

    /// Bodies trimmed from the live answers of 02.11.2026.
    #[test]
    fn each_registry_answer_dates_only_the_digest_it_names() {
        let hub = format!(
            r#"{{"name":"v1.31.3","digest":"{D}","tag_last_pushed":"2026-09-27T07:17:55.672391Z","images":[]}}"#
        );
        assert_eq!(
            parse(
                DateSource::HubTagLastPushed,
                hub.as_bytes(),
                "v1.31.3",
                D,
                &[]
            ),
            Some(1_790_493_475)
        );
        assert_eq!(
            parse(
                DateSource::HubTagLastPushed,
                hub.as_bytes(),
                "v1.31.3",
                "sha256:other",
                &[]
            ),
            None
        );

        let quay = format!(
            r#"{{"tags":[{{"name":"0.51.0","start_ts":1772742889,"manifest_digest":"{D}","is_manifest_list":true,"last_modified":"Thu, 05 Mar 2026 20:34:49 -0000"}}],"page":1,"has_additional":false}}"#
        );
        assert_eq!(
            parse(
                DateSource::QuayLastModified,
                quay.as_bytes(),
                "0.51.0",
                D,
                &[]
            ),
            Some(1_772_742_889)
        );
        assert_eq!(
            parse(
                DateSource::QuayLastModified,
                quay.as_bytes(),
                "0.51.0",
                "sha256:other",
                &[]
            ),
            None
        );

        let gcr = format!(
            r#"{{"manifest":{{"{D}":{{"mediaType":"application/vnd.docker.distribution.manifest.list.v2+json","tag":["3.10"],"timeUploadedMs":"1716500079876","timeCreatedMs":"0"}}}},"name":"pause","tags":["3.10"]}}"#
        );
        assert_eq!(
            parse(DateSource::GcrTimeUploaded, gcr.as_bytes(), D, D, &[]),
            Some(1_716_500_079)
        );
        assert_eq!(
            parse(
                DateSource::GcrTimeUploaded,
                gcr.as_bytes(),
                D,
                "sha256:other",
                &[]
            ),
            None
        );
        assert_eq!(
            parse(DateSource::GcrTimeUploaded, b"<html>", D, D, &[]),
            None
        );
    }

    const P1: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const P2: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

    /// nginx:1.21.0 on 04.11.2026, trimmed: a pushed date and images, no `digest`.
    fn old_tag(images: &[&str]) -> String {
        let images: Vec<_> = images
            .iter()
            .map(|d| serde_json::json!({"digest": d, "architecture": "amd64"}))
            .collect();
        serde_json::json!({"name": "1.21.0", "tag_last_pushed": "2021-06-23T09:57:28.310033Z", "images": images}).to_string()
    }

    #[test]
    fn a_hub_tag_without_a_digest_dates_only_the_platforms_it_lists() {
        let hub = |body: &str, runnable: &[String]| {
            parse(
                DateSource::HubTagLastPushed,
                body.as_bytes(),
                "1.21.0",
                D,
                runnable,
            )
        };
        let both = [P1.to_string(), P2.to_string()];
        assert_eq!(hub(&old_tag(&[P1, P2]), &both), Some(1_624_442_248));
        assert_eq!(
            hub(&old_tag(&[P1]), &both),
            None,
            "a platform it does not list"
        );
        assert_eq!(hub(&old_tag(&[]), &both), None, "nothing to check against");
        assert_eq!(
            hub(&old_tag(&[P1, P2]), &[]),
            None,
            "an index with no platforms"
        );
        // A digest the record does name wins over the images: a differing one is rejected.
        let moved =
            serde_json::json!({"digest": "sha256:other", "tag_last_pushed": "2021-06-23T09:57:28Z",
            "images": [{"digest": P1}, {"digest": P2}]})
            .to_string();
        assert_eq!(hub(&moved, &both), None);
    }

    #[test]
    fn runnable_digests_leave_attestations_out() {
        let index = serde_json::json!({"manifests": [
            {"digest": P1, "platform": {"architecture": "amd64", "os": "linux"}},
            {"digest": P2, "platform": {"architecture": "unknown", "os": "unknown"},
             "annotations": {"vnd.docker.reference.type": "attestation-manifest"}},
        ]})
        .to_string();
        assert_eq!(runnable_digests(index.as_bytes(), D), [P1]);
        assert_eq!(runnable_digests(br#"{"config":{}}"#, D), [D]);
    }

    #[test]
    fn a_tag_page_dates_a_digest_by_the_tag_that_carries_it() {
        let page = serde_json::json!({"next": "https://hub.docker.com/next", "results": [
            {"name": "latest", "digest": "sha256:other", "tag_last_pushed": "2026-10-28T02:53:21Z",
             "images": [{"digest": "sha256:another"}]},
            {"name": "4.1.1", "digest": "sha256:index", "tag_last_pushed": "2021-06-23T09:57:28Z",
             "images": [{"digest": P1}, {"digest": P2}]},
        ]})
        .to_string();
        let hub = |digest: &str, runnable: &[String]| {
            search_page(
                DateSource::HubTagLastPushed,
                page.as_bytes(),
                digest,
                runnable,
            )
        };
        let dated = Some((Some(1_624_442_248), true));
        assert_eq!(hub("sha256:index", &[]), dated, "the tag's own digest");
        assert_eq!(
            hub(P1, &[P1.to_string()]),
            dated,
            "a platform manifest of it"
        );
        assert_eq!(
            hub(D, &[P1.to_string(), P2.to_string()]),
            dated,
            "an index all of whose platforms it carries"
        );
        assert_eq!(
            hub(D, &[P1.to_string(), "sha256:new".to_string()]),
            Some((None, true)),
            "a platform no tag carries"
        );

        let quay = format!(
            r#"{{"tags":[{{"name":"latest","manifest_digest":"{D}","end_ts":1772742899,"last_modified":"Thu, 05 Mar 2026 20:34:49 -0000"}}],"has_additional":false}}"#
        );
        assert_eq!(
            search_page(DateSource::QuayLastModified, quay.as_bytes(), D, &[]),
            Some((Some(1_772_742_889), false)),
            "quay's history dates a digest its tag moved off"
        );
        assert_eq!(
            search_page(DateSource::HubTagLastPushed, b"<html>", D, &[]),
            None
        );
    }
}
