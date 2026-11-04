// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT
//! A docker upstream's own publish date for a manifest (`trust_upstream_dates`,
//! issues-maestra#1649). Read from the registry's record of the push, never from the
//! image (`created` is the builder's, 1970 for some). Best effort: any failure (429,
//! 5xx, timeout, an answer about another digest) is `None`, and the quarantine falls
//! back to NORA's first-seen; the pull itself never waits on more than one lookup.

use crate::circuit_breaker::BreakerScope;
use crate::config::{DateSource, DockerUpstream};
use crate::registry_type::RegistryType;
use crate::AppState;
use std::time::Duration;

/// A gcr.io tags/list names every digest of the repository: megabytes for the largest.
const MAX_BODY: u64 = 8 << 20;
const TIMEOUT: Duration = Duration::from_secs(5);
const HUB_API: &str = "https://hub.docker.com";
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
        let body = fetch(state, upstream, source, &url).await?;
        parse(source, &body, reference, digest, &runnable)
    };
    date.filter(|date| *date <= chrono::Utc::now().timestamp())
}

async fn fetch(
    state: &AppState,
    upstream: &DockerUpstream,
    source: DateSource,
    url: &str,
) -> Option<axum::body::Bytes> {
    // Its own breaker: a throttled date API must not open the upstream's pull breaker.
    let scope = format!("{}#{}", upstream.url, source.label());
    super::proxy_fetch_capped(
        &state.http_client,
        url,
        TIMEOUT,
        None,
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
        let body = fetch(state, upstream, source, &url).await?;
        let (date, more) = search_page(source, &body, digest, runnable)?;
        if date.is_some() || !more {
            return date;
        }
    }
    None
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: &str = "sha256:ed9b00c609e77e99c79b93f1178255ebc271868920f2c69a8d166bd5634ed10d";

    fn upstream(url: &str, ns: &str) -> DockerUpstream {
        DockerUpstream {
            trust_upstream_dates: true,
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
        for ns in ["ghcr.io", "mcr.microsoft.com", "public.ecr.aws", "cgr.dev"] {
            assert_eq!(upstream("https://x", ns).date_source(), None, "{ns}");
        }
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
