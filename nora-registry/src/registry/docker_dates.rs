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

/// When `upstream` published `digest`, which NORA fetched as `name:reference`, by the
/// registry's own record. `None` when the registry has no date for it or the lookup
/// failed; a date in the future is `None` too.
pub(super) async fn published_at(
    state: &AppState,
    upstream: &DockerUpstream,
    source: DateSource,
    name: &str,
    reference: &str,
    digest: &str,
) -> Option<i64> {
    let url = lookup_url(upstream, source, name, reference)?;
    // Its own breaker: a throttled date API must not open the upstream's pull breaker.
    let scope = format!("{}#{}", upstream.url, source.label());
    let body = super::proxy_fetch_capped(
        &state.http_client,
        &url,
        TIMEOUT,
        None,
        &state.circuit_breaker,
        BreakerScope::upstream(RegistryType::Docker, &scope),
        MAX_BODY,
    )
    .await;
    match body {
        Ok(body) => parse(source, &body, reference, digest)
            .filter(|date| *date <= chrono::Utc::now().timestamp()),
        Err(e) => {
            tracing::info!(url = %url, error = ?e, source = source.label(), "docker publish date lookup failed: first-seen applies");
            None
        }
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
        DateSource::HubTagLastPushed => {
            // The Hub API lives on its own host; a non-Hub URL (a mirror, a test) is asked itself.
            let api = if base.ends_with("docker.io") {
                HUB_API
            } else {
                base
            };
            Some(format!("{api}/v2/repositories/{name}/tags/{}", tag?))
        }
        DateSource::QuayLastModified => Some(format!(
            "{base}/api/v1/repository/{name}/tag/?specificTag={}&onlyActiveTags=true",
            tag?
        )),
        DateSource::GcrTimeUploaded => Some(format!("{base}/v2/{name}/tags/list")),
    }
}

/// The date `body` gives `digest`, only when the registry says `reference` is `digest`
/// now (a tag moved since NORA fetched it reads as no date).
fn parse(source: DateSource, body: &[u8], reference: &str, digest: &str) -> Option<i64> {
    let doc: serde_json::Value = serde_json::from_slice(body).ok()?;
    match source {
        DateSource::HubTagLastPushed => {
            if doc["digest"].as_str()? != digest {
                return None;
            }
            let at = doc["tag_last_pushed"].as_str()?;
            Some(chrono::DateTime::parse_from_rfc3339(at).ok()?.timestamp())
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
            parse(DateSource::HubTagLastPushed, hub.as_bytes(), "v1.31.3", D),
            Some(1_790_493_475)
        );
        assert_eq!(
            parse(
                DateSource::HubTagLastPushed,
                hub.as_bytes(),
                "v1.31.3",
                "sha256:other"
            ),
            None
        );

        let quay = format!(
            r#"{{"tags":[{{"name":"0.51.0","start_ts":1772742889,"manifest_digest":"{D}","is_manifest_list":true,"last_modified":"Thu, 05 Mar 2026 20:34:49 -0000"}}],"page":1,"has_additional":false}}"#
        );
        assert_eq!(
            parse(DateSource::QuayLastModified, quay.as_bytes(), "0.51.0", D),
            Some(1_772_742_889)
        );
        assert_eq!(
            parse(
                DateSource::QuayLastModified,
                quay.as_bytes(),
                "0.51.0",
                "sha256:other"
            ),
            None
        );

        let gcr = format!(
            r#"{{"manifest":{{"{D}":{{"mediaType":"application/vnd.docker.distribution.manifest.list.v2+json","tag":["3.10"],"timeUploadedMs":"1716500079876","timeCreatedMs":"0"}}}},"name":"pause","tags":["3.10"]}}"#
        );
        assert_eq!(
            parse(DateSource::GcrTimeUploaded, gcr.as_bytes(), D, D),
            Some(1_716_500_079)
        );
        assert_eq!(
            parse(
                DateSource::GcrTimeUploaded,
                gcr.as_bytes(),
                D,
                "sha256:other"
            ),
            None
        );
        assert_eq!(parse(DateSource::GcrTimeUploaded, b"<html>", D, D), None);
    }
}
