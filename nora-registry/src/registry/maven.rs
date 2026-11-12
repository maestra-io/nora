// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Maven registry — Maven 2 repository layout with checksums, immutability,
//! and automatic `maven-metadata.xml` generation.
//!
//! Implements:
//!   GET  /maven2/{*path}  — download artifact, checksum, or metadata
//!   PUT  /maven2/{*path}  — upload artifact (with auto-checksum + metadata update)

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::auth::{enforce_namespace_scope, NamespaceAuthority};
use crate::circuit_breaker::BreakerScope;
use crate::config::UpstreamAuth;
use crate::registry::{
    method_not_allowed, proxy_fetch, proxy_fetch_artifact, ProxyBody, UpstreamMiss,
};
use crate::registry_type::RegistryType;
use crate::storage::StorageError;
use crate::validation::ends_with_ci;
use crate::AppState;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Extension, Router,
};
use nora_registry::maven_paths::{
    classify_path, compare_maven_versions, is_checksum_file, is_snapshot, xml_escape, MavenPathKind,
};
use quick_xml::{events::Event, Reader};
use sha2::Digest;
use std::collections::BTreeSet;
use std::time::Duration;

/// Build the storage key for a Maven artifact at repo-relative `path`.
///
/// Single source of truth for the `maven/<path>` layout so that anything writing
/// Maven objects (the handlers here, and `nora import` — review R7, contract
/// `import-key-format-equals-handler-key-format`) produces byte-identical keys
/// that GC/retention/UI browse walk as strings.
pub(crate) fn storage_key(path: &str) -> String {
    format!("maven/{path}")
}

pub fn routes() -> Router<AppState> {
    Router::new().route(
        "/maven2/{*path}",
        get(download)
            .put(upload)
            .fallback(|| async { method_not_allowed("GET, PUT") }),
    )
}

// ============================================================================
// Path parsing
// ============================================================================

#[derive(Debug, PartialEq, Eq)]
enum MavenMetadataLevel {
    Group,
    Artifact,
    Version,
}

fn classify_metadata_level(data: &[u8]) -> Option<MavenMetadataLevel> {
    let mut reader = Reader::from_reader(data);
    reader.config_mut().trim_text(true);

    let mut depth = 0;
    let mut root_seen = false;
    let mut root_closed = false;
    let mut has_artifact_id = false;
    let mut has_version = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                let name = element.local_name();
                if depth == 0 {
                    if root_seen || name.as_ref() != b"metadata" {
                        return None;
                    }
                    root_seen = true;
                } else if depth == 1 {
                    has_artifact_id |= name.as_ref() == b"artifactId";
                    has_version |= name.as_ref() == b"version";
                }
                depth += 1;
            }
            Ok(Event::Empty(element)) => {
                let name = element.local_name();
                if depth == 0 {
                    if root_seen || name.as_ref() != b"metadata" {
                        return None;
                    }
                    root_seen = true;
                    root_closed = true;
                } else if depth == 1 {
                    has_artifact_id |= name.as_ref() == b"artifactId";
                    has_version |= name.as_ref() == b"version";
                }
            }
            Ok(Event::End(element)) => {
                if depth == 0 {
                    return None;
                }
                depth -= 1;
                if depth == 0 {
                    if element.local_name().as_ref() != b"metadata" {
                        return None;
                    }
                    root_closed = true;
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return None,
            _ => {}
        }
    }

    if !root_seen || !root_closed || depth != 0 {
        return None;
    }

    if has_version {
        Some(MavenMetadataLevel::Version)
    } else if has_artifact_id {
        Some(MavenMetadataLevel::Artifact)
    } else {
        Some(MavenMetadataLevel::Group)
    }
}

fn metadata_document_key(checksum_key: &str) -> Option<&str> {
    [".md5", ".sha1", ".sha256", ".sha512"]
        .into_iter()
        .find_map(|suffix| checksum_key.strip_suffix(suffix))
}

fn checksum_suffix(path: &str) -> Option<&'static str> {
    [".md5", ".sha1", ".sha256", ".sha512"]
        .into_iter()
        .find(|suffix| path.ends_with(suffix))
        .map(|suffix| &suffix[1..])
}

/// The artifacts a `maven-metadata.xml` path can belong to. maven-resolver writes metadata at
/// three levels (`Maven2RepositoryLayoutFactory`): an artifact's (`group/artifact/`), a snapshot
/// version's (`group/artifact/1.0-SNAPSHOT/`) and a group's plugin list (`group/`), and the path
/// alone does not tell an artifact's from a group's. So the path reads as the artifact
/// `group:artifact`; as the artifact of a snapshot version, when its last directory is one; and
/// as the group, every artifact of which a `group.name:` namespace covers.
fn metadata_names(group_path: &str, artifact_id: &str) -> Vec<String> {
    let group = group_path.replace('/', ".");
    let mut names = vec![format!("{group}:{artifact_id}")];
    if is_snapshot(artifact_id) {
        if let Some((parent, artifact)) = group_path.rsplit_once('/') {
            names.push(format!("{}:{artifact}", parent.replace('/', ".")));
        }
    }
    if group.is_empty() {
        names.push(format!("{artifact_id}:"));
    } else {
        names.push(format!("{group}.{artifact_id}:"));
    }
    names
}

/// Whether a Maven path points at a MUTABLE resource that must be revalidated when proxied:
/// `maven-metadata.xml` (and its checksums) is rewritten as versions are deployed, and SNAPSHOT
/// version files are republished in place. Release artifacts are immutable.
fn is_mutable_maven_path(path: &str) -> bool {
    if ends_with_ci(path, "maven-metadata.xml")
        || ends_with_ci(path, "maven-metadata.xml.sha1")
        || ends_with_ci(path, "maven-metadata.xml.md5")
        || ends_with_ci(path, "maven-metadata.xml.sha256")
        || ends_with_ci(path, "maven-metadata.xml.sha512")
    {
        return true;
    }
    matches!(classify_path(path), MavenPathKind::VersionFile(c) if is_snapshot(&c.version))
}

/// True when a URL points at Maven Central (one of its canonical hosts) — the only
/// Maven upstream NORA reads a per-artifact date from (`Last-Modified`, its search API).
/// A private mirror (Nexus/Artifactory) returns false, so its coordinates are never sent
/// to the public search.maven.org (#68/#733).
fn url_is_maven_central(u: &str) -> bool {
    u.contains("repo1.maven.org")
        || u.contains("repo.maven.apache.org")
        || u.contains("search.maven.org")
        || u.contains("central.sonatype")
}

/// Central's search API: the fallback date source when the file's own `Last-Modified` is
/// not available.
const MAVEN_CENTRAL_SEARCH: &str = "https://search.maven.org";

/// Why a date lookup gave no date: the `outcome` label of `nora_maven_date_lookup_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DateMiss {
    Timeout,
    Transport,
    Status(u16),
    /// Central has no such file / GAV: not a failure, the artifact is not on Central.
    NotFound,
    /// Answered without a date (no `Last-Modified`, no `timestamp`).
    Missing,
    Parse,
}

impl DateMiss {
    fn outcome(self) -> &'static str {
        match self {
            DateMiss::Timeout => "timeout",
            DateMiss::Transport => "transport",
            DateMiss::Status(_) => "status",
            DateMiss::NotFound => "not_found",
            DateMiss::Missing => "missing",
            DateMiss::Parse => "parse",
        }
    }

    fn from_send(e: &reqwest::Error) -> Self {
        if e.is_timeout() {
            DateMiss::Timeout
        } else {
            DateMiss::Transport
        }
    }

    fn from_status(status: reqwest::StatusCode) -> Self {
        if status == reqwest::StatusCode::NOT_FOUND {
            DateMiss::NotFound
        } else {
            DateMiss::Status(status.as_u16())
        }
    }
}

/// `Last-Modified` of the file on Central (a HEAD): Central files are immutable, so it is
/// the upload date.
async fn central_last_modified(
    client: &reqwest::Client,
    file_url: &str,
    auth: Option<&str>,
    timeout: Duration,
) -> Result<i64, DateMiss> {
    let mut request = client.head(file_url).timeout(timeout);
    if let Some(credentials) = auth {
        let value = UpstreamAuth::Basic(credentials)
            .header_value()
            .map_err(|_| DateMiss::Transport)?;
        request = request.header(header::AUTHORIZATION, value);
    }
    let resp = request.send().await.map_err(|e| DateMiss::from_send(&e))?;
    if !resp.status().is_success() {
        return Err(DateMiss::from_status(resp.status()));
    }
    let lm = resp
        .headers()
        .get(header::LAST_MODIFIED)
        .ok_or(DateMiss::Missing)?;
    let lm = lm.to_str().map_err(|_| DateMiss::Parse)?;
    chrono::DateTime::parse_from_rfc2822(lm)
        .map(|at| at.timestamp())
        .map_err(|_| DateMiss::Parse)
}

/// Upload timestamp of a GAV from the Central search API.
async fn central_search_date(
    client: &reqwest::Client,
    search_base: &str,
    (group, artifact, version): (&str, &str, &str),
    timeout: Duration,
) -> Result<i64, DateMiss> {
    let url = format!(
        "{}/solrsearch/select?q=g:%22{}%22+AND+a:%22{}%22+AND+v:%22{}%22&core=gav&rows=1&wt=json",
        search_base, group, artifact, version
    );
    let resp = client
        .get(&url)
        .timeout(timeout)
        .send()
        .await
        .map_err(|e| DateMiss::from_send(&e))?;
    if !resp.status().is_success() {
        return Err(DateMiss::from_status(resp.status()));
    }
    let json: serde_json::Value = resp.json().await.map_err(|e| {
        if e.is_timeout() {
            DateMiss::Timeout
        } else {
            DateMiss::Parse
        }
    })?;
    let docs = json["response"]["docs"].as_array().ok_or(DateMiss::Parse)?;
    let doc = docs.first().ok_or(DateMiss::NotFound)?;
    let ts_ms = doc["timestamp"].as_i64().ok_or(DateMiss::Missing)?;
    Ok(ts_ms / 1000)
}

fn record_date_lookup(source: &str, result: Result<i64, DateMiss>, path: &str) {
    let outcome = result.map_or_else(DateMiss::outcome, |_| "ok");
    crate::metrics::MAVEN_DATE_LOOKUP_TOTAL
        .with_label_values(&[source, outcome])
        .inc();
    match result {
        Ok(_) => {}
        // Not on Central (a maven.google.com artifact): expected, nothing to act on.
        Err(DateMiss::NotFound) => {
            tracing::debug!(source, path, "Maven Central has no date for this artifact")
        }
        Err(miss) => tracing::warn!(
            source,
            path,
            reason = outcome,
            status = ?match miss { DateMiss::Status(code) => Some(code), _ => None },
            "Maven Central date lookup failed; the quarantine falls back to first_seen"
        ),
    }
}

/// Upload date of a Maven Central file: its `Last-Modified`, else the search API's GAV
/// `timestamp`, both within one `budget` (a slow or throttled lookup must not hold the
/// download). `None` leaves the quarantine on NORA's first-seen clock; every failure is
/// logged at WARN with its reason and counted in `nora_maven_date_lookup_total`.
async fn maven_central_publish_date(
    client: &reqwest::Client,
    file_url: &str,
    auth: Option<&str>,
    search_base: &str,
    gav: (&str, &str, &str),
    budget: Duration,
) -> Option<i64> {
    let started = std::time::Instant::now();
    let head = central_last_modified(client, file_url, auth, budget).await;
    record_date_lookup("last_modified", head, file_url);
    match head {
        Ok(ts) => return Some(ts),
        // Not on Central / out of budget: the search cannot answer either.
        Err(DateMiss::NotFound | DateMiss::Timeout) => return None,
        Err(_) => {}
    }
    let remaining = budget.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        record_date_lookup("search", Err(DateMiss::Timeout), file_url);
        return None;
    }
    let search = central_search_date(client, search_base, gav, remaining).await;
    record_date_lookup("search", search, file_url);
    search.ok()
}

/// [`maven_central_publish_date`] of `path` on the configured Central proxy; `None` with no
/// Central proxy, so a private mirror's coordinates never reach Central (#68/#733).
async fn central_publish_date(
    state: &AppState,
    path: &str,
    maven_name: &str,
    version: &str,
) -> Option<i64> {
    let central = state
        .config
        .maven
        .proxies
        .iter()
        .find(|p| url_is_maven_central(p.url()))?;
    let (group, artifact) = maven_name.split_once(':')?;
    maven_central_publish_date(
        &state.http_client,
        &format!("{}/{}", central.url().trim_end_matches('/'), path),
        central.auth(),
        MAVEN_CENTRAL_SEARCH,
        (group, artifact, version),
        Duration::from_secs(state.config.maven.date_lookup_timeout),
    )
    .await
}

/// A held digest is dated again at most once per this many seconds.
const REDATE_RETRY_SECS: i64 = 3600;

/// When each held digest was last dated again (unix seconds).
// ponytail: process-local; a restart retries every held digest once, which is the point.
static REDATE_TRIED: std::sync::LazyLock<
    parking_lot::Mutex<std::collections::HashMap<String, i64>>,
> = std::sync::LazyLock::new(Default::default);

/// A cached artifact the quarantine holds, or has no entry for, is dated before it is served:
/// a cache hit asks no upstream, so a lookup that failed on the miss (a throttled search, the
/// 30 s misses of 11.11.2026) would hold a years-old artifact for the whole TTL. No entry is
/// the common case after a restart: an artifact dated past the prune line on its miss is not
/// persisted (`DigestStore::record`), so the next hit would start its clock at now (216
/// first hits held on 11.11.2026 after the .16 rollout). `lookup` runs once per digest per
/// [`REDATE_RETRY_SECS`]; its date only moves the clock back (`backdate`, persisted), never
/// forward, and no date keeps first_seen.
async fn redate_held<F, Fut>(
    store: &crate::digest_quarantine::DigestStore,
    digest: &str,
    quarantine_secs: i64,
    lookup: F,
) where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Option<i64>>,
{
    let was = store.check("maven", digest, quarantine_secs);
    if was == crate::digest_quarantine::QuarantineStatus::Mature {
        return;
    }
    let now = crate::cache_ttl::now_unix() as i64;
    {
        let mut tried = REDATE_TRIED.lock();
        if tried
            .get(digest)
            .is_some_and(|at| now - at < REDATE_RETRY_SECS)
        {
            return;
        }
        tried.retain(|_, at| now - *at < REDATE_RETRY_SECS);
        // While the ledger loads, its merge prunes an entry dated past the prune line, so
        // the next hit must be free to date it again.
        if store.loaded() {
            tried.insert(digest.to_string(), now);
        }
    }
    let Some(at) = lookup().await else {
        return;
    };
    // Creates a missing entry at the date; an existing one keeps its own until backdated.
    store.record("maven", digest, "cache", Some(at));
    if let Some(entry) = store.backdate("maven", digest, at, true) {
        if entry.first_seen == at {
            tracing::info!(
                digest,
                first_seen = at,
                ?was,
                "Quarantine: held Maven artifact dated by Central"
            );
        }
    }
}

// ============================================================================
// Download
// ============================================================================

async fn download(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(path): Path<String>,
) -> Response {
    let key = storage_key(&path);
    // A path with an empty segment names another artifact's file and must not reach
    // curation, storage or an upstream (which may normalise it to that artifact).
    if crate::validation::validate_storage_key(&key).is_err() {
        return (StatusCode::BAD_REQUEST, "Invalid path").into_response();
    }

    let artifact_name = path
        .split('/')
        .rev()
        .take(3)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("/");

    // Classify path for curation (used in both pre-download and integrity checks)
    let curation_coords = if let MavenPathKind::VersionFile(coords) = classify_path(&path) {
        let maven_name = format!(
            "{}:{}",
            coords.group_path.replace('/', "."),
            coords.artifact_id
        );
        Some((maven_name, coords.version))
    } else {
        None
    };

    // #733 serve-local: an internal-namespace artifact is operator-owned — skip curation and
    // serve any local copy (fresh below, or stale before the proxy loop); the upstream branch is
    // blocked separately (never proxy an internal name).
    let internal = curation_coords
        .as_ref()
        .map(|(n, _)| {
            crate::curation::is_internal_namespace(
                &state.curation().curation_engine,
                crate::curation::RegistryType::Maven,
                n,
            )
        })
        .unwrap_or(false);

    // Release date for the digest-quarantine first-seen clock (#748/#750), hoisted
    // to function scope so the serve gate below can use it. For a Maven Central upstream
    // it is the file's `Last-Modified` on Central, else the Central search API, within
    // `maven.date_lookup_timeout` (gated to a Central proxy to avoid leaking coordinates);
    // other proxies have no date (None → NORA's own clock). Hosted-only uses mtime.
    // The search used to run on `proxy_timeout` and fail silently: a throttled search
    // added 30 s to every cold miss and held years-old artifacts by first_seen.
    //
    // #754: the Central query only happens on a cache MISS. On a cache hit the digest
    // is already recorded (quarantine `record` is idempotent → the date is ignored),
    // so a cheap local stat skips the upstream round-trip — a cache hit never pays it.
    let cached_meta = state.storage.stat(&key).await;
    let already_cached = cached_meta.is_some();
    let publish_date: Option<i64> =
        if let Some((ref maven_name, ref maven_version)) = curation_coords {
            if state.config.maven.proxies.is_empty() {
                crate::curation::extract_mtime_as_publish_date(&state.storage, &key).await
            } else if !already_cached && !internal && state.config.server.trust_upstream_dates {
                // #68/#733: never send an internal-namespace GAV to Central — that would
                // leak operator-internal coordinates.
                central_publish_date(&state, &path, maven_name, maven_version).await
            } else {
                None
            }
        } else {
            None
        };

    // Curation check — only for versioned artifact files, not metadata
    if let Some((ref maven_name, ref maven_version)) = curation_coords {
        if !internal {
            if let Some(response) = crate::curation::check_download(
                &state.curation().curation_engine,
                state.bypass_token().as_deref(),
                &headers,
                crate::curation::RegistryType::Maven,
                maven_name,
                crate::curation::RequestVersion::Known(maven_version.to_string()),
                publish_date,
            ) {
                return response;
            }
        }
    }

    // Resolved here, not at the serve site, so the range branch below can see it.
    let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
        state.config.curation.maven.quarantine.as_ref().or(state
            .config
            .curation
            .quarantine
            .as_ref()),
        state
            .config
            .curation
            .maven
            .quarantine_ttl
            .as_deref()
            .or(state.config.curation.quarantine_ttl.as_deref()),
    );

    // Resumable download (#657): serve the requested bytes from the backend and skip
    // the full read below. Release artifacts only — maven-metadata.xml and SNAPSHOT
    // paths are mutable and need the freshness check. A partial read cannot be hashed,
    // so neither the quarantine gate nor the curation integrity check can run on it:
    // the range serve stands down while quarantine holds artifacts or an integrity rule
    // applies to the artifact.
    let integrity_applies = curation_coords
        .as_ref()
        .is_some_and(|(maven_name, maven_version)| {
            crate::curation::integrity_applies(
                &state.curation().curation_engine,
                crate::curation::RegistryType::Maven,
                maven_name,
                Some(maven_version),
            )
        });
    if !is_mutable_maven_path(&path)
        && matches!(q_mode, crate::digest_quarantine::QuarantineMode::Off)
        && !integrity_applies
    {
        if let Some(meta) = cached_meta.as_ref() {
            if let Some(response) = crate::registry::range::range_response(
                &state.storage,
                &[&key],
                &headers,
                meta.size,
                maven_content_type(&path),
                &[(
                    header::CACHE_CONTROL,
                    "public, max-age=31536000, immutable".to_string(),
                )],
            )
            .await
            {
                if response.status() == StatusCode::PARTIAL_CONTENT {
                    state.metrics.record_download("maven");
                    state.metrics.record_cache_hit("maven");
                }
                return response;
            }
        }
    }

    // An immutable artifact (release .jar/.pom/...) is always fresh when cached: read it
    // integrity-gated with bounded memory — whole and verified up to
    // `server.stream_threshold_mb`, streamed above it with its pin checked as it streams.
    // Read whole, a 125 MB jar pulled by ~75 CI shards at once OOM-killed the pod at its
    // 4Gi limit three times (ContainerOOMKillLoop 03.11.2026).
    if !is_mutable_maven_path(&path) {
        let artifact =
            match crate::registry::read_cached_artifact(&state, "maven", &key, internal).await {
                Ok(artifact) => artifact,
                Err(resp) => return resp,
            };
        if let Some(artifact) = artifact {
            let engine = &state.curation().curation_engine;
            let quarantine_on = !matches!(q_mode, crate::digest_quarantine::QuarantineMode::Off);
            // Hashed only when a gate reads it: a streamed copy carries its verified pin,
            // a buffered one is hashed here.
            let digest = curation_coords
                .as_ref()
                .filter(|_| engine.is_active() || quarantine_on)
                .map(|_| artifact.digest());
            // Curation integrity verification (issue #189)
            if let (Some((maven_name, maven_version)), Some(digest)) = (&curation_coords, &digest) {
                if let Some(response) = crate::curation::verify_integrity_by_hash(
                    engine,
                    crate::curation::RegistryType::Maven,
                    maven_name,
                    Some(maven_version),
                    digest,
                ) {
                    return response;
                }
            }
            state.metrics.record_download("maven");
            state.metrics.record_cache_hit("maven");
            state.activity.push(ActivityEntry::new(
                ActionType::CacheHit,
                artifact_name.clone(),
                crate::registry_type::RegistryType::Maven,
                "CACHE",
            ));
            state
                .audit
                .log(AuditEntry::new("cache_hit", "proxy", "", "maven", ""));
            // Quarantine only real version artifacts (.jar/.pom/.sha1, immutable per version).
            if let Some(digest) = digest.as_deref().filter(|_| quarantine_on) {
                if let Some((maven_name, maven_version)) = curation_coords
                    .as_ref()
                    .filter(|_| !internal && state.config.server.trust_upstream_dates)
                {
                    redate_held(&state.digest_store, digest, q_secs, || {
                        central_publish_date(&state, &path, maven_name, maven_version)
                    })
                    .await;
                }
                // A digest with no record counts from when its copy was cached (R4-C05).
                if let Some(resp) = crate::digest_quarantine::cache_gate_digest(
                    &state.digest_store,
                    &state.storage,
                    &key,
                    "maven",
                    digest,
                    &q_mode,
                    q_secs,
                    publish_date,
                )
                .await
                {
                    return resp;
                }
            }
            let len = artifact.len();
            let body = artifact.into_body(&state, "maven", &key, internal);
            let mut response = with_content_type(&path, body).into_response();
            let h = response.headers_mut();
            h.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
            h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
            return response;
        }
    }

    // A mutable path (maven-metadata.xml, SNAPSHOT files; small) is read whole: kept for the
    // freshness check and the stale-on-error fallback. An immutable one was served above.
    let (cached, read_failure) = if is_mutable_maven_path(&path) {
        crate::registry::cached_read(state.storage.get(&key).await)
    } else {
        (None, None)
    };

    // maven-metadata.xml and SNAPSHOT artifacts are MUTABLE (rewritten as versions deploy); a
    // proxied mutable path must be revalidated against upstream unless within a positive
    // metadata_ttl window — otherwise newly deployed versions / SNAPSHOT updates never appear.
    // Release artifacts are immutable and served from cache; a hosted artifact is authoritative.
    let cache_fresh = match &cached {
        None => false,
        Some(_) if !is_mutable_maven_path(&path) => true,
        Some(_) => {
            let modified = cached_meta.as_ref().map(|m| m.modified);
            crate::cache_ttl::mutable_ref_fresh(
                !state.config.maven.proxies.is_empty(),
                state.config.maven.metadata_ttl,
                modified,
            )
        }
    };

    if let Some(ref data) = cached {
        if cache_fresh {
            // Curation integrity verification (issue #189)
            if let Some((ref maven_name, ref maven_version)) = curation_coords {
                if let Some(response) = crate::curation::verify_integrity(
                    &state.curation().curation_engine,
                    crate::curation::RegistryType::Maven,
                    maven_name,
                    Some(maven_version),
                    data,
                ) {
                    return response;
                }
            }

            state.metrics.record_download("maven");
            state.metrics.record_cache_hit("maven");
            state.activity.push(ActivityEntry::new(
                ActionType::CacheHit,
                artifact_name.clone(),
                crate::registry_type::RegistryType::Maven,
                "CACHE",
            ));
            state
                .audit
                .log(AuditEntry::new("cache_hit", "proxy", "", "maven", ""));
            // Quarantine only real version artifacts (.jar/.pom/.sha1, immutable
            // per version). maven-metadata.xml is mutable (curation_coords=None) —
            // never quarantine it or its digest would change forever.
            if curation_coords.is_some() {
                // A digest with no record counts from when its copy was cached (R4-C05).
                if let Some(resp) = crate::digest_quarantine::cache_gate_dated(
                    &state.digest_store,
                    &state.storage,
                    &key,
                    "maven",
                    data,
                    &q_mode,
                    q_secs,
                    publish_date,
                )
                .await
                {
                    return resp;
                }
            }
            let mut response = with_content_type(&path, data.clone()).into_response();
            if !is_mutable_maven_path(&path) {
                response
                    .headers_mut()
                    .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
            }
            return response;
        }
    }

    // #68 namespace isolation: the maven-metadata.xml (ArtifactMeta) path is not
    // covered by the VersionFile check_download above. An internal group:artifact's
    // metadata must never be fetched upstream (dependency confusion): serve any local
    // copy (deployed/cached metadata; the fresh path already returned above) and block
    // only when nothing is hosted locally — never proxy.
    if let MavenPathKind::ArtifactMeta {
        group_path,
        artifact_id,
        ..
    } = classify_path(&path)
    {
        if let Some(maven_name) =
            metadata_names(&group_path, &artifact_id)
                .into_iter()
                .find(|name| {
                    crate::curation::is_internal_namespace(
                        &state.curation().curation_engine,
                        crate::curation::RegistryType::Maven,
                        name,
                    )
                })
        {
            if let Some(ref data) = cached {
                state.metrics.record_download("maven");
                state.metrics.record_cache_hit("maven");
                return with_content_type(&path, data.clone()).into_response();
            }
            if let Some(e) = &read_failure {
                return crate::registry::local_copy_unreadable("maven", &key, e);
            }
            return crate::curation::check_namespace_isolation(
                &state.curation().curation_engine,
                crate::curation::RegistryType::Maven,
                &maven_name,
            )
            .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
        }
    }

    // #733: an internal-namespace VersionFile artifact with no fresh copy — serve any stale
    // local copy, else block; never proxy upstream. (The ArtifactMeta path is handled above.)
    if internal {
        if let Some(ref data) = cached {
            state.metrics.record_download("maven");
            state.metrics.record_cache_hit("maven");
            return with_content_type(&path, data.clone()).into_response();
        }
        if let Some(e) = &read_failure {
            return crate::registry::local_copy_unreadable("maven", &key, e);
        }
        if let Some((ref maven_name, _)) = curation_coords {
            return crate::curation::check_namespace_isolation(
                &state.curation().curation_engine,
                crate::curation::RegistryType::Maven,
                maven_name,
            )
            .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
        }
        return StatusCode::NOT_FOUND.into_response();
    }

    let metadata_request = match classify_path(&path) {
        MavenPathKind::ArtifactMeta {
            group_path,
            artifact_id,
            ..
        } => Some((
            group_path,
            artifact_id,
            metadata_document_key(&path).unwrap_or(&path).to_string(),
            checksum_suffix(&path),
        )),
        _ => None,
    };

    let mut miss = UpstreamMiss::default();
    for proxy in &state.config.maven.proxies {
        let upstream_path = metadata_request
            .as_ref()
            .map(|(_, _, document_path, _)| document_path.as_str())
            .unwrap_or(&path);
        let url = format!("{}/{}", proxy.url().trim_end_matches('/'), upstream_path);

        let auth = proxy.auth().map(UpstreamAuth::Basic);
        let scope = BreakerScope::upstream(RegistryType::Maven, proxy.url());
        // maven-metadata.xml is small and merged in memory; an artifact above
        // `server.stream_threshold_mb` is spooled to disk, as NuGet/npm/PyPI files are:
        // buffered whole, a jar over `proxy_max_buffered_mb` (awssdk bundle, 641 MB) was refused.
        let fetched = if metadata_request.is_some() {
            proxy_fetch(
                &state.http_client,
                &url,
                Duration::from_secs(state.config.maven.proxy_timeout),
                auth,
                &state.circuit_breaker,
                scope,
            )
            .await
            .map(|data| (ProxyBody::Mem(Bytes::from(data)), true))
        } else {
            proxy_fetch_artifact(
                &state,
                &key,
                "maven",
                &url,
                state.config.maven.proxy_timeout,
                auth,
                scope,
            )
            .await
        };
        match fetched {
            Ok((data, fetched)) => {
                let engine = &state.curation().curation_engine;
                let quarantine_on =
                    !matches!(q_mode, crate::digest_quarantine::QuarantineMode::Off);
                // Hashed once, only when a gate reads it (a spooled body already carries it).
                let digest = curation_coords
                    .as_ref()
                    .filter(|_| engine.is_active() || quarantine_on)
                    .map(|_| data.digest());
                // The allowlist's pinned integrity holds on the first download too, before anything is cached:
                // the cache-hit branch checks the same rule.
                if let (Some((maven_name, maven_version)), Some(digest)) =
                    (&curation_coords, &digest)
                {
                    if let Some(response) = crate::curation::verify_integrity_by_hash(
                        engine,
                        crate::curation::RegistryType::Maven,
                        maven_name,
                        Some(maven_version),
                        digest,
                    ) {
                        return response;
                    }
                }
                state.metrics.record_download("maven");
                state.metrics.record_cache_miss("maven");
                state.activity.push(ActivityEntry::new(
                    ActionType::ProxyFetch,
                    artifact_name,
                    crate::registry_type::RegistryType::Maven,
                    "PROXY",
                ));
                state
                    .audit
                    .log(AuditEntry::new("proxy_fetch", "proxy", "", "maven", ""));

                if let (
                    Some((group_path, artifact_id, document_path, requested_checksum)),
                    ProxyBody::Mem(raw),
                ) = (&metadata_request, &data)
                {
                    let metadata = merge_and_cache_proxy_metadata(
                        &state,
                        group_path,
                        artifact_id,
                        document_path,
                        raw,
                    )
                    .await;
                    let response_data = match requested_checksum {
                        Some(suffix) => match checksum_hex(suffix, &metadata) {
                            Some(checksum) => Bytes::from(checksum),
                            None => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                        },
                        None => metadata,
                    };
                    return with_content_type(&path, response_data).into_response();
                }

                // Only the caller that fetched caches; coalesced followers share its body.
                if fetched {
                    let (state, key, body) = (state.clone(), key.clone(), data.clone());
                    let immutable = !is_mutable_maven_path(&path);
                    tokio::spawn(async move {
                        match body.cache(&state, &key, immutable).await {
                            Ok(true) => state.repo_index.invalidate("maven"),
                            Ok(false) => {}
                            Err(e) => crate::record_cache_write_error("maven", &key, &e),
                        }
                    });
                }

                // Quarantine only real version artifacts; never maven-metadata.xml.
                if let Some(digest) = digest.as_deref().filter(|_| quarantine_on) {
                    if let Some(resp) = crate::digest_quarantine::proxy_gate_digest(
                        &state.digest_store,
                        "maven",
                        digest,
                        &q_mode,
                        q_secs,
                        &url,
                        publish_date,
                    ) {
                        return resp;
                    }
                }
                let len = data.len();
                return match data.into_body(&key).await {
                    Ok(body) => {
                        let mut response = with_content_type(&path, body).into_response();
                        response
                            .headers_mut()
                            .insert(header::CONTENT_LENGTH, HeaderValue::from(len));
                        response
                    }
                    Err(e) => {
                        tracing::warn!(key = %key, error = %e, "maven: spooled artifact unreadable");
                        StatusCode::INTERNAL_SERVER_ERROR.into_response()
                    }
                };
            }
            // An open breaker skips this upstream for the next, as a failure does (#1198).
            Err(e) => miss.record_from(proxy.url(), &e),
        }
    }

    // All proxies failed — serve the stale cached artifact if we have one (graceful).
    if let Some(ref data) = cached {
        tracing::warn!(registry = "maven", path = %path, "Maven upstream failed, serving stale cached artifact");
        // Quarantine still applies to a version artifact served from a stale cache:
        // a held SNAPSHOT must not be released just because the upstream went down
        // (mutable SNAPSHOT artifacts reach this path; immutable releases serve from
        // the fresh-cache branch above, which is already gated).
        // The allowlist's pinned integrity holds on a stale copy too: the verified read above did
        // not serve it.
        if let Some((ref maven_name, ref maven_version)) = curation_coords {
            if let Some(response) = crate::curation::verify_integrity(
                &state.curation().curation_engine,
                crate::curation::RegistryType::Maven,
                maven_name,
                Some(maven_version),
                data,
            ) {
                return response;
            }
        }
        if curation_coords.is_some() {
            let (q_mode, q_secs) = crate::digest_quarantine::resolve_global(
                state.config.curation.maven.quarantine.as_ref().or(state
                    .config
                    .curation
                    .quarantine
                    .as_ref()),
                state
                    .config
                    .curation
                    .maven
                    .quarantine_ttl
                    .as_deref()
                    .or(state.config.curation.quarantine_ttl.as_deref()),
            );
            // A digest with no record counts from when its copy was cached (R4-C05).
            if let Some(resp) = crate::digest_quarantine::cache_gate_dated(
                &state.digest_store,
                &state.storage,
                &key,
                "maven",
                data,
                &q_mode,
                q_secs,
                publish_date,
            )
            .await
            {
                return resp;
            }
        }
        let mut response = with_content_type(&path, data.clone()).into_response();
        response.headers_mut().insert(
            axum::http::header::HeaderName::from_static("x-nora-stale"),
            axum::http::header::HeaderValue::from_static("true"),
        );
        return response;
    }

    miss.response("maven", &path)
}

// ============================================================================
// Upload
// ============================================================================

async fn upload(
    State(state): State<AppState>,
    Path(path): Path<String>,
    Extension(authority): Extension<NamespaceAuthority>,
    user: Option<Extension<crate::auth::AuthenticatedUser>>,
    super::PublishBody(body): super::PublishBody,
) -> Response {
    if !path.is_ascii() || path.contains("..") || path.contains('\0') || path.starts_with('/') {
        return (StatusCode::BAD_REQUEST, "Invalid path").into_response();
    }
    // An empty segment (`com//x`, `x.jar/`) would name another artifact's file: refuse it
    // with the other invalid paths, before the scope check and the write.
    if crate::validation::validate_storage_key(&storage_key(&path)).is_err() {
        return (StatusCode::BAD_REQUEST, "Invalid path").into_response();
    }

    // Enforce OIDC namespace_scope on the artifact coordinate (group/artifactId).
    // An unrecognized (Opaque) path yields an empty coordinate → fail-closed (#583).
    let maven_namespace = match classify_path(&path) {
        MavenPathKind::VersionFile(c) => format!("{}/{}", c.group_path, c.artifact_id),
        MavenPathKind::ArtifactMeta {
            group_path,
            artifact_id,
            ..
        } => format!("{}/{}", group_path, artifact_id),
        MavenPathKind::Opaque => String::new(),
    };
    if enforce_namespace_scope(&authority, &maven_namespace).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }

    let key = storage_key(&path);

    let artifact_name = path
        .split('/')
        .rev()
        .take(3)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("/");

    match classify_path(&path) {
        MavenPathKind::VersionFile(coords) if is_checksum_file(&coords.filename) => {
            // Client uploading a checksum — verify against our computed value
            if state.config.maven.checksum_verify {
                // The lock of the artifact's upload: the comparison and the rollback below
                // see one upload, never half of a concurrent one.
                let lock = state.publish_lock(&format!(
                    "maven/{}/{}/maven-metadata.xml",
                    coords.group_path, coords.artifact_id
                ));
                let _guard = lock.lock().await;
                if let Ok(computed) = state.storage.get(&key).await {
                    // A checksum file is the digest, in either case, optionally followed by
                    // the file name (`<hex>  foo.jar`).
                    let digest = |raw: &[u8]| {
                        String::from_utf8_lossy(raw)
                            .split_whitespace()
                            .next()
                            .unwrap_or_default()
                            .to_ascii_lowercase()
                    };
                    let (computed_str, client_str) = (digest(&computed), digest(&body));
                    if computed_str != client_str {
                        tracing::warn!(
                            path = %path,
                            expected = %computed_str,
                            received = %client_str,
                            "SECURITY: Maven checksum mismatch on upload"
                        );
                        if roll_back_unvouched_artifact(&state, &key).await {
                            update_artifact_metadata(
                                &state,
                                &coords.group_path,
                                &coords.artifact_id,
                            )
                            .await;
                            state.repo_index.invalidate("maven");
                            return (
                                StatusCode::BAD_REQUEST,
                                "Checksum mismatch: the artifact was removed, deploy it again",
                            )
                                .into_response();
                        }
                        return (StatusCode::BAD_REQUEST, "Checksum mismatch").into_response();
                    }
                    // The same digest: the stored checksum already says it.
                    return StatusCode::CREATED.into_response();
                }
            }
            match state.storage.put(&key, &body).await {
                Ok(()) => StatusCode::CREATED.into_response(),
                Err(e) => {
                    tracing::error!(error = %e, key = %key, "Failed to store Maven checksum");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            }
        }

        MavenPathKind::VersionFile(coords) => {
            // Primary artifact upload (jar, pom, war, etc.)
            let snap = is_snapshot(&coords.version);

            // Lock on metadata key to serialize all uploads for the same artifact.
            // This prevents TOCTOU races on both immutability checks and
            // maven-metadata.xml generation (read-list-generate-write cycle).
            let metadata_lock_key = format!(
                "maven/{}/{}/maven-metadata.xml",
                coords.group_path, coords.artifact_id
            );
            let lock = state.publish_lock(&metadata_lock_key);
            let _guard = lock.lock().await;

            if !snap
                && state.config.maven.immutable_releases
                && state.storage.stat(&key).await.is_some()
            {
                return (
                    StatusCode::CONFLICT,
                    format!(
                        "Version {}:{} is immutable (already deployed)",
                        coords.artifact_id, coords.version
                    ),
                )
                    .into_response();
            }

            if let Err(e) = state.storage.put(&key, &body).await {
                tracing::error!(error = %e, key = %key, "Failed to store Maven artifact");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }

            compute_and_store_checksums(&state.storage, &key, &body).await;

            update_artifact_metadata(&state, &coords.group_path, &coords.artifact_id).await;

            state.metrics.record_upload("maven");
            state.audit.log(AuditEntry::new(
                "push",
                crate::auth::audit_actor(&user),
                &artifact_name,
                "maven",
                "",
            ));
            state.activity.push(ActivityEntry::new(
                ActionType::Push,
                artifact_name,
                crate::registry_type::RegistryType::Maven,
                "LOCAL",
            ));
            state.repo_index.invalidate("maven");

            StatusCode::CREATED.into_response()
        }

        MavenPathKind::ArtifactMeta { filename, .. } => {
            let server_managed = if filename == "maven-metadata.xml" {
                classify_metadata_level(&body) == Some(MavenMetadataLevel::Artifact)
            } else if let Some(metadata_key) = metadata_document_key(&key) {
                match state.storage.get(metadata_key).await {
                    Ok(metadata) => {
                        classify_metadata_level(&metadata) == Some(MavenMetadataLevel::Artifact)
                    }
                    Err(StorageError::NotFound) => false,
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            key = %metadata_key,
                            "Failed to read Maven metadata for checksum classification"
                        );
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                }
            } else {
                false
            };

            if server_managed {
                state.metrics.record_upload("maven");
                return StatusCode::CREATED.into_response();
            }

            match state.storage.put(&key, &body).await {
                Ok(()) => {
                    state.metrics.record_upload("maven");
                    StatusCode::CREATED.into_response()
                }
                Err(e) => {
                    tracing::error!(error = %e, key = %key, "Failed to store Maven metadata");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            }
        }

        MavenPathKind::Opaque => match state.storage.put(&key, &body).await {
            Ok(()) => {
                state.metrics.record_upload("maven");
                state.audit.log(AuditEntry::new(
                    "push",
                    crate::auth::audit_actor(&user),
                    &artifact_name,
                    "maven",
                    "",
                ));
                state.activity.push(ActivityEntry::new(
                    ActionType::Push,
                    artifact_name,
                    crate::registry_type::RegistryType::Maven,
                    "LOCAL",
                ));
                state.repo_index.invalidate("maven");
                StatusCode::CREATED.into_response()
            }
            Err(e) => {
                tracing::error!(error = %e, key = %key, "Failed to store Maven artifact");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
    }
}

// ============================================================================
// Checksum helpers
// ============================================================================

fn checksum_hex(suffix: &str, data: &[u8]) -> Option<String> {
    match suffix {
        "md5" => Some(hex::encode(md5::Md5::digest(data))),
        "sha1" => Some(hex::encode(sha1::Sha1::digest(data))),
        "sha256" => Some(hex::encode(sha2::Sha256::digest(data))),
        "sha512" => Some(hex::encode(sha2::Sha512::digest(data))),
        _ => None,
    }
}

/// How long after an artifact is stored a mismatching client checksum still removes it. Maven
/// uploads a file's checksums right after the file; a later mismatch is not that deploy's, and
/// must not let a publisher remove a settled release.
const CHECKSUM_ROLLBACK_WINDOW_SECS: i64 = 600;

/// The client's checksum at `checksum_key` does not match the artifact just stored: the
/// publisher does not vouch for these bytes. Remove the artifact and its computed checksums, so
/// the deploy can be retried instead of meeting `immutable_releases` on a file nobody vouches
/// for. Only within [`CHECKSUM_ROLLBACK_WINDOW_SECS`] of the upload. Returns whether it was
/// removed.
async fn roll_back_unvouched_artifact(state: &AppState, checksum_key: &str) -> bool {
    let Some(artifact_key) = metadata_document_key(checksum_key) else {
        return false;
    };
    let just_stored = state.storage.stat(artifact_key).await.is_some_and(|meta| {
        crate::cache_ttl::is_within_ttl(meta.modified, CHECKSUM_ROLLBACK_WINDOW_SECS)
    });
    if !just_stored {
        return false;
    }
    if let Err(e) = state.storage.delete(artifact_key).await {
        tracing::error!(key = %artifact_key, error = %e, "maven: failed to remove an artifact whose checksum did not match");
        return false;
    }
    for suffix in ["md5", "sha1", "sha256", "sha512"] {
        let _ = state
            .storage
            .delete(&format!("{artifact_key}.{suffix}"))
            .await;
    }
    tracing::warn!(key = %artifact_key, "maven: removed an artifact whose uploaded checksum did not match");
    true
}

async fn compute_and_store_checksums(storage: &crate::storage::Storage, key: &str, data: &[u8]) {
    for suffix in ["md5", "sha1", "sha256", "sha512"] {
        let ck = format!("{}.{}", key, suffix);
        let Some(hash) = checksum_hex(suffix, data) else {
            continue;
        };
        if let Err(e) = storage.put(&ck, hash.as_bytes()).await {
            tracing::warn!(key = %ck, error = %e, "maven: failed to store checksum");
        }
    }
}

// ============================================================================
// Metadata generation
// ============================================================================

#[derive(Default)]
struct ArtifactMetadata {
    latest: Option<String>,
    release: Option<String>,
    last_updated: Option<String>,
    versions: Vec<String>,
}

fn parse_artifact_metadata(data: &[u8]) -> Option<ArtifactMetadata> {
    if classify_metadata_level(data) != Some(MavenMetadataLevel::Artifact) {
        return None;
    }

    let mut reader = Reader::from_reader(data);
    reader.config_mut().trim_text(true);
    let mut metadata = ArtifactMetadata::default();
    let mut in_versions = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) if element.local_name().as_ref() == b"versions" => {
                in_versions = true;
            }
            Ok(Event::Start(element))
                if element.local_name().as_ref() == b"version" && in_versions =>
            {
                let text = reader.read_text(element.name()).ok()?.decode().ok()?;
                let version = quick_xml::escape::unescape(&text).ok()?.into_owned();
                if !version.is_empty() {
                    metadata.versions.push(version);
                }
            }
            Ok(Event::Start(element)) if element.local_name().as_ref() == b"latest" => {
                let text = reader.read_text(element.name()).ok()?.decode().ok()?;
                let latest = quick_xml::escape::unescape(&text).ok()?.into_owned();
                if !latest.is_empty() {
                    metadata.latest = Some(latest);
                }
            }
            Ok(Event::Start(element)) if element.local_name().as_ref() == b"release" => {
                let text = reader.read_text(element.name()).ok()?.decode().ok()?;
                let release = quick_xml::escape::unescape(&text).ok()?.into_owned();
                if !release.is_empty() {
                    metadata.release = Some(release);
                }
            }
            Ok(Event::Start(element)) if element.local_name().as_ref() == b"lastUpdated" => {
                let text = reader.read_text(element.name()).ok()?.decode().ok()?;
                let last_updated = quick_xml::escape::unescape(&text).ok()?.into_owned();
                if !last_updated.is_empty() {
                    metadata.last_updated = Some(last_updated);
                }
            }
            Ok(Event::End(element)) if element.local_name().as_ref() == b"versions" => {
                in_versions = false;
            }
            Ok(Event::Eof) => break,
            Err(_) => return None,
            _ => {}
        }
    }

    Some(metadata)
}

async fn stored_artifact_versions(
    state: &AppState,
    group_path: &str,
    artifact_id: &str,
) -> Result<BTreeSet<String>, StorageError> {
    let prefix = format!("maven/{}/{}/", group_path, artifact_id);
    let keys = state.storage.list(&prefix).await?;
    let mut versions = BTreeSet::new();

    for key in &keys {
        let relative = match key.strip_prefix(&prefix) {
            Some(relative) => relative,
            None => continue,
        };
        if let Some(version) = relative.split('/').next() {
            if !version.is_empty() && !version.starts_with("maven-metadata") {
                versions.insert(version.to_string());
            }
        }
    }

    Ok(versions)
}

fn merge_artifact_metadata(
    group_id: &str,
    artifact_id: &str,
    base: Option<&[u8]>,
    stored_versions: &BTreeSet<String>,
    last_updated: Option<&str>,
) -> Option<String> {
    let mut metadata = match base {
        Some(data) => parse_artifact_metadata(data)?,
        None => ArtifactMetadata::default(),
    };
    let mut known = BTreeSet::new();
    metadata
        .versions
        .retain(|version| known.insert(version.clone()));
    let mut additional: Vec<String> = stored_versions
        .iter()
        .filter(|version| !known.contains(*version))
        .cloned()
        .collect();
    sort_maven_versions(&mut additional);

    for version in additional {
        if metadata
            .latest
            .as_ref()
            .is_none_or(|latest| compare_maven_versions(latest, &version).is_lt())
        {
            metadata.latest = Some(version.clone());
        }
        if !is_snapshot(&version)
            && metadata
                .release
                .as_ref()
                .is_none_or(|release| compare_maven_versions(release, &version).is_lt())
        {
            metadata.release = Some(version.clone());
        }
        metadata.versions.push(version);
    }

    if metadata.versions.is_empty() {
        return None;
    }
    if metadata.latest.is_none() || metadata.release.is_none() {
        let mut sorted = metadata.versions.clone();
        sort_maven_versions(&mut sorted);
        metadata
            .latest
            .get_or_insert_with(|| sorted.last().cloned().unwrap_or_default());
        if metadata.release.is_none() {
            metadata.release = sorted
                .into_iter()
                .rev()
                .find(|version| !is_snapshot(version));
        }
    }

    Some(generate_metadata_xml_with_versioning(
        group_id,
        artifact_id,
        &metadata.versions,
        metadata.latest.as_deref().unwrap_or(""),
        metadata.release.as_deref().unwrap_or(""),
        last_updated.or(metadata.last_updated.as_deref()),
    ))
}

async fn merge_and_cache_proxy_metadata(
    state: &AppState,
    group_path: &str,
    artifact_id: &str,
    document_path: &str,
    upstream: &[u8],
) -> Bytes {
    let key = storage_key(document_path);

    // Serialize the read -> merge -> write -> checksums cycle with the upload-side
    // regeneration (`update_artifact_metadata`) and any concurrent proxy merge: all of them
    // write the same `maven-metadata.xml` key and its four checksum sidecars. Without a shared
    // lock those five independent `put`s interleave, leaving a stored `.sha1`/`.md5`/… that
    // corresponds to different bytes than the stored `.xml` (checksum-mismatch window). The
    // upload path locks the artifact's `maven-metadata.xml` key; locking the document key here
    // — identical for artifact-level metadata — keeps `publish_lock serializes all writes to the
    // same artifact path` intact on the proxy path too (#886). Held across the writes below.
    let lock = state.publish_lock(&key);
    let _guard = lock.lock().await;

    // The stored copy only adds its `lastUpdated` and spares an identical write: unreadable,
    // the merge of the upstream and the stored versions is still whole.
    let (cached, unreadable) = crate::registry::cached_read(state.storage.get(&key).await);
    if let Some(e) = unreadable {
        tracing::warn!(key = %key, error = %e, "maven: stored metadata unreadable, merging without it");
    }
    let last_updated = [Some(upstream), cached.as_deref()]
        .into_iter()
        .flatten()
        .filter_map(parse_artifact_metadata)
        .filter_map(|metadata| metadata.last_updated)
        .max();
    let data = if let Ok(stored_versions) =
        stored_artifact_versions(state, group_path, artifact_id).await
    {
        merge_artifact_metadata(
            &group_path.replace('/', "."),
            artifact_id,
            Some(upstream),
            &stored_versions,
            last_updated.as_deref(),
        )
        .map_or_else(|| Bytes::copy_from_slice(upstream), Bytes::from)
    } else {
        Bytes::copy_from_slice(upstream)
    };

    // Skip the write when the merged document is byte-identical to the cached
    // version — avoids 5 no-op storage writes (1 doc + 4 checksums) on every
    // revalidation under low/zero metadata_ttl (#888).
    if cached.as_deref() != Some(data.as_ref()) {
        if let Err(error) = state.storage.put(&key, &data).await {
            tracing::warn!(key = %key, error = %error, "maven: failed to cache metadata");
        } else {
            compute_and_store_checksums(&state.storage, &key, &data).await;
        }
    }

    data
}

async fn update_artifact_metadata(state: &AppState, group_path: &str, artifact_id: &str) {
    let versions = match stored_artifact_versions(state, group_path, artifact_id).await {
        Ok(versions) => versions,
        Err(e) => {
            tracing::warn!(error = ?e, group_path, artifact_id, "maven: failed to list storage for metadata generation");
            return;
        }
    };

    if versions.is_empty() {
        return;
    }

    let prefix = format!("maven/{}/{}/", group_path, artifact_id);
    let metadata_key = format!("{}maven-metadata.xml", prefix);
    // Unreadable: the document is regenerated from the stored versions, which lists the
    // version just uploaded; versions only an upstream has return at its next revalidation.
    let (current, unreadable) =
        crate::registry::cached_read(state.storage.get(&metadata_key).await);
    if let Some(e) = unreadable {
        tracing::warn!(key = %metadata_key, error = %e, "maven: stored metadata unreadable, regenerating it from the stored versions");
    }
    let group_id_dotted = group_path.replace('/', ".");
    let last_updated = chrono::Utc::now().format("%Y%m%d%H%M%S").to_string();
    let xml = merge_artifact_metadata(
        &group_id_dotted,
        artifact_id,
        current.as_deref(),
        &versions,
        Some(&last_updated),
    )
    .unwrap_or_else(|| {
        let mut sorted: Vec<String> = versions.into_iter().collect();
        sort_maven_versions(&mut sorted);
        generate_metadata_xml(&group_id_dotted, artifact_id, &sorted)
    });

    if state
        .storage
        .put(&metadata_key, xml.as_bytes())
        .await
        .is_err()
    {
        tracing::error!(key = %metadata_key, "Failed to write maven-metadata.xml");
        return;
    }

    compute_and_store_checksums(&state.storage, &metadata_key, xml.as_bytes()).await;
}

fn sort_maven_versions(versions: &mut [String]) {
    versions.sort_by(|a, b| compare_maven_versions(a, b));
}

fn generate_metadata_xml(group_id: &str, artifact_id: &str, versions: &[String]) -> String {
    let latest = versions.last().map(|s| s.as_str()).unwrap_or("");
    let release = versions
        .iter()
        .rev()
        .find(|v| !v.ends_with("-SNAPSHOT"))
        .map(|s| s.as_str())
        .unwrap_or("");

    generate_metadata_xml_with_versioning(group_id, artifact_id, versions, latest, release, None)
}

fn generate_metadata_xml_with_versioning(
    group_id: &str,
    artifact_id: &str,
    versions: &[String],
    latest: &str,
    release: &str,
    last_updated: Option<&str>,
) -> String {
    let generated_last_updated;
    let last_updated = match last_updated {
        Some(last_updated) => last_updated,
        None => {
            generated_last_updated = chrono::Utc::now().format("%Y%m%d%H%M%S").to_string();
            &generated_last_updated
        }
    };

    let version_elements: String = versions
        .iter()
        .map(|v| format!("      <version>{}</version>", xml_escape(v)))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>{}</groupId>
  <artifactId>{}</artifactId>
  <versioning>
    <latest>{}</latest>
    <release>{}</release>
    <versions>
{}
    </versions>
    <lastUpdated>{}</lastUpdated>
  </versioning>
</metadata>
"#,
        xml_escape(group_id),
        xml_escape(artifact_id),
        xml_escape(latest),
        xml_escape(release),
        version_elements,
        last_updated
    )
}

// ============================================================================
// Content type
// ============================================================================

fn maven_content_type(path: &str) -> &'static str {
    if ends_with_ci(path, ".pom") {
        "application/xml"
    } else if ends_with_ci(path, ".jar") {
        "application/java-archive"
    } else if ends_with_ci(path, ".xml") {
        "application/xml"
    } else if ends_with_ci(path, ".sha1")
        || ends_with_ci(path, ".md5")
        || ends_with_ci(path, ".sha256")
        || ends_with_ci(path, ".sha512")
    {
        "text/plain"
    } else {
        "application/octet-stream"
    }
}

fn with_content_type<B>(
    path: &str,
    data: B,
) -> (StatusCode, [(header::HeaderName, &'static str); 2], B) {
    let content_type = maven_content_type(path);

    // maven-metadata.xml is mutable; release artifacts are immutable
    let cache_control = if ends_with_ci(path, "maven-metadata.xml")
        || ends_with_ci(path, "maven-metadata.xml.sha1")
        || ends_with_ci(path, "maven-metadata.xml.md5")
    {
        "public, max-age=60, must-revalidate"
    } else {
        "public, max-age=31536000, immutable"
    };

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, cache_control),
        ],
        data,
    )
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests;

// ============================================================================
// Integration Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod index_cost_tests;

#[cfg(test)]
mod upstream_failure_cases;

#[cfg(test)]
mod upstream_failure_edge_cases;

/// A name or path with an empty segment (or, where the name is one segment, any `/`) never
/// reaches curation, storage or an upstream: it would name another artifact's files, and an
/// upstream that normalises paths would answer for that other artifact.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod empty_segment_requests;

/// Repository paths as maven-resolver builds them and Maven requests them (testdata/maven,
/// regenerated by the programs there).
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod per_maven_resolver;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod maven_version_metadata_identity;
