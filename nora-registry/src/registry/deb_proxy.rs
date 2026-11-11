// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Filtered apt pull-through (maestra): a `[deb.proxies]` repository served with its
//! own indexes while `[curation.deb] min_release_age` is set ("0d" included).
//!
//!   GET /deb/{repo}/dists/{suite}/InRelease|Release|Release.gpg     — NORA-signed
//!   GET /deb/{repo}/dists/{suite}/{comp}/binary-{arch}/Packages.gz   — filtered
//!   GET /deb/{repo}/dists/{suite}/{comp}/binary-{arch}/by-hash/SHA256/{hex}
//!   GET /deb/{repo}/pool/…/*.deb                                      — a package
//!   GET /deb/{repo}/pubkey.gpg                                        — NORA's key
//!
//! An apt `Packages` stanza carries no publish date, so a version is dated by the time
//! NORA first saw it in an upstream index (its pool `Filename`, recorded per index in
//! NORA's storage). An index NORA sees for the first time dates everything it lists as
//! "before NORA" (0): a hold switched on later never hides a whole distribution.
//!
//! The upstream `InRelease` must verify with a key of `deb.upstream_keyring_dir`; each
//! `Packages` file is fetched as that Release names it and refused on another SHA-256.
//! On serve, a package keeps its listed versions older than `min_release_age`; when
//! every listed version is younger, the newest older version the upstream has dropped
//! and NORA has cached stands in (Debian/Ubuntu suites list one version per package);
//! otherwise the package is left out of that suite. The `Release` names only the
//! rewritten `Packages.gz` files (by hash), is signed with NORA's `[signing]` key, and
//! keeps the upstream `Date`/`Valid-Until`. A package file of a held version is refused.

use crate::config::{RepoProxyEntry, UpstreamAuth};
use crate::registry::{circuit_open_response, proxy_error_response, ProxyError};
use crate::registry_type::RegistryType;
use crate::AppState;
use axum::{
    body::Bytes,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use pgp::composed::{CleartextSignedMessage, Deserializable, SignedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

const MAX_RELEASE_BYTES: u64 = 16 * 1024 * 1024;
/// A compressed upstream `Packages` (Ubuntu universe is ~20 MiB) and its text.
const MAX_PACKAGES_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PACKAGES_TEXT: u64 = 1024 * 1024 * 1024;
/// Dropped versions are kept at least this long, so a hold switched on later still has
/// the version a young replacement displaced.
const RETAIN_AGE_SECS: i64 = 7 * 86_400;
/// How long a loaded young-version map is reused for package downloads.
const YOUNG_TTL: Duration = Duration::from_secs(30);
/// How long a client waits for a suite refresh before it gets the previous build
/// (apt times a request out after 30 s).
const STALE_AFTER: Duration = Duration::from_secs(if cfg!(test) { 1 } else { 10 });

/// Whether proxied deb repositories are served filtered: `[curation.deb]
/// min_release_age` is set. "0d" filters nothing but keeps the ledger and signing on.
pub(crate) fn active(config: &crate::config::Config) -> bool {
    config.curation.deb.min_release_age.is_some()
}

// ── Keys ──────────────────────────────────────────────────────────────────────

type Keyring = Arc<Vec<SignedPublicKey>>;

/// Every public key in the files of `dir` (`*.gpg`, `*.pgp`, `*.asc`; binary keyrings
/// or armored).
fn load_keyring(dir: &str) -> Result<Vec<SignedPublicKey>, String> {
    if dir.is_empty() {
        return Err("deb.upstream_keyring_dir is not set".into());
    }
    let mut keys = Vec::new();
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("deb.upstream_keyring_dir {dir}: {e}"))?;
    let mut paths: Vec<_> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
    paths.sort();
    for path in paths {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !matches!(ext, "gpg" | "pgp" | "asc") {
            continue;
        }
        let data = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let (iter, _) = SignedPublicKey::from_reader_many(std::io::Cursor::new(data))
            .map_err(|e| format!("{}: {e}", path.display()))?;
        for key in iter {
            keys.push(key.map_err(|e| format!("{}: {e}", path.display()))?);
        }
    }
    if keys.is_empty() {
        return Err(format!("deb.upstream_keyring_dir {dir}: no keys"));
    }
    Ok(keys)
}

fn keyring(dir: &str) -> Result<Keyring, String> {
    static CACHE: OnceLock<Mutex<HashMap<String, Keyring>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some(k) = cache.lock().ok().and_then(|c| c.get(dir).cloned()) {
        return Ok(k);
    }
    let keys = Arc::new(load_keyring(dir)?);
    if let Ok(mut c) = cache.lock() {
        c.insert(dir.to_string(), keys.clone());
    }
    Ok(keys)
}

/// Config check: the keyring loads.
pub(crate) fn check_keyring(dir: &str) -> Result<(), String> {
    load_keyring(dir).map(|_| ())
}

/// The text of a clearsigned `InRelease` that a key of `keys` (primary or subkey)
/// signed, with LF line ends.
fn verify_inrelease(body: &[u8], keys: &[SignedPublicKey]) -> Result<String, String> {
    let text = std::str::from_utf8(body).map_err(|_| "InRelease is not UTF-8".to_string())?;
    let (msg, _) =
        CleartextSignedMessage::from_string(text).map_err(|e| format!("InRelease: {e}"))?;
    let ok = keys
        .iter()
        .any(|k| msg.verify(k).is_ok() || k.public_subkeys.iter().any(|s| msg.verify(s).is_ok()));
    if !ok {
        return Err("InRelease signature does not verify with deb.upstream_keyring_dir".into());
    }
    Ok(msg.signed_text().replace("\r\n", "\n"))
}

// ── Release / Packages ────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct Release {
    /// Single-line fields in upstream order.
    fields: Vec<(String, String)>,
    /// `SHA256` entries: path → (hash, size).
    sha256: BTreeMap<String, (String, u64)>,
}

impl Release {
    fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn parse_release(text: &str) -> Release {
    let mut rel = Release::default();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            if current.as_deref() == Some("SHA256") {
                let parts: Vec<_> = line.split_whitespace().collect();
                if let [hash, size, path] = parts[..] {
                    if let Ok(size) = size.parse() {
                        rel.sha256
                            .insert(path.to_string(), (hash.to_ascii_lowercase(), size));
                    }
                }
            }
            continue;
        }
        let Some((k, v)) = line.split_once(':') else {
            current = None;
            continue;
        };
        let (k, v) = (k.trim().to_string(), v.trim().to_string());
        if v.is_empty() {
            current = Some(k);
        } else {
            current = None;
            rel.fields.push((k, v));
        }
    }
    rel
}

/// Upstream fields carried into NORA's Release. `Signed-By` (the upstream's own key
/// fingerprints) and the checksum lists are not; apt would refuse NORA's signature.
const KEPT_FIELDS: &[&str] = &[
    "Origin",
    "Label",
    "Suite",
    "Version",
    "Codename",
    "Changelogs",
    "Date",
    "Valid-Until",
    "NotAutomatic",
    "ButAutomaticUpgrades",
    "No-Support-for-Architecture-all",
    "Components",
    "Description",
];

/// The `(component, arch)` binary indexes of a Release, each with the upstream file to
/// fetch (gz, xz, then plain), restricted to `archs`.
fn binary_indexes(rel: &Release, archs: &[String]) -> BTreeMap<(String, String), String> {
    let mut out: BTreeMap<(String, String), String> = BTreeMap::new();
    // gz first: lzma-rs reads no multi-stream or padded xz (some Ubuntu files).
    let rank = |p: &str| match p.rsplit('/').next() {
        Some("Packages.gz") => 0,
        Some("Packages.xz") => 1,
        _ => 2,
    };
    for path in rel.sha256.keys() {
        let parts: Vec<_> = path.split('/').collect();
        let [comp, bin, file] = parts[..] else {
            continue;
        };
        let Some(arch) = bin.strip_prefix("binary-") else {
            continue;
        };
        if !matches!(file, "Packages" | "Packages.xz" | "Packages.gz")
            || !archs.iter().any(|a| a == arch)
            || !valid_token(comp)
        {
            continue;
        }
        let slot = out
            .entry((comp.to_string(), arch.to_string()))
            .or_insert_with(|| path.clone());
        if rank(path) < rank(slot) {
            slot.clone_from(path);
        }
    }
    out
}

/// One stanza of a `Packages` file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Stanza {
    name: String,
    version: String,
    filename: String,
    #[serde(default)]
    first_seen: i64,
    text: String,
}

fn parse_packages(text: &str) -> Vec<Stanza> {
    text.split("\n\n")
        .filter_map(|block| {
            let block = block.trim_matches('\n');
            let field = |k: &str| {
                block.lines().find_map(|l| {
                    l.split_once(':')
                        .filter(|(name, _)| name.eq_ignore_ascii_case(k))
                        .map(|(_, v)| v.trim())
                })
            };
            Some(Stanza {
                name: field("Package")?.to_string(),
                version: field("Version")?.to_string(),
                filename: field("Filename")?.to_string(),
                first_seen: 0,
                text: block.to_string(),
            })
        })
        .collect()
}

fn decompress(path: &str, data: &[u8]) -> Result<String, String> {
    let mut out = Vec::new();
    if path.ends_with(".xz") {
        let mut sink = Capped(Vec::new());
        lzma_rs::xz_decompress(&mut &data[..], &mut sink).map_err(|e| format!("xz: {e}"))?;
        out = sink.0;
    } else if path.ends_with(".gz") {
        flate2::read::GzDecoder::new(data)
            .take(MAX_PACKAGES_TEXT + 1)
            .read_to_end(&mut out)
            .map_err(|e| format!("gz: {e}"))?;
    } else {
        out = data.to_vec();
    }
    if out.len() as u64 > MAX_PACKAGES_TEXT {
        return Err("Packages too large".into());
    }
    String::from_utf8(out).map_err(|_| "Packages is not UTF-8".into())
}

/// A sink refusing more than [`MAX_PACKAGES_TEXT`] bytes (decompression bomb).
struct Capped(Vec<u8>);

impl Write for Capped {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if (self.0.len() + data.len()) as u64 > MAX_PACKAGES_TEXT {
            return Err(std::io::Error::other("decompressed size limit exceeded"));
        }
        self.0.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn gzip(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).map_err(|e| e.to_string())?;
    enc.finish().map_err(|e| e.to_string())
}

fn sha256_hex(d: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(d))
}

fn valid_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.starts_with('.')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+'))
}

// ── Ledger ────────────────────────────────────────────────────────────────────

/// Per (suite, component, arch): when each listed file was first seen, the upstream
/// file the listing came from, and the dropped stanzas that may still be served.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Ledger {
    /// Upstream path (relative to `dists/{suite}/`) and SHA-256 of the last listing.
    upstream: Option<(String, String)>,
    seen: BTreeMap<String, i64>,
    #[serde(default)]
    retired: Vec<Stanza>,
}

/// Date `current` from `prev` (a file not seen before: `now`, or 0 when there is no
/// previous ledger), and keep from `dropped` + `prev.retired` what may still be served.
fn update_ledger(
    prev: Option<&Ledger>,
    current: &mut [Stanza],
    dropped: Vec<Stanza>,
    min_age: Option<i64>,
    now: i64,
) -> (BTreeMap<String, i64>, Vec<Stanza>) {
    let mut seen = BTreeMap::new();
    for s in current.iter_mut() {
        s.first_seen = match prev {
            None => 0,
            Some(p) => p.seen.get(&s.filename).copied().unwrap_or(now),
        };
        seen.insert(s.filename.clone(), s.first_seen);
    }
    let listed: HashSet<&str> = current.iter().map(|s| s.filename.as_str()).collect();
    let mut gone: Vec<Stanza> = Vec::new();
    let mut have = HashSet::new();
    for mut s in dropped
        .into_iter()
        .chain(prev.map(|p| p.retired.clone()).unwrap_or_default())
    {
        if listed.contains(s.filename.as_str()) || !have.insert(s.filename.clone()) {
            continue;
        }
        if let Some(p) = prev {
            if let Some(t) = p.seen.get(&s.filename) {
                s.first_seen = *t;
            }
        }
        gone.push(s);
    }
    (seen, retire(current, gone, min_age, now))
}

/// The dropped stanzas worth keeping: per package, those newer than its second-newest
/// version older than `max(min_release_age, 7 days)`, listed and dropped counted
/// together. Anything older can never be served again.
fn retire(current: &[Stanza], gone: Vec<Stanza>, min_age: Option<i64>, now: i64) -> Vec<Stanza> {
    let min_age = min_age.unwrap_or(0).max(RETAIN_AGE_SECS);
    let mut by_name: BTreeMap<String, Vec<(i64, Option<Stanza>)>> = BTreeMap::new();
    for s in current {
        by_name
            .entry(s.name.clone())
            .or_default()
            .push((s.first_seen, None));
    }
    let names: HashSet<&str> = current.iter().map(|s| s.name.as_str()).collect();
    for s in gone {
        // A package the upstream no longer lists at all is removed, not replaced.
        if names.contains(s.name.as_str()) {
            by_name
                .entry(s.name.clone())
                .or_default()
                .push((s.first_seen, Some(s)));
        }
    }
    let mut kept = Vec::new();
    for (_, mut versions) in by_name {
        versions.sort_by_key(|v| std::cmp::Reverse(v.0));
        let mut mature = 0;
        for (seen, s) in versions {
            if mature == 2 {
                break;
            }
            if now - seen >= min_age {
                mature += 1;
            }
            if let Some(s) = s {
                kept.push(s);
            }
        }
    }
    kept
}

/// What one index serves: listed versions not `hidden`; for a package with none, the
/// newest dropped one not hidden that `cached` has. Returns the stanzas in upstream
/// order (stand-ins last) and the earliest time a hidden one matures.
fn choose<'a>(
    current: &'a [Stanza],
    retired: &'a [Stanza],
    hidden: impl Fn(&Stanza) -> Option<i64>,
    cached: impl Fn(&Stanza) -> bool,
) -> (Vec<&'a Stanza>, Option<i64>) {
    let mut matures: Option<i64> = None;
    let mut note = |t: i64| matures = Some(matures.map_or(t, |m| m.min(t)));
    let mut out = Vec::new();
    let mut served: HashSet<&str> = HashSet::new();
    let mut held: Vec<&str> = Vec::new();
    for s in current {
        match hidden(s) {
            Some(t) => {
                note(t);
                held.push(&s.name);
            }
            None => {
                served.insert(&s.name);
                out.push(s);
            }
        }
    }
    let mut stand_in: BTreeMap<&str, &Stanza> = BTreeMap::new();
    for s in retired {
        if served.contains(s.name.as_str()) || !held.contains(&s.name.as_str()) {
            continue;
        }
        if let Some(t) = hidden(s) {
            note(t);
            continue;
        }
        if stand_in
            .get(s.name.as_str())
            .is_some_and(|b| b.first_seen >= s.first_seen)
            || !cached(s)
        {
            continue;
        }
        stand_in.insert(&s.name, s);
    }
    out.extend(stand_in.into_values());
    (out, matures)
}

fn packages_text(stanzas: &[&Stanza]) -> String {
    let mut out = String::new();
    for s in stanzas {
        out.push_str(&s.text);
        out.push_str("\n\n");
    }
    out
}

// ── Storage layout ────────────────────────────────────────────────────────────

fn meta(repo: &str) -> String {
    format!("deb/{repo}/.nora-meta/proxy")
}
fn suite_key(repo: &str, suite: &str, file: &str) -> String {
    format!("{}/dists/{suite}/{file}", meta(repo))
}
fn ledger_key(repo: &str, suite: &str, comp: &str, arch: &str) -> String {
    format!("{}/ledger/{suite}/{comp}/{arch}.json", meta(repo))
}
fn upstream_copy_key(repo: &str, suite: &str, comp: &str, arch: &str) -> String {
    format!("{}/upstream/{suite}/{comp}/{arch}", meta(repo))
}
fn blob_key(repo: &str, sha: &str) -> String {
    format!("{}/by-hash/{sha}", meta(repo))
}
fn young_key(repo: &str) -> String {
    format!("{}/young.json", meta(repo))
}

/// Suite state: the upstream InRelease it was built from and the files it names.
#[derive(Debug, Default, Serialize, Deserialize)]
struct SuiteState {
    upstream_sha: String,
    matures_at: Option<i64>,
    /// `{comp}/binary-{arch}/Packages.gz` → (sha256, size), current and previous build.
    files: BTreeMap<String, (String, u64)>,
    #[serde(default)]
    prev_files: BTreeMap<String, (String, u64)>,
    /// SHA-256 of an uncompressed `Packages` → its `Packages.gz` blob (apt finds an
    /// index by its uncompressed name, then fetches the gz), current and previous build.
    #[serde(default)]
    plain: BTreeMap<String, String>,
}

/// Held versions per index: filename → (name, version, first_seen).
type Young = BTreeMap<String, BTreeMap<String, (String, String, i64)>>;

async fn get_json<T: for<'de> Deserialize<'de>>(state: &AppState, key: &str) -> Option<T> {
    let data = state.storage.get(key).await.ok()?;
    serde_json::from_slice(&data).ok()
}

async fn put_json<T: Serialize>(state: &AppState, key: &str, v: &T) -> Result<(), String> {
    let json = serde_json::to_vec(v).map_err(|e| e.to_string())?;
    state
        .storage
        .put(key, &json)
        .await
        .map_err(|e| e.to_string())
}

// ── Build ─────────────────────────────────────────────────────────────────────

async fn fetch(
    state: &AppState,
    up: &RepoProxyEntry,
    url: &str,
    cap: u64,
) -> Result<Bytes, ProxyError> {
    crate::registry::proxy_fetch_capped(
        &state.http_client,
        url,
        Duration::from_secs(state.config.deb.proxy_timeout),
        up.auth().map(UpstreamAuth::Basic),
        &state.circuit_breaker,
        crate::circuit_breaker::BreakerScope::upstream(RegistryType::Deb, up.url()),
        cap,
    )
    .await
}

fn dists_url(up: &RepoProxyEntry, suite: &str, path: &str) -> String {
    format!("{}/dists/{suite}/{path}", up.url().trim_end_matches('/'))
}

/// Refresh `suite` of `repo` when its state is older than `metadata_ttl`, a held
/// version has matured, or there is none. Errors only when nothing can be served.
///
/// The refresh runs in its own task. Request handlers are dropped when the client
/// disconnects, and apt gives up on a request after 30 s, so a build slower than that
/// used to restart from scratch on every retry and never finished: trixie-security
/// (61 s) answered 499 to 44% of InRelease requests on 04-05.11.2026. With a previous
/// build the client waits at most `STALE_AFTER`, then gets that build.
async fn ensure_suite(
    state: &AppState,
    repo: &str,
    up: &RepoProxyEntry,
    suite: &str,
) -> Result<(), Response> {
    let state_key = suite_key(repo, suite, "state.json");
    let current: Option<SuiteState> = get_json(state, &state_key).await;
    if current.is_some() && !needs_refresh(state, &state_key, &current).await {
        return Ok(());
    }
    let task = {
        let (state, repo, up, suite) = (
            state.clone(),
            repo.to_string(),
            up.clone(),
            suite.to_string(),
        );
        let has_build = current.is_some();
        tokio::spawn(async move { refresh_suite(&state, &repo, &up, &suite, has_build).await })
    };
    let joined = if current.is_none() {
        task.await
    } else {
        match tokio::time::timeout(STALE_AFTER, task).await {
            Ok(r) => r,
            // Still building: serve the previous build, the task finishes on its own.
            Err(_) => return Ok(()),
        }
    };
    match joined {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "deb proxy: suite refresh task failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

async fn needs_refresh(state: &AppState, state_key: &str, current: &Option<SuiteState>) -> bool {
    let now = crate::cache_ttl::now_unix() as i64;
    let matured = current
        .as_ref()
        .and_then(|s| s.matures_at)
        .is_some_and(|t| now >= t);
    let fresh = state.storage.stat(state_key).await.is_some_and(|m| {
        crate::cache_ttl::is_within_ttl(m.modified, state.config.deb.metadata_ttl)
    });
    current.is_none() || matured || !fresh
}

async fn refresh_suite(
    state: &AppState,
    repo: &str,
    up: &RepoProxyEntry,
    suite: &str,
    has_build: bool,
) -> Result<(), Response> {
    let state_key = suite_key(repo, suite, "state.json");
    let lock = state.publish_lock(&state_key);
    let _guard = match lock.try_lock() {
        Ok(g) => g,
        // Another task is refreshing: serve what is there, or wait for it.
        Err(_) if has_build => return Ok(()),
        Err(_) => lock.lock().await,
    };
    let current: Option<SuiteState> = get_json(state, &state_key).await;
    if !needs_refresh(state, &state_key, &current).await {
        return Ok(());
    }
    match build_suite(state, repo, up, suite, current.as_ref()).await {
        Ok(()) => Ok(()),
        Err(e) if current.is_some() => {
            tracing::warn!(repo, suite, error = %e, "deb proxy: refresh failed, serving the last build");
            Ok(())
        }
        Err(e) => {
            tracing::warn!(repo, suite, error = %e, "deb proxy: no build to serve");
            Err(match e {
                BuildError::Upstream(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
                BuildError::Upstream(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
                BuildError::Upstream(err) => {
                    proxy_error_response("deb", &dists_url(up, suite, "InRelease"), &err)
                }
                BuildError::Refused(_) => StatusCode::BAD_GATEWAY.into_response(),
                BuildError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            })
        }
    }
}

#[derive(Debug)]
enum BuildError {
    Upstream(ProxyError),
    /// The upstream answered something NORA does not trust (signature, hash).
    Refused(String),
    Internal(String),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Upstream(e) => write!(f, "upstream: {e:?}"),
            Self::Refused(e) => write!(f, "refused: {e}"),
            Self::Internal(e) => write!(f, "{e}"),
        }
    }
}

async fn build_suite(
    state: &AppState,
    repo: &str,
    up: &RepoProxyEntry,
    suite: &str,
    current: Option<&SuiteState>,
) -> Result<(), BuildError> {
    let signer = state
        .signer
        .clone()
        .ok_or_else(|| BuildError::Internal("no [signing] key".into()))?;
    let keys = keyring(&state.config.deb.upstream_keyring_dir).map_err(BuildError::Internal)?;
    let body = fetch(
        state,
        up,
        &dists_url(up, suite, "InRelease"),
        MAX_RELEASE_BYTES,
    )
    .await
    .map_err(BuildError::Upstream)?;
    let upstream_sha = sha256_hex(&body);
    let now = crate::cache_ttl::now_unix() as i64;
    let state_key = suite_key(repo, suite, "state.json");
    if let Some(cur) = current {
        if cur.upstream_sha == upstream_sha && cur.matures_at.is_none_or(|t| now < t) {
            // Unchanged: rewrite the state to restart its TTL.
            return put_json(state, &state_key, cur)
                .await
                .map_err(BuildError::Internal);
        }
    }
    let text = tokio::task::spawn_blocking(move || verify_inrelease(&body, &keys))
        .await
        .map_err(|e| BuildError::Internal(e.to_string()))?
        .map_err(BuildError::Refused)?;
    let rel = parse_release(&text);
    let by_hash = rel
        .field("Acquire-By-Hash")
        .is_some_and(|v| v.eq_ignore_ascii_case("yes"));
    let indexes = binary_indexes(&rel, &state.config.deb.architectures);
    if indexes.is_empty() {
        return Err(BuildError::Refused(format!(
            "{suite}: no binary index for {:?}",
            state.config.deb.architectures
        )));
    }
    let curation = arc_swap::Guard::into_inner(state.curation());
    let engine = &curation.curation_engine;
    let min_age = engine.min_release_age_secs(RegistryType::Deb);

    let mut files = BTreeMap::new();
    let mut plain = BTreeMap::new();
    let mut matures_at: Option<i64> = None;
    let mut young: BTreeMap<String, BTreeMap<String, (String, String, i64)>> = BTreeMap::new();
    let mut served: HashSet<String> = HashSet::new();
    // Every ledger of the repo: one pool file can be listed by several suites, components
    // and architectures.
    // An unreadable ledger fails the build: dating without it would hold, and write to
    // this suite's ledger, a file another suite serves.
    let ledgers = match min_age {
        Some(_) => state
            .storage
            .list(&format!("{}/ledger/", meta(repo)))
            .await
            .map_err(|e| BuildError::Internal(e.to_string()))?,
        None => Vec::new(),
    };
    for ((comp, arch), path) in &indexes {
        let (hash, _) = rel.sha256[path].clone();
        let lkey = ledger_key(repo, suite, comp, arch);
        let ukey = upstream_copy_key(repo, suite, comp, arch);
        let prev: Option<Ledger> = get_json(state, &lkey).await;
        // The previous upstream listing, for the stanzas this one dropped.
        let prev_upstream = match prev.as_ref().and_then(|p| p.upstream.clone()) {
            Some((ppath, _)) => state.storage.get(&ukey).await.ok().map(|d| (ppath, d)),
            None => None,
        };
        let unchanged = prev
            .as_ref()
            .and_then(|p| p.upstream.as_ref())
            .is_some_and(|(_, h)| *h == hash);
        let data = match (&prev_upstream, unchanged) {
            (Some((_, d)), true) => d.clone(),
            _ => {
                let url = if by_hash {
                    let dir = path.rsplit_once('/').map_or("", |(d, _)| d);
                    dists_url(up, suite, &format!("{dir}/by-hash/SHA256/{hash}"))
                } else {
                    dists_url(up, suite, path)
                };
                let d = match fetch(state, up, &url, MAX_PACKAGES_BYTES).await {
                    Ok(d) => d,
                    // Ubuntu's archive and ports list every architecture in Release
                    // but each hosts only its own: an index that is not there is left out.
                    Err(ProxyError::NotFound) => {
                        tracing::debug!(repo, suite, %url, "deb proxy: index listed but absent upstream");
                        continue;
                    }
                    Err(e) => return Err(BuildError::Upstream(e)),
                };
                if sha256_hex(&d) != hash {
                    return Err(BuildError::Refused(format!(
                        "{url}: SHA-256 differs from the Release"
                    )));
                }
                d
            }
        };
        let path_c = path.clone();
        let prev_c = prev_upstream.clone();
        let data_c = data.clone();
        let parsed = tokio::task::spawn_blocking(move || {
            let current = parse_packages(&decompress(&path_c, &data_c)?);
            let dropped = match prev_c {
                Some((ppath, pdata)) if !unchanged => {
                    let listed: HashSet<String> =
                        current.iter().map(|s| s.filename.clone()).collect();
                    parse_packages(&decompress(&ppath, &pdata)?)
                        .into_iter()
                        .filter(|s| !listed.contains(&s.filename))
                        .collect()
                }
                _ => Vec::new(),
            };
            Ok::<_, String>((current, dropped))
        })
        .await
        .map_err(|e| BuildError::Internal(e.to_string()))?
        .map_err(BuildError::Refused)?;
        let (mut current_st, dropped) = parsed;
        let (mut seen, mut retired) =
            update_ledger(prev.as_ref(), &mut current_st, dropped, min_age, now);
        if let Some(age) = min_age {
            let wanted: HashSet<String> = current_st
                .iter()
                .chain(&retired)
                .filter(|s| now - s.first_seen < age)
                .map(|s| s.filename.clone())
                .collect();
            let others: Vec<String> = ledgers.iter().filter(|k| **k != lkey).cloned().collect();
            let earliest = earliest_seen(state, &others, &wanted)
                .await
                .map_err(BuildError::Internal)?;
            for s in current_st.iter_mut().chain(retired.iter_mut()) {
                if let Some(&t) = earliest.get(&s.filename) {
                    if t < s.first_seen {
                        s.first_seen = t;
                        if let Some(v) = seen.get_mut(&s.filename) {
                            *v = t;
                        }
                    }
                }
            }
        }

        let hidden = |s: &Stanza| -> Option<i64> {
            held_by_policy(engine, &s.name, &s.version, s.first_seen)
                .then(|| s.first_seen + min_age.unwrap_or(0))
        };
        let mut cached = HashSet::new();
        for s in &retired {
            if state
                .storage
                .stat(&format!("deb/{repo}/{}", s.filename))
                .await
                .is_some()
            {
                cached.insert(s.filename.clone());
            }
        }
        let (chosen, matures) = choose(&current_st, &retired, hidden, |s| {
            cached.contains(&s.filename)
        });
        if let Some(t) = matures {
            matures_at = Some(matures_at.map_or(t, |m: i64| m.min(t)));
        }
        let held: BTreeMap<String, (String, String, i64)> = current_st
            .iter()
            .chain(&retired)
            .filter(|s| hidden(s).is_some())
            .map(|s| {
                (
                    s.filename.clone(),
                    (s.name.clone(), s.version.clone(), s.first_seen),
                )
            })
            .collect();
        tracing::debug!(
            repo,
            suite,
            comp,
            arch,
            listed = current_st.len(),
            served = chosen.len(),
            held = held.len(),
            "deb proxy: index built"
        );
        served.extend(chosen.iter().map(|s| s.filename.clone()));
        let text = packages_text(&chosen);
        let (plain_sha, plain_len, gz) = tokio::task::spawn_blocking(move || {
            gzip(text.as_bytes()).map(|gz| (sha256_hex(text.as_bytes()), text.len() as u64, gz))
        })
        .await
        .map_err(|e| BuildError::Internal(e.to_string()))?
        .map_err(BuildError::Internal)?;
        let gz_sha = sha256_hex(&gz);
        plain.insert(plain_sha.clone(), gz_sha.clone());
        files.insert(
            format!("{comp}/binary-{arch}/Packages"),
            (plain_sha, plain_len),
        );
        state
            .storage
            .put(&blob_key(repo, &gz_sha), &gz)
            .await
            .map_err(|e| BuildError::Internal(e.to_string()))?;
        files.insert(
            format!("{comp}/binary-{arch}/Packages.gz"),
            (gz_sha, gz.len() as u64),
        );
        young.insert(format!("{suite}/{comp}/{arch}"), held);
        if !unchanged {
            state
                .storage
                .put(&ukey, &data)
                .await
                .map_err(|e| BuildError::Internal(e.to_string()))?;
        }
        let ledger = Ledger {
            upstream: Some((path.clone(), hash)),
            seen,
            retired,
        };
        put_json(state, &lkey, &ledger)
            .await
            .map_err(BuildError::Internal)?;
    }

    if files.is_empty() {
        return Err(BuildError::Upstream(ProxyError::NotFound));
    }
    // Held versions first, so a direct package fetch is refused before apt can see them.
    update_young(state, repo, suite, young, &served, min_age, now)
        .await
        .map_err(BuildError::Internal)?;

    let release = release_text(&rel, &state.config.deb.architectures, &files);
    let inrelease = signer.clearsign(&release).map_err(BuildError::Internal)?;
    let gpg = signer
        .sign_detached(release.as_bytes())
        .map_err(BuildError::Internal)?;
    // Release before its signatures, InRelease last: a reader never gets a signature
    // over files that are not there yet.
    for (file, data) in [
        ("Release", release.into_bytes()),
        ("Release.gpg", gpg.into_bytes()),
        ("InRelease", inrelease.into_bytes()),
    ] {
        state
            .storage
            .put(&suite_key(repo, suite, file), &data)
            .await
            .map_err(|e| BuildError::Internal(e.to_string()))?;
    }
    let prev_files = current.map(|c| c.files.clone()).unwrap_or_default();
    // Two builds back is gone: an apt run that read that Release has long finished.
    if let Some(cur) = current {
        let keep: HashSet<&String> = files
            .values()
            .chain(prev_files.values())
            .map(|(h, _)| h)
            .collect();
        for (h, _) in cur.prev_files.values() {
            if !keep.contains(h) {
                let _ = state.storage.delete(&blob_key(repo, h)).await;
            }
        }
    }
    if let Some(cur) = current {
        for (p, g) in &cur.plain {
            if prev_files.values().any(|(h, _)| h == g) {
                plain.entry(p.clone()).or_insert_with(|| g.clone());
            }
        }
    }
    let new_state = SuiteState {
        upstream_sha,
        matures_at,
        files,
        prev_files,
        plain,
    };
    put_json(state, &state_key, &new_state)
        .await
        .map_err(BuildError::Internal)
}

fn release_text(
    rel: &Release,
    archs: &[String],
    files: &BTreeMap<String, (String, u64)>,
) -> String {
    let mut out = String::new();
    for name in KEPT_FIELDS {
        if *name == "Components" {
            if let Some(a) = rel.field("Architectures") {
                let kept: Vec<_> = a
                    .split_whitespace()
                    .filter(|x| archs.iter().any(|y| y == x))
                    .collect();
                out.push_str(&format!("Architectures: {}\n", kept.join(" ")));
            }
        }
        if let Some(v) = rel.field(name) {
            out.push_str(&format!("{name}: {v}\n"));
        }
    }
    out.push_str("Acquire-By-Hash: yes\nSHA256:\n");
    for (path, (sha, size)) in files {
        out.push_str(&format!(" {sha} {size:>16} {path}\n"));
    }
    out
}

/// Whether curation hides a version first seen at `first_seen` from the indexes.
fn held_by_policy(
    engine: &crate::curation::CurationEngine,
    name: &str,
    version: &str,
    first_seen: i64,
) -> bool {
    crate::curation::is_internal_namespace(engine, RegistryType::Deb, name)
        || engine.hides_from_metadata(RegistryType::Deb, name, version, Some(first_seen))
}

/// The earliest date the ledgers `keys` give each of `files`. A pool file is as old as
/// its first sighting in any suite, component or architecture: jammy-updates and
/// jammy-security list one kernel `.deb` days apart, every arch index lists an
/// `_all.deb`.
async fn earliest_seen(
    state: &AppState,
    keys: &[String],
    files: &HashSet<String>,
) -> Result<HashMap<String, i64>, String> {
    let mut earliest: HashMap<String, i64> = HashMap::new();
    if files.is_empty() {
        return Ok(earliest);
    }
    // ponytail: parses every ledger of the repo when a build has young files; a
    // repo-wide first-seen map if that gets slow.
    for key in keys {
        let ledger: Ledger = match state.storage.get(key).await {
            Ok(data) => serde_json::from_slice(&data).map_err(|e| format!("{key}: {e}"))?,
            // Listed, then replaced or removed meanwhile: nothing to date from.
            Err(crate::storage::StorageError::NotFound) => continue,
            Err(e) => return Err(format!("{key}: {e}")),
        };
        let dates = ledger
            .seen
            .iter()
            .map(|(f, t)| (f, *t))
            .chain(ledger.retired.iter().map(|s| (&s.filename, s.first_seen)));
        for (f, t) in dates {
            if files.contains(f) {
                let e = earliest.entry(f.clone()).or_insert(t);
                *e = (*e).min(t);
            }
        }
    }
    Ok(earliest)
}

async fn update_young(
    state: &AppState,
    repo: &str,
    suite: &str,
    held: BTreeMap<String, BTreeMap<String, (String, String, i64)>>,
    served: &HashSet<String>,
    min_age: Option<i64>,
    since: i64,
) -> Result<(), String> {
    let key = young_key(repo);
    let lock = state.publish_lock(&key);
    let _g = lock.lock().await;
    let mut young: Young = get_json(state, &key).await.unwrap_or_default();
    let prefix = format!("{suite}/");
    young.retain(|k, _| !k.starts_with(&prefix));
    // A file this suite serves is not held by another suite's younger sighting of it:
    // apt finds it in this suite's index.
    for files in young.values_mut() {
        files.retain(|f, _| !served.contains(f));
    }
    young.retain(|_, files| !files.is_empty());
    let mut held = held;
    if min_age.is_some() {
        // Ledgers another build wrote after this one read them (a suite's first build
        // dates everything 0): under the lock, so that build's own update has run or
        // will run after this one and clear what it serves.
        let files: HashSet<String> = held.values().flat_map(|m| m.keys().cloned()).collect();
        if !files.is_empty() {
            let fresh: Vec<String> = state
                .storage
                .list_with_meta(&format!("{}/ledger/", meta(repo)))
                .await
                .map_err(|e| e.to_string())?
                .into_iter()
                // A minute early: the storage clock may lag this one.
                .filter(|(_, m)| m.modified as i64 >= since - 60)
                .map(|(k, _)| k)
                .collect();
            let earliest = earliest_seen(state, &fresh, &files).await?;
            let curation = state.curation();
            let engine = &curation.curation_engine;
            for m in held.values_mut() {
                m.retain(|f, (name, version, seen)| {
                    let Some(&t) = earliest.get(f) else {
                        return true;
                    };
                    *seen = (*seen).min(t);
                    // Held for its name (an internal namespace) whatever its age.
                    held_by_policy(engine, name, version, *seen)
                });
            }
        }
    }
    young.extend(held.into_iter().filter(|(_, v)| !v.is_empty()));
    put_json(state, &key, &young).await?;
    state
        .deb_young
        .lock()
        .insert(key, (Instant::now(), Arc::new(young)));
    Ok(())
}

async fn load_young(state: &AppState, repo: &str) -> Arc<Young> {
    let key = young_key(repo);
    let cached = state.deb_young.lock().get(&key).cloned();
    if let Some((at, y)) = cached {
        if at.elapsed() < YOUNG_TTL {
            return y;
        }
    }
    let y: Arc<Young> = Arc::new(get_json(state, &key).await.unwrap_or_default());
    state
        .deb_young
        .lock()
        .insert(key, (Instant::now(), y.clone()));
    y
}

// ── Handlers ──────────────────────────────────────────────────────────────────

fn file_response(data: Bytes, content_type: &'static str, immutable: bool) -> Response {
    let cache = if immutable {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (header::CACHE_CONTROL, HeaderValue::from_static(cache)),
        ],
        data,
    )
        .into_response()
}

/// An index file by its SHA-256: a stored `Packages.gz`, or an uncompressed `Packages`
/// decompressed from the gz it maps to.
async fn index_file(
    state: &AppState,
    repo: &str,
    suite: &str,
    sha: &str,
    immutable: bool,
) -> Response {
    if let Ok(d) = state.storage.get(&blob_key(repo, sha)).await {
        return file_response(d, "application/gzip", immutable);
    }
    let st: Option<SuiteState> = get_json(state, &suite_key(repo, suite, "state.json")).await;
    let Some(gz_sha) = st.and_then(|s| s.plain.get(sha).cloned()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(gz) = state.storage.get(&blob_key(repo, &gz_sha)).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match tokio::task::spawn_blocking(move || decompress("Packages.gz", &gz)).await {
        Ok(Ok(text)) => file_response(Bytes::from(text), "text/plain", immutable),
        _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// A GET on a filtered proxied repo. `None`: a package path, for the caller's
/// pull-through (after [`package_gate`]).
pub(crate) async fn serve(
    state: &AppState,
    repo: &str,
    up: &RepoProxyEntry,
    path: &str,
) -> Option<Response> {
    if path == "pubkey.gpg" {
        return Some(match &state.signer {
            Some(s) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/pgp-keys")],
                s.public_key_armored().to_string(),
            )
                .into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        });
    }
    let rest = path.strip_prefix("dists/")?;
    let parts: Vec<&str> = rest.split('/').collect();
    let not_found = || Some(StatusCode::NOT_FOUND.into_response());
    let suite = parts[0];
    if !valid_token(suite) {
        return not_found();
    }
    if let Err(r) = ensure_suite(state, repo, up, suite).await {
        return Some(r);
    }
    let read = |key: String| async move { state.storage.get(&key).await.ok() };
    match parts[1..] {
        [file @ ("InRelease" | "Release" | "Release.gpg")] => {
            Some(match read(suite_key(repo, suite, file)).await {
                Some(d) => file_response(d, "text/plain", false),
                None => StatusCode::NOT_FOUND.into_response(),
            })
        }
        [comp, bin, file @ ("Packages" | "Packages.gz")] => {
            let st: Option<SuiteState> =
                get_json(state, &suite_key(repo, suite, "state.json")).await;
            let sha = st.and_then(|s| {
                s.files
                    .get(&format!("{comp}/{bin}/{file}"))
                    .map(|(h, _)| h.clone())
            });
            match sha {
                Some(sha) => Some(index_file(state, repo, suite, &sha, false).await),
                None => not_found(),
            }
        }
        [_, _, "by-hash", "SHA256", hex]
            if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            Some(index_file(state, repo, suite, &hex.to_ascii_lowercase(), true).await)
        }
        // Translations, Contents, other compressions: not in NORA's Release.
        _ => not_found(),
    }
}

/// The curation check of a package download: a held version is refused (403 in
/// enforce, logged in audit).
pub(crate) async fn package_gate(
    state: &AppState,
    headers: &HeaderMap,
    repo: &str,
    path: &str,
) -> Option<Response> {
    let young = load_young(state, repo).await;
    let (name, version, first_seen) = young.values().find_map(|m| m.get(path))?.clone();
    let engine = &state.curation().curation_engine;
    crate::curation::check_download(
        engine,
        state.bypass_token().as_deref(),
        headers,
        RegistryType::Deb,
        &name,
        crate::curation::RequestVersion::Known(version),
        Some(first_seen),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn st(name: &str, version: &str, seen: i64) -> Stanza {
        Stanza {
            name: name.into(),
            version: version.into(),
            filename: format!("pool/main/{name}_{version}_amd64.deb"),
            first_seen: seen,
            text: format!("Package: {name}\nVersion: {version}\nFilename: pool/main/{name}_{version}_amd64.deb"),
        }
    }

    const DAY: i64 = 86_400;

    #[test]
    fn parses_release_fields_and_sha256() {
        let rel = parse_release(
            "Origin: Debian\nAcquire-By-Hash: yes\nSHA256:\n abc 12 main/binary-amd64/Packages.xz\n def 40 main/binary-amd64/Packages\n 0 1 main/debian-installer/binary-amd64/Packages\nSigned-By: X\n",
        );
        assert_eq!(rel.field("origin"), Some("Debian"));
        assert_eq!(
            rel.sha256["main/binary-amd64/Packages.xz"],
            ("abc".into(), 12)
        );
        let idx = binary_indexes(&rel, &["amd64".into()]);
        assert_eq!(
            idx.len(),
            1,
            "debian-installer is not a binary index of the component"
        );
        assert_eq!(
            idx[&("main".into(), "amd64".into())],
            "main/binary-amd64/Packages.xz"
        );
        let text = release_text(&rel, &["amd64".into()], &BTreeMap::new());
        assert!(!text.contains("Signed-By"), "{text}");
    }

    #[test]
    fn a_new_ledger_dates_everything_before_nora_then_new_files_now() {
        let mut cur = vec![st("a", "1", 99)];
        let (seen, _) = update_ledger(None, &mut cur, vec![], None, 1000);
        assert_eq!(seen["pool/main/a_1_amd64.deb"], 0);
        let prev = Ledger {
            upstream: None,
            seen,
            retired: vec![],
        };
        let mut cur = vec![st("a", "2", 0)];
        let (seen, retired) = update_ledger(
            Some(&prev),
            &mut cur,
            vec![st("a", "1", 0)],
            Some(3 * DAY),
            1000,
        );
        assert_eq!(seen["pool/main/a_2_amd64.deb"], 1000);
        assert_eq!(retired.len(), 1, "the displaced version is kept");
        assert_eq!(retired[0].first_seen, 0);
    }

    #[test]
    fn choose_holds_young_and_stands_in_a_cached_dropped_version() {
        let now = 100 * DAY;
        let current = vec![
            st("a", "2", now - DAY),
            st("b", "1", 0),
            st("c", "2", now - DAY),
        ];
        let retired = vec![st("a", "1", 0), st("c", "1", 0)];
        let hidden = |s: &Stanza| (now - s.first_seen < 3 * DAY).then_some(s.first_seen + 3 * DAY);
        let (out, matures) = choose(&current, &retired, hidden, |s| s.name == "a");
        let v: Vec<_> = out
            .iter()
            .map(|s| (s.name.as_str(), s.version.as_str()))
            .collect();
        assert_eq!(v, [("b", "1"), ("a", "1")], "c has no cached stand-in");
        assert_eq!(matures, Some(now + 2 * DAY));
    }

    #[test]
    fn retire_drops_what_can_never_be_served_again() {
        let now = 100 * DAY;
        let current = vec![st("a", "4", now)];
        let gone = vec![
            st("a", "3", now - 20 * DAY),
            st("a", "2", now - 30 * DAY),
            st("a", "1", now - 40 * DAY),
            st("z", "1", 0),
        ];
        let kept: Vec<_> = retire(&current, gone, Some(3 * DAY), now)
            .into_iter()
            .map(|s| s.version)
            .collect();
        assert_eq!(
            kept,
            ["3", "2"],
            "two mature versions are enough; z is gone upstream"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use crate::config::{CurationMode, RepoProxyEntry};
    use crate::digest_quarantine::QuarantineMode;
    use crate::test_helpers::*;
    use axum::http::{Method, StatusCode};
    use pgp::composed::{
        ArmorOptions, CleartextSignedMessage, Deserializable, KeyType, SecretKeyParamsBuilder,
        SignedPublicKey, SignedSecretKey,
    };
    use pgp::types::Password;
    use std::io::Read;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn upstream_key() -> (SignedSecretKey, tempfile::TempDir) {
        let key = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .can_sign(true)
            .primary_user_id("Test Archive".into())
            .build()
            .unwrap()
            .generate(rand::thread_rng())
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let public = key
            .to_public_key()
            .to_armored_string(ArmorOptions::default())
            .unwrap();
        std::fs::write(dir.path().join("archive.asc"), public).unwrap();
        (key, dir)
    }

    fn gz(data: &[u8]) -> Vec<u8> {
        super::gzip(data).unwrap()
    }

    fn stanza(name: &str, version: &str) -> String {
        format!("Package: {name}\nVersion: {version}\nArchitecture: amd64\nFilename: pool/main/{name}_{version}_amd64.deb\n")
    }

    /// Mount a signed suite listing `stanzas` and their package files.
    async fn publish(server: &MockServer, key: &SignedSecretKey, stanzas: &[(&str, &str)]) {
        publish_slow(server, key, stanzas, std::time::Duration::ZERO).await;
    }

    /// `publish` with an upstream InRelease that answers after `delay`.
    async fn publish_slow(
        server: &MockServer,
        key: &SignedSecretKey,
        stanzas: &[(&str, &str)],
        delay: std::time::Duration,
    ) {
        server.reset().await;
        mount_suite(server, key, "bookworm", "main", stanzas, delay).await;
    }

    /// Mount one signed suite beside what `server` already serves.
    async fn mount_suite(
        server: &MockServer,
        key: &SignedSecretKey,
        suite: &str,
        comp: &str,
        stanzas: &[(&str, &str)],
        delay: std::time::Duration,
    ) {
        let text: String = stanzas.iter().map(|(n, v)| stanza(n, v) + "\n").collect();
        let packages = gz(text.as_bytes());
        let release = format!(
            "Origin: Test\nSuite: stable\nCodename: bookworm\nDate: Tue, 03 Nov 2026 00:00:00 UTC\nArchitectures: amd64 i386\nComponents: {comp}\nSigned-By: ABCDEF\nSHA256:\n {} {} {comp}/binary-amd64/Packages.gz\n {} 0 {comp}/binary-i386/Packages.gz\n",
            super::sha256_hex(&packages),
            packages.len(),
            super::sha256_hex(b""),
        );
        let signed =
            CleartextSignedMessage::sign(rand::thread_rng(), &release, &**key, &Password::empty())
                .unwrap()
                .to_armored_string(ArmorOptions::default())
                .unwrap();
        let mount = |at: String, body: Vec<u8>| async move {
            Mock::given(method("GET"))
                .and(path(at))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
                .mount(server)
                .await;
        };
        Mock::given(method("GET"))
            .and(path(format!("/dists/{suite}/InRelease")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(signed.into_bytes())
                    .set_delay(delay),
            )
            .mount(server)
            .await;
        mount(
            format!("/dists/{suite}/{comp}/binary-amd64/Packages.gz"),
            packages,
        )
        .await;
        for (n, v) in stanzas {
            mount(
                format!("/pool/main/{n}_{v}_amd64.deb"),
                format!("{n}-{v}").into_bytes(),
            )
            .await;
        }
    }

    /// The served Release (verified with NORA's public key) and the Packages it names.
    async fn served(ctx: &TestContext) -> (String, Vec<(String, String)>) {
        served_in(ctx, "bookworm", "main").await
    }

    async fn served_in(
        ctx: &TestContext,
        suite: &str,
        comp: &str,
    ) -> (String, Vec<(String, String)>) {
        let key = body_bytes(send(&ctx.app, Method::GET, "/deb/debian/pubkey.gpg", "").await).await;
        let (key, _) = SignedPublicKey::from_armor_single(std::io::Cursor::new(&key[..])).unwrap();
        let resp = send(
            &ctx.app,
            Method::GET,
            &format!("/deb/debian/dists/{suite}/InRelease"),
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let release = super::verify_inrelease(&body, &[key]).expect("signed by NORA");
        let rel = super::parse_release(&release);
        let (sha, _) = rel.sha256[&format!("{comp}/binary-amd64/Packages.gz")].clone();
        let resp = send(
            &ctx.app,
            Method::GET,
            &format!("/deb/debian/dists/{suite}/{comp}/binary-amd64/by-hash/SHA256/{sha}"),
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let data = body_bytes(resp).await;
        assert_eq!(
            super::sha256_hex(&data),
            sha,
            "by-hash body matches the Release"
        );
        let mut text = String::new();
        flate2::read::GzDecoder::new(&data[..])
            .read_to_string(&mut text)
            .unwrap();
        let pkgs = super::parse_packages(&text)
            .into_iter()
            .map(|s| (s.name, s.version))
            .collect();
        (release, pkgs)
    }

    #[tokio::test]
    async fn holds_young_versions_signs_and_refuses_held_packages() {
        let (key, keydir) = upstream_key();
        let server = MockServer::start().await;
        publish(&server, &key, &[("a", "1"), ("b", "1")]).await;
        let uri = server.uri();
        let dir = keydir.path().to_str().unwrap().to_string();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.deb.enabled = true;
            cfg.deb.metadata_ttl = 0;
            cfg.deb.upstream_keyring_dir = dir;
            cfg.deb
                .proxies
                .insert("debian".into(), RepoProxyEntry::Simple(uri));
            cfg.curation.mode = CurationMode::Enforce;
            cfg.curation.deb.min_release_age = Some("3d".into());
            cfg.curation.deb.quarantine = Some(QuarantineMode::Observe);
            cfg.curation.deb.quarantine_ttl = Some("3d".into());
        });

        // First sight: everything predates NORA and is served.
        let (release, pkgs) = served(&ctx).await;
        assert_eq!(pkgs, [("a".into(), "1".into()), ("b".into(), "1".into())]);
        assert!(!release.contains("Signed-By"), "{release}");
        assert!(release.contains("Architectures: amd64\n"), "{release}");
        assert!(release.contains("Acquire-By-Hash: yes"));
        // a 1 is installed once, so NORA has it cached.
        let resp = send(
            &ctx.app,
            Method::GET,
            "/deb/debian/pool/main/a_1_amd64.deb",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        // The download is cached in the background; the stand-in below needs it stored.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while ctx
            .state
            .storage
            .stat("deb/debian/pool/main/a_1_amd64.deb")
            .await
            .is_none()
        {
            assert!(
                std::time::Instant::now() < deadline,
                "a 1 never reached the cache"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // The upstream replaces a 1 and b 1 with new versions and adds c.
        publish(&server, &key, &[("a", "2"), ("b", "2"), ("c", "1")]).await;
        let (_, pkgs) = served(&ctx).await;
        assert_eq!(
            pkgs,
            [("a".into(), "1".into())],
            "a falls back to the cached 1; b 1 was never cached; c is new"
        );
        // Another server in the same process with a repository of the same name and
        // nothing held: its held set must not replace this one's (it was a process-wide
        // cache, and this test failed when the 0d test ran beside it).
        let other_uri = server.uri();
        let other_dir = keydir.path().to_str().unwrap().to_string();
        let other = create_test_context_with_config(move |cfg| {
            cfg.deb.enabled = true;
            cfg.deb.metadata_ttl = 0;
            cfg.deb.upstream_keyring_dir = other_dir;
            cfg.deb
                .proxies
                .insert("debian".into(), RepoProxyEntry::Simple(other_uri));
            cfg.curation.mode = CurationMode::Enforce;
            cfg.curation.deb.min_release_age = Some("0d".into());
        });
        served(&other).await;
        let resp = send(
            &ctx.app,
            Method::GET,
            "/deb/debian/pool/main/a_2_amd64.deb",
            "",
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "a held version is refused"
        );
        let resp = send(
            &ctx.app,
            Method::GET,
            "/deb/debian/pool/main/a_1_amd64.deb",
            "",
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the stand-in comes from the cache"
        );
        let resp = send(
            &ctx.app,
            Method::GET,
            "/deb/debian/dists/bookworm/main/i18n/Translation-en",
            "",
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "only the files NORA's Release names"
        );
    }

    /// jammy-updates and jammy-security list one pool file, days apart (issues-maestra#1649);
    /// here under different components, as an `_all.deb` is under different architectures.
    #[tokio::test]
    async fn a_pool_file_two_suites_list_is_as_old_as_its_first_sighting() {
        let (key, keydir) = upstream_key();
        let server = MockServer::start().await;
        let z = std::time::Duration::ZERO;
        let uri = server.uri();
        let dir = keydir.path().to_str().unwrap().to_string();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.deb.enabled = true;
            cfg.deb.metadata_ttl = 0;
            cfg.deb.upstream_keyring_dir = dir;
            cfg.deb
                .proxies
                .insert("debian".into(), RepoProxyEntry::Simple(uri));
            cfg.curation.mode = CurationMode::Enforce;
            cfg.curation.deb.min_release_age = Some("3d".into());
        });
        let get = |p: &'static str| send(&ctx.app, Method::GET, p, "");
        let k2 = "/deb/debian/pool/main/k_2_amd64.deb";

        // security lists k 1 before NORA, then k 2: k 2 is young there, and refused.
        mount_suite(&server, &key, "security", "extra", &[("k", "1")], z).await;
        served_in(&ctx, "security", "extra").await;
        server.reset().await;
        mount_suite(&server, &key, "security", "extra", &[("k", "2")], z).await;
        served_in(&ctx, "security", "extra").await;
        assert_eq!(get(k2).await.status(), StatusCode::FORBIDDEN);

        // updates has listed k 2 since before NORA: apt sees it there, the file is served.
        mount_suite(&server, &key, "updates", "main", &[("k", "2")], z).await;
        let (_, pkgs) = served_in(&ctx, "updates", "main").await;
        assert_eq!(pkgs, [("k".into(), "2".into())]);
        assert_eq!(get(k2).await.status(), StatusCode::OK);

        // security's next build dates k 2 from updates; l 1, new in both, stays held.
        server.reset().await;
        mount_suite(&server, &key, "updates", "main", &[("k", "2")], z).await;
        mount_suite(
            &server,
            &key,
            "security",
            "extra",
            &[("k", "2"), ("l", "1")],
            z,
        )
        .await;
        let (_, pkgs) = served_in(&ctx, "security", "extra").await;
        assert_eq!(pkgs, [("k".into(), "2".into())]);
        assert_eq!(get(k2).await.status(), StatusCode::OK);
        assert_eq!(
            get("/deb/debian/pool/main/l_1_amd64.deb").await.status(),
            StatusCode::FORBIDDEN,
            "a file no suite has listed for 3 days is still held"
        );
    }

    /// A build that read the ledgers before another suite wrote an older date for its
    /// held file drops the hold under the lock; a ledger it had read already is not
    /// read again, and a file held for its name stays held whatever its date.
    #[tokio::test]
    async fn a_hold_is_checked_against_ledgers_written_during_the_build() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.deb.enabled = true;
            cfg.curation.deb.min_release_age = Some("3d".into());
            cfg.curation.internal_namespaces = vec!["corp-*".to_string()];
        });
        let state = &ctx.state;
        let now = crate::cache_ttl::now_unix() as i64;
        let f = "pool/main/k_2_amd64.deb".to_string();
        let corp = "pool/main/corp-x_1_amd64.deb".to_string();
        let ledger = super::Ledger {
            upstream: None,
            seen: [(f.clone(), 0), (corp.clone(), 0)].into(),
            retired: Vec::new(),
        };
        super::put_json(
            state,
            &super::ledger_key("debian", "updates", "main", "amd64"),
            &ledger,
        )
        .await
        .unwrap();
        let held = |seen: i64| -> std::collections::BTreeMap<_, _> {
            [(
                "security/main/amd64".to_string(),
                [
                    (f.clone(), ("k".to_string(), "2".to_string(), seen)),
                    (corp.clone(), ("corp-x".to_string(), "1".to_string(), seen)),
                ]
                .into(),
            )]
            .into()
        };
        let none = std::collections::HashSet::new();
        let age = Some(3 * 86_400);
        // Read before the build started (since = later): the hold stays.
        super::update_young(
            state,
            "debian",
            "security",
            held(now),
            &none,
            age,
            now + 3600,
        )
        .await
        .unwrap();
        assert!(super::load_young(state, "debian").await["security/main/amd64"].contains_key(&f));
        // Written during the build: the hold goes, but not the one on an internal name.
        super::update_young(state, "debian", "security", held(now), &none, age, now)
            .await
            .unwrap();
        let young = super::load_young(state, "debian").await;
        let files = &young["security/main/amd64"];
        assert!(!files.contains_key(&f), "{files:?}");
        assert!(files.contains_key(&corp), "{files:?}");
    }

    /// A ledger that cannot be read fails the dating, so the build fails and keeps the
    /// last one, instead of holding a file the unread ledger dates older.
    #[tokio::test]
    async fn an_unreadable_ledger_fails_the_dating() {
        let ctx = create_test_context_with_config(|cfg| cfg.deb.enabled = true);
        let state = &ctx.state;
        let bad = super::ledger_key("debian", "updates", "main", "amd64");
        state.storage.put(&bad, b"not json").await.unwrap();
        let gone = super::ledger_key("debian", "gone", "main", "amd64");
        let files: std::collections::HashSet<String> =
            ["pool/main/k_2_amd64.deb".to_string()].into();
        assert!(super::earliest_seen(state, &[bad], &files).await.is_err());
        assert_eq!(
            super::earliest_seen(state, &[gone], &files).await,
            Ok(Default::default())
        );
    }

    #[tokio::test]
    async fn zero_age_serves_everything_and_an_unsigned_upstream_is_refused() {
        let (key, keydir) = upstream_key();
        let (other, _) = upstream_key();
        let server = MockServer::start().await;
        publish(&server, &key, &[("a", "1")]).await;
        let uri = server.uri();
        let dir = keydir.path().to_str().unwrap().to_string();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.deb.enabled = true;
            cfg.deb.metadata_ttl = 0;
            cfg.deb.upstream_keyring_dir = dir;
            cfg.deb
                .proxies
                .insert("debian".into(), RepoProxyEntry::Simple(uri));
            cfg.curation.mode = CurationMode::Enforce;
            cfg.curation.deb.min_release_age = Some("0d".into());
            cfg.curation.deb.quarantine = Some(QuarantineMode::Observe);
        });
        served(&ctx).await;
        publish(&server, &key, &[("a", "2")]).await;
        let (_, pkgs) = served(&ctx).await;
        assert_eq!(pkgs, [("a".into(), "2".into())], "0d holds nothing");
        let resp = send(
            &ctx.app,
            Method::GET,
            "/deb/debian/pool/main/a_2_amd64.deb",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Signed by a key outside the keyring: the last good build stays served.
        publish(&server, &other, &[("a", "3")]).await;
        let (_, pkgs) = served(&ctx).await;
        assert_eq!(pkgs, [("a".into(), "2".into())]);
    }
    #[tokio::test]
    async fn a_slow_refresh_serves_the_last_build_and_finishes_without_the_client() {
        let (key, keydir) = upstream_key();
        let server = MockServer::start().await;
        publish(&server, &key, &[("a", "1")]).await;
        let uri = server.uri();
        let dir = keydir.path().to_str().unwrap().to_string();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.deb.enabled = true;
            cfg.deb.metadata_ttl = 0;
            cfg.deb.upstream_keyring_dir = dir;
            cfg.deb
                .proxies
                .insert("debian".into(), RepoProxyEntry::Simple(uri));
            cfg.curation.mode = CurationMode::Enforce;
            cfg.curation.deb.min_release_age = Some("0d".into());
            cfg.curation.deb.quarantine = Some(QuarantineMode::Observe);
        });
        served(&ctx).await;

        // The upstream takes longer than a client waits: the previous build is served
        // after STALE_AFTER (apt would have given up at 30 s and cancelled the build).
        let delay = std::time::Duration::from_secs(3);
        publish_slow(&server, &key, &[("a", "2")], delay).await;
        let t = std::time::Instant::now();
        let resp = send(
            &ctx.app,
            Method::GET,
            "/deb/debian/dists/bookworm/InRelease",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            t.elapsed() < delay,
            "waited {:?} for a slow upstream",
            t.elapsed()
        );

        // The refresh outlived that request and finished on its own.
        tokio::time::sleep(delay + std::time::Duration::from_secs(1)).await;
        let (_, pkgs) = served(&ctx).await;
        assert_eq!(pkgs, [("a".into(), "2".into())]);
    }
}
