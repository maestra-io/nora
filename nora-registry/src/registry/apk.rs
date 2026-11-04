// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Alpine (apk) repository proxy (maestra): one `[apk.proxies]` entry per mirror root,
//! pull-through only.
//!
//!   GET /apk/keys/{key_name}                               — NORA's public key (no auth)
//!   GET /apk/{name}/{branch}/{repo}/{arch}/APKINDEX.tar.gz — the upstream index, filtered
//!   GET /apk/{name}/{branch}/{repo}/{arch}/{pkg}-{ver}.apk — a package
//!   GET /apk/{name}/{arch}/...                             — the same for a flat repository
//!                                                            (apk.corretto.aws)
//!
//! The upstream index is refused unless one of `upstream_keys_dir`'s keys verifies its
//! signature. It is kept as JSON (`apk/index/...json`) with every entry the upstream has
//! listed and since dropped, while it may still be needed: an Alpine branch lists ONE
//! version per package and deletes the file of the one it replaces. On serve, each
//! package gets its newest version that is older than `min_release_age` by its build time
//! (`t:`, inside the signed index) and that NORA can still deliver (listed upstream, or a
//! dropped one NORA has cached). A package whose every version is too young is left out,
//! so `apk add` fails with "no such package" rather than reaching around NORA. The result
//! is signed with NORA's key (`.SIGN.RSA256.<key_name>`), which clients trust from
//! `/etc/apk/keys/<key_name>`; signature checking stays on end to end.
//!
//! A package is fetched only under the name and version an index entry lists, refused
//! when its control segment does not hash to the entry's `C:` (the identity apk itself
//! verifies), cached under `apk/pkgs/` and held by the digest quarantine like any proxy
//! artifact, seeded from the signed build time with `server.trust_upstream_dates`.
//!
//! Client: `https://nora.example.com/apk/alpine/v3.22/main` as the repository, the token
//! in `HTTP_AUTH="basic:*:token:<token>"` (apk-tools <= 2.14.6 rejects a URL password over
//! ~1 KiB, and a GitHub OIDC token is longer).

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::cache_ttl::is_within_ttl;
use crate::circuit_breaker::BreakerScope;
use crate::config::{ApkConfig, RepoProxyEntry, UpstreamAuth};
use crate::registry::{circuit_open_response, proxy_error_response, ProxyBody, ProxyError};
use crate::registry_type::RegistryType;
use crate::AppState;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePublicKey, LineEnding};
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Cached packages, one directory per repository (the repo index counts them).
pub const INDEX_PATTERN: (&str, &str) = ("apk/pkgs/", ".apk");

/// Largest upstream `APKINDEX.tar.gz` fetched (edge/community is ~2 MiB) and its
/// decompressed size.
const MAX_INDEX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_INDEX_TEXT: u64 = 256 * 1024 * 1024;
/// Bytes read from the start of a package for its signature and control segments.
const MAX_CONTROL_PREFIX: usize = 8 * 1024 * 1024;
/// A rendered index is reused this long (render: gzip of a few MiB plus one signature).
// ponytail: a version that matures, or a dropped one getting cached, shows up to a minute late.
const RENDER_TTL: Duration = Duration::from_secs(60);

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/apk/keys/{file}", get(public_key))
        .route("/apk/{name}/{branch}/{repo}/{arch}/{file}", get(file))
        .route("/apk/{name}/{arch}/{file}", get(flat_file))
}

// ── Index model ───────────────────────────────────────────────────────────────

/// One package entry of an APKINDEX: its name (`P:`), version (`V:`), build time
/// (`t:`) and the whole block as the upstream wrote it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Entry {
    name: String,
    version: String,
    built: i64,
    block: String,
}

impl Entry {
    fn file(&self) -> String {
        format!("{}-{}.apk", self.name, self.version)
    }

    /// The `C:` identity: `Q1` + base64 of the control segment's SHA-1.
    fn identity(&self) -> Option<&str> {
        self.block.lines().find_map(|l| l.strip_prefix("C:"))
    }
}

/// What is cached per index: the upstream's DESCRIPTION, its current entries and the
/// ones it has dropped that may still be served.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Cached {
    description: String,
    entries: Vec<Entry>,
    #[serde(default)]
    retired: Vec<Entry>,
}

/// Names and versions as abuild writes them (`libstdc++`, `1.2.3_git20240101-r0`).
fn is_valid_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 200
        && !s.starts_with('.')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+' | '~'))
}

/// A path segment NORA routes (`v3.22`, `edge`, `main`, `x86_64`).
fn is_valid_segment(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.starts_with('.')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// Entries of an APKINDEX text. An entry without a name, version or build time is
/// dropped: undated, it could not be held back.
fn parse_apkindex(text: &str) -> Vec<Entry> {
    text.split("\n\n")
        .filter_map(|block| {
            let block = block.trim_matches('\n');
            let field = |k: &str| block.lines().find_map(|l| l.strip_prefix(k));
            let name = field("P:")?;
            let version = field("V:")?;
            let built = field("t:")?.trim().parse::<i64>().ok()?;
            (is_valid_token(name) && is_valid_token(version)).then(|| Entry {
                name: name.to_string(),
                version: version.to_string(),
                built,
                block: block.to_string(),
            })
        })
        .collect()
}

/// History kept even with no (or a shorter) `min_release_age`, so a hold switched on
/// later finds the versions upstream dropped meanwhile.
const RETAIN_AGE_SECS: i64 = 7 * 86_400;

/// The dropped entries worth keeping: per package, those newer than its second-newest
/// version older than `max(min_release_age, 7 days)` (current and dropped entries
/// counted together). Anything older can never be the version served again.
fn retire(prev: &Cached, current: &[Entry], min_age: Option<i64>, now: i64) -> Vec<Entry> {
    let min_age = min_age.unwrap_or(0).max(RETAIN_AGE_SECS);
    let listed: HashSet<(&str, &str)> = current
        .iter()
        .map(|e| (e.name.as_str(), e.version.as_str()))
        .collect();
    let mut by_name: BTreeMap<&str, Vec<(&Entry, bool)>> = BTreeMap::new();
    for e in current {
        by_name.entry(&e.name).or_default().push((e, false));
    }
    let mut seen = HashSet::new();
    for e in prev.entries.iter().chain(&prev.retired) {
        if listed.contains(&(e.name.as_str(), e.version.as_str()))
            || !seen.insert((e.name.as_str(), e.version.as_str()))
        {
            continue;
        }
        by_name.entry(&e.name).or_default().push((e, true));
    }
    let mut kept = Vec::new();
    for (_, mut versions) in by_name {
        versions.sort_by_key(|v| std::cmp::Reverse(v.0.built));
        let mut mature = 0;
        for (e, dropped) in versions {
            if mature == 2 {
                break;
            }
            if now - e.built >= min_age {
                mature += 1;
            }
            if dropped {
                kept.push(e.clone());
            }
        }
    }
    kept
}

/// Per package (by name), the versions that may be served, best first: old enough by
/// `hidden`, newest build first, a listed one before a dropped one of the same build.
fn candidates(
    cached: &Cached,
    hidden: impl Fn(&Entry) -> bool,
) -> BTreeMap<&str, Vec<(&Entry, bool)>> {
    let mut by_name: BTreeMap<&str, Vec<(&Entry, bool)>> = BTreeMap::new();
    let all = cached
        .entries
        .iter()
        .map(|e| (e, false))
        .chain(cached.retired.iter().map(|e| (e, true)));
    for (e, dropped) in all {
        if !hidden(e) {
            by_name.entry(&e.name).or_default().push((e, dropped));
        }
    }
    for versions in by_name.values_mut() {
        versions.sort_by(|a, b| b.0.built.cmp(&a.0.built).then(a.1.cmp(&b.1)));
    }
    by_name
}

// ── Archives ──────────────────────────────────────────────────────────────────

/// The first gzip member of `buf`, decompressed (at most `cap` bytes), and its
/// compressed length.
fn gzip_member(buf: &[u8], cap: u64) -> Result<(Vec<u8>, usize), String> {
    let mut decoder = flate2::bufread::GzDecoder::new(buf);
    let mut out = Vec::new();
    (&mut decoder)
        .take(cap + 1)
        .read_to_end(&mut out)
        .map_err(|e| format!("gzip: {e}"))?;
    if out.len() as u64 > cap {
        return Err(format!("gzip member over {cap} bytes"));
    }
    let rest = decoder.into_inner();
    Ok((out, buf.len() - rest.len()))
}

fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    // Writing to a Vec cannot fail.
    let _ = e.write_all(data);
    e.finish().unwrap_or_default()
}

/// Regular files of a tar stream, ended by a zero block or by the end of the data (the
/// signature segment of an apk archive has no end-of-archive blocks).
fn tar_files(tar: &[u8]) -> Result<Vec<(String, &[u8])>, String> {
    let mut files = Vec::new();
    let mut off = 0;
    while off + 512 <= tar.len() {
        let h = &tar[off..off + 512];
        if h.iter().all(|&b| b == 0) {
            break;
        }
        let field = |r: std::ops::Range<usize>| {
            let f = &h[r];
            String::from_utf8_lossy(&f[..f.iter().position(|&b| b == 0).unwrap_or(f.len())])
                .into_owned()
        };
        let name = field(0..100);
        let size = u64::from_str_radix(field(124..136).trim(), 8)
            .map_err(|_| format!("tar: bad size of {name:?}"))? as usize;
        let start = off + 512;
        let end = start
            .checked_add(size)
            .filter(|&e| e <= tar.len())
            .ok_or_else(|| format!("tar: {name:?} runs past the end"))?;
        if matches!(h[156], b'0' | 0) {
            files.push((name, &tar[start..end]));
        }
        off = start + size.div_ceil(512) * 512;
    }
    Ok(files)
}

/// A tar member (ustar header + data padded to a block), no end-of-archive.
fn tar_entry(name: &str, data: &[u8], mtime: u64) -> Result<Vec<u8>, String> {
    let mut h = tar::Header::new_ustar();
    h.set_path(name).map_err(|e| format!("tar: {e}"))?;
    h.set_size(data.len() as u64);
    h.set_mode(0o644);
    h.set_mtime(mtime);
    h.set_uid(0);
    h.set_gid(0);
    h.set_entry_type(tar::EntryType::Regular);
    h.set_cksum();
    let mut out = h.as_bytes().to_vec();
    out.extend_from_slice(data);
    out.resize(512 + data.len().div_ceil(512) * 512, 0);
    Ok(out)
}

/// The signature of an apk archive's first segment: (digest is SHA-256, key name, bytes).
fn signature(sig_tar: &[u8]) -> Result<(bool, String, Vec<u8>), String> {
    for (name, data) in tar_files(sig_tar)? {
        if let Some(key) = name.strip_prefix(".SIGN.RSA256.") {
            return Ok((true, key.to_string(), data.to_vec()));
        }
        if let Some(key) = name.strip_prefix(".SIGN.RSA.") {
            return Ok((false, key.to_string(), data.to_vec()));
        }
    }
    Err("no .SIGN.RSA signature".to_string())
}

fn rsa_verify(key: &RsaPublicKey, sha256: bool, signed: &[u8], sig: &[u8]) -> bool {
    use rsa::sha2::Digest as _;
    if sha256 {
        let digest = rsa::sha2::Sha256::digest(signed);
        key.verify(Pkcs1v15Sign::new::<rsa::sha2::Sha256>(), &digest, sig)
            .is_ok()
    } else {
        let digest = sha1_digest010::Sha1::digest(signed);
        key.verify(Pkcs1v15Sign::new::<sha1_digest010::Sha1>(), &digest, sig)
            .is_ok()
    }
}

/// DESCRIPTION and APKINDEX of an upstream `APKINDEX.tar.gz` whose signature one of
/// `keys` verifies.
fn open_upstream_index(
    buf: &[u8],
    keys: &HashMap<String, RsaPublicKey>,
) -> Result<(String, String), String> {
    let (sig_tar, sig_len) = gzip_member(buf, 1024 * 1024)?;
    let (sha256, key_name, sig) = signature(&sig_tar)?;
    let key = keys
        .get(&key_name)
        .ok_or_else(|| format!("signed by {key_name}, not a trusted upstream key"))?;
    let signed = &buf[sig_len..];
    if !rsa_verify(key, sha256, signed, &sig) {
        return Err(format!("signature by {key_name} does not verify"));
    }
    let mut tar = Vec::new();
    flate2::read::MultiGzDecoder::new(signed)
        .take(MAX_INDEX_TEXT + 1)
        .read_to_end(&mut tar)
        .map_err(|e| format!("gzip: {e}"))?;
    if tar.len() as u64 > MAX_INDEX_TEXT {
        return Err("index over the size limit".to_string());
    }
    let files = tar_files(&tar)?;
    let get = |n: &str| {
        files
            .iter()
            .find(|(name, _)| name == n)
            .map(|(_, d)| String::from_utf8_lossy(d).into_owned())
    };
    let index = get("APKINDEX").ok_or("no APKINDEX in the index")?;
    Ok((get("DESCRIPTION").unwrap_or_default(), index))
}

/// An `APKINDEX.tar.gz` of `entries`, signed by `keys` as `key_name` (RSA, SHA-256).
fn signed_index(
    keys: &Keys,
    key_name: &str,
    description: &str,
    entries: &[&Entry],
    mtime: u64,
) -> Result<Vec<u8>, String> {
    use rsa::sha2::Digest as _;
    let mut text = String::new();
    for e in entries {
        text.push_str(&e.block);
        text.push_str("\n\n");
    }
    let mut tar = tar_entry("DESCRIPTION", description.as_bytes(), mtime)?;
    tar.extend(tar_entry("APKINDEX", text.as_bytes(), mtime)?);
    tar.resize(tar.len() + 1024, 0);
    let data = gzip(&tar);
    let digest = rsa::sha2::Sha256::digest(&data);
    // Blinded (random) RSA: the signing time does not track the key (RUSTSEC-2023-0071).
    let sig = keys
        .signer
        .sign_with_rng(
            &mut rand::thread_rng(),
            Pkcs1v15Sign::new::<rsa::sha2::Sha256>(),
            &digest,
        )
        .map_err(|e| format!("sign: {e}"))?;
    let mut out = gzip(&tar_entry(
        &format!(".SIGN.RSA256.{key_name}"),
        &sig,
        mtime,
    )?);
    out.extend(data);
    Ok(out)
}

/// `Q1` + base64(SHA-1) of the control segment of an apk package: the segment after the
/// signature (a package without one starts with it). `prefix` is the start of the file.
fn package_identity(prefix: &[u8]) -> Result<String, String> {
    use base64::Engine as _;
    use sha1::Digest as _;
    let (first, first_len) = gzip_member(prefix, MAX_CONTROL_PREFIX as u64)?;
    let signed = tar_files(&first)?
        .first()
        .is_some_and(|(n, _)| n.starts_with(".SIGN."));
    let control = if signed {
        let rest = &prefix[first_len..];
        let (_, len) = gzip_member(rest, MAX_CONTROL_PREFIX as u64)?;
        &rest[..len]
    } else {
        &prefix[..first_len]
    };
    Ok(format!(
        "Q1{}",
        base64::engine::general_purpose::STANDARD.encode(sha1::Sha1::digest(control))
    ))
}

// ── Keys ──────────────────────────────────────────────────────────────────────

struct Keys {
    signer: RsaPrivateKey,
    public_pem: String,
    upstream: HashMap<String, RsaPublicKey>,
}

fn load_keys(cfg: &ApkConfig) -> Result<Keys, String> {
    let pem = zeroize::Zeroizing::new(
        std::fs::read_to_string(&cfg.signing_key_path)
            .map_err(|e| format!("apk signing key {}: {e}", cfg.signing_key_path))?,
    );
    let signer = RsaPrivateKey::from_pkcs8_pem(&pem)
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&pem))
        .map_err(|e| format!("apk signing key {}: {e}", cfg.signing_key_path))?;
    let public_pem = signer
        .to_public_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| format!("apk public key: {e}"))?;
    let mut upstream = HashMap::new();
    let mut dirs = vec![std::path::PathBuf::from(&cfg.upstream_keys_dir)];
    while let Some(dir) = dirs.pop() {
        let entries = std::fs::read_dir(&dir)
            .map_err(|e| format!("apk upstream keys {}: {e}", dir.display()))?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                dirs.push(path);
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !name.ends_with(".pub") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            match RsaPublicKey::from_public_key_pem(&text)
                .or_else(|_| RsaPublicKey::from_pkcs1_pem(&text))
            {
                Ok(key) => {
                    upstream.insert(name.to_string(), key);
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "apk: unreadable upstream key, skipped")
                }
            }
        }
    }
    if upstream.is_empty() {
        return Err(format!(
            "apk: no upstream keys under {}: no upstream index could be verified",
            cfg.upstream_keys_dir
        ));
    }
    Ok(Keys {
        signer,
        public_pem,
        upstream,
    })
}

/// The keys of `cfg`, loaded once per (signing key, keys dir) and kept for the process.
/// A rotated key takes a restart (Reloader restarts on the Secret change).
fn keys(cfg: &ApkConfig) -> Result<Arc<Keys>, String> {
    type KeyCache = Mutex<HashMap<(String, String), Arc<Keys>>>;
    static CACHE: std::sync::OnceLock<KeyCache> = std::sync::OnceLock::new();
    let id = (cfg.signing_key_path.clone(), cfg.upstream_keys_dir.clone());
    let cache = CACHE.get_or_init(Default::default);
    if let Some(keys) = cache.lock().ok().and_then(|c| c.get(&id).cloned()) {
        return Ok(keys);
    }
    let keys = Arc::new(load_keys(cfg)?);
    if let Ok(mut c) = cache.lock() {
        c.insert(id, keys.clone());
    }
    Ok(keys)
}

/// Startup check (config validation): the keys load.
pub fn check_keys(cfg: &ApkConfig) -> Result<(), String> {
    keys(cfg).map(|_| ())
}

// ── Index loading ─────────────────────────────────────────────────────────────

fn upstream<'a>(state: &'a AppState, name: &str) -> Option<&'a RepoProxyEntry> {
    state.config.apk.proxies.get(name)
}

/// The effective `(mode, ttl_secs)` of the apk quarantine.
fn quarantine(state: &AppState) -> (crate::digest_quarantine::QuarantineMode, i64) {
    let curation = &state.config.curation;
    crate::digest_quarantine::resolve_global(
        curation
            .apk
            .quarantine
            .as_ref()
            .or(curation.quarantine.as_ref()),
        curation
            .apk
            .quarantine_ttl
            .as_deref()
            .or(curation.quarantine_ttl.as_deref()),
    )
}

/// `/{branch}/{repo}/{arch}` of a request, validated; `/{arch}` alone for a flat
/// repository (apk.corretto.aws keeps `<arch>/APKINDEX.tar.gz` at its root).
struct RepoPath {
    name: String,
    /// `branch/repo/arch`, or `arch`.
    dir: String,
}

impl RepoPath {
    fn new(name: String, segments: &[&str]) -> Option<Self> {
        segments
            .iter()
            .all(|s| is_valid_segment(s))
            .then(|| RepoPath {
                name,
                dir: segments.join("/"),
            })
    }

    fn index_key(&self) -> String {
        format!("apk/index/{}/{}.json", self.name, self.dir)
    }

    fn package_key(&self, file: &str) -> String {
        format!("apk/pkgs/{}/{}/{file}", self.name, self.dir)
    }

    fn upstream_url(&self, up: &RepoProxyEntry, file: &str) -> String {
        format!("{}/{}/{file}", up.url().trim_end_matches('/'), self.dir)
    }
}

async fn parse_cached(data: Bytes) -> Option<Cached> {
    tokio::task::spawn_blocking(move || serde_json::from_slice(&data).ok())
        .await
        .ok()
        .flatten()
}

async fn fresh_index(state: &AppState, key: &str) -> Option<Cached> {
    let meta = state.storage.stat(key).await?;
    if !is_within_ttl(meta.modified, state.config.apk.metadata_ttl) {
        return None;
    }
    parse_cached(state.storage.get(key).await.ok()?).await
}

/// The last cached index whatever its age; `serve_stale` decides whether it may be
/// served, a refresh always merges into it.
async fn last_index(state: &AppState, key: &str) -> Option<Cached> {
    parse_cached(state.storage.get(key).await.ok()?).await
}

/// The index of `path` and whether it is a stale copy, or the response to give when
/// there is none. One refresh per index at a time, as the helm proxy does.
async fn load_index(
    state: &AppState,
    path: &RepoPath,
    up: &RepoProxyEntry,
) -> Result<(Cached, bool), Response> {
    let key = path.index_key();
    if let Some(index) = fresh_index(state, &key).await {
        return Ok((index, false));
    }
    let serve_stale = state.config.apk.serve_stale;
    let lock = state.publish_lock(&key);
    let _refresh = match lock.try_lock() {
        Ok(guard) => guard,
        Err(_) => {
            if serve_stale {
                if let Some(index) = last_index(state, &key).await {
                    return Ok((index, true));
                }
            }
            lock.lock().await
        }
    };
    if let Some(index) = fresh_index(state, &key).await {
        return Ok((index, false));
    }

    let url = path.upstream_url(up, "APKINDEX.tar.gz");
    let keys = match keys(&state.config.apk) {
        Ok(keys) => keys,
        Err(e) => {
            tracing::error!(error = %e, "apk: keys unavailable");
            return Err(StatusCode::SERVICE_UNAVAILABLE.into_response());
        }
    };
    let fetched = crate::registry::proxy_fetch_capped(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.apk.proxy_timeout),
        up.auth().map(UpstreamAuth::Basic),
        &state.circuit_breaker,
        BreakerScope::upstream(RegistryType::Apk, up.url()),
        MAX_INDEX_BYTES,
    )
    .await;
    let prev = last_index(state, &key).await;
    let err = match fetched {
        Ok(body) => {
            let min_age = state
                .curation()
                .curation_engine
                .min_release_age_secs(RegistryType::Apk);
            let prev_for_merge = prev.as_ref().map(|p| Cached {
                description: String::new(),
                entries: p.entries.clone(),
                retired: p.retired.clone(),
            });
            let parsed = tokio::task::spawn_blocking(move || {
                let (description, text) = open_upstream_index(&body, &keys.upstream)?;
                let entries = parse_apkindex(&text);
                let now = crate::cache_ttl::now_unix() as i64;
                let retired = prev_for_merge
                    .map(|p| retire(&p, &entries, min_age, now))
                    .unwrap_or_default();
                let cached = Cached {
                    description,
                    entries,
                    retired,
                };
                let json = serde_json::to_vec(&cached).map_err(|e| e.to_string())?;
                Ok::<_, String>((cached, json))
            })
            .await;
            match parsed {
                Ok(Ok((cached, json))) => {
                    if let Err(e) = state.storage.put(&key, &json).await {
                        tracing::warn!(key = %key, error = %e, "apk: failed to cache index");
                    }
                    return Ok((cached, false));
                }
                Ok(Err(e)) => {
                    tracing::warn!(url = %url, error = %e, "apk: upstream index refused");
                    ProxyError::Upstream(502)
                }
                Err(e) => ProxyError::Network(e.to_string()),
            }
        }
        Err(e) => e,
    };
    if let Some(index) = prev.filter(|_| serve_stale) {
        tracing::warn!(registry = "apk", url = %url, error = ?err, "apk upstream error, serving stale index");
        return Ok((index, true));
    }
    Err(match err {
        ProxyError::NotFound => StatusCode::NOT_FOUND.into_response(),
        ProxyError::CircuitOpen(reg) => circuit_open_response(&reg),
        e => proxy_error_response("apk", &url, &e),
    })
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn public_key(State(state): State<AppState>, Path(file): Path<String>) -> Response {
    let cfg = &state.config.apk;
    if file != cfg.key_name {
        return StatusCode::NOT_FOUND.into_response();
    }
    match keys(cfg) {
        Ok(keys) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/x-pem-file"),
            )],
            keys.public_pem.clone(),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "apk: keys unavailable");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

async fn file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((name, branch, repo, arch, file)): Path<(String, String, String, String, String)>,
) -> Response {
    let path = RepoPath::new(name, &[&branch, &repo, &arch]);
    serve(&state, &headers, path, &file).await
}

async fn flat_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((name, arch, file)): Path<(String, String, String)>,
) -> Response {
    let path = RepoPath::new(name, &[&arch]);
    serve(&state, &headers, path, &file).await
}

async fn serve(
    state: &AppState,
    headers: &HeaderMap,
    path: Option<RepoPath>,
    file: &str,
) -> Response {
    let Some(path) = path else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(up) = upstream(state, &path.name) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if file == "APKINDEX.tar.gz" {
        index(state, &path, up).await
    } else if file.ends_with(".apk") && is_valid_token(file) {
        package(state, headers, &path, up, file).await
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

type RenderCache = Mutex<HashMap<String, (Instant, bool, Bytes)>>;

fn render_cache() -> &'static RenderCache {
    static CACHE: std::sync::OnceLock<RenderCache> = std::sync::OnceLock::new();
    CACHE.get_or_init(Default::default)
}

async fn index(state: &AppState, path: &RepoPath, up: &RepoProxyEntry) -> Response {
    // Keyed by the upstream too: the cache is per process, not per AppState.
    let key = format!("{}|{}", up.url(), path.index_key());
    let ttl = RENDER_TTL.min(Duration::from_secs(
        state.config.apk.metadata_ttl.max(0) as u64
    ));
    let hit = render_cache()
        .lock()
        .ok()
        .and_then(|c| c.get(&key).cloned())
        .filter(|(at, _, _)| at.elapsed() < ttl);
    let (stale, body) = match hit {
        Some((_, stale, body)) => (stale, body),
        None => match render(state, path, up).await {
            Ok((stale, body)) => {
                if let Ok(mut c) = render_cache().lock() {
                    c.insert(key, (Instant::now(), stale, body.clone()));
                }
                (stale, body)
            }
            Err(response) => return response,
        },
    };
    let mut response = (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/gzip"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=0, must-revalidate"),
            ),
        ],
        body,
    )
        .into_response();
    if stale {
        response.headers_mut().insert(
            HeaderName::from_static("x-nora-stale"),
            HeaderValue::from_static("true"),
        );
    }
    response
}

/// The filtered, signed index of `path` and whether it came from a stale copy.
async fn render(
    state: &AppState,
    path: &RepoPath,
    up: &RepoProxyEntry,
) -> Result<(bool, Bytes), Response> {
    let (cached, stale) = load_index(state, path, up).await?;
    let engine = &state.curation().curation_engine;
    let by_name = candidates(&cached, |e| {
        crate::curation::is_internal_namespace(engine, RegistryType::Apk, &e.name)
            || engine.hides_from_metadata(RegistryType::Apk, &e.name, &e.version, Some(e.built))
    });
    // A dropped version is deliverable only from NORA's cache; a listed one always.
    let mut chosen = Vec::with_capacity(by_name.len());
    let mut fallbacks = 0;
    for versions in by_name.values() {
        for (e, dropped) in versions {
            if !dropped
                || state
                    .storage
                    .stat(&path.package_key(&e.file()))
                    .await
                    .is_some()
            {
                chosen.push(*e);
                fallbacks += usize::from(*dropped);
                break;
            }
        }
    }
    tracing::debug!(index = %path.index_key(), served = chosen.len(), listed = cached.entries.len(), fallbacks, "apk: index rendered");
    let keys = keys(&state.config.apk).map_err(|e| {
        tracing::error!(error = %e, "apk: keys unavailable");
        StatusCode::SERVICE_UNAVAILABLE.into_response()
    })?;
    let mtime = chosen.iter().map(|e| e.built).max().unwrap_or(0).max(0) as u64;
    let body = signed_index(
        &keys,
        &state.config.apk.key_name,
        &cached.description,
        &chosen,
        mtime,
    )
    .map_err(|e| {
        tracing::error!(error = %e, "apk: index signing failed");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;
    Ok((stale, Bytes::from(body)))
}

async fn package(
    state: &AppState,
    headers: &HeaderMap,
    path: &RepoPath,
    up: &RepoProxyEntry,
    file: &str,
) -> Response {
    // The date, version and identity come from the index (a stale copy will do), never
    // from the file name, which does not split unambiguously into name and version.
    let (cached, _) = match load_index(state, path, up).await {
        Ok(loaded) => loaded,
        Err(response) => return response,
    };
    let Some(entry) = cached
        .entries
        .iter()
        .chain(&cached.retired)
        .find(|e| e.file() == file)
        .cloned()
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let engine = &state.curation().curation_engine;
    if let Some(response) =
        crate::curation::check_namespace_isolation(engine, RegistryType::Apk, &entry.name)
    {
        return response;
    }
    if let Some(response) = crate::curation::check_download(
        engine,
        state.bypass_token().as_deref(),
        headers,
        RegistryType::Apk,
        &entry.name,
        crate::curation::RequestVersion::Known(entry.version.clone()),
        Some(entry.built),
    ) {
        return response;
    }
    // The build time sits inside the upstream-signed index: a trusted publish date.
    let publish_date = Some(entry.built).filter(|_| state.config.server.trust_upstream_dates);
    let (q_mode, q_secs) = quarantine(state);
    let key = path.package_key(file);
    let label = format!("{}/{}/{file}", path.name, path.dir);

    let cached_copy = match crate::registry::read_cached_artifact(state, "apk", &key, false).await {
        Ok(copy) => copy,
        Err(response) => return response,
    };
    if let Some(copy) = cached_copy {
        let digest = copy.digest();
        if let Some(response) = crate::curation::verify_integrity_by_hash(
            engine,
            RegistryType::Apk,
            &entry.name,
            Some(&entry.version),
            &digest,
        ) {
            return response;
        }
        state.metrics.record_download("apk");
        state.metrics.record_cache_hit("apk");
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            label,
            RegistryType::Apk,
            "CACHE",
        ));
        state
            .audit
            .log(AuditEntry::new("cache_hit", "proxy", "", "apk", ""));
        if let Some(resp) = crate::digest_quarantine::proxy_gate_digest(
            &state.digest_store,
            "apk",
            &digest,
            &q_mode,
            q_secs,
            "cache",
            publish_date,
        ) {
            return resp;
        }
        let len = copy.len();
        return package_response(len, copy.into_body(state, "apk", &key, false));
    }

    let url = path.upstream_url(up, file);
    let (data, fetched) = match crate::registry::proxy_fetch_artifact(
        state,
        &key,
        "apk",
        &url,
        state.config.apk.proxy_timeout,
        up.auth().map(UpstreamAuth::Basic),
        BreakerScope::upstream(RegistryType::Apk, up.url()),
    )
    .await
    {
        Ok(fetched) => fetched,
        Err(e) => return proxy_error_response("apk", &url, &e),
    };
    // The signed index names the package's control-segment hash: a body without it
    // (truncated, swapped, rebuilt) is neither served nor cached.
    let actual = match control_prefix(&data).await {
        Ok(prefix) => package_identity(&prefix),
        Err(e) => Err(e),
    };
    match (&actual, entry.identity()) {
        (Ok(actual), Some(expected)) if actual == expected => {}
        _ => {
            tracing::warn!(url = %url, expected = ?entry.identity(), actual = ?actual, "apk package does not match its index identity, refusing it");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    }
    let digest = data.digest();
    if let Some(response) = crate::curation::verify_integrity_by_hash(
        engine,
        RegistryType::Apk,
        &entry.name,
        Some(&entry.version),
        &digest,
    ) {
        return response;
    }
    state.metrics.record_download("apk");
    state.metrics.record_cache_miss("apk");
    state.activity.push(ActivityEntry::new(
        ActionType::ProxyFetch,
        label,
        RegistryType::Apk,
        "PROXY",
    ));
    state
        .audit
        .log(AuditEntry::new("proxy_fetch", "proxy", "", "apk", ""));
    if fetched {
        crate::registry::spawn_cache_body(state, "apk", key.clone(), data.clone());
    }
    if let Some(resp) = crate::digest_quarantine::proxy_gate_digest(
        &state.digest_store,
        "apk",
        &digest,
        &q_mode,
        q_secs,
        &url,
        publish_date,
    ) {
        return resp;
    }
    let len = data.len();
    match data.into_body(&key).await {
        Ok(body) => package_response(len, body),
        Err(e) => {
            tracing::warn!(key = %key, error = %e, "apk: spooled package unreadable");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// The first [`MAX_CONTROL_PREFIX`] bytes of a fetched body.
async fn control_prefix(data: &ProxyBody) -> Result<Vec<u8>, String> {
    match data {
        ProxyBody::Mem(b) => Ok(b[..b.len().min(MAX_CONTROL_PREFIX)].to_vec()),
        ProxyBody::File(spool) => {
            use tokio::io::AsyncReadExt;
            let file = tokio::fs::File::open(&spool.path)
                .await
                .map_err(|e| format!("spool: {e}"))?;
            let mut out = Vec::new();
            file.take(MAX_CONTROL_PREFIX as u64)
                .read_to_end(&mut out)
                .await
                .map_err(|e| format!("spool: {e}"))?;
            Ok(out)
        }
    }
}

fn package_response(len: u64, body: axum::body::Body) -> Response {
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=31536000, immutable"),
            ),
            (header::CONTENT_LENGTH, HeaderValue::from(len)),
        ],
        body,
    )
        .into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use rsa::pkcs8::EncodePrivateKey;

    pub(super) const DAY: i64 = 86_400;

    pub(super) fn now() -> i64 {
        crate::cache_ttl::now_unix() as i64
    }

    /// A key pair on disk: (dir holding `<name>` public key, private key path).
    pub(super) fn key_files(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let key = RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap();
        let private = dir.path().join("signing.pem");
        std::fs::write(
            &private,
            key.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes(),
        )
        .unwrap();
        let pubdir = dir.path().join("pub/x86_64");
        std::fs::create_dir_all(&pubdir).unwrap();
        std::fs::write(
            pubdir.join(name),
            key.to_public_key()
                .to_public_key_pem(LineEnding::LF)
                .unwrap(),
        )
        .unwrap();
        (dir, private)
    }

    pub(super) fn config(
        upstream: &(tempfile::TempDir, std::path::PathBuf),
        own: &(tempfile::TempDir, std::path::PathBuf),
    ) -> ApkConfig {
        ApkConfig {
            enabled: true,
            signing_key_path: own.1.display().to_string(),
            key_name: "nora-test.rsa.pub".into(),
            upstream_keys_dir: upstream.0.path().join("pub").display().to_string(),
            ..ApkConfig::default()
        }
    }

    /// The upstream's view of `cfg`: its own key signs, as `alpine-test.rsa.pub`.
    pub(super) fn upstream_signer(
        upstream: &(tempfile::TempDir, std::path::PathBuf),
        own: &(tempfile::TempDir, std::path::PathBuf),
    ) -> Arc<Keys> {
        let cfg = ApkConfig {
            signing_key_path: upstream.1.display().to_string(),
            upstream_keys_dir: own.0.path().join("pub").display().to_string(),
            ..ApkConfig::default()
        };
        keys(&cfg).unwrap()
    }

    pub(super) fn entry(name: &str, version: &str, built: i64, identity: &str) -> Entry {
        Entry {
            name: name.into(),
            version: version.into(),
            built,
            block: format!("C:{identity}\nP:{name}\nV:{version}\nA:x86_64\nt:{built}\nD:so:libc.musl-x86_64.so.1"),
        }
    }

    pub(super) fn upstream_index(keys: &Keys, entries: &[Entry]) -> Vec<u8> {
        let refs: Vec<&Entry> = entries.iter().collect();
        signed_index(keys, "alpine-test.rsa.pub", "v3.22.0-1-gtest", &refs, 0).unwrap()
    }

    /// A synthetic apk package: signature, control and data segments.
    pub(super) fn package(name: &str, payload: &[u8]) -> (Vec<u8>, String) {
        use base64::Engine as _;
        use sha1::Digest as _;
        let sig = gzip(&tar_entry(".SIGN.RSA.alpine-test.rsa.pub", b"sig", 0).unwrap());
        let control =
            gzip(&tar_entry(".PKGINFO", format!("pkgname = {name}\n").as_bytes(), 0).unwrap());
        let mut data = tar_entry("usr/bin/demo", payload, 0).unwrap();
        data.resize(data.len() + 1024, 0);
        let identity = format!(
            "Q1{}",
            base64::engine::general_purpose::STANDARD.encode(sha1::Sha1::digest(&control))
        );
        let mut out = sig;
        out.extend(control);
        out.extend(gzip(&data));
        (out, identity)
    }

    #[test]
    fn parses_entries_and_drops_undated_ones() {
        let text = "C:Q1a=\nP:musl\nV:1.2.5-r4\nt:100\n\nP:nodate\nV:1\n\nP:bad/name\nV:1\nt:1\n\nP:libstdc++\nV:14.2.0-r4\nt:5\n";
        let e = parse_apkindex(text);
        assert_eq!(e.len(), 2);
        assert_eq!((e[0].name.as_str(), e[0].built), ("musl", 100));
        assert_eq!(e[0].identity(), Some("Q1a="));
        assert_eq!(e[1].file(), "libstdc++-14.2.0-r4.apk");
    }

    #[test]
    fn tar_reader_takes_a_segment_without_end_blocks() {
        let mut t = tar_entry("a", b"hello", 0).unwrap();
        t.extend(tar_entry("b", &[7u8; 600], 0).unwrap());
        let files = tar_files(&t).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0], ("a".to_string(), &b"hello"[..]));
        assert_eq!(files[1].1.len(), 600);
        t.truncate(1024 + 512 + 100);
        assert!(tar_files(&t).is_err(), "a member running past the end");
    }

    #[test]
    fn signature_skips_a_pax_header_before_it() {
        // v3.22+ indexes: abuild's tar writes ./PaxHeaders/<name> (type 'x') first.
        let mut pax = tar_entry("./PaxHeaders/.SIGN.RSA.k.rsa.pub", b"11 ctime=0\n", 0).unwrap();
        pax[156] = b'x';
        pax.extend(tar_entry(".SIGN.RSA.k.rsa.pub", b"sig", 0).unwrap());
        assert_eq!(
            signature(&pax).unwrap(),
            (false, "k.rsa.pub".to_string(), b"sig".to_vec())
        );
    }

    #[test]
    fn a_signed_index_opens_only_with_its_key_and_untampered() {
        let up = key_files("alpine-test.rsa.pub");
        let own = key_files("nora-test.rsa.pub");
        let signer = upstream_signer(&up, &own);
        let trusted = keys(&config(&up, &own)).unwrap();
        let body = upstream_index(&signer, &[entry("musl", "1.2.5-r4", 7, "Q1x=")]);
        let (desc, text) = open_upstream_index(&body, &trusted.upstream).unwrap();
        assert_eq!(desc, "v3.22.0-1-gtest");
        assert_eq!(parse_apkindex(&text)[0].version, "1.2.5-r4");

        let mut tampered = body.clone();
        let last = tampered.len() - 9;
        tampered[last] ^= 1;
        assert!(open_upstream_index(&tampered, &trusted.upstream).is_err());
        // NORA's own key is not an upstream key.
        let own_signed = signed_index(&trusted, "nora-test.rsa.pub", "", &[], 0).unwrap();
        let err = open_upstream_index(&own_signed, &trusted.upstream).unwrap_err();
        assert!(err.contains("not a trusted upstream key"), "{err}");
    }

    #[test]
    fn a_sha1_signature_verifies_too() {
        use sha1_digest010::Digest as _;
        let up = key_files("alpine-test.rsa.pub");
        let own = key_files("nora-test.rsa.pub");
        let signer = upstream_signer(&up, &own);
        let trusted = keys(&config(&up, &own)).unwrap();
        let mut tar = tar_entry("DESCRIPTION", b"d", 0).unwrap();
        tar.extend(tar_entry("APKINDEX", b"P:a\nV:1\nt:1\n\n", 0).unwrap());
        tar.resize(tar.len() + 1024, 0);
        let data = gzip(&tar);
        let digest = sha1_digest010::Sha1::digest(&data);
        let sig = signer
            .signer
            .sign(Pkcs1v15Sign::new::<sha1_digest010::Sha1>(), &digest)
            .unwrap();
        let mut body = gzip(&tar_entry(".SIGN.RSA.alpine-test.rsa.pub", &sig, 0).unwrap());
        body.extend(data);
        let (_, text) = open_upstream_index(&body, &trusted.upstream).unwrap();
        assert_eq!(parse_apkindex(&text).len(), 1);
    }

    #[test]
    fn retire_keeps_what_a_young_replacement_needs() {
        let now = now();
        let old = entry("lib", "1-r0", now - 30 * DAY, "Q1a=");
        let older = entry("lib", "0-r0", now - 60 * DAY, "Q1b=");
        let young = entry("lib", "2-r0", now - DAY, "Q1c=");
        let prev = Cached {
            entries: vec![old.clone()],
            retired: vec![older.clone()],
            ..Cached::default()
        };
        // Young 2-r0 replaced 1-r0: 1-r0 (the newest mature) and 0-r0 (the second) stay.
        let kept = retire(&prev, std::slice::from_ref(&young), Some(3 * DAY), now);
        assert_eq!(kept, vec![old.clone(), older.clone()]);
        // A mature 3-r0 listed: one mature dropped one (2-r0 once mature) is enough.
        let mature = entry("lib", "3-r0", now - 8 * DAY, "Q1d=");
        let prev = Cached {
            entries: vec![entry("lib", "2-r0", now - 10 * DAY, "Q1c=")],
            retired: vec![old.clone(), older],
            ..Cached::default()
        };
        let kept = retire(&prev, &[mature], Some(3 * DAY), now);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].version, "2-r0");
        // No hold (min_release_age "0d"): the history a later hold needs is kept anyway.
        let kept = retire(&prev, &[], None, now);
        assert_eq!(kept.len(), 2, "{kept:?}");
    }

    #[test]
    fn candidates_order_newest_first_listed_before_dropped() {
        let a = entry("p", "1", 10, "Q1a=");
        let b = entry("p", "1-dup", 10, "Q1b=");
        let c = entry("p", "2", 20, "Q1c=");
        let cached = Cached {
            entries: vec![a, c],
            retired: vec![b],
            ..Cached::default()
        };
        let by = candidates(&cached, |e| e.version == "2");
        let v: Vec<_> = by["p"]
            .iter()
            .map(|(e, d)| (e.version.as_str(), *d))
            .collect();
        assert_eq!(v, [("1", false), ("1-dup", true)]);
    }

    #[test]
    fn package_identity_hashes_the_control_segment() {
        let (pkg, identity) = package("demo", b"payload");
        assert_eq!(package_identity(&pkg).unwrap(), identity);
        // An unsigned package starts with its control segment.
        let unsigned = {
            let (_, len) = gzip_member(&pkg, 1 << 20).unwrap();
            pkg[len..].to_vec()
        };
        assert_eq!(package_identity(&unsigned).unwrap(), identity);
        assert!(package_identity(b"not gzip").is_err());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use super::tests::*;
    use crate::config::{CurationMode, RepoProxyEntry};
    use crate::digest_quarantine::QuarantineMode;
    use crate::test_helpers::*;
    use axum::http::{Method, StatusCode};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const INDEX: &str = "/alpine/v3.22/main/x86_64/APKINDEX.tar.gz";

    async fn mount(server: &MockServer, at: &str, body: Vec<u8>) {
        Mock::given(method("GET"))
            .and(path(at))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(server)
            .await;
    }

    async fn served(ctx: &TestContext, keys_cfg: &crate::config::ApkConfig) -> Vec<super::Entry> {
        let resp = send(
            &ctx.app,
            Method::GET,
            "/apk/alpine/v3.22/main/x86_64/APKINDEX.tar.gz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        // Clients verify it with NORA's public key: open it as an upstream index of that key.
        let own = super::keys(keys_cfg).unwrap();
        let mut trusted = std::collections::HashMap::new();
        trusted.insert(keys_cfg.key_name.clone(), own.signer.to_public_key());
        let (_, text) = super::open_upstream_index(&body, &trusted).unwrap();
        super::parse_apkindex(&text)
    }

    #[tokio::test]
    async fn holds_young_versions_back_and_falls_back_to_a_cached_older_one() {
        let up_keys = key_files("alpine-test.rsa.pub");
        let own_keys = key_files("nora-test.rsa.pub");
        let signer = upstream_signer(&up_keys, &own_keys);
        let now = now();
        let (lib1, lib1_id) = package("lib", b"one");
        let (lib2, lib2_id) = package("lib", b"two");
        let (tool, tool_id) = package("tool", b"tool");
        let (young, young_id) = package("young", b"young");
        let server = MockServer::start().await;
        mount(
            &server,
            INDEX,
            upstream_index(
                &signer,
                &[
                    super::tests::entry("lib", "1-r0", now - 30 * DAY, &lib1_id),
                    super::tests::entry("tool", "1-r0", now - 30 * DAY, &tool_id),
                    super::tests::entry("young", "1-r0", now - DAY, &young_id),
                ],
            ),
        )
        .await;
        mount(
            &server,
            "/alpine/v3.22/main/x86_64/lib-1-r0.apk",
            lib1.clone(),
        )
        .await;
        mount(
            &server,
            "/alpine/v3.22/main/x86_64/tool-1-r0.apk",
            tool.clone(),
        )
        .await;
        mount(&server, "/alpine/v3.22/main/x86_64/young-1-r0.apk", young).await;

        let mut cfg_apk = config(&up_keys, &own_keys);
        cfg_apk.metadata_ttl = 0;
        cfg_apk.proxies.insert(
            "alpine".into(),
            RepoProxyEntry::Simple(format!("{}/alpine", server.uri())),
        );
        let apk = cfg_apk.clone();
        let ctx = create_test_context_with_config(|cfg| {
            cfg.apk = apk;
            cfg.curation.mode = CurationMode::Enforce;
            cfg.curation.apk.min_release_age = Some("3d".into());
            cfg.curation.apk.quarantine = Some(QuarantineMode::Observe);
            cfg.curation.apk.quarantine_ttl = Some("3d".into());
        });

        let names: Vec<_> = served(&ctx, &cfg_apk)
            .await
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, ["lib", "tool"], "young-1-r0 is held back");
        let get = |file: &str| format!("/apk/alpine/v3.22/main/x86_64/{file}");
        let resp = send(&ctx.app, Method::GET, &get("young-1-r0.apk"), "").await;
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "a held version is refused on download"
        );
        let resp = send(&ctx.app, Method::GET, &get("lib-1-r0.apk"), "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await, lib1);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // The upstream replaces lib 1-r0 with a young 2-r0 and deletes 1-r0, and adds a
        // package NORA never cached a version of.
        server.reset().await;
        mount(
            &server,
            INDEX,
            upstream_index(
                &signer,
                &[
                    super::tests::entry("lib", "2-r0", now - DAY, &lib2_id),
                    super::tests::entry("tool", "2-r0", now - DAY, &tool_id),
                ],
            ),
        )
        .await;
        mount(&server, "/alpine/v3.22/main/x86_64/lib-2-r0.apk", lib2).await;
        let served_now = served(&ctx, &cfg_apk).await;
        let v: Vec<_> = served_now
            .iter()
            .map(|e| (e.name.as_str(), e.version.as_str()))
            .collect();
        assert_eq!(
            v,
            [("lib", "1-r0")],
            "lib falls back to the cached 1-r0; tool has nothing deliverable"
        );
        let resp = send(&ctx.app, Method::GET, &get("lib-1-r0.apk"), "").await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "served from the cache, gone upstream"
        );
        assert_eq!(body_bytes(resp).await, lib1);
        let resp = send(&ctx.app, Method::GET, &get("lib-2-r0.apk"), "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let resp = send(&ctx.app, Method::GET, &get("other-1-r0.apk"), "").await;
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "only files an index lists"
        );
    }

    #[tokio::test]
    async fn serves_a_flat_repository() {
        // apk.corretto.aws: `<arch>/APKINDEX.tar.gz` at the root, no branch or repo.
        let up_keys = key_files("alpine-test.rsa.pub");
        let own_keys = key_files("nora-test.rsa.pub");
        let signer = upstream_signer(&up_keys, &own_keys);
        let (jdk, jdk_id) = package("jdk", b"jdk");
        let server = MockServer::start().await;
        let entries = [super::tests::entry(
            "jdk",
            "17-r0",
            now() - 30 * DAY,
            &jdk_id,
        )];
        mount(
            &server,
            "/x86_64/APKINDEX.tar.gz",
            upstream_index(&signer, &entries),
        )
        .await;
        mount(&server, "/x86_64/jdk-17-r0.apk", jdk.clone()).await;

        let mut cfg_apk = config(&up_keys, &own_keys);
        cfg_apk
            .proxies
            .insert("corretto".into(), RepoProxyEntry::Simple(server.uri()));
        let apk = cfg_apk.clone();
        let ctx = create_test_context_with_config(|cfg| cfg.apk = apk);

        let resp = send(
            &ctx.app,
            Method::GET,
            "/apk/corretto/x86_64/APKINDEX.tar.gz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let own = super::keys(&cfg_apk).unwrap();
        let mut trusted = std::collections::HashMap::new();
        trusted.insert(cfg_apk.key_name.clone(), own.signer.to_public_key());
        let (_, text) = super::open_upstream_index(&body_bytes(resp).await, &trusted).unwrap();
        assert_eq!(super::parse_apkindex(&text)[0].name, "jdk");
        let resp = send(
            &ctx.app,
            Method::GET,
            "/apk/corretto/x86_64/jdk-17-r0.apk",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await, jdk);
        let resp = send(
            &ctx.app,
            Method::GET,
            "/apk/corretto/.x/APKINDEX.tar.gz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn refuses_a_package_off_its_identity_and_an_unverified_index() {
        let up_keys = key_files("alpine-test.rsa.pub");
        let own_keys = key_files("nora-test.rsa.pub");
        let signer = upstream_signer(&up_keys, &own_keys);
        let now = now();
        let (_, id) = package("lib", b"one");
        // Another build: its control segment (with the data hash) differs.
        let (other, _) = package("lib-rebuilt", b"swapped");
        let server = MockServer::start().await;
        mount(
            &server,
            INDEX,
            upstream_index(
                &signer,
                &[super::tests::entry("lib", "1-r0", now - 30 * DAY, &id)],
            ),
        )
        .await;
        mount(&server, "/alpine/v3.22/main/x86_64/lib-1-r0.apk", other).await;
        // The other branch is signed by a key NORA does not trust.
        let stranger = key_files("alpine-test.rsa.pub");
        let stranger = upstream_signer(&stranger, &own_keys);
        mount(
            &server,
            "/alpine/edge/main/x86_64/APKINDEX.tar.gz",
            upstream_index(&stranger, &[]),
        )
        .await;

        let mut apk = config(&up_keys, &own_keys);
        apk.proxies.insert(
            "alpine".into(),
            RepoProxyEntry::Simple(format!("{}/alpine", server.uri())),
        );
        let ctx = create_test_context_with_config(|cfg| cfg.apk = apk);
        let resp = send(
            &ctx.app,
            Method::GET,
            "/apk/alpine/v3.22/main/x86_64/lib-1-r0.apk",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let resp = send(
            &ctx.app,
            Method::GET,
            "/apk/alpine/edge/main/x86_64/APKINDEX.tar.gz",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        for uri in [
            "/apk/other/v3.22/main/x86_64/APKINDEX.tar.gz",
            "/apk/alpine/.x/main/x86_64/APKINDEX.tar.gz",
            "/apk/alpine/v3.22/main/x86_64/x.tar",
        ] {
            assert_eq!(
                send(&ctx.app, Method::GET, uri, "").await.status(),
                StatusCode::NOT_FOUND,
                "{uri}"
            );
        }
    }

    #[tokio::test]
    async fn serves_the_public_key_by_its_name() {
        let up_keys = key_files("alpine-test.rsa.pub");
        let own_keys = key_files("nora-test.rsa.pub");
        let apk = config(&up_keys, &own_keys);
        let expected =
            std::fs::read_to_string(own_keys.0.path().join("pub/x86_64/nora-test.rsa.pub"))
                .unwrap();
        let ctx = create_test_context_with_config(|cfg| cfg.apk = apk);
        let resp = send(&ctx.app, Method::GET, "/apk/keys/nora-test.rsa.pub", "").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_bytes(resp).await, expected.as_bytes());
        let resp = send(&ctx.app, Method::GET, "/apk/keys/other.rsa.pub", "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
