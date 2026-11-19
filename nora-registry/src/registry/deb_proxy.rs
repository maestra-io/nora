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
//! The upstream `InRelease` must carry an unexpired signature by an unexpired, unrevoked
//! signing key of the repository's keyring (`deb.upstream_keyrings`, else
//! `deb.upstream_keyring_dir`) and name the requested suite; each `Packages` file is fetched as that Release names it and refused on another SHA-256.
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
use pgp::composed::{CleartextSignedMessage, Deserializable, SignedPublicKey, SignedPublicSubKey};
use pgp::packet::{PublicKey, Signature, SignatureType, SubpacketData};
use pgp::types::{KeyDetails, Tag, Timestamp};
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

/// Every usable public key (see `usable_key`) in the keyring file `path`, or in the
/// files of the directory `path` (`*.gpg`, `*.pgp`, `*.asc`; binary keyrings or armored).
fn load_keyring(path: &str) -> Result<Vec<SignedPublicKey>, String> {
    if path.is_empty() {
        return Err("deb.upstream_keyring_dir is not set".into());
    }
    let meta = std::fs::metadata(path).map_err(|e| format!("deb keyring {path}: {e}"))?;
    let mut paths = if meta.is_dir() {
        let entries = std::fs::read_dir(path).map_err(|e| format!("deb keyring {path}: {e}"))?;
        entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
                matches!(ext, "gpg" | "pgp" | "asc")
            })
            .collect()
    } else {
        vec![std::path::PathBuf::from(path)]
    };
    paths.sort();
    let mut keys = Vec::new();
    for path in paths {
        let data = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let (iter, _) = SignedPublicKey::from_reader_many(std::io::Cursor::new(data))
            .map_err(|e| format!("{}: {e}", path.display()))?;
        for key in iter {
            let key = key.map_err(|e| format!("{}: {e}", path.display()))?;
            let fingerprint = key.fingerprint().to_string();
            match usable_key(key) {
                Ok(key) => keys.push(key),
                Err(why) => tracing::warn!(
                    file = %path.display(),
                    fingerprint,
                    why,
                    "deb proxy: upstream key left out of the keyring"
                ),
            }
        }
    }
    if keys.is_empty() {
        return Err(format!("deb keyring {path}: no keys"));
    }
    Ok(keys)
}

/// `key` with only its signing subkeys, as gpgv/apt would use it: refused when a
/// revocation self-signature verifies, or when neither the primary key nor a subkey
/// may sign. Expiry depends on the time and is checked in `verify_inrelease`.
fn usable_key(mut key: SignedPublicKey) -> Result<SignedPublicKey, &'static str> {
    let primary = key.primary_key.clone();
    if key
        .details
        .revocation_signatures
        .iter()
        .any(|s| s.verify_key(&primary).is_ok())
    {
        return Err("revoked");
    }
    key.public_subkeys
        .retain(|sub| subkey_binding(&primary, sub).is_some());
    if key.public_subkeys.is_empty() && !self_signature(&key).is_some_and(may_sign) {
        return Err("neither the key nor a subkey may sign");
    }
    Ok(key)
}

/// The newest valid self-signature of the primary key (user-id certification or
/// direct-key signature). Third-party certifications are skipped, never failed on.
fn self_signature(key: &SignedPublicKey) -> Option<&Signature> {
    let primary = &key.primary_key;
    let certs = key.details.users.iter().flat_map(|u| {
        u.signatures.iter().filter(move |s| {
            s.typ() != Some(SignatureType::CertRevocation)
                && s.verify_certification(primary, Tag::UserId, &u.id).is_ok()
        })
    });
    let direct = (key.details.direct_signatures.iter()).filter(|s| s.verify_key(primary).is_ok());
    certs.chain(direct).max_by_key(|s| s.created())
}

/// The newest valid binding of a signing subkey (sign flag and a valid back-signature),
/// or none when a subkey revocation verifies.
fn subkey_binding<'a>(primary: &PublicKey, sub: &'a SignedPublicSubKey) -> Option<&'a Signature> {
    let valid: Vec<_> = (sub.signatures.iter())
        .filter(|s| s.verify_subkey_binding(primary, &sub.key).is_ok())
        .collect();
    if valid
        .iter()
        .any(|s| s.typ() == Some(SignatureType::SubkeyRevocation))
    {
        return None;
    }
    valid.into_iter().max_by_key(|s| s.created()).filter(|s| {
        s.key_flags().sign()
            && s.embedded_signature()
                .is_some_and(|b| b.verify_primary_key_binding(&sub.key, primary).is_ok())
    })
}

/// Whether a self-signature lets the primary key sign: the sign flag, or (as gpg) no
/// key-flags subpacket at all.
fn may_sign(sig: &Signature) -> bool {
    let flagged = sig.config().is_some_and(|c| {
        c.hashed_subpackets()
            .any(|p| matches!(p.data, SubpacketData::KeyFlags(_)))
    });
    !flagged || sig.key_flags().sign()
}

/// Whether `validity` (zero or none: forever) after `created` has passed at `now`. A
/// signature without a creation time counts as expired.
fn expired(created: Option<Timestamp>, validity: Option<pgp::types::Duration>, now: u64) -> bool {
    let Some(created) = created else { return true };
    validity.is_some_and(|v| {
        v.as_secs() > 0 && u64::from(created.as_secs()) + u64::from(v.as_secs()) <= now
    })
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

/// The text of a clearsigned `InRelease`, with LF line ends, when one of its signatures
/// is unexpired and verifies with a key of `keys` that may sign and is unexpired: the
/// primary key per its newest self-signature, a subkey per its newest binding and the
/// primary key's.
fn verify_inrelease(body: &[u8], keys: &[SignedPublicKey]) -> Result<String, String> {
    let text = std::str::from_utf8(body).map_err(|_| "InRelease is not UTF-8".to_string())?;
    let (msg, _) =
        CleartextSignedMessage::from_string(text).map_err(|e| format!("InRelease: {e}"))?;
    let signed = msg.signed_text();
    let now = crate::cache_ttl::now_unix();
    let data = signed.as_bytes();
    let ok = msg.signatures().iter().any(|sig| {
        !expired(sig.created(), sig.signature_expiration_time(), now)
            && keys.iter().any(|k| {
                // An expired primary key expires its subkeys too, as in gpgv (review R11).
                let live = self_signature(k).filter(|s| {
                    !expired(
                        Some(k.primary_key.created_at()),
                        s.key_expiration_time(),
                        now,
                    )
                });
                let Some(live) = live else { return false };
                let by_primary = sig.verify(&k.primary_key, data).is_ok() && may_sign(live);
                by_primary
                    || k.public_subkeys.iter().any(|sub| {
                        sig.verify(&sub.key, data).is_ok()
                            && subkey_binding(&k.primary_key, sub).is_some_and(|b| {
                                let created = Some(sub.key.created_at());
                                !expired(created, b.key_expiration_time(), now)
                            })
                    })
            })
    });
    if !ok {
        return Err(
            "InRelease has no unexpired signature by an unexpired signing key of the keyring"
                .into(),
        );
    }
    Ok(signed.replace("\r\n", "\n"))
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

/// Date `current` from `prev` (its `seen`, else its `retired`; a file not seen before:
/// `now`, or 0 when there is no previous ledger), and keep from `dropped` + `prev.retired` what may still be served.
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
            // A re-listed file NORA had dropped keeps its date: one stale upstream answer
            // must not make a known version new (audit A048).
            Some(p) => p
                .seen
                .get(&s.filename)
                .copied()
                .or_else(|| {
                    p.retired
                        .iter()
                        .find(|r| r.filename == s.filename)
                        .map(|r| r.first_seen)
                })
                .unwrap_or(now),
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
    /// The upstream Release `Date` (unix seconds) of the build: an older one is refused.
    #[serde(default)]
    upstream_date: Option<i64>,
}

/// Held versions per index: filename → (name, version, first_seen).
type Young = BTreeMap<String, BTreeMap<String, (String, String, i64)>>;

/// `Ok(None)`: no such object. A storage error or bytes that do not parse are an `Err`
/// naming the key (logged): a hold or a date must not be read as absent.
async fn read_json<T: for<'de> Deserialize<'de>>(
    state: &AppState,
    key: &str,
) -> Result<Option<T>, String> {
    let read = match state.storage.get(key).await {
        Ok(data) => serde_json::from_slice(&data)
            .map(Some)
            .map_err(|e| e.to_string()),
        Err(crate::storage::StorageError::NotFound) => return Ok(None),
        Err(e) => Err(e.to_string()),
    };
    read.map_err(|e| {
        tracing::error!(key, error = %e, "deb proxy: cannot read a state object (docs/deb-proxy.md: delete it to rebuild)");
        format!("{key}: {e}")
    })
}

async fn get_json<T: for<'de> Deserialize<'de>>(state: &AppState, key: &str) -> Option<T> {
    read_json(state, key).await.ok().flatten()
}

/// A Release `Date` in unix seconds. Debian and Ubuntu write `... UTC`, which RFC 2822
/// does not name.
fn release_date(rel: &Release) -> Option<i64> {
    let date = rel.field("Date")?;
    let date = match date.strip_suffix(" UTC") {
        Some(d) => format!("{d} +0000"),
        None => date.to_string(),
    };
    chrono::DateTime::parse_from_rfc2822(&date)
        .ok()
        .map(|d| d.timestamp())
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
    let keys = keyring(state.config.deb.keyring_for(repo)).map_err(BuildError::Internal)?;
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
    // A signed Release of another suite is not this suite (apt only warns). A Release
    // naming no suite matches, as in apt; a configured alias (Ubuntu `devel`) may name
    // its current target (review R12).
    let (named_suite, codename) = (rel.field("Suite"), rel.field("Codename"));
    if (named_suite.is_some() || codename.is_some())
        && named_suite != Some(suite)
        && codename != Some(suite)
        && !state.config.deb.is_suite_alias(repo, suite)
    {
        return Err(BuildError::Refused(format!(
            "{suite}: the upstream Release is for Suite {:?} / Codename {:?}",
            rel.field("Suite"),
            rel.field("Codename")
        )));
    }
    // An older generation, however validly signed, is not served over a newer one
    // (audit A048, A086). Without a parsable Date there is nothing to compare.
    let upstream_date = release_date(&rel);
    // A served Date past the clock (plus skew) is not compared: it would refuse every
    // later Release until then (review R05).
    let served_date = (current.and_then(|c| c.upstream_date))
        .filter(|&d| d <= now + crate::cache_ttl::MAX_UPSTREAM_CLOCK_SKEW_SECS);
    if let (Some(new), Some(old)) = (upstream_date, served_date) {
        if new < old {
            return Err(BuildError::Refused(format!(
                "{suite}: the upstream Release Date {:?} is older than the served build's",
                rel.field("Date")
            )));
        }
    }
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
    // Upstream copy (when changed) and ledger of each index, written once the holds are.
    let mut ledgers_out = Vec::new();
    // Indexes the upstream did not host this time: their holds stay (audit A049).
    let mut skipped: HashSet<String> = HashSet::new();
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
        // Only an absent ledger is a first sight: an unreadable one would date everything
        // 0 and release every hold of the index (audit A043).
        let prev: Option<Ledger> = read_json(state, &lkey)
            .await
            .map_err(BuildError::Internal)?;
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
                        skipped.insert(format!("{suite}/{comp}/{arch}"));
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
            // An index's first build dates what it lists 0 ("before NORA") unless another
            // ledger already dates the file; later builds backdate their young files.
            let first = prev.is_none();
            let wanted: HashSet<String> = current_st
                .iter()
                .chain(&retired)
                .filter(|s| first || now - s.first_seen < age)
                .map(|s| s.filename.clone())
                .collect();
            // This build's earlier indexes count as rewritten, though written only later.
            let pending = |k: &String| ledgers_out.iter().any(|(_, _, p, _)| p == k);
            let others: Vec<String> = (ledgers.iter())
                .filter(|k| **k != lkey && !pending(k))
                .cloned()
                .collect();
            let mut earliest = earliest_seen(state, &others, &wanted)
                .await
                .map_err(BuildError::Internal)?;
            for (_, _, k, l) in &ledgers_out {
                if ledgers.contains(k) {
                    merge_dates(&mut earliest, l, &wanted);
                }
            }
            for s in current_st.iter_mut().chain(retired.iter_mut()) {
                if let Some(&t) = earliest.get(&s.filename) {
                    if first || t < s.first_seen {
                        s.first_seen = t;
                        if let Some(v) = seen.get_mut(&s.filename) {
                            *v = t;
                        }
                    }
                }
            }
        }

        let hidden = |s: &Stanza| held_until(engine, &s.name, &s.version, s.first_seen, min_age);
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
        // Only a hold that matures later: a permanent one or a time already past would
        // rebuild the suite on every request (audit A042).
        if let Some(t) = matures.filter(|&t| t > now && t < i64::MAX) {
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
        let ledger = Ledger {
            upstream: Some((path.clone(), hash)),
            seen,
            retired,
        };
        ledgers_out.push((ukey, (!unchanged).then_some(data), lkey, ledger));
    }

    if files.is_empty() {
        return Err(BuildError::Upstream(ProxyError::NotFound));
    }
    // Held versions first, so a direct package fetch is refused before apt can see them.
    // Added to the current holds only: until the ledgers below are written, the old ones
    // still date what a dropped hold covered (audit A044).
    update_young(
        state,
        repo,
        suite,
        young.clone(),
        &skipped,
        min_age,
        now,
        true,
    )
    .await
    .map_err(BuildError::Internal)?;
    // Then the ledgers: a date the download gate reads always has its hold committed, a
    // build failing earlier leaves its new files undated (audit A044).
    for (ukey, data, lkey, ledger) in ledgers_out {
        if let Some(data) = data {
            state
                .storage
                .put(&ukey, &data)
                .await
                .map_err(|e| BuildError::Internal(e.to_string()))?;
        }
        put_json(state, &lkey, &ledger)
            .await
            .map_err(BuildError::Internal)?;
    }
    // The download gate's dated files follow the ledgers this build wrote; only then may
    // the holds they no longer date go.
    state.deb_dated.lock().remove(repo);
    update_young(state, repo, suite, young, &skipped, min_age, now, false)
        .await
        .map_err(BuildError::Internal)?;
    if let Err(e) = dated(state, repo).await {
        tracing::warn!(repo, error = %e, "deb proxy: dated pool files not reloaded");
    }

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
        upstream_date: upstream_date.or(served_date),
    };
    put_json(state, &state_key, &new_state)
        .await
        .map_err(BuildError::Internal)?;
    clear_served(state, repo, &served)
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

/// Until when curation hides a version first seen at `first_seen` from the indexes:
/// `None` served, `Some(t)` a release-age hold maturing at `t`, `Some(i64::MAX)` a rule
/// on its name or version (internal namespace, blocklist, allowlist) that never matures
/// (audit A042, A045).
fn held_until(
    engine: &crate::curation::CurationEngine,
    name: &str,
    version: &str,
    first_seen: i64,
    min_age: Option<i64>,
) -> Option<i64> {
    if engine.hides_from_metadata(RegistryType::Deb, name, version, Some(first_seen)) {
        return Some(first_seen + min_age.unwrap_or(0));
    }
    // The chain runs the namespace filter first, in every mode.
    engine
        .refuses(RegistryType::Deb, name, version, Some(first_seen))
        .then_some(i64::MAX)
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
        // None: listed, then replaced or removed meanwhile: nothing to date from.
        let Some(ledger) = read_json::<Ledger>(state, key).await? else {
            continue;
        };
        merge_dates(&mut earliest, &ledger, files);
    }
    Ok(earliest)
}

/// Fold the dates `ledger` gives `files` into `earliest`.
fn merge_dates(earliest: &mut HashMap<String, i64>, ledger: &Ledger, files: &HashSet<String>) {
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

/// Commit a build's holds of `suite`. With `merge` they are only added to the current ones:
/// the ledgers that drop a hold's date are not written yet, so no hold may go (audit A044).
#[allow(clippy::too_many_arguments)]
async fn update_young(
    state: &AppState,
    repo: &str,
    suite: &str,
    held: BTreeMap<String, BTreeMap<String, (String, String, i64)>>,
    skipped: &HashSet<String>,
    min_age: Option<i64>,
    since: i64,
    merge: bool,
) -> Result<(), String> {
    let key = young_key(repo);
    let lock = state.publish_lock(&key);
    let _g = lock.lock().await;
    // An unreadable set fails the build: rewritten from empty it would drop every other
    // suite's holds (audit A043, A049).
    let mut young: Young = read_json(state, &key).await?.unwrap_or_default();
    let mut held = held;
    if merge {
        for (k, files) in std::mem::take(&mut held) {
            if !files.is_empty() {
                young.entry(k).or_default().extend(files);
            }
        }
    } else {
        let prefix = format!("{suite}/");
        young.retain(|k, _| !k.starts_with(&prefix) || skipped.contains(k));
    }
    if !merge && min_age.is_some() {
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
                    // Held for a rule on its name or version whatever its age.
                    held_until(engine, name, version, *seen, min_age).is_some()
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

/// After a suite is published: a file it serves is not held by another index's later
/// sighting of it, apt finds it in this suite's index. Serving it took a ledger date
/// older than `min_release_age` and no rule on its name.
async fn clear_served(
    state: &AppState,
    repo: &str,
    served: &HashSet<String>,
) -> Result<(), String> {
    let key = young_key(repo);
    let lock = state.publish_lock(&key);
    let _g = lock.lock().await;
    let mut young: Young = read_json(state, &key).await?.unwrap_or_default();
    let before: usize = young.values().map(BTreeMap::len).sum();
    for files in young.values_mut() {
        files.retain(|f, _| !served.contains(f));
    }
    young.retain(|_, files| !files.is_empty());
    if young.values().map(BTreeMap::len).sum::<usize>() == before {
        return Ok(());
    }
    put_json(state, &key, &young).await?;
    state
        .deb_young
        .lock()
        .insert(key, (Instant::now(), Arc::new(young)));
    Ok(())
}

/// The held set; on a read error the last one read, however old, else `Err`.
async fn load_young(state: &AppState, repo: &str) -> Result<Arc<Young>, String> {
    let key = young_key(repo);
    let cached = state.deb_young.lock().get(&key).cloned();
    if let Some((at, y)) = &cached {
        if at.elapsed() < YOUNG_TTL {
            return Ok(y.clone());
        }
    }
    let y: Arc<Young> = match read_json(state, &key).await {
        Ok(y) => Arc::new(y.unwrap_or_default()),
        Err(e) => return cached.map(|(_, y)| y).ok_or(e),
    };
    state
        .deb_young
        .lock()
        .insert(key, (Instant::now(), y.clone()));
    Ok(y)
}

/// Every pool file a ledger of `repo` dates (listed or retired). The cached set is reused
/// for `YOUNG_TTL`, then only while the ledger listing is unchanged: another process's
/// build can drop a date as well as add one.
// ponytail: one in-memory set of every ledgered filename per repository (Ubuntu main +
// universe is ~10^5 names, a few tens of MiB); an on-disk filename index if that grows.
async fn dated(state: &AppState, repo: &str) -> Result<Arc<HashSet<String>>, String> {
    let usable = || {
        let cached = state.deb_dated.lock().get(repo).cloned();
        match &cached {
            Some((at, _, files)) if at.elapsed() < YOUNG_TTL => Ok(files.clone()),
            _ => Err(cached),
        }
    };
    if let Ok(files) = usable() {
        return Ok(files);
    }
    // One reload per repository at a time: a burst of downloads after a restart parses the
    // ledgers once.
    let lock = state.publish_lock(&format!("{}/dated", meta(repo)));
    let _g = lock.lock().await;
    let cached = match usable() {
        Ok(files) => return Ok(files),
        Err(cached) => cached,
    };
    let listing: Vec<(String, u64, u64)> = state
        .storage
        .list_with_meta(&format!("{}/ledger/", meta(repo)))
        .await
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|(k, m)| (k, m.size, m.modified))
        .collect();
    if let Some((_, seen, files)) = cached {
        if seen == listing {
            state
                .deb_dated
                .lock()
                .insert(repo.to_string(), (Instant::now(), listing, files.clone()));
            return Ok(files);
        }
    }
    let mut files = HashSet::new();
    for (key, ..) in &listing {
        let Some(ledger) = read_json::<Ledger>(state, key).await? else {
            continue;
        };
        files.extend(ledger.seen.into_keys());
        files.extend(ledger.retired.into_iter().map(|s| s.filename));
    }
    let files = Arc::new(files);
    state
        .deb_dated
        .lock()
        .insert(repo.to_string(), (Instant::now(), listing, files.clone()));
    // The holds are read again, none older than these ledgers: an older set is no fallback,
    // it may lack the hold of a file they now date.
    state.deb_young.lock().remove(&young_key(repo));
    Ok(files)
}

/// What NORA knows of a pool file across every `[deb.proxies]` repository: one pool can be
/// served through an entry other than the one whose suites list it.
enum Sighting {
    Held(String, String, i64),
    Dated,
    Undated,
}

/// The requesting repository decides a file it knows (its index may serve a file another
/// entry still holds); otherwise any other repository's hold, then the date of one with
/// the same upstream. `Err`: a hold set that cannot be read.
async fn sighting(state: &AppState, repo: &str, path: &str) -> Result<Sighting, String> {
    let proxies = &state.config.deb.proxies;
    let upstream = |r: &str| proxies.get(r).map(|u| u.url().trim_end_matches('/'));
    let others: Vec<&str> = (state.config.deb.proxies.keys())
        .map(String::as_str)
        .filter(|r| *r != repo)
        .collect();
    for repos in [&[repo][..], &others] {
        // Dates before holds: a build commits its holds before its ledgers, so the holds
        // read next cover every date read here.
        let mut dates = false;
        for r in repos {
            // A date vouches only for the bytes of its own upstream: another can serve
            // different ones under the same pool path. An unreadable ledger dates nothing.
            if upstream(r) == upstream(repo) {
                dates |= (dated(state, r).await).is_ok_and(|f| f.contains(path));
            }
        }
        for r in repos {
            if let Some((name, version, first_seen)) = load_young(state, r)
                .await?
                .values()
                .find_map(|m| m.get(path))
            {
                return Ok(Sighting::Held(name.clone(), version.clone(), *first_seen));
            }
        }
        if dates {
            return Ok(Sighting::Dated);
        }
    }
    Ok(Sighting::Undated)
}

/// Name and version of a pool `.deb` of a configured architecture or `all`; `None` for
/// any other file (`.udeb`, other architectures), which keeps the first-sight rule.
fn judged_package<'a>(path: &'a str, archs: &[String]) -> Option<(&'a str, &'a str)> {
    let file = path.rsplit('/').next()?.strip_suffix(".deb")?;
    let mut parts = file.splitn(3, '_');
    let (name, version, arch) = (parts.next()?, parts.next()?, parts.next()?);
    (arch == "all" || archs.iter().any(|a| a == arch)).then_some((name, version))
}

/// Refresh every suite NORA has built, of every repository, at once (each under its
/// `metadata_ttl`, waiting at most `STALE_AFTER` on one with a previous build).
async fn refresh_built_suites(state: &AppState) {
    let mut refreshes = Vec::new();
    for (repo, up) in &state.config.deb.proxies {
        let Ok(keys) = state.storage.list(&format!("{}/dists/", meta(repo))).await else {
            continue;
        };
        for key in keys {
            let suite = key
                .strip_prefix(&format!("{}/dists/", meta(repo)))
                .and_then(|k| k.strip_suffix("/state.json"));
            if let Some(suite) = suite.filter(|s| valid_token(s)).map(str::to_string) {
                refreshes.push(async move {
                    let _ = ensure_suite(state, repo, up, &suite).await;
                });
            }
        }
    }
    futures::future::join_all(refreshes).await;
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

/// The curation check of a package download, by the file's date (audit A044): a version
/// any repository holds is refused (403 in enforce, logged in audit); one a ledger dates
/// passes; a `.deb` of a configured architecture or `all` that no ledger dates, even after
/// the built suites are refreshed, is judged by `[curation.deb] unknown_date`.
pub(crate) async fn package_gate(
    state: &AppState,
    headers: &HeaderMap,
    repo: &str,
    path: &str,
) -> Option<Response> {
    let mut found = sighting(state, repo, path).await;
    let mut judged = None;
    if matches!(found, Ok(Sighting::Undated)) {
        judged = judged_package(path, &state.config.deb.architectures).filter(|_| {
            state
                .curation()
                .curation_engine
                .reads_release_date(RegistryType::Deb)
        });
        if judged.is_some() {
            refresh_built_suites(state).await;
            found = sighting(state, repo, path).await;
        }
    }
    let (name, version, date) = match found {
        // Unknown holds: no download passes (audit A043).
        Err(_) => {
            return Some(
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [(header::RETRY_AFTER, "30")],
                )
                    .into_response(),
            )
        }
        Ok(Sighting::Held(name, version, first_seen)) => (name, version, Some(first_seen)),
        Ok(Sighting::Dated) => return None,
        Ok(Sighting::Undated) => {
            let (name, version) = judged?;
            tracing::warn!(repo, path, "[AUDIT] deb: undated pool file");
            let date =
                state
                    .curation()
                    .curation_engine
                    .judged_release_date(RegistryType::Deb, true, None);
            (name.to_string(), version.to_string(), date)
        }
    };
    let engine = &state.curation().curation_engine;
    crate::curation::check_download(
        engine,
        state.bypass_token().as_deref(),
        headers,
        RegistryType::Deb,
        &name,
        crate::curation::RequestVersion::Known(version),
        date,
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

    /// audit A048: a file NORA dropped and the upstream lists again keeps its date.
    #[test]
    fn a_relisted_file_keeps_its_retired_date() {
        let prev = Ledger {
            upstream: None,
            seen: [("pool/main/a_1_amd64.deb".to_string(), 1000)].into(),
            retired: vec![st("a", "2", 0)],
        };
        let mut cur = vec![st("a", "2", 0)];
        let (seen, _) = update_ledger(Some(&prev), &mut cur, vec![], Some(3 * DAY), 50 * DAY);
        assert_eq!(seen["pool/main/a_2_amd64.deb"], 0);
        assert_eq!(cur[0].first_seen, 0);
    }

    #[test]
    fn a_release_date_parses_with_utc_or_an_offset() {
        let date = |d: &str| release_date(&parse_release(&format!("Origin: X\nDate: {d}\n")));
        assert_eq!(date("Thu, 01 Jan 1970 00:01:00 UTC"), Some(60));
        assert_eq!(date("Thu, 01 Jan 1970 01:01:00 +0100"), Some(60));
        assert_eq!(date("yesterday"), None);
        assert_eq!(release_date(&parse_release("Origin: X\n")), None);
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
        mount_suite_comps(server, key, suite, &[(comp, stanzas)], delay).await;
    }

    /// `mount_suite` with one amd64 index per component.
    async fn mount_suite_comps(
        server: &MockServer,
        key: &SignedSecretKey,
        suite: &str,
        comps: &[(&str, &[(&str, &str)])],
        delay: std::time::Duration,
    ) {
        mount_dated(server, key, suite, DATE, comps, delay).await;
    }

    /// The Release `Date` of every generation the helpers publish.
    const DATE: &str = "Tue, 03 Nov 2026 00:00:00 UTC";

    /// `mount_suite_comps` whose Release carries `date`.
    async fn mount_dated(
        server: &MockServer,
        key: &SignedSecretKey,
        suite: &str,
        date: &str,
        comps: &[(&str, &[(&str, &str)])],
        delay: std::time::Duration,
    ) {
        let names = format!("Suite: {suite}\nCodename: bookworm\n");
        mount_release(server, key, suite, &names, date, comps, delay).await;
    }

    /// `mount_dated` whose Release carries the `Suite`/`Codename` lines `names`.
    async fn mount_release(
        server: &MockServer,
        key: &SignedSecretKey,
        suite: &str,
        names: &str,
        date: &str,
        comps: &[(&str, &[(&str, &str)])],
        delay: std::time::Duration,
    ) {
        let mut sums = String::new();
        let mut files = Vec::new();
        for (comp, stanzas) in comps {
            let text: String = stanzas.iter().map(|(n, v)| stanza(n, v) + "\n").collect();
            let packages = gz(text.as_bytes());
            sums.push_str(&format!(
                " {} {} {comp}/binary-amd64/Packages.gz\n {} 0 {comp}/binary-i386/Packages.gz\n",
                super::sha256_hex(&packages),
                packages.len(),
                super::sha256_hex(b""),
            ));
            files.push((
                format!("/dists/{suite}/{comp}/binary-amd64/Packages.gz"),
                packages,
            ));
        }
        let comp_names: Vec<&str> = comps.iter().map(|(c, _)| *c).collect();
        let release = format!(
            "Origin: Test\n{names}Date: {date}\nArchitectures: amd64 i386\nComponents: {}\nSigned-By: ABCDEF\nSHA256:\n{sums}",
            comp_names.join(" "),
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
        for (at, packages) in files {
            mount(at, packages).await;
        }
        for (n, v) in comps.iter().flat_map(|(_, s)| s.iter()) {
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

    /// The gate looks the pool path up as written, and the upstream URL parser cuts it at an
    /// encoded `#` or `?`: such a path is refused before the gate and the upstream, so the
    /// held file is never fetched under another name.
    #[tokio::test]
    async fn held_package_path_with_encoded_hash_or_query_is_refused() {
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
            cfg.curation.deb.min_release_age = Some("3d".into());
        });
        served(&ctx).await;
        publish(&server, &key, &[("a", "2")]).await;
        served(&ctx).await;
        let held = "/deb/debian/pool/main/a_2_amd64.deb";
        let resp = send(&ctx.app, Method::GET, held, "").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "control");
        for suffix in ["%23.deb", "%3Fv=1.deb", "%3F", "%20"] {
            let uri = format!("{held}{suffix}");
            let resp = send(&ctx.app, Method::GET, &uri, "").await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{uri}");
        }
        let asked: Vec<String> = upstream_paths(&server).await;
        assert!(
            !asked.iter().any(|p| p.starts_with("/pool/main/a_2")),
            "{asked:?}"
        );
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

    /// A filtered repo `debian` (min_release_age 3d, enforce) and a pool-only `pool` on the
    /// same upstream; `unknown_date` for deb as given.
    fn undated_ctx(
        uri: String,
        keydir: &tempfile::TempDir,
        ttl: i64,
        unknown: Option<crate::config::UnknownDate>,
    ) -> TestContext {
        undated_ctx_at(uri.clone(), uri, keydir, ttl, unknown)
    }

    /// `undated_ctx` with `pool` proxying `pool_uri`.
    fn undated_ctx_at(
        uri: String,
        pool_uri: String,
        keydir: &tempfile::TempDir,
        ttl: i64,
        unknown: Option<crate::config::UnknownDate>,
    ) -> TestContext {
        let dir = keydir.path().to_str().unwrap().to_string();
        create_test_context_with_config(move |cfg| {
            cfg.deb.enabled = true;
            cfg.deb.metadata_ttl = ttl;
            cfg.deb.upstream_keyring_dir = dir;
            cfg.deb
                .proxies
                .insert("debian".into(), RepoProxyEntry::Simple(uri.clone()));
            cfg.deb
                .proxies
                .insert("pool".into(), RepoProxyEntry::Simple(pool_uri));
            cfg.curation.mode = CurationMode::Enforce;
            cfg.curation.deb.min_release_age = Some("3d".into());
            cfg.curation.deb.quarantine = Some(QuarantineMode::Observe);
            cfg.curation.deb.unknown_date = unknown;
        })
    }

    async fn mount_pool(server: &MockServer, files: &[&str]) {
        for f in files {
            Mock::given(method("GET"))
                .and(path(format!("/pool/main/{f}")))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(f.as_bytes().to_vec()))
                .mount(server)
                .await;
        }
    }

    /// A044: a version published after NORA's last look at a suite is dated by a refresh
    /// on its download and held, through the repo whose suite lists it and through
    /// another entry serving the same pool; a file a ledger dates passes through both.
    #[tokio::test]
    async fn an_undated_pool_file_of_a_tracked_suite_is_refused() {
        let (key, keydir) = upstream_key();
        let server = MockServer::start().await;
        publish(&server, &key, &[("a", "1")]).await;
        let ctx = undated_ctx(server.uri(), &keydir, 0, None);
        served(&ctx).await;
        publish(&server, &key, &[("a", "2")]).await;
        mount_pool(&server, &["a_1_amd64.deb"]).await;
        let get = |p: &'static str| send(&ctx.app, Method::GET, p, "");
        let status = |p: &'static str| async move { get(p).await.status() };
        assert_eq!(
            status("/deb/debian/pool/main/a_2_amd64.deb").await,
            StatusCode::FORBIDDEN,
            "the suite was not asked for since a 2 appeared"
        );
        assert_eq!(
            status("/deb/debian/pool/main/a_1_amd64.deb").await,
            StatusCode::OK
        );
        assert_eq!(
            status("/deb/pool/pool/main/a_2_amd64.deb").await,
            StatusCode::FORBIDDEN,
            "another entry's hold applies to the same pool"
        );
        assert_eq!(
            status("/deb/pool/pool/main/a_1_amd64.deb").await,
            StatusCode::OK,
            "another entry's ledger dates it"
        );
        // Once `pool`'s own suite has listed a 2 for 4 days, its index serves it: its own
        // date decides over `debian`'s hold.
        let ledger = super::Ledger {
            upstream: None,
            seen: [("pool/main/a_2_amd64.deb".to_string(), 0)].into(),
            retired: Vec::new(),
        };
        let lkey = super::ledger_key("pool", "updates", "main", "amd64");
        super::put_json(&ctx.state, &lkey, &ledger).await.unwrap();
        ctx.state.deb_dated.lock().remove("pool");
        assert_eq!(
            status("/deb/pool/pool/main/a_2_amd64.deb").await,
            StatusCode::OK,
            "the requesting entry's own date decides"
        );
    }

    /// A044: a `.deb` of a configured architecture or `all` that no ledger dates after the
    /// refresh is judged by `unknown_date`: `hold` refuses it, `log` serves and counts it;
    /// `.udeb` and other architectures keep the first-sight rule.
    #[tokio::test]
    async fn an_undated_pool_file_is_judged_by_unknown_date() {
        let (key, keydir) = upstream_key();
        let server = MockServer::start().await;
        publish(&server, &key, &[("a", "1")]).await;
        mount_pool(
            &server,
            &[
                "z_1_amd64.deb",
                "x_1_all.deb",
                "n_1_i386.deb",
                "d_1_amd64.udeb",
            ],
        )
        .await;
        let hold = undated_ctx(
            server.uri(),
            &keydir,
            3600,
            Some(crate::config::UnknownDate::Hold),
        );
        served(&hold).await;
        let status = |ctx: &TestContext, p: &str| {
            let (app, p) = (ctx.app.clone(), p.to_string());
            async move { send(&app, Method::GET, &p, "").await.status() }
        };
        for (p, want) in [
            ("/deb/debian/pool/main/z_1_amd64.deb", StatusCode::FORBIDDEN),
            ("/deb/pool/pool/main/x_1_all.deb", StatusCode::FORBIDDEN),
            ("/deb/debian/pool/main/a_1_amd64.deb", StatusCode::OK),
            ("/deb/debian/pool/main/n_1_i386.deb", StatusCode::OK),
            ("/deb/debian/pool/main/d_1_amd64.udeb", StatusCode::OK),
        ] {
            assert_eq!(status(&hold, p).await, want, "{p}");
        }

        let log = undated_ctx(server.uri(), &keydir, 3600, None);
        let counter =
            crate::metrics::CURATION_UNKNOWN_RELEASE_DATE_TOTAL.with_label_values(&["deb"]);
        let before = counter.get();
        assert_eq!(
            status(&log, "/deb/debian/pool/main/z_1_amd64.deb").await,
            StatusCode::OK
        );
        assert!(counter.get() > before, "a logged undated file is counted");
    }

    /// A044: a build that fails before it commits its holds leaves the new versions it read
    /// undated, so they are judged by `unknown_date`, never passed as dated.
    #[tokio::test]
    async fn a_failed_build_dates_nothing_it_did_not_hold() {
        let (key, keydir) = upstream_key();
        let server = MockServer::start().await;
        publish(&server, &key, &[("a", "1")]).await;
        let ctx = undated_ctx(
            server.uri(),
            &keydir,
            0,
            Some(crate::config::UnknownDate::Hold),
        );
        served(&ctx).await;
        publish(&server, &key, &[("a", "2")]).await;
        // An unreadable hold set fails the next build when it commits its holds.
        let ykey = super::young_key("debian");
        let young = ctx.state.storage.get(&ykey).await.unwrap();
        ctx.state.storage.put(&ykey, b"{").await.unwrap();
        ctx.state.deb_young.lock().clear();
        let up = ctx.state.config.deb.proxies["debian"].clone();
        let _ = super::refresh_suite(&ctx.state, "debian", &up, "bookworm", false).await;
        ctx.state.storage.put(&ykey, &young).await.unwrap();
        ctx.state.deb_young.lock().clear();
        ctx.state.deb_dated.lock().clear();
        // The upstream index is gone: the download's refresh cannot date it either.
        server.reset().await;
        mount_pool(&server, &["a_2_amd64.deb"]).await;
        let res = send(
            &ctx.app,
            Method::GET,
            "/deb/debian/pool/main/a_2_amd64.deb",
            "",
        )
        .await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    /// Every cache entry of `map` read `YOUNG_TTL` ago or earlier.
    fn age<K, A, B>(map: &mut std::collections::HashMap<K, (std::time::Instant, A, B)>) {
        let long_ago = std::time::Instant::now()
            .checked_sub(super::YOUNG_TTL * 2)
            .unwrap();
        for e in map.values_mut() {
            e.0 = long_ago;
        }
    }

    /// A044: a date another process's build dropped does not outlive `YOUNG_TTL` here.
    #[tokio::test]
    async fn a_dropped_date_leaves_the_cache() {
        let (key, keydir) = upstream_key();
        let server = MockServer::start().await;
        publish(&server, &key, &[("a", "1")]).await;
        let hold = Some(crate::config::UnknownDate::Hold);
        let ctx = undated_ctx(server.uri(), &keydir, 3600, hold);
        served(&ctx).await;
        mount_pool(&server, &["a_1_amd64.deb"]).await;
        let p = "/deb/debian/pool/main/a_1_amd64.deb";
        assert_eq!(
            send(&ctx.app, Method::GET, p, "").await.status(),
            StatusCode::OK
        );
        let lkey = super::ledger_key("debian", "bookworm", "main", "amd64");
        super::put_json(&ctx.state, &lkey, &super::Ledger::default())
            .await
            .unwrap();
        age(&mut ctx.state.deb_dated.lock());
        assert_eq!(
            send(&ctx.app, Method::GET, p, "").await.status(),
            StatusCode::FORBIDDEN
        );
    }

    /// A044: a build failing after it committed its holds keeps the holds its old ledgers
    /// still date, though its new listing drops the package.
    #[tokio::test]
    async fn a_build_failing_before_its_ledgers_keeps_the_old_holds() {
        let (key, keydir) = upstream_key();
        let server = MockServer::start().await;
        publish(&server, &key, &[("a", "1")]).await;
        let hold = Some(crate::config::UnknownDate::Hold);
        let ctx = undated_ctx(server.uri(), &keydir, 0, hold);
        served(&ctx).await;
        let up = ctx.state.config.deb.proxies["debian"].clone();
        publish(&server, &key, &[("a", "1"), ("a", "2")]).await;
        super::refresh_suite(&ctx.state, "debian", &up, "bookworm", false)
            .await
            .unwrap();
        publish(&server, &key, &[("b", "1")]).await;
        // The upstream copy cannot be written: the build fails after its holds.
        let ukey = super::upstream_copy_key("debian", "bookworm", "main", "amd64");
        ctx.state.storage.delete(&ukey).await.unwrap();
        ctx.state
            .storage
            .put(&format!("{ukey}/x"), b"")
            .await
            .unwrap();
        let _ = super::refresh_suite(&ctx.state, "debian", &up, "bookworm", false).await;
        mount_pool(&server, &["a_2_amd64.deb"]).await;
        let p = "/deb/debian/pool/main/a_2_amd64.deb";
        assert_eq!(
            send(&ctx.app, Method::GET, p, "").await.status(),
            StatusCode::FORBIDDEN
        );
    }

    /// A044: ledgers that newly date a file are never paired with an older hold set read
    /// before them: with the holds unreadable, the download waits.
    #[tokio::test]
    async fn new_dates_never_fall_back_on_older_holds() {
        let (key, keydir) = upstream_key();
        let server = MockServer::start().await;
        publish(&server, &key, &[("a", "1")]).await;
        let ctx = undated_ctx(server.uri(), &keydir, 3600, None);
        served(&ctx).await;
        let file = "pool/main/a_2_amd64.deb";
        let lkey = super::ledger_key("debian", "bookworm", "main", "amd64");
        let mut ledger: super::Ledger = super::read_json(&ctx.state, &lkey).await.unwrap().unwrap();
        ledger
            .seen
            .insert(file.to_string(), chrono::Utc::now().timestamp());
        super::put_json(&ctx.state, &lkey, &ledger).await.unwrap();
        let ykey = super::young_key("debian");
        ctx.state.storage.put(&ykey, b"{").await.unwrap();
        age(&mut ctx.state.deb_dated.lock());
        mount_pool(&server, &["a_2_amd64.deb"]).await;
        let res = send(&ctx.app, Method::GET, &format!("/deb/debian/{file}"), "").await;
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// A044: another entry's date does not date a file of a different upstream: the same
    /// pool path may name other bytes there.
    #[tokio::test]
    async fn another_upstreams_date_does_not_date_a_file() {
        let (key, keydir) = upstream_key();
        let server = MockServer::start().await;
        let other = MockServer::start().await;
        publish(&server, &key, &[("a", "1")]).await;
        let hold = Some(crate::config::UnknownDate::Hold);
        let ctx = undated_ctx_at(server.uri(), other.uri(), &keydir, 3600, hold);
        served(&ctx).await;
        mount_pool(&server, &["a_1_amd64.deb"]).await;
        mount_pool(&other, &["a_1_amd64.deb"]).await;
        let status = |p: &'static str| {
            let app = ctx.app.clone();
            async move { send(&app, Method::GET, p, "").await.status() }
        };
        assert_eq!(
            status("/deb/debian/pool/main/a_1_amd64.deb").await,
            StatusCode::OK
        );
        assert_eq!(
            status("/deb/pool/pool/main/a_1_amd64.deb").await,
            StatusCode::FORBIDDEN
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

        // updates has listed k 2 for 4 days (its ledger says so): apt sees it there, and
        // once updates is published the file is served.
        let old = crate::cache_ttl::now_unix() as i64 - 4 * 86_400;
        let ledger = super::Ledger {
            upstream: None,
            seen: [("pool/main/k_2_amd64.deb".to_string(), old)].into(),
            retired: Vec::new(),
        };
        let updates = super::ledger_key("debian", "updates", "main", "amd64");
        super::put_json(&ctx.state, &updates, &ledger)
            .await
            .unwrap();
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
        let l1 = "/deb/debian/pool/main/l_1_amd64.deb";
        assert_eq!(
            get(l1).await.status(),
            StatusCode::FORBIDDEN,
            "a file no suite has listed for 3 days is still held"
        );

        // A suite new to NORA lists l 1 and n 1: n 1 predates NORA, l 1 is dated by the
        // ledger that already knows it, so it is neither served nor released.
        mount_suite(
            &server,
            &key,
            "backports",
            "main",
            &[("l", "1"), ("n", "1")],
            z,
        )
        .await;
        let (_, pkgs) = served_in(&ctx, "backports", "main").await;
        assert_eq!(pkgs, [("n".into(), "1".into())]);
        assert_eq!(get(l1).await.status(), StatusCode::FORBIDDEN);
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
        let age = Some(3 * 86_400);
        // Read before the build started (since = later): the hold stays.
        let none = std::collections::HashSet::new();
        super::update_young(
            state,
            "debian",
            "security",
            held(now),
            &none,
            age,
            now + 3600,
            false,
        )
        .await
        .unwrap();
        let young = super::load_young(state, "debian").await.unwrap();
        assert!(young["security/main/amd64"].contains_key(&f));
        // Written during the build: the hold goes, but not the one on an internal name.
        super::update_young(
            state,
            "debian",
            "security",
            held(now),
            &none,
            age,
            now,
            false,
        )
        .await
        .unwrap();
        let young = super::load_young(state, "debian").await.unwrap();
        let files = &young["security/main/amd64"];
        assert!(!files.contains_key(&f), "{files:?}");
        assert!(files.contains_key(&corp), "{files:?}");
    }

    /// A filtered `debian` proxy of `server`, enforcing, with `customize` on top.
    fn rule_ctx(
        server: &MockServer,
        keydir: &tempfile::TempDir,
        customize: impl FnOnce(&mut crate::config::Config),
    ) -> TestContext {
        let uri = server.uri();
        let dir = keydir.path().to_str().unwrap().to_string();
        create_test_context_with_config(move |cfg| {
            cfg.deb.enabled = true;
            cfg.deb.upstream_keyring_dir = dir;
            cfg.deb
                .proxies
                .insert("debian".into(), RepoProxyEntry::Simple(uri));
            cfg.curation.mode = CurationMode::Enforce;
            customize(cfg);
        })
    }

    async fn suite_state(ctx: &TestContext) -> super::SuiteState {
        super::get_json(
            &ctx.state,
            &super::suite_key("debian", "bookworm", "state.json"),
        )
        .await
        .unwrap()
    }

    /// audit A042: a hold on a name never matures, so it gives the suite no maturity time
    /// and the suite is reused for metadata_ttl.
    #[tokio::test]
    async fn a_permanent_hold_does_not_rebuild_the_suite_on_every_request() {
        for age in ["3d", "0d"] {
            let (key, keydir) = upstream_key();
            let server = MockServer::start().await;
            publish(&server, &key, &[("corp-x", "1"), ("a", "1")]).await;
            let ctx = rule_ctx(&server, &keydir, |cfg| {
                cfg.deb.metadata_ttl = 300;
                cfg.curation.deb.min_release_age = Some(age.into());
                cfg.curation.internal_namespaces = vec!["corp-*".to_string()];
            });
            let (_, pkgs) = served(&ctx).await;
            assert_eq!(pkgs, [("a".into(), "1".into())], "{age}");
            assert_eq!(suite_state(&ctx).await.matures_at, None, "{age}");
            let inrelease = super::suite_key("debian", "bookworm", "InRelease");
            let signed = ctx.state.storage.get(&inrelease).await.unwrap();
            for _ in 0..2 {
                let at = "/deb/debian/dists/bookworm/InRelease";
                assert_eq!(status(&ctx, at).await, StatusCode::OK);
            }
            let fetched = upstream_paths(&server)
                .await
                .into_iter()
                .filter(|p| p == "/dists/bookworm/InRelease")
                .count();
            assert_eq!(fetched, 1, "{age}: one build within metadata_ttl");
            assert_eq!(ctx.state.storage.get(&inrelease).await.unwrap(), signed);
        }
    }

    /// audit A042: an age hold still sets a maturity time, in the future and within
    /// min_release_age.
    #[tokio::test]
    async fn an_age_hold_still_matures_the_suite() {
        let (key, keydir) = upstream_key();
        let server = MockServer::start().await;
        publish(&server, &key, &[("corp-x", "1"), ("a", "1")]).await;
        let ctx = rule_ctx(&server, &keydir, |cfg| {
            cfg.deb.metadata_ttl = 0;
            cfg.curation.deb.min_release_age = Some("3d".into());
            cfg.curation.internal_namespaces = vec!["corp-*".to_string()];
        });
        served(&ctx).await;
        publish(&server, &key, &[("corp-x", "2"), ("a", "2")]).await;
        let now = crate::cache_ttl::now_unix() as i64;
        served(&ctx).await;
        let t = suite_state(&ctx).await.matures_at.expect("a 2 is held");
        assert!(t > now && t <= now + 3 * 86_400 + 5, "{t} vs {now}");
    }

    fn rules_file(dir: &tempfile::TempDir, file: &str, body: &str) -> String {
        let path = dir.path().join(file);
        std::fs::write(&path, body).unwrap();
        path.to_str().unwrap().to_string()
    }

    /// audit A045: a blocklisted version is held whatever its age or allow exemption: it is
    /// not listed, not stood in for a held version, and its download is refused.
    #[tokio::test]
    async fn the_blocklist_holds_old_and_allow_exempt_versions() {
        let (key, keydir) = upstream_key();
        let server = MockServer::start().await;
        publish(&server, &key, &[("evil", "1"), ("bad", "1"), ("a", "1")]).await;
        let rules = tempfile::tempdir().unwrap();
        let blocklist = rules_file(
            &rules,
            "blocklist.json",
            r#"{"version": 1, "rules": [
                {"registry": "deb", "name": "bad", "version": "*", "reason": "test"},
                {"registry": "*", "name": "evil*", "version": "*", "reason": "test"}]}"#,
        );
        let ctx = rule_ctx(&server, &keydir, |cfg| {
            cfg.deb.metadata_ttl = 0;
            cfg.curation.deb.min_release_age = Some("3d".into());
            cfg.curation.deb.allow = vec!["bad".into()];
            cfg.curation.blocklist_path = Some(blocklist);
        });
        let (_, pkgs) = served(&ctx).await;
        assert_eq!(pkgs, [("a".into(), "1".into())], "first sight");
        let pool = |n: &str, v: &str| format!("/deb/debian/pool/main/{n}_{v}_amd64.deb");
        for (n, v) in [("evil", "1"), ("bad", "1")] {
            let resp = send(&ctx.app, Method::GET, &pool(n, v), "").await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{n} {v}");
            let body = String::from_utf8_lossy(&body_bytes(resp).await).to_string();
            assert!(body.contains("blocklist"), "{body}");
        }
        assert_eq!(status(&ctx, &pool("a", "1")).await, StatusCode::OK);

        // evil 1 was cached before the rule: it does not stand in for the held evil 2.
        let cached = "deb/debian/pool/main/evil_1_amd64.deb";
        ctx.state.storage.put(cached, b"evil-1").await.unwrap();
        publish(&server, &key, &[("evil", "2"), ("bad", "2"), ("a", "2")]).await;
        let now = crate::cache_ttl::now_unix() as i64;
        let (_, pkgs) = served(&ctx).await;
        assert!(
            !pkgs.iter().any(|(n, _)| n == "evil" || n == "bad"),
            "{pkgs:?}"
        );
        assert_eq!(status(&ctx, &pool("bad", "2")).await, StatusCode::FORBIDDEN);
        assert_eq!(
            status(&ctx, &pool("evil", "1")).await,
            StatusCode::FORBIDDEN
        );
        let t = suite_state(&ctx).await.matures_at.expect("a 2 is held");
        assert!(t > now && t < i64::MAX, "{t}");
    }

    /// audit A045: under an allowlist an unlisted version is held and refused.
    #[tokio::test]
    async fn the_allowlist_holds_unlisted_versions() {
        let (key, keydir) = upstream_key();
        let server = MockServer::start().await;
        publish(&server, &key, &[("a", "1"), ("b", "1")]).await;
        let rules = tempfile::tempdir().unwrap();
        let allowlist = rules_file(
            &rules,
            "allowlist.json",
            r#"{"version": 1, "entries": [{"registry": "deb", "name": "a", "version": "1"}]}"#,
        );
        let ctx = rule_ctx(&server, &keydir, |cfg| {
            cfg.deb.metadata_ttl = 300;
            cfg.curation.deb.min_release_age = Some("3d".into());
            cfg.curation.allowlist_path = Some(allowlist);
        });
        let (_, pkgs) = served(&ctx).await;
        assert_eq!(pkgs, [("a".into(), "1".into())]);
        let b1 = "/deb/debian/pool/main/b_1_amd64.deb";
        assert_eq!(status(&ctx, b1).await, StatusCode::FORBIDDEN);
        assert_eq!(suite_state(&ctx).await.matures_at, None);
    }

    /// audit A045: an unfiltered apt proxy judges no .deb by name, so name rules beside it
    /// are a configuration error.
    #[test]
    fn name_rules_need_a_filtered_apt_proxy() {
        let rule_errors = |customize: fn(&mut crate::config::Config)| {
            let mut cfg = crate::config::Config::default();
            cfg.deb.enabled = true;
            let entry = RepoProxyEntry::Simple("https://deb.example".into());
            cfg.deb.proxies.insert("debian".into(), entry);
            customize(&mut cfg);
            let (_, errors) = cfg.validate_with_config_path(None);
            errors
                .into_iter()
                .filter(|e| e.contains("apply to [deb.proxies]"))
                .count()
        };
        assert_eq!(rule_errors(|_| {}), 0);
        assert_eq!(
            rule_errors(|c| c.curation.blocklist_path = Some("b.json".into())),
            1
        );
        assert_eq!(
            rule_errors(|c| c.curation.allowlist_path = Some("a.json".into())),
            1
        );
        assert_eq!(
            rule_errors(|c| c.curation.internal_namespaces = vec!["corp-*".into()]),
            1
        );
        assert_eq!(
            rule_errors(|c| {
                c.curation.internal_namespaces = vec!["corp-*".into()];
                c.curation.deb.min_release_age = Some("0d".into());
            }),
            0,
            "filtered"
        );
        assert_eq!(
            rule_errors(|c| {
                c.curation.internal_namespaces = vec!["corp-*".into()];
                c.deb.enabled = false;
            }),
            0,
            "deb off"
        );
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
        let holders = ctx.state.storage.holders();
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
        crate::test_helpers::background_writes_done(&ctx.state.storage, holders).await;
        let (_, pkgs) = served(&ctx).await;
        assert_eq!(pkgs, [("a".into(), "2".into())]);
    }

    // ── Upstream key policy (audit A050) and repository/suite binding (audit A051) ──

    /// `text` clearsigned by `key`, created at `created`, with extra hashed subpackets.
    fn sign_at(
        text: &str,
        key: &impl pgp::types::SigningKey,
        created: pgp::types::Timestamp,
        extra: Vec<pgp::packet::Subpacket>,
    ) -> CleartextSignedMessage {
        use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
        let mut config =
            SignatureConfig::from_key(rand::thread_rng(), key, SignatureType::Text).unwrap();
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(created)).unwrap(),
            Subpacket::regular(SubpacketData::IssuerFingerprint(key.fingerprint())).unwrap(),
        ];
        config.hashed_subpackets.extend(extra);
        CleartextSignedMessage::new(text, config, key, &Password::empty()).unwrap()
    }

    fn armored(msg: &CleartextSignedMessage) -> String {
        msg.to_armored_string(ArmorOptions::default()).unwrap()
    }

    /// A keyring directory holding `keys`, one file each.
    fn keyring_dir(keys: &[&SignedPublicKey]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (i, k) in keys.iter().enumerate() {
            let text = k.to_armored_string(ArmorOptions::default()).unwrap();
            std::fs::write(dir.path().join(format!("{i}.asc")), text).unwrap();
        }
        dir
    }

    fn load(dir: &tempfile::TempDir) -> Result<Vec<SignedPublicKey>, String> {
        super::load_keyring(dir.path().to_str().unwrap())
    }

    /// The public half of `key` with a key revocation self-signature.
    fn revoked(key: &SignedSecretKey) -> SignedPublicKey {
        use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
        use pgp::types::{KeyDetails, Timestamp};
        let mut public = key.to_public_key();
        let mut cfg =
            SignatureConfig::from_key(rand::thread_rng(), &**key, SignatureType::KeyRevocation)
                .unwrap();
        cfg.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now())).unwrap(),
            Subpacket::regular(SubpacketData::IssuerFingerprint(key.fingerprint())).unwrap(),
        ];
        let rev = cfg
            .sign_key(&**key, &Password::empty(), key.primary_key.public_key())
            .unwrap();
        public.details.revocation_signatures.push(rev);
        public
    }

    /// A signing key created two years ago whose only self-certification grants one day,
    /// and its public half.
    fn expired_key() -> (SignedSecretKey, SignedPublicKey) {
        use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
        use pgp::types::{Duration, KeyDetails, Tag, Timestamp};
        let born = Timestamp::from_secs(Timestamp::now().as_secs() - 730 * 86_400);
        let key = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .can_sign(true)
            .created_at(born)
            .primary_user_id("Expired Archive".into())
            .build()
            .unwrap()
            .generate(rand::thread_rng())
            .unwrap();
        let mut public = key.to_public_key();
        let uid = public.details.users[0].id.clone();
        let mut cfg =
            SignatureConfig::from_key(rand::thread_rng(), &*key, SignatureType::CertPositive)
                .unwrap();
        cfg.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(born)).unwrap(),
            Subpacket::regular(SubpacketData::IssuerFingerprint(key.fingerprint())).unwrap(),
            Subpacket::regular(SubpacketData::KeyExpirationTime(Duration::from_secs(
                86_400,
            )))
            .unwrap(),
        ];
        let cert = cfg
            .sign_certification(
                &*key,
                key.primary_key.public_key(),
                &Password::empty(),
                Tag::UserId,
                &uid,
            )
            .unwrap();
        public.details.users[0].signatures = vec![cert];
        (key, public)
    }

    #[test]
    fn only_an_unexpired_signature_by_a_valid_signing_key_verifies() {
        use pgp::composed::SubkeyParamsBuilder;
        use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
        use pgp::types::{Duration, Tag, Timestamp};
        let text = "Origin: Test\nSuite: stable\n";
        let now = Timestamp::now();
        let verify = |msg: &CleartextSignedMessage, keys: &[SignedPublicKey]| {
            super::verify_inrelease(armored(msg).as_bytes(), keys)
        };

        let (key, keydir) = upstream_key();
        let keys = load(&keydir).unwrap();
        let good = sign_at(text, &*key, now, vec![]);
        assert_eq!(verify(&good, &keys).unwrap(), text, "control");

        // An expired signature, alone and beside a valid one.
        let ten_days_ago = Timestamp::from_secs(now.as_secs() - 10 * 86_400);
        let one_day = Subpacket::regular(SubpacketData::SignatureExpirationTime(
            Duration::from_secs(86_400),
        ))
        .unwrap();
        let stale = sign_at(text, &*key, ten_days_ago, vec![one_day]);
        assert!(verify(&stale, &keys).is_err(), "expired signature");

        // Several signatures: one unexpired signature by a valid key is enough.
        let (expired, expired_pub) = expired_key();
        let by_expired = sign_at(text, &*expired, now, vec![]);
        let both = CleartextSignedMessage::new_many(text, |_| {
            Ok(vec![
                by_expired.signatures()[0].clone(),
                good.signatures()[0].clone(),
            ])
        })
        .unwrap();
        let mut with_expired = keys.clone();
        with_expired.extend(load(&keyring_dir(&[&expired_pub])).unwrap());
        assert!(verify(&both, &with_expired).is_ok(), "one valid signer");

        // A key past its expiry.
        assert!(verify(&by_expired, &with_expired).is_err(), "expired key");

        // A revoked key is left out of the keyring; alone it leaves no key.
        let (rkey, _) = upstream_key();
        let rdir = keyring_dir(&[&revoked(&rkey), &key.to_public_key()]);
        let rkeys = load(&rdir).unwrap();
        assert_eq!(rkeys.len(), 1);
        assert!(
            verify(&sign_at(text, &*rkey, now, vec![]), &rkeys).is_err(),
            "revoked key"
        );
        let err = load(&keyring_dir(&[&revoked(&rkey)])).unwrap_err();
        assert!(err.ends_with("no keys"), "{err}");

        // A subkey whose only flag is authentication does not sign for the key.
        let with_sub = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .can_sign(true)
            .primary_user_id("Sub Archive".into())
            .subkey(
                SubkeyParamsBuilder::default()
                    .key_type(KeyType::Ed25519Legacy)
                    .can_authenticate(true)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap()
            .generate(rand::thread_rng())
            .unwrap();
        let skeys = load(&keyring_dir(&[&with_sub.to_public_key()])).unwrap();
        assert!(skeys[0].public_subkeys.is_empty());
        let by_sub = sign_at(text, &with_sub.secret_subkeys[0].key, now, vec![]);
        assert!(
            verify(&by_sub, &skeys).is_err(),
            "authentication-only subkey"
        );

        // A third-party certification of the user id does not drop the key.
        let (other, _) = upstream_key();
        let mut certified = key.to_public_key();
        let uid = certified.details.users[0].id.clone();
        let cert =
            SignatureConfig::from_key(rand::thread_rng(), &*other, SignatureType::CertGeneric)
                .unwrap()
                .sign_certification_third_party(
                    &*other,
                    &Password::empty(),
                    &certified.primary_key,
                    Tag::UserId,
                    &uid,
                )
                .unwrap();
        certified.details.users[0].signatures.push(cert);
        assert!(
            certified.verify_bindings().is_err(),
            "a whole-key check would drop it"
        );
        let ckeys = load(&keyring_dir(&[&certified])).unwrap();
        assert!(verify(&good, &ckeys).is_ok(), "third-party certification");
    }

    /// review R11: a signing subkey of an expired primary key does not verify, even
    /// when its own binding never expires.
    #[test]
    fn a_subkey_of_an_expired_primary_key_does_not_verify() {
        use pgp::composed::SubkeyParamsBuilder;
        use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
        use pgp::types::{Duration, KeyDetails, Tag, Timestamp};
        let text = "Origin: Test\nSuite: stable\n";
        let born = Timestamp::from_secs(Timestamp::now().as_secs() - 730 * 86_400);
        let key = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .can_sign(false)
            .can_certify(true)
            .created_at(born)
            .primary_user_id("Archive".into())
            .subkey(
                SubkeyParamsBuilder::default()
                    .key_type(KeyType::Ed25519Legacy)
                    .can_sign(true)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap()
            .generate(rand::thread_rng())
            .unwrap();
        let by_sub = sign_at(text, &key.secret_subkeys[0].key, Timestamp::now(), vec![]);
        let verify = |public: &SignedPublicKey| {
            let keys = load(&keyring_dir(&[public])).unwrap();
            super::verify_inrelease(armored(&by_sub).as_bytes(), &keys)
        };
        assert!(verify(&key.to_public_key()).is_ok(), "control");

        // The primary's only self-certification grants one day from its creation.
        let mut expired = key.to_public_key();
        let uid = expired.details.users[0].id.clone();
        let mut cfg =
            SignatureConfig::from_key(rand::thread_rng(), &*key, SignatureType::CertPositive)
                .unwrap();
        cfg.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(born)).unwrap(),
            Subpacket::regular(SubpacketData::IssuerFingerprint(key.fingerprint())).unwrap(),
            Subpacket::regular(SubpacketData::KeyExpirationTime(Duration::from_secs(
                86_400,
            )))
            .unwrap(),
        ];
        let cert = cfg
            .sign_certification(
                &*key,
                key.primary_key.public_key(),
                &Password::empty(),
                Tag::UserId,
                &uid,
            )
            .unwrap();
        expired.details.users[0].signatures = vec![cert];
        assert!(verify(&expired).is_err(), "expired primary key");
    }

    #[test]
    fn a_signing_subkey_verifies_and_a_flagless_primary_signs() {
        use pgp::composed::SubkeyParamsBuilder;
        use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
        use pgp::types::{KeyDetails, Tag, Timestamp};
        let text = "Origin: Test\nSuite: stable\n";
        let key = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .can_sign(false)
            .can_certify(true)
            .primary_user_id("Archive".into())
            .subkey(
                SubkeyParamsBuilder::default()
                    .key_type(KeyType::Ed25519Legacy)
                    .can_sign(true)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap()
            .generate(rand::thread_rng())
            .unwrap();
        let keys = load(&keyring_dir(&[&key.to_public_key()])).unwrap();
        let by_sub = sign_at(text, &key.secret_subkeys[0].key, Timestamp::now(), vec![]);
        assert!(super::verify_inrelease(armored(&by_sub).as_bytes(), &keys).is_ok());
        let by_primary = sign_at(text, &*key, Timestamp::now(), vec![]);
        assert!(
            super::verify_inrelease(armored(&by_primary).as_bytes(), &keys).is_err(),
            "certify-only primary"
        );
        // Without its signing subkey nothing of the key may sign: no key is left.
        let mut bare = key.to_public_key();
        bare.public_subkeys.clear();
        let err = load(&keyring_dir(&[&bare])).unwrap_err();
        assert!(err.ends_with("no keys"), "{err}");

        // The same primary with a self-certification that carries no key flags signs.
        let mut flagless = key.to_public_key();
        flagless.public_subkeys.clear();
        let uid = flagless.details.users[0].id.clone();
        let mut cfg =
            SignatureConfig::from_key(rand::thread_rng(), &*key, SignatureType::CertPositive)
                .unwrap();
        cfg.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now())).unwrap(),
            Subpacket::regular(SubpacketData::IssuerFingerprint(key.fingerprint())).unwrap(),
        ];
        let cert = cfg
            .sign_certification(
                &*key,
                key.primary_key.public_key(),
                &Password::empty(),
                Tag::UserId,
                &uid,
            )
            .unwrap();
        flagless.details.users[0].signatures = vec![cert];
        let keys = load(&keyring_dir(&[&flagless])).unwrap();
        assert!(super::verify_inrelease(armored(&by_primary).as_bytes(), &keys).is_ok());
    }

    /// A filtered proxy context: `repos` (name, upstream), the shared keyring directory
    /// `dir` and the per-repository `keyrings`.
    fn keyring_ctx(
        repos: &[(&str, String)],
        dir: &str,
        keyrings: &[(&str, String)],
    ) -> TestContext {
        let (repos, dir, keyrings) = (repos.to_vec(), dir.to_string(), keyrings.to_vec());
        let repos: Vec<(String, String)> =
            repos.into_iter().map(|(r, u)| (r.to_string(), u)).collect();
        let keyrings: Vec<(String, String)> = keyrings
            .into_iter()
            .map(|(r, k)| (r.to_string(), k))
            .collect();
        create_test_context_with_config(move |cfg| {
            cfg.deb.enabled = true;
            cfg.deb.metadata_ttl = 0;
            cfg.deb.upstream_keyring_dir = dir;
            for (repo, uri) in repos {
                cfg.deb.proxies.insert(repo, RepoProxyEntry::Simple(uri));
            }
            cfg.deb.upstream_keyrings.extend(keyrings);
            cfg.curation.mode = CurationMode::Enforce;
            cfg.curation.deb.min_release_age = Some("0d".into());
        })
    }

    async fn status(ctx: &TestContext, uri: &str) -> StatusCode {
        send(&ctx.app, Method::GET, uri, "").await.status()
    }

    #[tokio::test]
    async fn an_inrelease_signed_only_by_a_revoked_key_is_refused() {
        let (key, keydir) = upstream_key();
        let (rkey, _) = upstream_key();
        std::fs::write(
            keydir.path().join("revoked.asc"),
            revoked(&rkey)
                .to_armored_string(ArmorOptions::default())
                .unwrap(),
        )
        .unwrap();
        let server = MockServer::start().await;
        publish(&server, &rkey, &[("openssl", "9.9")]).await;
        let dir = keydir.path().to_str().unwrap();
        let ctx = keyring_ctx(&[("debian", server.uri())], dir, &[]);
        let uri = "/deb/debian/dists/bookworm/InRelease";
        assert_eq!(status(&ctx, uri).await, StatusCode::BAD_GATEWAY);
        publish(&server, &key, &[("openssl", "9.8")]).await;
        assert_eq!(status(&ctx, uri).await, StatusCode::OK, "control");
    }

    #[tokio::test]
    async fn a_release_of_another_suite_is_refused() {
        let (key, keydir) = upstream_key();
        let server = MockServer::start().await;
        let z = std::time::Duration::ZERO;
        let old: &[(&str, &[(&str, &str)])] = &[("main", &[("openssl", "1.1.1n")])];
        let other = "Suite: oldoldstable\nCodename: buster\n";
        mount_release(&server, &key, "bookworm", other, DATE, old, z).await;
        let ctx = keyring_ctx(
            &[("debian", server.uri())],
            keydir.path().to_str().unwrap(),
            &[],
        );
        let uri = "/deb/debian/dists/bookworm/InRelease";
        assert_eq!(
            status(&ctx, uri).await,
            StatusCode::BAD_GATEWAY,
            "first build"
        );

        // Matched by Suite or by Codename.
        publish(&server, &key, &[("openssl", "3.0")]).await;
        assert_eq!(served(&ctx).await.1, [("openssl".into(), "3.0".into())]);
        server.reset().await;
        let by_suite: &[(&str, &[(&str, &str)])] = &[("main", &[("openssl", "3.1")])];
        let names = "Suite: bookworm\nCodename: other\n";
        mount_release(&server, &key, "bookworm", names, DATE, by_suite, z).await;
        assert_eq!(served(&ctx).await.1, [("openssl".into(), "3.1".into())]);

        // A replayed Release of another suite: the last good build stays served.
        server.reset().await;
        mount_release(&server, &key, "bookworm", other, DATE, old, z).await;
        assert_eq!(served(&ctx).await.1, [("openssl".into(), "3.1".into())]);
    }

    /// review R12: a Release naming no suite builds, as apt accepts it; a configured
    /// alias suite builds from a Release naming its target, an unconfigured one does not.
    #[tokio::test]
    async fn a_nameless_release_and_a_configured_alias_build() {
        let (key, keydir) = upstream_key();
        let server = MockServer::start().await;
        let z = std::time::Duration::ZERO;
        let comps: &[(&str, &[(&str, &str)])] = &[("main", &[("openssl", "3.0")])];
        mount_release(&server, &key, "bookworm", "", DATE, comps, z).await;
        let target = "Suite: tenacious\nCodename: tenacious\n";
        mount_release(&server, &key, "devel", target, DATE, comps, z).await;
        mount_release(&server, &key, "noble", target, DATE, comps, z).await;
        let (uri, dir) = (server.uri(), keydir.path().to_str().unwrap().to_string());
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.deb.enabled = true;
            cfg.deb.metadata_ttl = 0;
            cfg.deb.upstream_keyring_dir = dir;
            cfg.deb
                .proxies
                .insert("debian".into(), RepoProxyEntry::Simple(uri));
            (cfg.deb.suite_aliases).insert("debian".into(), vec!["devel".into()]);
            cfg.curation.mode = CurationMode::Enforce;
            cfg.curation.deb.min_release_age = Some("0d".into());
        });
        assert_eq!(served(&ctx).await.1, [("openssl".into(), "3.0".into())]);
        assert_eq!(
            served_in(&ctx, "devel", "main").await.1,
            [("openssl".into(), "3.0".into())]
        );
        let noble = "/deb/debian/dists/noble/InRelease";
        assert_eq!(
            status(&ctx, noble).await,
            StatusCode::BAD_GATEWAY,
            "not an alias"
        );
    }

    #[tokio::test]
    async fn a_repository_verifies_only_with_its_own_keyring() {
        let (debian_key, _) = upstream_key();
        let (vendor_key, _) = upstream_key();
        let files = tempfile::tempdir().unwrap();
        let file = |name: &str, key: &SignedSecretKey| {
            let at = files.path().join(name);
            let text = key
                .to_public_key()
                .to_armored_string(ArmorOptions::default())
                .unwrap();
            std::fs::write(&at, text).unwrap();
            at.to_str().unwrap().to_string()
        };
        let (debian_ring, vendor_ring) = (
            file("debian.asc", &debian_key),
            file("vendor.pgp", &vendor_key),
        );
        let (debian_up, vendor_up) = (MockServer::start().await, MockServer::start().await);
        publish(&debian_up, &vendor_key, &[("openssl", "9.9")]).await;
        publish(&vendor_up, &vendor_key, &[("tool", "1")]).await;
        let ctx = keyring_ctx(
            &[("debian", debian_up.uri()), ("vendor", vendor_up.uri())],
            "",
            &[("debian", debian_ring), ("vendor", vendor_ring)],
        );
        let at = |repo: &str| format!("/deb/{repo}/dists/bookworm/InRelease");
        assert_eq!(
            status(&ctx, &at("debian")).await,
            StatusCode::BAD_GATEWAY,
            "vendor's key"
        );
        assert_eq!(status(&ctx, &at("vendor")).await, StatusCode::OK);
        publish(&debian_up, &debian_key, &[("openssl", "3.0")]).await;
        assert_eq!(status(&ctx, &at("debian")).await, StatusCode::OK, "own key");
    }

    #[test]
    fn upstream_keyrings_must_load_and_name_a_proxy() {
        let (_, keydir) = upstream_key();
        let dir = keydir.path().to_str().unwrap().to_string();
        let base = || {
            let mut cfg = crate::config::Config::default();
            cfg.deb.enabled = true;
            cfg.curation.deb.min_release_age = Some("0d".into());
            for repo in ["debian", "ubuntu"] {
                let entry = RepoProxyEntry::Simple("https://deb.example".into());
                cfg.deb.proxies.insert(repo.into(), entry);
            }
            cfg
        };
        let keyring_errors = |cfg: &crate::config::Config| {
            let (warnings, errors) = cfg.validate_with_config_path(None);
            let errors: Vec<String> = errors
                .into_iter()
                .filter(|e| e.contains("keyring") || e.contains("upstream_keyrings"))
                .collect();
            (warnings, errors)
        };

        let mut shared = base();
        shared.deb.upstream_keyring_dir = dir.clone();
        let (warnings, errors) = keyring_errors(&shared);
        assert!(errors.is_empty(), "{errors:?}");
        assert!(
            warnings.iter().any(|w| w.contains("deb.upstream_keyrings")),
            "{warnings:?}"
        );

        // Every proxy on its own keyring: the shared directory is not needed.
        let mut own = base();
        for repo in ["debian", "ubuntu"] {
            own.deb.upstream_keyrings.insert(repo.into(), dir.clone());
        }
        let (warnings, errors) = keyring_errors(&own);
        assert!(errors.is_empty(), "{errors:?}");
        assert!(
            !warnings.iter().any(|w| w.contains("deb.upstream_keyrings")),
            "{warnings:?}"
        );

        own.deb
            .upstream_keyrings
            .insert("vendor".into(), dir.clone());
        own.deb
            .upstream_keyrings
            .insert("ubuntu".into(), format!("{dir}/missing.gpg"));
        let (_, errors) = keyring_errors(&own);
        assert_eq!(errors.len(), 2, "{errors:?}");
        assert!(errors
            .iter()
            .any(|e| e.contains("deb.upstream_keyrings.vendor")));
        assert!(errors.iter().any(|e| e.contains("missing.gpg")));

        // review R12: an alias entry must name a proxy too.
        let mut alias = base();
        alias.deb.upstream_keyring_dir = dir.clone();
        alias
            .deb
            .suite_aliases
            .insert("vendor".into(), vec!["devel".into()]);
        let (_, errors) = alias.validate_with_config_path(None);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("deb.suite_aliases.vendor")),
            "{errors:?}"
        );
    }

    // ── Upstream generations (audit A048, A086) and unreadable state (A043, A049) ──

    /// `publish` of a Release dated `date`.
    async fn publish_dated(
        server: &MockServer,
        key: &SignedSecretKey,
        stanzas: &[(&str, &str)],
        date: &str,
    ) {
        server.reset().await;
        let z = std::time::Duration::ZERO;
        mount_dated(server, key, "bookworm", date, &[("main", stanzas)], z).await;
    }

    /// A filtered proxy of `uri` holding 3 days, over `storage`.
    fn held_ctx(
        uri: String,
        dir: &tempfile::TempDir,
        storage: Option<crate::storage::Storage>,
    ) -> TestContext {
        let dir = dir.path().to_str().unwrap().to_string();
        let customize = move |cfg: &mut crate::config::Config| {
            cfg.deb.enabled = true;
            cfg.deb.metadata_ttl = 0;
            cfg.deb.upstream_keyring_dir = dir;
            cfg.deb
                .proxies
                .insert("debian".into(), RepoProxyEntry::Simple(uri));
            cfg.curation.mode = CurationMode::Enforce;
            cfg.curation.deb.min_release_age = Some("3d".into());
        };
        match storage {
            Some(s) => create_test_context_with_storage_and_config(s, customize),
            None => create_test_context_with_config(customize),
        }
    }

    fn pkgs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    /// audit A086: a validly signed Release older than the served build is refused, and
    /// NORA keeps serving (and signing) the newer one.
    #[tokio::test]
    async fn an_older_signed_generation_is_not_served_over_a_newer_one() {
        let (key, keydir) = upstream_key();
        let server = MockServer::start().await;
        let dir = keydir.path().to_str().unwrap();
        let ctx = keyring_ctx(&[("debian", server.uri())], dir, &[]);
        publish_dated(&server, &key, &[("a", "2")], DATE).await;
        assert_eq!(served(&ctx).await.1, pkgs(&[("a", "2")]));

        publish_dated(
            &server,
            &key,
            &[("a", "1")],
            "Wed, 01 Jan 2020 00:00:00 UTC",
        )
        .await;
        let (release, served_now) = served(&ctx).await;
        assert_eq!(served_now, pkgs(&[("a", "2")]));
        assert!(release.contains(&format!("Date: {DATE}\n")), "{release}");

        // A newer one is built; an equal Date too.
        publish_dated(
            &server,
            &key,
            &[("a", "3")],
            "Thu, 05 Nov 2026 00:00:00 +0000",
        )
        .await;
        assert_eq!(served(&ctx).await.1, pkgs(&[("a", "3")]));
        publish_dated(
            &server,
            &key,
            &[("a", "4")],
            "Thu, 05 Nov 2026 00:00:00 +0000",
        )
        .await;
        assert_eq!(served(&ctx).await.1, pkgs(&[("a", "4")]));
    }

    /// review R05: a served Release dated in the future does not refuse the next
    /// Release with a current Date.
    #[tokio::test]
    async fn a_future_release_date_does_not_freeze_the_suite() {
        let (key, keydir) = upstream_key();
        let server = MockServer::start().await;
        let dir = keydir.path().to_str().unwrap();
        let ctx = keyring_ctx(&[("debian", server.uri())], dir, &[]);
        let future = "Mon, 01 Jan 2035 00:00:00 UTC";
        publish_dated(&server, &key, &[("a", "1")], future).await;
        assert_eq!(served(&ctx).await.1, pkgs(&[("a", "1")]));
        publish_dated(&server, &key, &[("a", "2")], DATE).await;
        assert_eq!(served(&ctx).await.1, pkgs(&[("a", "2")]));
        // An older one is still refused.
        let older = "Wed, 01 Jan 2020 00:00:00 UTC";
        publish_dated(&server, &key, &[("a", "0")], older).await;
        assert_eq!(served(&ctx).await.1, pkgs(&[("a", "2")]));
    }

    /// audit A048: one stale upstream answer neither re-dates known versions as new nor
    /// withdraws them.
    #[tokio::test]
    async fn a_stale_generation_does_not_redate_known_versions() {
        let (key, keydir) = upstream_key();
        let server = MockServer::start().await;
        let ctx = held_ctx(server.uri(), &keydir, None);
        let ctx = &ctx;
        let get = |p: String| async move { status(ctx, &p).await };
        let pool = |n: &str, v: &str| format!("/deb/debian/pool/main/{n}_{v}_amd64.deb");
        let gen3: &[(&str, &str)] = &[("a", "2"), ("b", "1"), ("c", "1")];

        publish_dated(&server, &key, gen3, DATE).await;
        assert_eq!(served(ctx).await.1, pkgs(gen3));
        assert_eq!(get(pool("a", "2")).await, StatusCode::OK);

        let older = "Sun, 01 Nov 2026 00:00:00 UTC";
        publish_dated(&server, &key, &[("a", "1"), ("b", "1")], older).await;
        assert_eq!(served(ctx).await.1, pkgs(gen3), "the older generation");

        publish_dated(&server, &key, gen3, DATE).await;
        assert_eq!(served(ctx).await.1, pkgs(gen3));
        assert_eq!(get(pool("a", "2")).await, StatusCode::OK);
        assert_eq!(get(pool("c", "1")).await, StatusCode::OK);

        // Control: a newer generation still holds what is new.
        let newer = "Thu, 05 Nov 2026 00:00:00 UTC";
        let gen4: &[(&str, &str)] = &[("a", "2"), ("b", "1"), ("c", "1"), ("d", "1")];
        publish_dated(&server, &key, gen4, newer).await;
        assert_eq!(served(ctx).await.1, pkgs(gen3));
        assert_eq!(get(pool("d", "1")).await, StatusCode::FORBIDDEN);
    }

    /// audit A043: a ledger NORA cannot read or parse is not a first sight; the build
    /// fails, the last one stays served and its holds stay.
    #[tokio::test]
    async fn an_unreadable_own_ledger_keeps_the_hold() {
        let (key, keydir) = upstream_key();
        let server = MockServer::start().await;
        let (storage, outage) = outage_storage();
        let ctx = held_ctx(server.uri(), &keydir, Some(storage));
        let a2 = "/deb/debian/pool/main/a_2_amd64.deb";
        let lkey = super::ledger_key("debian", "bookworm", "main", "amd64");
        publish(&server, &key, &[("a", "1")]).await;
        served(&ctx).await;
        publish(&server, &key, &[("a", "2")]).await;
        assert_eq!(served(&ctx).await.1, pkgs(&[]));
        assert_eq!(status(&ctx, a2).await, StatusCode::FORBIDDEN);

        // A read error.
        outage.fail_reads_of("/ledger/bookworm/main/amd64.json");
        publish(&server, &key, &[("a", "2"), ("z", "1")]).await;
        assert_eq!(served(&ctx).await.1, pkgs(&[]));
        assert_eq!(status(&ctx, a2).await, StatusCode::FORBIDDEN);
        outage.end();
        served(&ctx).await;
        let ledger: super::Ledger = super::get_json(&ctx.state, &lkey).await.unwrap();
        assert_ne!(ledger.seen["pool/main/a_2_amd64.deb"], 0, "{ledger:?}");
        assert_eq!(status(&ctx, a2).await, StatusCode::FORBIDDEN);

        // Bytes that do not parse.
        ctx.state.storage.put(&lkey, b"not json").await.unwrap();
        publish(&server, &key, &[("a", "2"), ("y", "1")]).await;
        assert_eq!(served(&ctx).await.1, pkgs(&[]));
        assert_eq!(status(&ctx, a2).await, StatusCode::FORBIDDEN);
    }

    /// audit A043: an unreadable hold set is an error, never an empty set: a download
    /// waits (503) unless a set was read before.
    #[tokio::test]
    async fn an_unreadable_hold_set_is_an_error() {
        let ctx = create_test_context_with_config(|cfg| cfg.deb.enabled = true);
        let state = &ctx.state;
        let key = super::young_key("debian");
        state.storage.put(&key, b"not json").await.unwrap();
        let none = std::collections::HashSet::new();
        let held = Default::default();
        assert!(
            super::update_young(state, "debian", "bookworm", held, &none, None, 0, false)
                .await
                .is_err()
        );
        assert!(super::clear_served(state, "debian", &none).await.is_err());
        assert!(super::load_young(state, "debian").await.is_err());
        let file = "pool/main/a_2_amd64.deb";
        let headers = axum::http::HeaderMap::new();
        let gate = super::package_gate(state, &headers, "debian", file).await;
        assert_eq!(gate.unwrap().status(), StatusCode::SERVICE_UNAVAILABLE);

        // A set read before, however old, answers for the unreadable one.
        let young: super::Young = [(
            "bookworm/main/amd64".to_string(),
            [(file.to_string(), ("a".into(), "2".into(), 0))].into(),
        )]
        .into();
        let long_ago = std::time::Instant::now()
            .checked_sub(super::YOUNG_TTL * 2)
            .unwrap();
        let cached = std::sync::Arc::new(young);
        state
            .deb_young
            .lock()
            .insert(key.clone(), (long_ago, cached.clone()));
        assert_eq!(super::load_young(state, "debian").await.unwrap(), cached);
    }

    /// audit A049: an index the upstream did not host this time keeps its holds.
    #[tokio::test]
    async fn a_skipped_index_keeps_its_holds() {
        let (key, keydir) = upstream_key();
        let server = MockServer::start().await;
        let ctx = held_ctx(server.uri(), &keydir, None);
        let z = std::time::Duration::ZERO;
        let r2 = "/deb/debian/pool/main/r_2_amd64.deb";
        let suite = |main: &'static [(&'static str, &'static str)],
                     contrib: &'static [(&'static str, &'static str)]| {
            [("main", main), ("contrib", contrib)]
        };
        mount_suite_comps(
            &server,
            &key,
            "bookworm",
            &suite(&[("a", "1")], &[("r", "1")]),
            z,
        )
        .await;
        served(&ctx).await;
        server.reset().await;
        mount_suite_comps(
            &server,
            &key,
            "bookworm",
            &suite(&[("a", "2")], &[("r", "2")]),
            z,
        )
        .await;
        served(&ctx).await;
        assert_eq!(status(&ctx, r2).await, StatusCode::FORBIDDEN);

        // contrib changes but its index is not there: main is rebuilt, contrib skipped.
        server.reset().await;
        let gen3 = suite(&[("a", "2"), ("z", "1")], &[("r", "2"), ("s", "1")]);
        mount_suite_comps(&server, &key, "bookworm", &gen3, z).await;
        Mock::given(method("GET"))
            .and(path("/dists/bookworm/contrib/binary-amd64/Packages.gz"))
            .respond_with(ResponseTemplate::new(404))
            .with_priority(1)
            .mount(&server)
            .await;
        served(&ctx).await;
        let young: super::Young = super::get_json(&ctx.state, &super::young_key("debian"))
            .await
            .unwrap();
        assert!(
            young["bookworm/contrib/amd64"].contains_key("pool/main/r_2_amd64.deb"),
            "{young:?}"
        );
        assert!(young["bookworm/main/amd64"].contains_key("pool/main/z_1_amd64.deb"));
        assert_eq!(status(&ctx, r2).await, StatusCode::FORBIDDEN);
    }

    /// audit A049: a hold set NORA cannot read or parse fails the build; the other
    /// suites' holds are not dropped and the object is not rewritten.
    #[tokio::test]
    async fn an_unreadable_hold_set_fails_the_build_and_keeps_other_suites() {
        let (key, keydir) = upstream_key();
        let server = MockServer::start().await;
        let (storage, outage) = outage_storage();
        let ctx = held_ctx(server.uri(), &keydir, Some(storage));
        let z = std::time::Duration::ZERO;
        let t2 = "/deb/debian/pool/main/t_2_amd64.deb";
        let ykey = super::young_key("debian");
        let generation = |bookworm: &'static [(&'static str, &'static str)]| {
            let server = &server;
            let key = &key;
            async move {
                server.reset().await;
                mount_suite(server, key, "bookworm", "main", bookworm, z).await;
                mount_suite(server, key, "trixie", "main", &[("t", "2")], z).await;
            }
        };
        mount_suite(&server, &key, "bookworm", "main", &[("a", "1")], z).await;
        mount_suite(&server, &key, "trixie", "main", &[("t", "1")], z).await;
        served_in(&ctx, "bookworm", "main").await;
        served_in(&ctx, "trixie", "main").await;
        generation(&[("a", "2")]).await;
        served_in(&ctx, "bookworm", "main").await;
        served_in(&ctx, "trixie", "main").await;
        assert_eq!(status(&ctx, t2).await, StatusCode::FORBIDDEN);
        let has_t2 = |young: &super::Young| {
            young
                .get("trixie/main/amd64")
                .is_some_and(|m| m.contains_key("pool/main/t_2_amd64.deb"))
        };

        // A read error: bookworm's last build stays served, trixie's hold stays.
        outage.fail_reads_of("/young.json");
        generation(&[("a", "2"), ("z", "1")]).await;
        assert_eq!(served_in(&ctx, "bookworm", "main").await.1, pkgs(&[]));
        outage.end();
        let young: super::Young = super::get_json(&ctx.state, &ykey).await.unwrap();
        assert!(has_t2(&young), "{young:?}");
        assert_eq!(status(&ctx, t2).await, StatusCode::FORBIDDEN);

        // A truncated object: not rewritten.
        let bytes = ctx.state.storage.get(&ykey).await.unwrap();
        let cut = bytes[..bytes.len() / 2].to_vec();
        ctx.state.storage.put(&ykey, &cut).await.unwrap();
        generation(&[("a", "2"), ("y", "1")]).await;
        served_in(&ctx, "bookworm", "main").await;
        assert_eq!(ctx.state.storage.get(&ykey).await.unwrap().to_vec(), cut);
        assert_eq!(status(&ctx, t2).await, StatusCode::FORBIDDEN);
    }
}
