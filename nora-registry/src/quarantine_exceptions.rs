// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Break-glass exceptions to the docker digest quarantine (Maestra fork, issues-maestra#1649).
//!
//! `[docker] quarantine_exceptions` names a TOML file of `[[exception]]` entries, each a
//! `digest`, a `reason` and an RFC 3339 `expires`. An unexpired entry admits that manifest
//! digest, and every digest an admitted manifest names (platform manifests, config,
//! layers), past the quarantine under `observe` and `enforce`. The file is re-read every
//! [`RELOAD_EVERY`]: it is meant to be a ConfigMap mounted as a directory, so a change
//! reaches nora without a restart. A file that breaks a rule (no reason, a malformed or
//! repeated digest, an unparsable expiry, an expiry more than [`MAX_AHEAD_SECS`] after the
//! read) is refused whole: nora keeps the last good list, logs the error and sets
//! `nora_docker_quarantine_exceptions_invalid`. At start there is no last good list, so a
//! bad file means none.

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use parking_lot::{Mutex, RwLock};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// How far ahead of the read an entry may expire.
pub const MAX_AHEAD_SECS: i64 = 7 * 86400;
/// How often the file is re-read.
pub const RELOAD_EVERY: Duration = Duration::from_secs(30);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    exception: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    digest: String,
    reason: String,
    expires: String,
}

/// One accepted entry.
#[derive(Debug, Clone, PartialEq)]
pub struct Exception {
    pub reason: String,
    /// Unix seconds.
    pub expires: i64,
}

fn is_sha256(d: &str) -> bool {
    d.strip_prefix("sha256:").is_some_and(|h| {
        h.len() == 64
            && h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// Parse and check the file read at `now` (unix seconds). Expired entries are kept and
/// never admit anything, so a list that only expired is not an error.
pub fn parse(text: &str, now: i64) -> Result<HashMap<String, Exception>, String> {
    let file: File = toml::from_str(text).map_err(|e| e.to_string())?;
    let mut list = HashMap::new();
    for (i, e) in file.exception.into_iter().enumerate() {
        let at = format!("exception #{} ({})", i + 1, e.digest);
        if !is_sha256(&e.digest) {
            return Err(format!("{at}: digest must be sha256:<64 lowercase hex>"));
        }
        if e.reason.trim().is_empty() {
            return Err(format!("{at}: reason is empty"));
        }
        let expires = DateTime::parse_from_rfc3339(&e.expires)
            .map_err(|err| {
                format!(
                    "{at}: expires {:?} is not RFC 3339 with an offset: {err}",
                    e.expires
                )
            })?
            .timestamp();
        if expires > now + MAX_AHEAD_SECS {
            return Err(format!(
                "{at}: expires {} is more than 7 days after now",
                e.expires
            ));
        }
        let entry = Exception {
            reason: e.reason.trim().to_string(),
            expires,
        };
        if list.insert(e.digest, entry).is_some() {
            return Err(format!("{at}: digest listed twice"));
        }
    }
    Ok(list)
}

/// Held by a test while it reloads or reads the process-global gauges.
#[cfg(test)]
pub static GAUGES: Mutex<()> = Mutex::new(());

/// The live list, swapped whole on a good read.
#[derive(Default)]
pub struct QuarantineExceptions {
    list: ArcSwap<HashMap<String, Exception>>,
    /// A digest an admitted manifest names -> the listed digest that admitted it. Kept only
    /// while that entry is in the list.
    // ponytail: in memory, learned as manifests are served, so a restart forgets it: a client
    // resuming a pull past its manifests gets 403 until they are served again (docs/docker-proxy.md).
    named: RwLock<HashMap<String, String>>,
    /// The bytes of the last read, good or not: an unchanged file is not parsed again.
    last: Mutex<Option<Vec<u8>>>,
}

impl QuarantineExceptions {
    /// The listed digest and its entry that admit `digest` now, if any.
    pub fn covering(&self, digest: &str) -> Option<(String, Exception)> {
        let list = self.list.load();
        let listed = if list.contains_key(digest) {
            digest.to_string()
        } else {
            self.named.read().get(digest)?.clone()
        };
        let entry = list.get(&listed)?;
        (entry.expires > Utc::now().timestamp()).then(|| (listed, entry.clone()))
    }

    /// Admit what `manifest`, admitted by `listed`'s entry, names.
    pub fn admit_named(&self, listed: &str, manifest: &[u8]) {
        let named = crate::registry::docker::named_digests(manifest);
        if named.is_empty() {
            return;
        }
        let mut map = self.named.write();
        for d in named {
            map.insert(d, listed.to_string());
        }
    }

    /// Re-read `path` (start and every [`RELOAD_EVERY`]).
    pub fn reload(&self, path: &str) {
        let now = Utc::now().timestamp();
        let read = std::fs::read(path);
        let active = |list: &HashMap<String, Exception>| {
            list.values().filter(|e| e.expires > now).count() as i64
        };
        let mut last = self.last.lock();
        if let (Ok(bytes), Some(prev)) = (&read, last.as_ref()) {
            if bytes == prev {
                crate::metrics::DOCKER_QUARANTINE_EXCEPTIONS_ACTIVE.set(active(&self.list.load()));
                return;
            }
        }
        let parsed = match &read {
            Ok(bytes) => std::str::from_utf8(bytes)
                .map_err(|e| e.to_string())
                .and_then(|text| parse(text, now)),
            Err(e) => Err(e.to_string()),
        };
        *last = read.ok();
        match parsed {
            Ok(list) => {
                self.named
                    .write()
                    .retain(|_, listed| list.contains_key(listed));
                // The series exists from the load, so an alert on increase() sees the first use.
                for d in list.keys() {
                    crate::metrics::DOCKER_QUARANTINE_EXCEPTION_USED_TOTAL
                        .with_label_values(&[d.as_str()]);
                }
                crate::metrics::DOCKER_QUARANTINE_EXCEPTIONS_ACTIVE.set(active(&list));
                crate::metrics::DOCKER_QUARANTINE_EXCEPTIONS_INVALID.set(0);
                tracing::warn!(
                    path,
                    entries = list.len(),
                    active = active(&list),
                    digests = ?list.keys().collect::<Vec<_>>(),
                    "Quarantine exceptions loaded"
                );
                self.list.store(Arc::new(list));
            }
            Err(e) => {
                crate::metrics::DOCKER_QUARANTINE_EXCEPTIONS_INVALID.set(1);
                tracing::error!(
                    path,
                    error = %e,
                    kept = self.list.load().len(),
                    "Quarantine exceptions file refused, keeping the last good list"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const NOW: i64 = 1_800_000_000; // 2027-01-15T08:00:00Z

    fn file(digest: &str, reason: &str, expires: &str) -> String {
        format!("[[exception]]\ndigest = {digest:?}\nreason = {reason:?}\nexpires = {expires:?}\n")
    }

    #[test]
    fn the_rules_of_an_entry() {
        let ok = parse(&file(D, "CVE fix", "2027-01-20T00:00:00Z"), NOW).unwrap();
        assert_eq!(ok[D].expires, 1_800_403_200);
        assert!(parse("", NOW).unwrap().is_empty());
        // expired: accepted, admits nothing
        assert!(parse(&file(D, "x", "2020-01-01T00:00:00Z"), NOW).is_ok());
        for (text, why) in [
            (file(D, "  ", "2027-01-20T00:00:00Z"), "reason is empty"),
            (
                file("sha256:0123", "x", "2027-01-20T00:00:00Z"),
                "digest must be",
            ),
            (
                file(&D.to_uppercase(), "x", "2027-01-20T00:00:00Z"),
                "digest must be",
            ),
            (
                file("nginx:1.27", "x", "2027-01-20T00:00:00Z"),
                "digest must be",
            ),
            (file(D, "x", "2027-01-20"), "RFC 3339"),
            (file(D, "x", "2027-01-23T08:00:01Z"), "more than 7 days"),
            (
                file(D, "x", "2027-01-20T00:00:00Z").repeat(2),
                "listed twice",
            ),
            (
                format!("{}extra = 1\n", file(D, "x", "2027-01-20T00:00:00Z")),
                "extra",
            ),
            (
                "[[exception]]\ndigest = \"x\"\n".to_string(),
                "missing field",
            ),
        ] {
            let err = parse(&text, NOW).unwrap_err();
            assert!(err.contains(why), "{text}: {err}");
        }
        // exactly 7 days ahead is allowed
        assert!(parse(&file(D, "x", "2027-01-22T08:00:00Z"), NOW).is_ok());
    }

    #[test]
    fn a_bad_file_keeps_the_last_good_list_and_names_follow_their_entry() {
        let _gauges = GAUGES.lock();
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("exceptions.toml");
        let path = path.to_str().unwrap();
        let soon = (Utc::now() + chrono::Duration::days(1)).to_rfc3339();
        let ex = QuarantineExceptions::default();
        assert!(ex.covering(D).is_none());

        std::fs::write(path, file(D, "hotfix", &soon)).unwrap();
        ex.reload(path);
        assert_eq!(ex.covering(D).unwrap().0, D);
        let index = format!(
            r#"{{"manifests":[{{"digest":"sha256:{}"}}]}}"#,
            "1".repeat(64)
        );
        let child = format!("sha256:{}", "1".repeat(64));
        assert!(ex.covering(&child).is_none());
        ex.admit_named(D, index.as_bytes());
        assert_eq!(ex.covering(&child).unwrap().0, D);

        // a broken file, a missing reason, a missing file: the list stays
        std::fs::write(path, "[[exception]\n").unwrap();
        ex.reload(path);
        std::fs::write(path, file(D, "", &soon)).unwrap();
        ex.reload(path);
        assert!(ex.covering(D).is_some());
        assert_eq!(
            crate::metrics::DOCKER_QUARANTINE_EXCEPTIONS_INVALID.get(),
            1
        );
        std::fs::remove_file(path).unwrap();
        ex.reload(path);
        assert!(ex.covering(&child).is_some());

        // removed from the list: the entry and what it admitted are gone
        std::fs::write(path, "").unwrap();
        ex.reload(path);
        assert!(ex.covering(D).is_none());
        assert!(ex.covering(&child).is_none());
        assert_eq!(
            crate::metrics::DOCKER_QUARANTINE_EXCEPTIONS_INVALID.get(),
            0
        );

        // expired: listed, admits nothing
        std::fs::write(path, file(D, "x", "2020-01-01T00:00:00Z")).unwrap();
        ex.reload(path);
        assert!(ex.covering(D).is_none());
    }
}
