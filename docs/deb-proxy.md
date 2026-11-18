# Filtered apt proxy (maestra fork)

NORA proxies Debian and Ubuntu archives (`[deb.proxies]`) and, once `[curation.deb]
min_release_age` is set, serves them with its own indexes: a package version NORA first
saw less than `min_release_age` ago is left out, so apt resolves the previous version.
Signature checking stays on end to end: NORA verifies the upstream `InRelease` and signs
its own with its `[signing]` key. Pull-through only.

## Configuration

```toml
[signing]
key_path = "/etc/nora/signing/nora.key"   # armored Ed25519 OpenPGP key; required off local storage

[deb]
enabled = true
upstream_keyring_dir = "/etc/nora/deb-keyrings"   # *.gpg / *.pgp keyrings or *.asc
architectures = ["amd64", "arm64"]                # binary indexes built (default)
metadata_ttl = 300                                 # seconds a built suite is reused

[deb.upstream_keyrings]   # per repository: keyring file or directory (else upstream_keyring_dir)
debian = "/etc/nora/deb-keyrings/debian-archive-keyring.pgp"
debian-security = "/etc/nora/deb-keyrings/debian-archive-keyring.pgp"
ubuntu = "/etc/nora/deb-keyrings/ubuntu-archive-keyring.gpg"
ubuntu-ports = "/etc/nora/deb-keyrings/ubuntu-archive-keyring.gpg"

[deb.suite_aliases]   # per repository: suites whose Release names another suite
ubuntu = ["devel"]

[deb.proxies]
debian = "https://deb.debian.org/debian"
debian-security = "https://deb.debian.org/debian-security"
ubuntu = "https://archive.ubuntu.com/ubuntu"          # amd64
ubuntu-ports = "https://ports.ubuntu.com/ubuntu-ports" # arm64

[curation.deb]
min_release_age = "3d"   # "0d": indexes rewritten and dated, nothing held
quarantine = "observe"
quarantine_ttl = "3d"
```

Environment: `NORA_DEB_UPSTREAM_KEYRING_DIR`, `NORA_DEB_ARCHITECTURES` (comma-separated),
`NORA_CURATION_DEB_MIN_RELEASE_AGE`. With `min_release_age` set, an enabled proxy needs a
loadable keyring, `[signing]` on with a key (`signing.key_path` off local storage) and a
non-empty `architectures`, or NORA does not start. Without it the proxies stay verbatim
(upstream indexes and signatures passed through).

Upstream keys: `/usr/share/keyrings/debian-archive-keyring.pgp` of a Debian image and
`/usr/share/keyrings/ubuntu-archive-keyring.gpg` of an Ubuntu image. A repository listed in
`deb.upstream_keyrings` verifies only with its own keyring (a file or a directory); the
others share `upstream_keyring_dir`, and NORA warns at startup when more than one
repository does. Each keyring must load, and each `upstream_keyrings` entry must name a
`[deb.proxies]` repository, or NORA does not start. A key is used as gpgv would use it: a
key with a valid revocation self-signature is left out (logged), a subkey signs only with a
valid binding that carries the sign flag (and its back-signature) while neither it nor the
primary key has expired, and the primary key only when its newest self-signature has the
sign flag or no key flags at all. Signing key: any
armored Ed25519 secret key without a passphrase (`gpg --quick-gen-key 'NORA apt' ed25519
sign never`, then `gpg --export-secret-keys --armor`).

## Clients

```sh
curl -fsS -u token:$TOKEN https://packages.example.com/deb/debian/pubkey.gpg \
  -o /etc/apt/keyrings/nora.asc
cat > /etc/apt/sources.list.d/nora.sources <<EOT
Types: deb
URIs: https://packages.example.com/deb/debian
Suites: bookworm bookworm-updates
Components: main
Signed-By: /etc/apt/keyrings/nora.asc

Types: deb
URIs: https://packages.example.com/deb/debian-security
Suites: bookworm-security
Components: main
Signed-By: /etc/apt/keyrings/nora.asc
EOT
printf 'machine packages.example.com login token password %s\n' "$TOKEN" \
  > /etc/apt/auth.conf.d/nora.conf
```

`[trusted=yes]` is never needed. `pubkey.gpg` is the same key for every proxied repo.

maestra Dockerfile builds use the `nora-apt` helper of maestra-io/dockerfiles
(`dockerfiles-multiarch-public/nora-apt`): it pins packages.maestra.io's key, rewrites the
image's Debian/Ubuntu sources for one `RUN` and reads the token from the BuildKit secret.

## How a version is dated and chosen

An apt `Packages` stanza has no publish date. NORA dates each pool file (`Filename`) by the
first time it saw it in an upstream index of that suite, component and architecture,
stored in its storage (`deb/<repo>/.nora-meta/proxy/ledger/`). An index NORA sees for the
first time dates everything it lists as 0 ("before NORA"), except a file another ledger
already dates, so switching the hold on, or a build asking for a new suite, never hides a
whole distribution and never releases a version another suite still holds. A version that appeared
upstream while nobody asked NORA for that suite is dated by NORA's next look: it is held
longer, never shorter. One pool file listed by several suites (Ubuntu's `jammy-updates`
and `jammy-security` share a kernel `.deb`, often days apart) is as old as its first
sighting in any of them: a build dates its young files from every other ledger of the
repository (other suites, components and architectures: an `_all.deb` is in every arch
index), and checks its holds again, under the lock of the held-version map, against the
ledgers written while it ran. Once a suite is published, another index's hold of a file it
serves is dropped.

1. `dists/<suite>/InRelease` is fetched under `metadata_ttl` and refused unless one of
   its signatures is unexpired and was made by an unexpired signing key of the
   repository's keyring, and unless its `Suite` or `Codename` is the requested suite
   (stricter than apt, which only warns; a `Release` with neither field matches, and a
   suite listed in `deb.suite_aliases.<repo>`, such as Ubuntu's `devel`, may name its
   current target), or when its `Date` is older than the `Date` of the build NORA serves
   (a mirror or replay answering an older generation; a missing or unparsable `Date` is
   not compared, nor a served `Date` more than an hour past NORA's clock). A refused refresh keeps the last good build served. Each `<component>/binary-<arch>/Packages` it lists
   (gz, else xz, else plain; `by-hash` when the upstream offers it) is fetched and refused
   on a SHA-256 other than the Release's. An index the Release lists but the mirror does
   not host (Ubuntu's archive and ports list every architecture) is left out; the
   versions it held stay held. A file the upstream lists again after NORA dropped it keeps
   its first date.
2. A package keeps its listed versions older than `min_release_age`. When all of them are
   younger, the newest dropped version (one the upstream listed before and has since
   replaced) older than that stands in, if NORA has its `.deb` cached; otherwise the
   package is left out of that suite and apt takes it from another one (an older
   `bookworm` version for a held `bookworm-security` one) or fails. Dropped stanzas are
   kept while they can still be served (at least 7 days).
3. NORA's `Release` keeps the upstream `Origin`, `Suite`, `Codename`, `Date`,
   `Valid-Until`, `Components` and the configured architectures, drops `Signed-By` and the
   upstream checksums, and lists only its own `Packages` / `Packages.gz` with
   `Acquire-By-Hash: yes`. Translations, Contents and other index files are not served.
   It is signed as `InRelease` and `Release.gpg`. A suite is rebuilt when the upstream
   `InRelease` changes or an age-held version matures.
4. A `.deb` of a held version is refused (403, curation `enforce`; logged in `audit`),
   unless a published suite serves that file: apt found it in that suite's index. The
   allow list (`[curation.deb] allow`) releases a version early. Packages pass the digest
   quarantine like any proxied file.
5. A version the curation chain refuses by rule in `enforce` (`internal_namespaces`, the
   blocklist, the allowlist) is held whatever its age or `allow` exemption: left out of
   `Packages`, never a stand-in, its `.deb` refused with the rule. Such a hold never
   matures, so it does not rebuild the suite before `metadata_ttl`. An allowlist with a
   `*` registry and no `deb` entries empties every index; add rules in `audit` first.
   Without `min_release_age` no `.deb` is judged by name, so these rules beside
   `[deb.proxies]` are a configuration error.

Storage per repo: the last upstream `Packages` per index, the ledgers, and the built
`Packages.gz` of the current and previous build (`by-hash/`).

## Unreadable state

A ledger or the held-version map (`deb/<repo>/.nora-meta/proxy/young.json`) that NORA
cannot read or parse is never taken as absent: that would date every listed file "before
NORA" or drop every hold. The rebuild fails instead, logged at error level with the key (`deb proxy: cannot read a state object`), and the last good build stays
served; a suite with no build yet answers 500. With the held-version map unreadable and
not cached, `.deb` downloads of that repository answer 503 (`Retry-After: 30`).

A transient storage error clears on the next refresh. An object that stays unreadable
freezes that suite (a ledger) or every suite of the repository (`young.json`), and a frozen
suite with `Valid-Until` (debian-security, about 7 days) ends in apt's "Release file
expired". Recovery: delete the object the error names. The next build re-dates the files
of a deleted ledger from the other ledgers, else as first sight. After deleting
`young.json`, also delete the repository's `dists/*/state.json`: a suite re-enters its holds
only when it rebuilds, and until then its held `.deb` files are not refused. An upstream whose `Date` really goes back (a rollback, or a
bogus future `Date` once published) is refused the same way and logged as
`refresh failed, serving the last build`: delete
`deb/<repo>/.nora-meta/proxy/dists/<suite>/state.json` to accept it.
