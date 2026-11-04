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
`/usr/share/keyrings/ubuntu-archive-keyring.gpg` of an Ubuntu image. Signing key: any
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
first time dates everything it lists as 0 ("before NORA"), so switching the hold on, or a
build asking for a new suite, never hides a whole distribution. A version that appeared
upstream while nobody asked NORA for that suite is dated by NORA's next look: it is held
longer, never shorter.

1. `dists/<suite>/InRelease` is fetched under `metadata_ttl` and refused unless a key of
   `upstream_keyring_dir` signed it. Each `<component>/binary-<arch>/Packages` it lists
   (gz, else xz, else plain; `by-hash` when the upstream offers it) is fetched and refused
   on a SHA-256 other than the Release's. An index the Release lists but the mirror does
   not host (Ubuntu's archive and ports list every architecture) is left out.
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
   `InRelease` changes or a held version matures.
4. A `.deb` of a held version is refused (403, curation `enforce`; logged in `audit`). The
   allow list (`[curation.deb] allow`) releases a version early. Packages pass the digest
   quarantine like any proxied file.

Storage per repo: the last upstream `Packages` per index, the ledgers, and the built
`Packages.gz` of the current and previous build (`by-hash/`).
