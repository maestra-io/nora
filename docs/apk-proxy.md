# Alpine (apk) repository proxy (maestra fork)

NORA proxies Alpine package repositories (`APKINDEX.tar.gz` + `.apk`) from one or more
mirror roots and holds back package versions younger than `min_release_age`, with
signature checking on all the way to the client. Pull-through only.

## Configuration

```toml
[apk]
enabled = true
signing_key_path = "/etc/nora/apk/signing.pem" # RSA private key (PEM, PKCS#1 or #8), required
key_name = "packages.example.com.rsa.pub"      # name in /etc/apk/keys (default nora.rsa.pub)
upstream_keys_dir = "/usr/share/apk/keys"      # upstream public keys (default; Alpine images ship them)
metadata_ttl = 300                             # seconds an upstream index is reused
serve_stale = true                             # upstream down: serve the last index
proxy_timeout = 30

[apk.proxies]
alpine = "https://dl-cdn.alpinelinux.org/alpine"
corretto = "https://apk.corretto.aws"   # flat: <arch>/APKINDEX.tar.gz at the root

[curation.apk]
min_release_age = "3d"   # held back by the build time `t:` in the signed index
quarantine = "observe"
quarantine_ttl = "3d"
```

Environment: `NORA_APK_ENABLED`, `NORA_APK_PROXIES` (`name=url|auth,…`),
`NORA_APK_SIGNING_KEY_PATH`, `NORA_APK_KEY_NAME`, `NORA_APK_UPSTREAM_KEYS_DIR`,
`NORA_APK_PROXY_TIMEOUT`, `NORA_APK_METADATA_TTL`, `NORA_APK_SERVE_STALE`, and
`NORA_CURATION_APK_*`. A proxy name is one path segment, not `keys`. An enabled proxy
whose keys do not load is a config error.

Key: `openssl genrsa -out signing.pem 4096`. Keep it in a secret store and mount it; the
public half is derived from it.

## Clients

```sh
wget -O /etc/apk/keys/packages.example.com.rsa.pub \
  https://packages.example.com/apk/keys/packages.example.com.rsa.pub   # no auth
echo "https://packages.example.com/apk/alpine/v3.22/main" > /tmp/repos
HTTP_AUTH="basic:*:token:$TOKEN" apk add --repositories-file /tmp/repos jq
```

apk appends `/<arch>/APKINDEX.tar.gz` to each repository line; branches (`v3.22`,
`edge`), repositories (`main`, `community`, `testing`) and architectures are passed
through. A flat repository (`/apk/corretto` for `https://apk.corretto.aws`) has no
branch or repository segment; its signing key (`amazoncorretto.rsa.pub`) goes in
`upstream_keys_dir` next to Alpine's. apk's libfetch sends the `HTTP_AUTH` credentials after NORA's 401, on apk 2.x
and 3.x alike. Do not put the token in the URL (`https://token:$TOKEN@…`): apk-tools
2.14.6 and older (Alpine 3.21 and older) reject a URL password over about 1 KiB as
"invalid URL", and a GitHub OIDC token is longer. Keep the token out of image layers:
read it from a BuildKit secret mount inside the `RUN` that uses it.

## How a version is chosen

1. The upstream `APKINDEX.tar.gz` is fetched under `metadata_ttl` and refused (502, or
   the stale copy) unless its `.SIGN.RSA.`/`.SIGN.RSA256.` signature verifies with a key
   of that name under `upstream_keys_dir`.
2. NORA keeps every entry the upstream has listed and since dropped, while it can still
   matter (newer than the package's second-newest version older than `min_release_age`,
   at least 7 days, so a hold switched on later still has it). An Alpine branch
   lists one version per package and deletes the file of the version it replaces.
3. On serve, each package gets its newest version older than `min_release_age` by its
   build time (`t:`) that NORA can deliver: listed upstream, or dropped and cached by
   NORA. A package with no such version is left out: `apk add` fails with `no such
   package`, it never reaches the upstream around NORA. A fresh security fix therefore
   waits `min_release_age`; an entry in the curation `allow` list releases it early.
4. The result is re-signed with NORA's key as `.SIGN.RSA256.<key_name>` (verified with apk-tools
   2.10 to 3.x, Alpine 3.9 to 3.24). It is cached in memory for up to a minute.

A package is fetched only under a name and version some index entry lists (404
otherwise), refused with 403 while younger than `min_release_age` (curation `enforce`),
and refused with 502 when its control segment does not hash to the entry's `C:` identity.
Packages are cached under `apk/pkgs/` (counted by `gc.proxy_cache_max_bytes`; an evicted
dropped version can no longer be the fallback) and pass the digest quarantine, seeded
from the build time with `server.trust_upstream_dates` (the date sits inside the
upstream-signed index).

Fallback limit: a dropped version is a fallback only if NORA cached it before the
upstream deleted it, i.e. some build installed it through NORA while it was current.
