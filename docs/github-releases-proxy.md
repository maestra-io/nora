# GitHub Releases proxy (maestra fork)

NORA proxies release assets of public GitHub repositories, so CI downloads toolchains
(`gitleaks`, `kustomize`, `trivy`, …) through the same supply-chain controls as packages
instead of straight from github.com. Pull-through only: nothing is published here.

## Configuration

```toml
[github]
enabled = true
download_url = "https://github.com"      # default; asset downloads
api_url = "https://api.github.com"       # default; release records
metadata_ttl = 86400                     # seconds a release record is reused (default 86400)
proxy_timeout = 30

[curation.github]
quarantine = "observe"    # off | observe | enforce
quarantine_ttl = "3d"
min_release_age = "3d"
```

Environment: `NORA_GITHUB_ENABLED`, `NORA_GITHUB_DOWNLOAD_URL`, `NORA_GITHUB_API_URL`,
`NORA_GITHUB_PROXY_TIMEOUT`, `NORA_GITHUB_METADATA_TTL`, `NORA_GITHUB_TOKEN`, and
`NORA_CURATION_GITHUB_*` for the curation section. `NORA_GITHUB_TOKEN` (environment
only, never in config.toml) is sent to the API only and lifts its rate limit from 60
to 5000 requests per hour; a token with no scopes is enough for public repositories.

## Clients

The path is GitHub's own, under `/github`: swap `https://github.com` for
`https://packages.example.com/github`. A tag with a `/` is sent percent-encoded, as in
GitHub's own download URLs (`kustomize%2Fv5.4.3`). Pin the sha256 in the client too:

```sh
url=https://packages.example.com/github/gitleaks/gitleaks/releases/download/v8.28.0/gitleaks_8.28.0_linux_x64.tar.gz
curl -fsSL -u "ci:$NORA_TOKEN" -o gitleaks.tgz "$url"
echo "a65b5253807a68ac0cafa4414031fd740aeb55f54fb7e55f386acb52e6a840eb  gitleaks.tgz" | sha256sum -c -
```

On a server that accepts GitHub Actions OIDC tokens, a job with `id-token: write` mints
one for the server's audience and sends it as the Basic password (or Bearer).

## Routes

- `GET|HEAD /github/<owner>/<repo>/releases/download/<tag>/<asset>`: the asset.
  NORA first reads the release record (`GET <api_url>/repos/<owner>/<repo>/releases/tags/<tag>`),
  cached under `github/meta/` for `metadata_ttl`; one refresh per release runs at a
  time, and an API failure (rate limit included) uses the last copy. A release the API
  does not know, or an asset it does not list, is a 404 and never fetched. The asset is
  fetched from `<download_url>/<owner>/<repo>/releases/download/<tag>/<asset>` only,
  refused when its sha256 differs from the `digest` GitHub publishes for it (502, not
  cached; assets uploaded before mid-2025 have none), and cached under
  `github/releases/<owner>/<repo>/<tag>/`.
- Every request goes through the SSRF guard (no loopback, private, link-local or
  metadata address, DNS pinned), and every redirect hop must stay on the
  `download_url` host, the `api_url` host or GitHub's asset CDN
  (`release-assets.githubusercontent.com`, `objects.githubusercontent.com`).
  `allow_private_hosts = true` lifts the address check for a lab (not the host list).
- The `latest/download` alias is not served: it moves, so nothing could pin it.

## Controls

The package name is `<owner>/<repo>` and the version is the tag.

- **Release age** (`min_release_age`): by the release's `published_at`. A younger
  release answers 403 under `curation.mode = "enforce"`.
- **Digest quarantine** (`quarantine`): an asset's sha256 is held from the moment NORA
  first fetches it (seeded from `published_at` with `server.trust_upstream_dates`). In
  `enforce` a held asset answers 403 with `x-nora-quarantine`.
- **A first-seen copy is kept**: an asset re-uploaded upstream with other content keeps
  serving the first cached copy, the one its quarantine dated.
- **Internal namespaces**, blocklist, allowlist pins and `allow` exemptions apply by
  `<owner>/<repo>`, as elsewhere.

## Operations

Metrics carry `registry="github"`: downloads, cache hits and misses,
`nora_quarantine_holds_total`, `nora_artifacts_total` (assets by owner). Cached assets
count against `gc.proxy_cache_max_bytes`; release records (`github/meta/`) do not.

Known limits: private repositories are not served (their assets need the API asset
endpoint and a token with access); a release record lacking a just-uploaded asset is
refreshed only after `metadata_ttl`.
