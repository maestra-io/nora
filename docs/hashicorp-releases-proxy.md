# HashiCorp releases proxy (maestra fork)

NORA proxies product archives of releases.hashicorp.com (`terraform`, `vault`,
`consul`, …), so CI and image builds take them through the same supply-chain controls
as packages. Pull-through only. Terraform providers go through the Terraform network
mirror (`/terraform/`) instead.

## Configuration

```toml
[hashicorp]
enabled = true
download_url = "https://releases.hashicorp.com"     # default
api_url = "https://api.releases.hashicorp.com"      # default; release dates
metadata_ttl = 86400      # seconds a version record is reused (default 86400)
proxy_timeout = 30

[curation.hashicorp]
quarantine = "observe"    # off | observe | enforce
quarantine_ttl = "3d"
min_release_age = "3d"
```

Environment: `NORA_HASHICORP_ENABLED`, `NORA_HASHICORP_DOWNLOAD_URL`,
`NORA_HASHICORP_API_URL`, `NORA_HASHICORP_PROXY_TIMEOUT`, `NORA_HASHICORP_METADATA_TTL`,
and `NORA_CURATION_HASHICORP_*`.

## Clients

The path is releases.hashicorp.com's own, under `/hashicorp`:

```sh
base=https://packages.example.com/hashicorp/terraform/1.9.8
curl -fsSL -u "ci:$NORA_TOKEN" -O "$base/terraform_1.9.8_linux_amd64.zip"
curl -fsSL -u "ci:$NORA_TOKEN" -O "$base/terraform_1.9.8_SHA256SUMS"
grep linux_amd64.zip terraform_1.9.8_SHA256SUMS | sha256sum -c -
```

## Routes and controls

- `GET|HEAD /hashicorp/<product>/<version>/<file>`. NORA first reads the version's
  record, cached under `hashicorp/meta/` for `metadata_ttl` (stale on upstream error):
  `timestamp_created` from `<api_url>/v1/releases/<product>/<version>` and the
  version's `<product>_<version>_SHA256SUMS`. A file the sums do not list is a 404 and
  never fetched. Curation and the quarantine decide on the listed sum before the fetch;
  a cold file then streams to a GET client as it downloads, its last byte held until
  the whole file matched its sum: a mismatch breaks the transfer off (the client sees a
  failed download, never a complete one) and is not cached. A HEAD fetches the whole
  file first (a mismatch is a 502). The `SHA256SUMS` file is served as NORA read it. Files come only from `download_url`
  through the SSRF guard, every redirect hop pinned to the download and API hosts,
  and are cached under `hashicorp/releases/<product>/<version>/`.
- Package name = product, version = version. `min_release_age` by
  `timestamp_created`; the first-seen digest quarantine as for every proxy (seeded
  from `timestamp_created` with `server.trust_upstream_dates`); internal namespaces,
  blocklist and allow exemptions by product.
- NORA neither checks nor serves `SHA256SUMS.sig` (the sums do not list it): TLS to
  releases.hashicorp.com is what vouches for the sums.

Metrics carry `registry="hashicorp"`. Cached files count against
`gc.proxy_cache_max_bytes`; the records under `hashicorp/meta/` do not.
