# Helm chart repository proxy (maestra fork)

NORA proxies classic Helm chart repositories (`index.yaml` + `.tgz`), one path per
upstream, with the same supply-chain controls as the other proxy formats. Pull-through
only: no chart is published here. OCI chart repositories (`oci://…`) go through the
Docker proxy instead (a chart is an OCI manifest there, quarantined by digest like any
image).

## Configuration

```toml
[helm]
enabled = true
metadata_ttl = 300        # seconds an upstream index.yaml is reused (default 300)
serve_stale = true        # upstream down: serve the last index (default true)
proxy_timeout = 30
# repos whose index `created` is a real release date (see "Release age" below)
trust_created = ["jetstack", "hashicorp"]

[helm.proxies]
jetstack = "https://charts.jetstack.io"
hashicorp = "https://helm.releases.hashicorp.com"
private = { url = "https://charts.example.com", auth = "user:token" }

[curation.helm]
quarantine = "observe"    # off | observe | enforce
quarantine_ttl = "3d"
min_release_age = "3d"
```

Environment: `NORA_HELM_ENABLED`, `NORA_HELM_PROXIES` (`name=url|auth,name2=url`),
`NORA_HELM_PROXY_TIMEOUT`, `NORA_HELM_METADATA_TTL`, `NORA_HELM_SERVE_STALE`,
`NORA_HELM_TRUST_CREATED` (comma-separated), and `NORA_CURATION_HELM_*` for the
curation section. A proxy name is one path segment (letters, digits, `-`, `_`, `.`).

## Clients

```sh
helm repo add jetstack https://packages.example.com/helm/jetstack
helm pull jetstack/cert-manager --version v1.21.2
```

```yaml
apiVersion: source.toolkit.fluxcd.io/v1
kind: HelmRepository
metadata:
  name: jetstack
spec:
  url: https://packages.example.com/helm/jetstack
  interval: 1h
  secretRef:            # only when the server requires auth for reads
    name: nora-read
```

## Routes

- `GET|HEAD /helm/<name>/index.yaml`: the upstream index, filtered (below). One
  refresh per repo runs at a time; an upstream failure, a 404 included, serves the last
  copy (`x-nora-stale: true`) while `serve_stale` is on. Every chart
  URL in it is rewritten to the relative `charts/<chart>/<chart>-<version>.tgz`, so
  clients download through NORA whatever host the upstream names (GitHub releases for
  many repositories). The body is JSON, which is valid YAML; Helm, Flux and Renovate
  read it as `index.yaml`.
- `GET|HEAD /helm/<name>/charts/<chart>/<chart>-<version>.tgz`: the chart. NORA fetches
  it from the URL the cached upstream index names for that chart and version (never
  from client input; https only, plain http only from an upstream configured as http),
  refuses a body whose sha256 differs from the index `digest` (502, not cached), sends
  the upstream credential only to the upstream's own origin, and caches it under
  `helm/charts/<chart>/<name>/`. A version with no `digest` in the index is left out
  of the served index and not fetched (seen 22.10.2026 only on a few pre-2021
  external-dns and metrics-server versions).

## Controls

- **Digest quarantine** (`[curation.helm] quarantine`, the primary control): a chart's
  sha256 is held from the moment NORA first fetches it, by NORA's clock. In `enforce` a
  held chart answers 403 with `x-nora-quarantine`, and once seen it is also left out of
  the served index until it matures, so resolvers never pick it. A chart nobody has
  fetched yet stays listed: the first fetch starts its clock.
- **Release age** (`min_release_age` by the index `created`): only for repos listed in
  `trust_created`. Several repositories re-stamp every `created` on each index rebuild
  (teleport, ory and crossplane, seen in 2026-09/10), which would hide every version they
  have for the whole window, so trust is per repo and off by default. For a trusted repo
  younger versions are left out of the index and refused on download; with
  `server.trust_upstream_dates` the quarantine clock is also seeded from `created`.
- **Internal namespaces**: a chart name matching `curation.internal_namespaces` is left
  out of every index and never fetched from an upstream (403).
- Blocklist, allowlist pins and `allow` exemptions apply by chart name, as elsewhere.

## Operations

Metrics carry `registry="helm"`: downloads, cache hits and misses,
`nora_quarantine_holds_total`, `nora_artifacts_total` (charts by name). Cached charts
count against `gc.proxy_cache_max_bytes`; the cached indexes (`helm/index/`) do not.

Known limits: the index is re-parsed from its cached JSON on every request (off the
async runtime; ~14 ms for prometheus-community's 6.5 MB index); a chart version
re-published upstream with new content keeps serving the first cached copy; upstream indexes are refetched whole after `metadata_ttl` (no conditional
request) and capped at 128 MiB.
