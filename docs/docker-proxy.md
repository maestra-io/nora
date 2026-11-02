# Docker proxy (maestra fork)

## Quarantine age from the registry (`trust_upstream_dates`)

The digest quarantine (`[curation.docker] quarantine`, `quarantine_ttl`) holds a manifest
NORA has not seen for the TTL, by NORA's own clock. An image published months ago is
therefore held as "new to this mirror" the first time anyone pulls it. With
`trust_upstream_dates = true` on an upstream, the first sight of a manifest is dated by
the registry's own record of the push instead, so an image published longer than the TTL
ago is admitted at once; a fresh one is held until it is TTL old by that date. What the
manifest names (platform manifests, config, layers) matures with it (#112).

```toml
[[docker.upstreams]]
url = "https://quay.io"
prefix = "quay"
namespace = "quay.io"
trust_upstream_dates = true   # default false
```

The source is picked by the upstream's namespace. Only dates the registry sets on push
are used, never the image's own `created` (the builder writes it: 1970 for external-dns).

| registry (namespace) | date | dates |
|---|---|---|
| Docker Hub (`docker.io`) | `hub.docker.com/v2/repositories/<repo>/tags/<tag>` `tag_last_pushed` | a tag request, when the tag still names the fetched digest |
| quay.io | `/api/v1/repository/<repo>/tag/?specificTag=<tag>` `last_modified` | the same |
| registry.k8s.io, gcr.io, mirror.gcr.io | `/v2/<repo>/tags/list` `manifest.<digest>.timeUploadedMs` | tag and digest requests |
| ghcr.io, mcr.microsoft.com, public.ecr.aws, others | none | first-seen; `trust_upstream_dates` there only logs a config warning |

A date is looked up once per manifest digest, when the quarantine sees it for the first
time; the ledger keeps the result. A failed lookup (429, 5xx, timeout, a tag that moved,
a date in the future) falls back to first-seen and never fails the pull. A digest
reference to Docker Hub or quay has no tag to ask about, so it is first-seen unless a tag
request dated it before. Tag dates move on a re-push, so they are never older than the
push that put the digest there; `timeUploadedMs` is the digest's upload into that
repository (registry.k8s.io promotes reviewed images only).

`quarantine = "observe"` logs and counts what enforce would hold. Each first sight logs
`Quarantine: first sight of a proxied manifest` with `source`
(`hub_tag_last_pushed`, `quay_last_modified`, `gcr_time_uploaded` or `first_seen`) and
`status` (`mature` = admitted at once, `held`), and counts
`nora_docker_quarantine_first_sight_total{upstream, source, status}`.

### The verdict on every manifest answer

Every manifest `GET` and `HEAD` returns the quarantine verdict, so a client can read it
under `observe`, where nothing is refused (fluxcd `scripts/nora-image-check.py`):

| answer | `x-nora-quarantine` | `x-nora-quarantine-until` |
|---|---|---|
| 200, digest still inside the TTL | `pending` | unix seconds the hold ends |
| 200, admitted (past the TTL, dated past it by the registry, quarantine off, or a local push with no proxy record) | `mature` | absent |
| 403 under `enforce` | `pending` or `new`, as before | unix seconds the hold ends |
