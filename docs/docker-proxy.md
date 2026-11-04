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
| Docker Hub (`docker.io`) | `hub.docker.com/v2/repositories/<repo>/tags/<tag>` `tag_last_pushed` | a tag request, when the tag still names the fetched digest; a digest request, when one of the newest 300 tags names it |
| quay.io | `/api/v1/repository/<repo>/tag/?specificTag=<tag>` `last_modified` | the same, and the digest search includes quay's tag history |
| registry.k8s.io, gcr.io, mirror.gcr.io | `/v2/<repo>/tags/list` `manifest.<digest>.timeUploadedMs` | tag and digest requests |
| ghcr.io, mcr.microsoft.com, public.ecr.aws, others | none | first-seen; `trust_upstream_dates` there is a config warning (an error under `NORA_CONFIG_STRICT`) |

A date is looked up once per manifest digest, when the quarantine sees it for the first
time; the ledger keeps the result. A failed lookup (429, 5xx, timeout, a tag that moved,
a date in the future) falls back to first-seen and never fails the pull. Tag dates move
on a re-push, so they are never older than the push that put the digest there;
`timeUploadedMs` is the digest's upload into that repository (registry.k8s.io promotes
reviewed images only).

A Hub tag last pushed before the API recorded digests has `tag_last_pushed` and `images`
but no `digest`. Such a tag dates the fetched manifest only when its `images` list every
runnable platform of it (attestations are not listed), so a stale answer about a re-pushed
tag reads as no date. A `digest` that differs is always no date.

A digest reference carries no tag, so NORA searches the repository's tags, newest first:
at most 3 pages of 100, inside the single lookup's 5 s, once per digest. A Hub tag dates
the digest it names, a platform manifest it lists, or an index all of whose platforms it
lists. A digest no tag names any more stays first-seen on Docker Hub, which keeps no tag
history: being untagged says nothing about its age, and a pin whose floating tag moved on
is held for the TTL from its first pull.

`quarantine = "observe"` logs and counts what enforce would hold. Each first sight logs
`Quarantine: first sight of a proxied manifest` with `source`
(`hub_tag_last_pushed`, `quay_last_modified`, `gcr_time_uploaded` or `first_seen`) and
`status` (`mature` = admitted at once, `held`), and counts
`nora_docker_quarantine_first_sight_total{upstream, source, status}`.

A ledger entry older than 90 days is pruned at boot, and a registry date that old is never
written, so after a restart a cached manifest of an old image has no record. Serving such a
proxied copy admits what it names, so an uncached blob of it does not start a new TTL. A
manifest still held, a local push, and any manifest while the ledger is still loading admit
nothing.

### A floating tag under enforce

A tag that moves to a held digest keeps answering with the copy NORA already admitted for
that tag, until the new digest matures; the next pull after that moves the tag. This is the
same behaviour as the apk and deb holds, and it is what keeps `FROM <image>:<floating tag>`
building on the day the upstream patches it.

| request | previous admitted copy | answer |
|---|---|---|
| tag, new digest held | yes | 200 with the previous digest, plus `x-nora-quarantine-held: <new digest>` and `x-nora-quarantine-held-until` |
| tag, new digest held | no (a brand-new tag) | 403 |
| digest of a held manifest | any | 403 |

A held digest never replaces the admitted tag copy, under `observe` too, so a tag that moved
in the days before switching to `enforce` still has a copy behind it. Each such request logs
`Quarantine: tag moved to a held digest` and counts
`nora_docker_quarantine_tag_held_total{upstream, outcome}`: `fallback` and `blocked` under
`enforce`, `would_fallback` and `would_block` under `observe`.

### The verdict on every manifest answer

Every manifest `GET` and `HEAD` returns the quarantine verdict, so a client can read it
under `observe`, where nothing is refused (fluxcd `scripts/nora-image-check.py`):

| answer | `x-nora-quarantine` | `x-nora-quarantine-until` |
|---|---|---|
| 200, digest still inside the TTL | `pending` | unix seconds the hold ends |
| 200, admitted (past the TTL, dated past it by the registry, quarantine off, or a local push with no proxy record) | `mature` | absent |
| 403 under `enforce` | `pending` or `new`, as before | unix seconds the hold ends |
