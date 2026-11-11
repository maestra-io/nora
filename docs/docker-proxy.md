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
| registry.k8s.io, gcr.io, mirror.gcr.io, Artifact Registry (`<region>-docker.pkg.dev`) | `/v2/<repo>/tags/list` `manifest.<digest>.timeUploadedMs` | tag and digest requests |
| ghcr.io | `api.github.com/users/<owner>/packages/container/<package>/versions` `created_at` (a nested name is one package, `a%2Fb`); needs `date_token_file` | tag and digest requests, when one of the newest 1000 versions is the digest |
| mcr.microsoft.com | `/api/v1/catalog/<repo>/tags?reg=mar`: the earliest `lastModifiedDate` of the tags naming the digest (`createdDate` is the tag's first push, not the digest's) | tag and digest requests, when a tag names the digest |
| public.ecr.aws | gallery `describeImageTags` `imagePushedAt` per tag (cosign `.sig`/`.att`/`.sbom` tags skipped) | tag and digest requests, when one of the first 25000 tags names the digest |
| cgr.dev | `/v2/<repo>/_chainguard/history/<tag>` `updateTimestamp`: when the tag moved onto the digest (the earliest record of it), with an anonymous token from `/token?scope=repository:<repo>:pull` | a tag request by that tag's history; a digest request by the history of the repository's first 10 tags on tags/list (cosign `sha256-*` tags skipped; a public `chainguard/*` repository has `latest` and `latest-dev`), 5 pages of 1000 records per tag |
| docker.dragonflydb.io, others | none | first-seen; `trust_upstream_dates` there is a config warning (an error under `NORA_CONFIG_STRICT`) |

ghcr.io, mcr, public.ecr.aws and cgr.dev date a digest only in a listing of the whole
repository (cgr.dev: of a tag, a tag request walks that tag alone).
NORA walks that listing once per repository on a task of its own (pages bounded as in the
table, 120 s in all) and keeps the result for 10 min (a walk that got nothing: 1 min), so
every first sight in the repository, a platform manifest or another tag, reads the same
walk. A request waits at most the lookup's 5 s for it; a walk still running then starts
the digest at first-seen and, when it lands, moves it and everything it names back to the
registry's date. A tag is usually the first request of a repository, so before this it
stayed first-seen while the digest request a second later had the date. ghcr pages after a
full first one are asked at once (10 one after another took 5.9 s). A failed walk (401,
429, 5xx) or a digest the listing does not name leaves first-seen and never fails the
pull. A digest pushed after the walk is first-seen as well, which is never younger than it
is. public.ecr.aws lists tags in no date order, 1000 per 4 s page, so a repository with
thousands of signature tags (gravitational/teleport-distroless: 17 pages, about 50 s) is
dated when its walk lands, not on the first request: under enforce that request is a 403.
public.ecr.aws and the cgr.dev history list no platform manifest of an index (they carry
no tag): they take the index's date.

A digest already held by NORA's own clock, recorded before its registry had a date source
or in a failed lookup, is asked about again each time a tag pull revalidates it, and moves
back to the registry's date, with everything it names. Only Docker Hub and quay.io are not
asked again: they date a tag, and the first sight used that. A pull by digest of a cached
held manifest asks the walked registries (ghcr.io, mcr, public.ecr.aws, cgr.dev) too, which costs no
request of its own; for registry.k8s.io and Artifact Registry it stays held until a tag pull
or the TTL. A move is written beside the ledger entry (`<entry>.dated`), and every start
takes the earliest of the two, so it outlives a restart.

tags/list is read anonymously: a private Artifact Registry repository answers 401, and its
images stay first-seen. So is cgr.dev: Chainguard documents an anonymous token for the
free `latest`/`latest-dev` images; a private repository needs a Chainguard token, which
NORA does not send, so its images stay first-seen.

cgr.dev rebuilds its images about daily and moves `latest` each time, so a pin such as
`cgr.dev/chainguard/nginx:latest@sha256:…` is pulled by digest, usually first by a kubelet.
Its history answers the date the tag moved onto the digest: `0352063c` of chainguard/nginx,
first fetched by NORA on 08.11.2026 12:49Z, was published 07.11.2026 19:55Z. The history
answers 1000 records a request, oldest first; a full page asks for the next from its last
record (`?start=`).

The GitHub packages API answers only with a token. `date_token_file` names a file holding
one, re-read at each walk, so a mounted Secret that rotates applies without a restart.
GitHub documents that a GitHub App installation token reads public packages with no
permission of its own; a classic PAT needs `read:packages`. A refusal (401/403) logs
GitHub's own reason in `docker publish date lookup failed` (`Denied(403, Some("<message>
(<documentation_url>)"))`): an organisation's IP allow list, SSO enforcement or the
token's reach.

```toml
[[docker.upstreams]]
url = "https://ghcr.io"
prefix = "ghcr"
namespace = "ghcr.io"
trust_upstream_dates = true
date_token_file = "/var/run/secrets/github/token"
```

A date is looked up when the quarantine sees a manifest digest for the first time, and
again on each tag pull while NORA's own clock holds it (above); the ledger keeps the first
result, and a date only moves a hold back. A failed lookup (429, 5xx, timeout, a tag that
moved, a date in the future) falls back to first-seen and never fails the pull. Tag dates move
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
(`hub_tag_last_pushed`, `quay_last_modified`, `gcr_time_uploaded`, `ghcr_created_at`,
`mcr_last_modified`, `ecr_public_pushed_at` or `first_seen`) and
`status` (`mature` = admitted at once, `held`), and counts
`nora_docker_quarantine_first_sight_total{upstream, source, status}`.

A ledger entry older than 90 days is pruned at boot, and a registry date that old is never
written, so after a restart a cached manifest of an old image has no record. Serving such a
proxied copy admits what it names, so an uncached blob of it does not start a new TTL. A
manifest still held, a local push, and any manifest while the ledger is loading or could not
be read whole (a failed listing, an unreadable entry) admit nothing.

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
in the days before switching to `enforce` still has a copy behind it. A tag that moved before
1.4.3-maestra.5 lost that copy, so it stays `would_block` until its digest matures. Every fetch
of a tag that resolves to a held digest, moved or not, logs
`Quarantine: tag resolves to a held digest` and counts
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

A plain request for a digest NORA has not cached fetches it and starts its clock. To read a
verdict without that, send `Cache-Control: only-if-cached` (RFC 9111 5.2.1.7): NORA answers
from its cache only, never asks an upstream and records nothing; a manifest it does not hold
is `504` (`MANIFEST_UNKNOWN`), a cached tag answers its cached copy. The github-actions
`base-images` PR check asks this way (issues-maestra#1649).

## Break-glass: admit a held image before the TTL (`quarantine_exceptions`)

When to use: an urgent fix (a CVE, an outage) needs an image digest that the quarantine holds,
and waiting `quarantine_ttl` is worse than the supply-chain risk of a fresh upstream push.
For anything else, wait or pin an older digest.

```toml
[docker]
quarantine_exceptions = "/etc/nora/quarantine-exceptions/exceptions.toml"
```

The file is re-read every 30 s. Mount it from its own ConfigMap as a directory: a `subPath`
mount never sees an update, and the main ConfigMap is in the pod's `checksum/config`, so an
edit there restarts nora. Annotate that ConfigMap `reloader.stakater.com/ignore: "true"`.

```toml
[[exception]]
digest = "sha256:<64 hex>"   # the manifest digest the pod pins: the index of a multi-arch image
reason = "CVE-2026-1234 fix, issues-maestra#NNNN"
expires = "2026-11-08T12:00:00Z"
```

- An unexpired entry admits that digest under `observe` and `enforce`. It also admits every
  digest an admitted manifest names, so the platform manifests, config and layers a pull
  needs are served too. The manifest answer then carries `x-nora-quarantine: exception`.
- Every use logs `Quarantine: held digest admitted by a break-glass exception` (with `listed`,
  `reason`, `expires`) and counts `nora_docker_quarantine_exception_used_total{digest}`. The
  `NoraQuarantineExceptionUsed` alert (warning) shows a used entry.
- Rules: a non-empty `reason`, `digest` as `sha256:` plus 64 lowercase hex, listed once, and
  `expires` as RFC 3339 with an offset, at most 7 days after the read. A file that breaks a rule
  is refused whole: nora keeps the last good list, logs `Quarantine exceptions file refused`,
  sets `nora_docker_quarantine_exceptions_invalid` to 1 and raises
  `NoraQuarantineExceptionsInvalid`. At start there is no last good list, so a bad file means
  no exceptions. `nora_docker_quarantine_exceptions_active` counts the unexpired entries.
- Expired entries admit nothing. Removing an entry withdraws it, and what it admitted, at the
  next read.
- What a manifest names is learned when nora serves that manifest, and is kept in memory. After
  a nora restart, a client that already holds the index and platform manifest and asks only for
  a missing layer gets 403 under `enforce`. A fresh pull is not affected. If that happens, list
  the platform manifest digest as well.

Procedure (packages.maestra.io): in one fluxcd PR, add the entry to
`iota/us-iota-lw-kube-infra/nora/quarantine-exceptions.yaml` and add the image. The PR's
`scripts/nora-image-check.py` reads the entry from the PR tree: the held digest passes with a
notice, and an entry that breaks a rule fails the job. Once merged, nora admits the digest
within about 1–2 minutes (ConfigMap propagation plus one read). Remove the entry in a follow-up
PR once the digest is past `quarantine_ttl` (the `x-nora-quarantine-until` it had), or at the
latest when it expires.
