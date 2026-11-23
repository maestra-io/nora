# Maven proxies and release dates (maestra fork)

`/maven2/` serves a stored file first (an upload here or a cached upstream copy), then tries
each `[maven] proxies` entry in order; the first upstream that has the file answers.

## Hosted groups

With proxies configured, a coordinate is uploaded (PUT) here only under
`curation.internal_namespaces` or `[maven] hosted_groups` (the same glob syntax). Elsewhere an
upload would seat its own file under a coordinate the upstreams serve, before NORA cached it.

```toml
[maven]
hosted_groups = ["io.delta.**"]
hosted_groups_enforcement = "warn"   # or "enforce": 403 "group not hosted here"
```

`warn` (the default) stores such an upload and logs `[SECURITY] Maven upload outside
curation.internal_namespaces and maven.hosted_groups`; both modes count
`nora_maven_unhosted_uploads_total{outcome="warned"|"refused"}`. List the groups the WARN names,
add them to `hosted_groups`, then switch to `enforce`. Reads are not affected, and a registry
without proxies hosts every coordinate.

Checksum files are NORA's own: a deploy stores `.md5`, `.sha1`, `.sha256` and `.sha512` of
the file it stored. An uploaded checksum is compared with that (or with the stored file's digest)
and never stored as sent: 404 when the file is not stored, 400 on a mismatch
(`checksum_verify = false` skips the comparison).

```toml
[maven]
proxies = ["https://repo1.maven.org/maven2", "https://maven.google.com"]

[curation.maven]
min_release_age = "3d"
quarantine = "observe"
quarantine_ttl = "3d"
```

`maven.google.com` answers with a redirect to `dl.google.com/dl/android/maven2/`, which NORA
follows (measured 05.11.2026: `androidx/core/core/1.13.0` and `com/android/tools/build/gradle/8.7.0`
poms 200 through the list above).

## Large artifacts and misses

A cold-miss artifact above `server.stream_threshold_mb` (16 MB by default) is spooled to disk
under the spool budget, as NuGet, npm and PyPI files are, and served from the spool; the hold
below dates it by the spooled file's digest. Only `maven-metadata.xml` is read whole, under
`server.proxy_max_buffered_mb`. The largest artifact is `server.proxy_max_artifact_mb`.

An upstream whose body NORA refuses (over that cap, spool busy, local disk) has the file: the
miss is the spool's answer (507, or 503 with `Retry-After` while the spool is busy), never a 404
because a later upstream does not have it. Before, `software/amazon/awssdk/bundle/2.29.52`
(641 MB, over the buffered cap) was a 404: Central's body was refused and maven.google.com said
"not found". Every miss logs a `proxy miss` WARN with each upstream's answer.

## Which artifacts the hold dates

| Upstream | Date | `min_release_age` | Quarantine clock |
|---|---|---|---|
| Maven Central | the file's `Last-Modified` on Central, else search.maven.org `timestamp` (with `server.trust_upstream_dates`) | applies; a date the lookup could not get is judged by `unknown_date` | seeded with the publish date |
| maven.google.com (`dl.google.com/dl/android/maven2`) | the file's `Last-Modified` there (with `server.trust_upstream_dates`) | applies; `unknown_date` as above | seeded with the publish date |
| any other proxy | none NORA reads | skipped | first seen by NORA |

Dated proxies are asked in configured order, all within one `maven.date_lookup_timeout`; only a
404 passes to the next. A date names the bytes of the upstream that gave it: a file another
dated proxy serves is judged undated, and one an undated proxy serves keeps the first-seen clock. Google's `Last-Modified` is the publish time (measured
23.11.2026: within 4 minutes of `lastUpdated` in `maven-metadata.xml` for androidx core, AGP,
Firebase and Play services; files from before 2019 carry the day they were moved).

An artifact without a date (Cloudsmith, Confluent) is held only by the digest quarantine,
counted from NORA's first fetch of that file. With `quarantine = "observe"` that is a log line and
`nora_quarantine_holds_total{registry="maven",outcome="observed"}`, no 403. With `enforce` every
such artifact NORA has not fetched before, including one released years ago, is refused for
`quarantine_ttl` after its first fetch.

Central is asked first, so a Google-only coordinate costs a Central HEAD and GET 404 per cache
miss.

The date lookup runs on a cache miss before the download, within `maven.date_lookup_timeout`
(default 5 s, `NORA_MAVEN_DATE_LOOKUP_TIMEOUT`) for the HEADs and the search together. A lookup
that fails (timeout, throttled 403, no date) logs `Maven date lookup failed` at WARN
with `source` and `reason` and counts `nora_maven_date_lookup_total{source,outcome}`. Only the
HEAD's 404 means "not on that upstream"; an empty search after a failed HEAD is `missing`.
`source` is `last_modified` or `search` (Central) or `google`.

When a dated upstream then serves the file anyway, its date stayed unknown and
`[curation.maven] unknown_date` decides before anything is cached: `log` (the default) serves it, logs
`[SECURITY] min-release-age unknown date` and counts
`nora_curation_unknown_release_date_total{registry="maven"}`, the quarantine keeping it on the
first-seen clock; `hold` judges it released now, so `min_release_age` refuses it (403, nothing
cached, a later request asks the date again). A file an undated proxy serves stays on
the quarantine path either way. Before switching to `hold`, read
`nora_maven_date_lookup_total{outcome!~"ok|not_found"}`: each such cold miss of a file
on a dated upstream would be a 403. Before 1.4.3-maestra.16 only the search was asked,
on `proxy_timeout` (30 s), silently: a throttled search added 30 s to a cold miss and held a
years-old artifact as new.

A file is looked up once per `maven.metadata_ttl` (a miss once a minute), and concurrent misses
of the file share one lookup. A HEAD answered 429 or 503 is not followed by the search. The HEAD
and the search report to breakers of their own (`maven:<url>#dates`), never the download breaker,
and the search answer is read up to 32 MiB. The same memo serves the RubyGems versions API and
the registry.terraform.io `/v2` API; `nora_upstream_date_lookup_total{registry,outcome}` counts
`memo`, `fetch` and `breaker_open`.

A cache hit asks the dated upstreams again (once per digest per hour) when the quarantine holds the artifact
or has no entry for it, and a date moves the clock back. No entry is what a restart
leaves for an artifact dated past the prune line on its miss: that entry is never persisted, so
the first hit after a restart used to hold it as new.
