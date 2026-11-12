# Maven proxies and release dates (maestra fork)

`/maven2/` serves hosted artifacts first, then tries each `[maven] proxies` entry in order;
the first upstream that has the file answers.

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
| Maven Central | the file's `Last-Modified` on Central, else search.maven.org `timestamp` (with `server.trust_upstream_dates`) | applies | seeded with the publish date |
| maven.google.com, any other proxy | none NORA reads | skipped | first seen by NORA |

An artifact without a date is held only by the digest quarantine, counted from NORA's first
fetch of that file. With `quarantine = "observe"` that is a log line and
`nora_quarantine_holds_total{registry="maven",outcome="observed"}`, no 403: a Google artifact
released yesterday is served. With `enforce` every Google artifact NORA has not fetched before,
including one released years ago, is refused for `quarantine_ttl` after its first fetch.

Central is asked first, so a Google-only coordinate costs one Central 404 per cache miss, and the
Central date lookup also runs for it (a HEAD 404, no date, no search).

The date lookup runs on a cache miss before the download, within `maven.date_lookup_timeout`
(default 5 s, `NORA_MAVEN_DATE_LOOKUP_TIMEOUT`) for the HEAD and the search together. A lookup
that fails (timeout, throttled 403, no date) leaves the artifact on the first-seen clock, logs
`Maven Central date lookup failed` at WARN with `source` and `reason`, and counts
`nora_maven_date_lookup_total{source,outcome}`. Before 1.4.3-maestra.16 only the search was asked,
on `proxy_timeout` (30 s), silently: a throttled search added 30 s to a cold miss and held a
years-old artifact as new.

A cache hit asks Central again (once per digest per hour) when the quarantine holds the artifact
or has no entry for it, and a Central date moves the clock back. No entry is what a restart
leaves for an artifact dated past the prune line on its miss: that entry is never persisted, so
the first hit after a restart used to hold it as new.
