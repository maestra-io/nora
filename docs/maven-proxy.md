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
