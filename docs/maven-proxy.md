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
| Maven Central | search.maven.org `timestamp` (with `server.trust_upstream_dates`) | applies | seeded with the publish date |
| maven.google.com, any other proxy | none NORA reads | skipped | first seen by NORA |

An artifact without a date is held only by the digest quarantine, counted from NORA's first
fetch of that file. With `quarantine = "observe"` that is a log line and
`nora_quarantine_holds_total{registry="maven",outcome="observed"}`, no 403: a Google artifact
released yesterday is served. With `enforce` every Google artifact NORA has not fetched before,
including one released years ago, is refused for `quarantine_ttl` after its first fetch.

Central is asked first, so a Google-only coordinate costs one Central 404 per cache miss, and the
Central date lookup also runs for it (no match, no date).
