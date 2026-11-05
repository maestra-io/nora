# RubyGems proxy (maestra fork)

NORA proxies rubygems.org for Bundler and `gem install` and holds back gem versions younger
than `min_release_age`. Pull-through only.

## Configuration

```toml
[registries]
enable = ["gems"]   # plus the others

[gems]
enabled = true
proxy = "https://rubygems.org"   # default
metadata_ttl = 300               # seconds an upstream index is reused

[curation.gems]
min_release_age = "3d"   # dated by the RubyGems API created_at
quarantine = "observe"
quarantine_ttl = "3d"
```

## What is served

| Path | Upstream | Hold |
|---|---|---|
| `/gems/versions` | `/versions`, as written | none: names, versions and info checksums only |
| `/gems/info/<name>` | `/info/<name>` | rows of versions younger than `min_release_age` left out |
| `/gems/gems/<file>.gem`, `/gems/quick/Marshal.4.8/<file>.gemspec.rz` | same path | refused (403) when younger than `min_release_age` |
| `/gems/specs.4.8.gz`, `latest_specs`, `prerelease_specs` | same path | none (Marshal index, not filtered) |

The dates come from `/api/v1/versions/<name>.json` (`created_at` per version and platform),
kept at `gems/dates/<name>.json` and asked again when a listed version is not in it, at most
once per `metadata_ttl`. An undated version is listed; its download still meets the `.gem`
gate and the digest quarantine.

`versions` and `info/<name>` carry `ETag` = the quoted MD5 of the body NORA serves: Bundler 1.x
takes the compact index only then, and otherwise falls back to the full Marshal index. The
checksum column of `versions` stays upstream's, so Bundler re-fetches a filtered `info` file
on each install (served from NORA's cache).

## Clients

Measured 05.11.2026 against a young `aws-partitions` 1.1301.0 (17 h old, hold 3d):

| Client | Pinned old version | Range | Fresh version pinned |
|---|---|---|---|
| Bundler 1.17.3, 2.6.9, 4.0.20 | installs | newest mature (1.1300.0) | "Could not find gem" |
| `gem install`, RubyGems 3.6.9, 4.0.20 | installs | newest mature | "Could not find a valid gem" |
| `gem install`, RubyGems 3.0.3, 3.4.19 | installs | 403 when the newest match is young | 403 |

RubyGems before 3.6 resolves `gem install` from the Marshal index, which lists the young
version: pin the version (`gem install fpm -v 1.18.0`) on those.

Credentials: NORA needs a token (`anonymous_read = false`). Bundler reads them per host:

```sh
export BUNDLE_PACKAGES__EXAMPLE__COM="token:$TOKEN"
```

```ruby
source "https://packages.example.com/gems/"
```

`gem install --clear-sources --source "https://token:$TOKEN@packages.example.com/gems/" fpm -v 1.18.0`.
In a Docker build pass the token as a BuildKit secret, never as a build arg.
