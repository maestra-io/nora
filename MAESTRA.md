# Maestra fork of nora

Real GitHub fork of [getnora-io/nora](https://github.com/getnora-io/nora); tracking issue maestra-io/issues-maestra#1442.

- `main` is an untouched mirror of upstream `main`: fast-forward only, never commit to it.
- `maestra/main` (default branch) is upstream `main` plus our commits. All our work lands here via PRs.

Maestra-only changes (not upstream):
- Hosted NuGet feed retention/repair: `[nuget] hosted_pr_retention_days` (`NORA_NUGET_HOSTED_PR_RETENTION_DAYS`, default 30, 0 = keep all) and `hosted_pr_keep_last` (`NORA_NUGET_HOSTED_PR_KEEP_LAST`, default 20) expire `X.Y.Z-pr.*` versions in a periodic pass (retention interval and dry-run) that also sweeps blob dirs no state document names (>1 h old); `nora nuget rebuild <id>` rewrites `nuget/hosted-meta/{id}.json` from the stored nuspecs; `POST /api/v1/admin/reindex` also re-reads hosted state documents.
- `nora import` hosts npm, NuGet and PyPI (C73): each verified file goes through the publish internals (`npm::publish_versions`, `nuget::hosted::import_package`, `pypi::store_file`), so it is served like an upload (npm `latest` = highest imported release; publish times are the import time; NuGet unlisted and PyPI yanked state are not carried). NuGet state documents written behind a running server are served after `POST /api/v1/admin/reindex`. `curation.internal_namespaces` is not applied to an import (hosted source repos only).
- `[storage] s3_credentials_dir` / `NORA_STORAGE_S3_CREDENTIALS_DIR`: S3 credentials (`access_key_id`, `secret_access_key`, optional `session_token`) read from files and re-read every 60 s, for the rotating STS-style R2 creds Vault mints (packages.maestra.io, issues-maestra#1442).
- `[auth] read_only_users` / `NORA_AUTH_READ_ONLY_USERS`: htpasswd accounts that authenticate as `read` (pull only, read tokens only); every self-service token mint is capped at the caller's own role.
- An enabled OIDC provider with an empty `audience` is a config warning, and an error under `NORA_CONFIG_STRICT`.
- `[auth.teleport]` (`nora-registry/src/auth/teleport.rs`): web UI identity from Teleport application access. On UI paths (`/`, `/ui*`, `/api/ui*`, `/api-docs*`) a `Teleport-Jwt-Assertion` from a TCP peer in `trusted_proxies` is verified against `jwks_url` (`iss` = `issuer`, `aud` = `audience`, ES256/RS256, JWKS cached `jwks_cache_secs`, refetched on an unknown `kid`, stale on fetch failure). Identity = the `username` claim; `roles` ∩ `write_roles` → `write`, else `read`; never `admin`. `require_for_ui = true`: UI paths without that identity answer 404, and a 401 to a browser (`Sec-Fetch-Mode`, or `text/html` first in `Accept`) carries no `WWW-Authenticate`, so no password dialog. Registry paths ignore the header. Keys: `enabled`, `jwks_url`, `issuer`, `audience`, `trusted_proxies` (IP/CIDR string), `write_roles`, `require_for_ui`, `leeway_secs` (60), `jwks_cache_secs` (300).
- `[auth] htpasswd_allowed_peers` / `NORA_AUTH_HTPASSWD_ALLOWED_PEERS`: TCP peers whose htpasswd password is checked (unset = all, as upstream). Any other peer: no bcrypt, `/api/tokens*` → 403, Basic carries only `nra_` tokens and OIDC JWTs.
- Cargo features `rpm` and `deb` (default on): `--no-default-features` builds without those registries, their parsers and the rpgp index signer; a config enabling them on such a build logs an error and does not mount them. Our release image is built that way (`CARGO_FEATURES=--no-default-features`).
- Builds are `--locked` (Dockerfile, CI); Swagger UI comes from the `vendored` feature of `utoipa-swagger-ui` (crates.io, checksummed), not a build-time GitHub download.
- `[curation.<registry>] allow = ["name@version"]` / `NORA_CURATION_<REGISTRY>_ALLOW` (comma-separated): exact versions exempt from `min_release_age` only (the digest quarantine still applies), names normalized per format (NuGet case-insensitive, PyPI PEP 503); reloaded on SIGHUP; each exemption logs `[SECURITY]` and counts in `nora_curation_min_age_allowed_total{registry}`.
- `curation.mode = "enforce"` + `min_release_age` also hides younger versions from proxied metadata, filtered on serve (cache keeps the upstream original): npm packument (full and `install-v1`; `latest` → newest allowed, other tags on hidden versions dropped), PyPI simple index (HTML + PEP 691, dated by `dates.json`), NuGet registration index/pages, flat-container `index.json`, search and autocomplete `?id=` (search reads only the newest registration page). Uses the upstream dates regardless of `trust_upstream_dates` (hiding cannot let a version through). Audit mode only logs. Hosted, internal-namespace and `allow`-listed versions are not hidden.

### Auth matrix, packages.maestra.io (fluxcd `iota/us-iota-lw-kube-infra/nora/`)

| Who | Where | How | Role |
|---|---|---|---|
| People (browser) | `https://packages.teleport.maestra.io` (Teleport app `packages`, GitHub SSO) | Teleport JWT; UI, mint/revoke own `nra_` tokens | `write` with Teleport role `apps`, else `read` |
| People / CI (package clients) | `https://packages.maestra.io` `/nuget/`, `/npm/`, `/simple/` | `nra_` token as Bearer, `X-NuGet-ApiKey` or Basic password | the token's role |
| GitHub Actions | same | OIDC JWT (`aud` `packages.maestra.io`) as Bearer or Basic password | per `[auth.oidc]` rules |
| Admin (`admin` htpasswd) | `kubectl port-forward svc/nora 4000` only (peer `127.0.0.1`) | Basic password, `POST /api/tokens` | `admin` mint via `auth.admin_users` |
| Anyone | public hostname, any other path | none: traefik routes only the registry prefixes and `/health`, `/ready` | n/a |

Update from upstream:
```sh
git fetch upstream && git checkout main && git merge --ff-only upstream/main && git push origin main
git checkout maestra/main && git merge main && git push origin maestra/main
```

Merge, not rebase: `maestra/main` is the default branch with open PRs on it, a rebase would force-push it and invalidate every branch cut from it; a merge resolves each upstream conflict once, in one commit.
Changes meant for upstream: branch from `main`, cherry-pick, open the PR against getnora-io/nora.

## CI and releases

- `.github/workflows/maestra-ci.yml`: on PRs into `maestra/main` (RunsOn `pool=build`): `cargo fmt --check`, clippy `-D warnings` and `cargo test`, all `--locked`, for the default and the release (`--no-default-features`) feature sets; `cargo deny check advisories` against `deny.toml`.
- `.github/workflows/maestra-release.yml`: tag `v<version>-maestra.<n>` (version = `Cargo.toml`) on `maestra/main` builds the upstream `Dockerfile` with `--build-arg CARGO_FEATURES=--no-default-features` (no rpm/deb) and pushes `515260921971.dkr.ecr.us-west-2.amazonaws.com/nora:<version>-maestra.<n>` via the Teleport image-push bot (token `image-push-github-actions-nora`, fluxcd `iota/us-iota-lw-kube-infra/teleport-maestra/operator-crs/image-push-tokens.yaml`). Re-run: `gh workflow run maestra-release.yml -f tag=<tag>`.
- Our workflows carry a `maestra-` prefix so upstream merges never conflict on them. Upstream `Release`, `Post-Release Gate` and `PR Image Cleanup` target upstream's ghcr/self-hosted runners and are disabled in this repo (`gh workflow disable`); upstream `Release` would otherwise fire on our `v*` tags.

## Helm chart

`maestra/charts/nora`: upstream getnora-io/helm-charts `charts/nora` vendored with our fixes (Recreate, full `[auth]`, PVC-safe S3 mode, `s3_credentials_dir`, envFrom secrets). Provenance, differences and re-sync: `maestra/charts/nora/MAESTRA-CHART.md`.
