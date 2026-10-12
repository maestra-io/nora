# nora Helm chart (Maestra fork)

Vendored from [getnora-io/helm-charts](https://github.com/getnora-io/helm-charts) `charts/nora`, chart `0.4.11` (appVersion `1.3.3`) at `1530cb5c3c37322b843a9822ffe5879d30f6a55b`, the version the packages.maestra.io HelmRelease pinned.
The first commit on this path is the verbatim copy; every later commit is ours. Version in the tree: `<upstream>-maestra.<n>`; the published chart is versioned by release tag (below).

## What differs from upstream

- `strategy: Recreate`, `preStopSleepSeconds` (5), `terminationGracePeriodSeconds` (40, render fails if it cannot cover preStop + `shutdown_timeout` + 10 s), `deploymentAnnotations`, no PDB (README "Rollout").
- `image.repository` defaults to our ECR `nora`; `image.digest` → `repository:tag@digest`; memory request == limit; hardened securityContext.
- The whole `[auth]` section: `trusted_proxies`, `admin_users`, `docker_anon_pull`, `public_web_ui`, `public_metrics`, `token_cache_ttl`, provider `namespace_scope` / `namespace_scope_enforcement`, rule `namespace_scope`; explicit provider `enabled: false` kept.
- `storage.mode: s3` refuses `persistence.enabled: false` (tokens, quarantine ledger, audit live on `/data`) unless `persistence.allowEphemeral`; `token_storage: /data/tokens`.
- `config.storage.s3Credentials.existingSecret` → directory mount + `s3_credentials_dir` (fork-only key, see `MAESTRA.md`).
- `existingSecret` is an `envFrom` secretRef (nora never read the mounted `secrets.toml`); `extraVolumes` / `extraVolumeMounts`.
- `[audit] mode` (default `stdout`), `[circuit_breaker]` (on), `[nuget]` (`metadata_proxy_timeout` 15 s), extra `[server]` keys.
- `spool` (off by default, on in `ci/maestra-values.yaml`): size-limited emptyDir for the disk spools, rendered as `server.spool_dir` with `spool_max_mb` below the size limit and a matching `ephemeral-storage` request/limit.
- `ci/maestra-values.yaml`: our HelmRelease (fluxcd `iota/us-iota-lw-kube-infra/nora`) as values for this chart.

## Re-sync from upstream

```sh
base=1530cb5c3c37322b843a9822ffe5879d30f6a55b          # vendored upstream commit
git clone -q https://github.com/getnora-io/helm-charts /tmp/hc
git -C /tmp/hc diff "$base" HEAD -- charts/nora > /tmp/upstream.patch
git apply -3 -p3 --directory=maestra/charts/nora /tmp/upstream.patch   # resolve conflicts, then
# set Chart.yaml version to <new upstream version>-maestra.1 and update `base` + the version above
helm unittest maestra/charts/nora
helm lint --strict maestra/charts/nora -f maestra/charts/nora/ci/maestra-values.yaml
```

## Checks

`helm unittest maestra/charts/nora` (suites in `tests/`, ours marked `# Maestra`), and the `helm chart` job in `.github/workflows/maestra-ci.yml` (lint + template with default and Maestra values).

## Publishing

`.github/workflows/maestra-release.yml`, on tag `v<version>-maestra.<n>`, after the image push: `oci://515260921971.dkr.ecr.us-west-2.amazonaws.com/charts/nora:<version>-maestra.<n>`, version and appVersion = the image tag, so the default image is the image of that release. The job summary prints chart and image digests.

Not done yet: pointing the HelmRelease at it, which drops its postRenderer patches and the separate config ConfigMap.
