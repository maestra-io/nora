# Maestra fork of nora

Real GitHub fork of [getnora-io/nora](https://github.com/getnora-io/nora); tracking issue maestra-io/issues-maestra#1442.

- `main` is an untouched mirror of upstream `main`: fast-forward only, never commit to it.
- `maestra/main` (default branch) is upstream `main` plus our commits. All our work lands here via PRs.

Maestra-only changes (not upstream):
- Hosted NuGet feed retention/repair: `[nuget] hosted_pr_retention_days` (`NORA_NUGET_HOSTED_PR_RETENTION_DAYS`, default 30, 0 = keep all) and `hosted_pr_keep_last` (`NORA_NUGET_HOSTED_PR_KEEP_LAST`, default 20) expire `X.Y.Z-pr.*` versions in a periodic pass (retention interval and dry-run) that also sweeps blob dirs no state document names (>1 h old); `nora nuget rebuild <id>` rewrites `nuget/hosted-meta/{id}.json` from the stored nuspecs; `POST /api/v1/admin/reindex` also re-reads hosted state documents.
- `[storage] s3_credentials_dir` / `NORA_STORAGE_S3_CREDENTIALS_DIR`: S3 credentials (`access_key_id`, `secret_access_key`, optional `session_token`) read from files and re-read every 60 s, for the rotating STS-style R2 creds Vault mints (packages.maestra.io, issues-maestra#1442).

Update from upstream:
```sh
git fetch upstream && git checkout main && git merge --ff-only upstream/main && git push origin main
git checkout maestra/main && git merge main && git push origin maestra/main
```

Merge, not rebase: `maestra/main` is the default branch with open PRs on it, a rebase would force-push it and invalidate every branch cut from it; a merge resolves each upstream conflict once, in one commit.
Changes meant for upstream: branch from `main`, cherry-pick, open the PR against getnora-io/nora.

## CI and releases

- `.github/workflows/maestra-ci.yml`: `cargo test` on PRs into `maestra/main` (RunsOn `pool=build`).
- `.github/workflows/maestra-release.yml`: tag `v<version>-maestra.<n>` (version = `Cargo.toml`) on `maestra/main` builds the upstream `Dockerfile` and pushes `515260921971.dkr.ecr.us-west-2.amazonaws.com/nora:<version>-maestra.<n>` via the Teleport image-push bot (token `image-push-github-actions-nora`, fluxcd `iota/us-iota-lw-kube-infra/teleport-maestra/operator-crs/image-push-tokens.yaml`). Re-run: `gh workflow run maestra-release.yml -f tag=<tag>`.
- Our workflows carry a `maestra-` prefix so upstream merges never conflict on them. Upstream `Release`, `Post-Release Gate` and `PR Image Cleanup` target upstream's ghcr/self-hosted runners and are disabled in this repo (`gh workflow disable`); upstream `Release` would otherwise fire on our `v*` tags.
