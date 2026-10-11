# Maestra fork of nora

Real GitHub fork of [getnora-io/nora](https://github.com/getnora-io/nora); tracking issue maestra-io/issues-maestra#1442.

- `main` is an untouched mirror of upstream `main`: fast-forward only, never commit to it.
- `maestra/main` (default branch) is upstream `main` plus our commits. All our work lands here via PRs.

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
