# Maestra fork of nora

Real GitHub fork of [getnora-io/nora](https://github.com/getnora-io/nora); tracking issue maestra-io/issues-maestra#1442.

- `main` is an untouched mirror of upstream `main`: fast-forward only, never commit to it.
- `maestra/main` (default branch) is upstream `main` plus our commits. All our work lands here via PRs.

Maestra-only changes (not upstream):
- `[storage] s3_credentials_dir` / `NORA_STORAGE_S3_CREDENTIALS_DIR`: S3 credentials (`access_key_id`, `secret_access_key`, optional `session_token`) read from files and re-read every 60 s, for the rotating STS-style R2 creds Vault mints (packages.maestra.io, issues-maestra#1442).

Update from upstream:
```sh
git fetch upstream && git checkout main && git merge --ff-only upstream/main && git push origin main
git checkout maestra/main && git merge main && git push origin maestra/main
```

Merge, not rebase: `maestra/main` is the default branch with open PRs on it, a rebase would force-push it and invalidate every branch cut from it; a merge resolves each upstream conflict once, in one commit.
Changes meant for upstream: branch from `main`, cherry-pick, open the PR against getnora-io/nora.
