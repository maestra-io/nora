#!/usr/bin/env bash
# Upstream's workflows must not run in this fork: Release fires on any v* tag (ours
# included), builds from RU registries and pushes to ghcr; the rest target `main` and
# ubuntu-latest runners. They are switched off with `gh workflow disable`, a state kept
# outside git: a workflow upstream adds, renames or splits arrives enabled, and a
# re-created repository has all of them enabled.
#
# Fails when
#   - .github/workflows holds a file that is neither maestra-* nor listed below
#     (decide: `gh workflow disable <file>` and add it to DISABLED, or to ACTIVE);
#   - GitHub reports a DISABLED workflow, or an unlisted non-maestra one, as active;
#   - maestra-release.yml loses its release gate (see below);
#   - a maestra-* workflow runs `pip install` without --require-hashes (see below).
#
# Usage: GH_TOKEN=... GITHUB_REPOSITORY=maestra-io/nora maestra/scripts/check-upstream-workflows.sh
#        STATES_FILE=<file of "path state" lines> skips the API call (self-test, offline).
#        Without GH_TOKEN and STATES_FILE only the file list is checked.
set -euo pipefail

DISABLED="auto-reland.yml benchmarks.yml ci.yml codeql.yml kani.yml link-check.yml packaging.yml post-release.yml pr-image-cleanup.yml release.yml scorecard.yml"
# gitleaks.yml is ours despite the name: the org-wide secret scan on pull requests.
ACTIVE="gitleaks.yml"

WORKFLOWS_DIR="${WORKFLOWS_DIR:-$(cd "$(dirname "$0")/../.." && pwd)/.github/workflows}"
failed=0
fail() { echo "FAIL: $1"; failed=1; }
listed() { case " $2 " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

for path in "$WORKFLOWS_DIR"/*; do
    file=$(basename "$path")
    case "$file" in maestra-*) continue ;; esac
    listed "$file" "$DISABLED $ACTIVE" ||
        fail "$file is not a maestra-* workflow and is not listed in $0: disable it (gh workflow disable $file) and list it"
done

# Release gate (audit A016): job `image`, the only one that gets push credentials, runs
# in the protected `nora-release` environment after `verify` and `ci`, and `verify` and
# `image` accept the same anchored v<version>-maestra.<n> tag pattern.
release="$WORKFLOWS_DIR/maestra-release.yml"
job() { awk -v j="  $1:" '$0 == j { on = 1; next } on && /^  [^ #]/ { exit } on' "$release"; }
# shellcheck disable=SC2016  # $GIT_TAG is matched literally
tag_re() { job "$1" | sed -n 's/.*\[\[ "\$GIT_TAG" =~ \(.*\) \]\].*/\1/p'; }
if [ ! -f "$release" ]; then
    fail "maestra-release.yml is missing"
else
    image=$(job image)
    grep -qx '    environment: nora-release' <<<"$image" ||
        fail "maestra-release.yml: job image is not in environment nora-release"
    grep -qx '    needs: \[verify, ci\]' <<<"$image" ||
        fail "maestra-release.yml: job image does not need [verify, ci]"
    re=$(tag_re image)
    if [ -z "$re" ] || [ "$re" != "$(tag_re verify)" ]; then
        fail "maestra-release.yml: verify and image do not share one [[ \"\$GIT_TAG\" =~ ... ]] tag check"
    else
        for t in v1.4.3-maestra.15 v10.20.30-maestra.400; do
            [[ $t =~ $re ]] || fail "maestra-release.yml: tag check refuses $t"
        done
        for t in v1.4.3-maestra.15-unreviewed v1.4.3-maestra.x v1.4.3 v1.4-maestra.1 xv1.4.3-maestra.1; do
            [[ $t =~ $re ]] && fail "maestra-release.yml: tag check accepts $t"
        done
    fi
fi

# Python dependencies (audit A103): a pip install in our workflows takes every package
# by sha256 from a lock (`--require-hashes -r <requirements.txt>`), never by a range.
for path in "$WORKFLOWS_DIR"/maestra-*; do
    [ -f "$path" ] || continue
    while IFS= read -r line; do
        fail "$(basename "$path"):${line%%:*}: pip install without --require-hashes"
    done < <(grep -nE "pip[\"']? install" "$path" | grep -v -- '--require-hashes' || true)
done

states="${STATES_FILE:-}"
if [ -z "$states" ] && [ -n "${GH_TOKEN:-}" ]; then
    states=$(mktemp)
    trap 'rm -f "$states"' EXIT
    gh api "repos/${GITHUB_REPOSITORY}/actions/workflows" --paginate \
        --jq '.workflows[] | "\(.path) \(.state)"' > "$states"
    [ -s "$states" ] || fail "GitHub returned no workflows for ${GITHUB_REPOSITORY}"
fi

if [ -n "$states" ]; then
    while read -r path state; do
        # dynamic/*: GitHub's own workflows (Dependabot's dependency graph for a manifest
        # such as maestra/scripts/import/requirements.txt), not files of this repository.
        case "$path" in dynamic/*) continue ;; esac
        file=$(basename "$path")
        case "$file" in maestra-*) continue ;; esac
        listed "$file" "$ACTIVE" && continue
        [ "$state" = "active" ] && fail "$file is active on GitHub: gh workflow disable $file"
    done < "$states"
    echo "checked workflow states: $(wc -l < "$states" | tr -d ' ')"
else
    echo "no GH_TOKEN and no STATES_FILE: workflow states not checked"
fi

[ "$failed" = 0 ] && echo "upstream workflows OK"
exit "$failed"
