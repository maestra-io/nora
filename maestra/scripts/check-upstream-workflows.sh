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
#   - a maestra-* workflow runs `pip install` (pip3, pip3.12, `uv pip`, ...) without
#     --require-hashes (see below).
#
# Usage: GH_TOKEN=... GITHUB_REPOSITORY=maestra-io/nora maestra/scripts/check-upstream-workflows.sh
#        STATES_FILE=<file of "path state" lines> skips the API call (self-test, offline).
#        Without GH_TOKEN and STATES_FILE only the file list is checked.
set -euo pipefail

DISABLED="auto-reland.yml benchmarks.yml ci.yml codeql.yml kani.yml link-check.yml packaging.yml post-release.yml pr-image-cleanup.yml release.yml scorecard.yml"
# gitleaks.yml and security-scan.yml are ours despite the names: the org-wide secret scan and
# the shared security scan (issues-maestra#1649) on pull requests.
ACTIVE="gitleaks.yml security-scan.yml"

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
# `image` accept the same anchored v<version>-maestra.<n> tag pattern. Every checkout is
# of github.sha, never the tag re-read by name (audit R18), and only `image` and `ci`
# get an OIDC token (audit R04).
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
    # shellcheck disable=SC2016  # ${{ github.sha }} is matched literally
    while IFS= read -r line; do
        fail "maestra-release.yml:${line%%:*}: checks out ${line#*ref: }, not \${{ github.sha }}"
    done < <(grep -nE '^[[:space:]]+ref:' "$release" | grep -vF 'ref: ${{ github.sha }}' || true)
    while IFS= read -r where; do
        fail "maestra-release.yml: $where gets id-token: write (only image and ci may)"
    done < <(awk '/^jobs:/ { jobs = 1 } jobs && /^  [^ #][^ ]*:$/ { j = "job " substr($1, 1, length($1) - 1) }
        /^[[:space:]]*id-token:[[:space:]]*write/ { w = jobs ? j : "the workflow (top level)"; if (w != "job image" && w != "job ci") print w }' "$release")
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
    done < <(grep -nE "pip[0-9.]*[\"']?[[:space:]]+install" "$path" | grep -v -- '--require-hashes' || true)
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
        # dynamic/* is run by GitHub itself (Dependency Graph, Dependabot, default code
        # scanning): no file in this repository, nothing of upstream's.
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
