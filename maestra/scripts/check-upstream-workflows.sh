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
#   - GitHub reports a DISABLED workflow, or an unlisted non-maestra one, as active.
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
