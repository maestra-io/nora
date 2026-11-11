#!/usr/bin/env bash
# Self-test for check-upstream-workflows.sh: a check that never fails reads like a clean repo.
set -uo pipefail
CHECK="$(cd "$(dirname "$0")" && pwd)/check-upstream-workflows.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
FAILURES=0
unset GH_TOKEN

expect() { # description, expected exit code, expected output fragment
    if [ "$RC" = "$2" ] && echo "$OUT" | grep -q "$3"; then
        echo "  OK: $1"
    else
        echo "FAIL: $1 (exit $RC, expected $2 and '$3')"; echo "$OUT"; FAILURES=$((FAILURES + 1))
    fi
}
run() { OUT=$(WORKFLOWS_DIR="$TMP/wf" STATES_FILE="$TMP/states" bash "$CHECK" 2>&1); RC=$?; }

mkdir "$TMP/wf"
touch "$TMP/wf/maestra-ci.yml" "$TMP/wf/release.yml" "$TMP/wf/gitleaks.yml"
printf '%s\n' ".github/workflows/maestra-ci.yml active" ".github/workflows/release.yml disabled_manually" \
    ".github/workflows/gitleaks.yml active" > "$TMP/states"
run; expect "listed files, upstream release disabled: passes" 0 "upstream workflows OK"

touch "$TMP/wf/release-images.yml"
run; expect "a workflow upstream added is reported" 1 "release-images.yml is not a maestra-"
rm "$TMP/wf/release-images.yml"

printf '%s\n' ".github/workflows/release.yml active" > "$TMP/states"
run; expect "an enabled upstream release is reported" 1 "release.yml is active on GitHub"

printf '%s\n' ".github/workflows/new-upstream.yml active" > "$TMP/states"
run; expect "an active workflow known only to GitHub is reported" 1 "new-upstream.yml is active on GitHub"

[ "$FAILURES" = 0 ] && echo "check-upstream-workflows self-test PASSED" || exit 1
