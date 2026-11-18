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

REAL_RELEASE="$(cd "$(dirname "$0")/../.." && pwd)/.github/workflows/maestra-release.yml"
mkdir "$TMP/wf"
touch "$TMP/wf/maestra-ci.yml" "$TMP/wf/release.yml" "$TMP/wf/gitleaks.yml"
cp "$REAL_RELEASE" "$TMP/wf/maestra-release.yml"
printf '%s\n' ".github/workflows/maestra-ci.yml active" ".github/workflows/release.yml disabled_manually" \
    ".github/workflows/gitleaks.yml active" > "$TMP/states"
run; expect "listed files, upstream release disabled: passes" 0 "upstream workflows OK"

touch "$TMP/wf/release-images.yml"
run; expect "a workflow upstream added is reported" 1 "release-images.yml is not a maestra-"
rm "$TMP/wf/release-images.yml"

printf '%s\n' ".github/workflows/release.yml active" > "$TMP/states"
run; expect "an enabled upstream release is reported" 1 "release.yml is active on GitHub"

touch "$TMP/wf/auto-reland.yml"
printf '%s\n' ".github/workflows/auto-reland.yml active" > "$TMP/states"
run; expect "an enabled upstream auto-reland is reported (audit A003)" 1 "auto-reland.yml is active on GitHub"
rm "$TMP/wf/auto-reland.yml"

printf '%s\n' ".github/workflows/new-upstream.yml active" > "$TMP/states"
run; expect "an active workflow known only to GitHub is reported" 1 "new-upstream.yml is active on GitHub"

printf '%s\n' ".github/workflows/release.yml disabled_manually" "dynamic/dependabot/update-graph active" > "$TMP/states"
run; expect "a workflow GitHub runs itself is not upstream's" 0 "upstream workflows OK"
printf '%s\n' "dynamic/dependabot/update-graph active" ".github/workflows/release.yml active" > "$TMP/states"
run; expect "a GitHub-run workflow does not hide an enabled upstream release" 1 "release.yml is active on GitHub"

# Release gate (audit A016), on edited copies of the real maestra-release.yml.
printf '%s\n' ".github/workflows/release.yml disabled_manually" > "$TMP/states"
release_variant() { # description, expected output fragment, sed program
    sed "$3" "$REAL_RELEASE" > "$TMP/wf/maestra-release.yml"
    run; expect "$1" 1 "$2"
}
release_variant "image job without the protected environment is reported" \
    "job image is not in environment nora-release" '/^    environment: nora-release$/d'
release_variant "image job in another environment is reported" \
    "job image is not in environment nora-release" 's/^    environment: nora-release$/    environment: scratch/'
release_variant "image job that skips verify and ci is reported" \
    "job image does not need \[verify, ci\]" 's/^    needs: \[verify, ci\]$/    needs: []/'
release_variant "an unanchored tag check is reported" \
    "tag check accepts v1.4.3-maestra.15-unreviewed" 's/-maestra\\\.\[0-9\]+\$ \]\]/-maestra\\.[0-9]+ ]]/'
# shellcheck disable=SC2016  # $GIT_TAG is matched literally
release_variant "a tag check only in verify is reported" \
    "do not share one" '/^  image:$/,$ s/\[\[ "\$GIT_TAG" =~ .* \]\]/true/'
# shellcheck disable=SC2016  # workflow expressions are written literally
release_variant "an image job that re-reads the tag by name is reported (audit R18)" \
    'checks out refs/tags/${{ env.GIT_TAG }}, not' '/^  image:$/,$ s/ref: \${{ github.sha }}/ref: refs\/tags\/${{ env.GIT_TAG }}/'
# shellcheck disable=SC2016  # workflow expressions are written literally
release_variant "a ci call on the tag name is reported (audit R18)" \
    'checks out refs/tags/${{ github.ref_name }}, not' '/^  ci:$/,/^  image:$/ s/ref: \${{ github.sha }}/ref: refs\/tags\/${{ github.ref_name }}/'
release_variant "an OIDC token for every job is reported (audit R04)" \
    "the workflow (top level) gets id-token: write" 's/^  contents: read$/  contents: read\n  id-token: write/'
release_variant "an OIDC token for verify is reported (audit R04)" \
    "job verify gets id-token: write" 's/^    name: Tag is on maestra\/main$/&\n    permissions:\n      id-token: write/'
rm "$TMP/wf/maestra-release.yml"
run; expect "a missing maestra-release.yml is reported" 1 "maestra-release.yml is missing"
cp "$REAL_RELEASE" "$TMP/wf/maestra-release.yml"

# Python dependencies (audit A103), on the real workflows and on edited copies.
REAL_WF="$(dirname "$REAL_RELEASE")"
for f in maestra-ci.yml maestra-sync-public-ids.yml; do cp "$REAL_WF/$f" "$TMP/wf/$f"; done
run; expect "the real workflows install Python dependencies by hash" 0 "upstream workflows OK"
# shellcheck disable=SC2016  # the workflow line is written literally
printf '%s\n' '      - run: "$RUNNER_TEMP/venv/bin/pip" install --quiet requests==2.32.5' >> "$TMP/wf/maestra-ci.yml"
run; expect "a pip install by version only is reported" 1 "maestra-ci.yml:[0-9]*: pip install without --require-hashes"
cp "$REAL_WF/maestra-ci.yml" "$TMP/wf/maestra-ci.yml"
sed 's/ --require-hashes//' "$REAL_WF/maestra-sync-public-ids.yml" > "$TMP/wf/maestra-sync-public-ids.yml"
run; expect "the sync job without --require-hashes is reported" 1 "maestra-sync-public-ids.yml:[0-9]*: pip install without"
cp "$REAL_WF/maestra-sync-public-ids.yml" "$TMP/wf/maestra-sync-public-ids.yml"
for pip in pip3 pip3.12 "uv pip" "python3 -m pip"; do # audit R26
    cp "$REAL_WF/maestra-ci.yml" "$TMP/wf/maestra-ci.yml"
    printf '      - run: %s install requests==2.32.5\n' "$pip" >> "$TMP/wf/maestra-ci.yml"
    run; expect "a hash-less '$pip install' is reported" 1 "maestra-ci.yml:[0-9]*: pip install without --require-hashes"
done

[ "$FAILURES" = 0 ] && echo "check-upstream-workflows self-test PASSED" || exit 1
