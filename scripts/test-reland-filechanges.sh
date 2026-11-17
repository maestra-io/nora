#!/usr/bin/env bash
# Regression test for scripts/reland-build-filechanges.sh.
#
# Guards the auto-reland ARG_MAX bug (#825): a staged file whose base64 is well
# past MAX_ARG_STRLEN (128 KiB/arg) must still produce a valid FileChanges
# payload that round-trips. If anyone reverts the builder to passing contents
# through `jq --arg`, this test fails with "Argument list too long".
# Also checks the empty-diff guard (#798).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
builder="$here/reland-build-filechanges.sh"

fail() { echo "FAIL: $1" >&2; exit 1; }

# --- large + small file build and round-trip ---------------------------------
repo="$(mktemp -d)"
trap 'rm -rf "$repo"' EXIT
git -C "$repo" init -q
git -C "$repo" config user.email t@example.com
git -C "$repo" config user.name test
git -C "$repo" commit -q --allow-empty -m base

# 512 KiB → base64 ≈ 683 KiB, over 5× the 128 KiB single-arg limit.
head -c 524288 /dev/zero | tr '\0' 'A' >"$repo/big.txt"
printf 'hello\n' >"$repo/small.txt"
git -C "$repo" add big.txt small.txt

out="$repo/fc.json"
( cd "$repo" && "$builder" "$out" ) || fail "builder errored on a large staged file"

jq -e . "$out" >/dev/null || fail "output is not valid JSON"
n=$(jq '.additions | length' "$out")
[ "$n" = 2 ] || fail "expected 2 additions, got $n"
jq -r '.additions[] | select(.path=="big.txt") | .contents' "$out" \
  | base64 -d | cmp -s - "$repo/big.txt" \
  || fail "big.txt content did not round-trip through base64"
echo "PASS: large-file FileChanges builds and round-trips ($(wc -c <"$out") bytes JSON)"

# --- empty diff must be rejected (#798) --------------------------------------
empty="$(mktemp -d)"
git -C "$empty" init -q
git -C "$empty" config user.email t@example.com
git -C "$empty" config user.name test
git -C "$empty" commit -q --allow-empty -m base
if ( cd "$empty" && "$builder" "$empty/fc.json" ) 2>/dev/null; then
  fail "empty diff should have been rejected"
fi
echo "PASS: empty diff rejected (#798 guard)"

# --- auto-reland.yml relands the approved commit with the base's builder ----
# Audit A003: the guard requires the last approval to be on the labeled head, and the
# squash fetches that commit, not the moving PR ref. Audit A004: the step that handles
# PR content holds no secret and runs the builder saved from the base.
wf="$here/../.github/workflows/auto-reland.yml"
step_run() { # step name -> its `run: |` block, dedented
  awk -v name="      - name: $1" '
    $0 == name { s = 1; next }
    s && /^      - name: / { exit }
    s && $0 == "        run: |" { r = 1; next }
    r && $0 != "" && substr($0, 1, 10) != "          " { exit }
    r { print substr($0, 11) }' "$wf"
}
step_block() { awk -v name="      - name: $1" '$0 == name { s = 1; print; next } s && /^      - name: / { exit } s' "$wf"; }

grep -qF './scripts/reland-build-filechanges.sh' "$wf" && fail "auto-reland runs the builder from the work tree"
# shellcheck disable=SC2016  # literal workflow text
grep -qF 'pull/$PR/head' "$wf" && fail "auto-reland fetches the moving PR ref"
[ -n "$(step_run 'Squash the approved commit')" ] || fail "auto-reland has no 'Squash the approved commit' step"
step_block 'Squash the approved commit' | grep -q 'secrets\.' && fail "the squash step holds a secret"
step_block 'Reland as a signed commit' | grep -q 'git merge' && fail "the token step merges PR content"
echo "PASS: auto-reland squashes without a token and never runs the PR's builder"

fx="$(mktemp -d)"
trap 'rm -rf "$repo" "$empty" "$fx"' EXIT
mkdir "$fx/bin" "$fx/tmp"

# Guard: a stub gh answers the permission and decision calls and applies the guard's own
# --jq filter to a reviews fixture.
cat >"$fx/bin/gh" <<'GH'
#!/usr/bin/env bash
case "$*" in
  *collaborators*) echo write ;;
  "pr view"*) echo APPROVED ;;
  *"/reviews"*) while [ "$1" != --jq ]; do shift; done; jq -r "$2" "$REVIEWS" ;;
  *) exit 1 ;;
esac
GH
chmod +x "$fx/bin/gh"
step_run 'Guard — approved PR + authorized labeler' >"$fx/guard.sh"
guard() { # head sha, approved commits in order
  local head="$1"; shift
  printf '%s\n' "$@" | jq -R '{state: "APPROVED", commit_id: .}' | jq -s . >"$fx/reviews.json"
  : >"$fx/out"
  PATH="$fx/bin:$PATH" REVIEWS="$fx/reviews.json" GITHUB_OUTPUT="$fx/out" HEAD_SHA="$head" \
    REPO=o/r PR=7 LABELER=m bash "$fx/guard.sh" >/dev/null 2>&1
}
guard bbb aaa bbb || fail "guard refused a head that carries the last approval"
grep -qx 'approved_sha=bbb' "$fx/out" || fail "guard did not hand the approved sha on"
guard bbb bbb aaa && fail "guard accepted a head pushed after the last approval"
guard bbb && fail "guard accepted a PR with no approving review"
echo "PASS: guard relands only a head that carries the last approval"

# Squash: origin holds the base, the approved commit (which also swaps the builder for
# one that leaves a marker) and a commit pushed after the approval.
origin="$fx/origin.git"
git init -q --bare "$origin"
git -C "$origin" config uploadpack.allowAnySHA1InWant true
git init -q "$fx/src"
git -C "$fx/src" config user.email t@example.com
git -C "$fx/src" config user.name test
mkdir "$fx/src/scripts"
cp "$builder" "$fx/src/scripts/reland-build-filechanges.sh"
git -C "$fx/src" add -A && git -C "$fx/src" commit -q -m base
base=$(git -C "$fx/src" rev-parse HEAD)
# shellcheck disable=SC2016  # $1 belongs to the planted script
printf '#!/usr/bin/env bash\ntouch "%s"\necho "{}" > "$1"\n' "$fx/marker" >"$fx/src/scripts/reland-build-filechanges.sh"
echo reviewed >"$fx/src/reviewed.txt"
git -C "$fx/src" add -A && git -C "$fx/src" commit -q -m approved
approved=$(git -C "$fx/src" rev-parse HEAD)
echo unreviewed >"$fx/src/unreviewed.txt"
git -C "$fx/src" add -A && git -C "$fx/src" commit -q -m late
git -C "$fx/src" push -q "$origin" "$base:refs/heads/main" "HEAD:refs/pull/7/head"
git clone -q --branch main "$origin" "$fx/wt"
step_run 'Squash the approved commit' >"$fx/squash.sh"
: >"$fx/out"
( cd "$fx/wt" && RUNNER_TEMP="$fx/tmp" GITHUB_OUTPUT="$fx/out" APPROVED_SHA="$approved" BASE_REF=main \
    bash "$fx/squash.sh" ) >/dev/null 2>&1 || fail "the squash step failed on a clean approved commit"
[ ! -e "$fx/marker" ] || fail "the squash step ran the PR's builder"
paths=$(jq -r '.additions[].path' "$fx/tmp/file_changes.json" | sort | tr '\n' ' ')
[ "$paths" = "reviewed.txt scripts/reland-build-filechanges.sh " ] \
  || fail "the reland carries '$paths', expected the approved commit's two files"
grep -qx "base_sha=$base" "$fx/out" || fail "the squash step did not hand the base sha on"
echo "PASS: the squash relands the approved commit with the base's builder"
