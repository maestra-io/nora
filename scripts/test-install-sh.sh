#!/usr/bin/env bash
# Self-test for dist/install.sh, run offline against stub curl/cosign/sudo/uname/id.
# Audit A009: staging happens in a private mktemp dir and files land through
# `sudo install` with explicit owner and mode, never `sudo mv` of a /tmp name.
# Audit A010: the binary is installed only after `cosign verify-blob --bundle`
# passes; a failed or impossible check stops the script unless NORA_SKIP_VERIFY=1.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/dist/install.sh"
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
FAILURES=0

ok() { echo "  OK: $1"; }
bad() { echo "FAIL: $1"; echo "$OUT"; FAILURES=$((FAILURES + 1)); }
check() { local d="$1"; shift; if "$@"; then ok "$d"; else bad "$d"; fi; }      # description, command...
check_not() { local d="$1"; shift; if "$@"; then bad "$d"; else ok "$d"; fi; }  # description, command...

mkdir -p "$T/stubs" "$T/nocosign"
cat > "$T/stubs/curl" <<'EOF'
#!/usr/bin/env bash
out=""; prev=""
for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; done
echo "${!#}" >> "$LOGS/curl"
printf 'payload\n' > "$out"
EOF
cat > "$T/stubs/cosign" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" >> "$LOGS/cosign"
exit "${COSIGN_RC:-0}"
EOF
cat > "$T/stubs/sudo" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "$LOGS/sudo"
EOF
cat > "$T/stubs/uname" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = "-s" ]; then echo Linux; else echo "${STUB_ARCH:-x86_64}"; fi
EOF
printf '#!/usr/bin/env bash\nexit 0\n' > "$T/stubs/id"
chmod +x "$T/stubs/"*
for s in curl sudo uname id; do cp "$T/stubs/$s" "$T/nocosign/$s"; done

run() { # stub dir, extra env...
    local dir="$1"; shift
    export LOGS="$T/logs"; rm -rf "$LOGS" "$T/tmp"; mkdir -p "$LOGS" "$T/tmp"
    : > "$LOGS/sudo"; : > "$LOGS/curl"; : > "$LOGS/cosign"; RC=
    # A009: pre-planted links at the names the old script staged under.
    echo sentinel > "$T/sentinel"
    for n in nora nora.env nora.service nora.sig nora.pem; do ln -s "$T/sentinel" "$T/tmp/$n"; done
    OUT=$(env -i HOME="$T" PATH="$dir:/usr/bin:/bin" TMPDIR="$T/tmp" LOGS="$LOGS" "$@" bash "$SCRIPT" 2>&1)
    RC=$?
}
# Staging dirs the installed files came from: private (not /tmp or $TMPDIR itself) and gone after exit.
staged_dirs() { awk '$1 == "install" { print $(NF - 1) }' "$LOGS/sudo" | while read -r f; do dirname "$f"; done | sort -u; }
staging_is_private() {
    local d n=0
    while read -r d; do
        n=$((n + 1))
        case "$d" in /tmp|/var/tmp|"$T/tmp") return 1 ;; esac
        [ ! -e "$d" ] || return 1
    done < <(staged_dirs)
    [ "$n" = 1 ]
}
leftovers() { find "$T/tmp" -mindepth 1 ! -type l | wc -l | tr -d ' '; }

# --- verified install -------------------------------------------------------
run "$T/stubs" COSIGN_RC=0
check "verified install exits 0" test "$RC" = 0
check "binary comes from the published amd64 asset" grep -qx "https://github.com/getnora-io/nora/releases/latest/download/nora-linux-amd64" "$LOGS/curl"
check "the Sigstore bundle is fetched" grep -qx "https://github.com/getnora-io/nora/releases/latest/download/nora-linux-amd64.bundle" "$LOGS/curl"
check "cosign checks the bundle" grep -qx -- "--bundle" "$LOGS/cosign"
ID='^https://github\.com/getnora-io/nora/\.github/workflows/release\.yml@refs/tags/v[^/]+$'
check "cosign pins the anchored release.yml identity" grep -qxF -- "$ID" "$LOGS/cosign"
check "binary installed root:root 0755" grep -q "^install -o root -g root -m 0755 /.*/nora /usr/local/bin/nora$" "$LOGS/sudo"
if [ ! -f /etc/nora/nora.env ]; then
    check "env file installed nora:nora 0600" grep -q "^install -o nora -g nora -m 0600 /.*/nora.env /etc/nora/nora.env$" "$LOGS/sudo"
fi
if [ -d /etc/systemd/system ]; then
    check "unit installed root:root 0644" grep -q "^install -o root -g root -m 0644 /.*/nora.service /etc/systemd/system/nora.service$" "$LOGS/sudo"
fi
check_not "nothing is moved into place" grep -qE "^mv |^(chmod|chown) .*/(bin/nora|nora\.env|nora\.service)$" "$LOGS/sudo"
check_not "nothing is staged under a fixed /tmp name" grep -qE "(^| )/tmp/nora" "$LOGS/sudo"
check "pre-planted links are left alone" test "$(cat "$T/sentinel")" = sentinel
check "files are staged in one private dir, removed on exit" staging_is_private
check "nothing is left in TMPDIR" test "$(leftovers)" = 0

run "$T/stubs" COSIGN_RC=0 STUB_ARCH=aarch64
check "aarch64 maps to the published arm64 asset" grep -qx "https://github.com/getnora-io/nora/releases/latest/download/nora-linux-arm64" "$LOGS/curl"

# --- fail closed ------------------------------------------------------------
run "$T/stubs" COSIGN_RC=1
check "a failed signature check exits non-zero" test "$RC" != 0
check "a failed signature check installs nothing" test ! -s "$LOGS/sudo"
check "a failed signature check leaves no staged file" test "$(leftovers)" = 0

run "$T/nocosign"
check "no cosign exits non-zero" test "$RC" != 0
check "no cosign installs nothing" test ! -s "$LOGS/sudo"

run "$T/nocosign" NORA_SKIP_VERIFY=1
check "NORA_SKIP_VERIFY=1 exits 0 without cosign" test "$RC" = 0
check "NORA_SKIP_VERIFY=1 installs the binary" grep -q "^install -o root -g root -m 0755 .*/nora /usr/local/bin/nora$" "$LOGS/sudo"
check "NORA_SKIP_VERIFY=1 warns" grep -q "NOT verified" <<< "$OUT"

# --- the names install.sh asks for are the ones release.yml publishes --------
for asset in nora-linux-amd64 nora-linux-amd64.bundle nora-linux-arm64 nora-linux-arm64.bundle; do
    check "release.yml publishes $asset" grep -qx " *$asset" "$ROOT/.github/workflows/release.yml"
done

[ "$FAILURES" = 0 ] && echo "install.sh self-test PASSED" || exit 1
