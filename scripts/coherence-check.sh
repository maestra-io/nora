#!/usr/bin/env bash
# Coherence check — deterministic cross-layer consistency validation
# Catches: version drift, undocumented env vars, registry list mismatch
# Runs in CI (<5s, no dependencies beyond bash+grep)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ERRORS=0
WARNINGS=0

fail() { echo "FAIL: $1"; ERRORS=$((ERRORS + 1)); }
warn() { echo "WARN: $1"; WARNINGS=$((WARNINGS + 1)); }
ok()   { echo "  OK: $1"; }

echo "=== NORA Coherence Check ==="
echo ""

# ── 1. Version sync: Cargo.toml (workspace) ↔ openapi.rs ──────────────────

CARGO_VERSION=$(grep -m1 '^version = ' "$REPO_ROOT/Cargo.toml" | grep -oP '"\K[^"]+')
OPENAPI_VERSION=$(grep -oP 'version = "\K[^"]+' "$REPO_ROOT/nora-registry/src/openapi.rs" | head -1)

echo "--- Version Sync ---"
if [ "$CARGO_VERSION" = "$OPENAPI_VERSION" ]; then
    ok "Cargo.toml ($CARGO_VERSION) = openapi.rs ($OPENAPI_VERSION)"
else
    fail "Cargo.toml ($CARGO_VERSION) != openapi.rs ($OPENAPI_VERSION)"
fi

# CHANGELOG should mention current version (unless Unreleased-only)
if grep -q "\[$CARGO_VERSION\]" "$REPO_ROOT/CHANGELOG.md"; then
    ok "CHANGELOG contains [$CARGO_VERSION]"
else
    warn "CHANGELOG missing [$CARGO_VERSION] — acceptable if version just bumped"
fi
echo ""

# ── 2. Env vars: README table ⊆ config/ apply_env_overrides() ──────────

echo "--- Env Vars (README → Code) ---"
README_VARS=$(grep -oP 'NORA_[A-Z_]+' "$REPO_ROOT/README.md" | sort -u)
CODE_VARS=$(grep -roP 'NORA_[A-Z_]+' "$REPO_ROOT/nora-registry/src/config/" | grep -oP 'NORA_[A-Z_]+' | sort -u)

for var in $README_VARS; do
    if echo "$CODE_VARS" | grep -qx "$var"; then
        ok "$var exists in code"
    else
        fail "$var in README but NOT in config/"
    fi
done
echo ""

# ── 3. Registry list consistency ──────────────────────────────────────────

echo "--- Registry List ---"
# Source of truth: Router mounts in main.rs or lib.rs
EXPECTED_REGISTRIES="docker maven npm cargo pypi go raw gems terraform ansible nuget pub conan rpm deb cpan hf"

for reg in $EXPECTED_REGISTRIES; do
    # Check README mentions it
    if grep -qi "$reg" "$REPO_ROOT/README.md"; then
        ok "README mentions $reg"
    else
        fail "README missing registry: $reg"
    fi
done
echo ""

# ── 4. allow(dead_code) budget ────────────────────────────────────────────

echo "--- Dead Code Budget ---"
DEAD_CODE_COUNT=$(grep -rc 'allow(dead_code)' "$REPO_ROOT/nora-registry/src/" 2>/dev/null | awk -F: '{s+=$2} END {print s}')
DEAD_CODE_BUDGET=35

if [ "$DEAD_CODE_COUNT" -le "$DEAD_CODE_BUDGET" ]; then
    ok "allow(dead_code): $DEAD_CODE_COUNT (budget: $DEAD_CODE_BUDGET)"
else
    fail "allow(dead_code): $DEAD_CODE_COUNT exceeds budget $DEAD_CODE_BUDGET — review new additions"
fi
echo ""

# ── 5. License file matches Cargo.toml ────────────────────────────────────

echo "--- License ---"
CARGO_LICENSE=$(grep -m1 '^license' "$REPO_ROOT/Cargo.toml" | grep -oP '"\K[^"]+' || echo "")
if [ -f "$REPO_ROOT/LICENSE" ]; then
    if [ "$CARGO_LICENSE" = "MIT" ] && grep -q "MIT License" "$REPO_ROOT/LICENSE"; then
        ok "Cargo.toml license ($CARGO_LICENSE) matches LICENSE file"
    elif [ -n "$CARGO_LICENSE" ]; then
        warn "Cargo.toml says $CARGO_LICENSE — verify LICENSE file matches"
    fi
else
    fail "LICENSE file missing"
fi
echo ""

# ── 6. Silent error swallowing: _ => None without logging ─────────────────

echo "--- Silent Error Check (storage/handlers) ---"
SILENT_ERRORS=0
# Find `_ => None` or `_ => { None }` patterns in critical paths without tracing nearby
while IFS=: read -r file line content; do
    # Check 3 lines above for tracing/log
    start=$((line > 3 ? line - 3 : 1))
    context=$(sed -n "${start},${line}p" "$file")
    if ! echo "$context" | grep -qE 'tracing::|log::|error!|warn!'; then
        warn "Silent error at $file:$line — consider adding tracing"
        SILENT_ERRORS=$((SILENT_ERRORS + 1))
    fi
done < <(grep -rn '_ => None\|_ => {\s*None' \
    "$REPO_ROOT/nora-registry/src/storage/" \
    "$REPO_ROOT/nora-registry/src/registry/" \
    2>/dev/null || true)

if [ "$SILENT_ERRORS" -eq 0 ]; then
    ok "No silent error swallowing in storage/handlers"
fi
echo ""

# ── 7. CANCEL-SAFETY annotations ─────────────────────────────────────────

echo "--- Cancel-Safety Annotations ---"
SRC="$REPO_ROOT/nora-registry/src"

# Check select! macros (exclude comments and test code)
SELECT_MISSING=0
while IFS=: read -r file lineno _content; do
    # Check if CANCEL-SAFETY appears within 5 lines before
    start=$((lineno > 5 ? lineno - 5 : 1))
    if ! sed -n "${start},${lineno}p" "$file" | grep -q 'CANCEL-SAFETY'; then
        warn "select! without CANCEL-SAFETY at $file:$lineno"
        SELECT_MISSING=$((SELECT_MISSING + 1))
    fi
done < <(grep -rn 'tokio::select!' "$SRC" --include='*.rs' | grep -v '//.*select!' | grep -v '_test\|#\[test\|#\[cfg(test' || true)

# Check tokio::time::timeout (the same CANCEL-SAFETY requirement)
while IFS=: read -r file lineno _content; do
    start=$((lineno > 5 ? lineno - 5 : 1))
    if ! sed -n "${start},${lineno}p" "$file" | grep -q 'CANCEL-SAFETY'; then
        warn "tokio::time::timeout without CANCEL-SAFETY at $file:$lineno"
        SELECT_MISSING=$((SELECT_MISSING + 1))
    fi
done < <(grep -rn 'tokio::time::timeout' "$SRC" --include='*.rs' | grep -v '//.*timeout' | grep -v '_test\|#\[test\|#\[cfg(test' || true)

if [ "$SELECT_MISSING" -eq 0 ]; then
    SELECT_TOTAL=$(grep -rc 'tokio::select!\|tokio::time::timeout' "$SRC" --include='*.rs' 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')
    ok "All select!/timeout macros have CANCEL-SAFETY annotations ($SELECT_TOTAL total)"
fi
echo ""

# ── Namespace scope enforcement coverage (#583) ───────────────────────────
# Every registry whose routes() mounts a write/any route must call
# enforce_namespace_scope, so a new write-capable format cannot silently
# reintroduce the OIDC namespace_scope fail-open.

echo "--- Namespace Scope Enforcement Coverage ---"
NS_COVERED=0
NS_MISSING=0
for ns_file in "$REPO_ROOT"/nora-registry/src/registry/*.rs; do
    ns_base=$(basename "$ns_file")
    [ "$ns_base" = "mod.rs" ] && continue
    ns_routes=$(awk '/pub fn routes\(\)/{flag=1} flag{print} flag&&/^}/{exit}' "$ns_file")
    if echo "$ns_routes" | grep -qE '\b(put|post|delete|any)\('; then
        # maestra: rpm and deb run their writes through registry/os_repo.rs (R4-T11).
        if grep -q 'enforce_namespace_scope' "$ns_file" \
            || { grep -q 'os_repo::' "$ns_file" \
                && grep -q 'enforce_namespace_scope' "$REPO_ROOT/nora-registry/src/registry/os_repo.rs"; }; then
            NS_COVERED=$((NS_COVERED + 1))
        else
            fail "registry/$ns_base mounts a write/any route but never calls enforce_namespace_scope (#583)"
            NS_MISSING=$((NS_MISSING + 1))
        fi
    fi
done
if [ "$NS_MISSING" -eq 0 ]; then
    ok "All write-capable registries enforce namespace_scope ($NS_COVERED modules)"
fi
echo ""

# ── maestra: release supply chain pins (audit A001, A008) ─────────────────
# Every Dockerfile base is pinned by digest: the root Dockerfile and every
# deploy/Dockerfile.* (release.yml builds deploy/Dockerfile.release, audit R28). The
# RU-vendor stages redos and astra are exempt by name: we do not pull from those
# registries to resolve their digests.

echo "--- Release Supply Chain Pins ---"
DOCKERFILE_ROOT="${COHERENCE_DOCKERFILE_ROOT:-$REPO_ROOT}"
FROM_UNPINNED=0
for DOCKERFILE in "$DOCKERFILE_ROOT/Dockerfile" "$DOCKERFILE_ROOT"/deploy/Dockerfile.*; do
    [ -f "$DOCKERFILE" ] || continue
    STAGES=" "
    while read -r -a words; do
        i=1
        while [ "${words[$i]:-}" != "${words[$i]#--}" ]; do i=$((i + 1)); done  # --platform=...
        image="${words[$i]:-}" stage=""
        if [ "$(echo "${words[$((i + 1))]:-}" | tr '[:upper:]' '[:lower:]')" = as ]; then stage="${words[$((i + 2))]:-}"; fi
        case "$image|$stage" in
            scratch\|*|*@sha256:*|*\|redos|*\|astra) ;;
            *) case "$STAGES" in
                   *" $image "*) ;;  # built on an earlier stage
                   *) fail "${DOCKERFILE#"$DOCKERFILE_ROOT"/} FROM $image${stage:+ AS $stage} is not pinned by @sha256: digest"
                      FROM_UNPINNED=$((FROM_UNPINNED + 1)) ;;
               esac ;;
        esac
        if [ -n "$stage" ]; then STAGES="$STAGES$stage "; fi
    done < <(grep -iE '^FROM[[:space:]]' "$DOCKERFILE")
done
[ -f "$DOCKERFILE_ROOT/Dockerfile" ] || { fail "no Dockerfile in $DOCKERFILE_ROOT"; FROM_UNPINNED=1; }
if [ "$FROM_UNPINNED" -eq 0 ]; then ok "Dockerfile and deploy/Dockerfile.* bases are pinned by digest (redos/astra exempt)"; fi

# One signer identity for every cosign check of upstream release artifacts: release.yml
# on a v* tag, anchored at both ends.
CANONICAL_SIGNER='^https://github\.com/getnora-io/nora/\.github/workflows/release\.yml@refs/tags/v[^/]+$'
SIGNER_OK=1
GOOD_SIGNER=https://github.com/getnora-io/nora/.github/workflows/release.yml@refs/tags/v0.9.1
echo "$GOOD_SIGNER" | grep -qE "$CANONICAL_SIGNER" || { fail "signer pattern rejects $GOOD_SIGNER"; SIGNER_OK=0; }
for evil in \
    https://github.com/evil/x/.github/workflows/x.yml@refs/heads/github.com/getnora-io/nora \
    https://github.com/getnora-io/nora-fork/.github/workflows/release.yml@refs/tags/v1 \
    https://github.com/getnora-io/nora/.github/workflows/ci.yml@refs/heads/main \
    https://github.com/getnora-io/nora/.github/workflows/release.yml@refs/heads/v1/x; do
    if echo "$evil" | grep -qE "$CANONICAL_SIGNER"; then fail "signer pattern accepts $evil"; SIGNER_OK=0; fi
done
SIGNER_DIRS=("$REPO_ROOT/dist" "$REPO_ROOT/scripts" "$REPO_ROOT/.github/workflows")
if [ -n "${COHERENCE_SIGNER_DIRS:-}" ]; then SIGNER_DIRS=("$COHERENCE_SIGNER_DIRS"); fi
# shellcheck disable=SC2016  # $SIGNER_IDENTITY is matched literally
while IFS=: read -r file lineno content; do
    case "$content" in
        *'--certificate-identity-regexp "$SIGNER_IDENTITY"'*)
            grep -qxF "SIGNER_IDENTITY='$CANONICAL_SIGNER'" "$file" \
                || { fail "$file:$lineno uses \$SIGNER_IDENTITY but does not set it to the release.yml signer"; SIGNER_OK=0; } ;;
        *) fail "$file:$lineno: --certificate-identity-regexp must be \"\$SIGNER_IDENTITY\""; SIGNER_OK=0 ;;
    esac
done < <(grep -rnF -e '--certificate-identity-regexp' "${SIGNER_DIRS[@]}" \
    --exclude=coherence-check.sh --exclude='test-*.sh' || true)
while IFS=: read -r file lineno content; do
    [ "${content#"${content%%[![:space:]]*}"}" = "SIGNER_IDENTITY='$CANONICAL_SIGNER'" ] \
        || { fail "$file:$lineno: SIGNER_IDENTITY is not the release.yml signer"; SIGNER_OK=0; }
done < <(grep -rnE '^[[:space:]]*SIGNER_IDENTITY=' "${SIGNER_DIRS[@]}" --exclude=coherence-check.sh --exclude='test-*.sh' || true)
if [ "$SIGNER_OK" = 1 ]; then ok "cosign checks pin the release.yml signer"; fi
echo ""

# ── Summary ───────────────────────────────────────────────────────────────

echo "=== Summary ==="
echo "Errors:   $ERRORS"
echo "Warnings: $WARNINGS"

if [ "$ERRORS" -gt 0 ]; then
    echo ""
    echo "Coherence check FAILED with $ERRORS error(s)."
    exit 1
fi

echo "Coherence check PASSED."
exit 0
