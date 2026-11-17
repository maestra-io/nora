#!/usr/bin/env bash
# Self-test for the release supply chain section of coherence-check.sh: an unpinned
# Dockerfile base (audit A001) and a loose cosign signer identity (audit A008) fail it.
set -uo pipefail
CHECK="$(cd "$(dirname "$0")" && pwd)/coherence-check.sh"
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
FAILURES=0
mkdir "$T/signers"

run() { OUT=$(COHERENCE_DOCKERFILE="$T/Dockerfile" COHERENCE_SIGNER_DIRS="$T/signers" bash "$CHECK" 2>&1); RC=$?; }
expect() { # description, expected exit code, expected output fragment (empty: no FAIL line)
    local hit
    if [ -n "$3" ]; then hit=$(grep -cF -- "$3" <<< "$OUT"); else hit=$((1 - $(grep -c '^FAIL' <<< "$OUT"))); fi
    if [ "$RC" = "$2" ] && [ "$hit" -ge 1 ]; then
        echo "  OK: $1"
    else
        echo "FAIL: $1 (exit $RC, expected $2 and '$3')"; grep '^FAIL' <<< "$OUT"; FAILURES=$((FAILURES + 1))
    fi
}
dockerfile() { printf '%s\n' "$@" > "$T/Dockerfile"; }
D=sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0
GOOD="SIGNER_IDENTITY='^https://github\\.com/getnora-io/nora/\\.github/workflows/release\\.yml@refs/tags/v[^/]+\$'"
# shellcheck disable=SC2016  # fixture script text
USE='cosign verify-blob --certificate-identity-regexp "$SIGNER_IDENTITY" x'

dockerfile "FROM alpine:3.23@$D AS builder" "FROM scratch AS binary" "FROM builder AS again" \
    "FROM registry.red-soft.ru/ubi8/ubi-minimal AS redos" "FROM registry.astralinux.ru/library/astra/ubi17:latest AS astra" \
    "FROM --platform=linux/amd64 alpine:3.23@$D"
printf '%s\n' "$GOOD" "$USE" > "$T/signers/ok.sh"
run; expect "pinned bases, exempt RU stages and the canonical signer pass" 0 ""

dockerfile "FROM alpine:3.23@$D" "FROM foo:latest AS x"
run; expect "an unpinned base fails" 1 "FROM foo:latest AS x is not pinned"
dockerfile "from --platform=linux/arm64 debian:12"
run; expect "an unpinned base behind --platform fails" 1 "FROM debian:12 is not pinned"
dockerfile "FROM debian:12 AS redos2"
run; expect "the exemption is by exact stage name" 1 "FROM debian:12 AS redos2 is not pinned"

dockerfile "FROM alpine:3.23@$D"
printf '%s\n' 'cosign verify-blob --certificate-identity-regexp "github.com/getnora-io/nora" x' > "$T/signers/loose.sh"
run; expect "a literal unanchored identity fails" 1 "must be \"\$SIGNER_IDENTITY\""
rm "$T/signers/loose.sh"

printf '%s\n' "SIGNER_IDENTITY='github.com/getnora-io/nora'" "$USE" > "$T/signers/loose.sh"
run; expect "a loose SIGNER_IDENTITY fails" 1 "SIGNER_IDENTITY is not the release.yml signer"
rm "$T/signers/loose.sh"

printf '%s\n' "$USE" > "$T/signers/unset.sh"
run; expect "a script using an unset SIGNER_IDENTITY fails" 1 "does not set it to the release.yml signer"
rm "$T/signers/unset.sh"

OUT=$(bash "$CHECK" 2>&1); RC=$?
expect "the repository itself passes" 0 "cosign checks pin the release.yml signer"

[ "$FAILURES" = 0 ] && echo "coherence-check self-test PASSED" || exit 1
