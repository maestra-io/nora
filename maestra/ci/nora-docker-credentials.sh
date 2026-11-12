#!/usr/bin/env bash
# Docker pulls through nora (packages.maestra.io, issues-maestra#1649) in a GitHub Actions
# job with `id-token: write`: a docker credential helper mints a fresh GitHub OIDC token per
# pull (the token lives minutes), so nothing is stored as a secret. Copy of the
# nora-cred-helper block of maestra-io/github-actions service-build.yml.
set -euo pipefail
AUDIENCE=${AUDIENCE:-packages.maestra.io}
PACKAGES_URL=${PACKAGES_URL:-https://packages.maestra.io}
bin="$RUNNER_TEMP/nora-bin"; mkdir -p "$bin"
# The job's OIDC request URL and token go to a 0600 file next to the helper: docker runs it
# without the job's environment.
( umask 077; printf 'url=%q\ntoken=%q\naud=%q\n' "$ACTIONS_ID_TOKEN_REQUEST_URL" \
  "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$AUDIENCE" > "$bin/oidc.env" )
cat > "$bin/docker-credential-nora" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "${1:-}" = get ] || exit 0
server=$(cat) # docker sends it without a newline
. "${BASH_SOURCE[0]%/*}/oidc.env"
t=$(curl -sSf --retry 3 --connect-timeout 10 --max-time 30 -H "Authorization: bearer $token" \
  "$url&audience=$aud" | jq -r '.value // empty')
[ -n "$t" ]
jq -cn --arg s "$server" --arg t "$t" '{ServerURL: $s, Username: "token", Secret: $t}'
EOF
chmod 755 "$bin/docker-credential-nora"
echo "$bin" >> "$GITHUB_PATH"
export PATH="$bin:$PATH"
host="${PACKAGES_URL#*://}"; host="${host%%/*}"
cfg="${DOCKER_CONFIG:-$HOME/.docker}/config.json"; mkdir -p "$(dirname "$cfg")"
[ -s "$cfg" ] || echo '{}' > "$cfg"
# credHelpers wins over a stored auths entry for the host; drop a stale one anyway.
jq --arg h "$host" '.credHelpers[$h] = "nora" | del(.auths[$h])' "$cfg" > "$cfg.t" \
  && mv "$cfg.t" "$cfg"
# Prove the helper answers before the pulls depend on it.
printf '%s' "$host" | docker-credential-nora get | jq -e '.Secret | length > 0' >/dev/null
