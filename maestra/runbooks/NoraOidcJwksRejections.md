# NoraOidcJwksRejections

> **Scope: Maestra only** — `packages.maestra.io`, cluster `us-iota-lw-kube-infra`,
> namespace `nora`, single replica (HelmRelease `maestra-io/fluxcd`
> `iota/us-iota-lw-kube-infra/nora/helm-release.yaml`). Upstream nora has no runbook.

For an automation agent; every step is read-only except **Act**.
Provenance: this alert had no runbook; everything below comes from the first incident
(12.10.2026, Slack <https://maestraio.slack.com/archives/C0BN1L82W8M/p1791816928729459>,
root-cause thread <https://maestraio.slack.com/archives/C0BN1L82W8M/p1791814920896829>),
the code in `nora-registry/src/auth/oidc.rs` and probes re-run while writing. Branches
other than "cold cache after a restart" are code-derived, not incident history:
frequencies unknown.

## What the alert means

| Alert | Expression | `for` | Meaning |
|---|---|---|---|
| `NoraOidcJwksRejections` | `sum by (namespace) (increase(nora_auth_oidc_rejected_total{namespace="nora",reason="jwks"}[10m])) > 5` | 10m | more than 5 OIDC logins in 10m rejected because nora could not get or match the issuer's signing keys |

Defined **in fluxcd, not in this repo**: `metrics.prometheusRule.extraGroups`, group
`nora-maestra`, of the HelmRelease above (next to `NoraRateLimiting`,
`NoraReadinessFlapping`, `NoraTokenVolumeFilling`). Its `runbook_url` and expression
change with a fluxcd PR only. The HelmRelease has
`kustomize.toolkit.fluxcd.io/substitute: disabled`, so `{{ $value }}` is safe there.

The only OIDC provider is `github-actions` (issuer
`https://token.actions.githubusercontent.com`, audience `packages.maestra.io`), so the
alert means **OIDC key-validation failures for tokens claiming that issuer**. It is not
proof that CI is broken: a token with that issuer and an unknown `kid` counts too (a
different issuer is `no_provider`). Say CI is affected only after confirming real
GitHub Actions jobs fail on packages.maestra.io (12.10: they did).

`classify_rejection` maps **any reason containing `JWK`** to `jwks`. Possible reasons
(`nora-registry/src/auth/oidc.rs`):

| Reason string (log `fields.reason`) | Meaning |
|---|---|
| `JWKS fetch failed for github-actions: HTTP error: error sending request for url (<uri>)` | network/timeout to GitHub (5 s per request) |
| `JWKS fetch failed for github-actions: JWKS endpoint returned 404 Not Found` (or another status) | wrong JWKS URI or GitHub-side error |
| `JWKS fetch failed for github-actions: JWKS parse error: …` | body is not a JWKS |
| `JWKS fetch failed for github-actions: previous fetch failed, retrying shortly` | 5 s failure backoff after a failed fetch (since nora#54) — a symptom, read the first reason before it |
| `No matching key (kid=…) in JWKS for provider github-actions` | token signed with a kid absent even after the refetch (key rotation, or a forged/foreign token) |
| `Cannot build key from JWK: …` | malformed key in the JWKS |

`jwt_invalid` (`JWT validation failed: ExpiredSignature`) is a **different reason** and
does not fire this alert: client-side expired tokens, not an incident.

How keys are fetched (since `1.3.4-maestra.1`, maestra-io/nora#54): cache TTL
`jwks_cache_secs: 300`; one refresh at a time (`refresh_lock`); a failed fetch is
remembered for 5 s; on failure an expired cache is served (`JWKS fetch failed, serving
stale keys`). A fetch failure therefore becomes rejections on a **cold cache** (fresh
start), or on a warm cache when a token's `kid` is missing from the stale set (GitHub
rotated keys while refreshes keep failing). URI order: explicit `jwks_uri` (pinned in fluxcd to
`https://token.actions.githubusercontent.com/.well-known/jwks`, fluxcd#22246) >
discovered URI (cached) > fallback `{issuer}/.well-known/jwks.json`, which **GitHub
answers 404**.

## Setup

```bash
CTX=teleport.maestra.io-us-iota-lw-kube-infra
DS=tp-us-iota-lw-kube-infra              # Grafana datasource uid (grafana.maestra.io)
q() { gcx --context maestra metrics query -d "$DS" "$@" -o table; }   # add --time <RFC3339> for the past
```

## Step 1 — Is it still happening, and since when

```bash
q 'sum by (reason) (increase(nora_auth_oidc_rejected_total{namespace="nora"}[5m]))'
q 'sum(changes(kube_pod_container_status_restarts_total{namespace="nora"}[6h]))'
kubectl --context "$CTX" -n nora get pod -l app.kubernetes.io/name=nora \
  -o jsonpath='{range .items[*]}{.metadata.name} restarts={.status.containerStatuses[0].restartCount} last={.status.containerStatuses[0].lastState.terminated.reason}@{.status.containerStatuses[0].lastState.terminated.finishedAt} started={.status.containerStatuses[0].state.running.startedAt} image={.spec.containers[0].image}{"\n"}{end}'
```

Counters reset on restart (`increase` handles it); one series per container, so a
burst can sit on the previous container only.

## Step 2 — Read the reasons from the log

```bash
# current container; add --previous for the one that died (OOM restart)
kubectl --context "$CTX" -n nora logs deploy/nora --since=1h \
  | grep -E 'JWKS fetch failed|auth rejected: credential refused' \
  | jq -r '.fields.message + " | " + (.fields.detail // .fields.reason // .fields.error) + " | " + (.fields.client_ip // "-")' \
  | sort | uniq -c | sort -rn | head
# first/last timestamp of the burst: same grep, then  jq -r .timestamp | sed -n '1p;$p'
```

## Step 3 — Probe the endpoints

```bash
for u in https://token.actions.githubusercontent.com/.well-known/openid-configuration \
         https://token.actions.githubusercontent.com/.well-known/jwks \
         https://token.actions.githubusercontent.com/.well-known/jwks.json; do
  /usr/bin/curl -s -o /dev/null -w "%{http_code} $u\n" "$u"; done
/usr/bin/curl -s https://token.actions.githubusercontent.com/.well-known/openid-configuration | jq -r .jwks_uri
/usr/bin/curl -s https://token.actions.githubusercontent.com/.well-known/jwks | jq -r '.keys[].kid'
# egress from the pod (busybox wget is in the image; CiliumNetworkPolicy nora allows world:443)
kubectl --context "$CTX" -n nora exec deploy/nora -- \
  wget -q -T 5 -O /dev/null -S https://token.actions.githubusercontent.com/.well-known/jwks 2>&1 | head -1
# the URI nora is configured with
kubectl --context "$CTX" -n nora get helmrelease nora -o yaml | grep -n 'jwks_uri'
```

Expected (17:08 UTC 12.10.2026): `200` openid-configuration, `200` `/jwks`, **`404`
`/jwks.json`**; discovery says `jwks_uri` = `…/.well-known/jwks`; pod egress
`HTTP/1.1 200 OK`; 4 kids in the set.

## Step 4 — DECISION GATE

| Signature | Cause | Act |
|---|---|---|
| burst right after a container start (`lastState OOMKilled`, restartCount grew), reasons `error sending request for url (…/jwks.json)` then `JWKS endpoint returned 404`; stops by itself | cold cache + discovery timing out under CPU saturation → fallback `jwks.json` → 404 (12.10 incident, `1.3.3-maestra.9`) | check `jwks_uri` is still pinned and the image is ≥ `1.3.4-maestra.1`; then the restart cause: `NoraHighLatency.md` Step 2–3 (OOM / CPU) |
| `JWKS endpoint returned 404` with `jwks_uri` pinned to `/jwks`, and Step 3 workstation probe of `/jwks` is 404 too | GitHub moved the JWKS | update `jwks_uri` in fluxcd from the `openid-configuration` `jwks_uri` |
| `error sending request` / timeouts, pod `wget` fails while the workstation probe is 200 | egress from the pod (CiliumNetworkPolicy `nora`, DNS, node) | `kubectl --context "$CTX" -n nora get ciliumnetworkpolicy nora -o yaml`; fix the policy in fluxcd |
| errors from both workstation and pod, `githubstatus.com` shows an Actions incident | GitHub outage | nothing to fix; stale keys cover a warm pod, so avoid restarting nora meanwhile |
| `No matching key (kid=…)` with a kid that is in Step 3's kid list | cached set older than the rotation; refetch should cure it within 60 s | if it persists, look for `JWKS fetch failed, serving stale keys` in the log and run the pod egress probe (Step 3): refreshes failing → egress/GitHub rows above; refreshes succeeding → open an issue in maestra-io/nora with the log |
| `No matching key (kid=…)` with a kid absent from GitHub's list | foreign or forged token, not GitHub Actions | find the caller (audit log by time); nothing to fix in nora |
| only `previous fetch failed, retrying shortly` | backoff after a failed fetch | read the earlier reason; it is the real one |

## Act

All changes go through PRs, never by hand:

- Config (`jwks_uri`, resources, image tag): `maestra-io/fluxcd`
  `iota/us-iota-lw-kube-infra/nora/helm-release.yaml`, `config.auth.oidc.providers`.
- Code: `maestra-io/nora`, PR to `maestra/main`; tagging `v<version>-maestra.N` lets the
  release workflow build the image — do not build images locally.

## Verify

- `q 'sum by (reason) (increase(nora_auth_oidc_rejected_total{namespace="nora"}[5m]))'`
  shows no `jwks` for ≥ 10 min (after 12.10: only `jwt_invalid`, 4 in 55 min);
- the alert resolved in Rootly; no new restarts in Step 1;
- a GitHub Actions job that restores/publishes from packages.maestra.io is green.

## Case history

| Date (UTC) | Object | Cause | Category | What helped | Thread |
|---|---|---|---|---|---|
| 12.10.2026, burst 14:43–14:47 (970 rejections in one container), Rootly `P6kLb3` resolved 15:00:27 | nora `1.3.3-maestra.9`, iota | OOM restarts (2Gi) under CPU saturation from musl malloc lock contention; every restart left the JWKS cache empty and every request with a GitHub OIDC token ran discovery (5 s timeout) + JWKS fetch itself, no single-flight, no failure memory; discovery failed → fallback `/.well-known/jwks.json` → GitHub 404. Log: `error sending request for url (…/jwks.json)`, then `JWKS endpoint returned 404`. CI OIDC restores/publishes failed meanwhile | cold cache after restart | `jwks_uri` pinned to `/.well-known/jwks` (fluxcd#22246); single-flight `refresh_lock`, 5 s failure backoff, cached discovered URI (maestra-io/nora#54, `v1.3.4-maestra.1`, fluxcd#22257, live 16:10); memory 2Gi→4Gi (fluxcd#22241); mimalloc (maestra-io/nora#53). After: zero `jwks` rejections | <https://maestraio.slack.com/archives/C0BN1L82W8M/p1791816928729459> |

## Reply format for the alert thread

Diagnosis post: rejection count and window, top log reason verbatim, restart/OOM state,
Step 3 probe codes, the Step 4 row that matched, plan with PR links. Resolution post:
zero `jwks` rejections since HH:MM UTC and the Rootly resolve time.
