# NoraUnavailable

> **Scope: Maestra only** — `packages.maestra.io`, cluster `us-iota-lw-kube-infra`,
> namespace `nora`, single replica (HelmRelease `maestra-io/fluxcd`
> `iota/us-iota-lw-kube-infra/nora/helm-release.yaml`). Upstream nora has no runbook.

For an automation agent; every step is read-only except **Act**.
Provenance: written after nora was down 10–25 min four times on 19–20.10.2026 with no
alert firing (Slack <https://maestraio.slack.com/archives/C07NA432R4H/p1792503642764279>).
Branches other than "rollout whose new pod does not start" are derived from the chart and
the other runbooks, not from incident history: frequencies unknown.

## What the alert means

| Alert | Expression | `for` | Meaning |
|---|---|---|---|
| `NoraUnavailable` | `max by (cluster, namespace, deployment) (kube_deployment_status_replicas_available{namespace="nora",deployment="nora"}) < 1` | 5m | Deployment `nora/nora` has had no available (Ready) pod for 5 min |

Defined **in fluxcd, not in this repo**: `metrics.prometheusRule.extraGroups`, group
`nora-maestra`, of the HelmRelease above. Severity `high`.

nora runs **one replica with strategy `Recreate`** (the publish lock is in-process, see
the HelmRelease header): every rollout kills the old pod before the new one starts, and
any pod that is not Ready is a full outage. While the alert fires every npm / NuGet / PyPI
restore and publish against packages.maestra.io fails — GitHub Actions CI and laptops.

Why the other alerts stay silent: the `nora_*` rules read nora's own metrics, which vanish
with the pod; `KubeDeploymentReplicasMismatch` resets on every new ReplicaSet
(`changes(kube_deployment_status_replicas_updated[10m]) == 0`) and is warning only;
`TargetDown` resets when the pod changes. A clean rollout measured < 1 min of zero
replicas (20.10 12:25:30–12:26:00 UTC), hence `for: 5m`.

## Setup

```bash
CTX=teleport.maestra.io-us-iota-lw-kube-infra
DS=tp-us-iota-lw-kube-infra              # Grafana datasource uid (grafana.maestra.io)
q() { gcx --context maestra metrics query -d "$DS" "$@" -o table; }   # add --time <RFC3339> for the past
```

## Step 1 — Pod, rollout and events (one call)

```bash
kubectl --context "$CTX" -n nora get deploy,pod -o wide
kubectl --context "$CTX" -n nora get rs --sort-by=.metadata.creationTimestamp | tail -3
kubectl --context "$CTX" -n nora get pod -l app.kubernetes.io/name=nora \
  -o jsonpath='{range .items[*]}{.metadata.name} phase={.status.phase} ready={.status.containerStatuses[0].ready} restarts={.status.containerStatuses[0].restartCount} last={.status.containerStatuses[0].lastState.terminated.reason}/{.status.containerStatuses[0].lastState.terminated.exitCode}@{.status.containerStatuses[0].lastState.terminated.finishedAt} image={.spec.containers[0].image}{"\n"}{end}'
kubectl --context "$CTX" -n nora get events --sort-by=.lastTimestamp | tail -25
kubectl --context "$CTX" -n nora get helmrelease nora -o jsonpath='{.status.lastAttemptedRevision} {.status.conditions[?(@.type=="Ready")].message}{"\n"}'
```

Read: is a new ReplicaSet/image there (a rollout), the last termination reason
(`OOMKilled`, `Error` after `failed startup probe`), `Startup probe failed` /
`Readiness probe failed` events, `FailedScheduling`, image pull errors, `UpgradeFailed`
on the HelmRelease.

## Step 2 — The pod log

```bash
kubectl --context "$CTX" -n nora logs deploy/nora --tail=30
kubectl --context "$CTX" -n nora logs deploy/nora --previous --tail=30   # the killed container
```

The startup probe (`/health`, 30 × 5 s = **150 s budget**) kills a container that has
not opened port 4000 by then. A log that stops after the config lines (`Rate limits
enforced`, `Registry selection …`) with `connect: connection refused` on the probe means
the start-up work did not finish within the budget (20.10: 1.4.0-maestra.3 and
1.4.1-maestra.1). `/ready` follows R2 reachability (periodic bucket LIST): a pod that
runs and is not Ready while `/health` passes points to R2 — see `NoraStorageUnreachable`.

## Step 3 — DECISION GATE

| Signal (Steps 1–2) | Cause | Act |
|---|---|---|
| new ReplicaSet from a version bump, container killed by the startup probe, log stops before the listener | new release starts slower than 150 s or hangs | roll back the image/chart tag in fluxcd to the last good version, or raise `startupProbe.failureThreshold` if the log shows progress (e.g. an index rebuild) |
| `OOMKilled` | memory limit | raise `resources.limits.memory` in fluxcd; check `container_memory_rss` against the limit first |
| running, `/health` ok, `/ready` failing | R2 unreachable or slow | `NoraStorageUnreachable` path: R2 status, egress, credentials in `/r2-creds` |
| `Pending` / `FailedScheduling`, node `SchedulingDisabled` | node drain or lack of capacity | check `#maintenance-notifications` and the node; the drain owner decides |
| `ErrImagePull` / `ImagePullBackOff` | tag/digest missing in ECR or pull secret | fix the tag/digest in fluxcd (`image-pull` secret) |
| none of the above | unknown | escalate with Step 1–2 output |

## Act

All changes go through PRs, never by hand:

- Tag, digest, chart version, resources, probes: `maestra-io/fluxcd`
  `iota/us-iota-lw-kube-infra/nora/helm-release.yaml` (chart version == image tag).
- Code: `maestra-io/nora`, PR to `maestra/main`; tagging `v<version>-maestra.N` lets the
  release workflow build the image — do not build images locally.
- Do not scale to two replicas: two pods race writes to the same packument/index.

## Verify

- `q 'max(kube_deployment_status_replicas_available{namespace="nora",deployment="nora"})'` is `1`;
- `curl -s -o /dev/null -w '%{http_code}\n' https://packages.maestra.io/health` is no longer `503` (it answered 503 at 13:47 UTC 20.10 while the pod was down);
- the alert resolved in Rootly; no new restarts in Step 1 for ≥ 10 min.

## Case history

| Date (UTC) | Object | Cause | What helped | Thread |
|---|---|---|---|---|
| 19.10.2026 19:37:30–19:51:00, 20:07:00–20:21:30, 20:40:30–20:50:00 | nora, iota | not investigated (measured afterwards from kube-state-metrics) | — | <https://maestraio.slack.com/archives/C07NA432R4H/p1792503642764279> |
| 20.10.2026 13:06:30–13:31:30 and from 13:40:30 | nora `1.4.0-maestra.3`, then `1.4.1-maestra.1` | new pod did not open port 4000 within the 150 s startup budget, killed and restarted (log ends at `Rate limits enforced`) | — (this alert did not exist yet) | <https://maestraio.slack.com/archives/C07NA432R4H/p1792503642764279> |

## Reply format for the alert thread

Diagnosis post: down since HH:MM UTC, the Step 3 row that matched with the event or log
line verbatim, the image/chart version, plan with PR links. Resolution post: Ready since
HH:MM UTC, total downtime, the Rootly resolve time.
