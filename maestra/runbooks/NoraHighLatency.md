# NoraHighLatency

> **Scope: Maestra only** — `packages.maestra.io`, cluster `us-iota-lw-kube-infra`,
> namespace `nora`, single replica (HelmRelease `maestra-io/fluxcd`
> `iota/us-iota-lw-kube-infra/nora/helm-release.yaml`). Upstream nora has no runbook.

For an automation agent; every step is read-only except **Act**.
Provenance: this alert had no runbook; everything below comes from the first incident
(12.10.2026, Slack <https://maestraio.slack.com/archives/C0BN1L82W8M/p1791814920896829>)
and probes re-run while writing; the allocator (4a) and link (4d) branches have since
recurred (case history). Step 3 branches are config-derived checks, not incident
history: frequencies unknown.

## What the alert means

| Alert | Expression | `for` | Meaning |
|---|---|---|---|
| `NoraHighLatency` | `histogram_quantile(0.99, sum by (le) (rate(nora_http_request_duration_seconds_bucket[5m]))) > 5` | 5m | p99 of all nora HTTP requests (every registry together) above 5s |

Defined in `deploy/prometheus-rules.yml`, copied byte-for-byte to
`maestra/charts/nora/files/prometheus-rules.yml` (CI `cmp`s them). The cluster gets
it from the nora chart version pinned in the fluxcd HelmRelease, so a rule or
annotation change reaches the cluster only with the next nora release + fluxcd bump.

- Histogram buckets: `0.001 0.005 0.01 0.025 0.05 0.1 0.25 0.5 1 2.5 5 10 +Inf`. The
  top finite bucket is 10s, so **p99 = 10 means "≥ 10s"**, not 10s.
- Normal p99 is **~2–2.5s**, p50 ~1ms (measured 10:00, 13:00, 15:16 UTC 12.10.2026).
- The quantile is over all registries; one slow registry is enough to fire.
- An OOM restart resets the counters, so the alert **flaps**: on 12.10 it fired four
  times between 14:15 and 15:07 UTC (Rootly `pyaioJ`, `QH0utM`, `884gFi`, `be6MaV`).
  A resolve is not a recovery — check Step 1 before closing.

## Setup

```bash
CTX=teleport.maestra.io-us-iota-lw-kube-infra
DS=tp-us-iota-lw-kube-infra              # Grafana datasource uid (grafana.maestra.io)
q() { gcx --context maestra metrics query -d "$DS" "$@" -o table; }   # add --time <RFC3339> for the past
pod_of() { kubectl --context "$CTX" -n nora get pod -l app.kubernetes.io/name=nora \
  -o jsonpath='{range .items[?(@.status.phase=="Running")]}{.metadata.name} {.spec.nodeName}{"\n"}{end}'; }
pod_of    # name + node; re-run after any restart or rollout
```

## Step 1 — Measure latency, load and CPU per request

```bash
q 'histogram_quantile(0.99, sum by (le, registry) (rate(nora_http_request_duration_seconds_bucket[5m])))'
q 'sum(rate(nora_http_request_duration_seconds_count[5m]))'                                    # rps
q 'sum by (status) (rate(nora_http_requests_total[5m]))'
q 'sum by (pod) (rate(container_cpu_usage_seconds_total{namespace="nora",container="nora"}[5m]))'
q 'sum(rate(container_cpu_usage_seconds_total{namespace="nora",container="nora"}[5m])) / sum(rate(nora_http_request_duration_seconds_count[5m]))'   # core-seconds per request
kubectl --context "$CTX" top pod -n nora
```

Reference values (measured from the metrics store):

| UTC 12.10.2026 | Build | rps | p99 | CPU (cores) | core-s / request |
|---|---|---|---|---|---|
| 10:00 | musl malloc | 34 | 2.3s | — | 0.021 |
| 13:00 | musl malloc | 48 | 2.1s | — | 0.008 |
| 14:30 (incident) | musl malloc | 166 | ≥ 10s | 10–26 | **0.083** |
| 15:16 (after fix) | mimalloc | 77 | 2.3s | 0.3 | **0.004** |

At 14:30 69 of the 166 rps were `401` — NuGet clients send an anonymous request first
and retry with credentials, so about half the NuGet requests are 401 handshakes. They
are cheap and normal; do not chase them.

**Branch:** CPU per request ≥ ~0.05 or pod CPU in whole cores while rps is in the
hundreds → Step 2 (CPU contention). CPU per request flat (12.10 16:00: 0.006 at 413 rps,
1.5–1.8 cores) and p99 high → Step 2b (network link) before Step 3. p99 high only for
one registry → Step 3.

## Step 2 — CPU contention: profile the process on the node

```bash
NODE=$(pod_of | awk '{print $2}')
tsh ssh --login=teleport-production "$NODE" \
  'P=$(pgrep -f "nora serve" | head -1); awk "{print \"utime=\"\$14, \"stime=\"\$15}" /proc/$P/stat; nproc; cat /proc/loadavg'
tsh ssh --login=teleport-production "$NODE" \
  'sudo -n perf record -F 199 -g -p $(pgrep -f "nora serve" | head -1) -o /tmp/nora.perf -- sleep 8 >/dev/null 2>&1;
   sudo -n perf report -i /tmp/nora.perf --stdio --no-children --sort sym 2>/dev/null | grep -v "^#" | grep "%" | head -15;
   sudo -n rm -f /tmp/nora.perf'
```

`perf` needs `sudo` (`perf_event_paranoid=4`); `strace` is denied (`ptrace_scope`). Both
`/proc/<pid>/stat` fields are clock ticks (`CLK_TCK=100`), cumulative since start: sample
twice and diff. The node has 32 cores.

| Signature | Meaning | Go to |
|---|---|---|
| `native_queued_spin_lock_slowpath` on top (12.10: 85% of nora CPU), under `futex_wait`/`futex_wake`; `stime` ≥ `utime`; node load ≈ core count (12.10: 26, node at 90% CPU) | allocator lock contention: every tokio worker (32) spins on one malloc lock | Step 4a |
| userspace frames on top (`[.] 0x…`: the binary is stripped, so they show as addresses), `stime` ≪ `utime`, no spinlock in the top 15 (12.10 after the fix: top entry `__handle_mm_fault` 8.8%) | real work: load beyond one replica | Step 4b |

## Step 2b — Network link: the node's 1 Gbit NIC and the pod quota

nora serves every artifact from R2 (no local blob cache), so each download is read from
R2 over the node's public NIC `eno5` (1 Gbit on every iota node) and written back out
towards traefik (`eno6` to the other nodes, `eno5` for the local one). A NuGet burst fills
the link before CPU matters: on 12.10 16:00–16:05 UTC 413 rps pushed `eno5` rx to
982 Mbit/s (98%) and 3.6–7 rps of NuGet requests took > 10s, no 5xx.

```bash
NODE=$(pod_of | awk '{print $2}')
q "rate(node_network_receive_bytes_total{instance=\"$NODE\",device=\"eno5\"}[1m]) * 8 / 1e6"    # Mbit/s, R2 → nora
q "rate(node_network_transmit_bytes_total{instance=\"$NODE\",device=~\"eno5|eno6\"}[1m]) * 8 / 1e6"
q 'sum(rate(container_network_receive_bytes_total{namespace="nora",pod=~"nora-.*"}[1m])) * 8 / 1e6'
```

Since 13.10.2026 the pod carries a Cilium bandwidth quota (`podAnnotations`
`kubernetes.io/ingress-bandwidth: 800M`, `egress-bandwidth: 800M` in the fluxcd
HelmRelease; Cilium bandwidth manager enabled by kubernetes-clusters#165). Confirm it is
in force on the node (`kube-system` exec is RBAC-denied; `nsenter` into the agent):

```bash
tsh ssh --login=teleport-production "$NODE" 'pid=$(pgrep -xo cilium-agent);
  sudo nsenter -t "$pid" -m -p -- cilium-dbg status | grep BandwidthManager;
  sudo nsenter -t "$pid" -m -p -- cilium-dbg bpf bandwidth list'     # nora endpoint: Egress 800M + Ingress 800M
```

| Signature | Meaning | Go to |
|---|---|---|
| `eno5` rx ≈ 800 Mbit/s flat (quota engaged), rps in the hundreds, p99 up only for NuGet | the quota is doing its job: clients queue behind 800 Mbit/s; the node's neighbours are protected | Step 4d |
| `bpf bandwidth list` has no 800M entries for the nora endpoint (or `BandwidthManager: Disabled`), whatever `eno5` shows | the quota is not applied: pod created before the annotation, or the bandwidth manager is off. `eno5` rx alone cannot tell: it is the whole node, another tenant can fill it while nora stays capped | Step 4d |
| `eno5` rx well below 800 and p99 still high | not the link | Step 3 |

## Step 3 — Other causes (check each; the alert does not say which)

```bash
# OOMKilled restarts: counters reset, cold caches, JWKS herd. Memory limit is 4Gi (fluxcd#22241, was 2Gi).
kubectl --context "$CTX" -n nora get pod -l app.kubernetes.io/name=nora \
  -o jsonpath='{range .items[*]}{.metadata.name} restarts={.status.containerStatuses[0].restartCount} last={.status.containerStatuses[0].lastState.terminated.reason}@{.status.containerStatuses[0].lastState.terminated.finishedAt}{"\n"}{end}'
q 'sum by (reason) (max_over_time(kube_pod_container_status_last_terminated_reason{namespace="nora"}[6h]))'
q 'sum(changes(kube_pod_container_status_restarts_total{namespace="nora"}[6h]))'

# JWKS herd after a restart: GitHub Actions OIDC logins rejected (own alert NoraOidcJwksRejections)
q 'sum by (reason) (increase(nora_auth_oidc_rejected_total[10m]))'

# Slow upstream (npm / NuGet / PyPI): upstream p99 near the HTTP p99 => the tail is upstream
q 'histogram_quantile(0.99, sum by (le, registry) (rate(nora_upstream_request_duration_seconds_bucket[5m])))'

# R2 storage errors
q 'sum by (operation) (increase(nora_storage_operations_total{status="error"}[10m]))'

# Repo index rebuild after start (npm took 21s on 12.10 with 3399 packages)
kubectl --context "$CTX" -n nora logs "$(pod_of | awk '{print $1}')" --since=30m | grep 'Index rebuilt'
```

| Signature | Cause | Act |
|---|---|---|
| `last=OOMKilled`, restarts > 0 | memory limit hit under load (12.10: OOMKilled at 2Gi every 1–6 min, 5 restarts, CPU spiking to ~25 cores) | raise `resources` in the fluxcd HelmRelease (requests == limits); then Step 2, OOMs and CPU contention came together |
| `reason="jwks"` rejections rising right after a start (12.10: 970 in 1h, 596 in 3 min) | every request refetches JWKS on a cold cache; GitHub CI logins fail | wait for it to drain; fix is single-flight JWKS fetch, maestra-io/nora#54 |
| upstream p99 ≈ HTTP p99 for one registry | upstream slow | nothing to fix in nora; confirm on the upstream's status page |
| `get`/`get_reader` errors well above baseline | R2 problem | see `NoraStorageUnreachable` / `NoraReadinessFlapping` |
| `Index rebuilt` `elapsed_ms` in tens of seconds | cold start | transient; only matters if restarts repeat |

Baselines: storage `get` errors are never zero (12.10 12:00 UTC: 2880 `get` + 1564
`get_reader` errors/h with p99 2.1s) — compare against that, not against 0.
`jwt_invalid` rejections are expired/foreign tokens, not an incident.

## Step 4 — DECISION GATE

- **4a. Allocator contention** (Step 2 first row). Fixed since `1.3.3-maestra.10`
  (maestra-io/nora#53: mimalloc as `#[global_allocator]`). Check the running image:
  `kubectl --context "$CTX" -n nora get deploy nora -o jsonpath='{.spec.template.spec.containers[0].image}'`.
  If it is older, or the allocator was removed, the fix is the release, not more CPU or
  replicas: more cores only add spinners on the same lock and burn the node (12.10:
  26 cores). The image tag is not proof: since nora#23 `mimalloc` is a cargo feature
  inside `default`, and the release builds `--no-default-features`, so a release that
  forgets `--features mimalloc` ships musl's malloc under a newer tag (16–19.10.2026:
  `1.3.6-maestra.1/.2`). Check the binary itself:
  `docker pull <ECR>/nora:<tag> && docker create … && docker cp <id>:/usr/local/bin/nora - | grep -a -c mimalloc`
  (5 hits with the allocator, 0 without; since nora#76 the Dockerfile fails the build
  at 0). A cheaper tell without the image: `stime` ≫ `utime` in `/proc/<pid>/stat`
  (19.10 before the fix: 3.1M vs 0.68M ticks; after, over a 10 s sample: +7 vs +34)
  and CPU per request ≥ 0.03 core-s at only 15–25 rps.
- **4b. Real load.** CPU per request flat near the after-fix value while rps grows:
  capacity. nora runs a single replica (local token volume), so options are CPU
  `requests` in the HelmRelease or finding the client generating the burst (12.10: the
  GitHub runner migration raised traffic to ~200 rps).
- **4c. A Step 3 branch.** Act per its table row.
- **4d. Link saturated / quota engaged** (Step 2b). Expected during a CI burst: the
  latency is the price of the 800 Mbit/s cap and ends with the burst (12.10: resolved
  16:10 UTC on its own). Nothing to roll back. A missing throttle entry → recreate the pod
  (`kubectl --context "$CTX" -n nora rollout restart deploy/nora`, Recreate strategy, ~20s outage) after
  confirming the bandwidth manager is on. Raising the cap costs the node's other tenants
  (traefik, backups) their headroom; the real fix for repeated bursts is a local hot cache
  in nora so repeated restores stop reading R2 (open, not built). Find the client
  before accepting the burst: `sum by (registry, result) (increase(nora_cache_requests_total[10m]))`
  all `hit` while the link is full only says clients re-download what nora already
  holds. Attribute it to CI cache misses after both: the org's runs in the window
  (`gh api --paginate "repos/maestra-io/<repo>/actions/runs?created=<from>..<to>&per_page=100"`
  over repos pushed in the last hour) and `Cache not found` in their install job logs
  (21.10.2026: a Renovate wave over the frontend repos).

## Act

All changes go through PRs, never by hand:

- Code / allocator: `maestra-io/nora`, PR to `maestra/main`; merging and tagging
  `v<version>-maestra.N` lets the release workflow build the image — **do not build
  images locally** (Igor, 12.10: "пусть пайплайн соберет").
- Version, resources, config: `maestra-io/fluxcd`
  `iota/us-iota-lw-kube-infra/nora/helm-release.yaml` (chart `version:` and image
  `tag:` together). Example: fluxcd#22246 rolled `1.3.3-maestra.10` at 15:08 UTC.
- Bandwidth quota: `podAnnotations` in the same HelmRelease (fluxcd#22471 set
  800M/800M); the bandwidth manager itself lives in `maestra-io/kubernetes-clusters`
  `k0s/us-iota-lw-kube-infra/cilium-values.yaml` + its k0sctl.yaml mirror.

## Verify

After the pod is Ready (`pod_of`), at least 10 minutes of traffic:

- p99 back to ~2–2.5s and the alert resolved (Step 1);
- CPU per request in the after-fix range (≈ 0.004 core-s); pod CPU < 1 core at ~100 rps;
- `perf` (Step 2) no longer shows `native_queued_spin_lock_slowpath`;
- no new restarts, `reason="jwks"` rejections back to 0;
- re-check at the next traffic peak: on 12.10 the fix was verified at 75–112 rps, not
  at the 200 rps peak.

## Known measurement traps

- `p99 = 10` is the top bucket: the real value is unknown and ≥ 10s.
- Counters reset on restart: `rate()` across an OOM loop under-reads; check restarts
  before trusting a quiet window.
- One series per pod: after a rollout, queries without `pod=` mix old and new pods for
  up to the range window.
- `kubectl top` lags ~1 min; use the `rate(container_cpu_usage_seconds_total[5m])`
  query for numbers.

## Case history

| Date (UTC) | Object | Cause | Category | What helped | Thread |
|---|---|---|---|---|---|
| 21.10.2026 10:20–10:25 | nora `1.3.6-maestra.3`, iota node 02 | Renovate wave over ~15 frontend repos (09:51–10:19, ~70 `pr` runs of `mcf-build.yml`): `node_modules` was cached under the exact lockfile hash and `~/.npm` not at all, so every bump ran a full `npm ci` (2534 packages, 6 min). npm 176 rps, 99k tarballs and 66 GB from R2 in 10 min, all nora `cache_hit`; `eno5` rx 908 Mbit/s, npm p99 5.1s; CPU 0.007 core-s/request | network link saturated (client-side cache miss) | ended with the wave. github-actions#184: on a `node_modules` miss `mcf-build` and `npm-package-publish` restore `~/.npm/_cacache` by key prefix (RunsOn magic cache), so a new lockfile fetches only changed packages | <https://maestraio.slack.com/archives/C0BN1L82W8M/p1792578041939979> |
| 16–19.10.2026, 10 firings (16.10 ×1, 17.10 ×4, 18.10 ×3, 19.10 ×1) | nora `1.3.6-maestra.1/.2`, iota | the 1.3.6 release was built `--no-default-features` after nora#23 moved `mimalloc` into `default`: the image lost the allocator and the 12.10 musl malloc lock came back. CPU per request 0.004 → 0.03–0.07 core-s, `stime/utime` 4.6 on node 02, p99 ≥ 9s on NuGet bursts of only 15–25 rps while traffic itself had dropped 6–12× (170 → 12–28 GB/day) after the CI cache-mount sweep | allocator regression | nora#76: release and CI gates build `--no-default-features --features mimalloc`, Dockerfile refuses a binary without mimalloc; `1.3.6-maestra.3` (fluxcd#23672). Traffic side, same week: NuGet cache mount in ~180 repo Dockerfiles + test-job cache (github-actions #146/#147/#149/#151/#153): warm image legs 300 → 0.2 MB, test jobs 210 → 0 MB | <https://maestraio.slack.com/archives/C0BN1L82W8M/p1792399381398669> |
| 12.10.2026 16:05–16:10 | nora `1.3.3-maestra.10`, iota node 02 | NuGet CI burst up to 413 rps; every artifact read from R2 filled the node's 1 Gbit `eno5` (982 Mbit/s rx, 98%), responses 637 Mbit/s on `eno6`; CPU 1.5–1.8 cores, 0.006 core-s/request; 3.6–7 rps of NuGet > 10s, no 5xx | network link saturated | ended with the burst. Follow-up 13.10: Cilium bandwidth manager on iota (kubernetes-clusters#165) + 800M/800M pod quota (fluxcd#22471); verified with 2×16 parallel downloads from nodes 01/03: `eno5` rx ~805 Mbit/s, 256/256 OK | <https://maestraio.slack.com/archives/C0BN1L82W8M/p1791821141024479> |
| 12.10.2026 14:15–15:07, 4 firings | nora `1.3.3-maestra.9`, iota | musl static-pie build (Alpine builder) using musl's malloc with one global lock; at ~200 rps all 32 tokio workers spun on it: `perf` 85% `native_queued_spin_lock_slowpath`, 10–26 cores, node load 26, p99 ≥ 10s, p90 3.9s, p50 60ms, no 5xx. OOMKilled at 2Gi in parallel, with a JWKS rejection burst after each restart | allocator contention + OOM | mimalloc global allocator (maestra-io/nora#53, release `v1.3.3-maestra.10`, fluxcd#22246, rolled 15:08); memory 2Gi→4Gi (fluxcd#22241). After: 0.2–0.5 cores at 75–112 rps, p99 2.1s, node load 3 | <https://maestraio.slack.com/archives/C0BN1L82W8M/p1791814920896829> |

## Reply format for the alert thread

Diagnosis post: p99 / p90 / p50, rps, pod CPU and CPU per request, the Step 2
signature or Step 3 row that matched, plan with PR links. Resolution post: the after
numbers from Verify with the measurement time in UTC.
