# NoraDockerQuarantineBlocked

> **Scope: Maestra only**: `packages.maestra.io`, cluster `us-iota-lw-kube-infra`, namespace `nora`.
> The rule lives in `maestra-io/fluxcd` `iota/us-iota-lw-kube-infra/nora/helm-release.yaml`
> (`metrics.prometheusRule.extraGroups`); its expression and `runbook_url` change with a fluxcd PR only.

For an automation agent; every step is read-only. Quarantine policy, who decides exceptions and how
to repin: `maestra-io/skillz` `plugins/delivery/rules/quarantine.md`.

## What the alert means

`sum by (namespace) (increase(nora_quarantine_holds_total{namespace="nora",registry="docker",outcome="blocked",client="consumer"}[15m])) > 0`, `for: 0m`.

nora answered 403 "held by quarantine policy" to a **consumer** (not Renovate, not `pull_request` CI,
not a person's Teleport laptop token) for an image manifest or layer it first fetched less than the
docker quarantine TTL ago (3 days). It fires on ONE held request. The question is always: **is
something real failing to pull** (a pod in `ImagePullBackOff`, a default-branch CI job, an asbo host),
or did someone just touch a fresh digest nothing runs.

## Diagnosis (one call, ~15 s)

Set `S`/`E` to `[startsAt − 15m, startsAt + 10m]` (RFC3339 UTC). The block prints the held requests
(who, which digest, mode), when each digest entered quarantine, where it is pinned, whether a pod runs
it, which pods fail to pull right now, and the alert's state.

```bash
S=<startsAt-15m>; E=<startsAt+10m>
vl(){ timeout 90 gcx api "/api/datasources/proxy/uid/tp-victorialogs-pod-logs-iota/select/logsql/query?query=$(jq -rn --arg q "$1" '$q|@uri')" 2>&1 | grep -v '"class":"hint"'; }
echo "== held requests by consumer"
R=$(vl "_time:[$S, $E] kubernetes.pod_namespace:nora fields.message:~\"Quarantine: (held cached|proxy-fetched)\" fields.client:consumer | stats by (fields.message, fields.digest, fields.upstream, fields.principal, fields.mode) count() n, min(_time) first, max(_time) last"); jq -c . <<<"$R"
for L in $(jq -r 'select(."fields.message"|test("blob held"))|."fields.digest"//empty' <<<"$R" | sort -u); do grep -q "$L" <<<"$(jq -r 'select(."fields.message"|test("blob")|not)|."fields.digest"' <<<"$R")" || echo "== $L is a layer: its image = the manifest row of the same principal and upstream within those seconds"; done
for D in $(jq -r 'select(."fields.message"|test("blob held")|not)|."fields.digest"//empty' <<<"$R" | sed 's/^sha256://' | sort -u); do
  echo "== $D entered quarantine (3 days back; 'dated by its registry' = backdated first_seen)"; vl "_time:[$(date -u -d "$S -3 days" +%FT%TZ), $E] kubernetes.pod_namespace:nora fields.digest:\"sha256:$D\" fields.message:~\"Quarantine: (proxy-fetched|first sight|held manifest dated)\" | stats by (fields.message, fields.first_seen) min(_time) first" | jq -c .
  echo "== $D pinned in git"; GH_TOKEN=$(asbo creds github --ro) timeout 60 gh api "search/code?q=$D+org:maestra-io" --jq '.items[]|"\(.repository.full_name) \(.path)"'
  # a `held cached artifact` row may be a layer (nora logs no path, so its image is not resolvable here): [] below is not "no impact" alone
  for c in us-omega-lw-kube-common us-omicron-lw-kube-common us-iota-lw-kube-infra; do printf '== %s running on %s: ' "$D" "$c"
    gcx metrics query -d tp-$c "count by (namespace) (max_over_time({__name__=~\"kube_pod_(init_)?container_info\",image_spec=~\".*$D.*\"}[1h]))" -o json 2>/dev/null | jq -c '[.data.result[]|"\(.metric.namespace)=\(.value[1])"]'; done
done
for c in us-omega-lw-kube-common us-omicron-lw-kube-common us-iota-lw-kube-infra; do printf '== pods failing to pull on %s: ' "$c"
  gcx metrics query -d tp-$c 'count by (namespace,pod) (max_over_time({__name__=~"kube_pod_(init_)?container_status_waiting_reason",reason=~"ImagePullBackOff|ErrImagePull"}[1h]) > 0)' -o json 2>/dev/null | jq -c '[.data.result[]|"\(.metric.namespace)/\(.metric.pod)"]'; done
echo "== holds since S until now (still happening?)"; vl "_time:[$S, now] kubernetes.pod_namespace:nora fields.message:~\"Quarantine: (held cached|proxy-fetched)\" fields.client:consumer | stats by (fields.digest, fields.principal) count() n, max(_time) last" | jq -c .
echo "== blocked holds to consumers in the last 15m (0 = the alert clears on its next evaluation)"; gcx metrics query -d tp-us-iota-lw-kube-infra 'sum(increase(nora_quarantine_holds_total{namespace="nora",registry="docker",outcome="blocked",client="consumer"}[15m]))' -o json 2>/dev/null | jq -c '[.data.result[].value[1]]'
echo "== alert now"; gcx metrics query -d tp-us-iota-lw-kube-infra 'ALERTS{alertname="NoraDockerQuarantineBlocked"}' -o json 2>/dev/null | jq -c '[.data.result[]|.metric.alertstate]'
```

## How to read it

- Every row is a hold: `held cached artifact` (a cached manifest or layer), `proxy-fetched manifest`
  (a fresh manifest), `proxy-fetched blob held` (a fresh layer). The log has no outcome: with
  `fields.mode` = `Enforce` a row is a 403 or a fallback to an admitted copy (the metric counts only
  the 403s); `Observe` rows never refuse. `principal`: a Teleport bot (`teleport:bot-*`, asbo hosts), a
  service token, or a person's token without the `teleport:` prefix.
- A layer digest (every `blob held` row, and a `held cached artifact` row may be one too) is pinned nowhere and runs nowhere by itself, and nora logs no request path:
  so its owning image cannot be resolved from logs: the block prints it as a layer and its image is the
  manifest row of the same principal and upstream within those seconds. No such row, or more than one
  = owning image unknown or ambiguous: say so and check each candidate; live impact is then judged only by `pods failing to pull` and the principal's job.
- **Released at** ≈ `first_seen` + 3 days: `fields.first_seen` (epoch, `date -u -d @<N>`) of the
  `held manifest dated by its registry` line when present (backdated to the publish date), else of the
  `first sight of a proxied manifest` line. Neither in the window: "release time not measured". The
  exact time is only in the 403 body (`quarantine_until`); never pull the digest to read it: a consumer
  pull is one more hold and re-fires the alert.
- **Nothing broken** needs all of: `running on` all `[]`; no live pin (only a comment, a test fixture or
  a closed PR); `pods failing to pull` empty or unrelated to the row's upstream image; and a principal
  that is a person checking by hand. Then: "quarantine worked as designed", the principal, the release
  time, and that the alert clears when `blocked holds … last 15m` is 0 (rows of the log also count fallback and observe holds, which the alert does not) (`for: 0m`, `increase[15m]`).
- A bot or service principal pulls for a job or a host: find what failed in the window (its
  default-branch runs, its host's unit) before "nothing broken"; a tag pull stores no digest in git.
- A namespace in `running on` or a live pin (HelmRelease, Kustomize image patch, a default-branch
  workflow) is potential impact; a real pull is failing only with a failing pod or job of that image
  (`pods failing to pull`, the job's run). Name the pod or job and the commit
  that pinned it (`git log -S <digest>`). `image_spec` carries a digest only for digest-pinned pods; a
  tag-pinned pod shows up in `pods failing to pull`, not in `running on`.

## Answers

- Nothing runs it: "do nothing", the release time and the clear time. A person who keeps checking a
  fresh digest with a consumer token will raise it again until the release time: say so once.
- A live pin: the fix is a repin through git to a digest older than 3 days, or waiting for the release
  time. Variants: do nothing (pulls fail until `<release time>`); repin to `<mature digest>` in
  `<repo/path>`. Exceptions and TTL changes are not variants: only Igor Kudrin decides them
  (`quarantine.md`).

## Traps

- One held request fires the alert; the count says nothing about impact. Impact is only `running on`
  plus failing pods or jobs.
- `outcome="fallback"` (an enforce fallback to an admitted copy) is not a refusal; the block drops it.
- Renovate (`client="renovate"`), `pull_request` CI and laptop tokens are excluded from the rule; if
  the rows show them, the alert is about another request in the window.
- Do not run `kubectl get pods -A` over the clusters for the digest (over a minute per cluster): the
  metrics probe above answers in seconds.
