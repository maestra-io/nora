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

Set `S`/`E` to `[startsAt − 15m, startsAt + 10m]` (RFC3339 UTC). The block prints who was refused
which digest, where it is pinned, whether any pod runs it, and the alert's state now.

```bash
S=<startsAt-15m>; E=<startsAt+10m>
vl(){ timeout 90 gcx api "/api/datasources/proxy/uid/tp-victorialogs-pod-logs-iota/select/logsql/query?query=$(jq -rn --arg q "$1" '$q|@uri')" 2>&1 | grep -v '"class":"hint"'; }
echo "== held / first-fetched digests by consumer"
R=$(vl "_time:[$S, $E] kubernetes.pod_namespace:nora fields.message:~\"Quarantine\" fields.client:consumer -fields.outcome:fallback | stats by (fields.message, fields.digest, fields.upstream, fields.repository, fields.principal) count() n, min(_time) first, max(_time) last"); jq -c . <<<"$R"
for D in $(jq -r 'select(."fields.message"|test("held"))|."fields.digest"//empty' <<<"$R" | sed 's/^sha256://' | sort -u); do
  echo "== $D first fetched (3 days back)"; vl "_time:[$(date -u -d "$S -3 days" +%FT%TZ), $E] kubernetes.pod_namespace:nora fields.message:\"Quarantine: proxy-fetched manifest\" fields.digest:\"sha256:$D\" | stats min(_time) first, max(_time) last" | jq -c .
  echo "== $D pinned in git"; GH_TOKEN=$(asbo creds github --ro) timeout 60 gh api "search/code?q=$D+org:maestra-io" --jq '.items[]|"\(.repository.full_name) \(.path)"'
  for c in us-omega-lw-kube-common us-omicron-lw-kube-common us-iota-lw-kube-infra; do printf '== %s running on %s: ' "$D" "$c"
    gcx metrics query -d tp-$c "count by (namespace) (max_over_time({__name__=~\"kube_pod_(init_)?container_info\",image_spec=~\".*$D.*\"}[1h]))" -o json 2>/dev/null | jq -c '[.data.result[]|"\(.metric.namespace)=\(.value[1])"]'; done
done
echo "== alert now"; gcx metrics query -d tp-us-iota-lw-kube-infra 'ALERTS{alertname="NoraDockerQuarantineBlocked"}' -o json 2>/dev/null | jq -c '[.data.result[]|.metric.alertstate]'
```

## How to read it

- `Quarantine: held cached artifact` rows are the refusals; `proxy-fetched manifest` is nora's first
  fetch of that digest. `principal` is who asked: a Teleport bot (`teleport:bot-*`, asbo hosts), a
  service token, or a person's token without the `teleport:` prefix.
- **Released at** = the first fetch (the `first fetched` line) + 3 days. Not in the 3-day window = the
  first fetch is older than the logs kept: say "release time not measured".
- `running on` all `[]` and the digest is pinned nowhere, or only in a comment, a test fixture or a
  closed PR: nothing real is broken. Answer "quarantine worked as designed", name the principal and the
  release time, and say the alert clears by itself 15 min after the last `held` row (`for: 0m`,
  `increase[15m]`). The `alert now` line confirms it.
- `running on` shows a namespace, or the digest is pinned in a live manifest (HelmRelease, Kustomize
  image patch, a workflow on the default branch): a real pull is failing. Find the pod in
  `ImagePullBackOff` or the failed job, and the commit that pinned the digest (`git log -S <digest>`).
- `image_spec` carries the digest only when the pod was pinned by digest; a tag-pinned pod is matched
  by the `repository` from the first block, not by the digest.

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
