# NoraUpstreamUrlLeak

> **Scope: Maestra only** — `packages.maestra.io`, cluster `us-iota-lw-kube-infra`, namespace `nora`, single
> replica. Written for an automation agent; everything below is read-only.

A JSON response nora served still carried an upstream hostname (`api.nuget.org`, `registry.npmjs.org`, …).
Either nora failed to rewrite a URL a client follows (clients then bypass nora: a real gap), or the URL is one
nora keeps on purpose and the detector does not know it yet (a false positive: the fix is the pass-through list).

## Diagnostics (one call)

Fill `T` (Rootly `started_at`) and `A` (Rootly short id).

```bash
T='<rootly started_at>' A='<rootly short id>' timeout 300 bash <<'EOS'
C=teleport.maestra.io-us-iota-lw-kube-infra; D=tp-us-iota-lw-kube-infra; T0=$(date -u -d "$T" +%s); iso(){ date -u -d @$1 +%FT%TZ; }
echo "probe $(iso $(date +%s)), alert start $(iso $T0)"
echo "## 0. alert labels (registry = which rewriter; a silence matches only labels the alert carries)"
rootly alerts get "$A" --format json | jq -c '.data.attributes.data.commonLabels'
echo "## 1. leaks by registry, increase over 15m ending at T-30m, T, T+15m"
for t in $((T0-1800)) $T0 $((T0+900)); do echo "$(iso $t) $(gcx metrics query -d $D 'sum by (registry) (increase(nora_response_upstream_url_leak_total[15m]))' --time $(iso $t) -o json 2>/dev/null | jq -c '[.data.result[]?|{(.metric.registry):(.value[1]|tonumber|round)}]|add')"; done
echo "## 1b. counter peak per registry over T-6h..T (survives a pod restart that emptied the windows above)"
gcx metrics query -d $D 'max by (registry) (max_over_time(nora_response_upstream_url_leak_total[6h]))' --time $(iso $T0) -o json 2>/dev/null | jq -c '[.data.result[]?|{(.metric.registry):(.value[1]|tonumber|round)}]|add'
echo "## 2. pod and image (started after T = the WARN lines left with the old pod)"
kubectl --context $C -n nora get pod -l app.kubernetes.io/name=nora -o jsonpath='{range .items[*]}{.metadata.name} start={.status.startTime} restarts={.status.containerStatuses[0].restartCount} image={.spec.containers[0].image}{"\n"}{end}'
echo "## 3. WARN lines per path, T-2h..T+15m (VictoriaLogs pod logs: survives a pod restart; the text is in fields.message, not _msg)"
q="_time:[$(iso $((T0-7200))), $(iso $((T0+900)))] kubernetes.pod_namespace:nora fields.message:\"upstream URL leak detected\" | stats by (fields.registry, fields.upstream, fields.path) count() n, min(_time) first, max(_time) last | sort by (n desc) | limit 20"
gcx api "/api/datasources/proxy/uid/tp-victorialogs-pod-logs-iota/select/logsql/query?query=$(jq -rn --arg q "$q" '$q|@uri')"
echo "## 3b. upstream 304 revalidations by registry, 15m ending at T (a 304 serves the copy nora stored earlier)"
gcx metrics query -d $D 'sum by (registry) (increase(nora_proxy_upstream_304_total[15m]))' --time $(iso $T0) -o json 2>/dev/null | jq -c '[.data.result[]?|{(.metric.registry):(.value[1]|tonumber|round)}]|add'
echo "## 4. pass-through lists on maestra/main (URLs kept on purpose)"
for r in nuget npm; do gh api "repos/maestra-io/nora/contents/nora-registry/src/registry/$r.rs?ref=maestra/main" -H 'Accept: application/vnd.github.raw' | grep -A6 'UPSTREAM_PASSTHROUGH_PATHS: '; done
echo "## 5. nora PRs merged T-24h..T"
gh pr list -R maestra-io/nora --state merged --search "merged:>=$(date -u -d @$((T0-86400)) +%F)" --limit 60 --json number,title,mergedAt --jq ".[]|select(.mergedAt <= \"$(iso $T0)\")|\"\\(.mergedAt[0:16]) #\\(.number) \\(.title)\"" | grep -iE 'leak|passthrough|pass-through|rewrite|upstream' 
EOS
```

Output shape: `<time> {"<registry>":<N>}` per window; `<pod> start=<time> restarts=<N> image=…nora:<ver>`;
`WARN … upstream URL leak detected in response registry=<r> upstream=<host> path=<nora path>`; the
`UPSTREAM_PASSTHROUGH_PATHS` line of each registry; merged PRs whose title names a leak or a rewrite.

## Reading it

1. Step 1 names the registry and how many responses leaked; `{}` or 0 next to a restart = the series reset, then
   step 1b gives the totals the old pod reached. Every registry with a count needs its own cause (one prefix rarely
   explains two registries).
2. Step 3 gives the path, how often and when (`first`/`last`). Empty: the WARN lines are not there either, so there is no path; say so, and go on from the registry and step 5.
3. Fetch what the upstream returns for that path and list the upstream URL prefixes in it:
   `curl -s --compressed '<upstream URL of the same document>' | grep -oE 'https://<upstream host>/[^"]*' | sed -E 's|^(https://[^/]+/[^/]+/[^/]+/).*|\1|' | sort | uniq -c`
   - a prefix clients follow on install/restore (NuGet registration/flatcontainer, npm tarball, PyPI file) that
     nora left as is → **rewriter gap**: clients bypass nora for it; the fix is in `nora-registry/src/registry/<r>.rs`.
   - a prefix clients never follow (NuGet `/v3/catalog0/`, npm attestations) → **false positive**: the fix is the
     registry's `UPSTREAM_PASSTHROUGH_PATHS` (step 4), not a silence.
   - npm: count the host inside and outside the README text, for EVERY path of step 3 (`%2F` stays encoded):
     `curl -s --compressed https://registry.npmjs.org/<pkg> > /tmp/p.json; grep -o 'registry\.npmjs\.org' /tmp/p.json | wc -l; jq -c 'del(.readme, .versions[]?.readme) | walk(if type=="object" then del(.tarball, .attestations) else . end)' /tmp/p.json | grep -o 'registry\.npmjs\.org' | wc -l`
     second number 0 = every hit is README prose (cache-key examples, `fetch('https://registry.npmjs.org/…')` in code
     samples): **false positive of the detector**. The fix is a detector that skips `readme` fields; matching only after
     `://` or a pass-through entry does not cover READMEs that carry full URLs, so check all paths before proposing it.
4. Step 5 lists a fix merged before the alert; compare its release with the running `image` tag (step 2): merged but not
   running = wait for the release, the alert repeats until then.

## Options

1. Nothing — a known false positive whose fix is already merged and rolling out (step 5 + step 2).
2. A PR to `maestra-io/nora` (`maestra/main`): pass-through entry or rewriter fix, named by step 3; owner of nora reviews.
3. A silence on `alertname=NoraUpstreamUrlLeak` (plus `registry=<r>` only if the firing alert carries that label:
   read its labels in Rootly first) until that PR is released, with the PR link.

## Traps

- One leaked response is enough to fire (`increase(...[15m]) > 0`, `for: 5m`, critical). Count and path decide
  severity, not the alert.
- The detector matches the hostname anywhere in the body, not the path: one false-positive prefix fires on
  almost every metadata response of that registry.
- The counter resets on restart: compare windows from step 1, never the raw total across a restart.
- Repeated firing after a merged fix: check the running image first (step 2) before suspecting a new gap.
- The running image has the rewriter fix, yet the same paths leak, and step 3's upstream document holds only prefixes
  the fix rewrites: the leak is the copy nora stored BEFORE the fix. Upstream answers a revalidation with 304 (step
  3b counts them) and nora serves that stored body. Prove it in the code of the RUNNING release (tag = image version
  from step 2), not main: `gh api 'repos/maestra-io/nora/contents/nora-registry/src/registry/<r>.rs?ref=v<image version>'
  -H 'Accept: application/vnd.github.raw' | grep -nE 'NOT_MODIFIED|304' -A8`, and that the fix is in that release:
  `gh api repos/maestra-io/nora/compare/<fix merge sha>...v<image version> --jq .status` (`ahead`/`identical` = in). The 304 branch returns the cached body
  without the rewriter = this case. A real gap, not a false positive: the fix is in that branch, and the stored copies
  heal on the first request after its release. An upstream document fetched now is an example of today's upstream,
  not the body nora stored: say so.
- A threshold or `for:` change hides a real leak too: a real gap is also one response. Never the fix.
- No WARN line = no path: a document fetched for step 3 is an example, say so; the code and the prefix count
  carry the conclusion.

The rule lives in `deploy/prometheus-rules.yml` and `maestra/charts/nora/files/prometheus-rules.yml` (identical, CI
`cmp`); it reaches the cluster with the next nora release.
