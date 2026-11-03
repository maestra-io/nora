# Monitoring

NORA exposes Prometheus metrics at `/metrics`. This page documents all available metrics and provides a ready-to-import Grafana dashboard.

## Quick Start

```yaml
# prometheus.yml
scrape_configs:
  - job_name: nora
    static_configs:
      - targets: ['nora:4000']
    scrape_interval: 15s
```

Import `dist/grafana-dashboard.json` into Grafana (Dashboards > Import > Upload JSON file).

## Metrics Reference

### HTTP (RED signals)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nora_http_requests_total` | counter | registry, method, status | Total HTTP requests |
| `nora_http_request_duration_seconds` | histogram | registry, method | Request latency (buckets: 1ms–10s) |

### Cache

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nora_cache_requests_total` | counter | registry, result | Cache lookups (`result`: hit / miss) |
| `nora_cache_write_errors_total` | counter | registry, operation | Background cache writes that failed: the response was served, nothing was cached |
| `nora_spool_failures_total` | counter | registry, reason | Transfers the disk spool refused or lost (`reason`: `busy` 503, `too_large` 507, `no_space` 507, `io` 500); never upstream's fault |

### Upstream Proxy

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nora_upstream_request_duration_seconds` | histogram | registry, status | Upstream proxy latency (buckets: 1ms–30s) |

### Artifacts & Traffic

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nora_artifacts_total` | gauge | registry | Repositories with stored files, the count `/api/ui/stats` shows (not files or versions). Set every 60 s from the dashboard index, which a read of the dashboard or the stats rebuilds after a change |
| `nora_downloads_total` | counter | registry | Total artifact downloads |
| `nora_uploads_total` | counter | registry | Total artifact uploads |

### Storage

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nora_storage_bytes` | gauge | registry | Storage size in bytes per registry |
| `nora_storage_reachable` | gauge | — | 1 when the storage backend is reachable, 0 when `/ready` answers 503 |
| `nora_config_deprecated` | gauge | reason | 1 while the running configuration relies on a default that a later release refuses. `curation_mode_implicit`: proxy registries are enabled and `curation.mode` is not set, which stops startup from 1.5.0 |
| `nora_storage_operations_total` | counter | operation, status | Every backend round-trip: `put`, `get`, `get_range`, `get_reader`, `copy`, `delete`, `stat`, `pin`, `list`, `list_with_meta`. On an object store each one is a network request, so the rate of this counter against the request rate is what shows a handler paying a round-trip per file. `status="miss"` on `stat`/`pin` is an absent object or an unpinned one — not an error. `status="integrity_fail"`/`"verify_error"` on `operation="get"` mean a stored artifact failed hash-pin verification and was refused (fail-closed, #582) — see [Integrity recovery](#integrity-recovery). |

### Circuit Breaker

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nora_circuit_breaker_state` | gauge | registry | 0 = closed, 1 = open, 2 = half_open |
| `nora_circuit_breaker_rejections_total` | counter | registry | Requests rejected by open circuit breaker |

`registry` on both is the breaker key: the format name (`cargo`, `go`, …), or
`<format>:<upstream URL>` for formats with a breaker per configured upstream (Docker,
PyPI, npm and Maven), credentials stripped — e.g. `pypi:https://pypi.org/simple`. Match a format
with `registry=~"pypi(:.*)?"`, not `registry="pypi"`.

### Security

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nora_response_upstream_url_leak_total` | counter | registry | Upstream hostname detected in outgoing response body |

### Retention

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nora_retention_versions_deleted_total` | counter | — | Versions removed by retention policy |
| `nora_retention_bytes_freed_total` | counter | — | Bytes freed by retention |
| `nora_retention_duration_seconds` | histogram | — | Retention sweep duration |
| `nora_retention_last_run_timestamp` | gauge | — | Unix timestamp of last retention run |

### Garbage Collection

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nora_gc_blobs_removed_total` | counter | — | Orphan blobs removed by GC |
| `nora_gc_bytes_freed_total` | counter | — | Bytes freed by GC |
| `nora_gc_duration_seconds` | histogram | — | GC sweep duration |
| `nora_gc_last_run_timestamp` | gauge | — | Unix timestamp of last GC run |
| `nora_gc_metadata_phantoms_total` | counter | — | Metadata entries without corresponding blobs |

### Background tasks

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `nora_task_panics_total` | counter | task | Panics of a long-lived background task: `maintenance` (session expiry, storage reachability), `token_flush` (token `last_used` to disk), `storage_size` (the store's size and the per-registry gauges), `pull_stats`, `cleanup` (GC and retention), `sighup` (curation reload), `audit` (audit writer). Each one is logged as `background task panicked` with the task's name. A task is restarted after a backoff; one that keeps panicking, or a maintenance loop that has not finished a tick for `server.maintenance_stall_secs`, makes `/health` answer 503 with `failing_task`. `token_flush` and `storage_size` are started by the maintenance loop, one run at a time; a panic ends only that run, and the next tick starts another. A panic of `audit` ends the process (exit 70): NORA does not serve without its audit trail. Any increase is a bug |
| `nora_maintenance_timeouts_total` | counter | — | Maintenance ticks cut at their deadline, a third of what `server.maintenance_stall_secs` leaves after one 30 s tick (90 s by default), because the storage did not answer its reachability request (the first page of a listing on an object store, a write probe on the local disk) in time; each one is logged as `maintenance tick cut at its deadline`. The loop goes on, so this does not fail `/health`: whether the storage answers is `/ready`'s business, and a restart would not fix it. The size of the store is counted apart from the tick, so a large bucket does not cut ticks |

### Health probes

`/health` and `/ready` do no storage I/O, on either backend. They serve the verdict the maintenance loop took on its last 30 s tick: one request for the first page of a listing on an object store, a write probe on the local disk (create, write, fsync and remove a file in the storage directory).

- A read-only remount or a full disk turns `/ready` to 503 at the next tick, within one tick period (30 s) of the change. `/health` stays 200.
- A disk or bucket that stops answering leaves the tick's request waiting: the tick is cut at its deadline (`nora_maintenance_timeouts_total`), and `/ready` turns 503 at the next tick. On the local disk, a probe still waiting is not started again. `/health` stays 200.
- A verdict older than 150 s (five ticks) counts as unreachable, so a maintenance loop that stops probing un-readies the instance too. Until the first tick has run, right after start, `/ready` answers 503.
- `storage.total_size_bytes` on `/health` and `nora_storage_bytes{registry="total"}` are the size the `storage_size` task last counted, every second tick (60 s). The count walks the whole store, so on a large store it lags behind writes.

## Grafana Dashboard

The included dashboard (`dist/grafana-dashboard.json`) provides:

- **Row 1** — Key stats: request rate, error rate, p50/p99 latency, cache hit rate, storage used
- **Row 2** — Request rate by registry, HTTP latency percentiles (p50/p95/p99)
- **Row 3** — Error rate by registry, upstream proxy latency by registry
- **Row 4** — Cache hit/miss rate, downloads/uploads by registry
- **Row 5** — Storage by registry, circuit breaker state table, security alerts (URL leaks, CB rejections)
- **Row 6** — Retention & GC bytes freed, last run timestamps, storage operations

The dashboard includes a `registry` template variable to filter by specific protocol.

## Alerting Recommendations

[`deploy/prometheus-rules.yml`](deploy/prometheus-rules.yml) ships these alerts ready to load; point Prometheus at it via `rule_files:`.

| Alert | Fires when | Severity |
|-------|------------|----------|
| `NoraHighErrorRate` | 5xx share of `nora_http_requests_total` above 5% for 5m | warning |
| `NoraHighLatency` | p99 of `nora_http_request_duration_seconds` above 5s for 10m, while traffic is above 5 rps | warning |
| `NoraStorageSlow` | p99 of `nora_storage_operation_duration_seconds{operation="stat"}` above 1.5s for 15m, while the store sees more than 0.5 stat/s: the object store itself is slow | warning |
| `NoraCircuitBreakerOpen` | `nora_circuit_breaker_state == 1` for 1m | critical |
| `NoraCacheLowHitRate` | hit share of `nora_cache_requests_total` below 50% for 15m | warning |
| `NoraUpstreamUrlLeak` | any `nora_response_upstream_url_leak_total` increase for 5m (NuGet catalog0 `@id`s are not counted) | critical |
| `NoraCacheWriteErrors` | any `nora_cache_write_errors_total` increase in 15m | warning |
| `NoraSpoolFailures` | any `nora_spool_failures_total` increase in 15m | warning |
| `NoraStorageWriteErrors` | `nora_storage_operations_total{operation=~"put\|copy",status="error"}` increasing for 5m | warning |
| `NoraStorageUnreachable` | `nora_storage_reachable == 0` for 2m (readiness failing) | critical |
| `NoraIntegrityFailure` | any `get` with `status=~"integrity_fail\|verify_error"` | critical |
| `NoraTaskPanic` | any `nora_task_panics_total` increase in 15m (a background task panicked and was restarted) | warning |

## Integrity recovery

When `nora_storage_operations_total{operation="get",status="integrity_fail"}`
fires, a stored artifact's bytes no longer match its hash pin (bit rot or
tampering) and `Storage::get()` returns 5xx on every read (fail-closed, #582).
The offending key is in the `integrity violation` error log line.

- **Cache/proxy artifacts** self-heal: the next request treats the failure as a
  cache miss, re-fetches from upstream, and re-pins. Only a provable proxy copy is
  dropped: a NuGet flat-container package, or an npm tarball / PyPI file whose
  provenance record (`.nora-origins/<key>`) carries the object's pin. A published,
  uploaded or imported npm tarball or PyPI file is kept and answers 500 (error log
  `hosted artifact failed integrity verification`); restore it as below.
- **Locally-authored artifacts** (e.g. uploaded `raw` blobs) have no upstream.
  Verify the on-disk bytes against a hash you trust, then:

  ```sh
  # Dry run — shows old → new pin without writing:
  nora re-pin raw/myorg/app-1.0.0.bin --expected <sha256>
  # Apply once you've confirmed:
  nora re-pin raw/myorg/app-1.0.0.bin --expected <sha256> --yes
  ```

  `--expected` is **mandatory**: re-pin updates the pin only if the on-disk
  bytes already hash to it. If they do not, the disk is genuinely corrupt — the
  command refuses (re-pin cannot heal corruption); restore from backup first.
