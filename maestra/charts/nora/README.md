# NORA Helm Chart

A Helm chart for deploying [NORA](https://github.com/getnora-io/nora) — a container registry proxy with caching and garbage collection.

## Installation

```bash
helm repo add nora https://getnora-io.github.io/helm-charts
helm repo update
helm install nora nora/nora
```

Or from source:

```bash
git clone https://github.com/getnora-io/helm-charts
helm install nora ./helm-charts/charts/nora/
```

## Configuration

### Image

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | Container image | `ghcr.io/getnora-io/nora` |
| `image.tag` | Image tag (defaults to `appVersion`) | `""` |
| `image.pullPolicy` | Pull policy | `IfNotPresent` |

### Service

| Parameter | Description | Default |
|-----------|-------------|---------|
| `service.type` | Service type | `ClusterIP` |
| `service.port` | Service port | `4000` |

### Ingress

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ingress.enabled` | Enable Ingress | `false` |
| `ingress.className` | Ingress class | `""` |
| `ingress.hosts` | Ingress hosts | see values.yaml |
| `ingress.tls` | TLS configuration | `[]` |

### Persistence

| Parameter | Description | Default |
|-----------|-------------|---------|
| `persistence.enabled` | Enable PVC for local storage | `true` |
| `persistence.size` | PVC size | `10Gi` |
| `persistence.storageClass` | Storage class | `""` |
| `persistence.accessModes` | Access modes | `[ReadWriteOnce]` |

Set `persistence.enabled: false` when using S3 storage. An emptyDir volume is used for `/data/` regardless, so audit log and metrics work in both modes.

### NORA Configuration

The `config` section maps directly to NORA's `config.toml`:

```yaml
config:
  server:
    host: "0.0.0.0"
    port: 4000
  storage:
    mode: local       # or "s3"
    path: /data/storage
    # S3 settings (used when mode: s3)
    s3_url: ""
    bucket: ""
    s3_region: "us-east-1"
  gc:
    enabled: true
    interval: 86400
  retention:
    enabled: false
    interval: 86400
    rules: []
  rate_limit:
    enabled: true
    auth_rps: 1
    auth_burst: 5
    upload_rps: 200
    upload_burst: 500
    general_rps: 100
    general_burst: 200
```

### Authentication

Maps to `[auth]` (and optionally `[auth.oidc]`) in `config.toml`.

#### Basic auth (htpasswd)

Create a bcrypt htpasswd file locally, then store it in a Secret:

```bash
htpasswd -Bc /tmp/users.htpasswd admin
kubectl create secret generic nora-htpasswd \
  --from-file=users.htpasswd=/tmp/users.htpasswd
```

```yaml
config:
  auth:
    enabled: true
    token_storage: data/tokens
    anonymous_read: false
    htpasswd:
      existingSecret: nora-htpasswd
```

The chart mounts the Secret at `/etc/nora/users.htpasswd` and sets `htpasswd_file` in `config.toml` automatically. Override the path with `config.auth.htpasswd_file` if needed.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.auth.enabled` | Enable authentication | `false` |
| `config.auth.htpasswd_file` | Explicit htpasswd path in the container | `""` (auto when Secret is set) |
| `config.auth.anonymous_read` | Allow unauthenticated reads | `false` |
| `config.auth.token_storage` | API token storage path | `data/tokens` |
| `config.auth.htpasswd.existingSecret` | Secret with htpasswd file | `""` |
| `config.auth.htpasswd.secretKey` | Key in the Secret | `users.htpasswd` |
| `config.auth.htpasswd.mountPath` | Mount directory | `/etc/nora` |

#### OIDC

Role rules use glob patterns on the JWT `sub` claim; first match wins.

```yaml
config:
  auth:
    enabled: true
    anonymous_read: false
    oidc:
      enabled: true
      leeway_secs: 60
      jwks_cache_secs: 300
      providers:
        - name: github-actions
          issuer: https://token.actions.githubusercontent.com
          audience: nora
          algorithms:
            - RS256
            - ES256
          max_token_lifetime_secs: 900
          enabled: true
          role_rules:
            - pattern: "repo:myorg/*:ref:refs/heads/main"
              role: write
            - pattern: "repo:myorg/*"
              role: read
```

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.auth.oidc.enabled` | Enable OIDC JWT auth | `false` |
| `config.auth.oidc.leeway_secs` | Clock skew tolerance (seconds) | `60` |
| `config.auth.oidc.jwks_cache_secs` | JWKS cache TTL (seconds) | `300` |
| `config.auth.oidc.providers` | OIDC provider list | `[]` |

Per provider: `name`, `issuer`, `audience`, `algorithms`, `max_token_lifetime_secs`, `enabled`, optional `jwks_uri`, and `role_rules` (`pattern`, `role`).

You can still use `NORA_AUTH_*` env vars via `extraEnv`; they take precedence over `config.toml` when set.

### Rate limiting

Maps to NORA’s `[rate_limit]` in `config.toml`. Tuning guide: [Rate limits configuration](https://getnora.dev/configuration/rate-limits/).

When `config.rate_limit.enabled` is `false`, the chart only writes `enabled = false` under `[rate_limit]`; RPS/burst keys are omitted (NORA uses built-in defaults for unused fields).

You can still override with `NORA_RATE_LIMIT_*` env vars via `extraEnv` (they take precedence over `config.toml`).

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.rate_limit.enabled` | Enable HTTP rate limiting | `true` |
| `config.rate_limit.auth_rps` | Auth endpoint sustained RPS | `1` |
| `config.rate_limit.auth_burst` | Auth endpoint burst | `5` |
| `config.rate_limit.upload_rps` | Upload (push) sustained RPS | `200` |
| `config.rate_limit.upload_burst` | Upload burst | `500` |
| `config.rate_limit.general_rps` | General traffic sustained RPS | `100` |
| `config.rate_limit.general_burst` | General traffic burst | `200` |

### Curation (blocklist / allowlist)

Maps to `[curation]` in `config.toml`. See the [curation guide](https://getnora.dev/configuration/curation/).

Store the blocklist (or allowlist) JSON in a Secret or ConfigMap, then reference it — the chart mounts the file and wires `blocklist_path` / `allowlist_path` automatically:

```bash
kubectl create configmap nora-blocklist --from-file=blocklist.json=blocklist.json
# or, to keep it opaque:
kubectl create secret generic nora-blocklist --from-file=blocklist.json=blocklist.json
```

```yaml
config:
  curation:
    mode: enforce            # off | audit | enforce (default off)
    blocklist:
      existingConfigMap: nora-blocklist   # or existingSecret
      # key: blocklist.json               # default
```

The chart mounts the key at `<mountPath>/<key>` (default `/etc/nora-curation/blocklist/blocklist.json`, a sibling of the htpasswd mount) and sets `blocklist_path` in `config.toml` — no need to specify the path twice. The `[curation]` section is only rendered when curation is actually configured, so defaults leave existing installs unchanged. `existingSecret` wins if both sources are set; set `blocklist.path` directly if the file is supplied another way (baked into the image, `extraVolumes`).

Example `blocklist.json`:

```json
{
  "version": 1,
  "rules": [
    { "registry": "npm", "name": "event-stream", "version": "3.3.6", "reason": "CVE-2018-16396" },
    { "registry": "*", "name": "log4j*", "version": "2.*", "reason": "CVE-2021-44228 Log4Shell" }
  ]
}
```

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.curation.mode` | `off`, `audit`, or `enforce` | `off` |
| `config.curation.on_failure` | Filter-error behavior: `closed` or `open` | `closed` |
| `config.curation.require_integrity` | Require integrity metadata on allowlisted artifacts | `false` |
| `config.curation.min_release_age` | Minimum release age gate (e.g. `7d`, `24h`) | `""` |
| `config.curation.blocklist.existingSecret` | Secret holding the blocklist JSON | `""` |
| `config.curation.blocklist.existingConfigMap` | ConfigMap holding the blocklist JSON | `""` |
| `config.curation.blocklist.key` | Key in the Secret/ConfigMap | `blocklist.json` |
| `config.curation.blocklist.mountPath` | Mount directory | `/etc/nora-curation/blocklist` |
| `config.curation.blocklist.path` | Explicit `blocklist_path` (when not mounted) | `""` |
| `config.curation.allowlist.*` | Same fields as `blocklist` | `allowlist.json`, `/etc/nora-curation/allowlist` |

You can still override with `NORA_CURATION_*` env vars via `extraEnv` (they take precedence over `config.toml`).

### Environment Variables

Use `extraEnv` for plain values or references to Secrets/ConfigMaps:

```yaml
extraEnv:
  - name: NORA_AUTH_ENABLED
    value: "true"
  - name: NORA_STORAGE_S3_ACCESS_KEY
    valueFrom:
      secretKeyRef:
        name: nora-s3-credentials
        key: access-key
  - name: NORA_STORAGE_S3_SECRET_KEY
    valueFrom:
      secretKeyRef:
        name: nora-s3-credentials
        key: secret-key
```

Or inject all keys from a Secret at once with `extraEnvFrom`:

```yaml
extraEnvFrom:
  - secretRef:
      name: nora-s3-credentials
```

### Docker Upstream Credentials

Use `existingSecret` for upstream registry auth:

```yaml
existingSecret: my-nora-upstreams
```

The Secret should contain a key `secrets.toml` with TOML content:

```toml
[[docker.upstreams]]
url = "https://private.registry.io"
auth = "user:token"
```

### Resources

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    memory: 512Mi
```

## S3 Storage

```yaml
persistence:
  enabled: false

config:
  storage:
    mode: s3
    s3_url: "https://s3.amazonaws.com"
    bucket: "my-registry"
    s3_region: "eu-west-1"

extraEnv:
  - name: NORA_STORAGE_S3_ACCESS_KEY
    valueFrom:
      secretKeyRef:
        name: nora-s3-credentials
        key: access-key
  - name: NORA_STORAGE_S3_SECRET_KEY
    valueFrom:
      secretKeyRef:
        name: nora-s3-credentials
        key: secret-key
```

> **Note:** Audit log is written to `/data/` (emptyDir when `persistence.enabled: false`). Audit data is ephemeral without persistence. For production with S3, consider a log aggregator (Fluentd/Promtail) to capture audit events from pod logs. Single replica recommended when using emptyDir for audit storage.

## Registries

Enable all registries:
```yaml
config:
  registries:
    enable: "all"
```

Enable all except specific ones:
```yaml
config:
  registries:
    enable:
      - "all"
      - "-maven"
```

Enable only what you need:
```yaml
config:
  registries:
    enable:
      - "docker"
      - "pypi"     
```

### Supported registries:
- `docker`
- `maven`
- `npm`
- `pypi`
- `cargo`
- `go`
- `raw`
- `rubygems`
- `terraform`
- `ansible`
- `nuget`
- `pub`
- `conan`

## Testing

### Unit tests (helm-unittest)

```bash
helm plugin install https://github.com/helm-unittest/helm-unittest --version v1.1.0 --verify=false
helm unittest charts/nora
```

Tests live in `charts/nora/tests/`:

| Suite | Coverage |
|-------|----------|
| `configmap_test.yaml` | `config.toml`: auth, OIDC, S3, docker upstreams, retention, rate limits, `public_url` |
| `deployment_test.yaml` | image, probes, volumes, env, scheduling, service account |
| `service_test.yaml` | Service type, port, naming |
| `ingress_test.yaml` | Ingress rules, TLS, annotations |
| `httproute_test.yaml` | Gateway API HTTPRoute |
| `pvc_test.yaml` | persistence on/off, storage class |
| `serviceaccount_test.yaml` | create/skip, annotations |
| `test_connection_test.yaml` | `helm test` hook pod |

### Post-install hook

After deploying to a cluster:

```bash
helm test nora
```
