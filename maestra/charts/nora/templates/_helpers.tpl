{{/*
Expand the name of the chart.
*/}}
{{- define "nora.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "nora.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "nora.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "nora.labels" -}}
helm.sh/chart: {{ include "nora.chart" . }}
{{ include "nora.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "nora.selectorLabels" -}}
app.kubernetes.io/name: {{ include "nora.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use.
*/}}
{{- define "nora.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "nora.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image reference. Tag defaults to Chart.appVersion; set image.tag to override.
image.digest pins it: repo:tag@sha256:... (the digest is what runs, the tag
only says which release it is).
*/}}
{{- define "nora.image" -}}
{{- $tag := .Chart.AppVersion }}
{{- if .Values.image.tag }}
{{- $tag = .Values.image.tag }}
{{- end }}
{{- if .Values.image.digest }}
{{- printf "%s:%s@%s" .Values.image.repository $tag .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository $tag }}
{{- end }}
{{- end }}

{{/*
Resolved htpasswd file path for config.toml (explicit htpasswd_file or Secret mount).
*/}}
{{- define "nora.auth.htpasswdFile" -}}
{{- if .Values.config.auth.htpasswd_file }}
{{- .Values.config.auth.htpasswd_file }}
{{- else if .Values.config.auth.htpasswd.existingSecret }}
{{- printf "%s/%s" .Values.config.auth.htpasswd.mountPath (.Values.config.auth.htpasswd.secretKey | default "users.htpasswd") }}
{{- end }}
{{- end }}

{{/*
Resolved curation blocklist_path for config.toml.
Derived from the mounted Secret/ConfigMap (<mountPath>/<key>) when one is set,
otherwise the explicit .path, otherwise empty.
*/}}
{{- define "nora.curation.blocklistPath" -}}
{{- $bl := .Values.config.curation.blocklist -}}
{{- if or $bl.existingSecret $bl.existingConfigMap -}}
{{- printf "%s/%s" $bl.mountPath ($bl.key | default "blocklist.json") -}}
{{- else if $bl.path -}}
{{- $bl.path -}}
{{- end -}}
{{- end }}

{{/*
Resolved curation allowlist_path for config.toml. Mirrors blocklistPath.
*/}}
{{- define "nora.curation.allowlistPath" -}}
{{- $al := .Values.config.curation.allowlist -}}
{{- if or $al.existingSecret $al.existingConfigMap -}}
{{- printf "%s/%s" $al.mountPath ($al.key | default "allowlist.json") -}}
{{- else if $al.path -}}
{{- $al.path -}}
{{- end -}}
{{- end }}

{{/*
Resolved [storage] s3_credentials_dir (Maestra fork): the Secret mount when
s3Credentials.existingSecret is set, otherwise the explicit value.
*/}}
{{- define "nora.storage.s3CredentialsDir" -}}
{{- $st := .Values.config.storage -}}
{{- if $st.s3Credentials.existingSecret -}}
{{- $st.s3Credentials.mountPath -}}
{{- else if $st.s3_credentials_dir -}}
{{- $st.s3_credentials_dir -}}
{{- end -}}
{{- end }}

{{/*
`key = value` lines for a flat map of scalars or scalar lists (toJson output is
valid TOML for strings, numbers, booleans and string arrays).
*/}}
{{- define "nora.tomlScalars" -}}
{{- range $k, $v := . }}
{{- if or (kindIs "map" $v) (and (kindIs "slice" $v) $v (kindIs "map" (first $v))) }}
{{- fail (printf "config key %q is a table; the chart renders scalar values here only" $k) }}
{{- end }}
{{ $k }} = {{ toJson $v }}
{{- end }}
{{- end }}

{{/*
Env var carrying the credential of docker upstream (list index upstream): the
explicit auth_env, or NORA_DOCKER_UPSTREAM_AUTH_<index> filled from authSecret.
*/}}
{{- define "nora.docker.authEnv" -}}
{{- $i := index . 0 }}{{- $u := index . 1 }}
{{- if $u.authSecret }}NORA_DOCKER_UPSTREAM_AUTH_{{ $i }}{{- else if $u.auth_env }}{{ $u.auth_env }}{{- end }}
{{- end }}
