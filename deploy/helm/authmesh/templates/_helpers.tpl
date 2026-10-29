{{/*
Shared naming, labelling and connection-string helpers.
Every resource name flows through authmesh.fullname so that two releases can
coexist in one namespace.
*/}}

{{- define "authmesh.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "authmesh.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "authmesh.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Labels shared by every object in the release. */}}
{{- define "authmesh.labels" -}}
helm.sh/chart: {{ include "authmesh.chart" . }}
app.kubernetes.io/name: {{ include "authmesh.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: authmesh
{{- end -}}

{{/*
Per-component labels. Usage:
  {{- include "authmesh.componentLabels" (dict "ctx" . "component" "gateway") | nindent 4 }}
*/}}
{{- define "authmesh.componentLabels" -}}
{{ include "authmesh.labels" .ctx }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* Selector labels: the minimal stable set, never including version. */}}
{{- define "authmesh.selectorLabels" -}}
app.kubernetes.io/name: {{ include "authmesh.name" .ctx }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "authmesh.componentName" -}}
{{- printf "%s-%s" (include "authmesh.fullname" .ctx) .component | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "authmesh.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "authmesh.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Image reference for a component, honouring the global registry override. */}}
{{- define "authmesh.image" -}}
{{- $registry := .ctx.Values.global.imageRegistry -}}
{{- $repository := .image.repository -}}
{{- $tag := default .ctx.Chart.AppVersion .image.tag -}}
{{- if and $registry (not (contains "/" $repository)) -}}
{{- printf "%s/%s:%s" $registry $repository $tag -}}
{{- else -}}
{{- printf "%s:%s" $repository $tag -}}
{{- end -}}
{{- end -}}

{{- define "authmesh.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "authmesh.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Mongo connection URI. Uses the bundled StatefulSet when mongodb.enabled,
otherwise the operator-supplied external URI.
*/}}
{{- define "authmesh.mongoUri" -}}
{{- if .Values.mongodb.enabled -}}
{{- printf "mongodb://%s:27017/?directConnection=true" (include "authmesh.componentName" (dict "ctx" . "component" "mongodb")) -}}
{{- else -}}
{{- required "mongodb.externalUri is required when mongodb.enabled is false" .Values.mongodb.externalUri -}}
{{- end -}}
{{- end -}}

{{- define "authmesh.redisUrl" -}}
{{- if .Values.redis.enabled -}}
{{- printf "redis://%s:6379/0" (include "authmesh.componentName" (dict "ctx" . "component" "redis")) -}}
{{- else -}}
{{- required "redis.externalUrl is required when redis.enabled is false" .Values.redis.externalUrl -}}
{{- end -}}
{{- end -}}

{{- define "authmesh.authTarget" -}}
{{- printf "%s:%d" (include "authmesh.componentName" (dict "ctx" . "component" "auth")) (int .Values.auth.service.port) -}}
{{- end -}}

{{- define "authmesh.userTarget" -}}
{{- printf "%s:%d" (include "authmesh.componentName" (dict "ctx" . "component" "user")) (int .Values.user.service.port) -}}
{{- end -}}

{{/*
Pod annotations for Prometheus' annotation-based discovery, so metrics work even
without prometheus-operator CRDs.
*/}}
{{- define "authmesh.scrapeAnnotations" -}}
prometheus.io/scrape: "true"
prometheus.io/port: {{ .port | quote }}
prometheus.io/path: "/metrics"
{{- end -}}

{{/*
Hardened container security context. Applied to every application container:
the images run as uid 10001 and need nothing writable.
*/}}
{{- define "authmesh.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
runAsUser: 10001
runAsGroup: 10001
capabilities:
  drop:
    - ALL
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "authmesh.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 10001
runAsGroup: 10001
fsGroup: 10001
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{/*
Spread replicas across nodes. Applied as a soft constraint so a single-node
cluster (kind) can still schedule every replica.
*/}}
{{- define "authmesh.topologySpread" -}}
- maxSkew: 1
  topologyKey: kubernetes.io/hostname
  whenUnsatisfiable: ScheduleAnyway
  labelSelector:
    matchLabels:
      {{- include "authmesh.selectorLabels" (dict "ctx" .ctx "component" .component) | nindent 6 }}
{{- end -}}
