{{- define "octosts.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- /*
The fullname intentionally collapses to "octosts". The ServiceAccount name is
LOCKED to "octosts" because the Vault JWT auth role binds
`system:serviceaccount:octosts:octosts`; using a Release-name-prefixed
fullname would break that binding silently.
*/ -}}
{{- define "octosts.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- include "octosts.name" . | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "octosts.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "octosts.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: octosts
{{- end }}

{{- define "octosts.selectorLabels" -}}
app.kubernetes.io/name: {{ include "octosts.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "octosts.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end }}
