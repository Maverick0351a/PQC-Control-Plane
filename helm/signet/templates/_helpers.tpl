{{- define "signet.name" -}}
signet
{{- end -}}

{{- define "signet.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "signet.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "signet.chart" -}}
{{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}
