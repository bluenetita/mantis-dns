{{- define "aegis-dns.fullname" -}}
{{ .Release.Name }}
{{- end -}}

{{- define "aegis-dns.labels" -}}
app.kubernetes.io/name: {{ include "aegis-dns.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "aegis-dns.databaseUrl" -}}
{{- if .Values.postgresql.enabled -}}
postgresql+psycopg://{{ .Values.postgresql.auth.username }}:$(POSTGRES_PASSWORD)@{{ .Release.Name }}-postgresql:5432/{{ .Values.postgresql.auth.database }}
{{- else -}}
{{ .Values.database.url }}
{{- end -}}
{{- end -}}
