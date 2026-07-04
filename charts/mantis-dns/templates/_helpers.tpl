{{- define "mantis-dns.fullname" -}}
{{ .Release.Name }}
{{- end -}}

{{- define "mantis-dns.labels" -}}
app.kubernetes.io/name: {{ include "mantis-dns.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "mantis-dns.databaseUrl" -}}
{{- if .Values.postgresql.enabled -}}
postgresql+psycopg://{{ .Values.postgresql.auth.username }}:$(POSTGRES_PASSWORD)@{{ .Release.Name }}-postgresql:5432/{{ .Values.postgresql.auth.database }}
{{- else -}}
{{ .Values.database.url }}
{{- end -}}
{{- end -}}
