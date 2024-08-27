{{/*
Create the container images
*/}}
{{- define "unikorn.baremetalClusterControllerImage" -}}
{{- .Values.clusterController.image | default (printf "%s/unikorn-baremetal-cluster-controller:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default .Chart.Version)) }}
{{- end }}

{{- define "unikorn.baremetalServerImage" -}}
{{- .Values.server.image | default (printf "%s/unikorn-baremetal-server:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default .Chart.Version)) }}
{{- end }}

{{/*
Create image pull secrets
*/}}
{{- define "unikorn.imagePullSecrets" -}}
{{- if .Values.imagePullSecret -}}
- name: {{ .Values.imagePullSecret }}
{{ end }}
{{- if .Values.dockerConfig -}}
- name: docker-config
{{- end }}
{{- end }}
