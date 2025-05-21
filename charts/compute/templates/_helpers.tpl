{{/*
Create the container images
*/}}
{{- define "unikorn.computeClusterControllerImage" -}}
{{- .Values.clusterController.image | default (printf "%s/unikorn-compute-cluster-controller:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default .Chart.Version)) }}
{{- end }}

{{- define "unikorn.computeServerImage" -}}
{{- .Values.server.image | default (printf "%s/unikorn-compute-server:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default .Chart.Version)) }}
{{- end }}

{{- define "unikorn.computeMonitorImage" -}}
{{- .Values.monitor.image | default (printf "%s/unikorn-compute-monitor:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default .Chart.Version)) }}
{{- end }}
