{{/*
Expand the chart name.
*/}}
{{- define "edgepacer.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "edgepacer.fullname" -}}
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

{{/*
Chart label value.
*/}}
{{- define "edgepacer.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels.
*/}}
{{- define "edgepacer.labels" -}}
helm.sh/chart: {{ include "edgepacer.chart" . }}
{{ include "edgepacer.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: logpacer
{{- end -}}

{{/*
Selector labels.
*/}}
{{- define "edgepacer.selectorLabels" -}}
app.kubernetes.io/name: {{ include "edgepacer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: agent
{{- end -}}

{{/*
Service account name.
*/}}
{{- define "edgepacer.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "edgepacer.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Secret name containing the account bootstrap token.
*/}}
{{- define "edgepacer.secretName" -}}
{{- if .Values.auth.createSecret -}}
{{- include "edgepacer.fullname" . -}}
{{- else -}}
{{- required "auth.existingSecret is required when auth.createSecret=false" .Values.auth.existingSecret -}}
{{- end -}}
{{- end -}}

{{/*
Validate value combinations that would render a DaemonSet with mounted paths or
published ports the running agent cannot use.
*/}}
{{- define "edgepacer.validateValues" -}}
{{- $rawPodLogsDir := trimSuffix "/" .Values.hostLogs.podLogsDir -}}
{{- $podLogsDir := clean .Values.hostLogs.podLogsDir -}}
{{- $rawVarLogMountPath := trimSuffix "/" .Values.hostLogs.varLog.mountPath -}}
{{- $varLogMountPath := clean .Values.hostLogs.varLog.mountPath -}}
{{- $rawPodLogsMountPath := trimSuffix "/" .Values.hostLogs.podLogs.mountPath -}}
{{- $podLogsMountPath := clean .Values.hostLogs.podLogs.mountPath -}}
{{- if or (eq $podLogsDir ".") (eq $podLogsDir "/") (not (hasPrefix "/" $podLogsDir)) (ne $podLogsDir $rawPodLogsDir) -}}
{{- fail "hostLogs.podLogsDir must be an absolute normalized pod log directory, not / or empty" -}}
{{- end -}}
{{- if and .Values.hostLogs.varLog.enabled (or (eq $varLogMountPath ".") (eq $varLogMountPath "/") (not (hasPrefix "/" $varLogMountPath)) (ne $varLogMountPath $rawVarLogMountPath)) -}}
{{- fail "hostLogs.varLog.mountPath must be an absolute normalized mount path, not / or empty" -}}
{{- end -}}
{{- if and .Values.hostLogs.podLogs.enabled (or (eq $podLogsMountPath ".") (eq $podLogsMountPath "/") (not (hasPrefix "/" $podLogsMountPath)) (ne $podLogsMountPath $rawPodLogsMountPath)) -}}
{{- fail "hostLogs.podLogs.mountPath must be an absolute normalized mount path, not / or empty" -}}
{{- end -}}
{{- $coveredByVarLog := and .Values.hostLogs.varLog.enabled (or (eq $podLogsDir $varLogMountPath) (hasPrefix (printf "%s/" $varLogMountPath) $podLogsDir)) -}}
{{- $coveredByPodLogs := and .Values.hostLogs.podLogs.enabled (or (eq $podLogsDir $podLogsMountPath) (hasPrefix (printf "%s/" $podLogsMountPath) $podLogsDir)) -}}
{{- if not (or $coveredByVarLog $coveredByPodLogs) -}}
{{- fail "hostLogs.podLogsDir must be equal to or below hostLogs.varLog.mountPath or hostLogs.podLogs.mountPath, and that mount must be enabled" -}}
{{- end -}}
{{- if and (or .Values.runtimeSockets.containerd.enabled .Values.runtimeSockets.crio.enabled) (not .Values.runtimeSockets.crictl.imageHasBinary) -}}
{{- fail "containerd/CRI-O runtime socket mounts require an image that includes crictl; set runtimeSockets.crictl.imageHasBinary=true only after selecting such an image" -}}
{{- end -}}
{{- if and .Values.runtimeSockets.containerd.enabled .Values.runtimeSockets.crio.enabled -}}
{{- fail "runtimeSockets.containerd.enabled and runtimeSockets.crio.enabled cannot both be true because CONTAINER_RUNTIME_ENDPOINT can target only one CRI socket" -}}
{{- end -}}
{{- if and .Values.traces.otlpHttp.enabled (not .Values.traces.otlpHttp.listenerConfiguredByControlPlane) -}}
{{- fail "traces.otlpHttp.enabled only publishes the OTLP port; set traces.otlpHttp.listenerConfiguredByControlPlane=true after LogPacer config enables a matching trace proxy listener" -}}
{{- end -}}
{{- $traceInternalTrafficPolicy := default "" .Values.traces.service.internalTrafficPolicy -}}
{{- if and $traceInternalTrafficPolicy (not (has $traceInternalTrafficPolicy (list "Cluster" "Local"))) -}}
{{- fail "traces.service.internalTrafficPolicy must be Cluster, Local, or empty" -}}
{{- end -}}
{{- if and .Values.traces.networkPolicy.enabled (not (and .Values.traces.service.enabled .Values.traces.otlpHttp.enabled .Values.traces.otlpHttp.listenerConfiguredByControlPlane)) -}}
{{- fail "traces.networkPolicy.enabled requires traces.service.enabled=true, traces.otlpHttp.enabled=true, and traces.otlpHttp.listenerConfiguredByControlPlane=true" -}}
{{- end -}}
{{- if and .Values.traces.networkPolicy.enabled .Values.traces.otlpHttp.hostPort -}}
{{- fail "traces.networkPolicy.enabled cannot protect traces.otlpHttp.hostPort; use the ClusterIP Service path or disable the chart NetworkPolicy" -}}
{{- end -}}
{{- $securityContext := default dict .Values.securityContext -}}
{{- $runAsUser := get $securityContext "runAsUser" -}}
{{- $runAsGroup := get $securityContext "runAsGroup" -}}
{{- if and .Values.state.hostPath.enabled (or (not (hasKey $securityContext "runAsUser")) (eq (toString $runAsUser) "")) -}}
{{- fail "securityContext.runAsUser is required when state.hostPath.enabled=true" -}}
{{- end -}}
{{- if and .Values.state.hostPath.enabled (hasKey $securityContext "runAsGroup") (eq (toString $runAsGroup) "") -}}
{{- fail "securityContext.runAsGroup cannot be empty when state.hostPath.enabled=true" -}}
{{- end -}}
{{- if and .Values.state.hostPath.enabled (hasKey $securityContext "runAsUser") (ne (toString $runAsUser) "0") (or (not (hasKey $securityContext "runAsGroup")) (eq (toString $runAsGroup) "")) -}}
{{- fail "securityContext.runAsGroup is required when state.hostPath.enabled=true and securityContext.runAsUser is non-root" -}}
{{- end -}}
{{- end -}}
