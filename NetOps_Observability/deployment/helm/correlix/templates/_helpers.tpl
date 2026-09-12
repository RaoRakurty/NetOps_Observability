{{/*
Shared helpers.

correlix.image FAILS the render when images.requireDigest is on and the
reference carries no digest. A mutable tag in production is an unreproducible
deployment, so the failure names the service and says how to fix it.

Note what is deliberately NOT here: a name helper. Service and workload names
are written out literally in the templates because the mounted configuration
files address peers by the bare compose service name, and a release-prefixed
name would break the pipeline silently. One release per namespace.
*/}}

{{- define "correlix.labels" -}}
app.kubernetes.io/name: correlix
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/version: {{ .root.Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .root.Chart.Name .root.Chart.Version }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "correlix.selectorLabels" -}}
app.kubernetes.io/name: correlix
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/*
correlix.image — dict: root, img (a map with repository/tag/digest), name.
Digest wins over tag; global.imageRegistry prefixes the repository.
*/}}
{{- define "correlix.image" -}}
{{- $reg := .root.Values.global.imageRegistry | default "" -}}
{{- $repo := .img.repository -}}
{{- if $reg }}{{- $repo = printf "%s/%s" (trimSuffix "/" $reg) $repo -}}{{- end -}}
{{- $digest := .img.digest | default "" -}}
{{- if $digest -}}
{{- printf "%s@%s" $repo $digest -}}
{{- else -}}
{{- if .root.Values.images.requireDigest -}}
{{- fail (printf "images.requireDigest is true but the %s image (%s) carries no digest. Publish the image and set <service>.image.digest, or set images.requireDigest=false and accept a mutable tag." .name $repo) -}}
{{- end -}}
{{- printf "%s:%s" $repo (.img.tag | default .root.Chart.AppVersion) -}}
{{- end -}}
{{- end -}}

{{/*
Pod-level fields every workload shares. `restricted` PodSecurity requires
runAsNonRoot + a seccomp profile at the pod level.
*/}}
{{- define "correlix.podCommon" -}}
serviceAccountName: {{ .root.Values.serviceAccount.name }}
automountServiceAccountToken: false
{{- with .root.Values.global.imagePullSecrets }}
imagePullSecrets:
{{ toYaml . | indent 2 }}
{{- end }}
{{- with .root.Values.global.nodeSelector }}
nodeSelector:
{{ toYaml . | indent 2 }}
{{- end }}
{{- with .root.Values.global.tolerations }}
tolerations:
{{ toYaml . | indent 2 }}
{{- end }}
{{- with .root.Values.global.affinity }}
affinity:
{{ toYaml . | indent 2 }}
{{- end }}
securityContext:
  runAsNonRoot: true
  runAsUser: {{ .uid | default 65532 }}
  runAsGroup: {{ .gid | default 65532 }}
  fsGroup: {{ .fsGroup | default (.gid | default 65532) }}
  fsGroupChangePolicy: OnRootMismatch
  seccompProfile:
    type: RuntimeDefault
{{- end -}}

{{/*
Container-level securityContext. PodSecurity `restricted` allows exactly one
added capability — NET_BIND_SERVICE — and nothing else; pass netBind=true for
the two services that bind a privileged port (syslog-ng 514, the api's SNMP
trap listener when it is moved below 1024).
*/}}
{{- define "correlix.containerSecurity" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: {{ .readOnlyRootFilesystem | default false }}
capabilities:
  drop: ["ALL"]
{{- if .netBind }}
  add: ["NET_BIND_SERVICE"]
{{- end }}
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{/*
The Secret every workload draws credentials from. Referenced, never created.
*/}}
{{- define "correlix.secretName" -}}
{{- required "secrets.existingSecret must name a Secret you created; this chart never generates credentials (see docs/DEPLOY_KUBERNETES.md)" .Values.secrets.existingSecret -}}
{{- end -}}

{{/*
Bootstrap broker list. Kept as a helper so an external Kafka-compatible cluster
is a one-line override rather than an edit in six places.
*/}}
{{- define "correlix.brokerUrls" -}}
kafka:9092
{{- end -}}

{{/*
Component selector for the NetworkPolicies: "any pod whose component label is
one of these". Kept here because a `define` may not follow another action at
the top of a template file.
*/}}
{{- define "correlix.compSelector" -}}
matchExpressions:
  - key: app.kubernetes.io/component
    operator: In
    values:
{{ toYaml .components | indent 6 }}
{{- end -}}
