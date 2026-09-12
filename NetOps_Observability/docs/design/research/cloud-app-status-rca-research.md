# Cloud App Status / Health / Change / RCA — Research Findings (#81 P3C/D)

> Deep-research pass `wf_d7f8ca1d-e34`, 2026-06-25. 8 findings, all 3-0 confirmed vs
> PRIMARY vendor docs (+ Datadog for the RCA-anchor pattern). Feeds the cloud_health /
> cloud_change signal models and the app-to-underlay RCA join (P3C/P3D).

## Verdict (validates the status lane + two new signals)

The cloud app-STATUS lane ingests **five canonical signals** — `cloud_health`,
`cloud_change`, `cloud_metric`, `cloud_lb_access`, `cloud_trace` — via a **hybrid
stream-where-possible, poll-where-not** connector layer per provider, feeding the
SAME confidence-fusion engine. `confirmed` requires **one authoritative health signal
+ one supporting symptom** (or two independent evidence classes).

## Confirmed findings

**1. Golden-signal metrics — poll vs stream, per cloud.** AWS: poll `GetMetricData`
(500 rps/acct/region, 180k datapoints/sec for last 3h) OR **stream Metric Streams →
Firehose** (JSON / OTLP 1.0.0 / 0.7.0). Azure: **stream to Event Hubs via Diagnostic
Settings** as per-resource JSON (resourceId, metricName, count/total/min/max/average).
GCP: Cloud Monitoring. → prefer the native streaming sink for low-latency `cloud_metric`.
[aws CloudWatch-Metric-Streams; azure stream-monitoring-data-event-hubs]

**2. Metric-stream cost is volume-driven** (per metric-update + Firehose charges; 1
update = 4 stats) → **filter namespaces/metrics at the stream**, selective-poll low-volume targets. [aws cloudwatch_limits]

**3. LB access logs = the highest-fidelity per-request app-health signal, and they
SEPARATE LB-status from backend-status** — the structural basis for "is this a real
app 5xx or an LB 5xx." AWS ALB: `elb_status_code` (LB/WAF) vs `target_status_code`
(backend; `'-'` ⇒ no backend response, e.g. 502). Azure AGWAccessLogs: `HttpStatus`
(client) vs `ServerStatus` (backend). GCP external ALB: `statusDetails`
(backend_timeout / failed_to_connect_to_backend). → **`cloud_lb_access` is the
backbone health signal.** [aws load-balancer-access-logs; azure agwaccesslogs; gcp https-logging-monitoring]

**4. LB logs decompose latency LB-side vs backend-side** — attribute latency to app
vs LB path. ALB: `request_processing_time` / `target_processing_time` (backend, `-1`
if no response) / `response_processing_time`. Azure: `ServerResponseLatency` /
`ServerConnectTime` / `ServerHeaderTime` / `ClientResponseTime` / `TimeTaken`. GCP:
`total_latencies` − `backend_latencies`. → per-request latency evidence for RCA.

**5. LB logs carry the backend-target identifier = the join key to the identity
layer.** ALB: `target:port` + `target_group_arn`. Azure: `BackendPoolName` /
`ServerRouted` / `BackendSettingName`. GCP: `backend_service_name` / `url_map_name`.
CAVEAT: GCP `backendTargetProjectNumber` only populated for global ALBs w/ custom
error responses — not universal. → cloud_lb_access rows attribute to an app via the
target → resource → app chain.

**6. Direct availability state = the `cloud_health` source, and its state model maps
to our 'unknown'-first model.** Route 53 `HealthCheckStatus` = 1 healthy / 0 unhealthy
(aggregate). CloudWatch alarm = **OK / INSUFFICIENT_DATA / ALARM**, where
**INSUFFICIENT_DATA ≈ our first-class `unknown`** (not "healthy"). → design
`cloud_health` as **up/degraded/down/unknown**, not binary; authoritative health
signal (Route53 / ELB target health / Resource Health) + one supporting symptom = confirmed.
[aws Route53 monitoring-health-checks]

**7. Change/deploy is a first-class RCA causality anchor — validated by how leaders
work.** Datadog Watchdog scopes RCA to four categories with **version-changes/deploys
listed FIRST** (via APM Deployment Tracking). → elevate `cloud_change` to canonical
and implement the **deploy→degradation temporal rule** (a change shortly before a
health-degradation onset becomes the RCA anchor; never *confirmed* from change alone).
[datadog watchdog/rca; change-overlays]

**8. Per-provider delivery converges** → standardize one connector strategy:
**stream via Firehose (AWS) / Event Hubs (Azure) / Pub-Sub (GCP); poll only where
streaming is unavailable.** Connectors are the documented SDK exception; everything
downstream stays stdlib. [azure application-gateway-diagnostics]

## Caveats (honesty — what's NOT source-confirmed)

- **GCP read-quota REFUTED (0-3):** the assumed 60,000 req/min figure is wrong —
  the GCP connector must **discover + respect the actual current quota at runtime**,
  and prefer the Pub/Sub log-sink over polling.
- **Evidence is AWS/Azure-skewed.** LB-log + health-state findings are deeply verified
  for AWS (ALB + Route 53) and Azure (AGWAccessLogs); **verified GCP coverage is
  narrower** (external ALB only — GCP Uptime checks / Service Health / LB backend
  health did NOT surface as confirmed).
- **Design-inference, NOT source-confirmed (treat as recommendation):** dependency/
  tracing root-cause (X-Ray / App Insights / Cloud Trace / OTel), orchestration
  pod/task health (OOMKilled / CrashLoopBackOff / restarts), data-tier status
  (RDS/SQL/Cloud SQL slow-query / conn-pool), and the **cloud-network / hybrid-underlay
  seams** (NAT GW, Transit Gateway, Direct Connect / ExpressRoute / Interconnect, flow
  rejects, BGP). The app-to-underlay RCA join + root domains beyond application/deploy/
  cloud_resource/cloud_network rest on industry pattern-matching → build with explicit
  "design recommendation" labels + low default confidence until grounded on real data.
- Pricing specifics (~$0.003/1k updates, ~$0.029/GB Firehose) are corroborating context.

## Direct design implications (→ P3C/P3D signal models)
- **`cloud_health`**: states up/degraded/down/**unknown** (INSUFFICIENT_DATA=unknown);
  symptom ∈ latency/errors/saturation/availability/target_unhealthy/dependency_unhealthy.
- **`cloud_lb_access`**: separate `elb_status_code`/`target_status_code` (LB-vs-backend
  5xx) + LB-vs-backend latency split + the backend-target join key. The single richest
  app-health log.
- **`cloud_change`**: deploy/config/route/security/IAM/dns/cert; the deploy→degradation
  rule is the RCA anchor (never *confirmed* alone; needs a health/traffic symptom).
- **Verdict ladder**: confirmed = 1 authoritative health + 1 supporting symptom (or 2
  independent evidence classes); the underlay/dependency domains stay *suspected* until
  grounded on verified per-provider state models (open questions below).

## Open questions (carry to P3D / future research)
1. GCP's actual current Cloud Monitoring read-quota + whether Pub/Sub sink removes polling.
2. Evidence-grounding the app-to-underlay RCA join for hybrid_underlay / cloud_network (NAT/TGW/DX/ExpressRoute/Interconnect, flow rejects, BGP).
3. Authoritative state models + event fidelity for non-AWS direct-health (GCP Uptime/Service Health/LB backend; Azure Resource Health).
4. Dependency/data-tier grounding (RDS/SQL conn-pool; X-Ray/App-Insights/Cloud-Trace/OTel downstream attribution).
