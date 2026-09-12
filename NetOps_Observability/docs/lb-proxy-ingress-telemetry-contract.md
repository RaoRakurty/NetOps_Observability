# LB / proxy / ingress telemetry contract (#98 Phase 5)

A minimal, vendor-neutral contract for application-edge telemetry — load
balancers, reverse proxies, ingress controllers, gateways — as an
**independent corroboration lane** for application-impact RCA. Deliberately
NOT APM: no traces, spans, agents, or payload inspection; the app-edge device
reports its own request outcomes.

## Semantic kinds (canonical — the catalog already consumes these)

| kind | meaning | typical reasons |
|---|---|---|
| `lb_5xx` | 5xx family at the edge | `http_5xx`, `bad_gateway` (502), `backend_unavailable` (503), `gateway_timeout` (504), `upstream_connect_fail`, `connection_reset_high`, `request_drop_high` |
| `lb_target_unhealthy` | backend pool / member / target-group health | `backend_pool_down`, `pool_member_down`, `target_group_unhealthy` |
| `app_error_rate_high` | declared error-rate anomaly | `error_rate_high` |
| `app_latency_high` | declared latency anomaly (p95/p99/total) | `latency_high` |
| `lb_4xx_high` | high 4xx rate | `http_4xx_high` — **INTENTIONAL_BLIND**: an auth/config/client indicator, consumed by NO outage signature, can never confirm one |

No new vocabulary was invented — these are the kinds the app signatures
already referenced (they were `COLLECTION_PENDING` until this lane landed).

## Wire format (topic `netops.app.edge`)

Vendor-neutral JSON; every field optional-defensive, `tenant_id` REQUIRED
(default-closed — untenanted events are dropped, never guessed):

```json
{
  "source": "lb", "vendor": "generic", "product": "reverse_proxy",
  "tenant_id": "acme", "ts": "2026-07-09T09:00:30Z",
  "app_name": "customer_portal", "service_name": "portal_frontend",
  "host": "portal.acme.example", "path": "/login",
  "status_code": 503, "request_count": 1200, "error_count": 486,
  "error_rate": 0.405, "latency_ms": 3200,
  "lb_name": "edge-lb-01", "backend_pool": "portal_pool",
  "reason": "backend_unavailable", "raw_event_id": "lb-evt-7731"
}
```

`lb_normalize.normalize_lb_event` turns one event into **at most one** signal
(one raw observation = one evidence stream — a 503 that is also
backend-unavailable is one signal with the specific reason, never two).
`raw_event_id` becomes the dedup fingerprint (`native_id`).

## Modality / independence

`modality_class = device_telemetry` (the edge device reporting its own
counters), `attrs.lane = "app_gateway"`. That keeps LB evidence independent of
`active_probe` (synthetics) and `passive_flow` (flow anomalies) in the verdict
gate without widening the core modality taxonomy. One raw LB event can never
count as two witness classes.

## Grounding

Entity: explicit app (slug) → `entity_type=app`; else service/host →
`entity_type=service` (honest fallback, same policy as synthetics). Tokens:
`<slug>`, `app:<slug>`, `service:<name>`, `host:<host>`, `lb:<name>`,
`backend_pool:<pool>`, `site:<site|region>`. **No tenant token** — grounding
tokens are the engine's co-location keys and the correlation window is
single-tenant by construction; a tenant-wide token would merge unrelated apps
into one object (a real over-grounding bug this phase's cross-app test caught
and fixed in both this lane and the synthetic lane).

## Threshold policy

Discrete events (5xx status, backend health) map directly. Rate/latency kinds
require the event to declare `anomaly: true` (with measured/baseline fields) —
detection belongs to the emitting collector or an upstream baseline; this
normalizer never invents one.

## Verdict outcomes

| evidence | verdict |
|---|---|
| LB 503 alone | not confirmed (single witness class) |
| synthetic failure + same-app LB 503 | **confirmed** |
| synthetic + app-flow drop + LB 503 | **confirmed**, three independent classes |
| synthetic Teams + Salesforce LB 5xx | no attachment (different app tokens) |
| 4xx/auth spike | never confirms — `lb_4xx_high` is signature-blind |
| tenant A synthetic + tenant B LB | structurally impossible (single-tenant window) |

## Adding vendor parsers later

Vendor-specific formats (F5/NGINX/Envoy/HAProxy logs, ALB/App-GW exports)
should be parsed at the edge (Vector/collector) or in a small adapter that
emits THIS wire format onto `netops.app.edge` — the semantic vocabulary and
grounding rules above stay fixed. AWS ALB access logs already flow via the
cloud lane (`cloud_log_parsers.py` → `cloud_lb_log`).

Remaining future work: on-prem vendor log adapters; ELB/App-GW mapping onto
the canonical kinds; per-route SLO baselines.
