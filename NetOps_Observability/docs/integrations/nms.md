# NMS / Controller Integrations (#95)

Correlix ingests third-party NMS and controller platforms as **controller
intelligence** — the state, SLA metrics and alarms each vendor platform already
computed become normalized RCA evidence, reconciled against direct telemetry.
Read-only: no connector ever writes to a controller.

Three signal classes, routed per class:

| Class | Where it lands | Example |
|---|---|---|
| `controller_metric` | VictoriaMetrics (`controller_metric_*`) | vManage app-route latency/jitter/loss/QoE |
| `controller_state`  | `controller_state_current` (PG, flap-tracked) | BFD session up/down, first/last seen, flap count |
| `controller_event`  | `netops.controller_events` → correlation → `corr_signals` | BFD down alarm → `controller_bfd_down` signal |

A controller is ONE modality (`management_plane`): controller-only evidence
caps at **suspected** — confirmation always needs corroborating direct
telemetry (the independence gate). Signatures like
`sdwan-tunnel-controller-corroborated` fire when both agree.

## Enable

```bash
# deployment/docker/.env
FEATURE_NMS_INTEGRATIONS=true
docker compose up -d api
```

UI: **Infrastructure → NMS Integrations** — pick a vendor card, walk the
wizard (connection → credentials → review), and the connector authenticates,
polls on its interval, and shows health/state/runs on the integration row.

Credentials are Vault-encrypted per tenant and **write-only** — the API and UI
only ever show which fields are set. Every integration is tenant-owned;
another tenant can't see or reach it.

## Try the whole cycle with no real controller

A bundled stdlib mock vManage ships as a compose profile
(`deployment/docker/mock-nms/`):

```bash
cd deployment/docker
docker compose --profile mock-nms up -d --build mock-nms
```

Connect **vManage / Catalyst SD-WAN Manager** in the UI:

| Field | Value |
|---|---|
| Base URL | `http://mock-nms:8091` |
| Username / Password | `correlix` / `correlix-mock-secret` |
| Streams | `alarms`, `statistics` |

The mock flaps a BFD session every ~90s (fresh event + state transition each
phase; steady polls dedupe) and serves four tunnels of jittering app-route
metrics whose loss spikes during the BFD-down phase — so you can watch the
metric lane corroborate the event lane.

Scripted proof of the full path (create → auth → poll → VM + state table +
`corr_signals`):

```bash
scripts/validate-nms-e2e.sh             # 7 asserted stages, PASS/FAIL
scripts/validate-nms-e2e.sh --teardown  # remove what it created
```

## Vendor connector matrix

| Vendor card | Auth (test-path / preferred) | Poll streams | Webhook |
|---|---|---|---|
| Meraki Dashboard | API key / OAuth bearer | alarms, inventory (needs `org` credential field) | ✔ shared-secret + HMAC |
| Catalyst Center | Basic → X-Auth-Token (60 min) | assurance_issues, inventory, events | — |
| Catalyst SD-WAN Manager (vManage) | user/pass → JWT (`/jwt/login`) | alarms, events, tunnels, control_connections, bfd, statistics, inventory | — |
| Nexus Dashboard / NDFC | user/pass (+`domain`) → JWT | fabric_alarms, switch_health, interface_alarms, inventory | — |
| Versa Director | OAuth client-credentials / Basic | alarms, appliances, events | — |
| Versa Concerto | OAuth client-credentials / Basic | alarms, appliances, events | — |
| Prime Infrastructure | Basic per request | alarms, inventory | — |
| Generic controller | Bearer / API key / Basic | events (`/events`) | ✔ HMAC (`X-Signature`) |

Vendor path placeholders (e.g. Meraki `{org}`) resolve from the credential
extras; an unresolved placeholder fails loudly rather than being sent raw.
Self-signed controllers: tick **Accept self-signed certificate** on the
integration (per-integration opt-in; default is strict TLS).

> **Honesty note:** transformers and pollers are built against current vendor
> API docs and validated against fixtures + the bundled mock. They have NOT yet
> been exercised against live vendor controllers — expect one-line fixes per
> vendor on first real contact (each transformer is a single file).

## Upgrading a live stack (ClickHouse enum drift)

`init.sql` shapes **fresh** ClickHouse volumes only. A stack whose
`netops.corr_signals` predates #95 needs the enum extensions applied once:

```sql
ALTER TABLE netops.corr_signals MODIFY COLUMN source
  Enum8('flow'=1,'probe'=2,'metric'=3,'alert'=4,'topology'=5,'syslog'=6,
        'sot_drift'=7,'trap'=8,'cloud'=9,'app_identity'=10,'controller'=11);
ALTER TABLE netops.corr_signals MODIFY COLUMN observer_type
  Enum8('device'=1,'vantage_agent'=2,'cloud_api'=3,'flow_exporter'=4,
        'platform'=5,'controller'=6);
ALTER TABLE netops.corr_signals MODIFY COLUMN modality_class
  Enum8('active_probe'=1,'passive_flow'=2,'control_plane'=3,
        'device_telemetry'=4,'management_plane'=5);
-- repeat all three for netops.corr_signals_archive
```

(Already applied to the lab stack 2026-07-03.) Symptom if missed: correlation
logs `Unknown element 'controller' for enum` and controller signals never
reach `corr_signals`.

## Operational surface

- `GET /api/nms/connectors` — catalog; `GET/POST /api/nms/integrations`;
  `GET/PUT/DELETE /api/nms/integrations/{id}`; `POST …/{id}/test` (live auth
  check); `POST …/{id}/poll` (immediate cycle, works while paused);
  `GET …/{id}/health` (snapshot + recent runs); `GET …/{id}/states`.
- `POST /api/nms/webhook/{token}` — inbound controller webhooks; JWT-exempt,
  authenticated by the opaque token + the connector's signature verification.
- Scheduler: each enabled integration polls on its own `pollIntervalS`
  (floored at 30s); `NMS_POLL_TICK` (default 30s) only re-evaluates due-ness.
- Correlation `/healthz` → `ingest.controller_events_*` counters prove the
  event lane end-to-end.
