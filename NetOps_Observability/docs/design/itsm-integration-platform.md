# ITSM / Collaboration Integration Platform — bidirectional, multi-tenant control plane

Status: **DESIGN.** Reconciles the proposed "Integration Control Plane" spec with
what already exists on this branch (#40 per-tenant connectors, #38 incident system
of record, #37/#39 async PG job substrate). The goal is to **evolve, not rebuild**:
~70% of the spec's reliability surface already ships; the genuinely new work is the
**inbound** path (webhooks + reconciliation), a formal **provider** abstraction,
and per-tenant **mapping/state** configuration.

Guardrails (CLAUDE.md): stdlib + the `pgx`/`sqlc` allowlist only. No Kafka/Redis
Streams for control-plane events — the Postgres job queue already gives
at-least-once + DLQ + idempotency with transactional consistency against incident
state (Redpanda stays the *telemetry* bus; integration events stay in PG so a
ticket write and an incident-state write commit together).

---

## 1. Spec → current-state gap map

| Spec requirement | Today | Gap / action |
|---|---|---|
| Outbound: alert → ITSM incident | ✅ per-tenant ServiceNow/Jira via incident projection (`incidents_sync.go`, `projectIncident` routes by `inc.TenantID`) | keep |
| Async, never sync in alert path | ✅ `EnqueueIncidentSync` → PG queue → worker; alert path only enqueues | keep |
| Queue + retry + DLQ + idempotency | ✅ `report_jobs_pg.go`: `FOR UPDATE SKIP LOCKED`, lease/visibility timeout, `attempts/max_attempts`, backoff, dead-letter; idempotent (skip if `external_ticket_id` set) | keep; generalize `job_type` to `integration_*` |
| Plugin providers (SN/Jira/PD/Slack) | ⚠️ one-way `notify.Channel{Name,Send}` + connectors per system | **wrap in a bidirectional `Provider` interface + registry** |
| **Inbound: ITSM → NMS state** | ❌ none (no webhook receiver, no poller) | **NEW — core of this design** |
| Tenant policy resolver | ✅ per-tenant `itsm_config` (`itsmKey(tenant)`) | extend to `integration_configs` (per provider, sync_mode, webhook) |
| Mapping engine (field + state) | ❌ severity→SN impact/urgency is hard-coded; no state map | **NEW — per-tenant `field_mappings` + `state_map`** |
| External↔internal correlation | ⚠️ forward only (`incident.external_ticket_id`) | **add reverse index** `(provider, external_id) → incident` |
| Credentials encrypted at rest | ❌ plaintext in kv | gated on **#17 swtpm** (AES-GCM envelope); interim = normalized table + clear seam |
| Webhook signature validation | ❌ | **NEW per provider** (SN shared-secret, Jira secret, PD HMAC, Slack v0 signing) |
| RBAC for config | ✅ admin + per-tenant scoping (`handleITSMConfig`) | extend to new endpoints |
| Audit of integration actions | ✅ `audit_events` (per-row, RLS) | emit on every inbound/outbound action |
| Per-tenant health / metrics | ⚠️ `/metrics` report gauges only | **NEW integration metrics + health endpoint** |
| Horizontal scale | ✅ lease-based PG queue, workers across instances | keep |

**Takeaway:** the *outbound + reliability spine* is done. This design adds the
**inbound half**, formalizes **providers**, and makes **mapping/state** per-tenant
configurable — turning the feature into a control plane.

---

## 1a. The closed loop (canonical lifecycle)

```
        ┌────────────────────────┐
        │         NMS            │  incident raised (alert/finding fold-in)
        └─────────┬──────────────┘
                  │ OUTBOUND SYNC   enqueue(integration_outbound) → worker → Provider.Apply
                  ▼
        ┌────────────────────────┐
        │  ITSM systems          │  ticket created/updated; external_id stored
        │  SNOW / Jira / PD      │  (Slack = notify + action source)
        └─────────┬──────────────┘
                  │ INBOUND SYNC    webhook (signed) ─or─ reconcile poll
                  ▼
        ┌────────────────────────┐
        │   State Reconciler     │  VerifyWebhook → Normalize → dedup(external_evt_id)
        │                        │  → MappingEngine(state_map) → correlate(provider,external_id)
        └─────────┬──────────────┘
                  │ SOURCE UPDATE   incident.Transition(...) — last-writer-wins by OccurredAt
                  ▼
        ┌────────────────────────┐
        │   NMS (source of truth)│  state converged; audit + metrics emitted
        └────────────────────────┘
```

Each box → concrete component (and the phase that builds it):

| Loop box | Component | Reuses | Phase |
|---|---|---|---|
| NMS → OUTBOUND | Outbound Event Router (`enqueueIntegrationEvent`) | incident SoR + PG queue | ✅ P0 / P1 reshape |
| ITSM systems | `Provider.Apply` (SN/Jira/PD/Slack) | existing connectors | ✅ P0 / P1 interface |
| INBOUND SYNC | Inbound webhook endpoint + drift poller | `tenantRateLimiter`, scheduler | P2 / P4 |
| **State Reconciler** | `Provider.VerifyWebhook`+`Normalize` → MappingEngine → Correlation | reverse `integration_mappings` index | **P2-P3** |
| NMS source update | `incident.Transition()` lifecycle | ack/investigate/resolve/close/reopen (exists) | P2 |

The reconciler is the only genuinely new control point; everything it calls
(queue, incident lifecycle, audit) already exists. Its hard requirements —
idempotency (`external_evt_id` dedup), drift/conflict resolution (last-writer-wins
by `OccurredAt`, NMS authoritative for severity / external for ticket fields), and
fail-closed verification — are specified in §4, §6, §9.

## 2. Architecture — the Integration Orchestrator

Reuse the existing worker pool (`reportPipeline`) as the orchestrator runtime;
add integration-specific job types and an inbound HTTP layer. One logical service,
horizontally scalable via the lease queue (no new process).

```
 OUTBOUND                                  INBOUND
 alert/incident                            ITSM/Slack webhook  ── or ──  reconcile poller
   │ enqueue(integration_outbound)           │ POST /api/integrations/webhook/{provider}/{tenantToken}
   ▼                                          ▼ verify signature + resolve tenant (fail-closed, bounded, rate-limited)
 PG job queue (SKIP LOCKED, lease, backoff, DLQ, idempotent)   enqueue(integration_inbound, raw payload)
   │                                          │
   ▼ worker                                   ▼ worker
 Provider.Outbound(event) ─► ITSM API        Provider.Normalize(payload) ─► canonical IntegrationEvent
   │ store external_id + state                │ MappingEngine: external state → internal state (per-tenant state_map)
   ▼                                          ▼ Correlation: (provider, external_id) → incident
 mapping row + audit + metrics              incident.Transition(...) + audit + metrics
```

Orchestrator sub-components mapped to code:
- **Outbound Event Router** = `enqueueIntegrationEvent` (generalize `EnqueueIncidentSync`).
- **Inbound Event Processor** = new `integrations_webhook.go` handler + `integration_inbound` job worker.
- **Retry Engine** = the PG queue (exists).
- **Mapping Engine** = `integration_mapping.go` (field + state translation, pure/testable).
- **Tenant Policy Resolver** = `integrationConfigStore` (per-tenant, per-provider; extends `itsm_config`).
- **Correlation Engine** = reverse index lookup → existing incident dedup/lifecycle.

---

## 3. Provider plugin model (extensibility without core changes)

Generalize today's one-way `notify.Channel` into a bidirectional capability-typed
interface. Existing `notify.ServiceNow/Jira/Slack/PagerDuty` become the first
implementations (outbound methods already exist; add inbound).

```go
// Provider is a pluggable ITSM/collaboration integration. Registered by type;
// the orchestrator never imports a concrete provider.
type Provider interface {
    Type() string                  // "servicenow" | "jira" | "pagerduty" | "slack"
    Capabilities() Capabilities    // ticketing? webhooks? polling? interactive?

    // Outbound (exists today, reshaped to the canonical event)
    Apply(ctx context.Context, conn Conn, ev OutboundEvent) (ExternalRef, error)

    // Inbound (NEW)
    VerifyWebhook(r *http.Request, secret string) (rawBody []byte, err error) // signature + replay window
    Normalize(raw []byte) ([]IntegrationEvent, error)                          // provider payload → canonical
    // Poll is optional (Capabilities.Poll); used by the reconciler for drift / missed webhooks.
    Poll(ctx context.Context, conn Conn, since time.Time) ([]IntegrationEvent, error)
}

type Capabilities struct {
    Ticketing   bool // SN/Jira yes; PD partial; Slack no
    Webhooks    bool
    Polling     bool
    Interactive bool // Slack Block Kit actions, PD ack
}
```

Registry: `map[string]Provider` seeded at startup; adding a provider = one file +
one `Register`. The orchestrator core is provider-agnostic (satisfies CLAUDE.md
§4 plugin-isolation and §7 "extensible without core changes").

---

## 4. Canonical event + state machine

```go
type IntegrationEvent struct {
    Provider     string
    Tenant       string
    ExternalID   string            // ticket/incident id in the external system
    ExternalEvtID string           // provider event id / etag — idempotency key
    Type         EventType         // incident.created|updated|acknowledged|resolved|assigned|comment_added
    ExternalState string           // raw external state ("In Progress", "6", "resolved", …)
    Actor        string
    Comment      string
    Assignee     string
    OccurredAt   time.Time
    Raw          json.RawMessage
}
```

**State reconciliation** — per-tenant configurable map external→internal, with a
shipped default:

| External (normalized) | Internal incident state |
|---|---|
| new / open | Open |
| acknowledged / in progress | Acknowledged |
| investigating | Investigating |
| resolved / closed / done | Resolved → (auto) Closed |
| escalated | Open + severity bump |

Conflict policy (drift): **last-writer-wins by `OccurredAt`**, but NMS-originated
transitions within a short window are authoritative for fields NMS owns
(severity), external authoritative for ticket fields (assignee, ticket comments).
Configurable per tenant; default documented above.

---

## 5. Data models — reconciled (extend, don't duplicate)

New migration `0006_integrations.sql` (RLS, `FORCE ROW LEVEL SECURITY`,
`tenant_iso` policy — same pattern as 0001-0005).

```sql
-- Per-tenant, per-provider config (supersedes the itsm_config kv blob).
integration_configs(
  tenant_id text, provider text,            -- PK (tenant_id, provider)
  enabled boolean, sync_mode text,          -- 'outbound' | 'bidirectional'
  webhook_enabled boolean, webhook_secret_enc bytea,  -- enc via #17 envelope (interim: obfuscated)
  credentials_enc bytea,                    -- connector creds (enc; today plaintext in kv)
  field_mappings jsonb, state_map jsonb,    -- mapping engine inputs
  status text, updated_at timestamptz)

-- External↔internal correlation (the reverse index inbound needs).
integration_mappings(
  tenant_id text, provider text, external_id text,  -- PK (tenant_id, provider, external_id)
  internal_incident_id text, state text,
  external_etag text, last_synced_at timestamptz,
  UNIQUE(tenant_id, provider, external_id))

-- Durable event log (outbound + inbound) for idempotency, audit, observability.
integration_events(
  id text PK, tenant_id text, provider text,
  direction text,                           -- 'outbound' | 'inbound'
  type text, external_evt_id text,          -- dedup key (tenant, provider, external_evt_id)
  status text, retry_count int, error text,
  payload jsonb, created_at, updated_at,
  UNIQUE(tenant_id, provider, external_evt_id))   -- at-least-once → exactly-once effect
```

Reuse, don't re-create:
- **The job queue** (`report_jobs`) carries the *work* (`job_type` =
  `integration_outbound` / `integration_inbound`); `integration_events` is the
  *ledger* (idempotency + observability). Migration 0004 already generalized jobs.
- **The incident** remains the internal alert/state entity; `external_ticket_id`
  stays the forward link; `integration_mappings` is the reverse link.
- **`itsm_config`** migrates into `integration_configs` (its per-tenant kv map →
  rows). This is the same blob→rows normalization theme as #19/M0.

---

## 6. Inbound webhook layer (the new core)

`integrations_webhook.go`:
```
POST /api/integrations/webhook/{provider}/{tenantToken}
```
- **Unauthenticated by app JWT** (external systems can't carry it) — prefixed in
  `withAuth` allowlist; does its OWN auth via provider signature + the opaque
  per-tenant `tenantToken` (random, stored in `integration_configs`, rotates).
- **Verify** (`Provider.VerifyWebhook`): per-provider signature —
  Slack v0 (`crypto/hmac` SHA-256 over `v0:ts:body` + 5-min replay window),
  PagerDuty `X-PagerDuty-Signature` HMAC, Jira webhook secret, ServiceNow shared
  secret/Basic. Fail-closed; `http.MaxBytesReader`; per-tenant rate limit (reuse
  `tenantRateLimiter`); `TRUST_PROXY`-gated XFF (same hardening as log-export #39).
- **Enqueue fast**: persist raw to `integration_events(inbound)`, enqueue
  `integration_inbound` job, return `200` immediately (no sync external work).
- **Worker**: `Normalize` → dedup on `external_evt_id` → `MappingEngine` →
  correlate `(provider, external_id)` → `incident.Transition(...)` (reuses the
  existing lifecycle: ack/investigate/resolve/close/reopen + note/assign) →
  audit + metrics. Unknown mapping → DLQ with a typed reason, never a 5xx to the
  caller.

---

## 7. Reconciliation / drift poller

For `sync_mode=bidirectional` providers with `Capabilities.Polling`, a scheduled
job (reuse the report scheduler's recurrence/jitter) per tenant+provider pulls
open mappings' external state via `Provider.Poll(since=last_synced_at)` and
reconciles drift — covers missed/duplicated webhooks (at-least-once world) and
providers without webhooks. Bounded batch; same idempotency ledger.

---

## 8. Slack as a special case

Slack is notification + **action source**, not a ticket store:
- Outbound: rich Block Kit message with **Acknowledge / Resolve / Escalate**
  buttons (reuse `notify.Slack`, extend payload).
- Inbound: Slack **Interactivity** webhook (`/api/integrations/webhook/slack/{token}`)
  → verify v0 signing secret → action → `incident.Transition` AND optionally
  fan the same transition to the tenant's ticketing provider (ack in Slack →
  ack in ServiceNow). Slack never holds authoritative ticket state.

---

## 9. Security

- **Credentials at rest**: today plaintext in the `itsm_config` kv — this design
  moves them to `integration_configs.credentials_enc` / `webhook_secret_enc`,
  encrypted with the **#17 swtpm** TPM-sealed KEK + stdlib `crypto/aes` GCM
  envelope (per-tenant KEKs). **Hard dependency on #17**; interim ships the column
  + a pluggable `Sealer` (identity/no-op until #17 lands) so the schema is final.
- **Webhook auth**: per-provider signature + opaque per-tenant token in the path;
  replay windows; fail-closed.
- **Tenant isolation**: RLS on all three tables; the orchestrator resolves tenant
  from the token/payload and binds `app.current_tenant` (same as #33).
- **RBAC**: config writes = admin, scoped to the caller's tenant (platform owner
  cross-tenant), reusing `handleITSMConfig`'s model.
- **Audit**: every inbound/outbound integration action → `audit_events`.

---

## 10. Observability

- **Metrics** (`/metrics`): `integration_events_total{provider,direction,status}`,
  `integration_delivery_seconds` histogram, `integration_queue_depth{job_type}`
  (from the PG queue), `integration_webhook_received_total{provider}`,
  `..._rejected_total{reason}`.
- **Per-tenant health endpoint** `GET /api/integrations/health` → per provider:
  enabled, sync_mode, last inbound/outbound ok, success/failure rates, queue
  depth, last error. Backs an admin "Integration Health" panel.
- **Webhook ingestion log**: `integration_events(inbound)` is queryable per tenant.

---

## 11. Phased plan

- **P0 — done**: outbound per-tenant + async spine + idempotency + DLQ (#40/#38/#37).
- **P1 — provider + config normalization**: `Provider` interface + registry
  (wrap existing connectors); `integration_configs` table (migrate `itsm_config`);
  reverse `integration_mappings` index; `Sealer` seam. *No behavior change.*
- **P2 — inbound (SN + Jira)**: webhook endpoint + signature verify + normalize +
  state_map + correlate → incident lifecycle; `integration_events` ledger; audit.
- **P3 — PagerDuty + Slack interactivity**: ack/resolve/escalate actions → state,
  fan-out to ticketing.
- **P4 — reconciliation poller + observability**: drift correction; metrics +
  health endpoint + admin panel.
- **P5 — credential encryption**: wire the `Sealer` to #17 (swtpm); migrate
  plaintext creds → envelope; RBAC/audit polish.

---

## 12. Deliberate deviations from the spec (and why)

- **No Kafka/Redis for control-plane events** — the Postgres `FOR UPDATE SKIP
  LOCKED` queue already gives at-least-once + DLQ + retry, and keeps integration
  writes transactional with incident state. Adding a broker would violate the
  stdlib+pgx guardrail for no real reliability gain at this scale. (Telemetry
  keeps Redpanda; the two buses stay separate by purpose.)
- **One binary, queue-scaled** — horizontal scale is "run more API replicas";
  lease-based claiming already prevents double-processing. No separate
  orchestrator service to operate.
- **Encryption-at-rest is staged behind #17** — schema is final now (the `_enc`
  columns + `Sealer`), so no migration later; the actual sealing lands with the
  TPM work rather than blocking inbound sync on it.
