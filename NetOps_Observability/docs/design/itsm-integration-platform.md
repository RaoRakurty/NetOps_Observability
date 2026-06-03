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
        │  Normalization +       │  VerifyWebhook → Normalize → 3-level dedup
        │  Ordering / Causality  │  → per-incident sequencing (watermark) → drop/reorder stale
        └─────────┬──────────────┘
                  │ ORDERED EVENT   causally-correct, deduped, in-order per external_incident
                  ▼
        ┌────────────────────────┐
        │   State Reconciler     │  MappingEngine(state_map) → priority conflict resolution
        │                        │  → correlate(provider, external_id) → decide internal action
        └─────────┬──────────────┘
                  │ SOURCE UPDATE   incident.Transition(...) — priority rules, not bare LWW
                  ▼
        ┌────────────────────────┐
        │   NMS (source of truth)│  state converged; audit + metrics emitted
        └────────────────────────┘
```

**Two control planes, not one.** The reconciler decides *what the state should
be*; it must be fed *causally-correct, deduped, in-order* events — otherwise
webhooks + retries + polling (an at-least-once, multi-source world) produce
resolved-before-acknowledged, duplicate reopen/close flapping, and wrong SLA
math. So an **Event Normalization + Ordering / Causality Layer** sits *before*
the reconciler. See §4a (ordering), §4c (conflict resolution), §4d (idempotency).

Each box → concrete component (and the phase that builds it):

| Loop box | Component | Reuses | Phase |
|---|---|---|---|
| NMS → OUTBOUND | Outbound Event Router (`enqueueIntegrationEvent`) | incident SoR + PG queue | ✅ P0 / P1 reshape |
| ITSM systems | Provider Adapter (`Provider.Apply`) | existing connectors | ✅ P0 / P1 interface |
| INBOUND SYNC | Inbound Ingestion (webhook endpoint + drift poller) | `tenantRateLimiter`, scheduler | P2 / P4 |
| **Normalization + Ordering** | `Provider.Normalize` + **Causality/Ordering engine** (3-level dedup, per-incident watermark) | `integration_events` ledger | **P2 (new core)** |
| **State Reconciler** | MappingEngine + priority conflict resolver + Correlation | reverse `integration_mappings` index | **P2-P3** |
| NMS source update | Incident Lifecycle Engine (`incident.Transition()`) | ack/investigate/resolve/close/reopen (exists) | P2 |

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

The orchestrator is a **6-layer pipeline** (the layering is the contract; each
layer is independently testable and replaceable):

| # | Layer | Responsibility | Code | Status |
|---|---|---|---|---|
| 1 | **Outbound Router** | alert/incident → enqueue → provider | `enqueueIntegrationEvent` (generalizes `EnqueueIncidentSync`) | ✅ exists |
| 2 | **Provider Adapter** | per-provider in/out translation (no core deps) | `integration.Provider` registry | P1 |
| 3 | **Inbound Ingestion** | receive webhooks / poll; verify signature; persist raw; enqueue | `integrations_webhook.go` + `integration_inbound` worker | P2 |
| 4 | **Normalization + Ordering / Causality** | normalize → 3-level dedup → per-incident sequencing (watermark) → drop/reorder stale | `integration.Normalize` + `ordering.go` | **P2 (new)** |
| 5 | **State Reconciler** | map external→internal; priority conflict resolution; correlate to incident | `mapping.go` + `reconcile.go` | **P2-P3** |
| 6 | **Incident Lifecycle Engine** | apply the decided transition | `incident.Transition()` | ✅ exists |

Cross-cutting: **Retry Engine** = the PG queue (exists); **Tenant Policy
Resolver** = `integrationConfigStore` (per-tenant/provider, extends `itsm_config`);
**Audit/Metrics** = `audit_events` + `/metrics` (exist).

Layers 1, 2, 6 already ship or are thin wrappers. **Layers 3-5 are the new work**,
and **Layer 4 (ordering/causality) is the subtle, non-optional one** — without it
the reconciler (Layer 5) makes correct decisions on *incorrectly-ordered* input.

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

## 4. Canonical event, ordering & reconciliation

```go
type IntegrationEvent struct {
    Provider      string
    Tenant        string
    // --- 3-level idempotency keys (§4d) ---
    ProviderEvtID string  // (1) raw dedup — provider's event/delivery id
    ExternalID    string  // (2) logical dedup — ticket/incident id in the external system
    AlertID       string  // (3) business dedup — the internal alert/incident this maps to
    // --- ordering / causality (§4a) ---
    ExternalSeq   int64   // provider monotonic version (SN sys_mod_count, Jira changelog id, …); 0 if absent
    OccurredAt    time.Time
    // --- payload ---
    Type          EventType // incident.created|updated|acknowledged|resolved|assigned|comment_added
    ExternalState string    // raw external state ("In Progress", "6", "resolved", …)
    Actor         string
    Comment       string
    Assignee      string
    Raw           json.RawMessage
}
```

### 4a. Event Normalization + Ordering / Causality Layer (Layer 4)

Webhooks (at-least-once, retried) + polling (catch-up) + multiple providers means
events arrive **out of order and duplicated**. Applying them naïvely yields
resolved-before-acknowledged, reopen/close flapping, and corrupted SLA timers.
This layer guarantees the reconciler sees a **causally-correct, deduped,
monotonic stream per `(tenant, provider, external_id)`**:

1. **Dedup** (§4a, 3 levels) — drop raw/logical/business duplicates.
2. **Sequence** — order by a robust key, NOT wall-clock alone:
   `orderKey = (ExternalSeq, OccurredAt, providerPrecedence)`. Provider-supplied
   monotonic version (`ExternalSeq`) is primary because it's immune to clock
   drift; `OccurredAt` breaks ties; deterministic provider precedence breaks the
   rest.
3. **Watermark** — `integration_mappings.applied_seq` is the high-water mark per
   incident. An event whose `orderKey` is **≤** the watermark is **stale**:
   dropped (terminal already applied) or merged (non-conflicting field), never
   replayed as a transition. This is what stops flapping.
4. **Reorder window** (optional, P4) — a short hold buffer to reorder
   near-simultaneous events before applying; default off (watermark handles the
   common case), enabled per tenant if a provider is bursty.

The ordering engine is **pure** (events in → ordered/decided events out, given
the current watermark) and therefore exhaustively unit-testable with adversarial
orderings (resolve-then-ack, duplicate close, late reopen).

### 4b. State reconciliation (the map)

Per-tenant configurable map external→internal, with a shipped default:

| External (normalized) | Internal incident state |
|---|---|
| new / open | Open |
| acknowledged / in progress | Acknowledged |
| investigating | Investigating |
| resolved / closed / done | Resolved → (auto) Closed |
| escalated | Open + severity bump |

### 4c. Conflict resolution (priority order, NOT bare last-writer-wins)

`OccurredAt` alone is unsafe: clocks drift across systems and retries violate
ordering. After the ordering layer (§4a) has sequenced events, conflicts are
resolved by a **deterministic priority ladder**, evaluated top-down:

1. **Terminal states win for NMS** — once NMS marks an incident `Resolved`/`Closed`
   (the alert genuinely cleared), a later external non-terminal update does **not**
   reopen it. NMS owns "is the underlying condition still true?".
2. **Assignment / ownership → ITSM wins** — assignee, assignment group, owner are
   authoritative from the ticketing system (that's where humans triage).
3. **Intermediate states → event-time ordering** — ack/investigate/in-progress
   resolve by `orderKey` (§4a): `ExternalSeq` first (drift-immune), then
   `OccurredAt`.
4. **Tie → deterministic provider precedence** — a fixed, configured ordering
   (e.g. ServiceNow > Jira > PagerDuty > Slack) so the outcome is reproducible.

Field ownership summary: NMS owns severity + terminal lifecycle (it sees the
telemetry); ITSM owns assignment + ticket comments. All four rules are
per-tenant overridable; the ladder above is the shipped default. Pure + table-
driven → unit-tested with adversarial event pairs.

### 4d. Idempotency — three levels

A single logical change can arrive many times (webhook retry, poll overlap,
fan-out). Dedup at three scopes, each backed by a unique key:

1. **Raw dedup** — `ProviderEvtID` (the provider's delivery/event id). Unique
   `(tenant, provider, provider_evt_id)` on `integration_events` → a redelivered
   webhook is a no-op insert.
2. **Logical dedup** — `ExternalID` + `ExternalSeq`. Two different deliveries
   describing the *same ticket version* collapse via the §4a watermark
   (`applied_seq`) — never applied twice.
3. **Business dedup** — `(tenant, AlertID)`. The incident system already dedups
   alerts→one incident (`DedupKey`); inbound events resolve to that same incident,
   so N external tickets for one root cause don't spawn N internal state machines.

Without all three, reconciliation is noisy at scale (level 1 stops storms,
level 2 stops flapping, level 3 stops fan-out duplication).

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

-- External↔internal correlation (reverse index) + the ordering WATERMARK (§4a).
integration_mappings(
  tenant_id text, provider text, external_id text,  -- PK (tenant_id, provider, external_id)
  internal_incident_id text, state text,            -- level-2/3 correlation (§4d)
  applied_seq bigint, applied_at timestamptz,       -- high-water mark: last orderKey applied
  external_etag text, last_synced_at timestamptz,
  UNIQUE(tenant_id, provider, external_id))

-- Durable event log (outbound + inbound): 3-level idempotency + ordering + audit.
integration_events(
  id text PK, tenant_id text, provider text,
  direction text,                           -- 'outbound' | 'inbound'
  type text,
  provider_evt_id text,                     -- level-1 raw dedup (§4d)
  external_id text, external_seq bigint,    -- level-2 logical dedup + ordering key (§4a)
  alert_id text,                            -- level-3 business dedup (§4d)
  status text, retry_count int, error text,
  payload jsonb, occurred_at timestamptz, created_at, updated_at,
  UNIQUE(tenant_id, provider, provider_evt_id))   -- redelivery → no-op insert (exactly-once effect)
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
- **P1 — provider + ordering/reconciliation core (pure)**: `Provider` interface +
  registry (Type/Capabilities/VerifyWebhook/Normalize); SN/Jira/PD/Slack inbound
  translators (real HMAC verify + payload normalize); **`ordering.go`** (3-level
  dedup + per-incident watermark + orderKey) and **`mapping.go`/`reconcile.go`**
  (state_map + priority ladder §4c) — all pure + exhaustively unit-tested with
  adversarial orderings. *No live wiring / no behavior change.*
- **P2 — inbound wiring (SN + Jira)**: webhook endpoint + signature verify →
  ordering layer → reconciler → incident lifecycle; `integration_configs` table
  (migrate `itsm_config`); reverse `integration_mappings` index + `applied_seq`
  watermark; `integration_events` ledger (3-level dedup); `Sealer` seam; audit.
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
