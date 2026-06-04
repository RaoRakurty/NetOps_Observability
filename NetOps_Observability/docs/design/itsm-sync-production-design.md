# Production-grade bidirectional ITSM sync — design enhancement

Status: **DESIGN.** Upgrades the integration platform (`itsm-integration-platform.md`)
to Datadog↔ServiceNow maturity. **Enhances, does not replace** — most of the spine
is already built and live-proven (P1 pure core `5a046a6`, P2a persistence `f1e61b6`,
P2b inbound→incident `ad998d6`). This doc delivers the 7 requested sections, marks
**[DONE]** vs **[PLAN]**, and is explicit about the production hardening the current
(inline, best-effort) P2b still needs.

Legend: **[DONE]** shipped + live-verified · **[PARTIAL]** built but needs hardening ·
**[PLAN]** designed, not yet built.

---

## 1. Architecture (ASCII)

```
                          ┌──────────────────────────────────────────────┐
                          │              NMS — System of Record           │
                          │   Alert Engine → Incident Engine (canonical)  │
                          └───────────────┬───────────────▲──────────────┘
       OUTBOUND                           │ enqueue        │ apply (idempotent)
       (NMS → ITSM)                       ▼                │
                          ┌──────────────────────────────────────────────┐
                          │            INTEGRATION ORCHESTRATOR           │
                          │  ┌────────────┐   PG queue (SKIP LOCKED,      │
                          │  │ Outbound   │──▶ lease, backoff, DLQ) ──┐   │
                          │  │ Router     │                           │   │
                          │  └────────────┘                           ▼   │
   ┌───────────┐          │  ┌────────────┐   ┌──────────────────────────┴┐│
   │ ServiceNow│◀────────▶│  │ Provider   │   │ Worker: Provider.Apply     ││
   │ Jira      │  REST    │  │ Adapter    │──▶│ (Create/Update/Resolve)    ││
   │ PagerDuty │  /v2/v3  │  │ Registry   │   │ → persist ExternalMapping  ││
   │ Slack     │          │  └────────────┘   └────────────────────────────┘│
   └─────┬─────┘          │        ▲                                         │
         │ webhook (signed)│        │ canonical event                         │
         ▼                │  ┌────────────┐  ┌────────────┐  ┌─────────────┐ │
   ┌───────────────┐      │  │ Inbound    │  │ Normalize +│  │ State       │ │
   │ Inbound       │─────▶│  │ Ingestion  │─▶│ Ordering / │─▶│ Reconciler  │─┘
   │ (webhook/poll)│      │  │ (verify)   │  │ Causality  │  │ (conflict)  │
   └───────────────┘      │  └────────────┘  └────────────┘  └─────────────┘
         ▲                │                                                   
         │ poll           │  ┌──────────────────────────────────────────────┐
         └────────────────┼──│ DRIFT RECONCILER (periodic): poll vs NMS,     │
                          │  │ detect mismatch, re-drive through SAME pipes  │
                          │  └──────────────────────────────────────────────┘
                          └──────────────────────────────────────────────────┘
  Cross-cutting: RLS per tenant · correlation_id chain · audit_events · /metrics
```

6-layer pipeline (each independently testable): **Outbound Router · Provider
Adapter · Inbound Ingestion · Normalization+Ordering · State Reconciler · Incident
Lifecycle**. Layers 2/4/5 live in the pure `integration` package; 1/3/6 in the
server. **[DONE]** for the inbound half; outbound Update/Resolve + drift loop are
**[PARTIAL]/[PLAN]** (below).

---

## 2. Canonical Incident Identity Model

The crux the prior design under-formalized: **three identity tiers**, with the
canonical incident as the single join point (a hub-and-spoke, NOT a mesh).

```
  Alert(s)  ──dedup(tenant, dedup_key)──▶  Canonical Incident  ──▶  External Mapping (per provider)
  alert_id                                  incident_id (PK)         (tenant, provider, external_id) → incident_id
  (N alerts fold into 1 incident)           the SYSTEM OF RECORD     (≤1 active mapping per provider)
```

| Tier | Identifier | Owner | Cardinality |
|---|---|---|---|
| **Source signal** | `alert_id` (finding/alert) | NMS detectors | **N** alerts → 1 incident (existing `dedup_key` storm-proof unique index) **[DONE]** |
| **Canonical** | `incident_id` | NMS Incident Engine (SoR) | the hub; 1 per real-world condition **[DONE]** |
| **External** | `external_id` per provider (SN number, Jira key, PD id, Slack n/a) | the ITSM system | **≤1 per provider** per incident; many providers per incident **[DONE]** via `integration_mappings` PK `(tenant, provider, external_id)` + `internal_incident_id` |

**Why hub-and-spoke:** an inbound event from ServiceNow and one from PagerDuty for
the *same* outage both resolve to the *one* `incident_id` (level-3 business dedup),
so they drive a single state machine — never two divergent ones. Correlation:
- Slack → `incident_id` is carried directly (the Block Kit button `value`). **[DONE]**
- Ticketing → `external_id` ↔ `external_ticket_id` forward link (`FindByExternalTicket`). **[DONE]**
- Reverse index + ordering watermark: `integration_mappings`. **[DONE]**

---

## 3. Canonical State Machine

### Canonical states + allowed transitions  **[DONE]** (existing incident lifecycle)

```
            ┌─────────────────────────── reopen ───────────────────────────┐
            ▼                                                               │
  ┌──────┐  ack   ┌──────────────┐  investigate  ┌───────────────┐  resolve ┌──────────┐  close  ┌────────┐
  │ Open │──────▶ │ Acknowledged │──────────────▶│ Investigating │────────▶ │ Resolved │───────▶ │ Closed │
  └──┬───┘        └──────┬───────┘               └──────┬────────┘          └────┬─────┘         └────────┘
     │  resolve          │ resolve                      │ resolve               │ reopen
     └───────────────────┴──────────────────────────────┴───────────────▲──────┘
                                                                          (Resolved → Open only)
```
`validTransition()` enforces this; `Resolved`/`Closed` are terminal (reopen allowed
from Resolved only). Terminal = NMS-owned in conflict resolution (§5).

### Provider → canonical mapping (the `state_map`, per-tenant overridable) **[DONE]**

| Canonical | ServiceNow (numeric) | Jira | PagerDuty | Slack action |
|---|---|---|---|---|
| **Open** | New `1`, *(reopened)* | Open / To Do / Reopened | Triggered | — (escalate→Open) |
| **Acknowledged** | In Progress `2` | In Progress | **Acknowledged** | `ack_incident` |
| **Investigating** | On Hold `3` | In Review | *(n/a)* | — |
| **Resolved** | Resolved `6` | Done / Resolved | **Resolved** | `resolve_incident` |
| **Closed** | Closed `7`, Canceled `8` | Closed | *(→Resolved)* | — |

Providers normalize native state → these lowercase tokens in `Normalize()`
(SN numeric translation built); the reconciler maps token → canonical via the
per-tenant `MappingEngine` (defaults + `state_map` overrides). **[DONE]**

---

## 4. Bidirectional Sync Flow

### A. Outbound (NMS → ITSM)

```
alert → Ingest (dedup → incident) → [critical|manual promote] enqueue(integration_outbound)
  → PG queue claim (SKIP LOCKED, lease) → Provider.Apply(Create|Update|Resolve)
  → persist external mapping (external_id) + ledger(outbound) → audit
```
- **Create + auto-Resolve on alert-clear**: **[DONE]** (`incidents_sync.go`,
  per-tenant `projectIncident`, idempotent on `external_ticket_id`, retry+backoff+DLQ).
- **Update (severity/notes) + push-Resolve from NMS-side transition**: **[PARTIAL]** —
  connectors have resolve; need an outbound event on every NMS lifecycle change
  (not just create/clear) so NMS→ITSM tracks intermediate states. **[PLAN]**

### B. Inbound (ITSM → NMS)  **[DONE]** (P2b, live-proven)

```
webhook POST /api/integrations/webhook/{provider}/{token}
  → resolve config by token (platform scope)          [auth: token]
  → Provider.VerifyWebhook(sig + replay window)        [auth: signature] — fail-closed 401
  → Provider.Normalize → []IntegrationEvent
  → RecordInbound (level-1 dedup: unique provider_evt_id) — redelivery = no-op
  → [FEATURE_ITSM_INBOUND && bidirectional]:
       Order (watermark) → Reconcile (conflict ladder) → incident.Transition/Assign/AddNote
       → Advance watermark → ledger(applied|dropped:reason) → audit
  → 200 {received, applied}
```
Verified live: 401/404 auth, ingest-only when flag off, redelivery deduped, SN
resolve→incident resolved + watermark advanced, **stale event dropped (no flap)**.

---

## 5. Event Ordering + Idempotency  **[DONE]**

**3-level dedup** (`integration_events`):
1. `provider_evt_id` — raw (redelivery) → DB unique → no-op insert.
2. `external_id` + `external_seq` — logical → §4a watermark, never applied twice.
3. `(tenant, alert_id/incident_id)` — business → hub-and-spoke → one state machine.

**Ordering (hybrid, drift-immune):** `orderKey = (external_seq, occurred_at,
provider_precedence)`. `external_seq` (SN `sys_mod_count`, Jira changelog id) is
primary — monotonic, immune to clock skew; `occurred_at` breaks ties; provider
precedence is the final deterministic tie-break. Per-incident **watermark**
(`integration_mappings.applied_seq`): an event ≤ watermark is **stale → dropped**.

**Retry-safe:** at-least-once everywhere; idempotency from (a) the unique ledger
keys, (b) the watermark, (c) transitions to the same state being no-ops.

---

## 6. Conflict Resolution Engine  **[DONE]** (`reconcile.go` priority ladder)

Deterministic ladder, top-down (clock-skew/retry safe because ordering already ran):
1. **Stale** (≤ watermark) → drop, no replay.
2. **Terminal = NMS wins** — NMS `Resolved`/`Closed` is not reopened by a non-terminal
   external update (NMS sees the telemetry; it owns "is the condition still true?").
3. **Assignment / comments = ITSM wins** — ownership + ticket notes are authoritative
   from the triage system.
4. **Intermediate states** — by `orderKey` (event-time order).
5. **Tie** — deterministic provider precedence (ServiceNow > Jira > PagerDuty > Slack;
   per-tenant overridable).

**System-of-record rule:** NMS owns *lifecycle terminal state + severity*; ITSM owns
*assignment + ticket comments*. All per-tenant configurable.

---

## 7. State Reconciler / Drift Loop  **[DONE inbound `10c2a06`]** — the core algorithm

Webhooks are unreliable (dropped, duplicated, out-of-order). The reconciler is the
**safety net** that converges NMS↔ITSM regardless. It re-drives everything through
the **same** ordering/reconcile/outbound pipelines (no special path) → idempotent.

Schedule: reuse the report scheduler's recurrence/jitter; one run per
`(tenant, provider)` where `sync_mode=bidirectional` and `Capabilities.Polling`.

```
reconcile(tenant, provider):
  for mapping in open_mappings(tenant, provider, last_synced_at < now - interval):   # bounded batch, lease
    inc      = incidents.Get(mapping.internal_incident_id)
    ext      = provider.Poll(mapping.external_id)            # current external state + version (etag/seq)
    if ext.version <= mapping.applied_seq and inc.state == map(ext.state):
        continue                                            # in sync → no-op (idempotent)

    # DRIFT CASES
    if ext.version > mapping.applied_seq:                    # (a) missed/late inbound
        ev = synthesize_event(ext)                          # same canonical IntegrationEvent shape
        run_inbound_pipeline(ev)                            # Order→Reconcile→apply (idempotent via watermark)

    elif inc.is_terminal and not ext.is_terminal:           # (b) NMS resolved, ITSM still open
        enqueue_outbound(Resolve, inc, provider)            # NMS owns terminal → push resolve

    elif ext.is_terminal and not inc.is_terminal:           # (c) ITSM closed, NMS open
        run_inbound_pipeline(synthesize_event(ext))         # apply via conflict ladder

    mapping.last_synced_at = now                            # advance scan cursor
  emit drift_metrics(checked, repaired, divergent)
```

Properties: **idempotent** (re-running when in-sync is a no-op via watermark +
unique keys), **safe under races** (corrective actions flow through the same
at-least-once pipelines; the watermark serializes), **bounded** (batch + lease +
backoff), **observable** (drift counters + per-repair ledger rows). A divergence
that can't auto-repair (e.g. unmapped external state) → DLQ + alert, never a silent
wrong state.

**Built (`10c2a06`):** `integration_reconciler.go` — periodic loop
(`FEATURE_ITSM_RECONCILE`, default off, `ITSM_RECONCILE_INTERVAL=5m`) + on-demand
`POST /api/integrations/reconcile` (NOC "sync now"). Polls open mappings
(`Provider.PollState` on SN/Jira), and on `version > applied_seq` synthesizes a
canonical event re-driven through the inbound pipeline. The outbound projection now
seeds `integration_mappings` so tickets are pollable. Live-verified: a ticket
resolved-in-SNOW with no webhook → reconcile detected drift → incident converged.
**Remaining (case b):** NMS-terminal-but-external-open → push an outbound Resolve
(today the reconciler drives ITSM→NMS only; NMS→ITSM re-push is the next slice).

---

## 8. Multi-Tenant Isolation  **[DONE]**

- **Credentials**: per-tenant connectors (`itsm_config`, #42) + per-tenant webhook
  token+secret (`integration_configs`, P2b). Webhook token (globally unique)
  resolves the tenant for an unauthenticated request.
- **Event boundaries**: RLS `FORCE` + `tenant_iso` on `incidents`,
  `integration_{configs,mappings,events}`; every read binds `app.current_tenant`;
  reconciler runs per-tenant scope. Inbound routing can only reach the token's tenant.
- **Sync rules**: `state_map`, provider precedence, `sync_mode`, thresholds — all
  per `(tenant, provider)`.
- **Secrets at rest**: plaintext today → #17 swtpm AES-GCM envelope (schema `_enc`
  columns final). **[PLAN]**

---

## 9. Observability  **[DONE]**

- **Correlation chain**: `alert_id ↔ incident_id ↔ (provider, external_id) ↔ ledger
  event id`. **[DONE]** A single `correlation_id` (`ic-…`) is minted in
  `RecordInbound`, persisted on `integration_events` (migration 0008, indexed +
  backfill-safe), carried through the async job payload (survives crash/re-claim)
  into the worker apply + incident-transition log, and logged at every hop
  (webhook record → enqueue → apply → verdict). Reconciler-synthesized drift
  events carry it too. One grep of an id spans the whole sync.
- **Audit**: `audit_events` (RLS) on every inbound/outbound action. **[DONE]**
- **Per-incident timeline**: `incident_events` (lifecycle) ⨝ `integration_events`
  (sync) → unified timeline. **[DONE]** `GET /api/incidents/{id}/timeline` merges
  both (via the mapping reverse-index + Slack `alert_id` path), RLS-scoped, with a
  deterministic tie-break (`mergeTimeline`, unit-tested); `Incidents.tsx` renders
  sync rows accent-bordered with direction/verdict/correlation_id. Degrades to
  lifecycle-only on the file backend.
- **Metrics** `/metrics`: stdlib atomic counters (no label cardinality — the
  per-tenant/provider/direction breakdown stays queryable in the ledger):
  `netops_integration_webhook_received_total`, `..._webhook_rejected_total`,
  `..._inbound_applied_total`, `..._inbound_dropped_total`,
  `..._drift_inbound_total`, `..._drift_outbound_total`. **[DONE]**

---

## 10. Key failure scenarios + handling

| # | Scenario | Handling | Status |
|---|---|---|---|
| 1 | Duplicate webhook (retry) | Level-1 dedup: unique `provider_evt_id` → no-op insert | **[DONE]** proven |
| 2 | Out-of-order (resolve before ack) | Watermark drops stale → no flap | **[DONE]** proven live |
| 3 | Webhook dropped / never delivered | Drift reconciler polls, synthesizes the missed event through the inbound pipeline | **[DONE]** `10c2a06`, verified live |
| 4 | NMS resolves, ITSM push fails | Outbound job retries (backoff) → DLQ. Reconciler catches ITSM→NMS drift; NMS→ITSM re-push (case b) re-pushes a Resolve on NMS-terminal drift (`47b6fe6`) | **[DONE]** |
| 5 | Concurrent NMS + ITSM update | Conflict ladder: terminal→NMS, assignment→ITSM | **[DONE]** |
| 6 | Clock skew across systems | Ordering keys on `external_seq` (monotonic), not wall-clock | **[DONE]** |
| 7 | Provider API down | Outbound queue backs off; inbound unaffected (NMS is SoR, never blocks) | **[DONE]** |
| 8 | Tenant misconfig (bad webhook secret) | Signature verify fails → 401, audited, zero state change | **[DONE]** proven |
| 9 | Two providers on one incident | Hub-and-spoke (one incident) + provider precedence tie-break | **[DONE]** |
| 10 | **Worker crash mid-apply** | Inbound apply runs on the **PG worker queue** (`jobTypeIntegrationInbound`): the webhook only verifies+records+enqueues (returns 200 fast); a worker crash lapses the lease, another worker re-claims, and the re-run is **idempotent** (watermark drops an already-applied event; an interrupted apply re-applies a same-state transition = no-op). | **[DONE]** `5acda2b`, verified live |

---

## Hardening backlog (to reach the maturity bar)

1. ~~**Queue the inbound apply**~~ — **[DONE]** `5acda2b`: `integration_inbound`
   job, crash-safe via lease re-claim + idempotent re-run; webhook returns 200 fast.
   (Subsumes the "atomic apply" concern — the queue's re-claim + watermark
   idempotency make a single-tx unnecessary.)
2. ~~**Drift reconciler**~~ — **[DONE]** `10c2a06` (inbound direction). Remaining:
   outbound re-push (NMS-terminal → push Resolve to ITSM, §7 case b).
4. **Outbound on every lifecycle change** (not just create/clear) for full NMS→ITSM.
5. ~~**Observability**~~ — **[DONE]**: `correlation_id` column threaded end-to-end
   (migration 0008), merged `/timeline` (lifecycle ⨝ sync) + UI, and `/metrics`
   integration counters. See §9.
6. **Secrets at rest** via #17.

These are the gap between the working, live-proven P2b and Datadog-grade maturity —
each is additive and rides the existing primitives.
