# RCA-Driven Auto-Ticketing (Correlix → ServiceNow) — IN PROGRESS

**Status: P1–P5 SHIPPED (P5 = live-validated; external ServiceNow create needs a
real/mock SNOW target to exercise the last leg).** Queued 2026-06-16.

- **P1 (`a1ca360`, 2026-06-27):** data model (migration `0016`, 4 net-new tenant
  tables + FORCE RLS), `buildTicketPayload` (reuses `buildRcaPathView`), pure
  `evalTicketDecision` policy engine, in-mem/pg `ticketingStore` seam, tests +
  cross-tenant isolation.
- **P2 (2026-06-27):** `serviceNowAdapter` (Table API, SSRF-guarded, secret-safe
  errors, RCA `correlation_id` dedupe + `u_correlix_*` fields), httptest mock
  ServiceNow, outbox `ticketWorker` (SKIP-LOCKED claim, exp-backoff+jitter,
  dead-letter, never-double-create via correlation-id lookup, audit + link
  advance). `make test-ticketing-unit` / `test-servicenow-mock`.
- **P3 backend (2026-06-27):** request-free `chRowsScope`/`loadCorrSlice`
  (`552c7a2`) so background jobs build payloads off-request; conn resolver
  (`itsmConfigStore.ticketSystemConfig` — each tenant's OWN ServiceNow);
  `ticketSweeper` (`efb7a88`) = the policy→enqueue path (scan recent corr objects
  across tenants → `buildRcaPathView`→facts→payload → `evalTicketDecision` →
  enqueue create/update; pure `decideSweepAction`, tenant-scoped `resolvePolicy`
  w/ default-on fallback + explicit-disable opt-out); worker + sweeper started in
  `main()` under `FEATURE_RCA_TICKETING`. REST APIs: incident-policy CRUD +
  `/{id}/test` simulator, `/api/correlations/{id}/{tickets,ticket,ticket/sync}`,
  `/api/tickets/{outbox,audit}`, and `ticket_status` on `GET
  /api/correlations/{id}`. Tenant-isolation tests (store + HTTP: token-stamped
  owner, own-only list, cross-tenant 404, no outbox leak).
- **P4 UI (2026-06-27, `b7bf4f3`):** RCA Inspector **Ticket card**
  (`RcaTicketCard`, a self-contained slot on the correlation detail) — live
  state (No ticket / Creation queued / Open / Updated / Resolved / Failed),
  number→deep-link, last-synced + verdict, action audit trail, and
  perm-gated (infrastructure:write) Create/Sync that enqueue + re-poll;
  read-only callers see status only. Admin **RCA Auto-Ticketing** page
  (`IncidentPoliciesAdmin`, under Incident Response) — per-tenant incident-policy
  CRUD + a pure decision **Simulator** (`/{id}/test`). ServiceNow connection
  reuses the existing Integrations connector. Label maps keep engine enums out of
  the UI; 3 new component tests.
- **P5 live E2E (2026-06-28, `73b29ee`+`270f625`):** deployed to the running
  stack with `FEATURE_RCA_TICKETING=true`; migration 0016 applied; sweeper+worker
  started; incident-policy CRUD + simulator + outbox/audit + `ticket_status`
  validated on REAL data; manual create → 202 → outbox row → worker claim → conn
  resolver correctly **held** ("no ticketing connection configured") with no link
  / no double-anything. **Found + fixed a latent P2 bug** (the outbox claim SQL's
  ambiguous `id` in `RETURNING`, invisible to the in-mem tests) and added a
  `DATABASE_URL_TEST`-gated Postgres regression test that fails on the bug and
  passes on the fix. **Remaining:** the external ServiceNow Table-API create leg
  needs a real or mock SNOW instance configured for a tenant to exercise.

## Goal & core principle

When Correlix detects a ticket-worthy incident, open/update **one** external ticket
from the **RCA correlation object** — never one ticket per raw alert. The ticket
carries the RCA diagnosis: verdict, confidence, evidence used, missing evidence,
affected scope, owner recommendation, recommended action, and a link back to
Correlix.

**Bad:** 4 tickets (interface down · BGP down · probe loss · path degraded).
**Good:** 1 ServiceNow incident tied to one RCA object — *"Suspected local link
fault on e2e-edge1 Gi0/1"* with all evidence as work-note context.

Primary rule: **tickets are wired to `corr_object_id`, not raw alert IDs.**

## Architecture

```
Redpanda → correlation service → corr_objects/signals/edges/evidence
        → incident policy engine → ticket outbox → ServiceNow adapter → ServiceNow
```

- Correlation creates the RCA object. Incident policy decides ticket-worthiness.
  Adapter creates/updates. Ticket lifecycle follows the correlation object.
- **Ticketing must never block correlation.** Use an **outbox + retry** pattern.
- Builds on the existing ITSM control plane (see `netops-integration-platform-build`,
  `netops-security-policy-system`) — reuse async outbox/reconciler + cred encryption
  (`netops-secret-custody`) rather than greenfield.

## Data model (Postgres, tenant-scoped + FORCE RLS)

- **incident_policies** — when to create/update (external_system, min_verdict,
  min_severity, require_customer_facing, allow_probe_only, allow_internal_monitoring,
  require_persistence_seconds, suppress_flapping_seconds, assignment_group,
  default_impact/urgency, filters jsonb).
- **correlix_ticket_links** — RCA object ↔ external ticket (corr_object_id,
  external_system/instance_url/ticket_number/sys_id, dedupe_key, status, last_verdict,
  last_confidence, last_payload_hash, last_synced_at). Unique
  (tenant_id, corr_object_id, external_system).
- **ticket_outbox** — reliable async actions (create|update|add_work_note|resolve|
  reopen, idempotency_key unique, payload, status pending|sent|failed|retrying|
  dead_letter, retry_count/max_retries/next_retry_at/last_error). Index
  (status, next_retry_at).
- **integration_configs** — ServiceNow connection (instance_url, auth_type basic|oauth,
  encrypted creds, default assignment_group/category, custom_field_mapping jsonb,
  rate_limit_per_minute). Secrets encrypted; masked in API responses; never logged.
- **ticket_audit_log** — every action (actor system|user, old/new status, payload_hash,
  result, error). Compliance trail.

## Incident policy (MVP)

Create when **customer-facing** AND (verdict=confirmed) OR (verdict=suspected AND
severity=critical) OR (critical health contributor persists > threshold) OR
(affected service/site/path is business-critical).

Never create when: internal/debug-only · active-check-only low-authority ·
undetermined · cleared within suppression window · duplicate open ticket exists ·
no meaningful affected entity. Raw critical alerts with no RCA object → no immediate
ticket unless a **fallback "health contributor" policy** is explicitly enabled.

## Payload — `BuildTicketPayload(corr_object_id, policy_id) -> TicketPayload`

Gathers corr_object + signals + evidence used + missing evidence + affected
device/interface/path/site/service + verdict/confidence/signature + recommended
action + RCA URL + owner. **Reuse `buildRcaPathView` (already shipped) as the
evidence/affected/missing/owner source** — it already produces this. Title:
`Suspected|Confirmed <fault type> on <entity/path>`. ServiceNow fields incl.
custom `u_correlix_*` (object_id/verdict/confidence/signature/owner/affected_*/rca_url),
configurable field mapping. Work-note templates for opened / verdict-change /
new-evidence / recovery / no-longer-correlated.

## Idempotency / dedupe

dedupe_key = tenant_id+corr_object_id+external_system. Idempotency keys:
`servicenow:create:<t>:<obj>` · `:update:<t>:<obj>:<hash>` · `:note:<t>:<obj>:<event_hash>`.
Never a 2nd active ticket per corr_object unless policy allows splits. On
create-success-but-link-store-fail → `LookupByCorrelationID` before re-creating.
Set ServiceNow correlation_id/correlation_display.

## ServiceNow adapter — `services/integrations/servicenow`

`ValidateConfig · CreateIncident · UpdateIncident · AddWorkNote · ResolveIncident ·
LookupByCorrelationID · HealthCheck`. HTTP w/ timeouts; retry only idempotent ops;
respect rate limits; capture error bodies with secrets redacted; structured logs
(tenant_id, corr_object_id, action, ticket_number). **Validate outbound URL belongs
to the configured instance** (SSRF guard). Stdlib `net/http` — no new dep.

## Outbox worker

Poll pending/retrying with `SKIP LOCKED` (reuse the report-scheduler pattern,
`netops-reporting-async-pipeline`); concurrency cap; exp backoff; dead_letter after
max retries; write ticket_audit_log; update link on success.

## APIs

Integrations: GET/POST/PUT `/api/integrations/servicenow` + `/test`. Policies:
GET/POST/PUT/DELETE `/api/incident-policies` + `/{id}/test`. Tickets:
GET `/api/correlations/{id}/tickets`, POST `.../ticket`, POST `.../ticket/sync`,
GET `/api/tickets/outbox`, GET `/api/tickets/audit`. Add `ticket_status` to
`GET /api/correlations/{id}`.

## RBAC

`integrations.read/write · tickets.read/create/sync · incident_policies.read/write`.

## UI

RCA Inspector "Ticket" card (status Not created|Open|Updated|Failed|Resolved,
number→link, last-synced, Create/Sync buttons gated by perm, history). Overview /
Recommended Action: "ServiceNow incident INC… is open for this RCA object" /
"Ticket creation pending" / blocked-reason ("active-check-only / internal monitoring
/ not customer-facing / below policy threshold"). Admin: ServiceNow setup + Incident
Policy editor. NO raw-alert ticketing language anywhere.

## Implementation order

P1 data model + BuildTicketPayload + policy eval · P2 mock ServiceNow + adapter +
outbox worker + retry/dedupe · P3 APIs + ticket_status on correlation detail · P4 UI
· P5 E2E on golden object `936cc7fe-…` (short desc "Suspected local link fault on
e2e-edge1 Gi0/1", payload incl. all evidence, outbox create, mock INC + sys_id,
link stored, ticket_status in API, UI card).

Make targets: `test-ticketing-unit · -integration · -e2e · test-servicenow-mock`.

## Non-goals (MVP)

No bidirectional sync · no auto-close by default · ServiceNow first (Jira/PD later,
same outbox/policy model) · no raw-alert tickets · no Redpanda→ServiceNow direct ·
never bypass the correlation object · internal/debug checks never create
customer-facing tickets.

## Acceptance

One incident per RCA object · ticket has RCA summary+evidence+missing+scope+action+
link · RCA updates add work notes to the same ticket · no duplicates · internal/debug
excluded · failures retry without blocking correlation · UI shows ticket status ·
tests prove the full flow.
