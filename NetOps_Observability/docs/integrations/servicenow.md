# ServiceNow Integration — Setup Guide (RCA Auto-Ticketing)

Correlix files **one ServiceNow incident per correlated root cause** — not per
alert. The pipeline (#78, live-validated): correlation object → policy
decision → outbox → worker → ServiceNow Table API create/update, deduplicated
by `correlation_id`, with the ticket link and audit trail visible on the RCA
Inspector. Contract/details: `docs/design/rca-ticketing.md`.

Everything is **per-tenant**: each tenant connects its OWN ServiceNow
instance and owns its OWN policies (strict isolation, FORCE RLS).

> **Validation status:** exercised end-to-end against a **real ServiceNow PDI**
> (developer instance, 2026-07-10/11 owner validation — priority mapping,
> display-value reference fields, and the create/update loop verified against
> genuine ServiceNow behavior) in addition to the bundled mock (§5), which
> remains the offline/e2e test path.

## 0. Prerequisites

- `FEATURE_RCA_TICKETING=true` on the stack (default in current bundles).
- A ServiceNow instance (or the bundled mock — §5) and an **integration user**
  on it:
  1. In ServiceNow: **User Administration → Users → New** → e.g.
     `correlix.integration`, set a strong password, uncheck *Web service
     access only* only if you also want UI login for debugging.
  2. Grant roles: `itil` (create/update incidents) — add `rest_api_explorer`
     for testing convenience only.
  3. Note your instance URL: `https://<instance>.service-now.com`.

## 1. Connect the tenant's ServiceNow (connection ≠ policy)

1. Log in to Correlix as the tenant admin → **Administration → ITSM /
   Integrations → ServiceNow**.
2. Enter **Base URL** (`https://<instance>.service-now.com`) and the
   integration user's **username/password** (stored encrypted, write-only).
3. **Test connection** — must succeed before anything files.
   (API equivalent: `PUT /api/itsm/servicenow`.)

No connection → nothing enqueues: the sweeper **skips unconnected tenants**
(no dead-letter buildup) and a manual create returns an honest `409`.

## 2. Create an incident policy (the control plane)

**RCA Auto-ticketing** pane → **New incident policy** (modal wizard):

1. **Scope**: the policy belongs to your tenant; exactly **one enabled policy
   per (tenant, external system)** — enabling a second one is refused (409;
   DB-enforced by a partial unique index). Disabled shadow policies are
   allowed and clearly badged (`Conflict — ticketing held` never happens
   silently: multi-enabled legacy data fails CLOSED with a loud banner).
2. **Gates**: minimum verdict (`suspected` / `confirmed`) and severity for
   auto-filing. Start with `confirmed` if you fear noise; `suspected` once
   you trust the engine (mock-validated default).
3. **Field mapping**: `category` is always `network`; assignment group and
   other reference fields are sent by **display name**
   (`sysparm_input_display_value=true` — no sys_id hunting).
4. **Priority mapping** (per-policy slots): leave a slot at `0` for the
   automatic escalation ladder — confirmed+critical → **P1** (impact 1 /
   urgency 1), confirmed → **P2** (urgency 1) — or set explicit
   impact/urgency values, which always win, including deliberate demotion.
   The escalation never demotes stricter configured defaults.
5. **Save**, then **Test** (simulator): dry-runs the policy against a real
   correlation and returns the decision AND `runtime_state`
   (`active | shadowed | held | opted_out`) naming the exact policy the live
   engine would evaluate — a dry-run on a shadowed policy says so instead of
   lying about what production would do.

## 3. Lifecycle (what happens after)

- **Auto**: the sweeper scans recent correlation objects, evaluates the
  enabled policy, enqueues creates/updates to the outbox; the worker delivers
  with exponential backoff + jitter, dead-letters on permanent failure, and
  **never double-creates** (correlation-id lookup before create).
- **Manual**: RCA Inspector → **Ticket card** → create/sync a ticket for the
  object you're looking at. On a MERGED object you get a `409` with the
  TERMINAL canonical id (merge chains followed ≤5 hops, cycle-safe) — file on
  the survivor it points to.
- **Status**: `ticket_status` appears on the correlation detail and list;
  outbox and audit are inspectable at `/api/tickets/outbox` and
  `/api/tickets/audit`.
- **Resolution**: Correlix-side resolution transitions the incident;
  full inbound state-sync (SNOW → Correlix human-phase timing) is the
  remaining #84 tail — the webhook plumbing exists
  (`/api/integrations/webhook/servicenow/<token>` + signing secret, see
  `docs/ITSM_INTEGRATION.md`), the reconciler write-contract is
  forward-compatible.

## 4. Verify end-to-end

After connecting + enabling a policy, watch one incident flow:
RCA page → pick/await a qualifying correlation → Ticket card shows
`queued → open` with the `INC…` number linking to your instance. CLI probe:
`GET /api/correlations/{id}/tickets`.

## 5. Testing without a real ServiceNow

The bundle ships a mock: start with `--profile mock-snow`
(`deployment/docker/mock-servicenow/`), point the tenant connection at it,
and run `scripts/validate-rca-ticketing-e2e.sh` — it drives a real
`suspected` object through sweeper→outbox→worker→HTTP create and asserts the
`INC0000001` link reaches `state=open`.

## 6. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Nothing ever files | No enabled policy, gates too strict, tenant not connected, or `FEATURE_RCA_TICKETING` off. The simulator names which. |
| Manual create → 409 "no connection" | Connect ServiceNow for THIS tenant first (§1). |
| Manual create → 409 with `canonical_correlation_id` | You're on a merged object — follow the id to the terminal survivor. |
| Policy enable → 409 | Another policy is already enabled for this tenant+system — disable it first (one-enabled invariant). |
| Reference fields empty/wrong in SNOW | Display-name mismatch — the name in the policy must exist verbatim in the instance (assignment group etc.). |
| Outbox rows dead-lettered | Check audit for the last HTTP error: auth (integration user/roles), instance URL, or SNOW-side ACLs on `incident`. |
| Ticket on detail but not in list views | Fixed (GetLink cross-scan) — if seen on newer builds, file it; a regression test pins this. |

## 7. Security notes

- Credentials: write-only, encrypted at rest (vault), never in logs; adapter
  errors are secret-safe and the outbound client is SSRF-guarded.
- All surfaces are tenant-scoped (CLAUDE.md §3a): policies, outbox, audit,
  links — cross-tenant access 404s, enforced by tests.
