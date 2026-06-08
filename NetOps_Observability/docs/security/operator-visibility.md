# Per-Tenant Operator Visibility (Data-Privacy / Compliance)

A customer can require that the **platform operator** (the cross-tenant
super-admin) **not be able to view their data**. This is the
`Tenant.OperatorRestricted` control.

- Toggle in **Administration → Tenants → Operator access** (or
  `PATCH /api/tenants/{id} {"operator_restricted": true}`; platform-owner only).
- Default is **false** (operator-visible) — existing behavior is unchanged until a
  tenant is explicitly restricted. The **global tenant can never be restricted**.
- A restricted tenant's **own users are unaffected** — they always see their own
  data. Only the platform operator is blocked.

## Semantics

| Viewer | Restricted tenant's data |
|--------|--------------------------|
| Platform operator, **Global** (cross-tenant) view | **excluded** from results |
| Platform operator, **scoped into** the restricted tenant | **denied** (empty) |
| The restricted tenant's **own** users | **fully visible** (their data) |
| Untagged / platform-owned data | unaffected (operator still sees it) |

Enforced server-side via `operatorTelemetryRestriction()` (tenancy.go) — only ever
applies to the platform operator, and is a no-op when no tenant is restricted.

## Enforcement coverage (what is binding today)

✅ **OpenSearch telemetry API** — the primary log/telemetry read path:
  - `GET /api/logs/search` (logs · syslog · **flows** · snmptraps) — `must_not`
    tenant exclusion in the Global view; `match_none` when scoped into a restricted
    tenant.
  - `GET/POST /api/logs/export` (sync + async worker) — restriction **frozen onto
    the export spec** at request time, so a queued export can't exfiltrate later.
  - `GET /api/logs/indices` — restricted tenants' index names are filtered out
    (zero-knowledge); **fails closed** (empty) on any parse error.
  - The Opsis Ai "+ context" button reads through `/api/logs/search`, so it inherits
    the restriction.

## Known gaps (NOT yet binding — follow-ups for full zero-knowledge)

These surfaces still scope by tenant but do **not** yet honor
`OperatorRestricted`; an operator could see a restricted tenant's data through
them. Document/▢ before promising a customer full zero-knowledge:

1. **ClickHouse flows** (`flows.go` / `flowTenantClause`) — the dedicated Flows UI
   reads netflow from ClickHouse, scoped by device address, not by the restriction.
   Fix: exclude restricted tenants' device addresses (chokepoint exists).
2. **ClickHouse findings** (correlation anomalies) — same shape as flows.
3. **Metrics** (VictoriaMetrics) — per-device series; restricted tenant's metrics
   are still visible. Lower PII sensitivity but in scope for strict compliance.
4. **Raw OpenSearch Dashboards console** (`/search`, platform-owner only) — a raw
   query tool that bypasses the API filter entirely. True enforcement here needs
   per-tenant index restrictions at the OpenSearch security layer (the security
   plugin is disabled in the scaffold) or removing operator OSD access.

The right long-term home for (1)–(3) is a single tenant-exclusion clause applied
at each store's query chokepoint, mirroring `operatorTelemetryRestriction()`.
