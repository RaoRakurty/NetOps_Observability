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

## Enforcement coverage (binding on every telemetry surface)

✅ **OpenSearch telemetry API** (`operatorTelemetryRestriction`, tenant_id based):
  - `GET /api/logs/search` (logs · syslog · flows-in-OS · snmptraps) — `must_not`
    tenant exclusion in the Global view; `match_none` when scoped into a restricted
    tenant.
  - `GET/POST /api/logs/export` (sync + async worker) — restriction **frozen onto
    the export spec** at request time, so a queued export can't exfiltrate later.
  - `GET /api/logs/indices` — restricted tenants' index names filtered out
    (zero-knowledge); **fails closed** (empty) on any parse error.
  - Opsis Ai "+ context" reads through `/api/logs/search`, so it inherits it.

✅ **ClickHouse + VictoriaMetrics** (`restrictedTelemetry`, device-keyed):
  - **Flows** (`flowTenantClause`) — `src/dst NOT IN` restricted tenants' device
    addresses in the Global view; deny when scoped in.
  - **Findings** (`handleFindings`) — `device NOT IN` restricted tenants' keys.
  - **Metrics** (`proxyMetrics`) — a single AND'd negative `extra_filters[]`
    excludes restricted tenants' device id/name labels; deny → match-nothing.

✅ **Raw OpenSearch Dashboards console** (`/search`) — can't be per-tenant filtered
  (security plugin off), so it is **denied entirely whenever any tenant is
  operator-restricted** (`?c=search` gate). The operator uses the in-app Logs view
  (which IS filtered). NetBox is unaffected (it's inventory, not tenant telemetry).

A tenant's OWN users are never restricted from their own data on any surface, and
all checks are a no-op when no tenant is restricted (default).

## Residual notes

- Device→tenant attribution drives the ClickHouse/metrics exclusion, so a device
  must be tagged to the restricted tenant for its flows/findings/metrics to be
  hidden (untagged/platform devices stay visible — by design).
- For defence-in-depth beyond the API, ClickHouse row policies + the OpenSearch
  security plugin (per-tenant index roles) would enforce at the datastore layer;
  today enforcement is at the API query chokepoints.
