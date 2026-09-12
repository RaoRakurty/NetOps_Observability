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

✅ **Inventory — the device registry and the declared sites** (`deviceVisibility`
  / `tenantVisibility` in tenancy.go, tenant_id based). This is an OWNER DECISION,
  not a telemetry rule: devices and sites are counted and listed per tenant, so a
  restricted tenant's inventory is not part of the platform operator's estate.
  - Dashboard **Devices** and **Sites** tiles (`currentMetricTiles`).
  - `GET /api/devices` — the registry rows AND the wireless controllers/APs the
    projection appends (`wirelessDeviceRows`); both carry `TenantID`.
  - The **global omnibox** (`/api/search/global`) — devices and active alerts;
    unified search (`/api/search`) already applied it.
  - `GET /api/sites`, `GET /api/sites/{slug}` (**404**, never 403) and the
    geomap's resolvable-slug set (`geoSiteSlugs`).
  - `GET /api/compliance` (findings AND gaps) and `GET /api/vulns` (findings,
    unassessed rows and the summary counts).
  - The `device_sites` **import resolver** — a write path, but `resolve()` answers
    by serial/address/hostname and the plan echoes the resolved device id, so it
    is an existence oracle; an unresolvable row is a reported per-row error.
  - The CTEM funnel's `scope` denominator (`securityRegistryDevices`).

  **Deliberately NOT restricted** (accounting, not visibility — a restricted
  tenant still pays for its devices): licence usage and ceilings, metering,
  config-backup device sets, and the `netops_devices_total` gauge.

✅ **Reports — the run, execution and ARTIFACT surfaces** (`reports.ExecScope`,
  threaded into `ExecutionStore.List/Get`, tenant_id based; tracker 304). An
  execution row carries the rendered summary of one report fire, and
  `GET /api/reports/executions/{id}/artifact` streams the stored HTML/XLSX/PDF —
  rendered under the owning tenant's own scope, so it is that tenant's complete
  data, not a summary of it.
  - `GET /api/reports/executions` and `/{id}` (**404**, never 403) and the
    `/artifact` stream. The exclusion rides in the SQL, not in a post-filter, so
    the LIMIT is applied to the visible set (a short page is itself a disclosure).
  - `GET /api/reports/runs` on BOTH backends — the execution history under
    Postgres (`runsFromExecutions`) and the scheduler's in-memory map under the
    file backend; `run.Detail` is the rendered summary in both.
  - `GET /api/exports/{id}`, which carries an export's size and a signed
    download link for the stored rows.

  **Deliberately NOT restricted on this path**: the scheduler's own
  de-duplication probe (`anchorFor`), which must see a restricted tenant's last
  fire or it re-fires its schedule for ever, and the signed-link download routes
  `/api/reports/view` + `/api/exports/view`, where the short-lived token IS the
  authorization and the recipient is the TENANT — the restriction hides a tenant
  from the platform, never from itself.

✅ **Maintenance windows** (`tenantVisibility` at the handler, tenant_id based;
  tracker 305). A declared window is when a customer's network is deliberately
  down and who is touching it — device ids, site slugs, rule names, the
  operator's description and the schedule.
  - `GET /api/alerts/maintenance-windows` (rows AND the `count` beside them) and
    `GET|PUT|DELETE /api/alerts/maintenance-windows/{id}` (**404**, never 403 —
    a window platform staff may not read is not one they may overwrite or
    delete either).
  - The count is computed at the handler over the filtered list, which is
    sufficient HERE because `maintenance.Store.List` takes no limit and returns
    whole rows — unlike the episode list, whose `total` is computed inside the
    store and therefore needed `alerts.EpisodeScope`.

  **Deliberately NOT restricted**: window SUPPRESSION itself
  (`alertNotifySuppressed`, `maintenanceCoveredIDs`, `Store.Covering`). A
  restricted tenant's planned work still pauses that tenant's notifications and
  still stamps its timeintel snapshots — this is a rule about operator reads,
  never about what the platform collects or does on a tenant's behalf.

✅ **Raw OpenSearch Dashboards console** (`/search`) — can't be per-tenant filtered
  (security plugin off), so it is **denied entirely whenever any tenant is
  operator-restricted** (`?c=search` gate). The operator uses the in-app Logs view
  (which IS filtered). NetBox is unaffected (it's inventory, not tenant telemetry).

A tenant's OWN users are never restricted from their own data on any surface, and
all checks are a no-op when no tenant is restricted (default).

## Residual notes

- **Dashboard "Devices Down", Global view only** — for a cross-tenant caller the
  tile sums `Targets - Reachable` across the protocol collectors
  (`collectors.Pool.Status()`). Those counters are two ints per COLLECTOR with no
  device or tenant dimension, so a restricted tenant's unreachable targets are
  still inside that number, and it can exceed the (filtered) Devices count —
  which itself says hidden devices exist. It cannot be filtered without giving
  the collectors a per-device reachability output (or reading the reachability
  from VictoriaMetrics with the device-label filter `proxyMetrics` already
  applies). The as_tenant half is already correct: a scoped view uses the
  per-device LastSeen proxy over a device list the restriction has emptied.

- Device→tenant attribution drives the ClickHouse/metrics exclusion, so a device
  must be tagged to the restricted tenant for its flows/findings/metrics to be
  hidden (untagged/platform devices stay visible — by design).
- For defence-in-depth beyond the API, ClickHouse row policies + the OpenSearch
  security plugin (per-tenant index roles) would enforce at the datastore layer;
  today enforcement is at the API query chokepoints.
