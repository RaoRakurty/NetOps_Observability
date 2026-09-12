# Tenant/Org ID Migration Inventory — remaining slug-keyed systems

**Status:** Phase 1 shipped (opaque ids minted, slug validated/separated, resolution
boundary, TenantContext, audit). This doc inventories what still keys on the
tenant/org identifier so Phase 2+ can migrate each deliberately. Companion to
[opaque-identity-model.md](opaque-identity-model.md).

## What Phase 1 changed

- **Opaque immutable ids** for new orgs/tenants (`org_<hex>` / `t_<hex>`,
  `identity_ids.go`), never derived from name/slug/metadata. Existing seed/sentinel
  ids (`global`) unchanged.
- **Slug** = validated (lowercase, `[a-z0-9-]`, no `_`, no leading/trailing/
  consecutive hyphens, length-bounded, reserved-word-blocked), globally unique,
  immutable. Human/URL handle only.
- **Resolution boundary**: untrusted id-or-slug refs resolve to the opaque id
  server-side (`tenantStore.Resolve`/`orgStore.Resolve`, `Get` is the slug-aware
  compat alias; `withActingTenant`, `scopeAncestorOrSelf`, `canonicalOrgID`,
  `canonicalScopeID`). Authorization is always on the opaque id — never the slug.
- **TenantContext** (`tenant_context.go`) is the canonical identity for internal
  code (`tenant_id`/`org_id` + slug/name/region/status + `resolved_from`).
- **Audit** records opaque ids + slug/name snapshots (`recordIdentityAudit`).

The **canonical key carried by claims, stamped on data, and compared in authz is
the opaque id.** Legacy slug-keyed data still resolves via the compat resolver.

## RLS target (Postgres)

Today's row policies read `current_setting('app.current_tenant', true)`, which
**already carries the canonical tenant id** (what `principalTenant` returns) — NOT
the slug. So "RLS keyed on the opaque tenant id, never the slug" already holds.

- **Target**: rename the GUC `app.current_tenant → app.tenant_id` across all
  policies + `withTenant` for clarity (no semantic change). `app.tenant_slug` is
  never introduced.
- **Rule (now in force)**: no new RLS policy may key on a slug. New tables use the
  same `tenant_iso` FORCE-RLS predicate on the opaque `tenant_id` column
  (migration `0012_topology.sql` follows this).

## Remaining slug-keyed / tenant-keyed systems (Phase 2+)

| System | Where | Migration note |
|---|---|---|
| **Postgres RLS GUC name** | `db.go withTenant`, all `migrations/*.sql` `tenant_iso` policies | Rename `app.current_tenant`→`app.tenant_id` (mechanical; value already the id). |
| **Postgres `tenant_id` columns** | `users`, `saved_objects`, `api_keys`, `snmp_credentials`, `incidents`, `services*`, `integration_*`, `report_*`, `topology_*`, `audit_events` | Values are whatever the app stamps. New writes stamp the opaque id (claims-derived). No column change; no backfill (lab reset clean). |
| **ClickHouse** (flows/findings) | `chTenantScope` | Scope value = opaque id once telemetry ingest stamps it (below). |
| **OpenSearch** (logs/traps) | per-tenant index name + `osTenantFilter` | New per-tenant index named from the opaque id; filter by opaque id. |
| **VictoriaMetrics / Prometheus** | device/tenant label filter | `tenant` label = opaque id; device→tenant map (`telemetry_enrichment.go` CSV) emits the opaque id. |
| **Telemetry ingest stamping** | `telemetry_enrichment.go` (`device_tenant.csv`), Vector enrichment | Emit the device's opaque `Device.TenantID`; the device-create boundary already stamps opaque (resolve at the edge). |
| **Redis / cache keys** | any `…:<tenant>` key, rate limiters (`tenantRateLimiter`), `cred_cache_reload` | Key by opaque id. |
| **File / object / KV paths** | `tenantKV` stores (sites, device→site, contact points), saved-object blobs, report artifacts | Key/filter by opaque id; `tenantKV` already filters by the stamped value. |
| **Agent / collector registration** | future cloud collector (`docs/design/cloud-ingestion.md`), SNMP discovery device tagging | Register/stamp by opaque tenant id; never trust an agent-sent slug (resolve at ingest). |
| **API tokens / JWT claims** | `auth.go` `jwtClaims.TenantID`, `api_keys.TenantID` | Claims carry the opaque id; user/api-key create resolves a provided slug→id at the boundary. |
| **WebSocket subscriptions** | event hub topic/scope per tenant | Subscribe/authorize by opaque id (resolve the subscription request once). |
| **Report jobs / background workers** | `report_jobs_pg`, scheduler, reconcilers | Carry opaque `tenant_id` in the job row; workers never re-derive from a slug. |
| **Audit logs** | `audit_events.tenant` | Stores the opaque id + slug/name snapshot (Phase 1 done for identity actions; extend snapshot to other mutations as needed). |
| **Frontend** | URLs, scope selector, `as_tenant` | Use slug in URLs (resolves at the edge); display name; show opaque id only in a details/advanced affordance. |

## Order of attack (Phase 2)

1. **GUC rename** `app.current_tenant`→`app.tenant_id` (cosmetic, low-risk, do first).
2. **Ingest stamping** (`telemetry_enrichment.go` + collectors) → opaque id, so new
   telemetry across CH/OS/VM is opaque-keyed from the start.
3. **Per-tenant OS index / VM label naming** → opaque id for new tenants.
4. **WebSocket + report-job + cache keys** → opaque id.
5. **Frontend** slug-in-URL / name-display / id-in-details polish.

No big-bang rewrite of existing telemetry is required (the lab was reset clean and
telemetry is regenerable + TTL'd); each item above is independently shippable.
