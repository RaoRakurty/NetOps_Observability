# Org / Tenant Model — as-built reference

**Status:** implemented · **Last updated:** 2026-06-20

The single source of truth for how Correlix isolates customers. This is the
**as-built** model (what the code does today), consolidating what was spread
across [saas-identity-pbac.md](saas-identity-pbac.md),
[provider-org-tenant-ia.md](provider-org-tenant-ia.md),
[saas-orgs-regions-compliance.md](saas-orgs-regions-compliance.md),
[postgres-rls.md](postgres-rls.md) and
[multitenant-telemetry-isolation.md](multitenant-telemetry-isolation.md).
Isolation rules are mandatory — see **CLAUDE.md §3a**.

---

## 1. The hierarchy

A **strict single-parent tree**. Containment is the only thing authorization
traverses (ancestor-or-self, depth ≤ 4). Cross-cutting access (MSP / shared /
break-glass) is never re-parenting — it is a *binding* that points across the
tree (§4).

```
platform                          ← the operator (us). Root of the tree.
  └─ org:<slug>                   ← Organization = one customer ACCOUNT
       │                            (orgs.go: HomeRegion, SSOConnection)
       └─ tenant:<slug>           ← Tenant = the ISOLATION BOUNDARY
            │                       (tenants.go: OrgID, Region, IsolationMode,
            │                        OperatorRestricted)
            └─ resource:<kind>:<id>   ← lazy, per-resource ACLs (future; Phase D+)
```

- **Org** (`orgs.go`) — a customer account. Carries data-residency `HomeRegion`
  and an optional `SSOConnection` (one identity source inherited by all its
  tenants — the enterprise pattern). An org owns one or more tenants.
- **Tenant** (`tenants.go`) — **the isolation boundary**: every piece of
  customer data is tagged with exactly one `TenantID`. A tenant belongs to
  exactly one org (`OrgID`; blank ⇒ the Global org, for pre-org tenants).
  Per-tenant knobs: `Region` (inherits org `HomeRegion` if blank),
  `IsolationMode` (shared | dedicated_schema | dedicated_db | dedicated_cluster),
  `OperatorRestricted` (hide this tenant's telemetry from the platform operator).
- **`global` tenant** (`TenantGlobal = "global"`) — platform-owned / untagged
  data. Visible **only** to the platform owner (cross-tenant), never to a
  scoped tenant. A device or record with no `TenantID` is platform-owned.

Scope ids are canonical `type:slug` strings (`platform`, `org:acme`,
`tenant:acme-prod`) — human-readable in audits/incidents/logs (`scopes.go`). The
tree is **derived** from the org + tenant stores, never a separate persisted
table, so it always matches reality.

---

## 2. Principals (who is asking)

| Principal | How it's recognized | Reach |
|---|---|---|
| **Platform owner** | `isPlatformOwner`: super-admin role **and** tenant `""`/`global` | Everything — `cross = true`, unrestricted (subject to `OperatorRestricted`) |
| **Org admin** | role `org-admin` bound at an `org:` scope | All tenants **within that org** (`isOrgManagerRole`) |
| **Tenant admin** | super-admin **scoped to a tenant** (non-global) | That one tenant |
| **Operator / Read-only / Auditor / API-client** | tenant-scoped role | Their one tenant (perms differ; auditor = read incl. audit, change nothing) |

Roles (`rbac.go`): `super-admin`, `org-admin`, `operator`, `read-only`,
`auditor`, `api-client`. Role **definitions** are platform-wide — a tenant admin
can *read* them (to assign) but only the platform owner can *change* them.

---

## 3. Identity resolution — `principalTenant(claims) → (tenant, cross)`

The one function every data path agrees on (`tenancy.go`):

- **Platform owner**, no override → `(global, cross=true)` = sees all tenants +
  platform-owned data. With a `?as_tenant=X` override → `(X, false)` (narrows).
- **Non-owner** → `(lower(claims.Tenant), false)`. **`as_tenant` is NEVER trusted
  here for a non-owner** — that is a hard invariant. A legitimate multi-tenant
  switch is applied earlier by `withActingTenant`, which rewrites the effective
  tenant **only after** a `reachesTenant` binding check (§4).

So a scoped caller is *structurally* confined to its own tenant; the only way to
act in another tenant is to hold a binding that reaches it.

---

## 4. Authorization & reach

**`Authorize(Principal, Action, Resource)` (`authz.go`)** — the leaf rule:

- `cross` (platform owner) → allow.
- `ResInfraStack` (platform plumbing) → tenant principal **denied** (platform
  only).
- `ResRole` → view allowed, mutate platform-only.
- `ResTenant` → view your own; create/change platform-only.
- **default** (devices, saved objects, users, api keys, SNMP creds, alerts,
  **sites**, **device→site bindings**, …) → **exact tenant match**. Global/
  untagged is platform-owned.

**`reachesTenant(principal, tenant)` (`access.go`)** — the PBAC reach check for
the multi-tenant/MSP/SRE switch. Walks the principal's active role **bindings**;
a binding grants reach when its `scope_id` is **ancestor-or-self** of the target
tenant (`scopeAncestorOrSelf` walks parents). An **org-scope** binding confers
reach only for an **org-manager** role (org-admin / super-admin); a tenant-scope
binding always does. **Deny-wins.** Org reach is *derived* from tenant reach
(org = its tenants) — never a separate cross-org grant.

---

## 5. How isolation is enforced at the data plane (default-closed)

Tenant tagging is not organic — it is a build-time requirement (CLAUDE.md §3a).
Every store enforces it in the store itself:

| Store | Mechanism |
|---|---|
| PostgreSQL | `tenant_iso` **FORCE-RLS** policy + query via `withTenant` |
| ClickHouse (flows/findings) | `chTenantScope` injected into every query |
| OpenSearch (logs/traps) | per-tenant index + `osTenantFilter` |
| VictoriaMetrics (metrics) | device/tenant label filter |
| File / KV / in-memory | **`tenantKV`** — default-closed, **no unscoped "list all"** (sites, device→site bindings, contact points, …) |

**Universal rules (CLAUDE.md §3a):**
1. **Scope by the principal, default-closed** — filter every list/get/search by
   `principalTenant`.
2. **Stamp the owner from the token / server-side state, never the request body.**
3. **Cross-tenant resource-by-id → 404** (never reveal another tenant's id);
   cross-tenant write/delete refused.
4. **Pick the right gate** — per-tenant data → `requirePerm` + tenant filter;
   platform-global plumbing → `requirePlatformAdmin` / `requireCrossTenant`.
5. **Ship a cross-org isolation test with every feature** (`org_isolation_test.go`
   template).

**Structural backstop:** `route_isolation_test.go` (`TestEveryRouteClassified`)
fails the build if any `/api/*` route is unclassified. Categories: `scoped`
(per-tenant data, needs an isolation test), `adminScoped`, `platform`,
`globalRef`, `infra`, `selfScoped`, `token`, `public`.

---

## 6. Special semantics

- **`OperatorRestricted` tenant** — even the platform owner cannot view this
  tenant's telemetry (logs/syslog/flows/traps excluded from the Global view,
  denied if the operator scopes in). The tenant's own users are unaffected.
- **Observed vs intended** — the **observed** plane (SNMP-discovered inventory →
  Infrastructure → Devices) is always authoritative for live state; the
  **intended** plane (internal sites + device→site bindings = the Source of
  Truth) is always editable in-app. NetBox is an automation connector only,
  never the authority. See [sot-provider-model.md](sot-provider-model.md).

---

## 7. The SoT/geo features under this model (2026-06-20)

The recent Source-of-Truth work follows the rules above end-to-end:

- **Internal sites store** (`sites.go`) — `tenantKV[Site]`, stamped from the
  token, cross-tenant id → 404. (`org_isolation_test.go`.)
- **Device→site bindings** (`device_sites.go`) — `tenantKV[DeviceSiteBinding]`,
  owning tenant stamped from the **device**, `canSeeDevice` gate → 404.
  (`TestDeviceSiteIsolation`.)
- **External SoT import** (`sot_import.go`, `POST /api/sot/import`) — tenant-
  scoped (`infrastructure:write`), records stamped from the principal/device;
  device matching runs **only against the caller's visible inventory** so a
  foreign device can't match (structurally no cross-tenant write); the target
  site must be visible to the caller. (`TestSoTImportIsolation`.)

All three are classified `scoped` in the route-coverage guard and ship with a
cross-org isolation test.

---

## 8. Honest scope of "done"

Cross-tenant isolation is enforced by construction (default-closed stores +
per-feature tests) and guarded structurally (route-coverage guard) so a *new*
unscoped endpoint cannot ship. This guarantees every route is classified and
every `scoped` route carries an isolation test; it is **not** a substitute for
the periodic full security sweep (last full SR-/SC- audit: 2026-06-07). New
features must continue to ship with their own isolation test.
