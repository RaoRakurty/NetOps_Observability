# SaaS Orgs, Regions & Data Residency

**Status:** Region MODEL implemented (control plane + routing seam + governance
view); real regional data planes are config-not-code (dormant).
**Related:** `docs/design/saas-identity-pbac.md`, `orgs.go`, `regions.go`,
`region_router.go`, `tenants.go`.

---

## 0. Goal

Support multi-region **in code** — a tenant can be *named into* a region (e.g. a
lab network you call "eu-central") and the platform models, routes, and displays
it as belonging there — **without** requiring real multi-region infrastructure.
Standing up a real region later is configuration, not a rewrite.

## 1. Topology

```
┌────────── CONTROL PLANE (GLOBAL, single) ──────────┐
│ orgs · identity · RBAC/bindings · tenants · billing│   the platform process
└───────────────┬────────────────────────────────────┘
                │
        ┌───────▼─────── ROUTING / EDGE LAYER ───────┐
        │ tenant → region mapping (effectiveTenantRegion)│
        │ region → data-plane resolution (dataPlaneFor)  │   region_router.go
        └───────┬─────────────────────────┬─────────────┘
                │                          │
        ┌───────▼────────┐        ┌────────▼───────┐
        │ DATA PLANE     │        │ DATA PLANE     │   per-region telemetry
        │ us-east (local)│        │ eu-central     │   ClickHouse · OpenSearch
        └────────────────┘        └────────────────┘   Kafka · VictoriaMetrics
```

- **Control plane** is global and single: orgs, identity, RBAC bindings, the
  tenant registry. (Built — `orgs.go`, PBAC.)
- **Routing/edge layer** maps a tenant → its region → a data plane. (Built —
  `region_router.go`: `effectiveTenantRegion`, `dataPlaneFor`, `tenantDataPlane`.)
- **Data planes** are per-region telemetry stacks. (MODELLED — every region
  resolves to the local stack until a region is explicitly configured.)

## 2. The region model (what's built)

| Layer | Entity | Where |
|-------|--------|-------|
| Region catalog | `us-east · us-west · eu-central · eu-west · ap-southeast` | `regions.go` |
| Org home region | `Org.HomeRegion` (validated) | `orgs.go` |
| **Tenant region** | `Tenant.Region` — explicit, else inherits org's home region | `tenants.go` |
| Effective region | `effectiveTenantRegion(t)` = tenant.Region ‖ org.HomeRegion ‖ default | `region_router.go` |
| Data-plane resolution | `dataPlaneFor(region)` → local stack, or a configured override | `region_router.go` |
| Tenant routing | `tenantDataPlane(tenant)` = tenant → region → data plane | `region_router.go` |
| Governance view | Administration → **Regions** (control-plane → routing → data-plane map, per-region tenant/org counts) | `RegionsAdmin` |
| Selector | Top-bar Org\|Region\|Tenant shows each scope's region | `ScopeSelector` |

Region is a **mapping/attribute, not a containment scope** (it never appears in a
scope id), so a tenant can be re-homed across regions without orphaning any role
binding (the PBAC stable-never-remap invariant holds).

## 3. Lighting up a real region (config, not code)

Each region's data plane is resolved from an env var; unset → the local stack:

```
REGION_DATAPLANE_EU_CENTRAL="ch=https://ch.eu;os=https://os.eu;vm=https://vm.eu;kafka=eu-broker:9092"
```

Steps to make `eu-central` real:
1. Deploy a data-plane stack (ClickHouse · OpenSearch · Redpanda · VictoriaMetrics)
   in an EU cloud region.
2. Set `REGION_DATAPLANE_EU_CENTRAL` to its endpoints.
3. Tenants assigned `eu-central` now resolve to that data plane.

No code change. The wiring of telemetry **reads/writes** through `tenantDataPlane`
into the actual query paths is the remaining integration (today the model
resolves the endpoint; the read paths still target the single local stack).

## 4. Data residency & compliance

- **Residency is a legal guarantee, not a label.** Assigning a tenant `eu-central`
  is necessary but not sufficient — the *bytes* must physically be in the EU,
  which requires a real EU data plane (step 3). Until then, a tenant's region is
  declared *intent* and the governance view shows it routing to the local stack.
- The model makes the residency posture **auditable**: the Regions view shows,
  per region, which tenants/orgs live there and whether the data plane is local or
  dedicated.
- Operator visibility (`OperatorRestricted`) + break-glass (PBAC §7.1) compose
  with regions: an EU tenant can be operator-restricted *and* region-pinned.

## 5. Capacity & sizing (per region)

The control plane stays single and small; **each region duplicates the data
plane**. Indicative footprint (from the capacity analysis):

| Scope | RAM | Storage |
|-------|-----|---------|
| Control plane (shared) | ~30–50 GB (HA pair) | few GB |
| Data plane — starter | ~16 GB | few TB |
| Data plane — at scale (100K devices) | 250–400 GB | 20–50 TB |

So **final footprint ≈ (per-region data plane × region count) + one shared control
plane.** A lab "named" region adds **zero** infrastructure — it rides the local
data plane. Real regions cost a data-plane replica each, in that geography.

The levers that bound per-region cost (before scaling): VM cardinality caps +
`tenant_id` label, rollups/downsampling in all three stores, hot→cold retention
tiering, Redpanda replication. (Tracked separately.)

## 6. Status & remaining work

**Built:** orgs, tenant region (+ inherit), the routing seam (`region_router.go`),
the Regions governance view, region in the scope selector, region-aware tenant
create/edit. Tests: `region_router_test.go`.

**Deferred (config/integration, not model):**
- Wire `tenantDataPlane` into the telemetry read/write paths (so a configured
  region's queries actually hit its data plane).
- Real regional data-plane deployments (per real customer/compliance need).
- SSO global-vs-per-region (open decision) and the starting region set.
