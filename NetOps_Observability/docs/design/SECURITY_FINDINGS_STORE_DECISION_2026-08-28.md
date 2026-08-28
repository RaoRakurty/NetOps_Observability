# Security findings store — storage-architecture decision (2026-08-28)

**Status: DECIDED (Fable, owns the storage-architecture decision per Project 2
model rule). Unblocks T8 (the read API + Security UI need somewhere to read
from).**

## Decision (one line)
**The durable findings store is a per-tenant OpenSearch index
`netops-secfindings-<tenantseg>-*`, written from the `netops.security` Kafka
topic by vector-router (exactly as syslog/flows/cloudlogs are), and read through
`TenantIndexPattern` + `TenantFilter`. PostgreSQL FORCE-RLS holds only the small
MUTABLE control-plane state (feed/rule enablement, saved views, future
triage/lifecycle). ClickHouse is unchanged — flow-behavioral detections keep
grounding through the engine into `corr_*` Exposure Stories (the correlated
OUTPUT, not the raw findings list).**

## Why (grounded in the data shape + platform precedent)
The `secfindings.Finding` (internal/secfindings/finding.go) is **immutable,
time-stamped, append-heavy verdict data**:
- One subject × one evaluated rule, stamped with `Time` (verdict instant) +
  `ScanID`. **No lifecycle/state fields** (no first/last_seen, resolved,
  reopened) — recurrence yields a NEW time-stamped verdict sharing a
  deterministic identity, not a mutated row.
- Dedup is already **consumer-side** via `nativeIDOf` → stable native_id →
  stable signal_id (secbus/event.go). The store does not upsert a mutable record.

The T8 UI access patterns (from SECURITY_OBSERVABILITY_HLD §3/§5, cloud-monitoring
review) are: paginated list-by-tenant, filter by severity/seam/asset/framework,
**facet/aggregation counts** (CTEM funnel, compliance-% by framework, signal
volume), **time-range trend**, **full-text narrative search** (observed/intended/
detail/remediation), cursor pagination.

Match to precedent:
| Need | Store |
|---|---|
| Append-only, time-stamped, no in-place lifecycle | **OpenSearch** (the syslog/flows/cloudlogs model) |
| Time-range trend (exposure/compliance over time, drift) | **OpenSearch** time-partitioned `-<date>` indices |
| Facet/aggregation counts (funnel, by-framework %, severity) | **OpenSearch** aggregations |
| Full-text narrative search | **OpenSearch** (its purpose; PG full-text is weaker) |
| Consumer-side dedup, not mutable upsert | append+collapse — **OpenSearch**, not PG |
| Small MUTABLE control-plane state (rule enable, saved views) | **PG FORCE-RLS** (`withTenant`, the ~40-table precedent) |

The HLD's own steer ("per-tenant feeds state, RLS on new PG tables,
`chTenantScope` on new ClickHouse queries, isolation test shipped per feature")
and the hardening research ("storage (ClickHouse/OpenSearch, FORCE-RLS per
tenant)") both describe a **split, not a single winner**. This decision picks the
split explicitly and assigns each store its precedent-matching role.

## Why OpenSearch over ClickHouse for the findings LIST
Both are append/aggregation stores. Deciding factors: (1) findings need
**full-text narrative search** — OpenSearch's core competency, ClickHouse's
weak spot; (2) writing a Kafka topic → per-tenant index via vector-router is the
**identical, already-proven, low-code path** the other telemetry lanes use
(no new persistence service); (3) findings volume is far below flows/syslog (a
scan emits bounded findings per device, not per-packet), so OpenSearch cost is
comfortable. ClickHouse stays where it already earns its place — high-volume
flow-behavioral detection + the engine's `corr_*` — and we do **not** stand up a
competing CH findings table for the UI (avoids two sources of truth). The LLD's
existing CH `findings` INSERT grant remains the engine's internal grounding
substrate, NOT the UI read source.

## The write path (mirror the existing lanes — near-zero new code)
`provider (vuln/compliance/netrule) → secfindings.Finding → secbus.Producer →
Kafka netops.security` **[already built]** → add a vector-router route
`netops.security → netops-secfindings-<tenantseg>-*` (mirrors the syslog/flows
routes; `IndexTenantSeg` MUST match, same as the other lanes). Two consumers of
one topic (standard Kafka fan-out): (a) vector-router → OpenSearch (the raw
findings list); (b) T2b Python engine → grounds into `corr_*` Exposure Stories.
Independent, neither blocks the other.

### Doc identity — preserve BOTH trend and dedup
`_id = hash(native_id | scan_id)` → every scan's verdict is retained
(time-series → trend/drift), while **current state** is a query-time collapse
(latest-by-`Time` per `native_id`, e.g. a `top_hits` agg over a `native_id`
terms bucket). This keeps history AND a dedup'd "current exposures" view without
a mutable upsert. `TenantID` (json:`-`) is written to the index as the routing/
filter field but never serialized to the client.

## Read path + §3a isolation (REQUIRED with the feature)
- Read API scopes by `principalTenant(claims)`, default-closed:
  `TenantIndexPattern("secfindings", tenant, cross)` selects
  `netops-secfindings-<seg>-*` (+ `-untagged-*`) for a scoped tenant, `-*` for
  platform cross-tenant; `TenantFilter` adds the per-doc defense-in-depth clause
  (mirrors the applogs/flows chokepoint). Cross-tenant get-by-id → 404.
- The read gate is `requirePerm` (per-tenant operator data) — NOT a
  platform-global gate. Feed/rule enablement + saved views (the PG state) get
  their own `tenant_iso` FORCE-RLS migration + `withTenant`.
- Ship the isolation test (`org_isolation_test.go` template): own-only list,
  cross-tenant get → 404, `as_tenant` into another org ignored, on BOTH the OS
  read API and the PG control-plane state.

## What this unblocks / next build tasks (hand to Opus)
1. vector-router `netops.security → netops-secfindings-<seg>-*` route + index
   template/mapping (severity/status/framework/seam keyword fields for facets;
   observed/intended/detail/remediation text fields for full-text; `Time` +
   `ScanID` for trend). Mapping hygiene: guard dotted keys (the `del(.label)`
   OpenSearch gotcha in CLAUDE.md).
2. `secfindings` read API: list+facet+trend+search handlers, cursor pagination,
   `TenantIndexPattern`/`TenantFilter` scoping, §3a isolation test.
3. PG FORCE-RLS migration for the mutable control-plane state (feed/rule
   enablement, saved views) + `withTenant` queries + isolation test.
4. Then T8 builds the approved mockup (artifact 4b3b450f) against this read API.

See [[security-scope-decision]], docs/design/research/SECURITY_OBSERVABILITY_HLD_2026-08-25.md.
