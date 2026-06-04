# #20 — Multi-tenant telemetry isolation

Status: **Phase 1 (ingest tagging) + Phase 2 (DB-enforced ClickHouse reads)
IMPLEMENTED + deployed.** Storage carries a `tenant_id` discriminator (Phase 1);
ClickHouse row policies on flows/findings/tunnels now enforce it at the DB —
the API injects a `tenant_scope` custom setting on every telemetry read
(`proxyClickHouse`/`chTenantScope`), so another tenant's TAGGED rows are refused
even if a query filter is forgotten. Untagged rows stay app-layer device-gated
during the tagging transition.

⚠️ **Phase 2 gotcha (learned the hard way):** a materialized view that reads a
policy table re-evaluates the row policy on every INSERT, in the inserting
connection's context where `getSetting('tenant_scope')` is unset → the INSERT
ERRORS and ingestion stops. We dropped the unused `flows_hourly` MV. Any future
rollup over a policy table must be policy-exempt or tenant-aware. Row policies
gate SELECT only; the API self-heals the policies on start (`ensureCHRowPolicies`).

**Phase 3 (open):** at-rest separation (CH `PARTITION BY tenant_id`, per-tenant
OpenSearch indices/DLS — the latter needs the OS security plugin, off in the
scaffold). Owner: `docs/TRACKER.md` #20.

Companion to #15 (`postgres-rls.md`): that doc isolates **app-state** (Postgres
RLS); this one isolates **telemetry** (flows/logs/metrics/findings across
ClickHouse, OpenSearch, VictoriaMetrics).

---

## The one-way-door decision: how does telemetry acquire a tenant?

Two models were on the table (flagged in the tracker as a SaaS one-way door):

- **(A) Customer-run collector/agent** — each tenant runs an agent that
  authenticates and tags its own data with its tenant id at the edge. Clean
  identity, but requires shipping/operating per-tenant agents and a tenant-auth
  ingest gateway. Premature for the current single-operator deployments.
- **(B) Operator-run receivers + device→tenant attribution** — the operator runs
  the stack; every device already belongs to a tenant via the device inventory
  (`models.Device.TenantID`). Telemetry is attributed to a tenant by matching its
  **source device identity** (hostname / sampler/exporter address) against the
  inventory.

**Decision: (B).** It matches how the read path already works (every read-time
scoper in `tenancy.go` maps principal → visible devices → identity matchers), it
needs zero new edge components, and it degrades gracefully (untagged data =
global tenant `""`, exactly today's behaviour). (A) remains a future option for
true customer-managed ingest; (B) does not foreclose it (an agent could write the
same `tenant_id` field this design introduces).

### Tenant identity, per signal (the matcher already proven on the read path)

| Signal   | Storage          | Identity field(s) at ingest        | Inventory field matched |
|----------|------------------|------------------------------------|-------------------------|
| syslog   | OpenSearch       | `hostname`                         | `Device.Name`           |
| flows    | ClickHouse + OS  | `sampler_address`, `src/dst_addr`  | `Device.Address`        |
| applogs  | OpenSearch       | (stack-internal services)          | → global tenant `""`    |
| metrics  | VictoriaMetrics  | `device` / `hostname` / `source`   | id / name (read-time)   |
| findings | ClickHouse       | `device` (id or name)              | id / name               |

Metrics keep their existing **read-time** `extra_filters[]` label enforcement
(`metrics_query.go`) — single-node VictoriaMetrics has no native tenancy
(`vmtenant` is a vmcluster feature), so the label-injection scoper *is* the VM
tenant story. No ingest change for metrics in Phase 1.

---

## Why tag at ingest at all (reads already isolate correctly)

Today isolation is enforced **only** at the application read path: each query
maps the caller → visible devices → identity matchers (`flowTenantClause`,
`handleLogsSearch`, `visibleDevice*`). That is correct, but it is the *only* line
of defense — a single forgotten filter on a new query path is a cross-customer
breach. Stamping `tenant_id` at ingest is the prerequisite for **defense in
depth**: ClickHouse row policies and OpenSearch DLS can then refuse to return
another tenant's rows even if an app-layer filter is ever missed — the same
"developer cannot leak by omission" property #15 gives app-state.

Phase 1 deliberately **does not** change read behaviour. It makes the data carry
`tenant_id` so Phase 2 can flip enforcement onto it safely, after the column is
populated and verified in the live stack.

---

## The device→tenant enrichment substrate (Phase 1)

The aggregator has no inventory access; the inventory lives in the Go API's
discovery. So the API **exports** the mapping and Vector **consumes** it:

```
 Go API (discovery, source of truth for Device.TenantID)
   │  every TENANT_ENRICHMENT_INTERVAL, atomically writes
   ▼
 data/enrichment/device_tenant.csv      (identity,tenant_id  — one row per name & per address)
   │  mounted read-only
   ├─────────────► vector-aggregator   enrichment_tables.device_tenant (file/csv)
   │                                    remap: .tenant_id = lookup(hostname|sampler_address) ?? ""
   └─────────────► correlation         reads same CSV, stamps tenant_id on findings
```

- **Export** (`telemetry_enrichment.go`): a background loop writes the CSV
  atomically (temp + rename) to `TENANT_ENRICHMENT_DIR`. One row per distinct
  device **name** and per distinct **address**, each → its `tenant_id` (lowercased
  inventory value; `""` for global/untagged). Empty identities skipped.
- **Aggregator** loads it as a `file` enrichment table and, in each normalize
  transform, sets `.tenant_id` by looking the event's identity up in the table,
  defaulting to `""`. The value rides through Redpanda → router → storage
  unchanged (`skip_unknown_fields` already passes it to ClickHouse; OpenSearch
  maps it dynamically + via the updated templates).
- **Correlation** loads the same CSV at startup + refresh and stamps
  `tenant_id` on each finding before the ClickHouse insert.

**Staleness:** Vector loads enrichment tables at config load, so a newly-added
device is tagged only after the next aggregator reload/deploy. This is acceptable
in Phase 1 because **reads do not depend on the tag** — they still use the live
read-time scoper. Phase 2 adds reload-on-change (Vector `--watch-config` / API
SIGHUP) before reads switch onto `tenant_id`. Untagged rows = `tenant_id=""`
(global), which is fail-safe under the strict model (a scoped tenant never
matches `""`).

---

## Storage schema changes (Phase 1, additive)

- **ClickHouse** (`clickhouse/init.sql` for fresh installs + `ALTER TABLE …
  ADD COLUMN IF NOT EXISTS` applied online to the running instance):
  `tenant_id String DEFAULT ''` on `flows`, `findings`, `tunnels`. ORDER BY is
  left unchanged in Phase 1 (re-keying needs a table rebuild); row policies key on
  the column directly. Phase 2 may add `tenant_id` to the sort key for fresh
  installs.
- **OpenSearch** (`opensearch/index-templates.json`, re-applied): `tenant_id`
  `keyword` on the applogs/syslog/flows templates. New daily indices pick it up;
  existing indices map it dynamically.

---

## Phased plan

1. **Phase 1 — ingest tenant-tagging (this change).** Export substrate +
   aggregator stamping + correlation stamping + storage `tenant_id`. Additive;
   reads unchanged. Verifiable: `SELECT DISTINCT tenant_id FROM netops.flows`.
2. **Phase 2 — database-enforced reads.** ClickHouse row policies + per-tenant
   role/`SETTINGS`, OpenSearch DLS / per-tenant index routing; switch the Go read
   paths to filter on `tenant_id` (keeping device-match as the populate-time
   fallback via `tenant_id IN (scope) OR (tenant_id='' AND <device match>)`).
   Add enrichment reload-on-change.
3. **Phase 3 — at-rest separation.** ClickHouse `PARTITION BY (tenant_id, …)` on
   fresh installs; OpenSearch per-tenant index naming for large tenants; ties into
   #16 (per-tenant encryption) and #20-VM (vmcluster) if/when adopted.

---

## Non-goals (Phase 1)

- No change to read behaviour or to the metrics read-time scoper.
- No per-tenant ClickHouse users / OpenSearch DLS yet (Phase 2).
- No customer-run agent / tenant-auth ingest gateway (model A, future).
- No re-keying of ClickHouse sort orders on existing tables.
