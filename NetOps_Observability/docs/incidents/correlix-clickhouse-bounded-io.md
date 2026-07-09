# Correlix ClickHouse bounded-IO incident — RCA & permanent rules

**Date:** 2026-07-09 · **Surface:** Command Center intermittently 502
(`clickhouse:8123 context deadline exceeded`), whole UI degraded, watchdog
flapping. · **Tracker:** #100 · **Status:** fixed, hardened, guarded.

## Summary

One tenant's sustained probe storm (a lab target down for ~a day) inflated the
correlation history table ~30x and pushed two latent defects past ClickHouse's
4 GiB container memory cliff. ClickHouse's OvercommitTracker killed *neighbor*
queries (101 MEMORY_LIMIT kills/hour), so every user of the platform saw 502s.
This was a **bug class, not a resourcing problem**: a hot read path whose cost
is unbounded in table size, and a write path whose row count is unbounded in
incident *duration*, violate the reliability rule that all IO must be bounded.

## Trigger chain (why now and never before)

1. **New code** — the app-experience lane (#98/#99) turned probe failures into
   semantic correlation signals; before it, a dead probe target produced almost
   no correlation-table growth. The ticketing sweeper (#78) and the canary
   added polled read load.
2. **Broken source** — lab target `.120` stayed dead ~a day → a *persisting*
   storm-lived incident, not an open/close blip.
3. **Write churn (defect 2)** — the engine persisted a full snapshot + archive
   slice every 30 s for a materially-unchanged incident, because rotating
   signal instance ids churned `content_hash`. `corr_objects`: ~3k → 236k
   version rows in ~a day.
4. **Read cliff (defect 1)** — list queries carried the ~5.7 KB `hypotheses`
   blob through full-table sorts (`SELECT *` through a `LIMIT 1 BY` fold) and
   GROUP BY'd all of `corr_edges` to decorate 100-row pages. Linear cost, hard
   threshold: ~2.6 GiB/query at storm size; two concurrent polls crossed the
   4 GiB cgroup limit → OvercommitTracker kills → platform-wide 502s. No
   gradual warning — a cliff, not a slope.
5. **Contributing noise** — `docker-hygiene.sh` had silently lost its exec bit
   (cron `Permission denied` since Jul 5); the debris drove a disk warning the
   same afternoon and muddied diagnosis. Noise, not cause.

## Fixes (all live)

| Fix | Commit | Measured |
|---|---|---|
| Narrow-key fold, keyed wide fetch (list/detail/health/backfill) | `c47b86c` + `126598c` | 6.8 s / 2.6 GiB → 0.5 s / <100 MiB; CH 275% → ~10% CPU |
| `archived_for` bloom skip index + numeric compares | `c47b86c` | archive probes 3.4 s → 38 ms |
| 2 GiB per-query `max_memory_usage` (blast-radius containment) | `126598c` | a runaway query fails **alone** |
| `material_hash` damping + heartbeat (write side) | `c4f0315` | ~23 → ~1.8 version rows/min (−92%) on live storm |
| `corr_current` hot projection + hot-path switch | this pass | list reads O(active objects), blobs unreachable from hot picks |
| Query attribution (`log_comment=api:<path>`) + budget checker + alerts + soak harness | this pass | regressions surface as CI failures / alerts, not outages |
| Reliability rollups/trends/chronic-offenders → `corr_current` (blob-free) | this pass | the budget checker itself caught these being memory-killed live: `JSONExtractString(hypotheses)` through `corr_objects_latest` re-widened the view's fold. Guardrail extended: the view now *counts as* a fold in `TestNoWideColumnsThroughFolds` |

### Current-state vs history (design separation)

- **`corr_current`** — HOT projection: ONE narrow row per object
  (ReplacingMergeTree keyed on `created_at`, partitioned by tenant only, strict
  row policy). No `hypotheses`/`layer_coverage`/`app_impact` columns *by
  schema*, so no hot list pick can ever drag a blob through a scan. The triage
  badges (`owner`, `plane_count`, `debug_excluded`, `low_authority`) are
  **narrow projection columns derived by the engine at persist time** — the
  first list-shape draft JSONExtract'd them from the blob keyed by the picked
  page, which still read ~1.3 GiB of `hypotheses` granules per poll (measured
  130 MiB/query, over the 100 MiB endpoint budget); the projection columns cut
  the list read to ~10 MiB. The only history touch left on the list path is
  the keyed `app_impact` fetch (~84 B avg column). Maintained by **app-level
  dual-write** from the engine's persist path — **not** a materialized view
  (row policies break MV inserts; frozen invariant) — so it inherits the write
  damping. Backfilled idempotently at api boot (narrow fold picks keys, badge
  extracts run keyed in the outer read only).
- **`corr_objects`** — append-only history: replay, audit, Inspector timeline,
  and the keyed wide fetch for a picked page. `corr_objects_latest` (view)
  remains for bounded background readers.
- ReplacingMergeTree note: its dedup is **asynchronous** — reads use `FINAL`
  (cheap on a current-state-sized table) and correctness never depends on merge
  timing. Keying on `created_at` (latest write wins) also self-heals the
  engine-restart version reset that a version-keyed fold would trip over.
  Storage-level cleanup is optional hygiene; **application-level damping stays
  the primary correctness mechanism.**

### Deployment follow-up (same day): schema-converge stall

Rolling out `corr_current` surfaced a latent defect in the boot-time schema
converge (`clickhouse_policies.go`): the `corr_signals` enum ALTERs in
`corrSchemaDDL()` were stale (missing `'controller'=11` / `observer_type
'controller'=6`, which the live tables and init.sql already had from the NMS
lane). ClickHouse refuses an enum ALTER that *drops* a value on a key column,
so the ALTER failed on **every boot**, `chExecAll` aborted at the first
failure, and everything after it — including the new `corr_current` CREATE —
never ran. Symptom: `/api/correlations` 404s + ticketing outbox dead-letters
after deploy; the only log line was a generic row-policy warning. Fixed
three ways: (a) enums re-synced to the live/init.sql superset, (b) converge
now runs **all** statements and logs each failing statement + ClickHouse's
error, (c) `TestCorrSignalEnumsConsistent` pins every signal-spine Enum8 to be
identical across corr_schema.go (CREATEs *and* ALTERs) and init.sql. Rule: a
converge ALTER must always carry the full superset enum, and adding a signal
class means updating init.sql + CREATE + ALTER together.

## Permanent engineering rules

1. **No `SELECT *` on hot ClickHouse paths** — column pruning through a
   view/CTE is optimizer behavior, not a contract (CI: `TestNoSelectStarOnCorrTables`).
2. **Hot list paths must not fetch wide blobs** — pick narrow keys, decorate
   keyed by the picked (id, version) set (CI: `TestNoWideColumnsThroughFolds`,
   `TestCorrelationsListSQLShape`).
3. **All hot reads: bounded rows, columns, time, and memory** — LIMIT, named
   columns, a time predicate, and the per-query cap underneath.
4. **Every hot query is tenant-scoped** — row policies via `tenant_scope`
   injection; corr intel uses the STRICT policy (untagged = platform-only).
5. **New signal lanes require broken-source soak testing** — see readiness
   checklist below (harness: `src/correlation/test_lane_soak.py`).
6. **Persist material changes, not clock ticks** — `material_hash` gates
   writes; heartbeat bounds staleness; terminal transitions always persist.
7. **Query memory caps are containment, not optimization** — the 2 GiB cap
   turns a regression into one failing query instead of a platform outage;
   fixing the query shape is still mandatory.
8. **Current-state reads and historical replay reads stay separated** —
   Command Center reads `corr_current`; replay/audit read `corr_objects`.

## New-lane readiness checklist (required before a lane ships)

A lane = anything that turns raw telemetry into correlation signals
(`netops.probes`, `netops.app.edge`, traps, metrics, cloud, controller, …).

- [ ] **Broken-source soak** — feed N cycles of one persistently-broken source
      through `run_broken_source_soak()` (test_lane_soak.py); assert the write
      budget: 1 persist + heartbeats, not 1 per cycle.
- [ ] **Write-amplification budget** — object/current/archive rows bounded and
      asserted; `corr_versions{outcome=}` counters move as expected.
- [ ] **Hot-query budget** — the lane's read surfaces stay within
      `ch-query-budget-check.sh` budgets (<100 MiB, p95 <1 s) with storm-sized
      fixtures.
- [ ] **Tenant blast radius** — a storm in tenant A must not degrade tenant B:
      damped writes + bounded reads + per-query cap all hold under the soak.
- [ ] **Wide-column rule** — no new blob column reachable from a hot list path
      (extend `corrWideColumns` in bounded_io_test.go when adding one).
- [ ] **Canary semantic validation** — if the lane feeds a flagship verdict,
      extend `rca-canary.sh` (or add a lane canary) so a silent lane outage
      alerts within one canary cadence.

## Operational observability

- **Metrics:** `corr_versions{outcome=persisted|damped}` (+ open objects,
  ingest counters) from the correlation `/metrics`; ClickHouse native exporter
  (`:9363` → vmscrape `clickhouse`) provides
  `ClickHouseProfileEvents_QueryMemoryLimitExceeded` / `FailedQuery`.
- **Attribution:** every API-issued CH query carries
  `log_comment=api:<endpoint>` (workers: `worker:*`) — budgets are enforced
  per endpoint by `scripts/ch-query-budget-check.sh` (cron-able, exits 1 on
  breach; MEM_BUDGET_MB / P95_BUDGET_MS / WINDOW_MIN env-tunable).
- **Alerts (`src/config/rules.yaml`, group `noc-ch-bounded-io`):**
  `CHQueryMemoryKilled` (critical — the cap fired), `CHFailedQueriesRising`,
  `CorrVersionChurnUndamped` (persists with zero damped = damper regressed).
  Existing: `noc-corr-ingest` flatlines, watchdog disk warnings.
- **Watchdog:** now also fails loudly when the docker-hygiene cron is stale
  (>8 days) or erroring — the silent-cron trap that muddied this incident.
- **Canary:** `rca-canary.sh` (cron */15) asserts bus → signals → confirmed
  RCA → delivered ticket, damping-aware.
- ~~**TODO (deferred):** per-tenant write-amplification counters; alert on
  `corr_current` projection-write failures~~ — **CLOSED by #101** (see below).

## #101 follow-up — the deferred items are now the data contract

The deferred half of this incident shipped as tracker **#101** and is codified
in `docs/design/correlation-data-contract.md` (binding):

- **Retention/TTL-to-cold:** profile-driven hot TTLs (`corr_retention.go`,
  `CORR_RETENTION_PROFILE`) + cold Parquet export (`scripts/ch-cold-export.sh`)
  + preview (`scripts/ch-retention-dry-run.sh`). No corr table grows forever.
- **Projection reliability:** `corr_current_projection_write_failures_total`
  metric + `CorrCurrentProjectionFailing` alert + Go `corr-current-reconcile`
  drift repair worker (hourly; boot backfill for missing rows).
- **Tenant write-amp visibility:** `netops.corr_tenant_write_amp` rollup +
  bounded top-K `corr_tenant_writes_window` metrics +
  `CorrTenantWriteAmpOverBudget` alert (runbook: `correlation-storm.md`).
- **Chaos fixture:** the .120 storm source is now the REGISTERED
  `lab_probe_storm_fixture_120` (`CORR_CHAOS_FIXTURES`) — badged in Command
  Center, skipped by auto-ticketing, still exercising damping continuously.
- **Fairness:** `hot_ui`/`background` ClickHouse settings profiles routed by
  attribution tag (`ch_workload.go` + `workload-profiles.xml`).
- **Release gate:** `make release-gate` (storm SLOs: write budget ≥0.9 damping,
  tenant blast radius, RCA integrity + the SQL-shape guardrails).

Runbooks: `docs/runbooks/clickhouse-query-budget.md` (this incident's 502
shape), `docs/runbooks/correlation-storm.md`,
`docs/runbooks/correlation-retention-cold-archive.md`.

## Scaling roadmap

**10x (present hardware, tens of tenants):** everything in this document —
query budgets enforced per endpoint, `corr_current` projection, write damping,
per-query caps — plus explicit retention: TTL policy for closed `corr_objects`
versions and `corr_signals_archive` growth (owner decision — calibration #67 P4
wants history; propose TTL-to-cold rather than delete).

**100x (SaaS scale):** per-tenant fairness (CH quotas/workload isolation or
per-tenant query queues so one tenant cannot consume the shared read budget),
tenant/region sharding of the corr tables, read replicas separating UI reads
from ingest, cold archive tier for replay history, and SLO tests (storm soak +
concurrent-poll latency) in CI as release gates.

## Verification commands

```bash
# Backend guardrails + schema freeze
cd src/backend && go test -run 'TestNo|TestCorr' .

# Write-amplification + lane soak
cd src/correlation && python3 -m pytest test_lane_soak.py test_resilience.py test_engine.py -q

# Live read budgets (against the running stack)
scripts/ch-query-budget-check.sh

# Live end-to-end semantic canary
scripts/rca-canary.sh
```
