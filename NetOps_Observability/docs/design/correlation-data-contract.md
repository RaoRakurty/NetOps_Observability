# Correlation Data Contract — current / history / archive (#101)

**Status:** binding. Established after the 2026-07-09 bounded-IO incident
(`docs/incidents/correlix-clickhouse-bounded-io.md`, tracker #100) and the #101
hardening pass that converted its fixes into this durable contract. Every new
signal lane, endpoint, and schema change against the `netops.corr_*` tables
MUST honor it.

## 1. The three tiers (+ detail blobs)

| Table | Role | Growth bound | Reads allowed |
|---|---|---|---|
| `corr_current` | **HOT read model.** One NARROW row per live object: latest state, triage badges, `chaos_fixture`. What Command Center lists, the sweeper pre-filters, and reliability views poll. | Active objects + closed/merged rows for `CORR_RETENTION_CLOSED_DAYS` (row-level TTL) | Hot paths only ever read this. `FROM netops.corr_current [AS x] FINAL` (alias **before** FINAL). |
| `corr_objects` (+ `corr_edges`, `corr_evidence`) | **HISTORY.** Append-only material version snapshots: Inspector, replay, audit, wide `hypotheses`/`layer_coverage`/`app_impact` blobs. | Hot for `CORR_RETENTION_HISTORY_DAYS`, then part-drop (cold export leads) | Keyed by a picked `(tenant, correlation_id, version)` set ONLY. Never fold/sort a wide column. `corr_objects_latest` **counts as a fold**. |
| `corr_signals_archive` | **ARCHIVE.** Full version-scoped window slices — replay input, calibration corpus source. | Hot for `CORR_RETENTION_ARCHIVE_DAYS`, then part-drop (cold export leads) | Keyed by `archived_for` (bloom-filter index). Never wrap indexed columns in functions. |
| cold tier (`data/clickhouse-cold/*.parquet`) | **COLD.** Closed month-partitions exported by `scripts/ch-cold-export.sh` before TTL can drop them. | Object storage / disk, not ClickHouse | Offline: calibration (#67 P4), audit, replay of aged objects, model evaluation. Restore via `INSERT … SELECT FROM file(…, Parquet)`. |

Wide blobs (`hypotheses` ~5.7 KB, `layer_coverage`, `app_impact`) are
**detail-only**: they exist in history, are fetched keyed for a picked page,
and are banned from `corr_current` by schema and by test
(`TestCorrCurrentIsNarrowAndReplacing`, `TestNoWideColumnsThroughFolds`).

## 2. Write-side contract

- **`material_hash` gates persistence** (`ObjectSnapshot.material_hash()`):
  evidence kinds per entity, entity set, edge structure, confidence bucket —
  and NEVER rotating instance ids/weights/decay. A persisting incident whose
  window merely refreshes does not version.
- **Heartbeat** (`CORR_VERSION_HEARTBEAT_S`, default 900 s) bounds staleness:
  an unchanged incident re-persists at most once per heartbeat, proving
  liveness without per-cycle churn. `0` = damping off (legacy, tests only).
  Since P3 change A (`CORR_HEARTBEAT_TOUCH_ONLY`, default on) that re-persist is
  a **touch, not a version**: an incident whose `material_hash` did not move
  writes ONE `corr_current` row — fresh `created_at`, fresh
  `window_start`/`window_end`/`signal_count`/`top_confidence`, **version number
  unchanged** — and nothing else. No `corr_objects` version, no
  `corr_edges`/`corr_evidence` rows, no `corr_signals_archive` slice, no
  Evidence item. Counted `corr_versions{outcome="heartbeat_touch"}` and folded
  into the SUPPRESSED side of `damping_ratio` (it wrote a projection row, so it
  is not `damped`, which has always meant "wrote nothing").
- **Keepalive** (`CORR_VERSION_KEEPALIVE_S`, default 21 600 s = 6 h): an open
  object that never moves materially is still forced to persist a **real
  version** once per keepalive, because history has consumers that read
  `corr_objects.created_at` rather than the version series —
  `corr_objects`/`corr_edges`/`corr_evidence` TTL on their own `created_at`
  (`corr_retention.go`), the Command Center list's `app_impact` decorate joins
  history under a 24 h `created_at` window (`correlations.go`), and the drift
  reconciler scans 7 days back. The keepalive MUST stay below the shortest of
  those horizons (today the 24 h decorate window is binding). A never-moving
  open object therefore costs 4 versions/day, not 96.
- **`corr_current` is NOT 1:1 with `corr_objects`** (it was, pre-P3). Exactly
  what holds now:
  - `corr_current` may be **newer by `created_at`** than the newest
    `corr_objects` row for the same object — by at most one keepalive.
  - The **version number is shared**: a touch reuses the current version, never
    mints one. So every `(correlation_id, version)` join taken FROM
    `corr_current` INTO `corr_objects`/`corr_edges`/`corr_evidence` — list
    decorate, `health_score.go` grounding/edge counts, Inspector — still
    resolves to real history rows. A projection version with no history row
    would render `edge_count=0` / `grounding='none'` on a live incident; that is
    why the number must not move.
  - **Freshness readers take `corr_current`** and see the touch: Command Center
    list/sort, the sweeper pre-filter, the orphan-close sweep, the drift
    reconciler (`CorrDriftSelect`, `created_at`-based), closed-row TTL.
  - **Material-content readers take history** and correctly see the last
    MATERIAL version: Inspector, audit, calibration. Replay is unaffected —
    `replay._select_slice` and the Go timeline resolve the newest archive slice
    with `archived_version <= requested`, and a touch mints no version to
    resolve.
  - Therefore: `corr_objects` version count is bounded by **material changes +
    lifecycle + keepalive**, NOT by heartbeats.
- **Lifecycle always persists**: open v1, merge, close are never damped and
  never touched.
- **Dual-write**: `_persist_snapshot` writes history (truth) then the
  `corr_current` projection. Projection failure never blocks truth, but is
  counted (`corr_current_projection_write_failures_total`), structured-logged
  (tenant_id/corr_id/version_id/material_hash/retryable/error), alerted
  (`CorrCurrentProjectionFailing`), and repaired (Go
  `corr-current-reconcile` worker: missing + drifted rows re-seeded from
  history hourly; boot backfill covers cold starts). A heartbeat touch
  (`_touch_current`) writes the projection half ALONE and counts its failures on
  the same counter — a lost touch is a stale Command Center row, healed by the
  next write and force-repaired by the same reconciler.
- **Per-tenant write accounting**: every raw/persisted/damped outcome rolls up
  per tenant and flushes to `corr_tenant_write_amp` each `CORR_WA_FLUSH_S`
  (300 s). Metrics carry only the top-K noisiest tenants
  (`corr_tenant_writes_window`, K=`CORR_WA_TOPK`) — **never one series per
  tenant**.

## 3. Read-side contract (ClickHouse discipline)

1. No `SELECT *` on corr tables (enforced: `TestNoSelectStarOnCorrTables`).
2. Hot list/detail paths read `corr_current`; history reads are keyed by a
   picked id/version set; folds are narrow (`TestCorrelationsListSQLShape`).
3. Every query is attributed: `log_comment=api:<path>` or `worker:<name>`.
4. Budgets are enforced operationally: `scripts/ch-query-budget-check.sh`
   (<100 MiB, p95 <1 s, zero memory kills) + the `noc-ch-bounded-io` alerts.
5. Workload profiles (`ch_workload.go` → `workload-profiles.xml`): hot UI
   reads run under `hot_ui` (1 GiB / 10 s — fail small, fail alone),
   workers under `background` (2 GiB / 60 s, de-prioritized), analytics under
   the default (spill at 1.5 GiB, hard 2 GiB cap). Kill-switch:
   `CH_WORKLOAD_PROFILES=off`.

## 4. Retention contract

Profiles (`CORR_RETENTION_PROFILE`, applied by boot converge —
`corr_retention.go`; per-knob overrides `CORR_RETENTION_{HISTORY,ARCHIVE,CLOSED}_DAYS`,
`0` = keep forever, explicit):

| Profile | history | archive | corr_current closed |
|---|---|---|---|
| `lab` | 90 d | 45 d | 60 d |
| `demo` | 30 d | 14 d | 30 d |
| `production` (default) | 180 d | 90 d | 90 d |
| `extended` (enterprise) | 730 d | 365 d | 365 d |

Mechanics: metadata-only `MODIFY TTL` (`materialize_ttl_after_modify=0`) +
`ttl_only_drop_parts=1` — whole month-partitions drop; effective retention lags
the horizon by up to one partition month; a 7-day floor makes a typo'd knob
slow, never destructive. **Cold export must lead the TTL horizon** (cron
`scripts/ch-cold-export.sh`; verify with `scripts/ch-retention-dry-run.sh`).
The calibration path (#67 P4) reads in-horizon archive hot and aged history
from the cold Parquet tier — retention never deletes untiered closed months if
the export cron is honored (dry-run shows coverage).

`corr_signals` (hot spine) keeps its own 30-day TTL, unchanged. Every other
`corr_*` table now has an explicit bound or an explicit keep-forever override —
**no table grows forever by accident.**

## 5. Tenant fairness contract

- No tenant can exhaust the shared hot read path: per-query caps + workload
  profiles today; per-tenant ClickHouse quotas/pools at 100x (below).
- No tenant's storm can hide: write-amp rollup rows + top-K metrics + the
  `CorrTenantWriteAmpOverBudget` alert answer "who is storming" in one query.
- Storm blast radius is release-gated: a lane cannot ship if one tenant's
  storm changes another tenant's writes or RCA (`test_storm_release_gate.py`).

## 6. New-lane contract (release gate)

Every NEW signal lane MUST, before shipping (`make release-gate`):

1. Pass the broken-source soak with its own signals (`test_lane_soak.py`
   harness): damping ratio ≥ 0.9 over a 20-cycle storm (heartbeat touches count
   on the suppressed side), and `corr_objects` versions bounded by MATERIAL
   changes + lifecycle + keepalive — an unchanged heartbeat must mint no
   version.
2. Pass tenant blast-radius + RCA-integrity SLOs (`test_storm_release_gate.py`).
3. Keep the Command Center list blob-free (Go bounded-IO SQL-shape tests).
4. On a live stack: stay inside per-endpoint read budgets
   (`ch-query-budget-check.sh`) during its soak.
5. Update the enum trio in lockstep if it adds a signal class
   (`TestCorrSignalEnumsConsistent`).

## 7. Chaos fixtures

An intentional storm source (e.g. lab target 10.70.245.120 kept dead) is
REGISTERED, not ambient: `CORR_CHAOS_FIXTURES=name=match,…` tags matching
objects' `corr_current.chaos_fixture`. Command Center badges them ("planned
drill"), auto-ticketing skips them, `/healthz` lists them — while the storm
still exercises damping, write-amp accounting, and bounded IO end to end.

## 8. Roadmap

**10x (done in #100/#101):** narrow hot projection; material damping +
heartbeat; retention/TTL-to-cold; projection-failure alert + reconciler;
tenant write-amp top-K; workload profiles; query budgets + release-gate storm
tests; chaos fixtures.

**100x / SaaS (designed-for, not yet built — nothing in the current schema
blocks these):**
- Per-tenant CH quotas (`CREATE QUOTA … KEYED BY` the `tenant_scope` custom
  setting) or per-workload connection pools.
- Read replicas for hot UI (`corr_current` is tiny + ReplacingMergeTree —
  trivially replicable); separate shards/clusters for large tenants
  (every corr table is already tenant-led in PARTITION BY and ORDER BY).
- Cold tier on object storage (Parquet layout already matches).
- Replay/calibration jobs isolated from hot ClickHouse (read the cold tier).
- HA/replication (ReplicatedMergeTree swap), backup validation, DR runbook.
- Customer-visible retention policy controls (profile knobs are already
  per-env; per-tenant TTL WHERE clauses are the extension point).
- Noisy-neighbor SLO enforcement: write-amp budget → automated per-tenant
  ingest throttling (today: alert + runbook).
