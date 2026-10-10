# Runbook — Correlation storm (write amplification / noisy source)

**Symptoms:** `CorrTenantWriteAmpOverBudget`, `CorrVersionChurnUndamped` or
`CorrHeartbeatTouchNotEngaging` firing; `corr_objects`/`corr_signals_archive`
growing fast; one incident re-versioning continuously; Command Center dominated
by one source.

## 1. Who is storming?

```sql
-- deployment/docker: docker compose exec -T clickhouse clickhouse-client -q "…"
SELECT tenant_id, window_start, raw_seen, persisted, damped, damping_ratio,
       top_signal_kind, top_entity, open_objects, max_incident_age_s
  FROM netops.corr_tenant_write_amp
 ORDER BY window_start DESC, persisted DESC LIMIT 30
 SETTINGS tenant_scope='__all__';
```
`top_entity` + `top_signal_kind` name the source. Cross-check the live top-K:
`curl -s correlation:8000/healthz | jq .engine_v2.tenant_write_amp_topk`.
`persisted` counts `corr_objects` versions only; the `damped` column (and
`damping_ratio`) is the SUPPRESSED total — skipped re-persists **plus**
heartbeat touches (§3). The `CorrTenantWriteAmpOverBudget` budget (100 per
5-min window) is derived from that split in `src/config/rules.yaml`.

## 2. Real incident, or a chaos fixture?

```bash
curl -s correlation:8000/healthz | jq .engine_v2.chaos_fixtures
```
- The storming entity matches a listed fixture (e.g.
  `lab_probe_storm_fixture_120`) → **intentional**. Command Center shows the
  object as "planned drill"; auto-ticketing already skips it. No action —
  that storm exists to exercise damping and bounded IO continuously.
- Not listed → treat as REAL. Never register a fixture just to silence an
  alert during triage: fixtures are for sources you deliberately keep broken,
  registered in config review, not mid-incident.

## 3. Is damping healthy?

```bash
curl -s correlation:8000/metrics | grep corr_versions
```
Three DISJOINT outcomes since P3 change A:
- `persisted` — a `corr_objects` version was written: first version, material
  change (evidence growth / verdict change), terminal transition (close/merge),
  or the `CORR_VERSION_KEEPALIVE_S` (6 h) floor for a never-moving open object.
- `damped` — the re-persist was skipped entirely (`material_hash` unchanged,
  inside the heartbeat). Wrote nothing.
- `heartbeat_touch` — the 900 s heartbeat fell due on an object whose
  `material_hash` had not moved: ONE `corr_current` freshness row, **version
  number unchanged**, no `corr_objects` version, no edges/evidence/archive.

`damped + heartbeat_touch` is the SUPPRESSED side — what the engine's
`damping_ratio` and the rollup table's `damped` column both count, and what the
release-gate SLO (ratio ≥ 0.9) is measured against. Under a storm the suppressed
side must climb much faster than `persisted`. Steady state for an open object
that is not moving materially is now **one version per 6 h keepalive** plus its
material changes (pre-P3: one per 15 min heartbeat — 24× more).

- Ratio ≈ 0 under sustained load = damper regression: check
  `CORR_VERSION_HEARTBEAT_S` (0 disables damping!) and recent changes to
  `ObjectSnapshot.material_hash()`. Alert: `CorrVersionChurnUndamped`.
- `heartbeat_touch` flat at 0 while `damped` climbs = the touch path is off or
  unreachable (`CORR_HEARTBEAT_TOUCH_ONLY`); `corr_objects` growth and the
  `persist.decision` cost are back at the pre-P3 rate. Alert:
  `CorrHeartbeatTouchNotEngaging`. Not a correctness bug — `corr_current` is
  still fresh and history is still written — but the §1 write budget was
  re-derived assuming touches, so expect `CorrTenantWriteAmpOverBudget` next.

## 4. Blast radius + read side

- Other tenants' Command Center must stay fast: `scripts/ch-query-budget-check.sh`.
- Growth check: `SELECT table, sum(rows) FROM system.parts WHERE database='netops'
  AND table LIKE 'corr%' AND active GROUP BY table` — compare over an hour.
  Retention keeps this bounded long-term (`scripts/ch-retention-dry-run.sh`).

## 5. Stopping a real storm

1. Fix the source (device/probe/exporter) — the storm ends at quiesce
   (`CORR_QUIESCE_S`, default 15 min after signals stop).
2. Source will stay broken a while (lab outage, vendor ticket)? Either accept
   the damped storm (it is bounded: an unchanged heartbeat mints NO version, so
   `corr_objects` grows only with material changes, terminal transitions and the
   6 h keepalive — 4 versions/day for a stuck-open object; `corr_current` is one
   replacing row per object; every table is TTL'd),
   or — if it is *deliberately* kept broken — register it as a fixture:
   set `CORR_CHAOS_FIXTURES=<name>=<entity-substring>` on the correlation
   service (site override / `.env`), restart it, verify the badge appears and
   `/healthz` lists it.
3. Never suppress by tenant: suppression is per named SOURCE (fixture), so a
   real incident on the same tenant still tickets.

## 6. Escalate when

- Damping ratio is healthy but disk/CPU still climbing → read-path or
  retention problem (`clickhouse-query-budget.md`,
  `correlation-retention-cold-archive.md`).
- The storm is multi-tenant/platform-wide → suspect an ingest-tier defect
  (Vector/Kafka duplication), not a broken source.

## 7. Projection drift — Command Center says open, history says closed

`corr_current` (what Command Center, the health strip, Iris and the ticketing
sweeper read) is a projection of `corr_objects` history. The api's
`corr-current-reconcile` worker repairs it every `CORR_CURRENT_RECONCILE_INTERVAL`
(default 1 h) in three independent steps, each logged and counted:

| Kind (`netops_corr_current_drift_rows{kind}`) | Meaning | Repair |
|---|---|---|
| `orphaned` | open, no persist for `CORR_ORPHAN_OPEN_CLOSE_HOURS` (engine lost it at restart) | closing version written to history (`reconciler/orphan-close`) |
| `drifted` | projection older than the newest history row, inside the 7-day lookback (lost projection write) | re-projected from history |
| `state_drifted` | projection `open`, newest history row terminal, **any age** (tracker 328) | re-projected from history, restamped `now()` |

Alerts: `CorrCurrentProjectionFailing` (the engine is losing projection writes),
`CorrCurrentStateDriftPersisting` (the repair is not clearing state drift),
`CorrCurrentReconcileFailing` (the reconciler's own steps error).

Verify by hand (read-only, `SET tenant_scope='__all__'` first):

```sql
SELECT count() FROM (
  SELECT tenant_id, correlation_id, state FROM netops.corr_objects
   WHERE (tenant_id, correlation_id) IN
         (SELECT tenant_id, correlation_id FROM netops.corr_current FINAL WHERE state = 'open')
   ORDER BY tenant_id, correlation_id, created_at DESC
   LIMIT 1 BY tenant_id, correlation_id)
WHERE state != 'open';
```

Non-zero after a pass, with `state_repaired=` in the api log, means the repair
ran but the fold did not take — check ClickHouse merges on `corr_current`. No
`corr-current-reconcile` lines at all means the worker is not running.
