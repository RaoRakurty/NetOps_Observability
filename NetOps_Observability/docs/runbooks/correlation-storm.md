# Runbook — Correlation storm (write amplification / noisy source)

**Symptoms:** `CorrTenantWriteAmpOverBudget` or `CorrVersionChurnUndamped`
firing; `corr_objects`/`corr_signals_archive` growing fast; one incident
re-versioning continuously; Command Center dominated by one source.

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
Under a storm, `damped` must climb much faster than `persisted`
(steady-state: ~1 persist/object/15 min heartbeat + material changes; the
release-gate SLO is ratio ≥ 0.9). Ratio ≈ 0 under sustained load = damper
regression: check `CORR_VERSION_HEARTBEAT_S` (0 disables damping!) and recent
changes to `ObjectSnapshot.material_hash()`.

## 4. Blast radius + read side

- Other tenants' Command Center must stay fast: `scripts/ch-query-budget-check.sh`.
- Growth check: `SELECT table, sum(rows) FROM system.parts WHERE database='netops'
  AND table LIKE 'corr%' AND active GROUP BY table` — compare over an hour.
  Retention keeps this bounded long-term (`scripts/ch-retention-dry-run.sh`).

## 5. Stopping a real storm

1. Fix the source (device/probe/exporter) — the storm ends at quiesce
   (`CORR_QUIESCE_S`, default 15 min after signals stop).
2. Source will stay broken a while (lab outage, vendor ticket)? Either accept
   the damped storm (it is bounded: heartbeat-paced versions + TTL'd tables),
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
