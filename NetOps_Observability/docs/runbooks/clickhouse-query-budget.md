# Runbook — Command Center 502s / ClickHouse memory pressure

**Symptoms:** Command Center intermittently 502s (`clickhouse:8123 context
deadline exceeded`), UI-wide lag, watchdog flapping, `CHQueryMemoryKilled`
alert firing. This is the 2026-07-09 incident shape
(`docs/incidents/correlix-clickhouse-bounded-io.md`).

All commands run from `deployment/docker/` unless noted;
`ch() { docker compose exec -T clickhouse clickhouse-client -q "$1"; }`.

## 1. Identify the offending query (by endpoint, not query hash)

```bash
scripts/ch-query-budget-check.sh          # breaches + kills + top readers, last 60m
```
or directly:
```sql
SELECT log_comment, count(), max(memory_usage) AS mem,
       sum(read_bytes) AS rb, round(quantile(0.95)(query_duration_ms)) AS p95
  FROM system.query_log
 WHERE event_time >= now() - INTERVAL 1 HOUR AND type = 'QueryFinish'
 GROUP BY log_comment ORDER BY mem DESC LIMIT 10
```
Every API query is `api:<path>`; background jobs are `worker:<name>`. An
untagged heavy query came from ad-hoc SQL or a code path missing attribution —
that itself is a bug.

## 2. Check kills and live pressure

```sql
-- who got memory-killed (code 241), last hour
SELECT log_comment, event_time, substring(query,1,120) FROM system.query_log
 WHERE type='ExceptionWhileProcessing' AND exception_code=241
   AND event_time >= now() - INTERVAL 1 HOUR ORDER BY event_time DESC LIMIT 10;
-- what's running right now
SELECT query_id, log_comment, elapsed, formatReadableSize(memory_usage)
  FROM system.processes ORDER BY memory_usage DESC;
```
One kill = the 2 GiB per-query cap did its containment job; find WHICH query
regressed. Kills of *innocent* queries (OvercommitTracker) mean total pressure
— look for the biggest reader, not the killed one.

## 3. Did wide blobs enter a hot path?

```sql
SELECT log_comment, sum(read_bytes) FROM system.query_log
 WHERE event_time >= now() - INTERVAL 1 HOUR AND type='QueryFinish'
   AND query ILIKE '%hypotheses%' AND log_comment LIKE 'api:%'
 GROUP BY log_comment ORDER BY 2 DESC;
```
A hot endpoint reading GiBs with `hypotheses` in its SQL = the incident shape.
Rule: hot paths read `corr_current` only; wide columns are fetched keyed
(contract §3, `docs/design/correlation-data-contract.md`). The Go guardrails
(`bounded_io_test.go`) should have caught this at CI — if it got past them,
extend them with the new shape.

## 4. Identify tenant/source and projection health

```sql
-- which tenant is generating write pressure (last windows)
SELECT tenant_id, window_start, raw_seen, persisted, damped, damping_ratio,
       top_signal_kind, top_entity
  FROM netops.corr_tenant_write_amp ORDER BY window_start DESC LIMIT 20
 SETTINGS tenant_scope='__all__';
```
- Damping ratio collapsed to ~0 under load → damper regression
  (`CorrVersionChurnUndamped` should also be firing).
- Projection health: `curl -s correlation:8000/healthz | jq .engine_v2.projection_write_failures`
  (non-zero and rising = `CorrCurrentProjectionFailing`); drift count:
  the Go log line `corr-current-reconcile: drifted_rows=…` (worker runs hourly).

## 5. Immediate mitigations (in order)

1. **Nothing** if kills are contained to one endpoint (the cap is working) —
   fix the query shape instead.
2. Restart the API (`docker compose restart api`) if a poll loop is stuck
   re-issuing a bad query.
3. Silence the storm source if it is a known chaos fixture
   (`correlation-storm.md` — check `chaos_fixture` first, do NOT suppress a
   real customer incident).
4. Emergency: bump `CLICKHOUSE_MEM_LIMIT` in `.env` + `docker compose up -d
   clickhouse` — buys headroom, fixes nothing; the query shape is the bug.

## 6. Escalate when

- Kills persist after the offending endpoint is fixed/disabled.
- `system.query_log` shows an *ingest*-side failure pattern (Vector sink
  errors), not a read regression.
- Disk is also climbing — check the docker-hygiene cron FIRST (exec-bit
  incident, 2026-07-05) and OpenSearch index blocks; retention dry-run
  (`scripts/ch-retention-dry-run.sh`) tells you whether TTLs are live.

**Post-incident:** add the regressed shape to `bounded_io_test.go`, re-run
`make release-gate`, and record the RCA in `docs/incidents/`.
