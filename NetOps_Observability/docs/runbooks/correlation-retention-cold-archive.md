# Runbook — Correlation retention & cold archive (#101)

**Contract:** `docs/design/correlation-data-contract.md` §4. Hot ClickHouse
keeps a bounded window of correlation history; closed month-partitions are
exported to Parquet BEFORE the TTL horizon can drop them.

## What is hot, what moves cold

| Data | Hot (ClickHouse) | Cold (`data/clickhouse-cold/`) |
|---|---|---|
| `corr_current` (live incident list) | active + closed for `CLOSED_DAYS` | never (rebuilt from history) |
| `corr_objects`/`edges`/`evidence` | `HISTORY_DAYS` (default 180) | Parquet per month-partition |
| `corr_signals_archive` | `ARCHIVE_DAYS` (default 90) | Parquet per month-partition |
| `corr_tenant_write_amp` | fixed 30 d | no (operational telemetry) |
| `corr_signals` hot spine | fixed 30 d (pre-existing) | no (archive holds the slices) |

Profiles: `CORR_RETENTION_PROFILE` = `lab` (90/45/60) · `demo` (30/14/30) ·
`production` (180/90/90, default) · `extended` (730/365/365). Overrides:
`CORR_RETENTION_{HISTORY,ARCHIVE,CLOSED}_DAYS` (`0` = keep forever). Applied
by the API boot converge — change `.env`, `docker compose up -d api`, done.

## Operating it

```bash
scripts/ch-retention-dry-run.sh    # what WOULD drop, when, and export coverage
scripts/ch-cold-export.sh          # export closed months (idempotent; cron monthly)
# suggested cron (lead the horizon by weeks):
# 17 2 3 * * /opt/correlix/scripts/ch-cold-export.sh --quiet
```
Expiry is part-level (`ttl_only_drop_parts`): a month-partition drops only
when its NEWEST row passes the horizon, so retention lags by up to a month —
that lag is your export safety margin. **Run the dry-run after changing any
knob** and before enabling a shorter profile on a long-lived deployment.

## Retrieving cold history

```bash
# inspect without touching the stack
clickhouse local -q "SELECT count() FROM file('data/clickhouse-cold/corr_signals_archive/*.parquet', Parquet)"
# restore a month into hot CH (replay/audit of an aged object)
docker compose exec -T clickhouse clickhouse-client -q \
  "INSERT INTO netops.corr_signals_archive SELECT * FROM file('/cold/corr_signals_archive/<partition>.parquet', Parquet)"
# (mount data/clickhouse-cold into the container as /cold first, read-only)
```
Parquet is engine-neutral: DuckDB/pandas/Spark read it directly for
calibration (#67 P4) and model evaluation — no live ClickHouse needed.

## Calibration contract (#67 P4)

Calibration reads (a) in-horizon archive slices hot, (b) aged months from the
cold tier. The calibration corpus stays a *curated export* (confirmed objects'
windows), not an accidental infinite archive — the cold tier is its durable
source, so shortening hot retention never costs calibration data **as long as
the export cron leads the TTL** (dry-run shows coverage gaps).

## Enterprise extended retention

Per contract: set `CORR_RETENTION_PROFILE=extended`, or pin explicit day
counts / `0` (forever) per knob, per deployment. Document the chosen values in
the customer's deployment record; the dry-run output is the auditable
statement of what is retained where.

## Failure modes

- **Export cron dead** → dry-run shows partitions past horizon with no
  Parquet file. Fix cron BEFORE the horizon passes; TTL lag (≤1 month) is the
  grace window. (Watchdog lesson from the docker-hygiene exec-bit incident:
  verify the cron actually runs, `--quiet` still exits non-zero on failure.)
- **TTL not applied** → dry-run "NO TTL configured": the API converge failed —
  check api logs for `converge failure`.
- **Disk pressure NOW** → do not hand-DELETE; lower `ARCHIVE_DAYS`
  (floor 7), restart api, let part drops do it; export first if the months
  aren't tiered yet.
