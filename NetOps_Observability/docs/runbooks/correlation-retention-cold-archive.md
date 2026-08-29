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
scripts/ch-cold-export.sh          # export closed DAYS (idempotent; cron DAILY)
# suggested cron (lead the horizon by weeks):
# 17 2 * * * /opt/correlix/scripts/ch-cold-export.sh --quiet
```
Expiry is part-level (`ttl_only_drop_parts`): a part drops only when its
NEWEST row passes the horizon. **The corr_* history tables are partitioned
DAILY on the very column their TTL is keyed on**, so that lag is now at most
ONE DAY and space comes back in ~1/30th increments instead of one month-sized
cliff. It used to be up to a month (corr_objects was partitioned on
`window_start` while its TTL was keyed on `created_at`), which is why the cron
above is daily now: a monthly export would leave up to a month of days untiered
ahead of the horizon. **Run the dry-run after changing any knob** and before
enabling a shorter profile on a long-lived deployment.

### Re-partitioning an existing deployment (one time, per table)

A partition-key change is a full table REWRITE, so the API boot converge does
NOT do it implicitly on a big table. `chschema/corr_repartition.go` runs after
the converge list and, per table:

| env | default | meaning |
|---|---|---|
| `CORR_REPARTITION` | `auto` | `auto` migrates below the size gate and SKIPS above it with a loud log line; `force` ignores the gate; `off` does nothing |
| `CORR_REPARTITION_MAX_GIB` | `4` | the gate, in **uncompressed** GiB per table (the lab's `corr_objects` is 3.51 GiB on disk but 48.9 GiB uncompressed — the rewrite pays the uncompressed cost) |
| `CORR_REPARTITION_BATCH_ROWS` | `500000` | a destination day-partition bigger than this is copied in hourly sub-batches |
| `CORR_REPARTITION_CATCHUP_PASSES` | `3` | how many delta passes to try while the engine is still writing, before ABORTING without swapping |
| `CORR_REPARTITION_DROP_OLD` | `false` | drop `netops.<table>__premigration` after a verified swap; leaving it false keeps your rollback |

To run it deliberately: **stop the correlation engine** (so the source stops
growing), set `CORR_REPARTITION=force` in `.env`, `docker compose up -d api`,
and watch the `corr-repartition:` log lines. It is resumable — a crash or a
restart continues from the last completed day-partition, and the live table is
untouched until the copy is row-count verified. Afterwards, verify
`netops.<table>__premigration` and `DROP TABLE` it to reclaim the space.

Cold archives exported BEFORE the migration are one (tenant, month) per file;
after it they are one (tenant, day). `ch-cold-restore.sh` handles both — use
`--day YYYYMMDD` for the new vintage, `--month YYYYMM` for the old.

## Retrieving cold history — WITHOUT disturbing hot production

**Never restore into the live `netops.*` tables.** Restored rows are older
than the retention horizon by definition, so the hot TTL re-drops them, and
the insert + analyst queries would compete with Command Center's read
budgets. `scripts/ch-cold-restore.sh` restores into the isolated
`netops_restore` side database (schema cloned from live, TTL removed) —
query it freely, `DROP TABLE` when done. Tenant granularity is native: cold
files are one-(tenant, day)-per-file because the partitions are tenant-led
(one-(tenant, month) for archives exported before the daily re-partition).

### The four scenarios (all validated live 2026-07-09)

```bash
# 1. Single-tenant restore (customer audit/contract request):
scripts/ch-cold-restore.sh --table corr_objects --tenant acme
scripts/ch-cold-restore.sh --table corr_signals_archive --tenant acme

# 2. Single-day restore (incident-era investigation, current daily partitions):
scripts/ch-cold-restore.sh --table corr_objects --day 20260803
#    ...or a whole month (also the unit of pre-migration archives):
scripts/ch-cold-restore.sh --table corr_signals_archive --month 202606

# 3. Calibration-only (no cluster involvement at ALL — preferred):
clickhouse local -q "SELECT ... FROM file('data/clickhouse-cold/corr_signals_archive/*.parquet', Parquet) WHERE tenant_id='acme'"
# DuckDB/pandas/Spark read the same files; restore into netops_restore only
# if the calibration job needs SQL against the cluster.

# 4. Replay from cold archive (aged object, offline RCA re-run):
scripts/ch-cold-restore.sh --table corr_signals_archive --tenant <t> --month <YYYYMM>
scripts/ch-cold-restore.sh --table corr_objects          --tenant <t> --month <YYYYMM>
# then run replay tooling against netops_restore.* — slices are keyed by
# archived_for/archived_version exactly as in the hot archive.
```

Notes: UUID columns travel as strings in Parquet (CH 24.8 limitation) and are
parsed back into UUID columns on restore — verified round-trip. Restores run
as ordinary background work; hot tables, TTLs, and read budgets are untouched.

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
