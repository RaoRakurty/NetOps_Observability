# Storage & Volume Operations — ClickHouse + Docker at Scale

Runbook + design guide for keeping the stack's storage bounded, from a single
lab host to a large production deployment. Written after the 2026-07-03 #96
baseline, where **93% of ClickHouse's disk was its own introspection logging**
(5.84 GiB of `system.*` vs 453 MiB of telemetry) on a host at 82% disk — on top
of two prior disk-driven ingest outages (2026-06-10 unsampled flows, 2026-06-12
Docker build cache). Storage problems creep silently and surface as *other*
components' bugs: OpenSearch flips every index read-only at its 95% flood
stage and ingestion stops with no error.

Related: `deployment/docker/clickhouse/system-logs.xml` (#96a),
`scripts/docker-hygiene.sh` (#96b), `scripts/stack-watchdog.sh` (disk warn 85% /
auto builder-prune 90% / ingest-liveness probe), TRACKER §G.

---

## 1. ClickHouse — production optimization practices

### 1.1 Bound the server's self-logging (do this on every deployment, first)

Default CH writes unbounded `system.*` logs (`text_log`, `trace_log`,
`processors_profile_log`, `part_log`, `metric_log`, `query_log`, …). They have
**no TTL by default** and on a quiet system will out-grow the data.

- Ship `config.d/system-logs.xml` (this repo does): `remove` the
  investigation-only logs, keep `query_log` (7d TTL) and `metric_log` (3d TTL).
- `asynchronous_metric_log` duplicates what the native Prometheus endpoint
  (`:9363`, already scraped into VictoriaMetrics) exports — disable it.
- The config `<ttl>` applies at table **creation**; on an existing server,
  `DROP TABLE` the old logs once after restart (auto-recreated). CH renames
  schema-changed log tables to `*_0` — drop those too.
- Data files delete ~8 min after DROP (`database_atomic_delay_before_drop_table_sec`,
  default 480) — don't panic when `du` doesn't move instantly.

### 1.2 Schema design that keeps disk (and merges) bounded

- **Partition to match your TTL.** `PARTITION BY toYYYYMMDD(ts)` with a 7-day
  TTL means expiry = whole-part drops (instant, no I/O). Set
  `ttl_only_drop_parts = 1` on high-volume tables (flows) so TTL never rewrites
  parts row-by-row. Never partition finer than ~an order of magnitude below
  retention (7d retention + daily partitions = 7 partitions — right; hourly =
  168 — wrong, too many parts).
- **TTL every raw table.** Retention is config, not cleanup. This repo: flows
  7d, findings/tunnels/telemetry 30d; corr objects/archive intentionally
  unbounded (replay contract) — that's a *decision recorded in init.sql*, which
  is the point: every table states its retention or why it has none.
- **Codecs.** `LowCardinality(String)` for enum-ish columns (vendor, severity,
  proto, tenant_id) — typically 5–10× on those columns; `CODEC(DoubleDelta)` for
  timestamps/counters, `CODEC(Gorilla)` for gauges, `CODEC(ZSTD(1-3))` for long
  strings (summaries, raw messages) instead of default LZ4 when the table is
  large and read-mostly.
- **ORDER BY = your isolation + your scans.** Leading `(tenant_id, ts)` means
  per-tenant RLS scans touch only that tenant's granules. Keep the sorting key
  short; every extra column costs merge CPU.
- **Downsample instead of retaining raw.** For metrics-like tables past ~30d,
  a materialized view into a 5-min/1-h `AggregatingMergeTree` rollup with a
  long TTL beats keeping raw rows (10–100× smaller).

### 1.3 Ingest and query discipline

- **Batch inserts** (we do: `jsonEachRow` batches). Small frequent inserts
  create "too many parts" — the classic CH failure. If many independent
  writers appear, turn on `async_insert=1, wait_for_async_insert=1` instead of
  letting each writer micro-insert.
- **Bound every query path**: `max_memory_usage` + disk spill
  (`users.d/query-spill.xml` here), `max_execution_time`, and a **readonly user
  with quotas** for dashboards so one bad panel can't OOM the ingest path.
- Watch `system.parts` count per table and merge backlog; alert on
  `parts_to_throw_insert` proximity. Native Prometheus endpoint exposes these.

### 1.4 Scaling up: tiering, replication, backup

- **Storage tiering** when retention grows: define a `storage_policy` with a
  hot volume (local NVMe) and a cold volume (S3/object storage), then
  `TTL ts + INTERVAL 7 DAY TO VOLUME 'cold'` — recent data stays fast, history
  gets ~10× cheaper. This is the single biggest cost lever for flow archives.
- **Replication only when you need it**: `ReplicatedMergeTree` + ClickHouse
  Keeper (3 nodes) buys HA, not speed. Shard (by tenant hash) only after a
  single well-tuned node is actually saturated — CH goes surprisingly far
  vertically.
- **Backups**: `BACKUP TABLE ... TO S3(...)` (or clickhouse-backup) with
  incrementals; never file-copy a live data dir. Backup the *netops* database;
  system logs are disposable by design.
- **Pin versions** (we pin `24.8-alpine` by digest) and upgrade LTS→LTS.

---

## 2. Docker volume & host-disk management at scale

### 2.1 Layout: separate the classes of growth

The root cause of both lab outages was **everything sharing one filesystem** —
databases, Docker images, build cache, container logs all compete for `/`.
Production layout:

- **Dedicated LV/filesystem for `data/`** (the bind-mounted store dirs), and
  ideally one per heavy store (clickhouse, opensearch) so one store filling
  cannot read-only the others. Keep ≥20% LVM free space for online grow.
- **`/var/lib/docker` on its own LV** so image/build churn can never starve a
  database.
- **State lives in bind mounts, never in named/anonymous volumes** (this
  repo's convention). Then *every* unreferenced volume is garbage by
  definition and `docker volume prune` is always safe.

### 2.2 Caps and retention as configuration (not cleanup)

- **Container stdout**: `x-logging` anchor caps json-file logs at 50m×N per
  service (already in our compose). At fleet scale, set it host-wide in
  `/etc/docker/daemon.json` (`log-driver: local`, `max-size`, `max-file`) so a
  service added without the anchor can't regress it.
- **Build cache**: structural cap in `daemon.json` (`builder.gc` policy,
  e.g. `defaultKeepStorage: 2GB`) beats cron-only pruning — the cap holds even
  during a heavy build session, which is exactly when the 2026-06-12 outage
  happened.
- **Every datastore states its retention**: CH TTLs (init.sql, with
  `ttl_only_drop_parts=1` so daily-partitioned expiry is a free part drop),
  OpenSearch ISM (14d), VictoriaMetrics `-retentionPeriod=30d`, Redpanda
  cluster defaults `delete_retention_ms=72h` + `retention_bytes=512MB` (the
  `redpanda-init` one-shot sets them on every fresh install; per-topic
  overrides like flows/applogs/syslog still win), Prometheus
  `--storage.tsdb.retention`. A store without retention is a future outage.

### 2.3 Watermarks and automation (defense in depth)

| Layer | Threshold | Action |
|---|---|---|
| stack-watchdog (1m cron) | disk ≥85% | ntfy phone alert (transition-edged) |
| stack-watchdog | disk ≥90% | auto `docker builder prune` emergency valve |
| docker-hygiene.sh (weekly cron) | always | builder cache →2GB, unused images >1wk, anonymous volumes |
| OpenSearch | 95% flood stage | **indices go read-only silently** — the cliff all of the above exists to prevent; recovery: free disk, then `PUT netops-*/_settings {"index.blocks.read_only_allow_delete": null}` |

Install the weekly hygiene cron (one-liner, also in the script header):

```bash
(crontab -l; echo '10 4 * * 0 <repo>/NetOps_Observability/scripts/docker-hygiene.sh >> <repo>/NetOps_Observability/scripts/docker-hygiene.log 2>&1') | crontab -
```

### 2.4 Capacity forecasting (5 minutes, monthly)

```bash
# growth per store
docker exec netops-clickhouse-1 clickhouse-client -q "
  SELECT table, formatReadableSize(sum(bytes_on_disk)) FROM system.parts
  WHERE active AND database='netops' GROUP BY table ORDER BY 2 DESC"
docker exec netops-opensearch-1 curl -s localhost:9200/_cat/indices/netops-*?v'&s=store.size:desc' | head
docker system df
df -h /
```

Trend bytes/day per store against retention: `daily_rate × retention_days ×
1.3 (merge/replica headroom)` must fit the volume. If it doesn't, shorten TTL,
add a codec/rollup, or tier to object storage — in that order of effort.

---

## 3. Incident quick reference

**Logs/ingest stopped silently?** In order: `df -h` → `docker system df` →
OpenSearch index blocks (`_cat/indices`, look for `read_only_allow_delete`) →
Vector router logs for 429s. The two historical causes were disk (build cache,
unsampled flows); the watchdog now alerts before both.
