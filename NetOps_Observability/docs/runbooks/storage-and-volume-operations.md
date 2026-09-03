# Storage & Volume Operations — ClickHouse + Docker at Scale

Runbook + design guide for keeping the stack's storage bounded, from a single
lab host to a large production deployment. Written after the 2026-07-03 #96
baseline, where **93% of ClickHouse's disk was its own introspection logging**
(5.84 GiB of `system.*` vs 453 MiB of telemetry) on a host at 82% disk — on top
of two prior disk-driven ingest outages (2026-06-10 unsampled flows, 2026-06-12
Docker build cache). Storage problems creep silently and surface as *other*
components' bugs: OpenSearch flips every index read-only at its 95% flood
stage and ingestion stops with no error.

Related: `deployment/docker/clickhouse/system-logs.xml` (#96a, the system.*
TABLES) and `clickhouse/logger.xml` (2026-09-03, the server's TEXT log inside
the container layer — §1.1 a), `scripts/docker-hygiene.sh` (#96b),
`scripts/stack-watchdog.sh` (disk warn 85% / auto builder-prune 90% /
ingest-liveness probe), TRACKER §G. Guards:
`tests/test_clickhouse_server_log_bounded.py`,
`tests/test_compose_logging_bounded.py`.

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

### 1.1a Bound the server's TEXT log (the copy inside the container layer)

`system-logs.xml` bounds the system.* *tables*, which live in the bind mount.
It does nothing for `/var/log/clickhouse-server/` — the server's plain-text log
— and that directory is **not mounted at all**, so its bytes land in the
container's writable layer under `/var/lib/docker/overlay2`.

Measured 2026-09-03, host at 94% disk (OpenSearch flood stage is 95%):

```
docker exec netops-clickhouse-1 du -sh /var/log/clickhouse-server
1.8G     # clickhouse-server.log 924M + .err.log 109M + 10 x ~90M .gz
```

Two blind spots make this creep silently, and both are worth internalising
because they generalise to any container that logs to a file:

- **`du -sh data/` cannot see it.** Only `docker system df -v` (or
  `docker ps -s`, "SIZE ... virtual") accounts for a container's writable layer.
- **The compose `x-logging` cap cannot see it either.** That cap applies to
  *stdout*; the ClickHouse image leaves `<console>` commented out in
  `docker_related_config.xml`, so nothing of substance reaches `docker logs`.

Stock 24.8 defaults are `<level>trace</level>`, `<size>1000M</size>`,
`<count>10</count>`, applied to the server log **and** the error log — an
~11 GiB per-server ceiling. This repo ships
`deployment/docker/clickhouse/logger.xml` (mounted into `config.d/`) with
`information` / `100M` / `3`, a ~0.3 GiB ceiling.

- Takes effect on **container recreate** (`docker compose up -d clickhouse`),
  not on `docker restart`.
- The oversized file is in the OLD container layer; recreating the container
  reclaims it. To reclaim without a recreate:
  `docker exec netops-clickhouse-1 sh -c ': > /var/log/clickhouse-server/clickhouse-server.log'`
  (truncate in place — never `rm`, the server holds the fd).
- To debug a server-side problem, set `<level>` back to `debug`/`trace` in
  `logger.xml`, `docker compose up -d clickhouse`, and **put it back**.
- Guarded by `tests/test_clickhouse_server_log_bounded.py`.

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

- **Container stdout**: the `x-logging: &deflog` anchor caps json-file logs at
  50m×3 per service. As of 2026-09-03 it is on **every** service in every
  compose file, enforced by `tests/test_compose_logging_bounded.py` — before
  that it was on 8 of 35, which is how `opensearch` reached a 1.1 GiB json log
  and `opensearch-dashboards` 200 MiB on a host at 94%. Two things to know:
  - **it applies on container RECREATE.** Docker fixes the log driver and its
    options at create time, so `docker compose up -d` (which recreates on a
    config change) is what applies a new or changed cap; `docker restart` and
    `docker compose restart` keep the old, unbounded file. The already-oversized
    json logs are only reclaimed by that recreate, or by truncating
    `$(docker inspect --format '{{.LogPath}}' <container>)` in place.
  - **it caps stdout only** — a container that writes its own log FILE (see
    §1.1 a, ClickHouse) is not covered by it at all.
  At fleet scale, also set it host-wide in `/etc/docker/daemon.json`
  (`log-driver: local`, `max-size`, `max-file`) so a service added without the
  anchor can't regress it.
- **Build cache**: structural cap in `daemon.json` (`builder.gc` policy,
  e.g. `defaultKeepStorage: 2GB`) beats cron-only pruning — the cap holds even
  during a heavy build session, which is exactly when the 2026-06-12 outage
  happened.
- **Every datastore states its retention**: CH TTLs (init.sql, with
  `ttl_only_drop_parts=1` so daily-partitioned expiry is a free part drop),
  OpenSearch ISM (14d), VictoriaMetrics `-retentionPeriod=30d`, Kafka
  broker-wide bounds `BUS_RETENTION_MS` (72h) + `BUS_RETENTION_BYTES`
  (512MB) set via `.env` on the broker itself (per-topic overrides still
  win), Prometheus `--storage.tsdb.retention`. A store without retention
  is a future outage. The Kafka data dir is `data/kafka/` (uid 1000);
  `data/redpanda/` is legacy on upgraded installs and can be removed.

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

# growth that lives NOWHERE in data/ — container writable layers + json logs
docker system df -v | head -30
for c in $(docker ps -q); do
  printf '%s\t%s\n' \
    "$(docker inspect --format '{{.Name}}' "$c")" \
    "$(sudo du -h "$(docker inspect --format '{{.LogPath}}' "$c")" | cut -f1)"
done | sort -k2 -h -r | head
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

**Disk climbing and `data/` doesn't explain it?** Three places outside the bind
mounts, in the order they have actually bitten us:

| Where | Find it | Bound it |
|---|---|---|
| Container json logs (stdout) | `sudo du -h $(docker inspect --format '{{.LogPath}}' <container>)` | `logging: *deflog` on the service, then `docker compose up -d` to **recreate** |
| Container writable layer (a service logging to a file — ClickHouse) | `docker system df -v`; `docker exec <c> du -sh /var/log/...` | ship a config that rotates it (§1.1 a) |
| Build cache / dangling images | `docker system df` | `docker-hygiene.sh`; `builder.gc` in `daemon.json` |

The watchdog's own log is `data/stack-watchdog.log` (see
`scripts/stack-watchdog.sh`); it is timestamped and appended by cron, so
`tail -50 data/stack-watchdog.log` is the fastest read of what the host looked
like when the alert fired.
