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

## Managing snapshots

Everything below is the search tier's backup: the `netops-fs` filesystem
repository, the `netops-daily` Snapshot Management (SM) policy that fills it,
and the restore probe that is the only thing proving any of it works. The
alerts `OpenSearchSnapshotNotRestorable`, `OpenSearchSnapshotRestorabilityStale`
and `OpenSearchSnapshotProbeDisabled` (`src/config/rules-scale-slo.yaml`) link
here.

### Why this section exists

On **2026-08-27**, during a disk crunch, somebody ran `rm -rf
data/opensearch-snapshots/indices` to free space. The repository stayed
registered, so OpenSearch kept using it. The `indices/` directory's birth
timestamp is `2026-08-27T01:30:46.011Z` — the cluster re-created it at the
instant that night's 01:30 UTC snapshot started, and every shard in that
snapshot then failed with:

```
java.nio.file.NoSuchFileException: .../indices/<id>/0/index-<gen>
```

**Eight snapshots that read `SUCCESS` were silently unrestorable for seven
days**, because nothing ever tested a RESTORE. `_cat/snapshots` kept listing
rows, the repository kept passing `_verify`, and the Data Protection page kept
saying a snapshot existed. Two rules come out of that incident, and they are
rules, not advice:

1. **Never delete anything inside a registered repository.** Unregister it
   first (`DELETE /_snapshot/<name>`), or delete nothing. Freeing disk by
   deleting blobs under a live repository destroys every restore point that
   references them, including the ones taken months earlier, and `_cleanup`
   cannot repair it: it returns `deleted_bytes: 0` because the older snapshots
   still reference the blobs that are gone.
2. **A backup that has never been restored is not a backup.** `_verify` only
   proves the node can write to `path.repo`. It says nothing about whether a
   single byte of a snapshot is readable. Only the restore-and-compare probe
   below proves a restore point.

**Disk arithmetic (the reason the disk filled).** A filesystem repository on the
same disk as the data it protects, with `max_count: 14`, holds the union of the
segments referenced by ~28 days of indices — roughly **2× the live store** on
top of the live store. That is what filled the volume. Retention on this host
was lowered to `max_count: 3` plus `max_age: 7d` on 2026-09-03. **Raising it
again requires shipping the repository off-host first** (`BACKUP_REMOTE`, see
`docs/audit/BACKUP-FAILURE-DOMAIN.md`); a bigger local repository buys retention
by spending the disk that both copies live on.

### Two ways in

Every operation below has both forms. Use the API form for day-to-day work: it
is authenticated, audited, and it records operator intent. Use the direct form
when the api is the thing that is broken.

**(a) Direct to OpenSearch**, over the admin client certificate. The transport
security plugin is on, so the hostname in the URL must match the certificate;
`--resolve` is what makes that work against the container IP:

```bash
cd NetOps_Observability
OS_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' netops-opensearch-1)
curl -s --cacert data/tls/ca.pem --cert data/tls/admin/admin.crt --key data/tls/admin/admin.key \
     --resolve opensearch:9200:"$OS_IP" https://opensearch:9200/<path>
```

That prefix is written as `curl … ` in the recipes below. It is verified working
on this deployment as of 2026-09-03. `data/tls/admin/admin.key` is a path, not a
secret to print — never `cat` it, and never paste a token or `.env` line into a
ticket.

**(b) Through the Correlix API.** All routes are platform-admin only and
audited. Long operations answer `202` with an `operation` id you poll:

```bash
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/system/backup/...
```

| Route | Method | Body / effect |
|---|---|---|
| `/api/system/backup` | GET | Intent plus live DR status. |
| `/api/system/backup/coverage` | GET | Per-engine coverage table. |
| `/api/system/backup/snapshots` | GET | The `netops-daily` SM policy plus repository state. |
| `/api/system/backup/snapshots` | PUT | `{"enabled":false}` · `{"schedule_cron":"30 1 * * *"}` · `{"retention_max_count":3}` · `{"retention_max_age_days":7}` |
| `/api/system/backup/snapshots/list` | GET | Snapshot inventory with the restorable-verified verdict. |
| `/api/system/backup/snapshots/create` | POST | `{}` — the name is generated server-side. |
| `/api/system/backup/snapshots/delete` | POST | `{"snapshot":"<name>","confirm":"<name>"}` (type-to-confirm). |
| `/api/system/backup/snapshots/restore` | POST | `{"snapshot":"<name>","indices":["<idx>"],"mode":"renamed","rename_prefix":"restored-"}`; `"mode":"in_place"` additionally requires `"confirm":"<name>"`. |
| `/api/system/backup/snapshots/verify` | POST | `{}` probes the newest `SUCCESS`, or `{"snapshot":"<name>"}`. |
| `/api/system/backup/operations`, `/api/system/backup/operations/{id}` | GET | Poll a `202`. |

### Inventory: repositories, snapshots, policies

```bash
curl … https://opensearch:9200/_snapshot/_all           # every registered repository
curl … https://opensearch:9200/_cat/snapshots/netops-fs?v
curl … https://opensearch:9200/_plugins/_sm/policies    # every SM policy
curl … https://opensearch:9200/_plugins/_sm/policies/netops-daily/_explain
```

`_snapshot/_all` returns one object per repository; ours reads
`{"netops-fs":{"type":"fs","settings":{"location":"/usr/share/opensearch/snapshots","compress":"true"}}}`.
An empty `{}` means **no repository is registered and there is no backup of the
search tier at all**.

`_cat/snapshots/netops-fs?v` returns a table with the columns
`id status start_epoch start_time end_epoch end_time duration indices successful_shards failed_shards total_shards`.
A healthy row ends `SUCCESS … 51 51 0 51`: 51 indices, 51 successful shards, 0
failed, 51 total. **A row whose status is `PARTIAL`, or whose `failed_shards` is
non-zero, is a BROKEN restore point, not a warning.** The shards that failed are
not in the snapshot and no later snapshot backfills them. Treat the row as if it
were absent and find out why it failed.

API form:

```bash
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/system/backup/snapshots
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/system/backup/snapshots/list
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/system/backup/coverage
```

`/snapshots` answers the policy (`enabled`, `schedule_cron`,
`retention_max_count`, `retention_max_age_days`, `last_run`, `next_run`).
`/snapshots/list` answers the inventory, each entry carrying its state and the
restorable-verified verdict; an entry that has never been probed reports
unverified, and unverified is not the same fact as good.

### Take a snapshot now

```bash
curl … -X PUT "https://opensearch:9200/_snapshot/netops-fs/<name>?wait_for_completion=false" \
     -H 'Content-Type: application/json' \
     -d '{"indices":"netops-*","ignore_unavailable":true,"include_global_state":false}'
```

Success is `{"accepted":true}` — that is acceptance, not completion. Poll
`_cat/snapshots/netops-fs?v` until the row leaves `IN_PROGRESS`, then read
`failed_shards`. **On this host a full snapshot of ~3.1 GiB took 8.2 minutes.**
Size the maintenance window from that number, not from the first snapshot of an
empty cluster.

`wait_for_completion=true` is the wrong choice here: the request outlives most
proxy and client timeouts, and a timed-out client leaves a snapshot running that
you then have to discover with `GET /_snapshot/_status`.

API form (name generated server-side, returns `202` plus an `operation`):

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{}' http://localhost:8000/api/system/backup/snapshots/create
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/system/backup/operations/<id>
```

### Delete a snapshot

```bash
curl … -X DELETE https://opensearch:9200/_snapshot/netops-fs/<name>
```

Success is `{"acknowledged":true}`. Deleting a snapshot through this API is
safe: OpenSearch drops only the blobs no remaining snapshot references. Deleting
the same bytes with `rm` is the 2026-08-27 incident.

API form, type-to-confirm — `confirm` must equal `snapshot`:

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"snapshot":"<name>","confirm":"<name>"}' \
     http://localhost:8000/api/system/backup/snapshots/delete
```

### Restore

**Renamed (safe, and the default choice).** The restored indices land beside the
live ones under a new prefix, so nothing in production is touched:

```bash
curl … -X POST "https://opensearch:9200/_snapshot/netops-fs/<snap>/_restore?wait_for_completion=true" \
     -H 'Content-Type: application/json' \
     -d '{"indices":"<idx>","rename_pattern":"(.+)","rename_replacement":"restored-$1",
          "include_global_state":false,"include_aliases":false,
          "index_settings":{"index.number_of_replicas":0}}'
```

Success is a `snapshot` object naming the restored indices and a `shards` block
with `"failed":0`. Read the shard counts; a restore that half-worked reports it
there and nowhere else.

**In place.** OpenSearch refuses to restore over an open index, so the live
index must be closed or deleted first. That makes in-place restore a
data-destroying operation on the live tier:

```bash
curl … -X POST https://opensearch:9200/<idx>/_close        # -> {"acknowledged":true}
curl … -X POST "https://opensearch:9200/_snapshot/netops-fs/<snap>/_restore?wait_for_completion=true" \
     -H 'Content-Type: application/json' \
     -d '{"indices":"<idx>","include_global_state":false,"include_aliases":false}'
curl … -X POST https://opensearch:9200/<idx>/_open         # -> {"acknowledged":true}
```

API form:

```bash
# renamed
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"snapshot":"<name>","indices":["<idx>"],"mode":"renamed","rename_prefix":"restored-"}' \
     http://localhost:8000/api/system/backup/snapshots/restore

# in place — requires the type-to-confirm field as well
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"snapshot":"<name>","indices":["<idx>"],"mode":"in_place","confirm":"<name>"}' \
     http://localhost:8000/api/system/backup/snapshots/restore
```

Both answer `202` with an `operation` id; poll
`/api/system/backup/operations/<id>` for the verdict.

### Verify the repository, and the restorability probe

These are two different checks and only one of them is evidence.

**Repository verification** asks every node whether it can write to the
repository path:

```bash
curl … -X POST https://opensearch:9200/_snapshot/netops-fs/_verify
```

Success is the node list, on this single-node deployment:

```json
{"nodes":{"<node-id>":{"name":"opensearch"}}}
```

**That is all it proves.** It passed every day through the 2026-08-27 outage
with an empty blob tree underneath it.

**The restorability probe** is restore-and-compare, and it is the only proof
that matters. Verified end to end on 2026-09-03:

```bash
IDX=<smallest netops-* index>

curl … https://opensearch:9200/$IDX/_count
# -> {"count":64,...}

curl … -X POST "https://opensearch:9200/_snapshot/netops-fs/<snap>/_restore?wait_for_completion=true" \
     -H 'Content-Type: application/json' \
     -d "{\"indices\":\"$IDX\",\"rename_pattern\":\"(.+)\",\"rename_replacement\":\"probe-\$1\",\"include_global_state\":false,\"include_aliases\":false,\"index_settings\":{\"index.number_of_replicas\":0}}"
# -> {"snapshot":{"snapshot":"<snap>","indices":["probe-<IDX>"],"shards":{"total":1,"failed":0,"successful":1}}}

curl … https://opensearch:9200/probe-$IDX/_count
# -> {"count":64,...}   MUST equal the source count

curl … -X DELETE https://opensearch:9200/probe-$IDX
# -> {"acknowledged":true}
```

Pick the smallest index so the probe costs seconds. The count comparison is the
assertion: a restore that produces an index with a different document count is a
failed restore even though every call returned `200`. Always delete the
`probe-*` index afterwards; it is a full second copy of real data and it
consumes the disk this section exists to protect.

API form, which runs the same probe and records the verdict the alerts read:

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{}' http://localhost:8000/api/system/backup/snapshots/verify           # newest SUCCESS
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"snapshot":"<name>"}' http://localhost:8000/api/system/backup/snapshots/verify
```

The verdict feeds `netops_opensearch_snapshot_restorable` and
`netops_opensearch_snapshot_restorable_verified_timestamp_seconds`. A zero
timestamp means the probe has never returned a verdict, which the alert rules
report as not-restorable on purpose: treating unproven as healthy is exactly
what hid a week of unrestorable backups.

### Start, stop and retune the schedule

```bash
curl … -X POST https://opensearch:9200/_plugins/_sm/policies/netops-daily/_stop    # -> {"acknowledged":true}
curl … -X POST https://opensearch:9200/_plugins/_sm/policies/netops-daily/_start   # -> {"acknowledged":true}
curl … https://opensearch:9200/_plugins/_sm/policies/netops-daily/_explain
```

Editing the window or retention means rewriting the policy, and SM's method
rules are not the same as ISM's:

- A **CREATE** is a bare `POST /_plugins/_sm/policies/netops-daily`.
- An **UPDATE** is `PUT /_plugins/_sm/policies/netops-daily?if_seq_no=<n>&if_primary_term=<n>`,
  with both values read from a preceding `GET`. SM rejects a token-less `PUT`
  with "seq_no and primary_term must be provided when updating" **even when the
  policy does not exist and the `GET` 404s** — that mismatch is what left
  `netops-daily` uninstalled once already.
- **Always include `"enabled": <the current value>` in an update body.**
  OpenSearch defaults a missing `enabled` to `true`, so an update that omits it
  silently restarts a schedule an operator deliberately stopped. This was proven
  live at 11:47Z on 2026-09-03: set `enabled=false`, replay a body without the
  field, read `enabled=true` back.

```bash
curl … https://opensearch:9200/_plugins/_sm/policies/netops-daily   # read _seq_no, _primary_term, enabled
curl … -X PUT "https://opensearch:9200/_plugins/_sm/policies/netops-daily?if_seq_no=<n>&if_primary_term=<n>" \
     -H 'Content-Type: application/json' -d '{
  "description": "Daily snapshot of netops-* to the netops-fs repository (F-59).",
  "enabled": true,
  "creation": { "schedule": { "cron": { "expression": "30 1 * * *", "timezone": "UTC" } }, "time_limit": "2h" },
  "deletion": { "schedule": { "cron": { "expression": "0 3 * * *", "timezone": "UTC" } },
                "condition": { "max_count": 3, "max_age": "7d" } },
  "snapshot_config": { "repository": "netops-fs", "indices": "netops-*",
                       "ignore_unavailable": true, "include_global_state": false }
}'
```

A successful write echoes the policy with `"netops-daily"` in it. `deployment/docker/opensearch/apply-ism.sh`
writes the same body on every `compose up` and reads the live `enabled` flag
first so it cannot clobber a deliberate stop; keep any hand-edit consistent with
that file or the next bootstrap reverts it.

API form, which is the one to prefer because it also records who changed what
and why:

```bash
curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"enabled":false}' http://localhost:8000/api/system/backup/snapshots
curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"schedule_cron":"30 1 * * *"}' http://localhost:8000/api/system/backup/snapshots
curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"retention_max_count":3,"retention_max_age_days":7}' \
     http://localhost:8000/api/system/backup/snapshots
```

Each returns the updated policy, the same shape the `GET` answers. While
`enabled` is `false` no new restore points are created, and every hour it stays
off is an hour of indexed logs, traps and flows with no backup.

### Emergency: recreate the repository

Use this only when the repository is proven corrupt — the probe fails with
`NoSuchFileException`, or two repository names were registered over one
location. **It discards every existing restore point.** There is no path back
from it, so read the whole recipe before starting. This is the exact sequence
run on 2026-09-03:

```bash
# 1. Confirm nothing is running. Anything other than an empty list, stop and wait.
curl … https://opensearch:9200/_snapshot/_status
# -> {"snapshots":[]}

# 2. Stop the schedule so it cannot fire mid-recreate.
curl … -X POST https://opensearch:9200/_plugins/_sm/policies/netops-daily/_stop
# -> {"acknowledged":true}

# 3. Unregister the repository FIRST. Rule 1: never delete inside a registered repo.
curl … -X DELETE https://opensearch:9200/_snapshot/netops-fs
# -> {"acknowledged":true}

# 4. Only now move the on-disk tree aside (preferred) or delete it.
mv data/opensearch-snapshots data/opensearch-snapshots.broken-$(date +%F)
mkdir -p data/opensearch-snapshots
# the container writes as uid 1000
sudo chown 1000:1000 data/opensearch-snapshots

# 5. Re-register with the body apply-ism.sh uses, so the next bootstrap agrees.
curl … -X PUT https://opensearch:9200/_snapshot/netops-fs \
     -H 'Content-Type: application/json' \
     -d '{"type":"fs","settings":{"location":"/usr/share/opensearch/snapshots","compress":true}}'
# -> {"acknowledged":true}

# 6. Take one snapshot and wait for it.
curl … -X PUT "https://opensearch:9200/_snapshot/netops-fs/rebuild-$(date +%Y%m%d)?wait_for_completion=false" \
     -H 'Content-Type: application/json' \
     -d '{"indices":"netops-*","ignore_unavailable":true,"include_global_state":false}'
# -> {"accepted":true}   then poll _cat/snapshots/netops-fs?v until SUCCESS with failed_shards 0

# 7. PROVE it with the restorability probe above. Do not skip this step: an
#    unproven fresh repository is the same state the incident started from.

# 8. Restart the schedule.
curl … -X POST https://opensearch:9200/_plugins/_sm/policies/netops-daily/_start
# -> {"acknowledged":true}
```

Free the `.broken-*` directory only after step 7 passes. Once the recreate is
complete the oldest restore point on this host is minutes old, so the recovery
point for everything indexed before it is gone; say so in the incident record
rather than letting the green `_cat/snapshots` row imply otherwise.

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
