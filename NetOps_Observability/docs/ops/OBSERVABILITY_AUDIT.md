# CORRELIX Observability & Audit Catalog (GA readiness)

Per-component monitoring catalog for the shipped stack: what to watch, the
exact copy-paste command, and when a number means "investigate". Thresholds are
tied to the **measured L0/L1 ceilings** in
[`docs/scale/CORRELIX_SCALE_TEST_REPORT.md`](../scale/CORRELIX_SCALE_TEST_REPORT.md)
and [`SCALE_TEST_FINDINGS.md`](../scale/SCALE_TEST_FINDINGS.md) (4 vCPU /
16 GiB rig). Every command and metric name below was **run/verified against a
live TLS-variant install** on 2026-08-16; example outputs are real.

**Component reality check** — generic capacity-plan text does not name our
stack. The mapping (never reintroduce the left column — licensing #97):

| Generic plan says       | This stack ships                                                      |
|-------------------------|-----------------------------------------------------------------------|
| Redpanda / Kafka cluster| **Apache Kafka 4.1.1, single-node KRaft** (`kafka` service, `embedded-bus` profile; external brokers via `BROKER_URLS`) |
| Prometheus              | **VictoriaMetrics v1.101.0** (`victoria`) scrapes natively (`src/config/vmscrape.yml`); **vmalert** evaluates rules; **vmauth** fronts writes/reads on the TLS variant |
| Filebeat / Logstash     | **Vector 0.40** (`vector-aggregator` + `vector-router`) → **OpenSearch 2.16** |
| Redis                   | **Valkey 8** (service name stays `redis`)                              |
| cAdvisor/node exporters | shipped, behind the `self-monitoring` compose profile                  |

## 0. Access conventions

- Compose project is `netops`; containers are `netops-<service>-1`.
- Config + secrets: `deployment/docker/.env` (gitignored). The TLS variant is
  detected by `COMPOSE_FILE=` containing `compose.tls.yml`.
- **Never put credentials on argv** (visible in `ps`). The pattern used
  throughout (same as `scripts/stack-watchdog.sh`): build a curl config on
  stdin — `printf 'url = ...\nuser = "u:pw"\n' | docker exec -i <c> curl --config -`.
- Metrics all land in **one store**: query VictoriaMetrics for everything
  (`docker exec netops-victoria-1 wget -qO- 'http://127.0.0.1:8428/api/v1/query?query=...'`).
  vmauth (TLS variant) is mesh-internal only — it publishes no host port; from
  the host, exec into the victoria container as above.
- Firing alerts are queryable as series (vmalert `-remoteWrite` writes them
  back): `query=ALERTS{alertstate="firing"}`.

---

## 1. ClickHouse (`netops-clickhouse-1`, 24.8-alpine)

In-container `clickhouse-client` needs no credentials (default user,
localhost). **`netops.*` tables carry FORCE row policies** filtering on the
`tenant_scope` custom setting — data queries without
`SETTINGS tenant_scope='__all__'` fail with `UNKNOWN_SETTING`; `system.*`
tables are unaffected.

| Signal | Healthy | Investigate |
|---|---|---|
| Active parts per table | < 100/table on this workload | > 1000 in any single partition (server `parts_to_delay_insert` — inserts get throttled); 3000 = inserts **rejected** (`parts_to_throw_insert`) |
| Merge backlog | 0–2 concurrent merges | sustained > 5, or oldest merge > 10 min |
| Stuck mutations | 0 | any row with `is_done=0` older than minutes |
| Memory | `MemoryTracking` well under the 5.2 GiB container cap | `CHMemoryPressureSustained` rule fires at 85% of 90% cgroup total; `MEMORY_LIMIT_EXCEEDED` errors = `CHMemoryLimitExceeded` |
| Row counts (key tables) | grows with load | use for clean-slate verification |

```bash
# Active part counts, rows, on-disk size per table
docker exec netops-clickhouse-1 clickhouse-client --query \
  "SELECT database, table, count() AS active_parts, sum(rows) AS rows,
          formatReadableSize(sum(bytes_on_disk)) AS size
     FROM system.parts WHERE active AND database='netops'
    GROUP BY database, table ORDER BY active_parts DESC LIMIT 20 FORMAT PrettyCompact"

# Merge / mutation backlog (both 0 on a healthy idle stack)
docker exec netops-clickhouse-1 clickhouse-client --query "SELECT count() FROM system.merges"
docker exec netops-clickhouse-1 clickhouse-client --query \
  "SELECT count() FROM system.mutations WHERE NOT is_done"

# Memory: tracked allocations vs the cgroup
docker exec netops-clickhouse-1 clickhouse-client --query \
  "SELECT formatReadableSize(value) FROM system.metrics WHERE metric='MemoryTracking'"
docker exec netops-clickhouse-1 clickhouse-client --query \
  "SELECT metric, formatReadableSize(value) FROM system.asynchronous_metrics
    WHERE metric IN ('CGroupMemoryUsed','CGroupMemoryTotal') FORMAT PrettyCompact"

# Row count on a tenant-policied table (note the SETTINGS clause)
docker exec netops-clickhouse-1 clickhouse-client --query \
  "SELECT count() FROM netops.corr_signals SETTINGS tenant_scope='__all__'"
```

Live example (idle, freshly reset):

```
   ┌─database─┬─table────────┬─active_parts─┬─rows─┬─size─────┐
1. │ netops   │ flows        │            2 │   33 │ 5.10 KiB │
2. │ netops   │ corr_signals │            1 │    4 │ 2.43 KiB │
   └──────────┴──────────────┴──────────────┴──────┴──────────┘
MemoryTracking: 563.89 MiB   CGroupMemoryUsed: 348.17 MiB / CGroupMemoryTotal: 5.20 GiB
```

ClickHouse also has a native Prometheus endpoint (`clickhouse:9363`, scraped by
victoria — job `clickhouse`); the standing rules `CHMemoryLimitExceeded`,
`CHMemoryPressureSustained`, `CHFailedQueriesRising` in `src/config/rules.yaml`
evaluate `ClickHouseErrorMetric_*` / `ClickHouseMetrics_*` /
`ClickHouseProfileEvents_*` series from it.

---

## 2. VictoriaMetrics (`netops-victoria-1`, v1.101.0)

The container ships busybox `wget`, not curl. Scale finding: VM was **never the
L1 bottleneck** (cardinality not pushed) — the signals below are the standing
guard for when fleets grow.

| Signal | Metric (verified live) | Healthy | Investigate |
|---|---|---|---|
| Active series (hourly) | `vm_cache_entries{type="storage/hour_metric_ids"}` | ~21k idle on L1; scales with devices×interfaces×metrics | step-change vs your own baseline; `VMActiveSeriesSurge` fires at +100k/h |
| Series churn | `rate(vm_new_timeseries_created_total[1h])` | single digits/s | sustained hundreds/s = label cardinality bug |
| Slow inserts | `rate(vm_slow_row_inserts_total[5m]) / sum(rate(vm_rows_inserted_total[5m]))` | ≪ 1% (measured 0.025%) | > 5% for 15m (`VMSlowInsertRatioHigh`) — working set outgrew RAM |
| Ingest rate | `sum(rate(vm_rows_inserted_total[5m]))` | ~460 rows/s idle stack | flat-line = producers stopped |

```bash
# Instant query helper (works on any install; victoria has wget only)
docker exec netops-victoria-1 wget -qO- \
  'http://127.0.0.1:8428/api/v1/query?query=vm_cache_entries%7Btype%3D%22storage%2Fhour_metric_ids%22%7D'

# Slow-insert ratio (the >5% rule expression, verbatim)
docker exec netops-victoria-1 wget -qO- \
  'http://127.0.0.1:8428/api/v1/query?query=rate(vm_slow_row_inserts_total%5B5m%5D)%2Fclamp_min(sum(rate(vm_rows_inserted_total%5B5m%5D))%2C1)'
```

Live example: active series `21210`, churn `7.8 new series/s`, slow-insert
ratio `0.00025` — all healthy.

Scrape inventory (who is monitored at all) is `src/config/vmscrape.yml`
(plaintext) / `vmscrape-mtls.yml` (TLS variant): jobs `netops-api`, `victoria`,
`correlation`, `clickhouse`, `vector` (aggregator + router), `kafka`
(kafka-exporter sidecar), and — `self-monitoring` profile — `cadvisor`, `node`,
`grafana`, `cloud-ingest`. Check coverage with `query=up` (live: all 1 except
`cloud-ingest`, whose sidecar is not deployed — a silent no-op by design).

---

## 3. Kafka (`netops-kafka-1`, Apache Kafka 4.1.1, KRaft single node)

Single node ⇒ **replication factor 1 everywhere; under-min-ISR / partition-
replica alerts are structurally n/a** — broker loss is total bus loss, and the
compose healthcheck + watchdog own that. What matters operationally is
**consumer-group lag**: the scale test showed the bus itself recovers (~3.1M
backlog drained at ~10k msg/s once input stopped) while the correlation
consumer is the slow one (~1k evt/s).

On the **TLS variant the plaintext listener is removed** (SEC-006.3); the admin
tools must dial the mTLS listener `kafka:9094` with the SSL client config the
broker's entrypoint stages at `/tmp/kafka-tls/admin.properties`. Plaintext
baseline: drop `--command-config` and use `kafka:9092`.

```bash
# Consumer-group lag for the RCA engine (TLS variant)
docker exec netops-kafka-1 /opt/kafka/bin/kafka-consumer-groups.sh \
  --bootstrap-server kafka:9094 --command-config /tmp/kafka-tls/admin.properties \
  --describe --group netops-correlation

# All groups (router lanes + correlation)
docker exec netops-kafka-1 /opt/kafka/bin/kafka-consumer-groups.sh \
  --bootstrap-server kafka:9094 --command-config /tmp/kafka-tls/admin.properties \
  --describe --all-groups

# Per-topic end offsets (produce-side volume)
docker exec netops-kafka-1 /opt/kafka/bin/kafka-get-offsets.sh \
  --bootstrap-server kafka:9094 --command-config /tmp/kafka-tls/admin.properties \
  --topic-partitions 'netops.syslog:0,netops.flows:0,netops.applogs:0'
```

Live example (healthy — lag single digits):

```
GROUP              TOPIC                    PARTITION  CURRENT-OFFSET  LOG-END-OFFSET  LAG
netops-correlation netops.syslog            0          1070            1073            3
netops-correlation netops.flows             0          33              33              0
netops-correlation netops.cloud             0          0               0               0
...
```

**READING THE TABLE — `-` is not zero and not dead.** A partition a **live**
member holds but has **never committed** prints `-` in BOTH `CURRENT-OFFSET`
and `LAG`, with a real `CONSUMER-ID` (verified live 2026-08-17 on
apache/kafka 4.1.1). That is the normal state of a freshly installed stack
before any traffic — correlation commits manually (N=100/T=5 s) and Vector
commits on consume, so neither has committed yet. **Membership is the
`CONSUMER-ID` column, never the offset columns**: `CONSUMER-ID = -` is the
dead-consumer signature (committed offsets frozen, lag growing, nobody
attached — the 2026-08-16 wiped-ACL shape). Misreading `-` LAG as "no
consumer" is exactly what failed nightly CI run 31991056443 against a
perfectly healthy stack.

| Signal | Healthy | Investigate (from measured ceilings) |
|---|---|---|
| `netops-correlation` total lag | 0–100 | > 60k ≈ 1 min RCA staleness (warning), > 300k ≈ 5 min (critical) — drain rate is ~1k evt/s |
| Router lanes (`netops-router-*`) lag | 0–1000 | growing lag with flat `CURRENT-OFFSET` = consumer dead (`KafkaConsumerStalled` rule) |
| Broker disk (`data/kafka`) | see §8 host disk | the 8k-EPS run burned ~3 GB in minutes → disk-full in ~1 h sustained |

Metrics path: the broker is JMX-only (no native Prometheus endpoint —
deliberate); lag series come from the **kafka-exporter sidecar**
(`self-monitoring` profile, `kafka-exporter:9308`):
`kafka_consumergroup_lag_sum{consumergroup,topic}`,
`kafka_consumergroup_current_offset_sum`, `kafka_topic_partition_current_offset`.
`KafkaLagMetricsMissing` (rules.yaml) meta-alerts when the series vanish — live
observation 2026-08-16: the exporter intermittently returns only `kafka_brokers`
on a scrape (group describe raced); the meta-alert fires on the gap, and the
`docker exec` commands above are the ground truth when it does.

---

## 4. OpenSearch (`netops-opensearch-1`, 2.16.0-slim)

Two very different access stories:

- **Plaintext baseline**: security plugin disabled — `docker exec
  netops-opensearch-1 curl -s http://localhost:9200/_cluster/health` just works.
- **TLS variant (SEC-008)**: security plugin ON, per-service users, HTTPS with
  the mesh CA. Probe from inside the container against hostname `opensearch`
  (the SVID's SAN — `localhost` fails hostname verification), CA at
  `/usr/share/opensearch/config/tls/ca.pem`, credentials from `.env` via curl
  config on stdin. Role scopes matter: `svc_api` may read `_cluster/health`
  but **403s on `_cat/indices`** (`indices:monitor/stats` not granted);
  `svc_bootstrap` (password `OS_BOOTSTRAP_PASSWORD`) is the service role that
  can list indices; `svc_aggregator` (`OS_AGGREGATOR_PASSWORD`) reads
  `_nodes/stats`.

```bash
# TLS variant — cluster health (svc_api). Creds via stdin, never argv.
ENVF=deployment/docker/.env
PW=$(sed -n 's/^OS_API_PASSWORD=//p' "$ENVF" | head -1)
printf 'url = "https://opensearch:9200/_cluster/health?pretty"\nmax-time = 8\nsilent\ncacert = "/usr/share/opensearch/config/tls/ca.pem"\nuser = "svc_api:%s"\n' "$PW" |
  docker exec -i netops-opensearch-1 curl --config -

# TLS variant — index inventory (svc_bootstrap)
PW=$(sed -n 's/^OS_BOOTSTRAP_PASSWORD=//p' "$ENVF" | head -1)
printf 'url = "https://opensearch:9200/_cat/indices/netops-*?v&h=health,index,docs.count,store.size&s=index"\nmax-time = 8\nsilent\ncacert = "/usr/share/opensearch/config/tls/ca.pem"\nuser = "svc_bootstrap:%s"\n' "$PW" |
  docker exec -i netops-opensearch-1 curl --config -

# TLS variant — node stats incl. the per-document reject counter (svc_aggregator)
PW=$(sed -n 's/^OS_AGGREGATOR_PASSWORD=//p' "$ENVF" | head -1)
printf 'url = "https://opensearch:9200/_nodes/stats/indices/indexing"\nmax-time = 8\nsilent\ncacert = "/usr/share/opensearch/config/tls/ca.pem"\nuser = "svc_aggregator:%s"\n' "$PW" |
  docker exec -i netops-opensearch-1 curl --config -
```

Live example:

```
"cluster_name":"netops-search", "status":"green", "active_shards":11, "unassigned_shards":0

health index                                   docs.count store.size
green  netops-applogs-untagged-2026.08.16            3264      1.2mb
green  netops-flows-untagged-2026.08.16                 1     25.1kb
green  netops-platformlogs-untagged-2026.08.16       5449      1.5mb
green  netops-syslog-untagged-2026.08.16              927    462.6kb
```

| Signal | Healthy | Investigate |
|---|---|---|
| Cluster status | **green — and green means something here** (templates pin `number_of_replicas: 0`; see the `OpenSearchClusterNotGreen` rule comment) | yellow >15m (existing rule); **red ≥5m = page** (`OpenSearchClusterRed`, scale-slo) |
| Indexing CPU | idle ~0 | scale finding: OS hit **94% CPU at ~2k EPS** on 4 cores — sustained >90% container CPU = at the L1 ingest ceiling |
| Heap | idles **2.29 GiB / 3.69 GiB cap (62%)** — the tightest memory on an L1 box | working-set ≥ 90% of container cap (`ContainerMemoryNearLimit`) |
| Per-doc rejects | `doc_status.4xx` moves only on housekeeping conflicts (~0.8/min measured) | `OpenSearchDocumentsRejected` composite (4xx + Vector unintentional discards) — **do not read `index_failed`; it stays 0 during real loss** |
| Shards/node | ~11 today | > 300 warn / > 700 critical (heap density; existing rules) |

Metrics path (no separate exporter): **vector-aggregator polls
`_cluster/health` + `_nodes/stats/indices/indexing`** and flattens them into VM
series (`vector.yaml`): `opensearch_cluster_status` (0 green / 1 yellow /
2 red / 3 unknown, label `status_text`), `opensearch_cluster_active_shards`,
`opensearch_cluster_unassigned_shards`, `opensearch_indexing_doc_status{code}`,
`opensearch_indexing_index_total`.

---

## 5. PostgreSQL (`netops-postgres-1`, 16-alpine)

In-container psql authenticates as `$POSTGRES_USER` (from `.env` `DB_USER`).
`max_connections` defaults to 100 (`PG_MAX_CONNECTIONS`). Scale finding: PG was
**never the limit** — device-scale pain lives in the app-side KV blob
(report §3.7), not here.

```bash
# Connection saturation vs max_connections
docker exec netops-postgres-1 sh -c \
  'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c \
   "SELECT datname, state, count(*) FROM pg_stat_activity GROUP BY datname, state ORDER BY datname;" \
   -c "SHOW max_connections;"'

# RLS policy inventory (tenant_iso FORCE policies)
docker exec netops-postgres-1 sh -c \
  'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c \
   "SELECT schemaname, tablename, policyname, permissive, cmd FROM pg_policies ORDER BY tablename;"'
```

Live example:

```
 datname  | state  | count          max_connections: 100
----------+--------+-------
 keycloak | idle   |     1
 netops   | active |     1
```

| Signal | Healthy | Investigate |
|---|---|---|
| Total connections | < 20 on the bundle | > 80 of 100 = saturation (long-lived leak or Keycloak storm) |
| `pg_policies` rows | **0 on a default install** — `STORE_BACKEND=file` keeps app state out of PG, so only Keycloak uses it. With `STORE_BACKEND=postgres`, every `tenant_iso` FORCE-RLS policy from `src/backend/internal/platformdb/migrations/` must be present | app-state tables existing **without** their `tenant_iso` policy = cross-tenant exposure — treat as an incident |
| `state='idle in transaction'` | 0 | any, for minutes — blocks vacuum |

---

## 6. Correlation engine (`netops-correlation-1`, Python)

**The value-path limiter**: measured ~850–1,050 events/s on one core
(report §9); its consumer lag ↔ RCA staleness conversion drives the scale-slo
alerts. Two surfaces, same numbers: `/metrics` (Prometheus text, scraped by
victoria as job `correlation`) and `/healthz` (JSON, richer).

Plaintext baseline: `curl http://correlation:8000/healthz` from any mesh
container. TLS variant serves mTLS on **:8443**; the container's own
healthcheck pattern doubles as the operator probe:

```bash
docker exec netops-correlation-1 python -c "import urllib.request,ssl; \
ctx=ssl.create_default_context(cafile='/certs/ca.pem'); \
ctx.load_cert_chain('/certs/svid/correlation.crt','/certs/svid/correlation.key'); \
print(urllib.request.urlopen('https://correlation:8443/healthz', timeout=4, context=ctx).read().decode())"
```

Exposed Prometheus series (all live-verified except where noted):

| Series | Meaning | Investigate |
|---|---|---|
| `corr_ingest_events{counter}` | per-lane received/accepted/dropped counters (`syslog_received`, `metrics_dropped_no_identity`, `cloud_dropped`, …) | `*_dropped` rising (`CorrEventsDroppedRising`); received flat while the bus moves (`CorrProbeLaneFlatlined`) |
| `corr_deadletters` | engine dead-letter count | any increase (`CorrDeadLettersRising`) |
| `corr_window_signals` | in-memory correlation window depth | > 40k (cap floor 50k = silent eviction; `CorrWindowBufferNearCap`) |
| `corr_open_objects`, `corr_versions{outcome}` | RCA object churn / damping health | damped:persisted collapsing to 0 in a storm (`CorrVersionChurnUndamped`) |
| `corr_quarantined_events`, `corr_tenant_claims_total{outcome}` | poison events; tenant-claim verification | `refused` rising = something on the bus forges tenant ids |
| `corr_current_projection_write_failures_total` | stale-Command-Center risk | > 0 (`CorrCurrentProjectionFailing`) |
| `corr_signal_batch{event}`, `corr_signal_batch_pending`, `corr_ch_insert_failures_total{table}`, `corr_handler_failures_total{topic}` | batched CH write path / durability | **ship with this branch's build** — absent on older deployed images (verified live: not yet exposed on the 2026-08-16 install). `rows_quarantined` > 0 = rows parked in the durable DLQ (`CorrSignalRowsQuarantined`) |

`/healthz` additionally reports what has **no metric form** — see §9.

`/deadletters` (fronted with authz by the Go API) returns the quarantined
payloads themselves — the reproduction artifact when `corr_handler_failures`
moves.

---

## 7. Vector pipelines (`vector-aggregator`, `vector-router`, 0.40)

Both expose `internal_metrics` via a Prometheus exporter on `:9598` (job
`vector` — two instances). The names the standing rules already use (all in
`src/config/rules.yaml`, verified in VM):

- `vector_component_discarded_events_total{intentional="false"}` — the ONLY
  honest loss counter (`VectorEventsDiscarded`).
- `vector_component_errors_total{component_id,error_type}` — includes
  `*_quarantine` sinks (`VectorQuarantineSealFailures`).
- `vector_component_sent_events_total{component_id=~"opensearch_deadletter|kafka_deadletter"}`
  — ingest dead-letter traffic (`VectorDeadLetters`).
- Scale context: the measured ~10k msg/s router ceiling (consume → VRL →
  bulk-index) is the ingest bound on L1 — watch router CPU (§8) alongside
  consumer lag (§3) when pushing EPS.

---

## 8. Host & containers (`self-monitoring` profile: cadvisor v0.52.1, node-exporter v1.8.2)

What victoria scrapes for the resource/restart layer (verified live: 26
per-container series sets):

```bash
# Per-container series present? (containerd handler: `name` label is the ID hash — select name!="" , never name=~"netops-.*")
docker exec netops-victoria-1 wget -qO- \
  'http://127.0.0.1:8428/api/v1/query?query=count(container_last_seen%7Bname!%3D%22%22%7D)'

# Host disk headroom (the DiskHeadroomLow / DiskWillFillIn24h expressions' source)
docker exec netops-victoria-1 wget -qO- \
  'http://127.0.0.1:8428/api/v1/query?query=node_filesystem_avail_bytes%7Bmountpoint%3D%22%2F%22%2Cfstype!~%22tmpfs%7Coverlay%7Csquashfs%22%7D'

# Quick live triage without metrics at all
docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}'
```

Standing rules riding these: `ContainerDown`, `ContainerRestartLoop`,
`ContainerOOMKilled`, `ContainerMemoryNearLimit`, `ContainerCPUSaturated`,
`HostMemoryLow`, `HostDiskLow`, `DiskWillFillIn24h`, `ContainerMetricsMissing`
(meta-alert for cadvisor itself). L1 context for triage: the empty stack idles
at **5.5 GiB/15.6 GiB host RAM** with OpenSearch the tightest container; disk
is the sacrificial resource under ingest overload (~3 GB burned in the 8k-EPS
run).

---

## 9. Signals with NO metric (watchdog territory — do not invent series)

Verified absent; covered instead by `scripts/stack-watchdog.sh` (external
cron, healthchecks.io dead-man's-switch + ntfy push — deliberately independent
of the stack's own notifiers):

| Signal | Where it actually lives | Coverage |
|---|---|---|
| **Correlation dead-letter WRITE failures** (`QUARANTINE_WRITE_FAILURES` — the 238k-silent-drop incident, report §5 defect 3) | `/healthz` JSON `durability.quarantine_write_failures` and `/deadletters` `write_failures` — **not in `/metrics`** | watchdog + the §6 healthz probe; product fix (entrypoint self-chown) tracked in the scale report |
| Broker-internal health (ISR, controller, log flush) | JMX only — no Prometheus endpoint by decision (vmscrape.yml note) | compose healthcheck (TCP accept on the listener), kafka-init as functional gate, §3 lag as the outcome signal |
| vmauth per-credential auth failures | vmauth logs (`docker logs netops-vmauth-1`) | watchdog stack-freshness probes fail loudly through it |
| Anything during a victoria outage | — (the metrics store is down) | watchdog probes services directly, never through VM |

---

## 10. Scale-SLO alert rules & runbooks

Rules: [`src/config/rules-scale-slo.yaml`](../../src/config/rules-scale-slo.yaml)
— evaluated by **vmalert only** (second `-rule=` flag in both compose files;
the in-API engine keeps reading `rules.yaml` alone). Validated with the pinned
image: `docker run --rm -v $PWD/src/config:/rules:ro
victoriametrics/vmalert:v1.101.0 -rule=/rules/rules.yaml
-rule=/rules/rules-scale-slo.yaml -dryRun` (exit 0, 2026-08-16). Firing state
is queryable: `ALERTS{alertstate="firing", slo="scale"}`.

Each alert's `runbook` annotation anchors below. Plays are first-response —
minutes, not projects.

> **Engine liveness (2026-09-02).** The `engine-liveness` group in the same
> file answers a different question from the scale SLOs above: not "is this
> fast enough" but **"is this engine doing any work at all"**. Its rules anchor
> into two dedicated runbooks instead of this section:
>
> * [`docs/runbooks/engine-not-consuming.md`](../runbooks/engine-not-consuming.md)
>   — first response for a service that is *running and healthy and doing
>   nothing*: the 3-hour silent outage of 2026-09-02, the three alerting layers,
>   and the ACL/topic bootstrap commands.
> * [`docs/runbooks/engine-liveness-matrix.md`](../runbooks/engine-liveness-matrix.md)
>   — the per-service inventory of what "doing its job" means, the metric that
>   proves it, the expected-idle guard, the tier, and the known gaps.

### Runbook: correlation consumer lag

`CorrelationRcaLagBudgetWarning` (>60k) / `CorrelationRcaLagBudgetBreached`
(>300k). Lag ÷ ~1,000/s = seconds of RCA staleness (measured drain rate).

1. Confirm with ground truth (§3 `--describe --group netops-correlation`) —
   if the exporter lied (KafkaLagMetricsMissing also firing), trust the CLI.
2. Is correlation alive and consuming? `docker logs --tail 50
   netops-correlation-1`; §6 healthz. A crash-loop is `ContainerRestartLoop`
   territory — restart cause first.
3. Is this overload (input > ~1k evt/s) or a stall (offsets flat)? Offsets
   flat ⇒ engine wedged: capture `/healthz`, then `docker restart
   netops-correlation-1` (consumer group resumes at committed offsets; nothing
   is lost, §Kafka-recovers finding).
4. Overload ⇒ storage stays current, RCA lags — measured behavior. Shed input
   at the source (stop the EPS source / narrow discovery), then watch lag
   drain at ~1k/s. Sustained real load at this level needs the report §7
   partitioned-instances plan — an ops shift cannot fix it live; say so in the
   incident.
5. Check disk while lagged: backlog holds Kafka segments alive
   (~3 GB burned in minutes at 8k EPS; retention `BUS_RETENTION_MS` = 72 h).

### Runbook: VM series growth

`VMActiveSeriesSurge` (+100k/h) / `VMSlowInsertRatioHigh` (>5% for 15m).

1. What changed? `delta(vm_cache_entries{type="storage/hour_metric_ids"}[1h])`
   plus churn `sum(rate(vm_new_timeseries_created_total[1h]))`.
2. Find the offender by count per job/metric:
   `topk(10, count({__name__!=""}) by (__name__))` — a runaway label shows up
   as one metric name with a huge series count.
3. Typical causes here: a discovery storm registering thousands of devices
   (×interfaces×metrics), a collector emitting an unbounded label (scan ids,
   session ids), or a scrape target added with per-request labels. Stop the
   producer; series age out of the active window on their own.
4. Slow-inserts >5% with normal cardinality = memory pressure: check
   `VICTORIA_MEM_LIMIT` (default 1536m) against §8 container memory, and the
   `--memory.allowedPercent=60` budget, before granting more RAM.

### Runbook: correlation queues

`CorrWindowBufferNearCap` (>40k of the 50k floor) /
`CorrSignalBatchBacklog` (>5k pending for 10m).

1. Window buffer near cap: the engine is buffering faster than it correlates —
   same triage as consumer lag (above), it is the in-process symptom of the
   same ~1k evt/s ceiling. Raising `CORR_WINDOW_BUFFER` buys minutes, not a
   fix; eviction at the cap is silent signal loss.
2. Batch backlog: ClickHouse insert path is slow/failing. Check
   `corr_ch_insert_failures_total` and §1 merge backlog / memory; a CH
   restart mid-load shows here first.
3. Both while input is idle = engine wedged → healthz snapshot, restart.

### Runbook: correlation DLQ

`CorrSignalRowsQuarantined` (>0 in 15m): ClickHouse REJECTED a corr_signals
batch; the rows are parked durably, not lost — but RCA history has a hole
until replay.

1. `corr_ch_insert_failures_total{table}` names the table;
   `docker logs netops-correlation-1 | grep -i quarantin` has the CH error.
2. Fix the cause (schema drift after a partial upgrade, CH memory/parts
   pressure §1), then replay the parked rows from the DLQ dir
   (`CORR_DLQ_DIR`, default under `data/correlation/`).
3. **Related but metric-less**: if the DLQ *directory itself* is unwritable
   (the 238k-drop ownership incident), nothing fires here — that is §9
   watchdog territory. `/healthz` `durability.quarantine_write_failures` > 0
   is the tell; fix ownership (`chown 10001` on the dir) immediately, every
   event lost meanwhile is unrecoverable.

### Runbook: OpenSearch red

`OpenSearchClusterRed` (`opensearch_cluster_status >= 2` for 5m). Single-node:
red = a primary shard is unassigned/lost — the affected lanes are **failing
writes right now** (Vector retries buffer briefly, then §7 discards count the
loss).

1. Status + which lane: §4 health command, then the §4 `_cat/indices`
   command — the `health` column names the red index. (On the TLS variant no
   service role is granted `cluster:monitor/allocation/explain` — verified
   403 for `svc_bootstrap` — so `_cluster/allocation/explain` is a
   plaintext-baseline tool only; least privilege is deliberate.)
2. `docker logs --tail 100 netops-opensearch-1` — on this stack red has two
   realistic shapes: disk flood-stage (OS force-blocks allocation; check §8
   host disk, then clear space — Kafka retention and old indices first) or a
   corrupted shard after an unclean stop.
3. Heap-death restart-loop: §4 heap idles at 62% of cap on L1 — if
   `ContainerOOMKilled` fired too, raise `OPENSEARCH_MEM_LIMIT`/heap before
   anything else.
4. `status=3` ("unknown") = the health poll itself broke (aggregator token,
   OS down entirely) — check `up{job="vector"}` and the watchdog, not shards.
5. After recovery, verify no silent loss: `OpenSearchDocumentsRejected`
   history + `_cat/indices` doc counts vs expectation.

---

## 11. Clean-slate reset (`scripts/clean-slate.sh`)

Scripts the manual factory-reset used to start the scale-test programme
(report §2). Destroys **everything under `data/`** (including TLS custody —
TLS installs cannot start again without reinstall); **preserves
`deployment/docker/.env`** unless `--reset-env`.

```bash
scripts/clean-slate.sh --dry-run              # show exactly what would be destroyed
scripts/clean-slate.sh                        # stop stack, wipe data/, chown back (asks first)
scripts/clean-slate.sh --yes --reinstall --tls yes   # full unattended reset + reinstall
scripts/clean-slate.sh --reset-env --reinstall       # reset + rotate all secrets
scripts/clean-slate.sh --verify               # read-only: prove the running stack is empty
```

`--verify` checks: **0 devices** via the API (admin login from `.env`),
ClickHouse `netops.corr_signals`/`netops.flows` counts, OpenSearch
`_cat/indices` per lane, and Kafka consumer-group offsets — with explicit
tolerance for the platform's own self-telemetry, which starts refilling
applogs/platformlogs the moment the stack boots. Guards: refuses a data dir
resolving outside the repo, refuses to run unattended without `--yes`, refuses
to wipe while project containers are still running, and every step reports its
own failure (no `|| true` error-swallowing — §16 scripts bar).

---

## 12. G2 scale mini-ladder (`scripts/scale-miniladder.py`)

Self-judging nightly scale-regression harness — the G2 GA gate. Runs against
the LIVE stack and asserts the RELATIVE/invariant properties whose loss
produced the three 2026-08 scale defects, so it is valid on any hardware:
onboarding linearity (the O(N²) per-device-persistence class), consumer-lag
drain after a 10×-nominal burst (the "lag never drains" class), and exact
loss accounting — every injected event must be OpenSearch-persisted,
DLQ-counted, or an explicitly-counted rejection (the 238k-silent-drop class;
`quarantine_write_failures` movement fails the run). Plus per-container
memory flatness, and a cleanup phase that always runs: devices deleted and
verified gone, run telemetry purged from ClickHouse/OpenSearch — a green run
leaves the stack passing `clean-slate.sh --verify`.

```bash
scripts/scale-miniladder.py --dry-run              # print the plan, touch nothing
scripts/scale-miniladder.py                        # full gate: 1000 devices, 5-min burst @2000 eps
scripts/scale-miniladder.py --devices 100 --burst-minutes 1 --eps 400   # smoke profile
```

Credentials come from `deployment/docker/.env` (or `MLX_ADMIN_USER`/
`MLX_ADMIN_PASSWORD`), never argv. Reports land in
`data/miniladder/<ts>-<runid>/report.{md,json}`; the summary heartbeat
`data/miniladder/last-run.json` is refreshed every run so the watchdog can
tell "G2 failed" from "G2 stopped running". Nightly wiring is cron on the lab
host — sample line and the hostile-cron-environment notes are in the script
header (same discipline as `stack-watchdog.sh`); do not install it blindly.

CI: a REDUCED profile (200 devices, 2-min burst) runs on GH-hosted runners in
`.github/workflows/scale-miniladder-nightly.yml`, reusing the proven
`tls-install-boot` full-stack bring-up from `fresh-install-integrity.yml`.
The full-size run stays lab-cron on purpose: shared 4-vCPU runners make
absolute ceilings meaningless, and the harness's invariants at small scale
are the honest subset that fits there.

Preflight will refuse a stack whose bus consumers hold no group membership —
that is the fresh-TLS-install wiped-ACL failure shape (2026-08-16: broker
enforces `allow.everyone.if.no.acl.found=false`, `data/kafka` reset wiped the
ACL matrix, nothing re-applies `deployment/docker/kafka/apply-acls.sh` — the
whole ingest tier is auth-dead while every container reports healthy). Until
the install path applies the matrix itself, re-apply it per the SEC-007
runbook after any clean-slate reinstall.
