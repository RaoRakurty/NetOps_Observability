# Engine liveness matrix — what proves each service is *working*

> **The question this answers:** "How many engines does Correlix need to
> function, and how do I know each one is doing its job?"
>
> `docker compose ps` answers a different and much weaker question. On
> 2026-09-02 every container read `healthy` while the correlation engine
> consumed nothing for three hours
> (`docs/runbooks/engine-not-consuming.md`). **Running ≠ working.** This file
> is the inventory of the difference, per service.

## How to read it

* **Doing its job** — the claim that must be true, phrased as work performed,
  never as "the process exists".
* **Proof** — the metric that carries that claim, verified present in the live
  VictoriaMetrics store on 2026-09-02. Where a service has **no metric**, the
  row says so; nothing here is aspirational.
* **Expected-idle guard** — how the rule avoids paging for a legitimately quiet
  lab. Getting this wrong is worse than no rule: a pager that cries wolf gets
  muted, and then the platform is blind again.
* **Tier** — see below.
* **Covered by** — the specific rule / layer. `NEW` marks something this change
  added.

### Tiers (owner ruling, 2026-09-02)

| Tier | Meaning | Routing |
|---|---|---|
| **page** | One of exactly **four** page-worthy conditions | `severity: critical`, `tier: page` → delivered to the phone |
| **watch** | Real, actionable, not worth waking someone | `severity: warning` → status surfaces + digest |
| **heartbeat** | Plumbing, never routed to a human | `AlertingHeartbeat` only |

**The four page conditions, and nothing else:**

1. **An engine consumer is not consuming** — a consumer group has zero members,
   or lag is rising while a member is still joined.
2. **Ingest is silent when it should not be** — the funnel emits nothing while
   an independent producer says there is data to carry.
3. **Storage is refusing writes** — OpenSearch red / flood-stage, or ClickHouse
   rejecting batches.
4. **The alerting heartbeat stopped arriving** — the delivery chain itself is
   broken, so every other alert is unproven.

Everything else is `watch`. The stack already carries ~140 warning/critical
rules in `src/config/rules.yaml`; this matrix **maps services onto them**
rather than minting duplicates.

### The three layers (each works without the other two)

| Layer | Mechanism | Survives |
|---|---|---|
| **A** | vmalert rule → delivered via the webhook to `notify.Dispatcher` | api-side rule engine being down |
| **B** | `scripts/stack-watchdog.sh` → ntfy (independent channel) | **the entire stack**, alerting included |
| **C** | container healthcheck / `restart:` policy | nothing subtle — it is the floor, not the ceiling |

---

## Tier-1 engines — the pipeline. If one of these stops, data is lost.

| Service | Doing its job means | Proof metric | Expected-idle guard | Tier | Covered by |
|---|---|---|---|---|---|
| **correlation** | Its Kafka consumer is joined **and draining** the 14 required lanes into RCA | `kafka_consumergroup_members{consumergroup="netops-correlation"}`; `corr_consumer_running`; `kafka_consumergroup_lag_sum` | None needed — the prober ticks 24/7, so this lane is *never* legitimately idle | **page** | A: `CorrelationConsumerDead` **NEW**, `CorrelationLagGrowing` **NEW**, `CorrConsumerNotRunning` **NEW**, `CorrConsumerRestartLoop` **NEW** · B: watchdog consumer probe **NEW** · C: `:8094` (HTTP-200 only, tracker 174 — deliberately weak) |
| **correlation** (evidence lanes) | Each optional `CORR_EVIDENCE_TOPICS` lane is subscribed | `corr_evidence_topic_dropped{topic,reason}` | Gauge only exists while a lane is dropped | watch | A: `CorrEvidenceLaneNotGrounded` **NEW** |
| **correlation** (engine internals) | Loop not starved; window not evicting; batches landing | `corr_loop_lag_stalls_total`, `corr_window_signals`, `corr_signal_batch_pending` | Counter-based (`increase`), silent when idle | watch | A: `CorrelationEventLoopStalling`, `CorrWindowBufferNearCap`, `CorrSignalBatchBacklog`, `CorrSignalRowsQuarantined`, `CorrelationRebalanceChurn`, `CorrelationWindowStaysCold`, `CorrelationReplicaIdle` |
| **vector-router** | All 9 `netops-router-*` groups joined and draining bus → OpenSearch/ClickHouse | `kafka_consumergroup_members{consumergroup=~"netops-router-.*"}` | Membership is independent of traffic volume — a joined consumer on an empty topic still reports members | **page** | A: `RouterConsumerDead` **NEW**, `RouterConsumerLagGrowing` **NEW** · B: watchdog router probe **NEW** |
| **vector-aggregator** | Every non-flow lane (syslog, traps, collector metrics, probes, applogs) reaches the bus | `vector_component_sent_events_total{component_kind="sink"}` @ `vector-aggregator:9598` | **`collector_targets_reachable > 0`** — an independent producer must confirm data exists to carry. On an idle lab this is `0` and the rule is silent *by design* | **page** | A: `IngestPipelineSilent` **NEW** |
| **vector** (both) | No events discarded, no component erroring, sink buffers not filling | `vector_component_discarded_events_total{intentional="false"}`, `vector_component_errors_total`, `vector_buffer_events` | `increase(...) > 0` — silent when idle | watch | A: `VectorEventsDiscarded`, `VectorComponentErrors`, `VectorSinkBufferFilling`, `VectorOpenSearchRetryStorm`, `VectorDeadLetters`, `VectorQuarantineSealFailures` |
| **api** (collectors) | SNMP/tunnel collectors reach targets and produce samples | `collector_up`, `collector_targets`, `collector_targets_reachable`, `collector_samples`, `collector_poll_duration_ms` | `and collector_targets > 0` — no configured devices, no alert | watch | A: `CollectorDown`, `CollectorTelemetryMissing`, `CollectorAllTargetsUnreachable`, `CollectorPartialReachability`, `NoSamplesIngested`, `CollectorPollSlow` |
| **api** (serving) | Answers on `:8000` with a non-empty body | `up{job="netops-api"}` | Always expected | **page**-equivalent | A: `ScrapeTargetDown` · B: `check_api_liveness` (`API_UNRESPONSIVE`) |
| **api** (security lane) | Findings emitted, not dead-lettered | `netops_security_findings_emitted_total`, `netops_security_dead_lettered_total`, `netops_security_lost_total` | Counter-based | watch | Flag-gated (`FEATURE_SECURITY_LANE`); metrics exist, no dedicated rule |
| **kafka** | Partitions have leaders and in-sync replicas; consumers can commit | `kafka_brokers`, `kafka_topic_partition_in_sync_replica`, `kafka_consumergroup_current_offset_sum` | Offset-advance rules gate on `lag > 100` | watch → **page** via the consumer rules | A: `KafkaConsumerStalled`, `KafkaConsumerLagGrowing`, `KafkaConsumerLagHigh`, `KafkaLagMetricsMissing` · C: TCP accept on 9092 |
| **kafka-exporter** | Exports consumer-group series at all | `absent(kafka_consumergroup_lag_sum)` | Optional `self-monitoring` profile — the watchdog reports a **named skip**, never a pass, when it is not running | watch | A: `KafkaLagMetricsMissing` · B: named-skip branch **NEW** |
| **opensearch** | Cluster not red; documents accepted, not rejected; indexing advancing | `opensearch_cluster_status`, `opensearch_indexing_doc_status{code}`, `opensearch_indexing_index_failed` — **polled by vector, not by a scrape job**, so there is deliberately no `up{job="opensearch"}` (see G1) | `LogIngestRateDegraded` self-baselines over 6 h with a `> 100` floor — **median**, not mean (2026-09-03: a restart's catch-up spike poisoned a mean baseline and held a false CRITICAL for ~4 h) | **page** | A: `OpenSearchClusterRed`, `OpenSearchFloodStageBlock`, `OpenSearchDocumentsRejected`, `OpenSearchRejectionRatioHigh`, `LogIngestStalled`, `OpenSearchStatsMissing` (the meta-alert for the lane itself disappearing) |
| **clickhouse** | Accepts write batches; queries not failing; memory bounded | `netops_clickhouse_write_outcomes_total{outcome="rejected"}`, `ClickHouseProfileEvents_*`, `up{job="clickhouse"}` | `increase(...) > 0` | **page** | A: `ClickHouseWritesRejected` **NEW**, `CHMemoryLimitExceeded`, `CHFailedQueriesRising`, `StorageBackendDown`, `StorageExporterAbsent` **NEW** · B: `check_clickhouse_health` |
| **victoria** | Ingesting rows; series cardinality stable; fast path holding | `vm_rows_inserted_total`, `vm_slow_row_inserts_total`, `vm_cache_entries` | Ratio-based | watch | A: `VMSlowInsertRatioHigh`, `VMActiveSeriesSurge`, `ScrapeTargetDown`, `StorageBackendDown`, `StorageExporterAbsent` **NEW** · B: telemetry-freshness probe |
| **vmalert** | Evaluating rules **and delivering** them | `netops_alert_webhook_heartbeat_timestamp_seconds` (end-to-end, **NEW**) | Gated on `netops_alert_webhook_enabled == 1` — delivery switched off on purpose is not "broken" | **page** | A: `AlertingHeartbeat` **NEW** + `AlertDeliveryBroken` **NEW** · B: watchdog heartbeat probe **NEW** · C: `/health` on 8880 |
| **prober** | Synthetic probes keep arriving at the engine | `corr_ingest_events{counter="probes_received"}` — **no `prober` scrape job exists**, so the lane is only observable at the engine end | **Trailing-24h activity** (`increase(...[24h]) > 0`). The original premise here — "the prober ticks 24/7, so a flat line is unambiguous" — was **FALSE and is corrected**: `prober` is a compose *profile* whose `FEATURE_ACTIVE_PROBE` / `FEATURE_SYNTHETICS` / `FEATURE_WAN_ECHO` default `false` with empty `*_TARGETS`, so a lab with no probe targets is legitimately silent and was paging for it | **page**-equivalent | A: `CorrProbeLaneFlatlined` (guarded 2026-09-03; annotations name "engine not consuming" first). Cold-start blind spot (an install that has never had a probe) is covered by `CorrelationConsumerDead` + the watchdog consumer probe, which read Kafka group membership rather than lane traffic |

## Tier-2 — supporting services. Failure degrades, it does not lose data.

| Service | Doing its job means | Proof metric | Tier | Covered by |
|---|---|---|---|---|
| **postgres** | Serving app-state queries | **no exporter, no scrape job, no metric.** Proven today ONLY by the container's `pg_isready` healthcheck and the watchdog's compose service loop. `StorageBackendDown` does **not** cover it (G1) and no longer pretends to | watch | C: `pg_isready` healthcheck · B: service loop (`postgres: not running` / `health=`) |
| **redis** | Serving cache/session ops | **no exporter, no scrape job, no metric.** Same as postgres: container healthcheck + watchdog service loop only | watch | C: healthcheck · B: service loop |
| **nginx** | Fronting `:8000` | indirect: `up{job="netops-api"}` + the watchdog's `:8000` probe | watch | B: `api_probe_once` |
| **frontend** | Serving the SPA bundle | indirect: the `:8000` probe returns a non-empty body | watch | B: `api_probe_once` · C: healthcheck |
| **syslog-ng** | Accepting syslog on 514 (TCP **and** UDP) and forwarding to the aggregator | indirect: `vector_component_received_events_total{component_id="syslog_in"}`; `check_syslog_udp_drops` | watch | B: UDP-drop probe · C: socket-level healthcheck **NEW** — TCP connect to :514 + UDP socket bound (G3, fixed) |
| **gnmic** | Streaming gNMI telemetry | **none scraped** — see gap G2 | watch | C: container only |
| **goflow2** | Receiving NetFlow/sFlow → `netops.flows.raw` | indirect: `vector_component_received_events_total{component_id="kafka_flows_raw"}` on the router | watch | A: indirect via router lanes · C: container only |
| **keycloak** | Issuing SSO tokens | **none scraped** | watch | C: healthcheck (`sso` profile) |
| **vmauth** | Proxying VM read/write with per-service creds | **none scraped** | watch | C: container (`vmauth` profile) |
| **secrets-seal** | Serving the KEK to the api | `netops_tls_*`, vault errors in the api | watch | C: healthcheck (`seal` profile) |
| **grafana / opensearch-dashboards** | Rendering dashboards | `up{job="grafana"}`; OSD none | watch | A: `ScrapeTargetDown` (grafana) · C: healthcheck |
| **cadvisor / node-exporter** | Supplying container/host metrics that ~20 other rules depend on | `container_last_seen`, `node_*` | watch | A: `ContainerMetricsMissing` (meta-alert) |
| **telegraf** | Retired — `legacy` profile, not started | n/a | n/a | deliberately excluded from `EXPECTED_SERVICES` |

**Every container**, tier-1 and tier-2 alike, additionally gets `ContainerDown`,
`ContainerRestartLoop`, `ContainerOOMKilled`, `ContainerMemoryNearLimit` and
`ContainerCPUSaturated` from cadvisor. That is the floor.

---

## Known gaps (honest, not aspirational)

| # | Gap | Consequence | Status |
|---|---|---|---|
| **G1** | `StorageBackendDown` selected `up{job=~"opensearch\|clickhouse\|victoria\|postgres\|redis"}` but only `clickhouse` and `victoria` are real job names (checked in **both** `vmscrape.yml` and `vmscrape-mtls.yml`). The other three matched nothing, so the rule read three stores broader than it was. | the rule *looked* like coverage that did not exist — same class as the blackholed notifier | **FIXED 2026-09-02.** Selector narrowed to the jobs that exist; `StorageExporterAbsent` **NEW** added as the meta-alert for a scrape job disappearing (`up == 0` cannot fire when there is no `up` series). Regression-tested in `rules-tests/storage-backend-coverage.test.yaml`, including a case that fails if the selector is widened back. **Residual:** postgres and redis still have no exporter — that is now *stated* in their rows above rather than implied away. Adding exporters remains a separate change. |
| **G2** | gnmic and goflow2 expose no scraped metrics, so "is it collecting?" is only answerable indirectly (downstream lane volume). | a silently-collecting-nothing gNMI target is invisible | Not fixed here |
| **G3** | `syslog-ng` inherited the **image's** baked-in healthcheck (`syslog-ng-ctl healthcheck --timeout 5`), which fork/execs the vendor CLI to round-trip the control socket. It was observed `unhealthy` on 2026-09-02 (~22:55Z) and healthy again shortly after; **the cause was not captured** — Docker keeps only the last 5 health-log entries and all five were exit 0 by the time it was inspected. The structural problem stands regardless of that one event: a probe that spawns processes fails whenever the container cannot fork, which this stack has already suffered (ClickHouse at pids.max, 2026-08-15, `healthy`→`unhealthy` while serving perfectly — the reason `check_pid_capacity` exists). On the ingest EDGE a false `unhealthy` sends an operator to restart the thing devices are logging to. | false `unhealthy` indistinguishable from real failure | **FIXED 2026-09-02.** Replaced with a socket-level probe: a `/dev/tcp` connect to :514 (bash builtin, no second binary fork/exec'd) plus a `/proc/net/udp`+`udp6` bound-socket check for the UDP lane, which cannot be connect-tested. Uses `CMD` + explicit `bash` because `/bin/sh` in this image is **dash** and has no `/dev/tcp` (verified). Verified live against the running container including negative controls (unlistened TCP port and unbound UDP port both fail). |
| **G5** | On TLS installs the external watchdog probed OpenSearch at `https://localhost:9200`, but the wire cert's SANs are `DNS:opensearch` + the SPIFFE URI — **no `localhost`** — so every OpenSearch check failed hostname verification (curl exit 60) and reported `OPENSEARCH_UNVERIFIABLE`, "BLIND this run", on every run since the TLS cutover. | the entire search tier was unwatched by the one layer that survives the stack dying, and the log said "TLS/auth mismatch?" — a guess, not a diagnosis | **FIXED 2026-09-03.** Probe host changed to `opensearch` (in-SAN, resolves via compose DNS); **never** `-k`. Added an evidence-keyed self-test that classifies a blind result as TLS_HOSTNAME / TLS_CA / AUTH / UNREACHABLE / UNCLASSIFIED from the curl exit code and HTTP status instead of guessing. Regression-tested in `tests/test_watchdog_transitions.py`. **Unblinding it immediately surfaced two real, previously invisible problems — see below.** |
| **G4** | The `notify` package has no digest/rollup channel, so the `watch` tier surfaces on the status boards and in `ALERTS`, but is not mailed as a daily summary. | warning-tier findings need someone to look | Noted; a digest channel would be a `notify/` change |

## Deliberate non-goals

* **No new custom probes.** The watchdog gained exactly three checks (two
  consumer-group, one heartbeat). Everything else reuses metrics that already
  existed.
* **No rule per service.** One rule *pattern* per lane, parameterised with
  `by (consumergroup)` / label selectors, so a lane added tomorrow is covered
  without anyone remembering to write a rule.
* **No paging on tier-2.** A degraded dashboard is not worth a 3 a.m. phone
  call, and pretending otherwise is how the pager gets muted.

## Surfaced by this work (pre-existing, owner attention)

Unblinding the checks above turned up conditions that were real the whole time
and simply had nothing watching them. None is caused by this change:

* **The newest OpenSearch snapshot is `PARTIAL`** — some shards were not
  captured, so a restore from it would be incomplete. The backup exists; it is
  not a backup you can rely on.
* **`docker-hygiene` cron has been dead for 17 days** with the disk at **90%**.
  OpenSearch sets every index read-only at 95% and ingestion stops with no
  error (`OpenSearchFloodStageBlock`, and the 2026-06-10 outage mode).
* **The api reports no git SHA** — it was built without `GIT_SHA`, so the
  build-drift check cannot tell which source the running binary came from.
