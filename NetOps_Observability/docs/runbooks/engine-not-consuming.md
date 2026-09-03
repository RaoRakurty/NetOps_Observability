# Runbook — "the engine is not consuming"

**Symptom class:** a pipeline service is *running and healthy* and is *doing no
work*. Nothing is obviously broken. The UI shows an honestly empty incident
list, which reads as "a quiet network".

**Alerts that route here:** `CorrelationConsumerDead`, `CorrelationLagGrowing`,
`CorrConsumerNotRunning`, `CorrConsumerRestartLoop`, `RouterConsumerDead`,
`RouterConsumerLagGrowing`, `IngestPipelineSilent`, `ClickHouseWritesRejected`,
`AlertDeliveryBroken`, `CorrEvidenceLaneNotGrounded`, `CorrProbeLaneFlatlined`.

---

## 1. What happened on 2026-09-02 (why this file exists)

Between **19:04 and 22:10 UTC the correlation engine's Kafka consumer never
started.** Its `subscribe()` raised `TopicAuthorizationFailedError` and then
`UnknownTopicOrPartitionError` on the **optional** `netops.security` topic, and
that abandoned the *whole* 14-topic subscription. For three hours the engine
correlated nothing.

Every control that should have caught it was green:

| Control | What it said | Why it was wrong |
|---|---|---|
| container healthcheck | `healthy` | It polls the `:8094` sidecar, a daemon **thread** that outlives the consumer *by design* (tracker 174: a busy loop must not read as a dead service). |
| `scripts/stack-watchdog.sh` | green | It checked services running/healthy, `:8000`, and api liveness. None of those distinguishes *running* from *doing work*. |
| `vmalert` | `CorrProbeLaneFlatlined` fired at 19:18 | Delivered **nowhere**. vmalert shipped with `-notifier.blackhole`; 13 alerts were firing, some since 2026-08-27, and not one had ever been delivered. |

`kafka-exporter` had the proof in VictoriaMetrics the entire time —
`kafka_consumergroup_members{consumergroup="netops-correlation"}` was `0` and
the group's lag climbed to ~23k — and **no rule read it**.

A near-identical incident on **2026-08-16** hit `vector-router` *and*
correlation for ~80 minutes: a `data/kafka` wipe emptied the KRaft ACL store,
every non-super-user principal was denied, lag froze, and every container
stayed `healthy`.

**The lesson, in one line:** *"the container is up" and "the process is
consuming" are different claims, and only the second one matters.*

---

## 2. The three layers that now cover it

Each layer works **without the other two**. That is the design requirement, not
a nicety — the 2026-09-02 outage is what one-layer coverage looks like.

| # | Layer | Where | Fails when | Independent of |
|---|---|---|---|---|
| 1 | **vmalert rules** | `src/config/rules-scale-slo.yaml`, group `engine-liveness` | rules are wrong, or vmalert is down | the api |
| 2 | **Delivery** | vmalert `-notifier.url` → `POST /api/internal/vmalert/api/v2/alerts` → `notify.Dispatcher` | the api is down, or the token is wrong | — (this is the layer that was missing entirely) |
| 3 | **External watchdog** | `scripts/stack-watchdog.sh`, `ENGINE_CONSUMER_CHECK` block → ntfy | the host is dead (healthchecks.io dead-man's-switch catches that) | **the whole stack**, including its own alerting |

Layer 3 exists because *a stack cannot report its own death*. It queries
VictoriaMetrics directly and pages over ntfy, which is deliberately not one of
the platform's own notifiers.

### The heartbeat (how layer 2 proves itself)

`AlertingHeartbeat` fires **always** (`expr: vector(1)`, `severity: info`,
`tier: heartbeat`). The api's receiver recognises it by name, records the
arrival time in `netops_alert_webhook_heartbeat_timestamp_seconds`, and
deliberately does **not** fan it out to any channel — a heartbeat on your phone
every 30 minutes is pure noise.

A fresh timestamp is end-to-end proof of
`vmalert evaluates → notifier delivers → api receives`. **Its absence is the
alarm**, and it is checked in two independent places: `AlertDeliveryBroken`
(in-stack) and the watchdog (over its own channel — because an alert about
broken alert delivery obviously cannot rely on alert delivery).

### Where an alert goes (two audiences, two routes)

| Alert class | Route | Destination | Depends on |
|---|---|---|---|
| **Platform self-health** — everything vmalert sends through the receiver (layers stack/host/clickhouse/platform, the four page conditions, the warning tier) | `internal/alertwebhook` host route | the **host-monitoring ntfy topic** — the same phone channel `scripts/stack-watchdog.sh` uses (`PLATFORM_ALERTS_NTFY_TOPIC`, default `WATCHDOG_NTFY_TOPIC`) | nothing but the topic. It works on an install with **no** notification channel configured, because it is how the stack reports on itself |
| **Product / tenant** — monitor rules, BGP watch, per-tenant security findings | `notify.Dispatcher` | the channels configured in Settings → Notification channels | operator configuration; still **refuses** the watchdog topic (watchdog independence, #101) |

Tier → push priority on the host route: `tier: page` → **high**, everything
else firing → **default**, a resolution → **low**. The `AlertingHeartbeat` is
**never** pushed — it exists for the freshness probe, and a heartbeat on the
phone every 30 minutes is how a pager gets muted. Delivery is counted in
`netops_alert_webhook_pushed_total{route="host_monitoring",tier}` and
`netops_alert_webhook_push_failures_total{route,reason}`
(`reason="not_configured"` means no topic is set — see
`netops_alert_webhook_host_route_enabled`).

Platform alerts still reach the product dispatcher as well, unchanged; the host
route is an **additional** destination, sharing the same cool-down, so nothing
buzzes twice.

**Warnings do not buzz individually (2026-09-03).** ntfy.sh's free public server
rate-limits per topic/IP and started answering `429` here while chronic warnings
were each spending a push — budget a real page needs. The `page` tier and the
resolution of a page stay immediate (and a page now retries on 429/5xx with
capped backoff + jitter, honouring `Retry-After`); everything else is folded
into a **digest** sent at most once per
`PLATFORM_ALERTS_WARNING_DIGEST_INTERVAL` (default `30m`), including any warning
that resolved inside the window. An hourly token budget
(`PLATFORM_ALERTS_PUSH_BUDGET`, default 30) reserves
`PLATFORM_ALERTS_PUSH_BUDGET_PAGE_RESERVE` (default 10) tokens that only a page
may spend. So a *missing* warning push within the window is expected behaviour,
not a delivery fault — see `netops_alert_webhook_digest_alerts_total` and
`docs/runbooks/engine-liveness-matrix.md` for the full per-tier table.

---

## 3. Triage — in this order

> **Did a deploy just add or change a lane?** Then start at
> [`upgrade-bootstraps.md`](upgrade-bootstraps.md) instead. A lane can be
> *silent* rather than *stalled*: on 2026-09-03 the security-findings lane wrote
> nothing because `netops-secfindings-*` was missing from the `netops_writer`
> OpenSearch role — every bulk write 403'd on `indices:admin/create`, Vector
> dropped the batch as non-retriable, and there was no lag, no rejected-doc
> counter and no red healthcheck to see. That file lists every bootstrap an
> upgraded stack must re-run (Kafka ACLs, kafka-init, opensearch-security-init,
> index templates, ISM) and the one-command read-only audit
> (`bash scripts/bootstrap-opensearch.sh --verify`).

### 3.1 Is it consuming? (30 seconds, no guessing)

```bash
# Broker's view: does the group have members? 0 = not consuming.
docker exec "$(docker ps -qf label=com.docker.compose.service=victoria)" \
  wget -qO- --timeout=5 \
  'http://127.0.0.1:8428/api/v1/query?query=kafka_consumergroup_members'

# Ground truth from the broker itself (works with no exporter):
docker compose -f deployment/docker/docker-compose.yml exec kafka \
  /opt/kafka/bin/kafka-consumer-groups.sh --bootstrap-server localhost:9092 \
  --describe --group netops-correlation
```

Read `--describe` carefully:

* **`Consumer group has no active members`** → the consumer is not joined.
  Continue to §3.2.
* **members present, `LAG` large and not falling** → joined but not draining.
  Go to §3.4.
* **`CURRENT-OFFSET` blank / `-`** → the group has never committed. This is a
  first-boot or post-wipe bootstrap problem: §3.3.

### 3.2 Why did the subscription fail?

```bash
docker compose -f deployment/docker/docker-compose.yml logs --tail=200 correlation \
  | grep -Ei 'TopicAuthorizationFailed|UnknownTopicOrPartition|GroupAuthorizationFailed|subscribe'
curl -s localhost:8000/../healthz   # or: docker exec <correlation> wget -qO- 127.0.0.1:8094/healthz
```

`/healthz` now carries `status`, `health_reasons` and `consumer.subscription`,
and the engine exports `corr_consumer_running`,
`corr_consumer_start_failures_total`, `corr_consumer_restarts_total` and
`corr_evidence_topic_dropped{topic,reason}`. **These name the exact topic and
error.** Two shapes:

* **authorization** (`TopicAuthorizationFailedError`) → §3.3, ACLs.
* **missing topic** (`UnknownTopicOrPartitionError`) → §3.3, `kafka-init`.
  Broker auto-create is **OFF by design** (SEC-006.1), so a missing topic never
  fixes itself.

> Since the 2026-09-02 fix, an **optional** `CORR_EVIDENCE_TOPICS` lane failing
> no longer takes the subscription down: it is dropped, re-probed, and reported
> via `corr_evidence_topic_dropped` / `CorrEvidenceLaneNotGrounded` (warning,
> not a page). Only a **REQUIRED** lane is fatal.

### 3.3 Bootstrap: ACLs and topics

Both are **idempotent** — safe to re-run, safe after every rebuild, and safe
after a `data/kafka` wipe (which is exactly when they are needed, because the
KRaft ACL store *is* the authorization state and a wipe empties it).

```bash
cd deployment/docker

# 1. ACL matrix. The script lives in the repo, not in the image; on a non-TLS
#    lab broker there is no /acls mount, so PIPE it in rather than exec a path
#    that may not exist.
docker compose exec -T kafka sh -s < kafka/apply-acls.sh
#    (TLS deployments: it auto-detects /tmp/kafka-tls/admin.properties and uses
#     the mTLS listener kafka:9094. install.py runs it after TLS phase B.)

# 2. Canonical topics. kafka-init is a `restart: "no"` one-shot in the
#    embedded-bus profile; re-running it re-creates nothing that exists.
docker compose --profile embedded-bus up kafka-init

# 3. Verify — the ONLY step that proves anything.
docker compose exec kafka /opt/kafka/bin/kafka-consumer-groups.sh \
  --bootstrap-server localhost:9092 --describe --group netops-correlation
docker compose exec kafka /opt/kafka/bin/kafka-topics.sh \
  --bootstrap-server localhost:9092 --list | grep '^netops\.'
```

Then let the consumer re-join (the supervisor retries on its own). **Restarting
the container is not the remedy** — without the bootstrap it reproduces the
same failure in a fresh process, which is what `CorrConsumerRestartLoop`
detects.

The full principal matrix (who may produce/consume what, and why goflow2 is
`ANONYMOUS`) is in the header of `deployment/docker/kafka/apply-acls.sh`.

### 3.4 Joined but not draining

Membership is not liveness. Work down in this order:

1. `corr_loop_lag_stalls_total` / `corr_loop_lag_max_ms` — event-loop
   starvation (`CorrelationEventLoopStalling`; known residual ~1.0–1.3 s,
   tracker 156).
2. Downstream persistence — `ClickHouseWritesRejected`,
   `CorrSignalRowsQuarantined`, `OpenSearchDocumentsRejected`,
   `VectorSinkBufferFilling`, `OpenSearchClusterRed`.
3. Per-partition lag skew — one hot tenant pins one partition, and more
   partitions will not move it.
4. `corr_consumer_revoke_commits_total{outcome!="ok"}` — rebalance churn.

**Do not** raise session/heartbeat/max-poll timeouts. That converts a visible
backlog into a silent one.

### 3.5 Alert delivery itself

```bash
# Is the receiver configured and being fed?
docker exec "$(docker ps -qf label=com.docker.compose.service=victoria)" \
  wget -qO- --timeout=5 \
  'http://127.0.0.1:8428/api/v1/query?query=netops_alert_webhook_enabled'
docker exec "$(docker ps -qf label=com.docker.compose.service=victoria)" \
  wget -qO- --timeout=5 \
  'http://127.0.0.1:8428/api/v1/query?query=time()-netops_alert_webhook_heartbeat_timestamp_seconds'

# What does vmalert think it is doing?
docker compose exec vmalert wget -qO- 127.0.0.1:8880/api/v1/alerts
docker compose logs --tail=50 vmalert | grep -i notifier
```

| Reading | Meaning | Fix |
|---|---|---|
| `netops_alert_webhook_enabled` absent | api predates the receiver, or is not scraped | upgrade / check the `netops-api` scrape job |
| `enabled == 0` | `VMALERT_WEBHOOK_TOKEN` unset → route not registered (fail-closed, by design) | set it in `deployment/docker/.env`; `scripts/install.py` generates it |
| `vmalert` will not start, compose says `environment variable "VMALERT_WEBHOOK_TOKEN" required by secret … is not set` | since D-16 (2026-09-03) the token reaches vmalert as a compose **secret file** (`-notifier.basicAuth.passwordFile=/run/secrets/vmalert_notifier_password`), not in the url userinfo — argv is disclosed verbatim by `docker inspect`. Compose refuses to materialise a secret from an unset variable, and says which one. | set `VMALERT_WEBHOOK_TOKEN` in `deployment/docker/.env` (`scripts/install.py` mints it on every install) |
| `enabled == 1`, heartbeat stale | vmalert down/wedged, flag reverted to `-notifier.blackhole`, or a token mismatch | check `netops_alert_webhook_unauthorized_total`; compare the token on both sides |
| `netops_alert_webhook_host_route_enabled == 0` | no host-monitoring topic: platform alerts reach the configured product channels only, and an install with none configured is silent | set `PLATFORM_ALERTS_NTFY_TOPIC` (or `WATCHDOG_NTFY_TOPIC`) in `deployment/docker/.env` |
| `netops_alert_webhook_push_failures_total{reason="send_error"}` rising | the ntfy server/token is wrong, or ntfy is unreachable from the api | check the api log line `platform alert push to host monitoring FAILED` (it never carries the topic) |
| `..._push_failures_total{reason="rate_limited"}` rising | the ntfy server is refusing (429) even after the bounded retry ladder — the free public server limits per topic/IP | check `netops_alert_webhook_push_retries_total`; move to a self-hosted/paid ntfy, or lengthen `PLATFORM_ALERTS_WARNING_DIGEST_INTERVAL` |
| `..._push_failures_total{reason="budget_exhausted"}` rising | *we* refused locally: the hourly push budget is spent. Warnings stop at the page reserve; only a `tier="page"` refusal is logged at ERROR | inspect `netops_alert_webhook_push_budget_remaining` (`-1` = guard disabled); raise `PLATFORM_ALERTS_PUSH_BUDGET` only after confirming the server itself is not rate-limiting |
| `netops_alert_webhook_push_budget_remaining` pinned at the reserve | normal under a warning storm — warnings are being held back so a page can still go out | nothing; confirm with `netops_alert_webhook_digest_alerts_total` |

To deliberately turn delivery off, set
`VMALERT_NOTIFIER_FLAG=-notifier.blackhole` — that is the supported opt-out and
it makes `AlertDeliveryBroken` silent rather than lying.

---

## 4. Prevention

* **`scripts/deploy-qualify.sh`** — run it after every `compose up`. It runs the
  bootstraps above and then *proves* the consumers joined, lag is draining, the
  aggregator and router are emitting, and no `TopicAuthorizationFailedError` /
  `UnknownTopicOrPartitionError` appears in the engine or router logs.
  `docker compose up` exiting 0 is not evidence of anything.
* **`docs/runbooks/engine-liveness-matrix.md`** — what "doing its job" means for
  every service, the metric that proves it, and which layer covers it.
* **`docs/runbooks/upgrade-bootstraps.md`** — the bootstraps an UPGRADED stack
  must re-run when a deploy adds a lane, and `deploy-qualify.sh`'s B4 audit that
  a lane is actually writable. A lane whose OpenSearch role was never updated is
  silent, not stalled: none of the consumer/lag checks above will see it.
* Never wipe `data/kafka` without re-running §3.3 immediately afterwards.
