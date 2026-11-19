# Streaming bus (Apache Kafka)

> Reviewed against the code 2026-11-19. The topic list is
> `deployment/docker/docker-compose.yml` → `kafka-init`; the consumers are
> `deployment/docker/vector-router/vector.yaml` and `src/correlation/main.py`
> (`LANE_TOPICS`); the ACL matrix is `deployment/docker/kafka/apply-acls.sh`.

Apache Kafka is the platform's central event bus — a single-node broker in
KRaft mode (compose service `kafka`, profile `embedded-bus`). Every record a
device or a collector produces crosses a named `netops.*` topic before it
reaches a store or the correlation engine. External Kafka-compatible brokers
are supported via `BROKER_URLS`.

> **Internal note:** Redpanda was removed from the product entirely on
> 2026-07-03 (BSL licensing — not redistributable in customer bundles). It must
> not be recommended to customers; the embedded bus is Apache Kafka.

## Topics

`kafka-init` (a one-shot) creates 22 topics, all with `BUS_PARTITIONS`
partitions (default 1; every topic must share the count — see
`docs/scale-correlation.md`) and replication factor 1. The main lanes:

| Topic | Producer | Consumers |
|---|---|---|
| `netops.syslog` | vector-aggregator (from the syslog-ng edge) | vector-router → OpenSearch (`netops-syslog-*`, and routine management sessions → `netops-syslogroutine-*`); correlation engine |
| `netops.syslog.control` | vector-aggregator (the admitted subset) | nobody yet (the engine can switch to it with `CORR_SYSLOG_TOPIC`) |
| `netops.snmptrap` | vector-aggregator | vector-router → OpenSearch; correlation engine |
| `netops.flows.raw` | goflow2 (native `kafka://` transport) | vector-router (re-keys by exporter tenant) |
| `netops.flows` | vector-router (re-keyed) | vector-router → OpenSearch + ClickHouse `netops.flows`; correlation engine |
| `netops.metrics` | vector-aggregator / collectors | correlation engine only — the router does NOT consume it; metrics reach VictoriaMetrics on their own path |
| `netops.applogs` | vector-aggregator (container logs) | vector-router → OpenSearch |
| `netops.probes`, `netops.cloud`, `netops.controller_events`, `netops.app.edge`, `netops.app.identities.v1`, `netops.verification`, `netops.wireless_sessions`, `netops.wireless_events` | the api's collectors, the prober and the integrations (directly or via the aggregator's HTTP ingest sources) | correlation engine |
| `netops.cloudlogs`, `netops.cloudcosts`, `netops.experience`, `netops.security.audit`, `netops.deadletter` | the api / aggregator lanes | vector-router → OpenSearch or ClickHouse |
| `netops.security` | the api's security findings | vector-router → OpenSearch (`netops-secfindings-*`); correlation engine (optional evidence class) |
| `netops.bgp` | the api's BGP watch (`internal/bgpwatch`) | correlation engine (optional evidence class) |

Retention is bounded broker-wide with `BUS_RETENTION_MS` (72 h) and
`BUS_RETENTION_BYTES` (512 MiB per partition), whichever runs out first. Never
shrink Kafka retention to buy disk: it is the buffer that turns a storage block
into delay instead of loss.

## Why a bus at all

* **Storage outages absorb at the bus.** OpenSearch blocked or ClickHouse
  refusing writes? The router's sinks back-pressure, offsets stop committing,
  the producers keep producing, and nothing is lost while retention lasts.
* **Replay is an offset reset** within the retention window.
* **Fan-out.** The router (storage) and the correlation engine read the same
  lanes independently.

## Connecting to the broker

The broker listens only inside the compose network (`kafka:9092`; no host
ports). Every client resolves it via `BROKER_URLS` (default `kafka:9092`):

```
docker compose exec kafka /opt/kafka/bin/kafka-topics.sh \
  --bootstrap-server localhost:9092 --list
```

Producers and consumers are authorised per principal by the ACL matrix
(`apply-acls.sh`; `deploy-qualify.sh` B1 verifies it). To attach outside
consumers (a SIEM, a data lake), point the stack at an external
Kafka-compatible cluster via `BROKER_URLS`.

## Operational notes

* **Memory.** `KAFKA_MEM_LIMIT` (1g) with a 512M JVM heap by default.
* **Persistence.** `data/kafka/`; survives `docker compose down` (not `-v`).
* **Liveness.** Consumer groups (`netops-correlation`, `netops-router-*`) are
  watched by the page-tier rules in `src/config/rules-scale-slo.yaml` and by
  `scripts/stack-watchdog.sh`; see `docs/runbooks/engine-not-consuming.md`.
