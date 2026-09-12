# Streaming bus (Apache Kafka)

Apache Kafka is the platform's central event bus — a single-node
broker in KRaft mode (compose service `kafka`, profile `embedded-bus`).
Every signal — device syslog, SNMP metrics, flow records, application
logs — flows through a named topic before reaching its storage tier.

> **Internal note:** Redpanda was removed from the product entirely on
> 2026-07-03 (BSL licensing — not redistributable in customer bundles).
> It is not part of customer distribution and must not be recommended
> to customers; the embedded bus is Apache Kafka, and external
> Kafka-compatible brokers are supported via `BROKER_URLS`.

## Topics

| Topic            | Producer            | Consumers                              |
|------------------|---------------------|----------------------------------------|
| `netops.applogs` | vector-aggregator   | vector-router (→ OpenSearch), correlation |
| `netops.syslog`  | vector-aggregator   | vector-router (→ OpenSearch), correlation |
| `netops.metrics` | vector-aggregator   | vector-router (→ VictoriaMetrics), correlation |
| `netops.flows`   | vector-aggregator   | vector-router (→ OpenSearch + ClickHouse), correlation |

Topics are pre-created by the one-shot `kafka-init` service (all
netops.* topics, 1 partition, replication factor 1). Retention is
bounded broker-wide via `BUS_RETENTION_MS` / `BUS_RETENTION_BYTES` in
`.env`; tune per topic via `kafka-configs.sh --alter`.

## Why a bus at all

Without Kafka, every signal would flow directly from the aggregator
to its storage backend — and any storage outage would drop ingestion.
With the bus in front:

* **Storage outages absorb at the bus.** OpenSearch down for 30 minutes?
  Vector-router falls behind on offsets, Vector-aggregator keeps
  producing, no data lost.
* **Replay is one offset reset.** Want to backfill a new ClickHouse
  rollup from yesterday's flow data? `kafka-console-consumer.sh
  --topic netops.flows --from-beginning | clickhouse-client
  --query="INSERT INTO ..."`
* **Multi-consumer fan-out is free.** Want to send a copy of every
  syslog event to a SIEM, a data lake, and the correlation engine all
  at once? Add the consumer; producers don't know or care.

## Connecting external consumers

The broker listens only inside the compose network (`kafka:9092`; no
host ports are published). Every client resolves it via `BROKER_URLS`
in `.env` (default `kafka:9092`). Any Kafka client works:

```
# From inside the broker container
docker compose exec kafka /opt/kafka/bin/kafka-topics.sh \
  --bootstrap-server localhost:9092 --list
docker compose exec kafka /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 --topic netops.syslog \
  --from-beginning --max-messages 10
```

To attach outside consumers (a SIEM, a data lake, a custom analytics
job), point the stack at an external Kafka-compatible cluster instead:
`install-correlix.sh --external-kafka --broker-urls <host:port,...>`.

## Operational notes

* **Memory.** Kafka runs with a 512M JVM heap inside a 1g container
  cap (`KAFKA_MEM_LIMIT`) in the scaffold — enough for the topic load
  described above. Bump for higher volume.
* **Persistence.** All topics persist to `data/kafka/`. Surviving
  `docker compose down` (not `-v`) is automatic.
* **Auth.** None in the scaffold (the broker is unreachable from
  outside the compose network). Deployments needing SASL/SCRAM or TLS
  should use an external Kafka-compatible cluster via `BROKER_URLS`.
* **Schemas.** No schema registry ships with the stack. The per-topic
  event shapes are documented contracts; when you formalize them,
  register them in a Kafka-compatible schema registry of your choice.
