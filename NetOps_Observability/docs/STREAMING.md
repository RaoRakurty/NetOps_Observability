# Streaming bus (Redpanda)

Redpanda is the platform's central event bus. Every signal — device
syslog, SNMP metrics, flow records, application logs — flows through a
named topic before reaching its storage tier.

## Topics

| Topic            | Producer            | Consumers                              |
|------------------|---------------------|----------------------------------------|
| `netops.applogs` | vector-aggregator   | vector-router (→ OpenSearch), correlation |
| `netops.syslog`  | vector-aggregator   | vector-router (→ OpenSearch), correlation |
| `netops.metrics` | vector-aggregator   | vector-router (→ VictoriaMetrics), correlation |
| `netops.flows`   | vector-aggregator   | vector-router (→ OpenSearch + ClickHouse), correlation |

Topics are auto-created by Redpanda on first produce. The retention
defaults are reasonable for the scaffold (one week, segment.bytes=1GB);
tune them per workload via `rpk topic alter-config`.

## Why a bus at all

Without Redpanda, every signal would flow directly from the aggregator
to its storage backend — and any storage outage would drop ingestion.
With the bus in front:

* **Storage outages absorb at the bus.** OpenSearch down for 30 minutes?
  Vector-router falls behind on offsets, Vector-aggregator keeps
  producing, no data lost.
* **Replay is one offset reset.** Want to backfill a new ClickHouse
  rollup from yesterday's flow data? `rpk consume --offset start
  netops.flows | clickhouse-client --query="INSERT INTO ..."`
* **Multi-consumer fan-out is free.** Want to send a copy of every
  syslog event to a SIEM, a data lake, and the correlation engine all
  at once? Add the consumer; producers don't know or care.

## Connecting external consumers

Redpanda exposes its Kafka API on the host at port 19092 (configurable
via `REDPANDA_KAFKA_PORT` in `.env`). Any Kafka client works:

```
# From the host
docker compose exec redpanda rpk topic list
docker compose exec redpanda rpk topic consume netops.syslog --offset start --num 10

# From your laptop with kafkacat
kcat -b localhost:19092 -t netops.flows -C -o -10
```

## Operational notes

* **Memory.** Redpanda runs with `--memory 512M` in the scaffold —
  enough for the topic load described above. Bump for higher volume.
* **Persistence.** All topics persist to `data/redpanda/`. Surviving
  `docker compose down` (not `-v`) is automatic.
* **Auth.** None in the scaffold. Production deployments should enable
  SASL/SCRAM via `--sasl-enable` and rotate the broker credentials via
  `rpk acl user create`.
* **Schemas.** Redpanda's Schema Registry is enabled on host port 18082.
  No schemas registered yet — when you formalize the per-topic event
  shapes, register them here.
