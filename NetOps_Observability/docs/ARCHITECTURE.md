# Architecture

The platform follows the reference NOC/SOC architecture: dedicated edge
collectors, a Vector aggregation layer, a Redpanda streaming bus, fan-
out to OpenSearch (hot search) + VictoriaMetrics (TS) + ClickHouse
(OLAP), a Python correlation/AI engine, a Go API + GraphQL gateway, and
a React UI with ECharts and an LLM-backed copilot.

```
   Network devices (routers / switches / firewalls)
       │             │             │
    Syslog        SNMP          Flow (NetFlow/IPFIX/sFlow)
       ▼             ▼             ▼
   syslog-ng     Telegraf       goflow2
       │             │             │
       └─────────────┼─────────────┘
                     ▼
       VECTOR AGGREGATOR  (parse, normalize, enrich, buffer)
                     │
                     ▼
       REDPANDA / KAFKA  ─ topics: netops.{syslog, metrics, flows, applogs}
                     │
                     ▼
              VECTOR ROUTER
              │      │      │
              ▼      ▼      ▼
       OpenSearch  Victoria  ClickHouse
       (hot       (SNMP +   (NetFlow analytics,
        search)    telemetry) findings,
                              long-term trends)
              │      │      │
              └──────┼──────┘
                     ▼
       CORRELATION + AI ENGINE  (Python / FastAPI)
       - anomaly detection (rolling z-score)
       - severity-weighted event correlation
       - RCA stubs, automation triggers
                     │
                     ▼
       API + QUERY LAYER  (Go REST + GraphQL gateway + LLM copilot proxy)
                     │
                     ▼
       MODERN UI (React + ECharts + Topology + Copilot)
```

## Tier by tier

### Edge ingestion

Three protocol-specific collectors, each one well-suited to its job and
deliberately not asked to do anything else.

* **syslog-ng** listens on UDP/TCP 514, parses RFC3164 and RFC5424, and
  forwards to vector-aggregator over TCP/6601 with `syslog-protocol`
  framing. Config: `deployment/docker/syslog-ng/syslog-ng.conf`.
* **Telegraf** polls SNMP on the configured device list, emits InfluxDB
  line protocol over TCP/9094 to vector-aggregator's `socket` source.
  Config: `deployment/docker/telegraf/telegraf.conf`.
* **goflow2** decodes NetFlow v5/v9, IPFIX, sFlow and emits one JSON
  record per flow to stdout. Vector picks them up via `docker_logs`.
  Config: `deployment/docker/goflow2/goflow2.yaml`.

The collectors run as separate containers so they can be scaled
independently — a high-flow site can run multiple goflow2 instances
behind a Layer-4 load balancer without affecting syslog or SNMP paths.

### Vector aggregator

`deployment/docker/vector/vector.yaml`. Receives from the three edges,
parses (JSON unpacking on app logs), normalizes (uniform `signal`
field), enriches (device labels), buffers, and produces to four Redpanda
topics:

| Topic              | Source             | Sink (router)                    |
|--------------------|--------------------|----------------------------------|
| `netops.applogs`   | docker_logs        | OpenSearch `netops-applogs-*`    |
| `netops.syslog`    | syslog-ng          | OpenSearch `netops-syslog-*`     |
| `netops.metrics`   | Telegraf           | VictoriaMetrics remote_write     |
| `netops.flows`     | goflow2 (stdout)   | OpenSearch + ClickHouse          |

### Redpanda

Single-node Kafka-API-compatible broker. Provides the decoupling
benefits of a streaming bus (replay, multi-consumer fan-out, ingestion
absorption during storage outages) without a Zookeeper dependency or
JVM tuning. The external Kafka port (host 19092 by default) is exposed
so future producers — a SIEM, a data-lake exporter, a custom analytics
job — can subscribe without touching the aggregator.

### Vector router

`deployment/docker/vector-router/vector.yaml`. Four Kafka consumer
groups, one per topic. Writes:

* App logs and syslog → OpenSearch via `elasticsearch` sink.
* Metrics → VictoriaMetrics via `prometheus_remote_write` sink.
* Flows → both OpenSearch (ad-hoc search) and ClickHouse (analytics).

Decoupling consumers via Kafka means a router restart re-reads from the
consumer-group offset, not from scratch — replay is free.

### Storage tier

* **OpenSearch** — hot search and SIEM. Three rolling indices:
  `netops-applogs-YYYY.MM.DD`, `netops-syslog-YYYY.MM.DD`,
  `netops-flows-YYYY.MM.DD`. Templates are in
  `deployment/docker/opensearch/index-templates.json`; apply with
  `scripts/bootstrap-opensearch.sh`.
* **OpenSearch Dashboards** — power-user UI for ad-hoc exploration,
  served under `/search/`.
* **VictoriaMetrics** — long-term time-series for SNMP + telemetry.
  Scraped by Prometheus on the side for rule evaluation.
* **ClickHouse** — OLAP. Tables: `netops.flows` (raw flow records, TTL
  90 days), `netops.flows_hourly` (materialized rollup for top-talker
  dashboards), `netops.findings` (correlation engine output). Init SQL
  in `deployment/docker/clickhouse/init.sql`.

### Correlation + AI engine

`src/correlation/`. Python 3.12 + FastAPI + aiokafka. Subscribes to
the netops.* topics, runs:

* Per-(device, metric) rolling z-score anomaly detection over a
  200-sample window with threshold 3σ.
* Severity-weighted syslog burst correlation — accumulates per-host
  severity points in a 60-second window and emits a correlation
  finding when the bucket exceeds 30.
* RCA endpoint is a stub — the integration shape is ready (Kafka in,
  ClickHouse out, REST API for the UI), the algorithm is a placeholder.

Writes findings to `clickhouse.netops.findings`; the Findings tab in the
UI renders them as a ranked triage queue.

### API + query layer

Go API at `src/backend/`. Handlers:

| Route                        | Backed by                          |
|------------------------------|------------------------------------|
| `/api/devices`               | in-memory discovery aggregator     |
| `/api/collectors`            | collector pool                     |
| `/api/alerts` / `/rules`     | alert engine                       |
| `/api/logs/search`           | OpenSearch query_string DSL        |
| `/api/logs/indices`          | OpenSearch `_cat/indices`          |
| `/api/flows/top`             | ClickHouse `netops.flows`          |
| `/api/flows/by-proto`        | ClickHouse `netops.flows`          |
| `/api/flows/timeseries`      | ClickHouse `netops.flows`          |
| `/api/findings`              | ClickHouse `netops.findings`       |
| `/api/copilot/chat`          | Anthropic / OpenAI passthrough     |
| `/api/graphql`               | minimal stub (see `graphql.go`)    |

The GraphQL endpoint is a scaffold — it answers a small set of named
queries by dispatching to the REST handlers behind it. Swap in
`graph-gophers/graphql-go` when you want a real schema.

### UI

React + TypeScript + ECharts, served by nginx at `http://localhost:8000`.
Tabs:

| Tab        | Backed by                            |
|------------|--------------------------------------|
| Dashboard  | KPI tiles + recent alerts            |
| Devices    | `/api/devices` CRUD                  |
| Topology   | ECharts force graph over device list |
| Collectors | `/api/collectors`                    |
| Alerts     | `/api/alerts`                        |
| Rules      | `/api/rules`                         |
| Findings   | `/api/findings` (ClickHouse)         |
| Logs       | `/api/logs/search` (OpenSearch DSL)  |
| Flows      | `/api/flows/*` (ClickHouse + ECharts) |
| Copilot    | `/api/copilot/chat` (LLM)            |
| Prometheus | iframe                               |
| Grafana    | iframe (Prometheus + Victoria + ClickHouse datasources) |
| OS Dashboards | iframe (`/search/`)               |
| Settings   | integration status + manual refresh  |

## What's still TODO inside this architecture

* GraphQL is a stub — replace `graphql.go` with a real schema + resolver.
* RCA in the correlation engine is a stub — wire in incident-cluster
  detection and feed the result back to the Go alerts engine.
* OpenSearch index templates aren't applied automatically — run
  `scripts/bootstrap-opensearch.sh` after the first start.
* The frontend dev dependencies (echarts, echarts-for-react) need
  `npm install` — the build container does this automatically.
