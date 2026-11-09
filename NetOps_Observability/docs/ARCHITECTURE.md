# Architecture

A Docker Compose stack behind nginx on one port (`:8000`): edge collectors, a
Vector aggregation layer, an Apache Kafka bus, storage (OpenSearch,
VictoriaMetrics, ClickHouse), a Python correlation engine, a Go API, and a React
UI with the Iris assistant. The purpose of the platform is correlation and root
cause analysis; every other tier exists to feed it signals, entities, topology
and ownership, or to present its results.

```
   Network devices · controllers (NMS) · cloud APIs · probes
       │            │             │            │
    Syslog/traps   SNMP/gNMI    Flows      Connectors
       ▼            ▼             ▼            ▼
   syslog-ng   Go collectors   goflow2    api, cloud-ingest,
               (in the api)               prober
       │            │             │            │
       │            ├── full samples ─────────────► VictoriaMetrics
       ▼            ▼             ▼            ▼
       VECTOR AGGREGATOR  (parse, normalize, enrich, buffer)
                     │
                     ▼
       APACHE KAFKA (KRaft) ─ netops.* topics
              │                          │
              ▼                          ▼
        VECTOR ROUTER            CORRELATION ENGINE (Python)
              │                  signals → grounded graph →
              ▼                  ranked hypotheses + verdict
       OpenSearch · ClickHouse           │
              │                          ▼
              │                     ClickHouse corr_* tables
              └────────────┬─────────────┘
                           ▼
       API  (Go REST + GraphQL + Iris, tenant-scoped)
                           │
                           ▼
       UI  (React + ECharts, served by nginx)
```

## Tier by tier

### Edge ingestion

* **syslog-ng** listens on UDP/TCP 514, parses RFC3164 and RFC5424, and
  forwards to vector-aggregator over TCP/6601 with `syslog-protocol`
  framing. Config: `deployment/docker/syslog-ng/syslog-ng.conf`.
* **SNMP polling is native Go, in-process in the api** (`src/backend/collectors/`:
  `poller.go`, `snmpmetrics.go`, `snmpv3.go`). The collector writes the full
  sample set straight to VictoriaMetrics, and POSTs a filtered canonical subset
  (the RCA metric families, `collectors/metric_events.go`) to Vector, which
  publishes it on `netops.metrics` for the engine. Telegraf is **legacy and does
  not run** (`profiles: [legacy]` in compose).
* **goflow2** decodes NetFlow v5/v9, IPFIX and sFlow and produces one JSON record
  per flow to Kafka (`netops.flows.raw`); vector-router re-keys it by tenant onto
  `netops.flows`. Settings are flags on the compose `command:`; the one mounted
  file is `deployment/docker/goflow2/mapping.yaml`. `goflow2.yaml` beside it is
  reference documentation of the flow schema.
* **Other sources:** gNMI (`gnmic`, `collectors/gnmi.go`), controller and NMS
  integrations (`src/backend/nms/`, publishing `netops.controller_events`), cloud
  connectors (`cloud-ingest`, profile `cloud-ingest`) and active probes (`prober`,
  profile `prober`).

### Vector aggregator

`deployment/docker/vector/vector.yaml`. Receives from the edges, parses,
normalizes, enriches and buffers, then produces to the bus with end-to-end
acknowledgements. Topic list: the `kafka-init` service in
`deployment/docker/docker-compose.yml`.

### Apache Kafka

Single-node broker in KRaft mode (service `kafka`, profile `embedded-bus`),
internal to the compose network. Every client resolves it through `BROKER_URLS`,
so an external Kafka-compatible cluster can replace it
(`install-correlix.sh --external-kafka --broker-urls ...`). The one-shot
`kafka-init` service pre-creates the `netops.*` topics. Redpanda and Prometheus
were removed for licensing reasons (#97); see Valkey below for the Redis
replacement.

### Vector router

`deployment/docker/vector-router/vector.yaml`. One consumer group per lane
(`netops-router-*`: applogs, syslog, snmptrap, flows, flows-rekey, cloudlogs,
security, deadletter, experience, cloudcosts). It writes logs, traps, security
findings and dead letters to OpenSearch, and flows, cloud costs and experience
events to ClickHouse (flows go to OpenSearch as well). It does **not** consume
`netops.metrics`; that lane exists for the engine.

### Storage tier

* **OpenSearch** — hot search, in rolling daily `netops-*` indices. Templates are
  in `deployment/docker/opensearch/index-templates.json`; the installer and
  `scripts/update.sh` apply them through `scripts/bootstrap-opensearch.sh`, and
  `scripts/deploy-qualify.sh` verifies them. **OpenSearch Dashboards** is
  optional (profile `osd`), served under `/search/`.
* **VictoriaMetrics** — time series for SNMP and telemetry, and the query API the
  alert rules run against (`vmalert`).
* **ClickHouse** — OLAP. `netops.flows` (default TTL 7 days,
  `deployment/docker/clickhouse/init.sql`), the correlation tables (below), and
  the path, application, wireless and experience tables. Row policies enforce
  tenant isolation.
* **PostgreSQL** — relational app state, under FORCE-RLS `tenant_iso` policies.
  The installer writes `STORE_BACKEND` explicitly; Postgres is the default for
  fresh installs, and the file backend remains for compatibility.
* **Valkey** — collector state and caches. The compose service is still named
  `redis` so that `REDIS_HOST` consumers are unchanged, but the image is Valkey
  (BSD-3), not Redis.

### Correlation engine

`src/correlation/`, Python with FastAPI and aiokafka. The authoritative
description, with line references, is
[`src/correlation/CLAUDE.md`](../src/correlation/CLAUDE.md); this section is only
the outline. `engine.py`, `scoring.py` and `verdicts.py` form a pure core with no
IO, clock or randomness, and `main.py` is the impure shell around it.

1. **Normalize.** Kafka lane records become canonical `Signal`s carrying tenant,
   event time, observer, collection path, clock quality, modality and entity. A
   record that fails a construction gate goes to a dead letter. Raw evidence is
   written to `corr_signals` before any window filter.
2. **Episodes.** Metrics and flow volumes go through a two-sided **CUSUM**
   change-point detector (`episodes.py`: H=4σ, K=0.5σ, at least 20 baseline
   samples). Onset uncertainty is carried, not discarded: it is the observed
   sampling interval plus a budget for the source's clock quality. Cumulative
   counters are converted to rates first. Syslog, traps and controller records
   are point signals.
3. **Window.** Signals are grouped per tenant in an event-time window. A window
   is single-tenant by construction, and a mixed one raises an error.
4. **Grounding gate.** Two nodes join only through a ranked relationship: shared
   identity or containment, seam membership, path hop or adjacency, app binding,
   flow or NAT stitch, then inferred route and shared token. Ranks 1–5 can be
   authoritative; 6–7 never are. An ungrounded pair is a gap hint, never an edge.
   Topology comes from enrichment files the API writes, including the path graph
   defined by the frozen contract in `docs/design/service-path-graph-contract.md`.
5. **Objects.** Connected components become versioned correlation objects with a
   stable identity and an `open`, `closed` or `merged` lifecycle.
6. **Scoring (the rank).** `scoring.py` ranks competing hypotheses from a
   declarative signature catalog (`catalog.py`: 149 templates, 103 enabled) using
   a structure gate, clause coverage and a discriminator penalty that promotes the
   competing template. It reports the top 4 plus forced and contradicted
   competitors. Below the 0.3 floor the result is `undetermined`, with the
   evidence that is missing; a root cause is never forced. The rank is a heuristic
   rank, not a probability.
7. **Verdict (the tier).** `verdicts.py` grades the evidence separately from the
   rank. `CONFIRMED` needs at least two modalities and two observers, a trusted,
   cross-modality, independent pair, and every required modality met by a trusted
   witness; otherwise the verdict is `SUSPECTED`. Later caps can only downgrade,
   for example when the component has no authoritative edge.
8. **Persist.** Objects go to `corr_objects` and `corr_current`, then evidence to
   `corr_edges`, `corr_evidence` and `corr_signals_archive` through a bounded
   queue. Identical inputs replay to byte-identical snapshots, pinned to
   `engine_version`.

RCA auto-promotion requires a `CONFIRMED` verdict with confirmed impact
(`src/backend/internal/rca/rca_promotion_model.go`).

**Legacy findings path.** `main.py` also keeps an older path that writes
`netops.findings`: a per-(device, metric) rolling z-score (200 samples, 3σ) and a
severity-weighted syslog burst detector. It is retained for compatibility and is
not how root causes are determined.

**Horizontal scale.** Every bus producer keys records by tenant (Java murmur2),
every `netops.*` topic carries `BUS_PARTITIONS` partitions, and the range assignor
gives `docker compose up --scale correlation=N` instance k partition k of every
topic: a disjoint slice of tenants with worker-local state. See
`docs/scale-correlation.md`.

### API

Go, at `src/backend/` (routes are registered in `main.go`). Data routes scope by
the caller's tenant. The main route families:

| Routes | Backed by |
|---|---|
| `/api/correlations` and `/api/correlations/...` | ClickHouse `corr_current` under the tenant scope (`correlations.go`) |
| `/api/findings` | ClickHouse `netops.findings` (legacy path above) |
| `/api/devices`, `/api/collectors` | device inventory and collector pool |
| `/api/alerts`, `/api/rules` | alert engine |
| `/api/logs/*` | OpenSearch |
| `/api/flows/*` | ClickHouse `netops.flows` |
| `/api/ai/*`, `/api/copilot/chat` | Iris (see below) |
| `/api/graphql` | a fixed schema with its own parser, permission-checked (`graphql.go`) |

**Iris** is the assistant. `/api/ai/ask` answers through the grounded engine in
`src/backend/ai/`: read-only tools, tenant-scoped data, and citations checked
against the evidence it read. It reports the engine's verdict and does not produce
its own. `/api/copilot/chat` is the provider path; see `docs/COPILOT.md` and
`docs/ai/evals.md`.

### UI

React, TypeScript and ECharts, served by nginx at `http://localhost:8000`. The
navigation (`src/frontend/src/nav.tsx`) has these sections: Overview, Operations,
Investigate, Infrastructure, Explore, Security, Analytics, Iris AI, Administration
(tenant level) and Platform (provider only).

## Monitoring

Three independent layers: vmalert rules, alert delivery through the API receiver,
and the external `scripts/stack-watchdog.sh`. See
`docs/runbooks/engine-not-consuming.md` and
`docs/runbooks/engine-liveness-matrix.md`.

## Open work

`docs/TRACKER.md` lists open items, and `docs/audit/INVARIANTS.md` records what is
proven versus merely built.
