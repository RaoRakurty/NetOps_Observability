# Flows UI & Pipeline — Investigation and Design

Research only — **no code was modified**. Covers backlog items #1 (see NetFlow on
UI), #2 (IPFIX), #3 (sFlow), #4 (lab not sourcing flows), #5 (Explore→Flows
source-type selector), #10 (Incidents only simulated).

All file paths are absolute under
`/home/rao/Projects/NetOps_Observability/NetOps_Observability/`.

---

## 1. Pipeline trace (edge ingest → ClickHouse)

### Text diagram

```
 NetFlow v5/v9 (UDP 2055)    IPFIX (UDP 4739)        sFlow v5 (UDP 6343)
        │                          │                        │
        ▼                          ▼                        ▼
 ┌──────────────────────────────────────────────────────────────────┐
 │ goflow2  (netsampler/goflow2:v2.2.1)                              │
 │ -listen "netflow://:2055,sflow://:6343,netflow://:4739"          │
 │ -format json  -transport file  -transport.file /dev/stdout       │
 │  →  emits one JSON object per flow record to STDOUT               │
 └───────────────────────────────┬──────────────────────────────────┘
                                  │ docker stdout
                                  ▼
 ┌──────────────────────────────────────────────────────────────────┐
 │ vector-aggregator  (deployment/docker/vector/vector.yaml)        │
 │  source docker (docker_logs)                                     │
 │  └ filter docker_flows: container_name contains "goflow2"        │
 │     └ transform flows_normalized: parse_json(.message),          │
 │        merge into ., del(.label), .signal="netflow"              │
 │  sink kafka_flows → Redpanda topic netops.flows  (codec json)    │
 └───────────────────────────────┬──────────────────────────────────┘
                                  ▼  Redpanda topic: netops.flows
 ┌──────────────────────────────────────────────────────────────────┐
 │ vector-router  (deployment/docker/vector-router/vector.yaml)     │
 │  source kafka_flows: topic netops.flows                          │
 │  transform flows_decoded (VRL):                                  │
 │     proto name→IANA number;  derive .flow_type from goflow2 .type│
 │  sinks: opensearch_flows (search)  +  clickhouse_flows (analytics)│
 └───────────────────────────────┬──────────────────────────────────┘
                                  ▼
                    ClickHouse  netops.flows  (MergeTree)
                                  ▲
 ┌────────────────────────────────┴─────────────────────────────────┐
 │ Go API /api/flows/*  (src/backend/flows.go)                       │
 │  → React Flows tab (src/frontend/src/tabs/Flows.tsx)              │
 └──────────────────────────────────────────────────────────────────┘

 OPTIONAL synthetic source (this is what fills the UI today):
   scripts/lab/flowgen/flowgen.py  (stdlib UDP sender)
     → goflow2 :2055 / :4739 / :6343  → (same path as above)
   Enabled via:  deployment/docker/docker-compose.flowgen.yml
     (network_mode service:goflow2, sends to 127.0.0.1, ~30 eps,
      ~40% NetFlow v5 / 30% IPFIX / 30% sFlow)
```

Key correction vs. earlier assumptions: goflow2 here does **not** use a Kafka
transport. It writes JSON to **stdout**; vector-aggregator scrapes it via
`docker_logs`, parses the JSON, and publishes to `netops.flows`. The
vector-**router** (a second Vector instance, separate config dir) consumes that
topic and writes to ClickHouse + OpenSearch.

### How each flow type is received and distinguished

- **Listeners** (`docker-compose.yml`, goflow2 service): three URIs on one
  process — `netflow://:2055`, `sflow://:6343`, **`netflow://:4739`**. In
  goflow2 v2 the `netflow://` decoder handles **NetFlow v5, NetFlow v9, and
  IPFIX** (IPFIX = IETF successor of NFv9, same decoder). Here IPFIX gets its
  **own dedicated port 4739** (the IANA IPFIX port) via a second `netflow://`
  listener, separate from the 2055 NetFlow port. `sflow://:6343` handles
  **sFlow v5**.
- **Published ports**: `2055/udp` (NETFLOW_PORT), `4739/udp` (IPFIX_PORT),
  `6343/udp` (SFLOW_PORT) — all published to the host, reachable by external
  exporters.
- **Type tag**: goflow2 JSON carries a `type` field (`NETFLOW_V5`,
  `NETFLOW_V9`, `IPFIX`, `SFLOW_5`). The router VRL normalizes it to
  `flow_type`.

### ClickHouse DDL (`deployment/docker/clickhouse/init.sql`)

```sql
CREATE TABLE IF NOT EXISTS netops.flows
(
    ts               DateTime64(3) DEFAULT now64(3),
    time_received_ns UInt64,
    sampler_address  String,
    src_addr         String,
    dst_addr         String,
    src_port         UInt16,
    dst_port         UInt16,
    proto            UInt8,
    bytes            UInt64,
    packets          UInt64,
    in_if            UInt32,
    out_if           UInt32,
    src_as           UInt32,
    dst_as           UInt32,
    sampling_rate    UInt32,
    vlan_id          UInt16,
    flow_type        LowCardinality(String) DEFAULT 'unknown'  -- netflow | ipfix | sflow
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, sampler_address, src_addr, dst_addr)
TTL toDateTime(ts) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;
```

So **yes, the `flow_type` column exists** (project memory confirmed),
`LowCardinality(String) DEFAULT 'unknown'`. The same file also defines a
`netops.flows_hourly` SummingMergeTree materialized view (top-talkers rollup),
`netops.tunnels`, and `netops.findings`.

### Router VRL transform (`deployment/docker/vector-router/vector.yaml`, `flows_decoded`)

Two jobs:
1. **proto name → IANA number** — goflow2 renders proto as a *name*
   (`"TCP"`/`"UDP"`/…) but `flows.proto` is `UInt8`. Without this map every flow
   batch failed the ClickHouse insert with a 400 and was dropped — the comment in
   the file documents this was *the* reason `netops.flows` stayed empty
   (matches commit `1f4e3c1 fix(flows): repair vector-router flows_decoded VRL`).
2. **derive `.flow_type`** from goflow2 `.type`:

```text
ft = to_string(.type) ?? ""
if starts_with(ft, "NETFLOW") { .flow_type = "netflow" }
else if ft == "IPFIX"        { .flow_type = "ipfix"   }
else if starts_with(ft, "SFLOW") { .flow_type = "sflow" }
else { .flow_type = "unknown" }
```

> This **already normalizes** the upper-snake goflow2 values to lowercase
> `netflow/ipfix/sflow`, which is exactly what the `/api/flows/by-type`
> handler and the #5 selector need. (The "value mismatch" worry is *not* a real
> bug here — the VRL handles it. NetFlow v5 and v9 both collapse to `netflow`,
> which is the intended UI grouping.)

The aggregator VRL (`flows_normalized`) only parses JSON, merges, `del(.label)`
(the dotted-key OpenSearch fix from CLAUDE.md), and stamps `.signal="netflow"`.

---

## 2. UI and backend flow endpoints

### Frontend (`src/frontend/src/tabs/Flows.tsx`, 199 lines)

The Flows tab is a **single scrolling page** (no Overview/Explore sub-tabs in
this checkout). On mount and every 30s it fires **three** calls in parallel:

- `api.topTalkers(since, 25)`     → `/api/flows/top`        → Top-talkers table
- `api.flowsByProto(since)`       → `/api/flows/by-proto`   → "By protocol" donut
- `api.flowsTimeseries(since, …)` → `/api/flows/timeseries` → "Traffic over time"

Cards rendered: a header card with a **static heading**
`<h2>NetFlow / IPFIX / sFlow analytics</h2>` and a time-range `<select>` (15m /
1h / 6h / 24h, shown only when no global range is supplied); "Traffic over time"
(dual-axis bytes/packets line); "Top talkers" (table); "By protocol" (donut,
proto numbers mapped to names via local `PROTO_NAMES`). Counts are scaled by
`sampling_rate` server-side.

> The static `<h2>NetFlow / IPFIX / sFlow analytics</h2>` (Flows.tsx line ~75)
> is the heading #5 targets. **`/api/flows/by-type` is implemented in the backend
> but is NOT called by the frontend at all today** — there is no by-type view in
> the UI yet. There is no `pages/panels.tsx` flow panel; `panels.tsx` exists but
> is the Overview dashboard registry, unrelated to Flows.

### Backend handlers (`src/backend/flows.go`; routes in `src/backend/main.go` L346-349)

All run server-side SQL against `netops.flows` over the ClickHouse HTTP
interface (`proxyClickHouse`, `CLICKHOUSE_URL` default `http://clickhouse:8123`,
`FORMAT JSON` → `{ "meta":[], "data":[...], "rows":n }`). Every handler:
honors `?since=` (default 1h, capped 30d) and applies a **tenant clause**
(`flowTenantClause`) restricting `src_addr/dst_addr` to the principal's visible
devices (or empty result for a scoped principal with no addresses). Counts are
scaled `bytes * if(sampling_rate=0, 1, sampling_rate)`.

| Route | Handler | Query shape | Returns |
|---|---|---|---|
| `/api/flows/top?limit=&since=` | `handleFlowsTopTalkers` | `SELECT src_addr src, dst_addr dst, sum(bytes*…) bytes_total, sum(packets*…) packets_total, count() flows GROUP BY src,dst ORDER BY bytes_total DESC LIMIT n` | talker pairs |
| `/api/flows/by-proto?since=` | `handleFlowsByProto` | `SELECT proto, sum(bytes*…) bytes_total, …, count() flows GROUP BY proto ORDER BY bytes_total DESC` | per-protocol totals |
| `/api/flows/by-type?since=` | `handleFlowsByType` | `SELECT flow_type, sum(bytes*…) bytes_total, …, count() flows, uniqExact(sampler_address) exporters GROUP BY flow_type ORDER BY flows DESC` | per-flow_type totals (**built, unused by UI**) |
| `/api/flows/timeseries?since=&step=` | `handleFlowsTimeseries` | `SELECT toStartOfInterval(ts, step) bucket, sum(bytes*…), sum(packets*…) GROUP BY bucket ORDER BY bucket` | bytes/packets per bucket |

(There is no `/api/flows/recent`, `/summary`, or `/health` in this checkout —
those were in an earlier draft of my notes and do not exist.) `handleFindings`
(`/api/findings`) and `handleTunnels` (`/api/tunnels`) also live in
`flows.go`.

---

## 3. #5 — Flow source-type selector design (replaces the static heading)

Goal: turn the static "NetFlow / IPFIX / sFlow analytics" heading into a live
**source-type selector** (All / NetFlow / IPFIX / sFlow) that filters all four
Flows panels and finally wires up the unused `/api/flows/by-type` endpoint so
the UI proves each source is arriving.

### Backend change (small, stdlib, injection-safe)

Add an optional `type` query param to the flow handlers; whitelist it and append
`AND flow_type = '<v>'`. Because `flows.go` builds SQL by string concatenation, a
**whitelist map is mandatory** (never interpolate the raw param):

```go
// flowTypeClause returns " AND flow_type = '<v>'" for a known type, else "".
var flowTypeAllowed = map[string]bool{"netflow": true, "ipfix": true, "sflow": true}
func flowTypeClause(r *http.Request) string {
    v := strings.ToLower(r.URL.Query().Get("type"))
    if flowTypeAllowed[v] {
        return " AND flow_type = '" + v + "'"
    }
    return "" // "all" / empty / unknown → no filter
}
```

Append `flowTypeClause(r)` to the WHERE of `handleFlowsTopTalkers`,
`handleFlowsByProto`, `handleFlowsTimeseries` (right after `tenantClause`), so the
whole page reacts to the selector. `handleFlowsByType` needs no filter (it *is*
the breakdown). The VRL already stores lowercase values, so the whitelist matches
real and synthetic rows alike.

### Frontend change (`Flows.tsx`, consistent with existing minimal styling)

Add a `flowType` state and a second `<select>` in the header card, on the same
row as the existing time selector. Pass `type` through the three existing API
calls, and add a `byType` table/chips strip that calls `/api/flows/by-type` so
the operator can see all three sources at a glance and click to filter.

```tsx
const [flowType, setFlowType] = useState<'all'|'netflow'|'ipfix'|'sflow'>('all');
const [byType, setByType] = useState<{flow_type:string; flows:number; bytes_total:number; exporters:number}[]>([]);

// in load(): pass flowType (omit when 'all') to top/by-proto/timeseries,
// and always fetch the full breakdown for the chips:
const q = flowType === 'all' ? undefined : flowType;
const [a, b, c, d] = await Promise.all([
  api.topTalkers(since, 25, q),
  api.flowsByProto(since, q),
  api.flowsTimeseries(since, step, q),
  api.flowsByType(since),           // new api helper → /api/flows/by-type
]);
setByType((d?.data as any[]) ?? []);
// add flowType to the effect deps so changing it re-fetches.
```

Header (reference-grade: title left, controls right):

```tsx
<div className="card">
  <div className="row" style={{ justifyContent:'space-between', alignItems:'center' }}>
    <h2 style={{ margin:0 }}>Flow analytics</h2>
    <select value={flowType} onChange={e => setFlowType(e.target.value as any)} style={{ width: 180 }}>
      <option value="all">All sources</option>
      <option value="netflow">NetFlow</option>
      <option value="ipfix">IPFIX</option>
      <option value="sflow">sFlow</option>
    </select>
  </div>
  {/* source chips driven by /api/flows/by-type: clickable, set flowType */}
  <div className="row" style={{ gap: 8, marginTop: 8 }}>
    {byType.map(t => (
      <button key={t.flow_type}
        className={t.flow_type === flowType ? 'chip chip-active' : 'chip'}
        onClick={() => setFlowType(t.flow_type as any)}>
        {t.flow_type.toUpperCase()} · {Number(t.flows).toLocaleString()} flows · {t.exporters} exp
      </button>
    ))}
  </div>
</div>
```

UI notes: keep the existing `card` / `table` / `select` tokens; render the
breakdown as severity-neutral chips with a per-type count + exporter count so an
all-synthetic stack reads clearly; show an empty-state ("No NetFlow flows in
window") when a filtered panel is empty; reuse the existing `paletteColor` so each
source gets a stable color across the page. This depends only on the existing
`flow_type` VRL normalization (§1) — no schema change.

The `api.ts` helpers (`topTalkers`, `flowsByProto`, `flowsTimeseries`) gain an
optional `type` arg appended as `&type=`; add a `flowsByType(since)` helper hitting
`/api/flows/by-type`.

---

## 4. #4 — Why real lab flows are not arriving (verification checklist)

The pipeline and tooling are **proven good** — the project intentionally ships a
synthetic generator (`scripts/lab/flowgen/flowgen.py` +
`docker-compose.flowgen.yml`) precisely because the virtual clos fabric can't
produce real flow *records*. The flowgen header comment states the root cause
directly: **cEOS / SR Linux have no ASIC, so their sFlow yields only
counter-samples (never per-flow records), and goflow2 can't turn counters into
rows.** That, plus the data-plane/exporter issues from
[[netops-flow-pipeline-status]] (OSPF not forming → empty IPFIX cache; Cisco
monitor on the mgmt interface, off the data path; NAT collapsing source
addresses), is why only flowgen rows land.

### Collector / stack side (verify these resolve)
- [ ] **goflow2 up & listening on all three ports**: `docker compose ps goflow2`;
      logs show binds on `netflow://:2055`, `netflow://:4739`, `sflow://:6343`.
- [ ] **Ports reachable from the exporter**: from the lab host,
      `nc -u -z <stack-ip> 2055 / 4739 / 6343`. Stack is local on `.122`, lab on
      `.120/.245` — confirm L3 reachability between subnets.
- [ ] **Host firewall**: allow inbound UDP 2055/4739/6343 on the stack host
      (ufw/iptables/nft). Compose publishes them, but a host firewall can drop them.
- [ ] **goflow2 is emitting to stdout**: `docker logs goflow2` shows JSON lines
      while flows arrive. Empty ⇒ nothing decoded ⇒ problem is upstream (exporter
      / data-plane), not the pipeline.
- [ ] **Topic carries flows**: `rpk topic consume netops.flows --num 5`. Empty ⇒
      aggregator's `docker_flows` filter or JSON parse is the gap; non-empty ⇒
      pipeline is fine.
- [ ] **ClickHouse landing + proto coercion intact**: `SELECT flow_type, count(),
      max(ts) FROM netops.flows GROUP BY flow_type`. If counts are 0 but the topic
      has data, suspect the `flows_decoded` proto-name→number VRL (a non-numeric
      proto that isn't in the map → CH 400, row dropped — this exact bug was fixed
      once already; new vendor proto names could reintroduce it).
- [ ] **Distinguish synthetic vs real**: flowgen NetFlow/IPFIX `sampler_address`
      is the sender (the flowgen container, sharing goflow2's netns → 127.0.0.1);
      flowgen sFlow agents are `172.40.40.x`. Real exporters will show the device
      management IPs. Stop flowgen (`docker compose -f docker-compose.yml -f
      docker-compose.flowgen.yml stop flowgen`) for an unambiguous real-flow test.

### Exporter / data-plane side (the actual root cause)
- [ ] **sFlow must do packet/flow sampling, not just counters**: the virtual
      fabric only emits counter-samples; goflow2 makes **no rows** from those. On
      real hardware (or a soft-forwarding agent like host-sflow on a data-plane
      box) enable flow sampling so `flow_sample`/`raw header` records are sent.
- [ ] **Data plane must carry transit traffic**: NetFlow/IPFIX export only
      *transit* flows. Bring up routing (OSPF/BGP) so a forwarding path exists, and
      generate device-to-device traffic across the monitored interface.
- [ ] **Exporter destination = stack**: NetFlow/IPFIX `destination <stack-ip>
      2055` (or `4739` for IPFIX); sFlow collector `<stack-ip> 6343`. Match the
      port to the listener (IPFIX → 4739, not 2055, in this config).
- [ ] **Flow monitor on a transit interface, ingress + egress** — not the mgmt
      interface (the prior Cisco mis-config). Verify `show flow monitor … cache`
      shows active flows.
- [ ] **Sampling rate set** (e.g. 1:1 for a lab) so flows are actually sampled
      and exported; an empty cache exports nothing.
- [ ] **Watch for NAT**: export *before* NAT, else all sources collapse to one
      address and top-talkers are meaningless.

---

## 5. #10 — Incidents are only simulated

### How findings are produced (`src/correlation/main.py`, 330 lines)

- **Service**: FastAPI (`main.py`), built from `Dockerfile.correlation`, runs in
  compose as `correlation` (env `KAFKA_BOOTSTRAP=redpanda:9092`,
  `CLICKHOUSE_URL`, etc.). It listens on port 8000 inside the container
  (`CORRELATION_URL: http://correlation:8000` in the api env).
- **Consumer**: on FastAPI `lifespan` startup it spawns
  `asyncio.create_task(consume())`, an **`AIOKafkaConsumer`** subscribed to
  `TOPICS = ["netops.syslog", "netops.flows", "netops.metrics"]`,
  `auto_offset_reset="latest"`. There is **no synthetic generator inside this
  service** — it is a clean real-data consumer (contrast with my earlier
  assumption; there is no `synth_loop`).
- **Detection**:
  - `handle_metric()` (topic `netops.metrics`): per-`(device, metric)` rolling
    window (`deque` maxlen 200); after ≥20 samples, |z|≥3 emits a finding
    (`warning`, or `critical` if |z|≥5). Device key = `hostname`/`agent_host`;
    metric = `name`/`metric`; value = first numeric field.
  - `handle_syslog()` (topic `netops.syslog`): severity-weighted burst detector —
    sums `SEVERITY_WEIGHT` per host over a 60s window; ≥30 points → a `correlation`
    finding.
  - `handle_flow()` (topic `netops.flows`): **empty placeholder** (`return`) —
    DDoS / top-talker-shift / port-scan detection is a TODO.
- **Persistence + API**: `emit()` INSERTs into `netops.findings` (ClickHouse,
  JSONEachRow). `/findings` reads them back. **The UI never calls
  `/findings` directly** — the Go API exposes `/api/findings` (`handleFindings`
  in `flows.go`, querying `netops.findings`), and the React **Findings tab**
  (`src/frontend/src/tabs/Findings.tsx`) calls `api.findings()` →
  `/api/findings`. There is no separate "Incidents" view; findings ARE the
  incident queue. There is no grouping/RCA: `/analyze` is a stub.

### Why only "simulated" incidents appear

1. **`netops.metrics` has no producer.** This is the core gap. Real device
   metrics bypass Redpanda entirely: **Telegraf** writes straight to
   VictoriaMetrics via Prometheus remote_write (`telegraf.conf` `[[outputs.http]]
   → http://victoria:8428/api/v1/write`), and the **gNMI** collector also targets
   `http://victoria:8428`. Nothing publishes to the `netops.metrics` topic
   (confirmed: only `main.py` and `scripts/smoke-test.py` even mention it). So
   `handle_metric()` — the z-score anomaly engine — **never receives a single
   sample**, and produces **zero** real anomaly findings.
2. **`handle_flow()` is a no-op**, so the flows that *do* exist (synthetic
   flowgen traffic) generate no findings either.
3. **The only live producer feeding correlation is syslog** (`netops.syslog`, fed
   by syslog-ng → vector-aggregator). So whatever findings appear come solely from
   the syslog-burst detector, driven by whatever log volume the lab emits — there
   is no anomaly/RCA correlation against real lab *metrics or flows*. Combined with
   the synthetic flowgen traffic, the Flows + Findings views read as "simulated".

### What's needed for real lab incidents

1. **Produce real metrics into `netops.metrics`.** Bridge the existing metric
   stream into Redpanda so `handle_metric()` can score it. Options:
   - Add a `[[outputs.kafka]]` to Telegraf (topic `netops.metrics`, JSON) **in
     addition to** the VictoriaMetrics remote_write, or
   - Add a small VM→Redpanda bridge (query VictoriaMetrics, publish samples), or
   - Have the Go SNMP/gNMI collectors dual-publish `{hostname, name, value}` JSON
     to `netops.metrics`.
   Emit the keys `handle_metric` reads: `hostname` (or `agent_host`), `name` (or
   `metric`), and a numeric value field. (Note: a Redpanda topic-create step for
   `netops.metrics` isn't visible in compose — `smoke-test.py` expects the four
   topics to exist; confirm they're auto-created or add an init step.)
2. **Implement `handle_flow()`** for real flow-based findings (DDoS, top-talker
   shift, scan signatures) once real flows land (#4), so the Flows pipeline
   contributes incidents.
3. **Add grouping / RCA**: replace the `/analyze` stub with finding→incident
   clustering (group by device + time bucket) and surface it, so the UI shows
   incidents, not just a flat findings list.
4. **Verify the consumer actually connects**: `aiokafka` to `redpanda:9092` with
   `auto_offset_reset="latest"` will silently see nothing if no producer exists —
   so step 1 is the unblock. Check `correlation` logs for the
   "consuming topics=… bootstrap=…" line and a non-empty `netops.metrics`.

---

## Cross-cutting findings (research notes)

- **#1/#2/#3 work via the synthetic generator.** Real NetFlow/IPFIX/sFlow land
  through the same proven path; the blocker for *real* data is exporter/data-plane
  side (#4), not the stack. The `flow_type` VRL already distinguishes the three.
- **`/api/flows/by-type` is implemented but unused by the UI** — wiring it up is
  the substance of #5.
- **`netops.metrics` has zero producers** (Telegraf + gNMI bypass Redpanda → VM)
  → correlation's metric anomaly engine never runs → Incidents are effectively
  syslog-only/simulated (#10). This is the single highest-leverage fix.
- **`handle_flow()` is an empty placeholder** in `main.py` — no flow-derived
  findings today.
- **Findings reach the UI via the Go API `/api/findings`** (ClickHouse-backed),
  not a direct nginx→correlation proxy; the React tab is `Findings.tsx`.
- The earlier-suspected "flow_type value mismatch", duplicate `/api/flows/health`
  route, and `metrics-raw` topic name were **incorrect** assumptions — the real
  config normalizes flow_type in VRL, has no `/health` route, and uses
  `netops.metrics`.
