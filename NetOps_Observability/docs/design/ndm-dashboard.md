# Network Device Monitoring (NDM) — dashboard design

Status: **direction-setting for the NEXT PHASE — not started.** Date: 2026-06-07.
Reference screenshots: `/var/tmp/` (reference NDM captures, 2026-06-05) — see §1.

> **Sequencing (owner-driven):** NDM is the agreed next phase. Before any build,
> the owner will provide: **(1)** the finalized **left-navigation structure / IA**,
> then **(2)** the **NDM display spec** (what each NDM view shows). Those inputs
> SUPERSEDE the proposed nav (§2.1) and panel catalog (§2.2) here — treat §2 as a
> reference menu to align against, not the final layout. §1 (reference layout) and
> §3 (data sources / gaps) stand regardless.

## 0. Goal
Bring a first-class **Network Device Monitoring** experience to the platform,
modeled on a leading observability vendor's NDM + the Cisco SD-WAN dashboard: device health, **interface
utilization**, **heat maps**, per-interface/top-talker breakdowns, maps, and a
**continuously-updating live WAN interface utilization graph on the Overview**.
"Every bit and detail" — this captures the reference layouts and the exact build.

---

## 1. Reference: how the reference NDM is laid out (from the screenshots)

**Top-level IA** — *Network Monitoring* splits into three products:
`Cloud Network` · **`Network Devices` (NDM)** · `Network Path`. NDM has tabs:

| NDM tab | Screenshot | Layout |
|---|---|---|
| **Devices** | `10.08.40` | Device inventory: auto-discovery, multi-vendor (Arista/Aruba/Cisco/Dell/F5/HP/Juniper/Palo Alto), "high-level device + per-interface views", proactive ML anomaly/forecast alerts. A filterable list with per-device health. |
| **Maps** | `10.08.54` | Sub-tabs **Device Geomap** + **Device Topology Map** (geo placement + L2/L3 topology). |
| **NetFlow** | `10.09.01`, `10.09.09` | Left sub-nav: Traffic Volume · Device Health · Flows · Conversations · Autonomous Systems · Geo IP · Source Ports · Dest Ports · Protocols · Flags. Top filters: `source.ip`, `ingress.interface.name`, `device.name`, `device.ip`, `egress.interface.name`, `destination.ip` + Uni/Bidirectional. Panels: **Top Devices**, **Top Ingress Interfaces**, **Top Egress Interfaces**. |
| **Integrations** | `10.09.23`, `10.10.41` | Per-vendor curated dashboards (Cisco/Arista/Juniper/Aruba/F5…): Overview counts (Devices, APIs offline, Switches, Gateways), **Top Devices – Resource Utilization**, and a **Dashboards** dropdown: *Network Device Monitoring · Network Performance · BGP/OSPF Overview · NetFlow Monitoring*. |
| **Dashboards** | `Graphs-Traffic.png` | "System – Networking": a grid of traffic timeseries — **Network traffic (per sec)**, **Network in/out (per sec, avg/min/max)**, **Network in/out by host**, **Network in/out by device**. |

**The "section full of panels" model** — Cisco SD-WAN dashboard
(`sd-wan-dashboard-main.webp`, `…-tunnels.webp`), the template for a rich NDM page:
- Health **big-numbers**: Sites up/down, **Edges up/down** (green/red), Tunnels up/down.
- **CPU % / Memory % / Disk %** per role, as sparklines; **Uptime**.
- **Control connections** as a donut/sunburst by state; **Reboots / Crashes** timeseries.
- **Traffic** + **Traffic (bits per second)** timeseries.
- **Interfaces table** — `SITE ID · SYSTEM IP · INTERFACE · IN/OUT BANDWIDTH USAGE (bars) · IN/OUT BANDWIDTH · IN/OUT BITS · IN/OUT PKTS`.
- **Tunnels** — up/down, Top latencies, Top traffic, and a table with **Latency / Jitter / Loss / QoE** color-coded cells.

Per-device drill (`cnm-feature-1-v2.webp`): a device strip with **PING STATE / DEVICE
STATE**, tags, per-device metric charts, and a **"View Device in NDM"** button.

---

## 2. How we bring it to our tool

### 2.1 Information architecture (nav)
A new top-level **NDM** section (icon rail) — siblings of Infrastructure — reusing
what we already have, with these leaves:

| NDM leaf | Built from |
|---|---|
| **Health** (landing) | new — KPI strip + per-device CPU/mem/disk + reachability (SD-WAN big-number model) |
| **Interfaces** | new — utilization timeseries + **heatmap** + interface **table** + Top Ingress/Egress |
| **Maps** | reuse **Topology** (`tabs/Topology.tsx`) — add a geomap later |
| **Flows / NetFlow** | reuse **Flows** (`tabs/Flows.tsx`) — already has top-talkers/by-proto/timeseries |
| **Tunnels / WAN** | reuse **Tunnels** (`tabs/Tunnels.tsx`) |
| **Dashboards** | reuse **Overview** saved-dashboards (curated NDM boards) |

(Alternative: nest these under **Infrastructure** next to Devices. Decision in §6.)

### 2.2 Panel catalog — every panel, with the exact query + viz
Data already in VictoriaMetrics (per telegraf/gnmic/collectors — see §3):
SNMP `device_if_in_octets` / `device_if_out_octets` / `device_if_oper_status` /
`device_cpu_percent` (+ Telegraf `interface_ifInOctets/ifOutOctets/ifOperStatus`);
gNMI `gnmi_interfaces_interface_state_counters_in_octets/out_octets` /
`…_oper_status`. Labels: `device`/`hostname`/`source` + `ifName`/`interface`.

| Panel | Viz | Query (PromQL/MetricsQL) |
|---|---|---|
| Devices up / down / unreachable | big-number tiles | `count(device_if_oper_status==1)` vs `==2`; reachability from collector health |
| Avg CPU / Mem | gauge | `avg(device_cpu_percent)` / `avg(device_mem_percent)` |
| Per-device CPU/Mem | small multiples / sparklines | `avg by (device)(device_cpu_percent)` |
| **Traffic in/out (fleet)** | area timeseries | `sum(rate(device_if_in_octets[5m]))*8`, `…out…` |
| **Traffic by device** | multi-line | `sum by (device)(rate(device_if_in_octets[5m])*8)` |
| **Interface utilization** | multi-line (per ifName) | `rate(device_if_in_octets{device="X"}[5m])*8` (+ out) |
| **% utilization** | line / heatmap value | `rate(device_if_in_octets[5m])*8 / (device_if_speed*1e6)` — **needs ifSpeed (§3 gap)** |
| **Interface heatmap** | ECharts `heatmap` + `visualMap` | matrix of `%util` (or bps), device×interface — see §4 |
| **Top Ingress / Egress interfaces** | ranked bars / table | `topk(10, sum by (device,ifName)(rate(device_if_in_octets[5m])*8))` |
| **Interface table** | `DataTable` (sev-tinted) | per-(device,ifName): oper-status, in bps, out bps, **%util** (ok<50 / warn<80 / crit), errors/discards |
| **Live WAN utilization** (Overview) | continuous strip | live in/out bps for WAN-tagged interfaces — see §5 |
| Tunnels up/down + table | reuse Tunnels | existing |
| Flows top-talkers / by-proto | reuse Flows | existing |

### 2.3 Component reuse (don't rebuild)
- **Overview panel registry** `pages/panels.tsx` (`PANELS` + `PanelDef`, categories) +
  `pages/Dashboard.tsx` (`usePolled`, add/remove/resize). New NDM panels register here.
- **Charts**: `echarts-for-react` with `theme/charts.ts` (`chartBase`, `axisStyle`,
  `areaGradient`, `fmtBps`, palette) — mirror `TrafficInOut` / `Flows` charts.
- **Tables**: `components/DataTable.tsx` (`Column.sev` → `data-sev` tint), the
  Tunnels/Flows pattern with `latSev`-style threshold helpers for %util.
- **Metrics API**: `api.metricsQueryRange / metricsQuery / metricNames`
  (`metrics_query.go`, Prometheus-compatible, tenant-scoped via `extra_filters`).
- **Live**: the `/api/events` hub already broadcasts `metric_update` every 5s
  (`dashboard.go startBroadcaster`); the live WAN panel rides this (§5).

---

## 3. Data sources & gaps (what we collect vs what NDM needs)

**Have:** in/out octets, oper-status, CPU (SNMP + gNMI), flows (ClickHouse),
tunnels. Per-device + per-interface labels.

**Gaps to close for full parity:**
1. **`ifSpeed` / `ifHighSpeed`** — *required to compute % utilization* (the headline
   NDM metric and the heatmap color). NOT collected today. Add `IF-MIB::ifHighSpeed`
   to `telegraf.conf` interface table **and** `device_if_speed` to
   `collectors/profiles.go` (OID `1.3.6.1.2.1.31.1.1.1.15`). Until then: show
   **absolute bps** and allow a manual speed override.
2. **Interface errors/discards** — `ifInErrors/ifOutErrors/ifInDiscards/ifOutDiscards`
   for the interface table's health columns. Add to telegraf + profiles.
3. **Memory %** — `device_mem_percent` referenced in MetricsExplorer; confirm a
   collector populates it (else add the vendor mem OIDs).
4. **Label consistency** — SNMP uses `device`/`ifName`, Telegraf `hostname`/`ifName`,
   gNMI `source`/`interface`. Normalize (relabel) so one query spans transports, or
   pick the SNMP `device_if_*` family as the canonical NDM source.
5. **BGP/OSPF** (for the "BGP/OSPF Overview" board) — confirm gNMI/SNMP routing
   metrics exist; likely a later add.

---

## 4. Interface utilization heatmap (detail)
ECharts `heatmap` series + `visualMap` (green→amber→red, 0–100%).
- **Orientation A — snapshot** (device × interface): X = interface, Y = device,
  cell = current %util (instant query `…/(device_if_speed*1e6)`). Best for "which
  interface on which device is hot right now." Tooltip: device/iface/%util/bps;
  click → interface timeseries drill.
- **Orientation B — trend** (interface × time): X = time buckets, Y = interface (for
  a chosen device), cell = %util over the window. Classic NDM "utilization heatmap."
Offer both via a toggle; default A on the NDM Interfaces page, B on device drill.
`visualMap` thresholds mirror the table sev (≥80% red, ≥50% amber).

---

## 5. Live WAN interface utilization graph (Overview, continuous)
Requirement: a panel that **runs continuously** on the Overview showing WAN
interface utilization in near-real-time.
- **WAN selection**: interfaces tagged/role-marked WAN (device tag `wan` or an
  interface allow-list in panel config; default = highest-throughput uplinks).
- **Transport (two options):**
  - **A. Fast poll** (simplest): `api.metricsQuery` (instant) every 5–10s, append to
    a rolling client-side buffer (e.g. last 5–15 min), render a smooth strip chart
    (`ReactECharts` `setOption` with the rolling series — no full reload).
  - **B. WebSocket push** (tighter): extend `dashboard.go startBroadcaster` to emit a
    `metric_update` for WAN-interface bps each 5s tick; the panel subscribes to
    `/api/events` and appends. Lower latency, no per-panel polling.
- Recommend **A for v1** (zero backend change), graduate to **B** if we want
  sub-poll latency. Panel is Overview-resident now; becomes a saved Dashboard panel
  later (the registry makes it portable).

---

## 6. Phased build plan
- **N0 — interface metrics readiness (backend/config).** Add `ifHighSpeed`
  (+ errors/discards) to `telegraf.conf` and `device_if_speed` to `profiles.go` so
  **% utilization** is computable. Confirm `device_mem_percent`.
- **N1 — NDM Overview panels.** Register: device-health KPIs, per-device CPU/Mem,
  interface utilization timeseries, **interface table** (DataTable + %util sev).
- **N2 — utilization heatmap.** ECharts heatmap + visualMap + drill (orientation A).
- **N3 — live WAN graph** on Overview (fast-poll rolling strip).
- **N4 — NDM section IA.** New nav section + leaves (Health/Interfaces/Maps/Flows/
  Tunnels/Dashboards), Top Ingress/Egress interfaces, per-vendor rollups.
- **N5 — depth.** Geomap, BGP/OSPF overview, NetFlow-style per-interface drilldowns,
  heatmap orientation B, ML anomaly overlays.

## 7. Open decisions
1. **Nav**: new top-level **NDM** section vs nested under **Infrastructure**.
2. **% utilization now or later**: add `ifSpeed` collection in N0 (needs a telegraf +
   profiles change + re-poll) vs ship **bps-only** v1 and add %util after.
3. **Live transport**: fast-poll (A) vs WebSocket push (B).
4. **Heatmap default orientation**: device×interface snapshot (A) vs interface×time (B).
5. **Canonical metric family**: standardize on SNMP `device_if_*` vs unify SNMP+gNMI
   via relabeling.
6. **First slice to build**: the live WAN graph (most-requested) vs the interface
   table+heatmap, vs N0 metrics-readiness first (unblocks %util for both).
