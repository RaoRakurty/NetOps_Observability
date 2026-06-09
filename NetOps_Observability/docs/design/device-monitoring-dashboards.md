# Device Monitoring dashboard suite — design & implementation plan

Status: **Phase 1+2 shipped** (2026-06-09, `d6c7f7b`); Phases 3-4 proposed.
Builds on the
already-shipped `pages/DeviceMonitoring.tsx` (Infrastructure → Device Monitoring)
and the Flows rebuild (`tabs/Flows.tsx`).

References (Datadog NDM dashboards the user supplied as design targets, captured
as PDFs in /var/tmp — ⚠️ not durable):
- **Network Device Monitoring** (the master board; file `…Datacenter-Overview…`)
- **Interface Performance** (per-device/per-interface deep dive)
- **BGP / OSPF Overview** (routing-protocol session/adjacency health)
- **NDM Troubleshooting** (collection-pipeline health; two copies)
- (earlier) Netflow section + NDM overview

> Naming rule (user): no "NDM" in the UI; no duplicate item names; use distinct,
> industry-standard names for every item.

---

## 1. The five boards — purpose + panel inventory

### A. Device Monitoring (master board)
The fleet cockpit. Sections (tinted, collapsible) in reference order:
1. **Network overview** — Alerts by severity · device geomap · NetFlow Sankey
2. **Capacity: outliers & utilization forecast** — in/out throughput with DBSCAN
   outlier flag + linear forecast; in/out utilization %
3. **Network events** — syslog events · triggering SNMP traps
4. **Global search** — find any device/interface/circuit
5. **Fleet pulse, reachability & hot interfaces** — monitored/reachable/
   unreachable; network-path alerts; devices responding; highest in/out util;
   most errors; most discards
6. **Fleet aggregates** — fleet total throughput · fleet errors+discards
7. **Device inventory & uptime** — device table; **row action → Interface
   Performance scoped to that device**
8. **Device resources (CPU & memory)** — highest/avg CPU & mem; util heatmaps
9. **Interfaces** — utilization; flaps (24h); most discards/errors; top
   bandwidth & throughput in/out
10. **NetFlow traffic** — Sankey, conversations, top sources/dests, apps by
    port, top ports
11. **Throughput & line speed** — highest in/out bit rate; nominal port speed;
    device aggregate throughput (`ifHCOctets.rate` vs `ifHighSpeed`)
12. **Network Path** — latency 4h; NetPath check duration/status/active/interval
13. **Synthetic Tests** — synthetics status
14. **Anomaly Tests** — ICMP stats by device; ICMP latency; HTTP response time;
    response time by runner; ICMP latency avg
15. **Packet mix** — unicast/multicast/broadcast pkt/s in & out
16. **IPsec VPN tunnels (SNMP)** — auth/crypto failures; tunnel throughput

### B. Interface Performance (drill-down board, scoped by $device/$interface)
1. **Overview** — intro + filters ($snmp_host, $snmp_device, $interface)
2. **All interfaces** — throughput, speed & state table
3. **Top flapping interfaces** — devices with interface flaps (24h)
4. **Throughput & utilization** — top bandwidth/throughput in/out; in/out
   utilization %; bits/s in/out; throughput+util dual-axis; util heatmap
5. **Errors & discards** — most discarded/errored interfaces; errors in/out;
   discards in/out; errors+discards heatmap
6. **Oper & admin status** — ifOperStatus / ifAdminStatus over time + legends
7. **Packet mix (pkt/s)** — inbound/outbound unicast/multicast/broadcast
8. **NetFlow traffic** — Sankey, conversations, top sources/dests/ports

### C. BGP / OSPF Overview (routing health, scoped by $device/$neighbor)
1. **Device context** — system uptime by device; interface admin/oper status
2. **BGP — session health** — peers snapshot (state table); BGP peer state over
   time; established transitions; update rate; accepted prefixes
3. **OSPF — IGP health** — OSPF interfaces; OSPF neighbors; interface state over
   time; neighbor state over time
   (data source: BGP4-MIB + OSPF-MIB via SNMP)

### D. Troubleshooting (collection-pipeline health)
1. **Fleet counts** — devices monitored; flows indexed; traps indexed;
   submitted metrics
2. **Collectors/agents** — running collectors; CPU/mem; versions; restarts
3. **SNMP** — devices reachable/unreachable; device status; check duration &
   interval by device; submitted metrics by device; autodiscovery subnets
4. **Traps** — received/forwarded/stored
5. **NetFlow** — records received/flushed/stored; exporters; packets per
   exporter; flow contexts; flush duration; decoded vs processed; port rollup;
   bytes/packets received; buffer length; hash collisions
6. **NetFlow packet drop** — v5/v9/IPFIX missing flows; sequence delta/reset
7. **SNMP agent memory & ICMP reachability** — unreachable ICMP targets

---

## 2. Data inventory — what we actually collect

**SNMP metrics in VictoriaMetrics** (runtime profile `src/config/snmp_profiles.json`,
labels `device`, `index`):
- Interface: `device_if_in_octets`, `device_if_out_octets`,
  `device_if_oper_status`, `device_if_admin_status`, `device_if_speed`,
  `device_if_in_errors`, `device_if_out_errors`, `device_if_in_discards`,
  `device_if_out_discards`, `device_if_{in,out}_{ucast,mcast,bcast}_pkts`
- Device: `device_cpu_percent`, `device_cpu_1min_percent`, `device_mem_percent`,
  `device_mem_used_bytes/kb`, `device_mem_free_bytes`, `device_mem_total_kb`,
  `device_dram_bytes`, `device_disk_used_mb`/`_capacity_mb`,
  `device_storage_used`/`_size`, `device_session_count`, `device_sysuptime`
- Environment: `device_temp_celsius`, `device_temp_state`, `device_fan_state`,
  `device_psu_state`, `device_sensor_value`
- Collector self-metrics (for Troubleshooting): `collector_up`,
  `collector_target_up`, `collector_targets`, `collector_targets_reachable`,
  `collector_poll_duration_ms`, `collector_samples`

**ClickHouse `netops.flows`** — full NetFlow/IPFIX/sFlow (src/dst addr/port,
proto, in/out_if, src/dst_as, bytes, packets, sampling_rate, flow_type). Backing
the new `/api/flows/topn` + `/api/flows/top` + by-proto + timeseries endpoints.

**OpenSearch** — syslog (`netops-applogs-*`/syslog) + SNMP traps
(`netops-snmptrap-*`). **Alerts** — `/api/alerts`. **Tunnels** —
`/api/tunnels` + `tunnel_*` metrics.

**NOT collected (gaps):**
- **BGP/OSPF**: `device_bgp_peer_state`, `device_bgp_accepted_prefixes`,
  `device_bgp_fsm_transitions`, `device_ospf_nbr_state` are referenced in
  `rules.yaml` but **no collector emits them** → needs a new SNMP collector.
- **Synthetics / NetPath / ICMP-HTTP runners** — no active-probe pipeline (ties
  to the Flow Trace / Network Path feature, also a stub).
- **IPsec SNMP OIDs** — tunnels come from the tunnel collector, not vendor IPsec
  MIBs; auth/crypto-failure counters not collected.
- **GeoIP** (device geomap by country) — no geo enrichment.
- **DBSCAN outliers / forecast** — Datadog server-side analytics; we'd compute
  z-score/linear-fit client-side or in the correlation service.

---

## 3. Per-board buildability matrix

| Board | Buildable now | Needs new collection |
|-------|---------------|----------------------|
| **Device Monitoring** | ~80%: fleet pulse, resources, interfaces, aggregates, inventory, throughput/line-speed, packet mix, network events (syslog/traps), alerts, flow panels | NetPath, synthetics, anomaly-tests, IPsec, geomap, DBSCAN/forecast |
| **Interface Performance** | ~95%: all interface util/throughput/errors/discards/packet-mix/oper-admin + flow panels | (none material — fully supported) |
| **BGP / OSPF Overview** | device context (uptime, if status) only | **BGP4-MIB + OSPF-MIB collector** (the core of the board) |
| **Troubleshooting** | most: fleet counts, collector CPU/mem/restarts, SNMP reachability/duration, flow counts, trap counts | a few NetFlow internal counters (buffer, hash collisions, seq delta) we don't expose |

---

## 4. The one real collector gap — BGP/OSPF

Add SNMP collection (new `collectors/routing.go`, reusing the existing BER/USM
engine) for:
- **BGP4-MIB** (`1.3.6.1.2.1.15`): `bgpPeerState` (.3.1.2),
  `bgpPeerAdminStatus` (.3.1.3), `bgpPeerFsmEstablishedTransitions` (.3.1.15),
  `bgpPeerInUpdates`/`OutUpdates` → `device_bgp_peer_state`,
  `device_bgp_fsm_transitions`, `device_bgp_update_rate`; accepted prefixes from
  the per-AFI table where available.
- **OSPF-MIB** (`1.3.6.1.2.1.14`): `ospfNbrState` (.10.1.6),
  `ospfIfState` (.7.1.12) → `device_ospf_nbr_state`, `device_ospf_if_state`.
Labels: `device`, `neighbor`/`peer`, `index`. Opt-in via a profile flag; respects
the same tenant attribution as other metrics. This is the only board that is
data-blocked today.

---

## 5. Architecture — one dashboard engine, four boards

Rather than five bespoke pages, build a **small reusable board framework** so
every board (and future ones) is declarative and consistent.

**5.1 Shared scope bar (template variables).** A sticky bar exposing
`$device`, `$interface`, `$profile` (+ the global time range). Selecting a value
re-scopes every panel. Implemented as a context the panel primitives read; the
selection serializes to the hash (`#/infrastructure/ifperf?device=leaf1&if=Eth1`)
so boards are shareable/bookmarkable and **drill-down works**: the Device
Monitoring inventory row's "Interface Performance" action navigates to the
Interface Performance board with `?device=<id>` pre-set.

**5.2 Panel primitives** (extend what `DeviceMonitoring.tsx` already has):
- `MetricLine` (timeseries) and `MetricTop` (top-N bars) — exist; add scope-var
  interpolation into the PromQL (`device_cpu_percent{device="$device"}`).
- `MetricStat` (single scalar tile), `MetricTable` (per-series latest-value
  table with conditional coloring), `MetricHeatmap` (per-device/interface heat).
- `FlowPanel` (wraps `/api/flows/*` with the scope filters) and `LogPanel`
  (wraps the logs/traps search) — so NetFlow + Network-events sections reuse the
  Flows + Logs machinery instead of re-implementing.
- `StatusOverTime` for oper/admin/BGP/OSPF state (stepped state bands + legend).

**5.3 Declarative board spec.** Each board is an array of section groups →
panels (title, type, query/endpoint, scope). The renderer maps spec → primitives.
Keeps boards readable, names centralized (helps the no-duplicate-names rule), and
makes "make it cleaner" a spec edit, not a rewrite.

**5.4 Nav placement.** Under **Infrastructure**, a `group: "Dashboards"` cluster
(flyout subheader) — matching the user's original IA:
`Device Monitoring · Interface Performance · BGP / OSPF Overview · Troubleshooting`.
(Device Monitoring already exists; the other three are new leaves.) Optionally
pin Device Monitoring under Monitoring too (single component, two entry points).

**5.5 Naming (industry-standard, no collisions).** Board names above are unique.
Where the same panel concept appears on multiple boards (e.g. interface
throughput on both Device Monitoring and Interface Performance), the master board
uses fleet-scoped titles ("Busiest interfaces — inbound") and Interface
Performance uses scope-aware titles ("Inbound throughput (bits/s)"), so no two
visible items share a label.

---

## 6. Phased plan

- **Phase 1 — Board framework + Interface Performance (data-complete).**
  Build the scope bar, panel primitives, declarative renderer; ship Interface
  Performance fully wired (it needs no new data). Add drill-down from the Device
  Monitoring inventory row.
- **Phase 2 — Re-spec Device Monitoring onto the framework ("cleaner").**
  Reorganize the existing board to the reference's 16 sections, wiring everything
  the data supports (add packet mix, throughput/line-speed, errors/discards,
  network events via Logs, flow panels), keeping NetPath/synthetics/IPsec/geomap
  as honest "Planned" stubs.
- **Phase 3 — BGP/OSPF collector + BGP / OSPF Overview board.**
  `collectors/routing.go` (BGP4-MIB/OSPF-MIB) → metrics → the board.
- **Phase 4 — Troubleshooting board.** Wire collector self-metrics + flow/trap
  counts; expose the few missing NetFlow internal counters as needed.
- **Later — NetPath/synthetics** (active-probe pipeline; ties to Flow Trace),
  GeoIP, DBSCAN/forecast (correlation service).

**Recommended start: Phase 1 + 2** (the two highest-value, data-complete boards),
then Phase 3 (the only one needing a collector).

---

## 7. Risks / decisions to confirm
- Scope-var PromQL interpolation must stay injection-safe (allowlist label
  values; the backend `/api/metrics/query_range` already proxies PromQL — keep
  interpolation client-side to known device/interface ids).
- Per-tenant isolation: metric queries must respect the caller's visible-device
  set (the flows endpoints already do; metrics proxy needs the same care).
- BGP/OSPF collector is opt-in and adds SNMP load — gate behind a profile flag.
- "Cleaner" Device Monitoring is a re-spec of the live board; keep the current
  one working until the framework lands (no regression).
