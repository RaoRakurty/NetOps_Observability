# Placeholder build-out — data-sourcing design

Status: **in progress** (2026-06-09). Goal: replace every "Planned" stub in the
UI with a real, data-backed view. Principle (per user): **bring data in
robustly, and prefer flow telemetry (NetFlow/IPFIX/sFlow) wherever the signal
can come from flows** — it's already collected, tenant-attributed, and needs no
device-side config beyond an export target.

## Data sources available
- **Flow telemetry (IPFIX/NetFlow/sFlow)** → ClickHouse `netops.flows`
  (src/dst addr/port, proto, in/out_if, src/dst_as, bytes, packets, sampling).
  Endpoints: `/api/flows/{top,topn,by-proto,by-type,timeseries}`.
- **SNMP metrics** → VictoriaMetrics (`device_*`, labels device/index). Includes
  interface counters, CPU/mem, env, and (new) BGP/OSPF.
- **Logs & traps** → OpenSearch (`searchLogs`, signals syslog/snmptrap/applogs).
- **Alerts / incidents / findings** → `/api/alerts`, `/api/incidents`, ClickHouse
  `netops.findings` (the correlation service).
- **Tunnels** → `/api/tunnels` + `tunnel_*` metrics.
- **Inventory / intent** → discovery + NetBox (Source of Truth).
- **External feeds / active probes** → not yet present (CVE feeds, traceroute).

## Placeholder → source → feasibility

| Placeholder | Primary source | IPFIX? | Feasibility |
|---|---|---|---|
| **Threat Detection** (Security) | flows: scan fan-out (uniq dst/ports per src), risky-port traffic, top external talkers | ✅ core | **now** (add a flow fan-out endpoint) |
| **Geo IP** (Flows) | flows + GeoIP (MaxMind GeoLite2) enrichment of src/dst | ✅ | needs GeoIP DB + enrich step |
| **TCP Flags** (Flows) | flows: IPFIX `tcpControlBits` | ✅ | needs goflow2 field + CH column + router map |
| **Device Health** (Flows) | SNMP interface errors/discards/util (already in VM) | — | **now** (data exists) |
| **NetFlow per-interface** (Interface Perf) | flows filtered by in_if/out_if + device | ✅ | **now** (endpoint exists) |
| **Traffic insights** (Device Monitoring) | flows top talkers/exporters | ✅ | **now** |
| **Quality** (Monitoring) | interface errors/discards/util + tunnel QoE + flow retransmits | ✅/SNMP | **now** (composite) |
| **Events** (Monitoring) | logs + traps + alerts + findings unified stream | — | **now** (aggregate) |
| **IPsec VPN tunnels** (Device Monitoring) | `/api/tunnels` + tunnel_* metrics | — | **now** (data exists) |
| **Device Geomap** / Geographic map | GeoIP of mgmt IP, or site metadata (NetBox) | — | needs GeoIP/site data |
| **Vulnerability Management** (Security) | device OS/version (SNMP sysDescr) × CVE/PSIRT feed | — | needs external feed |
| **Compliance Monitoring** (Security) | config baselines vs intent (NetBox) | — | needs config backups |
| **Flow Trace / Network Path** | active traceroute probes (TCP/UDP/ICMP) | — | needs probe runner |
| **NetPath / Synthetics** (Device Monitoring) | active ICMP/HTTP runners | — | needs probe runner |
| **New Monitor** (Monitoring) | UI form over alert-rule engine | — | now (UI) |
| **Dashboard List** named dashboards | saved dashboards + the 4 new boards | — | now (link/curate) |
| **Command Center** (Incident Response) | incidents + notify + chat integrations | — | now (compose) |

## Build order (telemetry/IPFIX first)
1. ✅ **Threat Detection** — flow fan-out endpoint (`/api/flows/fanout`) + board.
   Done (`8965303`).
2. ✅ **Events** (Monitoring) — unified syslog+traps+alerts timeline. Done
   (`9f96523`).
3. **Device Health** (Flows) + **NetFlow per-interface** + **Traffic insights**
   (Device Monitoring) — flows/SNMP already collected; wire panels. ← next
4. **TCP Flags** — IPFIX `tcpControlBits`: goflow2 export field → vector-router
   map → `netops.flows.tcp_flags` column (ALTER) → flags breakdown endpoint +
   Flows panel.
5. **Geo IP** — GeoLite2 enrichment (vector or query-time) → country panels +
   dashboard-wide country filter.
6. **Quality** (Monitoring) — composite over interface errors/discards/util +
   tunnel QoE.
7. **IPsec** — wire tunnels into the Device Monitoring section.
8. **Device Geomap** — GeoIP/site placement.
9. **New Monitor / Dashboard List / Command Center** — UI compositions.
10. **Active-probe pipeline** — traceroute (Flow Trace/Network Path) + ICMP/HTTP
    synthetics; the one genuinely new collector.
11. **Vuln / Compliance** — external CVE feed + config-baseline pipeline (NetBox).

Each item ships independently; this doc tracks the program. See also
[[device-monitoring-dashboards]].
