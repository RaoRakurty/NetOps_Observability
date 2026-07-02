---
title: Built-in dashboards
sidebar_label: Built-in dashboards
sidebar_position: 2
description: A tour of every built-in board — what each answers, its key panels, and how to drill down.
---

# Built-in dashboards

<kbd>Dashboards → Dashboard List</kbd> is the directory of every built-in board. Cards are grouped into **Network monitoring**, **Traffic & paths**, and **Health & operations**; clicking a card opens the board it names. The boards in the Network monitoring group are driven by the [global time range](/dashboards-reports/overview#the-global-time-range) in the top bar — set the window before you read the graphs.

## Network monitoring

### Device Metrics

*Answers: "How is the fleet doing, device by device?"* Also reachable as <kbd>Infrastructure → Device Monitoring</kbd>; the **Bandwidth Utilization** card opens this same board.

Key panels, top to bottom:

- **Fleet vitals & reachability** — active alerts by severity, and the **Devices — inventory & reachability** table (a green/red dot per device).
- **Fleet aggregates** — fleet total throughput (bps) and fleet errors + discards (/s).
- **Device inventory & uptime** — longest device uptime.
- **Device resources — CPU & memory** — average CPU and memory utilization over the window, plus the devices with the highest CPU and memory.
- **Interfaces** — busiest interfaces inbound and outbound (bps).
- **Flows** — busiest talkers and top flow exporters (bytes).
- **Tunnels — current state** — per-tunnel status.

**Drill down to one device's interfaces:**

1. Open <kbd>Dashboards → Dashboard List</kbd> and click **Device Metrics**.
2. In the **Devices — inventory & reachability** table, find the device (the dot shows reachable/unreachable).
3. Click the device's row link ("Open Interface Performance scoped to this device"). The Interface Metrics board opens pre-scoped to that device.

### Interface Metrics

*Answers: "What is this interface actually doing — throughput, errors, flaps, and who is on it?"* Also reachable as <kbd>Infrastructure → Interface Performance</kbd>.

The board starts fleet-wide and narrows through the **scope bar** at the top:

1. In the **Device** dropdown, pick a device (or leave **All devices** for fleet leaders).
2. Once a device is chosen, the **Interface** dropdown lists that device's interfaces — pick one to pin every time-series panel to it, or leave **All interfaces**.

Panels, in reading order:

- **All interfaces — leaders** — top 10 by inbound and outbound throughput.
- **Top flapping interfaces** — most operational-state changes in the last 24 h (a flap detector).
- **Throughput & utilization** — inbound/outbound bits per second and percent-of-speed utilization for the selected scope.
- **Errors & discards** — the interfaces taking the most errors and discards, plus inbound-vs-outbound trend lines.
- **Packet mix** — unicast / multicast / broadcast packet rates (a broadcast-storm tell).
- **Oper & admin status** — operational and administrative state over time (stepped lines make flaps obvious).
- **NetFlow traffic** — top sources (ingress) and top destinations (egress) crossing the selected device, from flow records.

### BGP Metrics

*Answers: "Is routing converged and stable?"* Also reachable as <kbd>Infrastructure → Protocol Monitoring</kbd>. It covers all three routing planes:

- **Device context** — system uptime and interfaces-up per device.
- **BGP — session health** — peer state over time, established-state transitions per minute (session flaps), and prefixes received per peer.
- **OSPF — IGP health** — neighbor state and interface state over time.
- **IS-IS — fabric IGP** — adjacency state over time and adjacency counts per device.

Reading tip: the state panels are stepped lines — a flat line at the top value is healthy; any step down is a session or adjacency event worth correlating with <kbd>Monitoring → Events</kbd>.

### WAN Interface Metrics

*Answers: "Is each WAN circuit meeting its SLA?"* A per-WAN-interface table: utilization, in/out throughput and status with a live sparkline, plus latency, jitter, loss, QoE and availability measured to a derived target. It has its own full page — see [WAN Interface Metrics](/infrastructure/wan-interface-metrics).

## Traffic & paths

- **Flow Analytics** — traffic exploration over flow records (talkers, protocols, filters). See [Flows](/explore/flows).
- **Network Path** — hop-by-hop path views for tracing where traffic goes and where it degrades.
- **Quality** — link-quality measurements (also <kbd>Monitoring → Link Quality</kbd>).

## Health & operations

- **Troubleshooting** — *the platform watching its own collection*: flow sources seen in the last hour (by protocol and exporter), fleet counts, collector reachability and poll timings, SNMP reachable-vs-configured, the flow pipeline, and SNMP traps received. Open this board first when a monitoring board looks empty — it tells you whether data is arriving at all.
- **Data Sources** — the ingestion inventory (see [Data sources](/onboard-devices/data-sources)).
- **Events** — the event stream (also <kbd>Monitoring → Events</kbd>).
- **Threat Detection** — security findings and critical alerts.

## Saved dashboards

Below the directory sits the **Saved dashboards** slot — the future home for dashboards you compose yourself from KPI tiles, saved log searches, flow charts, and metric queries. Composable dashboards are not available yet; the built-in boards above are the current catalog.

## Troubleshooting

- **Panels show "no data" on Device or Interface Metrics.** Open the **Troubleshooting** board: if **Collectors** shows zero reachable targets or **SNMP reachability** is flat, the problem is collection, not the dashboard — start at [verify monitoring](/onboard-devices/verify-monitoring).
- **The Interface dropdown is empty after picking a device.** Interface options are discovered from that device's collected metrics; a freshly added device needs a poll cycle or two before its interfaces appear.
- **Flow panels are empty while SNMP panels work.** Flow panels need flow export (NetFlow/IPFIX/sFlow) from the device — check the flow-sources panel on the Troubleshooting board, then [flows setup](/send-data/flows).
- **A graph looks flat or truncated.** Check the top-bar time range; each section remembers its own last-used window, so the board may be on a different range than the one you set elsewhere.
