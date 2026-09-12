---
title: Built-in dashboards
description: Every built-in board, what it answers and its key panels, plus the panel registry and span model behind dashboards you compose yourself.
page_type: reference
sidebar_position: 2
---

# Built-in dashboards

**Analytics → Dashboards → Dashboard List** is the directory of built-in boards, grouped as Network monitoring, Traffic and paths, and Health and operations. Below the directory sits **Your dashboards**, the composer. Boards in the Network monitoring group are driven by the [global time range](/dashboards-reports/overview#the-global-time-range), so set the window before reading the graphs.

## Network monitoring

### Device Metrics

Answers how the fleet is doing, device by device. Reached from the card, or directly at **Analytics → Metric Dashboards → Device Monitoring**. The **Bandwidth Utilization** card opens the same board.

| Section | Panels |
|---|---|
| Fleet vitals and reachability | Active alerts by severity, and a device inventory and reachability table with a state dot per device |
| Fleet aggregates | Fleet total throughput, and fleet errors and discards |
| Device inventory and uptime | Longest device uptime |
| Device resources | Average CPU and memory over the window, plus the highest-CPU and highest-memory devices |
| Interfaces | Busiest interfaces inbound and outbound |
| Flows | Busiest talkers and top flow exporters |
| Tunnels | Current per-tunnel state |

To scope to one device's interfaces, find the device in the reachability table and select its row link. The Interface Metrics board opens pre-scoped to that device.

### Interface Metrics

Answers what an interface is doing: throughput, errors, flaps and who is on it. Also at **Analytics → Metric Dashboards → Interface Performance**.

The board starts fleet-wide and narrows through the scope bar: choose a device, then choose one of that device's interfaces to pin every time-series panel to it.

| Panel | What it shows |
|---|---|
| All interfaces, leaders | Top 10 by inbound and outbound throughput |
| Top flapping interfaces | Most operational-state changes in the last 24 hours |
| Throughput and utilization | Bits per second each way, and per cent of interface speed |
| Errors and discards | The interfaces taking the most of each, with trend lines |
| Packet mix | Unicast, multicast and broadcast rates, which is the broadcast-storm tell |
| Oper and admin status | State over time as stepped lines, so a flap is obvious |
| NetFlow traffic | Top sources and destinations crossing the selected device |

### BGP Metrics

Answers whether routing is converged and stable. Also at **Analytics → Metric Dashboards → Protocol Monitoring**. It covers three routing planes: BGP session health with peer state, established-state transitions and prefixes received; OSPF neighbor and interface state; and IS-IS adjacency state and adjacency counts per device. A device-context row carries system uptime and interfaces up.

The state panels are stepped lines. A flat line at the top value is healthy, and any step down is a session or adjacency event worth correlating against **Explore → Events**.

**Analytics → Metric Dashboards → BGP Operations** is the consolidated routing-outage screen: routing status, RPKI, AS paths, churn and ownership in one place. See [BGP operations](/bgp/overview).

### WAN Interface Metrics

Answers whether each WAN circuit is meeting its SLA. The card opens **Investigate → Paths → WAN Paths**, which has its own page: [Measure WAN paths](/infrastructure/wan-interface-metrics).

## Traffic and paths

| Card | Opens | What it answers |
|---|---|---|
| Flow Analytics | **Explore → Flows** | Who is talking to whom. See [Analyse flows](/explore/flows). |
| Network Path | **Investigate → Paths → Flow Trace** | Where traffic goes and where it degrades. |
| Quality | **Operations → Network Health** | Link-quality measurement. |

## Health and operations

| Card | Opens | What it answers |
|---|---|---|
| Troubleshooting | **Investigate → Troubleshooting** | The platform watching its own collection: flow sources seen in the last hour by protocol and exporter, fleet counts, collector reachability and poll timings, SNMP reachable versus configured, the flow pipeline, and traps received. Open this first when a monitoring board looks empty, because it says whether data is arriving at all. |
| Data Sources | **Administration → Data sources → Data Sources** | The ingestion inventory. See [Data sources](/onboard-devices/data-sources). |
| Events | **Explore → Events** | The merged event timeline. See [Review the event feed](/explore/events). |
| Threat Detection | **Security → Threat Detection** | Security findings and critical alerts. |

**Analytics → Dashboards → Demo Showcase** renders the same live panel registry with different chrome, as a sales surface.

## Dashboards you compose yourself

**Your dashboards** sits below the directory. A dashboard is a named, ordered list of panel cells rendered through the same registry the curated boards use, and it is persisted server-side as a saved object of type `dashboard`, scoped to your tenant.

1. Select **+ New dashboard**.
2. Select **+ Add panel** and pick from the categorised registry. Each entry shows its default width.
3. Set each panel's width from the span control, reorder with the move controls, and remove with the remove control.
4. Name the dashboard and select **Save**.

The layout model is a 12-column grid, and a span is the only layout unit. The five valid spans are 3, 4, 6, 8 and 12 columns, and a board holds at most 40 cells. Reordering and resizing cover composition without a drag-layout dependency.

### The panel registry

29 panels in nine categories:

| Category | Panels |
|---|---|
| Health and KPIs | KPIs, Site availability, Stack performance |
| Resources | CPU, Memory, Storage and Bandwidth utilization gauges, plus CPU, memory, storage and temperature saturation trends |
| Interfaces | Interface utilization, errors and discards, each top-N |
| Routing | BGP peers, OSPF neighbors |
| Active measurement | Probe RTT, probe jitter, probe loss |
| Alerts | Alerts by severity, active alerts, recent incidents |
| Traffic | WAN interfaces, traffic in and out, top hosts, flows by protocol, tunnel health |
| Inventory | Devices by vendor |
| Topology | Topology |

A board saved by a newer version can hold a panel type this version does not know. That cell is **kept in the saved layout untouched**. The editor discloses it above the grid, stating how many panels come from a newer version and cannot render here. It is never silently dropped, so opening and saving an unfamiliar board does not destroy it.

An empty board says so and offers to add the first panel. A board list that fails to load says the load failed rather than showing zero dashboards.

## Troubleshooting

| Symptom | What it means |
|---|---|
| Panels read no data on Device or Interface Metrics | Open the Troubleshooting board. Where collectors show zero reachable targets, the fault is collection rather than the dashboard. Start at [verify monitoring](/onboard-devices/verify-monitoring). |
| The Interface dropdown is empty after picking a device | Interface options come from that device's collected metrics. A freshly added device needs a poll cycle or two. |
| Flow panels are empty while SNMP panels work | Flow export is not reaching the platform. Check the flow-sources panel on the Troubleshooting board, then [flows setup](/send-data/flows). |
| A graph looks flat or truncated | Check the top-bar range. Each section remembers its own last-used window. |
