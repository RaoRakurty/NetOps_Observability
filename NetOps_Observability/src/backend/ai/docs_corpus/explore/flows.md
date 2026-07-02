---
title: Flow analytics
sidebar_label: Flow analytics
sidebar_position: 3
description: Analyze traffic — top talkers, conversations, ports, protocols, and TCP flags — with filters that apply across every panel.
---

# Flow analytics

Once devices are exporting **[flow records](/send-data/flows)** (NetFlow, IPFIX, or sFlow), analyze traffic at <kbd>Flows</kbd>. The page is a set of themed sections — pick one from the left-hand section list — under a shared filter bar that scopes **every panel at once**.

:::info Sampling
Devices usually export *sampled* flows (e.g. 1 in 50 packets). All byte/packet counts on this page are **scaled by each device's sampling rate**, as the note under the filter bar says — so figures are estimates of true volume, accurate in proportion, approximate in the absolute for low-volume conversations.
:::

## The layout

- **Left section list** — Traffic Volume, Device Health, Flows, Conversations, Autonomous Systems, Geo IP, Source Ports, Destination Ports, Protocols, Flags.
- **Filter bar (top)** — free-form fields plus a flow-source selector and a direction toggle. Applies to every section.
- **Panels** — each Top-N panel has a **bar/table toggle** (top right); the table view adds sortable **Bytes / Packets / Flows** columns. Panels refresh automatically every 30 seconds.

The **time window** comes from the global range picker in the top bar (e.g. **Last 1 hour**).

## Filter the view

1. Enter any combination of:
   - **Source IP** / **Destination IP** — endpoints of the traffic,
   - **Device (exporter IP)** — only flows reported by one device,
   - **Ingress if (index)** / **Egress if (index)** — the interface index the traffic entered/left on.
2. Click **Filter**. Active filters appear as badges under the bar; **Clear** removes them all.
3. Optionally narrow the **flow source** — **All sources / NetFlow / IPFIX / sFlow** — and switch **Unidirectional / Bidirectional**:
   - **Unidirectional** counts each direction separately (Initiator → Responder).
   - **Bidirectional** merges both directions of a conversation into one row (Endpoint A ↔ Endpoint B) — usually what you want for "how much did these two exchange in total".

## The sections

### Traffic Volume

The starting point: **Top Devices (exporters)** ranked by bytes, plus **Top Ingress Interfaces** and **Top Egress Interfaces**. Answers "which device and which port carries the load".

### Flows

Two health views of the feed itself:

- **Source presence** — one badge per flow type currently arriving (`SFLOW: 12,403 flows · 11 exporters`). If a device you configured is missing here, the export isn't reaching the platform.
- **Volume over time** — bytes and packets as a time series, so you can see *when* a surge happened, not just that it did.

### Conversations

- **Top conversations (Initiator → Responder)** — the heaviest pairs, with bytes/packets/flows.
- **Top Initiator IPs** and **Top Responder IPs** — the endpoints, ranked individually.

### Autonomous Systems

**Top Initiator AS / Top Responder AS** — traffic grouped by BGP AS number, when your exporters fill the AS fields. Useful at internet edges: "how much of this is going to one provider".

### Geo IP

Traffic by **initiator and responder country**, with a **Public traffic share** stat. Private address space (RFC 1918) has no geography, so an internal lab honestly shows 0% public rather than fake countries. If GeoIP enrichment hasn't been provisioned, the panel says so and shows your platform administrator the one-time setup step (licensing prevents bundling GeoIP data, so you bring your own free country dataset).

### Source Ports / Destination Ports

Top ports by volume, annotated with well-known service names — `443 (HTTPS)`, `22 (SSH)`, `179 (BGP)` — so the destination-port panel reads as applications rather than bare numbers. Richer per-flow application identity (firewall App-ID) appears in [Log Search](/explore/logs) under the **Application** column.

### Protocols

A donut of traffic by IP protocol — TCP, UDP, ICMP, GRE, ESP, OSPF, SCTP — with share percentages.

### Flags

TCP control-flag analysis with built-in heuristics:

- **SYN-only (scan signal)** — a high share of flows that are pure SYN suggests scanning or connection failures.
- **RST-bearing (resets)** — a high reset share suggests refused/broken connections.
- The **TCP flag combinations** panel breaks down every observed combination (`SYN·ACK`, `FIN·ACK`, …).

If every flow reports empty flags, the panel tells you: that exporter isn't filling the TCP-flags field — enable full NetFlow v9/IPFIX templates on the device (sFlow carries flags natively).

### Device Health

A compact strip — average CPU, average memory, interfaces up, interfaces with recent errors — for the devices behind the flows, with links to the full **Device Monitoring** and **Interface Performance** views under <kbd>Infrastructure</kbd>.

## Worked example: chase a bandwidth spike

1. Set the top-bar range to cover the spike (e.g. **Last 6 hours**).
2. Open **Flows** → the volume time series confirms when it happened.
3. Open **Traffic Volume** → note the top exporter and egress interface.
4. Put the exporter's IP in **Device (exporter IP)**, click **Filter**.
5. Open **Conversations** → the top pair is your talker. Toggle **Bidirectional** to see total exchange.
6. Open **Destination Ports** → what service the traffic was.

## Drill from a flow to a device

Two pivots:

- **Filter down**: put an exporter or endpoint IP in the filter bar — every section now describes only that device's traffic.
- **Jump across**: paste the IP into the global **Search…** box in the top bar. The dropdown resolves it to the matching **device** (jump to its inventory entry) or offers **Search logs for "…"** to see what that device logged at the same time — see the [overview](/explore/overview#the-global-search-box).

## Troubleshooting

**All panels empty:**

- **No exporters yet** — check the **Flows → Source presence** badges. Nothing there means no flow packets are arriving; configure export per [Send flow data](/send-data/flows).
- **Time range** — flows are kept for a bounded retention window; very old ranges return nothing.
- **A filter is too tight** — check the active-filter badges under the bar and **Clear**.

**One device missing** — its export target, source interface, or flow type may be wrong; compare against a working device and confirm its flow type is arriving in **Source presence**.

**Geo IP empty** — either enrichment isn't provisioned (the panel says so) or all traffic is private address space (the page tells you the public share honestly).

**Flags all "none"** — the exporter isn't sending TCP control bits; switch the device to full v9/IPFIX templates.

All flow queries are **tenant-scoped** — you only ever see your own devices' traffic.
