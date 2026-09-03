---
title: Analyse flows
description: Analyse traffic from NetFlow, IPFIX and sFlow records - top talkers, conversations, ports, protocols and TCP flags - with one filter bar across every panel.
page_type: task
sidebar_position: 4
---

# Analyse flows

**Explore → Flows** reads the unsampled flow store in ClickHouse. It is a set of themed sections under one filter bar that scopes every panel at once, so a filter you set for top talkers also narrows protocols, ports and flags.

## Before you begin

- Devices exporting flow records. Correlix listens on UDP 2055 for NetFlow, UDP 4739 for IPFIX and UDP 6343 for sFlow. See [Send flow data](/send-data/flows).
- A window chosen in the top-bar range picker. Panels refresh every 30 seconds.
- An authenticated session. Every flow query is tenant-scoped before it runs.

:::note Sampling
Devices usually export sampled flows. Byte and packet counts are scaled by each device's sampling rate, so figures are proportionally accurate and approximate in absolute terms for a low-volume conversation. The log-search view of flows reads a separate 1-in-50 sample and says so; this page reads the canonical store.
:::

## Steps

### Step 1 - Choose a section

The left-hand list holds ten sections: **Traffic Volume**, **Device Health**, **Flows**, **Conversations**, **Autonomous Systems**, **Geo IP**, **Source Ports**, **Destination Ports**, **Protocols** and **Flags**.

Each Top-N panel has a bar-or-table toggle. The table view adds sortable **Bytes**, **Packets** and **Flows** columns.

### Step 2 - Filter every panel at once

1. Enter any combination of **Source IP**, **Destination IP**, **Device (exporter IP)**, **Ingress if (index)** and **Egress if (index)**.
2. Select **Filter**. Active filters appear as badges under the bar, and **Clear** removes them all.
3. Narrow the flow source to **NetFlow**, **IPFIX** or **sFlow**, or leave it on all sources.
4. Choose a direction:
   - **Unidirectional** counts each direction separately, as initiator to responder.
   - **Bidirectional** merges both directions of a conversation into one row, which is what you want for how much two endpoints exchanged in total.

### Step 3 - Confirm the feed is arriving

Open the **Flows** section. **Source presence** shows one badge per flow type currently arriving, in the form `TYPE: N flows · M exporters`. A device you configured that is missing here is not exporting to the platform, so fix the export before reading any other panel.

**Volume over time** charts bytes and packets, so you can see when a surge happened rather than only that it did.

### Step 4 - Follow the traffic

- **Traffic Volume** ranks exporters and the ingress and egress interfaces carrying the load.
- **Conversations** ranks the heaviest pairs, and the initiator and responder endpoints individually.
- **Autonomous Systems** groups by BGP AS number, where the exporter fills the AS fields.
- **Geo IP** breaks traffic down by initiator and responder country and states the public-traffic share. Private address space has no geography, so an internal lab honestly reads zero per cent public rather than inventing countries. Where GeoIP enrichment has not been provisioned, the panel says so instead of showing an empty map.
- **Source Ports**, **Destination Ports** and **Protocols** rank the port and protocol mix.
- **Flags** reads TCP control bits. Where every TCP flow reports empty flags, the panel states that the exporter is not filling `tcpControlBits` and names how to turn it on, rather than rendering the flags as zero.

## What you see

Panels populated from the flow store, and a **Source presence** badge for each protocol actually arriving. The live lab has one flow type arriving from two exporters:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/flows/by-type
```

```json
{
  "meta": [
    {"name": "flow_type", "type": "LowCardinality(String)"},
    {"name": "bytes_total", "type": "UInt64"},
    {"name": "packets_total", "type": "UInt64"},
    {"name": "flows", "type": "UInt64"},
    {"name": "exporters", "type": "UInt64"}
  ],
  "data": [
    {"flow_type": "ipfix", "bytes_total": "173192", "packets_total": "1893", "flows": "268", "exporters": "2"}
  ],
  "rows": 1
}
```

That response renders as one badge reading `IPFIX: 268 flows · 2 exporters`. A protocol absent from the response has no badge, because no record of that type arrived.

Top talkers come from `/api/flows/top`, which returns ClickHouse column metadata alongside the rows so the type of every column is stated:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/flows/top
```

```json
{
  "meta": [
    {"name": "src", "type": "String"},
    {"name": "dst", "type": "String"},
    {"name": "bytes_total", "type": "UInt64"},
    {"name": "packets_total", "type": "UInt64"},
    {"name": "flows", "type": "UInt64"}
  ],
  "data": [
    {"src": "172.16.13.2", "dst": "224.0.0.5", "bytes_total": "38420", "packets_total": "385", "flows": "54"},
    {"src": "172.16.14.2", "dst": "224.0.0.5", "bytes_total": "36288", "packets_total": "378", "flows": "54"},
    {"src": "172.16.11.2", "dst": "224.0.0.5", "bytes_total": "36288", "packets_total": "378", "flows": "54"},
    {"src": "172.16.15.2", "dst": "224.0.0.5", "bytes_total": "36288", "packets_total": "378", "flows": "54"},
    {"src": "172.16.13.1", "dst": "224.0.0.5", "bytes_total": "24952", "packets_total": "364", "flows": "51"}
  ],
  "rows": 5,
  "rows_before_limit_at_least": 5
}
```

The counters arrive as strings because ClickHouse serialises `UInt64` that way. `224.0.0.5` is the OSPF all-routers multicast group, so this lab's heaviest talkers are its routing protocol, which is what an idle fabric looks like.

## Related

- [Send flow data](/send-data/flows) for configuring the exporters and the listener ports.
- [Search logs](/explore/logs) for the sampled flow index and its estimate warning.
- [Trace paths and tunnels](/infrastructure/paths-and-tunnels) for measured paths rather than observed conversations.
