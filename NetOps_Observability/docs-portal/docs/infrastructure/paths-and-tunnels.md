---
title: Trace paths and tunnels
description: Read measured hop-by-hop paths and path SLA probes, and read overlay tunnel health.
page_type: task
sidebar_position: 6
---

# Trace paths and tunnels

**Investigate → Paths** groups the three surfaces that answer how traffic actually gets there: **Measured paths** for measured hop-by-hop paths and path SLA, **Tunnels** for overlay circuit health, and **WAN circuits** for per-circuit SLA on the underlay. Every number on these pages comes from a measurement, and an empty board says that nothing is measured rather than going blank. (Until 2026-11 the first and third pages were labelled **Flow Trace** and **WAN Paths**; their addresses did not change, so old bookmarks still open them.)

## Before you begin

- An authenticated session in your tenant. Both pages read tenant-scoped stores, so another tenant's paths and tunnels are never returned.
- Path discovery is off by default. A platform administrator turns on **Path discovery** under **Platform → Configuration → Features → Active measurement** ([Turn Correlix features on and off](/administration/features)); the prober service applies it within about 15 seconds.
- What gets traced is your workspace's own choice. While no path is measured, **Measured paths** shows three numbered steps: whether Path discovery is on, your branch edges by site (pre-ticked) to trace, and when the first trace appears. Adding them puts them on your Digital Experience target list with path tracing on; each path is then traced every minute and only your workspace sees it.
- Path SLA needs **Active path probes (STAMP)** on the same page, a target with STAMP probing on, and a STAMP reflector at the far end.
- Correlix never traces or probes an address that must not receive test packets (the server itself, link-local and cloud metadata addresses, multicast), and an internal address only when it belongs to a device in your own inventory.
- Service checks (HTTP, ICMP, TCP and certificate expiry) live on **Operations → Digital Experience → Synthetics**, not on these pages.

## Steps

### Step 1 - Read Path Behavior Health

Open **Investigate → Paths → Measured paths**. The first board asks whether each path is behaving normally right now compared with its own typical behaviour. It uses an adaptive baseline rather than a fixed threshold, carries a confidence and a likely owner per path, and sorts worst first.

### Step 2 - Read a traceroute panel

The second board shows the measured hop-by-hop path to each configured destination. The trace runs from the platform's measurement point toward each target. To trace between two of your own devices instead, use [Path Trace on the topology canvas](/infrastructure/topology-canvas#path-trace--resolve-an-ab-path).

1. Find the panel for your destination. Its title is the target followed by the hop count of that trace.
2. Read the badges. **reached** means the trace arrived. **incomplete** means it ran out first. A **path changed** badge means the route differs from the previously observed one, which is worth correlating with whatever else changed at that time.
3. Read the hop table:

| Column | What it shows |
|---|---|
| **Hop** | Position along the path, by TTL. |
| **Router** | The responding address. A silent hop renders as `* (no reply)`, which is common because many routers rate-limit or drop probe replies. |
| **RTT** | Round-trip time to that hop, or a dash where the hop did not answer. |
| **Loss** | Per-hop loss where the prober measures it, or a dash where it does not. |

4. Look for the jump in RTT between consecutive hops. That segment is where the delay is added.

The trace is Paris-consistent, so on a load-balanced network the path shown is one real path rather than an artifact of per-probe re-hashing.

With path discovery off, the board reads **No paths yet** and says that path discovery is not switched on for this installation. `/api/probe/paths` answers with an empty list rather than an error:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/probe/paths
```

```json
[]
```

### Step 3 - Read path SLA

Below the traces, four charts show the standards-based path SLA per target from active probes: round-trip delay, one-way delay, jitter and PDV, and packet loss. They feed the Path Behavior Health board above.

Service checks measure a service, not a path, so the page links to **Operations → Digital Experience → Synthetics** for them instead of repeating their charts.

### Step 4 - Read tunnels {#tunnels}

Open **Investigate → Paths → Tunnels**. It lists overlay circuits, **one row per tunnel**, and refreshes every 15 seconds. An SD-WAN tunnel is reported by both of its edges; the page folds the two reports into one row under the same tunnel identity the correlation engine uses, so a row and an RCA case about that tunnel name the same thing. IPsec and GRE tunnels read from device telemetry appear as before.

1. Read the summary tiles: **Tunnels up** of the total, **Tunnels down**, **Avg latency**, **Avg loss**. The two averages cover only the tunnels whose quality is measured, and the tiles say how many that is and how old the reading is. A tunnel known only as up or down counts toward the first two tiles and never drags an average toward zero. With no measured tunnel, latency and loss read as a dash rather than as zero. When the two ends of a tunnel report different states, **Tunnels down** says how many ends disagree.
2. Read the **Site matrix**. Each site with a tunnel end is a row and a column; a cell is every tunnel between those two sites (the diagonal is tunnels inside one site). The cell shows how many tunnels there are and is coloured by the worst state among them: red when one is down, amber when two ends disagree, green when all are up. Select a cell to narrow the table to that site pair, and select it again, or the filter button above the table, to show every tunnel. Sites follow the one site rule: a site you assign by hand wins over a discovered one. Tunnels with an end at no site are counted under the matrix.
3. Narrow with **Search tunnels, devices, sites…**, which matches devices, system-ips, colours, sites, type, state and the tunnel identity.
4. Read the columns:

| Column | What it shows |
|---|---|
| **Type** | The tunnel type: `sdwan`, `ipsec` or `gre`. |
| **End A** / **End B** | Each end: device name with its transport colour, and its site underneath. An end on a device you cannot see is named by its system-ip. |
| **State** | `up`, `down`, or **ends disagree** when the two ends report different states. **One end reporting** means only one edge has reported the tunnel so far. |
| **Latency** | Tinted green under 50 ms, amber under 150 ms, red above. |
| **Jitter** | Green under 30 ms, amber under 60 ms, red above. |
| **Loss** | Green under 1 per cent, amber under 3 per cent, red above. |
| **QoE** | A 0 to 10 experience score. Green at 8 and above, amber at 5, red below. |
| **Quality as of** | When the quality reading was taken, with its age, for example *as of 16:30 (40 min ago)*. |
| **Case** | When an open correlation case names this tunnel, a chip with its confidence that opens the case in **Investigate → RCA**. |

5. Sort by any column to bring the worst tunnel to the top. The table opens with down tunnels first, then tunnels whose ends disagree.

For an SD-WAN tunnel, latency, jitter, loss and QoE are the controller's own path statistics. The controller publishes them about 30 to 60 minutes after the fact, in 10-minute buckets, which is why every reading carries its time: it tells you how a path behaved, not what it is doing this minute. The current up or down state comes from the controller's live session state and is not delayed. When the worst quality differs between the two directions of a tunnel, the row shows the worse one, as of the older of the two readings. A tunnel with no reading shows a dash.

If path quality or open cases cannot be read at that moment, the page says so in one line above the matrix and shows dashes and no case chips; it never fills the gap with zeros.

## What you see

Every destination you configured has a traceroute panel, the SLA charts carry your probe targets, and each overlay circuit you operate has a Tunnels row whose status matches reality.

Where no collector populates tunnel state, the page says so rather than implying there are no tunnels, and `/api/tunnels` returns the column metadata with an empty result:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/tunnels
```

```json
{
  "meta": [
    {"name": "id", "type": "String"},
    {"name": "type", "type": "LowCardinality(String)"},
    {"name": "local_device", "type": "String"},
    {"name": "local_addr", "type": "String"},
    {"name": "remote_device", "type": "String"},
    {"name": "remote_addr", "type": "String"},
    {"name": "status", "type": "LowCardinality(String)"},
    {"name": "latency_ms", "type": "Float32"},
    {"name": "jitter_ms", "type": "Float32"},
    {"name": "loss_pct", "type": "Float32"},
    {"name": "qoe", "type": "Float32"},
    {"name": "uptime_s", "type": "UInt64"},
    {"name": "ts", "type": "String"}
  ],
  "data": [],
  "rows": 0,
  "rows_before_limit_at_least": 0
}
```

The page states it as `No tunnels reported yet. SD-WAN tunnels come from Infrastructure › NMS Integrations.`, with a link to that page: SD-WAN tunnels appear once a controller integration is connected, and IPsec and GRE tunnels once a device reports them.

Three states to keep apart. A trace reading **incomplete** means the destination or an intermediate hop never answered, which is a fact about the probe rather than a fault. A hop reading a dash for loss means the method measures loss end to end and not per hop. An empty Tunnels table means nothing is exporting tunnel state, not that every tunnel is down.

## Related

- [Measure WAN paths](/infrastructure/wan-interface-metrics) for per-circuit SLA on the underlay.
- [Read the topology canvas](/infrastructure/topology-canvas) for tracing between two of your own devices.
- [Create a monitor](/monitoring/create-a-monitor) to alert on path or tunnel degradation.
