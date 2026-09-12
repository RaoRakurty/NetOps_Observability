---
title: Trace paths and tunnels
description: Read measured hop-by-hop paths, path SLA probes and active service checks, and read overlay tunnel health.
page_type: task
sidebar_position: 6
---

# Trace paths and tunnels

**Investigate → Paths** groups the three surfaces that answer how traffic actually gets there: **Flow Trace** for measured hop-by-hop paths and path SLA, **Tunnels** for overlay circuit health, and **WAN Paths** for per-circuit SLA on the underlay. Every number on these pages comes from a measurement, and an empty board states what to enable rather than going blank.

## Before you begin

- An authenticated session in your tenant. Both pages read tenant-scoped stores, so another tenant's paths and tunnels are never returned.
- Path discovery is opt-in. `FEATURE_TRACEROUTE` is off by default; an administrator sets it with a target list in `TRACEROUTE_TARGETS` and grants the container `CAP_NET_RAW`.
- Path SLA needs `FEATURE_ACTIVE_PROBE` plus `STAMP_TARGETS`, and a reflector at the far end via `FEATURE_STAMP_REFLECTOR`.
- Service checks need `FEATURE_SYNTHETICS` plus the per-check target lists.

## Steps

### Step 1 - Read Path Behavior Health

Open **Investigate → Paths → Flow Trace**. The first board asks whether each path is behaving normally right now compared with its own typical behaviour. It uses an adaptive baseline rather than a fixed threshold, carries a confidence and a likely owner per path, and sorts worst first.

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

With the feature off, the board reads **No paths yet** and names the environment variables to set. `/api/probe/paths` answers with an empty list rather than an error:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/probe/paths
```

```json
[]
```

### Step 3 - Read path SLA and service checks

Below the traces, four charts show the standards-based path SLA per target from active probes: round-trip delay, one-way delay, jitter and PDV, and packet loss. They feed the Path Behavior Health board above.

The last board covers active service checks: HTTP total time and time to first byte with per-phase timings, ICMP round-trip, TCP connect time, TLS certificate days to expiry, and checks down now.

### Step 4 - Read tunnels {#tunnels}

Open **Investigate → Paths → Tunnels**. It lists overlay circuits reported through device telemetry, one row per tunnel, and refreshes every 15 seconds.

1. Read the summary tiles: **Tunnels up** of the total, **Tunnels down**, **Avg latency**, **Avg loss**. With no tunnels reported, latency and loss read as a dash rather than as zero.
2. Narrow with **Search tunnels, devices, addresses…**, which matches id, type, endpoint device, address and status.
3. Read the columns:

| Column | What it shows |
|---|---|
| **Type** | The tunnel type as the device reports it. |
| **Local** / **Remote** | Each endpoint, device name with its tunnel address. |
| **Latency** | Tinted green under 50 ms, amber under 150 ms, red above. |
| **Jitter** | Green under 30 ms, amber under 60 ms, red above. |
| **Loss** | Green under 1 per cent, amber under 3 per cent, red above. |
| **QoE** | A 0 to 10 experience score. Green at 8 and above, amber at 5, red below. |
| **Uptime** | How long the tunnel has been up, rendered as days and hours, then hours and minutes, then minutes. Zero renders as a dash. |
| **Status** | `up` or `down`. |

4. Sort by any SLA column to bring the worst tunnel to the top. The cell tinting keeps an impaired overlay readable in a long list.

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

The page states it as `No tunnels reported. IPsec / SD-WAN tunnel state appears here once a collector populates it from device telemetry.`

Three states to keep apart. A trace reading **incomplete** means the destination or an intermediate hop never answered, which is a fact about the probe rather than a fault. A hop reading a dash for loss means the method measures loss end to end and not per hop. An empty Tunnels table means nothing is exporting tunnel state, not that every tunnel is down.

## Related

- [Measure WAN paths](/infrastructure/wan-interface-metrics) for per-circuit SLA on the underlay.
- [Read the topology canvas](/infrastructure/topology-canvas) for tracing between two of your own devices.
- [Create a monitor](/monitoring/create-a-monitor) to alert on path or tunnel degradation.
