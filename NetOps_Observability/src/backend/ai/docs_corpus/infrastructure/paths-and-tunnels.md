---
title: Flow Trace & Tunnels
sidebar_label: Flow Trace & Tunnels
sidebar_position: 6
description: Measured hop-by-hop paths, path SLA probes, active service checks, and overlay tunnel health.
---

# Flow Trace & Tunnels

The **Paths & Overlays** group answers *how does traffic actually get there*: **Flow Trace** shows measured hop-by-hop paths and path SLAs, and **Tunnels** shows overlay circuit health. Both are evidence pages — every number comes from a real measurement, and empty states say what to enable rather than going blank.

## Flow Trace

<kbd>Infrastructure → Flow Trace</kbd> visualizes the active-measurement pipeline in four boards, top to bottom.

### Path Behavior Health

The first board asks: *is each path behaving normally right now, compared with its own typical behavior?* It uses an adaptive baseline (not fixed thresholds), shows a confidence and a likely owner per path, and sorts worst-first — so the path most worth your attention is the first row.

### Network paths (traceroute)

This board shows the measured hop-by-hop path to each configured destination. Targets are configured by your administrator on the platform (the trace runs *from the platform's measurement point toward each target* — to trace between two of your own devices instead, use the [Topology Canvas → Path Trace mode](/infrastructure/topology-canvas#path-trace--resolve-an-ab-path)).

To read a path:

1. Find the panel for your destination — the title shows the target and its hop count (e.g. `8.8.8.8 — 9 hops`).
2. Check the badges: **reached** (green) means the trace got to the destination; **incomplete** (amber) means it ran out before arriving. A red **path changed** badge means the route differs from the previously observed one — worth correlating with whatever else changed at that time.
3. Read the hop table, one row per hop:
   - **Hop** — the position (TTL) along the path.
   - **Router** — the responding address, or `* (no reply)` for silent hops (common; many routers rate-limit or drop probe replies).
   - **RTT** — round-trip time to that hop.
   - **Loss** — per-hop loss where the prober measures it; "—" where it doesn't.
4. Look for where RTT jumps between consecutive hops — that segment is where the delay is added.

The trace method is consistent across load-balanced (ECMP) networks, so the path you see is a real single path, not an artifact of per-probe re-hashing.

:::note Enabling path discovery
If the board shows *No active path measurements*, path discovery is off. An administrator enables it on the platform with `FEATURE_TRACEROUTE=true` and a target list (`TRACEROUTE_TARGETS`); a TCP-based method is available for paths where firewalls swallow ICMP. See [connectivity requirements](/reference/connectivity-requirements).
:::

### Path SLA (probes)

Below the traces, four leaderboards show the standards-based path SLA per target, from active probes: **round-trip delay**, **one-way delay**, **jitter/PDV**, and **packet loss**. These feed the Path Behavior Health board above. Enabled by your administrator (`FEATURE_ACTIVE_PROBE=true` plus probe targets, and a reflector at the far end).

### Service checks (synthetics)

The last board covers active service-level checks: **HTTP total time** and **time to first byte** (with per-phase timings — DNS, connect, TLS, first byte), **ICMP round-trip**, **TCP connect time**, **TLS certificate days-to-expiry**, and **checks down now**. Enabled with `FEATURE_SYNTHETICS=true` plus per-check target lists.

## Tunnels

<kbd>Infrastructure → Tunnels</kbd> lists overlay circuits — IPsec, SD-WAN, GRE — reported through device telemetry, one row per tunnel. The table refreshes every 15 seconds.

1. Check the summary tiles: **Tunnels up** (of total), **Tunnels down**, **Avg latency**, **Avg loss**.
2. Use the search box (**Search tunnels, devices, addresses…**) to narrow by tunnel ID, type, endpoint device, address, or status.
3. Read the columns:

| Column | What it shows |
| --- | --- |
| **Type** | The tunnel type (e.g. IPsec, GRE, SD-WAN overlay). |
| **Local / Remote** | Each endpoint: device name with its tunnel address. |
| **Latency** | Heat-tinted: green under 50 ms, amber under 150 ms, red above. |
| **Jitter** | Green under 30 ms, amber under 60 ms. |
| **Loss** | Green under 1%, amber under 3%, red above. |
| **QoE** | A 0–10 experience score: green at 8+, amber at 5+, red below. |
| **Uptime** | How long the tunnel has been up (e.g. `3d 4h`). |
| **Status** | `up` (green) or `down` (red). |

4. Sort by any SLA column to surface the worst tunnel first — the cell tinting makes an impaired overlay readable at a glance even in a long list.

If the page shows *No tunnels reported*, no device telemetry is populating tunnel state yet — tunnels appear once your devices or SD-WAN estate export it. Confirm collection with [Verify monitoring](/onboard-devices/verify-monitoring).

## Verify

- Each expected destination has a traceroute panel, and it reads **reached**.
- Path SLA leaderboards show your probe targets with plausible delay/loss numbers.
- Every overlay circuit you operate has a Tunnels row, and its status matches reality.

## Troubleshooting

- **A trace reads "incomplete"** — the destination (or an intermediate hop) never answered. Try the TCP trace method if a firewall sits on the path, or accept it if the destination simply doesn't reply to probes.
- **"path changed" won't clear** — the route genuinely differs from the prior observation; the badge reflects the latest comparison. Investigate what re-routed (Protocol Monitoring shows adjacency changes).
- **Hops show "—" for loss** — the prober measures loss end-to-end but not per-hop for that method; it's an honest gap, not a failure.
- **Tunnels SLA looks frozen** — check the device-side export; rows only update as telemetry arrives.

## Related

- [WAN Interface Metrics](/infrastructure/wan-interface-metrics) — per-circuit SLA on the underlay.
- [Monitoring](/monitoring/overview) — alert on path or tunnel degradation.
