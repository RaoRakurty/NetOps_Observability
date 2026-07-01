---
title: WAN Interface Metrics
sidebar_label: WAN Interface Metrics
sidebar_position: 5
description: Per-WAN-interface SLA (latency/jitter/loss/QoE/availability) measured to a derived target, with live throughput.
---

# WAN Interface Metrics

**WAN Interface Metrics** (<kbd>Infrastructure → WAN Interface Metrics</kbd>) gives every WAN interface its own SLA row: live utilization and throughput, plus latency, jitter, loss, QoE, and availability *measured to a target* — with the target and the measurement method shown honestly on every row. The table refreshes every 5 seconds, so the in-row sparkline advances live.

## Which interfaces appear

- Every interface on a **WAN device**. WAN devices are matched by a name pattern from the measurement policy — by default any device whose name contains `wan`, `edge`, `gw`, or `dmz`.
- Plus any interface **directly connected to** a WAN device (marked with a `linked` badge) — so a WAN router *and* the core link facing it are both measured.
- Management interfaces are never included.

## Read a row

1. Check the summary tiles first: **WAN interfaces** (and how many have a measured SLA), total **Throughput** (with in/out split), **Peak utilization** (the busiest interface), and **Interfaces down**.
2. Use the search box (**Search devices, interfaces, targets…**) to narrow the table; the default sort is by utilization, busiest first. Click any column header to re-sort.
3. Read the columns:

| Column | What it shows |
| --- | --- |
| **Router / Interface** | The device and interface name (e.g. `Ethernet1`). A `linked` badge means this interface sits on a non-WAN device but faces a WAN device. |
| **Utilization** | Live utilization with a color bar — green under 70%, amber under 90%, red above. |
| **↓ In / ↑ Out** | Current throughput in each direction. |
| **Live** | A small sparkline of recent throughput that advances on every poll; hover for the current and peak values. |
| **Measured to** | The measurement target: a provenance chip (**Peer**, **Next-hop**, or **Anchor**) plus the remote device, its interface, and the target address. |
| **Latency / Jitter / Loss / QoE / Avail.** | The resolved SLA, heat-tinted (e.g. latency green under 50 ms, amber under 150 ms; loss green under 1%, amber under 3%; availability red below 95%). Each cell shows "—" until something actually measures it — never a fabricated number. |
| **Measured by** | Which measurement source won for this row: a tier badge (**T1**–**T5**) plus the method name. |
| **Status** | The interface's operational state — `up` or `down`. |

## How the measurement target is derived

Each interface measures to a **derived target** — you don't pair circuits by hand. The first rule that matches wins:

1. **Operator override** — a next-hop you've configured for the device (or the specific interface), such as the ISP gateway. Shown as **Next-hop**.
2. **Directly-connected peer** — the neighbor learned from discovery on that interface (typical inside a lab or private WAN). Shown as **Peer**.
3. **Reachability anchor** — a well-known public address (defaults are public DNS resolvers), used for internet-facing interfaces where the far end isn't yours to probe. Shown as **Anchor**.

## How the SLA numbers are chosen

Several sources can measure the same target. Correlix ranks them by **closeness to the user experience** and, per field, uses the best available:

**T1** application-level checks → **T2** active path probes → **T3** device-native measurements → **T4** passive measurement → **T5** flow-derived. The **Measured by** column shows the winning tier and method for each row, so a number is never anonymous. If no probe is measuring the target yet, the SLA cells stay "—" while utilization, throughput, and status still populate from interface metrics.

## Tune the measurement policy

The measurement policy — the WAN device name pattern, the anchor addresses, per-device/per-interface next-hop overrides, and whether connected interfaces are included — is per-tenant. There is currently **no console form** for it; it is read and written through the platform API (`GET`/`PUT /api/wan/policy`) using an [API token](/administration/api-access). For example, setting a next-hop override:

```json
{
  "wan_pattern": "wan|edge|gw|dmz",
  "next_hops": { "edge-router-1/Ethernet1": "203.0.113.1" }
}
```

Overrides take effect on the next refresh — the row's **Measured to** chip changes to **Next-hop**.

Active SLA measurement of the derived targets is an opt-in capability; if every row shows only utilization and "—" SLAs, ask your administrator to enable the WAN echo measurement feature and the active prober.

## Verify

- Every interface you consider a WAN circuit has a row (check the `linked` rows too).
- Each row's **Measured to** target is sensible — a real next-hop, the true far-end peer, or an anchor for internet-facing links.
- SLA cells fill within a few probe cycles; **Measured by** shows the tier you expect.

## Troubleshooting

- **The table is empty** — no device names match the WAN pattern, or the devices aren't exporting interface metrics yet. Check the device names against the pattern above (adjust it via the policy API), and confirm collection with [Verify monitoring](/onboard-devices/verify-monitoring).
- **SLA columns stay "—"** — nothing is probing the derived target yet. Confirm the active measurement features are enabled, and that the target is reachable from the prober ([connectivity requirements](/reference/connectivity-requirements)).
- **The wrong target is being measured** — set an explicit next-hop override for that device or interface via the policy API; overrides always win over the derived peer/anchor.

## Related

- [Flow Trace & Tunnels](/infrastructure/paths-and-tunnels) — hop-by-hop paths and overlay tunnel health.
- [Topology Canvas → Path Trace](/infrastructure/topology-canvas#path-trace--resolve-an-ab-path) — per-hop metrics along a device-to-device path.
