---
title: Measure WAN paths
description: Read one row per WAN interface - live utilization and status plus a measured SLA to a derived target, with the tier that measured it.
page_type: task
sidebar_position: 7
---

# Measure WAN paths

**Investigate → Paths → WAN Paths** puts one row on screen for every WAN interface, and for every interface directly connected to a WAN device. The page heading reads **WAN Interface Metrics**. Each row carries live utilization and status from the interface itself, and a latency, jitter, loss, QoE and availability SLA measured to a target the platform derived for that interface. An SLA cell with no measurement behind it reads as a dash, never as a number. Below the table the page carries the derived paths and endpoints, and the measurement policy that produces both.

## Before you begin

- Devices exporting `device_if_*` interface metrics. See [Verify monitoring](/onboard-devices/verify-monitoring).
- WAN devices matched by the measurement policy. The default name pattern is `wan|edge|gw|dmz`.
- At least one measurement source for the SLA columns. Utilization and status populate without one; latency, jitter, loss, QoE and availability do not.

## Steps

### Step 1 - Read the summary tiles

1. Open **Investigate → Paths → WAN Paths**. The table polls every 5 seconds, so the in-row sparkline advances live.
2. Read the four tiles: **WAN interfaces** with the count that has a measured SLA, **Throughput** with its inbound and outbound split, **Peak utilization** for the busiest interface, and **Interfaces down**.

With no rows, peak utilization reads as a dash rather than as zero per cent.

### Step 2 - Read a row

| Column | What it shows |
|---|---|
| **Router** and **Interface** | The device and its interface. An interface marked **linked** is not itself a WAN interface but is directly connected to a WAN device, so both ends of a lab WAN hop are measured. |
| **Utilization**, **In**, **Out** | Live load as a bar plus a percentage, and the two throughput directions. All three read as a dash where no interface counters arrived. |
| **Live** | An inline sparkline of recent throughput, redrawn each poll. |
| **Measured to** | The derived target and how it was derived: **Peer** for a directly connected peer learned over LLDP, **Next-hop** for an ISP next hop, or **Anchor** for a public-DNS reachability anchor. |
| **Latency**, **Jitter**, **Loss**, **QoE**, **Avail.** | The measured SLA. Each cell is tinted, and each reads as a dash when nothing measured it. |
| **Measured by** | The winning measurement tier and method for that row. |
| **Status** | `up` or `down`, or a dash when no operational state was read. |

### Step 3 - Read the measurement tier

The SLA columns resolve through a five-tier ranking, and the tier closest to the user experience wins:

| Tier | Source |
|---|---|
| T1 | Application |
| T2 | Active path probe |
| T3 | Device-native measurement, such as STAMP |
| T4 | Passive measurement |
| T5 | Flow |

The **Measured by** badge names the winning tier and method per row, so a latency figure always says where it came from. Two rows in the same table can be measured by different tiers, and the badge is how you tell.

### Step 4 - Narrow the table

Use **Search devices, interfaces, targets…** to match on device, interface, remote device, target, target label or measurement method. The counter beside the box states how many of the total rows match. Sort by **Utilization** to bring the busiest circuit to the top, which is the default order.

### Step 5 - Read the measured paths and the endpoint registry

Below the table the page carries two derived sections. Neither is stored: the
platform re-derives both from the interface addresses, the neighbours it learned
and the measurement policy.

**Measured paths** puts one row on each interface-to-target link, with the local
device and interface, the far end, and how the target was derived. A row marked
**held** is in the registry and is not being measured.

**Endpoint registry** lists every interface the projection covers, its address,
the address the far end measures to, its site, and its derived target. An
interface marked **linked** is not on a WAN device. It is directly connected to
one, so the platform measures it too.

Both sections are empty until an interface has an address and either a neighbour
on the wire, a declared ISP next-hop or a reachability anchor. The empty state
says which of the three is missing.

### Step 6 - Set the measurement policy

**Measurement policy** is the only stored part of this page. Saving it re-derives
the endpoint registry and the measured paths above.

1. Set the **WAN device name pattern**. A device whose name matches is a WAN
   device. Matching ignores case, and the default is `wan|edge|gw|dmz`.
2. Leave **Also measure interfaces directly connected to a WAN device** selected
   to keep both ends of a WAN hop measured.
3. Set the **Reachability anchors** an interface measures to when it has neither
   a neighbour on the wire nor a declared next-hop. Separate them with commas.
   The defaults are `1.1.1.1` and `8.8.8.8`.
4. Add an **ISP next-hop override** for each interface whose far end is an ISP.
   A next-hop is where your ownership of the path hands off to the ISP. Key it by
   device, or by `device/interface` for a single interface.
5. Select **Save policy**.

`infrastructure:write` is required to save. Without it the section renders the
stored policy read-only and says so, rather than offering a control that is
refused.

## What you see

Every WAN interface you operate has a row, its utilization matches the device, and each SLA column either carries a measured number with a tier badge or an honest dash.

On a deployment with no WAN interface matched yet, `/api/wan/interfaces` says so with a null list rather than an empty success:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/wan/interfaces
```

```json
{"interfaces":null}
```

The page states the same thing and names both halves of the fix: the interfaces appear once the matched devices export `device_if_*` metrics, and the SLA columns populate once a probe measures each interface's derived target.

## Related

- [Trace paths and tunnels](/infrastructure/paths-and-tunnels) for the probes that feed the SLA columns.
- [Read the topology canvas](/infrastructure/topology-canvas#path-trace--resolve-an-ab-path) for resolving a path between two of your own devices.
- [Link quality](/monitoring/link-quality) for alerting on a degrading circuit.
