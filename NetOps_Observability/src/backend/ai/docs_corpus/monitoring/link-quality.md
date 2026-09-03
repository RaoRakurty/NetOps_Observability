---
title: Track link quality
sidebar_label: Track link quality
description: Track interface error and discard ratios, saturation risk and overlay tunnel health on the Network Health board.
page_type: task
sidebar_position: 5
---

# Track link quality

The Network Health board answers a different question from the traffic
dashboards. Not "how busy is this link", but "is this link healthy". It scores
interfaces on rates and ratios rather than raw counters, so a quiet link that
drops a high fraction of its packets cannot hide behind a busy link's volume.

Use it to find the interface that is degrading before an availability rule fires
on it.

## Before you begin

- SNMP interface counters flowing from the devices you care about. The board is
  built entirely on `device_if_*` series plus tunnel measurements. See
  [verify monitoring](/onboard-devices/verify-monitoring).
- `device_if_speed` populated on the interfaces you want saturation figures for.
  The utilization expressions divide by it and skip an interface reporting `0`.
- Active probe or tunnel telemetry, if you want the overlay section to hold
  anything. See [paths and tunnels](/infrastructure/paths-and-tunnels).

## Steps

1. Go to **Operations → Network Health**.
2. Set the time range with the global range picker. Every panel on the board
   honours it.
3. Read **Link error quality** first. It is the section that finds a link nobody
   has complained about yet.
4. Read **Capacity quality (saturation)** to find links approaching line speed.
5. Read **Overlay quality (tunnels)** for the paths that cross somebody else's
   network.

## What you see

### Link error quality

The stat strip carries four counts.

| Stat | What it counts |
|---|---|
| **Interfaces monitored** | Interfaces reporting an operational status. |
| **Operationally up** | Interfaces whose operational status is up. |
| **With errors (5m)** | Interfaces with a non-zero input or output error rate over the last 5 minutes. |
| **With discards (5m)** | Interfaces with a non-zero input or output discard rate over the last 5 minutes. |

Below the strip, **Worst error rate (errors / 1k packets)** and **Worst discard
rate (discards / 1k packets)** rank the top ten interfaces by device and
interface name.

Both are ratios. The denominator is the total packet rate across unicast,
multicast and broadcast in both directions. A busy link with a handful of errors
scores better than a quiet link dropping a high fraction, which is the ranking a
raw counter gets backwards.

### Capacity quality (saturation)

Two counts, **Interfaces ≥ 80% util** and **Interfaces ≥ 60% util**, over
inbound or outbound utilization against line speed.

Two rankings give the top ten interfaces in each direction:
**Saturation risk, inbound peak (util %)** and **Saturation risk, outbound peak
(util %)**. Both are labelled with an em dash in the console.

### Overlay quality (tunnels)

**Path Health by tunnel** scores every tunnel from 0 to 100 as a weighted
composite:

| Component | Weight | Scored against |
|---|---|---|
| Loss | 40% | 0% is 100 points, 3% is 0 points. |
| Latency | 30% | 50 ms is 100 points, 300 ms is 0 points. |
| Jitter | 20% | 10 ms is 100 points, 60 ms is 0 points. |
| Route stability | 10% | One hour of uptime is 100 points, five minutes is 0 points. |

The thresholds follow ITU-T G.1010 and MEF guidance. A score at or above 80 is
good, 60 to 80 is a warning, and below 60 is bad.

**Lowest-QoE overlay tunnels** lists the worst by that score.

## What the board does not tell you

The board reports on the interfaces and tunnels that are producing telemetry
right now. An interface with no counters is absent from every panel rather than
counted as healthy. A zero on a stat is a measured zero across the series that
did report; it is not a claim about interfaces nothing measured. Confirm
collection coverage with [verify monitoring](/onboard-devices/verify-monitoring)
before reading an empty panel as an all-clear.

## Related

- [Create a monitor](/monitoring/create-a-monitor)
- [WAN interface metrics](/infrastructure/wan-interface-metrics)
- [Paths and tunnels](/infrastructure/paths-and-tunnels)
- [Honest states](/reference/honest-states)
