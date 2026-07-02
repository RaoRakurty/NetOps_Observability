---
title: Link Quality
sidebar_label: Link Quality
sidebar_position: 4
description: Read the Link Quality board — error and discard ratios, saturation risk, overlay-tunnel health — and investigate a degraded link.
---

# Link Quality

<kbd>Monitoring → Link Quality</kbd> answers a different question than the raw traffic dashboards: not "how busy is this link?" but **"is this link healthy?"**. It scores every interface and overlay tunnel on **rates and ratios** — errors and discards per 1,000 packets, saturation against line speed, and probe-measured loss/latency/jitter — so a quiet link that silently drops a high fraction of its packets can't hide behind busy-link volume.

All of it comes from telemetry you're already collecting (interface counters and tunnel measurements). The board respects the global time-range picker.

## What the board measures

The page has three groups, top to bottom:

### 1. Link error quality

The stat strip gives you the fleet at a glance:

| Stat | Meaning |
| --- | --- |
| **Interfaces monitored** | Every interface reporting status |
| **Operationally up** | How many are currently up |
| **With errors (5m)** | Interfaces that recorded *any* input/output errors in the last 5 minutes — turns red when non-zero |
| **With discards (5m)** | Interfaces that dropped *any* packets in the last 5 minutes (a congestion signal) |

Below it, two ranked charts — **Worst error rate (errors / 1k packets)** and **Worst discard rate (discards / 1k packets)** — list the ten worst interfaces by device and interface name (e.g. `leaf-2 Ethernet1`).

:::note Why per 1,000 packets?
A busy 10-gig link with a handful of errors is healthier than a quiet link dropping 2% of everything it carries. Normalizing by traffic ranks links by *drop fraction*, which is what your users actually feel.
:::

Rule of thumb: **errors** point at the physical layer (optics, cabling, duplex, FCS); **discards** point at congestion or policy (queue drops, policing).

### 2. Capacity quality (saturation)

| Stat / chart | Meaning |
| --- | --- |
| **Interfaces ≥ 80% util** | Links at saturation risk in either direction — red when non-zero |
| **Interfaces ≥ 60% util** | Links trending toward saturation — early warning |
| **Saturation risk — inbound / outbound peak (util %)** | The ten hottest interfaces per direction, as a percentage of each link's line speed |

Utilization here is measured against each interface's actual speed, so a 70%-full 1-gig access port ranks above a 20%-full 100-gig core link.

### 3. Overlay quality (tunnels)

For overlay/tunnel paths the board scores end-to-end experience:

| Stat | Meaning |
| --- | --- |
| **Tunnels / Up** | Overlay tunnels known and currently up |
| **Avg Path Health** | Fleet-average composite score, 0–100 (see below) |
| **Avg QoE** | Average quality-of-experience score; roughly ≥ 8 good, 5–8 watch, below 5 bad |
| **Worst loss** | The highest packet loss on any tunnel — warns at 1%, red at 3% |

**Path Health by tunnel** ranks the twelve weakest tunnels by a composite score weighted **40% loss + 30% latency + 20% jitter + 10% route stability**, each component graded against telecom-grade targets (loss perfect at 0%, failing at 3%; latency perfect at or below 50 ms, failing at 300 ms; jitter perfect at or below 10 ms, failing at 60 ms; stability full-credit after an hour up). Read the score as: **80–100 healthy · 60–79 watch · below 60 degraded**.

**Lowest-QoE overlay tunnels** lists the weakest tunnels with their QoE, latency, and loss side by side.

## Investigate a degraded link, step by step

1. Go to <kbd>Monitoring → Link Quality</kbd> and set the time range to cover the report ("it's been slow since this morning" → 12h or 24h).
2. **Classify the symptom** from the three groups:
   - Link appears in **Worst error rate** → suspect physical layer. Check optics, patching, and speed/duplex on that interface. Errors on both ends of the same link usually mean the cable/optic between them.
   - Link appears in **Worst discard rate** but *not* errors → suspect congestion or QoS policy. Cross-check the same interface in the saturation charts.
   - Link appears in **Saturation risk** at ≥ 80% → capacity problem. Discards on the same interface confirm queue drops; plan an upgrade or reroute.
   - A tunnel ranks low in **Path Health** → read its weighted components: high loss dominates the score (40%), so a score in the 50s with 2% loss is a loss problem, not a latency problem. Low stability credit means the tunnel recently flapped.
3. **Pivot to the device.** Note the device and interface name from the chart row, then open <kbd>Infrastructure → Device Monitoring</kbd> (or <kbd>Infrastructure → Interface Performance</kbd>) to see the raw counters and traffic curves over time — was this a step change, a slow creep, or a spike?
4. **Check the logs** for the same window: <kbd>Logs → Log Search</kbd> filtered to the device (see [Search logs](/explore/logs)). Interface resets, protocol events, or optic warnings around the degradation onset usually name the cause.
5. **Check whether it already alerted.** <kbd>Monitoring → Active Alerts</kbd> may have a firing errors/discards/utilization alert on the same interface — and [correlation](/incidents/overview) may have already grouped it with related events into an incident.
6. **Lock in detection.** If this link class wasn't covered, [create a monitor](/monitoring/create-a-monitor) from the matching template — **Interface errors**, **Interface discards**, **Interface utilization**, or **Path loss** — scoped to the affected devices, so next time it pages before the users call.

## Verify a fix

After remediation (optic swap, QoS change, reroute):

1. Return to <kbd>Monitoring → Link Quality</kbd> with a short range (15–60 minutes) so pre-fix history doesn't dominate.
2. The interface should drop out of the worst-ten charts, and **With errors (5m)** / **With discards (5m)** should stop counting it.
3. For tunnels, watch **Path Health** recover — note the stability component only returns to full credit after the tunnel has been up for an hour.

## Troubleshooting

- **Panels are empty or show zero interfaces.** Interface telemetry isn't arriving — verify device onboarding and collection first ([Verify monitoring](/onboard-devices/verify-monitoring)).
- **"No overlay tunnel telemetry yet."** The overlay group only populates when tunnel measurements are being collected; interface-level groups work without it.
- **A link you know is bad isn't in the worst-ten.** The charts show the ten worst per panel. If more than ten links are degraded, fix the visible ones first, or narrow the time range to when your link misbehaved so it ranks.
- **Error rate looks huge on an idle link.** That's the point of normalization — a near-idle link dropping most of its few packets is genuinely unhealthy and will rank high even at tiny absolute volumes.
