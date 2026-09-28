---
title: View the Demo Showcase board
sidebar_label: Demo Showcase
description: View the live, presentation-styled board on a wall screen, and read its fleet counters, gauges and traffic panels.
page_type: task
sidebar_position: 6
---

# View the Demo Showcase board

**Analytics → Dashboards → Demo Showcase** is a presentation board for a wall
screen or a customer demonstration. It restyles the same live telemetry the
operational boards read. Nothing on it is replayed or invented, and it is not
editable.

## Before you begin

- A signed-in account. The board reads the telemetry your account can see.
- Devices that report metrics. The panels are empty until telemetry arrives.

## Steps

1. Go to **Analytics → Dashboards → Demo Showcase**.
2. Read the header counters: **devices**, **critical** and **active alerts**.
   They refresh every 20 seconds.
3. Check the live marker beside the counters before you present:

   | Marker | Meaning |
   |---|---|
   | **live** and a time | Every panel's last read worked. The time is the last good read. |
   | **connecting** | No panel has answered yet. |
   | **N/M feeds down** | N of the M panel reads are failing. Those panels are stale. |

## What you see

| Row | Panels |
|---|---|
| Gauges | **CPU**, **Memory**, **Bandwidth**, **Reachability** and **Interfaces up** as fleet averages, with **Ingress** throughput and **Path RTT**. |
| Fleet activity | **Fleet activity**: CPU per device over the last hour, and **Utilization terrain**: the per-device CPU distribution. |
| Interfaces | **Interface utilization** (the top nine, ranked live), **Saturation histogram** (interfaces by utilization band) and **Error hot spots** (errors and discards per second). |
| Traffic and events | **Traffic by protocol** from NetFlow over the last hour, and a live **Event stream**. |

A counter that could not be read shows `—`, never `0`.

## Common questions

**Is this data real?** Yes. The board runs the same metric queries as the
operational boards, against the running stack.

**Which board should operators use day to day?** An operational one:
[Read the Command Center](/dashboards-reports/command-center) for incidents, or
[Built-in dashboards](/dashboards-reports/built-in-dashboards) for metrics.

## Related

- [Built-in dashboards](/dashboards-reports/built-in-dashboards)
- [Read My Dashboard](/dashboards-reports/my-dashboard)
