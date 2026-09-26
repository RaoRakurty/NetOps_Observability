---
title: Read My Dashboard
sidebar_label: My Dashboard
description: Read the fixed operations board under Overview → My Dashboard, from service health down to topology, and tell a live board from a disconnected one.
page_type: task
sidebar_position: 3
---

# Read My Dashboard

**Overview → My Dashboard** is a fixed, curated board that walks the network
from the top down on one screen. Every panel reads its live source. The board is
not editable. To arrange your own board, use the composer described in
[Built-in dashboards](/dashboards-reports/built-in-dashboards).

## Before you begin

- A signed-in account. Every panel is per tenant and reads your own tenant's
  devices only.

## Steps

1. Go to **Overview → My Dashboard**.
2. Check the header first. It states whether the board is live:
   - **Live**, with the time of the last successful data.
   - **Connecting** with **no data loaded yet**, before the first answer.
   - **Disconnected**, with how many feeds are failing and when data last
     arrived.
3. Read the numbered sections in order:

   | # | Section | Panels |
   |---|---|---|
   | 01 | **Service health** | The fleet KPIs. |
   | 02 | **Resource saturation** | CPU, memory, storage and temperature. |
   | 03 | **Traffic & flows** | Traffic, top hosts, flows by protocol, tunnel health and devices by vendor. |
   | 04 | **WAN & interfaces** | WAN interfaces and the top interfaces by utilisation. |
   | 05 | **Errors & quality** | The top interfaces by errors and by discards. |
   | 06 | **Control-plane** | BGP peers and OSPF neighbours. |
   | 07 | **Path quality** | Probe round-trip time, jitter and loss. |
   | 08 | **Events & incidents** | Alerts by severity, active alerts and incidents. |
   | 09 | **Topology** | The topology map. |

4. Select **⤢** on a panel to enlarge it.
5. Select a panel title that carries an arrow to open its full detail view.

## What you see

The live state in the header comes from the panels' own requests, not from a
clock, so a backend outage reads **Disconnected**. It never reads as a live
board.

A panel with no wired source is left out, so the section numbers always run
without gaps.

## Related

- [Dashboards and reports](/dashboards-reports/overview)
- [Read the Operations Overview](/dashboards-reports/operations-overview)
- [Built-in dashboards](/dashboards-reports/built-in-dashboards)
