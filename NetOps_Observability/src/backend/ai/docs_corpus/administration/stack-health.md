---
title: Check the health of the Correlix stack
sidebar_label: Stack Health
description: Check whether the search, metrics, flow, analytics, event-bus, state and visualization backends behind Correlix are up, and whether collection is reaching your devices.
page_type: task
sidebar_position: 20
---

# Check the health of the Correlix stack

**Platform → Tools → Stack Health** monitors Correlix's own infrastructure: the
backends behind the console, and the collection layer that feeds them. Open it
when pages load slowly or show no data and you need to know whether the cause
is the platform or the network.

## Before you begin

- A platform administrator account. Stack Health is platform-global. Any other
  account sees **Infrastructure-stack monitoring is available to platform
  administrators only.**

## Steps

1. Go to **Platform → Tools → Stack Health**.
2. Read the summary: **Stack status**, and the number of components **Up**,
   **Degraded** and **Down**.
3. Read the board. Components are grouped by category: **Search**,
   **Metrics**, **OLAP / Flows**, **Analytics**, **Event bus**, **State** and
   **Visualization**. Each row shows the component, its state
   (**Operational**, **Degraded** or **Down**), a detail line and the probe
   latency in milliseconds.
4. Scroll to **Collection** to check the devices side.

The page refreshes every 15 seconds.

## What you see

**Collection** carries four counts and two lists:

| Item | What it tells you |
|---|---|
| **Monitored devices** | The targets the SNMP metrics collector is configured to poll. |
| **Reachable (SNMP)** | The SNMP targets that are reachable. |
| **Flows (1h)** | Flow records received in the last hour. |
| **Traps (1h)** | SNMP traps received in the last hour. |
| **Collectors** | One row per collector with its configured targets, reachable targets and poll time. **No collector reported.** means none reported. |
| **Flow sources** | The flow types that arrived in the last hour, with their counts. **No flows in the last hour.** means none did. |

**Reachable (SNMP)** at `0` while **Monitored devices** is above `0` means the
collector is healthy and the devices are not answering. It is not a pipeline
failure. Start at the device end: a rotated SNMP community or SNMPv3 user, an
access list or firewall between Correlix and the devices, or the devices being
down. **Monitored devices** at `0` means nothing is configured for collection.

## Related

- [Verify the deployment](/deploy/verify-deployment)
- [Watch Correlix with the self-monitoring dashboards](/administration/self-monitoring)
- [Follow a record through the pipeline](/administration/pipeline-debugger)
- [Review collector status](/administration/sensors)
