---
title: Review collector status on the Sensors page
sidebar_label: Sensors
description: Check that each collector is enabled, healthy and reaching its targets, and scope the subnet discovery sweep, from Administration → Data sources → Sensors.
page_type: task
sidebar_position: 26
---

# Review collector status on the Sensors page

**Administration → Data sources → Sensors** shows the collection layer: every
protocol collector and the SNMP trap receiver, whether each is enabled and
healthy, and how many of its targets it reaches. The subnet discovery settings
sit at the top of the same page.

## Before you begin

- A platform administrator account. Sensors is platform-global: the collectors
  poll for every tenant, so a tenant or organization administrator does not
  see the page.

## Steps

1. Go to **Administration → Data sources → Sensors**.
2. Read the summary under **Collectors**:
   - **Collectors**: how many are registered.
   - **Enabled**: how many of them are on.
   - **Healthy**: how many enabled collectors are healthy.
   - **Targets reachable**: reachable targets out of all targets, across every
     collector.
3. Read the table. One row per registered collector, for example **SNMP v2c**, **SNMP v3**, **SNMP
   metrics**, **gNMI**, **NETCONF** and the trap receiver, with **Enabled**
   (`on` or `off`), **Healthy** (`ok` or `fail`), **Targets**, **Reachable**,
   **Last poll** in milliseconds and **Last tick**. Hover a **Reachable** cell to
   see the collector's last error.
4. To change what subnet discovery sweeps, edit the **Subnet discovery** card at
   the top and select **Save changes**. **Scan now** runs a sweep straight
   away once discovery is enabled and saved. See
   [Configure SNMP discovery](/onboard-devices/snmp-discovery).

The page refreshes every 10 seconds.

## What you see

For the SNMP trap receiver, **Targets** counts the traps received and
**Reachable** counts the ones decoded.

A **Reachable** count of `0` on a healthy collector means the targets are not
answering. Check the credentials and access lists on the devices before you
look at Correlix.

## Related

- [Configure SNMP discovery](/onboard-devices/snmp-discovery)
- [Check the data-source coverage matrix](/onboard-devices/data-sources)
- [Check the health of the Correlix stack](/administration/stack-health)
