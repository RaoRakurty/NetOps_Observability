---
title: Onboard Network Devices
sidebar_label: Overview
sidebar_position: 1
description: The complete reference for getting your devices into Correlix — credentials, discovery, manual add, streaming telemetry, and verification.
---

# Onboard Network Devices

This section is the complete reference for getting devices into Correlix. Where the [Quickstart](/getting-started/quickstart) walked one device end to end, here each step is documented as a full procedure so you can onboard a whole fleet — and prove it worked.

## The onboarding journey

Work through these steps in order. Each links to a page with the full click-by-click procedure.

1. **Check connectivity.** Correlix monitors agentlessly, so the only hard requirement is network reachability on a handful of standard ports (SNMP UDP 161 outbound; syslog, traps, and flows inbound). Review [Connectivity requirements](/reference/connectivity-requirements) and open the paths on any firewall or ACL between Correlix and your devices.

2. **Create SNMP credentials first.** Every device needs a read credential before it can be polled. Add your SNMP v2c communities and SNMPv3 users in the **[SNMP Profile Manager](/onboard-devices/snmp-profiles)** (<kbd>Administration → Data Collection → SNMP Profile Manager</kbd>). Doing this before adding devices means polling starts the moment a device appears.

3. **Get devices into the inventory.** Pick the method that fits — you can mix them freely:

   | Method | Best for | Page |
   | --- | --- | --- |
   | **SNMP discovery** | Finding many devices on known management subnets automatically | [Discover devices](/onboard-devices/snmp-discovery) |
   | **Add device manually** | A handful of devices, or ones outside a scanned range | [Add devices manually](/onboard-devices/add-devices-manually) |
   | **Import / Source of Truth** | You already have an inventory (CSV/JSON import, or an external system of record) | [Source of Truth](/automation/overview) |

   However a device arrives, it lands in the same inventory at <kbd>Infrastructure → Devices</kbd>, with a **Source** badge showing where it came from.

4. **Confirm collection.** Open the **[Data Sources coverage matrix](/onboard-devices/data-sources)** (<kbd>Administration → Data Collection → Data Sources</kbd>). Every onboarded device should turn green in the **SNMP metrics** column within a poll cycle (about a minute).

5. **Add the event and traffic planes.** SNMP polling gives you metrics and inventory. To unlock events, traffic analytics, and — most importantly — multi-plane root-cause correlation, configure your devices to *push* telemetry to Correlix:

   - **[Syslog](/send-data/syslog)** — device log messages become searchable events and correlation signals.
   - **[SNMP traps](/send-data/traps)** — asynchronous device notifications (link down, hardware alarms).
   - **[Flow records](/send-data/flows)** — NetFlow/sFlow/IPFIX for traffic and top-talker analytics.

6. **Add streaming telemetry where it's worth it (optional).** On platforms that support **gNMI**, [streaming telemetry](/onboard-devices/streaming-gnmi) adds sub-minute interface counters and on-change protocol state — it catches BGP and IGP flaps that a polling interval can miss.

7. **Verify.** Run the **[verification checklist](/onboard-devices/verify-monitoring)**: device green in the inventory, metrics on dashboards, logs searchable, flows flowing. Done means rendered — don't consider a device onboarded until you've seen its data on screen.

## The four green checks

For each device, you're aiming for:

1. ✅ **Known** — the device exists in <kbd>Infrastructure → Devices</kbd> with an **Up** status dot.
2. ✅ **Credentialed** — a working SNMP credential is attached ([SNMP profiles & credentials](/onboard-devices/snmp-profiles)).
3. ✅ **Collecting** — the device is green on the [Data Sources coverage matrix](/onboard-devices/data-sources) for every plane you configured.
4. ✅ **Rendering** — its dashboards fill in ([Verify a device is monitored](/onboard-devices/verify-monitoring)).

:::tip Aim for multi-plane coverage on critical devices
Correlation is most confident when a fault shows up in more than one plane — a syslog event *and* a metric anomaly *and* a trap. Prioritize getting syslog and flows onboarded for your core and edge devices, not just SNMP.
:::

## What onboarding unlocks

Once a device is collecting, it's automatically eligible for [monitors and alerting](/monitoring/overview), anomaly detection, the [Topology Canvas](/infrastructure/topology-canvas), and root-cause correlation — no extra wiring per device.

## Where things live

- **<kbd>Infrastructure → Devices</kbd>** — the inventory: every discovered and declared device, health, type, source.
- **<kbd>Administration → Data Collection</kbd>** — the collection controls: **SNMP Profile Manager** (credentials and the vendor metric library) and **Data Sources** (per-device coverage).
- **[Supported devices & vendors](/onboard-devices/supported-devices)** — what works out of the box, and the honest baseline for everything else.

Start with **[SNMP profiles & credentials](/onboard-devices/snmp-profiles)**.
