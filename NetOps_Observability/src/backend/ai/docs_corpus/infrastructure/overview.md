---
title: Infrastructure overview
sidebar_label: Overview
sidebar_position: 1
description: See and navigate your device fleet, dashboards, topology, maps, and network paths.
---

# Infrastructure

The **Infrastructure** section is your window into the device fleet — what you have, how it's doing, where it is, and how traffic gets there. Everything here is populated automatically once devices are [onboarded](/onboard-devices/overview); nothing is drawn or typed in by hand unless you choose to (sites and manually added devices are the exceptions, and both are labelled as such).

The left-hand navigation groups the section by the questions an operator asks, in order:

## Inventory — *what do I have?*

| Feature | Console path | What it's for |
| --- | --- | --- |
| **[Devices](/infrastructure/devices)** | <kbd>Infrastructure → Devices</kbd> | The inventory: live 3‑state health, device facts, fleet composition, a per‑device workspace, site assignment, and (if enabled) an in‑browser SSH terminal |

## Dashboards — *how is it doing?*

| Feature | Console path | What it's for |
| --- | --- | --- |
| **Device Monitoring** | <kbd>Infrastructure → Device Monitoring</kbd> | Fleet vitals and reachability, fleet‑wide throughput and error aggregates, device inventory & uptime, CPU/memory leaders, flow talkers, tunnel state |
| **Interface Performance** | <kbd>Infrastructure → Interface Performance</kbd> | Per‑interface throughput and utilization, top flapping interfaces, errors & discards, packet mix, operational status over time |
| **Protocol Monitoring** | <kbd>Infrastructure → Protocol Monitoring</kbd> | BGP session health (peer state, transitions, prefixes received) and OSPF neighbor / interface state over time |
| **Troubleshooting** | <kbd>Infrastructure → Troubleshooting</kbd> | Collection‑plane health: fleet counts, collector reachability and poll timing, SNMP reachable vs. configured, flow sources |

The dashboards are read-only boards built from telemetry you already collect. If a panel is empty, the honest fix is usually upstream — see [Verify monitoring](/onboard-devices/verify-monitoring).

## Maps — *where is it?*

| Feature | Console path | What it's for |
| --- | --- | --- |
| **[Topology Canvas](/infrastructure/topology-canvas)** | <kbd>Infrastructure → Topology Canvas</kbd> | The live, evidence‑backed network graph, with operator modes: Explore, Investigate, Path Trace, Dependency, Capacity |
| **[Device Geomap](/infrastructure/geomap)** | <kbd>Infrastructure → Device Geomap</kbd> | Sites and devices on a world map with health rollups — plus the **Sites** manager, where sites are declared and imported |

## Paths & Overlays — *how does traffic get there?*

| Feature | Console path | What it's for |
| --- | --- | --- |
| **[Flow Trace](/infrastructure/paths-and-tunnels)** | <kbd>Infrastructure → Flow Trace</kbd> | Hop‑by‑hop active path measurement (traceroute), path SLA probes, and active service checks |
| **[WAN Interface Metrics](/infrastructure/wan-interface-metrics)** | <kbd>Infrastructure → WAN Interface Metrics</kbd> | One row per WAN interface: live utilization and throughput plus a measured SLA (latency / jitter / loss / QoE / availability) to a derived target |
| **[Tunnels](/infrastructure/paths-and-tunnels#tunnels)** | <kbd>Infrastructure → Tunnels</kbd> | Overlay tunnel health (IPsec / SD‑WAN / GRE): endpoints, SLA heatmap, uptime, status |

## Where to start

1. **Confirm the fleet.** Open <kbd>Infrastructure → Devices</kbd> and check the **Up / Degraded / Down** counters and the *Fleet composition* panel. If devices you expect are missing, go back to [device onboarding](/onboard-devices/overview) — everything else in this section derives from the inventory.
2. **Check health.** Use **Device Monitoring** for fleet-level vitals, then drop into **Interface Performance** or **Protocol Monitoring** when a specific device or adjacency looks wrong.
3. **See the shape of the network.** Open the **Topology Canvas** in *Explore* mode. The graph is built from discovered relationships (neighbor and routing adjacencies), so it fills in as discovery warms up.
4. **Place things on the map.** Declare **Sites** with coordinates (<kbd>Device Geomap → Sites</kbd>) and assign devices to them (the **Site** column on the Devices page) so the geomap and site rollups light up.
5. **Understand paths and circuits.** Use **Flow Trace** for measured hop-by-hop paths, **WAN Interface Metrics** for circuit SLAs, and **Tunnels** for overlay state.

:::note
Data in this section is scoped to your tenant. Two teams looking at the same console paths see their own fleets — never each other's.
:::

## Related

- [Onboard devices](/onboard-devices/overview) — get devices into the inventory in the first place.
- [Monitoring](/monitoring/overview) — turn what you see here into alerting rules.
- [Automation & Source of Truth](/automation/overview) — how intent (sites, placement) relates to observed state.
