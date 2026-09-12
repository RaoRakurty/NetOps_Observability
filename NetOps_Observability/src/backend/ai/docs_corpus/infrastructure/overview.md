---
title: Infrastructure
description: The device fleet and everything derived from it - inventory, interfaces and optics, sites, topology, paths, tunnels, wireless and vendor controllers.
page_type: index
sidebar_position: 1
---

# Infrastructure

The **Infrastructure** section answers one question: what do you own, and what has been observed about it. Every page here reads the device inventory, so [onboard devices](/onboard-devices/overview) first. Each request is scoped to your tenant on the server before the query runs, so two teams reading the same console path see their own fleets.

| Page | Console path | What it does |
|---|---|---|
| [Work with the device inventory](/infrastructure/devices) | **Infrastructure → Devices** | Three-state health per device, fleet composition, the per-device workspace, site assignment, and the opt-in SSH terminal. |
| [Inspect interfaces and optics](/infrastructure/interfaces-and-optics) | **Infrastructure → Interfaces & Optics** | Fleet-wide interface table with six column presets, a port-health score, transceiver inventory, and the physical-layer signature catalog. |
| [Place devices on the map](/infrastructure/geomap) | **Infrastructure → Sites** | Declare sites with coordinates, place devices, and read the health rollup per site. |
| [Monitor wireless](/infrastructure/wireless) | **Infrastructure → Wireless** | Controllers, access points, slot-keyed radios and WLANs, read-only, filled by a vendor controller connector. |
| [Connect a vendor controller](/infrastructure/nms-integrations) | **Infrastructure → Discovery & NMS** | Poll a third-party controller for its computed state, SLA metrics and alarms, and feed them to correlation as management-plane evidence. |
| [Read the topology canvas](/infrastructure/topology-canvas) | **Investigate → Topology** | The evidence-backed graph, with Explore, Investigate, Path Trace, Capacity and Dependency modes. |
| [Trace paths and tunnels](/infrastructure/paths-and-tunnels) | **Investigate → Paths** | Measured hop-by-hop paths, path SLA probes, service checks, and overlay tunnel health. |
| [Measure WAN paths](/infrastructure/wan-interface-metrics) | **Investigate → Paths → WAN Paths** | One row per WAN interface: live utilization plus a measured SLA to a derived target, with the tier that measured it. |

## Where the metric boards went

Device Monitoring, Interface Performance, Protocol Monitoring and BGP Operations are boards, not inventory. They sit under **Analytics → Metric Dashboards**, and the topology, path and tunnel views sit under **Investigate**. The [built-in dashboards](/dashboards-reports/built-in-dashboards) page is the tour of what each board answers.

## Where to start

1. Open **Infrastructure → Devices** and read the **Inventory**, **Up**, **Degraded** and **Down** counters. If devices you expect are missing, go back to [device onboarding](/onboard-devices/overview).
2. Open **Infrastructure → Sites** and declare the sites you operate, then assign devices to them. An unplaced device rolls up into no site view.
3. Open **Investigate → Topology** in *Explore* mode. The graph is built from discovered adjacencies, so it fills in as discovery warms up.
4. Open **Investigate → Paths** for measured paths, WAN SLA and overlay tunnel state.

## Related

- [Onboard devices](/onboard-devices/overview) for getting devices into the inventory.
- [Monitoring](/monitoring/overview) for turning what you see here into alert rules.
- [Automation and source of truth](/automation/overview) for how declared records relate to observed state.
