---
title: Read the topology canvas
description: Read the evidence-backed network graph, switch operator modes and overlays, and resolve an A-to-B path across discovered adjacencies.
page_type: task
sidebar_position: 4
---

# Read the topology canvas

**Investigate → Topology** is Correlix's live network graph. It is built from relationships that were observed, neighbor adjacencies and routing adjacencies learned as devices are polled, and never hand-drawn. A link is on the map because there is evidence for it, and hovering a node or an edge shows that evidence.

## Before you begin

- `topology:read` in your tenant.
- Devices onboarded and polling. The graph fills in as discovery warms up, so a sparse canvas right after onboarding is expected. If it stays sparse, widen [SNMP discovery](/onboard-devices/snmp-discovery) so the intervening devices are learned.
- The canvas takes the full page height under the toolbar. There is no minimap.

## Steps

### Step 1 - Set the toolbar

The toolbar runs across the top of the page. The controls, left to right:

| Control | What it does |
|---|---|
| **Domain** | A dropdown: **LAN**, **SD-WAN**, **DC**, **Cloud**. It slices the canvas to one part of the estate. LAN is the default and the catch-all, so a node is never dropped. |
| **Carrier** | A toggle that overlays the shared carrier and transport network tying the domains together. |
| **Devices** | A toggle that docks the device inventory beside the map. |
| Mode selector | **Explore**, **Investigate**, **Path Trace**, **Capacity**, **Dependency**. Only implemented modes are offered. |
| **Live** / **Persisted** | The data source. *Live* recomputes the projection for the current mode on each load. *Persisted* reads the continuously reconciled graph with stable identities and shows a coverage readout of nodes, edges and a stale count. |
| **Overlay** | What colours the map. Only overlays the current view actually carries are offered, so the picker never offers one that would render nothing. |
| **Group** | A dropdown that regroups the canvas by a node dimension. **Zone** segregates by ownership border. |
| **Shape** | A dropdown that arranges the canvas by topology archetype. **Auto** names what was detected and why. |
| **Canvas** / **Overview** / **Geo** | The renderer. |
| **Density** | A dropdown: **Exec**, **Operator**, **Engineer**, **Incident**. It controls how much each node card reveals. *Engineer* also forces every label on. |
| **Labels**, **Reset layout**, zoom and fit | View controls. **Reset layout** appears once you have pinned a node. |

A freshness chip beside the toolbar reads the age of the data from the view's own `generated_at`, never from a wall clock, and turns to a warning past two refresh cycles. A view with no live data is badged **Sample data**, so a bundled fabric is never presented as your network.

**Full screen** sits on the stage itself. Press `Esc` to exit.

### Step 2 - Explore the fabric

1. Open the canvas. **Explore** is the default mode with the **Health** overlay.
2. Read the map. Nodes are devices, grouped by the current **Group** dimension and coloured by health. Edges are discovered links. The legend decodes the current overlay.
3. Hover a device to spotlight its first-degree neighbourhood and read its evidence popover.
4. Select a node or an edge to open the detail drawer. Select empty canvas to clear.
5. Search from the top of the stage to find a node by name. A match hidden inside a collapsed group expands it.
6. Drag a node to pin it for this layout, and use **Reset layout** to return to the automatic arrangement.

### Step 3 - Read utilization in Capacity mode

1. Switch the mode to **Capacity**. The overlay flips to **Utilization**, which is the point of the mode.
2. Read the link colouring. Saturated paths and ECMP imbalance surface visually.
3. Select a hot edge to open its drawer.

### Step 4 - Pin an incident in Investigate mode

1. Switch the mode to **Investigate**. It lands on the most actionable open incident and renders that incident's fault path.
2. Use the **Incident** picker to switch to another incident, each labelled with its verdict tier and top hypothesis, or choose **Live projection** for the plain topology.
3. Read the verdict banner and the docked path-analysis panel.
4. Select any node on the fault path to refocus and open its drawer.

With no open correlations the picker reads **No active incidents** and Investigate shows the live topology. The cases themselves live under [Incidents](/incidents/overview).

### Step 5 - Path Trace: resolve an A-to-B path {#path-trace--resolve-an-ab-path}

1. Switch the mode to **Path Trace**. A guided card appears.
2. Choose a **Source…** and a **Destination…** device. Once a trace is active the same pair sits in the toolbar so you can re-aim it.
3. Wait for the resolve to finish. The result is one of two honest states:
   - A resolved path, rendered as a left-to-right ribbon of hops rather than the whole topology, with each hop's ingress and egress interface.
   - **No path found**, meaning no route exists between the endpoints over the *discovered* adjacency. Either the endpoints sit in separate fabrics, or discovery has not learned the intervening hops.
4. Read the per-hop metrics. Each hop carries a latency and jitter headline where an active probe reaches it. Select the headline to expand the full metric list below the ribbon. A slot with nothing measuring it reads as a dash. Between measured hops the ribbon shows the added latency of each segment, so the segment contributing the most delay is named.

:::caution Computed is not measured
A path resolved from the discovered topology is a shortest-path inference, not an observed forwarding path, and the header says so. For hops confirmed by an active traceroute, use [Trace paths and tunnels](/infrastructure/paths-and-tunnels).
:::

### Step 6 - Map service dependencies

Switch the mode to **Dependency** to map service relationships derived from flow attribution, then select a service to light up what it depends on. With no flows attributed to services in the current window the canvas says so. Widen the range or confirm flow collection under [Analyse flows](/explore/flows).

## What you see

Devices you own appear as nodes, discovered links as edges, and the overlay you chose colours both. In *Persisted* mode the coverage readout states the node and edge counts and how many have not been re-confirmed recently, so an ageing graph declares itself instead of looking complete.

## Related

- [Trace paths and tunnels](/infrastructure/paths-and-tunnels) for measured, hop-by-hop paths.
- [Read an RCA case](/investigate/read-an-rca-case) for the case an Investigate-mode fault path belongs to.
- [Analyse flows](/explore/flows) for the flow attribution behind Dependency mode.
