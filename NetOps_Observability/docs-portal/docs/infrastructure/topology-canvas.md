---
title: Topology Canvas
sidebar_label: Topology Canvas
sidebar_position: 3
description: A live, evidence-backed graph of your network, with operator modes for exploring, capacity, incident investigation, and path tracing.
---

# Topology Canvas

The **Topology Canvas** (<kbd>Infrastructure → Topology Canvas</kbd>) is Correlix's live network graph. It is built automatically from relationships Correlix *observed* — neighbor adjacencies (LLDP/CDP) and routing adjacencies learned as devices are polled — never hand-drawn. A link is on the map because there is evidence for it: hover any node or edge and a popover shows *why it's here* (health, verdict, and the evidence behind it).

:::note Discovery warm-up
The graph fills in as discovery warms up. A sparse canvas right after onboarding is normal — nodes and edges appear as neighbor and routing data is learned. If it stays sparse, widen discovery ([SNMP discovery](/onboard-devices/snmp-discovery)) so intervening devices are learned.
:::

## The toolbar

Along the top, left to right:

- **Mode selector** — the operator workflows: **Explore**, **Investigate**, **Path Trace**, **Dependency**, **Capacity** (each described below).
- **Live / Persisted** — the data source. *Live* recomputes the projection for the current mode on each load; *Persisted* shows the continuously reconciled graph with stable identities, plus a coverage readout (`N nodes · N edges`, with a stale count when parts of the graph haven't been re-confirmed recently).
- **Overlay** — what colors the map. **Health** is the default; **Utilization**, **Interface errors**, **Routing changes**, **Config drift**, **Syslog**, **Flow dependencies**, and **RCA evidence** appear only when the current view actually carries that data — the picker never offers an overlay that would render nothing.
- **Group** — the grouping lens: bucket the canvas by **site** (default) or another node dimension such as role, vendor, or owner. Click a group's header to collapse or expand it.
- **Canvas / Overview / Geo** — the renderer: the interactive operator canvas (default), a large-scale overview, or a geographic map.
- **Density** — **Exec / Operator / Engineer / Incident** presets controlling how much detail each node card shows (*Engineer* also forces all labels on).
- **Labels toggle, zoom in/out, fit** — view controls. **Full screen** sits on the stage itself (<kbd>Esc</kbd> exits). A **reset layout** action appears once you've pinned nodes.

### Interactions that work in every mode

- **Pan** by dragging empty canvas; **zoom** with the scroll wheel or the toolbar buttons; **fit** re-frames everything.
- **Hover** a node to softly spotlight it and its first-degree neighbors, with an evidence popover at the cursor.
- **Click** a node or edge to select it — a side drawer opens with its details. Click empty canvas to clear.
- **Search** (top of the stage) to find nodes by name; matches are highlighted, and a match hidden inside a collapsed group expands it. Picking a match centers on it.
- **Drag** a node to pin its position for this layout; **reset layout** returns to the automatic arrangement.

## Explore — browse the fabric

1. Open the canvas; **Explore** is the default mode with the **Health** overlay.
2. Read the map: **nodes** are your devices (grouped by site by default), colored by health; **edges** are discovered links between them. The legend (bottom of the stage) decodes the current overlay's colors.
3. Hover a device to light up its neighborhood and glance at its evidence; click it to open the drawer with full detail.
4. Switch the **Overlay** to ask a different question of the same map — e.g. **Interface errors** to see which links are erroring, or **Syslog** to see which devices are talking.

## Capacity — utilization overlay

1. Switch the mode to **Capacity**. The overlay flips to **Utilization** automatically — that is the mode's whole point.
2. Hot links stand out first: link coloring follows measured utilization, so saturated paths and ECMP imbalance surface visually.
3. A **capacity panel** docks on the stage summarizing the view; click any hot edge to open its drawer.

## Investigate — pin an incident

1. Switch the mode to **Investigate**. It automatically lands on the **most actionable open incident** (highest verdict tier, then confidence, then recency) and renders that incident's root-cause fault path on the canvas.
2. Use the **Incident** picker in the toolbar to switch to a different incident — each option shows its verdict tier and top hypothesis — or choose **Live projection** to see the plain topology instead.
3. Read the stage: a **verdict banner** states the engine's conclusion for the pinned incident, the affected path is pre-spotlighted, and a **path analysis panel** docks alongside with the hop-by-hop detail.
4. Click any node on the fault path to refocus and open its drawer.

If there are no open correlations, the picker says **No active incidents** and Investigate shows the live topology. Incidents themselves live under [Monitoring → Incidents](/incidents/overview).

## Path Trace — resolve an A→B path

1. Switch the mode to **Path Trace**. A guided card appears: *Trace a network path*.
2. Pick a **Source…** and a **Destination…** device from the dropdowns (they're also available in the toolbar once a trace is active, so you can re-aim).
3. Wait for **Resolving path…** to finish. The result is one of:
   - **A resolved path** — rendered as a clean left-to-right ribbon of hops (not the full topology), with each hop's ingress/egress interface and the links colored by measured load, status, or verdict.
   - **No path found** — an honest state: no route exists between the endpoints over the *discovered* adjacency. Either they sit in separate fabrics or discovery hasn't learned the intervening hops yet. Re-aim the trace or widen discovery.
4. **Read per-hop metrics.** Each hop carries a latency + jitter headline where an active probe reaches it. **Click the headline** to expand the hop's full metric list (latency, jitter, one-way delay, loss, load, and more) below the ribbon; slots read "—" honestly where nothing measures that hop yet. Between measured hops, the ribbon also shows the **added latency of each segment** — the difference between consecutive hops — so the segment contributing the most delay is identified.

:::caution Computed vs. measured
A path resolved from the discovered topology is a shortest-path *inference*, not an observed forwarding path — the header says so explicitly. Hops confirmed by an active traceroute/probe are ground truth; see [Flow Trace](/infrastructure/paths-and-tunnels) for measured paths.
:::

## Dependency — service relationships

Switch the mode to **Dependency** to map service dependencies derived from flow attribution: select a service to light up what it depends on. If no flows are attributed to services in the current window, the canvas says so — widen the time range or confirm flow collection is active ([Flows](/explore/flows)).

## Troubleshooting

- **Canvas is empty or missing devices** — discovery hasn't learned the adjacencies yet; check [Verify monitoring](/onboard-devices/verify-monitoring).
- **Path Trace looks like Explore** — you haven't picked both endpoints yet; the mode only differs once a source *and* destination are set.
- **An overlay you want isn't offered** — the current view has no data for it (for example, Utilization needs interface metrics on the drawn links).
