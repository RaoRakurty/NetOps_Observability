---
title: Topology Canvas
sidebar_label: Topology Canvas
sidebar_position: 2
description: A live, evidence-backed graph of your network, built automatically from discovered relationships.
---

# Topology Canvas

The **Topology Canvas** is Correlix's live network graph. It's built automatically from the relationships Correlix learns (LLDP/CDP neighbors and routing adjacencies) as devices are polled — you don't draw it by hand. Open it at <kbd>Infrastructure → Topology Canvas</kbd>.

## What you see

- **Nodes** — your devices, colored by health/status.
- **Edges** — the links between them (physical/logical adjacencies).
- **Incident overlay** — when there's an active incident, the affected devices and path light up so you can see *where* the problem is.

## Modes

The canvas supports several ways to read the graph — explore freely, focus on **capacity**, **investigate** an incident (auto‑pins the impacted nodes), or trace a **path**. Switch modes from the canvas controls.

## How it stays accurate

The topology is **evidence‑backed** and refreshes as discovery warms up. A link appears because Correlix observed it (a neighbor or an adjacency), not because someone typed it — so the map reflects reality.

## Related

- **[Device Geomap](/infrastructure/geomap)** — the same fleet on a geographic map.
- **[Flow Trace](/infrastructure/overview)** — hop‑by‑hop path measurement.
