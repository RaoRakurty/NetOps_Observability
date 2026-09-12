// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// topologyToEchartsGeo.ts — the pure, renderer-agnostic adapter for the Phase-5
// geographic renderer. TopologyView in → the minimal geo series data an ECharts
// world map needs (site bubbles + WAN-circuit lines). Nothing here imports
// echarts; the domain contract (TopologyView) is the only input.
//
// Honesty rules carried over from the React Flow adapter:
//   • a node is plotted ONLY if it has real coordinates (lng/lat),
//   • a circuit is drawn ONLY if it has evidence AND both endpoints resolve to
//     coordinates — no link without evidence, no arc to nowhere.
//
// Coordinate convention: node.coordinates = { x: longitude, y: latitude } in
// decimal WGS-84 (the same intent data the Device Geomap reads from the Source of
// Truth). The renderer feeds [lng, lat] straight to ECharts' geo coordinate
// system.

import type { TopologyView, TopologyNode, TopologyEdge, Health, EdgeStatus } from "../../api/topologyTypes";
import { hasEvidence, statusToHealth } from "../../utils/topologyHealth";

/** A site bubble: a node pinned to a real geographic coordinate. */
export type GeoSitePoint = {
  id: string;
  name: string;
  lng: number;
  lat: number;
  health: Health;
  /** Devices rolled up at the site (metrics.devices), for bubble size + tooltip. */
  devices: number;
  node: TopologyNode;
};

/** A WAN circuit: an evidence-backed edge between two sited nodes. */
export type GeoCircuit = {
  id: string;
  from: [number, number];
  to: [number, number];
  fromName: string;
  toName: string;
  status: EdgeStatus;
  /** Health band of the circuit's status, for line colour. */
  health: Health;
  utilization: number | undefined;
  edge: TopologyEdge;
};

export type GeoModel = {
  sites: GeoSitePoint[];
  circuits: GeoCircuit[];
  /** Nodes the view carries but can't place (no coordinates) — surfaced honestly. */
  unplaced: number;
};

/** Read metrics.devices defensively (it may be a number, a string, or absent). */
function deviceCount(node: TopologyNode): number {
  const v = node.metrics?.devices;
  const n = typeof v === "string" ? Number(v) : v;
  return Number.isFinite(n) ? Number(n) : 0;
}

/**
 * Project a renderer-agnostic TopologyView into geo series data. Pure and
 * deterministic: same view in → same model out.
 */
export function topologyToEchartsGeo(view: TopologyView): GeoModel {
  const sites: GeoSitePoint[] = [];
  const coordOf = new Map<string, [number, number]>();
  let unplaced = 0;

  for (const n of view.nodes) {
    if (!n.coordinates) {
      unplaced++;
      continue;
    }
    const lng = n.coordinates.x;
    const lat = n.coordinates.y;
    coordOf.set(n.id, [lng, lat]);
    sites.push({
      id: n.id,
      name: n.label,
      lng,
      lat,
      health: n.health,
      devices: deviceCount(n),
      node: n,
    });
  }

  const circuits: GeoCircuit[] = [];
  for (const e of view.edges) {
    if (!hasEvidence(e.evidence)) continue; // never draw a link without evidence
    const from = coordOf.get(e.source);
    const to = coordOf.get(e.target);
    if (!from || !to) continue; // an endpoint isn't placed → can't draw the arc
    const status: EdgeStatus = e.status ?? "unknown";
    circuits.push({
      id: e.id,
      from,
      to,
      fromName: nameOf(view, e.source),
      toName: nameOf(view, e.target),
      status,
      health: statusToHealth(status),
      utilization: e.utilization_pct,
      edge: e,
    });
  }

  return { sites, circuits, unplaced };
}

function nameOf(view: TopologyView, id: string): string {
  return view.nodes.find((n) => n.id === id)?.label ?? id;
}
