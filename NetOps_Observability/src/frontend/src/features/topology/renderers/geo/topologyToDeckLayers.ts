// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Placeholder. MapLibre GL JS + deck.gl geo/WAN renderer is Phase 5; adapter
// boundary only.
//
// Nothing here imports deck.gl / maplibre-gl — when Phase 5 lands, only this
// file changes; the domain TopologyView contract does not.

import type { TopologyView } from "../../api/topologyTypes";

export type DeckLayerSpec = { id: string; type: string; data: unknown };

/**
 * Map a renderer-agnostic TopologyView into the minimal deck.gl layer specs the
 * Phase-5 geo renderer will instantiate: a scatterplot of node coordinates and
 * an arc/line layer of edges. Real-shaped but intentionally minimal.
 */
export function topologyToDeckLayers(view: TopologyView): DeckLayerSpec[] {
  const points = view.nodes
    .filter((n) => n.coordinates)
    .map((n) => ({
      id: n.id,
      label: n.label,
      health: n.health,
      position: [n.coordinates!.x, n.coordinates!.y] as [number, number],
    }));

  const links = view.edges.map((e) => ({
    id: e.id,
    source: e.source,
    target: e.target,
    status: e.status,
  }));

  return [
    { id: "nodes-scatterplot", type: "scatterplot", data: points },
    { id: "edges-arc", type: "arc", data: links },
  ];
}
