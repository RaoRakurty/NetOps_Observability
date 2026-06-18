// GeoTopologyMap — PLACEHOLDER (Phase 5).
//
// Stand-in for the geographic WAN renderer (MapLibre GL JS + deck.gl). Renders a
// calm centered panel so the executive/geo workflow can mount "the map" today
// without pulling a mapping dependency. Phase 5 replaces the body with a real
// map fed by topologyToDeckLayers().

import type { TopologyView } from "../../api/topologyTypes";

export default function GeoTopologyMap({ view }: { view: TopologyView }) {
  // "Sites" are nodes pinned to geographic coordinates.
  const siteCount = view.nodes.filter((n) => n.coordinates).length;

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        gap: 8,
        height: "100%",
        minHeight: 240,
        padding: 24,
        textAlign: "center",
        background: "var(--panel)",
        border: "1px solid var(--border)",
        borderRadius: 8,
        color: "var(--fg-muted)",
      }}
    >
      <div style={{ fontWeight: 600, color: "var(--accent)" }}>
        Geo / WAN map — Phase 5
      </div>
      <div>
        MapLibre + deck.gl will plot {siteCount} sites and WAN circuits here.
      </div>
    </div>
  );
}
