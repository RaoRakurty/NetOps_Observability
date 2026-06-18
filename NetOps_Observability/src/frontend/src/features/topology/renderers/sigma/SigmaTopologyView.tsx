// SigmaTopologyView — PLACEHOLDER (Phase 4).
//
// Stand-in for the WebGL enterprise-overview renderer (Sigma.js / cosmos.gl).
// Renders a calm centered panel so the workflow plumbing can mount "the
// renderer" today without pulling a WebGL dependency. Phase 4 replaces the body
// with a real canvas fed by topologyToSigma().

import type { TopologyView } from "../../api/topologyTypes";

export default function SigmaTopologyView({ view }: { view: TopologyView }) {
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
        Enterprise overview (WebGL) — Phase 4
      </div>
      <div>
        {view.nodes.length} nodes would render here via Sigma.js/cosmos.gl.
      </div>
    </div>
  );
}
