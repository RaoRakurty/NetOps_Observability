// TopologyMiniMap — thin styled wrapper over React Flow's MiniMap. Nodes are
// colored by health so the operator keeps situational awareness while panning.
//
// It only renders once the graph is big enough to be worth a navigator: on a
// handful of nodes a minimap is just a near-empty box (the "half-cooked blob"),
// so below MIN_NODES_FOR_MINIMAP we hide it entirely. Node marks are drawn solid
// with a faint stroke so they read clearly even when scaled down.

import { MiniMap } from "@xyflow/react";
import type { Node } from "@xyflow/react";
import type { Health } from "../api/topologyTypes";
import { HEALTH_COLOR } from "../utils/topologyHealth";

const MIN_NODES_FOR_MINIMAP = 8;

export default function TopologyMiniMap({ nodeCount }: { nodeCount: number }) {
  if (nodeCount < MIN_NODES_FOR_MINIMAP) return null;
  return (
    <MiniMap
      pannable
      zoomable
      ariaLabel="Topology minimap"
      nodeColor={(n: Node) =>
        HEALTH_COLOR[((n.data as { node?: { health?: Health } })?.node?.health ?? "unknown") as Health]
      }
      // a faint same-tone stroke gives each mark a crisp edge at small scale
      nodeStrokeColor="color-mix(in srgb, var(--fg) 22%, transparent)"
      nodeStrokeWidth={2}
      nodeBorderRadius={3}
      // translucent mask so the whole map reads at a glance with the viewport
      // highlighted — not opaque squares floating on a flat box.
      maskColor="color-mix(in srgb, var(--surface) 74%, transparent)"
      maskStrokeColor="var(--accent)"
      maskStrokeWidth={2}
      offsetScale={6}
      style={{
        background: "var(--panel)",
        border: "1px solid var(--border)",
        borderRadius: 10,
        boxShadow: "0 4px 16px rgba(16,24,40,0.20)",
        // sit clear of the canvas corner so it doesn't fuse with the frame
        margin: 12,
        width: 184,
        height: 124,
      }}
    />
  );
}
