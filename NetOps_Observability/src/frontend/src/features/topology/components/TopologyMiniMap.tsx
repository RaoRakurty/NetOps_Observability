// TopologyMiniMap — thin styled wrapper over React Flow's MiniMap. Nodes are
// colored by health so the operator keeps situational awareness while panning.

import { MiniMap } from "@xyflow/react";
import type { Node } from "@xyflow/react";
import type { Health } from "../api/topologyTypes";
import { HEALTH_COLOR } from "../utils/topologyHealth";

export default function TopologyMiniMap() {
  return (
    <MiniMap
      pannable
      zoomable
      nodeColor={(n: Node) =>
        HEALTH_COLOR[((n.data as { node?: { health?: Health } })?.node?.health ?? "unknown") as Health]
      }
      nodeStrokeColor="transparent"
      nodeStrokeWidth={0}
      nodeBorderRadius={3}
      // translucent mask so the whole map reads at a glance with the viewport
      // highlighted — not opaque green squares floating on a white box.
      maskColor="color-mix(in srgb, var(--surface) 76%, transparent)"
      maskStrokeColor="var(--accent)"
      maskStrokeWidth={2}
      style={{
        background: "var(--panel)",
        border: "1px solid var(--border)",
        borderRadius: 10,
        boxShadow: "0 2px 10px rgba(16,24,40,0.16)",
        width: 168,
        height: 112,
      }}
    />
  );
}
