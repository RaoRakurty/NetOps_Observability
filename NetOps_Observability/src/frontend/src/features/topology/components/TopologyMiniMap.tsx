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
      nodeStrokeWidth={2}
      maskColor="var(--panel)"
      style={{
        background: "var(--surface)",
        border: "1px solid var(--border)",
        borderRadius: 8,
        width: 150,
        height: 100,
      }}
    />
  );
}
