// GroupNode.tsx — a GROUP/site/zone BACKDROP. It sits behind devices: a large,
// very translucent rounded rect with a dashed border, a label chip top-left and
// a health-rollup dot. No heavy content — it's scenery, not a device card.

import { Handle, Position, type NodeProps } from "@xyflow/react";
import { memo } from "react";
import type { RFNodeData } from "../rfTypes";
import { HEALTH_COLOR, HEALTH_TINT, HEALTH_LABEL } from "../../../utils/topologyHealth";

function GroupNodeBase(props: NodeProps) {
  const data = props.data as unknown as RFNodeData;
  const { node, emphasis } = data;

  const dim = emphasis === "dim";
  const spotlight = emphasis === "spotlight";
  const opacity = dim ? 0.4 : 1;

  return (
    <div
      style={{
        width: "100%",
        height: "100%",
        boxSizing: "border-box",
        borderRadius: 18,
        // very subtle backdrop — low-alpha surface so devices stay legible on top
        background: "color-mix(in srgb, var(--surface) 55%, transparent)",
        border: `1px dashed ${spotlight ? "var(--accent)" : "var(--border)"}`,
        opacity,
        pointerEvents: "none",
      }}
    >
      {/* handles kept (containment edges may attach) but invisible */}
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />

      {/* label chip top-left — the only interactive bit */}
      <div
        style={{
          position: "absolute",
          top: 8,
          left: 10,
          display: "inline-flex",
          alignItems: "center",
          gap: 6,
          padding: "3px 8px",
          borderRadius: 8,
          background: "var(--panel)",
          border: "1px solid var(--border)",
          pointerEvents: "auto",
        }}
      >
        <span
          title={HEALTH_LABEL[node.health]}
          aria-label={HEALTH_LABEL[node.health]}
          style={{
            width: 8,
            height: 8,
            borderRadius: "50%",
            background: HEALTH_COLOR[node.health],
            boxShadow: `0 0 0 2px ${HEALTH_TINT[node.health]}`,
            flex: "0 0 auto",
          }}
        />
        <span
          style={{
            fontSize: 11,
            fontWeight: 600,
            letterSpacing: 0.2,
            color: "var(--fg-muted)",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            maxWidth: 220,
          }}
        >
          {node.label}
        </span>
      </div>
    </div>
  );
}

export const GroupNode = memo(GroupNodeBase);
export default GroupNode;
