// UnresolvedNode.tsx — a MUTED placeholder for an unresolved remote neighbour
// (we saw the adjacency but couldn't identify the far-end device). Dashed
// border, permanently reduced opacity, a "?" icon and an UNRESOLVED tag. Still
// selectable so the operator can drill in. Uses the slate unknown color.

import { Handle, Position, type NodeProps } from "@xyflow/react";
import { memo } from "react";
import type { RFNodeData } from "../rfTypes";
import { HEALTH_COLOR, confidencePct } from "../../../utils/topologyHealth";

const SLATE = HEALTH_COLOR.unknown;

function UnknownIcon() {
  return (
    <svg width={18} height={18} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx={12} cy={12} r={9} stroke="currentColor" strokeWidth={1.5} strokeDasharray="3 2" />
      <path
        d="M9.3 9.2a2.7 2.7 0 0 1 5.2 1c0 1.8-2.5 2-2.5 3.6"
        stroke="currentColor"
        strokeWidth={1.6}
        strokeLinecap="round"
      />
      <circle cx={12} cy={17} r={0.9} fill="currentColor" />
    </svg>
  );
}

function UnresolvedNodeBase(props: NodeProps) {
  const data = props.data as unknown as RFNodeData;
  const { node, emphasis, showLabel } = data;

  const dim = emphasis === "dim";
  const spotlight = emphasis === "spotlight";
  // muted even when "normal"
  const opacity = dim ? 0.3 : spotlight ? 0.85 : 0.6;

  return (
    <div
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 8,
        maxWidth: 200,
        boxSizing: "border-box",
        padding: "8px 12px",
        borderRadius: 14,
        background: "var(--panel)",
        border: `1px dashed ${spotlight ? "var(--accent)" : SLATE}`,
        opacity,
        color: "var(--fg-muted)",
      }}
    >
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />

      <span style={{ display: "inline-flex", color: SLATE, flex: "0 0 auto" }}>
        <UnknownIcon />
      </span>

      <div style={{ minWidth: 0, display: "flex", flexDirection: "column", gap: 2 }}>
        <span
          style={{
            fontSize: 10,
            fontWeight: 700,
            letterSpacing: 0.6,
            textTransform: "uppercase",
            color: SLATE,
          }}
        >
          Unresolved
        </span>
        {showLabel && node.label && (
          <span
            style={{
              fontSize: 12,
              fontWeight: 600,
              color: "var(--fg-muted)",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
              maxWidth: 130,
            }}
          >
            {node.label}
          </span>
        )}
      </div>

      <span
        title={`Confidence ${confidencePct(node.confidence)}`}
        style={{
          marginLeft: "auto",
          fontSize: 9,
          fontFamily:
            "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
          color: "var(--fg-subtle)",
          flex: "0 0 auto",
        }}
      >
        {confidencePct(node.confidence)}
      </span>

      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />
    </div>
  );
}

export const UnresolvedNode = memo(UnresolvedNodeBase);
export default UnresolvedNode;
