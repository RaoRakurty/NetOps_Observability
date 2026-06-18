// BundledEdge.tsx — a collapsed parallel-link bundle (LAG / 2×100G). Drawn as a
// DOUBLE stroke (a wider track with a thin inner line) so it visibly reads as
// "more than one physical member", with a small count chip at mid-path.
// Expand-on-click is future work; here we render the bundle look + count.

import {
  BaseEdge,
  EdgeLabelRenderer,
  getSmoothStepPath,
  type EdgeProps,
} from "@xyflow/react";
import { memo } from "react";
import type { RFEdgeData } from "../rfTypes";
import { utilizationWidth, EMPHASIS_TREATMENT } from "./TopologyEdge";
import { edgeEvidenceSummary } from "../../../utils/topologyHealth";

function BundledEdgeBase(props: EdgeProps) {
  const {
    id,
    sourceX,
    sourceY,
    targetX,
    targetY,
    sourcePosition,
    targetPosition,
    markerEnd,
  } = props;
  const data = props.data as unknown as RFEdgeData | undefined;
  const emphasis = data?.emphasis ?? "normal";
  const edge = data?.edge;
  const overlay = data?.overlay;

  const [path, labelX, labelY] = getSmoothStepPath({
    sourceX,
    sourceY,
    targetX,
    targetY,
    sourcePosition,
    targetPosition,
    borderRadius: 14,
  });

  const t = EMPHASIS_TREATMENT[emphasis];
  const color = emphasis === "strong" ? "var(--accent)" : "var(--fg-muted)";

  // Outer track is deliberately thick (the "bundle"); inner is a thin highlight,
  // creating the double-stroke read. Utilization overlay scales the outer track.
  let outer = Math.max(t.width + 3, 4.5);
  if (overlay === "utilization") outer = utilizationWidth(outer, edge?.utilization_pct);
  const inner = Math.max(1, outer - 3);

  const count = edge?.bundle_count ?? 2;
  const chip = edge?.bundle_id ? `${edge.bundle_id}` : `×${count}`;

  return (
    <>
      <BaseEdge
        id={`${id}-track`}
        path={path}
        style={{
          stroke: color,
          strokeWidth: outer,
          opacity: t.opacity * 0.45,
          strokeLinecap: "round",
        }}
      />
      <BaseEdge
        id={id}
        path={path}
        markerEnd={markerEnd}
        style={{
          stroke: emphasis === "strong" ? "var(--accent)" : "var(--surface)",
          strokeWidth: inner,
          opacity: t.opacity,
          strokeLinecap: "round",
        }}
      />
      <EdgeLabelRenderer>
        <div
          style={{
            position: "absolute",
            transform: `translate(-50%,-50%) translate(${labelX}px,${labelY}px)`,
            pointerEvents: "all",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            gap: 3,
          }}
          className="nodrag nopan"
        >
          {/* Always-visible count chip — the defining mark of a bundle. */}
          <span
            style={{
              background: "var(--panel)",
              border: "1px solid var(--border)",
              borderRadius: 999,
              padding: "1px 7px",
              fontSize: 10,
              fontWeight: 700,
              letterSpacing: 0.2,
              color: "var(--fg)",
              fontVariantNumeric: "tabular-nums",
              boxShadow: "0 2px 6px rgba(0,0,0,0.16)",
              whiteSpace: "nowrap",
              fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
            }}
          >
            {chip}
          </span>
          {data?.showLabel && edge && (
            <div
              style={{
                background: "var(--panel)",
                border: "1px solid var(--border)",
                borderRadius: 7,
                padding: "5px 8px",
                boxShadow: "0 4px 14px rgba(0,0,0,0.18)",
                fontSize: 11,
                lineHeight: 1.45,
                color: "var(--fg)",
                fontVariantNumeric: "tabular-nums",
                whiteSpace: "nowrap",
                fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
              }}
            >
              <div style={{ fontWeight: 600 }}>
                {edge.source_port || edge.target_port
                  ? `${edge.source_port ?? ""} → ${edge.target_port ?? ""}`
                  : `${edge.source} → ${edge.target}`}
              </div>
              <div style={{ color: "var(--fg-muted)" }}>
                {count} members · {edgeEvidenceSummary(edge)}
              </div>
              <div style={{ color: "var(--fg-muted)" }}>
                Util {edge.utilization_pct ?? 0}% · Err {edge.errors ?? 0} · seen {edge.last_seen ?? "—"}
              </div>
            </div>
          )}
        </div>
      </EdgeLabelRenderer>
    </>
  );
}

export const BundledEdge = memo(BundledEdgeBase);
export default BundledEdge;
