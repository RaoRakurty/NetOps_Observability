// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// BundledEdge.tsx — a collapsed parallel-link bundle (LAG / 2×100G). Drawn as a
// DOUBLE stroke (a wider track with a thin inner line) so it visibly reads as
// "more than one physical member", with a small count chip at mid-path.
// Expand-on-click is future work; here we render the bundle look + count.

import {
  BaseEdge,
  EdgeLabelRenderer,
  getBezierPath,
  useInternalNode,
  type EdgeProps,
} from "@xyflow/react";
import { memo } from "react";
import type { RFEdgeData } from "../rfTypes";
import { utilizationWidth, EMPHASIS_TREATMENT, EdgeLabelCard } from "./TopologyEdge";
import { getEdgeParams } from "./floatingEdge";

function BundledEdgeBase(props: EdgeProps) {
  const { id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, markerEnd } = props;
  const data = props.data as unknown as RFEdgeData | undefined;
  const emphasis = data?.emphasis ?? "normal";
  const edge = data?.edge;
  const overlay = data?.overlay;

  // Floating geometry — same as EdgeBody so a bundle anchors and curves like every
  // other link (consistent fan-out, follows drags).
  const sourceNode = useInternalNode(props.source);
  const targetNode = useInternalNode(props.target);
  let sx = sourceX, sy = sourceY, tx = targetX, ty = targetY;
  let sPos = sourcePosition, tPos = targetPosition;
  if (sourceNode?.measured?.width && targetNode?.measured?.width) {
    const p = getEdgeParams(sourceNode, targetNode);
    sx = p.sx; sy = p.sy; tx = p.tx; ty = p.ty; sPos = p.sourcePos; tPos = p.targetPos;
  }
  const [path, labelX, labelY] = getBezierPath({
    sourceX: sx, sourceY: sy, targetX: tx, targetY: ty,
    sourcePosition: sPos, targetPosition: tPos, curvature: 0.28,
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
            // Non-interactive: the always-on count chip + the hover detail sit at
            // the edge midpoint. Capturing the pointer here would steal the hover
            // from the edge underneath and oscillate mouseleave/enter (canvas
            // shake). Both are read-only, so they never need pointer events.
            pointerEvents: "none",
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
          {/* Compact "where it goes" line; member count is the chip above, full
              detail (members · util · errors · evidence) is in the click drawer. */}
          {data?.showLabel && edge && <EdgeLabelCard edge={edge} />}
        </div>
      </EdgeLabelRenderer>
    </>
  );
}

export const BundledEdge = memo(BundledEdgeBase);
export default BundledEdge;
