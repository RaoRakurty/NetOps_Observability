// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// DegradedEdge.tsx — an unhealthy link (warning/critical). Uses HEALTH_COLOR for
// the edge status, a dashed-dotted pattern so degradation reads without relying on
// color alone (accessibility, PDF §11), and a warning glyph at mid-path.

import { type EdgeProps } from "@xyflow/react";
import { memo } from "react";
import type { ReactNode } from "react";
import type { RFEdgeData } from "../rfTypes";
import { EdgeBody, utilizationWidth, EdgeLabelCard } from "./TopologyEdge";
import { HEALTH_COLOR, HEALTH_GLYPH, statusToHealth } from "../../../utils/topologyHealth";

/** Small diamond + glyph at mid-path so degradation reads beyond color. */
function WarningGlyph({ x, y, color, glyph }: { x: number; y: number; color: string; glyph: string }): ReactNode {
  return (
    <g pointerEvents="none" transform={`translate(${x},${y})`}>
      <rect
        x={-7}
        y={-7}
        width={14}
        height={14}
        rx={3}
        transform="rotate(45)"
        fill={color}
        stroke="var(--panel)"
        strokeWidth={1.5}
      />
      <text
        x={0}
        y={0}
        textAnchor="middle"
        dominantBaseline="central"
        fontSize={9}
        fontWeight={700}
        fill="#fff"
        fontFamily="ui-monospace, monospace"
      >
        {glyph}
      </text>
    </g>
  );
}

function DegradedEdgeBase(props: EdgeProps) {
  const data = props.data as unknown as RFEdgeData | undefined;
  const emphasis = data?.emphasis ?? "normal";
  const overlay = data?.overlay;
  const edge = data?.edge;
  // edge.status is an EdgeStatus ("down"/"degraded"/…); map to a Health band.
  const health = statusToHealth(edge?.status ?? "warning");
  const color = HEALTH_COLOR[health];
  const glyph = HEALTH_GLYPH[health];

  // Unhealthy links are always at least 'normal' weight so they don't disappear.
  let width = emphasis === "strong" ? 3 : 2;
  if (overlay === "utilization") width = utilizationWidth(width, edge?.utilization_pct);

  return (
    <EdgeBody
      props={props}
      color={color}
      width={width}
      dash="6 3 1 3" // dash-dot
      glow={emphasis === "strong"}
      decoration={(geom) => (
        <WarningGlyph x={geom.labelX} y={geom.labelY} color={color} glyph={glyph} />
      )}
      // Nudge the default card down so it doesn't sit under the glyph.
      label={
        edge
          ? () => (
              <div style={{ transform: "translateY(16px)" }}>
                <EdgeLabelCard edge={edge} />
              </div>
            )
          : undefined
      }
    />
  );
}

export const DegradedEdge = memo(DegradedEdgeBase);
export default DegradedEdge;
