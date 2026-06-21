// RcaOverlayEdge.tsx — a link carrying an RCA Layer-3 verdict (edge.rca_status).
// This is the edge counterpart to the node RcaMarker: it renders the engine's
// grounded state with a DISTINCT treatment so "suspected" never looks like
// "confirmed". Line style + glyph come from utils/rcaOverlay (single source of
// truth); colour is never the only signal.
//
//   suspected_down → red dashed + ⚠   (evidence points here, NOT certain)
//   confirmed_down → red solid + ✕     (independently confirmed)
//   degraded       → amber dash-dot + ! (flowing when motion is allowed)
//   insufficient_visibility / missing_evidence → slate dotted + ? / ○ (honest gap)
//   observed       → green solid + ●   (this hop is observed-good)

import { type EdgeProps } from "@xyflow/react";
import { memo } from "react";
import type { ReactNode } from "react";
import type { RFEdgeData } from "../rfTypes";
import { EdgeBody, EdgeLabelCard } from "./TopologyEdge";
import { RCA_OVERLAY } from "../../../utils/rcaOverlay";

/** Diamond + glyph (filled) or a hollow ring at mid-path so the state reads beyond colour. */
function StateGlyph({ x, y, color, glyph, hollow }: { x: number; y: number; color: string; glyph: string; hollow: boolean }): ReactNode {
  if (hollow) {
    return (
      <g pointerEvents="none" transform={`translate(${x},${y})`}>
        <circle cx={0} cy={0} r={7} fill="var(--panel)" stroke={color} strokeWidth={1.8} strokeDasharray="2 2" />
      </g>
    );
  }
  return (
    <g pointerEvents="none" transform={`translate(${x},${y})`}>
      <rect x={-7} y={-7} width={14} height={14} rx={3} transform="rotate(45)" fill={color} stroke="var(--panel)" strokeWidth={1.5} />
      <text x={0} y={0} textAnchor="middle" dominantBaseline="central" fontSize={9} fontWeight={700} fill="#fff" fontFamily="ui-monospace, monospace">
        {glyph}
      </text>
    </g>
  );
}

function RcaOverlayEdgeBase(props: EdgeProps) {
  const data = props.data as unknown as RFEdgeData | undefined;
  const edge = data?.edge;
  const emphasis = data?.emphasis ?? "normal";
  // edge.rca_status is guaranteed by the variant router (edgeVariant → "rca"); fall
  // back to insufficient_visibility defensively so a stray edge never throws.
  const s = RCA_OVERLAY[edge?.rca_status ?? "insufficient_visibility"];

  // RCA edges read at least 'normal' weight (they're the focus of the view); on the
  // fault path they're 'strong'. A calm 'observed' hop stays thinner than a fault.
  const fault = edge?.rca_status === "confirmed_down" || edge?.rca_status === "suspected_down";
  const width = emphasis === "strong" ? 3 : fault ? 2.4 : 2;

  return (
    <EdgeBody
      props={props}
      color={s.color}
      width={width}
      dash={s.dash}
      glow={emphasis === "strong" || fault}
      className={s.animate && s.dash ? "topo-rca-edge-flow" : undefined}
      decoration={(geom) => <StateGlyph x={geom.labelX} y={geom.labelY} color={s.color} glyph={s.glyph} hollow={s.hollow} />}
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

export const RcaOverlayEdge = memo(RcaOverlayEdgeBase);
export default RcaOverlayEdge;
