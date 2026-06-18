// PathHighlightEdge.tsx — the thick accent edge for a traced path / RCA causal
// chain. Always reads as 'strong': accent stroke, soft glow underlay, and a
// subtle animated dash that flows source→target to convey traffic direction.

import { type EdgeProps } from "@xyflow/react";
import { memo } from "react";
import type { RFEdgeData } from "../rfTypes";
import { EdgeBody, utilizationWidth, ErrorMarker } from "./TopologyEdge";

// Keyframes are injected once; React Flow renders many edges so we keep a single
// global <style> rather than per-edge style tags.
const DASH_ANIM_ID = "topo-path-dash-anim";
function ensureDashAnim(): void {
  if (typeof document === "undefined") return;
  if (document.getElementById(DASH_ANIM_ID)) return;
  const style = document.createElement("style");
  style.id = DASH_ANIM_ID;
  style.textContent = `@keyframes topoPathDash { to { stroke-dashoffset: -24; } }
.topo-path-edge { animation: topoPathDash 1s linear infinite; }`;
  document.head.appendChild(style);
}

function PathHighlightEdgeBase(props: EdgeProps) {
  ensureDashAnim();
  const data = props.data as unknown as RFEdgeData | undefined;
  const overlay = data?.overlay;
  const edge = data?.edge;

  let width = 3.2;
  if (overlay === "utilization") width = utilizationWidth(width, edge?.utilization_pct);

  return (
    <EdgeBody
      props={props}
      color="var(--accent)"
      width={width}
      dash="6 10"
      glow
      style={{ animation: "topoPathDash 1s linear infinite" }}
      decoration={
        overlay === "interface_errors" && (edge?.errors ?? 0) > 0
          ? (geom) => <ErrorMarker x={geom.labelX} y={geom.labelY} />
          : undefined
      }
    />
  );
}

export const PathHighlightEdge = memo(PathHighlightEdgeBase);
export default PathHighlightEdge;
