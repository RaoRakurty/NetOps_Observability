// InferredEdge.tsx — dashed, low-opacity slate edge for inferred / dependency /
// flow relationships (low confidence). It must visibly read as "derived, not
// directly observed" so an operator never mistakes it for a confirmed L2 link.

import { type EdgeProps } from "@xyflow/react";
import { memo } from "react";
import type { RFEdgeData } from "../rfTypes";
import { EdgeBody, utilizationWidth } from "./TopologyEdge";

const INFERRED_COLOR = "#64748b"; // slate — "no hard signal", matches unknown health

function InferredEdgeBase(props: EdgeProps) {
  const data = props.data as unknown as RFEdgeData | undefined;
  const emphasis = data?.emphasis ?? "normal";
  const overlay = data?.overlay;
  const edge = data?.edge;

  // Even when spotlighted, an inferred edge stays slate + dashed (honest).
  let width = emphasis === "strong" ? 2.2 : emphasis === "normal" ? 1.6 : 1.2;
  if (overlay === "utilization") width = utilizationWidth(width, edge?.utilization);

  return (
    <EdgeBody
      props={props}
      color={INFERRED_COLOR}
      width={width}
      dash="5 5"
      glow={emphasis === "strong"}
    />
  );
}

export const InferredEdge = memo(InferredEdgeBase);
export default InferredEdge;
