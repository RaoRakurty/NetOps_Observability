// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// InferredEdge.tsx — dashed/dotted, low-opacity slate edge for inferred /
// dependency / flow relationships. It must visibly read as "derived, not directly
// observed" so an operator never mistakes it for a confirmed L2 link. Honesty
// rule: it stays slate + dashed/dotted even when spotlighted.
//
// Confidence distinction (skill design-tokens): solid = confirmed (other edges),
// DASHED = inferred, DOTTED = low confidence. Below DOTTED_CONFIDENCE we drop to
// a round-dotted line; otherwise a dashed line.

import { type EdgeProps } from "@xyflow/react";
import { memo } from "react";
import type { RFEdgeData } from "../rfTypes";
import { EdgeBody, utilizationWidth } from "./TopologyEdge";
import { DOTTED_CONFIDENCE } from "../../../utils/topologyHealth";

const INFERRED_COLOR = "#64748b"; // slate — "no hard signal", matches unknown health

function InferredEdgeBase(props: EdgeProps) {
  const data = props.data as unknown as RFEdgeData | undefined;
  const emphasis = data?.emphasis ?? "normal";
  const overlay = data?.overlay;
  const edge = data?.edge;

  // Even when spotlighted, an inferred edge stays slate + dashed/dotted (honest).
  let width = emphasis === "strong" ? 2.2 : emphasis === "normal" ? 1.6 : 1.2;
  if (overlay === "utilization") width = utilizationWidth(width, edge?.utilization_pct);

  // Low confidence → DOTTED (tight round dots); otherwise inferred → DASHED.
  const lowConfidence = (edge?.confidence ?? 1) < DOTTED_CONFIDENCE;
  const dash = lowConfidence ? "1 6" : "5 5";

  return (
    <EdgeBody
      props={props}
      color={INFERRED_COLOR}
      width={width}
      dash={dash}
      glow={emphasis === "strong"}
      style={lowConfidence ? { strokeLinecap: "round" } : undefined}
    />
  );
}

export const InferredEdge = memo(InferredEdgeBase);
export default InferredEdge;
