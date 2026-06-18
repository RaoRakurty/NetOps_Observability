// index.ts — the React Flow `edgeTypes` registry. Keys MUST match
// EDGE_TYPE_FOR_VARIANT in ../rfTypes.ts (adapter ↔ renderer contract).

import type { EdgeTypes } from "@xyflow/react";
import { TopologyEdge } from "./TopologyEdge";
import { PathHighlightEdge } from "./PathHighlightEdge";
import { InferredEdge } from "./InferredEdge";
import { DegradedEdge } from "./DegradedEdge";
import { BundledEdge } from "./BundledEdge";

export const edgeTypes: EdgeTypes = {
  topologyEdge: TopologyEdge,
  pathHighlightEdge: PathHighlightEdge,
  inferredEdge: InferredEdge,
  degradedEdge: DegradedEdge,
  bundledEdge: BundledEdge,
};

export {
  TopologyEdge,
  PathHighlightEdge,
  InferredEdge,
  DegradedEdge,
  BundledEdge,
};
export { EdgeBody, EdgeLabelCard, utilizationWidth, EMPHASIS_TREATMENT } from "./TopologyEdge";
