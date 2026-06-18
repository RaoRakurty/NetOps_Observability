// PathTraceWorkflow — Phase 1 (implemented).
//
// Follows a traced A→B path. Opens on the path topology and pre-spotlights the
// ordered path. A node selection overrides the default to that node's
// first-degree neighbourhood.

import type { WorkflowDef, SpotlightResult } from "./workflowTypes";
import type { TopologyView, TopologySelection } from "../api/topologyTypes";
import { firstDegree, edgesWithin, pathEdgeIds } from "../graph/graphAlgorithms";
import { pathTopology } from "../mock/index";

export const PathTraceWorkflow: WorkflowDef = {
  id: "path_trace",
  label: "Path Trace",
  blurb: "Follow a traced A→B path hop by hop. Select a hop to inspect its neighbours.",
  implemented: true,
  view: pathTopology,
  computeSpotlight(view: TopologyView, selection: TopologySelection): SpotlightResult {
    if (selection.nodeId) {
      const nodes = firstDegree(view, selection.nodeId);
      return { nodes, edges: edgesWithin(view, nodes) };
    }
    // Default: pre-spotlight the traced path.
    const path = view.path ?? [];
    return { nodes: new Set(path), edges: pathEdgeIds(view, path) };
  },
};

export default PathTraceWorkflow;
