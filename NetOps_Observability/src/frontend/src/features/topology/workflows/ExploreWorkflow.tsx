// ExploreWorkflow — Phase 1 (implemented).
//
// The calm, day-to-day "look around the fabric" mode. Opens on the physical
// topology and stays quiet until the operator selects a node, at which point it
// brightens that node's first-degree neighbourhood (acceptance #2).

import type { WorkflowDef, SpotlightResult } from "./workflowTypes";
import { EMPTY_SPOTLIGHT } from "./workflowTypes";
import type { TopologyView, TopologySelection } from "../api/topologyTypes";
import { firstDegree, edgesWithin } from "../graph/graphAlgorithms";
import { physicalTopology } from "../mock/index";

export const ExploreWorkflow: WorkflowDef = {
  id: "explore",
  label: "Explore",
  blurb: "Browse the physical fabric. Select a device to light up its neighbours.",
  implemented: true,
  view: physicalTopology,
  computeSpotlight(view: TopologyView, selection: TopologySelection): SpotlightResult {
    if (selection.nodeId) {
      const nodes = firstDegree(view, selection.nodeId);
      return { nodes, edges: edgesWithin(view, nodes) };
    }
    // Calm default: nothing dimmed, nothing forced.
    return EMPTY_SPOTLIGHT;
  },
};

export default ExploreWorkflow;
