// CapacityWorkflow — Phase 2 (implemented).
//
// The capacity-planning view (PDF §9). Opens on a routed leaf-spine fabric and,
// by default, pre-spotlights the SATURATED links (and their endpoints) so the hot
// paths read instantly while the healthy fabric stays dim — calm-except-trouble.
// Selecting a node pivots the spotlight to that node's first-degree neighbourhood.
// The Capacity panel (docked by the canvas) ranks hot links + ECMP imbalance.

import type { WorkflowDef, SpotlightResult } from "./workflowTypes";
import type { TopologyView, TopologySelection } from "../api/topologyTypes";
import { firstDegree, edgesWithin } from "../graph/graphAlgorithms";
import { saturatedEdgeIds } from "../utils/topologyCapacity";
import { capacityTopology } from "../mock/index";

export const CapacityWorkflow: WorkflowDef = {
  id: "capacity",
  label: "Capacity",
  blurb: "Hot links and equal-cost balance.",
  implemented: true,
  view: capacityTopology,
  computeSpotlight(view: TopologyView, selection: TopologySelection): SpotlightResult {
    if (selection.nodeId) {
      const nodes = firstDegree(view, selection.nodeId);
      return { nodes, edges: edgesWithin(view, nodes) };
    }
    // Default: spotlight saturated links + their endpoints.
    const edges = saturatedEdgeIds(view);
    const nodes = new Set<string>();
    for (const e of view.edges) {
      if (edges.has(e.id)) {
        nodes.add(e.source);
        nodes.add(e.target);
      }
    }
    return { nodes, edges };
  },
};

export default CapacityWorkflow;
