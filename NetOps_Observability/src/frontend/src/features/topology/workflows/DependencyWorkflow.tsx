// DependencyWorkflow — Phase 1 (implemented).
//
// The app/service dependency map. Opens on the cloud topology and stays calm
// until a node is selected, then brightens that node's first-degree
// neighbourhood (its immediate upstream/downstream dependencies).

import type { WorkflowDef, SpotlightResult } from "./workflowTypes";
import { EMPTY_SPOTLIGHT } from "./workflowTypes";
import type { TopologyView, TopologySelection } from "../api/topologyTypes";
import { firstDegree, edgesWithin } from "../graph/graphAlgorithms";
import { cloudTopology } from "../mock/index";

export const DependencyWorkflow: WorkflowDef = {
  id: "dependency",
  label: "Dependency",
  blurb: "Application and service dependencies.",
  implemented: true,
  view: cloudTopology,
  computeSpotlight(view: TopologyView, selection: TopologySelection): SpotlightResult {
    if (selection.nodeId) {
      const nodes = firstDegree(view, selection.nodeId);
      return { nodes, edges: edgesWithin(view, nodes) };
    }
    return EMPTY_SPOTLIGHT;
  },
};

export default DependencyWorkflow;
