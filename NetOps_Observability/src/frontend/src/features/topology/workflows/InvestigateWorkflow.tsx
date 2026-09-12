// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// InvestigateWorkflow — Phase 1 (implemented).
//
// The intense, incident-driven mode. Opens on the incident topology and
// pre-spotlights the RCA path so the operator lands on the blast radius. A node
// selection overrides the default to that node's first-degree neighbourhood.

import type { WorkflowDef, SpotlightResult } from "./workflowTypes";
import type { TopologyView, TopologySelection } from "../api/topologyTypes";
import { firstDegree, edgesWithin, pathEdgeIds } from "../graph/graphAlgorithms";
import { incidentTopology } from "../mock/index";

export const InvestigateWorkflow: WorkflowDef = {
  id: "investigate",
  label: "Investigate",
  blurb: "Triage an incident on its RCA path.",
  implemented: true,
  view: incidentTopology,
  computeSpotlight(view: TopologyView, selection: TopologySelection): SpotlightResult {
    if (selection.nodeId) {
      const nodes = firstDegree(view, selection.nodeId);
      return { nodes, edges: edgesWithin(view, nodes) };
    }
    // Default: pre-spotlight the RCA path (Investigate is intense by default).
    const path = view.path ?? [];
    return { nodes: new Set(path), edges: pathEdgeIds(view, path) };
  },
};

export default InvestigateWorkflow;
