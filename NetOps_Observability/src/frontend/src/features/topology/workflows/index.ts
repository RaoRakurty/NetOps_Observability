// index.ts — the ordered registry of topology workflows.
//
// Display order is deliberate: the three Phase-1 implemented modes first, then
// the remaining placeholders, ending on the executive geo view.

import type { WorkflowDef } from "./workflowTypes";
import type { WorkflowMode } from "../api/topologyTypes";

import ExploreWorkflow from "./ExploreWorkflow";
import InvestigateWorkflow from "./InvestigateWorkflow";
import PathTraceWorkflow from "./PathTraceWorkflow";
import DependencyWorkflow from "./DependencyWorkflow";
import CapacityWorkflow from "./CapacityWorkflow";
import ChangeReviewWorkflow from "./ChangeReviewWorkflow";
import ExecutiveGeoWorkflow from "./ExecutiveGeoWorkflow";

export const WORKFLOWS: WorkflowDef[] = [
  ExploreWorkflow,
  InvestigateWorkflow,
  PathTraceWorkflow,
  DependencyWorkflow,
  CapacityWorkflow,
  ChangeReviewWorkflow,
  ExecutiveGeoWorkflow,
];

export function workflowById(id: WorkflowMode): WorkflowDef | undefined {
  return WORKFLOWS.find((w) => w.id === id);
}
