// CapacityWorkflow — PLACEHOLDER (Phase 2).
//
// Will surface hot links, ECMP imbalance and a utilization overlay so operators
// can spot saturation before it bites. No view or spotlight yet — the adapter
// boundary exists; the implementation lands in Phase 2.

import type { WorkflowDef } from "./workflowTypes";

export const CapacityWorkflow: WorkflowDef = {
  id: "capacity",
  label: "Capacity",
  blurb: "Hot links, ECMP balance and a utilization overlay across the fabric (Phase 2).",
  implemented: false,
};

export default CapacityWorkflow;
