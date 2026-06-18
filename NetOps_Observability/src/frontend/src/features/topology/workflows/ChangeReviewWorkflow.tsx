// ChangeReviewWorkflow — PLACEHOLDER (Phase 6).
//
// Will diff a before/after window and overlay a golden-path delta so operators
// can review what a change actually did to the topology. No view or spotlight
// yet — the adapter boundary exists; the implementation lands in Phase 6.

import type { WorkflowDef } from "./workflowTypes";

export const ChangeReviewWorkflow: WorkflowDef = {
  id: "change_review",
  label: "Change Review",
  blurb: "Before/after diff with golden-path delta to review a change's blast radius (Phase 6).",
  implemented: false,
};

export default ChangeReviewWorkflow;
