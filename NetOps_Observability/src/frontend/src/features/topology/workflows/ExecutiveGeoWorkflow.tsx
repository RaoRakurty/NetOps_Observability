// ExecutiveGeoWorkflow — PLACEHOLDER (Phase 5).
//
// The executive geo / WAN view. Will render sites and WAN circuits on a real map
// via MapLibre GL JS + deck.gl (see renderers/geo). Carries the geo view so the
// selector can preview it, but has no spotlight logic until Phase 5.

import type { WorkflowDef } from "./workflowTypes";
import { geoWanTopology } from "../mock/index";

export const ExecutiveGeoWorkflow: WorkflowDef = {
  id: "executive_geo",
  label: "Executive / Geo",
  blurb: "Sites and WAN circuits on a geographic map via MapLibre + deck.gl (Phase 5).",
  implemented: false,
  view: geoWanTopology,
};

export default ExecutiveGeoWorkflow;
