// ExecutiveGeoWorkflow — the executive geo / WAN view.
//
// The geographic map is a RENDERER, not a node-link layout: it lives behind the
// "Geo" renderer toggle (top-right of the canvas), which mounts GeoTopologyMap
// (ECharts world basemap, sites + WAN circuits). This workflow descriptor carries
// NO `view` on purpose — its geo data has geographic coordinates the ELK/React-Flow
// canvas can't lay out, so selecting this mode in the Canvas renderer shows a
// placeholder that points the operator at the Geo toggle.

import type { WorkflowDef } from "./workflowTypes";

export const ExecutiveGeoWorkflow: WorkflowDef = {
  id: "executive_geo",
  label: "Executive / Geo",
  blurb: "Sites and WAN circuits on a map.",
  implemented: false,
};

export default ExecutiveGeoWorkflow;
