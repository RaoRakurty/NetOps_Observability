// index.ts — barrel re-export of the mock TopologyView datasets.
//
// These are fixtures for building & demoing the topology renderers against the
// renderer-agnostic TopologyView contract. Not used in production data paths.

export { physicalTopology } from "./physicalTopology";
export { pathTopology } from "./pathTopology";
export { incidentTopology } from "./incidentTopology";
export { cloudTopology } from "./cloudTopology";
export { capacityTopology } from "./capacityTopology";
export { enterpriseOverviewTopology } from "./enterpriseOverviewTopology";
export { geoWanTopology } from "./geoWanTopology";
