// topologyApi.ts — the topology API client.
//
// STUB: today this serves mock TopologyViews. The real backend is a Go graph-
// projection service that resolves identities, scores confidence, windows by time
// and returns a resolved TopologyView. When it lands, fetchTopologyView becomes a
// real call:
//
//     GET /api/topology/view?mode=<WorkflowMode>&...   →   TopologyView (JSON)
//
// The contract is immovable: the API returns a renderer-agnostic TopologyView and
// NEVER React Flow nodes. The client always runs the response through normalizeView
// so the UI gets a safe, evidence-backed graph regardless of backend bugs.

import type { TopologyView, WorkflowMode } from "./topologyTypes";
import { normalizeView } from "../utils/topologyMapper";
import {
  physicalTopology,
  pathTopology,
  incidentTopology,
  cloudTopology,
  enterpriseOverviewTopology,
  geoWanTopology,
} from "../mock";

/** Pick the mock view that matches an operator workflow mode. */
function mockForMode(mode: WorkflowMode): TopologyView {
  switch (mode) {
    case "explore":
      return physicalTopology;
    case "path_trace":
      return pathTopology;
    case "investigate":
      return incidentTopology;
    case "dependency":
      return cloudTopology;
    case "executive_geo":
      return geoWanTopology;
    default:
      return enterpriseOverviewTopology;
  }
}

/**
 * Fetch the resolved TopologyView for a workflow mode.
 *
 * Stubbed against mocks for now (wrapped in Promise.resolve so the signature is
 * already the async one the real client will use). Will become
 *   GET /api/topology/view?mode=… → TopologyView
 * The response is always normalized before reaching the renderer.
 */
export async function fetchTopologyView(mode: WorkflowMode): Promise<TopologyView> {
  return Promise.resolve(normalizeView(mockForMode(mode)));
}

/** Catalogue of operator workflows for the mode switcher (PDF §9). */
export function listWorkflowMeta(): {
  id: WorkflowMode;
  label: string;
  implemented: boolean;
  blurb: string;
}[] {
  return [
    {
      id: "explore",
      label: "Explore",
      implemented: true,
      blurb: "Browse the physical/logical fabric and expand neighbourhoods hop by hop.",
    },
    {
      id: "investigate",
      label: "Investigate",
      implemented: true,
      blurb: "Incident-centred view with blast radius and RCA evidence on the graph.",
    },
    {
      id: "path_trace",
      label: "Path trace",
      implemented: true,
      blurb: "Highlight the A→B path, its hops and where it diverges from the golden path.",
    },
    {
      id: "dependency",
      label: "Dependency",
      implemented: true,
      blurb: "App/cloud dependency map built from observed flows and cloud APIs.",
    },
    {
      id: "change_review",
      label: "Change review",
      implemented: false,
      blurb: "Diff topology across a time window: what was added, removed or changed.",
    },
    {
      id: "capacity",
      label: "Capacity",
      implemented: false,
      blurb: "Utilization and headroom overlay for capacity planning.",
    },
    {
      id: "executive_geo",
      label: "Executive geo",
      implemented: false,
      blurb: "Geographic WAN rollup for executive and NOC wallboards.",
    },
  ];
}
