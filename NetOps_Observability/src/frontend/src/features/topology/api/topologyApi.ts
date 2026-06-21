// topologyApi.ts — the topology API client.
//
// The real backend is a Go graph-projection service that resolves identities,
// scores confidence, windows by time and returns a resolved TopologyView:
//
//     GET /api/topology/view?mode=<WorkflowMode>&...   →   TopologyView (JSON)
//
// The contract is immovable: the API returns a renderer-agnostic TopologyView and
// NEVER React Flow nodes. The client always runs the response through normalizeView
// so the UI gets a safe, evidence-backed graph regardless of backend bugs.
//
// GRACEFUL DEGRADATION: if the endpoint errors, or returns an EMPTY graph (e.g.
// collectors are off, or a mode the backend doesn't yet project with real data),
// we fall back to the matching mock view so the canvas always renders something
// meaningful instead of a blank screen.

import type { TopologyView, WorkflowMode } from "./topologyTypes";
import { normalizeView } from "../utils/topologyMapper";
import { rcaPathToView } from "./rcaPathToView";
import { api, type RcaPathView } from "../../../services/api";
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
 *   GET /api/topology/view?mode=… → TopologyView
 *
 * The response is always normalized before reaching the renderer. On any error
 * (or an empty graph) the matching mock view is used so the canvas never blanks.
 */
/** Modes the Go projection serves with real data; others stay mock-only. */
const REAL_MODES: ReadonlySet<WorkflowMode> = new Set<WorkflowMode>([
  "explore",
  "investigate",
  "path_trace",
  "dependency",
  "executive_geo",
]);

export async function fetchTopologyView(
  mode: WorkflowMode,
  params?: { src?: string; dst?: string },
): Promise<TopologyView> {
  if (!REAL_MODES.has(mode)) return normalizeView(mockForMode(mode));
  try {
    // Path Trace passes src/dst so the backend resolves a real A→B path; the other
    // modes ignore them. Only forward when both endpoints are set.
    const ep = params?.src && params?.dst ? { src: params.src, dst: params.dst } : undefined;
    const raw = (await api.topologyView(mode, ep)) as TopologyView;
    const view = normalizeView(raw);
    if (view.nodes.length > 0) return view;
    // Empty real graph (collectors off / no inventory) → show the mock instead.
    return normalizeView(mockForMode(mode));
  } catch {
    return normalizeView(mockForMode(mode));
  }
}

/** Coverage summary returned alongside the persistent graph (#77). */
export type TopologyCoverage = {
  nodes: number;
  edges: number;
  stale_nodes: number;
  stale_edges: number;
  resolved_edges: number;
};

/**
 * Fetch the PERSISTENT topology graph (GET /api/topology/graph): the reconciler-
 * maintained spine with stable ids + first_seen/last_seen + stale (carried as each
 * node/edge's change_state) + live health/util enrichment, plus a coverage summary.
 * Mode-agnostic (the whole tenant graph). Same graceful degradation as the live
 * view: an empty/errored graph falls back to the physical mock so the canvas never
 * blanks.
 */
export async function fetchTopologyGraph(): Promise<{ view: TopologyView; coverage?: TopologyCoverage }> {
  try {
    const raw = (await api.topologyGraph()) as TopologyView & { coverage?: TopologyCoverage };
    const view = normalizeView(raw);
    if (view.nodes.length > 0) return { view, coverage: raw.coverage };
    return { view: normalizeView(physicalTopology) };
  } catch {
    return { view: normalizeView(physicalTopology) };
  }
}

/**
 * Fetch a REAL incident's RCA fault path as a TopologyView (#77): resolves the
 * correlation object's path overlay (GET /api/correlations/{id}/rca-path-view),
 * converts it to the canonical view via the pure {@link rcaPathToView} adapter,
 * then normalizes it for the renderer. Returns null on any error or an empty path
 * so the caller falls back to the live Investigate projection — the canvas never
 * blanks on a malformed or visibility-restricted incident. The raw `overlay` is
 * carried alongside the view so the canvas can render the verdict banner (title,
 * summary, recommended action, missing evidence) — the anti-black-box narrative.
 */
export async function fetchRcaPathView(
  corrId: string,
): Promise<{ view: TopologyView; overlay: RcaPathView } | null> {
  try {
    const overlay = await api.rcaPathView(corrId);
    const view = normalizeView(rcaPathToView(overlay));
    return view.nodes.length > 0 ? { view, overlay } : null;
  } catch {
    return null;
  }
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
