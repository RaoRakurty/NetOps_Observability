// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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
// HONESTY OVER "GRACEFUL DEGRADATION": every real surface shows REAL data or an
// honest empty/error state — NEVER a fabricated demo network presented as the
// operator's own. A failed fetch is not "no data" either, so each fetcher returns
// an empty view plus a status discriminator ("live" | "empty" | "error") and the
// canvas renders which one it is. The bundled mock views survive ONLY for the
// not-yet-implemented workflow modes, which are labelled as samples in the UI.

import type { TopologyView, WorkflowMode } from "./topologyTypes";
import { normalizeView } from "../utils/topologyMapper";
import { rcaPathToView } from "./rcaPathToView";
import { api, type RcaPathView } from "../../../services/api";
import {
  physicalTopology,
  pathTopology,
  incidentTopology,
  cloudTopology,
  capacityTopology,
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
    case "capacity":
      return capacityTopology;
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
 * The response is always normalized before reaching the renderer. On any error (or
 * an empty graph) an EMPTY view is returned — never a mock — so the canvas renders
 * its honest "nothing to display" state. Only the not-yet-implemented modes (those
 * outside REAL_MODES) render a bundled sample view.
 */
/** Modes the Go projection serves with real data; others stay mock-only. */
const REAL_MODES: ReadonlySet<WorkflowMode> = new Set<WorkflowMode>([
  "explore",
  "investigate",
  "path_trace",
  "dependency",
  "capacity",
  "executive_geo",
]);

/** What the live-view read actually established (drives the honest UI state). */
export type TopologyViewStatus = "live" | "empty" | "error" | "sample";

export async function fetchTopologyView(
  mode: WorkflowMode,
  params?: { src?: string; dst?: string },
): Promise<{ view: TopologyView; status: TopologyViewStatus }> {
  if (!REAL_MODES.has(mode)) return { view: normalizeView(mockForMode(mode)), status: "sample" };
  const emptyView = (): TopologyView => normalizeView({
    view_id: `empty-${mode}`, mode, scope: { tenant_id: "" }, layout_type: "spine_leaf",
    generated_at: new Date().toISOString(), nodes: [], edges: [], groups: [], overlays: [],
  } as unknown as TopologyView);
  try {
    // Path Trace passes src/dst so the backend resolves a real A→B path; the other
    // modes ignore them. Only forward when both endpoints are set.
    const ep = params?.src && params?.dst ? { src: params.src, dst: params.dst } : undefined;
    const raw = (await api.topologyView(mode, ep)) as TopologyView;
    // HONESTY (zero-trust on display): a real mode shows REAL data or an honest empty
    // state — NEVER fabricated demo nodes presented as the live network. An empty
    // graph (collectors off / no inventory / no flow attribution) returns the empty
    // view so the canvas renders its "nothing to display" state, not a fake cloud map.
    const view = normalizeView(raw);
    return view.nodes.length > 0 ? { view, status: "live" } : { view: emptyView(), status: "empty" };
  } catch (err) {
    // A failed fetch is not "no data" either (audit S2: this branch used to be
    // indistinguishable from an empty network — an API outage rendered as "you
    // have no devices"). status:"error" lets the canvas say which, honestly.
    console.warn("topology view fetch failed", mode, err);
    return { view: emptyView(), status: "error" };
  }
}

/** What the cloud-topology read actually established (drives the honest UI state). */
export type CloudTopologyStatus = "live" | "empty" | "error";

/**
 * Fetch the in-cloud NETWORK topology (GET /api/topology/cloud): the discovered
 * VPC/VNet → subnet → route-table → gateway/NVA graph, mapped server-side from the
 * provider APIs (route tables are the authoritative egress facts).
 *
 * HONESTY (2026-07 product review): the SAME rule as fetchTopologyView applies —
 * real surfaces show REAL data or an honest empty state, NEVER a fabricated cloud
 * network presented as the operator's own. The old grounded-mock fallback rendered
 * a fake VPC map to any tenant with no discovered cloud network; it is gone.
 * Returns `{ view, live, status }` — `live` is true only when the API served a
 * real, non-empty topology; `status` distinguishes "nothing discovered" (empty)
 * from "the read failed" (error) so the tab can say which honestly.
 */
export async function fetchCloudTopology(): Promise<{ view: TopologyView; live: boolean; status: CloudTopologyStatus }> {
  const emptyView = (): TopologyView => normalizeView({
    view_id: "cloud-network-empty", mode: "explore", scope: { tenant_id: "" },
    layout_type: "cloud_grouped", generated_at: new Date().toISOString(),
    nodes: [], edges: [], groups: [], overlays: ["health"],
  } as unknown as TopologyView);
  try {
    const raw = (await api.topologyCloud()) as TopologyView;
    const view = normalizeView(raw);
    if (view.nodes.length > 0) return { view, live: true, status: "live" };
    return { view: emptyView(), live: false, status: "empty" };
  } catch {
    return { view: emptyView(), live: false, status: "error" };
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

/** What the persistent-graph read actually established (drives the honest UI state). */
export type TopologyGraphStatus = "live" | "empty" | "error";

/**
 * Fetch the PERSISTENT topology graph (GET /api/topology/graph): the reconciler-
 * maintained spine with stable ids + first_seen/last_seen + stale (carried as each
 * node/edge's change_state) + live health/util enrichment, plus a coverage summary.
 * Mode-agnostic (the whole tenant graph).
 *
 * HONESTY: identical rule to {@link fetchTopologyView} / {@link fetchCloudTopology}.
 * This used to fall back to `physicalTopology` — a MOCK spine-leaf fabric — on both
 * the error path and the zero-node path, so an operator whose graph service was
 * down was shown a fabricated healthy network of devices that were not theirs, as
 * their live graph. That fallback is gone: returns an empty view plus `status`
 * distinguishing "nothing reconciled yet" (empty) from "the read failed" (error).
 */
export async function fetchTopologyGraph(): Promise<{ view: TopologyView; coverage?: TopologyCoverage; status: TopologyGraphStatus }> {
  const emptyView = (): TopologyView => normalizeView({
    view_id: "topology-graph-empty", mode: "explore", scope: { tenant_id: "" },
    layout_type: "spine_leaf", generated_at: new Date().toISOString(),
    nodes: [], edges: [], groups: [], overlays: ["health"],
  } as unknown as TopologyView);
  try {
    const raw = (await api.topologyGraph()) as TopologyView & { coverage?: TopologyCoverage };
    const view = normalizeView(raw);
    if (view.nodes.length > 0) return { view, coverage: raw.coverage, status: "live" };
    return { view: emptyView(), status: "empty" };
  } catch {
    return { view: emptyView(), status: "error" };
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
