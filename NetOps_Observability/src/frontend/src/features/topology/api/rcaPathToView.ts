// rcaPathToView.ts — convert an RCA path-overlay (GET /api/correlations/{id}/
// rca-path-view) into the canonical TopologyView the operating canvas renders
// (#77, design doc "RCA overlay"). This lets Investigate mode show a REAL
// incident's fault path on the canvas (elk layout, device nodes) instead of a
// mock, reusing the whole render pipeline.
//
// Overlay-state fidelity: the canvas health/status enums don't have distinct
// suspected_down vs confirmed_down treatments yet (that lands with the edge-
// component work in topology increment #2/#3). For now both map to the closest
// existing severity (confirmed → critical/down, suspected/degraded → warning/
// degraded) so the path reads correctly by colour; the verdict banner carries the
// precise wording. Pure (no I/O) → unit-testable.

import type { RcaPathView, RcaPathNode, RcaPathEdge } from "../../../services/api";
import type { TopologyView, TopologyNode, TopologyEdge, NodeKind, Health, EdgeStatus, EdgeRelationship } from "./topologyTypes";

/** Map the path node's shape hint to a canonical NodeKind. */
function kindFor(hint: string): NodeKind {
  switch ((hint || "").toLowerCase()) {
    case "router":
    case "gateway":
    case "core":
      return "router";
    case "switch":
    case "access":
      return "switch";
    case "firewall":
      return "firewall";
    case "cloud":
      return "cloud";
    case "vantage":
    case "target":
    case "endpoint":
    case "server":
      return "server";
    default:
      return "unresolved";
  }
}

/** Worst-of node health from its overlay status, then its RCA role. */
function nodeHealth(n: RcaPathNode): Health {
  switch ((n.status || "").toLowerCase()) {
    case "confirmed_down":
      return "critical";
    case "suspected_down":
    case "degraded":
      return "warning";
    case "observed":
      return "ok";
    case "insufficient_visibility":
    case "missing_evidence":
    case "internal_only":
      return "unknown";
  }
  switch ((n.role || "").toLowerCase()) {
    case "fault":
      return "critical";
    case "suspected":
    case "affected":
      return "warning";
    default:
      return "unknown";
  }
}

/** Map the path edge's overlay state to the closest EdgeStatus. */
function edgeStatus(state: string): EdgeStatus {
  switch ((state || "").toLowerCase()) {
    case "healthy":
      return "up";
    case "degraded":
      return "degraded";
    case "suspected_down":
      return "warning";
    case "confirmed_down":
      return "down";
    default:
      return "unknown";
  }
}

function edgeRelationship(type: string): EdgeRelationship {
  switch ((type || "").toLowerCase()) {
    case "bgp_session":
      return "routed_adjacency";
    case "provider_boundary":
      return "inferred";
    default:
      return "path_hop";
  }
}

/**
 * Convert an RcaPathView into a TopologyView. Per-target annotations override the
 * inline node/edge status (the annotation layer is authoritative). The returned
 * view's `path` is the ordered node ids source→destination so the canvas
 * highlights the fault path.
 */
export function rcaPathToView(rpv: RcaPathView): TopologyView {
  // Annotation status by target id (authoritative overlay).
  const annStatus = new Map<string, string>();
  for (const a of rpv.annotations || []) {
    if (a.target_id && a.status) annStatus.set(a.target_id, a.status);
  }

  const nodes: TopologyNode[] = (rpv.path?.nodes || []).map((n) => {
    const merged: RcaPathNode = { ...n, status: annStatus.get(n.id) || n.status };
    return {
      id: n.id,
      label: n.label,
      kind: kindFor(n.kind),
      role: n.role,
      health: nodeHealth(merged),
      confidence: rpv.confidence || 1,
      resolved: kindFor(n.kind) !== "unresolved",
      evidence: [{ source: "trace", confidence: rpv.confidence || 1, detail: merged.status || n.role || "" }],
    };
  });

  const edges: TopologyEdge[] = (rpv.path?.edges || []).map((e: RcaPathEdge) => {
    const state = annStatus.get(e.id) || e.state;
    return {
      id: e.id,
      source: e.source,
      target: e.target,
      relationship: edgeRelationship(e.type),
      status: edgeStatus(state),
      confidence: rpv.confidence || 1,
      evidence: [{ source: "trace", confidence: rpv.confidence || 1, detail: e.label || state || "" }],
    };
  });

  // Ordered fault path: source → … → destination (by node order, endpoints first/last).
  const path = nodes.map((n) => n.id);

  return {
    view_id: `rca-${rpv.corr_object_id}`,
    mode: "investigate",
    layout_type: "path_first",
    generated_at: new Date().toISOString(),
    nodes,
    edges,
    groups: [],
    overlays: ["health"],
    path,
    scope: { incident_id: rpv.corr_object_id },
  };
}
