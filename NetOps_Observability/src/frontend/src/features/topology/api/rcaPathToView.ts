// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// rcaPathToView.ts — convert an RCA path-overlay (GET /api/correlations/{id}/
// rca-path-view) into the canonical TopologyView the operating canvas renders
// (#77, design doc "RCA overlay"). This lets Investigate mode show a REAL
// incident's fault path on the canvas (elk layout, device nodes) instead of a
// mock, reusing the whole render pipeline.
//
// Overlay-state fidelity: each node/edge now carries its precise RCA Layer-3 state
// in `rca_status` (suspected_down vs confirmed_down vs insufficient_visibility vs
// missing_evidence) — the canvas renders these as DISTINCT treatments via
// utils/rcaOverlay.ts (dashed+⚠ for suspected, solid+✕ for confirmed, hollow ○ for
// missing evidence), so the path no longer collapses "suspected" and "confirmed"
// into the same red. We still set health/status for the colour band + neighbouring
// non-RCA UI; the verdict banner carries the full grounded wording. Pure → testable.

import type { RcaPathView, RcaPathNode, RcaPathEdge, RcaAnnotation } from "../../../services/api";
import type { TopologyView, TopologyNode, TopologyEdge, NodeKind, Health, EdgeStatus, EdgeRelationship, RcaOverlayState } from "./topologyTypes";
import type { EvidenceRef } from "../graph/topologyFactTypes";
import { normalizeRcaState } from "../utils/rcaOverlay";

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
    case "observed":
      return "ok"; // an explicitly-observed healthy hop reads green, not "unknown"
    default:
      return "unknown";
  }
}

/**
 * Role-based RCA marker fallback when a node has no explicit overlay `status`.
 * ONLY an "observed" role earns a marker (green ● — a healthy hop should read as
 * observed-good, not a gray "unknown" ring). A fault/suspected/affected role is
 * NOT promoted to a verdict marker without a grounded status — that would
 * overclaim; the verdict banner + health colour still convey it. (Endpoints like
 * "destination"/"target" stay markerless — they're not a verdict.)
 */
function roleRcaFallback(role?: string): RcaOverlayState | undefined {
  return (role || "").toLowerCase() === "observed" ? "observed" : undefined;
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
 * Build the evidence row for a path target from its annotation (the grounded RCA
 * reasoning the engine attached) with a plain-status fallback when there is none.
 * Carries the annotation's reason, the missing-evidence gaps and a USED-BY-RCA flag
 * so the side drawer explains every fault node/edge — no silent "just trust it".
 */
function evidenceFor(ann: RcaAnnotation | undefined, fallbackDetail: string, baseConf: number): EvidenceRef {
  if (ann) {
    const missing = (ann.missing_evidence || []).filter(Boolean).join("; ");
    return {
      source: "trace",
      confidence: ann.confidence || baseConf,
      summary: ann.reason || fallbackDetail,
      used_by_rca: true,
      raw_ref: ann.evidence_refs?.[0],
      missing_evidence_if_any: missing || undefined,
    };
  }
  return { source: "trace", confidence: baseConf, detail: fallbackDetail };
}

/**
 * Convert an RcaPathView into a TopologyView. Per-target annotations override the
 * inline node/edge status (the annotation layer is authoritative) AND supply the
 * grounded reasoning surfaced in the side drawer. The returned view's `path` is the
 * ordered node ids source→destination so the canvas highlights the fault path.
 */
export function rcaPathToView(rpv: RcaPathView): TopologyView {
  // Annotation by target id (authoritative overlay: status + grounded reasoning).
  const annById = new Map<string, RcaAnnotation>();
  for (const a of rpv.annotations || []) {
    if (a.target_id) annById.set(a.target_id, a);
  }
  const baseConf = rpv.confidence || 1;

  const nodes: TopologyNode[] = (rpv.path?.nodes || []).map((n) => {
    const ann = annById.get(n.id);
    const merged: RcaPathNode = { ...n, status: ann?.status || n.status };
    return {
      id: n.id,
      label: n.label,
      kind: kindFor(n.kind),
      role: n.role,
      owner: ann?.owner,
      health: nodeHealth(merged),
      confidence: baseConf,
      resolved: kindFor(n.kind) !== "unresolved",
      // Authoritative Layer-3 verdict (when the engine asserted a state), else an
      // observed-role fallback so a healthy hop reads green ● (never fabricated for
      // a fault/affected role — see roleRcaFallback).
      rca_status: normalizeRcaState(merged.status) ?? roleRcaFallback(n.role),
      evidence: [evidenceFor(ann, merged.status || n.role || "", baseConf)],
    };
  });

  const edges: TopologyEdge[] = (rpv.path?.edges || []).map((e: RcaPathEdge) => {
    const ann = annById.get(e.id);
    const state = ann?.status || e.state;
    return {
      id: e.id,
      source: e.source,
      target: e.target,
      relationship: edgeRelationship(e.type),
      status: edgeStatus(state),
      confidence: baseConf,
      rca_status: normalizeRcaState(state),
      evidence: [evidenceFor(ann, e.label || state || "", baseConf)],
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
