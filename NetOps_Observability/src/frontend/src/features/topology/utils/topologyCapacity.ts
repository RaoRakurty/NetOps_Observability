// topologyCapacity.ts — PURE capacity analytics over a TopologyView (PDF §9
// "Capacity" workflow: hot links, ECMP imbalance, errors/saturation). No React,
// no renderer types — just the domain graph in, ranked facts out, so the logic
// is unit-testable and the panel/canvas stay thin.
//
// HONESTY RULE (skill topology-context.md): an edge with no MEASURED utilization
// is *unmeasured*, not 0%. Unmeasured links are excluded from hot-link ranking
// and ECMP math — we never invent a number we didn't observe.

import type { TopologyView, TopologyEdge, TopologyNode } from "../api/topologyTypes";

/** A link is "hot"/saturated at or above this utilization (%). */
export const SATURATION_THRESHOLD = 85;
/** ECMP sibling links whose util spread (max−min) ≥ this are flagged imbalanced. */
export const ECMP_IMBALANCE_SPREAD = 25;

export type HotLink = {
  edge: TopologyEdge;
  utilization: number;
  sourceLabel: string;
  targetLabel: string;
  saturated: boolean;
  errored: boolean;
};

function labelOf(byId: Map<string, TopologyNode>, id: string): string {
  return byId.get(id)?.label ?? id;
}

function nodeIndex(view: TopologyView): Map<string, TopologyNode> {
  return new Map(view.nodes.map((n) => [n.id, n]));
}

/**
 * Links with a MEASURED utilization, ranked busiest-first. Unmeasured links are
 * excluded (honest — they are not "0%"). `limit` caps the returned list.
 */
export function rankHotLinks(view: TopologyView, limit = 8): HotLink[] {
  const byId = nodeIndex(view);
  return view.edges
    .filter((e) => e.utilization_pct != null)
    .map((e) => {
      const u = e.utilization_pct as number;
      return {
        edge: e,
        utilization: u,
        sourceLabel: labelOf(byId, e.source),
        targetLabel: labelOf(byId, e.target),
        saturated: u >= SATURATION_THRESHOLD,
        errored: (e.errors ?? 0) > 0,
      };
    })
    .sort((a, b) => b.utilization - a.utilization)
    .slice(0, limit);
}

/**
 * Edge ids at or above saturation — used to pre-spotlight trouble when the
 * Capacity workflow opens (bright hot paths, dimmed healthy fabric).
 */
export function saturatedEdgeIds(view: TopologyView, threshold = SATURATION_THRESHOLD): Set<string> {
  return new Set(
    view.edges
      .filter((e) => e.utilization_pct != null && (e.utilization_pct as number) >= threshold)
      .map((e) => e.id),
  );
}

export type EcmpMember = { edge: TopologyEdge; utilization: number; otherLabel: string };
export type EcmpGroup = {
  /** the node the sibling links share (load-balancing point). */
  node: string;
  nodeLabel: string;
  members: EcmpMember[];
  min: number;
  max: number;
  /** max − min utilization across the sibling set (% points). */
  spread: number;
  imbalanced: boolean;
};

/**
 * Group each node's MEASURED incident links into ECMP sibling sets and surface
 * the imbalanced ones (util spread ≥ ECMP_IMBALANCE_SPREAD), busiest spread
 * first. Edges are undirected, so a set is keyed by the shared node — this
 * catches imbalance viewed from either the leaf (uplinks) or the spine
 * (downlinks). Only groups with ≥ `minMembers` measured links qualify.
 */
export function ecmpGroups(view: TopologyView, minMembers = 2): EcmpGroup[] {
  const byId = nodeIndex(view);
  const incident = new Map<string, EcmpMember[]>();

  for (const e of view.edges) {
    if (e.utilization_pct == null) continue;
    const u = e.utilization_pct;
    for (const [node, other] of [
      [e.source, e.target],
      [e.target, e.source],
    ] as const) {
      const arr = incident.get(node) ?? [];
      arr.push({ edge: e, utilization: u, otherLabel: labelOf(byId, other) });
      incident.set(node, arr);
    }
  }

  const groups: EcmpGroup[] = [];
  for (const [node, members] of incident) {
    if (members.length < minMembers) continue;
    const utils = members.map((m) => m.utilization);
    const min = Math.min(...utils);
    const max = Math.max(...utils);
    const spread = max - min;
    groups.push({
      node,
      nodeLabel: labelOf(byId, node),
      members: members.sort((a, b) => b.utilization - a.utilization),
      min,
      max,
      spread,
      imbalanced: spread >= ECMP_IMBALANCE_SPREAD,
    });
  }

  return groups.filter((g) => g.imbalanced).sort((a, b) => b.spread - a.spread);
}
