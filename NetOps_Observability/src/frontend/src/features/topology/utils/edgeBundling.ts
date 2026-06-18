// edgeBundling.ts — collapse parallel links between the same node pair into a
// single bundled edge (2×100G / LAG-N). Pure: returns a NEW view; single edges are
// returned untouched. Bundling is a view transform, not a graph mutation — the
// underlying member links still live in the facts/evidence (PDF §16).

import type { TopologyView, TopologyEdge, EvidenceRef } from "../api/topologyTypes";

/** Unordered node-pair key so A→B and B→A bundle together. */
function pairKey(e: TopologyEdge): string {
  return e.source < e.target ? `${e.source}|${e.target}` : `${e.target}|${e.source}`;
}

/** Dedup evidence refs by raw_ref so a bundle doesn't list the same fact twice. */
function mergeEvidence(refs: EvidenceRef[]): EvidenceRef[] {
  const seen = new Set<string>();
  const out: EvidenceRef[] = [];
  for (const r of refs) {
    const k = r.raw_ref || `${r.source}:${r.observed_at}:${r.summary}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(r);
  }
  return out;
}

/**
 * Returns a new view where every group of ≥2 edges sharing a node pair is replaced
 * by one bundled edge:
 *   - id           = first member's id,
 *   - bundle_id    = "×N",
 *   - bundle_count = N,
 *   - evidence     = merged (deduped) across members,
 *   - utilization  = summed across members (undefined if no member carried it),
 *   - confidence   = max across members,
 *   - status       = worst (critical > warning > unknown > ok),
 *   - direction    = "bi" if any member is bidirectional.
 * Single edges pass through unchanged (object identity preserved).
 */
export function bundleParallelEdges(view: TopologyView): TopologyView {
  const groups = new Map<string, TopologyEdge[]>();
  for (const e of view.edges) {
    const k = pairKey(e);
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k)!.push(e);
  }

  const statusRank: Record<string, number> = { critical: 3, warning: 2, unknown: 1, ok: 0 };
  const worse = (a: TopologyEdge["status"], b: TopologyEdge["status"]) =>
    (statusRank[a] ?? 1) >= (statusRank[b] ?? 1) ? a : b;

  const edges: TopologyEdge[] = [];
  for (const members of groups.values()) {
    if (members.length === 1) {
      edges.push(members[0]);
      continue;
    }

    const head = members[0];
    let util: number | undefined = undefined;
    let confidence = 0;
    let status = head.status;
    let bi = false;
    const evidence: EvidenceRef[] = [];

    for (const m of members) {
      if (m.utilization != null) util = (util ?? 0) + m.utilization;
      confidence = Math.max(confidence, m.confidence);
      status = worse(status, m.status);
      if (m.direction === "bi") bi = true;
      evidence.push(...(m.evidence ?? []));
    }

    edges.push({
      ...head,
      status,
      confidence,
      utilization: util,
      direction: bi ? "bi" : head.direction,
      evidence: mergeEvidence(evidence),
      bundle_id: `×${members.length}`,
      bundle_count: members.length,
    });
  }

  return { ...view, edges };
}
