// edgeBundling.ts — collapse parallel links between the same node pair into a
// single bundled edge (2×100G / LAG-N). Pure: returns a NEW view; single edges are
// returned untouched. Bundling is a view transform, not a graph mutation — the
// underlying member links still live in the facts/evidence (PDF §16).

import type { TopologyView, TopologyEdge, EvidenceRef, Health } from "../api/topologyTypes";
import { statusToHealth } from "./topologyHealth";

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
 * WHEN A BUNDLE IS REFUSED (the honesty rule).
 *
 * Collapsing parallel links is a LEGIBILITY device for a healthy LAG: four member
 * curves the operator has to count by eye become one "×4". It must never collapse
 * away the answer:
 *
 *   - a member with a DEGRADED/DOWN status — `edgeVariant` ranks `bundled` above
 *     `degraded`, and BundledEdge carries no health colour, so bundling a 4×10G
 *     with one member down would draw a calm bundle over a real fault. WHICH
 *     member is broken is the whole question;
 *   - a member carrying an `rca_status` — that is the engine's grounded verdict on
 *     one specific link, and merging it into a sibling erases it;
 *   - members of different RELATIONSHIP classes — an observed LLDP adjacency and
 *     an inferred/dependency edge between the same pair are different claims, and
 *     observed-vs-inferred must stay visually distinct.
 *
 * Any of those and the pair's edges pass through untouched, drawn individually.
 */
function bundlable(members: TopologyEdge[]): boolean {
  if (members.length < 2) return false;
  const rel = members[0].relationship;
  for (const m of members) {
    if (m.relationship !== rel) return false;
    if (m.rca_status) return false;
    const h = statusToHealth(m.status);
    if (h === "critical" || h === "warning") return false;
  }
  return true;
}

/**
 * Returns a new view where every group of ≥2 edges sharing a node pair AND a
 * relationship class, none of which is degraded or RCA-flagged (see `bundlable`),
 * is replaced by one bundled edge:
 *   - id           = first member's id,
 *   - bundle_id    = "×N",
 *   - bundle_count = N,
 *   - evidence       = merged (deduped) across members,
 *   - utilization_pct = summed across members (undefined if no member carried it),
 *   - confidence     = max across members,
 *   - status         = worst (by health band: critical > warning > maintenance >
 *                      unknown > ok),
 *   - direction      = "bi" if any member is bidirectional.
 * Single edges — and every group the honesty rule refuses — pass through unchanged
 * (object identity preserved).
 */
export function bundleParallelEdges(view: TopologyView): TopologyView {
  const groups = new Map<string, TopologyEdge[]>();
  for (const e of view.edges) {
    // The relationship class is part of the key: an observed adjacency and an
    // inferred edge between the same two devices are two different claims and are
    // never candidates for the same bundle.
    const k = `${pairKey(e)}|${e.relationship}`;
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k)!.push(e);
  }

  // Rank an edge status by the health band it maps to (worst-wins).
  const healthRank: Record<Health, number> = {
    critical: 4,
    warning: 3,
    maintenance: 2,
    unknown: 1,
    ok: 0,
  };
  const statusRank = (s: TopologyEdge["status"]): number => healthRank[statusToHealth(s)];
  const worse = (a: TopologyEdge["status"], b: TopologyEdge["status"]) =>
    statusRank(a) >= statusRank(b) ? a : b;

  const edges: TopologyEdge[] = [];
  for (const members of groups.values()) {
    if (!bundlable(members)) {
      for (const m of members) edges.push(m);
      continue;
    }

    const head = members[0];
    let util: number | undefined = undefined;
    let confidence = 0;
    let status = head.status;
    let bi = false;
    const evidence: EvidenceRef[] = [];

    for (const m of members) {
      if (m.utilization_pct != null) util = (util ?? 0) + m.utilization_pct;
      confidence = Math.max(confidence, m.confidence);
      status = worse(status, m.status);
      if (m.direction === "bi") bi = true;
      evidence.push(...(m.evidence ?? []));
    }

    edges.push({
      ...head,
      status,
      confidence,
      utilization_pct: util,
      direction: bi ? "bi" : head.direction,
      evidence: mergeEvidence(evidence),
      bundle_id: `×${members.length}`,
      bundle_count: members.length,
    });
  }

  return { ...view, edges };
}
