// topologyMapper.ts — projection + defensive normalization for the resolved
// TopologyView. These are PURE functions over the domain contract; no renderer,
// no React.
//
// Two responsibilities:
//   1. normalizeView — make any TopologyView safe to render (arrays present,
//      evidence-less edges dropped, confidence clamped, health defaulted).
//   2. factsToView   — a documented STAND-IN for the backend graph-projection
//      service (Go). The real identity-resolution + confidence-scoring happens
//      server-side per the architecture; this is a minimal client-side stub so
//      the UI can be built against the contract.

import type {
  TopologyView,
  TopologyNode,
  TopologyEdge,
  Health,
  EvidenceRef,
} from "../api/topologyTypes";
import type { TopologyFact } from "../graph/topologyFactTypes";
import { hasEvidence, SOURCE_BASE_CONFIDENCE } from "./topologyHealth";

/** Clamp any number into [0, 1]; coerce non-finite to 0. */
function clamp01(n: number | undefined): number {
  if (typeof n !== "number" || !Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(1, n));
}

function normalizeHealth(h: Health | undefined): Health {
  return h === "ok" || h === "warning" || h === "critical" || h === "maintenance"
    ? h
    : "unknown";
}

/**
 * Defensive normalization. Returns a NEW view safe to hand to a renderer:
 *  - every array exists (never undefined),
 *  - edges without evidence are dropped (PDF rule 6: never draw a link without
 *    evidence) and edges whose endpoints no longer exist are pruned,
 *  - node/edge confidence is clamped to [0, 1],
 *  - missing node health defaults to "unknown".
 * Pure: does not mutate the input.
 */
export function normalizeView(v: TopologyView): TopologyView {
  const nodesIn = Array.isArray(v.nodes) ? v.nodes : [];
  const edgesIn = Array.isArray(v.edges) ? v.edges : [];

  const nodes: TopologyNode[] = nodesIn.map((n) => ({
    ...n,
    health: normalizeHealth(n.health),
    confidence: clamp01(n.confidence),
    resolved: n.resolved !== false,
    evidence: Array.isArray(n.evidence) ? n.evidence : [],
    metrics: n.metrics ?? {},
    tags: n.tags ?? {},
  }));

  const nodeIds = new Set(nodes.map((n) => n.id));

  const edges: TopologyEdge[] = edgesIn
    .filter((e) => hasEvidence(e.evidence))
    .filter((e) => nodeIds.has(e.source) && nodeIds.has(e.target))
    .map((e) => ({
      ...e,
      status: e.status ?? "unknown",
      confidence: clamp01(e.confidence),
      evidence: e.evidence,
    }));

  // A group's `children` is a REQUIRED array in the contract, and ~10 call sites
  // iterate/spread it without a guard because the type promises it is there. A
  // producer that emits `null` (a nil Go slice marshals to `null` — which is
  // exactly what the cloud projection did for REGION groups, whose members are
  // other groups) therefore did not degrade: it threw "children is not iterable"
  // mid-render, React unmounted to the root, and the whole page went blank with a
  // 200 on the wire. The boundary is where that gets fixed for every consumer at
  // once — normalizeView already promises "every array exists".
  const groupsIn = Array.isArray(v.groups) ? v.groups : [];
  const groups = groupsIn.map((g) => ({
    ...g,
    children: Array.isArray(g.children) ? g.children : [],
  }));

  return {
    ...v,
    nodes,
    edges,
    groups,
    overlays: Array.isArray(v.overlays) ? v.overlays : [],
  };
}

/** Build an EvidenceRef from a raw fact (its own justification). */
function factEvidence(fact: TopologyFact): EvidenceRef {
  return {
    source: fact.source,
    confidence: clamp01(fact.confidence),
    observed_at: fact.observed_at,
    raw_ref: fact.raw_ref,
    summary: `${fact.subject} ${fact.predicate} ${fact.object}`,
  };
}

/**
 * PLACEHOLDER projection: facts → resolved view.
 *
 * ⚠️ This is a STAND-IN for the backend graph-projection service. In the real
 * system a Go service performs identity resolution (mgmt-IP → serial → name
 * dedup), per-source confidence scoring, time-validity windowing and evidence
 * aggregation, then returns a TopologyView. This client-side version does the
 * crudest possible thing so the UI has something to render in dev:
 *   - each distinct subject/object becomes an unresolved-ish node,
 *   - each fact becomes (or augments) one edge subject→object,
 *   - evidence is the per-fact EvidenceRef,
 *   - confidence seeds from SOURCE_BASE_CONFIDENCE for the fact's source.
 * Do NOT rely on this for production correctness.
 */
export function factsToView(
  facts: TopologyFact[],
  meta: Partial<TopologyView>,
): TopologyView {
  const safeFacts = Array.isArray(facts) ? facts : [];

  const nodeMap = new Map<string, TopologyNode>();
  const edgeMap = new Map<string, TopologyEdge>();

  const ensureNode = (id: string, time: { observed_at: string }): TopologyNode => {
    const existing = nodeMap.get(id);
    if (existing) return existing;
    const node: TopologyNode = {
      id,
      label: id,
      kind: "unresolved",
      health: "unknown",
      confidence: 0.5,
      resolved: false,
      evidence: [],
      first_seen: time.observed_at,
      last_seen: time.observed_at,
      change_state: "unchanged",
      metrics: {},
      tags: {},
    };
    nodeMap.set(id, node);
    return node;
  };

  for (const fact of safeFacts) {
    const ev = factEvidence(fact);
    const base = SOURCE_BASE_CONFIDENCE[fact.source] ?? 0.5;

    const subj = ensureNode(fact.subject, fact);
    subj.evidence.push(ev);
    subj.confidence = Math.max(subj.confidence, base);
    const obj = ensureNode(fact.object, fact);
    obj.evidence.push(ev);

    const edgeId = `${fact.subject}->${fact.object}`;
    const existing = edgeMap.get(edgeId);
    if (existing) {
      existing.evidence.push(ev);
      existing.confidence = Math.max(existing.confidence, base);
    } else {
      edgeMap.set(edgeId, {
        id: edgeId,
        source: fact.subject,
        target: fact.object,
        relationship: "inferred",
        protocol: fact.source,
        source_port: fact.source_interface,
        target_port: fact.target_interface,
        status: "up",
        confidence: base,
        evidence: [ev],
        first_seen: fact.observed_at,
        last_seen: fact.observed_at,
        change_state: "unchanged",
      });
    }
  }

  const stub: TopologyView = {
    view_id: meta.view_id ?? "facts-projection",
    topology_id: meta.topology_id ?? "facts",
    mode: meta.mode ?? "explore",
    scope: meta.scope ?? { tenant_id: "unknown" },
    generated_at: meta.generated_at ?? "",
    time_range: meta.time_range ?? { from: "", to: "" },
    layout_type: meta.layout_type ?? "spine_leaf",
    nodes: [...nodeMap.values()],
    edges: [...edgeMap.values()],
    groups: meta.groups ?? [],
    overlays: meta.overlays ?? [],
    renderer_hints: meta.renderer_hints ?? { preferred: "react_flow", max_detail_level: 3 },
    path: meta.path,
  };

  // Run through the same safety pass as any other view.
  return normalizeView(stub);
}
