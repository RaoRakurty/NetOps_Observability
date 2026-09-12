// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// topologyArchetype.ts — PURE topology-archetype detection + analytic layouts.
//
// Operators name networks by SHAPE — ring, star, bus, mesh, leaf-spine — and the
// canvas should both recognize the shape and arrange the graph the way a network
// engineer would draw it. Detection is structural (degree distribution, cycle
// shape, hub dominance, bipartite tiering over the MANAGED device subgraph) with
// role names as a tie-breaker; it returns a confidence + a human "why" so the
// toolbar can say "Auto (ring — every node has exactly two neighbours)" instead
// of asserting a shape blindly.
//
// The analytic layouts are DETERMINISTIC position generators (skill rule: never
// random force layout): ring/mesh → circle (mesh reads as a chord diagram), star
// → hub-centred radial, bus → a single line. Leaf-spine keeps the existing ELK
// layered preset with role partitioning. Unresolved/external boundary nodes are
// excluded from detection (they'd distort degrees) but still get positions —
// parked on an outer arc so they are never hidden (skill: never hide unresolved).

import type { TopologyView, TopologyNode } from "../api/topologyTypes";
import type { LayoutResult } from "../layout/layoutTypes";
import { NODE_SIZE } from "../layout/layoutTypes";

export type Archetype = "leaf_spine" | "ring" | "star" | "bus" | "mesh" | "irregular";

export type ArchetypeVerdict = {
  archetype: Archetype;
  confidence: number; // 0..1 — how cleanly the structure matches
  reason: string;     // operator-facing "why" for the toolbar
};

export const ARCHETYPES: { id: Archetype; label: string }[] = [
  { id: "leaf_spine", label: "Leaf-spine" },
  { id: "ring", label: "Ring" },
  { id: "star", label: "Star" },
  { id: "bus", label: "Bus" },
  { id: "mesh", label: "Mesh" },
];

/** Managed device nodes only — boundary/unresolved nodes distort degrees. */
function deviceNodes(view: TopologyView): TopologyNode[] {
  return view.nodes.filter((n) => n.kind !== "unresolved" && n.kind !== "group" && n.kind !== "site");
}

/** Undirected simple adjacency over the given node set (parallel edges folded). */
function adjacency(view: TopologyView, ids: Set<string>): Map<string, Set<string>> {
  const adj = new Map<string, Set<string>>();
  for (const id of ids) adj.set(id, new Set());
  for (const e of view.edges) {
    if (e.source === e.target) continue;
    if (!ids.has(e.source) || !ids.has(e.target)) continue;
    adj.get(e.source)!.add(e.target);
    adj.get(e.target)!.add(e.source);
  }
  return adj;
}

function connectedComponents(adj: Map<string, Set<string>>): string[][] {
  const seen = new Set<string>();
  const out: string[][] = [];
  for (const start of adj.keys()) {
    if (seen.has(start)) continue;
    const comp: string[] = [];
    const stack = [start];
    seen.add(start);
    while (stack.length) {
      const cur = stack.pop()!;
      comp.push(cur);
      for (const nb of adj.get(cur) ?? []) {
        if (!seen.has(nb)) {
          seen.add(nb);
          stack.push(nb);
        }
      }
    }
    out.push(comp);
  }
  return out;
}

const SPINE_RE = /(spine|core|aggreg|distribution)/i;
const LEAF_RE = /(leaf|tor|access|edge)/i;

/**
 * Detect the archetype of the view's managed-device subgraph. Requirements per
 * shape (classic textbook definitions, tolerance for one or two exceptions so a
 * real network with a management stub still classifies):
 *   ring  — connected, every degree == 2 (one simple cycle)
 *   bus   — connected path: exactly two degree-1 ends, all else degree 2
 *   star  — one hub adjacent to (almost) everything, all else degree 1
 *   leaf_spine — bipartite two-tier: every edge crosses tier A↔B, each B
 *                multi-homed to ≥2 A (role names strengthen the verdict)
 *   mesh  — dense: average degree ≥ 3 (full mesh → confidence 1)
 */
export function detectArchetype(view: TopologyView): ArchetypeVerdict {
  const devs = deviceNodes(view);
  const ids = new Set(devs.map((n) => n.id));
  const n = ids.size;
  if (n < 3) return { archetype: "irregular", confidence: 0, reason: "fewer than 3 managed devices" };

  const adj = adjacency(view, ids);
  const comps = connectedComponents(adj);
  const degrees = [...ids].map((id) => adj.get(id)!.size);
  const edgeCount = degrees.reduce((a, b) => a + b, 0) / 2;
  const connected = comps.length === 1;
  const deg = (id: string) => adj.get(id)!.size;

  if (connected) {
    // ring: all degree 2, |E| == |V|
    const deg2 = degrees.filter((d) => d === 2).length;
    if (deg2 === n && edgeCount === n) {
      return { archetype: "ring", confidence: 1, reason: "every device has exactly two neighbours in one closed loop" };
    }
    // bus: a path — two ends of degree 1, the rest degree 2
    const ends = degrees.filter((d) => d === 1).length;
    if (ends === 2 && deg2 === n - 2 && edgeCount === n - 1) {
      return { archetype: "bus", confidence: 1, reason: "a single line: two end devices, everything else chained through" };
    }
    // star: one dominant hub, (almost) everything else a spoke
    const maxDeg = Math.max(...degrees);
    const hubs = [...ids].filter((id) => deg(id) === maxDeg);
    const spokes = degrees.filter((d) => d === 1).length;
    if (hubs.length === 1 && maxDeg >= n - 2 && spokes >= n - 2) {
      return { archetype: "star", confidence: maxDeg === n - 1 ? 1 : 0.8, reason: "one hub carries every connection; all other devices are single-homed spokes" };
    }
  }

  // leaf_spine: role names first (the strongest signal), else structural bipartite.
  const byRole = { spine: [] as string[], leaf: [] as string[] };
  for (const d of devs) {
    const hay = `${d.role ?? ""} ${d.device_role ?? ""} ${d.label}`;
    if (SPINE_RE.test(hay)) byRole.spine.push(d.id);
    else if (LEAF_RE.test(hay)) byRole.leaf.push(d.id);
  }
  if (byRole.spine.length >= 2 && byRole.leaf.length >= 2) {
    const spineSet = new Set(byRole.spine);
    const leafSet = new Set(byRole.leaf);
    let crossing = 0;
    let total = 0;
    for (const e of view.edges) {
      if (!ids.has(e.source) || !ids.has(e.target)) continue;
      total++;
      const sSpine = spineSet.has(e.source) ? 1 : leafSet.has(e.source) ? 0 : -1;
      const tSpine = spineSet.has(e.target) ? 1 : leafSet.has(e.target) ? 0 : -1;
      if (sSpine >= 0 && tSpine >= 0 && sSpine !== tSpine) crossing++;
    }
    if (total > 0 && crossing / total >= 0.8) {
      return {
        archetype: "leaf_spine",
        confidence: crossing / total,
        reason: `${byRole.spine.length} spines × ${byRole.leaf.length} leaves, ${Math.round((crossing / total) * 100)}% of links cross the tiers`,
      };
    }
  }

  // mesh: dense interconnection
  const avgDeg = n > 0 ? (2 * edgeCount) / n : 0;
  const fullMeshEdges = (n * (n - 1)) / 2;
  if (edgeCount === fullMeshEdges && connected) {
    return { archetype: "mesh", confidence: 1, reason: "full mesh — every device connects to every other" };
  }
  if (avgDeg >= 3 && connected) {
    return { archetype: "mesh", confidence: Math.min(0.9, edgeCount / fullMeshEdges + 0.4), reason: `dense partial mesh (average ${avgDeg.toFixed(1)} links per device)` };
  }

  return { archetype: "irregular", confidence: 0.3, reason: connected ? "no dominant textbook shape" : `${comps.length} disconnected islands` };
}

// ── analytic layouts (deterministic; no force physics) ───────────────────────

const CX = 600;
const CY = 420;

/** Park excluded (boundary/unresolved) nodes on an outer arc, never hidden. */
function parkOthers(view: TopologyView, placed: LayoutResult, radius: number): LayoutResult {
  const others = view.nodes.filter((n) => !placed[n.id]);
  others.forEach((n, i) => {
    const a = (Math.PI * 2 * i) / Math.max(1, others.length) + Math.PI / others.length;
    placed[n.id] = { x: CX + Math.cos(a) * radius, y: CY + Math.sin(a) * radius };
  });
  return placed;
}

/** Ring/mesh: devices on a circle. Ring is ordered by WALKING the cycle so the
 *  drawn circle follows the physical loop; mesh sorts by label (chord diagram). */
export function circularLayout(view: TopologyView, walkCycle: boolean): LayoutResult {
  const devs = deviceNodes(view);
  const ids = new Set(devs.map((n) => n.id));
  const adj = adjacency(view, ids);
  let order = [...devs].sort((a, b) => a.label.localeCompare(b.label)).map((n) => n.id);
  if (walkCycle && devs.length > 2) {
    const start = order[0];
    const walked: string[] = [start];
    const seen = new Set([start]);
    let cur = start;
    for (let i = 1; i < devs.length; i++) {
      const next = [...(adj.get(cur) ?? [])].find((nb) => !seen.has(nb));
      if (!next) break;
      walked.push(next);
      seen.add(next);
      cur = next;
    }
    if (walked.length === devs.length) order = walked;
  }
  const r = Math.max(220, (order.length * (NODE_SIZE.width + 40)) / (2 * Math.PI));
  const out: LayoutResult = {};
  order.forEach((id, i) => {
    const a = (Math.PI * 2 * i) / order.length - Math.PI / 2;
    out[id] = { x: CX + Math.cos(a) * r, y: CY + Math.sin(a) * r };
  });
  return parkOthers(view, out, r + 200);
}

/** Star: the highest-degree device at the centre, spokes on a circle. */
export function radialLayout(view: TopologyView): LayoutResult {
  const devs = deviceNodes(view);
  const ids = new Set(devs.map((n) => n.id));
  const adj = adjacency(view, ids);
  const hub = [...devs].sort((a, b) => (adj.get(b.id)?.size ?? 0) - (adj.get(a.id)?.size ?? 0))[0];
  const spokes = devs.filter((n) => n.id !== hub?.id).sort((a, b) => a.label.localeCompare(b.label));
  const r = Math.max(240, (spokes.length * (NODE_SIZE.width + 40)) / (2 * Math.PI));
  const out: LayoutResult = {};
  if (hub) out[hub.id] = { x: CX, y: CY };
  spokes.forEach((n, i) => {
    const a = (Math.PI * 2 * i) / Math.max(1, spokes.length) - Math.PI / 2;
    out[n.id] = { x: CX + Math.cos(a) * r, y: CY + Math.sin(a) * r };
  });
  return parkOthers(view, out, r + 200);
}

/** Bus: one horizontal line, ordered by walking the path end-to-end. */
export function linearLayout(view: TopologyView): LayoutResult {
  const devs = deviceNodes(view);
  const ids = new Set(devs.map((n) => n.id));
  const adj = adjacency(view, ids);
  const end = devs.find((n) => (adj.get(n.id)?.size ?? 0) === 1) ?? devs[0];
  const order: string[] = [];
  if (end) {
    const seen = new Set<string>();
    let cur: string | undefined = end.id;
    while (cur && !seen.has(cur)) {
      order.push(cur);
      seen.add(cur);
      cur = [...(adj.get(cur) ?? [])].find((nb) => !seen.has(nb));
    }
    for (const d of devs) if (!seen.has(d.id)) order.push(d.id); // stragglers
  }
  const gap = NODE_SIZE.width + 80;
  const out: LayoutResult = {};
  order.forEach((id, i) => {
    out[id] = { x: 80 + i * gap, y: CY };
  });
  return parkOthers(view, out, 300);
}

/** The analytic generator for an archetype, or null when ELK should run
 *  (leaf_spine/irregular → the existing layered presets). */
export function archetypeLayout(view: TopologyView, archetype: Archetype): LayoutResult | null {
  switch (archetype) {
    case "ring":
      return circularLayout(view, true);
    case "mesh":
      return circularLayout(view, false);
    case "star":
      return radialLayout(view);
    case "bus":
      return linearLayout(view);
    default:
      return null;
  }
}
