// topologySearch.ts — case-insensitive substring search across a TopologyView.
// Pure; returns matching node ids (for spotlight) and a ranked, explained summary
// (for a search-results dropdown). No renderer, no React.

import type { TopologyView, TopologyNode } from "../api/topologyTypes";

/** Lowercase a value safely (numbers, undefined, etc.). */
function lc(v: unknown): string {
  return v == null ? "" : String(v).toLowerCase();
}

/**
 * The searchable text fields of a node, paired with the field label used in the
 * "why it matched" reason. Interface names are folded in separately (from edges).
 */
function nodeFields(node: TopologyNode): { field: string; value: string }[] {
  const fields: { field: string; value: string }[] = [
    { field: "label", value: lc(node.label) },
    { field: "id", value: lc(node.id) },
    { field: "vendor", value: lc(node.vendor) },
    { field: "model", value: lc(node.model) },
    { field: "site", value: lc(node.site) },
    { field: "role", value: lc(node.role) },
    { field: "zone", value: lc(node.zone) },
    { field: "health", value: lc(node.health) },
    { field: "owner", value: lc(node.owner) },
  ];
  for (const [k, v] of Object.entries(node.tags ?? {})) {
    fields.push({ field: `tag:${k}`, value: lc(v) });
  }
  return fields;
}

/** node id → set of interface (port) names gathered from edges touching it. */
function interfaceIndex(view: TopologyView): Map<string, Set<string>> {
  const idx = new Map<string, Set<string>>();
  const add = (nodeId: string, port: string | undefined) => {
    if (!port) return;
    if (!idx.has(nodeId)) idx.set(nodeId, new Set());
    idx.get(nodeId)!.add(port);
  };
  for (const e of view.edges) {
    add(e.source, e.source_port);
    add(e.target, e.target_port);
  }
  return idx;
}

/**
 * Set of node ids matching the query. Matches over label/id/vendor/model/site/
 * role/zone/health/ownership.owner, tag values, and interface (port) names of
 * edges incident to the node. Empty/blank query => empty set.
 */
export function searchNodeIds(view: TopologyView, query: string): Set<string> {
  const q = query.trim().toLowerCase();
  const out = new Set<string>();
  if (!q) return out;

  const ifIdx = interfaceIndex(view);
  for (const node of view.nodes) {
    const hit =
      nodeFields(node).some((f) => f.value.includes(q)) ||
      [...(ifIdx.get(node.id) ?? [])].some((p) => p.toLowerCase().includes(q));
    if (hit) out.add(node.id);
  }
  return out;
}

/**
 * Top ~12 matches, each with the first field that explains WHY it matched. Useful
 * for a search dropdown. Ranking: label/id matches first, then everything else.
 */
export function searchSummary(
  view: TopologyView,
  query: string,
): { id: string; label: string; reason: string }[] {
  const q = query.trim().toLowerCase();
  if (!q) return [];

  const ifIdx = interfaceIndex(view);
  const results: { id: string; label: string; reason: string; rank: number }[] = [];

  for (const node of view.nodes) {
    let reason = "";
    let rank = 99;

    for (const f of nodeFields(node)) {
      if (f.value.includes(q)) {
        const r = f.field === "label" || f.field === "id" ? 0 : 1;
        if (r < rank) {
          rank = r;
          reason = `${f.field} contains “${query}”`;
        }
      }
    }
    if (!reason) {
      const port = [...(ifIdx.get(node.id) ?? [])].find((p) => p.toLowerCase().includes(q));
      if (port) {
        reason = `interface ${port} matches “${query}”`;
        rank = 2;
      }
    }

    if (reason) results.push({ id: node.id, label: node.label, reason, rank });
  }

  results.sort((a, b) => a.rank - b.rank || a.label.localeCompare(b.label));
  return results.slice(0, 12).map(({ id, label, reason }) => ({ id, label, reason }));
}
