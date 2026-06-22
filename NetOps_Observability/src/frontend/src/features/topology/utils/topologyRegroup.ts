// topologyRegroup.ts — PURE client-side regrouping of a TopologyView by any node
// dimension (site / role / vendor / owner), or none. Borrows the "regroup by any
// tag dimension" idea (Datadog) so the operator isn't locked to the backend's fixed
// site hierarchy: pick a lens and the canvas re-buckets into containers on the fly.
// The renderer + ELK + collapse logic all consume view.groups, so overriding groups
// is all that's needed — no graph mutation, nodes are untouched.

import type { TopologyView, TopologyGroup, GroupType, Health, TopologyNode } from "../api/topologyTypes";

export type GroupDimension = "site" | "role" | "vendor" | "owner" | "none";

export const GROUP_DIMENSIONS: { id: GroupDimension; label: string }[] = [
  { id: "site", label: "Site" },
  { id: "role", label: "Role" },
  { id: "vendor", label: "Vendor" },
  { id: "owner", label: "Owner" },
  { id: "none", label: "None" },
];

// Map a regroup dimension to a valid GroupType (the contract's closed set). The
// label carries the real value (e.g. "arista", "leaf"); the type only tints/rolls up.
const TYPE_FOR_DIM: Record<Exclude<GroupDimension, "none">, GroupType> = {
  site: "site", role: "cluster", vendor: "zone", owner: "app",
};

const HEALTH_RANK: Record<Health, number> = {
  ok: 0, maintenance: 1, unknown: 2, warning: 3, critical: 4,
};

function worse(a: Health, b: Health): Health {
  return (HEALTH_RANK[b] ?? 0) > (HEALTH_RANK[a] ?? 0) ? b : a;
}

function keyOf(n: TopologyNode, dim: Exclude<GroupDimension, "none">): string {
  const v = dim === "site" ? n.site : dim === "role" ? n.role : dim === "vendor" ? n.vendor : n.owner;
  return (v ?? "").trim();
}

/**
 * Return a view re-grouped by `dim`. "none" clears grouping (flat canvas); "site"
 * keeps the backend's own groups (already site-scoped) so we don't fight its layout.
 * Any other dimension buckets nodes by that attribute into fresh containers with a
 * worst-child health rollup. Nodes without a value for the dimension stay ungrouped.
 */
export function regroupView(view: TopologyView, dim: GroupDimension): TopologyView {
  if (dim === "site") return view; // backend already groups by site
  if (dim === "none") return { ...view, groups: [] };

  const buckets = new Map<string, TopologyNode[]>();
  for (const n of view.nodes) {
    const k = keyOf(n, dim);
    if (!k) continue;
    const arr = buckets.get(k);
    if (arr) arr.push(n);
    else buckets.set(k, [n]);
  }

  const groups: TopologyGroup[] = [...buckets.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([label, members]) => ({
      id: `${dim}:${label}`,
      label,
      group_type: TYPE_FOR_DIM[dim],
      children: members.map((n) => n.id).sort(),
      health: members.reduce<Health>((h, n) => worse(h, (n.health as Health) ?? "unknown"), "ok"),
      collapsed: false,
    }));

  return { ...view, groups };
}
