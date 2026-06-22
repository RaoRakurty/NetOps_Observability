// topologyFilters.ts — pure faceted filtering over a TopologyView. Filtering is a
// view operation: it returns a NEW view with non-matching nodes removed and edges
// pruned to surviving nodes. It never mutates the input (PDF §16: filters are an
// overlay/lens, not a graph mutation).

import type { TopologyView, Health, NodeKind, TopologyNode } from "../api/topologyTypes";
import { mentionsInternal } from "../../../components/rca/labels";

/**
 * Drop the platform's OWN infrastructure (api/correlation/prober/etc.) from the
 * customer topology canvas — decision #76: RCA/topology is the CUSTOMER's network,
 * the internal stack belongs to Stack Health, not here. Matches an internal node by
 * its label or id; edges to a dropped node are pruned. Pure. A node mixing a real
 * device with infra is kept (mentionsInternal is conservative on the customer side).
 */
export function excludeInternalNodes(view: TopologyView): TopologyView {
  const keep = view.nodes.filter((n) => !mentionsInternal(n.label || "") && !mentionsInternal(n.id || ""));
  if (keep.length === view.nodes.length) return view;
  const surviving = new Set(keep.map((n) => n.id));
  return {
    ...view,
    nodes: keep,
    edges: view.edges.filter((e) => surviving.has(e.source) && surviving.has(e.target)),
    groups: view.groups.map((g) => ({ ...g, children: g.children.filter((c) => surviving.has(c)) })),
  };
}

export type TopologyFilter = {
  health?: Health[];
  sites?: string[];
  kinds?: NodeKind[];
  /** Drop unresolved (remote-neighbour) nodes when true. */
  hideUnresolved?: boolean;
};

function nodeMatches(node: TopologyNode, f: TopologyFilter): boolean {
  if (f.hideUnresolved && node.resolved === false) return false;
  if (f.health && f.health.length > 0 && !f.health.includes(node.health)) return false;
  if (f.kinds && f.kinds.length > 0 && !f.kinds.includes(node.kind)) return false;
  if (f.sites && f.sites.length > 0) {
    if (!node.site || !f.sites.includes(node.site)) return false;
  }
  return true;
}

/**
 * Return a new view containing only nodes that pass the filter, with edges pruned
 * to those whose BOTH endpoints survive, and groups' children narrowed to survivors.
 * Pure — input is untouched.
 */
export function filterView(view: TopologyView, f: TopologyFilter): TopologyView {
  const empty =
    (!f.health || f.health.length === 0) &&
    (!f.sites || f.sites.length === 0) &&
    (!f.kinds || f.kinds.length === 0) &&
    !f.hideUnresolved;
  if (empty) return view;

  const nodes = view.nodes.filter((n) => nodeMatches(n, f));
  const surviving = new Set(nodes.map((n) => n.id));
  const edges = view.edges.filter((e) => surviving.has(e.source) && surviving.has(e.target));
  const groups = view.groups.map((g) => ({
    ...g,
    children: g.children.filter((c) => surviving.has(c)),
  }));

  return { ...view, nodes, edges, groups };
}
