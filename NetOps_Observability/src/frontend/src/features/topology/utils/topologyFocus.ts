import type { TopologyView } from "../api/topologyTypes";

// topologyFocus — narrow the canvas to a subset the operator chose.
//
// WHY THIS EXISTS. The >1000-node card tells the operator to "narrow this
// canvas with search, the domain tabs, or grouping to a subset under 1,000
// nodes". Domain tabs and grouping did that; search did NOT — it only
// spotlighted matches inside a view that was already too big to render, and in
// the over-ceiling branch the search dock was not even mounted. The escape
// hatch the UI advertised did not exist, so a large tenant's interactive canvas
// was unreachable.
//
// This is the missing half: a filter that actually removes nodes.
//
// NEIGHBOURS ARE INCLUDED ON PURPOSE. Narrowing to the literal matches alone
// produces a field of disconnected dots — searching "core" would show four core
// switches and none of the links that make them a topology, which is worse than
// not narrowing at all. Pulling in one hop of context keeps every match's
// immediate structure visible, which is what an operator is actually looking
// for when they search a map.

/** How many hops of context to keep around each match. */
export const FOCUS_HOPS = 1;

/**
 * focusView narrows a view to the matched nodes plus `hops` of neighbours.
 *
 * Returns the view UNCHANGED when there is nothing to narrow to — an empty
 * match set means "no filter", never "show an empty canvas". A search that
 * matches nothing must leave the map alone rather than blank it, or the
 * operator loses their place every time they mistype.
 */
export function focusView(
  view: TopologyView,
  matches: ReadonlySet<string>,
  hops: number = FOCUS_HOPS,
): TopologyView {
  if (matches.size === 0) return view;

  // Adjacency over the CURRENT view, so focus composes with the domain slice
  // and the grouping lens rather than reaching back to the unfiltered graph.
  const neighbours = new Map<string, string[]>();
  const link = (a: string, b: string) => {
    const cur = neighbours.get(a);
    if (cur) cur.push(b);
    else neighbours.set(a, [b]);
  };
  for (const e of view.edges) {
    link(e.source, e.target);
    link(e.target, e.source);
  }

  const keep = new Set<string>(matches);
  let frontier = [...matches];
  for (let h = 0; h < Math.max(0, hops); h++) {
    const next: string[] = [];
    for (const id of frontier) {
      for (const n of neighbours.get(id) ?? []) {
        if (!keep.has(n)) {
          keep.add(n);
          next.push(n);
        }
      }
    }
    if (next.length === 0) break;
    frontier = next;
  }

  const nodes = view.nodes.filter((n) => keep.has(n.id));
  const edges = view.edges.filter((e) => keep.has(e.source) && keep.has(e.target));
  const groups = view.groups
    .map((g) => ({ ...g, children: g.children.filter((c) => keep.has(c)) }))
    .filter((g) => g.children.length > 0);

  return { ...view, nodes, edges, groups };
}

/**
 * focusSummary describes what a focus did, for the status line.
 *
 * Operators need to know they are looking at a SUBSET — an unlabelled narrowed
 * canvas is indistinguishable from a small network, and mistaking one for the
 * other during an incident is how people conclude a device "isn't there".
 */
export function focusSummary(
  total: number,
  shown: number,
  matched: number,
): string {
  const context = shown - matched;
  return context > 0
    ? `${shown} of ${total} nodes — ${matched} matched, ${context} neighbouring`
    : `${shown} of ${total} nodes — ${matched} matched`;
}
