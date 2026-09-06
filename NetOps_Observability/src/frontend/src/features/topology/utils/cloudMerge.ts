// cloudMerge.ts — put the discovered CLOUD network onto the SAME canvas as the
// on-prem fabric (#131).
//
// Cloud used to be a separate page with its own renderer, its own nodeTypes and
// its own fetch. That reads fine as a tab and is useless for the question an
// operator actually has ("is the problem on my side of the seam or theirs?"),
// because cloud↔on-prem troubleshooting needs both ends on ONE canvas. The Cloud
// domain is a FILTER over this merged view now, not a different graph.
//
// Both halves arrive from routes the caller was independently authorized for
// (`/api/topology/view` and `/api/topology/cloud`, each tenant-scoped and
// default-closed on the server), so the union carries no tenancy of its own —
// there is nothing here to widen. Pure: returns a new view, never mutates.
//
// The on-prem half WINS every id collision. It is the operator's own inventory
// and the reconciler's identity; a cloud fixture must never overwrite a device
// row the discovery resolved.

import type { TopologyView, OverlayKind } from "../api/topologyTypes";

/**
 * Union the cloud projection into the fabric view.
 *
 * Identity path: a null/empty cloud view returns the base object UNCHANGED (same
 * reference), so a tenant with no discovered cloud network renders exactly the
 * canvas it rendered before — and the memo above this never re-derives.
 */
export function mergeCloudView(base: TopologyView, cloud: TopologyView | null | undefined): TopologyView {
  if (!cloud || cloud.nodes.length === 0) return base;

  const nodeIds = new Set(base.nodes.map((n) => n.id));
  const nodes = [...base.nodes];
  for (const n of cloud.nodes) {
    if (nodeIds.has(n.id)) continue; // on-prem identity wins
    nodeIds.add(n.id);
    nodes.push(n);
  }

  const edgeIds = new Set(base.edges.map((e) => e.id));
  const edges = [...base.edges];
  for (const e of cloud.edges) {
    if (edgeIds.has(e.id)) continue;
    // An edge whose endpoints did not survive the merge would render as a link to
    // nowhere; the same rule normalizeView applies at the API boundary.
    if (!nodeIds.has(e.source) || !nodeIds.has(e.target)) continue;
    edgeIds.add(e.id);
    edges.push(e);
  }

  const groupIds = new Set(base.groups.map((g) => g.id));
  const groups = [...base.groups];
  for (const g of cloud.groups) {
    if (groupIds.has(g.id)) continue;
    groupIds.add(g.id);
    groups.push(g);
  }
  // A nested container whose parent did not come across would be laid out as a
  // top-level box; drop the dangling reference rather than the group (losing a
  // whole VPC is far worse than rendering it un-nested — the same call
  // `buildChildren` makes in the layout).
  const nested = groups.map((g) => (g.parent_id && !groupIds.has(g.parent_id) ? { ...g, parent_id: undefined } : g));

  const overlays = [...new Set<OverlayKind>([...base.overlays, ...cloud.overlays])];

  // The BASE view's identity is kept: same view_id, mode and layout_type, so the
  // layout cache key, the saved-layout key and the workflow all stay the base
  // canvas's. The cloud half contributes objects, never identity.
  return { ...base, nodes, edges, groups: nested, overlays };
}
