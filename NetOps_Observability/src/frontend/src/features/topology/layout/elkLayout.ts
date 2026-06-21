// elkLayout.ts — deterministic layout via the Eclipse Layout Kernel (elkjs).
//
// Performance rule (PDF §13): compute layout only when the graph/view changes, and
// CACHE by topology_id + mode + scope hash. Never recompute on every render. ELK
// runs on demand and returns positions; React Flow renders them.

import ELK from "elkjs/lib/elk.bundled.js";
import type { TopologyView } from "../api/topologyTypes";
import type { LayoutResult } from "./layoutTypes";
import { NODE_SIZE } from "./layoutTypes";
import { presetFor } from "./layoutPresets";

const elk = new ELK();

// Role → vertical tier (0 = top). Drives ELK partitioning so a DC/campus graph
// reads as a proper tree: WAN/edge on top, then spine, then leaf, then access/LAN —
// instead of ELK inferring layers from the undirected mesh (which put leaves above
// spines). Unknown roles land in the middle tier so they never break the layout.
function roleTier(role?: string, kind?: string): number {
  const r = (role || kind || "").toLowerCase();
  if (/(wan|edge|border|core|internet|uplink|transit)/.test(r)) return 0;
  if (/(firewall|fw|dmz|spine|gateway)/.test(r)) return 1;
  if (/(leaf|tor|aggreg|distribution)/.test(r)) return 2;
  if (/(lan|access|server|host|endpoint|workload)/.test(r)) return 3;
  return 2;
}

// view-keyed cache; a view's identity is its id + node/edge cardinality + intent.
const cache = new Map<string, LayoutResult>();

function viewKey(view: TopologyView): string {
  return [view.view_id, view.mode, view.layout_type, view.nodes.length, view.edges.length].join("|");
}

/**
 * Lay the view out. If a node already carries pinned coordinates (saved operator
 * layout / geo), they win and ELK is skipped for that node.
 */
export async function layoutView(view: TopologyView): Promise<LayoutResult> {
  const key = viewKey(view);
  const hit = cache.get(key);
  if (hit) return hit;

  const preset = presetFor(view.layout_type);

  // If every node is pinned (e.g. geo/saved), short-circuit ELK entirely.
  if (view.nodes.length > 0 && view.nodes.every((n) => n.coordinates)) {
    const pinned: LayoutResult = {};
    for (const n of view.nodes) pinned[n.id] = { x: n.coordinates!.x, y: n.coordinates!.y };
    cache.set(key, pinned);
    return pinned;
  }

  const graph = {
    id: "root",
    layoutOptions: {
      "elk.algorithm": "layered",
      "elk.direction": preset.direction,
      "elk.layered.spacing.nodeNodeBetweenLayers": String(preset.layerSpacing),
      "elk.spacing.nodeNode": String(preset.nodeSpacing),
      "elk.layered.considerModelOrder.strategy": "NODES_AND_EDGES",
      "elk.edgeRouting": "ORTHOGONAL",
      // Tier the graph by device role (spine above leaf, etc.) when the preset asks.
      ...(preset.partitionByRole ? { "elk.partitioning.activate": "true" } : {}),
    },
    children: view.nodes.map((n) => ({
      id: n.id,
      width: NODE_SIZE.width,
      height: NODE_SIZE.height,
      ...(preset.partitionByRole
        ? { layoutOptions: { "elk.partitioning.partition": String(roleTier(n.role, n.kind)) } }
        : {}),
    })),
    // Only edges between two laid-out nodes guide the layout.
    edges: view.edges
      .filter((e) => e.source && e.target)
      .map((e) => ({ id: e.id, sources: [e.source], targets: [e.target] })),
  };

  let result: LayoutResult = {};
  try {
    const laid = await elk.layout(graph);
    for (const c of laid.children ?? []) {
      result[c.id] = { x: c.x ?? 0, y: c.y ?? 0 };
    }
  } catch {
    // ELK should not fail, but never blank the canvas — fall back to a calm grid.
    result = gridFallback(view);
  }
  // any node ELK didn't place (shouldn't happen) gets a grid slot.
  if (Object.keys(result).length < view.nodes.length) {
    const grid = gridFallback(view);
    for (const n of view.nodes) if (!result[n.id]) result[n.id] = grid[n.id];
  }

  cache.set(key, result);
  return result;
}

function gridFallback(view: TopologyView): LayoutResult {
  const cols = Math.max(1, Math.ceil(Math.sqrt(view.nodes.length)));
  const out: LayoutResult = {};
  view.nodes.forEach((n, i) => {
    out[n.id] = {
      x: (i % cols) * (NODE_SIZE.width + 60),
      y: Math.floor(i / cols) * (NODE_SIZE.height + 60),
    };
  });
  return out;
}

/** Drop a cached layout (e.g. after a saved-layout edit). */
export function invalidateLayout(view: TopologyView): void {
  cache.delete(viewKey(view));
}
