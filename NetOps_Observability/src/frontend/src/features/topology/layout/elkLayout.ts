// elkLayout.ts — deterministic layout via the Eclipse Layout Kernel (elkjs).
//
// Performance rule (PDF §13): compute layout only when the graph/view changes, and
// CACHE by topology_id + mode + scope hash. Never recompute on every render. ELK
// runs on demand and returns positions; React Flow renders them.

import type { ELK as ElkInstance } from "elkjs/lib/elk-api";
import type { TopologyView } from "../api/topologyTypes";
import type { LayoutResult } from "./layoutTypes";
import { NODE_SIZE } from "./layoutTypes";
import { presetFor } from "./layoutPresets";
import { ELK_GROUP_PADDING, GROUP_GAP, GROUP_ASPECT, GROUP_MIN_W, GROUP_MIN_H } from "./groupGeometry";

// elkjs is ~1.6 MB — dynamic-import it on first layout so it never rides in
// the initial bundle. Memoized: one in-flight/loaded instance per session.
let elkPromise: Promise<ElkInstance> | null = null;
function loadElk(): Promise<ElkInstance> {
  if (!elkPromise) {
    elkPromise = import("elkjs/lib/elk.bundled.js").then((m) => new m.default());
  }
  return elkPromise;
}

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

// view-keyed cache, bounded (FIFO eviction — Map preserves insertion order).
const cache = new Map<string, LayoutResult>();
const CACHE_CAP = 24;

/**
 * Content signature over the node/edge id sets. Cardinality alone is NOT an
 * identity (audit S4): the client-side lenses (domain slice, carrier overlay)
 * mutate the node set without changing view_id/layout_type, so two different
 * graphs with equal counts collided in this cache — and every node missing
 * from the reused result fell to (0,0). Order-independent fold so a reordered
 * but identical view still hits.
 */
export function viewSignature(view: TopologyView): string {
  let h = 0;
  const fold = (s: string) => {
    let x = 5381;
    for (let i = 0; i < s.length; i++) x = ((x << 5) + x + s.charCodeAt(i)) | 0;
    h = (h + (x >>> 0)) >>> 0; // commutative sum → order-independent
  };
  for (const n of view.nodes) fold("n:" + n.id);
  for (const e of view.edges) fold("e:" + e.id);
  return `${view.nodes.length}.${view.edges.length}.${h.toString(36)}`;
}

function viewKey(view: TopologyView): string {
  return [view.view_id, view.mode, view.layout_type, viewSignature(view)].join("|");
}

function cachePut(key: string, result: LayoutResult): void {
  if (cache.size >= CACHE_CAP) {
    const oldest = cache.keys().next().value;
    if (oldest !== undefined) cache.delete(oldest);
  }
  cache.set(key, result);
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
    cachePut(key, pinned);
    return pinned;
  }

  const children = buildChildren(view, preset);

  // ── FILL THE STAGE, DON'T STRIPE IT ──────────────────────────────────────
  // A grouped cloud view's top level is a handful of independent boxes (regions,
  // or VPCs when a region is not declared) with NO edges between them. "layered"
  // has nothing to layer, so it puts all of them in ONE ROW: the deployed view
  // came out roughly 2100×270, an 8:1 ribbon that fit-to-view then had to shrink
  // to a thin strip across the middle of a 2:1 stage — the canvas looked mostly
  // empty no matter how large the window was.
  //
  // Independent boxes are a PACKING problem, not a layering one. rectpacking with
  // a target aspect ratio wraps them into a grid roughly the shape of the stage,
  // so the same content fills both dimensions. Scoped to cloud_grouped: every
  // other view has real edges whose direction is the whole point of layered.
  const packRoot = view.layout_type === "cloud_grouped" && children.some((c) => c.children?.length);

  const graph = {
    id: "root",
    layoutOptions: {
      "elk.algorithm": packRoot ? "rectpacking" : "layered",
      "elk.direction": preset.direction,
      "elk.layered.spacing.nodeNodeBetweenLayers": String(preset.layerSpacing),
      // Gap between packed top-level boxes; the tighter per-node spacing is only
      // right for leaves inside a container.
      "elk.spacing.nodeNode": String(packRoot ? GROUP_GAP : preset.nodeSpacing),
      // 2.0 ≈ the shape of a wide dashboard stage. Exact fit is fit-to-view's
      // job; this only has to stop the one-row ribbon.
      ...(packRoot ? { "elk.aspectRatio": "2.0" } : {}),
      "elk.layered.considerModelOrder.strategy": "NODES_AND_EDGES",
      // Lay CONTAINERS out together with what is inside them. Without this ELK
      // treats every node as a peer, group rectangles are drawn afterwards
      // around wherever members happened to land, and blocks from different
      // regions interleave — which is exactly why the cloud tab's VPC boxes
      // overlapped and could not be read.
      "elk.hierarchyHandling": "INCLUDE_CHILDREN",
      "elk.edgeRouting": "ORTHOGONAL",
      // Tier the graph by device role (spine above leaf, etc.) when the preset asks.
      ...(preset.partitionByRole ? { "elk.partitioning.activate": "true" } : {}),
    },
    children,
    // Only edges between two laid-out nodes guide the layout.
    edges: view.edges
      .filter((e) => e.source && e.target)
      .map((e) => ({ id: e.id, sources: [e.source], targets: [e.target] })),
  };

  let result: LayoutResult = {};
  try {
    const elk = await loadElk();
    const laid = await elk.layout(graph);
    // ELK reports a nested child's position RELATIVE TO ITS PARENT, so the tree
    // has to be walked with the parent origin accumulated. Reading only the top
    // level (as this did while the graph was flat) would place every grouped
    // node at its offset inside its container — i.e. all containers stacked at
    // the origin, which looks exactly like the overlapping blocks this change
    // exists to fix.
    const walk = (children: ElkChild[] | undefined, ox: number, oy: number) => {
      for (const c of children ?? []) {
        const x = ox + ((c as { x?: number }).x ?? 0);
        const y = oy + ((c as { y?: number }).y ?? 0);
        const w = (c as { width?: number }).width;
        const h = (c as { height?: number }).height;
        // A CONTAINER carries its solved rect; a leaf carries only a position.
        // This is the single-source rule: whatever ELK reserved is what gets
        // drawn, so the layout and the picture cannot disagree.
        result[c.id] = c.children?.length ? { x, y, w, h } : { x, y };
        walk(c.children, x, y);
      }
    };
    walk(laid.children as ElkChild[] | undefined, 0, 0);
  } catch {
    // ELK should not fail, but never blank the canvas — fall back to a calm grid.
    result = gridFallback(view);
  }
  // any node ELK didn't place (shouldn't happen) gets a grid slot.
  if (Object.keys(result).length < view.nodes.length) {
    const grid = gridFallback(view);
    for (const n of view.nodes) if (!result[n.id]) result[n.id] = grid[n.id];
  }

  cachePut(key, result);
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

// ── group hierarchy ──────────────────────────────────────────────────────────


type ElkChild = {
  id: string;
  width?: number;
  height?: number;
  layoutOptions?: Record<string, string>;
  children?: ElkChild[];
};

/**
 * buildChildren turns the view into ELK's child tree.
 *
 * A view with no groups produces the FLAT list this always used to produce —
 * every existing canvas is byte-for-byte unaffected. A view WITH groups nests
 * its nodes inside container children (and containers inside their parent
 * container, via Group.parent_id), which is what makes ELK pack each region's
 * VPCs inside one boundary instead of scattering them.
 */
function buildChildren(view: TopologyView, preset: ReturnType<typeof presetFor>): ElkChild[] {
  const leaf = (n: TopologyView["nodes"][number]): ElkChild => ({
    id: n.id,
    width: NODE_SIZE.width,
    height: NODE_SIZE.height,
    ...(preset.partitionByRole
      ? { layoutOptions: { "elk.partitioning.partition": String(roleTier(n.role, n.kind)) } }
      : {}),
  });

  const groups = view.groups ?? [];
  if (groups.length === 0) return view.nodes.map(leaf);

  const nodeById = new Map(view.nodes.map((n) => [n.id, n]));
  const claimed = new Set<string>();
  const containerById = new Map<string, ElkChild>();

  for (const g of groups) {
    const members: ElkChild[] = [];
    for (const childId of g.children ?? []) {
      const n = nodeById.get(childId);
      // A node may be listed by only ONE group; a second claim would duplicate
      // it in the layout and place the same id twice.
      if (n && !claimed.has(childId)) {
        claimed.add(childId);
        members.push(leaf(n));
      }
    }
    containerById.set(g.id, {
      id: g.id,
      layoutOptions: {
        "elk.padding": ELK_GROUP_PADDING,
        "elk.spacing.nodeNode": String(GROUP_GAP),
        "elk.aspectRatio": String(GROUP_ASPECT),
        "elk.nodeSize.minimum": `(${GROUP_MIN_W},${GROUP_MIN_H})`,
        "elk.algorithm": "layered",
        "elk.direction": preset.direction,
      },
      children: members,
    });
  }

  // Nest containers under their parent container where one is declared.
  const roots: ElkChild[] = [];
  for (const g of groups) {
    const c = containerById.get(g.id)!;
    const parent = g.parent_id ? containerById.get(g.parent_id) : undefined;
    // A parent that does not exist is treated as top level rather than dropped —
    // losing a whole region because of one bad reference would be far worse than
    // rendering it un-nested.
    if (parent && parent !== c) (parent.children ??= []).push(c);
    else roots.push(c);
  }

  // Anything no group claimed still has to be laid out — a node dropped from the
  // graph is a node the operator cannot see.
  for (const n of view.nodes) if (!claimed.has(n.id)) roots.push(leaf(n));
  return roots;
}
