// topologyLayout.ts — dynamic, topology-aware graph layout.
//
// Network topologies historically fall into a few shapes — Star, Ring, Bus,
// Tree, Mesh (and CLOS/spine-leaf, a layered bipartite mesh) — and each reads
// best with a different geometry. Rather than force one fixed tier layout (which
// renders a spine-leaf fabric as a serial hairball), this module CLASSIFIES the
// topology from the observed adjacency (LLDP/CDP/BGP-LS links) and positions
// nodes for that shape. Role hints (spine/leaf/core/access) refine the layered
// case; pure structure drives the rest. Nodes stay individually draggable — this
// only computes the initial arrangement.

export type TopoType = "star" | "ring" | "bus" | "tree" | "clos" | "mesh" | "hybrid";

export interface LayoutNodeInput {
  id: string;
  role?: string;
}
export interface LayoutEdgeInput {
  source: string;
  target: string;
}
export interface LayoutResult {
  type: TopoType;
  positions: Record<string, { x: number; y: number }>;
  layer: Record<string, number>; // vertical layer (for edge orientation); 0 = top
}

// Vertical rank for known roles — the canonical north→south NOC hierarchy.
// Unknown roles are placed by structure (BFS depth) instead.
const ROLE_RANK: Record<string, number> = {
  internet: 0, cloud: 0, isp: 0,
  wan: 1, edge: 1, border: 1, gateway: 1,
  core: 2, spine: 2,
  distribution: 3, dist: 3, aggregation: 3, agg: 3, firewall: 3,
  leaf: 4, tor: 4,
  access: 5, switch: 5,
  server: 6, host: 6, compute: 6, endpoint: 6,
};

const X_GAP = 200;
const Y_GAP = 170;
const CENTER_X = 600;

interface Graph {
  ids: string[];
  adj: Map<string, Set<string>>;
  deg: Map<string, number>;
}

function buildGraph(nodes: LayoutNodeInput[], edges: LayoutEdgeInput[]): Graph {
  const adj = new Map<string, Set<string>>();
  for (const n of nodes) adj.set(n.id, new Set());
  for (const e of edges) {
    if (e.source === e.target) continue;
    if (!adj.has(e.source) || !adj.has(e.target)) continue;
    adj.get(e.source)!.add(e.target);
    adj.get(e.target)!.add(e.source);
  }
  const deg = new Map<string, number>();
  for (const [id, s] of adj) deg.set(id, s.size);
  return { ids: nodes.map((n) => n.id), adj, deg };
}

function isConnected(g: Graph): boolean {
  if (g.ids.length === 0) return true;
  const seen = new Set<string>([g.ids[0]]);
  const q = [g.ids[0]];
  while (q.length) {
    const cur = q.shift()!;
    for (const nb of g.adj.get(cur) ?? []) if (!seen.has(nb)) { seen.add(nb); q.push(nb); }
  }
  return seen.size === g.ids.length;
}

// twoColor returns the bipartite partition [setA, setB], or null if odd cycle.
function twoColor(g: Graph): [string[], string[]] | null {
  const color = new Map<string, number>();
  for (const start of g.ids) {
    if (color.has(start)) continue;
    color.set(start, 0);
    const q = [start];
    while (q.length) {
      const cur = q.shift()!;
      for (const nb of g.adj.get(cur) ?? []) {
        if (!color.has(nb)) { color.set(nb, color.get(cur)! ^ 1); q.push(nb); }
        else if (color.get(nb) === color.get(cur)) return null;
      }
    }
  }
  const a: string[] = [], b: string[] = [];
  for (const [id, c] of color) (c === 0 ? a : b).push(id);
  return [a, b];
}

function classify(g: Graph, nodes: LayoutNodeInput[]): TopoType {
  const n = g.ids.length;
  let m = 0;
  for (const s of g.adj.values()) m += s.size;
  m /= 2; // undirected edge count
  if (n <= 2) return "bus";

  const degs = g.ids.map((id) => g.deg.get(id) ?? 0);
  const maxDeg = Math.max(...degs);
  const deg1 = degs.filter((d) => d === 1).length;
  const allDeg2 = degs.every((d) => d === 2);
  const connected = isConnected(g);

  // Star: one hub adjacent to everyone, all others are leaves.
  if (maxDeg === n - 1 && deg1 === n - 1) return "star";
  // Ring: a single cycle — every node degree 2, edges == nodes.
  if (connected && allDeg2 && m === n) return "ring";
  // Bus/line: a path — two endpoints (deg 1), the rest deg 2, acyclic.
  if (connected && deg1 === 2 && m === n - 1 && degs.every((d) => d === 1 || d === 2)) return "bus";

  // CLOS / spine-leaf: bipartite with cross-set links only, has cycles (m > n-1),
  // and both sides non-trivial. The defining shape of a DC fabric.
  const parts = twoColor(g);
  if (parts && m > n - 1 && parts[0].length >= 2 && parts[1].length >= 1 && (parts[0].length >= 2 && parts[1].length >= 2)) {
    return "clos";
  }
  // Tree: connected & acyclic.
  if (connected && m === n - 1) return "tree";
  // Mesh: dense (>= 60% of a full mesh).
  if (n >= 4 && m >= 0.6 * (n * (n - 1)) / 2) return "mesh";
  // Roles describe a clear hierarchy → treat as a tree-like layered graph.
  if (nodes.some((nd) => roleRank(nd.role) !== undefined)) return "tree";
  return "hybrid";
}

function roleRank(role?: string): number | undefined {
  if (!role) return undefined;
  return ROLE_RANK[role.toLowerCase().trim()];
}

// ---- per-shape positioners --------------------------------------------------

function radial(g: Graph): Record<string, { x: number; y: number }> {
  // hub at center, spokes on a circle.
  const hub = g.ids.reduce((a, b) => ((g.deg.get(b) ?? 0) > (g.deg.get(a) ?? 0) ? b : a), g.ids[0]);
  const spokes = g.ids.filter((id) => id !== hub);
  const pos: Record<string, { x: number; y: number }> = { [hub]: { x: CENTER_X, y: 300 } };
  const R = Math.max(180, spokes.length * 26);
  spokes.forEach((id, i) => {
    const t = (2 * Math.PI * i) / spokes.length;
    pos[id] = { x: CENTER_X + R * Math.cos(t), y: 300 + R * Math.sin(t) };
  });
  return pos;
}

function circular(g: Graph): Record<string, { x: number; y: number }> {
  const pos: Record<string, { x: number; y: number }> = {};
  const order = ringOrder(g);
  const R = Math.max(200, order.length * 30);
  order.forEach((id, i) => {
    const t = (2 * Math.PI * i) / order.length - Math.PI / 2;
    pos[id] = { x: CENTER_X + R * Math.cos(t), y: 320 + R * Math.sin(t) };
  });
  return pos;
}

// ringOrder walks the cycle so circular placement follows true adjacency.
function ringOrder(g: Graph): string[] {
  const order: string[] = [];
  const seen = new Set<string>();
  let cur = g.ids[0];
  while (cur && !seen.has(cur)) {
    order.push(cur); seen.add(cur);
    const next = [...(g.adj.get(cur) ?? [])].find((nb) => !seen.has(nb));
    cur = next as string;
  }
  for (const id of g.ids) if (!seen.has(id)) order.push(id); // stragglers
  return order;
}

function linear(g: Graph): Record<string, { x: number; y: number }> {
  // walk the path from an endpoint (degree 1) so order matches the bus.
  const start = g.ids.find((id) => (g.deg.get(id) ?? 0) === 1) ?? g.ids[0];
  const order: string[] = []; const seen = new Set<string>();
  let cur: string | undefined = start;
  while (cur && !seen.has(cur)) {
    order.push(cur); seen.add(cur);
    cur = [...(g.adj.get(cur) ?? [])].find((nb) => !seen.has(nb));
  }
  for (const id of g.ids) if (!seen.has(id)) order.push(id);
  const pos: Record<string, { x: number; y: number }> = {};
  order.forEach((id, i) => { pos[id] = { x: 120 + i * X_GAP, y: 320 }; });
  return pos;
}

// layered assigns each node a vertical layer (role rank when known, else BFS
// depth from a top anchor) and spreads each layer horizontally. Powers tree,
// CLOS and hybrid — the hierarchical shapes.
function layered(g: Graph, nodes: LayoutNodeInput[], type: TopoType): { positions: Record<string, { x: number; y: number }>; layer: Record<string, number> } {
  const roleOf = new Map(nodes.map((n) => [n.id, n.role]));
  const layer = new Map<string, number>();

  const haveRoles = nodes.some((n) => roleRank(n.role) !== undefined);
  if (type === "clos" && !haveRoles) {
    // structural bipartite: the higher-degree side is the "spine" row (top).
    const parts = twoColor(g)!;
    const avg = (s: string[]) => s.reduce((t, id) => t + (g.deg.get(id) ?? 0), 0) / Math.max(s.length, 1);
    const [top, bottom] = avg(parts[0]) >= avg(parts[1]) ? [parts[0], parts[1]] : [parts[1], parts[0]];
    top.forEach((id) => layer.set(id, 0));
    bottom.forEach((id) => layer.set(id, 1));
  } else if (haveRoles) {
    // role rank, with unknown-role nodes pulled to just-below their min-rank neighbour.
    for (const id of g.ids) {
      const r = roleRank(roleOf.get(id));
      if (r !== undefined) layer.set(id, r);
    }
    for (let pass = 0; pass < 4; pass++) {
      for (const id of g.ids) {
        if (layer.has(id)) continue;
        const nbLayers = [...(g.adj.get(id) ?? [])].map((nb) => layer.get(nb)).filter((v): v is number => v !== undefined);
        if (nbLayers.length) layer.set(id, Math.min(...nbLayers) + 1);
      }
    }
    for (const id of g.ids) if (!layer.has(id)) layer.set(id, 3); // orphan default mid
  } else {
    // BFS depth from the highest-degree root (top of the tree).
    const root = g.ids.reduce((a, b) => ((g.deg.get(b) ?? 0) > (g.deg.get(a) ?? 0) ? b : a), g.ids[0]);
    layer.set(root, 0);
    const q = [root];
    while (q.length) {
      const cur = q.shift()!;
      for (const nb of g.adj.get(cur) ?? []) if (!layer.has(nb)) { layer.set(nb, layer.get(cur)! + 1); q.push(nb); }
    }
    for (const id of g.ids) if (!layer.has(id)) layer.set(id, 0);
  }

  // normalize layers to 0..k and place each row.
  const used = [...new Set([...layer.values()])].sort((a, b) => a - b);
  const norm = new Map(used.map((v, i) => [v, i]));
  const rows = new Map<number, string[]>();
  for (const id of g.ids) {
    const ly = norm.get(layer.get(id)!)!;
    layer.set(id, ly);
    (rows.get(ly) ?? rows.set(ly, []).get(ly)!).push(id);
  }
  const positions: Record<string, { x: number; y: number }> = {};
  const layerObj: Record<string, number> = {};
  for (const [ly, ids] of rows) {
    ids.sort(); // stable; barycenter ordering is a future refinement
    const width = (ids.length - 1) * X_GAP;
    ids.forEach((id, i) => {
      positions[id] = { x: CENTER_X - width / 2 + i * X_GAP, y: 80 + ly * Y_GAP };
      layerObj[id] = ly;
    });
  }
  return { positions, layer: layerObj };
}

// layoutTopology classifies the graph and returns node positions + per-node
// layer (for edge-handle orientation). Pure; deterministic for a given input.
export function layoutTopology(nodes: LayoutNodeInput[], edges: LayoutEdgeInput[]): LayoutResult {
  if (nodes.length === 0) return { type: "hybrid", positions: {}, layer: {} };
  const g = buildGraph(nodes, edges);
  const type = classify(g, nodes);
  switch (type) {
    case "star":
      return { type, positions: radial(g), layer: {} };
    case "ring":
    case "mesh":
      return { type, positions: circular(g), layer: {} };
    case "bus":
      return { type, positions: linear(g), layer: {} };
    default: {
      const { positions, layer } = layered(g, nodes, type);
      return { type, positions, layer };
    }
  }
}
