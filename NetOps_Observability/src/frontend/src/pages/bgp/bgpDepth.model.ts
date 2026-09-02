// bgpDepth.model.ts — the PURE model behind the BGP depth panels. No React, no
// fetch, no React Flow types: everything here is a function of the wire shape,
// which is why it is the part that carries the tests.
//
// The AS-path layout is deliberately NOT a force layout and NOT ELK: an AS path
// is already layered — the API hands back each node's `depth` (its shortest hop
// distance from a collector vantage point), so the honest drawing is columns of
// depth, vantage on the left, origin on the right. That is deterministic (the
// same data always draws the same picture, which matters when two engineers
// compare screens during an outage) and costs no layout engine.

import type {
  BgpAsPathGraph, BgpGraphEdge, BgpGraphNode, BgpRpkiResult, BgpRpkiState,
  BgpFeedUpdate, BgpGeofeedResp,
} from "../../services/api";

// ── RPKI ────────────────────────────────────────────────────────────────────

export type RpkiTone = { label: string; tone: string; detail: string };

/** Map an API RPKI state (+reason) onto the page's chip. `unavailable` is its
 *  OWN presentation — it is not a verdict and must never look like one. */
export function rpkiStateTone(state: BgpRpkiState | undefined, reason?: string, error?: string): RpkiTone {
  switch (state) {
    case "valid":
      return { label: "VALID", tone: "var(--ok)", detail: "A ROA covers this announcement from this origin." };
    case "invalid":
      if (reason === "origin_as")
        return { label: "INVALID · origin", tone: "var(--crit)", detail: "A ROA exists but authorises a DIFFERENT origin AS — hijack or a stale ROA." };
      if (reason === "max_length")
        return { label: "INVALID · length", tone: "var(--crit)", detail: "More specific than the ROA's maxLength allows — often an accidental de-aggregation." };
      return { label: "INVALID", tone: "var(--crit)", detail: "The announcement violates a published ROA." };
    case "unknown":
      return { label: "NO ROA", tone: "var(--muted)", detail: "No ROA covers this prefix. Publishing one is what makes an invalid hijack droppable." };
    default:
      return { label: "UNAVAILABLE", tone: "var(--warn)", detail: error || "The validator could not be reached — this is not a verdict." };
  }
}

/** Counts for the summary strip. Deliberately keeps `unavailable` separate from
 *  `unknown`: "we could not check" and "nobody published a ROA" are different
 *  facts and collapsing them would overstate coverage. */
export function rpkiSummary(results: BgpRpkiResult[]): Record<BgpRpkiState, number> {
  const out: Record<BgpRpkiState, number> = { valid: 0, invalid: 0, unknown: 0, unavailable: 0 };
  for (const r of results) out[r.state] = (out[r.state] ?? 0) + 1;
  return out;
}

// ── AS-path graph layout ────────────────────────────────────────────────────

export const NODE_W = 132;
export const NODE_H = 44;
const COL_GAP = 86;
const ROW_GAP = 16;

export type LaidNode = BgpGraphNode & { x: number; y: number };
export type LaidGraph = {
  nodes: LaidNode[];
  edges: BgpGraphEdge[];
  width: number;
  height: number;
  /** Columns, left (vantage) to right (origin), for the axis caption. */
  depths: number[];
};

/**
 * layoutAsPathGraph places nodes in depth columns.
 *
 * Origins are FORCED into the last column even when a short path gave them a
 * small depth: the picture's whole promise is "vantage on the left, the origin
 * on the right", and an origin floating mid-graph breaks that reading.
 * Within a column, heavier nodes (more observed paths) sit nearer the middle,
 * which pulls the trunk of the path into a straight line.
 */
export function layoutAsPathGraph(g: Pick<BgpAsPathGraph, "nodes" | "edges" | "origins">): LaidGraph {
  const origins = new Set(g.origins ?? []);
  const maxDepth = g.nodes.reduce((m, n) => Math.max(m, n.depth), 0);
  const lastCol = g.nodes.length > 1 ? Math.max(maxDepth, 1) : 0;

  const colOf = (n: BgpGraphNode): number => (origins.has(n.asn) || n.origin ? lastCol : Math.min(n.depth, Math.max(lastCol - 1, 0)));

  const columns = new Map<number, BgpGraphNode[]>();
  for (const n of g.nodes) {
    const c = colOf(n);
    const list = columns.get(c) ?? [];
    list.push(n);
    columns.set(c, list);
  }

  const depths = [...columns.keys()].sort((a, b) => a - b);
  const tallest = Math.max(1, ...[...columns.values()].map((c) => c.length));
  const height = tallest * (NODE_H + ROW_GAP);

  const nodes: LaidNode[] = [];
  for (const c of depths) {
    // Heaviest first, then by ASN — deterministic, and the trunk lands centrally.
    const col = [...(columns.get(c) ?? [])].sort((a, b) => (b.paths - a.paths) || (a.asn - b.asn));
    const colH = col.length * (NODE_H + ROW_GAP);
    const top = (height - colH) / 2;
    col.forEach((n, i) => {
      nodes.push({ ...n, x: c * (NODE_W + COL_GAP), y: top + i * (NODE_H + ROW_GAP) });
    });
  }
  const width = (depths.length ? depths[depths.length - 1] : 0) * (NODE_W + COL_GAP) + NODE_W;

  // Drop any edge whose endpoint we did not lay out — a link to nothing is worse
  // than a missing link.
  const present = new Set(nodes.map((n) => n.asn));
  const edges = (g.edges ?? []).filter((e) => present.has(e.from) && present.has(e.to));

  return { nodes, edges, width, height, depths };
}

/** Stroke width for an edge, by how many collector paths traverse it. */
export function edgeWidth(peers: number, maxPeers: number): number {
  if (maxPeers <= 1) return 1.4;
  const t = Math.min(1, Math.max(0, (peers - 1) / (maxPeers - 1)));
  return 1.2 + t * 3.6;
}

/** The label a node shows: the holder name when the registry gave us one, and
 *  otherwise the bare ASN — never a placeholder that could be read as a name. */
export function nodeLabel(n: BgpGraphNode): string {
  return `AS${n.asn}`;
}
export function nodeSubLabel(n: BgpGraphNode): string {
  return n.name ?? "";
}

/** Path-length distribution across the observed graph, for the caption. */
export function pathLengthHint(g: Pick<BgpAsPathGraph, "nodes">): { min: number; max: number } | null {
  if (!g.nodes.length) return null;
  const depths = g.nodes.map((n) => n.depth);
  return { min: Math.min(...depths) + 1, max: Math.max(...depths) + 1 };
}

// ── live feed ───────────────────────────────────────────────────────────────

/** Merge a new page into the local buffer, newest LAST, capped. The client
 *  buffer mirrors the server ring: constant size, oldest dropped. */
export function mergeFeed(existing: BgpFeedUpdate[], page: BgpFeedUpdate[], cap = 500): BgpFeedUpdate[] {
  if (!page.length) return existing;
  const seen = new Set(existing.map((u) => u.seq));
  const merged = existing.concat(page.filter((u) => !seen.has(u.seq)));
  merged.sort((a, b) => a.seq - b.seq);
  return merged.length > cap ? merged.slice(merged.length - cap) : merged;
}

/** Announce/withdraw counts for the feed's header. */
export function feedCounts(ups: BgpFeedUpdate[]): { announce: number; withdraw: number } {
  let announce = 0, withdraw = 0;
  for (const u of ups) (u.type === "W" ? withdraw++ : announce++);
  return { announce, withdraw };
}

// ── geofeed ─────────────────────────────────────────────────────────────────

/** Country → row count, biggest first, for the geofeed summary line. */
export function geofeedCountries(r: Pick<BgpGeofeedResp, "entries">): { country: string; rows: number }[] {
  const by = new Map<string, number>();
  for (const e of r.entries ?? []) {
    const c = e.country || "—";
    by.set(c, (by.get(c) ?? 0) + 1);
  }
  return [...by.entries()].map(([country, rows]) => ({ country, rows }))
    .sort((a, b) => b.rows - a.rows || a.country.localeCompare(b.country));
}
