// AsPathGraphPanel — the flagship of the BGP visualization design
// (docs/design/research/BGP_OPS_CONSOLIDATION_RESEARCH_2026-08-25.md): the
// wall of AS-path pills becomes a node-link graph, vantage points on the left
// converging through transit to the origin on the right.
//
// Renderer: @xyflow/react — the SAME stack the topology canvas uses. No new
// dependency, and no layout engine either: the API hands back each node's hop
// depth, so the layout is a deterministic column placement (bgpDepth.model.ts).
// Determinism matters operationally — two engineers comparing screens during an
// outage must be looking at the same picture.
//
// Honesty: the edge cap, the node cap and the data SOURCE (bgp-state vs the
// looking-glass fallback) are all stated in the caption. A capped graph that
// does not say it is capped is a false statement about the topology.

import { useEffect, useMemo, useState } from "react";
import {
  ReactFlow, Background, BackgroundVariant, Controls, Handle, Position,
  type Edge, type Node, type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { api, type BgpAsPathGraph, type BgpGraphNode } from "../../services/api";
import { Chip } from "../../components/noc";
import { NODE_H, NODE_W, edgeWidth, layoutAsPathGraph, nodeLabel, nodeSubLabel, pathLengthHint } from "./bgpDepth.model";

// ── node renderer ───────────────────────────────────────────────────────────

type AsNodeData = BgpGraphNode & { maxPaths: number };

function AsNode({ data }: NodeProps) {
  const d = data as unknown as AsNodeData;
  const tone = d.origin ? "var(--accent)" : d.tenant ? "var(--ok)" : "var(--border)";
  const title = [
    `AS${d.asn}${d.name ? ` — ${d.name}` : ""}`,
    d.origin ? "Origin AS for this prefix" : d.vantage ? "Collector-adjacent (vantage point)" : `${d.depth} hop${d.depth === 1 ? "" : "s"} from a collector peer`,
    d.tenant ? "One of your watched ASNs" : "",
    `Seen on ${d.paths} observed path${d.paths === 1 ? "" : "s"}`,
  ].filter(Boolean).join("\n");

  return (
    <div
      title={title}
      style={{
        width: NODE_W, height: NODE_H, boxSizing: "border-box",
        display: "flex", flexDirection: "column", justifyContent: "center",
        padding: "4px 8px", borderRadius: 8, fontFamily: "var(--font-mono)",
        border: `${d.origin || d.tenant ? 2 : 1}px solid ${tone}`,
        background: d.origin
          ? "color-mix(in srgb, var(--accent) 16%, transparent)"
          : d.tenant
            ? "color-mix(in srgb, var(--ok) 14%, transparent)"
            : "var(--surface)",
      }}
    >
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
      <div style={{ fontSize: 12, fontWeight: 600, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
        {nodeLabel(d)}
      </div>
      <div className="mini-meta" style={{ fontSize: 9, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
        {nodeSubLabel(d) || (d.origin ? "origin" : d.vantage ? "vantage" : `${d.paths}×`)}
      </div>
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />
    </div>
  );
}

const nodeTypes = { asnode: AsNode };

// ── panel ───────────────────────────────────────────────────────────────────

export function AsPathGraphPanel({ prefix }: { prefix?: string }) {
  const [g, setG] = useState<BgpAsPathGraph | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!prefix) { setG(null); setErr(""); return; }
    let alive = true;
    setBusy(true); setErr(""); setG(null);
    api.bgpAsPathGraph(prefix)
      .then((d) => { if (alive) setG(d); })
      .catch((e: Error) => { if (alive) setErr(e.message || "AS-path graph unavailable"); })
      .finally(() => { if (alive) setBusy(false); });
    return () => { alive = false; };
  }, [prefix]);

  const laid = useMemo(() => (g ? layoutAsPathGraph(g) : null), [g]);

  const rf = useMemo(() => {
    if (!laid) return { nodes: [] as Node[], edges: [] as Edge[] };
    const maxPeers = laid.edges.reduce((m, e) => Math.max(m, e.peers), 1);
    const maxPaths = laid.nodes.reduce((m, n) => Math.max(m, n.paths), 1);
    const nodes: Node[] = laid.nodes.map((n) => ({
      id: String(n.asn),
      type: "asnode",
      position: { x: n.x, y: n.y },
      data: { ...n, maxPaths } as unknown as Record<string, unknown>,
      draggable: false,
      selectable: false,
    }));
    const edges: Edge[] = laid.edges.map((e) => ({
      id: `${e.from}-${e.to}`,
      source: String(e.from),
      target: String(e.to),
      style: { strokeWidth: edgeWidth(e.peers, maxPeers), stroke: "var(--border-strong, var(--border))" },
      label: e.peers > 1 ? String(e.peers) : undefined,
      labelStyle: { fontSize: 9, fill: "var(--fg-muted)" },
    }));
    return { nodes, edges };
  }, [laid]);

  const hint = g ? pathLengthHint(g) : null;
  const height = laid ? Math.min(520, Math.max(220, laid.height + 80)) : 220;

  return (
    <div className="card" style={{ marginTop: 12 }}>
      <h2>AS-path graph</h2>
      {!prefix && <div className="empty">Look up a prefix to see how the internet reaches it.</div>}
      {busy && <div className="empty">Building the path graph…</div>}
      {err && <p className="mini-meta" style={{ color: "var(--bad)" }} role="alert">{err}</p>}

      {g && g.error && !g.nodes.length && (
        <div className="empty" style={{ textAlign: "left" }}>
          Path data is unavailable right now: {g.error}. This is a collector outage, not evidence that the prefix is
          unreachable.
        </div>
      )}

      {g && !g.error && g.nodes.length === 0 && (
        <div className="empty">No route-collector peer currently sees a path to {g.prefix}.</div>
      )}

      {laid && laid.nodes.length > 0 && (
        <>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 8 }}>
            <Chip label={`${g?.paths ?? 0} observed paths`} title="Collector peers folded into this graph" />
            <Chip label={`${laid.nodes.length} ASNs`} />
            <Chip label={`${laid.edges.length} adjacencies`} />
            {g?.origins.map((o) => (
              <Chip key={o} label={`origin AS${o}`} tone="var(--accent)" title="Announces this prefix" />
            ))}
            {hint && <Chip label={`path length ${hint.min}–${hint.max}`} title="Shorter than usual can be a hijack tell; longer, a leak tell." />}
            <Chip label={g?.source === "looking-glass" ? "looking-glass (fallback)" : "RIS bgp-state"}
              title="Which RIPE data call this graph was built from" />
          </div>

          <div data-testid="aspath-canvas" style={{ height, border: "1px solid var(--border)", borderRadius: 8 }}>
            <ReactFlow
              nodes={rf.nodes}
              edges={rf.edges}
              nodeTypes={nodeTypes}
              fitView
              fitViewOptions={{ padding: 0.18 }}
              nodesDraggable={false}
              nodesConnectable={false}
              proOptions={{ hideAttribution: true }}
            >
              <Background variant={BackgroundVariant.Dots} gap={18} size={1} />
              <Controls showInteractive={false} />
            </ReactFlow>
          </div>

          {(g?.edges_capped || g?.nodes_capped) && (
            <p className="mini-meta" style={{ color: "var(--warn)" }}>
              This graph is capped at {g?.max_edges} adjacencies{g?.nodes_capped ? " and its node budget" : ""} — the
              strongest adjacencies are kept, so the trunk of the path is complete but the long tail of
              single-peer edges is not drawn.
            </p>
          )}
          <p className="mini-meta" style={{ marginBottom: 0 }}>
            Left to right: collector-adjacent AS → transit → <span style={{ color: "var(--accent)" }}>origin</span>.
            Line thickness is how many collector paths traverse that adjacency — an observation count, not capacity.
            Your own watched ASNs are outlined in <span style={{ color: "var(--ok)" }}>green</span>. Hover any AS for its
            registry holder.
          </p>
        </>
      )}
    </div>
  );
}

export default AsPathGraphPanel;
