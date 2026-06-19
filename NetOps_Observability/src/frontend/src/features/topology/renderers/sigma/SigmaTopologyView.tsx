// SigmaTopologyView — the Phase 4 enterprise-overview renderer (WebGL via
// Sigma.js). Mounts a deterministically laid-out graphology graph onto a GPU
// canvas so a graph too large for React Flow (hundreds–thousands of nodes) stays
// fluid. Same renderer-agnostic TopologyView in; a different renderer out.
//
// Interaction model mirrors the canvas (PDF §11): calm by default with sparse
// labels; hover spotlights a node's neighbourhood and dims the rest; click
// selects and opens a compact info card; search highlights matches. Heavy deps
// (sigma + graphology layout) are isolated here so the canvas can lazy-load them
// only when the operator opens the overview.

import { useEffect, useMemo, useRef, useState } from "react";
import Sigma from "sigma";
import { buildSigmaGraph } from "./sigmaGraph";
import type { TopologyView, Health } from "../../api/topologyTypes";
import { HEALTH_COLOR, HEALTH_LABEL } from "../../utils/topologyHealth";

const DIM_NODE = "#dbe1ea";
const ACTIVE_EDGE = "#8aa0bd";

const LEGEND: Health[] = ["ok", "warning", "critical", "maintenance", "unknown"];

export default function SigmaTopologyView({ view }: { view: TopologyView }) {
  const containerRef = useRef<HTMLDivElement>(null);
  // latest interaction state for the reducers (avoids rebuilding Sigma on hover).
  const hoveredRef = useRef<string | null>(null);
  const queryRef = useRef<string>("");
  const selectedRef = useRef<string | null>(null);
  const sigmaRef = useRef<Sigma | null>(null);

  const [selected, setSelected] = useState<string | null>(null);
  const [query, setQuery] = useState("");

  const counts = useMemo(() => {
    const by: Record<string, number> = {};
    for (const n of view.nodes) by[n.health] = (by[n.health] ?? 0) + 1;
    return by;
  }, [view]);

  // Build graph + Sigma once per view. Reducers read the refs so hover/search
  // never re-instantiate the renderer.
  useEffect(() => {
    if (!containerRef.current) return;
    const graph = buildSigmaGraph(view);

    const renderer = new Sigma(graph, containerRef.current, {
      defaultEdgeColor: "#e2e8f0",
      minCameraRatio: 0.05,
      maxCameraRatio: 3,
      labelRenderedSizeThreshold: 12, // sparse by default — only hubs label
      labelColor: { color: "#0f172a" },
      labelFont: "Inter, system-ui, sans-serif",
      labelSize: 12,
      labelWeight: "600",
      nodeReducer: (node, data) => {
        const res = { ...data } as typeof data & { highlighted?: boolean; zIndex?: number };
        const q = queryRef.current.trim().toLowerCase();
        if (q) {
          if (String(data.label ?? "").toLowerCase().includes(q)) {
            res.highlighted = true;
            res.zIndex = 2;
          } else {
            res.color = DIM_NODE;
            res.label = "";
          }
          return res;
        }
        const focus = hoveredRef.current ?? selectedRef.current;
        if (focus) {
          if (node === focus) {
            res.highlighted = true;
            res.zIndex = 2;
          } else if (graph.areNeighbors(focus, node)) {
            res.zIndex = 1;
          } else {
            res.color = DIM_NODE;
            res.label = "";
          }
        }
        return res;
      },
      edgeReducer: (edge, data) => {
        const res = { ...data } as typeof data & { hidden?: boolean; zIndex?: number };
        if (queryRef.current.trim()) {
          res.hidden = true;
          return res;
        }
        const focus = hoveredRef.current ?? selectedRef.current;
        if (focus) {
          const [s, t] = graph.extremities(edge);
          if (s === focus || t === focus) {
            res.color = ACTIVE_EDGE;
            res.zIndex = 1;
          } else {
            res.hidden = true;
          }
        }
        return res;
      },
    });

    renderer.on("enterNode", ({ node }) => {
      hoveredRef.current = node;
      renderer.refresh({ skipIndexation: true });
    });
    renderer.on("leaveNode", () => {
      hoveredRef.current = null;
      renderer.refresh({ skipIndexation: true });
    });
    renderer.on("clickNode", ({ node }) => {
      selectedRef.current = node;
      setSelected(node);
      renderer.refresh({ skipIndexation: true });
    });
    renderer.on("clickStage", () => {
      selectedRef.current = null;
      setSelected(null);
      renderer.refresh({ skipIndexation: true });
    });

    sigmaRef.current = renderer;
    return () => {
      renderer.kill();
      sigmaRef.current = null;
    };
  }, [view]);

  // Push search changes into the reducer and repaint.
  useEffect(() => {
    queryRef.current = query;
    sigmaRef.current?.refresh({ skipIndexation: true });
  }, [query]);

  const selectedInfo = useMemo(() => {
    if (!selected) return null;
    const g = sigmaRef.current?.getGraph();
    if (!g || !g.hasNode(selected)) return null;
    const a = g.getNodeAttributes(selected);
    return {
      label: String(a.label ?? selected),
      kind: String(a.kind ?? "—"),
      health: (a.health as Health) ?? "unknown",
      cluster: String(a.cluster ?? "—"),
      degree: g.degree(selected),
    };
  }, [selected]);

  return (
    <div className="topo-sigma">
      <div ref={containerRef} className="topo-sigma-canvas" />

      <div className="topo-sigma-search">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search the overview…"
          aria-label="Search overview nodes"
        />
      </div>

      <div className="topo-sigma-stats">
        <div className="topo-sigma-count">
          {view.nodes.length.toLocaleString()} nodes · {view.edges.length.toLocaleString()} links
        </div>
        <div className="topo-sigma-legend">
          {LEGEND.filter((h) => counts[h]).map((h) => (
            <span key={h} title={HEALTH_LABEL[h]}>
              <i style={{ background: HEALTH_COLOR[h] }} />
              {counts[h]}
            </span>
          ))}
        </div>
      </div>

      {selectedInfo && (
        <div className="topo-sigma-card">
          <div className="topo-sigma-card-head">
            <span className="topo-sigma-card-title">{selectedInfo.label}</span>
            <i
              className="topo-sigma-dot"
              style={{ background: HEALTH_COLOR[selectedInfo.health] }}
              title={HEALTH_LABEL[selectedInfo.health]}
            />
          </div>
          <dl>
            <div><dt>Kind</dt><dd>{selectedInfo.kind}</dd></div>
            <div><dt>Site</dt><dd>{selectedInfo.cluster}</dd></div>
            <div><dt>Health</dt><dd>{HEALTH_LABEL[selectedInfo.health]}</dd></div>
            <div><dt>Links</dt><dd>{selectedInfo.degree}</dd></div>
          </dl>
        </div>
      )}
    </div>
  );
}
