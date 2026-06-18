// PathAnalysisPanel — renders a traced A→B path as an ordered hop list. For each
// hop it shows the hostname, the ingress/egress interfaces (pulled from the
// connecting edge's source_port/target_port) and a per-hop decision note
// (node.tags.decision). The golden-path comparison is a Phase 6 placeholder.

import type { TopologyView, TopologyNode, TopologyEdge } from "../api/topologyTypes";

function edgeBetween(edges: TopologyEdge[], a: string, b: string): TopologyEdge | undefined {
  return edges.find(
    (e) => (e.source === a && e.target === b) || (e.source === b && e.target === a),
  );
}

export default function PathAnalysisPanel({ view }: { view: TopologyView }) {
  const path = view.path ?? [];

  if (path.length === 0) {
    return (
      <div
        style={{
          fontSize: 12,
          color: "var(--fg-muted)",
          padding: "12px",
          border: "1px dashed var(--border)",
          borderRadius: 6,
          background: "var(--surface)",
        }}
      >
        No path selected.
      </div>
    );
  }

  const byId = new Map<string, TopologyNode>(view.nodes.map((n) => [n.id, n]));

  return (
    <section>
      <div
        style={{
          fontSize: 11,
          fontWeight: 600,
          letterSpacing: 0.4,
          textTransform: "uppercase",
          color: "var(--fg-subtle)",
          marginBottom: 10,
        }}
      >
        Path · {path.length} hops
      </div>

      <ol style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 4 }}>
        {path.map((id, i) => {
          const node = byId.get(id);
          const prevEdge = i > 0 ? edgeBetween(view.edges, path[i - 1], id) : undefined;
          const nextEdge = i < path.length - 1 ? edgeBetween(view.edges, id, path[i + 1]) : undefined;

          // ingress = the port on this node facing the previous hop;
          // egress  = the port on this node facing the next hop.
          const ingress = prevEdge
            ? prevEdge.target === id
              ? prevEdge.target_port
              : prevEdge.source_port
            : undefined;
          const egress = nextEdge
            ? nextEdge.source === id
              ? nextEdge.source_port
              : nextEdge.target_port
            : undefined;

          const decision = node?.tags?.decision;

          return (
            <li
              key={id}
              style={{
                display: "flex",
                gap: 10,
                padding: "8px 10px",
                border: "1px solid var(--border)",
                borderRadius: 6,
                background: "var(--surface)",
                alignItems: "flex-start",
              }}
            >
              <span
                style={{
                  flex: "0 0 auto",
                  width: 22,
                  height: 22,
                  borderRadius: "50%",
                  background: "var(--panel)",
                  border: "1px solid var(--border)",
                  color: "var(--fg)",
                  fontSize: 11,
                  fontWeight: 700,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontFamily: "var(--font-mono, ui-monospace, monospace)",
                }}
              >
                {i + 1}
              </span>

              <div style={{ minWidth: 0, flex: 1 }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: "var(--fg)" }}>
                  {node?.label ?? id}
                </div>

                <div
                  style={{
                    fontSize: 11,
                    color: "var(--fg-muted)",
                    marginTop: 2,
                    fontFamily: "var(--font-mono, ui-monospace, monospace)",
                  }}
                >
                  {ingress ? `in ${ingress}` : i === 0 ? "ingress" : "in —"}
                  {"  ·  "}
                  {egress ? `out ${egress}` : i === path.length - 1 ? "egress" : "out —"}
                </div>

                {decision ? (
                  <div style={{ fontSize: 11, color: "var(--fg-subtle)", marginTop: 3 }}>
                    {decision}
                  </div>
                ) : null}
              </div>
            </li>
          );
        })}
      </ol>

      <div
        style={{
          fontSize: 11,
          color: "var(--fg-subtle)",
          marginTop: 10,
          opacity: 0.7,
          fontStyle: "italic",
        }}
      >
        Golden path: matches (Phase 6)
      </div>
    </section>
  );
}
