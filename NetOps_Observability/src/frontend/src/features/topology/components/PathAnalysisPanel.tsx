// PathAnalysisPanel — renders an A→B path as an instrumented hop ladder. The path
// may be MEASURED (traceroute ground truth) or COMPUTED (an IGP shortest-path
// inference); a provenance chip states which so a computed proxy is never read as a
// live trace (honesty guard).
// Each hop shows the device, a per-hop HEALTH band, and the ingress/egress
// interfaces; between hops it shows the connecting LINK's utilization + status,
// and the worst hop/link on the path is flagged as the likely bottleneck. Per-hop
// active-measurement (loss/latency/jitter) is end-to-end today, not per-segment —
// so we show what we honestly have (device health + measured link load) rather
// than fabricate per-hop probe numbers. Golden-path delta is honest until wired.

import type React from "react";
import type { TopologyView, TopologyNode, TopologyEdge } from "../api/topologyTypes";

const MONO = "var(--font-mono, ui-monospace, monospace)";

function edgeBetween(edges: TopologyEdge[], a: string, b: string): TopologyEdge | undefined {
  return edges.find((e) => (e.source === a && e.target === b) || (e.source === b && e.target === a));
}

/** Health → band colour. Mirrors the canvas health bands. */
function healthColor(h: string | undefined): string {
  switch (h) {
    case "critical": return "var(--crit, #e5484d)";
    case "warning": return "var(--warn, #f5a524)";
    case "ok": return "var(--ok, #30a46c)";
    case "maintenance": return "var(--accent, #5b8def)";
    default: return "var(--fg-subtle)"; // unknown
  }
}

/** Utilization → colour band (calm under load, hot near saturation). */
function utilColor(u: number): string {
  if (u >= 85) return "var(--crit, #e5484d)";
  if (u >= 70) return "var(--warn, #f5a524)";
  return "var(--fg-muted)";
}

const SECTION: React.CSSProperties = {
  fontSize: 11, fontWeight: 600, letterSpacing: 0.4, textTransform: "uppercase",
  color: "var(--fg-subtle)", marginBottom: 10,
};

export default function PathAnalysisPanel({ view }: { view: TopologyView }) {
  const path = view.path ?? [];

  if (path.length === 0) {
    return (
      <div style={{ fontSize: 12, color: "var(--fg-muted)", padding: 12, border: "1px dashed var(--border)", borderRadius: 6, background: "var(--surface)" }}>
        No path selected.
      </div>
    );
  }

  const byId = new Map<string, TopologyNode>(view.nodes.map((n) => [n.id, n]));

  // Inter-hop links + their measured utilization; find the worst (bottleneck).
  const links = path.slice(1).map((id, i) => edgeBetween(view.edges, path[i], id));
  let worstLinkIdx = -1;
  let worstUtil = -1;
  let downIdx = -1;
  links.forEach((e, i) => {
    if (e && (e.status === "down" || e.status === "degraded") && downIdx < 0) downIdx = i;
    const u = e?.utilization_pct;
    if (u != null && u > worstUtil) { worstUtil = u; worstLinkIdx = i; }
  });
  // Bottleneck = a down/degraded link if any, else the busiest measured link ≥ 70%.
  const bottleneckIdx = downIdx >= 0 ? downIdx : worstUtil >= 70 ? worstLinkIdx : -1;

  // HONESTY: a "computed" path is an IGP shortest-path INFERENCE, not a live trace.
  // Surface its provenance so the operator never mistakes a proxy for a measurement.
  const measured = view.path_source === "measured";
  const provenance = view.path_source
    ? measured
      ? { label: "Measured · live traceroute", color: "var(--ok, #30a46c)" }
      : { label: "Computed · inferred shortest path (not a live trace)", color: "var(--warn, #f5a524)" }
    : null;

  return (
    <section>
      <div style={SECTION}>Path · {path.length} hops</div>

      {provenance && (
        <div
          title={
            measured
              ? "Hops observed by an active traceroute/probe — ground truth."
              : "Derived from the IGP-weighted topology (shortest path), not an observed forwarding path. Run a traceroute to confirm."
          }
          style={{ fontSize: 10.5, fontWeight: 600, color: provenance.color, marginBottom: 8,
            padding: "4px 8px", border: `1px solid ${provenance.color}`, borderRadius: 5,
            background: `color-mix(in srgb, ${provenance.color} 10%, transparent)`,
            display: "inline-block" }}
        >
          {provenance.label}
        </div>
      )}

      {bottleneckIdx >= 0 && (
        <div style={{ fontSize: 11, fontWeight: 600, color: "var(--warn)", marginBottom: 8,
          padding: "5px 8px", border: "1px solid var(--warn)", borderRadius: 5,
          background: "color-mix(in srgb, var(--warn) 10%, transparent)" }}>
          Likely bottleneck: {byId.get(path[bottleneckIdx])?.label ?? path[bottleneckIdx]} →{" "}
          {byId.get(path[bottleneckIdx + 1])?.label ?? path[bottleneckIdx + 1]}
          {downIdx >= 0 ? " (link down/degraded)" : ` (${Math.round(worstUtil)}% utilized)`}
        </div>
      )}

      <ol style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 0 }}>
        {path.map((id, i) => {
          const node = byId.get(id);
          const prevEdge = i > 0 ? edgeBetween(view.edges, path[i - 1], id) : undefined;
          const nextEdge = i < path.length - 1 ? edgeBetween(view.edges, id, path[i + 1]) : undefined;
          const ingress = prevEdge ? (prevEdge.target === id ? prevEdge.target_port : prevEdge.source_port) : undefined;
          const egress = nextEdge ? (nextEdge.source === id ? nextEdge.source_port : nextEdge.target_port) : undefined;
          const decision = node?.tags?.decision;
          const band = healthColor(node?.health);

          // The link to the NEXT hop (rendered as a connector below this hop).
          const linkE = i < path.length - 1 ? links[i] : undefined;
          const linkUtil = linkE?.utilization_pct;
          const isBottleneck = i === bottleneckIdx;

          return (
            <li key={id}>
              <div style={{ display: "flex", gap: 10, padding: "8px 10px", border: "1px solid var(--border)",
                borderLeft: `3px solid ${band}`, borderRadius: 6, background: "var(--surface)", alignItems: "flex-start" }}>
                <span style={{ flex: "0 0 auto", width: 22, height: 22, borderRadius: "50%", background: "var(--panel)",
                  border: `1px solid ${band}`, color: "var(--fg)", fontSize: 11, fontWeight: 700,
                  display: "flex", alignItems: "center", justifyContent: "center", fontFamily: MONO }}>
                  {i + 1}
                </span>
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div style={{ display: "flex", alignItems: "baseline", gap: 7 }}>
                    <span style={{ fontSize: 12, fontWeight: 600, color: "var(--fg)" }}>{node?.label ?? id}</span>
                    <span style={{ fontSize: 10, fontWeight: 600, color: band, textTransform: "capitalize" }}>
                      {node?.health ?? "unknown"}
                    </span>
                  </div>
                  <div style={{ fontSize: 11, color: "var(--fg-muted)", marginTop: 2, fontFamily: MONO }}>
                    {ingress ? `in ${ingress}` : i === 0 ? "ingress" : "in —"}
                    {"  ·  "}
                    {egress ? `out ${egress}` : i === path.length - 1 ? "egress" : "out —"}
                  </div>
                  {decision ? <div style={{ fontSize: 11, color: "var(--fg-subtle)", marginTop: 3 }}>{decision}</div> : null}
                </div>
              </div>

              {/* Inter-hop link connector: measured utilization + status. */}
              {i < path.length - 1 && (
                <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "3px 0 3px 21px" }}>
                  <span style={{ width: 2, height: 16, background: isBottleneck ? "var(--warn)" : "var(--border)" }} />
                  <span style={{ fontSize: 10, fontFamily: MONO,
                    color: linkUtil != null ? utilColor(linkUtil) : "var(--fg-subtle)" }}>
                    {linkE?.status === "down" || linkE?.status === "degraded"
                      ? `link ${linkE.status}`
                      : linkUtil != null
                        ? `${Math.round(linkUtil)}% util`
                        : "load unmeasured"}
                  </span>
                </div>
              )}
            </li>
          );
        })}
      </ol>

      <div style={{ fontSize: 11, color: "var(--fg-subtle)", marginTop: 10, fontStyle: "italic" }}>
        Golden-path comparison: not configured
      </div>
    </section>
  );
}
