// PathAnalysisPanel — renders an A→B path as an instrumented hop ladder. The path
// may be MEASURED (traceroute ground truth) or COMPUTED (an IGP shortest-path
// inference); a provenance chip states which so a computed proxy is never read as a
// live trace (honesty guard).
// Each hop shows the device, a per-hop HEALTH band, the ingress/egress interfaces,
// and the hop edge's interface facts (bandwidth / throughput / reliability / MTU,
// #85 — measured value or an honest "—" with a provenance tooltip); between hops
// it shows the connecting LINK's utilization + status,
// and the worst hop/link on the path is flagged as the likely bottleneck. Per-hop
// active-measurement (loss/latency/jitter) is end-to-end today, not per-segment —
// so we show what we honestly have (device health + measured link load) rather
// than fabricate per-hop probe numbers. Golden-path delta is honest until wired.

import type React from "react";
import type { TopologyView, TopologyNode, TopologyEdge, RcaOverlayState } from "../api/topologyTypes";
import { fmtMbps } from "../utils/pathFormat";
import AskIris from "../../../components/AskIris";

const MONO = "var(--font-mono, ui-monospace, monospace)";

// Hop → evidence link (Increment 5): when an investigated path crosses a hop the
// RCA engine has implicated, say so on the hop — connecting the path to the verdict.
// Only fault roles get a tag; "observed"/internal never fabricate a root cause.
type RootCauseTag = { text: string; color: string; glyph: string };
const ROOT_CAUSE: Partial<Record<RcaOverlayState, RootCauseTag>> = {
  confirmed_down: { text: "Confirmed root cause", color: "#dc2626", glyph: "✕" },
  suspected_down: { text: "Where evidence points · suspected", color: "#dc2626", glyph: "⚠" },
  degraded: { text: "Degraded on this hop", color: "#d97706", glyph: "!" },
  missing_evidence: { text: "Needs evidence here", color: "#64748b", glyph: "○" },
  insufficient_visibility: { text: "Limited visibility here", color: "#64748b", glyph: "?" },
};
const rootCauseTag = (rca: RcaOverlayState | undefined): RootCauseTag | null =>
  (rca && ROOT_CAUSE[rca]) || null;

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
  fontSize: 12.5, fontWeight: 600, letterSpacing: 0.2,
  color: "var(--fg-subtle)", marginBottom: 10,
};

export default function PathAnalysisPanel({ view }: { view: TopologyView }) {
  const path = view.path ?? [];

  if (path.length === 0) {
    return (
      <div style={{ fontSize: 12.5, color: "var(--fg-muted)", padding: 12, border: "1px dashed var(--border)", borderRadius: 6, background: "var(--surface)" }}>
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
      ? { label: "Measured", topic: "path.measured", color: "var(--ok, #30a46c)" }
      : { label: "Computed · not a live trace", topic: "path.computed", color: "var(--warn, #f5a524)" }
    : null;

  return (
    <section>
      <div style={SECTION}>Path · {path.length} hops</div>

      {provenance && (
        <div
          title={measured ? "Every hop was observed by a probe" : "Derived from the topology, not observed"}
          style={{ fontSize: 12.5, fontWeight: 600, color: provenance.color, marginBottom: 8,
            padding: "4px 8px", border: `1px solid ${provenance.color}`, borderRadius: 5,
            background: `color-mix(in srgb, ${provenance.color} 10%, transparent)`,
            display: "inline-flex", alignItems: "center", gap: 4 }}
        >
          {provenance.label}
          <AskIris topic={provenance.topic} label={provenance.label} />
        </div>
      )}

      {bottleneckIdx >= 0 && (
        <div style={{ fontSize: 12.5, fontWeight: 600, color: "var(--warn)", marginBottom: 8,
          padding: "5px 8px", border: "1px solid var(--warn)", borderRadius: 5,
          background: "color-mix(in srgb, var(--warn) 10%, transparent)" }}>
          Likely bottleneck: {byId.get(path[bottleneckIdx])?.label ?? path[bottleneckIdx]} →{" "}
          {byId.get(path[bottleneckIdx + 1])?.label ?? path[bottleneckIdx + 1]}
          {downIdx >= 0 ? " (link down/degraded)" : ` (${Math.round(worstUtil)}% utilized)`}
          <AskIris topic="path.bottleneck" label="Likely bottleneck" />
        </div>
      )}

      <ol style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 0 }}>
        {path.map((id, i) => {
          const node = byId.get(id);
          const prevEdge = i > 0 ? edgeBetween(view.edges, path[i - 1], id) : undefined;
          const nextEdge = i < path.length - 1 ? edgeBetween(view.edges, id, path[i + 1]) : undefined;
          const ingress = prevEdge ? (prevEdge.target === id ? prevEdge.target_port : prevEdge.source_port) : undefined;
          const egress = nextEdge ? (nextEdge.source === id ? nextEdge.source_port : nextEdge.target_port) : undefined;
          // #85 — interface facts on the hop's edge (egress preferred, ingress
          // fallback — same per-metric join the ribbon's hop detail uses). Honesty:
          // a measured value or "—" with a provenance tooltip, never a fabrication.
          const em = (k: "bandwidth_mbps" | "throughput_mbps" | "reliability_pct" | "mtu") =>
            nextEdge?.[k] ?? prevEdge?.[k];
          const bw = em("bandwidth_mbps"), thr = em("throughput_mbps");
          const rel = em("reliability_pct"), mtu = em("mtu");
          const decision = node?.tags?.decision;
          // Hop → evidence link: a fault role recolours the hop's rail to the verdict
          // colour, so the path itself shows WHERE the root cause sits.
          const rc = rootCauseTag(node?.rca_status);
          const band = rc?.color ?? healthColor(node?.health);

          // The link to the NEXT hop (rendered as a connector below this hop).
          const linkE = i < path.length - 1 ? links[i] : undefined;
          const linkUtil = linkE?.utilization_pct;
          const isBottleneck = i === bottleneckIdx;

          return (
            <li key={id}>
              <div style={{ display: "flex", gap: 10, padding: "8px 10px", border: "1px solid var(--border)",
                borderLeft: `3px solid ${band}`, borderRadius: 6, background: "var(--surface)", alignItems: "flex-start" }}>
                <span style={{ flex: "0 0 auto", width: 22, height: 22, borderRadius: "50%", background: "var(--panel)",
                  border: `1px solid ${band}`, color: "var(--fg)", fontSize: 12.5, fontWeight: 700,
                  display: "flex", alignItems: "center", justifyContent: "center", fontFamily: MONO }}>
                  {i + 1}
                </span>
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div style={{ display: "flex", alignItems: "baseline", gap: 7 }}>
                    <span style={{ fontSize: 12.5, fontWeight: 600, color: "var(--fg)" }}>{node?.label ?? id}</span>
                    <span style={{ fontSize: 12.5, fontWeight: 600, color: band, textTransform: "capitalize" }}>
                      {node?.health ?? "unknown"}
                    </span>
                  </div>
                  <div style={{ fontSize: 12.5, color: "var(--fg-muted)", marginTop: 2, fontFamily: MONO }}>
                    {ingress ? `in ${ingress}` : i === 0 ? "ingress" : "in —"}
                    {"  ·  "}
                    {egress ? `out ${egress}` : i === path.length - 1 ? "egress" : "out —"}
                  </div>
                  {/* #85 hop-edge interface facts: bandwidth / throughput / reliability / MTU. */}
                  <div style={{ fontSize: 12.5, color: "var(--fg-subtle)", marginTop: 2, fontFamily: MONO, display: "flex", flexWrap: "wrap", alignItems: "center", gap: 2 }}>
                    <span title={bw != null ? "Interface link speed" : "No link-speed series for this interface"}>
                      {`bw ${bw != null ? fmtMbps(bw) : "—"}`}
                    </span>
                    {"  ·  "}
                    <span title={thr != null ? "Measured interface throughput" : "No throughput series for this interface"}>
                      {`thr ${thr != null ? fmtMbps(thr) : "—"}`}
                    </span>
                    {"  ·  "}
                    <span title={rel != null ? "Up time against error-free traffic" : "No reliability series for this interface"}>
                      {`rel ${rel != null ? `${rel.toFixed(2)}%` : "—"}`}
                    </span>
                    {"  ·  "}
                    <span title={mtu != null ? "Interface MTU" : "Not in the collection profile yet"}>
                      {`mtu ${mtu != null ? `${Math.round(mtu)} B` : "—"}`}
                    </span>
                    <AskIris topic="path.hop-interface" label="Hop interface facts" />
                  </div>
                  {rc && (
                    <div style={{ display: "inline-flex", alignItems: "center", gap: 5, marginTop: 4,
                      fontSize: 12.5, fontWeight: 700, color: rc.color, border: `1px solid ${rc.color}`,
                      borderRadius: 4, padding: "1px 6px",
                      background: `color-mix(in srgb, ${rc.color} 12%, transparent)` }}
                      title="This hop is part of the incident's RCA">
                      <span aria-hidden="true">{rc.glyph}</span>{rc.text}
                    </div>
                  )}
                  {decision ? <div style={{ fontSize: 12.5, color: "var(--fg-subtle)", marginTop: 3 }}>{decision}</div> : null}
                </div>
              </div>

              {/* Inter-hop link connector: measured utilization + status. */}
              {i < path.length - 1 && (
                <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "3px 0 3px 21px" }}>
                  <span style={{ width: 2, height: 16, background: isBottleneck ? "var(--warn)" : "var(--border)" }} />
                  <span style={{ fontSize: 12.5, fontFamily: MONO,
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

      <div style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 12.5, color: "var(--fg-subtle)", marginTop: 10 }}>
        Golden path: not configured
        <AskIris topic="path.golden" label="Golden path" />
      </div>
    </section>
  );
}
