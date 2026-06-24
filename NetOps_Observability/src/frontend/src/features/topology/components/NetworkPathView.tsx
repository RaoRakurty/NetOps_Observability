// NetworkPathView — the DEDICATED source→destination path view (#77 design doc:
// "NetworkPathView (L→R src→dst)"). Where the generic TopologyCanvas drops the
// operator into the FULL topology with the path merely highlighted (noisy), this
// renders ONLY the resolved path as a clean left-to-right ribbon: endpoints, every
// hop as a glossy shaped node (the shared shape kit, distinct from the canvas
// cards), and the connecting links coloured by measured load / status / RCA verdict.
//
// HONESTY (CLAUDE.md + path-provenance guard): a COMPUTED path is an IGP shortest-
// path INFERENCE, not an observed forwarding path — the header says so prominently
// and the word "traced" is never used for a computed path. The instrumented hop
// ladder (PathAnalysisPanel) rides alongside as the detail rail, reused unchanged.
//
// Pure render — no business logic, no fetching. The parent (TopologyCanvas) resolves
// the path and the empty/resolving/no-path states; this only draws a resolved path.

import { useMemo } from "react";
import type { TopologyView, TopologyNode, TopologyEdge, RcaOverlayState } from "../api/topologyTypes";
import { HEALTH_COLOR, HEALTH_LABEL } from "../utils/topologyHealth";
import { RCA_OVERLAY } from "../utils/rcaOverlay";
import { ShapeSVG, kindForRole, type ShapeKind } from "../../../components/graph/shapes";
import PathAnalysisPanel from "./PathAnalysisPanel";

const MONO = "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace";

/** A node is an unresolved/external boundary when discovery never managed it. */
function isBoundary(n: TopologyNode | undefined, id: string): boolean {
  return (!n || n.kind === "unresolved" || n.kind === "cloud") || id.startsWith("ext:");
}

/** Map a topology node to one of the shared shape kit's shapes (hero glyphs). */
function shapeFor(n: TopologyNode | undefined, id: string): ShapeKind {
  if (isBoundary(n, id)) return "cloud";
  if (!n) return "switch";
  if (n.kind === "load_balancer" || n.kind === "wan") return "gateway";
  return kindForRole(n.role || n.kind);
}

/** A visible RCA verdict (non-internal) supersedes plain health as the node tone. */
function rcaVisible(state: RcaOverlayState | undefined) {
  if (!state) return undefined;
  const s = RCA_OVERLAY[state];
  return s.customerHidden ? undefined : s;
}

/** Node tone: the engine's grounded verdict if present, else the health colour. */
function toneFor(n: TopologyNode | undefined): string {
  const rca = rcaVisible(n?.rca_status);
  if (rca) return rca.color;
  return HEALTH_COLOR[n?.health ?? "unknown"];
}

/** A fault node breathes (pulse ring) — confirmed/suspected RCA, or critical health. */
function pulseFor(n: TopologyNode | undefined): boolean {
  const r = n?.rca_status;
  if (r === "confirmed_down" || r === "suspected_down") return true;
  return n?.health === "critical";
}

function edgeBetween(edges: TopologyEdge[], a: string, b: string): TopologyEdge | undefined {
  return edges.find((e) => (e.source === a && e.target === b) || (e.source === b && e.target === a));
}

/** A hop's STAMP active-measurement metrics, read from node.metrics (backend attaches
 *  stamp_* keys for hops a probe reaches; absent → honest "—"). */
type HopStamp = { rtt?: number; pdv?: number; owd?: number; loss?: number; has: boolean };
function hopStamp(n: TopologyNode | undefined): HopStamp {
  const m = n?.metrics;
  const num = (k: string): number | undefined => {
    const v = m?.[k];
    return typeof v === "number" ? v : undefined;
  };
  const rtt = num("stamp_rtt_ms"), pdv = num("stamp_pdv_ms"), owd = num("stamp_owd_ms"), loss = num("stamp_loss_pct");
  return { rtt, pdv, owd, loss, has: rtt != null || pdv != null || owd != null || loss != null };
}
/** Format a millisecond value compactly: sub-ms as µs, else 1-decimal ms. */
function fmtMs(v: number): string {
  if (v < 1) return `${Math.round(v * 1000)} µs`;
  return `${v.toFixed(v < 10 ? 1 : 0)} ms`;
}
/** A hop's end-to-end latency for segment-delta math: prefer one-way delay (OWD),
 *  fall back to RTT. The DIFFERENCE between two consecutive hops' values is that
 *  segment's added latency — an honest derivation of "where the delay enters". */
function segLatencyOf(st: HopStamp): number | undefined {
  return st.owd ?? st.rtt;
}

/** Utilisation → calm-under-load → hot-near-saturation band (mirrors the hop ladder). */
function utilColor(u: number): string {
  if (u >= 85) return "var(--crit, #e5484d)";
  if (u >= 70) return "var(--warn, #f5a524)";
  return "var(--fg-muted)";
}

type SegStyle = { color: string; dash?: string; flow: boolean; meta: string };

/** The connecting link's visual: RCA verdict wins, else measured status/load. */
function segStyle(e: TopologyEdge | undefined): SegStyle {
  const rca = rcaVisible(e?.rca_status);
  if (rca) {
    return { color: rca.color, dash: rca.dash, flow: rca.animate, meta: rca.label };
  }
  if (e?.status === "down" || e?.status === "degraded") {
    return { color: "var(--crit, #e5484d)", dash: "7 4", flow: false, meta: `link ${e.status}` };
  }
  const u = e?.utilization_pct;
  if (u != null) return { color: utilColor(u), flow: false, meta: `${Math.round(u)}% util` };
  return { color: "var(--border)", dash: "2 4", flow: false, meta: "load unmeasured" };
}

export default function NetworkPathView({ view }: { view: TopologyView }) {
  const path = view.path ?? [];
  const byId = useMemo(() => new Map(view.nodes.map((n) => [n.id, n])), [view.nodes]);

  // Bottleneck = a down/degraded link if any, else the busiest measured link ≥ 70%
  // (same rule as the hop ladder so the ribbon and the rail agree on the culprit).
  const bottleneckIdx = useMemo(() => {
    let downIdx = -1, worstIdx = -1, worst = -1;
    for (let i = 0; i < path.length - 1; i++) {
      const e = edgeBetween(view.edges, path[i], path[i + 1]);
      if (e && (e.status === "down" || e.status === "degraded") && downIdx < 0) downIdx = i;
      const u = e?.utilization_pct;
      if (u != null && u > worst) { worst = u; worstIdx = i; }
    }
    return downIdx >= 0 ? downIdx : worst >= 70 ? worstIdx : -1;
  }, [path, view.edges]);

  // Does ANY hop carry a STAMP measurement? Drives the honest path-level footnote
  // (a wall of "—" reads as broken; one note explains it instead).
  const anyStamp = useMemo(
    () => path.some((id) => hopStamp(byId.get(id)).has),
    [path, byId],
  );

  // Per-segment added latency = downstream hop's e2e latency − upstream's, where BOTH
  // hops are STAMP-measured. The segment that adds the most is the latency culprit
  // (the fault-isolation answer: "the delay enters between spine2 and wan-r2"). null
  // where either endpoint is unmeasured — never inferred.
  const segDelay = useMemo<(number | null)[]>(() => {
    const out: (number | null)[] = [];
    for (let i = 0; i < path.length - 1; i++) {
      const up = segLatencyOf(hopStamp(byId.get(path[i])));
      const dn = segLatencyOf(hopStamp(byId.get(path[i + 1])));
      out.push(up != null && dn != null ? Math.max(0, dn - up) : null);
    }
    return out;
  }, [path, byId]);
  const worstDelayIdx = useMemo(() => {
    let idx = -1, worst = -1;
    segDelay.forEach((d, i) => { if (d != null && d > worst) { worst = d; idx = i; } });
    return worst > 0 ? idx : -1; // only flag a real positive delta
  }, [segDelay]);

  if (path.length < 2) return null; // parent owns the no-path/resolving/empty states

  const srcN = byId.get(path[0]);
  const dstN = byId.get(path[path.length - 1]);
  const measured = view.path_source === "measured";
  const provenance = view.path_source
    ? measured
      ? { label: "Measured · live traceroute", color: "var(--ok, #30a46c)" }
      : { label: "Computed · inferred shortest path (not a live trace)", color: "var(--warn, #f5a524)" }
    : null;

  return (
    <div className="netpath">
      <div className="netpath-main">
        <header className="netpath-head">
          <div>
            <div className="netpath-title">Network Path</div>
            <div className="netpath-route" style={{ fontFamily: MONO }}>
              {srcN?.label ?? path[0]} <span className="netpath-route-arrow" aria-hidden="true">→</span>{" "}
              {dstN?.label ?? path[path.length - 1]}
              <span className="netpath-route-hops"> · {path.length} hops</span>
            </div>
          </div>
          {provenance && (
            <span
              className="netpath-prov"
              style={{ color: provenance.color, borderColor: provenance.color,
                background: `color-mix(in srgb, ${provenance.color} 10%, transparent)` }}
              title={measured
                ? "Hops observed by an active traceroute/probe — ground truth."
                : "Derived from the IGP-weighted topology (shortest path), not an observed forwarding path. Run a traceroute to confirm."}
            >
              {provenance.label}
            </span>
          )}
        </header>

        <div className="netpath-ribbon" role="list" aria-label="Network path, source to destination">
          {path.map((id, i) => {
            const n = byId.get(id);
            const tone = toneFor(n);
            const rca = rcaVisible(n?.rca_status);
            const isSrc = i === 0;
            const isDst = i === path.length - 1;
            const endpointTag = isSrc ? "Source" : isDst ? "Destination" : null;
            const stateLabel = rca ? rca.label : HEALTH_LABEL[n?.health ?? "unknown"];
            const st = hopStamp(n);

            // The connector to the NEXT hop (drawn to the right of this node).
            const nextEdge = i < path.length - 1 ? edgeBetween(view.edges, id, path[i + 1]) : undefined;
            const seg = nextEdge !== undefined || !isDst ? segStyle(nextEdge) : null;
            const egress = nextEdge ? (nextEdge.source === id ? nextEdge.source_port : nextEdge.target_port) : undefined;
            const ingress = nextEdge ? (nextEdge.target === path[i + 1] ? nextEdge.target_port : nextEdge.source_port) : undefined;
            const isBottleneck = i === bottleneckIdx;

            return (
              <div className="netpath-seg" key={id}>
                <div className="netpath-node" role="listitem"
                  aria-label={`Hop ${i + 1}: ${n?.label ?? id}, ${stateLabel}${endpointTag ? `, ${endpointTag}` : ""}`}>
                  {endpointTag && (
                    <span className="netpath-endpoint" style={{ color: tone, borderColor: tone }}>{endpointTag}</span>
                  )}
                  <div className="netpath-glyph">
                    <ShapeSVG kind={shapeFor(n, id)} tone={tone} size={56} pulse={pulseFor(n)} />
                    <span className="netpath-hopno" style={{ borderColor: tone, color: "var(--fg)" }}>{i + 1}</span>
                    {(rca || n) && (
                      <span className="netpath-mark"
                        title={stateLabel} aria-hidden="true"
                        style={{ color: tone, borderColor: tone,
                          borderStyle: rca?.hollow ? "dashed" : "solid",
                          background: rca?.hollow ? "transparent" : `color-mix(in srgb, ${tone} 16%, transparent)` }}>
                        {rca?.hollow ? "" : (rca?.glyph ?? "")}
                      </span>
                    )}
                  </div>
                  <div className="netpath-label" title={n?.label ?? id}>{n?.label ?? id}</div>
                  <div className="netpath-sub" style={{ color: tone }}>{stateLabel}</div>

                  {/* Per-hop STAMP active-measurement: latency / jitter / delay / loss
                      to this hop. Honest "—" when no probe reaches the hop. */}
                  <div className="netpath-stamp" aria-label="STAMP metrics for this hop">
                    {st.has ? (
                      <>
                        {st.rtt != null && (
                          <span title="STAMP latency to this hop (RTT, p95 over 5m)">
                            <b>{fmtMs(st.rtt)}</b> lat
                          </span>
                        )}
                        {st.pdv != null && (
                          <span title="STAMP jitter to this hop (PDV, p95 over 5m)">
                            <b>{fmtMs(st.pdv)}</b> jit
                          </span>
                        )}
                        {st.owd != null && (
                          <span title="STAMP one-way delay to this hop (OWD, p95 over 5m)">
                            <b>{fmtMs(st.owd)}</b> delay
                          </span>
                        )}
                        {st.loss != null && (
                          <span title="STAMP packet loss to this hop (avg over 5m)"
                            style={{ color: st.loss >= 1 ? "var(--crit, #e5484d)" : undefined }}>
                            <b>{st.loss.toFixed(st.loss < 1 ? 2 : 1)}%</b> loss
                          </span>
                        )}
                      </>
                    ) : (
                      <span className="netpath-stamp-none" title="No active STAMP/probe reaches this hop yet">— no probe</span>
                    )}
                  </div>
                </div>

                {!isDst && seg && (
                  <div className="netpath-link" role="listitem"
                    aria-label={`Link to ${byId.get(path[i + 1])?.label ?? path[i + 1]}: ${seg.meta}`}>
                    <svg className="netpath-link-svg" width="100%" height="18" viewBox="0 0 100 18" preserveAspectRatio="none">
                      <line x1="0" y1="9" x2="92" y2="9" stroke={seg.color} strokeWidth={isBottleneck ? 3.2 : 2.2}
                        strokeDasharray={seg.dash}
                        className={seg.flow ? "topo-rca-edge-flow" : undefined} />
                      <path d="M92 9 L84 5 L84 13 Z" fill={seg.color} />
                    </svg>
                    <div className="netpath-link-meta" style={{ color: isBottleneck ? "var(--warn)" : seg.color, fontFamily: MONO }}>
                      {isBottleneck && <span className="netpath-bottleneck" title="Likely bottleneck on this path">bottleneck · </span>}
                      {seg.meta}
                    </div>
                    {(egress || ingress) && (
                      <div className="netpath-link-ports" style={{ fontFamily: MONO }}>
                        {egress ? `out ${egress}` : "out —"} <span aria-hidden="true">→</span> {ingress ? `in ${ingress}` : "in —"}
                      </div>
                    )}
                    {/* Per-segment added latency (STAMP delta between the two hops) — the
                        segment that adds the most is the latency culprit. */}
                    {segDelay[i] != null && (
                      <div className={`netpath-seg-delay${i === worstDelayIdx ? " worst" : ""}`}
                        style={{ fontFamily: MONO }}
                        title={i === worstDelayIdx
                          ? "This segment adds the most latency on the path (STAMP delta)"
                          : "Latency this segment adds (downstream STAMP − upstream STAMP)"}>
                        +{fmtMs(segDelay[i] as number)} {i === worstDelayIdx ? "⤴ most delay" : "added"}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {!anyStamp && (
          <div className="netpath-stamp-foot" role="note">
            Per-hop latency / jitter / delay appear here from STAMP active probes. No probe
            currently targets the hops on this path — add a STAMP target per hop to light them up.
          </div>
        )}
      </div>

      <aside className="netpath-rail" aria-label="Per-hop path detail">
        <PathAnalysisPanel view={view} />
      </aside>
    </div>
  );
}
