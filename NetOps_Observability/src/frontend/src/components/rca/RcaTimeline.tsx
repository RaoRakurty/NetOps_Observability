import { useMemo, useState } from "react";
import { CorrSignal, CorrTimeline } from "../../services/api";
import { C, MODALITY_META, PROBE_AUTHORITY_META, probeScopeLabel, probeAuthorityLabel, entityLabel, kindLabel, modalityLabel, isRoutingKind, nocUnlinkedReason } from "./labels";

// RcaTimeline — the PRIMARY RCA Inspector view. Cross-plane cascade over time:
// one swimlane per modality, each signal plotted at its onset (ts) with an
// uncertainty bar (onset_uncertainty_s, widened by clock_quality). It answers:
// what happened first/next (left→right), which planes agree (lanes lighting up
// together), which signals contradict (role ring), what the engine attached vs
// ignored (solid vs hollow), and how certain the timing is (bar width / overlap).
// It visualizes engine-recorded values only — never re-derives causality.

const LANES: { key: string; label: string; color: string; noun: string }[] = [
  { key: "device_telemetry", label: MODALITY_META.device_telemetry.label, color: MODALITY_META.device_telemetry.color, noun: "signals" },
  { key: "control_plane", label: MODALITY_META.control_plane.label, color: MODALITY_META.control_plane.color, noun: "events" },
  { key: "passive_flow", label: MODALITY_META.passive_flow.label, color: MODALITY_META.passive_flow.color, noun: "flow signals" },
  { key: "active_probe", label: MODALITY_META.active_probe.label, color: MODALITY_META.active_probe.color, noun: "checks" },
  { key: "_other", label: "Other", color: C.faint, noun: "signals" },
];

const ROLE_COLOR: Record<string, string> = {
  supports: C.ok,
  contradicts: C.crit,
  discriminates: C.discriminates,
};

// Linkage status → color + glyph (mirrors the backend's per-signal taxonomy).
export const STATUS_COLOR: Record<string, string> = {
  attached: C.ok,
  recovery: C.faint,
  unlinked: C.warn,
  malformed: C.crit,
};

function statusLabel(s: CorrSignal): string {
  switch (s.link_status) {
    case "attached": return `● attached / ${s.link_role || "supporting"}`;
    case "recovery": return "○ recovery / clear";
    case "malformed": return "△ malformed identity";
    default: return "○ concurrent — not linked";
  }
}

// Operator (NOC) status phrase — no engine vocabulary.
function nocStatus(s: CorrSignal): string {
  if (s.probe_authority === "debug_only") return "Test check — ignored";
  if (s.attached) return `Used as ${s.link_role || "supporting"} evidence`;
  if (s.link_status === "recovery") return "Recovery / clear";
  if (s.link_status === "malformed") return "Not usable — missing identity";
  return "Not linked to this issue";
}

// clock_quality → minimum uncertainty floor (seconds) for point events that
// carry no CUSUM onset_uncertainty_s. Honest: a free-running clock can't claim
// sub-second ordering.
const CLOCK_FLOOR_S: Record<string, number> = {
  ntp: 0.05,
  ptp: 0.001,
  free_running: 2,
  unknown: 1,
};

const toMs = (s?: string): number => {
  if (!s) return NaN;
  const t = Date.parse(s.replace(" ", "T") + "Z");
  return isNaN(t) ? Date.parse(s) : t;
};

// Which lane a signal is drawn on. Operator View places routing-protocol signals
// (e.g. a polled BGP state metric) on the "Routing & link events" lane — that's
// where a NOC looks for BGP, even when it was observed via device telemetry.
// Debug View keeps the true modality_class lane. Engine independence math is
// unaffected (it uses modality_class, never this display lane).
function laneOf(s: CorrSignal, view: "operator" | "debug"): string {
  const m = view === "operator" && isRoutingKind(s.kind) ? "control_plane" : s.modality_class;
  return LANES.some((l) => l.key === m) ? m : "_other";
}

function signalRole(sig: CorrSignal): string {
  const roles = (sig.evidence ?? []).map((e) => e.role);
  if (roles.includes("contradicts")) return "contradicts";
  if (roles.includes("supports")) return "supports";
  if (roles.includes("discriminates")) return "discriminates";
  return "";
}

function fmtAbs(ms: number): string {
  if (isNaN(ms)) return "?";
  return new Date(ms).toISOString().replace("T", " ").replace("Z", "").slice(11, 23);
}

export default function RcaTimeline({
  timeline,
  selected,
  onSelect,
  highlight,
  view = "operator",
}: {
  timeline: CorrTimeline;
  selected?: string | null;
  onSelect?: (signalId: string) => void;
  highlight?: Set<string>;
  view?: "operator" | "debug";
}) {
  const [hover, setHover] = useState<CorrSignal | null>(null);

  const t0 = toMs(timeline.window_start);
  const t1raw = toMs(timeline.window_end);
  const t1 = t1raw > t0 ? t1raw : t0 + 1000;
  const span = t1 - t0;

  const byLane = useMemo(() => {
    const m: Record<string, CorrSignal[]> = {};
    for (const l of LANES) m[l.key] = [];
    for (const s of timeline.signals) m[laneOf(s, view)].push(s);
    return m;
  }, [timeline.signals, view]);

  // Inset the plot by a small gutter so a marker at the origin (centered via
  // translate(-50%)) doesn't bleed left of the "+0.0s" column.
  const PAD = 3;
  const pct = (ms: number) => PAD + Math.max(0, Math.min(100, ((ms - t0) / span) * 100)) * (100 - 2 * PAD) / 100;

  // A few axis ticks (relative seconds from window start) — same inset scale.
  const ticks = useMemo(() => {
    const n = 5;
    return Array.from({ length: n + 1 }, (_, i) => {
      const ms = t0 + (span * i) / n;
      return { left: PAD + (i / n) * (100 - 2 * PAD), label: `+${((ms - t0) / 1000).toFixed(span > 120000 ? 0 : 1)}s` };
    });
  }, [t0, span]);

  const muted: React.CSSProperties = { color: C.muted };

  // --- marker overlap handling (item 9) ---------------------------------------
  // Important markers (trigger / high-severity) always render individually + are
  // always labeled. The rest (the noise — e.g. 28 probe flaps) get grouped by
  // time-proximity into a "N checks" cluster pill; clicking a pill expands it so
  // each member is selectable. Expanded members get a small vertical zig-zag so
  // they don't sit on top of each other.
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());
  const toggleCluster = (id: string) =>
    setExpanded((prev) => { const n = new Set(prev); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  const CLUSTER_GAP = 2.2;        // lane-% within which markers are considered "together"
  const isProminent = (s: CorrSignal) => s.is_trigger || s.severity === "crit" || s.severity === "high";

  // Render one marker (dot + uncertainty bar + optional label). offsetY shifts it
  // vertically within the lane (used to de-overlap expanded cluster members).
  const renderMarker = (s: CorrSignal, lane: { key: string; color: string }, offsetY = 0, forceLabel = false) => {
    const ms = toMs(s.ts);
    const left = pct(ms);
    const unc = s.onset_uncertainty_s > 0 ? s.onset_uncertainty_s : (CLOCK_FLOOR_S[s.clock_quality] ?? 1);
    // Onset uncertainty capsule: drawn ONLY when we have a measured onset window
    // (CUSUM onset_uncertainty_s). Point events (link up/down) carry only the
    // clock floor and get no capsule — that removes the stray "lines" that made
    // the old timeline unreadable. The capsule is a soft, rounded time-window.
    const showUnc = s.onset_uncertainty_s > 0;
    const barW = Math.max(8, (unc * 2000 / span) * 100);
    const role = signalRole(s);
    const isHi = highlight?.has(s.signal_id);
    const isSel = selected === s.signal_id;
    const isHover = hover?.signal_id === s.signal_id;
    const dim = highlight && highlight.size > 0 && !isHi;
    // Attached (used) evidence = larger solid dot; concurrent = hollow ring;
    // debug/test = muted dashed; trigger = a diamond with a soft glow (the start);
    // selected = accent ring. Severity scales size so big problems read bigger.
    const sevSz: Record<string, number> = { crit: 15, high: 13, warn: 12, info: 11 };
    const baseSz = sevSz[s.severity] ?? 12;
    const sz = s.is_trigger ? 17 : (s.attached ? baseSz + 2 : baseSz);
    const isDebugProbe = s.probe_authority === "debug_only";
    const isRecovery = s.link_status === "recovery";
    const ringColor = role ? ROLE_COLOR[role] : lane.color;
    // Labels: only the trigger, the selected, or the hovered marker — never every
    // dot. Auto-labeling every high-severity marker made labels collide; lanes +
    // colors + hover carry the rest, and a click opens full detail.
    const labeled = (forceLabel || isSel || s.is_trigger || isHover) && !dim && !s.kind.endsWith("_clear");
    return (
      <div key={s.signal_id} style={{ position: "absolute", left: `${left}%`, top: `calc(50% + ${offsetY}px)`, transform: "translate(-50%,-50%)", opacity: dim ? 0.4 : 1, zIndex: isSel || isHover ? 6 : (s.attached ? 3 : 1) }}>
        {showUnc && (
          <div style={{
            position: "absolute", top: "50%", left: "50%",
            width: `${barW}%`, minWidth: 14, maxWidth: 240, height: 11,
            transform: "translate(-50%,-50%)", borderRadius: 6,
            background: lane.color + "26", border: `1px solid ${lane.color}55`,
          }} title={`±${unc}s onset window (${s.clock_quality})`} />
        )}
        <div
          onMouseEnter={() => setHover(s)}
          onMouseLeave={() => setHover((h) => (h?.signal_id === s.signal_id ? null : h))}
          onClick={() => onSelect?.(s.signal_id)}
          title={view === "debug" ? `${s.kind} · ${s.entity_id}` : `${kindLabel(s.kind)} · ${entityLabel(s.entity_id)}`}
          style={{
            position: "relative", width: sz, height: sz,
            borderRadius: s.is_trigger ? 3 : "50%",
            transform: s.is_trigger ? "rotate(45deg)" : undefined,
            background: s.attached ? lane.color : "var(--panel)",
            border: isDebugProbe ? `2px dashed ${C.faint}` : `${s.attached ? 2.5 : 2.25}px solid ${ringColor}`,
            opacity: isDebugProbe ? 0.55 : isRecovery ? 0.6 : 1,
            boxShadow: isSel ? `0 0 0 3px var(--accent,#4c8dff)` : (s.is_trigger ? `0 0 0 4px ${lane.color}33, 0 1px 4px rgba(0,0,0,.4)` : (s.attached ? `0 1px 3px rgba(0,0,0,.35), 0 0 0 1.5px var(--panel)` : "0 0 0 1.5px var(--panel)")),
            cursor: "pointer",
          }}
        />
        {labeled && (
          <span style={{
            position: "absolute", left: sz / 2 + 5, top: "50%", transform: "translateY(-50%)",
            whiteSpace: "nowrap", fontSize: 11, lineHeight: 1, pointerEvents: "none",
            padding: "1px 4px", borderRadius: 3, zIndex: 7,
            background: "var(--panel)", border: `1px solid ${isSel ? "var(--accent,#4c8dff)" : lane.color}`,
            color: "var(--fg)", fontWeight: 700,
          }}>{kindLabel(s.kind)}{s.is_trigger ? " · trigger" : ""}</span>
        )}
      </div>
    );
  };

  return (
    <div style={{ position: "relative", border: "1px solid var(--border,#2a2f3a)", borderRadius: 8, padding: "8px 10px", overflow: "hidden" }}>
      {/* axis */}
      <div style={{ position: "relative", height: 16, marginLeft: 132, fontSize: 11.5, ...muted }}>
        {ticks.map((tk, i) => (
          <span key={i} style={{ position: "absolute", left: `${tk.left}%`, transform: "translateX(-50%)" }}>{tk.label}</span>
        ))}
      </div>
      {LANES.map((lane) => {
        const sigs = byLane[lane.key];
        if (lane.key === "_other" && sigs.length === 0) return null;
        return (
          <div key={lane.key} style={{ display: "flex", alignItems: "center", height: 40, borderTop: "1px solid var(--border,#23272f)" }}>
            <div style={{ width: 124, flexShrink: 0, fontSize: 12, position: "relative", zIndex: 2, paddingRight: 8, height: "100%", display: "flex", alignItems: "center" }}>
              <span style={{ display: "inline-block", width: 8, height: 8, borderRadius: 2, background: lane.color, marginRight: 6, flexShrink: 0 }} />
              <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{lane.label}</span>
              <span style={{ ...muted, marginLeft: 4 }}>{sigs.length}</span>
            </div>
            {/* overflow:hidden clips markers/capsules to their lane so a hop at the
                window start can't bleed left over the lane name. */}
            <div style={{ position: "relative", flex: 1, height: "100%", overflow: "hidden" }}>
              {/* time grid + centerline rail — gives the dots a frame to read
                  against instead of floating in space. */}
              {ticks.map((tk, i) => (
                <div key={`g${i}`} style={{ position: "absolute", left: `${tk.left}%`, top: 0, bottom: 0, width: 1, background: "var(--border,#23272f)", opacity: 0.5 }} />
              ))}
              <div style={{ position: "absolute", left: 0, right: 0, top: "50%", height: 1, background: lane.color, opacity: 0.16 }} />
              {(() => {
                // prominent markers always individual + labeled; cluster the rest
                // by time-proximity so dense lanes don't turn to mush.
                const prom = sigs.filter(isProminent);
                const rest = sigs.filter((s) => !isProminent(s)).sort((a, b) => toMs(a.ts) - toMs(b.ts));
                type Cl = { id: string; members: CorrSignal[]; lastX: number; cx: number };
                const clusters: Cl[] = [];
                for (const s of rest) {
                  const x = pct(toMs(s.ts));
                  const cur = clusters[clusters.length - 1];
                  if (cur && x - cur.lastX <= CLUSTER_GAP) { cur.members.push(s); cur.lastX = x; cur.cx = (cur.cx + x) / 2; }
                  else clusters.push({ id: `${lane.key}:${s.signal_id}`, members: [s], lastX: x, cx: x });
                }
                const out: React.ReactNode[] = [];
                for (const s of prom) out.push(renderMarker(s, lane));
                for (const cl of clusters) {
                  if (cl.members.length === 1) { out.push(renderMarker(cl.members[0], lane)); continue; }
                  if (expanded.has(cl.id)) {
                    // fan members vertically (zig-zag) so they de-overlap; a small
                    // pill above collapses the cluster again.
                    cl.members.forEach((m, i) => out.push(renderMarker(m, lane, ((i % 3) - 1) * 11)));
                    out.push(
                      <div key={`${cl.id}-collapse`} onClick={() => toggleCluster(cl.id)}
                        style={{ position: "absolute", left: `${cl.cx}%`, top: -2, transform: "translateX(-50%)", cursor: "pointer", zIndex: 8,
                          fontSize: 10, fontWeight: 700, padding: "0 5px", borderRadius: 8, whiteSpace: "nowrap",
                          background: "var(--panel)", border: `1px solid ${lane.color}`, color: lane.color }}>
                        {cl.members.length} · collapse ▴
                      </div>,
                    );
                    continue;
                  }
                  // collapsed cluster pill: "N checks"
                  const anyAttached = cl.members.some((m) => m.attached);
                  out.push(
                    <div key={cl.id} onClick={() => toggleCluster(cl.id)}
                      onMouseEnter={() => setHover(cl.members[0])}
                      onMouseLeave={() => setHover((h) => (cl.members.includes(h as CorrSignal) ? null : h))}
                      title={`${cl.members.length} ${lane.label.toLowerCase()} — click to expand`}
                      style={{ position: "absolute", left: `${cl.cx}%`, top: "50%", transform: "translate(-50%,-50%)", cursor: "pointer", zIndex: 2,
                        fontSize: 10.5, fontWeight: 700, padding: "1px 7px", borderRadius: 9, whiteSpace: "nowrap",
                        background: anyAttached ? lane.color : "var(--panel)",
                        border: `1.5px solid ${lane.color}`, color: anyAttached ? "#fff" : lane.color,
                        boxShadow: "0 0 0 1px var(--panel)" }}>
                      {cl.members.length} {lane.noun}
                    </div>,
                  );
                }
                return out;
              })()}
            </div>
          </div>
        );
      })}

      {/* legend — NOC wording in Operator, engine terms in Debug */}
      <div style={{ display: "flex", gap: 14, marginTop: 8, fontSize: 11.5, flexWrap: "wrap", ...muted }}>
        {view === "debug" ? (
          <>
            <span><b style={{ color: "var(--fg,#e6edf3)" }}>◆</b> trigger</span>
            <span>● filled = attached · ○ hollow = concurrent, engine did not link</span>
            <span style={{ color: ROLE_COLOR.supports }}>ring: supports</span>
            <span style={{ color: ROLE_COLOR.contradicts }}>contradicts</span>
            <span style={{ color: ROLE_COLOR.discriminates }}>discriminates</span>
            <span>bar = timing uncertainty (overlap ⇒ order not certain)</span>
          </>
        ) : (
          <>
            <span><b style={{ color: "var(--fg,#e6edf3)" }}>◆</b> first/strongest sign</span>
            <span>● filled = counted as evidence · ○ hollow = seen but not related</span>
            <span style={{ color: ROLE_COLOR.contradicts }}>red ring = conflicting</span>
            <span>“N checks” pill = several close together — click to expand</span>
            <span>bar = timing certainty (overlap ⇒ order not certain)</span>
          </>
        )}
      </div>

      {hover && (
        <div style={{
          position: "absolute", right: 10, top: 6, zIndex: 9, maxWidth: 320,
          background: "var(--panel,#161b22)", border: "1px solid var(--border,#2a2f3a)",
          borderRadius: 6, padding: "6px 8px", fontSize: 12,
          fontFamily: view === "debug" ? "ui-monospace,monospace" : "inherit",
          boxShadow: "0 4px 16px rgba(0,0,0,.4)",
        }}>
          {view === "debug" ? (
            <>
              <div style={{ fontWeight: 600 }}>{hover.kind} {hover.is_trigger ? "· TRIGGER" : ""}</div>
              <div style={muted}>{hover.entity_id}</div>
              <div>{hover.modality_class} · {hover.source} · sev {hover.severity}</div>
              <div>onset {fmtAbs(toMs(hover.ts))} ±{(hover.onset_uncertainty_s > 0 ? hover.onset_uncertainty_s : (CLOCK_FLOOR_S[hover.clock_quality] ?? 1))}s ({hover.clock_quality})</div>
              {hover.metric_name && <div>{hover.metric_name} = {hover.value}{hover.deviation ? ` (${Number(hover.deviation).toFixed(1)}σ)` : ""}</div>}
              {hover.clear_ts && <div style={muted}>clears {hover.clear_ts}</div>}
              {hover.modality_class === "active_probe" && hover.probe_authority && (
                <div style={{ color: PROBE_AUTHORITY_META[hover.probe_authority]?.color ?? C.muted }}>
                  probe: {probeScopeLabel(hover.probe_scope)} · {probeAuthorityLabel(hover.probe_authority)}
                </div>
              )}
              <div style={{ marginTop: 3, paddingTop: 3, borderTop: "1px solid var(--border,#2a2f3a)", color: STATUS_COLOR[hover.link_status] ?? "#d29922" }}>
                <b>{statusLabel(hover)}</b> — <span style={{ color: "var(--fg,#e6edf3)" }}>{hover.link_reason}</span>
                {(hover.linked_edges ?? []).length > 0 && (
                  <div style={{ ...muted, marginTop: 2 }}>
                    {(hover.linked_edges ?? []).map((e, i) => (
                      <div key={i}>↔ {e.peer.split(":").slice(1, -1).join(":")} [{e.grounding_kind}:{e.grounding_ref}] w={Number(e.weight).toFixed(2)}</div>
                    ))}
                  </div>
                )}
              </div>
            </>
          ) : (
            <>
              <div style={{ fontWeight: 700 }}>{kindLabel(hover.kind)} {hover.is_trigger ? "· trigger" : ""}</div>
              <div style={muted}>{entityLabel(hover.entity_id)}</div>
              <div>{modalityLabel(hover.modality_class)} · {fmtAbs(toMs(hover.ts)).slice(0, 8)}</div>
              <div style={{ marginTop: 3, paddingTop: 3, borderTop: "1px solid var(--border,#2a2f3a)", color: STATUS_COLOR[hover.link_status] ?? "#d29922", fontWeight: 700 }}>
                {nocStatus(hover)}
              </div>
              {/* operator-safe reason a signal was NOT tied to this issue (item 4) */}
              {!hover.attached && nocUnlinkedReason(hover) && (
                <div style={{ ...muted, marginTop: 2, fontSize: 11, lineHeight: 1.4 }}>{nocUnlinkedReason(hover)}</div>
              )}
              <div style={{ ...muted, marginTop: 1, fontSize: 11 }}>Click for details</div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
