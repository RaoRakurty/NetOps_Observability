import { useMemo, useState } from "react";
import { CorrSignal, CorrTimeline } from "../../services/api";
import { C, MODALITY_META, PROBE_AUTHORITY_META, probeScopeLabel, probeAuthorityLabel } from "./labels";

// RcaTimeline — the PRIMARY RCA Inspector view. Cross-plane cascade over time:
// one swimlane per modality, each signal plotted at its onset (ts) with an
// uncertainty bar (onset_uncertainty_s, widened by clock_quality). It answers:
// what happened first/next (left→right), which planes agree (lanes lighting up
// together), which signals contradict (role ring), what the engine attached vs
// ignored (solid vs hollow), and how certain the timing is (bar width / overlap).
// It visualizes engine-recorded values only — never re-derives causality.

const LANES: { key: string; label: string; color: string }[] = [
  { key: "device_telemetry", label: MODALITY_META.device_telemetry.label, color: MODALITY_META.device_telemetry.color },
  { key: "control_plane", label: MODALITY_META.control_plane.label, color: MODALITY_META.control_plane.color },
  { key: "passive_flow", label: MODALITY_META.passive_flow.label, color: MODALITY_META.passive_flow.color },
  { key: "active_probe", label: MODALITY_META.active_probe.label, color: MODALITY_META.active_probe.color },
  { key: "_other", label: "Other", color: C.faint },
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

function laneOf(modality: string): string {
  return LANES.some((l) => l.key === modality) ? modality : "_other";
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
}: {
  timeline: CorrTimeline;
  selected?: string | null;
  onSelect?: (signalId: string) => void;
  highlight?: Set<string>;
}) {
  const [hover, setHover] = useState<CorrSignal | null>(null);

  const t0 = toMs(timeline.window_start);
  const t1raw = toMs(timeline.window_end);
  const t1 = t1raw > t0 ? t1raw : t0 + 1000;
  const span = t1 - t0;

  const byLane = useMemo(() => {
    const m: Record<string, CorrSignal[]> = {};
    for (const l of LANES) m[l.key] = [];
    for (const s of timeline.signals) m[laneOf(s.modality_class)].push(s);
    return m;
  }, [timeline.signals]);

  const pct = (ms: number) => Math.max(0, Math.min(100, ((ms - t0) / span) * 100));

  // A few axis ticks (relative seconds from window start).
  const ticks = useMemo(() => {
    const n = 5;
    return Array.from({ length: n + 1 }, (_, i) => {
      const ms = t0 + (span * i) / n;
      return { left: (i / n) * 100, label: `+${((ms - t0) / 1000).toFixed(span > 120000 ? 0 : 1)}s` };
    });
  }, [t0, span]);

  const muted: React.CSSProperties = { color: C.muted };

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
            <div style={{ width: 124, flexShrink: 0, fontSize: 12 }}>
              <span style={{ display: "inline-block", width: 8, height: 8, borderRadius: 2, background: lane.color, marginRight: 6 }} />
              {lane.label}
              <span style={{ ...muted, marginLeft: 4 }}>{sigs.length}</span>
            </div>
            <div style={{ position: "relative", flex: 1, height: "100%" }}>
              {sigs.map((s) => {
                const ms = toMs(s.ts);
                const left = pct(ms);
                const unc = s.onset_uncertainty_s > 0 ? s.onset_uncertainty_s : (CLOCK_FLOOR_S[s.clock_quality] ?? 1);
                const barW = Math.max(2, (unc * 2000 / span) * 100); // ±unc as % of span
                const role = signalRole(s);
                const isHi = highlight?.has(s.signal_id);
                const isSel = selected === s.signal_id;
                const dim = highlight && highlight.size > 0 && !isHi;
                const sz = s.is_trigger ? 14 : 10;
                return (
                  <div key={s.signal_id} style={{ position: "absolute", left: `${left}%`, top: "50%", transform: "translate(-50%,-50%)", opacity: dim ? 0.25 : 1 }}>
                    {/* uncertainty bar */}
                    <div style={{
                      position: "absolute", top: "50%", left: "50%",
                      width: `${barW}%`, minWidth: 6, maxWidth: 240, height: 2,
                      transform: "translate(-50%,-50%)", background: lane.color, opacity: 0.35,
                    }} title={`±${unc}s (${s.clock_quality})`} />
                    {/* marker */}
                    <div
                      onMouseEnter={() => setHover(s)}
                      onMouseLeave={() => setHover((h) => (h?.signal_id === s.signal_id ? null : h))}
                      onClick={() => onSelect?.(s.signal_id)}
                      title={`${s.kind} · ${s.entity_id}`}
                      style={{
                        position: "relative", width: sz, height: sz, borderRadius: s.is_trigger ? 3 : "50%",
                        background: s.attached ? lane.color : "transparent",
                        border: `2px solid ${role ? ROLE_COLOR[role] : lane.color}`,
                        boxShadow: isSel ? `0 0 0 3px var(--accent,#4c8dff)` : (s.is_trigger ? `0 0 0 2px ${lane.color}55` : "none"),
                        cursor: "pointer",
                      }}
                    />
                    {/* label — only meaningful events (trigger, crit, or the
                        rarer control-plane / device lanes) so the probe lane
                        stays uncluttered. Selecting a signal always labels it. */}
                    {(s.is_trigger || isSel || s.severity === "crit"
                      || lane.key === "control_plane" || lane.key === "device_telemetry") && !dim && left < 86 && (
                      <span style={{
                        position: "absolute", left: sz / 2 + 4, top: "50%", transform: "translateY(-50%)",
                        whiteSpace: "nowrap", fontSize: 10.5, lineHeight: 1, pointerEvents: "none",
                        color: isSel ? "var(--accent,#4c8dff)" : lane.color, opacity: isSel ? 1 : 0.85,
                        fontWeight: s.is_trigger || isSel ? 700 : 400,
                      }}>{s.kind.replace(/_anomaly$/, "").replace(/_change$/, "")}</span>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}

      {/* legend */}
      <div style={{ display: "flex", gap: 14, marginTop: 8, fontSize: 11.5, flexWrap: "wrap", ...muted }}>
        <span><b style={{ color: "var(--fg,#e6edf3)" }}>◆</b> trigger</span>
        <span>● filled = attached · ○ hollow = concurrent, engine did not link</span>
        <span style={{ color: ROLE_COLOR.supports }}>ring: supports</span>
        <span style={{ color: ROLE_COLOR.contradicts }}>contradicts</span>
        <span style={{ color: ROLE_COLOR.discriminates }}>discriminates</span>
        <span>bar = timing uncertainty (overlap ⇒ order not certain)</span>
      </div>

      {hover && (
        <div style={{
          position: "absolute", right: 10, top: 6, zIndex: 5, maxWidth: 320,
          background: "var(--panel,#161b22)", border: "1px solid var(--border,#2a2f3a)",
          borderRadius: 6, padding: "6px 8px", fontSize: 12, fontFamily: "ui-monospace,monospace",
          boxShadow: "0 4px 16px rgba(0,0,0,.4)",
        }}>
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
          {/* linkage: the engine's recorded reason this signal was/ wasn't linked */}
          <div style={{
            marginTop: 3, paddingTop: 3, borderTop: "1px solid var(--border,#2a2f3a)",
            color: STATUS_COLOR[hover.link_status] ?? "#d29922",
          }}>
            <b>{statusLabel(hover)}</b>
            {" — "}
            <span style={{ color: "var(--fg,#e6edf3)" }}>{hover.link_reason}</span>
            {(hover.linked_edges ?? []).length > 0 && (
              <div style={{ ...muted, marginTop: 2 }}>
                {(hover.linked_edges ?? []).map((e, i) => (
                  <div key={i}>↔ {e.peer.split(":").slice(1, -1).join(":")} [{e.grounding_kind}:{e.grounding_ref}] w={Number(e.weight).toFixed(2)}</div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
