import { C } from "./labels";

// ConfidenceLadder — an EXPLAINABLE verdict ladder (not a magic AI score). It
// shows three rungs an issue climbs as evidence accumulates — Observed →
// Suspected → Confirmed — with the confirm rung LOCKED until independent evidence
// is present, plus the concrete checklist of what would unlock it. Operator-View
// component: NOC language only, no weights/IDs. Reduced-motion safe (no animation).

export type LadderLevel = "observed" | "suspected" | "confirmed";

export interface LadderProps {
  level: LadderLevel;
  observed: string[]; // bright "✓ …" facts already in hand (e.g. "Device-health change on leaf1")
  related?: string;   // the suspected-rung reason (why the facts are related)
  missing: string[];  // "○ …" independent evidence that would confirm
}

const RUNGS: { key: LadderLevel; label: string }[] = [
  { key: "observed", label: "Observed" },
  { key: "suspected", label: "Suspected" },
  { key: "confirmed", label: "Confirmed" },
];
const ORDER: Record<LadderLevel, number> = { observed: 0, suspected: 1, confirmed: 2 };
const RUNG_TONE: Record<LadderLevel, string> = { observed: C.ok, suspected: C.warn, confirmed: C.crit };

export default function ConfidenceLadder({ level, observed, related, missing }: LadderProps) {
  const cur = ORDER[level];
  const card: React.CSSProperties = {
    border: "1px solid var(--border,#2a2f3a)", borderRadius: 8, padding: "11px 14px",
    background: "var(--panel,#11151c)", display: "flex", flexDirection: "column", gap: 10, minWidth: 0,
  };
  const head: React.CSSProperties = { fontSize: 12, fontWeight: 700, letterSpacing: 0.6, textTransform: "uppercase", color: C.muted };

  return (
    <div style={card}>
      <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", gap: 8, flexWrap: "wrap" }}>
        <span style={head}>Confidence ladder</span>
        <span style={{ fontSize: 12.5, color: C.fg }}>
          Current level: <b style={{ color: RUNG_TONE[level], fontWeight: 800 }}>{RUNGS[cur].label}{level !== "confirmed" ? " · not confirmed" : ""}</b>
        </span>
      </div>

      {/* the three rungs */}
      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
        {RUNGS.map((r, i) => {
          const reached = ORDER[r.key] <= cur;
          const locked = r.key === "confirmed" && level !== "confirmed";
          const tone = locked ? C.faint : reached ? RUNG_TONE[r.key] : C.faint;
          return (
            <div key={r.key} style={{ display: "flex", alignItems: "center", gap: 6, flex: i < RUNGS.length - 1 ? 1 : "0 0 auto", minWidth: 0 }}>
              <span style={{
                fontSize: 12, fontWeight: 800, padding: "3px 10px", borderRadius: 6, whiteSpace: "nowrap",
                color: reached && !locked ? "#fff" : tone,
                background: reached && !locked ? tone : "transparent",
                border: `1px solid ${tone}${reached && !locked ? "" : "66"}`,
                opacity: locked ? 0.7 : 1,
              }}>
                {locked ? "🔒 " : reached ? "✓ " : ""}{r.label}
              </span>
              {i < RUNGS.length - 1 && (
                <span style={{ flex: 1, height: 2, borderRadius: 2, minWidth: 14, background: ORDER[r.key] < cur ? RUNG_TONE[r.key] : `${C.faint}55` }} />
              )}
            </div>
          );
        })}
      </div>

      {/* what's in hand (bright) */}
      {observed.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
          {observed.map((o, i) => (
            <div key={i} style={{ fontSize: 13, color: C.fg, lineHeight: 1.45 }}>
              <span style={{ color: C.ok, fontWeight: 800 }}>✓</span> {o}
            </div>
          ))}
          {related && level !== "observed" && (
            <div style={{ fontSize: 13, color: C.fg, lineHeight: 1.45 }}>
              <span style={{ color: C.warn, fontWeight: 800 }}>✓</span> {related}
            </div>
          )}
        </div>
      )}

      {/* what's missing to confirm */}
      {level !== "confirmed" && missing.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: C.muted }}>Missing to confirm</div>
          {missing.map((m, i) => (
            <div key={i} style={{ fontSize: 13, color: C.muted, lineHeight: 1.45 }}>
              <span style={{ color: C.faint, fontWeight: 800 }}>○</span> {m}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
