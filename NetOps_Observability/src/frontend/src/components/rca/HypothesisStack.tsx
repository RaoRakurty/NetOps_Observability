import { C } from "./labels";

// HypothesisStack — an explainable "what else could this be" ranking. NOT a
// black-box AI score: every hypothesis carries WHY it's ranked there and WHAT
// evidence is missing to raise it. Grounded only — the deriver builds these from
// the evidence actually present, never invents facts, and never claims a confirmed
// root cause when the verdict isn't confirmed. Operator-View: NOC language only.

export type Confidence = "High" | "Medium" | "Low";

export interface Hypothesis {
  title: string;
  confidence: Confidence;
  why: string;
  missing?: string;
}

const CONF_TONE: Record<Confidence, string> = { High: C.ok, Medium: C.warn, Low: C.faint };

export default function HypothesisStack({ hypotheses }: { hypotheses: Hypothesis[] }) {
  if (hypotheses.length === 0) return null;
  const card: React.CSSProperties = {
    border: "1px solid var(--border,#2a2f3a)", borderRadius: 8, padding: "11px 14px",
    background: "var(--panel,#11151c)", display: "flex", flexDirection: "column", gap: 9, minWidth: 0,
    borderLeft: "3px solid #8b7cf6", // subtle AI accent (lightly, per the visual rules)
  };
  const head: React.CSSProperties = { fontSize: 12, fontWeight: 700, letterSpacing: 0.6, textTransform: "uppercase", color: C.muted };

  return (
    <div style={card}>
      <span style={head}>Hypothesis ranking</span>
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {hypotheses.slice(0, 3).map((h, i) => {
          const tone = CONF_TONE[h.confidence];
          const lead = i === 0;
          return (
            <div key={i} style={{
              display: "flex", flexDirection: "column", gap: 3, padding: "7px 9px", borderRadius: 6,
              background: lead ? "var(--hover)" : "transparent",
              border: `1px solid ${lead ? "var(--border)" : "transparent"}`,
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                <span style={{ fontFamily: "ui-monospace,monospace", fontSize: 12, color: C.muted, fontWeight: 700 }}>#{i + 1}</span>
                <span style={{ fontSize: 13.5, fontWeight: lead ? 800 : 700, color: C.fg }}>{h.title}</span>
                <span style={{
                  fontSize: 10.5, fontWeight: 800, letterSpacing: 0.3, padding: "1px 7px", borderRadius: 4,
                  color: tone, background: tone + "1c", border: `1px solid ${tone}55`, whiteSpace: "nowrap",
                }}>
                  {h.confidence}
                </span>
              </div>
              <div style={{ fontSize: 12.5, color: C.muted, lineHeight: 1.45 }}>
                <span style={{ color: C.muted }}>Why: </span>{h.why}
              </div>
              {h.missing && (
                <div style={{ fontSize: 12.5, color: C.muted, lineHeight: 1.45 }}>
                  <span style={{ color: C.faint }}>Missing: </span>{h.missing}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
