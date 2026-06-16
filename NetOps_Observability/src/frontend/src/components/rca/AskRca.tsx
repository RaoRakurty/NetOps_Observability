import { useState } from "react";
import { C } from "./labels";

// AskRca — a compact, collapsible "Ask this RCA" panel. Answers are GROUNDED in
// the structured RCA evidence already on the page (deterministic, not a free-form
// model call), so they can never invent data, never claim confirmed when it isn't,
// and never leak raw IDs — exactly the §13 guardrails. It assists; it doesn't
// dominate the page. Each answer is built by the parent from real RCA values.

export interface QA {
  q: string;
  a: string;
}

export default function AskRca({ items }: { items: QA[] }) {
  const [open, setOpen] = useState(false);
  const [sel, setSel] = useState<number | null>(null);
  if (items.length === 0) return null;

  const card: React.CSSProperties = {
    border: "1px solid var(--border,#2a2f3a)", borderRadius: 8, padding: "9px 13px",
    background: "var(--panel,#11151c)", display: "flex", flexDirection: "column", gap: 8, minWidth: 0,
    borderLeft: "3px solid #38bdf8", // light cyan AI accent
  };
  const head: React.CSSProperties = {
    fontSize: 12, fontWeight: 700, letterSpacing: 0.6, textTransform: "uppercase", color: C.muted,
    display: "flex", alignItems: "center", justifyContent: "space-between", cursor: "pointer", gap: 8,
  };

  return (
    <div style={card}>
      <div style={head} onClick={() => setOpen((v) => !v)} role="button" aria-expanded={open}>
        <span>Ask this RCA</span>
        <span style={{ color: C.muted, fontSize: 13 }}>{open ? "−" : "+"}</span>
      </div>
      {open && (
        <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {items.map((it, i) => (
              <button key={i} onClick={() => setSel(sel === i ? null : i)} style={{
                fontSize: 12, fontWeight: 600, padding: "4px 10px", borderRadius: 14, cursor: "pointer",
                border: `1px solid ${sel === i ? "#38bdf8" : "var(--border,#2a2f3a)"}`,
                background: sel === i ? "#38bdf81c" : "transparent",
                color: sel === i ? C.fg : C.muted, whiteSpace: "nowrap",
              }}>
                {it.q}
              </button>
            ))}
          </div>
          {sel !== null && (
            <div style={{ fontSize: 13, lineHeight: 1.5, color: C.fg, background: "var(--bg,#0d1117)", borderRadius: 6, padding: "8px 11px" }}>
              {items[sel].a}
            </div>
          )}
          <div style={{ fontSize: 11, color: C.faint }}>
            Answers are grounded in this issue's recorded evidence — no external lookups.
          </div>
        </div>
      )}
    </div>
  );
}
