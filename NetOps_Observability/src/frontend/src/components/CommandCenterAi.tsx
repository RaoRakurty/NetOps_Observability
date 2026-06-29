import { useState } from "react";
import { api, AiAnswer } from "../services/api";
import Icon from "./Icon";

// CommandCenterAi — the Correlix AI "what's going on right now" panel for the
// Command Center. One click → a grounded NOC situation summary (active-incident
// counts, most-impacted entities, recommended focus) with clickable citations.
// All model text renders as escaped React text (OWASP LLM05).
export default function CommandCenterAi() {
  const [ans, setAns] = useState<AiAnswer | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const ask = async () => {
    setBusy(true);
    setErr(null);
    try {
      setAns(await api.aiAsk("What is going on right now? What should the NOC focus on first?"));
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const cs = ans?.current_state;

  return (
    <div className="cc-panel" style={{ marginBottom: 14 }}>
      <div className="cc-panel-h">
        <h3 className="cc-panel-t" style={{ display: "inline-flex", alignItems: "center", gap: 7 }}>
          <Icon name="copilot" size={14} /> Correlix AI
        </h3>
        <button className="btn-accent" style={{ padding: "4px 12px", fontSize: 12.5 }} onClick={ask} disabled={busy}>
          {busy ? "Thinking…" : ans ? "Refresh" : "What's going on right now?"}
        </button>
      </div>
      <div style={{ padding: "11px 13px" }}>
        {err && <p style={{ color: "var(--bad)", fontSize: 13, margin: 0 }}>Correlix AI: {err}</p>}
        {!ans && !busy && !err && (
          <p className="mini-meta" style={{ margin: 0 }}>
            Ask Correlix AI for a grounded NOC situation summary — active incidents by verdict, most-impacted
            entities, and what to work first — built from the live correlations, with clickable evidence.
          </p>
        )}
        {ans && (
          <div>
            <p style={{ fontSize: 13.5, lineHeight: 1.55, color: "var(--fg)", whiteSpace: "pre-wrap", margin: "0 0 10px" }}>
              {ans.text}
            </p>
            {cs && (
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 10 }}>
                <Stat label="Confirmed" n={cs.confirmed} tone="var(--crit)" />
                <Stat label="Suspected" n={cs.suspected} tone="var(--warn)" />
                <Stat label="Undetermined" n={cs.undetermined} />
              </div>
            )}
            {cs && cs.impacted_entities?.length > 0 && (
              <div style={{ marginBottom: 10, fontSize: 12.5 }}>
                <span style={{ color: "var(--muted)" }}>Most impacted: </span>
                {cs.impacted_entities.join(", ")}
              </div>
            )}
            {cs && cs.recommended_focus?.length > 0 && (
              <div style={{ marginBottom: 10, fontSize: 12.5 }}>
                <span style={{ color: "var(--muted)" }}>Focus first: </span>
                {cs.recommended_focus[0]}
              </div>
            )}
            {ans.citations?.length > 0 && (
              <details>
                <summary className="mini-meta" style={{ cursor: "pointer" }}>
                  {ans.citations.length} cited incident{ans.citations.length > 1 ? "s" : ""}
                </summary>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 6 }}>
                  {ans.citations.slice(0, 20).map((c) => (
                    <a key={c.id} className="chip" href={c.href} title={c.label}
                      style={{ maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {c.label || c.id}
                    </a>
                  ))}
                </div>
              </details>
            )}
            {ans.provider && (
              <p className="mini-meta" style={{ margin: "8px 0 0", opacity: 0.7 }}>
                {ans.provider === "none" ? "Evidence-only summary (no AI provider configured)." : `Grounded answer · ${ans.provider}.`}
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function Stat({ label, n, tone }: { label: string; n: number; tone?: string }) {
  return (
    <span style={{ display: "inline-flex", alignItems: "baseline", gap: 6, border: "1px solid var(--border)", borderRadius: 7, padding: "4px 10px" }}>
      <strong style={{ fontFamily: "var(--font-mono)", fontSize: 15, color: tone || "var(--fg)" }}>{n}</strong>
      <span className="mini-meta">{label}</span>
    </span>
  );
}
