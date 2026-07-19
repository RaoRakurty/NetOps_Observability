import { useState } from "react";
import { api, AiAnswer } from "../../services/api";
import Icon from "../Icon";

// RcaAskAi — the Iris AI "Ask AI" card on the RCA Inspector. One click asks
// the orchestrator to explain THIS correlation; the backend retrieves the
// tenant-scoped evidence, grounds the model, and returns a cited answer. All
// model text renders as escaped React text (never HTML) — OWASP LLM05.
export default function RcaAskAi({ correlationId }: { correlationId: string }) {
  const [ans, setAns] = useState<AiAnswer | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const ask = async () => {
    setBusy(true);
    setErr(null);
    try {
      const a = await api.aiAsk("Explain this problem", { correlation_id: correlationId });
      setAns(a);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const pe = ans?.problem;

  return (
    <div className="card" style={{ borderColor: "var(--accent)" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}>
        <h3 style={{ margin: 0, display: "inline-flex", alignItems: "center", gap: 7 }}>
          <span aria-hidden="true"><Icon name="copilot" size={15} /></span> Iris AI
        </h3>
        <button className="btn-accent" onClick={ask} disabled={busy} aria-busy={busy}>
          {busy ? "Thinking…" : ans ? "Re-ask" : "Explain this problem"}
        </button>
      </div>

      {/* Announce the async error (4.1.3). */}
      {err && <p role="alert" style={{ color: "var(--bad)", fontSize: 13, marginBottom: 0 }}>Iris AI: {err}</p>}

      {!ans && !busy && !err && (
        <p className="mini-meta" style={{ marginTop: 8, marginBottom: 0 }}>
          Ask Iris AI for a grounded, evidence-cited explanation of this correlation — root cause, supporting
          evidence, what's missing, and a recommended next action.
        </p>
      )}

      {/* Live region (4.1.3): the grounded answer is announced when it lands. */}
      {ans && (
        <div style={{ marginTop: 10 }} role="status" aria-live="polite">
          {/* Grounded narrative (escaped text only). */}
          <p style={{ fontSize: 13.5, lineHeight: 1.55, color: "var(--fg)", whiteSpace: "pre-wrap", margin: "0 0 10px" }}>
            {ans.text || "No answer."}
          </p>

          {pe && (
            <div style={{ display: "grid", gap: 6, fontSize: 12.5, marginBottom: 8 }}>
              {pe.recommended_owner && (
                <Row label="Recommended owner" value={pe.recommended_owner} />
              )}
              {pe.missing_evidence?.length > 0 && (
                <Row label="Missing evidence" value={pe.missing_evidence.join(", ")} tone="var(--warn)" />
              )}
              {pe.verdict && <Row label="Verdict" value={`${pe.verdict} · ${pe.confidence}`} />}
            </div>
          )}

          {/* Cited evidence — clickable back into the source views (anti-black-box). */}
          {ans.citations?.length > 0 && (
            <div style={{ marginTop: 4 }}>
              <div className="mini-meta" style={{ fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.4, marginBottom: 5 }}>
                Evidence
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {ans.citations.map((c) => (
                  <a key={c.id} className="chip" href={c.href} title={c.label}
                    style={{ maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {c.label || c.id}
                  </a>
                ))}
              </div>
            </div>
          )}

          {ans.disclaimers?.length > 0 && (
            <ul className="mini-meta" style={{ margin: "10px 0 0", paddingLeft: 16 }}>
              {ans.disclaimers.map((d, i) => <li key={i}>{d}</li>)}
            </ul>
          )}

          {ans.provider && (
            <p className="mini-meta" style={{ margin: "8px 0 0", opacity: 0.7 }}>
              Grounded answer · {ans.provider === "none" ? "evidence-only (no provider)" : ans.provider} · cite the linked evidence to verify.
            </p>
          )}
        </div>
      )}
    </div>
  );
}

function Row({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <div style={{ display: "flex", gap: 8 }}>
      <span style={{ color: "var(--muted)", minWidth: 130 }}>{label}</span>
      <span style={{ color: tone || "var(--fg)" }}>{value}</span>
    </div>
  );
}
