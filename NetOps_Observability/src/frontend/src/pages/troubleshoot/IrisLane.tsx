// IrisLane — the IRIS co-pilot lane of the investigation surface.
//
// It asks the SAME grounded endpoint the rest of the product asks
// (POST /api/ai/ask) with the investigation as context, and renders the answer
// beside the evidence lanes rather than in a separate window. A second control
// opens the docked Iris drawer for a free-form conversation carrying the same
// grounding.
//
// PROVENANCE (IRIS Phase A). When the backend names the answering `skill`
// {name, version, layer} and per-citation provenance {tool, ids}, this lane
// renders them as chips so the operator can see WHICH read-only skill and WHICH
// tool produced each claim. Both fields are OPTIONAL: absent means no chip is
// drawn — never a placeholder, never an invented tool name.
//
// SECURITY (§15). Model output is untrusted (LLM02): every string here — the
// narrative, the skill name, the tool name, each citation id — is rendered as an
// ESCAPED React text node. There is no innerHTML, no dangerouslySetInnerHTML and
// no markup parsing. Citation hrefs are rendered as links ONLY when they are
// same-origin relative paths; anything else (javascript:, an absolute URL a
// model composed) renders as inert text (LLM08: no excessive agency).
// The grounding we send carries only what is already on the operator's screen —
// no secrets, no other tenant's data (LLM06).

import { useState } from "react";
import { api, type AiAnswer, type AiCitation } from "../../services/api";

/** A relative, same-origin path is safe to link. Everything else is inert text.
 *  Both protocol-relative spellings are rejected: browsers normalise a leading
 *  backslash to a slash, so "/\\evil.example" is "//evil.example" off-origin. */
export function safeCiteHref(href: string | undefined): string | null {
  const h = (href || "").trim();
  if (!h.startsWith("/")) return null;
  if (h.startsWith("//") || h.startsWith("/\\")) return null;
  return h;
}

/** The provenance chip text for one citation: "tool · N ids", "tool", or "". */
export function citeProvenance(c: AiCitation): string {
  const tool = (c.tool || "").trim();
  if (!tool) return "";
  const n = c.ids?.length ?? 0;
  return n > 0 ? `${tool} · ${n} ${n === 1 ? "id" : "ids"}` : tool;
}

export default function IrisLane({ caseId, symptomLabel, onOpenDrawer }: {
  /** Correlation id when a case drives the investigation (the grounding key). */
  caseId?: string;
  /** The chosen symptom's own words, used to ground a symptom-only ask. */
  symptomLabel?: string;
  /** Opens the docked Iris drawer. Absent = the control is not rendered. */
  onOpenDrawer?: () => void;
}) {
  const [ans, setAns] = useState<AiAnswer | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const question = caseId
    ? "Explain this problem and what to check next."
    : symptomLabel
      ? `An operator reports: ${symptomLabel}. What should I check next, and what evidence is missing?`
      : "What is going on right now?";

  const ask = async () => {
    setBusy(true); setErr(null);
    try {
      setAns(await api.aiAsk(question, caseId ? { correlation_id: caseId } : {}));
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const cites = ans?.citations ?? [];

  return (
    <section className="tsl-card card tsl-iris" role="region" aria-labelledby="lane-h-iris" data-lane="iris">
      <div className="tsl-head">
        <h3 id="lane-h-iris" className="tsl-title">Iris co-pilot</h3>
        <div className="tsl-head-actions">
          <button type="button" className="btn-accent" onClick={ask} disabled={busy} aria-busy={busy}>
            {busy ? "Thinking…" : ans ? "Re-ask" : "Ask Iris"}
          </button>
          {onOpenDrawer && (
            <button type="button" className="chip-btn" onClick={onOpenDrawer}>Open Iris</button>
          )}
        </div>
      </div>
      <div className="tsl-src mini-meta">/api/ai/ask</div>

      {err && <p className="empty" role="alert" style={{ color: "var(--bad)" }}>Iris: {err}</p>}

      {!ans && !busy && !err && (
        <p className="mini-meta tsl-foot">
          Ask for a grounded, evidence-cited read of this investigation — what the evidence supports, what is missing,
          and a recommended next step. Nothing is executed on your behalf.
        </p>
      )}

      {ans && (
        <div role="status" aria-live="polite">
          {/* Skill provenance (Phase A) — drawn ONLY when the backend names it. */}
          {ans.skill?.name && (
            <div className="tsl-prov" aria-label="Answering skill">
              <span className="badge accent-badge" data-testid="iris-skill-chip">
                Skill: {ans.skill.name}
                {ans.skill.version ? ` v${ans.skill.version}` : ""}
                {ans.skill.layer ? ` · ${ans.skill.layer}` : ""}
              </span>
            </div>
          )}

          <p className="tsl-iris-text">{ans.text || "No answer."}</p>

          {cites.length > 0 && (
            <div className="tsl-cites" aria-label="Evidence citations">
              {cites.slice(0, 12).map((c, i) => {
                const prov = citeProvenance(c);
                const href = safeCiteHref(c.href);
                const label = c.label || c.id;
                return (
                  <span key={c.id || i} className="tsl-cite">
                    {href
                      ? <a className="chip" href={href} title={label}>{label}</a>
                      : <span className="chip">{label}</span>}
                    {prov && <span className="badge" data-testid="iris-cite-provenance">{prov}</span>}
                  </span>
                );
              })}
            </div>
          )}

          {ans.disclaimers?.length > 0 && (
            <ul className="mini-meta tsl-foot" style={{ paddingLeft: 16 }}>
              {ans.disclaimers.map((d, i) => <li key={i}>{d}</li>)}
            </ul>
          )}
        </div>
      )}
    </section>
  );
}
