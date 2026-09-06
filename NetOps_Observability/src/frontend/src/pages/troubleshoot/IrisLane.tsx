// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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
// CHAIN (IRIS Phase A2). When the investigation ran more than one method, the
// backend also sends `chain` — every hop in authored order with how it was
// chosen (entry / rule / model). It renders as a breadcrumb of chips so the
// operator can audit the PATH the server took, not just its last step. A single
// hop draws no breadcrumb (the skill chip already says it), and a pre-A2 backend
// sends no chain at all.
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
import { api, type AiAnswer, type AiCitation, type AiSkillHop } from "../../services/api";

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

/** How a hop was chosen, in the operator's words. An unrecognised value from a
 *  newer backend renders verbatim as escaped text rather than being dropped. */
export function hopSelectionLabel(hop: AiSkillHop): string {
  switch (hop.selected) {
    case "entry": return "entry";
    case "rule": return "rule";
    case "model": return "proposed";
    default: return (hop.selected || "").trim();
  }
}

/** The breadcrumb is drawn only for a REAL chain (more than one hop). */
export function chainHops(ans: AiAnswer | null): AiSkillHop[] {
  const chain = ans?.chain ?? [];
  return chain.length > 1 ? chain : [];
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
  const hops = chainHops(ans);

  return (
    <section className="ts-iris" role="region" aria-labelledby="lane-h-iris" data-lane="iris">
      <div className="tsl-head">
        <h3 id="lane-h-iris" className="tsl-title">Ask Iris</h3>
        <div className="tsl-head-actions">
          <button type="button" className="btn-accent" onClick={ask} disabled={busy} aria-busy={busy}>
            {busy ? "Thinking…" : ans ? "Re-ask" : "Ask Iris"}
          </button>
          {onOpenDrawer && (
            <button type="button" className="chip-btn" onClick={onOpenDrawer}>Open Iris</button>
          )}
        </div>
      </div>
      {err && <p className="ts-bad" role="alert">Iris: {err}</p>}

      {!ans && !busy && !err && (
        <p className="tsl-sum">
          Iris reads the evidence above and tells you what it supports, what is missing, and what to check next.
          It cites what it read, and it never changes anything on your network.
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

          {/* Investigation chain (Phase A2) — the path the server took. */}
          {hops.length > 0 && (
            <ol
              className="tsl-chain" aria-label="Investigation path" data-testid="iris-chain"
              style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 6, listStyle: "none", padding: 0, margin: "0 0 6px" }}
            >
              {hops.map((h, i) => {
                const how = hopSelectionLabel(h);
                return (
                  <li key={`${h.name}-${i}`} className="tsl-chain-hop"
                      style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    {i > 0 && <span aria-hidden="true" className="tsl-chain-arrow">→</span>}
                    <span className="badge" data-testid="iris-chain-hop" title={h.reason || undefined}>
                      {h.name}{how ? ` · ${how}` : ""}
                    </span>
                  </li>
                );
              })}
            </ol>
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
      <div className="tsl-src">Read from <span className="tsl-api">/api/ai/ask</span></div>
    </section>
  );
}
