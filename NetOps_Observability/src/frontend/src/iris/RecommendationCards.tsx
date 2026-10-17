// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// RecommendationCards — an Iris answer's suggested next steps (tracker 337
// N-I7). Each card is grounded in evidence the answer cites (its basis links
// back to that evidence) and ALWAYS says "No action has been executed." The
// label is a client constant: it never depends on the server's data. A card is
// text and links only — there is no button, no form, nothing that acts.

import type { AiCitation, AiRecommendation } from "../services/api";
import { answerCiteHref } from "./links";

export const NO_ACTION_NOTICE = "No action has been executed.";

export default function RecommendationCards({ cards, citations }: { cards: AiRecommendation[]; citations: AiCitation[] }) {
  const byId = new Map(citations.map((c) => [c.id, c]));
  return (
    <div className="op-section" aria-label="Suggested next steps">
      {cards.slice(0, 4).map((c) => (
        <article key={c.id} className="iris-card iris-rec" aria-label={c.title || "Suggested next steps"}>
          <div className="op-sec-h">{c.title || "Suggested next steps"}</div>
          {c.why && <p className="iris-text">{c.why}</p>}
          <ol className="op-actions">
            {(c.steps ?? []).slice(0, 6).map((s, i) => <li key={i}>{s}</li>)}
          </ol>
          {c.owner && <div className="op-kv"><span className="op-kv-k">Owner</span> {c.owner}</div>}
          {(c.basis ?? []).length > 0 && (
            <div className="op-kv">
              <span className="op-kv-k">Based on</span>{" "}
              {(c.basis ?? []).slice(0, 8).map((id, i) => {
                const cite = byId.get(id);
                const href = cite ? answerCiteHref(cite.href) : null;
                const label = cite?.label || id;
                return (
                  <span key={id}>
                    {i > 0 && ", "}
                    {href ? <a className="op-cite" href={href} title={label}>{label}</a> : <span>{label}</span>}
                  </span>
                );
              })}
            </div>
          )}
          <footer className="iris-card-foot">{NO_ACTION_NOTICE}</footer>
        </article>
      ))}
    </div>
  );
}
