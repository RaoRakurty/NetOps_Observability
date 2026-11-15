// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ActionProposalCards — the writes Iris PROPOSED at the end of a concluded
// investigation (tracker 337 N-I4). A card is text only: there is no button
// here, because the person Iris answered can never approve it. Approval
// happens on Iris settings, step 8, by someone else. Every card says
// "No action has been executed." — a client constant, never the server's data.

import type { AiActionProposal } from "../services/api";
import { NO_ACTION_NOTICE } from "./RecommendationCards";

export const PROPOSED_NOTICE = "Proposed — needs approval by someone else.";

function statusLine(p: AiActionProposal): string {
  switch (p.status) {
    case "proposed":
      return `${PROPOSED_NOTICE} Iris settings, step 8.`;
    case "existing":
      return "Already waiting for approval — Iris settings, step 8.";
    case "dry_run":
      return "Dry run only: this workspace sends nothing.";
    default:
      return p.note || "Not proposed.";
  }
}

export default function ActionProposalCards({ proposals }: { proposals: AiActionProposal[] }) {
  if (!proposals.length) return null;
  return (
    <div className="op-section" aria-label="Proposed actions" data-testid="iris-action-proposals">
      {proposals.slice(0, 2).map((p, i) => (
        <article key={p.id || `${p.kind}-${i}`} className="iris-card iris-rec" aria-label={p.label}>
          <div className="op-sec-h">{p.label}</div>
          {p.summary && <p className="iris-text">{p.summary}</p>}
          <p className="iris-text">{statusLine(p)}</p>
          <footer className="iris-card-foot">{NO_ACTION_NOTICE}</footer>
        </article>
      ))}
    </div>
  );
}
