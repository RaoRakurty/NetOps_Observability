// ai.tsx — the AI investigator panel, in both of its states.
//
// The panel is NEVER hidden. A feature that disappears when it is switched off
// is indistinguishable from one that was never built, and an operator who
// cannot see that the investigator exists cannot ask for it to be turned on.
// So when `ai_investigator.available` is false the panel renders DISABLED with
// the server's own reason next to it, verbatim.
//
// What the investigator is allowed to be is stated on the panel itself: it
// explains evidence Correlix has already gathered, it never gathers its own,
// and it can never mark a cause confirmed. That sentence is the guard against
// the failure mode where a model's fluency is read as a verdict.

import type { DemAIAvailability } from "../../services/api";

export function AiInvestigatorPanel({ availability, subject, onExplain }: {
  availability: DemAIAvailability;
  /** What it would explain — an incident title, or the window. */
  subject: string;
  onExplain?: () => void;
}) {
  const off = !availability.available;
  return (
    <section className="card dx-section" role="region" aria-label="AI investigator">
      <div className="dx-section-head">
        <h2 className="dx-h2">AI investigator</h2>
        <span className="dx-chip">{off ? "Unavailable" : "Available"}</span>
      </div>
      <p className="dx-note">
        It explains the evidence already gathered for {subject}. It never gathers evidence of
        its own, and it can never move a cause to confirmed — only two independent kinds of
        instrument can do that.
      </p>
      {off && (
        <p className="dx-note" role="note">
          {availability.reason
            || "The AI investigator is switched off for this deployment."}
        </p>
      )}
      <div className="dx-actions">
        <button type="button" className="btn" disabled={off} onClick={onExplain}
          aria-disabled={off}
          title={off ? availability.reason : undefined}>
          Explain the evidence
        </button>
      </div>
    </section>
  );
}
