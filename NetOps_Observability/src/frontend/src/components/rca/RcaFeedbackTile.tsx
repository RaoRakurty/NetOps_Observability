// RcaFeedbackTile — "Verdict feedback (30 d)": how often operators told us the
// engine was right (Project 2 P7). This is the ONLY honest measurement of RCA
// quality we have — the engine's own confidence tier is its opinion of itself.
//
// Honesty rules (they are the whole point of the tile):
//  · An empty sample has NO false-positive rate. `false_positive_rate` is null
//    from the server when n = 0 and renders as "Not enough feedback yet" — never
//    as 0 %, which would read as "the engine is never wrong".
//  · The split is shown alongside the rate so a 1-of-1 sample can't masquerade
//    as a trend.
//  · A failed read says so; it does not render zeros.

import { useEffect, useState } from "react";
import { api, type RcaFeedbackSummary } from "../../services/api";
import { VERDICT_LABEL } from "./labels";

export const FEEDBACK_WINDOW_DAYS = 30;

/** ratePct — the rate as a whole percent, or null when there is no sample. */
export function ratePct(s: RcaFeedbackSummary | null): number | null {
  if (!s || s.n <= 0 || s.false_positive_rate == null) return null;
  return Math.round(s.false_positive_rate * 100);
}

export default function RcaFeedbackTile() {
  const [data, setData] = useState<RcaFeedbackSummary | null>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    let alive = true;
    Promise.resolve()
      .then(() => api.rcaFeedbackSummary(FEEDBACK_WINDOW_DAYS))
      .then((s) => { if (alive) { setData(s); setErr(""); } })
      .catch(() => { if (alive) setErr("Verdict feedback is unavailable right now."); });
    return () => { alive = false; };
  }, []);

  const pct = ratePct(data);
  const n = data?.n ?? 0;
  const counts = data?.counts ?? { correct: 0, wrong: 0, partial: 0 };

  return (
    <div className="rsc-panel rsc-fb">
      <div className="rsc-panel-title">Verdict feedback ({FEEDBACK_WINDOW_DAYS} d) — did operators agree with the engine?</div>
      {err ? (
        <div className="rsc-empty">{err}</div>
      ) : (
        <div className="rsc-cards" style={{ marginBottom: 0 }}>
          <div className={`rsc-card rsc-card-${pct == null ? "muted" : pct >= 25 ? "amber" : "hero"}`}>
            <div className="rsc-card-label">False-positive RCA rate</div>
            <div className="rsc-card-val">
              {pct == null
                ? <span className="rsc-card-na">Not enough feedback yet</span>
                : `${pct}%`}
            </div>
            <div className="rsc-card-sub">
              {pct == null ? "No operator verdict recorded in this window" : `${counts.wrong} of ${n} judged wrong`}
            </div>
          </div>

          <div className="rsc-card">
            <div className="rsc-card-label">Operator verdicts recorded</div>
            <div className="rsc-card-val">{n.toLocaleString()}</div>
            <div className="rsc-card-sub">last {FEEDBACK_WINDOW_DAYS} days</div>
          </div>

          <div className="rsc-card">
            <div className="rsc-card-label">Split by verdict</div>
            <div className="rsc-card-val rsc-fb-split">
              <span title={`${VERDICT_LABEL.correct}: ${counts.correct}`}>{counts.correct}</span>
              <span className="rsc-fb-sep">/</span>
              <span title={`${VERDICT_LABEL.partial}: ${counts.partial}`}>{counts.partial}</span>
              <span className="rsc-fb-sep">/</span>
              <span title={`${VERDICT_LABEL.wrong}: ${counts.wrong}`}>{counts.wrong}</span>
            </div>
            <div className="rsc-card-sub">correct / partially / wrong</div>
          </div>
        </div>
      )}
    </div>
  );
}
