import type { ReactNode } from "react";
import "./RcaWorkspace.css";
import type { RcaCase, RcaPill } from "./rcaCase";
import FidelityBadge from "../FidelityBadge";

// RcaCaseHeader — the RCA "six-question" case header (what happened · how
// certain · what is affected · when · which evidence · which RCA id), lifted
// verbatim out of RcaWorkspace so the Troubleshooting investigation surface can
// show the SAME verdict header for the same object instead of growing a second,
// divergent one. RcaWorkspace still renders it in place; this file is the only
// definition.
//
// PURE PRESENTATION. It renders an RcaCase and owns no state. Styles stay under
// `.rca-ws` (RcaWorkspace.css), so every host must wrap it in a `.rca-ws`
// container — RcaWorkspace already is one, and the investigation page wraps it.
// Every value is escaped React text: no innerHTML anywhere (§15 LLM02).

export const Pill = ({ p }: { p: RcaPill }) => <span className={`rw-pill ${p.tone}`}>{p.text}</span>;

export default function RcaCaseHeader({ data, feedbackSlot }: {
  data: RcaCase;
  // Operator verdict feedback — a full-width row under the aside, where the
  // reader has just finished the verdict and the aside claims.
  feedbackSlot?: ReactNode;
}) {
  return (
      <section className="rw-case">
        <div>
          <h2>{data.title}</h2>
          <div className="rw-statusline">{data.pills.map((p, i) => <Pill key={i} p={p} />)}</div>
          {data.decision.text && (
            <div className={`rw-callout${data.decision.tone ? " " + data.decision.tone : ""}`}>
              <strong>Decision:</strong><span>{data.decision.text}</span>
            </div>
          )}
          <div className="rw-note">Detected at: <b>{data.observedAt}</b> · RCA ID: <b>{data.rcaId}</b></div>
        </div>
        <aside className="rw-aside">
          {data.aside.map((m, i) => <div key={i} className="rw-metric"><span>{m.k}</span><b className={m.mono ? "mono" : undefined}>{m.v}</b></div>)}
        </aside>
        {/* Evidence summary (owner 2026-07-18): verdict reason in operator words
            + one time-density bar per symptom — repetition rendered as ink,
            never as a count posing as evidence. Spans the full card width so the
            two columns above stay balanced (no dead space under either). */}
        {data.evidenceSummary && data.evidenceSummary.rows.length > 0 && (
          <div className="rw-evsum" aria-label="Evidence summary">
            <div className="rw-evsum-verdict">{data.evidenceSummary.verdictReason}</div>
            {data.evidenceSummary.rows.map((r, i) => (
              <div key={i} className="rw-evsum-row" title={`${r.label} — seen by ${r.source}; ${r.observations} observations`}>
                <span className="rw-evsum-label">{r.label}</span>
                <span className="rw-evsum-bar" aria-hidden="true">
                  {r.buckets.map((b, j) => {
                    const max = Math.max(...r.buckets, 1);
                    return <span key={j} className="rw-evsum-cell" style={{ opacity: b > 0 ? 0.25 + 0.75 * (b / max) : 0.08 }} />;
                  })}
                </span>
                {r.fidelity && <FidelityBadge fidelity={r.fidelity} />}
                <span className="rw-evsum-since">{r.since ? `since ${r.since}` : ""}</span>
              </div>
            ))}
          </div>
        )}
        {/* Operator verdict feedback (Project 2 P7) — the reader has just read
            the verdict and the aside claims; this is where "was it right?"
            belongs. Full-width row so neither column is squeezed. */}
        {feedbackSlot && <div className="rw-fbrow">{feedbackSlot}</div>}
      </section>
  );
}
