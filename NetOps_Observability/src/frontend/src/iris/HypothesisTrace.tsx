// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// HypothesisTrace — the lines of investigation one Iris investigation held
// (tracker 337 N-B3), shown inside the investigation trace.
//
// What it shows, top to bottom:
//   1. the CORRELATION ENGINE's verdict, labelled as the engine's — its tier and
//      its own words — or the engine's honest "no cause identified / no verdict
//      in scope". Iris never writes here;
//   2. the server's notice that these are lines of investigation, not causes;
//   3. each hypothesis: its state as a WORD (never colour alone), the
//      observation it tests, how it stands against the engine's verdict, and —
//      on demand — every transition with the check and the fact that drove it,
//      plus the evidence ids the check returned.
//
// The set either rides the answer (`set`) or is read back by its id
// (`investigationId`, e.g. from the decision ledger). Every string is server
// data rendered as an escaped React text node; there is no markup parsing.
// Fonts stay on the 14 / 16 px scale (NOC-admin UI standard).

import { useEffect, useState } from "react";
import { api, type AiHypothesis, type AiHypothesisEngine, type AiHypothesisSet } from "../services/api";
import { httpFailure, operatorError } from "../lib/errors";

const text14 = { fontSize: 14, lineHeight: 1.5 } as const;
const muted14 = { ...text14, color: "var(--muted)" } as const;
const heading16 = { fontSize: 16, fontWeight: 600, margin: "0 0 4px" } as const;

/** The operator's word for each state. An unknown state from a newer backend
 *  is shown verbatim (escaped), never dropped. */
export const STATE_WORD: Record<string, string> = {
  PROPOSED: "Proposed",
  TESTING: "Being tested",
  SUPPORTED: "Supported by evidence",
  REJECTED: "Ruled out by evidence",
  INCONCLUSIVE: "Inconclusive",
};

export function stateWord(state: string | undefined): string {
  const s = (state || "").trim();
  return STATE_WORD[s] ?? s;
}

const TIER_WORD: Record<string, string> = {
  confirmed: "Confirmed", suspected: "Suspected", candidate: "Candidate", undetermined: "Undetermined",
};

/** The engine block's heading — always names the ENGINE as the source. */
export function engineHeading(engine: AiHypothesisEngine | undefined): string {
  const tier = (engine?.tier || "").trim();
  if (tier === "confirmed" || tier === "suspected" || tier === "candidate") {
    return `Correlation engine verdict: ${TIER_WORD[tier]}`;
  }
  if (tier === "undetermined") return "Correlation engine: no cause identified";
  return "Correlation engine: no verdict in scope";
}

function Hypothesis({ h }: { h: AiHypothesis }) {
  const steps = h.transitions ?? [];
  const evidence = h.evidence ?? [];
  return (
    <li data-testid="iris-hyp" data-state={h.state} style={{ ...text14, marginBottom: 8 }}>
      <span className="badge" data-testid="iris-hyp-state" style={text14}>{stateWord(h.state)}</span>{" "}
      <span>{h.statement}</span>
      {h.engine_note && <div style={muted14} data-testid="iris-hyp-engine-note">{h.engine_note}</div>}
      {steps.length > 0 && (
        <details style={text14}>
          <summary style={text14}>How this was checked ({steps.length} {steps.length === 1 ? "step" : "steps"})</summary>
          <ol style={{ margin: "4px 0 0", paddingLeft: 22 }} data-testid="iris-hyp-steps">
            {steps.map((s, i) => (
              <li key={i} style={text14}>
                <span>{stateWord(s.to)}</span>
                <span style={muted14}>
                  {" "}— round {s.round}{s.skill ? `, ${s.skill.replace(/-/g, " ")}` : ""}: {s.reason}
                </span>
              </li>
            ))}
          </ol>
          {evidence.length > 0 && (
            <div style={muted14} data-testid="iris-hyp-evidence">
              Evidence read: {evidence.join(" · ")}
            </div>
          )}
        </details>
      )}
    </li>
  );
}

function SetView({ set }: { set: AiHypothesisSet }) {
  const engine = set.engine;
  const hs = set.hypotheses ?? [];
  return (
    <section aria-label="Lines of investigation" data-testid="iris-hypotheses" style={{ ...text14, margin: "6px 0 8px" }}>
      <h4 style={heading16}>Lines of investigation</h4>
      <div data-testid="iris-hyp-engine" style={{ ...text14, marginBottom: 6 }}>
        <div style={{ ...text14, fontWeight: 600 }}>{engineHeading(engine)}</div>
        {engine?.statement && <div style={text14} data-testid="iris-hyp-engine-statement">{engine.statement}</div>}
        {engine?.note && <div style={muted14}>{engine.note}</div>}
      </div>
      {set.notice && <p style={{ ...muted14, margin: "0 0 6px" }}>{set.notice}</p>}
      {hs.length > 0
        ? <ol style={{ margin: 0, paddingLeft: 20 }}>{hs.map((h) => <Hypothesis key={h.id} h={h} />)}</ol>
        : <div style={muted14}>No line of investigation could be tested.</div>}
    </section>
  );
}

/** Loads a held set by id. A 404 is a plain sentence, not an error. */
function LoadedSet({ id }: { id: string }) {
  const [set, setSet] = useState<AiHypothesisSet | null>(null);
  const [err, setErr] = useState("");
  const [gone, setGone] = useState(false);
  useEffect(() => {
    let live = true;
    setSet(null); setErr(""); setGone(false);
    api.aiHypotheses(id)
      .then((s) => { if (live) setSet(s); })
      .catch((e) => {
        if (!live) return;
        if (httpFailure(e)?.status === 404) setGone(true);
        else setErr(operatorError(e, "The lines of investigation could not be loaded."));
      });
    return () => { live = false; };
  }, [id]);
  if (err) return <div role="alert" style={{ ...text14, color: "var(--bad)" }}>{err}</div>;
  if (gone) {
    return (
      <div style={muted14} data-testid="iris-hypotheses-gone">
        This investigation's lines of investigation are no longer held — they are kept for 7 days.
      </div>
    );
  }
  if (!set) return <div style={muted14}>Loading lines of investigation…</div>;
  return <SetView set={set} />;
}

export default function HypothesisTrace({ set, investigationId }: {
  /** The set as it rode the answer. Takes precedence over `investigationId`. */
  set?: AiHypothesisSet | null;
  /** Read a held set back by its id (the investigation's decision id). */
  investigationId?: string;
}) {
  if (set) return <SetView set={set} />;
  if (investigationId) return <LoadedSet id={investigationId} />;
  return null;
}
