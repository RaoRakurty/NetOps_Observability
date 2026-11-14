// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// InvestigationTrace — how one read-only Iris investigation ran (tracker 337
// N-I1), drawn under its answer.
//
// What it shows, top to bottom:
//   1. the outcome in words (concluded / inconclusive / no evidence / not run)
//      and what was investigated;
//   2. the CORRELATION ENGINE's verdict, labelled as the engine's, when an
//      incident was in scope — it was read first, and the investigation is
//      read against it, never instead of it;
//   3. the numbered steps the server took (bind → context → engine verdict →
//      runbooks → plan → passes → diagnosis), each with its outcome as a WORD;
//   4. on demand: the methods and runbooks considered (and why one did not
//      apply), each pass's path, and what the investigation spent against its
//      budget, with the reason it stopped early when it did.
//
// Every string is server data rendered as an escaped React text node; there is
// no markup parsing and no link built from trace text. Fonts stay on the
// 14 / 16 px scale (NOC-admin UI standard).

import { useEffect, useState } from "react";
import { api, type AiInvestigationTrace } from "../services/api";
import { httpFailure, operatorError } from "../lib/errors";

const text14 = { fontSize: 14, lineHeight: 1.5 } as const;
const muted14 = { ...text14, color: "var(--muted)" } as const;
const heading16 = { fontSize: 16, fontWeight: 600, margin: "0 0 4px" } as const;

/** The operator's words for an investigation's status. */
export function statusWord(status: string | undefined): string {
  switch ((status || "").trim()) {
    case "concluded": return "Investigation concluded";
    case "inconclusive": return "Investigation inconclusive";
    case "no_evidence": return "Investigation found no evidence";
    case "refused": return "Investigation not run";
    default: return (status || "").trim() || "Investigation";
  }
}

/** The operator's word for a step outcome — never colour alone. */
export function outcomeWord(outcome: string | undefined): string {
  switch ((outcome || "").trim()) {
    case "ok": return "Done";
    case "none": return "Nothing";
    case "skipped": return "Skipped";
    case "not_found": return "Not found";
    case "denied": return "Not allowed";
    case "error": return "Failed";
    case "cutoff": return "Stopped";
    default: return (outcome || "").trim();
  }
}

const STEP_WORD: Record<string, string> = {
  bind: "Scope", context: "Network context", rca: "Engine verdict", runbooks: "Runbooks and methods",
  plan: "Plan", pass: "Pass", agent: "AI lookups", stop: "Stopped", diagnosis: "Diagnosis",
};

export function stepWord(kind: string | undefined): string {
  const k = (kind || "").trim();
  return STEP_WORD[k] ?? k;
}

const SOURCE_WORD: Record<string, string> = {
  runbook_link: "your runbook, linked here", selected: "matches the question", entry_method: "top-level method",
};

const CUTOFF_WORD: Record<string, string> = {
  passes: "pass budget", tool_calls: "lookup budget", tokens: "AI-model budget", time: "time budget",
};

export function targetLine(t: AiInvestigationTrace["target"] | undefined): string {
  const dev = (t?.device || "").trim();
  const inc = (t?.correlation_id || "").trim();
  if (dev && inc) return `${dev}, within incident ${inc}`;
  if (dev) return dev;
  if (inc) return `incident ${inc}`;
  return "the question, with no device or incident named";
}

function TraceBody({ trace }: { trace: AiInvestigationTrace }) {
  const [open, setOpen] = useState(false);
  const steps = trace.steps ?? [];
  const tier = (trace.engine?.tier || "").trim();
  const cutoffs = trace.cutoffs ?? [];
  return (
    <section className="iris-investigation" aria-label="Investigation trace" data-testid="iris-investigation"
      style={{ borderTop: "1px solid var(--border)", marginTop: 8, paddingTop: 8 }}>
      <h4 style={heading16}>{statusWord(trace.status)}</h4>
      <p style={muted14}>Investigated: {targetLine(trace.target)}</p>
      {trace.engine && (
        <div data-testid="iris-investigation-engine" style={{ margin: "6px 0" }}>
          <div style={{ ...text14, fontWeight: 600 }}>
            {tier ? `Correlation engine verdict: ${tier}` : "Correlation engine: no verdict yet"}
          </div>
          {trace.engine.statement && <div style={text14}>{trace.engine.statement}</div>}
          <div style={muted14}>Read first. The investigation is read against it; only the engine names a root cause.</div>
        </div>
      )}
      <ol data-testid="iris-investigation-steps" style={{ ...text14, paddingLeft: 20, margin: "6px 0" }}>
        {steps.map((s) => (
          <li key={s.seq} data-testid="iris-investigation-step">
            <strong>{stepWord(s.kind)}</strong> — {outcomeWord(s.outcome)}: {s.summary}
          </li>
        ))}
      </ol>
      {cutoffs.length > 0 && (
        <p style={muted14} data-testid="iris-investigation-cutoffs">
          Stopped early at its {cutoffs.map((c) => CUTOFF_WORD[c] ?? c).join(", ")}; methods it did not reach were not run.
        </p>
      )}
      <button type="button" className="chip-btn" onClick={() => setOpen((v) => !v)} aria-expanded={open} style={text14}>
        {open ? "Hide details" : "Show details"}
      </button>
      {open && (
        <div data-testid="iris-investigation-details" style={{ marginTop: 6 }}>
          {(trace.candidates ?? []).length > 0 && (
            <>
              <div style={{ ...text14, fontWeight: 600 }}>Methods considered</div>
              <ul style={{ ...text14, paddingLeft: 20, margin: "2px 0 6px" }}>
                {(trace.candidates ?? []).map((c) => (
                  <li key={c.skill}>
                    {c.skill} ({SOURCE_WORD[c.source] ?? c.source}) — {c.applies ? "applies" : "does not apply"}
                    {c.why ? `: ${c.why}` : ""}
                  </li>
                ))}
              </ul>
            </>
          )}
          {(trace.passes ?? []).length > 0 && (
            <>
              <div style={{ ...text14, fontWeight: 600 }}>Passes</div>
              <ol style={{ ...text14, paddingLeft: 20, margin: "2px 0 6px" }}>
                {(trace.passes ?? []).map((p) => (
                  <li key={p.pass}>
                    {(p.chain ?? []).length > 0 ? (p.chain ?? []).map((h) => h.name).join(" → ") : p.entry}
                    {p.answered
                      ? ` — ${p.tool_calls} lookup${p.tool_calls === 1 ? "" : "s"}; ${p.supported} supported, ${p.rejected} ruled out, ${p.inconclusive} inconclusive`
                      : " — gathered no evidence"}
                  </li>
                ))}
              </ol>
            </>
          )}
          <p style={muted14} data-testid="iris-investigation-budget">
            Spent {trace.used.passes} of {trace.budget.max_passes} passes, {trace.used.tool_calls} of {trace.budget.max_tool_calls} lookups,
            {" "}{trace.used.tokens} of {trace.budget.max_tokens} AI-model tokens, in {Math.round(trace.used.duration_ms / 1000)} of {trace.budget.wall_seconds} seconds.
            {trace.context_applied ? " Your approved network context was applied." : ""}
            {" "}Read-only: nothing was changed on your network.
          </p>
        </div>
      )}
    </section>
  );
}

/** The trace either rides the answer (`trace`) or is read back by its id. */
export default function InvestigationTrace({ trace, investigationId }: {
  trace?: AiInvestigationTrace;
  investigationId?: string;
}) {
  const [loaded, setLoaded] = useState<AiInvestigationTrace | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    if (trace || !investigationId) return;
    let live = true;
    void (async () => {
      try {
        const t = await api.aiInvestigation(investigationId);
        if (live) setLoaded(t);
      } catch (e) {
        if (!live) return;
        setErr(httpFailure(e)?.status === 404
          ? "This investigation is no longer held."
          : operatorError(e, "The investigation could not be read."));
      }
    })();
    return () => { live = false; };
  }, [trace, investigationId]);
  const t = trace ?? loaded;
  if (err) return <p style={muted14} role="alert">{err}</p>;
  if (!t) return investigationId ? <p style={muted14}>Loading the investigation…</p> : null;
  return <TraceBody trace={t} />;
}
