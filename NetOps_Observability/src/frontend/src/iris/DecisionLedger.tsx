// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// DecisionLedger — how each Iris answer was reached (tracker 337 N-A6). Every
// answer from the Iris box is one DECISION in an append-only ledger: the
// question received, the plan, each policy check and tool run, the evidence,
// the answer returned. The ledger holds fingerprints (SHA-256) of what was
// asked and read — never the question, the data or the answer text — so this
// panel shows the steps, the model and tools that acted, and short hashes.
//
// Workspace admins read their workspace's ledger; the server decides who may
// and scopes it. Every field is rendered as escaped React text.

import { useCallback, useEffect, useState } from "react";
import { api, type AiDecisionEntry, type AiDecisionEventType } from "../services/api";
import { httpFailure, operatorError } from "../lib/errors";

export const EVENT_LABEL: Record<AiDecisionEventType, string> = {
  QUESTION_RECEIVED: "question received", INVESTIGATION_STARTED: "investigation started",
  PLAN_CREATED: "plan made", TOOL_SELECTED: "tool chosen (not available)", TOOL_EXECUTED: "tool ran",
  EVIDENCE_ADDED: "evidence cited", HYPOTHESIS_CREATED: "hypothesis", HYPOTHESIS_REJECTED: "hypothesis rejected",
  ROOT_CAUSE_SELECTED: "root cause chosen", RECOMMENDATION_CREATED: "next steps recommended",
  ACTION_REQUESTED: "action requested", POLICY_EVALUATED: "policy checked", APPROVAL_RECEIVED: "approval received",
  EXECUTION_STARTED: "execution started", VERIFICATION_COMPLETED: "verification completed",
  ROLLBACK_EXECUTED: "rollback executed", ANSWER_RETURNED: "answer returned",
};

const RECENT_ENTRIES = 200;
const text14 = { fontSize: 14 } as const;
const muted = { color: "var(--muted)", fontSize: 14 } as const;
const mono = { fontFamily: "var(--font-mono, monospace)", fontSize: 13 } as const;

function when(at: string): string {
  const d = new Date(at);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleString();
}

// short is the first 12 hex characters of a hash: enough to compare by eye.
function short(h?: string): string {
  return h ? h.slice(0, 12) : "";
}

interface DecisionSummary {
  id: string;
  at: string;
  principal: string;
  tenant?: string;
  answer?: AiDecisionEntry;
  steps: number;
}

// summarize groups a newest-first page of entries into decisions, newest first.
// A decision cut by the page edge still shows; its step count is what was seen.
export function summarize(entries: AiDecisionEntry[]): DecisionSummary[] {
  const byID = new Map<string, DecisionSummary>();
  for (const e of entries) {
    let d = byID.get(e.decision_id);
    if (!d) {
      d = { id: e.decision_id, at: e.at, principal: e.principal, tenant: e.tenant, steps: 0 };
      byID.set(e.decision_id, d);
    }
    d.steps++;
    if (e.at < d.at) d.at = e.at;
    if (e.event_type === "ANSWER_RETURNED") d.answer = e;
  }
  return [...byID.values()].sort((a, b) => (a.at < b.at ? 1 : a.at > b.at ? -1 : 0));
}

function answerLine(a?: AiDecisionEntry): string {
  if (!a) return "no answer recorded in this page";
  const model = a.model_name ? `${a.model_provider ? a.model_provider + " " : ""}${a.model_name}` : a.model_tier || "no model";
  return [a.outcome, a.mode, model].filter(Boolean).join(" · ");
}

function Steps({ decisionId }: { decisionId: string }) {
  const [steps, setSteps] = useState<AiDecisionEntry[] | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => {
    let live = true;
    api.aiDecisions({ decisionId, limit: RECENT_ENTRIES })
      .then((r) => { if (live) setSteps(r.decisions ?? []); })
      .catch((e) => { if (live) setErr(operatorError(e, "The steps of this decision could not be loaded.")); });
    return () => { live = false; };
  }, [decisionId]);
  if (err) return <div role="alert" style={{ ...text14, color: "var(--bad)" }}>{err}</div>;
  if (!steps) return <div style={muted}>Loading steps…</div>;
  return (
    <ol start={0} style={{ margin: "4px 0 0", paddingLeft: 22 }} data-testid="iris-decision-steps">
      {steps.map((s) => (
        <li key={s.id} style={{ ...text14, marginBottom: 2 }}>
          <span>{EVENT_LABEL[s.event_type] ?? s.event_type}</span>
          {s.tool && <span style={mono}> {s.tool}</span>}
          {s.skill && <span style={muted}> — method {s.skill}</span>}
          {s.outcome && <span style={muted}> — {s.outcome}</span>}
          {typeof s.item_count === "number" && s.item_count > 0 && <span style={muted}> — {s.item_count} item{s.item_count === 1 ? "" : "s"}</span>}
          {s.args_sha256 && <span style={mono} title={s.args_sha256}> args {short(s.args_sha256)}</span>}
          {s.result_sha256 && <span style={mono} title={s.result_sha256}> result {short(s.result_sha256)}</span>}
        </li>
      ))}
    </ol>
  );
}

export default function DecisionLedger({ refreshKey = 0 }: { refreshKey?: number }) {
  const [decisions, setDecisions] = useState<DecisionSummary[]>([]);
  const [platform, setPlatform] = useState(false);
  const [open, setOpen] = useState<string>("");
  const [err, setErr] = useState("");
  const [forbidden, setForbidden] = useState(false);
  const [loaded, setLoaded] = useState(false);

  const load = useCallback(async () => {
    try {
      const r = await api.aiDecisions({ limit: RECENT_ENTRIES });
      setDecisions(summarize(r.decisions ?? []));
      setPlatform(r.scope === "platform");
      setErr("");
      setForbidden(false);
    } catch (e) {
      setDecisions([]);
      if (httpFailure(e)?.status === 403) {
        setForbidden(true);
      } else {
        setErr(operatorError(e, "The decision ledger could not be loaded."));
      }
    } finally {
      setLoaded(true);
    }
  }, []);

  useEffect(() => { void load(); }, [load, refreshKey]);

  if (forbidden) {
    return <div style={muted} data-testid="iris-ledger">Only workspace admins can read the decision ledger.</div>;
  }
  return (
    <div data-testid="iris-ledger">
      {err && <div role="alert" style={{ ...text14, color: "var(--bad)" }}>{err}</div>}
      {loaded && !err && decisions.length === 0 && <div style={muted}>No decisions recorded yet.</div>}
      {decisions.length > 0 && (
        <ul style={{ margin: "4px 0 0", paddingLeft: 18 }} data-testid="iris-ledger-list">
          {decisions.map((d) => (
            <li key={d.id} style={{ ...text14, marginBottom: 6 }}>
              <span>{when(d.at)}</span>{" "}
              <span style={muted}>
                — asked by {d.principal}{platform && d.tenant ? ` (${d.tenant})` : ""}, {answerLine(d.answer)}, {d.steps} step{d.steps === 1 ? "" : "s"}
              </span>{" "}
              <button type="button" className="dash-btn" style={text14} aria-expanded={open === d.id}
                onClick={() => setOpen(open === d.id ? "" : d.id)}>
                {open === d.id ? "Hide steps" : "Show steps"}
              </button>
              {open === d.id && <Steps decisionId={d.id} />}
            </li>
          ))}
        </ul>
      )}
      <div style={muted}>Fingerprints only: the ledger never stores questions, data or answers. Entries cannot be changed or deleted.</div>
    </div>
  );
}
