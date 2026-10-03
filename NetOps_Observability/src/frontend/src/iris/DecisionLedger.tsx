// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// DecisionLedger — how Iris answers were reached (tracker 337 N-A6). Workspace
// admins see their workspace's recent decisions; the platform owner sees every
// workspace's. Each decision is its steps in order: the question received, the
// plan, each policy check and tool run (with the tool version), the evidence,
// and the answer (with the model that gave it).
//
// The ledger holds HASHES, counts and closed tokens — never the question, the
// data or the answer text — so this view shows fingerprints, not content. A
// decision id from an answer can be looked up directly; one outside the
// caller's workspace is "not found", exactly like one that never existed. The
// server decides who may read and scopes every read; nothing here is trusted
// beyond rendering it as escaped text.

import { useCallback, useEffect, useState } from "react";
import { api, type AiDecisionEntry } from "../services/api";
import { httpFailure, operatorError } from "../lib/errors";

export const EVENT_LABEL: Record<string, string> = {
  QUESTION_RECEIVED: "Question received",
  INVESTIGATION_STARTED: "Investigation started",
  PLAN_CREATED: "Plan made",
  TOOL_SELECTED: "Tool chosen (not available)",
  TOOL_EXECUTED: "Tool ran",
  EVIDENCE_ADDED: "Evidence cited",
  HYPOTHESIS_CREATED: "Hypothesis",
  HYPOTHESIS_REJECTED: "Hypothesis rejected",
  ROOT_CAUSE_SELECTED: "Root cause selected",
  RECOMMENDATION_CREATED: "Recommendation made",
  ACTION_REQUESTED: "Action requested",
  POLICY_EVALUATED: "Policy check",
  APPROVAL_RECEIVED: "Approval received",
  EXECUTION_STARTED: "Execution started",
  VERIFICATION_COMPLETED: "Verification completed",
  ROLLBACK_EXECUTED: "Rollback executed",
  ANSWER_RETURNED: "Answer returned",
};

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const text14 = { fontSize: 14 } as const;
const muted = { color: "var(--muted)", fontSize: 14 } as const;

function when(at: string): string {
  const d = new Date(at);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleString();
}

// short shows the first 12 hex characters of a hash — enough to compare by eye.
function short(h?: string): string {
  return h ? h.slice(0, 12) : "";
}

type Decision = { id: string; tenant?: string; principal: string; at: string; steps: AiDecisionEntry[] };

// group folds entries into decisions, newest decision first, steps in seq order.
export function group(entries: AiDecisionEntry[]): Decision[] {
  const by = new Map<string, Decision>();
  for (const e of entries) {
    let d = by.get(e.decision_id);
    if (!d) {
      d = { id: e.decision_id, tenant: e.tenant, principal: e.principal, at: e.at, steps: [] };
      by.set(e.decision_id, d);
    }
    d.steps.push(e);
    if (e.at > d.at) d.at = e.at;
  }
  const out = [...by.values()];
  for (const d of out) d.steps.sort((a, b) => a.seq - b.seq);
  out.sort((a, b) => (a.at < b.at ? 1 : a.at > b.at ? -1 : 0));
  return out;
}

function StepLine({ e }: { e: AiDecisionEntry }) {
  const parts: string[] = [];
  if (e.skill) parts.push(`method ${e.skill}`);
  if (e.tool) parts.push(e.tool_version ? `${e.tool} (${e.tool_version})` : e.tool);
  if (e.intent) parts.push(e.intent);
  if (e.mode) parts.push(e.mode);
  if (e.model_name || e.model_provider) parts.push(`model ${[e.model_provider, e.model_name].filter(Boolean).join("/")}`);
  if (e.model_tier) parts.push(`tier ${e.model_tier}`);
  if (e.outcome) parts.push(e.outcome);
  if (e.item_count) parts.push(`${e.item_count} item${e.item_count === 1 ? "" : "s"}`);
  if (e.incident_ref) parts.push(`incident ${e.incident_ref}`);
  return (
    <li style={text14} data-testid="iris-decision-step">
      <strong>{EVENT_LABEL[e.event_type] ?? e.event_type}</strong>
      {parts.length > 0 && <> — {parts.join(", ")}</>}
      {(e.args_sha256 || e.result_sha256) && (
        <span style={muted}>
          {" "}
          {e.args_sha256 && <>asked <code>{short(e.args_sha256)}</code></>}
          {e.args_sha256 && e.result_sha256 && " · "}
          {e.result_sha256 && <>read <code>{short(e.result_sha256)}</code></>}
        </span>
      )}
    </li>
  );
}

export default function DecisionLedger() {
  const [decisions, setDecisions] = useState<Decision[]>([]);
  const [platform, setPlatform] = useState(false);
  const [lookup, setLookup] = useState("");
  const [shown, setShown] = useState(""); // the decision id being shown, "" = recent
  const [err, setErr] = useState("");
  const [loaded, setLoaded] = useState(false);

  const load = useCallback(async (id: string) => {
    try {
      const r = await api.aiDecisions(id || undefined);
      setDecisions(group(r.decisions ?? []));
      setPlatform(r.scope === "platform");
      setErr("");
    } catch (e) {
      setDecisions([]);
      const f = httpFailure(e);
      if (id && f?.status === 404) setErr("No decision with that id in your workspace.");
      else if (f?.status === 403) setErr("The decision ledger is for workspace admins.");
      else setErr(operatorError(e, "The decision ledger could not be loaded."));
    } finally {
      setLoaded(true);
    }
  }, []);

  useEffect(() => { void load(shown); }, [load, shown]);

  const id = lookup.trim().toLowerCase();
  const idOK = UUID_RE.test(id);

  return (
    <div data-testid="iris-decisions">
      <form
        style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}
        onSubmit={(ev) => { ev.preventDefault(); if (idOK) setShown(id); }}
      >
        <input
          aria-label="Decision id"
          placeholder="Decision id from an answer"
          style={{ ...text14, minWidth: 300 }}
          value={lookup}
          onChange={(ev) => setLookup(ev.target.value)}
        />
        <button type="submit" className="btn" style={text14} disabled={!idOK}>Look up</button>
        {shown && <button type="button" className="btn" style={text14} onClick={() => { setLookup(""); setShown(""); }}>Show recent</button>}
      </form>
      {err && <div role="alert" style={{ ...text14, color: "var(--bad)" }}>{err}</div>}
      {loaded && !err && decisions.length === 0 && <div style={muted}>No decisions recorded yet.</div>}
      {decisions.length > 0 && (
        <ul style={{ margin: "4px 0 0", paddingLeft: 18 }} data-testid="iris-decision-list">
          {decisions.map((d) => (
            <li key={d.id} style={{ ...text14, marginBottom: 8 }}>
              <code>{d.id}</code>{" "}
              <span style={muted}>— asked by {d.principal}, {when(d.at)}{platform && d.tenant && <>, workspace {d.tenant}</>}</span>
              <ol style={{ margin: "2px 0 0", paddingLeft: 18 }}>
                {d.steps.map((e) => <StepLine key={e.id} e={e} />)}
              </ol>
            </li>
          ))}
        </ul>
      )}
      <div style={muted}>Fingerprints (SHA-256) only: the ledger never keeps the question, the data or the answer text. Records are append-only.</div>
    </div>
  );
}
