// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// IrisLearning — Administration → Iris → Learning (tracker 337 N-F5).
//
// What operators already told Correlix — how incidents were fixed, which
// entity an answer should have meant, which questions Iris could not answer —
// comes back here as SUGGESTIONS. A person decides each one; nothing changes on
// its own and nothing retrains a model. The page is the workflow, in order:
//   1. Look for suggestions   → POST /api/ai/learning/refresh
//   2. Decide                 → POST /{id}/adopt {edit} (as you) | /{id}/dismiss {reason}
//   3. Second person          → POST /{id}/approve (a fact or an alias; a runbook is
//                               finished and approved on the Runbooks page)
//   4. Decided                → applied or dismissed
//
// TWO PEOPLE: the server refuses an approval by the person who adopted (or, for
// a fact, wrote) it; the page does not offer one. An operator's own note is
// shown as quoted evidence for the reviewer and is never part of a draft.
//
// §3a: every call is the caller's own workspace (from the token); the page never
// sends a tenant. All text is rendered as text.

import { useCallback, useEffect, useState } from "react";
import { api, LearningEdit, LearningList, LearningProposal } from "../../services/api";
import { fmtDateTime } from "../../lib/time";
import { operatorError } from "../../lib/errors";

const TARGET_LABEL: Record<LearningProposal["target"], string> = {
  org_context: "Network context fact",
  runbook: "Runbook draft",
  alias: "Iris alias",
};

const TARGET_STATE_LABEL: Record<string, string> = {
  pending: "Waiting for a second administrator",
  active: "Approved — Iris reads it",
  rejected: "Not approved",
  retired: "Stopped",
  superseded: "Replaced by a newer version",
  draft: "Draft — finish it on the Runbooks page",
  waiting_for_second_person: "Waiting for a second administrator",
  written: "Saved — Iris understands it",
  gone: "Removed",
};

const PLACEHOLDER = "{{";

type Run = (what: () => Promise<unknown>, done: string | ((out: unknown) => string)) => Promise<void>;

export default function IrisLearning() {
  const [data, setData] = useState<LearningList | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setData(await api.learning());
      setError(null);
    } catch (e) {
      setError(operatorError(e, "Suggestions could not be loaded."));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const run: Run = async (what, done) => {
    setBusy(true);
    setNotice(null);
    try {
      const out = await what();
      setNotice(typeof done === "function" ? done(out) : done);
      setError(null);
      await load();
    } catch (e) {
      setError(operatorError(e, "That did not work."));
    } finally {
      setBusy(false);
    }
  };

  const you = data?.you ?? "";
  const ps = data?.proposals ?? [];
  const open = ps.filter((p) => p.state === "proposed");
  const waiting = ps.filter((p) => p.state === "adopted");
  const decided = ps.filter((p) => p.state === "applied" || p.state === "dismissed");

  return (
    <div className="card disc-card nctx" style={{ marginBottom: 16 }}>
      <div className="disc-head">
        <div>
          <h2 className="disc-title">Iris learning</h2>
          <p className="disc-desc">
            Suggestions drawn from how your team fixed incidents and corrected Iris. Nothing changes until a person
            adopts a suggestion and a second administrator approves it.
          </p>
        </div>
      </div>
      {error && (
        <div className="disc-refusal" role="alert">
          {error}
        </div>
      )}
      {notice && (
        <p className="disc-text" role="status">
          {notice}
        </p>
      )}
      <ol className="disc-steps" aria-label="Learning workflow">
        <li className="disc-step">
          <span className="disc-step-num" aria-hidden>
            1
          </span>
          <div className="disc-step-body">
            <h3 className="disc-step-title">Look for suggestions</h3>
            <button
              type="button"
              className="btn"
              disabled={busy || !data}
              onClick={() =>
                run(
                  () => api.learningRefresh(),
                  (out) => {
                    const r = out as { added: number; refreshed: number };
                    return `${r.added} new, ${r.refreshed} updated.`;
                  },
                )
              }
            >
              Look now
            </button>
          </div>
        </li>
        <li className="disc-step">
          <span className="disc-step-num" aria-hidden>
            2
          </span>
          <div className="disc-step-body">
            <h3 className="disc-step-title">Suggestions to decide</h3>
            {open.length === 0 ? (
              <p className="disc-text">Nothing to decide right now.</p>
            ) : (
              open.map((p) => <Decide key={p.id} p={p} busy={busy} run={run} />)
            )}
          </div>
        </li>
        <li className="disc-step">
          <span className="disc-step-num" aria-hidden>
            3
          </span>
          <div className="disc-step-body">
            <h3 className="disc-step-title">Second person</h3>
            {waiting.length === 0 ? (
              <p className="disc-text">Nothing is waiting for a second person.</p>
            ) : (
              waiting.map((p) => <Waiting key={p.id} p={p} you={you} busy={busy} run={run} />)
            )}
          </div>
        </li>
        <li className="disc-step">
          <span className="disc-step-num" aria-hidden>
            4
          </span>
          <div className="disc-step-body">
            <h3 className="disc-step-title">Decided</h3>
            {decided.length === 0 ? (
              <p className="disc-text">Nothing decided yet.</p>
            ) : (
              <ul className="lrn-decided" data-testid="lrn-decided">
                {decided.map((p) => (
                  <li key={p.id}>
                    <strong>{p.title}</strong> —{" "}
                    {p.state === "dismissed"
                      ? `dismissed by ${p.decided_by ?? "someone"}: ${p.reason ?? ""}`
                      : TARGET_STATE_LABEL[p.target_state ?? ""] ?? "approved"}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </li>
      </ol>
    </div>
  );
}

function Evidence({ p }: { p: LearningProposal }) {
  return (
    <details className="lrn-evidence">
      <summary>
        Sources ({p.evidence_count}
        {p.evidence_count > p.evidence.length ? `, newest ${p.evidence.length} shown` : ""})
      </summary>
      <ul>
        {p.evidence.map((e, i) => (
          <li key={`${e.ref}-${i}`}>
            {fmtDateTime(e.at)} — {e.label}
            {e.quote ? (
              <blockquote className="lrn-quote" data-testid="lrn-quote">
                Operator's note, for you only — never sent to Iris: “{e.quote}”
              </blockquote>
            ) : null}
          </li>
        ))}
      </ul>
    </details>
  );
}

function Decide({ p, busy, run }: { p: LearningProposal; busy: boolean; run: Run }) {
  const [body, setBody] = useState(p.context?.body ?? "");
  const [key, setKey] = useState(p.context?.key ?? "");
  const [alias, setAlias] = useState(p.alias?.alias ?? "");
  const [name, setName] = useState(p.runbook?.name ?? "");
  const [reason, setReason] = useState("");

  const edit: LearningEdit = {};
  if (p.context) {
    if (body !== p.context.body) edit.body = body;
    if (key !== p.context.key) edit.key = key;
  }
  if (p.alias && alias !== p.alias.alias) edit.alias = alias;
  if (p.runbook && name !== p.runbook.name) edit.name = name;
  const unfinished = (p.context ? body + key : p.alias ? alias : "").includes(PLACEHOLDER);

  return (
    <div className="lrn-card" data-testid="lrn-open">
      <p className="disc-text">
        <strong>{p.title}</strong> · {TARGET_LABEL[p.target]}
      </p>
      <p className="disc-text">{p.why}</p>
      {p.context && (
        <>
          <label className="disc-label">
            Name
            <input className="disc-input" value={key} onChange={(e) => setKey(e.target.value)} />
          </label>
          <label className="disc-label">
            Fact
            <textarea className="disc-input" rows={3} value={body} onChange={(e) => setBody(e.target.value)} />
          </label>
        </>
      )}
      {p.alias && (
        <label className="disc-label">
          Words that mean {p.alias.entity_id}
          <input className="disc-input" value={alias} onChange={(e) => setAlias(e.target.value)} />
        </label>
      )}
      {p.runbook && (
        <label className="disc-label">
          Runbook name
          <input className="disc-input" value={name} onChange={(e) => setName(e.target.value)} />
        </label>
      )}
      {unfinished && (
        <p className="disc-text" role="note">
          Replace each part in {"{{ }}"} before adopting.
        </p>
      )}
      <Evidence p={p} />
      <div className="disc-actions">
        <button
          type="button"
          className="btn btn-primary"
          disabled={busy || unfinished}
          onClick={() =>
            run(
              () => api.learningAdopt(p.id, edit),
              p.target === "runbook"
                ? "Adopted as a runbook draft. Finish and submit it on the Runbooks page."
                : "Adopted. A second administrator approves it next.",
            )
          }
        >
          Adopt
        </button>
        <input
          className="disc-input"
          aria-label="Reason to dismiss"
          placeholder="Reason to dismiss"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
        />
        <button
          type="button"
          className="btn"
          disabled={busy || reason.trim() === ""}
          onClick={() => run(() => api.learningDismiss(p.id, reason.trim()), "Dismissed. It will not be suggested again.")}
        >
          Dismiss
        </button>
      </div>
    </div>
  );
}

function Waiting({ p, you, busy, run }: { p: LearningProposal; you: string; busy: boolean; run: Run }) {
  const mine = p.adopted_by === you;
  const preview = p.context?.body ?? p.alias?.alias ?? p.runbook?.name ?? "";
  return (
    <div className="lrn-card" data-testid="lrn-waiting">
      <p className="disc-text">
        <strong>{p.title}</strong> · {TARGET_LABEL[p.target]} · adopted by {p.adopted_by}
      </p>
      <p className="disc-text">“{preview}”</p>
      <p className="disc-text">{TARGET_STATE_LABEL[p.target_state ?? ""] ?? p.target_state}</p>
      <Evidence p={p} />
      {p.target === "runbook" ? (
        <p className="disc-text">Approve it on the Runbooks page.</p>
      ) : mine ? (
        <p className="disc-text">Another administrator approves this one.</p>
      ) : p.target_state === "pending" || p.target_state === "waiting_for_second_person" ? (
        <button
          type="button"
          className="btn btn-primary"
          disabled={busy}
          onClick={() => run(() => api.learningApprove(p.id), "Approved. Iris uses it from now on.")}
        >
          Approve
        </button>
      ) : null}
    </div>
  );
}
