// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// TenantRunbooks — Administration → Iris → Runbooks (tracker 337 N-F2).
//
// A workspace's own troubleshooting methods (investigative runbooks) and
// procedures for a person (MOPs), written in the same format as Correlix's
// built-in methods. The page is the workflow, in order:
//   1. Write a runbook           → POST /api/ai/runbooks (a draft)
//   2. Check and submit → POST /{id}/check, /{id}/submit (the cases run)
//   3. Review (another admin)    → POST /{id}/approve {version, body_sha256} | /reject
//   4. What Iris runs            → runs_in_iris / needs_recheck, POST /{id}/reprove
// plus each runbook's history (restore, stop using) and links (what it is about).
//
// TWO PEOPLE: the server refuses an approval by the version's author; the page
// does not offer one. The approval carries the hash of the text on screen, so a
// text changed after it was read is refused, never approved blind.
//
// §3a: every call is the caller's own workspace (from the token); the page never
// sends a tenant. All runbook text is rendered as text.

import { useCallback, useEffect, useState } from "react";
import {
  api,
  Runbook,
  RunbookCaseProblem,
  RunbookKind,
  RunbookLink,
  RunbookLinkType,
  RunbookList,
  RunbookVersion,
} from "../../services/api";
import { fmtDateTime } from "../../lib/time";
import { httpFailure, operatorError } from "../../lib/errors";

const STATE_LABEL: Record<string, string> = {
  draft: "Draft",
  pending: "Waiting for review",
  active: "Approved",
  superseded: "Replaced",
  rejected: "Not approved",
  retired: "Stopped",
};

const KIND_LABEL: Record<RunbookKind, string> = {
  investigative: "Troubleshooting method (Iris runs it)",
  mop: "Procedure for a person (Iris shows it, never runs it)",
};

const LINK_LABEL: Record<RunbookLinkType, string> = {
  alert: "Alert rule",
  signature: "Problem signature",
  entity: "Device, site, circuit or application",
  incident: "Incident",
};

const LINK_HINT: Record<RunbookLinkType, string> = {
  alert: "BgpSessionDown",
  signature: "bgp_session_down",
  entity: "device:edge-1",
  incident: "the incident id",
};

// The server's limits (internal/tenantrunbook, ai.ParseSkillSource).
const SKILL_MD_BYTES = 16 * 1024;
const CASES_BYTES = 32 * 1024;

const STARTER_MD = `---
name: my-wan-check
layer: path_seam
version: 1
when_to_use: our carrier brownout, our circuit fault
symptom_kinds: wan
tools: get_rca_verdict, search_logs
gather:
  - get_rca_verdict(correlation_id)
  - search_logs(query=WAN, window=6h)
look_for:
  - the carrier ticket number
decisions:
  - next=log-confirmation when evidence:kind=log the logs name the carrier
  - verdict=name the carrier circuit
  - escalate=the carrier NOC
---
First read the carrier portal, then compare the handoff counters.
`;

function bytes(s: string): number {
  return new TextEncoder().encode(s).length;
}

function openVersion(r: Runbook): RunbookVersion | undefined {
  return r.versions.find((v) => v.state === "draft" || v.state === "pending");
}

function activeVersion(r: Runbook): RunbookVersion | undefined {
  return r.versions.find((v) => v.state === "active");
}

/** The case problems a 422 carries, or null when the failure is something else. */
function caseProblems(e: unknown): RunbookCaseProblem[] | null {
  const f = httpFailure(e);
  if (!f || f.status !== 422) return null;
  try {
    const parsed = JSON.parse(f.body) as { problems?: RunbookCaseProblem[] };
    return Array.isArray(parsed.problems) ? parsed.problems : [];
  } catch {
    return [];
  }
}

export default function TenantRunbooks() {
  const [data, setData] = useState<RunbookList | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [problems, setProblems] = useState<RunbookCaseProblem[] | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setData(await api.runbooks());
      setError(null);
    } catch (e) {
      setError(operatorError(e, "Runbooks could not be loaded."));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const run: Run = async (what, done) => {
    setBusy(true);
    setNotice(null);
    setProblems(null);
    try {
      const out = await what();
      setNotice(typeof done === "function" ? done(out) : done);
      setError(null);
      await load();
    } catch (e) {
      const cp = caseProblems(e);
      if (cp) {
        setError("The runbook's cases did not pass, so nothing was changed. Fix the points below and try again.");
        setProblems(cp);
      } else {
        setError(operatorError(e, "That did not work."));
      }
    } finally {
      setBusy(false);
    }
  };

  const you = data?.you ?? "";
  const rbs = data?.runbooks ?? [];
  const mineOpen = rbs.filter((r) => {
    const v = openVersion(r);
    return v && v.author === you;
  });
  const toReview = rbs.filter((r) => {
    const v = openVersion(r);
    return v && v.state === "pending" && v.author !== you;
  });
  const approved = rbs.filter((r) => activeVersion(r));

  return (
    <div className="card disc-card nctx" style={{ marginBottom: 16 }}>
      <div className="disc-head">
        <div>
          <h2 className="disc-title">Runbooks</h2>
          <p className="disc-desc">
            Your own troubleshooting methods and procedures, in the same format as Iris's built-in methods. A runbook
            reaches Iris only after its test cases pass and a second administrator approves it. Iris follows only the
            next steps a runbook names, and never runs a procedure meant for a person.
          </p>
        </div>
      </div>
      {error && (
        <div className="disc-refusal" role="alert">
          {error}
          {problems && problems.length > 0 && (
            <ul className="rbk-problems" data-testid="rbk-problems">
              {problems.map((p, i) => (
                <li key={i}>
                  {p.case ? <strong>{p.case}: </strong> : null}
                  {p.message}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
      {notice && (
        <p className="disc-text" role="status">
          {notice}
        </p>
      )}
      <ol className="disc-steps" aria-label="Runbook workflow">
        <li className="disc-step">
          <span className="disc-step-num" aria-hidden>
            1
          </span>
          <div className="disc-step-body">
            <h3 className="disc-step-title">Write a runbook</h3>
            {data && (
              <NewRunbook
                busy={busy}
                onSave={(r) => run(() => api.runbookCreate(r), "Draft saved. Check it, then send it for review.")}
              />
            )}
          </div>
        </li>
        <li className="disc-step">
          <span className="disc-step-num" aria-hidden>
            2
          </span>
          <div className="disc-step-body">
            <h3 className="disc-step-title">Check and submit</h3>
            {mineOpen.length === 0 ? (
              <p className="disc-text">You have no drafts.</p>
            ) : (
              mineOpen.map((r) => <MyDraft key={r.id} rb={r} busy={busy} run={run} />)
            )}
          </div>
        </li>
        <li className="disc-step">
          <span className="disc-step-num" aria-hidden>
            3
          </span>
          <div className="disc-step-body">
            <h3 className="disc-step-title">Review others' runbooks</h3>
            {toReview.length === 0 ? (
              <p className="disc-text">Nothing is waiting for your review.</p>
            ) : (
              toReview.map((r) => <Review key={r.id} rb={r} busy={busy} run={run} />)
            )}
          </div>
        </li>
        <li className="disc-step">
          <span className="disc-step-num" aria-hidden>
            4
          </span>
          <div className="disc-step-body">
            <h3 className="disc-step-title">What Iris runs</h3>
            {approved.length === 0 ? (
              <p className="disc-text">Iris runs none of your runbooks yet. Approved runbooks appear here.</p>
            ) : (
              <ul className="rbk-status" data-testid="rbk-status">
                {approved.map((r) => (
                  <RunStatus key={r.id} rb={r} busy={busy} run={run} />
                ))}
              </ul>
            )}
          </div>
        </li>
      </ol>
      <h3 className="disc-step-title" style={{ marginTop: 20 }}>
        All runbooks
      </h3>
      {rbs.length === 0 ? (
        <p className="disc-text">No runbooks yet.</p>
      ) : (
        rbs.map((r) => <History key={r.id} rb={r} busy={busy} run={run} />)
      )}
    </div>
  );
}

type Run = (what: () => Promise<unknown>, done: string | ((out: unknown) => string)) => Promise<void>;

function ByteCount({ text, limit }: { text: string; limit: number }) {
  const n = bytes(text);
  return (
    <span className={`nctx-count${n > limit ? " over" : ""}`} aria-live="polite">
      {n} / {limit} bytes
    </span>
  );
}

function SourceFields(props: {
  md: string;
  cases: string;
  kind: RunbookKind;
  setMd: (s: string) => void;
  setCases: (s: string) => void;
  label: string;
}) {
  return (
    <>
      <label className="disc-field">
        <span>The method (SKILL.md)</span>
        <textarea
          className="rbk-src"
          rows={14}
          value={props.md}
          onChange={(e) => props.setMd(e.target.value)}
          aria-label={`${props.label} method text`}
          spellCheck={false}
        />
      </label>
      <ByteCount text={props.md} limit={SKILL_MD_BYTES} />
      {props.kind === "investigative" && (
        <>
          <label className="disc-field">
            <span>Its test cases (CASES.yaml) — what Iris must do, and must never do, for a question</span>
            <textarea
              className="rbk-src"
              rows={10}
              value={props.cases}
              onChange={(e) => props.setCases(e.target.value)}
              aria-label={`${props.label} test cases`}
              spellCheck={false}
            />
          </label>
          <ByteCount text={props.cases} limit={CASES_BYTES} />
        </>
      )}
    </>
  );
}

function NewRunbook(props: { busy: boolean; onSave: (r: { name: string; kind: RunbookKind; skill_md: string; cases_yaml: string }) => void }) {
  const [name, setName] = useState("");
  const [kind, setKind] = useState<RunbookKind>("investigative");
  const [md, setMd] = useState(STARTER_MD);
  const [cases, setCases] = useState("");
  const nameOK = /^[a-z][a-z0-9-]{0,47}$/.test(name);
  const tooLong = bytes(md) > SKILL_MD_BYTES || bytes(cases) > CASES_BYTES;
  return (
    <div className="nctx-form">
      <label className="disc-field">
        <span>Name (lower-case letters, digits and hyphens; it must match the name: line)</span>
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="my-wan-check" />
      </label>
      <label className="disc-field">
        <span>Type</span>
        <select value={kind} onChange={(e) => setKind(e.target.value as RunbookKind)}>
          {(Object.keys(KIND_LABEL) as RunbookKind[]).map((k) => (
            <option key={k} value={k}>
              {KIND_LABEL[k]}
            </option>
          ))}
        </select>
      </label>
      <SourceFields md={md} cases={cases} kind={kind} setMd={setMd} setCases={setCases} label="New runbook" />
      <div className="nctx-actions">
        <button
          className="btn"
          disabled={props.busy || !nameOK || tooLong || !md.trim() || (kind === "investigative" && !cases.trim())}
          onClick={() => props.onSave({ name, kind, skill_md: md, cases_yaml: kind === "mop" ? "" : cases })}
        >
          Save draft
        </button>
      </div>
    </div>
  );
}

function MyDraft({ rb, busy, run }: { rb: Runbook; busy: boolean; run: Run }) {
  const v = openVersion(rb)!;
  const [md, setMd] = useState(v.skill_md);
  const [cases, setCases] = useState(v.cases_yaml);
  useEffect(() => {
    setMd(v.skill_md);
    setCases(v.cases_yaml);
  }, [v.skill_md, v.cases_yaml]);
  const head = `${rb.name} · ${KIND_LABEL[rb.kind]} · version ${v.version}`;
  if (v.state === "pending") {
    return (
      <div className="nctx-item">
        <div className="nctx-item-head">{head}</div>
        <p className="disc-text">Its cases passed. Waiting for another administrator to review it.</p>
        <button className="btn" disabled={busy} onClick={() => run(() => api.runbookAct(rb.id, "withdraw"), "Taken back to draft.")}>
          Take back to edit
        </button>
      </div>
    );
  }
  const edited = md !== v.skill_md || cases !== v.cases_yaml;
  return (
    <div className="nctx-item">
      <div className="nctx-item-head">{head}</div>
      <SourceFields md={md} cases={cases} kind={rb.kind} setMd={setMd} setCases={setCases} label={rb.name} />
      <div className="nctx-actions">
        <button
          className="btn"
          disabled={busy || !edited || bytes(md) > SKILL_MD_BYTES || bytes(cases) > CASES_BYTES}
          onClick={() => run(() => api.runbookDraft(rb.id, { skill_md: md, cases_yaml: cases }), "Draft saved.")}
        >
          Save changes
        </button>
        <button
          className="btn"
          disabled={busy || edited}
          onClick={() =>
            run(
              () => api.runbookCheck(rb.id),
              (out) => {
                const c = out as { cases?: number };
                return rb.kind === "mop" ? "The procedure is valid." : `All ${c.cases ?? 0} cases passed. Nothing was changed.`;
              },
            )
          }
        >
          Run its cases
        </button>
        <button className="btn" disabled={busy || edited} onClick={() => run(() => api.runbookAct(rb.id, "submit"), "Its cases passed. Sent for review.")}>
          Send for review
        </button>
        <button className="btn" disabled={busy} onClick={() => run(() => api.runbookDiscard(rb.id), "Draft discarded.")}>
          Discard draft
        </button>
      </div>
    </div>
  );
}

function Review({ rb, busy, run }: { rb: Runbook; busy: boolean; run: Run }) {
  const v = openVersion(rb)!;
  const current = activeVersion(rb);
  const [reason, setReason] = useState("");
  return (
    <div className="nctx-item">
      <div className="nctx-item-head">
        {rb.name} · {KIND_LABEL[rb.kind]} — written by {v.author}
      </div>
      <p className="disc-text">{v.harness_passed ? "Its cases passed when it was sent for review." : "Its cases have not passed."}</p>
      <div className="nctx-compare">
        <div>
          <div className="nctx-col-h">Approved now</div>
          <pre className="rbk-text">{current ? current.skill_md : "Nothing (a new runbook)."}</pre>
        </div>
        <div>
          <div className="nctx-col-h">Proposed</div>
          <pre className="rbk-text">{v.skill_md}</pre>
          {rb.kind === "investigative" && (
            <details>
              <summary>Its test cases</summary>
              <pre className="rbk-text">{v.cases_yaml}</pre>
            </details>
          )}
        </div>
      </div>
      <label className="disc-field">
        <span>Note (required to decline)</span>
        <input value={reason} onChange={(e) => setReason(e.target.value)} />
      </label>
      <div className="nctx-actions">
        <button
          className="btn"
          disabled={busy}
          onClick={() =>
            run(
              () => api.runbookAct(rb.id, "approve", { version: v.version, body_sha256: v.body_sha256, reason }),
              rb.kind === "mop" ? "Approved." : "Approved. Iris can run it from now on.",
            )
          }
        >
          Approve
        </button>
        <button
          className="btn"
          disabled={busy || !reason.trim()}
          onClick={() => run(() => api.runbookAct(rb.id, "reject", { version: v.version, reason }), "Declined.")}
        >
          Decline
        </button>
      </div>
    </div>
  );
}

function RunStatus({ rb, busy, run }: { rb: Runbook; busy: boolean; run: Run }) {
  const v = activeVersion(rb)!;
  let say: string;
  if (rb.kind === "mop") say = "a procedure for a person; Iris never runs it";
  else if (rb.runs_in_iris) say = "Iris can run it";
  else say = "not running: the platform changed since its cases last passed";
  return (
    <li className="rbk-status-row">
      <span>
        <strong>{rb.name}</strong> (version {v.version}) — {say}
      </span>
      {rb.needs_recheck && (
        <button
          className="btn"
          disabled={busy}
          onClick={() =>
            run(
              () => api.runbookRecheck(rb.id),
              (out) => {
                const r = out as { passed?: boolean; problems?: RunbookCaseProblem[] };
                return r.passed
                  ? "Its cases pass again. Iris runs it."
                  : `Its cases failed (${r.problems?.length ?? 0} problems). It stays out of Iris until its author fixes it.`;
              },
            )
          }
        >
          Re-run its cases
        </button>
      )}
    </li>
  );
}

function Links({ rb, busy, run }: { rb: Runbook; busy: boolean; run: Run }) {
  const [links, setLinks] = useState<RunbookLink[] | null>(null);
  const [type, setType] = useState<RunbookLinkType>("signature");
  const [key, setKey] = useState("");
  const reload = useCallback(async () => {
    try {
      setLinks((await api.runbookLinks(rb.id)).links);
    } catch {
      setLinks([]);
    }
  }, [rb.id]);
  useEffect(() => {
    void reload();
  }, [reload]);
  return (
    <div className="rbk-links">
      <div className="nctx-col-h">What it is about</div>
      {links && links.length === 0 && <p className="disc-text">Not linked to anything.</p>}
      {links && links.length > 0 && (
        <ul>
          {links.map((l) => (
            <li key={`${l.link_type}:${l.link_key}`}>
              {LINK_LABEL[l.link_type]}: {l.link_key}{" "}
              <button
                className="btn"
                disabled={busy}
                onClick={() => run(async () => { await api.runbookLink(rb.id, l.link_type, l.link_key, true); await reload(); }, "Link removed.")}
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
      <div className="nctx-actions">
        <select value={type} onChange={(e) => setType(e.target.value as RunbookLinkType)} aria-label="Link type">
          {(Object.keys(LINK_LABEL) as RunbookLinkType[]).map((t) => (
            <option key={t} value={t}>
              {LINK_LABEL[t]}
            </option>
          ))}
        </select>
        <input value={key} onChange={(e) => setKey(e.target.value)} placeholder={LINK_HINT[type]} aria-label="Link target" />
        <button
          className="btn"
          disabled={busy || !key.trim()}
          onClick={() =>
            run(async () => {
              await api.runbookLink(rb.id, type, key.trim());
              setKey("");
              await reload();
            }, "Linked.")
          }
        >
          Add link
        </button>
      </div>
    </div>
  );
}

function History({ rb, busy, run }: { rb: Runbook; busy: boolean; run: Run }) {
  const [reason, setReason] = useState("");
  const current = activeVersion(rb);
  const versions = [...rb.versions].sort((a, b) => b.version - a.version);
  return (
    <details className="nctx-history">
      <summary>
        {rb.name} · {KIND_LABEL[rb.kind]} — {current ? `version ${current.version} approved` : "not approved"}
      </summary>
      <Links rb={rb} busy={busy} run={run} />
      <label className="disc-field">
        <span>Reason (required to stop using or restore)</span>
        <input value={reason} onChange={(e) => setReason(e.target.value)} />
      </label>
      {current && (
        <button
          className="btn"
          disabled={busy || !reason.trim()}
          onClick={() => run(() => api.runbookAct(rb.id, "retire", { reason }), "Iris no longer uses this runbook.")}
        >
          Stop using this runbook
        </button>
      )}
      <table className="ds-table nctx-table">
        <thead>
          <tr>
            <th>Version</th>
            <th>State</th>
            <th>Cases</th>
            <th>Written by</th>
            <th>Approved by</th>
            <th>When</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {versions.map((v) => (
            <tr key={v.version}>
              <td>
                {v.version}
                {v.restored_from ? ` (restores ${v.restored_from})` : ""}
              </td>
              <td>{STATE_LABEL[v.state] ?? v.state}</td>
              <td>{rb.kind === "mop" ? "—" : v.harness_passed ? "passed" : "not passed"}</td>
              <td>{v.author}</td>
              <td>{v.approver ?? "—"}</td>
              <td>{fmtDateTime(v.decided_at ?? v.created_at)}</td>
              <td>
                {v.approver && v.state !== "active" && (
                  <button
                    className="btn"
                    disabled={busy || !reason.trim()}
                    onClick={() => run(() => api.runbookAct(rb.id, "rollback", { to_version: v.version, reason }), `Version ${v.version} is approved again.`)}
                  >
                    Restore this version
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </details>
  );
}
