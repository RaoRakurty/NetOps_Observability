// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// NetworkContext — Administration → Iris → Network Context (tracker 337 N-F1).
//
// Short facts a workspace writes about its own network ("core-02 is the DR
// site", "circuit ids starting CCT- are Comcast") that Iris reads before every
// answer. The page is the workflow, in order:
//   1. Write a fact           → POST /api/ai/context (a draft)
//   2. Send it for review     → POST /{id}/submit
//   3. Review (another admin) → POST /{id}/approve {version, body_sha256} | /reject
//   4. What Iris reads now    → GET  /api/ai/context/preview
// plus each fact's history: restore an earlier approved version, or stop
// using the fact.
//
// TWO PEOPLE: the server refuses an approval by the version's author; the page
// does not offer one (it says "waiting for another administrator"). The
// approval carries the hash of the text on screen, so a text changed after it
// was read is refused, never approved blind.
//
// §3a: every call is the caller's own workspace (from the token); the page
// never sends a tenant. All fact text is rendered as text.

import { useCallback, useEffect, useMemo, useState } from "react";
import { api, OrgContextFact, OrgContextList, OrgContextPreview, OrgContextVersion } from "../../services/api";
import { fmtDateTime } from "../../lib/time";
import { operatorError } from "../../lib/errors";

const STATE_LABEL: Record<string, string> = {
  draft: "Draft",
  pending: "Waiting for review",
  active: "In use by Iris",
  superseded: "Replaced",
  rejected: "Not approved",
  retired: "Stopped",
};

function bytes(s: string): number {
  return new TextEncoder().encode(s).length;
}

function placeLabel(scope: string): string {
  return scope.startsWith("site:") ? `Site ${scope.slice(5)}` : "Whole network";
}

function openVersion(f: OrgContextFact): OrgContextVersion | undefined {
  return f.versions.find((v) => v.state === "draft" || v.state === "pending");
}

function activeVersion(f: OrgContextFact): OrgContextVersion | undefined {
  return f.versions.find((v) => v.state === "active");
}

export default function NetworkContext() {
  const [data, setData] = useState<OrgContextList | null>(null);
  const [preview, setPreview] = useState<OrgContextPreview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const [list, pv] = await Promise.all([api.orgContext(), api.orgContextPreview()]);
      setData(list);
      setPreview(pv);
      setError(null);
    } catch (e) {
      setError(operatorError(e, "Network context could not be loaded."));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const run = async (what: () => Promise<unknown>, done: string) => {
    setBusy(true);
    setNotice(null);
    try {
      await what();
      setNotice(done);
      setError(null);
      await load();
    } catch (e) {
      setError(operatorError(e, "That did not work."));
    } finally {
      setBusy(false);
    }
  };

  const kindLabel = useMemo(() => {
    const m: Record<string, string> = {};
    for (const k of data?.kinds ?? []) m[k.kind] = k.label;
    return m;
  }, [data]);

  const you = data?.you ?? "";
  const facts = data?.facts ?? [];
  const mineOpen = facts.filter((f) => {
    const v = openVersion(f);
    return v && v.author === you;
  });
  const toReview = facts.filter((f) => {
    const v = openVersion(f);
    return v && v.state === "pending" && v.author !== you;
  });

  return (
    <div className="card disc-card nctx" style={{ marginBottom: 16 }}>
      <div className="disc-head">
        <div>
          <h2 className="disc-title">Network context</h2>
          <p className="disc-desc">
            Facts about your network that Iris reads before every answer. A fact reaches Iris only after a second
            administrator approves it. When live data disagrees with a fact, Iris goes with the live data.
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
      <ol className="disc-steps" aria-label="Network context workflow">
        <li className="disc-step">
          <span className="disc-step-num" aria-hidden>
            1
          </span>
          <div className="disc-step-body">
            <h3 className="disc-step-title">Write a fact</h3>
            {data && (
              <NewFact
                kinds={data.kinds}
                limit={data.limits.body_bytes}
                keyLimit={data.limits.key_bytes}
                busy={busy}
                onSave={(f) => run(() => api.orgContextCreate(f), "Draft saved. Send it for review when it is ready.")}
              />
            )}
          </div>
        </li>
        <li className="disc-step">
          <span className="disc-step-num" aria-hidden>
            2
          </span>
          <div className="disc-step-body">
            <h3 className="disc-step-title">Send for review</h3>
            {mineOpen.length === 0 ? (
              <p className="disc-text">You have no drafts.</p>
            ) : (
              mineOpen.map((f) => (
                <MyDraft
                  key={f.id}
                  fact={f}
                  label={kindLabel[f.kind] ?? f.kind}
                  limit={data?.limits.body_bytes ?? 2000}
                  busy={busy}
                  run={run}
                />
              ))
            )}
          </div>
        </li>
        <li className="disc-step">
          <span className="disc-step-num" aria-hidden>
            3
          </span>
          <div className="disc-step-body">
            <h3 className="disc-step-title">Review others' facts</h3>
            {toReview.length === 0 ? (
              <p className="disc-text">Nothing is waiting for your review.</p>
            ) : (
              toReview.map((f) => (
                <Review key={f.id} fact={f} label={kindLabel[f.kind] ?? f.kind} busy={busy} run={run} />
              ))
            )}
          </div>
        </li>
        <li className="disc-step">
          <span className="disc-step-num" aria-hidden>
            4
          </span>
          <div className="disc-step-body">
            <h3 className="disc-step-title">What Iris reads</h3>
            {!preview || preview.facts === 0 ? (
              <p className="disc-text">Iris reads no facts yet. Approved facts appear here.</p>
            ) : (
              <>
                <p className="disc-text">
                  {preview.facts} {preview.facts === 1 ? "fact" : "facts"}
                  {preview.omitted > 0 ? `; ${preview.omitted} left out to keep it short` : ""}.
                </p>
                <pre className="nctx-preview" data-testid="nctx-preview">
                  {preview.block}
                </pre>
              </>
            )}
          </div>
        </li>
      </ol>
      <h3 className="disc-step-title" style={{ marginTop: 20 }}>
        All facts
      </h3>
      {facts.length === 0 ? (
        <p className="disc-text">No facts yet.</p>
      ) : (
        facts.map((f) => <History key={f.id} fact={f} label={kindLabel[f.kind] ?? f.kind} busy={busy} run={run} />)
      )}
    </div>
  );
}

type Run = (what: () => Promise<unknown>, done: string) => Promise<void>;

function ByteCount({ text, limit }: { text: string; limit: number }) {
  const n = bytes(text);
  return (
    <span className={`nctx-count${n > limit ? " over" : ""}`} aria-live="polite">
      {n} / {limit} bytes
    </span>
  );
}

function NewFact(props: {
  kinds: { kind: string; label: string }[];
  limit: number;
  keyLimit: number;
  busy: boolean;
  onSave: (f: { scope: string; kind: string; key: string; body: string }) => void;
}) {
  const [kind, setKind] = useState(props.kinds[0]?.kind ?? "");
  const [site, setSite] = useState("");
  const [key, setKey] = useState("");
  const [body, setBody] = useState("");
  const tooLong = bytes(body) > props.limit || bytes(key) > props.keyLimit;
  const save = () => {
    props.onSave({ scope: site.trim() ? `site:${site.trim()}` : "tenant", kind, key: key.trim(), body });
    setKey("");
    setBody("");
  };
  return (
    <div className="nctx-form">
      <label className="disc-field">
        <span>Type of fact</span>
        <select value={kind} onChange={(e) => setKind(e.target.value)}>
          {props.kinds.map((k) => (
            <option key={k.kind} value={k.kind}>
              {k.label}
            </option>
          ))}
        </select>
      </label>
      <label className="disc-field">
        <span>Site (leave empty for the whole network)</span>
        <input value={site} onChange={(e) => setSite(e.target.value)} placeholder="dfw-hq" />
      </label>
      <label className="disc-field">
        <span>Short name</span>
        <input value={key} onChange={(e) => setKey(e.target.value)} placeholder="DR site" />
      </label>
      <label className="disc-field">
        <span>The fact</span>
        <textarea
          rows={4}
          value={body}
          onChange={(e) => setBody(e.target.value)}
          placeholder="core-02 is the DR site; its alerts are lower urgency until 06:00."
        />
      </label>
      <div className="nctx-actions">
        <ByteCount text={body} limit={props.limit} />
        <button className="btn" disabled={props.busy || tooLong || !key.trim() || !body.trim()} onClick={save}>
          Save draft
        </button>
      </div>
    </div>
  );
}

function MyDraft({ fact, label, limit, busy, run }: { fact: OrgContextFact; label: string; limit: number; busy: boolean; run: Run }) {
  const v = openVersion(fact)!;
  const [text, setText] = useState(v.body);
  useEffect(() => setText(v.body), [v.body]);
  const head = `${label} · ${placeLabel(fact.scope)} · ${fact.key}`;
  if (v.state === "pending") {
    return (
      <div className="nctx-item">
        <div className="nctx-item-head">{head}</div>
        <p className="nctx-body">{v.body}</p>
        <p className="disc-text">Waiting for another administrator to review it.</p>
        <button className="btn" disabled={busy} onClick={() => run(() => api.orgContextAct(fact.id, "withdraw"), "Taken back to draft.")}>
          Take back to edit
        </button>
      </div>
    );
  }
  return (
    <div className="nctx-item">
      <div className="nctx-item-head">{head}</div>
      <textarea rows={4} value={text} onChange={(e) => setText(e.target.value)} aria-label={`Edit ${fact.key}`} />
      <div className="nctx-actions">
        <ByteCount text={text} limit={limit} />
        <button className="btn" disabled={busy || text === v.body || bytes(text) > limit} onClick={() => run(() => api.orgContextDraft(fact.id, text), "Draft saved.")}>
          Save changes
        </button>
        <button
          className="btn"
          disabled={busy || text !== v.body}
          onClick={() => run(() => api.orgContextAct(fact.id, "submit"), "Sent for review.")}
        >
          Send for review
        </button>
        <button className="btn" disabled={busy} onClick={() => run(() => api.orgContextDiscard(fact.id), "Draft discarded.")}>
          Discard draft
        </button>
      </div>
    </div>
  );
}

function Review({ fact, label, busy, run }: { fact: OrgContextFact; label: string; busy: boolean; run: Run }) {
  const v = openVersion(fact)!;
  const current = activeVersion(fact);
  const [reason, setReason] = useState("");
  return (
    <div className="nctx-item">
      <div className="nctx-item-head">
        {label} · {placeLabel(fact.scope)} · {fact.key} — written by {v.author}
      </div>
      <div className="nctx-compare">
        <div>
          <div className="nctx-col-h">Iris reads now</div>
          <p className="nctx-body">{current ? current.body : "Nothing (a new fact)."}</p>
        </div>
        <div>
          <div className="nctx-col-h">Proposed</div>
          <p className="nctx-body">{v.body}</p>
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
            run(() => api.orgContextAct(fact.id, "approve", { version: v.version, body_sha256: v.body_sha256, reason }), "Approved. Iris reads it from now on.")
          }
        >
          Approve
        </button>
        <button
          className="btn"
          disabled={busy || !reason.trim()}
          onClick={() => run(() => api.orgContextAct(fact.id, "reject", { version: v.version, reason }), "Declined.")}
        >
          Decline
        </button>
      </div>
    </div>
  );
}

function History({ fact, label, busy, run }: { fact: OrgContextFact; label: string; busy: boolean; run: Run }) {
  const [reason, setReason] = useState("");
  const current = activeVersion(fact);
  const versions = [...fact.versions].sort((a, b) => b.version - a.version);
  return (
    <details className="nctx-history">
      <summary>
        {label} · {placeLabel(fact.scope)} · {fact.key} — {current ? `version ${current.version} in use` : "not in use"}
      </summary>
      <label className="disc-field">
        <span>Reason (required to stop using or restore)</span>
        <input value={reason} onChange={(e) => setReason(e.target.value)} />
      </label>
      {current && (
        <button
          className="btn"
          disabled={busy || !reason.trim()}
          onClick={() => run(() => api.orgContextAct(fact.id, "retire", { reason }), "Iris no longer reads this fact.")}
        >
          Stop using this fact
        </button>
      )}
      <table className="ds-table nctx-table">
        <thead>
          <tr>
            <th>Version</th>
            <th>State</th>
            <th>Text</th>
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
              <td className="nctx-body">{v.body}</td>
              <td>{v.author}</td>
              <td>{v.approver ?? "—"}</td>
              <td>{fmtDateTime(v.decided_at ?? v.created_at)}</td>
              <td>
                {v.approver && v.state !== "active" && (
                  <button
                    className="btn"
                    disabled={busy || !reason.trim()}
                    onClick={() => run(() => api.orgContextAct(fact.id, "rollback", { to_version: v.version, reason }), `Version ${v.version} is in use again.`)}
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
