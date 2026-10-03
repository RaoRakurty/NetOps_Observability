// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// IrisVocabulary — the workspace's own words for its network, in four steps
// (tracker 337 N-C2 / N-C5 / N-C8):
//
//   1. Names your team uses — aliases ("the HQ firewall" → device:fw-hq-01).
//   2. Check a name — how Iris resolves a phrase, and how sure it is.
//   3. Try a question — what Iris understood, and the answer the deterministic
//      query engine returns, before any model is involved. "That's not what I
//      meant" records a correction for offline review.
//   4. Recent questions — the caller's own questions and what became of each.
//   5. Decision ledger (admins, N-A6) — how answers were reached, as hashes.
//
// Everything here is scoped server-side to the caller's workspace; the tenant
// is never sent. A question Iris did not fully understand is shown as such —
// the words it could not place are listed, and nothing is run.

import { useCallback, useEffect, useState } from "react";
import { api, type IrisAlias, type IrisCompiled, type IrisRef, type IrisResolution, type IrisResultSet, type IrisTurn } from "../services/api";
import { httpFailure, operatorError } from "../lib/errors";
import QueryCorrection from "../iris/QueryCorrection";
import RecentQuestions from "../iris/RecentQuestions";
import DecisionLedger from "../iris/DecisionLedger";

// The entity kinds an alias can point at (catalog entities minus incidents and
// changes, which are named by id, not by nickname).
export const ALIAS_TYPES = ["device", "site", "interface", "circuit", "bgp_peer", "provider", "application", "probe_target"] as const;

const TYPE_LABEL: Record<string, string> = {
  device: "Device", site: "Site", interface: "Interface", circuit: "Circuit", bgp_peer: "BGP peer",
  provider: "Provider", application: "Application", probe_target: "Probe target", incident: "Incident", change: "Change",
};

// Plain-language names for the resolution ladder's methods.
export const METHOD_LABEL: Record<string, string> = {
  canonical_id: "exact id",
  tenant_alias: "your team's name",
  inventory_name: "inventory name",
  partial_name: "partial match — confirm",
};

const MAX_ROWS_SHOWN = 20;

// Plain-language turn outcomes.
export const OUTCOME_LABEL: Record<IrisTurn["outcome"], string> = {
  answered: "answered", clarify: "needs you to choose", declined: "declined",
  unparsed: "not understood", invalid: "could not be run", error: "failed",
};

function browserTZ(): string | undefined {
  try { return Intl.DateTimeFormat().resolvedOptions().timeZone; } catch { return undefined; }
}

const text14 = { fontSize: 14 } as const;
const muted = { color: "var(--muted)", fontSize: 14 } as const;
const stepHead = { fontSize: 16, fontWeight: 600, margin: "14px 0 4px" } as const;

// cell renders one result value as text (objects as JSON — never as markup).
export function cell(v: unknown): string {
  if (v == null) return "—";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

function RefLine({ r }: { r: IrisRef }) {
  return (
    <li style={text14} data-testid="iris-ref">
      <strong>{r.input_text}</strong> → {TYPE_LABEL[r.entity_type] ?? r.entity_type} <code>{r.entity_id}</code>{" "}
      <span style={muted}>({METHOD_LABEL[r.resolution_method] ?? r.resolution_method}, {Math.round(r.confidence * 100)}% sure)</span>
      {r.needs_confirmation && <span className="badge warn" style={{ fontSize: 14, marginLeft: 6 }}>needs confirmation</span>}
    </li>
  );
}

export default function IrisVocabulary() {
  const [aliases, setAliases] = useState<IrisAlias[]>([]);
  const [max, setMax] = useState(0);
  const [loadErr, setLoadErr] = useState("");

  const [newType, setNewType] = useState<string>("device");
  const [newTarget, setNewTarget] = useState("");
  const [newAlias, setNewAlias] = useState("");
  const [candidates, setCandidates] = useState<IrisRef[]>([]);
  const [addErr, setAddErr] = useState("");
  const [busy, setBusy] = useState(false);

  const [checkText, setCheckText] = useState("");
  const [check, setCheck] = useState<IrisResolution | null>(null);
  const [checkErr, setCheckErr] = useState("");

  const [question, setQuestion] = useState("");
  const [compiled, setCompiled] = useState<IrisCompiled | null>(null);
  const [result, setResult] = useState<IrisResultSet | null>(null);
  const [qErr, setQErr] = useState("");
  // "asked" = the answer came from the conversation (already run); "preview" =
  // only compiled, runnable on request.
  const [mode, setMode] = useState<"asked" | "preview">("preview");
  const [convId, setConvId] = useState<string | null>(null);
  const [history, setHistory] = useState<IrisTurn[]>([]);
  // Bumped after every question so "Recent questions" re-reads the log.
  const [asked, setAsked] = useState(0);

  const reload = useCallback(async () => {
    try {
      const r = await api.irisAliases();
      setAliases(r.aliases ?? []);
      setMax(r.max);
      setLoadErr("");
    } catch (e) {
      setLoadErr(operatorError(e, "Could not load your team's names."));
    }
  }, []);

  useEffect(() => { void reload(); }, [reload]);

  const save = async (entityID: string) => {
    setBusy(true);
    setAddErr("");
    try {
      await api.putIrisAlias({ entity_type: newType, entity_id: entityID, alias: newAlias.trim() });
      setNewAlias("");
      setNewTarget("");
      setCandidates([]);
      await reload();
    } catch (e) {
      setAddErr(operatorError(e, "The name could not be saved."));
    } finally {
      setBusy(false);
    }
  };

  // Add: an explicit id ("device:fw-hq-01") is saved as-is (the server checks
  // it is visible); a name is resolved first, and anything short of exactly
  // one confident match is offered as a choice rather than guessed.
  const add = async () => {
    const target = newTarget.trim();
    if (!newAlias.trim() || !target) {
      setAddErr("Enter both the name your team uses and what it refers to.");
      return;
    }
    if (target.startsWith(newType + ":")) {
      await save(target);
      return;
    }
    setBusy(true);
    setAddErr("");
    try {
      const res = await api.resolveIrisEntity(target, [newType]);
      const refs = (res.refs ?? []).filter((r) => r.entity_type === newType);
      if (refs.length === 1 && !res.ambiguous && !refs[0].needs_confirmation) {
        setBusy(false);
        await save(refs[0].entity_id);
        return;
      }
      setCandidates(refs);
      if (refs.length === 0) {
        setAddErr(`No ${TYPE_LABEL[newType]?.toLowerCase() ?? newType} called "${target}" is visible to you. You can also enter its id, e.g. ${newType}:name.`);
      }
    } catch (e) {
      setAddErr(operatorError(e, "Could not look that up."));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (a: IrisAlias) => {
    try {
      await api.deleteIrisAlias(a.entity_type, a.alias);
      await reload();
    } catch (e) {
      setLoadErr(operatorError(e, "The name could not be removed."));
    }
  };

  const runCheck = async () => {
    setCheck(null);
    setCheckErr("");
    if (!checkText.trim()) return;
    try {
      setCheck(await api.resolveIrisEntity(checkText.trim()));
    } catch (e) {
      setCheckErr(operatorError(e, "Could not check that name."));
    }
  };

  const understand = async () => {
    setCompiled(null);
    setResult(null);
    setQErr("");
    if (!question.trim()) return;
    try {
      setMode("preview");
      setCompiled(await api.compileIrisQuery(question.trim(), browserTZ()));
      setAsked((n) => n + 1);
    } catch (e) {
      setQErr(operatorError(e, "Could not read that question."));
    }
  };

  // ask sends the question into the conversation: follow-ups ("that device",
  // "what else did they change") resolve against what the server holds. A
  // conversation that has gone (expired, restarted) or is full is replaced
  // once, and the restart is said, not hidden.
  const ask = async () => {
    setCompiled(null);
    setResult(null);
    setQErr("");
    const q = question.trim();
    if (!q) return;
    const send = async (id: string) => api.askIrisConversation(id, q, browserTZ());
    try {
      let id = convId;
      if (!id) {
        id = (await api.startIrisConversation()).id;
        setConvId(id);
      }
      let ans;
      try {
        ans = await send(id);
      } catch (e) {
        const st = httpFailure(e)?.status;
        if (st !== 404 && st !== 409) throw e;
        id = (await api.startIrisConversation()).id;
        setConvId(id);
        setHistory([]);
        setQErr(st === 409 ? "That conversation was full — started a new one." : "That conversation had ended — started a new one.");
        ans = await send(id);
      }
      setMode("asked");
      setCompiled(ans);
      setResult(ans.result ?? null);
      if (ans.error) setQErr(ans.error === "not found" ? "Iris could not find that." : "The question could not be run.");
      setHistory((h) => [...h, ans.turn]);
      setQuestion("");
      setAsked((n) => n + 1);
    } catch (e) {
      setQErr(operatorError(e, "The question could not be asked."));
    }
  };

  const newConversation = () => {
    setConvId(null);
    setHistory([]);
    setCompiled(null);
    setResult(null);
    setQErr("");
  };

  const run = async () => {
    if (!compiled?.ast || !compiled.validation?.valid) return;
    setQErr("");
    try {
      setResult((await api.executeIrisQuery(compiled.ast)).result);
    } catch (e) {
      setQErr(operatorError(e, "The question could not be run."));
    }
  };

  const runnable = mode === "preview" && !!compiled?.ast && !!compiled.validation?.valid && !compiled.unparsed && !compiled.decline;
  const rows = result?.rows ?? [];
  const cols = rows.length ? Object.keys(rows[0]) : [];

  return (
    <div data-testid="iris-vocabulary" style={{ marginTop: 14, borderTop: "1px solid var(--line)", paddingTop: 10 }}>
      <div style={{ fontSize: 16, fontWeight: 600 }}>Iris vocabulary</div>
      <p style={{ ...muted, margin: "2px 0 0" }}>Teach Iris the names your team uses, and check how it reads a question. Only your workspace sees these.</p>

      <div style={stepHead}>1. Names your team uses</div>
      {loadErr && <div role="alert" style={{ ...text14, color: "var(--bad)" }}>{loadErr}</div>}
      {aliases.length === 0 && !loadErr && <div style={muted}>No names yet.</div>}
      {aliases.length > 0 && (
        <ul style={{ margin: 0, paddingLeft: 18 }} data-testid="iris-alias-list">
          {aliases.map((a) => (
            <li key={`${a.entity_type}|${a.alias}`} style={text14}>
              <strong>{a.alias}</strong> → {TYPE_LABEL[a.entity_type] ?? a.entity_type} <code>{a.entity_id}</code>{" "}
              <button type="button" className="dash-btn" style={{ fontSize: 14 }} onClick={() => void remove(a)} aria-label={`Remove ${a.alias}`}>Remove</button>
            </li>
          ))}
        </ul>
      )}
      {max > 0 && <div style={muted}>{aliases.length} of {max} used.</div>}
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginTop: 6 }}>
        <input aria-label="Name your team uses" placeholder='e.g. "HQ firewall"' value={newAlias}
          onChange={(e) => setNewAlias(e.target.value)} style={text14} maxLength={128} />
        <span style={text14}>means</span>
        <select aria-label="Kind" value={newType} onChange={(e) => { setNewType(e.target.value); setCandidates([]); }} style={text14}>
          {ALIAS_TYPES.map((t) => <option key={t} value={t}>{TYPE_LABEL[t]}</option>)}
        </select>
        <input aria-label="What it refers to" placeholder="its name or id" value={newTarget}
          onChange={(e) => setNewTarget(e.target.value)} style={text14} maxLength={200} />
        <button type="button" className="dash-btn accent" style={text14} disabled={busy} onClick={() => void add()}>Add</button>
      </div>
      {addErr && <div role="alert" style={{ ...text14, color: "var(--bad)", marginTop: 4 }}>{addErr}</div>}
      {candidates.length > 0 && (
        <div style={{ marginTop: 6 }} data-testid="iris-alias-candidates">
          <div style={text14}>Which one did you mean?</div>
          {candidates.map((c) => (
            <button key={c.entity_id} type="button" className="dash-btn" style={{ ...text14, margin: "4px 6px 0 0" }}
              disabled={busy} onClick={() => void save(c.entity_id)}>{c.entity_id}</button>
          ))}
        </div>
      )}

      <div style={stepHead}>2. Check a name</div>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        <input aria-label="Name to check" placeholder="type any name" value={checkText} maxLength={128}
          onChange={(e) => setCheckText(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") void runCheck(); }} style={text14} />
        <button type="button" className="dash-btn" style={text14} onClick={() => void runCheck()}>Check</button>
      </div>
      {checkErr && <div role="alert" style={{ ...text14, color: "var(--bad)" }}>{checkErr}</div>}
      {check && (
        <div data-testid="iris-check">
          {(check.refs ?? []).length === 0
            ? <div style={muted}>Iris does not recognise that name.</div>
            : <ul style={{ margin: "4px 0 0", paddingLeft: 18 }}>{(check.refs ?? []).map((r) => <RefLine key={r.entity_id} r={r} />)}</ul>}
          {check.ambiguous && <div style={{ ...text14, color: "var(--warn)" }}>More than one match — Iris will ask which you mean.</div>}
        </div>
      )}

      <div style={stepHead}>3. Try a question</div>
      <p style={{ ...muted, margin: "0 0 6px" }}>Ask, then follow up — &quot;that device&quot;, &quot;what else did they change&quot;. Iris only follows up on what it answered.</p>
      {history.length > 0 && (
        <ol style={{ margin: "0 0 6px", paddingLeft: 22 }} data-testid="iris-history">
          {history.map((h, i) => (
            <li key={i} style={text14}>{h.question} <span style={muted}>— {OUTCOME_LABEL[h.outcome] ?? h.outcome}</span></li>
          ))}
        </ol>
      )}
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        <input aria-label="Question" placeholder="e.g. latency on the HQ firewall last 24 hours" value={question} maxLength={1000}
          onChange={(e) => setQuestion(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") void ask(); }}
          style={{ ...text14, flex: 1, minWidth: 220 }} />
        <button type="button" className="dash-btn accent" style={text14} onClick={() => void ask()}>Ask</button>
        <button type="button" className="dash-btn" style={text14} onClick={() => void understand()}>Only show how Iris reads it</button>
        {convId && <button type="button" className="dash-btn" style={text14} onClick={newConversation}>New conversation</button>}
      </div>
      {qErr && <div role="alert" style={{ ...text14, color: "var(--bad)" }}>{qErr}</div>}
      {compiled && (
        <div data-testid="iris-understood" style={{ marginTop: 6 }}>
          {compiled.decline && <div style={text14}>Iris will not do this: {compiled.decline}</div>}
          {compiled.unparsed && (
            <div style={text14}>
              Iris did not fully understand this question
              {(compiled.not_understood ?? []).length > 0 && <> — it could not place: <strong>{(compiled.not_understood ?? []).join(", ")}</strong></>}.
              Nothing will be run.
            </div>
          )}
          {(compiled.clarify ?? []).length > 0 && (
            <div style={text14}>Iris needs you to confirm: <ul style={{ margin: 0, paddingLeft: 18 }}>{(compiled.clarify ?? []).map((r) => <RefLine key={r.entity_id} r={r} />)}</ul></div>
          )}
          {compiled.intent && <div style={text14}>Understood as: <strong>{compiled.intent.replace(/_/g, " ")}</strong></div>}
          {(compiled.entities ?? []).length > 0 && (
            <ul style={{ margin: "2px 0 0", paddingLeft: 18 }}>{(compiled.entities ?? []).map((r) => <RefLine key={r.entity_id} r={r} />)}</ul>
          )}
          {compiled.validation && !compiled.validation.valid && (
            <ul style={{ margin: "2px 0 0", paddingLeft: 18 }} data-testid="iris-validation-errors">
              {(compiled.validation.errors ?? []).map((e, i) => (
                <li key={i} style={text14}>{e.message || e.code}{(e.suggestions ?? []).length > 0 && <> — did you mean {(e.suggestions ?? []).join(", ")}?</>}</li>
              ))}
            </ul>
          )}
          {(compiled.validation?.constraints_applied ?? []).map((c, i) => (
            <div key={i} style={muted}>Adjusted: {c.reason}</div>
          ))}
          {runnable && <button type="button" className="dash-btn accent" style={{ ...text14, marginTop: 6 }} onClick={() => void run()}>Run it</button>}
          {compiled.query_log_id && (
            <QueryCorrection key={compiled.query_log_id} queryId={compiled.query_log_id} onSaved={() => setAsked((n) => n + 1)} />
          )}
        </div>
      )}
      {result && (
        <div data-testid="iris-result" style={{ marginTop: 8 }}>
          <div style={muted}>
            {result.series?.length ? `${result.series.length} series` : `${rows.length} row${rows.length === 1 ? "" : "s"}`}
            {result.truncated && " (more exist — showing the first page)"} · from {result.provenance.source} in {result.provenance.duration_ms} ms
          </div>
          {(result.notes ?? []).map((n, i) => <div key={i} style={muted}>{n}</div>)}
          {rows.length > 0 && (
            <div style={{ overflowX: "auto" }}>
              <table style={{ ...text14, borderCollapse: "collapse", marginTop: 4 }}>
                <thead><tr>{cols.map((c) => <th key={c} style={{ ...text14, textAlign: "left", padding: "2px 8px" }}>{c}</th>)}</tr></thead>
                <tbody>
                  {rows.slice(0, MAX_ROWS_SHOWN).map((r, i) => (
                    <tr key={i}>{cols.map((c) => <td key={c} style={{ ...text14, padding: "2px 8px" }}>{cell(r[c])}</td>)}</tr>
                  ))}
                </tbody>
              </table>
              {rows.length > MAX_ROWS_SHOWN && <div style={muted}>Showing {MAX_ROWS_SHOWN} of {rows.length}.</div>}
            </div>
          )}
        </div>
      )}

      <div style={stepHead}>4. Recent questions</div>
      <p style={{ ...muted, margin: "0 0 6px" }}>Your last questions and what Iris made of them. Mark any that went wrong.</p>
      <RecentQuestions refreshKey={asked} />

      <div style={stepHead}>5. Decision ledger (admins)</div>
      <p style={{ ...muted, margin: "0 0 6px" }}>How each answer was reached: the plan, the policy checks, the tools and versions it ran, and the model that answered.</p>
      <DecisionLedger />
    </div>
  );
}
