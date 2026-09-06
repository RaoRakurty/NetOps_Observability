// SeamGroups — the redundancy roll-up over the seam list, on Security Overview.
//
// WHY THIS EXISTS. A seam is one ownership handoff. A seam GROUP is the set of
// seams that carry the same traffic redundantly — two ISP circuits, an
// active/standby pair — and that is the unit an operator actually reasons about
// during an outage ("is the other side of this pair still up?"). The engine
// suggests groups from evidence; a person confirms or rejects them. Until now
// the console read only the flat seam list, so the suggestion queue had no
// surface and nothing could ever be confirmed from the product.
//
// WORD SWEEP (2026-09-06, tracker 270): what a group IS, and what confirming
// one buys, moved into ai/skills/explain/seam.group*.md behind the `(i)`.
//
// HONESTY RULES:
//   · A SUGGESTION is labelled as one, with what suggested it and how confident
//     it is. It is never rendered as a settled fact.
//   · Confidence is shown only when the row carries one; a group with none says
//     "not stated" rather than 0 %.
//   · The state machine is the SERVER's (seam.TransitionAllowed). The page
//     offers the vocabulary and renders the server's refusal verbatim rather
//     than re-implementing the transitions and disagreeing with it.
//   · 501 means the seam store is not on this deployment — a different fact
//     from "no groups", and said as itself.
//
// §3a: the list and the PATCH are tenant-scoped server-side; a cross-tenant
// group id answers 404. The page never sends a tenant.

import { useCallback, useEffect, useState } from "react";
import { api, SeamGroup } from "../../services/api";
import { Panel } from "../../components/board/panels";
import { fmtDateTime } from "../../lib/time";
import { httpFailure, operatorError } from "../../lib/errors";
import AskIris from "../../components/AskIris";

/** The closed state vocabulary the server validates the filter against. */
const STATES = ["suggested", "confirmed", "active", "rejected", "retired"] as const;

type Load =
  | { kind: "loading" }
  | { kind: "unavailable" }
  | { kind: "denied" }
  | { kind: "error"; message: string }
  | { kind: "ready"; groups: SeamGroup[] };

function pct(confidence: number | undefined): string {
  if (typeof confidence !== "number" || !Number.isFinite(confidence) || confidence <= 0) return "not stated";
  return `${Math.round(confidence * (confidence <= 1 ? 100 : 1))}%`;
}

export default function SeamGroups({ canWrite = false }: { canWrite?: boolean }) {
  const [load, setLoad] = useState<Load>({ kind: "loading" });
  const [state, setState] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  const read = useCallback(async (filter: string) => {
    setLoad({ kind: "loading" });
    try {
      const groups = await api.seamGroups(filter);
      setLoad({ kind: "ready", groups: Array.isArray(groups) ? groups : [] });
    } catch (e) {
      const f = httpFailure(e);
      if (f?.status === 501) setLoad({ kind: "unavailable" });
      else if (f?.status === 403) setLoad({ kind: "denied" });
      else setLoad({ kind: "error", message: operatorError(e, "The seam groups could not be read.") });
    }
  }, []);

  useEffect(() => { void read(state); }, [read, state]);

  const setGroupState = useCallback(async (g: SeamGroup, next: string) => {
    if (!next || next === g.state) return;
    setBusy(g.group_id);
    setNote(null);
    try {
      await api.seamGroupSetState(g.group_id, next);
      setNote(`${g.display_name || g.group_id} is now ${next}.`);
      await read(state);
    } catch (e) {
      // The server owns the state machine; an illegal step comes back as its
      // own sentence and is shown as-is rather than reworded into a guess.
      setNote(operatorError(e, "That state change was not accepted."));
    } finally {
      setBusy(null);
    }
  }, [read, state]);

  const filter = (
    <label>
      <span className="sr-only">Filter seam groups by state</span>
      <select value={state} onChange={(e) => setState(e.target.value)} aria-label="Filter seam groups by state">
        <option value="">Every state</option>
        {STATES.map((s) => <option key={s} value={s}>{s}</option>)}
      </select>
    </label>
  );

  if (load.kind === "loading") {
    return <Panel title="Seam groups" action={filter}><div className="empty" role="status">Reading the seam groups…</div></Panel>;
  }
  if (load.kind === "unavailable") {
    return (
      <Panel title="Seam groups">
        <div className="empty">
          The seam registry is not available here.
          <AskIris topic="seam.registry-unavailable" label="the seam registry" />
        </div>
      </Panel>
    );
  }
  if (load.kind === "denied") {
    return <Panel title="Seam groups"><div className="empty">Seeing seam groups needs infrastructure access.</div></Panel>;
  }
  if (load.kind === "error") {
    return (
      <Panel title="Seam groups" action={filter}>
        <div className="empty" role="alert" style={{ color: "var(--bad)" }}>{load.message} The grouping is unknown, not absent.</div>
      </Panel>
    );
  }

  const groups = load.groups;
  return (
    <Panel title="Seam groups" action={filter}>
      {note && <p className="sec-line" role="status">{note}</p>}
      {groups.length === 0 ? (
        <div className="empty">
          {state ? `No seam group is ${state}.` : "No seam group recorded yet."}
          <AskIris topic="seam.group" label="a seam group" />
        </div>
      ) : (
        <table className="ds-table" aria-label="Seam groups">
          <thead>
            <tr>
              <th scope="col">Group</th>
              <th scope="col">Type</th>
              <th scope="col">Redundancy</th>
              <th scope="col">Members</th>
              <th scope="col">State</th>
              <th scope="col">Proposed by</th>
              <th scope="col">Confidence</th>
              <th scope="col">Updated</th>
              {canWrite && <th scope="col">Set state</th>}
            </tr>
          </thead>
          <tbody>
            {groups.map((g) => (
              <tr key={g.group_id}>
                <th scope="row" style={{ fontWeight: 500, textAlign: "left" }}>
                  {g.display_name || g.group_id}
                  {g.state === "suggested" && (
                    <span className="sec-line" style={{ display: "block" }}>
                      proposed, not confirmed
                      <AskIris topic="seam.group-suggested" label="a proposed grouping" />
                    </span>
                  )}
                </th>
                <td>{g.seam_type || "not stated"}</td>
                <td>{g.redundancy_model || "not stated"}</td>
                <td title={(g.members ?? []).map((m) => `${m.member_id} (${m.role})`).join(", ")}>
                  {(g.members ?? []).length}
                </td>
                <td><span className={`chip ${g.state === "active" ? "chip-ok" : g.state === "suggested" ? "chip-warn" : ""}`}>{g.state || "not stated"}</span></td>
                <td>{g.suggested_by || "not stated"}</td>
                <td>{pct(g.confidence)}</td>
                <td>{g.updated_at ? fmtDateTime(g.updated_at) : "—"}</td>
                {canWrite && (
                  <td>
                    <label>
                      <span className="sr-only">Set the state of {g.display_name || g.group_id}</span>
                      <select
                        aria-label={`Set the state of ${g.display_name || g.group_id}`}
                        value={g.state}
                        disabled={busy === g.group_id}
                        onChange={(e) => void setGroupState(g, e.target.value)}
                      >
                        {STATES.map((s) => <option key={s} value={s}>{s}</option>)}
                      </select>
                    </label>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  );
}
