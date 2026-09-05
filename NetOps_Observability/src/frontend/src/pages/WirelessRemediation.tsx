// WirelessRemediation — the guarded wireless approval queue, rendered on
// Operations → Action Queue beneath the incident queue.
//
// WHY IT SITS HERE. The Action Queue answers "what do I work next". A wireless
// remediation proposal is exactly that question with a decision attached: an
// operator either approves it, rejects it with a reason, or runs it. Until now
// the whole propose → approve → reject → execute loop (#128 Phase 8) existed,
// was fully audited, and had no surface at all — the one shape of debt where a
// human-approval control is built and no human can reach it.
//
// THE FIVE GATES ARE THE SERVER'S, AND THIS PANEL RENDERS THEM RATHER THAN
// RE-IMPLEMENTING THEM (§3, never trust the client):
//   1 proposal    only from evidence that PARTICIPATED in the correlation
//   2 eligibility per-tenant allowlist, verdict must be confirmed, one target
//   3 approval    a named human; a REJECTION must carry a reason
//   4 execution   via the vendor connector only. v1 registers NO executor, so
//                 an execute fails CLOSED with "no executor" — the panel shows
//                 that refusal as the recorded outcome, not as an error to hide
//   5 verification a settle-window recheck; recorded as pending, never as done
//
// HONESTY RULES:
//   · 404 on the list means the whole surface is dormant (FEATURE_WIRELESS_ACTIONS
//     is off). The panel says so and renders nothing else — a dormant workflow
//     is not an empty queue.
//   · Executing is type-to-confirm on the action's own target, because it is the
//     step that touches a radio serving live clients.
//   · A failed execution keeps its recorded refusal text on the row. The panel
//     never re-labels a fail-closed gate as a transient error.
//
// §3a: the list is tenant-scoped server-side and a cross-tenant id is 404,
// indistinguishable from unknown. The panel never sends a tenant.

import { useCallback, useEffect, useMemo, useState } from "react";
import { api, WirelessActionRow } from "../services/api";
import { fmtDateTime } from "../lib/time";
import { httpFailure, operatorError } from "../lib/errors";

type Load =
  | { kind: "loading" }
  | { kind: "dormant" }
  | { kind: "denied" }
  | { kind: "error"; message: string }
  | { kind: "ready"; rows: WirelessActionRow[] };

/** What each action kind actually does, in the operator's words. */
const KIND_COPY: Record<string, string> = {
  rrm_channel_change: "Move one radio to a different channel. Clients on it re-associate briefly.",
  ap_radio_reset: "Restart one access point's radio. Everything on that radio drops and re-joins.",
  client_deauth: "Disconnect one client session. The client re-associates on its own.",
};

const KIND_LABEL: Record<string, string> = {
  rrm_channel_change: "Channel change",
  ap_radio_reset: "Radio reset",
  client_deauth: "Client disconnect",
};

const STATE_TONE: Record<string, string> = {
  proposed: "chip-warn",
  approved: "",
  executed: "chip-ok",
  verified: "chip-ok",
  failed: "chip-crit",
  rejected: "",
};

const PENDING = new Set(["proposed", "approved"]);

function kindLabel(kind: string): string {
  return KIND_LABEL[kind] ?? kind ?? "not stated";
}

export default function WirelessRemediation() {
  const [load, setLoad] = useState<Load>({ kind: "loading" });
  const [canWrite, setCanWrite] = useState(false);
  const [reason, setReason] = useState<Record<string, string>>({});
  const [confirmFor, setConfirmFor] = useState<string | null>(null);
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [rowErr, setRowErr] = useState<string | null>(null);

  const read = useCallback(async () => {
    try {
      const rows = await api.wirelessActions();
      setLoad({ kind: "ready", rows: Array.isArray(rows) ? rows : [] });
    } catch (e) {
      const f = httpFailure(e);
      if (f?.status === 404) setLoad({ kind: "dormant" });
      else if (f?.status === 403) setLoad({ kind: "denied" });
      else setLoad({ kind: "error", message: operatorError(e, "The wireless remediation queue could not be read.") });
    }
  }, []);

  useEffect(() => {
    void read();
    api.permissions()
      .then((p) => setCanWrite((p.permissions?.infrastructure ?? 0) >= 2))
      .catch(() => setCanWrite(false));
  }, [read]);

  const act = useCallback(async (row: WirelessActionRow, verb: "approve" | "reject" | "execute") => {
    setBusy(`${row.id}:${verb}`);
    setNote(null);
    setRowErr(null);
    try {
      const text = (reason[row.id] ?? "").trim();
      if (verb === "approve") {
        await api.wirelessActionApprove(row.id, text);
        setNote(`Approved ${kindLabel(row.kind).toLowerCase()} on ${row.target}. It does not run until it is executed.`);
      } else if (verb === "reject") {
        await api.wirelessActionReject(row.id, text);
        setNote(`Rejected ${kindLabel(row.kind).toLowerCase()} on ${row.target}. The reason is on the record.`);
      } else {
        const done = await api.wirelessActionExecute(row.id);
        setNote(
          done.state === "executed"
            ? `Executed on ${row.target}. Verification is pending: the originating observation is re-measured in a settle window before this counts as fixed.`
            : `Execution did not run on ${row.target}: ${done.error || "the outcome was not stated"}.`,
        );
        setConfirmFor(null);
        setTyped("");
      }
      setReason((r) => ({ ...r, [row.id]: "" }));
      await read();
    } catch (e) {
      // A refusal here is a GATE, not a glitch: the server's own sentence is
      // the most useful thing an operator can be shown.
      setRowErr(operatorError(e, "That decision was not accepted."));
      await read();
    } finally {
      setBusy(null);
    }
  }, [reason, read]);

  const rows = load.kind === "ready" ? load.rows : [];
  const pending = useMemo(() => rows.filter((r) => PENDING.has(r.state)), [rows]);
  const history = useMemo(() => rows.filter((r) => !PENDING.has(r.state)), [rows]);

  if (load.kind === "loading") {
    return <section className="cc-panel" aria-label="Wireless remediation"><div className="cc-empty" role="status">Reading the wireless remediation queue…</div></section>;
  }
  if (load.kind === "dormant") {
    // A dormant workflow is deliberately quiet: rendering an empty approval
    // queue would suggest there is one and that nothing is waiting in it.
    return null;
  }
  if (load.kind === "denied") {
    return (
      <section className="cc-panel" aria-label="Wireless remediation">
        <div className="cc-panel-h"><h3 className="cc-panel-t">Wireless remediation</h3></div>
        <div className="cc-empty">Seeing proposed wireless remediation needs infrastructure access.</div>
      </section>
    );
  }
  if (load.kind === "error") {
    return (
      <section className="cc-panel" aria-label="Wireless remediation">
        <div className="cc-panel-h"><h3 className="cc-panel-t">Wireless remediation</h3></div>
        <div className="cc-empty" role="alert">{load.message} What is proposed is unknown, not nothing.</div>
      </section>
    );
  }

  return (
    <section className="cc-panel" aria-label="Wireless remediation">
      <div className="cc-panel-h">
        <h3 className="cc-panel-t">Wireless remediation</h3>
        <span className="cc-panel-meta">
          proposed from an incident&apos;s own evidence — approved by a person, executed one target at a time
        </span>
      </div>

      {note && <p className="mini-meta" role="status">{note}</p>}
      {rowErr && <p className="mini-meta" role="alert" style={{ color: "var(--bad)" }}>{rowErr}</p>}
      {!canWrite && (
        <p className="mini-meta">
          You can see what is proposed. Approving, rejecting and executing need infrastructure write access.
        </p>
      )}

      <h4 style={{ margin: "var(--sp-2) 0 var(--sp-1)" }}>Waiting on a decision</h4>
      {pending.length === 0 ? (
        <div className="cc-empty">
          Nothing is waiting. A proposal is only created from evidence that took part in a confirmed
          incident, so an empty queue means no incident has met that bar — not that the wireless estate
          is healthy.
        </div>
      ) : (
        <table className="ds-table" aria-label="Wireless remediation, waiting on a decision">
          <thead>
            <tr>
              <th scope="col">Action</th>
              <th scope="col">Target</th>
              <th scope="col">From incident</th>
              <th scope="col">State</th>
              <th scope="col">Proposed</th>
              <th scope="col">Decision</th>
            </tr>
          </thead>
          <tbody>
            {pending.map((r) => {
              const confirming = confirmFor === r.id;
              const canExecute = r.state === "approved";
              return (
                <tr key={r.id}>
                  <th scope="row" style={{ fontWeight: 500, textAlign: "left" }}>
                    {kindLabel(r.kind)}
                    <span className="mini-meta" style={{ display: "block" }}>{KIND_COPY[r.kind] ?? "This action's effect is not described."}</span>
                  </th>
                  <td className="mono">{r.target || "not stated"}</td>
                  <td>
                    {r.correlation_id ? (
                      <a href={`#/investigate/rca?id=${encodeURIComponent(r.correlation_id)}`} title={r.correlation_id}>
                        {r.correlation_id.slice(0, 8)}…
                      </a>
                    ) : "not stated"}
                    <span className="mini-meta" style={{ display: "block" }}>the evidence that justifies it</span>
                  </td>
                  <td><span className={`chip ${STATE_TONE[r.state] ?? ""}`}>{r.state}</span></td>
                  <td>
                    {r.created_at ? fmtDateTime(r.created_at) : "—"}
                    <span className="mini-meta" style={{ display: "block" }}>by {r.proposed_by || "not stated"}</span>
                  </td>
                  <td>
                    {canWrite ? (
                      <>
                        <label>
                          <span className="sr-only">Reason for {r.target}</span>
                          <input
                            type="text"
                            value={reason[r.id] ?? ""}
                            onChange={(e) => setReason((v) => ({ ...v, [r.id]: e.target.value }))}
                            placeholder={r.state === "proposed" ? "reason (required to reject)" : "note"}
                            aria-label={`Reason for ${r.target}`}
                            style={{ minWidth: 220 }}
                          />
                        </label>
                        <div style={{ marginTop: 4 }}>
                          {r.state === "proposed" && (
                            <>
                              <button
                                type="button" className="btn"
                                disabled={busy !== null}
                                onClick={() => void act(r, "approve")}
                              >
                                {busy === `${r.id}:approve` ? "Approving…" : "Approve"}
                              </button>{" "}
                              <button
                                type="button" className="btn"
                                disabled={busy !== null || (reason[r.id] ?? "").trim() === ""}
                                title={(reason[r.id] ?? "").trim() === "" ? "A rejection is recorded with its reason — write one first." : undefined}
                                onClick={() => void act(r, "reject")}
                              >
                                {busy === `${r.id}:reject` ? "Rejecting…" : "Reject"}
                              </button>
                            </>
                          )}
                          {canExecute && !confirming && (
                            <button type="button" className="btn danger" onClick={() => { setConfirmFor(r.id); setTyped(""); }}>
                              Execute
                            </button>
                          )}
                        </div>
                        {canExecute && confirming && (
                          <div style={{ marginTop: 6 }}>
                            <p className="mini-meta" role="note" style={{ margin: 0 }}>
                              This touches a radio that is serving clients right now, and it cannot be taken back
                              once it runs.
                            </p>
                            <label>
                              <span className="mini-meta">Type <span className="mono">{r.target}</span> to confirm</span>{" "}
                              <input
                                type="text"
                                className="mono"
                                aria-label={`Type ${r.target} to confirm executing this action`}
                                value={typed}
                                onChange={(e) => setTyped(e.target.value)}
                              />
                            </label>{" "}
                            <button
                              type="button" className="btn danger"
                              disabled={typed !== r.target || busy !== null}
                              onClick={() => void act(r, "execute")}
                            >
                              {busy === `${r.id}:execute` ? "Executing…" : "Execute now"}
                            </button>{" "}
                            <button type="button" className="btn" onClick={() => { setConfirmFor(null); setTyped(""); }}>Cancel</button>
                          </div>
                        )}
                      </>
                    ) : (
                      <span className="mini-meta">read-only</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}

      <h4 style={{ margin: "var(--sp-2) 0 var(--sp-1)" }}>Decided</h4>
      {history.length === 0 ? (
        <div className="cc-empty">Nothing has been decided yet.</div>
      ) : (
        <table className="ds-table" aria-label="Wireless remediation history">
          <thead>
            <tr>
              <th scope="col">Action</th>
              <th scope="col">Target</th>
              <th scope="col">Outcome</th>
              <th scope="col">Decided by</th>
              <th scope="col">Reason</th>
              <th scope="col">Recorded</th>
            </tr>
          </thead>
          <tbody>
            {history.map((r) => (
              <tr key={r.id}>
                <th scope="row" style={{ fontWeight: 500, textAlign: "left" }}>{kindLabel(r.kind)}</th>
                <td className="mono">{r.target || "not stated"}</td>
                <td>
                  <span className={`chip ${STATE_TONE[r.state] ?? ""}`}>{r.state}</span>
                  {r.error && <span className="mini-meta" style={{ display: "block", color: "var(--bad)" }}>{r.error}</span>}
                  {r.verify_note && <span className="mini-meta" style={{ display: "block" }}>{r.verify_note}</span>}
                </td>
                <td>{r.approved_by || r.proposed_by || "not stated"}</td>
                <td>{r.reason || "none recorded"}</td>
                <td>{r.updated_at ? fmtDateTime(r.updated_at) : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="mini-meta">
        Every transition above is an audit event. Execution runs through the vendor controller, never over
        a device login; where no controller write is available the action records itself as refused rather
        than reporting a change it did not make.
      </p>
    </section>
  );
}
