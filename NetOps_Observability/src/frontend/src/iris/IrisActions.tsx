// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// IrisActions — Iris's approval-gated writes (tracker 337 N-I4), step 8 of the
// Iris settings.
//
// Two parts:
//   1. Workspace admins: turn actions on (with an acknowledgement), choose
//      which kinds Iris may propose, or allow dry runs only.
//   2. Everyone who works incidents: the actions waiting for a decision. The
//      person Iris answered can withdraw a request but never approve it; a
//      different person approves the EXACT text shown, and only then is it
//      sent. Nothing on this page proposes an action — Iris does that at the
//      end of a concluded investigation.
//
// Every server string renders as escaped React text.

import { useCallback, useEffect, useState } from "react";
import {
  api,
  type IrisActionKind,
  type IrisActionRequest,
  type IrisActionSettings,
  type IrisActionsView,
} from "../services/api";
import { operatorError } from "../lib/errors";

const text14 = { fontSize: 14 } as const;
const muted = { color: "var(--muted)", fontSize: 14 } as const;
const row = { display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" as const, margin: "4px 0" };
const box = { border: "1px solid var(--border)", borderRadius: 6, padding: 10, margin: "8px 0" } as const;
const pre = { whiteSpace: "pre-wrap" as const, fontSize: 14, margin: "6px 0", padding: 8, background: "var(--panel-2, transparent)", border: "1px solid var(--border)", borderRadius: 4 };

export const STATUS_LABEL: Record<IrisActionRequest["status"], string> = {
  proposed: "Waiting for approval",
  dry_run: "Dry run — not sent",
  executing: "Sending",
  executed: "Sent",
  failed: "Approved, sending failed",
  rejected: "Declined",
  expired: "Expired",
};

const NOT_AVAILABLE = "Iris actions are not available here.";

/** A partial or older answer must never take the whole Settings panel down:
 *  every missing field reads as "off / nothing", never as an approve button. */
export function normalizeActionsView(raw: Partial<IrisActionsView> | null | undefined): IrisActionsView {
  const r = raw ?? {};
  const s = r.settings;
  const available = r.available === true;
  return {
    settings: {
      enabled: s?.enabled === true,
      kinds: Array.isArray(s?.kinds) ? s.kinds : [],
      dry_run_only: s?.dry_run_only === true,
    },
    available,
    unavailable_reason: available ? "" : (r.unavailable_reason || NOT_AVAILABLE),
    kinds: Array.isArray(r.kinds) ? r.kinds : [],
    requests: Array.isArray(r.requests) ? r.requests : [],
    open: typeof r.open === "number" ? r.open : 0,
  };
}

export default function IrisActions() {
  const [view, setView] = useState<IrisActionsView | null>(null);
  const [loadErr, setLoadErr] = useState("");
  const load = useCallback(async () => {
    try {
      setView(normalizeActionsView(await api.irisActions()));
      setLoadErr("");
    } catch (e) {
      setLoadErr(operatorError(e, "Iris actions could not be loaded."));
    }
  }, []);
  useEffect(() => { void load(); }, [load]);

  if (loadErr) return <div data-testid="iris-actions" style={muted}>{loadErr}</div>;
  if (!view) return <div data-testid="iris-actions" style={muted}>Loading…</div>;
  const waiting = view.requests.filter((r) => r.status === "proposed");
  const decided = view.requests.filter((r) => r.status !== "proposed").slice(0, 10);
  return (
    <div data-testid="iris-actions" style={text14}>
      {!view.available && <div role="status" style={muted}>{view.unavailable_reason}</div>}
      <ActionSettings view={view} onSaved={load} />
      <div style={{ fontWeight: 600, marginTop: 10 }}>Waiting for approval ({waiting.length})</div>
      {waiting.length === 0 && <div style={muted}>Nothing is waiting.</div>}
      {waiting.map((r) => <ActionRequest key={r.id} r={r} onDecided={load} />)}
      {decided.length > 0 && (
        <>
          <div style={{ fontWeight: 600, marginTop: 10 }}>Recent decisions</div>
          <table style={{ ...text14, borderCollapse: "collapse", width: "100%" }}>
            <thead>
              <tr><th style={{ textAlign: "left" }}>Action</th><th style={{ textAlign: "left" }}>Status</th><th style={{ textAlign: "left" }}>Decided by</th><th style={{ textAlign: "left" }}>Result</th></tr>
            </thead>
            <tbody>
              {decided.map((r) => (
                <tr key={r.id}>
                  <td>{r.summary}</td>
                  <td>{STATUS_LABEL[r.status]}</td>
                  <td>{r.decided_by || "—"}</td>
                  <td>{r.result?.message || r.reason || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}

// ── 1. settings ─────────────────────────────────────────────────────────────

function ActionSettings({ view, onSaved }: { view: IrisActionsView; onSaved: () => Promise<void> }) {
  const [draft, setDraft] = useState<IrisActionSettings>(view.settings);
  const [ack, setAck] = useState(false);
  const [err, setErr] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => { setDraft(view.settings); }, [view.settings]);

  const turningOn = draft.enabled && !view.settings.enabled;
  const toggleKind = (k: IrisActionKind, on: boolean) =>
    setDraft((d) => ({ ...d, kinds: on ? [...d.kinds.filter((x) => x !== k), k] : d.kinds.filter((x) => x !== k) }));

  const save = async () => {
    setBusy(true);
    setErr("");
    setNote("");
    try {
      await api.saveIrisActionSettings({ ...draft, acknowledged: ack });
      setAck(false);
      setNote("Saved.");
      await onSaved();
    } catch (e) {
      setErr(operatorError(e, "The settings were not saved. Only a workspace admin can change them."));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={box} aria-label="Action settings">
      <label style={row}>
        <input type="checkbox" style={text14} checked={draft.enabled} disabled={!view.available || busy}
          onChange={(e) => setDraft((d) => ({ ...d, enabled: e.target.checked }))} />
        Iris can propose actions for this workspace
      </label>
      {view.kinds.map((k) => (
        <label key={k.kind} style={{ ...row, marginLeft: 24 }}>
          <input type="checkbox" style={text14} checked={draft.kinds.includes(k.kind)} disabled={!draft.enabled || busy}
            onChange={(e) => toggleKind(k.kind, e.target.checked)} />
          {k.label}
        </label>
      ))}
      <label style={{ ...row, marginLeft: 24 }}>
        <input type="checkbox" style={text14} checked={draft.dry_run_only} disabled={!draft.enabled || busy}
          onChange={(e) => setDraft((d) => ({ ...d, dry_run_only: e.target.checked }))} />
        Dry runs only — show what would be sent, send nothing
      </label>
      {turningOn && (
        <label style={{ ...row, marginLeft: 24 }}>
          <input type="checkbox" style={text14} checked={ack} onChange={(e) => setAck(e.target.checked)} />
          I understand: an approved action is sent to the ticketing system or saved to investigation memory
        </label>
      )}
      <div style={row}>
        <button className="dash-btn" onClick={save} disabled={busy || (turningOn && !ack)}>Save</button>
        {note && <span role="status" style={muted}>{note}</span>}
      </div>
      {err && <div role="alert" style={text14}>{err}</div>}
      <div style={muted}>Never a device change. Someone other than the person Iris answered approves each one.</div>
    </div>
  );
}

// ── 2. one request ──────────────────────────────────────────────────────────

function ActionRequest({ r, onDecided }: { r: IrisActionRequest; onDecided: () => Promise<void> }) {
  const [reason, setReason] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const decide = async (approve: boolean) => {
    setBusy(true);
    setErr("");
    try {
      await api.decideIrisAction(r.id, approve, reason.trim());
      await onDecided();
    } catch (e) {
      setErr(operatorError(e, approve ? "The action was not approved." : "The action was not declined."));
    } finally {
      setBusy(false);
    }
  };
  return (
    <article style={box} aria-label={r.summary} data-testid="iris-action-request">
      <div style={{ fontWeight: 600 }}>{r.summary}</div>
      <div style={muted}>{r.kind_label} · proposed by Iris for {r.mine ? "you" : r.proposed_by} · expires {new Date(r.expires_at).toLocaleString()}</div>
      <div style={muted}>
        {r.dry_run.description}{r.dry_run.problem ? ` Problem: ${r.dry_run.problem}` : ""}
      </div>
      <pre style={pre} aria-label="Exact text that will be sent">{r.preview}</pre>
      {r.mine && <div style={muted}>You asked Iris, so someone else approves this.</div>}
      {(r.can_approve || r.can_reject) && (
        <div style={row}>
          <input style={{ fontSize: 14, padding: "4px 6px", minWidth: 260 }} placeholder="Reason (needed to decline)"
            aria-label="Reason" value={reason} onChange={(e) => setReason(e.target.value)} disabled={busy} />
          {r.can_approve && (
            <button className="dash-btn accent" onClick={() => decide(true)} disabled={busy || !r.dry_run.ok}>Approve and send</button>
          )}
          {r.can_reject && (
            <button className="dash-btn" onClick={() => decide(false)} disabled={busy || !reason.trim()}>
              {r.mine ? "Withdraw" : "Decline"}
            </button>
          )}
        </div>
      )}
      {err && <div role="alert" style={text14}>{err}</div>}
    </article>
  );
}
