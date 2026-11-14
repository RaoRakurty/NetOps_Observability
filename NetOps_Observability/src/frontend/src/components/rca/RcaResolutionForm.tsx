// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// RcaResolutionForm — "How was this fixed?" for one RCA case (tracker 337 N-F4
// residue). When an operator resolves a case, they may record what fixed it.
// Iris reads it back when a similar incident happens ("last time this was
// fixed by a configuration rollback") — always as history, never as the cause
// of the new incident.
//
// Design rules (the RcaVerdictFeedback conventions):
//  · APPEND-ONLY, never optimistic: nothing shows as recorded until the server
//    stored it and the list was read back. Recording again adds a row; the
//    newest leads.
//  · Three numbered steps in plain language, fonts from the shared ≥14px rules.
//  · The server's rules are mirrored here only to help the operator early; the
//    server still decides (a refused note is refused there too).
//  · Errors inline in operator words; one polite live region.

import { useCallback, useEffect, useState } from "react";
import { api, type RcaResolution, type RcaResolutionKind } from "../../services/api";
import { operatorError } from "../../lib/errors";
import { fmtDateTime } from "../../lib/time";

export const RESOLUTION_NOTE_MAX = 500;

/** The closed vocabulary in the order the form offers it, with plain labels. */
export const RESOLUTION_CHOICES: ReadonlyArray<{ kind: RcaResolutionKind; label: string }> = [
  { kind: "config_rollback", label: "Rolled back a configuration change" },
  { kind: "hardware_replace", label: "Replaced hardware" },
  { kind: "provider_ticket", label: "The provider fixed it (ticket raised)" },
  { kind: "reboot", label: "Rebooted a device" },
  { kind: "routing_change", label: "Changed routing" },
  { kind: "capacity_add", label: "Added capacity" },
  { kind: "no_action_transient", label: "No action — it cleared on its own" },
  { kind: "other", label: "Something else (say what below)" },
];

const LABEL: Record<RcaResolutionKind, string> = Object.fromEntries(
  RESOLUTION_CHOICES.map((c) => [c.kind, c.label]),
) as Record<RcaResolutionKind, string>;

const CHANGE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
// Control characters, bidi controls and zero-width characters (refused server-side too).
// eslint-disable-next-line no-control-regex
const HIDDEN = /[\u0000-\u001f\u007f-\u009f\u200b-\u200d\u2060\u202a-\u202e\u2066-\u2069\ufeff]/;

const UID = "rw-res";

/** errText — an HTTP failure in operator words, naming THIS action. */
export function resolutionErrText(e: unknown): string {
  const msg = String((e as { message?: string } | null)?.message ?? e ?? "");
  if (/^403\b/.test(msg)) return "You don't have permission to record how this case was fixed.";
  if (/^401\b/.test(msg)) return "Your session expired — sign in again to record the fix.";
  if (/^404\b/.test(msg)) return "This case is no longer available.";
  if (/^400\b/.test(msg)) return operatorError(e, "The fix could not be recorded — check the fields and try again.");
  return operatorError(e, "Could not record the fix.");
}

/** checkDraft mirrors the server's rules so the operator hears early. "" = fine. */
export function checkDraft(kind: RcaResolutionKind | "", note: string, changeId: string): string {
  if (!kind) return "Choose what fixed it.";
  const n = note.trim();
  if ([...n].length > RESOLUTION_NOTE_MAX) return `Keep the note to ${RESOLUTION_NOTE_MAX} characters.`;
  if (HIDDEN.test(n)) return "The note can't contain line breaks or hidden characters.";
  if (kind === "other" && !n) return "Say briefly what was done.";
  const c = changeId.trim();
  if (c && !CHANGE_ID.test(c)) return "A change number is letters, digits, '.', '_', ':' or '-', up to 64 characters.";
  return "";
}

export default function RcaResolutionForm({ correlationId }: { correlationId: string }) {
  const [list, setList] = useState<RcaResolution[] | null>(null);
  const [loadErr, setLoadErr] = useState("");
  const [open, setOpen] = useState(false);
  const [kind, setKind] = useState<RcaResolutionKind | "">("");
  const [note, setNote] = useState("");
  const [changeId, setChangeId] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [done, setDone] = useState("");

  const load = useCallback(() => {
    if (!correlationId) return;
    api.correlationResolutions(correlationId)
      .then((r) => { setList(r.resolutions ?? []); setLoadErr(""); })
      .catch(() => { setList([]); setLoadErr("Recorded fixes are unavailable right now."); });
  }, [correlationId]);

  useEffect(() => {
    setList(null); setLoadErr(""); setOpen(false); setKind(""); setNote(""); setChangeId(""); setErr(""); setDone("");
    load();
  }, [correlationId, load]);

  const submit = async () => {
    if (busy) return;
    const problem = checkDraft(kind, note, changeId);
    if (problem) { setErr(problem); return; }
    setBusy(true); setErr(""); setDone("");
    try {
      await api.correlationResolutionCreate(correlationId, {
        kind: kind as RcaResolutionKind,
        ...(note.trim() ? { note: note.trim() } : {}),
        ...(changeId.trim() ? { change_id: changeId.trim() } : {}),
      });
      setOpen(false); setKind(""); setNote(""); setChangeId("");
      setDone("Fix recorded. Iris will mention it when a similar incident happens.");
      load(); // what shows as recorded is what the server stored
    } catch (e) {
      setErr(resolutionErrText(e));
    } finally {
      setBusy(false);
    }
  };

  const latest = list && list.length > 0 ? list[0] : null;
  const remaining = RESOLUTION_NOTE_MAX - [...note.trim()].length;

  return (
    <section className="rw-fb rw-res" aria-labelledby={`${UID}-q`}>
      <div className="rw-fb-head">
        <span className="rw-fb-q" id={`${UID}-q`}>How was this fixed?</span>
        {!open && (
          <button type="button" className="rw-btn" onClick={() => { setOpen(true); setErr(""); setDone(""); }}>
            {latest ? "Record a correction" : "Record the fix"}
          </button>
        )}
      </div>

      {list === null && <p className="disc-text">Loading recorded fixes…</p>}
      {loadErr && <p className="disc-text" role="alert">{loadErr}</p>}
      {latest && (
        <p className="disc-text" data-testid="rw-res-latest">
          <strong>Recorded:</strong> {LABEL[latest.kind] ?? latest.kind}
          {latest.change_id ? ` · change ${latest.change_id}` : ""}
          {" · "}{latest.created_by} on {fmtDateTime(latest.created_at)}
          {latest.note ? <><br /><span style={{ color: "var(--muted)" }}>{latest.note}</span></> : null}
        </p>
      )}
      {list !== null && !latest && !loadErr && !open && (
        <p className="disc-text" style={{ color: "var(--muted)" }}>
          Nothing recorded yet. Once it's fixed, record how — Iris uses it when a similar incident happens.
        </p>
      )}

      {open && (
        <div className="rw-fb-form">
          <fieldset className="rw-fb-parts">
            <legend>1. What fixed it?</legend>
            {RESOLUTION_CHOICES.map((c) => (
              <label key={c.kind} className="rw-fb-part">
                <input
                  type="radio"
                  name={`${UID}-kind`}
                  value={c.kind}
                  checked={kind === c.kind}
                  onChange={() => { setKind(c.kind); setErr(""); }}
                />
                {c.label}
              </label>
            ))}
          </fieldset>

          <div className="rw-fb-reason">
            <label htmlFor={`${UID}-note`}>
              2. Anything to add? {kind === "other" ? "(required)" : "(optional)"}
            </label>
            <textarea
              id={`${UID}-note`}
              value={note}
              maxLength={RESOLUTION_NOTE_MAX * 2}
              rows={2}
              aria-describedby={`${UID}-count`}
              onChange={(e) => { setNote(e.target.value); setErr(""); }}
            />
            <span id={`${UID}-count`} className="disc-text" style={{ color: remaining < 0 ? "var(--bad)" : "var(--muted)" }}>
              {remaining} characters left
            </span>
          </div>

          <div className="rw-fb-reason">
            <label htmlFor={`${UID}-change`}>3. Change number, if one was linked (optional)</label>
            <input
              id={`${UID}-change`}
              type="text"
              value={changeId}
              maxLength={64}
              onChange={(e) => { setChangeId(e.target.value); setErr(""); }}
            />
          </div>

          <div className="rw-fb-btns">
            <button type="button" className="rw-btn primary" disabled={busy} onClick={() => { void submit(); }}>
              {busy ? "Recording…" : "Record the fix"}
            </button>
            <button type="button" className="rw-btn" disabled={busy}
              onClick={() => { setOpen(false); setKind(""); setNote(""); setChangeId(""); setErr(""); }}>
              Cancel
            </button>
          </div>
        </div>
      )}

      <p className="disc-text" role="status" aria-live="polite">{err || done}</p>
    </section>
  );
}
