// RcaVerdictFeedback — the operator VERDICT control for one RCA case (Project 2
// P7). It asks the only question that measures the engine honestly: "was this
// verdict right?" — and, when it was not, WHICH of the five claims the case
// makes (cause · owner · affected · evidence · recovery) was wrong.
//
// Design rules:
//  · APPEND-ONLY, never optimistic. Nothing is shown as recorded until the
//    server has stored it and the GET has read it back; a revision adds a row.
//  · The version the operator actually judged is submitted with the verdict —
//    an honest "which rendering was this?" beats a guessed "latest".
//  · Errors surface inline in operator words (403 = a permission answer, not a
//    stack trace). No silent failure.
//  · a11y: a labelled button group with aria-pressed, a radio fieldset for the
//    part, a character counter tied to the textarea, and one polite live region
//    that announces both the confirmation and the error.

import { useCallback, useEffect, useState } from "react";
import { api, type RcaFeedback, type RcaVerdict, type RcaWrongPart } from "../../services/api";
import {
  RCA_MAX_REASON_CHARS, VERDICT_LABEL, WRONG_PART_LABEL, WRONG_PART_ORDER, rcaVerdictLine,
} from "./labels";

/** The three choices, in the order an operator reads them (best → worst). */
const CHOICES: readonly RcaVerdict[] = ["correct", "partial", "wrong"];

// Stable DOM ids. One verdict control exists per RCA case view, so a fixed
// prefix is unambiguous — and unlike useId it does not shift with render order.
const UID = "rw-fb";

/**
 * errText — an HTTP failure in operator words. `request()` throws
 * `Error("<status> <statusText>: <body>")`, so the status is the message prefix.
 */
export function errText(e: unknown): string {
  const msg = String((e as { message?: string } | null)?.message ?? e ?? "");
  if (/^403\b/.test(msg)) return "You don't have permission to record a verdict on this case.";
  if (/^401\b/.test(msg)) return "Your session expired — sign in again to record a verdict.";
  if (/^404\b/.test(msg)) return "This case is no longer available.";
  const detail = msg.replace(/^\d{3}\s*[^:]*:\s*/, "").trim();
  return detail ? `Could not record the verdict: ${detail}` : "Could not record the verdict.";
}

export default function RcaVerdictFeedback({ correlationId, correlationVersion }: {
  correlationId: string;
  /** The object version currently on screen; omitted when unknown (never guessed). */
  correlationVersion?: number;
}) {
  const [list, setList] = useState<RcaFeedback[] | null>(null);
  const [loadErr, setLoadErr] = useState("");
  const [draft, setDraft] = useState<RcaVerdict | null>(null);   // open inline form
  const [part, setPart] = useState<RcaWrongPart | "">("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [note, setNote] = useState("");

  const load = useCallback(() => {
    if (!correlationId) return;
    api.correlationFeedback(correlationId)
      .then((r) => { setList(r.feedback ?? []); setLoadErr(""); })
      .catch(() => { setList([]); setLoadErr("Recorded verdicts are unavailable right now."); });
  }, [correlationId]);

  useEffect(() => {
    setList(null); setLoadErr(""); setDraft(null); setPart(""); setReason(""); setErr(""); setNote("");
    load();
  }, [correlationId, load]);

  const closeForm = () => { setDraft(null); setPart(""); setReason(""); setErr(""); };

  const submit = async (verdict: RcaVerdict, wrongPart: RcaWrongPart | "") => {
    if (busy) return;
    // A "wrong"/"partial" verdict without a named part is not actionable feedback.
    if (verdict !== "correct" && !wrongPart) { setErr("Choose which part was wrong."); return; }
    setBusy(true); setErr(""); setNote("");
    const trimmed = reason.trim();
    try {
      await api.correlationFeedbackCreate(correlationId, {
        verdict,
        ...(wrongPart ? { wrong_part: wrongPart } : {}),
        ...(verdict !== "correct" && trimmed ? { reason: trimmed } : {}),
        ...(correlationVersion && correlationVersion > 0 ? { correlation_version: correlationVersion } : {}),
      });
      setDraft(null); setPart(""); setReason("");
      setNote("Verdict recorded.");
      load();   // re-read: what is shown as recorded is what the server stored
    } catch (e) {
      setErr(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const latest = list && list.length > 0 ? list[0] : null;
  const earlier = list ? list.slice(1) : [];

  return (
    <div className="rw-fb">
      <div className="rw-fb-head">
        <span className="rw-fb-q" id={`${UID}-q`}>Was this verdict right?</span>
        <div className="rw-fb-btns" role="group" aria-labelledby={`${UID}-q`}>
          {CHOICES.map((v) => (
            <button
              key={v}
              type="button"
              className={`rw-btn rw-fb-btn${draft === v ? " active" : ""}`}
              aria-pressed={draft === v}
              disabled={busy}
              onClick={() => {
                setErr(""); setNote("");
                if (v === "correct") { setDraft(null); setPart(""); setReason(""); void submit("correct", ""); }
                else { setDraft(v); setPart(""); }
              }}
            >
              {VERDICT_LABEL[v]}
            </button>
          ))}
        </div>
      </div>

      {draft && (
        <div className="rw-fb-form">
          <fieldset className="rw-fb-parts">
            <legend>Which part was wrong?</legend>
            {WRONG_PART_ORDER.map((p) => (
              <label key={p} className="rw-fb-part">
                <input
                  type="radio"
                  name={`${UID}-part`}
                  value={p}
                  checked={part === p}
                  onChange={() => { setPart(p); setErr(""); }}
                />
                {WRONG_PART_LABEL[p]}
              </label>
            ))}
          </fieldset>

          <div className="rw-fb-reason">
            <label htmlFor={`${UID}-reason`}>What did it get wrong? (optional)</label>
            <textarea
              id={`${UID}-reason`}
              rows={2}
              value={reason}
              maxLength={RCA_MAX_REASON_CHARS}
              aria-describedby={`${UID}-count`}
              placeholder="e.g. the ISP was not at fault — the break was on the LAN uplink"
              onChange={(e) => setReason(e.target.value.slice(0, RCA_MAX_REASON_CHARS))}
            />
            <span className="rw-fb-count" id={`${UID}-count`}>
              {reason.length}/{RCA_MAX_REASON_CHARS} characters
            </span>
          </div>

          <div className="rw-fb-actions">
            <button type="button" className="rw-btn primary" disabled={busy} onClick={() => submit(draft, part)}>
              {busy ? "Recording…" : "Record verdict"}
            </button>
            <button type="button" className="rw-btn" disabled={busy} onClick={closeForm}>Cancel</button>
          </div>
        </div>
      )}

      {/* Live region (4.1.3) — the confirmation and any failure are announced. */}
      <div className="rw-fb-status" role="status" aria-live="polite" aria-busy={busy}>
        {err ? <span className="rw-fb-err">{err}</span> : note ? <span className="rw-fb-ok">{note}</span> : null}
      </div>

      {latest ? (
        <div className="rw-fb-latest">{rcaVerdictLine(latest)}</div>
      ) : loadErr ? (
        <div className="rw-fb-none">{loadErr}</div>
      ) : list ? (
        <div className="rw-fb-none">No operator verdict recorded on this case yet.</div>
      ) : null}

      {earlier.length > 0 && (
        <details className="rw-fb-earlier">
          <summary>{earlier.length} earlier verdict{earlier.length === 1 ? "" : "s"}</summary>
          <ul>
            {earlier.map((f) => <li key={f.id}>{rcaVerdictLine(f)}</li>)}
          </ul>
        </details>
      )}
    </div>
  );
}
