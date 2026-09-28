// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// QueryCorrection — "That's not what I meant" on one Iris answer (tracker 337
// N-C8, design Part 2 §22).
//
// The operator says WHAT was wrong (a closed list), may add a short note, and
// may say the question the way they meant it. That rewording is compiled by
// the server like any question; only a query the server validated is attached,
// and the server validates it AGAIN against the caller's scope when the
// correction is stored. Corrections are kept for offline evaluation — nothing
// here changes how Iris answers the next question, and the form says so.

import { useId, useState } from "react";
import { api, type IrisCorrectionKind } from "../services/api";
import { operatorError } from "../lib/errors";

export const KIND_LABEL: Record<IrisCorrectionKind, string> = {
  wrong_entity: "Wrong device, site or thing",
  wrong_metric: "Wrong measurement",
  wrong_window: "Wrong time range",
  wrong_filter: "Wrong filter",
  other: "Something else",
};

const KINDS = Object.keys(KIND_LABEL) as IrisCorrectionKind[];
const NOTE_MAX = 500;
const text14 = { fontSize: 14 } as const;
const muted = { color: "var(--muted)", fontSize: 14 } as const;

function browserTZ(): string | undefined {
  try { return Intl.DateTimeFormat().resolvedOptions().timeZone; } catch { return undefined; }
}

export default function QueryCorrection({ queryId, onSaved }: { queryId: string; onSaved?: () => void }) {
  const [open, setOpen] = useState(false);
  const [kind, setKind] = useState<IrisCorrectionKind>("wrong_entity");
  const [note, setNote] = useState("");
  const [meant, setMeant] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [done, setDone] = useState(false);
  const kindId = useId();
  const noteId = useId();
  const meantId = useId();

  if (done) {
    return <div style={muted} data-testid="iris-correction-saved">Thanks — noted for review. Iris&apos;s answers do not change on their own.</div>;
  }
  if (!open) {
    return (
      <button type="button" className="dash-btn" style={{ ...text14, marginTop: 6 }} onClick={() => setOpen(true)}>
        That&apos;s not what I meant
      </button>
    );
  }

  const submit = async () => {
    setErr("");
    if (kind === "other" && !note.trim() && !meant.trim()) {
      setErr("Say what was wrong, or how you would ask it.");
      return;
    }
    setBusy(true);
    try {
      let ast: Record<string, unknown> | undefined;
      const q = meant.trim();
      if (q) {
        // The rewording must be something Iris can run; otherwise say so and
        // let the operator send the note alone.
        const c = await api.compileIrisQuery(q, browserTZ());
        if (!c.ast || !c.validation?.valid || c.unparsed || c.decline) {
          setErr("Iris could not turn that wording into a query it can run. Rephrase it, or clear it and send your note.");
          return;
        }
        ast = c.ast;
      }
      await api.correctIrisQuery(queryId, { kind, ...(note.trim() ? { note: note.trim() } : {}), ...(ast ? { ast } : {}) });
      setDone(true);
      onSaved?.();
    } catch (e) {
      setErr(operatorError(e, "The correction could not be saved."));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div data-testid="iris-correction" style={{ marginTop: 6, borderLeft: "3px solid var(--line)", paddingLeft: 10 }}>
      <div style={{ fontSize: 16, fontWeight: 600 }}>What was wrong?</div>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginTop: 4 }}>
        <label htmlFor={kindId} style={text14}>Iris got the</label>
        <select id={kindId} value={kind} onChange={(e) => setKind(e.target.value as IrisCorrectionKind)} style={text14}>
          {KINDS.map((k) => <option key={k} value={k}>{KIND_LABEL[k]}</option>)}
        </select>
      </div>
      <label htmlFor={meantId} style={{ ...text14, display: "block", marginTop: 6 }}>How would you ask it? (optional)</label>
      <input id={meantId} value={meant} maxLength={1000} onChange={(e) => setMeant(e.target.value)}
        placeholder="e.g. memory on edge-a for the last hour" style={{ ...text14, width: "100%", maxWidth: 520 }} />
      <label htmlFor={noteId} style={{ ...text14, display: "block", marginTop: 6 }}>Note (optional)</label>
      <textarea id={noteId} value={note} maxLength={NOTE_MAX} rows={2} onChange={(e) => setNote(e.target.value)}
        style={{ ...text14, width: "100%", maxWidth: 520 }} />
      <div style={muted}>Kept for review so Iris can be improved. It does not change today&apos;s answers.</div>
      {err && <div role="alert" style={{ ...text14, color: "var(--bad)" }}>{err}</div>}
      <div style={{ display: "flex", gap: 8, marginTop: 6 }}>
        <button type="button" className="dash-btn accent" style={text14} disabled={busy} onClick={() => void submit()}>Send</button>
        <button type="button" className="dash-btn" style={text14} disabled={busy} onClick={() => { setOpen(false); setErr(""); }}>Cancel</button>
      </div>
    </div>
  );
}
