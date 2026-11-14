// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ChangeDiff — "What changed" for one ledger change (tracker 337 N-D3), read
// from /api/changes/{id}/diff on demand. A configuration change shows the
// redacted unified diff of its two captured versions; any other change its
// redacted before → after. Everything is rendered as text.
//
// Iris opens it too (the change drawer, a one-change answer, and the change
// record page): `initiallyOpen` reads the diff on mount instead of on click.
// The read is the caller's own: another workspace's change id answers 404,
// which is said plainly and never shown as a diff.

import { useEffect, useRef, useState } from "react";
import { api, type ChangeDiffResponse } from "../../services/api";
import { httpFailure, operatorError } from "../../lib/errors";

/** A 404 means the change is not the caller's (or is gone) — never a diff. */
export function changeDiffError(e: unknown): string {
  if (httpFailure(e)?.status === 404) return "This change is not in your workspace, or it no longer exists.";
  return operatorError(e, "What this change did could not be read.");
}

export default function ChangeDiff({ id, initiallyOpen = false }: { id: string; initiallyOpen?: boolean }) {
  const [open, setOpen] = useState(initiallyOpen);
  const [data, setData] = useState<ChangeDiffResponse | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  // The id already read (StrictMode runs the mount effect twice; one read).
  const readFor = useRef("");

  const load = async () => {
    readFor.current = id;
    setBusy(true);
    setErr("");
    try {
      setData(await api.changeDiff(id));
    } catch (e) {
      setErr(changeDiffError(e));
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    if (initiallyOpen && id && readFor.current !== id) {
      setData(null);
      void load();
    }
    // load reads the current id; re-run only when the id or mode changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id, initiallyOpen]);

  const toggle = async () => {
    if (open) {
      setOpen(false);
      return;
    }
    setOpen(true);
    if (data || readFor.current === id) return;
    await load();
  };

  const d = data?.diff;
  return (
    <div data-testid="change-diff">
      <button type="button" className="dash-btn" style={{ fontSize: 14 }} aria-expanded={open} onClick={() => void toggle()}>
        {open ? "Hide" : "What changed"}
      </button>
      {open && busy && <div className="dx-cap">Reading…</div>}
      {open && err && <div role="alert" className="dx-cap" style={{ color: "var(--bad)" }}>{err}</div>}
      {open && data && data.kind === "config" && d && (
        d.unavailable
          ? <div className="dx-cap">{d.unavailable}</div>
          : (
            <div>
              <div className="dx-cap">+{d.added} / −{d.removed} lines{d.truncated ? " (diff shortened)" : ""} · secrets are hidden</div>
              <pre className="dx-mono" style={{ fontSize: 14, whiteSpace: "pre-wrap", maxHeight: 320, overflow: "auto", margin: "4px 0 0" }}>{d.unified}</pre>
            </div>
          )
      )}
      {open && data && data.kind === "values" && (
        data.before || data.after
          ? <div className="dx-mono" style={{ fontSize: 14 }}>{data.before || "—"} → {data.after || "—"}</div>
          : <div className="dx-cap">Not recorded.</div>
      )}
    </div>
  );
}
