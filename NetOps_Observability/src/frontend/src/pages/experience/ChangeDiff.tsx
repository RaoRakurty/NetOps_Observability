// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ChangeDiff — "What changed" for one ledger change (tracker 337 N-D3), read
// from /api/changes/{id}/diff on demand. A configuration change shows the
// redacted unified diff of its two captured versions; any other change its
// redacted before → after. Everything is rendered as text.

import { useState } from "react";
import { api, type ChangeDiffResponse } from "../../services/api";
import { operatorError } from "../../lib/errors";

export default function ChangeDiff({ id }: { id: string }) {
  const [open, setOpen] = useState(false);
  const [data, setData] = useState<ChangeDiffResponse | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const toggle = async () => {
    if (open) {
      setOpen(false);
      return;
    }
    setOpen(true);
    if (data) return;
    setBusy(true);
    setErr("");
    try {
      setData(await api.changeDiff(id));
    } catch (e) {
      setErr(operatorError(e, "What this change did could not be read."));
    } finally {
      setBusy(false);
    }
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
