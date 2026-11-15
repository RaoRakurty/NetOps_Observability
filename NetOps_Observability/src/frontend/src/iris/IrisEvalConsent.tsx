// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// IrisEvalConsent — the person's OWN choice to share their Iris questions with
// their workspace's evaluation set (tracker 337 N-H3). Off until they tick it;
// unticking it takes effect at the next export. It is never set for anyone
// else, and the box is hidden when the server has no store for it.

import { useEffect, useState } from "react";
import { api } from "../services/api";
import { httpFailure, operatorError } from "../lib/errors";

const text14 = { fontSize: 14 } as const;
const muted = { color: "var(--muted)", fontSize: 14 } as const;

export default function IrisEvalConsent() {
  const [on, setOn] = useState<boolean | null>(null);
  const [hidden, setHidden] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let live = true;
    Promise.resolve()
      .then(() => api.irisEvalConsent())
      .then((c) => {
        if (live) setOn(Boolean(c?.consented));
      })
      .catch((e) => {
        if (!live) return;
        const f = httpFailure(e);
        // No workspace (the platform view) or no store: nothing to choose here.
        if (f && (f.status === 400 || f.status === 503 || f.status === 403)) setHidden(true);
        else setErr(operatorError(e, "Your sharing choice could not be read."));
      });
    return () => {
      live = false;
    };
  }, []);

  if (hidden || on === null) {
    return err ? (
      <p role="alert" style={text14}>
        {err}
      </p>
    ) : null;
  }

  const change = async (next: boolean) => {
    setBusy(true);
    setErr("");
    try {
      setOn(Boolean((await api.setIrisEvalConsent(next)).consented));
    } catch (e) {
      setErr(operatorError(e, "Your sharing choice could not be saved."));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div data-testid="iris-eval-consent" style={{ ...text14, margin: "6px 0" }}>
      <label style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 14 }}>
        <input type="checkbox" checked={on} disabled={busy} onChange={(e) => void change(e.target.checked)} style={{ fontSize: 14 }} />
        Share my questions to help test Iris
      </label>
      <p style={{ ...muted, margin: "2px 0 0" }}>
        Your admin may export them, unnamed, for review. Untick to stop.
      </p>
      {err && (
        <p role="alert" style={text14}>
          {err}
        </p>
      )}
    </div>
  );
}
