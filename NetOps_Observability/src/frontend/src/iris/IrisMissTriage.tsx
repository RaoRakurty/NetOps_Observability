// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// IrisMissTriage — the questions Iris left unanswered, grouped by WHY
// (model-first decision point 5). The fix for a class is a tool, data, a route
// or a description — never a phrase written for one wording — so this panel
// shows the classes, how many questions each holds, and the caller's own
// example questions (a colleague's wording is withheld by the server).
//
// Workspace admins only; the server decides who may and scopes it. Every field
// is rendered as escaped React text.

import { useCallback, useEffect, useState } from "react";
import { api, type IrisMissClass, type IrisTriage } from "../services/api";
import { httpFailure, operatorError } from "../lib/errors";

export const CLASS_LABEL: Record<IrisMissClass, { title: string; fix: string }> = {
  no_tool: { title: "No tool for it", fix: "Nothing in this installation can answer these yet." },
  no_data: { title: "Searched, nothing found", fix: "The right place was searched and held nothing (no document, playbook, page or rows)." },
  wrong_route: { title: "Wrong kind of answer", fix: "The operator said the answer was not what they meant." },
  wrong_tool: { title: "Wrong reading", fix: "The operator corrected the device, metric, time window or filter." },
  wording: { title: "Wording not understood", fix: "Nothing read the words — connect an AI model, or check the question." },
  provider_error: { title: "AI model did not answer", fix: "The AI model was on but did not respond; see Iris AI models." },
};

const text14 = { fontSize: 14 } as const;
const muted = { color: "var(--muted)", fontSize: 14 } as const;

export default function IrisMissTriage({ refreshKey }: { refreshKey?: unknown }) {
  const [view, setView] = useState<IrisTriage | null>(null);
  const [err, setErr] = useState("");
  const [denied, setDenied] = useState(false);

  const load = useCallback(async () => {
    try {
      setView(await api.irisTriage());
      setErr("");
    } catch (e) {
      if (httpFailure(e)?.status === 403) {
        setDenied(true);
        return;
      }
      setErr(operatorError(e, "The unanswered questions could not be loaded."));
    }
  }, []);

  useEffect(() => { void load(); }, [load, refreshKey]);

  if (denied) return <p style={muted}>Only workspace admins can see this.</p>;
  if (err) return <p role="alert" style={text14}>{err}</p>;
  if (!view) return <p style={muted}>Loading…</p>;
  const classes = view.classes ?? [];
  if (classes.length === 0) return <p style={muted}>Iris has answered every recent question.</p>;
  return (
    <div data-testid="iris-miss-triage">
      <ol style={{ ...text14, paddingLeft: 20, margin: 0 }}>
        {classes.map((c) => {
          const label = CLASS_LABEL[c.class] ?? { title: c.class, fix: "" };
          return (
            <li key={c.class} style={{ marginBottom: 8 }}>
              <div><strong>{label.title}</strong> — {c.count} question{c.count === 1 ? "" : "s"}</div>
              <div style={muted}>{label.fix}</div>
              {c.examples.filter((x) => x.question).length > 0 && (
                <ul style={{ margin: "4px 0 0", paddingLeft: 18 }}>
                  {c.examples.filter((x) => x.question).map((x, i) => (
                    <li key={i} style={text14}>“{x.question}”{view.scope === "platform" && x.tenant ? ` (${x.tenant})` : ""}</li>
                  ))}
                </ul>
              )}
            </li>
          );
        })}
      </ol>
      <p style={{ ...muted, marginTop: 6 }}>From {view.window}.</p>
    </div>
  );
}
