// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// QueryExplain — "Explain this query" on one recorded Iris question (tracker
// 337 N-C5, Part 2 §33 "Interpreted Query").
//
// The server reads the stored query, says in plain words what it does (what
// it measures, about what, when, filtered and grouped how) and re-checks it
// against what the operator can see now. When the AI model — not the built-in
// question grammar — wrote the query, that is said first, every time.
//
// Every string shown here came from the server and is rendered as escaped
// React text, never markup.

import { useState } from "react";
import { api, type IrisQueryExplanation } from "../services/api";
import { operatorError } from "../lib/errors";

const text14 = { fontSize: 14 } as const;
const muted = { color: "var(--muted)", fontSize: 14 } as const;

export const FACET_LABEL: Record<string, string> = {
  what: "What it does",
  metric: "Measurement",
  entities: "About",
  filters: "Filters",
  condition: "Condition",
  window: "When",
  compare: "Compared with",
  grouping: "Grouping",
  order: "Order",
  limit: "Limit",
  incident: "Incident",
};

export default function QueryExplain({ queryId }: { queryId: string }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [ex, setEx] = useState<IrisQueryExplanation | null>(null);

  const toggle = async () => {
    if (open) {
      setOpen(false);
      return;
    }
    setOpen(true);
    if (ex) return;
    setBusy(true);
    setErr("");
    try {
      setEx(await api.explainIrisQuery(queryId));
    } catch (e) {
      setErr(operatorError(e, "The explanation could not be loaded."));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <button type="button" className="dash-btn" style={{ ...text14, marginTop: 6 }} aria-expanded={open} onClick={() => void toggle()}>
        {open ? "Hide explanation" : "Explain this query"}
      </button>
      {open && (
        <div data-testid="iris-explain" style={{ ...text14, marginTop: 6 }}>
          {busy && <div style={muted}>Reading the query…</div>}
          {err && <div role="alert" style={{ ...text14, color: "var(--bad)" }}>{err}</div>}
          {ex && (
            <>
              {ex.source === "model" && (
                <div role="note" data-testid="iris-explain-model" style={{ ...text14, color: "var(--warn)", marginBottom: 4 }}>
                  {ex.disclosure || "Interpreted by the AI model, not the built-in question grammar."}
                </div>
              )}
              {ex.explanation ? (
                <>
                  <div style={{ fontSize: 16, marginBottom: 4 }}>{ex.explanation.summary}</div>
                  <dl style={{ margin: 0, display: "grid", gridTemplateColumns: "max-content 1fr", columnGap: 12, rowGap: 2 }}>
                    {ex.explanation.parts.map((p) => (
                      <div key={p.facet} style={{ display: "contents" }}>
                        <dt style={muted}>{FACET_LABEL[p.facet] ?? p.facet}</dt>
                        <dd style={{ ...text14, margin: 0 }}>{p.text}</dd>
                      </div>
                    ))}
                  </dl>
                  {ex.still_valid === false && (
                    <div style={{ ...text14, color: "var(--warn)", marginTop: 4 }} data-testid="iris-explain-stale">
                      This query no longer passes its checks for you — something it names may no longer be visible to you.
                    </div>
                  )}
                  {ex.compiled_by === "supplied" && <div style={muted}>This query was supplied directly, not written from a question.</div>}
                </>
              ) : (
                <div style={muted}>{ex.reason || "No query was kept for this question."}</div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
