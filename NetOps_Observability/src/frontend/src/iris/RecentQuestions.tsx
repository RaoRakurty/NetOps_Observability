// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// RecentQuestions — the caller's own recent Iris questions and what became of
// each (tracker 337 N-C8). Each can be marked "That's not what I meant". A
// workspace admin can switch to everyone's questions in the workspace; the
// server decides who may, and scopes the list to the caller's workspace.
//
// Question text is untrusted and rendered as escaped React text.

import { useCallback, useEffect, useState } from "react";
import { api, type IrisQueryRecord } from "../services/api";
import { operatorError } from "../lib/errors";
import QueryCorrection from "./QueryCorrection";

export const RECORD_OUTCOME_LABEL: Record<IrisQueryRecord["outcome"], string> = {
  answered: "answered", compiled: "read, not run", clarify: "needed you to choose", declined: "declined",
  unparsed: "not understood", invalid: "could not be run", error: "failed",
};

const SOURCE_LABEL: Record<IrisQueryRecord["source"], string> = {
  router: "Iris box", query_compile: "vocabulary", query_execute: "vocabulary (run)", conversation: "conversation",
};

const text14 = { fontSize: 14 } as const;
const muted = { color: "var(--muted)", fontSize: 14 } as const;

function when(at: string): string {
  const d = new Date(at);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleString();
}

export default function RecentQuestions({ refreshKey = 0 }: { refreshKey?: number }) {
  const [everyone, setEveryone] = useState(false);
  const [recs, setRecs] = useState<IrisQueryRecord[]>([]);
  const [days, setDays] = useState(0);
  const [err, setErr] = useState("");
  const [loaded, setLoaded] = useState(false);

  const load = useCallback(async () => {
    try {
      const r = await api.irisQueries(everyone ? "tenant" : "mine", 10);
      setRecs(r.queries ?? []);
      setDays(r.retention_days);
      setErr("");
    } catch (e) {
      setRecs([]);
      setErr(operatorError(e, "Recent questions could not be loaded."));
    } finally {
      setLoaded(true);
    }
  }, [everyone]);

  useEffect(() => { void load(); }, [load, refreshKey]);

  return (
    <div data-testid="iris-recent">
      <label style={{ ...text14, display: "inline-flex", gap: 6, alignItems: "center" }}>
        <input type="checkbox" style={text14} checked={everyone} onChange={(e) => setEveryone(e.target.checked)} />
        Everyone in this workspace (admins)
      </label>
      {err && <div role="alert" style={{ ...text14, color: "var(--bad)" }}>{err}</div>}
      {loaded && !err && recs.length === 0 && <div style={muted}>No questions yet.</div>}
      {recs.length > 0 && (
        <ul style={{ margin: "4px 0 0", paddingLeft: 18 }} data-testid="iris-recent-list">
          {recs.map((r) => {
            const fixes = r.corrections?.length ?? 0;
            return (
              <li key={r.id} style={{ ...text14, marginBottom: 6 }}>
                <span>{r.question || "A query you ran"}</span>{" "}
                <span style={muted}>
                  — {RECORD_OUTCOME_LABEL[r.outcome] ?? r.outcome}, {SOURCE_LABEL[r.source] ?? r.source}, {when(r.at)}
                  {everyone && <>, asked by {r.principal}</>}
                </span>
                {fixes > 0 && <span className="badge" style={{ fontSize: 14, marginLeft: 6 }}>{fixes} correction{fixes === 1 ? "" : "s"}</span>}
                {!everyone && <QueryCorrection queryId={r.id} onSaved={() => void load()} />}
              </li>
            );
          })}
        </ul>
      )}
      {days > 0 && <div style={muted}>Kept for {days} days.</div>}
    </div>
  );
}
