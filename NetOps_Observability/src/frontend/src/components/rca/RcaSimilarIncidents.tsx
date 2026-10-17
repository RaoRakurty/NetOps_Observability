// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// RcaSimilarIncidents — "Similar past incidents" in the RCA workspace (tracker
// 337 N-F4). Earlier CLOSED incidents of this workspace that look like this one
// (GET /api/correlations/{id}/similar). Honest by construction: below the
// server's threshold it says "No similar incident" and shows no near miss, and
// every match is labelled as context — similar is not the same cause.

import { useEffect, useState } from "react";
import { api, SimilarIncidents } from "../../services/api";
import { fmtDateTime } from "../../lib/time";
import { operatorError } from "../../lib/errors";

export default function RcaSimilarIncidents({ correlationId }: { correlationId: string }) {
  const [res, setRes] = useState<SimilarIncidents | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    api.correlationSimilar(correlationId)
      .then((r) => { if (live) { setRes(r); setError(null); } })
      .catch((e) => { if (live) setError(operatorError(e, "Similar incidents could not be read.")); });
    return () => { live = false; };
  }, [correlationId]);

  if (error) return <section className="rw-panel"><p className="disc-text" role="alert">{error}</p></section>;
  if (!res) return <section className="rw-panel"><p className="disc-text">Looking for similar incidents…</p></section>;
  const matches = res.matches ?? [];
  return (
    <section className="rw-panel" aria-label="Similar past incidents">
      {matches.length === 0 ? (
        <p className="disc-text"><strong>No similar incident.</strong> {res.note}</p>
      ) : (
        <ol className="op-actions">
          {matches.map((m) => (
            <li key={m.correlation_id}>
              <a href={`#/investigate/rca?id=${encodeURIComponent(m.correlation_id)}`}>
                {m.strength === "strong" ? "Strong match" : "Similar"} · {fmtDateTime(m.occurred_at)}
              </a>{" "}
              — matched on {(m.matched_on ?? []).join(", ")}
              {m.differences && m.differences.length > 0 ? `; differs in ${m.differences.join(", ")}` : ""}
            </li>
          ))}
        </ol>
      )}
      <p className="disc-text" style={{ color: "var(--muted)" }}>{res.caveat}</p>
    </section>
  );
}
