// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// EvidenceDrawer — "Why am I seeing this?" (tracker 337 N-E3, design Part 2 §32).
//
// Shows the provenance of an answer (or of one row of it) in the operator's
// words: which store it was read from, the time window, the entities it was
// scoped to, any bound the validator tightened, and the query reference an
// administrator can look up. It NEVER shows the physical backend query — the
// normalised ResultSet has no field for it (presentation.ts drops it), and this
// component reads nothing else. Physical text is /explain, administrators only.
//
// The body (EvidenceDetails) is exported so a drawer that already exists — the
// change drawer — can show the same section inline instead of stacking dialogs.

import { Modal } from "../components/ui";
import { fmtDateTime } from "../lib/time";
import { cellText, humanize, rowId, sourceLabels, type ResultSet, type Row } from "./presentation";
import { SafeLink } from "./links";

function windowText(from: string, to: string): string {
  if (!from && !to) return "Not stated";
  return `${fmtDateTime(from)} → ${fmtDateTime(to)}`;
}

export function EvidenceDetails({ result, row }: { result: ResultSet; row?: Row }) {
  const p = result.provenance;
  const sources = sourceLabels(p.source);
  const rowRef = row ? rowId(row, 0) : "";
  return (
    <dl className="iris-kv">
      <dt>Where this came from</dt>
      <dd>{sources.length > 0 ? sources.join(", ") : "Not stated"}</dd>

      <dt>Time window searched</dt>
      <dd>{windowText(result.window.from, result.window.to)}</dd>

      {result.compare && (
        <>
          <dt>Compared with</dt>
          <dd>{windowText(result.compare.from, result.compare.to)}</dd>
        </>
      )}

      <dt>Limited to</dt>
      <dd>
        {p.entities.length === 0 ? (
          "Everything you are allowed to see"
        ) : (
          <ul className="iris-plain-list">
            {p.entities.map((e, i) => (
              <li key={`${e.type}-${e.id}-${i}`}>
                {humanize(e.type)}:{" "}
                <SafeLink kind={e.type} id={e.id}>
                  {e.id}
                </SafeLink>
              </li>
            ))}
          </ul>
        )}
      </dd>

      {row && !rowRef.startsWith("row-") && (
        <>
          <dt>This row</dt>
          <dd className="mono">{rowRef}</dd>
        </>
      )}

      {result.constraints_applied.length > 0 && (
        <>
          <dt>Adjusted to answer safely</dt>
          <dd>
            <ul className="iris-plain-list">
              {result.constraints_applied.map((c, i) => (
                <li key={i}>
                  {humanize(c.path) || "Limit"}: {c.from || "none"} → {c.to || "none"}
                  {c.reason && ` — ${c.reason}`}
                </li>
              ))}
            </ul>
          </dd>
        </>
      )}

      <dt>Answered at</dt>
      <dd>
        {p.executed_at ? fmtDateTime(p.executed_at) : "Not stated"}
        {p.duration_ms !== null && ` · took ${cellText(p.duration_ms)} ms`}
      </dd>

      <dt>Query reference</dt>
      <dd className="mono">{result.query_id || "Not stated"}</dd>
    </dl>
  );
}

export default function EvidenceDrawer({
  result,
  row,
  onClose,
}: {
  result: ResultSet;
  row?: Row;
  onClose: () => void;
}) {
  return (
    <Modal title="Why am I seeing this?" subtitle="Where this answer came from and what it was limited to" onClose={onClose}>
      <EvidenceDetails result={result} row={row} />
      <p className="iris-note">
        An administrator can look up the query by its reference.
      </p>
    </Modal>
  );
}
