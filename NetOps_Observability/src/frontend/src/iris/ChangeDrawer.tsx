// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ChangeDrawer — one change, opened from the change table or timeline
// (tracker 337 N-E3, design Part 2 §28). Everything the ledger recorded, the
// honest relation wording, the before/after diff when one exists, and where the
// row came from — inline, so there is never a dialog on top of a dialog.
//
// All values are untrusted text rendered as escaped React text nodes; every
// reference goes through the safe link map.

import { Modal } from "../components/ui";
import { fmtDateTime } from "../lib/time";
import { cellText, hasBeforeAfter, type ResultSet, type Row } from "./presentation";
import { automationText, changeSourceText, changeTitle, relationText, str } from "./changes";
import { SafeLink } from "./links";
import JsonDiff from "./JsonDiff";
import { EvidenceDetails } from "./EvidenceDrawer";

function Field({ label, value }: { label: string; value: string | null }) {
  return (
    <>
      <dt>{label}</dt>
      <dd>{value ?? <span className="iris-muted">Not recorded</span>}</dd>
    </>
  );
}

export default function ChangeDrawer({
  row,
  result,
  onClose,
}: {
  row: Row;
  result?: ResultSet;
  onClose: () => void;
}) {
  const changeId = str(row, "change_id");
  const incidentId = str(row, "incident_id");
  const time = str(row, "time");
  const minutes = typeof row.minutes_before_incident === "number" && Number.isFinite(row.minutes_before_incident)
    ? row.minutes_before_incident
    : null;
  // One note, whichever applies (the word budget allows one per card).
  const diffNote = row.has_diff === true
    ? "Before/after not included here — open the change record."
    : "No before/after was recorded for this change.";
  return (
    <Modal title={changeTitle(row)} subtitle={time ? fmtDateTime(time) : "Time not recorded"} onClose={onClose}>
      <div className="iris-drawer">
        {cellText(row.summary) && <p className="iris-text">{cellText(row.summary)}</p>}
        <dl className="iris-kv">
          <Field label="Who" value={cellText(row.actor)} />
          <Field label="Change type" value={cellText(row.type)} />
          <Field label="Object" value={cellText(row.object)} />
          <Field label="Object kind" value={cellText(row.object_kind)} />
          <dt>Site</dt>
          <dd>
            {str(row, "site") ? (
              <SafeLink kind="site" id={str(row, "site")}>
                {str(row, "site")}
              </SafeLink>
            ) : (
              <span className="iris-muted">Not recorded</span>
            )}
          </dd>
          <Field label="Application" value={cellText(row.app)} />
          <Field label="Ticket" value={cellText(row.ticket)} />
          <Field label="Recorded by" value={changeSourceText(row)} />
          <Field label="Automation or manual" value={automationText(row)} />
          <dt>Relation</dt>
          <dd>
            {relationText(row)}
            {incidentId && (
              <>
                {" "}
                to incident{" "}
                <SafeLink kind="incident" id={incidentId}>
                  {incidentId}
                </SafeLink>
                {minutes !== null && ` (${minutes} minutes before it started)`}
              </>
            )}
          </dd>
          {changeId && (
            <>
              <dt>Change record</dt>
              <dd>
                <SafeLink kind="change" id={changeId}>
                  Open the change record
                </SafeLink>
              </dd>
            </>
          )}
        </dl>

        {hasBeforeAfter(row) ? (
          <JsonDiff before={row.before} after={row.after} />
        ) : (
          <p className="iris-note">{diffNote}</p>
        )}

        {result && (
          <section aria-label="Why am I seeing this?">
            <h3 className="iris-h">Data source</h3>
            <EvidenceDetails result={result} row={row} />
          </section>
        )}
      </div>
    </Modal>
  );
}
