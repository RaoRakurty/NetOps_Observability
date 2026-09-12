// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// TacCaseChip — the vendor case, as one line, wherever the case is relevant.
//
// Design of record: docs/design/TAC_ESCALATION_2026-09-05.md; the chip itself is
// internal/tac/caselink.go, whose header carries the owner's requirement
// (2026-09-07): "finally display message on Correlix with case number and its
// status, update the status of the case with a refresh interval that is
// reasonable for case management".
//
// ONE COMPONENT, THREE HOSTS. The escalation panel, the investigation answer
// card and the Operations incident list all show the same case, and a second
// implementation would word it differently within a release.
//
// WHERE THE SENTENCE COMES FROM. The SERVER computes it wherever it can — the
// state read, the confirm reply and the refresh reply each carry `status_line`
// and `tooltip` from the same Go functions — and this component prefers those.
// The client-side mirror in tacModel is the fallback, and it is not merely a
// convenience: the Operations incident list reads INCIDENTS, not the
// escalation's case register, so no server string exists for that row at all.
// The mirror is therefore tested directly against the Go behaviour cases.
//
// THE RULE THIS EXISTS TO KEEP. A failed status read renders "status unknown
// since <time> — <cause>", never the status it last saw. Showing yesterday's
// "Open" as if it were current is the failure mode caselink.go was written to
// prevent, and a chip that quietly reverted to it would undo that.
//
// §15 LLM02 / §3 zero trust: the case id, the vendor's status word, the cause of
// a failed read and the deep link are all REMOTE text. Every one of them is
// rendered as escaped React text; the link is rendered only when it is an
// https URL, so a vendor string can never become a javascript: target.

import { useState } from "react";
import { api, type TacCaseLink } from "../../services/api";
import {
  CASE_CHIP_TONE,
  REFRESH_FAILED,
  canRefresh,
  caseChipState,
  caseStatusLine,
  caseTooltip,
  refreshWaitMessage,
  tacError,
} from "../../pages/troubleshoot/tacModel";

/** The label on the operator's own refresh. Never "Poll now": Correlix collects. */
export const REFRESH_LABEL = "Refresh now";
export const REFRESHING_LABEL = "Refreshing…";

/** Only an https deep link is ever rendered as one. */
function safeCaseHref(url: string | undefined): string {
  const v = (url ?? "").trim();
  return /^https:\/\//i.test(v) ? v : "";
}

export default function TacCaseChip({
  link, incidentId, onRefreshed, compact = false, statusLine, tooltip,
}: {
  link: TacCaseLink | null | undefined;
  /** Present only where a refresh is possible — the list rows read incidents,
   *  which carry no register entry to re-read. */
  incidentId?: string;
  onRefreshed?: (next: TacCaseLink) => void;
  /** The incident-list rendering: the sentence and its tooltip, no controls. */
  compact?: boolean;
  /** The SERVER's own sentence and hover text, where the caller has them. The
   *  mirror below is the fallback, and it is what the incident list uses: that
   *  row reads incidents, not the escalation's case register, so no server
   *  string exists for it. Preferring the server's where it exists is what
   *  keeps a wording change to one place. */
  statusLine?: string;
  tooltip?: string;
}) {
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState("");
  const [live, setLive] = useState<{ line: string; tip: string } | null>(null);

  if (!link) return null;
  const state = caseChipState(link);
  const line = live?.line || (statusLine ?? "").trim() || caseStatusLine(link);
  const tip = live?.tip || (tooltip ?? "").trim() || caseTooltip(link);
  const href = safeCaseHref(link.case_url);
  const refreshable = Boolean(incidentId) && canRefresh(link) && !compact;

  const refresh = async () => {
    if (!incidentId) return;
    setBusy(true);
    setNote("");
    try {
      const r = await api.tacCaseRefresh(incidentId);
      // The refresh answers with the server's own two strings. Taking them is
      // not an optimisation: it is what stops a re-read wording the case one
      // way and the poller wording it another.
      setLive({ line: (r.status_line ?? "").trim(), tip: (r.tooltip ?? "").trim() });
      onRefreshed?.(r.case);
    } catch (e) {
      // A 429 is the 60-second floor doing its job, and the server says how
      // long. It is a WAIT, not a failure, so it does not read as an alert.
      const wait = refreshWaitMessage(e);
      setNote(wait || tacError(e, REFRESH_FAILED));
    } finally {
      setBusy(false);
    }
  };

  return (
    <span className="tac-case-chip" data-testid="tac-case-chip" data-state={state}>
      <span className={`tac-chip ${CASE_CHIP_TONE[state]}`} title={tip} data-testid="tac-case-line">
        {line}
      </span>
      {href && (
        <a href={href} target="_blank" rel="noreferrer noopener" data-testid="tac-case-link">
          {/* The LINK is labelled, not numbered. The chip beside it already says
              the case number; repeating it as the link text read as two cases,
              and gave the operator nothing to click that said where it went. */}
          Open at the vendor
        </a>
      )}
      {refreshable && (
        <button
          type="button"
          className="btn tiny"
          disabled={busy}
          onClick={() => { void refresh(); }}
          data-testid="tac-case-refresh"
        >
          {busy ? REFRESHING_LABEL : REFRESH_LABEL}
        </button>
      )}
      {note && (
        <span className="fact-line" role="status" data-testid="tac-case-refresh-note">{note}</span>
      )}
    </span>
  );
}
