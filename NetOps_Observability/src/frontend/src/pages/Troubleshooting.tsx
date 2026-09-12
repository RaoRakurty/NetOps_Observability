// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { useEffect } from "react";
import InvestigationPage from "./troubleshoot/InvestigationPage";
import {
  hashWithoutSection,
  parseInvestigationHash,
  type TroubleshootSection,
} from "./troubleshoot/investigationModel";

// Troubleshooting — ONE FACE: the investigation surface. Pick an open case (or
// describe one), read the answer, open the evidence (Project 4 §A).
//
// WHAT LEFT, AND WHERE IT WENT (owner, 2026-09-07: "Whenever I refresh
// troubleshooting page there is a stale page … It looks like stale page"). The
// page used to carry a second section, the June collection-pipeline board, and
// a bookmark holding `?section=pipeline` reopened it on every refresh — which
// reads as a stale page, because it is the old one. The board is deleted:
//
//   · its fleet counts (monitored, SNMP-reachable, flows, traps), its
//     per-collector rows and its flow-source list moved to Platform → Stack
//     Health, beside the rest of the stack's own health;
//   · its four collector charts became those rows — the same facts, read now
//     instead of over a window;
//   · its flow-source list (per type: flows and exporters) moved with them —
//     neither Stack Health nor the Pipeline Debugger carried it;
//   · its "individual traps live in Log Explorer" pointer and its "flow
//     analysis lives in the Flows dashboard" pointer were dropped: both
//     screens are one nav click away and say so themselves.
//
// The earlier "Protocol diagnostics" section was removed on 2026-09-05
// (docs/design/TAC_ESCALATION_2026-09-05.md §5). Both retired deep links land
// here, and the parameter is stripped from the address so the next refresh is
// clean.
export type { TroubleshootSection };

/** Kept for callers that still ask: the page has one section. */
export function sectionFromHash(hash?: string): TroubleshootSection {
  const h = hash ?? (typeof location !== "undefined" ? location.hash : "");
  return parseInvestigationHash(h).section;
}

export default function Troubleshooting({ rangeMinutes = 60 }: { rangeMinutes?: number } = {}) {
  const initial = parseInvestigationHash(typeof location !== "undefined" ? location.hash : "");

  // A retired `?section=` is honoured once (it lands here) and then erased, so a
  // refresh cannot reopen a surface that no longer exists. replaceState does not
  // raise hashchange, so the router is not disturbed.
  useEffect(() => {
    if (typeof location === "undefined" || typeof history === "undefined") return;
    const cleaned = hashWithoutSection(location.hash);
    if (cleaned && cleaned !== location.hash) history.replaceState(null, "", cleaned);
  }, []);

  return (
    <div className="dm-board">
      <InvestigationPage rangeMinutes={rangeMinutes} initialCaseId={initial.caseId} />
    </div>
  );
}
