// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// fidelity.ts — the ONE parser-evidence fidelity vocabulary (parser programme
// W1b/A3). Every classified signal carries `attrs.fidelity`, and two surfaces
// now render it: the Telemetry Coverage rules table and the RCA evidence rows.
// The tier table lived in pages/telemetry/coverageModel.ts; it is extracted here
// so both surfaces share ONE ladder, ONE set of colours and ONE tooltip — a
// second copy would drift and the two pages would grade the same rule
// differently.
//
// Pure (no React, no DOM) so the RCA adapter and the PDF exporter can use it.
import type { ParserFidelity } from "../services/api";

// Evidence ladder, strongest first. The badge tier classes already exist in
// styles.css (tier-t1 green … tier-t5 neutral), so the four values get four
// distinct, ordered colours without new CSS.
const FIDELITY: Record<ParserFidelity, { rank: number; cls: string; label: string; title: string }> = {
  live_validated: { rank: 4, cls: "tier-t1", label: "live validated", title: "Confirmed against live device output" },
  lab_validated: { rank: 3, cls: "tier-t3", label: "lab validated", title: "Confirmed against a lab capture" },
  doc_claimed: { rank: 2, cls: "tier-t4", label: "doc claimed", title: "Vendor documentation only — unconfirmed on the wire" },
  code: { rank: 1, cls: "tier-t5", label: "unverified", title: "Defined in the product, not yet confirmed against a device" },
};

export function fidelityBadgeClass(f: string): string {
  const hit = FIDELITY[f as ParserFidelity];
  return `badge ${hit ? hit.cls : "tier-t5"}`;
}

export function fidelityLabel(f: string): string {
  const hit = FIDELITY[f as ParserFidelity];
  return hit ? hit.label : f || "unrated";
}

export function fidelityTitle(f: string): string {
  const hit = FIDELITY[f as ParserFidelity];
  return hit ? hit.title : "Fidelity not recorded — treat as unproven";
}

/** Sort key: higher = stronger evidence. Unknown values sort below `code`. */
export function fidelityRank(f: string): number {
  return FIDELITY[f as ParserFidelity]?.rank ?? 0;
}

/**
 * The WEAKEST tier in a group of observations — the honest grade for a row that
 * fuses several rules. A row is only as trustworthy as its least-proven rule, so
 * a `live_validated` + `code` pair grades `code`; an unrecognised token grades
 * below `code` (rank 0) and is shown verbatim rather than hidden. Returns "" when
 * nothing in the group declared a fidelity — the caller then renders NO badge
 * (an absent grade is not a bad grade).
 */
export function weakestFidelity(values: readonly string[]): string {
  let out = "";
  for (const raw of values) {
    const v = (raw ?? "").trim();
    if (!v) continue;
    if (!out || fidelityRank(v) < fidelityRank(out)) out = v;
  }
  return out;
}
