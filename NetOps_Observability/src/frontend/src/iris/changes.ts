// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// changes.ts — pure wording for one change-ledger row (plan/lists.go changeRow).
//
// The honesty rule lives here so every change surface says it the same way: a
// change the ledger found near a problem is related IN TIME only. "temporal" is
// never shown as a cause; only the engine's causal chain can say "caused".

import { cellText, humanize, type Row } from "./presentation";

export function str(r: Row, k: string): string {
  const v = r[k];
  return typeof v === "string" ? v : "";
}

/** The relation column, in the operator's words. Unknown → "Not stated". */
export function relationText(r: Row): string {
  switch (str(r, "relation")) {
    case "temporal":
      return "Happened before — not proven cause";
    case "causal":
      return "Linked by the root-cause engine";
    default:
      return "Not stated";
  }
}

/** Automation vs manual, only when the record says so. */
export function automationText(r: Row): string {
  const a = r.automated;
  if (a === true) return "Automation";
  if (a === false) return "Manual";
  const o = str(r, "origin").toLowerCase();
  if (o === "automation" || o === "automated") return "Automation";
  if (o === "manual") return "Manual";
  return "Not recorded";
}

/** Where the change record came from. */
export function changeSourceText(r: Row): string {
  const s = str(r, "source");
  if (s === "ledger") return "Change record";
  return s || "Not recorded";
}

/** A one-line name for a change: "Config change · core-sw-1". */
export function changeTitle(r: Row): string {
  const type = str(r, "type");
  const obj = str(r, "object");
  const parts = [type ? humanize(type) : "Change", obj].filter(Boolean);
  return parts.join(" · ");
}

/** A short before → after for the table cell, or null when none is recorded. */
export function beforeAfterShort(r: Row): string | null {
  if (r.before === undefined && r.after === undefined) return null;
  const b = typeof r.before === "string" ? r.before : cellText(r.before);
  const a = typeof r.after === "string" ? r.after : cellText(r.after);
  const short = (s: string | null) => {
    if (s === null || s === "") return "(none)";
    const one = s.replace(/\s+/g, " ").trim();
    return one.length > 40 ? `${one.slice(0, 40)}…` : one;
  };
  return `${short(b)} → ${short(a)}`;
}
