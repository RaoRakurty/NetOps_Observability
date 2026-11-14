// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// changes.ts — pure wording for one change-ledger row (plan/lists.go changeRow).
//
// The honesty rule lives here so every change surface says it the same way: a
// change the ledger found near a problem is related IN TIME only. "temporal" is
// never shown as a cause; only the engine's causal chain can say "caused".

import { cellText, hasBeforeAfter, humanize, type Row } from "./presentation";

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
    // N-S3: the engine's causal chain for that incident names a change of this
    // KIND. The chain does not name the individual change, so this is not proof.
    case "chain_kind":
      return "Same kind as a root-cause step — not proven cause";
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

// The ledger's change types (experience.ChangeType) in the operator's words.
// One map for every change surface — the table, its drawer and the title —
// so a row never says NETWORK_CHANGE where the drawer says "Network change".
const CHANGE_TYPE_WORDS: Record<string, string> = {
  APPLICATION_DEPLOY: "Application deploy",
  CONFIG_CHANGE: "Config change",
  FEATURE_FLAG_CHANGE: "Feature flag change",
  CLOUD_CHANGE: "Cloud change",
  NETWORK_CHANGE: "Network change",
  SECURITY_POLICY_CHANGE: "Security policy change",
  DNS_CHANGE: "DNS change",
  ROUTE_CHANGE: "Routing change",
  INFRASTRUCTURE_CHANGE: "Infrastructure change",
};

/** The change type in plain words; "" when the row records none. */
export function changeTypeText(r: Row): string {
  const t = str(r, "type").trim();
  if (!t) return "";
  const key = t.toUpperCase();
  // Own keys only: a hostile "__proto__" must not resolve to Object's.
  if (Object.prototype.hasOwnProperty.call(CHANGE_TYPE_WORDS, key)) return CHANGE_TYPE_WORDS[key];
  return humanize(t);
}

/** A one-line name for a change: "Config change · core-sw-1". */
export function changeTitle(r: Row): string {
  const obj = str(r, "object");
  const parts = [changeTypeText(r) || "Change", obj].filter(Boolean);
  return parts.join(" · ");
}

/**
 * The ledger id whose diff can be read from /api/changes/{id}/diff, or "".
 * Only when the row says a diff exists (has_diff) and does not already carry
 * its own before/after — then there is nothing to fetch.
 */
export function diffableChangeId(r: Row): string {
  if (r.has_diff !== true || hasBeforeAfter(r)) return "";
  const id = str(r, "change_id").trim();
  // The ledger's id shape (changeapi idRe); anything else is not fetched.
  return /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(id) ? id : "";
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

/** "12 min before onset" / "at onset" / "3 min after onset"; null when absent. */
export function beforeOnsetText(r: Row): string | null {
  const m = r.minutes_before_incident;
  if (typeof m !== "number" || !Number.isFinite(m)) return null;
  if (m > 0) return `${m} min before onset`;
  if (m === 0) return "At onset";
  return `${-m} min after onset`;
}

/** Rows found near an incident ("what changed before every X incident"). */
export function isPerIncidentRow(r: Row): boolean {
  return str(r, "incident_id") !== "" && typeof r.minutes_before_incident === "number";
}
