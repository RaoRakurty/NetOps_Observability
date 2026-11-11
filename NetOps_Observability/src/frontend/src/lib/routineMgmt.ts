// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// routineMgmt.ts: routine management sessions on the Logs page (owner decision
// 2026-11-11). The sessions monitoring systems and SD-WAN controllers open on a
// device all day were 96 % of the lab's syslog: SNMP polls, their group and close
// lines, and the controller's NETCONF and SSH sessions. They are never deleted;
// the page leaves them out by default and says how many it left out, the same
// pattern as the flows views' "Show Correlix's own polling".
//
// The SERVER decides which records are routine (src/backend/internal/logroutine)
// and names the rule on each shown record (OpenSearch matched_queries). Nothing
// here classifies a record: it only words the server's answer. Security records,
// failures and a person's logins are never in the class.

/** The rule names the server puts in matched_queries (logroutine.Rule*). */
export const ROUTINE_RULES = {
  poll: "routine_mgmt.poll",
  monitoring: "routine_mgmt.monitoring_source",
  controller: "routine_mgmt.controller_source",
  detail: "routine_mgmt.session_detail",
} as const;

/** One line per rule: why the record is classed routine, in plain words. */
const REASONS: Record<string, string> = {
  [ROUTINE_RULES.poll]: "Routine: an SNMP monitoring poll. SNMP never carries a person's login.",
  [ROUTINE_RULES.monitoring]: "Routine: an automated session from Correlix's own address.",
  [ROUTINE_RULES.controller]: "Routine: a session opened by the SD-WAN controller that manages this device.",
  [ROUTINE_RULES.detail]: "Routine: a step inside a management session. The login that opened it is shown on its own.",
};

/** Why a shown record is routine, or null when it is not. */
export function routineReason(matched: readonly string[] | null | undefined): string | null {
  if (!matched) return null;
  for (const name of matched) {
    const reason = REASONS[name];
    if (reason) return reason;
  }
  return null;
}

/** What a search answer says about the class (absent on stores that hold none). */
export type RoutineSummary = { included: boolean; count: number };

export const ROUTINE_TOGGLE_LABEL = "Show routine management sessions";
export const ROUTINE_TOGGLE_HINT = "Monitoring polls and SD-WAN controller sessions. Security records, failed logins and people's logins are always shown.";

const fmt = (x: number) => x.toLocaleString("en-US");
const sessions = (x: number) => `${fmt(x)} routine management ${x === 1 ? "session" : "sessions"}`;

/** The sentence beside the toggle. Empty when the answer carries no summary. */
export function routineNote(summary: RoutineSummary | null | undefined): string {
  if (!summary) return "";
  const x = Math.max(0, Math.floor(Number(summary.count) || 0));
  if (x === 0) return "No routine management sessions match this search.";
  return summary.included ? `Includes ${sessions(x)}.` : `${sessions(x)} hidden.`;
}

/** The viewer's choice, remembered in this browser only. */
export const ROUTINE_STORAGE_KEY = "correlix.logs.showRoutineMgmt";

/** Reads the remembered choice. Off when nothing is stored or storage is unavailable. */
export function loadShowRoutine(): boolean {
  try {
    return window.localStorage.getItem(ROUTINE_STORAGE_KEY) === "1";
  } catch {
    return false;
  }
}

/** Remembers the choice. A browser that refuses storage keeps it for this visit only. */
export function saveShowRoutine(show: boolean): void {
  try {
    if (show) window.localStorage.setItem(ROUTINE_STORAGE_KEY, "1");
    else window.localStorage.removeItem(ROUTINE_STORAGE_KEY);
  } catch {
    // Private window or blocked site data: nothing to do, the toggle still works.
  }
}
