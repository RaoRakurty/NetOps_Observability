// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// commandCenter.model.ts — the PURE decision logic behind the Command Center NOC
// view (extracted from CommandCenter.tsx so the product's triage rules are unit-
// testable, not buried in JSX). Mirrors the rcaCase.ts ↔ RcaWorkspace.tsx split.
//
// HONESTY / non-negotiables enforced here:
//   - never "Confirmed" on a single evidence stream (the ≥2-independent-stream rule
//     lives upstream in verdict_tier; this layer must not promote past it);
//   - internal-stack noise is excluded from the customer-facing queue (#76);
//   - a ticket is only "needed" once RCA is Confirmed (no premature ITSM churn).

import type { CorrObject, TicketLinkRow } from "../services/api";
import { ownerLabel, isInternalStackAffected } from "../components/rca/labels";

export type RcaState = "New" | "Correlated" | "RCA running" | "Suspected" | "Confirmed" | "Blocked" | "Resolved";
export type EvidenceState = "Complete" | "Partial" | "Single-stream";
export type FaultDomain = "LAN" | "SD-WAN" | "Data Center" | "ISP / Carrier" | "Cloud Provider" | "Application" | "Security" | "Unknown";
export type OwnerState = "Assigned" | "Recommended" | "Missing" | "Escalated";
export type TicketState =
  | "Not eligible" | "Eligible" | "Ticket needed" | "Ticket pending" | "Ticketed" | "Sync failed"
  // The ticket links could not be read in full, so "no ticket" cannot be said:
  // a miss in a partial read is "not in this page", never "not filed" (F-67).
  | "Unknown";

/** The tenant's ticket links, joined by correlation id. `ok` says the read
 *  succeeded; `complete` says it returned every link (the endpoint pages). */
export type TicketLinks = { byCorr: ReadonlyMap<string, readonly TicketLinkRow[]>; ok: boolean; complete: boolean };

export const NO_TICKET_LINKS: TicketLinks = { byCorr: new Map(), ok: false, complete: false };

/** The queue reads at most this many open problems per refresh. */
export const QUEUE_PAGE = 200;

/** "Showing the 200 newest open problems — more exist" when the read stopped at
 *  the page size, so a truncated queue never passes for the whole picture. */
export function truncationNote(read: number, more: boolean): string {
  return more ? `Showing the ${read} newest open problems — more exist. Open Investigate → RCA for all of them.` : "";
}

/** Problems tab: "needs" is the actionable queue; "all" adds the single-signal
 *  groups still gathering evidence (internal-stack objects stay out of both). */
export type ProblemsTab = "needs" | "all";

export function problemsForTab(all: readonly CorrObject[], tab: ProblemsTab): CorrObject[] {
  return tab === "needs" ? all.filter(isActionableCorr) : all.filter((c) => !isInternalStackAffected(c.affected));
}

/** Indexes a /api/tickets/links answer by correlation id. */
export function indexTicketLinks(rows: readonly TicketLinkRow[] | undefined, complete: boolean): TicketLinks {
  const byCorr = new Map<string, TicketLinkRow[]>();
  for (const r of rows ?? []) {
    if (!r?.corr_object_id) continue;
    const list = byCorr.get(r.corr_object_id);
    if (list) list.push(r);
    else byCorr.set(r.corr_object_id, [r]);
  }
  return { byCorr, ok: true, complete };
}
export type Sev = "crit" | "major" | "warn" | "ok";

export interface ActionItem {
  corr: CorrObject;
  affected: { devices: string[]; paths: string[]; interfaces: string[]; sites: string[] };
  missing: string[];
  sev: Sev;
  rca: RcaState;
  evidence: EvidenceState;
  fault: FaultDomain;
  owner: OwnerState;
  ownerName: string;
  ticket: TicketState;
  nextAction: string;
  ageMs: number;
}

// startedAt — the incident's real start timestamp. SINGLE source of truth for the
// queue's absolute date column AND ageMs (window_start, else created_at), so the
// relative age and the absolute date can never describe different instants.
export const startedAt = (c: CorrObject): string => c.window_start || c.created_at || "";

export const fmtAge = (iso?: string, now: number = Date.now()): string => {
  if (!iso) return "—";
  const ms = now - Date.parse(iso);
  if (!Number.isFinite(ms) || ms < 0) return "—";
  const m = Math.floor(ms / 60_000);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h`;
  return `${Math.floor(h / 24)}d`;
};

const safeArr = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x) => typeof x === "string") : []);

export function parseAffected(json: string): ActionItem["affected"] {
  try {
    const a = JSON.parse(json || "{}");
    return { devices: safeArr(a.devices), paths: safeArr(a.paths), interfaces: safeArr(a.interfaces), sites: safeArr(a.sites) };
  } catch { return { devices: [], paths: [], interfaces: [], sites: [] }; }
}

export function parseMissing(json: string): string[] {
  try { const a = JSON.parse(json || "[]"); return Array.isArray(a) ? a.map(String) : []; } catch { return []; }
}

// RCA state — verdict + lifecycle, never "Confirmed" on a single stream (the ≥2
// independent-stream rule lives upstream in verdict_tier).
export function deriveRca(c: CorrObject, missing: string[]): RcaState {
  const st = (c.state || "").toLowerCase();
  if (st === "recovered" || st === "closed") return "Resolved";
  if (c.verdict_tier === "confirmed") return "Confirmed";
  if (c.verdict_tier === "suspected") return missing.length >= 3 ? "Blocked" : "Suspected";
  // undetermined: a formed group still gathering evidence
  return c.signal_count > 1 ? "Correlated" : "RCA running";
}

export function deriveEvidence(c: CorrObject, missing: string[]): EvidenceState {
  if (c.signal_count <= 1) return "Single-stream";
  return missing.length === 0 ? "Complete" : "Partial";
}

export function deriveFault(c: CorrObject, aff: ActionItem["affected"]): FaultDomain {
  const o = (c.owner || "").toLowerCase();
  if (o === "isp") return "ISP / Carrier";
  if (o === "cloudops") return "Cloud Provider";
  if (o === "secops") return "Security";
  if (o === "appops") return "Application";
  const hay = [...aff.devices, ...aff.paths, ...aff.interfaces].join(" ").toLowerCase();
  if (/spine|leaf|fabric|dc-|tor/.test(hay)) return "Data Center";
  if (/wan|sd-?wan|edge|tunnel|vpn|mpls/.test(hay)) return "SD-WAN";
  if (/lan|sw-|access|dmz|fw/.test(hay)) return "LAN";
  return "Unknown";
}

export function deriveOwner(c: CorrObject): { state: OwnerState; name: string } {
  const o = (c.owner || "").trim().toLowerCase();
  if (!o || o === "unknown") return { state: "Missing", name: "Unassigned" };
  // verdict owner is a recommendation (no assignment workflow yet)
  return { state: "Recommended", name: ownerLabel(c.owner) };
}

export function deriveTicket(rca: RcaState): TicketState {
  if (rca === "Confirmed") return "Ticket needed";
  if (rca === "Resolved") return "Not eligible";
  return "Not eligible"; // suspected/correlated: hold until RCA confirms impact
}

/**
 * The ticket state from the case's REAL ticket links (any system: ServiceNow,
 * Jira, PagerDuty…), falling back to the RCA-derived eligibility only when the
 * links were read in full and none names this case. Before this the column
 * could never say "Ticketed": it read the RCA state alone (owner review,
 * 2026-11-22).
 */
export function ticketFromLinks(rca: RcaState, rows: readonly TicketLinkRow[] | undefined, links: TicketLinks): TicketState {
  if (rows && rows.length) {
    const states = rows.map((r) => (r.state || "").toLowerCase());
    if (states.some((s) => s === "open" || s === "updated" || s === "resolved")) return "Ticketed";
    if (states.some((s) => s === "pending")) return "Ticket pending";
    if (states.some((s) => s === "failed")) return "Sync failed";
  }
  const derived = deriveTicket(rca);
  if (links.ok && links.complete) return derived;
  // Not read, or read in part: never claim "Ticket needed" (it invites a
  // duplicate ticket); the eligibility rules that need no read still hold.
  return derived === "Ticket needed" ? "Unknown" : derived;
}

export function deriveSev(c: CorrObject, rca: RcaState): Sev {
  if (rca === "Confirmed") return "crit";
  if (rca === "Suspected" || rca === "Blocked") return "major";
  return c.top_confidence >= 0.6 ? "warn" : "ok";
}

// Next action — enterprise NOC language; what the operator should do NOW.
export function deriveNextAction(it: Omit<ActionItem, "nextAction">): string {
  if (it.rca === "Confirmed" && it.owner === "Missing") return "Assign owner · escalate";
  if (it.rca === "Confirmed") {
    if (it.ticket === "Ticketed") return "Track resolution";
    if (it.ticket === "Ticket pending") return "Track ticket creation";
    if (it.ticket === "Sync failed") return "Fix ticket sync · escalate";
    if (it.ticket === "Unknown") return "Check for a ticket · escalate";
    return "Open ticket · escalate";
  }
  if (it.rca === "Blocked") return "Add evidence · unblock RCA";
  if (it.owner === "Missing") return "Assign owner · open RCA";
  if (it.rca === "Suspected") return "Confirm impact · hold ticket";
  return "Review correlation";
}

export function buildItem(c: CorrObject, now: number = Date.now(), links: TicketLinks | null = null): ActionItem {
  const affected = parseAffected(c.affected);
  const missing = parseMissing(c.evidence_missing);
  const rca = deriveRca(c, missing);
  const { state: owner, name: ownerName } = deriveOwner(c);
  const base = {
    corr: c, affected, missing,
    sev: deriveSev(c, rca), rca,
    evidence: deriveEvidence(c, missing),
    fault: deriveFault(c, affected),
    owner, ownerName,
    ticket: links ? ticketFromLinks(rca, links.byCorr.get(c.correlation_id), links) : deriveTicket(rca),
    ageMs: now - Date.parse(startedAt(c)),
  };
  return { ...base, nextAction: deriveNextAction(base) };
}

// isActionableCorr — the customer-facing queue filter: drop un-correlated single-
// signal noise AND internal-stack objects (#76 — RCA is scoped to CUSTOMER networks;
// our own stack health belongs to Stack Health, not the operator queue).
export function isActionableCorr(c: CorrObject): boolean {
  if (c.verdict_tier === "undetermined" && c.signal_count <= 1) return false;
  if (isInternalStackAffected(c.affected)) return false;
  return true;
}

// ── Triage ladders (semantic sort ranks) ───────────────────────────────────────
// The queue's columns must sort by OPERATOR URGENCY, never alphabetically
// ("Blocked" < "Confirmed" lexically is meaningless to a NOC). Each ladder is
// ascending = work-this-first, mirroring theme/severity.ts::severityRank and
// appobs/sortRanks.ts. They live here, with the rest of the triage decision
// logic, because "which state outranks which" IS a product rule — the view only
// reads them. bySeverityThenAge is defined in terms of the same table, so the
// default queue order and a click-sort on Sev can never disagree.

const SEV_RANK: Record<Sev, number> = { crit: 0, major: 1, warn: 2, ok: 3 };
export const sevRank = (s: Sev): number => SEV_RANK[s] ?? 9;

const RCA_RANK: Record<RcaState, number> = {
  Confirmed: 0, Suspected: 1, Blocked: 2, Correlated: 3, "RCA running": 4, New: 5, Resolved: 6,
};
export const rcaRank = (r: RcaState): number => RCA_RANK[r] ?? 9;

// Weakest evidence first — a Single-stream group is the one an operator must
// shore up before it can ever be confirmed.
const EVIDENCE_RANK: Record<EvidenceState, number> = { "Single-stream": 0, Partial: 1, Complete: 2 };
export const evidenceRank = (e: EvidenceState): number => EVIDENCE_RANK[e] ?? 9;

// Biggest ownership gap first.
const OWNER_RANK: Record<OwnerState, number> = { Missing: 0, Escalated: 1, Recommended: 2, Assigned: 3 };
export const ownerRank = (o: OwnerState): number => OWNER_RANK[o] ?? 9;

// Most ITSM-urgent first.
const TICKET_RANK: Record<TicketState, number> = {
  "Sync failed": 0, "Ticket needed": 1, Unknown: 2, Eligible: 3, "Ticket pending": 4, Ticketed: 5, "Not eligible": 6,
};
export const ticketRank = (t: TicketState): number => TICKET_RANK[t] ?? 9;

// Severity-first, then newest — the operator works the top of this list.
export function bySeverityThenAge(a: ActionItem, b: ActionItem): number {
  return sevRank(a.sev) - sevRank(b.sev) || b.ageMs - a.ageMs;
}

// ── Action Queue filters (Increment 2) ─────────────────────────────────────────
// Pure, unit-testable predicates over the already-built ActionItem list. "all"/
// undefined = no constraint on that facet; needsAction is a derived shortcut.

export type CcFilters = {
  rca?: RcaState | "all";
  sev?: Sev | "all";
  fault?: FaultDomain | "all";
  evidence?: EvidenceState | "all";
  owner?: OwnerState | "all";
  needsAction?: boolean;
  untriaged?: boolean; // correlated but RCA not yet run (Correlated / RCA running / New)
};

// needsAction — the operator's "what actually needs me right now": a missing owner,
// an unticketed confirmed incident, or an RCA blocked on evidence.
export function needsAction(it: ActionItem): boolean {
  return it.owner === "Missing" || it.ticket === "Ticket needed" || it.rca === "Blocked";
}

// isUntriaged — a correlated group whose RCA hasn't been run/resolved yet. Mirrors the
// Untriaged KPI exactly so clicking it filters to the same set it counts.
export function isUntriaged(it: ActionItem): boolean {
  return it.rca === "Correlated" || it.rca === "RCA running" || it.rca === "New";
}

export function filterItems(items: ActionItem[], f: CcFilters): ActionItem[] {
  const on = (v: string | undefined): v is string => !!v && v !== "all";
  return items.filter((it) => {
    if (on(f.rca) && it.rca !== f.rca) return false;
    if (on(f.sev) && it.sev !== f.sev) return false;
    if (on(f.fault) && it.fault !== f.fault) return false;
    if (on(f.evidence) && it.evidence !== f.evidence) return false;
    if (on(f.owner) && it.owner !== f.owner) return false;
    if (f.needsAction && !needsAction(it)) return false;
    if (f.untriaged && !isUntriaged(it)) return false;
    return true;
  });
}

// activeFilterCount — how many facets are constraining, for the "clear (N)" affordance.
export function activeFilterCount(f: CcFilters): number {
  let n = 0;
  for (const k of ["rca", "sev", "fault", "evidence", "owner"] as const) if (f[k] && f[k] !== "all") n++;
  if (f.needsAction) n++;
  if (f.untriaged) n++;
  return n;
}
