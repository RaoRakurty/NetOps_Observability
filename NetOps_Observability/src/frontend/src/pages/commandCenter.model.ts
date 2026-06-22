// commandCenter.model.ts — the PURE decision logic behind the Command Center NOC
// view (extracted from CommandCenter.tsx so the product's triage rules are unit-
// testable, not buried in JSX). Mirrors the rcaCase.ts ↔ RcaWorkspace.tsx split.
//
// HONESTY / non-negotiables enforced here:
//   - never "Confirmed" on a single evidence stream (the ≥2-independent-stream rule
//     lives upstream in verdict_tier; this layer must not promote past it);
//   - internal-stack noise is excluded from the customer-facing queue (#76);
//   - a ticket is only "needed" once RCA is Confirmed (no premature ITSM churn).

import type { CorrObject } from "../services/api";
import { ownerLabel, isInternalStackAffected } from "../components/rca/labels";

export type RcaState = "New" | "Correlated" | "RCA running" | "Suspected" | "Confirmed" | "Blocked" | "Resolved";
export type EvidenceState = "Complete" | "Partial" | "Single-stream";
export type FaultDomain = "LAN" | "SD-WAN" | "Data Center" | "ISP / Carrier" | "Cloud Provider" | "Application" | "Security" | "Unknown";
export type OwnerState = "Assigned" | "Recommended" | "Missing" | "Escalated";
export type TicketState = "Not eligible" | "Eligible" | "Ticket needed" | "Ticketed" | "Sync failed";
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

export function deriveSev(c: CorrObject, rca: RcaState): Sev {
  if (rca === "Confirmed") return "crit";
  if (rca === "Suspected" || rca === "Blocked") return "major";
  return c.top_confidence >= 0.6 ? "warn" : "ok";
}

// Next action — enterprise NOC language; what the operator should do NOW.
export function deriveNextAction(it: Omit<ActionItem, "nextAction">): string {
  if (it.rca === "Confirmed" && it.owner === "Missing") return "Assign owner · escalate";
  if (it.rca === "Confirmed") return it.ticket === "Ticketed" ? "Track resolution" : "Open ticket · escalate";
  if (it.rca === "Blocked") return "Add evidence · unblock RCA";
  if (it.owner === "Missing") return "Assign owner · open RCA";
  if (it.rca === "Suspected") return "Confirm impact · hold ticket";
  return "Review correlation";
}

export function buildItem(c: CorrObject, now: number = Date.now()): ActionItem {
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
    ticket: deriveTicket(rca),
    ageMs: now - Date.parse(c.window_start || c.created_at || ""),
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

// Severity-first, then newest — the operator works the top of this list.
export function bySeverityThenAge(a: ActionItem, b: ActionItem): number {
  const sr: Record<Sev, number> = { crit: 0, major: 1, warn: 2, ok: 3 };
  return sr[a.sev] - sr[b.sev] || b.ageMs - a.ageMs;
}
