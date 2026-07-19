// costContext (Wave 5 #18 slice 3) — the data layer + pure math for the
// "cost context" block on the cloud investigation drawer.
//
// HONESTY CONTRACT (the whole point of this module):
//   * Everything shown is a figure the provider itself billed, read from
//     /api/cloud/costs (tenant-scoped, server-enforced row policy).
//   * The block is CONTEXT, not causation: "what the affected account's
//     services cost around the incident" — never a fabricated "downtime cost"
//     multiplication, never a business-impact claim.
//   * Scope is derived from the investigation's OWN recorded changes (their
//     provider/account cloud refs). No account derivable ⇒ an honest empty
//     state, never "all accounts everywhere".
//   * Baseline math is plain arithmetic over real rows: pre-onset total
//     divided by the CALENDAR days of the baseline period. A day the provider
//     has not billed yet reads "not yet billed", never 0.

import { getActiveScope, getToken } from "../../services/api";
import type { InvestigationChange } from "./api";

export interface CostRow {
  day: string;       // YYYY-MM-DD
  provider: string;
  account: string;
  service: string;   // the provider's own billing service name
  amount: number;    // may be negative (credits/refunds)
  currency: string;
}

export interface CostScopeAccount {
  provider: string;
  account: string;
}

// Bounded fan-out: at most this many affected accounts are queried.
export const MAX_COST_ACCOUNTS = 3;
// Incident window ± baseline: 7 days either side of onset.
export const COST_CONTEXT_DAYS = 7;

// ── pure helpers (unit-tested) ───────────────────────────────────────────────

const PROVIDERS = new Set(["aws", "azure", "gcp"]);

/** unique (provider, account) pairs actually recorded on the investigation's
 * changes — the only accounts cost can be scoped to honestly. Bounded. */
export function costScope(changes: InvestigationChange[]): CostScopeAccount[] {
  const seen = new Set<string>();
  const out: CostScopeAccount[] = [];
  for (const c of changes) {
    const provider = c.cloudRef?.provider ?? "";
    const account = c.cloudRef?.account ?? "";
    if (!PROVIDERS.has(provider) || !account) continue;
    const key = `${provider}:${account}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ provider, account });
    if (out.length >= MAX_COST_ACCOUNTS) break;
  }
  return out;
}

function dayStr(d: Date): string {
  return d.toISOString().slice(0, 10);
}

/** [from, to] day window around onset: onset − 7d … min(today, onset + 7d).
 * null when the onset is unparseable — no window can be anchored honestly. */
export function costWindow(
  onsetIso: string, now: Date,
): { from: string; to: string; onsetDay: string } | null {
  const onset = new Date(onsetIso);
  if (!onsetIso || Number.isNaN(onset.getTime())) return null;
  const msDay = 24 * 3600 * 1000;
  const from = new Date(onset.getTime() - COST_CONTEXT_DAYS * msDay);
  const after = new Date(onset.getTime() + COST_CONTEXT_DAYS * msDay);
  const to = after.getTime() < now.getTime() ? after : now;
  return { from: dayStr(from), to: dayStr(to), onsetDay: dayStr(onset) };
}

export interface ServiceCost {
  service: string;
  provider: string;
  currency: string;
  /** total billed over the fetched window (real rows summed, nothing else) */
  total: number;
  /** pre-onset total / calendar baseline days; null when no pre-onset rows */
  baselineDaily: number | null;
  /** amount billed ON the onset day; null = the provider has not billed it yet */
  onsetDayAmount: number | null;
}

/** aggregate real rows per (service, provider, currency); never mixes
 * currencies. Sorted by |total| descending, capped at topN. */
export function summarizeCosts(
  rows: CostRow[], fromDay: string, onsetDay: string, topN = 5,
): ServiceCost[] {
  const byKey = new Map<string, ServiceCost & { preTotal: number; preSeen: boolean; onsetSeen: boolean }>();
  for (const r of rows) {
    if (typeof r.amount !== "number" || !Number.isFinite(r.amount)) continue;
    const key = `${r.service}|${r.provider}|${r.currency}`;
    let s = byKey.get(key);
    if (!s) {
      s = {
        service: r.service, provider: r.provider, currency: r.currency,
        total: 0, baselineDaily: null, onsetDayAmount: null,
        preTotal: 0, preSeen: false, onsetSeen: false,
      };
      byKey.set(key, s);
    }
    s.total += r.amount;
    if (r.day < onsetDay) {
      s.preTotal += r.amount;
      s.preSeen = true;
    }
    if (r.day === onsetDay) {
      s.onsetDayAmount = (s.onsetDayAmount ?? 0) + r.amount;
      s.onsetSeen = true;
    }
  }
  // calendar days of the baseline period [from, onsetDay) — exact arithmetic,
  // not "days that happened to have rows" (which would overstate the average).
  const from = new Date(`${fromDay}T00:00:00Z`).getTime();
  const onset = new Date(`${onsetDay}T00:00:00Z`).getTime();
  const baselineDays = Math.max(0, Math.round((onset - from) / (24 * 3600 * 1000)));
  const out: ServiceCost[] = [];
  for (const s of byKey.values()) {
    out.push({
      service: s.service, provider: s.provider, currency: s.currency,
      total: s.total,
      baselineDaily: s.preSeen && baselineDays > 0 ? s.preTotal / baselineDays : null,
      onsetDayAmount: s.onsetSeen ? s.onsetDayAmount : null,
    });
  }
  out.sort((a, b) => Math.abs(b.total) - Math.abs(a.total));
  return out.slice(0, topN);
}

/** "12.34 USD" — plain rendering of a billed figure; no invented precision. */
export function fmtAmount(amount: number, currency: string): string {
  return `${amount.toFixed(2)} ${currency}`;
}

// ── data access ──────────────────────────────────────────────────────────────

export interface CostsResponse {
  costs: CostRow[];
  count: number;
  from: string;
  to: string;
  truncated: boolean;
}

// services/api.ts keeps its `request` helper module-private; this read uses the
// same authed-fetch pattern as loadServiceMap — Bearer token + X-Acting-Tenant,
// tenant scope enforced SERVER-side like every other cloud read.
export async function loadCloudCosts(params: {
  provider?: string; account?: string; from?: string; to?: string;
}): Promise<CostsResponse> {
  const p = new URLSearchParams();
  if (params.provider) p.set("provider", params.provider);
  if (params.account) p.set("account", params.account);
  if (params.from) p.set("from", params.from);
  if (params.to) p.set("to", params.to);
  const qs = p.toString();
  const headers: Record<string, string> = {};
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  const scope = getActiveScope();
  if (scope) headers["X-Acting-Tenant"] = scope;
  const res = await fetch(`/api/cloud/costs${qs ? `?${qs}` : ""}`, { headers });
  if (!res.ok) throw new Error(`cost read failed: ${res.status} ${res.statusText}`);
  return await res.json() as CostsResponse;
}
