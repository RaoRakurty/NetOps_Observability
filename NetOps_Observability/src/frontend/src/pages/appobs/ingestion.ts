// App Observability — ingestion model (#81 P3F+1 Phase 2).
//
// Turns the live cloud inventory into the per-account and per-(account×region)
// readiness the Ingestion page renders. Honest by construction: inventory is the
// only real source today (deriveReadiness), so every other source reports "off"
// per region — the matrix shows the truth, never a fabricated "flowing".

import type { CloudResourceRow } from "../../services/api";
import { SourceReadiness, SourceStatus, deriveReadiness } from "./readiness";

// freshest of two ISO timestamps (string compare is correct for RFC3339/UTC).
function maxIso(a: string | undefined, b: string | undefined): string | undefined {
  if (!a) return b;
  if (!b) return a;
  return a > b ? a : b;
}

function groupBy(rows: CloudResourceRow[], keyOf: (r: CloudResourceRow) => string): Map<string, CloudResourceRow[]> {
  const m = new Map<string, CloudResourceRow[]>();
  for (const r of rows) {
    const k = keyOf(r);
    const cur = m.get(k);
    if (cur) cur.push(r);
    else m.set(k, [r]);
  }
  return m;
}

// ── Per-(provider, account, region) readiness — the matrix rows ───────────────
export interface RegionReadiness {
  provider: string;
  accountId: string;
  region: string;
  resourceCount: number;
  readiness: SourceReadiness[]; // one per SOURCE_TYPES, inventory first
}

export function buildMatrix(rows: CloudResourceRow[]): RegionReadiness[] {
  const groups = groupBy(rows, (r) => `${r.cloud_provider}|${r.account_id}|${r.region}`);
  const out: RegionReadiness[] = [];
  for (const [key, rs] of groups) {
    const [provider, accountId, region] = key.split("|");
    const lastSyncIso = rs.reduce<string | undefined>((acc, r) => maxIso(acc, r.last_seen_at), undefined);
    out.push({
      provider,
      accountId,
      region,
      resourceCount: rs.length,
      readiness: deriveReadiness({ inventoryCount: rs.length, inventoryError: false, lastSyncIso }),
    });
  }
  out.sort((a, b) =>
    a.provider.localeCompare(b.provider) ||
    a.accountId.localeCompare(b.accountId) ||
    a.region.localeCompare(b.region));
  return out;
}

// ── Per-(provider, account) — the Accounts tab ────────────────────────────────
export interface CloudAccount {
  provider: string;
  accountId: string;
  regions: string[];
  resourceCount: number;
  lastSyncIso?: string;
  status: SourceStatus;   // inventory connection status
  enabledSources: number; // sources currently flowing for this account (inventory only today)
}

export function buildAccounts(rows: CloudResourceRow[]): CloudAccount[] {
  const groups = groupBy(rows, (r) => `${r.cloud_provider}|${r.account_id}`);
  const out: CloudAccount[] = [];
  for (const [key, rs] of groups) {
    const [provider, accountId] = key.split("|");
    const regions = [...new Set(rs.map((r) => r.region).filter(Boolean))].sort();
    const lastSyncIso = rs.reduce<string | undefined>((acc, r) => maxIso(acc, r.last_seen_at), undefined);
    out.push({
      provider,
      accountId,
      regions,
      resourceCount: rs.length,
      lastSyncIso,
      status: rs.length ? "flowing" : "no_data",
      enabledSources: 1, // only the inventory source is live today
    });
  }
  out.sort((a, b) => a.provider.localeCompare(b.provider) || a.accountId.localeCompare(b.accountId));
  return out;
}
