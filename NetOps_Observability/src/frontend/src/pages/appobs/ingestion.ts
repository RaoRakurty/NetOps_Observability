// App Observability — ingestion model (#81 P3F+1 Phase 2).
//
// Turns the live cloud inventory into the per-account and per-(account×region)
// readiness the Ingestion page renders. Honest by construction: inventory is the
// only real source today (deriveReadiness), so every other source reports "off"
// per region — the matrix shows the truth, never a fabricated "flowing".

import type { CloudResourceRow } from "../../services/api";
import { IngestionSource, SourceReadiness, SourceStatus, deriveReadiness, isMeasured } from "./readiness";

// Per-provider live source statuses from GET /api/cloud/ingestion (audit Azure
// P0-7): a provider's matrix row is only credited with ITS OWN signals — AWS
// flow logs landing must never light the Azure chips.
export type ProviderIngestion = Record<string, IngestionSource[]>;

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

export function buildMatrix(rows: CloudResourceRow[], byProvider?: ProviderIngestion): RegionReadiness[] {
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
      readiness: deriveReadiness({
        inventoryCount: rs.length, inventoryError: false, lastSyncIso,
        // THIS provider's measured statuses only (audit P0-7) — absent map or
        // unknown provider keeps the honest inventory-only default.
        ingestion: byProvider?.[provider.toLowerCase()],
      }),
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
  tenant: string;         // the owning tenant ("" = global) — from the scoped data, never assumed
  regions: string[];
  resourceCount: number;
  lastSyncIso?: string;
  status: SourceStatus;   // inventory connection status
  enabledSources: number; // sources currently flowing for this account (inventory only today)
}

export function buildAccounts(rows: CloudResourceRow[], byProvider?: ProviderIngestion): CloudAccount[] {
  const groups = groupBy(rows, (r) => `${r.cloud_provider}|${r.account_id}`);
  const out: CloudAccount[] = [];
  for (const [key, rs] of groups) {
    const [provider, accountId] = key.split("|");
    const regions = [...new Set(rs.map((r) => r.region).filter(Boolean))].sort();
    const lastSyncIso = rs.reduce<string | undefined>((acc, r) => maxIso(acc, r.last_seen_at), undefined);
    // enabled = sources MEASURED flowing/stale for this provider (+ inventory,
    // proven by the rows themselves) — never the hardcoded "1" placeholder.
    const measured = (byProvider?.[provider.toLowerCase()] ?? [])
      .filter((s) => s.source_type !== "inventory" && isMeasured(s.status)).length;
    out.push({
      provider,
      accountId,
      tenant: rs[0]?.tenant_id ?? "", // all rows are already scoped to the caller's tenant
      regions,
      resourceCount: rs.length,
      lastSyncIso,
      status: rs.length ? "flowing" : "no_data",
      enabledSources: (rs.length ? 1 : 0) + measured,
    });
  }
  out.sort((a, b) => a.provider.localeCompare(b.provider) || a.accountId.localeCompare(b.accountId));
  return out;
}
