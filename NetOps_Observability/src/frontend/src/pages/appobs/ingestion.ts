// App Observability — ingestion model (#81 P3F+1 Phase 2).
//
// Turns the live cloud inventory into the per-account and per-(account×region)
// readiness the Ingestion page renders. Honest by construction: inventory is the
// only real source today (deriveReadiness), so every other source reports "off"
// per region — the matrix shows the truth, never a fabricated "flowing".

import type { CloudResourceRow, CloudConnectorView } from "../../services/api";
import { IngestionSource, SourceReadiness, SourceStatus, deriveReadiness, isMeasured } from "./readiness";
import { connectorStatus, resumePrimaryRef, resumeRegions } from "./connectorWizard";

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

// ── Connector-first account rows (Wave 2 #4) ──────────────────────────────────
// The defect this fixes (review #10): accounts were derived from DISCOVERED
// inventory, so an account whose ingestion is fully broken — the exact case the
// page exists for — silently disappeared. Rows now come from the CONNECTOR
// STORE first (an account exists because it is configured), joined with what
// actually arrived, with an explicit identity-vs-telemetry split: "connection
// OK / telemetry silent" is a different, red, truth than "connection broken".

/** Identity side: can the platform authenticate to this account? */
export type AccountConnection = "ok" | "broken" | "setup" | "paused" | "platform";
/** Telemetry side: is data actually arriving on its expected cadence? */
export type AccountTelemetry = "flowing" | "stale" | "silent";

// Telemetry cadence windows — the same honesty windows the backend's source
// matrix uses (cloud_ingestion.go: fresh 15 min, stale horizon 24 h).
const TELEMETRY_FRESH_MS = 15 * 60_000;
const TELEMETRY_STALE_MS = 24 * 3600_000;

export interface AccountRowState { label: string; tone: string; attention: boolean }

export interface MergedAccountRow {
  key: string;
  provider: string;
  accountId: string;
  /** Connector display name; "" for a discovered-only (deployment-credential) account. */
  name: string;
  tenant: string;
  regions: string[];
  resourceCount: number;
  lastSyncIso?: string;
  flowingSources: number;
  connection: AccountConnection;
  connectionLabel: string;
  connectionTone: string;
  telemetry: AccountTelemetry;
  state: AccountRowState;
  connector?: CloudConnectorView;
}

function telemetryOf(lastSyncIso: string | undefined, nowMs: number): AccountTelemetry {
  if (!lastSyncIso) return "silent";
  const t = new Date(lastSyncIso).getTime();
  if (Number.isNaN(t)) return "silent";
  const age = nowMs - t;
  if (age <= TELEMETRY_FRESH_MS) return "flowing";
  if (age <= TELEMETRY_STALE_MS) return "stale";
  return "silent";
}

function connectionOf(c: CloudConnectorView): AccountConnection {
  // Enabled states are expected to produce telemetry — silence there is RED.
  if (c.state === "ACTIVE" || c.state === "DEGRADED") return "ok";
  if (c.state === "REVOKED" || c.state === "REAUTHORIZATION_REQUIRED") return "broken";
  if (c.state === "DISABLED" || c.state === "DELETING") return "paused";
  // Setup-stage connector whose own validation already failed is broken too.
  return connectorStatus(c).tone === "var(--crit)" ? "broken" : "setup";
}

// The identity × telemetry verdict matrix. NEVER green on silence: a validated
// connection with no data is an attention row stating exactly that.
function rowState(connection: AccountConnection, telemetry: AccountTelemetry): AccountRowState {
  if (connection === "broken") {
    return {
      label: telemetry === "flowing" ? "Connection broken — data still arriving" : "Connection broken",
      tone: "var(--crit)", attention: true,
    };
  }
  if (connection === "setup") return { label: "Setup incomplete — not collecting yet", tone: "var(--warn)", attention: false };
  if (connection === "paused") return { label: "Paused", tone: "var(--fg-subtle)", attention: false };
  // ok | platform-managed → the telemetry side decides.
  switch (telemetry) {
    case "flowing": return { label: "Healthy", tone: "var(--ok)", attention: false };
    case "stale": return { label: "Data stale", tone: "var(--warn)", attention: false };
    default: return {
      label: connection === "ok" ? "Connected — no data arriving" : "No data arriving",
      tone: "var(--crit)", attention: true,
    };
  }
}

export function mergeAccounts(
  connectors: CloudConnectorView[],
  rows: CloudResourceRow[],
  byProvider?: ProviderIngestion,
  nowMs: number = Date.now(),
): MergedAccountRow[] {
  const inv = buildAccounts(rows, byProvider);
  const invByKey = new Map(inv.map((a) => [`${a.provider.toLowerCase()}|${a.accountId}`, a]));
  const claimed = new Set<string>();
  const out: MergedAccountRow[] = [];

  for (const c of connectors) {
    const accountId = resumePrimaryRef(c);
    if (!accountId) continue; // no account scoped yet — visible in Connections, not an account row
    const key = `${c.provider.toLowerCase()}|${accountId}`;
    const arrived = invByKey.get(key);
    if (arrived) claimed.add(key);
    // Last data = the freshest of the inventory the account actually delivered
    // and the connector's own measured telemetry-health check.
    const healthIso = c.telemetry_health?.state === "healthy" ? c.telemetry_health.checked : undefined;
    const lastSyncIso = maxIso(arrived?.lastSyncIso, healthIso);
    const connection = connectionOf(c);
    const telemetry = telemetryOf(lastSyncIso, nowMs);
    const regions = arrived?.regions?.length
      ? arrived.regions
      : resumeRegions(c).split(",").map((s) => s.trim()).filter(Boolean);
    out.push({
      key: c.id,
      provider: c.provider,
      accountId,
      name: c.display_name || "",
      tenant: arrived?.tenant ?? "",
      regions,
      resourceCount: arrived?.resourceCount ?? 0,
      lastSyncIso,
      flowingSources: arrived?.enabledSources ?? 0,
      connection,
      connectionLabel: connectorStatus(c).label,
      connectionTone: connectorStatus(c).tone,
      telemetry,
      state: rowState(connection, telemetry),
      connector: c,
    });
  }

  // Discovered accounts with no connector: the ambient (deployment-credential)
  // lane. They stay visible — data that arrived is real — but the identity
  // column says honestly that no self-service connection owns them.
  for (const a of inv) {
    const key = `${a.provider.toLowerCase()}|${a.accountId}`;
    if (claimed.has(key)) continue;
    const telemetry = telemetryOf(a.lastSyncIso, nowMs);
    out.push({
      key,
      provider: a.provider,
      accountId: a.accountId,
      name: "",
      tenant: a.tenant,
      regions: a.regions,
      resourceCount: a.resourceCount,
      lastSyncIso: a.lastSyncIso,
      flowingSources: a.enabledSources,
      connection: "platform",
      connectionLabel: "Platform managed",
      connectionTone: "var(--fg-subtle)",
      telemetry,
      state: rowState("platform", telemetry),
    });
  }

  // Attention rows first — a NOC scans red before green.
  out.sort((x, y) =>
    Number(y.state.attention) - Number(x.state.attention) ||
    x.provider.localeCompare(y.provider) ||
    x.accountId.localeCompare(y.accountId));
  return out;
}
