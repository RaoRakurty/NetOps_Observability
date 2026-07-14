// App Observability — data-readiness model (#81 P3F+1 Trust & Data Readiness Pass).
//
// The product principle: show WHY Correlix is allowed to claim app health/RCA —
// prove the data is connected, flowing, fresh and attributed BEFORE any verdict.
// This module is the pure, testable core. It invents NO backend behaviour: today
// only the cloud INVENTORY (/api/cloud/*) is real, so inventory readiness is
// derived from that live load and every not-yet-ingested source is honestly
// reported "off" — never silently treated as healthy.

import type { Health, Provider } from "./types";

// ── Source taxonomy ──────────────────────────────────────────────────────────
// The cloud observability sources Correlix can ingest per account/region. Order
// is display order in the Sources / Ingestion-Status matrices.
export type SourceType =
  | "inventory"
  | "flow_logs"
  | "lb_logs"
  | "metrics"
  | "cloud_health"
  | "change_audit"
  | "traces"
  | "dns_logs"
  | "firewall_logs"
  | "nat_logs"
  | "seam_data";

export const SOURCE_TYPES: SourceType[] = [
  "inventory", "flow_logs", "lb_logs", "metrics", "cloud_health",
  "change_audit", "traces", "dns_logs", "firewall_logs", "nat_logs", "seam_data",
];

export const SOURCE_LABEL: Record<SourceType, string> = {
  inventory: "Inventory",
  flow_logs: "Flow Logs",
  lb_logs: "Load Balancer Logs",
  metrics: "Metrics",
  cloud_health: "Cloud Health",
  change_audit: "Change / Audit",
  traces: "Traces",
  dns_logs: "DNS Logs",
  firewall_logs: "Firewall Logs",
  nat_logs: "NAT Gateway Logs",
  seam_data: "Network Seam Data", // TGW / VPN / DX / ExpressRoute / Interconnect
};

// ── Source status ────────────────────────────────────────────────────────────
// What is actually true about a source right now. "off" / "no_data" / etc. are
// first-class, honest answers — the UI must never paper over them as healthy.
export type SourceStatus =
  | "flowing"
  | "stale"
  | "off"
  | "permission_denied"
  | "misconfigured"
  | "no_data"
  | "not_supported";

export const STATUS_META: Record<SourceStatus, { label: string; tone: string }> = {
  flowing: { label: "Flowing", tone: "var(--ok)" },
  stale: { label: "Stale", tone: "var(--warn)" },
  off: { label: "Not configured", tone: "var(--fg-subtle)" },
  permission_denied: { label: "Permission denied", tone: "var(--crit)" },
  misconfigured: { label: "Misconfigured", tone: "var(--crit)" },
  no_data: { label: "No data received", tone: "var(--warn)" },
  not_supported: { label: "Coming soon", tone: "var(--fg-subtle)" },
};

export interface SourceReadiness {
  sourceType: SourceType;
  provider?: Provider;
  accountId?: string;
  region?: string;
  status: SourceStatus;
  lastSyncIso?: string;
  volume?: number;
  errorCount?: number;
  lastError?: string;
  freshnessSeconds?: number;
}

// ── Data mode ────────────────────────────────────────────────────────────────
// How to honestly describe what the user is looking at. NEVER the word "mock".
export type DataMode = "live" | "demo" | "synthetic" | "empty";

export const DATA_MODE_LABEL: Record<DataMode, string> = {
  live: "Live telemetry",
  demo: "Demo tenant · synthetic signals",
  synthetic: "Synthetic demo data",
  empty: "No cloud data connected",
};

export const DATA_MODE_TONE: Record<DataMode, string> = {
  live: "var(--ok)",
  demo: "var(--accent)",
  synthetic: "var(--accent)",
  empty: "var(--fg-subtle)",
};

// connectorKind reflects what the backend is actually serving: a real per-tenant
// SDK connector ("live") vs the bootstrap fixture provider ("fixture") vs nothing.
export type ConnectorKind = "live" | "fixture" | "none";

export function deriveDataMode(opts: { inventoryCount: number; connector: ConnectorKind }): DataMode {
  if (opts.connector === "live") return "live";
  if (opts.inventoryCount > 0) return "demo"; // fixtures present ⇒ demo tenant w/ synthetic signals
  return "empty";
}

// ── Scope ────────────────────────────────────────────────────────────────────
export interface CloudScope {
  tenant: string;
  provider: string; // "AWS" | "Azure" | "GCP" | "2 clouds" | "All clouds" | "—"
  account: string;  // account/sub/project, "3 accounts", or "—"
  region: string;
  env: string;
  timeRange: string; // e.g. "Last 1h"
}

function uniq(xs: (string | undefined)[]): string[] {
  return [...new Set(xs.filter((x): x is string => !!x && x !== "—"))];
}

// summarise a multi-value dimension: one value shown verbatim, many as a count.
function dimension(values: string[], plural: string, fmtOne?: (s: string) => string): string {
  if (values.length === 0) return "—";
  if (values.length === 1) return fmtOne ? fmtOne(values[0]) : values[0];
  return `${values.length} ${plural}`;
}

export interface ScopeSource {
  provider?: string;
  account?: string;
  region?: string;
  env?: string;
}

export function deriveScope(rows: ScopeSource[], tenant: string, timeRange = "Last 1h"): CloudScope {
  return {
    tenant: tenant || "—",
    provider: dimension(uniq(rows.map((r) => r.provider)), "clouds", (p) => p.toUpperCase()),
    account: dimension(uniq(rows.map((r) => r.account)), "accounts"),
    region: dimension(uniq(rows.map((r) => r.region)), "regions"),
    env: dimension(uniq(rows.map((r) => r.env)), "envs"),
    timeRange,
  };
}

// ── Readiness derivation ──────────────────────────────────────────────────────
// MEASURED, not assumed. Each source's status comes from GET /api/cloud/ingestion,
// which derives it from what actually landed (signal volume + last-seen, active
// seams, inventory rows). A source with no producer reports "off" — never invent
// coverage — but a source that IS flowing must say so: hard-coding "off" was a
// placeholder that could never become true, and it understated a live deployment.
export interface IngestionSource {
  source_type: SourceType;
  status: SourceStatus;
  volume?: number;
  last_seen_iso?: string;
  /** available = a producer exists for this source; planned = nothing ships it yet. */
  capability?: "available" | "planned";
}

export function deriveReadiness(opts: {
  inventoryCount: number;
  inventoryError: boolean;
  lastSyncIso?: string;
  /** Live per-source status from the backend. Absent → inventory-only (offline/legacy). */
  ingestion?: IngestionSource[];
}): SourceReadiness[] {
  const invStatus: SourceStatus = opts.inventoryError
    ? "off"
    : opts.inventoryCount > 0
      ? "flowing"
      : "no_data";
  const inventory: SourceReadiness = {
    sourceType: "inventory",
    status: invStatus,
    volume: opts.inventoryCount,
    lastSyncIso: opts.lastSyncIso,
    freshnessSeconds: 0,
  };

  const live = new Map<SourceType, IngestionSource>(
    (opts.ingestion ?? []).map((s) => [s.source_type, s]),
  );
  const rest = SOURCE_TYPES.filter((t) => t !== "inventory").map(
    (sourceType): SourceReadiness => {
      const s = live.get(sourceType);
      // No reading for this source (endpoint absent, or source has no producer)
      // → "off". Honest default, same as before.
      if (!s) return { sourceType, status: "off" };
      // "off" means three different things; the backend now says which. A source
      // no producer ships yet is "Coming soon", not a broken feed.
      const status: SourceStatus =
        s.status === "off" && s.capability === "planned" ? "not_supported" : s.status;
      return {
        sourceType,
        status,
        volume: s.volume,
        lastSyncIso: s.last_seen_iso,
      };
    },
  );
  return [inventory, ...rest];
}

// ── Summary (the readiness strip / Ingestion summary cards) ───────────────────
export interface ReadinessSummary {
  connectedAccounts: number;
  flowing: number;
  stale: number;
  off: number;
  permissionErrors: number;
  partial: number; // no_data | misconfigured
  lastSyncIso?: string;
}

export function summarize(readiness: SourceReadiness[], connectedAccounts: number): ReadinessSummary {
  const count = (s: SourceStatus) => readiness.filter((r) => r.status === s).length;
  return {
    connectedAccounts,
    flowing: count("flowing"),
    stale: count("stale"),
    off: count("off"),
    permissionErrors: count("permission_denied"),
    partial: count("no_data") + count("misconfigured"),
    lastSyncIso: readiness.find((r) => r.sourceType === "inventory")?.lastSyncIso,
  };
}

// ── Measurement state — the bridge from "is the source on?" to "what do we show?"
// Used everywhere a value depends on a source: missing ⇒ "not measured", never 0.
export type MeasureState = "ok" | "stale" | "not_measured" | "partial" | "permission_denied";

export const MEASURE_LABEL: Record<MeasureState, string> = {
  ok: "",
  stale: "stale",
  not_measured: "not measured",
  partial: "partial data",
  permission_denied: "permission denied",
};

export function isMeasured(status: SourceStatus | undefined): boolean {
  return status === "flowing" || status === "stale";
}

export function getMeasurementState(status: SourceStatus | undefined): MeasureState {
  switch (status) {
    case "flowing":
      return "ok";
    case "stale":
      return "stale";
    case "permission_denied":
      return "permission_denied";
    default:
      // off | no_data | misconfigured | not_supported | undefined
      return "not_measured";
  }
}

// ── Honest health derivation ──────────────────────────────────────────────────
// Never claim "healthy" when the health source is not measured. If another signal
// already shows trouble, keep it; otherwise downgrade to partial/not measured.
export type DisplayHealth = Health | "not_measured" | "partial";

export function deriveHealthFromAvailableSignals(
  raw: Health,
  signals: { health: SourceStatus | undefined; anyMeasured: boolean },
): DisplayHealth {
  if (isMeasured(signals.health)) return raw;
  // No cloud-health source: a real problem on another signal is still real.
  if (raw === "down" || raw === "degraded") return raw;
  // Otherwise we are NOT allowed to say healthy.
  return signals.anyMeasured ? "partial" : "not_measured";
}

// ── Freshness label ──────────────────────────────────────────────────────────
// Seconds-granularity (the scope bar wants "updated 42s ago"). Pure: pass nowMs
// in tests for determinism; defaults to Date.now() at call sites.
export function freshnessLabel(iso: string | undefined, nowMs: number = Date.now()): string {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "—";
  const s = Math.max(0, Math.round((nowMs - t) / 1000));
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}
