// App Observability — live data layer (#81 P3A wiring).
//
// Maps the backend cloud.* shapes (api.cloudApps/cloudResources/cloudCoverage)
// into the UI view types in ./types.ts. ONLY the identity surfaces are live in
// P3A: app/resource → confidence/source/owner/env from the cloud inventory.
// Health, traffic, errors, p95, RCA and underlay are NOT ingested yet (they
// arrive with cloud_health/cloud_flow/cloud_change in P3B–P3D), so this layer
// marks them NOT_MEASURED and the UI renders "—" — never a fabricated 0.

import { api } from "../../services/api";
import type {
  CloudAppRow, CloudResourceRow, CloudCoverageReport, CloudConfidence, CloudSource,
} from "../../services/api";
import type {
  App, CloudResource, Coverage, UnknownContributor, Provider, Confidence, AttrSource, AppRca,
} from "./types";

// Sentinel for a numeric metric the platform does not measure yet (P3B–D).
// The UI renders any value < 0 as "—" so it reads as "not measured", not "zero".
export const NOT_MEASURED = -1;

// confidence/source enum values are identical across backend + UI; pass through
// with a safe fallback so an unexpected value never crashes a render.
function conf(c: CloudConfidence | string | undefined): Confidence {
  switch (c) {
    case "confirmed": case "strong": case "suspected": case "weak": case "unknown":
      return c;
    default: return "unknown";
  }
}
function src(s: CloudSource | string | undefined): AttrSource {
  switch (s) {
    case "cloud_tag": case "cloud_graph": case "operator_catalog":
    case "firewall_appid": case "domain": case "ip_catalog": case "unknown":
      return s;
    default: return "unknown";
  }
}
function provider(p: string | undefined): Provider {
  return p === "aws" || p === "azure" || p === "gcp" ? p : "—";
}

// "AWS::ElasticLoadBalancingV2::LoadBalancer" → "LoadBalancer" (the real type,
// just the readable tail). Plain names pass through unchanged.
function shortType(t: string): string {
  if (!t) return "—";
  const parts = t.split("::");
  return parts[parts.length - 1] || t;
}

const APP_KEYS = ["app", "application", "app_name", "app-name", "service", "workload"];
const OWNER_KEYS = ["owner", "team", "owner_team", "managed_by"];
const ENV_KEYS = ["env", "environment", "stage", "tier"];

// Which of app/owner/env tags are absent (mirrors backend resolve.go tag keys),
// so the coverage "fix list" tells operators exactly what to add.
function missingTags(tags?: Record<string, string>): string[] {
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(tags ?? {})) {
    if (v && v.trim()) lower[k.trim().toLowerCase()] = v;
  }
  const has = (keys: string[]) => keys.some((k) => lower[k]);
  const out: string[] = [];
  if (!has(APP_KEYS)) out.push("app");
  if (!has(OWNER_KEYS)) out.push("owner");
  if (!has(ENV_KEYS)) out.push("env");
  return out;
}

// ── App (Applications tab) ───────────────────────────────────────────────────
function toApp(r: CloudAppRow): App {
  return {
    id: r.app_id || r.app_name,
    name: r.app_name || r.app_id,
    health: "unknown",           // not measured (P3C)
    owner: r.owner || "—",
    env: r.env || "—",
    confidence: conf(r.confidence),
    source: src(r.source),
    provider: provider(r.cloud_provider),
    account: r.account_id || "—",
    region: r.region || "—",
    resources: r.resources,
    trafficBps: NOT_MEASURED,    // not measured (P3B cloud_flow)
    errorPct: NOT_MEASURED,      // not measured (P3C)
    p95ms: 0,                    // renders "—" via existing column logic
    unknownPct: NOT_MEASURED,    // not measured
    lastSeen: new Date().toISOString(),
    primarySymptom: "—",
    rootDomain: "unknown",       // no RCA engine over cloud yet (P3D)
    underlayImpacted: false,
  };
}

// ── CloudResource (Cloud Resources tab) ──────────────────────────────────────
function toResource(r: CloudResourceRow): CloudResource {
  return {
    id: r.resource_id,
    name: r.resource_name || r.resource_id,
    type: shortType(r.resource_type),
    provider: provider(r.cloud_provider),
    account: r.account_id || "—",
    region: r.region || "—",
    app: r.app_name || "",       // "" = unattributed (first-class unknown)
    owner: r.owner || "—",
    env: r.env || "—",
    source: src(r.source),
    confidence: conf(r.confidence),
    health: "unknown",           // not measured (P3C)
    trafficBps: NOT_MEASURED,    // not measured (P3B)
    lastSeen: r.last_seen_at,
    missingTags: missingTags(r.tags),
    tags: r.tags ?? {},
    resourceId: r.resource_id,
  };
}

// ── UnknownContributor (Attribution + Unknowns tabs) ─────────────────────────
// Built from an unattributed resource (app_id == ""). Traffic/flows/errors are
// NOT_MEASURED until cloud_flow lands — the recommendation is the actionable bit.
function toUnknown(r: CloudResourceRow): UnknownContributor {
  const ip = r.private_ips?.[0];
  const label = r.resource_name || r.resource_id;
  return {
    entity: ip ? `${label} (${ip})` : label,
    kind: shortType(r.resource_type),
    provider: provider(r.cloud_provider),
    account: r.account_id || "—",
    region: r.region || "—",
    bytes: NOT_MEASURED,
    flows: NOT_MEASURED,
    errors: NOT_MEASURED,
    likelyResource: `${r.resource_id} (${shortType(r.resource_type)})`,
    missingFields: missingTags(r.tags),
    recommendation: `Tag ${label} with app/owner/env`,
  };
}

function toCoverage(c: CloudCoverageReport): Coverage {
  return {
    confirmedTag: c.confirmed_tag,
    strongGraph: c.strong_graph,
    firewallAppId: c.firewall_appid,
    suspectedDomainIp: c.suspected_domain_ip,
    unknown: c.unknown,
    total: c.total,
  };
}

// ── Loaders (what the tabs call) ─────────────────────────────────────────────
export async function loadApps(): Promise<App[]> {
  const r = await api.cloudApps();
  return (r.apps ?? []).map(toApp);
}

export async function loadResources(): Promise<CloudResource[]> {
  const r = await api.cloudResources();
  return (r.resources ?? []).map(toResource);
}

// The REAL engine RCA for an app (#81 P3G). Returns the most recent grounded
// corr_object, or null when the app has no active RCA (unknown stays first-class —
// we never synthesize a verdict the engine didn't form).
export async function loadAppRca(appId: string): Promise<AppRca | null> {
  if (!appId) return null;
  const r = await api.cloudAppRca(appId);
  const row = (r.data ?? [])[0];
  if (!row) return null;
  return {
    correlationId: row.correlation_id,
    verdictTier: row.verdict_tier || "undetermined",
    confidence: typeof row.confidence === "number" ? row.confidence : 0,
    signalCount: row.signal_count ?? 0,
    state: row.state || "open",
    crossPlane: row.cross_plane === 1 || row.cross_plane === true,
    sources: Array.isArray(row.sources) ? row.sources : [],
  };
}

export type CoverageBundle = { coverage: Coverage; unknowns: UnknownContributor[] };

export async function loadCoverage(): Promise<CoverageBundle> {
  const r = await api.cloudCoverage();
  return {
    coverage: toCoverage(r.coverage),
    unknowns: (r.top_unknown ?? []).map(toUnknown),
  };
}
