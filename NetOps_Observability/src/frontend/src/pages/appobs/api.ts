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
  CloudHealthSignalRow, CloudChangeRow, CloudEvidenceRow, CloudRcaObjectRow, CloudRefWire,
  CloudResourceQuery,
} from "../../services/api";
import type {
  App, CloudResource, Coverage, UnknownContributor, Provider, Confidence, AttrSource, AppRca,
  HealthSignal, ChangeEvent, EvidenceRow, EvidenceCategory, Health, CloudRef,
} from "./types";
import { deriveObjectOrigins, EMPTY_ORIGIN } from "./origin";
import type { ObjectOrigin } from "./origin";

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
  const p = provider(r.cloud_provider);
  return {
    id: r.app_id || r.app_name,
    name: r.app_name || r.app_id,
    health: "unknown",           // not measured (P3C)
    owner: r.owner || "—",
    env: r.env || "—",
    confidence: conf(r.confidence),
    source: src(r.source),
    provider: p,
    providers: p === "—" ? [] : [p],
    account: r.account_id || "—",
    region: r.region || "—",
    resources: r.resources,
    trafficBps: NOT_MEASURED,    // not measured (P3B cloud_flow)
    errorPct: NOT_MEASURED,      // not measured (P3C)
    p95ms: NOT_MEASURED,         // ONE sentinel for "not measured" (audit C)
    unknownPct: NOT_MEASURED,    // not measured
    lastSeen: new Date().toISOString(),
    primarySymptom: "—",
    rootDomain: "unknown",       // no RCA engine over cloud yet (P3D)
    underlayImpacted: false,
  };
}

// One service, however many clouds it spans: rows sharing an app_id merge into
// a single App carrying the provider SET (a dual-cloud app must never collapse
// to one provider or collide as duplicate row keys — audit D-P0-4 sibling).
function mergeApps(rows: App[]): App[] {
  const byId = new Map<string, App>();
  for (const a of rows) {
    const cur = byId.get(a.id);
    if (!cur) {
      byId.set(a.id, a);
      continue;
    }
    for (const p of a.providers) {
      if (!cur.providers.includes(p)) cur.providers.push(p);
    }
    if (a.account !== "—" && !cur.account.includes(a.account)) {
      cur.account = cur.account === "—" ? a.account : `${cur.account} · ${a.account}`;
    }
    if (a.region !== "—" && !cur.region.includes(a.region)) {
      cur.region = cur.region === "—" ? a.region : `${cur.region} · ${a.region}`;
    }
    cur.resources += a.resources;
    if (cur.owner === "—") cur.owner = a.owner;
    if (cur.env === "—") cur.env = a.env;
  }
  return [...byId.values()];
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
    powerState: r.power_state || "—", // provider lifecycle; stopped ≠ broken
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
  const ip = r.private_ips?.[0] ?? "";
  const label = r.resource_name || r.resource_id;
  return {
    entity: ip ? `${label} (${ip})` : label,
    name: label,
    address: ip,
    resourceId: r.resource_id,
    kind: shortType(r.resource_type),
    provider: provider(r.cloud_provider),
    account: r.account_id || "—",
    region: r.region || "—",
    bytes: NOT_MEASURED,
    flows: NOT_MEASURED,
    errors: NOT_MEASURED,
    // name-first, never the raw handle as the human answer (audit C):
    likelyResource: `${label} (${shortType(r.resource_type)})`,
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
  const live = r.live ?? {};
  return mergeApps((r.apps ?? []).map(toApp)).map((app) => {
    // Merge the backend's measured live enrichment (provider status checks,
    // probe outcomes). Without this the page hard-coded health "unknown" and
    // rendered a degraded cloud as all-grey — the exact lie the audit flagged.
    const l = live[app.name] ?? live[app.id];
    if (l?.health === "healthy" || l?.health === "degraded" || l?.health === "down") {
      app.health = l.health;
      // failing status checks / probe failures are an availability symptom
      if (l.health !== "healthy") app.primarySymptom = "availability";
    }
    return app;
  });
}

// ── Shared inventory read (2026-07 review, improvement #14) ──────────────────
// One page visit used to fire GET /api/cloud/resources 3–5× (the shell hook plus
// every tab that needs the inventory), each pulling the FULL inventory. A short-
// TTL module cache with in-flight dedup keeps a visit to one fetch without
// changing any consumer's data shape. 30s stays well inside the backend's
// 2-minute inventory refresh cadence, so staleness is bounded by the store
// itself; errors are never cached (zero-trust: a failure is re-asked, not
// remembered as truth).
type CloudResourcesResponse = Awaited<ReturnType<typeof api.cloudResources>>;
const INVENTORY_TTL_MS = 30_000;
// Cache is keyed by the server-side filter (Wave 2 #5): the unfiltered read the
// shell/options need and each scoped read coexist without evicting each other.
const invCache = new Map<string, { at: number; data: CloudResourcesResponse }>();
const invInflight = new Map<string, Promise<CloudResourcesResponse>>();

function invKey(q?: CloudResourceQuery): string {
  if (!q) return "";
  return [q.providers ?? [], q.accounts ?? [], q.regions ?? []]
    .map((v) => [...v].sort().join(",")).join("|");
}

export function fetchCloudInventory(q?: CloudResourceQuery): Promise<CloudResourcesResponse> {
  const key = invKey(q);
  const hit = invCache.get(key);
  if (hit && Date.now() - hit.at < INVENTORY_TTL_MS) {
    return Promise.resolve(hit.data);
  }
  const inflight = invInflight.get(key);
  if (inflight) return inflight;
  const p = api.cloudResources(q).then(
    (r) => { invCache.set(key, { at: Date.now(), data: r }); invInflight.delete(key); return r; },
    (e) => { invInflight.delete(key); throw e; },
  );
  invInflight.set(key, p);
  return p;
}

// Drop the cached inventory: after a write that changes attribution (e.g. a
// bulk service assignment) the next read must see the server's truth. Also the
// test seam.
export function invalidateCloudInventory(): void {
  invCache.clear();
  invInflight.clear();
}

// SERVER-side scope filtering (Wave 2 #5): provider/account/region ride the
// Wave-1 SQL filters on /api/cloud/resources — never fetch-all-and-narrow for
// dimensions the store filters itself. env is the one client-side leftover:
// it is a resolved tag, not a store column, and the fetched page is already
// LIMIT-bounded, so narrowing it here is the honest, cheap remainder.
export async function loadResources(scope?: {
  providers: string[]; accounts: string[]; regions: string[]; envs: string[];
}): Promise<CloudResource[]> {
  const q: CloudResourceQuery | undefined =
    scope && (scope.providers.length || scope.accounts.length || scope.regions.length)
      ? { providers: scope.providers, accounts: scope.accounts, regions: scope.regions }
      : undefined;
  const r = await fetchCloudInventory(q);
  const consoleUrls = r.console_urls ?? {};
  const out = (r.resources ?? []).map((row) => ({
    ...toResource(row),
    consoleUrl: safeConsoleUrl(consoleUrls[row.resource_id]),
  }));
  const envs = scope?.envs ?? [];
  if (envs.length === 0) return out;
  return out.filter((res) => envs.includes(res.env));
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
    planeCount: typeof row.plane_count === "number" ? row.plane_count : 0,
    observerCount: typeof row.observer_count === "number" ? row.observer_count : 0,
    observers: Array.isArray(row.observers) ? row.observers : [],
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

// ── Health / Change / Evidence (#81 P3H — LIVE cloud telemetry) ───────────────
// These used to render sample rows. They now render ONLY signals that actually
// landed from a connected AWS / Azure account (corr_signals, source=cloud). The
// backend already shapes each row for the table (src/backend/cloud_signals.go);
// this layer only re-keys to the view types and defends the enums. When nothing
// landed, the list is empty and the tab shows its honest empty state — never a
// fabricated app, resource or event.

function health(h: string | undefined): Health {
  switch (h) {
    case "healthy": case "degraded": case "down": case "unknown": return h;
    default: return "unknown";
  }
}
function severity(s: string | undefined): HealthSignal["severity"] {
  return s === "critical" || s === "warning" ? s : "info";
}
const CHANGE_TYPES: ChangeEvent["changeType"][] = [
  "deploy", "config_change", "security_policy_change", "route_change",
  "scale_change", "iam_change", "dns_change", "cert_change", "unknown",
];
function changeType(t: string | undefined): ChangeEvent["changeType"] {
  const hit = CHANGE_TYPES.find((c) => c === t);
  return hit ?? "unknown";
}
// The engine records only two evidence roles today: a signal it GROUNDED into an
// object and its own declared gaps (missing). Anything else would be a category
// we invented — it degrades to "grounded" rather than being claimed.
function evidenceCategory(c: string | undefined): EvidenceCategory {
  return c === "missing" ? "missing" : "grounded";
}

function toHealthSignal(r: CloudHealthSignalRow): HealthSignal {
  return {
    time: r.time, app: r.app, resource: r.resource, signal: r.signal,
    state: health(r.state), metric: r.metric, current: r.current,
    baseline: r.baseline, severity: severity(r.severity), source: r.source,
    // the provider's own reasonType for a state event ("" when it declared none)
    reason: r.reason ?? "",
  };
}

// Zero-trust gate on server-built console links: only https URLs on the three
// provider console hosts ever reach an <a href>. Anything else renders no link.
// (2026-07 product review finding: GCP was missing here, so every GCP console /
// Logs Explorer pivot the backend built was silently dropped in the UI.)
export function safeConsoleUrl(u: string | undefined): string {
  if (!u) return "";
  try {
    const p = new URL(u);
    if (p.protocol !== "https:") return "";
    if (
      p.hostname === "portal.azure.com" ||
      p.hostname.endsWith(".console.aws.amazon.com") ||
      p.hostname === "console.cloud.google.com"
    ) return u;
  } catch { /* not parseable — no link */ }
  return "";
}

function toCloudRef(r: CloudRefWire | undefined): CloudRef | undefined {
  if (!r) return undefined;
  const consoleUrl = safeConsoleUrl(r.console_url);
  const logUrl = safeConsoleUrl(r.log_url);
  if (!r.resource_id && !consoleUrl && !logUrl) return undefined; // nothing to pivot on
  return {
    provider: r.provider ?? "", resourceId: r.resource_id ?? "",
    account: r.account ?? "", region: r.region ?? "", consoleUrl, logUrl,
  };
}

function toChangeEvent(r: CloudChangeRow): ChangeEvent {
  return {
    time: r.time, app: r.app, resource: r.resource, changeType: changeType(r.change_type),
    actor: r.actor, source: r.source, confidence: conf(r.confidence),
    relatedSymptoms: r.related_symptoms ?? [],
    cloudRef: toCloudRef(r.cloud_ref),
  };
}

function toEvidenceRow(r: CloudEvidenceRow): EvidenceRow {
  return {
    time: r.time, category: evidenceCategory(r.category), signalType: r.signal_type,
    app: r.app, resource: r.resource, source: r.source, confidence: conf(r.confidence),
    reason: r.reason, grounded: !!r.grounded,
    rcaGroup: r.rca_group, evidenceRef: r.evidence_ref,
    cloudRef: toCloudRef(r.cloud_ref),
  };
}

// A cloud correlation object the engine actually formed (the Overview "Active
// cloud RCA" table + the evidence ledger's grouping).
export interface CloudRcaObject {
  correlationId: string;
  verdictTier: string;
  confidence: number;
  topHypothesis: string;
  signalCount: number;
  state: string;
  windowStart: string;
  apps: string[];
  // DERIVED from this object's own attached evidence (see ./origin), not from a
  // new backend field: the clouds that actually produced its signals, and the
  // primary affected resource used as the Service column's honest fallback.
  // providers = [] means no cloud signal is attached — a network/on-prem object.
  origin: ObjectOrigin;
}
function toRcaObject(r: CloudRcaObjectRow): CloudRcaObject {
  return {
    correlationId: r.correlation_id, verdictTier: r.verdict_tier || "undetermined",
    confidence: typeof r.confidence === "number" ? r.confidence : 0,
    topHypothesis: r.top_hypothesis || "—", signalCount: r.signal_count ?? 0,
    state: r.state || "open", windowStart: r.window_start, apps: r.apps ?? [],
    origin: EMPTY_ORIGIN,
  };
}

// windowHours (Wave 2 #5): the REAL server read window — the backend clamps to
// 1..168 and reports what it honored; absent keeps the 24h default.
export async function loadHealthSignals(app?: string, windowHours?: number): Promise<HealthSignal[]> {
  const r = await api.cloudHealth(app, undefined, windowHours);
  return (r.signals ?? []).map(toHealthSignal);
}

export async function loadChangeEvents(app?: string, windowHours?: number): Promise<ChangeEvent[]> {
  const r = await api.cloudChanges(app, undefined, windowHours);
  return (r.changes ?? []).map(toChangeEvent);
}

export type EvidenceBundle = {
  objects: CloudRcaObject[];
  rows: EvidenceRow[];
  // TRUE counts from the backend (audit D-P1-7 / D-P2-13): openCount is a real
  // COUNT of open investigations (never the LIMIT-capped list length); total is
  // the full ledger size; the rows above are one LIMIT-bounded page.
  openCount: number;
  total: number;
  objectsTruncated: boolean;
};

export async function loadEvidence(app?: string, windowHours?: number): Promise<EvidenceBundle> {
  const r = await api.cloudEvidence(app, undefined, windowHours);
  const rows = (r.evidence ?? []).map(toEvidenceRow);
  // Origin + fallback identity come from the evidence already in this response —
  // one join, no extra request, and nothing claimed that the engine did not ground.
  const origins = deriveObjectOrigins(rows);
  const objects = (r.objects ?? []).map(toRcaObject).map((o) => ({
    ...o,
    origin: origins.get(o.correlationId) ?? EMPTY_ORIGIN,
  }));
  return {
    objects,
    rows,
    openCount: typeof r.open_object_count === "number"
      ? r.open_object_count
      : objects.filter((o) => o.state === "open").length,
    total: typeof r.count === "number" ? r.count : (r.evidence ?? []).length,
    objectsTruncated: !!r.objects_truncated,
  };
}
