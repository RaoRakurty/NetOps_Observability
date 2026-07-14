// App Observability — typed model (#81 P3F/P3H UI).
//
// These types are the CONTRACT the cloud endpoints return. Every one of them is
// now fed by a LIVE, tenant-scoped endpoint — there is no sample data behind this
// page any more (the old mock.ts is deleted; a tab with no ingested source renders
// an honest empty state instead of rows).
//   GET /api/cloud/apps · /api/cloud/resources · /api/cloud/identity-map
//   GET /api/cloud/attribution/coverage · /api/cloud/ingestion
//   GET /api/cloud/health · /api/cloud/changes · /api/cloud/evidence · /api/cloud/app-rca
// Not ingested yet (rendered as explicit gaps, never faked): per-app cloud flow /
// LB traffic, traces, and the app→underlay seam correlation.

export type Confidence = "confirmed" | "strong" | "suspected" | "weak" | "unknown";
export type Health = "healthy" | "degraded" | "down" | "unknown";
export type Provider = "aws" | "azure" | "gcp" | "—";

// the source that attributed an app/resource (mirrors backend cloud.Source)
export type AttrSource =
  | "cloud_tag" | "cloud_graph" | "operator_catalog" | "firewall_appid"
  | "domain" | "ip_catalog" | "unknown";

// RCA root-domain taxonomy (mirrors the P3D spec)
export type RootDomain =
  | "application" | "deployment" | "cloud_resource" | "cloud_security_policy"
  | "cloud_network" | "cloud_provider" | "hybrid_underlay" | "external_saas"
  | "dns" | "certificate_tls" | "identity_auth" | "database_dependency" | "unknown";

export type Symptom =
  | "latency" | "errors" | "saturation" | "availability"
  | "target_unhealthy" | "dependency_unhealthy" | "—";

export interface App {
  id: string;
  name: string;
  health: Health;
  owner: string;
  env: string;
  confidence: Confidence;
  source: AttrSource;
  provider: Provider;   // primary (first seen) — kept for single-provider surfaces
  // ALL providers this service spans (a dual-cloud app is one service in two
  // clouds, never two rows and never a row that silently drops one cloud).
  providers: Provider[];
  account: string;      // joined with " · " when the service spans accounts
  region: string;
  resources: number;
  trafficBps: number;
  errorPct: number;
  p95ms: number;
  unknownPct: number;
  lastSeen: string;       // ISO
  lastChange?: string;    // ISO
  primarySymptom: Symptom;
  rootDomain: RootDomain; // active RCA domain ("unknown" when none)
  underlayImpacted: boolean;
}

export interface CloudResource {
  id: string;
  name: string;
  type: string;
  provider: Provider;
  account: string;
  region: string;
  app: string;            // "" = unattributed
  owner: string;
  env: string;
  source: AttrSource;
  confidence: Confidence;
  health: Health;
  powerState: string;     // provider lifecycle (running | stopped | …); "—" unknown
  trafficBps: number;
  lastSeen: string;
  missingTags: string[];  // e.g. ["app","owner"]
  tags?: Record<string, string>;
  resourceId?: string;    // the raw cloud id/ARN (drawer identity)
  consoleUrl?: string;    // server-built provider console deep-link ("" = none)
}

export interface HealthSignal {
  time: string;
  app: string;
  resource: string;
  signal: string;         // e.g. "alb_5xx", "resource_health"
  state: Health;
  metric: string;
  current: string;
  baseline: string;
  severity: "critical" | "warning" | "info";
  source: string;         // cloudwatch_alarm | azure_resource_health | ...
}

export interface ChangeEvent {
  time: string;
  app: string;
  resource: string;
  changeType:
    | "deploy" | "config_change" | "security_policy_change" | "route_change"
    | "scale_change" | "iam_change" | "dns_change" | "cert_change" | "unknown";
  actor: string;          // hashed/role, not raw identity
  source: string;         // cloudtrail | azure_activity_log | cloud_audit
  confidence: Confidence;
  relatedSymptoms: string[];
  cloudRef?: CloudRef;    // console pivot to the provider's audit record
}

// How a finding relates to an investigation — the anti-black-box ledger.
// grounded = the engine attached it to the investigation (a fact we hold) ·
// contradicting = argues against · discriminating = separates competing root
// domains · missing = a signal we'd want but don't have (honest gap) ·
// recovery = confirmed the fix/return-to-baseline. Per-signal verdict
// participation is NOT recorded, so it is never claimed (audit D-P2-13).
export type EvidenceCategory = "grounded" | "contradicting" | "discriminating" | "missing" | "recovery";

// The provider-native identity behind a row: the raw handle (i-…, eni-…, ARM id)
// an engineer pastes into a support case, plus the server-built console pivot.
// consoleUrl/logUrl are "" when unresolvable — the UI shows no link over a guess.
export interface CloudRef {
  provider: string;
  resourceId: string;
  account: string;
  region: string;
  consoleUrl: string;  // the resource in the AWS console / Azure portal
  logUrl: string;      // the provider's log record (CloudTrail event / Activity Log)
}

export interface EvidenceRow {
  time: string;
  category: EvidenceCategory;
  signalType: string;     // cloud_health | cloud_change | cloud_flow | cloud_lb_access | underlay | ...
  app: string;
  resource: string;
  source: AttrSource | string;
  confidence: Confidence;
  reason: string;
  grounded: boolean;      // the engine attached this row to the investigation (vs a declared gap)
  rcaGroup: string;       // "" when none
  evidenceRef: string;    // opaque ref to the raw record
  cloudRef?: CloudRef;    // console pivot (absent for engine-generated gap rows)
}

export interface Coverage {
  confirmedTag: number;   // counts (resources or flows)
  strongGraph: number;
  firewallAppId: number;
  suspectedDomainIp: number;
  unknown: number;
  total: number;
}

export interface UnknownContributor {
  entity: string;         // stable row key (name + address)
  name: string;           // the resource NAME leads every cell (audit C: never a bare id)
  address: string;        // primary private IP ("" when none)
  resourceId: string;     // the raw provider handle — secondary, mono, drawer-only
  kind: string;           // "ENI" | "private_ip" | "resource_id" | ...
  provider: Provider;
  account: string;
  region: string;
  bytes: number;
  flows: number;
  errors: number;
  likelyResource: string; // best-effort guess (never asserted as the app)
  missingFields: string[];
  recommendation: string;
}

// ── Overview-specific models (#81 P3F Overview pass) ────────────────────────

// Underlay involvement is EXPLICIT — never a bare "—". kind drives tone, seam names it.
export type UnderlayState =
  | { kind: "none" }                       // "No impact"
  | { kind: "suspected"; seam: string }    // "Suspected: DX Dallas"
  | { kind: "confirmed"; seam: string }    // "Confirmed: VPN East"
  | { kind: "not_checked" }                // "Not checked"
  | { kind: "unknown" };                   // "Unknown"

export interface EvidenceItem {
  text: string;
  kind: "supporting" | "contradicting";
}

export interface RcaDrawerModel {
  app: string;
  health: Health;
  rootDomain: RootDomain;
  confidence: Confidence;
  recommendedOwner: string;
  evidence: EvidenceItem[];   // supporting + contradicting, in one list
  nextAction: string;
}

// A row in the Overview "Impacted Applications" table — the 5-second story.
export interface ImpactedApplication {
  id: string;
  name: string;
  health: Health;
  owner: string;
  env: string;
  symptom: string;            // human symptom (e.g. "5xx errors", "latency")
  rootDomain: RootDomain;     // likely root domain
  confidence: Confidence;
  why: string;                // evidence-grounded one-liner — the critical column
  trafficBps: number;
  lastChange?: string;        // ISO
  underlay: UnderlayState;
  action: string;             // recommended action label
  rca: RcaDrawerModel;        // drawer payload
}

export interface RootDomainBreakdown { domain: RootDomain; count: number; }

export interface AppOverviewSummary {
  // impact group
  appsDegraded: number;
  activeRca: number;
  underlayImpacted: number;
  // coverage group
  appsObserved: number;
  resourcesMapped: number;
  unknownPct: number;
  // change group
  recentChanges: number;
  deployLinkedIncidents: number;
  // small subtext/trend per metric key (e.g. "+3 vs 1h", "↑ 2")
  trends?: Partial<Record<string, string>>;
}

export interface UnderlayImpact {
  app: string;
  provider: Provider;
  seam: string;           // DX / VPN / ExpressRoute / Interconnect / TGW / NAT
  path: string;
  underlayEvidence: string;
  appSymptom: string;
  rootDomain: RootDomain;
  confidence: Confidence;
  owner: string;
}

// AppRca — the REAL engine-formed cloud RCA object for an app (#81 P3G), as
// surfaced by /api/cloud/app-rca. Distinct from the heuristic root-domain verdict:
// this is the correlation engine's grounded object (links to the full RCA detail).
export interface AppRca {
  correlationId: string;
  verdictTier: string;     // confirmed | suspected | undetermined | recovered | contradicted
  confidence: number;      // 0..1
  signalCount: number;
  state: string;           // open | closed
  // corroboration facts (audit D-P2-12): crossPlane = the engine's own
  // plane_count ≥ 2 (the ≥2-independent-streams standard), observers = the
  // DISTINCT observer identities that actually saw it (not source planes).
  crossPlane: boolean;
  planeCount: number;
  observerCount: number;
  observers: string[];     // up to 8 observer ids
  sources: string[];       // observed signal planes (cloud, probe, …)
}
