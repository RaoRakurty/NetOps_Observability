// App Observability — typed model (#81 P3F UI).
//
// These types are the CONTRACT the future cloud endpoints will return; the UI is
// built against them with typed mock data today and wires cleanly later. No fake
// backend calls are made — see mock.ts. Endpoints (future):
//   GET /api/cloud/apps · /api/cloud/resources · /api/cloud/identity-map
//   GET /api/cloud/attribution/coverage · /api/cloud/health · /api/cloud/changes
//   GET /api/cloud/evidence · GET /api/flows/apps?include_cloud=true

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
  provider: Provider;
  account: string;
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
  trafficBps: number;
  lastSeen: string;
  missingTags: string[];  // e.g. ["app","owner"]
  tags?: Record<string, string>;
  resourceId?: string;    // the raw cloud id/ARN (drawer identity)
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
}

// How a piece of evidence relates to a verdict — the anti-black-box ledger.
// supporting = argues for · contradicting = argues against · discriminating =
// separates competing root domains · missing = a signal we'd want but don't have
// (honest gap) · recovery = confirmed the fix/return-to-baseline.
export type EvidenceCategory = "supporting" | "contradicting" | "discriminating" | "missing" | "recovery";

export interface EvidenceRow {
  time: string;
  category: EvidenceCategory;
  signalType: string;     // cloud_health | cloud_change | cloud_flow | cloud_lb_access | underlay | ...
  app: string;
  resource: string;
  source: AttrSource | string;
  confidence: Confidence;
  reason: string;
  usedInVerdict: boolean; // did this row feed the verdict, or is it context/gap?
  rcaGroup: string;       // "" when none
  evidenceRef: string;    // opaque ref to the raw record
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
  entity: string;         // resource / IP / ENI / NIC
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
