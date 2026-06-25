// App Observability — typed MOCK data (#81 P3F UI).
//
// This is clearly-labelled placeholder data so the UI renders + is reviewable today;
// it is NOT a backend call and makes no fake-data claims. Each page swaps `mockX`
// for `await api.cloudX()` when the /api/cloud/* endpoints land (shapes match types.ts).
// The set deliberately exercises EVERY confidence + health + unknown state.

import type {
  App, CloudResource, HealthSignal, ChangeEvent, EvidenceRow, Coverage,
  UnknownContributor, UnderlayImpact,
} from "./types";

const now = Date.UTC(2026, 5, 25, 14, 30); // fixed clock for deterministic mock
const t = (minsAgo: number) => new Date(now - minsAgo * 60_000).toISOString();

export const mockApps: App[] = [
  {
    id: "billing", name: "billing", health: "degraded", owner: "payments", env: "prod",
    confidence: "confirmed", source: "cloud_tag", provider: "aws", account: "123456789012",
    region: "us-east-1", resources: 4, trafficBps: 84_000_000, errorPct: 6.4, p95ms: 820,
    unknownPct: 2, lastSeen: t(0), lastChange: t(7), primarySymptom: "errors",
    rootDomain: "deployment", underlayImpacted: false,
  },
  {
    id: "checkout", name: "checkout", health: "down", owner: "commerce", env: "prod",
    confidence: "confirmed", source: "cloud_tag", provider: "aws", account: "123456789012",
    region: "us-east-1", resources: 6, trafficBps: 42_000_000, errorPct: 31.2, p95ms: 4200,
    unknownPct: 0, lastSeen: t(0), lastChange: t(140), primarySymptom: "availability",
    rootDomain: "database_dependency", underlayImpacted: false,
  },
  {
    id: "reports", name: "reports-worker", health: "degraded", owner: "data", env: "prod",
    confidence: "strong", source: "cloud_graph", provider: "aws", account: "123456789012",
    region: "us-east-1", resources: 2, trafficBps: 9_500_000, errorPct: 0.2, p95ms: 1500,
    unknownPct: 18, lastSeen: t(1), lastChange: t(1300), primarySymptom: "latency",
    rootDomain: "hybrid_underlay", underlayImpacted: true,
  },
  {
    id: "search", name: "search-api", health: "healthy", owner: "platform", env: "prod",
    confidence: "confirmed", source: "cloud_tag", provider: "gcp", account: "proj-platform",
    region: "us-central1", resources: 5, trafficBps: 120_000_000, errorPct: 0.1, p95ms: 95,
    unknownPct: 1, lastSeen: t(0), lastChange: t(2600), primarySymptom: "—",
    rootDomain: "unknown", underlayImpacted: false,
  },
  {
    id: "identity", name: "identity-svc", health: "healthy", owner: "security", env: "prod",
    confidence: "confirmed", source: "cloud_tag", provider: "azure", account: "sub-core",
    region: "eastus", resources: 3, trafficBps: 31_000_000, errorPct: 0.0, p95ms: 60,
    unknownPct: 0, lastSeen: t(0), primarySymptom: "—", rootDomain: "unknown",
    underlayImpacted: false,
  },
  {
    id: "unknown-1", name: "unknown", health: "unknown", owner: "—", env: "—",
    confidence: "unknown", source: "unknown", provider: "aws", account: "123456789012",
    region: "us-east-1", resources: 3, trafficBps: 22_000_000, errorPct: 0, p95ms: 0,
    unknownPct: 100, lastSeen: t(2), primarySymptom: "—", rootDomain: "unknown",
    underlayImpacted: false,
  },
];

export const mockResources: CloudResource[] = [
  { id: "alb-billing", name: "billing-alb", type: "ALB", provider: "aws", account: "123456789012", region: "us-east-1", app: "billing", owner: "payments", env: "prod", source: "cloud_tag", confidence: "confirmed", health: "degraded", trafficBps: 84_000_000, lastSeen: t(0), missingTags: [] },
  { id: "ecs-billing", name: "billing-svc", type: "ECS Task", provider: "aws", account: "123456789012", region: "us-east-1", app: "billing", owner: "payments", env: "prod", source: "cloud_tag", confidence: "confirmed", health: "degraded", trafficBps: 40_000_000, lastSeen: t(0), missingTags: [] },
  { id: "rds-billing", name: "billing-db", type: "RDS", provider: "aws", account: "123456789012", region: "us-east-1", app: "billing", owner: "payments", env: "prod", source: "cloud_tag", confidence: "confirmed", health: "healthy", trafficBps: 5_000_000, lastSeen: t(0), missingTags: [] },
  { id: "ec2-legacy", name: "legacy-reports-worker", type: "EC2", provider: "aws", account: "123456789012", region: "us-east-1", app: "reports-worker", owner: "data", env: "—", source: "cloud_graph", confidence: "strong", health: "degraded", trafficBps: 9_500_000, lastSeen: t(1), missingTags: ["app", "env"] },
  { id: "ec2-orphan", name: "i-0untagged01", type: "EC2", provider: "aws", account: "123456789012", region: "us-east-1", app: "", owner: "—", env: "—", source: "unknown", confidence: "unknown", health: "unknown", trafficBps: 22_000_000, lastSeen: t(2), missingTags: ["app", "owner", "env"] },
];

export const mockHealth: HealthSignal[] = [
  { time: t(6), app: "billing", resource: "billing-alb", signal: "alb_5xx", state: "degraded", metric: "HTTPCode_Target_5XX", current: "6.4%", baseline: "0.2%", severity: "warning", source: "cloudwatch_metric" },
  { time: t(5), app: "billing", resource: "billing-db", signal: "rds_connections", state: "degraded", metric: "DatabaseConnections", current: "98%", baseline: "40%", severity: "warning", source: "cloudwatch_metric" },
  { time: t(0), app: "checkout", resource: "checkout-alb", signal: "target_health", state: "down", metric: "UnHealthyHostCount", current: "3/3", baseline: "0", severity: "critical", source: "elb_target_health" },
  { time: t(2), app: "reports-worker", resource: "dx-conn-1", signal: "resource_health", state: "degraded", metric: "ConnectionState", current: "degraded", baseline: "available", severity: "warning", source: "aws_health" },
];

export const mockChanges: ChangeEvent[] = [
  { time: t(7), app: "billing", resource: "billing-svc", changeType: "deploy", actor: "ci:deploy-7f3a", source: "cloudtrail", confidence: "confirmed", relatedSymptoms: ["alb_5xx", "rds_connections"] },
  { time: t(140), app: "checkout", resource: "checkout-sg", changeType: "security_policy_change", actor: "role:netops-7c2", source: "cloudtrail", confidence: "confirmed", relatedSymptoms: ["target_unhealthy"] },
  { time: t(20), app: "search-api", resource: "search-rt", changeType: "route_change", actor: "ci:deploy-9b1", source: "cloud_audit", confidence: "strong", relatedSymptoms: [] },
];

export const mockEvidence: EvidenceRow[] = [
  { time: t(7), signalType: "cloud_change", app: "billing", resource: "billing-svc", source: "cloudtrail", confidence: "confirmed", reason: "deploy 7 min before 5xx onset", rcaGroup: "rca-billing-01", evidenceRef: "ct:evt/9f3a..." },
  { time: t(6), signalType: "cloud_health", app: "billing", resource: "billing-alb", source: "cloudwatch_metric", confidence: "strong", reason: "ALB target 5xx 0.2%→6.4%", rcaGroup: "rca-billing-01", evidenceRef: "cw:HTTPCode_Target_5XX" },
  { time: t(5), signalType: "cloud_health", app: "billing", resource: "billing-db", source: "cloudwatch_metric", confidence: "suspected", reason: "DB connections near max (pool exhaustion)", rcaGroup: "rca-billing-01", evidenceRef: "cw:DatabaseConnections" },
  { time: t(0), signalType: "cloud_lb_access", app: "checkout", resource: "checkout-alb", source: "cloud_tag", confidence: "confirmed", reason: "target_status_code='-' (no backend response)", rcaGroup: "rca-checkout-01", evidenceRef: "alb:log/00ab..." },
];

export const mockCoverage: Coverage = {
  confirmedTag: 412, strongGraph: 88, firewallAppId: 41, suspectedDomainIp: 53, unknown: 96, total: 690,
};

export const mockUnknowns: UnknownContributor[] = [
  { entity: "eni-unk1 (10.0.6.6)", kind: "ENI", provider: "aws", account: "123456789012", region: "us-east-1", bytes: 18_400_000_000, flows: 240_000, errors: 1200, likelyResource: "i-0untagged01 (EC2)", missingFields: ["app", "owner", "env"], recommendation: "Tag i-0untagged01 with app/owner/env" },
  { entity: "10.0.9.12", kind: "private_ip", provider: "aws", account: "123456789012", region: "us-east-1", bytes: 6_100_000_000, flows: 51_000, errors: 0, likelyResource: "(no inventory match — ENI recycled)", missingFields: ["resource"], recommendation: "Enable Config/Resource Explorer for full inventory" },
];

export const mockUnderlay: UnderlayImpact[] = [
  { app: "reports-worker", provider: "aws", seam: "Direct Connect", path: "us-east-1 ⇄ on-prem dc1", underlayEvidence: "DX virtual interface BGP flap + RTT 12→140ms", appSymptom: "p95 latency 1.5s", rootDomain: "hybrid_underlay", confidence: "suspected", owner: "data" },
];
