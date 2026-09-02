// App Observability — attribution analytics (#81 P3F+1 gap close).
//
// Pure, testable helpers over the LIVE cloud inventory (no telemetry needed):
// the coverage funnel, coverage-by-scope, and resource categorization. Everything
// here is derivable from identity/structure alone — traffic/health stay elsewhere
// and honestly "not measured".

import type { CloudResource, Coverage } from "./types";

// ── Resource category (compute / network / data / observability) ──────────────
export type ResourceCategory = "Compute" | "Network" | "Data" | "Observability" | "Other";

export function resourceCategory(type: string): ResourceCategory {
  const t = (type || "").toLowerCase();
  // Data first: "DBInstance" must not match Compute's "instance" before Data's "db".
  // \bdb avoids matching "loaDBalancer"; covers db/database/dbinstance.
  if (/\bdb|rds|dynamo|table|s3|bucket|cache|redis|elasticache|queue|stream|sql|cosmos|storage/.test(t)) return "Data";
  if (/loadbalancer|natgateway|gateway|vpc|vnet|subnet|eni|networkinterface|nic|securitygroup|nacl|transitgateway|vpn|directconnect|expressroute|interconnect|route/.test(t)) return "Network";
  if (/instance|task|function|lambda|ecs|eks|container|virtualmachine|\bvm\b|compute|pod|node|web\/sites|appservice|web:site|serverfarm|run:service|agentpool/.test(t)) return "Compute";
  if (/metric|log|flow|trace|cloudwatch|monitor/.test(t)) return "Observability";
  return "Other";
}

export const RESOURCE_CATEGORIES: ResourceCategory[] = ["Compute", "Network", "Data", "Observability", "Other"];

// ── Workload classes (Wave 5 #15 — inventory beyond VMs) ──────────────────────
// Exact-type classifier over the SAME vocabulary the backend buckets by
// (cloud/kinds.go componentFamilies): the K8s layer, serverless/PaaS, and
// managed databases. Distinct from resourceCategory (the coarse AppMap axis):
// a class names WHAT the discovery lanes can enumerate, so each class can
// carry an honest "nothing discovered — here is the permission it needs" state.
export type WorkloadClass = "k8s" | "serverless" | "db";

const WORKLOAD_TYPES: Record<string, WorkloadClass> = {
  // K8s layer — clusters + node pools
  "eks:cluster": "k8s", "eks:nodegroup": "k8s",
  "containerservice:managedcluster": "k8s", "containerservice:agentpool": "k8s",
  "container:cluster": "k8s", "container:nodepool": "k8s",
  // serverless / PaaS
  "lambda:function": "serverless", "web:site": "serverless",
  "web:serverfarm": "serverless", "run:service": "serverless",
  // managed databases
  "rds:instance": "db", "sql:server": "db", "sql:database": "db",
  "sqladmin:instance": "db",
};

export function workloadClass(type: string): WorkloadClass | null {
  return WORKLOAD_TYPES[(type || "").trim().toLowerCase()] ?? null;
}

export const WORKLOAD_CLASSES: WorkloadClass[] = ["k8s", "serverless", "db"];

// Per-class label + the HONEST empty state: which read permissions the
// discovery lanes need per provider. Rendered verbatim when a class filter
// matches nothing — absence explained, never a bare empty table.
export const WORKLOAD_CLASS_META: Record<WorkloadClass, { label: string; emptyTitle: string; emptyHint: string }> = {
  k8s: {
    label: "K8s clusters",
    emptyTitle: "No clusters discovered",
    emptyHint: "the collector needs eks:ListClusters + eks:DescribeCluster (AWS), Microsoft.ContainerService/managedClusters read (Azure), or container.clusters.list (GCP) — grant the read and clusters appear on the next discovery cycle",
  },
  serverless: {
    label: "Serverless / PaaS",
    emptyTitle: "No serverless or PaaS services discovered",
    emptyHint: "the collector needs lambda:ListFunctions (AWS), Microsoft.Web sites/serverfarms read (Azure), or run.services.list (GCP) — grant the read and services appear on the next discovery cycle",
  },
  db: {
    label: "Managed databases",
    emptyTitle: "No managed databases discovered",
    emptyHint: "the collector needs rds:DescribeDBInstances (AWS), Microsoft.Sql servers/databases read (Azure), or cloudsql.instances.list (GCP) — grant the read and databases appear on the next discovery cycle",
  },
};

// a resource counts as attributed when it has an app AND a non-unknown confidence.
export function isAttributed(r: CloudResource): boolean {
  return !!r.app && r.confidence !== "unknown";
}

// ── Coverage-by-scope ─────────────────────────────────────────────────────────
export interface ScopeCoverage {
  scope: string;
  total: number;
  attributed: number;
  pct: number;
}

export function coverageByScope(resources: CloudResource[], dimOf: (r: CloudResource) => string): ScopeCoverage[] {
  const m = new Map<string, { total: number; attributed: number }>();
  for (const r of resources) {
    const k = dimOf(r) || "—";
    const cur = m.get(k) ?? { total: 0, attributed: 0 };
    cur.total++;
    if (isAttributed(r)) cur.attributed++;
    m.set(k, cur);
  }
  return [...m.entries()]
    .map(([scope, v]) => ({ scope, total: v.total, attributed: v.attributed, pct: v.total ? Math.round((v.attributed / v.total) * 100) : 0 }))
    .sort((a, b) => a.scope.localeCompare(b.scope));
}

// ── Coverage funnel ───────────────────────────────────────────────────────────
export interface FunnelStep { label: string; count: number; pct: number; tone: string }

export function funnelSteps(c: Coverage): FunnelStep[] {
  const pct = (n: number) => (c.total ? Math.round((n / c.total) * 100) : 0);
  return [
    { label: "Confirmed by tag", count: c.confirmedTag, pct: pct(c.confirmedTag), tone: "var(--ok)" },
    { label: "Strong by resource graph", count: c.strongGraph, pct: pct(c.strongGraph), tone: "var(--accent)" },
    { label: "Firewall App-ID", count: c.firewallAppId, pct: pct(c.firewallAppId), tone: "var(--ok)" },
    { label: "Suspected (domain / IP)", count: c.suspectedDomainIp, pct: pct(c.suspectedDomainIp), tone: "var(--warn)" },
    { label: "Unknown", count: c.unknown, pct: pct(c.unknown), tone: "var(--fg-subtle)" },
  ];
}

// ── App → resources grouping (App Map structural view) ────────────────────────
export interface AppGroup {
  app: string;          // "" = unattributed bucket
  resources: CloudResource[];
  byCategory: Record<ResourceCategory, CloudResource[]>;
}

export function groupByApp(resources: CloudResource[]): AppGroup[] {
  const m = new Map<string, CloudResource[]>();
  for (const r of resources) {
    const k = r.app || "";
    const cur = m.get(k);
    if (cur) cur.push(r);
    else m.set(k, [r]);
  }
  const groups: AppGroup[] = [...m.entries()].map(([app, rs]) => {
    const byCategory = {} as Record<ResourceCategory, CloudResource[]>;
    for (const c of RESOURCE_CATEGORIES) byCategory[c] = [];
    for (const r of rs) byCategory[resourceCategory(r.type)].push(r);
    return { app, resources: rs, byCategory };
  });
  // attributed apps first (alpha), unattributed bucket last.
  return groups.sort((a, b) => (a.app === "" ? 1 : b.app === "" ? -1 : a.app.localeCompare(b.app)));
}
