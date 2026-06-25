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
  if (/instance|task|function|lambda|ecs|eks|container|virtualmachine|\bvm\b|compute|pod|node|web\/sites|appservice/.test(t)) return "Compute";
  if (/metric|log|flow|trace|cloudwatch|monitor/.test(t)) return "Observability";
  return "Other";
}

export const RESOURCE_CATEGORIES: ResourceCategory[] = ["Compute", "Network", "Data", "Observability", "Other"];

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
