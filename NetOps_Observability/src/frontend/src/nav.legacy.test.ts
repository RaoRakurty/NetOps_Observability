// nav.legacy.test.ts — the RATCHET for the 2026-08 nav redesign (owner tree).
//
// Every pre-redesign hash — all leaves of the old 11-section tree, the
// panels.tsx ghost drill routes, and the 2026-07-10 Explain/Stack legacies —
// must keep resolving to a REAL leaf of the new tree. A redesign regression
// that orphans a saved link (silently falling back to Home when Home is not
// the intended target) fails the build here, not in an operator's bookmarks.
//
// Also ratcheted: sub-item suffixes survive canonicalisation (canonicalHash),
// already-canonical routes are left alone, and every lazy import in nav.tsx
// points at a file that exists (a dead chunk would only surface on click).

import { describe, it, expect } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { resolveRoute, canonicalHash, filteredNav, landingResolves, NAV } from "./nav";

const nav = filteredNav(true); // platform admin sees the full tree

// ── The complete Before → After table ────────────────────────────────────────
// [legacy hash, expected new section, expected new leaf]
const LEGACY: [string, string, string][] = [
  // Dashboards (old section)
  ["#/dashboards", "overview", "home"],
  ["#/dashboards/home", "overview", "home"],
  ["#/dashboards/operations", "overview", "operations"],
  ["#/dashboards/board", "overview", "board"],
  ["#/dashboards/demo", "analytics", "demo"],
  ["#/dashboards/list", "analytics", "dashboards"],
  ["#/dashboards/reports", "analytics", "reports"],
  // Monitoring (old section)
  ["#/monitoring/monitors", "operations", "rules"],
  ["#/monitoring/new", "operations", "new"],
  ["#/monitoring/triggered", "operations", "alerts"],
  ["#/monitoring/maintenance", "operations", "maintenance"],
  ["#/monitoring/quality", "operations", "network-health"],
  ["#/monitoring/events", "explore", "events"],
  ["#/monitoring/incidents", "operations", "incidents"],
  ["#/monitoring/anomalies", "investigate", "findings"],
  ["#/monitoring/correlations", "investigate", "rca"],
  ["#/monitoring/rca-reports", "analytics", "rca-reports"],
  ["#/monitoring/appobs", "operations", "services"],
  ["#/monitoring/reliability", "analytics", "scorecard"],
  // Incident Response (old section)
  ["#/incident", "overview", "home"],
  ["#/incident/overview", "overview", "home"],
  ["#/incident/notifications", "admin", "notifications"],
  ["#/incident/integrations", "admin", "integrations"],
  ["#/incident/rca-ticketing", "admin", "ticketing"],
  // Automation (old section, one leaf, platform-only)
  ["#/automation", "infrastructure", "sot"],
  ["#/automation/sot", "infrastructure", "sot"],
  // Infrastructure (old leaves that moved or renamed)
  ["#/infrastructure/devices", "infrastructure", "devices"],
  ["#/infrastructure/ports", "infrastructure", "interfaces"],
  ["#/infrastructure/nms", "infrastructure", "discovery"],
  ["#/infrastructure/wireless", "infrastructure", "wireless"],
  ["#/infrastructure/monitoring", "analytics", "device-monitoring"],
  ["#/infrastructure/ifperf", "analytics", "interface-performance"],
  ["#/infrastructure/bgpospf", "analytics", "protocols"],
  ["#/infrastructure/troubleshooting", "investigate", "troubleshooting"],
  ["#/infrastructure/topology-canvas", "investigate", "topology"],
  ["#/infrastructure/geomap", "infrastructure", "sites"],
  ["#/infrastructure/flowtrace", "investigate", "flowtrace"],
  ["#/infrastructure/wan-circuits", "investigate", "wan-paths"],
  ["#/infrastructure/tunnels", "investigate", "tunnels"],
  // Security (unchanged ids)
  ["#/security/vuln", "security", "vuln"],
  ["#/security/threat", "security", "threat"],
  ["#/security/compliance", "security", "compliance"],
  // The old top-level data-plane sections
  ["#/metrics", "explore", "metrics"],
  ["#/flows", "explore", "flows"],
  ["#/logs", "explore", "logs"],
  ["#/logs/logs", "explore", "logs"],
  ["#/logs/cloud", "explore", "logs"],
  ["#/logs/saved", "explore", "saved"],
  // Administration (kept ids + the collectors rename)
  ["#/admin/settings", "admin", "settings"],
  ["#/admin/datasources", "admin", "datasources"],
  ["#/admin/collectors", "admin", "sensors"],
  ["#/admin/snmp", "admin", "snmp"],
  ["#/admin/processors", "admin", "processors"],
  ["#/admin/sensitive-data-access", "admin", "sensitive-data-access"],
  ["#/admin/regions", "admin", "regions"],
  ["#/admin/identity", "admin", "identity"],
  ["#/admin/auth", "admin", "auth"],
  ["#/admin/access", "admin", "access"],
  ["#/admin/sessions", "admin", "sessions"],
  ["#/admin/audit", "admin", "audit"],
  ["#/admin/transport", "admin", "transport"],
  ["#/admin/health", "admin", "health"],
  ["#/admin/grafana", "admin", "grafana"],
  ["#/admin/opensearch", "admin", "opensearch"],
  ["#/admin/graphql", "admin", "graphql"],
  ["#/admin/api", "admin", "api"],
  // Explain + Stack (dissolved 2026-07-10)
  ["#/explain", "admin", "access"],
  ["#/explain/access", "admin", "access"],
  ["#/stack", "admin", "health"],
  ["#/stack/health", "admin", "health"],
  ["#/stack/grafana", "admin", "grafana"],
  ["#/stack/opensearch", "admin", "opensearch"],
  ["#/stack/graphql", "admin", "graphql"],
  // panels.tsx ghost drill routes (never real sections — they used to silently
  // land on Home; now they land where the panel meant to send the operator)
  ["#/explore/metrics", "explore", "metrics"],
  ["#/explore/flows", "explore", "flows"],
  ["#/alerts/active", "operations", "alerts"],
  ["#/alerts/incidents", "operations", "incidents"],
  ["#/topology/map", "infrastructure", "sites"],
  ["#/topology/tunnels", "investigate", "tunnels"],
  ["#/topology-canvas", "investigate", "topology"],
];

describe("legacy-hash ratchet — every pre-redesign route resolves", () => {
  it.each(LEGACY)("%s → %s/%s", (hash, section, leaf) => {
    const r = resolveRoute(hash, nav);
    expect(r.section.id).toBe(section);
    expect(r.leaf?.id).toBe(leaf);
  });

  it("never falls back to Home unless Home IS the target", () => {
    for (const [hash, section, leaf] of LEGACY) {
      const r = resolveRoute(hash, nav);
      if (!(section === "overview" && leaf === "home")) {
        expect(`${hash} → ${r.section.id}/${r.leaf?.id}`).not.toBe(`${hash} → overview/home`);
      }
    }
  });

  it("keeps saved legacy landings valid (no silent fallback)", () => {
    // Every OLD landing option an admin could have configured pre-redesign.
    for (const h of [
      "#/incident/overview",
      "#/dashboards/home",
      "#/monitoring/correlations",
      "#/monitoring/incidents",
      "#/infrastructure/topology-canvas",
    ]) {
      expect(landingResolves(h, nav), h).toBe(true);
    }
  });
});

describe("canonicalHash — suffix + query preservation", () => {
  it("preserves sub-item suffixes across the rename", () => {
    expect(canonicalHash("#/monitoring/appobs/investigations")).toBe("#/operations/services/investigations");
    expect(canonicalHash("#/logs/cloud")).toBe("#/explore/logs/cloud");
    expect(canonicalHash("#/infrastructure/geomap")).toBe("#/infrastructure/sites/map");
    expect(canonicalHash("#/infrastructure/nms")).toBe("#/infrastructure/discovery/nms");
  });

  it("preserves ?query deep-link params", () => {
    expect(canonicalHash("#/monitoring/correlations?id=abc")).toBe("#/investigate/rca?id=abc");
    expect(canonicalHash("#/logs/cloud?family=dns")).toBe("#/explore/logs/cloud?family=dns");
  });

  it("leaves canonical routes and resource URLs alone", () => {
    expect(canonicalHash("#/investigate/rca?id=abc")).toBeNull();
    expect(canonicalHash("#/admin/api/token")).toBeNull();
    expect(canonicalHash("#/infrastructure/devices")).toBeNull();
    expect(canonicalHash("#/resource/device/edge-1")).toBeNull();
    expect(canonicalHash("#/")).toBeNull();
    expect(canonicalHash("")).toBeNull();
  });
});

describe("new tree shape (owner tree, 2026-08)", () => {
  it("has exactly the owner's sections in order", () => {
    expect(NAV.map((s) => s.id)).toEqual([
      "overview", "operations", "investigate", "infrastructure",
      "explore", "security", "analytics", "copilot", "admin",
    ]);
  });

  it("gates carried verbatim: platform-only leaves stay invisible to tenants", () => {
    const tenantNav = filteredNav(false);
    const ids = (section: string) =>
      (tenantNav.find((s) => s.id === section)?.children ?? []).map((l) => l.id);
    expect(ids("infrastructure")).not.toContain("sot");
    for (const gated of ["sensors", "sessions", "regions", "health", "grafana", "opensearch", "graphql"]) {
      expect(ids("admin")).not.toContain(gated);
    }
    // ...and legacy deep links to them cannot resolve onto the gated leaf.
    expect(resolveRoute("#/admin/collectors", tenantNav).leaf?.id).not.toBe("sensors");
    expect(resolveRoute("#/automation/sot", tenantNav).leaf?.id).not.toBe("sot");
  });
});

describe("nav.tsx lazy imports all exist (no dead chunks)", () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const src = readFileSync(resolve(here, "nav.tsx"), "utf8");
  const specs = [...src.matchAll(/import\("(\.[^"]+)"\)/g)].map((m) => m[1]);

  it("found the lazy import list", () => {
    expect(specs.length).toBeGreaterThan(20);
  });

  it.each(specs.map((s) => [s]))("%s resolves to a file", (spec) => {
    const base = resolve(here, spec);
    const candidates = [base, `${base}.tsx`, `${base}.ts`, resolve(base, "index.tsx"), resolve(base, "index.ts")];
    expect(candidates.some((c) => existsSync(c)), `missing module: ${spec}`).toBe(true);
  });
});
