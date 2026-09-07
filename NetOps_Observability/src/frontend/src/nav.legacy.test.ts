// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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
  // The pre-redesign Service View. Its cloud half is Operations → Cloud; its
  // application half is Infrastructure → Applications (owner IA, 2026-09-07).
  ["#/monitoring/appobs", "operations", "cloud"],
  ["#/monitoring/appobs/services", "infrastructure", "applications"],
  ["#/monitoring/appobs/catalog", "infrastructure", "applications"],
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
  // Topology's pre-move home — old bookmarks/panel drills must land on the
  // canvas, not silently fall back to the Devices inventory.
  ["#/infrastructure/topology", "investigate", "topology"],
  ["#/infrastructure/geomap", "infrastructure", "sites"],
  ["#/infrastructure/flowtrace", "investigate", "flowtrace"],
  ["#/infrastructure/wan-circuits", "investigate", "wan-paths"],
  ["#/infrastructure/tunnels", "investigate", "tunnels"],
  // Security (unchanged ids)
  ["#/security/vuln", "security", "vuln"],
  ["#/security/threat", "security", "threat"],
  ["#/security/compliance", "security", "compliance"],
  // ── Services → Cloud + Applications (owner IA, 2026-09-07) ────────────────
  // The 2026-08 leaf "operations/services" carried both halves; every one of its
  // routes must land on the half that now owns it.
  ["#/operations/services", "operations", "cloud"],
  ["#/operations/services/overview", "operations", "cloud"],
  ["#/operations/services/resources", "operations", "cloud"],
  ["#/operations/services/investigations", "operations", "cloud"],
  ["#/operations/services/security", "operations", "cloud"],
  ["#/operations/services/datasources", "operations", "cloud"],
  ["#/operations/services/settings", "operations", "cloud"],
  ["#/operations/services/accounts", "operations", "cloud"],
  ["#/operations/services/services", "infrastructure", "applications"],
  ["#/operations/services/applications", "infrastructure", "applications"],
  ["#/operations/services/catalog", "infrastructure", "applications"],
  ["#/operations/services/registries", "infrastructure", "applications"],
  ["#/operations/services/map", "infrastructure", "applications"],
  ["#/operations/services/appmap", "infrastructure", "applications"],
  // The old top-level data-plane sections
  ["#/metrics", "explore", "metrics"],
  ["#/flows", "explore", "flows"],
  ["#/logs", "explore", "logs"],
  ["#/logs/logs", "explore", "logs"],
  ["#/logs/cloud", "explore", "logs"],
  ["#/logs/saved", "explore", "saved"],
  // Administration — the leaves that STAYED tenant-level (kept ids + the
  // collectors rename)
  ["#/admin/settings", "admin", "settings"],
  ["#/admin/datasources", "admin", "datasources"],
  ["#/admin/collectors", "admin", "sensors"],
  ["#/admin/snmp", "admin", "snmp"],
  ["#/admin/processors", "admin", "processors"],
  ["#/admin/sensitive-data-access", "admin", "sensitive-data-access"],
  ["#/admin/telemetry-coverage", "admin", "telemetry-coverage"],
  ["#/admin/identity", "admin", "identity"],
  ["#/admin/access", "admin", "access"],
  ["#/admin/sessions", "admin", "sessions"],
  ["#/admin/audit", "admin", "audit"],
  ["#/admin/transport", "admin", "transport"],
  ["#/admin/integrations", "admin", "integrations"],
  ["#/admin/notifications", "admin", "notifications"],
  ["#/admin/ticketing", "admin", "ticketing"],
  ["#/admin/api", "admin", "api"],
  // Administration → Platform (owner IA, 2026-09-05). Every provider-level
  // leaf kept its id and changed section, so an old bookmark lands on the
  // SAME page at its new address.
  ["#/admin/auth", "platform", "auth"],
  ["#/admin/data-protection", "platform", "data-protection"],
  // Licence moved to Platform in the 2026-09-05 IA and came BACK the same day,
  // when GET /api/system/licence became requireAdmin with a tenant projection.
  ["#/admin/licence", "admin", "licence"],
  ["#/platform/licence", "admin", "licence"],
  ["#/admin/regions", "platform", "regions"],
  ["#/admin/health", "platform", "health"],
  ["#/admin/grafana", "platform", "grafana"],
  ["#/admin/opensearch", "platform", "opensearch"],
  ["#/admin/graphql", "platform", "graphql"],
  // The debugger GUI's agreed route id names its group as well as its leaf;
  // the two-part router has no room for that, so it is aliased.
  ["#/platform/tools", "platform", "health"],
  ["#/platform/tools/pipeline-debugger", "platform", "pipeline-debugger"],
  // Explain + Stack (dissolved 2026-07-10; Stack's four leaves moved on to
  // Platform on 2026-09-05, so a pre-2026-07 bookmark makes BOTH hops)
  ["#/explain", "admin", "access"],
  ["#/explain/access", "admin", "access"],
  ["#/stack", "platform", "health"],
  ["#/stack/health", "platform", "health"],
  ["#/stack/grafana", "platform", "grafana"],
  ["#/stack/opensearch", "platform", "opensearch"],
  ["#/stack/graphql", "platform", "graphql"],
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
    expect(canonicalHash("#/monitoring/appobs/investigations")).toBe("#/operations/cloud/investigations");
    expect(canonicalHash("#/logs/cloud")).toBe("#/explore/logs/cloud");
    expect(canonicalHash("#/infrastructure/geomap")).toBe("#/infrastructure/sites/map");
    expect(canonicalHash("#/infrastructure/nms")).toBe("#/infrastructure/discovery/nms");
  });

  it("preserves ?query deep-link params", () => {
    expect(canonicalHash("#/monitoring/correlations?id=abc")).toBe("#/investigate/rca?id=abc");
    expect(canonicalHash("#/logs/cloud?family=dns")).toBe("#/explore/logs/cloud?family=dns");
  });

  it("rewrites the Administration → Platform moves, suffix and query intact", () => {
    expect(canonicalHash("#/admin/health")).toBe("#/platform/health");
    expect(canonicalHash("#/platform/licence")).toBe("#/admin/licence");
    expect(canonicalHash("#/admin/data-protection")).toBe("#/platform/data-protection");
    expect(canonicalHash("#/admin/auth?tab=oidc")).toBe("#/platform/auth?tab=oidc");
    expect(canonicalHash("#/stack/opensearch")).toBe("#/platform/opensearch");
    // The three-segment alias consumes all three segments — no stray tail.
    expect(canonicalHash("#/platform/tools/pipeline-debugger")).toBe("#/platform/pipeline-debugger");
  });

  it("leaves canonical routes and resource URLs alone", () => {
    expect(canonicalHash("#/investigate/rca?id=abc")).toBeNull();
    expect(canonicalHash("#/admin/api/token")).toBeNull();
    expect(canonicalHash("#/admin/access")).toBeNull();
    expect(canonicalHash("#/admin/licence")).toBeNull();
    expect(canonicalHash("#/infrastructure/devices")).toBeNull();
    expect(canonicalHash("#/resource/device/edge-1")).toBeNull();
    expect(canonicalHash("#/")).toBeNull();
    expect(canonicalHash("")).toBeNull();
  });
});

// ── Services → Cloud + Applications (owner IA, 2026-09-07) ───────────────────
//
// The split is by WHAT FEEDS THE VIEW: Operations → Cloud holds what the cloud
// connectors feed, Infrastructure → Applications holds the provider-neutral
// application layer. Resolving to the right LEAF is not enough — the third
// segment names the sub-view, and one id CHANGED MEANING in the move ("catalog"
// was the business-service catalogue, and is now the application list), so every
// old sub-view is asserted here as a full canonical hash.
describe("Services split — every old sub-view lands on its new home", () => {
  const CASES: [string, string][] = [
    // cloud half — the tab ids are unchanged under the renamed leaf
    ["#/operations/services", "#/operations/cloud"],
    ["#/operations/services/overview", "#/operations/cloud/overview"],
    ["#/operations/services/resources", "#/operations/cloud/resources"],
    ["#/operations/services/investigations", "#/operations/cloud/investigations"],
    ["#/operations/services/security", "#/operations/cloud/security"],
    ["#/operations/services/datasources", "#/operations/cloud/datasources"],
    ["#/operations/services/settings", "#/operations/cloud/settings"],
    ["#/operations/services/accounts", "#/operations/cloud/accounts"],
    // application half — including the two ids that used to sit under a
    // "Services → Services" sub-tab nobody could name out loud
    ["#/operations/services/services", "#/infrastructure/applications/catalog"],
    ["#/operations/services/applications", "#/infrastructure/applications/catalog"],
    ["#/operations/services/registries", "#/infrastructure/applications/registries"],
    ["#/operations/services/map", "#/infrastructure/applications/appmap"],
    ["#/operations/services/appmap", "#/infrastructure/applications/appmap"],
    // the id that changed meaning: old "catalog" = business services
    ["#/operations/services/catalog", "#/infrastructure/applications/business"],
    // …and the same set one hop further back, from the pre-2026-08 Service View
    ["#/monitoring/appobs", "#/operations/cloud"],
    ["#/monitoring/appobs/overview", "#/operations/cloud/overview"],
    ["#/monitoring/appobs/services", "#/infrastructure/applications/catalog"],
    ["#/monitoring/appobs/applications", "#/infrastructure/applications/catalog"],
    ["#/monitoring/appobs/catalog", "#/infrastructure/applications/business"],
    ["#/monitoring/appobs/registries", "#/infrastructure/applications/registries"],
    ["#/monitoring/appobs/map", "#/infrastructure/applications/appmap"],
    ["#/monitoring/appobs/appmap", "#/infrastructure/applications/appmap"],
  ];

  it.each(CASES)("%s → %s", (from, to) => {
    expect(canonicalHash(from)).toBe(to);
  });

  it("carries the deep-link query through the split", () => {
    expect(canonicalHash("#/operations/services?provider=aws&range=7d"))
      .toBe("#/operations/cloud?provider=aws&range=7d");
    expect(canonicalHash("#/operations/services/investigations?inv=obj-1"))
      .toBe("#/operations/cloud/investigations?inv=obj-1");
    expect(canonicalHash("#/monitoring/appobs/catalog?q=checkout"))
      .toBe("#/infrastructure/applications/business?q=checkout");
  });

  it("the unified-search app href still resolves (search_unified.go)", () => {
    // src/backend/search_unified.go answers app hits with this legacy href.
    expect(canonicalHash("#/monitoring/appobs/services"))
      .toBe("#/infrastructure/applications/catalog");
  });

  it("both new routes are canonical — no further rewrite", () => {
    expect(canonicalHash("#/operations/cloud")).toBeNull();
    expect(canonicalHash("#/operations/cloud/resources")).toBeNull();
    expect(canonicalHash("#/infrastructure/applications")).toBeNull();
    expect(canonicalHash("#/infrastructure/applications/catalog")).toBeNull();
  });

  it("the two entries carry the owner's sub-items, and no 'Services / Services'", () => {
    const leaf = (sec: string, id: string) =>
      NAV.find((s) => s.id === sec)!.children!.find((l) => l.id === id)!;
    const cloud = leaf("operations", "cloud");
    expect(cloud.label).toBe("Cloud");
    expect((cloud.subItems ?? []).map((i) => i.id)).toEqual([
      "overview", "resources", "logs", "datasources", "security", "investigations", "settings",
    ]);
    // Cloud Logs moved in from Explore → Logs and deep-links back to the plane.
    expect((cloud.subItems ?? []).find((i) => i.id === "logs")?.route).toBe("explore/logs/cloud");
    expect(NAV.find((s) => s.id === "explore")!.children!.find((l) => l.id === "logs")!.subItems)
      .toBeUndefined();

    const apps = leaf("infrastructure", "applications");
    expect(apps.label).toBe("Applications");
    expect((apps.subItems ?? []).map((i) => i.id)).toEqual([
      "catalog", "appmap", "registries", "business",
    ]);
    // Applications sits BESIDE Devices — same question, different inventory.
    const infraIds = NAV.find((s) => s.id === "infrastructure")!.children!.map((l) => l.id);
    expect(infraIds.indexOf("applications")).toBe(infraIds.indexOf("devices") + 1);
    // The repetition the split existed to kill.
    for (const l of [cloud, apps]) {
      for (const sub of l.subItems ?? []) expect(sub.label).not.toBe(l.label);
    }
    // The old leaf id is gone from both sections.
    expect(NAV.find((s) => s.id === "operations")!.children!.map((l) => l.id)).not.toContain("services");
  });
});

describe("new tree shape (owner tree, 2026-08)", () => {
  it("has exactly the owner's sections in order", () => {
    // 2026-09-05: "platform" joins the tail — ONE provider-only section, sitting
    // beneath Administration in the rail's foot zone.
    expect(NAV.map((s) => s.id)).toEqual([
      "overview", "operations", "investigate", "infrastructure",
      "explore", "security", "analytics", "copilot", "admin", "platform",
    ]);
  });

  it("gates carried verbatim: platform-only leaves stay invisible to tenants", () => {
    const tenantNav = filteredNav(false);
    const ids = (section: string) =>
      (tenantNav.find((s) => s.id === section)?.children ?? []).map((l) => l.id);
    expect(ids("infrastructure")).not.toContain("sot");
    // Sensors is the ONE leaf left platform-stamped inside the tenant-level
    // Administration section: /api/collectors and /api/discovery/config are
    // requireCrossTenant, but the Data sources group is where the owner put it.
    expect(ids("admin")).not.toContain("sensors");
    // The rest of the provider-level set left Administration entirely — the
    // Platform section carries the gate now, so a tenant admin sees no section.
    expect(tenantNav.find((s) => s.id === "platform")).toBeUndefined();
    for (const moved of ["auth", "data-protection", "regions", "health", "grafana", "opensearch", "graphql"]) {
      expect(ids("admin")).not.toContain(moved);
    }
    // Sessions is NO LONGER platform-stamped (2026-09-05): handleSessions is
    // requireAdmin and filters by sameTenant(), so a tenant admin legitimately
    // sees its own tenant's live sessions.
    expect(ids("admin")).toContain("sessions");
    // Licence is tenant-level too: the read is requireAdmin and answers the
    // tenant its own entitlements, usage and ceilings.
    expect(ids("admin")).toContain("licence");
    // ...and legacy deep links to gated leaves cannot resolve onto them.
    expect(resolveRoute("#/admin/collectors", tenantNav).leaf?.id).not.toBe("sensors");
    expect(resolveRoute("#/automation/sot", tenantNav).leaf?.id).not.toBe("sot");
  });
});

describe("FrontPage drill links stay routable", () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const src = readFileSync(resolve(here, "pages/FrontPage.tsx"), "utf8");

  it("never links the moved infrastructure/topology route (canvas lives at investigate/topology)", () => {
    // 'infrastructure/topology' resolves to Infrastructure's FIRST leaf (the
    // Devices inventory) with no error — a silent mis-drill. The Impact panel
    // and KPI cells must point at the canvas's real home.
    expect(src).not.toContain("infrastructure/topology");
    expect(src).toContain("investigate/topology");
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
