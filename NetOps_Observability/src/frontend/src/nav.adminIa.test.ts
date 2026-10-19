// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// nav.adminIa.test.ts — the ratchet for the Administration / Platform split
// (owner IA, 2026-09-05; design note: docs/design/ADMIN_IA_2026-09-05.md).
//
// THE RULE THIS FILE ENFORCES. There is ONE provider section, `platform`, and
// membership of it is decided by the BACKEND ROUTE GATE, not by topic:
//
//   requirePlatformAdmin / requireCrossTenant  →  Platform      (provider-only)
//   requirePerm / requireAdmin + tenant filter →  Administration (tenant-level)
//
// The gate for every leaf is named in GATES below, quoting the handler it was
// read from. If a page's gate changes, this table is the place that has to be
// re-read against the backend — a placement nobody re-checked is exactly how a
// tenant-scoped page ends up hidden from tenants, or a platform-global one ends
// up offered to them as dead tiles and 403'd saves.

import { describe, it, expect } from "vitest";
import { NAV, filteredNav, landingResolves, resolveRoute } from "./nav";

const providerNav = filteredNav(true);
const tenantNav = filteredNav(false);
const platform = NAV.find((s) => s.id === "platform")!;
const admin = NAV.find((s) => s.id === "admin")!;
const leafIds = (s?: { children?: { id: string }[] }) => (s?.children ?? []).map((l) => l.id);
const groupIds = (s: { children?: { id: string; group?: string }[] }, g: string) =>
  (s.children ?? []).filter((l) => l.group === g).map((l) => l.id);

// Where each Administration/Platform leaf's authority actually lives. "platform"
// = every route behind the page is requirePlatformAdmin or requireCrossTenant;
// "tenant" = requirePerm/requireAdmin with a tenant filter.
const GATES: Record<string, { scope: "platform" | "tenant"; gate: string }> = {
  // ── Platform ───────────────────────────────────────────────────────────────
  auth: { scope: "platform", gate: "oidc_config.go / auth_config.go / token_policy.go → requirePlatformAdmin" },
  "data-protection": { scope: "platform", gate: "internal/dataprotect → dataProtectGate → requirePlatformAdmin" },
  health: { scope: "platform", gate: "stack_health.go handleStackHealth → requireCrossTenant" },
  grafana: { scope: "platform", gate: "nginx auth_request → auth.go handleOSDGate → isPlatformOwner" },
  opensearch: { scope: "platform", gate: "nginx auth_request → auth.go handleOSDGate → isPlatformOwner" },
  regions: { scope: "platform", gate: "region_router.go handleRegionTopology → requireCrossTenant" },
  // The one deliberate over-restriction: /api/graphql is requirePerm
  // (infrastructure, read), so the UI is STRICTER than the route. Fail-closed
  // is the safe direction; unhiding it would be a new exposure.
  graphql: { scope: "platform", gate: "graphql.go handleGraphQL → requirePerm(infrastructure, read); UI kept provider-only (fail-closed)" },
  "pipeline-debugger": { scope: "platform", gate: "internal/pipedebug/http.go via debugAuthz → requirePlatformAdmin, on all five /api/debug/* routes" },
  features: { scope: "platform", gate: "feature_flags.go handlePlatformFeatures / handlePlatformRestart → requirePlatformAdmin" },
  quarantine: { scope: "platform", gate: "pipeline_processors.go handleQuarantineList → requirePlatformAdmin (the index holds events attributable to NO tenant)" },
  // ── Administration ─────────────────────────────────────────────────────────
  access: { scope: "tenant", gate: "access_explain.go handleAccessExplain → requireAdmin" },
  sessions: { scope: "tenant", gate: "session_handlers.go handleSessions → requireAdmin + sameTenant() filter" },
  audit: { scope: "tenant", gate: "audit.go handleAudit → requireAdmin" },
  transport: { scope: "tenant", gate: "/api/security/transport-posture → requireAdmin (export alone is requirePlatformAdmin)" },
  processors: { scope: "tenant", gate: "pipeline_processors.go handleProcessors → requireAdmin + principalTenant" },
  "sensitive-data-access": { scope: "tenant", gate: "pipeline_processors.go unseal routes → requirePerm(sensitive_data, admin)" },
  identity: { scope: "tenant", gate: "identity_handlers.go → requireAdmin (role/tenant/org writes alone escalate to requirePlatformAdmin)" },
  api: { scope: "tenant", gate: "identity_handlers.go apikeys → requireAdmin" },
  settings: { scope: "tenant", gate: "tenant_display.go → requireAdmin" },
  // Licence moved BACK to Administration on 2026-09-05, when the read split
  // shipped: GET is licenceReadGate → requireAdmin + principalTenant and
  // answers a per-tenant projection. PUT/DELETE stay requirePlatformAdmin, and
  // the page hides those controls by the PAYLOAD's scope rather than 403ing —
  // a mixed-verb page whose READ decides its placement (design note §5.1a).
  licence: { scope: "tenant", gate: "internal/licence/api.go GET → licenceReadGate → requireAdmin + principalTenant (tenant projection); PUT/DELETE alone → licenceGate → requirePlatformAdmin" },
  integrations: { scope: "tenant", gate: "integrations_http.go → requireAdmin, keyed by itsmKey(tenant)" },
  // RCA Tickets (owner 2026-10-18) merged Ticketing & Automation and Ticket
  // Delivery into one flow; both halves were tenant-scoped.
  ticketing: { scope: "tenant", gate: "ticketing_http.go policies → requirePerm(administration, read|write); handleTicketsOutbox/handleTicketsAudit → requirePerm(infrastructure, read) + principalTenant; integrations_http.go handleIntegrationReconcile → requireAdmin on the caller's own tenant" },
  "network-context": { scope: "tenant", gate: "ai_handlers.go handleAIContext → requirePerm(administration, read/write/admin) + ai.context.author + principalTenant (a Global view must choose a workspace); approval needs a second person (internal/orgcontext)" },
  // Discovery (owner 2026-10-18) is ONE tenant-visible leaf over five
  // sections, each keeping the gate it had as a leaf (MIXED):
  //   snmp      → snmp_profiles.go read → requirePerm(infrastructure, read);
  //               writes escalate to requirePlatformAdmin
  //   scan      → snmp_discovery.go handleDiscoveryConfig → requireCrossTenant;
  //               SubnetDiscovery audience-gates the card on platform_admin and
  //               shows tenants where their devices and credentials live
  //   sensors   → main.go handleCollectors → requireCrossTenant, switches →
  //               requirePlatformAdmin: the hub neither renders nor fetches it
  //               for a tenant (DiscoveryHub.test.tsx) and the sub-item is
  //               platformOnly
  //   coverage  → /api/devices → requirePerm(infrastructure, read)
  //   telemetry → /api/telemetry/unrecognized → requirePerm(infrastructure,
  //               read); the parser-stats half alone is requirePlatformAdmin
  discovery: { scope: "tenant", gate: "five sections, each its former leaf gate; Sensors platform-only inside the page (MIXED)" },
  // Notifications mixes: the channel config is platform-global, the contact
  // points are tenant-scoped. It stays tenant-level because the tenant half is
  // the operator surface; the platform half already refuses a tenant admin.
  notifications: { scope: "tenant", gate: "notify_config.go channels → requirePlatformAdmin; contactpoints.go → requireAdmin (MIXED)" },
};

describe("Platform is ONE provider-only section", () => {
  it("exists, is platform-only at the SECTION level, and is pinned to the foot", () => {
    expect(platform).toBeDefined();
    expect(platform.platformOnly).toBe(true);
    expect(platform.footer).toBe(true);
    expect(platform.label).toBe("Platform");
  });

  it("carries the Security and Tools groups the owner asked for, plus Configuration (Features, tracker 348)", () => {
    const groups = [...new Set((platform.children ?? []).map((l) => l.group).filter(Boolean))];
    expect(groups).toEqual(["Security", "Configuration", "Tools"]);
    expect(groupIds(platform, "Configuration")).toEqual(["features"]);
  });

  it("Security holds the provider-level security plumbing", () => {
    expect(groupIds(platform, "Security")).toEqual(["auth", "data-protection"]);
  });

  it("Tools holds the provider's instruments, stack health first", () => {
    const tools = groupIds(platform, "Tools");
    expect(tools.slice(0, 4)).toEqual(["health", "grafana", "opensearch", "pipeline-debugger"]);
    expect(tools).toContain("regions");
    expect(tools).toContain("graphql");
  });

  it("carries the Pipeline Debugger at the route id the CLI guide names", () => {
    // The agreed id is platform/tools/pipeline-debugger; the two-part router
    // resolves it through the three-segment alias onto this leaf.
    expect(resolveRoute("#/platform/tools/pipeline-debugger", providerNav)).toMatchObject({
      section: { id: "platform" },
      leaf: { id: "pipeline-debugger" },
    });
    expect(resolveRoute("#/platform/pipeline-debugger", providerNav).leaf?.id).toBe("pipeline-debugger");
    expect(landingResolves("#/platform/tools/pipeline-debugger", providerNav)).toBe(true);
  });

  it("no longer carries Licence — its read is tenant-level since 2026-09-05", () => {
    expect(leafIds(platform)).not.toContain("licence");
    expect(leafIds(admin)).toContain("licence");
    // Every leaf left in Platform is grouped: the section opens on Security.
    expect(platform.children?.[0]?.group).toBe("Security");
  });

  it("no leaf re-states the gate: the SECTION carries it", () => {
    for (const l of platform.children ?? []) {
      expect(l.platformOnly, `${l.id} should not re-stamp platformOnly`).toBeUndefined();
    }
  });
});

describe("every item sits under the gate the design note states", () => {
  it("Platform holds only provider-level items", () => {
    for (const id of leafIds(platform)) {
      const g = GATES[id];
      expect(g, `no gate recorded for platform/${id}`).toBeDefined();
      expect(g.scope, `platform/${id}: ${g.gate}`).toBe("platform");
    }
  });

  it("Administration holds tenant-level items, with Sensors leaf-stamped", () => {
    for (const l of admin.children ?? []) {
      const g = GATES[l.id];
      expect(g, `no gate recorded for admin/${l.id}`).toBeDefined();
      if (g.scope === "platform") {
        // A provider-level route inside the tenant section MUST carry the leaf
        // stamp, or a tenant admin is handed a page that 403s.
        expect(l.platformOnly, `admin/${l.id} is ${g.gate} — it must be platformOnly`).toBe(true);
      } else {
        expect(l.platformOnly, `admin/${l.id} is tenant-scoped (${g.gate}) — it must NOT be platformOnly`).toBeUndefined();
      }
    }
  });
});

describe("what each principal sees", () => {
  it("the provider sees Platform, with Security and Tools intact", () => {
    const p = providerNav.find((s) => s.id === "platform");
    expect(p).toBeDefined();
    expect(groupIds(p!, "Security")).toContain("auth");
    expect(groupIds(p!, "Tools")).toContain("health");
  });

  it("a tenant administrator sees no Platform section at all", () => {
    expect(tenantNav.find((s) => s.id === "platform")).toBeUndefined();
    expect(tenantNav.map((s) => s.id)).toContain("admin");
  });

  it("a tenant administrator keeps every tenant-level Administration page", () => {
    const ids = leafIds(tenantNav.find((s) => s.id === "admin"));
    for (const id of Object.keys(GATES)) {
      if (GATES[id].scope !== "tenant") continue;
      if (!leafIds(admin).includes(id)) continue;
      expect(ids, `admin/${id} is tenant-scoped and must stay visible`).toContain(id);
    }
  });

  it("a tenant administrator cannot reach a Platform page by hash", () => {
    for (const id of leafIds(platform)) {
      expect(resolveRoute(`#/platform/${id}`, tenantNav).section.id).not.toBe("platform");
      expect(landingResolves(`#/platform/${id}`, tenantNav)).toBe(false);
    }
  });
});

describe("Administration groups (owner IA, 2026-09-05)", () => {
  it("Data sources is ONE Discovery leaf, with its sections as sub-items in setup order", () => {
    expect(groupIds(admin, "Data sources")).toEqual(["discovery"]);
    const leaf = (admin.children ?? []).find((l) => l.id === "discovery")!;
    expect(leaf.label).toBe("Discovery");
    expect((leaf.subItems ?? []).map((x) => x.id)).toEqual(["snmp", "scan", "sensors", "coverage", "telemetry"]);
    expect(resolveRoute("#/admin/discovery", providerNav).leaf?.id).toBe("discovery");
    // Tenants keep the page (each section gates itself)…
    expect(leafIds(tenantNav.find((s) => s.id === "admin"))).toContain("discovery");
  });

  it("the platform-only Sensors sub-item is never offered to a tenant", () => {
    const sub = (nav: typeof providerNav) =>
      (nav.find((s) => s.id === "admin")?.children ?? []).find((l) => l.id === "discovery")?.subItems?.map((x) => x.id) ?? [];
    expect(sub(providerNav)).toContain("sensors");
    expect(sub(tenantNav)).not.toContain("sensors");
    expect(sub(tenantNav)).toEqual(["snmp", "scan", "coverage", "telemetry"]);
  });

  it("Processors and Sensitive Data Access are one group", () => {
    expect(groupIds(admin, "Data handling")).toEqual(["processors", "sensitive-data-access"]);
  });

  it("the old Platform / Platform Security groups are gone from Administration", () => {
    const groups = (admin.children ?? []).map((l) => l.group);
    expect(groups).not.toContain("Platform");
    expect(groups).not.toContain("Platform Security");
    expect(groups).not.toContain("Data Collection");
  });

  it("People & access and Audit & security are tenant-level throughout", () => {
    expect(groupIds(admin, "People & access")).toEqual(["identity", "api", "sessions"]);
    expect(groupIds(admin, "Audit & security")).toEqual(["access", "audit", "transport"]);
    for (const id of [...groupIds(admin, "People & access"), ...groupIds(admin, "Audit & security")]) {
      expect(GATES[id].scope).toBe("tenant");
    }
  });

  // Owner IA 2026-10-18 (Administration phase 4): seven groups in SETUP order,
  // every leaf grouped, so the flyout reads top to bottom as a setup path.
  it("groups appear in setup order and every leaf is grouped", () => {
    const groups = [...new Set((admin.children ?? []).map((l) => l.group))];
    expect(groups).toEqual([
      "Data sources", "Incident response", "Data handling", "Iris", "People & access", "Audit & security", "Workspace",
    ]);
    expect((admin.children ?? []).every((l) => !!l.group)).toBe(true);
    expect(groupIds(admin, "Incident response")).toEqual(["integrations", "notifications", "ticketing"]);
    expect(groupIds(admin, "Workspace")).toEqual(["settings", "licence"]);
  });

  it("the retired group names are gone", () => {
    const groups = (admin.children ?? []).map((l) => l.group);
    for (const old of ["Access & Audit", "Incident Response"]) expect(groups).not.toContain(old);
  });
});

describe("redirects — no saved link is orphaned by the move", () => {
  const MOVED: [string, string][] = [
    ["#/admin/auth", "auth"],
    ["#/admin/data-protection", "data-protection"],
    ["#/admin/regions", "regions"],
    ["#/admin/health", "health"],
    ["#/admin/grafana", "grafana"],
    ["#/admin/opensearch", "opensearch"],
    ["#/admin/graphql", "graphql"],
  ];

  it("#/platform/licence → admin/licence — the one leaf that moved BACK", () => {
    expect(resolveRoute("#/platform/licence", providerNav)).toMatchObject({
      section: { id: "admin" },
      leaf: { id: "licence" },
    });
    // A tenant admin, who never saw the Platform section, reaches it too.
    expect(resolveRoute("#/admin/licence", tenantNav)).toMatchObject({
      section: { id: "admin" },
      leaf: { id: "licence" },
    });
    expect(landingResolves("#/platform/licence", providerNav)).toBe(true);
  });

  it.each(MOVED)("%s → platform/%s", (hash, leaf) => {
    expect(resolveRoute(hash, providerNav)).toMatchObject({
      section: { id: "platform" },
      leaf: { id: leaf },
    });
    // A landing configured at the old address stays valid instead of silently
    // dropping the operator on Home.
    expect(landingResolves(hash, providerNav)).toBe(true);
  });

  it("keeps the tenant-level leaves exactly where they were", () => {
    for (const id of ["access", "sessions", "audit", "transport", "processors", "sensitive-data-access", "identity", "api", "settings"]) {
      expect(resolveRoute(`#/admin/${id}`, providerNav)).toMatchObject({
        section: { id: "admin" },
        leaf: { id },
      });
    }
  });
});
