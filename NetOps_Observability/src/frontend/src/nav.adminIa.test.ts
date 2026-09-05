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
  licence: { scope: "platform", gate: "internal/licence/api.go Handle → licenceGate → requirePlatformAdmin, before the GET/PUT/DELETE switch" },
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
  // ── Administration ─────────────────────────────────────────────────────────
  access: { scope: "tenant", gate: "access_explain.go handleAccessExplain → requireAdmin" },
  sessions: { scope: "tenant", gate: "session_handlers.go handleSessions → requireAdmin + sameTenant() filter" },
  audit: { scope: "tenant", gate: "audit.go handleAudit → requireAdmin" },
  transport: { scope: "tenant", gate: "/api/security/transport-posture → requireAdmin (export alone is requirePlatformAdmin)" },
  processors: { scope: "tenant", gate: "pipeline_processors.go handleProcessors → requireAdmin + principalTenant" },
  "sensitive-data-access": { scope: "tenant", gate: "pipeline_processors.go unseal routes → requirePerm(sensitive_data, admin)" },
  "telemetry-coverage": { scope: "tenant", gate: "/api/telemetry/unrecognized → requirePerm(infrastructure, read); the parser-stats half alone is requirePlatformAdmin" },
  identity: { scope: "tenant", gate: "identity_handlers.go → requireAdmin (role/tenant/org writes alone escalate to requirePlatformAdmin)" },
  api: { scope: "tenant", gate: "identity_handlers.go apikeys → requireAdmin" },
  settings: { scope: "tenant", gate: "tenant_display.go → requireAdmin" },
  integrations: { scope: "tenant", gate: "integrations_http.go → requireAdmin, keyed by itsmKey(tenant)" },
  ticketing: { scope: "tenant", gate: "ticketing_http.go → requirePerm(administration, read|write)" },
  datasources: { scope: "tenant", gate: "/api/devices → requirePerm(infrastructure, read)" },
  snmp: { scope: "tenant", gate: "snmp_profiles.go read → requirePerm(infrastructure, read); writes escalate to requirePlatformAdmin" },
  // Sensors is the ONE leaf that keeps a leaf-level platform stamp inside the
  // tenant-level section: the owner put it under Data sources, and the backend
  // is requireCrossTenant, so the leaf carries `platformOnly` instead.
  sensors: { scope: "platform", gate: "main.go handleCollectors + snmp_discovery.go handleDiscoveryConfig → requireCrossTenant" },
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

  it("carries exactly the Security and Tools groups the owner asked for", () => {
    const groups = [...new Set((platform.children ?? []).map((l) => l.group).filter(Boolean))];
    expect(groups).toEqual(["Security", "Tools"]);
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

  it("opens on Licence — one licence file per installation, ungrouped and first", () => {
    expect(platform.children?.[0]?.id).toBe("licence");
    expect(platform.children?.[0]?.group).toBeUndefined();
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
  it("Sensors sits under Data sources", () => {
    expect(groupIds(admin, "Data sources")).toContain("sensors");
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

  it("Access & Audit is tenant-level throughout", () => {
    expect(groupIds(admin, "Access & Audit")).toEqual(["access", "sessions", "audit", "transport"]);
    for (const id of groupIds(admin, "Access & Audit")) {
      expect(GATES[id].scope).toBe("tenant");
    }
  });
});

describe("redirects — no saved link is orphaned by the move", () => {
  const MOVED: [string, string][] = [
    ["#/admin/auth", "auth"],
    ["#/admin/data-protection", "data-protection"],
    ["#/admin/licence", "licence"],
    ["#/admin/regions", "regions"],
    ["#/admin/health", "health"],
    ["#/admin/grafana", "grafana"],
    ["#/admin/opensearch", "opensearch"],
    ["#/admin/graphql", "graphql"],
  ];

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
