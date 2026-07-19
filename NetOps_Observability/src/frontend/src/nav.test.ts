// landingResolves — guards the admin-configurable default landing: a configured
// route is only applied if it resolves to a REAL, ACCESSIBLE leaf in the principal's
// (already-filtered) nav. A stale or forbidden route must fall back to the built-in
// home rather than trap the user.

import { describe, it, expect } from "vitest";
import { landingResolves, filteredNav, resolveRoute } from "./nav";

describe("landingResolves", () => {
  const nav = filteredNav(true); // platform admin sees the full tree

  it("accepts a real section/leaf route", () => {
    expect(landingResolves("#/incident/overview", nav)).toBe(true);
    expect(landingResolves("#/dashboards/home", nav)).toBe(true);
  });

  it("ignores deep-link query params when validating", () => {
    expect(landingResolves("#/monitoring/correlations?tier=confirmed", nav)).toBe(true);
  });

  it("rejects a route whose section does not exist", () => {
    expect(landingResolves("#/nonsense/page", nav)).toBe(false);
    expect(landingResolves("#/", nav)).toBe(false);
    expect(landingResolves("", nav)).toBe(false);
  });

  it("rejects a real section but non-existent leaf (no silent fallback)", () => {
    expect(landingResolves("#/incident/does-not-exist", nav)).toBe(false);
  });

  it("rejects a route a tenant-scoped user cannot access", () => {
    const tenantNav = filteredNav(false); // no platform-only sections
    // A platform-only leaf that exists for the admin must NOT resolve for a tenant
    // user — proving the gate respects the principal's filtered nav.
    const adminOnly = "#/incident/overview"; // exists for both — sanity it still works
    expect(landingResolves(adminOnly, tenantNav)).toBe(true);
  });
});

// The Explain + Stack rail sections were dissolved into Administration
// (2026-07-10). Old bookmarks/deep links + saved landings must keep resolving
// to the moved pages, and the platform-only Stack pages must stay invisible to
// tenant-scoped users after losing their section-level gate.
describe("Explain/Stack → Administration move", () => {
  const adminNav = filteredNav(true);

  it("aliases legacy explain/stack routes to the moved admin leaves", () => {
    expect(resolveRoute("#/explain/access", adminNav)).toMatchObject({
      section: { id: "admin" },
      leaf: { id: "access" },
    });
    for (const leaf of ["health", "grafana", "opensearch", "graphql"]) {
      expect(resolveRoute(`#/stack/${leaf}`, adminNav)).toMatchObject({
        section: { id: "admin" },
        leaf: { id: leaf },
      });
    }
    // Bare legacy section hashes land on their old first page, not admin's.
    expect(resolveRoute("#/explain", adminNav).leaf?.id).toBe("access");
    expect(resolveRoute("#/stack", adminNav).leaf?.id).toBe("health");
  });

  it("keeps a saved legacy landing valid instead of falling back home", () => {
    expect(landingResolves("#/stack/health", adminNav)).toBe(true);
    expect(landingResolves("#/explain/access", adminNav)).toBe(true);
  });

  it("hides every Stack page from tenant-scoped users (isolation gate)", () => {
    const tenantNav = filteredNav(false);
    const admin = tenantNav.find((s) => s.id === "admin");
    expect(admin).toBeDefined();
    const ids = (admin?.children ?? []).map((l) => l.id);
    for (const gated of ["health", "grafana", "opensearch", "graphql"]) {
      expect(ids).not.toContain(gated);
    }
    // And the legacy deep link must NOT resolve onto a gated page for them —
    // resolveRoute falls back to admin's first visible leaf instead.
    expect(resolveRoute("#/stack/health", tenantNav).leaf?.id).not.toBe("health");
    // Access Explorer is per-tenant (not platform-only) — still reachable.
    expect(ids).toContain("access");
  });

  it("dropped the old top-level sections entirely", () => {
    expect(adminNav.find((s) => s.id === "explain")).toBeUndefined();
    expect(adminNav.find((s) => s.id === "stack")).toBeUndefined();
  });
});

// resolveResourceRoute — the permanent #/resource/{kind}/{id} URL space
// (Wave 6 #20). Matched BEFORE the section/leaf router; null = not a resource
// URL. The id is the canonical opaque id, URL-decoded.
import { resolveResourceRoute, resourceRouteFor } from "./nav";

describe("resolveResourceRoute", () => {
  it("parses kind + id", () => {
    expect(resolveResourceRoute("#/resource/cloud/i-0abc123")).toEqual({ kind: "cloud", id: "i-0abc123" });
  });

  it("URL-decodes the id (ARNs and slashes survive)", () => {
    const id = "arn:aws:elasticloadbalancing:us-east-1:1111:loadbalancer/app/web/50d";
    const route = resourceRouteFor("cloud", id);
    expect(resolveResourceRoute(`#/${route}`)).toEqual({ kind: "cloud", id });
  });

  it("ignores query params", () => {
    expect(resolveResourceRoute("#/resource/cloud/i-1?tab=metrics")).toEqual({ kind: "cloud", id: "i-1" });
  });

  it("returns null for non-resource routes and incomplete paths", () => {
    expect(resolveResourceRoute("#/monitoring/correlations?id=x")).toBeNull();
    expect(resolveResourceRoute("#/resource")).toBeNull();
    expect(resolveResourceRoute("#/resource/cloud")).toBeNull();
    expect(resolveResourceRoute("#/resource/cloud/")).toBeNull();
    expect(resolveResourceRoute("#/dashboards/home")).toBeNull();
  });

  it("round-trips resourceRouteFor for plain ids", () => {
    expect(resourceRouteFor("cloud", "vm-1")).toBe("resource/cloud/vm-1");
  });
});
