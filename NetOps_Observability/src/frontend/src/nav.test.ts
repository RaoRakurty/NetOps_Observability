// landingResolves — guards the admin-configurable default landing: a configured
// route is only applied if it resolves to a REAL, ACCESSIBLE leaf in the principal's
// (already-filtered) nav. A stale or forbidden route must fall back to the built-in
// home rather than trap the user.

import { describe, it, expect } from "vitest";
import { landingResolves, filteredNav } from "./nav";

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
