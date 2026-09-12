// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// routes.test.ts — the Security section's route surface. The CTEM leaves are
// new; the three pre-existing ids must keep resolving so every bookmark, saved
// landing and panel drill into the old Security section still lands.

import { describe, it, expect } from "vitest";
import { NAV, ROUTE_CHUNKS, filteredNav, resolveRoute, landingResolves } from "../../nav";

const security = NAV.find((s) => s.id === "security")!;
const nav = filteredNav(true);

describe("Security section shape", () => {
  it("carries the CTEM leaves in operator order", () => {
    expect((security.children ?? []).map((l) => l.id)).toEqual([
      "overview", "exposures", "stories", "vuln", "threat", "compliance", "rules", "views",
    ]);
  });

  it("never shows engine vocabulary in a leaf label", () => {
    for (const l of security.children ?? []) expect(l.label).not.toMatch(/\bSignals\b/);
  });

  it("is tenant-visible end to end — no leaf is platform-owner only", () => {
    const tenantLeaves = (filteredNav(false).find((s) => s.id === "security")?.children ?? []).map((l) => l.id);
    expect(tenantLeaves).toEqual((security.children ?? []).map((l) => l.id));
  });
});

describe("Security routes resolve", () => {
  it("every new leaf is reachable by hash", () => {
    for (const leaf of ["overview", "exposures", "stories", "rules", "views"]) {
      expect(resolveRoute(`#/security/${leaf}`, nav)).toMatchObject({ section: { id: "security" }, leaf: { id: leaf } });
      expect(landingResolves(`#/security/${leaf}`, nav)).toBe(true);
    }
  });

  it("the pre-existing ids still resolve (legacy bookmarks keep working)", () => {
    for (const leaf of ["vuln", "threat", "compliance"]) {
      expect(resolveRoute(`#/security/${leaf}`, nav)).toMatchObject({ section: { id: "security" }, leaf: { id: leaf } });
    }
  });

  it("a story deep link resolves onto the stories leaf, id suffix and all", () => {
    expect(resolveRoute("#/security/stories/corr-9", nav)).toMatchObject({
      section: { id: "security" }, leaf: { id: "stories" },
    });
  });

  it("the bare section lands on the overview", () => {
    expect(resolveRoute("#/security", nav).leaf?.id).toBe("overview");
  });
});

describe("Security route chunks", () => {
  it("every Security page is registered for lazy loading + prefetch", () => {
    for (const key of ["SecurityOverview", "SecurityExposures", "SecurityExposureStories",
      "SecurityThreatDetection", "SecurityCompliance", "SecurityRules", "SecuritySavedViews"]) {
      expect(typeof ROUTE_CHUNKS[key]).toBe("function");
    }
  });
});
