// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// routes.test.ts — where Telemetry coverage lives in the nav, and that it is
// actually reachable. The placement is load-bearing: it belongs to the
// Administration → Data sources group (beside the other ingest plumbing) and
// must NOT be platformOnly — a tenant admin needs its unrecognized-shapes half
// even though the parser-stats half answers 403 for them (§3a).
//
// 2026-09-05 (owner IA, docs/design/ADMIN_IA_2026-09-05.md): the single "Data
// Collection" group split in two — "Data sources" (what feeds telemetry in,
// Sensors included) and "Data handling" (Processors beside Sensitive Data
// Access). Telemetry coverage reports on what the SOURCES delivered, so it
// stays with them. Its route and its gate are unchanged.
//
// 2026-10-18 (owner): the five Data sources leaves became sections of ONE
// Administration → Discovery page. Telemetry Coverage is its last section
// (#/admin/discovery/telemetry); the old #/admin/telemetry-coverage still
// lands there. The tenant-visibility rule is unchanged.

import { describe, it, expect } from "vitest";
import { NAV, ROUTE_CHUNKS, filteredNav, resolveRoute, landingResolves, canonicalHash } from "../../nav";

const admin = NAV.find((s) => s.id === "admin")!;
const leaf = (admin.children ?? []).find((l) => l.id === "discovery");
const section = leaf?.subItems?.find((x) => x.id === "telemetry");

describe("Telemetry coverage nav placement", () => {
  it("is the Telemetry Coverage section of Administration → Data sources → Discovery", () => {
    expect(leaf).toBeDefined();
    expect(leaf!.group).toBe("Data sources");
    expect(section?.label).toBe("Telemetry Coverage");
    expect(leaf!.subItems!.map((x) => x.id).at(-1)).toBe("telemetry");
  });

  it("the shaping pair stays its own group", () => {
    const groupIds = (g: string) => (admin.children ?? []).filter((l) => l.group === g).map((l) => l.id);
    expect(groupIds("Data sources")).toEqual(["discovery"]);
    expect(groupIds("Data handling")).toEqual(["processors", "sensitive-data-access"]);
  });

  it("stays visible to a tenant admin (the unrecognized half is tenant-scoped)", () => {
    expect(leaf!.platformOnly).toBeUndefined();
    expect(section?.platformOnly).toBeUndefined();
    const tenantLeaf = (filteredNav(false).find((s) => s.id === "admin")?.children ?? []).find((l) => l.id === "discovery");
    expect(tenantLeaf?.subItems?.map((x) => x.id)).toContain("telemetry");
  });

  it("never uses engine vocabulary in its label", () => {
    expect(section!.label).not.toMatch(/\bSignals\b/);
  });
});

describe("Telemetry coverage route", () => {
  it("resolves by hash for both principals (new and old address) and is a valid saved landing", () => {
    expect(canonicalHash("#/admin/telemetry-coverage")).toBe("#/admin/discovery/telemetry");
    for (const platform of [true, false]) {
      const nav = filteredNav(platform);
      for (const h of ["#/admin/discovery/telemetry", "#/admin/telemetry-coverage"]) {
        expect(resolveRoute(h, nav)).toMatchObject({ section: { id: "admin" }, leaf: { id: "discovery" } });
        expect(landingResolves(h, nav)).toBe(true);
      }
    }
  });

  it("is registered as a lazy chunk for code-splitting + prefetch", () => {
    expect(typeof ROUTE_CHUNKS["DiscoveryHub"]).toBe("function");
  });

  it("renders the page component from the leaf", () => {
    const el = leaf!.render({} as never);
    expect(el).toBeTruthy();
  });
});
