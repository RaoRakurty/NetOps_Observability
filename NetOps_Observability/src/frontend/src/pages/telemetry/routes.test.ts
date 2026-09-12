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

import { describe, it, expect } from "vitest";
import { NAV, ROUTE_CHUNKS, filteredNav, resolveRoute, landingResolves } from "../../nav";

const admin = NAV.find((s) => s.id === "admin")!;
const leaf = (admin.children ?? []).find((l) => l.id === "telemetry-coverage");

describe("Telemetry coverage nav placement", () => {
  it("sits in the Administration → Data sources group", () => {
    expect(leaf).toBeDefined();
    expect(leaf!.label).toBe("Telemetry Coverage");
    expect(leaf!.group).toBe("Data sources");
  });

  it("is the last Data sources item, and the shaping pair is its own group", () => {
    const groupIds = (g: string) => (admin.children ?? []).filter((l) => l.group === g).map((l) => l.id);
    expect(groupIds("Data sources")).toEqual([
      "datasources", "snmp", "sensors", "telemetry-coverage",
    ]);
    // Owner IA 2026-09-05: Processors and Sensitive Data Access are ONE group.
    expect(groupIds("Data handling")).toEqual(["processors", "sensitive-data-access"]);
  });

  it("stays visible to a tenant admin (the unrecognized half is tenant-scoped)", () => {
    expect(leaf!.platformOnly).toBeUndefined();
    const tenantIds = (filteredNav(false).find((s) => s.id === "admin")?.children ?? []).map((l) => l.id);
    expect(tenantIds).toContain("telemetry-coverage");
  });

  it("never uses engine vocabulary in its label", () => {
    expect(leaf!.label).not.toMatch(/\bSignals\b/);
  });
});

describe("Telemetry coverage route", () => {
  it("resolves by hash for both principals and is a valid saved landing", () => {
    for (const platform of [true, false]) {
      const nav = filteredNav(platform);
      expect(resolveRoute("#/admin/telemetry-coverage", nav)).toMatchObject({
        section: { id: "admin" },
        leaf: { id: "telemetry-coverage" },
      });
      expect(landingResolves("#/admin/telemetry-coverage", nav)).toBe(true);
    }
  });

  it("is registered as its own lazy chunk for code-splitting + prefetch", () => {
    expect(typeof ROUTE_CHUNKS["TelemetryCoverage"]).toBe("function");
  });

  it("renders the page component from the leaf", () => {
    const el = leaf!.render({} as never);
    expect(el).toBeTruthy();
  });
});
