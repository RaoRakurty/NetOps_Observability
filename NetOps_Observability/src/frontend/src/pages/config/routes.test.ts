// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// routes.test.ts — where the fleet Config drift list lives in the nav, and that
// it is actually reachable. Placement is load-bearing: it sits in Infrastructure
// beside Devices (each row deep-links into a device's Configuration panel), and
// it must NOT be platformOnly — configuration state is tenant-scoped data every
// tenant operator needs, server-filtered by the token (§3a).

import { describe, it, expect } from "vitest";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { NAV, ROUTE_CHUNKS, filteredNav, resolveRoute, landingResolves } from "../../nav";

const infra = NAV.find((s) => s.id === "infrastructure")!;
const leaf = (infra.children ?? []).find((l) => l.id === "config-drift");

describe("Config drift nav placement", () => {
  it("is an Infrastructure leaf", () => {
    expect(leaf).toBeDefined();
    expect(leaf!.label).toBe("Config Drift");
  });

  it("stays visible to a tenant principal — drift is tenant-scoped data", () => {
    expect(leaf!.platformOnly).toBeUndefined();
    const tenantIds = (filteredNav(false).find((s) => s.id === "infrastructure")?.children ?? []).map((l) => l.id);
    expect(tenantIds).toContain("config-drift");
  });

  it("never uses engine vocabulary in its label", () => {
    expect(leaf!.label).not.toMatch(/\bSignals\b/);
  });
});

describe("Config drift route", () => {
  it("resolves by hash for both principals and is a valid saved landing", () => {
    for (const platform of [true, false]) {
      const nav = filteredNav(platform);
      expect(resolveRoute("#/infrastructure/config-drift", nav)).toMatchObject({
        section: { id: "infrastructure" },
        leaf: { id: "config-drift" },
      });
      expect(landingResolves("#/infrastructure/config-drift", nav)).toBe(true);
    }
  });

  it("is registered as a prefetchable route chunk pointing at a real file", () => {
    expect(typeof ROUTE_CHUNKS["ConfigDrift"]).toBe("function");
    const here = dirname(fileURLToPath(import.meta.url));
    expect(existsSync(resolve(here, "ConfigDrift.tsx"))).toBe(true);
  });
});
