// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import { budgetTone, fmtSloPct, removeSlo, sloForApp, upsertSlo, validateSloTarget } from "./slo";
import type { CloudSloResponse } from "../../services/api";

const resp = (slos: CloudSloResponse["slos"]): CloudSloResponse => ({
  tenant_id: "t1", slos, count: slos.length, max_slos: 20,
});

describe("sloForApp", () => {
  it("matches case-insensitively and returns null when absent", () => {
    const r = resp([{ app_name: "Shop", target_pct: 99.9, window_days: 30 }]);
    expect(sloForApp(r, "shop")?.app_name).toBe("Shop");
    expect(sloForApp(r, "other")).toBeNull();
    expect(sloForApp(null, "shop")).toBeNull();
  });
});

describe("upsertSlo / removeSlo", () => {
  const defs = [
    { app_name: "shop", target_pct: 99.9, window_days: 30 },
    { app_name: "crm", target_pct: 99, window_days: 7 },
  ];
  it("replaces an existing objective without duplicating", () => {
    const next = upsertSlo(defs, "SHOP", 99.5, 7);
    expect(next).toHaveLength(2);
    const shop = next.find((d) => d.app_name.toLowerCase() === "shop");
    expect(shop).toEqual({ app_name: "SHOP", target_pct: 99.5, window_days: 7 });
  });
  it("appends a new objective and removes by name", () => {
    expect(upsertSlo(defs, "billing", 99, 14)).toHaveLength(3);
    expect(removeSlo(defs, "crm").map((d) => d.app_name)).toEqual(["shop"]);
  });
  it("is pure — the input list is untouched", () => {
    upsertSlo(defs, "x", 99, 7);
    removeSlo(defs, "shop");
    expect(defs).toHaveLength(2);
  });
});

describe("validateSloTarget", () => {
  it("mirrors the backend bounds", () => {
    expect(validateSloTarget("99.9")).toBe("");
    expect(validateSloTarget("50")).toBe("");
    expect(validateSloTarget("49.9")).not.toBe("");
    expect(validateSloTarget("100")).not.toBe("");
    expect(validateSloTarget("abc")).not.toBe("");
  });
});

describe("fmtSloPct", () => {
  it("never rounds 99.95 up to 100%", () => {
    expect(fmtSloPct(99.95)).toBe("99.95%");
    expect(fmtSloPct(99.9995)).toBe("99.999%");
    expect(fmtSloPct(100)).toBe("100%");
    expect(fmtSloPct(undefined)).toBe("—");
  });
});

describe("budgetTone", () => {
  it("is undefined (no false green) when not measurable", () => {
    expect(budgetTone(undefined)).toBeUndefined();
    expect(budgetTone({ measurable: false })).toBeUndefined();
  });
  it("grades by remaining budget", () => {
    expect(budgetTone({ measurable: true, budget_remaining_pct: 80 })).toBe("good");
    expect(budgetTone({ measurable: true, budget_remaining_pct: 10 })).toBe("warn");
    expect(budgetTone({ measurable: true, budget_remaining_pct: 0 })).toBe("bad");
  });
});
