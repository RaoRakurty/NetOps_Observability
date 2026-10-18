// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import { NAV } from "../nav";
import { ADMIN_LEAF_THEME, ADMIN_THEMES, adminThemeFor, adminThemeVars, contrastRatio } from "./adminTheme";

const admin = NAV.find((s) => s.id === "admin")!;
const adminLeaves = (admin.children ?? []).map((l) => l.id);

describe("adminTheme", () => {
  it("every Administration leaf chooses its colour — a new leaf must be listed", () => {
    const unlisted = adminLeaves.filter((id) => !(id in ADMIN_LEAF_THEME));
    expect(unlisted).toEqual([]);
  });

  it("lists no leaf that is gone (a stale row would hide a removed page's colour bug)", () => {
    const stale = Object.keys(ADMIN_LEAF_THEME).filter((id) => !adminLeaves.includes(id));
    expect(stale).toEqual([]);
  });

  it("every theme key a leaf names exists", () => {
    for (const k of Object.values(ADMIN_LEAF_THEME)) expect(ADMIN_THEMES[k]).toBeDefined();
  });

  it("white button text on every solid meets WCAG AA (4.5:1)", () => {
    for (const t of Object.values(ADMIN_THEMES)) {
      expect(contrastRatio(t.solid, "#ffffff"), t.key).toBeGreaterThanOrEqual(4.5);
    }
  });

  it("every ink is readable as text on the light surfaces (4.5:1 on white and on the panel tint)", () => {
    for (const t of Object.values(ADMIN_THEMES)) {
      expect(contrastRatio(t.ink, "#ffffff"), t.key).toBeGreaterThanOrEqual(4.5);
      expect(contrastRatio(t.ink, "#f8fafc"), t.key).toBeGreaterThanOrEqual(4.5);
    }
  });

  it("an unknown leaf falls back to Workspace rather than an uncoloured page", () => {
    expect(adminThemeFor("no-such-leaf").key).toBe("workspace");
    expect(adminThemeFor(undefined).key).toBe("workspace");
    expect(adminThemeFor("discovery").key).toBe("sources");
  });

  it("emits the three scope variables", () => {
    expect(adminThemeVars(ADMIN_THEMES.audit)).toEqual({
      "--adm-hue": "var(--mod-stack)", "--adm-ink": "#155e75", "--adm-solid": "#155e75",
    });
  });

  it("contrast maths matches known WCAG values", () => {
    expect(contrastRatio("#000000", "#ffffff")).toBeCloseTo(21, 1);
    expect(contrastRatio("#ffffff", "#ffffff")).toBeCloseTo(1, 5);
    expect(contrastRatio("#767676", "#ffffff")).toBeCloseTo(4.54, 1);
  });
});
