// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// nav.icons — the visual language (owner 2026-11-24): every menu item carries
// an icon, and the menu uses ONE accent colour. Guards:
//   · every section and every page (leaf) names an icon that EXISTS in
//     components/Icon.tsx (an unknown name would silently render the fallback);
//   · no two pages of one section share an icon (they must be told apart);
//   · the menu components carry no hard-coded colours (the per-section hues are
//     gone; colour comes from the theme's --rail-* tokens only).

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { NAV } from "./nav";
import { hasIcon } from "./components/Icon";

describe("menu icons", () => {
  it("every section has a known icon", () => {
    const bad = NAV.filter((s) => !hasIcon(s.icon)).map((s) => `${s.id}: ${s.icon}`);
    expect(bad).toEqual([]);
  });

  it("every page in every section has a known icon", () => {
    const bad: string[] = [];
    for (const s of NAV) for (const l of s.children ?? []) if (!l.icon || !hasIcon(l.icon)) bad.push(`${s.id}/${l.id}: ${l.icon}`);
    expect(bad).toEqual([]);
  });

  it("no two pages of one section share an icon", () => {
    const dup: string[] = [];
    for (const s of NAV) {
      const seen = new Map<string, string>();
      for (const l of s.children ?? []) {
        // A duplicate inside one section makes two pages look alike.
        const prev = seen.get(l.icon);
        if (prev) dup.push(`${s.id}: ${prev} and ${l.id} both use "${l.icon}"`);
        seen.set(l.icon, l.id);
      }
    }
    expect(dup).toEqual([]);
  });
});

describe("one accent colour in the menu", () => {
  const files = ["components/IconRail.tsx", "components/NavTree.tsx", "components/NavFlyout.tsx"];
  it.each(files)("%s has no hard-coded colour", (f) => {
    const src = readFileSync(join(__dirname, f), "utf8")
      // comments may name colours when explaining history
      .replace(/\/\/.*$/gm, "")
      .replace(/\/\*[\s\S]*?\*\//g, "");
    expect(src.match(/#[0-9a-fA-F]{3,8}\b|rgba?\(/g) ?? []).toEqual([]);
  });
});
