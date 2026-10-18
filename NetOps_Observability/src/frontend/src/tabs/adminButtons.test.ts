// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Every button in the Administration pages uses the shared button styles
// (.btn / .btn.accent / .btn.danger). Owner 2026-10-18: the contact-point "Add"
// rendered as the browser's default button, and two class names in use
// ("btn primary", "btn btn-primary") matched no rule at all, so "Save policy"
// silently looked like a secondary action.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const FILES = ["tabs/admin.tsx"];
const SRC = join(__dirname, "..");

describe("admin buttons use the shared styles", () => {
  for (const f of FILES) {
    const lines = readFileSync(join(SRC, f), "utf8").split("\n");
    it(`${f}: no unstyled <button>`, () => {
      const bare = lines
        .map((l, i) => [i + 1, l] as const)
        .filter(([, l]) => /<button(\s|>)/.test(l) && !/className=/.test(l) && !/\{\.\.\./.test(l))
        .map(([n, l]) => `${f}:${n} ${l.trim().slice(0, 80)}`);
      expect(bare).toEqual([]);
    });
    it(`${f}: no class names that match no rule`, () => {
      const dead = lines
        .map((l, i) => [i + 1, l] as const)
        .filter(([, l]) => /className="(ghost|btn primary|btn btn-primary)"/.test(l))
        .map(([n]) => `${f}:${n}`);
      expect(dead).toEqual([]);
    });
  }
});
