// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix
//
// The sign-in screen wears the setup wizard's template (owner, 2026-09-15):
// the network-mesh wallpaper behind a CLEAR pane — almost no fill, no blur —
// in both appearances, without the wizard's large eye. The template lives in
// styles.css only, so this pins the properties that make it read as
// transparent; a later restyle that quietly brings back an opaque, blurred
// card or the hero eye fails here instead of on the lab.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const SRC = dirname(fileURLToPath(import.meta.url));
const css = readFileSync(join(SRC, "styles.css"), "utf8");

function rule(selector: string): string {
  const at = css.indexOf(`${selector} {`);
  expect(at, `rule ${selector} must exist`).toBeGreaterThanOrEqual(0);
  return css.slice(at, css.indexOf("\n}", at));
}

const loginBlock = css.slice(css.indexOf(".login-scene {"), css.indexOf(".mode-toggle {"));

describe("the sign-in screen uses the setup wizard's template", () => {
  it("draws the mesh wallpaper and frost grain behind both appearances", () => {
    for (const sel of [".login-scene", ".login-scene.login-light"]) {
      const r = rule(sel);
      expect(r).toContain("background-image:");
      expect(r.match(/data:image\/svg\+xml;base64,/g)?.length, `${sel} mesh + grain`).toBe(2);
    }
  });

  it("keeps the pane clear — a whisper of fill and no blur", () => {
    expect(rule(".login-scene .card")).toContain("background: rgba(255, 255, 255, 0.03)");
    expect(rule(".login-scene.login-light .card")).toContain("background: rgba(255, 255, 255, 0.06)");
    expect(loginBlock).not.toMatch(/backdrop-filter/);
  });

  it("uses the wizard's indigo accent and near-black text in the light appearance", () => {
    const r = rule(".login-scene.login-light");
    expect(r).toContain("--fg: #0b1020");
    expect(r).toContain("--login-btn-bg: #4f46e5");
  });

  it("does not bring the wizard's large eye onto the sign-in screen", () => {
    expect(loginBlock).not.toMatch(/eye-hero|correlix-eye/);
  });
});
