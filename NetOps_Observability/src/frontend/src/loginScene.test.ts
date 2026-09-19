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
  it("draws the network topology behind both appearances, smoke and ash in the dark", () => {
    // The wallpaper is generated, not hand-drawn: scripts/login_topology.py
    // emits POPs on metro rings with a long-haul backbone, and
    // tests/test_login_topology.py re-derives it and proves nothing sits behind
    // the sign-in panel. Here we only pin the LAYERS the stylesheet carries.
    const dark = rule(".login-scene");
    expect(dark).toContain("background-image:");
    expect(dark.match(/data:image\/svg\+xml;base64,/g)?.length,
      ".login-scene: smoke sheet + topology + frost grain").toBe(3);

    const light = rule(".login-scene.login-light");
    expect(light).toContain("background-image:");
    expect(light.match(/data:image\/svg\+xml;base64,/g)?.length,
      ".login-scene.login-light: topology + frost grain").toBe(2);
  });

  it("wears the rustic smoke-and-ash ground in the dark appearance", () => {
    const dark = rule(".login-scene");
    expect(dark).toContain("background-color: #16151a");        // warm charcoal, not blue-black
    expect(dark).toMatch(/rgba\(176, 137, 104/);                 // ember haze, top left
    expect(dark).toMatch(/rgba\(140, 130, 120/);                 // ash haze, bottom right
    expect(dark).toMatch(/soft-light/);                          // the smoke sits IN the ground
    expect(dark, "the old indigo/cyan wash is gone").not.toMatch(/rgba\(99, 102, 241|rgba\(56, 189, 248/);
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
