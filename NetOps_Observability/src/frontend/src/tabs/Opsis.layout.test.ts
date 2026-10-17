// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Opsis.layout.test.ts — the Iris drawer's settings pane must scroll.
//
// The Iris panel (.iris-panel) is position:fixed with a flex column inside
// (.op-chat, min-height:0). The settings pane holds the workspace AI settings
// and, since tracker 337 N-C2, the Iris vocabulary panel — about 1 000 px on a
// 660 px drawer. With neither min-height:0 nor overflow on .op-settings the
// pane could not shrink and the page could not scroll a fixed element, so the
// vocabulary's Add / Check / Ask controls sat below the screen, unreachable.
// Found by e2e/irisVocabulary.spec.ts (N-E5), which clicks them in a real
// browser; this pins the two properties so a restyle cannot quietly undo it.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const css = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "styles.css"), "utf8");

function rule(selector: string): string {
  const at = css.indexOf(`\n${selector} {`);
  expect(at, `rule ${selector} must exist`).toBeGreaterThanOrEqual(0);
  return css.slice(at, css.indexOf("}", at));
}

describe("the Iris drawer's settings pane", () => {
  it("can shrink inside the drawer and scrolls its own content", () => {
    const r = rule(".op-settings");
    expect(r).toMatch(/min-height:\s*0/);
    expect(r).toMatch(/overflow-y:\s*auto/);
  });

  it("lives in a flex column that lets it shrink", () => {
    expect(rule(".op-chat")).toMatch(/flex-direction:\s*column/);
    expect(rule(".op-chat")).toMatch(/min-height:\s*0/);
  });
});
