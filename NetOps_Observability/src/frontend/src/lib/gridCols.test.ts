// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, expect, it } from "vitest";
import { bestCols } from "./gridCols";

describe("bestCols — balanced tile grids", () => {
  it.each([
    [0, 1], [1, 1], [2, 2], [3, 3], [4, 4],
    [5, 3], // 3 + 2 beats 4 + 1
    [6, 3], // the notification channels: 3 + 3, no empty cells
    [7, 4], // 4 + 3 beats 3 + 3 + 1
    [8, 4], [9, 3], [10, 4], [12, 4],
  ])("%i tiles → %i columns", (n, cols) => {
    expect(bestCols(n)).toBe(cols);
  });

  it("never leaves more empty cells than any other allowed layout (3–4 columns past six tiles)", () => {
    for (let n = 5; n <= 40; n++) {
      const c = bestCols(n);
      const empty = (c - (n % c)) % c;
      for (let alt = n > 6 ? 3 : 2; alt <= 4; alt++) expect(empty).toBeLessThanOrEqual((alt - (n % alt)) % alt);
    }
  });
});
