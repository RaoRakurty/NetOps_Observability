// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Correlations promoted badge/filter logic (#113) — the candidates page keeps
// showing EVERYTHING (don't-hide); the library set only decorates rows and
// powers an optional client-side narrowing. Pure-function tests: membership is
// a cross-reference of one library fetch, never a per-row evaluation.

import { describe, it, expect } from "vitest";
import { filterPromoted } from "./Correlations";

const rows = [
  { correlation_id: "a", verdict_tier: "confirmed" },
  { correlation_id: "b", verdict_tier: "suspected" },
  { correlation_id: "c", verdict_tier: "confirmed" },
];
const promoted = new Set(["a", "c"]);

describe("filterPromoted", () => {
  it("passes every row through when the filter is off (don't-hide default)", () => {
    expect(filterPromoted(rows, promoted, false)).toEqual(rows);
    expect(filterPromoted(rows, new Set(), false)).toEqual(rows);
  });

  it("narrows to library members when toggled on", () => {
    expect(filterPromoted(rows, promoted, true).map((r) => r.correlation_id)).toEqual(["a", "c"]);
  });

  it("an empty library set narrows to nothing — never a fabricated match", () => {
    expect(filterPromoted(rows, new Set(), true)).toEqual([]);
  });
});
