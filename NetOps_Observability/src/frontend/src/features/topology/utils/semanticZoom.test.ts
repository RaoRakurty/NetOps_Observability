// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// semanticZoom.test.ts — the ONE zoom ladder.
//
// This file exists because the canvas, the adapter and the node renderer once
// carried THREE separate zoom threshold tables that disagreed: a node could be
// rendering as a badge while the adapter still thought it was a card and the
// canvas bucketed it as a third thing. The fix was to derive all three from
// `zoomLevel()` — but nothing guarded it, so the next hand-written `zoom > 0.8`
// anywhere would silently reintroduce the split.
//
// These tests pin the derivation, not the numbers: every assertion is expressed
// in terms of what the ladder DECIDES, so retuning a boundary stays a one-line
// change here rather than a hunt through three files.

import { describe, it, expect } from "vitest";
import { zoomLevel, labelDensityForZoom, bucketForZoom, tierForZoom } from "./semanticZoom";

const LEVELS = ["global", "site", "fabric", "device", "interface"] as const;

// A zoom that lands in each level, from far out to close in.
const SAMPLES: Array<{ zoom: number; level: (typeof LEVELS)[number] }> = [
  { zoom: 0.1, level: "global" },
  { zoom: 0.3, level: "global" },
  { zoom: 0.6, level: "site" },
  { zoom: 1.0, level: "fabric" },
  { zoom: 1.5, level: "device" },
  { zoom: 3.0, level: "interface" },
];

describe("the zoom ladder is monotonic", () => {
  it("never moves backwards as you zoom in", () => {
    const order = new Map(LEVELS.map((l, i) => [l, i]));
    let prev = -1;
    for (let z = 0.05; z <= 5; z += 0.05) {
      const rank = order.get(zoomLevel(z))!;
      expect(rank).toBeGreaterThanOrEqual(prev);
      prev = rank;
    }
  });

  it("covers the whole range — no zoom is unclassified", () => {
    for (let z = 0.01; z <= 10; z += 0.07) {
      expect(LEVELS).toContain(zoomLevel(z));
    }
  });
});

describe("every consumer derives from the same ladder", () => {
  it("bucketForZoom is stable within a level and distinct between levels", () => {
    // The canvas buckets zoom so a tiny wheel movement does not rebuild the
    // whole RF array. Two zooms at the same level MUST bucket identically, or
    // that memoisation thrashes.
    const byLevel = new Map<string, Set<number>>();
    for (let z = 0.05; z <= 5; z += 0.01) {
      const l = zoomLevel(z);
      if (!byLevel.has(l)) byLevel.set(l, new Set());
      byLevel.get(l)!.add(bucketForZoom(z));
    }
    for (const [level, buckets] of byLevel) {
      expect(buckets.size, `level ${level} produced ${buckets.size} buckets`).toBe(1);
    }
    // ...and different levels must not collide onto one bucket, or the adapter
    // cannot tell them apart.
    const all = [...byLevel.values()].map((s) => [...s][0]);
    expect(new Set(all).size).toBe(byLevel.size);
  });

  it("tierForZoom follows the ladder, coarse when far out", () => {
    // The exact mapping is a product decision; what must hold is that zooming
    // OUT never produces a MORE detailed tier.
    const detail = { badge: 0, token: 1, card: 2 } as Record<string, number>;
    let prev = -1;
    for (let z = 0.05; z <= 5; z += 0.05) {
      const d = detail[tierForZoom(z)];
      expect(d, `tier at zoom ${z}`).toBeGreaterThanOrEqual(prev);
      prev = d;
    }
    expect(detail[tierForZoom(0.1)]).toBeLessThan(detail[tierForZoom(3)]);
  });

  it("labelDensityForZoom turns on at fabric and never turns back off", () => {
    for (const { zoom, level } of SAMPLES) {
      const named = labelDensityForZoom(zoom);
      const isCloseIn = level === "fabric" || level === "device" || level === "interface";
      expect(named, `zoom ${zoom} (${level})`).toBe(isCloseIn);
    }
    // Monotonic: once labels are on, zooming further in keeps them on.
    let seenOn = false;
    for (let z = 0.05; z <= 5; z += 0.05) {
      const on = labelDensityForZoom(z);
      if (on) seenOn = true;
      else expect(seenOn, `labels turned back OFF at zoom ${z}`).toBe(false);
    }
  });
});

describe("the ladder classifies the samples as documented", () => {
  it.each(SAMPLES)("zoom $zoom is $level", ({ zoom, level }) => {
    expect(zoomLevel(zoom)).toBe(level);
  });
});
