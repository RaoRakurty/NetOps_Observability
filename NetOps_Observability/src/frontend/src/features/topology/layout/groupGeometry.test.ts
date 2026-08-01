// groupGeometry.test.ts — the single-source rule.
//
// The group box was once produced by three systems that disagreed: ELK reserved
// one padding, the adapter re-derived the rect with a different one, and the
// layout cell was a different size from the drawn card. The visible result was a
// box padded 28px on one side and 58px on the other, and sibling containers
// whose borders nearly touched despite a "clean" layout.
//
// These tests pin the invariants that make that impossible to reintroduce.

import { describe, it, expect } from "vitest";
import {
  LABEL_BAND, GROUP_PAD, ELK_GROUP_PADDING, GROUP_MIN_W, GROUP_MIN_H, radiusForDepth,
} from "./groupGeometry";
import { NODE_SIZE } from "./layoutTypes";
import { CARD_W, CARD_H } from "../renderers/react-flow/nodes/DeviceNode";
import { layoutView } from "./elkLayout";

describe("one geometry source", () => {
  it("lays out with the size it actually draws", () => {
    // A layout cell bigger than the card is phantom slack, and it makes a group
    // rect computed from cells look mis-padded against cards the eye measures.
    expect(NODE_SIZE.width).toBe(CARD_W);
    expect(NODE_SIZE.height).toBe(CARD_H);
  });

  it("reserves in ELK exactly what the renderer draws", () => {
    expect(ELK_GROUP_PADDING).toBe(
      `[top=${LABEL_BAND + GROUP_PAD},left=${GROUP_PAD},bottom=${GROUP_PAD},right=${GROUP_PAD}]`,
    );
  });

  it("reserves a label band at least as tall as the chip", () => {
    // The chip renders ~26px; reserving 16 (as the adapter used to) puts members
    // under the label.
    expect(LABEL_BAND).toBeGreaterThanOrEqual(26);
  });

  it("keeps a one-child container off its child's shoulders", () => {
    expect(GROUP_MIN_W).toBeGreaterThanOrEqual(CARD_W + 2 * GROUP_PAD);
    expect(GROUP_MIN_H).toBeGreaterThanOrEqual(CARD_H + LABEL_BAND + 2 * GROUP_PAD);
  });

  it("shrinks the corner radius with depth so nested corners do not collide", () => {
    expect(radiusForDepth(0)).toBeGreaterThan(radiusForDepth(1));
    expect(radiusForDepth(1)).toBeGreaterThan(radiusForDepth(2));
  });
});

describe("ELK returns container rectangles", () => {
  it("gives every container a solved width/height, and leaves leaves alone", async () => {
    const view: any = {
      view_id: "g1", layout_type: "cloud_grouped", mode: "explore",
      nodes: [
        { id: "n1", label: "a", kind: "cloud" },
        { id: "n2", label: "b", kind: "cloud" },
      ],
      edges: [],
      groups: [
        { id: "region", label: "r", group_type: "region", children: [], health: "unknown", collapsed: false },
        { id: "vpc", label: "v", group_type: "vpc", parent_id: "region", children: ["n1", "n2"], health: "unknown", collapsed: false },
      ],
    };
    const pos = await layoutView(view);

    // Containers carry a rect — that rect is what gets DRAWN.
    for (const id of ["region", "vpc"]) {
      expect(pos[id], `no position for ${id}`).toBeTruthy();
      expect(pos[id].w, `${id} has no solved width`).toBeGreaterThan(0);
      expect(pos[id].h, `${id} has no solved height`).toBeGreaterThan(0);
    }
    // Leaves do not — a leaf's size is the card's business.
    expect(pos["n1"].w).toBeUndefined();

    // The nested container must sit INSIDE its parent's rect, not overlap it.
    const r = pos["region"], v = pos["vpc"];
    expect(v.x).toBeGreaterThanOrEqual(r.x);
    expect(v.y).toBeGreaterThanOrEqual(r.y);
    expect(v.x + (v.w ?? 0)).toBeLessThanOrEqual(r.x + (r.w ?? 0) + 0.5);
    expect(v.y + (v.h ?? 0)).toBeLessThanOrEqual(r.y + (r.h ?? 0) + 0.5);

    // And the child must clear the parent's label band.
    expect(v.y - r.y).toBeGreaterThanOrEqual(LABEL_BAND);
  });
});
