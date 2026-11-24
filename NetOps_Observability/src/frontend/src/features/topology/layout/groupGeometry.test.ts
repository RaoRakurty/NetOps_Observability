// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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
  labelChipWidth, groupMinWidth,
} from "./groupGeometry";
import { NODE_SIZE, cardWidth, CARD_LABEL_MAX } from "./layoutTypes";
import { CARD_W, CARD_H } from "../renderers/react-flow/nodes/DeviceNode";
import { layoutView, minSize } from "./elkLayout";

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


// Owner, 2026-11-24: the site name went to 14px (secondary text 12px), and the
// chip used to hang past a one-device box onto its neighbour. A box is never
// narrower than its own chip.
describe("a site box fits its label chip", () => {
  it("the chip estimate grows with the name and is capped like the chip caps it", () => {
    expect(labelChipWidth("Site 50 · from vManage", 2)).toBeGreaterThan(labelChipWidth("Site 5", 2));
    expect(labelChipWidth("x".repeat(80), 2)).toBe(labelChipWidth("x".repeat(38), 2));
    expect(labelChipWidth("Site 1", 1000)).toBeGreaterThan(labelChipWidth("Site 1", 1));
  });

  it("a box is at least the card minimum and at least chip + its 10px insets", () => {
    for (const label of ["", "Site 1", "Site 50 · from vManage", "x".repeat(60)]) {
      const w = groupMinWidth(label, 1);
      expect(w).toBeGreaterThanOrEqual(GROUP_MIN_W);
      expect(w).toBeGreaterThanOrEqual(labelChipWidth(label, 1) + 20);
    }
  });

  it("ELK lays a one-device site out at least as wide as its chip", async () => {
    const label = "Site 50 · from vManage";
    const view = {
      // Unique ids: layoutView caches by view id + node/edge ids.
      view_id: "chip-fit", mode: "explore", scope: {}, layout_type: "hierarchical", generated_at: "",
      nodes: [{ id: "chip-fit-a", label: "a", kind: "router", health: "ok", confidence: 1, evidence: [] }],
      edges: [], overlays: [],
      groups: [{ id: "site:chip-fit", label, group_type: "site", children: ["chip-fit-a"], health: "ok", collapsed: false }],
    } as unknown as Parameters<typeof layoutView>[0];
    const out = await layoutView(view);
    const r = out["site:chip-fit"] as { w?: number };
    expect(r.w ?? 0).toBeGreaterThanOrEqual(labelChipWidth(label, 1) + 20);
  });
});

// elkjs, hierarchyHandling INCLUDE_CHILDREN: a compound node's minimum is
// applied transposed in a vertical flow (measured 2026-11-24: (413,148) came
// back 168×413 with DOWN). minSize passes it the way ELK reads it.
describe("ELK container minimum is passed the way ELK reads it", () => {
  it("vertical flows transpose, horizontal flows do not", () => {
    expect(minSize(413, 148, "DOWN")).toBe("(148,413)");
    expect(minSize(413, 148, "UP")).toBe("(148,413)");
    expect(minSize(413, 148, "RIGHT")).toBe("(413,148)");
    expect(minSize(413, 148, "LEFT")).toBe("(413,148)");
  });
});

// Owner, 2026-11-24: hostnames shown in full ("cEDGE-40", never "cEDG…"). A
// card's footprint comes from its hostname, and every layout reserves it.
describe("a card is as wide as its hostname", () => {
  it("never below the base card, grows per character, capped at CARD_LABEL_MAX", () => {
    expect(cardWidth("")).toBe(NODE_SIZE.width);
    expect(cardWidth("cEDGE-40")).toBeGreaterThan(NODE_SIZE.width);
    expect(cardWidth("edge-router-paris-01")).toBeGreaterThan(cardWidth("cEDGE-40"));
    expect(cardWidth("x".repeat(80))).toBe(cardWidth("x".repeat(CARD_LABEL_MAX)));
  });

  it("the WAN layout gives each card its own width — no two cards in a box overlap", async () => {
    const ids = ["edge-router-paris-01", "e2", "edge-router-lyon-0002", "e4"];
    const view = {
      view_id: "card-fit", mode: "explore", scope: {}, layout_type: "wan_overlay", generated_at: "",
      nodes: ids.map((id) => ({ id, label: id, kind: "router", health: "ok", confidence: 1, evidence: [] })),
      edges: [], overlays: [],
      groups: [{ id: "site:cf", label: "Site 1", group_type: "site", children: ids, health: "ok", collapsed: false }],
    } as unknown as Parameters<typeof layoutView>[0];
    const pos = await layoutView(view);
    const r = (id: string) => ({ x: pos[id].x, y: pos[id].y, w: cardWidth(id), h: CARD_H });
    for (let i = 0; i < ids.length; i++) for (let j = i + 1; j < ids.length; j++) {
      const a = r(ids[i]), b = r(ids[j]);
      const overlap = a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
      expect(overlap, `${ids[i]} overlaps ${ids[j]}`).toBe(false);
    }
    // …and the box encloses every card.
    const box = pos["site:cf"] as { x: number; y: number; w: number; h: number };
    for (const id of ids) {
      const c = r(id);
      expect(c.x >= box.x && c.x + c.w <= box.x + box.w, `${id} outside its box`).toBe(true);
    }
  });
});
