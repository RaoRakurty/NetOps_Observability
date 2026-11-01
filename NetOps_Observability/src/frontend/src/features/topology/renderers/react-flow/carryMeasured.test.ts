// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import type { Node } from "@xyflow/react";
import { carryMeasured } from "./carryMeasured";

const n = (id: string, extra: Partial<Node> = {}): Node => ({ id, position: { x: 0, y: 0 }, data: {}, ...extra });

describe("carryMeasured", () => {
  it("carries the last measurement onto a re-derived node of the same id", () => {
    const prev = [n("a", { measured: { width: 120, height: 56 } })];
    const next = [n("a", { position: { x: 10, y: 20 }, data: { tier: "badge" } })];
    const out = carryMeasured(next, prev);
    expect(out[0].measured).toEqual({ width: 120, height: 56 });
    // everything else comes from the re-derived node, not the old one
    expect(out[0].position).toEqual({ x: 10, y: 20 });
    expect(out[0].data).toEqual({ tier: "badge" });
  });

  it("does not mutate either input and copies the measurement object", () => {
    const measured = { width: 120, height: 56 };
    const prevNode = n("a", { measured });
    const nextNode = n("a");
    const out = carryMeasured([nextNode], [prevNode]);
    expect(nextNode.measured).toBeUndefined();
    expect(out[0]).not.toBe(nextNode);
    expect(out[0].measured).not.toBe(measured);
  });

  it("leaves a brand-new node unmeasured so React Flow measures it", () => {
    const out = carryMeasured([n("new")], [n("a", { measured: { width: 1, height: 1 } })]);
    expect(out[0].measured).toBeUndefined();
  });

  it("never carries a partial or missing measurement", () => {
    const prev = [n("a", { measured: { width: 120 } }), n("b")];
    const out = carryMeasured([n("a"), n("b")], prev);
    expect(out[0].measured).toBeUndefined();
    expect(out[1].measured).toBeUndefined();
  });

  it("keeps a measurement the re-derived node already carries", () => {
    const own = { width: 300, height: 200 };
    const nextNode = n("g", { measured: own });
    const out = carryMeasured([nextNode], [n("g", { measured: { width: 1, height: 1 } })]);
    expect(out[0]).toBe(nextNode);
  });

  it("drops nodes that left the view and preserves the incoming order", () => {
    const prev = [n("a", { measured: { width: 1, height: 2 } }), n("gone", { measured: { width: 3, height: 4 } })];
    const out = carryMeasured([n("c"), n("a")], prev);
    expect(out.map((x) => x.id)).toEqual(["c", "a"]);
    expect(out[1].measured).toEqual({ width: 1, height: 2 });
  });

  it("is a no-op copy on the first render (nothing measured yet)", () => {
    const next = [n("a"), n("b")];
    const out = carryMeasured(next, []);
    expect(out).toEqual(next);
    expect(out).not.toBe(next);
  });
});
