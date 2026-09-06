// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// text.test.ts — display helpers. capitalize touches only the first character
// and leaves the rest (and empty input) untouched, so it is safe as a pure
// render-layer transform over vendor ids.
import { describe, expect, it } from "vitest";
import { capitalize } from "./text";

describe("capitalize — first-letter display transform", () => {
  it("upper-cases the first letter of a lowercase vendor id", () => {
    expect(capitalize("arista")).toBe("Arista");
    expect(capitalize("cisco")).toBe("Cisco");
  });
  it("leaves the remaining characters untouched", () => {
    expect(capitalize("paloalto")).toBe("Paloalto");
    expect(capitalize("f5")).toBe("F5");
  });
  it("is a no-op on empty input", () => {
    expect(capitalize("")).toBe("");
  });
});
