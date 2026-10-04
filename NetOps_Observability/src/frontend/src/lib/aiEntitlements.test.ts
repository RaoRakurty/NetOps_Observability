// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import { hasAIEntitlement } from "./aiEntitlements";

describe("hasAIEntitlement (tracker 337 N-A7)", () => {
  it("answers from the caller's list", () => {
    const f = { ai_entitlements: ["ai.chat"] };
    expect(hasAIEntitlement(f, "ai.chat")).toBe(true);
    expect(hasAIEntitlement(f, "ai.nlquery")).toBe(false);
    expect(hasAIEntitlement(f, "ai.mcp")).toBe(false);
  });

  it("an empty list grants nothing", () => {
    expect(hasAIEntitlement({ ai_entitlements: [] }, "ai.chat")).toBe(false);
  });

  it("no answer (failed or still loading) hides", () => {
    expect(hasAIEntitlement(null, "ai.chat")).toBe(false);
    expect(hasAIEntitlement(undefined, "ai.chat")).toBe(false);
  });

  it("a server that predates the list keeps the old visibility", () => {
    expect(hasAIEntitlement({ copilot: true }, "ai.chat")).toBe(true);
  });
});
