// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import { applyEvent, finishAll, toolLabel } from "./progressStream";
import type { ProgressStep } from "./IrisProgress";

const run = (evs: { type: string; tool?: string; outcome?: string }[]) => evs.reduce<ProgressStep[]>((s, e) => applyEvent(s, e), []);

describe("applyEvent", () => {
  it("folds a typical answer into steps with states", () => {
    const steps = run([
      { type: "planning" },
      { type: "tool_started", tool: "get_problem" },
      { type: "tool_finished", tool: "get_problem", outcome: "ok" },
      { type: "tool_started", tool: "search_logs" },
      { type: "tool_finished", tool: "search_logs", outcome: "error" },
      { type: "narrating" },
    ]);
    expect(steps.map((s) => `${s.event}:${s.detail ?? ""}:${s.state}`)).toEqual([
      "planning::done",
      "tool:the incident:done",
      "tool:logs:failed",
      "narrating::active",
    ]);
    expect(finishAll(steps).every((s) => s.state !== "active")).toBe(true);
  });

  it("never echoes an unknown tool or event", () => {
    const steps = run([{ type: "tool_started", tool: "<img src=x>" }, { type: "model_text" }, { type: "tool_finished", tool: "nope", outcome: "ok" }]);
    expect(steps).toHaveLength(1);
    expect(steps[0].detail).toBeUndefined();
    expect(toolLabel("__proto__")).toBeUndefined();
  });
});
