// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import StepFlow, { unlockedSteps, type FlowStep } from "./StepFlow";

const step = (id: string, o: Partial<FlowStep> = {}): FlowStep => ({ id, title: id, done: false, render: () => <p>{`body-${id}`}</p>, ...o });

afterEach(() => cleanup());

describe("StepFlow gating", () => {
  it("the first step is always open; a later one opens when the step before it is done", () => {
    expect(unlockedSteps([step("a"), step("b"), step("c")])).toEqual([true, false, false]);
    expect(unlockedSteps([step("a", { done: true }), step("b"), step("c")])).toEqual([true, true, false]);
    expect(unlockedSteps([step("a", { done: true }), step("b", { done: true }), step("c")])).toEqual([true, true, true]);
  });

  it("a step that already holds data is shown even while its prerequisite is unmet", () => {
    // A failing outbox must never hide behind "finish step 2 first".
    expect(unlockedSteps([step("a"), step("b"), step("c", { hasData: true })])).toEqual([true, false, true]);
  });

  it("an optional step never blocks the step after it — the last required step decides", () => {
    const s = [step("a", { done: true }), step("b", { done: true }), step("c", { optional: true }), step("d")];
    expect(unlockedSteps(s)).toEqual([true, true, true, true]);
    const notYet = [step("a", { done: true }), step("b"), step("c", { optional: true }), step("d")];
    expect(unlockedSteps(notYet)).toEqual([true, true, false, false]);
  });

  it("a LOCKED step's own done never unlocks the next step, and never wears a ✓", () => {
    // RCA Tickets: "rules" is done (ticketing runs, nothing conflicts) even
    // with no destination connected — but it is locked, so step 3/4 stay locked.
    const s = [step("a"), step("b", { done: true }), step("c")];
    expect(unlockedSteps(s)).toEqual([true, false, false]);
    render(<StepFlow label="flow" steps={s} />);
    expect(screen.queryByText("✓")).toBeNull();
    expect(screen.queryByText("body-c")).toBeNull();
  });

  it("a locked step names the step to finish first, and does not render its body", () => {
    render(<StepFlow label="flow" steps={[step("a"), step("b"), step("c", { optional: true }), step("d")]} />);
    expect(screen.getByText("body-a")).toBeTruthy();
    expect(screen.queryByText("body-b")).toBeNull();
    expect(screen.queryByText("body-d")).toBeNull();
    // b waits on 1; d waits on 2 (c is optional, so it is not the blocker).
    expect(screen.getAllByText("Finish step 1 first.")).toHaveLength(1);
    expect(screen.getAllByText("Finish step 2 first.")).toHaveLength(2);
  });

  it("is an ordered list with a done mark, an optional label and a status", () => {
    render(<StepFlow label="Set up X" steps={[step("a", { done: true, status: "2 connected" }), step("b", { optional: true })]} />);
    expect(screen.getByRole("list", { name: "Set up X" }).tagName).toBe("OL");
    expect(screen.getByText("✓")).toBeTruthy();
    expect(screen.getByText("(optional)")).toBeTruthy();
    expect(screen.getByText("2 connected")).toBeTruthy();
  });
});
