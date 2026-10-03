// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// DecisionLedger.test.tsx — the Iris AI decision ledger view (tracker 337
// N-A6): decisions grouped with their steps in order, fingerprints not
// content, a decision id looked up directly, another workspace's id answered
// as "not found", and every value rendered as escaped text.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";

const aiDecisions = vi.fn();
vi.mock("../services/api", () => ({
  api: { aiDecisions: (...a: unknown[]) => aiDecisions(...a) },
}));

import DecisionLedger, { group } from "./DecisionLedger";

const D1 = "11111111-2222-4333-8444-555555555555";
const D2 = "22222222-2222-4333-8444-555555555555";
const H = "a".repeat(64);
const entry = (over = {}) => ({
  id: crypto.randomUUID(), decision_id: D1, seq: 0, event_type: "QUESTION_RECEIVED", principal: "alice",
  surface: "ask", at: "2026-10-03T10:00:00Z", ...over,
});

beforeEach(() => {
  aiDecisions.mockReset();
});
afterEach(() => cleanup());

describe("DecisionLedger", () => {
  it("groups steps into decisions, in order, showing fingerprints and versions", async () => {
    aiDecisions.mockResolvedValue({
      scope: "tenant", event_types: [],
      decisions: [
        entry({ seq: 2, event_type: "ANSWER_RETURNED", mode: "data_query", model_tier: "deterministic", result_sha256: H, at: "2026-10-03T10:00:02Z" }),
        entry({ seq: 1, event_type: "TOOL_EXECUTED", tool: "nl_query", tool_version: "catalog:v1", args_sha256: H, result_sha256: H, item_count: 1 }),
        entry({ seq: 0, args_sha256: H }),
        entry({ decision_id: D2, principal: "bob", at: "2026-10-03T09:00:00Z" }),
      ],
    });
    render(<DecisionLedger />);
    const list = await screen.findByTestId("iris-decision-list");
    expect(aiDecisions).toHaveBeenCalledWith(undefined);
    const steps = screen.getAllByTestId("iris-decision-step");
    expect(steps).toHaveLength(4);
    expect(steps[0]).toHaveTextContent("Question received");
    expect(steps[1]).toHaveTextContent("Tool ran — nl_query (catalog:v1), 1 item");
    expect(steps[1]).toHaveTextContent("asked aaaaaaaaaaaa · read aaaaaaaaaaaa");
    expect(steps[2]).toHaveTextContent("Answer returned — data_query, tier deterministic");
    expect(list.textContent!.indexOf(D1)).toBeLessThan(list.textContent!.indexOf(D2)); // newest first
  });

  it("looks a decision up by id, and says not found for one outside the workspace", async () => {
    aiDecisions.mockResolvedValueOnce({ decisions: [], scope: "tenant", event_types: [] });
    aiDecisions.mockRejectedValueOnce(new Error("404 Not Found: no such decision"));
    render(<DecisionLedger />);
    await screen.findByText("No decisions recorded yet.");
    const input = screen.getByLabelText("Decision id");
    const button = screen.getByRole("button", { name: "Look up" });
    fireEvent.change(input, { target: { value: "not-an-id" } });
    expect(button).toBeDisabled();
    fireEvent.change(input, { target: { value: D2.toUpperCase() } });
    fireEvent.click(button);
    await waitFor(() => expect(aiDecisions).toHaveBeenLastCalledWith(D2));
    expect(await screen.findByRole("alert")).toHaveTextContent("No decision with that id in your workspace.");
  });

  it("tells a non-admin the ledger is for admins", async () => {
    aiDecisions.mockRejectedValue(new Error("403 Forbidden: forbidden"));
    render(<DecisionLedger />);
    expect(await screen.findByRole("alert")).toHaveTextContent("The decision ledger is for workspace admins.");
  });

  it("renders hostile values as text, and names the workspace only on the platform view", async () => {
    aiDecisions.mockResolvedValue({
      scope: "platform", event_types: [],
      decisions: [entry({ tenant: "t-b", principal: '<img src=x onerror="alert(1)">', event_type: "<b>X</b>" })],
    });
    const { container } = render(<DecisionLedger />);
    await screen.findByTestId("iris-decision-list");
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("b")).toBeNull();
    expect(container.textContent).toContain("workspace t-b");
  });

  it("group orders steps by seq", () => {
    const g = group([entry({ seq: 1 }), entry({ seq: 0 })]);
    expect(g).toHaveLength(1);
    expect(g[0].steps.map((s) => s.seq)).toEqual([0, 1]);
  });
});
