// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// DecisionLedger.test.tsx — the decision ledger panel (tracker 337 N-A6):
// entries grouped into decisions newest first with the answer's outcome and
// model, one decision's steps loaded on demand, fields rendered as escaped
// text, and a non-admin's 403 shown as a plain sentence rather than an error.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent } from "@testing-library/react";

const aiDecisions = vi.fn();
const aiHypotheses = vi.fn();
vi.mock("../services/api", () => ({
  api: {
    aiDecisions: (...a: unknown[]) => aiDecisions(...a),
    aiHypotheses: (...a: unknown[]) => aiHypotheses(...a),
  },
}));

import DecisionLedger, { summarize } from "./DecisionLedger";

const D1 = "11111111-2222-4333-8444-555555555555";
const D2 = "22222222-2222-4333-8444-555555555555";
const H = "a".repeat(64);
const entry = (over = {}) => ({
  id: crypto.randomUUID(), decision_id: D1, seq: 0, event_type: "QUESTION_RECEIVED", principal: "alice",
  surface: "ask", at: "2026-10-01T10:00:00Z", ...over,
});

beforeEach(() => { aiDecisions.mockReset(); aiHypotheses.mockReset(); });
afterEach(() => cleanup());

describe("summarize", () => {
  it("groups entries into decisions, newest first, carrying the answer", () => {
    const out = summarize([
      entry({ decision_id: D2, seq: 1, event_type: "ANSWER_RETURNED", at: "2026-10-01T11:00:01Z", outcome: "answered" }),
      entry({ decision_id: D2, seq: 0, at: "2026-10-01T11:00:00Z" }),
      entry({ decision_id: D1, seq: 0, at: "2026-10-01T10:00:00Z" }),
    ] as never);
    expect(out.map((d) => d.id)).toEqual([D2, D1]);
    expect(out[0].steps).toBe(2);
    expect(out[0].at).toBe("2026-10-01T11:00:00Z");
    expect(out[0].answer?.outcome).toBe("answered");
    expect(out[1].answer).toBeUndefined();
  });
});

describe("DecisionLedger", () => {
  it("lists decisions and loads one decision's steps on demand", async () => {
    aiDecisions.mockImplementation((opts: { decisionId?: string }) => Promise.resolve(opts.decisionId
      ? { scope: "tenant", event_types: [], decisions: [
        entry({ seq: 0, args_sha256: H }),
        entry({ seq: 1, event_type: "TOOL_EXECUTED", tool: "nl_query", outcome: "ok", item_count: 3, args_sha256: H, result_sha256: H }),
        entry({ seq: 2, event_type: "ANSWER_RETURNED", outcome: "answered" }),
      ] }
      : { scope: "tenant", event_types: [], decisions: [
        entry({ seq: 1, event_type: "ANSWER_RETURNED", outcome: "answered", mode: "data_query", model_tier: "deterministic" }),
        entry({ seq: 0 }),
      ] }));
    render(<DecisionLedger />);
    const list = await screen.findByTestId("iris-ledger-list");
    expect(aiDecisions).toHaveBeenCalledWith({ limit: 200 });
    expect(list).toHaveTextContent("asked by alice, answered · data_query · deterministic, 2 steps");
    fireEvent.click(screen.getByText("Show steps"));
    const steps = await screen.findByTestId("iris-decision-steps");
    expect(aiDecisions).toHaveBeenCalledWith({ decisionId: D1, limit: 200 });
    expect(steps).toHaveTextContent("question received");
    expect(steps).toHaveTextContent("tool ran nl_query — ok — 3 items args aaaaaaaaaaaa result aaaaaaaaaaaa");
    expect(steps).toHaveTextContent("answer returned");
  });

  it("renders hostile fields as text, never markup", async () => {
    aiDecisions.mockResolvedValue({ scope: "tenant", event_types: [], decisions: [entry({ principal: '<img src=x onerror="alert(1)">' })] });
    const { container } = render(<DecisionLedger />);
    await screen.findByTestId("iris-ledger-list");
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toContain('<img src=x onerror="alert(1)">');
  });

  it("names each tenant only on the platform owner's view", async () => {
    aiDecisions.mockResolvedValue({ scope: "platform", event_types: [], decisions: [entry({ tenant: "t-a" })] });
    render(<DecisionLedger />);
    expect(await screen.findByTestId("iris-ledger-list")).toHaveTextContent("asked by alice (t-a)");
  });

  it("tells a non-admin plainly that the ledger is for admins", async () => {
    aiDecisions.mockRejectedValue(new Error("403 Forbidden: {\"error\":\"forbidden\"}"));
    render(<DecisionLedger />);
    expect(await screen.findByText("Only workspace admins can read the decision ledger.")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("shows any other failure as an operator sentence", async () => {
    aiDecisions.mockRejectedValue(new Error("503 Service Unavailable: {\"error\":\"the AI decision ledger is not available on this deployment\"}"));
    render(<DecisionLedger />);
    expect(await screen.findByRole("alert")).toHaveTextContent("The AI decision ledger is not available on this deployment.");
  });

  it("opens the investigation's lines of investigation from a decision that held them", async () => {
    aiDecisions.mockImplementation((opts: { decisionId?: string }) => Promise.resolve(opts.decisionId
      ? { scope: "tenant", event_types: [], decisions: [
        entry({ seq: 0 }),
        entry({ seq: 1, event_type: "HYPOTHESIS_CREATED", skill: "interface-down", tool: "get_device_state", outcome: "link-down:supported", result_sha256: H }),
        entry({ seq: 2, event_type: "ANSWER_RETURNED", outcome: "answered" }),
      ] }
      : { scope: "tenant", event_types: [], decisions: [entry({ seq: 0 })] }));
    aiHypotheses.mockResolvedValue({
      id: D1, notice: "Lines of investigation, not causes.", engine: { note: "No correlation-engine verdict is in scope." },
      hypotheses: [{ id: "link-down", statement: "The interface in scope is down", layer: "physical", state: "SUPPORTED", transitions: [] }],
    });
    render(<DecisionLedger />);
    await screen.findByTestId("iris-ledger-list");
    fireEvent.click(screen.getByText("Show steps"));
    const steps = await screen.findByTestId("iris-decision-steps");
    expect(steps).toHaveTextContent("hypothesis get_device_state — method interface-down — link-down:supported");
    fireEvent.click(screen.getByText("Show lines of investigation"));
    expect(await screen.findByTestId("iris-hypotheses")).toHaveTextContent("The interface in scope is down");
    expect(aiHypotheses).toHaveBeenCalledWith(D1);
  });

  it("offers no lines of investigation for a decision that held none", async () => {
    aiDecisions.mockResolvedValue({ scope: "tenant", event_types: [], decisions: [entry({ seq: 0 })] });
    render(<DecisionLedger />);
    await screen.findByTestId("iris-ledger-list");
    fireEvent.click(screen.getByText("Show steps"));
    await screen.findByTestId("iris-decision-steps");
    expect(screen.queryByText("Show lines of investigation")).toBeNull();
  });

  it("says so when nothing has been recorded", async () => {
    aiDecisions.mockResolvedValue({ scope: "tenant", event_types: [], decisions: null });
    render(<DecisionLedger />);
    expect(await screen.findByText("No decisions recorded yet.")).toBeInTheDocument();
  });
});
