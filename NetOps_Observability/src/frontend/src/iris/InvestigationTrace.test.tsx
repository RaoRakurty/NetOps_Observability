// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// InvestigationTrace.test.tsx — the read-only investigation trace (tracker 337
// N-I1): the outcome in words, the engine's verdict labelled as the engine's
// and read first, numbered steps with each outcome as a word, details on
// demand (methods considered and why one did not apply, passes, budget spent),
// the early stop said, nothing rendered as markup, a held trace read back by
// id, and a 404 as a plain sentence.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent } from "@testing-library/react";
import type { AiInvestigationTrace } from "../services/api";

const aiInvestigation = vi.fn();
// A refusal is returned by the wrapper itself, not through the spy: vitest's
// spy tracks every returned promise, and that tracking leaves a rejection
// unhandled even when the component handles it.
let failWith: Error | null = null;
vi.mock("../services/api", () => ({
  api: { aiInvestigation: (...a: unknown[]) => (failWith ? Promise.reject(failWith) : aiInvestigation(...a)) },
}));

import InvestigationTrace, { outcomeWord, statusWord, stepWord, targetLine } from "./InvestigationTrace";

const ID = "11111111-2222-4333-8444-555555555555";

function sample(over: Partial<AiInvestigationTrace> = {}): AiInvestigationTrace {
  return {
    id: ID,
    status: "inconclusive",
    target: { device_id: "dev-a", device: "cEdge-80", correlation_id: "P-7" },
    engine: { tier: "confirmed", statement: "P-7 — control connections lost on cEdge-80; verdict confirmed", citation_id: "verdict:P-7" },
    context_applied: true,
    candidates: [
      { skill: "acme-wan-check", source: "runbook_link", customer_authored: true, applies: true, why: "your team linked the runbook acme wan check to this incident" },
      { skill: "ospf-adjacency", source: "selected", applies: false, why: "no OSPF adjacency is discovered on cEdge-80" },
    ],
    plan: [{ skill: "acme-wan-check", tools: ["get_overlay_state"] }],
    passes: [
      { pass: 1, entry: "acme-wan-check", source: "runbook_link", chain: [{ name: "acme-wan-check" }, { name: "interface-down" }],
        tool_calls: 3, supported: 0, rejected: 1, inconclusive: 1, answered: true },
    ],
    steps: [
      { seq: 1, kind: "bind", outcome: "ok", summary: "investigating cEdge-80 within incident P-7" },
      { seq: 2, kind: "context", outcome: "ok", summary: "the workspace's approved network context is applied" },
      { seq: 3, kind: "rca", outcome: "ok", summary: "the engine's verdict was read first (confirmed)" },
      { seq: 4, kind: "pass", outcome: "ok", summary: "pass 1: acme wan check → interface down — 3 lookups" },
      { seq: 5, kind: "stop", outcome: "cutoff", summary: "the investigation stopped at its time budget" },
      { seq: 6, kind: "diagnosis", outcome: "ok", summary: "evidence gathered, but no line of investigation was supported" },
    ],
    budget: { max_passes: 3, max_tool_calls: 32, max_tokens: 60000, wall_seconds: 100 },
    used: { passes: 1, tool_calls: 4, tokens: 2100, duration_ms: 41000 },
    cutoffs: ["time"],
    ...over,
  };
}

beforeEach(() => { aiInvestigation.mockReset(); failWith = null; });
afterEach(cleanup);

describe("words", () => {
  it("names every status, outcome and step, and keeps an unknown one verbatim", () => {
    expect(statusWord("concluded")).toBe("Investigation concluded");
    expect(statusWord("refused")).toBe("Investigation not run");
    expect(statusWord("newer_status")).toBe("newer_status");
    expect(outcomeWord("cutoff")).toBe("Stopped");
    expect(outcomeWord("not_found")).toBe("Not found");
    expect(stepWord("rca")).toBe("Engine verdict");
    expect(stepWord("future_kind")).toBe("future_kind");
  });
  it("says what was investigated", () => {
    expect(targetLine({ device: "edge-1", correlation_id: "P-1" })).toBe("edge-1, within incident P-1");
    expect(targetLine({})).toBe("the question, with no device or incident named");
  });
});

describe("InvestigationTrace", () => {
  it("shows the outcome, the engine's verdict labelled as the engine's, and numbered steps", () => {
    render(<InvestigationTrace trace={sample()} />);
    expect(screen.getByText("Investigation inconclusive")).toBeTruthy();
    expect(screen.getByText(/Investigated: cEdge-80, within incident P-7/)).toBeTruthy();
    const engine = screen.getByTestId("iris-investigation-engine");
    expect(engine.textContent).toContain("Correlation engine verdict: confirmed");
    expect(engine.textContent).toContain("only the engine names a root cause");
    const steps = screen.getAllByTestId("iris-investigation-step");
    expect(steps).toHaveLength(6);
    expect(steps[0].textContent).toContain("Scope");
    expect(steps[4].textContent).toContain("Stopped");
    expect(screen.getByTestId("iris-investigation-steps").tagName).toBe("OL");
    expect(screen.getByTestId("iris-investigation-cutoffs").textContent).toContain("time budget");
  });

  it("shows the methods considered, the passes and the budget on demand", () => {
    render(<InvestigationTrace trace={sample()} />);
    expect(screen.queryByTestId("iris-investigation-details")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Show details" }));
    const d = screen.getByTestId("iris-investigation-details");
    expect(d.textContent).toContain("acme-wan-check (your runbook, linked here) — applies");
    expect(d.textContent).toContain("ospf-adjacency (matches the question) — does not apply: no OSPF adjacency is discovered on cEdge-80");
    expect(d.textContent).toContain("acme-wan-check → interface-down");
    const budget = screen.getByTestId("iris-investigation-budget").textContent || "";
    expect(budget).toContain("1 of 3 passes");
    expect(budget).toContain("4 of 32 lookups");
    expect(budget).toContain("Read-only");
  });

  it("renders server text as text, never markup", () => {
    const evil = "<img src=x onerror=alert(1)>";
    const { container } = render(<InvestigationTrace trace={sample({
      steps: [{ seq: 1, kind: "bind", outcome: "ok", summary: evil }],
      engine: { tier: "confirmed", statement: evil },
    })} />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toContain(evil);
  });

  it("keeps fonts on the 14 / 16 px scale", () => {
    const { container } = render(<InvestigationTrace trace={sample()} />);
    fireEvent.click(screen.getByRole("button", { name: "Show details" }));
    container.querySelectorAll<HTMLElement>("[style]").forEach((el) => {
      const fs = el.style.fontSize;
      if (fs) expect(["14px", "16px"]).toContain(fs);
    });
  });

  it("reads a held trace back by id", async () => {
    aiInvestigation.mockResolvedValue(sample({ status: "concluded" }));
    render(<InvestigationTrace investigationId={ID} />);
    expect(await screen.findByText("Investigation concluded")).toBeTruthy();
    expect(aiInvestigation).toHaveBeenCalledWith(ID);
  });

  it("says a trace that is no longer held in a plain sentence", async () => {
    failWith = new Error('404 Not Found: {"error":"not found"}');
    render(<InvestigationTrace investigationId={ID} />);
    expect((await screen.findByRole("alert")).textContent).toBe("This investigation is no longer held.");
  });

  it("routes any other failure through operatorError — no developer text on screen", async () => {
    failWith = new Error('500 Internal Server Error: {"error":"dial tcp 10.0.0.5:5432: connect: connection refused"}');
    render(<InvestigationTrace investigationId={ID} />);
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).not.toMatch(/10\.0\.0\.5|dial tcp|\{/);
  });

  it("draws no engine block when no incident was in scope", () => {
    render(<InvestigationTrace trace={sample({ engine: undefined, target: { device: "edge-1" } })} />);
    expect(screen.queryByTestId("iris-investigation-engine")).toBeNull();
  });
});
