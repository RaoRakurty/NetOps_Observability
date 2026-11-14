// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";

const correlationSimilar = vi.fn();
vi.mock("../../services/api", () => ({ api: { correlationSimilar: (...a: unknown[]) => correlationSimilar(...a) } }));

import RcaSimilarIncidents from "./RcaSimilarIncidents";

const caveat = "Similar is not the same cause: past incidents are context, never confirmation of this one.";

beforeEach(() => vi.clearAllMocks());
afterEach(cleanup);

describe("RcaSimilarIncidents", () => {
  it("lists matches with what they matched on, and the caveat", async () => {
    correlationSimilar.mockResolvedValue({
      verdict: "similar_incidents", examined: 4, incomplete: 0, window: "180d", note: "", caveat,
      matches: [{ correlation_id: "c-1", score: 0.8, strength: "strong", matched_on: ["same signature", "same device"], occurred_at: "2026-08-01T00:00:00Z" }],
    });
    render(<RcaSimilarIncidents correlationId="x" />);
    expect(await screen.findByText(/Strong match/)).toBeTruthy();
    expect(screen.getByText(/matched on same signature, same device/)).toBeTruthy();
    expect(screen.getByText(caveat)).toBeTruthy();
    expect(screen.getByRole("link").getAttribute("href")).toBe("#/investigate/rca?id=c-1");
  });

  it("says no earlier incident matches yet, with the count compared, and shows no near miss", async () => {
    correlationSimilar.mockResolvedValue({
      verdict: "no_similar_incident", examined: 7, incomplete: 2, window: "180d", matches: [], caveat,
      note: "Earlier incidents were compared, and none is similar enough to show.",
    });
    const { container } = render(<RcaSimilarIncidents correlationId="x" />);
    expect(await screen.findByText("No earlier incident matches yet.")).toBeTruthy();
    expect(screen.getByText(/7 closed incidents compared\./)).toBeTruthy();
    expect(container.querySelectorAll("a, li").length).toBe(0);
  });

  it("a fresh install with no history yet still answers honestly", async () => {
    correlationSimilar.mockResolvedValue({
      verdict: "no_similar_incident", examined: 0, incomplete: 0, window: "180d", matches: [], caveat,
      note: "",
    });
    const { container } = render(<RcaSimilarIncidents correlationId="x" />);
    expect(await screen.findByText("No earlier incident matches yet.")).toBeTruthy();
    expect(screen.queryByText(/compared/)).toBeNull();
    expect(screen.getByText(caveat)).toBeTruthy();
    expect(container.querySelectorAll("a, li").length).toBe(0);
  });

  it("shows a past case's recorded fix as history, and its note as plain text", async () => {
    correlationSimilar.mockResolvedValue({
      verdict: "similar_incidents", examined: 4, incomplete: 0, window: "180d", note: "", caveat,
      matches: [
        { correlation_id: "c-1", score: 0.8, strength: "strong", matched_on: ["same signature"], occurred_at: "2026-08-01T00:00:00Z",
          resolution: { kind: "config_rollback", label: "a configuration rollback", change_id: "CHG-1042",
            note: "<img src=x onerror=alert(1)>", recorded_at: "2026-08-01T03:00:00Z" } },
        { correlation_id: "c-2", score: 0.6, strength: "similar", matched_on: ["same device"], occurred_at: "2026-07-01T00:00:00Z" },
      ],
    });
    const { container } = render(<RcaSimilarIncidents correlationId="x" />);
    const fixes = await screen.findAllByTestId("similar-fix");
    expect(fixes.length).toBe(1); // the case without a recorded fix shows none
    expect(fixes[0].textContent).toMatch(/Last time this was fixed by a configuration rollback \(change CHG-1042\)/);
    expect(fixes[0].textContent).toMatch(/recorded by an operator on/);
    // Operator text renders escaped — never as markup.
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText("<img src=x onerror=alert(1)>")).toBeTruthy();
    expect(screen.getByText(caveat)).toBeTruthy();
  });

  it("a failed read says so", async () => {
    correlationSimilar.mockRejectedValue(new Error("500"));
    render(<RcaSimilarIncidents correlationId="x" />);
    expect(await screen.findByRole("alert")).toBeTruthy();
  });
});
