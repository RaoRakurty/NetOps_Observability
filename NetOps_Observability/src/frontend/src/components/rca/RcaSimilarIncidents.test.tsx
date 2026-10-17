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

  it("says No similar incident and shows no near miss", async () => {
    correlationSimilar.mockResolvedValue({
      verdict: "no_similar_incident", examined: 7, incomplete: 2, window: "180d", matches: [], caveat,
      note: "Earlier incidents were compared, and none is similar enough to show.",
    });
    const { container } = render(<RcaSimilarIncidents correlationId="x" />);
    expect(await screen.findByText("No similar incident.")).toBeTruthy();
    expect(container.querySelectorAll("a, li").length).toBe(0);
  });

  it("a failed read says so", async () => {
    correlationSimilar.mockRejectedValue(new Error("500"));
    render(<RcaSimilarIncidents correlationId="x" />);
    expect(await screen.findByRole("alert")).toBeTruthy();
  });
});
