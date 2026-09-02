// RcaFeedbackTile.test.tsx — "Verdict feedback (30 d)" on the NOC scorecard.
// The tile exists to report ONE number honestly, so that is what is pinned:
// an empty sample has no false-positive rate ("Not enough feedback yet"), never
// 0 % — and a real sample reports the rate, the denominator and the split.

import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import type { RcaFeedbackSummary } from "../../services/api";

const EMPTY: RcaFeedbackSummary = {
  days: 30, since: "2026-08-03T00:00:00Z", n: 0,
  counts: { correct: 0, wrong: 0, partial: 0 }, false_positive_rate: null, by_template: [],
};
const SAMPLED: RcaFeedbackSummary = {
  days: 30, since: "2026-08-03T00:00:00Z", n: 20,
  counts: { correct: 14, wrong: 4, partial: 2 }, false_positive_rate: 0.2,
  by_template: [{ template: "wan_brownout", correct: 10, wrong: 3, partial: 1, n: 14, false_positive_rate: 0.214 }],
};

function mockApi(summary?: RcaFeedbackSummary) {
  const fn = vi.fn(() => (summary ? Promise.resolve(summary) : Promise.reject(new Error("503 unavailable"))));
  vi.doMock("../../services/api", () => ({ api: { rcaFeedbackSummary: fn } }));
  return fn;
}

async function mount() {
  const { default: Tile } = await import("./RcaFeedbackTile");
  return render(<Tile />);
}

afterEach(() => { cleanup(); vi.resetModules(); vi.clearAllMocks(); });

describe("RcaFeedbackTile", () => {
  it("asks for a 30-day window", async () => {
    const fn = mockApi(EMPTY);
    await mount();
    expect(await screen.findByText(/Verdict feedback \(30 d\)/)).toBeTruthy();
    expect(fn).toHaveBeenCalledWith(30);
  });

  it('says "Not enough feedback yet" for an empty sample — never 0 %', async () => {
    mockApi(EMPTY);
    const { container } = await mount();
    expect(await screen.findByText("Not enough feedback yet")).toBeTruthy();
    expect(screen.getByText(/No operator verdict recorded in this window/)).toBeTruthy();
    expect(container.textContent).not.toContain("0%");
  });

  it("reports the rate, the denominator and the split for a real sample", async () => {
    mockApi(SAMPLED);
    await mount();
    expect(await screen.findByText("20%")).toBeTruthy();
    expect(screen.getByText("4 of 20 judged wrong")).toBeTruthy();
    expect(screen.getByText("correct / partially / wrong")).toBeTruthy();
    expect(screen.getByText("14")).toBeTruthy();
    expect(screen.getByText("2")).toBeTruthy();
  });

  it("says the read failed rather than rendering zeros", async () => {
    mockApi(undefined);
    await mount();
    expect(await screen.findByText(/Verdict feedback is unavailable right now/)).toBeTruthy();
    expect(screen.queryByText("Not enough feedback yet")).toBeNull();
  });

  it("ratePct returns null for an empty or rate-less summary", async () => {
    mockApi(EMPTY);
    const { ratePct } = await import("./RcaFeedbackTile");
    expect(ratePct(null)).toBeNull();
    expect(ratePct(EMPTY)).toBeNull();
    expect(ratePct({ ...SAMPLED, false_positive_rate: null })).toBeNull();
    expect(ratePct(SAMPLED)).toBe(20);
  });
});
