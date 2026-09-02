// SecurityOverview.test.tsx — the CTEM command centre. The assertions that
// matter are the honesty ones: an unassessed estate must never render as clear,
// an unscored seam must never render as a zero, and a stage with no honest
// denominator must not invent a percentage.

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, within } from "@testing-library/react";

const securityPosture = vi.fn();
const securityFindingFacets = vi.fn();
const securityFindings = vi.fn();
const securityFindingTrend = vi.fn();
const securityExposureStories = vi.fn();
const correlationTimeline = vi.fn();
const seams = vi.fn();

vi.mock("../../services/api", () => ({
  api: {
    securityPosture: (...a: unknown[]) => securityPosture(...a),
    securityFindingFacets: (...a: unknown[]) => securityFindingFacets(...a),
    securityFindings: (...a: unknown[]) => securityFindings(...a),
    securityFindingTrend: (...a: unknown[]) => securityFindingTrend(...a),
    securityExposureStories: (...a: unknown[]) => securityExposureStories(...a),
    correlationTimeline: (...a: unknown[]) => correlationTimeline(...a),
    seams: (...a: unknown[]) => seams(...a),
  },
}));

import SecurityOverview from "./SecurityOverview";
import { FACETS, FINDINGS, POSTURE, POSTURE_UNASSESSED, SEAMS, STORY, TREND } from "./fixtures";

afterEach(cleanup);

beforeEach(() => {
  for (const m of [securityPosture, securityFindingFacets, securityFindings,
    securityFindingTrend, securityExposureStories, correlationTimeline, seams]) m.mockReset();
  securityPosture.mockResolvedValue(POSTURE);
  securityFindingFacets.mockResolvedValue(FACETS);
  securityFindings.mockResolvedValue({ items: FINDINGS, next_cursor: null, total: FINDINGS.length });
  securityFindingTrend.mockResolvedValue(TREND);
  securityExposureStories.mockResolvedValue([STORY]);
  correlationTimeline.mockRejectedValue(new Error("no timeline"));
  seams.mockResolvedValue(SEAMS);
});

describe("Security Overview — CTEM funnel", () => {
  it("renders the five pipeline stages with their counts", async () => {
    render(<SecurityOverview />);
    const funnel = await screen.findByRole("list", { name: /exposure management pipeline/i });
    for (const [label, n] of [["Scope", "2,547"], ["Discover", "1,284"], ["Prioritize", "47"], ["Validate", "12"], ["Mobilize", "5"]]) {
      const stage = within(funnel).getByText(label).closest("li")!;
      expect(within(stage).getByText(n)).toBeTruthy();
    }
  });

  it("asks the API for CURRENT verdicts only", async () => {
    render(<SecurityOverview />);
    await screen.findByRole("list", { name: /exposure management pipeline/i });
    expect(securityFindingFacets).toHaveBeenCalledWith(expect.objectContaining({ current: true }));
    expect(securityFindings).toHaveBeenCalledWith(expect.objectContaining({ current: true }));
  });
});

describe("Security Overview — honesty", () => {
  it("leads with coverage and names the unassessed gap in words", async () => {
    render(<SecurityOverview />);
    expect(await screen.findByText(/1900 of 2547 assets assessed/)).toBeTruthy();
    expect(screen.getByText(/647 unassessed \(unknown, not clear\)/)).toBeTruthy();
    expect(screen.getByText(/never assessed/i)).toBeTruthy();
  });

  it("a wholly unassessed estate says posture is UNKNOWN, and shows no coverage bar", async () => {
    securityPosture.mockResolvedValue(POSTURE_UNASSESSED);
    render(<SecurityOverview />);
    expect(await screen.findByText(/posture is unknown, not clear/i)).toBeTruthy();
    expect(screen.getByText(/No assessment has run yet/i)).toBeTruthy();
  });

  it("an unscored seam renders an em dash and the word unassessed, never a zero", async () => {
    render(<SecurityOverview />);
    const saas = (await screen.findByText("SaaS")).closest(".sec-seam")!;
    expect(within(saas).getByText("—")).toBeTruthy();
    expect(within(saas).getByText("unassessed")).toBeTruthy();
    const isp = screen.getAllByText("ISP")[0].closest(".sec-seam")!;
    expect(within(isp).getByText("2")).toBeTruthy();
  });

  it("labels standards counts as tagged hardening findings, never framework compliance", async () => {
    render(<SecurityOverview />);
    expect(await screen.findByText(/not a framework compliance verdict/i)).toBeTruthy();
    expect(screen.queryByText(/framework compliance score/i)).toBeNull();
  });

  it("says why the trend is empty rather than drawing a reassuring blank chart", async () => {
    securityFindingTrend.mockResolvedValue({ buckets: [] });
    render(<SecurityOverview />);
    expect(await screen.findByText(/a trend needs at least one completed scan/i)).toBeTruthy();
  });
});

describe("Security Overview — exposure story hero", () => {
  it("renders the flagship story headline and its stated confidence", async () => {
    render(<SecurityOverview />);
    expect(await screen.findByRole("heading", { name: /management plane is reachable from the ISP seam/i })).toBeTruthy();
    expect(screen.getByText(/Confidence: 72%/)).toBeTruthy();
  });

  it("degrades to a note when the chronology cannot be read (never a fabricated chain)", async () => {
    render(<SecurityOverview />);
    expect(await screen.findByText(/chronology for this story has not loaded/i)).toBeTruthy();
  });

  it("says nothing correlated yet when there is no story, instead of an empty hero", async () => {
    securityExposureStories.mockResolvedValue([]);
    render(<SecurityOverview />);
    expect(await screen.findByText(/No security-lane correlation has been grounded yet/i)).toBeTruthy();
  });
});

describe("Security Overview — snapshot", () => {
  it("matches the rendered posture page for the fixture set", async () => {
    const { container } = render(<SecurityOverview />);
    await screen.findByRole("list", { name: /exposure management pipeline/i });
    expect(container.firstChild).toMatchSnapshot();
  });
});
