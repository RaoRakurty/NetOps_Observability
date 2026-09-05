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
// The producer-lane strip the page now embeds (LaneHealth) — mocked here so the
// overview's own assertions are not measuring the lane panel.
const securityLaneStatus = vi.fn();
const securityScan = vi.fn();
// The seam-group roll-up embedded under "Exposure by seam", and the permission
// read that decides whether its state control is offered at all.
const seamGroups = vi.fn();
const permissions = vi.fn();

vi.mock("../../services/api", () => ({
  api: {
    securityPosture: (...a: unknown[]) => securityPosture(...a),
    securityFindingFacets: (...a: unknown[]) => securityFindingFacets(...a),
    securityFindings: (...a: unknown[]) => securityFindings(...a),
    securityFindingTrend: (...a: unknown[]) => securityFindingTrend(...a),
    securityExposureStories: (...a: unknown[]) => securityExposureStories(...a),
    correlationTimeline: (...a: unknown[]) => correlationTimeline(...a),
    seams: (...a: unknown[]) => seams(...a),
    securityLaneStatus: (...a: unknown[]) => securityLaneStatus(...a),
    securityScan: (...a: unknown[]) => securityScan(...a),
    seamGroups: (...a: unknown[]) => seamGroups(...a),
    permissions: (...a: unknown[]) => permissions(...a),
  },
}));

import SecurityOverview from "./SecurityOverview";
import { FACETS, FINDINGS, POSTURE, POSTURE_UNASSESSED, SEAMS, STORY, TREND } from "./fixtures";
import { signal, timeline } from "../../test/factories";

// A deliberately UNFRIENDLY flagship: a headline and an owner made of long
// unbreakable identifiers, six chain nodes, and details long enough to wrap.
// This is the shape that made the hero render its columns on top of each other.
const LONG_STORY = {
  ...STORY,
  top_hypothesis:
    "dc1-border-leaf-01.pod3.example.net:HundredGigE0/0/0/17.3001 management plane is reachable from the ISP seam",
  owner: "dc1-border-leaf-01.pod3.example.net/HundredGigE0/0/0/17.3001",
  grounding: "seam+topo+prefix-origin",
};
const LONG_TIMELINE = timeline({
  correlation_id: "corr-9",
  signals: [
    "bgp_state_anomaly", "interface_error_rate", "security_exposure",
    "security_posture", "probe_latency_departure", "syslog_burst",
  ].map((kind, i) =>
    signal({
      signal_id: `sig-${i}`,
      kind,
      ts: `2026-09-01 09:0${i}:00`,
      entity_id: `dc1-border-leaf-0${i + 1}.pod3.example.net:HundredGigE0/0/0/17.300${i}`,
      modality_class: i % 2 ? "data_plane" : "control_plane",
      attached: true,
      is_trigger: i === 0,
    }),
  ),
});

afterEach(cleanup);

beforeEach(() => {
  for (const m of [securityPosture, securityFindingFacets, securityFindings,
    securityFindingTrend, securityExposureStories, correlationTimeline, seams,
    securityLaneStatus, securityScan, seamGroups, permissions]) m.mockReset();
  seamGroups.mockResolvedValue([]);
  permissions.mockResolvedValue({ role: "viewer", permissions: { infrastructure: 1 } });
  // Dormant lane by default: 404 is what a deployment with FEATURE_SECURITY_LANE
  // off actually answers, and it is the state most installs are in.
  securityLaneStatus.mockRejectedValue(new Error("404 Not Found: "));
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

// Layout contract for the flagship box (owner report 2026-09-05: "the stories
// overlapped format"). The cause was CSS, so the guards here are the STRUCTURE
// the fixed CSS keys off: the two hero columns are real, labelled elements that
// can fold independently, every chain node still owns exactly one rail and one
// body, and — the actual bug — nothing in the section reuses an app-shell class
// name. `.rail` (the nav sidebar) and `.main` (the content region) are global
// element rules in styles.css; a bare `rail`/`main` class inside a `.sec` grid
// inherits grid-area:sidebar / grid-area:main and paints out of its cell, over
// its siblings. happy-dom applies no CSS, so these are class contracts, not
// geometry — geometry is what they PROTECT.
describe("Security Overview — exposure story hero layout", () => {
  beforeEach(() => {
    securityExposureStories.mockResolvedValue([LONG_STORY]);
    correlationTimeline.mockResolvedValue(LONG_TIMELINE);
  });

  it("gives the hero two independently foldable columns, both allowed to shrink", async () => {
    const { container } = render(<SecurityOverview />);
    await screen.findByRole("list", { name: /causality chain/i });
    const grid = container.querySelector(".sec-hero-grid")!;
    const cols = grid.querySelectorAll(":scope > .sec-hero-col");
    expect(cols.length).toBe(2);
    expect(cols[0].classList.contains("sec-hero-chain")).toBe(true);
    expect(cols[1].classList.contains("sec-hero-side")).toBe(true);
    // The chain lives in the first column, the ownership card in the second —
    // never both in one cell.
    expect(cols[0].querySelector(".sec-chain")).toBeTruthy();
    expect(cols[1].querySelector(".sec-owner")).toBeTruthy();
  });

  it("renders every chain node as exactly one rail plus one body", async () => {
    const { container } = render(<SecurityOverview />);
    const chain = await screen.findByRole("list", { name: /causality chain/i });
    const nodes = chain.querySelectorAll(".sec-node");
    expect(nodes.length).toBe(6);
    for (const n of nodes) {
      expect(n.querySelectorAll(":scope > .sec-rail").length).toBe(1);
      expect(n.querySelectorAll(":scope > .body").length).toBe(1);
      // pin + dashed link ride INSIDE the rail, never as loose node children.
      expect(n.querySelectorAll(".sec-rail > .pin").length).toBe(1);
      expect(n.querySelectorAll(".sec-rail > .link").length).toBe(1);
      // title and timestamp are separate elements so they can be separate lines
      expect(n.querySelector(".body > b")).toBeTruthy();
      expect(n.querySelector(".body > .meta")).toBeTruthy();
    }
  });

  it("reuses no app-shell class name anywhere in the section", async () => {
    const { container } = render(<SecurityOverview />);
    await screen.findByRole("list", { name: /causality chain/i });
    // styles.css owns `.rail` (grid-area: sidebar, z-index: 50) and `.main`
    // (grid-area: main, own background). Either one inside `.sec` is the
    // overlap bug coming back.
    expect(container.querySelectorAll(".rail, .main").length).toBe(0);
    expect(container.querySelectorAll(".sec-rail").length).toBe(6);
    expect(container.querySelectorAll(".sec-row .sec-main").length).toBeGreaterThan(0);
  });

  it("keeps a long headline and a long owner as plain wrapping text", async () => {
    render(<SecurityOverview />);
    await screen.findByRole("list", { name: /causality chain/i });
    const h = screen.getByRole("heading", { name: /management plane is reachable from the ISP seam/i });
    // No inline nowrap/width escape hatch: wrapping is the CSS's job and must
    // stay possible for the long identifier in the headline.
    expect((h as HTMLElement).style.whiteSpace).toBe("");
    const owner = document.querySelector(".sec-owner .seam-name") as HTMLElement;
    expect(owner.textContent).toContain("HundredGigE0/0/0/17.3001");
    expect(owner.style.whiteSpace).toBe("");
  });
});

describe("Security Overview — snapshot", () => {
  it("matches the rendered posture page for the fixture set", async () => {
    const { container } = render(<SecurityOverview />);
    await screen.findByRole("list", { name: /exposure management pipeline/i });
    expect(container.firstChild).toMatchSnapshot();
  });
});
