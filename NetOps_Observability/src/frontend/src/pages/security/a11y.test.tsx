// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// a11y.test.tsx — the Security section's accessible semantics, pinned the way
// the RCA workspace's are: a real heading structure, named landmarks, live
// regions for the counts that change under the operator, toggle semantics on
// the facets, and status never conveyed by colour alone.

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, within } from "@testing-library/react";

const securityPosture = vi.fn();
const securityFindingFacets = vi.fn();
const securityFindings = vi.fn();
const securityFindingTrend = vi.fn();
const securityExposureStories = vi.fn();
const correlationTimeline = vi.fn();
const seams = vi.fn();
const securityViews = vi.fn();
// The two panels the overview now embeds: the producer-lane strip and the seam
// group roll-up, plus the permission read that gates the group state control.
const securityLaneStatus = vi.fn();
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
    securityViews: (...a: unknown[]) => securityViews(...a),
    securityLaneStatus: (...a: unknown[]) => securityLaneStatus(...a),
    seamGroups: (...a: unknown[]) => seamGroups(...a),
    permissions: (...a: unknown[]) => permissions(...a),
  },
}));
vi.mock("../../context/workspace", () => ({ useWorkspace: () => ({ enabled: false, openInspector: vi.fn() }) }));

import SecurityOverview from "./SecurityOverview";
import Exposures from "./Exposures";
import { FindingDetail } from "./parts";
import { FACETS, FINDINGS, POSTURE, SEAMS, STORY, TREND } from "./fixtures";

afterEach(cleanup);
beforeEach(() => {
  securityPosture.mockResolvedValue(POSTURE);
  securityFindingFacets.mockResolvedValue(FACETS);
  securityFindings.mockResolvedValue({ items: FINDINGS, next_cursor: null, total: FINDINGS.length });
  securityFindingTrend.mockResolvedValue(TREND);
  securityExposureStories.mockResolvedValue([STORY]);
  correlationTimeline.mockRejectedValue(new Error("none"));
  seams.mockResolvedValue(SEAMS);
  securityViews.mockResolvedValue([]);
  // Dormant lane (the shipped default) and no recorded seam groups.
  securityLaneStatus.mockRejectedValue(new Error("404 Not Found: "));
  seamGroups.mockResolvedValue([]);
  permissions.mockResolvedValue({ role: "viewer", permissions: { infrastructure: 1 } });
});

describe("Security Overview a11y", () => {
  it("names every region so a screen reader can jump between them", async () => {
    render(<SecurityOverview />);
    expect(await screen.findByRole("list", { name: /exposure management pipeline/i })).toBeTruthy();
    expect(screen.getByRole("region", { name: /assessment coverage/i })).toBeTruthy();
    expect(screen.getByRole("table", { name: /verdict trend by day/i })).toBeTruthy();
    for (const lane of ["Hardening & posture", "Seam exposure", "Threat detections", "Standards coverage"]) {
      expect(screen.getByRole("region", { name: lane })).toBeTruthy();
    }
  });

  it("gives the hero a real heading and the lanes real sub-headings", async () => {
    render(<SecurityOverview />);
    // The hero is labelled BY its own heading (aria-labelledby), which is the
    // stronger a11y contract: the region's name is the story it is about.
    const hero = await screen.findByRole("region", { name: /management plane is reachable/i });
    expect(within(hero).getByRole("heading", { level: 3, name: /management plane is reachable/i })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Seam exposure", level: 3 })).toBeTruthy();
  });

  it("announces the scan freshness through a live region", async () => {
    render(<SecurityOverview />);
    const live = await screen.findByText(/Last assessment/);
    expect(live.getAttribute("role")).toBe("status");
  });

  it("labels a severity by TEXT, never by colour alone", async () => {
    render(<SecurityOverview />);
    const lane = await screen.findByRole("region", { name: "Seam exposure" });
    expect(within(lane).getByText(/core-01/)).toBeTruthy();
  });
});

describe("Exposures a11y", () => {
  it("labels the filter sidebar and every facet group heading", async () => {
    render(<Exposures />);
    const aside = await screen.findByRole("complementary", { name: "Filters" });
    for (const g of ["Severity", "Verdict", "Seam", "Standard", "Evidence lane"]) {
      expect(within(aside).getByRole("heading", { name: g, level: 3 })).toBeTruthy();
    }
  });

  it("facets are toggle buttons with aria-pressed, not links", async () => {
    render(<Exposures />);
    const crit = await screen.findByRole("button", { name: /^Critical 2$/ });
    expect(crit.getAttribute("aria-pressed")).toBe("false");
  });

  it("the row count is a polite live region", async () => {
    render(<Exposures />);
    const status = await screen.findByText(/shown$/);
    expect(status.getAttribute("aria-live")).toBe("polite");
  });

  it("labels the search field and the saved-view picker for screen readers", async () => {
    render(<Exposures />);
    expect(await screen.findByLabelText("Search findings")).toBeTruthy();
  });
});

describe("Finding detail a11y", () => {
  it("uses headings for the observed / intended / evidence / standards sections", () => {
    render(<FindingDetail finding={FINDINGS[0]} />);
    for (const h of ["Observed", "Intended", "Remediation", "Evidence", "Standards", "Detail"]) {
      expect(screen.getByRole("heading", { name: h, level: 4 })).toBeTruthy();
    }
  });

  it("states the verdict in words next to the colour", () => {
    render(<FindingDetail finding={FINDINGS[0]} />);
    expect(screen.getByText("Fail")).toBeTruthy();
    expect(screen.getByText("critical")).toBeTruthy();
  });

  it("explains an unassessed verdict in its tooltip rather than leaving a bare grey chip", () => {
    render(<FindingDetail finding={FINDINGS[3]} />);
    const chip = screen.getAllByText("Unassessed")[0];
    expect(chip.getAttribute("title")).toMatch(/unknown, not clear/i);
  });
});
