// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// InvestigationChanges.test.tsx (Wave 4 #12 slice 3) — the change→incident
// card renders only recorded changes with exact onset-relative wording, and
// every empty state says WHY there is nothing to show.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";

const h = vi.hoisted(() => ({
  api: {
    cloudInvestigationChanges: vi.fn(async () => ({
      changes: [], count: 0, onset: "2026-07-18T12:00:00Z",
      basis: "affected_scope", lookback_hours: 6,
    })),
  },
}));
vi.mock("../../services/api", () => ({ api: h.api }));

import InvestigationChanges, { fmtOffset } from "./InvestigationChanges";

afterEach(cleanup);
beforeEach(() => h.api.cloudInvestigationChanges.mockClear());

describe("fmtOffset", () => {
  it("renders exact onset-relative wording", () => {
    expect(fmtOffset(-840)).toBe("14m before onset");
    expect(fmtOffset(840)).toBe("14m after onset");
    expect(fmtOffset(0)).toBe("at onset");
    expect(fmtOffset(10)).toBe("at onset"); // sub-30s jitter is not a claim
    expect(fmtOffset(-7500)).toBe("2h 05m before onset");
  });
});

describe("<InvestigationChanges/>", () => {
  it("says exactly why when no changes were recorded in the window", async () => {
    render(<InvestigationChanges id="cid-1" />);
    expect(await screen.findByText("no changes recorded in the window")).toBeTruthy();
    expect(h.api.cloudInvestigationChanges).toHaveBeenCalledWith("cid-1");
  });

  it("says why when the object records no affected resources", async () => {
    h.api.cloudInvestigationChanges.mockResolvedValueOnce({
      changes: [], count: 0, onset: "2026-07-18T12:00:00Z",
      basis: "no_affected_resources", lookback_hours: 6,
    } as never);
    render(<InvestigationChanges id="cid-1" />);
    expect(await screen.findByText(/no affected cloud resources/)).toBeTruthy();
  });

  it("renders change · actor · time-relative-to-onset from recorded rows", async () => {
    h.api.cloudInvestigationChanges.mockResolvedValueOnce({
      changes: [{
        time: "2026-07-18T11:46:00Z", app: "store-api", resource: "web01",
        change_type: "deploy", actor: "role/deployer", source: "cloudtrail",
        confidence: "confirmed", related_symptoms: [], offset_seconds: -840,
        cloud_ref: { provider: "aws", resource_id: "i-1", console_url: "", log_url: "" },
      }],
      count: 1, onset: "2026-07-18T12:00:00Z", basis: "affected_scope", lookback_hours: 6,
    } as never);
    render(<InvestigationChanges id="cid-1" />);
    expect(await screen.findByText("14m before onset")).toBeTruthy();
    expect(screen.getByText("deploy")).toBeTruthy();
    expect(screen.getByText("· web01")).toBeTruthy();
    expect(screen.getByText("by role/deployer")).toBeTruthy();
  });
});
