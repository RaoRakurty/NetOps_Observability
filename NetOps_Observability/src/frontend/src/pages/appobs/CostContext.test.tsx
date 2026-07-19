// CostContext.test.tsx (Wave 5 #18 slice 3) — the cost-context card renders
// only provider-billed figures with the honesty label, and every empty state
// says exactly what is missing / what to connect.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";

const h = vi.hoisted(() => ({
  loadInvestigationChanges: vi.fn(),
  loadCloudCosts: vi.fn(),
}));
vi.mock("./api", async (importOriginal) => ({
  ...(await importOriginal<object>()),
  loadInvestigationChanges: h.loadInvestigationChanges,
}));
vi.mock("./costContext", async (importOriginal) => ({
  ...(await importOriginal<object>()),
  loadCloudCosts: h.loadCloudCosts,
}));

import CostContext from "./CostContext";

const CHANGE = {
  time: "2026-07-10T05:46:00Z", app: "store-api", resource: "web01",
  changeType: "deploy", actor: "u", source: "cloudtrail", confidence: "confirmed",
  relatedSymptoms: [], offsetSeconds: -840,
  cloudRef: { provider: "aws", resourceId: "i-1", account: "111111111111",
    region: "us-west-2", consoleUrl: "", logUrl: "" },
};

afterEach(cleanup);
beforeEach(() => {
  h.loadInvestigationChanges.mockReset();
  h.loadCloudCosts.mockReset();
  h.loadInvestigationChanges.mockResolvedValue({
    changes: [CHANGE], onset: "2026-07-10T06:00:00Z",
    basis: "affected_scope", lookbackHours: 6,
  });
  h.loadCloudCosts.mockResolvedValue({
    costs: [
      { day: "2026-07-04", provider: "aws", account: "111111111111",
        service: "Amazon Elastic Compute Cloud - Compute", amount: 10, currency: "USD" },
      { day: "2026-07-10", provider: "aws", account: "111111111111",
        service: "Amazon Elastic Compute Cloud - Compute", amount: 12, currency: "USD" },
    ],
    count: 2, from: "2026-07-03", to: "2026-07-17", truncated: false,
  });
});

describe("<CostContext/>", () => {
  it("always carries the honesty label — context, not business impact", async () => {
    render(<CostContext id="cid-1" />);
    expect(await screen.findByText(/not a measured business impact/)).toBeTruthy();
  });

  it("renders provider-billed service figures for the affected account", async () => {
    render(<CostContext id="cid-1" />);
    expect(await screen.findByText("Amazon Elastic Compute Cloud - Compute")).toBeTruthy();
    expect(screen.getByText("22.00 USD in window")).toBeTruthy();
    expect(screen.getByText(/onset day 12\.00 USD/)).toBeTruthy();
    // scoped to the account recorded on the investigation's own changes
    expect(h.loadCloudCosts).toHaveBeenCalledWith(expect.objectContaining({
      provider: "aws", account: "111111111111",
      from: "2026-07-03", to: "2026-07-17",
    }));
  });

  it("says why when no cloud account is recorded on the changes", async () => {
    h.loadInvestigationChanges.mockResolvedValueOnce({
      changes: [], onset: "2026-07-10T06:00:00Z",
      basis: "no_affected_resources", lookbackHours: 6,
    });
    render(<CostContext id="cid-1" />);
    expect(await screen.findByText(/no cloud account is recorded/)).toBeTruthy();
    expect(h.loadCloudCosts).not.toHaveBeenCalled();
  });

  it("says what to connect when no cost data landed", async () => {
    h.loadCloudCosts.mockResolvedValueOnce({
      costs: [], count: 0, from: "2026-07-03", to: "2026-07-17", truncated: false,
    });
    render(<CostContext id="cid-1" />);
    expect(await screen.findByText(/connect billing access/)).toBeTruthy();
    expect(screen.getByText(/AWS Cost Explorer \/ Azure Cost Management Reader/)).toBeTruthy();
  });

  it("says why when the onset is unknown — no window is invented", async () => {
    h.loadInvestigationChanges.mockResolvedValueOnce({
      changes: [CHANGE], onset: "", basis: "onset_unknown", lookbackHours: 6,
    });
    render(<CostContext id="cid-1" />);
    expect(await screen.findByText(/onset time is unknown/)).toBeTruthy();
    expect(h.loadCloudCosts).not.toHaveBeenCalled();
  });

  it("degrades to an honest unavailable state on a read failure", async () => {
    h.loadInvestigationChanges.mockRejectedValueOnce(new Error("boom"));
    render(<CostContext id="cid-1" />);
    expect(await screen.findByText("cost context unavailable")).toBeTruthy();
  });
});
