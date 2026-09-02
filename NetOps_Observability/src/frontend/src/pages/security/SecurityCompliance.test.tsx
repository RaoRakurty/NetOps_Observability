// SecurityCompliance.test.tsx — the control-set view. The vocabulary is the
// point: this page reports HARDENING FINDINGS ON THE TAGGED CONTROL SET, and
// must never claim framework compliance.

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, fireEvent, within } from "@testing-library/react";

const securityFindingFacets = vi.fn();

vi.mock("../../services/api", () => ({
  api: { securityFindingFacets: (...a: unknown[]) => securityFindingFacets(...a) },
}));
vi.mock("../ComplianceMonitoring", () => ({ default: () => <div>drift board</div> }));

import SecurityCompliance from "./SecurityCompliance";
import { FACETS } from "./fixtures";

afterEach(cleanup);
beforeEach(() => {
  securityFindingFacets.mockReset();
  securityFindingFacets.mockImplementation(async (q: { framework?: string }) => {
    if (!q?.framework) return FACETS;
    const per: Record<string, { pass: number; warn: number; fail: number }> = {
      CIS: { pass: 2, warn: 0, fail: 3 },
      "NIST-CSF": { pass: 1, warn: 0, fail: 0 },
      "PCI-DSS": { pass: 0, warn: 0, fail: 0 },
    };
    return { ...FACETS, status: per[q.framework] ?? { pass: 0, warn: 0, fail: 0 } };
  });
});

describe("Compliance — control set", () => {
  it("scores each tagged standard over its own findings", async () => {
    render(<SecurityCompliance />);
    const table = await screen.findByRole("table", { name: /hardening findings by standard/i });
    const cis = within(table).getByText("CIS").closest("tr")!;
    expect(within(cis).getByText("40%")).toBeTruthy();  // 2 pass of 5 scored
    const nist = within(table).getByText("NIST-CSF").closest("tr")!;
    expect(within(nist).getByText("100%")).toBeTruthy();
  });

  it("a standard with nothing scored is UNASSESSED, never 0% and never 100%", async () => {
    render(<SecurityCompliance />);
    const table = await screen.findByRole("table", { name: /hardening findings by standard/i });
    const pci = within(table).getByText("PCI-DSS").closest("tr")!;
    expect(within(pci).getByText("unassessed")).toBeTruthy();
  });

  it("labels the number as hardening findings on the tagged control set", async () => {
    render(<SecurityCompliance />);
    expect(await screen.findByText(/hardening findings on the tagged control set/i)).toBeTruthy();
    expect(screen.getByText(/it is not a framework compliance score/i)).toBeTruthy();
  });

  it("queries facets once per tagged standard, scoped to current verdicts", async () => {
    render(<SecurityCompliance />);
    await screen.findByRole("table", { name: /hardening findings by standard/i });
    const frameworks = securityFindingFacets.mock.calls.map((c) => c[0]?.framework).filter(Boolean);
    expect(frameworks.sort()).toEqual(["CIS", "NIST-CSF", "PCI-DSS"]);
    for (const call of securityFindingFacets.mock.calls) expect(call[0].current).toBe(true);
  });

  it("no tagged standard reads as an absence of assessment, not a pass", async () => {
    securityFindingFacets.mockResolvedValue({ ...FACETS, framework: {} });
    render(<SecurityCompliance />);
    expect(await screen.findByText(/absence of assessment, not a passing result/i)).toBeTruthy();
  });

  it("keeps the existing drift board as a sub-view rather than replacing it", async () => {
    render(<SecurityCompliance />);
    await screen.findByRole("table", { name: /hardening findings by standard/i });
    fireEvent.click(screen.getByRole("button", { name: "Drift & baselines" }));
    expect(screen.getByText("drift board")).toBeTruthy();
  });
});
