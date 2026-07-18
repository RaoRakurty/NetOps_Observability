// RcaReports.test — the management library page (#113). Pins: promoted rows
// render with their report identity, at-a-glance line and AUTO/MANUAL basis
// badge; the honest empty state points back to Correlations (candidates live
// there); truncation is disclosed, never silent; and the pure badge/duration
// helpers behave.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, cleanup } from "@testing-library/react";

const h = vi.hoisted(() => ({
  mock: {
    rcaLibrary: vi.fn(async (): Promise<any> => ({ reports: [], evaluated: 0, truncated: false, window_days: 30 })),
    downloadRcaReport: vi.fn(async (): Promise<"pdf"> => "pdf"),
  },
}));
vi.mock("../services/api", () => ({ api: h.mock }));

import RcaReports, { fmtDurMs, promotionBadge } from "./RcaReports";
import type { RcaLibraryReport } from "../services/api";

const mock = h.mock;

function libRow(over: Partial<RcaLibraryReport> = {}): RcaLibraryReport {
  return {
    correlation_id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    display_id: "P-AAAAAA",
    report_type: "Incident Analysis — Fault Confirmed",
    title: "Private-app outage — IPsec tunnel down",
    at_a_glance: {
      where: "dallas-dx-1 (ipsec seam (localization domain))",
      what: "The IPsec tunnel's IKE/DPD keepalives failed.",
      owners_label: "Possible owner(s)", owners: ["ISP / carrier"],
    },
    states: { incident: "recovered", analysis: "confirmed", impact: "confirmed" },
    times: { start: "2026-07-12 18:10:00", end: "2026-07-12 18:30:00", duration_ms: 1200000 },
    promotion: { promoted: true, basis: "auto", reason: "meets the real-outage criteria" },
    validation: false,
    ...over,
  } as RcaLibraryReport;
}

beforeEach(() => {
  Object.values(mock).forEach((m) => m.mockClear());
  mock.rcaLibrary.mockResolvedValue({ reports: [], evaluated: 0, truncated: false, window_days: 30 });
});
afterEach(cleanup);

describe("RcaReports page", () => {
  it("renders the honest empty state pointing back to Correlations", async () => {
    render(<RcaReports />);
    await waitFor(() => {
      expect(screen.getByText(/No promoted outages in this window — candidates live in Correlations\./)).toBeTruthy();
    });
  });

  it("lists promoted outages with identity, at-a-glance and basis badges", async () => {
    mock.rcaLibrary.mockResolvedValue({
      reports: [
        libRow(),
        libRow({
          correlation_id: "cccccccc-cccc-cccc-cccc-cccccccccccc", display_id: "P-CCCCCC",
          title: "Middle-mile latency escalation",
          promotion: {
            promoted: true, basis: "manual", reason: "manually promoted",
            manual: { promoted_by: "ops@acme", promoted_at: "2026-07-18 12:00:00 UTC" },
          },
        }),
      ],
      evaluated: 2, truncated: false, window_days: 30,
    });
    render(<RcaReports />);
    await waitFor(() => expect(screen.getByText("P-AAAAAA")).toBeTruthy());
    expect(screen.getByText("Private-app outage — IPsec tunnel down")).toBeTruthy();
    expect(screen.getAllByText(/dallas-dx-1/).length).toBeGreaterThan(0);
    expect(screen.getByText("AUTO")).toBeTruthy();
    const manual = screen.getByText("MANUAL");
    expect(manual.getAttribute("title")).toContain("ops@acme");
    // both rows link into the RCA workspace
    const links = screen.getAllByText("Open workspace") as HTMLAnchorElement[];
    expect(links).toHaveLength(2);
    expect(links[0].getAttribute("href")).toContain("#/monitoring/correlations?id=");
    expect(screen.getByText("2 promoted")).toBeTruthy();
  });

  it("discloses evaluation truncation — never a silent cap", async () => {
    mock.rcaLibrary.mockResolvedValue({
      reports: [libRow()], evaluated: 100, truncated: true, window_days: 30,
    });
    render(<RcaReports />);
    await waitFor(() => {
      expect(screen.getByText(/Evaluated the 100 most recent qualifying candidates/)).toBeTruthy();
    });
  });
});

describe("promotionBadge / fmtDurMs (pure)", () => {
  it("labels auto vs manual and attributes the manual promoter", () => {
    expect(promotionBadge(libRow()).label).toBe("AUTO");
    const m = promotionBadge(libRow({
      promotion: {
        promoted: true, basis: "manual", reason: "x",
        manual: { promoted_by: "ops@acme", promoted_at: "2026-07-18 12:00:00 UTC", note: "board review" },
      },
    }));
    expect(m.label).toBe("MANUAL");
    expect(m.tip).toContain("ops@acme");
    expect(m.tip).toContain("board review");
  });

  it("formats durations compactly and never claims a zero duration", () => {
    expect(fmtDurMs(0)).toBe("—");
    expect(fmtDurMs(45_000)).toBe("45s");
    expect(fmtDurMs(120_000)).toBe("2m");
    expect(fmtDurMs(1_200_000)).toBe("20m");
    expect(fmtDurMs(5_400_000)).toBe("1h 30m");
  });
});
