// Security.test.tsx (Wave 5 #16) — the security surface renders ONLY what the
// tenant-scoped API returned, labels each finding with its lane + provider, and
// its empty states are HONEST: "lanes not configured" is a different truth from
// "lanes flowing, nothing security-relevant landed".

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, cleanup } from "@testing-library/react";
import type { CloudSecurityFindingRow, CloudIngestionSource } from "../../services/api";

const h = vi.hoisted(() => {
  const finding = (over: Partial<CloudSecurityFindingRow> = {}): CloudSecurityFindingRow => ({
    time: "2026-07-18T12:00:00Z", lane: "waf", signal: "cloud_waf_log",
    app: "shop", resource: "edge-acl", source: "aws", severity: "warn",
    count: 42, detail: "rule rate-limit · BLOCK · host shop.example", ...over,
  });
  const src = (type: string, status: string): CloudIngestionSource =>
    ({ source_type: type, status });
  return {
    finding, src,
    mock: {
      cloudSecurity: vi.fn(async () => ({
        findings: [finding()], count: 1, window_hours: 24,
        lane_counts: { waf: 1, lb: 0, dns: 0 },
      })),
      cloudIngestion: vi.fn(async () => ({
        sources: [src("firewall_logs", "flowing"), src("lb_logs", "off"),
                  src("dns_logs", "permission_denied")],
        generated_at: "2026-07-18T12:00:00Z",
      })),
    },
  };
});
vi.mock("../../services/api", () => ({ api: h.mock }));

import Security, { laneCoverage, SECURITY_LANES } from "./Security";

const finding = h.finding;
const mock = h.mock;

beforeEach(() => { Object.values(mock).forEach((m) => m.mockClear()); });
afterEach(cleanup);

describe("laneCoverage", () => {
  it("joins the ingestion sources per lane; an absent source is honestly off", () => {
    const cov = laneCoverage([h.src("firewall_logs", "flowing")]);
    const by = Object.fromEntries(cov.map((c) => [c.lane, c.status]));
    expect(by).toEqual({ waf: "flowing", lb: "off", dns: "off" });
    expect(SECURITY_LANES.map((l) => l.lane)).toEqual(["waf", "lb", "dns"]);
  });
});

describe("Security surface", () => {
  it("renders findings with lane + provider labels and the lane coverage note", async () => {
    render(<Security />);
    expect(await screen.findByText("edge-acl")).toBeInTheDocument();
    expect(screen.getByText("WAF block")).toBeInTheDocument();
    expect(screen.getByText("rule rate-limit · BLOCK · host shop.example")).toBeInTheDocument();
    // coverage chips carry the honest per-lane statuses
    expect(screen.getByText("WAF blocks · Flowing")).toBeInTheDocument();
    expect(screen.getByText("LB errors · Not configured")).toBeInTheDocument();
    expect(screen.getByText("DNS failures · Permission denied")).toBeInTheDocument();
  });

  it("no lanes configured → says so, never a bare empty table", async () => {
    mock.cloudSecurity.mockResolvedValueOnce({
      findings: [], count: 0, window_hours: 24, lane_counts: { waf: 0, lb: 0, dns: 0 },
    });
    mock.cloudIngestion.mockResolvedValueOnce({
      sources: [h.src("firewall_logs", "off"), h.src("lb_logs", "off"), h.src("dns_logs", "off")],
      generated_at: "t",
    });
    render(<Security />);
    expect(await screen.findByText("No security lanes are delivering")).toBeInTheDocument();
  });

  it("lanes flowing but nothing landed → the OTHER honest empty state", async () => {
    mock.cloudSecurity.mockResolvedValueOnce({
      findings: [], count: 0, window_hours: 24, lane_counts: { waf: 0, lb: 0, dns: 0 },
    });
    render(<Security />);
    expect(await screen.findByText("No security findings in the window")).toBeInTheDocument();
    expect(screen.getByText(/nothing security-relevant landed/)).toBeInTheDocument();
  });

  it("an ingestion read failure never blanks the findings", async () => {
    mock.cloudIngestion.mockRejectedValueOnce(new Error("boom"));
    mock.cloudSecurity.mockResolvedValueOnce({
      findings: [finding({ resource: "still-here" })], count: 1,
      window_hours: 24, lane_counts: { waf: 1, lb: 0, dns: 0 },
    });
    render(<Security />);
    expect(await screen.findByText("still-here")).toBeInTheDocument();
  });

  it("a failed security read shows the load error, not an empty-success state", async () => {
    mock.cloudSecurity.mockRejectedValueOnce(new Error("503"));
    render(<Security />);
    expect(await screen.findByText("Unable to load security findings")).toBeInTheDocument();
  });
});
