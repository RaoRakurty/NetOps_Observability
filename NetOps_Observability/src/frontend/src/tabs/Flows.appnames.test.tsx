// Flows conversations — app-name enrichment (#81 P3G): after the top-talkers
// table loads, the visible endpoint IPs go to /api/appid/resolve/batch ONCE and
// resolved IPs gain a secondary app-name line with a provenance tooltip;
// unresolved IPs render exactly as before (no "unknown" spam).

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, waitFor } from "@testing-library/react";

vi.mock("echarts-for-react", () => ({ default: () => <div data-testid="chart" /> }));

const topTalkers = vi.fn();
const flowsTopN = vi.fn();
const appIdResolveBatch = vi.fn();

vi.mock("../services/api", () => ({
  api: {
    topTalkers: (...a: unknown[]) => topTalkers(...a),
    flowsTopN: (...a: unknown[]) => flowsTopN(...a),
    appIdResolveBatch: (...a: unknown[]) => appIdResolveBatch(...a),
  },
}));

import { ConversationsSection } from "./Flows";
import { _resetAppNamesForTest } from "../services/appNames";

const q = { since: 3600, ftype: "", filters: {}, fkey: "", direction: "" } as never;

afterEach(cleanup);
beforeEach(() => {
  topTalkers.mockReset();
  flowsTopN.mockReset();
  appIdResolveBatch.mockReset();
  _resetAppNamesForTest();
  topTalkers.mockResolvedValue({
    data: [
      { src: "10.0.1.10", dst: "52.94.0.9", bytes_total: 3000, packets_total: 30, flows: 3 },
      { src: "192.0.2.7", dst: "8.8.8.8", bytes_total: 100, packets_total: 1, flows: 1 },
    ],
  });
  flowsTopN.mockResolvedValue({ data: [] });
  appIdResolveBatch.mockResolvedValue({
    "10.0.1.10": { app: "payroll", source: "cloud_tag", confidence: 0.95 },
    "52.94.0.9": { app: "AWS S3", source: "ip_catalog", confidence: 0.55 },
  });
});

describe("Flows conversations app-name enrichment", () => {
  it("batch-resolves visible IPs once and renders app chips with provenance", async () => {
    render(<ConversationsSection q={q} />);

    // the raw IPs render first
    await waitFor(() => expect(screen.getByText("10.0.1.10")).toBeInTheDocument());

    // one debounced batch call carrying only the visible IPs
    await waitFor(() => expect(appIdResolveBatch).toHaveBeenCalledTimes(1));
    const sent = appIdResolveBatch.mock.calls[0][0] as string[];
    expect(sent).toEqual(expect.arrayContaining(["10.0.1.10", "52.94.0.9", "192.0.2.7", "8.8.8.8"]));

    // resolved IPs gain the secondary app line + source tooltip
    await waitFor(() => expect(screen.getByText("payroll")).toBeInTheDocument());
    expect(screen.getByText("AWS S3")).toBeInTheDocument();
    expect(screen.getByText("payroll")).toHaveAttribute("title", "identified by cloud_tag");

    // unresolved IPs render exactly as before — the bare IP, no "unknown" chip
    expect(screen.getByText("8.8.8.8")).toBeInTheDocument();
    expect(screen.queryByText("unknown")).not.toBeInTheDocument();
  });
});
