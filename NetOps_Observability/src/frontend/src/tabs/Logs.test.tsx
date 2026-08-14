// Logs.test.tsx — sample honesty for the flows signal (finder 2026-08-14).
//
// netops-flows-* holds the router's 1:50 OpenSearch sample (ClickHouse keeps
// the canonical flow store). The Logs view previously rendered the sample's
// counts as exact — "showing X of Y matched", "This store holds N logs",
// "Export all (N)" — so an operator concluded ~50x too little traffic existed.
// These tests pin the disclosure: flows results SAY they are a 1:50 sample and
// that totals are estimates (×50); exact signals (syslog) stay undisclosed.

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, waitFor } from "@testing-library/react";

const searchLogs = vi.fn();
const logsRetention = vi.fn();

vi.mock("../services/api", () => ({
  api: {
    searchLogs: (...a: unknown[]) => searchLogs(...a),
    logsRetention: (...a: unknown[]) => logsRetention(...a),
    createSaved: vi.fn(),
    exportLogRows: vi.fn(),
    exportLogQuery: vi.fn(),
    exportStatus: vi.fn(),
  },
}));
vi.mock("../context/workspace", () => ({
  useWorkspace: () => ({ enabled: false, openInspector: vi.fn() }),
}));
vi.mock("../hooks/useAuth", () => ({
  useAuth: () => ({ user: { platform_admin: true } }),
}));

import Logs from "./Logs";

afterEach(cleanup);

const flowHit = {
  _index: "netops-flows-acme-2026.08.14",
  _id: "f1",
  _source: {
    timestamp: "2026-08-14T10:00:00Z",
    src_addr: "10.0.0.5",
    dst_addr: "10.0.0.9",
    message: "flow record",
    sample_rate: 50,
  },
};
const syslogHit = {
  _index: "netops-syslog-acme-2026.08.14",
  _id: "s1",
  _source: {
    timestamp: "2026-08-14T10:00:00Z",
    hostname: "router-01",
    severity: "err",
    message: "%LINK-3-UPDOWN: Interface Gi0/1, changed state to down",
  },
};

beforeEach(() => {
  searchLogs.mockReset();
  logsRetention.mockReset();
});

describe("Logs flows sample honesty", () => {
  it("disclosing the 1:50 sample on flows results (server metadata)", async () => {
    searchLogs.mockResolvedValue({
      hits: { total: { value: 123 }, hits: [flowHit] },
      sampling: { rate: 50, note: "1:50 sample - counts and totals are estimates" },
    });
    logsRetention.mockResolvedValue({
      signal: "flows", total: 1000, oldest: "2026-08-01T00:00:00Z", days: 13,
      sampling: { rate: 50 },
    });
    render(<Logs initialSignal="flows" />);
    const note = await screen.findByTestId("flows-sampling-note");
    expect(note.textContent).toContain("1:50 sample");
    expect(note.textContent).toContain("totals are estimates (×50)");
    // The retention line also carries the sample caveat, not a bare count.
    await waitFor(() => expect(logsRetention).toHaveBeenCalled());
    expect((await screen.findByText(/This store holds/)).textContent).toContain("1:50 sample");
  });

  it("falls back to the pinned rate when a response carries no metadata", async () => {
    // An older backend (or a proxy stripping the key) must not silently
    // re-present the sample as exact — the UI's own constant backstops it.
    searchLogs.mockResolvedValue({ hits: { total: { value: 7 }, hits: [flowHit] } });
    logsRetention.mockResolvedValue({ signal: "flows", total: 7, oldest: null, days: 0 });
    render(<Logs initialSignal="flows" />);
    const note = await screen.findByTestId("flows-sampling-note");
    expect(note.textContent).toContain("1:50 sample");
  });

  it("exact signals carry NO sampling note (syslog)", async () => {
    searchLogs.mockResolvedValue({ hits: { total: { value: 5 }, hits: [syslogHit] } });
    logsRetention.mockResolvedValue({ signal: "syslog", total: 5, oldest: "2026-08-01T00:00:00Z", days: 13 });
    render(<Logs initialSignal="syslog" />);
    await screen.findByText(/router-01/);
    expect(screen.queryByTestId("flows-sampling-note")).toBeNull();
    expect(screen.queryByText(/totals are estimates/)).toBeNull();
  });
});
