// panels.honesty.test.tsx — the registry panels must never report an API FAILURE
// as GOOD NEWS. The class of defect: `catch {}` turned a rejected fetch into an
// empty array, which rendered as "All clear — no active alerts." and as five
// zeros in severity colours — an affirmative claim that the network is healthy,
// manufactured by the monitoring stack being down.
//
// The rule these tests lock in (same shape as FrontPage's usePoll {data, err}
// and the appobs tri-state): a panel may claim "nothing is wrong" ONLY when the
// API actually answered.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, waitFor } from "@testing-library/react";

const alerts = vi.fn();
const findings = vi.fn();
const tunnels = vi.fn();
const collectors = vi.fn();

vi.mock("../services/api", () => ({
  api: {
    alerts: (...a: unknown[]) => alerts(...a),
    findings: (...a: unknown[]) => findings(...a),
    tunnels: (...a: unknown[]) => tunnels(...a),
    collectors: (...a: unknown[]) => collectors(...a),
  },
}));
// The chart lib and the topology canvas are irrelevant to the honesty contract
// and pull heavy renderers; stub them.
vi.mock("../components/EChart", () => ({ default: () => <div data-testid="chart" /> }));
vi.mock("../features/topology/renderers/react-flow/TopologyCanvas", () => ({ default: () => <div /> }));
vi.mock("../context/shell", () => ({ useShell: () => ({ navigate: vi.fn() }) }));

import { PANELS, __resetBoardHealth } from "./panels";

// NB: drive rejections with mockImplementation(() => Promise.reject(...)) — the
// convention in cloudTopology.test.ts — so a prior resolving test can't leave a
// promise-tracking artifact that surfaces the rejection elsewhere.
beforeEach(() => {
  vi.clearAllMocks();
  __resetBoardHealth();
});
afterEach(cleanup);

describe("Active alerts panel", () => {
  it("says the alerts API is unreachable — NEVER 'All clear' — when the fetch rejects", async () => {
    alerts.mockImplementation(() => Promise.reject(new Error("500 Internal Server Error")));
    render(PANELS["active-alerts"].render());
    await waitFor(() => expect(alerts).toHaveBeenCalled());

    expect(await screen.findByText(/Unavailable/)).toBeTruthy();
    expect(screen.getByText(/Alerts API unreachable/)).toBeTruthy();
    // THE assertion this whole change exists for.
    expect(screen.queryByText(/All clear/)).toBeNull();
  });

  it("still says 'All clear' when the API genuinely answers with no alerts", async () => {
    alerts.mockImplementation(() => Promise.resolve([]));
    render(PANELS["active-alerts"].render());
    expect(await screen.findByText(/All clear — no active alerts\./)).toBeTruthy();
    expect(screen.queryByText(/Unavailable/)).toBeNull();
  });
});

describe("Alerts-by-severity panel", () => {
  it("renders an unavailable state instead of a row of zeros when the fetch rejects", async () => {
    alerts.mockImplementation(() => Promise.reject(new Error("500 Internal Server Error")));
    render(PANELS["alerts-severity"].render());
    await waitFor(() => expect(alerts).toHaveBeenCalled());

    expect(await screen.findByText(/severity counts are unknown/)).toBeTruthy();
    // No severity labels — a zero under "critical" is a claim, not an absence.
    expect(screen.queryByText("critical")).toBeNull();
    expect(screen.queryByText("warning")).toBeNull();
  });

  it("renders the severity counts when the API answers", async () => {
    alerts.mockImplementation(() => Promise.resolve([{ id: "a1", severity: "critical" }]));
    render(PANELS["alerts-severity"].render());
    expect(await screen.findByText("critical")).toBeTruthy();
    expect(screen.queryByText(/unknown/)).toBeNull();
  });
});

describe("other registry panels that used to render a failure as an absence", () => {
  it("recent incidents: a rejected findings read is not 'No correlated incidents'", async () => {
    findings.mockImplementation(() => Promise.reject(new Error("503")));
    render(PANELS["incidents"].render());
    expect(await screen.findByText(/Correlation API unreachable/)).toBeTruthy();
    expect(screen.queryByText(/No correlated incidents/)).toBeNull();
  });

  it("tunnels health: a rejected read never renders 'Tunnels down 0'", async () => {
    tunnels.mockImplementation(() => Promise.reject(new Error("503")));
    render(PANELS["tunnels-health"].render());
    expect(await screen.findByText(/tunnel state is unknown/)).toBeTruthy();
    expect(screen.queryByText("Tunnels down")).toBeNull();
  });

  it("site availability: a rejected collector read never renders a reachability percentage", async () => {
    collectors.mockImplementation(() => Promise.reject(new Error("503")));
    render(PANELS["site-availability"].render());
    expect(await screen.findByText(/reachability is unknown/)).toBeTruthy();
    expect(screen.queryByText(/targets reachable/)).toBeNull();
  });
});
