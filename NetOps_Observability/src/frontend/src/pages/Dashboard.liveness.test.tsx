// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Dashboard.liveness.test.tsx — the board header's liveness indicator must be a
// statement about DATA, not about time passing. It used to be a pulsing "Live"
// dot beside an "as of HH:MM" clock driven by a local setInterval that never
// touched the network, so a total backend outage still read as a live board.
// Now every panel poll reports its outcome into the board-health signal and the
// header states what that says.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, waitFor } from "@testing-library/react";

// Every API call this board makes fails. A Proxy covers the whole surface so the
// test doesn't have to enumerate the registry's data sources.
const failing = vi.fn(() => Promise.reject(new Error("500 Internal Server Error")));
const ok = vi.fn(() => Promise.resolve([]));
let mode: "fail" | "ok" = "fail";

vi.mock("../services/api", () => ({
  api: new Proxy(
    {},
    { get: () => (...a: unknown[]) => (mode === "fail" ? failing() : ok(...(a as []))) },
  ),
}));
vi.mock("../components/EChart", () => ({ default: () => <div data-testid="chart" /> }));
vi.mock("../features/topology/renderers/react-flow/TopologyCanvas", () => ({ default: () => <div /> }));
vi.mock("../context/shell", () => ({ useShell: () => ({ navigate: vi.fn() }) }));
vi.mock("../components/ui", () => ({ Modal: () => null }));
vi.mock("../components/Icon", () => ({ default: () => null }));

import Dashboard from "./Dashboard";
import { __resetBoardHealth } from "./panels";

beforeEach(() => {
  vi.clearAllMocks();
  __resetBoardHealth();
});
afterEach(cleanup);

describe("Dashboard liveness indicator", () => {
  it("reads Disconnected — not Live with a ticking clock — while every feed is failing", async () => {
    mode = "fail";
    render(<Dashboard />);
    await waitFor(() => expect(screen.getByText("Disconnected")).toBeTruthy());

    // No affirmative liveness claim, and no wall-clock "as of" stamp.
    expect(screen.queryByText("Live")).toBeNull();
    expect(screen.queryByText(/^as of /)).toBeNull();
    // It says WHICH feeds are failing and that nothing has loaded.
    expect(screen.getByText(/feeds failing/)).toBeTruthy();
    expect(screen.getByText(/no data loaded/)).toBeTruthy();
  });

  it("reads Live with the last SUCCESSFUL load time once the feeds answer", async () => {
    mode = "ok";
    render(<Dashboard />);
    await waitFor(() => expect(screen.getByText("Live")).toBeTruthy());
    expect(screen.getByText(/^as of /)).toBeTruthy();
    expect(screen.queryByText("Disconnected")).toBeNull();
  });
});
