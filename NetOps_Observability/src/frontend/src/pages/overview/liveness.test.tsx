// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// liveness.test.tsx — the board header's liveness indicator (Overview and every
// custom dashboard) must be a statement about DATA, not about time passing. It
// once was a pulsing "Live" dot beside an "as of HH:MM" clock driven by a local
// setInterval that never touched the network, so a total backend outage still
// read as a live board. Every panel poll reports its outcome into the
// board-health signal and the header states what that says. (Moved from My
// Dashboard's test when the board was merged into Overview, 2026-11-22.)

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, waitFor } from "@testing-library/react";

vi.mock("../../components/AskIris", () => ({ default: () => null }));
vi.mock("../../components/Icon", () => ({ default: () => null }));
vi.mock("../../context/shell", () => ({ useShell: () => ({ navigate: vi.fn() }) }));

import { Liveness } from "./boardParts";
import { usePolled, __resetBoardHealth } from "../panels";

function Feed({ load }: { load: () => Promise<unknown> }) {
  usePolled(load, 60_000);
  return null;
}

beforeEach(() => { __resetBoardHealth(); });
afterEach(cleanup);

describe("Board liveness indicator", () => {
  it("reads Disconnected — not Live with a ticking clock — while every feed is failing", async () => {
    const failing = () => Promise.reject(new Error("500 Internal Server Error"));
    render(<><Feed load={failing} /><Feed load={failing} /><Liveness /></>);
    await waitFor(() => expect(screen.getByText("Disconnected")).toBeTruthy());
    // No affirmative liveness claim, and no wall-clock "as of" stamp.
    expect(screen.queryByText("Live")).toBeNull();
    expect(screen.queryByText(/^as of /)).toBeNull();
    // It says HOW MANY feeds are failing and that nothing has loaded.
    expect(screen.getByText(/2 of 2 feeds failing/)).toBeTruthy();
    expect(screen.getByText(/no data loaded/)).toBeTruthy();
  });

  it("reads Live with the last SUCCESSFUL load time once the feeds answer", async () => {
    const ok = () => Promise.resolve([]);
    render(<><Feed load={ok} /><Liveness /></>);
    await waitFor(() => expect(screen.getByText("Live")).toBeTruthy());
    expect(screen.getByText(/^as of /)).toBeTruthy();
    expect(screen.queryByText("Disconnected")).toBeNull();
  });

  it("reads Connecting before the first answer", () => {
    render(<><Feed load={() => new Promise(() => { /* never answers */ })} /><Liveness /></>);
    expect(screen.getByText("Connecting")).toBeTruthy();
  });
});
