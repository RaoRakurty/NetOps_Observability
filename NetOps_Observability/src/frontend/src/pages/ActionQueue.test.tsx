// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ActionQueue.test.tsx — Operations → Problems (owner review, 2026-11-22):
// the two tabs, the honest truncation line, and a Ticket column that reads the
// case's real ticket links instead of the RCA state alone.

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, fireEvent, within } from "@testing-library/react";
import { corrObject } from "../test/factories";

const correlations = vi.fn();
const ticketLinks = vi.fn();

vi.mock("../services/api", () => ({
  api: {
    correlations: (...a: unknown[]) => correlations(...a),
    ticketLinks: (...a: unknown[]) => ticketLinks(...a),
    permissions: vi.fn(() => Promise.resolve({})),
    rcaPathView: vi.fn(),
    correlationTicketCreate: vi.fn(),
    devices: vi.fn(() => Promise.resolve([])),
    wirelessRemediations: vi.fn(() => Promise.reject(new Error("off"))),
  },
}));

import ActionQueue from "./ActionQueue";

const FILED = "aaaaaa11-0000-0000-0000-000000000001";
const rows = [
  corrObject({ correlation_id: FILED, verdict_tier: "confirmed", signal_count: 4, owner: "netops",
    top_hypothesis: "bgp.session.flap", window_start: "2026-11-21T08:00:00Z" }),
  corrObject({ correlation_id: "bbbbbb22-0000-0000-0000-000000000002", verdict_tier: "undetermined", signal_count: 1,
    window_start: "2026-11-21T09:00:00Z" }),
];

const grid = () => screen.findByRole("grid", { name: /^Problems/ });

beforeEach(() => {
  correlations.mockReset();
  ticketLinks.mockReset();
  correlations.mockResolvedValue({ data: rows, next_cursor: "c2" });
  ticketLinks.mockResolvedValue({ links: [{ corr_object_id: FILED, state: "open", system: "servicenow" }], complete: true });
});
afterEach(cleanup);

describe("Operations → Problems", () => {
  it("opens on Needs action, and All open adds the groups still gathering evidence", async () => {
    render(<ActionQueue />);
    const g = await grid();
    expect(within(g).getAllByRole("row").filter((r) => r.classList.contains("dtv-row"))).toHaveLength(1);
    expect(screen.getByRole("button", { name: "Needs action (1)" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "All open (2)" }));
    const g2 = await grid();
    expect(within(g2).getAllByRole("row").filter((r) => r.classList.contains("dtv-row"))).toHaveLength(2);
  });

  it("says plainly when the read stopped at its page size", async () => {
    render(<ActionQueue />);
    await grid();
    expect(screen.getByTestId("queue-truncated").textContent).toMatch(/more exist/);
  });

  it("shows no truncation line when the read was the whole set", async () => {
    correlations.mockResolvedValue({ data: rows });
    render(<ActionQueue />);
    await grid();
    expect(screen.queryByTestId("queue-truncated")).toBeNull();
  });

  it("a filed ticket reads Ticketed in the row", async () => {
    render(<ActionQueue />);
    const g = await grid();
    expect(within(g).getByText("Ticketed")).toBeTruthy();
    expect(ticketLinks).toHaveBeenCalledWith(2000);
  });

  it("a failed links read never claims a ticket is needed", async () => {
    ticketLinks.mockRejectedValue(new Error("502"));
    render(<ActionQueue />);
    const g = await grid();
    expect(within(g).queryByText("Ticket needed")).toBeNull();
    // The confirmed case's next step asks the operator to check, not to file.
    expect(within(g).getByText("Check for a ticket · escalate")).toBeTruthy();
  });
});
