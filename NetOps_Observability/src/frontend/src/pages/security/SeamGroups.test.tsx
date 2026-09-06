// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// SeamGroups.test.tsx — the redundancy roll-up over the seam list.
//
// What has to hold: a suggested grouping is labelled as a proposal and never as
// a settled fact, the state filter and the PATCH hit the routes they claim to,
// the server keeps ownership of the state machine (its refusal is shown), and a
// store that is not deployed is not reported as "no groups".

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, within } from "@testing-library/react";

const seamGroups = vi.fn();
const seamGroupSetState = vi.fn();

vi.mock("../../services/api", () => ({
  api: {
    seamGroups: (...a: unknown[]) => seamGroups(...a),
    seamGroupSetState: (...a: unknown[]) => seamGroupSetState(...a),
  },
}));

import SeamGroups from "./SeamGroups";

const SUGGESTED = {
  group_id: "sg-1",
  tenant_id: "acme",
  seam_type: "isp",
  redundancy_model: "active_standby",
  state: "suggested",
  display_name: "HQ dual ISP",
  members: [{ member_id: "sm-a", role: "primary" }, { member_id: "sm-b", role: "standby" }],
  suggested_by: "engine",
  evidence: null,
  confidence: 0.82,
  created_at: "2026-09-01T09:00:00Z",
  updated_at: "2026-09-05T09:00:00Z",
  updated_by: "engine",
};
const ACTIVE = { ...SUGGESTED, group_id: "sg-2", display_name: "DC dual ISP", state: "active", confidence: 0 };

afterEach(cleanup);
beforeEach(() => {
  seamGroups.mockReset();
  seamGroupSetState.mockReset();
  seamGroups.mockResolvedValue([SUGGESTED, ACTIVE]);
});

describe("SeamGroups — reading", () => {
  it("reads /api/seams/groups unfiltered on mount", async () => {
    render(<SeamGroups />);
    await screen.findByRole("table", { name: /seam groups/i });
    expect(seamGroups).toHaveBeenCalledWith("");
  });

  it("labels a suggested grouping as a proposal, with what proposed it", async () => {
    render(<SeamGroups />);
    const table = await screen.findByRole("table", { name: /seam groups/i });
    const row = within(table).getByText("HQ dual ISP").closest("tr")!;
    expect(within(row).getByText(/proposed, not confirmed/i)).toBeTruthy();
    expect(within(row).getByRole("button", { name: /Ask Iris about a proposed grouping/i })).toBeTruthy();
    expect(within(row).getByText("engine")).toBeTruthy();
    expect(within(row).getByText("82%")).toBeTruthy();
  });

  it("a group with no confidence says NOT STATED, never 0%", async () => {
    render(<SeamGroups />);
    const table = await screen.findByRole("table", { name: /seam groups/i });
    const row = within(table).getByText("DC dual ISP").closest("tr")!;
    expect(within(row).getByText("not stated")).toBeTruthy();
    expect(within(row).queryByText("0%")).toBeNull();
  });

  it("filters by state through the server's own vocabulary", async () => {
    render(<SeamGroups />);
    await screen.findByRole("table", { name: /seam groups/i });
    fireEvent.change(screen.getByLabelText(/filter seam groups by state/i), { target: { value: "suggested" } });
    await waitFor(() => expect(seamGroups).toHaveBeenLastCalledWith("suggested"));
  });

  it("a 501 says the seam registry is not deployed, not that there are no groups", async () => {
    seamGroups.mockRejectedValue(new Error("501 Not Implemented: "));
    render(<SeamGroups />);
    expect(await screen.findByText(/seam registry is not available here/i)).toBeTruthy();
    expect(screen.getByRole("button", { name: /Ask Iris about the seam registry/i })).toBeTruthy();
  });

  it("a failed read says the grouping is unknown, not absent", async () => {
    seamGroups.mockRejectedValue(new Error("500 Internal Server Error: "));
    render(<SeamGroups />);
    expect(await screen.findByText(/unknown, not absent/i)).toBeTruthy();
  });
});

describe("SeamGroups — confirming a grouping", () => {
  it("offers no state control without infrastructure write access", async () => {
    render(<SeamGroups />);
    await screen.findByRole("table", { name: /seam groups/i });
    expect(screen.queryByLabelText(/Set the state of HQ dual ISP/i)).toBeNull();
  });

  it("PATCHes the group with the chosen state", async () => {
    seamGroupSetState.mockResolvedValue({ ...SUGGESTED, state: "confirmed" });
    render(<SeamGroups canWrite />);
    await screen.findByRole("table", { name: /seam groups/i });
    fireEvent.change(screen.getByLabelText(/Set the state of HQ dual ISP/i), { target: { value: "confirmed" } });
    await waitFor(() => expect(seamGroupSetState).toHaveBeenCalledWith("sg-1", "confirmed"));
    expect(await screen.findByText(/HQ dual ISP is now confirmed/i)).toBeTruthy();
  });

  it("shows the SERVER's refusal for an illegal transition rather than guessing", async () => {
    seamGroupSetState.mockRejectedValue(new Error('400 Bad Request: {"error":"transition retired to active is not allowed"}'));
    render(<SeamGroups canWrite />);
    await screen.findByRole("table", { name: /seam groups/i });
    fireEvent.change(screen.getByLabelText(/Set the state of HQ dual ISP/i), { target: { value: "retired" } });
    expect(await screen.findByText(/transition retired to active is not allowed/i)).toBeTruthy();
  });
});
