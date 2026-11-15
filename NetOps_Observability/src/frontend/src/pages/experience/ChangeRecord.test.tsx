// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ChangeRecord — the page Iris's "Open the change record" lands on
// (`#/operations/digital-experience/changes?id=…`): the ledger record and what
// it did, both read under the caller's own scope; another workspace's id is a
// 404, said plainly.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent } from "@testing-library/react";

const change = vi.fn();
const changeDiff = vi.fn();
vi.mock("../../services/api", () => ({
  api: {
    change: (...a: unknown[]) => change(...a),
    changeDiff: (...a: unknown[]) => changeDiff(...a),
  },
}));

import ChangeRecord from "./ChangeRecord";

const HOSTILE = `<img src=x onerror="alert(1)">`;

beforeEach(() => {
  change.mockReset();
  changeDiff.mockReset();
});
afterEach(() => cleanup());

describe("ChangeRecord", () => {
  it("shows the record and what it did, for the id in the link", async () => {
    change.mockResolvedValue({
      id: "chg-1042", type: "NETWORK_CHANGE", event_at: "2026-09-24T14:18:00Z", actor: "jsmith",
      object: "dfw-edge-1", summary: `WAN policy wan-pref updated ${HOSTILE}`, source_system: "ledger", has_diff: true,
    });
    changeDiff.mockResolvedValue({ change_id: "chg-1042", kind: "values", before: "pref 100", after: "pref 200" });
    const { container } = render(<ChangeRecord id="chg-1042" onShowAll={() => {}} />);
    expect(await screen.findByText(`WAN policy wan-pref updated ${HOSTILE}`)).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText("network change")).toBeInTheDocument();
    expect(await screen.findByText("pref 100 → pref 200")).toBeInTheDocument();
    expect(change).toHaveBeenCalledWith("chg-1042");
    expect(changeDiff).toHaveBeenCalledWith("chg-1042");
  });

  it("says another workspace's change (404) is not in yours", async () => {
    change.mockRejectedValue(new Error("404 Not Found: not found"));
    render(<ChangeRecord id="chg-other" onShowAll={() => {}} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("This change is not in your workspace, or it no longer exists.");
    expect(changeDiff).not.toHaveBeenCalled();
  });

  it("reads no diff when the record has none, and goes back to the feed", async () => {
    change.mockResolvedValue({ id: "chg-2", type: "DNS_CHANGE", event_at: "", object: "zone", summary: "x", source_system: "ledger", has_diff: false });
    const back = vi.fn();
    render(<ChangeRecord id="chg-2" onShowAll={back} />);
    expect(await screen.findByText("No before/after was recorded for this change.")).toBeInTheDocument();
    expect(changeDiff).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Show all changes" }));
    expect(back).toHaveBeenCalled();
  });
});
