// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// DeviceChangeCheck.test.tsx — the device page's before/after change check.
//
// Pinned here:
//  · the two numbered steps and the "nothing on the device changes" line
//  · take posts the ticket label and refreshes the list; compare renders the
//    server's OBSERVED lines, a loss in the bad tone, an unread section muted
//  · compare is disabled until a baseline exists; no baseline → the empty state
//  · 403 → the permission line, 409 → the server's reason verbatim, 503 → the
//    not-available card (the server is the authority)
//  · the status line is a live region

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";
import type { Device, DeviceBaselineDiff, DeviceBaselineSummary } from "../../services/api";

const deviceBaselines = vi.fn();
const deviceBaselineTake = vi.fn();
const deviceBaselineCompare = vi.fn();

vi.mock("../../services/api", () => ({
  api: {
    deviceBaselines: (...a: unknown[]) => deviceBaselines(...a),
    deviceBaselineTake: (...a: unknown[]) => deviceBaselineTake(...a),
    deviceBaselineCompare: (...a: unknown[]) => deviceBaselineCompare(...a),
  },
}));

import DeviceChangeCheck, { NO_PERMISSION, NOT_AVAILABLE, lineTone, serverReason } from "./DeviceChangeCheck";

const DEVICE = { id: "cedge-80", name: "cedge-80", address: "198.51.100.80", vendor: "cisco", source: "snmp",
  last_seen: "2026-11-18T09:00:00Z" } as Device;

const B1: DeviceBaselineSummary = { id: "b-1", device_id: "cedge-80", device_name: "cedge-80",
  taken_at: "2026-11-18T09:30:00Z", taken_by: "a@acme", label: "CHG-1042", interfaces: 5, neighbors: 3, not_read: 0 };

const DIFF: DeviceBaselineDiff = {
  baseline: B1, read_at: "2026-11-18T11:30:00Z", unchanged: 9, cannot_compare: ["isis (not read in the baseline)"],
  changes: [{ kind: "interface_down", subject: "GigabitEthernet3", before: "up/up", after: "up/down" }],
  lines: [
    "Interface GigabitEthernet3 was up/up before the change and is up/down now.",
    "OSPF 10.0.0.3 on GigabitEthernet3 (FULL/BDR before the change) did not come back.",
    "The routing table held 10 routes before the change and 4 routes now.",
    "Cannot compare isis (not read in the baseline).",
  ],
};

beforeEach(() => {
  deviceBaselines.mockReset();
  deviceBaselineTake.mockReset();
  deviceBaselineCompare.mockReset();
});
afterEach(() => cleanup());

describe("DeviceChangeCheck", () => {
  it("shows the two steps, the read-only line and the empty state; compare waits for a baseline", async () => {
    deviceBaselines.mockResolvedValue({ device_id: "cedge-80", items: [], keep: 10 });
    render(<DeviceChangeCheck device={DEVICE} />);
    expect(await screen.findByText("No baseline taken yet.")).toBeTruthy();
    expect(screen.getByText("1. Before the change")).toBeTruthy();
    expect(screen.getByText("2. After the change")).toBeTruthy();
    expect(screen.getByText(/Nothing on the device changes/)).toBeTruthy();
    expect((screen.getByTestId("baseline-compare") as HTMLButtonElement).disabled).toBe(true);
  });

  it("takes a baseline with the ticket label and refreshes the list", async () => {
    deviceBaselines.mockResolvedValueOnce({ device_id: "cedge-80", items: [], keep: 10 })
      .mockResolvedValueOnce({ device_id: "cedge-80", items: [B1], keep: 10 });
    deviceBaselineTake.mockResolvedValue(B1);
    render(<DeviceChangeCheck device={DEVICE} />);
    await screen.findByText("No baseline taken yet.");
    fireEvent.change(screen.getByPlaceholderText("CHG-1042"), { target: { value: " CHG-1042 " } });
    fireEvent.click(screen.getByTestId("baseline-take"));
    await waitFor(() => expect(deviceBaselineTake).toHaveBeenCalledWith("cedge-80", "CHG-1042"));
    expect(await screen.findByText(/Baseline taken at/)).toBeTruthy();
    expect(await screen.findByText("a@acme")).toBeTruthy();
    expect((screen.getByTestId("baseline-compare") as HTMLButtonElement).disabled).toBe(false);
  });

  it("compares and renders the server's observed lines with tones", async () => {
    deviceBaselines.mockResolvedValue({ device_id: "cedge-80", items: [B1], keep: 10 });
    deviceBaselineCompare.mockResolvedValue(DIFF);
    render(<DeviceChangeCheck device={DEVICE} />);
    await screen.findByText("a@acme");
    fireEvent.click(screen.getByTestId("baseline-compare"));
    await waitFor(() => expect(deviceBaselineCompare).toHaveBeenCalledWith("cedge-80", undefined));
    const lost = await screen.findByText(/did not come back/);
    expect(lost.className).toContain("chg-bad");
    expect(screen.getByText(/Cannot compare isis/).className).toContain("chg-muted");
    expect(screen.getByText(/routing table held 10 routes/).className).not.toContain("chg-bad");
  });

  it("shows the server as the authority: 403, 409 reason, 503 card", async () => {
    deviceBaselines.mockResolvedValue({ device_id: "cedge-80", items: [B1], keep: 10 });
    deviceBaselineTake.mockRejectedValueOnce(new Error('403 Forbidden: {"error":"forbidden"}'))
      .mockRejectedValueOnce(new Error('409 Conflict: {"error":"live device-state collection is not wired on this deployment — no command was run"}'));
    render(<DeviceChangeCheck device={DEVICE} />);
    await screen.findByText("a@acme");
    fireEvent.click(screen.getByTestId("baseline-take"));
    expect(await screen.findByText(NO_PERMISSION)).toBeTruthy();
    fireEvent.click(screen.getByTestId("baseline-take"));
    const status = await screen.findByText(/no command was run/);
    expect(status.getAttribute("role")).toBe("status");
    expect(status.getAttribute("aria-live")).toBe("polite");
    cleanup();
    deviceBaselines.mockRejectedValue(new Error('503 Service Unavailable: {"error":"device baselines are not available on this deployment"}'));
    render(<DeviceChangeCheck device={DEVICE} />);
    expect(await screen.findByText(NOT_AVAILABLE)).toBeTruthy();
  });

  it("parses reasons and tones", () => {
    expect(serverReason(new Error('409 Conflict: {"error":"x"}'))).toEqual({ status: 409, reason: "x" });
    expect(serverReason(new Error("500 Internal: boom"))).toEqual({ status: 500, reason: "boom" });
    expect(lineTone("The software version was 17.03.02 before the change and is 17.09.04a now.")).toBe("");
    expect(lineTone("Interface Gi1 came up: down before, up now.")).toBe("");
  });
});
