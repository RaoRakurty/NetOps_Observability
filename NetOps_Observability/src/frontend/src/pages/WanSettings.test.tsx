// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// WanSettings.test.tsx — the measurement policy editor, now under
// Administration → Discovery → WAN circuits (moved off Investigate › Paths on
// 2026-11-22). The guards are the ones it carried on the Paths page:
//
//   1. THE PUT BODY MUST CARRY INTENT ONLY. The server stamps tenant, author and
//      time from the token, so the exact body is asserted.
//   2. A REJECTED SAVE LEAVES THE OPERATOR'S TEXT WHERE THEY LEFT IT.
//   3. WITHOUT WRITE ACCESS THE EDITOR SAYS SO instead of offering a dead button.

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, within } from "@testing-library/react";
import type { WanMeasurementPolicy } from "../services/api";

const mockApi = vi.hoisted(() => ({
  wanPolicy: vi.fn(),
  setWanPolicy: vi.fn(),
  permissions: vi.fn(),
}));

vi.mock("../services/api", () => ({ api: mockApi }));

import WanSettings from "./WanSettings";

const POLICY: WanMeasurementPolicy = {
  tenant_id: "acme",
  wan_pattern: "wan|edge|gw|dmz",
  anchors: ["1.1.1.1", "8.8.8.8"],
  next_hops: { "wan-edge-1/Ethernet2": "203.0.113.1" },
  include_connected: true,
  updated_by: "rao",
  updated_at: "2026-09-04T10:00:00Z",
};

beforeEach(() => {
  vi.clearAllMocks();
  mockApi.wanPolicy.mockResolvedValue(POLICY);
  mockApi.setWanPolicy.mockResolvedValue(POLICY);
  mockApi.permissions.mockResolvedValue({ role: "operator", permissions: { infrastructure: 2 } });
});

afterEach(() => { cleanup(); });

async function openEditor() {
  render(<WanSettings />);
  return waitFor(() => screen.getByLabelText("WAN device name pattern") as HTMLInputElement);
}

describe("WAN settings (the measurement policy)", () => {
  it("reads only the policy and the caller's permissions", async () => {
    await openEditor();
    expect(mockApi.wanPolicy).toHaveBeenCalledTimes(1);
    expect(mockApi.permissions).toHaveBeenCalledTimes(1);
  });

  it("seeds the form from the stored policy and names who changed it", async () => {
    const pattern = await openEditor();
    expect(pattern.value).toBe("wan|edge|gw|dmz");
    expect((screen.getByLabelText("Reachability anchors") as HTMLInputElement).value).toBe("1.1.1.1, 8.8.8.8");
    expect((screen.getByLabelText("Device or device and interface, override 1") as HTMLInputElement).value)
      .toBe("wan-edge-1/Ethernet2");
    expect(screen.getByText(/Last changed by rao/)).toBeTruthy();
  });

  it("keeps the save inert until the form differs from what is stored", async () => {
    const pattern = await openEditor();
    expect((screen.getByRole("button", { name: "Save policy" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(pattern, { target: { value: "wan|edge|dia" } });
    expect((screen.getByRole("button", { name: "Save policy" }) as HTMLButtonElement).disabled).toBe(false);
  });

  it("PUTs exactly the four intent fields, and never a tenant", async () => {
    const pattern = await openEditor();
    fireEvent.change(pattern, { target: { value: "wan|edge|dia" } });
    fireEvent.change(screen.getByLabelText("Reachability anchors"), { target: { value: "9.9.9.9, 1.1.1.1" } });
    fireEvent.click(screen.getByLabelText("Also measure interfaces directly connected to a WAN device"));
    fireEvent.change(screen.getByLabelText("ISP next-hop address, override 1"), { target: { value: "203.0.113.9" } });
    fireEvent.click(screen.getByRole("button", { name: "Save policy" }));

    await waitFor(() => expect(mockApi.setWanPolicy).toHaveBeenCalledTimes(1));
    const body = mockApi.setWanPolicy.mock.calls[0][0] as WanMeasurementPolicy;
    expect(body).toEqual({
      wan_pattern: "wan|edge|dia",
      anchors: ["9.9.9.9", "1.1.1.1"],
      next_hops: { "wan-edge-1/Ethernet2": "203.0.113.9" },
      include_connected: false,
    });
    for (const k of ["tenant_id", "updated_by", "updated_at"]) expect(Object.keys(body)).not.toContain(k);
  });

  it("adds and removes ISP next-hop overrides, and clearing the last one PUTs an empty map", async () => {
    await openEditor();
    fireEvent.click(screen.getByRole("button", { name: "Remove override 1" }));
    expect(screen.getByText(/No ISP next-hop has been declared/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Save policy" }));
    await waitFor(() => expect(mockApi.setWanPolicy).toHaveBeenCalled());
    expect((mockApi.setWanPolicy.mock.calls[0][0] as WanMeasurementPolicy).next_hops).toEqual({});
  });

  it("blocks a save while an override is half-filled, and says which half is missing", async () => {
    await openEditor();
    fireEvent.click(screen.getByRole("button", { name: "Add an override" }));
    fireEvent.change(screen.getByLabelText("Device or device and interface, override 2"), { target: { value: "wan-edge-2" } });
    expect(screen.getByText(/no ISP next-hop address to measure to/)).toBeTruthy();
    expect((screen.getByRole("button", { name: "Save policy" }) as HTMLButtonElement).disabled).toBe(true);
    expect(mockApi.setWanPolicy).not.toHaveBeenCalled();
  });

  it("re-reads the stored policy after a successful save and says it was saved", async () => {
    const pattern = await openEditor();
    fireEvent.change(pattern, { target: { value: "wan|edge|dia" } });
    fireEvent.click(screen.getByRole("button", { name: "Save policy" }));
    await waitFor(() => expect(mockApi.wanPolicy).toHaveBeenCalledTimes(2));
    expect(await screen.findByText(/Measurement policy saved\./)).toBeTruthy();
  });

  it("catches an unreadable pattern before it is ever sent", async () => {
    const pattern = await openEditor();
    fireEvent.change(pattern, { target: { value: "wan(edge" } });
    expect(screen.getByText(/That device name pattern could not be read\./)).toBeTruthy();
    expect((screen.getByRole("button", { name: "Save policy" }) as HTMLButtonElement).disabled).toBe(true);
    expect(mockApi.setWanPolicy).not.toHaveBeenCalled();
  });

  it("renders an operator sentence on a refused save and keeps the edit in the form", async () => {
    mockApi.setWanPolicy.mockRejectedValue(new Error('400 Bad Request: {"error":"wan_pattern is not a valid expression"}'));
    const pattern = await openEditor();
    fireEvent.change(pattern, { target: { value: "(?<edge>wan)" } });
    fireEvent.click(screen.getByRole("button", { name: "Save policy" }));
    await waitFor(() => expect(screen.getByRole("status")).toBeTruthy());
    expect(screen.getByRole("status").textContent).toBe("Wan_pattern is not a valid expression.");
    expect((screen.getByLabelText("WAN device name pattern") as HTMLInputElement).value).toBe("(?<edge>wan)");
  });

  it("falls back to our own sentence when the server's failure is developer text", async () => {
    mockApi.setWanPolicy.mockRejectedValue(new Error(
      '500 Internal Server Error: {"error":"kv: write /data/wan_policy.json: no space left on device"}',
    ));
    const pattern = await openEditor();
    fireEvent.change(pattern, { target: { value: "wan|edge|dia" } });
    fireEvent.click(screen.getByRole("button", { name: "Save policy" }));
    await waitFor(() => expect(screen.getByRole("status")).toBeTruthy());
    expect(screen.getByRole("status").textContent).toBe("The service did not answer.");
  });

  it("a dead policy read says so in an operator sentence", async () => {
    mockApi.wanPolicy.mockRejectedValue(new Error(
      '500 Internal Server Error: {"error":"dial tcp 10.0.0.9:2379: connect: connection refused"}',
    ));
    render(<WanSettings />);
    const alert = await waitFor(() => within(screen.getByTestId("wan-settings")).getByRole("alert"));
    expect(alert.textContent).toContain("The service did not answer.");
    expect(alert.textContent).not.toContain("10.0.0.9");
  });

  it("without write access explains the read-only state instead of offering a dead button", async () => {
    mockApi.permissions.mockResolvedValue({ role: "viewer", permissions: { infrastructure: 1 } });
    render(<WanSettings />);
    await waitFor(() => expect(screen.getByText(/Changing the policy needs write access\./)).toBeTruthy());
    expect(screen.queryByRole("button", { name: "Save policy" })).toBeNull();
    expect((screen.getByLabelText("WAN device name pattern") as HTMLInputElement).disabled).toBe(true);
    expect(screen.getByRole("button", { name: "Ask Iris about Read-only policy" })).toBeTruthy();
  });

  it("treats an unreadable permission check as read-only", async () => {
    mockApi.permissions.mockRejectedValue(new Error("401 Unauthorized: {}"));
    render(<WanSettings />);
    await waitFor(() => expect(screen.getByText(/Changing the policy needs write access\./)).toBeTruthy());
  });
});
