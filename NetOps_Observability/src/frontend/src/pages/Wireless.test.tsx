// Wireless.test.tsx — the wireless inventory, focused on the BSSID sub-table
// added beneath the access points.
//
// The honesty line this guards: a BSSID read that FAILED is not an AP that
// broadcasts nothing, and a controller that publishes no BSSID is not an AP with
// no SSIDs on air. The page must say which of the three it is, and a BSSID
// failure must never take the inventory down with it.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, within } from "@testing-library/react";

const wirelessControllers = vi.fn();
const wirelessAPs = vi.fn();
const wirelessWLANs = vi.fn();
const wirelessBSSIDs = vi.fn();

vi.mock("../services/api", () => ({
  api: {
    wirelessControllers: (...a: unknown[]) => wirelessControllers(...a),
    wirelessAPs: (...a: unknown[]) => wirelessAPs(...a),
    wirelessWLANs: (...a: unknown[]) => wirelessWLANs(...a),
    wirelessBSSIDs: (...a: unknown[]) => wirelessBSSIDs(...a),
  },
}));

import Wireless from "./Wireless";

const AP = {
  ap_id: "ap-lobby-3",
  name: "lobby-3",
  model: "C9130",
  serial: "FCW123",
  radios: [{ radio_id: "r0", ap_id: "ap-lobby-3", slot: 0, band: "2.4GHz", oper_state: "up" }],
  last_seen: "2026-09-05T09:00:00Z",
};
const CONTROLLER = {
  controller_id: "wlc-1", name: "wlc-1", vendor: "cisco", cluster_role: "primary",
  visibility: "full", last_seen: "2026-09-05T09:00:00Z",
};
const WLAN = { wlan_id: "w1", profile_name: "corp", ssid_name: "Acme-Corp", enabled: true };
const BSSID = {
  bssid: "00:11:22:33:44:50",
  ap_ref: "ap-lobby-3",
  wlan_ref: "w1",
  radio_ref: "r0",
  first_seen: "2026-09-01T09:00:00Z",
  last_seen: "2026-09-05T09:00:00Z",
};

afterEach(cleanup);
beforeEach(() => {
  for (const m of [wirelessControllers, wirelessAPs, wirelessWLANs, wirelessBSSIDs]) m.mockReset();
  wirelessControllers.mockResolvedValue([CONTROLLER]);
  wirelessAPs.mockResolvedValue([AP]);
  wirelessWLANs.mockResolvedValue([WLAN]);
  wirelessBSSIDs.mockResolvedValue([BSSID]);
});

describe("Wireless — BSSIDs beneath the access points", () => {
  it("reads /api/wireless/bssids and renders one row per broadcast identity", async () => {
    render(<Wireless />);
    expect(await screen.findByText("BSSIDs")).toBeTruthy();
    expect(wirelessBSSIDs).toHaveBeenCalledTimes(1);
    const row = screen.getByText("00:11:22:33:44:50").closest("tr")!;
    expect(within(row).getByText("lobby-3")).toBeTruthy();
    expect(within(row).getByText("w1")).toBeTruthy();
    expect(within(row).getByText("r0")).toBeTruthy();
  });

  it("marks a BSSID the connector has not re-observed as stale", async () => {
    wirelessBSSIDs.mockResolvedValue([{ ...BSSID, stale: true }]);
    render(<Wireless />);
    await screen.findByText("BSSIDs");
    const row = screen.getByText("00:11:22:33:44:50").closest("tr")!;
    expect(row.className).toContain("row-stale");
    expect(within(row).getByText(/\(stale\)/)).toBeTruthy();
  });

  it("a failed BSSID read says UNKNOWN — and does not take the inventory down", async () => {
    wirelessBSSIDs.mockRejectedValue(new Error("500 Internal Server Error: "));
    render(<Wireless />);
    // The inventory still renders.
    expect(await screen.findByText("lobby-3")).toBeTruthy();
    // UI-words sweep 4 (tracker 270): the failure is STATED on screen; "not a
    // claim that they broadcast nothing" is ai/skills/explain/wifi.bssid-unread.md,
    // reachable from the `(i)` that replaced it.
    expect(screen.getByText(/The BSSIDs were not read\./i)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Ask Iris about BSSIDs not read" })).toBeTruthy();
    expect(screen.queryByText("BSSIDs")).toBeNull();
  });

  it("a controller that publishes no BSSID is stated as a gap, not as silence", async () => {
    wirelessBSSIDs.mockResolvedValue([]);
    render(<Wireless />);
    await screen.findByText("lobby-3");
    expect(screen.getByText(/The controller reported no BSSID here\./i)).toBeTruthy();
    // "a controller that publishes no BSSIDs still serves clients; nothing is
    // inferred from the gap" is ai/skills/explain/wifi.bssid-none.md now.
    expect(screen.getByRole("button", { name: "Ask Iris about No BSSID reported" })).toBeTruthy();
  });
});
