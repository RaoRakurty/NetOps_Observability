// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ConfigDrift.test.tsx — the fleet Config drift list.
//
// Pinned: honest per-device states (including "Unknown" and "Never captured"),
// the state filter chips re-querying the SERVER (not filtering client-side, so
// the count can never lie about a page), cursor pagination that APPENDS, the
// empty state naming the filter that emptied it, and the feature-off card.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, within } from "@testing-library/react";
import type { ConfigDriftRow } from "../../services/api";

const configDriftList = vi.fn();

vi.mock("../../services/api", () => ({
  api: { configDriftList: (...a: unknown[]) => configDriftList(...a) },
}));

import ConfigDrift, { deviceHref } from "./ConfigDrift";

const ROWS: ConfigDriftRow[] = [
  { device_id: "d1", device_name: "leaf1", state: "drifted", last_capture_at: "2026-09-01T12:00:00Z", last_sha: "aaaaaaaaaaaa1111", golden_sha: "bbbbbbbbbbbb2222" },
  { device_id: "d2", device_name: "leaf2", state: "in_sync", last_capture_at: "2026-09-01T11:00:00Z", last_sha: "cccccccccccc3333", golden_sha: "cccccccccccc3333" },
  { device_id: "d3", device_name: "leaf3", state: "unknown" },
];

beforeEach(() => { configDriftList.mockReset(); });
afterEach(cleanup);

describe("ConfigDrift list", () => {
  it("lists devices by state, keeping a never-captured device honest", async () => {
    configDriftList.mockResolvedValue({ items: ROWS, next_cursor: null, total: 3 });
    render(<ConfigDrift />);
    const table = await screen.findByRole("table", { name: "Configuration drift by device" });
    const rows = table.querySelectorAll("tbody tr");
    expect(rows.length).toBe(3);
    // Scoped to the table: the same words also label the filter chips.
    expect(within(table).getByText("Drifted")).toBeTruthy();
    expect(within(table).getByText("In sync")).toBeTruthy();
    // d3 has no capture at all — never "in sync" by omission.
    expect(within(table).getByText("Never captured")).toBeTruthy();
    expect(rows[2].textContent).toContain("never");
    expect(rows[2].textContent).toContain("none");
    expect(configDriftList).toHaveBeenCalledWith({ state: undefined, cursor: undefined, limit: 100 });
  });

  it("deep-links every row to the device's Configuration panel", async () => {
    configDriftList.mockResolvedValue({ items: ROWS, next_cursor: null, total: 3 });
    render(<ConfigDrift />);
    const link = await screen.findByRole("link", { name: "leaf1" });
    expect(link.getAttribute("href")).toBe("#/infrastructure/devices?q=leaf1");
    expect(deviceHref({ device_id: "d9", device_name: "", state: "unknown" } as ConfigDriftRow)).toBe("#/infrastructure/devices?q=d9");
  });

  it("filters by state chip and re-queries the server", async () => {
    configDriftList.mockResolvedValue({ items: ROWS, next_cursor: null, total: 3 });
    render(<ConfigDrift />);
    await screen.findByRole("table", { name: "Configuration drift by device" });
    configDriftList.mockResolvedValue({ items: [ROWS[0]], next_cursor: null, total: 1 });
    fireEvent.click(screen.getByRole("button", { name: "Drifted" }));
    await waitFor(() => expect(configDriftList).toHaveBeenLastCalledWith({ state: "drifted", cursor: undefined, limit: 100 }));
    await waitFor(() => expect(screen.getByRole("table").querySelectorAll("tbody tr").length).toBe(1));
    expect(screen.getByRole("button", { name: "Drifted" }).getAttribute("aria-pressed")).toBe("true");
  });

  it("appends the next page from the cursor and then reports the list exhausted", async () => {
    configDriftList.mockResolvedValue({ items: [ROWS[0], ROWS[1]], next_cursor: "cur-2", total: 3 });
    render(<ConfigDrift />);
    await screen.findByRole("table", { name: "Configuration drift by device" });
    expect(screen.getByText(/2 of 3 devices shown/)).toBeTruthy();

    configDriftList.mockResolvedValue({ items: [ROWS[2]], next_cursor: null, total: 3 });
    fireEvent.click(screen.getByRole("button", { name: "Load more" }));
    await waitFor(() => expect(configDriftList).toHaveBeenLastCalledWith({ state: undefined, cursor: "cur-2", limit: 100 }));
    await waitFor(() => expect(screen.getByRole("table").querySelectorAll("tbody tr").length).toBe(3));
    expect(screen.getByText(/3 of 3 devices shown/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "All rows loaded" })).toBeTruthy();
  });

  it("names the filter that emptied the list", async () => {
    configDriftList.mockResolvedValue({ items: ROWS, next_cursor: null, total: 3 });
    render(<ConfigDrift />);
    await screen.findByRole("table", { name: "Configuration drift by device" });
    configDriftList.mockResolvedValue({ items: [], next_cursor: null, total: 0 });
    fireEvent.click(screen.getByRole("button", { name: "Changed" }));
    expect(await screen.findByText(/No device is in the "Changed" state/)).toBeTruthy();
  });

  it("says an empty fleet means nothing was captured, not that it is in sync", async () => {
    configDriftList.mockResolvedValue({ items: [], next_cursor: null, total: 0 });
    render(<ConfigDrift />);
    expect(await screen.findByText(/An empty list means nothing was captured/)).toBeTruthy();
  });

  it("renders the feature-off card on 404 rather than an error", async () => {
    configDriftList.mockRejectedValue(new Error("404 Not Found: "));
    render(<ConfigDrift />);
    expect(await screen.findByText(/Config backup is not enabled on this deployment/)).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("still surfaces a real server failure as an error", async () => {
    configDriftList.mockRejectedValue(new Error("500 Internal Server Error: boom"));
    render(<ConfigDrift />);
    expect(await screen.findByRole("alert")).toBeTruthy();
  });
});
