// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// PathsSetup.test.tsx — the Measured paths setup steps (Paths redesign P3).

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";

const mockApi = vi.hoisted(() => ({
  probeTargetSuggestions: vi.fn(),
  createDemTarget: vi.fn(),
}));
vi.mock("../services/api", () => ({ api: mockApi }));

import PathsSetup, { freshSuggestions, FEATURES_HREF } from "./PathsSetup";

const sugg = [
  { device_id: "d1", name: "cedge-40", address: "192.168.222.105", site: "Branch 40" },
  { device_id: "d2", name: "cedge-50", address: "192.168.222.106", site: "Branch 50" },
  { device_id: "d3", name: "vedge-51", address: "192.168.222.107", site: "Branch 50", traced: true },
];

beforeEach(() => {
  mockApi.probeTargetSuggestions.mockResolvedValue({ path_discovery: true, active_probe: false, tracing: 1, suggestions: sugg });
  mockApi.createDemTarget.mockResolvedValue({});
});
afterEach(() => { cleanup(); vi.clearAllMocks(); });

describe("PathsSetup", () => {
  it("offers only the edges not already traced, de-duplicated", () => {
    const dup = [...sugg, { device_id: "d4", name: "cedge-40b", address: "192.168.222.105" }];
    expect(freshSuggestions(dup).map((s) => s.name)).toEqual(["cedge-40", "cedge-50"]);
  });

  it("pre-ticks the suggestions and adds the ticked ones as traced catalogue targets", async () => {
    render(<PathsSetup />);
    const list = await screen.findByTestId("paths-suggestions");
    const boxes = list.querySelectorAll<HTMLInputElement>("input[type=checkbox]");
    expect(boxes.length).toBe(2);
    expect([...boxes].every((b) => b.checked)).toBe(true);
    fireEvent.click(boxes[1]); // untick cedge-50
    fireEvent.click(screen.getByTestId("paths-trace-selected"));
    await waitFor(() => expect(mockApi.createDemTarget).toHaveBeenCalledTimes(1));
    expect(mockApi.createDemTarget).toHaveBeenCalledWith({
      name: "Path to cedge-40", kind: "icmp", host: "192.168.222.105", site: "Branch 40", interval_sec: 60, trace_path: true,
    });
    // The body never carries a tenant: the server stamps it from the token.
    expect(JSON.stringify(mockApi.createDemTarget.mock.calls[0][0])).not.toMatch(/tenant/);
    expect(await screen.findByRole("status")).toHaveTextContent("1 added");
  });

  it("when path discovery is off, step 1 links the Features page and names no environment variable", async () => {
    mockApi.probeTargetSuggestions.mockResolvedValue({ path_discovery: false, active_probe: false, tracing: 0, suggestions: [] });
    render(<PathsSetup />);
    const link = await screen.findByRole("link", { name: "Platform › Configuration › Features" });
    expect(link.getAttribute("href")).toBe(FEATURES_HREF);
    expect(document.body.textContent).not.toMatch(/\bFEATURE_[A-Z_]+|_TARGETS\b/);
  });

  it("a failed read says so instead of showing empty steps", async () => {
    mockApi.probeTargetSuggestions.mockRejectedValue(new Error("500 Internal Server Error: boom"));
    render(<PathsSetup />);
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBeTruthy();
    // The raw api envelope never reaches the screen (tracker 293).
    expect(alert.textContent).not.toMatch(/500 Internal Server Error/);
  });
});
