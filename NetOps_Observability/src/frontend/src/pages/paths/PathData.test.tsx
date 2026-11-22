// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// PathData.test.tsx — the "Path data" drawer of Investigate → Paths (P5): the
// four sources with their state, the console page that turns each on, and a
// source that cannot be read shown as unknown, never as off.

import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup, waitFor } from "@testing-library/react";

const mockApi = vi.hoisted(() => ({
  probeTargetSuggestions: vi.fn(),
  tunnels: vi.fn(),
  wanInterfaces: vi.fn(),
}));
vi.mock("../../services/api", () => ({ api: mockApi }));
vi.mock("../../components/AskIris", () => ({ default: () => null }));

import PathData from "./PathData";

afterEach(() => { cleanup(); vi.clearAllMocks(); });

const item = (id: string) => screen.getByTestId(`paths-data-${id}`);

describe("Path data drawer", () => {
  it("reads nothing while closed", () => {
    render(<PathData open={false} onClose={() => {}} />);
    expect(mockApi.probeTargetSuggestions).not.toHaveBeenCalled();
  });

  it("says what is on and what is off, and where each is turned on", async () => {
    mockApi.probeTargetSuggestions.mockResolvedValue({ path_discovery: true, active_probe: false, tracing: 2, suggestions: [] });
    mockApi.tunnels.mockResolvedValue({ data: [], rows: 0, total: 0 });
    mockApi.wanInterfaces.mockResolvedValue({ interfaces: [{ has_latency: false, has_loss: false }] });
    render(<PathData open onClose={() => {}} />);
    await waitFor(() => expect(item("discovery").dataset.state).toBe("on"));
    expect(item("discovery").textContent).toContain("Tracing 2 targets");
    expect(item("stamp").dataset.state).toBe("off");
    expect(item("tunnels").dataset.state).toBe("off");
    const nms = item("tunnels").querySelector("a");
    expect(nms?.getAttribute("href")).toBe("#/infrastructure/nms");
    expect(nms?.textContent).toBe("Infrastructure › NMS Integrations");
    expect(item("wan").textContent).toContain("1 interface found; none measured.");
    // An "on" source has nothing to turn on.
    expect(item("discovery").querySelector("a")).toBeNull();
  });

  it("a source that fails to read is unknown, never off", async () => {
    mockApi.probeTargetSuggestions.mockRejectedValue(new Error("403"));
    mockApi.tunnels.mockResolvedValue({ data: [], rows: 5, total: 5 });
    mockApi.wanInterfaces.mockRejectedValue(new Error("502"));
    render(<PathData open onClose={() => {}} />);
    await waitFor(() => expect(item("tunnels").dataset.state).toBe("on"));
    expect(item("discovery").dataset.state).toBe("unknown");
    expect(item("stamp").dataset.state).toBe("unknown");
    expect(item("wan").dataset.state).toBe("unknown");
    expect(item("wan").textContent).toContain("Could not be read.");
  });

  it("closes on Escape", async () => {
    mockApi.probeTargetSuggestions.mockResolvedValue({ path_discovery: true, active_probe: true, tracing: 0, suggestions: [] });
    mockApi.tunnels.mockResolvedValue({ data: [], rows: 0 });
    mockApi.wanInterfaces.mockResolvedValue({ interfaces: [] });
    const onClose = vi.fn();
    render(<PathData open onClose={onClose} />);
    window.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
    expect(onClose).toHaveBeenCalled();
    await waitFor(() => expect(item("discovery").dataset.state).toBe("on"));
  });
});
