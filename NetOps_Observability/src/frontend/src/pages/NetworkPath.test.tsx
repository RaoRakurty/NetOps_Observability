// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// NetworkPath.test.tsx — Investigate → Paths → Measured paths (Paths redesign
// P0, 2026-11-20).
//
// The page's empty state used to point at "API settings" that do not exist,
// and the path-health empty state printed environment variable names a
// customer can never set. Both now say what is true. Service checks moved to a
// link: they measure a service, not a path, and Digital Experience owns them.

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, waitFor } from "@testing-library/react";

const mockApi = vi.hoisted(() => ({
  probePaths: vi.fn(),
  pathsHealth: vi.fn(),
  metricsQueryRange: vi.fn(),
  features: vi.fn(),
  devices: vi.fn(),
}));

vi.mock("../services/api", () => ({ api: mockApi }));

import NetworkPath from "./NetworkPath";

beforeEach(() => {
  mockApi.probePaths.mockResolvedValue([]);
  mockApi.pathsHealth.mockResolvedValue({ paths: [] });
  mockApi.metricsQueryRange.mockResolvedValue({ data: { result: [] } });
  mockApi.features.mockResolvedValue({});
  mockApi.devices.mockResolvedValue([]);
});
afterEach(() => { cleanup(); vi.clearAllMocks(); });

describe("Measured paths — empty states say what is true", () => {
  it("says path discovery is not switched on, with no setting that does not exist", async () => {
    render(<NetworkPath />);
    const hint = await screen.findByTestId("paths-empty-hint");
    expect(hint.textContent).toBe("Path discovery is not switched on for this installation yet.");
    expect(document.body.textContent).not.toMatch(/API settings/);
  });

  it("names no environment variable anywhere on the page", async () => {
    render(<NetworkPath />);
    await screen.findByTestId("path-health-none");
    expect(document.body.textContent).not.toMatch(/\b(FEATURE|ENABLE)_[A-Z_]+|\b[A-Z]+_TARGETS\b/);
    expect(document.querySelectorAll("code").length).toBe(0);
  });

  it("links service checks to Digital Experience › Synthetics instead of repeating them", async () => {
    render(<NetworkPath />);
    const p = await screen.findByTestId("paths-synthetics-link");
    expect(p.querySelector("a")?.getAttribute("href")).toBe("#/operations/digital-experience/synthetics");
    expect(screen.queryByText("Service checks")).toBeNull();
    expect(screen.queryByText(/HTTP total time/)).toBeNull();
  });

  it("renders a measured path when the prober has one", async () => {
    mockApi.probePaths.mockResolvedValue([
      { dst: "10.20.0.1", reached: true, changed: false, hops: [{ ttl: 1, ip: "10.0.0.1", rtt_ms: 1.2, loss_pct: 0 }] },
    ]);
    render(<NetworkPath />);
    await waitFor(() => expect(screen.getByText("10.20.0.1 — 1 hops")).toBeTruthy());
    expect(screen.queryByTestId("paths-empty-hint")).toBeNull();
  });
});
