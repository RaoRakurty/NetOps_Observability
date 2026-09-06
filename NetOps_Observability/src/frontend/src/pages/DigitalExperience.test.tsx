// DigitalExperience.test.tsx — the route target.
//
// This file used to pin a deliberate stub in place. The design of record is now
// ratified and the screen is live, so what it pins instead is that the route
// mounts the REAL surface: the seven-tab Digital Experience page, with its tab
// list and its measurement-window control. A route that silently fell back to a
// placeholder again would pass every other test in the suite.

import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach } from "vitest";

const mockApi = vi.hoisted(() => ({
  demOverview: vi.fn(),
  demExperience: vi.fn(),
}));
vi.mock("../services/api", async () => {
  const actual = await vi.importActual<Record<string, unknown>>("../services/api");
  return { ...actual, api: mockApi };
});

import DigitalExperience from "./DigitalExperience";

describe("DigitalExperience", () => {
  beforeEach(() => {
    window.location.hash = "";
    mockApi.demOverview.mockRejectedValue(new Error("503 Service Unavailable: not wired"));
    mockApi.demExperience.mockRejectedValue(new Error("503 Service Unavailable: not wired"));
  });

  it("mounts the Digital Experience surface, not a placeholder", async () => {
    render(<DigitalExperience />);
    expect(await screen.findByRole("tablist", { name: /digital experience/i })).toBeInTheDocument();
    for (const tab of ["Experience", "Incidents", "Journeys", "Service Paths", "Synthetics", "Changes", "Data Health"]) {
      expect(screen.getByRole("tab", { name: tab })).toBeInTheDocument();
    }
  });

  it("offers the measurement window and states the honesty rule the page follows", async () => {
    render(<DigitalExperience />);
    expect(await screen.findByRole("button", { name: /measure over the last 1h/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /measure over the last 24h/i })).toBeInTheDocument();
    // The honesty rule is still stated, in four words, with the reasoning behind
    // it one click away (ai/skills/explain/dem.absence-not-health.md).
    expect(screen.getByText(/Absent is not healthy\./)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /Ask Iris about an absent measurement/ }),
    ).toBeInTheDocument();
  });

  it("says the read failed rather than showing an empty screen as healthy", async () => {
    render(<DigitalExperience />);
    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
    expect(screen.getByRole("alert").textContent).toMatch(/could not be read/i);
  });
});
