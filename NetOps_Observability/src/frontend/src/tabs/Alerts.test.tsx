// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Alerts.test.tsx — the Active Alerts page grouped by EPISODE: repeated
// firings render as one row with a count badge, first/last seen, a flap chip
// and an HONEST suppressed state (muted episodes stay visible), plus the
// per-row triage affordance (acknowledge / assign / mute / snooze / notes).

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";
import { fmtDateTime } from "../lib/time";

const alertEpisodes = vi.fn();
const alerts = vi.fn();
const episodeAck = vi.fn();
const episodeMute = vi.fn();
const episodeAssign = vi.fn();
const episodeSnooze = vi.fn();
const episodeNote = vi.fn();
const devices = vi.fn();

vi.mock("../services/api", () => ({
  api: {
    alertEpisodes: (...a: unknown[]) => alertEpisodes(...a),
    alerts: (...a: unknown[]) => alerts(...a),
    episodeAck: (...a: unknown[]) => episodeAck(...a),
    episodeMute: (...a: unknown[]) => episodeMute(...a),
    episodeAssign: (...a: unknown[]) => episodeAssign(...a),
    episodeSnooze: (...a: unknown[]) => episodeSnooze(...a),
    episodeNote: (...a: unknown[]) => episodeNote(...a),
    devices: (...a: unknown[]) => devices(...a),
  },
}));

import Alerts, { EpisodeDetailBody } from "./Alerts";
import { resetDeviceNamesForTest } from "../lib/deviceNames";

const baseEpisode = {
  id: "ep-1",
  resource: "leaf1",
  signal: "HighCPU",
  state: "critical",
  summary: "CPU 97% on leaf1",
  status: "active" as const,
  first_seen: "2026-07-16T08:00:00Z",
  last_seen: "2026-07-16T09:30:00Z",
  count: 7,
  flapping: true,
  flip_count: 6,
};

const mutedEpisode = {
  id: "ep-2",
  resource: "spine2",
  signal: "LinkDown",
  state: "warning",
  summary: "Link down on spine2",
  status: "cleared" as const,
  first_seen: "2026-07-16T07:00:00Z",
  last_seen: "2026-07-16T09:00:00Z",
  count: 3,
  muted: true,
  muted_by: "noc-lee",
};

afterEach(cleanup);

beforeEach(() => {
  vi.clearAllMocks();
  resetDeviceNamesForTest();
  devices.mockResolvedValue([{ id: "leaf1", name: "Leaf-1", address: "10.0.0.1" }]);
  alertEpisodes.mockResolvedValue({ episodes: [baseEpisode, mutedEpisode], total: 2, truncated: false });
  alerts.mockResolvedValue([{ id: "a1" }, { id: "a2" }, { id: "a3" }]);
});

describe("Active Alerts grouped by episode", () => {
  it("renders one row per episode with count badge, first/last seen, flap chip and honest suppressed state", async () => {
    render(<Alerts />);
    // The Firing tab asks the episode API for active episodes (no client re-filter).
    await waitFor(() => expect(alertEpisodes).toHaveBeenCalledWith("active"));

    // Count badge: 7 firings folded into ×7.
    expect(await screen.findByText("×7")).toBeTruthy();
    // First/last seen render for the episode row — through the shared labeled
    // time authority (lib/time), never an unlabeled toLocaleString.
    expect(screen.getAllByText(fmtDateTime("2026-07-16T08:00:00Z")).length).toBeGreaterThan(0);
    expect(screen.getAllByText(fmtDateTime("2026-07-16T09:30:00Z")).length).toBeGreaterThan(0);
    // Flap chip is visible — flapping is surfaced, never hidden. (It also
    // appears as a KPI label, so assert at least one chip exists.)
    expect(screen.getAllByText("Flapping").length).toBeGreaterThan(0);
    // The muted episode STAYS in the list, with its paused state disclosed.
    expect(screen.getByText("LinkDown on spine2")).toBeTruthy();
    // The device reads by its inventory NAME (owner, 2026-11-22), not the raw id.
    expect(await screen.findByText("HighCPU on Leaf-1")).toBeTruthy();
    // (Also a KPI label — assert the chip exists alongside it.)
    expect(screen.getAllByText("Notifications paused").length).toBeGreaterThan(1);
  });

  it("opens the triage panel from a row and acknowledges as the signed-in user", async () => {
    episodeAck.mockResolvedValue({ ...baseEpisode, acknowledged_by: "admin", acknowledged_at: "2026-07-16T10:00:00Z" });
    render(<Alerts />);
    fireEvent.click(await screen.findByText("×7")); // v1 fallback: inline detail

    const ackBtn = await screen.findByRole("button", { name: "Acknowledge" });
    fireEvent.click(ackBtn);
    await waitFor(() => expect(episodeAck).toHaveBeenCalledWith("ep-1", true));
    // The response reflects back into the UI (ack chip / undo affordance).
    expect(await screen.findByRole("button", { name: "Undo acknowledge" })).toBeTruthy();
  });
});

// The page used to swallow its load failure with `catch { /* ignore — top-level
// health banner shows the failure */ }`. That comment was false: the global
// indicator polls a separate /healthz that stays 200 during a route-scoped 500,
// so an alerts outage rendered green zeros and the sentence "all monitored
// conditions are within threshold" — a failure reported as good news.
describe("Active Alerts on a failed load", () => {
  it("never claims conditions are within threshold when the episode fetch rejects", async () => {
    alertEpisodes.mockImplementation(() => Promise.reject(new Error("500 Internal Server Error")));
    alerts.mockImplementation(() => Promise.reject(new Error("500 Internal Server Error")));
    render(<Alerts />);
    await waitFor(() => expect(alertEpisodes).toHaveBeenCalled());

    // The forbidden sentence, in any form.
    await waitFor(() => expect(screen.queryByText(/within threshold/)).toBeNull());
    expect(screen.queryByText(/No open alert episodes/)).toBeNull();

    // A real, page-scoped error state is rendered instead.
    expect(await screen.findByText(/Alert episodes could not be loaded\./)).toBeTruthy();
    // The words shrank in the 2026-09-06 sweep; the CLAIM must not.
    expect(screen.getByText(/Unknown, not all-clear\./)).toBeTruthy();
    expect(screen.getByRole("button", { name: /Ask Iris about an unavailable alert feed/ })).toBeTruthy();
    expect(screen.getAllByText("Feed unavailable").length).toBeGreaterThan(0);
  });

  it("renders the KPIs as unknown, not as green zeros", async () => {
    alertEpisodes.mockImplementation(() => Promise.reject(new Error("503 Service Unavailable")));
    alerts.mockImplementation(() => Promise.reject(new Error("503 Service Unavailable")));
    render(<Alerts />);

    // Every KPI reads "—" (unknown); none reads a confident 0. The caption that
    // used to spell out "unknown — feed failed" under each tile is gone (word
    // sweep); the em dash IS the claim, and what it means is on the tile's (i).
    await waitFor(() => expect(screen.getAllByText("—").length).toBe(4));
    expect(screen.queryByText("0")).toBeNull();
    expect(screen.getAllByRole("button", { name: /^Ask Iris about/ }).length).toBeGreaterThanOrEqual(4);
  });
});

describe("EpisodeDetailBody triage affordances", () => {
  it("mutes notifications only — wording promises the row stays visible", async () => {
    episodeMute.mockResolvedValue({ ...baseEpisode, muted: true, muted_by: "admin" });
    render(<EpisodeDetailBody episode={baseEpisode} />);
    fireEvent.click(screen.getByRole("button", { name: "Mute notifications" }));
    await waitFor(() => expect(episodeMute).toHaveBeenCalledWith("ep-1", true));
    expect(await screen.findByRole("button", { name: "Resume notifications" })).toBeTruthy();
    expect(screen.getByText(/Notifications paused by admin\./)).toBeTruthy();
  });

  it("assigns to a username and snoozes for a preset duration", async () => {
    // The assign answer arrives a little later, as it does on a loaded CI runner.
    episodeAssign.mockImplementation(() => new Promise((r) => setTimeout(() => r({ ...baseEpisode, assigned_to: "noc-lee", assigned_by: "admin" }), 50)));
    episodeSnooze.mockResolvedValue({ ...baseEpisode, snoozed_until: new Date(Date.now() + 7_200_000).toISOString() });
    render(<EpisodeDetailBody episode={baseEpisode} />);

    fireEvent.change(screen.getByLabelText("Assignee"), { target: { value: "noc-lee" } });
    fireEvent.click(screen.getByRole("button", { name: "Assign" }));
    await waitFor(() => expect(episodeAssign).toHaveBeenCalledWith("ep-1", "noc-lee"));
    // Tracker 429: every action button is disabled while a request is in flight.
    // The call above is recorded the moment Assign is clicked, long before the
    // answer lands, so wait for the assignment itself (and the buttons coming
    // back) — a click on a still-disabled Snooze is silently dropped.
    expect(await screen.findByText("Assigned to")).toBeTruthy();
    await waitFor(() => expect((screen.getByRole("button", { name: "Snooze" }) as HTMLButtonElement).disabled).toBe(false));

    fireEvent.click(screen.getByRole("button", { name: "Snooze" }));
    await waitFor(() => expect(episodeSnooze).toHaveBeenCalledTimes(1));
    const [id, until] = episodeSnooze.mock.calls[0] as [string, string];
    expect(id).toBe("ep-1");
    expect(Date.parse(until)).toBeGreaterThan(Date.now()); // future RFC3339 stamp
  });

  it("adds a note and renders the note trail", async () => {
    episodeNote.mockResolvedValue({
      ...baseEpisode,
      notes: [{ at: "2026-07-16T10:00:00Z", by: "admin", text: "correlated with maintenance" }],
    });
    render(<EpisodeDetailBody episode={baseEpisode} />);
    fireEvent.change(screen.getByLabelText("New note"), { target: { value: "correlated with maintenance" } });
    fireEvent.click(screen.getByRole("button", { name: "Add note" }));
    await waitFor(() => expect(episodeNote).toHaveBeenCalledWith("ep-1", "correlated with maintenance"));
    expect(await screen.findByText("correlated with maintenance")).toBeTruthy();
  });
});

describe("Active Alerts in the Logs pattern (owner, 2026-11-22)", () => {
  it("each tab asks the episode API for its own status", async () => {
    render(<Alerts />);
    await waitFor(() => expect(alertEpisodes).toHaveBeenCalledWith("active"));
    fireEvent.click(screen.getByRole("button", { name: /^Cleared/ }));
    await waitFor(() => expect(alertEpisodes).toHaveBeenCalledWith("cleared"));
    fireEvent.click(screen.getByRole("button", { name: /^All/ }));
    await waitFor(() => expect(alertEpisodes).toHaveBeenCalledWith("all"));
  });

  it("a cut list says so, and its tiles say they count the loaded rows only", async () => {
    alertEpisodes.mockResolvedValue({ episodes: [baseEpisode, mutedEpisode], total: 900, truncated: true });
    render(<Alerts />);
    expect(await screen.findByTestId("alerts-truncated")).toBeTruthy();
    expect(screen.getByText("Counted in the 2 loaded episodes of 900.")).toBeTruthy();
  });

  it("a severity tile filters the list to that severity", async () => {
    render(<Alerts />);
    await screen.findByText("LinkDown on spine2");
    fireEvent.click(screen.getByRole("button", { name: /^Critical: 1/ }));
    await waitFor(() => expect(screen.queryByText("LinkDown on spine2")).toBeNull());
    expect(screen.getByText(/HighCPU on/)).toBeTruthy();
  });

  it("a row opens a side panel; Esc closes it", async () => {
    render(<Alerts />);
    fireEvent.click(await screen.findByText("×7"));
    const dlg = await screen.findByRole("dialog");
    expect(dlg.getAttribute("aria-modal")).toBe("true");
    fireEvent.keyDown(document, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });
});
