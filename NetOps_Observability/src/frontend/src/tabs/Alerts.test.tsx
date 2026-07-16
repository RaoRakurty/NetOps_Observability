// Alerts.test.tsx — the Active Alerts page grouped by EPISODE: repeated
// firings render as one row with a count badge, first/last seen, a flap chip
// and an HONEST suppressed state (muted episodes stay visible), plus the
// per-row triage affordance (acknowledge / assign / mute / snooze / notes).

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";

const alertEpisodes = vi.fn();
const alerts = vi.fn();
const episodeAck = vi.fn();
const episodeMute = vi.fn();
const episodeAssign = vi.fn();
const episodeSnooze = vi.fn();
const episodeNote = vi.fn();

vi.mock("../services/api", () => ({
  api: {
    alertEpisodes: (...a: unknown[]) => alertEpisodes(...a),
    alerts: (...a: unknown[]) => alerts(...a),
    episodeAck: (...a: unknown[]) => episodeAck(...a),
    episodeMute: (...a: unknown[]) => episodeMute(...a),
    episodeAssign: (...a: unknown[]) => episodeAssign(...a),
    episodeSnooze: (...a: unknown[]) => episodeSnooze(...a),
    episodeNote: (...a: unknown[]) => episodeNote(...a),
  },
}));

import Alerts, { EpisodeDetailBody } from "./Alerts";

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
  alertEpisodes.mockResolvedValue({ episodes: [baseEpisode, mutedEpisode], total: 2, truncated: false });
  alerts.mockResolvedValue([{ id: "a1" }, { id: "a2" }, { id: "a3" }]);
});

describe("Active Alerts grouped by episode", () => {
  it("renders one row per episode with count badge, first/last seen, flap chip and honest suppressed state", async () => {
    render(<Alerts />);
    await waitFor(() => expect(alertEpisodes).toHaveBeenCalledWith("open"));

    // Count badge: 7 firings folded into ×7.
    expect(await screen.findByText("×7")).toBeTruthy();
    // First/last seen render for the episode row.
    expect(screen.getAllByText(new Date("2026-07-16T08:00:00Z").toLocaleString()).length).toBeGreaterThan(0);
    expect(screen.getAllByText(new Date("2026-07-16T09:30:00Z").toLocaleString()).length).toBeGreaterThan(0);
    // Flap chip is visible — flapping is surfaced, never hidden. (It also
    // appears as a KPI label, so assert at least one chip exists.)
    expect(screen.getAllByText("Flapping").length).toBeGreaterThan(0);
    // The muted episode STAYS in the list, with its paused state disclosed.
    expect(screen.getByText("LinkDown")).toBeTruthy();
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

describe("EpisodeDetailBody triage affordances", () => {
  it("mutes notifications only — wording promises the row stays visible", async () => {
    episodeMute.mockResolvedValue({ ...baseEpisode, muted: true, muted_by: "admin" });
    render(<EpisodeDetailBody episode={baseEpisode} />);
    fireEvent.click(screen.getByRole("button", { name: "Mute notifications" }));
    await waitFor(() => expect(episodeMute).toHaveBeenCalledWith("ep-1", true));
    expect(await screen.findByRole("button", { name: "Resume notifications" })).toBeTruthy();
    expect(screen.getByText(/Notifications are paused for this episode/)).toBeTruthy();
  });

  it("assigns to a username and snoozes for a preset duration", async () => {
    episodeAssign.mockResolvedValue({ ...baseEpisode, assigned_to: "noc-lee", assigned_by: "admin" });
    episodeSnooze.mockResolvedValue({ ...baseEpisode, snoozed_until: new Date(Date.now() + 7_200_000).toISOString() });
    render(<EpisodeDetailBody episode={baseEpisode} />);

    fireEvent.change(screen.getByLabelText("Assignee"), { target: { value: "noc-lee" } });
    fireEvent.click(screen.getByRole("button", { name: "Assign" }));
    await waitFor(() => expect(episodeAssign).toHaveBeenCalledWith("ep-1", "noc-lee"));

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
