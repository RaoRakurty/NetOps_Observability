// IgpAdjacencies render tests — the five honest states, and the one thing the
// PromQL board above this panel cannot do: tell "0 adjacencies down" apart from
// "nothing is watching this protocol". If a future edit ever makes an
// uncollected source render as a digit, these fail.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";

const devices = vi.fn();
const igpAdjacencies = vi.fn();
const igpSummary = vi.fn();
const igpHealth = vi.fn();

vi.mock("../../services/api", () => ({
  api: {
    devices: (...a: unknown[]) => devices(...a),
    igpAdjacencies: (...a: unknown[]) => igpAdjacencies(...a),
    igpSummary: (...a: unknown[]) => igpSummary(...a),
    igpHealth: (...a: unknown[]) => igpHealth(...a),
  },
}));
// The Panel primitive pulls the chart/modal stack; the honesty contract lives in
// what we put INSIDE it, so render it as a plain section.
vi.mock("../../components/board/panels", () => ({
  Panel: ({ title, children }: { title: string; children: React.ReactNode }) => (
    <section aria-label={title}>{children}</section>
  ),
}));

import IgpAdjacencies from "./IgpAdjacencies";

const coverage = (over: Partial<{ events: boolean; live_series: boolean; lsdb: boolean }> = {}) => ({
  events: true, live_series: true, lsdb: false, ...over,
});

const adjBody = (over: Record<string, unknown> = {}) => ({
  protocol: "isis",
  device: "",
  window_seconds: 86400,
  since: "2026-09-01T12:00:00Z",
  now: "2026-09-02T12:00:00Z",
  adjacencies: [],
  event_count: 0,
  coverage: coverage(),
  source: "events+live_series",
  notes: [],
  limit: 200,
  truncated: false,
  next_cursor: "",
  ...over,
});

const sumBody = (over: Record<string, unknown> = {}) => ({
  protocol: "isis",
  window_seconds: 86400,
  since: "s",
  now: "n",
  devices: [],
  event_count: 0,
  coverage: coverage(),
  source: "events+live_series",
  notes: [],
  limit: 100,
  truncated: false,
  ...over,
});

const adjRow = (over: Record<string, unknown> = {}) => ({
  device: "leaf1",
  peer: "0000.0000.0002",
  ifname: "ethernet-1/1",
  level: "L2",
  current_state: "up",
  state_source: "live_series",
  up: true,
  last_change: "",
  flaps: 0,
  changes: 0,
  up_events: 0,
  down_events: 0,
  timeline: [],
  ...over,
});

beforeEach(() => {
  vi.clearAllMocks();
  devices.mockResolvedValue([{ id: "leaf1", name: "leaf1", address: "10.0.0.1", source: "snmp", last_seen: "" }]);
  igpAdjacencies.mockResolvedValue(adjBody());
  igpSummary.mockResolvedValue(sumBody());
  igpHealth.mockResolvedValue({});
});
afterEach(cleanup);

const view = () => document.querySelector(".igp-view") as HTMLElement;

describe("loading", () => {
  it("shows a loading state before either call resolves — never an empty table", async () => {
    igpAdjacencies.mockImplementation(() => new Promise(() => {}));
    igpSummary.mockImplementation(() => new Promise(() => {}));
    render(<IgpAdjacencies proto="isis" />);
    expect(view().dataset.state).toBe("loading");
    expect(await screen.findAllByText("Loading…")).not.toHaveLength(0);
  });
});

describe("error", () => {
  it("renders a REJECTED fetch as an error carrying the status — never as 'nothing wrong'", async () => {
    igpAdjacencies.mockImplementation(() => Promise.reject(new Error("503 Service Unavailable")));
    render(<IgpAdjacencies proto="ospf" />);
    await waitFor(() => expect(view().dataset.state).toBe("error"));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("503 Service Unavailable");
    expect(document.body.textContent).not.toMatch(/all clear|healthy/i);
  });
});

describe("not_connected", () => {
  it("says the protocol is NOT OBSERVED when neither evidence class answered", async () => {
    igpAdjacencies.mockResolvedValue(adjBody({
      protocol: "ospf",
      coverage: coverage({ events: false, live_series: false }),
      source: "none",
      notes: ["no live series collected for this device; adjacency history is from syslog/trap events only"],
    }));
    render(<IgpAdjacencies proto="ospf" />);
    await waitFor(() => expect(view().dataset.state).toBe("not_connected"));
    expect(document.body.textContent).toContain("not observed on this deployment");
    expect(screen.getAllByText("Not collected").length).toBeGreaterThan(0);
  });

  it("never renders an uncollected count as 0", async () => {
    igpAdjacencies.mockResolvedValue(adjBody({
      coverage: coverage({ live_series: false }),
      adjacencies: [adjRow({ state_source: "events", up: null, current_state: "down", flaps: 2 })],
      notes: ["no live series collected for this device"],
    }));
    render(<IgpAdjacencies proto="isis" />);
    await waitFor(() => expect(view().dataset.state).toBe("ready"));

    const up = screen.getByText("Up now").closest(".ds-stat") as HTMLElement;
    const down = screen.getByText("Down now").closest(".ds-stat") as HTMLElement;
    expect(within(up).getByText("not collected")).toBeTruthy();
    expect(within(down).getByText("not collected")).toBeTruthy();
    // and the tile carries no reassuring tone
    expect(up.className).not.toContain("good");
    expect(down.className).not.toContain("bad");
  });
});

describe("empty", () => {
  it("distinguishes 'the sources answered and were quiet' from 'not collected'", async () => {
    igpAdjacencies.mockResolvedValue(adjBody({ adjacencies: [] }));
    render(<IgpAdjacencies proto="isis" />);
    await waitFor(() => expect(view().dataset.state).toBe("empty"));
    expect(document.body.textContent).toContain("The sources answered");
    expect(document.body.textContent).not.toContain("not observed on this deployment");
    // The coverage strip still renders, and still says what IS collected.
    expect(document.querySelectorAll(".igp-cov-chip").length).toBe(3);
  });
});

describe("ready", () => {
  it("renders per-adjacency state, its source and a timeline", async () => {
    igpAdjacencies.mockResolvedValue(adjBody({
      adjacencies: [
        adjRow({ peer: "0000.0000.0003", current_state: "down", up: false, flaps: 3, last_change: "2026-09-02T11:00:00Z",
          timeline: [
            { ts: "2026-09-02T11:00:00Z", signal_id: "s3", device: "leaf1", state: "down", severity: "warn", source: "syslog" },
            { ts: "2026-09-02T10:00:00Z", signal_id: "s2", device: "leaf1", state: "up", severity: "info", source: "trap" },
          ] }),
        adjRow({ peer: "0000.0000.0002" }),
      ],
    }));
    render(<IgpAdjacencies proto="isis" />);
    await waitFor(() => expect(view().dataset.state).toBe("ready"));

    // Worst-first: the down adjacency leads.
    const rows = document.querySelectorAll("tbody tr[data-source]");
    expect(rows[0].textContent).toContain("0000.0000.0003");
    expect((rows[0] as HTMLElement).dataset.tone).toBe("bad");
    expect((rows[1] as HTMLElement).dataset.tone).toBe("good");
    expect(rows[0].textContent).toContain("(live)");

    // Oldest → newest ticks.
    const ticks = rows[0].querySelectorAll(".igp-tick");
    expect(ticks).toHaveLength(2);
    expect((ticks[0] as HTMLElement).dataset.state).toBe("up");
    expect((ticks[1] as HTMLElement).dataset.state).toBe("down");

    // Live counts ARE numbers here, because a live series backed them.
    const up = screen.getByText("Up now").closest(".ds-stat") as HTMLElement;
    expect(within(up).getByText("1")).toBeTruthy();
  });

  it("renders the roll-up with nullable live counts kept honest", async () => {
    igpSummary.mockResolvedValue(sumBody({
      coverage: coverage({ live_series: false }),
      devices: [
        { device: "leaf2", flaps: 4, changes: 6, up_events: 2, down_events: 4, last_change: "2026-09-02T11:00:00Z", adjacencies: null, down_adjacencies: null },
      ],
      notes: ["roll-up covers only the 2000 most recent adjacency-change events in the window"],
      truncated: true,
    }));
    render(<IgpAdjacencies proto="isis" />);
    const rollup = await screen.findByLabelText("IS-IS roll-up by device (worst first)");
    await waitFor(() => expect(within(rollup).getByText("leaf2")).toBeTruthy());
    expect(within(rollup).getAllByText("not collected").length).toBe(2); // adjacencies + down
    expect(rollup.textContent).toContain("This roll-up is partial");
    expect(rollup.textContent).toContain("2000 most recent");
  });

  it("shows the OSPF state legend and no IS-IS Level column", async () => {
    igpAdjacencies.mockResolvedValue(adjBody({ protocol: "ospf", adjacencies: [adjRow({ level: undefined })] }));
    render(<IgpAdjacencies proto="ospf" />);
    await waitFor(() => expect(view().dataset.state).toBe("ready"));
    expect(document.body.textContent).toContain("8 full");
    expect(screen.queryByRole("columnheader", { name: "Level" })).toBeNull();
    expect(screen.getByRole("columnheader", { name: /Neighbour \(router/ })).toBeTruthy();
  });
});

describe("health block", () => {
  it("appears only for a chosen device, and renders nulls as 'not collected'", async () => {
    render(<IgpAdjacencies proto="ospf" />);
    await waitFor(() => expect(igpAdjacencies).toHaveBeenCalled());
    expect(screen.queryByLabelText("Device IGP health")).toBeNull();
    expect(igpHealth).not.toHaveBeenCalled();

    igpHealth.mockResolvedValue({
      protocol: "ospf", device: "leaf1", device_name: "leaf1",
      window_seconds: 86400, since: "s", now: "n",
      areas: null, levels: null,
      neighbor_count: null, adjacencies_up: null, adjacencies_down: null,
      adjacency_changes: 3, flaps: 2, last_change: "2026-09-02T11:00:00Z",
      stability: { flaps_per_hour: 2, score: 33.3, basis: "2 adjacency down-transitions over 1h, counted from syslog/trap adjacency-change events" },
      lsdb: { lsp_count: null, note: "no LSDB/LSP-count series is collected on this deployment" },
      coverage: coverage({ live_series: false }),
      source: "events",
      notes: ["OSPF area membership is not collected on this deployment"],
    });

    const select = screen.getByLabelText("Device") as HTMLSelectElement;
    const { fireEvent } = await import("@testing-library/react");
    fireEvent.change(select, { target: { value: "leaf1" } });

    const panel = await screen.findByLabelText("Device IGP health");
    await waitFor(() => expect(igpHealth).toHaveBeenCalledWith("ospf", "leaf1", { since: "24h" }));
    await waitFor(() => expect(within(panel).getByText("2 adjacency down-transitions over 1h, counted from syslog/trap adjacency-change events")).toBeTruthy());

    // Neighbours / up / down / LSDB are all absent → phrases, never zeros.
    expect(within(panel).getAllByText("not collected").length).toBeGreaterThanOrEqual(4);
    // The flap count IS measured, so it is a number.
    const flaps = within(panel).getByText("Flaps in window").closest(".ds-stat") as HTMLElement;
    expect(within(flaps).getByText("2")).toBeTruthy();
    // And the server's own reason is shown.
    expect(panel.textContent).toContain("OSPF area membership is not collected");
  });
});

describe("controls", () => {
  it("asks the server for the chosen window, using only values the server accepts", async () => {
    render(<IgpAdjacencies proto="isis" />);
    await waitFor(() => expect(igpAdjacencies).toHaveBeenCalledWith("isis", { device: undefined, since: "24h" }));

    const { fireEvent } = await import("@testing-library/react");
    fireEvent.click(screen.getByRole("button", { name: "7d" }));
    await waitFor(() => expect(igpAdjacencies).toHaveBeenLastCalledWith("isis", { device: undefined, since: "7d" }));
    expect(igpSummary).toHaveBeenLastCalledWith("isis", { since: "7d" });
  });

  it("keeps working when the device inventory cannot be read", async () => {
    devices.mockImplementation(() => Promise.reject(new Error("403 Forbidden")));
    render(<IgpAdjacencies proto="isis" />);
    await waitFor(() => expect(view().dataset.state).toBe("empty"));
    const select = screen.getByLabelText("Device") as HTMLSelectElement;
    expect(select.options).toHaveLength(1);
    expect(select.options[0].textContent).toBe("All devices");
  });
});
