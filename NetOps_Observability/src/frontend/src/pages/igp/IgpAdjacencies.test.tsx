// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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

type Cov = {
  events: boolean; live_series: boolean;
  lsdb: boolean; areas: boolean; spf_runs: boolean; timers: boolean;
};
/** The default: both adjacency sources answered, none of the four depth
 *  sources did — the state of a deployment that has not wired those
 *  collectors, which is what the "not collected" rendering must survive. */
const coverage = (over: Partial<Cov> = {}): Cov => ({
  events: true, live_series: true,
  lsdb: false, areas: false, spf_runs: false, timers: false, ...over,
});

/** The four depth blocks, all absent, with the server's own reasons. */
const noDepth = () => ({
  lsdb: { lsp_count: null, note: "no LSDB/LSP-count series is collected for these devices (device_isis_lsp_count …)" },
  areas: { areas: null, note: "IS-IS area addresses are not collected for these devices (device_isis_area …)" },
  spf_runs: { runs: null, note: "no SPF-run counter is collected for these devices (device_isis_spf_runs_total …)" },
  timers: { rows: null, note: "no IS-IS timer series is collected for these devices (device_isis_adj_hold_seconds …)" },
});

const adjBody = (over: Record<string, unknown> = {}) => ({
  protocol: "isis",
  device: "",
  window_seconds: 86400,
  since: "2026-09-01T12:00:00Z",
  now: "2026-09-02T12:00:00Z",
  adjacencies: [],
  event_count: 0,
  ...noDepth(),
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
  hold_seconds: null,
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
    // Six chips: the two adjacency sources plus the four depth sources, each
    // probed and reported independently.
    expect(document.querySelectorAll(".igp-cov-chip").length).toBe(6);
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
        { device: "leaf2", flaps: 4, changes: 6, up_events: 2, down_events: 4, last_change: "2026-09-02T11:00:00Z", adjacencies: null, down_adjacencies: null, lsp_count: null, spf_runs: null, areas: null },
      ],
      notes: ["roll-up covers only the 2000 most recent adjacency-change events in the window"],
      truncated: true,
    }));
    render(<IgpAdjacencies proto="isis" />);
    const rollup = await screen.findByLabelText("IS-IS roll-up by device (worst first)");
    await waitFor(() => expect(within(rollup).getByText("leaf2")).toBeTruthy());
    // adjacencies + down + LSDB + SPF runs + areas: every uncollected column on
    // the row says so, and not one of them is a 0.
    expect(within(rollup).getAllByText("not collected").length).toBe(5);
    expect(within(rollup).queryAllByText("0")).toHaveLength(0);
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
      levels: null,
      neighbor_count: null, adjacencies_up: null, adjacencies_down: null,
      adjacency_changes: 3, flaps: 2, last_change: "2026-09-02T11:00:00Z",
      stability: { flaps_per_hour: 2, score: 33.3, basis: "2 adjacency down-transitions over 1h, counted from syslog/trap adjacency-change events" },
      ...noDepth(),
      coverage: coverage({ live_series: false }),
      source: "events",
      notes: ["OSPF area membership is not collected for these devices (device_ospf_area …)"],
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

// ── the advanced depth (LSDB · areas · SPF runs · timers) ───────────────────
//
// The rendering rule under test is one sentence: a depth source that was not
// collected shows the words "Not collected" and the server's reason, and a
// depth source that WAS collected shows its number. Nothing in between, and no
// digit anywhere on an uncollected block.

const healthBody = (over: Record<string, unknown> = {}) => ({
  protocol: "isis", device: "spine1", device_name: "spine1",
  window_seconds: 86400, since: "s", now: "n",
  levels: ["L2"],
  neighbor_count: 4, adjacencies_up: 4, adjacencies_down: 0,
  adjacency_changes: 0, flaps: 0, last_change: "",
  stability: { flaps_per_hour: 0, score: 100, basis: "0 adjacency down-transitions over 24h" },
  ...noDepth(),
  coverage: coverage(),
  source: "events+live_series",
  notes: [],
  ...over,
});

/** Selects the device so the health + timers panels mount. */
async function pickDevice(id = "spine1") {
  const { fireEvent } = await import("@testing-library/react");
  fireEvent.change(screen.getByLabelText("Device") as HTMLSelectElement, { target: { value: id } });
}

describe("advanced depth blocks", () => {
  beforeEach(() => {
    devices.mockResolvedValue([{ id: "spine1", name: "spine1", address: "10.0.0.1", source: "gnmi", last_seen: "" }]);
  });

  it("renders a COLLECTED LSDB and SPF count with their per-level breakdown", async () => {
    igpHealth.mockResolvedValue(healthBody({
      lsdb: { lsp_count: 8, scope_label: "isis_level", by_scope: [{ scope: "L1", count: 2 }, { scope: "L2", count: 6 }] },
      spf_runs: { runs: 10, scope_label: "isis_level", by_scope: [{ scope: "L2", count: 10 }] },
      coverage: coverage({ lsdb: true, spf_runs: true }),
    }));
    render(<IgpAdjacencies proto="isis" />);
    await waitFor(() => expect(igpAdjacencies).toHaveBeenCalled());
    await pickDevice();
    const panel = await screen.findByLabelText("Device IGP health");
    const lsdb = panel.querySelector('.igp-depth[data-block="LSDB / LSP count"]') as HTMLElement;
    expect(lsdb.dataset.collected).toBe("yes");
    expect((lsdb.querySelector(".igp-depth-value") as HTMLElement).textContent).toBe("8");
    expect(lsdb.textContent).toContain("L1");
    expect(lsdb.textContent).toContain("L2");
    const spf = panel.querySelector('.igp-depth[data-block="SPF runs"]') as HTMLElement;
    expect(spf.dataset.collected).toBe("yes");
    expect((spf.querySelector(".igp-depth-value") as HTMLElement).textContent).toBe("10");
  });

  it("renders an UNCOLLECTED LSDB as 'Not collected' plus the server's reason — never a digit", async () => {
    igpHealth.mockResolvedValue(healthBody());
    render(<IgpAdjacencies proto="isis" />);
    await waitFor(() => expect(igpAdjacencies).toHaveBeenCalled());
    await pickDevice();
    const panel = await screen.findByLabelText("Device IGP health");
    const lsdb = panel.querySelector('.igp-depth[data-block="LSDB / LSP count"]') as HTMLElement;
    expect(lsdb.dataset.collected).toBe("no");
    expect(within(lsdb).getByText("Not collected")).toBeTruthy();
    expect(lsdb.textContent).toContain("device_isis_lsp_count");
    // The one thing that must never appear on an uncollected block.
    expect(lsdb.querySelector(".igp-depth-value")).toBeNull();
    expect(lsdb.textContent).not.toMatch(/\b0\b/);
  });

  it("shows collected area addresses, and 'not collected' when nothing collects them", async () => {
    igpHealth.mockResolvedValue(healthBody({
      areas: { areas: ["49.0001"] },
      coverage: coverage({ areas: true }),
    }));
    render(<IgpAdjacencies proto="isis" />);
    await waitFor(() => expect(igpAdjacencies).toHaveBeenCalled());
    await pickDevice();
    const panel = await screen.findByLabelText("Device IGP health");
    const areaRow = within(panel).getByText("IS-IS area addresses").closest("tr") as HTMLElement;
    expect(areaRow.textContent).toContain("49.0001");
    // Area membership and "levels with an adjacency" are DIFFERENT facts and
    // are shown as separate rows — one is configuration, one is topology.
    expect(within(panel).getByText("Levels with an adjacency")).toBeTruthy();
  });

  it("says 'not collected' for area membership when nothing collects it", async () => {
    igpHealth.mockResolvedValue(healthBody());
    render(<IgpAdjacencies proto="isis" />);
    await waitFor(() => expect(igpAdjacencies).toHaveBeenCalled());
    await pickDevice();
    const panel = await screen.findByLabelText("Device IGP health");
    const absent = within(panel).getByText("IS-IS area addresses").closest("tr") as HTMLElement;
    expect(absent.textContent).toContain("not collected");
  });

  it("renders IS-IS timers per adjacency, with the countdown caveat", async () => {
    igpHealth.mockResolvedValue(healthBody({
      timers: {
        scope_kind: "adjacency",
        rows: [{ device: "spine1", scope: "0100.0000.0011", ifname: "ethernet-1/1.0", level: "L2", hold_seconds: 27 }],
      },
      coverage: coverage({ timers: true }),
    }));
    render(<IgpAdjacencies proto="isis" />);
    await waitFor(() => expect(igpAdjacencies).toHaveBeenCalled());
    await pickDevice();
    const panel = await screen.findByLabelText("IGP timers");
    expect(within(panel).getByRole("columnheader", { name: "Neighbour" })).toBeTruthy();
    expect(within(panel).getByRole("columnheader", { name: "Hold remaining" })).toBeTruthy();
    expect(within(panel).getByText("27s")).toBeTruthy();
    // Without this sentence a sampled countdown reads as a configured timer.
    expect(panel.textContent).toMatch(/countdown/i);
  });

  it("renders OSPF timers per INTERFACE, with no per-neighbour column and no invented dead interval", async () => {
    igpHealth.mockResolvedValue(healthBody({
      protocol: "ospf", device: "edge1", device_name: "edge1",
      timers: {
        scope_kind: "interface",
        rows: [{ device: "edge1", scope: "10.0.0.5.0", hello_seconds: 30 }],
      },
      coverage: coverage({ timers: true }),
    }));
    devices.mockResolvedValue([{ id: "edge1", name: "edge1", address: "10.0.0.5", source: "snmp", last_seen: "" }]);
    render(<IgpAdjacencies proto="ospf" />);
    await waitFor(() => expect(igpAdjacencies).toHaveBeenCalled());
    await pickDevice("edge1");
    const panel = await screen.findByLabelText("IGP timers");
    expect(within(panel).getByRole("columnheader", { name: "Interface" })).toBeTruthy();
    expect(within(panel).queryByRole("columnheader", { name: "Neighbour" })).toBeNull();
    expect(within(panel).getByText("30s")).toBeTruthy();
    // The dead interval was not collected for this row: a dash, not a 0 and not
    // a value inferred from hello.
    expect(within(panel).getByText("—")).toBeTruthy();
    expect(panel.textContent).not.toContain("120s");
  });

  it("says why the timers panel is empty instead of showing an empty table", async () => {
    igpHealth.mockResolvedValue(healthBody());
    render(<IgpAdjacencies proto="isis" />);
    await waitFor(() => expect(igpAdjacencies).toHaveBeenCalled());
    await pickDevice();
    const panel = await screen.findByLabelText("IGP timers");
    expect(within(panel).getByText("Not collected")).toBeTruthy();
    expect(panel.textContent).toContain("device_isis_adj_hold_seconds");
    expect(panel.querySelector("table")).toBeNull();
  });

  it("carries the per-adjacency hold timer on the adjacency row, and only for IS-IS", async () => {
    igpAdjacencies.mockResolvedValue(adjBody({
      adjacencies: [
        adjRow({ peer: "0100.0000.0011", hold_seconds: 27 }),
        adjRow({ peer: "0100.0000.0012", hold_seconds: null }),
      ],
      timers: { scope_kind: "adjacency", rows: [] },
      coverage: coverage({ timers: true }),
    }));
    render(<IgpAdjacencies proto="isis" />);
    await waitFor(() => expect(view().dataset.state).toBe("ready"));
    const table = screen.getByLabelText("IS-IS adjacencies").querySelector("table") as HTMLElement;
    expect(within(table).getByRole("columnheader", { name: "Hold remaining" })).toBeTruthy();
    expect(within(table).getByText("27s")).toBeTruthy();
    // The adjacency with no hold sample says so — a 0 would read as "expiring".
    expect(within(table).getAllByText("not collected").length).toBe(1);
  });

  it("gives OSPF adjacencies NO hold column — OSPF-MIB has no per-neighbour timer", async () => {
    igpAdjacencies.mockResolvedValue(adjBody({
      protocol: "ospf",
      adjacencies: [adjRow({ level: undefined, hold_seconds: null })],
    }));
    render(<IgpAdjacencies proto="ospf" />);
    await waitFor(() => expect(view().dataset.state).toBe("ready"));
    const table = screen.getByLabelText("OSPF adjacencies").querySelector("table") as HTMLElement;
    expect(within(table).queryByRole("columnheader", { name: "Hold remaining" })).toBeNull();
  });
});
