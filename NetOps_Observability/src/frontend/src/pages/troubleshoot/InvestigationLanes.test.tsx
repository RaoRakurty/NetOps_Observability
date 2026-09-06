// InvestigationLanes.test.tsx — the parallel evidence lanes.
//
// Every lane must render FIVE honest states — loading, error, not_connected,
// empty, ready — and must NAME the API it read so nothing on the page is
// unverifiable. The two states this file guards hardest are `not_connected`
// (the source was never wired: we cannot see) and `empty` (the source is wired
// and was quiet: we looked). A lane that collapses them is lying to the NOC.
//
// Nothing here renders HTML from a remote string: the hostile-value tests assert
// that a device name carrying markup arrives on screen as characters (§15).

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, within } from "@testing-library/react";
import type { FeedItem, PathHealthItem, ProbePath, PromInstantSeries } from "../../services/api";

const mocks = vi.hoisted(() => ({
  pathsHealth: vi.fn(), eventsFeed: vi.fn(), metricNames: vi.fn(), metricsQuery: vi.fn(),
  probePaths: vi.fn(), flowsByType: vi.fn(), topTalkers: vi.fn(),
}));
vi.mock("../../services/api", () => ({ api: { ...mocks } }));

import {
  ChangedLane, DemLane, EventsLane, FlowsLane, HealthLane, PathLane, RoutingLane,
  LANE_COMPONENT, type LaneScope,
} from "./InvestigationLanes";
import { ALL_LANES, LANE_SOURCE, LANE_TITLE, type LaneId, type LaneState } from "./investigationModel";

// ── fixtures ─────────────────────────────────────────────────────────────────

const scope: LaneScope = { minutes: 60 };
const scoped: LaneScope = { device: "wan-r1", minutes: 120, caseId: "corr-1" };
const never = () => new Promise<never>(() => { /* stays pending: the loading state */ });

const feed = (over: Partial<FeedItem> = {}): FeedItem => ({
  signal_id: "sig-1", ts: "2026-08-25 10:00:00", source: "lab", kind: "link_down",
  severity: "warning", entity_type: "device", entity_id: "wan-r1", site: "dc1",
  title: "Link down", correlation_id: null, ...over,
});
const pathHealth = (over: Partial<PathHealthItem> = {}): PathHealthItem => ({
  path_id: "p1", agent: "probe-a", dst: "10.0.0.1", health_state: "degraded", score: 40,
  confidence: "medium", severities: {}, baseline_source: "rolling", reason: "loss above baseline",
  likely_fault_domain: "wan", evidence: [],
  current: { latency_p95_5m: 30, jitter_p95_5m: 3, loss_pct_5m: 1 },
  baseline: { source: "rolling", source_label: "7d", window: "7d", sample_count: 100, latency_p50: 20, latency_p99: 40, jitter_p50: 2, jitter_p99: 5 },
  ...over,
});
const probePath = (over: Partial<ProbePath> = {}): ProbePath =>
  ({ dst: "10.0.0.1", method: "icmp", hops: [{ ttl: 1, ip: "10.0.0.254" }], reached: true, changed: false, ts: "t", ...over });
const promSeries = (metric: Record<string, string>): PromInstantSeries => ({ metric, value: [0, "1"] });

const card = (id: LaneId) => screen.getByRole("region", { name: LANE_TITLE[id] });
const stateOf = (id: LaneId) => card(id).getAttribute("data-state");

// Default: every source is wired and has rows, so a test only overrides what it
// is about (and a lane never silently reads a mock another test left behind).
beforeEach(() => {
  Object.values(mocks).forEach((f) => f.mockReset());
  mocks.pathsHealth.mockResolvedValue({ paths: [pathHealth()], count: 1 });
  mocks.eventsFeed.mockResolvedValue({ items: [feed()] });
  mocks.metricNames.mockResolvedValue({ status: "success", data: ["device_if_oper_status", "device_bgp_peer_state"] });
  mocks.metricsQuery.mockResolvedValue({ status: "success", data: { resultType: "vector", result: [promSeries({ device: "wan-r1", ifName: "Gi0/1" })] } });
  mocks.probePaths.mockResolvedValue([probePath()]);
  mocks.flowsByType.mockResolvedValue({ data: [{ flow_type: "netflow", flows: 10, exporters: 2 }] });
  mocks.topTalkers.mockResolvedValue({ data: [{ src_addr: "10.1.1.1", dst_addr: "10.2.2.2", bytes: 1234 }] });
});
afterEach(() => cleanup());

// ── the registry ─────────────────────────────────────────────────────────────

describe("LANE_COMPONENT", () => {
  it("has a component for every lane the model knows about", () => {
    expect(Object.keys(LANE_COMPONENT).sort()).toEqual([...ALL_LANES].sort());
  });

  it("every lane names the API it read on its own card", async () => {
    for (const id of ALL_LANES) {
      const Lane = LANE_COMPONENT[id];
      const { unmount } = render(<Lane scope={scope} />);
      await waitFor(() => expect(stateOf(id)).not.toBe("loading"));
      expect(within(card(id)).getByText(LANE_SOURCE[id])).toBeInTheDocument();
      unmount();
    }
  });
});

// ── the five states, lane by lane ────────────────────────────────────────────

describe("every lane renders the loading state before its source answers", () => {
  it.each(ALL_LANES)("%s", (id) => {
    Object.values(mocks).forEach((f) => f.mockImplementation(never));
    const Lane = LANE_COMPONENT[id];
    render(<Lane scope={scope} />);
    expect(stateOf(id)).toBe("loading");
    expect(within(card(id)).getByRole("status")).toHaveTextContent("Checking…");
  });
});

// The raw message is no longer rendered verbatim: lib/errors.ts strips the api
// envelope so an operator never reads "500 Internal Server Error: {…}". The
// lane PREFIX stays — it is what says which lane failed.
describe("every lane renders its failure as operator copy, prefixed by the lane", () => {
  it.each(ALL_LANES)("%s", async (id) => {
    Object.values(mocks).forEach((f) => f.mockRejectedValue(new Error("upstream 502")));
    const Lane = LANE_COMPONENT[id];
    render(<Lane scope={scope} />);
    await waitFor(() => expect(stateOf(id)).toBe("error"));
    const alert = within(card(id)).getByRole("alert");
    expect(alert).toHaveTextContent("Upstream 502.");
    expect(alert).toHaveTextContent(LANE_TITLE[id]);
  });
});

describe("not_connected — the source was never wired", () => {
  it("DEM says no probe has ever reported", async () => {
    mocks.pathsHealth.mockResolvedValue({ paths: [], count: 0 });
    render(<DemLane scope={scope} />);
    await waitFor(() => expect(stateOf("dem")).toBe("not_connected"));
    expect(within(card("dem")).getByText("Nothing feeding this")).toBeInTheDocument();
    expect(card("dem")).toHaveTextContent(/probe collector is not measuring/i);
  });

  it("path says no traceroute has been recorded", async () => {
    mocks.probePaths.mockResolvedValue([]);
    render(<PathLane scope={scope} />);
    await waitFor(() => expect(stateOf("path")).toBe("not_connected"));
    expect(card("path")).toHaveTextContent(/path collector is not wired/i);
  });

  it("health says no device metric has ever been scraped", async () => {
    mocks.metricNames.mockResolvedValue({ status: "success", data: ["collector_targets"] });
    render(<HealthLane scope={scope} />);
    await waitFor(() => expect(stateOf("health")).toBe("not_connected"));
    expect(card("health")).toHaveTextContent(/SNMP\/gNMI collectors are not collecting/i);
  });

  it("routing says protocol collection is not enabled", async () => {
    mocks.metricNames.mockResolvedValue({ status: "success", data: ["device_if_oper_status"] });
    render(<RoutingLane scope={scope} />);
    await waitFor(() => expect(stateOf("routing")).toBe("not_connected"));
    expect(card("routing")).toHaveTextContent(/BGP\/OSPF\/IS-IS collection is not enabled/i);
  });

  it("flows says no exporter has ever been seen", async () => {
    mocks.flowsByType.mockResolvedValue({ data: [] });
    mocks.topTalkers.mockResolvedValue({ data: [] });
    render(<FlowsLane scope={scope} />);
    await waitFor(() => expect(stateOf("flows")).toBe("not_connected"));
    expect(card("flows")).toHaveTextContent(/no flow exporter has been seen/i);
  });
});

describe("empty — the source is wired and was quiet", () => {
  it("changes: the event store is always wired, so no rows is EMPTY", async () => {
    mocks.eventsFeed.mockResolvedValue({ items: [] });
    render(<ChangedLane scope={scope} />);
    await waitFor(() => expect(stateOf("changed")).toBe("empty"));
    expect(card("changed")).toHaveTextContent(/no change was recorded/i);
    expect(within(card("changed")).queryByText("Nothing feeding this")).toBeNull();
  });

  it("events: no rows is EMPTY, never not connected", async () => {
    mocks.eventsFeed.mockResolvedValue({ items: [] });
    render(<EventsLane scope={scope} />);
    await waitFor(() => expect(stateOf("events")).toBe("empty"));
    expect(card("events")).toHaveTextContent(/no event was recorded/i);
  });

  it("health: metrics collected but nothing out of state", async () => {
    mocks.metricsQuery.mockResolvedValue({ status: "success", data: { resultType: "vector", result: [] } });
    render(<HealthLane scope={scope} />);
    await waitFor(() => expect(stateOf("health")).toBe("empty"));
    expect(card("health")).toHaveTextContent(/nothing is out of state right now/i);
    expect(within(card("health")).queryByText("Nothing feeding this")).toBeNull();
  });

  it("routing: adjacencies polled and all established", async () => {
    mocks.metricsQuery.mockResolvedValue({ status: "success", data: { resultType: "vector", result: [] } });
    render(<RoutingLane scope={scope} />);
    await waitFor(() => expect(stateOf("routing")).toBe("empty"));
  });

  it("flows: exporters sending but no conversation matched", async () => {
    mocks.topTalkers.mockResolvedValue({ data: [] });
    render(<FlowsLane scope={scope} />);
    await waitFor(() => expect(stateOf("flows")).toBe("empty"));
    expect(card("flows")).toHaveTextContent(/exporters are sending, but no conversation matched/i);
  });

  it("the two facts are worded differently for the same lane", async () => {
    mocks.topTalkers.mockResolvedValue({ data: [] });
    render(<FlowsLane scope={scope} />);
    await waitFor(() => expect(stateOf("flows")).toBe("empty"));
    const quiet = card("flows").textContent ?? "";
    cleanup();
    mocks.flowsByType.mockResolvedValue({ data: [] });
    render(<FlowsLane scope={scope} />);
    await waitFor(() => expect(stateOf("flows")).toBe("not_connected"));
    expect(card("flows").textContent).not.toBe(quiet);
  });
});

describe("ready — the rows an operator came for", () => {
  it("DEM lists the worst-scoring measured paths", async () => {
    mocks.pathsHealth.mockResolvedValue({
      paths: [pathHealth({ path_id: "ok", dst: "10.9.9.9", score: 95, health_state: "healthy" }),
              pathHealth({ path_id: "bad", dst: "10.0.0.1", score: 12, reason: "loss above baseline" })],
      count: 2,
    });
    render(<DemLane scope={scope} />);
    await waitFor(() => expect(stateOf("dem")).toBe("ready"));
    const rows = card("dem").querySelectorAll("li");
    expect(rows[0]).toHaveTextContent("probe-a → 10.0.0.1");
    expect(rows[0]).toHaveTextContent("loss above baseline");
    expect(rows).toHaveLength(2);
  });

  it("changes name a config change in operator words and disclaim causality", async () => {
    mocks.eventsFeed.mockResolvedValue({
      items: [feed({ signal_id: "a", kind: "link_down" }), feed({ signal_id: "b", kind: "device_config_change", entity_id: "core-sw1" })],
    });
    render(<ChangedLane scope={scope} />);
    await waitFor(() => expect(stateOf("changed")).toBe("ready"));
    const rows = card("changed").querySelectorAll("li");
    expect(rows[0]).toHaveTextContent("Configuration change");
    expect(rows[0]).toHaveTextContent("core-sw1");
    expect(card("changed")).toHaveTextContent("Proximity in time, never a causal claim.");
  });

  it("health lists the down interfaces it found", async () => {
    mocks.metricsQuery.mockResolvedValue({
      status: "success",
      data: { resultType: "vector", result: [promSeries({ device: "wan-r1", ifName: "Gi0/1" }), promSeries({ device: "wan-r1", ifName: "Gi0/1" })] },
    });
    render(<HealthLane scope={scope} />);
    await waitFor(() => expect(stateOf("health")).toBe("ready"));
    // two identical series must both render (the row key disambiguates them)
    expect(card("health").querySelectorAll("li")).toHaveLength(2);
    expect(card("health")).toHaveTextContent("operationally down");
  });

  it("routing names the neighbour that is not established", async () => {
    mocks.metricsQuery.mockResolvedValue({
      status: "success", data: { resultType: "vector", result: [promSeries({ device: "wan-r2", peer: "192.0.2.9" })] },
    });
    render(<RoutingLane scope={scope} />);
    await waitFor(() => expect(stateOf("routing")).toBe("ready"));
    expect(card("routing")).toHaveTextContent("192.0.2.9");
    expect(card("routing")).toHaveTextContent("not in the established state");
  });

  it("path says whether the destination was reached and whether the path moved", async () => {
    mocks.probePaths.mockResolvedValue([probePath({ dst: "8.8.8.8", reached: false, changed: true })]);
    render(<PathLane scope={scope} />);
    await waitFor(() => expect(stateOf("path")).toBe("ready"));
    expect(card("path")).toHaveTextContent("8.8.8.8");
    expect(card("path")).toHaveTextContent("did not reach");
    expect(card("path")).toHaveTextContent("path changed");
  });

  it("flows list the top conversations", async () => {
    render(<FlowsLane scope={scope} />);
    await waitFor(() => expect(stateOf("flows")).toBe("ready"));
    expect(card("flows")).toHaveTextContent("10.1.1.1");
    expect(card("flows")).toHaveTextContent("10.2.2.2");
  });

  it("events list the correlated feed rows", async () => {
    mocks.eventsFeed.mockResolvedValue({ items: [feed({ title: "BGP peer down", severity: "critical" })] });
    render(<EventsLane scope={scope} />);
    await waitFor(() => expect(stateOf("events")).toBe("ready"));
    expect(card("events")).toHaveTextContent("BGP peer down");
  });
});

// ── the scope actually reaches the API ───────────────────────────────────────

describe("the investigation scope is passed to the source", () => {
  it("the change lane asks for the change class, the window and the entity", async () => {
    render(<ChangedLane scope={scoped} />);
    await waitFor(() => expect(mocks.eventsFeed).toHaveBeenCalled());
    expect(mocks.eventsFeed).toHaveBeenCalledWith({ from: "2h", class: "changes", limit: "25", entity: "wan-r1" });
  });

  it("the event lane asks the whole feed, not just changes", async () => {
    render(<EventsLane scope={scoped} />);
    await waitFor(() => expect(mocks.eventsFeed).toHaveBeenCalled());
    expect(mocks.eventsFeed).toHaveBeenCalledWith({ from: "2h", limit: "25", entity: "wan-r1" });
  });

  it("an unscoped investigation sends no entity filter and never a sub-hour window", async () => {
    render(<EventsLane scope={{ minutes: 15 }} />);
    await waitFor(() => expect(mocks.eventsFeed).toHaveBeenCalled());
    expect(mocks.eventsFeed).toHaveBeenCalledWith({ from: "1h", limit: "25" });
  });

  it("the flow lane scopes top talkers to the device", async () => {
    render(<FlowsLane scope={scoped} />);
    await waitFor(() => expect(mocks.topTalkers).toHaveBeenCalled());
    expect(mocks.flowsByType).toHaveBeenCalledWith(7200);
    expect(mocks.topTalkers).toHaveBeenCalledWith(7200, 8, "", { device: "wan-r1" });
  });

  it("re-reads its source when the investigation moves to another case", async () => {
    const { rerender } = render(<EventsLane scope={{ device: "wan-r1", minutes: 60, caseId: "corr-1" }} />);
    await waitFor(() => expect(mocks.eventsFeed).toHaveBeenCalledTimes(1));
    rerender(<EventsLane scope={{ device: "wan-r1", minutes: 60, caseId: "corr-2" }} />);
    await waitFor(() => expect(mocks.eventsFeed).toHaveBeenCalledTimes(2));
  });
});

// ── the ladder report ────────────────────────────────────────────────────────

describe("each lane reports its state up to the ladder", () => {
  it("reports loading first, then the resolved state", async () => {
    const report = vi.fn();
    render(<EventsLane scope={scope} report={report} />);
    await waitFor(() => expect(report).toHaveBeenCalledWith("events", "ready"));
    expect(report.mock.calls.map((c) => c[1] as LaneState)).toEqual(["loading", "ready"]);
  });

  it("reports not_connected so the ladder never claims the layer was answered", async () => {
    const report = vi.fn();
    mocks.probePaths.mockResolvedValue([]);
    render(<PathLane scope={scope} report={report} />);
    await waitFor(() => expect(report).toHaveBeenCalledWith("path", "not_connected"));
  });

  it("reports the error state", async () => {
    const report = vi.fn();
    mocks.pathsHealth.mockRejectedValue(new Error("nope"));
    render(<DemLane scope={scope} report={report} />);
    await waitFor(() => expect(report).toHaveBeenCalledWith("dem", "error"));
  });
});

// ── health lane's protocol-diagnostics slot ──────────────────────────────────

describe("the health lane hosts the protocol diagnostics on demand", () => {
  it("keeps the slot closed until asked, then shows it", async () => {
    render(<HealthLane scope={scope} protocolSlot={<div data-testid="diag">DIAG</div>} />);
    await waitFor(() => expect(stateOf("health")).not.toBe("loading"));
    expect(screen.queryByTestId("diag")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Protocol diagnostics" }));
    expect(screen.getByTestId("diag")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Hide protocol diagnostics" }));
    expect(screen.queryByTestId("diag")).toBeNull();
  });

  // A control that expands to nothing is a promise the page cannot keep, so the
  // toggle is not rendered at all when the host supplies no slot.
  it("renders no toggle at all when the host supplied no slot", async () => {
    render(<HealthLane scope={scope} />);
    await waitFor(() => expect(stateOf("health")).not.toBe("loading"));
    expect(screen.queryByRole("button", { name: "Protocol diagnostics" })).toBeNull();
  });
});

// ── remote strings are text, never markup (§15) ──────────────────────────────

describe("remote-authored values are escaped text", () => {
  it("a device name carrying markup renders as characters", async () => {
    const hostile = '<img src=x onerror="alert(1)">';
    mocks.metricsQuery.mockResolvedValue({
      status: "success", data: { resultType: "vector", result: [promSeries({ device: hostile, ifName: "Gi0/1" })] },
    });
    const { container } = render(<HealthLane scope={scope} />);
    await waitFor(() => expect(stateOf("health")).toBe("ready"));
    expect(screen.getByText(hostile)).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
  });

  it("an event title carrying markup renders as characters", async () => {
    const hostile = "<b>owned</b>";
    mocks.eventsFeed.mockResolvedValue({ items: [feed({ title: hostile })] });
    const { container } = render(<EventsLane scope={scope} />);
    await waitFor(() => expect(stateOf("events")).toBe("ready"));
    expect(screen.getByText(hostile)).toBeInTheDocument();
    expect(container.querySelector("b")).toBeNull();
  });
});

// ── the card shell: one plain sentence, raw material behind "Details" ─────────
//
// Owner, 2026-09-06: the page showed everything at once, in engine vocabulary.
// The evidence card now LEADS with a sentence a NOC admin can read and keeps the
// rows and the API path behind one disclosure — open when the lane has something
// to show, closed when it does not, and always openable.

describe("the evidence card leads with one plain sentence", () => {
  it("counts what a lane found, in words", async () => {
    mocks.metricsQuery.mockResolvedValue({
      status: "success", data: { resultType: "vector", result: [promSeries({ device: "wan-r1", ifName: "Gi0/1" })] },
    });
    render(<HealthLane scope={scope} />);
    await waitFor(() => expect(stateOf("health")).toBe("ready"));
    expect(card("health")).toHaveTextContent("1 interface is down right now.");
  });

  it("pluralises that count", async () => {
    mocks.metricsQuery.mockResolvedValue({
      status: "success",
      data: { resultType: "vector", result: [promSeries({ device: "a", ifName: "1" }), promSeries({ device: "b", ifName: "2" })] },
    });
    render(<HealthLane scope={scope} />);
    await waitFor(() => expect(stateOf("health")).toBe("ready"));
    expect(card("health")).toHaveTextContent("2 interfaces are down right now.");
  });

  it("opens the details when the lane HAS something, and closes them on demand", async () => {
    render(<EventsLane scope={scope} />);
    await waitFor(() => expect(stateOf("events")).toBe("ready"));
    expect(within(card("events")).getByText(LANE_SOURCE.events)).toBeInTheDocument();
    fireEvent.click(within(card("events")).getByRole("button", { name: "Hide details" }));
    expect(within(card("events")).queryByText(LANE_SOURCE.events)).toBeNull();
    fireEvent.click(within(card("events")).getByRole("button", { name: "Details" }));
    expect(within(card("events")).getByText(LANE_SOURCE.events)).toBeInTheDocument();
  });

  it("keeps the raw material closed for a QUIET lane — and still lets the operator open it", async () => {
    mocks.eventsFeed.mockResolvedValue({ items: [] });
    render(<EventsLane scope={scope} />);
    await waitFor(() => expect(stateOf("events")).toBe("empty"));
    expect(within(card("events")).queryByText(LANE_SOURCE.events)).toBeNull();
    // the honest sentence is NOT hidden — only the raw material is
    expect(card("events")).toHaveTextContent(/no event was recorded/i);
    fireEvent.click(within(card("events")).getByRole("button", { name: "Details" }));
    expect(within(card("events")).getByText(LANE_SOURCE.events)).toBeInTheDocument();
  });

  it("opens the details for a FAILED lane, so the failure is never a click away", async () => {
    mocks.pathsHealth.mockRejectedValue(new Error("upstream 502"));
    render(<DemLane scope={scope} />);
    await waitFor(() => expect(stateOf("dem")).toBe("error"));
    expect(within(card("dem")).getByRole("alert")).toBeInTheDocument();
    expect(within(card("dem")).getByText(LANE_SOURCE.dem)).toBeInTheDocument();
  });

  it("titles every lane in the operator's words, not the engine's", () => {
    for (const t of Object.values(LANE_TITLE)) {
      expect(t).not.toMatch(/telemetry|protocol health|correlated|digital experience|DEM/i);
    }
    expect(LANE_TITLE.health).toBe("Devices & links");
    expect(LANE_TITLE.dem).toBe("User experience");
  });
});
