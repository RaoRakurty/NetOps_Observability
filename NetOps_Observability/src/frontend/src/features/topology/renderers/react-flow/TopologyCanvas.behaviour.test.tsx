// TopologyCanvas.behaviour.test.tsx — #133c. The canvas holds the most behaviour
// in the feature (fetch state machine, Investigate auto-pin, 60s background
// refresh, the guided Path-Trace states) and none of it was covered; the two
// existing files pin the domain selector and the scale/load-flash guards only.
//
// Each case here is a behaviour that has already been wrong at least once:
//  - a failed read rendering as "you have no devices" (audit S2),
//  - Investigate silently mirroring Explore because nothing was pinned,
//  - a wallboard hammering the API while the tab is hidden,
//  - a failed trace falling back to the full topology (an Explore look-alike),
//  - and #133a: the shareable route, which is also how these drive modes.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor, act } from "@testing-library/react";
import TopologyCanvas from "./TopologyCanvas";
import type { TopologyView } from "../../api/topologyTypes";

const correlations = vi.fn();

vi.mock("../../../../services/api", async () => {
  const actual = await vi.importActual<Record<string, unknown>>("../../../../services/api");
  return {
    ...actual,
    api: { ...(actual.api as Record<string, unknown>), correlations: (...a: unknown[]) => correlations(...a) },
  };
});

vi.mock("../../layout/elkLayout", async () => {
  const actual = await vi.importActual<Record<string, unknown>>("../../layout/elkLayout");
  return { ...actual, layoutView: vi.fn().mockResolvedValue({}) };
});

vi.mock("../../api/topologyApi", async () => {
  const actual = await vi.importActual<Record<string, unknown>>("../../api/topologyApi");
  return {
    ...actual,
    fetchTopologyView: vi.fn(),
    fetchTopologyGraph: vi.fn().mockResolvedValue({ view: emptyView("g"), status: "empty" }),
    fetchCloudTopology: vi.fn().mockResolvedValue({ view: emptyView("c"), status: "empty" }),
    fetchRcaPathView: vi.fn().mockResolvedValue(null),
  };
});

function emptyView(id: string): TopologyView {
  return {
    view_id: id,
    mode: "explore",
    layout_type: "layered",
    generated_at: "",
    nodes: [],
    edges: [],
    groups: [],
    overlays: ["health"],
  } as unknown as TopologyView;
}

function twoDeviceView(): TopologyView {
  const ev = [{ source: "lldp", confidence: 0.9 }];
  return {
    view_id: "two-dev",
    mode: "explore",
    layout_type: "layered",
    generated_at: "2026-08-01T00:00:00Z",
    nodes: [
      { id: "core-1", label: "core-1", kind: "router", health: "ok", confidence: 1, evidence: ev },
      { id: "edge-9", label: "edge-9", kind: "router", health: "ok", confidence: 1, evidence: ev },
    ],
    edges: [],
    groups: [],
    overlays: ["health"],
  } as unknown as TopologyView;
}

async function topologyApi() {
  return import("../../api/topologyApi");
}

function atRoute(query: string) {
  window.history.replaceState(null, "", `/#/observability/topology${query}`);
}

beforeEach(() => {
  vi.clearAllMocks();
  correlations.mockResolvedValue({ data: [] });
  atRoute("");
});

afterEach(() => {
  window.history.replaceState(null, "", "/");
});

// ── fetch state machine ───────────────────────────────────────────────────────
describe("TopologyCanvas — fetch state machine", () => {
  it("a FAILED read says the topology could not be read — never 'you have no devices'", async () => {
    const api = await topologyApi();
    (api.fetchTopologyView as ReturnType<typeof vi.fn>).mockResolvedValue({ view: emptyView("v"), status: "error" });

    render(<TopologyCanvas />);

    expect(await screen.findByText(/could not be read/i)).toBeInTheDocument();
    expect(screen.getByRole("alert")).toBeInTheDocument();
    expect(screen.queryByText(/Nothing to show for this view yet/i)).toBeNull();
  });

  it("an EMPTY read says nothing resolved — and is not an alert", async () => {
    const api = await topologyApi();
    (api.fetchTopologyView as ReturnType<typeof vi.fn>).mockResolvedValue({ view: emptyView("v"), status: "empty" });

    render(<TopologyCanvas />);

    expect(await screen.findByText(/Nothing to show for this view yet/i)).toBeInTheDocument();
    expect(screen.queryByRole("alert")).toBeNull();
  });
});

// ── 60s background refresh ────────────────────────────────────────────────────
describe("TopologyCanvas — 60s background refresh", () => {
  it("refetches on the cadence, and NOT while the tab is hidden", async () => {
    const api = await topologyApi();
    (api.fetchTopologyView as ReturnType<typeof vi.fn>).mockResolvedValue({ view: twoDeviceView(), status: "live" });
    const setInterval = vi.spyOn(window, "setInterval");

    render(<TopologyCanvas />);
    await waitFor(() => expect(api.fetchTopologyView).toHaveBeenCalledTimes(1));

    const tick = setInterval.mock.calls.find((c) => c[1] === 60_000)?.[0] as (() => void) | undefined;
    expect(tick, "the canvas must register a 60s refresh interval").toBeTypeOf("function");

    // Hidden wallboard: the tick must not reach the API.
    Object.defineProperty(document, "hidden", { value: true, configurable: true });
    act(() => tick!());
    await Promise.resolve();
    expect(api.fetchTopologyView).toHaveBeenCalledTimes(1);

    // Visible again: the same tick refetches.
    Object.defineProperty(document, "hidden", { value: false, configurable: true });
    act(() => tick!());
    await waitFor(() => expect(api.fetchTopologyView).toHaveBeenCalledTimes(2));

    // A background refresh must NOT drop the canvas back to the loading placeholder.
    expect(screen.queryByText(/Loading topology/i)).toBeNull();
    setInterval.mockRestore();
  });
});

// ── Investigate auto-pin ──────────────────────────────────────────────────────
describe("TopologyCanvas — Investigate auto-pin", () => {
  const incidents = [
    { correlation_id: "c-undetermined", verdict_tier: "undetermined", top_confidence: 0.9, created_at: "2026-08-02T00:00:00Z", top_hypothesis: "maybe" },
    { correlation_id: "c-confirmed", verdict_tier: "confirmed", top_confidence: 0.4, created_at: "2026-08-01T00:00:00Z", top_hypothesis: "link down" },
    { correlation_id: "c-suspected", verdict_tier: "suspected", top_confidence: 0.99, created_at: "2026-08-03T00:00:00Z", top_hypothesis: "flapping" },
  ];

  it("lands on the most ACTIONABLE incident (verdict tier first), not the newest", async () => {
    const api = await topologyApi();
    (api.fetchTopologyView as ReturnType<typeof vi.fn>).mockResolvedValue({ view: twoDeviceView(), status: "live" });
    correlations.mockResolvedValue({ data: incidents });
    atRoute("?mode=investigate");

    render(<TopologyCanvas />);

    // Confirmed outranks a newer, more confident suspected one.
    await waitFor(() => expect(api.fetchRcaPathView).toHaveBeenCalledWith("c-confirmed"));
    const picker = (await screen.findByLabelText("Pin an incident's RCA path")) as HTMLSelectElement;
    expect(picker.value).toBe("c-confirmed");
  });

  it("an operator switching back to the live projection is NOT re-pinned", async () => {
    const api = await topologyApi();
    (api.fetchTopologyView as ReturnType<typeof vi.fn>).mockResolvedValue({ view: twoDeviceView(), status: "live" });
    correlations.mockResolvedValue({ data: incidents });
    atRoute("?mode=investigate");

    render(<TopologyCanvas />);
    const picker = (await screen.findByLabelText("Pin an incident's RCA path")) as HTMLSelectElement;
    await waitFor(() => expect(picker.value).toBe("c-confirmed"));

    fireEvent.change(picker, { target: { value: "" } });
    await waitFor(() => expect(picker.value).toBe(""));
    // The auto-pin fires ONCE per entry into the mode; it must not re-assert.
    await new Promise((r) => setTimeout(r, 20));
    expect(picker.value).toBe("");
  });

  it("no incidents at all leaves Investigate on the live projection", async () => {
    const api = await topologyApi();
    (api.fetchTopologyView as ReturnType<typeof vi.fn>).mockResolvedValue({ view: twoDeviceView(), status: "live" });
    correlations.mockResolvedValue({ data: [] });
    atRoute("?mode=investigate");

    render(<TopologyCanvas />);
    const picker = (await screen.findByLabelText("Pin an incident's RCA path")) as HTMLSelectElement;
    expect(picker.value).toBe("");
    expect(api.fetchRcaPathView).not.toHaveBeenCalled();
  });
});

// ── guided Path Trace states ──────────────────────────────────────────────────
describe("TopologyCanvas — Path Trace states", () => {
  it("prompts for endpoints, then resolves, then says NO PATH — never the full topology", async () => {
    const api = await topologyApi();
    const fetchView = api.fetchTopologyView as ReturnType<typeof vi.fn>;
    // The first (endpoint-less) read lands; every read for a chosen PAIR is held
    // open so the in-flight state is observable.
    let resolveTrace: ((v: { view: TopologyView; status: string }) => void) | null = null;
    fetchView.mockImplementation((_mode: string, ep?: { src: string; dst: string }) => {
      if (ep?.src && ep?.dst) return new Promise((res) => { resolveTrace = res as typeof resolveTrace; });
      return Promise.resolve({ view: twoDeviceView(), status: "live" });
    });
    atRoute("?mode=path_trace");

    render(<TopologyCanvas />);

    // 1) No endpoints yet → the guided prompt.
    expect(await screen.findByText(/Trace a network path/i)).toBeInTheDocument();

    // 2) Both endpoints chosen, fetch still in flight → the resolving state names
    //    the pair being traced (the generic loader used to swallow it).
    fireEvent.change(screen.getByLabelText("Path source device"), { target: { value: "core-1" } });
    // Picking one endpoint re-reads the view, so the guided card remounts; wait for
    // it before aiming the second half of the trace.
    await waitFor(() => expect(screen.getByLabelText("Path destination device")).toHaveValue(""));
    fireEvent.change(screen.getByLabelText("Path destination device"), { target: { value: "edge-9" } });
    expect(await screen.findByText(/Resolving path…/i)).toBeInTheDocument();
    await waitFor(() => expect(resolveTrace).toBeTypeOf("function"));

    // 3) It resolves with NO path → the honest no-path state, not Explore.
    await act(async () => { resolveTrace!({ view: twoDeviceView(), status: "live" }); });
    expect(await screen.findByText(/No path found/i)).toBeInTheDocument();
    expect(screen.queryByText(/Resolving path…/i)).toBeNull();
  });
});

// ── #133a: the route IS the canvas state ──────────────────────────────────────
describe("TopologyCanvas — shareable route", () => {
  it("opens on the overlay / grouping / shape the link names", async () => {
    const api = await topologyApi();
    (api.fetchTopologyView as ReturnType<typeof vi.fn>).mockResolvedValue({ view: twoDeviceView(), status: "live" });
    atRoute("?overlay=utilization&group=vendor&arrange=ring&domain=dc");

    render(<TopologyCanvas />);

    expect(((await screen.findByLabelText("Group the canvas by")) as HTMLSelectElement).value).toBe("vendor");
    expect((screen.getByLabelText("Arrange by topology shape") as HTMLSelectElement).value).toBe("ring");
    expect((screen.getByLabelText("Network domain") as HTMLSelectElement).value).toBe("dc");
  });

  it("writes a changed control back onto the route so the view can be shared", async () => {
    const api = await topologyApi();
    (api.fetchTopologyView as ReturnType<typeof vi.fn>).mockResolvedValue({ view: twoDeviceView(), status: "live" });

    render(<TopologyCanvas />);
    const group = (await screen.findByLabelText("Group the canvas by")) as HTMLSelectElement;
    fireEvent.change(group, { target: { value: "role" } });

    await waitFor(() => expect(location.hash).toContain("group=role"));
    // A control still at its default stays OUT of the link.
    expect(location.hash).not.toContain("overlay=health");
  });

  it("ignores a mode the closed set does not contain — a bad link opens the default canvas", async () => {
    const api = await topologyApi();
    (api.fetchTopologyView as ReturnType<typeof vi.fn>).mockResolvedValue({ view: twoDeviceView(), status: "live" });
    atRoute("?mode=drop-tables&group=../../etc");

    render(<TopologyCanvas />);

    // Explore + the default site grouping, and nothing from the hostile link applied.
    expect(((await screen.findByLabelText("Group the canvas by")) as HTMLSelectElement).value).toBe("site");
    expect(screen.queryByLabelText("Pin an incident's RCA path")).toBeNull();
  });
});

// ── #131: the cloud projection is ON this canvas, as a filter ─────────────────
function cloudNetworkView(): TopologyView {
  const ev = [{ source: "cloud_api", confidence: 0.9 }];
  const tags = { provider: "aws", region: "us-west-2", vpc: "vpc-1" };
  return {
    view_id: "cloud-network",
    mode: "explore",
    layout_type: "cloud_grouped",
    generated_at: "2026-08-02T00:00:00Z",
    nodes: [
      { id: "subnet-app", label: "Subnet · app-a", kind: "cloud", health: "unknown", confidence: 0.9, evidence: ev, tags, group_id: "vpc-1" },
      { id: "igw-1", label: "IGW · prod-igw", kind: "cloud", health: "unknown", confidence: 0.9, evidence: ev, tags: { provider: "aws", region: "us-west-2" } },
    ],
    edges: [],
    groups: [
      { id: "region:aws:us-west-2", label: "aws · us-west-2", group_type: "region", children: [], health: "unknown", collapsed: false },
      { id: "vpc-1", label: "VPC · prod", group_type: "vpc", parent_id: "region:aws:us-west-2", children: ["subnet-app"], health: "unknown", collapsed: false },
    ],
    overlays: ["health"],
  } as unknown as TopologyView;
}

describe("TopologyCanvas — cloud on the one canvas", () => {
  it("merges the discovered cloud network into the default canvas alongside the fabric", async () => {
    const api = await topologyApi();
    (api.fetchTopologyView as ReturnType<typeof vi.fn>).mockResolvedValue({ view: twoDeviceView(), status: "live" });
    (api.fetchCloudTopology as ReturnType<typeof vi.fn>).mockResolvedValue({ view: cloudNetworkView(), live: true, status: "live" });

    render(<TopologyCanvas />);

    // On-prem and cloud are on the SAME canvas — that is what makes an
    // on-prem↔cloud investigation possible without changing page.
    expect(await screen.findByText("core-1")).toBeInTheDocument();
    await waitFor(() => expect(screen.getAllByText("Subnet · app-a").length).toBeGreaterThan(0));
  });

  it("the Cloud domain FILTERS that canvas — on-prem drops out, the region container stays", async () => {
    const api = await topologyApi();
    (api.fetchTopologyView as ReturnType<typeof vi.fn>).mockResolvedValue({ view: twoDeviceView(), status: "live" });
    (api.fetchCloudTopology as ReturnType<typeof vi.fn>).mockResolvedValue({ view: cloudNetworkView(), live: true, status: "live" });

    render(<TopologyCanvas />);
    await screen.findByText("Subnet · app-a");

    fireEvent.change(screen.getByLabelText("Network domain"), { target: { value: "cloud" } });

    await waitFor(() => expect(screen.queryByText("core-1")).toBeNull());
    // The cloud half is still drawn (inventory row + the card on the stage).
    expect(screen.getAllByText("Subnet · app-a").length).toBeGreaterThan(0);
  });

  it("OFFERS cloud endpoints to the path tracer — the projection crosses the seam now (#130)", async () => {
    const api = await topologyApi();
    (api.fetchTopologyView as ReturnType<typeof vi.fn>).mockResolvedValue({ view: twoDeviceView(), status: "live" });
    (api.fetchCloudTopology as ReturnType<typeof vi.fn>).mockResolvedValue({ view: cloudNetworkView(), live: true, status: "live" });
    atRoute("?mode=path_trace");

    render(<TopologyCanvas />);
    const src = (await screen.findByLabelText("Path source device")) as HTMLSelectElement;
    const options = [...src.options].map((o) => o.value);

    // Cloud ids ARE vertices in the graph the trace walks, so hiding them would
    // now be withholding a control that works. Where no seam has been discovered
    // the trace still refuses honestly (`path_state`) rather than inventing a hop
    // — an honest refusal is a better answer than a missing option.
    expect(options).toContain("core-1");
    expect(options).toContain("subnet-app");
    expect(options).toContain("igw-1");
  });

  it("says NO SEAM LINK when the two ends have no discovered adjacency (#130b)", async () => {
    const api = await topologyApi();
    (api.fetchTopologyView as ReturnType<typeof vi.fn>).mockResolvedValue({
      view: { ...twoDeviceView(), mode: "path_trace", path: [], path_state: "no_seam_edge" },
      status: "live",
    });
    (api.fetchCloudTopology as ReturnType<typeof vi.fn>).mockResolvedValue({ view: cloudNetworkView(), live: true, status: "live" });
    atRoute("?mode=path_trace");

    render(<TopologyCanvas />);
    // Pick an on-prem source and a CLOUD destination — the pair the picker now
    // allows and the backend answers for.
    fireEvent.change(await screen.findByLabelText("Path source device"), { target: { value: "core-1" } });
    // The picker re-renders through a load between the two choices.
    fireEvent.change(await screen.findByLabelText("Path destination device"), { target: { value: "subnet-app" } });

    // A DISTINCT state, not the generic "no route": the operator's next action is
    // to fix discovery, not to re-aim the trace.
    expect(await screen.findByText("No seam link discovered")).toBeInTheDocument();
    expect(screen.queryByText("No path found")).toBeNull();
    expect(screen.getByRole("button", { name: "Ask Iris about No seam link discovered" })).toBeInTheDocument();
  });

  it("an empty cloud read says nothing is discovered — never a blank Cloud canvas", async () => {
    const api = await topologyApi();
    (api.fetchTopologyView as ReturnType<typeof vi.fn>).mockResolvedValue({ view: twoDeviceView(), status: "live" });
    (api.fetchCloudTopology as ReturnType<typeof vi.fn>).mockResolvedValue({ view: emptyView("c"), live: false, status: "empty" });
    atRoute("?domain=cloud");

    render(<TopologyCanvas />);

    expect(await screen.findByText(/No cloud network discovered yet/i)).toBeInTheDocument();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("a FAILED cloud read is an alert — distinct from nothing discovered", async () => {
    const api = await topologyApi();
    (api.fetchTopologyView as ReturnType<typeof vi.fn>).mockResolvedValue({ view: twoDeviceView(), status: "live" });
    (api.fetchCloudTopology as ReturnType<typeof vi.fn>).mockResolvedValue({ view: emptyView("c"), live: false, status: "error" });
    atRoute("?domain=cloud");

    render(<TopologyCanvas />);

    expect(await screen.findByText(/Unable to load the cloud network/i)).toBeInTheDocument();
    expect(screen.getByRole("alert")).toBeInTheDocument();
  });
});
