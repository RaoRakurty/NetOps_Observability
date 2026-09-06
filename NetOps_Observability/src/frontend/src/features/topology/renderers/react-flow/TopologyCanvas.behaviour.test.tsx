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
