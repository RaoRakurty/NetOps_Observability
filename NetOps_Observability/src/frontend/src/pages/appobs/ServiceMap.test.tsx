// ServiceMap.test.tsx — mount smoke + honest-state contract for the observed
// Service Map (tracker #110). Full React Flow measurement is unreliable under
// happy-dom (same caveat as CloudTopologyView.test.tsx), so the canvas cases
// assert the pipeline mounts (.react-flow) and — the part this view exists
// for — that the mandatory honesty caption renders meta verbatim. The empty
// state must name the telemetry that lights the map up, and a failed read must
// say so — never a blank or a fabricated graph.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, waitFor } from "@testing-library/react";
import type { ServiceMapWire } from "./serviceMap";
import type { CloudScopeControl } from "./useCloudScope";

const h = vi.hoisted(() => ({ loadServiceMap: vi.fn() }));
vi.mock("./api", () => ({ loadServiceMap: h.loadServiceMap }));

import ServiceMap from "./ServiceMap";

const ctl = (over: Partial<CloudScopeControl> = {}): CloudScopeControl => ({
  scope: { providers: [], accounts: [], regions: [], envs: [], rangeMinutes: 1440 },
  active: false, add: () => {}, remove: () => {}, clearFilters: () => {},
  setRangeMinutes: () => {}, ...over,
});

const wire = (over: Partial<ServiceMapWire> = {}): ServiceMapWire => ({
  nodes: [
    { id: "svc:web", label: "web", kind: "service", resolved: true, bytes: 1_000_000, providers: ["aws"] },
    { id: "svc:db", label: "db", kind: "service", resolved: true, bytes: 500_000, providers: ["aws"] },
    { id: "ip:10.0.0.9", label: "10.0.0.9", kind: "endpoint", resolved: false, bytes: 50, providers: ["aws"] },
  ],
  edges: [
    { source_service: "svc:web", dest_service: "svc:db", relationship: "talks_to",
      bytes: 500_000, pair_count: 3, blocked: false, blocked_count: 0, providers: ["aws"] },
    { source_service: "svc:web", dest_service: "ip:10.0.0.9", relationship: "talks_to",
      bytes: 0, pair_count: 0, blocked: true, blocked_count: 7, providers: ["aws"] },
  ],
  meta: {
    window_hours: 24, pair_signals: 132, resolved_endpoints: 5, unresolved_endpoints: 3,
    unattributed_shown: 3, unattributed_dropped: 0, generated_at: "2026-07-18T10:00:00Z",
  },
  ...over,
});

// braces matter: returning the mock from beforeEach would hand vitest a callable
// "teardown" that invokes the mock post-test → an unhandled rejected promise.
beforeEach(() => { h.loadServiceMap.mockReset(); });
afterEach(cleanup);

describe("ServiceMap (observed dependencies)", () => {
  it("renders the canvas with the mandatory honesty caption from meta", async () => {
    h.loadServiceMap.mockResolvedValue(wire());
    const { container } = render(<ServiceMap ctl={ctl()} />);
    // caption: window · pair signals · resolved/unresolved · generated_at
    await screen.findByText("132 pair signals aggregated");
    expect(screen.getByText("last 24 hours")).toBeTruthy();
    expect(screen.getByText("5 resolved · 3 unresolved endpoints")).toBeTruthy();
    expect(screen.getByText(/^generated /)).toBeTruthy();
    expect(screen.getByText("observed traffic")).toBeTruthy();
    // no truncation line when nothing was dropped
    expect(screen.queryByText(/unattributed shown/)).toBeNull();
    // the React Flow pipeline mounts after the deterministic ELK layout resolves
    await waitFor(() => expect(container.querySelector(".react-flow")).toBeTruthy());
    // legend explains every mark, including the blocked treatment
    expect(screen.getByText(/talks_to · width = observed bytes/)).toBeTruthy();
    expect(screen.getByText(/blocked · observed REJECT count/)).toBeTruthy();
  });

  it("states the unattributed truncation when the backend dropped endpoints", async () => {
    h.loadServiceMap.mockResolvedValue(wire({
      meta: {
        window_hours: 24, pair_signals: 9, resolved_endpoints: 2, unresolved_endpoints: 25,
        unattributed_shown: 10, unattributed_dropped: 15, generated_at: "2026-07-18T10:00:00Z",
      },
    }));
    render(<ServiceMap ctl={ctl()} />);
    await screen.findByText("top 10 of 25 unattributed shown · 15 dropped");
  });

  it("says the map is tenant-wide when scope filters are active (endpoint takes none)", async () => {
    h.loadServiceMap.mockResolvedValue(wire());
    render(<ServiceMap ctl={ctl({
      active: true,
      scope: { providers: ["aws"], accounts: [], regions: [], envs: [], rangeMinutes: 1440 },
    })} />);
    await screen.findByText("tenant-wide · scope filters not applied");
  });

  it("empty window → honest empty state naming the flow-pair telemetry", async () => {
    h.loadServiceMap.mockResolvedValue(wire({
      nodes: [], edges: [],
      meta: {
        window_hours: 24, pair_signals: 0, resolved_endpoints: 0, unresolved_endpoints: 0,
        unattributed_shown: 0, unattributed_dropped: 0, generated_at: "2026-07-18T10:00:00Z",
      },
    }));
    const { container } = render(<ServiceMap ctl={ctl()} />);
    await screen.findByText("No observed service traffic in the last 24 hours");
    expect(screen.getByText(/observed cloud flow pairs/)).toBeTruthy();
    expect(screen.getByText(/nothing is inferred/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Open Data sources" })).toBeTruthy();
    expect(container.querySelector(".react-flow")).toBeNull(); // no fake canvas
  });

  it("failed read → honest error state, no canvas", async () => {
    h.loadServiceMap.mockRejectedValue(new Error("503"));
    const { container } = render(<ServiceMap ctl={ctl()} />);
    await screen.findByText("Unable to load the service map");
    expect(container.querySelector(".react-flow")).toBeNull();
  });

  it("requests the server-honored window for the active range (7d → 168h)", async () => {
    h.loadServiceMap.mockResolvedValue(wire());
    render(<ServiceMap ctl={ctl({
      scope: { providers: [], accounts: [], regions: [], envs: [], rangeMinutes: 7 * 24 * 60 },
    })} />);
    await waitFor(() => expect(h.loadServiceMap).toHaveBeenCalledWith(168));
  });
});
