// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Overview — the merged default page (2026-11-22). Pins what the merge promised:
// one read of each shared source per tick, honest quiet/degraded wording, the
// platform's own panels for platform admins only, a real Health by site, and
// collapsed groups that mount (and so poll) nothing.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, waitFor, fireEvent } from "@testing-library/react";
import { corrObject } from "../../test/factories";

const api = {
  correlations: vi.fn(), healthScore: vi.fn(), correlationsStats: vi.fn(), geomap: vi.fn(), me: vi.fn(),
  eventsFeed: vi.fn(), metricsForecast: vi.fn(), stackHealth: vi.fn(), correlationTimeline: vi.fn(),
  listSaved: vi.fn(), getOverviewDefault: vi.fn(),
};
vi.mock("../../services/api", () => ({
  api: new Proxy({}, { get: (_t, k: string) => (api as Record<string, unknown>)[k] }),
  getActiveScope: () => "",
  sessionTenantKey: () => "t1",
}));
vi.mock("../../context/shell", () => ({ useShell: () => ({ navigate: vi.fn() }) }));
vi.mock("../../components/AskIris", () => ({ default: () => null }));
vi.mock("../../components/PathHealthList", () => ({ default: () => <div>hot paths</div> }));
vi.mock("../../components/rca/RcaPathCausality", () => ({ default: () => <div>path view</div> }));

// Registry panels: stubs that count their mounts, so a collapsed group is checked.
const mounted: string[] = [];
vi.mock("../panels", async (orig) => {
  const real = await orig<typeof import("../panels")>();
  const stub = (type: string, title: string) => ({
    type, title, defaultSpan: 6, category: "Traffic" as const,
    render: () => { mounted.push(type); return <div data-testid={`stub-${type}`}>{title}</div>; },
  });
  return {
    ...real,
    PANELS: Object.fromEntries(["active-alerts", "bgp-peers", "ospf-nbrs", "site-availability", "traffic", "tunnels-health", "if-util-topn", "sat-cpu", "sat-mem"]
      .map((t) => [t, stub(t, t)])),
  };
});

import OverviewPage from "./OverviewPage";
import { __resetBoardHealth } from "../panels";

const healthy = { scope: "global", score: 95, band: "healthy", confidence: "high", coverage_status: "OK", signal_classes_live: ["availability", "device_health"], contributions: [], stale_inputs: [] };
const stats = { open: 0, open_confirmed: 0, open_suspected: 0, signatures_matched: 0 };

beforeEach(() => {
  mounted.length = 0;
  __resetBoardHealth();
  api.correlations.mockResolvedValue({ data: [] });
  api.healthScore.mockResolvedValue(healthy);
  api.correlationsStats.mockResolvedValue(stats);
  api.geomap.mockResolvedValue({ geo_enabled: true, sites: [] });
  api.me.mockResolvedValue({ platform_admin: false });
  api.eventsFeed.mockResolvedValue({ items: [] });
  api.metricsForecast.mockResolvedValue({ interfaces: [], min_days: 14 });
  api.stackHealth.mockResolvedValue({ overall: "healthy", up: 10, degraded: 0, down: 0 });
  api.correlationTimeline.mockResolvedValue({ signals: [] });
  api.listSaved.mockResolvedValue([]);
  api.getOverviewDefault.mockResolvedValue({ tenant_id: "t1", dashboard_id: "", dashboard: null, unavailable: false });
});
afterEach(() => { cleanup(); vi.clearAllMocks(); location.hash = ""; });

// The merged layout's own tests open it at its address; the default address is
// the Operations Overview again (owner, 2026-11-23).
const openStandard = () => { location.hash = "#/overview/operations/standard"; };

describe("Overview — one read per source", () => {
  beforeEach(openStandard);
  it("reads correlations, health and stats ONCE for every panel that shares them", async () => {
    render(<OverviewPage />);
    await screen.findByText("Nothing needs attention right now.");
    expect(api.correlations).toHaveBeenCalledTimes(1);
    expect(api.healthScore).toHaveBeenCalledTimes(1);
    expect(api.correlationsStats).toHaveBeenCalledTimes(1);
  });
});

describe("Overview — honest attention line", () => {
  beforeEach(openStandard);
  it("says nothing needs attention only when there is no case AND health is healthy", async () => {
    render(<OverviewPage />);
    expect(await screen.findByText("Nothing needs attention right now.")).toBeTruthy();
  });

  it("never says quiet while health is degraded with no confirmed cause", async () => {
    api.healthScore.mockResolvedValue({ ...healthy, band: "degraded", score: 41, contributions: [{ signal_class: "device_health", entity: "edge-1", badness: 1, points: 12, reason: "edge-1 CPU at 97%" }] });
    render(<OverviewPage />);
    expect(await screen.findByText(/Health is degraded but no cause is confirmed yet/)).toBeTruthy();
    expect(screen.queryByText("Nothing needs attention right now.")).toBeNull();
  });

  it("leads with the top open problem when one exists", async () => {
    api.correlations.mockResolvedValue({ data: [corrObject({ correlation_id: "c1", verdict_tier: "confirmed", top_hypothesis: "sig.ent.access.local-link-fault", affected: '{"devices":["edge-1"]}' })] });
    render(<OverviewPage />);
    expect(await screen.findByText("CONFIRMED")).toBeTruthy();
    expect(screen.getByText(/on edge-1/)).toBeTruthy();
  });

  it("says a source is not answering instead of reading quiet when correlation fails", async () => {
    api.correlations.mockRejectedValue(new Error("502"));
    render(<OverviewPage />);
    expect(await screen.findByText("Correlation or health is not answering right now.")).toBeTruthy();
    expect(await screen.findByText("Disconnected")).toBeTruthy();
  });
});

describe("Overview — platform panels", () => {
  beforeEach(openStandard);
  it("never shows the platform's own health to a tenant user (and never reads it)", async () => {
    render(<OverviewPage />);
    await screen.findByText("Nothing needs attention right now.");
    await waitFor(() => expect(api.me).toHaveBeenCalled());
    expect(screen.queryByText("Platform health (internal)")).toBeNull();
    expect(api.stackHealth).not.toHaveBeenCalled();
  });

  it("shows them to the platform admin", async () => {
    api.me.mockResolvedValue({ platform_admin: true });
    render(<OverviewPage />);
    expect(await screen.findByText("Platform health (internal)")).toBeTruthy();
    expect(screen.getByText("Internal monitoring checks")).toBeTruthy();
  });
});

describe("Overview — health by site", () => {
  beforeEach(openStandard);
  it("names the next step when no site is declared", async () => {
    render(<OverviewPage />);
    expect(await screen.findByText("No sites declared yet.")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Add sites" }).getAttribute("href")).toBe("#/infrastructure/sites/sites");
  });

  it("lists sites worst first", async () => {
    api.geomap.mockResolvedValue({ geo_enabled: true, sites: [
      { name: "HQ", slug: "hq", lat: 0, lng: 0, has_coords: true, devices: 4, up: 4, down: 0 },
      { name: "Branch 7", slug: "b7", lat: 0, lng: 0, has_coords: true, devices: 2, up: 0, down: 2 },
    ] });
    render(<OverviewPage />);
    const table = await screen.findByTestId("overview-site-health");
    const names = [...table.querySelectorAll("tbody tr td:first-child")].map((td) => td.textContent);
    expect(names).toEqual(["Branch 7", "HQ"]);
    expect(table.textContent).toContain("All down");
  });

  it("says the site list is unavailable rather than empty when it fails", async () => {
    api.geomap.mockRejectedValue(new Error("boom"));
    render(<OverviewPage />);
    expect(await screen.findByText("The site list is not answering right now.")).toBeTruthy();
  });
});

describe("Overview — collapsed groups poll nothing", () => {
  beforeEach(openStandard);
  it("does not mount the closed 'Traffic and resources' panels until opened", async () => {
    render(<OverviewPage />);
    await screen.findByText("Nothing needs attention right now.");
    expect(mounted).toContain("active-alerts");
    expect(mounted).not.toContain("traffic");
    expect(screen.queryByTestId("stub-traffic")).toBeNull();

    const head = screen.getByText("Traffic and resources").closest("details") as HTMLDetailsElement;
    head.open = true;
    fireEvent(head, new Event("toggle"));
    expect(await screen.findByTestId("stub-traffic")).toBeTruthy();
  });
});

describe("Overview — the team default", () => {
  const teamBoard = {
    id: "0f1e2d3c4b5a69788796a5b4c3d2e1f0", type: "dashboard", name: "NOC wall", owner: "adm", tenant_id: "t1",
    body: { v: 1, cells: [{ type: "traffic", span: 12 }] }, created_at: "2026-11-22T10:00:00Z", updated_at: "2026-11-22T10:00:00Z",
  };
  afterEach(() => { location.hash = ""; });

  it("opens the team's default dashboard instead of the built-in page", async () => {
    api.getOverviewDefault.mockResolvedValue({ tenant_id: "t1", dashboard_id: teamBoard.id, dashboard: teamBoard, unavailable: false });
    render(<OverviewPage />);
    expect(await screen.findByText("Your team's default: NOC wall")).toBeTruthy();
    expect(screen.getByTestId("team-default-board")).toBeTruthy();
    expect(screen.getByTestId("stub-traffic")).toBeTruthy();
    // The built-in page is not mounted underneath it.
    expect(screen.queryByText("Open problems")).toBeNull();
    // The picker names the team default and still reaches the built-in page.
    expect(screen.getByRole("option", { name: "Overview (team default)" })).toBeTruthy();
    expect(screen.getByRole("option", { name: "Operations Overview" })).toBeTruthy();
  });

  it("opens the Operations Overview at the built-in address even when a team default exists", async () => {
    location.hash = "#/overview/operations/builtin";
    api.getOverviewDefault.mockResolvedValue({ tenant_id: "t1", dashboard_id: teamBoard.id, dashboard: teamBoard, unavailable: false });
    render(<OverviewPage />);
    expect(await screen.findByRole("heading", { name: "Operations Overview" })).toBeTruthy();
    expect(screen.queryByTestId("team-default-board")).toBeNull();
  });

  it("keeps the merged layout at its own address, with the picker on it", async () => {
    location.hash = "#/overview/operations/standard";
    api.getOverviewDefault.mockResolvedValue({ tenant_id: "t1", dashboard_id: teamBoard.id, dashboard: teamBoard, unavailable: false });
    render(<OverviewPage />);
    expect(await screen.findByText("Nothing needs attention right now.")).toBeTruthy();
    expect(screen.queryByTestId("team-default-board")).toBeNull();
    expect((screen.getByTestId("dashboard-picker") as HTMLSelectElement).value).toBe("__standard");
    expect(screen.getByRole("option", { name: "Operations Overview" })).toBeTruthy();
  });

  it("falls back to the Operations Overview with a quiet note when the default is gone", async () => {
    api.getOverviewDefault.mockResolvedValue({ tenant_id: "t1", dashboard_id: teamBoard.id, dashboard: null, unavailable: true });
    render(<OverviewPage />);
    expect(await screen.findByTestId("team-default-unavailable")).toBeTruthy();
    expect(await screen.findByRole("heading", { name: "Operations Overview" })).toBeTruthy();
  });

  it("shows the Operations Overview when the team default cannot be read", async () => {
    api.getOverviewDefault.mockRejectedValue(new Error("502"));
    render(<OverviewPage />);
    expect(await screen.findByRole("heading", { name: "Operations Overview" })).toBeTruthy();
    expect(screen.queryByTestId("team-default-unavailable")).toBeNull();
  });
});

describe("Overview — the Operations Overview is the default again (owner, 2026-11-23)", () => {
  it("opens the Operations Overview at #/overview/operations with no team default", async () => {
    render(<OverviewPage />);
    expect(await screen.findByRole("heading", { name: "Operations Overview" })).toBeTruthy();
    expect(screen.getByTestId("operations-overview")).toBeTruthy();
    // The merged layout is not mounted underneath it.
    expect(screen.queryByText("Nothing needs attention right now.")).toBeNull();
  });

  it("shows real per-site health, not the old 'not available' stub", async () => {
    api.geomap.mockResolvedValue({ geo_enabled: true, sites: [] });
    render(<OverviewPage />);
    expect(await screen.findByText("No sites declared yet.")).toBeTruthy();
    expect(screen.queryByText("Per-site health not available yet.")).toBeNull();
  });

  it("never shows (or polls) the platform's own health for a tenant user", async () => {
    render(<OverviewPage />);
    await screen.findByRole("heading", { name: "Operations Overview" });
    await waitFor(() => expect(api.me).toHaveBeenCalled());
    expect(screen.queryByText("Platform health (internal)")).toBeNull();
    expect(api.stackHealth).not.toHaveBeenCalled();
  });

  it("shows the platform's own health to the platform admin", async () => {
    api.me.mockResolvedValue({ platform_admin: true });
    render(<OverviewPage />);
    expect(await screen.findByText("Platform health (internal)")).toBeTruthy();
  });
});
