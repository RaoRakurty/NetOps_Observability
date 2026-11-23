// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// My dashboards — the builder under Overview (2026-11-22). Pins: the list and its
// three starting points, opening a dashboard by its address, "not found" for an
// id the server refuses (another tenant's, or deleted), a save that names a save
// failure, the delete confirm, and a template that starts with real panels.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, act } from "@testing-library/react";
import { StrictMode } from "react";

const api = {
  listSaved: vi.fn(), getSaved: vi.fn(), createSaved: vi.fn(), updateSaved: vi.fn(), deleteSaved: vi.fn(),
  correlations: vi.fn(), healthScore: vi.fn(), correlationsStats: vi.fn(), geomap: vi.fn(),
  eventsFeed: vi.fn(), metricsForecast: vi.fn(), correlationTimeline: vi.fn(),
  getOverviewDefault: vi.fn(), setOverviewDefault: vi.fn(), resetOverviewDefault: vi.fn(), permissions: vi.fn(),
};
vi.mock("../../services/api", () => ({
  api: new Proxy({}, { get: (_t, k: string) => (api as Record<string, unknown>)[k] ?? (() => Promise.resolve([])) }),
  getActiveScope: () => "",
  sessionTenantKey: () => "t1",
}));
vi.mock("../../context/shell", () => ({ useShell: () => ({ navigate: vi.fn() }) }));
vi.mock("../../components/AskIris", () => ({ default: () => null }));
vi.mock("../../components/Icon", () => ({ default: () => null }));
vi.mock("../../components/PathHealthList", () => ({ default: () => <div>hot paths</div> }));
vi.mock("../../components/rca/RcaPathCausality", () => ({ default: () => <div>path view</div> }));
vi.mock("../../components/ui", () => ({ Modal: ({ children, title }: { children: unknown; title: string }) => <div role="dialog" aria-label={title}>{children as never}</div> }));
vi.mock("../panels", async (orig) => {
  const real = await orig<typeof import("../panels")>();
  const stub = (type: string) => ({ type, title: `panel ${type}`, defaultSpan: 6, category: "Traffic" as const, render: () => <div data-testid={`stub-${type}`} /> });
  return { ...real, PANELS: Object.fromEntries(Object.keys(real.PANELS).map((t) => [t, stub(t)])) };
});

import MyDashboards from "./MyDashboards";
import { __resetBoardHealth } from "../panels";

const board = (o: Partial<{ id: string; name: string; body: unknown }> = {}) => ({
  id: "0f1e2d3c4b5a69788796a5b4c3d2e1f0", type: "dashboard", name: "NOC wall", owner: "a", tenant_id: "t1",
  body: { v: 1, cells: [{ type: "traffic", span: 8 }] }, created_at: "2026-11-22T10:00:00Z", updated_at: "2026-11-22T10:00:00Z", ...o,
});

beforeEach(() => {
  __resetBoardHealth();
  api.listSaved.mockResolvedValue([board()]);
  api.correlations.mockResolvedValue({ data: [] });
  api.healthScore.mockResolvedValue({ score: 90, band: "healthy", coverage_status: "OK", signal_classes_live: [], contributions: [], stale_inputs: [] });
  api.correlationsStats.mockResolvedValue({ open: 0, open_confirmed: 0, open_suspected: 0, signatures_matched: 0 });
  api.geomap.mockResolvedValue({ geo_enabled: true, sites: [] });
  api.eventsFeed.mockResolvedValue({ items: [] });
  api.metricsForecast.mockResolvedValue({ interfaces: [], min_days: 14 });
});
afterEach(() => { cleanup(); vi.clearAllMocks(); location.hash = ""; });

describe("My dashboards — the list", () => {
  it("lists the tenant's dashboards with their addresses and offers three starting points", async () => {
    location.hash = "#/overview/dashboards";
    render(<MyDashboards />);
    const link = await screen.findByRole("link", { name: /NOC wall/ });
    expect(link.getAttribute("href")).toBe("#/overview/dashboards/0f1e2d3c4b5a69788796a5b4c3d2e1f0");
    expect(screen.getByText("Make a copy of the default")).toBeTruthy();
    expect(screen.getByText("Start from Network telemetry")).toBeTruthy();
    expect(screen.getByText("Start empty")).toBeTruthy();
  });

  it("says the list failed rather than showing zero dashboards", async () => {
    location.hash = "#/overview/dashboards";
    api.listSaved.mockRejectedValue(new Error("502 Bad Gateway: upstream"));
    render(<MyDashboards />);
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(screen.queryByText(/No dashboards yet/)).toBeNull();
  });

  it("asks before deleting, and names a delete failure as a delete failure", async () => {
    location.hash = "#/overview/dashboards";
    api.deleteSaved.mockRejectedValue(new Error("403 Forbidden: write permission required to delete it"));
    render(<MyDashboards />);
    fireEvent.click(await screen.findByRole("button", { name: "Delete NOC wall" }));
    expect(api.deleteSaved).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: 'Delete "NOC wall"' }));
    await waitFor(() => expect(api.deleteSaved).toHaveBeenCalledWith("0f1e2d3c4b5a69788796a5b4c3d2e1f0"));
    expect((await screen.findByRole("alert")).textContent).toMatch(/permission|could not be deleted/i);
  });

  it("a deleted dashboard stays deleted when an older list read answers last", async () => {
    // StrictMode mounts twice, so two list reads are in flight; the FIRST one
    // answers only after the delete's own re-read (as the network may order it).
    location.hash = "#/overview/dashboards";
    let answerStale: (v: unknown) => void = () => {};
    api.listSaved
      .mockImplementationOnce(() => new Promise((res) => { answerStale = res; }))
      .mockResolvedValueOnce([board()])
      .mockResolvedValueOnce([]);
    api.deleteSaved.mockResolvedValue(undefined);
    render(<StrictMode><MyDashboards /></StrictMode>);
    fireEvent.click(await screen.findByRole("button", { name: "Delete NOC wall" }));
    fireEvent.click(screen.getByRole("button", { name: 'Delete "NOC wall"' }));
    expect(await screen.findByText(/No dashboards yet/)).toBeTruthy();
    await act(async () => { answerStale([board()]); });
    expect(screen.getByText(/No dashboards yet/)).toBeTruthy();
    expect(screen.queryByRole("link", { name: /NOC wall/ })).toBeNull();
  });
});

describe("My dashboards — open by address", () => {
  it("opens the dashboard its address names", async () => {
    location.hash = "#/overview/dashboards/0f1e2d3c4b5a69788796a5b4c3d2e1f0";
    api.getSaved.mockResolvedValue(board());
    render(<MyDashboards />);
    expect(await screen.findByRole("heading", { level: 1, name: "NOC wall" })).toBeTruthy();
    expect(screen.getByTestId("stub-traffic")).toBeTruthy();
    expect(api.getSaved).toHaveBeenCalledWith("0f1e2d3c4b5a69788796a5b4c3d2e1f0");
  });

  it("reads 'does not exist' for an id the server refuses — another tenant's or a deleted one", async () => {
    location.hash = "#/overview/dashboards/aaaabbbbccccdddd";
    api.getSaved.mockRejectedValue(new Error("404 Not Found: not found"));
    render(<MyDashboards />);
    expect(await screen.findByText("This dashboard does not exist")).toBeTruthy();
    expect(screen.getByText("It was deleted, or it belongs to another tenant.")).toBeTruthy();
  });

  it("never calls the server for an address that is not a well-formed id", async () => {
    location.hash = "#/overview/dashboards/..%2Fapi";
    render(<MyDashboards />);
    await screen.findByTestId("dashboard-list");
    expect(api.getSaved).not.toHaveBeenCalled();
  });
});

describe("My dashboards — templates and saving", () => {
  it("a copy of the default starts with the Overview's panels and the shared read", async () => {
    location.hash = "#/overview/dashboards/new?template=default";
    render(<MyDashboards />);
    expect((await screen.findByLabelText("Dashboard name") as HTMLInputElement).value).toBe("Copy of Overview");
    expect(await screen.findByText("Nothing needs attention right now.")).toBeTruthy();
    // Many RCA cells, ONE correlations read for the whole dashboard.
    await waitFor(() => expect(api.correlations).toHaveBeenCalled());
    expect(api.correlations).toHaveBeenCalledTimes(1);
  });

  it("saves a new dashboard and goes to its address", async () => {
    location.hash = "#/overview/dashboards/new?template=telemetry";
    api.createSaved.mockResolvedValue(board({ id: "1234abcd", name: "Network telemetry" }));
    render(<MyDashboards />);
    fireEvent.click(await screen.findByRole("button", { name: "Save" }));
    await waitFor(() => expect(api.createSaved).toHaveBeenCalled());
    const [type, name, body] = api.createSaved.mock.calls[0];
    expect(type).toBe("dashboard");
    expect(name).toBe("Network telemetry");
    expect((body as { cells: unknown[] }).cells.length).toBeGreaterThan(10);
    await waitFor(() => expect(location.hash).toBe("#/overview/dashboards/1234abcd"));
  });

  it("names a save failure as a save failure", async () => {
    location.hash = "#/overview/dashboards/new";
    api.createSaved.mockRejectedValue(new Error("409 Conflict: this tenant already keeps 500 saved objects of this kind; delete one first"));
    render(<MyDashboards />);
    fireEvent.change(await screen.findByLabelText("Dashboard name"), { target: { value: "Mine" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).not.toMatch(/could not be loaded/);
  });

  it("refuses to save without a name", async () => {
    location.hash = "#/overview/dashboards/new";
    render(<MyDashboards />);
    fireEvent.click(await screen.findByRole("button", { name: "Save" }));
    expect((await screen.findByRole("alert")).textContent).toBe("Give the dashboard a name.");
    expect(api.createSaved).not.toHaveBeenCalled();
  });
});

describe("My dashboards — the team default", () => {
  const ID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";
  const asAdmin = () => api.permissions.mockResolvedValue({ role: "admin", permissions: { administration: 3 } });
  const asOperator = () => api.permissions.mockResolvedValue({ role: "operator", permissions: { administration: 0 } });

  it("lets a tenant administrator make a dashboard the team default", async () => {
    location.hash = "#/overview/dashboards";
    asAdmin();
    api.getOverviewDefault.mockResolvedValue({ tenant_id: "t1", dashboard_id: "", dashboard: null, unavailable: false });
    api.setOverviewDefault.mockResolvedValue({ tenant_id: "t1", dashboard_id: ID, dashboard: board(), unavailable: false });
    render(<MyDashboards />);
    fireEvent.click(await screen.findByRole("button", { name: "Make this the team default" }));
    await waitFor(() => expect(api.setOverviewDefault).toHaveBeenCalledWith(ID));
    expect(await screen.findByTestId("team-default-chip")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Reset to built-in" })).toBeTruthy();
  });

  it("resets the team default to the built-in Overview", async () => {
    location.hash = "#/overview/dashboards";
    asAdmin();
    api.getOverviewDefault.mockResolvedValue({ tenant_id: "t1", dashboard_id: ID, dashboard: board(), unavailable: false });
    api.resetOverviewDefault.mockResolvedValue({ tenant_id: "t1", dashboard_id: "", dashboard: null, unavailable: false });
    render(<MyDashboards />);
    fireEvent.click(await screen.findByRole("button", { name: "Reset to built-in" }));
    await waitFor(() => expect(api.resetOverviewDefault).toHaveBeenCalled());
    await waitFor(() => expect(screen.queryByTestId("team-default-chip")).toBeNull());
  });

  it("shows everyone which dashboard is the team default, but only administrators get the buttons", async () => {
    location.hash = "#/overview/dashboards";
    asOperator();
    api.getOverviewDefault.mockResolvedValue({ tenant_id: "t1", dashboard_id: ID, dashboard: board(), unavailable: false });
    render(<MyDashboards />);
    expect(await screen.findByTestId("team-default-chip")).toBeTruthy();
    await waitFor(() => expect(api.permissions).toHaveBeenCalled());
    expect(screen.queryByRole("button", { name: "Make this the team default" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Reset to built-in" })).toBeNull();
  });

  it("shows the server's reason when a promotion is refused, and marks nothing", async () => {
    location.hash = "#/overview/dashboards";
    asAdmin();
    api.getOverviewDefault.mockResolvedValue({ tenant_id: "t1", dashboard_id: "", dashboard: null, unavailable: false });
    api.setOverviewDefault.mockRejectedValue(new Error("404 Not Found: dashboard not found"));
    render(<MyDashboards />);
    fireEvent.click(await screen.findByRole("button", { name: "Make this the team default" }));
    expect((await screen.findByRole("alert")).textContent).toBe("Dashboard not found.");
    expect(screen.queryByTestId("team-default-chip")).toBeNull();
  });
});
