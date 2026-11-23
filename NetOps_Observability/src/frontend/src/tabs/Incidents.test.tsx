// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Incidents.test.tsx — Operations → Incidents in the Logs pattern (owner,
// 2026-11-22): the true total and paging, source tabs and status tiles over the
// loaded rows, an owner column with Assign, the side panel, and the honest
// failure state ("unknown, not empty").

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, within } from "@testing-library/react";

const listIncidentsPage = vi.fn();
const getIncidentTimeline = vi.fn();
const incidentAction = vi.fn();
const devices = vi.fn();

vi.mock("../services/api", () => ({
  api: {
    listIncidentsPage: (...a: unknown[]) => listIncidentsPage(...a),
    getIncidentTimeline: (...a: unknown[]) => getIncidentTimeline(...a),
    incidentAction: (...a: unknown[]) => incidentAction(...a),
    devices: (...a: unknown[]) => devices(...a),
  },
}));
vi.mock("../lib/aiEntitlements", () => ({ useAIEntitlements: () => ({ has: () => true }) }));

import Incidents from "./Incidents";
import { resetDeviceNamesForTest } from "../lib/deviceNames";

const A = { id: "11111111-aaaa-0000-0000-000000000001", title: "WAN loss at DFW", severity: "critical", status: "open",
  source_type: "alert", device_id: "edge-dfw-1a2b", occurrences: 3, sync_status: "", owner: "", first_seen_at: "2026-11-22T08:00:00Z", last_seen_at: "2026-11-22T09:00:00Z" };
const B = { id: "22222222-bbbb-0000-0000-000000000002", title: "User reports slow CRM", severity: "medium", status: "acknowledged",
  source_type: "manual", occurrences: 1, sync_status: "", owner: "noc-lee", first_seen_at: "2026-11-22T07:00:00Z", last_seen_at: "2026-11-22T07:30:00Z" };

const grid = () => screen.findByRole("grid", { name: "Incidents" });
const dataRows = (g: HTMLElement) => within(g).getAllByRole("row").filter((r) => r.classList.contains("dtv-row"));

beforeEach(() => {
  vi.clearAllMocks();
  resetDeviceNamesForTest();
  devices.mockResolvedValue([{ id: "edge-dfw-1a2b", name: "edge-dfw", address: "10.9.0.1", source: "snmp", last_seen: "",
    labels: { site: "Dallas DC" } }]);
  listIncidentsPage.mockResolvedValue({ incidents: [A, B], total: 2, offset: 0, complete: true });
  getIncidentTimeline.mockImplementation((id: string) => Promise.resolve({ incident: id === A.id ? A : B, timeline: [] }));
});
afterEach(cleanup);

describe("Operations → Incidents", () => {
  it("reads one page with its true total and shows an owner column", async () => {
    render(<Incidents />);
    const g = await grid();
    expect(listIncidentsPage).toHaveBeenCalledWith({ limit: 200, offset: 0 });
    expect(dataRows(g)).toHaveLength(2);
    expect(within(g).getByText("Unassigned")).toBeTruthy();
    expect(within(g).getByText("noc-lee")).toBeTruthy();
    expect(screen.queryByTestId("incidents-pager")).toBeNull(); // the page IS the whole set
  });

  it("says WHERE: the device by name over its site, and — when no device is named", async () => {
    render(<Incidents />);
    const g = await grid();
    const where = await within(g).findByText("edge-dfw");
    const cell = where.closest("[data-testid='incident-where']") as HTMLElement;
    expect(cell.textContent).toContain("Dallas DC");
    // Owner, 2026-11-23: the internal id is never shown beside the name.
    expect(cell.textContent).not.toContain("1a2b");
    const rowB = dataRows(g).find((r) => r.textContent?.includes("User reports slow CRM")) as HTMLElement;
    expect(within(rowB).getByTitle("This incident names no device")).toBeTruthy();
  });

  it("a title minted with the internal device id reads with the device's name, in the row and the panel", async () => {
    listIncidentsPage.mockResolvedValue({ incidents: [{ ...A, title: "edge-dfw-1a2b if9 inbound traffic anomaly (z>3)" }, B], total: 2, offset: 0, complete: true });
    render(<Incidents />);
    const g = await grid();
    expect(await within(g).findByText("edge-dfw if9 inbound traffic anomaly (z>3)")).toBeTruthy();
    expect(g.textContent).not.toContain("1a2b");
    fireEvent.click(within(g).getByText("edge-dfw if9 inbound traffic anomaly (z>3)"));
    const panel = await screen.findByTestId("incident-panel");
    await waitFor(() => expect(panel.textContent).toContain("edge-dfw if9 inbound traffic anomaly (z>3)"));
    expect(panel.textContent).not.toContain("1a2b");
  });

  it("search finds an incident by its device name and its site", async () => {
    render(<Incidents />);
    const g = await grid();
    await within(g).findByText("edge-dfw");
    fireEvent.change(screen.getByLabelText("Search incidents"), { target: { value: "dallas" } });
    await waitFor(() => expect(dataRows(g)).toHaveLength(1));
    expect(within(g).getByText("WAN loss at DFW")).toBeTruthy();
  });

  it("a device the inventory does not hold keeps its id; a failed inventory read never breaks the page", async () => {
    devices.mockRejectedValue(new Error("500"));
    render(<Incidents />);
    const g = await grid();
    expect(await within(g).findByText("edge-dfw-1a2b")).toBeTruthy();
  });

  it("the side panel says where the incident is", async () => {
    render(<Incidents />);
    const g = await grid();
    await within(g).findByText("edge-dfw");
    fireEvent.click(within(g).getByText("WAN loss at DFW"));
    const where = await screen.findByTestId("incident-panel-where");
    await waitFor(() => expect(where.textContent).toMatch(/edge-dfw · Dallas DC/));
  });

  it("a page that is not the whole set says so and pages", async () => {
    listIncidentsPage.mockResolvedValue({ incidents: [A, B], total: 1437, offset: 0, complete: false });
    render(<Incidents />);
    await grid();
    expect(screen.getByTestId("incidents-pager").textContent).toMatch(/Showing 1–2 of 1,437 incidents/);
    expect(screen.getByText("Counted in the 2 loaded incidents of 1,437.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Older" }));
    await waitFor(() => expect(listIncidentsPage).toHaveBeenCalledWith({ limit: 200, offset: 200 }));
  });

  it("source tabs and status tiles narrow the loaded rows", async () => {
    render(<Incidents />);
    await grid();
    fireEvent.click(screen.getByRole("button", { name: /^Opened by people/ }));
    expect(dataRows(await grid())).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: /^All/ }));
    fireEvent.click(screen.getByRole("button", { name: /^Open: 1/ }));
    const g = await grid();
    expect(dataRows(g)).toHaveLength(1);
    expect(within(g).getByText("WAN loss at DFW")).toBeTruthy();
  });

  it("a row opens the side panel, where the incident can be assigned", async () => {
    incidentAction.mockResolvedValue({ ...A, owner: "noc-lee" });
    render(<Incidents />);
    const g = await grid();
    fireEvent.click(within(g).getByText("WAN loss at DFW"));
    const dlg = await screen.findByRole("dialog");
    fireEvent.change(within(dlg).getByLabelText("Owner"), { target: { value: "noc-lee" } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Assign" }));
    await waitFor(() => expect(incidentAction).toHaveBeenCalledWith(A.id, "assign", { owner: "noc-lee" }));
  });

  it("asking Iris closes the panel so Iris is not behind it", async () => {
    render(<Incidents />);
    fireEvent.click(within(await grid()).getByText("WAN loss at DFW"));
    const dlg = await screen.findByRole("dialog");
    fireEvent.click(within(dlg).getByTestId("ask-iris-incident"));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("a failed read is unknown, not empty", async () => {
    listIncidentsPage.mockRejectedValue(new Error("500 Internal Server Error"));
    render(<Incidents />);
    expect(await screen.findByText(/Incidents could not be loaded/)).toBeTruthy();
    expect(screen.getByText("Unknown, not empty.")).toBeTruthy();
    expect(screen.queryByText("No incidents.")).toBeNull();
    expect(screen.getAllByText("—").length).toBeGreaterThanOrEqual(3);
  });
});
