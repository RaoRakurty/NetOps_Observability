// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import type { Incident } from "../services/api";
import {
  INCIDENT_SOURCE_TABS, inSourceTab, filterIncidents, statusCounts, countsNote, pageNote, ownerText, statusText,
  activeIncidentFilterCount, isActiveIncident, incidentWhere, whereText,
} from "./incidentsModel";
import { buildDevicePlaces, deviceSite } from "../lib/deviceNames";
import type { Device } from "../services/api";

const inc = (o: Partial<Incident>): Incident => ({
  id: "i", title: "WAN loss at DFW", severity: "high", status: "open", source_type: "alert",
  occurrences: 1, sync_status: "", ...o,
}) as Incident;

describe("incidentsModel — Incidents as a presenter", () => {
  it("source tabs cover every source the store keeps, alerts first after All", () => {
    expect(INCIDENT_SOURCE_TABS.map((t) => t.id)).toEqual(["all", "alert", "logs", "manual", "experience"]);
    expect(inSourceTab(inc({ source_type: "log" }), "logs")).toBe(true);
    expect(inSourceTab(inc({ source_type: "anomaly" }), "logs")).toBe(true);
    expect(inSourceTab(inc({ source_type: "experience" }), "experience")).toBe(true);
    // An unset source is what the store would have collapsed it to: manual.
    expect(inSourceTab(inc({ source_type: "" }), "manual")).toBe(true);
  });

  it("filters combine over the tab", () => {
    const items = [
      inc({ id: "a", status: "open", owner: "" }),
      inc({ id: "b", status: "acknowledged", owner: "noc-lee", severity: "critical" }),
      inc({ id: "c", status: "resolved", source_type: "manual", title: "User reports slow CRM" }),
    ];
    const ids = (tab: Parameters<typeof filterIncidents>[1], f: Parameters<typeof filterIncidents>[2]) =>
      filterIncidents(items, tab, f).map((i) => i.id);
    expect(ids("all", {})).toEqual(["a", "b", "c"]);
    expect(ids("alert", {})).toEqual(["a", "b"]);
    expect(ids("all", { status: "acknowledged" })).toEqual(["b"]);
    expect(ids("all", { unassigned: true })).toEqual(["a", "c"]);
    expect(ids("all", { severity: "critical" })).toEqual(["b"]);
    expect(ids("all", { q: "crm" })).toEqual(["c"]);
    expect(ids("manual", { q: "wan" })).toEqual([]);
    expect(activeIncidentFilterCount({ status: "open", q: " " })).toBe(1);
  });

  it("status tiles count the loaded rows of the current tab", () => {
    const items = [inc({ status: "open" }), inc({ status: "open" }), inc({ status: "closed", source_type: "manual" })];
    expect(statusCounts(items, "all")).toMatchObject({ open: 2, closed: 1 });
    expect(statusCounts(items, "alert")).toMatchObject({ open: 2, closed: 0 });
  });

  it("the notes say when a page is not the whole set", () => {
    expect(countsNote(200, 1437)).toBe("Counted in the 200 loaded incidents of 1,437.");
    expect(countsNote(12, 12)).toBe("Counted across all 12 incidents.");
    expect(pageNote(0, 12, 12)).toBe("");
    expect(pageNote(200, 200, 1437)).toBe("Showing 201–400 of 1,437 incidents.");
  });

  it("owner and status read in plain words", () => {
    expect(ownerText(inc({ owner: "  " }))).toBe("Unassigned");
    expect(ownerText(inc({ owner: "noc-lee" }))).toBe("noc-lee");
    expect(statusText("investigating")).toBe("Investigating");
    expect(isActiveIncident(inc({ status: "resolved" }))).toBe(false);
  });
});

describe("WHERE an incident is (tracker 438)", () => {
  const d = (o: Partial<Device>): Device => ({ id: "", name: "", address: "", source: "snmp", last_seen: "", ...o }) as Device;
  const places = buildDevicePlaces([
    d({ id: "edge-1-aa", name: "edge-1", address: "10.0.0.1", labels: { site: "HQ" } }),
    d({ id: "edge-1-bb", name: "edge-1", address: "10.0.0.2", reported_site_id: "100" }),
    d({ id: "core-cc", name: "core", address: "10.0.0.3" }),
  ]);

  it("names the device and its site; two same-named devices are told apart by address", () => {
    expect(incidentWhere(inc({ device_id: "edge-1-aa" }), places)).toEqual({ device: "edge-1 (10.0.0.1)", site: "HQ", id: "edge-1-aa" });
    expect(whereText(incidentWhere(inc({ device_id: "edge-1-bb" }), places))).toBe("edge-1 (10.0.0.2) · site-id 100");
    expect(whereText(incidentWhere(inc({ device_id: "core-cc" }), places))).toBe("core");
  });

  it("an unknown device keeps its id; no device is empty, never invented", () => {
    expect(incidentWhere(inc({ device_id: "ghost-9" }), places)).toEqual({ device: "ghost-9", site: "", id: "ghost-9" });
    expect(incidentWhere(inc({ device_id: "ghost-9" }), null).device).toBe("ghost-9");
    expect(whereText(incidentWhere(inc({}), places))).toBe("");
  });

  it("the operator's site wins over a location label and the reported site id", () => {
    expect(deviceSite({ labels: { site: "HQ", location: "Bldg 2" }, reported_site_id: "7" })).toBe("HQ");
    expect(deviceSite({ labels: { location: "Bldg 2" }, reported_site_id: "7" })).toBe("Bldg 2");
    expect(deviceSite({ reported_site_id: "7" })).toBe("site-id 7");
    expect(deviceSite({})).toBe("");
  });

  it("search reads the device name, the site and the raw id", () => {
    const rows = [inc({ id: "1", title: "Gi1 down", device_id: "edge-1-aa" }), inc({ id: "2", title: "Disk full" })];
    expect(filterIncidents(rows, "all", { q: "hq" }, places).map((i) => i.id)).toEqual(["1"]);
    expect(filterIncidents(rows, "all", { q: "edge-1-aa" }, places).map((i) => i.id)).toEqual(["1"]);
    expect(filterIncidents(rows, "all", { q: "edge-1-aa" }).map((i) => i.id)).toEqual(["1"]);
  });
});
