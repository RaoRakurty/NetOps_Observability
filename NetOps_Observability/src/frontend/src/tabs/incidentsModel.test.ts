// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import type { Incident } from "../services/api";
import {
  INCIDENT_SOURCE_TABS, inSourceTab, filterIncidents, statusCounts, countsNote, pageNote, ownerText, statusText,
  activeIncidentFilterCount, isActiveIncident,
} from "./incidentsModel";

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
