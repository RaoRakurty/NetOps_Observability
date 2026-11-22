// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import type { AlertEpisode } from "../services/api";
import {
  ALERT_TABS, toAlertView, alertTiles, filterAlerts, facetValues, deviceLabel, isSuppressed, activeAlertFilterCount,
} from "./alertsModel";

const ep = (o: Partial<AlertEpisode>): AlertEpisode => ({
  id: "e", signal: "HighCPU", state: "critical", status: "active",
  first_seen: "2026-11-22T08:00:00Z", last_seen: "2026-11-22T09:00:00Z", count: 1, ...o,
});
const names = new Map([["vedge-20-02efdcad", "vEdge-20"]]);
const NOW = Date.parse("2026-11-22T10:00:00Z");

describe("alertsModel — Active Alerts as a presenter", () => {
  it("tabs map 1:1 onto the episode API's status filter, Firing first", () => {
    expect(ALERT_TABS.map((t) => [t.id, t.label])).toEqual([
      ["active", "Firing"], ["cleared", "Cleared"], ["closed", "Closed"], ["all", "All"],
    ]);
  });

  it("a row says what fired where, with the device by name and the raw id kept", () => {
    const v = toAlertView(ep({ resource: "vedge-20-02efdcad", summary: "CPU 97%", count: 7 }), names);
    expect(v.title).toBe("HighCPU on vEdge-20");
    expect(v.detail).toBe("CPU 97% · 7 firings");
    expect(v.device).toBe("vEdge-20");
    expect(v.deviceId).toBe("vedge-20-02efdcad");
  });

  it("an unknown device shows its id, a stack-level episode says Platform", () => {
    expect(deviceLabel(ep({ resource: "leaf9" }), names)).toBe("leaf9");
    expect(toAlertView(ep({ resource: "leaf9" }), names).deviceId).toBe("");
    expect(toAlertView(ep({}), names).title).toBe("HighCPU");
    expect(deviceLabel(ep({}), null)).toBe("Platform");
  });

  it("tiles count the loaded rows and say so when the list is cut", () => {
    const items = [ep({ state: "critical" }), ep({ state: "warning" }), ep({ state: "warning" })];
    const full = alertTiles(items, false, 3);
    expect(full.tiles.find((t) => t.id === "warning")?.count).toBe(2);
    expect(full.note).toBe("Counted across all 3 episodes in this view.");
    expect(alertTiles(items, true, 900).note).toBe("Counted in the 3 loaded episodes of 900.");
  });

  it("quick filters narrow the loaded rows, and combine", () => {
    const views = [
      ep({ id: "a", resource: "vedge-20-02efdcad", flapping: true }),
      ep({ id: "b", resource: "leaf9", state: "warning", assigned_to: "noc-lee" }),
      ep({ id: "c", resource: "leaf9", muted: true }),
    ].map((e) => toAlertView(e, names));
    const ids = (f: Parameters<typeof filterAlerts>[1]) => filterAlerts(views, f, NOW).map((v) => v.id);
    expect(ids({ device: "vEdge-20" })).toEqual(["a"]);
    expect(ids({ flapping: true })).toEqual(["a"]);
    expect(ids({ paused: true })).toEqual(["c"]);
    expect(ids({ unassigned: true })).toEqual(["a", "c"]);
    expect(ids({ severity: "warning" })).toEqual(["b"]);
    expect(ids({ q: "noc-lee" })).toEqual(["b"]);
    expect(ids({ device: "leaf9", unassigned: true })).toEqual(["c"]);
    expect(activeAlertFilterCount({ device: "leaf9", unassigned: true, q: "  " })).toBe(2);
  });

  it("facets list values most frequent first", () => {
    const views = [ep({ resource: "leaf9" }), ep({ resource: "leaf9" }), ep({ resource: "vedge-20-02efdcad" })].map((e) => toAlertView(e, names));
    expect(facetValues(views, (v) => v.device)).toEqual([{ value: "leaf9", count: 2 }, { value: "vEdge-20", count: 1 }]);
  });

  it("a snooze in the past is not a pause", () => {
    expect(isSuppressed(ep({ snoozed_until: "2026-11-22T09:00:00Z" }), NOW)).toBe(false);
    expect(isSuppressed(ep({ snoozed_until: "2026-11-22T11:00:00Z" }), NOW)).toBe(true);
  });
});
