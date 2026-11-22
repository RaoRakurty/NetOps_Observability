// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect, vi } from "vitest";

vi.mock("../../components/AskIris", () => ({ default: () => null }));

import { MAX_CELLS, TEMPLATES, dashHref, dashRoute, parseBody } from "./dashboardModel";
import { BOARD_CATEGORIES, BOARD_PANELS, RCA_PANELS } from "./panelRegistry";

describe("parseBody", () => {
  it("keeps an unknown panel type from a newer version — never drops it", () => {
    const b = parseBody({ v: 1, cells: [{ type: "from-the-future", span: 6 }, { type: "traffic", span: 8 }] });
    expect(b.cells).toEqual([{ type: "from-the-future", span: 6 }, { type: "traffic", span: 8 }]);
  });

  it("falls back to 4 columns for a bad span and drops cells with no type", () => {
    const b = parseBody({ cells: [{ type: "traffic", span: 7 }, { span: 6 }, null, { type: "" }] });
    expect(b.cells).toEqual([{ type: "traffic", span: 4 }]);
  });

  it("caps the cell count", () => {
    const many = Array.from({ length: MAX_CELLS + 5 }, () => ({ type: "traffic", span: 3 }));
    expect(parseBody({ cells: many }).cells).toHaveLength(MAX_CELLS);
  });

  it("reads garbage as an empty dashboard", () => {
    expect(parseBody(null).cells).toEqual([]);
    expect(parseBody("nope").cells).toEqual([]);
  });
});

describe("templates", () => {
  it.each(Object.entries(TEMPLATES))("every %s cell is a panel this version can render", (_id, t) => {
    const missing = t.cells.filter((c) => !BOARD_PANELS[c.type]).map((c) => c.type);
    expect(missing).toEqual([]);
    expect(t.cells.length).toBeLessThanOrEqual(MAX_CELLS);
  });

  it("the copy of the default carries the RCA panels, which a dashboard could not show before", () => {
    const types = TEMPLATES.default.cells.map((c) => c.type);
    for (const t of ["overview-attention", "overview-kpis", "rca-top-issues", "site-health"]) expect(types).toContain(t);
  });

  it("Network telemetry keeps everything the retired My Dashboard board had", () => {
    const types = TEMPLATES.telemetry.cells.map((c) => c.type);
    for (const t of ["kpis", "sat-cpu", "traffic", "wan-interfaces", "bgp-peers", "probe-rtt", "alerts-severity", "topology"]) expect(types).toContain(t);
  });
});

describe("the panel picker", () => {
  it("lists the RCA panels first, in their own group", () => {
    expect(BOARD_CATEGORIES[0]).toEqual({ category: "Problems and RCA", types: Object.keys(RCA_PANELS) });
    expect(Object.values(RCA_PANELS).every((p) => p.selfTitled)).toBe(true);
  });
});

describe("dashboard addresses", () => {
  it.each([
    ["#/overview/dashboards", { kind: "list" }],
    ["#/overview/dashboards/new", { kind: "new" }],
    ["#/overview/dashboards/new?template=default", { kind: "new", template: "default" }],
    ["#/overview/dashboards/new?template=telemetry", { kind: "new", template: "telemetry" }],
    ["#/overview/dashboards/new?template=evil", { kind: "new" }],
    ["#/overview/dashboards/0f1e2d3c4b5a69788796a5b4c3d2e1f0", { kind: "open", id: "0f1e2d3c4b5a69788796a5b4c3d2e1f0" }],
    ["#/overview/dashboards/..%2F..%2Fapi", { kind: "list" }],
    ["#/overview/dashboards/a b", { kind: "list" }],
    ["#/overview/operations", { kind: "list" }],
  ])("%s → %j", (hash, want) => {
    expect(dashRoute(hash)).toEqual(want);
  });

  it("round-trips every address", () => {
    for (const r of [{ kind: "list" }, { kind: "new" }, { kind: "new", template: "telemetry" }, { kind: "open", id: "abc123" }] as const) {
      expect(dashRoute(dashHref(r))).toEqual(r);
    }
  });
});
