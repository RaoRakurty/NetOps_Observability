// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// charts.test.tsx — TIME_SERIES and BAR: gaps stay gaps, unmeasured is never a
// bar of 0, the tooltip has no HTML sink, and a click drills to the rows.

import { describe, it, expect, afterEach, vi, beforeEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import type { EChartEvents } from "../components/EChart";

const captured: { option: Record<string, unknown>; onEvents?: EChartEvents }[] = [];
vi.mock("../components/EChart", () => ({
  default: (props: { option: Record<string, unknown>; onEvents?: EChartEvents }) => {
    captured.push(props);
    return <div data-testid="chart" />;
  },
}));

import { BarView, TimeSeriesView, barModel, barOption, timeSeriesOption } from "./charts";
import { normalizeResult, type ResultSet } from "./presentation";
import { HOSTILE, baseResult, changeRow, compareResult, seriesResult } from "../test/irisFixtures";

function norm(v: unknown): ResultSet {
  const n = normalizeResult(v);
  if (!n.ok) throw new Error("fixture");
  return n.result;
}

beforeEach(() => {
  captured.length = 0;
});
afterEach(cleanup);

type Series = { type: string; name: string; data: unknown[]; connectNulls?: boolean; label?: { formatter?: (p: unknown) => string } };

describe("TimeSeriesView", () => {
  it("draws a line per entity, keeps unmeasured samples as gaps, and uses a text-only tooltip", () => {
    render(<TimeSeriesView result={norm(seriesResult())} onDrill={() => {}} />);
    const opt = captured[0].option;
    const series = opt.series as Series[];
    expect(series.map((s) => s.name)).toEqual(["core-sw-1", "edge-1"]);
    expect(series[1].data).toEqual([[1789898400000, 3], [1789898460000, null]]);
    expect(series[1].connectNulls).toBe(false);
    expect((opt.tooltip as { renderMode: string }).renderMode).toBe("richText");
    expect(screen.getByText(/Gaps in a line are periods with no measurement/)).toBeInTheDocument();
  });

  it("drills to the rows behind a clicked line", () => {
    const onDrill = vi.fn();
    render(<TimeSeriesView result={norm(seriesResult())} onDrill={onDrill} />);
    captured[0].onEvents!.click({ seriesIndex: 0, dataIndex: 1 });
    expect(onDrill).toHaveBeenCalledWith({
      label: "core-sw-1",
      rows: [
        { device: "core-sw-1", time: "2026-09-20T10:00:00.000Z", value: 10 },
        { device: "core-sw-1", time: "2026-09-20T10:01:00.000Z", value: 12 },
      ],
    });
  });

  it("ignores a malformed click", () => {
    const onDrill = vi.fn();
    render(<TimeSeriesView result={norm(seriesResult())} onDrill={onDrill} />);
    captured[0].onEvents!.click({});
    captured[0].onEvents!.click({ seriesIndex: 99 });
    expect(onDrill).not.toHaveBeenCalled();
  });

  it("says 'Nothing found in this window' instead of drawing an empty chart", () => {
    render(<TimeSeriesView result={norm(seriesResult({ series: [{ entity: {}, points: [{ t: 1, v: null }] }] }))} onDrill={() => {}} />);
    expect(screen.queryByTestId("chart")).toBeNull();
    expect(screen.getByRole("status")).toHaveTextContent("Nothing found in this window.");
  });

  it("carries a hostile entity name only as chart data", () => {
    const opt = timeSeriesOption([{ entity: { device: HOSTILE }, points: [{ t: 1, v: 1 }] }], "");
    expect((opt.series as Series[])[0].name).toBe(HOSTILE);
    expect((opt.tooltip as { renderMode: string }).renderMode).toBe("richText");
  });
});

describe("BarView — compare windows (BAR with delta)", () => {
  it("draws earlier vs this window, with the delta beside it, and 'not measured' for a missing earlier value", () => {
    render(<BarView result={norm(compareResult())} onDrill={() => {}} />);
    const series = captured[0].option.series as Series[];
    expect(series.map((s) => s.name)).toEqual(["Earlier window", "This window"]);
    expect(series[0].data).toEqual([30, null]); // NYC had no earlier measurement — not 0
    expect(series[1].data).toEqual([40, 25]);
    const fmt = series[1].label!.formatter!;
    expect(fmt({ dataIndex: 0, value: 40 })).toBe("+10 ms");
    expect(fmt({ dataIndex: 1, value: 25 })).toBe("change not measured");
    expect(screen.getByText(/change from the earlier window/)).toBeInTheDocument();
  });

  it("drills to the row behind a bar", () => {
    const onDrill = vi.fn();
    render(<BarView result={norm(compareResult())} onDrill={onDrill} />);
    captured[0].onEvents!.click({ dataIndex: 1 });
    expect(onDrill).toHaveBeenCalledWith({ label: "NYC", rows: [{ site: "NYC", value: 25 }] });
  });
});

describe("BarView — who made the most changes", () => {
  const rows = [changeRow({ change_id: "1", actor: "bob" }), changeRow({ change_id: "2", actor: "alice" }), changeRow({ change_id: "3", actor: "bob" }), changeRow({ change_id: "4", actor: "" })];

  it("counts changes per actor, most first, and a missing actor as 'Not recorded'", () => {
    const m = barModel(norm(baseResult({ rows })), "actor")!;
    expect(m.kind).toBe("counts");
    expect(m.categories).toEqual(["bob", "alice", "Not recorded"]);
    expect(m.series[0].values).toEqual([2, 1, 1]);
  });

  it("drills to that actor's changes", () => {
    const onDrill = vi.fn();
    render(<BarView result={norm(baseResult({ rows }))} groupField="actor" onDrill={onDrill} />);
    captured[0].onEvents!.click({ dataIndex: 0 });
    expect(onDrill.mock.calls[0][0].label).toBe("bob");
    expect(onDrill.mock.calls[0][0].rows.map((r: { change_id: string }) => r.change_id)).toEqual(["1", "3"]);
  });

  it("warns that counts from a partial answer are partial", () => {
    render(<BarView result={norm(baseResult({ rows, truncated: true }))} groupField="actor" onDrill={() => {}} />);
    expect(screen.getByText(/Counts cover only the rows returned/)).toBeInTheDocument();
  });
});

describe("BarView — values and empties", () => {
  it("top-k values: a missing value is labelled, not drawn as 0", () => {
    const m = barModel(norm(baseResult({ query_type: "metric_topk", metric: "cpu", rows: [{ device: "a", value: 90 }, { device: "b" }] })))!;
    expect(m.series[0].values).toEqual([90, null]);
    expect(m.labels).toEqual([null, "not measured"]);
    const opt = barOption(m, "%");
    expect(((opt.series as Series[])[0].label!.formatter!)({ dataIndex: 0, value: 90 })).toBe("90");
  });

  it("no rows, or rows with nothing to bar → 'Nothing found in this window'", () => {
    render(<BarView result={norm(baseResult({ query_type: "metric_topk", rows: [] }))} onDrill={() => {}} />);
    expect(screen.getByRole("status")).toHaveTextContent("Nothing found in this window.");
    cleanup();
    render(<BarView result={norm(baseResult({ query_type: "metric_topk", rows: [{ device: "a" }] }))} onDrill={() => {}} />);
    expect(screen.getByRole("status")).toHaveTextContent("Nothing found in this window.");
    expect(captured).toHaveLength(0);
  });
});
