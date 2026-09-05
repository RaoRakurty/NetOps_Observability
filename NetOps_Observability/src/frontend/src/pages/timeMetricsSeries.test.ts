// timeMetricsSeries.test.ts — the honesty rules of the detection/repair trend.
//
// Every assertion here exists because the alternative would be a lie on a NOC
// screen: an incomplete phase rendered as 0 ms, an incident counted twice
// because its metrics were recalculated, platform self-monitoring inflating a
// customer-impacting median, or a row from outside the window moving a point.

import { describe, it, expect } from "vitest";
import {
  buildTimeMetricsSeries, dedupeSnapshots, medianMs, missingEventPhrase,
  METRIC_TTD, METRIC_TTR_RECOVERY, PHASE_SERIES_LABEL,
} from "./timeMetricsSeries";
import type { IncidentTimeMetricRow, IncidentTimeMetric } from "../services/api";

const NOW = Date.parse("2026-06-30T00:00:00Z");
const DAY = 86400_000;
const WEEK = 7 * 86400;

/** A complete phase: it has a measured duration. */
function done(metric: string, ms: number): IncidentTimeMetric {
  return {
    metric_name: metric, complete: true, duration_ms: ms,
    started_at: "2026-06-24T00:00:00Z", ended_at: "2026-06-24T00:01:00Z",
    start_event_type: "impact_started", end_event_type: metric === METRIC_TTD ? "detected" : "recovered",
    confidence: 1, is_inferred: false,
    calculated_at: "2026-06-24T01:00:00Z", calculation_version: "v1",
  };
}

/** An incomplete phase: no duration, and the lifecycle event it waits on. */
function blocked(metric: string, missing: string): IncidentTimeMetric {
  return {
    metric_name: metric, complete: false, duration_ms: 0,
    start_event_type: "impact_started", end_event_type: missing,
    confidence: 0, is_inferred: false,
    blocked_by: `missing ${missing}`, missing_event: missing,
    calculated_at: "2026-06-24T01:00:00Z", calculation_version: "v1",
  };
}

function row(o: Partial<IncidentTimeMetricRow> & { correlation_id: string; occurred_at: string }): IncidentTimeMetricRow {
  return {
    calculation_version: "v1", owner_domain: "LAN", current_bottleneck: "recovery",
    metrics: [], calculated_at: "2026-06-24T01:00:00Z", internal: false, maintenance: false,
    ...o,
  };
}

const opts = (snapshots: IncidentTimeMetricRow[], extra: Record<string, unknown> = {}) => ({
  snapshots, metrics: [METRIC_TTD, METRIC_TTR_RECOVERY],
  windowSeconds: WEEK, bucketSeconds: 86400, now: NOW, ...extra,
});

describe("medianMs — nearest-rank p50, matching the backend's statOf", () => {
  it("returns null for no measurements (never 0)", () => {
    expect(medianMs([])).toBeNull();
  });
  it("picks the nearest-rank value for even and odd samples", () => {
    expect(medianMs([10, 20, 30])).toBe(20);
    expect(medianMs([40, 10, 30, 20])).toBe(20); // ceil(0.5*4)=2 → sorted[1]
    expect(medianMs([5])).toBe(5);
  });
});

describe("dedupeSnapshots", () => {
  it("keeps one row per correlation_id, the freshest calculated_at winning", () => {
    const older = row({ correlation_id: "c1", occurred_at: "2026-06-24T00:00:00Z", calculated_at: "2026-06-24T01:00:00Z", calculation_version: "v1" });
    const newer = row({ correlation_id: "c1", occurred_at: "2026-06-24T00:00:00Z", calculated_at: "2026-06-25T01:00:00Z", calculation_version: "v2" });
    const out = dedupeSnapshots([older, newer]);
    expect(out).toHaveLength(1);
    expect(out[0].calculation_version).toBe("v2");
    expect(dedupeSnapshots([newer, older])[0].calculation_version).toBe("v2");
  });
  it("drops rows carrying no correlation_id (they cannot be deduplicated honestly)", () => {
    expect(dedupeSnapshots([row({ correlation_id: "", occurred_at: "2026-06-24T00:00:00Z" })])).toHaveLength(0);
  });
});

describe("buildTimeMetricsSeries", () => {
  it("builds an empty-but-shaped window from no snapshots", () => {
    const r = buildTimeMetricsSeries(opts([]));
    expect(r.buckets).toHaveLength(8); // 7d window, 1d buckets, both edges
    expect(r.buckets[0].label).toBe("2026-06-23");
    expect(r.buckets[7].label).toBe("2026-06-30");
    expect(r.incidentCount).toBe(0);
    expect(r.incompleteIncidents).toBe(0);
    expect(r.blockers).toEqual([]);
    expect(r.series.map((s) => s.metric)).toEqual([METRIC_TTD, METRIC_TTR_RECOVERY]);
    expect(r.series[0].points.every((p) => p === null)).toBe(true);
  });

  it("charts the median of COMPLETE metrics per bucket and labels the series in the page's vocabulary", () => {
    const r = buildTimeMetricsSeries(opts([
      row({ correlation_id: "a", occurred_at: "2026-06-24T01:00:00Z", metrics: [done(METRIC_TTD, 10_000), done(METRIC_TTR_RECOVERY, 600_000)] }),
      row({ correlation_id: "b", occurred_at: "2026-06-24T09:00:00Z", metrics: [done(METRIC_TTD, 30_000)] }),
      row({ correlation_id: "c", occurred_at: "2026-06-24T23:59:59Z", metrics: [done(METRIC_TTD, 20_000)] }),
      row({ correlation_id: "d", occurred_at: "2026-06-26T05:00:00Z", metrics: [done(METRIC_TTD, 90_000)] }),
    ]));
    const ttd = r.series[0];
    expect(ttd.label).toBe(PHASE_SERIES_LABEL[METRIC_TTD]);
    expect(ttd.points[1]).toBe(20_000);  // 2026-06-24: median of 10/20/30s
    expect(ttd.complete[1]).toBe(3);
    expect(ttd.points[3]).toBe(90_000);  // 2026-06-26
    expect(ttd.points[2]).toBeNull();    // 2026-06-25 — nothing happened, a real gap
    expect(r.series[1].points[1]).toBe(600_000);
    expect(r.incidentCount).toBe(4);
    expect(r.incompleteIncidents).toBe(0);
  });

  it("an incomplete-only bucket is null with the blocking event named — never 0 ms", () => {
    const r = buildTimeMetricsSeries(opts([
      row({ correlation_id: "a", occurred_at: "2026-06-24T01:00:00Z", metrics: [blocked(METRIC_TTR_RECOVERY, "recovered")] }),
      row({ correlation_id: "b", occurred_at: "2026-06-24T02:00:00Z", metrics: [blocked(METRIC_TTR_RECOVERY, "recovered")] }),
      row({ correlation_id: "c", occurred_at: "2026-06-24T03:00:00Z", metrics: [blocked(METRIC_TTR_RECOVERY, "mitigated")] }),
    ]));
    const mttr = r.series[1];
    expect(mttr.points[1]).toBeNull();
    expect(mttr.complete[1]).toBe(0);
    expect(mttr.incomplete[1]).toBe(3);
    expect(mttr.reasons[1]).toEqual({ event: "recovered", count: 2, text: "waiting on a service-recovery signal" });
    expect(mttr.topReason?.event).toBe("recovered");
    expect(r.incompleteIncidents).toBe(3);
    expect(r.blockers[0]).toMatchObject({ event: "recovered", count: 2 });
    expect(r.blockers[1]).toMatchObject({ event: "mitigated", count: 1 });
  });

  it("derives the blocking event from blocked_by when missing_event is absent", () => {
    const m = { ...blocked(METRIC_TTR_RECOVERY, "recovered") };
    delete m.missing_event;
    const r = buildTimeMetricsSeries(opts([row({ correlation_id: "a", occurred_at: "2026-06-24T01:00:00Z", metrics: [m] })]));
    expect(r.series[1].reasons[1]?.event).toBe("recovered");
  });

  it("counts a mixed bucket honestly: a median from the complete rows AND the incomplete tally", () => {
    const r = buildTimeMetricsSeries(opts([
      row({ correlation_id: "a", occurred_at: "2026-06-24T01:00:00Z", metrics: [done(METRIC_TTR_RECOVERY, 100_000)] }),
      row({ correlation_id: "b", occurred_at: "2026-06-24T02:00:00Z", metrics: [blocked(METRIC_TTR_RECOVERY, "recovered")] }),
    ]));
    const mttr = r.series[1];
    expect(mttr.points[1]).toBe(100_000);
    expect(mttr.complete[1]).toBe(1);
    expect(mttr.incomplete[1]).toBe(1);
    expect(mttr.reasons[1]).toBeNull();       // the bucket HAS a value; no gap to explain
    expect(mttr.topReason?.event).toBe("recovered"); // still reported for the window
    expect(r.incidentCount).toBe(2);
    expect(r.incompleteIncidents).toBe(1);
  });

  it("a recalculated incident is counted once, at its freshest snapshot", () => {
    const r = buildTimeMetricsSeries(opts([
      row({ correlation_id: "a", occurred_at: "2026-06-24T01:00:00Z", calculated_at: "2026-06-24T02:00:00Z", calculation_version: "v1", metrics: [done(METRIC_TTD, 10_000)] }),
      row({ correlation_id: "a", occurred_at: "2026-06-24T01:00:00Z", calculated_at: "2026-06-27T02:00:00Z", calculation_version: "v2", metrics: [done(METRIC_TTD, 50_000)] }),
    ]));
    expect(r.incidentCount).toBe(1);
    expect(r.series[0].complete[1]).toBe(1);
    expect(r.series[0].points[1]).toBe(50_000); // the v2 value, not a median of both
  });

  it("excludes internal/platform self-monitoring by default and includes it on request", () => {
    const rows = [
      row({ correlation_id: "a", occurred_at: "2026-06-24T01:00:00Z", metrics: [done(METRIC_TTD, 10_000)] }),
      row({ correlation_id: "p", occurred_at: "2026-06-24T02:00:00Z", internal: true, metrics: [done(METRIC_TTD, 900_000)] }),
    ];
    const off = buildTimeMetricsSeries(opts(rows));
    expect(off.incidentCount).toBe(1);
    expect(off.series[0].points[1]).toBe(10_000);

    const on = buildTimeMetricsSeries(opts(rows, { includeInternal: true }));
    expect(on.incidentCount).toBe(2);
    expect(on.series[0].points[1]).toBe(10_000); // nearest-rank of [10s, 900s] → sorted[0]
    expect(on.series[0].complete[1]).toBe(2);
  });

  it("honours the owner filter and treats an empty owner as every owner", () => {
    const rows = [
      row({ correlation_id: "a", occurred_at: "2026-06-24T01:00:00Z", owner: "isp", metrics: [done(METRIC_TTD, 10_000)] }),
      row({ correlation_id: "b", occurred_at: "2026-06-24T02:00:00Z", owner: "netops", metrics: [done(METRIC_TTD, 20_000)] }),
    ];
    expect(buildTimeMetricsSeries(opts(rows, { owner: "isp" })).incidentCount).toBe(1);
    expect(buildTimeMetricsSeries(opts(rows, { owner: "isp" })).series[0].points[1]).toBe(10_000);
    expect(buildTimeMetricsSeries(opts(rows, { owner: "" })).incidentCount).toBe(2);
  });

  it("ignores rows outside the selected window", () => {
    const r = buildTimeMetricsSeries(opts([
      row({ correlation_id: "old", occurred_at: "2026-06-01T00:00:00Z", metrics: [done(METRIC_TTD, 999_000)] }),
      row({ correlation_id: "future", occurred_at: "2026-07-05T00:00:00Z", metrics: [done(METRIC_TTD, 999_000)] }),
      row({ correlation_id: "bad", occurred_at: "not a timestamp", metrics: [done(METRIC_TTD, 999_000)] }),
      row({ correlation_id: "in", occurred_at: "2026-06-24T01:00:00Z", metrics: [done(METRIC_TTD, 10_000)] }),
    ]));
    expect(r.incidentCount).toBe(1);
    expect(r.series[0].points.filter((p) => p !== null)).toEqual([10_000]);
  });

  it("puts a row exactly on a bucket boundary in that bucket, and one millisecond earlier in the previous one", () => {
    const boundary = Date.parse("2026-06-25T00:00:00Z");
    const r = buildTimeMetricsSeries(opts([
      row({ correlation_id: "on", occurred_at: new Date(boundary).toISOString(), metrics: [done(METRIC_TTD, 40_000)] }),
      row({ correlation_id: "before", occurred_at: new Date(boundary - 1).toISOString(), metrics: [done(METRIC_TTD, 10_000)] }),
    ]));
    expect(r.buckets[1].start).toBe(boundary - DAY);
    expect(r.buckets[2].start).toBe(boundary);
    expect(r.series[0].points[1]).toBe(10_000);
    expect(r.series[0].points[2]).toBe(40_000);
  });

  it("includes the window's first and last instant", () => {
    const r = buildTimeMetricsSeries(opts([
      row({ correlation_id: "start", occurred_at: new Date(NOW - WEEK * 1000).toISOString(), metrics: [done(METRIC_TTD, 10_000)] }),
      row({ correlation_id: "end", occurred_at: new Date(NOW).toISOString(), metrics: [done(METRIC_TTD, 20_000)] }),
    ]));
    expect(r.incidentCount).toBe(2);
    expect(r.series[0].points[0]).toBe(10_000);
    expect(r.series[0].points[7]).toBe(20_000);
  });

  it("refuses to treat a broken 'complete' row (negative duration) as a measurement", () => {
    const r = buildTimeMetricsSeries(opts([
      row({ correlation_id: "a", occurred_at: "2026-06-24T01:00:00Z", metrics: [{ ...done(METRIC_TTD, -5) }] }),
    ]));
    expect(r.series[0].points[1]).toBeNull();
    expect(r.series[0].complete[1]).toBe(0);
  });

  it("returns an empty window for a nonsense window or bucket width", () => {
    for (const bad of [{ windowSeconds: 0 }, { bucketSeconds: 0 }, { bucketSeconds: -1 }, { now: Number.NaN }, { bucketSeconds: 1 }]) {
      const r = buildTimeMetricsSeries(opts([row({ correlation_id: "a", occurred_at: "2026-06-24T01:00:00Z", metrics: [done(METRIC_TTD, 1)] })], bad));
      expect(r.buckets).toEqual([]);
      expect(r.incidentCount).toBe(0);
      expect(r.series).toHaveLength(2);
    }
  });

  it("skips phases the caller did not ask for", () => {
    const r = buildTimeMetricsSeries(opts([
      row({ correlation_id: "a", occurred_at: "2026-06-24T01:00:00Z", metrics: [done("tti", 5_000), blocked("ttc", "correlation_completed")] }),
    ]));
    expect(r.series[0].completeTotal).toBe(0);
    expect(r.incompleteIncidents).toBe(0);
    expect(r.blockers).toEqual([]);
  });
});

describe("missingEventPhrase", () => {
  it("speaks the lifecycle events in the operator's words", () => {
    expect(missingEventPhrase("recovered")).toBe("a service-recovery signal");
    expect(missingEventPhrase("closed")).toBe("ticket closure");
    expect(missingEventPhrase("root_domain_identified")).toBe("root / seam isolation");
  });
  it("never prints a raw underscore key or an empty phrase", () => {
    expect(missingEventPhrase("some_future_event")).toBe("some future event");
    expect(missingEventPhrase("")).toBe("a lifecycle event that was never recorded");
  });
});
