// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// stackCollection.test.ts — the model behind Stack Health's Collection section.
//
// This is where the retired collection-pipeline board's facts landed
// (Troubleshooting had a second section, and a `?section=pipeline` bookmark
// reopened it on every refresh — owner, 2026-09-07). The board charted four
// collector series; the section reads them now, so the rules that turn a
// PromQL payload into rows are pinned here, without a DOM.
//
// The rule that matters: ABSENT IS NOT ZERO. A metric family that was never
// scraped yields null and renders "—"; a zero on this section is a collector
// that reported zero.

import { describe, it, expect } from "vitest";
import type { PromInstantSeries } from "../services/api";
import {
  COLLECTION_QUERIES,
  collectorNames,
  collectorRows,
  flowSourceRows,
  flowsTotal,
  instantValue,
  scalarValue,
} from "./stackCollection";

const series = (collector: string, value: number): PromInstantSeries =>
  ({ metric: { collector }, value: [1_700_000_000, String(value)] });

describe("instantValue / scalarValue", () => {
  it("reads the collector's own value", () => {
    expect(instantValue([series("snmpmetrics", 12), series("gnmi", 3)], "gnmi")).toBe(3);
  });

  it("is null for a collector the family never reported", () => {
    expect(instantValue([series("snmpmetrics", 12)], "gnmi")).toBeNull();
    expect(instantValue(undefined, "gnmi")).toBeNull();
  });

  it("is null for a value that is not a number (never 0)", () => {
    expect(instantValue([{ metric: { collector: "x" }, value: [1, "NaN"] }], "x")).toBeNull();
    expect(scalarValue([{ metric: {}, value: [1, "+Inf"] }])).toBeNull();
    expect(scalarValue([])).toBeNull();
    expect(scalarValue(undefined)).toBeNull();
  });

  it("reads the single scalar of an aggregate", () => {
    expect(scalarValue([{ metric: {}, value: [1, "41"] }])).toBe(41);
  });

  it("keeps a reported zero as zero", () => {
    expect(instantValue([series("snmp", 0)], "snmp")).toBe(0);
    expect(scalarValue([{ metric: {}, value: [1, "0"] }])).toBe(0);
  });
});

describe("collectorNames", () => {
  it("unions every family and sorts, so a collector that only polls still lists", () => {
    expect(collectorNames([series("snmp", 1)], [series("gnmi", 1)], [series("snmp", 1)]))
      .toEqual(["gnmi", "snmp"]);
  });

  it("ignores series with no collector label", () => {
    expect(collectorNames([{ metric: {}, value: [1, "1"] }])).toEqual([]);
  });
});

describe("collectorRows", () => {
  it("carries configured, reachable and poll time per collector", () => {
    const rows = collectorRows(
      [series("snmpmetrics", 10)],
      [series("snmpmetrics", 10)],
      [series("snmpmetrics", 42)],
    );
    expect(rows).toEqual([
      { collector: "snmpmetrics", configured: 10, reachable: 10, pollMs: 42, status: "up" },
    ]);
  });

  it.each([
    [10, 10, "up"],
    [10, 4, "degraded"],
    [10, 0, "down"],
  ] as const)("configured %i reachable %i → %s", (conf, reach, status) => {
    expect(collectorRows([series("c", conf)], [series("c", reach)], []) [0].status).toBe(status);
  });

  // A collector that reported no targets has not FAILED — it has nothing to
  // reach. Painting it red would send an operator after a healthy collector.
  it("is 'unknown', not 'down', when there is nothing to judge", () => {
    expect(collectorRows([series("c", 0)], [series("c", 0)], [])[0].status).toBe("unknown");
    expect(collectorRows([], [series("c", 3)], [])[0].status).toBe("unknown");
    expect(collectorRows([series("c", 3)], [], [])[0].status).toBe("unknown");
  });

  it("leaves an unreported poll time null rather than 0 ms", () => {
    expect(collectorRows([series("c", 1)], [series("c", 1)], [])[0].pollMs).toBeNull();
  });
});

describe("flowSourceRows", () => {
  it("normalises the ClickHouse rows, largest first", () => {
    expect(flowSourceRows([
      { flow_type: "sflow", flows: 5, exporters: 1 },
      { flow_type: "netflow", flows: 90, exporters: 3 },
    ])).toEqual([
      { flowType: "NETFLOW", flows: 90, exporters: 3 },
      { flowType: "SFLOW", flows: 5, exporters: 1 },
    ]);
  });

  it("survives a payload that is not a list of rows", () => {
    expect(flowSourceRows(undefined)).toEqual([]);
    expect(flowSourceRows(null)).toEqual([]);
    expect(flowSourceRows({})).toEqual([]);
    expect(flowSourceRows([{ flows: 1 }])).toEqual([]);
    expect(flowSourceRows([{ flow_type: "ipfix" }]))
      .toEqual([{ flowType: "IPFIX", flows: 0, exporters: 0 }]);
  });

  it("totals the records across sources", () => {
    expect(flowsTotal(flowSourceRows([
      { flow_type: "netflow", flows: 90, exporters: 3 },
      { flow_type: "sflow", flows: 5, exporters: 1 },
    ]))).toBe(95);
    expect(flowsTotal([])).toBe(0);
  });
});

describe("COLLECTION_QUERIES", () => {
  // The board's four charts became three aggregated instant reads. Aggregating
  // server-side keeps the section one row per collector instead of one per
  // target — and `or vector(0)` keeps the two fleet counts honest on a fresh
  // install where the family has no series yet.
  it("aggregates by collector, so a row is a collector", () => {
    for (const q of [COLLECTION_QUERIES.configured, COLLECTION_QUERIES.reachable, COLLECTION_QUERIES.poll]) {
      expect(q).toContain("by (collector)");
    }
  });

  it("reads the same series the retired board charted", () => {
    expect(COLLECTION_QUERIES.configured).toContain("collector_targets");
    expect(COLLECTION_QUERIES.reachable).toContain("collector_targets_reachable");
    expect(COLLECTION_QUERIES.poll).toContain("collector_poll_duration_ms");
    expect(COLLECTION_QUERIES.monitored).toContain('collector="snmpmetrics"');
    expect(COLLECTION_QUERIES.snmpReachable).toContain('collector=~"snmp.*"');
  });
});
