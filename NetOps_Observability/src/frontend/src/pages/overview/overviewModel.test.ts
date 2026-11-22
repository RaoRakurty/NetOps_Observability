// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import { corrObject } from "../../test/factories";
import type { HealthScoreResp } from "../../services/api";
import { attentionOf, customerProblems, impactOf, internalObjects, siteHealthRows, siteState, topProblem } from "./overviewModel";

const health = (o: Partial<HealthScoreResp> = {}): HealthScoreResp => ({
  scope: "global", score: 92, band: "healthy", confidence: "high", coverage_status: "OK",
  signal_classes_live: ["availability"], contributions: [], ...o,
} as HealthScoreResp);

describe("customerProblems / internalObjects", () => {
  it("keeps graded customer cases and drops undetermined and the platform's own", () => {
    const objs = [
      corrObject({ correlation_id: "a", verdict_tier: "confirmed", affected: '{"devices":["edge-1"]}' }),
      corrObject({ correlation_id: "b", verdict_tier: "undetermined", affected: '{"devices":["edge-2"]}' }),
      corrObject({ correlation_id: "c", verdict_tier: "suspected", affected: '{"devices":["clickhouse"]}' }),
    ];
    expect(customerProblems(objs).map((o) => o.correlation_id)).toEqual(["a"]);
    expect(internalObjects(objs).map((o) => o.correlation_id)).toEqual(["c"]);
    expect(customerProblems(undefined)).toEqual([]);
  });
});

describe("topProblem", () => {
  it("leads with the first confirmed case, else the first graded one", () => {
    const s = corrObject({ correlation_id: "s", verdict_tier: "suspected" });
    const c = corrObject({ correlation_id: "c", verdict_tier: "confirmed" });
    expect(topProblem([s, c])?.correlation_id).toBe("c");
    expect(topProblem([s])?.correlation_id).toBe("s");
    expect(topProblem([])).toBeUndefined();
  });
});

describe("impactOf", () => {
  it("counts devices from devices, path ends and interface keys, sites, and health contributors — never platform infra", () => {
    const objs = [corrObject({
      verdict_tier: "confirmed",
      affected: JSON.stringify({ devices: ["edge-1"], paths: ["edge-1->core-2"], interfaces: ["10.0.0.9:if3"], sites: ["hq"] }),
    })];
    const h = health({ contributions: [{ entity: "sw-7", points: 6, reason: "cpu", signal_class: "device_health" } as never, { entity: "clickhouse", points: 3, reason: "x", signal_class: "device_health" } as never] });
    const { devices, sites } = impactOf(objs, h);
    expect([...devices].sort()).toEqual(["10.0.0.9", "core-2", "edge-1", "sw-7"]);
    expect([...sites]).toEqual(["hq"]);
  });
});

describe("attentionOf — 'quiet' only when health agrees", () => {
  it("is a problem when a case is open", () => {
    expect(attentionOf([corrObject({ verdict_tier: "confirmed" })], health())).toBe("problem");
  });
  it("never says quiet while health is degraded with no confirmed cause", () => {
    expect(attentionOf([], health({ band: "degraded", score: 40 }))).toBe("unhealthy");
  });
  it("says insufficient when health cannot be scored", () => {
    expect(attentionOf([], health({ coverage_status: "INSUFFICIENT_TELEMETRY" }))).toBe("insufficient");
    expect(attentionOf([], health({ score: null }))).toBe("insufficient");
  });
  it("is quiet only with no case and healthy", () => {
    expect(attentionOf([], health())).toBe("quiet");
  });
  it("is reading until both answers arrive", () => {
    expect(attentionOf(undefined, health())).toBe("reading");
    expect(attentionOf([], undefined)).toBe("reading");
  });
});

describe("siteHealthRows", () => {
  it("classifies a site", () => {
    expect(siteState({ devices: 0, up: 0, down: 0 })).toBe("empty");
    expect(siteState({ devices: 3, up: 0, down: 3 })).toBe("down");
    expect(siteState({ devices: 3, up: 2, down: 1 })).toBe("partial");
    expect(siteState({ devices: 3, up: 2, down: 0 })).toBe("partial"); // one unknown is not "all up"
    expect(siteState({ devices: 3, up: 3, down: 0 })).toBe("up");
  });

  it("orders worst first and says how many there are when it truncates", () => {
    const site = (name: string, devices: number, up: number, down: number) =>
      ({ name, slug: name.toLowerCase(), lat: 0, lng: 0, has_coords: false, devices, up, down });
    const { rows, total } = siteHealthRows([
      site("HQ", 10, 10, 0), site("Branch 2", 4, 0, 4), site("Lab", 0, 0, 0), site("Branch 1", 5, 3, 2), site("Branch 3", 5, 4, 1),
    ], 3);
    expect(total).toBe(5);
    expect(rows.map((r) => r.name)).toEqual(["Branch 2", "Branch 1", "Branch 3"]);
    expect(rows[1]).toMatchObject({ devices: 5, up: 3, down: 2, unknown: 0, state: "partial" });
  });

  it("treats a missing list as empty", () => {
    expect(siteHealthRows(undefined)).toEqual({ rows: [], total: 0 });
  });
});
