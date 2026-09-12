// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect, vi, beforeEach } from "vitest";

// #81 P3G — loadAppRca maps the /api/cloud/app-rca ClickHouse response into the
// AppRca view type. Mock the API so the mapping is tested without a backend.
const cloudAppRca = vi.fn();
vi.mock("../../services/api", () => ({ api: { cloudAppRca: (...a: unknown[]) => cloudAppRca(...a) } }));

import { loadAppRca } from "./api";

beforeEach(() => cloudAppRca.mockReset());

describe("loadAppRca (#81 P3G)", () => {
  it("maps a corroborated row (cross_plane 1 → true, sources passthrough)", async () => {
    cloudAppRca.mockResolvedValue({ data: [{
      correlation_id: "0244aabd", verdict_tier: "suspected", confidence: 0.5,
      signal_count: 3, state: "open", sources: ["probe", "cloud"], cross_plane: 1,
    }] });
    const r = await loadAppRca("checkout");
    expect(r).not.toBeNull();
    expect(r!.correlationId).toBe("0244aabd");
    expect(r!.verdictTier).toBe("suspected");
    expect(r!.signalCount).toBe(3);
    expect(r!.crossPlane).toBe(true);
    expect(r!.sources).toEqual(["probe", "cloud"]);
  });

  it("maps a single-plane row (cross_plane 0 → false)", async () => {
    cloudAppRca.mockResolvedValue({ data: [{
      correlation_id: "aa855349", verdict_tier: "undetermined", confidence: 0,
      signal_count: 2, state: "open", sources: ["cloud"], cross_plane: 0,
    }] });
    const r = await loadAppRca("billing");
    expect(r!.crossPlane).toBe(false);
    expect(r!.sources).toEqual(["cloud"]);
  });

  it("returns null when the app has no RCA (unknown stays first-class)", async () => {
    cloudAppRca.mockResolvedValue({ data: [] });
    expect(await loadAppRca("nope")).toBeNull();
  });

  it("does not call the API for an empty app id", async () => {
    expect(await loadAppRca("")).toBeNull();
    expect(cloudAppRca).not.toHaveBeenCalled();
  });

  it("tolerates a boolean cross_plane and missing sources", async () => {
    cloudAppRca.mockResolvedValue({ data: [{ correlation_id: "x", cross_plane: true }] });
    const r = await loadAppRca("x");
    expect(r!.crossPlane).toBe(true);
    expect(r!.sources).toEqual([]);
    expect(r!.verdictTier).toBe("undetermined"); // default when absent
  });
});
