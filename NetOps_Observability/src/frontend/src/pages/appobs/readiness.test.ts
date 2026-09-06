// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// readiness.test.ts — the honest data-readiness core (#81 P3F+1). Proves the
// trust rules: only inventory is real today, missing sources are "off" not
// healthy, missing values are "not measured" not 0, and no label ever says "mock".

import { describe, it, expect } from "vitest";
import {
  deriveDataMode, DATA_MODE_LABEL, deriveReadiness, summarize, deriveScope,
  deriveConnectorKind,
  getMeasurementState, isMeasured, deriveHealthFromAvailableSignals, freshnessLabel,
  sinceLabel, SOURCE_TYPES,
} from "./readiness";

describe("data mode", () => {
  it("is live only with a real connector", () => {
    expect(deriveDataMode({ inventoryCount: 5, connector: "live" })).toBe("live");
  });
  it("is demo when fixtures are present (no live connector)", () => {
    expect(deriveDataMode({ inventoryCount: 5, connector: "fixture" })).toBe("demo");
  });
  it("is empty when nothing is connected", () => {
    expect(deriveDataMode({ inventoryCount: 0, connector: "none" })).toBe("empty");
  });
  it("never uses the word 'mock' in any label", () => {
    for (const label of Object.values(DATA_MODE_LABEL)) {
      expect(label.toLowerCase()).not.toContain("mock");
    }
  });
});

describe("deriveConnectorKind — provenance is measured, default-closed (#105)", () => {
  const live = { kind: "live", resource_count: 3 };
  const fixture = { kind: "fixture", resource_count: 1 };
  it("is live when every contributing inventory file is live-poller written", () => {
    expect(deriveConnectorKind([live, { kind: "live", resource_count: 2 }], 5)).toBe("live");
  });
  it("one hand fixture in the mix demotes the whole view (never overclaim live)", () => {
    expect(deriveConnectorKind([live, fixture], 4)).toBe("fixture");
  });
  it("a backend without provenance info keeps the old honest assumption", () => {
    expect(deriveConnectorKind(undefined, 4)).toBe("fixture");
    expect(deriveConnectorKind([], 4)).toBe("fixture");
  });
  it("empty files carry no provenance weight", () => {
    expect(deriveConnectorKind([{ kind: "fixture", resource_count: 0 }, live], 3)).toBe("live");
  });
  it("no inventory ⇒ none, regardless of stamps", () => {
    expect(deriveConnectorKind([live], 0)).toBe("none");
  });
});

describe("deriveReadiness — measured, never assumed", () => {
  it("without an ingestion reading, only inventory is real (honest fallback)", () => {
    const r = deriveReadiness({ inventoryCount: 12, inventoryError: false });
    expect(r.find((x) => x.sourceType === "inventory")?.status).toBe("flowing");
    expect(r.filter((x) => x.sourceType !== "inventory").every((x) => x.status === "off")).toBe(true);
    expect(r).toHaveLength(SOURCE_TYPES.length);
  });
  it("reports a source that IS flowing (the hard-coded 'off' understated a live stack)", () => {
    const r = deriveReadiness({
      inventoryCount: 9, inventoryError: false,
      ingestion: [
        { source_type: "flow_logs", status: "flowing", volume: 712, last_seen_iso: "2026-07-12T08:00:00Z" },
        { source_type: "cloud_health", status: "flowing", volume: 151 },
        { source_type: "seam_data", status: "flowing", volume: 2 },
        { source_type: "change_audit", status: "stale", volume: 75 },
      ],
    });
    const by = (t: string) => r.find((x) => x.sourceType === t);
    expect(by("flow_logs")?.status).toBe("flowing");
    expect(by("flow_logs")?.volume).toBe(712);
    expect(by("cloud_health")?.status).toBe("flowing");
    expect(by("seam_data")?.status).toBe("flowing");
    expect(by("change_audit")?.status).toBe("stale");
    // a source with no producer is still honestly off
    expect(by("traces")?.status).toBe("off");
    expect(r).toHaveLength(SOURCE_TYPES.length);
  });
  it("inventory no_data when empty (honest, not healthy)", () => {
    const r = deriveReadiness({ inventoryCount: 0, inventoryError: false });
    expect(r.find((x) => x.sourceType === "inventory")?.status).toBe("no_data");
  });
  it("inventory off on load error", () => {
    const r = deriveReadiness({ inventoryCount: 0, inventoryError: true });
    expect(r.find((x) => x.sourceType === "inventory")?.status).toBe("off");
  });
});

describe("summarize", () => {
  it("counts flowing/off and carries account count", () => {
    const r = deriveReadiness({ inventoryCount: 3, inventoryError: false, lastSyncIso: "2026-06-25T00:00:00Z" });
    const s = summarize(r, 2);
    expect(s.connectedAccounts).toBe(2);
    expect(s.flowing).toBe(1); // only inventory
    expect(s.off).toBe(SOURCE_TYPES.length - 1);
    expect(s.lastSyncIso).toBe("2026-06-25T00:00:00Z");
  });
});

describe("deriveScope", () => {
  it("shows a single value verbatim and many as a count", () => {
    const s = deriveScope(
      [
        { provider: "aws", account: "111", region: "us-east-1", env: "prod" },
        { provider: "aws", account: "222", region: "us-west-2", env: "prod" },
      ],
      "Retail-US",
    );
    expect(s.tenant).toBe("Retail-US");
    expect(s.provider).toBe("AWS"); // single provider, upper-cased
    expect(s.account).toBe("2 accounts"); // many
    expect(s.region).toBe("2 regions");
    expect(s.env).toBe("prod"); // single
  });
  it("handles an empty inventory honestly", () => {
    const s = deriveScope([], "t1");
    expect(s.provider).toBe("—");
    expect(s.account).toBe("—");
  });
});

describe("measurement state", () => {
  it("flowing/stale are measured; off/no_data/undefined are not", () => {
    expect(isMeasured("flowing")).toBe(true);
    expect(isMeasured("stale")).toBe(true);
    expect(isMeasured("off")).toBe(false);
    expect(isMeasured(undefined)).toBe(false);
  });
  it("maps status to a display state", () => {
    expect(getMeasurementState("flowing")).toBe("ok");
    expect(getMeasurementState("stale")).toBe("stale");
    expect(getMeasurementState("permission_denied")).toBe("permission_denied");
    expect(getMeasurementState("off")).toBe("not_measured");
    expect(getMeasurementState("no_data")).toBe("not_measured");
  });
});

describe("deriveHealthFromAvailableSignals — never fake healthy", () => {
  it("returns raw health when the health source is measured", () => {
    expect(deriveHealthFromAvailableSignals("healthy", { health: "flowing", anyMeasured: true })).toBe("healthy");
  });
  it("cloud health off + other signals ⇒ partial data, not healthy", () => {
    expect(deriveHealthFromAvailableSignals("healthy", { health: "off", anyMeasured: true })).toBe("partial");
  });
  it("cloud health off + nothing measured ⇒ not measured", () => {
    expect(deriveHealthFromAvailableSignals("healthy", { health: "off", anyMeasured: false })).toBe("not_measured");
  });
  it("a real problem on another signal is preserved even with no health source", () => {
    expect(deriveHealthFromAvailableSignals("down", { health: "off", anyMeasured: false })).toBe("down");
    expect(deriveHealthFromAvailableSignals("degraded", { health: "off", anyMeasured: true })).toBe("degraded");
  });
});

describe("freshnessLabel", () => {
  const now = new Date("2026-06-25T12:00:00Z").getTime();
  it("renders seconds / minutes / dash", () => {
    expect(freshnessLabel(undefined, now)).toBe("—");
    expect(freshnessLabel("2026-06-25T11:59:18Z", now)).toBe("42s ago");
    expect(freshnessLabel("2026-06-25T11:57:00Z", now)).toBe("3m ago");
    expect(freshnessLabel("2026-06-25T11:59:59Z", now)).toBe("just now");
  });
});

// Wave 2 #4 — poller-reported failure context flows through to the chip model,
// and the "since" wording matches the operator question ("denied since Tuesday").
describe("permission-denied context (Wave 2 #4)", () => {
  it("deriveReadiness carries detail + since for a denied source", () => {
    const r = deriveReadiness({
      inventoryCount: 1, inventoryError: false,
      ingestion: [{
        source_type: "flow_logs", status: "permission_denied",
        detail: "IAM denied logs:FilterLogEvents", since_iso: "2026-06-23T08:00:00Z",
      }],
    });
    const flow = r.find((x) => x.sourceType === "flow_logs")!;
    expect(flow.status).toBe("permission_denied");
    expect(flow.lastError).toBe("IAM denied logs:FilterLogEvents");
    expect(flow.sinceIso).toBe("2026-06-23T08:00:00Z");
    // …and the summary tile counts it (the "Permission errors" card).
    expect(summarize(r, 1).permissionErrors).toBe(1);
  });
  it("sinceLabel: weekday inside a week, date beyond, empty for garbage", () => {
    const now = new Date("2026-07-16T12:00:00Z").getTime(); // a Thursday
    expect(sinceLabel("2026-07-14T08:00:00Z", now)).toBe("since Tuesday");
    expect(sinceLabel("2026-07-01T08:00:00Z", now)).toBe("since Jul 1");
    expect(sinceLabel(undefined, now)).toBe("");
    expect(sinceLabel("not-a-date", now)).toBe("");
    expect(sinceLabel("2026-07-16T09:30:00Z", now)).toMatch(/^since \d/);
  });
});
