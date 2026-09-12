// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// rcaOverlay.test.ts — the raw-status → canonical RcaOverlayState normaliser and
// the visual-map invariants. Guards the honesty contract: suspected ≠ confirmed,
// missing_evidence is hollow, internal_only is customer-hidden, unknown strings
// never fabricate a verdict.

import { describe, it, expect } from "vitest";
import { normalizeRcaState, RCA_OVERLAY, RCA_OVERLAY_ORDER } from "./rcaOverlay";

describe("normalizeRcaState", () => {
  it("maps the backend's status/state strings to canonical states", () => {
    expect(normalizeRcaState("suspected")).toBe("suspected_down");
    expect(normalizeRcaState("suspected_down")).toBe("suspected_down");
    expect(normalizeRcaState("confirmed")).toBe("confirmed_down");
    expect(normalizeRcaState("down")).toBe("confirmed_down");
    expect(normalizeRcaState("healthy")).toBe("observed");
    expect(normalizeRcaState("degraded")).toBe("degraded");
    expect(normalizeRcaState("missing_evidence")).toBe("missing_evidence");
    expect(normalizeRcaState("internal")).toBe("internal_only");
  });

  it("is case/whitespace tolerant", () => {
    expect(normalizeRcaState("  Suspected_Down ")).toBe("suspected_down");
  });

  it("returns undefined for empty / unrecognised input (never fabricates a verdict)", () => {
    expect(normalizeRcaState(undefined)).toBeUndefined();
    expect(normalizeRcaState("")).toBeUndefined();
    expect(normalizeRcaState("wat")).toBeUndefined();
  });
});

describe("RCA_OVERLAY map invariants", () => {
  it("keeps suspected and confirmed visually distinct", () => {
    expect(RCA_OVERLAY.suspected_down.dash).toBeDefined(); // dashed = not certain
    expect(RCA_OVERLAY.confirmed_down.dash).toBeUndefined(); // solid = confirmed
    expect(RCA_OVERLAY.suspected_down.glyph).not.toBe(RCA_OVERLAY.confirmed_down.glyph);
  });

  it("missing_evidence is hollow; internal_only is customer-hidden", () => {
    expect(RCA_OVERLAY.missing_evidence.hollow).toBe(true);
    expect(RCA_OVERLAY.internal_only.customerHidden).toBe(true);
  });

  it("the legend order is customer-visible states only", () => {
    expect(RCA_OVERLAY_ORDER).not.toContain("internal_only");
    for (const s of RCA_OVERLAY_ORDER) expect(RCA_OVERLAY[s].customerHidden).toBe(false);
  });
});
