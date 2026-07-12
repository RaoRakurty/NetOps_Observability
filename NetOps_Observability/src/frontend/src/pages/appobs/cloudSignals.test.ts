import { describe, it, expect, vi, beforeEach } from "vitest";

// #81 P3H — the Health / Changes / Evidence tabs render ONLY real cloud telemetry.
// These lock the mapping from the live /api/cloud/{health,changes,evidence} rows into
// the view types, and the honest-empty contract: no signals ⇒ no rows, never samples.
const cloudHealth = vi.fn();
const cloudChanges = vi.fn();
const cloudEvidence = vi.fn();
vi.mock("../../services/api", () => ({
  api: {
    cloudHealth: (...a: unknown[]) => cloudHealth(...a),
    cloudChanges: (...a: unknown[]) => cloudChanges(...a),
    cloudEvidence: (...a: unknown[]) => cloudEvidence(...a),
  },
}));

import { loadHealthSignals, loadChangeEvents, loadEvidence } from "./api";

beforeEach(() => {
  cloudHealth.mockReset();
  cloudChanges.mockReset();
  cloudEvidence.mockReset();
});

describe("loadHealthSignals", () => {
  it("maps a real cloud_health signal (Azure journey failure)", async () => {
    cloudHealth.mockResolvedValue({ signals: [{
      time: "2026-07-12T08:34:15.000Z", app: "journey", resource: "azure-host-01",
      signal: "cloud_health", state: "down", metric: "journey_failed", current: "1",
      baseline: "—", severity: "critical", source: "azure",
    }] });
    const rows = await loadHealthSignals();
    expect(rows).toHaveLength(1);
    expect(rows[0].app).toBe("journey");
    expect(rows[0].state).toBe("down");
    expect(rows[0].severity).toBe("critical");
    expect(rows[0].baseline).toBe("—"); // not measured, never a fabricated 0
  });

  it("passes the app filter through and returns [] when nothing landed", async () => {
    cloudHealth.mockResolvedValue({ signals: [] });
    expect(await loadHealthSignals("store-api")).toEqual([]);
    expect(cloudHealth).toHaveBeenCalledWith("store-api");
  });

  it("defends the enums — an unknown state/severity never crashes a render", async () => {
    cloudHealth.mockResolvedValue({ signals: [{ state: "weird", severity: "weird" }] });
    const rows = await loadHealthSignals();
    expect(rows[0].state).toBe("unknown");
    expect(rows[0].severity).toBe("info");
  });
});

describe("loadChangeEvents", () => {
  it("maps a real CloudTrail change (security-group revoke)", async () => {
    cloudChanges.mockResolvedValue({ changes: [{
      time: "2026-07-12T13:37:32.000Z", app: "—", resource: "sg-01",
      change_type: "security_policy_change", actor: "iam:user/correlix",
      source: "ec2.amazonaws.com", confidence: "confirmed", related_symptoms: [],
    }] });
    const rows = await loadChangeEvents();
    expect(rows[0].changeType).toBe("security_policy_change");
    expect(rows[0].actor).toBe("iam:user/correlix");
    expect(rows[0].confidence).toBe("confirmed");
    // symptoms are NOT invented — the engine does not record them on a change
    expect(rows[0].relatedSymptoms).toEqual([]);
  });

  it("degrades an unknown change type instead of guessing one", async () => {
    cloudChanges.mockResolvedValue({ changes: [{ change_type: "teleportation" }] });
    expect((await loadChangeEvents())[0].changeType).toBe("unknown");
  });

  it("returns [] when no change landed", async () => {
    cloudChanges.mockResolvedValue({ changes: [] });
    expect(await loadChangeEvents()).toEqual([]);
  });
});

describe("loadEvidence", () => {
  it("maps grounded signals (supporting) and the engine's own gaps (missing)", async () => {
    cloudEvidence.mockResolvedValue({
      objects: [{
        correlation_id: "96c16a06", verdict_tier: "suspected", confidence: 0.5,
        top_hypothesis: "sig.ent.cloud.app-dependency-down", signal_count: 254,
        state: "open", window_start: "2026-07-12T13:00:00.000Z",
        apps: ["booking-service", "journey"],
      }],
      evidence: [
        {
          time: "2026-07-12T13:10:00.000Z", category: "supporting", signal_type: "cloud_health",
          app: "booking-service", resource: "azure-host-01", source: "azure",
          confidence: "suspected", reason: "cloud_health · app_error …", used_in_verdict: true,
          rca_group: "96c16a06", evidence_ref: "sig-1",
        },
        {
          time: "2026-07-12T13:00:00.000Z", category: "missing", signal_type: "gap",
          app: "booking-service", resource: "—", source: "correlation engine",
          confidence: "unknown", reason: "single observer (cloud:…); need ≥2",
          used_in_verdict: false, rca_group: "96c16a06", evidence_ref: "—",
        },
      ],
    });
    const { objects, rows } = await loadEvidence();
    expect(objects[0].topHypothesis).toBe("sig.ent.cloud.app-dependency-down");
    expect(objects[0].apps).toEqual(["booking-service", "journey"]);
    expect(rows[0].category).toBe("supporting");
    expect(rows[0].usedInVerdict).toBe(true);
    expect(rows[1].category).toBe("missing");
    expect(rows[1].usedInVerdict).toBe(false);
  });

  // The engine records no contradicting/discriminating role — a category we did not
  // measure must never be claimed by the UI.
  it("never invents an evidence category", async () => {
    cloudEvidence.mockResolvedValue({ objects: [], evidence: [{ category: "contradicting" }] });
    const { rows } = await loadEvidence();
    expect(rows[0].category).toBe("supporting");
  });

  it("returns an empty ledger when the engine grounded nothing", async () => {
    cloudEvidence.mockResolvedValue({ objects: [], evidence: [] });
    const { objects, rows } = await loadEvidence("store-api");
    expect(objects).toEqual([]);
    expect(rows).toEqual([]);
    expect(cloudEvidence).toHaveBeenCalledWith("store-api");
  });
});
