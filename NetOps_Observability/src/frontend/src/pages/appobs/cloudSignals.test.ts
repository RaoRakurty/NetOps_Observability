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

import { loadHealthSignals, loadChangeEvents, loadEvidence, safeConsoleUrl } from "./api";

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
    expect(cloudHealth).toHaveBeenCalledWith("store-api", undefined, undefined);
  });

  it("threads the REAL range window to the read (Wave 2 #5)", async () => {
    cloudHealth.mockResolvedValue({ signals: [] });
    await loadHealthSignals("store-api", 168);
    expect(cloudHealth).toHaveBeenCalledWith("store-api", undefined, 168);
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
  it("maps grounded signals and the engine's own gaps (missing)", async () => {
    cloudEvidence.mockResolvedValue({
      objects: [{
        correlation_id: "96c16a06", verdict_tier: "suspected", confidence: 0.5,
        top_hypothesis: "sig.ent.cloud.app-dependency-down", signal_count: 254,
        state: "open", window_start: "2026-07-12T13:00:00.000Z",
        apps: ["booking-service", "journey"],
      }],
      evidence: [
        {
          time: "2026-07-12T13:10:00.000Z", category: "grounded", signal_type: "cloud_health",
          app: "booking-service", resource: "azure-host-01", source: "azure",
          confidence: "suspected", reason: "cloud_health · app_error …", grounded: true,
          rca_group: "96c16a06", evidence_ref: "sig-1",
        },
        {
          time: "2026-07-12T13:00:00.000Z", category: "missing", signal_type: "gap",
          app: "booking-service", resource: "—", source: "correlation engine",
          confidence: "unknown", reason: "single observer (cloud:…); need ≥2",
          grounded: false, rca_group: "96c16a06", evidence_ref: "—",
        },
      ],
    });
    const { objects, rows } = await loadEvidence();
    expect(objects[0].topHypothesis).toBe("sig.ent.cloud.app-dependency-down");
    expect(objects[0].apps).toEqual(["booking-service", "journey"]);
    expect(rows[0].category).toBe("grounded");
    expect(rows[0].grounded).toBe(true);
    expect(rows[1].category).toBe("missing");
    expect(rows[1].grounded).toBe(false);
  });

  // The console pivot (audit Wave 3 #9): cloud_ref must survive the mapping, and
  // only https URLs on the two provider console hosts may reach an <a href>.
  it("maps cloud_ref with its server-built console links", async () => {
    cloudEvidence.mockResolvedValue({
      objects: [],
      evidence: [{
        time: "2026-07-12T13:10:00.000Z", category: "grounded", signal_type: "cloud_health",
        app: "shared", resource: "correlix-app-host-01 (i-0448c)", source: "aws",
        confidence: "suspected", reason: "r", grounded: true,
        rca_group: "g", evidence_ref: "sig-1",
        cloud_ref: {
          provider: "aws", resource_id: "i-0448c", account: "945714973156", region: "us-west-2",
          console_url: "https://us-west-2.console.aws.amazon.com/ec2/home?region=us-west-2#InstanceDetails:instanceId=i-0448c",
          log_url: "https://us-west-2.console.aws.amazon.com/cloudtrailv2/home?region=us-west-2#/events/ev-1",
        },
      }],
    });
    const { rows } = await loadEvidence();
    expect(rows[0].cloudRef?.resourceId).toBe("i-0448c");
    expect(rows[0].cloudRef?.consoleUrl).toContain("console.aws.amazon.com");
    expect(rows[0].cloudRef?.logUrl).toContain("cloudtrailv2");
  });

  it("refuses console links off the provider hosts or off https", async () => {
    cloudEvidence.mockResolvedValue({
      objects: [],
      evidence: [{
        time: "t", category: "grounded", signal_type: "cloud_health", app: "a",
        resource: "r", source: "aws", confidence: "suspected", reason: "r",
        grounded: true, rca_group: "g", evidence_ref: "e",
        cloud_ref: {
          provider: "aws", resource_id: "i-1",
          console_url: "https://evil.example.com/phish",
          log_url: "javascript:alert(1)",
        },
      }],
    });
    const { rows } = await loadEvidence();
    expect(rows[0].cloudRef?.consoleUrl).toBe("");
    expect(rows[0].cloudRef?.logUrl).toBe("");
  });

  // The engine records no contradicting/discriminating role — a category we did not
  // measure must never be claimed by the UI.
  it("never invents an evidence category", async () => {
    cloudEvidence.mockResolvedValue({ objects: [], evidence: [{ category: "contradicting" }] });
    const { rows } = await loadEvidence();
    expect(rows[0].category).toBe("grounded");
  });

  it("returns an empty ledger when the engine grounded nothing", async () => {
    cloudEvidence.mockResolvedValue({ objects: [], evidence: [] });
    const { objects, rows } = await loadEvidence("store-api");
    expect(objects).toEqual([]);
    expect(rows).toEqual([]);
    expect(cloudEvidence).toHaveBeenCalledWith("store-api", undefined, undefined);
  });

  it("threads the REAL range window to the ledger read (Wave 2 #5)", async () => {
    cloudEvidence.mockResolvedValue({ objects: [], evidence: [] });
    await loadEvidence(undefined, 168);
    expect(cloudEvidence).toHaveBeenCalledWith(undefined, undefined, 168);
  });
});

// Zero-trust gate on server-built links: only https on the three console hosts.
describe("safeConsoleUrl", () => {
  it("admits only https on the three console hosts", () => {
    expect(safeConsoleUrl("https://portal.azure.com/#resource/subscriptions/x")).toContain("portal.azure.com");
    expect(safeConsoleUrl("https://us-west-2.console.aws.amazon.com/ec2/home")).toContain("aws.amazon.com");
    // GCP console + Logs Explorer pivots (2026-07 review: these were dropped).
    expect(safeConsoleUrl("https://console.cloud.google.com/compute/instancesDetail/zones/us-west1-a/instances/x"))
      .toContain("console.cloud.google.com");
    expect(safeConsoleUrl("https://console.cloud.google.com/logs/query;query=insertId%3D%22abc%22?project=p"))
      .toContain("console.cloud.google.com");
    expect(safeConsoleUrl("http://portal.azure.com/#resource/x")).toBe("");
    expect(safeConsoleUrl("https://portal.azure.com.evil.io/x")).toBe("");
    expect(safeConsoleUrl("https://fakeconsole.aws.amazon.com.evil.io/x")).toBe("");
    expect(safeConsoleUrl("https://console.cloud.google.com.evil.io/x")).toBe("");
    expect(safeConsoleUrl("https://evilconsole.cloud.google.com/x")).toBe("");
    expect(safeConsoleUrl("not a url")).toBe("");
    expect(safeConsoleUrl(undefined)).toBe("");
  });
});
