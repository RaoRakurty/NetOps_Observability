import { describe, it, expect } from "vitest";
import { buildRcaCase, EXAMPLE_CASE } from "./rcaCase";
import { signal, timeline, corrObject } from "../../test/factories";

// These tests pin the ADAPTER (buildRcaCase) — the wiring between a real
// correlation object/timeline and every widget in the RCA workspace. They guard:
// data correctness per widget, honest degradation (suspected vs confirmed),
// and the copy rules (no product name, no overclaim, suspected ≠ confirmed).

const ALL_PLANES = 4; // device_telemetry · control_plane · passive_flow · active_probe

describe("buildRcaCase — suspected single-signal routing object", () => {
  const tl = timeline({
    verdict_tier: "suspected",
    top_hypothesis: "undetermined",
    signals: [signal({
      kind: "bgp_state_anomaly", modality_class: "control_plane",
      entity_id: "wan-r2:192.168.100.5", attrs: '{"peer":"192.168.100.5"}', attached: true,
    })],
  });
  const obj = corrObject({ verdict_tier: "suspected", state: "open", signal_count: 1 });
  const c = buildRcaCase(tl, obj, {}, "NetOps", []);

  it("titles it factually by observed condition (no speculative 'Possible …')", () => {
    expect(c.title).toBe("Routing adjacency change");
    expect(c.title).not.toMatch(/^Possible/);
  });

  it("status pills say NOT CONFIRMED · Low · Under review", () => {
    const texts = c.pills.map((p) => p.text);
    expect(texts).toContain("NOT CONFIRMED");
    expect(texts).toContain("Confidence: Low");
    expect(texts).toContain("RCA state: Under review");
    expect(texts).not.toContain("✓ CONFIRMED");
  });

  it("decision is HOLD, not escalate", () => {
    expect(c.decision.tone).toBe("");
    expect(c.decision.text).toMatch(/^HOLD/);
  });

  it("impact reports no confirmed customer impact + resolves device/peer", () => {
    expect(c.impact[0]).toMatchObject({ k: "Impact", v: "No confirmed customer impact" });
    expect(c.impact.find((r) => r.k === "Affected device")?.v).toBe("wan-r2");
    expect(c.impact.find((r) => r.k === "Affected peer")?.v).toBe("192.168.100.5");
    expect(c.impact.find((r) => r.k === "Scope type")?.v).toBe("Routing adjacency");
  });

  it("summary names device + peer and states impact not confirmed", () => {
    expect(c.summary).toContain("wan-r2");
    expect(c.summary).toContain("192.168.100.5");
    expect(c.summary).toMatch(/not confirmed/i);
  });

  it("confidence ladder stops at Suspected (Probable/Confirmed locked)", () => {
    expect(c.ladder).toHaveLength(4);
    expect(c.ladder[0].state).toBe("done");      // Observed
    expect(c.ladder[1].state).toBe("active");     // Suspected
    expect(c.ladder[2].state).toBe("next");       // Probable (locked)
    expect(c.ladder[3].state).toBe("next");       // Confirmed (locked)
    expect(c.ladder[3].label).toContain("🔒");
  });

  it("evidence matrix has one card per plane; routing is the main card", () => {
    expect(c.evidence).toHaveLength(ALL_PLANES);
    const routing = c.evidence.find((e) => e.title === "Routing / link");
    expect(routing?.variant).toBe("main");
    const device = c.evidence.find((e) => e.title === "Device health");
    expect(device?.variant).toBe("missing");
    expect(device?.pill.text).toBe("Not observed");
  });

  it("timeline shows ALL standard lanes (empty ones included)", () => {
    expect(c.timeline).toHaveLength(ALL_PLANES);
    const routing = c.timeline.find((l) => l.label === "Routing / link");
    expect(routing?.markers.length).toBeGreaterThan(0);
    const flow = c.timeline.find((l) => l.label === "Traffic flow");
    expect(flow?.markers).toHaveLength(0); // present but empty → shows what's missing
  });

  it("ticket is not opened while impact is unconfirmed", () => {
    expect(c.ticket.callout.strong).toMatch(/Not opened/i);
    expect(c.ticket.rows.find((r) => r.k === "Ticket state")?.v).toBe("Not opened");
  });

  it("next actions include a HOLD step", () => {
    expect(c.nextActions.some((a) => a.badge === "HOLD")).toBe(true);
  });

  it("is not flagged synthetic and exposes a debug model", () => {
    expect(c.synthetic).toBe(false);
    expect(c.debug.model).toBeTruthy();
  });
});

describe("buildRcaCase — confirmed multi-plane object", () => {
  const tl = timeline({
    verdict_tier: "confirmed",
    top_hypothesis: "bgp-flap",
    signals: [
      signal({ kind: "bgp_state_anomaly", modality_class: "control_plane", entity_id: "wan-r2:192.168.100.5", attrs: '{"peer":"192.168.100.5"}', ts: "2026-06-16 19:25:06" }),
      signal({ kind: "device_resource_anomaly", modality_class: "device_telemetry", entity_id: "wan-r2", ts: "2026-06-16 19:25:10", is_trigger: false }),
      signal({ kind: "flow_volume_anomaly", modality_class: "passive_flow", entity_id: "wan-r2", ts: "2026-06-16 19:25:20", is_trigger: false }),
    ],
  });
  const obj = corrObject({ verdict_tier: "confirmed", top_hypothesis: "bgp-flap", state: "open", signal_count: 3 });
  const c = buildRcaCase(tl, obj, {}, "NetOps", ["Check wan-r2 interface counters"]);

  it("status pills say CONFIRMED · High", () => {
    const texts = c.pills.map((p) => p.text);
    expect(texts).toContain("✓ CONFIRMED");
    expect(texts).toContain("Confidence: High");
  });

  it("decision opens an incident on confirmed independent evidence", () => {
    expect(c.decision.tone).toBe("confirmed");
    expect(c.decision.text).toMatch(/^OPEN INCIDENT/);
    expect(c.decision.text).toMatch(/confirmed by independent evidence/i);
  });

  it("impact reports confirmed customer impact", () => {
    expect(c.impact[0].v).toBe("Confirmed customer impact");
  });

  it("ladder reaches Confirmed", () => {
    expect(c.ladder[2].state).toBe("done");    // Probable
    expect(c.ladder[3].state).toBe("active");   // Confirmed
    expect(c.ladder[3].label).toContain("✓");
  });

  it("uses the supplied playbook steps as next actions", () => {
    expect(c.nextActions[0].text).toBe("Check wan-r2 interface counters");
  });
});

describe("buildRcaCase — copy guards (operator view)", () => {
  const tl = timeline({ signals: [signal({ entity_id: "wan-r2:192.168.100.5", attrs: '{"peer":"192.168.100.5"}' })] });
  const obj = corrObject();
  const c = buildRcaCase(tl, obj, {}, "NetOps", []);
  const operatorText = JSON.stringify({
    title: c.title, subtitle: c.subtitle, summary: c.summary, why: c.why,
    impact: c.impact, decision: c.decision, ticket: c.ticket,
    evidence: c.evidence, hypotheses: c.hypotheses, nextActions: c.nextActions,
    assistant: c.assistant.questions,
  });

  it("never product-brands the operator copy", () => {
    expect(operatorText).not.toMatch(/Correlix/);
  });

  it("never claims a likely fault location for an unconfirmed object", () => {
    expect(operatorText).not.toMatch(/Likely fault location/i);
  });

  it("never uses 'BGP session up' as RCA wording", () => {
    expect(operatorText).not.toMatch(/BGP session up/i);
  });
});

describe("buildRcaCase — ≥2 independent-stream confirmation guard", () => {
  // HARD RULE: the engine may say verdict_tier=confirmed, but the UI must NEVER
  // render "confirmed root cause" on a single independent evidence stream — a
  // routing event + a device-health event on the same area is ONE stream, not two.
  const tl = timeline({
    verdict_tier: "confirmed", top_hypothesis: "bgp-flap",
    signals: [
      signal({ kind: "bgp_state_anomaly", modality_class: "control_plane", entity_id: "wan-r2:192.168.100.5", attrs: '{"peer":"192.168.100.5"}' }),
      signal({ kind: "device_resource_anomaly", modality_class: "device_telemetry", entity_id: "wan-r2", is_trigger: false }),
    ],
  });
  const c = buildRcaCase(tl, corrObject({ verdict_tier: "confirmed", state: "open", signal_count: 2 }), {}, "NetOps", []);

  it("downgrades single-stream 'confirmed' to NOT CONFIRMED", () => {
    const texts = c.pills.map((p) => p.text);
    expect(texts).toContain("NOT CONFIRMED");
    expect(texts).not.toContain("✓ CONFIRMED");
  });
  it("does not OPEN an incident on a single stream", () => {
    expect(c.decision.text).not.toMatch(/^OPEN INCIDENT/);
    expect(c.impact[0].v).toBe("No confirmed customer impact");
  });
});

describe("EXAMPLE_CASE (synthetic golden)", () => {
  it("is flagged synthetic and fully populated", () => {
    expect(EXAMPLE_CASE.synthetic).toBe(true);
    expect(EXAMPLE_CASE.evidence.length).toBeGreaterThan(0);
    expect(EXAMPLE_CASE.timeline.length).toBeGreaterThan(0);
    expect(EXAMPLE_CASE.ladder).toHaveLength(4);
  });
});
