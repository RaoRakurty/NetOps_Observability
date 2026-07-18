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

  it("status pills say NOT CONFIRMED · Low · Incident Active / Analysis Suspected", () => {
    const texts = c.pills.map((p) => p.text);
    expect(texts).toContain("NOT CONFIRMED");
    expect(texts).toContain("Confidence: Low");
    expect(texts).toContain("Incident: Active");
    expect(texts).toContain("Analysis: Suspected");
    expect(texts).not.toContain("✓ CONFIRMED");
  });

  it("decision is HOLD, not escalate", () => {
    expect(c.decision.tone).toBe("");
    expect(c.decision.text).toMatch(/^HOLD/);
  });

  it("impact reports no confirmed customer impact + resolves device/peer", () => {
    // telemetry-qualified (owner 2026-07-12): a routing-only window has no
    // impact telemetry, so impact is NOT OBSERVABLE — never a bare "no impact".
    expect(c.impact[0]).toMatchObject({ k: "Impact", v: "Impact not observable — no impact telemetry in this window" });
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
    expect(device?.pill.text).toBe("No data");
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

// #113 (owner directive 2026-07-18): ownership must name the seam's responsible
// party from the matched signature — never a hardcoded "NOC" catch-all. NOC
// appears only when the engine has no attribution at all.
describe("buildRcaCase — seam ownership attribution (#113)", () => {
  const suspectedTl = timeline({
    verdict_tier: "suspected",
    top_hypothesis: "undetermined",
    signals: [signal({ kind: "probe_loss", modality_class: "active_probe", entity_id: "site-a>saas", attached: true })],
  });
  const suspectedObj = corrObject({ verdict_tier: "suspected", state: "open", signal_count: 1 });

  it("suspected + engine attribution → 'Possible owner: <label> — unconfirmed', no hardcoded NOC", () => {
    const c = buildRcaCase(suspectedTl, suspectedObj, {}, "isp", []);
    const possible = c.aside.find((r) => r.k === "Possible owner");
    expect(possible?.v).toBe("ISP / carrier — unconfirmed");
    expect(c.aside.some((r) => r.v === "NOC")).toBe(false);
    expect(c.aside.some((r) => r.k === "Owner")).toBe(false); // unconfirmed never claims "Owner"
  });

  it("registry entry upgrades the class label to the tenant's actual party (#113 slice 2)", () => {
    const c = buildRcaCase(suspectedTl, suspectedObj, {}, "isp", [], { isp: { name: "Lumen (DIA #12345)", contact: "noc@lumen.example" } });
    expect(c.aside.find((r) => r.k === "Possible owner")?.v).toBe("Lumen (DIA #12345) · ISP / carrier — unconfirmed");
  });

  it("suspected + no attribution → honest 'Not yet narrowed — NOC triage'", () => {
    const c = buildRcaCase(suspectedTl, suspectedObj, {}, "", []);
    expect(c.aside.find((r) => r.k === "Possible owner")?.v).toBe("Not yet narrowed — NOC triage");
  });

  it("confirmed + attribution → 'Owner: <label>' and ticket assignment uses the label", () => {
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
    const c = buildRcaCase(tl, obj, {}, "cloud_provider", []);
    expect(c.aside.find((r) => r.k === "Owner")?.v).toBe("Cloud provider");
    expect(c.aside.some((r) => r.k === "Possible owner")).toBe(false);
    expect(c.ticket.rows.find((r) => r.k === "Assignment")?.v).toBe("Cloud provider");
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
    expect(c.impact[0].v).toMatch(/^(No customer impact confirmed within available telemetry coverage|Impact not observable)/);
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

describe("buildRcaCase — cloud evidence section (#81 P3G 1c)", () => {
  const cloudHealth = signal({ source: "cloud", kind: "cloud_health", modality_class: "device_telemetry", entity_type: "app", entity_id: "billing", attrs: '{"app":"billing","account":"123","region":"us-east-1"}', severity: "high" });
  const cloudRes = signal({ source: "cloud", kind: "database_metric", modality_class: "device_telemetry", entity_type: "cloud_resource", entity_id: "billing-db", attrs: '{"account":"123","region":"us-east-1"}', metric_name: "connections_pct", value: 98, severity: "warn", is_trigger: false });
  const cloudChange = signal({ source: "cloud", kind: "cloud_change", modality_class: "control_plane", entity_type: "cloud_resource", entity_id: "billing-svc", attrs: '{"account":"123","region":"us-east-1"}', is_trigger: false });

  it("omits the cloud section when there is no cloud evidence (network RCA untouched)", () => {
    const c = buildRcaCase(timeline({ signals: [signal({})] }), corrObject(), {}, "NetOps", []);
    expect(c.cloud).toBeUndefined();
  });

  it("a cloud-only object builds a single-plane (not corroborated) section", () => {
    const tl = timeline({ verdict_tier: "suspected", signals: [cloudHealth, cloudRes, cloudChange] });
    const c = buildRcaCase(tl, corrObject({ verdict_tier: "suspected", signal_count: 3 }), {}, "AppOps", []);
    expect(c.cloud).toBeDefined();
    expect(c.cloud!.app).toBe("billing");
    expect(c.cloud!.account).toBe("123");
    expect(c.cloud!.region).toBe("us-east-1");
    expect(c.cloud!.crossPlane).toBe(false);
    expect(c.cloud!.resources.map((r) => r.name)).toContain("billing-db");
    expect(c.cloud!.resources[0].finding).toMatch(/connections_pct/);
    expect(c.cloud!.changes).toHaveLength(1);
    expect(c.cloud!.note).toMatch(/single|suspected at best/i);
  });

  it("a cloud symptom + an independent network observer reads as corroborated", () => {
    const probe = signal({ source: "lab", kind: "probe_loss", modality_class: "active_probe", entity_type: "path", entity_id: "branch->billing", is_trigger: false });
    const tl = timeline({ verdict_tier: "confirmed", signals: [cloudHealth, probe] });
    const c = buildRcaCase(tl, corrObject({ verdict_tier: "confirmed", signal_count: 2 }), {}, "AppOps", []);
    expect(c.cloud!.crossPlane).toBe(true);
    expect(c.cloud!.note).toMatch(/corroborated|independent/i);
  });

  it("titles a cloud object app-centric, not by the network plane it rides", () => {
    // cloud_health/database_metric map onto device_telemetry — the title must NOT
    // read "Device health change"; it must name the cloud app.
    const tl = timeline({ verdict_tier: "suspected", signals: [cloudHealth, cloudRes] });
    const c = buildRcaCase(tl, corrObject({ verdict_tier: "suspected", signal_count: 2 }), {}, "AppOps", []);
    expect(c.title).toBe("Cloud application issue — billing");
    expect(c.title).not.toMatch(/device/i);
    expect(c.summary).toMatch(/cloud issue.*billing/i);
  });

  it("ignores cleared and unattached cloud signals in the count", () => {
    const cleared = signal({ source: "cloud", kind: "cloud_health_clear", entity_type: "app", entity_id: "billing", attached: true });
    const unattached = signal({ source: "cloud", kind: "cloud_health", entity_type: "app", entity_id: "ghost", attached: false });
    const tl = timeline({ signals: [cloudHealth, cleared, unattached] });
    const c = buildRcaCase(tl, corrObject({ signal_count: 1 }), {}, "AppOps", []);
    expect(c.cloud!.signalCount).toBe(1);
  });
});

describe("buildRcaCase — application impact section (#81 P5)", () => {
  // The UI reads the engine's authoritative app_impact projection off the object.
  const teamsImpact = JSON.stringify({
    apps: [{ app: "Microsoft Teams", band: "authoritative", state: "fused", sources: ["ngfw_app_id", "ip_catalog"], evidence_score: 92, provider: "Microsoft" }],
  });

  it("omits the section when the object carries no app_impact (network RCA untouched)", () => {
    const c = buildRcaCase(timeline({ signals: [signal({})] }), corrObject(), {}, "NetOps", []);
    expect(c.appImpact).toBeUndefined();
  });

  it("names the affected app with provenance from the engine projection", () => {
    const c = buildRcaCase(timeline({ signals: [signal({})] }), corrObject({ app_impact: teamsImpact }), {}, "NetOps", []);
    expect(c.appImpact).toBeDefined();
    expect(c.appImpact!.apps).toHaveLength(1);
    const a = c.appImpact!.apps[0];
    expect(a.app).toBe("Microsoft Teams");
    expect(a.band).toBe("authoritative");
    expect(a.state).toBe("fused");
    expect(a.evidenceScore).toBe(92);
    expect(a.sources).toEqual(["ngfw_app_id", "ip_catalog"]);
    expect(a.provider).toBe("Microsoft");
  });

  it("renders multiple impacted apps verbatim", () => {
    const impact = JSON.stringify({ apps: [
      { app: "Zoom", band: "high", state: "fused", sources: ["ngfw_app_id"], evidence_score: 88 },
      { app: "Salesforce", band: "medium", state: "inferred", sources: ["ip_catalog"], evidence_score: 55 },
    ] });
    const c = buildRcaCase(timeline({ signals: [signal({})] }), corrObject({ app_impact: impact }), {}, "NetOps", []);
    expect(c.appImpact!.apps.map((a) => a.app)).toEqual(["Zoom", "Salesforce"]);
    expect(c.appImpact!.apps[0].evidenceScore).toBe(88);
  });

  it("tolerates absent/malformed app_impact (no section, no crash)", () => {
    expect(buildRcaCase(timeline({ signals: [signal({})] }), corrObject({ app_impact: "" }), {}, "NetOps", []).appImpact).toBeUndefined();
    expect(buildRcaCase(timeline({ signals: [signal({})] }), corrObject({ app_impact: "not-json" }), {}, "NetOps", []).appImpact).toBeUndefined();
    expect(buildRcaCase(timeline({ signals: [signal({})] }), corrObject({ app_impact: "{}" }), {}, "NetOps", []).appImpact).toBeUndefined();
  });
});

describe("buildRcaCase — canonical 5-state verdict (convergence)", () => {
  const tl = timeline({
    verdict_tier: "suspected", top_hypothesis: "undetermined",
    signals: [signal({ kind: "bgp_state_anomaly", modality_class: "control_plane", entity_id: "wan-r2:192.168.100.5", attached: true })],
  });

  it("an open suspected object → verdictState 'suspected'", () => {
    const c = buildRcaCase(tl, corrObject({ verdict_tier: "suspected", state: "open", signal_count: 1 }), {}, "NetOps", []);
    expect(c.verdictState).toBe("suspected");
    expect(Array.isArray(c.ruledOut)).toBe(true);
    expect(Array.isArray(c.whyNot)).toBe(true);
  });

  it("a closed object → verdictState 'recovered' and a RECOVERED pill", () => {
    const c = buildRcaCase(tl, corrObject({ verdict_tier: "suspected", state: "closed", signal_count: 1 }), {}, "NetOps", []);
    expect(c.verdictState).toBe("recovered");
    expect(c.pills.map((p) => p.text)).toContain("● RECOVERED");
  });

  it("a contradicted top hypothesis → verdictState 'contradicted' + ruledOut populated", () => {
    const obj = corrObject({
      verdict_tier: "suspected", state: "open", signal_count: 2,
      hypotheses: JSON.stringify({ ranking: { hypotheses: [{ contradicted: true, contradictions: ["link_state_change"], verdict: { reasons: ["routing remained stable"] } }] } }),
    });
    const c = buildRcaCase(tl, obj, {}, "NetOps", []);
    expect(c.verdictState).toBe("contradicted");
    expect(c.ruledOut.length).toBeGreaterThan(0);
    expect(c.whyNot).toContain("routing remained stable");
  });
});
