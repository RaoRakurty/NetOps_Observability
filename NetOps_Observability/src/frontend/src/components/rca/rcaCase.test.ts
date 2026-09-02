import { describe, it, expect } from "vitest";
import { buildRcaCase, buildCaseEvents, EXAMPLE_CASE } from "./rcaCase";
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
    expect(c.ladder[0].state).toBe("done");      // Detected
    // owner 2026-07-19: no "Observed" epistemic label anywhere in operator UI
    expect(c.ladder[0].label).toBe("✓ Detected");
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
    expect(device?.pill.text).toBe("Nothing collected");
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

  it("unconfirmed with a hypothesis reads 'possibly because of X' + evidence state — never a bare 'Not identified' (#113 point 4)", () => {
    const tl = timeline({
      verdict_tier: "suspected",
      top_hypothesis: "sig.ent.wan-edge.bgp-peer-down",
      signals: [signal({ kind: "bgp_state_anomaly", modality_class: "control_plane", entity_id: "wan-r2:192.168.100.5", attrs: '{"peer":"192.168.100.5"}', attached: true })],
    });
    const obj = corrObject({
      verdict_tier: "suspected", state: "open", top_hypothesis: "sig.ent.wan-edge.bgp-peer-down",
      evidence_missing: '["peer-side routing evidence not observed"]',
    });
    const c = buildRcaCase(tl, obj, {}, "isp", []);
    const root = c.aside.find((r) => r.k === "Root cause");
    expect(root?.v).toMatch(/^Not confirmed — possibly because of .+/);
    expect(root?.v).not.toBe("Not identified");
    expect(c.aside.find((r) => r.k === "Evidence state")?.v).toContain("peer-side routing evidence not observed");
  });

  it("no supported hypothesis → honest absence wording, no invented cause (#113 point 4)", () => {
    const c = buildRcaCase(suspectedTl, suspectedObj, {}, "", []);
    const root = c.aside.find((r) => r.k === "Root cause");
    expect(root?.v).toBe("Not identified — no cause hypothesis has supporting evidence yet");
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

// ── "Affected" aside row (2026-09-02) — the sixth NOC header question answered
// above the fold. It reports SCALE only, from exactly what the "Impact & blast
// radius" panel already shows (affected device / adjacency peer + the engine's
// app_impact projection). It never invents a site or user count, and it never
// prints "0 devices" when the blast radius is simply unknown.
describe("buildRcaCase — the aside answers \"What is affected\"", () => {
  const affected = (c: ReturnType<typeof buildRcaCase>) => c.aside.find((r) => r.k === "Affected")?.v;

  it("counts device + peer and names the impacted apps", () => {
    const tl = timeline({
      signals: [signal({
        kind: "bgp_state_anomaly", modality_class: "control_plane",
        entity_id: "wan-r2:192.168.100.5", attrs: '{"peer":"192.168.100.5"}', attached: true,
      })],
    });
    const appImpact = JSON.stringify({ apps: [
      { app: "Checkout API", band: "authoritative", state: "fused", sources: ["ngfw_app_id"], evidence_score: 91 },
      { app: "Salesforce", band: "medium", state: "inferred", sources: ["ip_catalog"], evidence_score: 55 },
    ] });
    const c = buildRcaCase(tl, corrObject({ app_impact: appImpact }), {}, "NetOps", []);
    expect(affected(c)).toBe("1 device · 1 peer · Checkout API (+1 app)");
  });

  it("reports only what is known when the object names a device and nothing else", () => {
    const tl = timeline({
      signals: [signal({ kind: "bgp_state_anomaly", modality_class: "control_plane", entity_id: "wan-r2", attrs: "{}", attached: true })],
    });
    const c = buildRcaCase(tl, corrObject(), {}, "NetOps", []);
    expect(affected(c)).toBe("1 device");
  });

  it("says \"Not yet determined\" when the blast radius is unknown (never \"0 devices\")", () => {
    const tl = timeline({ signals: [signal({ kind: "probe_loss", modality_class: "active_probe", entity_id: "probe-dallas", attached: true })] });
    const c = buildRcaCase(tl, corrObject(), {}, "NetOps", []);
    expect(affected(c)).toBe("Not yet determined");
    expect(affected(c)).not.toMatch(/\b0\b/);
  });

  it("counts the engine's affected.devices list, not just the trigger device", () => {
    const tl = timeline({
      signals: [signal({
        kind: "bgp_state_anomaly", modality_class: "control_plane",
        entity_id: "wan-r2:192.168.100.5", attrs: '{"peer":"192.168.100.5"}', attached: true,
      })],
    });
    const appImpact = JSON.stringify({ apps: [
      { app: "Checkout API", band: "authoritative", state: "fused", sources: ["ngfw_app_id"], evidence_score: 91 },
      { app: "Salesforce", band: "medium", state: "inferred", sources: ["ip_catalog"], evidence_score: 55 },
    ] });
    const obj = corrObject({
      app_impact: appImpact,
      affected: JSON.stringify({ devices: ["wan-r2", "core-sw-1", "edge-fw-1"] }),
    });
    const c = buildRcaCase(tl, obj, {}, "NetOps", []);
    expect(affected(c)).toBe("3 devices · 1 peer · Checkout API (+1 app)");
    // header and the "Impact & blast radius" panel are ONE source of truth
    expect(c.impact.find((r) => r.k === "Affected devices")?.v).toBe("3 devices");
  });

  it("falls back to the routing device when affected.devices is absent or malformed", () => {
    const tl = timeline({
      signals: [signal({ kind: "bgp_state_anomaly", modality_class: "control_plane", entity_id: "wan-r2", attrs: "{}", attached: true })],
    });
    for (const aff of ["{}", "", "not-json", JSON.stringify({ paths: ["a -> b"] })]) {
      const c = buildRcaCase(tl, corrObject({ affected: aff }), {}, "NetOps", []);
      expect(affected(c), `affected=${aff}`).toBe("1 device");
      expect(c.impact.find((r) => r.k === "Affected devices")?.v).toBe("1 device");
    }
  });

  it("dedupes the trigger device against the list and drops internal names", () => {
    const tl = timeline({
      signals: [signal({ kind: "bgp_state_anomaly", modality_class: "control_plane", entity_id: "wan-r2", attrs: "{}", attached: true })],
    });
    const obj = corrObject({ affected: JSON.stringify({ devices: ["wan-r2", "wan-r2", "core-sw-1", "clickhouse", ""] }) });
    expect(affected(buildRcaCase(tl, obj, {}, "NetOps", []))).toBe("2 devices");
  });

  it("sits directly under the ownership row and survives the PDF export contract", () => {
    const c = buildRcaCase(timeline({ signals: [signal({ attached: true })] }), corrObject(), {}, "NetOps", []);
    const keys = c.aside.map((r) => r.k);
    const own = Math.max(keys.indexOf("Owner"), keys.indexOf("Possible owner"));
    expect(own).toBeGreaterThanOrEqual(0);
    expect(keys[own + 1]).toBe("Affected");
    // rcaExport renders data.aside by iteration — every row must be a k/v pair.
    for (const r of c.aside) { expect(typeof r.k).toBe("string"); expect(typeof r.v).toBe("string"); }
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

// ── Evidence summary (owner directive 2026-07-18, rca-evidence-summary.md) ────
// Symptoms · independent sources · duration replace the raw "Signals: N" line;
// repetition renders as per-symptom time density, never as a count posing as
// evidence; the verdict names its reason in words (never a percentage); the raw
// observation total trails, de-emphasized. The word "Signals" never reaches
// operator-facing text.
import { buildEvidenceSummary, bucketTimes, EVIDENCE_BUCKETS } from "./rcaCase";

describe("bucketTimes — render-side density bucketing", () => {
  it("distributes and clamps timestamps into n buckets", () => {
    const start = Date.parse("2026-06-16T19:00:00Z");
    const end = start + 20 * 60_000;
    const got = bucketTimes(
      [start, start + 10 * 60_000, end, start - 60_000, end + 60_000],
      start, end, 4,
    );
    expect(got).toEqual([2, 0, 1, 2]);
    expect(got.reduce((a, b) => a + b, 0)).toBe(5); // nothing dropped, nothing invented
  });
});

describe("buildEvidenceSummary — repeats collapse into one symptom's density", () => {
  const sigs = [
    ...Array.from({ length: 5 }, (_, i) => signal({
      kind: "probe_loss", modality_class: "active_probe",
      ts: `2026-06-16 19:25:${String(10 + i * 10).padStart(2, "0")}`, attached: true,
    })),
    signal({ kind: "bgp_adjacency_change", modality_class: "control_plane", ts: "2026-06-16 19:25:30", attached: true }),
    signal({ kind: "probe_loss_clear", modality_class: "active_probe", ts: "2026-06-16 19:26:00", attached: false }),
  ];
  const es = buildEvidenceSummary(sigs, "2026-06-16 19:25:00", "2026-06-16 19:26:15",
    true, ["Active checks", "Routing / link"], "suspected", 300);

  it("counts distinct symptoms, not raw repeats", () => {
    expect(es.symptoms).toBe(2);
    expect(es.rows).toHaveLength(2);
    const loss = es.rows.find((r) => r.observations === 5);
    expect(loss).toBeTruthy();
    expect(loss!.buckets).toHaveLength(EVIDENCE_BUCKETS);
    expect(loss!.buckets.reduce((a, b) => a + b, 0)).toBe(5);
  });

  it("orders symptoms by onset (earliest first) and keeps the raw total as a trailing fact", () => {
    expect(es.rows[0].observations).toBe(5); // probe_loss started 19:25:10, bgp at 19:25:30
    expect(es.observations).toBe(300);
  });

  it("verdict reason is words, never a percentage, and never says 'signal'", () => {
    expect(es.verdictReason.length).toBeGreaterThan(0);
    expect(es.verdictReason).not.toMatch(/%/);
    expect(es.verdictReason).not.toMatch(/\bsignals?\b/i);
  });

  it("a single-source case reads honestly weak and names the solo source", () => {
    const solo = buildEvidenceSummary(
      [signal({ kind: "probe_loss", modality_class: "active_probe", ts: "2026-06-16 19:25:10", attached: true })],
      "2026-06-16 19:25:00", "2026-06-16 19:26:15", true, ["Active checks"], "suspected", 240);
    expect(solo.verdictReason).toMatch(/only active checks saw this/i);
    expect(solo.verdictReason).toMatch(/second independent source/i);
  });
});

describe("evidence summary in the workspace aside (no 'Signals' line)", () => {
  const tl = timeline({
    verdict_tier: "suspected", top_hypothesis: "undetermined",
    signals: [
      signal({ kind: "probe_loss", modality_class: "active_probe", ts: "2026-06-16 19:25:10", attached: true }),
      signal({ kind: "probe_loss", modality_class: "active_probe", ts: "2026-06-16 19:25:40", attached: true, signal_id: "s2" }),
    ],
    counts: {
      total: 240, attached: 2, unattached: 0, recovery: 0, unlinked: 0, attached_observers: 1,
      by_modality: { active_probe: 240 }, attached_by_modality: { active_probe: 2 },
      by_role: {}, by_grounding: {}, by_status: {},
    } as any,
  });
  const c = buildRcaCase(tl, corrObject({ verdict_tier: "suspected", state: "open", signal_count: 240 }), {}, "NetOps", []);

  it("the aside headlines evidence quality and demotes the raw count", () => {
    const keys = c.aside.map((r) => r.k);
    expect(keys).not.toContain("Signals");
    const ev = c.aside.find((r) => r.k === "Evidence");
    expect(ev?.v).toMatch(/1 symptom · 1 independent source/);
    const obs = c.aside.find((r) => r.k === "Observations");
    expect(obs?.v).toBe("240 collected");
    // raw volume trails the quality line
    expect(keys.indexOf("Observations")).toBeGreaterThan(keys.indexOf("Evidence"));
  });

  it("carries the render-ready summary for the density bars", () => {
    expect(c.evidenceSummary?.rows.length).toBe(1);
    expect(c.evidenceSummary?.verdictReason).toMatch(/only active checks saw this/i);
  });
});

describe("buildCaseEvents — chronological event timeline (owner P1 2026-07-19)", () => {
  const tl = timeline({
    verdict_tier: "suspected",
    signals: [
      signal({ ts: "2026-06-16 19:25:06", kind: "bgp_state_anomaly", modality_class: "control_plane", entity_id: "wan-r2:192.168.100.5", is_trigger: true }),
      signal({ ts: "2026-06-16 19:25:31", kind: "packet_loss_anomaly", modality_class: "active_probe", entity_id: "probe-dallas", is_trigger: false }),
      // later repeat of an already-seen symptom — must NOT create a second entry
      signal({ ts: "2026-06-16 19:25:52", kind: "bgp_state_anomaly", modality_class: "control_plane", entity_id: "wan-r2:192.168.100.5", is_trigger: false }),
      // recovery clear
      signal({ ts: "2026-06-16 19:29:10", kind: "bgp_state_anomaly_clear", modality_class: "control_plane", entity_id: "wan-r2:192.168.100.5", is_trigger: false, attached: false }),
    ],
  });
  const obj = corrObject({ created_at: "2026-06-16 19:25:40" } as never);
  const events = buildCaseEvents(tl, obj, {
    times: { recovered_at: "2026-06-16 19:31:02" },
    promotion: { manual: { promoted_by: "rao", promoted_at: "2026-06-16 19:30:00" } },
    verification: {
      run_id: "r1", correlation_id: tl.correlation_id, trigger: "manual", actor: "rao",
      started_at: "2026-06-16 19:27:00", status: "completed", devices: ["wan-r2"],
      results: [{ check: "iface", device_id: "wan-r2", target: "wan-r2", method: "snmp",
        status: "pass", ts: "2026-06-16 19:27:04", duration_ms: 90, refutes_kinds: ["bgp_state_anomaly"] }],
    },
  });

  it("is sorted ascending and every entry carries a real payload timestamp", () => {
    const ts = events.map((e) => Date.parse(e.ts.replace(" ", "T") + "Z"));
    expect([...ts].sort((a, b) => a - b)).toEqual(ts);
    expect(events.every((e) => !Number.isNaN(Date.parse(e.ts.replace(" ", "T") + "Z")))).toBe(true);
  });

  it("first sighting per symptom only — repeats collapse; the first is marked First symptom", () => {
    const bgp = events.filter((e) => /BGP state change on wan-r2/i.test(e.label) && !/cleared/i.test(e.label));
    expect(bgp).toHaveLength(1);
    expect(events[0].label).toMatch(/^First symptom — /);
    expect(events[0].detail).toContain("detection trigger");
  });

  it("a second independent source is called out in plain language", () => {
    const spread = events.find((e) => /probe-dallas/.test(e.label));
    expect(spread?.detail).toContain("independent source joined");
  });

  it("includes case-opened, promotion, verification and recovery milestones", () => {
    const labels = events.map((e) => e.label);
    expect(labels).toContain("Case opened — related evidence grouped into one case");
    expect(labels).toContain("Promoted to RCA case by rao");
    expect(labels.some((l) => l.startsWith("Verification battery run — devices healthy — refuting"))).toBe(true);
    expect(labels).toContain("Service recovery confirmed");
    expect(labels.some((l) => /cleared on wan-r2/.test(l))).toBe(true);
  });

  it("never invents timestamps — no extras ⇒ only signal + case events", () => {
    const bare = buildCaseEvents(tl, corrObject(), undefined);
    expect(bare.some((e) => /Promoted|Verification|recovery confirmed/i.test(e.label))).toBe(false);
  });

  it("buildRcaCase carries the events on the case", () => {
    const c = buildRcaCase(tl, obj, {}, "isp", []);
    expect((c.events ?? []).length).toBeGreaterThan(0);
  });
});

// ── Security evidence class (T2b) + parser-rule fidelity (A7) ────────────────
// The engine's fourth evidence class is a VERDICT plane: a rule/benchmark/
// advisory evaluated against captured state, published on the evidence bus with
// modality_class "security". These tests pin that it is accounted as its OWN
// independent source class (so security + BGP reads "2 independent sources"),
// that it can never confirm alone, and that its rows carry the attribution the
// operator needs (seam · internet exposure · witnessing provider) plus the
// weakest parser-rule fidelity behind them.

const SEC_ATTRS = JSON.stringify({
  evidence_class: "security", evidence_subclass: "exposure",
  rule_id: "netrule.exposed_mgmt", parser_rev: "bus", rules_hash: "abc123",
  fidelity: "doc_claimed", seam_id: "seam-7", seam_type: "DIA", internet_facing: true,
});

function securitySignal(over: Record<string, unknown> = {}) {
  return signal({
    kind: "security_exposure", source: "security", modality_class: "security",
    observer_type: "platform", observer_id: "security:vuln", collection_path: "via_aggregator",
    entity_id: "edge-r1", entity_type: "device", metric_name: "", severity: "warning",
    attrs: SEC_ATTRS, attached: true, is_trigger: false,
    ...over,
  });
}

function bgpSignal(over: Record<string, unknown> = {}) {
  return signal({
    kind: "bgp_adjacency_change", modality_class: "control_plane",
    entity_id: "edge-r1:192.168.100.5", attrs: JSON.stringify({ peer: "192.168.100.5", fidelity: "live_validated" }),
    attached: true, ts: "2026-06-16 19:25:30", ...over,
  });
}

describe("buildRcaCase — security evidence is its own independent source class", () => {
  const tl = timeline({
    verdict_tier: "confirmed", top_hypothesis: "sig.ent.security.exposure-story",
    signals: [bgpSignal(), securitySignal()],
  });
  const c = buildRcaCase(tl, corrObject({ verdict_tier: "confirmed", signal_count: 2 }), {}, "netops", []);

  it("counts security + network evidence as 2 independent sources", () => {
    expect(c.evidenceSummary?.sources).toBe(2);
    expect(c.evidenceSummary?.verdictReason).toContain("2 independent sources");
    expect(c.evidenceSummary?.verdictReason).toContain("Security evidence");
  });

  it("never labels the class with the engine word", () => {
    const printed = JSON.stringify(c);
    expect(printed).not.toMatch(/\bSignals\b/);
  });

  it("adds a security evidence row named by its lane subclass, beside the four planes", () => {
    expect(c.evidence).toHaveLength(ALL_PLANES + 1);
    const sec = c.evidence.find((e) => e.title === "Exposure");
    expect(sec).toBeTruthy();
    expect(sec?.variant).toBe("confirm");
    expect(sec?.finding).toBe("1 observation used.");
    expect(sec?.foot).toMatch(/rule verdict, not a wire measurement/);
  });

  it("chips the security row with its seam, internet exposure and provider", () => {
    const sec = c.evidence.find((e) => e.title === "Exposure");
    expect(sec?.chips).toEqual(["Seam: ISP (seam-7)", "Internet-facing", "Observed by vuln"]);
  });

  it("grades the security row with the parser-rule fidelity the evidence declared", () => {
    expect(c.evidence.find((e) => e.title === "Exposure")?.fidelity).toBe("doc_claimed");
    expect(c.evidence.find((e) => e.title === "Routing / link")?.fidelity).toBe("live_validated");
  });

  it("gives the evidence summary row the subclass label, not a plane label", () => {
    const row = c.evidenceSummary?.rows.find((r) => r.label === "Exposure finding");
    expect(row?.source).toBe("Exposure");
    expect(row?.fidelity).toBe("doc_claimed");
  });

  it("shows a security lane in the evidence timeline only because security evidence exists", () => {
    const lane = c.timeline.find((l) => l.label === "Security evidence");
    expect(lane?.markers.length).toBe(1);
    // a network-only case keeps exactly the four standard lanes
    const netOnly = buildRcaCase(timeline({ signals: [bgpSignal()] }), corrObject(), {}, "netops", []);
    expect(netOnly.timeline).toHaveLength(ALL_PLANES);
    expect(netOnly.evidence).toHaveLength(ALL_PLANES);
  });

  it('the "Why" rows treat security like any other modality — no special casing', () => {
    // control_plane is dominant here, so the why-lines read exactly as they do
    // for a plain routing case: the class only changes the labels, not the logic.
    expect(c.why.map((w) => w.label)).toEqual(["Why suspected", "Why confirmed", "To confirm"]);
  });

  it("security evidence rows are stable (snapshot)", () => {
    expect(c.evidence.filter((e) => e.title === "Exposure")).toMatchSnapshot();
  });
});

describe("buildRcaCase — security evidence alone can never confirm", () => {
  const tl = timeline({
    verdict_tier: "confirmed", top_hypothesis: "sig.ent.security.exposure-story",
    signals: [securitySignal()],
  });
  const c = buildRcaCase(tl, corrObject({ verdict_tier: "confirmed", signal_count: 1 }), {}, "netops", []);

  it("reports exactly 1 independent source", () => {
    expect(c.evidenceSummary?.sources).toBe(1);
    expect(c.evidenceSummary?.verdictReason).toBe("Only security evidence saw this — a second independent source is needed to confirm.");
  });

  it("keeps the header verdict at NOT CONFIRMED even though the engine tier says confirmed", () => {
    expect(c.pills.map((p) => p.text)).toContain("NOT CONFIRMED");
    expect(c.pills.map((p) => p.text)).not.toContain("✓ CONFIRMED");
    expect(c.verdictState).toBe("suspected");
  });

  it("titles and describes it as a security finding without inventing a network cause", () => {
    const sec = c.evidence.find((e) => e.title === "Exposure");
    expect(sec?.variant).toBe("main");
    expect(sec?.pill.text).toBe("Main evidence");
  });
});

describe("buildRcaCase — fidelity gap (A7) is rendered only when the engine sends it", () => {
  const hypotheses = (verdict: Record<string, unknown>) => JSON.stringify({
    ranking: { hypotheses: [{ id: "sig.ent.security.exposure-story", verdict }] },
  });
  const tl = timeline({
    verdict_tier: "suspected", top_hypothesis: "sig.ent.security.exposure-story",
    signals: [bgpSignal(), securitySignal()],
  });

  it("names the rules that held confirmation back", () => {
    const c = buildRcaCase(tl, corrObject({
      hypotheses: hypotheses({ reasons: [], fidelity_gap: ["netrule.exposed_mgmt", "cisco.ios.link_updown"], fidelity_min: "doc_claimed" }),
    }), {}, "netops", []);
    expect(c.fidelityGap).toEqual(["netrule.exposed_mgmt", "cisco.ios.link_updown"]);
    expect(c.fidelityMin).toBe("doc_claimed");
    expect(c.ladderNote).toBe("Confirmation held back — evidence from unvalidated parser rules: netrule.exposed_mgmt, cisco.ios.link_updown");
  });

  it("renders nothing at all when the engine sends no gap (flag off)", () => {
    const c = buildRcaCase(tl, corrObject({ hypotheses: hypotheses({ reasons: [] }) }), {}, "netops", []);
    expect(c.fidelityGap).toBeUndefined();
    expect(c.fidelityMin).toBeUndefined();
    expect(c.ladderNote).toBeUndefined();
  });

  it("truncates a very long gap list honestly rather than overflowing the ladder", () => {
    const ids = Array.from({ length: 11 }, (_, i) => `rule.${i}`);
    const c = buildRcaCase(tl, corrObject({ hypotheses: hypotheses({ fidelity_gap: ids }) }), {}, "netops", []);
    expect(c.ladderNote).toContain("rule.7");
    expect(c.ladderNote).not.toContain("rule.8");
    expect(c.ladderNote).toContain("(+3 more)");
  });

  it("never upgrades the verdict the engine gave, gap or no gap", () => {
    const c = buildRcaCase(tl, corrObject({ hypotheses: hypotheses({ fidelity_gap: ["r1"] }) }), {}, "netops", []);
    expect(c.pills.map((p) => p.text)).toContain("NOT CONFIRMED");
  });
});
