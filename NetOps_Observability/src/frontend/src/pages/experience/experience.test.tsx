// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// experience.test.tsx — the Digital Experience surface.
//
// WHAT THESE TESTS ARE FOR. This screen's whole reason to exist is that an
// operator can trust what it says at 03:00 without re-deriving it. That trust
// has exactly one failure mode worth most of this file: a hole in the telemetry
// rendered as a good result. So the payloads below are deliberately full of
// holes — an unpublished score, a journey nobody measured, an incident with no
// user count, a source that is switched off, business impact nobody declared —
// and each test asserts the exact sentence an operator reads in the place a
// number would have been.
//
// The rest follows the owner's frontend list: partial data loads safely, source
// degradation is visible, evidence carries its provenance, confidence is
// visible AND accessible, inferred and observed look different, filters and the
// URL agree, loading and error states exist, and the AI panel renders disabled
// with its reason rather than vanishing.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, within } from "@testing-library/react";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { scanCopy } from "../../copyVoice.test";
import { scanForEngineVocabulary } from "../../components/rca/vocabulary.test";
import type {
  DemChangesResponse, DemCoverageResponse, DemDataHealth, DemDataHealthResponse,
  DemEvidenceItem, DemExperienceIncident, DemExperienceResponse, DemExperienceScore,
  DemHypothesis, DemIncidentEvidenceResponse, DemIncidentPathResponse,
  DemIncidentResponse, DemIncidentSummary, DemIncidentTimelineResponse,
  DemJourneyHealth, DemJourneysResponse, DemOverviewResponse, DemProvenance,
  DemSourceHealth, DemTargetsResponse,
} from "../../services/api";

const mockApi = vi.hoisted(() => ({
  demOverview: vi.fn(),
  demIncidents: vi.fn(),
  demIncident: vi.fn(),
  demIncidentEvidence: vi.fn(),
  demIncidentTimeline: vi.fn(),
  demIncidentPath: vi.fn(),
  demJourneys: vi.fn(),
  demCreateJourney: vi.fn(),
  demJourney: vi.fn(),
  demUpdateJourney: vi.fn(),
  demDeleteJourney: vi.fn(),
  demSyntheticCoverage: vi.fn(),
  demChanges: vi.fn(),
  demRecordChange: vi.fn(),
  demDataHealth: vi.fn(),
  demTargets: vi.fn(),
  demExperience: vi.fn(),
}));

// The band edges are pinned to the server's own constants, so the mock must
// carry them: a page that silently banded on 0 would pass every other test.
vi.mock("../../services/api", () => ({
  api: mockApi,
  DEM_BAND_GOOD_AT: 70,
  DEM_BAND_POOR_AT: 30,
}));

import ExperiencePage from "./ExperiencePage";

// ── fixtures (the wire shapes from internal/dem/experience) ─────────────────

function prov(over: Partial<DemProvenance> = {}): DemProvenance {
  return {
    source: "synthetic", producer: "prober-1",
    event_at: "2026-09-05T10:00:00Z", observed_at: "2026-09-05T10:00:05Z",
    observation: "observed", data_class: "internal",
    schema_name: "correlix.dem.experience", schema_version: 1,
    ...over,
  };
}

function score(over: Partial<DemExperienceScore> = {}): DemExperienceScore {
  return {
    subject: "acme", subject_kind: "tenant", window: "1h", app_class: "default",
    aggregation: "worst_weighted",
    measured: true, score: 86.4, band: "good",
    previous_score: 97.1, delta: -10.7,
    dimensions: [
      {
        name: "journey_success", measured: true, points: 91.6, weight: 0.35, max: 35,
        score: 32.06, delta_contribution: -5.8, detail: "Checkout success fell to 91.6%",
        samples: 240,
      },
      {
        name: "user_friction", measured: false, points: 0, weight: 0, max: 0, score: 0,
        reason: "no_samples", samples: 0,
      },
    ],
    policy_version: 3, policy_name: "correlix-default",
    measured_dimensions: 1, declared_dimensions: 6,
    ...over,
  };
}

function source(over: Partial<DemSourceHealth> = {}): DemSourceHealth {
  return {
    source: "synthetic", label: "Synthetic checks", independence_group: "active_probe",
    configured: true, state: "flowing", detail: "reporting on cadence",
    last_seen: "2026-09-05T10:59:00Z", expected_interval_sec: 60, freshness_seconds: 30,
    events_in_window: 240, coverage: 0.8, coverage_covered: 8, coverage_total: 10,
    confidence_influence: 0, anchor_capable: true,
    ...over,
  };
}

function dataHealth(over: Partial<DemDataHealth> = {}): DemDataHealth {
  return {
    window: "1h",
    sources: [
      source(),
      source({
        source: "rum", label: "Real-user telemetry", independence_group: "real_user",
        configured: false, state: "off", anchor_capable: true,
        detail: "no producer for this source is deployed yet",
        last_seen: undefined, coverage: undefined, coverage_covered: 0, coverage_total: 0,
        events_in_window: 0, confidence_influence: 0.4,
      }),
    ],
    anchor_sources_flowing: 1,
    can_confirm: false,
    explanation: "Only one kind of instrument is reporting, so a cause can be suspected but never confirmed.",
    ...over,
  };
}

function journeyHealth(over: Partial<DemJourneyHealth> = {}): DemJourneyHealth {
  return {
    journey_id: "jny-1", name: "Checkout", app: "shop", business_importance: "critical",
    window: "1h", version: 2,
    measured: true, success_pct: 91.6, steps_measured: 2, steps_declared: 3,
    slo: { success_pct: 99 }, meets_slo: false, failing_step_id: "pay",
    steps: [
      { step_id: "cart", label: "Add to cart", measured: true, success_pct: 99.8, samples: 120, meets_slo: true },
      { step_id: "pay", label: "Pay", measured: true, success_pct: 91.8, samples: 120, meets_slo: false, failing: true },
      { step_id: "receipt", label: "Receipt", measured: false, meets_slo: false, reason: "step_not_bound" },
    ],
    ...over,
  };
}

function summary(over: Partial<DemIncidentSummary> = {}): DemIncidentSummary {
  return {
    id: "exp-000000000000001", title: "Checkout is failing from Berlin",
    severity: "high", status: "open",
    app: "shop", journey: "Checkout",
    detected_at: "2026-09-05T10:05:00Z", first_impact_at: "2026-09-05T10:00:00Z",
    duration_sec: 3900,
    leading_cause: "the ISP-A transit segment lost 8% of probes from two sites",
    leading_cause_class: "transit_degradation", likely_layer: "ISP",
    confidence: 0.62, verdict_tier: "suspected",
    confidence_factors: [
      { name: "support", value: 0.82, reason: "weighted supporting evidence" },
      { name: "independence", value: 0.75, reason: "only one kind of instrument reported it" },
      { name: "alignment", value: 0.9, reason: "share of supporting evidence inside the incident window" },
      { name: "specificity", value: 0.7, reason: "a concrete entity is named" },
      { name: "contradiction", value: 0.85, reason: "one observation argues against it" },
      { name: "completeness", value: 0.6, reason: "a required source is not reporting" },
    ],
    gate_reasons: ["no second, independent kind of instrument agrees, so this stays suspected"],
    owner: "isp", seam: "DIA",
    journey_success_pct: 91.6,
    impact_not_measured: ["users", "sessions"],
    evidence_count: 3, contradiction_count: 1, missing_evidence_count: 2,
    ...over,
  };
}

function evidence(over: Partial<DemEvidenceItem> = {}): DemEvidenceItem {
  return {
    id: "ev-1", tenant_id: "acme", kind: "probe_loss",
    entity: "as64500", entity_kind: "seam",
    summary: "Probe loss to the shop front door rose to 8% from two sites",
    stance: "supports", independence_group: "active_probe", observer: "prober@berlin",
    reliability: 0.9, provenance: prov(),
    ...over,
  };
}

function hypothesis(over: Partial<DemHypothesis> = {}): DemHypothesis {
  return {
    id: "hyp-1", tenant_id: "acme",
    cause_class: "transit_degradation", cause_entity: "AS64500",
    explanation: "the ISP-A transit segment lost 8% of probes from two sites",
    seam: "DIA", owner: "isp",
    state: "SUSPECTED", verdict_tier: "suspected", confidence: 0.62,
    confidence_factors: [
      { name: "support", value: 0.82, reason: "weighted supporting evidence" },
      { name: "independence", value: 0.75, reason: "only one kind of instrument reported it" },
    ],
    independence: {
      anchor_modalities: ["active_probe"], modalities: ["active_probe"],
      observers: ["prober@berlin"],
      reasons: ["only one kind of instrument reported it"],
    },
    supporting_evidence_ids: ["ev-1"],
    gate_reasons: ["no second, independent kind of instrument agrees, so this stays suspected"],
    ...over,
  };
}

function incident(over: Partial<DemExperienceIncident> = {}): DemExperienceIncident {
  return {
    id: "exp-000000000000001", tenant_id: "acme", promoted: false,
    title: "Checkout is failing from Berlin", severity: "high", status: "open",
    detected_at: "2026-09-05T10:05:00Z", first_impact_at: "2026-09-05T10:00:00Z",
    window: { start: "2026-09-05T10:00:00Z", end: "2026-09-05T11:00:00Z" },
    affected_apps: ["shop"], affected_journeys: ["Checkout"], affected_sites: ["berlin"],
    impact: {
      journey_success_pct: 91.6, journey_success_before: 99.4,
      not_measured: ["users", "sessions"],
    },
    hypotheses: [hypothesis()], leading_hypothesis_id: "hyp-1",
    confidence: 0.62, verdict_tier: "suspected",
    evidence: [evidence()],
    missing_evidence: [
      { source: "rum", independence_group: "real_user", reason: "not_configured",
        detail: "Real-user telemetry would be the only second opinion here.", required: true },
    ],
    owner: "isp", seam: "DIA",
    verification: { attempted: false, recovered: false, detail: "No remediation has been verified." },
    ...over,
  };
}

function overview(over: Partial<DemOverviewResponse> = {}): DemOverviewResponse {
  return {
    window: "1h", enabled: true, measured: true,
    score: score(),
    journeys: [journeyHealth()],
    incidents: [summary()],
    changes: [],
    data_health: dataHealth(),
    hotspots: [
      { dimension: "app", key: "shop", band: "fair", measured: true, score: 66, subjects: 2, failing: 1 },
      { dimension: "isp", key: "", band: "not_measured", measured: false, subjects: 0, failing: 0,
        reason: "this breakdown needs first-party real-user telemetry, which is not collected yet" },
    ],
    ai_investigator: {
      available: false,
      reason: "The AI investigator is switched off for this deployment.",
    },
    generated_at: "2026-09-05T11:00:00Z", policy_version: 3,
    ...over,
  };
}

function experienceResp(over: Partial<DemExperienceResponse> = {}): DemExperienceResponse {
  return {
    window: "1h", enabled: true, measured: true,
    targets: [
      {
        tenant: "acme", target: "tgt-1", kind: "http", site: "berlin", app: "shop",
        source: "synthetic", window: "1h", measured: true, score: 62, grade: "degraded",
        availability: { measured: true, value: 96, budget: 99, budget_declared: true, met: false, points: 60, weight: 0.5, samples: 120 },
        latency: { measured: true, value: 420, budget: 300, budget_declared: true, met: false, points: 40, weight: 0.3, samples: 120 },
        path_stability: { measured: false, reason: "no_samples", budget_declared: false, met: false, points: 0, weight: 0, samples: 0 },
        samples: 120, last_probe: "2026-09-05T10:59:00Z",
      },
      {
        tenant: "acme", target: "tgt-2", kind: "dns", site: "berlin", app: "mail",
        source: "synthetic", window: "1h", measured: false, grade: "not_measured",
        reason: "no_samples", detail: "no probe result was recorded for this check in this window",
        availability: { measured: false, budget_declared: false, met: false, points: 0, weight: 0, samples: 0 },
        latency: { measured: false, budget_declared: false, met: false, points: 0, weight: 0, samples: 0 },
        path_stability: { measured: false, budget_declared: false, met: false, points: 0, weight: 0, samples: 0 },
        samples: 0,
      },
    ],
    sites: [], apps: [], target_count: 2, scored_count: 1,
    generated_at: "2026-09-05T11:00:00Z",
    ...over,
  };
}

function targetsResp(over: Partial<DemTargetsResponse> = {}): DemTargetsResponse {
  return {
    targets: [{
      id: "tgt-1", tenant_id: "acme", name: "shop front door", kind: "http",
      host: "https://shop.example/health", interval_sec: 60, site: "berlin", app: "shop",
      paused: false, created_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-01T00:00:00Z",
    }],
    count: 1, limit: 200, enabled: true,
    ...over,
  };
}

function coverageResp(over: Partial<DemCoverageResponse> = {}): DemCoverageResponse {
  return {
    window: "1h",
    coverage: {
      window: "1h",
      actions: [{
        journey_id: "jny-1", step_id: "receipt", label: "Receipt", app: "shop",
        business_importance: "critical", synthetics: 0, vantages: 0,
        reliability_grade: "unknown", state: "untested",
        detail: "nothing measures this action",
      }],
      critical_actions: 1, protected_actions: 0, untested_actions: 1, thin_actions: 0,
      broken_tests: 0, flaky_tests: 0, coverage_pct: 0,
      detail: "One critical action is untested.",
    },
    reliability_note: "A check nobody has graded is not a check that passed.",
    ...over,
  };
}

const JOURNEYS: DemJourneysResponse = {
  window: "1h", measured: true, journeys: [], health: [], count: 0, limit: 100,
  reason: "no_journeys",
  note: "No journey is declared for this tenant.",
};

const CHANGES: DemChangesResponse = {
  window: "1h", changes: [], total: 0, returned: 0, limit: 100, offset: 0, complete: true,
  note: "No change was recorded in this window.",
};

const EVIDENCE_RES: DemIncidentEvidenceResponse = {
  incident_id: "exp-000000000000001",
  evidence: [
    evidence(),
    evidence({
      id: "ev-2", summary: "The same release is healthy on the unaffected cohort",
      stance: "contradicts", decisive: true, independence_group: "change_record",
      provenance: prov({ source: "configdrift", observation: "inferred" }),
    }),
  ],
  missing_evidence: [
    { source: "rum", independence_group: "real_user", reason: "not_configured",
      detail: "Real-user telemetry would be the only second opinion here.", required: true },
  ],
  hypotheses: [hypothesis()],
};

const TIMELINE_RES: DemIncidentTimelineResponse = {
  incident_id: "exp-000000000000001",
  timeline: [
    { at: "2026-09-05T10:00:00Z", kind: "impact", summary: "Checkout success fell below its objective", observation: "observed" },
    { at: "2026-09-05T10:20:00Z", kind: "evidence", summary: "Probe loss rose on the ISP-A segment", observation: "inferred" },
  ],
  changes: [],
};

const PATH_RES: DemIncidentPathResponse = {
  incident_id: "exp-000000000000001",
  measured: false,
  reason: "no forward path was observed for this incident's subject in this window, so there is no path to render — this is an absent measurement, not a clean path",
};

// ── harness ─────────────────────────────────────────────────────────────────

function setup(over: {
  overview?: DemOverviewResponse;
  incidents?: DemIncidentSummary[];
  incident?: DemIncidentResponse;
  dataHealth?: DemDataHealthResponse;
} = {}) {
  mockApi.demOverview.mockResolvedValue(over.overview ?? overview());
  mockApi.demExperience.mockResolvedValue(experienceResp());
  mockApi.demTargets.mockResolvedValue(targetsResp());
  mockApi.demSyntheticCoverage.mockResolvedValue(coverageResp());
  mockApi.demJourneys.mockResolvedValue(JOURNEYS);
  mockApi.demChanges.mockResolvedValue(CHANGES);
  mockApi.demDataHealth.mockResolvedValue(over.dataHealth ?? {
    window: "1h", enabled: true, data_health: dataHealth(), policy_version: 3,
  });
  mockApi.demIncidents.mockResolvedValue({
    window: "1h", measured: true, incidents: over.incidents ?? [summary()],
    total: 1, returned: 1, limit: 100, offset: 0, complete: true,
  });
  mockApi.demIncident.mockResolvedValue(over.incident ?? {
    window: "1h", incident: incident(),
    ai_investigator: { available: false, reason: "The AI investigator is switched off for this deployment." },
    evidence_packet_available: true,
  } as DemIncidentResponse);
  mockApi.demIncidentEvidence.mockResolvedValue(EVIDENCE_RES);
  mockApi.demIncidentTimeline.mockResolvedValue(TIMELINE_RES);
  mockApi.demIncidentPath.mockResolvedValue(PATH_RES);
}

function goto(hash: string) {
  window.location.hash = hash;
}

beforeEach(() => {
  vi.clearAllMocks();
  goto("");
});
afterEach(cleanup);

// ── 1. partial data loads safely ────────────────────────────────────────────

describe("the Experience overview with holes in the payload", () => {
  it("renders every absent measure as its reason, and never as a number", async () => {
    setup({
      overview: overview({
        score: score({ measured: false, score: undefined, band: "not_measured",
          reason: "below_evidence_minimum", previous_score: undefined, delta: undefined }),
        journeys: [journeyHealth({ measured: false, success_pct: undefined,
          reason: "journey_not_measured", detail: "no required step of this journey is measured in this window" })],
        incidents: [],
        business_impact: undefined,
      }),
    });
    render(<ExperiencePage />);

    // The published score is withheld, with the reason in its place.
    expect(await screen.findByText(/Too few dimensions were measured to publish a score/i))
      .toBeInTheDocument();
    // …and nothing invented a 0 or a 100 for it.
    const slo = screen.getByRole("button", { name: /^Experience SLO/i });
    expect(within(slo).queryByText("0")).toBeNull();
    expect(within(slo).queryByText("0.0")).toBeNull();
    expect(within(slo).queryByText("100.0")).toBeNull();

    // A journey nobody measured says so instead of scoring.
    expect(screen.getAllByText(/no required step of this journey is measured/i).length)
      .toBeGreaterThan(0);
  });

  it("says a user count is missing rather than reporting nobody was affected", async () => {
    setup();
    render(<ExperiencePage />);
    const card = await screen.findByRole("button", { name: /^Impacted users/i });
    expect(within(card).getByText("Not measured")).toBeInTheDocument();
    expect(within(card).getByText(/no producer for this source is deployed yet/i)).toBeInTheDocument();
  });

  it("keeps the other panels when one read fails (they are independent)", async () => {
    setup();
    mockApi.demExperience.mockRejectedValue(new Error("500 Internal Server Error: nope"));
    render(<ExperiencePage />);
    // The heatmap's own read failed…
    expect(await screen.findByText(/The per-check scores could not be read/i)).toBeInTheDocument();
    // …and the overview is still on screen.
    expect(screen.getByRole("region", { name: /Active experience incidents/i })).toBeInTheDocument();
  });
});

// ── 2. data-source degradation is visible ───────────────────────────────────

describe("telemetry confidence", () => {
  it("states that no cause can be confirmed, and which source is off", async () => {
    setup();
    render(<ExperiencePage />);
    const panel = await screen.findByRole("region", { name: /Telemetry confidence/i });
    expect(within(panel).getByText(/No cause can be confirmed\./i)).toBeInTheDocument();
    expect(within(panel).getByText(/Only one kind of instrument is reporting/i)).toBeInTheDocument();
    const rum = within(panel).getByRole("region", { name: "Real-user telemetry" });
    expect(within(rum).getByText(/Lowering confidence by 40%/i)).toBeInTheDocument();
  });

  it("shows the same degradation on the Data Health tab, from the payload", async () => {
    setup();
    goto("#/operations/digital-experience/data-health");
    render(<ExperiencePage />);
    expect(await screen.findByText(/No — no cause can be confirmed/i)).toBeInTheDocument();
    const rum = screen.getByRole("region", { name: /Real-user telemetry telemetry source/i });
    expect(within(rum).getByText("Not configured")).toBeInTheDocument();
    expect(within(rum).getByText(/lowering diagnostic confidence by 40%/i)).toBeInTheDocument();
    // Coverage that is not knowable is stated, never rendered as full coverage.
    // (Both coverage and freshness are absent for this source, so there are two.)
    expect(within(rum).getAllByText("Not measured").length).toBe(2);
    expect(within(rum).queryByText("100%")).toBeNull();
  });
});

// ── 3 + 5. evidence, provenance, and inferred ≠ observed ────────────────────

describe("the incident view", () => {
  async function openIncident() {
    setup();
    goto("#/operations/digital-experience/incidents?incident=exp-000000000000001");
    render(<ExperiencePage />);
    return screen.findByRole("region", { name: /Incident evidence/i });
  }

  it("renders each evidence item with its provenance", async () => {
    const panel = await openIncident();
    expect(within(panel).getByText(/Probe loss to the shop front door rose to 8%/i)).toBeInTheDocument();
    expect(within(panel).getAllByText("Observed").length).toBeGreaterThan(0);
    expect(within(panel).getByText("Inferred")).toBeInTheDocument();
    expect(within(panel).getAllByText(/observer: prober@berlin/i).length).toBe(2);
  });

  it("makes an inferred item look different from an observed one", async () => {
    const panel = await openIncident();
    const items = panel.querySelectorAll("li.dx-ev-item");
    expect(items.length).toBe(2);
    const observed = [...items].find((n) => !n.className.includes("dx-ev-item--inferred"));
    const inferred = [...items].find((n) => n.className.includes("dx-ev-item--inferred"));
    expect(observed).toBeTruthy();
    expect(inferred).toBeTruthy();
    // The distinction survives without colour: a different chip word and a
    // different rule style, not merely a different hue.
    expect(within(inferred as HTMLElement).getByText("Inferred")).toBeInTheDocument();
    expect(within(observed as HTMLElement).getByText("Observed")).toBeInTheDocument();
  });

  it("filters evidence to supporting, contradicting and missing", async () => {
    const panel = await openIncident();
    fireEvent.click(within(panel).getByRole("button", { name: "Contradicting" }));
    expect(within(panel).getByText(/same release is healthy on the unaffected cohort/i)).toBeInTheDocument();
    expect(within(panel).queryByText(/Probe loss to the shop front door/i)).toBeNull();

    fireEvent.click(within(panel).getByRole("button", { name: "Missing" }));
    expect(within(panel).getByText(/only second opinion here/i)).toBeInTheDocument();
    expect(within(panel).getByText(/required for confirmation/i)).toBeInTheDocument();
  });

  it("renders the path REFERENCE verbatim when no path was observed", async () => {
    await openIncident();
    expect(
      screen.getAllByText(/absent measurement, not a clean path/i).length,
    ).toBeGreaterThan(0);
  });

  it("puts the sections in the owner's order", async () => {
    await openIncident();
    const order = ["Impact", "Experience path", "Timeline", "Hypotheses", "Changes",
      "Evidence", "Action", "Verify"];
    const headings = screen.getAllByRole("heading", { level: 2 }).map((h) => h.textContent);
    const seen = order.filter((o) => headings.includes(o));
    expect(seen).toEqual(order);
  });

  it("does not claim recovery that nothing verified", async () => {
    await openIncident();
    const verify = screen.getByRole("region", { name: /Recovery verification/i });
    expect(within(verify).getByText(/Not verified yet\./i)).toBeInTheDocument();
    expect(within(verify).getByText(/Action done is not recovery\./i)).toBeInTheDocument();
    expect(within(verify).getByRole("button", { name: /Ask Iris about verified recovery/ })).toBeInTheDocument();
  });
});

// ── 4. confidence is visible and accessible ─────────────────────────────────

describe("confidence on the incident LIST row", () => {
  it("decomposes the number into its factors without opening the incident", async () => {
    setup();
    render(<ExperiencePage />);
    const table = await screen.findByRole("region", { name: /Active experience incidents/i });
    const group = within(table).getByRole("group", { name: /62%, Suspected/i });
    for (const factor of ["support", "independence", "alignment", "specificity",
      "contradiction", "completeness"]) {
      expect(within(group).getByText(new RegExp(`\\b${factor}\\b`))).toBeInTheDocument();
    }
    expect(within(group).getByText(/weighted supporting evidence/i)).toBeInTheDocument();
    expect(within(group).getByText(/a required source is not reporting/i)).toBeInTheDocument();
  });

  it("shows the gate reasons on a row that is not confirmed", async () => {
    setup();
    render(<ExperiencePage />);
    const table = await screen.findByRole("region", { name: /Active experience incidents/i });
    const gate = within(table).getByRole("list", { name: /Why this is not confirmed/i });
    expect(within(gate).getByText(/no second, independent kind of instrument agrees/i))
      .toBeInTheDocument();
  });

  it("drops the gate reasons once the verdict IS confirmed", async () => {
    setup({
      overview: overview({
        incidents: [summary({ verdict_tier: "confirmed", confidence: 0.94, gate_reasons: undefined })],
      }),
    });
    render(<ExperiencePage />);
    const table = await screen.findByRole("region", { name: /Active experience incidents/i });
    expect(within(table).getByRole("group", { name: /94%, Confirmed/i })).toBeInTheDocument();
    expect(within(table).queryByRole("list", { name: /Why this is not confirmed/i })).toBeNull();
    // The factors still travel with a confirmed number — it is decomposable too.
    expect(within(table).getByText(/weighted supporting evidence/i)).toBeInTheDocument();
  });

  it("survives a row the server sent without a breakdown", async () => {
    setup({
      overview: overview({
        incidents: [summary({ confidence_factors: undefined, gate_reasons: undefined })],
      }),
    });
    render(<ExperiencePage />);
    const table = await screen.findByRole("region", { name: /Active experience incidents/i });
    expect(within(table).getByRole("group", { name: /62%, Suspected/i })).toBeInTheDocument();
  });
});

describe("confidence", () => {
  it("carries an accessible name, its factor breakdown and its gate reasons", async () => {
    setup();
    goto("#/operations/digital-experience/incidents?incident=exp-000000000000001");
    render(<ExperiencePage />);
    const hyp = await screen.findByRole("region", { name: /Incident hypotheses/i });
    const group = within(hyp).getByRole("group", { name: /62%, Suspected/i });
    expect(group).toBeInTheDocument();
    // The factors ARE the number: a bare 62% teaches an operator to ignore it.
    expect(within(group).getByText(/weighted supporting evidence/i)).toBeInTheDocument();
    // Not confirmed ⇒ the mechanical reason is shown, never a bare "not confirmed".
    expect(
      within(group).getByText(/no second, independent kind of instrument agrees/i),
    ).toBeInTheDocument();
  });
});

// ── 6. filters and the URL agree ────────────────────────────────────────────

describe("incident filters", () => {
  it("mirrors a filter into the URL and into the request", async () => {
    setup();
    goto("#/operations/digital-experience/incidents");
    render(<ExperiencePage />);
    const sev = await screen.findByLabelText("Severity");
    fireEvent.change(sev, { target: { value: "high" } });

    await waitFor(() => expect(window.location.hash).toContain("severity=high"));
    await waitFor(() =>
      expect(mockApi.demIncidents).toHaveBeenCalledWith(
        expect.objectContaining({ severity: "high" }),
      ));
    // An unset filter is DROPPED, never sent blank.
    const last = mockApi.demIncidents.mock.calls.at(-1)![0];
    expect(last.app).toBeUndefined();
    expect(last.journey).toBeUndefined();
  });

  it("reads a filter back out of the URL on mount, so a link reproduces the list", async () => {
    setup();
    goto("#/operations/digital-experience/incidents?severity=critical");
    render(<ExperiencePage />);
    expect(await screen.findByLabelText("Severity")).toHaveValue("critical");
    await waitFor(() =>
      expect(mockApi.demIncidents).toHaveBeenCalledWith(
        expect.objectContaining({ severity: "critical" }),
      ));
    expect(screen.getByRole("button", { name: /Ask Iris about a filtered list/ }))
      .toBeInTheDocument();
  });

  it("pushes the tab into the hash so every sub-view is linkable", async () => {
    setup();
    render(<ExperiencePage />);
    fireEvent.click(await screen.findByRole("tab", { name: "Changes" }));
    expect(window.location.hash).toContain("/operations/digital-experience/changes");
    expect(await screen.findByRole("region", { name: /Change feed filters/i })).toBeInTheDocument();
  });
});

// ── 7. no-data is not healthy ───────────────────────────────────────────────

describe("absence is never rendered as health", () => {
  it("marks an unmeasured check on the heatmap as not measured, not as good", async () => {
    setup();
    goto("#/operations/digital-experience/synthetics");
    render(<ExperiencePage />);
    const heat = await screen.findByRole("region", { name: /Synthetic site and application heatmap/i });
    await waitFor(() =>
      expect(heat.querySelectorAll("td.dx-heat-cell--not_measured").length).toBe(1));
    const notMeasured = heat.querySelectorAll("td.dx-heat-cell--not_measured");
    expect((notMeasured[0] as HTMLElement).getAttribute("title"))
      .toMatch(/no probe result was recorded/i);
    // And it is not painted as good.
    expect(heat.querySelectorAll("td.dx-heat-cell--good").length).toBe(0);
  });

  it("calls an action nothing measures untested, never covered", async () => {
    setup();
    goto("#/operations/digital-experience/synthetics");
    render(<ExperiencePage />);
    const panel = await screen.findByRole("region", { name: /Synthetic coverage/i });
    expect(await within(panel).findByText(/Untested — nothing measures this/i)).toBeInTheDocument();
    expect(within(panel).getByText(/A check nobody has graded is not a check that passed/i))
      .toBeInTheDocument();
  });

  it("reports a hotspot dimension with no producer by its reason", async () => {
    setup();
    render(<ExperiencePage />);
    const panel = await screen.findByRole("region", { name: /Experience hotspots/i });
    const isp = within(panel).getByRole("region", { name: /Provider \(ISP\)/i });
    expect(within(isp).getByText("Not measured")).toBeInTheDocument();
    expect(within(isp).getByText(/needs first-party real-user telemetry/i)).toBeInTheDocument();
    expect(within(isp).queryByText("0")).toBeNull();
  });
});

describe("the published score", () => {
  it("names the fold that produced it, not just its weights", async () => {
    setup();
    render(<ExperiencePage />);
    fireEvent.click(await screen.findByRole("button", { name: /^Experience SLO/i }));
    const panel = await screen.findByRole("region", { name: /Experience score breakdown/i });
    expect(await within(panel).findByText(/worst-weighted mean/i)).toBeInTheDocument();
    expect(within(panel).getByText(/carries 40% of the weight/i)).toBeInTheDocument();
  });

  it("puts the fold and every dimension into the 'how this was made' tooltip", async () => {
    setup();
    render(<ExperiencePage />);
    const slo = await screen.findByRole("button", { name: /^Experience SLO/i });
    const tip = slo.getAttribute("title") ?? "";
    expect(tip).toMatch(/policy correlix-default v3/);
    expect(tip).toMatch(/1 of 6 dimensions measured/);
    expect(tip).toMatch(/Subjects folded by a worst-weighted mean/);
    expect(tip).toMatch(/Journey success: 91\.6\/100 × weight 35% → 32\.1 · -5\.8 pts of the change/);
    // A dimension nothing measured is LISTED with its reason, never omitted.
    expect(tip).toMatch(/User friction: not measured — No measurement was recorded/);
  });
});

// ── 8. loading and error states ─────────────────────────────────────────────

describe("load states", () => {
  it("shows a loading state before the read settles", () => {
    setup();
    mockApi.demOverview.mockReturnValue(new Promise(() => { /* never settles */ }));
    render(<ExperiencePage />);
    expect(screen.getByRole("status").textContent).toMatch(/Reading the experience overview/i);
  });

  it("says the read failed rather than rendering an empty, healthy-looking screen", async () => {
    setup();
    mockApi.demOverview.mockRejectedValue(new Error("500 Internal Server Error: store down"));
    render(<ExperiencePage />);
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(/whether it is healthy is unknown/i);
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
  });

  it("retries the failed read on request", async () => {
    setup();
    mockApi.demOverview.mockRejectedValueOnce(new Error("500 Internal Server Error: store down"));
    render(<ExperiencePage />);
    fireEvent.click(await screen.findByRole("button", { name: "Try again" }));
    expect(await screen.findByRole("region", { name: /Active experience incidents/i }))
      .toBeInTheDocument();
  });
});

// ── 9. business impact can be absent ────────────────────────────────────────

describe("business impact", () => {
  it("renders the absence, not a zero, when nobody declared a value", async () => {
    setup({ overview: overview({ business_impact: undefined, business_impact_currency: undefined }) });
    render(<ExperiencePage />);
    const card = await screen.findByRole("button", { name: /^Business impact/i });
    expect(within(card).getByText("Not measured")).toBeInTheDocument();
    expect(within(card).getByText(/No affected journey declares a value/i)).toBeInTheDocument();
    expect(within(card).queryByText("0")).toBeNull();
  });

  it("renders the amount with its currency when one was declared", async () => {
    setup({
      overview: overview({ business_impact: 12400, business_impact_currency: "EUR" }),
    });
    render(<ExperiencePage />);
    const card = await screen.findByRole("button", { name: /^Business impact/i });
    expect(within(card).getByText(/12,400 EUR/)).toBeInTheDocument();
  });

  it("says a total was WITHHELD, not that there was no impact, on mixed currencies", async () => {
    setup({
      overview: overview({
        business_impact: undefined, business_impact_currency: undefined,
        business_impact_note: "Business impact is declared in more than one currency in this window, so no single total is shown. The per-incident figures are correct.",
      }),
    });
    render(<ExperiencePage />);
    const card = await screen.findByRole("button", { name: /^Business impact/i });
    expect(within(card).getByText(/declared in more than one currency/i)).toBeInTheDocument();
    // …and NOT the "nobody declared a value" sentence, which is a different claim.
    expect(within(card).queryByText(/No affected journey declares a value/i)).toBeNull();
    expect(within(card).queryByText("0")).toBeNull();
  });

  it("survives an incident row whose impact is entirely unmeasured", async () => {
    setup({
      overview: overview({
        incidents: [summary({
          journey_success_pct: undefined, business_impact: undefined, currency: undefined,
          owner: undefined, leading_cause: undefined, likely_layer: undefined,
        })],
      }),
    });
    render(<ExperiencePage />);
    const table = await screen.findByRole("region", { name: /Active experience incidents/i });
    expect(within(table).getByText("Owner not determined")).toBeInTheDocument();
    expect(within(table).getByText("No cause has enough evidence yet")).toBeInTheDocument();
    expect(within(table).getByText("Not placed on the path")).toBeInTheDocument();
  });
});

// ── 10. the AI panel is disabled with a reason, never hidden ────────────────

describe("the AI investigator panel", () => {
  it("renders disabled with the server's reason when it is unavailable", async () => {
    setup();
    render(<ExperiencePage />);
    const panel = await screen.findByRole("region", { name: "AI investigator" });
    expect(within(panel).getByText("Unavailable")).toBeInTheDocument();
    expect(within(panel).getByText(/switched off for this deployment/i)).toBeInTheDocument();
    expect(within(panel).getByRole("button", { name: /Explain the evidence/i })).toBeDisabled();
  });

  it("enables it when the deployment has it", async () => {
    setup({ overview: overview({ ai_investigator: { available: true } }) });
    render(<ExperiencePage />);
    const panel = await screen.findByRole("region", { name: "AI investigator" });
    expect(within(panel).getByRole("button", { name: /Explain the evidence/i })).not.toBeDisabled();
    // Even when it is on, what it may claim is stated on the panel.
    expect(within(panel).getByText(/can never move a cause to confirmed/i)).toBeInTheDocument();
  });
});

// ── accessibility ───────────────────────────────────────────────────────────

describe("accessibility", () => {
  it("exposes the tab list, the selected tab and the measurement window", async () => {
    setup();
    render(<ExperiencePage />);
    const tablist = await screen.findByRole("tablist", { name: /Digital Experience/i });
    expect(within(tablist).getAllByRole("tab")).toHaveLength(7);
    expect(screen.getByRole("tab", { name: "Experience" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("button", { name: /Measure over the last 24h/i })).toBeInTheDocument();
  });

  it("gives every incident row a keyboard-reachable control that opens it", async () => {
    setup();
    goto("#/operations/digital-experience/incidents");
    render(<ExperiencePage />);
    const row = await screen.findByRole("button", { name: /Checkout is failing from Berlin/i });
    fireEvent.click(row);
    expect(await screen.findByRole("region", { name: /Incident header/i })).toBeInTheDocument();
  });

  it("labels every control the operator types into on the journey editor", async () => {
    setup();
    goto("#/operations/digital-experience/journeys");
    render(<ExperiencePage />);
    fireEvent.click(await screen.findByRole("button", { name: /Declare a journey/i }));
    expect(screen.getByLabelText("Name")).toBeInTheDocument();
    expect(screen.getByLabelText("Business importance")).toBeInTheDocument();
    expect(screen.getByLabelText("Objective, success percent")).toBeInTheDocument();
    expect(screen.getByLabelText("Currency")).toBeInTheDocument();
    expect(screen.getByLabelText("Measured by")).toBeInTheDocument();
  });

  it("refuses a value with no currency, and says why", async () => {
    setup();
    goto("#/operations/digital-experience/journeys");
    render(<ExperiencePage />);
    fireEvent.click(await screen.findByRole("button", { name: /Declare a journey/i }));
    fireEvent.change(screen.getByLabelText("Value of one successful traversal"),
      { target: { value: "50" } });
    expect(screen.getByText(/An unlabelled number is not an amount/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Declare journey" })).toBeDisabled();
  });
});

// ── copy guards on this surface's own sources ───────────────────────────────

describe("copy guards on the Digital Experience sources", () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const files = readdirSync(here).filter((f) => /\.tsx?$/.test(f) && !f.includes(".test."));

  it("finds the surface's files (a broken walk must not pass silently)", () => {
    expect(files.length).toBeGreaterThan(8);
  });

  it("shows no denied developer-speak", () => {
    const hits = files.flatMap((f) =>
      scanCopy(readFileSync(join(here, f), "utf-8"), `pages/experience/${f}`));
    expect(hits, hits.join("\n")).toEqual([]);
  });

  it("never puts the engine word on screen", () => {
    const hits = files.flatMap((f) =>
      scanForEngineVocabulary(readFileSync(join(here, f), "utf-8"), `pages/experience/${f}`));
    expect(hits, hits.join("\n")).toEqual([]);
  });
});
