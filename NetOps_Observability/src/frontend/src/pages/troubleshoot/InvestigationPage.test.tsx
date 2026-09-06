// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// InvestigationPage.test.tsx — the Troubleshooting surface, THREE blocks.
//
// The shape under test (owner, 2026-09-06 — "There are two sections which look
// similar, one place we can describe the problem but cannot do anything its
// just fixed page and then cases where we can escalate or open ticket … simplify
// these pages and make it intuitive"):
//
//   1 What's wrong?      2 The answer      3 The evidence
//
// The things that must never regress:
//  · ONE WAY IN — a single list holds every open case, correlated or described.
//    There is no symptom picker, no second tab, no separate describe-only mode.
//  · DESCRIBING CREATES A CASE — the box posts to the incident seam and the new
//    record is selected immediately, so the actions work on it at once.
//  · ONE ANSWER — headline, "Breaking at", "Affects", "Since", one confidence
//    chip and exactly three actions. Nothing else above the evidence.
//  · ONE DISCLOSURE — the evidence is COLLAPSED by default, and collapsing it
//    does not stop the lanes looking (that is what earns "Breaking at"). A quiet
//    lane collapses to one line; it is never dropped.
//  · HONESTY — an unwired source says it has no data source, a failed case read
//    is shown verbatim instead of an eternal spinner, and a verdict is never
//    upgraded past what the engine said.
//
// The lanes are the REAL lane components against a mocked api, so the answer
// card's layer line is asserted end-to-end rather than through a stub.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, within, act } from "@testing-library/react";
import type { CorrObject, Incident, PathHealthItem } from "../../services/api";
import { ShellContext, type ShellState } from "../../context/shell";
import { signal, timeline, corrObject } from "../../test/factories";

const mocks = vi.hoisted(() => ({
  // block 1
  correlations: vi.fn(), listIncidents: vi.fn(), createIncident: vi.fn(),
  seams: vi.fn(), getSeamOwners: vi.fn(),
  // block 2
  correlationDetail: vi.fn(), correlationTimeline: vi.fn(),
  correlationTickets: vi.fn(), correlationTicketCreate: vi.fn(),
  // block 3 — the lanes
  pathsHealth: vi.fn(), eventsFeed: vi.fn(), metricNames: vi.fn(), metricsQuery: vi.fn(),
  probePaths: vi.fn(), flowsByType: vi.fn(), topTalkers: vi.fn(),
  // iris + the TAC escalation panel that hangs off the answer
  aiAsk: vi.fn(), devices: vi.fn(), permissions: vi.fn(),
  tacState: vi.fn(), tacClassify: vi.fn(),
}));

// The un-promoted-RCA policy error is a CLASS other pages test with instanceof,
// so the mocked module must still export the same constructor shape.
const errs = vi.hoisted(() => {
  class FakeNotPromoted extends Error {
    constructor(public reason: string) { super(reason); this.name = "RcaNotPromotedError"; }
  }
  return { FakeNotPromoted };
});

vi.mock("../../services/api", () => ({
  api: { ...mocks },
  RcaNotPromotedError: errs.FakeNotPromoted,
}));

import InvestigationPage, { caseDevice } from "./InvestigationPage";
import { ALL_LANES, LANE_TITLE, type LaneId } from "./investigationModel";

// ── fixtures ─────────────────────────────────────────────────────────────────

const CASE_ID = "corr-abc1234567890";
const HYPOTHESES = JSON.stringify({
  ranking: { hypotheses: [{ id: "upstream_link_fault", verdict: { owner: "isp", first_steps: ["Call the carrier"] } }] },
});

const openCase = (over: Partial<CorrObject> = {}): CorrObject => corrObject({
  correlation_id: CASE_ID,
  top_hypothesis: "upstream_link_fault",
  verdict_tier: "suspected",
  top_confidence: 0.62,
  hypotheses: HYPOTHESES,
  affected: JSON.stringify({ devices: ["wan-r2"], sites: ["dc1"] }),
  ...over,
});

const caseTimeline = () => timeline({
  correlation_id: CASE_ID,
  top_hypothesis: "upstream_link_fault",
  signals: [signal({ kind: "bgp_state_anomaly", modality_class: "control_plane", entity_id: "wan-r2" })],
});

const investigation = (over: Partial<Incident> = {}): Incident => ({
  id: "inc-77", tenant_id: "t1", title: "Branch users cannot reach the CRM",
  severity: "medium", status: "open", source_type: "manual", occurrences: 1,
  created_at: "2026-09-06 11:00:00", updated_at: "2026-09-06 11:00:00",
  first_seen_at: "2026-09-06 11:00:00", last_seen_at: "2026-09-06 11:00:00",
  sync_status: "none", ...over,
});

const pathHealth = (over: Partial<PathHealthItem> = {}): PathHealthItem => ({
  path_id: "p1", agent: "probe-a", dst: "10.0.0.1", health_state: "degraded", score: 40,
  confidence: "medium", severities: {}, baseline_source: "rolling", reason: "loss above baseline",
  likely_fault_domain: "wan", evidence: [],
  current: { latency_p95_5m: 30, jitter_p95_5m: 3, loss_pct_5m: 1 },
  baseline: { source: "rolling", source_label: "7d", window: "7d", sample_count: 100, latency_p50: 20, latency_p99: 40, jitter_p50: 2, jitter_p99: 5 },
  ...over,
});

const shell = (over: Partial<ShellState> = {}): ShellState => ({
  range: { label: "Last 1 hour", minutes: 60 }, setRange: vi.fn(),
  query: "", setQuery: vi.fn(),
  copilotOpen: false, setCopilotOpen: vi.fn(),
  helpOpen: false, setHelpOpen: vi.fn(), helpPath: "", openHelp: vi.fn(),
  navigate: vi.fn(), ...over,
});

/** Render and let every fetch settle inside act(). */
async function show(ui: React.ReactElement) {
  const utils = render(ui);
  await act(async () => { await Promise.resolve(); });
  return utils;
}

const click = async (name: string | RegExp) => {
  await act(async () => { fireEvent.click(screen.getByRole("button", { name })); });
};
const laneSlot = (id: LaneId) => document.querySelector(`[data-lane="${id}"]`)?.closest(".ts-lane-slot");
const answer = () => screen.getByTestId("ts-answer");
const blockHeadings = () => Array.from(document.querySelectorAll(".ts-block-h")).map((el) => el.textContent?.trim());
/** Pick the one correlated case from the single list. */
const pickCase = async () => { await click(/Link state change/); };

beforeEach(() => {
  Object.values(mocks).forEach((f) => f.mockReset());
  mocks.correlations.mockResolvedValue({ data: [openCase()] });
  mocks.listIncidents.mockResolvedValue([]);
  mocks.createIncident.mockResolvedValue({ incident: investigation(), created: true });
  mocks.seams.mockResolvedValue([]);
  mocks.getSeamOwners.mockResolvedValue({ seam_owners: { isp: { name: "Lumen" } } });
  mocks.correlationDetail.mockResolvedValue({ object: openCase(), edges: [] });
  mocks.correlationTimeline.mockResolvedValue(caseTimeline());
  mocks.correlationTickets.mockResolvedValue({ status: { state: "none" }, audit: [] });
  mocks.correlationTicketCreate.mockResolvedValue({ system: "servicenow" });
  mocks.pathsHealth.mockResolvedValue({ paths: [pathHealth()], count: 1 });
  mocks.eventsFeed.mockResolvedValue({ items: [] });
  mocks.metricNames.mockResolvedValue({ status: "success", data: ["device_if_oper_status", "device_bgp_peer_state"] });
  mocks.metricsQuery.mockResolvedValue({ status: "success", data: { resultType: "vector", result: [] } });
  mocks.probePaths.mockResolvedValue([]);
  mocks.flowsByType.mockResolvedValue({ data: [] });
  mocks.topTalkers.mockResolvedValue({ data: [] });
  mocks.aiAsk.mockResolvedValue({ mode: "grounded", intent: "x", modules: [], text: "ok", citations: [], disclaimers: [] });
  mocks.devices.mockResolvedValue([]);
  // Nothing has been escalated in these fixtures — the state the panel renders
  // its one "Escalate to TAC" button for.
  mocks.tacState.mockResolvedValue({
    incident_id: CASE_ID, incident_ref: "INC-2026-0007", title: "",
    can_collect: false, collect_note: "Live collection is not wired on this deployment.",
    catalog_version: "correlix-tac-classes-2026-09-05", connectors: [], devices: ["wan-r2"],
    state: null, state_note: "This incident has not been escalated in this api process.",
  });
});
afterEach(() => cleanup());

// ── the three blocks ─────────────────────────────────────────────────────────

describe("the three blocks", () => {
  it("opens with ONLY the picker — no answer and no evidence until something is picked", async () => {
    await show(<InvestigationPage />);
    expect(blockHeadings()).toEqual(["What's wrong?"]);
    expect(screen.queryByTestId("ts-answer-block")).toBeNull();
    expect(screen.queryByTestId("ts-evidence")).toBeNull();
  });

  it("renders the three blocks in order once a case is picked", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    expect(blockHeadings()).toEqual(["What's wrong?", "The evidence"]);
    const blocks = Array.from(document.querySelectorAll(".ts-block"));
    expect(blocks.map((b) => b.getAttribute("data-testid")))
      .toEqual(["ts-pick", "ts-answer-block", "ts-evidence"]);
  });

  it("carries NONE of the retired scaffolding", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    // no "How this page works", no numbered steps, no ladder, no quiet toggle
    expect(screen.queryByRole("heading", { name: /how this page works/i })).toBeNull();
    expect(document.querySelector(".ts-step")).toBeNull();
    expect(document.querySelector("[data-rung]")).toBeNull();
    expect(screen.queryByTestId("ts-quiet-toggle")).toBeNull();
    // no symptom picker and no second tab
    expect(screen.queryByRole("list", { name: "Symptom" })).toBeNull();
    expect(screen.queryByRole("group", { name: "How to start" })).toBeNull();
    // no per-lane "Details" button anywhere
    expect(screen.queryAllByRole("button", { name: /^Details$/ })).toHaveLength(0);
  });

  it("puts ONE Ask Iris explanation on the picker heading, not a paragraph of prose", async () => {
    await show(<InvestigationPage />);
    const asks = Array.from(document.querySelectorAll("button.ask-iris"));
    expect(asks).toHaveLength(1);
    expect(asks[0].getAttribute("data-topic")).toBe("investigate.how");
  });
});

// ── block 1: one way in ──────────────────────────────────────────────────────

describe("block 1 — what's wrong?", () => {
  it("lists correlated cases and described investigations in ONE list", async () => {
    mocks.listIncidents.mockResolvedValue([investigation()]);
    await show(<InvestigationPage />);
    const list = screen.getByRole("list", { name: "Open cases" });
    const rows = within(list).getAllByRole("button");
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent("Link state change");   // NOC words, not "upstream_link_fault"
    expect(rows[0]).toHaveTextContent("Likely");              // one-word state chip
    expect(rows[0]).toHaveTextContent("1 device, 1 site");    // who it touches
    expect(rows[1]).toHaveTextContent("Branch users cannot reach the CRM");
    expect(rows[1]).toHaveTextContent("Described");
  });

  it("says plainly when nothing is open — never a blank column", async () => {
    mocks.correlations.mockResolvedValue({ data: [] });
    await show(<InvestigationPage />);
    expect(screen.getByText("No open case right now.")).toBeInTheDocument();
  });

  it("renders the case-list failure verbatim", async () => {
    mocks.correlations.mockRejectedValue(new Error("403 correlations forbidden"));
    await show(<InvestigationPage />);
    expect(await screen.findByRole("alert")).toHaveTextContent("403 correlations forbidden");
  });

  it("still lists the correlated cases when the incident store is absent", async () => {
    mocks.listIncidents.mockRejectedValue(new Error("409 no incident store"));
    await show(<InvestigationPage />);
    expect(within(screen.getByRole("list", { name: "Open cases" })).getAllByRole("button")).toHaveLength(1);
  });
});

// ── describing a problem CREATES a case ──────────────────────────────────────

describe("describing a problem", () => {
  const describeIt = async (text: string) => {
    fireEvent.change(screen.getByLabelText("Not listed? Describe it"), { target: { value: text } });
    await click("Start investigation");
  };

  it("creates a record through the incident seam and sends NO tenant", async () => {
    await show(<InvestigationPage />);
    await describeIt("  Branch users cannot   reach the CRM ");
    expect(mocks.createIncident).toHaveBeenCalledWith({ title: "Branch users cannot reach the CRM" });
    const [[body]] = mocks.createIncident.mock.calls;
    expect(Object.keys(body)).toEqual(["title"]);   // the owner is stamped server-side
  });

  it("selects the new record at once, so every action works on it", async () => {
    await show(<InvestigationPage />);
    await describeIt("Branch users cannot reach the CRM");
    // it joined the same list, selected
    const row = screen.getByRole("button", { name: /Branch users cannot reach the CRM/ });
    expect(row).toHaveAttribute("aria-pressed", "true");
    // and the answer block is open on it
    expect(screen.getByTestId("ts-answer-block")).toBeInTheDocument();
    await click("Escalate to TAC");
    expect(mocks.tacState).toHaveBeenCalledWith("inc-77");
  });

  it("answers honestly on a described case — no cause, and nothing invented", async () => {
    await show(<InvestigationPage />);
    await describeIt("Branch users cannot reach the CRM");
    expect(answer()).toHaveTextContent("No cause confirmed yet");
    expect(answer()).toHaveTextContent("Affects: Nothing named yet");
    expect(screen.getByTestId("ts-confidence")).toHaveTextContent("Not scored");
    expect(mocks.correlationDetail).not.toHaveBeenCalled();
  });

  it("refuses to start on words that say nothing", async () => {
    await show(<InvestigationPage />);
    expect(screen.getByRole("button", { name: "Start investigation" })).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Not listed? Describe it"), { target: { value: "   " } });
    expect(screen.getByRole("button", { name: "Start investigation" })).toBeDisabled();
    expect(mocks.createIncident).not.toHaveBeenCalled();
  });

  it("reports a refused create in the operator's words and picks nothing", async () => {
    mocks.createIncident.mockRejectedValue(new Error("403 Forbidden: alerts:write required"));
    await show(<InvestigationPage />);
    await describeIt("Something is wrong");
    const alert = await screen.findByRole("alert");
    // the server's own sentence survives; the HTTP envelope does not
    expect(alert).toHaveTextContent(/alerts:write required/i);
    expect(alert.textContent).not.toContain("403");
    expect(screen.queryByTestId("ts-answer-block")).toBeNull();
  });
});

// ── block 2: one answer card ─────────────────────────────────────────────────

describe("block 2 — the answer", () => {
  it("leads with the engine's verdict in plain words, never upgraded", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await waitFor(() => expect(answer()).toHaveAttribute("data-answer", "likely"));
    expect(answer().textContent).not.toContain("upstream_link_fault");
  });

  it("carries the four facts and one confidence chip", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await waitFor(() => expect(answer()).toHaveTextContent("Affects: 1 device, 1 site"));
    expect(answer()).toHaveTextContent(/Breaking at:/);
    expect(answer()).toHaveTextContent(/Since:/);
    expect(answer()).toHaveTextContent("Lumen");                     // owner, from the registry
    expect(screen.getByTestId("ts-confidence")).toHaveTextContent("Medium confidence");
  });

  it("names the layer a lane actually found something on", async () => {
    // one interface down → the health lane is ready → the physical layer
    mocks.metricsQuery.mockResolvedValue({
      status: "success",
      data: { resultType: "vector", result: [{ metric: { device: "wan-r2", ifName: "Gi0/1" }, value: [0, "0"] }] },
    });
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await waitFor(() => expect(answer()).toHaveTextContent("Breaking at: Physical link"));
  });

  it("says Unknown rather than guessing a layer nothing points at", async () => {
    mocks.pathsHealth.mockResolvedValue({ paths: [], count: 0 });
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await waitFor(() => expect(answer()).toHaveTextContent("Breaking at: Unknown"));
  });

  it("offers exactly three actions", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    const actions = screen.getByTestId("ts-actions");
    expect(within(actions).getAllByRole("button").map((b) => b.textContent))
      .toEqual(["Ask Iris", "Open ticket", "Escalate to TAC"]);
  });

  it("says the case is being read, then renders the answer", async () => {
    let resolve!: (v: unknown) => void;
    mocks.correlationDetail.mockReturnValue(new Promise((r) => { resolve = r; }));
    render(<InvestigationPage initialCaseId={CASE_ID} />);
    expect(screen.getByTestId("ts-case-loading")).toBeInTheDocument();
    await act(async () => { resolve({ object: openCase(), edges: [] }); });
    await waitFor(() => expect(screen.queryByTestId("ts-case-loading")).toBeNull());
  });

  it("renders a failed case read VERBATIM instead of spinning forever", async () => {
    mocks.correlationDetail.mockRejectedValue(new Error("404 correlation not found"));
    mocks.correlationTimeline.mockRejectedValue(new Error("404 correlation not found"));
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    const err = await screen.findByTestId("ts-case-error");
    expect(err).toHaveTextContent("404 correlation not found");
    expect(screen.queryByTestId("ts-case-loading")).toBeNull();
  });

  it("fetches the case, its timeline and its ticket state", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    expect(mocks.correlationDetail).toHaveBeenCalledWith(CASE_ID);
    expect(mocks.correlationTimeline).toHaveBeenCalledWith(CASE_ID);
    expect(mocks.correlationTickets).toHaveBeenCalledWith(CASE_ID);
  });
});

// ── the three actions ────────────────────────────────────────────────────────

describe("the actions", () => {
  it("opens Iris in place, grounded on the case, and asks once", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    expect(screen.queryByRole("region", { name: "Ask Iris" })).toBeNull();
    await click("Ask Iris");
    expect(await screen.findByRole("region", { name: "Ask Iris" })).toBeInTheDocument();
    await waitFor(() => expect(mocks.aiAsk).toHaveBeenCalledTimes(1));
    expect(mocks.aiAsk).toHaveBeenCalledWith(expect.any(String), { correlation_id: CASE_ID });
    await click("Close Iris");
    expect(screen.queryByRole("region", { name: "Ask Iris" })).toBeNull();
  });

  it("offers 'Open Iris' only inside the shell, and opens the docked drawer", async () => {
    const st = shell();
    await show(
      <ShellContext.Provider value={st}>
        <InvestigationPage initialCaseId={CASE_ID} />
      </ShellContext.Provider>,
    );
    await click("Ask Iris");
    fireEvent.click(screen.getByRole("button", { name: "Open Iris" }));
    expect(st.setCopilotOpen).toHaveBeenCalledWith(true);
  });

  it("creates a ticket and re-reads the authoritative state instead of inventing a number", async () => {
    mocks.correlationTickets
      .mockResolvedValueOnce({ status: { state: "none" }, audit: [] })
      .mockResolvedValueOnce({ status: { state: "open", ticket_number: "INC0012345" }, audit: [] });
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await waitFor(() => expect(mocks.correlationDetail).toHaveBeenCalled());
    await click("Open ticket");
    expect(mocks.correlationTicketCreate).toHaveBeenCalledWith(CASE_ID);
    expect(await screen.findByText(/Ticket request enqueued to servicenow\./)).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "Ticket INC0012345" })).toBeInTheDocument();
  });

  it("reports a ticket failure verbatim", async () => {
    mocks.correlationTicketCreate.mockRejectedValue(new Error("ticketing not configured"));
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await waitFor(() => expect(mocks.correlationDetail).toHaveBeenCalled());
    await click("Open ticket");
    expect(await screen.findByText("Could not create a ticket: ticketing not configured")).toBeInTheDocument();
  });

  it("says why a ticket needs a correlated case, rather than failing silently", async () => {
    mocks.listIncidents.mockResolvedValue([investigation()]);
    await show(<InvestigationPage />);
    await click(/Branch users cannot reach the CRM/);
    expect(screen.getByRole("button", { name: "Open ticket" })).toBeDisabled();
    expect(screen.getByText("A ticket needs a correlated case.")).toBeInTheDocument();
  });

  it("opens the TAC escalation on demand rather than sitting open", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await waitFor(() => expect(mocks.correlationDetail).toHaveBeenCalled());
    expect(screen.queryByLabelText("Escalate to TAC")).toBeNull();
    await click("Escalate to TAC");
    expect(await screen.findByLabelText("Escalate to TAC")).toBeInTheDocument();
    expect(mocks.tacState).toHaveBeenCalledWith(CASE_ID);
    await click("Close TAC escalation");
    expect(screen.queryByLabelText("Escalate to TAC")).toBeNull();
  });
});

// ── block 3: one disclosure ──────────────────────────────────────────────────

describe("block 3 — the evidence", () => {
  it("is COLLAPSED by default", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    const toggle = screen.getByRole("button", { name: "Show the evidence" });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(document.getElementById("ts-ev-body")).toHaveAttribute("hidden");
  });

  it("opens and closes on the one toggle", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await click("Show the evidence");
    expect(document.getElementById("ts-ev-body")).not.toHaveAttribute("hidden");
    await click("Hide the evidence");
    expect(document.getElementById("ts-ev-body")).toHaveAttribute("hidden");
  });

  it("keeps every lane LOOKING while collapsed — that is what earns the answer", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    // collapsed, yet every lane's API ran
    expect(document.getElementById("ts-ev-body")).toHaveAttribute("hidden");
    expect(mocks.pathsHealth).toHaveBeenCalled();
    expect(mocks.metricNames).toHaveBeenCalled();
    expect(mocks.probePaths).toHaveBeenCalled();
    expect(mocks.flowsByType).toHaveBeenCalled();
    expect(mocks.eventsFeed).toHaveBeenCalled();
  });

  it("opens EVERY lane — the engine did not pre-narrow the evidence", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await click("Show the evidence");
    expect(Array.from(document.querySelectorAll("[data-lane]")).map((el) => el.getAttribute("data-lane")))
      .toEqual([...ALL_LANES]);
  });

  it("shows a lane with rows and collapses a quiet one to ONE line", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await click("Show the evidence");
    // DEM has a path → shown; flows have no exporter → quiet
    await waitFor(() => expect(laneSlot("dem")).toHaveAttribute("data-quiet", "no"));
    expect(laneSlot("flows")).toHaveAttribute("data-quiet", "yes");
    expect(laneSlot("flows")).toHaveAttribute("hidden");
    const quiet = screen.getByTestId("ts-quiet");
    expect(quiet).toHaveTextContent(`Nothing feeds ${LANE_TITLE.flows}`);
  });

  it("keeps a quiet lane's API call — hidden is never skipped", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await waitFor(() => expect(mocks.flowsByType).toHaveBeenCalled());
    expect(mocks.topTalkers).toHaveBeenCalled();
  });

  it("renders a lane's rows with no second Details click", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await click("Show the evidence");
    const dem = await screen.findByRole("region", { name: LANE_TITLE.dem });
    expect(within(dem).getByText(/probe-a/)).toBeInTheDocument();
    expect(within(dem).queryByRole("button", { name: "Details" })).toBeNull();
  });

  it("puts the engine's own RCA header INSIDE the same disclosure", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    // it is not above the fold
    expect(document.getElementById("ts-ev-body")).toHaveAttribute("hidden");
    await click("Show the evidence");
    const header = await screen.findByTestId("ts-rca-header");
    expect(header.querySelector(".rw-case")).not.toBeNull();
    expect(header).toHaveTextContent("RCA ID:");
    // there is no SECOND disclosure inside the first
    expect(screen.queryByRole("button", { name: /Full RCA detail/ })).toBeNull();
  });

  it("scopes the lanes to the case's first affected device", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await waitFor(() => expect(mocks.eventsFeed).toHaveBeenCalledWith(expect.objectContaining({ entity: "wan-r2" })));
  });

  it("passes the shell's range down to the lanes", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} rangeMinutes={1440} />);
    await waitFor(() => expect(mocks.eventsFeed).toHaveBeenCalledWith(expect.objectContaining({ from: "24h" })));
  });

  it("keeps 'we cannot see this' distinct from 'we looked and saw nothing'", async () => {
    // no probe has ever reported (not_connected) while the event feed IS wired
    // and was simply quiet (empty). Both collapse to one line — different lines.
    mocks.pathsHealth.mockResolvedValue({ paths: [], count: 0 });
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await click("Show the evidence");
    const quiet = await screen.findByTestId("ts-quiet");
    await waitFor(() => expect(quiet).toHaveTextContent(`Nothing feeds ${LANE_TITLE.dem}`));
    expect(quiet).toHaveTextContent(`Nothing from ${LANE_TITLE.events}`);
    expect(document.querySelector(`[data-lane="${"dem"}"]`)?.getAttribute("data-state")).toBe("not_connected");
  });
});

// ── picking, outside the shell, deep links ───────────────────────────────────

describe("picking", () => {
  it("switches from one case to another and re-reads the new one", async () => {
    mocks.listIncidents.mockResolvedValue([investigation()]);
    await show(<InvestigationPage />);
    await pickCase();
    await waitFor(() => expect(mocks.correlationDetail).toHaveBeenCalledWith(CASE_ID));
    await click(/Branch users cannot reach the CRM/);
    expect(screen.getByRole("button", { name: /Branch users cannot reach the CRM/ }))
      .toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: /Link state change/ })).toHaveAttribute("aria-pressed", "false");
  });

  it("renders with no shell provider and does not crash", async () => {
    await show(<InvestigationPage />);
    expect(screen.getByRole("heading", { name: /What's wrong\?/, level: 2 })).toBeInTheDocument();
  });

  it("opens the case a deep link named", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    expect(screen.getByRole("button", { name: /Link state change/ })).toHaveAttribute("aria-pressed", "true");
  });
});

// ── caseDevice ───────────────────────────────────────────────────────────────

describe("caseDevice", () => {
  it("takes the first named device off the case", () => {
    expect(caseDevice(openCase())).toBe("wan-r2");
  });

  it("treats a malformed or empty affected blob as no scope, never a throw", () => {
    expect(caseDevice(null)).toBe("");
    expect(caseDevice(corrObject({ affected: "not json" }))).toBe("");
    expect(caseDevice(corrObject({ affected: JSON.stringify({ devices: [] }) }))).toBe("");
    expect(caseDevice(corrObject({ affected: JSON.stringify({ devices: ["  ", "wan-r9"] }) }))).toBe("wan-r9");
    expect(caseDevice(corrObject({ affected: JSON.stringify({ devices: [{ id: "x" }] }) }))).toBe("");
  });
});

// ── onset ────────────────────────────────────────────────────────────────────

describe("the Since line", () => {
  it("falls back to the case object when the case is older than the list window", async () => {
    mocks.correlations.mockResolvedValue({ data: [] });  // not in the open list
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await waitFor(() => expect(answer()).not.toHaveTextContent("Since: Not stated"));
  });

  it("says Not stated rather than inventing an onset", async () => {
    mocks.correlations.mockResolvedValue({ data: [] });
    mocks.correlationDetail.mockResolvedValue({
      object: openCase({ window_start: "", created_at: "" }), edges: [],
    });
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await waitFor(() => expect(answer()).toHaveTextContent("Since: Not stated"));
  });
});
