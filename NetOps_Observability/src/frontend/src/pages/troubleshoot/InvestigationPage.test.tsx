// InvestigationPage.test.tsx — the guided Troubleshooting surface.
//
// The shape under test (owner, 2026-09-06 — "this page doesn't make sense,
// what's the goal of this page"): FOUR NUMBERED STEPS, in order.
//
//   1 What's wrong?          2 Where is it breaking?
//   3 Evidence               4 Answer & next action
//
// The things that must never regress:
//  · ORDER — the four steps render, numbered, in that sequence. A NOC admin can
//    follow the page top to bottom without training.
//  · DENSITY — quiet lanes (nothing seen / nothing feeding us) are hidden behind
//    ONE toggle, and every lane's raw material sits behind its own "Details".
//    Hidden is never deleted: the API still runs and the operator can open it.
//  · POSITIONING — picking a CASE still builds the SAME RcaCaseHeader the RCA
//    workspace builds (one verdict vocabulary, not two); it now lives behind
//    step 4's "Full RCA detail" so the plain answer leads. Picking only a
//    SYMPTOM says honestly that we do not have the cause, and the ladder's rungs
//    are earned by lane state, never by being on screen.
//  · HONESTY — an unwired source says it has no data source, a quiet one says it
//    was quiet, and a failure is shown instead of an eternal spinner.
//  · CAPABILITY — nothing was removed: ticket, TAC escalation, Correlate, the
//    report, Iris and all seven lanes are still reachable.
//
// The lanes are the REAL lane components against a mocked api, so the ladder is
// asserted end-to-end rather than through a stub.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, within, act } from "@testing-library/react";
import type { CorrObject, PathHealthItem } from "../../services/api";
import { ShellContext, type ShellState } from "../../context/shell";
import { signal, timeline, corrObject } from "../../test/factories";

const mocks = vi.hoisted(() => ({
  // investigation page
  correlations: vi.fn(), seams: vi.fn(), getSeamOwners: vi.fn(),
  correlationDetail: vi.fn(), correlationTimeline: vi.fn(),
  correlationTickets: vi.fn(), correlationTicketCreate: vi.fn(), downloadRcaReport: vi.fn(),
  // lanes
  pathsHealth: vi.fn(), eventsFeed: vi.fn(), metricNames: vi.fn(), metricsQuery: vi.fn(),
  probePaths: vi.fn(), flowsByType: vi.fn(), topTalkers: vi.fn(),
  // iris + the TAC escalation panel that hangs off the verdict
  aiAsk: vi.fn(), devices: vi.fn(), permissions: vi.fn(),
  tacState: vi.fn(), tacClassify: vi.fn(),
  exportRcaPdf: vi.fn(),
}));

// The un-promoted-RCA policy error is a CLASS the page tests with instanceof,
// so the mocked module must export the same constructor the page imports.
const errs = vi.hoisted(() => {
  class FakeNotPromoted extends Error {
    constructor(public reason: string) { super(reason); this.name = "RcaNotPromotedError"; }
  }
  return { FakeNotPromoted };
});
const FakeNotPromoted = errs.FakeNotPromoted;

vi.mock("../../services/api", () => ({
  api: { ...mocks },
  RcaNotPromotedError: errs.FakeNotPromoted,
}));
vi.mock("../../components/rca/rcaExport", () => ({ exportRcaPdf: (...a: unknown[]) => mocks.exportRcaPdf(...a) }));

import InvestigationPage, { caseDevice, tierLabel } from "./InvestigationPage";
import { LANE_TITLE, lanesForSymptom, type LaneId } from "./investigationModel";

// ── fixtures ─────────────────────────────────────────────────────────────────

const CASE_ID = "corr-abc1234567890";
const HYPOTHESES = JSON.stringify({
  ranking: { hypotheses: [{ id: "upstream_link_fault", verdict: { owner: "isp", first_steps: ["Call the carrier"] } }] },
});

const openCase = (over: Partial<CorrObject> = {}): CorrObject => corrObject({
  correlation_id: CASE_ID,
  top_hypothesis: "upstream_link_fault",
  verdict_tier: "suspected",
  hypotheses: HYPOTHESES,
  affected: JSON.stringify({ devices: ["wan-r2"] }),
  ...over,
});

const caseTimeline = () => timeline({
  correlation_id: CASE_ID,
  top_hypothesis: "upstream_link_fault",
  signals: [signal({ kind: "bgp_state_anomaly", modality_class: "control_plane", entity_id: "wan-r2" })],
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

/** Render and let every lane's fetch settle inside act(). */
async function show(ui: React.ReactElement) {
  const utils = render(ui);
  await act(async () => { await Promise.resolve(); });
  return utils;
}

const laneIds = () => Array.from(document.querySelectorAll("[data-lane]"))
  .map((el) => el.getAttribute("data-lane"));
const rung = (id: string) => document.querySelector(`[data-rung="${id}"]`);
/** The step headings, in DOM order — the page's order of operations. */
const stepHeadings = () => Array.from(document.querySelectorAll(".ts-step .ts-step-h"))
  .map((el) => el.textContent);
const laneSlot = (id: LaneId) => document.querySelector(`[data-lane="${id}"]`)?.closest(".ts-lane-slot");
const click = async (name: string | RegExp) => {
  await act(async () => { fireEvent.click(screen.getByRole("button", { name })); });
};
/** Step 1 is one control with two tabs — a case is picked on the second. */
const pickCase = async () => {
  await click("Open cases (1)");
  await click(/P-CORRAB/);
};

beforeEach(() => {
  Object.values(mocks).forEach((f) => f.mockReset());
  mocks.correlations.mockResolvedValue({ data: [openCase()] });
  mocks.seams.mockResolvedValue([]);
  mocks.getSeamOwners.mockResolvedValue({ seam_owners: { isp: { name: "Lumen" } } });
  mocks.correlationDetail.mockResolvedValue({ object: openCase(), edges: [] });
  mocks.correlationTimeline.mockResolvedValue(caseTimeline());
  mocks.correlationTickets.mockResolvedValue({ status: { state: "none" }, audit: [] });
  mocks.correlationTicketCreate.mockResolvedValue({ system: "servicenow" });
  mocks.downloadRcaReport.mockResolvedValue("pdf");
  mocks.pathsHealth.mockResolvedValue({ paths: [pathHealth()], count: 1 });
  mocks.eventsFeed.mockResolvedValue({ items: [] });
  mocks.metricNames.mockResolvedValue({ status: "success", data: ["device_if_oper_status", "device_bgp_peer_state"] });
  mocks.metricsQuery.mockResolvedValue({ status: "success", data: { resultType: "vector", result: [] } });
  mocks.probePaths.mockResolvedValue([]);
  mocks.flowsByType.mockResolvedValue({ data: [] });
  mocks.topTalkers.mockResolvedValue({ data: [] });
  mocks.aiAsk.mockResolvedValue({ mode: "grounded", intent: "x", modules: [], text: "ok", citations: [], disclaimers: [] });
  mocks.exportRcaPdf.mockReturnValue(true);
  mocks.devices.mockResolvedValue([]);
  // The escalation panel reads the incident's escalation state as soon as it is
  // opened. Nothing has been escalated in these fixtures, which is the state
  // the panel renders its one "Escalate to TAC" button for.
  mocks.tacState.mockResolvedValue({
    incident_id: CASE_ID, incident_ref: "INC-2026-0007", title: "",
    can_collect: false, collect_note: "Live collection is not wired on this deployment.",
    catalog_version: "correlix-tac-classes-2026-09-05", connectors: [], devices: ["wan-r2"],
    state: null, state_note: "This incident has not been escalated in this api process.",
  });
});
afterEach(() => cleanup());

// ── the guided flow: four numbered steps, in order ───────────────────────────

describe("the guided flow", () => {
  it("opens with a three-line 'How this page works' in plain words", async () => {
    await show(<InvestigationPage />);
    const how = screen.getByRole("heading", { name: "How this page works", level: 2 });
    const list = how.parentElement!.querySelector("ol")!;
    expect(list.querySelectorAll("li")).toHaveLength(3);
    expect(list).toHaveTextContent(/pick the problem you are seeing/i);
    expect(list).toHaveTextContent(/checks each layer of the network for you/i);
    expect(list).toHaveTextContent(/a likely cause, or a clean handoff/i);
  });

  it("renders the four steps IN ORDER once an investigation has started", async () => {
    await show(<InvestigationPage initialSymptom="dns" />);
    expect(stepHeadings()).toEqual([
      "What's wrong?", "Where is it breaking?", "Evidence", "Answer & next action",
    ]);
  });

  it("numbers each step so the order of operations is visible, not implied", async () => {
    await show(<InvestigationPage initialSymptom="dns" />);
    expect(Array.from(document.querySelectorAll(".ts-step")).map((s) => s.getAttribute("data-step")))
      .toEqual(["1", "2", "3", "4"]);
    expect(Array.from(document.querySelectorAll(".ts-step .ts-step-n")).map((n) => n.textContent))
      .toEqual(["1", "2", "3", "4"]);
  });

  it("shows only step 1 until the operator has picked something", async () => {
    await show(<InvestigationPage />);
    expect(stepHeadings()).toEqual(["What's wrong?"]);
    expect(screen.queryByTestId("ts-lanes")).toBeNull();
    expect(screen.queryByTestId("ts-handoff")).toBeNull();
    expect(screen.getByText(/pick a problem or an open case/i)).toBeInTheDocument();
  });
});

// ── it renders outside the app shell ─────────────────────────────────────────

describe("outside the app shell", () => {
  it("renders the entry surface with no shell provider and does not crash", async () => {
    await show(<InvestigationPage />);
    expect(screen.getByRole("heading", { name: "What's wrong?", level: 2 })).toBeInTheDocument();
    const tabs = screen.getByRole("group", { name: "How to start" });
    expect(within(tabs).getAllByRole("button").map((b) => b.textContent))
      .toEqual(["Describe the problem", "Open cases (1)"]);
  });

  it("offers NO 'Open Iris' control when there is no shell to open the drawer", async () => {
    await show(<InvestigationPage initialSymptom="dns" />);
    expect(screen.getByRole("button", { name: "Ask Iris" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Open Iris" })).toBeNull();
  });

  it("offers 'Open Iris' inside the shell and opens the docked drawer", async () => {
    const st = shell();
    await show(
      <ShellContext.Provider value={st}>
        <InvestigationPage initialSymptom="dns" />
      </ShellContext.Provider>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Open Iris" }));
    expect(st.setCopilotOpen).toHaveBeenCalledWith(true);
  });
});

// ── step 1: one picker, two tabs ─────────────────────────────────────────────

describe("step 1 — what's wrong?", () => {
  it("offers the nine canonical workflows on the first tab", async () => {
    await show(<InvestigationPage />);
    const list = screen.getByRole("list", { name: "Symptom" });
    expect(within(list).getAllByRole("button")).toHaveLength(9);
    // the two entry points are equal citizens — the cases are one tab away
    expect(screen.queryByRole("button", { name: /P-CORRAB/ })).toBeNull();
  });

  it("shows the open cases on the second tab, named in NOC words", async () => {
    await show(<InvestigationPage />);
    await click("Open cases (1)");
    const row = screen.getByRole("button", { name: /P-CORRAB/ });
    expect(row).toHaveTextContent("Link state change");   // signatureNocTitle, not "upstream_link_fault"
    expect(row).toHaveTextContent("Likely cause");        // not the raw verdict tier
    expect(screen.queryByRole("list", { name: "Symptom" })).toBeNull();
  });

  it("says plainly when there is no open case — never a blank column", async () => {
    mocks.correlations.mockResolvedValue({ data: [] });
    await show(<InvestigationPage />);
    await click("Open cases (0)");
    expect(screen.getByText("No open correlation case right now.")).toBeInTheDocument();
  });

  it("renders the case-list failure verbatim", async () => {
    mocks.correlations.mockRejectedValue(new Error("403 correlations forbidden"));
    await show(<InvestigationPage />);
    await click("Open cases (0)");
    expect(await screen.findByRole("alert")).toHaveTextContent("403 correlations forbidden");
  });

  it("filters the visible tab from one search box", async () => {
    await show(<InvestigationPage />);
    fireEvent.change(screen.getByRole("searchbox", { name: /search symptoms/i }), { target: { value: "wireless" } });
    expect(within(screen.getByRole("list", { name: "Symptom" })).getAllByRole("button")).toHaveLength(1);
  });

  it("says so when nothing matches the search", async () => {
    await show(<InvestigationPage />);
    fireEvent.change(screen.getByRole("searchbox", { name: /search symptoms/i }), { target: { value: "zzzz" } });
    expect(screen.getByText("No symptom matches that.")).toBeInTheDocument();
  });

  it("names what is being investigated once something is picked", async () => {
    await show(<InvestigationPage initialSymptom="dns" />);
    expect(screen.getByText(/^Investigating:/)).toHaveTextContent("DNS, DHCP or authentication is failing");
  });
});

describe("tierLabel", () => {
  it.each([
    ["confirmed", "Cause confirmed"],
    ["suspected", "Likely cause"],
    ["recovered", "Recovered"],
    ["undetermined", "Cause not known yet"],
    ["", "Cause not known yet"],
  ])("%p → %p", (tier, label) => { expect(tierLabel(tier)).toBe(label); });
});

// ── step 2: where is it breaking? ────────────────────────────────────────────

describe("step 2 — where is it breaking?", () => {
  it("renders FOUR rungs in plain language, numbered bottom-up", async () => {
    await show(<InvestigationPage initialSymptom="bgp_upstream" />);
    const ladder = screen.getByRole("list", { name: "Where it is breaking" });
    expect(Array.from(ladder.querySelectorAll(".ts-rung-l")).map((e) => e.textContent))
      .toEqual(["Physical link", "Routing", "Overlay / Service", "Application"]);
  });

  it("states honestly that we do not have the cause on a symptom-only investigation", async () => {
    await show(<InvestigationPage initialSymptom="bgp_upstream" />);
    const head = screen.getByTestId("ts-bisect-header");
    expect(head).toHaveTextContent("BGP or an upstream is unstable");
    expect(head).toHaveTextContent(/do not have the cause yet/i);
    expect(screen.queryByTestId("ts-rca-header")).toBeNull();
  });

  it("opens exactly the lanes that workflow needs, plus Iris", async () => {
    await show(<InvestigationPage initialSymptom="link_interface" />);
    expect(laneIds()).toEqual([...lanesForSymptom("link_interface"), "iris"]);
  });

  it("earns each rung from lane state — never from being on screen", async () => {
    // routing metrics were never scraped; probes never reported; the feed is
    // wired and quiet; flows have no exporter.
    mocks.metricNames.mockResolvedValue({ status: "success", data: ["collector_targets"] });
    mocks.pathsHealth.mockResolvedValue({ paths: [], count: 0 });
    await show(<InvestigationPage initialSymptom="bgp_upstream" />);
    await waitFor(() => expect(rung("routing")?.getAttribute("data-state")).toBe("blind"));
    expect(rung("routing")).toHaveTextContent("Can't check");
    expect(rung("overlay")?.getAttribute("data-state")).toBe("blind");
    // the event feed IS wired and was quiet, so the link rung honestly reads OK
    expect(rung("link")?.getAttribute("data-state")).toBe("ok");
    expect(rung("link")).toHaveTextContent("OK");
  });

  it("says a layer this problem does not need was simply not checked", async () => {
    // link_interface opens health/flows/changed/events — no path, no dem, so the
    // overlay rung has nothing behind it and must NOT claim to be clean.
    await show(<InvestigationPage initialSymptom="link_interface" />);
    await waitFor(() => expect(rung("overlay")?.getAttribute("data-state")).toBe("skipped"));
    expect(rung("overlay")).toHaveTextContent("Not checked yet");
  });

  it("says 'Problem found here' only once an anomaly lane returned rows", async () => {
    mocks.metricsQuery.mockResolvedValue({
      status: "success",
      data: { resultType: "vector", result: [{ metric: { device: "wan-r1", ifName: "Gi0/1" }, value: [0, "0"] }] },
    });
    await show(<InvestigationPage initialSymptom="link_interface" />);
    await waitFor(() => expect(rung("link")?.getAttribute("data-state")).toBe("found"));
    expect(rung("link")).toHaveTextContent("Problem found here");
  });

  it("switching symptom re-opens the right lanes", async () => {
    await show(<InvestigationPage initialSymptom="dns" />);
    expect(laneIds()).toEqual([...lanesForSymptom("dns"), "iris"]);
    await click(/Wireless clients are struggling/);
    expect(laneIds()).toEqual([...lanesForSymptom("wireless"), "iris"]);
  });
});

// ── step 3: the evidence cards ───────────────────────────────────────────────

describe("step 3 — evidence", () => {
  it("hides the QUIET lanes by default and offers one toggle to reveal them", async () => {
    // default fixtures: dem has rows (loud); path + flows are unwired, changed +
    // health + events are quiet → five quiet lanes on app_slow.
    await show(<InvestigationPage initialSymptom="app_slow" />);
    await waitFor(() => expect(laneSlot("flows")).toHaveAttribute("hidden"));
    expect(laneSlot("dem")).not.toHaveAttribute("hidden");
    for (const id of ["path", "changed", "health", "events"] as LaneId[]) {
      expect(laneSlot(id)).toHaveAttribute("hidden");
    }
    // hidden means hidden from the reader, not from the accessibility tree by accident
    expect(screen.queryByRole("region", { name: LANE_TITLE.flows })).toBeNull();

    const toggle = screen.getByTestId("ts-quiet-toggle");
    expect(toggle).toHaveTextContent("Show 5 quiet lanes");
    expect(toggle).toHaveAttribute("aria-expanded", "false");

    await act(async () => { fireEvent.click(toggle); });
    for (const id of ["path", "changed", "health", "events", "flows"] as LaneId[]) {
      expect(laneSlot(id)).not.toHaveAttribute("hidden");
    }
    expect(screen.getByTestId("ts-quiet-toggle")).toHaveTextContent("Hide 5 quiet lanes");
  });

  it("hides a quiet lane WITHOUT skipping its API call — nothing is lost", async () => {
    await show(<InvestigationPage initialSymptom="app_slow" />);
    await waitFor(() => expect(laneSlot("flows")).toHaveAttribute("hidden"));
    // the flow lane is hidden and still read both of its sources
    expect(mocks.flowsByType).toHaveBeenCalled();
    expect(mocks.topTalkers).toHaveBeenCalled();
    expect(document.querySelector('[data-lane="flows"]')?.getAttribute("data-state")).toBe("not_connected");
  });

  it("offers no quiet toggle when every lane has something to say", async () => {
    mocks.eventsFeed.mockResolvedValue({ items: [{ signal_id: "s1", ts: "t", source: "lab", kind: "link_down", severity: "warning", entity_type: "device", entity_id: "wan-r1", site: "", title: "Link down", correlation_id: null }] });
    mocks.probePaths.mockResolvedValue([{ dst: "10.0.0.1", method: "icmp", hops: [], reached: true, changed: false, ts: "t" }]);
    mocks.flowsByType.mockResolvedValue({ data: [{ flow_type: "netflow", flows: 1, exporters: 1 }] });
    mocks.topTalkers.mockResolvedValue({ data: [{ src_addr: "a", dst_addr: "b", bytes: 1 }] });
    mocks.metricsQuery.mockResolvedValue({
      status: "success", data: { resultType: "vector", result: [{ metric: { device: "d" }, value: [0, "0"] }] },
    });
    await show(<InvestigationPage initialSymptom="app_slow" />);
    await waitFor(() => expect(document.querySelector('[data-lane="flows"]')?.getAttribute("data-state")).toBe("ready"));
    expect(screen.queryByTestId("ts-quiet-toggle")).toBeNull();
  });

  it("renders each opened lane with its own honest state", async () => {
    await show(<InvestigationPage initialSymptom="app_slow" />);
    await waitFor(() => {
      expect(document.querySelector('[data-lane="flows"]')?.getAttribute("data-state")).toBe("not_connected");
    });
    expect(document.querySelector('[data-lane="dem"]')?.getAttribute("data-state")).toBe("ready");
    expect(document.querySelector('[data-lane="path"]')?.getAttribute("data-state")).toBe("not_connected");
    expect(document.querySelector('[data-lane="changed"]')?.getAttribute("data-state")).toBe("empty");
    expect(document.querySelector('[data-lane="health"]')?.getAttribute("data-state")).toBe("empty");
  });

  it("every lane names the API behind it, once revealed", async () => {
    await show(<InvestigationPage initialSymptom="app_slow" />);
    await waitFor(() => expect(screen.getByTestId("ts-quiet-toggle")).toBeInTheDocument());
    await act(async () => { fireEvent.click(screen.getByTestId("ts-quiet-toggle")); });
    for (const id of lanesForSymptom("app_slow") as LaneId[]) {
      expect(screen.getByRole("region", { name: LANE_TITLE[id] })).toBeInTheDocument();
    }
  });
});

// ── step 4: the answer, and the case path ────────────────────────────────────

describe("step 4 — answer & next action", () => {
  it("says plainly that no cause is confirmed on a symptom-only investigation", async () => {
    await show(<InvestigationPage initialSymptom="dns" />);
    const ans = screen.getByTestId("ts-answer");
    expect(ans).toHaveTextContent("No cause confirmed yet");
    expect(ans).toHaveTextContent(/nobody is named yet/i);
  });

  it("offers exactly the four next actions, disabled until a case backs them", async () => {
    await show(<InvestigationPage initialSymptom="dns" />);
    const actions = screen.getByTestId("ts-handoff");
    expect(within(actions).getAllByRole("button").map((b) => b.textContent))
      .toEqual(["Open ticket", "Escalate to TAC", "Correlate", "Download report"]);
    for (const b of within(actions).getAllByRole("button")) expect(b).toBeDisabled();
    expect(screen.getByText(/pick an open case above to escalate/i)).toBeInTheDocument();
  });

  it("names the seam owner the evidence attributed, from the tenant registry", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await waitFor(() => expect(screen.getByTestId("ts-answer")).toHaveTextContent("Lumen"));
  });

  it("keeps Iris inside step 4 — the assistant, not an eighth lane", async () => {
    await show(<InvestigationPage initialSymptom="dns" />);
    const step4 = screen.getByTestId("ts-step-4");
    expect(within(step4).getByRole("region", { name: "Ask Iris" })).toBeInTheDocument();
    expect(within(screen.getByTestId("ts-step-3")).queryByRole("region", { name: "Ask Iris" })).toBeNull();
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

  it("jumps to the correlation workspace from Correlate", async () => {
    const st = shell();
    await show(
      <ShellContext.Provider value={st}>
        <InvestigationPage initialCaseId={CASE_ID} />
      </ShellContext.Provider>,
    );
    await waitFor(() => expect(mocks.correlationDetail).toHaveBeenCalled());
    await click("Correlate");
    expect(st.navigate).toHaveBeenCalledWith(`investigate/rca?id=${CASE_ID}`);
  });
});

describe("case-driven — the correlated verdict", () => {
  it("fetches the case, its timeline and its ticket state", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    expect(mocks.correlationDetail).toHaveBeenCalledWith(CASE_ID);
    expect(mocks.correlationTimeline).toHaveBeenCalledWith(CASE_ID);
    expect(mocks.correlationTickets).toHaveBeenCalledWith(CASE_ID);
  });

  it("renders the SAME RcaCaseHeader the RCA workspace renders, behind one disclosure", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await waitFor(() => expect(screen.getByRole("button", { name: "Full RCA detail" })).toBeInTheDocument());
    // the engine header does NOT lead the page any more — the plain answer does
    expect(screen.queryByTestId("ts-rca-header")).toBeNull();
    await click("Full RCA detail");
    const header = await screen.findByTestId("ts-rca-header");
    expect(header.querySelector(".rw-case")).not.toBeNull();
    expect(within(header).getByRole("heading", { level: 2 })).toBeInTheDocument();
    expect(header).toHaveTextContent("RCA ID:");
    await click("Hide the full RCA detail");
    expect(screen.queryByTestId("ts-rca-header")).toBeNull();
  });

  it("opens EVERY lane for a case — the engine did not pre-narrow the evidence", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await waitFor(() => expect(mocks.correlationDetail).toHaveBeenCalled());
    expect(laneIds()).toEqual([...lanesForSymptom(null), "iris"]);
  });

  it("scopes the lanes to the case's first affected device", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await waitFor(() => expect(mocks.eventsFeed).toHaveBeenCalledWith(expect.objectContaining({ entity: "wan-r2" })));
  });

  it("says the case is being read, then renders the answer", async () => {
    let resolve!: (v: unknown) => void;
    mocks.correlationDetail.mockReturnValue(new Promise((r) => { resolve = r; }));
    render(<InvestigationPage initialCaseId={CASE_ID} />);
    expect(screen.getByTestId("ts-case-loading")).toBeInTheDocument();
    await act(async () => { resolve({ object: openCase(), edges: [] }); });
    expect(await screen.findByRole("button", { name: "Full RCA detail" })).toBeInTheDocument();
    expect(screen.queryByTestId("ts-case-loading")).toBeNull();
  });

  it("renders a failed case read VERBATIM instead of spinning forever", async () => {
    mocks.correlationDetail.mockRejectedValue(new Error("404 correlation not found"));
    mocks.correlationTimeline.mockRejectedValue(new Error("404 correlation not found"));
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    const err = await screen.findByTestId("ts-case-error");
    expect(err).toHaveTextContent("404 correlation not found");
    expect(screen.queryByTestId("ts-case-loading")).toBeNull();
  });

  it("picking a case clears the symptom, and picking a symptom clears the case", async () => {
    await show(<InvestigationPage initialSymptom="dns" />);
    await pickCase();
    await waitFor(() => expect(mocks.correlationDetail).toHaveBeenCalledWith(CASE_ID));
    expect(screen.getByRole("button", { name: /P-CORRAB/ })).toHaveAttribute("aria-pressed", "true");

    await click("Describe the problem");
    await click(/DNS, DHCP/);
    expect(screen.getByTestId("ts-bisect-header")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /DNS, DHCP/ })).toHaveAttribute("aria-pressed", "true");
  });
});

// ── deep links ───────────────────────────────────────────────────────────────

describe("deep-link initial props", () => {
  it("pre-selects the symptom from the link", async () => {
    await show(<InvestigationPage initialSymptom="cloud_saas" />);
    expect(screen.getByRole("button", { name: /A cloud or SaaS service is degraded/ }))
      .toHaveAttribute("aria-pressed", "true");
    expect(screen.getByTestId("ts-bisect-header")).toHaveTextContent("A cloud or SaaS service is degraded");
  });

  it("opens step 1 on the CASE tab when the link named a case", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    expect(screen.getByRole("button", { name: /P-CORRAB/ })).toHaveAttribute("aria-pressed", "true");
    expect(screen.queryByRole("list", { name: "Symptom" })).toBeNull();
  });

  it("starts on the entry prompt when the link named neither", async () => {
    await show(<InvestigationPage />);
    expect(screen.queryByTestId("ts-bisect-header")).toBeNull();
    expect(screen.queryByTestId("ts-rca-header")).toBeNull();
  });

  it("passes the shell's range down to the lanes", async () => {
    await show(<InvestigationPage initialSymptom="dns" rangeMinutes={1440} />);
    await waitFor(() => expect(mocks.eventsFeed).toHaveBeenCalledWith(expect.objectContaining({ from: "24h" })));
  });
});

// ── the seam-owned handoff ───────────────────────────────────────────────────

describe("the handoff", () => {
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

  it("exports the server-built report under the friendly problem id", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await waitFor(() => expect(screen.getByRole("button", { name: "Download report" })).toBeEnabled());
    await click("Download report");
    expect(mocks.downloadRcaReport).toHaveBeenCalledWith(CASE_ID, "P-CORRAB");
    expect(mocks.exportRcaPdf).not.toHaveBeenCalled();
  });

  it("explains an UN-PROMOTED case as policy, and never prints a document the platform refused", async () => {
    mocks.downloadRcaReport.mockRejectedValue(new FakeNotPromoted("This candidate is not promoted."));
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await waitFor(() => expect(screen.getByRole("button", { name: "Download report" })).toBeEnabled());
    await click("Download report");
    expect(await screen.findByText(/not promoted.*Promote it from the RCA workspace/i)).toBeInTheDocument();
    expect(mocks.exportRcaPdf).not.toHaveBeenCalled();
  });

  it("falls back to the client-rendered report when the server report is unavailable", async () => {
    mocks.downloadRcaReport.mockRejectedValue(new Error("502"));
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await waitFor(() => expect(screen.getByRole("button", { name: "Download report" })).toBeEnabled());
    await click("Download report");
    expect(mocks.exportRcaPdf).toHaveBeenCalledTimes(1);
    expect(screen.queryByText("Could not generate the incident report.")).toBeNull();
  });

  it("says so when even the fallback could not render", async () => {
    mocks.downloadRcaReport.mockRejectedValue(new Error("502"));
    mocks.exportRcaPdf.mockReturnValue(false);
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await waitFor(() => expect(screen.getByRole("button", { name: "Download report" })).toBeEnabled());
    await click("Download report");
    expect(await screen.findByText("Could not generate the incident report.")).toBeInTheDocument();
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
