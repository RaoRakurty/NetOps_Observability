// InvestigationPage.test.tsx — the symptom-first Troubleshooting surface.
//
// The shape under test (design of record §c): symptom entry → verdict header →
// parallel evidence lanes → IRIS → seam-owned handoff.
//
// The two things that must never regress:
//  · POSITIONING — picking a CASE shows the SAME RcaCaseHeader the RCA
//    workspace shows (one verdict vocabulary, not two). Picking only a SYMPTOM
//    shows an honest bisecting header that says there is no verdict, plus a
//    ladder whose rungs are earned by lane state, never by being on screen.
//  · HONESTY — an unwired source says "not connected", a quiet one says it was
//    quiet, and a failure is shown verbatim instead of an eternal spinner.
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
  // iris + protocol diagnostics panel
  aiAsk: vi.fn(), devices: vi.fn(), permissions: vi.fn(),
  protocolDiagCatalog: vi.fn(), protocolDiagCollect: vi.fn(), protocolDiagAnalyze: vi.fn(),
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

import InvestigationPage, { caseDevice } from "./InvestigationPage";
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
});
afterEach(() => cleanup());

// ── it renders outside the app shell ─────────────────────────────────────────

describe("outside the app shell", () => {
  it("renders the entry surface with no shell provider and does not crash", async () => {
    await show(<InvestigationPage />);
    expect(screen.getByRole("heading", { name: "What's wrong?", level: 2 })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Symptom", level: 3 })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Open correlation case", level: 3 })).toBeInTheDocument();
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

// ── the entry surface ────────────────────────────────────────────────────────

describe("symptom + case entry", () => {
  it("offers the nine canonical workflows and the open cases as equal citizens", async () => {
    await show(<InvestigationPage />);
    const list = screen.getByRole("list", { name: "Symptom" });
    expect(within(list).getAllByRole("button")).toHaveLength(9);
    expect(screen.getByRole("button", { name: /P-CORRAB/ })).toBeInTheDocument();
  });

  it("says plainly when there is no open case — never a blank column", async () => {
    mocks.correlations.mockResolvedValue({ data: [] });
    await show(<InvestigationPage />);
    expect(screen.getByText("No open correlation case right now.")).toBeInTheDocument();
  });

  it("renders the case-list failure verbatim", async () => {
    mocks.correlations.mockRejectedValue(new Error("403 correlations forbidden"));
    await show(<InvestigationPage />);
    expect(await screen.findByRole("alert")).toHaveTextContent("403 correlations forbidden");
  });

  it("filters both columns from one search box", async () => {
    await show(<InvestigationPage />);
    fireEvent.change(screen.getByRole("searchbox", { name: /search symptoms/i }), { target: { value: "wireless" } });
    expect(within(screen.getByRole("list", { name: "Symptom" })).getAllByRole("button")).toHaveLength(1);
    expect(screen.queryByRole("button", { name: /P-CORRAB/ })).toBeNull();
  });

  it("says so when nothing matches the search", async () => {
    await show(<InvestigationPage />);
    fireEvent.change(screen.getByRole("searchbox", { name: /search symptoms/i }), { target: { value: "zzzz" } });
    expect(screen.getByText("No symptom matches that.")).toBeInTheDocument();
  });

  it("prompts for a starting point before anything is picked", async () => {
    await show(<InvestigationPage />);
    expect(screen.getByText(/pick a symptom or an open correlation case/i)).toBeInTheDocument();
    expect(screen.queryByTestId("ts-lanes")).toBeNull();
    expect(screen.queryByTestId("ts-handoff")).toBeNull();
  });
});

// ── the honest symptom-only header ───────────────────────────────────────────

describe("symptom-only — the bisecting header", () => {
  it("states that there is no correlated verdict and names what it bisects", async () => {
    await show(<InvestigationPage initialSymptom="bgp_upstream" />);
    const head = screen.getByTestId("ts-bisect-header");
    expect(within(head).getByRole("heading", { level: 2 })).toHaveTextContent("BGP or an upstream is unstable");
    expect(head).toHaveTextContent(/no correlated verdict yet/i);
    expect(head).toHaveTextContent("Session state and flaps");
    expect(screen.queryByTestId("ts-rca-header")).toBeNull();
  });

  it("opens exactly the lanes that workflow needs, plus Iris", async () => {
    await show(<InvestigationPage initialSymptom="link_interface" />);
    expect(laneIds()).toEqual([...lanesForSymptom("link_interface"), "iris"]);
  });

  it("earns each ladder rung from lane state — never from being on screen", async () => {
    // routing metrics were never scraped; probes never reported; the feed is
    // wired and quiet; flows have no exporter.
    mocks.metricNames.mockResolvedValue({ status: "success", data: ["collector_targets"] });
    mocks.pathsHealth.mockResolvedValue({ paths: [], count: 0 });
    await show(<InvestigationPage initialSymptom="bgp_upstream" />);
    await waitFor(() => expect(rung("igp")?.getAttribute("data-state")).toBe("not_connected"));
    expect(rung("bgp")?.getAttribute("data-state")).toBe("not_connected");
    expect(rung("path")?.getAttribute("data-state")).toBe("not_connected");
    // the physical rung's lane (health) is not opened by this workflow
    expect(rung("physical")?.getAttribute("data-state")).toBe("not_opened");
    // the feed answered and was quiet — looked, saw nothing
    expect(rung("logs")?.getAttribute("data-state")).toBe("no_data");
  });

  it("marks a rung has_data only once a lane returned rows", async () => {
    mocks.eventsFeed.mockResolvedValue({ items: [{ signal_id: "s1", ts: "t", source: "lab", kind: "link_down", severity: "warning", entity_type: "device", entity_id: "wan-r1", site: "", title: "Link down", correlation_id: null }] });
    await show(<InvestigationPage initialSymptom="bgp_upstream" />);
    await waitFor(() => expect(rung("logs")?.getAttribute("data-state")).toBe("has_data"));
  });

  it("switching symptom re-opens the right lanes", async () => {
    await show(<InvestigationPage initialSymptom="dns" />);
    expect(laneIds()).toEqual([...lanesForSymptom("dns"), "iris"]);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /Wireless clients are struggling/ }));
    });
    expect(laneIds()).toEqual([...lanesForSymptom("wireless"), "iris"]);
  });
});

// ── the case path shows the SAME RCA header ──────────────────────────────────

describe("case-driven — the correlated verdict", () => {
  it("fetches the case, its timeline and its ticket state", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    expect(mocks.correlationDetail).toHaveBeenCalledWith(CASE_ID);
    expect(mocks.correlationTimeline).toHaveBeenCalledWith(CASE_ID);
    expect(mocks.correlationTickets).toHaveBeenCalledWith(CASE_ID);
  });

  it("renders the SAME RcaCaseHeader the RCA workspace renders, not a second verdict", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    const header = await screen.findByTestId("ts-rca-header");
    expect(header.querySelector(".rw-case")).not.toBeNull();
    expect(within(header).getByRole("heading", { level: 2 })).toBeInTheDocument();
    expect(header).toHaveTextContent("RCA ID:");
    expect(screen.queryByTestId("ts-bisect-header")).toBeNull();
  });

  it("opens EVERY lane for a case — the engine did not pre-narrow the evidence", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await screen.findByTestId("ts-rca-header");
    expect(laneIds()).toEqual([...lanesForSymptom(null), "iris"]);
  });

  it("scopes the lanes to the case's first affected device", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await waitFor(() => expect(mocks.eventsFeed).toHaveBeenCalledWith(expect.objectContaining({ entity: "wan-r2" })));
  });

  it("says the verdict is loading, then renders it", async () => {
    let resolve!: (v: unknown) => void;
    mocks.correlationDetail.mockReturnValue(new Promise((r) => { resolve = r; }));
    render(<InvestigationPage initialCaseId={CASE_ID} />);
    expect(screen.getByTestId("ts-case-loading")).toBeInTheDocument();
    await act(async () => { resolve({ object: openCase(), edges: [] }); });
    expect(await screen.findByTestId("ts-rca-header")).toBeInTheDocument();
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
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: /P-CORRAB/ })); });
    await screen.findByTestId("ts-rca-header");
    expect(screen.getByRole("button", { name: /DNS, DHCP/ })).toHaveAttribute("aria-pressed", "false");

    await act(async () => { fireEvent.click(screen.getByRole("button", { name: /DNS, DHCP/ })); });
    expect(screen.getByTestId("ts-bisect-header")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /P-CORRAB/ })).toHaveAttribute("aria-pressed", "false");
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

  it("pre-selects the case from the link", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await screen.findByTestId("ts-rca-header");
    expect(screen.getByRole("button", { name: /P-CORRAB/ })).toHaveAttribute("aria-pressed", "true");
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

// ── lanes render per their state ─────────────────────────────────────────────

describe("the evidence lanes", () => {
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

  it("every lane names the API behind it", async () => {
    await show(<InvestigationPage initialSymptom="app_slow" />);
    for (const id of lanesForSymptom("app_slow") as LaneId[]) {
      expect(screen.getByRole("region", { name: LANE_TITLE[id] })).toBeInTheDocument();
    }
  });
});

// ── the seam-owned handoff ───────────────────────────────────────────────────

describe("the handoff", () => {
  it("names the seam owner the evidence attributed, from the tenant registry", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await screen.findByTestId("ts-rca-header");
    expect(screen.getByTestId("ts-handoff")).toHaveTextContent("Lumen");
  });

  it("refuses to name an owner on a symptom-only investigation", async () => {
    await show(<InvestigationPage initialSymptom="dns" />);
    const handoff = screen.getByTestId("ts-handoff");
    expect(handoff).toHaveTextContent(/no seam owner is attributed yet/i);
    expect(within(handoff).getByRole("button", { name: "Create ticket" })).toBeDisabled();
    expect(within(handoff).getByRole("button", { name: "Export PDF" })).toBeDisabled();
    expect(handoff).toHaveTextContent(/attached to a correlation case/i);
  });

  it("creates a ticket and re-reads the authoritative state instead of inventing a number", async () => {
    mocks.correlationTickets
      .mockResolvedValueOnce({ status: { state: "none" }, audit: [] })
      .mockResolvedValueOnce({ status: { state: "open", ticket_number: "INC0012345" }, audit: [] });
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await screen.findByTestId("ts-rca-header");
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Create ticket" })); });
    expect(mocks.correlationTicketCreate).toHaveBeenCalledWith(CASE_ID);
    expect(await screen.findByText(/Ticket request enqueued to servicenow\./)).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "Ticket INC0012345" })).toBeInTheDocument();
  });

  it("reports a ticket failure verbatim", async () => {
    mocks.correlationTicketCreate.mockRejectedValue(new Error("ticketing not configured"));
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await screen.findByTestId("ts-rca-header");
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Create ticket" })); });
    expect(await screen.findByText("Could not create a ticket: ticketing not configured")).toBeInTheDocument();
  });

  it("exports the server-built report under the friendly problem id", async () => {
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await screen.findByTestId("ts-rca-header");
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Export PDF" })); });
    expect(mocks.downloadRcaReport).toHaveBeenCalledWith(CASE_ID, "P-CORRAB");
    expect(mocks.exportRcaPdf).not.toHaveBeenCalled();
  });

  it("explains an UN-PROMOTED case as policy, and never prints a document the platform refused", async () => {
    mocks.downloadRcaReport.mockRejectedValue(new FakeNotPromoted("This candidate is not promoted."));
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await screen.findByTestId("ts-rca-header");
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Export PDF" })); });
    expect(await screen.findByText(/not promoted.*Promote it from the RCA workspace/i)).toBeInTheDocument();
    expect(mocks.exportRcaPdf).not.toHaveBeenCalled();
  });

  it("falls back to the client-rendered report when the server report is unavailable", async () => {
    mocks.downloadRcaReport.mockRejectedValue(new Error("502"));
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await screen.findByTestId("ts-rca-header");
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Export PDF" })); });
    expect(mocks.exportRcaPdf).toHaveBeenCalledTimes(1);
    expect(screen.queryByText("Could not generate the incident report.")).toBeNull();
  });

  it("says so when even the fallback could not render", async () => {
    mocks.downloadRcaReport.mockRejectedValue(new Error("502"));
    mocks.exportRcaPdf.mockReturnValue(false);
    await show(<InvestigationPage initialCaseId={CASE_ID} />);
    await screen.findByTestId("ts-rca-header");
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Export PDF" })); });
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
