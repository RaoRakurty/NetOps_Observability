// TacEscalationPanel.test.tsx — the TAC escalation flow on the Investigate page.
//
// Every step of the flow is covered, and for each one the HONEST state is
// covered beside the happy path, because the honest state is the feature:
//  · classify — a matched class with the exact evidence rows that scored it and
//    the alternatives; and `classified:false`, which shows the server's own note
//    and never invents a class
//  · plan     — bound steps with their commands, a `doc_claimed` command
//    labelled "documented, not verified", unbound intents listed WITH their
//    reason, and `has_plan:false` rendered as the honest no-plan state
//  · collect  — a 503 rendering the server's own collect_note with the Start
//    button disabled; live per-command progress; cancel; the paste fallback
//  · bundle   — the download called with the profile and a safe file name
//  · case     — an unconfigured connector greyed and unpressable, the pre-filled
//    form with its required fields marked, and a submit that is never automatic
//  · escaping — device output carrying markup renders as TEXT (§15)
//
// The honest-state sentences are asserted BY IMPORT from tacModel, never as
// copy-pasted literals: a reworded state must be reworded in one place.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, within, act } from "@testing-library/react";
import type {
  TacCaseFormResponse,
  TacClassifyResponse,
  TacPlan,
  TacPlanResponse,
  TacState,
  TacStateResponse,
} from "../../services/api";

const mocks = vi.hoisted(() => ({
  tacState: vi.fn(), tacClassify: vi.fn(), tacPlan: vi.fn(), tacCollect: vi.fn(),
  tacCancelCollect: vi.fn(), tacDownloadBundle: vi.fn(), tacCaseForm: vi.fn(),
  tacCaseSubmit: vi.fn(), devices: vi.fn(),
}));
vi.mock("../../services/api", () => ({ api: { ...mocks } }));

import TacEscalationPanel from "./TacEscalationPanel";
import {
  CONNECTOR_NOT_CONFIGURED,
  DOC_CLAIMED_LABEL,
  NOTHING_SCORED_NOTE,
  NO_CAPTURE_YET,
  PASTE_INVITE,
  PLAN_NEEDS_DEVICE,
  STATE_READ_FAILED,
  bundleFileName,
  unboundReason,
} from "./tacModel";

const INC = "corr-abc1234567890";
const COLLECT_NOTE =
  "Live collection is not wired on this deployment (FEATURE_PROTOCOL_DIAG_COLLECT is off, or no read-only " +
  "SSH account is provisioned). The plan, the bundle and the case text still work — collect the outputs by " +
  "hand and paste them into the collect step.";

// ── fixtures ─────────────────────────────────────────────────────────────────

const stateResponse = (over: Partial<TacStateResponse> = {}): TacStateResponse => ({
  incident_id: INC,
  incident_ref: "INC-2026-0007",
  title: "OSPF adjacency down on leaf1",
  can_collect: true,
  collect_note: "",
  catalog_version: "correlix-tac-classes-2026-09-05",
  connectors: [],
  devices: ["leaf1"],
  state: null,
  state_note: "This incident has not been escalated in this api process.",
  ...over,
});

const classification = (over = {}) => ({
  class_id: "ospf-adjacency",
  title: "OSPF adjacency will not form or is stuck",
  protocol: "ospf",
  tac_first_look: "The neighbour state word, then the interface MTU.",
  classified: true,
  why: [{ kind: "signature", ref: "ospf-exstart-mtu", weight: 5 }],
  alternatives: [{ class_id: "ospf-flapping-link", title: "OSPF flapping link", score: 2, why: [] }],
  note: "",
  catalog_version: "correlix-tac-classes-2026-09-05",
  ...over,
});

const classifyResponse = (over: Partial<TacClassifyResponse> = {}): TacClassifyResponse => ({
  incident_id: INC,
  classification: classification() as never,
  evidence_sources: ["correlation object", "case timeline"],
  evidence_missing: ["incident register (not readable for this id)"],
  classes: [
    { id: "ospf-adjacency", title: "OSPF adjacency will not form or is stuck", protocol: "ospf", summary: "" },
    { id: "bgp-session", title: "BGP session down", protocol: "bgp", summary: "" },
    { id: "generic", title: "General escalation", protocol: "generic", summary: "" },
  ],
  ...over,
});

const plan = (over: Partial<TacPlan> = {}): TacPlan => ({
  id: "plan-1",
  incident_id: INC,
  device_id: "leaf1",
  hostname: "leaf1",
  platform: "Cisco IOS-XE 17.9",
  dialect: "cisco-iosxe",
  dialect_display: "Cisco IOS-XE",
  has_plan: true,
  plan_version: "correlix-tac-plan-cisco-iosxe-2026-09-05",
  class_id: "ospf-adjacency",
  class_title: "OSPF adjacency will not form or is stuck",
  tac_first_look: "The neighbour state word.",
  target: {},
  include_optional: false,
  steps: [
    {
      intent: "system.version", title: "Software version", section: "baseline",
      bound: true, command: "show version", verified: "capture",
    },
    {
      intent: "ospf.neighbors.detail", title: "OSPF neighbours, detailed", section: "deep-dive",
      bound: true, command: "show ip ospf neighbor detail", verified: "doc_claimed",
      sources: [{ title: "Troubleshoot OSPF Neighbor Problems", url: "https://example.invalid/ospf", retrieved: "2026-09-05" }],
    },
  ],
  unbound: [
    {
      intent: "ospf.database.router", title: "OSPF router LSA", section: "deep-dive",
      bound: false, note: "no binding on this dialect",
    },
  ],
  topology: [{ kind: "neighbor", ref: "spine1", detail: "Gi0/1 → Gi0/2 (observed by lldp)" }],
  estimated_bytes: 2048,
  estimated_seconds: 45,
  redaction_note: "Secrets, community strings and keys are removed from the bundle; tenant ids are kept.",
  note: "",
  catalog_version: "correlix-tac-classes-2026-09-05",
  engine_version: "correlix-tac-2026-09-05",
  ...over,
});

const stateWith = (over: Partial<TacState> = {}): TacState => ({
  incident_id: INC,
  classification: classification() as never,
  plan: plan(),
  bundles: [],
  updated_at: "2026-09-05T10:00:00Z",
  ...over,
});

const planResponse = (p: TacPlan = plan()): TacPlanResponse =>
  ({ plan: p, can_collect: true, collect_note: "" });

const caseFormResponse = (over: Partial<TacCaseFormResponse> = {}): TacCaseFormResponse => ({
  form: {
    connector_id: "servicenow",
    title: "OSPF adjacency down on leaf1",
    description: "Correlix problem statement…",
    severity: "3",
    bundle_name: "correlix-tac-INC-2026-0007.zip",
    bundle_bytes: 4096,
    profile: "full",
    missing_fields: ["serial_number"],
    portal_text: "Problem statement for the vendor portal.",
  },
  connector: {
    id: "servicenow", display: "ServiceNow", capabilities: ["create", "attach"],
    max_attachment_bytes: 18 * 1024 * 1024, profile: "full", configured: true,
  },
  bundle: {
    name: "correlix-tac-INC-2026-0007.zip", bytes: 4096, created_at: "2026-09-05T10:05:00Z",
    incident_id: INC, profile: "full", class_id: "ospf-adjacency", plan_id: "plan-1",
  },
  ...over,
});

/** Render and let the mount reads settle inside act(). */
async function show(res: TacStateResponse = stateResponse()) {
  mocks.tacState.mockResolvedValue(res);
  const utils = render(<TacEscalationPanel incidentId={INC} />);
  await act(async () => { await Promise.resolve(); });
  return utils;
}

const click = async (name: string | RegExp) => {
  await act(async () => { fireEvent.click(screen.getByRole("button", { name })); });
};

beforeEach(() => {
  Object.values(mocks).forEach((m) => m.mockReset());
  mocks.devices.mockResolvedValue([
    { id: "leaf1", name: "leaf1", address: "10.0.0.1", source: "snmp", last_seen: "2026-09-05T09:00:00Z" },
    { id: "spine1", name: "spine1", address: "10.0.0.2", source: "snmp", last_seen: "2026-09-05T09:00:00Z" },
  ]);
});
afterEach(() => { cleanup(); vi.useRealTimers(); });

// ── step 0: the panel itself ─────────────────────────────────────────────────

describe("the escalation panel opens on one button", () => {
  it("offers Escalate to TAC and the server's own not-escalated note", async () => {
    await show();
    expect(screen.getByRole("heading", { name: "Escalate to TAC" })).toBeInTheDocument();
    expect(screen.getByText(/has not been escalated in this api process/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Escalate to TAC" })).toBeEnabled();
  });

  it("says what did not happen when the escalation cannot be read", async () => {
    mocks.tacState.mockRejectedValue(new Error("TypeError: fetch failed"));
    render(<TacEscalationPanel incidentId={INC} />);
    expect(await screen.findByRole("alert")).toHaveTextContent(STATE_READ_FAILED);
  });
});

// ── step 2: class + why ──────────────────────────────────────────────────────

describe("classify", () => {
  it("shows the class, the evidence rows that scored it, and the alternatives", async () => {
    await show();
    mocks.tacClassify.mockResolvedValue(classifyResponse());
    mocks.tacState.mockResolvedValue(stateResponse({ state: stateWith({ plan: undefined }) }));
    await click("Escalate to TAC");

    expect(mocks.tacClassify).toHaveBeenCalledWith(INC);
    expect(screen.getByText("OSPF adjacency will not form or is stuck")).toBeInTheDocument();
    expect(screen.getByText("signature ospf-exstart-mtu · weight 5")).toBeInTheDocument();
    expect(screen.getByText("OSPF flapping link")).toBeInTheDocument();
    expect(screen.getByText(/score 2/)).toBeInTheDocument();
    expect(screen.getByText(/What TAC opens first:/)).toBeInTheDocument();
  });

  it("shows what it was classified ON and what it was classified WITHOUT", async () => {
    await show();
    mocks.tacClassify.mockResolvedValue(classifyResponse());
    mocks.tacState.mockResolvedValue(stateResponse({ state: stateWith({ plan: undefined }) }));
    await click("Escalate to TAC");

    const ev = screen.getByTestId("tac-evidence");
    expect(ev).toHaveTextContent("Classified on: correlation object · case timeline");
    expect(ev).toHaveTextContent("Classified without: incident register (not readable for this id)");
  });

  it("offers the FULL class list as an override", async () => {
    await show();
    mocks.tacClassify.mockResolvedValue(classifyResponse());
    mocks.tacState.mockResolvedValue(stateResponse({ state: stateWith({ plan: undefined }) }));
    await click("Escalate to TAC");

    const sel = screen.getByLabelText("Change the issue class") as HTMLSelectElement;
    expect(Array.from(sel.options).map((o) => o.value))
      .toEqual(["ospf-adjacency", "bgp-session", "generic"]);
  });

  it("never invents a class when nothing scored", async () => {
    await show();
    const unclassified = classification({
      class_id: "generic", title: "General escalation", classified: false,
      why: [], alternatives: [], note: "",
    });
    mocks.tacClassify.mockResolvedValue(classifyResponse({ classification: unclassified as never }));
    mocks.tacState.mockResolvedValue(stateResponse({
      state: stateWith({ classification: unclassified as never, plan: undefined }),
    }));
    await click("Escalate to TAC");

    expect(screen.getByText("nothing scored")).toBeInTheDocument();
    expect(screen.getByText(NOTHING_SCORED_NOTE)).toBeInTheDocument();
    expect(screen.getByText("No evidence row scored this class.")).toBeInTheDocument();
  });
});

// ── step 3: plan preview ─────────────────────────────────────────────────────

describe("plan preview", () => {
  const openClassified = async (over: Partial<TacState> = {}) => {
    await show();
    mocks.tacClassify.mockResolvedValue(classifyResponse());
    mocks.tacState.mockResolvedValue(stateResponse({ state: stateWith({ plan: undefined, ...over }) }));
    await click("Escalate to TAC");
  };

  it("asks for a device before anything is planned", async () => {
    await openClassified();
    expect(screen.getByText(PLAN_NEEDS_DEVICE)).toBeInTheDocument();
    expect(screen.queryByTestId("tac-plan")).toBeNull();
  });

  it("sends the device, class, optional toggle and typed target", async () => {
    await openClassified();
    mocks.tacPlan.mockResolvedValue(planResponse());
    mocks.tacState.mockResolvedValue(stateResponse({ state: stateWith() }));

    fireEvent.change(screen.getByLabelText("Interface (optional)"), { target: { value: "Gi0/1" } });
    fireEvent.click(screen.getByLabelText(/Include the optional captures/));
    await click("Build the command plan");

    expect(mocks.tacPlan).toHaveBeenCalledWith(INC, {
      device_id: "leaf1",
      class_id: "ospf-adjacency",
      include_optional: true,
      target: { interface: "Gi0/1" },
    });
  });

  it("shows bound commands, the size/time estimate and the redaction note verbatim", async () => {
    await openClassified();
    mocks.tacPlan.mockResolvedValue(planResponse());
    mocks.tacState.mockResolvedValue(stateResponse({ state: stateWith() }));
    await click("Build the command plan");

    const preview = within(screen.getByTestId("tac-plan"));
    expect(preview.getByText("show version")).toBeInTheDocument();
    expect(preview.getByText("show ip ospf neighbor detail")).toBeInTheDocument();
    expect(screen.getByText(/Estimated 2.0 KB · about 45 s/)).toBeInTheDocument();
    expect(screen.getByTestId("tac-redaction"))
      .toHaveTextContent("Secrets, community strings and keys are removed from the bundle; tenant ids are kept.");
  });

  it("labels a documented command as unverified", async () => {
    await openClassified();
    mocks.tacPlan.mockResolvedValue(planResponse());
    mocks.tacState.mockResolvedValue(stateResponse({ state: stateWith() }));
    await click("Build the command plan");
    expect(within(screen.getByTestId("tac-plan")).getByText(DOC_CLAIMED_LABEL)).toBeInTheDocument();
  });

  it("lists an unbound intent with its own reason instead of dropping it", async () => {
    await openClassified();
    mocks.tacPlan.mockResolvedValue(planResponse());
    mocks.tacState.mockResolvedValue(stateResponse({ state: stateWith() }));
    await click("Build the command plan");

    const unbound = screen.getByTestId("tac-unbound");
    expect(unbound).toHaveTextContent("OSPF router LSA");
    expect(unbound).toHaveTextContent("no binding on this dialect");
    expect(unboundReason({ intent: "x", title: "x", section: "deep-dive", bound: false }))
      .toBeTruthy();
  });

  it("says out loud when the platform has no authored command set", async () => {
    await openClassified();
    const noPlan = plan({
      has_plan: false, steps: [], plan_version: undefined,
      note: "There is no authored command set for Nokia SR Linux.",
      unbound: [{ intent: "system.version", title: "Software version", section: "baseline", bound: false, note: "no plan for this dialect" }],
    });
    mocks.tacPlan.mockResolvedValue(planResponse(noPlan));
    mocks.tacState.mockResolvedValue(stateResponse({ state: stateWith({ plan: noPlan }) }));
    await click("Build the command plan");

    expect(screen.getByTestId("tac-no-plan"))
      .toHaveTextContent("There is no authored command set for Nokia SR Linux.");
    expect(screen.getByTestId("tac-paste")).toHaveTextContent(PASTE_INVITE);
  });

  it("renders the plan failure as an operator sentence", async () => {
    await openClassified();
    mocks.tacPlan.mockRejectedValue(new Error("404 Not Found: "));
    await click("Build the command plan");
    expect(screen.getByRole("alert")).toHaveTextContent("That is not available.");
  });
});

// ── step 4: collect ──────────────────────────────────────────────────────────

describe("collect", () => {
  const openPlanned = async (over: Partial<TacStateResponse> = {}) => {
    await show(stateResponse({ state: stateWith(), ...over }));
    mocks.tacClassify.mockResolvedValue(classifyResponse());
    return undefined;
  };

  it("disables the start and shows the server's own note when collection is unwired", async () => {
    await openPlanned({ can_collect: false, collect_note: COLLECT_NOTE });
    expect(screen.getByTestId("tac-collect-note")).toHaveTextContent(COLLECT_NOTE);
    expect(screen.getByRole("button", { name: "Start the collection" })).toBeDisabled();
  });

  it("renders a 503 from the start as the server's own sentence", async () => {
    await openPlanned();
    mocks.tacCollect.mockRejectedValue(new Error(`503 Service Unavailable: {"error":${JSON.stringify(COLLECT_NOTE)}}`));
    await click("Start the collection");
    expect(screen.getByTestId("tac-collect-error")).toHaveTextContent("Live collection is not wired on this deployment");
  });

  it("shows live per-command progress and stops reading once the job ends", async () => {
    vi.useFakeTimers();
    const running = stateResponse({
      state: stateWith({
        job: {
          id: "job-1", status: "running", started_at: "2026-09-05T10:00:00Z", total: 2, done: 1,
          progress: [
            { index: 0, total: 2, intent: "system.version", command: "show version", phase: "done", bytes: 512 },
            { index: 1, total: 2, intent: "ospf.neighbors.detail", command: "show ip ospf neighbor detail", phase: "start" },
          ],
        },
      }),
    });
    mocks.tacState.mockResolvedValue(running);
    render(<TacEscalationPanel incidentId={INC} />);
    await act(async () => { await Promise.resolve(); });

    const job = screen.getByTestId("tac-job");
    expect(job).toHaveTextContent("1 of 2 commands · running");
    expect(job).toHaveTextContent("collected");
    expect(job).toHaveTextContent("running");
    expect(job).toHaveTextContent("512 B");

    const before = mocks.tacState.mock.calls.length;
    mocks.tacState.mockResolvedValue(stateResponse({
      state: stateWith({
        job: { id: "job-1", status: "done", started_at: "x", finished_at: "y", total: 2, done: 2, progress: [] },
      }),
    }));
    await act(async () => { vi.advanceTimersByTime(2000); await Promise.resolve(); });
    expect(mocks.tacState.mock.calls.length).toBeGreaterThan(before);

    // Now that the job is done the 2 s read must stop entirely.
    const settled = mocks.tacState.mock.calls.length;
    await act(async () => { vi.advanceTimersByTime(10_000); await Promise.resolve(); });
    expect(mocks.tacState.mock.calls.length).toBe(settled);
  });

  it("cancels a running collection", async () => {
    mocks.tacState.mockResolvedValue(stateResponse({
      state: stateWith({
        job: { id: "job-1", status: "running", started_at: "x", total: 2, done: 0, progress: [] },
      }),
    }));
    render(<TacEscalationPanel incidentId={INC} />);
    await act(async () => { await Promise.resolve(); });
    mocks.tacCancelCollect.mockResolvedValue({ cancelled: true, state: null });
    await click("Stop");
    expect(mocks.tacCancelCollect).toHaveBeenCalledWith(INC);
  });

  it("files pasted output for exactly the intents that were not collected", async () => {
    await openPlanned();
    mocks.tacCollect.mockResolvedValue({ job: {}, state: {} });

    fireEvent.change(screen.getByLabelText("Output for ospf.database.router"), {
      target: { value: "  Router Link States  " },
    });
    await click("File the pasted output");

    expect(mocks.tacCollect).toHaveBeenCalledWith(INC, {
      outputs: [{ intent: "ospf.database.router", command: "", output: "Router Link States" }],
    });
  });

  it("renders captured device output as escaped text, never as markup", async () => {
    const hostile = '<img src=x onerror="alert(1)">';
    mocks.tacState.mockResolvedValue(stateResponse({
      state: stateWith({
        capture: {
          incident_id: INC, plan_id: "plan-1", class_id: "ospf-adjacency", class_title: "x",
          device_id: "leaf1", hostname: "leaf1", platform: "Cisco IOS-XE", dialect: "cisco-iosxe",
          dialect_display: "Cisco IOS-XE", has_plan: true, started_at: "x", finished_at: "y",
          commands: [{
            intent: "system.version", title: "Software version", section: "baseline",
            command: "show version", verified: "capture", output: hostile, bytes: 30,
            started_at: "x", duration_ms: 10,
          }],
          unbound: [], topology: [], target: {}, total_bytes: 30, redacted: false,
          catalog_version: "v", engine_version: "e",
        },
      }),
    }));
    const { container } = render(<TacEscalationPanel incidentId={INC} />);
    await act(async () => { await Promise.resolve(); });

    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText(hostile)).toBeInTheDocument();
  });
});

// ── step 5: bundle ───────────────────────────────────────────────────────────

describe("bundle", () => {
  const captured = () => stateResponse({
    state: stateWith({
      capture: {
        incident_id: INC, plan_id: "plan-1", class_id: "ospf-adjacency", class_title: "x",
        device_id: "leaf1", hostname: "leaf1", platform: "p", dialect: "cisco-iosxe",
        dialect_display: "Cisco IOS-XE", has_plan: true, started_at: "x", finished_at: "y",
        commands: [], unbound: [], topology: [], target: {}, total_bytes: 0, redacted: true,
        catalog_version: "v", engine_version: "e",
      },
      bundles: [{
        name: "correlix-tac-INC-2026-0007.zip", bytes: 4096, created_at: "2026-09-05T10:05:00Z",
        incident_id: INC, profile: "full", class_id: "ospf-adjacency", plan_id: "plan-1",
      }],
    }),
  });

  it("has nothing to bundle before anything is collected", async () => {
    await show(stateResponse({ state: stateWith() }));
    expect(screen.getByText(NO_CAPTURE_YET)).toBeInTheDocument();
  });

  it("downloads the profile the operator picked, under a safe name", async () => {
    await show(captured());
    mocks.tacDownloadBundle.mockResolvedValue(undefined);
    fireEvent.change(screen.getByLabelText("Profile"), { target: { value: "email" } });
    await click("Download the redacted bundle");

    expect(mocks.tacDownloadBundle).toHaveBeenCalledWith(INC, "email", bundleFileName("INC-2026-0007", "email"));
  });

  it("lists the bundles already built, with their size and profile", async () => {
    await show(captured());
    expect(screen.getByText("correlix-tac-INC-2026-0007.zip")).toBeInTheDocument();
    expect(screen.getByText(/4.0 KB · full profile/)).toBeInTheDocument();
  });

  it("says what did not happen when the download is refused", async () => {
    await show(captured());
    mocks.tacDownloadBundle.mockRejectedValue(new Error("409 Conflict: {\"error\":\"collect the evidence first\"}"));
    await click("Download the redacted bundle");
    expect(screen.getByRole("alert")).toHaveTextContent("Collect the evidence first.");
  });
});

// ── step 6: open the case ────────────────────────────────────────────────────

describe("open the case", () => {
  const withConnectors = () => stateResponse({
    state: stateWith(),
    connectors: [
      {
        id: "servicenow", display: "ServiceNow", capabilities: ["create", "attach"],
        max_attachment_bytes: 18 * 1024 * 1024, profile: "full", configured: true,
      },
      {
        id: "cisco", display: "Cisco TAC", capabilities: ["create", "attach"],
        max_attachment_bytes: 20 * 1024 * 1024, profile: "full", configured: false,
        note: "Bring a Smart Bonding client id and a CXD token for this tenant.",
      },
      {
        id: "portal-text", display: "Vendor portal text", capabilities: ["link"],
        max_attachment_bytes: 0, profile: "link_only", configured: true,
      },
    ],
  });

  it("greys an unconfigured connector and shows its own note", async () => {
    await show(withConnectors());
    const row = screen.getByTestId("tac-conn-cisco");
    expect(row.className).toContain("off");
    expect(row).toHaveTextContent("Bring a Smart Bonding client id and a CXD token for this tenant.");
    expect(screen.getByRole("button", { name: "Cisco TAC" })).toBeDisabled();
  });

  it("says honestly when a connector cannot open the case itself", async () => {
    await show(withConnectors());
    expect(screen.getByTestId("tac-conn-portal-text"))
      .toHaveTextContent("This connector cannot open the case itself");
  });

  it("pre-fills the form, marks the fields the vendor requires and shows the case text", async () => {
    await show(withConnectors());
    mocks.tacCaseForm.mockResolvedValue(caseFormResponse());
    await click("ServiceNow");

    expect(mocks.tacCaseForm).toHaveBeenCalledWith(INC, "servicenow");
    const form = screen.getByTestId("tac-case-form");
    expect(form).toBeInTheDocument();
    expect((screen.getByLabelText(/^Title/) as HTMLInputElement).value).toBe("OSPF adjacency down on leaf1");
    expect(screen.getByLabelText(/Serial number — the vendor requires this/)).toBeRequired();
    expect((screen.getByLabelText("Case text") as HTMLTextAreaElement).value)
      .toBe("Problem statement for the vendor portal.");
    expect(screen.getByLabelText("Case text")).toHaveAttribute("readonly");
  });

  it("submits only on a person's press, with the edited fields", async () => {
    await show(withConnectors());
    mocks.tacCaseForm.mockResolvedValue(caseFormResponse());
    await click("ServiceNow");
    expect(mocks.tacCaseSubmit).not.toHaveBeenCalled();

    fireEvent.change(screen.getByLabelText(/Serial number/), { target: { value: "FDO1234" } });
    mocks.tacCaseSubmit.mockResolvedValue({
      result: {
        connector_id: "servicenow", case_id: "INC0012345", case_url: "https://example.invalid/INC0012345",
        attached: true, submitted_at: "2026-09-05T10:10:00Z",
      },
      bundle: caseFormResponse().bundle,
    });
    await click("Open the case");

    expect(mocks.tacCaseSubmit).toHaveBeenCalledWith(INC, "servicenow", expect.objectContaining({
      title: "OSPF adjacency down on leaf1", serial_number: "FDO1234",
    }));
    await waitFor(() => expect(screen.getByTestId("tac-case-result")).toHaveTextContent("The bundle was attached."));
    expect(screen.getByText(/Case INC0012345 recorded with ServiceNow/)).toBeInTheDocument();
  });

  it("renders a refusal to open the case as an operator sentence", async () => {
    await show(withConnectors());
    mocks.tacCaseForm.mockRejectedValue(
      new Error('409 Conflict: {"error":"collect the evidence before opening a case"}'),
    );
    await click("ServiceNow");
    expect(screen.getByTestId("tac-case-error"))
      .toHaveTextContent("Collect the evidence before opening a case.");
  });

  it("does not offer a connector that this deployment does not carry", async () => {
    await show(stateResponse({ state: stateWith(), connectors: [] }));
    expect(screen.getByText(/No case connector is offered on this deployment/)).toBeInTheDocument();
  });
});

// ── the unconfigured-connector guard, and the "not configured" wording ───────

describe("an unconfigured connector never becomes a case", () => {
  it("cannot be pressed, so no form is ever requested for it", async () => {
    await show(stateResponse({
      state: stateWith(),
      connectors: [{
        id: "juniper", display: "Juniper", capabilities: ["create"], max_attachment_bytes: 0,
        profile: "full", configured: false,
      }],
    }));
    expect(screen.getByTestId("tac-conn-juniper")).toHaveTextContent(CONNECTOR_NOT_CONFIGURED);
    fireEvent.click(screen.getByRole("button", { name: "Juniper" }));
    expect(mocks.tacCaseForm).not.toHaveBeenCalled();
  });
});
