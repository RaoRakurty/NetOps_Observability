// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// TacEscalationPanel.test.tsx — the TAC escalation flow on the Investigate page.
//
// Design of record for what the customer SEES:
// docs/design/TAC_CAPTURES_2026-09-06.md (owner decision). The guard it asks for
// is the spine of this file:
//
//   · no plan table, no intent id, no citation link, no verification chip in the
//     escalation step — every one of them is behind "What Correlix is doing"
//   · a capture row is a name, a count and a status; its commands are HIDDEN
//     until the chevron is used
//   · after a partial collection ONLY the failed commands are listed, each with
//     its plain reason — the successful output is in the bundle and is never
//     rendered
//   · an upload round-trips for each format, and a refusal names the LINE in the
//     operator's own file and the rule that refused it
//   · the behind-the-scenes control is collapsed by default and, when opened,
//     carries the class, the plan and the collection log
//
// And the honest states of every other step are covered beside their happy path,
// because the honest state is the feature: `classified:false` shows the server's
// own note and never an invented class; a 503 on collect renders the server's
// own collect_note; a connector with no credentials is greyed and unpressable;
// device output carrying markup renders as TEXT (§15).
//
// The honest-state sentences are asserted BY IMPORT from tacModel, never as
// copy-pasted literals: a reworded state must be reworded in one place.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, within, act } from "@testing-library/react";
import type {
  TacCaseFormResponse,
  TacClassifyResponse,
  TacCommandCapture,
  TacPlan,
  TacPlanResponse,
  TacState,
  TacStateResponse,
} from "../../services/api";

const mocks = vi.hoisted(() => ({
  tacState: vi.fn(), tacClassify: vi.fn(), tacPlan: vi.fn(), tacCollect: vi.fn(),
  tacCancelCollect: vi.fn(), tacDownloadBundle: vi.fn(), tacCaseForm: vi.fn(),
  tacCaseSubmit: vi.fn(), devices: vi.fn(),
  // Captures (docs/design/TAC_CAPTURES_2026-09-06.md).
  tacCaptures: vi.fn(), tacCaptureUpload: vi.fn(), tacCaptureSave: vi.fn(),
}));
vi.mock("../../services/api", () => ({ api: { ...mocks } }));

import TacEscalationPanel from "./TacEscalationPanel";
import {
  BEHIND_LABEL,
  CAPTURES_NEED_DEVICE,
  CAPTURE_STATUS_LABEL,
  CONNECTOR_CHIP,
  CONNECTOR_NOT_CONFIGURED,
  NOTHING_SCORED_NOTE,
  NO_BUNDLE_YET,
  NO_CAPTURE_YET,
  NO_CASE_CONNECTOR,
  PASTE_INVITE,
  REDACTION_SHORT,
  STATE_READ_FAILED,
  UPLOAD_FORMATS_LINE,
  bundleFileName,
  commandCountLine,
  connectorTopic,
  missingOutputsLine,
  showAllConnectorsLabel,
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

/** The vendor default the SERVER derives from the plan's bound steps. */
const defaultCapture = (over: Partial<TacCommandCapture> = {}): TacCommandCapture => ({
  id: "capture:vendor-default",
  name: "Cisco IOS-XE default",
  source: "vendor-default",
  dialect: "cisco-iosxe",
  commands: [
    { command: "show version", note: "Software version" },
    { command: "show ip ospf neighbor detail", note: "OSPF neighbours, detailed" },
  ],
  ...over,
});

const stateWith = (over: Partial<TacState> = {}): TacState => ({
  incident_id: INC,
  classification: classification() as never,
  plan: plan(),
  default_capture: defaultCapture(),
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

/** Render and let the mount reads AND the silent plan build settle inside act(). */
async function show(res: TacStateResponse = stateResponse()) {
  mocks.tacState.mockResolvedValue(res);
  const utils = render(<TacEscalationPanel incidentId={INC} />);
  await act(async () => { await Promise.resolve(); });
  await act(async () => { await Promise.resolve(); });
  return utils;
}

const click = async (name: string | RegExp) => {
  await act(async () => { fireEvent.click(screen.getByRole("button", { name })); });
};

/** Open the ONE "what is happening behind the scene" control. Its body is
 *  mounted only while open, so everything it holds is absent until this runs. */
const openBehind = async () => {
  await act(async () => { fireEvent.click(screen.getByTestId("tac-behind-toggle")); });
  return screen.getByTestId("tac-behind-body");
};

/** The escalation step as the customer sees it — everything except the one
 *  disclosure. Assertions about "the visible step" read THIS. */
const visibleStep = () => screen.getByTestId("tac-captures");

beforeEach(() => {
  Object.values(mocks).forEach((m) => m.mockReset());
  mocks.devices.mockResolvedValue([
    { id: "leaf1", name: "leaf1", address: "10.0.0.1", source: "snmp", last_seen: "2026-09-05T09:00:00Z" },
    { id: "spine1", name: "spine1", address: "10.0.0.2", source: "snmp", last_seen: "2026-09-05T09:00:00Z" },
  ]);
  mocks.tacPlan.mockResolvedValue(planResponse());
  mocks.tacCaptures.mockResolvedValue({
    captures: [], count: 0, limit: 200,
    formats: ["txt", "csv", "json", "yaml", "docx"], note: "",
  });
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

// ── the extraction is silent (owner, 2026-09-06) ─────────────────────────────

describe("classification and command extraction happen without being asked", () => {
  it("builds the plan for the incident's own device with no button press", async () => {
    await show(stateResponse({ state: stateWith({ plan: undefined, default_capture: undefined }) }));
    await waitFor(() => expect(mocks.tacPlan).toHaveBeenCalledWith(INC, {
      device_id: "leaf1", include_optional: false, class_id: "ospf-adjacency",
    }));
    // And the step never offers "build the plan" — it is not the customer's step.
    expect(screen.queryByRole("button", { name: /Build the command plan/ })).toBeNull();
  });

  it("shows no class, no intent id and no citation link in the escalation step", async () => {
    await show(stateResponse({ state: stateWith() }));
    const step = visibleStep();
    expect(step.textContent).not.toContain("ospf-adjacency");
    expect(step.textContent).not.toContain("system.version");
    expect(step.textContent).not.toContain("ospf.neighbors.detail");
    expect(step.textContent).not.toContain("From vendor docs");
    expect(step.querySelector("a")).toBeNull();
    // The whole panel carries no plan table and no citation while the one
    // disclosure is shut — this is mounting, not CSS.
    expect(screen.queryByTestId("tac-plan-table")).toBeNull();
    expect(screen.queryByTestId("tac-behind-body")).toBeNull();
  });

  it("asks for a device before there is anything to collect", async () => {
    await show(stateResponse({
      devices: [], state: stateWith({ plan: undefined, default_capture: undefined }),
    }));
    expect(screen.getByText(CAPTURES_NEED_DEVICE)).toBeInTheDocument();
  });
});

// ── captures ─────────────────────────────────────────────────────────────────

describe("captures", () => {
  it("lists the vendor default with its count, and hides its commands", async () => {
    await show(stateResponse({ state: stateWith() }));
    const row = screen.getByTestId("tac-capture-capture:vendor-default");
    expect(row).toHaveTextContent("Cisco IOS-XE default");
    expect(row).toHaveTextContent(commandCountLine(2));
    // Collapsed by default: the commands are not in the document at all.
    expect(screen.queryByTestId("tac-capture-cmds-capture:vendor-default")).toBeNull();
    expect(row.textContent).not.toContain("show version");
    expect(within(row).getByRole("button", { name: /Commands in Cisco IOS-XE default/ }))
      .toHaveAttribute("aria-expanded", "false");
  });

  it("reveals the commands when the chevron is used, and hides them again", async () => {
    await show(stateResponse({ state: stateWith() }));
    await click(/Commands in Cisco IOS-XE default/);
    const list = screen.getByTestId("tac-capture-cmds-capture:vendor-default");
    expect(within(list).getByText("show version")).toBeInTheDocument();
    expect(within(list).getByText("show ip ospf neighbor detail")).toBeInTheDocument();
    await click(/Commands in Cisco IOS-XE default/);
    expect(screen.queryByTestId("tac-capture-cmds-capture:vendor-default")).toBeNull();
  });

  it("reads Queued before anything has run", async () => {
    await show(stateResponse({ state: stateWith() }));
    const row = screen.getByTestId("tac-capture-capture:vendor-default");
    expect(within(row).getByText(CAPTURE_STATUS_LABEL.queued)).toBeInTheDocument();
  });

  it("shows Running while the collection is in flight", async () => {
    await show(stateResponse({
      state: stateWith({
        job: { id: "j1", status: "running", started_at: "t", total: 2, done: 1, progress: [] },
        progress: {
          capture_id: "capture:vendor-default", status: "running",
          total: 2, done: 1, failed: 0, commands: [],
        },
      }),
    }));
    const row = screen.getByTestId("tac-capture-capture:vendor-default");
    expect(within(row).getByText(CAPTURE_STATUS_LABEL.running)).toBeInTheDocument();
  });

  it("lists ONLY the commands that failed after a partial collection", async () => {
    await show(stateResponse({
      state: stateWith({
        job: { id: "j1", status: "done", started_at: "t", total: 2, done: 2, progress: [] },
        progress: {
          capture_id: "capture:vendor-default", status: "partial", total: 2, done: 1, failed: 1,
          commands: [{ command: "show ip ospf neighbor detail", status: "failed", reason: "timed out" }],
        },
      }),
    }));
    const row = screen.getByTestId("tac-capture-capture:vendor-default");
    expect(within(row).getByText(CAPTURE_STATUS_LABEL.partial)).toBeInTheDocument();
    const fails = screen.getByTestId("tac-capture-failed-capture:vendor-default");
    expect(fails).toHaveTextContent("show ip ospf neighbor detail — timed out");
    // The command that WORKED is not rendered — its output is in the bundle.
    expect(fails.textContent).not.toContain("show version");
    expect(fails.querySelector(".tac-capture-fail")).not.toBeNull();
  });

  it("lists nothing under a clean collection", async () => {
    await show(stateResponse({
      state: stateWith({
        job: { id: "j1", status: "done", started_at: "t", total: 2, done: 2, progress: [] },
        progress: {
          capture_id: "capture:vendor-default", status: "done",
          total: 2, done: 2, failed: 0, commands: [],
        },
      }),
    }));
    const row = screen.getByTestId("tac-capture-capture:vendor-default");
    expect(within(row).getByText(CAPTURE_STATUS_LABEL.done)).toBeInTheDocument();
    expect(screen.queryByTestId("tac-capture-failed-capture:vendor-default")).toBeNull();
  });

  it("never borrows a verdict for a capture that did not run", async () => {
    mocks.tacCaptures.mockResolvedValue({
      captures: [{
        id: "tpl-1", name: "ACME baseline", source: "template", dialect: "cisco-iosxe",
        commands: [{ command: "show ip route summary" }],
      }],
      count: 1, limit: 200, formats: ["txt"], note: "",
    });
    await show(stateResponse({
      state: stateWith({
        progress: {
          capture_id: "capture:vendor-default", status: "done",
          total: 2, done: 2, failed: 0, commands: [],
        },
      }),
    }));
    const saved = await screen.findByTestId("tac-capture-tpl-1");
    expect(within(saved).getByText(CAPTURE_STATUS_LABEL.queued)).toBeInTheDocument();
    expect(mocks.tacCaptures).toHaveBeenCalledWith("cisco-iosxe");
  });

  it("collects Correlix's own capture without sending a command list", async () => {
    mocks.tacCollect.mockResolvedValue({ job: { id: "j1", status: "running" }, state: stateWith() });
    await show(stateResponse({ state: stateWith() }));
    await click(/Start the collection/);
    expect(mocks.tacCollect).toHaveBeenCalledWith(INC, {});
  });

  it("collects a saved capture as a template, by id", async () => {
    mocks.tacCaptures.mockResolvedValue({
      captures: [{
        id: "tpl-1", name: "ACME baseline", source: "template", dialect: "cisco-iosxe",
        commands: [{ command: "show ip route summary" }, { command: "show logging" }],
      }],
      count: 1, limit: 200, formats: ["txt"], note: "",
    });
    mocks.tacCollect.mockResolvedValue({ job: { id: "j1", status: "running" }, state: stateWith() });
    await show(stateResponse({ state: stateWith() }));
    const saved = await screen.findByTestId("tac-capture-tpl-1");
    await act(async () => { fireEvent.click(within(saved).getByRole("radio")); });
    await click(/Start the collection/);
    expect(mocks.tacCollect).toHaveBeenCalledWith(INC, {
      steps: [{ command: "show ip route summary" }, { command: "show logging" }],
      template_id: "tpl-1",
    });
  });
});

// ── upload ───────────────────────────────────────────────────────────────────

describe("upload your own command list", () => {
  const file = (name: string, body = "show version\n") =>
    new File([body], name, { type: "application/octet-stream" });

  const drop = async (f: File) => {
    const input = screen.getByTestId("tac-upload") as HTMLInputElement;
    await act(async () => { fireEvent.change(input, { target: { files: [f] } }); });
  };

  it("names the formats it accepts", async () => {
    await show(stateResponse({ state: stateWith() }));
    expect(screen.getByText(UPLOAD_FORMATS_LINE)).toBeInTheDocument();
    expect((screen.getByTestId("tac-upload") as HTMLInputElement).accept).toContain(".docx");
  });

  it("adds the uploaded capture as a row and selects it, with its commands hidden", async () => {
    mocks.tacCaptureUpload.mockResolvedValue({
      capture: {
        id: "upload:txt", name: "acme runbook", source: "uploaded", dialect: "cisco-iosxe",
        commands: [{ command: "show version", line: 3 }, { command: "show logging", line: 4 }],
      },
    });
    await show(stateResponse({ state: stateWith() }));
    await drop(file("acme runbook.txt"));

    expect(mocks.tacCaptureUpload).toHaveBeenCalledWith(expect.any(File), "cisco-iosxe");
    const row = await screen.findByTestId("tac-capture-upload:txt");
    expect(row).toHaveTextContent("acme runbook");
    expect(row).toHaveTextContent(commandCountLine(2));
    expect(screen.queryByTestId("tac-capture-cmds-upload:txt")).toBeNull();
    expect(within(row).getByRole("radio")).toBeChecked();
  });

  it("refuses the WHOLE file by line and rule, and adds no row", async () => {
    mocks.tacCaptureUpload.mockRejectedValue(new Error(
      '400 Bad Request: {"error":"That file was not accepted: nothing in it will run until every line passes.",' +
      '"refusals":[{"line":5,"command":"configure terminal","family":"config","rule":"configure",' +
      '"reason":"refused by the output-only policy (config): it changes configuration"}]}',
    ));
    await show(stateResponse({ state: stateWith() }));
    await drop(file("bad.txt"));

    const refusals = await screen.findByTestId("tac-upload-refusals");
    expect(refusals).toHaveTextContent("Line 5: configure terminal");
    expect(refusals).toHaveTextContent("it changes configuration");
    expect(refusals).toHaveTextContent("rule `configure`");
    expect(screen.queryByTestId("tac-capture-upload:txt")).toBeNull();
    // Nothing partial was accepted: the row list still holds only the default.
    const rows = screen.getByTestId("tac-capture-rows").querySelectorAll("li.tac-capture-row");
    expect(rows).toHaveLength(1);
  });

  it("says what did not happen when the file itself cannot be read", async () => {
    mocks.tacCaptureUpload.mockRejectedValue(new Error("400 Bad Request: tac: that file type is not one Correlix reads"));
    await show(stateResponse({ state: stateWith() }));
    await drop(file("set.xlsx"));
    expect(await screen.findByTestId("tac-upload-error")).toHaveTextContent(/not one Correlix reads/);
  });

  it("saves an uploaded capture as a template for this tenant", async () => {
    mocks.tacCaptureUpload.mockResolvedValue({
      capture: {
        id: "upload:txt", name: "acme runbook", source: "uploaded", dialect: "cisco-iosxe",
        commands: [{ command: "show version" }],
      },
    });
    mocks.tacCaptureSave.mockResolvedValue({
      capture: {
        id: "tpl-9", name: "acme runbook", source: "template", dialect: "cisco-iosxe",
        commands: [{ command: "show version" }],
      },
    });
    await show(stateResponse({ state: stateWith() }));
    await drop(file("acme runbook.txt"));
    await screen.findByTestId("tac-capture-save");
    await act(async () => { fireEvent.click(screen.getByTestId("tac-capture-save-btn")); });

    expect(mocks.tacCaptureSave).toHaveBeenCalledWith({
      dialect: "cisco-iosxe", name: "acme runbook",
      commands: [{ command: "show version", note: undefined }],
    });
    await waitFor(() => expect(screen.getByTestId("tac-capture-save-note")).toHaveTextContent("Saved"));
  });

  it("offers no save control for Correlix's own capture", async () => {
    await show(stateResponse({ state: stateWith() }));
    expect(screen.queryByTestId("tac-capture-save")).toBeNull();
  });
});

// ── collect ──────────────────────────────────────────────────────────────────

describe("collect", () => {
  const unwired = () => stateResponse({
    state: stateWith(), can_collect: false, collect_note: COLLECT_NOTE,
  });

  it("disables the start and shows the server's own note when collection is unwired", async () => {
    await show(unwired());
    expect(screen.getByTestId("tac-collect-note")).toHaveTextContent(COLLECT_NOTE);
    expect(screen.getByRole("button", { name: /Start the collection/ })).toBeDisabled();
  });

  it("renders a 503 from the start as the server's own sentence", async () => {
    await show(stateResponse({ state: stateWith() }));
    mocks.tacCollect.mockRejectedValue(new Error(`503 Service Unavailable: {"error":${JSON.stringify(COLLECT_NOTE)}}`));
    await click(/Start the collection/);
    expect(screen.getByTestId("tac-collect-error")).toHaveTextContent(COLLECT_NOTE);
  });

  it("cancels a running collection", async () => {
    mocks.tacCancelCollect.mockResolvedValue({ cancelled: true });
    await show(stateResponse({
      state: stateWith({
        job: { id: "j1", status: "running", started_at: "t", total: 2, done: 0, progress: [] },
      }),
    }));
    await click("Stop");
    expect(mocks.tacCancelCollect).toHaveBeenCalledWith(INC);
  });

  it("offers no paste wall when the gateway can collect and nothing has failed", async () => {
    await show(stateResponse({ state: stateWith() }));
    expect(screen.queryByTestId("tac-paste")).toBeNull();
  });

  it("offers ONE control over the bound steps only, never an unbound intent", async () => {
    await show(stateResponse({ state: stateWith(), can_collect: false, collect_note: COLLECT_NOTE }));
    expect(screen.getByTestId("tac-paste")).toBeInTheDocument();
    expect(screen.getByText(PASTE_INVITE)).toBeInTheDocument();
    const picker = screen.getByTestId("tac-paste-picker") as HTMLSelectElement;
    const options = Array.from(picker.options).map((o) => o.value);
    expect(options).toEqual(["system.version", "ospf.neighbors.detail"]);
    expect(options).not.toContain("ospf.database.router");
    expect(screen.getByTestId("tac-paste-count")).toHaveTextContent(missingOutputsLine(2, 2));
  });

  it("files ONE pasted output for the step the operator picked", async () => {
    mocks.tacCollect.mockResolvedValue({ job: { id: "j1", status: "done" }, state: stateWith() });
    await show(stateResponse({ state: stateWith(), can_collect: false, collect_note: COLLECT_NOTE }));
    fireEvent.change(screen.getByTestId("tac-paste-picker"), { target: { value: "ospf.neighbors.detail" } });
    fireEvent.change(screen.getByLabelText("Pasted output"), { target: { value: "Neighbor 10.0.0.2 FULL" } });
    await click("Add output");
    expect(mocks.tacCollect).toHaveBeenCalledWith(INC, {
      outputs: [{ intent: "ospf.neighbors.detail", command: "show ip ospf neighbor detail", output: "Neighbor 10.0.0.2 FULL" }],
    });
  });
});

// ── behind the scenes ────────────────────────────────────────────────────────

describe("what Correlix is doing", () => {
  it("is one control, collapsed, and mounts nothing until it is opened", async () => {
    await show(stateResponse({ state: stateWith() }));
    const toggle = screen.getByTestId("tac-behind-toggle");
    expect(toggle).toHaveTextContent(BEHIND_LABEL);
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByTestId("tac-behind-body")).toBeNull();
  });

  it("shows the class it chose and the evidence rows that scored it", async () => {
    await show();
    mocks.tacClassify.mockResolvedValue(classifyResponse());
    mocks.tacState.mockResolvedValue(stateResponse({ state: stateWith() }));
    await click("Escalate to TAC");
    const body = await openBehind();

    expect(body).toHaveTextContent("OSPF adjacency will not form or is stuck");
    expect(body).toHaveTextContent("signature ospf-exstart-mtu · weight 5");
    expect(body).toHaveTextContent("OSPF flapping link");
    expect(body).toHaveTextContent(/score 2/);
    expect(body).toHaveTextContent(/What TAC opens first:/);
    expect(screen.getByTestId("tac-evidence")).toHaveTextContent(
      "Classified on: correlation object · case timeline",
    );
    expect(screen.getByTestId("tac-evidence")).toHaveTextContent(
      "Classified without: incident register (not readable for this id)",
    );
  });

  it("never invents a class when nothing scored", async () => {
    await show();
    const unclassified = classification({
      class_id: "generic", title: "General escalation", classified: false,
      why: [], alternatives: [], note: "",
    });
    mocks.tacClassify.mockResolvedValue(classifyResponse({ classification: unclassified as never }));
    mocks.tacState.mockResolvedValue(stateResponse({
      state: stateWith({ classification: unclassified as never }),
    }));
    await click("Escalate to TAC");
    await openBehind();

    expect(screen.getByText("nothing scored")).toBeInTheDocument();
    expect(screen.getByText(NOTHING_SCORED_NOTE)).toBeInTheDocument();
    expect(screen.getByText("No evidence row scored this class.")).toBeInTheDocument();
    // The blanks and the list labels are STATED FACTS, not explanatory notes
    // (sweep 5, tracker 270) — they carry `fact-line`, and the guard counts notes.
    expect(screen.getByText("No evidence row scored this class.").className).toContain("fact-line");
  });

  it("offers the FULL class list as an override, and re-plans on it", async () => {
    await show();
    mocks.tacClassify.mockResolvedValue(classifyResponse());
    mocks.tacState.mockResolvedValue(stateResponse({ state: stateWith() }));
    await click("Escalate to TAC");
    await openBehind();

    const sel = screen.getByLabelText("Issue class") as HTMLSelectElement;
    expect(Array.from(sel.options).map((o) => o.value))
      .toEqual(["ospf-adjacency", "bgp-session", "generic"]);
    await act(async () => { fireEvent.change(sel, { target: { value: "bgp-session" } }); });
    await waitFor(() => expect(mocks.tacPlan).toHaveBeenCalledWith(INC, {
      device_id: "leaf1", include_optional: false, class_id: "bgp-session",
    }));
  });

  it("carries the plan table with its sources and verification state", async () => {
    await show(stateResponse({ state: stateWith() }));
    const body = await openBehind();
    const table = within(body).getByTestId("tac-plan-table");
    const rows = table.querySelectorAll("tbody tr");
    expect(rows).toHaveLength(2);
    expect(rows[0].textContent).toContain("Software version");
    expect(rows[0].textContent).toContain("show version");
    expect(rows[1].textContent).toContain("From vendor docs");
    expect(within(table).getByRole("link", { name: /Vendor page for OSPF neighbours/ }))
      .toHaveAttribute("href", "https://example.invalid/ospf");
    // The intent id stays on the row's tooltip for support, never in a cell.
    expect(rows[0].getAttribute("title")).toContain("system.version");
    expect(rows[0].textContent).not.toContain("system.version");
  });

  it("sends the typed target on Rebuild", async () => {
    await show(stateResponse({ state: stateWith() }));
    await openBehind();
    await act(async () => {
      fireEvent.change(screen.getByLabelText("Interface"), { target: { value: "Gi0/1" } });
      fireEvent.click(screen.getByLabelText(/Include the optional captures/));
    });
    await act(async () => { fireEvent.click(screen.getByTestId("tac-rebuild")); });
    expect(mocks.tacPlan).toHaveBeenLastCalledWith(INC, {
      device_id: "leaf1", include_optional: true, class_id: "ospf-adjacency",
      target: { interface: "Gi0/1" },
    });
  });

  it("carries the collection log with the per-command progress", async () => {
    await show(stateResponse({
      state: stateWith({
        job: {
          id: "j1", status: "done", started_at: "t", total: 2, done: 2,
          progress: [
            { index: 0, total: 2, intent: "system.version", command: "show version", phase: "done", bytes: 512 },
            { index: 1, total: 2, intent: "ospf.neighbors.detail", command: "show ip ospf neighbor detail", phase: "error", error: "timed out" },
          ],
        },
      }),
    }));
    const body = await openBehind();
    const job = within(body).getByTestId("tac-job");
    expect(job).toHaveTextContent("2 of 2 commands");
    expect(job).toHaveTextContent("show version");
    expect(job).toHaveTextContent("timed out");
  });

  it("renders captured device output as escaped text, never as markup", async () => {
    await show(stateResponse({
      state: stateWith({
        capture: {
          incident_id: INC, plan_id: "plan-1", class_id: "ospf-adjacency", class_title: "x",
          device_id: "leaf1", hostname: "leaf1", platform: "p", dialect: "cisco-iosxe",
          dialect_display: "Cisco IOS-XE", has_plan: true, started_at: "x", finished_at: "y",
          commands: [{
            intent: "system.version", title: "Software version", section: "baseline",
            command: "show version", bytes: 40, started_at: "x", duration_ms: 5,
            output: "<img src=x onerror=alert(1)>Version 17.9",
          }],
          unbound: [], topology: [], target: {}, total_bytes: 40, redacted: true,
          catalog_version: "v", engine_version: "e",
        },
      }),
    }));
    const body = await openBehind();
    const pre = within(body).getByText(/Version 17.9/);
    expect(pre.querySelector("img")).toBeNull();
    expect(pre.textContent).toContain("<img src=x onerror=alert(1)>");
  });
});

// ── bundle ───────────────────────────────────────────────────────────────────

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

  it("states the redaction promise once, as ONE line, with the server's own words on it", async () => {
    await show(stateResponse({ state: stateWith() }));
    const line = screen.getByTestId("tac-redaction");
    expect(line).toHaveTextContent(REDACTION_SHORT);
    expect(line).toHaveAttribute("title", plan().redaction_note);
    expect(screen.getAllByTestId("tac-redaction")).toHaveLength(1);
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

  it("names the built-bundle list in three words or fewer", async () => {
    await show(captured());
    expect(screen.getByRole("heading", { name: "Built bundles" })).toBeInTheDocument();
    expect(screen.queryByText("Bundles built for this incident")).toBeNull();
  });

  it("says what did not happen when the download is refused", async () => {
    await show(captured());
    mocks.tacDownloadBundle.mockRejectedValue(new Error("409 Conflict: {\"error\":\"collect the evidence first\"}"));
    await click("Download the redacted bundle");
    expect(screen.getByRole("alert")).toHaveTextContent("Collect the evidence first.");
  });

  it("says 'No bundle yet' in one short line", async () => {
    await show(stateResponse({ state: stateWith() }));
    expect(screen.getByText(NO_BUNDLE_YET)).toBeInTheDocument();
    expect(NO_BUNDLE_YET.split(/\s+/)).toHaveLength(3);
  });
});

// ── open the case ────────────────────────────────────────────────────────────

describe("open the case", () => {
  const withConnectors = () => stateResponse({
    state: stateWith(),
    connectors: [
      {
        id: "servicenow", display: "ServiceNow", vendor: "servicenow", capabilities: ["create", "attach"],
        max_attachment_bytes: 18 * 1024 * 1024, profile: "full", configured: true,
      },
      {
        id: "cisco-cxd", display: "Cisco TAC", vendor: "cisco", capabilities: ["create", "attach"],
        max_attachment_bytes: 20 * 1024 * 1024, profile: "full", configured: false,
        status_note: "Bring a Smart Bonding client id and a CXD token for this tenant.",
      },
      {
        id: "portal-text", display: "Vendor portal text", capabilities: ["link"],
        max_attachment_bytes: 0, profile: "link_only", configured: true,
      },
    ],
  });

  it("greys an unconfigured connector and links to where credentials are brought", async () => {
    await show(withConnectors());
    const row = screen.getByTestId("tac-conn-cisco-cxd");
    expect(row.className).toContain("off");
    expect(row).toHaveTextContent(CONNECTOR_CHIP["not-configured"]);
    expect(within(row).getByRole("link", { name: "Ticket delivery" }))
      .toHaveAttribute("href", "#/admin/ticket-delivery");
    expect(screen.getByRole("button", { name: "Cisco TAC" })).toBeDisabled();
  });

  it("says in plain words what each connector does", async () => {
    await show(withConnectors());
    expect(screen.getByTestId("tac-conn-portal-text"))
      .toHaveTextContent("Prepares the text and bundle for you to paste");
    expect(screen.getByTestId("tac-conn-servicenow"))
      .toHaveTextContent("Opens the case and attaches the bundle");
  });

  it("pre-fills the form, marks the fields the vendor requires and shows the case text", async () => {
    await show(withConnectors());
    mocks.tacCaseForm.mockResolvedValue(caseFormResponse());
    await click("ServiceNow");

    expect(mocks.tacCaseForm).toHaveBeenCalledWith(INC, "servicenow");
    expect(screen.getByTestId("tac-case-form")).toBeInTheDocument();
    expect((screen.getByLabelText(/^Title/) as HTMLInputElement).value).toBe("OSPF adjacency down on leaf1");
    expect(screen.getByLabelText(/Serial number — the vendor requires this/)).toBeRequired();
    expect((screen.getByLabelText("Case text") as HTMLTextAreaElement).value)
      .toBe("Problem statement for the vendor portal.");
    expect(screen.getByLabelText("Case text")).toHaveAttribute("readonly");
    expect(screen.getByRole("heading", { name: /ServiceNow — review before sending/ })).toBeInTheDocument();
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
    expect(screen.getByText(NO_CASE_CONNECTOR)).toBeInTheDocument();
    expect(NO_CASE_CONNECTOR).toMatch(/download the bundle/);
    expect(NO_CASE_CONNECTOR.split(/\s+/).length).toBeLessThanOrEqual(8);
    expect(screen.getByRole("button", { name: "Ask Iris about No case connector" })).toBeInTheDocument();
  });
});

// ── the unconfigured-connector guard, and the "not configured" wording ───────

describe("an unconfigured connector never becomes a case", () => {
  it("cannot be pressed, so no form is ever requested for it", async () => {
    await show(stateResponse({
      state: stateWith(),
      connectors: [{
        id: "juniper", display: "Juniper", vendor: "juniper", capabilities: ["create"],
        max_attachment_bytes: 0, profile: "full", configured: false,
      }],
    }));
    const row = screen.getByTestId("tac-conn-juniper");
    expect(row).toHaveTextContent(CONNECTOR_CHIP["not-configured"]);
    expect(within(row).getByRole("link", { name: "Ticket delivery" })).toHaveAttribute("title", CONNECTOR_NOT_CONFIGURED);
    fireEvent.click(screen.getByRole("button", { name: "Juniper" }));
    expect(mocks.tacCaseForm).not.toHaveBeenCalled();
  });
});

// ── the step reads like a study, not a menu (owner, 2026-09-06) ─────────────

describe("the Nokia escalation shows the paths this device can use", () => {
  const NOKIA_RESEARCH =
    "NSP publishes exactly five APIs (NSP REST, RESTCONF, Kafka, NFM-P REST, NFM-P XML) and none is a " +
    "case/ticket/TSR API (checked 2026-09-05). phone is the vendor-preferred channel for outages.";
  const JIRA_RESEARCH =
    "Cloud defaults to 1 GB per attachment on /rest/api/3, Data Center to 10 MB on /rest/api/2. " +
    "Jira Cloud rate-limits 20 writes per 2 s PER ISSUE.";

  const nokiaPlan = () => plan({ dialect: "nokia-srlinux", dialect_display: "Nokia SR Linux" });

  /** The twelve the api actually ships, as the lab returns them. */
  const twelve = (over: Record<string, Partial<TacStateResponse["connectors"][number]>> = {}) => {
    const rows: TacStateResponse["connectors"] = [
      { id: "email-arista", display: "Arista support email", vendor: "arista", capabilities: ["create", "attach", "link"], max_attachment_bytes: 14_000_000, profile: "email", configured: false },
      { id: "email-cisco", display: "Cisco support email", vendor: "cisco", capabilities: ["attach"], max_attachment_bytes: 14_000_000, profile: "email", configured: false },
      { id: "jira", display: "Jira issue", vendor: "jira", capabilities: ["create", "attach", "poll_status", "link"], max_attachment_bytes: 1_073_741_824, profile: "full", configured: true, note: JIRA_RESEARCH },
      { id: "servicenow", display: "ServiceNow incident", vendor: "servicenow", capabilities: ["create", "attach", "poll_status", "link"], max_attachment_bytes: 1_073_741_824, profile: "full", configured: false },
      { id: "cisco-cxd", display: "Cisco CXD (attach to an existing SR)", vendor: "cisco", capabilities: ["attach"], max_attachment_bytes: 8_589_934_592, profile: "full", configured: false },
      { id: "cisco-smart-bonding", display: "Cisco Smart Bonding (open an SR)", vendor: "cisco", capabilities: ["create", "attach", "poll_status", "link"], max_attachment_bytes: 8_589_934_592, profile: "full", configured: false },
      { id: "juniper", display: "Juniper Service Case", vendor: "juniper", capabilities: ["create", "attach", "poll_status", "link"], max_attachment_bytes: 8_589_934_592, profile: "full", configured: false },
      { id: "portal-fortinet", display: "Fortinet portal (copy & paste)", vendor: "fortinet", capabilities: [], max_attachment_bytes: 0, profile: "link_only", configured: true },
      { id: "portal-huawei", display: "Huawei portal (copy & paste)", vendor: "huawei", capabilities: [], max_attachment_bytes: 0, profile: "link_only", configured: true },
      { id: "portal-nokia", display: "Nokia portal (copy & paste)", vendor: "nokia", capabilities: [], max_attachment_bytes: 0, profile: "link_only", configured: true, note: NOKIA_RESEARCH },
      { id: "portal-paloalto", display: "Palo Alto portal (copy & paste)", vendor: "paloalto", capabilities: [], max_attachment_bytes: 0, profile: "link_only", configured: true },
      { id: "portal-text", display: "Vendor portal / email (copy & paste)", capabilities: ["link"], max_attachment_bytes: 0, profile: "link_only", configured: true },
    ];
    return rows.map((r) => ({ ...r, ...(over[r.id] ?? {}) }));
  };

  const nokiaState = (over: Record<string, Partial<TacStateResponse["connectors"][number]>> = {}) =>
    stateResponse({ state: stateWith({ plan: nokiaPlan() }), connectors: twelve(over) });

  it("shows the Nokia path, the configured ITSM and the generic one — the rest are folded", async () => {
    await show(nokiaState());
    const rows = screen.getByTestId("tac-conn-rows");
    const ids = Array.from(rows.querySelectorAll("li")).map((li) => li.getAttribute("data-testid"));
    expect(ids).toEqual(["tac-conn-jira", "tac-conn-portal-nokia", "tac-conn-portal-text"]);

    const others = screen.getByTestId("tac-conn-others") as HTMLDetailsElement;
    expect(others.open).toBe(false);
    expect(within(others).getByText(showAllConnectorsLabel(9))).toBeInTheDocument();
    // Nothing is hidden — every connector is still reachable, one press away.
    expect(within(others).getByTestId("tac-conn-portal-fortinet")).toBeInTheDocument();
    expect(within(others).getByTestId("tac-conn-juniper")).toBeInTheDocument();
  });

  it("carries no research paragraph in the visible step — it is behind the (i)", async () => {
    await show(nokiaState());
    const step = screen.getByTestId("tac-conn-rows");
    expect(step.textContent).not.toContain("NSP publishes exactly five APIs");
    expect(step.textContent).not.toContain("checked 2026-09-05");
    expect(step.textContent).not.toContain("rate-limits 20 writes");
    expect(step.textContent).not.toContain("1 GB per attachment");
    const nokiaRow = screen.getByTestId("tac-conn-portal-nokia");
    expect(within(nokiaRow).getByRole("button", { name: /Ask Iris/ }))
      .toHaveAttribute("data-topic", connectorTopic("portal-nokia"));
  });

  it("carries ONE chip per row, and never says 'could not be read' for a fresh tenant", async () => {
    await show(nokiaState());
    const rows = screen.getByTestId("tac-conn-rows");
    expect(rows.textContent).not.toContain("could not be read");
    expect(within(screen.getByTestId("tac-conn-jira")).getByText(CONNECTOR_CHIP.ready)).toBeInTheDocument();
    expect(within(screen.getByTestId("tac-conn-portal-nokia")).getByText(CONNECTOR_CHIP.ready)).toBeInTheDocument();
    for (const li of Array.from(rows.querySelectorAll("li"))) {
      expect(li.querySelectorAll(".tac-chip")).toHaveLength(1);
    }
  });

  it("chips an attach-only connector as such", async () => {
    await show(nokiaState({ "email-cisco": { configured: true } }));
    const row = within(screen.getByTestId("tac-conn-others")).getByTestId("tac-conn-email-cisco");
    expect(row).toHaveTextContent(CONNECTOR_CHIP["attach-only"]);
    expect(row).toHaveTextContent("Attaches to an existing case");
  });

  it("names the cause when a connector's configuration really cannot be read", async () => {
    await show(nokiaState({
      jira: { configured: false, unavailable: true, status_note: "the stored connector configuration could not be read: app_kv: connection refused" },
    }));
    const row = screen.getByTestId("tac-conn-jira");
    expect(row).toHaveTextContent(CONNECTOR_CHIP.unavailable);
    expect(within(row).getByRole("alert")).toHaveTextContent("app_kv: connection refused");
  });

  it("mentions an attachment ceiling only when the bundle exceeds it", async () => {
    await show(nokiaState({ "email-arista": { configured: true } }));
    expect(screen.getByTestId("tac-conn-others").textContent).not.toContain("13 MB");

    cleanup();
    await show(stateResponse({
      state: stateWith({
        plan: plan({ dialect: "arista-eos", dialect_display: "Arista EOS" }),
        bundles: [{
          name: "correlix-tac-INC-2026-0007-email.zip", bytes: 30_000_000,
          created_at: "2026-09-05T10:05:00Z", incident_id: INC, profile: "email",
          class_id: "ospf-adjacency", plan_id: "plan-1",
        }],
      }),
      connectors: twelve({ "email-arista": { configured: true } }),
    }));
    expect(screen.getByTestId("tac-conn-email-arista")).toHaveTextContent("over the 13 MB limit");
  });
});
