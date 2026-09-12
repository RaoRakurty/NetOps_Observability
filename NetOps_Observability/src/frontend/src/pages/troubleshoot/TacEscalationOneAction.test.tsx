// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// TacEscalationOneAction.test.tsx — the ONE ACTION and the ONE confirmation
// screen (internal/tac/escalate.go, internal/tac/dryrun.go).
//
// Owner, 2026-09-06: "ease of collecting data and open the case with one or two
// clicks, that's the goal." So the guard is the shape of the flow, not just its
// happy path:
//
//   · ONE press classifies, escalates and starts collecting, and the route it
//     chose is on screen WITH the server's sentence saying why;
//   · the confirmation screen is built with NO second press — prepare runs on
//     its own once the collection has finished;
//   · that screen shows exactly what will be sent, and carries the redaction
//     promise and the approval sentence VERBATIM above the button;
//   · `ready:false` DISABLES the button and names every blocker with its reason
//     and a link to where it is set — no case is ever filed with a blank
//     entitlement field;
//   · warnings are shown and do not block;
//   · a portal route is a COMPLETE outcome, not a failure;
//   · the dry run is SECONDARY, answers in one of six closed outcomes, and says
//     the server's own "nothing was created".
//
// The honest-state sentences are asserted BY IMPORT from tacModel, never as
// copy-pasted literals.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, act } from "@testing-library/react";
import type {
  TacConnectorInfo,
  TacDryRunOutcome,
  TacDryRunReport,
  TacProposal,
  TacState,
  TacStateResponse,
} from "../../services/api";

const mocks = vi.hoisted(() => ({
  tacState: vi.fn(), tacClassify: vi.fn(), tacPlan: vi.fn(), tacCollect: vi.fn(),
  tacCancelCollect: vi.fn(), tacDownloadBundle: vi.fn(), tacCaseForm: vi.fn(),
  tacCaseSubmit: vi.fn(), devices: vi.fn(), tacCaptures: vi.fn(),
  tacCaptureUpload: vi.fn(), tacCaptureSave: vi.fn(),
  tacEscalate: vi.fn(), tacEscalatePrepare: vi.fn(), tacEscalateConfirm: vi.fn(),
  tacEscalateDryRun: vi.fn(), tacCaseRefresh: vi.fn(),
}));
vi.mock("../../services/api", () => ({ api: { ...mocks } }));

import TacEscalationPanel from "./TacEscalationPanel";
import {
  caseNumberRefusal,
  CONFIRM_ACTION,
  CONFIRM_PORTAL_ACTION,
  CONFIRM_PORTAL_NEXT,
  DRY_RUN_ACTION,
  DRY_RUN_CREATED_NOTHING,
  DRY_RUN_SENTENCE,
  ESCALATE_FAILED,
  PREPARING_NOTE,
  UPLOAD_TOKEN_LABEL,
} from "./tacModel";

const INC = "corr-abc1234567890";

// ── fixtures ─────────────────────────────────────────────────────────────────

const CISCO: TacConnectorInfo = {
  id: "cisco-smart-bonding",
  display: "Cisco Smart Bonding",
  vendor: "cisco",
  capabilities: ["create", "attach", "poll_status", "link"],
  max_attachment_bytes: 1 << 30,
  profile: "full",
  configured: true,
  auth_mode: "oauth",
  severity_values: ["S1", "S2", "S3", "S4"],
};

const PORTAL: TacConnectorInfo = {
  id: "portal-text",
  display: "Portal text",
  capabilities: [],
  max_attachment_bytes: 0,
  profile: "link_only",
  configured: true,
};

const CXD: TacConnectorInfo = {
  id: "cisco-cxd",
  display: "Cisco CXD",
  vendor: "cisco",
  capabilities: ["attach"],
  max_attachment_bytes: 1 << 30,
  profile: "full",
  configured: true,
  auth_mode: "basic",
};

const capture = {
  id: "cap-1", incident_id: INC, plan_id: "plan-1", class_id: "ospf-adjacency",
  class_title: "OSPF adjacency", device_id: "leaf1", hostname: "leaf1",
  platform: "Cisco IOS-XE 17.9", dialect: "cisco-iosxe", serial: "FDO123", model: "C9300",
  started_at: "2026-09-07T09:00:00Z", finished_at: "2026-09-07T09:01:00Z",
  total_bytes: 4096, commands: [], unbound: [], topology: [], target: {},
  redaction_note: "", stopped: "",
};

const state = (over: Partial<TacState> = {}): TacState => ({
  incident_id: INC,
  bundles: [],
  updated_at: "2026-09-07T09:01:00Z",
  capture: capture as never,
  ...over,
});

const stateResponse = (over: Partial<TacStateResponse> = {}): TacStateResponse => ({
  incident_id: INC,
  incident_ref: "INC-2026-0007",
  title: "OSPF adjacency down on leaf1",
  can_collect: true,
  collect_note: "",
  catalog_version: "correlix-tac-classes-2026-09-05",
  connectors: [CISCO, PORTAL],
  devices: ["leaf1"],
  state: null,
  state_note: "This incident has not been escalated in this api process.",
  ...over,
});

const classifyResponse = () => ({
  incident_id: INC,
  classification: {
    class_id: "ospf-adjacency", title: "OSPF adjacency will not form", protocol: "ospf",
    classified: true, why: [], alternatives: [], note: "",
    catalog_version: "correlix-tac-classes-2026-09-05",
  },
  evidence_sources: ["correlation object"],
  evidence_missing: [],
  classes: [{ id: "ospf-adjacency", title: "OSPF adjacency will not form", protocol: "ospf", summary: "" }],
});

const ROUTE = {
  connector_id: "cisco-smart-bonding",
  display: "Cisco Smart Bonding",
  vendor: "cisco",
  reason: "tenant_route" as const,
  note: "your team routed Cisco cases here.",
  configured: true,
  portal: false,
  auth_mode: "oauth",
  alternatives: ["cisco-smart-bonding", "portal-text"],
};

const REDACTION = "Passwords, keys and community strings are masked; tenant ids are kept.";
const APPROVAL =
  "Correlix never opens a case on its own. Nothing above has been sent — " +
  "pressing Open case is what sends it, from you, with your name on it.";

const proposal = (over: Partial<TacProposal> = {}): TacProposal => ({
  incident_id: INC,
  route: ROUTE,
  form: {
    connector_id: "cisco-smart-bonding",
    title: "OSPF adjacency will not form on leaf1",
    description: "OSPF adjacency on leaf1 has been stuck in EXSTART since 09:02 UTC.",
    severity: "S2",
    product: "C9300",
    serial_number: "FDO123",
    contract_id: "SVC-4411",
    contact_name: "Jane Doe",
    contact_email: "jane.doe@example.com",
    bundle_name: "correlix-tac-INC-2026-0007.zip",
    bundle_bytes: 2_400_000,
    profile: "full",
    portal_text: "Case text for the vendor portal.",
  },
  bundle: {
    name: "correlix-tac-INC-2026-0007.zip", bytes: 2_400_000,
    created_at: "2026-09-07T09:02:00Z", incident_id: INC, profile: "full",
    class_id: "ospf-adjacency", plan_id: "plan-1",
  },
  ready: true,
  redaction: REDACTION,
  approval: APPROVAL,
  prepared_at: "2026-09-07T09:02:00Z",
  ...over,
});

const dryRun = (over: Partial<TacDryRunReport> = {}): TacDryRunReport => ({
  connector_id: "cisco-smart-bonding",
  display: "Cisco Smart Bonding",
  outcome: "ok",
  auth_mode: "oauth",
  note: "Cisco returned a token for this client.",
  calls: [
    {
      step: "authenticate", method: "POST", url: "https://id.cisco.com/oauth2/default/v1/token",
      performed: true,
      fields: [{ name: "client_id", value: "corx-9911" }, { name: "client_secret", value: "[REDACTED]", secret: true }],
    },
    {
      step: "create the case", method: "POST", url: "https://api.cisco.com/smartbonding/push",
      performed: false,
      fields: [
        { name: "synopsis", vendor_name: "problemSynopsis", value: "OSPF adjacency will not form on leaf1" },
        { name: "serial_number", vendor_name: "serialNumber", value: "FDO123" },
      ],
      note: "Cisco publishes no schema for this body; the field names come from your onboarding.",
    },
  ],
  created_nothing: true,
  elapsed_ms: 412,
  at: "2026-09-07T09:03:00Z",
  ...over,
});

// ── harness ──────────────────────────────────────────────────────────────────

beforeEach(() => {
  Object.values(mocks).forEach((m) => m.mockReset());
  mocks.devices.mockResolvedValue([{ id: "leaf1", name: "leaf1", address: "10.0.0.1", source: "snmp", last_seen: "" }]);
  mocks.tacCaptures.mockResolvedValue({ captures: [], count: 0, limit: 200, formats: [], note: "" });
  mocks.tacPlan.mockResolvedValue({ plan: undefined, can_collect: true, collect_note: "" });
  mocks.tacClassify.mockResolvedValue(classifyResponse());
  mocks.tacState.mockResolvedValue(stateResponse());
  mocks.tacEscalate.mockResolvedValue({
    incident_id: INC, route: ROUTE, state: state(), can_collect: true, collect_note: "",
    capture_note: "", evidence_sources: [], evidence_missing: [], connectors: [CISCO, PORTAL],
  });
  mocks.tacEscalatePrepare.mockResolvedValue({ proposal: proposal(), state: state() });
});
afterEach(() => cleanup());

/** Render, let the state read settle, press Escalate, let prepare settle. */
async function escalate(res: TacStateResponse = stateResponse()) {
  mocks.tacState.mockResolvedValue(res);
  render(<TacEscalationPanel incidentId={INC} />);
  await act(async () => { await Promise.resolve(); });
  await act(async () => { await Promise.resolve(); });
  // The escalate reply carries the state; the panel re-reads it afterwards.
  mocks.tacState.mockResolvedValue({ ...res, state: state() });
  await act(async () => { fireEvent.click(screen.getByTestId("tac-escalate")); });
  await act(async () => { await Promise.resolve(); });
}

// ── click one ────────────────────────────────────────────────────────────────

describe("ONE press starts the whole escalation", () => {
  it("classifies and escalates on the same press, with no device chosen by hand", async () => {
    await escalate();
    expect(mocks.tacClassify).toHaveBeenCalledWith(INC);
    await waitFor(() => expect(mocks.tacEscalate).toHaveBeenCalledWith(INC, {
      device_id: "leaf1", include_optional: false, class_id: "ospf-adjacency",
    }));
  });

  it("says which route was chosen and the SERVER's sentence saying why", async () => {
    mocks.tacEscalatePrepare.mockImplementation(() => new Promise(() => {}));
    await escalate();
    const route = await screen.findByTestId("tac-route");
    expect(route).toHaveTextContent("Cisco Smart Bonding");
    expect(route).toHaveTextContent("your team routed Cisco cases here.");
  });

  it("prepares the confirmation screen with NO second press", async () => {
    await escalate();
    await waitFor(() => expect(mocks.tacEscalatePrepare).toHaveBeenCalled());
    expect(await screen.findByTestId("tac-confirm")).toBeInTheDocument();
  });

  it("says what did not happen when the escalation itself fails", async () => {
    mocks.tacEscalate.mockRejectedValue(new Error("503 Service Unavailable: {}"));
    await escalate();
    expect(await screen.findByTestId("tac-escalate-error")).toHaveTextContent(/./);
    // The classification still happened, so the rest of the panel still works.
    expect(mocks.tacClassify).toHaveBeenCalled();
  });

  it("says it is still collecting rather than showing an empty screen", async () => {
    mocks.tacEscalatePrepare.mockImplementation(() => new Promise(() => {}));
    mocks.tacState.mockResolvedValue(stateResponse({ state: state({ capture: undefined }) }));
    await escalate(stateResponse({ state: state({ capture: undefined }) }));
    expect(await screen.findByTestId("tac-preparing")).toHaveTextContent(PREPARING_NOTE);
  });
});

// ── the one confirmation screen ──────────────────────────────────────────────

describe("the confirmation screen shows exactly what will be sent", () => {
  it("carries the route, the title, the contact, the serial, the contract, the bundle and the statement", async () => {
    await escalate();
    const panel = await screen.findByTestId("tac-confirm");
    expect(screen.getByTestId("tac-confirm-route")).toHaveTextContent("your team routed Cisco cases here.");
    expect((screen.getByTestId("tac-confirm-title") as HTMLInputElement).value)
      .toBe("OSPF adjacency will not form on leaf1");
    expect((screen.getByTestId("tac-confirm-contact_name") as HTMLInputElement).value).toBe("Jane Doe");
    expect((screen.getByTestId("tac-confirm-contact_email") as HTMLInputElement).value).toBe("jane.doe@example.com");
    expect((screen.getByTestId("tac-confirm-serial_number") as HTMLInputElement).value).toBe("FDO123");
    expect((screen.getByTestId("tac-confirm-contract_id") as HTMLInputElement).value).toBe("SVC-4411");
    expect(screen.getByTestId("tac-confirm-device")).toHaveTextContent("C9300 · FDO123");
    expect(screen.getByTestId("tac-confirm-bundle")).toHaveTextContent("correlix-tac-INC-2026-0007.zip");
    expect(screen.getByTestId("tac-confirm-bundle")).toHaveTextContent("2.3 MB");
    expect((screen.getByTestId("tac-confirm-statement") as HTMLTextAreaElement).value)
      .toContain("stuck in EXSTART");
    expect(panel).toBeInTheDocument();
  });

  it("carries the two standing claims VERBATIM, above the button", async () => {
    await escalate();
    expect(await screen.findByTestId("tac-redaction-promise")).toHaveTextContent(REDACTION);
    expect(screen.getByTestId("tac-approval")).toHaveTextContent(APPROVAL);
  });

  it("offers the vendor's OWN severity vocabulary when it publishes one", async () => {
    await escalate();
    const sel = await screen.findByTestId("tac-confirm-severity");
    expect(sel.tagName).toBe("SELECT");
    expect(Array.from((sel as HTMLSelectElement).options).map((o) => o.value))
      .toEqual(["", "S1", "S2", "S3", "S4"]);
  });

  it("falls back to free text when the vendor publishes no vocabulary", async () => {
    const bare = { ...CISCO, severity_values: [] };
    mocks.tacState.mockResolvedValue(stateResponse({ connectors: [bare, PORTAL], state: state() }));
    await escalate(stateResponse({ connectors: [bare, PORTAL] }));
    const box = await screen.findByTestId("tac-confirm-severity");
    expect(box.tagName).toBe("INPUT");
  });

  it("asks for the case it is attaching to on an attach-only path", async () => {
    mocks.tacEscalate.mockResolvedValue({
      incident_id: INC, route: { ...ROUTE, connector_id: "cisco-cxd", display: "Cisco CXD" },
      state: state(), can_collect: true, collect_note: "", capture_note: "",
      evidence_sources: [], evidence_missing: [], connectors: [CXD, PORTAL],
    });
    mocks.tacEscalatePrepare.mockResolvedValue({
      proposal: proposal({ route: { ...ROUTE, connector_id: "cisco-cxd", display: "Cisco CXD" } }),
      state: state(),
    });
    await escalate(stateResponse({ connectors: [CXD, PORTAL] }));
    expect(await screen.findByTestId("tac-confirm-existing-case")).toBeInTheDocument();
  });

  it("opens the case with the operator's own edits — CLICK TWO", async () => {
    mocks.tacEscalateConfirm.mockResolvedValue({
      result: { connector_id: "cisco-smart-bonding", case_id: "689123456", attached: true, submitted_at: "" },
      case: {
        connector: "cisco-smart-bonding", case_id: "689123456", opened_at: "2026-09-07T09:05:00Z",
        tier: "high", attached: true, pollable: true, closed: false, status: "Open", auth_mode: "oauth",
      },
    });
    await escalate();
    await screen.findByTestId("tac-confirm-btn");
    fireEvent.change(screen.getByTestId("tac-confirm-title"), { target: { value: "Edited title" } });
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: CONFIRM_ACTION })); });
    expect(mocks.tacEscalateConfirm).toHaveBeenCalledWith(INC, {
      form: {
        title: "Edited title", severity: "S2", product: "C9300", serial_number: "FDO123",
        contract_id: "SVC-4411", contact_name: "Jane Doe", contact_email: "jane.doe@example.com",
        existing_case_number: "",
      },
    });
    // And the case comes BACK to the incident as the chip.
    expect(await screen.findByTestId("tac-case-line")).toHaveTextContent("689123456 · Open");
  });
});

// ── the proposal's states ────────────────────────────────────────────────────

describe("a proposal that is not ready refuses BY NAME", () => {
  const blocked = proposal({
    ready: false,
    blocker_note: "this case still needs your CCO-ID; a serial number, or a contract id and a PID",
    blockers: [
      {
        key: "account_id", label: "your CCO-ID",
        why: "Cisco opens a case against the account that owns the contract.",
        settings_hint: "Administration → Ticket delivery → Vendor contracts",
      },
      {
        key: "serial_number", label: "a serial number",
        why: "Cisco checks entitlement on the chassis serial.",
        settings_hint: "Inventory → the device record", any_of: "entitlement", alt: "serial",
      },
    ],
  });

  it("disables the button and names every blocker with its reason and its destination", async () => {
    mocks.tacEscalatePrepare.mockResolvedValue({ proposal: blocked, state: state() });
    await escalate();
    const btn = await screen.findByTestId("tac-confirm-btn");
    expect(btn).toBeDisabled();
    const list = screen.getByTestId("tac-blockers");
    expect(list).toHaveTextContent("your CCO-ID — Cisco opens a case against the account that owns the contract.");
    expect(list).toHaveTextContent("a serial number — Cisco checks entitlement on the chassis serial.");
    // The destination is a LINK where Correlix knows the route, and plain text
    // where it does not — never a guessed one.
    expect(screen.getByTestId("tac-blocker-account_id").querySelector("a"))
      .toHaveAttribute("href", "#/admin/ticket-delivery");
    expect(screen.getByTestId("tac-blocker-serial_number").querySelector("a"))
      .toHaveAttribute("href", "#/inventory/devices");
    expect(screen.getByTestId("tac-confirm-blocked")).toHaveTextContent(blocked.blocker_note!);
  });

  it("never sends when the button is disabled", async () => {
    mocks.tacEscalatePrepare.mockResolvedValue({ proposal: blocked, state: state() });
    await escalate();
    await act(async () => { fireEvent.click(await screen.findByTestId("tac-confirm-btn")); });
    expect(mocks.tacEscalateConfirm).not.toHaveBeenCalled();
  });
});

describe("warnings are shown and do not block", () => {
  it("renders every warning and leaves the button live", async () => {
    mocks.tacEscalatePrepare.mockResolvedValue({
      proposal: proposal({
        warnings: [
          "your support contract for this vendor shows an end date of 2026-01-31. The vendor may refuse the case; Correlix will still send it if you do.",
          "2 of 14 commands did not come back. The bundle carries what was collected and names the rest.",
        ],
      }),
      state: state(),
    });
    await escalate();
    const warnings = await screen.findByTestId("tac-warnings");
    expect(warnings.querySelectorAll("li")).toHaveLength(2);
    expect(warnings).toHaveTextContent("shows an end date of 2026-01-31");
    expect(screen.getByTestId("tac-confirm-btn")).toBeEnabled();
    expect(screen.queryByTestId("tac-blockers")).toBeNull();
  });
});

describe("the portal path is a complete outcome, not a failure", () => {
  it("offers the case text and the vendor's own link, and still opens the case", async () => {
    const portalRoute = {
      ...ROUTE, connector_id: "portal-text", display: "Portal text", portal: true,
      reason: "portal_fallback" as const,
      note: "no support integration is configured for Nokia, so Correlix has prepared the case text, the redacted bundle and the vendor's portal link for you to submit.",
    };
    mocks.tacEscalatePrepare.mockResolvedValue({
      proposal: proposal({
        route: portalRoute,
        form: { ...proposal().form, portal_url: "https://portal.example/cases/new" },
      }),
      state: state(),
    });
    await escalate();
    expect(await screen.findByTestId("tac-confirm-route"))
      .toHaveTextContent("no support integration is configured for Nokia");
    expect(screen.getByTestId("tac-confirm-copy")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /vendor portal/i }))
      .toHaveAttribute("href", "https://portal.example/cases/new");
    expect(screen.getByTestId("tac-confirm-btn")).toBeEnabled();
  });
});

// ── the MANUAL route says what pressing the button does (owner, 2026-09-08) ──
//
// "it still shows copy paste options". The vendors in this state publish no case
// API, so "Open case" was a button that could not do what it said. It now says
// what actually happens, and the line beside it says what the next few seconds
// look like.

describe("a portal route asks to PREPARE, not to open", () => {
  const NOKIA_PORTAL: TacConnectorInfo = {
    id: "portal-nokia", display: "Nokia portal", vendor: "nokia", vendor_display: "Nokia",
    portal_only: true, config_section: "portal", capabilities: [],
    max_attachment_bytes: 0, profile: "link_only", configured: true,
    portal_url: "https://customer.nokia.example/support/s/",
    case_number_pattern: "TSR\\d{6}",
  };
  const nokiaRoute = {
    ...ROUTE, connector_id: "portal-nokia", display: "Nokia portal", vendor: "nokia",
    portal: true, reason: "portal_fallback" as const,
    note: "Nokia publishes no case API, so Correlix has prepared the case text and the bundle.",
  };

  const showNokia = async () => {
    const res = stateResponse({ connectors: [NOKIA_PORTAL] });
    mocks.tacEscalate.mockResolvedValue({
      incident_id: INC, route: nokiaRoute, state: state(), can_collect: true, collect_note: "",
      capture_note: "", evidence_sources: [], evidence_missing: [], connectors: [NOKIA_PORTAL],
    });
    mocks.tacEscalatePrepare.mockResolvedValue({
      proposal: proposal({
        route: nokiaRoute,
        form: {
          ...proposal().form, connector_id: "portal-nokia",
          portal_url: "https://customer.nokia.example/support/s/",
        },
      }),
      state: state(),
    });
    await escalate(res);
    return await screen.findByTestId("tac-confirm-btn");
  };

  it("labels the one control 'Prepare for the portal' and says what happens next", async () => {
    const btn = await showNokia();
    expect(btn).toHaveTextContent(CONFIRM_PORTAL_ACTION);
    expect(btn).not.toHaveTextContent(CONFIRM_ACTION);
    expect(screen.getByTestId("tac-portal-next")).toHaveTextContent(CONFIRM_PORTAL_NEXT);
    // The configured portal is a link, and it is the tenant's own address.
    expect(screen.getByTestId("tac-confirm-portal-link"))
      .toHaveAttribute("href", "https://customer.nokia.example/support/s/");
  });

  it("checks the case number pasted back before it can be filed", async () => {
    const btn = await showNokia();
    const box = screen.getByTestId("tac-portal-case-number");
    // Empty is fine: the case may not be open yet.
    expect(btn).toBeEnabled();
    expect(screen.queryByTestId("tac-case-number-bad")).toBeNull();

    fireEvent.change(box, { target: { value: "I have not opened it yet" } });
    expect(screen.getByTestId("tac-case-number-bad")).toHaveTextContent(caseNumberRefusal("Nokia"));
    expect(screen.getByTestId("tac-confirm-btn")).toBeDisabled();

    fireEvent.change(box, { target: { value: "TSR900123" } });
    expect(screen.queryByTestId("tac-case-number-bad")).toBeNull();
    expect(screen.getByTestId("tac-confirm-btn")).toBeEnabled();
  });

  // A link on an incident screen can only ever be http(s) — whatever reached the
  // client.
  it("renders no link at all for an address that is not one", async () => {
    const res = stateResponse({ connectors: [NOKIA_PORTAL] });
    mocks.tacEscalate.mockResolvedValue({
      incident_id: INC, route: nokiaRoute, state: state(), can_collect: true, collect_note: "",
      capture_note: "", evidence_sources: [], evidence_missing: [], connectors: [NOKIA_PORTAL],
    });
    mocks.tacEscalatePrepare.mockResolvedValue({
      proposal: proposal({
        route: nokiaRoute,
        form: { ...proposal().form, portal_url: "javascript:alert(1)" },
      }),
      state: state(),
    });
    await escalate(res);
    await screen.findByTestId("tac-confirm-btn");
    expect(screen.queryByTestId("tac-confirm-portal-link")).toBeNull();
    expect(screen.queryByRole("link", { name: /vendor portal/i })).toBeNull();
  });
});

describe("a prepare that fails says so and offers no screen to press", () => {
  it("renders the failure rather than an empty confirmation", async () => {
    mocks.tacEscalatePrepare.mockRejectedValue(new Error("409 Conflict: {}"));
    await escalate();
    expect(await screen.findByTestId("tac-prepare-error")).toHaveTextContent(/./);
    expect(screen.queryByTestId("tac-confirm-btn")).toBeNull();
  });
});

// ── the dry run ──────────────────────────────────────────────────────────────

describe("the dry run proves the setup without creating anything", () => {
  it("is a SECONDARY control beside Open case", async () => {
    await escalate();
    const primary = await screen.findByTestId("tac-confirm-btn");
    const secondary = screen.getByTestId("tac-dry-run-btn");
    expect(primary.className).toContain("accent");
    expect(secondary.className).not.toContain("accent");
    expect(secondary).toHaveTextContent(DRY_RUN_ACTION);
  });

  it("sends the routed connector, and states the server's own 'nothing was created'", async () => {
    mocks.tacEscalateDryRun.mockResolvedValue({ dry_run: dryRun() });
    await escalate();
    await act(async () => { fireEvent.click(await screen.findByTestId("tac-dry-run-btn")); });
    expect(mocks.tacEscalateDryRun).toHaveBeenCalledWith(INC, "cisco-smart-bonding");
    expect(await screen.findByTestId("tac-dry-run-created-nothing"))
      .toHaveTextContent(DRY_RUN_CREATED_NOTHING);
  });

  it("shows the call sequence collapsed, and expands into the field table", async () => {
    mocks.tacEscalateDryRun.mockResolvedValue({ dry_run: dryRun() });
    await escalate();
    await act(async () => { fireEvent.click(await screen.findByTestId("tac-dry-run-btn")); });
    const calls = await screen.findByTestId("tac-dry-run-calls");
    // Nothing expands by default.
    expect(calls.querySelectorAll("details[open]")).toHaveLength(0);
    // The authenticate step says it was MADE; everything else says described.
    expect(calls).toHaveTextContent("authenticate · POST https://id.cisco.com/oauth2/default/v1/token · made");
    expect(calls).toHaveTextContent("create the case · POST https://api.cisco.com/smartbonding/push · described");
    const first = calls.querySelectorAll("details")[1] as HTMLDetailsElement;
    await act(async () => { fireEvent.click(first.querySelector("summary")!); });
    expect(first.textContent).toContain("synopsis");
    expect(first.textContent).toContain("problemSynopsis");
    expect(first.textContent).toContain("FDO123");
  });

  it("marks a secret field and renders the SERVER's redaction rather than re-masking it", async () => {
    mocks.tacEscalateDryRun.mockResolvedValue({ dry_run: dryRun() });
    await escalate();
    await act(async () => { fireEvent.click(await screen.findByTestId("tac-dry-run-btn")); });
    const auth = (await screen.findByTestId("tac-dry-run-calls")).querySelectorAll("details")[0] as HTMLDetailsElement;
    await act(async () => { fireEvent.click(auth.querySelector("summary")!); });
    expect(auth.textContent).toContain("[REDACTED]");
    expect(auth.textContent).toContain("redacted");
  });

  it.each<[TacDryRunOutcome, string]>([
    ["ok", DRY_RUN_SENTENCE.ok],
    ["incomplete", DRY_RUN_SENTENCE.incomplete],
    ["not_configured", DRY_RUN_SENTENCE.not_configured],
    ["refused", DRY_RUN_SENTENCE.refused],
    ["unreachable", DRY_RUN_SENTENCE.unreachable],
    ["unsupported", DRY_RUN_SENTENCE.unsupported],
  ])("renders the %s outcome with its own sentence and the vendor's note", async (outcome, sentence) => {
    mocks.tacEscalateDryRun.mockResolvedValue({
      dry_run: dryRun({ outcome, note: `the vendor said ${outcome}` }),
    });
    await escalate();
    await act(async () => { fireEvent.click(await screen.findByTestId("tac-dry-run-btn")); });
    expect(await screen.findByTestId("tac-dry-run-outcome")).toHaveTextContent(outcome);
    expect(screen.getByTestId("tac-dry-run")).toHaveTextContent(sentence);
    expect(screen.getByTestId("tac-dry-run")).toHaveTextContent(`the vendor said ${outcome}`);
  });

  it("an incomplete dry run names what is missing, exactly as the proposal does", async () => {
    mocks.tacEscalateDryRun.mockResolvedValue({
      dry_run: dryRun({
        outcome: "incomplete", note: "the payload is missing an entitlement identifier",
        blockers: [{
          key: "account_id", label: "your CCO-ID",
          why: "Cisco opens a case against the account that owns the contract.",
          settings_hint: "Administration → Ticket delivery → Vendor contracts",
        }],
      }),
    });
    await escalate();
    await act(async () => { fireEvent.click(await screen.findByTestId("tac-dry-run-btn")); });
    const blockers = await screen.findByTestId("tac-dry-run-blockers");
    expect(blockers).toHaveTextContent("your CCO-ID — Cisco opens a case against the account that owns the contract.");
    expect(blockers.querySelector("a")).toHaveAttribute("href", "#/admin/ticket-delivery");
  });

  it("says what did not happen when the dry run itself could not be made", async () => {
    mocks.tacEscalateDryRun.mockRejectedValue(new Error("409 Conflict: {}"));
    await escalate();
    await act(async () => { fireEvent.click(await screen.findByTestId("tac-dry-run-btn")); });
    expect(await screen.findByTestId("tac-dry-run-error")).toHaveTextContent(/./);
    expect(screen.queryByTestId("tac-dry-run")).toBeNull();
  });
});

// ── the answer card's own press ──────────────────────────────────────────────

describe("autoStart", () => {
  it("runs the ONE ACTION on mount, so the answer card's press is the only one", async () => {
    render(<TacEscalationPanel incidentId={INC} autoStart />);
    await waitFor(() => expect(mocks.tacClassify).toHaveBeenCalledWith(INC));
    await waitFor(() => expect(mocks.tacEscalate).toHaveBeenCalled());
    // And it fires ONCE — a re-render must not restart an escalation.
    await act(async () => { await Promise.resolve(); });
    expect(mocks.tacEscalate).toHaveBeenCalledTimes(1);
  });

  it("does nothing on its own without the prop", async () => {
    render(<TacEscalationPanel incidentId={INC} />);
    await act(async () => { await Promise.resolve(); });
    await act(async () => { await Promise.resolve(); });
    expect(mocks.tacEscalate).not.toHaveBeenCalled();
  });

  it("reports the opened case to its host", async () => {
    const link = {
      connector: "cisco-smart-bonding", case_id: "689123456", opened_at: "2026-09-07T09:05:00Z",
      tier: "high" as const, attached: true, pollable: true, closed: false, status: "Open",
    };
    mocks.tacEscalateConfirm.mockResolvedValue({
      result: { connector_id: "cisco-smart-bonding", case_id: "689123456", attached: true, submitted_at: "" },
      case: link,
    });
    const onCaseOpened = vi.fn();
    mocks.tacState.mockResolvedValue({ ...stateResponse(), state: state() });
    render(<TacEscalationPanel incidentId={INC} autoStart onCaseOpened={onCaseOpened} />);
    for (let i = 0; i < 6; i += 1) {
      // eslint-disable-next-line no-await-in-loop
      await act(async () => { await Promise.resolve(); });
    }
    const btn = await screen.findByTestId("tac-confirm-btn");
    await act(async () => { fireEvent.click(btn); });
    await waitFor(() => expect(onCaseOpened).toHaveBeenCalledWith(link));
  });
});

describe("the case comes back to the incident", () => {
  it("shows the case the STATE READ carries, so a reload still shows it", async () => {
    mocks.tacState.mockResolvedValue(stateResponse({
      state: state(),
      case: {
        connector: "cisco-smart-bonding", case_id: "689123456", opened_at: "2026-09-07T09:05:00Z",
        tier: "high", attached: true, pollable: true, closed: false, status: "Open", auth_mode: "oauth",
      },
      case_status_line: "689123456 · Awaiting customer",
      case_tooltip: "via cisco-smart-bonding · authenticated with oauth",
    }));
    render(<TacEscalationPanel incidentId={INC} autoStart />);
    // The SERVER's sentence, not a second one computed here.
    expect(await screen.findByTestId("tac-case-line"))
      .toHaveTextContent("689123456 · Awaiting customer");
    expect(screen.getByTestId("tac-case-line").getAttribute("title"))
      .toBe("via cisco-smart-bonding · authenticated with oauth");
  });

  it("takes the confirm reply's own rendering of the chip", async () => {
    mocks.tacEscalateConfirm.mockResolvedValue({
      result: { connector_id: "cisco-smart-bonding", case_id: "689123456", attached: true, submitted_at: "" },
      case: {
        connector: "cisco-smart-bonding", case_id: "689123456", opened_at: "2026-09-07T09:05:00Z",
        tier: "high", attached: true, pollable: true, closed: false, status: "Open",
      },
      status_line: "689123456 · Open",
      tooltip: "via cisco-smart-bonding · refreshing every 5 min",
    });
    await escalate();
    await act(async () => { fireEvent.click(await screen.findByTestId("tac-confirm-btn")); });
    expect(await screen.findByTestId("tac-case-line")).toHaveTextContent("689123456 · Open");
    expect(screen.getByTestId("tac-case-line").getAttribute("title"))
      .toBe("via cisco-smart-bonding · refreshing every 5 min");
  });
});

describe("the escalation refuses to invent anything", () => {
  it("never renders a route the server did not choose", async () => {
    mocks.tacEscalate.mockRejectedValue(new Error(`503 Service Unavailable: {"error":"${ESCALATE_FAILED}"}`));
    await escalate();
    await screen.findByTestId("tac-escalate-error");
    expect(screen.queryByTestId("tac-route")).toBeNull();
    expect(screen.queryByTestId("tac-confirm")).toBeNull();
  });

  it("renders a hostile problem statement as TEXT (§15 LLM02)", async () => {
    mocks.tacEscalatePrepare.mockResolvedValue({
      proposal: proposal({
        form: { ...proposal().form, description: "<script>alert(1)</script>" },
      }),
      state: state(),
    });
    await escalate();
    const box = await screen.findByTestId("tac-confirm-statement");
    expect((box as HTMLTextAreaElement).value).toBe("<script>alert(1)</script>");
    expect(box.querySelector("script")).toBeNull();
  });
});

// ── the per-case upload credential ───────────────────────────────────────────
//
// 3.1-11. The attach-to-existing Cisco route needs two things a create route
// does not: the case it attaches to, and the per-case upload token the vendor's
// portal mints. The token was declared, cleared and sent, but no control on the
// screen ever set it, so the server blocked the route for a field the operator
// had no way to fill and the blocker's own hint ("the case form") named a box
// that did not exist.
//
// The token is a credential, not a case field: masked, never pre-filled, sent
// once and cleared the moment the case is filed.
//
// ASSUMED OF THE SERVER: the proposal names the field as a blocker with the key
// `upload_token` whenever the route needs it, and the confirm body carries it
// as top-level `upload_token` beside `form`. Both are the contract at
// internal/tac/escalatehttp.go today. The screen reads the blocker list rather
// than deciding for itself which vendors need a token, so a server that stops
// demanding it (for the email-cisco route, say) simply stops rendering the box.

const cxdRoute = { ...ROUTE, connector_id: "cisco-cxd", display: "Cisco CXD" };

const UPLOAD_BLOCKER = {
  key: "upload_token",
  label: "the per-case CXD upload token",
  why: "the token from Support Case Manager is the Basic-auth password; it is valid 72 days, is supplied per attach and is never stored by Correlix",
  settings_hint: "the case form (copy it from Cisco Support Case Manager)",
};

/** A CXD proposal blocked exactly the way the server blocks one: the case
 *  reference and the upload token, both of which are typed on this screen. */
const cxdBlocked = (): TacProposal => proposal({
  route: cxdRoute,
  ready: false,
  form: { ...proposal().form, connector_id: "cisco-cxd", existing_case_number: "" },
  blocker_note: "this case still needs the SR it attaches to and the per-case upload token",
  blockers: [
    {
      key: "existing_case_number", label: "the Cisco SR number",
      why: "CXD authenticates the upload with the SR number as the Basic-auth user.",
      settings_hint: "the case form (copy it from Cisco Support Case Manager)",
    },
    UPLOAD_BLOCKER,
  ],
});

async function escalateCXD(p: TacProposal) {
  mocks.tacEscalate.mockResolvedValue({
    incident_id: INC, route: cxdRoute, state: state(), can_collect: true, collect_note: "",
    capture_note: "", evidence_sources: [], evidence_missing: [], connectors: [CXD, PORTAL],
  });
  mocks.tacEscalatePrepare.mockResolvedValue({ proposal: p, state: state() });
  await escalate(stateResponse({ connectors: [CXD, PORTAL] }));
  await screen.findByTestId("tac-confirm");
}

describe("the per-case upload credential has a box on the screen that asks for it", () => {
  it("renders the box the blocker names, masked and empty", async () => {
    await escalateCXD(cxdBlocked());
    const box = await screen.findByTestId("tac-confirm-upload-token") as HTMLInputElement;
    expect(box).toBeInTheDocument();
    expect(box.type).toBe("password");
    expect(box.value).toBe("");
    // The label the blocker's hint sends the operator to is on this screen.
    expect(screen.getByText(UPLOAD_TOKEN_LABEL)).toBeInTheDocument();
  });

  it("does not ask for one on a route the server did not block on it", async () => {
    await escalateCXD(proposal({ route: cxdRoute }));
    expect(screen.queryByTestId("tac-confirm-upload-token")).toBeNull();
  });

  it("the button stays shut until both boxes are filled, then opens", async () => {
    await escalateCXD(cxdBlocked());
    const btn = await screen.findByTestId("tac-confirm-btn");
    expect(btn).toBeDisabled();
    fireEvent.change(screen.getByTestId("tac-confirm-existing-case"), { target: { value: "695123456" } });
    expect(btn).toBeDisabled();
    fireEvent.change(screen.getByTestId("tac-confirm-upload-token"), { target: { value: "cxd-secret" } });
    expect(btn).toBeEnabled();
    // And the refusal stops naming boxes the operator has now filled in.
    expect(screen.queryByTestId("tac-blockers")).toBeNull();
  });

  it("a blocker set somewhere else still holds the button shut", async () => {
    await escalateCXD(proposal({
      route: cxdRoute, ready: false,
      blockers: [
        UPLOAD_BLOCKER,
        {
          key: "account_id", label: "your CCO-ID",
          why: "Cisco opens a case against the account that owns the contract.",
          settings_hint: "Administration → Ticket delivery → Vendor contracts",
        },
      ],
    }));
    const btn = await screen.findByTestId("tac-confirm-btn");
    fireEvent.change(screen.getByTestId("tac-confirm-upload-token"), { target: { value: "cxd-secret" } });
    expect(btn).toBeDisabled();
    expect(screen.getByTestId("tac-blocker-account_id")).toBeInTheDocument();
  });

  it("sends the token once, beside the form and never inside it, then clears it", async () => {
    mocks.tacEscalateConfirm.mockResolvedValue({
      result: { connector_id: "cisco-cxd", case_id: "695123456", attached: true, submitted_at: "" },
      case: {
        connector: "cisco-cxd", case_id: "695123456", opened_at: "2026-09-07T09:05:00Z",
        tier: "high", attached: true, pollable: false, closed: false, status: "existing", auth_mode: "basic",
      },
    });
    await escalateCXD(cxdBlocked());
    await screen.findByTestId("tac-confirm-btn");
    fireEvent.change(screen.getByTestId("tac-confirm-existing-case"), { target: { value: "695123456" } });
    fireEvent.change(screen.getByTestId("tac-confirm-upload-token"), { target: { value: "cxd-secret" } });
    await act(async () => { fireEvent.click(screen.getByTestId("tac-confirm-btn")); });

    expect(mocks.tacEscalateConfirm).toHaveBeenCalledTimes(1);
    const [, body] = mocks.tacEscalateConfirm.mock.calls[0];
    expect(body.upload_token).toBe("cxd-secret");
    expect(body.form.existing_case_number).toBe("695123456");
    // A credential never travels in a field meant for something else.
    expect(JSON.stringify(body.form)).not.toContain("cxd-secret");
    // No upload host is invented: the client pins the vendor's published one.
    expect(body.upload_host).toBeUndefined();
  });
});
