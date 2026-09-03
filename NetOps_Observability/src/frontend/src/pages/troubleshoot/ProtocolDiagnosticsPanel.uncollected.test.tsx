// ProtocolDiagnosticsPanel.uncollected.test.tsx — D-4 in the UI (QA 2026-09-03).
//
// The live run collected from an SR Linux spine, every one of the read-only
// commands was rejected by the device, zero bytes came back — and the panel
// said "Captured N command(s)…" in the success tone, then "No signature
// matched". This pins the two states apart on screen:
//
//   nothing captured  → the notice says nothing was captured and the state is
//                       unknown; the analysis block says "Nothing was analyzed"
//                       and lists each command's own rejection reason.
//   captured, unmatched → the original "No signature matched" copy, unchanged.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";
import type {
  Device,
  ProtocolDiagAnalysis,
  ProtocolDiagCatalog,
  ProtocolDiagCollection,
} from "../../services/api";

const devices = vi.fn();
const permissions = vi.fn();
const protocolDiagCatalog = vi.fn();
const protocolDiagCollect = vi.fn();
const protocolDiagAnalyze = vi.fn();

vi.mock("../../services/api", () => ({
  api: {
    devices: (...a: unknown[]) => devices(...a),
    permissions: (...a: unknown[]) => permissions(...a),
    protocolDiagCatalog: (...a: unknown[]) => protocolDiagCatalog(...a),
    protocolDiagCollect: (...a: unknown[]) => protocolDiagCollect(...a),
    protocolDiagAnalyze: (...a: unknown[]) => protocolDiagAnalyze(...a),
  },
}));

import ProtocolDiagnosticsPanel from "./ProtocolDiagnosticsPanel";
import { NOTHING_ANALYZED_HEADING } from "./protocolDiagModel";

const DEVICE = {
  id: "spine1", name: "spine1", address: "172.40.40.11", vendor: "nokia", os: "SR Linux", model: "7220 IXR-D3L",
  source: "snmp", last_seen: "2026-09-03T04:00:00Z",
} as Device;

const CATALOG: ProtocolDiagCatalog = {
  ruleset_version: "correlix-protocoldiag-2026-08-27",
  vendor: "nokia",
  vendor_display: "Nokia SR OS",
  protocols: ["bgp", "ospf", "isis"],
  issues: {
    bgp: [],
    ospf: [],
    isis: [
      {
        id: "isis-adjacency-down", protocol: "isis",
        title: "IS-IS adjacency down",
        description: "The adjacency never comes up.",
        commands: [
          { spec_id: "isis-neighbors", purpose: "adjacency", command: "show router isis adjacency" },
          { spec_id: "isis-interface", purpose: "circuit", command: "show router isis interface detail" },
        ],
      },
    ],
  },
};

const REJECTED = 'command "show router isis adjacency" failed: Process exited with status 1';

/** The lab's real outcome: every command errored, zero bytes captured. */
const NOTHING_CAPTURED: ProtocolDiagCollection = {
  device_id: "spine1", hostname: "spine1", platform: "nokia SR Linux",
  vendor: "nokia", rendered_vendor: "nokia",
  protocol: "isis", issue_id: "isis-adjacency-down", issue_title: "IS-IS adjacency down",
  ruleset_version: "correlix-protocoldiag-2026-08-27",
  collected_at: "2026-09-03T04:14:39Z",
  commands: [
    { spec_id: "isis-neighbors", command: "show router isis adjacency", purpose: "adjacency", output: "", timestamp: "2026-09-03T04:14:39Z", error: REJECTED },
    { spec_id: "isis-interface", command: "show router isis interface detail", purpose: "circuit", output: "", timestamp: "2026-09-03T04:14:41Z", error: 'command "show router isis interface detail" failed: Process exited with status 1' },
  ],
};

const NOT_ANALYZED: ProtocolDiagAnalysis = {
  protocol: "isis", issue_id: "isis-adjacency-down", issue_title: "IS-IS adjacency down",
  ruleset_version: "correlix-protocoldiag-2026-08-27",
  analyzed: false,
  outputs_received: 0,
  outputs_supplied: 0,
  matched: false,
  findings: [],
  unmatched: "",
  not_analyzed: "no command output was supplied, so nothing was analysed — this is NOT “no signature matched”",
  tac_export: "CORRELIX PROTOCOL DIAGNOSTICS — TAC EXPORT (redacted)\n",
};

const SCORED_UNMATCHED: ProtocolDiagAnalysis = {
  ...NOT_ANALYZED,
  analyzed: true,
  outputs_received: 1,
  outputs_supplied: 1,
  not_analyzed: "",
  unmatched: "no known signature matched — the raw captured output is attached for TAC",
};

function ok() {
  devices.mockResolvedValue([DEVICE]);
  permissions.mockResolvedValue({ role: "operator", permissions: { infrastructure: 2 } });
  protocolDiagCatalog.mockResolvedValue(CATALOG);
}

async function openIsis() {
  render(<ProtocolDiagnosticsPanel />);
  fireEvent.click(await screen.findByRole("button", { name: "IS-IS" }));
  await screen.findByText("IS-IS adjacency down");
  fireEvent.change(screen.getByLabelText(/^Device/), { target: { value: "spine1" } });
  await waitFor(() => expect(protocolDiagCatalog).toHaveBeenCalledWith("nokia SR Linux 7220 IXR-D3L"));
  fireEvent.click(await screen.findByRole("radio", { name: /IS-IS adjacency down/ }));
}

const collectBtn = () => screen.getByRole("button", { name: /Collect the read-only command bundle/i });
const analyzeBtn = () => screen.getByRole("button", { name: /Analyze the collected or pasted output/i });

beforeEach(() => {
  for (const m of [devices, permissions, protocolDiagCatalog, protocolDiagCollect, protocolDiagAnalyze]) m.mockReset();
});
afterEach(() => cleanup());

describe("a collection in which the device rejected everything", () => {
  it("is never announced as a capture", async () => {
    ok();
    protocolDiagCollect.mockResolvedValue(NOTHING_CAPTURED);
    await openIsis();
    fireEvent.click(collectBtn());

    const notice = await screen.findByText(/rejected all 2 read-only commands/);
    expect(notice).toBeInTheDocument();
    expect(notice.textContent).toContain("nothing was captured");
    expect(notice.textContent).toContain("unknown, not healthy");
    // the exact defect
    expect(screen.queryByText(/^Captured 2 commands/)).toBeNull();
    // and it is rendered in the failure tone, not the success one
    expect(notice.className).toContain("cfg-bad");
  });

  it("shows every command's own rejection reason", async () => {
    ok();
    protocolDiagCollect.mockResolvedValue(NOTHING_CAPTURED);
    await openIsis();
    fireEvent.click(collectBtn());
    expect(await screen.findByText(new RegExp(`Command error: ${REJECTED.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`))).toBeInTheDocument();
    // the paste fallback is still offered — the operator can bring their own output
    expect(screen.getByLabelText("Paste output for show router isis adjacency")).toBeInTheDocument();
  });

  it("says 'Nothing was analyzed', not 'No signature matched'", async () => {
    ok();
    protocolDiagCollect.mockResolvedValue(NOTHING_CAPTURED);
    protocolDiagAnalyze.mockResolvedValue(NOT_ANALYZED);
    await openIsis();
    fireEvent.click(collectBtn());
    await screen.findByText(/rejected all 2 read-only commands/);
    // Paste something so the client-side guard lets the request through; the
    // SERVER is the one saying nothing was analysable here.
    fireEvent.change(screen.getByLabelText("Paste output for show router isis adjacency"), {
      target: { value: "x" },
    });
    fireEvent.click(analyzeBtn());

    expect(await screen.findByText(NOTHING_ANALYZED_HEADING)).toBeInTheDocument();
    expect(screen.getByText(NOT_ANALYZED.not_analyzed as string)).toBeInTheDocument();
    expect(screen.queryByText("No signature matched")).toBeNull();
    const live = screen.getByLabelText("Analysis result");
    expect(live.textContent).not.toContain("no known signature matched");
    // the per-command reasons are repeated where the verdict would have been
    expect(live.textContent).toContain("Why each command produced nothing");
    expect(live.textContent).toContain("Process exited with status 1");
  });
});

describe("a capture that WAS scored", () => {
  it("keeps the original honest no-match copy", async () => {
    ok();
    protocolDiagAnalyze.mockResolvedValue(SCORED_UNMATCHED);
    await openIsis();
    fireEvent.change(screen.getByLabelText("Paste output for show router isis adjacency"), {
      target: { value: "| ethernet-1/1.0 | 0100.0000.0011 | L2 | up |" },
    });
    fireEvent.click(analyzeBtn());
    expect(await screen.findByText("No signature matched")).toBeInTheDocument();
    expect(screen.getByText(SCORED_UNMATCHED.unmatched)).toBeInTheDocument();
    expect(screen.queryByText(NOTHING_ANALYZED_HEADING)).toBeNull();
  });
});
