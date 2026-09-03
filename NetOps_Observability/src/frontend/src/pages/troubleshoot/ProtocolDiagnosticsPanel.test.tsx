// ProtocolDiagnosticsPanel.test.tsx — the Troubleshooting → Protocol diagnostics panel.
//
// What is pinned here:
//  · the 15-issue matrix renders per protocol tab (BGP / OSPF / IS-IS), each
//    issue showing its symptoms and the commands the bundle collects
//  · collect: 200 sends the exact body and shows the capture; 503 is the honest
//    "not wired — paste it instead"; 404 is "not visible"; 403 is inline
//  · the paste fallback feeds analyze with the exact payload shape
//  · matched findings vs the honest "no signature matched" state
//  · device output is ESCAPED — a <script> in a capture renders as TEXT
//  · Send to TAC downloads the SERVER's redacted export, named safely
//  · the analysis area is a live region

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
import { COLLECTOR_UNWIRED_MESSAGE, DEVICE_NOT_VISIBLE_MESSAGE, NO_PERMISSION_MESSAGE } from "./protocolDiagModel";

const DEVICE = {
  id: "leaf1", name: "leaf1", address: "10.0.0.1", vendor: "Cisco", os: "IOS-XE", model: "C9300",
  source: "snmp", last_seen: "2026-09-01T10:00:00Z",
} as Device;

const CATALOG: ProtocolDiagCatalog = {
  ruleset_version: "correlix-protocoldiag-2026-08-27",
  vendor: "cisco-iosxe",
  vendor_display: "Cisco IOS-XE",
  protocols: ["bgp", "ospf", "isis"],
  issues: {
    bgp: [
      {
        id: "bgp-session-down", protocol: "bgp",
        title: "BGP session down (Idle/Active/Connect)",
        description: "The peering never reaches Established.",
        commands: [
          { spec_id: "bgp-summary", purpose: "peer state", command: "show ip bgp summary" },
          { spec_id: "bgp-neighbor", purpose: "peer detail", command: "show ip bgp neighbors" },
        ],
      },
      {
        id: "bgp-routes-missing", protocol: "bgp",
        title: "BGP routes missing",
        description: "The peer is up but the prefixes never install.",
        commands: [{ spec_id: "bgp-table", purpose: "table", command: "show ip bgp" }],
      },
    ],
    ospf: [
      {
        id: "ospf-neighbor-stuck", protocol: "ospf",
        title: "OSPF neighbor stuck in ExStart",
        description: "The adjacency never reaches Full.",
        commands: [{ spec_id: "ospf-neighbor", purpose: "adjacency", command: "show ip ospf neighbor" }],
      },
    ],
    isis: [
      {
        id: "isis-adjacency-down", protocol: "isis",
        title: "IS-IS adjacency down",
        description: "The adjacency never comes up.",
        commands: [{ spec_id: "isis-neighbors", purpose: "adjacency", command: "show isis neighbors" }],
      },
    ],
  },
};

const COLLECTION: ProtocolDiagCollection = {
  device_id: "leaf1", hostname: "leaf1", platform: "Cisco IOS-XE C9300",
  vendor: "cisco-iosxe", rendered_vendor: "cisco-iosxe",
  protocol: "bgp", issue_id: "bgp-session-down", issue_title: "BGP session down (Idle/Active/Connect)",
  ruleset_version: "correlix-protocoldiag-2026-08-27",
  collected_at: "2026-09-02T09:00:00Z",
  commands: [
    {
      spec_id: "bgp-summary", command: "show ip bgp summary", purpose: "peer state",
      output: "Neighbor 10.0.0.2 State Idle <script>alert(1)</script>",
      timestamp: "2026-09-02T09:00:00Z", error: "",
    },
    {
      spec_id: "bgp-neighbor", command: "show ip bgp neighbors", purpose: "peer detail",
      output: "", timestamp: "2026-09-02T09:00:01Z", error: "transport timeout",
    },
  ],
};

const MATCHED: ProtocolDiagAnalysis = {
  protocol: "bgp", issue_id: "bgp-session-down", issue_title: "BGP session down (Idle/Active/Connect)",
  ruleset_version: "correlix-protocoldiag-2026-08-27",
  matched: true,
  findings: [{
    signature_id: "bgp-idle-no-route",
    verdict: "The peer is Idle because there is no route to it",
    cause: "The peer address is not in the routing table",
    remediation: "Restore reachability to the peer address, then clear the session",
    confidence: "high",
    evidence: { command: "show ip bgp summary", spec_id: "bgp-summary", line: "10.0.0.2 4 65001 Idle" },
  }],
  unmatched: "",
  tac_export: "CORRELIX PROTOCOL DIAGNOSTICS — TAC EXPORT (redacted)\npassword <redacted>\n",
};

const UNMATCHED: ProtocolDiagAnalysis = {
  ...MATCHED,
  matched: false,
  findings: [],
  unmatched: "no known signature matched — the raw captured output is attached for TAC",
};

function ok(infra = 2) {
  devices.mockResolvedValue([DEVICE]);
  permissions.mockResolvedValue({ role: "operator", permissions: { infrastructure: infra } });
  protocolDiagCatalog.mockResolvedValue(CATALOG);
}

/** Render, wait for the catalog, and (optionally) pick the device + issue. */
async function open(opts: { device?: boolean; issue?: RegExp } = {}) {
  render(<ProtocolDiagnosticsPanel />);
  await screen.findByText("BGP session down (Idle/Active/Connect)");
  if (opts.device) {
    fireEvent.change(screen.getByLabelText(/^Device/), { target: { value: "leaf1" } });
    await waitFor(() => expect(protocolDiagCatalog).toHaveBeenCalledWith("Cisco IOS-XE C9300"));
  }
  if (opts.issue) fireEvent.click(await screen.findByRole("radio", { name: opts.issue }));
}

const collectBtn = () => screen.getByRole("button", { name: /Collect the read-only command bundle/i });
const analyzeBtn = () => screen.getByRole("button", { name: /Analyze the collected or pasted output/i });
const tacBtn = () => screen.getByRole("button", { name: /Download the redacted TAC bundle/i });

beforeEach(() => {
  for (const m of [devices, permissions, protocolDiagCatalog, protocolDiagCollect, protocolDiagAnalyze]) m.mockReset();
});
afterEach(() => cleanup());

describe("the issue matrix renders per protocol", () => {
  it("shows the BGP issues, their symptoms and the commands collected", async () => {
    ok();
    await open();
    expect(screen.getByText("BGP session down (Idle/Active/Connect)")).toBeInTheDocument();
    expect(screen.getByText("The peering never reaches Established.")).toBeInTheDocument();
    expect(screen.getByText("show ip bgp summary")).toBeInTheDocument();
    expect(screen.getByText("BGP routes missing")).toBeInTheDocument();
    // the covered vendors are stated, not implied
    expect(screen.getByText(/Cisco IOS-XE · Juniper Junos · Nokia SR OS/)).toBeInTheDocument();
  });

  it("switches to OSPF and to IS-IS from the tab group", async () => {
    ok();
    await open();
    const tabs = screen.getByRole("group", { name: "Protocol" });
    fireEvent.click(screen.getByRole("button", { name: "OSPF" }));
    expect(await screen.findByText("OSPF neighbor stuck in ExStart")).toBeInTheDocument();
    expect(screen.queryByText("BGP routes missing")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "IS-IS" }));
    expect(await screen.findByText("IS-IS adjacency down")).toBeInTheDocument();
    expect(tabs.querySelector('button[aria-pressed="true"]')?.textContent).toBe("IS-IS");
  });
});

describe("collect", () => {
  it("sends the exact body and renders the capture (200)", async () => {
    ok();
    protocolDiagCollect.mockResolvedValue(COLLECTION);
    await open({ device: true, issue: /BGP session down/ });
    fireEvent.change(screen.getByLabelText(/^Peer/), { target: { value: "10.0.0.2" } });
    fireEvent.click(collectBtn());
    await waitFor(() => expect(protocolDiagCollect).toHaveBeenCalledTimes(1));
    expect(protocolDiagCollect.mock.calls[0][0]).toEqual({
      device_id: "leaf1",
      issue_id: "bgp-session-down",
      target: { interface: "", peer: "10.0.0.2", prefix: "", vrf: "" },
    });
    // D-4: this fixture is a PARTIAL capture (1 of 2 commands answered), and the
    // notice says so rather than claiming both were captured.
    expect(await screen.findByText(/Captured 1 of 2 commands from leaf1/)).toBeInTheDocument();
    expect(screen.getByText(/1 was rejected/)).toBeInTheDocument();
    // a per-command transport failure is reported, not hidden
    expect(screen.getByText(/Command error: transport timeout/)).toBeInTheDocument();
  });

  it("renders device output as escaped TEXT, never markup", async () => {
    ok();
    protocolDiagCollect.mockResolvedValue(COLLECTION);
    await open({ device: true, issue: /BGP session down/ });
    fireEvent.click(collectBtn());
    const pre = await screen.findByText(/Neighbor 10\.0\.0\.2 State Idle/);
    expect(pre.tagName).toBe("PRE");
    expect(pre.textContent).toContain("<script>alert(1)</script>");
    expect(pre.querySelector("script")).toBeNull();
    expect(document.querySelector("script")).toBeNull();
  });

  it("turns a 503 into the honest 'not wired — paste it instead' state", async () => {
    ok();
    protocolDiagCollect.mockRejectedValue(new Error("503 Service Unavailable: {}"));
    await open({ device: true, issue: /BGP session down/ });
    fireEvent.click(collectBtn());
    expect(await screen.findByText(COLLECTOR_UNWIRED_MESSAGE)).toBeInTheDocument();
    // the paste fallback is right there
    expect(screen.getByLabelText("Paste output for show ip bgp summary")).toBeInTheDocument();
  });

  it("says only 'not visible' on a 404", async () => {
    ok();
    protocolDiagCollect.mockRejectedValue(new Error("404 Not Found: 404 page not found"));
    await open({ device: true, issue: /BGP session down/ });
    fireEvent.click(collectBtn());
    expect(await screen.findByText(DEVICE_NOT_VISIBLE_MESSAGE)).toBeInTheDocument();
  });

  it("shows a server 403 inline", async () => {
    ok();
    protocolDiagCollect.mockRejectedValue(new Error("403 Forbidden: {}"));
    await open({ device: true, issue: /BGP session down/ });
    fireEvent.click(collectBtn());
    expect(await screen.findByText(NO_PERMISSION_MESSAGE)).toBeInTheDocument();
  });

  it("disables Collect without infrastructure write but still allows analyze", async () => {
    ok(1);
    await open({ device: true, issue: /BGP session down/ });
    await waitFor(() => expect(collectBtn()).toBeDisabled());
    expect(screen.getByText(/needs infrastructure write access/)).toBeInTheDocument();
    expect(analyzeBtn()).not.toBeDisabled();
  });
});

describe("analyze", () => {
  it("feeds the pasted output into the exact analyze payload", async () => {
    ok();
    protocolDiagAnalyze.mockResolvedValue(UNMATCHED);
    await open({ device: true, issue: /BGP session down/ });
    fireEvent.change(screen.getByLabelText("Paste output for show ip bgp summary"), {
      target: { value: "Neighbor 10.0.0.2 State Idle" },
    });
    fireEvent.click(analyzeBtn());
    await waitFor(() => expect(protocolDiagAnalyze).toHaveBeenCalledTimes(1));
    expect(protocolDiagAnalyze.mock.calls[0][0]).toEqual({
      protocol: "bgp",
      issue_id: "bgp-session-down",
      device: { hostname: "leaf1", platform: "Cisco IOS-XE C9300" },
      outputs: [{ spec_id: "bgp-summary", output: "Neighbor 10.0.0.2 State Idle" }],
    });
  });

  it("renders a matched signature with its confidence, cause, remediation and evidence", async () => {
    ok();
    protocolDiagAnalyze.mockResolvedValue(MATCHED);
    await open({ device: true, issue: /BGP session down/ });
    fireEvent.change(screen.getByLabelText("Paste output for show ip bgp summary"), { target: { value: "Idle" } });
    fireEvent.click(analyzeBtn());
    expect(await screen.findByText("The peer is Idle because there is no route to it")).toBeInTheDocument();
    expect(screen.getByText("high confidence")).toBeInTheDocument();
    expect(screen.getByText(/The peer address is not in the routing table/)).toBeInTheDocument();
    expect(screen.getByText(/Restore reachability to the peer address/)).toBeInTheDocument();
    expect(screen.getByText("10.0.0.2 4 65001 Idle")).toBeInTheDocument();
  });

  it("states the honest no-match verdict in the server's own words", async () => {
    ok();
    protocolDiagAnalyze.mockResolvedValue(UNMATCHED);
    await open({ device: true, issue: /BGP session down/ });
    fireEvent.change(screen.getByLabelText("Paste output for show ip bgp summary"), { target: { value: "Established" } });
    fireEvent.click(analyzeBtn());
    expect(await screen.findByText("No signature matched")).toBeInTheDocument();
    expect(screen.getByText(UNMATCHED.unmatched)).toBeInTheDocument();
    expect(screen.queryByText(/confidence/)).toBeNull();
  });

  it("refuses to analyze nothing", async () => {
    ok();
    await open({ device: true, issue: /BGP session down/ });
    fireEvent.click(analyzeBtn());
    expect(await screen.findByText(/no output to analyze yet/i)).toBeInTheDocument();
    expect(protocolDiagAnalyze).not.toHaveBeenCalled();
  });

  it("publishes the result in a live region", async () => {
    ok();
    await open();
    const live = screen.getByLabelText("Analysis result");
    expect(live.getAttribute("role")).toBe("status");
    expect(live.getAttribute("aria-live")).toBe("polite");
  });
});

describe("Send to TAC", () => {
  it("downloads the server's redacted export under a safe name", async () => {
    ok();
    protocolDiagAnalyze.mockResolvedValue(MATCHED);
    const blobs: Blob[] = [];
    const createURL = vi.spyOn(URL, "createObjectURL").mockImplementation((b: Blob | MediaSource) => {
      blobs.push(b as Blob);
      return "blob:tac";
    });
    const revoke = vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => undefined);
    const clicked: HTMLAnchorElement[] = [];
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      clicked.push(this);
    });
    try {
      await open({ device: true, issue: /BGP session down/ });
      fireEvent.change(screen.getByLabelText("Paste output for show ip bgp summary"), { target: { value: "Idle" } });
      fireEvent.click(analyzeBtn());
      await screen.findByText("The peer is Idle because there is no route to it");
      fireEvent.click(tacBtn());
      await waitFor(() => expect(clicked.length).toBe(1));
      expect(clicked[0].download).toBe("tac-bundle-leaf1-bgp-session-down.txt");
      expect(await blobs[0].text()).toBe(MATCHED.tac_export);
      expect(await screen.findByText(/TAC bundle \(redacted\) downloaded as tac-bundle-leaf1-bgp-session-down\.txt/)).toBeInTheDocument();
    } finally {
      createURL.mockRestore(); revoke.mockRestore(); click.mockRestore();
    }
  });

  it("asks for an analysis first instead of shipping an empty bundle", async () => {
    ok();
    await open({ device: true, issue: /BGP session down/ });
    fireEvent.click(tacBtn());
    expect(await screen.findByText(/Analyze the output first/)).toBeInTheDocument();
  });
});

describe("Correlate", () => {
  it("links to the RCA list (the RCA page has no device filter)", async () => {
    ok();
    await open();
    const link = screen.getByRole("link", { name: "Correlate" });
    expect(link.getAttribute("href")).toBe("#/investigate/rca");
  });
});
