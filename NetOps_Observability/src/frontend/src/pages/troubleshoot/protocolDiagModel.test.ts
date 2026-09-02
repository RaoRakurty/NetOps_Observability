// protocolDiagModel.test.ts — the pure half of Protocol diagnostics.
//
// What is pinned here:
//  · the status → product-state classification (503 unwired, 404 not visible,
//    403 no permission, 400 the server's own reason) and its copy
//  · buildCollectRequest emits EXACTLY the fields the server accepts (it
//    rejects unknown ones) with the target fields trimmed and clamped
//  · buildAnalyzeRequest drops empty outputs, refuses spec ids that are not in
//    the issue's own bundle, and enforces the server's caps client-side first
//  · the TAC download name can never carry a path or a wire-authored surprise

import { describe, it, expect } from "vitest";
import type { ProtocolDiagIssue } from "../../services/api";
import {
  COLLECTOR_UNWIRED_MESSAGE,
  DEVICE_NOT_VISIBLE_MESSAGE,
  MAX_OUTPUT_CHARS,
  NOTHING_TO_ANALYZE_MESSAGE,
  NO_PERMISSION_MESSAGE,
  PROTOCOL_TABS,
  buildAnalyzeRequest,
  buildCollectRequest,
  classifyProtocolDiagError,
  confidenceTone,
  platformOf,
  protocolDiagErrorMessage,
  protocolLabel,
  serverReason,
  tacFileName,
} from "./protocolDiagModel";

const ISSUE: ProtocolDiagIssue = {
  id: "bgp-session-down",
  protocol: "bgp",
  title: "Session down (Idle/Active/Connect)",
  description: "The peering never reaches Established.",
  commands: [
    { spec_id: "bgp-summary", purpose: "peer state", command: "show ip bgp summary" },
    { spec_id: "bgp-neighbor", purpose: "peer detail", command: "show ip bgp neighbors" },
    { spec_id: "iface-brief", purpose: "interface state", command: "show ip interface brief" },
  ],
};

describe("error classification", () => {
  it("maps 503 to the unwired-collector product state", () => {
    expect(classifyProtocolDiagError(new Error("503 Service Unavailable: {}"))).toBe("unwired");
    expect(protocolDiagErrorMessage(new Error("503 Service Unavailable: {}"))).toBe(COLLECTOR_UNWIRED_MESSAGE);
  });
  it("maps 404 to 'not visible' without revealing whose device it is", () => {
    const msg = protocolDiagErrorMessage(new Error("404 Not Found: 404 page not found"));
    expect(classifyProtocolDiagError(new Error("404 Not Found: x"))).toBe("missing");
    expect(msg).toBe(DEVICE_NOT_VISIBLE_MESSAGE);
    expect(msg).not.toMatch(/tenant/i);
  });
  it("maps 403 to the no-permission line", () => {
    expect(protocolDiagErrorMessage(new Error("403 Forbidden: {}"))).toBe(NO_PERMISSION_MESSAGE);
  });
  it("shows the server's own reason on a 400", () => {
    const e = new Error('400 Bad Request: {"error":"unknown issue \\"nope\\""}');
    expect(classifyProtocolDiagError(e)).toBe("rejected");
    expect(protocolDiagErrorMessage(e)).toBe('unknown issue "nope"');
  });
  it("falls back to the raw message when there is no reason to quote", () => {
    expect(serverReason(new Error("boom"))).toBeNull();
    expect(protocolDiagErrorMessage(new Error("boom"))).toBe("boom");
  });
});

describe("buildCollectRequest", () => {
  it("emits exactly the accepted fields, trimmed", () => {
    const r = buildCollectRequest(" leaf1 ", " bgp-session-down ", { interface: " Gi0/0 ", peer: "10.0.0.2" });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.request).toEqual({
      device_id: "leaf1",
      issue_id: "bgp-session-down",
      target: { interface: "Gi0/0", peer: "10.0.0.2", prefix: "", vrf: "" },
    });
    expect(Object.keys(r.request).sort()).toEqual(["device_id", "issue_id", "target"]);
  });
  it("clamps an oversized target field to the server's own cap", () => {
    const r = buildCollectRequest("leaf1", "bgp-session-down", { vrf: "v".repeat(1000) });
    expect(r.ok && r.request.target.vrf.length).toBe(256);
  });
  it("refuses without a device or an issue", () => {
    expect(buildCollectRequest("", "bgp-session-down").ok).toBe(false);
    expect(buildCollectRequest("leaf1", "").ok).toBe(false);
  });
});

describe("buildAnalyzeRequest", () => {
  it("sends only the commands that actually have output, keyed by spec id", () => {
    const r = buildAnalyzeRequest(ISSUE, { hostname: "leaf1", platform: "Cisco IOS-XE 17.9" }, {
      "bgp-summary": "Idle",
      "bgp-neighbor": "   ",
      "not-in-bundle": "ignored",
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.request).toEqual({
      protocol: "bgp",
      issue_id: "bgp-session-down",
      device: { hostname: "leaf1", platform: "Cisco IOS-XE 17.9" },
      outputs: [{ spec_id: "bgp-summary", output: "Idle" }],
    });
  });
  it("refuses when nothing has been collected or pasted", () => {
    const r = buildAnalyzeRequest(ISSUE, null, { "bgp-summary": "" });
    expect(r).toEqual({ ok: false, reason: NOTHING_TO_ANALYZE_MESSAGE });
  });
  it("refuses an output larger than the server's per-command cap", () => {
    const r = buildAnalyzeRequest(ISSUE, null, { "bgp-summary": "x".repeat(MAX_OUTPUT_CHARS + 1) });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/larger than/);
  });
  it("refuses without an issue", () => {
    expect(buildAnalyzeRequest(null, null, { a: "b" }).ok).toBe(false);
  });
});

describe("presentation helpers", () => {
  it("names the TAC bundle safely", () => {
    expect(tacFileName("bgp-session-down", "leaf1")).toBe("tac-bundle-leaf1-bgp-session-down.txt");
    expect(tacFileName("../../etc/passwd", "a/b c")).toBe("tac-bundle-a_b_c-.._.._etc_passwd.txt");
    expect(tacFileName("", "")).toBe("tac-bundle-device-issue.txt");
  });
  it("builds the platform string from the inventory fields", () => {
    expect(platformOf({ vendor: "Cisco", os: "IOS-XE", model: "C9300" })).toBe("Cisco IOS-XE C9300");
    expect(platformOf(null)).toBe("");
  });
  it("tones confidence honestly (low is a hint, not a verdict)", () => {
    expect(confidenceTone("high")).toBe("good");
    expect(confidenceTone("medium")).toBe("warn");
    expect(confidenceTone("low")).toBe("muted");
    expect(confidenceTone("")).toBe("muted");
  });
  it("labels the three protocol tabs", () => {
    expect(PROTOCOL_TABS.map((t) => t.id)).toEqual(["bgp", "ospf", "isis"]);
    expect(protocolLabel("isis")).toBe("IS-IS");
    expect(protocolLabel("rip")).toBe("RIP");
  });
});
