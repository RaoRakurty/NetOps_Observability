// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// pcapModel.test.ts — the guardrails that stand between an operator and a
// packet engine pointed at production traffic.
//
// What is pinned here:
//  · the bounds are BOUNDS: 61 s and 10 001 packets are refused, 60 s and
//    10 000 are accepted (the ceiling itself is legal)
//  · a filter carrying shell metacharacters is refused with the character named
//    — `; rm -rf` never reaches the wire
//  · the closed host/net/port/proto grammar accepts what tcpdump operators
//    actually type and refuses everything else
//  · the POST body is EXACTLY the contract: interface/duration_s/max_packets,
//    with `filter` omitted when empty
//  · an unrecognised wire status is never optimistically "done"
//  · 409/400/403/404 classify into the four product states, and the server's
//    own `{error}` reason survives to the operator verbatim

import { describe, it, expect } from "vitest";
import {
  DURATION_MESSAGE,
  FEATURE_OFF_MESSAGE,
  MAX_DURATION_S,
  MAX_FILTER_LEN,
  MAX_PACKETS,
  NO_PERMISSION_MESSAGE,
  PACKETS_MESSAGE,
  RUNNING_MESSAGE,
  canDownload,
  classifyPcapError,
  fmtFilter,
  fmtPackets,
  isTerminal,
  pcapErrorMessage,
  pcapStatusOf,
  serverReason,
  statusTone,
  validateCapture,
  validateFilter,
} from "./pcapModel";

const form = (over: Partial<Parameters<typeof validateCapture>[0]> = {}) => ({
  interface: "GigabitEthernet0/0/1",
  duration_s: 15,
  max_packets: 1000,
  filter: "",
  ...over,
});

describe("duration guardrail — the 60 second ceiling is a ceiling", () => {
  it("refuses a 61 second capture with the reason the operator needs", () => {
    const r = validateCapture(form({ duration_s: 61 }));
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error("expected a refusal");
    expect(r.errors.duration_s).toBe(DURATION_MESSAGE);
    expect(r.errors.duration_s).toContain(String(MAX_DURATION_S));
  });

  it("accepts the ceiling itself (60 s) and refuses zero and negatives", () => {
    expect(validateCapture(form({ duration_s: 60 })).ok).toBe(true);
    expect(validateCapture(form({ duration_s: 0 })).ok).toBe(false);
    expect(validateCapture(form({ duration_s: -5 })).ok).toBe(false);
  });

  it("refuses a non-integer or unparseable duration rather than coercing it", () => {
    expect(validateCapture(form({ duration_s: "12.5" })).ok).toBe(false);
    expect(validateCapture(form({ duration_s: "" })).ok).toBe(false);
    expect(validateCapture(form({ duration_s: "60; reboot" })).ok).toBe(false);
  });
});

describe("packet guardrail — the 10 000 packet ceiling is a ceiling", () => {
  it("refuses 10 001 packets with the reason the operator needs", () => {
    const r = validateCapture(form({ max_packets: 10001 }));
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error("expected a refusal");
    expect(r.errors.max_packets).toBe(PACKETS_MESSAGE);
  });

  it("accepts the ceiling itself (10 000) and refuses zero", () => {
    expect(validateCapture(form({ max_packets: MAX_PACKETS })).ok).toBe(true);
    expect(validateCapture(form({ max_packets: 0 })).ok).toBe(false);
  });
});

describe("interface guardrail", () => {
  it("refuses an empty interface", () => {
    const r = validateCapture(form({ interface: "  " }));
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error("expected a refusal");
    expect(r.errors.interface).toBeTruthy();
  });

  it("accepts the real vendor dialects operators type", () => {
    for (const name of ["ge-0/0/0.0", "GigabitEthernet0/0/1", "Ethernet1/1", "xe-0/0/0:1", "eth0", "1/1/1"]) {
      expect(validateCapture(form({ interface: name })).ok).toBe(true);
    }
  });

  it("refuses an interface name carrying a shell metacharacter", () => {
    const r = validateCapture(form({ interface: "eth0; reboot" }));
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error("expected a refusal");
    expect(r.errors.interface).toBeTruthy();
  });
});

describe("BPF filter grammar — closed by construction", () => {
  it("refuses a filter injection (`; rm -rf`) and names the character", () => {
    const r = validateFilter("; rm -rf");
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error("expected a refusal");
    expect(r.reason).toContain("Shell metacharacters are not allowed");
    expect(r.reason).toContain('";"');
  });

  it("refuses every other metacharacter an operator could smuggle in", () => {
    for (const bad of [
      "host 10.0.0.1 && reboot",
      "host 10.0.0.1 | nc evil 1",
      "host `id`",
      "host $(id)",
      "host 10.0.0.1 > /etc/passwd",
      "port 179 ; ls",
      "host 10.0.0.1\nport 179",
    ]) {
      expect(validateFilter(bad).ok, bad).toBe(false);
    }
  });

  it("accepts `host 10.0.0.1 and port 179`", () => {
    expect(validateFilter("host 10.0.0.1 and port 179")).toEqual({ ok: true });
  });

  it("accepts the rest of the host/net/port/proto grammar", () => {
    for (const good of [
      "",
      "tcp",
      "tcp port 179",
      "src host 10.0.0.1",
      "dst net 10.0.0.0/8",
      "not port 22",
      "host 10.0.0.1 or host 10.0.0.2",
      "proto icmp",
      "proto 47",
      "portrange 1000-2000",
      "udp and dst port 161",
      "host router1.example.com",
      "host fe80::1",
      "net 2001:db8::/32",
    ]) {
      expect(validateFilter(good).ok, good).toBe(true);
    }
  });

  it("refuses tokens outside the grammar and malformed values", () => {
    for (const bad of [
      "ether host aa",             // unsupported primitive
      "host",                      // primitive with no value
      "host 10.0.0.1 and",         // trailing logic
      "host 10.0.0.1 port 179",    // missing logic between terms
      "port 99999",                // out of range
      "port abc",                  // non-numeric port
      "net 10.0.0.0/99",           // impossible prefix
      "host 300.1.1.1",            // impossible octet
      "portrange 2000-1000",       // inverted range
    ]) {
      expect(validateFilter(bad).ok, bad).toBe(false);
    }
  });

  it("refuses a filter longer than the contract allows", () => {
    const long = "host 10.0.0.1 and ".repeat(40) + "port 179";
    expect(long.length).toBeGreaterThan(MAX_FILTER_LEN);
    expect(validateFilter(long).ok).toBe(false);
  });
});

describe("the POST payload", () => {
  it("is exactly the contract, with an empty filter OMITTED", () => {
    const r = validateCapture(form({ interface: " ge-0/0/0 ", duration_s: "30", max_packets: "500", filter: "  " }));
    expect(r.ok).toBe(true);
    if (!r.ok) throw new Error("expected acceptance");
    expect(r.request).toEqual({ interface: "ge-0/0/0", duration_s: 30, max_packets: 500 });
    expect("filter" in r.request).toBe(false);
  });

  it("carries the trimmed filter when one was given", () => {
    const r = validateCapture(form({ filter: "  host 10.0.0.1 and port 179  " }));
    expect(r.ok).toBe(true);
    if (!r.ok) throw new Error("expected acceptance");
    expect(r.request).toEqual({
      interface: "GigabitEthernet0/0/1",
      duration_s: 15,
      max_packets: 1000,
      filter: "host 10.0.0.1 and port 179",
    });
  });

  it("reports every broken field at once rather than one at a time", () => {
    const r = validateCapture({ interface: "", duration_s: 61, max_packets: 10001, filter: "; rm -rf" });
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error("expected a refusal");
    expect(Object.keys(r.errors).sort()).toEqual(["duration_s", "filter", "interface", "max_packets"]);
  });
});

describe("status vocabulary — an unknown state is never a success", () => {
  it("coerces an unrecognised wire status to failed, not done", () => {
    expect(pcapStatusOf("running")).toBe("running");
    expect(pcapStatusOf("done")).toBe("done");
    expect(pcapStatusOf("expired")).toBe("expired");
    expect(pcapStatusOf("succeeded")).toBe("failed");
    expect(pcapStatusOf(undefined)).toBe("failed");
  });

  it("polls only a running capture", () => {
    expect(isTerminal("running")).toBe(false);
    for (const s of ["done", "failed", "expired"] as const) expect(isTerminal(s)).toBe(true);
  });

  it("offers a download only for a finished capture that still holds bytes", () => {
    expect(canDownload({ status: "done", bytes: 2048 })).toBe(true);
    expect(canDownload({ status: "done", bytes: 0 })).toBe(false);
    expect(canDownload({ status: "running", bytes: 2048 })).toBe(false);
    expect(canDownload({ status: "expired", bytes: 2048 })).toBe(false);
  });

  it("tones the four states distinctly", () => {
    expect(statusTone("done")).toBe("good");
    expect(statusTone("running")).toBe("warn");
    expect(statusTone("failed")).toBe("bad");
    expect(statusTone("expired")).toBe("");
  });
});

describe("failure classification", () => {
  const err = (s: string) => new Error(s);

  it("maps 404 and 501 to the feature-off product state", () => {
    expect(classifyPcapError(err("404 Not Found: "))).toBe("off");
    expect(classifyPcapError(err("501 Not Implemented: "))).toBe("off");
    expect(pcapErrorMessage(err("404 Not Found: "))).toBe(`${FEATURE_OFF_MESSAGE}.`);
  });

  it("maps 409 to the already-running state and prefers the server's reason", () => {
    expect(classifyPcapError(err("409 Conflict: {}"))).toBe("conflict");
    expect(pcapErrorMessage(err("409 Conflict: "))).toBe(RUNNING_MESSAGE);
    expect(pcapErrorMessage(err('409 Conflict: {"error":"capture cap-1 is still running"}')))
      .toBe("capture cap-1 is still running");
  });

  it("maps 400 to a guardrail refusal and renders the server's reason inline", () => {
    expect(classifyPcapError(err("400 Bad Request: {}"))).toBe("rejected");
    expect(pcapErrorMessage(err('400 Bad Request: {"error":"duration_s must be 1-60"}')))
      .toBe("duration_s must be 1-60");
  });

  it("maps 403 to the permission message", () => {
    expect(classifyPcapError(err("403 Forbidden: "))).toBe("forbidden");
    expect(pcapErrorMessage(err("403 Forbidden: "))).toBe(NO_PERMISSION_MESSAGE);
  });

  it("returns null for a body that is not the contracted {error} object", () => {
    expect(serverReason(new Error("500 Internal Server Error: boom"))).toBeNull();
    expect(serverReason(new Error('400 Bad Request: {"error":""}'))).toBeNull();
    expect(serverReason(new Error("400 Bad Request: {not json"))).toBeNull();
  });
});

describe("formatting", () => {
  it("names an absent filter honestly instead of leaving a gap", () => {
    expect(fmtFilter("")).toBe("no filter (all traffic)");
    expect(fmtFilter(undefined)).toBe("no filter (all traffic)");
    expect(fmtFilter(" host 10.0.0.1 ")).toBe("host 10.0.0.1");
  });

  it("groups packet counts and refuses to invent one", () => {
    expect(fmtPackets(10000)).toBe("10,000");
    expect(fmtPackets(0)).toBe("0");
    expect(fmtPackets(undefined)).toBe("—");
  });
});
