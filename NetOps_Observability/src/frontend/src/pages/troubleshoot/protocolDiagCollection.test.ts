// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// protocolDiagCollection.test.ts — D-4 (QA run 2026-09-03).
//
// A live capture on the lab spines had every one of 7 read-only commands
// rejected by the device and captured ZERO bytes. The panel announced
// "Captured 7 command(s)…" in the success tone, and the analysis then said
// "no known signature matched". Both sentences told the operator the platform
// had looked at the protocol. It had not looked at anything.
//
// These are the pure tests for the three-way classification that fixes it.

import { describe, it, expect } from "vitest";
import type { ProtocolDiagCollectedCommand } from "../../services/api";
import {
  NOTHING_ANALYZED_MESSAGE,
  analysisWasScored,
  failedCommands,
  summarizeCollection,
} from "./protocolDiagModel";

function cmd(spec: string, output: string, error = ""): ProtocolDiagCollectedCommand {
  return { spec_id: spec, command: `show ${spec}`, purpose: spec, output, timestamp: "2026-09-03T00:00:00Z", error };
}

const REJECTED = 'command "show router isis adjacency" failed: Process exited with status 1';

describe("summarizeCollection", () => {
  it("calls a total rejection what it is: nothing captured, state unknown", () => {
    const s = summarizeCollection({
      hostname: "spine1",
      rendered_vendor: "nokia",
      commands: [cmd("a", "", REJECTED), cmd("b", "", REJECTED), cmd("c", "", REJECTED)],
    });
    expect(s.outcome).toBe("failed");
    expect(s.tone).toBe("bad");
    expect(s.total).toBe(3);
    expect(s.captured).toBe(0);
    expect(s.failed).toBe(3);
    expect(s.text).toContain("spine1");
    expect(s.text).toContain("rejected all 3 read-only commands");
    expect(s.text).toContain("nothing was captured");
    expect(s.text).toContain("unknown, not healthy");
    // The exact sentence the defect produced must be impossible here.
    expect(s.text).not.toMatch(/^Captured/);
    expect(s.text.toLowerCase()).not.toContain("signature");
  });

  it("treats a whitespace-only capture as no capture", () => {
    const s = summarizeCollection({ hostname: "spine1", commands: [cmd("a", "   \n\t ")] });
    expect(s.outcome).toBe("failed");
    expect(s.captured).toBe(0);
  });

  it("discloses a partial capture and says the verdict rests on less", () => {
    const s = summarizeCollection({
      hostname: "leaf1",
      rendered_vendor: "cisco-iosxe",
      commands: [cmd("a", "Neighbor 10.0.0.2 Idle"), cmd("b", "", "transport timeout")],
    });
    expect(s.outcome).toBe("partial");
    expect(s.tone).toBe("bad");
    expect(s.text).toContain("Captured 1 of 2 commands from leaf1");
    expect(s.text).toContain("1 was rejected");
    expect(s.text).toContain("less than the full bundle");
  });

  it("pluralises the rejection count", () => {
    const s = summarizeCollection({
      hostname: "leaf1",
      commands: [cmd("a", "x"), cmd("b", "", "e"), cmd("c", "", "e")],
    });
    expect(s.text).toContain("2 were rejected");
  });

  it("reports a full capture in the success tone", () => {
    const s = summarizeCollection({
      hostname: "leaf1",
      rendered_vendor: "cisco-iosxe",
      commands: [cmd("a", "out"), cmd("b", "out")],
    });
    expect(s).toMatchObject({ outcome: "captured", tone: "good", total: 2, captured: 2, failed: 0 });
    expect(s.text).toBe("Captured 2 commands from leaf1 in the cisco-iosxe dialect.");
  });

  it("is honest about an empty and about an absent collection", () => {
    for (const col of [null, undefined, { commands: [] }]) {
      const s = summarizeCollection(col);
      expect(s.outcome).toBe("failed");
      expect(s.tone).toBe("bad");
      expect(s.text).toContain("nothing was captured");
      expect(s.text).not.toMatch(/^Captured/);
    }
  });

  it("falls back to the device id, then to a neutral noun, for the subject", () => {
    expect(summarizeCollection({ device_id: "d-1", commands: [cmd("a", "x")] }).text).toContain("from d-1");
    expect(summarizeCollection({ commands: [cmd("a", "x")] }).text).toContain("from the device");
  });
});

describe("failedCommands", () => {
  it("returns exactly the commands that produced no output, with their reasons", () => {
    const rows = failedCommands({
      commands: [cmd("a", "out"), cmd("b", "", REJECTED), cmd("c", "  ", "timeout")],
    });
    expect(rows.map((r) => r.spec_id)).toEqual(["b", "c"]);
    expect(rows[0].error).toBe(REJECTED);
  });
  it("is empty for a clean capture and for no collection at all", () => {
    expect(failedCommands({ commands: [cmd("a", "out")] })).toEqual([]);
    expect(failedCommands(null)).toEqual([]);
    expect(failedCommands(undefined)).toEqual([]);
  });
});

describe("analysisWasScored", () => {
  it("is false only when the server explicitly says nothing was analysed", () => {
    expect(analysisWasScored({ analyzed: false })).toBe(false);
    expect(analysisWasScored({ analyzed: true })).toBe(true);
    // An older server omits the field; "scored" is the safe reading, because the
    // scored branch renders the server's own `unmatched` sentence.
    expect(analysisWasScored({})).toBe(true);
    expect(analysisWasScored(null)).toBe(false);
    expect(analysisWasScored(undefined)).toBe(false);
  });
  it("has a fallback body that never claims the signatures ran", () => {
    expect(NOTHING_ANALYZED_MESSAGE.toLowerCase()).toContain("no signature was scored");
    expect(NOTHING_ANALYZED_MESSAGE.toLowerCase()).toContain("unknown");
    expect(NOTHING_ANALYZED_MESSAGE.toLowerCase()).not.toContain("no known signature matched");
  });
});
