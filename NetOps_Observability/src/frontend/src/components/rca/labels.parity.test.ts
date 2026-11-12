// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { signatureNocTitle, hypothesisNocTitle, kindLabel } from "./labels";

// labels.parity.test.ts — the TS half of the noclabel ↔ labels.ts parity
// contract (RCA document v2 §3.2/§7). src/contracts/noc_label_parity.json is
// generated FROM the Go side (internal/noclabel, NOCLABEL_UPDATE_PARITY=1) and
// pins, for every explicit signature title and one probe id per cascade rung,
// the title an operator must see. When Go changes a title, its own test fails
// until the fixture is regenerated — and then this test fails until labels.ts
// says the same thing. One title per signature, on every surface.

interface ParityFile {
  signature_titles: Record<string, string>;
  cascade_probes: Record<string, string>;
  hypothesis_titles: { id: string; catalog_title: string; want: string }[];
}

const FIXTURE = join(dirname(fileURLToPath(import.meta.url)), "../../../../contracts/noc_label_parity.json");
const parity = JSON.parse(readFileSync(FIXTURE, "utf8")) as ParityFile;

describe("labels.ts ↔ noclabel parity (src/contracts/noc_label_parity.json)", () => {
  it("the fixture is not empty (a vacuous parity test proves nothing)", () => {
    expect(Object.keys(parity.signature_titles).length).toBeGreaterThan(20);
    expect(Object.keys(parity.cascade_probes).length).toBeGreaterThan(10);
    expect(parity.hypothesis_titles.length).toBeGreaterThan(0);
  });

  it("every explicit Go signature title reads the same in the UI", () => {
    const drift = Object.entries(parity.signature_titles)
      .filter(([id, want]) => signatureNocTitle(id) !== want)
      .map(([id, want]) => `${id}: ts=${signatureNocTitle(id)} go=${want}`);
    expect(drift).toEqual([]);
  });

  it("every cascade rung lands where Go lands it", () => {
    const drift = Object.entries(parity.cascade_probes)
      .filter(([id, want]) => signatureNocTitle(id) !== want)
      .map(([id, want]) => `${id}: ts=${signatureNocTitle(id)} go=${want}`);
    expect(drift).toEqual([]);
  });

  it("hypothesis titles follow the same precedence (explicit → catalog → cascade)", () => {
    for (const c of parity.hypothesis_titles) {
      expect(hypothesisNocTitle(c.id, c.catalog_title), c.id).toBe(c.want);
    }
  });
});

// Not pinned by the fixture yet: the kind labels the topology view prints. These
// three mirror noclabel.Kind word for word (an if_metric_anomaly is a
// counter/rate departure, never a state change; a device alarm is not a
// routing or link event).
describe("kind labels shown in section 6 mirror noclabel.Kind", () => {
  it.each([
    ["if_metric_anomaly", "Interface metric anomaly"],
    ["device_alarm", "Device alarm"],
    ["device_resource_anomaly", "Device CPU/memory change"],
    ["mac_flap", "MAC address flap"],
    ["link_state_change", "Link up/down"],
  ])("%s → %s", (kind, want) => {
    expect(kindLabel(kind)).toBe(want);
  });
});

describe("§3.2 — the access family no longer collapses into one title", () => {
  it("local link fault, MAC flap, OSPF flap and DNS read as four different things", () => {
    const titles = [
      "sig.ent.access.local-link-fault", "sig.ent.access.mac-flap",
      "sig.ent.access.ospf-adjacency-flap", "sig.ent.access.dns-local-resolver-failure",
    ].map(signatureNocTitle);
    expect(new Set(titles).size).toBe(4);
    expect(titles).not.toContain("Link state change");
    expect(signatureNocTitle("sig.ent.access.mac-flap")).toBe("MAC address flapping");
  });

  it("`access` is not a cascade token; an id that says link still is a link event", () => {
    expect(signatureNocTitle("sig.ent.access.new-template")).not.toBe("Link state change");
    expect(signatureNocTitle("sig.ent.access.port-link-errors")).toBe("Link state change");
  });

  it("a catalog title equal to the raw id never leaks the id", () => {
    expect(hypothesisNocTitle("sig.ent.lan.new-thing", "sig.ent.lan.new-thing")).not.toBe("sig.ent.lan.new-thing");
  });
});
