// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// rcaDocument.v2.test.ts — section 8 on the P-3E0400 regression case (RCA
// document v2 §3.2/§3.3): competitors are named by their catalog / NOC titles,
// and a template none of whose REQUIRED observations was seen reads "Nearest
// competitor — not observed", never as an observed or active candidate.

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseRanking, buildOthers, noRequiredClauseSatisfied } from "./rcaDocument";

const DETAIL = join(dirname(fileURLToPath(import.meta.url)), "../../../../backend/internal/rca/testdata/p3e0400/detail.json");
const detail = JSON.parse(readFileSync(DETAIL, "utf8")) as { object: { hypotheses: string } };
const ranking = parseRanking(detail.object.hypotheses);

describe("P-3E0400 — other explanations (§3.2 / §3.3)", () => {
  const others = buildOthers(ranking.slice(1), ranking[0]);

  it("names each competitor by its own title — never the 'Link state change' cascade phrase", () => {
    expect(others.map((o) => o.title)).toEqual([
      "Local DNS resolver failure", "MAC address flapping", "OSPF adjacency flap",
    ]);
    expect(others.map((o) => o.title)).not.toContain("Link state change");
  });

  it("reads DNS, MAC flap and OSPF as nearest competitors — not observed", () => {
    for (const o of others) expect(o.why).toMatch(/^Nearest competitor — not observed: none of its required evidence was seen/);
  });

  it("the leading template (a required clause satisfied) is not a nearest competitor", () => {
    expect(noRequiredClauseSatisfied(ranking[0])).toBe(false);
  });

  it("mirrors the server rule: coverage above the optional cap is a live candidate", () => {
    expect(noRequiredClauseSatisfied({ missing: ["x"], satisfied: ["y"], contradicted: false, confidence: 0.4 })).toBe(false);
    expect(noRequiredClauseSatisfied({ missing: [], satisfied: [], contradicted: false, confidence: 0.05 })).toBe(false);
    expect(noRequiredClauseSatisfied({ missing: ["x"], satisfied: [], contradicted: true, confidence: 0.05 })).toBe(false);
    expect(noRequiredClauseSatisfied({ missing: ["x"], satisfied: ["y"], contradicted: false, confidence: 0.05 })).toBe(true);
  });
});
