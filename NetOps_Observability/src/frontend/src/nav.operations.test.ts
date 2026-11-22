// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// nav.operations.test.ts — the Operations section's shape (owner, 2026-11-22).
//
// The three operational lists are ordered most-aggregated first: Problems (the
// correlated cases that need action — the leaf was "Action Queue"), then
// Incidents (owned, tracked), then Active Alerts (the raw rule firings). Ids
// are unchanged, so every link, bookmark and saved landing still resolves and
// no alias was added.

import { describe, it, expect } from "vitest";
import { NAV, resolveRoute, navDestinations } from "./nav";

const operations = () => {
  const s = NAV.find((x) => x.id === "operations");
  if (!s?.children) throw new Error("no Operations section");
  return s.children;
};

describe("Operations → Problems · Incidents · Active Alerts", () => {
  it("leads with the three lists, most aggregated first, under their NOC names", () => {
    expect(operations().slice(0, 3).map((l) => [l.id, l.label])).toEqual([
      ["queue", "Problems"],
      ["incidents", "Incidents"],
      ["alerts", "Active Alerts"],
    ]);
  });

  it("no leaf is called Action Queue any more", () => {
    expect(operations().some((l) => l.label === "Action Queue")).toBe(false);
  });

  it("every existing address still lands on its page", () => {
    const cases: [string, string][] = [
      ["#/operations/queue", "queue"],
      ["#/operations/incidents", "incidents"],
      ["#/operations/alerts", "alerts"],
      ["#/monitoring/triggered", "alerts"],
      ["#/monitoring/incidents", "incidents"],
      ["#/alerts/active", "alerts"],
      ["#/alerts/incidents", "incidents"],
    ];
    for (const [hash, leaf] of cases) {
      const r = resolveRoute(hash);
      expect(`${hash} → ${r.section.id}/${r.leaf?.id}`).toBe(`${hash} → operations/${leaf}`);
    }
  });

  it("the bare section opens Problems, the first list", () => {
    expect(resolveRoute("#/operations").leaf?.id).toBe("queue");
  });

  it("⌘K offers Problems under its new name", () => {
    const d = navDestinations().find((x) => x.route === "operations/queue");
    expect(d?.label ?? "").toMatch(/Problems/);
  });
});
