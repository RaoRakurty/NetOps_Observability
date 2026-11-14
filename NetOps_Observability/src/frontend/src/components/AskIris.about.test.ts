// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// AskIris.about.test.ts — N-E4 entry points ("Ask Iris about this device" /
// "… this incident") raise the panel's one ask event with the QUESTION only:
// no ids, no labels — the subject rides as the page's registered view.

import { describe, it, expect, afterEach } from "vitest";
import { askIrisAbout, IRIS_ASK_EVENT, type IrisAskDetail } from "./AskIris";
import { incidentQuestion } from "../tabs/Incidents";

function capture(fn: () => void): IrisAskDetail[] {
  const seen: IrisAskDetail[] = [];
  const on = (e: Event) => seen.push((e as CustomEvent<IrisAskDetail>).detail);
  window.addEventListener(IRIS_ASK_EVENT, on);
  try { fn(); } finally { window.removeEventListener(IRIS_ASK_EVENT, on); }
  return seen;
}

afterEach(() => undefined);

describe("askIrisAbout", () => {
  it("raises a free question (no topic) and nothing else", () => {
    const got = capture(() => askIrisAbout("Is this device healthy right now?"));
    expect(got).toEqual([{ topic: "", question: "Is this device healthy right now?" }]);
  });
  it("bounds the question and ignores an empty one", () => {
    expect(capture(() => askIrisAbout("   "))).toEqual([]);
    const long = capture(() => askIrisAbout("x".repeat(1000)));
    expect(long[0].question.length).toBe(300);
  });
});

describe("incidentQuestion", () => {
  it("names the incident by its own title on one line", () => {
    const q = incidentQuestion({ title: "BGP down\non edge-1", severity: "critical" });
    expect(q).toContain('"BGP down on edge-1"');
    expect(q).toContain("critical incident");
    expect(q).not.toContain("\n");
  });
  it("falls back when the incident has no title", () => {
    expect(incidentQuestion({ title: "", severity: "" })).toContain('"this incident"');
  });
});
