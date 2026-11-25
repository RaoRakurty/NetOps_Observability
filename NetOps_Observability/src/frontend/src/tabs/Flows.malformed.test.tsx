// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Flows.malformed.test.tsx — Explore → Flows must DEGRADE on a bare or partial
// answer, never crash (2026-11-25: with a minimal mock payload the page threw
// and the error boundary replaced it). Every panel reads each answer through a
// shape check; an answer it cannot read is said to be unreadable, and nothing
// renders "NaN" or "undefined".

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, waitFor, fireEvent } from "@testing-library/react";

vi.mock("../components/EChart", () => ({ default: () => <div data-testid="chart" /> }));

let answer: (name: string) => unknown = () => ({});
vi.mock("../services/api", () => ({
  api: new Proxy({}, { get: (_t, k: string) => () => Promise.resolve(answer(k)) }),
}));

import Flows from "./Flows";
import { resetCoverageCache } from "./flowEmpty";
import { _resetAppNamesForTest } from "../services/appNames";

const errors: unknown[] = [];
let spy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  errors.length = 0;
  resetCoverageCache();
  _resetAppNamesForTest();
  location.hash = "#/explore/flows";
  spy = vi.spyOn(console, "error").mockImplementation((...a: unknown[]) => { errors.push(a); });
});
afterEach(() => { cleanup(); spy.mockRestore(); location.hash = ""; });

const crashed = () => errors.some((a) => /The above error occurred|Uncaught|is not a function|Cannot read prop|is not iterable/i.test(String((a as unknown[])[0])));

async function visitAllTabs() {
  for (const name of [/right now/i, /who is talking/i, /capacity/i]) {
    const tab = screen.queryByRole("radio", { name }) ?? screen.queryByRole("button", { name }) ?? screen.queryByRole("tab", { name });
    if (tab) fireEvent.click(tab);
    await new Promise((r) => setTimeout(r, 50));
  }
}

for (const [label, make] of [
  ["every answer an empty object", () => ({})],
  ["every answer null", () => null],
  ["every answer an empty list", () => []],
  ["lists where objects are expected", () => ({ links: {}, rows: "x", data: { result: {} }, t: null, movers: 3 })],
] as const) {
  describe(`Flows — ${label}`, () => {
    it("renders without crashing and without NaN/undefined on screen", async () => {
      answer = make as () => unknown;
      render(<Flows />);
      await waitFor(() => expect(document.body.textContent?.length ?? 0).toBeGreaterThan(0));
      await visitAllTabs();
      await new Promise((r) => setTimeout(r, 100));
      expect(crashed()).toBe(false);
      expect(screen.queryByText(/\bNaN\b/)).toBeNull();
      expect(screen.queryByText(/\bundefined\b/)).toBeNull();
    });
  });
}
