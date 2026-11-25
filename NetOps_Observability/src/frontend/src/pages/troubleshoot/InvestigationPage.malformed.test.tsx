// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// InvestigationPage.malformed.test.tsx — Investigate → Troubleshooting must
// DEGRADE on a bare or partial answer, never fall to its error screen
// (2026-11-25: with a minimal mock payload the page showed its error boundary).
// Each read is shape-checked; nothing renders "NaN" or "undefined".

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import { ShellContext, type ShellState } from "../../context/shell";

let answer: (name: string) => unknown = () => ({});
const errs = vi.hoisted(() => {
  class FakeNotPromoted extends Error {
    constructor(public reason: string) { super(reason); this.name = "RcaNotPromotedError"; }
  }
  class FakeStreamBroken extends Error {}
  return { FakeNotPromoted, FakeStreamBroken };
});
vi.mock("../../services/api", () => ({
  api: new Proxy({}, { get: (_t, k: string) => () => Promise.resolve(answer(k)) }),
  RcaNotPromotedError: errs.FakeNotPromoted,
  StreamBrokenError: errs.FakeStreamBroken,
}));

import InvestigationPage from "./InvestigationPage";

const shell = (): ShellState => ({
  range: { label: "Last 1 hour", minutes: 60 }, setRange: vi.fn(),
  query: "", setQuery: vi.fn(),
  copilotOpen: false, setCopilotOpen: vi.fn(),
} as unknown as ShellState);

const errors: unknown[] = [];
let spy: ReturnType<typeof vi.spyOn>;
beforeEach(() => {
  errors.length = 0;
  spy = vi.spyOn(console, "error").mockImplementation((...a: unknown[]) => { errors.push(a); });
});
afterEach(() => { cleanup(); spy.mockRestore(); });

const crashed = () => errors.some((a) => /The above error occurred|Uncaught|is not a function|Cannot read prop|is not iterable/i.test(String((a as unknown[])[0])));

it("an unreadable case list says so — never an empty 'no open cases' (a false all-clear)", async () => {
  answer = () => ({});
  render(<ShellContext.Provider value={shell()}><InvestigationPage /></ShellContext.Provider>);
  expect(await screen.findByText(/open cases could not be read/i)).toBeTruthy();
});

for (const [label, make] of [
  ["every answer an empty object", () => ({})],
  ["every answer null", () => null],
  ["every answer an empty list", () => []],
  ["objects where lists are expected", () => ({ data: {}, items: "x", objects: {}, results: 3 })],
] as const) {
  describe(`Troubleshooting — ${label}`, () => {
    it("renders the page (no error screen, no crash, no NaN/undefined)", async () => {
      answer = make as () => unknown;
      render(<ShellContext.Provider value={shell()}><InvestigationPage /></ShellContext.Provider>);
      await new Promise((r) => setTimeout(r, 300));
      expect(crashed()).toBe(false);
      expect(screen.queryByText(/something went wrong|this panel hit an error|could not render/i)).toBeNull();
      expect(screen.queryByText(/\bNaN\b/)).toBeNull();
      expect(screen.queryByText(/\bundefined\b/)).toBeNull();
    });
  });
}
