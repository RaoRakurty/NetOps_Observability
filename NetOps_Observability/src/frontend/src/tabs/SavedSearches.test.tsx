// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// SavedSearches.test.tsx — Open must land on the log search, not on Home.
//
// The page used to navigate to "search/logs", a route from before the 2026-08
// nav redesign that no alias table rewrites. The SPA router never says "not
// found": an unknown section falls back to the first one, so Open silently
// dropped the operator on Overview → Home with the query set and nothing run.

import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup } from "@testing-library/react";
import SavedSearches from "./SavedSearches";
import { ShellContext, TIME_RANGES, type ShellState } from "../context/shell";
import { resolveRoute } from "../nav";

const listSaved = vi.fn();
vi.mock("../services/api", () => ({
  api: {
    listSaved: (...a: unknown[]) => listSaved(...a),
    deleteSaved: () => Promise.resolve(),
  },
}));

afterEach(() => cleanup());

describe("SavedSearches — Open", () => {
  it("sets the saved query and navigates to Explore → Logs", async () => {
    listSaved.mockResolvedValue([
      { id: "s1", type: "saved_search", name: "Core errors", body: { query: "severity:err", signal: "syslog" }, updated_at: "2026-09-27T10:00:00Z" },
    ]);
    const navigate = vi.fn();
    const setQuery = vi.fn();
    const shell: ShellState = {
      range: TIME_RANGES[1], setRange: () => {},
      query: "", setQuery,
      copilotOpen: false, setCopilotOpen: () => {},
      helpOpen: false, setHelpOpen: () => {}, helpPath: "", openHelp: () => {},
      navigate,
    };
    render(<ShellContext.Provider value={shell}><SavedSearches /></ShellContext.Provider>);
    fireEvent.click(await screen.findByText("Open"));

    expect(setQuery).toHaveBeenCalledWith("severity:err");
    expect(navigate).toHaveBeenCalledWith("explore/logs");
    // The route it navigates to must be the real Logs leaf, not a fallback.
    const r = resolveRoute("#/" + navigate.mock.calls[0][0]);
    expect(r.section.id).toBe("explore");
    expect(r.leaf?.id).toBe("logs");
  });
});
