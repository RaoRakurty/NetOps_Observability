// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// IrisNav — Iris is an ACTION with no pages.
//
// Iris is pinned to the foot: clicking it opens the ask slide-over rather than
// navigating. It used to carry a routed Knowledge page (the TAC catalogue);
// since 2026-09-15 that knowledge is built into Iris and read before it
// answers, and the page is gone (owner: an administrator should not have to
// read what Iris knows). This pins the leafless shape in every mode:
//   · Ask Iris opens the slide-over and does not navigate (sidebar and rail);
//   · no Knowledge leaf, no rail flyout, no ⌘K page destination;
//   · the old #/copilot/knowledge link resolves to the section, never a page.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent } from "@testing-library/react";
import { ShellContext, type ShellState } from "../context/shell";
import { NAV, filteredNav, navDestinations, resolveRoute, routeFor } from "../nav";
import Sidebar from "./Sidebar";
import IconRail from "./IconRail";

const USER = { username: "op", role: "operator" } as never;

function shell(over: Partial<ShellState> = {}): ShellState {
  return {
    range: { label: "1h", minutes: 60 } as never,
    setRange: vi.fn(),
    query: "",
    setQuery: vi.fn(),
    copilotOpen: false,
    setCopilotOpen: vi.fn(),
    helpOpen: false,
    setHelpOpen: vi.fn(),
    helpPath: "",
    openHelp: vi.fn(),
    navigate: vi.fn(),
    ...over,
  };
}

function withShell(ui: React.ReactElement, state: ShellState) {
  return render(<ShellContext.Provider value={state}>{ui}</ShellContext.Provider>);
}

const irisSection = () => NAV.find((s) => s.id === "copilot")!;

afterEach(cleanup);
beforeEach(() => localStorage.clear());

describe("the Iris nav section", () => {
  it("is an action with no routed pages", () => {
    const iris = irisSection();
    expect(iris.action).toBe("copilot");
    expect(iris.footer).toBe(true);
    expect(iris.children ?? [], "Iris must carry no pages — its knowledge is built in").toEqual([]);
  });

  it("resolves the old #/copilot/knowledge link to the section, never a page", () => {
    const r = resolveRoute("#/copilot/knowledge", filteredNav(false));
    expect(r.section.id).toBe("copilot");
    expect(r.leaf).toBeUndefined();
    expect(routeFor(irisSection())).toBe("copilot");
  });

  it("offers only the ask action to the command palette", () => {
    const dests = navDestinations(filteredNav(false));
    const ask = dests.find((d) => d.route === "copilot");
    expect(ask?.action, "Ask Iris must still be an action, not a route").toBe("copilot");
    expect(dests.filter((d) => d.route.startsWith("copilot/"))).toEqual([]);
  });
});

describe("sidebar mode", () => {
  it("opens the slide-over on click, does not navigate, and reveals no Knowledge", () => {
    const st = shell();
    withShell(
      <Sidebar nav={filteredNav(false)} activeSection="overview" collapsed={false} onToggle={vi.fn()} />,
      st,
    );
    fireEvent.click(screen.getByRole("button", { name: /iris/i }));
    expect(st.setCopilotOpen).toHaveBeenCalledWith(true);
    expect(st.navigate).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "Knowledge" })).toBeNull();
  });
});

describe("icon-rail mode", () => {
  it("opens the slide-over on click and advertises no menu", () => {
    const st = shell();
    withShell(<IconRail nav={filteredNav(false)} activeSection="overview" user={USER} onLogout={vi.fn()} />, st);
    const iris = screen.getByRole("button", { name: /iris/i });
    expect(iris.getAttribute("aria-haspopup")).toBeNull();
    fireEvent.click(iris);
    expect(st.setCopilotOpen).toHaveBeenCalledWith(true);
    expect(st.navigate).not.toHaveBeenCalled();
  });

  it("an acting section that did carry children would still get its flyout", () => {
    const st = shell();
    const withLeaf = [{ id: "copilot", label: "Iris", icon: "copilot", action: "copilot" as const, footer: true,
      children: [{ id: "x", label: "X", render: () => null }] }];
    withShell(<IconRail nav={withLeaf as never} activeSection="overview" user={USER} onLogout={vi.fn()} />, st);
    expect(screen.getByRole("button", { name: /iris/i }).getAttribute("aria-haspopup")).toBe("menu");
  });
});
