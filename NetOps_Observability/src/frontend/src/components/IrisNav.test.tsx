// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// IrisNav — the one section that BOTH acts and routes.
//
// Iris is pinned to the foot as an ACTION: clicking it opens the ask slide-over
// rather than navigating. It now also carries a routed child, Knowledge (the
// TAC/skills catalogue — what Iris knows). Those are independent properties,
// and the shell used to conflate them: both the sidebar and the icon rail
// short-circuited on `action === "copilot"` and never rendered children, so a
// page under Iris was unreachable in either mode.
//
// This pins both halves at once, because regressing either is silent:
//   · Ask Iris still opens the slide-over and still does not navigate;
//   · Knowledge is reachable from the sidebar list AND the rail flyout;
//   · ⌘K offers both the action and the page.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";
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
  it("is an action AND carries a routed Knowledge leaf", () => {
    const iris = irisSection();
    expect(iris.action).toBe("copilot");
    expect(iris.footer).toBe(true);
    const leaf = iris.children?.find((l) => l.id === "knowledge");
    expect(leaf, "Iris must carry the Knowledge page").toBeTruthy();
    expect(leaf!.label).toBe("Knowledge");
  });

  it("resolves #/copilot/knowledge to the Knowledge leaf", () => {
    const r = resolveRoute("#/copilot/knowledge", filteredNav(false));
    expect(r.section.id).toBe("copilot");
    expect(r.leaf?.id).toBe("knowledge");
    // routeFor now points at the first leaf, so the section is addressable.
    expect(routeFor(irisSection())).toBe("copilot/knowledge");
  });

  it("offers BOTH the ask action and the page to the command palette", () => {
    const dests = navDestinations(filteredNav(false));
    const ask = dests.find((d) => d.route === "copilot");
    const knowledge = dests.find((d) => d.route === "copilot/knowledge");
    expect(ask?.action, "Ask Iris must still be an action, not a route").toBe("copilot");
    expect(knowledge, "Knowledge must be a real ⌘K destination").toBeTruthy();
    expect(knowledge!.action, "the page routes; it must not open the slide-over").toBeUndefined();
  });
});

describe("sidebar mode", () => {
  it("opens the slide-over on click and does not navigate", () => {
    const st = shell();
    withShell(
      <Sidebar nav={filteredNav(false)} activeSection="overview" collapsed={false} onToggle={vi.fn()} />,
      st,
    );
    fireEvent.click(screen.getByRole("button", { name: /iris/i }));
    expect(st.setCopilotOpen).toHaveBeenCalledWith(true);
    expect(st.navigate).not.toHaveBeenCalled();
  });

  it("reveals Knowledge so the page is one more click away", () => {
    const st = shell();
    withShell(
      <Sidebar nav={filteredNav(false)} activeSection="overview" collapsed={false} onToggle={vi.fn()} />,
      st,
    );
    fireEvent.click(screen.getByRole("button", { name: /iris/i }));
    const knowledge = screen.getByRole("button", { name: "Knowledge" });
    fireEvent.click(knowledge);
    expect(st.navigate).toHaveBeenCalledWith("copilot/knowledge");
  });
});

describe("icon-rail mode", () => {
  it("still opens the slide-over on click", () => {
    const st = shell();
    withShell(<IconRail nav={filteredNav(false)} activeSection="overview" user={USER} onLogout={vi.fn()} />, st);
    fireEvent.click(screen.getByRole("button", { name: /iris/i }));
    expect(st.setCopilotOpen).toHaveBeenCalledWith(true);
    expect(st.navigate).not.toHaveBeenCalled();
  });

  it("opens a flyout that reaches Knowledge", async () => {
    const st = shell();
    withShell(<IconRail nav={filteredNav(false)} activeSection="overview" user={USER} onLogout={vi.fn()} />, st);
    const iris = screen.getByRole("button", { name: /iris/i });
    // An acting section with children advertises a menu — the gate that used to
    // be `!isCopilot` and is now "does it have children".
    expect(iris.getAttribute("aria-haspopup")).toBe("menu");
    fireEvent.keyDown(iris, { key: "ArrowRight" });
    // Flyout leaves are menuitems, not plain buttons (NavFlyout).
    const knowledge = await screen.findByRole("menuitem", { name: "Knowledge" });
    fireEvent.click(knowledge);
    await waitFor(() => expect(st.navigate).toHaveBeenCalledWith("copilot/knowledge"));
  });

  it("a leafless acting section would still advertise no menu", () => {
    const st = shell();
    const leafless = [{ id: "copilot", label: "Iris", icon: "copilot", action: "copilot" as const, footer: true }];
    withShell(<IconRail nav={leafless} activeSection="overview" user={USER} onLogout={vi.fn()} />, st);
    expect(screen.getByRole("button", { name: /iris/i }).getAttribute("aria-haspopup")).toBeNull();
  });
});
