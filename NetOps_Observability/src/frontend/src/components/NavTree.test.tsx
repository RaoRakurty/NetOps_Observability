// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// NavTree — the expanded menu (visual language, owner 2026-11-24). Pins:
//   · every page of an opened section renders, each with its icon;
//   · the section you are in is open (always), the others folded;
//   · folding is remembered per browser, and broken storage never breaks it;
//   · a page click routes `section/leaf`; a collapsible page toggles its tabs;
//   · Iris toggles the slide-over; tenants never see Platform;
//   · IconRail shows the tree by default and the icon rail when collapsed.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, within } from "@testing-library/react";
import { filteredNav } from "../nav";
import NavTree, { NAV_TREE_OPEN_KEY } from "./NavTree";
import IconRail from "./IconRail";
import { ShellContext, type ShellState } from "../context/shell";

afterEach(cleanup);
beforeEach(() => {
  localStorage.clear();
  location.hash = "";
});

function tree(over: Partial<React.ComponentProps<typeof NavTree>> = {}) {
  const props = {
    nav: filteredNav(true),
    activeSection: "infrastructure",
    activeLeaf: "devices",
    copilotOpen: false,
    onToggleCopilot: vi.fn(),
    onNavigate: vi.fn(),
    ...over,
  };
  render(<NavTree {...props} />);
  return props;
}

const head = (id: string) => within(screen.getByTestId(`nt-section-${id}`)).getAllByRole("button")[0];

describe("NavTree", () => {
  it("opens the section you are in and folds the rest", () => {
    tree();
    expect(head("infrastructure").getAttribute("aria-expanded")).toBe("true");
    expect(head("operations").getAttribute("aria-expanded")).toBe("false");
    expect(screen.getByTestId("nt-leaf-infrastructure-devices")).toBeTruthy();
    expect(screen.queryByTestId("nt-leaf-operations-alerts")).toBeNull();
  });

  it("marks only the page you are on, with an icon on every page", () => {
    tree();
    const active = screen.getByTestId("nt-leaf-infrastructure-devices");
    expect(active.getAttribute("aria-current")).toBe("page");
    expect(active.className).toContain("active");
    const pages = within(screen.getByTestId("nt-section-infrastructure")).getAllByRole("button").slice(1);
    for (const p of pages) expect(p.querySelector("svg"), p.textContent ?? "").toBeTruthy();
    expect(document.querySelectorAll(".nt-item.active").length).toBe(1);
  });

  it("renders every page of every section once all are opened", () => {
    const nav = filteredNav(true);
    tree({ nav });
    for (const s of nav) {
      if (s.id === "overview" || s.action === "copilot") continue; // the flat top group
      const h = head(s.id);
      if (h.getAttribute("aria-expanded") === "false") fireEvent.click(h);
      for (const l of s.children ?? []) expect(screen.getByTestId(`nt-leaf-${s.id}-${l.id}`)).toBeTruthy();
    }
    for (const l of nav.find((s) => s.id === "overview")!.children ?? []) {
      expect(screen.getByTestId(`nt-leaf-overview-${l.id}`)).toBeTruthy();
    }
  });

  it("remembers a fold across remounts", () => {
    tree();
    fireEvent.click(head("operations"));
    expect(JSON.parse(localStorage.getItem(NAV_TREE_OPEN_KEY)!)).toEqual({ operations: true });
    cleanup();
    tree();
    expect(head("operations").getAttribute("aria-expanded")).toBe("true");
  });

  it("keeps the section you are in open even if it was stored folded", () => {
    localStorage.setItem(NAV_TREE_OPEN_KEY, JSON.stringify({ infrastructure: false }));
    tree();
    expect(head("infrastructure").getAttribute("aria-expanded")).toBe("true");
  });

  it("survives broken stored state", () => {
    localStorage.setItem(NAV_TREE_OPEN_KEY, "{not json");
    tree();
    expect(screen.getByTestId("nt-leaf-infrastructure-devices")).toBeTruthy();
  });

  it("routes a page click to section/leaf", () => {
    const p = tree();
    fireEvent.click(screen.getByTestId("nt-leaf-infrastructure-sites"));
    expect(p.onNavigate).toHaveBeenCalledWith("infrastructure/sites");
  });

  it("a collapsible page toggles its tabs instead of navigating", () => {
    const p = tree({ activeSection: "operations", activeLeaf: "queue" });
    const cloud = screen.getByTestId("nt-leaf-operations-cloud");
    expect(cloud.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(cloud);
    expect(p.onNavigate).not.toHaveBeenCalled();
    expect(cloud.getAttribute("aria-expanded")).toBe("true");
    fireEvent.click(screen.getByRole("button", { name: "Cloud Logs" }));
    expect(p.onNavigate).toHaveBeenCalledWith("explore/logs/cloud");
  });

  it("Iris toggles the slide-over and does not navigate", () => {
    const p = tree();
    fireEvent.click(screen.getByRole("button", { name: /iris/i }));
    expect(p.onToggleCopilot).toHaveBeenCalled();
    expect(p.onNavigate).not.toHaveBeenCalled();
  });

  it("never shows a tenant the Platform section", () => {
    tree({ nav: filteredNav(false) });
    expect(screen.queryByTestId("nt-section-platform")).toBeNull();
    expect(screen.getByTestId("nt-section-admin")).toBeTruthy();
  });
});

describe("IconRail chooses the tree or the icon rail", () => {
  const USER = { username: "op", role: "operator" } as never;
  const st: ShellState = {
    range: { label: "1h", minutes: 60 } as never, setRange: vi.fn(), query: "", setQuery: vi.fn(),
    copilotOpen: false, setCopilotOpen: vi.fn(), helpOpen: false, setHelpOpen: vi.fn(),
    helpPath: "", openHelp: vi.fn(), navigate: vi.fn(),
  };
  const rail = () =>
    render(
      <ShellContext.Provider value={st}>
        <IconRail nav={filteredNav(false)} activeSection="infrastructure" activeLeaf="devices" user={USER} onLogout={vi.fn()} />
      </ShellContext.Provider>,
    );

  it("shows the full menu by default", () => {
    rail();
    expect(document.querySelector(".nav-tree")).toBeTruthy();
  });

  it("starts as the icon rail on a narrow screen, unless the operator expanded it", () => {
    const mm = vi.spyOn(window, "matchMedia" as never).mockImplementation((() => ({ matches: false })) as never);
    try {
      rail();
      expect(document.querySelector(".nav-tree")).toBeNull();
      cleanup();
      localStorage.setItem("netops.railExpanded", "1");
      rail();
      expect(document.querySelector(".nav-tree")).toBeTruthy();
    } finally {
      mm.mockRestore();
    }
  });

  it("shows the icon rail when the operator collapsed it", () => {
    localStorage.setItem("netops.railExpanded", "0");
    rail();
    expect(document.querySelector(".nav-tree")).toBeNull();
    expect(document.querySelectorAll(".rail-item").length).toBeGreaterThan(0);
  });

  it("gives no rail item a per-section colour", () => {
    localStorage.setItem("netops.railExpanded", "0");
    rail();
    for (const el of Array.from(document.querySelectorAll<HTMLElement>(".rail-item"))) {
      expect(el.style.getPropertyValue("--mod")).toBe("");
    }
  });
});
