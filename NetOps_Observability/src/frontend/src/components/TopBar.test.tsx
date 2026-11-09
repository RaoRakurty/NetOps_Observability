// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// TopBar per tier (components/topBarTier.ts): which controls sit in the bar,
// which fold into the ONE "More" disclosure, and how that disclosure behaves
// (aria-expanded/aria-controls, Esc closes and returns focus, popups inside it
// keep their own Esc, outside click closes). Layout geometry — no sideways
// scroll, 44 px targets, the mark crop — is proven in a real browser by
// e2e/headerPhoneWidth.spec.ts.

import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import TopBar from "./TopBar";
import { ShellContext, type ShellState } from "../context/shell";
import { installViewport, type FakeViewport } from "../test/fakeViewport";
import type { AuthUser, Health } from "../services/api";

// The scope selector fetches /api/scopes; a static chip stands in for it here.
vi.mock("./ScopeSelector", () => ({ default: () => <span className="scope-chip">Acme</span> }));

const USER = { username: "alice", role: "admin" } as AuthUser;
const HEALTHY = { status: "healthy", version: "1.2.3", uptime: "1h" } as Health;

function shell(over: Partial<ShellState> = {}): ShellState {
  return {
    range: { label: "Last 1 hour", minutes: 60 },
    setRange: () => {},
    query: "*",
    setQuery: () => {},
    copilotOpen: false,
    setCopilotOpen: () => {},
    helpOpen: false,
    setHelpOpen: () => {},
    helpPath: "",
    openHelp: () => {},
    navigate: () => {},
    ...over,
  } as ShellState;
}

function renderBar(opts: { health?: Health | null; hideUserMenu?: boolean; shell?: Partial<ShellState> } = {}) {
  return render(
    <ShellContext.Provider value={shell(opts.shell)}>
      <TopBar
        health={opts.health === undefined ? HEALTHY : opts.health}
        user={USER}
        onLogout={() => {}}
        hideUserMenu={opts.hideUserMenu ?? true}
      />
    </ShellContext.Provider>,
  );
}

const header = () => document.querySelector("header.topbar") as HTMLElement;
const moreBtn = () => screen.queryByRole("button", { name: /^More/ });
const panel = () => document.getElementById("topbar-more-panel");
const searchBox = () => screen.getByRole("combobox", { name: "Search devices, resources, and logs", hidden: true });

describe("TopBar", () => {
  const original = window.matchMedia;
  let vp: FakeViewport;
  beforeEach(() => {
    vp = installViewport(1280);
  });
  afterEach(() => {
    window.matchMedia = original;
  });

  describe("desktop (> 1000 px)", () => {
    it("is the desktop header: no tier, no More, every control inline in order", () => {
      renderBar();
      expect(header().hasAttribute("data-tier")).toBe(false);
      expect(moreBtn()).toBeNull();
      expect(panel()).toBeNull();
      const right = header().querySelector(".topbar-right")!;
      const classes = Array.from(right.children).map((el) => el.className.split(" ")[0]);
      expect(classes).toEqual(["omni", "scope-chip", "range-picker", "help-btn", "health", "iris-launch"]);
      // The help glyph carries no visible word on the desktop bar.
      expect(header().querySelector(".topbar-more-label")).toBeNull();
    });

    it("keeps the account menu in the bar when the shell does not move it to the rail", () => {
      renderBar({ hideUserMenu: false });
      const right = header().querySelector(".topbar-right")!;
      expect(right.lastElementChild?.className).toBe("user-menu");
    });
  });

  describe("medium (≤ 1000 px)", () => {
    beforeEach(() => vp.resize(800));

    it("keeps search inline and folds scope, time range, help and health into More", () => {
      renderBar();
      expect(header().getAttribute("data-tier")).toBe("medium");
      const right = header().querySelector(".topbar-right")!;
      expect(right.firstElementChild?.className).toContain("omni");
      const p = panel()!;
      expect(p.hidden).toBe(true);
      expect(within(p).queryByRole("combobox", { name: /Search devices/, hidden: true })).toBeNull();
      expect(p.querySelector(".scope-chip")).not.toBeNull();
      expect(within(p).getByRole("combobox", { name: "Time range", hidden: true })).toBeTruthy();
      expect(within(p).getByRole("button", { name: "Open documentation", hidden: true })).toBeTruthy();
      expect(within(p).getByRole("status", { hidden: true })).toBeTruthy();
      expect(moreBtn()!.getAttribute("title")).toBe("Time range, help and status");
    });
  });

  describe("phone (≤ 720 px)", () => {
    beforeEach(() => vp.resize(390));

    it("folds search too; ✦ Iris and the account menu stay in the bar", () => {
      renderBar({ hideUserMenu: false });
      expect(header().getAttribute("data-tier")).toBe("phone");
      const right = header().querySelector(".topbar-right")!;
      const classes = Array.from(right.children).map((el) => el.className.split(" ")[0]);
      expect(classes).toEqual(["topbar-more", "iris-launch", "user-menu"]);
      expect(panel()!.contains(searchBox())).toBe(true);
      // The More button comes straight before its panel, so Tab walks into it.
      expect(moreBtn()!.nextElementSibling).toBe(panel());
      // Visible word on the help row, still named "Open documentation".
      expect(within(panel()!).getByRole("button", { name: "Open documentation", hidden: true }).textContent).toContain("Documentation");
    });

    it("is a disclosure: aria-controls names the panel, aria-expanded tracks it", () => {
      renderBar();
      const btn = moreBtn()!;
      expect(btn.getAttribute("aria-controls")).toBe("topbar-more-panel");
      expect(btn.getAttribute("aria-haspopup")).toBeNull(); // not an ARIA menu
      expect(btn.getAttribute("aria-expanded")).toBe("false");
      expect(panel()!.hidden).toBe(true);
      fireEvent.click(btn);
      expect(btn.getAttribute("aria-expanded")).toBe("true");
      expect(panel()!.hidden).toBe(false);
      expect(panel()!.getAttribute("role")).toBe("group");
      expect(panel()!.getAttribute("aria-label")).toBe("Search, time range, help and status");
      fireEvent.click(btn);
      expect(btn.getAttribute("aria-expanded")).toBe("false");
      expect(panel()!.hidden).toBe(true);
    });

    it("Esc closes the panel, returns focus to More, and marks the key handled", () => {
      renderBar();
      const btn = moreBtn()!;
      fireEvent.click(btn);
      const range = within(panel()!).getByRole("combobox", { name: "Time range" });
      range.focus();
      const ev = new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true });
      act(() => {
        range.dispatchEvent(ev);
      });
      expect(panel()!.hidden).toBe(true);
      expect(btn.getAttribute("aria-expanded")).toBe("false");
      expect(document.activeElement).toBe(btn);
      // Handled, so an open Iris sheet does not also close on the same key.
      expect(ev.defaultPrevented).toBe(true);
    });

    it("Esc while closed is left alone (the page and Iris keep it)", () => {
      renderBar();
      const btn = moreBtn()!;
      btn.focus();
      const ev = new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true });
      act(() => {
        btn.dispatchEvent(ev);
      });
      expect(ev.defaultPrevented).toBe(false);
    });

    it("an open popup inside the panel keeps its own Esc; the panel stays open", () => {
      renderBar();
      fireEvent.click(moreBtn()!);
      // Stand-in for an open search-results list (or the scope list).
      const pop = document.createElement("div");
      pop.className = "omni-pop";
      panel()!.appendChild(pop);
      fireEvent.keyDown(searchBox(), { key: "Escape" });
      expect(panel()!.hidden).toBe(false);
      pop.remove();
      fireEvent.keyDown(searchBox(), { key: "Escape" });
      expect(panel()!.hidden).toBe(true);
    });

    it("a click outside closes it; a click inside does not", () => {
      renderBar();
      fireEvent.click(moreBtn()!);
      fireEvent.mouseDown(within(panel()!).getByRole("combobox", { name: "Time range" }));
      expect(panel()!.hidden).toBe(false);
      fireEvent.mouseDown(document.body);
      expect(panel()!.hidden).toBe(true);
    });

    it("Documentation opens help and closes the panel", () => {
      const setHelpOpen = vi.fn();
      renderBar({ shell: { setHelpOpen } });
      fireEvent.click(moreBtn()!);
      fireEvent.click(within(panel()!).getByRole("button", { name: "Open documentation" }));
      expect(setHelpOpen).toHaveBeenCalledWith(true);
      expect(panel()!.hidden).toBe(true);
    });

    it("running a search from the panel navigates and closes it", () => {
      const navigate = vi.fn();
      const setQuery = vi.fn();
      renderBar({ shell: { navigate, setQuery } });
      fireEvent.click(moreBtn()!);
      fireEvent.change(searchBox(), { target: { value: "core-1" } });
      fireEvent.submit(searchBox().closest("form")!);
      expect(setQuery).toHaveBeenCalledWith("core-1");
      expect(navigate).toHaveBeenCalledWith("explore/logs");
      expect(panel()!.hidden).toBe(true);
    });

    it("a lost connection still shows on the bar: a dot on More and its name says so", () => {
      renderBar({ health: null });
      const btn = moreBtn()!;
      expect(btn.getAttribute("aria-label")).toBe("More (disconnected)");
      expect(btn.querySelector(".topbar-more-alert")).not.toBeNull();
    });

    it("healthy: plain name, no dot", () => {
      renderBar();
      const btn = moreBtn()!;
      expect(btn.getAttribute("aria-label")).toBe("More");
      expect(btn.querySelector(".topbar-more-alert")).toBeNull();
    });

    it("crossing a breakpoint closes the panel and keeps what was typed", () => {
      renderBar();
      fireEvent.click(moreBtn()!);
      fireEvent.change(searchBox(), { target: { value: "edge-7" } });
      act(() => vp.resize(1280));
      expect(moreBtn()).toBeNull();
      expect((searchBox() as HTMLInputElement).value).toBe("edge-7");
      act(() => vp.resize(390));
      expect(moreBtn()!.getAttribute("aria-expanded")).toBe("false");
      expect(panel()!.hidden).toBe(true);
    });
  });
});
