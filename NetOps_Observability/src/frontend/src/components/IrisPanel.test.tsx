// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// IrisPanel.test.tsx — the one Iris container (tracker 338–340, 342).
//
// The harness wires the panel exactly as App does: the state machine in a
// reducer, the shell's `copilotOpen` derived from it, preferences saved on
// change. The Iris content is replaced by a probe that counts its own mounts, so "never
// remounted" is a number rather than an impression. Browser-level geometry,
// reflow and motion are e2e/irisPanel.spec.ts.

import { describe, it, expect, afterEach, beforeEach, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { useCallback, useState, type ReactNode } from "react";
import { ShellContext, TIME_RANGES, useShell, type ShellState } from "../context/shell";
import { askIris } from "./AskIris";
import IrisLauncher from "./IrisLauncher";
import IrisPanel from "./IrisPanel";
import {
  DOCK_DEFAULT_W,
  DOCK_MIN_W,
  DOCK_STEP_W,
  irisStorageKeys,
  isOpen,
  saveIrisState,
  type IrisPanelState,
} from "../iris/panel/irisPanelState";
import { useIrisPanelState } from "../iris/panel/useIrisPanelState";

const probe = vi.hoisted(() => ({ mounts: 0, unmounts: 0, asks: [] as string[] }));

vi.mock("../tabs/Iris", async () => {
  const { useEffect: useEff } = await import("react");
  const { useShell: useSh } = await import("../context/shell");
  return {
    default: function OpsisProbe({ controls, context, onBusyChange, ask, onAskHandled }: {
      controls?: ReactNode;
      context?: ReactNode;
      onBusyChange?: (busy: boolean) => void;
      ask?: { topic: string; question: string; seq: number } | null;
      onAskHandled?: () => void;
    }) {
      const { setCopilotOpen } = useSh();
      useEff(() => {
        probe.mounts += 1;
        return () => { probe.unmounts += 1; };
      }, []);
      useEff(() => {
        if (!ask) return;
        probe.asks.push(ask.topic);
        onAskHandled?.();
      }, [ask?.seq]); // eslint-disable-line react-hooks/exhaustive-deps
      return (
        <div className="op-chat">
          <div className="op-hd">
            {controls}
            <button type="button" aria-label="Close Iris" onClick={() => setCopilotOpen(false)}>x</button>
          </div>
          {context}
          <button type="button" onClick={() => onBusyChange?.(true)}>probe: start thinking</button>
          <button type="button" onClick={() => onBusyChange?.(false)}>probe: stop thinking</button>
          <textarea className="op-input" aria-label="Question" defaultValue="" />
        </div>
      );
    },
  };
});

let current: IrisPanelState;
const OWNER = "t-acme/p-alice";
const KEYS = irisStorageKeys(OWNER);

// `initial` is seeded into storage before the first render, then loaded the
// way App loads it (useIrisPanelState) for `owner`.
function Harness({ initial, owner = OWNER }: { initial?: IrisPanelState; owner?: string | null }) {
  useState(() => (initial ? saveIrisState(initial) : false));
  const [iris, dispatch] = useIrisPanelState(owner);
  current = iris;
  const setCopilotOpen = useCallback((b: boolean) => dispatch({ type: b ? "open" : "close" }), []);
  const shell: ShellState = {
    range: TIME_RANGES[1], setRange: () => {},
    query: "", setQuery: () => {},
    copilotOpen: isOpen(iris.mode), setCopilotOpen,
    helpOpen: false, setHelpOpen: () => {}, helpPath: "", openHelp: () => {},
    navigate: () => {},
  };
  return (
    <ShellContext.Provider value={shell}>
      <div className="shell shell-v2">
        <header className="topbar"><IrisLauncher /></header>
        <main id="main-content"><button type="button">page control</button></main>
        <RailItem />
        <IrisPanel state={iris} dispatch={dispatch} />
      </div>
    </ShellContext.Provider>
  );
}

// Stands in for the rail/sidebar/palette entry points: they all just call the
// shell's setter, which is why they open the same panel.
function RailItem() {
  const { copilotOpen, setCopilotOpen } = useShell();
  return <button type="button" title="Iris AI" onClick={() => setCopilotOpen(!copilotOpen)}>Iris AI</button>;
}

const launcher = () => screen.getByRole("button", { name: "Iris", exact: true });
const panelEl = () => document.getElementById("iris-panel") as HTMLElement;
const shellEl = () => document.querySelector(".shell") as HTMLElement;
const press = (key: string, target: Element | Window = window, init: KeyboardEventInit = {}) =>
  act(() => { fireEvent.keyDown(target, { key, ...init }); });

beforeEach(() => {
  localStorage.clear();
  probe.mounts = 0;
  probe.unmounts = 0;
  probe.asks = [];
  Object.defineProperty(window, "innerWidth", { configurable: true, value: 1600 });
});
afterEach(() => cleanup());

describe("the Iris panel container", () => {
  it("is one complementary landmark the header control points at", () => {
    render(<Harness />);
    const p = panelEl();
    expect(p.getAttribute("role")).toBe("complementary");
    expect(p.getAttribute("aria-label")).toBe("Iris");
    expect(launcher().getAttribute("aria-controls")).toBe("iris-panel");
    expect(launcher().getAttribute("aria-expanded")).toBe("false");
    expect(document.querySelectorAll("#iris-panel")).toHaveLength(1);
  });

  it("creates the content on first open only, and never remounts it", () => {
    render(<Harness />);
    expect(probe.mounts, "nothing heavy before Iris is opened").toBe(0);
    expect(panelEl().hasAttribute("inert")).toBe(true);
    expect(panelEl().getAttribute("aria-hidden")).toBe("true");

    fireEvent.click(launcher());
    expect(current.mode, "docked is the default (owner 2026-10-17)").toBe("docked");
    expect(probe.mounts).toBe(1);
    expect(panelEl().hasAttribute("inert")).toBe(false);
    expect(launcher().getAttribute("aria-expanded")).toBe("true");

    fireEvent.click(screen.getByRole("button", { name: "Undock" }));
    fireEvent.click(screen.getByRole("button", { name: "Expand" }));
    fireEvent.click(screen.getByRole("button", { name: "Collapse" }));
    fireEvent.click(screen.getByRole("button", { name: "Dock" }));
    fireEvent.click(screen.getByRole("button", { name: "Close Iris" }));
    expect(current.mode).toBe("closed");
    expect(panelEl().hasAttribute("inert"), "a closed panel cannot be tabbed into").toBe(true);
    fireEvent.click(launcher());
    expect(probe.mounts).toBe(1);
    expect(probe.unmounts).toBe(0);
  });

  it("keeps what the operator typed through every mode change and close/reopen", () => {
    render(<Harness />);
    fireEvent.click(launcher());
    const box = screen.getByRole("textbox", { name: "Question" }) as HTMLTextAreaElement;
    fireEvent.change(box, { target: { value: "top talkers on core-rtr-1" } });
    for (const name of ["Undock", "Expand", "Collapse", "Dock", "Close Iris"]) {
      fireEvent.click(screen.getByRole("button", { name }));
    }
    fireEvent.click(launcher());
    expect(screen.getByRole("textbox", { name: "Question" })).toBe(box);
    expect(box.value).toBe("top talkers on core-rtr-1");
  });

  it("every entry point opens the same panel", () => {
    render(<Harness />);
    fireEvent.click(screen.getByRole("button", { name: "Iris AI" }));
    expect(current.mode).toBe("docked");
    fireEvent.click(screen.getByRole("button", { name: "Undock" }));
    fireEvent.click(screen.getByRole("button", { name: "Iris AI" }));
    expect(current.mode).toBe("closed");
    fireEvent.click(launcher());
    expect(current.mode, "reopens floating, whichever control opens it").toBe("floating");
    expect(probe.mounts).toBe(1);
  });
});

describe("AskIris", () => {
  it("opens the panel in the preferred mode and hands the ask to the content", () => {
    render(<Harness initial={{ mode: "closed", lastOpen: "docked", beforeExpand: "floating", width: 520, owner: OWNER }} />);
    act(() => askIris("kpi.confirmed-rca", "Confirmed RCA"));
    expect(current.mode).toBe("docked");
    expect(probe.asks).toEqual(["kpi.confirmed-rca"]);
    act(() => askIris("kpi.confirmed-rca", "Confirmed RCA"));
    expect(probe.asks, "the same topic can be asked twice").toEqual(["kpi.confirmed-rca", "kpi.confirmed-rca"]);
    expect(probe.mounts).toBe(1);
  });
});

describe("focus and Esc", () => {
  it("moves focus into Iris on open and back to the header control on Esc", () => {
    render(<Harness />);
    launcher().focus();
    fireEvent.click(launcher());
    const box = screen.getByRole("textbox", { name: "Question" });
    expect(document.activeElement).toBe(box);
    press("Escape", box);
    expect(current.mode).toBe("closed");
    expect(document.activeElement).toBe(launcher());
  });

  it("Esc from expanded returns to the previous mode and keeps Iris open", () => {
    render(<Harness />);
    fireEvent.click(launcher());
    fireEvent.click(screen.getByRole("button", { name: "Expand" }));
    const box = screen.getByRole("textbox", { name: "Question" });
    box.focus();
    press("Escape", box);
    expect(current.mode).toBe("docked");
    press("Escape", box);
    expect(current.mode).toBe("closed");
    expect(document.activeElement).toBe(launcher());
  });

  it("closing with the header control returns focus there too", () => {
    render(<Harness />);
    fireEvent.click(launcher());
    fireEvent.click(screen.getByRole("button", { name: "Close Iris" }));
    expect(document.activeElement).toBe(launcher());
  });

  it("an Esc meant for the page does not close a docked panel, but closes a floating overlay", () => {
    render(<Harness />);
    fireEvent.click(launcher());
    const pageCtl = screen.getByRole("button", { name: "page control" });
    pageCtl.focus();
    press("Escape", pageCtl);
    expect(current.mode, "docked Iris is part of the page").toBe("docked");
    fireEvent.click(screen.getByRole("button", { name: "Undock" }));
    pageCtl.focus();
    press("Escape", pageCtl);
    expect(current.mode).toBe("closed");
    expect(document.activeElement, "focus stays where the operator was").toBe(pageCtl);
  });

  it("an Esc already handled inside Iris (an open menu) is left alone", () => {
    render(<Harness />);
    fireEvent.click(launcher());
    const box = screen.getByRole("textbox", { name: "Question" });
    const ev = new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true });
    ev.preventDefault();
    act(() => { box.dispatchEvent(ev); });
    expect(current.mode).toBe("docked");
  });

  it("keeps Tab inside an expanded panel, not a floating one", () => {
    render(<Harness />);
    fireEvent.click(launcher());
    fireEvent.click(screen.getByRole("button", { name: "Undock" }));
    fireEvent.click(screen.getByRole("button", { name: "Expand" }));
    const box = screen.getByRole("textbox", { name: "Question" });
    box.focus();
    press("Tab", box);
    expect(document.activeElement, "wraps to the first control").toBe(screen.getByRole("button", { name: "Collapse" }));
    press("Tab", document.activeElement!, { shiftKey: true });
    expect(document.activeElement).toBe(box);
    fireEvent.click(screen.getByRole("button", { name: "Collapse" }));
    box.focus();
    const ev = new KeyboardEvent("keydown", { key: "Tab", bubbles: true, cancelable: true });
    act(() => { box.dispatchEvent(ev); });
    expect(ev.defaultPrevented, "a floating panel lets Tab move on to the page").toBe(false);
  });
});

describe("docking and the splitter", () => {
  it("reserves a shell column only while docked", () => {
    render(<Harness />);
    expect(shellEl().style.getPropertyValue("--iris-dock-w")).toBe("0px");
    fireEvent.click(launcher());
    expect(shellEl().style.getPropertyValue("--iris-dock-w"), "opens docked by default").toBe(`${DOCK_DEFAULT_W}px`);
    expect(shellEl().classList.contains("iris-docked")).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Undock" }));
    expect(shellEl().style.getPropertyValue("--iris-dock-w"), "floating overlays").toBe("0px");
    fireEvent.click(screen.getByRole("button", { name: "Dock" }));
    expect(shellEl().style.getPropertyValue("--iris-dock-w")).toBe(`${DOCK_DEFAULT_W}px`);
    fireEvent.click(screen.getByRole("button", { name: "Close Iris" }));
    expect(shellEl().style.getPropertyValue("--iris-dock-w")).toBe("0px");
  });

  it("resizes from the keyboard within 380–650 and remembers the width", () => {
    render(<Harness />);
    fireEvent.click(launcher());
    const sep = screen.getByRole("separator", { name: "Resize Iris" });
    expect(sep.getAttribute("aria-valuenow")).toBe(String(DOCK_DEFAULT_W));
    expect(sep.getAttribute("aria-valuemin")).toBe(String(DOCK_MIN_W));
    expect(sep.getAttribute("aria-valuemax")).toBe("650");
    press("ArrowLeft", sep);
    expect(current.width).toBe(DOCK_DEFAULT_W + DOCK_STEP_W);
    press("ArrowRight", sep, { shiftKey: true });
    expect(current.width).toBe(DOCK_DEFAULT_W + DOCK_STEP_W - 4 * DOCK_STEP_W);
    press("End", sep);
    expect(current.width).toBe(650);
    press("ArrowLeft", sep);
    expect(current.width, "stops at the maximum").toBe(650);
    press("Home", sep);
    expect(current.width).toBe(DOCK_MIN_W);
    expect(shellEl().style.getPropertyValue("--iris-dock-w")).toBe(`${DOCK_MIN_W}px`);
    expect(localStorage.getItem(KEYS.width)).toBe(String(DOCK_MIN_W));
    expect(localStorage.getItem(KEYS.lastOpen)).toBe("docked");
  });

  it("a pointer drag paints without re-rendering and commits once on release", () => {
    render(<Harness />);
    fireEvent.click(launcher());
    const sep = screen.getByRole("separator", { name: "Resize Iris" });
    // Frames are queued and flushed by hand, so the test sees the throttle.
    const frames: FrameRequestCallback[] = [];
    const raf = vi.spyOn(window, "requestAnimationFrame").mockImplementation((cb: FrameRequestCallback) => frames.push(cb));
    const flush = () => frames.splice(0).forEach((cb) => cb(0));
    fireEvent.pointerDown(sep, { button: 0, pointerId: 7, clientX: 1000 });
    expect(document.documentElement.classList.contains("iris-resizing")).toBe(true);
    fireEvent.pointerMove(sep, { pointerId: 7, clientX: 950 });
    fireEvent.pointerMove(sep, { pointerId: 7, clientX: 900 });
    expect(frames, "two moves in one frame schedule one paint").toHaveLength(1);
    flush();
    expect(current.width, "no state change mid-drag").toBe(DOCK_DEFAULT_W);
    expect(panelEl().style.getPropertyValue("--iris-w")).toBe("580px");
    expect(shellEl().style.getPropertyValue("--iris-dock-w")).toBe("580px");
    fireEvent.pointerMove(sep, { pointerId: 7, clientX: 100 });
    flush();
    expect(panelEl().style.getPropertyValue("--iris-w"), "clamped at the maximum").toBe("650px");
    fireEvent.pointerUp(sep, { pointerId: 7, clientX: 100 });
    expect(current.width).toBe(650);
    expect(document.documentElement.classList.contains("iris-resizing")).toBe(false);
    raf.mockRestore();
  });

  it("restores the remembered mode and width on a fresh load, closed", () => {
    localStorage.setItem(KEYS.lastOpen, "docked");
    localStorage.setItem(KEYS.width, "600");
    render(<Harness />);
    expect(current.mode, "a page load never opens Iris by itself").toBe("closed");
    fireEvent.click(launcher());
    expect(current.mode).toBe("docked");
    expect(shellEl().style.getPropertyValue("--iris-dock-w")).toBe("600px");
  });

  it("offers no dock on a viewport too narrow to hold one", () => {
    Object.defineProperty(window, "innerWidth", { configurable: true, value: 900 });
    render(<Harness />);
    fireEvent.click(launcher());
    const dock = screen.getByRole("button", { name: "Dock" }) as HTMLButtonElement;
    expect(dock.disabled).toBe(true);
    expect(dock.title).toMatch(/wider window/);
  });

  it("a docked preference with no room overlays, keeps the preference, and reserves nothing", () => {
    Object.defineProperty(window, "innerWidth", { configurable: true, value: 900 });
    render(<Harness initial={{ mode: "closed", lastOpen: "docked", beforeExpand: "floating", width: 480, owner: OWNER }} />);
    fireEvent.click(launcher());
    expect(current.mode).toBe("docked");
    expect(panelEl().className).toContain("is-floating");
    expect(shellEl().style.getPropertyValue("--iris-dock-w")).toBe("0px");
    expect(screen.queryByRole("button", { name: "Undock" })).toBeNull();
    expect((screen.getByRole("button", { name: "Dock" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.queryByRole("separator")).toBeNull();
  });

  it("every window control is labeled and has a tooltip", () => {
    render(<Harness />);
    fireEvent.click(launcher());
    for (const name of ["Undock", "Expand"]) {
      const b = screen.getByRole("button", { name });
      expect(b.getAttribute("title")).toBeTruthy();
    }
    expect(launcher().getAttribute("title")).toBeTruthy();
  });
});

describe("per-operator preferences (design §15, CLAUDE.md §3a)", () => {
  const BOB = "t-globex/p-bob";
  const BOB_KEYS = irisStorageKeys(BOB);

  it("an account switch in the same tab loads the new operator's layout, closed", () => {
    saveIrisState({ mode: "closed", lastOpen: "floating", beforeExpand: "floating", width: 600, owner: OWNER });
    const { rerender } = render(<Harness />);
    fireEvent.click(launcher());
    expect(current.mode).toBe("floating");
    rerender(<Harness owner={BOB} />);
    expect(current, "Bob starts from the defaults, closed").toMatchObject({ owner: BOB, mode: "closed", lastOpen: "docked", width: DOCK_DEFAULT_W });
    fireEvent.click(launcher());
    expect(current.mode).toBe("docked");
    // Alice's saved layout is untouched by Bob's session, and Bob's is his own.
    expect(localStorage.getItem(KEYS.lastOpen)).toBe("floating");
    expect(localStorage.getItem(KEYS.width)).toBe("600");
    expect(localStorage.getItem(BOB_KEYS.lastOpen)).toBe("docked");
    rerender(<Harness owner={OWNER} />);
    fireEvent.click(launcher());
    expect(current).toMatchObject({ owner: OWNER, mode: "floating", width: 600 });
  });

  it("signed out, nothing is read or written", () => {
    saveIrisState({ mode: "closed", lastOpen: "floating", beforeExpand: "floating", width: 600, owner: OWNER });
    const before = { ...localStorage };
    render(<Harness owner={null} />);
    expect(current.lastOpen, "another operator's layout is not loaded").toBe("docked");
    fireEvent.click(launcher());
    fireEvent.click(screen.getByRole("button", { name: "Undock" }));
    expect({ ...localStorage }).toEqual(before);
  });
});

describe("micro-interactions and context (design §10–12)", () => {
  it("the thinking cue is on only while a question is in flight — on the panel and the header control", () => {
    render(<Harness />);
    fireEvent.click(launcher());
    expect(panelEl().hasAttribute("data-thinking")).toBe(false);
    expect(launcher().hasAttribute("data-thinking"), "idle: no ambient motion").toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "probe: start thinking" }));
    expect(panelEl().hasAttribute("data-thinking")).toBe(true);
    expect(launcher().hasAttribute("data-thinking")).toBe(true);
    // Closed while the answer is still coming: the control keeps the cue.
    fireEvent.click(screen.getByRole("button", { name: "Close Iris" }));
    expect(launcher().hasAttribute("data-thinking")).toBe(true);
    fireEvent.click(launcher());
    fireEvent.click(screen.getByRole("button", { name: "probe: stop thinking" }));
    expect(panelEl().hasAttribute("data-thinking")).toBe(false);
    expect(launcher().hasAttribute("data-thinking")).toBe(false);
  });

  it("Dock lights the splitter edge once, then it goes quiet", () => {
    vi.useFakeTimers();
    try {
      render(<Harness />);
      fireEvent.click(launcher());
      expect(screen.getByRole("separator").hasAttribute("data-flash"), "opening docked is not a Dock click").toBe(false);
      fireEvent.click(screen.getByRole("button", { name: "Undock" }));
      fireEvent.click(screen.getByRole("button", { name: "Dock" }));
      expect(screen.getByRole("separator").hasAttribute("data-flash")).toBe(true);
      act(() => { vi.advanceTimersByTime(600); });
      expect(screen.getByRole("separator").hasAttribute("data-flash")).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });

  it("the splitter shows a stop at 380 and 650 px, and clears it inside the range", () => {
    render(<Harness />);
    fireEvent.click(launcher());
    const sep = screen.getByRole("separator", { name: "Resize Iris" });
    press("ArrowLeft", sep);
    expect(sep.classList.contains("at-limit")).toBe(false);
    press("Home", sep);
    expect(sep.classList.contains("at-limit")).toBe(true);
    press("ArrowLeft", sep);
    expect(sep.classList.contains("at-limit")).toBe(false);
    press("End", sep);
    expect(sep.classList.contains("at-limit")).toBe(true);
    act(() => { fireEvent.blur(sep); });
    expect(sep.classList.contains("at-limit")).toBe(false);
  });

  it("a drag pushed past a limit shows the stop until release", () => {
    render(<Harness />);
    fireEvent.click(launcher());
    const sep = screen.getByRole("separator", { name: "Resize Iris" });
    const frames: FrameRequestCallback[] = [];
    const raf = vi.spyOn(window, "requestAnimationFrame").mockImplementation((cb: FrameRequestCallback) => frames.push(cb));
    const flush = () => frames.splice(0).forEach((cb) => cb(0));
    try {
      fireEvent.pointerDown(sep, { button: 0, pointerId: 3, clientX: 1000 });
      fireEvent.pointerMove(sep, { pointerId: 3, clientX: 1050 });
      flush();
      expect(sep.classList.contains("at-limit")).toBe(false);
      fireEvent.pointerMove(sep, { pointerId: 3, clientX: 1400 });
      flush();
      expect(sep.classList.contains("at-limit"), "pushed past 380").toBe(true);
      fireEvent.pointerUp(sep, { pointerId: 3, clientX: 1400 });
      expect(sep.classList.contains("at-limit")).toBe(false);
      expect(current.width).toBe(DOCK_MIN_W);
    } finally {
      raf.mockRestore();
    }
  });

  it("the context chip names the current page and changes with it", () => {
    window.location.hash = "#/overview/home";
    render(<Harness />);
    fireEvent.click(launcher());
    const chip = () => document.querySelector(".iris-context-chip") as HTMLElement | null;
    expect(screen.getByText("Current page")).toBeTruthy();
    const first = chip();
    expect(first?.textContent).toMatch(/Overview/);
    // Stable context: the same element (no re-animation) across a mode change.
    fireEvent.click(screen.getByRole("button", { name: "Undock" }));
    expect(chip()).toBe(first);
    act(() => {
      window.location.hash = "#/no-such/page";
      window.dispatchEvent(new HashChangeEvent("hashchange"));
    });
    expect(chip(), "no chip when the location names no real page").toBeNull();
    window.location.hash = "";
  });

  // N-E4: what the page registered as in view is shown beside the page, so
  // the operator sees what "this" will mean; it goes when the page clears it.
  it("the context chip shows what is in view and clears with it", async () => {
    const vc = await import("../iris/viewContext");
    vc.resetIrisViewForTest();
    render(<Harness />);
    fireEvent.click(launcher());
    expect(screen.queryByTestId("iris-view-chip")).toBeNull();
    act(() => vc.setIrisView({ kind: "device", id: "dev-1", label: "cEdge-80" }));
    expect(screen.getByTestId("iris-view-chip").textContent).toBe("Device · cEdge-80");
    expect(screen.getByText("Asking about")).toBeTruthy();
    act(() => vc.setIrisView(null));
    expect(screen.queryByTestId("iris-view-chip")).toBeNull();
  });

  // An entry point's question ("Ask Iris about this device") opens the panel
  // and is handed to the content as a free question (no topic).
  it("an entry point's free question opens Iris and reaches the content", async () => {
    const { askIrisAbout } = await import("./AskIris");
    const before = probe.asks.length;
    render(<Harness initial={{ mode: "closed", lastOpen: "docked", beforeExpand: "floating", width: 520, owner: OWNER }} />);
    act(() => askIrisAbout("Is this device healthy right now?"));
    expect(current.mode).toBe("docked");
    expect(probe.asks.slice(before)).toEqual([""]);
  });
});
