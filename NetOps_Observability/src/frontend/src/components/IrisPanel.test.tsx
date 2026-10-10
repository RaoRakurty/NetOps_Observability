// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// IrisPanel.test.tsx — the one Iris container (tracker 338–340, 342).
//
// The harness wires the panel exactly as App does: the state machine in a
// reducer, the shell's `copilotOpen` derived from it, preferences saved on
// change. Opsis is replaced by a probe that counts its own mounts, so "never
// remounted" is a number rather than an impression. Browser-level geometry,
// reflow and motion are e2e/irisPanel.spec.ts.

import { describe, it, expect, afterEach, beforeEach, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { useCallback, useEffect, useReducer, type ReactNode } from "react";
import { ShellContext, TIME_RANGES, useShell, type ShellState } from "../context/shell";
import { askIris } from "./AskIris";
import IrisLauncher from "./IrisLauncher";
import IrisPanel from "./IrisPanel";
import {
  DOCK_DEFAULT_W,
  DOCK_MIN_W,
  DOCK_STEP_W,
  IRIS_STORAGE_KEYS,
  irisReducer,
  isOpen,
  loadIrisState,
  saveIrisState,
  type IrisPanelState,
} from "../iris/panel/irisPanelState";

const probe = vi.hoisted(() => ({ mounts: 0, unmounts: 0, asks: [] as string[] }));

vi.mock("../tabs/Opsis", async () => {
  const { useEffect: useEff } = await import("react");
  const { useShell: useSh } = await import("../context/shell");
  return {
    default: function OpsisProbe({ controls, ask, onAskHandled }: {
      controls?: ReactNode;
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
          <textarea className="op-input" aria-label="Question" defaultValue="" />
        </div>
      );
    },
  };
});

let current: IrisPanelState;

function Harness({ initial }: { initial?: IrisPanelState }) {
  const [iris, dispatch] = useReducer(irisReducer, undefined, () => initial ?? loadIrisState());
  current = iris;
  useEffect(() => {
    saveIrisState(iris);
  }, [iris]);
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
    expect(current.mode).toBe("floating");
    expect(probe.mounts).toBe(1);
    expect(panelEl().hasAttribute("inert")).toBe(false);
    expect(launcher().getAttribute("aria-expanded")).toBe("true");

    fireEvent.click(screen.getByRole("button", { name: "Dock" }));
    fireEvent.click(screen.getByRole("button", { name: "Expand" }));
    fireEvent.click(screen.getByRole("button", { name: "Collapse" }));
    fireEvent.click(screen.getByRole("button", { name: "Undock" }));
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
    for (const name of ["Dock", "Expand", "Collapse", "Undock", "Close Iris"]) {
      fireEvent.click(screen.getByRole("button", { name }));
    }
    fireEvent.click(launcher());
    expect(screen.getByRole("textbox", { name: "Question" })).toBe(box);
    expect(box.value).toBe("top talkers on core-rtr-1");
  });

  it("every entry point opens the same panel", () => {
    render(<Harness />);
    fireEvent.click(screen.getByRole("button", { name: "Iris AI" }));
    expect(current.mode).toBe("floating");
    fireEvent.click(screen.getByRole("button", { name: "Dock" }));
    fireEvent.click(screen.getByRole("button", { name: "Iris AI" }));
    expect(current.mode).toBe("closed");
    fireEvent.click(launcher());
    expect(current.mode, "reopens docked, whichever control opens it").toBe("docked");
    expect(probe.mounts).toBe(1);
  });
});

describe("AskIris", () => {
  it("opens the panel in the preferred mode and hands the ask to the content", () => {
    render(<Harness initial={{ mode: "closed", lastOpen: "docked", beforeExpand: "floating", width: 520 }} />);
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
    fireEvent.click(screen.getByRole("button", { name: "Dock" }));
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
    fireEvent.click(screen.getByRole("button", { name: "Dock" }));
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
    expect(current.mode).toBe("floating");
  });

  it("keeps Tab inside an expanded panel, not a floating one", () => {
    render(<Harness />);
    fireEvent.click(launcher());
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
    expect(shellEl().style.getPropertyValue("--iris-dock-w"), "floating overlays").toBe("0px");
    fireEvent.click(screen.getByRole("button", { name: "Dock" }));
    expect(shellEl().style.getPropertyValue("--iris-dock-w")).toBe(`${DOCK_DEFAULT_W}px`);
    expect(shellEl().classList.contains("iris-docked")).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Close Iris" }));
    expect(shellEl().style.getPropertyValue("--iris-dock-w")).toBe("0px");
  });

  it("resizes from the keyboard within 380–650 and remembers the width", () => {
    render(<Harness />);
    fireEvent.click(launcher());
    fireEvent.click(screen.getByRole("button", { name: "Dock" }));
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
    expect(localStorage.getItem(IRIS_STORAGE_KEYS.width)).toBe(String(DOCK_MIN_W));
    expect(localStorage.getItem(IRIS_STORAGE_KEYS.lastOpen)).toBe("docked");
  });

  it("a pointer drag paints without re-rendering and commits once on release", () => {
    render(<Harness />);
    fireEvent.click(launcher());
    fireEvent.click(screen.getByRole("button", { name: "Dock" }));
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
    localStorage.setItem(IRIS_STORAGE_KEYS.lastOpen, "docked");
    localStorage.setItem(IRIS_STORAGE_KEYS.width, "600");
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
    render(<Harness initial={{ mode: "closed", lastOpen: "docked", beforeExpand: "floating", width: 480 }} />);
    fireEvent.click(launcher());
    expect(current.mode).toBe("docked");
    expect(panelEl().className).toContain("is-floating");
    expect(shellEl().style.getPropertyValue("--iris-dock-w")).toBe("0px");
    expect(screen.queryByRole("button", { name: "Undock" })).toBeNull();
    expect((screen.getByRole("button", { name: "Dock" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.queryByRole("separator")).toBeNull();
  });

  it("every window control is labelled and has a tooltip", () => {
    render(<Harness />);
    fireEvent.click(launcher());
    for (const name of ["Dock", "Expand"]) {
      const b = screen.getByRole("button", { name });
      expect(b.getAttribute("title")).toBeTruthy();
    }
    expect(launcher().getAttribute("title")).toBeTruthy();
  });
});
