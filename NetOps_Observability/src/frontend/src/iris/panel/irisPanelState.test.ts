// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// irisPanelState.test.ts — the Iris panel's window model (tracker 338–340, 342).
// Pins the transitions of docs/design/IRIS_PANEL_DESIGN_2026-10-05.md §7–8 and
// §15–16: Expand returns to the PREVIOUS mode, Esc steps back one level, close
// and reopen restore the preferred mode, the width stays in 380–650 px, storage
// is validated on the way back in, and a viewport that cannot hold a docked
// panel overlays instead of squeezing the workspace.

import { describe, it, expect } from "vitest";
import {
  DOCK_DEFAULT_W,
  DOCK_MAX_W,
  DOCK_MIN_W,
  INITIAL_IRIS_STATE,
  IRIS_STORAGE_KEYS,
  MIN_WORKSPACE_W,
  NARROW_W,
  canDock,
  clampWidth,
  dockedWidth,
  irisReducer,
  isOpen,
  loadIrisState,
  presentationFor,
  saveIrisState,
  workspaceReserve,
  type IrisAction,
  type IrisPanelState,
} from "./irisPanelState";

const run = (actions: IrisAction["type"][], from: IrisPanelState = INITIAL_IRIS_STATE): IrisPanelState =>
  actions.reduce<IrisPanelState>((s, type) => irisReducer(s, { type } as IrisAction), from);

/** A Storage stand-in; `fail` makes every access throw like a blocked store. */
function memStore(seed: Record<string, string> = {}, fail = false) {
  const m = new Map(Object.entries(seed));
  return {
    map: m,
    getItem: (k: string) => {
      if (fail) throw new Error("SecurityError");
      return m.has(k) ? m.get(k)! : null;
    },
    setItem: (k: string, v: string) => {
      if (fail) throw new Error("QuotaExceededError");
      m.set(k, v);
    },
  };
}

const WIDE = { width: 1600, navWidth: 60 };

describe("the mode state machine", () => {
  it("starts closed and opens floating by default", () => {
    expect(INITIAL_IRIS_STATE.mode).toBe("closed");
    expect(run(["open"]).mode).toBe("floating");
  });

  it("docks from floating and undocks back to floating", () => {
    expect(run(["open", "dock"]).mode).toBe("docked");
    expect(run(["open", "dock", "undock"]).mode).toBe("floating");
  });

  it("expand returns to the mode it was entered from", () => {
    expect(run(["open", "expand", "collapse"]).mode).toBe("floating");
    expect(run(["open", "dock", "expand", "collapse"]).mode).toBe("docked");
    expect(run(["open", "dock", "expand"]).beforeExpand).toBe("docked");
  });

  it("Esc: expanded → previous mode, floating/docked → closed, closed stays closed", () => {
    expect(run(["open", "dock", "expand", "escape"]).mode).toBe("docked");
    expect(run(["open", "expand", "escape"]).mode).toBe("floating");
    expect(run(["open", "escape"]).mode).toBe("closed");
    expect(run(["open", "dock", "escape"]).mode).toBe("closed");
    const closed = run([]);
    expect(irisReducer(closed, { type: "escape" })).toBe(closed);
  });

  it("close and reopen restore the preferred mode", () => {
    expect(run(["open", "dock", "close", "open"]).mode).toBe("docked");
    expect(run(["open", "dock", "undock", "close", "open"]).mode).toBe("floating");
    // Closed from Expanded: reopens expanded, and Collapse still knows where to go.
    const s = run(["open", "dock", "expand", "close", "open"]);
    expect(s.mode).toBe("expanded");
    expect(irisReducer(s, { type: "collapse" }).mode).toBe("docked");
  });

  it("toggle opens in the preferred mode and closes from any open mode", () => {
    expect(run(["toggle"]).mode).toBe("floating");
    expect(run(["open", "dock", "toggle"]).mode).toBe("closed");
    expect(run(["open", "dock", "toggle", "toggle"]).mode).toBe("docked");
  });

  it("actions that do not apply return the same state object (no re-render)", () => {
    const floating = run(["open"]);
    for (const type of ["open", "undock", "collapse"] as const) {
      expect(irisReducer(floating, { type })).toBe(floating);
    }
    const docked = run(["open", "dock"]);
    expect(irisReducer(docked, { type: "dock" })).toBe(docked);
    const expanded = run(["open", "expand"]);
    expect(irisReducer(expanded, { type: "expand" })).toBe(expanded);
    expect(irisReducer(expanded, { type: "dock" }), "no docking from expanded").toBe(expanded);
    const closed = run([]);
    for (const type of ["close", "dock", "undock", "expand", "collapse"] as const) {
      expect(irisReducer(closed, { type })).toBe(closed);
    }
  });

  it("never enters peek (reserved for tracker 341) and treats it as not open", () => {
    expect([...reachable()].some((st) => st.mode === "peek")).toBe(false);
    expect(isOpen("peek")).toBe(false);
    const peek: IrisPanelState = { ...INITIAL_IRIS_STATE, mode: "peek", lastOpen: "docked" };
    expect(irisReducer(peek, { type: "open" }).mode, "peek promotes into the preferred mode").toBe("docked");
    expect(irisReducer(peek, { type: "escape" }).mode).toBe("closed");
    expect(presentationFor(peek, WIDE)).toBe("hidden");
  });

  it("only ever reaches right-side modes — no left or bottom dock exists", () => {
    const modes = new Set([...reachable()].map((st) => st.mode));
    expect([...modes].sort()).toEqual(["closed", "docked", "expanded", "floating"]);
  });

  it("from every reachable state, Expand then Collapse lands back where it started", () => {
    for (const st of reachable()) {
      if (st.mode !== "floating" && st.mode !== "docked") continue;
      expect(run(["expand", "collapse"], st).mode).toBe(st.mode);
      expect(run(["expand", "escape"], st).mode).toBe(st.mode);
    }
  });
});

// Every state reachable from the initial one by mode actions (resize only moves
// the width, which no mode rule reads). Exhaustive breadth-first search.
function reachable(): IrisPanelState[] {
  const types: IrisAction["type"][] = ["open", "close", "toggle", "dock", "undock", "expand", "collapse", "escape"];
  const key = (st: IrisPanelState) => `${st.mode}|${st.lastOpen}|${st.beforeExpand}`;
  const seen = new Map<string, IrisPanelState>([[key(INITIAL_IRIS_STATE), INITIAL_IRIS_STATE]]);
  const queue = [INITIAL_IRIS_STATE];
  while (queue.length) {
    const st = queue.shift()!;
    for (const type of types) {
      const next = irisReducer(st, { type } as IrisAction);
      if (!seen.has(key(next))) {
        seen.set(key(next), next);
        queue.push(next);
      }
    }
  }
  return [...seen.values()];
}

describe("docked width", () => {
  it("defaults to 480 and clamps to 380–650", () => {
    expect(INITIAL_IRIS_STATE.width).toBe(DOCK_DEFAULT_W);
    expect(DOCK_DEFAULT_W).toBe(480);
    expect(clampWidth(100)).toBe(DOCK_MIN_W);
    expect(clampWidth(9000)).toBe(DOCK_MAX_W);
    expect(clampWidth(512.6)).toBe(513);
    expect(clampWidth(Number.NaN)).toBe(DOCK_DEFAULT_W);
    expect(irisReducer(INITIAL_IRIS_STATE, { type: "resize", width: 10 }).width).toBe(380);
    expect(irisReducer(INITIAL_IRIS_STATE, { type: "resize", width: 999 }).width).toBe(650);
  });

  it("a resize keeps the mode and a same-width resize is a no-op", () => {
    const docked = run(["open", "dock"]);
    const wider = irisReducer(docked, { type: "resize", width: 560 });
    expect(wider.mode).toBe("docked");
    expect(wider.width).toBe(560);
    expect(irisReducer(wider, { type: "resize", width: 560 })).toBe(wider);
  });
});

describe("persistence", () => {
  it("round-trips mode, pre-expand mode and width — and always starts closed", () => {
    const store = memStore();
    const s = irisReducer(run(["open", "dock", "expand"]), { type: "resize", width: 600 });
    expect(saveIrisState(s, store)).toBe(true);
    expect(store.map.get(IRIS_STORAGE_KEYS.lastOpen)).toBe("expanded");
    expect(store.map.get(IRIS_STORAGE_KEYS.beforeExpand)).toBe("docked");
    expect(store.map.get(IRIS_STORAGE_KEYS.width)).toBe("600");
    const back = loadIrisState(store);
    expect(back).toEqual({ mode: "closed", lastOpen: "expanded", beforeExpand: "docked", width: 600 });
    expect(irisReducer(back, { type: "open" }).mode).toBe("expanded");
    expect(run(["open", "collapse"], back).mode).toBe("docked");
  });

  it("stores nothing about the conversation", () => {
    const store = memStore();
    saveIrisState(run(["open"]), store);
    expect([...store.map.keys()].sort()).toEqual(Object.values(IRIS_STORAGE_KEYS).sort());
    expect([...store.map.keys()].some((k) => k.includes("conversation"))).toBe(false);
  });

  it("treats stored values as untrusted input", () => {
    const store = memStore({
      [IRIS_STORAGE_KEYS.lastOpen]: "left-dock",
      [IRIS_STORAGE_KEYS.beforeExpand]: "bottom",
      [IRIS_STORAGE_KEYS.width]: "1e9",
    });
    expect(loadIrisState(store)).toEqual(INITIAL_IRIS_STATE);
    const big = memStore({ [IRIS_STORAGE_KEYS.width]: "9999" });
    expect(loadIrisState(big).width).toBe(DOCK_MAX_W);
    const tiny = memStore({ [IRIS_STORAGE_KEYS.width]: "12" });
    expect(loadIrisState(tiny).width).toBe(DOCK_MIN_W);
    const junk = memStore({ [IRIS_STORAGE_KEYS.width]: "480px; x" });
    expect(loadIrisState(junk).width).toBe(DOCK_DEFAULT_W);
  });

  it("survives storage that throws on every access", () => {
    const blocked = memStore({}, true);
    expect(loadIrisState(blocked)).toEqual(INITIAL_IRIS_STATE);
    expect(saveIrisState(run(["open", "dock"]), blocked)).toBe(false);
    // null = no storage at all (the property access itself threw).
    expect(loadIrisState(null)).toEqual(INITIAL_IRIS_STATE);
    expect(saveIrisState(INITIAL_IRIS_STATE, null)).toBe(false);
  });

  it("uses window.localStorage by default", () => {
    localStorage.clear();
    saveIrisState(irisReducer(run(["open", "dock"]), { type: "resize", width: 520 }));
    expect(localStorage.getItem(IRIS_STORAGE_KEYS.lastOpen)).toBe("docked");
    expect(loadIrisState().width).toBe(520);
    localStorage.clear();
  });
});

describe("viewport rules", () => {
  const docked = run(["open", "dock"]);

  it("docks on a wide viewport and reserves the panel's width from the workspace", () => {
    expect(canDock(WIDE)).toBe(true);
    expect(presentationFor(docked, WIDE)).toBe("docked");
    expect(workspaceReserve(docked, WIDE)).toBe(DOCK_DEFAULT_W);
  });

  it("floating and expanded never take space from the workspace", () => {
    expect(workspaceReserve(run(["open"]), WIDE)).toBe(0);
    expect(workspaceReserve(run(["open", "expand"]), WIDE)).toBe(0);
    expect(workspaceReserve(run([]), WIDE)).toBe(0);
  });

  it("an expanded panel entered from Docked keeps the column so collapsing does not reflow twice", () => {
    expect(workspaceReserve(run(["open", "dock", "expand"]), WIDE)).toBe(DOCK_DEFAULT_W);
  });

  it("caps the drawn width so the workspace keeps at least its minimum", () => {
    const wide = irisReducer(docked, { type: "resize", width: 650 });
    const v = { width: 1300, navWidth: 60 }; // room = 1300 - 60 - 640 = 600
    expect(dockedWidth(wide, v)).toBe(600);
    expect(v.width - v.navWidth - dockedWidth(wide, v)).toBeGreaterThanOrEqual(MIN_WORKSPACE_W);
    expect(wide.width, "the preference is kept for a wider window").toBe(650);
  });

  it("falls back to an overlay when there is no room to dock — never squeezes the workspace", () => {
    const v = { width: 1000, navWidth: 60 }; // room 300 < 380
    expect(canDock(v)).toBe(false);
    expect(presentationFor(docked, v)).toBe("floating");
    expect(workspaceReserve(docked, v)).toBe(0);
    expect(docked.mode, "the docked preference survives").toBe("docked");
  });

  it("uses a near-full-screen sheet on a narrow viewport", () => {
    const v = { width: NARROW_W - 1, navWidth: 44 };
    expect(presentationFor(run(["open"]), v)).toBe("sheet");
    expect(presentationFor(docked, v)).toBe("sheet");
    expect(presentationFor(run(["open", "expand"]), v)).toBe("sheet");
    expect(workspaceReserve(docked, v)).toBe(0);
  });

  it("a closed panel is hidden whatever the viewport", () => {
    expect(presentationFor(run(["open", "dock", "close"]), WIDE)).toBe("hidden");
    expect(presentationFor(run(["open", "dock", "close"]), { width: 500, navWidth: 0 })).toBe("hidden");
  });
});
