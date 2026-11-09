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
  irisOwnerKey,
  irisReducer,
  irisStorageKeys,
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
  it("starts closed and opens DOCKED by default (owner 2026-10-17)", () => {
    expect(INITIAL_IRIS_STATE.mode).toBe("closed");
    expect(run(["open"]).mode).toBe("docked");
  });

  it("undocks to floating and docks back", () => {
    expect(run(["open", "undock"]).mode).toBe("floating");
    expect(run(["open", "undock", "dock"]).mode).toBe("docked");
  });

  it("expand returns to the mode it was entered from", () => {
    expect(run(["open", "undock", "expand", "collapse"]).mode).toBe("floating");
    expect(run(["open", "dock", "expand", "collapse"]).mode).toBe("docked");
    expect(run(["open", "dock", "expand"]).beforeExpand).toBe("docked");
  });

  it("Esc: expanded → previous mode, floating/docked → closed, closed stays closed", () => {
    expect(run(["open", "dock", "expand", "escape"]).mode).toBe("docked");
    expect(run(["open", "undock", "expand", "escape"]).mode).toBe("floating");
    expect(run(["open", "escape"]).mode).toBe("closed");
    expect(run(["open", "dock", "escape"]).mode).toBe("closed");
    const closed = run([]);
    expect(irisReducer(closed, { type: "escape" })).toBe(closed);
  });

  it("close and reopen restore the preferred mode", () => {
    expect(run(["open", "dock", "close", "open"]).mode).toBe("docked");
    expect(run(["open", "undock", "close", "open"]).mode).toBe("floating");
    // Closed from Expanded: reopens expanded, and Collapse still knows where to go.
    const s = run(["open", "dock", "expand", "close", "open"]);
    expect(s.mode).toBe("expanded");
    expect(irisReducer(s, { type: "collapse" }).mode).toBe("docked");
  });

  it("toggle opens in the preferred mode and closes from any open mode", () => {
    expect(run(["toggle"]).mode).toBe("docked");
    expect(run(["open", "dock", "toggle"]).mode).toBe("closed");
    expect(run(["open", "dock", "toggle", "toggle"]).mode).toBe("docked");
  });

  it("actions that do not apply return the same state object (no re-render)", () => {
    const floating = run(["open", "undock"]);
    for (const type of ["open", "undock", "collapse"] as const) {
      expect(irisReducer(floating, { type })).toBe(floating);
    }
    const docked = run(["open", "dock"]);
    expect(irisReducer(docked, { type: "dock" })).toBe(docked);
    const expanded = run(["open", "undock", "expand"]);
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
  const ALICE = irisOwnerKey({ id: "p-alice", username: "alice", tenant_id: "t-acme" })!;
  const BOB = irisOwnerKey({ id: "p-bob", username: "bob", tenant_id: "t-globex" })!;
  const K = irisStorageKeys(ALICE);
  const owned = (s: IrisPanelState, owner: string | null = ALICE): IrisPanelState => ({ ...s, owner });

  it("round-trips mode, pre-expand mode and width per owner — and always starts closed", () => {
    const store = memStore();
    const s = owned(irisReducer(run(["open", "dock", "expand"]), { type: "resize", width: 600 }));
    expect(saveIrisState(s, store)).toBe(true);
    expect(store.map.get(K.lastOpen)).toBe("expanded");
    expect(store.map.get(K.beforeExpand)).toBe("docked");
    expect(store.map.get(K.width)).toBe("600");
    const back = loadIrisState(ALICE, store);
    expect(back).toEqual({ mode: "closed", lastOpen: "expanded", beforeExpand: "docked", width: 600, owner: ALICE });
    expect(irisReducer(back, { type: "open" }).mode).toBe("expanded");
    expect(run(["open", "collapse"], back).mode).toBe("docked");
  });

  it("stores nothing about the conversation, and nothing under an unscoped key", () => {
    const store = memStore();
    saveIrisState(owned(run(["open"])), store);
    expect([...store.map.keys()].sort()).toEqual(Object.values(K).sort());
    expect([...store.map.keys()].some((k) => k.includes("conversation"))).toBe(false);
    for (const base of Object.values(IRIS_STORAGE_KEYS)) expect(store.map.has(base), base).toBe(false);
  });

  it("one operator's layout never reaches another in the same browser", () => {
    const store = memStore();
    saveIrisState(owned(irisReducer(run(["open", "undock"]), { type: "resize", width: 620 }), ALICE), store);
    const bob = loadIrisState(BOB, store);
    expect(bob).toEqual({ ...INITIAL_IRIS_STATE, owner: BOB });
    saveIrisState(irisReducer(run(["open", "dock"], bob), { type: "resize", width: 400 }), store);
    expect(loadIrisState(ALICE, store)).toMatchObject({ lastOpen: "floating", width: 620 });
    expect(loadIrisState(BOB, store)).toMatchObject({ lastOpen: "docked", width: 400 });
  });

  it("the same principal name in two tenants is two owners", () => {
    const a = irisOwnerKey({ id: "p-1", tenant_id: "t-a" });
    const b = irisOwnerKey({ id: "p-1", tenant_id: "t-b" });
    expect(a).not.toBe(b);
  });

  it("an owner string cannot forge another owner's keys", () => {
    // The owner is URI-encoded, so the "@" separator appears exactly once and
    // two different owners can never produce the same key.
    const tricky = irisStorageKeys("t/x@iris.panel.width");
    const plain = irisStorageKeys("t/x");
    expect(tricky.width).not.toBe(plain.width);
    for (const k of [...Object.values(tricky), ...Object.values(plain)]) expect(k.split("@")).toHaveLength(2);
  });

  it("with nobody signed in, reads nothing and writes nothing", () => {
    const store = memStore({ [K.lastOpen]: "floating" });
    expect(irisOwnerKey(null)).toBeNull();
    expect(irisOwnerKey({ username: "  " })).toBeNull();
    expect(irisOwnerKey({ username: "legacy" }), "username fallback for an older API").toBe("/legacy");
    expect(loadIrisState(null, store)).toBe(INITIAL_IRIS_STATE);
    const before = new Map(store.map);
    expect(saveIrisState(run(["open", "undock"]), store), "owner null").toBe(false);
    expect(store.map).toEqual(before);
  });

  it("hydrate swaps to the new owner's preferences, closed, whatever was open", () => {
    const open = owned(run(["open", "undock", "expand"]), ALICE);
    const next = irisReducer(open, { type: "hydrate", state: { ...INITIAL_IRIS_STATE, owner: BOB, lastOpen: "floating", mode: "docked" } });
    expect(next).toEqual({ ...INITIAL_IRIS_STATE, owner: BOB, lastOpen: "floating" });
    expect(irisReducer(open, { type: "hydrate", state: INITIAL_IRIS_STATE }), "sign-out resets").toEqual(INITIAL_IRIS_STATE);
  });

  it("a browser that saved 'floating' under the pre-2026-10-17 key opens DOCKED (the new default reaches everyone once)", () => {
    const store = memStore({
      "iris.panel.mode": "floating", "iris.panel.beforeExpand": "floating",
      [`iris.panel.mode@${encodeURIComponent(ALICE)}`]: "floating",
    });
    const s = loadIrisState(ALICE, store);
    expect(s.lastOpen).toBe("docked");
    expect(s.beforeExpand).toBe("docked");
    expect(irisReducer(s, { type: "open" }).mode).toBe("docked");
    // …and a choice made after that is remembered as before.
    const after = memStore({ [K.lastOpen]: "floating" });
    expect(loadIrisState(ALICE, after).lastOpen).toBe("floating");
  });

  it("treats stored values as untrusted input", () => {
    const store = memStore({
      [K.lastOpen]: "left-dock",
      [K.beforeExpand]: "bottom",
      [K.width]: "1e9",
    });
    expect(loadIrisState(ALICE, store)).toEqual({ ...INITIAL_IRIS_STATE, owner: ALICE });
    const big = memStore({ [K.width]: "9999" });
    expect(loadIrisState(ALICE, big).width).toBe(DOCK_MAX_W);
    const tiny = memStore({ [K.width]: "12" });
    expect(loadIrisState(ALICE, tiny).width).toBe(DOCK_MIN_W);
    const junk = memStore({ [K.width]: "480px; x" });
    expect(loadIrisState(ALICE, junk).width).toBe(DOCK_DEFAULT_W);
  });

  it("survives storage that throws on every access", () => {
    const blocked = memStore({}, true);
    expect(loadIrisState(ALICE, blocked)).toEqual({ ...INITIAL_IRIS_STATE, owner: ALICE });
    expect(saveIrisState(owned(run(["open", "dock"])), blocked)).toBe(false);
    // null = no storage at all (the property access itself threw).
    expect(loadIrisState(ALICE, null)).toEqual({ ...INITIAL_IRIS_STATE, owner: ALICE });
    expect(saveIrisState(owned(INITIAL_IRIS_STATE), null)).toBe(false);
  });

  it("survives a localStorage whose property access itself throws", () => {
    const desc = Object.getOwnPropertyDescriptor(window, "localStorage");
    Object.defineProperty(window, "localStorage", { configurable: true, get: () => { throw new Error("SecurityError"); } });
    try {
      expect(loadIrisState(ALICE)).toEqual({ ...INITIAL_IRIS_STATE, owner: ALICE });
      expect(saveIrisState(owned(run(["open"])))).toBe(false);
    } finally {
      if (desc) Object.defineProperty(window, "localStorage", desc);
    }
  });

  it("uses window.localStorage by default", () => {
    localStorage.clear();
    saveIrisState(owned(irisReducer(run(["open", "dock"]), { type: "resize", width: 520 })));
    expect(localStorage.getItem(K.lastOpen)).toBe("docked");
    expect(loadIrisState(ALICE).width).toBe(520);
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
    expect(workspaceReserve(run(["open", "undock"]), WIDE)).toBe(0);
    expect(workspaceReserve(run(["open", "undock", "expand"]), WIDE)).toBe(0);
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
