// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// irisPanelState — the Iris panel's window model (tracker 338–340; design of
// record docs/design/IRIS_PANEL_DESIGN_2026-10-05.md).
//
// The panel is ONE container with one mode at a time:
//
//   closed ──open──▶ the last open mode (floating by default)
//   floating ◀─dock/undock─▶ docked
//   floating | docked ──expand──▶ expanded ──collapse / Esc──▶ the mode it came from
//   floating | docked ──Esc / close──▶ closed
//
// `peek` (a small contextual card beside an `(i)`, tracker 341) is reserved in
// the type so the container and this reducer need no rewrite when it is built;
// nothing enters it today, and it behaves like `closed` everywhere.
//
// Everything here is pure: the reducer, the storage codec (which treats what it
// reads back as untrusted input) and the viewport rules. The React container
// (components/IrisPanel.tsx) only renders what these return.

/** The panel's DOM id — the header control's aria-controls target. */
export const IRIS_PANEL_ID = "iris-panel";
/** The `✦ Iris` header control's DOM id — focus returns here when Iris closes. */
export const IRIS_LAUNCHER_ID = "iris-launcher";

/** Panel motion (design §2/§5: 180–220 ms; no bounce, no overshoot). */
export const IRIS_MOTION_MS = 200;
export const IRIS_EASE = "cubic-bezier(0.2, 0, 0, 1)";

export type IrisMode = "closed" | "peek" | "floating" | "docked" | "expanded";

/** A mode the panel rests in beside the page: what Expand returns to. */
export type IrisRestingMode = "floating" | "docked";

/** A mode in which the full panel is on screen. */
export type IrisOpenMode = IrisRestingMode | "expanded";

export interface IrisPanelState {
  mode: IrisMode;
  /** The mode the panel was last open in — reopening restores it. A docked
   *  panel is the "pinned" one: there is no separate pin control. */
  lastOpen: IrisOpenMode;
  /** The mode Expand was entered from — Collapse and Esc return to it. */
  beforeExpand: IrisRestingMode;
  /** The operator's docked width in px, within [DOCK_MIN_W, DOCK_MAX_W]. */
  width: number;
}

export type IrisAction =
  | { type: "open" }
  | { type: "close" }
  | { type: "toggle" }
  | { type: "dock" }
  | { type: "undock" }
  | { type: "expand" }
  | { type: "collapse" }
  | { type: "escape" }
  | { type: "resize"; width: number };

// ── Geometry (design §2, §4) ───────────────────────────────────────────────
/** Floating width (design: about 440–460 px). */
export const FLOAT_W = 448;
/** Docked width bounds and default (design §4). */
export const DOCK_DEFAULT_W = 480;
export const DOCK_MIN_W = 380;
export const DOCK_MAX_W = 650;
/** One keyboard step on the splitter; Shift moves four steps. */
export const DOCK_STEP_W = 16;
/** The narrowest the observability workspace may be squeezed to by a docked
 *  panel. Below it the panel overlays instead (design §16). */
export const MIN_WORKSPACE_W = 640;
/** Below this viewport width the panel is a near-full-screen sheet. */
export const NARROW_W = 720;

export const clampWidth = (w: number): number =>
  Number.isFinite(w) ? Math.round(Math.min(DOCK_MAX_W, Math.max(DOCK_MIN_W, w))) : DOCK_DEFAULT_W;

export const isOpen = (m: IrisMode): m is IrisOpenMode => m === "floating" || m === "docked" || m === "expanded";

export const INITIAL_IRIS_STATE: IrisPanelState = {
  mode: "closed",
  lastOpen: "floating",
  beforeExpand: "floating",
  width: DOCK_DEFAULT_W,
};

// go moves to an open mode and remembers it as the one to reopen in.
function go(s: IrisPanelState, mode: IrisOpenMode, beforeExpand: IrisRestingMode = s.beforeExpand): IrisPanelState {
  return { ...s, mode, lastOpen: mode, beforeExpand };
}

/** The state machine. Every action is total: one that does not apply to the
 *  current mode returns the SAME object, so React skips the re-render. */
export function irisReducer(s: IrisPanelState, a: IrisAction): IrisPanelState {
  switch (a.type) {
    case "open":
      return isOpen(s.mode) ? s : go(s, s.lastOpen);
    case "close":
      return s.mode === "closed" ? s : { ...s, mode: "closed" };
    case "toggle":
      return isOpen(s.mode) ? { ...s, mode: "closed" } : go(s, s.lastOpen);
    case "dock":
      return s.mode === "floating" ? go(s, "docked") : s;
    case "undock":
      return s.mode === "docked" ? go(s, "floating") : s;
    case "expand":
      return s.mode === "floating" || s.mode === "docked" ? go(s, "expanded", s.mode) : s;
    case "collapse":
      return s.mode === "expanded" ? go(s, s.beforeExpand) : s;
    case "escape":
      if (s.mode === "expanded") return go(s, s.beforeExpand);
      return s.mode === "closed" ? s : { ...s, mode: "closed" };
    case "resize": {
      const width = clampWidth(a.width);
      return width === s.width ? s : { ...s, width };
    }
  }
}

// ── Persistence (design §15) ───────────────────────────────────────────────
// The app's pattern for a per-browser layout preference: localStorage, one key
// per value, every access in try/catch (a private window or blocked site data
// throws). Nothing about the conversation is stored here — its id stays in
// sessionStorage, owned by tabs/Opsis.tsx.
export const IRIS_STORAGE_KEYS = {
  lastOpen: "iris.panel.mode",
  beforeExpand: "iris.panel.beforeExpand",
  width: "iris.panel.width",
} as const;

type KV = Pick<Storage, "getItem" | "setItem">;

function read(store: KV | null, key: string): string | null {
  try {
    return store ? store.getItem(key) : null;
  } catch {
    return null; // storage unavailable: defaults apply
  }
}

/** Restores the remembered preferences. The panel always starts closed: a page
 *  load never opens Iris on its own. Values are validated — storage is input. */
export function loadIrisState(store: KV | null = safeLocalStorage()): IrisPanelState {
  const lastOpen = read(store, IRIS_STORAGE_KEYS.lastOpen);
  const before = read(store, IRIS_STORAGE_KEYS.beforeExpand);
  const rawW = read(store, IRIS_STORAGE_KEYS.width);
  const w = rawW !== null && /^\d{1,4}$/.test(rawW) ? Number(rawW) : NaN;
  return {
    mode: "closed",
    lastOpen: lastOpen === "docked" || lastOpen === "expanded" || lastOpen === "floating" ? lastOpen : "floating",
    beforeExpand: before === "docked" ? "docked" : "floating",
    width: Number.isFinite(w) ? clampWidth(w) : DOCK_DEFAULT_W,
  };
}

/** Writes the preferences. Returns false when storage refused the write, so a
 *  caller can tell (the choice still holds for this page load). */
export function saveIrisState(s: IrisPanelState, store: KV | null = safeLocalStorage()): boolean {
  if (!store) return false;
  try {
    store.setItem(IRIS_STORAGE_KEYS.lastOpen, s.lastOpen);
    store.setItem(IRIS_STORAGE_KEYS.beforeExpand, s.beforeExpand);
    store.setItem(IRIS_STORAGE_KEYS.width, String(clampWidth(s.width)));
    return true;
  } catch {
    return false;
  }
}

/** null = no storage at all (accessing the property itself can throw, e.g. in
 *  a sandboxed iframe). */
function safeLocalStorage(): KV | null {
  try {
    return typeof localStorage === "undefined" ? null : localStorage;
  } catch {
    return null;
  }
}

// ── Viewport rules (design §16) ─────────────────────────────────────────────
/**
 * How the panel is drawn. Usually the mode itself; on a viewport that cannot
 * hold it, a fallback that never squeezes the workspace:
 *   · `sheet`   — near-full-screen overlay on a narrow viewport;
 *   · a docked panel with no room to dock is drawn `floating` (an overlay),
 *     while the operator's docked preference is kept for a wider window.
 */
export type IrisPresentation = "hidden" | "floating" | "docked" | "expanded" | "sheet";

export interface IrisViewport {
  /** window.innerWidth */
  width: number;
  /** The left navigation's rendered width (rail or sidebar). */
  navWidth: number;
}

/** The widest a docked panel may be in this viewport without squeezing the
 *  workspace below MIN_WORKSPACE_W (may be below DOCK_MIN_W: then it cannot dock). */
export function dockRoom(v: IrisViewport): number {
  return Math.min(DOCK_MAX_W, Math.floor(v.width - v.navWidth - MIN_WORKSPACE_W));
}

export function canDock(v: IrisViewport): boolean {
  return v.width >= NARROW_W && dockRoom(v) >= DOCK_MIN_W;
}

/** The docked width actually drawn: the preference, capped by the room. */
export function dockedWidth(s: IrisPanelState, v: IrisViewport): number {
  return Math.max(DOCK_MIN_W, Math.min(clampWidth(s.width), dockRoom(v)));
}

export function presentationFor(s: IrisPanelState, v: IrisViewport): IrisPresentation {
  switch (s.mode) {
    case "closed":
    case "peek":
      return "hidden";
    case "expanded":
      return v.width < NARROW_W ? "sheet" : "expanded";
    case "docked":
      if (canDock(v)) return "docked";
      return v.width < NARROW_W ? "sheet" : "floating";
    case "floating":
      return v.width < NARROW_W ? "sheet" : "floating";
  }
}

/** The px the workspace gives up to the panel (0 = the panel overlays). An
 *  expanded panel that came from Docked keeps the column, so collapsing back
 *  does not reflow the workspace twice. */
export function workspaceReserve(s: IrisPanelState, v: IrisViewport): number {
  const p = presentationFor(s, v);
  const docked = p === "docked" || (p === "expanded" && s.beforeExpand === "docked" && canDock(v));
  return docked ? dockedWidth(s, v) : 0;
}
