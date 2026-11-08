// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// irisPanelState — the Iris panel's window model (tracker 338–340; design of
// record docs/design/IRIS_PANEL_DESIGN_2026-10-05.md).
//
// The panel is ONE container with one mode at a time:
//
//   closed ──open──▶ the last open mode (DOCKED by default — owner 2026-10-17)
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
  /** Whose preferences these are (irisOwnerKey of the signed-in principal),
   *  null when nobody is signed in. Saving writes under this owner only, so one
   *  operator's layout never follows another into a shared browser. */
  owner: string | null;
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
  | { type: "resize"; width: number }
  /** Replace everything with the preferences loaded for a (new) principal —
   *  sign in, sign out, or a switch of account in the same tab. Always closed. */
  | { type: "hydrate"; state: IrisPanelState };

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
  lastOpen: "docked",
  beforeExpand: "docked",
  width: DOCK_DEFAULT_W,
  owner: null,
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
    case "hydrate":
      return { ...a.state, mode: "closed" };
  }
}

// ── Persistence (design §15) ───────────────────────────────────────────────
// The app's pattern for a per-browser layout preference: localStorage, one key
// per value, every access in try/catch (a private window or blocked site data
// throws). Nothing about the conversation is stored here — its id stays in
// sessionStorage, owned by tabs/Iris.tsx.
//
// Keys are per PRINCIPAL (tenant + principal id): a browser shared by two
// operators — or one operator signed in to two tenants — keeps a layout per
// account, and nothing is read or written while nobody is signed in. The base
// names below are suffixed by irisStorageKeys().
export const IRIS_STORAGE_KEYS = {
  // ".v2" (2026-10-17): docked became the default, and every browser that had
  // opened Iris had "floating" saved under the old key — so the new default
  // would never have reached anyone. A fresh key starts everyone docked once;
  // whatever they choose after that is remembered as before.
  lastOpen: "iris.panel.mode.v2",
  beforeExpand: "iris.panel.beforeExpand.v2",
  width: "iris.panel.width",
} as const;

/** The principal fields the owner key is built from (services/api AuthUser). */
export interface IrisPrincipal {
  id?: string;
  username?: string;
  tenant_id?: string;
}

/** The stable per-account owner of the panel preferences, or null when there
 *  is no usable identity (signed out). The principal id is preferred; the
 *  username is the fallback for an older API that does not send one. */
export function irisOwnerKey(p: IrisPrincipal | null | undefined): string | null {
  if (!p) return null;
  const who = (p.id || p.username || "").trim();
  if (!who) return null;
  return `${(p.tenant_id || "").trim()}/${who}`;
}

/** One owner's storage keys: base key + "@" + the owner URI-encoded, so no
 *  owner string can contain a separator that forges another owner's key. */
export function irisStorageKeys(owner: string): Record<keyof typeof IRIS_STORAGE_KEYS, string> {
  const at = `@${encodeURIComponent(owner)}`;
  return {
    lastOpen: IRIS_STORAGE_KEYS.lastOpen + at,
    beforeExpand: IRIS_STORAGE_KEYS.beforeExpand + at,
    width: IRIS_STORAGE_KEYS.width + at,
  };
}

type KV = Pick<Storage, "getItem" | "setItem">;

function read(store: KV | null, key: string): string | null {
  try {
    return store ? store.getItem(key) : null;
  } catch {
    return null; // storage unavailable: defaults apply
  }
}

/** Restores one owner's remembered preferences. The panel always starts
 *  closed: a page load never opens Iris on its own. Values are validated —
 *  storage is input. No owner = the defaults, and nothing is read. */
export function loadIrisState(owner: string | null, store: KV | null = safeLocalStorage()): IrisPanelState {
  if (!owner) return INITIAL_IRIS_STATE;
  const keys = irisStorageKeys(owner);
  const lastOpen = read(store, keys.lastOpen);
  const before = read(store, keys.beforeExpand);
  const rawW = read(store, keys.width);
  const w = rawW !== null && /^\d{1,4}$/.test(rawW) ? Number(rawW) : NaN;
  return {
    mode: "closed",
    lastOpen: lastOpen === "docked" || lastOpen === "expanded" || lastOpen === "floating" ? lastOpen : "docked",
    beforeExpand: before === "floating" ? "floating" : "docked",
    width: Number.isFinite(w) ? clampWidth(w) : DOCK_DEFAULT_W,
    owner,
  };
}

/** Writes the preferences under the state's owner. Returns false when there is
 *  no owner or storage refused the write, so a caller can tell (the choice
 *  still holds for this page load). */
export function saveIrisState(s: IrisPanelState, store: KV | null = safeLocalStorage()): boolean {
  if (!store || !s.owner) return false;
  const keys = irisStorageKeys(s.owner);
  try {
    store.setItem(keys.lastOpen, s.lastOpen);
    store.setItem(keys.beforeExpand, s.beforeExpand);
    store.setItem(keys.width, String(clampWidth(s.width)));
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
