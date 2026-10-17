// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// IrisPanel — the ONE Iris container (tracker 338–340; design of record
// docs/design/IRIS_PANEL_DESIGN_2026-10-05.md). It replaced the left slide-over
// (OpsisDrawer: overlay / split) and owns only the WINDOW: where Iris sits, how
// it moves, how it resizes, where focus goes. What an answer looks like is
// tabs/Opsis.tsx and is unchanged by this file.
//
//   · Modes come from the pure state machine in iris/panel/irisPanelState.ts,
//     held by App so the shell's `copilotOpen` IS "the panel is open": the
//     `✦ Iris` header control, rail, sidebar, command palette, investigation
//     page and `(i)` AskIris all open this panel and nothing else.
//   · One element, mounted once, for every mode. Opsis is created on the FIRST
//     open and never unmounted after that — closing hides it (inert, invisible)
//     — so the conversation, scroll position and settings pane survive every
//     mode change and close/reopen. The server conversation id additionally
//     lives in sessionStorage ("iris.conversation", owned by Opsis).
//   · Floating overlays the workspace; Docked reserves a shell grid column so the
//     workspace reflows (App mirrors nothing — this component sets the column
//     width on the shell element, the same pattern ShellGridSizing uses for the
//     Inspector); Expanded covers the workspace and returns to where it came from.
//   · Motion is transform/opacity only. Open/close is a CSS slide + fade; a mode
//     change is a FLIP: the panel is laid out at its new place, then animated
//     from where it was. Skipped under prefers-reduced-motion.
//   · The splitter writes the width straight to two CSS custom properties while
//     dragging (once per animation frame) and commits to React state only on
//     release, so a drag re-renders nothing.

import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type PointerEvent as ReactPointerEvent,
} from "react";
import Opsis from "../tabs/Opsis";
import Icon from "./Icon";
import { IRIS_ASK_EVENT, type IrisAskDetail } from "./AskIris";
import {
  DOCK_MIN_W,
  DOCK_STEP_W,
  IRIS_EASE,
  IRIS_LAUNCHER_ID,
  IRIS_MOTION_MS,
  IRIS_PANEL_ID,
  canDock,
  dockRoom,
  dockedWidth,
  irisReducer,
  isOpen,
  presentationFor,
  workspaceReserve,
  type IrisAction,
  type IrisPanelState,
  type IrisViewport,
} from "../iris/panel/irisPanelState";

const FOCUSABLE =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

function tabbables(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE)).filter((el) => el.tabIndex >= 0 && !el.closest("[inert]"));
}

function measureViewport(): IrisViewport {
  const nav = document.querySelector<HTMLElement>(".shell > .rail, .shell > .sidebar");
  return { width: window.innerWidth, navWidth: nav ? Math.round(nav.getBoundingClientRect().width) : 0 };
}

function prefersReducedMotion(): boolean {
  try {
    return typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  } catch {
    return false; // no media queries: animate (the CSS guard still applies to CSS motion)
  }
}

type Drag = { pointer: number; startX: number; startW: number; max: number; w: number; frame: number };

export default function IrisPanel({ state, dispatch }: { state: IrisPanelState; dispatch: (a: IrisAction) => void }) {
  const panelRef = useRef<HTMLElement | null>(null);
  const splitterRef = useRef<HTMLDivElement | null>(null);
  const open = isOpen(state.mode);

  // Lazy initialisation (design §14): Opsis — and every request it makes on
  // mount — is created the first time Iris opens, then kept.
  const [initialized, setInitialized] = useState(open);
  if (open && !initialized) setInitialized(true);

  // ── Viewport (design §16) ──────────────────────────────────────────────
  const [viewport, setViewport] = useState<IrisViewport>(() => ({ width: window.innerWidth, navWidth: 0 }));
  useLayoutEffect(() => {
    let frame = 0;
    const remeasure = () => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        const next = measureViewport();
        setViewport((prev) => (prev.width === next.width && prev.navWidth === next.navWidth ? prev : next));
      });
    };
    setViewport(measureViewport()); // the nav is in the DOM now; it was not at first render
    window.addEventListener("resize", remeasure);
    // The rail widens without a window resize (its expand toggle).
    const nav = document.querySelector(".shell > .rail, .shell > .sidebar");
    const ro = nav && typeof ResizeObserver === "function" ? new ResizeObserver(remeasure) : null;
    if (nav && ro) ro.observe(nav);
    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener("resize", remeasure);
      ro?.disconnect();
    };
  }, []);

  const presentation = presentationFor(state, viewport);
  const dockW = dockedWidth(state, viewport);
  const reserve = workspaceReserve(state, viewport);
  const room = Math.max(DOCK_MIN_W, dockRoom(viewport));
  const dockable = canDock(viewport);
  // While hidden the panel keeps the geometry it was last shown with, so a
  // close slides out from where it was instead of jumping first. Before the
  // first open, that is the mode it will open in.
  const lastShown = useRef(presentationFor({ ...state, mode: state.lastOpen }, viewport));
  if (presentation !== "hidden") lastShown.current = presentation;
  const geometry = presentation === "hidden" ? lastShown.current : presentation;

  // Docked → the shell grid gives the panel a column and the workspace reflows.
  useLayoutEffect(() => {
    const shell = panelRef.current?.closest<HTMLElement>(".shell");
    if (!shell) return;
    shell.style.setProperty("--iris-dock-w", `${reserve}px`);
    shell.classList.toggle("iris-docked", reserve > 0);
  }, [reserve]);
  useLayoutEffect(() => {
    const shell = panelRef.current?.closest<HTMLElement>(".shell");
    return () => {
      shell?.style.removeProperty("--iris-dock-w");
      shell?.classList.remove("iris-docked");
    };
  }, []);

  // ── Transitions + FLIP (design §2, §5–7) ───────────────────────────────
  // Every mode change made from inside the panel goes through `transition`,
  // which records where the panel is on screen right before the change.
  const fromRect = useRef<DOMRect | null>(null);
  const stateRef = useRef(state);
  stateRef.current = state;
  const transition = useCallback((a: IrisAction) => {
    // Only an action that changes something gets a start point; a no-op
    // dispatch renders nothing and would otherwise leave a stale one behind.
    if (irisReducer(stateRef.current, a) !== stateRef.current) {
      fromRect.current = panelRef.current?.getBoundingClientRect() ?? null;
    }
    dispatch(a);
  }, [dispatch]);

  const prevPresentation = useRef(presentation);
  useLayoutEffect(() => {
    const from = fromRect.current;
    const prev = prevPresentation.current;
    fromRect.current = null;
    prevPresentation.current = presentation;
    const el = panelRef.current;
    if (!el || !from || prev === presentation || prev === "hidden" || presentation === "hidden") return;
    if (prefersReducedMotion() || typeof el.animate !== "function") return;
    const to = el.getBoundingClientRect();
    if (!to.width || !to.height || !from.width || !from.height) return;
    const sx = from.width / to.width;
    const sy = from.height / to.height;
    // Dock/undock: the panel travels from where it was into place (gap closes,
    // shadow and radius fade via CSS). A change of scale this large (expand,
    // collapse) would squash the text, so it settles in place instead.
    const travel = Math.abs(1 - sx) <= 0.25 && Math.abs(1 - sy) <= 0.25;
    const frames: Keyframe[] = travel
      ? [
          { transformOrigin: "0 0", transform: `translate(${from.left - to.left}px, ${from.top - to.top}px) scale(${sx}, ${sy})` },
          { transformOrigin: "0 0", transform: "none" },
        ]
      : [
          { opacity: 0.6, transform: "scale(0.985)" },
          { opacity: 1, transform: "none" },
        ];
    el.animate(frames, { duration: IRIS_MOTION_MS, easing: IRIS_EASE });
  }, [presentation]);
  // A recorded position is good for the render it was taken for only: an
  // action that changed nothing (or only the width) must not leave a stale
  // start point for a later change driven by the viewport.
  useLayoutEffect(() => {
    fromRect.current = null;
  });

  // ── Focus (design §8, §13) and inertness ───────────────────────────────
  // Opening moves focus into Iris (the question box when it is there).
  // Closing returns it to the `✦ Iris` header control when it was inside the
  // panel; a close from elsewhere (the rail item) leaves focus where it is.
  // A closed panel is inert: nothing in it can be tabbed to or read.
  const wasOpen = useRef(open);
  useLayoutEffect(() => {
    const el = panelRef.current;
    if (!el) return;
    // Order matters: nothing inside an inert subtree can take focus, so inert
    // comes off before focus moves in, and goes on only after focus moved out.
    if (open) el.removeAttribute("inert");
    if (open !== wasOpen.current) {
      wasOpen.current = open;
      if (open) {
        (el.querySelector<HTMLElement>("textarea.op-input") ?? el).focus({ preventScroll: true });
      } else {
        const active = document.activeElement;
        if (!active || active === document.body || el.contains(active)) {
          document.getElementById(IRIS_LAUNCHER_ID)?.focus();
        }
      }
    }
    if (!open) el.setAttribute("inert", "");
  }, [open]);

  // ── Esc (design §8) ─────────────────────────────────────────────────────
  // Expanded → the mode it came from; Floating/Docked → closed. A docked panel
  // is part of the page, so an Esc pressed in the page (closing a page menu)
  // is the page's — Esc reaches Iris when focus is in it or on its control.
  // An open modal dialog elsewhere also keeps its own Esc.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape" || e.defaultPrevented) return;
      const el = panelRef.current;
      const active = document.activeElement;
      const inside = !!el && !!active && el.contains(active);
      const onControl = !!active && active.id === IRIS_LAUNCHER_ID;
      if (!inside && !onControl) {
        if (presentation === "docked") return;
        if (document.querySelector('[aria-modal="true"]')) return;
      }
      e.preventDefault();
      transition({ type: "escape" });
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, presentation, transition]);

  // Expanded and the narrow sheet cover the workspace, so Tab stays inside
  // them. Floating and docked panels sit beside a usable page: Tab moves on.
  const trapsFocus = presentation === "expanded" || presentation === "sheet";
  const onPanelKeyDown = (e: ReactKeyboardEvent<HTMLElement>) => {
    if (!trapsFocus || e.key !== "Tab" || !panelRef.current) return;
    const items = tabbables(panelRef.current);
    if (items.length === 0) return;
    const first = items[0];
    const last = items[items.length - 1];
    const at = document.activeElement;
    if (e.shiftKey && (at === first || at === panelRef.current)) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && at === last) {
      e.preventDefault();
      first.focus();
    }
  };

  // ── AskIris (components/AskIris.tsx) ───────────────────────────────────
  // The `(i)` beside a number raises one window event; this is its only
  // listener. The panel opens in the operator's mode and the ask is handed to
  // Opsis. `seq` makes the same topic askable twice.
  const [pendingAsk, setPendingAsk] = useState<(IrisAskDetail & { seq: number }) | null>(null);
  useEffect(() => {
    let seq = 0;
    const onAsk = (e: Event) => {
      const d = (e as CustomEvent<IrisAskDetail>).detail;
      if (!d?.topic?.trim()) return;
      seq += 1;
      dispatch({ type: "open" });
      setPendingAsk({ topic: d.topic.trim(), question: d.question, seq });
    };
    window.addEventListener(IRIS_ASK_EVENT, onAsk);
    return () => window.removeEventListener(IRIS_ASK_EVENT, onAsk);
  }, [dispatch]);
  const onAskHandled = useCallback(() => setPendingAsk(null), []);

  // A citation is taking the operator to another page. Docked, Iris stays
  // beside it (that is what docking is for); expanded, it steps back to its
  // previous mode so the page shows; a floating panel or sheet gets out of the
  // way, as the drawer always did.
  const onLeave = useCallback(() => {
    if (presentation === "docked") return;
    transition({ type: presentation === "expanded" ? "collapse" : "close" });
  }, [presentation, transition]);

  // ── Splitter (design §4) ────────────────────────────────────────────────
  const drag = useRef<Drag | null>(null);
  const paintWidth = (w: number) => {
    panelRef.current?.style.setProperty("--iris-w", `${w}px`);
    panelRef.current?.closest<HTMLElement>(".shell")?.style.setProperty("--iris-dock-w", `${w}px`);
    splitterRef.current?.setAttribute("aria-valuenow", String(w));
  };
  const endDrag = () => {
    const d = drag.current;
    if (!d) return;
    drag.current = null;
    cancelAnimationFrame(d.frame);
    paintWidth(d.w);
    document.documentElement.classList.remove("iris-resizing");
    splitterRef.current?.classList.remove("dragging");
    transition({ type: "resize", width: d.w });
  };
  // A drag cut short by an unmount must not leave the page stuck in resize.
  useEffect(() => () => document.documentElement.classList.remove("iris-resizing"), []);
  const onSplitterPointerDown = (e: ReactPointerEvent<HTMLDivElement>) => {
    if (e.button !== 0) return;
    e.preventDefault();
    try {
      e.currentTarget.setPointerCapture(e.pointerId);
    } catch {
      /* no capture (synthetic pointer): window-level moves still arrive while the button is held */
    }
    drag.current = { pointer: e.pointerId, startX: e.clientX, startW: dockW, max: room, w: dockW, frame: 0 };
    document.documentElement.classList.add("iris-resizing");
    e.currentTarget.classList.add("dragging");
  };
  const onSplitterPointerMove = (e: ReactPointerEvent<HTMLDivElement>) => {
    const d = drag.current;
    if (!d || d.pointer !== e.pointerId) return;
    // The panel is on the right: dragging left widens it.
    d.w = Math.round(Math.min(d.max, Math.max(DOCK_MIN_W, d.startW + d.startX - e.clientX)));
    if (!d.frame) {
      d.frame = requestAnimationFrame(() => {
        d.frame = 0;
        paintWidth(d.w);
      });
    }
  };
  const onSplitterKeyDown = (e: ReactKeyboardEvent<HTMLDivElement>) => {
    const step = e.shiftKey ? DOCK_STEP_W * 4 : DOCK_STEP_W;
    const next =
      e.key === "ArrowLeft" ? dockW + step
      : e.key === "ArrowRight" ? dockW - step
      : e.key === "Home" ? DOCK_MIN_W
      : e.key === "End" ? room
      : null;
    if (next === null) return;
    e.preventDefault();
    transition({ type: "resize", width: Math.min(room, Math.max(DOCK_MIN_W, next)) });
  };

  // ── Window controls, rendered in Opsis's header ─────────────────────────
  const mode = state.mode;
  const controls = useMemo(() => {
    if (!isOpen(mode)) return null;
    // What the control offers follows what is on screen: a docked preference
    // drawn as an overlay (no room) shows a disabled Dock, not an Undock that
    // would appear to do nothing; the preference docks again when there is room.
    const docked = mode === "docked" && dockable;
    return (
      <>
        {mode !== "expanded" && (
          <button
            type="button"
            className={`op-hd-btn iris-ctl${docked ? " on" : ""}`}
            aria-label={docked ? "Undock" : "Dock"}
            title={docked ? "Undock — float over the page" : dockable ? "Dock — keep Iris beside the page" : "Dock needs a wider window"}
            disabled={!docked && !dockable}
            onClick={() => transition({ type: docked ? "undock" : "dock" })}
          >
            <Icon name={docked ? "undock" : "dock-right"} size={15} />
          </button>
        )}
        <button
          type="button"
          className="op-hd-btn iris-ctl"
          aria-label={mode === "expanded" ? "Collapse" : "Expand"}
          title={mode === "expanded" ? "Collapse — back to the previous size (Esc)" : "Expand — a large investigation view"}
          onClick={() => transition({ type: mode === "expanded" ? "collapse" : "expand" })}
        >
          <Icon name={mode === "expanded" ? "minimize" : "maximize"} size={15} />
        </button>
      </>
    );
  }, [mode, dockable, transition]);

  // Opsis re-renders only when what it is given changes — never on a resize.
  const body = useMemo(
    () => (initialized ? <Opsis controls={controls} onLeave={onLeave} ask={pendingAsk} onAskHandled={onAskHandled} /> : null),
    [initialized, controls, onLeave, pendingAsk, onAskHandled],
  );

  return (
    <aside
      ref={panelRef}
      id={IRIS_PANEL_ID}
      className={`iris-panel is-${geometry}${presentation === "hidden" ? " is-hidden" : ""}`}
      role="complementary"
      aria-label="Iris"
      aria-hidden={!open}
      tabIndex={-1}
      data-mode={state.mode}
      style={{ ["--iris-w" as string]: `${dockW}px` }}
      onKeyDown={onPanelKeyDown}
    >
      {presentation === "docked" && (
        <div
          ref={splitterRef}
          className="iris-splitter"
          role="separator"
          aria-orientation="vertical"
          aria-label="Resize Iris"
          aria-controls={IRIS_PANEL_ID}
          aria-valuemin={DOCK_MIN_W}
          aria-valuemax={room}
          aria-valuenow={dockW}
          tabIndex={0}
          title="Drag, or use the Left and Right arrow keys, to resize"
          onPointerDown={onSplitterPointerDown}
          onPointerMove={onSplitterPointerMove}
          onPointerUp={endDrag}
          onPointerCancel={endDrag}
          onLostPointerCapture={endDrag}
          onKeyDown={onSplitterKeyDown}
        />
      )}
      {body}
    </aside>
  );
}
