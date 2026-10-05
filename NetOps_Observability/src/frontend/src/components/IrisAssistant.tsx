// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// IrisAssistant — the floating Iris window (owner decision, 2026-10-05).
//
// A round "Ask Iris" launcher sits at the bottom right of every signed-in page.
// It opens a chat window OVER the page, anchored above the launcher, which can
// go full screen and come back. This replaced the left-docked slide-over
// (OpsisDrawer: overlay / split), which nobody could find from the page they
// were on. Only the CONTAINER lives here — what an answer looks like (the
// presentation plan, statement classes, hypotheses, chips, citations) is
// tabs/Opsis.tsx and is unchanged by this file.
//
// What the container owns:
//   · open / closed — the shell's `copilotOpen`, so the rail's Iris item, the
//     command palette and the investigation page all open THIS window. There
//     is exactly one Iris container.
//   · full screen — kept for the tab (sessionStorage) and across page changes:
//     the window is mounted beside the routed view, not inside it, so moving
//     between pages never closes or resets it.
//   · keyboard — Ctrl+I / ⌘I toggles it from anywhere, Esc closes it, Tab stays
//     inside it while focus is there, focus moves in on open and goes back to
//     whatever opened it (the launcher by default) on close.
//   · AskIris — the `(i)` beside a number raises one window event; this is its
//     only listener (see components/AskIris.tsx).
//
// The conversation itself is the server's (tracker 337 N-C7): only its id lives
// in the browser, in sessionStorage, written by Opsis. Closing the window
// unmounts Opsis and reopening it keeps asking in the same conversation.

import { useCallback, useEffect, useLayoutEffect, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from "react";
import Opsis from "../tabs/Opsis";
import Icon from "./Icon";
import { useShell } from "../context/shell";
import { IRIS_ASK_EVENT, type IrisAskDetail } from "./AskIris";
import irisMark from "../assets/brand/eye-iris.webp";

/** sessionStorage key for the full-screen choice (per tab, like the conversation). */
export const IRIS_EXPANDED_KEY = "iris.window.expanded";

/** The window's DOM id — the launcher's aria-controls target. */
export const IRIS_WINDOW_ID = "iris-window";

/** Below this width the window is a full-width sheet, and following a citation
 *  closes it (the sheet would otherwise hide the page the link opened). */
export const IRIS_NARROW_QUERY = "(max-width: 640px)";

/**
 * isIrisShortcut — Ctrl+I (⌘I on a Mac), with no other modifier. Chosen because
 * no Correlix shortcut uses it (the command palette is Ctrl/⌘+K and the rest are
 * Esc and arrow keys inside their own widgets), and the plain-text composer has
 * no italic to lose. Shift is excluded so Ctrl+Shift+I still opens the browser's
 * developer tools.
 */
export function isIrisShortcut(e: Pick<KeyboardEvent, "key" | "ctrlKey" | "metaKey" | "altKey" | "shiftKey">): boolean {
  return (e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && (e.key === "i" || e.key === "I");
}

/** The shortcut as the operator's keyboard prints it. */
export function irisShortcutLabel(): string {
  const p = typeof navigator !== "undefined" ? navigator.platform || navigator.userAgent : "";
  return /Mac|iPhone|iPad/i.test(p) ? "⌘I" : "Ctrl+I";
}

function readExpanded(): boolean {
  try { return sessionStorage.getItem(IRIS_EXPANDED_KEY) === "1"; } catch { return false; }
}
function writeExpanded(on: boolean): void {
  try {
    if (on) sessionStorage.setItem(IRIS_EXPANDED_KEY, "1");
    else sessionStorage.removeItem(IRIS_EXPANDED_KEY);
  } catch { /* storage unavailable: the choice holds until the page reloads */ }
}

function isNarrow(): boolean {
  try { return typeof window.matchMedia === "function" && window.matchMedia(IRIS_NARROW_QUERY).matches; } catch { return false; }
}

const FOCUSABLE =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

/** The window's tabbable controls, in DOM order, skipping anything not rendered. */
function tabbables(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
    (el) => !el.hasAttribute("inert") && el.getAttribute("aria-hidden") !== "true" && el.tabIndex >= 0,
  );
}

export default function IrisAssistant() {
  const { copilotOpen: open, setCopilotOpen } = useShell();
  const [expanded, setExpandedState] = useState<boolean>(readExpanded);
  const launcherRef = useRef<HTMLButtonElement | null>(null);
  const windowRef = useRef<HTMLDivElement | null>(null);
  // Whatever had focus when the window opened — focus goes back there on close.
  const openerRef = useRef<HTMLElement | null>(null);
  const wasOpen = useRef(open);

  const setExpanded = useCallback((on: boolean) => {
    setExpandedState(on);
    writeExpanded(on);
  }, []);

  // AskIris — the `(i)` beside a number on any screen raises one named window
  // event and THIS is its only listener: the window owns the open state, and
  // Opsis is mounted only while it is open, so a listener inside Opsis could not
  // open it. `seq` makes the same topic askable twice (an identical payload would
  // otherwise be no change to React).
  const [pendingAsk, setPendingAsk] = useState<(IrisAskDetail & { seq: number }) | null>(null);
  useEffect(() => {
    let seq = 0;
    const onAsk = (e: Event) => {
      const d = (e as CustomEvent<IrisAskDetail>).detail;
      if (!d?.topic?.trim()) return;
      seq += 1;
      setCopilotOpen(true);
      setPendingAsk({ topic: d.topic.trim(), question: d.question, seq });
    };
    window.addEventListener(IRIS_ASK_EVENT, onAsk);
    return () => window.removeEventListener(IRIS_ASK_EVENT, onAsk);
  }, [setCopilotOpen]);

  // Ctrl+I / ⌘I toggles the window from anywhere in the console.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!isIrisShortcut(e)) return;
      e.preventDefault();
      setCopilotOpen(!open);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, setCopilotOpen]);

  // Focus management. Layout effect: on the opening commit the opener still
  // holds focus (nothing has moved it yet), so it is captured before focus is
  // moved into the window; on the closing commit the launcher is back in the DOM.
  useLayoutEffect(() => {
    if (open === wasOpen.current) return;
    wasOpen.current = open;
    if (open) {
      const active = document.activeElement as HTMLElement | null;
      openerRef.current = active && active !== document.body && !windowRef.current?.contains(active) ? active : null;
      const root = windowRef.current;
      if (!root) return;
      const box = root.querySelector<HTMLElement>("textarea.op-input");
      (box ?? root).focus();
      return;
    }
    const back = openerRef.current;
    openerRef.current = null;
    if (back && back.isConnected && back !== document.body) back.focus();
    else launcherRef.current?.focus();
  }, [open]);

  // Esc closes; Tab and Shift+Tab stay inside the window while focus is in it.
  const onWindowKeyDown = (e: ReactKeyboardEvent<HTMLDivElement>) => {
    if (e.key === "Escape") {
      if (e.defaultPrevented) return; // an inner menu (the "/" list) took it
      e.preventDefault();
      setCopilotOpen(false);
      return;
    }
    if (e.key !== "Tab" || !windowRef.current) return;
    const items = tabbables(windowRef.current);
    if (items.length === 0) { e.preventDefault(); windowRef.current.focus(); return; }
    const first = items[0];
    const last = items[items.length - 1];
    const at = document.activeElement;
    if (e.shiftKey && (at === first || at === windowRef.current)) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && at === last) { e.preventDefault(); first.focus(); }
  };

  // A citation is taking the operator to another page: leave full screen so the
  // page shows, and keep the window open beside it — except on a narrow screen,
  // where the window is a sheet over the whole page and has to get out of the way.
  const onLeave = useCallback(() => {
    if (isNarrow()) setCopilotOpen(false);
    else setExpanded(false);
  }, [setCopilotOpen, setExpanded]);

  const shortcut = irisShortcutLabel();
  return (
    <>
      <button
        ref={launcherRef}
        type="button"
        className={`iris-launcher${open ? " open" : ""}`}
        aria-label="Ask Iris"
        aria-expanded={open}
        aria-controls={open ? IRIS_WINDOW_ID : undefined}
        aria-keyshortcuts="Control+I Meta+I"
        title={`Ask Iris (${shortcut})`}
        data-testid="iris-launcher"
        onClick={() => setCopilotOpen(!open)}
      >
        {open
          ? <Icon name="chevron-down" size={24} />
          : <img className="iris-launcher-mark" src={irisMark} alt="" draggable={false} />}
      </button>
      {open && (
        <div
          ref={windowRef}
          id={IRIS_WINDOW_ID}
          className={`iris-window${expanded ? " expanded" : ""}`}
          role="dialog"
          aria-label="Iris"
          aria-modal={expanded ? true : undefined}
          tabIndex={-1}
          data-testid="iris-window"
          onKeyDown={onWindowKeyDown}
        >
          <Opsis
            expanded={expanded}
            onToggleExpand={() => setExpanded(!expanded)}
            onLeave={onLeave}
            ask={pendingAsk}
            onAskHandled={() => setPendingAsk(null)}
          />
        </div>
      )}
    </>
  );
}
