// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// SidePanel — the right-hand detail panel the Logs redesign introduced, made
// generic so Active Alerts and Incidents open their rows the same way (owner,
// 2026-11-22). A modal dialog: focus moves into it, Tab stays inside it, Esc
// closes it and focus returns to what opened it. Under 900px it is full screen
// (the .evd-* styles).
//
// With `title`, the panel draws its own header (title, optional subtitle, a
// close button); without it the children bring their own (EventDetailView).

import { useEffect, useId, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";
import "./event.css";

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), summary, [tabindex]:not([tabindex="-1"])';

export default function SidePanel({
  onClose,
  children,
  title,
  subtitle,
  labelledBy,
  testId = "side-panel",
  overlayTestId = "side-panel-overlay",
  narrow = false,
}: {
  onClose: () => void;
  children: ReactNode;
  title?: string;
  subtitle?: string;
  /** The id of the heading inside `children` that names the dialog (no `title`). */
  labelledBy?: string;
  testId?: string;
  overlayTestId?: string;
  /** A record panel (an alert, an incident) rather than the wide event view. */
  narrow?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const ownTitleId = useId();
  const closeRef = useRef(onClose);
  closeRef.current = onClose;

  // Remember what had focus, move focus in, and give it back on close.
  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    // The dialog itself takes focus, not its first button: the Enter that opened
    // the panel from a row would otherwise land on that button and close it again.
    ref.current?.focus();
    return () => {
      if (opener && document.contains(opener)) opener.focus();
    };
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const panel = ref.current;
      if (!panel) return;
      if (e.key === "Escape") {
        e.preventDefault();
        e.stopPropagation();
        closeRef.current();
        return;
      }
      if (e.key !== "Tab") return;
      const items = [...panel.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((el) => el.offsetParent !== null || el === document.activeElement);
      if (items.length === 0) {
        e.preventDefault();
        panel.focus();
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      const active = document.activeElement as HTMLElement | null;
      if (e.shiftKey && (active === first || !panel.contains(active))) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && (active === last || !panel.contains(active))) {
        e.preventDefault();
        first.focus();
      }
    };
    // Capture: the panel answers Esc before the shell's own Esc handlers do.
    document.addEventListener("keydown", onKey, true);
    return () => document.removeEventListener("keydown", onKey, true);
  }, []);

  return createPortal(
    <div className="evd-overlay" data-testid={overlayTestId}>
      <div className="evd-scrim" onClick={() => closeRef.current()} aria-hidden="true" />
      <div
        ref={ref}
        className={narrow ? "evd-panel sp-narrow" : "evd-panel"}
        role="dialog"
        aria-modal="true"
        aria-labelledby={title ? ownTitleId : labelledBy}
        tabIndex={-1}
        data-testid={testId}
      >
        {title ? (
          <div className="sp-body">
            <div className="sp-head">
              <div className="sp-titles">
                <h2 id={ownTitleId} className="sp-title">{title}</h2>
                {subtitle && <div className="sp-sub">{subtitle}</div>}
              </div>
              <button type="button" className="btn-ghost sp-close" aria-label="Close" onClick={() => closeRef.current()}>✕</button>
            </div>
            {children}
          </div>
        ) : children}
      </div>
    </div>,
    document.body,
  );
}
