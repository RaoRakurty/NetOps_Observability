// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// EventDetailPanel — the Event Intelligence panel sliding over the Logs list from the
// right (owner screenshot A). A modal dialog: focus moves into it, Tab stays inside
// it, Esc closes it and focus returns to what opened it. Under 900px it is full screen.

import { useEffect, useId, useMemo, useRef } from "react";
import { createPortal } from "react-dom";
import { LogHit } from "../../lib/logEvent";
import { toEventView } from "../../lib/eventModel";
import EventDetailView from "./EventDetailView";

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), summary, [tabindex]:not([tabindex="-1"])';

export default function EventDetailPanel({ hit, onClose }: { hit: LogHit; onClose: () => void }) {
  const view = useMemo(() => toEventView(hit), [hit]);
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const closeRef = useRef(onClose);
  closeRef.current = onClose;

  // Remember what had focus, move focus in, and give it back on close.
  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    const panel = ref.current;
    (panel?.querySelector<HTMLElement>('[data-testid="event-close"]') ?? panel)?.focus();
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
    <div className="evd-overlay" data-testid="event-panel-overlay">
      <div className="evd-scrim" onClick={() => closeRef.current()} aria-hidden="true" />
      <div
        ref={ref}
        className="evd-panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        data-testid="event-panel"
      >
        <EventDetailView view={view} mode="panel" onClose={onClose} titleId={titleId} />
      </div>
    </div>,
    document.body,
  );
}
