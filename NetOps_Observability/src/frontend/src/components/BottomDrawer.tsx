// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { useEffect, useRef } from "react";
import { useWorkspace, DRW_MIN } from "../context/workspace";
import Icon from "./Icon";

// BottomDrawer — the collapsible bottom pane (#45 §11): correlated logs / events
// / timeline for the current selection (the NOC pivot). A true docked pane: the
// shell grid gives it a row (var --drawer-h mirrors ws.drawerHeight), so the
// center workspace reflows above it. Height is drag-resizable (top edge) +
// persisted. Driven via useWorkspace().openDrawer(node).

const clampH = (h: number) => Math.max(DRW_MIN, Math.min(h, Math.round(window.innerHeight * 0.8)));

export default function BottomDrawer() {
  const ws = useWorkspace();
  const open = ws.enabled && !!ws.drawer;
  const dragging = useRef(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && open) ws.closeDrawer();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, ws]);

  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      if (dragging.current) ws.setDrawerHeight(clampH(window.innerHeight - e.clientY));
    };
    const onUp = () => {
      if (!dragging.current) return;
      dragging.current = false;
      document.body.style.userSelect = "";
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
  }, [ws]);

  if (!ws.enabled) return null;
  const d = ws.drawer;

  return (
    <section className={`bottom-drawer${open ? " open" : ""}`} aria-hidden={!open} aria-label="Console">
      {open && (
        <>
          <div
            className="bottom-drawer-resize"
            role="separator"
            aria-orientation="horizontal"
            aria-label="Resize console"
            tabIndex={0}
            onMouseDown={() => {
              dragging.current = true;
              document.body.style.userSelect = "none";
            }}
            onKeyDown={(e) => {
              // Keyboard resize (2.1.1): arrows nudge the pane 24px per press.
              if (e.key === "ArrowUp") {
                e.preventDefault();
                ws.setDrawerHeight(clampH(ws.drawerHeight + 24));
              } else if (e.key === "ArrowDown") {
                e.preventDefault();
                ws.setDrawerHeight(clampH(ws.drawerHeight - 24));
              }
            }}
            title="Resize"
          />
          <div className="bottom-drawer-head">
            <strong>{d?.title ?? "Console"}</strong>
            <button className="inspector-btn" onClick={ws.closeDrawer} title="Close (Esc)" aria-label="Close console">
              <Icon name="close" size={15} />
            </button>
          </div>
          <div className="bottom-drawer-body">{d?.node}</div>
        </>
      )}
    </section>
  );
}
