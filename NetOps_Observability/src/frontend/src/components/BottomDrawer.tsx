import { useEffect, useRef, useState } from "react";
import { useWorkspace } from "../context/workspace";
import Icon from "./Icon";

// BottomDrawer — the collapsible bottom pane (#45 §11): correlated logs / events
// / timeline for the current selection (the NOC pivot). Height is drag-resizable
// (top edge) and persisted. Driven via useWorkspace().openDrawer(node).

const KEY = "ws.drawerH";
const MIN = 160;
const clampH = (h: number) => Math.max(MIN, Math.min(h, Math.round(window.innerHeight * 0.8)));

export default function BottomDrawer() {
  const ws = useWorkspace();
  const open = ws.enabled && !!ws.drawer;
  const [height, setHeight] = useState<number>(() => {
    const v = Number(localStorage.getItem(KEY));
    return v >= MIN ? v : 300;
  });
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
      if (!dragging.current) return;
      setHeight(clampH(window.innerHeight - e.clientY));
    };
    const onUp = () => {
      if (!dragging.current) return;
      dragging.current = false;
      document.body.style.userSelect = "";
      localStorage.setItem(KEY, String(height));
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
  }, [height]);

  if (!ws.enabled) return null;
  const d = ws.drawer;

  return (
    <section className={`bottom-drawer${open ? " open" : ""}`} style={{ height: open ? height : 0 }} aria-hidden={!open}>
      <div
        className="bottom-drawer-resize"
        onMouseDown={() => {
          dragging.current = true;
          document.body.style.userSelect = "none";
        }}
        title="Drag to resize"
      />
      <div className="bottom-drawer-head">
        <strong>{d?.title ?? "Console"}</strong>
        <button className="inspector-btn" onClick={ws.closeDrawer} title="Close (Esc)">
          <Icon name="close" size={15} />
        </button>
      </div>
      <div className="bottom-drawer-body">{d?.node}</div>
    </section>
  );
}
