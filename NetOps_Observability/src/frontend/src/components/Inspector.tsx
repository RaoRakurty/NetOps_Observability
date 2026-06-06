import { useEffect, useRef, useState } from "react";
import { useWorkspace } from "../context/workspace";
import Icon from "./Icon";

// Inspector — the dockable right context pane (#45 §11). Opens on entity
// selection; a pin keeps it across selections (un-pinned, an Escape / scrim
// click dismisses it). Width is drag-resizable and persisted per user.

const KEY = "ws.inspectorW";
const MIN = 300;
const clampW = (w: number) => Math.max(MIN, Math.min(w, Math.round(window.innerWidth * 0.6)));

export default function Inspector() {
  const ws = useWorkspace();
  const open = ws.enabled && !!ws.inspector;
  const [width, setWidth] = useState<number>(() => {
    const v = Number(localStorage.getItem(KEY));
    return v >= MIN ? v : 380;
  });
  const dragging = useRef(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && open && !ws.inspectorPinned) ws.closeInspector();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, ws]);

  // Left-edge drag to resize; persists on release.
  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      if (!dragging.current) return;
      setWidth(clampW(window.innerWidth - e.clientX));
    };
    const onUp = () => {
      if (!dragging.current) return;
      dragging.current = false;
      document.body.style.userSelect = "";
      localStorage.setItem(KEY, String(width));
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
  }, [width]);

  if (!ws.enabled) return null;
  const ins = ws.inspector;

  return (
      <aside
        className={`inspector${open ? " open" : ""}`}
        style={{ width }}
        aria-hidden={!open}
        aria-label="Inspector"
      >
        <div
          className="inspector-resize"
          onMouseDown={() => {
            dragging.current = true;
            document.body.style.userSelect = "none";
          }}
          title="Drag to resize"
        />
        <div className="inspector-head">
          <div className="inspector-title">
            <strong>{ins?.title ?? "Details"}</strong>
            {ins?.subtitle && <span className="mini-meta">{ins.subtitle}</span>}
          </div>
          <button
            className={`inspector-btn${ws.inspectorPinned ? " active" : ""}`}
            onClick={ws.toggleInspectorPin}
            title={ws.inspectorPinned ? "Unpin (close on selection change)" : "Pin (keep open)"}
            aria-pressed={ws.inspectorPinned}
          >
            <Icon name="pin" size={14} />
          </button>
          <button className="inspector-btn" onClick={ws.closeInspector} title="Close (Esc)">
            <Icon name="close" size={15} />
          </button>
        </div>
        <div className="inspector-body">{ins?.node}</div>
      </aside>
  );
}
