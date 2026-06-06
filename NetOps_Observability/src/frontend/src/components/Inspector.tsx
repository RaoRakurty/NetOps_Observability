import { useEffect, useRef } from "react";
import { useWorkspace, INS_MIN } from "../context/workspace";
import Icon from "./Icon";

// Inspector — the dockable right context pane (#45 §11). A true docked pane: the
// shell grid gives it a column (var --ins-w mirrors ws.inspectorWidth), so the
// center workspace reflows around it. Width is drag-resizable (left edge) and
// persisted; a pin keeps it open across selections (else Esc / close dismiss).

const clampW = (w: number) => Math.max(INS_MIN, Math.min(w, Math.round(window.innerWidth * 0.6)));

export default function Inspector() {
  const ws = useWorkspace();
  const open = ws.enabled && !!ws.inspector;
  const dragging = useRef(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && open && !ws.inspectorPinned) ws.closeInspector();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, ws]);

  // Left-edge drag to resize; the pane's right edge is the viewport edge.
  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      if (dragging.current) ws.setInspectorWidth(clampW(window.innerWidth - e.clientX));
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
  const ins = ws.inspector;

  return (
    <aside className={`inspector${open ? " open" : ""}`} aria-hidden={!open} aria-label="Inspector">
      {open && (
        <>
          <div
            className="inspector-resize"
            role="separator"
            aria-orientation="vertical"
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
              title={ws.inspectorPinned ? "Unpin (Esc closes)" : "Pin (keep open)"}
              aria-pressed={ws.inspectorPinned}
            >
              <Icon name="pin" size={14} />
            </button>
            <button className="inspector-btn" onClick={ws.closeInspector} title="Close (Esc)">
              <Icon name="close" size={15} />
            </button>
          </div>
          <div className="inspector-body">{ins?.node}</div>
        </>
      )}
    </aside>
  );
}
