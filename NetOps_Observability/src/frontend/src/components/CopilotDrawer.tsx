import { useEffect } from "react";
import Copilot from "../tabs/Copilot";
import { useShell } from "../context/shell";
import Icon from "./Icon";

// Copilot as a right-side slide-over (reference-grade), available from any
// section instead of being a separate destination tab.
export default function CopilotDrawer() {
  const { copilotOpen, setCopilotOpen } = useShell();

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setCopilotOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [setCopilotOpen]);

  return (
    <>
      <div
        className={`drawer-scrim${copilotOpen ? " open" : ""}`}
        onClick={() => setCopilotOpen(false)}
      />
      <aside className={`drawer${copilotOpen ? " open" : ""}`} aria-hidden={!copilotOpen}>
        <div className="drawer-head">
          <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
            <Icon name="copilot" size={16} /> Opsis Ai
          </span>
          <button className="drawer-close" onClick={() => setCopilotOpen(false)} title="Close (Esc)">
            <Icon name="close" size={16} />
          </button>
        </div>
        <div className="drawer-body">{copilotOpen && <Copilot />}</div>
      </aside>
    </>
  );
}
