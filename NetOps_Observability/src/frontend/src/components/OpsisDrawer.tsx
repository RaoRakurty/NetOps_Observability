import { useEffect } from "react";
import Opsis from "../tabs/Opsis";
import { useShell } from "../context/shell";
import Icon from "./Icon";
import CommandCenterAi from "./CommandCenterAi";

// Opsis Ai as a right-side slide-over, available from any section instead of
// being a separate destination tab.
export default function OpsisDrawer() {
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
      <aside className={`drawer op-drawer${copilotOpen ? " open" : ""}`} aria-hidden={!copilotOpen}>
        <div className="op-head">
          <span className="op-head-brand">
            <span className="op-head-logo"><Icon name="copilot" size={16} /></span>
            <span className="op-head-text">
              <span className="op-head-title">Correlix AI</span>
              <span className="op-head-sub">Network assistant</span>
            </span>
          </span>
          <button className="drawer-close" onClick={() => setCopilotOpen(false)} title="Close (Esc)">
            <Icon name="close" size={16} />
          </button>
        </div>
        <div className="drawer-body op-body">
          {copilotOpen && (
            <>
              {/* Grounded "what's going on right now" NOC summary (relocated from
                  the Command Center page) — one click, evidence-cited. Sits above
                  the free-form chat so the rail's AI symbol surfaces it anywhere. */}
              <div style={{ padding: "12px 12px 0" }}><CommandCenterAi /></div>
              <Opsis />
            </>
          )}
        </div>
      </aside>
    </>
  );
}
