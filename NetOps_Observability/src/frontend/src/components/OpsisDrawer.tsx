import { useEffect, useState } from "react";
import Opsis from "../tabs/Opsis";
import { useShell } from "../context/shell";
import { AI_NAME } from "../brand";

// Iris AI panel — a LEFT-docked assistant that slides in from the icon rail
// (attached to the "Iris AI" knob), not a right slide-over (which clipped on
// narrow screens). Two modes:
//   • overlay (default) — floats over the page with a light scrim; click-away closes.
//   • split            — docks beside the page; the main content reflows (no scrim)
//                        so the assistant and the screen are usable side-by-side.
// The header (brand + Split · New · Settings · Help · Close) lives inside Opsis,
// where the chat state it controls (history, settings) lives.
export default function OpsisDrawer() {
  const { copilotOpen, setCopilotOpen } = useShell();
  const [split, setSplit] = useState<boolean>(() => localStorage.getItem("aiSplit") === "1");

  // Esc closes the panel.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setCopilotOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [setCopilotOpen]);

  // In SPLIT mode the page reflows beside the panel: a body class drives a
  // padding-left on .main (descendant selector), so content is never hidden
  // behind the fixed panel. Cleared whenever the panel is closed or overlaid.
  useEffect(() => {
    const on = copilotOpen && split;
    document.body.classList.toggle("ai-split", on);
    return () => document.body.classList.remove("ai-split");
  }, [copilotOpen, split]);

  const toggleSplit = () => {
    setSplit((s) => {
      const next = !s;
      localStorage.setItem("aiSplit", next ? "1" : "0");
      return next;
    });
  };

  return (
    <>
      {/* Light scrim only in overlay mode — split mode leaves the page interactive. */}
      <div
        className={`op-scrim${copilotOpen && !split ? " open" : ""}`}
        onClick={() => setCopilotOpen(false)}
        aria-hidden="true"
      />
      <aside
        className={`op-panel${copilotOpen ? " open" : ""}${split ? " split" : ""}`}
        aria-hidden={!copilotOpen}
        role="complementary"
        aria-label={AI_NAME + " assistant"}
      >
        {copilotOpen && <Opsis split={split} onToggleSplit={toggleSplit} />}
      </aside>
    </>
  );
}
