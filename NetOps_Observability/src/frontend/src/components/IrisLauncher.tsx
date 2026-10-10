// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { useShell } from "../context/shell";
import { IRIS_LAUNCHER_ID, IRIS_PANEL_ID } from "../iris/panel/irisPanelState";
import Icon from "./Icon";

// IrisLauncher — the `✦ Iris` control in the upper right of the global header
// (design of record docs/design/IRIS_PANEL_DESIGN_2026-10-05.md §1). It is the
// primary way in; the rail item, the sidebar, the command palette, the
// investigation page and every `(i)` open the SAME panel (components/IrisPanel.tsx)
// through the shell's open state, so this button and they never disagree.
//
// The glyph is the Iris sparkle, never the standalone eye: the BLOGO5 wordmark
// on the left of this header stays the shell's only brand mark. Quiet by
// default — no badge, no animation.
export default function IrisLauncher() {
  const { copilotOpen, setCopilotOpen } = useShell();
  return (
    <button
      type="button"
      id={IRIS_LAUNCHER_ID}
      className={`iris-launch${copilotOpen ? " on" : ""}`}
      aria-expanded={copilotOpen}
      aria-controls={IRIS_PANEL_ID}
      title={copilotOpen ? "Close Iris (Esc)" : "Open Iris"}
      onClick={() => setCopilotOpen(!copilotOpen)}
    >
      <Icon name="copilot" size={15} />
      <span className="iris-launch-label">Iris</span>
    </button>
  );
}
