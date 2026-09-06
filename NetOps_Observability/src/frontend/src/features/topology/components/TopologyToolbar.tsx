// TopologyToolbar — the top control bar. Left slot (children) carries the
// workflow + overlay selectors from the canvas; right slot holds the density
// control, labels toggle and zoom/fit actions. Calm, compact, icon-driven.

import type React from "react";

type Density = "executive" | "operator" | "engineer" | "incident";

const DENSITIES: { id: Density; label: string }[] = [
  { id: "executive", label: "Exec" },
  { id: "operator", label: "Operator" },
  { id: "engineer", label: "Engineer" },
  { id: "incident", label: "Incident" },
];

const iconBtn: React.CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  justifyContent: "center",
  width: 28,
  height: 28,
  border: "1px solid var(--border)",
  background: "var(--surface)",
  color: "var(--fg-muted)",
  borderRadius: 6,
  cursor: "pointer",
  fontSize: 14,
  lineHeight: 1,
};

export default function TopologyToolbar({
  onFit,
  onZoomIn,
  onZoomOut,
  showAllLabels,
  onToggleLabels,
  density,
  onDensityChange,
  onResetLayout,
  layoutPinned,
  children,
}: {
  onFit: () => void;
  onZoomIn: () => void;
  onZoomOut: () => void;
  showAllLabels: boolean;
  onToggleLabels: () => void;
  density: Density;
  onDensityChange: (d: Density) => void;
  onResetLayout?: () => void;
  layoutPinned?: boolean;
  children?: React.ReactNode;
}) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 12,
        padding: "8px 12px",
        background: "var(--panel)",
        borderBottom: "1px solid var(--border)",
        flexWrap: "wrap",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>{children}</div>

      <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 8 }}>
        {/* Density — a SELECT, not four buttons (owner 2026-08-01). Same
            reasoning as the domain control: four fixed segments spend toolbar
            width on three inactive choices. The label stays on the closed
            control so the current density is readable without opening it. */}
        <label className="topo-select-wrap" title="Detail density — how much each node reveals">
          <span className="topo-select-label">Density</span>
          <select
            className="topo-select"
            aria-label="Density"
            value={density}
            onChange={(e) => onDensityChange(e.target.value as Density)}
          >
            {DENSITIES.map((d) => (
              <option key={d.id} value={d.id}>
                {d.label}
              </option>
            ))}
          </select>
        </label>

        <button
          type="button"
          onClick={onToggleLabels}
          aria-pressed={showAllLabels}
          title={showAllLabels ? "Hide interface labels" : "Show all labels"}
          style={{
            border: "1px solid var(--border)",
            background: showAllLabels ? "var(--panel)" : "var(--surface)",
            color: showAllLabels ? "var(--fg)" : "var(--fg-muted)",
            borderRadius: 6,
            padding: "5px 10px",
            fontSize: 12.5,
            fontWeight: 600,
            cursor: "pointer",
          }}
        >
          Labels
        </button>

        {onResetLayout && (
          <button
            type="button"
            onClick={onResetLayout}
            title="Reset to automatic layout and re-fit"
            style={{
              border: "1px solid var(--border)",
              background: "var(--surface)",
              color: layoutPinned ? "var(--fg-muted)" : "var(--fg-subtle)",
              borderRadius: 6,
              padding: "5px 10px",
              fontSize: 12.5,
              fontWeight: 600,
              cursor: "pointer",
            }}
          >
            Reset layout
          </button>
        )}

        <div style={{ display: "inline-flex", gap: 4 }}>
          <button type="button" onClick={onZoomOut} title="Zoom out" aria-label="Zoom out" style={iconBtn}>
            −
          </button>
          <button type="button" onClick={onZoomIn} title="Zoom in" aria-label="Zoom in" style={iconBtn}>
            +
          </button>
          <button type="button" onClick={onFit} title="Fit to view" aria-label="Fit to view" style={iconBtn}>
            ⤢
          </button>
        </div>
      </div>
    </div>
  );
}
